#!/usr/bin/env python3
"""Test backend api với server LLM local giả (chuẩn OpenAI như Ollama/vLLM): không cần key, không gửi header Authorization khi trống,
doctor gọi /models, phát hiện server cắt ngữ cảnh. Chạy: python3 tests/check_local_llm.py"""
import os, sys, json, threading, tempfile, importlib
from http.server import BaseHTTPRequestHandler, HTTPServer

SKILL = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), '..'))
sys.path.insert(0, SKILL)
SEEN, CUT, SCRIPT = [], [0], []
class H(BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def reply(self, d):
        b = json.dumps(d).encode(); self.send_response(200); self.send_header('Content-Type', 'application/json'); self.end_headers(); self.wfile.write(b)
    def do_GET(self):
        SEEN.append(('GET', self.path, self.headers.get('Authorization'))); self.reply({'data': [{'id': 'qwen-test'}]})
    def do_POST(self):
        n = int(self.headers['Content-Length']); body = json.loads(self.rfile.read(n))
        SEEN.append(('POST', self.path, self.headers.get('Authorization')))
        chars = sum(len(m['content']) for m in body['messages'])
        SEEN.append(body['messages'][-1]['content'])
        self.reply({'choices': [{'message': {'content': SCRIPT.pop(0) if SCRIPT else '{"canary": []}'}}], 'usage': {'prompt_tokens': CUT[0] or chars // 3, 'completion_tokens': 5}})
srv = HTTPServer(('127.0.0.1', 0), H); threading.Thread(target=srv.serve_forever, daemon=True).start()
base = f'http://127.0.0.1:{srv.server_port}/v1'

for k in ('REVIEW_API_KEY', 'OPENAI_API_KEY'): os.environ.pop(k, None)
os.environ.update(REVIEW_LLM='api', REVIEW_API_BASE=base, REVIEW_MODEL='qwen-test', REA_ENV=os.path.join(tempfile.mkdtemp(), 'none.env'))
import reacfg as CFG; importlib.reload(CFG)
assert CFG.API_LOCAL and CFG.review_backend() == 'api', 'server tự dựng: không cần key'
assert CFG.api_probe() == (True, f'{base} có qwen-test') and SEEN[-1] == ('GET', '/v1/models', None), SEEN
os.environ['REVIEW_MODEL'] = 'khong-co'; importlib.reload(CFG); assert not CFG.api_probe()[0]
os.environ['REVIEW_MODEL'] = 'qwen-test'; importlib.reload(CFG)
import reviewer; importlib.reload(reviewer); reviewer.CFG = CFG
cache = tempfile.mkdtemp()
msgs = [{'role': 'system', 'content': 'x' * 30000}, {'role': 'user', 'content': 'y'}]
assert reviewer.ask('api', msgs, cache) == '{"canary": []}' and ('POST', '/v1/chat/completions', None) in SEEN, SEEN
CUT[0] = 2048   # server chỉ nhận 2048 token cho prompt 30k ký tự -> báo lỗi, không coi là kết luận
try: reviewer.ask('api', [{'role': 'system', 'content': 'z' * 30000}, {'role': 'user', 'content': 'y'}], cache); raise AssertionError('phải báo cắt ngữ cảnh')
except RuntimeError as e: assert 'ngữ cảnh bị cắt' in str(e), e
# OpenAI thật vẫn bắt buộc key
os.environ['REVIEW_API_BASE'] = 'https://api.openai.com/v1'; importlib.reload(CFG)
assert not CFG.API_LOCAL and CFG.review_backend() is None

# auto: LLM local đã khai thì không bị CLI có sẵn trên máy giành mất (dữ liệu mẫu ra cloud)
os.environ.update(REVIEW_LLM='auto', CLAUDE_BIN=sys.executable, REVIEW_API_BASE=base); importlib.reload(CFG)
assert CFG.review_backend() == 'api', CFG.review_backend()
os.environ.update(REVIEW_API_BASE='https://api.openai.com/v1', REVIEW_API_KEY='k'); importlib.reload(CFG)
assert CFG.review_backend() == 'claude', 'cloud giữ thứ tự cũ'
del os.environ['REVIEW_API_KEY']
assert reviewer.parse('{"facts": [{"value": "ghi 0x27e2000 B"}]}')['facts'][0]['value'] == 'ghi 0x27e2000 B', 'parse không được đổi hex trong chuỗi'
assert reviewer.parse('{"requests": [{"off": 0x10}]}')['requests'][0]['off'] == 16, 'hex trần vẫn đọc được'

# review-loop trọn vòng với LLM local: mô hình chỉ đọc qua run_ops, script ghi fact qua case.add strict
os.environ.update(REVIEW_LLM='api', REVIEW_API_BASE=base, REVIEW_MAX_TURNS='5'); importlib.reload(CFG)
import case as C, review; importlib.reload(review); reviewer.CFG = review.CFG = CFG
c = tempfile.mkdtemp(); os.makedirs(c + '/report/evidence'); os.makedirs(c + '/work/review/r1')
open(c + '/report/evidence/e.txt', 'w').write('a\nhost good.example.com\nghi 0x27e2000 B\n')
C.add(c, id='f1', kind='c2', value='bad.example.com', src='S', evidence='report/evidence/e.txt#L2')
C.add(c, id='f2', kind='inject', value='x', src='S', evidence='report/evidence/e.txt#L3')
before = open(c + '/facts.jsonl', 'rb').read()
item = dict(id='f1', verdict='fail', severity='high', problem='sai host', where='report/evidence/e.txt#L2', redo='đọc lại dòng 2')
json.dump(dict(items=[item]), open(c + '/work/review/r1/review.json', 'w'))
good = '{"facts": [{"supersedes": "f1", "value": "good.example.com", "evidence": "report/evidence/e.txt#L2", "status": "active", "kind": "url", "src": "V", "id": "x"}]}'
SCRIPT[:] = ['{"requests": [{"op": "read", "file": "report/evidence/e.txt"}, {"op": "shell", "cmd": "id"}]}',
             '{"facts": [{"supersedes": "f2", "value": "good.example.com", "evidence": "report/evidence/e.txt#L2"}]}',   # ngoài danh sách lỗi
             '{"facts": [{"supersedes": "f1", "value": "hallucinated.example.com", "evidence": "report/evidence/e.txt#L2"}]}',   # lint chặn
             good]
ok, n, changed = review.analyst(c, 1)
F, msgs = C.load(c), [s for s in SEEN if isinstance(s, str)]
assert ok and n == 1 and changed and not SCRIPT, (ok, n, changed, SCRIPT)
assert open(c + '/facts.jsonl', 'rb').read().startswith(before), 'chỉ được nối thêm'
new = F['f1.r1']
assert (new['kind'], new['src'], new['value'], new['supersedes']) == ('c2', 'S', 'good.example.com', 'f1'), 'id/kind/src lấy từ fact cũ, không từ mô hình'
assert F['f1']['status'] == 'retracted' and F['f2']['status'] == 'active' and 'x' not in F
assert any('2: host good' in m for m in msgs) and any('op không hỗ trợ' in m for m in msgs), 'read chạy, shell bị từ chối'
assert sum('Fact bị từ chối' in m for m in msgs) == 2, 'fact lỗi được báo lại cho mô hình'
SCRIPT[:] = ['không phải json'] * 6
facts = open(c + '/facts.jsonl', 'rb').read()
ok, _, changed = review.analyst(c, 1)
assert not ok and not changed and open(c + '/facts.jsonl', 'rb').read() == facts, 'hết lượt: không đổi facts'
srv.shutdown(); print('OK test_local_llm')
