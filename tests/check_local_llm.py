#!/usr/bin/env python3
"""Test backend api với server LLM local giả (chuẩn OpenAI như Ollama/vLLM): không cần key, không gửi header Authorization khi trống,
doctor gọi /models, phát hiện server cắt ngữ cảnh. Chạy: python3 tests/check_local_llm.py"""
import os, sys, json, threading, tempfile, importlib, subprocess
from http.server import BaseHTTPRequestHandler, HTTPServer

SKILL = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), '..'))
sys.path.insert(0, SKILL)
SEEN, CUT, SCRIPT, BROKEN = [], [0], [], [False]
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
        if BROKEN[0]: return self.reply({})
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
for url, want in (('https://openrouter.ai/api/v1', 'claude'), ('https://api.groq.com/openai/v1', 'claude'), ('http://8.8.8.8:11434/v1', 'claude'),
                  ('http://localhost:11434/v1', 'api'), ('http://ollama:11434/v1', 'api'), ('http://10.0.0.5:11434/v1', 'api'),
                  ('http://192.168.1.2:8000/v1', 'api'), ('http://[::1]:11434/v1', 'api')):
    os.environ['REVIEW_API_BASE'] = url; importlib.reload(CFG)
    assert CFG.review_backend() == want, (url, CFG.review_backend())   # endpoint cloud khác không được giành chỗ của CLI
del os.environ['REVIEW_API_KEY']
assert reviewer.parse('{"facts": [{"value": "ghi 0x27e2000 B"}]}', ('facts',))['facts'][0]['value'] == 'ghi 0x27e2000 B', 'parse không được đổi hex trong chuỗi'
assert reviewer.parse('{"facts": []}') is None and reviewer.parse('{"items": []}', ('requests', 'facts')) is None, 'mỗi vòng chỉ nhận khóa của nó'
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

# trọn vòng thật: giá trị nguyên văn không có trong evidence -> lớp 1 FAIL -> model rút fact -> review 2 PASS
def mkcase():
    d = tempfile.mkdtemp(); os.makedirs(d + '/report/evidence'); os.makedirs(d + '/work/review/r1')
    open(d + '/report/evidence/e.txt', 'w').write('a\nhost good.example.com\n')
    C.add(d, id='good', kind='c2', value='good.example.com', src='S', evidence='report/evidence/e.txt#L2')
    C.add(d, id='f1', kind='c2', value='bad.example.com', src='S', evidence='report/evidence/e.txt#L2')
    open(d + '/report/README.md', 'w').write('# báo cáo\n'); os.utime(d + '/report/README.md', (1, 1))
    return d
c2 = mkcase(); SCRIPT[:] = ['{"facts": [{"supersedes": "f1", "status": "hypothesis", "value": "bad.example.com", "evidence": "report/evidence/e.txt#L2"}]}',   # lớp 1 vẫn FAIL fact này
                            '{"facts": [{"supersedes": "f1", "status": "retracted", "note": "không có trong evidence"}]}']
rc = review.loop(c2, llm=False); st = review.state(c2)
assert rc == 0 and [r['verdict'] for r in st['rounds']] == ['FAIL', 'PASS'] and not SCRIPT, (rc, st['rounds'], SCRIPT)
# vòng loop chỉ-lớp-máy: verdict PASS nhưng cổng KHÔNG mở (cần lớp 2) — đây là hành vi mới
assert not review.gate(c2)[0] and 'chỉ có lớp máy' in review.gate(c2)[1], review.gate(c2)
F = C.load(c2); assert F['f1.r1']['status'] == 'retracted' and F['f1.r1']['value'] == 'bad.example.com' and F['f1']['status'] == 'retracted', F
# đánh dấu vòng cuối là có lớp 2 (dàn dựng, không gọi mạng) để kiểm tiếp report_todo/final trên cổng đã mở hợp lệ
st['rounds'][-1]['reviewer'] = 'mech+stub'; review.save_state(c2, st)
assert review.gate(c2)[0], review.gate(c2)

# review PASS nhưng README chưa đổi theo fact đã rút: next và report --final phải chặn tới khi sửa README
final = lambda: subprocess.run([sys.executable, os.path.join(SKILL, 'flow.py'), 'report', c2, '--final'], capture_output=True, text=True)
assert review.report_todo(c2) and review.report_todo(c2)[0]['id'] == 'f1.r1' and 'thay f1) -> retracted' in review.report_todo(c2)[0]['line'], review.report_todo(c2)
assert review.next_step(c2, 'C1=x,C2=x,C3=x,C4=x,C5=x,C6=x,C7=x,C8=x,C9=x,C10=x,C11=x') == 1
r = final(); assert r.returncode != 0 and 'README' in r.stderr and 'thay f1) -> retracted' in r.stderr, r.stdout + r.stderr
os.utime(c2 + '/report/README.md', (2 ** 32, 2 ** 32)); assert review.report_todo(c2), 'touch không được coi là đã cập nhật'
open(c2 + '/report/README.md', 'a').write('Đã rút một fact.\n'); assert review.report_todo(c2), 'sửa dòng không liên quan chưa đủ'
os.rename(c2 + '/report/README.md', c2 + '/report/x'); assert review.report_todo(c2), 'thiếu README vẫn chặn'; os.rename(c2 + '/report/x', c2 + '/report/README.md')
open(c2 + '/report/README.md', 'a').write('Xem f1.r10 và xf1.r1.\n'); assert review.report_todo(c2), 'id khác có cùng tiền tố không được tính'
open(c2 + '/report/README.md', 'a').write('Đính chính: đã rút f1.r1.\n')
assert not review.report_todo(c2) and review.next_step(c2) == 0
r = final(); assert r.returncode == 0, r.stdout + r.stderr

# thất bại không được cache: chạy lại phải gọi model lần nữa
c3 = mkcase(); json.dump(dict(items=[dict(item)]), open(c3 + '/work/review/r1/review.json', 'w'))
SCRIPT[:] = ['không phải json'] * 6
assert not review.analyst(c3, 1)[0]
SCRIPT[:] = ['{"facts": [{"supersedes": "f1", "status": "retracted"}]}']
assert review.analyst(c3, 1)[0] and not SCRIPT, 'chạy lại phải hỏi model, không lặp câu trả lời cũ'

# server trả JSON thiếu choices: hủy sạch, ghi nhật ký, không văng traceback
c4 = mkcase(); json.dump(dict(items=[dict(item)]), open(c4 + '/work/review/r1/review.json', 'w'))
facts = open(c4 + '/facts.jsonl', 'rb').read(); BROKEN[0] = True
ok, _, changed = review.analyst(c4, 1); BROKEN[0] = False
assert not ok and not changed and open(c4 + '/facts.jsonl', 'rb').read() == facts and 'KeyError' in open(c4 + '/work/review/r1/analyst_out.txt').read()
assert 'analyst lỗi: KeyError' in open(c4 + '/work/review/usage.jsonl').read(), 'lỗi giữa chừng vẫn vào sổ usage'
assert not review.report_todo(c4), 'phiên hỏng không tạo việc cập nhật báo cáo'
json.dump(['f1 -> retracted: bad.example.com'], open(c4 + '/work/review/report_todo.json', 'w'))
assert review.report_todo(c4) == [dict(id='f1', line='f1 -> retracted: bad.example.com')], 'định dạng cũ vẫn chặn, không văng lỗi'
srv.shutdown(); print('OK test_local_llm')
