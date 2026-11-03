#!/usr/bin/env python3
"""Test backend api với server LLM local giả (chuẩn OpenAI như Ollama/vLLM): không cần key, không gửi header Authorization khi trống,
doctor gọi /models, phát hiện server cắt ngữ cảnh. Chạy: python3 tests/check_local_llm.py"""
import os, sys, json, threading, tempfile, importlib
from http.server import BaseHTTPRequestHandler, HTTPServer

SKILL = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), '..'))
sys.path.insert(0, SKILL)
SEEN, CUT = [], [0]
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
        self.reply({'choices': [{'message': {'content': '{"canary": []}'}}], 'usage': {'prompt_tokens': CUT[0] or chars // 3, 'completion_tokens': 5}})
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
assert reviewer.ask('api', msgs, cache) == '{"canary": []}' and SEEN[-1] == ('POST', '/v1/chat/completions', None), SEEN
CUT[0] = 2048   # server chỉ nhận 2048 token cho prompt 30k ký tự -> báo lỗi, không coi là kết luận
try: reviewer.ask('api', [{'role': 'system', 'content': 'z' * 30000}, {'role': 'user', 'content': 'y'}], cache); raise AssertionError('phải báo cắt ngữ cảnh')
except RuntimeError as e: assert 'ngữ cảnh bị cắt' in str(e), e
# OpenAI thật vẫn bắt buộc key
os.environ['REVIEW_API_BASE'] = 'https://api.openai.com/v1'; importlib.reload(CFG)
assert not CFG.API_LOCAL and CFG.review_backend() is None
srv.shutdown(); print('OK test_local_llm')
