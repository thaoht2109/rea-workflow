#!/usr/bin/env python3
# Kiểm `flow.py opencode`: sinh opencode.json, giữ cấu hình người dùng, chạy lại không đổi, không ghi đè file lỗi;
# luật quyền đi qua được công cụ của skill nhưng chặn cách chạy mẫu và mạng.
#   python3 tests/check_opencode.py
import os, sys, json, fnmatch, subprocess, tempfile
SRC = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
run = lambda *a: subprocess.run([sys.executable, os.path.join(SRC, 'flow.py'), 'opencode', *a], capture_output=True, text=True)
W = tempfile.mkdtemp(); P = os.path.join(W, 'opencode.json')
R = lambda: json.load(open(P, encoding='utf-8'))

r = run(W); assert r.returncode == 0, r.stdout + r.stderr
c = R()
assert c['model'] == 'ollama/qwen3-coder:30b' and c['autoupdate'] is False, c
ol = c['provider']['ollama']
assert ol['npm'] == '@ai-sdk/openai-compatible' and ol['options']['baseURL'] == 'http://localhost:11434/v1' and 'qwen3-coder:30b' in ol['models'], ol
assert c['permission']['webfetch'] == c['permission']['websearch'] == 'deny', c['permission']
first = open(P, 'rb').read()
assert run(W).returncode == 0 and open(P, 'rb').read() == first, 'chạy lại phải giữ nguyên file'

# máy chủ khác, model khác: giữ cấu hình của người dùng và model đã khai
c['theme'] = 'x'; c['provider']['khac'] = {'name': 'y'}
json.dump(c, open(P, 'w', encoding='utf-8'))
assert run(W, '--model', 'qwen3.5:27b', '--base-url', 'http://10.0.0.5:11434/v1').returncode == 0
c = R(); ol = c['provider']['ollama']
assert c['theme'] == 'x' and 'khac' in c['provider'] and c['model'] == 'ollama/qwen3.5:27b', c
assert ol['options']['baseURL'] == 'http://10.0.0.5:11434/v1' and {'qwen3-coder:30b', 'qwen3.5:27b'} <= set(ol['models']), ol

# --print không ghi; file JSON hỏng (ví dụ JSONC) không bị ghi đè
E = tempfile.mkdtemp(); r = run(E, '--print')
assert r.returncode == 0 and json.loads(r.stdout)['model'] and not os.path.exists(os.path.join(E, 'opencode.json')), r.stdout
bash = json.loads(r.stdout)['permission']['bash']
open(P, 'w').write('{ // chú thích\n}'); r = run(W)
assert r.returncode == 2 and open(P).read().startswith('{ //'), r.stdout

# luật OpenCode: khớp mẫu, luật khớp cuối cùng thắng
assert next(iter(bash)) == '*', '"*" phải đứng đầu, nếu không sẽ đè mọi luật khác'
assert not any('{SKILL}' in k for k in bash), bash
T = os.path.realpath(SRC)
def verdict(cmd): return [v for k, v in bash.items() if fnmatch.fnmatchcase(cmd, k)][-1]
for cmd, want in ((f'python3 {T}/flow.py next CASE', 'allow'), (f'python3 {T}/case.py add CASE id=a', 'allow'),
                  (f'python3 {T}/winemu/winemu.py --blob work/sample/x --out o', 'allow'),   # 'wine' không được bắt nhầm winemu
                  (f'python3 {T}/winemu/summarize.py o/events.jsonl', 'allow'), ('grep -n x a.log', 'allow'),
                  (f'python3 {T}/flow.py review CASE --llm --detach', 'allow'), (f'python3 {T}/flow.py review-loop CASE', 'allow'), (f'python3 {T}/flow.py help', 'allow'),
                  (f'python3 {T}/flow.py dec CASE f main', 'allow'), (f'python3 {T}/flow.py doctor', 'allow'),
                  # lệnh đổi cấu hình không được đi nhờ allow: trỏ provider ra ngoài, gỡ quy tắc, sửa shell, cài gói
                  (f'python3 {T}/flow.py opencode --base-url http://x/v1', 'deny'), (f'python3 {T}/flow.py opencode', 'deny'), ('python3 tools/flow.py opencode .', 'deny'),
                  (f'python3 {T}/flow.py rules --remove', 'deny'), (f'python3 {T}/flow.py session --install', 'deny'), (f'python3 {T}/flow.py setup --yes', 'deny'),
                  (f'python3 {T}/flow.py lạ x', 'ask'), (f'python3 {T}/flow.py next CASE --accept C9=x', 'ask'),
                  # plugin là mã Python tùy ý, snapshot là pickle
                  (f'python3 {T}/winemu/winemu.py --blob x --plugin evil.py', 'ask'), (f'python3 {T}/winemu/winemu.py --resume s.bin', 'ask'),
                  (f'python3 {T}/winemu/step.py --out-dir w -- --blob x', 'ask'),   # step.py tự resume: không có allow, luôn hỏi
                  # allow phải neo đường dẫn: script mẫu mang tên flow.py hoặc tham số flow.py không được tự duyệt
                  ('python3 work/sample/flow.py x', 'ask'), ('python3 work/sample/x.py flow.py a', 'ask'), ('python3 -c "import os" flow.py a', 'ask'),
                  # lệnh ghép và ghi file không được đi nhờ tiền tố đã allow; sed có lệnh e/w nên không allow
                  (f'python3 {T}/flow.py next C; python3 work/sample/x.py', 'ask'), ('grep x a | sh', 'ask'), ('head a && python3 x.py', 'ask'),
                  ('ls $(python3 x.py)', 'ask'), ('grep x a > facts.jsonl', 'ask'), ("sed -n '1e id' f", 'ask'), ("sed -n 'w facts.jsonl' f", 'ask'),
                  ('sed -n 1,5p a.log', 'ask'), ('grep x a; wine b.exe', 'deny'),
                  ('wine a.exe', 'deny'), ('wine64 a.exe', 'deny'), ('env wine a.exe', 'deny'), ('/usr/bin/wine a.exe', 'deny'),
                  ('qemu-x86_64 a', 'deny'), ('env qemu-arm a', 'deny'), ('rea capture-run a', 'deny'), ('npx rea capture-run a', 'deny'),
                  ('rea debug-with-gdb a', 'deny'), ('./a.out', 'deny'), ('chmod +x a', 'deny'), ('curl http://x', 'deny'), ('wget http://x', 'deny'),
                  ('nc 1.2.3.4 80', 'deny'), ('rm -rf a', 'ask'), ('sed -i s/a/b/ f', 'ask'), ('python3 work/sample/x.py', 'ask')):
    assert verdict(cmd) == want, (cmd, verdict(cmd), want)
# allow theo `winemu.py *`: viết tắt của argparse (--pl, --res) sẽ lách luật --plugin/--resume ở trên
assert 'ArgumentParser(allow_abbrev=False)' in open(os.path.join(SRC, 'winemu', 'winemu.py'), encoding='utf-8').read()
print('OK test_opencode')
