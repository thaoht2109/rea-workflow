#!/usr/bin/env python3
# Mọi lệnh flow.py xử lý phải có trong `flow.py help` (nguồn duy nhất của danh sách lệnh). Chạy: python3 tests/check_help.py
import os, re, subprocess, sys
T = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
src = open(os.path.join(T, 'flow.py'), encoding='utf-8').read()
cmds = set(re.findall(r"cmd == '([\w-]+)'", src)) | set(re.findall(r"cmd in \(([^)]*)\)", src) and re.findall(r"'([\w-]+)'", ' '.join(re.findall(r"cmd in \(([^)]*)\)", src)))) | set(re.findall(r"a\[:1\] == \['([\w-]+)'\]", src))
out = subprocess.run([sys.executable, os.path.join(T, 'flow.py'), 'help'], capture_output=True, text=True, check=True).stdout
miss = sorted(c for c in cmds if not re.search(rf'\b{c}\b', out))
assert not miss, f'lệnh thiếu trong flow.py help: {miss}'
assert 'BƯỚC KẾ' in open(os.path.join(T, 'review.py'), encoding='utf-8').read()
print('OK check_help', len(cmds), 'lệnh')
