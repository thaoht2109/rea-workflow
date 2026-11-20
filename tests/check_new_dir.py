#!/usr/bin/env python3
# flow.py new nhận mẫu dạng thư mục; triage ghi fact filetype riêng cho từng file dù cùng loại. Chạy: python3 tests/check_new_dir.py
import os, sys, json, tempfile, subprocess
T = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ws = tempfile.mkdtemp(prefix='rea-newdir-'); d = os.path.join(ws, 'app', 'sub'); os.makedirs(d)
open(os.path.join(ws, 'app', 'a.sh'), 'w').write('#!/bin/sh\necho one\n'); open(os.path.join(d, 'b.sh'), 'w').write('#!/bin/sh\necho two\n')
run = lambda *a: subprocess.run([sys.executable, os.path.join(T, 'flow.py'), *a], cwd=ws, capture_output=True, text=True)
r = run('new', 'C1', 'app'); assert r.returncode == 0, r.stderr[-500:]
assert os.path.isfile(os.path.join(ws, 'C1', 'work', 'sample', 'app', 'sub', 'b.sh'))
F = [json.loads(l) for l in open(os.path.join(ws, 'C1', 'facts.jsonl')) if l.strip()]
ft = {f['id']: f['value'] for f in F if f['kind'] == 'filetype'}
assert len(ft) == 2 and len(set(ft.values())) == 1, ft   # cùng loại, vẫn hai fact (mỗi file một evidence)
n = len(F); assert run('triage', 'C1').returncode == 0
assert sum(1 for l in open(os.path.join(ws, 'C1', 'facts.jsonl')) if l.strip()) == n   # chạy lại không nhân đôi fact
r = run('new', 'C2', 'khong_co'); assert r.returncode != 0 and 'không thấy mẫu' in (r.stderr + r.stdout) and 'Traceback' not in r.stderr, r.stderr[-300:]
print('OK check_new_dir')
