#!/usr/bin/env python3
# Chế độ light (mẫu đơn giản): `new --light`/`mode` ghi work/mode.json; khóa `tool` và `v8`; next hướng về tầng tĩnh; cổng phản biện không đổi; triage gợi ý light_ok chỉ với PE/ELF không đóng gói. Chạy: python3 tests/check_light.py
import os, sys, tempfile, subprocess
T = os.path.dirname(os.path.dirname(os.path.abspath(__file__))); sys.path.insert(0, T)
from static import triage   # noqa: E402
ok = lambda **kw: triage.light_ok({'type': 'ELF64 x86-64 LE', 'flags': [], 'entropy': 5.5, 'sections': [], **kw})
assert ok() and ok(flags=['stripped', 'static']) and triage.light_ok({'type': 'PE32', 'flags': [], 'entropy': 6.1, 'sections': [{'entropy': 6.2, 'raw': 9000}]})
assert not ok(flags=['UPX']) and not ok(flags=['Go']) and not ok(entropy=7.4) and not ok(flags=['no-section-header'])
assert not ok(sections=[{'entropy': 7.6, 'raw': 9000}]) and not ok(overlay={'entropy': 7.8, 'size': 5000}) and not ok(type='script/shell') and not ok(type='zip')
ws = tempfile.mkdtemp(prefix='rea-light-'); open(os.path.join(ws, 'a.sh'), 'w').write('#!/bin/sh\necho one\n')
run = lambda *a: subprocess.run([sys.executable, os.path.join(T, 'flow.py'), *a], cwd=ws, capture_output=True, text=True)
assert run('new', 'F1', 'a.sh').returncode == 0 and run('mode', 'F1').stdout.strip() == 'F1: chế độ full'
for cmd in ('tool', 'v8'): assert run(cmd, 'F1', 'list').returncode != 0 or cmd == 'tool'   # full: không bị khóa (có thể lỗi vì lý do khác)
r = run('new', 'L1', '--light', 'a.sh'); assert r.returncode == 0 and 'chế độ light' in r.stdout, r.stderr[-300:]
assert os.path.isfile(os.path.join(ws, 'L1', 'work', 'sample', 'a.sh')) and run('mode', 'L1').stdout.strip() == 'L1: chế độ light'
for cmd in ('tool', 'v8'):
    r = run(cmd, 'L1', 'list'); assert r.returncode != 0 and 'light' in (r.stdout + r.stderr) and 'mode L1 full' in (r.stdout + r.stderr), (cmd, r)
assert 'light' in run('resume', 'L1').stdout
r = run('next', 'L1'); assert 'NEED_MORE (light)' in r.stdout and 'mode L1 full' in r.stdout, r.stdout[-400:]
assert run('mode', 'L1', 'xyz').returncode != 0 and run('mode', 'L1', 'full').returncode == 0 and run('mode', 'L1').stdout.strip() == 'L1: chế độ full'
r = run('next', 'L1'); assert 'NEED_MORE (light)' not in r.stdout   # full: hướng dẫn cũ
open(os.path.join(ws, 'L1', 'work', 'mode.json'), 'w').write('hỏng'); assert run('mode', 'L1').stdout.strip() == 'L1: chế độ full'   # file hỏng: lùi về full
import review, case   # cổng giống nhau: light không mở cổng khi chưa có review lớp 2
case.set_mode(os.path.join(ws, 'L1'), 'light'); assert not review.gate(os.path.join(ws, 'L1'))[0]
print('OK check_light')
