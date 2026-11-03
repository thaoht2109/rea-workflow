#!/usr/bin/env python3
"""Test install.mjs (một lệnh: skill + quy tắc + công cụ) bằng npx/flow.py giả: không cài gì thật.
Chạy: python3 tests/check_installer.py"""
import os, shutil, tempfile, subprocess

SKILL = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), '..'))
if not shutil.which('node'): print('SKIP test_installer (không có node)'); raise SystemExit

def case(args, missing=True, tty=False, git=False, installed=True, lock_ref=None):
    h = tempfile.mkdtemp(prefix='rea-inst-'); b = os.path.join(h, 'bin'); os.makedirs(b)
    sk = os.path.join(h, '.claude', 'skills', 'rea-flow'); os.makedirs(sk)
    log = os.path.join(h, 'log'); open(log, 'w').close()
    open(os.path.join(b, 'git'), 'w').write(f'#!/bin/sh\necho "git $@" >> {log}\nexit {0 if git else 128}\n'); os.chmod(os.path.join(b, 'git'), 0o755)
    open(os.path.join(sk, 'flow.py'), 'w').write(   # flow.py giả: ghi tham số; setup không --yes trả 1 khi "thiếu"
        f'import sys\nopen({log!r}, "a").write(" ".join(sys.argv[1:]) + "\\n")\n'
        f'sys.exit(1 if {missing} and sys.argv[1:2] == ["setup"] and "--yes" not in sys.argv else 0)\n')
    if lock_ref is not None:
        os.makedirs(os.path.join(h, '.agents')); open(os.path.join(h, '.agents', '.skill-lock.json'), 'w').write(f'{{"skills": {{"rea-flow": {{"ref": "{lock_ref}"}}}}}}')
    if not installed: os.rename(os.path.join(sk, 'flow.py'), os.path.join(h, 'flow.py'))
    open(os.path.join(b, 'npx'), 'w').write(f'#!/bin/sh\necho "npx $@" >> {log}\n'); os.chmod(os.path.join(b, 'npx'), 0o755)
    env = dict(os.environ, HOME=h, PATH=b + ':' + os.environ['PATH'])
    r = subprocess.run(['node', os.path.join(SKILL, 'install.mjs')] + args, env=env, capture_output=True, text=True, stdin=subprocess.DEVNULL, cwd=h)
    out = open(log).read(); shutil.rmtree(h); return r, out

r, o = case(['-g', '-y'])                       # -y: cài skill, quy tắc, kiểm rồi cài công cụ không hỏi
assert 'npx -y skills@' in o and ' add thaoht2109/rea-workflow -g -y' in o and 'rules\n' in o and 'setup\n' in o and 'setup --yes\n' in o, o
r, o = case(['-g', '-y', '--no-ghidra'])        # --no-ghidra chuyển cho setup, không chuyển cho skills CLI
assert 'setup --no-ghidra' in o and 'setup --yes --no-ghidra' in o and 'no-ghidra' not in o.splitlines()[0], o
r, o = case(['-g', '-y', '--no-tools'])         # --no-tools: chỉ kiểm
assert 'setup\n' in o and '--yes' not in o.replace(' -y', '') and 'setup --yes' not in o, o
r, o = case(['-g'])                             # không -y, không có terminal: chỉ kiểm, in lệnh cài
assert 'setup --yes' not in o and 'setup --yes' in r.stdout, (o, r.stdout)
r, o = case(['-g', '-y'], missing=False)        # đủ công cụ: không chạy setup --yes
assert 'setup --yes' not in o, o
r, o = case(['update', '-g', '-y'])             # update: skills update thay cho add, rồi quy tắc + công cụ như lúc cài
assert ' update rea-flow -g -y' in o and ' add ' not in o and 'rules\n' in o and 'setup --yes\n' in o and 'cập nhật' in r.stdout, (o, r.stdout)
r, o = case(['update', '-g'], git=True)         # skill là bản clone git: git pull, không gọi skills CLI
assert 'pull --ff-only' in o and 'npx' not in o and 'rules\n' in o and 'setup --yes' not in o, o
r, o = case(['update', '-g'], installed=False)  # chưa cài: báo lỗi, không gọi gì
assert r.returncode == 1 and 'Chưa cài' in r.stderr and 'npx' not in o and 'rules' not in o, (r.stderr, o)
r, o = case(['update', '-g', '--to', '1.0.0'])   # --to qua skills CLI: add lại với ref là tag
assert ' add thaoht2109/rea-workflow#v1.0.0 -g' in o and ' update rea-flow' not in o, o
r, o = case(['update', '-g', '--to', 'v1.0.0'], git=True)   # --to bản clone git: fetch tag rồi checkout
assert 'fetch --tags' in o and 'checkout --quiet v1.0.0' in o and 'pull' not in o, o
r, o = case(['update', '-g', '--to', 'main;rm'])  # --to sai dạng: dừng, không gọi gì
assert r.returncode == 1 and 'npx' not in o and 'rules' not in o, o
r, o = case(['update', '-g'], lock_ref='v1.0.0')  # đang ghim tag mà update không --to: add lại không ref (về main)
assert ' add thaoht2109/rea-workflow -g' in o and ' update rea-flow' not in o, o
r, o = case(['version', '-g'])                  # version chuyển cho flow.py
assert 'version\n' in o and 'npx' not in o, o
print('OK test_installer')
