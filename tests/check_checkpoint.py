#!/usr/bin/env python3
"""Test flow.py checkpoint: chỉ cho tách phiên khi mọi kết quả đã thành fact/evidence. Chạy: python3 tests/check_checkpoint.py"""
import os, sys, time, tempfile, shutil, subprocess

SKILL = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), '..'))
sys.path.insert(0, SKILL); import case as C
cp = lambda c: subprocess.run([sys.executable, os.path.join(SKILL, 'flow.py'), 'checkpoint', c], capture_output=True, text=True)

c = tempfile.mkdtemp(prefix='rea-ckpt-')
try:
    os.makedirs(os.path.join(c, 'report', 'evidence')); os.makedirs(os.path.join(c, 'work', 'runs', 'emu1'))
    open(os.path.join(c, 'report', 'evidence', 'e.txt'), 'w').write('Run key Updater\n')
    C.add(c, id='p', kind='persistence', value='Run key Updater', src='S', evidence='report/evidence/e.txt#L1')
    run = os.path.join(c, 'work', 'runs', 'emu1', 'trace.log'); open(run, 'w').write('x')
    os.utime(run, (time.time() + 3600,) * 2)                       # kết quả chạy mới hơn fact cuối -> chưa chốt
    r = cp(c); assert r.returncode == 1 and 'work/runs/emu1' in r.stdout, r.stdout
    os.utime(run, (time.time() - 3600,) * 2)                       # đã ghi kết luận sau lần chạy -> chốt được
    r = cp(c); assert r.returncode == 0 and 'OK checkpoint' in r.stdout and os.path.exists(os.path.join(c, 'work', 'checkpoint.json')), r.stdout
    C.add(c, id='u', kind='url', value='http://nowhere.example/x', src='S', evidence='report/evidence/e.txt')   # lint fail
    r = cp(c); assert r.returncode == 1 and 'FAIL fact u' in r.stdout, r.stdout
    print('OK test_checkpoint')
finally: shutil.rmtree(c, ignore_errors=True)
