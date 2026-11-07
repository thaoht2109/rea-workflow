#!/usr/bin/env python3
"""Test review --detach: chạy nền gọi lặp lại được, khoá chống chạy review song song. Chạy: python3 tests/check_detach.py"""
import os, sys, time, tempfile, shutil, subprocess

HERE = os.path.dirname(os.path.abspath(__file__))
SKILL = os.path.normpath(os.path.join(HERE, '..'))
sys.path.insert(0, SKILL)
import case as C, review as R

c = tempfile.mkdtemp(prefix='rea-detach-')
try:
    os.makedirs(os.path.join(c, 'report', 'evidence'))
    open(os.path.join(c, 'report', 'evidence', 's.txt'), 'w').write('noi dung day du\n')
    C.add(c, id='f1', kind='string', value='noi dung', src='S', evidence='report/evidence/s.txt')
    flow = [sys.executable, os.path.join(SKILL, 'flow.py'), 'review', c, '--detach']
    # 1. lần đầu khởi chạy nền (6), gọi lại tới khi có kết quả thật (0 = PASS)
    assert subprocess.run(flow, capture_output=True).returncode == 6
    for _ in range(100):
        r = subprocess.run(flow, capture_output=True, text=True)
        if r.returncode != 6: break
        time.sleep(0.2)
    assert r.returncode == 0 and 'XONG' in r.stdout, r.stdout   # không --llm: xem trước PASS; detach vẫn chuyển mã thật ra ngoài
    assert not os.path.exists(os.path.join(R.DIR(c), 'run.pid')) and not os.path.exists(os.path.join(R.DIR(c), 'run.rc'))
    # 2. có tiến trình nền đang chạy: review thường và detach đều không chạy chồng (6)
    sl = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(10)', '_bg'])
    open(os.path.join(R.DIR(c), 'run.pid'), 'w').write(str(sl.pid))
    try:
        assert R.review(c) == 6
        assert subprocess.run(flow, capture_output=True).returncode == 6
    finally: sl.kill(); sl.wait()
    # 3. tiến trình nền chết không ghi kết quả: báo 7, gọi lại thì chạy lại
    assert subprocess.run(flow, capture_output=True).returncode == 7
    assert not os.path.exists(os.path.join(R.DIR(c), 'run.pid'))
    print('OK test_detach')
finally: shutil.rmtree(c, ignore_errors=True)
