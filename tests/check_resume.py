#!/usr/bin/env python3
"""Test flow.py resume và case.py show --id / search (làm tiếp sau khi ngữ cảnh bị nén). Chạy: python3 tests/check_resume.py"""
import os, sys, tempfile, shutil, subprocess

SKILL = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), '..'))
sys.path.insert(0, SKILL); import case as C
run = lambda *a: subprocess.run([sys.executable, os.path.join(SKILL, a[0])] + list(a[1:]), capture_output=True, text=True, check=True).stdout

c = tempfile.mkdtemp(prefix='rea-resume-')
try:
    os.makedirs(os.path.join(c, 'report', 'evidence')); os.makedirs(os.path.join(c, 'work', 'runs'))
    open(os.path.join(c, 'report', 'evidence', 'e.txt'), 'w').write('a' * 64 + ' s.exe\nhttp://evil.example/x\nRun key Updater\n')
    E = 'report/evidence/e.txt'
    C.add(c, id='h', kind='hash', value='a' * 64 + ' s.exe', src='S', evidence=E)
    C.add(c, id='u0', kind='url', value='http://old.example/x', src='S', evidence=E, status='hypothesis')
    C.add(c, id='u1', kind='url', value='http://evil.example/x', src='S', evidence=E + '#L2', supersedes='u0')
    C.add(c, id='p', kind='persistence', value='Run key Updater', src='S', evidence=E + '#L3', status='hypothesis')
    r = run('flow.py', 'resume', c)
    assert 'http://evil.example/x @ report/evidence/e.txt#L2' in r and 'old.example' not in r, r   # fact kết luận nguyên văn, bản bị thay không còn
    assert '1 hash: case.py show' in r and 'a' * 64 not in r, r                                     # hash chỉ đếm
    assert '## Giả thuyết còn mở (1)' in r and 'Run key Updater' in r and '## Việc kế tiếp' in r, r
    s = run('case.py', 'search', c, 'evil')
    assert 'u1' in s and '1 fact khớp' in s, s
    assert '0 fact khớp' in run('case.py', 'search', c, 'old.example') and 'u0' in run('case.py', 'search', c, 'old.example', '--all')
    assert 'p ' in run('case.py', 'search', c, 'run', '--src', 'S') and '0 fact khớp' in run('case.py', 'search', c, 'run', '--src', 'E')
    sh = run('case.py', 'show', c, '--id', 'u0')
    assert '"retracted"' in sh and 'bị thay bởi u1' in sh, sh
    print('OK test_resume')
finally: shutil.rmtree(c, ignore_errors=True)
