#!/usr/bin/env python3
"""Chạy --selftest của case.py, review.py, reviewer.py (luật checklist, cổng phản biện, lớp 2) để CI phủ chúng. Chạy: python3 tests/check_selftest.py"""
import os, subprocess, sys
SKILL = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), '..'))
for m in ('case.py', 'review.py', 'reviewer.py'):
    r = subprocess.run([sys.executable, os.path.join(SKILL, m), '--selftest'], capture_output=True, text=True, timeout=240, cwd=SKILL)
    assert r.returncode == 0 and 'selftest' in r.stdout and 'OK' in r.stdout, (m, (r.stdout + r.stderr)[-1500:])
print('ok')
