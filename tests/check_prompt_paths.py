#!/usr/bin/env python3
"""Prompt gửi LLM phản biện không chứa đường dẫn tuyệt đối dưới HOME (lộ tên người dùng): reviewer.short_home. Chạy: python3 tests/check_prompt_paths.py"""
import os, sys, tempfile, subprocess

SKILL = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), '..'))
home = tempfile.mkdtemp(prefix='rea-home-')
code = f'''import sys, os; sys.path.insert(0, {SKILL!r}); import reviewer as R
h = os.path.expanduser("~")
assert R.short_home(h + "/.local/share/rea-flow/pylib") == "~/.local/share/rea-flow/pylib"
assert R.short_home(h) == "~" and R.short_home("/opt/pylib") == "/opt/pylib" and R.short_home(h + "x/pylib") == h + "x/pylib"
p = open(os.path.join(R.HERE, "review", "re-reviewer-tools.md"), encoding="utf-8").read().replace("{{PYLIB}}", R.short_home(h + "/.local/share/rea-flow/pylib"))
assert h not in p and "os.path.expanduser('~/.local/share/rea-flow/pylib')" in p, p[:400]
print("ok")'''
r = subprocess.run([sys.executable, '-c', code], capture_output=True, text=True, env=dict(os.environ, HOME=home))
assert r.returncode == 0 and 'ok' in r.stdout, r.stdout + r.stderr
print('ok')
