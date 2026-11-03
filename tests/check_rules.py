#!/usr/bin/env python3
# Kiểm `flow.py rules`: phạm vi global/project theo nơi cài skill, ghi idempotent, --check, --remove giữ nội dung người dùng.
#   python3 tests/check_rules.py
import os, sys, shutil, subprocess, tempfile
SRC = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))), 'tools')
H = tempfile.mkdtemp(dir='/var/tmp'); env = dict(os.environ, HOME=H)
ign = shutil.ignore_patterns('.git', 'pylib', '__pycache__')
run = lambda sk, *a, cwd=H: subprocess.run([sys.executable, os.path.join(sk, 'flow.py'), 'rules', *a], cwd=cwd, env=env, capture_output=True, text=True)
R = lambda p: open(p, encoding='utf-8').read()
# global: skill ở ~/.agents/skills/rea-flow; chỉ agent có thư mục cấu hình mới được ghi
G = os.path.join(H, '.agents', 'skills', 'rea-flow'); shutil.copytree(SRC, G, ignore=ign)
os.makedirs(os.path.join(H, '.claude')); os.makedirs(os.path.join(H, '.codex'))
open(os.path.join(H, '.claude', 'CLAUDE.md'), 'w').write('# của người dùng\n')
assert run(G, '--check').returncode == 1
r = run(G); assert r.returncode == 0 and 'phạm vi: global' in r.stdout, r.stdout + r.stderr
c = R(os.path.join(H, '.claude', 'CLAUDE.md')); assert c.startswith('# của người dùng') and 'Không bao giờ thực thi mẫu' in c and '$SKILL' not in c, c
assert os.path.exists(os.path.join(H, '.codex', 'AGENTS.md')) and not os.path.exists(os.path.join(H, '.gemini'))
assert 'không đổi' in run(G).stdout and run(G, '--check').returncode == 0
# project: skill ở <proj>/.agents/skills/rea-flow -> chỉ ghi vào <proj>
P = os.path.join(H, 'proj'); PS = os.path.join(P, '.agents', 'skills', 'rea-flow'); shutil.copytree(SRC, PS, ignore=ign)
r = run(PS); assert 'phạm vi: project' in r.stdout and os.path.exists(os.path.join(P, 'AGENTS.md')) and os.path.exists(os.path.join(P, 'CLAUDE.md')), r.stdout
# gỡ: file chỉ có khối của rea-flow bị xóa, file có nội dung người dùng được giữ
run(G, '--remove'); run(PS, '--remove')
assert R(os.path.join(H, '.claude', 'CLAUDE.md')).strip() == '# của người dùng' and not os.path.exists(os.path.join(H, '.codex', 'AGENTS.md'))
assert not os.path.exists(os.path.join(P, 'AGENTS.md'))
shutil.rmtree(H); print('OK test_rules')
