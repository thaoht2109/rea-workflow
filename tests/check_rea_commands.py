#!/usr/bin/env python3
"""Đối chiếu danh sách lệnh rea trong FLOW.md mục 4a với `rea --help` (bắt lệnh đổi tên/bỏ khi nâng rea). Chạy: python3 tests/check_rea_commands.py"""
import os, re, shutil, subprocess

SKILL = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), '..'))
t = open(os.path.join(SKILL, 'FLOW.md'), encoding='utf-8').read()
sec = t.split('### 4a.', 1)[1].split('\n## ', 1)[0]
allow_part, deny_part = sec.split('**Cấm trên mẫu:**', 1)
allow = {c for c in re.findall(r'`([a-z][a-z0-9-]+)`', allow_part) if c not in ('flow.py', 'rea')} - {'reverse-engineer-anything'}
deny = re.findall(r'`([a-z*][a-z0-9*-]+)`', deny_part.split('Lệnh không có')[0])
if not shutil.which('rea'): print('SKIP test_rea_commands (không có rea)'); raise SystemExit
have = set(re.findall(r'^\s{2}([a-z][a-z0-9-]+)\s', subprocess.run(['rea', '--help'], capture_output=True, text=True).stdout, re.M))
missing = sorted(allow - have); assert not missing, f'lệnh rea trong danh sách được phép không còn tồn tại: {missing}'
pats = [re.compile('^' + d.replace('*', '.*') + '$') for d in deny]
assert not [c for c in allow if any(p.match(c) for p in pats)], 'lệnh vừa được phép vừa bị cấm'
for p in pats: assert any(p.match(c) for c in have), f'mẫu cấm {p.pattern} không khớp lệnh nào'
risky = sorted(c for c in have if re.match(r'(capture|debug|observe|instrument|start-adb|install-adb)', c) and c in allow)
assert not risky, risky
print(f'OK test_rea_commands ({len(allow)} lệnh được phép, {len(deny)} mẫu cấm, rea có {len(have)} lệnh)')
