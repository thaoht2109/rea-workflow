#!/usr/bin/env python3
"""Test plugin Claude Code: .claude-plugin/plugin.json + skills/manual, skills/auto (gọi là rea-workflow:manual / :auto).
Lệnh flow.py mà skill con nhắc phải có trong flow.py help; SKILL.md gốc vẫn là nguồn quy tắc. Chạy: python3 tests/check_plugin.py"""
import os, re, json, shutil, subprocess

SKILL = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), '..'))
rd = lambda *p: open(os.path.join(SKILL, *p), encoding='utf-8').read()
pj = json.loads(rd('.claude-plugin', 'plugin.json'))
assert pj['name'] == 'rea-workflow' and 'version' not in pj, pj   # version chỉ ở package.json (tag.yml); không chép để khỏi lệch
helps = rd('flow.py').split('\nimport', 1)[0]
cmds = set(re.findall(r'flow\.py (\w[\w-]*)', helps))
for n in ('manual', 'auto'):
    t = rd('skills', n, 'SKILL.md'); fm = re.match(r'---\n(.*?)\n---\n', t, re.S)[1]
    assert re.search(rf'^name: {n}$', fm, re.M) and re.search(r'^description: .{80,}', fm, re.M), fm
    assert '${CLAUDE_PLUGIN_ROOT}' in t and 'Không bao giờ thực thi mẫu' in fm and '$SKILL/SKILL.md' in t, n   # trỏ về quy tắc gốc, không chép
    bad = set(re.findall(r'flow\.py (\w[\w-]*)', t)) - cmds; assert not bad, (n, bad)
assert 'flow.py watch' in rd('skills', 'auto', 'SKILL.md') and 'flow.py new' in rd('SKILL.md')
root = rd('SKILL.md')
assert 'rea-workflow:manual' in root and 'rea-workflow:auto' in root and '$SKILL/skills/auto/SKILL.md' in root
assert 'Hai chế độ' not in root.split('## Quy tắc bắt buộc', 1)[1].split('\n## ', 1)[0]   # flow.py rules chỉ chép mục quy tắc
if shutil.which('claude'):
    r = subprocess.run(['claude', 'plugin', 'validate', SKILL], capture_output=True, text=True, timeout=120)
    assert r.returncode == 0, r.stdout + r.stderr
print('OK test_plugin')
