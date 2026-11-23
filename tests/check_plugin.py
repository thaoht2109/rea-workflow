#!/usr/bin/env python3
"""Test plugin Claude Code: .claude-plugin/plugin.json + plugin-skills/manual, plugin-skills/auto, plugin-skills/all (gọi là rea-workflow:manual / :auto / :all).
Lệnh flow.py mà skill con nhắc phải có trong flow.py help; SKILL.md gốc vẫn là nguồn quy tắc. Chạy: python3 tests/check_plugin.py
Đã kiểm tay với Claude Code 2.1.327 (CI không có claude): thư mục trong ~/.claude/skills có plugin.json được nạp thành
rea-workflow@skills-dir với đúng hai skill auto, manual (`claude plugin details`); skills@1.7.4 chỉ cài một skill rea-workflow."""
import os, re, json, shutil, subprocess

SKILL = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), '..'))
rd = lambda *p: open(os.path.join(SKILL, *p), encoding='utf-8').read()
pj = json.loads(rd('.claude-plugin', 'plugin.json'))
assert pj['name'] == 'rea-workflow' and pj['skills'] == './plugin-skills/' and 'version' not in pj, pj
assert not os.path.exists(os.path.join(SKILL, 'skills'))   # skills CLI có thể quét skills/: skill con chỉ nằm ở plugin-skills/   # version chỉ ở package.json (tag.yml); không chép để khỏi lệch
helps = rd('flow.py').split('\nimport', 1)[0]
cmds = set(re.findall(r'flow\.py (\w[\w-]*)', helps))
for n in ('manual', 'auto', 'all'):
    t = rd('plugin-skills', n, 'SKILL.md'); fm = re.match(r'---\n(.*?)\n---\n', t, re.S)[1]
    assert re.search(rf'^name: {n}$', fm, re.M) and re.search(r'^description: .{80,}', fm, re.M), fm
    assert '${CLAUDE_PLUGIN_ROOT}' in t and 'Không bao giờ thực thi mẫu' in fm and '$SKILL/SKILL.md' in t, n   # trỏ về quy tắc gốc, không chép
    bad = set(re.findall(r'flow\.py (\w[\w-]*)', t)) - cmds; assert not bad, (n, bad)
assert 'flow.py watch' in rd('plugin-skills', 'auto', 'SKILL.md') and 'flow.py new' in rd('SKILL.md')
root = rd('SKILL.md')
assert 'rea-workflow:manual' in root and 'rea-workflow:auto' in root and '$SKILL/plugin-skills/auto/SKILL.md' in root
assert 'rea-workflow:all' in root and '$SKILL/plugin-skills/all/SKILL.md' in root and 'flow.py scan' in rd('plugin-skills', 'all', 'SKILL.md') and 'rea-workflow:all' in pj['description']
assert 'Hai chế độ' not in root.split('## Quy tắc bắt buộc', 1)[1].split('\n## ', 1)[0]   # flow.py rules chỉ chép mục quy tắc
if shutil.which('claude'):
    r = subprocess.run(['claude', 'plugin', 'validate', SKILL], capture_output=True, text=True, timeout=120)
    assert r.returncode == 0, r.stdout + r.stderr
print('OK test_plugin')
