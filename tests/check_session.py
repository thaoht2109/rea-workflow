#!/usr/bin/env python3
"""Test flow.py session: giữ MCP/plugin/skill dịch ngược, tắt phần không liên quan và hook, nạp SKILL.md + ghi chú workspace; --strict dùng --safe-mode.
Chạy: python3 tests/check_session.py"""
import os, sys, json, shlex, tempfile, shutil, subprocess

SKILL = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), '..'))
ws = tempfile.mkdtemp(prefix='rea-ws-')
try:
    open(os.path.join(ws, 'CLAUDE.md'), 'w').write('ghi chú riêng: dùng tiếng Việt\n\n<!-- rea-flow:rules:begin (sinh bởi flow.py rules; sửa SKILL.md rồi chạy lại) -->\nKHỐI CŨ\n<!-- rea-flow:rules:end -->\n')
    # HOME giả: MCP/plugin/skill của "máy" để kiểm lọc theo dịch ngược
    H = tempfile.mkdtemp(); os.makedirs(os.path.join(H, '.claude')); os.makedirs(os.path.join(H, '.agents', 'skills', 'rev')); os.makedirs(os.path.join(H, '.agents', 'skills', 'ui'))
    json.dump({'mcpServers': {'ghidra-mcp': {'command': 'x'}, 'gmail': {'command': 'y'}, 'tool1': {'command': 'npx', 'args': ['rea-agents', 'mcp']}}}, open(os.path.join(H, '.claude.json'), 'w'))
    json.dump({'enabledPlugins': {'ponytail@p': True, 'ida-helper@m': True, 'old@x': False}}, open(os.path.join(H, '.claude', 'settings.json'), 'w'))
    open(os.path.join(H, '.agents', 'skills', 'rev', 'SKILL.md'), 'w').write('---\nname: rev-x\ndescription: Reverse engineer binaries\n---\n')
    open(os.path.join(H, '.agents', 'skills', 'ui', 'SKILL.md'), 'w').write('---\nname: ui-x\ndescription: Make web pages pretty\n---\n')
    E0 = dict(os.environ, HOME=H)
    run = lambda env=None, *x: subprocess.run([sys.executable, os.path.join(SKILL, 'flow.py'), 'session', '--print', *x, '-p'], cwd=ws, capture_output=True, text=True, env=env)
    r = run(E0)
    if shutil.which('claude'):
        argv = shlex.split(r.stdout.strip().splitlines()[-1])
        assert r.returncode == 0 and '--strict-mcp-config' in argv and argv[-1] == '-p' and '--safe-mode' not in argv, r.stdout
        st = json.loads(argv[argv.index('--settings') + 1])
        assert st['disableAllHooks'] and st['enabledPlugins'] == {'ponytail@p': False}, st          # chỉ tắt plugin không liên quan
        mcp = json.load(open(argv[argv.index('--mcp-config') + 1]))['mcpServers']
        assert set(mcp) == {'ghidra-mcp', 'tool1'}, mcp                                                 # giữ MCP dịch ngược theo tên/lệnh
        assert oct(os.stat(argv[argv.index('--mcp-config') + 1]).st_mode & 0o777) == '0o600'
        p = open(argv[argv.index('--append-system-prompt-file') + 1], encoding='utf-8').read()
        assert 'flow.py checkpoint' in p and '$SKILL' not in p and os.path.realpath(SKILL) in p, p[:300]   # SKILL.md đã thay đường dẫn
        assert 'ghi chú riêng: dùng tiếng Việt' in p and 'KHỐI CŨ' not in p, p[-300:]                     # giữ ghi chú, bỏ khối quy tắc trùng
        assert 'rev-x' in p and 'ui-x' not in p and 'quy tắc rea-flow thắng' in p, p                     # trỏ tới skill dịch ngược khác
        s = shlex.split(run(E0, '--strict').stdout.strip().splitlines()[-1])
        assert '--safe-mode' in s and '--strict' not in s, s
    shutil.rmtree(H)
    env = dict(os.environ, PATH=tempfile.mkdtemp())                # máy không có claude
    r = run(env); assert r.returncode == 2 and 'chỉ hỗ trợ Claude Code' in r.stdout, r.stdout
    # hàm shell: cài 2 lần vẫn 1 khối; trong workspace (kể cả thư mục con) -> session, ngoài -> claude thật; gỡ sạch
    rc = os.path.join(ws, 'rc'); open(rc, 'w').write('export A=1\n')
    fake = tempfile.mkdtemp(); open(os.path.join(fake, 'claude'), 'w').write('#!/bin/sh\necho REAL "$@"\n'); os.chmod(os.path.join(fake, 'claude'), 0o755)
    E = dict(os.environ, REA_SHELL_RC=rc, PATH=fake + ':' + os.environ['PATH'])
    fl = [sys.executable, os.path.join(SKILL, 'flow.py'), 'session']
    for _ in range(2): subprocess.run(fl + ['--install', ws], env=E, capture_output=True, check=True)
    assert open(rc).read().count('rea-flow session >>>') == 1, open(rc).read()
    os.makedirs(os.path.join(ws, 'CASE1'))
    sh = lambda d: subprocess.run(['bash', '-c', f'source {rc}; cd {d} && claude --print -x'], env=E, capture_output=True, text=True).stdout
    assert '--append-system-prompt-file' in sh(os.path.join(ws, 'CASE1')) and sh(ws).rstrip().endswith('-x'), sh(ws)
    assert sh(fake).strip() == 'REAL --print -x', sh(fake)
    # agent khác: trong workspace thì cập nhật quy tắc vào AGENTS.md rồi chạy agent thật
    open(os.path.join(fake, 'codex'), 'w').write('#!/bin/sh\necho CODEX "$@"\n'); os.chmod(os.path.join(fake, 'codex'), 0o755)
    o = subprocess.run(['bash', '-c', f'source {rc}; cd {ws}/CASE1 && codex -q'], env=E, capture_output=True, text=True).stdout
    assert o.strip() == 'CODEX -q' and 'rea-flow:rules:begin' in open(os.path.join(ws, 'AGENTS.md')).read(), o
    subprocess.run(fl + ['--uninstall'], env=E, capture_output=True, check=True)
    assert open(rc).read() == 'export A=1\n', repr(open(rc).read())
    shutil.rmtree(fake)
    print('OK test_session')
finally: shutil.rmtree(ws, ignore_errors=True)
