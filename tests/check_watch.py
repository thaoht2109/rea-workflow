#!/usr/bin/env python3
"""Test flow.py watch với claude giả trong PATH: nhận mẫu theo sha256 (chống trùng, chờ file đứng yên), mỗi vòng một phiên theo next,
khóa theo case, dừng khi fact không đổi / đủ trần / hậu kiểm thấy lệnh chạy mẫu / STOPPED, chọn model.
Chạy: python3 tests/check_watch.py"""
import os, sys, json, glob, time, fcntl, shutil, tempfile, subprocess

SKILL = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), '..'))
sys.path.insert(0, SKILL); import watch   # noqa: E402
from evals.run import fx_stopped_case, mk_case   # noqa: E402
HELP = "Options:\n  --model <model>   Model for the session. Use an alias (e.g.\n      'fable', 'opus', or 'sonnet') or a\n      model's full name.\n  -n, --name <name>  x"
FAKE = r'''#!/usr/bin/env python3
import sys, os, re, json, glob
a = sys.argv[1:]
if '--help' in a: print(HELP_TEXT); sys.exit()
open(os.environ['FAKE_LOG'], 'a').write(json.dumps(a) + '\n')
c = re.search(r'case `([^`]+)`', a[a.index('-p') + 1])[1]
if os.environ.get('FAKE_TOUCH'): open(glob.glob(c + '/report/report-*.md')[0], 'a').write('x\n')
s = glob.glob(c + '/work/sample/*')[0]
x = os.environ.get('FAKE_EXEC', '')
cmd = {'sh': f'cd x && bash {s}', 'watch': 'cd /x && python3 /x/flow.py watch inbox --once', 'pyw': "python3 -c \"import watch; watch.main(['inbox'])\"", 'grepw': 'grep -n "flow.py watch" SKILL.md', 'grepm': 'grep -n "watch.main(" watch.py', 'fromw': "python3 -c \"from watch import main; main(['inbox'])\"", 'grepsub': 'grep -n subprocess flow.py watch.py', 'subw': "python3 -c \"import os; os.system('python3 flow.py watch inbox')\"", 'py': f"python3 -c \"import os; os.system('sh {s}')\""}.get(x, f'python3 flow.py resume {c}; grep -n bash {s}')
use = {'type': 'tool_use', 'name': 'mcp__frida__spawn', 'input': {'target': s}} if x == 'mcp' else {'type': 'tool_use', 'name': 'Bash', 'input': {'command': cmd}}
print(json.dumps({'type': 'assistant', 'message': {'content': [use]}}))
print(json.dumps({'type': 'result', 'is_error': False, 'result': 'ok'}))
'''.replace('HELP_TEXT', repr(HELP))
assert watch.models(HELP) == ['fable', 'opus', 'sonnet']
T = tempfile.mkdtemp(prefix='rea-watch-')
try:
    ws, inbox, H, fb = (os.path.join(T, x) for x in ('ws', 'inbox', 'home', 'bin'))
    for d in (ws, inbox, H, fb): os.makedirs(d)
    open(os.path.join(fb, 'claude'), 'w').write(FAKE); os.chmod(os.path.join(fb, 'claude'), 0o700)
    log = os.path.join(T, 'log')
    E0 = {**{k: v for k, v in os.environ.items() if k != 'CLAUDE_CONFIG_DIR' and not k.startswith('REA_')}, 'HOME': H,
          'PATH': fb + ':' + os.environ['PATH'], 'FAKE_LOG': log, 'REA_WATCH_STALL': '2'}
    def drop(n, body):
        p = os.path.join(inbox, n); open(p, 'w').write(body); os.utime(p, (1, 1)); return p   # mtime cũ: coi như đã chép xong
    def W(*x, **e):
        r = subprocess.run([sys.executable, os.path.join(SKILL, 'flow.py'), 'watch', inbox, '--once', *x], cwd=ws, env={**E0, **e},
                           capture_output=True, text=True, stdin=subprocess.DEVNULL)
        assert r.returncode == 0, r.stdout + r.stderr; return r.stdout
    calls = lambda: [json.loads(l) for l in open(log)] if os.path.exists(log) else []
    cases = lambda: sorted(x for x in os.listdir(ws) if os.path.exists(os.path.join(ws, x, 'work', 'watch.json')))
    st = lambda c: json.load(open(os.path.join(ws, c, 'work', 'watch.json')))
    drop('s.sh', '#!/bin/sh\necho hi\n'); open(os.path.join(inbox, 'fresh.bin'), 'w').write('đang chép')   # file mới ghi: chưa nhận
    out = W('--model', 'mx')
    cs = cases(); assert len(cs) == 1 and cs[0].startswith('s_'), (cs, out)
    c = cs[0]; a = calls()[-1]
    os.remove(os.path.join(inbox, 'fresh.bin'))   # đã kiểm: chưa nhận; xóa để vòng sau (đã quá SETTLE) không nhận
    assert len(calls()) == 1 and a[a.index('--model') + 1] == 'mx' and a[a.index('--permission-mode') + 1] == 'default', a
    assert 'Bash(python3:*)' in a[a.index('--allowedTools') + 1] and 'mcp__' not in a[a.index('--allowedTools') + 1] and json.loads(a[a.index('--mcp-config') + 1]) == {'mcpServers': {}} and 'WebFetch' in a[a.index('--disallowedTools') + 1], a
    assert st(c)['sessions'] == 1 and st(c)['stall'] == 1 and os.path.exists(os.path.join(ws, c, 'work', 'runs', 'watch', 's01.jsonl')), st(c)
    # trùng nội dung, tên khác: không tạo case mới; phiên đổi báo cáo -> stall về 0
    drop('copy.sh', '#!/bin/sh\necho hi\n'); W('--model', 'mx', FAKE_TOUCH='1')
    assert cases() == [c] and st(c)['sessions'] == 2 and st(c)['stall'] == 0, (cases(), st(c))
    # case đang bị giữ khóa: không mở phiên
    with open(os.path.join(ws, c, 'work', '.watch.lock'), 'a') as f:
        fcntl.flock(f, fcntl.LOCK_EX); W('--model', 'mx')
    assert len(calls()) == 2
    # 2 phiên liên tiếp không đổi -> dừng, vòng sau không gọi claude
    W('--model', 'mx'); out = W('--model', 'mx')
    assert 'không đổi' in st(c).get('stop', '') and 'DỪNG' in out, (st(c), out)
    n = len(calls()); W('--model', 'mx'); assert len(calls()) == n
    # hậu kiểm: phiên chạy mẫu -> dừng case (grep tên mẫu ở trên không bị bắt nhầm)
    for k in ('sh', 'py', 'mcp', 'watch', 'pyw', 'fromw', 'subw', 'grepw', 'grepm', 'grepsub'):   # shell, os.system trong python3 -c, tool MCP chạy target, watcher lồng; grep chỉ là đọc
        old = set(cases()); drop(f'e{k}.sh', f'echo {k}\n'); W('--model', 'mx', FAKE_EXEC=k)
        e = sorted(set(cases()) - old); assert len(e) == 1 and ('hậu kiểm' in st(e[0]).get('stop', '')) == (not k.startswith('grep')), (k, st(e[0]))
    # trần số phiên; không --model và không có terminal -> không truyền --model (mặc định của claude)
    drop('m.sh', 'echo m\n'); W(REA_WATCH_MAX_SESSIONS='1', FAKE_TOUCH='1')
    m = [x for x in cases() if x.startswith('m_')][0]
    assert st(m)['stop'] == 'đủ 1 phiên' and '--model' not in calls()[-1], (st(m), calls()[-1])
    # case STOPPED (phản biện FAIL 2 lần): báo người, không mở phiên, không tự OVERRIDE
    n = len(calls()); fx_stopped_case(ws); json.dump({'sha256': 'x'}, open(os.path.join(ws, 'CASE_E3', 'work', 'watch.json'), 'w'))
    W('--model', 'mx'); assert st('CASE_E3')['stop'].startswith('STOPPED') and len(calls()) == n, st('CASE_E3')
    assert not glob.glob(os.path.join(ws, '*', 'work', 'review', 'OVERRIDE'))
    # đủ checklist, chưa phản biện -> review nền (không mở phiên); lớp 2 manual chờ người -> dừng case
    r3 = mk_case(ws, 'CASE_R', [('s.url', 'url', 'http://cdn.c2.invalid/a.bin')]); json.dump({f'C{i}': 'test' for i in range(1, 12)}, open(os.path.join(r3, 'work', 'accepted.json'), 'w'))
    json.dump({'sha256': 'y'}, open(os.path.join(r3, 'work', 'watch.json'), 'w'))
    for _ in range(60):
        W('--model', 'mx', REVIEW_LLM='manual')
        if st('CASE_R').get('stop'): break
        time.sleep(0.5)
    assert 'review lớp 2 cần người' in st('CASE_R').get('stop', '') and len(calls()) == n, st('CASE_R')
    r = subprocess.run([sys.executable, os.path.join(SKILL, 'flow.py'), 'watch'], capture_output=True, text=True); assert r.returncode == 2, r.stdout
    r = subprocess.run([sys.executable, os.path.join(SKILL, 'flow.py'), 'watch', inbox, '--once', '--model'], cwd=ws, env=E0, capture_output=True, text=True)
    assert r.returncode == 2 and '--model cần' in r.stdout, r.stdout + r.stderr
    print('OK test_watch')
finally: shutil.rmtree(T, ignore_errors=True)
