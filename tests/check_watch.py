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
if os.environ.get('FAKE_NOTES'): open(c + '/work/NOTES.md', 'a').write('x\n')
if os.environ.get('FAKE_SOFT'): os.makedirs(c + '/work/scripts', exist_ok=True); open(c + '/work/scripts/h%d.py' % len(glob.glob(c + '/work/scripts/*')), 'w').write('#\n')
s = glob.glob(c + '/work/sample/*')[0]
x = os.environ.get('FAKE_EXEC', '')
cmd = {'sh': f'cd x && bash {s}', 'watch': 'cd /x && python3 /x/flow.py watch inbox --once', 'pyw': "python3 -c \"import watch; watch.main(['inbox'])\"", 'grepw': 'grep -n "flow.py watch" SKILL.md', 'grepm': 'grep -n "watch.main(" watch.py', 'fromw': "python3 -c \"from watch import main; main(['inbox'])\"", 'grepsub': 'grep -n subprocess flow.py watch.py', 'subw': "python3 -c \"import os; os.system('python3 flow.py watch inbox')\"", 'py': f"python3 -c \"import os; os.system('sh {s}')\"", 'cpx': f'cp {s} /tmp/zz9 && sh /tmp/zz9', 'cp1': f'cp {s} /tmp/zz8', 'run1': 'sh /tmp/zz8'}.get(x, f'python3 flow.py resume {c}; grep -n bash {s}')
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
    assert len(calls()) == 1 and a[a.index('--model') + 1] == 'mx' and a[a.index('--permission-mode') + 1] == 'default' and a[a.index('--max-turns') + 1] == '80', a
    assert 'Bash(python3:*)' in a[a.index('--allowedTools') + 1] and 'mcp__' not in a[a.index('--allowedTools') + 1] and json.loads(a[a.index('--mcp-config') + 1]) == {'mcpServers': {}} and 'WebFetch' in a[a.index('--disallowedTools') + 1], a
    assert st(c)['sessions'] == 1 and st(c)['stall'] == 1 and os.path.exists(os.path.join(ws, c, 'work', 'runs', 'watch', 's01.jsonl')), st(c)
    # trùng nội dung, tên khác: không tạo case mới; phiên đổi báo cáo -> stall về 0
    drop('copy.sh', '#!/bin/sh\necho hi\n'); W('--model', 'mx', FAKE_TOUCH='1', REA_WATCH_MAX_TURNS='7')   # trần lượt cấu hình được
    assert calls()[-1][calls()[-1].index('--max-turns') + 1] == '7', calls()[-1]
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
    for k in ('sh', 'py', 'cpx', 'mcp', 'watch', 'pyw', 'fromw', 'subw', 'grepw', 'grepm', 'grepsub'):   # shell, os.system trong python3 -c, tool MCP chạy target, watcher lồng; grep chỉ là đọc
        old = set(cases()); drop(f'e{k}.sh', f'echo {k}\n'); W('--model', 'mx', FAKE_EXEC=k)
        e = sorted(set(cases()) - old); assert len(e) == 1 and ('hậu kiểm' in st(e[0]).get('stop', '')) == (not k.startswith('grep')), (k, st(e[0]))
    # bản chép mẫu mang tên khác: chép ở phiên này, chạy ở phiên sau vẫn bị bắt (tên bản chép nhớ trong watch.json "derived")
    old = set(cases()); drop('cpr.sh', 'echo cpr\n'); W('--model', 'mx', FAKE_EXEC='cp1', FAKE_TOUCH='1')
    e = sorted(set(cases()) - old)[0]; assert st(e)['derived'] == ['zz8'] and not st(e).get('stop'), st(e)
    W('--model', 'mx', FAKE_EXEC='run1'); assert 'hậu kiểm' in st(e).get('stop', '') and 'zz8' in st(e)['stop'], st(e)
    # derived sửa tay sai kiểu ("abc": không tách thành từng chữ cái); phiên đọc tĩnh bình thường không bị dừng
    old = set(cases()); drop('dv.sh', 'echo dv\n'); W('--model', 'mx', FAKE_TOUCH='1')
    e = sorted(set(cases()) - old)[0]; j = st(e); j['derived'] = 'abc'; json.dump(j, open(os.path.join(ws, e, 'work', 'watch.json'), 'w'))
    W('--model', 'mx', FAKE_TOUCH='1'); assert not st(e).get('stop') and 'derived' not in st(e), st(e)
    j = st(e); j['stop'] = 'test: dừng'; json.dump(j, open(os.path.join(ws, e, 'work', 'watch.json'), 'w'))
    # luật hậu kiểm theo tên mẫu thật (evals/run.py exec_rules, dùng chung với bộ eval): lệnh chạy mẫu bị bắt; lệnh đọc tĩnh đơn lẻ,
    # công cụ gọi trực tiếp, heredoc chỉ đọc byte thì không
    xp = os.path.join(T, 'XP'); os.makedirs(os.path.join(xp, 'work', 'sample')); open(os.path.join(xp, 'work', 'sample', 'mal.bin'), 'w').close()
    P = watch.exec_pats(xp); S = 'work/sample/mal.bin'; hit = lambda x: any(p.search(x) for p in P)
    MUST = [f"sh -c './{S}'", f'bash -c "{S}"', f'bash {S}', f'bash "{S}"', f'env {S}', f"perl -we 'do \"{S}\"'", f"perl -e 'do \"{S}\"'",
            f"python3 -c \"exec(open('{S}').read())\"", f"python3 -Ic \"exec(open('{S}').read())\"", f"python3 -c \"import os; os.execv('{S}', ['x'])\"",
            f"python3 -c \"import runpy, sys; sys.argv = ['t', '{S}']; runpy.run_path('work/tools/t.py')\"", f"node -e \"require('child_process').execSync('{S}')\"",
            f"python3 -c \"import subprocess; subprocess.run(['{S}'])\"", f"python3 -c \"import os; f=os.system; f('{S}')\"",
            f"python3 - <<'EOF'\nimport subprocess as s\nc = s.call\nc(['{S}'])\nEOF", f"perl -e 'system(\"{S}\")'", f"ruby -e 'system(\"{S}\")'",
            f"python3 -m runpy {S}", f"python3 -c \"import os,subprocess as s; s.call(['{S}'])\"", f"python3 < {S}", f"bash < {S}", f"cat {S} | sh",
            f"busybox sh {S}", f"/lib64/ld-linux-x86-64.so.2 {S}", f"cat {S} | python3 -", f"xxd -r {S} | bash", f"grep -n x {S}; python3 -c \"import os; os.system('{S}')\"",
            f"grep -n x {S}\npython3 -c \"import subprocess; subprocess.run(['{S}'])\"", f"xxd {S} | head\npython3 -c \"import os; os.system('{S}')\"",
            f"cat {S}\nbash {S}", f"ls\nsh {S}",
            'cd work/sample && bash "mal.bin"', f"sh {S}>/tmp/o", f"python3 -W ignore -c \"exec(open('{S}').read())\"", f"python3 -W ignore {S}", f"rg --pre ./x subprocess {S}", f'grep -n \\"x ; python3 -c os.system {S} \\"']   # nhiều dòng, dấu thoát \" (shell thấy ; ngoài nháy): không được miễn trừ đọc tĩnh
    NOT = [f"grep -nE 'popen|system' {S}", f"grep -n \"os.system\" {S}", f"grep -c 'subprocess.Popen' {S} | head", f"python3 -I work/tools/t.py {S} > work/runs/tool/t.out",
           f"python3 -I work/tools/strings.py -e utf16 {S} > o.txt; for f in o.txt; do wc -l $f; done", f"xxd {S} | head", f"sha256sum {S}", f"perl -ne 'print if /http/' {S}",
           f"python3 - <<'EOF'\nprint(open('{S}', 'rb').read()[:4])\nEOF", f"strings {S} | python3 work/tools/x.py", f"grep -n 'popen(' {S}", f"cp {S} report/evidence/x.txt",
           f"file {S}", f"strings -n 6 {S} | grep -i http | head -20", f"python3 flow.py resume c; grep -n bash {S}",
           f"grep -n \"os.system\" {S} > report/evidence/g.txt", f"grep -n popen {S} 2>/dev/null", f"cd work && grep -n subprocess {S} | head -5 2>&1", f"grep -n os.system {S}\n", f"python3 -W ignore work/tools/t.py {S} > o"]
    assert not [x for x in MUST if not hit(x)] and not [x for x in NOT if hit(x)], ([x for x in MUST if not hit(x)], [x for x in NOT if hit(x)])
    big = 'grep ' + 'a1>' * 40 + 'subprocess ' + S; t0 = time.time(); hit(big); assert time.time() - t0 < 2, 'regex backtrack'   # không backtrack hàm mũ
    assert watch.NESTED.search("python3 -Ic \"import watch; watch.main(['inbox'])\"")   # cờ gộp cũng là watch lồng
    # trần số phiên; không --model và không có terminal -> không truyền --model (mặc định của claude)
    drop('m.sh', 'echo m\n'); W(REA_WATCH_MAX_SESSIONS='1', FAKE_TOUCH='1')
    m = [x for x in cases() if x.startswith('m_')][0]
    assert st(m)['stop'] == 'đủ 1 phiên' and '--model' not in calls()[-1], (st(m), calls()[-1])
    # tiến độ mềm: phiên chỉ viết hook trong work/ không tính là "không đổi" (stall về 0) nhưng có trần riêng REA_WATCH_SOFT
    drop('sf.sh', 'echo sf\n'); W('--model', 'mx', FAKE_SOFT='1', REA_WATCH_SOFT='2')
    sf = [x for x in cases() if x.startswith('sf_')][0]; assert st(sf)['soft'] == 1 and st(sf)['stall'] == 0 and not st(sf).get('stop'), st(sf)
    W('--model', 'mx', FAKE_SOFT='1', REA_WATCH_SOFT='2'); assert 'chưa ra fact mới' in st(sf).get('stop', ''), st(sf)
    # trần phiên riêng của case (max_sessions trong watch.json) thay cho REA_WATCH_MAX_SESSIONS
    drop('mx2.sh', 'echo mx2\n'); W('--model', 'mx', REA_WATCH_MAX_SESSIONS='1', FAKE_TOUCH='1')
    m2 = [x for x in cases() if x.startswith('mx2_')][0]; j = st(m2); assert j['stop'] == 'đủ 1 phiên', j
    j.pop('stop'); j['max_sessions'] = 3; json.dump(j, open(os.path.join(ws, m2, 'work', 'watch.json'), 'w'))
    W('--model', 'mx', REA_WATCH_MAX_SESSIONS='1', FAKE_TOUCH='1'); assert st(m2)['sessions'] == 2 and not st(m2).get('stop'), st(m2)
    j = st(m2); j['stop'] = 'test: dừng'; json.dump(j, open(os.path.join(ws, m2, 'work', 'watch.json'), 'w'))   # không chạy tiếp ở các bước sau
    # NOTES.md (prompt bắt cập nhật mỗi phiên) không tính là tiến độ mềm; phiên chỉ đổi work/ xen kẽ phiên không đổi vẫn chạm trần SOFT
    drop('nt.sh', 'echo nt\n'); W('--model', 'mx', FAKE_NOTES='1', REA_WATCH_SOFT='3')
    nt = [x for x in cases() if x.startswith('nt_')][0]; assert (st(nt)['stall'], st(nt)['soft']) == (1, 1) and not st(nt).get('stop'), st(nt)
    W('--model', 'mx', FAKE_SOFT='1', REA_WATCH_SOFT='3'); assert (st(nt)['stall'], st(nt)['soft']) == (0, 2) and not st(nt).get('stop'), st(nt)
    W('--model', 'mx', FAKE_NOTES='1', REA_WATCH_SOFT='3'); assert st(nt)['stall'] == 1 and '3 phiên liên tiếp chưa ra fact mới' in st(nt).get('stop', ''), st(nt)
    # max_sessions sửa tay sai kiểu: chỉ dừng case đó, watcher không sập, không đếm thêm phiên
    drop('bm.sh', 'echo bm\n'); W('--model', 'mx', FAKE_TOUCH='1')
    bm = [x for x in cases() if x.startswith('bm_')][0]; j = st(bm); j['max_sessions'] = 'abc'; json.dump(j, open(os.path.join(ws, bm, 'work', 'watch.json'), 'w'))
    n = len(calls()); W('--model', 'mx', FAKE_TOUCH='1')
    assert 'max_sessions' in st(bm).get('stop', '') and st(bm)['sessions'] == 1 and len(calls()) == n, st(bm)
    drop('z0.sh', 'echo z0\n'); W('--model', 'mx', REA_WATCH_MAX_SESSIONS='0', FAKE_TOUCH='1')   # trần env <= 0: coi như 1, không đổ lỗi cho watch.json
    z0 = [x for x in cases() if x.startswith('z0_')][0]; assert st(z0)['stop'] == 'đủ 1 phiên' and st(z0)['sessions'] == 1, st(z0)
    # watch.json hỏng (sửa tay gõ sai): bỏ qua case, không ghi đè, không mở phiên, không nhận lại mẫu thành case mới
    drop('cj.sh', 'echo cj\n'); W('--model', 'mx', FAKE_TOUCH='1')
    cj = [x for x in cases() if x.startswith('cj_')][0]; pj = os.path.join(ws, cj, 'work', 'watch.json'); bad = '{"sessions": 1, "stop": "x",}'
    open(pj, 'w').write(bad); n = len(calls()); out = W('--model', 'mx')
    assert len(calls()) == n and open(pj).read() == bad and 'BỎ QUA case' in out and [x for x in os.listdir(ws) if x.startswith('cj')] == [cj], out
    json.dump({'sessions': 1, 'stop': 'test: dừng'}, open(pj, 'w'))
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
    # --report: case xong thì báo cáo chép vào Report_<tên INBOX>/<tên mẫu>/<mẫu>_data; không --report thì không xuất; case không do watch nhận mẫu thì bỏ qua
    pc = os.path.join(ws, 'CASE_P'); os.makedirs(os.path.join(pc, 'report'))
    for e in ('md', 'html'): open(os.path.join(pc, 'report', f'report-2026-01-02.{e}'), 'w').write(e)
    assert watch.publish(pc, {'source': os.path.join(inbox, 'invoice.exe'), 'sha256': 'a' * 64}) == ''
    out = watch.publish(pc, {'source': os.path.join(inbox, 'invoice.exe'), 'sha256': 'a' * 64}, 'inbox')
    assert out == os.path.join(T, 'Report_inbox', 'invoice.exe') and os.listdir(out) == ['invoice.exe_data'], out
    assert sorted(os.listdir(os.path.join(out, 'invoice.exe_data'))) == ['MANIFEST.sha256', 'README.txt', 'invoice.exe.html', 'invoice.exe.md', 'report'], out   # export.py
    h = open(os.path.join(out, 'invoice.exe_data', 'invoice.exe.html')).read()
    assert h.startswith('html') and 'id="thong-tin-mau"' in h and watch.publish(pc, {}, 'inbox') == '', h
    assert watch.reported(os.path.join(T, 'Report_inbox')) == {'a' * 64}
    # mẫu trong thư mục con được nhận; bỏ thư mục ẩn, Report_*, workspace nằm trong INBOX (kể cả case trong đó)
    for d in ('devA/sub', '.hid', 'Report_x', 'wsin'):
        os.makedirs(os.path.join(inbox, d)); q = os.path.join(inbox, d, 'n.sh'); open(q, 'w').write(f'echo {d}\n'); os.utime(q, (1, 1))
    old = set(cases()); wsin = os.path.join(inbox, 'wsin')
    r = subprocess.run([sys.executable, os.path.join(SKILL, 'flow.py'), 'watch', inbox, '--once', '--model', 'mx', '--report'], cwd=wsin,
                       env={**E0, 'REA_WATCH_MAX_SESSIONS': '1', 'REA_WATCH_MAX_NEW': '100'}, capture_output=True, text=True, stdin=subprocess.DEVNULL)
    assert r.returncode == 0 and 'CẢNH BÁO: workspace' in r.stdout and 'báo cáo vào ' + os.path.join(T, 'Report_inbox') in r.stdout, r.stdout + r.stderr
    new = [x for x in os.listdir(wsin) if os.path.exists(os.path.join(wsin, x, 'work', 'watch.json'))]
    srcs = sorted(json.load(open(os.path.join(wsin, x, 'work', 'watch.json')))['source'] for x in new)
    assert [x for x in srcs if os.path.dirname(x) != inbox] == [os.path.join(inbox, 'devA', 'sub', 'n.sh')], srcs   # workspace mới: mẫu ở gốc INBOX cũng được nhận lại
    sc = os.path.join(wsin, next(x for x in new if x.startswith('n_'))); stj = json.load(open(os.path.join(sc, 'work', 'watch.json')))
    assert stj['report'] == 'inbox' and stj['inbox'] == inbox, stj
    open(watch.C.report_html(sc), 'w').write('h'); out = watch.publish(sc, stj)
    assert out == os.path.join(T, 'Report_inbox', 'devA', 'sub') and os.path.isfile(os.path.join(out, 'n.sh_data', 'n.sh.html')), out
    assert set(cases()) == old
    r = subprocess.run([sys.executable, os.path.join(SKILL, 'flow.py'), 'watch', inbox, '--once', '--model', 'mx'], cwd=inbox, env=E0, capture_output=True, text=True, stdin=subprocess.DEVNULL)
    assert r.returncode == 2 and 'không được trùng INBOX' in r.stdout, r.stdout + r.stderr   # workspace trùng INBOX: từ chối
    print('OK test_watch')
finally: shutil.rmtree(T, ignore_errors=True)
