#!/usr/bin/env python3
# winemu --snap-unhandled và winemu/step.py (một bước resume từ lượt cuối). Không cần unicorn:
#   - đoạn nguồn thật của winemu (nhánh API chưa hỗ trợ, finish) được trích rồi exec trong namespace giả;
#   - step.py chạy thật, cạnh một winemu.py giả ghi events.jsonl theo kịch bản trong biến môi trường.
# Dữ liệu tổng hợp, không chạy mẫu.   python3 tests/check_winemu_step.py
import os, re, sys, json, types, shutil, tempfile, subprocess, collections, time
SRC = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
src = open(os.path.join(SRC, 'winemu', 'winemu.py'), encoding='utf-8').read()

# ---- 1. cờ và nhánh API chưa hỗ trợ trong winemu ----
assert re.search(r"AP\.add_argument\('--snap-unhandled', action='store_true'", src), 'thiếu cờ --snap-unhandled'
m = re.search(r'\n(    if res is None:\n.*?uc\.emu_stop\(\); return\n)', src, re.S)
assert m, 'không tìm thấy nhánh res is None'
fn = 'def h(uc, dll, name, caller, addr, res):\n' + m.group(1) + "    return 'tiếp'\n"

def run_unhandled(snap):
    calls = []
    ns = {'os': os, 'A': types.SimpleNamespace(snap_unhandled=snap, out='/o'), 'CTX': {'stop': False}, 'log': lambda *a: None,
          'save_snapshot': lambda p, e: calls.append(('snap', p, e)), 'ev': lambda k, **kw: calls.append((k, kw))}
    exec(fn, ns)   # nosec B102 - chạy đúng đoạn nguồn winemu vừa trích ở trên (không phải input ngoài)
    uc = types.SimpleNamespace(emu_stop=lambda: calls.append(('stop',)))
    return ns['h'](uc, 'kernel32.dll', 'FooBar', 0x401000, 0x7ff00010, None), ns['CTX'], calls

r, ctx, calls = run_unhandled(True)
assert r is None and ctx == {'stop': True, 'unhandled': 'kernel32.dll!FooBar'}, (r, ctx)
assert calls[0] == ('snap', '/o/snap_unhandled.bin', 0x7ff00010), calls      # snapshot tại stub, trước khi dừng
assert ('unhandled_snap', {'api': 'FooBar', 'dll': 'kernel32.dll'}) in calls and calls[-1] == ('stop',), calls
r, ctx, calls = run_unhandled(False)                                          # không bật cờ: không ghi snapshot, vẫn ghi CTX
assert ctx['unhandled'] == 'kernel32.dll!FooBar' and not any(c[0] == 'snap' for c in calls), calls

# ---- 2. finish() ghi 'unhandled' vào event end chỉ khi có ----
m = re.search(r'\n(def finish\(reason\):\n.*?)\nt0 = time\.time\(\)', src, re.S)
assert m, 'không tìm thấy finish()'
def run_finish(ctx):
    out = []
    ns = {'ev': lambda k, **kw: out.append(kw), 'mu': types.SimpleNamespace(reg_read=lambda r: 0x1234), 'UC_X86_REG_EIP': 0,
          'CALLS': [5], 'CTX': ctx, 'EXCN': {}, 'collections': collections, 'CCOUNT': {}, 'RESOLVED': set(), 'time': time, 't0': time.time()}
    exec(m.group(1), ns); ns['finish']('stop')   # nosec B102 - đoạn nguồn winemu đã trích
    return out[0]
assert run_finish({'unhandled': 'a.dll!X'})['unhandled'] == 'a.dll!X'
assert 'unhandled' not in run_finish({})

# ---- 3. step.py chạy với winemu giả ----
FAKE = r'''
import sys, os, json
a = sys.argv[1:]; out = a[a.index('--out') + 1]; os.makedirs(out)
json.dump(a, open(os.path.join(out, 'argv.json'), 'w'))
p = json.loads(os.environ['FAKE_ROUND'])
if p.get('crash'): sys.stderr.write('Traceback: giả lập chết\n'); sys.exit(1)
with open(os.path.join(out, 'events.jsonl'), 'w') as f:
    f.write(json.dumps({'kind': 'argstr', 's': '"end" "oep"'}) + '\n{hỏng\n')   # chuỗi "end"/"oep" trong dữ liệu không được tính là event
    if p.get('oep'): f.write(json.dumps({'kind': 'oep', 'eip': 1}) + '\n')
    e = {'kind': 'end', 'reason': p.get('reason', 'stop'), 'api_calls': 3, 'seconds': 0}
    if p.get('un'): e['unhandled'] = p['un']
    f.write(json.dumps(e) + '\n')
if p.get('un') and p.get('snap', True) and '--snap-unhandled' in a: open(os.path.join(out, 'snap_unhandled.bin'), 'wb').write(b'S')
'''
d = tempfile.mkdtemp(prefix='rea-step-')
try:
    tool = os.path.join(d, 'tool'); work = os.path.join(d, 'work'); os.makedirs(tool); os.makedirs(work)
    shutil.copy(os.path.join(SRC, 'winemu', 'step.py'), tool)
    open(os.path.join(tool, 'winemu.py'), 'w').write(FAKE)
    open(os.path.join(tool, 'summarize.py'), 'w').write('print("TÓM TẮT")\n')
    def step(plan, *extra, args=('--blob', 'x.bin')):
        env = dict(os.environ, FAKE_ROUND=json.dumps(plan))
        return subprocess.run([sys.executable, os.path.join(tool, 'step.py'), '--out-dir', work, *extra, '--', *args],
                              capture_output=True, text=True, env=env, timeout=60)
    argv = lambda n: json.load(open(os.path.join(work, n, 'argv.json')))
    rs = lambda a: a[a.index('--resume') + 1] if '--resume' in a else None

    r = step({'un': 'kernel32.dll!A'})                                      # r1: từ đầu, dừng ở API mới
    assert r.returncode == 2 and 'r1: chạy từ đầu' in r.stdout and 'thêm hook cho kernel32.dll!A' in r.stdout, r.stdout
    a = argv('r1'); assert '--snap-unhandled' in a and rs(a) is None and a[-2:] == ['--blob', 'x.bin'], a
    r = step({'un': 'kernel32.dll!B'}, '--summarize')                       # r2: tự resume từ r1, API khác -> 2
    assert r.returncode == 2 and rs(argv('r2')) == os.path.join(work, 'r1', 'snap_unhandled.bin'), (r.stdout, argv('r2'))
    assert 'TÓM TẮT' in r.stdout, r.stdout
    r = step({'un': 'kernel32.dll!B'})                                      # r3: cùng API như r2 -> hook chưa có tác dụng
    assert r.returncode == 3 and 'hook chưa có tác dụng' in r.stdout and rs(argv('r3')).endswith('r2/snap_unhandled.bin'), r.stdout
    r = step({'oep': True, 'un': 'k!AfterOep'}, '--prefix', 'g')            # qua OEP (go=1) rồi thiếu API: chưa xong
    assert r.returncode == 2 and 'thêm hook cho k!AfterOep' in r.stdout and 'xong' not in r.stdout, r.stdout
    r = step({'oep': True})                                                 # r4: tới OEP
    assert r.returncode == 0 and 'tới OEP' in r.stdout and '| OEP' in r.stdout, r.stdout
    r = step({'un': 'x!Y'})                                                 # r4 không dừng vì API thiếu: không tạo r5
    assert r.returncode == 0 and 'không có gì để chạy tiếp' in r.stdout and not os.path.exists(os.path.join(work, 'r5')), r.stdout
    r = step({'reason': 'max-steps'}, '--resume', '/s/khac.bin')            # --resume tường minh thắng, chạy được cả sau lượt xong
    assert r.returncode == 0 and rs(argv('r5')) == '/s/khac.bin' and 'hết API thiếu' in r.stdout, r.stdout

    r = step({'un': 'k!Z', 'snap': False}, '--prefix', 'q')                 # lượt q1 thiếu snapshot -> q2 báo lỗi rõ
    assert r.returncode == 2, r.stdout
    r = step({'un': 'k!Z'}, '--prefix', 'q')
    assert r.returncode == 1 and 'thiếu' in r.stderr and not os.path.exists(os.path.join(work, 'q2')), (r.stdout, r.stderr)

    r = step({'reason': 'error Invalid memory fetch @ 0x1'}, '--prefix', 'e')   # lỗi giả lập: mã 1, không báo 'xong'
    assert r.returncode == 1 and 'giả lập lỗi' in r.stdout and 'xong' not in r.stdout, r.stdout
    r = step({'crash': True}, '--prefix', 'c')                              # winemu chết: mã 1, in đuôi stderr
    assert r.returncode == 1 and 'không ghi event end' in r.stdout and 'giả lập chết' in r.stdout, r.stdout

    for bad in (('--out', 'x'), ('--resume=x',), ('--snap-unhandled',)):    # tham số step.py tự đặt: từ chối, không tạo lượt
        r = step({}, '--prefix', 'b', args=('--blob', 'x.bin', *bad))
        assert r.returncode != 0 and 'tự đặt' in r.stderr and not os.path.exists(os.path.join(work, 'b1')), (bad, r.stderr)
    r = step({}, '--prefix', 'b', args=())
    assert r.returncode != 0 and 'thiếu tham số winemu' in r.stderr, r.stderr

    for n in ('z1', 'z10', 'z9', 'zz3', 'z2x'): os.makedirs(os.path.join(work, n))   # đánh số theo giá trị, không theo chữ
    open(os.path.join(work, 'z10', 'events.jsonl'), 'w').write(json.dumps({'kind': 'end', 'reason': 'stop', 'unhandled': 'k!W'}) + '\n')
    open(os.path.join(work, 'z10', 'snap_unhandled.bin'), 'wb').write(b'S')
    r = step({}, '--prefix', 'z')
    assert r.returncode == 0 and os.path.isdir(os.path.join(work, 'z11')) and rs(argv('z11')).endswith('z10/snap_unhandled.bin'), r.stdout
    print('ok')
finally: shutil.rmtree(d, ignore_errors=True)
