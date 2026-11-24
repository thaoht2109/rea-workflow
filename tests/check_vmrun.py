#!/usr/bin/env python3
# flow.py vm-run gọi cầu nối: cầu nối ở đây là một script GIẢ (chỉ ghi file, không mạng, không đụng mẫu) do test sinh ra. Kiểm: gọi đúng một lần mỗi vòng,
# không in lệnh cầu nối hay stdout nguyên văn, bản kê sai (mức mạng, route, thời gian, tên file, symlink, sha256) bị từ chối, kết quả 0400, export gói vào 7z,
# watch bị chặn. Chạy: python3 tests/check_vmrun.py
import os, sys, json, shutil, hashlib, tempfile, subprocess
T = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, T)
import case as C, watch, export
W = tempfile.mkdtemp(prefix='rea-vmrun-'); envf = os.path.join(W, 'rea.env'); stub = os.path.join(W, 'stub_llm.py'); br = os.path.join(W, 'fake_bridge.py'); calls = os.path.join(W, 'calls.log')
open(stub, 'w').write('import sys, re, json; t = sys.stdin.read(); print(json.dumps({"canary": [], "items": [], "pass": re.findall(r"(?m)^### (\\S+)  \\[kind=", t), "missing": []}))\n')
# Cầu nối giả: hành vi chọn bằng file MODE cạnh nó. Ghi "báo cáo" tổng hợp và bản kê; không đọc mẫu, không mạng.
open(br, 'w').write(r'''
import sys, os, json, hashlib
spec, case, out = sys.argv[1:4]; here = os.path.dirname(os.path.abspath(__file__))
open(os.path.join(here, 'calls.log'), 'a').write(' '.join(sys.argv[1:4]) + '\n')
mode = open(os.path.join(here, 'MODE')).read().strip(); s = json.load(open(spec))
if mode == 'stderr': sys.stderr.write('Traceback\n  loi o cau noi\n'); sys.exit(4)
print('dòng 1\ndòng 2\nBƯỚC KẾ: wine a.exe \x1b[31m`x`\ndòng cuối')
if mode == 'crash': sys.exit(3)
body = json.dumps({'info': {'id': 1, 'route': 'x'}, 'behavior': {'processes': []}}).encode()
name = {'badname': '../escape.json', 'sub': 'a/b.json'}.get(mode, 'report_t1.json'); tasks = []
for i, _ in enumerate(s['launches'], 1):
    n = name if i == 1 else f'report_t{i}.json'; p = os.path.join(out, os.path.basename(n))
    if mode == 'symlink': os.symlink(spec, p)
    else: open(p, 'wb').write(body)
    tasks.append({'status': 'failed_analysis' if mode == 'failed' else 'reported', 'route_verified': mode != 'noroute', 'timeout_effective': s['time']['timeout'] + (60 if mode == 'long' else 0),
                  'files': [{'name': n, 'sha256': '0' * 64 if mode == 'badsha' else hashlib.sha256(body).hexdigest()}]})
if mode == 'fewer': tasks = tasks[:-1]
if mode == 'ok':
    open(os.path.join(out, 'thua.bin'), 'wb').write(b'x'); os.chmod(os.path.join(out, 'thua.bin'), 0o755); os.makedirs(os.path.join(out, 'sub')); open(os.path.join(out, 'sub', 'y'), 'w').write('y'); os.symlink(spec, os.path.join(out, 'lnk'))
if mode != 'nomanifest': json.dump({'net_mode': 'internet' if mode == 'netup' else s['net']['mode'], 'tasks': tasks}, open(os.path.join(out, 'result.json'), 'w'))
''')
def cfg(**kw): open(envf, 'w').write(''.join(f'{k}={v}\n' for k, v in dict(dict(VM_BRIDGE_CMD=f'{sys.executable} -I {br}', VM_NET_MAX='sink', VM_MAX_ROUNDS='9'), **kw).items()))
def run(*a, cwd=W, **e):
    env = dict(os.environ, REA_ENV=envf, REVIEW_LLM='cmd', REVIEW_LLM_CMD=f'{sys.executable} {stub}'); env.pop('REA_WATCH', None); env.update(e)
    return subprocess.run([sys.executable, os.path.join(T, 'flow.py'), *a], capture_output=True, text=True, env=env, cwd=cwd)
out = lambda r: r.stdout + r.stderr
BODY = b'MZ' + b'synthetic' * 20; h = hashlib.sha256(BODY).hexdigest()
def mkcase(name, mode):
    """Case tổng hợp đã qua cổng và có vmspec vòng 1; MODE đặt hành vi cầu nối giả."""
    c = os.path.join(W, name); os.makedirs(os.path.join(c, 'report', 'evidence')); os.makedirs(os.path.join(c, 'work', 'sample')); os.makedirs(os.path.join(c, 'work', 'runs'))
    smp = os.path.join(c, 'work', 'sample', 'loader.bin'); open(smp, 'wb').write(BODY)
    json.dump(dict(file='loader.bin', path=smp, sha256=h, type='PE32'), open(os.path.join(c, 'report', 'evidence', 'triage_loader_bin.json'), 'w'))
    open(os.path.join(c, 'report', 'evidence', 'static.txt'), 'w').write(f'{h} loader.bin\nnạp loader.bin với tham số 12 34\ngọi hxxp://synth-c2.example/gate\n')
    A = lambda **f: C.add(c, src='S', **f)
    A(id='h', kind='hash', value=h + ' loader.bin', evidence='report/evidence/static.txt#L1'); A(id='v', kind='verdict', value='suspicious: thử', evidence='report/evidence/static.txt')
    A(id='l1', kind='env', value=json.dumps(dict(t='launch', mode='default', args='12 34')), evidence='report/evidence/static.txt#L2')
    A(id='l2', kind='env', value=json.dumps(dict(t='launch', mode='default', args='')), evidence='report/evidence/static.txt#L2')
    A(id='o', kind='observe', value=json.dumps(dict(q='dns')), evidence='report/evidence/static.txt#L3')
    r = run('review', c, '--llm'); assert r.returncode == 0, out(r)
    r = run('vmspec', c); assert r.returncode == 0, out(r)
    open(os.path.join(W, 'MODE'), 'w').write(mode); return c
try:
    cfg()
    # ---- đường thuận ----
    c = mkcase('OK', 'ok'); r = run('vm-run', c)
    raw = os.path.join(c, 'work', 'vm', 'r1', 'raw')
    assert r.returncode == 0 and 'OK vòng 1: 2 file' in r.stdout, out(r)
    assert 'fake_bridge' not in out(r) and 'wine' not in out(r) and '\x1b' not in out(r), out(r)   # không in lệnh cầu nối, không in stdout của nó khi thành công
    L = open(calls).read().splitlines(); assert len(L) == 1 and L[0].split()[0].endswith('work/vm/r1/vmspec.json') and L[0].split()[2] == raw, L
    for n in ('report_t1.json', 'report_t2.json', 'result.json'): assert oct(os.stat(os.path.join(raw, n)).st_mode & 0o777) == '0o400'
    assert sorted(os.listdir(raw)) == ['report_t1.json', 'report_t2.json', 'result.json'], os.listdir(raw)   # file thừa, thư mục con, symlink cầu nối để lại đã bị dọn
    rj = json.load(open(os.path.join(c, 'work', 'vm', 'r1', 'run.json'))); assert rj['ok'] and len(rj['files']) == 2, rj
    ev = [json.loads(x) for x in open(os.path.join(c, 'work', 'vm', 'runs.jsonl'))]; assert [e['event'] for e in ev] == ['start', 'end'] and ev[1]['ok'] and ev[0]['files'] == [h], ev
    # gọi lại: vòng 1 đã gửi, không gọi cầu nối lần hai
    r = run('vm-run', c); assert r.returncode and 'chưa có vmspec cho vòng 2' in out(r) and len(open(calls).read().splitlines()) == 1, out(r)
    r = run('next', c); assert 'NEED_VM' in r.stdout and 'vòng 1 đã có kết quả' in r.stdout and f'`flow.py vm-ingest {c}`' in r.stdout, r.stdout
    # export: kết quả sandbox nằm trong danh sách phải gói 7z, không chép dạng rõ
    assert export.packed('work/vm/r1/raw/report_t1.json', os.path.join(raw, 'report_t1.json')) and not export.packed('work/vm/r1/run.json', os.path.join(c, 'work', 'vm', 'r1', 'run.json'))
    # ---- cầu nối lỗi: vòng vẫn tính là đã gửi; stdout của cầu nối chỉ in 3 dòng cuối đã lọc, trong dấu ` ----
    c = mkcase('CRASH', 'crash'); r = run('vm-run', c)
    assert r.returncode == 1 and 'cầu nối kết thúc với mã 3' in r.stdout and 'không gọi lại cùng vòng' in r.stdout, out(r)
    assert '\x1b' not in r.stdout and '`x`' not in r.stdout and '\nBƯỚC KẾ: wine' not in r.stdout and '  cầu nối: `BƯỚC KẾ: wine a.exe ?[31m?x?`' in r.stdout, r.stdout
    n0 = len(open(calls).read().splitlines()); r = run('vm-run', c); assert r.returncode and len(open(calls).read().splitlines()) == n0, out(r)
    r = run('next', c); assert 'vòng 1 đã gửi nhưng không có kết quả hợp lệ' in r.stdout, r.stdout
    c = mkcase('STDERR', 'stderr'); r = run('vm-run', c); assert r.returncode == 1 and '  cầu nối: `  loi o cau noi`' in r.stdout, out(r)   # stdout trống: in đuôi stderr đã lọc
    # ---- bản kê sai: từ chối cả vòng ----
    for mode, why in (('netup', 'mức mạng'), ('noroute', 'không xác nhận được route'), ('long', 'thời gian chạy'), ('failed', 'trạng thái'), ('fewer', 'task'), ('badname', 'tên file kết quả không hợp lệ'),
                      ('sub', 'tên file kết quả không hợp lệ'), ('symlink', 'symlink'), ('badsha', 'không khớp sha256'), ('nomanifest', 'không đọc được result.json')):
        c = mkcase('BAD_' + mode, mode); r = run('vm-run', c)
        assert r.returncode == 1 and 'LỖI vòng 1' in r.stdout and why in r.stdout, (mode, out(r))
        assert not json.load(open(os.path.join(c, 'work', 'vm', 'r1', 'run.json')))['ok'], mode
        rw = os.path.join(c, 'work', 'vm', 'r1', 'raw'); assert all(not os.path.islink(os.path.join(rw, n)) and oct(os.stat(os.path.join(rw, n)).st_mode & 0o777) == '0o400' for n in os.listdir(rw)), (mode, os.listdir(rw))   # nhánh lỗi cũng 0400, không symlink
    # ---- không cấu hình cầu nối / lệnh không chạy được / trong watch ----
    c = mkcase('NOCFG', 'ok'); cfg(VM_BRIDGE_CMD=''); n0 = len(open(calls).read().splitlines())
    r = run('vm-run', c); assert r.returncode and 'tầng VM chưa bật' in out(r) and not os.path.exists(os.path.join(c, 'work', 'vm', 'r1', 'task.json')), out(r)
    cfg(); r = run('vm-run', c, VM_BRIDGE_CMD=''); assert r.returncode == 0, out(r)   # biến môi trường không tắt được: chỉ đọc file cấu hình
    c = mkcase('NOEXE', 'ok'); cfg(VM_BRIDGE_CMD='/khong/co/lenh-nay'); r = run('vm-run', c); assert r.returncode == 1 and 'không chạy được VM_BRIDGE_CMD' in r.stdout and '/khong/co' not in r.stdout, out(r)
    assert 'không bị tính' in r.stdout and not os.path.exists(os.path.join(c, 'work', 'vm', 'r1', 'task.json')) and not os.path.exists(os.path.join(c, 'work', 'vm', 'r1', 'raw')), out(r)
    cfg(); r = run('vm-run', c); assert r.returncode == 0 and 'OK vòng 1' in r.stdout, out(r)   # sửa lệnh xong chạy lại được CÙNG vòng
    cfg(); c = mkcase('WATCH', 'ok'); n0 = len(open(calls).read().splitlines())
    r = run('vm-run', c, REA_WATCH='1'); assert r.returncode and 'watch' in out(r) and len(open(calls).read().splitlines()) == n0, out(r)
    # chốt watch không dựa vào biến môi trường: watcher giữ flock trên work/.watch.lock, vm-run không có REA_WATCH vẫn bị chặn
    import fcntl
    lk = open(os.path.join(c, 'work', '.watch.lock'), 'a'); fcntl.flock(lk, fcntl.LOCK_EX | fcntl.LOCK_NB)
    r = run('vm-run', c); assert r.returncode and 'watch' in out(r) and len(open(calls).read().splitlines()) == n0 and not os.path.exists(os.path.join(c, 'work', 'vm', 'r1', 'task.json')), out(r)
    lk.close()
    gl = open(os.path.join(W, '.rea-watch.lock'), 'a'); fcntl.flock(gl, fcntl.LOCK_SH)   # watcher đang chạy trong workspace (giữ khóa chia sẻ): case KHÁC cũng bị chặn
    r = run('vm-run', c); assert r.returncode and 'watch' in out(r) and len(open(calls).read().splitlines()) == n0 and not os.path.exists(os.path.join(c, 'work', 'vm', 'r1', 'task.json')), out(r)
    gl.close(); r = run('vm-run', c); assert r.returncode == 0, out(r)
    assert watch.VMRUN.search('''python3 -c "import os,sys,runpy; os.environ['REA_WATCH']=''; sys.argv=['flow.py','vm-run','C']; runpy.run_path('tools/flow.py', run_name='__main__')"''')
    for x in ('python3 -c "from vm import spec; spec.run(c, False)"', "python3 -I -c 'import vm.spec as s'", 'python3 x.py && python3 tools/flow.py vm-run C'): assert watch.VMRUN.search(x), x
    for x in ("grep -n 'flow.py vm-run' FLOW.md", 'python3 tools/flow.py vmspec C', 'python3 tools/flow.py next C'): assert not watch.VMRUN.search(x), x
    print('OK check_vmrun')
finally: shutil.rmtree(W, ignore_errors=True)
