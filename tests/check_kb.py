#!/usr/bin/env python3
# flow.py kb: kho tra chéo chỉ gợi ý, không ghi gì vào case, không lưu kết luận họ; từ chối kho nằm trong thư mục skill;
# thống kê đính chính từ chuỗi supersedes. Đặc trưng PE (rich, PDB, chứng thư) qua đối tượng giả. Dữ liệu tổng hợp.
#   python3 tests/check_kb.py
import os, sys, gzip, json, types, shutil, hashlib, tempfile, subprocess
T = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path[:0] = [T, os.path.join(T, 'static')]
import triage, kb

ws = tempfile.mkdtemp(prefix='rea-kb-'); kbd = os.path.join(ws, 'kbstore')
env = dict(os.environ, REA_KB=kbd, REA_WORKSPACE=ws)
run = lambda *a, **kw: subprocess.run([sys.executable, os.path.join(T, 'flow.py'), *a], capture_output=True, text=True, cwd=ws, env=kw.get('env', env))

def mk(name, files, facts):
    c = os.path.join(ws, name); sd = os.path.join(c, 'work', 'sample'); os.makedirs(sd); os.makedirs(os.path.join(c, 'report', 'evidence'))
    for n, b in files.items(): open(os.path.join(sd, n), 'wb').write(b)
    with open(os.path.join(c, 'facts.jsonl'), 'w') as f:
        for x in facts: f.write(json.dumps(dict(dict(src='S', evidence='report/evidence/e.txt', status='active', supersedes=None, ts='2026-01-01T00:00:00'), **x)) + '\n')
    return c

shared = b'loader-stage\x00' * 64; payload = b'payload-bytes' * 50
A = mk('CASE_A', {'drop.bin': shared}, [
    dict(id='a.c2', kind='c2', value='evil-host.example.net:443 (qua TLS)'),
    dict(id='a.mx', kind='mutex', value='Global\\{AAAA-1111}'),
    dict(id='a.fam', kind='family', value='HỌ-BÍ-MẬT-A'),
    dict(id='a.ph', kind='payload_hash', value=hashlib.sha256(payload).hexdigest() + ' payload giải mã'),
    dict(id='a.u1', kind='url', value='http://cert.example.com/ca.crt', ts='2026-01-01T00:00:00'),
    dict(id='a.u1r', kind='url', value='n/a: URL chứng thư', status='retracted', supersedes='a.u1', ts='2026-01-01T05:00:00'),
    dict(id='a.f1', kind='family', value='X', ts='2026-01-02T00:00:00'),
    dict(id='a.f1h', kind='family', value='chưa định danh', status='hypothesis', supersedes='a.f1', ts='2026-01-03T00:00:00')])
B = mk('CASE_B', {'other.bin': shared, 'stage2.bin': payload}, [
    dict(id='b.c2', kind='c2', value='EVIL-HOST.example.net:443'),
    dict(id='b.mx', kind='mutex', value='Global\\{AAAA-1111}'),
    dict(id='b.ip', kind='c2', value='n/a: 10.0.0.1 là IP nội bộ'),   # n/a không thành dấu hiệu
    dict(id='b.u1', kind='url', value='http://x.example.org/a', ts='2026-02-01T00:00:00'),
    dict(id='b.u1r', kind='url', value='n/a', status='retracted', supersedes='b.u1', ts='2026-02-01T01:00:00')])
mk('CASE_C', {'lone.bin': b'nothing alike here' * 9}, [dict(id='c.c2', kind='c2', value='other.example.org')])
os.makedirs(os.path.join(B, 'work', 'review', 'r1'))
json.dump({'items': [{'id': 'b.u1', 'verdict': 'fail'}]}, open(os.path.join(B, 'work', 'review', 'r1', 'review.json'), 'w'))
snap = lambda: sorted((os.path.relpath(os.path.join(d, n), ws), os.path.getmtime(os.path.join(d, n)))
                      for c in (A, B) for d, _, ns in os.walk(c) for n in ns)
try:
    before = snap()
    # 1. chưa có kho: match nhắc build; dựng kho
    r = run('kb', 'match', 'CASE_A'); assert r.returncode == 0 and 'kb build' in r.stdout, r.stdout + r.stderr
    r = run('kb', 'build'); assert r.returncode == 0 and '3 case' in r.stdout and '4 file' in r.stdout, r.stdout + r.stderr
    raw = open(os.path.join(kbd, 'samples.jsonl')).read()
    assert 'HỌ-BÍ-MẬT-A' not in raw and 'chưa định danh' not in raw, 'kho không được lưu kết luận họ của case khác'
    assert oct(os.stat(os.path.join(kbd, 'samples.jsonl')).st_mode & 0o777) == '0o600'
    # 2. gợi ý: trùng sha256, payload_hash của A là mẫu của B, c2 không phân biệt hoa thường, mutex; case không liên quan thì im
    r = run('kb', 'match', 'CASE_B'); o = r.stdout
    assert 'GỢI Ý, không phải fact' in o and 'work/sample/other.bin ~ CASE_A/work/sample/drop.bin: trùng sha256 (mạnh)' in o, o
    assert 'work/sample/stage2.bin: sha256 có trong fact hash/payload_hash của CASE_A' in o, o
    assert 'c2 trùng với CASE_A: evil-host.example.net:443' in o and 'mutex trùng với CASE_A' in o, o
    assert 'CASE_C' not in o and '10.0.0.1' not in o and 'HỌ-BÍ-MẬT' not in o, o
    r = run('kb', 'match', 'CASE_C'); assert 'không có gợi ý' in r.stdout, r.stdout
    # 3. sau triage: gợi ý không có header thừa; không ghi gì vào case
    out = []; sys.stdout = types.SimpleNamespace(write=out.append, flush=lambda: None)
    os.environ.update(REA_KB=kbd); kb.CFG.KB = kbd
    try: kb.hint(B)
    finally: sys.stdout = sys.__stdout__
    assert 'trùng sha256' in ''.join(out), out
    assert snap() == before, 'kb không được ghi vào case'
    # 4. thống kê đính chính: loại, nguồn phát hiện, mẫu lặp lại >= 3 lần / >= 2 case
    K = kb.corrections(A) + kb.corrections(B)
    t = {r['id']: r for r in K}
    assert t['a.u1r']['type'] == 'rút lại' and t['a.u1r']['lag_h'] == 5.0 and t['a.f1h']['type'] == 'hạ về giả thuyết', t
    assert t['b.u1r']['caught'] == 'phản biện' and t['a.u1r']['caught'] == 'tự sửa', t
    r = run('kb', 'corrections'); assert '3 fact bị thay ở 2 case' in r.stdout and 'url 2' in r.stdout, r.stdout
    r = run('kb', 'corrections', '--since', '2026-02-01'); assert '1 fact bị thay ở 1 case' in r.stdout, r.stdout
    # 4b. kho dùng chung nhiều workspace: dựng ở workspace khác (hoặc thư mục không có case) không xóa bản ghi của workspace này;
    #     report --final dựng theo workspace của case chứ không theo cwd; case trùng tên ở workspace khác vẫn được so, có tên workspace
    ws2 = tempfile.mkdtemp(prefix='rea-kb2-'); empty = tempfile.mkdtemp(prefix='rea-kb3-')
    try:
        shutil.copytree(A, os.path.join(ws2, 'CASE_B'))   # cùng tên CASE_B, nội dung như CASE_A
        assert run('kb', 'build', env=dict(env, REA_WORKSPACE=ws2)).returncode == 0
        assert run('kb', 'build', env=dict(env, REA_WORKSPACE=empty)).returncode == 0
        S = [json.loads(l) for l in open(os.path.join(kbd, 'samples.jsonl'))]
        assert {(os.path.basename(r['ws']), r['case']) for r in S} >= {(os.path.basename(ws), 'CASE_A'), (os.path.basename(ws2), 'CASE_B')}, S
        kb.refresh(os.path.join(ws, 'CASE_A'))   # in-process, cwd không phải workspace
        S = [json.loads(l) for l in open(os.path.join(kbd, 'samples.jsonl'))]
        assert {os.path.basename(r['ws']) for r in S} == {os.path.basename(ws), os.path.basename(ws2)}, S
        shutil.rmtree(ws2); kb.refresh(os.path.join(ws, 'CASE_A'))   # workspace đã xóa: bản ghi bị bỏ khi dựng lại
        assert {os.path.basename(r['ws']) for r in map(json.loads, open(os.path.join(kbd, 'samples.jsonl')))} == {os.path.basename(ws)}
        shutil.copytree(A, os.path.join(ws2, 'CASE_B')); assert run('kb', 'build', env=dict(env, REA_WORKSPACE=ws2)).returncode == 0
        o = run('kb', 'match', 'CASE_B').stdout
        assert f'{os.path.basename(ws2)}:CASE_B' in o and 'CASE_A/work/sample/drop.bin' in o, o
    finally: shutil.rmtree(ws2, ignore_errors=True); shutil.rmtree(empty, ignore_errors=True)
    r = subprocess.run([sys.executable, os.path.join(T, 'reacfg.py')], capture_output=True, text=True, cwd=T, env=dict(env, REA_KB='off'))
    assert any('REA_KB' in l and l.startswith('OK') and 'tắt' in l for l in r.stdout.splitlines()), r.stdout
    # 4c. mặc định: cache của người dùng, không phụ thuộc cwd; thư mục không ghi được thì báo rõ, không traceback
    cache = tempfile.mkdtemp(prefix='rea-kbc-'); e0 = {k: v for k, v in env.items() if k != 'REA_KB'}
    try:
        for cwd in (ws, T):
            r = subprocess.run([sys.executable, '-c', 'import reacfg; print(reacfg.KB)'], capture_output=True, text=True, cwd=cwd,
                               env=dict(e0, XDG_CACHE_HOME=cache, REA_ENV=os.path.join(cache, 'none.env'), PYTHONPATH=T))
            assert r.stdout.strip() == os.path.join(cache, 'rea-flow', 'kb'), r.stdout + r.stderr
        ro = os.path.join(cache, 'ro'); os.makedirs(ro); os.chmod(ro, 0o500)
        r = run('kb', 'build', env=dict(env, REA_KB=os.path.join(ro, 'kb')))
        if os.geteuid() != 0: assert r.returncode and 'không ghi được kho' in r.stderr and 'Traceback' not in r.stderr, r.stderr
    finally: os.chmod(os.path.join(cache, 'ro'), 0o700) if os.path.isdir(os.path.join(cache, 'ro')) else None; shutil.rmtree(cache, ignore_errors=True)
    # 4d. server mới: kho chưa có thì hint (sau new/triage) tự dựng; đã có workspace này thì không dựng lại; workspace mới thì thêm vào
    fresh = tempfile.mkdtemp(prefix='rea-kbf-'); old_kb = kb.CFG.KB; kb.CFG.KB = os.path.join(fresh, 'kb')
    try:
        out = []; sys.stdout = types.SimpleNamespace(write=out.append, flush=lambda: None)
        try: kb.hint(B)
        finally: sys.stdout = sys.__stdout__
        o = ''.join(out); p = os.path.join(fresh, 'kb', 'samples.jsonl')
        assert 'đang dựng từ 3 case' in o and 'trùng sha256' in o and os.path.exists(p), o
        m = os.path.getmtime(p); out.clear(); sys.stdout = types.SimpleNamespace(write=out.append, flush=lambda: None)
        try: kb.hint(A)
        finally: sys.stdout = sys.__stdout__
        assert 'đang dựng' not in ''.join(out) and os.path.getmtime(p) == m, out
        nocase = tempfile.mkdtemp(prefix='rea-kbn-'); os.makedirs(os.path.join(nocase, 'X', 'work'))   # case chưa có facts.jsonl
        try:
            out.clear(); sys.stdout = types.SimpleNamespace(write=out.append, flush=lambda: None)
            try: kb.hint(os.path.join(nocase, 'X'))
            finally: sys.stdout = sys.__stdout__
            assert 'đang dựng' not in ''.join(out) and os.path.getmtime(p) == m, out
        finally: shutil.rmtree(nocase, ignore_errors=True)
        ws3 = tempfile.mkdtemp(prefix='rea-kbw-'); shutil.copytree(A, os.path.join(ws3, 'CASE_Z'))
        try:
            sys.stdout = types.SimpleNamespace(write=out.append, flush=lambda: None)
            try: kb.hint(os.path.join(ws3, 'CASE_Z'))
            finally: sys.stdout = sys.__stdout__
            S = [json.loads(l) for l in open(p)]
            assert {os.path.basename(r['ws']) for r in S} == {os.path.basename(ws), os.path.basename(ws3)}, S
        finally: shutil.rmtree(ws3, ignore_errors=True)
    finally: kb.CFG.KB = old_kb; shutil.rmtree(fresh, ignore_errors=True)
    # 4e. dựng tăng dần: lần hai không đọc lại mẫu; file đổi mtime thì chỉ file đó được tính lại
    inc = tempfile.mkdtemp(prefix='rea-kbi-'); old_kb = kb.CFG.KB; kb.CFG.KB = os.path.join(inc, 'kb'); calls = []
    orig = triage.pivot_of; triage.pivot_of = lambda p: (calls.append(p), orig(p))[1]
    try:
        q = lambda: kb.build(ws, quiet=True)
        q(); n1 = len(calls); q(); assert n1 == 4 and len(calls) == n1, calls
        assert len(kb.read_jsonl(os.path.join(inc, 'kb', 'corrections.jsonl'))) == 3   # dựng lại không nhân đôi đính chính (fact có trường src riêng)
        f = os.path.join(B, 'work', 'sample', 'other.bin'); os.chmod(f, 0o600); os.utime(f, ns=(1, 10 ** 18)); q()
        assert calls[n1:] == [f], calls[n1:]
        recs = [r for r in kb.read_jsonl(os.path.join(inc, 'kb', 'samples.jsonl')) if r.get('file') == 'work/sample/other.bin']
        assert len(recs) == 1 and recs[0]['mtime_ns'] == 10 ** 18 and recs[0]['pv'] == kb.PIVOT_VER, recs
    finally: triage.pivot_of = orig; kb.CFG.KB = old_kb; shutil.rmtree(inc, ignore_errors=True)
    # 4f. nhiễu: sha256/section có ở >= 3 case là yếu; file ký số trùng sha256 chỉ là vừa; file không ký vẫn mạnh
    import collections as _c; fr = _c.defaultdict(_c.Counter)
    assert kb.compare(dict(sha256='h'), dict(sha256='h'), fr) == [('trùng sha256', 'mạnh')]
    assert kb.compare(dict(sha256='h', signer='CN=Big Vendor,O=Big'), dict(sha256='h'), fr)[0][1] == 'vừa'
    fr['sha256']['h'] = 3; assert kb.compare(dict(sha256='h'), dict(sha256='h'), fr)[0][1] == 'yếu'
    fr['sec_md5']['s1'] = 3; assert dict(kb.compare(dict(sha256='1', sec_md5=['s1']), dict(sha256='2', sec_md5=['s1']), fr)) == {'chung 1 section (phổ biến)': 'yếu'}
    # 4g. export/import: sang kho khác dưới tên nguồn; nhập lại thì thay; build không xóa bản nhập; chính case không tự khớp; file lạ bị từ chối
    xd = tempfile.mkdtemp(prefix='rea-kbx-'); exp = os.path.join(xd, 'a.jsonl.gz'); env2 = dict(env, REA_KB=os.path.join(xd, 'kb2'))
    try:
        assert run('kb', 'build').returncode == 0
        r = run('kb', 'export', exp, '--name', 'srv 1/../x'); assert r.returncode == 0 and 'IOC' in r.stdout, r.stdout + r.stderr
        assert oct(os.stat(exp).st_mode & 0o777) == '0o600'
        r = run('kb', 'import', exp, env=env2); assert r.returncode == 0 and 'srv_1_.._x' in r.stdout and '3 case' in r.stdout, r.stdout + r.stderr
        r = run('kb', 'import', exp, env=env2); S2 = kb.read_jsonl(os.path.join(xd, 'kb2', 'samples.jsonl'))
        assert len(S2) == 7 and all(x['peer'] == 'srv_1_.._x' for x in S2), S2   # 4 file + 3 case, không nhân đôi
        assert run('kb', 'build', env=dict(env2, REA_WORKSPACE=xd)).returncode == 0
        assert len([x for x in kb.read_jsonl(os.path.join(xd, 'kb2', 'samples.jsonl')) if x.get('peer')]) == 7
        o = run('kb', 'match', 'CASE_B', env=env2).stdout
        assert 'srv_1_.._x:CASE_A/work/sample/drop.bin' in o and 'srv_1_.._x:CASE_B' not in o, o   # cùng đường dẫn = chính case này
        assert 'cả kho' in run('kb', 'corrections', '--all', env=env2).stdout
        bad = os.path.join(xd, 'bad.gz'); open(bad, 'wb').write(gzip.compress(b'{"kind":"other"}\n'))
        r = run('kb', 'import', bad, env=env2); assert r.returncode and 'không phải file kb export' in r.stderr and 'Traceback' not in r.stderr, r.stderr
        open(bad, 'wb').write(b'not gzip'); r = run('kb', 'import', bad, env=env2); assert r.returncode and 'Traceback' not in r.stderr, r.stderr
        r = run('kb', 'export', os.path.join(T, 'x.gz')); assert r.returncode and 'thư mục skill' in r.stderr and not os.path.exists(os.path.join(T, 'x.gz'))
        # server mới cùng đường dẫn workspace: kho chỉ có bản nhập thì new/triage vẫn tự dựng phần cục bộ
        env3 = dict(env, REA_KB=os.path.join(xd, 'kb3')); assert run('kb', 'import', exp, env=env3).returncode == 0
        old_kb = kb.CFG.KB; kb.CFG.KB = os.path.join(xd, 'kb3'); out = []; sys.stdout = types.SimpleNamespace(write=out.append, flush=lambda: None)
        try: kb.hint(B)
        finally: sys.stdout = sys.__stdout__; kb.CFG.KB = old_kb
        S3 = kb.read_jsonl(os.path.join(xd, 'kb3', 'samples.jsonl'))
        assert 'đang dựng' in ''.join(out) and any(not x.get('peer') for x in S3) and any(x.get('peer') for x in S3), out
        # backup của chính máy này nhập vào kho đang có bản cục bộ: không đếm case hai lần (trùng sha256 vẫn mạnh, không thành phổ biến)
        assert run('kb', 'import', exp, '--name', 'bk').returncode == 0
        o = run('kb', 'match', 'CASE_B').stdout
        assert 'CASE_A/work/sample/drop.bin: trùng sha256 (mạnh)' in o and 'bk:CASE_B' not in o, o
        # case cùng tên + cùng đường dẫn ở máy khác nhưng khác nội dung vẫn được so
        rows = [json.loads(l) for l in gzip.open(exp, 'rt')]
        fake = dict(t='s', case='CASE_C', file='work/sample/x.bin', sha256='ab' * 32, ws=rows[1]['ws'])   # khác nội dung với CASE_C cục bộ
        fakec = dict(t='s', kind='case', case='CASE_C', ws=rows[1]['ws'], hashes=[], atoms={'c2': ['other.example.org']}); f2 = os.path.join(xd, 'p2.gz')
        with gzip.open(f2, 'wt') as fh:
            fh.write(json.dumps(dict(rows[0], name='p2')) + '\n' + json.dumps(fake) + '\n' + json.dumps(fakec) + '\n')
            fh.write(json.dumps(dict(t='s', case='Z', file='f', sha256='0' * 64, exports={'a': 1})) + '\n')   # sai dạng: bị bỏ
            fh.write(json.dumps(dict(t='s', kind='case', case='Z', atoms={'c2': [{'x': 1}]})) + '\n')         # sai dạng: bị bỏ
            fh.write(json.dumps(dict(t='c', case='Z', type='x')) + '\n' + 'không phải json\n')                # thiếu trường / hỏng: bị bỏ
        r = run('kb', 'import', f2); assert r.returncode == 0 and 'bỏ 4 bản ghi sai dạng' in r.stdout, r.stdout + r.stderr
        o = run('kb', 'match', 'CASE_C').stdout; assert 'c2 trùng với p2:CASE_C: other.example.org' in o, o
        assert run('kb', 'corrections', '--all').returncode == 0
        # dòng rất dài không vượt trần đọc
        big = os.path.join(xd, 'big.gz')
        with gzip.open(big, 'wt') as fh: fh.write(json.dumps(rows[0]) + '\n' + 'x' * 5000)
        old_max, kb.MAX_IMPORT, kb.CFG.KB = kb.MAX_IMPORT, 1000, os.path.join(xd, 'kb4')
        try: kb.import_(big); raise AssertionError('phải dừng')
        except SystemExit as e: assert 'MiB' in str(e) or 'lớn hơn' in str(e), e
        finally: kb.MAX_IMPORT, kb.CFG.KB = old_max, old_kb
    finally: shutil.rmtree(xd, ignore_errors=True)
    # 5. kho trong thư mục skill bị từ chối; off thì tắt
    r = run('kb', 'build', env=dict(env, REA_KB=os.path.join(T, 'kbdata'))); assert r.returncode and 'thư mục skill' in r.stderr and not os.path.exists(os.path.join(T, 'kbdata')), r.stderr
    r = run('kb', 'build', env=dict(env, REA_KB='off')); assert r.returncode == 0 and 'off' in r.stdout, r.stdout
    # 6. so đặc trưng: imphash ít import hoặc phổ biến là yếu; PDB GUID mạnh; chứng thư chung chỉ là yếu; export trùng
    import collections
    fr = collections.defaultdict(collections.Counter)
    n = dict(sha256='1', imphash='ih', imp_n=40, pdb_guid='G1', certs=['CA|01'], exports=['a', 'b', 'c', 'd'], sec_md5=['s1'])
    h = dict(kb.compare(n, dict(sha256='2', imphash='ih', pdb_guid='G1', certs=['CA|01'], exports=['a', 'b', 'c'], sec_md5=['s1']), fr))
    assert h == {'imphash': 'mạnh', 'PDB GUID': 'mạnh', 'chung 1 chứng thư': 'yếu', 'chung 1 section': 'vừa', 'export trùng 3/4': 'vừa'}, h
    assert dict(kb.compare(dict(n, imp_n=2), dict(sha256='2', imphash='ih'), fr)) == {'imphash': 'yếu'}
    fr['imphash']['ih'] = 3; assert dict(kb.compare(n, dict(sha256='2', imphash='ih'), fr)) == {'imphash': 'yếu'}
    assert kb.compare(dict(sha256='1'), dict(sha256='2'), fr) == []
    assert kb.atoms('c2', 'n/a: không') == set() and kb.atoms('mutex', 'khóa thường không có ký tự lạ') == set()
    # 7. triage: rich tự parse khi fast_load, PDB + GUID, chứng thư thiếu thư viện không làm hỏng; der_len bỏ phần đệm
    assert triage.der_len(b'\x30\x03abc\x00\x00') == 5 and triage.der_len(b'\x30\x82\x01\x00') == 260 and triage.der_len(b'\x31\x00') is None
    cv = types.SimpleNamespace(PdbFileName=b'C:\\b\\x.pdb\x00\x00', Signature_String='ABCD1')
    pe = types.SimpleNamespace(get_imphash=lambda: 'ih', parse_rich_header=lambda: {'clear_data': b'rich'}, FILE_HEADER=types.SimpleNamespace(TimeDateStamp=7),
                               DIRECTORY_ENTRY_DEBUG=[types.SimpleNamespace(entry=None), types.SimpleNamespace(entry=cv)])
    R = {}; triage.pe_pivots(pe, b'', R); P = R['pivot']
    assert P == {'imphash': 'ih', 'rich': hashlib.md5(b'rich', usedforsecurity=False).hexdigest(), 'timestamp': 7, 'pdb': 'C:\\b\\x.pdb', 'pdb_guid': 'ABCD1'}, P
    R = {'signature': {'offset': 0, 'size': 16}}; triage.pe_pivots(types.SimpleNamespace(), b'\x00' * 16, R)
    assert R['pivot']['imphash'] is None and R['pivot']['rich'] is None and R['pivot'].get('certs') in (None, []), R
finally:
    shutil.rmtree(ws, ignore_errors=True)
print('OK check_kb')
