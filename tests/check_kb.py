#!/usr/bin/env python3
# flow.py kb: kho tra chéo chỉ gợi ý, không ghi gì vào case, không lưu kết luận họ; từ chối kho nằm trong thư mục skill;
# thống kê đính chính từ chuỗi supersedes. Đặc trưng PE (rich, PDB, chứng thư) qua đối tượng giả. Dữ liệu tổng hợp.
#   python3 tests/check_kb.py
import os, sys, json, types, shutil, hashlib, tempfile, subprocess
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
