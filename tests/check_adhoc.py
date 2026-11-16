#!/usr/bin/env python3
# Tầng T1b (flow.py tool): skill không chạy công cụ, chỉ cấp khuôn và niêm phong output do agent tự chạy.
# Kiểm: khuôn, seal (FORMAT/SCOPE, file trạng thái tự kiểm, công cụ sửa sau lần chạy), evidence tool_* gắn dấu băm,
# luật cổng tool_selfcheck / tool_stale / tool_coverage ở cả lint và review.mech, probe của triage, kb tools.
# Dữ liệu tổng hợp: định dạng giả "len32 + crc32 + payload xor 0x5a". Test tự chạy script (như agent sẽ làm), không cần mẫu.
#   python3 tests/check_adhoc.py
import json, os, shutil, struct, subprocess, sys, tempfile, time, zlib
T = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path[:0] = [T, os.path.join(T, 'static')]
import adhoc, case, review

ws = tempfile.mkdtemp(prefix='rea-adhoc-'); c = os.path.join(ws, 'CASE1')
for d in ('report/evidence', 'work/sample'): os.makedirs(os.path.join(c, d))
open(os.path.join(c, 'facts.jsonl'), 'w').close()
pt = b'config: host=h.test port=8443\nSELFCHECK PASS gia: dong lay tu mau\n'; body = bytes(b ^ 0x5a for b in pt)
smp = os.path.join(c, 'work', 'sample', 'blob.dat'); open(smp, 'wb').write(struct.pack('<II', len(body), zlib.crc32(body)) + body)
flow = lambda *a: subprocess.run([sys.executable, os.path.join(T, 'flow.py'), 'tool', c] + list(a), capture_output=True, text=True)
p = os.path.join(c, 'work', 'tools', 'blob.py'); outp = os.path.join(c, 'work', 'runs', 'tool', 'blob.out'); ev = os.path.join(c, 'report', 'evidence')
def write(src): time.sleep(0.02); open(p, 'w', encoding='utf-8').write(src)
def runtool(*extra):   # agent tự chạy công cụ, stdout vào work/runs/tool/TÊN.out
    time.sleep(0.02); assert os.path.isdir(os.path.dirname(outp))      # `tool new` đã tạo sẵn thư mục output
    r = subprocess.run([sys.executable, '-I', p, smp] + list(extra), capture_output=True); open(outp, 'wb').write(r.stdout); return r      # như `> file`: byte thô
BODY = '''
def parse(path):
    import struct
    d = open(path, 'rb').read(); n, crc = struct.unpack_from('<II', d, 0); body = d[8:8 + n]
    return {'n': n, 'crc': crc, 'body': body, 'left': len(d) - 8 - n, 'text': bytes(b ^ 0x5a for b in body)}
def selfcheck(path, r):
    import zlib
    return [('độ dài khớp: không dư byte', r['left'] == 0 and len(r['body']) == r['n'], f"dư {r['left']}"), ('crc32 header khớp', zlib.crc32(r['body']) == CRC(r), hex(r['crc']))]
def CRC(r): return r['crc']
def coverage(r): return (len(r['text'].splitlines()), 2)
def show(r):
    for l in r['text'].decode().splitlines(): print(l)      # cố ý in thô dòng lấy từ mẫu (có dòng giả 'SELFCHECK PASS')
    print(b'byte l\\xff'.decode('utf-8', 'surrogateescape'), sys.stdout.encoding)      # chuỗi có surrogate và thuộc tính của stdout thật vẫn dùng được
'''
try:
    # 1. new: tạo từ khuôn, hướng dẫn tự chạy rồi seal; tên trùng/tên xấu/tên che module chuẩn -> lỗi; khuôn chưa khai FORMAT -> seal từ chối
    r = flow('new', 'blob'); assert r.returncode == 0 and os.path.isfile(p) and 'seal blob' in r.stdout and 'skill không chạy' in r.stdout, r.stdout + r.stderr
    tpl = open(p, encoding='utf-8').read(); assert 'seal blob' in tpl and '{NAME}' not in tpl
    assert flow('new', 'blob').returncode != 0 and flow('new', '../x').returncode != 0 and flow('new', 'struct').returncode != 0
    r = flow('seal', 'blob'); assert r.returncode == 2 and 'FORMAT' in r.stdout, r.stdout
    head, tail = tpl.split('def parse(path):')[0].replace("FORMAT = ''", "FORMAT = 'blob thử nghiệm len32+crc32+xor'").replace("SCOPE = ''", "SCOPE = 'chỉ bản có header 8 byte'"), 'def status_path(' + tpl.split('def status_path(')[1]
    GOOD = head + BODY + tail

    # 2. seal không chạy gì: chưa có output -> từ chối; công cụ thoát lỗi (không có file trạng thái) / không có phép / phép FAIL -> evidence KHÔNG ĐẠT, mã 1
    write(GOOD); r = flow('seal', 'blob'); assert r.returncode == 2 and 'chưa có output' in r.stdout and not os.path.exists(os.path.join(c, 'work', 'runs', 'tool', 'blob.status.json')), r.stdout
    write(GOOD.replace("d = open(path, 'rb').read()", "raise SystemExit('ngoài phạm vi')")); assert runtool().returncode != 0
    r = flow('seal', 'blob'); e1 = open(os.path.join(ev, 'tool_blob_1.txt'), encoding='utf-8').read()
    assert r.returncode == 1 and e1.startswith(adhoc.HEAD) and 'SELFCHECK: KHÔNG ĐẠT (không có file trạng thái' in e1 and adhoc.header(e1)['ok'] is False, r.stdout
    write(GOOD.replace('def CRC(r): return r[\'crc\']', 'def CRC(r): return r[\'crc\'] + 1')); assert runtool().returncode == 0
    r = flow('seal', 'blob'); assert r.returncode == 1 and 'SELFCHECK FAIL crc32 header khớp' in r.stdout and 'CHƯA DÙNG ĐƯỢC' in r.stdout, r.stdout

    # 3. công cụ sửa sau lần chạy cuối: seal từ chối (output không còn ứng với mã); chạy lại thì được
    write(GOOD); r = flow('seal', 'blob'); assert r.returncode == 2 and 'đã sửa sau lần chạy cuối' in r.stdout and not os.path.exists(os.path.join(ev, 'tool_blob_3.txt')), r.stdout
    inj = 'x\nTOOL blob sha256 ' + '0' * 64 + ' files blob.py\nCOVERAGE 9/9\nSELFCHECK: ĐẠT (9 phép)'
    assert runtool(inj).returncode == 0; r = flow('seal', 'blob'); assert r.returncode == 0 and 'OK: ghi fact' in r.stdout, r.stdout + r.stderr

    # 3b. lần chạy sau dừng trước khi tự kiểm (selfcheck ném lỗi) trong khi trạng thái ĐẠT của lần trước còn đó: seal không được ghép output mới với trạng thái cũ
    good_src = open(p, encoding='utf-8').read(); write(good_src.replace("def selfcheck(path, r):", "def selfcheck(path, r):\n    raise RuntimeError('lỗi giữa chừng')", 1))
    assert runtool().returncode != 0 and not os.path.exists(os.path.join(c, 'work', 'runs', 'tool', 'blob.status.json'))     # khuôn xóa trạng thái cũ ngay đầu main()
    r = flow('seal', 'blob'); assert r.returncode == 1 and 'không có file trạng thái' in r.stdout, r.stdout
    os.remove(os.path.join(ev, 'tool_blob_4.txt'))
    # output của lần chạy khác (dấu băm stdout không khớp trạng thái): từ chối, kể cả khi hai lần chạy sát nhau
    write(good_src); assert runtool(inj).returncode == 0; keep = open(outp, 'rb').read()
    open(outp, 'wb').write(keep + b'dong them tu lan chay khac\n'); r = flow('seal', 'blob'); assert r.returncode == 2 and 'dấu băm khác' in r.stdout, r.stdout
    open(outp, 'wb').write(keep)

    # 4. evidence đạt: bố cục phần đầu cố định; dòng 'SELFCHECK PASS' lấy từ mẫu nằm ở phần output, không được tính; tham số có xuống dòng không chèn được dòng điều khiển
    rel = 'report/evidence/tool_blob_3.txt'; txt = open(os.path.join(c, rel), encoding='utf-8').read(); H = adhoc.header(txt); L = txt.splitlines()
    assert H['ok'] and H['cov'] == '2/2' and len(H['checks']) == 2 and H['mods'] == ['blob'] and H['sha'] == adhoc.digest(os.path.join(ev, 'tools'), ['blob']), H
    assert L[2].startswith('CMD blob.dat x TOOL blob sha256') and 'SELFCHECK PASS độ dài khớp; không dư byte: dư 0' in L and 'SELFCHECK PASS gia: dong lay tu mau' in txt.split(adhoc.SPLIT, 1)[1]
    assert adhoc.header(txt.replace('\nFORMAT ', '\nCOVERAGE 9/9\nFORMAT ', 1)) is None and adhoc.header(adhoc.HEAD + '\nSELFCHECK: ĐẠT\n') is None
    assert open(os.path.join(ev, 'tools', 'blob.py'), encoding='utf-8').read() == GOOD
    ln = 1 + L.index('config: host=h.test port=8443')

    # 5. luật cổng: khớp nhau giữa lint và review.mech, đều mức high
    A = lambda **f: case.add(c, **f)
    A(id='ok', kind='config', value='h.test port=8443', src='S', evidence=f'{rel}#L{ln}'); A(id='cov', kind='dec_coverage', value='2/2', src='S', evidence=rel)
    A(id='badcov', kind='dec_coverage', value='9/9', src='S', evidence=rel); A(id='nosc', kind='config', value='h.test', src='S', evidence='report/evidence/tool_blob_2.txt')
    open(os.path.join(ev, 'tool_fake_1.txt'), 'w').write('SELFCHECK: ĐẠT (1 phép)\nh.test\n'); A(id='fake', kind='config', value='h.test', src='S', evidence='report/evidence/tool_fake_1.txt')
    F = case.load(c); lint = {i: sorted(x['check'] for x in case.lint_fact(c, F[i]) if x['check'].startswith('tool_')) for i in F}
    mech = {i: sorted(x['check'] for x in review.mech(c) if x['id'] == i and x['check'].startswith('tool_')) for i in F}
    want = {'ok': [], 'cov': [], 'badcov': ['tool_coverage'], 'nosc': ['tool_selfcheck', 'tool_stale'], 'fake': []}   # 'fake': tên trùng mẫu nhưng không mang phần đầu của seal -> không áp luật (evidence cũ của người phân tích)
    assert lint == want and mech == want, (lint, mech)
    assert all(x['severity'] == 'high' for x in review.mech(c) if x['check'].startswith('tool_'))
    open(os.path.join(ev, 'tool_output.txt'), 'w').write('h.test có sẵn\n'); A(id='old', kind='config', value='h.test', src='S', evidence='report/evidence/tool_output.txt')   # tên tool_ có từ trước, không theo mẫu của seal: không áp luật T1b
    assert not [x for x in case.lint_fact(c, case.load(c)['old']) if x['check'].startswith('tool_')]
    # một tiêu chí nhận diện cho lint/mech/gate: tên tool_<TÊN>_<n>.txt của công cụ có trong case thì xóa dòng đầu không thoát luật; sửa phần output sau khi seal -> tool_stale
    tk = lambda i: sorted(x['check'] for x in case.lint_fact(c, case.load(c)[i]) if x['check'].startswith('tool_'))
    good = open(os.path.join(c, rel), encoding='utf-8').read(); assert adhoc.header(good)['out'] == adhoc.body_sha(good) == adhoc.body_sha(good.rstrip('\n'))
    open(os.path.join(c, rel), 'w', encoding='utf-8').write(good.split('\n', 1)[1]); assert tk('ok') == ['tool_selfcheck'] and any(x['id'] == 'ok' and x['check'] == 'tool_selfcheck' for x in review.mech(c))
    open(os.path.join(c, rel), 'w', encoding='utf-8').write(good + 'config: host=evil.test port=1\n'); assert tk('ok') == ['tool_stale'] and any(x['id'] == 'ok' and x['check'] == 'tool_stale' for x in review.mech(c))
    open(os.path.join(c, rel), 'w', encoding='utf-8').write(good.replace('\nOUT sha256 ', '\nOUT sha255 ', 1)); assert tk('ok') == ['tool_stale']
    open(os.path.join(c, rel), 'w', encoding='utf-8').write(good); assert tk('ok') == []
    open(os.path.join(ev, 'copy.txt'), 'w', encoding='utf-8').write(good + 'thêm\n'); A(id='cp', kind='config', value='h.test port=8443', src='S', evidence=f'report/evidence/copy.txt#L{ln}'); assert tk('cp') == ['tool_stale']   # bản đã seal chép sang tên khác vẫn bị áp luật
    open(os.path.join(ev, 'copy.txt'), 'w', encoding='utf-8').write(good)
    assert subprocess.run([sys.executable, os.path.join(T, 'flow.py'), 'tool', os.path.join(ws, 'KHONG_CO'), 'list'], capture_output=True, text=True).returncode != 0

    # 6. sửa công cụ, chạy và seal lại: fact cũ thành tool_stale ở cả hai nơi, evidence mới sạch; module cạnh script cũng vào dấu băm; import mạng chỉ bị NHẮC
    open(os.path.join(c, 'work', 'tools', 'helper_mod.py'), 'w').write('import socket\nK = 0x5a\n')
    write(GOOD.replace('def parse(path):', 'import helper_mod\ndef parse(path):', 1)); assert runtool().returncode == 0
    r = flow('seal', 'blob'); t4 = open(os.path.join(ev, 'tool_blob_4.txt'), encoding='utf-8').read(); H4 = adhoc.header(t4)
    assert r.returncode == 0 and H4['mods'] == ['blob', 'helper_mod'] and H4['ok'] and 'NOTE helper_mod.py:1: import socket' in t4 and 'NHẮC' in r.stdout, r.stdout
    assert [x['check'] for x in case.lint_fact(c, F['ok']) if x['check'].startswith('tool_')] == ['tool_stale'] and any(x['id'] == 'ok' and x['check'] == 'tool_stale' for x in review.mech(c))
    A(id='ok2', kind='config', value='h.test port=8443', src='S', evidence=f'report/evidence/tool_blob_4.txt#L{1 + t4.splitlines().index("config: host=h.test port=8443")}', supersedes='ok')
    assert not [x for x in case.lint_fact(c, case.load(c)['ok2']) if x['check'].startswith('tool_')]
    time.sleep(0.02); open(os.path.join(ev, 'tools', 'helper_mod.py'), 'a').write('# đổi\n')       # sửa bản lưu của module phụ: evidence cũng thành stale
    assert [x['check'] for x in case.lint_fact(c, case.load(c)['ok2']) if x['check'].startswith('tool_')] == ['tool_stale']
    # lần seal không đạt không ghi đè bản lưu công cụ: evidence đạt trước đó không vì thế mà thành stale; output không cùng lần chạy với trạng thái -> từ chối
    shutil.copy(p, os.path.join(ev, 'tools', 'blob.py')); shutil.copy(os.path.join(c, 'work', 'tools', 'helper_mod.py'), os.path.join(ev, 'tools', 'helper_mod.py'))
    assert not [x for x in case.lint_fact(c, case.load(c)['ok2']) if x['check'].startswith('tool_')]
    good_now = open(p, encoding='utf-8').read(); write(good_now.replace("def CRC(r): return r['crc']", "def CRC(r): return r['crc'] + 2")); assert runtool().returncode == 0
    assert flow('seal', 'blob').returncode == 1 and not [x for x in case.lint_fact(c, case.load(c)['ok2']) if x['check'].startswith('tool_')]
    time.sleep(0.02); open(os.path.join(ev, 'tools', 'helper_mod.py'), 'a').write('# đổi\n')
    # cổng: review PASS rồi mà evidence công cụ thành stale (facts.jsonl không đổi) thì gate đóng lại
    c3 = os.path.join(ws, 'CASE3'); shutil.copytree(c, c3); os.makedirs(os.path.join(c3, 'work', 'review'), exist_ok=True)
    open(os.path.join(c3, 'facts.jsonl'), 'w').close(); case.add(c3, id='g', kind='config', value='h.test port=8443', src='S', evidence='report/evidence/tool_blob_4.txt')
    json.dump({'rule_version': case.REVIEW_RULE_VERSION, 'stopped': False, 'rounds': [{'n': 1, 'verdict': 'PASS', 'facts_sha256': review.facts_sha(c3), 'reviewer': 'mech+stub'}]}, open(os.path.join(review.DIR(c3), 'state.json'), 'w'))
    assert review.gate(c3)[0] is False and 'tool_stale' in review.gate(c3)[1], review.gate(c3)
    shutil.copy(os.path.join(c, 'work', 'tools', 'helper_mod.py'), os.path.join(c3, 'report', 'evidence', 'tools', 'helper_mod.py')); assert review.gate(c3)[0] is True, review.gate(c3)
    e3 = os.path.join(c3, 'report', 'evidence'); g4 = open(os.path.join(e3, 'tool_blob_4.txt'), encoding='utf-8').read()   # cổng dùng cùng tiêu chí: bản seal mang tên khác, bị sửa phần output -> đóng
    open(os.path.join(e3, 'khac.txt'), 'w', encoding='utf-8').write(g4 + 'thêm\n'); case.add(c3, id='g2', kind='config', value='h.test port=8443', src='S', evidence='report/evidence/khac.txt')
    st = json.load(open(os.path.join(review.DIR(c3), 'state.json'))); st['rounds'][0]['facts_sha256'] = review.facts_sha(c3); json.dump(st, open(os.path.join(review.DIR(c3), 'state.json'), 'w'))
    assert review.gate(c3)[0] is False and 'tool_stale' in review.gate(c3)[1], review.gate(c3)
    open(os.path.join(e3, 'khac.txt'), 'w', encoding='utf-8').write(g4); assert review.gate(c3)[0] is True, review.gate(c3)
    shutil.rmtree(c3)
    r = flow('list'); assert 'tool_blob_4.txt: blob tự kiểm ĐẠT, COVERAGE 2/2, CŨ' in r.stdout and 'tool_blob_1.txt: blob tự kiểm KHÔNG ĐẠT' in r.stdout, r.stdout
    import ast; tr = ast.parse(open(os.path.join(T, 'adhoc.py'), encoding='utf-8').read())    # bất biến của tầng này: adhoc.py không có đường chạy mã nào
    imps = {a.name.split('.')[0] for n in ast.walk(tr) if isinstance(n, ast.Import) for a in n.names} | {n.module.split('.')[0] for n in ast.walk(tr) if isinstance(n, ast.ImportFrom) and n.module}
    calls = {n.attr for n in ast.walk(tr) if isinstance(n, ast.Attribute)} | {n.id for n in ast.walk(tr) if isinstance(n, ast.Name)}
    assert imps == {'ast', 'hashlib', 'json', 'os', 're', 'shutil', 'sys'} and not calls & {'system', 'popen', 'exec', 'eval', 'run_path', 'Popen', 'execv', 'spawnv', '__import__'}, (imps, calls & {'system', 'popen', 'exec', 'eval'})

    # 6b. evidence gắn với file đầu vào: ghi dòng INPUT; đầu vào ngoài case -> KHÔNG ĐẠT; đầu vào đổi sau lần chạy -> từ chối
    import hashlib
    def runon(f): time.sleep(0.02); r = subprocess.run([sys.executable, '-I', p, f], capture_output=True); open(outp, 'wb').write(r.stdout); return r
    nev = lambda: sorted((x for x in os.listdir(ev) if x.startswith('tool_blob_')), key=lambda x: int(x.split('_')[2][:-4]))[-1]
    write(good_now); assert runon(smp).returncode == 0 and flow('seal', 'blob').returncode == 0
    relN = 'report/evidence/' + nev()
    assert f"INPUT sha256 {hashlib.sha256(open(smp, 'rb').read()).hexdigest()} {os.path.join('work', 'sample', 'blob.dat')}" in open(os.path.join(ev, nev()), encoding='utf-8').read().split(adhoc.SPLIT)[0]
    ngoai = os.path.join(ws, 'blob.dat'); shutil.copy(smp, ngoai); assert runon(ngoai).returncode == 0      # file cùng tên ở ngoài case
    r = flow('seal', 'blob'); assert r.returncode == 1 and 'không nằm trong thư mục case' in r.stdout and 'INPUT sha256' not in open(os.path.join(ev, nev()), encoding='utf-8').read(), r.stdout
    os.makedirs(os.path.join(c, 'work', 'extract')); trong = os.path.join(c, 'work', 'extract', 'b.dat'); shutil.copy(smp, trong); assert runon(trong).returncode == 0
    last = nev(); open(trong, 'ab').write(b'x'); r = flow('seal', 'blob'); assert r.returncode == 2 and 'đã đổi sau lần chạy' in r.stdout and nev() == last, r.stdout
    A(id='covtxt', kind='dec_coverage', value='9/9 chuỗi', src='S', evidence=relN); assert tk('covtxt') == ['tool_coverage']      # tỉ lệ kèm chữ vẫn được so
    A(id='covtxt2', kind='dec_coverage', value='2/2 dòng', src='S', evidence=relN); assert tk('covtxt2') == []
    r = flow('new', 'fake'); assert r.returncode != 0 and 'tool_fake_1.txt' in r.stderr and not os.path.exists(os.path.join(c, 'work', 'tools', 'fake.py')), r.stderr   # tên trùng file tool_* có sẵn không do seal sinh

    # 7. triage: file lạ -> unknown có probe, định tuyến sang flow.py tool; lớp zlib được nhận; bom nén không bị giải hết
    import triage
    rnd = bytes((i * 197 + 13) % 251 for i in range(5000)); P = triage.probe(rnd); assert len(P['head']) == 32 and len(P['entropy8']) == 8 and P['wrap'] == [], P
    P = triage.probe(zlib.compress(b'\x7fELF' + b'A' * 5000)); assert [(w['codec'], w['inner_type']) for w in P['wrap']] == [('zlib', 'ELF')], P
    assert len(triage._head(lambda b, n: zlib.decompressobj().decompress(b, n), zlib.compress(b'\0' * (64 << 20)))) == 4096
    assert 'flow.py tool' in triage.route({'flags': [], 'type': 'unknown'}, '.')
    o = os.path.join(ws, 'tri'); r = subprocess.run([sys.executable, '-I', os.path.join(T, 'static', 'triage.py'), smp, '--out', o], capture_output=True, text=True)
    R = json.load(open(os.path.join(o, 'triage.json'))); assert R['type'] == 'unknown' and 'probe' in R and '  probe: đầu ' in r.stdout and 'flow.py tool' in R['next'], r.stdout

    # 8. kb tools: gom theo FORMAT trên các case của workspace; cùng định dạng ở 2 case mới thành ứng viên
    kbrun = lambda: subprocess.run([sys.executable, os.path.join(T, 'flow.py'), 'kb', 'tools'], capture_output=True, text=True, env=dict(os.environ, REA_WORKSPACE=ws, REA_KB='off'), cwd=ws)
    r = kbrun(); assert 'lặp lại ở >= 2 case: 0' in r.stdout and '(1 case) blob thử nghiệm' in r.stdout, r.stdout + r.stderr
    c2 = os.path.join(ws, 'CASE2'); os.makedirs(os.path.join(c2, 'report', 'evidence', 'tools')); os.makedirs(os.path.join(c2, 'work')); open(os.path.join(c2, 'facts.jsonl'), 'w').close()
    shutil.copy(os.path.join(ev, 'tools', 'blob.py'), os.path.join(c2, 'report', 'evidence', 'tools', 'khac.py'))
    r = kbrun(); assert 'lặp lại ở >= 2 case: 1' in r.stdout and 'CASE1/blob.py' in r.stdout and 'CASE2/khac.py' in r.stdout, r.stdout
finally: shutil.rmtree(ws, ignore_errors=True)
print('OK check_adhoc')
