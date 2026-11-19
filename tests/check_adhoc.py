#!/usr/bin/env python3
# Tầng T1b (flow.py tool): skill không chạy công cụ, chỉ cấp khuôn và niêm phong output do agent tự chạy.
# Kiểm: khuôn, seal (FORMAT/SCOPE, file trạng thái tự kiểm, công cụ sửa sau lần chạy), evidence tool_* gắn dấu băm,
# luật cổng tool_selfcheck / tool_stale / tool_coverage ở cả lint và review.mech, probe của triage, kb tools.
# Dữ liệu tổng hợp: định dạng giả "len32 + crc32 + payload xor 0x5a". Test tự chạy script (như agent sẽ làm), không cần mẫu.
#   python3 tests/check_adhoc.py
import json, os, re, shutil, struct, subprocess, sys, tempfile, time, zlib
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
def known_answers():
    import struct, zlib      # đáp án biết trước: dữ liệu dựng bằng thư viện chuẩn, không bằng mã của công cụ
    mk = lambda pt: (lambda b: struct.pack('<II', len(b), zlib.crc32(b)) + b)(bytes(x ^ 0x5a for x in pt))
    return [('thông điệp ngắn', mk(b'abc'), lambda r: r['text'] == b'abc'), ('rỗng', mk(b''), lambda r: r['text'] == b'')]
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
    F = case.load(c); LF = {i: case.lint_fact(c, F[i]) for i in F}; MX = review.mech(c)
    # tool_isolation: cảnh báo (lint warn, mech weak), không chặn; tách riêng khỏi các luật fail
    iso = {i: [x['level'] for x in LF[i] if x['check'] == 'tool_isolation'] + [x['verdict'] for x in MX if x['id'] == i and x['check'] == 'tool_isolation'] for i in F}
    net = {i: case.adhoc.header(open(case.ev_path(c, F[i]['evidence'])[1], encoding='utf-8').read()) for i in F}
    for i in F:
        has = bool(net[i]) and str(net[i].get('net') or '').startswith('có')
        assert iso[i] == (['warn', 'weak'] if has else []), (i, iso[i], net[i] and net[i].get('net'))
    lint = {i: sorted(x['check'] for x in LF[i] if x['check'].startswith('tool_') and x['check'] != 'tool_isolation') for i in F}
    mech = {i: sorted(x['check'] for x in MX if x['id'] == i and x['check'].startswith('tool_') and x['check'] != 'tool_isolation') for i in F}
    want = {'ok': [], 'cov': [], 'badcov': ['tool_coverage'], 'nosc': ['tool_selfcheck', 'tool_stale'], 'fake': []}   # 'fake': tên trùng mẫu nhưng không mang phần đầu của seal -> không áp luật (evidence cũ của người phân tích)
    assert lint == want and mech == want, (lint, mech)
    assert all(x['severity'] == 'high' for x in review.mech(c) if x['check'].startswith('tool_') and x['check'] != 'tool_isolation')
    open(os.path.join(ev, 'tool_output.txt'), 'w').write('h.test có sẵn\n'); A(id='old', kind='config', value='h.test', src='S', evidence='report/evidence/tool_output.txt')   # tên tool_ có từ trước, không theo mẫu của seal: không áp luật T1b
    assert not [x for x in case.lint_fact(c, case.load(c)['old']) if (x['check'].startswith('tool_') and x['check'] != 'tool_isolation')]
    # một tiêu chí nhận diện cho lint/mech/gate: tên tool_<TÊN>_<n>.txt của công cụ có trong case thì xóa dòng đầu không thoát luật; sửa phần output sau khi seal -> tool_stale
    tk = lambda i: sorted(x['check'] for x in case.lint_fact(c, case.load(c)[i]) if x['check'].startswith('tool_') and x['check'] != 'tool_isolation')
    good = open(os.path.join(c, rel), encoding='utf-8').read(); assert adhoc.header(good)['out'] == adhoc.body_sha(good) == adhoc.body_sha(good.rstrip('\n'))
    open(os.path.join(c, rel), 'w', encoding='utf-8').write(good.split('\n', 1)[1]); assert tk('ok') == ['tool_selfcheck'] and any(x['id'] == 'ok' and x['check'] == 'tool_selfcheck' for x in review.mech(c))
    open(os.path.join(c, rel), 'w', encoding='utf-8').write(good + 'config: host=evil.test port=1\n'); assert tk('ok') == ['tool_stale'] and any(x['id'] == 'ok' and x['check'] == 'tool_stale' for x in review.mech(c))
    open(os.path.join(c, rel), 'w', encoding='utf-8').write(good.replace('\nOUT sha256 ', '\nOUT sha255 ', 1)); assert tk('ok') == ['tool_stale']
    open(os.path.join(c, rel), 'w', encoding='utf-8').write(good); assert tk('ok') == []
    open(os.path.join(ev, 'copy.txt'), 'w', encoding='utf-8').write(good + 'thêm\n'); A(id='cp', kind='config', value='h.test port=8443', src='S', evidence=f'report/evidence/copy.txt#L{ln}'); assert tk('cp') == ['tool_stale']   # bản đã seal chép sang tên khác vẫn bị áp luật
    open(os.path.join(ev, 'copy.txt'), 'w', encoding='utf-8').write(good)
    assert subprocess.run([sys.executable, os.path.join(T, 'flow.py'), 'tool', os.path.join(ws, 'KHONG_CO'), 'list'], capture_output=True, text=True).returncode != 0

    # 6. sửa công cụ, chạy và seal lại: fact cũ thành tool_stale ở cả hai nơi, evidence mới sạch; module cạnh script cũng vào dấu băm; import mạng chỉ bị NHẮC
    open(os.path.join(c, 'work', 'tools', 'helper_mod.py'), 'w').write('import struct\nK = 0x5a\n')
    write(GOOD.replace('def parse(path):', 'import helper_mod\ndef parse(path):', 1)); assert runtool().returncode == 0
    r = flow('seal', 'blob'); t4 = open(os.path.join(ev, 'tool_blob_4.txt'), encoding='utf-8').read(); H4 = adhoc.header(t4)
    assert r.returncode == 0 and H4['mods'] == ['blob', 'helper_mod'] and H4['ok'] and 'MUTATION 8/8' in t4 and 'KAT 2/2' in t4 and 'ISOLATION net=' in t4 and adhoc.header(t4)['mut'] == (8, 8) and adhoc.header(t4)['kat'] == (2, 2), r.stdout
    # tool_isolation có ca tổng hợp cố định cho cả hai nhánh, không phụ thuộc mạng của máy chạy test
    iso = lambda v: [x[0] for x in adhoc.notes(c, {}, 'report/evidence/tool_blob_4.txt', re.sub(r'(?m)^ISOLATION net=.*$', lambda m: 'ISOLATION net=' + v, t4))]
    assert iso('có (eth0)') == ['tool_isolation'] and iso('không') == [], (iso('có (eth0)'), iso('không'))
    ns = {'__file__': p, 'os': os}; exec(re.search(r'^OUT_DIR = .*?(?=   #)', open(p, encoding='utf-8').read(), re.M)[0], ns)   # OUT_DIR theo vị trí công cụ, không theo cwd
    assert ns['OUT_DIR'] == os.path.join(c, 'work', 'runs', 'tool', 'blob'), ns['OUT_DIR']
    assert [x['check'] for x in case.lint_fact(c, F['ok']) if (x['check'].startswith('tool_') and x['check'] != 'tool_isolation')] == ['tool_stale'] and any(x['id'] == 'ok' and x['check'] == 'tool_stale' for x in review.mech(c))
    A(id='ok2', kind='config', value='h.test port=8443', src='S', evidence=f'report/evidence/tool_blob_4.txt#L{1 + t4.splitlines().index("config: host=h.test port=8443")}', supersedes='ok')
    assert not [x for x in case.lint_fact(c, case.load(c)['ok2']) if (x['check'].startswith('tool_') and x['check'] != 'tool_isolation')]
    time.sleep(0.02); open(os.path.join(ev, 'tools', 'helper_mod.py'), 'a').write('# đổi\n')       # sửa bản lưu của module phụ: evidence cũng thành stale
    assert [x['check'] for x in case.lint_fact(c, case.load(c)['ok2']) if (x['check'].startswith('tool_') and x['check'] != 'tool_isolation')] == ['tool_stale']
    # lần seal không đạt không ghi đè bản lưu công cụ: evidence đạt trước đó không vì thế mà thành stale; output không cùng lần chạy với trạng thái -> từ chối
    shutil.copy(p, os.path.join(ev, 'tools', 'blob.py')); shutil.copy(os.path.join(c, 'work', 'tools', 'helper_mod.py'), os.path.join(ev, 'tools', 'helper_mod.py'))
    assert not [x for x in case.lint_fact(c, case.load(c)['ok2']) if (x['check'].startswith('tool_') and x['check'] != 'tool_isolation')]
    good_now = open(p, encoding='utf-8').read(); write(good_now.replace("def CRC(r): return r['crc']", "def CRC(r): return r['crc'] + 2")); assert runtool().returncode == 0
    assert flow('seal', 'blob').returncode == 1 and not [x for x in case.lint_fact(c, case.load(c)['ok2']) if (x['check'].startswith('tool_') and x['check'] != 'tool_isolation')]
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
    time.sleep(0.02); r = subprocess.run([sys.executable, '-I', os.path.join('work', 'tools', 'blob.py'), os.path.join('work', 'sample', 'blob.dat')], capture_output=True, cwd=c); open(outp, 'wb').write(r.stdout)
    r = subprocess.run([sys.executable, os.path.join(T, 'flow.py'), 'tool', c, 'seal', 'blob'], capture_output=True, text=True, cwd=ws); assert r.returncode == 0, r.stdout      # chạy bằng đường dẫn tương đối trong case, seal từ thư mục khác
    sj = os.path.join(c, 'work', 'runs', 'tool', 'blob.status.json'); st0 = json.load(open(sj)); json.dump({k: v for k, v in st0.items() if k not in ('inputs', 'first')}, open(sj, 'w'))
    r = flow('seal', 'blob'); assert r.returncode == 1 and 'khuôn cũ' in r.stdout and 'status_path()' in r.stdout, r.stdout      # trạng thái của khuôn cũ: nói rõ cách chuyển
    ngoai = os.path.join(ws, 'blob.dat'); shutil.copy(smp, ngoai); assert runon(ngoai).returncode == 0      # file cùng tên ở ngoài case
    r = flow('seal', 'blob'); assert r.returncode == 1 and 'không nằm trong thư mục case' in r.stdout and 'INPUT sha256' not in open(os.path.join(ev, nev()), encoding='utf-8').read(), r.stdout
    os.makedirs(os.path.join(c, 'work', 'extract')); trong = os.path.join(c, 'work', 'extract', 'b.dat'); shutil.copy(smp, trong); assert runon(trong).returncode == 0
    last = nev(); open(trong, 'ab').write(b'x'); r = flow('seal', 'blob'); assert r.returncode == 2 and 'đã đổi sau lần chạy' in r.stdout and nev() == last, r.stdout
    os.remove(trong); r = flow('seal', 'blob'); assert r.returncode == 2 and 'đã mất sau lần chạy' in r.stdout and nev() == last, r.stdout      # đầu vào trong case bị xóa: báo đúng lý do
    A(id='covtxt', kind='dec_coverage', value='9/9 chuỗi', src='S', evidence=relN); assert tk('covtxt') == ['tool_coverage']      # tỉ lệ kèm chữ vẫn được so
    A(id='covtxt2', kind='dec_coverage', value='2/2 dòng', src='S', evidence=relN); assert tk('covtxt2') == []
    r = flow('new', 'fake'); assert r.returncode != 0 and 'tool_fake_1.txt' in r.stderr and not os.path.exists(os.path.join(c, 'work', 'tools', 'fake.py')), r.stderr   # tên trùng file tool_* có sẵn không do seal sinh

    # 6c. thử đột biến, đáp án biết trước, thành phần bị cấm: mỗi biến thể là một công cụ riêng (không làm lệch số thứ tự evidence của blob)
    def mk(name, body=BODY, waiver='', hd=None):
        assert flow('new', name).returncode == 0; q = os.path.join(c, 'work', 'tools', name + '.py'); t = open(q, encoding='utf-8').read(); h0, t0 = t.split('def parse(path):')[0], 'def status_path(' + t.split('def status_path(')[1]
        h0 = h0.replace("FORMAT = ''", "FORMAT = 'blob thử nghiệm len32+crc32+xor'").replace("SCOPE = ''", "SCOPE = 'chỉ bản có header 8 byte'").replace("KAT_WAIVER = ''", f'KAT_WAIVER = {waiver!r}')
        time.sleep(0.02); open(q, 'w', encoding='utf-8').write((hd or h0) + body + t0)
        time.sleep(0.02); r = subprocess.run([sys.executable, '-I', q, smp], capture_output=True); open(os.path.join(c, 'work', 'runs', 'tool', name + '.out'), 'wb').write(r.stdout); return r, q
    def sealed(name): r = flow('seal', name); return r, open(os.path.join(ev, f'tool_{name}_1.txt'), encoding='utf-8').read()
    # (a) selfcheck luôn đúng: mọi byte sửa đều lọt -> MUTATION 0/8, KHÔNG ĐẠT, cổng báo tool_mutation
    weak = BODY[:BODY.index('def selfcheck')] + "def selfcheck(path, r):\n    return [('luôn đúng', True, '')]\n" + BODY[BODY.index('def CRC'):]
    assert mk('weak', weak)[0].returncode == 0; r, t = sealed('weak'); Hw = adhoc.header(t)
    assert r.returncode == 1 and 'MUTATION 0/8' in t and 'thử đột biến' in t and Hw['mut'] == (0, 8) and not Hw['ok'], r.stdout
    A(id='weakf', kind='config', value='h.test', src='S', evidence='report/evidence/tool_weak_1.txt'); assert 'tool_mutation' in tk('weakf') and 'tool_selfcheck' in tk('weakf'), tk('weakf')
    # sửa tay dòng MUTATION trên evidence đã seal: cổng vẫn bắt ở chỗ khác (dấu băm công cụ vẫn khớp nên kiểm trực tiếp dòng này)
    good4 = open(os.path.join(ev, 'tool_blob_4.txt'), encoding='utf-8').read(); assert [x[0] for x in adhoc.issues(c, {'kind': 'config', 'value': 'x'}, 'report/evidence/tool_blob_4.txt', good4.replace('MUTATION 8/8', 'MUTATION 0/8'))].count('tool_mutation') == 1
    # (b) đáp án biết trước sai -> KHÔNG ĐẠT, nêu tên ca; không có ca và không khai waiver -> KHÔNG ĐẠT; có waiver -> ĐẠT, ghi lý do
    badkat = BODY.replace("lambda r: r['text'] == b'abc'", "lambda r: r['text'] == b'abd'")
    assert mk('kat1', badkat)[0].returncode == 0; r, t = sealed('kat1'); assert r.returncode == 1 and 'KAT 1/2' in t and 'sai đáp án biết trước: thông điệp ngắn' in t, t
    assert 'tool_kat' in [x[0] for x in adhoc.issues(c, {'kind': 'config', 'value': 'x'}, 'report/evidence/tool_kat1_1.txt', t)]
    nokat = BODY[:BODY.index('def known_answers')] + BODY[BODY.index('def coverage'):]; nokat = nokat.replace('def coverage', 'def known_answers():\n    return []\ndef coverage', 1)
    assert mk('kat2', nokat)[0].returncode == 0; r, t = sealed('kat2'); assert r.returncode == 1 and 'chưa có known_answers' in t, t
    assert mk('kat3', nokat, waiver='định dạng chỉ có trong mẫu, không dựng lại được')[0].returncode == 0; r, t = sealed('kat3'); assert r.returncode == 0 and 'KAT n/a: định dạng chỉ có trong mẫu' in t and 'NHẮC' in r.stdout, r.stdout
    # (c) thành phần bị cấm: import mạng/nạp mã động, exec/eval/os.system -> KHÔNG ĐẠT; platform.system() và urllib.parse thì không
    for nm, line in (('b1', 'import socket'), ('b2', 'from importlib import import_module'), ('b3', 'def _f():\n    eval("1")'), ('b4', 'import os\ndef _f():\n    os.system("true")'), ('b5', 'import pickle')):
        q = mk(nm, BODY + '\n' + line + '\n')[1]; r, t = sealed(nm); assert r.returncode == 1 and 'NOTE ' in t and 'bị cấm trong T1b' in t, (nm, r.stdout)
    for nm, line in (('b7', 'from os import posix_spawn'), ('b8', 'import os\ndef _f():\n    os.posix_spawnp("a", ["a"], {})')):
        mk(nm, BODY + '\n' + line + '\n'); r, t = sealed(nm); assert r.returncode == 1 and 'bị cấm trong T1b' in t, (nm, r.stdout)
    ok = mk('b9', BODY + '\nfrom urllib import parse as up\nfrom re import compile as rc\n')[1]; r, t = sealed('b9'); assert r.returncode == 0 and 'NOTE ' not in t, r.stdout      # không chặn nhầm
    # (e) phép thử đột biến vô hiệu: parse chỉ chạy được khi đứng cạnh file khác -> bản sao ở thư mục tạm lỗi, không được tính là 'phát hiện'
    side = BODY.replace("d = open(path, 'rb').read();", "open(os.path.join(os.path.dirname(path), 'blob.dat')).close(); d = open(path, 'rb').read();")
    mk('side', side); r, t = sealed('side'); assert r.returncode == 1 and 'thử đột biến vô hiệu' in t, t
    # selfcheck phụ thuộc file cạnh đầu vào (parse thì không): bản đối chứng bị selfcheck báo hỏng -> vô hiệu, không được ra MUTATION 8/8
    mk('side2', BODY.replace("return [('độ dài khớp", "return [('có file cạnh', os.path.exists(os.path.join(os.path.dirname(path), 'blob.dat')), ''), ('độ dài khớp", 1)); r, t = sealed('side2')
    assert r.returncode == 1 and 'thử đột biến vô hiệu' in t and 'có file cạnh' in t and 'MUTATION 8/8' not in t, t
    # main() tùy biến không truyền trials: báo đúng lý do
    q = mk('notr')[1]; src = open(q, encoding='utf-8').read(); assert '_trials(path, dt)' in src; time.sleep(0.02); open(q, 'w', encoding='utf-8').write(src.replace('_trials(path, dt)', 'None'))
    time.sleep(0.02); r0 = subprocess.run([sys.executable, '-I', q, smp], capture_output=True); open(os.path.join(c, 'work', 'runs', 'tool', 'notr.out'), 'wb').write(r0.stdout); r, t = sealed('notr'); assert r.returncode == 1 and 'chưa chạy thử đột biến' in t, t
    # quá giờ trên dữ liệu đột biến (giới hạn nới xuống 1 giây): không tính vào mẫu số, báo đúng lý do chứ không phải 'selfcheck không phát hiện'
    slow = BODY.replace("d = open(path, 'rb').read();", "d = open(path, 'rb').read(); import time; (time.sleep(3) if d != open(" + repr(smp) + ", 'rb').read() else 0);", 1)
    mk('slow', slow, hd=None); qs = os.path.join(c, 'work', 'tools', 'slow.py'); ts = open(qs, encoding='utf-8').read(); time.sleep(0.02); open(qs, 'w', encoding='utf-8').write(ts.replace('TRIAL_SECONDS = 30', 'TRIAL_SECONDS = 1'))
    time.sleep(0.02); r0 = subprocess.run([sys.executable, '-I', qs, smp], capture_output=True); open(os.path.join(c, 'work', 'runs', 'tool', 'slow.out'), 'wb').write(r0.stdout); r, t = sealed('slow')
    assert r.returncode == 1 and 'đều quá giờ' in t and 'selfcheck không phát hiện' not in t, t
    # một phần lần thử quá giờ + selfcheck không bắt được lần còn lại: kết quả nêu số lần quá giờ
    half = weak.replace("d = open(path, 'rb').read();", "d = open(path, 'rb').read(); import time; (time.sleep(3) if d[:len(d) // 2] != open(" + repr(smp) + ", 'rb').read()[:len(d) // 2] else 0);", 1)
    mk('half', half); qh = os.path.join(c, 'work', 'tools', 'half.py'); th = open(qh, encoding='utf-8').read(); time.sleep(0.02); open(qh, 'w', encoding='utf-8').write(th.replace('TRIAL_SECONDS = 30', 'TRIAL_SECONDS = 1'))
    time.sleep(0.02); r0 = subprocess.run([sys.executable, '-I', qh, smp], capture_output=True); open(os.path.join(c, 'work', 'runs', 'tool', 'half.out'), 'wb').write(r0.stdout); r, t = sealed('half')
    assert r.returncode == 1 and 'MUTATION 0/4' in t and '(4 lần thử quá giờ không tính)' in t, t
    # công cụ khuôn cũ chuyển theo hướng dẫn (chép từ status_path() trở xuống) không có TRIAL_SECONDS ở phần đầu: vẫn chạy được
    mk('oldh'); qo = os.path.join(c, 'work', 'tools', 'oldh.py'); to = open(qo, encoding='utf-8').read(); assert 'TRIAL_SECONDS = 30' in to
    time.sleep(0.02); open(qo, 'w', encoding='utf-8').write(''.join(l for l in to.splitlines(True) if not l.startswith('TRIAL_SECONDS')))
    time.sleep(0.02); r0 = subprocess.run([sys.executable, '-I', qo, smp], capture_output=True); assert r0.returncode == 0, r0.stderr[-400:]; open(os.path.join(c, 'work', 'runs', 'tool', 'oldh.out'), 'wb').write(r0.stdout); r, t = sealed('oldh'); assert r.returncode == 0, t
    # known_answers() ném lỗi hoặc trả phần tử sai dạng: nêu đúng lý do KAT, không phải 'không có file trạng thái'
    mk('kerr', BODY.replace("    import struct, zlib      # đáp án", "    raise ValueError('hỏng')\n    import struct, zlib      # đáp án", 1)); r, t = sealed('kerr'); assert r.returncode == 1 and 'known_answers() lỗi (ValueError' in t and 'KAT 0/1' in t, t
    mk('kbad', BODY.replace("return [('thông điệp ngắn'", "return [('chỉ-tên',), ('thông điệp ngắn'", 1)); r, t = sealed('kbad'); assert r.returncode == 1 and 'sai đáp án biết trước: chỉ-tên' in t, t
    # file rỗng: nói đúng lý do
    e0 = os.path.join(c, 'work', 'sample', 'empty.dat'); open(e0, 'wb').close(); q = os.path.join(c, 'work', 'tools', 'b9.py'); time.sleep(0.02)
    r0 = subprocess.run([sys.executable, '-I', q, e0], capture_output=True); open(os.path.join(c, 'work', 'runs', 'tool', 'b9.out'), 'wb').write(r0.stdout)
    r = flow('seal', 'b9'); assert 'không thử đột biến được' in r.stdout or r0.returncode != 0, r.stdout
    ok = mk('b6', BODY + '\nimport platform, urllib.parse\nplatform.system(); urllib.parse.quote("x")\n')[1]; r, t = sealed('b6'); assert r.returncode == 0 and 'NOTE ' not in t, r.stdout
    # (d) trạng thái của khuôn trước 1.9.0 (có inputs, không có mutation): nói rõ cách chuyển
    sj = os.path.join(c, 'work', 'runs', 'tool', 'b6.status.json'); st0 = json.load(open(sj)); json.dump({k: v for k, v in st0.items() if k not in ('mutation', 'kat')}, open(sj, 'w'))
    r = flow('seal', 'b6'); assert r.returncode == 1 and 'khuôn cũ' in r.stdout, r.stdout

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
