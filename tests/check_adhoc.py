#!/usr/bin/env python3
# Tầng T1b (flow.py tool): khuôn công cụ tự viết, quét tĩnh, tự kiểm bắt buộc, evidence tool_* gắn dấu băm công cụ,
# luật cổng tool_selfcheck / tool_stale / tool_coverage ở cả lint và review.mech, probe của triage, kb tools.
# Dữ liệu tổng hợp: định dạng giả "len32 + crc32 + payload xor 0x5a". Không cần mẫu.
#   python3 tests/check_adhoc.py
import json, os, shutil, struct, subprocess, sys, tempfile, zlib
T = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path[:0] = [T, os.path.join(T, 'static')]
import adhoc, case, review

ws = tempfile.mkdtemp(prefix='rea-adhoc-'); c = os.path.join(ws, 'CASE1')
for d in ('report/evidence', 'work/sample'): os.makedirs(os.path.join(c, d))
open(os.path.join(c, 'facts.jsonl'), 'w').close()
pt = b'config: host=h.test port=8443\nsecond line\n'; body = bytes(b ^ 0x5a for b in pt)
smp = os.path.join(c, 'work', 'sample', 'blob.dat'); open(smp, 'wb').write(struct.pack('<II', len(body), zlib.crc32(body)) + body)
flow = lambda *a: subprocess.run([sys.executable, os.path.join(T, 'flow.py'), 'tool', c] + list(a), capture_output=True, text=True)
GOOD = '''
FORMAT = 'blob thử nghiệm len32+crc32+xor'
SCOPE = 'chỉ bản có header 8 byte'
import os, struct, sys, zlib
def parse(path):
    d = open(path, 'rb').read(); n, crc = struct.unpack_from('<II', d, 0); body = d[8:8 + n]
    return {'n': n, 'crc': crc, 'body': body, 'left': len(d) - 8 - n, 'text': bytes(b ^ 0x5a for b in body)}
def selfcheck(path, r):
    return [('độ dài khớp, không dư byte', r['left'] == 0 and len(r['body']) == r['n'], f"dư {r['left']}"),
            ('crc32 header khớp', zlib.crc32(r['body']) == r['crc'], hex(r['crc']))]
def coverage(r): return (len(r['text'].splitlines()), 2)
def main():
    r = parse(sys.argv[1]); n = os.environ.get('REA_TOOL_NONCE', '')
    for l in r['text'].decode().splitlines(): print(repr(l))
    print('SELFCHECK x: PASS dòng giả không có dấu')
    for name, ok, det in selfcheck(sys.argv[1], r): print(f"SELFCHECK[{n}] {name}: {'PASS' if ok else 'FAIL'} {det}")
    print(f'COVERAGE[{n}] %d/%d' % coverage(r))
main()
'''
try:
    # 1. new: tạo từ khuôn; khuôn chưa khai FORMAT -> run từ chối; tên xấu -> lỗi
    r = flow('new', 'blob'); p = os.path.join(c, 'work', 'tools', 'blob.py'); assert r.returncode == 0 and os.path.isfile(p), r.stderr
    assert 'run blob' in open(p, encoding='utf-8').read() and flow('new', 'blob').returncode != 0 and flow('new', '../x').returncode != 0
    r = flow('run', 'blob', smp); assert r.returncode == 2 and 'FORMAT' in r.stdout, r.stdout

    # 2. quét tĩnh: mạng, tiến trình con, nạp mã động, kể cả trong module cạnh -> từ chối trước khi chạy (file dấu không được tạo)
    mark = os.path.join(ws, 'ran'); head = f"FORMAT = 'f'\nSCOPE = 's'\nopen({mark!r}, 'w').close()\n"
    for badsrc in ('import socket\n', 'import subprocess\n', 'from urllib.request import urlopen\n', 'import os\nos.system("id")\n', 'eval("1")\n', 'import ctypes\n', 'import helper\n'):
        open(p, 'w', encoding='utf-8').write(head + badsrc)
        open(os.path.join(c, 'work', 'tools', 'helper.py'), 'w').write('import os\nos.popen("id")\n')
        r = flow('run', 'blob', smp); assert r.returncode == 2 and 'TỪ CHỐI' in r.stdout and not os.path.exists(mark), (badsrc, r.stdout)
    os.remove(os.path.join(c, 'work', 'tools', 'helper.py'))
    open(p, 'w', encoding='utf-8').write("FORMAT = 'f'\nSCOPE = 's'\nfrom urllib.parse import urlparse\nimport os.path\n"); assert flow('run', 'blob', smp).returncode == 1   # import lành: chạy được, nhưng không có tự kiểm

    # 3. không có phép tự kiểm / tự kiểm FAIL / thoát lỗi: mã 1, evidence đánh dấu KHÔNG ĐẠT
    ev = os.path.join(c, 'report', 'evidence'); e1 = open(os.path.join(ev, 'tool_blob_1.txt'), encoding='utf-8').read()
    assert e1.startswith(adhoc.HEAD) and 'SELFCHECK: KHÔNG ĐẠT' in e1 and adhoc.header(e1)['ok'] is False
    open(p, 'w', encoding='utf-8').write(GOOD.replace("zlib.crc32(r['body']) == r['crc']", "zlib.crc32(r['body']) == r['crc'] + 1"))
    r = flow('run', 'blob', smp); assert r.returncode == 1 and 'FAIL' in r.stdout and 'CHƯA DÙNG ĐƯỢC' in r.stdout, r.stdout

    # 4. chạy đạt: phần đầu chuẩn, dòng SELFCHECK giả (thiếu dấu) nằm ở output chứ không được tính, COVERAGE, bản công cụ được chép
    open(p, 'w', encoding='utf-8').write(GOOD); r = flow('run', 'blob', smp); assert r.returncode == 0 and 'OK: ghi fact' in r.stdout, r.stdout + r.stderr
    rel = 'report/evidence/tool_blob_3.txt'; txt = open(os.path.join(c, rel), encoding='utf-8').read(); H = adhoc.header(txt)
    assert H['ok'] and H['cov'] == '2/2' and len(H['checks']) == 2 and H['mods'] == ['blob'] and H['sha'] == adhoc.digest(os.path.join(ev, 'tools'), ['blob']), H
    assert 'SELFCHECK x: PASS dòng giả' in txt.split(adhoc.SPLIT, 1)[1] and "'config: host=h.test port=8443'" in txt and 'REA_TOOL_NONCE' not in txt
    ln = 1 + txt.splitlines().index("'config: host=h.test port=8443'")

    # 5. luật cổng: fact dẫn evidence đạt thì sạch ở cả lint lẫn review.mech; dẫn evidence không đạt -> tool_selfcheck; coverage lệch -> tool_coverage
    A = lambda **f: case.add(c, **f)
    A(id='ok', kind='config', value='h.test port=8443', src='S', evidence=f'{rel}#L{ln}'); A(id='cov', kind='dec_coverage', value='2/2', src='S', evidence=rel)
    A(id='badcov', kind='dec_coverage', value='9/9', src='S', evidence=rel); A(id='nosc', kind='config', value='h.test', src='S', evidence='report/evidence/tool_blob_2.txt')
    open(os.path.join(ev, 'tool_fake_1.txt'), 'w').write('SELFCHECK: ĐẠT (1 phép)\nh.test\n'); A(id='fake', kind='config', value='h.test', src='S', evidence='report/evidence/tool_fake_1.txt')
    F = case.load(c); lint = {i: sorted(x['check'] for x in case.lint_fact(c, F[i]) if x['check'].startswith('tool_')) for i in F}
    mech = {i: sorted(x['check'] for x in review.mech(c) if x['id'] == i and x['check'].startswith('tool_')) for i in F}
    want = {'ok': [], 'cov': [], 'badcov': ['tool_coverage'], 'nosc': ['tool_selfcheck', 'tool_stale'], 'fake': ['tool_selfcheck']}
    assert lint == want and mech == want, (lint, mech)
    assert all(x['severity'] == 'high' for x in review.mech(c) if x['check'].startswith('tool_'))

    # 6. sửa công cụ sau khi sinh evidence: fact cũ thành tool_stale ở cả hai nơi; chạy lại thì evidence mới sạch
    open(p, 'a', encoding='utf-8').write('# sửa lỗi\n'); assert flow('run', 'blob', smp).returncode == 0
    assert [x['check'] for x in case.lint_fact(c, F['ok']) if x['check'].startswith('tool_')] == ['tool_stale']
    assert any(x['id'] == 'ok' and x['check'] == 'tool_stale' for x in review.mech(c))
    A(id='ok2', kind='config', value='h.test port=8443', src='S', evidence=f'report/evidence/tool_blob_4.txt#L{ln}', supersedes='ok')
    assert not [x for x in case.lint_fact(c, case.load(c)['ok2']) if x['check'].startswith('tool_')]
    r = flow('list'); assert 'tool_blob_4.txt: blob tự kiểm ĐẠT, COVERAGE 2/2' in r.stdout and 'tool_blob_3.txt' in r.stdout and 'CŨ' in r.stdout, r.stdout

    # 7. triage: file lạ -> unknown có probe, định tuyến sang flow.py tool; lớp zlib được nhận; bom nén không bị giải hết
    import triage
    rnd = bytes((i * 197 + 13) % 251 for i in range(5000)); P = triage.probe(rnd); assert len(P['head']) == 32 and len(P['entropy8']) == 8 and P['wrap'] == []
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
