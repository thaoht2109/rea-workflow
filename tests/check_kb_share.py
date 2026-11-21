#!/usr/bin/env python3
# kb publish / kb update: chỉ case được chọn (share.txt hoặc --cases) và qua cổng phản biện; bản phát hành không có đường dẫn máy, tên case, đính chính;
# update kiểm sha256 theo manifest, chỉ nhận https/file/đường dẫn, nhập dưới nhãn upstream. Dữ liệu tổng hợp, cổng review giả.
#   python3 tests/check_kb_share.py
import os, sys, json, gzip, shutil, hashlib, tempfile
T = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ws = tempfile.mkdtemp(prefix='rea-kbs-'); other = tempfile.mkdtemp(prefix='rea-kbs2-')
os.environ.update(REA_KB=os.path.join(ws, 'kbstore'), REA_WORKSPACE=ws)
sys.path[:0] = [T, os.path.join(T, 'static')]
import kb, review   # noqa: E402

def mk(name, sample, facts):
    c = os.path.join(ws, name); os.makedirs(os.path.join(c, 'work', 'sample')); os.makedirs(os.path.join(c, 'report', 'evidence'))
    open(os.path.join(c, 'work', 'sample', 'drop.bin'), 'wb').write(sample)
    with open(os.path.join(c, 'facts.jsonl'), 'w') as f:
        for x in facts: f.write(json.dumps(dict(dict(src='S', evidence='report/evidence/e.txt', status='active', supersedes=None, ts='2026-01-01T00:00:00'), **x)) + '\n')
    return c

def die(f):
    try: f(); return None
    except SystemExit as e: return str(e)

try:
    sa = b'loader-A\x00' * 80; sb = b'loader-B\x00' * 80; sc = b'loader-C\x00' * 80
    mk('KHACH_HANG_ACME_vu1', sa, [dict(id='a.c2', kind='c2', value='evil-a.example.net:443'), dict(id='a.fam', kind='family', value='HỌ-BÍ-MẬT')])
    mk('CASE_B', sb, [dict(id='b.c2', kind='c2', value='evil-b.example.net:443')])
    mk('CASE_C', sc, [dict(id='c.c2', kind='c2', value='evil-c.example.net:443')])
    kb.build(ws, quiet=True); d = kb.kb_dir()
    out = os.path.join(other, 'rel')
    # mặc định không công khai case nào
    assert 'chưa chọn case nào' in (die(lambda: kb.publish(out)) or '')
    # trong thư mục skill: từ chối
    assert 'thư mục skill' in (die(lambda: kb.publish(os.path.join(T, 'x'), cases=['CASE_B'])) or '')
    # cổng phản biện chưa PASS: bỏ case, không có gì để phát hành
    real = review.gate
    review.gate = lambda c: (False, 'chưa có review PASS')
    m = die(lambda: kb.publish(out, cases=['CASE_B'])); assert m and 'không có case nào đủ điều kiện' in m and 'chưa có review PASS' in m, m
    # cổng PASS chỉ cho CASE_B; CASE_C được chọn nhưng không qua; tên không có trong kho được báo
    review.gate = lambda c: (os.path.basename(c) == 'CASE_B', 'chưa có review PASS')
    open(os.path.join(d, 'share.txt'), 'w').write('# được phép\nCASE_B\nCASE_C\nKHONG_CO\n')
    kb.publish(out, name='nguon-test')
    review.gate = real
    man = json.load(open(os.path.join(out, 'manifest.json')))
    blob = open(os.path.join(out, man['file']), 'rb').read()
    assert man['kind'] == 'rea-kb-manifest' and man['sha256'] == hashlib.sha256(blob).hexdigest() and man['size'] == len(blob) and man['files'] == 1 and man['cases'] == 1, man
    rows = [json.loads(l) for l in gzip.open(os.path.join(out, man['file']), 'rt', encoding='utf-8')]
    txt = json.dumps(rows)
    for bad in ('CASE_B', 'CASE_C', 'KHACH_HANG', 'ACME', ws, 'mtime_ns', 'drop.bin', 'work/sample'): assert bad not in txt, bad   # không đường dẫn, tên case, tên file
    assert 'evil-b.example.net:443' in txt and 'evil-c' not in txt and 'HỌ-BÍ-MẬT' not in txt
    assert all(r.get('t') in ('s', 'c') for r in rows[1:]) and not any(r['t'] == 'c' for r in rows[1:])   # không có đính chính
    # update: nhập vào kho khác dưới nhãn upstream; kiểm sha256
    os.environ['REA_KB'] = os.path.join(other, 'kb2'); import reacfg; reacfg.KB = os.environ['REA_KB']; kb.CFG.KB = reacfg.KB
    mp = os.path.join(out, 'manifest.json')
    assert kb.update(mp) == 0
    S2 = kb.read_jsonl(os.path.join(kb.kb_dir(), 'samples.jsonl'))
    assert S2 and all(r.get('peer') == 'nguon-test' for r in S2) and {r.get('imphash', '') for r in S2} is not None, S2
    # sha256 sai: không nhập
    bad = dict(man, sha256='0' * 64); os.makedirs(os.path.join(other, 'bad')); shutil.copy(os.path.join(out, man['file']), os.path.join(other, 'bad', man['file']))
    json.dump(bad, open(os.path.join(other, 'bad', 'manifest.json'), 'w'))
    assert 'không khớp manifest' in (die(lambda: kb.update(os.path.join(other, 'bad', 'manifest.json'))) or '')
    # tên file trong manifest không được chứa đường dẫn; http thường bị từ chối; thiếu nguồn báo rõ
    evil = dict(man, file='../x'); json.dump(evil, open(os.path.join(other, 'bad', 'manifest.json'), 'w'))
    assert 'manifest không đúng dạng' in (die(lambda: kb.update(os.path.join(other, 'bad', 'manifest.json'))) or '')
    assert 'chỉ nhận https' in (die(lambda: kb.update('http://example.invalid/manifest.json')) or '')
    os.environ.pop('REA_KB_UPSTREAM', None)
    assert 'chưa có nguồn' in (die(lambda: kb.update()) or '')
finally:
    shutil.rmtree(ws, ignore_errors=True); shutil.rmtree(other, ignore_errors=True)
print('OK check_kb_share')
