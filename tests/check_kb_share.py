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
    out = os.path.join(other, 'rel'); pub = os.path.join(other, 'pub'); os.environ['REA_KB_PUBLIC'] = pub; os.environ['REA_KB_PUBLIC'] = pub
    # kho công khai trống: không phát hành gì
    assert 'trống' in (die(lambda: kb.publish(out)) or '')
    # kho công khai trong thư mục skill hoặc lồng kho cá nhân: từ chối
    os.environ['REA_KB_PUBLIC'] = os.path.join(T, 'pubx'); assert 'thư mục skill' in (die(lambda: kb.pub_dir()) or '')
    os.environ['REA_KB_PUBLIC'] = os.path.join(d, 'sub'); assert 'không được trùng hoặc lồng' in (die(lambda: kb.pub_dir()) or '')
    os.environ['REA_KB_PUBLIC'] = pub
    # cổng phản biện chưa PASS: không vào kho công khai
    real = review.gate
    review.gate = lambda c: (False, 'chưa có review PASS')
    assert kb.share_add(['CASE_B']) == 1 and not kb._pub_cases(pub)
    # chỉ CASE_B qua cổng; CASE_C không qua; tên không có trong kho bị bỏ
    review.gate = lambda c: (os.path.basename(c) == 'CASE_B', 'chưa có review PASS')
    assert kb.share_add(['CASE_B', 'CASE_C', 'KHONG_CO']) == 0 and len(kb._pub_cases(pub)) == 1
    review.gate = real
    # kho cá nhân không bị đổi; kho công khai không có kho cá nhân trong đó
    assert os.path.isfile(os.path.join(d, 'samples.jsonl')) and not os.path.exists(os.path.join(d, 'cases'))
    assert kb.share_list() == 0
    kb.publish(out, name='nguon-test')
    man = json.load(open(os.path.join(out, 'manifest.json')))
    blob = open(os.path.join(out, man['file']), 'rb').read()
    assert man['kind'] == 'rea-kb-manifest' and man['sha256'] == hashlib.sha256(blob).hexdigest() and man['size'] == len(blob) and man['files'] == 1 and man['cases'] == 1, man
    rows = [json.loads(l) for l in gzip.open(os.path.join(out, man['file']), 'rt', encoding='utf-8')]
    txt = json.dumps(rows)
    for bad in ('CASE_B', 'CASE_C', 'KHACH_HANG', 'ACME', ws, 'mtime_ns', 'drop.bin', 'work/sample'): assert bad not in txt, bad   # không đường dẫn, tên case, tên file
    assert 'evil-b.example.net:443' in txt and 'evil-c' not in txt and 'HỌ-BÍ-MẬT' not in txt
    assert all(r.get('t') in ('s', 'c') for r in rows[1:]) and not any(r['t'] == 'c' for r in rows[1:])   # không có đính chính
    # gỡ khỏi kho công khai theo tên case hoặc theo mã
    cid = kb._pub_cases(pub)[0][:-6]
    assert kb.share_rm(['CASE_B']) == 0 and not kb._pub_cases(pub) and kb.share_rm([cid]) == 1
    os.environ['REA_KB_PUBLIC'] = pub
    review.gate = lambda c: (True, '')
    assert kb.share_add(['CASE_B']) == 0; assert len(kb._pub_cases(pub)) == 1; c0 = kb._pub_cases(pub)
    # mã công khai ổn định: case có thêm file (đứng trước work/sample theo thứ tự chữ cái) vẫn ra cùng mã, share add thay bản cũ, share rm theo tên gỡ được
    os.makedirs(os.path.join(ws, 'CASE_B', 'work', 'aaa')); xp = os.path.join(ws, 'CASE_B', 'work', 'aaa', 'x.bin'); open(xp, 'wb').write(b'extra-payload\x00' * 90)
    os.makedirs(os.path.join(ws, 'CASE_B', 'work', 'runs', 'triage_1')); json.dump({'path': xp}, open(os.path.join(ws, 'CASE_B', 'work', 'runs', 'triage_1', 'triage.json'), 'w'))
    kb.build(ws, quiet=True); assert kb.share_add(['CASE_B']) == 0 and kb._pub_cases(pub) == c0, (kb._pub_cases(pub), c0)
    assert sum(r.get('kind') != 'case' for r in kb.read_jsonl(os.path.join(pub, 'cases', c0[0]))) == 2
    m = json.load(open(os.path.join(kb.kb_dir(), 'share_ids.json'))); assert c0[0][:-6] in m.values() and not any(c0[0][1:-6] in hashlib.sha256(x.encode()).hexdigest() for x in m)
    assert kb.share_rm(['CASE_B']) == 0 and not kb._pub_cases(pub); assert kb.share_add(['CASE_B']) == 0 and kb._pub_cases(pub) == c0
    # share rm theo tên khi case đã biến mất khỏi workspace và kho cá nhân (mã vẫn nằm trong share_ids.json)
    shutil.rmtree(os.path.join(ws, 'CASE_B')); kb.build(ws, quiet=True)
    assert not any(r['case'] == 'CASE_B' for r in kb.read_jsonl(os.path.join(kb.kb_dir(), 'samples.jsonl')))
    assert kb.share_rm(['CASE_B']) == 0 and not kb._pub_cases(pub)
    # share_ids.json hỏng: dừng, không ghi đè
    fi = os.path.join(kb.kb_dir(), 'share_ids.json'); good = open(fi).read(); open(fi, 'w').write('{hong')
    assert 'hỏng' in (die(lambda: kb.cid_of(kb.kb_dir(), ws, 'CASE_C')) or '') and open(fi).read() == '{hong'
    open(fi, 'w').write(good)
    review.gate = real
    # update: nhập vào kho khác dưới nhãn upstream; kiểm sha256
    os.environ['REA_KB'] = os.path.join(other, 'kb2'); import reacfg; reacfg.KB = os.environ['REA_KB']; kb.CFG.KB = reacfg.KB
    mp = os.path.join(out, 'manifest.json')
    assert kb.update(mp) == 0
    S2 = kb.read_jsonl(os.path.join(kb.kb_dir(), 'samples.jsonl'))
    assert S2 and all(r.get('peer') == 'upstream' for r in S2), S2
    # sha256 sai: không nhập
    bad = dict(man, sha256='0' * 64); os.makedirs(os.path.join(other, 'bad')); shutil.copy(os.path.join(out, man['file']), os.path.join(other, 'bad', man['file']))
    json.dump(bad, open(os.path.join(other, 'bad', 'manifest.json'), 'w'))
    assert 'không khớp manifest' in (die(lambda: kb.update(os.path.join(other, 'bad', 'manifest.json'))) or '')
    # tên file trong manifest không được chứa đường dẫn; http thường bị từ chối; thiếu nguồn báo rõ
    evil = dict(man, file='../x'); json.dump(evil, open(os.path.join(other, 'bad', 'manifest.json'), 'w'))
    assert 'manifest không đúng dạng' in (die(lambda: kb.update(os.path.join(other, 'bad', 'manifest.json'))) or '')
    assert 'chỉ nhận https' in (die(lambda: kb.update('http://example.invalid/manifest.json')) or '')
    kb.CFG.KB_UPSTREAM = 'off'
    assert 'chưa có nguồn' in (die(lambda: kb.update()) or '')
    # setup: kho chưa có -> kb_ready False; kb_install tạo kho và kéo từ nguồn mặc định; nguồn hỏng/off không làm lỗi
    import install_tools as it
    kb.CFG.KB = os.path.join(other, 'kb3'); assert not it.kb_ready()
    kb.CFG.KB_UPSTREAM = os.path.join(other, 'khong-co', 'manifest.json'); it.kb_install()   # nguồn hỏng: chỉ cảnh báo
    assert not it.kb_ready() and os.path.isdir(kb.CFG.KB)
    kb.CFG.KB_UPSTREAM = mp; it.kb_install(); assert it.kb_ready()
    assert any(r.get('peer') == 'upstream' for r in kb.read_jsonl(os.path.join(kb.CFG.KB, 'samples.jsonl')))
    kb.CFG.KB = 'off'; assert it.kb_ready()   # tắt kho: không cần kéo
finally:
    shutil.rmtree(ws, ignore_errors=True); shutil.rmtree(other, ignore_errors=True)
print('OK check_kb_share')
