#!/usr/bin/env python3
# Symlink trong work/sample (mẫu dạng thư mục) không được theo đích ở các bộ đọc: link treo không làm crash, link hợp lệ không kéo
# file của máy phân tích vào danh sách mẫu/hash. Chạy: python3 tests/check_symlink_readers.py
import os, sys, hashlib, tempfile
T = os.path.dirname(os.path.dirname(os.path.abspath(__file__))); sys.path.insert(0, T)
import case as C, export, kb, reviewer
c = tempfile.mkdtemp(prefix='rea-symlink-'); sd = os.path.join(c, 'work', 'sample', 'app'); os.makedirs(sd)
open(os.path.join(sd, 'real.sh'), 'w').write('echo real\n')
host = os.path.join(c, 'host_secret.txt'); open(host, 'w').write('file của máy phân tích\n')   # nằm ngoài work/sample
os.symlink(host, os.path.join(sd, 'good_link')); os.symlink(os.path.join(c, 'khong_co'), os.path.join(sd, 'dangling_link'))
hs = hashlib.sha256(open(host, 'rb').read()).hexdigest()
export.collect(c)   # không crash với link treo
assert hs not in C._work_hashes(c) and hashlib.sha256(b'echo real\n').hexdigest() in C._work_hashes(c)
fl, _ = reviewer.files(c); assert [os.path.basename(p) for p in fl] == ['real.sh'], fl
assert [os.path.basename(p) for p in kb.files_of(c)] == ['real.sh'], kb.files_of(c)
# thư mục symlink trỏ ra ngoài: glob '**' đi vào đó, os.walk thì không; file bên trong không phải link nhưng vẫn không được tính
ext = tempfile.mkdtemp(prefix='rea-ext-'); open(os.path.join(ext, 'passwd'), 'w').write('root:x:0:0\n')
os.symlink(ext, os.path.join(sd, 'lib'))
import review
eh = hashlib.sha256(b'root:x:0:0\n').hexdigest()
assert eh not in C._work_hashes(c) and eh not in review.work_hashes(c)
assert [os.path.basename(p) for p in reviewer.files(c)[0]] == ['real.sh'] and [os.path.basename(p) for p in kb.files_of(c)] == ['real.sh']
os.makedirs(os.path.join(c, 'work', 'extract')); open(os.path.join(c, 'work', 'extract', 'a.bin'), 'w').write('x')
assert [os.path.basename(p) for p in C.work_files(c)] == ['real.sh', 'a.bin']   # sample trước extract
# review.analyst: mẫu dạng thư mục không làm crash, file lồng được kiểm toàn vẹn, link không vào
sh = review.sample_hashes(c); assert [os.path.basename(p) for p in sh] == ['real.sh'] and all(os.path.isfile(p) for p in sh), sh
# reviewer: chép sang workspace bỏ link (hợp lệ, thư mục, treo) và không lỗi
ws = os.path.join(tempfile.mkdtemp(prefix='rea-ws-'), 'sample'); reviewer.copy_nolinks(os.path.join(c, 'work', 'sample'), ws)
got = sorted(os.path.relpath(os.path.join(r, n), ws) for r, _, ns in os.walk(ws) for n in ns); assert got == ['app/real.sh'], got
assert not os.path.lexists(os.path.join(ws, 'app', 'lib')) and not os.path.lexists(os.path.join(ws, 'app', 'good_link'))
# evidence là symlink: lint và lớp 1 của cổng đều báo fail (phiên phản biện không thấy link), không im lặng
os.makedirs(os.path.join(c, 'report', 'evidence')); real = os.path.join(c, 'report', 'evidence', 'real.txt'); open(real, 'w').write('abc\n')
os.symlink(real, os.path.join(c, 'report', 'evidence', 'lnk.txt'))
f = dict(id='s.x', kind='note', value='abc', src='S', evidence='report/evidence/lnk.txt', status='active', verified_by=['S'], supersedes=None, stage='', note='')
assert any(i['check'] == 'evidence_exists' and 'symlink' in i['problem'] for i in C.lint_fact(c, f)), C.lint_fact(c, f)
f['evidence'] = 'report/evidence/real.txt'; assert not any('symlink' in i['problem'] for i in C.lint_fact(c, f))
# thư mục cha là symlink: vẫn fail (lint và lớp 1)
real_d = os.path.join(c, 'realdir'); os.makedirs(real_d); open(os.path.join(real_d, 'a.txt'), 'w').write('abc\n'); os.symlink(real_d, os.path.join(c, 'report', 'evidence', 'sub'))
f['evidence'] = 'report/evidence/sub/a.txt'; assert any('symlink' in i['problem'] for i in C.lint_fact(c, f)), C.lint_fact(c, f)
# lớp 1 của cổng (review.mech) trên case có fact trỏ evidence là link / nằm trong thư mục link / bình thường
import json
for ev, bad_expected in (('report/evidence/lnk.txt', True), ('report/evidence/sub/a.txt', True), ('report/evidence/real.txt', False)):
    open(os.path.join(c, 'facts.jsonl'), 'w').write(json.dumps(dict(f, id='s.t', evidence=ev)) + '\n')
    items = review.mech(c); items = items[0] if isinstance(items, tuple) else items
    hit = any(i['id'] == 's.t' and i['check'] == 'evidence_exists' and 'symlink' in i['problem'] for i in items)
    assert hit == bad_expected, (ev, hit, items)
# copy_nolinks in cảnh báo khi bỏ link
import io, contextlib
err = io.StringIO()
with contextlib.redirect_stderr(err): reviewer.copy_nolinks(os.path.join(c, 'work', 'sample'), os.path.join(tempfile.mkdtemp(prefix='rea-ws2-'), 's'))
assert 'CẢNH BÁO' in err.getvalue() and 'symlink' in err.getvalue(), err.getvalue()
print('OK check_symlink_readers')
