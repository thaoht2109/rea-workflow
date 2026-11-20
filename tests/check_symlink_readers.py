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
print('OK check_symlink_readers')
