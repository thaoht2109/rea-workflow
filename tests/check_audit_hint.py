#!/usr/bin/env python3
# audit: mục Evidence của README chỉ nhận bảng Markdown; danh sách văn xuôi báo thẳng định dạng cần dùng (thay vì chỉ "README thiếu").
#   python3 tests/check_audit_hint.py
import os, shutil, sys, tempfile
T = os.path.dirname(os.path.dirname(os.path.abspath(__file__))); sys.path.insert(0, T)
import case

c = tempfile.mkdtemp(prefix='rea-audit-')
try:
    os.makedirs(os.path.join(c, 'report', 'evidence')); os.makedirs(os.path.join(c, 'work')); open(os.path.join(c, 'facts.jsonl'), 'w').close()
    open(os.path.join(c, 'report', 'evidence', 'a.txt'), 'w').write('x\n'); rd = os.path.join(c, 'report', 'README.md')
    open(rd, 'w', encoding='utf-8').write('# B\n\n## 9. Evidence\n\nTệp: `a.txt`.\n')
    P = case.audit(c); assert any('bảng Markdown' in p for p in P) and any('README thiếu: a.txt' in p for p in P), P
    open(rd, 'w', encoding='utf-8').write('# B\n\n## 9. Evidence\n\n| File | Nội dung |\n|---|---|\n| `a.txt` | thử |\n'); assert case.audit(c) == [], case.audit(c)
    open(rd, 'w', encoding='utf-8').write('# B\n\n## 9. Evidence\n\n| File | Nội dung |\n|---|---|\n| `b.txt` | thử |\n'); P = case.audit(c)
    assert not any('bảng Markdown' in p for p in P) and any('README thiếu: a.txt' in p for p in P), P      # bảng có nhưng thiếu file: không nhắc nhầm định dạng
finally: shutil.rmtree(c, ignore_errors=True)
print('OK check_audit_hint')
