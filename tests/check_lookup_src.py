#!/usr/bin/env python3
# Evidence lookup_* (tra cứu thụ động) chỉ đi với src=S; các luật nguồn/evidence cũ giữ nguyên. Chạy: python3 tests/check_lookup_src.py
import os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__)))); import case   # noqa: E402
f = case.src_evidence_issue
assert f('S', 'lookup_rdap.txt') is None
for s in ('E', 'V'): assert f(s, 'lookup_rdap.txt') and 'lookup_' in f(s, 'lookup_rdap.txt')[0], s
assert f('S', 'emu_x.txt') and f('V', 'tri.txt') and f('E', 'emu_x.txt') is None and f('V', 'host_a.txt') is None and f('S', 'tri.txt') is None
print('OK check_lookup_src')
# lookup_* chứa thân lớn/nhị phân/mã chạy được bị lint fail; văn bản ngắn (địa chỉ C2 một dòng) thì qua
import tempfile
c = tempfile.mkdtemp(); E = os.path.join(c, 'report', 'evidence'); os.makedirs(E); os.makedirs(os.path.join(c, 'work', 'sample'))
body = {'ok': b'http://c2.example.net/v2\n', 'big': b'a' * (case.LOOKUP_MAX + 1), 'nul': b'abc\0def http://c2.example.net', 'mz': b'MZ' + b'http://c2.example.net', 'sh': b'#!/bin/sh\necho http://c2.example.net\n',
        'elf': b'\x7fELF http://c2.example.net', 'ctl': bytes([1, 2, 3, 4]) * 20 + b' http://c2.example.net'}
for k, b in body.items():
    open(os.path.join(E, f'lookup_{k}.txt'), 'wb').write(b)
    case.add(c, id=f'l.{k}', kind='url', value='http://c2.example.net', src='S', evidence=f'report/evidence/lookup_{k}.txt')
F = case.load(c)
chk = lambda k: [x['check'] for x in case.lint_fact(c, F[f'l.{k}'])]
assert 'lookup_content' not in chk('ok'), chk('ok')
for k in body:
    if k != 'ok': assert 'lookup_content' in chk(k), (k, chk(k))
print('OK check_lookup_src (thân lookup_*)')
import review   # cổng phản biện (lớp máy) cũng chặn
from review import mech  # noqa: E402,F401
it = {(i['id'], i['check']) for i in review.mech(c) if i['verdict'] == 'fail'}
assert ('l.big', 'lookup_content') in it and ('l.elf', 'lookup_content') in it and ('l.ok', 'lookup_content') not in it, it
print('OK check_lookup_src (cổng)')
