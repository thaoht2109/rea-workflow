#!/usr/bin/env python3
"""facts.jsonl có dòng cuối bị cụt (tiến trình bị giết lúc ghi): đọc bỏ qua dòng cụt, fact mới không dính vào mảnh cụt, file vẫn chỉ
nối thêm (cổng phản biện kiểm tiền tố); dòng hỏng kiểu khác thì báo lỗi rõ. Chạy: python3 tests/check_facts_cut.py"""
import os, sys, json, shutil, tempfile, subprocess
SKILL = os.path.dirname(os.path.dirname(os.path.abspath(__file__))); sys.path.insert(0, SKILL)
import case as C  # noqa: E402
from evals.run import mk_case  # noqa: E402

T = tempfile.mkdtemp(prefix='rea-cut-')
try:
    c = mk_case(T, 'K', [('s.u1', 'url', 'http://a.invalid/x'), ('s.u2', 'url', 'http://b.invalid/y')])
    p = os.path.join(c, 'facts.jsonl'); good = open(p, 'rb').read()
    open(p, 'ab').write(b'{"id": "s.u3", "kind": "url", "val')   # bị giết giữa lúc ghi
    before = open(p, 'rb').read()
    r = subprocess.run([sys.executable, '-c', f'import sys; sys.path.insert(0, {SKILL!r}); import case; print(sorted(case.load({c!r})))'], capture_output=True, text=True)
    assert r.returncode == 0 and "['s.u1', 's.u2']" in r.stdout and 'bị cụt' in r.stderr, r.stdout + r.stderr
    C.add(c, id='s.u4', kind='url', value='http://b.invalid/y', src='S', evidence='report/evidence/strings.txt#L2')
    after = open(p, 'rb').read()
    assert after.startswith(before) and after[len(before):len(before) + 1] == b'\n', after[len(good):]   # chỉ nối thêm, xuống dòng trước
    assert sorted(C.load(c)) == ['s.u1', 's.u2', 's.u4'] and [f['id'] for f in C.history(c)] == ['s.u1', 's.u2', 's.u4']
    open(p, 'a').write('dòng sửa tay\n')   # dòng hỏng không phải do cụt: báo lỗi, không im lặng bỏ
    try: C.history(c); raise AssertionError('phải báo lỗi')
    except ValueError as x: assert 'facts.jsonl:5' in str(x) and 'sửa tay' in str(x) and 'dòng cụt' not in str(x), x
    c2 = mk_case(T, 'K2', [('s.u1', 'url', 'http://a.invalid/x')]); p2 = os.path.join(c2, 'facts.jsonl')
    open(p2, 'ab').write(b'{"id": "s.u9", "kind": "url", "value": "a}')   # cụt đúng sau một } trong chuỗi: không đoán, báo lỗi kèm gợi ý xử lý
    try: C.history(c2); raise AssertionError('phải báo lỗi')
    except ValueError as x: assert 'facts.jsonl:2' in str(x) and 'dòng cụt' in str(x), x
    json.loads(open(p).read().splitlines()[0])
finally: shutil.rmtree(T, ignore_errors=True)
print('OK check_facts_cut')
