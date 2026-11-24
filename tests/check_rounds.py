#!/usr/bin/env python3
"""Test bộ đếm vòng của cổng phản biện: giới hạn 2 lượt tính từ lần PASS có lớp 2 gần nhất, không tính theo tổng số vòng của case.
Chạy: python3 tests/check_rounds.py  (reviewer giả, không gọi LLM)
"""
import os, sys, tempfile, shutil, io, contextlib

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.normpath(os.path.join(HERE, '..')))
import case as C, review as R, reviewer

NEXT = {'fail': [], 'valid': True}   # kịch bản cho lượt lớp 2 kế tiếp
def stub(c, k, ids, items):
    li = [dict(id=i, verdict='fail', severity='high', check='value_vs_evidence', problem='sai', where='report/evidence/s.txt#L1', redo='đọc lại', layer='llm') for i in NEXT['fail']]
    return li, [], dict(valid=NEXT['valid'], backend='stub', turns=1, requests=0, invalid_reasons=[] if NEXT['valid'] else ['thử'])
reviewer.run = stub

def mkcase():
    c = tempfile.mkdtemp(prefix='rea-rounds-')
    os.makedirs(os.path.join(c, 'report', 'evidence'))
    open(os.path.join(c, 'report', 'evidence', 's.txt'), 'w').write('noi dung day du\n')
    C.add(c, id='f1', kind='c2', value='noi dung day du', src='S', evidence='report/evidence/s.txt')
    return c
N = [1]
def more(c):   # đổi facts: lượt review kế tiếp được tính
    N[0] += 1; C.add(c, id=f'f{N[0]}', kind='string', value='noi dung', src='S', evidence='report/evidence/s.txt')
def rv(c, fail=(), valid=True, llm=True):
    NEXT.update(fail=list(fail), valid=valid); b = io.StringIO()
    with contextlib.redirect_stdout(b): rc = R.review(c, llm=llm, preview=False)
    return rc, b.getvalue()
def st(c): return R.state(c)

def main():
    # 0. hàm đếm: PASS có lớp 2 (hoặc state cũ thiếu reviewer) đặt lại; PASS chỉ-lớp-máy và FAIL thì không
    A = R.attempt; P, F = dict(verdict='PASS', reviewer='mech+x'), dict(verdict='FAIL', reviewer='mech+x')
    assert (A([]), A([F]), A([F, F]), A([P]), A([P, F]), A([F, P, F, F])) == (0, 1, 2, 0, 1, 2)
    assert A([dict(verdict='PASS'), F]) == 1 and A([F, dict(verdict='PASS', reviewer='mech'), F]) == 3
    # 1. PASS, thêm fact, FAIL: còn một lượt sửa (không STOPPED); FAIL nữa mới STOPPED, STOP_REPORT đọc đúng hai vòng cuối
    c = mkcase()
    try:
        rc, out = rv(c); assert rc == 0 and 'review 1/2: PASS' in out and R.gate(c)[0], out
        more(c); rc, out = rv(c); assert rc == 0 and R.gate(c)[0], out
        more(c); rc, out = rv(c, fail=['f1'])
        assert rc == 1 and not st(c)['stopped'] and 'review 3 (lượt 1/2' in out and 'BƯỚC KẾ: sửa' in out, out
        more(c); rc, out = rv(c, fail=['f1'])
        assert rc == 2 and st(c)['stopped'] and 'review 4 (lượt 2/2' in out and [r['n'] for r in st(c)['rounds']] == [1, 2, 3, 4], out
        rep = open(os.path.join(R.DIR(c), 'STOP_REPORT.md'), encoding='utf-8').read()
        assert '## Fact còn fail sau review 4' in rep and '| f1 | high |' in rep and '**f1**: review 3: sai → review 4: sai' in rep, rep
        assert R.gate(c) == (False, 'đã STOPPED sau 2 lần review')
    finally: shutil.rmtree(c, ignore_errors=True)
    # 2. case mới: hai lần FAIL liên tiếp vẫn STOPPED như trước
    c = mkcase()
    try:
        rc, out = rv(c, fail=['f1']); assert rc == 1 and 'review 1/2: FAIL' in out, out
        more(c); rc, out = rv(c, fail=['f1']); assert rc == 2 and 'review 2/2: FAIL' in out and st(c)['stopped'], out
    finally: shutil.rmtree(c, ignore_errors=True)
    # 3. PASS chỉ-lớp-máy chen giữa hai lần FAIL không đặt lại bộ đếm
    c = mkcase()
    try:
        assert rv(c, fail=['f1'])[0] == 1
        more(c); rc, out = rv(c, llm=False); assert rc == 0 and st(c)['rounds'][-1]['reviewer'] == 'mech' and not R.gate(c)[0], out
        more(c); rc, out = rv(c, fail=['f1']); assert rc == 2 and st(c)['stopped'], out
    finally: shutil.rmtree(c, ignore_errors=True)
    # 4. lượt lớp 2 không hợp lệ là FAIL và được tính vào giới hạn
    c = mkcase()
    try:
        assert rv(c)[0] == 0
        more(c); rc, out = rv(c, valid=False); assert rc == 1 and not st(c)['stopped'], out
        more(c); rc, out = rv(c, valid=False); assert rc == 2 and st(c)['stopped'], out
    finally: shutil.rmtree(c, ignore_errors=True)
    # 5. luật mức chặn: fact verdict thuộc nhóm chặn kể cả lỗi phán đoán; lookup_content là check cứng với mọi kind
    assert R.severity('verdict', 'fail', 'status_too_strong') == 'high' and R.severity('config', 'fail', 'lookup_content') == 'high'
    assert R.severity('string', 'fail', 'status_too_strong') == 'low' and R.severity('verdict', 'weak', 'status_too_strong') == 'low'
    print('OK check_rounds')

if __name__ == '__main__': main()
