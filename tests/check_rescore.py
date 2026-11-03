#!/usr/bin/env python3
"""Test re-score verdict khi đổi RULE_VERSION (review.rescore). Chạy: python3 tests/check_rescore.py"""
import os, sys, json, tempfile, shutil, glob

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.normpath(os.path.join(HERE, '..')))
import case as C, review as R

def mkcase():
    c = tempfile.mkdtemp(prefix='rea-rescore-')
    os.makedirs(os.path.join(c, 'report', 'evidence'))
    open(os.path.join(c, 'report', 'evidence', 's.txt'), 'w').write('noi dung day du\n')
    C.add(c, id='f1', kind='string', value='noi dung', src='S', evidence='report/evidence/s.txt')
    return c

def old_state(c, rounds, items_per_round, h=None):
    """Dựng state theo luật cũ: không rule_version, review.json do model/luật cũ chấm."""
    d = R.DIR(c); os.makedirs(d, exist_ok=True); h = h or R.facts_sha(c)
    for n, items in enumerate(items_per_round, 1):
        os.makedirs(os.path.join(d, f'r{n}'), exist_ok=True)
        if items is not None:
            json.dump(dict(round=n, facts_sha256=h, verdict='PASS', items=items), open(os.path.join(d, f'r{n}', 'review.json'), 'w'))
    json.dump({'rounds': [dict(n=n, facts_sha256=h, verdict='PASS', weak=0) for n in range(1, rounds + 1)], 'stopped': False}, open(os.path.join(d, 'state.json'), 'w'))

low_fail = dict(id='f1', verdict='fail', check='value_vs_evidence', severity='low', where='x', redo='y', problem='p')
weak = dict(id='f1', verdict='weak', check='status_too_strong', severity='low', where='x', redo='y', problem='p')
def st(c): return R.state(c)
def cache(c): return glob.glob(os.path.join(R.DIR(c), '**', 'llm_cache', '*'), recursive=True)

def main():
    # 1. PASS cũ + fail cứng gắn nhãn low: vòng 1 -> FAIL, chưa stopped, gate chặn
    c = mkcase()
    try:
        old_state(c, 1, [[low_fail]])
        assert R.review(c) == 1 and cache(c) == []
        assert st(c)['rounds'][0]['verdict'] == 'FAIL' and not st(c)['stopped'] and not R.gate(c)[0]
        assert json.load(open(os.path.join(R.DIR(c), 'r1', 'review.json')))['items'][0]['severity'] == 'high'
        n_before = json.dumps(st(c)['rounds'])
        assert R.review(c) == 1 and json.dumps(st(c)['rounds']) == n_before      # 6. idempotent
    finally: shutil.rmtree(c, ignore_errors=True)
    # 1b. vòng cuối FAIL -> STOPPED + STOP_REPORT
    c = mkcase()
    try:
        old_state(c, 2, [[weak], [low_fail]])
        assert R.review(c) == 2 and st(c)['stopped'] and os.path.exists(os.path.join(R.DIR(c), 'STOP_REPORT.md'))
        assert not R.gate(c)[0]
    finally: shutil.rmtree(c, ignore_errors=True)
    # 2. chỉ weak -> vẫn PASS, gate qua
    c = mkcase()
    try:
        old_state(c, 1, [[weak]])
        assert R.review(c) == 0 and st(c)['rounds'][0]['weak'] == 1 and R.gate(c)[0]
    finally: shutil.rmtree(c, ignore_errors=True)
    # 3. facts đổi sau vòng cuối -> không re-score, mở bộ đếm mới, review.json giữ nguyên
    c = mkcase()
    try:
        old_state(c, 1, [[low_fail]], h='x')
        R.review(c)
        assert len(st(c)['rounds']) == 1 and st(c)['rounds'][0]['facts_sha256'] == R.facts_sha(c)   # review lạnh mới
    finally: shutil.rmtree(c, ignore_errors=True)
    # 4. thiếu review.json -> fallback reset, không crash
    c = mkcase()
    try:
        old_state(c, 1, [None])
        R.review(c); assert st(c)['rule_version'] == C.REVIEW_RULE_VERSION and len(st(c)['rounds']) == 1
    finally: shutil.rmtree(c, ignore_errors=True)
    # 5. item thiếu check -> severity theo kind (string không gating -> low)
    c = mkcase()
    try:
        nocheck = dict(id='f1', verdict='fail', severity='high', where='x', redo='y', problem='p')
        old_state(c, 1, [[nocheck]])
        assert R.review(c) == 0
    finally: shutil.rmtree(c, ignore_errors=True)
    print('OK test_rescore')

if __name__ == '__main__': main()
