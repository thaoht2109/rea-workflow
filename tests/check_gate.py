#!/usr/bin/env python3
"""Test luật severity của cổng phản biện (review.py) và việc ghi đè severity của model (reviewer.py).
Chạy: python3 tests/check_gate.py
"""
import os, sys, json, tempfile, shutil

HERE = os.path.dirname(os.path.abspath(__file__))
SKILL = os.path.normpath(os.path.join(HERE, '..'))
sys.path.insert(0, SKILL)
import case as C, review as R, reviewer

def mkcase():
    c = tempfile.mkdtemp(prefix='rea-gate-')
    os.makedirs(os.path.join(c, 'report', 'evidence'))
    open(os.path.join(c, 'report', 'evidence', 's.txt'), 'w').write('noi dung day du\n')
    C.add(c, id='f1', kind='string', value='noi dung', src='S', evidence='report/evidence/s.txt')
    C.add(c, id='f2', kind='c2', value='noi dung day du', src='S', evidence='report/evidence/s.txt')
    return c

def main():
    c = mkcase()
    try:
        # 1. luật: fail ở check cứng luôn high, bất kể kind
        assert R.severity('string', 'fail', 'value_in_evidence') == 'high'
        assert R.severity('coverage', 'fail', 'src_vs_evidence') == 'high'
        assert R.severity('string', 'fail', 'value_vs_evidence') == 'high'      # LLM
        assert R.severity('string', 'fail', 'recompute') == 'high'              # LLM
        # 2. kind thuộc GATING luôn high
        assert R.severity('c2', 'fail', 'alternative_explanation') == 'high'
        assert R.severity('family', 'fail', 'status_too_strong') == 'high'
        # 3. fail phán đoán trên kind không gating vẫn low (không chặn)
        assert R.severity('string', 'fail', 'alternative_explanation') == 'low'
        assert R.severity('anti_analysis', 'fail', 'status_too_strong') == 'low'
        # 4. weak/pass luôn low
        assert R.severity('c2', 'weak', 'value_vs_evidence') == 'low'

        # 5. model trả severity low cho check cứng -> bị ghi đè thành high
        items = [dict(id='f1', verdict='fail', check='value_vs_evidence', severity='low', where='x', redo='y'),
                 dict(id='f2', verdict='fail', check='alternative_explanation', severity='low'),
                 dict(id='f1', verdict='weak', check='status_too_strong', severity='high')]
        reviewer.apply_severity(c, items)
        assert [i['severity'] for i in items] == ['high', 'high', 'low'], items

        # 6. verdict() chỉ FAIL khi có high; fail low không chặn
        assert R.verdict([dict(verdict='fail', severity='low')]) == 'PASS'
        assert R.verdict([dict(verdict='fail', severity='high')]) == 'FAIL'

        # 7. state.json không có rule_version (luật cũ) -> C0 missing, gate chặn
        d = os.path.join(c, 'work', 'review'); os.makedirs(d, exist_ok=True)
        json.dump({'rounds': [dict(n=1, facts_sha256='x', verdict='PASS', weak=0)], 'stopped': False},
                  open(os.path.join(d, 'state.json'), 'w'))
        assert dict((k.split()[0], v) for k, v, _ in C.check(c))['C0'] == 'missing'
        assert R.gate(c)[0] is False
        # 8. review() có lớp 2 mở bộ đếm mới và ghi rule_version hiện tại (reviewer giả, không gọi LLM)
        reviewer.run = lambda c, k, ids, items: ([], [], dict(valid=True, backend='stub', turns=1, requests=0, invalid_reasons=[]))
        assert R.review(c) == 0   # không --llm: chỉ xem trước (fact hợp lệ -> PASS), không tính vòng
        assert not R.gate(c)[0] and not (R.state(c).get('rounds') or [])
        R.review(c, llm=True)
        st = json.load(open(os.path.join(d, 'state.json')))
        assert st['rule_version'] == C.REVIEW_RULE_VERSION and len(st['rounds']) == 1 \
               and st['rounds'][0]['verdict'] == 'PASS' and '+' in st['rounds'][0]['reviewer'], st
        assert R.gate(c)[0]
    finally:
        shutil.rmtree(c, ignore_errors=True)
    print('OK test_gate (8 nhóm)')

if __name__ == '__main__':
    main()
