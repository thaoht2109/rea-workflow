#!/usr/bin/env python3
"""kind=verdict: lint giá trị, ưu tiên fact verdict hơn suy từ family, fact bị thay/hypothesis không tính, nhãn trong GENERATED.md,
bản HTML và bản export. Dữ liệu tổng hợp. Chạy: python3 tests/check_verdict.py"""
import os, sys, shutil, tempfile
SKILL = os.path.dirname(os.path.dirname(os.path.abspath(__file__))); sys.path.insert(0, SKILL)
import case as C  # noqa: E402
from evals.run import mk_case  # noqa: E402

T = tempfile.mkdtemp(prefix='rea-verdict-')
try:
    # chưa có fact nào: CHƯA XÁC ĐỊNH
    c = mk_case(T, 'V1', [('s.url', 'url', 'http://x.invalid/a')])
    v = C.verdict(c); assert v['key'] == 'unknown' and not v['inferred'], v
    # chỉ có family: suy tạm, ghi rõ là suy luận; khớp hẹp (n/a, chưa quy họ là nghi vấn, không phải mã độc)
    for i, (val, k) in enumerate((('backdoor dạng reverse shell', 'malicious'), ('không phải mã độc: archive rỗng', 'benign'), ('n/a: chưa quy họ, file dữ liệu mã hóa', 'suspicious'),
                   ('không thấy hành vi độc hại trong phạm vi tĩnh', 'nofind'), ('dropper ngụy trang thành bộ cài lành tính', 'malicious'),
                   ('loader không chứa mã độc nhúng sẵn, tải payload từ C2', 'malicious'), ('bộ cài hợp lệ, có chữ lành tính ở giữa', 'suspicious'))):   # từ khóa mã độc xét trước; lành tính chỉ khi đứng đầu
        c = mk_case(T, f'F{i}', [('s.fam', 'family', val)])
        v = C.verdict(c); assert v['key'] == k and v['inferred'] and v['id'] == 's.fam', (val, v)
    # có fact verdict: dùng nó, không suy từ family; fact bị supersedes và hypothesis không tính
    c = mk_case(T, 'V2', [('s.fam', 'family', 'trojan loader'), ('s.v1', 'verdict', 'suspicious: chưa thấy C2')])
    v = C.verdict(c); assert v['key'] == 'suspicious' and not v['inferred'] and v['id'] == 's.v1' and v['why'] == 'chưa thấy C2', v
    C.add(c, id='s.v2', kind='verdict', value='malicious: loader tải payload từ C2', src='S', evidence='report/evidence/strings.txt#L1', supersedes='s.v1')
    assert C.verdict(c)['key'] == 'malicious' and C.verdict(c)['id'] == 's.v2'
    C.add(c, id='s.v3', kind='verdict', value='benign: thử', src='S', evidence='report/evidence/strings.txt#L1', status='hypothesis')
    assert C.verdict(c)['id'] == 's.v2', 'hypothesis không thay kết luận'
    # lint: value phải bắt đầu bằng một khóa
    bad = dict(id='x', kind='verdict', value='có lẽ là mã độc', src='S', evidence='report/evidence/strings.txt#L1', status='active')
    assert [x['check'] for x in C.lint_fact(c, bad) if x['level'] == 'fail'] == ['verdict_value']
    import review  # noqa: E402  lớp 1 phản biện kiểm lại cùng luật, mức high
    C.add(c, id='s.bad', kind='verdict', value='có lẽ là mã độc', src='S', evidence='report/evidence/strings.txt#L1', status='hypothesis')
    assert [(x['verdict'], x['severity']) for x in review.mech(c) if x['id'] == 's.bad' and x['check'] == 'verdict_value'] == [('fail', 'high')], review.mech(c)
    for ok in ('malicious', 'nofind: không thấy hành vi', 'benign : tài liệu PDF hợp lệ'):
        assert not [x for x in C.lint_fact(c, dict(bad, value=ok)) if x['check'] == 'verdict_value'], ok
    # nhãn trong GENERATED.md và bản HTML của case
    C.report(c)
    g = open(os.path.join(c, 'report', 'GENERATED.md'), encoding='utf-8').read()
    assert '> **PHÂN LOẠI: MÃ ĐỘC / CÔNG CỤ TẤN CÔNG**. Căn cứ: fact `s.v2`: loader tải payload từ C2' in g, g[:400]
    h = open(C.report_html(c), encoding='utf-8').read()
    assert h.index('id="phan-loai"') > h.index('</h1>') and 'PHÂN LOẠI: MÃ ĐỘC' in h, h[:2000]
    c2 = os.path.join(T, 'F2'); C.report(c2)
    assert 'suy tạm từ fact s.fam (family), chưa có fact verdict' in open(C.report_html(c2), encoding='utf-8').read()
    # bản export: nhãn ngay dưới tiêu đề của bản .md
    os.environ['SEVENZ_BIN'] = '/bin/false'   # case không có mẫu/nhị phân: không gọi 7z
    import export  # noqa: E402
    d = os.path.join(T, 'out', 'v_data')
    info = dict(name='v', src='v', inbox='', sha256='a' * 64, size=1, ftype='', aliases=[], notes=[], sums=[], case=os.path.abspath(c))
    C.add(c, id='s.v4', kind='verdict', value='nofind: xem lại, không thấy hành vi', src='S', evidence='report/evidence/strings.txt#L1', supersedes='s.v2')
    export.export(info, d); export.augment(info, d)   # report.html của case sinh trước s.v4: bản export vẫn theo facts hiện tại
    hx = open(os.path.join(d, 'v.html'), encoding='utf-8').read()
    assert hx.count('id="phan-loai"') == 1 and 'KHÔNG THẤY HÀNH VI ĐỘC HẠI' in hx and 'MÃ ĐỘC / CÔNG CỤ' not in hx, hx[:1500]
    md = open(os.path.join(d, 'v.md'), encoding='utf-8').read().splitlines()
    assert md[0].startswith('# ') and md[2].startswith('> **PHÂN LOẠI: KHÔNG THẤY HÀNH VI'), md[:4]
finally: shutil.rmtree(T, ignore_errors=True)
print('OK check_verdict')
