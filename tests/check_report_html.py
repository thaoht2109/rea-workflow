#!/usr/bin/env python3
# Báo cáo theo ngày phân tích + bản HTML: report-<ngày>.md, đổi tên README.md của case cũ, report sinh report-<ngày>.html
# đã escape, không tải tài nguyên mạng, URL ngoài không thành link. Dữ liệu tổng hợp.   python3 tests/check_report_html.py
import os, re, sys, shutil, tempfile, subprocess
T = os.path.dirname(os.path.dirname(os.path.abspath(__file__))); sys.path.insert(0, T)
import case, review, htmlreport

w = tempfile.mkdtemp(prefix='rea-rpt-')
try:
    # case cũ: README.md -> report-<Ngày bắt đầu>.md; report_md/report_todo/audit đọc theo tên mới
    c = os.path.join(w, 'OLD'); E = os.path.join(c, 'report', 'evidence'); os.makedirs(E); os.makedirs(os.path.join(c, 'work', 'review'))
    open(os.path.join(E, 'e.txt'), 'w').write('a\nhost <b>evil</b>.example.com http://evil.example.com/x?a=1&b=2\n')
    case.add(c, id='c2x', kind='c2', value='evil</b>.example.com', src='S', evidence='report/evidence/e.txt#L2')
    old = os.path.join(c, 'report', 'README.md')
    assert case.report_md(c) == old and not case.migrate_report(c), 'chưa có README: không đổi tên gì'
    open(old, 'w', encoding='utf-8').write('# Báo cáo phân tích: `OLD`\n\n> Ngày bắt đầu: 2026-03-04. Quy trình\n\n## 1. Tóm tắt\n\n'
        'C2 (fact c2x) là `evil.example.com`, xem [trang](http://evil.example.com/x) và [GENERATED](GENERATED.md), [`e.txt`](evidence/e.txt).\n'
        'Chèn <script>alert(1)</script> **đậm** _nghiêng_ snake_case_name.\n\n- mục 1\n  - mục con `report/evidence/e.txt#L2`\n- mục 2\n\n'
        '```\nint x = a < b;\n```\n\n## 9. Evidence\n\n| File | Nội dung |\n|---|---|\n| `e.txt` | chuỗi có `a|b` |\n')
    assert case.report_md(c) == old
    m = case.migrate_report(c); assert m and os.path.basename(m) == 'report-2026-03-04.md' and not os.path.exists(old), m
    assert case.report_md(c) == m and case.migrate_report(c) is None and case.audit(c) == [], case.audit(c)
    open(os.path.join(c, 'work', 'review', 'report_todo.json'), 'w').write('[{"id": "c2x", "line": "c2x"}]')
    assert not review.report_todo(c), 'report_todo đọc báo cáo tên mới'
    open(os.path.join(c, 'work', 'review', 'report_todo.json'), 'w').write('[{"id": "zz9", "line": "zz9"}]'); assert review.report_todo(c)
    # nhiều bản: lấy ngày mới nhất; tên lạ không tính
    open(os.path.join(c, 'report', 'report-2026-01-01.md'), 'w').write('# cũ\n'); open(os.path.join(c, 'report', 'report-x.md'), 'w').write('#\n')
    assert case.report_md(c) == m
    os.remove(os.path.join(c, 'report', 'report-2026-01-01.md')); os.remove(os.path.join(c, 'report', 'report-x.md'))

    # report: GENERATED.md + report-2026-03-04.html
    case.report(c); h = open(os.path.join(c, 'report', 'report-2026-03-04.html'), encoding='utf-8').read()
    assert "default-src 'none'" in h and '<script>alert' not in h and '&lt;script&gt;alert(1)&lt;/script&gt;' in h, 'escape + CSP'
    assert '<b>evil</b>' not in h and 'evil&lt;/b&gt;.example.com' in h, 'giá trị fact phải escape'
    hrefs = re.findall(r'href="([^"]*)"', h)
    assert not [x for x in hrefs if re.match(r'^[a-z]+:|//', x, re.I)], f'không được có link ngoài: {hrefs}'
    assert '#phu-luc' in hrefs and 'evidence/e.txt' in hrefs, hrefs
    assert not re.search(r'<(link|img|iframe)\b|src=', h), 'không tải tài nguyên'
    assert '<strong>đậm</strong>' in h and '<em>nghiêng</em>' in h and 'snake_case_name' in h and '<pre><code>int x = a &lt; b;' in h
    assert re.search(r'<ul><li>mục 1<ul><li>mục con', h) and '<code>a|b</code>' in h, 'danh sách lồng, | trong code của bảng'
    assert 'title="report/evidence/e.txt#L2"' in h and '<code>e.txt#L2</code>' in h, 'nhãn evidence rút gọn'
    assert 'BẢN NHÁP' in h and 'C11' in h and 'id="phu-luc"' in h and 'Ngày phân tích 2026-03-04' in h

    # bản mới nhất có dòng 'Ngày bắt đầu' khác tên file: HTML theo tên file đang dùng
    open(os.path.join(c, 'report', 'report-2026-05-06.md'), 'w', encoding='utf-8').write('# x\n\n> Ngày bắt đầu: 2026-03-04\n')
    case.report(c); h = open(os.path.join(c, 'report', 'report-2026-05-06.html'), encoding='utf-8').read()
    assert 'Ngày phân tích 2026-05-06' in h and '<code>report-2026-05-06.md</code>' in h and 'report-2026-03-04.md</code>' not in h

    # chạy với CASE='.': gợi ý checklist không bị thay nhầm mọi dấu chấm
    cwd = os.getcwd(); os.chdir(c)
    try: case.report('.')
    finally: os.chdir(cwd)
    h = open(os.path.join(c, 'report', 'report-2026-05-06.html'), encoding='utf-8').read()
    assert 'flow.py review OLD' in h and 'flowOLDpy' not in h and 'triage_*.json' in h, 'gợi ý dùng tên case, không thay chuỗi'

    # mục đã chấp nhận là hạn chế (work/accepted.json): nhãn 'chấp nhận', hiện lý do thay gợi ý
    import json; json.dump({'C9': 'không có payload trong mẫu', 'C0': 'không được tính'}, open(os.path.join(c, 'work', 'accepted.json'), 'w'), ensure_ascii=False)
    case.report(c); h = open(os.path.join(c, 'report', 'report-2026-05-06.html'), encoding='utf-8').read()
    assert 'chấp nhận: missing' in h and 'Hạn chế đã chấp nhận: không có payload trong mẫu' in h and 'T4 (cần payload thật)' not in h, 'C9 chấp nhận'
    assert 'không được tính' not in h, 'C0 không chấp nhận qua accepted.json'

    # flow.py new: tạo report-<hôm nay>.md từ template, report in đường dẫn HTML
    s = os.path.join(w, 'x.bin'); open(s, 'wb').write(b'MZ' + b'\0' * 200)
    r = subprocess.run([sys.executable, os.path.join(T, 'flow.py'), 'new', os.path.join(w, 'NEW'), s], capture_output=True, text=True)
    R = os.listdir(os.path.join(w, 'NEW', 'report')); assert any(case.RPT.match(n) for n in R) and 'README.md' not in R, (R, r.stdout[-400:], r.stderr[-400:])
    r = subprocess.run([sys.executable, os.path.join(T, 'flow.py'), 'report', os.path.join(w, 'NEW')], capture_output=True, text=True)
    assert r.returncode == 0 and '.html' in r.stdout and any(n.endswith('.html') for n in os.listdir(os.path.join(w, 'NEW', 'report'))), r.stdout + r.stderr
    # flow.py report trên case cũ tự đổi tên
    c3 = os.path.join(w, 'OLD3'); os.makedirs(os.path.join(c3, 'report', 'evidence')); open(os.path.join(c3, 'report', 'README.md'), 'w').write('# x\n')
    r = subprocess.run([sys.executable, os.path.join(T, 'flow.py'), 'report', c3], capture_output=True, text=True)
    assert r.returncode == 0 and 'đổi tên' in r.stdout and not os.path.exists(os.path.join(c3, 'report', 'README.md')), r.stdout + r.stderr
    T = []; htmlreport.md('## A & <b> `x`\n', 0, set(), T); assert T[0][1] == 'A & <b> x', T      # mục lục: render() escape một lần
    assert htmlreport.md('| a |\n|---|\n| [x](javascript:alert(1)) |').count('href') == 0, 'javascript: không thành link'
    for u in ['/\\evil.example/x', '\\/evil.example', '\\\\evil\\s', '/etc/passwd', '\x01javascript:alert(1)', 'java\tscript:alert(1)', ' //evil', 'file:///x', 'HTTPS://a']:
        assert htmlreport._href(u) is None, u
    assert htmlreport._href('evidence/a.txt#L2') == 'evidence/a.txt#L2' and htmlreport._href('#muc') == '#muc' and htmlreport._href('GENERATED.md') == '#phu-luc'
finally: shutil.rmtree(w, ignore_errors=True)
print('OK check_report_html')
