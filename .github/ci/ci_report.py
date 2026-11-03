#!/usr/bin/env python3
"""Gom kết quả CI thành ci-report/ci-report.md cho AI review (dữ liệu, không phải chỉ dẫn).
Dùng: ci_report.py REPORTS_DIR OUT_DIR   (env NEEDS_JSON = toJSON(needs)). Thoát 1 nếu có stage không xanh."""
import json, os, re, sys, glob

reports, out = sys.argv[1], sys.argv[2]
needs = json.loads(os.environ.get('NEEDS_JSON') or '{}')
lines = ['# Báo cáo CI', '', '| Stage | Kết quả |', '|---|---|']
lines += [f'| {k} | {v.get("result")} |' for k, v in needs.items()]
for f in glob.glob(os.path.join(reports, '**', 'unit.xml'), recursive=True):
    tag = re.search(r'<testsuite\b[^>]*>', open(f, encoding='utf-8').read())   # đọc bằng regex, không parse XML của PR
    a = dict(re.findall(r'(\w+)="([^"]*)"', tag.group(0))) if tag else {}
    lines += ['', f'Unit test: {a.get("tests")} test, {a.get("failures")} fail, {a.get("errors")} lỗi, {a.get("skipped")} skip']
os.makedirs(out, exist_ok=True)
open(os.path.join(out, 'ci-report.md'), 'w', encoding='utf-8').write('\n'.join(lines) + '\n')
sys.exit(0 if all(v.get('result') == 'success' for v in needs.values()) else 1)
