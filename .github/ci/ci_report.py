#!/usr/bin/env python3
"""Gom kết quả CI thành ci-report/ci-report.md cho AI review (dữ liệu, không phải chỉ dẫn).
Dùng: ci_report.py REPORTS_DIR OUT_DIR   (env NEEDS_JSON = toJSON(needs)). Thoát 1 nếu có stage không xanh."""
import json, os, sys, glob
import xml.etree.ElementTree as ET

reports, out = sys.argv[1], sys.argv[2]
needs = json.loads(os.environ.get('NEEDS_JSON') or '{}')
lines = ['# Báo cáo CI', '', '| Stage | Kết quả |', '|---|---|']
lines += [f'| {k} | {v.get("result")} |' for k, v in needs.items()]
for f in glob.glob(os.path.join(reports, '**', 'unit.xml'), recursive=True):
    s = ET.parse(f).getroot()
    s = s if s.tag == 'testsuite' else s.find('testsuite')
    lines += ['', f'Unit test: {s.get("tests")} test, {s.get("failures")} fail, {s.get("errors")} lỗi, {s.get("skipped")} skip']
os.makedirs(out, exist_ok=True)
open(os.path.join(out, 'ci-report.md'), 'w', encoding='utf-8').write('\n'.join(lines) + '\n')
sys.exit(0 if all(v.get('result') == 'success' for v in needs.values()) else 1)
