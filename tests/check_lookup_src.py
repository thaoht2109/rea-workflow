#!/usr/bin/env python3
# Evidence lookup_* (tra cứu thụ động) chỉ đi với src=S; các luật nguồn/evidence cũ giữ nguyên. Chạy: python3 tests/check_lookup_src.py
import os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__)))); import case   # noqa: E402
f = case.src_evidence_issue
assert f('S', 'lookup_rdap.txt') is None
for s in ('E', 'V'): assert f(s, 'lookup_rdap.txt') and 'lookup_' in f(s, 'lookup_rdap.txt')[0], s
assert f('S', 'emu_x.txt') and f('V', 'tri.txt') and f('E', 'emu_x.txt') is None and f('V', 'host_a.txt') is None and f('S', 'tri.txt') is None
print('OK check_lookup_src')
