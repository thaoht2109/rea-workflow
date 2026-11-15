#!/usr/bin/env python3
# flow.py next --accept: nhiều cờ --accept trong một lệnh đều được ghi (trước đây chỉ cờ đầu, cờ sau bị bỏ lặng lẽ);
# một cờ chứa nhiều mục 'Cx=..., Cy=...' vẫn tách đúng. Dữ liệu tổng hợp.
#   python3 tests/check_accept.py
import json, os, subprocess, sys, tempfile, shutil
T = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
c = tempfile.mkdtemp(prefix='rea-acc-'); os.makedirs(os.path.join(c, 'report', 'evidence')); os.makedirs(os.path.join(c, 'work', 'sample'))
open(os.path.join(c, 'facts.jsonl'), 'w').close()
try:
    run = lambda *a: subprocess.run([sys.executable, os.path.join(T, 'flow.py'), 'next', c] + list(a), capture_output=True, text=True)
    r = run('--accept', 'C4=lý do một, có dấu phẩy', '--accept', 'C8=lý do hai')
    acc = json.load(open(os.path.join(c, 'work', 'accepted.json')))
    assert acc == {'C4': 'lý do một, có dấu phẩy', 'C8': 'lý do hai'}, (acc, r.stdout, r.stderr)
    assert 'chấp nhận hạn chế: C8' in r.stdout and 'còn thiếu: C8' not in r.stdout, r.stdout
    run('--accept', 'C6=ba, C9=bốn'); acc = json.load(open(os.path.join(c, 'work', 'accepted.json')))
    assert acc['C6'] == 'ba' and acc['C9'] == 'bốn' and len(acc) == 4, acc
    r = subprocess.run([sys.executable, os.path.join(T, 'review.py'), 'next', c, '--accept', 'C3=x', '--accept', 'C5=y'], capture_output=True, text=True)
    acc = json.load(open(os.path.join(c, 'work', 'accepted.json'))); assert acc['C3'] == 'x' and acc['C5'] == 'y', acc
finally: shutil.rmtree(c, ignore_errors=True)
print('OK check_accept')
