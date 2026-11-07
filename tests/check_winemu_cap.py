#!/usr/bin/env python3
# Kiểm trần --max-events của winemu: trích đúng đoạn nguồn (EVN/EV_KEEP/ev) rồi exec trong namespace giả
# (không cần unicorn). Khẳng định: dừng ghi kind ồn ào sau trần, chèn đúng một dòng warn, kind hiếm luôn qua,
# --max-events 0 tắt trần. Dữ liệu tổng hợp, không chạy mẫu.
#   python3 tests/check_winemu_cap.py
import os, re, json, types
SRC = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
src = open(os.path.join(SRC, 'winemu', 'winemu.py'), encoding='utf-8').read()

# đoạn từ 'EVN = [0]' tới hết thân hàm ev (dừng trước 'def page')
m = re.search(r'\nEVN = \[0\].*?\ndef page\(', src, re.S)
assert m, 'không tìm thấy khối EVN..ev trong winemu.py'
block = m.group(0).rsplit('\ndef page(', 1)[0]
assert '--max-events' in src and "AP.add_argument('--max-events'" in src, 'thiếu tham số --max-events'

def build(cap):
    """exec đoạn nguồn thật với EVF/A/json giả; trả (ev, lines)."""
    lines = []
    ns = {'json': json, 'A': types.SimpleNamespace(tag='parent', max_events=cap),
          'EVF': types.SimpleNamespace(write=lines.append, flush=lambda: None)}
    exec(block, ns)   # nosec B102 - cố ý chạy đúng đoạn nguồn winemu đã trích ở trên (không phải input ngoài) để test code thật
    return ns['ev'], lines, ns['EV_KEEP']

# 1. trần 3: 3 dòng api ồn ào + 1 warn, dòng thứ 4 trở đi bị bỏ
ev, lines, keep = build(3)
for _ in range(10):
    ev('api', name='X')
kinds = [json.loads(x)['kind'] for x in lines]
assert kinds == ['api', 'api', 'api', 'warn'], kinds
assert json.loads(lines[-1])['what'] == 'max_events' and json.loads(lines[-1])['cap'] == 3, lines[-1]

# 2. kind hiếm luôn ghi dù đã quá trần
for k in ('end', 'oep', 'snapshot', 'stop_at', 'anti', 'warn', 'start'):
    assert k in keep, f'EV_KEEP thiếu {k}'
before = len(lines)
ev('end', reason='stop'); ev('oep', eip=1)
after = [json.loads(x)['kind'] for x in lines[before:]]
assert after == ['end', 'oep'], after

# 3. trần 0 = không giới hạn, không có dòng warn
ev0, lines0, _ = build(0)
for _ in range(100):
    ev0('api', name='Y')
assert len(lines0) == 100 and all(json.loads(x)['kind'] == 'api' for x in lines0), len(lines0)

# 4. mặc định 50_000 trong argparse
assert re.search(r"--max-events'.*default=50_000", src), 'mặc định --max-events phải là 50_000'
print('ok')
