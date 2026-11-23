#!/usr/bin/env python3
# flow.py next: khi fact url trỏ tới nơi chứa nội dung công cộng (dead-drop) mà case chưa có evidence lookup_*, in MỘT lời nhắc hỏi người dùng
# (FLOW.md mục 0). Lời nhắc không chứa lệnh nào để chạy, không đổi trạng thái/mã thoát của next, và không hiện khi không áp dụng. Dữ liệu tổng hợp.
#   python3 tests/check_lookup_hint.py
import os, re, subprocess, sys, tempfile, shutil
T = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, T)
import case as C, review as R
STATES = r'^(STOPPED|NEED_MORE|NEED_FIX|NEED_REVIEW|NEED_REPORT|DONE)\b'   # như watch.py: lời nhắc không được trông như một trạng thái

def mk(url='https://raw.githubusercontent.com/user-x/repo-y/main/cfg'):
    c = tempfile.mkdtemp(prefix='rea-hint[1]-'); E = os.path.join(c, 'report', 'evidence'); os.makedirs(E); os.makedirs(os.path.join(c, 'work', 'sample'))
    open(os.path.join(E, 's.txt'), 'w').write(url + '\n')
    C.add(c, id='u1', kind='url', value=url, src='S', evidence='report/evidence/s.txt#L1')
    return c
def nxt(c): return subprocess.run([sys.executable, os.path.join(T, 'flow.py'), 'next', c], capture_output=True, text=True)

c = mk()
try:
    base = nxt(c); h = R.lookup_hint(c)
    assert h and 'u1' in h and 'KHÔNG tự tra' in h and 'FLOW.md mục 0' in h, h
    assert h in base.stdout and base.stdout.count('lưu ý (không chặn)') == 1, base.stdout
    assert not re.search(r'curl|wget|https?://|flow\.py|python3|`', h), h             # không có lệnh hay URL nào để chạy theo
    assert not any(re.match(STATES, l) for l in h.splitlines()), h                   # không bị watch đọc thành trạng thái
    st = [l.split()[0] for l in base.stdout.splitlines() if re.match(STATES, l)]
    open(os.path.join(c, 'report', 'evidence', 'lookup_dd.txt'), 'w').write('example.org\n')   # đã tra: hết nhắc, trạng thái và mã thoát không đổi
    after = nxt(c)
    assert R.lookup_hint(c) == '' and 'lưu ý (không chặn)' not in after.stdout, after.stdout
    assert after.returncode == base.returncode and [l.split()[0] for l in after.stdout.splitlines() if re.match(STATES, l)] == st, (base.stdout, after.stdout)
    os.remove(os.path.join(c, 'report', 'evidence', 'lookup_dd.txt'))
    C.add(c, id='u2', kind='url', value='https://raw.githubusercontent.com/user-x/repo-y/main/cfg', src='S', evidence='report/evidence/s.txt#L1', supersedes='u1', status='hypothesis')
    assert R.lookup_hint(c) == ''                                                    # fact đã bị thay và bản mới chỉ là giả thuyết: không nhắc
finally: shutil.rmtree(c, ignore_errors=True)
for url in ('https://updates.example.com/raw.githubusercontent.com/x', 'https://github.com/user-x/repo-y', 'không phải url',   # host khác, kể cả khi tên host nằm trong đường dẫn
            'http://host[abc/x', 'http://a]b/', 'http://evil[.]example/', 'http://x[1]/'):                                       # giá trị làm urlsplit ném ValueError: next không được sập
    c = mk(url)
    try:
        r = nxt(c)
        assert R.lookup_hint(c) == '' and 'lưu ý (không chặn)' not in r.stdout and 'Traceback' not in r.stderr and any(re.match(STATES, l) for l in r.stdout.splitlines()), (url, r.stdout, r.stderr)
    finally: shutil.rmtree(c, ignore_errors=True)
print('OK check_lookup_hint')
