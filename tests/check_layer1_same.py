#!/usr/bin/env python3
"""Lint khi ghi fact và lớp 1 của cổng dùng MỘT phép kiểm value-trong-evidence; cùng vài luật nhỏ đi kèm (C11, bảng đính chính, scan không cần bộ eval).
Chạy: python3 tests/check_layer1_same.py
"""
import os, sys, hashlib, tempfile, shutil, subprocess

HERE = os.path.dirname(os.path.abspath(__file__))
SKILL = os.path.normpath(os.path.join(HERE, '..'))
sys.path.insert(0, SKILL)
import case as C, review as R

def main():
    c = tempfile.mkdtemp(prefix='rea-l1-')
    try:
        ev = os.path.join(c, 'report', 'evidence'); os.makedirs(ev)
        open(os.path.join(ev, 'e.txt'), 'w').write('\n'.join(['host evil.example.com'] + [f'dong {i}' for i in range(2, 40)] + ['so luong 1,234 ban ghi']) + '\n')
        blob = b'\x00\x01\x02khoa' * 20; open(os.path.join(ev, 'k.bin'), 'wb').write(blob)
        A = lambda **k: C.add(c, src='S', **k)
        A(id='near', kind='c2', value='evil.example.com', evidence='report/evidence/e.txt#L3')        # trong ±WINDOW: sạch
        A(id='far', kind='c2', value='evil.example.com', evidence='report/evidence/e.txt#L30')        # có trong file nhưng trỏ lệch: nhắc
        A(id='none', kind='c2', value='other.example.net', evidence='report/evidence/e.txt#L3')       # không có ở đâu trong file: chặn
        A(id='whole', kind='c2', value='other.example.net', evidence='report/evidence/e.txt')
        A(id='num', kind='string', value='ban ghi: 1234 dong', evidence='report/evidence/e.txt#L40')   # số có dấu ngăn nghìn trong evidence (_normnum)
        A(id='bin0', kind='payload_key', value='khoa giai ma payload', evidence='report/evidence/k.bin')
        A(id='bin1', kind='payload_key', value='khoa sha256 ' + hashlib.sha256(blob).hexdigest(), evidence='report/evidence/k.bin')
        got = {i['id']: (i['verdict'], i['severity']) for i in R.mech(c) if i['check'] == 'value_in_evidence'}
        assert got == {'far': ('weak', 'low'), 'none': ('fail', 'high'), 'whole': ('fail', 'high'), 'bin0': ('weak', 'low')}, got
        cur = C.load(c)
        lint = {i: [x['level'] for x in C.lint_fact(c, cur[i]) if x['check'] == 'value_in_evidence'] for i in cur}
        assert lint == {'near': [], 'far': ['fail'], 'none': ['fail'], 'whole': ['fail'], 'num': [], 'bin0': ['warn'], 'bin1': []}, lint   # lint giữ mức chặt hơn cho trỏ lệch dòng (chỉ in cảnh báo khi ghi)
        # C11: exit_reason chỉ đạt khi value mở đầu bằng natural (có thể sau tên tiến trình)
        ok = lambda v: bool(C.NATURAL_RX.match(v))
        assert all(map(ok, ('natural: ExitProcess', 'parent: natural: TerminateProcess', ' natural')))
        assert not any(map(ok, ('unnatural: lỗi giả lập', 'stop_at 0x401a2c, chưa natural', 'child: stop_at: Sleep', 'emu1: chưa natural')))
        A(id='x1', kind='exit_reason', value='stop_at 0x401a2c, chưa natural', evidence='report/evidence/e.txt')
        A(id='x2', kind='api_unused', value='p: Sleep', evidence='report/evidence/e.txt'); A(id='x3', kind='dec_coverage', value='4/4', evidence='report/evidence/e.txt')
        assert dict((k.split()[0], v) for k, v, _ in C.check(c))['C11'] != 'ok'
        # bảng đính chính: không còn cột "Vòng" luôn trống
        A(id='near2', kind='c2', value='evil.example.com:443', evidence='report/evidence/e.txt#L1', supersedes='near')
        C.report(c); g = open(os.path.join(c, 'report', 'GENERATED.md'), encoding='utf-8').read()
        assert '| id | Trước | Sau |\n|---|---|---|\n' in g and '| near → near2 | evil.example.com | evil.example.com:443 |\n' in g, g[-600:]
        # flow.py scan không kéo theo watch/bộ eval (bản chép skill không có evals/)
        d = os.path.join(c, 'thu'); os.makedirs(d); open(os.path.join(d, 'm.bin'), 'wb').write(b'\x7fELF' + b'\0' * 60); open(os.path.join(d, 'm.bin.txt'), 'w').write('ghi chu thu mau\n')
        code = ("import sys, importlib.abc\n"
                "class B(importlib.abc.MetaPathFinder):\n"
                "    def find_spec(self, n, p, t=None):\n"
                "        if n.split('.')[0] in ('evals', 'watch'): raise ImportError('chặn ' + n)\n"
                "sys.meta_path.insert(0, B()); sys.path.insert(0, sys.argv[1]); import flow\n"
                "ok, skip = flow.scan_collect(sys.argv[2], sys.argv[3]); print(len(ok), skip[0][1][:15])\n")
        r = subprocess.run([sys.executable, '-c', code, SKILL, d, c], capture_output=True, text=True)
        assert r.returncode == 0 and r.stdout.strip() == '1 ghi chú thu mẫu', (r.stdout, r.stderr[-400:])
    finally: shutil.rmtree(c, ignore_errors=True)
    print('OK check_layer1_same')

if __name__ == '__main__': main()
