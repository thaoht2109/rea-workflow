#!/usr/bin/env python3
# flow.py scan: gom mọi mẫu ở cấp một của thư mục thu mẫu vào MỘT case, chạy lượt đọc nhanh, bật C12 khi có từ hai mẫu. Dữ liệu tổng hợp. Chạy: python3 tests/check_scan.py
import os, sys, hashlib, tempfile, subprocess
T = os.path.dirname(os.path.dirname(os.path.abspath(__file__))); sys.path.insert(0, T)
import case   # noqa: E402
base = tempfile.mkdtemp(prefix='rea-scan-'); ws = os.path.join(base, 'ws'); os.makedirs(ws)
run = lambda *a, cwd=ws: subprocess.run([sys.executable, os.path.join(T, 'flow.py'), *a], cwd=cwd, capture_output=True, text=True)
A = b'\x01\x02' + b'\0'.join([b'-key=KEY', b'http://c2.example.net/x', b'/opt/agent/helper.conf', b'start helper_b now']) + b'\0'
B = b'\x03\x04' + b'\0'.join([b'-mode=MODE', b'c2.example.net', b'/opt/agent/helper.conf']) + b'\0'
ck = lambda c: {k.split()[0]: v for k, v, _ in case.check(c)}
# --- thư mục hai mẫu, kèm thứ phải bị bỏ: file ẩn, ghi chú thu mẫu, tệp rỗng, thư mục báo cáo, thư mục case cũ, symlink
d2 = os.path.join(base, 'thu mau 2'); os.makedirs(d2)
open(os.path.join(d2, 'agent_a.bin'), 'wb').write(A); open(os.path.join(d2, 'helper_b.bin'), 'wb').write(B)
open(os.path.join(d2, '.hidden'), 'w').write('x'); open(os.path.join(d2, 'empty.bin'), 'w').close()
open(os.path.join(d2, 'agent_a.txt'), 'w').write('ghi chú: lấy từ thiết bị ngày 2026-01-02\n')                              # tên bắt đầu bằng tên một mẫu
open(os.path.join(d2, 'SHA256SUMS'), 'w').write(f"{hashlib.sha256(A).hexdigest()}  agent_a.bin\n")
os.makedirs(os.path.join(d2, 'old_report')); open(os.path.join(d2, 'old_report', 'README.md'), 'w').write('# báo cáo cũ\n')
os.makedirs(os.path.join(d2, 'Report_x')); open(os.path.join(d2, 'Report_x', 'r.md'), 'w').write('x\n')
os.makedirs(os.path.join(d2, 'OLDCASE', 'work', 'sample')); open(os.path.join(d2, 'OLDCASE', 'facts.jsonl'), 'w').close()
os.symlink('/etc/hostname', os.path.join(d2, 'link_out'))
r = run('scan', d2, '--dry-run'); o = r.stdout
assert r.returncode == 0 and '2 mẫu nhận' in o and 'nhận    agent_a.bin' in o and 'nhận    helper_b.bin' in o and '--dry-run: chưa tạo case' in o, o
for name, why in (('.hidden', 'ẩn'), ('empty.bin', 'tệp rỗng'), ('agent_a.txt', 'ghi chú thu mẫu'), ('SHA256SUMS', 'ghi chú thu mẫu'), ('old_report/', 'thư mục báo cáo'), ('Report_x/', 'thư mục báo cáo'), ('OLDCASE/', 'thư mục case'), ('link_out', 'symlink')):
    assert any(l.strip().startswith(f'bỏ qua  {name} ') and why in l for l in o.splitlines()), (name, why, o)
assert not os.path.exists(os.path.join(ws, 'THU_MAU_2'))                                                                    # dry-run không tạo gì
r = run('scan', d2); C2 = os.path.join(ws, 'THU_MAU_2'); assert r.returncode == 0 and 'Traceback' not in r.stderr, (r.stdout[-400:], r.stderr[-400:])
assert case.sources(C2) == ['agent_a.bin', 'helper_b.bin'] and ck(C2)['C12'] == 'missing' and sorted(os.listdir(os.path.join(C2, 'work', 'sample'))) == ['agent_a.bin', 'helper_b.bin']
ev = set(os.listdir(os.path.join(C2, 'report', 'evidence')))
assert {'quick_agent_a_bin.txt', 'quick_helper_b_bin.txt', 'link_samples.txt'} <= ev, ev                                    # lượt đọc nhanh và đối chiếu chéo
assert 'xref agent_a.bin: bỏ qua' in r.stdout and 'syscalls agent_a.bin: bỏ qua' in r.stdout and 'link -> ' in r.stdout     # không phải ELF: nói rõ bỏ qua, không sập
assert 'C12 Quan hệ giữa các mẫu' in r.stdout and 'BƯỚC KẾ' in r.stdout and 'relation' in r.stdout
assert not any(f['kind'] == 'relation' for f in case.load(C2).values())                                                     # scan không tự ghi kết luận
r = run('scan', d2); assert r.returncode == 0 and 'đã có: không tạo lại' in r.stdout and case.sources(C2) == ['agent_a.bin', 'helper_b.bin'], r.stdout[-300:]   # chạy lại: chỉ in trạng thái
# --- thư mục một mẫu: case một mẫu, C12 không áp dụng, không có link; đặt tên case tùy chọn
d1 = os.path.join(base, 'mot'); os.makedirs(d1); open(os.path.join(d1, 'solo.bin'), 'wb').write(A)
r = run('scan', d1, 'RIENG'); C1 = os.path.join(ws, 'RIENG'); assert r.returncode == 0, r.stderr[-300:]
assert case.sources(C1) == ['solo.bin'] and ck(C1)['C12'].startswith('n/a') and 'link_samples.txt' not in os.listdir(os.path.join(C1, 'report', 'evidence')) and 'link' not in r.stdout.split('== lượt đọc nhanh')[1].split('== bảng việc')[0]
# --- thư mục con là một mẫu dạng thư mục; thư mục rỗng bị bỏ
dd = os.path.join(base, 'cay'); os.makedirs(os.path.join(dd, 'app', 'sub')); os.makedirs(os.path.join(dd, 'rong'))
open(os.path.join(dd, 'app', 'a.js'), 'w').write('console.log(1)\n'); open(os.path.join(dd, 'app', 'sub', 'b.js'), 'w').write('console.log(2)\n'); open(os.path.join(dd, 'drop.bin'), 'wb').write(B)
r = run('scan', dd); CD = os.path.join(ws, 'CAY'); assert r.returncode == 0 and case.sources(CD) == ['app/', 'drop.bin'] and 'bỏ qua  rong/ (thư mục rỗng)' in r.stdout, (r.stdout[-400:], r.stderr[-300:])
# --- quá 8 mẫu: dừng, không tạo case; thư mục không có mẫu; chạy từ chính thư mục thu mẫu; thiếu tham số
dm = os.path.join(base, 'nhieu'); os.makedirs(dm)
for i in range(9): open(os.path.join(dm, f's{i}.bin'), 'wb').write(A + bytes([i]))
r = run('scan', dm); assert r.returncode != 0 and 'vượt giới hạn 8' in (r.stdout + r.stderr) and not os.path.exists(os.path.join(ws, 'NHIEU')) and 'Traceback' not in r.stderr
de = os.path.join(base, 'trong'); os.makedirs(de); open(os.path.join(de, '.x'), 'w').write('x')
r = run('scan', de); assert r.returncode != 0 and 'không có mẫu nào' in (r.stdout + r.stderr) and not os.path.exists(os.path.join(ws, 'TRONG'))
r = run('scan', '.', cwd=d1); assert r.returncode != 0 and 'NGOÀI thư mục thu mẫu' in (r.stdout + r.stderr)
r = run('scan'); assert r.returncode != 0 and 'dùng: flow.py scan' in (r.stdout + r.stderr)
r = run('scan', os.path.join(base, 'khong_co')); assert r.returncode != 0 and 'không thấy thư mục' in (r.stdout + r.stderr)
print('OK check_scan')
