#!/usr/bin/env python3
# Case nhiều mẫu: work/sources.json, mục checklist C12 "Quan hệ giữa các mẫu", `flow.py link`, fact kind=relation, mục báo cáo bắt buộc. Dữ liệu tổng hợp. Chạy: python3 tests/check_relation.py
import os, sys, json, tempfile, subprocess
T = os.path.dirname(os.path.dirname(os.path.abspath(__file__))); sys.path.insert(0, T)
import case, review   # noqa: E402
ws = tempfile.mkdtemp(prefix='rea-rel-')
open(os.path.join(ws, 'agent_a.bin'), 'wb').write(b'\x01\x02' + b'\0'.join([b'-key=KEY', b'http://c2.example.net/x', b'/opt/agent/helper.conf', b'start helper_b now', b'only-in-a-string']) + b'\0')
open(os.path.join(ws, 'helper_b.bin'), 'wb').write(b'\x03\x04' + b'\0'.join([b'-mode=MODE', b'c2.example.net', b'/opt/agent/helper.conf', b'/etc/hosts', b'only-in-b-string']) + b'\0')
open(os.path.join(ws, 'solo.bin'), 'wb').write(b'\x05\x06plain sample text\0')
run = lambda *a: subprocess.run([sys.executable, os.path.join(T, a[0]), *a[1:]], cwd=ws, capture_output=True, text=True)
R1 = os.path.join(ws, 'R1')
r = run('flow.py', 'new', 'R1', 'agent_a.bin', 'helper_b.bin'); assert r.returncode == 0, r.stderr[-400:]
assert case.sources(R1) == ['agent_a.bin', 'helper_b.bin'] and 'relation' in case.KINDS and 'relation' in review.GATING
ck = lambda c: {k.split()[0]: v for k, v, _ in case.check(c)}
assert ck(R1)['C12'] == 'missing'
r = run('flow.py', 'next', 'R1'); assert 'C12' in r.stdout and 'flow.py link R1' in r.stdout, r.stdout[-500:]
assert case.add_sources(R1, ['agent_a.bin']) == ['agent_a.bin', 'helper_b.bin'] and case.sources(R1) == ['agent_a.bin', 'helper_b.bin']   # ghi lại tên đã có không nhân đôi
r = run('flow.py', 'link', 'R1'); ev = os.path.join(R1, 'report', 'evidence', 'link_samples.txt')
assert r.returncode == 0 and 'Traceback' not in r.stderr and os.path.isfile(ev) and 'kind=relation' in r.stdout, (r.stdout[-300:], r.stderr[-300:])
tx = open(ev, encoding='utf-8').read(); L = tx.splitlines()
la = [l for l in L if l.startswith('helper_b.bin chứa định danh của agent_a.bin')][0]; lb = [l for l in L if l.startswith('agent_a.bin chứa định danh của helper_b.bin')][0]
assert '"c2.example.net" 1 lần' in la and '"/opt/agent/helper.conf" 1 lần' in la and '"helper_b" 1 lần' in lb, (la, lb)   # định danh chéo: host, đường dẫn riêng, tên mẫu
assert '"/etc/hosts"' not in lb and 'only-in-a-string' not in tx   # đường dẫn phổ biến và chuỗi thường không được coi là định danh
cm = tx.split('## Chuỗi chung đáng chú ý')[1]; assert '/opt/agent/helper.conf  [agent_a.bin, helper_b.bin]' in cm and '/etc/hosts' not in cm, cm
assert 'KHÔNG loại trừ' in tx and '## Thời điểm tệp' in tx and 'chênh lệch mtime' in tx
ln = next(i for i, l in enumerate(L, 1) if l.startswith('helper_b.bin chứa định danh'))
add = lambda **kw: run('case.py', 'add', 'R1', *[f'{k}={v}' for k, v in kw.items()])
r = add(id='l.h', kind='relation', value='agent_a.bin khởi chạy helper_b.bin (chuỗi start helper_b)', src='S', evidence=f'report/evidence/link_samples.txt#L{ln}', status='hypothesis')
assert r.returncode == 0 and ck(R1)['C12'] == 'partial', r.stdout   # chỉ có giả thuyết: chưa đủ
r = add(id='l.one', kind='relation', value='helper_b.bin dùng chung cấu hình', src='S', evidence=f'report/evidence/link_samples.txt#L{ln}')
assert 'relation_samples' in r.stdout, r.stdout   # chỉ nêu một mẫu: cảnh báo
r = add(id='l.ok', kind='relation', value='agent_a.bin và helper_b.bin cùng dùng /opt/agent/helper.conf và host c2.example.net', src='S', evidence=f'report/evidence/link_samples.txt#L{ln}')
assert 'relation_samples' not in r.stdout and ck(R1)['C12'] == 'ok', r.stdout
# báo cáo: case nhiều mẫu phải có mục 'Quan hệ giữa các mẫu'
assert 'Quan hệ giữa các mẫu' in review.report_relation(R1)
rp = case.report_md(R1); open(rp, 'a', encoding='utf-8').write('\n### 4.3 Quan hệ giữa các mẫu\n\n| Nhận định | Trạng thái | Căn cứ |\n|---|---|---|\n')
assert review.report_relation(R1) == ''
# một mẫu: C12 không áp dụng, link từ chối; case cũ không có sources.json: không áp dụng; n/a có lý do được chấp nhận
assert run('flow.py', 'new', 'R2', 'solo.bin').returncode == 0 and ck(os.path.join(ws, 'R2'))['C12'].startswith('n/a') and review.report_relation(os.path.join(ws, 'R2')) == ''
r = run('flow.py', 'link', 'R2'); assert r.returncode != 0 and 'cần từ hai mẫu' in (r.stdout + r.stderr) and 'Traceback' not in r.stderr
assert run('flow.py', 'new', 'R3', 'agent_a.bin', 'solo.bin').returncode == 0
r = run('case.py', 'add', 'R3', 'id=l.na', 'kind=relation', 'value=n/a: không thấy liên hệ giữa agent_a.bin và solo.bin (không có định danh chéo)', 'src=S', 'evidence=report/evidence/triage_solo_bin.json')
assert ck(os.path.join(ws, 'R3'))['C12'] == 'ok', r.stdout
os.remove(os.path.join(R1, 'work', 'sources.json')); assert case.sources(R1) == [] and ck(R1)['C12'].startswith('n/a')
json.dump({'x': 1}, open(os.path.join(R1, 'work', 'sources.json'), 'w')); assert case.sources(R1) == []   # file hỏng dạng: coi như không có
# --- zip chứa hai mẫu: sources ghi tên tệp đã giải nén (không phải tên zip), C12 bắt buộc, link chạy được
import zipfile, hashlib, shutil
A_, B_ = open(os.path.join(ws, 'agent_a.bin'), 'rb').read(), open(os.path.join(ws, 'helper_b.bin'), 'rb').read()
with zipfile.ZipFile(os.path.join(ws, 'bo_mau.zip'), 'w') as z: z.writestr('m1.bin', A_); z.writestr('m2.bin', B_)
if shutil.which('7z') or shutil.which('7zz') or shutil.which('7za'):
    r = run('flow.py', 'new', 'Z1', 'bo_mau.zip'); Z1 = os.path.join(ws, 'Z1'); assert r.returncode == 0, r.stderr[-300:]
    assert case.sources(Z1) == ['m1.bin', 'm2.bin'] and ck(Z1)['C12'] == 'missing', case.sources(Z1)
    r = run('flow.py', 'link', 'Z1'); assert r.returncode == 0 and 'm2.bin chứa định danh của m1.bin' in open(os.path.join(Z1, 'report', 'evidence', 'link_samples.txt'), encoding='utf-8').read(), r.stderr[-300:]
else: assert not os.environ.get('CI'), 'CI phải có 7z'
# --- tên mẫu dài 64 hex (triage cắt tên evidence còn 32 ký tự): link tìm triage theo sha256, không đoán tên; thiếu triage thì nói rõ, không khẳng định "cùng kiến trúc"
h1, h2 = hashlib.sha256(A_).hexdigest(), hashlib.sha256(B_).hexdigest()
open(os.path.join(ws, h1), 'wb').write(A_); open(os.path.join(ws, h2), 'wb').write(B_)
assert run('flow.py', 'new', 'H1', h1, h2).returncode == 0; H1 = os.path.join(ws, 'H1')
assert run('flow.py', 'link', 'H1').returncode == 0; th = open(os.path.join(H1, 'report', 'evidence', 'link_samples.txt'), encoding='utf-8').read()
assert 'không rõ' not in th and 'thiếu triage' not in th and ('cùng định dạng và kiến trúc: ' in th or 'khác định dạng/kiến trúc: ' in th), th
for f in os.listdir(os.path.join(H1, 'report', 'evidence')):
    if f.startswith('triage_'): os.remove(os.path.join(H1, 'report', 'evidence', f))
assert run('flow.py', 'link', 'H1').returncode == 0; th = open(os.path.join(H1, 'report', 'evidence', 'link_samples.txt'), encoding='utf-8').read()
assert 'không rõ (thiếu triage' in th and 'không so được' in th and 'cùng định dạng và kiến trúc' not in th, th
# --- tên không phải Latin: không sinh mẫu tìm kiếm rỗng (đếm hàng triệu lần)
open(os.path.join(ws, '样本一二.bin'), 'wb').write(A_ + b'x'); open(os.path.join(ws, 'mẫu_hai.bin'), 'wb').write(B_ + b'y')
assert run('flow.py', 'new', 'U1', '样本一二.bin', 'mẫu_hai.bin').returncode == 0 and run('flow.py', 'link', 'U1').returncode == 0
tu = open(os.path.join(ws, 'U1', 'report', 'evidence', 'link_samples.txt'), encoding='utf-8').read(); import re
assert all(int(n) < 50 for n in re.findall(r'" (\d+) lần', tu)) and '"样本一二"' not in tu.split('## Định danh')[1].split('(đã thử')[0], tu
# --- case cũ chưa có sources.json: thêm mẫu thứ hai thì tính cả mẫu đã có; mẫu dạng thư mục được ghi là một mẫu và link bỏ qua có thông báo
assert run('flow.py', 'new', 'O1', 'solo.bin').returncode == 0; O1 = os.path.join(ws, 'O1'); os.remove(os.path.join(O1, 'work', 'sources.json'))
assert run('flow.py', 'new', 'O1', 'agent_a.bin').returncode == 0 and case.sources(O1) == ['solo.bin', 'agent_a.bin'] and ck(O1)['C12'] == 'missing', case.sources(O1)
os.makedirs(os.path.join(ws, 'appdir')); open(os.path.join(ws, 'appdir', 'x.js'), 'w').write('console.log(1)\n')
assert run('flow.py', 'new', 'D1', 'appdir', 'agent_a.bin', 'helper_b.bin').returncode == 0; D1 = os.path.join(ws, 'D1')
assert case.sources(D1) == ['appdir/', 'agent_a.bin', 'helper_b.bin'], case.sources(D1)
assert run('flow.py', 'link', 'D1').returncode == 0 and 'bỏ qua, không đối chiếu: appdir/ (mẫu dạng thư mục)' in open(os.path.join(D1, 'report', 'evidence', 'link_samples.txt'), encoding='utf-8').read()
r = run('case.py', 'add', 'D1', 'id=l.d', 'kind=relation', 'value=appdir nạp agent_a.bin', 'src=S', 'evidence=report/evidence/link_samples.txt'); assert 'relation_samples' not in r.stdout, r.stdout   # tên thư mục cũng tính là tên mẫu
# --- "một mẫu" = một mục ở gốc work/sample: zip chứa cây thư mục là MỘT mẫu (C12 không áp dụng); zip có cả thư mục lẫn tệp phẳng thì mỗi mục gốc một mẫu
if shutil.which('7z') or shutil.which('7zz') or shutil.which('7za'):
    with zipfile.ZipFile(os.path.join(ws, 'app.zip'), 'w') as z: z.writestr('app/a.js', 'console.log(1)\n'); z.writestr('app/sub/b.js', 'console.log(2)\n'); z.writestr('app/package.json', '{}\n')
    assert run('flow.py', 'new', 'T1', 'app.zip').returncode == 0; T1 = os.path.join(ws, 'T1')
    assert case.sources(T1) == ['app/'] and ck(T1)['C12'].startswith('n/a') and review.report_relation(T1) == '', (case.sources(T1), ck(T1)['C12'])
    with zipfile.ZipFile(os.path.join(ws, 'mix.zip'), 'w') as z: z.writestr('tool/x.js', '1\n'); z.writestr('tool/y.js', '2\n'); z.writestr('drop.bin', A_)
    assert run('flow.py', 'new', 'T2', 'mix.zip').returncode == 0 and case.sources(os.path.join(ws, 'T2')) == ['drop.bin', 'tool/'], case.sources(os.path.join(ws, 'T2'))
# --- case cũ có mẫu dạng thư mục, chưa có sources.json: khi thêm mẫu, thư mục đã có vẫn là MỘT mẫu (không đếm từng tệp bên trong)
os.makedirs(os.path.join(ws, 'bigapp', 'sub')); [open(os.path.join(ws, 'bigapp', n), 'w').write(f'{n}\n') for n in ('a.js', 'b.js', os.path.join('sub', 'c.js'))]
assert run('flow.py', 'new', 'G1', 'bigapp').returncode == 0; G1 = os.path.join(ws, 'G1'); assert case.sources(G1) == ['bigapp/']
os.remove(os.path.join(G1, 'work', 'sources.json'))
r = run('flow.py', 'new', 'G1', 'solo.bin'); assert r.returncode == 0 and case.sources(G1) == ['bigapp/', 'solo.bin'] and ck(G1)['C12'] == 'missing', case.sources(G1)   # thêm mẫu thứ hai thật: C12 bật
print('OK check_relation')
