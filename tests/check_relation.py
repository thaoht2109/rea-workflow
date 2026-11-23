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
print('OK check_relation')
