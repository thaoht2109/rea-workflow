#!/usr/bin/env python3
"""flow.py export / export.py trên case tổng hợp: mẫu, file giải nén, payload, bản dump không header, snapshot giả lập vào 7z (không chép
dạng rõ); bỏ .claude/, work/ghidra/; MANIFEST, README dòng đầu có sha256; không xóa thư mục lạ; thông tin mẫu, ghi chú thu mẫu (escape),
bản trùng hash; liên kết báo cáo trỏ vào bản chép. 7z giả (ghi danh sách file) thay cho 7z thật. Chạy: python3 tests/check_export.py"""
import os, sys, json, shutil, hashlib, tempfile, subprocess
SKILL = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
T = tempfile.mkdtemp(prefix='rea-export-')
FAKE7Z = os.path.join(T, 'fake7z'); LIST = os.path.join(T, 'packed.json')
open(FAKE7Z, 'w').write('#!/usr/bin/env python3\nimport sys, json\na = sys.argv[1:]; i = a.index("--")\n'
                        f'json.dump(a[i + 1:], open({LIST!r}, "w")); open(a[i - 1], "wb").write(b"7z\\xbc\\xaf\\x27\\x1c")\n')
os.chmod(FAKE7Z, 0o700); os.environ['SEVENZ_BIN'] = FAKE7Z
sys.path.insert(0, SKILL)
import export  # noqa: E402

def w(p, b):
    os.makedirs(os.path.dirname(p), exist_ok=True); open(p, 'wb').write(b if isinstance(b, bytes) else b.encode()); return p
try:
    inbox = os.path.join(T, 'IN'); smp = b'\x7fELF' + b'\x02' * 60; h = hashlib.sha256(smp).hexdigest()
    src = w(os.path.join(inbox, 'U1', 'a', 'x.bin'), smp); dup = w(os.path.join(inbox, 'U2', 'y.bin'), smp)
    note = w(os.path.join(inbox, 'U1', 'a', 'x.txt'), '# host=m1 ip=10.0.0.9 at=2026-01-01\n$ ls -la /usr/lib/x\n' + h + '  /usr/lib/x\n<script>alert(1)</script>\n')
    sums = w(os.path.join(inbox, 'U1', 'a', 'SHA256SUMS'), h + '  x.bin\n' + '0' * 64 + '  other\n')
    c = os.path.join(T, 'ws', 'x_' + h[:8])
    w(os.path.join(c, 'work', 'sample', 'x.bin'), smp)
    w(os.path.join(c, 'work', 'extract', 'stage2.ps1'), 'IEX (New-Object Net.WebClient)\n')   # script giải nén: gói theo vị trí
    w(os.path.join(c, 'work', 'runs', 'emu', 'snap_oep.bin'), b'\x80\x04\x95' + b'\0' * 40)   # snapshot giả lập (pickle): nhị phân
    w(os.path.join(c, 'work', 'stage1.bin'), b'\0\0\0\0' + b'\x90' * 50)                      # dump bộ nhớ không header
    w(os.path.join(c, 'work', 'runs', 'triage.txt'), 'triage ok\n')
    w(os.path.join(c, 'work', 'ghidra', 'p.gpr'), 'ghidra'); w(os.path.join(c, 'work', 'scripts', '.claude', 'x.json'), '{}')
    w(os.path.join(c, 'work', '.watch.lock'), '')
    w(os.path.join(c, 'facts.jsonl'), json.dumps({'id': 's.ft', 'kind': 'filetype', 'value': 'ELF x86-64', 'src': 'S', 'evidence': 'report/evidence/e.txt#L1',
                                                  'status': 'active', 'verified_by': '', 'supersedes': '', 'stage': '', 'note': '', 'ts': '2026-01-01T00:00:00'}) + '\n')
    w(os.path.join(c, 'report', 'evidence', 'e.txt'), 'ELF x86-64\n')
    w(os.path.join(c, 'report', 'report-2026-01-01.md'), '# Báo cáo\n\n## 1. Tóm tắt\n\nXem [e](evidence/e.txt#L1), [mẫu](../work/sample/x.bin), [web](https://x.test/a).\n')
    w(os.path.join(c, 'report', 'report-2026-01-01.html'), '<html><style>x{}</style><nav><div class="t">B</div></nav><main><section><a href="evidence/e.txt#L1">e</a></section></main></html>')
    st = {'source': src, 'inbox': inbox, 'sha256': h}
    out = os.path.join(T, 'Report'); d = os.path.join(out, 'x.bin_data')
    info = export.write(c, st, d)
    assert info['aliases'] == [dup] and [n['file'] for n in info['notes']] == [note] and info['sums'][0][1] == [h + '  x.bin'], info
    assert info['ftype'] == 'ELF x86-64' and info['notes'][0]['sha'] == 'khớp' and info['notes'][0]['path'] == '/usr/lib/x', info['notes']
    P = sorted(json.load(open(LIST)))
    assert P == sorted(['work/sample/x.bin', 'work/extract/stage2.ps1', 'work/runs/emu/snap_oep.bin', 'work/stage1.bin']), P
    files = sorted(os.path.relpath(os.path.join(dp, n), d) for dp, _, ns in os.walk(d) for n in ns)
    assert not any(f.startswith(('work/sample', 'work/extract', 'work/ghidra')) or '.claude' in f or f.endswith(('snap_oep.bin', 'stage1.bin', '.watch.lock')) for f in files), files
    assert {'work/runs/triage.txt', 'facts.jsonl', 'report/evidence/e.txt', 'x.bin.md', 'x.bin.html', 'README.txt', 'MANIFEST.sha256', export.ZIP,
            'ghi_chu_thu_mau/x.txt', 'ghi_chu_thu_mau/SHA256SUMS'} <= set(files), files
    first = open(os.path.join(d, 'README.txt'), encoding='utf-8').readline(); assert f'(sha256 {h})' in first and export.ours(d), first
    man = open(os.path.join(d, 'MANIFEST.sha256'), encoding='utf-8').read(); assert f'{h}  {export.ZIP}:work/sample/x.bin' in man, man
    md = open(os.path.join(d, 'x.bin.md'), encoding='utf-8').read()
    assert md.index('## Thông tin mẫu') < md.index('## 1. Tóm tắt') and '(report/evidence/e.txt#L1)' in md and f'({export.ZIP})' in md and '(https://x.test/a)' in md, md
    assert 'U2/y.bin' in md and 'host=m1' in md, md
    ht = open(os.path.join(d, 'x.bin.html'), encoding='utf-8').read()
    assert 'id="thong-tin-mau"' in ht and 'href="report/evidence/e.txt#L1"' in ht and '&lt;script&gt;' in ht and '<script>alert' not in ht and 'href="#thong-tin-mau"' in ht, ht
    import watch  # noqa: E402  reported() đọc dòng đầu README.txt do export ghi
    assert watch.reported(out) == {h}
    # xuất lại: làm mới thư mục của mình; thư mục lạ trùng tên thì không xóa
    export.write(c, st, d); assert export.ours(d)
    lạ = os.path.join(out, 'z_data'); w(os.path.join(lạ, 'README.txt'), 'của người dùng\n')
    try: export.export(info, lạ); raise AssertionError('xóa thư mục lạ')
    except OSError as x: assert 'không do export sinh' in str(x) and os.path.exists(os.path.join(lạ, 'README.txt'))
    # flow.py export CASE OUT (case không do watch nhận: lấy mẫu trong work/sample)
    r = subprocess.run([sys.executable, os.path.join(SKILL, 'flow.py'), 'export', c, os.path.join(T, 'manual')], capture_output=True, text=True, env=dict(os.environ))
    assert r.returncode == 0 and os.path.isfile(os.path.join(T, 'manual', 'x.bin_data', 'x.bin.html')), r.stdout + r.stderr
    # 7z không chạy được: lỗi rõ, không im lặng chép mẫu dạng rõ
    os.environ['SEVENZ_BIN'] = os.path.join(T, 'khong-co-7z')
    r = subprocess.run([sys.executable, os.path.join(SKILL, 'flow.py'), 'export', c, os.path.join(T, 'no7z')], capture_output=True, text=True, env=dict(os.environ))
    assert r.returncode == 1 and '7z' in r.stdout and not os.path.exists(os.path.join(T, 'no7z', 'x.bin_data')), r.stdout + r.stderr   # không để lại thư mục dở
    os.environ['SEVENZ_BIN'] = FAKE7Z   # chạy lại sau lỗi: thư mục dở .part được dọn, xuất bình thường
    r = subprocess.run([sys.executable, os.path.join(SKILL, 'flow.py'), 'export', c, os.path.join(T, 'no7z')], capture_output=True, text=True, env=dict(os.environ))
    assert r.returncode == 0 and export.ours(os.path.join(T, 'no7z', 'x.bin_data')) and os.listdir(os.path.join(T, 'no7z')) == ['x.bin_data'], r.stdout + str(os.listdir(os.path.join(T, 'no7z')))
finally: shutil.rmtree(T, ignore_errors=True)
print('OK check_export')
