#!/usr/bin/env python3
"""Test install_tools: không --yes thì chỉ in kế hoạch, không chạy gì; cài Ghidra kiểm sha256, giữ quyền thực thi, ghi rea.env.
Chạy: python3 tests/check_install_tools.py"""
import os, sys, io, json, shutil, hashlib, zipfile, tempfile, contextlib, subprocess, urllib.request

SKILL = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), '..'))
sys.path.insert(0, SKILL); import install_tools as I

t = tempfile.mkdtemp(prefix='rea-inst-')
try:
    # 1. máy thiếu hết: in kế hoạch, mã 1, không gọi subprocess nào
    I.checks = lambda: [(n, False, r, apt, pip, step, 'x') for n, r, apt, pip, step in (
        ('7z', True, ['7zip'], None, None), ('python: unicorn 2.1.4', False, [], 'unicorn==2.1.4', None),
        ('Ghidra', False, [], None, 'ghidra'), ('rea', False, [], None, 'rea'))]
    called = []; real = subprocess.run; subprocess.run = lambda *a, **k: called.append(a) or real(['true'])
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf): rc = I.main([])
    subprocess.run = real; o = buf.getvalue()
    assert rc == 1 and not called and 'THIẾU 7z' in o and 'unicorn==2.1.4' in o and 'Ghidra' in o and 'Chưa cài gì' in o, o
    with contextlib.redirect_stdout(io.StringIO()) as b2: I.main(['--no-ghidra'])
    assert 'tải Ghidra' not in b2.getvalue()
    # 2. cài Ghidra: zip giả có file thực thi; sha256 khớp -> giải nén, chmod, ghi rea.env; sai -> dừng, xoá file tải
    src = os.path.join(t, 'g.zip')
    with zipfile.ZipFile(src, 'w') as z:
        i = zipfile.ZipInfo('ghidra_x/support/analyzeHeadless'); i.external_attr = 0o755 << 16; z.writestr(i, '#!/bin/sh\n')
        z.writestr('ghidra_x/README', 'x')
    dig = hashlib.sha256(open(src, 'rb').read()).hexdigest()
    rel = lambda d: io.BytesIO(json.dumps({'assets': [{'name': 'g.zip', 'size': 1, 'digest': 'sha256:' + d, 'browser_download_url': 'x'}]}).encode())
    I.SHARE, I.CFG.FILE = os.path.join(t, 'share'), os.path.join(t, 'rea.env')
    urllib.request.urlretrieve = lambda u, p: shutil.copy(src, p)
    urllib.request.urlopen = lambda u, timeout=0: rel(dig)
    with contextlib.redirect_stdout(io.StringIO()): gd = I.ghidra_install()
    assert os.access(os.path.join(gd, 'support', 'analyzeHeadless'), os.X_OK) and f'GHIDRA_INSTALL_DIR={gd}' in open(I.CFG.FILE).read()
    assert not os.path.exists(os.path.join(I.SHARE, 'g.zip'))
    urllib.request.urlopen = lambda u, timeout=0: rel('0' * 64)
    try:
        with contextlib.redirect_stdout(io.StringIO()): I.ghidra_install(); raise AssertionError('phải từ chối sha256 sai')
    except SystemExit as e: assert 'không khớp' in str(e) and not os.path.exists(os.path.join(I.SHARE, 'g.zip'))
    print('OK test_install_tools')
finally: shutil.rmtree(t, ignore_errors=True)
