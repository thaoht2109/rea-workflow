#!/usr/bin/env python3
"""Test flow.py new: ZIP là chính mẫu (APK, OOXML, JAR) được giữ nguyên, không giải nén; triage định tuyến đúng. Dữ liệu tổng hợp.
Chạy: python3 tests/check_zip_sample.py"""
import os, sys, json, tempfile, shutil, subprocess, zipfile

SKILL = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), '..'))
d = tempfile.mkdtemp(prefix='rea-zip-')
try:
    def mk(name, files):
        p = os.path.join(d, name)
        with zipfile.ZipFile(p, 'w') as z:
            for n in files: z.writestr(n, 'x')
        return p
    apk = mk('a.apk', ['AndroidManifest.xml', 'classes.dex'])
    doc = mk('b.docx', ['[Content_Types].xml', 'word/document.xml'])
    jar = mk('c.jar', ['META-INF/MANIFEST.MF', 'x.class'])
    sys.path.insert(0, os.path.join(SKILL, 'static')); import triage as T
    assert (T.zip_kind(apk), T.zip_kind(doc), T.zip_kind(jar)) == ('APK', 'Office OOXML', 'JAR')
    assert T.zip_kind(mk('plain.zip', ['readme.txt', 'payload.bin'])) is None and T.zip_kind(os.path.join(d, 'nope')) is None
    c = os.path.join(d, 'CASE')
    r = subprocess.run([sys.executable, os.path.join(SKILL, 'flow.py'), 'new', c, apk, doc, jar], capture_output=True, text=True, cwd=d)
    assert r.returncode == 0, (r.stdout + r.stderr)[-1500:]
    assert sorted(os.listdir(os.path.join(c, 'work', 'sample'))) == ['a.apk', 'b.docx', 'c.jar'], os.listdir(os.path.join(c, 'work', 'sample'))
    assert all(f'{k} (không giải nén)' in r.stdout for k in ('APK', 'Office OOXML', 'JAR')), r.stdout
    R = json.load(open(os.path.join(c, 'work', 'runs', 'triage_a_apk', 'triage.json')))
    assert R['zip_kind'] == 'APK' and 'inspect-android-package' in r.stdout, r.stdout
    print('ok')
finally:
    shutil.rmtree(d, ignore_errors=True)
