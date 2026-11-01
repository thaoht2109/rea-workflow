#!/usr/bin/env python3
# T0 triage tĩnh cho mọi file mẫu (tools/FLOW.md bước 2): PE, ELF, Go, .NET, UPX, NSIS, script, archive, Office/PDF.
# In tóm tắt ≤ 60 dòng + dòng next: (bước kế tiếp), ghi OUT/triage.json; dữ liệu đầy đủ nằm trong OUT/. Không thực thi mẫu:
# chỉ đọc byte, pefile, readelf, `go version -m` (đọc buildinfo), 7z (giải nén).
#   python3 -I triage.py FILE --out OUTDIR [--facts CASE]
# NSIS: tự dịch header, giải nén file bằng 7z, giải "sàng byte" (đọc 1 byte mỗi bước nhảy, dấu kết thúc chuỗi) để lộ chuỗi
# System::Call, rồi đề xuất --blob/--blob-off cho winemu. Chỉ là heuristic: luôn đối chiếu với nsis_disasm.txt.
import sys, os, re, json, math, struct, shutil, hashlib, argparse, subprocess
from collections import Counter
import pefile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE)); from reacfg import SEVENZ   # cấu hình theo máy: tools/rea.env
NSIS_SIG = b'\xef\xbe\xad\xdeNullsoftInst'

def entropy(b):
    if not b: return 0.0
    n = len(b); return round(-sum(c / n * math.log2(c / n) for c in Counter(b).values()), 2)

def strings(d, n=6):
    a = [m.decode() for m in re.findall(rb'[\x20-\x7e]{%d,}' % n, d)]
    u = [m.decode('utf-16le') for m in re.findall(rb'(?:[\x20-\x7e]\x00){%d,}' % n, d)]
    hot = re.compile(r'https?://|\\\\|[A-Za-z]:\\|\.(dll|exe|ps1|vbs|bat)\b|HKEY_|Software\\|::|%[a-z]+%', re.I)
    seen, out = set(), []
    for s in sorted(a + u, key=lambda s: (not hot.search(s), -len(s))):
        if s not in seen and len(set(s)) > 3: seen.add(s); out.append(s)
    return out

def sieve(disasm):
    """Ứng viên (A, B, sep): biến được cộng hằng A rồi cộng bước B, ngay sau đó StrCmp với một ký tự kết thúc."""
    adds, out = {}, []
    for m in re.finditer(r"IntOp (\$\S+) = '\1' \+ '(\d+)'", disasm): adds.setdefault(m.group(1), []).append((m.start(), int(m.group(2))))
    for v, xs in adds.items():
        for (_, a), (pos, b) in zip(xs, xs[1:]):
            m = re.search(r"StrCmp '\$\S+' '(.)' eq=", disasm[pos:pos + 400])
            if m and b > 1: out.append((a, b, m.group(1)))
    return out

def sieve_decode(d, a, b, sep):
    return [s for s in bytes(d[a::b]).decode('latin1').split(sep) if s.strip()]

def nsis(path, out, R):
    hdr, dis = os.path.join(out, 'nsis_hdr.bin'), os.path.join(out, 'nsis_disasm.txt')
    subprocess.run([sys.executable, '-I', os.path.join(HERE, 'nsis', 'nsis_hdr.py'), path, hdr], check=True, capture_output=True)
    with open(dis, 'w') as f: subprocess.run([sys.executable, '-I', os.path.join(HERE, 'nsis', 'nsis_dis.py'), hdr], check=True, stdout=f)
    fd = os.path.join(out, 'files'); shutil.rmtree(fd, ignore_errors=True)
    subprocess.run([SEVENZ, 'x', '-y', f'-o{fd}', path], check=True, capture_output=True)   # chỉ giải nén, không chạy gì
    files = []
    for d_, _, ns in os.walk(fd):
        for n in ns:
            p = os.path.join(d_, n); b = open(p, 'rb').read()
            files.append({'path': os.path.relpath(p, out), 'name': n, 'size': len(b), 'entropy': entropy(b)})
    txt = open(dis).read()
    R['nsis'] = {'files': files, 'system_plugin': 'System.dll' in txt, 'disasm': 'nsis_disasm.txt'}
    best = (0, None, [], None)
    for a, b, sep in sieve(txt):
        for f in files:
            dec = sieve_decode(open(os.path.join(out, f['path']), 'rb').read(), a, b, sep)
            score = sum('::' in s for s in dec)
            if score > best[0]: best = (score, f['name'], dec, (a, b, sep))
    if not best[1]: return
    a, b, sep = best[3]
    calls = [s for s in best[2] if '::' in s]
    open(os.path.join(out, 'nsis_syscalls.txt'), 'w').write('\n'.join(calls) + '\n')
    R['nsis']['sieve'] = {'file': best[1], 'start': a, 'step': b, 'sep': sep, 'calls': len(calls), 'out': 'nsis_syscalls.txt'}
    m = re.search(r'SetFilePointer\(\s*i\s*\S+\s*,\s*i\s*(\d+)', '\n'.join(calls))
    cand = [f for f in files if f['name'] != best[1] and not f['name'].lower().endswith('.dll')
            and re.search(r"(StrCpy|Push) [^\n]*" + re.escape(f['name']), txt)]
    cand = cand or [f for f in files if f['name'] != best[1] and not f['name'].lower().endswith('.dll')]
    if m and cand:
        blob = max(cand, key=lambda f: (f['entropy'], f['size']))
        va = re.search(r'VirtualAlloc\(\s*i\s*0\s*,\s*i\s*(\d+)', '\n'.join(calls))
        R['nsis']['shellcode'] = {'file': blob['path'], 'offset': int(m.group(1)), 'alloc': int(va.group(1)) if va else None,
                                  'callback': 'EnumWindows' if any('EnumWindows' in s for s in calls) else None}

ELF_MACH = {2: 'SPARC', 3: 'x86', 8: 'MIPS', 20: 'PPC', 21: 'PPC64', 40: 'ARM', 62: 'x86_64', 183: 'AArch64', 243: 'RISC-V'}
MAGIC = [(b'\x7fELF', 'ELF'), (b'MZ', 'PE'), (b'PK\x03\x04', 'zip'), (b'7z\xbc\xaf\x27\x1c', '7z'), (b'Rar!', 'rar'),
         (b'\x1f\x8b', 'gzip'), (b'\xd0\xcf\x11\xe0', 'ole'), (b'%PDF', 'pdf'), (b'dex\n', 'dex')]
IOC_SKIP = ('nsis.sf.net', 'schemas.microsoft.com', 'www.w3.org', 'ocsp.', 'crl.', 'digicert', 'verisign', 'sectigo', 'globalsign',
            'xml.org', 'purl.org', 'go.dev', 'upx.sf.net', 'adobe.com/xap', 'openssl.org', 'gnu.org', 'golang.org', 'github.com/golang')

def run(*a):
    r = subprocess.run(a, capture_output=True, text=True, errors='replace'); return r.stdout if r.returncode == 0 else ''

def pe_info(d, R):
    pe = pefile.PE(data=d, fast_load=True); pe.parse_data_directories()
    R['type'] = 'PE32+' if pe.OPTIONAL_HEADER.Magic == 0x20b else 'PE32'
    R['sections'] = [{'name': s.Name.rstrip(b'\0').decode('latin1'), 'raw': s.SizeOfRawData, 'entropy': entropy(s.get_data())} for s in pe.sections]
    ov = pe.get_overlay_data_start_offset()
    if ov: R['overlay'] = {'offset': ov, 'size': len(d) - ov, 'entropy': entropy(d[ov:])}
    R['imports'] = {e.dll.decode(): len(e.imports) for e in getattr(pe, 'DIRECTORY_ENTRY_IMPORT', [])}
    R['exports'] = [e.name.decode() for e in getattr(getattr(pe, 'DIRECTORY_ENTRY_EXPORT', None), 'symbols', []) if e.name][:30]
    if pe.OPTIONAL_HEADER.DATA_DIRECTORY[14].VirtualAddress: R['flags'].append('.NET')
    if any(s['name'].startswith('UPX') for s in R['sections']): R['flags'].append('UPX')
    if NSIS_SIG in d: R['flags'].append('NSIS')

def elf_info(path, d, R):
    end = '<' if d[5] == 1 else '>'
    etype, mach = struct.unpack(end + 'HH', d[16:20])
    R['type'] = f"ELF{'64' if d[4] == 2 else '32'} {ELF_MACH.get(mach, mach)} {'LE' if end == '<' else 'BE'} " + \
                {1: 'REL', 2: 'EXEC', 3: 'DYN', 4: 'CORE'}.get(etype, '?')
    secs = re.findall(r'\]\s+(\S+)\s+(\S+)\s+[0-9a-f]+\s+([0-9a-f]+)\s+([0-9a-f]+)', run('readelf', '-W', '-S', path))
    R['sections'] = [{'name': n, 'raw': int(sz, 16), 'entropy': 0.0 if ty == 'NOBITS' else entropy(d[int(o, 16):int(o, 16) + int(sz, 16)])}
                     for n, ty, o, sz in secs if n != 'NULL']
    if not R['sections']: R['flags'].append('no-section-header')
    elif not any(s['name'] == '.symtab' for s in R['sections']): R['flags'].append('stripped')
    R['imports'] = {l: 0 for l in re.findall(r'\(NEEDED\)\s+Shared library: \[([^\]]+)\]', run('readelf', '-W', '-d', path))}
    syms = re.findall(r'^\s*\d+:\s+[0-9a-f]+\s+\d+\s+FUNC\s+(GLOBAL|WEAK)\s+\S+\s+(\S+)\s+(\S+)', run('readelf', '-W', '--dyn-syms', path), re.M)
    R['imported_funcs'] = sorted({n.split('@')[0] for _, ndx, n in syms if ndx == 'UND'})
    R['exports'] = sorted({n.split('@')[0] for _, ndx, n in syms if ndx != 'UND'})[:40]
    if 'statically linked' in run('file', '-b', path): R['flags'].append('static')

def iocs(strs):
    url = re.compile(r'(?:https?|ftp|tcp|udp|wss?)://[^\s"\'<>]{4,120}?(?=(?:https?|ftp|wss?)://|[\s"\'<>)]|$)', re.I)
    ip = re.compile(r'(?<![\d.])(?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3}(?::\d{2,5})?(?![\d.])')
    out = [x for s in strs for x in url.findall(s) + [i for i in ip.findall(s) if max(map(int, i.split(':')[0].split('.'))) >= 10]]
    return list(dict.fromkeys(x for x in out if not any(k in x for k in IOC_SKIP) and not x.startswith(('127.', '0.', '255.'))))[:20]

def script_lang(t):
    for lang, rx in [('powershell', r'(?i)invoke-|frombase64string|\$env:|-enc\b'), ('vbscript', r'(?i)createobject\(|wscript\.'),
                     ('javascript', r'(?i)\bfunction\s*\(|eval\(|activexobject'), ('batch', r'(?i)^@echo off|%~dp0'),
                     ('python', r'(?m)^import |^from \S+ import'), ('shell', r'^#!.*\b(ba|z|da)?sh\b|\b(curl|wget|chmod)\b')]:
        if re.search(rx, t): return lang
    return 'text'

def route(R, out):
    f, t, sc = R['flags'], R['type'], R.get('nsis', {}).get('shellcode')
    if sc: return f"T3 winemu --blob {os.path.join(out, sc['file'])} --blob-off {sc['offset']}" + (f" --size {sc['alloc']:#x}" if sc['alloc'] else '') + \
                  f" --prerun --chain-child --exe '{R['path']}' --exe-path 'C:\\Users\\admin\\Downloads\\{R['file']}'"
    if 'NSIS' in f: return 'T1: đọc nsis_disasm.txt + nsis/files/ (chưa tự tìm ra shellcode)'
    if 'UPX' in f: return 'flow.py triage tự upx -d bản sao rồi triage lại (bước 3)'
    if t in ('zip', '7z', 'rar', 'gzip'): return 'flow.py new giải nén vào work/sample/ rồi triage từng file (bước 1)'
    if t in ('ole', 'pdf'): return 'T2: rea inspect-artifact; tìm macro/JS/stream nhúng (olevba/pdf-parser chưa cài)'
    if t == 'dex': return 'T2: rea inspect-android-package / inspect-android-method'
    if t.startswith('script'): return 'T2: khử làm rối script tĩnh (base64/eval/char-code) bằng Python, không chạy script'
    if '.NET' in f: return 'T2: rea inspect-managed-members (chuỗi ldstr, PInvoke) rồi decompile lớp/hàm đáng ngờ'
    if 'Go' in f: return 'T2: rea inspect-go-binary + flow.py dec main.main (và các hàm main.*)'
    hi = R.get('overlay', {}).get('entropy', 0) > 7.5 or any(s['entropy'] > 7.5 and s['raw'] > 4096 for s in R.get('sections', []))
    if t.startswith('PE'):
        return ('T2 tìm stub giải mã (flow.py dec entry) -> T3 winemu nếu là x86-32' if hi else
                'T2: flow.py dec <export/hàm theo import đáng ngờ>')
    if t.startswith('ELF'):
        tgt = ', '.join(e for e in R.get('exports', []) if not e.startswith('_'))[:120] or 'main/entry'
        return ('T2: flow.py dec ' + tgt) + (' | entropy cao: tìm stub giải mã' if hi or 'no-section-header' in f else '') + \
               ' | không có T3 cho ELF trên server (thiếu qemu-user): giải mã bằng tái hiện tĩnh'
    return 'T2: xem strings/hexdump có giới hạn; xác định định dạng thủ công'

def main():
    ap = argparse.ArgumentParser(); ap.add_argument('file'); ap.add_argument('--out', required=True); ap.add_argument('--facts')
    A = ap.parse_args(); os.makedirs(A.out, exist_ok=True)
    d = open(A.file, 'rb').read()
    R = {'file': os.path.basename(A.file), 'path': os.path.abspath(A.file), 'size': len(d), 'md5': hashlib.md5(d).hexdigest(),
         'sha1': hashlib.sha1(d).hexdigest(), 'sha256': hashlib.sha256(d).hexdigest(), 'type': 'unknown', 'flags': []}
    R['type'] = next((t for m, t in MAGIC if d.startswith(m)), 'unknown')
    if R['type'] == 'PE': pe_info(d, R)
    elif R['type'] == 'ELF': elf_info(A.file, d, R)
    elif R['type'] == 'unknown' and d and sum(32 <= b < 127 or b in (9, 10, 13) for b in d[:4096]) / len(d[:4096]) > 0.95:
        R['type'] = 'script/' + script_lang(d[:65536].decode('latin1'))
    if R['type'] in ('PE32', 'PE32+') or R['type'].startswith('ELF'):
        if b'UPX!' in d[:0x1000] or b'UPX!' in d[-0x1000:]: R['flags'].append('UPX') if 'UPX' not in R['flags'] else None
        go = run('go', 'version', '-m', A.file)
        if go: R['flags'].append('Go'); R['go'] = go.splitlines()[:8]
    allstr = strings(d)
    R['strings'] = allstr[:40]; R['ioc_candidates'] = iocs(allstr)
    R['entropy'] = entropy(d)
    if 'NSIS' in R['flags']: nsis(A.file, A.out, R)
    R['next'] = route(R, A.out)
    json.dump(R, open(os.path.join(A.out, 'triage.json'), 'w'), indent=1, ensure_ascii=False)

    sc = R.get('nsis', {}).get('shellcode')
    print(f"{R['file']}  {R['type']} {' '.join(R['flags'])}  {R['size']} B  H={R['entropy']}\nsha256 {R['sha256']}")
    for s in sorted(R.get('sections', []), key=lambda s: -s['raw'])[:8]: print(f"  sec {s['name']:<10} raw={s['raw']:<8} H={s['entropy']}")
    if 'overlay' in R: print(f"  overlay @{R['overlay']['offset']:#x} {R['overlay']['size']} B H={R['overlay']['entropy']}")
    if R.get('imports'): print('  imports:', ', '.join(list(R['imports'])[:12]))
    if R.get('imported_funcs'): print(f"  hàm import ({len(R['imported_funcs'])}):", ' '.join(R['imported_funcs'][:30]))
    if R.get('exports'): print(f"  export ({len(R['exports'])}):", ' '.join(R['exports'][:20]))
    if R.get('go'): print('  go:', ' | '.join(R['go'][:3]))
    if 'nsis' in R:
        for f in sorted(R['nsis']['files'], key=lambda f: -f['size'])[:10]: print(f"  nsis file {f['name']:<24} {f['size']:>9} B H={f['entropy']}")
        if 'sieve' in R['nsis']: s = R['nsis']['sieve']; print(f"  sàng byte: {s['file']} từ {s['start']} bước {s['step']} kết thúc '{s['sep']}' -> {s['calls']} lệnh System::Call ({s['out']})")
        if sc: print(f"  shellcode: {sc['file']} offset {sc['offset']} callback {sc['callback']}")
    if R['ioc_candidates']: print('  IOC ứng viên (từ strings, chưa xác nhận):', ' '.join(R['ioc_candidates'][:10]))
    print('  strings:'); [print('   ', s[:110]) for s in R['strings'][:12]]
    print('next:', R['next'])

    if A.facts:
        sys.path.insert(0, os.path.dirname(HERE)); import case
        tag = re.sub(r'\W+', '_', R['file'])[:32].strip('_')
        e = f'report/evidence/triage_{tag}.json'; shutil.copy(os.path.join(A.out, 'triage.json'), os.path.join(A.facts, e))
        have = {(f['kind'], f['value']) for f in case.load(A.facts).values()}
        def add(id_, kind, value, **kw):
            if (kind, value) not in have: have.add((kind, value)); case.add(A.facts, id=f's.{tag}.{id_}', kind=kind, value=value, src='S', evidence=e, **kw)
        add('hash', 'hash', f"{R['sha256']} {R['file']}")
        add('filetype', 'filetype', ' '.join([R['type']] + R['flags']))
        for c in ('NSIS', 'UPX'):
            if c in R['flags']: add(f'container_{c}', 'container', c)
        if sc: add('entry', 'entry', f"{sc['file']}@{sc['offset']} ({sc['callback']} callback)")
        for i, x in enumerate(R['ioc_candidates']):
            add(f'ioc{i}', 'url' if '://' in x else 'c2', x, status='hypothesis', note='chuỗi tĩnh, chưa thấy được dùng')

if __name__ == '__main__': main()
