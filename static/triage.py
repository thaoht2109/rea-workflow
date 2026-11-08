#!/usr/bin/env python3
# T0 triage tĩnh cho mọi file mẫu (FLOW.md bước 2): PE, ELF, Go, .NET, UPX, NSIS, script, archive, Office/PDF.
# In tóm tắt ≤ 60 dòng + dòng next: (bước kế tiếp), ghi OUT/triage.json; dữ liệu đầy đủ nằm trong OUT/. Không thực thi mẫu:
# chỉ đọc byte, pefile, readelf, `go version -m` (đọc buildinfo), 7z (giải nén).
#   python3 -I triage.py FILE --out OUTDIR [--facts CASE]
# NSIS: tự dịch header, giải nén file bằng 7z, giải "sàng byte" (đọc 1 byte mỗi bước nhảy, dấu kết thúc chuỗi) để lộ chuỗi
# System::Call, rồi đề xuất --blob/--blob-off cho winemu. Chỉ là heuristic: luôn đối chiếu với nsis_disasm.txt.
import sys, os, re, json, math, struct, shutil, hashlib, argparse, subprocess, shlex
from collections import Counter
import pefile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE)); from reacfg import SEVENZ   # cấu hình theo máy: reacfg.py
from static.ziptype import zip_kind   # noqa: E402  (ZIP là chính mẫu: APK, OOXML, JAR, ODF)
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

# API nhạy cảm theo mục checklist: triage chỉ ra cần decompile xref của hàm nào (thay vì tự đọc hết bảng import).
# So tên chính xác (không phân biệt hoa thường) sau khi bỏ hậu tố A/W/Ex/ExA/ExW; mẫu kết thúc '*' là tiền tố.
# Không so chuỗi con: 'connect' khớp nhầm DisconnectNamedPipe, 'send' khớp nhầm SendMessageW.
SENS = {
    'C3 chống phân tích': ('isdebuggerpresent', 'checkremotedebuggerpresent', 'ntqueryinformationprocess', 'zwqueryinformationprocess',
                           'outputdebugstring', 'ntsetinformationthread', 'zwsetinformationthread', 'gettickcount', 'gettickcount64',
                           'queryperformancecounter', 'createtoolhelp32snapshot', 'process32first', 'process32next', 'findwindow',
                           'blockinput', 'ntqueryobject', 'ntquerysysteminformation', 'zwquerysysteminformation', 'getsysteminfo',
                           'globalmemorystatus', 'ptrace'),
    'C4 giải mã chuỗi/config': ('cryptdecrypt', 'cryptencrypt', 'cryptderivekey', 'crypthashdata', 'cryptcreatehash', 'cryptacquirecontext',
                                'cryptimportkey', 'bcryptdecrypt', 'bcryptencrypt', 'rtldecompressbuffer', 'rtlcompressbuffer',
                                'cryptstringtobinary', 'cryptbinarytostring', 'evp_*', 'aes_*'),
    'C5 IOC mạng': ('internetopen*', 'internetconnect', 'internetreadfile', 'internetwritefile', 'httpopenrequest', 'httpsendrequest',
                    'urldownloadtofile', 'winhttpopen*', 'winhttpconnect', 'winhttpsendrequest', 'winhttpreaddata', 'wsastartup',
                    'wsasocket', 'wsaconnect', 'wsasend', 'wsarecv', 'socket', 'connect', 'send', 'sendto', 'recv', 'recvfrom',
                    'gethostbyname', 'getaddrinfo', 'inet_addr', 'dnsquery*', 'curl_easy_*', 'ssl_connect', 'ssl_write', 'ssl_read'),
    'C6 tiêm mã': ('writeprocessmemory', 'readprocessmemory', 'virtualallocex', 'virtualprotectex', 'createremotethread', 'ntcreatethreadex',
                   'rtlcreateuserthread', 'queueuserapc', 'ntqueueapcthread', 'setthreadcontext', 'getthreadcontext', 'ntunmapviewofsection',
                   'zwunmapviewofsection', 'ntmapviewofsection', 'createprocess*', 'ntcreateuserprocess', 'openprocess', 'resumethread',
                   'setwindowshook', 'shellexecute', 'winexec', 'dlopen', 'execve', 'fork'),
    'C7 persistence': ('regsetvalue', 'regsetkeyvalue', 'regcreatekey', 'regdeletevalue', 'createservice', 'openscmanager', 'startservice',
                       'changeserviceconfig*', 'registerservicectrlhandler', 'setservicestatus', 'startservicectrldispatcher',
                       'copyfile', 'movefile', 'movefilewithprogress'),
}
_SFX = re.compile(r'(?:exa|exw|ex|a|w)$')

def sens_hits(names):
    """{mục checklist: [API khớp]} từ danh sách tên hàm import của mẫu."""
    out = {}
    for mục, pats in SENS.items():
        exact = {p for p in pats if not p.endswith('*')}; pre = tuple(p[:-1] for p in pats if p.endswith('*'))
        hit = sorted({n for n in names if isinstance(n, str) and
                      ((l := n.lower()) in exact or _SFX.sub('', l) in exact or (pre and l.startswith(pre)))})
        if hit: out[mục] = hit[:24]
    return out

def run(*a):
    r = subprocess.run(a, capture_output=True, text=True, errors='replace'); return r.stdout if r.returncode == 0 else ''

# Đặc trưng tra chéo giữa các case (flow.py kb match): chỉ để gợi ý mẫu tương tự, không tự thành fact. Tên lấy từ mẫu (PDB,
# chủ thể chứng thư) giữ nguyên trong triage.json, khi in thì qua show(). tlsh, cryptography không bắt buộc: thiếu thì bỏ trường đó.
def tlsh_of(d):
    try: import tlsh
    except ImportError: return None
    h = tlsh.hash(d) if len(d) >= 50 else ''
    return h if h and h != 'TNULL' else None

def der_len(b):
    """Độ dài SEQUENCE DER ở đầu b (bỏ phần đệm WIN_CERTIFICATE phía sau); None nếu không phải DER."""
    if len(b) < 2 or b[0] != 0x30: return None
    if b[1] < 0x80: return 2 + b[1]
    n = b[1] & 0x7f
    return 2 + n + int.from_bytes(b[2:2 + n], 'big') if 0 < n <= 4 and len(b) >= 2 + n else None

def certs(d, sig):
    """Metadata chứng thư trong vùng Authenticode (không verify chữ ký): chủ thể, nơi cấp, serial, hạn. None = thiếu cryptography."""
    try: from cryptography.hazmat.primitives.serialization import pkcs7
    except ImportError: return None
    b = d[sig['offset'] + 8:sig['offset'] + sig['size']]   # bỏ header WIN_CERTIFICATE 8 byte
    n = der_len(b)
    try: cs = pkcs7.load_der_pkcs7_certificates(b[:n]) if n else []
    except Exception: return []
    day = lambda c, k: (getattr(c, k + '_utc', None) or getattr(c, k)).date().isoformat()
    return [{'subject': c.subject.rfc4514_string()[:200], 'issuer': c.issuer.rfc4514_string()[:200], 'serial': format(c.serial_number, 'x'),
             'not_before': day(c, 'not_valid_before'), 'not_after': day(c, 'not_valid_after')} for c in cs[:8]]

def pe_pivots(pe, d, R):
    P = R.setdefault('pivot', {})
    try: P['imphash'] = pe.get_imphash() or None
    except Exception: P['imphash'] = None
    try:   # fast_load không dựng RICH_HEADER: tự parse, hash như get_rich_header_hash (md5 phần đã giải XOR)
        rh = getattr(pe, 'RICH_HEADER', None); clear = rh.clear_data if rh else (pe.parse_rich_header() or {}).get('clear_data')
        P['rich'] = hashlib.md5(clear).hexdigest() if clear else None
    except Exception: P['rich'] = None
    P['timestamp'] = getattr(getattr(pe, 'FILE_HEADER', None), 'TimeDateStamp', None)
    for e in getattr(pe, 'DIRECTORY_ENTRY_DEBUG', []):
        cv = getattr(e, 'entry', None); pdb = getattr(cv, 'PdbFileName', None)
        if isinstance(pdb, bytes) and pdb.strip(b'\0'):
            P['pdb'] = pdb.split(b'\0')[0].decode('utf-8', 'replace')[:260]
            g = getattr(cv, 'Signature_String', None)
            if g: P['pdb_guid'] = g   # GUID + Age như symbol server
            break
    if 'signature' in R:
        cs = certs(d, R['signature'])
        if cs is not None: P['certs'] = cs

def pe_info(d, R):
    pe = pefile.PE(data=d, fast_load=True); pe.parse_data_directories()
    R['type'] = 'PE32+' if pe.OPTIONAL_HEADER.Magic == 0x20b else 'PE32'
    R['sections'] = [{'name': s.Name.rstrip(b'\0').decode('latin1'), 'raw': s.SizeOfRawData, 'entropy': entropy(s.get_data()),
                      'md5': hashlib.md5(s.get_data()).hexdigest() if s.SizeOfRawData else None} for s in pe.sections]
    ov = pe.get_overlay_data_start_offset()
    if ov: R['overlay'] = {'offset': ov, 'size': len(d) - ov, 'entropy': entropy(d[ov:])}
    R['imports'] = {e.dll.decode(): len(e.imports) for e in getattr(pe, 'DIRECTORY_ENTRY_IMPORT', [])}
    R['imported_funcs'] = sorted({i.name.decode() for e in getattr(pe, 'DIRECTORY_ENTRY_IMPORT', []) for i in e.imports if i.name})
    R['exports'] = [e.name.decode() for e in getattr(getattr(pe, 'DIRECTORY_ENTRY_EXPORT', None), 'symbols', []) if e.name][:30]
    if pe.OPTIONAL_HEADER.DATA_DIRECTORY[14].VirtualAddress: R['flags'].append('.NET')
    if any(s['name'].startswith('UPX') for s in R['sections']): R['flags'].append('UPX')
    if NSIS_SIG in d: R['flags'].append('NSIS')
    sd = pe.OPTIONAL_HEADER.DATA_DIRECTORY[4]   # vùng chữ ký Authenticode: địa chỉ ở đây là offset file
    if sd.VirtualAddress and sd.Size: R['signature'] = {'offset': sd.VirtualAddress, 'size': sd.Size}
    pe_pivots(pe, d, R)

def only_in_signature(d, x, sig):
    """Chuỗi chỉ xuất hiện trong vùng chữ ký (URL CA/CRL/OCSP/CPS của chứng thư): không phải hành vi của mã."""
    a, b = sig['offset'], sig['offset'] + sig['size']
    pos = [m.start() for e in (x.encode('latin1', 'ignore'), x.encode('utf-16le')) for m in re.finditer(re.escape(e), d)]
    return bool(pos) and all(a <= p < b for p in pos)

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
    P = R.setdefault('pivot', {})
    m = re.search(r'Build ID: ([0-9a-f]+)', run('readelf', '-W', '-n', path))
    if m: P['build_id'] = m.group(1)
    if R['imported_funcs']: P['impfuncs_md5'] = hashlib.md5(','.join(sorted(n.lower() for n in R['imported_funcs'])).encode()).hexdigest()

def pivot_of(path):
    """Đặc trưng tra chéo của một file cho flow.py kb, không chạy triage đầy đủ (không giải nén, không ghi file). Chỉ đọc byte."""
    d = open(path, 'rb').read()
    R = {'size': len(d), 'md5': hashlib.md5(d).hexdigest(), 'sha256': hashlib.sha256(d).hexdigest(), 'flags': [],
         'type': next((t for m, t in MAGIC if d.startswith(m)), 'unknown')}
    try:
        if R['type'] == 'PE': pe_info(d, R)
        elif R['type'] == 'ELF': elf_info(path, d, R)
    except Exception as e: R['error'] = f'{type(e).__name__}: {e}'[:120]   # PE/ELF hỏng: vẫn còn hash và TLSH
    t = tlsh_of(d)
    if t: R.setdefault('pivot', {})['tlsh'] = t
    return R

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

# Tên lấy từ mẫu (export, import, section) do tác giả mã độc đặt: chỉ đưa định danh hợp lệ vào output agent đọc,
# vì dòng `next:` là chỉ dẫn agent làm theo (chống chèn câu lệnh qua tên symbol). triage.json vẫn giữ bản gốc làm bằng chứng.
IDENT = re.compile(r'[A-Za-z_?@$.][\w?@$.:<>~-]{0,79}')
def idents(xs, n):
    ok = [x for x in xs if isinstance(x, str) and IDENT.fullmatch(x)]
    return ok[:n], len(xs) - len(ok)

CTRL = re.compile(r'[\x00-\x1f\x7f]')
def q(x): return shlex.quote(CTRL.sub('?', x))   # tham số lệnh từ tên do mẫu/installer đặt: bỏ ký tự điều khiển (xuống dòng) rồi quote
def show(x): return json.dumps(x, ensure_ascii=False)   # in tên do mẫu đặt: một dòng, có thoát ký tự

WIN_DL = 'C:\\Users\\admin\\Downloads\\'   # đường dẫn giả lập của mẫu trong winemu

def route(R, out):
    f, t, sc = R['flags'], R['type'], R.get('nsis', {}).get('shellcode')
    if sc: return f"T3 winemu --blob {q(os.path.join(out, sc['file']))} --blob-off {sc['offset']}" + (f" --size {sc['alloc']:#x}" if sc['alloc'] else '') + \
                  f" --prerun --chain-child --exe {q(R['path'])} --exe-path {q(WIN_DL + R['file'])}"
    if 'NSIS' in f: return 'T1: đọc nsis_disasm.txt + nsis/files/ (chưa tự tìm ra shellcode)'
    if 'UPX' in f: return 'flow.py triage tự upx -d bản sao rồi triage lại (bước 3)'
    if t == 'zip' and R.get('zip_kind') == 'APK': return 'T2: rea inspect-android-package / inspect-android-method (APK giữ nguyên, không giải nén)'
    if t == 'zip' and R.get('zip_kind'): return f"T2: rea inspect-artifact ({R['zip_kind']} giữ nguyên); tìm macro/script/đối tượng nhúng"
    if t in ('zip', '7z', 'rar', 'gzip'): return 'flow.py new giải nén vào work/sample/ rồi triage từng file (bước 1)'
    if t in ('ole', 'pdf'): return 'T2: rea inspect-artifact; tìm macro/JS/stream nhúng (olevba/pdf-parser chưa cài)'
    if t == 'dex': return 'T2: rea inspect-android-package / inspect-android-method'
    if t.startswith('script'): return 'T2: khử làm rối script tĩnh (base64/eval/char-code) bằng Python, không chạy script'
    if '.NET' in f: return 'T2: rea inspect-managed-members (chuỗi ldstr, PInvoke) rồi decompile lớp/hàm đáng ngờ'
    if 'Go' in f: return 'T2: rea inspect-go-binary + flow.py dec CASE FILE main.main (và các hàm main.*)'
    hi = R.get('overlay', {}).get('entropy', 0) > 7.5 or any(s['entropy'] > 7.5 and s['raw'] > 4096 for s in R.get('sections', []))
    if t.startswith('PE'):
        return ('T2 tìm stub giải mã (flow.py dec CASE FILE entry) -> T3 winemu nếu là x86-32' if hi else
                'T2: flow.py dec CASE FILE <export/hàm theo import đáng ngờ>')
    if t.startswith('ELF'):
        tgt = ' '.join(q(e) for e in idents([e for e in R.get('exports', []) if not e.startswith('_')], 8)[0]) or 'main/entry'
        return ('T2: flow.py dec CASE FILE ' + tgt) + (' | entropy cao: tìm stub giải mã' if hi or 'no-section-header' in f else '') + \
               ' | không có T3 cho ELF trên server (thiếu qemu-user): giải mã bằng tái hiện tĩnh'
    return 'T2: xem strings/hexdump có giới hạn; xác định định dạng thủ công'

def main():
    ap = argparse.ArgumentParser(); ap.add_argument('file'); ap.add_argument('--out', required=True); ap.add_argument('--facts')
    A = ap.parse_args(); os.makedirs(A.out, exist_ok=True)
    d = open(A.file, 'rb').read()
    R = {'file': os.path.basename(A.file), 'path': os.path.abspath(A.file), 'size': len(d), 'md5': hashlib.md5(d).hexdigest(),
         'sha1': hashlib.sha1(d).hexdigest(), 'sha256': hashlib.sha256(d).hexdigest(), 'type': 'unknown', 'flags': []}
    R['type'] = next((t for m, t in MAGIC if d.startswith(m)), 'unknown')
    zk = zip_kind(A.file) if R['type'] == 'zip' else None
    if zk: R['zip_kind'] = zk
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
    if 'signature' in R:
        R['ioc_in_signature'] = [x for x in R['ioc_candidates'] if only_in_signature(d, x, R['signature'])]
        R['ioc_candidates'] = [x for x in R['ioc_candidates'] if x not in R['ioc_in_signature']]
    R['entropy'] = entropy(d)
    t = tlsh_of(d)
    if t: R.setdefault('pivot', {})['tlsh'] = t
    if 'NSIS' in R['flags']: nsis(A.file, A.out, R)
    if R.get('imported_funcs'): R['sensitive_api'] = sens_hits(R['imported_funcs'])
    R['next'] = route(R, A.out)
    json.dump(R, open(os.path.join(A.out, 'triage.json'), 'w'), indent=1, ensure_ascii=False)

    sc = R.get('nsis', {}).get('shellcode')
    print(f"{show(R['file'])}  {R['type']} {' '.join(R['flags'])}  {R['size']} B  H={R['entropy']}\nsha256 {R['sha256']}")
    for s in sorted(R.get('sections', []), key=lambda s: -s['raw'])[:8]: print(f"  sec {s['name'] if IDENT.fullmatch(s['name']) else '<tên lạ>':<10} raw={s['raw']:<8} H={s['entropy']}")
    if 'overlay' in R: print(f"  overlay @{R['overlay']['offset']:#x} {R['overlay']['size']} B H={R['overlay']['entropy']}")
    if R.get('imports'): ok, bad = idents(list(R['imports']), 12); print('  imports:', ', '.join(ok) + (f' (+{bad} tên lạ không in)' if bad else ''))
    for k, lab, n in (('imported_funcs', 'hàm import', 30), ('exports', 'export', 20)):   # tên từ mẫu: chỉ in định danh hợp lệ
        if R.get(k): ok, bad = idents(R[k], n); print(f"  {lab} ({len(R[k])}):", ' '.join(ok) + (f' (+{bad} tên lạ không in, xem triage.json)' if bad else ''))
    if R.get('go'): print('  go:', ' | '.join(R['go'][:3]))
    pv = R.get('pivot', {}); bits = [f'{k} {pv[k]}' for k in ('imphash', 'rich', 'build_id', 'pdb_guid') if pv.get(k)]
    if pv.get('pdb'): bits.append('pdb ' + show(pv['pdb'])[:100])   # tên do mẫu đặt: in dạng chuỗi có thoát
    if pv.get('certs'):
        cs = pv['certs']; leafs = [c for c in cs if not any(o['issuer'] == c['subject'] for o in cs if o is not c)] or cs
        leaf = next((c for c in leafs if not re.search(r'time ?stamp|\btsa\b', c['subject'], re.I)), leafs[0])   # bỏ chứng thư đóng dấu thời gian
        bits.append(f'cert({len(cs)}) ' + show(leaf['subject'])[:90])
    if pv.get('tlsh'): bits.append('tlsh ' + pv['tlsh'][:16] + '…')
    if bits: print('  pivot (tra chéo: flow.py kb match; không phải fact):', ' | '.join(bits))
    for mục, hit in R.get('sensitive_api', {}).items():   # tên API từ bảng import: decompile xref của các hàm này trước
        ok, bad = idents(hit, 14); print(f'  {mục}:', ' '.join(ok) + (f' (+{bad} tên lạ không in)' if bad else ''))
    if 'nsis' in R:
        for f in sorted(R['nsis']['files'], key=lambda f: -f['size'])[:10]: print(f"  nsis file {json.dumps(f['name'])[:60]:<24} {f['size']:>9} B H={f['entropy']}")   # tên do installer đặt: in dạng chuỗi có thoát
        if 'sieve' in R['nsis']: s = R['nsis']['sieve']; print(f"  sàng byte: {show(s['file'])} từ {s['start']} bước {s['step']} kết thúc '{s['sep']}' -> {s['calls']} lệnh System::Call ({s['out']})")
        if sc: print(f"  shellcode: {show(sc['file'])} offset {sc['offset']} callback {show(str(sc['callback']))}")
    if R['ioc_candidates']: print('  IOC ứng viên (từ strings, CHƯA là fact; ghi fact url/c2 khi đã có xref tới mã hoặc quan sát giả lập):', ' '.join(R['ioc_candidates'][:10]))
    if R.get('ioc_in_signature'): print(f"  bỏ {len(R['ioc_in_signature'])} URL chỉ nằm trong vùng chữ ký Authenticode")
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
        # IOC ứng viên từ strings không tự thành fact: trên các case cũ 0/35 là IOC thật (chứng thư, banner thư viện, tính năng
        # của phần mềm hợp lệ, số phiên bản) và chiếm gần nửa số đính chính. Ứng viên nằm trong triage.json để phân tích xref.

if __name__ == '__main__': main()
