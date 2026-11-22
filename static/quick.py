#!/usr/bin/env python3
# "Đọc nhanh" một mẫu ELF/PE/script trong vài giây: chuỗi và symbol gom theo nhóm (CLI, mạng, đường dẫn, mật mã, hành vi, lớp C++/gói Go), mỗi dòng một mục để fact trỏ #L.
# Chuỗi quét bằng static.native (Rust nếu có). Thay cho việc đọc strings thô; KHÔNG phải fact: ứng viên cần xref/đọc mã trước khi kết luận. Chỉ đọc file.
#   python3 -I quick.py FILE
import os, re, sys, collections
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from static import elfinfo   # noqa: E402
from static.native import scan_strings   # noqa: E402

TLD = r'(?:com|net|org|io|xyz|live|cn|ru|top|info|co|me|cc|site|online|app|dev|vip|club|tk|pw|su|ws|icu|cloud|tech)'
GROUPS = [
    ('cli', 'Tham số dòng lệnh / usage', re.compile(r'(?i)^\s*-{1,2}[a-z][\w-]*(=|\s|$)|\busage\b|\bhelp\b')),
    ('net', 'URL, tên miền, IP', re.compile(rf'(?i:https?://[^\s"\']{{1,120}})|\b[a-z0-9][a-z0-9-]*(?:\.[a-z0-9-]+)*\.{TLD}\b|\b(?:\d{{1,3}}\.){{3}}\d{{1,3}}\b')),   # tên miền: chữ thường (loại godebugs.Info, type:.eq.io của Go)
    ('path', 'Đường dẫn và tệp', re.compile(r'(?:^|[\s"\'=])(?:/(?:etc|tmp|proc|var|dev|home|usr|sys|root|run|opt)/[\w./-]*|/proc|/dev/\w+)|\.(?:conf|cfg|pid|lock|log|ini|json|db|sock)\b')),
    ('crypto', 'Mật mã, khóa, định danh', re.compile(r'(?i)\bxor|base64|\bmd5|sha-?1\b|sha-?256|\baes|\brc4|chacha|encrypt|decrypt|cipher|app-?key|\bsecret|password|\btoken\b|api-?key|\bauth')),
    ('behav', 'Hành vi (từ khóa)', re.compile(r'(?i)tunnel|dispatch|heartbeat|download|upload|\bexec|\bshell\b|inject|persist|startup|install|\bupdate\b|\bkill\b|daemon|single.?instance|proxy|forward')),
]
URL_IP = re.compile(r'(?i:https?://[^\s"\']{1,120})|\b(?:\d{1,3}\.){3}\d{1,3}\b')
SKIP_PATH = re.compile(r'(?i)/(?:include|src|lib)/|\.(?:hpp|ipp|h|cpp|c|cc|go)\b|/proc/self|/usr/share/zoneinfo')   # đường dẫn build của thư viện, không phải hành vi
SKIP_NET = re.compile(r'(?i)gcc\.gnu\.org|golang\.org|go\.dev|\.so\b|\.go\b|\.h\b|\.cpp\b|\.c\b|^\d+\.\d+\.\d+\.\d+$|^0\.0\.0\.0|^127\.|^255\.')
CLS = re.compile(r'_ZN[KVr]*(\d+)')   # tên Itanium: _ZN<độ dài><tên>...; lấy đúng độ dài, không lấy phần còn lại

def build(path, d=None, cap=40):
    d = d or open(path, 'rb').read(); I = elfinfo.parse(d); L = []; sug = []
    L.append(f'# quick {os.path.basename(path)}: {len(d)} B')
    if I:
        L.append(f"elf: {I['machine']} {I['cls']}-bit {'BE' if I['be'] else 'LE'} etype={I['etype']} entry={I['entry']:#x} abi={elfinfo.abi(I)} section={len(I['sections'])} symbol={len(elfinfo.symbols(d, I))}")
    asc, wide = scan_strings(d, 6); seen = set(); S = [s for s in asc + wide if not (s in seen or seen.add(s))]
    for key, title, rx in GROUPS:
        L.append(f'## {title}'); n = 0
        for s in S:
            m = rx.search(s)
            if key == 'net' and len(s) > 120: m = URL_IP.search(s)   # chuỗi dài (kho chuỗi Go nối liền): chỉ nhận URL/IP, bỏ 'tên miền' ghép ngẫu nhiên
            if not m or (len(s) > 400 and key != 'net') or (key == 'net' and SKIP_NET.search(m.group(0))) or (key == 'path' and SKIP_PATH.search(s)) or s.startswith(('_Z', 'type:', '*')): continue
            L.append(m.group(0) if key == 'net' else s[:160].replace('\n', ' ')); n += 1
            if key in ('net', 'path') and len(sug) < 12:
                v = m.group(0).strip(' "\'=')
                if key == 'path' and not v.startswith('/'):   # nhánh theo đuôi tệp (.conf, .json): lấy cả token chứa nó
                    t = re.search(r'[\w./-]*' + re.escape(v), s); v = t.group(0) if t else ''
                if len(v) >= 5: sug.append((key, v, len(L)))
            if n >= cap: break
        if not n: L.append('(không có)')
    if I:
        syms = [x[0] for x in elfinfo.symbols(d, I)]
        L.append('## Lớp C++ trong symbol (không tính std/boost/fmt/spdlog/__gnu)'); C = collections.Counter()
        for s in syms:
            m = CLS.match(s)
            nm = s[m.end():m.end() + int(m.group(1))] if m else ''
            if nm and nm not in ('std', 'boost', 'fmt', 'spdlog', '__gnu_cxx', '__cxxabiv1'): C[nm] += 1
        L += [f'{k} ({v})' for k, v in C.most_common(cap)] or ['(không có)']
        try:
            from static import gopclntab
            g = [n for _, n in gopclntab.funcs(path)]
            L.append('## Hàm Go package main và package ngoài runtime/std (ước lượng theo tên)')
            ext = [n for n in g if n.startswith('main.') or (re.match(r'^[a-z0-9._-]+\.[a-z]+/', n) and not n.startswith(('internal/', 'vendor/')))]
            L += list(dict.fromkeys(ext))[:cap * 2] or ['(không có)']
        except (SystemExit, Exception): pass
    return '\n'.join(L) + '\n', sug

if __name__ == '__main__':
    print(build(sys.argv[1])[0], end='')
