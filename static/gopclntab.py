#!/usr/bin/env python3
# Khôi phục tên hàm Go từ .gopclntab (Go 1.18+, magic 0xFFFFFFF0/0xFFFFFFF1) cho ELF bị strip, mọi kiến trúc và endianness.
# Dùng khi Ghidra/rea không tự nhận tên Go (ví dụ Go MIPS). Chỉ đọc file, không chạy mẫu.
#   python3 -I gopclntab.py FILE [CHUỖI...]   -> in "0xaddr tên" (lọc theo CHUỖI nếu có; không có thì in tất cả)
import sys, struct, re, subprocess

def sections(path):
    out = subprocess.run(['readelf', '-W', '-S', path], capture_output=True, text=True).stdout
    return {n: (int(a, 16), int(o, 16), int(s, 16)) for n, a, o, s in
            re.findall(r'\]\s+(\S+)\s+\S+\s+([0-9a-f]+)\s+([0-9a-f]+)\s+([0-9a-f]+)', out)}

def funcs(path):
    d = open(path, 'rb').read()
    be = d[5] == 2
    sec = sections(path).get('.gopclntab')
    if sec:
        data = d[sec[1]:sec[1] + sec[2]]
    else:   # không có section header: tìm header pclntab theo magic
        m = re.search(rb'(\xff\xff\xff[\xf0\xf1]|[\xf0\xf1]\xff\xff\xff)\x00\x00[\x01\x02\x04][\x04\x08]', d)
        if not m: raise SystemExit('không thấy .gopclntab')
        data = d[m.start():]
    E = '>' if be else '<'
    magic = struct.unpack_from(E + 'I', data, 0)[0]
    if magic not in (0xFFFFFFF0, 0xFFFFFFF1): raise SystemExit(f'magic {magic:#x}: chỉ hỗ trợ Go 1.18+')
    ps = data[7]
    rd = lambda off, sz: struct.unpack_from(E + ('I' if sz == 4 else 'Q'), data, off)[0]
    nfunc, _, text, nameoff, _, _, _, pcln = (rd(8 + i * ps, ps) for i in range(8))
    for i in range(nfunc):
        fo = rd(pcln + i * 8 + 4, 4)
        entry, noff = rd(pcln + fo, 4), rd(pcln + fo + 4, 4)
        s = nameoff + noff
        yield text + entry, data[s:data.index(b'\0', s)].decode('utf-8', 'replace')

if __name__ == '__main__':
    pats = sys.argv[2:]
    for a, n in funcs(sys.argv[1]):
        if not pats or any(p in n for p in pats): print(f'{a:#x} {n}')
