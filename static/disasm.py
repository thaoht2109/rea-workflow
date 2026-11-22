#!/usr/bin/env python3
# Disasm hàm theo TÊN hoặc địa chỉ (ELF MIPS o32, x86-64, i386) bằng capstone: tên hàm từ .gopclntab (Go, kể cả strip) và symbol; lời gọi (jal/call) được đổi sang tên;
# hằng chuỗi nạp bằng lui+addiu (MIPS) hoặc lea rip (x86-64) được chú thích. Thay cho Ghidra khi chỉ cần đọc luồng nhanh. Chỉ đọc file, không chạy mẫu.
#   python3 -I disasm.py FILE SPEC...     SPEC: tên (khớp đúng, không có thì khớp chứa), 0xĐỊACHỈ (hàm chứa địa chỉ đó), hoặc list:CHUỖI
import os, re, sys, bisect
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from static import elfinfo, syscalls   # noqa: E402

def names_of(path, d, I):
    """{địa chỉ: tên} từ .gopclntab và symbol FUNC; kèm {địa chỉ: kích thước} nếu symbol có kích thước."""
    nm, sz = {}, {}
    try:
        from static import gopclntab
        for a, n in gopclntab.funcs(path): nm[a] = n
    except (SystemExit, Exception): pass   # không phải Go hoặc không có readelf
    for n, v, s, t in elfinfo.symbols(d, I):
        if t == 2 and v: nm.setdefault(v, n); sz[v] = s or sz.get(v, 0)
    return nm, sz

def _bounds(nm, sz, start):
    ks = sorted(nm); i = bisect.bisect_right(ks, start)
    nxt = ks[i] if i < len(ks) else start + 0x400
    return min(nxt, start + sz[start]) if sz.get(start) else nxt

def pick(nm, specs):
    """SPEC -> [(tên, địa chỉ)]; list:CHUỖI trả mọi hàm khớp (không disasm)."""
    out, lst = [], []
    for s in specs:
        if s.startswith('list:'): lst += [(n, a) for a, n in sorted(nm.items()) if s[5:] in n]; continue
        m = re.fullmatch(r'(?:0x)?([0-9a-fA-F]+)', s)
        if s.startswith('0x') and m:
            a = int(m.group(1), 16); ks = sorted(nm); i = bisect.bisect_right(ks, a) - 1
            out.append((nm.get(ks[i], f'sub_{ks[i]:x}'), ks[i]) if i >= 0 else (f'sub_{a:x}', a)); continue
        ex = [(n, a) for a, n in nm.items() if n == s] or [(n, a) for a, n in sorted(nm.items()) if s in n]
        if not ex: raise SystemExit(f'không thấy hàm: {s} (dùng list:CHUỖI để tìm)')
        out += ex[:20]
    return out, lst

def disasm(path, specs, d=None):
    d = d or open(path, 'rb').read(); I = elfinfo.parse(d)
    if I is None: raise SystemExit('không phải ELF')
    abi = elfinfo.abi(I)
    if abi is None: raise SystemExit(f"chưa hỗ trợ {I['machine']} {I['cls']}-bit (chỉ MIPS o32, x86-64, i386)")
    nm, sz = names_of(path, d, I); chosen, lst = pick(nm, specs); md = syscalls._cs(abi, I['be']); res = []
    def cstr(va, lim):
        o = elfinfo.va2off(I, va)
        if o is None: return None
        s = d[o:o + 200]; s = s.split(b'\0')[0][:lim]
        return s.decode('latin1') if len(s) >= 3 and all(32 <= c < 127 or c in (9, 10) for c in s) else None
    for name, a in chosen:
        end = _bounds(nm, sz, a); o = elfinfo.va2off(I, a)
        if o is None: raise SystemExit(f'địa chỉ {a:#x} không nằm trong đoạn LOAD')
        ins = list(md.disasm(d[o:o + (end - a)], a)); hi = {}; calls = []; lines = []
        for k, i in enumerate(ins):
            note = ''
            if abi == 'mips_o32':
                if i.mnemonic == 'lui': m = re.match(r'(\$\w+), (\S+)$', i.op_str); hi[m.group(1)] = int(m.group(2), 0) << 16 if m else None
                elif i.mnemonic in ('addiu', 'ori'):
                    m = re.match(r'(\$\w+), (\$\w+), (\S+)$', i.op_str)
                    if m and m.group(2) in hi and hi[m.group(2)] is not None:
                        v = (hi[m.group(2)] + int(m.group(3), 0)) & 0xffffffff; lim = 80
                        for p in ins[k + 1:k + 4]:   # Go: độ dài chuỗi nằm ở thanh ghi kế tiếp
                            mm = re.match(r'\$\w+, \$zero, (\d+|0x[0-9a-f]+)$', p.op_str) if p.mnemonic == 'addiu' else None
                            if mm and 3 <= int(mm.group(1), 0) <= 200: lim = int(mm.group(1), 0); break
                        s = cstr(v, lim)
                        note = f'; {v:#x}' + (f' "{s}"' if s else ''); hi.pop(m.group(2), None)
                elif i.mnemonic in ('jal', 'j'):
                    t = int(i.op_str, 0) if re.fullmatch(r'(0x)?[0-9a-f]+', i.op_str) else None
                    if t: note = '; ' + nm.get(t, f'sub_{t:x}'); calls.append(nm.get(t, f'sub_{t:x}'))
            else:
                m = re.match(r'(\w+), (?:\w+ ptr )?\[rip ([+-]) (0x[0-9a-f]+)\]$', i.op_str) if i.mnemonic == 'lea' else None
                if m:
                    v = i.address + i.size + (int(m.group(3), 16) * (1 if m.group(2) == '+' else -1)); s = cstr(v, 80); note = f'; {v:#x}' + (f' "{s}"' if s else '')
                elif i.mnemonic == 'call':
                    t = int(i.op_str, 0) if re.fullmatch(r'(0x)?[0-9a-f]+', i.op_str) else None
                    if t: note = '; ' + nm.get(t, f'sub_{t:x}'); calls.append(nm.get(t, f'sub_{t:x}'))
            lines.append(f'{i.address:#x}\t{i.mnemonic}\t{i.op_str}{note}')
        res.append(dict(name=name, start=a, end=end, lines=lines, calls=list(dict.fromkeys(calls))))
    return res, lst

if __name__ == '__main__':
    r, lst = disasm(sys.argv[1], sys.argv[2:])
    for n, a in lst[:200]: print(f'{a:#x} {n}')
    for f in r:
        print(f"# {f['name']} {f['start']:#x}-{f['end']:#x}"); print('\n'.join(f['lines'])); print('# gọi:', ', '.join(f['calls']))
