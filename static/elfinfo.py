#!/usr/bin/env python3
# Đọc ELF bằng struct (không cần readelf): header, section, đoạn LOAD, symbol; chọn bảng syscall/ABI; base địa chỉ Ghidra. Chỉ đọc file, không chạy mẫu.
import struct

MACH = {3: 'i386', 8: 'mips', 40: 'arm', 62: 'x86_64', 183: 'aarch64'}

def parse(d):
    """ELF -> dict(cls, be, etype, machine, flags, entry, phdrs, sections) hoặc None nếu không phải ELF."""
    if d[:4] != b'\x7fELF' or len(d) < 52 or d[4] not in (1, 2) or d[5] not in (1, 2): return None
    c64, be = d[4] == 2, d[5] == 2; E = '>' if be else '<'
    if c64: etype, mach, _, entry, phoff, shoff, flags, _, phes, phn, shes, shn, shstr = struct.unpack_from(E + 'HHIQQQIHHHHHH', d, 16)
    else: etype, mach, _, entry, phoff, shoff, flags, _, phes, phn, shes, shn, shstr = struct.unpack_from(E + 'HHIIIIIHHHHHH', d, 16)
    I = dict(cls=64 if c64 else 32, be=be, etype=etype, machine=MACH.get(mach, mach), flags=flags, entry=entry, phdrs=[], sections={}, _E=E)
    for i in range(phn if phes else 0):
        o = phoff + i * phes
        if o + phes > len(d): break
        I['phdrs'].append(struct.unpack_from(E + ('IIQQQQQQ' if c64 else 'IIIIIIII'), d, o)[:8] if c64 else struct.unpack_from(E + 'IIIIIIII', d, o))
    # phdr 32: type, offset, vaddr, paddr, filesz, memsz, flags, align ; 64: type, flags, offset, vaddr, paddr, filesz, memsz, align
    I['loads'] = [(p[2], p[3], p[5]) if c64 else (p[1], p[2], p[4]) for p in I['phdrs'] if p[0] == 1]   # (offset, vaddr, filesz)
    secs = []
    for i in range(shn if shes and shoff else 0):
        o = shoff + i * shes
        if o + shes > len(d): break
        secs.append(struct.unpack_from(E + ('IIQQQQIIQQ' if c64 else 'IIIIIIIIII'), d, o))
    if secs and shstr < len(secs):
        so, ss = (secs[shstr][4], secs[shstr][5]) if c64 else (secs[shstr][4], secs[shstr][5])
        names = d[so:so + ss]
        for s in secs:
            n = names[s[0]:names.find(b'\0', s[0])].decode('latin1')
            # 32/64 cùng thứ tự: name, type, flags, addr, off, size, link, info, align, entsize
            I['sections'][n] = dict(type=s[1], addr=s[3], off=s[4], size=s[5], link=s[6], entsize=s[9])
    return I

def abi(I):
    """Khóa bảng syscall: mips_o32, x86_64, i386; None nếu chưa có bảng (công cụ phải từ chối, không đoán)."""
    m = I['machine']
    if m == 'mips' and I['cls'] == 32 and not (I['flags'] & 0x20) and (I['flags'] & 0xf000) in (0x1000, 0): return 'mips_o32'   # 0x20 = EF_MIPS_ABI2 (n32): bảng khác, từ chối
    if m == 'x86_64' and I['cls'] == 64: return 'x86_64'
    if m == 'i386' and I['cls'] == 32: return 'i386'
    return None

def va2off(I, va):
    for off, vaddr, fsz in I['loads']:
        if vaddr <= va < vaddr + fsz: return off + va - vaddr
    return None

def ghidra_base(I):
    """Base địa chỉ Ghidra dùng cho ELF này: cộng vào địa chỉ ảo của ELF (readelf, dynsym) để ra địa chỉ trong Ghidra.
    Đã đo: ET_DYN MIPS32 = 0x10000, ET_DYN x86-64 = 0x100000; ET_EXEC = 0 (đúng p_vaddr). Kiến trúc khác chưa đo: theo lớp (32 bit 0x10000, 64 bit 0x100000)
    và `measured` = False để công cụ nói rõ."""
    if I['etype'] == 2: return 0, True
    measured = (I['machine'], I['cls']) in (('mips', 32), ('x86_64', 64))
    return (0x100000 if I['cls'] == 64 else 0x10000), measured

def symbols(d, I):
    """[(tên, giá trị, kích thước, loại)] từ .symtab và .dynsym (loại 2 = FUNC)."""
    out, E = [], I['_E']
    for sn, strn in (('.symtab', '.strtab'), ('.dynsym', '.dynstr')):
        S = I['sections'].get(sn); T = I['sections'].get(strn)
        if not S or not T: continue
        ent = S['entsize'] or (24 if I['cls'] == 64 else 16)
        for i in range(S['size'] // ent):
            o = S['off'] + i * ent
            if o + ent > len(d): break
            if I['cls'] == 64: nm, info, _, shndx, val, sz = struct.unpack_from(E + 'IBBHQQ', d, o)
            else: nm, val, sz, info, _, shndx = struct.unpack_from(E + 'IIIBBH', d, o)
            if not nm or shndx == 0: continue
            a = T['off'] + nm
            out.append((d[a:d.find(b'\0', a)].decode('latin1'), val, sz, info & 0xf))
    return out
