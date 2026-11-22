#!/usr/bin/env python3
# static/elfinfo.py, syscalls.py, disasm.py, quick.py trên ELF tổng hợp (MIPS o32 BE, x86-64, i386, ARM bị từ chối). Chạy: python3 tests/check_static_tools.py
import os, sys, struct, tempfile
T = os.path.dirname(os.path.dirname(os.path.abspath(__file__))); sys.path.insert(0, T)
from static import elfinfo, syscalls, disasm, quick   # noqa: E402

def elf(machine, cls, be, etype, flags, text, text_va, extra=b'', syms=()):
    """ELF tối thiểu: một LOAD chứa .text và .rodata(extra), section .text/.symtab/.strtab/.shstrtab. syms = [(tên, địa chỉ, kích thước)]."""
    E = '>' if be else '<'; c64 = cls == 64; eh = 64 if c64 else 52; ph = 56 if c64 else 32; sh = 64 if c64 else 40
    body = text + extra; strtab = b'\0' + b''.join(n.encode() + b'\0' for n, _, _ in syms)
    symtab = b'\0' * (24 if c64 else 16)
    off = 1
    for n, a, sz in syms:
        symtab += struct.pack(E + 'IBBHQQ', off, 2, 0, 1, a, sz) if c64 else struct.pack(E + 'IIIBBH', off, a, sz, 2, 0, 1)
        off += len(n) + 1
    names = [b'', b'.text', b'.symtab', b'.strtab', b'.shstrtab']; shs = b'\0'; noff = []
    for n in names[1:]: noff.append(len(shs)); shs += n + b'\0'
    o_body = eh + ph; o_sym = o_body + len(body); o_str = o_sym + len(symtab); o_shs = o_str + len(strtab); o_sh = (o_shs + len(shs) + 7) & ~7
    ident = b'\x7fELF' + bytes([2 if c64 else 1, 2 if be else 1, 1]) + b'\0' * 9
    hdr = ident + (struct.pack(E + 'HHIQQQIHHHHHH', etype, machine, 1, text_va, eh, o_sh, flags, eh, ph, 1, sh, 5, 4) if c64 else
                   struct.pack(E + 'HHIIIIIHHHHHH', etype, machine, 1, text_va, eh, o_sh, flags, eh, ph, 1, sh, 5, 4))
    ph_b = struct.pack(E + 'IIQQQQQQ', 1, 5, o_body, text_va, text_va, len(body), len(body), 0x1000) if c64 else struct.pack(E + 'IIIIIIII', 1, o_body, text_va, text_va, len(body), len(body), 5, 0x1000)
    def sec(n, ty, addr, o, sz, link=0, ent=0):
        return struct.pack(E + 'IIQQQQIIQQ', n, ty, 6, addr, o, sz, link, 0, 8, ent) if c64 else struct.pack(E + 'IIIIIIIIII', n, ty, 6, addr, o, sz, link, 0, 8, ent)
    shdr = sec(0, 0, 0, 0, 0) + sec(noff[0], 1, text_va, o_body, len(body)) + sec(noff[1], 2, 0, o_sym, len(symtab), 3, 24 if c64 else 16) + sec(noff[2], 3, 0, o_str, len(strtab)) + sec(noff[3], 3, 0, o_shs, len(shs))
    return hdr + ph_b + body + symtab + strtab + shs + b'\0' * (o_sh - o_shs - len(shs)) + shdr

be32 = lambda *w: b''.join(struct.pack('>I', x) for x in w)
# MIPS: addiu v0,zero,4011 (execve); syscall; addiu v0,zero,4170 (connect); syscall; syscall không số
mips_text = be32(0x24020fab, 0x0000000c, 0x2402104a, 0x0000000c, 0x00000000, 0x0000000c)
d = elf(8, 32, True, 2, 0x1007, mips_text, 0x400000)
I = elfinfo.parse(d); assert I['machine'] == 'mips' and elfinfo.abi(I) == 'mips_o32' and elfinfo.ghidra_base(I) == (0, True)
R = syscalls.scan(d); T = syscalls.table('mips_o32')
assert R['total'] == 3 and R['resolved'][4011] == 1 and R['resolved'][4170] == 1 and len(R['unresolved']) == 1, R
assert T[4011] == 'execve' and T[4168] == 'accept' and T[4169] == 'bind' and T[4170] == 'connect' and T[4002] == 'fork'   # không nhầm accept/bind như bảng gõ tay
rep = syscalls.report(d, 'x'); assert 'execve 1' in rep and 'connect 1' in rep and 'fork 0' in rep and 'KHÔNG loại trừ' in rep and 'không có số tức thời 1' in rep
assert elfinfo.ghidra_base(dict(I, etype=3)) == (0x10000, True)   # ET_DYN MIPS32 (đã đo trên một mẫu thật)
# x86-64: mov eax,59; syscall; xor eax,eax; syscall; ET_DYN -> base Ghidra 0x100000
x = elf(62, 64, False, 3, 0, bytes.fromhex('b83b0000000f05' + '31c0' + '0f05'), 0x1000)
Ix = elfinfo.parse(x); assert elfinfo.abi(Ix) == 'x86_64' and elfinfo.ghidra_base(Ix) == (0x100000, True)
Rx = syscalls.scan(x); assert Rx['resolved'][59] == 1 and Rx['resolved'][0] == 1 and syscalls.table('x86_64')[59] == 'execve', Rx
# i386: mov eax,11; int 0x80
i3 = elf(3, 32, False, 2, 0, bytes.fromhex('b80b000000cd80'), 0x8048000); assert syscalls.scan(i3)['resolved'][11] == 1 and syscalls.table('i386')[11] == 'execve'
# ARM: chưa có bảng -> từ chối, không đoán; Ghidra base chưa đo
a = elf(40, 32, False, 3, 0, b'\0' * 8, 0x1000)
try: syscalls.scan(a); raise AssertionError('ARM phải bị từ chối')
except ValueError as e: assert 'chưa có bảng' in str(e)
assert elfinfo.ghidra_base(elfinfo.parse(a)) == (0x10000, False)
try: syscalls.scan(b'MZ' + b'\0' * 64); raise AssertionError('không phải ELF')
except ValueError: pass
# disasm theo tên: hàm A gọi B bằng jal, nạp chuỗi bằng lui+addiu, độ dài Go ở thanh ghi kế tiếp
VA = 0x400000; lit = b'https://c2.example.net/v2\0rest'
fa = VA; fb = VA + 0x40; lit_va = VA + 0x100
code = be32(0x3c010000 | (lit_va >> 16), 0x24210000 | (lit_va & 0xffff), 0x24020019, 0x0c000000 | (fb >> 2), 0x00000000, 0x03e00008, 0x00000000)
code += b'\0' * (0x40 - len(code)) + be32(0x03e00008, 0x00000000)
code += b'\0' * (0x100 - len(code)) + lit
m = elf(8, 32, True, 2, 0x1007, code, VA, syms=[('pkg.A', fa, 0x40), ('pkg.B', fb, 8)])
d_path = os.path.join(tempfile.mkdtemp(), 'm.elf'); open(d_path, 'wb').write(m)
res, lst = disasm.disasm(d_path, ['pkg.A']); assert res[0]['name'] == 'pkg.A' and res[0]['calls'] == ['pkg.B'], res
txt = '\n'.join(res[0]['lines']); assert 'pkg.B' in txt and '"https://c2.example.net/v2"' in txt, txt   # độ dài 0x19 = 25 cắt đúng chuỗi
assert disasm.disasm(d_path, ['0x400004'])[0][0]['name'] == 'pkg.A'   # theo địa chỉ -> hàm chứa nó
assert disasm.disasm(d_path, ['list:pkg.'])[1] == [('pkg.A', fa), ('pkg.B', fb)] or len(disasm.disasm(d_path, ['list:pkg.'])[1]) == 2
try: disasm.disasm(d_path, ['khong.co']); raise AssertionError
except SystemExit as e: assert 'không thấy hàm' in str(e)
# quick: nhóm CLI, mạng, đường dẫn, mật mã; bỏ đường dẫn build thư viện
q = b'\0'.join([b'-key=KEY', b'Usage: tool', b'cdn.example.net', b'http://203.0.113.9/x', b'/etc/app.conf', b'/home/lib/include/x.hpp', b'Invalid token', b'heartbeat sent', b'12345']) + b'\0'
text, sug = quick.build('x', q)
assert '-key=KEY' in text and 'cdn.example.net' in text and 'http://203.0.113.9/x' in text and '/etc/app.conf' in text and 'Invalid token' in text and 'heartbeat sent' in text, text
assert '/home/lib/include/x.hpp' not in text and any(k == 'net' for k, _, _ in sug)
print('OK check_static_tools')

# --- góp ý bot: MIPS little-endian, ghi đè thanh ghi số, delay slot, n32, lea rip
le32 = lambda *w: b''.join(struct.pack('<I', v) for v in w)
ml = elf(8, 32, False, 2, 0x1007, le32(0x24020fab, 0x0000000c), 0x400000)   # mipsel: addiu v0,zero,4011; syscall
Rl = syscalls.scan(ml); assert Rl['resolved'][4011] == 1 and Rl['total'] == 1, Rl
# MIPS: move v0,a0 ghi đè -> chưa xác định (không gán số cũ); delay slot của jr thuộc hàm trước -> chưa xác định
ov = be32(0x24020fab, 0x00801021, 0x0000000c)                                      # addiu v0,4011 ; move v0,a0 ; syscall
ds = be32(0x03e00008, 0x24020fab, 0x0000000c)                                      # jr ra ; addiu v0,4011 (delay slot) ; syscall
for name, code in (('ghi đè', ov), ('delay slot', ds)):
    Rm = syscalls.scan(elf(8, 32, True, 2, 0x1007, code, 0x400000)); assert Rm['total'] == 1 and not Rm['resolved'] and len(Rm['unresolved']) == 1, (name, Rm)
# x86-64: mov eax,1 ... mov eax,[rbp-4] ; syscall -> chưa xác định; mov rax,60 -> 60; pop rax -> chưa xác định
xs = bytes.fromhex('b801000000' + '8b45fc' + '0f05') + bytes.fromhex('48c7c03c000000' + '0f05') + bytes.fromhex('58' + '0f05')
Rs = syscalls.scan(elf(62, 64, False, 3, 0, xs, 0x1000)); assert Rs['total'] == 3 and dict(Rs['resolved']) == {60: 1} and len(Rs['unresolved']) == 2, Rs
# n32 (EF_MIPS_ABI2 = 0x20) bị từ chối, không tra bảng o32
try: syscalls.scan(elf(8, 32, True, 2, 0x20, be32(0), 0x400000)); raise AssertionError('n32 phải bị từ chối')
except ValueError as e: assert 'chưa có bảng' in str(e)
# disasm x86-64: lea rax,[rip+disp] trỏ tới chuỗi được chú thích; mipsel disasm đúng endian
VX = 0x401000; lea = bytes.fromhex('488d05') + struct.pack('<i', 0x20 - 7) + bytes.fromhex('c3')   # lea rax,[rip+0x19]; ret  (chuỗi tại VX+0x20)
xc = lea + b'\0' * (0x20 - len(lea)) + b'/etc/app.conf\0'
xp = os.path.join(tempfile.mkdtemp(), 'x.elf'); open(xp, 'wb').write(elf(62, 64, False, 2, 0, xc, VX, syms=[('fx', VX, 0x20)]))
tx = '\n'.join(disasm.disasm(xp, ['fx'])[0][0]['lines']); assert '"/etc/app.conf"' in tx, tx
lp = os.path.join(tempfile.mkdtemp(), 'l.elf'); open(lp, 'wb').write(elf(8, 32, False, 2, 0x1007, le32(0x03e00008, 0, 0x03e00008, 0), 0x400000, syms=[('fl', 0x400000, 8), ('fm', 0x400008, 8)]))
assert disasm.disasm(lp, ['fl'])[0][0]['lines'][0].split('\t')[1] == 'jr', 'mipsel phải disasm đúng'
print('OK check_static_tools (endian, ghi đè, delay slot, n32, lea rip)')
