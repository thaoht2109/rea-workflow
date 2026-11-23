#!/usr/bin/env python3
# static/elfinfo.py, syscalls.py, disasm.py, quick.py trên ELF tổng hợp (MIPS o32 BE, x86-64, i386, ARM bị từ chối). Chạy: python3 tests/check_static_tools.py
import os, re, sys, struct, tempfile
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

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
# --- góp ý bot (lượt 2): ELF hỏng không sập, gợi ý path đủ token, tên evidence không trùng, vỏ flow.py, dec va: không đưa địa chỉ Ghidra cho rea
import subprocess
good = elf(8, 32, True, 2, 0x1007, mips_text, 0x400000)
for name, bad in (('cắt cụt', good[:60]), ('e_shentsize hỏng', good[:46] + struct.pack('>H', 3) + good[48:]), ('e_phentsize hỏng', good[:42] + struct.pack('>H', 5) + good[44:]),
                  ('e_shoff ngoài file', good[:32] + struct.pack('>I', 0x7fffff00) + good[36:]), ('e_shnum lớn', good[:48] + struct.pack('>H', 60000) + good[50:])):
    Ib = elfinfo.parse(bad)
    assert Ib is None or Ib['broken'] or Ib['machine'] == 'mips', name
    try: syscalls.report(bad, 'x')
    except ValueError: pass   # báo lỗi rõ, không phải struct.error
    quick.build('x', bad)   # không ném
assert elfinfo.parse(good[:60]) is None or elfinfo.parse(good[:60])['broken']
_, sg = quick.build('x', b'\0'.join([b'config.json', b'/etc/ok.conf', b'a.pid']) + b'\0')
vals = [v for k, v, _ in sg if k == 'path']; assert 'config.json' in vals and '/etc/ok.conf' in vals and '.json' not in vals and '.pid' not in vals, vals   # đủ token; token < 5 ký tự bị bỏ
W = tempfile.mkdtemp(); C = os.path.join(W, 'C1'); os.makedirs(os.path.join(C, 'work', 'sample')); os.makedirs(os.path.join(C, 'report', 'evidence'))
two = elf(8, 32, True, 2, 0x1007, be32(0x03e00008, 0, 0x03e00008, 0), 0x400000, syms=[('a.b', 0x400000, 8), ('a_b', 0x400008, 8)])   # hai tên cho cùng chuỗi rút gọn
open(os.path.join(C, 'work', 'sample', 'm.elf'), 'wb').write(two)
run = lambda *a: subprocess.run([sys.executable, os.path.join(ROOT, 'flow.py'), *a], cwd=W, capture_output=True, text=True)
r = run('quick', 'C1', 'm.elf'); assert r.returncode == 0 and 'Traceback' not in r.stderr and os.path.isfile(os.path.join(C, 'report', 'evidence', 'quick_m_elf.txt')), r.stderr[-300:]
r = run('syscalls', 'C1', 'm.elf'); assert r.returncode == 0 and os.path.isfile(os.path.join(C, 'report', 'evidence', 'syscalls_m_elf.txt')), r.stderr[-300:]
r = run('disasm', 'C1', 'm.elf', 'a.b', 'a_b'); ev = [f for f in os.listdir(os.path.join(C, 'report', 'evidence')) if f.startswith('disasm_')]
assert r.returncode == 0 and len(ev) == 2, (r.stdout, r.stderr[-300:], ev)   # hai hàm, hai file (tên kèm địa chỉ)
r = run('disasm', 'C1', 'm.elf', 'khong.co'); assert r.returncode != 0 and 'không thấy hàm' in (r.stdout + r.stderr) and 'Traceback' not in r.stderr
open(os.path.join(C, 'work', 'sample', 'bad.elf'), 'wb').write(good[:60]); r = run('syscalls', 'C1', 'bad.elf'); assert r.returncode != 0 and 'Traceback' not in r.stderr
r = run('quick', 'C1', 'khong_co.elf'); assert r.returncode != 0 and 'không thấy mẫu' in (r.stdout + r.stderr)
# dec va:: địa chỉ cộng base Ghidra chỉ đi Ghidra; hàm thường vẫn qua rea; rea báo capability_unavailable thì rơi về Ghidra
import flow, types   # noqa: E402
xd = os.path.join(W, 'x.elf'); open(xd, 'wb').write(elf(62, 64, False, 3, 0, bytes.fromhex('c3'), 0x1000))
calls = {'rea': [], 'ghidra': []}
real = (flow.CFG.unix_socket_ok, flow.ghidra_dec, flow.subprocess.run)
flow.CFG.unix_socket_ok = lambda: True
flow.ghidra_dec = lambda c, f, funcs, od, tag: calls['ghidra'].append(list(funcs))
flow.subprocess.run = lambda cmd, **k: calls['rea'].append(cmd) or types.SimpleNamespace(stdout='{"error": 1, "code": "capability_unavailable"}', stderr='', returncode=0)
try:
    flow.dec(os.path.join(W, 'C1'), xd, ['va:0x1010', 'main'])
    assert calls['ghidra'] == [['main', '0x101010']], calls   # main rơi về Ghidra sau capability_unavailable, 0x101010 = 0x1010 + base 0x100000 (x86-64 ET_DYN)
    assert [c for c in calls['rea'] if any('--procedure=' in x for x in c)] and all('0x101010' not in ' '.join(c) and 'va:' not in ' '.join(c) for c in calls['rea']), calls['rea']
    calls['rea'].clear(); calls['ghidra'].clear(); flow.dec(os.path.join(W, 'C1'), xd, ['va:0x20'])
    assert calls['rea'] == [] and calls['ghidra'] == [['0x100020']], calls   # chỉ có va: thì rea không được gọi
    try: flow.dec(os.path.join(W, 'C1'), xd, ['va:zz']); raise AssertionError('va: sai phải dừng')
    except SystemExit as e: assert 'không hợp lệ' in str(e)
finally: flow.CFG.unix_socket_ok, flow.ghidra_dec, flow.subprocess.run = real
print('OK check_static_tools (ELF hỏng, vỏ flow.py, dec va:)')

# --- MIPS PIC: gp từ prologue, lw $t9 qua GOT + jalr, chuỗi gp-relative; hàm bọc nhận số ở $a0; SPEC địa chỉ ngoài hàm; gợi ý quick
VP = 0x400000; fb2 = VP + 0x80
pic = be32(0x3c1c0000, 0x279c0200, 0x0399e021,                          # lui gp,0 ; addiu gp,gp,0x200 ; addu gp,gp,t9
           0x8f99fff0, 0x8f85fff4,                                      # lw t9,-0x10(gp) ; lw a1,-0xc(gp)
           0x24a50004, 0x0320f809, 0x00000000, 0x03e00008, 0x00000000)  # addiu a1,a1,4 ; jalr t9 ; nop ; jr ra ; nop
pic += b'\0' * (0x80 - len(pic)) + be32(0x03e00008, 0)                   # hàm B tại +0x80
pic += b'\0' * (0x1f0 - len(pic)) + be32(fb2, VP + 0x300)                # GOT: [gp-0x10]=B, [gp-0xc]=nền chuỗi
pic += b'\0' * (0x304 - len(pic)) + b'hello pic\0'
pp = os.path.join(tempfile.mkdtemp(), 'p.elf'); open(pp, 'wb').write(elf(8, 32, True, 3, 0x1007, pic, VP, syms=[('pic_a', VP, 0x80), ('pic_b', fb2, 8)]))
rp, _ = disasm.disasm(pp, ['pic_a']); tp = '\n'.join(rp[0]['lines']); assert rp[0]['calls'] == ['pic_b'] and '"hello pic"' in tp, tp
# SPEC địa chỉ nằm ngoài mọi hàm: bắt đầu tại chính địa chỉ đó, không gán cho hàm cuối
nm_, sz_ = {0x400000: 'f1', 0x400080: 'f2'}, {0x400000: 0x80, 0x400080: 8}
assert disasm.pick(nm_, ['0x400084'], sz_)[0] == [('f2', 0x400080)] and disasm.pick(nm_, ['0x400200'], sz_)[0] == [('sub_400200', 0x400200)]
# quick: gợi ý ELF, tham số dòng lệnh, lớp C++ kèm dòng
tq, sq = quick.build('x', elf(62, 64, False, 3, 0, b'\xc3', 0x1000, syms=[('_ZN4Auth3runEv', 0x1000, 1), ('_ZN7Forward3runEv', 0x1000, 1)]) + b'\0-key=KEY\0Usage: x\0')
ks = {k for k, _, _ in sq}; assert {'cls', 'cli'} <= ks and 'elf' not in ks, sq   # không gợi ý fact cho dòng ELF (triage đã ghi filetype)
for k, v, ln in sq: assert 1 <= ln <= tq.count('\n') + 1 and tq.splitlines()[ln - 1].strip() and (k != 'cli' or v in tq.splitlines()[ln - 1]), (k, v, ln)
r = run('quick', 'C1'); assert r.returncode != 0 and 'dùng:' in (r.stdout + r.stderr) and 'Traceback' not in r.stderr
r = run('disasm', 'C1', 'm.elf'); assert r.returncode != 0 and 'dùng:' in (r.stdout + r.stderr)
print('OK check_static_tools (PIC, quick gợi ý, tham số)')

# --- bộ theo dõi PIC chỉ tin đoạn chạy thẳng: đích nhánh nằm giữa lw t9 và jalr -> không gán tên; sau j/b/jr trạng thái bị bỏ
def picfn(mid):   # prologue gp ; lw t9,-0x10(gp) ; <mid> ; jalr t9 ; nop ; jr ra ; nop  (GOT[gp-0x10] = pic_b)
    c = be32(0x3c1c0000, 0x279c0200, 0x0399e021, 0x8f99fff0) + mid + be32(0x0320f809, 0, 0x03e00008, 0)
    c += b'\0' * (0x80 - len(c)) + be32(0x03e00008, 0); c += b'\0' * (0x1f0 - len(c)) + be32(VP + 0x80, 0)
    f = os.path.join(tempfile.mkdtemp(), 'q.elf'); open(f, 'wb').write(elf(8, 32, True, 3, 0x1007, c, VP, syms=[('pic_a', VP, 0x80), ('pic_b', VP + 0x80, 8)])); return f
assert disasm.disasm(picfn(b''), ['pic_a'])[0][0]['calls'] == ['pic_b']                                   # chạy thẳng: giải được
jal_at = VP + 0x10 + 8   # địa chỉ lệnh jalr khi mid dài 2 lệnh
r1 = disasm.disasm(picfn(be32(0x10000000 | (((jal_at - (VP + 0x10 + 4)) >> 2) & 0xffff), 0)), ['pic_a'])[0][0]   # mid = beq zero,zero,<jalr> ; nop -> jalr là đích nhánh
assert r1['calls'] == [], r1['calls']
r2 = disasm.disasm(picfn(be32(0x08000000 | ((VP + 0x40) >> 2), 0)), ['pic_a'])[0][0]; assert 'pic_b' not in r2['calls'], r2['calls']   # mid = j xa ; nop -> đoạn sau không nối tiếp, jalr không được gán pic_b
r3 = disasm.disasm(picfn(be32(0x0c000000 | ((VP + 0x80) >> 2), 0)), ['pic_a'])[0][0]; assert [l for l in r3['lines'] if '\tjalr\t' in l][0].endswith('$t9'), r3['lines']   # mid = jal pic_b ; nop -> t9 (caller-saved) bị bỏ, dòng jalr sau không có chú thích
print('OK check_static_tools (PIC chỉ đoạn chạy thẳng)')

# --- lệnh ghi thanh ghi chưa mô hình hóa (movz/movn/seb...) phải làm mất giá trị: không gán tên, không chú thích chuỗi
for nm_, w in (('movz', 0x0202C80A), ('movn', 0x0202C80B)):                      # movz/movn $t9,$s0,$v0 chen giữa lw $t9 và jalr
    rz = disasm.disasm(picfn(be32(w)), ['pic_a'])[0][0]
    assert rz['calls'] == [] and [l for l in rz['lines'] if '\tjalr\t' in l][0].endswith('$t9'), (nm_, rz['calls'])
def picstr(mid):   # prologue gp ; lw a1,-0xc(gp) ; <mid> ; addiu a1,a1,4 ; jr ra ; nop  (GOT[gp-0xc] = nền chuỗi, chuỗi tại nền+4)
    c = be32(0x3c1c0000, 0x279c0200, 0x0399e021, 0x8f85fff4) + mid + be32(0x24a50004, 0x03e00008, 0)
    c += b'\0' * (0x1f0 - len(c)) + be32(0, VP + 0x300); c += b'\0' * (0x304 - len(c)) + b'hello pic\0'
    f = os.path.join(tempfile.mkdtemp(), 's.elf'); open(f, 'wb').write(elf(8, 32, True, 3, 0x1007, c, VP, syms=[('pic_s', VP, 0x80)])); return f
assert '"hello pic"' in '\n'.join(disasm.disasm(picstr(b''), ['pic_s'])[0][0]['lines'])                       # chạy thẳng: chú thích được
for w in (0x0202280A, 0x7c052c20, 0x00a62804):                                   # movz $a1,$s0,$v0 ; seb $a1,$a1 ; sllv $a1,$a2,$a1
    assert '"hello pic"' not in '\n'.join(disasm.disasm(picstr(be32(w)), ['pic_s'])[0][0]['lines']), hex(w)
assert '"hello pic"' in '\n'.join(disasm.disasm(picstr(be32(0xafa50010)), ['pic_s'])[0][0]['lines'])          # sw $a1,0x10($sp): store không làm mất giá trị
# --- demangle bằng c++filt: tìm theo tên dễ đọc, list:, tên hàm và lời gọi trong kết quả
import shutil
if shutil.which('c++filt') is None:
    assert not os.environ.get('CI'), 'CI phải có c++filt (binutils) để kiểm demangle'
    print('bỏ qua kiểm demangle: máy không có c++filt')
else:
    VD = 0x400000; cd = be32(0x0c000000 | ((VD + 0x40) >> 2), 0, 0x03e00008, 0); cd += b'\0' * (0x40 - len(cd)) + be32(0x03e00008, 0)
    dp = os.path.join(tempfile.mkdtemp(), 'd.elf'); open(dp, 'wb').write(elf(8, 32, True, 2, 0x1007, cd, VD, syms=[('_ZN3Net4MainEv', VD, 0x40), ('_ZN3Net7ConnectEv', VD + 0x40, 8)]))
    rd, _ = disasm.disasm(dp, ['Net::Main']); assert rd[0]['name'] == 'Net::Main()' and rd[0]['calls'] == ['Net::Connect()'], rd[0]
    assert [n for n, _ in disasm.disasm(dp, ['list:Net::'])[1]] == ['_ZN3Net4MainEv', '_ZN3Net7ConnectEv']
    assert disasm.disasm(dp, ['_ZN3Net7ConnectEv'])[0][0]['name'] == 'Net::Connect()'
print('OK check_static_tools (mặc định mất giá trị, demangle)')

# --- vỏ flow.py quick: lệnh gợi ý phải in đúng kind (không in cả dict), tối đa 3 mỗi nhóm, nhóm lớp C++ vẫn hiện khi có nhiều chuỗi
qs = b'\0'.join([b'-key=KEY', b'-mode=MODE', b'-out=OUT', b'-extra=EXTRA'] + [b'http://203.0.113.%d/x' % n for n in range(9)] + [b'/etc/app%d.conf' % n for n in range(9)]) + b'\0'
open(os.path.join(C, 'work', 'sample', 'q.elf'), 'wb').write(elf(62, 64, False, 3, 0, b'\xc3', 0x1000, syms=[('_ZN3Net4MainEv', 0x1000, 1), ('_ZN4Auth3runEv', 0x1000, 1)]) + qs)
r = run('quick', 'C1', 'q.elf'); out = r.stdout; assert r.returncode == 0 and "{'net'" not in out and 'kind={' not in out, out[-400:]
import collections
kc = collections.Counter(re.findall(r' kind=(\w+) ', out)); assert kc == {'config': 3, 'url': 3, 'file': 3, 'string': 1}, (kc, out)
for ln_ in [l for l in out.splitlines() if 'gợi ý:' in l]:
    m_ = re.search(r'id=(s\.[\w.]+) kind=(\w+) value=(.+?) src=S evidence=(report/evidence/quick_q_elf\.txt)#L(\d+)', ln_); assert m_, ln_
    line_ = open(os.path.join(C, m_.group(4)), encoding='utf-8').read().splitlines()[int(m_.group(5)) - 1]
    assert m_.group(3).strip("'").split(':')[-1].strip().split(',')[0] in line_ or m_.group(2) == 'string', (ln_, line_)   # #L trỏ đúng dòng chứa giá trị
print('OK check_static_tools (gợi ý quick qua flow.py)')
