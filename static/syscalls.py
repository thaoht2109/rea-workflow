#!/usr/bin/env python3
# Thống kê lệnh syscall trong .text của ELF (MIPS o32, x86-64, i386), tên theo bảng kernel (static/data/syscalls_<abi>.json).
# Chỉ đọc và disasm tĩnh, không chạy mẫu. Giới hạn nói thẳng trong output: syscall có số đặt gián tiếp (hàm bọc, tham số) chỉ liệt kê địa chỉ.
#   python3 -I syscalls.py FILE
import os, re, sys, json, collections
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from static import elfinfo   # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
SENSITIVE = ('fork', 'vfork', 'clone', 'execve', 'execveat', 'ptrace', 'unlink', 'unlinkat', 'rename', 'chmod', 'fchmod', 'kill', 'tkill', 'tgkill', 'socket', 'connect', 'bind',
             'listen', 'accept', 'accept4', 'sendto', 'recvfrom', 'sendmsg', 'recvmsg', 'open', 'openat', 'mkdir', 'setuid', 'setgid', 'chroot', 'symlink', 'reboot', 'mount',
             'prctl', 'shmget', 'shmat', 'init_module', 'finit_module', 'memfd_create', 'socketcall')

def table(abi):
    return {int(k): v for k, v in json.load(open(os.path.join(HERE, 'data', f'syscalls_{abi}.json')))['names'].items()}

def _cs(abi):
    try: import capstone as cs
    except ImportError:
        import reacfg; sys.path.insert(0, reacfg.PYLIB)   # capstone cài ở pylib của skill
        import capstone as cs
    mode = {'mips_o32': cs.CS_MODE_MIPS32 + cs.CS_MODE_BIG_ENDIAN, 'x86_64': cs.CS_MODE_64, 'i386': cs.CS_MODE_32}[abi]
    md = cs.Cs({'mips_o32': cs.CS_ARCH_MIPS}.get(abi, cs.CS_ARCH_X86), mode); md.skipdata = True
    return md

def _imm(s):
    try: return int(s, 0)
    except ValueError: return None

def scan(d, I=None):
    """-> dict(abi, text=(va, size), total, resolved{số: lệnh}, unresolved[địa chỉ]); lỗi ValueError nếu kiến trúc chưa có bảng."""
    I = I or elfinfo.parse(d)
    if I is None: raise ValueError('không phải ELF')
    abi = elfinfo.abi(I)
    if abi is None: raise ValueError(f"chưa có bảng syscall cho {I['machine']} {I['cls']}-bit (flags {I['flags']:#x}): chỉ hỗ trợ MIPS o32, x86-64, i386; không đoán số")
    t = I['sections'].get('.text')
    if not t: raise ValueError('không có section .text (ELF không có section header)')
    md = _cs(abi); ins = list(md.disasm(d[t['off']:t['off'] + t['size']], t['addr']))
    res, unres = collections.Counter(), []
    for k, i in enumerate(ins):
        if abi == 'mips_o32': hit = i.mnemonic == 'syscall'
        elif abi == 'x86_64': hit = i.mnemonic == 'syscall'
        else: hit = i.mnemonic == 'int' and i.op_str.strip() == '0x80'
        if not hit: continue
        n = None
        for p in reversed(ins[max(0, k - 8):k]):
            if p.mnemonic in ('syscall', 'jr', 'ret', 'int'): break   # không đi qua syscall/return trước đó: tránh gán số của lệnh khác
            if abi == 'mips_o32' and p.mnemonic in ('addiu', 'ori'):
                m = re.match(r'\$v0, \$zero, (\S+)$', p.op_str)
                if m: n = _imm(m.group(1)); break
            elif abi != 'mips_o32' and p.mnemonic in ('mov', 'xor'):
                m = re.match(r'e?ax, (\S+)$', p.op_str)
                if m and p.mnemonic == 'mov': n = _imm(m.group(1)); break
                if p.mnemonic == 'xor' and p.op_str.replace(' ', '') in ('eax,eax', 'rax,rax'): n = 0; break
        if n is not None: res[n] += 1
        else: unres.append(i.address)
    return dict(abi=abi, text=(t['addr'], t['size']), ninstr=len(ins), total=sum(res.values()) + len(unres), resolved=res, unresolved=unres)

def report(d, name='FILE'):
    R = scan(d); T = table(R['abi']); res = R['resolved']
    L = [f"# syscalls {name}: abi={R['abi']} .text={R['text'][0]:#x} size={R['text'][1]} lệnh={R['ninstr']} (bảng: static/data/syscalls_{R['abi']}.json, từ header kernel)",
         f"syscall tổng {R['total']} | số tức thời {sum(res.values())} | không có số tức thời {len(R['unresolved'])}",
         '# giới hạn: số đặt gián tiếp (hàm bọc, tham số, GOT/jalr) không giải được; vắng mặt một syscall ở đây KHÔNG loại trừ nó nếu còn syscall chưa xác định số',
         '--- đã xác định (số tên: số lệnh)']
    L += [f'{n} {T.get(n, "?")} {c}' for n, c in sorted(res.items(), key=lambda x: (-x[1], x[0]))]
    L.append('--- nhạy cảm (tên: số lệnh)')
    rev = collections.defaultdict(int)
    for n, c in res.items(): rev[T.get(n, '?')] += c
    L += [f'{nm} {rev.get(nm, 0)}' for nm in SENSITIVE if nm in set(T.values())]
    L.append('--- chưa xác định số (địa chỉ)')
    L += [f'{a:#x}' for a in R['unresolved']]
    return '\n'.join(L) + '\n'

if __name__ == '__main__':
    try: print(report(open(sys.argv[1], 'rb').read(), os.path.basename(sys.argv[1])), end='')
    except ValueError as e: raise SystemExit(str(e))
