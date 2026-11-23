#!/usr/bin/env python3
# Thống kê lệnh syscall trong .text của ELF (MIPS o32, x86-64, i386), tên theo bảng kernel (static/data/syscalls_<abi>.json).
# Chỉ đọc và disasm tĩnh, không chạy mẫu. Giới hạn nói thẳng trong output: syscall có số đặt gián tiếp (hàm bọc, tham số) chỉ liệt kê địa chỉ.
#   python3 -I syscalls.py FILE
import os, re, sys, json, collections
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from static import elfinfo, mipspic   # noqa: E402
from static.mipspic import WRITES
import bisect

HERE = os.path.dirname(os.path.abspath(__file__))
SENSITIVE = ('fork', 'vfork', 'clone', 'execve', 'execveat', 'ptrace', 'unlink', 'unlinkat', 'rename', 'chmod', 'fchmod', 'kill', 'tkill', 'tgkill', 'socket', 'connect', 'bind',
             'listen', 'accept', 'accept4', 'sendto', 'recvfrom', 'sendmsg', 'recvmsg', 'open', 'openat', 'mkdir', 'setuid', 'setgid', 'chroot', 'symlink', 'reboot', 'mount',
             'prctl', 'shmget', 'shmat', 'init_module', 'finit_module', 'memfd_create', 'socketcall')

def table(abi):
    return {int(k): v for k, v in json.load(open(os.path.join(HERE, 'data', f'syscalls_{abi}.json')))['names'].items()}

def _cs(abi, be=True):
    try: import capstone as cs
    except ImportError:
        import reacfg; sys.path.insert(0, reacfg.PYLIB)   # capstone cài ở pylib của skill
        import capstone as cs
    mode = {'mips_o32': cs.CS_MODE_MIPS32 + (cs.CS_MODE_BIG_ENDIAN if be else cs.CS_MODE_LITTLE_ENDIAN), 'x86_64': cs.CS_MODE_64, 'i386': cs.CS_MODE_32}[abi]
    md = cs.Cs({'mips_o32': cs.CS_ARCH_MIPS}.get(abi, cs.CS_ARCH_X86), mode); md.skipdata = True
    return md

def _imm(s):
    try: return int(s, 0)
    except ValueError: return None

_REG = {'mips_o32': ('$v0', '$2'), 'x86_64': ('al', 'ax', 'eax', 'rax'), 'i386': ('al', 'ax', 'eax')}
_BR = {'mips_o32': ('jr', 'j', 'jal', 'jalr', 'b', 'beq', 'bne', 'beqz', 'bnez', 'bal', 'bgez', 'bgtz', 'blez', 'bltz', 'bc1t', 'bc1f'), 'x86_64': ('call', 'jmp', 'ret'), 'i386': ('call', 'jmp', 'ret')}

def _number(abi, ins, k):
    """Số syscall của lệnh ins[k]: lệnh gần nhất GHI vào thanh ghi số phải là nạp hằng tức thời, ngược lại chưa xác định (None).
    Dừng ở syscall/int, nhánh/gọi/return (x86), và ở delay slot của nhánh MIPS (lệnh đó thuộc luồng khác)."""
    for j in range(k - 1, max(-1, k - 9), -1):
        p = ins[j]
        if p.mnemonic in ('syscall', 'int') or p.mnemonic in _BR[abi] and abi != 'mips_o32': return None
        if abi == 'mips_o32':
            if p.mnemonic in _BR[abi]: return None
            if j > 0 and ins[j - 1].mnemonic in _BR[abi]: return None   # p là delay slot của nhánh trước nó
            dst, _, src = p.op_str.partition(',')
            if dst.strip() in _REG[abi]:
                m = re.match(r'\s*\$zero, (\S+)$', src)
                return _imm(m.group(1)) if p.mnemonic in ('addiu', 'ori') and m else None
        else:
            dst, _, src = p.op_str.partition(',')
            if dst.strip() in _REG[abi]:
                if p.mnemonic == 'mov': return _imm(src.strip())
                if p.mnemonic == 'xor' and src.strip() == dst.strip(): return 0
                return None
    return None

def _a0_to_v0(seq):
    """Đoạn từ đầu hàm tới syscall có đưa $a0 (đối số đầu = số syscall) vào $v0, kể cả qua bản sao (move $s0,$a0 ... addu $v0,$zero,$s0)."""
    alias = {'$a0'}
    for p in seq:
        ops = [x.strip() for x in p.op_str.split(',')]
        if p.mnemonic == 'move' and len(ops) == 2:
            if ops[1] in alias:
                if ops[0] == '$v0': return True
                alias.add(ops[0])
            else: alias.discard(ops[0])
        elif p.mnemonic == 'addu' and len(ops) == 3 and ops[1] == '$zero' and ops[2] in alias:
            if ops[0] == '$v0': return True
            alias.add(ops[0])
        elif p.mnemonic in WRITES and ops and ops[0].startswith('$'): alias.discard(ops[0])
    return False

def scan(d, I=None):
    """-> dict(abi, text=(va, size), total, resolved{số: lệnh}, unresolved[địa chỉ]); lỗi ValueError nếu kiến trúc chưa có bảng."""
    I = I or elfinfo.parse(d)
    if I is None: raise ValueError('không phải ELF')
    abi = elfinfo.abi(I)
    if abi is None: raise ValueError(f"chưa có bảng syscall cho {I['machine']} {I['cls']}-bit (flags {I['flags']:#x}): chỉ hỗ trợ MIPS o32, x86-64, i386; không đoán số")
    t = I['sections'].get('.text')
    if not t: raise ValueError('không có section .text (ELF không có section header)')
    md = _cs(abi, I['be']); ins = list(md.disasm(d[t['off']:t['off'] + t['size']], t['addr']))
    res, unres = collections.Counter(), []
    for k, i in enumerate(ins):
        if abi == 'mips_o32': hit = i.mnemonic == 'syscall'
        elif abi == 'x86_64': hit = i.mnemonic == 'syscall'
        else: hit = i.mnemonic == 'int' and i.op_str.strip() == '0x80'
        if not hit: continue
        n = _number(abi, ins, k)
        if n is not None: res[n] += 1
        else: unres.append(i.address)
    via, wrappers, left = collections.Counter(), [], list(unres)
    if abi == 'mips_o32' and unres:   # hàm bọc nhận số ở $a0 (syscall() chung, __syscall_cp...): giải số ở nơi gọi qua GOT (PIC) hoặc jal
        starts = sorted(v for n, v, sz, ty in elfinfo.symbols(d, I) if ty == 2 and v)
        idx = {i.address: k for k, i in enumerate(ins)}; W = {}
        def fstart(u):   # hàm musl nội bộ bị strip không có symbol: lấy sau `jr $ra` + delay slot gần nhất, hoặc symbol nếu gần hơn
            k = idx[u]
            while k > 0 and not (k >= 2 and ins[k - 2].mnemonic == 'jr' and ins[k - 2].op_str == '$ra'): k -= 1
            sy = starts[bisect.bisect_right(starts, u) - 1] if starts and bisect.bisect_right(starts, u) else 0
            return max(ins[k].address, sy)
        for u in unres:
            st = fstart(u)
            if _a0_to_v0(ins[idx[st]:idx[u]]): W[st] = W.get(st, 0) + 1
        if W:
            tr = mipspic.Tracker(d, I); calls_w = collections.Counter(); nocall = 0
            for k, i in enumerate(ins):
                tgt = tr.step(i)
                if i.mnemonic in ('jal', 'j', 'bal') and re.fullmatch(r'(0x)?[0-9a-f]+', i.op_str): tgt = int(i.op_str, 0)
                if tgt in W:
                    n = tr.regs.get('$a0'); calls_w[tgt] += 1
                    ds = ins[k + 1] if k + 1 < len(ins) else None   # delay slot của jalr/jal chạy trước khi vào hàm: thường nạp $a0 ở đây
                    if ds is not None and ds.mnemonic in ('addiu', 'ori'):
                        m = re.match(r'\$a0, \$zero, (\S+)$', ds.op_str)
                        if m: n = _imm(m.group(1))
                    if n and 0 < n < 0x2000: via[n] += 1
                    else: nocall += 1
            names = {v: n for n, v, sz, ty in elfinfo.symbols(d, I) if ty == 2}
            wrappers = [(a, names.get(a, f'sub_{a:x}'), calls_w[a]) for a in sorted(W)]
            left = [u for u in unres if not (fstart(u) in W and calls_w[fstart(u)] > 0)]   # hàm bọc chưa thấy nơi gọi nào: syscall bên trong vẫn là chưa xác định   # syscall nằm trong hàm bọc đã giải ở nơi gọi: không còn "chưa xác định" theo từng lệnh
            via['_nocall'] = nocall
    return dict(abi=abi, text=(t['addr'], t['size']), ninstr=len(ins), total=sum(res.values()) + len(unres), resolved=res, unresolved=left, via=via, wrappers=wrappers, in_wrappers=len(unres) - len(left))

def report(d, name='FILE'):
    R = scan(d); T = table(R['abi']); res = R['resolved']
    L = [f"# syscalls {name}: abi={R['abi']} .text={R['text'][0]:#x} size={R['text'][1]} lệnh={R['ninstr']} (bảng: static/data/syscalls_{R['abi']}.json, từ header kernel)",
         f"syscall tổng {R['total']} | số tức thời {sum(res.values())} | trong hàm bọc nhận số ở $a0 {R['in_wrappers']} | còn chưa xác định {len(R['unresolved'])}",
         '# giới hạn: số đặt gián tiếp (hàm bọc, tham số, GOT/jalr) không giải được; vắng mặt một syscall ở đây KHÔNG loại trừ nó nếu còn syscall chưa xác định số',
         '--- đã xác định (số tên: số lệnh)']
    L += [f'{n} {T.get(n, "?")} {c}' for n, c in sorted(res.items(), key=lambda x: (-x[1], x[0]))]
    if R['wrappers']:
        nv = R['via'].pop('_nocall', 0); L.append('--- hàm bọc nhận số syscall ở $a0 (địa chỉ tên số lời gọi); số giải ở nơi gọi (GOT/jal)')
        L += [f'{a:#x} {n} {c}' for a, n, c in R['wrappers']]
        L.append(f'lời gọi không đọc được số ở $a0: {nv}'); L.append('--- số qua hàm bọc (số tên: số lời gọi)')
        L += [f'{n} {T.get(n, "?")} {c}' for n, c in sorted(R['via'].items(), key=lambda x: (-x[1], x[0]))]
    L.append('--- nhạy cảm (tên: số lệnh; gồm cả số qua hàm bọc)')
    rev = collections.defaultdict(int)
    for n, c in list(res.items()) + [(n, c) for n, c in R['via'].items() if n != '_nocall']: rev[T.get(n, '?')] += c
    L += [f'{nm} {rev.get(nm, 0)}' for nm in SENSITIVE if nm in set(T.values())]
    L.append('--- chưa xác định số (địa chỉ)')
    L += [f'{a:#x}' for a in R['unresolved']]
    return '\n'.join(L) + '\n'

if __name__ == '__main__':
    try: print(report(open(sys.argv[1], 'rb').read(), os.path.basename(sys.argv[1])), end='')
    except ValueError as e: raise SystemExit(str(e))
