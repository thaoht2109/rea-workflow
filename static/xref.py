#!/usr/bin/env python3
# "Ai gọi hàm X" theo TÊN trong ELF (MIPS o32 kể cả PIC qua GOT, x86-64, i386): duyệt từng hàm đã biết tên (symbol, .gopclntab), gom lời gọi trực tiếp (jal/bal/call)
# và gián tiếp đã giải (MIPS: jalr $t9 qua ô GOT trên đoạn chạy thẳng). Trả lời "mẫu có gọi connect/execve... không" tốt hơn đếm số syscall.
# Giới hạn nêu trong output: lời gọi gián tiếp không giải được chỉ đếm, không đoán; "0 nơi gọi" KHÔNG phải kết luận khi còn lời gọi chưa giải. Chỉ đọc file.
#   python3 -I xref.py FILE [TÊN...]
import os, re, sys, collections
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from static import elfinfo, syscalls, mipspic, disasm   # noqa: E402

SENSITIVE = ('execve', 'execv', 'execvp', 'execl', 'execlp', 'execle', 'system', 'popen', 'posix_spawn', 'fork', 'vfork', 'daemon', 'ptrace', 'dlopen', 'mprotect', 'memfd_create',
             'socket', 'connect', 'bind', 'listen', 'accept', 'send', 'sendto', 'sendmsg', 'recv', 'recvfrom', 'recvmsg', 'getaddrinfo', 'gethostbyname',
             'kill', 'unlink', 'rename', 'chmod', 'chown', 'setuid', 'setgid', 'chroot', 'mount', 'reboot', 'prctl', 'shm_open', 'inotify_init')

def build(path, d=None):
    """-> dict(names{địa chỉ: tên}, callers{địa chỉ đích: [(nơi gọi, địa chỉ hàm gọi)]}, stats)."""
    d = d or open(path, 'rb').read(); I = elfinfo.parse(d)
    if I is None: raise ValueError('không phải ELF')
    abi = elfinfo.abi(I)
    if abi is None: raise ValueError(f"chưa hỗ trợ {I['machine']} {I['cls']}-bit (chỉ MIPS o32, x86-64, i386)")
    nm, sz = disasm.names_of(path, d, I)
    if not nm: raise ValueError('không có hàm nào có tên (binary bị strip hết symbol, không phải Go, hoặc ELF hỏng): xref theo tên không dùng được')
    md = syscalls._cs(abi, I['be']); callers = collections.defaultdict(list)
    st = dict(funcs=0, direct=0, indirect_ok=0, indirect_unknown=0)
    for a in sorted(nm):
        end = disasm._bounds(nm, sz, a); o = elfinfo.va2off(I, a)
        if o is None or end <= a or end - a > 1 << 20: continue
        ins = list(md.disasm(d[o:o + (end - a)], a)); st['funcs'] += 1
        tr = mipspic.Tracker(d, I) if abi == 'mips_o32' else None
        targets = {int(mt.group(1), 16) for i in ins for mt in [re.search(r'(0x[0-9a-f]+)$', i.op_str)]
                   if mt and i.mnemonic.startswith(('b', 'j')) and i.mnemonic not in ('jal', 'bal', 'jalr', 'break')} if tr else ()
        for i in ins:
            if tr:
                if i.address in targets: tr.reset()   # điểm hợp lưu: không tin giá trị thanh ghi từ đường khác
                tgt = tr.step(i, entry=a)
                if i.mnemonic in ('jal', 'bal') and re.fullmatch(r'(0x)?[0-9a-f]+', i.op_str): callers[int(i.op_str, 0)].append((i.address, a)); st['direct'] += 1
                elif i.mnemonic == 'jalr':
                    if tgt: callers[tgt].append((i.address, a)); st['indirect_ok'] += 1
                    else: st['indirect_unknown'] += 1
            elif i.mnemonic == 'call':
                if re.fullmatch(r'(0x)?[0-9a-f]+', i.op_str): callers[int(i.op_str, 0)].append((i.address, a)); st['direct'] += 1
                else: st['indirect_unknown'] += 1   # call qua thanh ghi/bộ nhớ (PLT/GOT x86 chưa giải)
    return dict(names=nm, callers=callers, stats=st, abi=abi)

def report(path, queries=(), d=None, name=None):
    X = build(path, d); nm, st = X['names'], X['stats']; dm = disasm.demangle(nm.values()); show = lambda n: dm.get(n, n)
    base = lambda n: re.sub(r'\(.*', '', show(n))   # tên dễ đọc không kèm tham số
    qs = list(queries) or list(SENSITIVE); exact = not queries
    L = [f"# xref {name or os.path.basename(path)}: abi={X['abi']} hàm đã duyệt={st['funcs']} lời gọi trực tiếp={st['direct']} gián tiếp đã giải={st['indirect_ok']} gián tiếp CHƯA giải={st['indirect_unknown']}",
         '# giới hạn: chỉ thấy lời gọi từ hàm có tên; lời gọi gián tiếp chưa giải (con trỏ hàm, bảng ảo, PLT x86) không được tính.',
         '# "0 nơi gọi" hoặc "không có symbol" KHÔNG chứng minh mẫu không dùng hàm đó khi còn lời gọi chưa giải hoặc binary bị strip/inline.']
    missing = []
    for q in qs:
        hit = sorted(a for a, n in nm.items() if n == q or base(n) == q) or ([] if exact else sorted(a for a, n in nm.items() if q in n or q in show(n))[:20])
        if not hit: missing.append(q); continue
        for a in hit:
            cs_ = X['callers'].get(a, [])
            L.append(f'## {show(nm[a])} @{a:#x}: {len(cs_)} nơi gọi')
            L += [f'{site:#x} trong {show(nm.get(fa, f"sub_{fa:x}"))}' for site, fa in cs_[:40]]
            if len(cs_) > 40: L.append(f'(+{len(cs_) - 40} nơi gọi nữa)')
    imp = set(elfinfo.imports(d or open(path, 'rb').read(), elfinfo.parse(d or open(path, 'rb').read())))
    und = [q for q in missing if q in imp]; missing = [q for q in missing if q not in imp]
    L.append('## nhập khẩu từ thư viện động (UND; mẫu CÓ tham chiếu, nơi gọi qua PLT/GOT động chưa giải): ' + (', '.join(und) if und else '(không)'))
    L.append('## không có symbol tên: ' + (', '.join(missing) if missing else '(không)'))
    return '\n'.join(L) + '\n'

if __name__ == '__main__':
    try: print(report(sys.argv[1], sys.argv[2:]), end='')
    except ValueError as e: raise SystemExit(str(e))
