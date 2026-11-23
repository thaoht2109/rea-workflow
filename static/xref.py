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

GO_SENSITIVE = ('os/exec.Command', 'os/exec.(*Cmd).Start', 'os/exec.(*Cmd).Run', 'os.StartProcess', 'syscall.Exec', 'syscall.ForkExec', 'syscall.StartProcess', 'syscall.Kill',
                'syscall.PtraceAttach', 'plugin.Open', 'net.Dial', 'net.DialTimeout', 'net.(*Dialer).DialContext', 'net.Listen', 'net/http.(*Client).do', 'net/http.(*Client).Get',
                'net/http.NewRequestWithContext', 'net/http.ListenAndServe', 'crypto/tls.Dial', 'os.WriteFile', 'os.Remove', 'os.Rename', 'os.Chmod', 'os.Symlink', 'syscall.Mount', 'syscall.Reboot')

def build(path, d=None):
    """-> dict(names{địa chỉ: tên}, callers{địa chỉ đích: [(nơi gọi, địa chỉ hàm gọi)]}, stats)."""
    d = d or open(path, 'rb').read(); I = elfinfo.parse(d)
    if I is None: raise ValueError('không phải ELF')
    abi = elfinfo.abi(I)
    if abi is None: raise ValueError(f"chưa hỗ trợ {I['machine']} {I['cls']}-bit (chỉ MIPS o32, x86-64, i386)")
    nm, sz = disasm.names_of(path, d, I)
    if not nm: raise ValueError('không có hàm nào có tên (binary bị strip hết symbol, không phải Go, hoặc ELF hỏng): xref theo tên không dùng được')
    md = syscalls._cs(abi, I['be']); callers = collections.defaultdict(list)
    st = dict(funcs=0, direct=0, indirect_ok=0, indirect_unknown=0, plt=0)
    plt = elfinfo.plt_ranges(I) if abi != 'mips_o32' else []; slots = elfinfo.got_relocs(d, I) if plt else {}; pstub = {}
    in_plt = lambda t: any(lo <= t < hi for lo, hi in plt)
    def plt_name(t):   # stub PLT: jmp [rip+disp] (x86-64) hoặc jmp [địa chỉ] (i386 không PIC) -> ô GOT -> tên symbol theo relocation
        if t not in pstub:
            pstub[t] = None; o = elfinfo.va2off(I, t)
            for j in (md.disasm(d[o:o + 16], t) if o is not None else ()):
                m = re.search(r'ptr \[rip ([+-]) (0x[0-9a-f]+)\]$', j.op_str) if 'jmp' in j.mnemonic else None
                slot = j.address + j.size + int(m.group(2), 16) * (1 if m.group(1) == '+' else -1) if m else None
                m2 = re.search(r'ptr \[(0x[0-9a-f]+)\]$', j.op_str) if 'jmp' in j.mnemonic and not m else None
                if m2: slot = int(m2.group(1), 16)
                if slot is not None: pstub[t] = slots.get(slot); break
        return pstub[t]
    hexop = lambda i: int(i.op_str, 0) if re.fullmatch(r'(0x)?[0-9a-f]+', i.op_str) else None
    for a in sorted(nm):
        end = disasm._bounds(nm, sz, a); o = elfinfo.va2off(I, a)
        if o is None or end <= a or end - a > 1 << 20: continue
        ins = list(md.disasm(d[o:o + (end - a)], a)); st['funcs'] += 1
        tr = mipspic.Tracker(d, I) if abi == 'mips_o32' else None
        targets = {int(mt.group(1), 16) for i in ins for mt in [re.search(r'(0x[0-9a-f]+)$', i.op_str)]
                   if mt and i.mnemonic.startswith(('b', 'j')) and i.mnemonic not in ('jal', 'bal', 'jalr', 'break')} if tr else ()
        def direct(i, t): callers[t].append((i.address, a)); st['direct'] += 1
        def indirect(i, t):
            if t: callers[t].append((i.address, a)); st['indirect_ok'] += 1
            else: st['indirect_unknown'] += 1
        for i in ins:
            t = hexop(i); out = t is not None and not (a <= t < end)   # đích trực tiếp nằm ngoài hàm: nhảy đuôi (tail-call) cũng là lời gọi
            if tr:
                if i.address in targets: tr.reset()   # điểm hợp lưu: không tin giá trị thanh ghi từ đường khác
                tgt = tr.step(i, entry=a)
                if i.mnemonic in ('jal', 'bal') and t is not None:
                    if not (a < t < end): direct(i, t)   # bal/jal tới giữa chính hàm (mẹo lấy PC ở prologue PIC) không phải lời gọi; tới đầu hàm (đệ quy) thì vẫn tính
                elif i.mnemonic in ('j', 'b') and out: direct(i, t)
                elif i.mnemonic == 'jalr' or (i.mnemonic == 'jr' and i.op_str.strip() != '$ra'): indirect(i, tgt)   # jr qua thanh ghi: tail-call qua GOT (hoặc bảng nhảy: tính là chưa giải, thà thừa còn hơn sót)
            elif i.mnemonic == 'call' or (i.mnemonic == 'jmp' and (out or t is None)):
                if t is not None and in_plt(t): callers[t].append((i.address, a)); st['plt'] += 1; plt_name(t)   # lời gọi qua stub PLT: đếm riêng, gắn tên hàm nhập khẩu nếu đọc được ô GOT
                elif t is not None: direct(i, t)
                else: indirect(i, None)   # call/jmp qua thanh ghi hay bộ nhớ
    aliases = collections.defaultdict(list)   # mọi tên của một địa chỉ: libc tĩnh hay có alias (__libc_connect, __connect, connect); nm chỉ giữ một tên
    for n, v, _, ty in elfinfo.symbols(d, I):
        if ty == 2 and v and n not in aliases[v]: aliases[v].append(n)
    for v, n in nm.items():
        if n not in aliases[v]: aliases[v].append(n)
    stubs = {v: n for n, v, _, ty in elfinfo.symbols(d, I, und=True) if ty == 'UND' and v}   # MIPS: stub của hàm nhập khẩu
    stubs.update({t: n for t, n in pstub.items() if n})   # x86: stub PLT đã gắn được tên
    st['plt_named'] = sum(len(callers[t]) for t, n in pstub.items() if n)
    is_go = any(n.startswith('runtime.') for n in nm.values())
    st['unnamed'] = sum(len(v) for t, v in callers.items() if t not in nm and t not in stubs and not in_plt(t))   # lời gọi đã có đích nhưng đích không có tên: không trả lời được câu hỏi theo tên
    return dict(names=nm, callers=callers, stats=st, abi=abi, stubs=stubs, aliases=aliases, is_go=is_go)

def _norm(n):
    n = n.lstrip('_')
    for p in ('libc_', 'GI_'):
        if n.startswith(p): n = n[len(p):]
    return n.lstrip('_')

def report(path, queries=(), d=None, name=None):
    X = build(path, d); nm, st, AL = X['names'], X['stats'], X['aliases']
    dm = disasm.demangle([n for ns in AL.values() for n in ns]); show = lambda n: dm.get(n, n)
    base = lambda n: re.sub(r'\(.*', '', show(n))   # tên dễ đọc không kèm tham số
    qs = list(queries) or list(GO_SENSITIVE if X['is_go'] else SENSITIVE); exact = not queries
    L = [f"# xref {name or os.path.basename(path)}: abi={X['abi']} hàm đã duyệt={st['funcs']} lời gọi trực tiếp={st['direct']} gián tiếp đã giải={st['indirect_ok']} gián tiếp CHƯA giải={st['indirect_unknown']} | qua stub PLT={st['plt']} (gắn được tên hàm nhập khẩu: {st['plt_named']}) | trong số đã có đích, đích KHÔNG có tên={st['unnamed']} (gồm cả nhảy đuôi j/jr/jmp ra ngoài hàm)",
         '# giới hạn: chỉ thấy lời gọi từ hàm có tên; lời gọi gián tiếp chưa giải (con trỏ hàm, bảng ảo, call/jmp qua thanh ghi hay bộ nhớ) và lời gọi qua stub PLT chưa gắn được tên không được quy cho hàm nào.',
         '# "0 nơi gọi" hoặc "không có symbol" KHÔNG chứng minh mẫu không dùng hàm đó khi còn lời gọi chưa giải hoặc binary bị strip/inline.']
    fn = lambda fa: show(nm.get(fa, f'sub_{fa:x}'))
    if not queries: L.append('# bộ tên mặc định: ' + ('Go (binary có .gopclntab; tên libc không áp dụng cho Go thuần)' if X['is_go'] else 'libc (exec, mạng, kill, unlink...)'))
    raw = open(path, 'rb').read() if d is None else d; imp = set(elfinfo.imports(raw, elfinfo.parse(raw))); rstub = collections.defaultdict(list)
    for a_, n_ in sorted(X['stubs'].items()): rstub[n_].append(a_)   # một hàm nhập khẩu có thể có nhiều stub (.plt, .plt.sec)
    missing, und = [], []
    for q in qs:
        m_exact = lambda n: n == q or base(n) == q or _norm(n) == q   # cả dạng nội bộ của libc: __connect, __libc_connect, __GI_connect
        m_sub = lambda n: q in n or q in show(n)
        hit = sorted(a for a, ns in AL.items() if any(m_exact(n) for n in ns)) or ([] if exact else sorted(a for a, ns in AL.items() if any(m_sub(n) for n in ns))[:20])
        ihit = sorted(n for n in imp if n == q) or ([] if exact else sorted(n for n in imp if q in n)[:20])   # hàm nhập khẩu (UND) khớp truy vấn
        for a in hit:
            ns = AL[a]   # ưu tiên đúng tên được hỏi, rồi dạng nội bộ của libc, rồi khớp chứa
            mt = next((n for n in ns if n == q or base(n) == q), None) or next((n for n in ns if m_exact(n)), None) or next((n for n in ns if m_sub(n)), ns[0])
            oth = [show(n) for n in ns if n != mt]
            cs_ = X['callers'].get(a, [])
            L.append(f'## {show(mt)} @{a:#x}: {len(cs_)} nơi gọi' + (f" (cùng địa chỉ: {', '.join(oth[:4])})" if oth else ''))
            L += [f'{site:#x} trong {fn(fa)}' for site, fa in cs_[:40]]
            if len(cs_) > 40: L.append(f'(+{len(cs_) - 40} nơi gọi nữa)')
        for n in ihit:
            cs_ = [c_ for a_ in rstub.get(n, []) for c_ in X['callers'].get(a_, [])]
            if cs_:   # nơi gọi tới stub của hàm nhập khẩu (MIPS: qua GOT; x86: stub PLT đã gắn tên)
                L.append(f"## {n} (nhập khẩu, stub @{', '.join(hex(a_) for a_ in rstub[n])}): {len(cs_)} nơi gọi"); L += [f'{site:#x} trong {fn(fa)}' for site, fa in cs_[:40]]
            elif n not in und: und.append(n)
        if not hit and not ihit: missing.append(q)
    L.append('## nhập khẩu từ thư viện động (UND; mẫu CÓ tham chiếu, nơi gọi qua PLT/GOT động chưa giải): ' + (', '.join(und) if und else '(không)'))
    L.append('## không có symbol tên: ' + (', '.join(missing) if missing else '(không)'))
    return '\n'.join(L) + '\n'

if __name__ == '__main__':
    try: print(report(sys.argv[1], sys.argv[2:]), end='')
    except ValueError as e: raise SystemExit(str(e))
