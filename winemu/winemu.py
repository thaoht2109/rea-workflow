# winemu: giả lập shellcode/loader Windows x86-32 bị làm rối nặng (unicorn), không chạy mẫu thật,
# không có mạng thật. Phát triển từ phân tích loader GuLoader; các lỗi giả lập đã sửa nằm sẵn
# ở đây (xem README.md mục "Bẫy đã xử lý"). Mọi địa chỉ do người dùng truyền là offset so với --base.
#
#   python3 winemu.py --blob SHELLCODE --blob-off OFF --size SIZE --prerun --out OUT \
#       [--plugin plugins/guloader.py:dec=0x...,s2=0x...,s2len=0x...] --chain-child
#   python3 summarize.py OUT/events.jsonl
import sys, os, struct, pickle, re, subprocess, time, collections, json, zlib, argparse, atexit, importlib.util
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__)))); import reacfg   # thêm REA_PYLIB vào sys.path
from unicorn import *
from unicorn.x86_const import *
from capstone import Cs, CS_ARCH_X86, CS_MODE_32

AP = argparse.ArgumentParser(allow_abbrev=False)
AP.add_argument('--blob', help='file shellcode/buffer nạp vào --base')
AP.add_argument('--blob-off', type=lambda s: int(s, 0), default=0, help='bỏ qua N byte đầu file')
AP.add_argument('--base', type=lambda s: int(s, 0), default=0x10000000)
AP.add_argument('--size', type=lambda s: int(s, 0), default=0, help='kích thước vùng cấp phát (mặc định = cỡ file)')
AP.add_argument('--entry', type=lambda s: int(s, 0), default=0, help='offset điểm vào so với base')
AP.add_argument('--prerun', action='store_true', help='chạy trần (không môi trường) tới lần đọc fs:[] đầu tiên: nhanh cho stage giải mã thuần')
AP.add_argument('--child', help='child_mem.bin do lần chạy cha ghi ra: chạy tiến trình con bị tiêm')
AP.add_argument('--chain-child', action='store_true', help='cha tự kết thúc sau khi tiêm thì chạy tiếp tiến trình con')
AP.add_argument('--exe', help='PE gốc map ở 0x400000 (tuỳ chọn)')
AP.add_argument('--exe-path', default='C:\\Users\\admin\\Downloads\\sample.exe', help='đường dẫn Windows của exe trong PEB')
AP.add_argument('--out', required=True, help='thư mục kết quả: events.jsonl, run.log, dump')
AP.add_argument('--tag', default='parent', help='nhãn tiến trình trong events')
AP.add_argument('--max-steps', type=int, default=40_000_000, help='số lát 5M lệnh tối đa')
AP.add_argument('--fake-dl', type=lambda s: int(s, 0), default=0, help='giả lập tải thành công N byte (0 = tải thất bại)')
AP.add_argument('--fake-dl-file', help='nội dung trả về cho InternetReadFile (mặc định toàn 0 -> lộ keystream XOR)')
AP.add_argument('--poll-xor', type=lambda s: int(s, 0), default=0x01010101, help='đổi giá trị con trỏ cha đang chờ trong con')
AP.add_argument('--snap-at', help='API[:N] lưu snapshot ở lần gọi thứ N rồi dừng')
AP.add_argument('--resume', help='snapshot để chạy tiếp')
AP.add_argument('--snap-unhandled', action='store_true', help='API chưa hỗ trợ: lưu snap_unhandled.bin để chạy tiếp sau khi thêm hook (winemu/step.py resume từ đây)')
AP.add_argument('--stop-at', help='API[:N] dừng ở lần gọi thứ N (kèm ring nếu có)')
AP.add_argument('--ring', type=int, default=0, help='giữ N lệnh cuối để in khi dừng/lỗi')
AP.add_argument('--max-events', type=int, default=50_000, help='trần số dòng events.jsonl ồn ào (api/argstr/net...); vượt thì chỉ còn ghi các kind hiếm (end, oep, snapshot, stop_at, anti, warn). 0 = không giới hạn')
AP.add_argument('--plugin', action='append', default=[], help='file.py[:k=v,...], gọi setup(g, opts)')
A = AP.parse_args()
os.makedirs(A.out, exist_ok=True)
LOG = open(os.path.join(A.out, f'{A.tag}.log'), 'w')
EVF = open(os.path.join(A.out, 'events.jsonl'), 'a')
def log(*a):
    s = ' '.join(str(x) for x in a); LOG.write(s + '\n'); LOG.flush()
EVN = [0]   # số dòng đã ghi; trần --max-events chặn log nổ (một lượt từng sinh >113k dòng khi mẫu lặp vô hạn)
EV_KEEP = {'end', 'oep', 'snapshot', 'stop_at', 'anti', 'warn', 'start'}   # kind hiếm/quan trọng: luôn ghi dù đã quá trần
def ev(kind, **kw):
    if A.max_events and kind not in EV_KEEP:
        if EVN[0] == A.max_events:
            EVN[0] += 1; EVF.write(json.dumps({'proc': A.tag, 'kind': 'warn', 'what': 'max_events', 'cap': A.max_events}, ensure_ascii=False) + '\n'); EVF.flush()
        if EVN[0] > A.max_events: return
        EVN[0] += 1
    kw = {k: (hex(v) if isinstance(v, int) and not isinstance(v, bool) and k not in ('n', 'len', 'i', 'keylen', 'api_calls', 'veh', 'seconds') else v) for k, v in kw.items()}
    EVF.write(json.dumps({'proc': A.tag, 'kind': kind, **kw}, ensure_ascii=False) + '\n'); EVF.flush()
def page(n): return (n + 0xfff) & ~0xfff

STK = 0x00100000
mu = Uc(UC_ARCH_X86, UC_MODE_32)
md = Cs(CS_ARCH_X86, CS_MODE_32)
def w32(a, v): mu.mem_write(a, struct.pack('<I', v & 0xffffffff))
def r32(a): return struct.unpack('<I', mu.mem_read(a, 4))[0]
def w16(a, v): mu.mem_write(a, struct.pack('<H', v & 0xffff))
REGN = ('EAX', 'EBX', 'ECX', 'EDX', 'ESI', 'EDI', 'EBP', 'ESP')
def R(name): return globals()['UC_X86_REG_' + name]

# ---- nạp buffer ----
if A.child:
    # tiến trình con: buffer do cha ghi (NtWriteVirtualMemory) + điểm vào = con trỏ cha ghi vào ntdll con
    raw = open(A.child, 'rb').read()
    BASE, n = struct.unpack_from('<II', raw, 0)
    data = zlib.decompress(raw[8:]); SIZE = page(n); del raw
    mu.mem_map(BASE, SIZE); mu.mem_write(BASE, data); del data
    mu.mem_map(STK, 0x100000)
    # luồng chính: EAX=EDX=điểm vào exe (ntdll gọi Kernel32ThreadInitThunk(0, start, PEB))
    mu.mem_write(STK + 0xf0000, struct.pack('<IIII', 0xdeadbeef, 0, 0x401000, 0x7ffd0000))
    REGS = dict(EAX=0x401000, EBX=0x7ffd0000, ECX=0, EDX=0x401000, ESI=0, EDI=0, EBP=0, ESP=STK + 0xf0000,
                EIP=BASE + A.entry, EFLAGS=0x202)
else:
    data = open(A.blob, 'rb').read()[A.blob_off:]
    BASE, SIZE = A.base, page(A.size or len(data))
    mu.mem_map(BASE, SIZE); mu.mem_write(BASE, data)
    mu.mem_map(STK, 0x100000)
    esp = STK + 0xf0000
    for v in (0, 0x1234, 0xdeadbeef):   # như callback EnumWindows: (hwnd, lParam), ret
        esp -= 4; w32(esp, v)
    mu.reg_write(UC_X86_REG_ESP, esp)
    pc = BASE + A.entry
    if A.prerun:
        # chưa có GDT nên fs base = 0: lần đầu đọc fs:[0x30] (PEB) sẽ lỗi -> đó là điểm vào stage sau
        t0 = time.time()
        try:
            mu.emu_start(pc, 0xdeadbeef, count=2_000_000_000); log('[prerun] hết ngân sách lệnh mà chưa chạm fs')
        except UcError as e:
            log(f'[prerun] dừng: {e} @ {mu.reg_read(UC_X86_REG_EIP):#x} sau {time.time() - t0:.0f}s')
        pc = mu.reg_read(UC_X86_REG_EIP)
        ev('prerun_end', eip=pc, off=pc - BASE)
    REGS = {r: mu.reg_read(R(r)) for r in REGN + ('EFLAGS',)}; REGS['EIP'] = pc
    del data

def rstr(a, n=512):
    if not a: return None
    try: b = bytes(mu.mem_read(a, n))
    except UcError: return f'<bad {a:#x}>'
    return b.split(b'\0')[0].decode('latin1')
def rwstr(a, n=1024):
    if not a: return None
    try: b = bytes(mu.mem_read(a, n))
    except UcError: return f'<bad {a:#x}>'
    i = 0
    while i + 1 < len(b) and b[i:i+2] != b'\0\0': i += 2
    return b[:i].decode('utf-16le', 'replace')
def rustr(a):  # UNICODE_STRING*
    if not a: return None
    ln = struct.unpack('<H', mu.mem_read(a, 2))[0]
    return bytes(mu.mem_read(r32(a + 4), ln)).decode('utf-16le', 'replace')
PRINT = re.compile(rb'^[\x20-\x7e]{4,}$')
def sniff(a):
    """Chuỗi ASCII/UTF-16 in được tại con trỏ a (bộ dò chuỗi chung, không cần biết hàm giải mã)."""
    try: b = bytes(mu.mem_read(a, 256))
    except UcError: return None
    s = b.split(b'\0')[0]
    if len(s) >= 4 and PRINT.match(s): return s.decode()
    if len(b) > 8 and b[1] == 0 and b[3] == 0:
        w = rwstr(a, 512)
        if w and len(w) >= 4 and PRINT.match(w.encode('latin1', 'replace')): return w
    return None

# ---- heap/cấp phát ----
ALLOC = [0x30000000]
ALLOCS_SEEN = []
def alloc(size, at=0):
    ALLOCS_SEEN.append(size)
    size = page(size)
    if at:
        at &= ~0xfff
        try: mu.mem_map(at, size); return at
        except UcError: pass
    a = ALLOC[0]; ALLOC[0] += size + 0x10000
    mu.mem_map(a, size); return a
HEAP = alloc(0x400000); HEAPP = [HEAP]
def halloc(n):
    a = HEAPP[0]; HEAPP[0] += (n + 15) & ~15; return a

# ---- DLL giả: tên export lấy từ builtin của wine, mỗi export một stub 32 byte ----
WINE = os.path.join(reacfg.WINE_DLL_DIR, '')
IDENT = re.compile(rb'^[A-Za-z_][A-Za-z0-9_]{2,63}$')
MODS, STUBS, BYNAME, MODHDR, MODORDER, NTLIST = {}, {}, {}, {}, [], []
NEXTBASE = [0x70000000]
def names_for(dll):
    try: out = subprocess.run(['strings', '-n', '3', WINE + dll + '.so'], capture_output=True).stdout
    except Exception: out = b''
    return sorted({l for l in out.split(b'\n') if IDENT.match(l)})
def make_module(dll):
    dll = dll.lower()
    if not dll.endswith('.dll'): dll += '.dll'
    if dll in MODS: return MODS[dll]['base']
    names = names_for(dll) or [b'DummyExport']
    base, n, stub_rva = NEXTBASE[0], len(names), 0x1000
    exp_rva = page(stub_rva + n * 32 + 0x1000)
    eat = exp_rva + 0x28; enpt = eat + 4 * n; eord = enpt + 4 * n; strs = eord + 2 * n
    blob, name_rvas = bytearray(), []
    dllname_rva = strs; blob += dll.encode() + b'\0'
    for nm in names: name_rvas.append(strs + len(blob)); blob += nm + b'\0'
    size = (strs + len(blob) + 0x1fff) & ~0xfff
    mu.mem_map(base, size + 0x10000, UC_PROT_ALL)
    NEXTBASE[0] += (size + 0x10000 + 0xfffff) & ~0xfffff
    hdr = bytearray(0x1000)
    hdr[0:2] = b'MZ'; struct.pack_into('<I', hdr, 0x3c, 0x80); hdr[0x80:0x84] = b'PE\0\0'
    struct.pack_into('<HHIIIHH', hdr, 0x84, 0x14c, 7, 0, 0, 0, 0xe0, 0x2102)
    opt = 0x98
    struct.pack_into('<H', hdr, opt, 0x10b); struct.pack_into('<I', hdr, opt + 0x1c, base)
    struct.pack_into('<II', hdr, opt + 0x20, 0x1000, 0x200); struct.pack_into('<I', hdr, opt + 0x38, size)
    struct.pack_into('<I', hdr, opt + 0x5c, 16); struct.pack_into('<II', hdr, opt + 0x60, exp_rva, 0x28 + 10 * n + len(blob))
    # bảng section giống DLL hệ thống thật (mã độc tìm .data theo tên để vá con trỏ)
    secs = [b'.text', b'RT', b'.data', b'.mrdata', b'.00cfg', b'.rsrc', b'.reloc']
    sec = opt + 0xe0
    for k, nm in enumerate(secs):
        o = sec + 0x28 * k
        hdr[o:o+8] = nm.ljust(8, b'\0')
        if k == 0: va, vs, ch = 0x1000, exp_rva - 0x1000, 0x60000020
        elif k == 2: va, vs, ch = exp_rva, size - exp_rva, 0xc0000040
        else: va, vs, ch = size + 0x1000 * (k - 1), 0x1000, 0x40000040
        struct.pack_into('<IIII', hdr, o + 8, vs, va, vs, va); struct.pack_into('<I', hdr, o + 36, ch)
    mu.mem_write(base, bytes(hdr)); MODHDR[base] = bytes(hdr)
    mu.mem_write(base + exp_rva, struct.pack('<IIHHIIIIIII', 0, 0, 0, 0, dllname_rva, 1, n, n, eat, enpt, eord))
    isnt = [dll == 'ntdll.dll' and nm[:2] in (b'Nt', b'Zw') for nm in names]
    mu.mem_write(base + eat, b''.join(struct.pack('<I', stub_rva + 32 * i + (4 if isnt[i] else 0)) for i in range(n)))
    mu.mem_write(base + enpt, b''.join(struct.pack('<I', r) for r in name_rvas))
    mu.mem_write(base + eord, b''.join(struct.pack('<H', i) for i in range(n)))
    mu.mem_write(base + strs, bytes(blob))
    kfs = base + 0x800  # KiFastSystemCall giả (chỉ ntdll dùng)
    for i, nm in enumerate(names):
        a = base + stub_rva + 32 * i
        if isnt[i]:
            # đệm NOP + "mov eax,SSN; mov edx,KiFastSystemCall; call edx; ret" như ntdll WoW64:
            # mã độc dò mẫu này để dựng lại số syscall
            mu.mem_write(a, b'\x90' * 4); a += 4
            code = b'\xb8' + struct.pack('<I', i) + b'\xba' + struct.pack('<I', kfs) + b'\xff\xd2' + b'\xc2\x00\x00'
            NTLIST.append(nm.decode())
        else:
            code = b'\x8b\xff\x55\x8b\xec\x5d\x90\x90\xc3'   # mov edi,edi; push ebp; mov ebp,esp; ...
        mu.mem_write(a, code)
        STUBS[a] = (dll, nm.decode()); BYNAME[(dll, nm.decode())] = a
    if dll == 'ntdll.dll':
        mu.mem_write(kfs, b'\x8b\xd4\x0f\x34\xc3'); STUBS[kfs] = ('ntdll.dll', '__KiFastSystemCall')
    MODS[dll] = {'base': base, 'size': size}; ALLOCS_SEEN.append(size); MODORDER.append(dll)
    mu.hook_add(UC_HOOK_CODE, on_stub, begin=base + 0x800, end=base + stub_rva + 32 * n)
    log(f'[mod] {dll} @ {base:#x} ({n} names)'); ev('module', name=dll, base=base)
    return base

# ---- TEB/PEB/Ldr/KUSER_SHARED_DATA ----
TEB, PEB, LDRP, EXE = 0x7ffde000, 0x7ffd0000, 0x7ffc0000, 0x00400000
mu.mem_map(PEB, 0x1000); mu.mem_map(TEB, 0x2000); mu.mem_map(LDRP, 0x10000); mu.mem_map(0x7ffe0000, 0x1000)
w32(0x7ffe0000 + 0x26c, 10); w32(0x7ffe0000 + 0x270, 0); w32(0x7ffe0000 + 0x260, 19045)
mu.mem_map(EXE, 0x80000)
if A.exe: mu.mem_write(EXE, open(A.exe, 'rb').read()[:0x80000])
else: mu.mem_write(EXE, b'MZ')
w32(TEB + 0x0, 0xffffffff); w32(TEB + 4, STK + 0x100000); w32(TEB + 8, STK)
w32(TEB + 0x18, TEB); w32(TEB + 0x20, 0x1a2c); w32(TEB + 0x24, 0x1a30); w32(TEB + 0x30, PEB)
w32(PEB + 8, EXE); w32(PEB + 0xc, LDRP); w32(PEB + 0x18, HEAP)
w32(PEB + 0x64, 4); w32(PEB + 0xa4, 10); w32(PEB + 0xa8, 0); w16(PEB + 0xac, 19045)
PP = halloc(0x300); w32(PEB + 0x10, PP)
def mk_ustr(at, s):
    b = s.encode('utf-16le'); buf = halloc(len(b) + 2); mu.mem_write(buf, b + b'\0\0')
    w16(at, len(b)); w16(at + 2, len(b) + 2); w32(at + 4, buf)
EXEPATH = A.exe_path
if not A.exe: print('cảnh báo: không có --exe, ảnh EXE ở 0x400000 chỉ có "MZ"; loader đọc PE header của chính nó '
                  '(EntryPoint, e_lfanew…) sẽ chạy sai', file=sys.stderr)
mk_ustr(PP + 0x38, EXEPATH); mk_ustr(PP + 0x40, '"' + EXEPATH + '"')
mk_ustr(PP + 0x24, EXEPATH.rsplit('\\', 1)[0] + '\\')
def build_ldr(order):
    w32(LDRP + 4, 1)
    ents, p = [], LDRP + 0x100
    for nm, b, sz in order:
        e = p; p += 0x100
        w32(e + 0x18, b); w32(e + 0x1c, b + 0x1000); w32(e + 0x20, sz)   # EntryPoint = base+0x1000
        full = ('C:\\Windows\\System32\\' + nm) if b != EXE else EXEPATH
        mk_ustr(e + 0x24, full); mk_ustr(e + 0x2c, nm if b != EXE else EXEPATH.split('\\')[-1])
        ents.append(e)
    for off, head in ((0, 0xc), (8, 0x14), (0x10, 0x1c)):
        es = ents if off != 0x10 else ents[1:]
        H = LDRP + head; prev = H
        for e in es:
            w32(prev if prev == H else prev + off, e + off); w32(e + off + 4, prev if prev == H else prev + off)
            prev = e
        w32(prev + off, H); w32(H + 4, prev + off)
        if not es: w32(H, H); w32(H + 4, H)

# ---- GDT + segment. GDT đặt cao: vùng < 0x10000 phải để trống (mã độc cố tình AV ở đó) ----
def gdt_entry(base, limit, access, flags):
    return struct.pack('<Q', limit & 0xffff | (base & 0xffffff) << 16 | (access & 0xff) << 40 | ((limit >> 16) & 0xf) << 48 | (flags & 0xf) << 52 | ((base >> 24) & 0xff) << 56)
GDT = 0x7fe00000
mu.mem_map(GDT, 0x1000)
gd = bytearray(0x100)
gd[14*8:15*8] = gdt_entry(TEB, 0xfff, 0xf2, 0x4)          # fs -> TEB
gd[15*8:16*8] = gdt_entry(0, 0xfffff, 0xf2, 0xc)          # data ring 3
gd[16*8:17*8] = gdt_entry(0, 0xfffff, 0xfa, 0xc)          # code ring 3
gd[17*8:18*8] = gdt_entry(0, 0xfffff, 0x92, 0xc)          # stack ring 0 (32-bit)
mu.mem_write(GDT, bytes(gd))
mu.reg_write(UC_X86_REG_GDTR, (0, GDT, 0xff, 0))
mu.reg_write(UC_X86_REG_FS, 14 << 3 | 3)
mu.reg_write(UC_X86_REG_DS, 15 << 3 | 3); mu.reg_write(UC_X86_REG_ES, 15 << 3 | 3)
mu.reg_write(UC_X86_REG_GS, 15 << 3 | 3); mu.reg_write(UC_X86_REG_SS, 17 << 3)

# ---- API ----
MAGIC = 0x7f000000
mu.mem_map(MAGIC, 0x1000); mu.mem_write(MAGIC, b'\xc3' * 0x1000)
VEH, CALLS, CHILD, CCOUNT, DL, STRS = [], [0], {}, {}, {}, set()
EXH = collections.deque(maxlen=40)
CTX = {'tick': 0x01234567, 'stop': False, 'cur': 100, 'enumw': None}
SNIFF_SKIP = {'NtQueryVirtualMemory', 'ZwQueryVirtualMemory', '__KiFastSystemCall'}
FAKEDATA = open(A.fake_dl_file, 'rb').read() if A.fake_dl_file else None
def arg(i, esp_off=4): return r32(mu.reg_read(UC_X86_REG_ESP) + esp_off + 4 * i)
def getproc(mod, name):
    for (d, n), a in BYNAME.items():
        if MODS[d]['base'] == mod and n == name: return a
    return 0
def S(N, p, n=2048): return rstr(p, n) if N.endswith('A') else rwstr(p, 2 * n)
API_HOOKS = {}   # plugin: tên API -> f(dll, name, a, ctx) trả về như api() hoặc None để rơi xuống mặc định

def api(dll, name, a, ctx):
    """(argc, retval), 'enumwindows', hoặc None nếu chưa hỗ trợ. a(i) đọc tham số i."""
    N = name
    if N in API_HOOKS:
        r = API_HOOKS[N](dll, N, a, ctx)
        if r is not None: return r
    if N in ('NtProtectVirtualMemory', 'ZwProtectVirtualMemory'):
        if a(4): w32(a(4), 0x40)
        return 5, 0
    if N in ('NtAllocateVirtualMemory', 'ZwAllocateVirtualMemory'):
        pb, ps = a(1), a(3)
        want, size = r32(pb), r32(ps)
        if a(0) != 0xffffffff:
            ev('child_alloc', addr=want, size=size, prot=a(5))
            w32(pb, want or 0x60000000); return 6, 0
        b = alloc(size, want); w32(pb, b); w32(ps, page(size))
        if size >= 0x10000: ev('alloc', addr=b, size=size, prot=a(5))
        return 6, 0
    if N == 'VirtualAlloc':
        b = alloc(a(1), a(0)); ev('alloc', addr=b, size=a(1), prot=a(3)); return 4, b
    if N == 'VirtualProtect':
        if a(3): w32(a(3), 0x40)
        return 4, 1
    if N in ('NtSetInformationThread', 'ZwSetInformationThread'):
        ev('anti', what=f'{N}(class={a(1):#x})') if CCOUNT[N] == 1 else None; return 4, 0
    if N in ('NtSetInformationProcess', 'ZwSetInformationProcess'):   # 0x22 ProcessExecuteFlags: GuLoader tắt DEP trước khi nạp payload
        ev('anti', what=f'{N}(class={a(1):#x}, value={r32(a(2)) if a(3) == 4 else None})'); return 4, 0
    if N in ('NtQueryInformationProcess', 'ZwQueryInformationProcess'):
        if a(2): mu.mem_write(a(2), b'\0' * min(a(3), 0x40))
        if a(4): w32(a(4), a(3))
        return 5, 0
    if N in ('RtlAddVectoredExceptionHandler', 'AddVectoredExceptionHandler'):
        VEH.append(a(1)); ev('veh', handler=a(1), off=a(1) - BASE); return 2, 0x5000
    if N in ('RtlRemoveVectoredExceptionHandler', 'RemoveVectoredExceptionHandler'):
        VEH.clear(); return 1, 1
    if N in ('LoadLibraryA', 'LoadLibraryW', 'LoadLibraryExA', 'LoadLibraryExW'):
        s = S(N, a(0)); return (3 if 'Ex' in N else 1), make_module(s.split('\\')[-1])
    if N in ('GetModuleHandleA', 'GetModuleHandleW'):
        if not a(0): return 1, EXE
        s = S(N, a(0)).lower()
        if not s.endswith('.dll'): s += '.dll'
        return 1, MODS[s]['base'] if s in MODS else 0
    if N == 'GetProcAddress':
        RESOLVED.add(rstr(a(1)) if a(1) >= 0x10000 else f'#{a(1)}'); return 2, getproc(a(0), rstr(a(1)))   # < 0x10000 là ordinal
    if N == 'LdrLoadDll':
        w32(a(3), make_module(rustr(a(2)).split('\\')[-1])); return 4, 0
    if N == 'LdrGetProcedureAddress':
        if a(1): RESOLVED.add(rstr(r32(a(1) + 4)))
        r = getproc(a(0), rstr(r32(a(1) + 4)) if a(1) else None); w32(a(3), r); return 4, 0 if r else 0xc0000139
    if N == 'GetTickCount': ctx['tick'] += 15; return 0, ctx['tick']
    if N == 'Sleep': return 1, 0
    if N in ('NtDelayExecution', 'ZwDelayExecution'): return 2, 0
    if N == 'IsDebuggerPresent': return 0, 0
    if N == 'CheckRemoteDebuggerPresent': w32(a(1), 0); return 2, 1
    if N == 'GetCurrentProcess': return 0, 0xffffffff
    if N == 'GetCurrentThread': return 0, 0xfffffffe
    if N in ('CloseHandle', 'NtClose', 'ZwClose'): return 1, 0 if N.startswith(('Nt', 'Zw')) else 1
    if N in ('TerminateProcess', 'ExitProcess', 'NtTerminateProcess', 'ZwTerminateProcess'):
        if N != 'ExitProcess' and a(0) not in (0xffffffff, 0):
            ev('proc_kill', handle=a(0)); return 2, (1 if N == 'TerminateProcess' else 0)
        ev('exit', api=N); ctx['stop'] = True; return (1 if N == 'ExitProcess' else 2), 0
    if N in ('GetSystemDirectoryA', 'GetWindowsDirectoryA', 'GetSystemWow64DirectoryA',
             'GetSystemDirectoryW', 'GetWindowsDirectoryW', 'GetSystemWow64DirectoryW'):
        s = {'GetSystemDirectory': 'C:\\Windows\\system32', 'GetWindowsDirectory': 'C:\\Windows',
             'GetSystemWow64Directory': 'C:\\Windows\\SysWOW64'}[N[:-1]]
        mu.mem_write(a(0), s.encode() + b'\0' if N.endswith('A') else s.encode('utf-16le') + b'\0\0'); return 2, len(s)
    if N in ('ExpandEnvironmentStringsA', 'ExpandEnvironmentStringsW'):
        s = S(N, a(0)); out = s.replace('%APPDATA%', 'C:\\Users\\admin\\AppData\\Roaming').replace('%TEMP%', 'C:\\Users\\admin\\AppData\\Local\\Temp')
        if a(1): mu.mem_write(a(1), out.encode() + b'\0' if N.endswith('A') else out.encode('utf-16le') + b'\0\0')
        return 3, len(out) + 1
    if N == 'EnumWindows':
        ctx['enumw'] = (a(0), a(1), 20); return 'enumwindows'   # gọi callback 20 lần
    if N in ('NtQueryVirtualMemory', 'ZwQueryVirtualMemory'):
        # MBI thật theo vùng đã map: mã độc quét toàn bộ không gian nhớ để tìm dấu vết công cụ
        addr, buf = a(1) & ~0xfff, a(3)
        if addr >= 0x7ffe0000: return 6, 0xc000000d
        if ctx.get('regs_n') != len(ALLOCS_SEEN):
            ctx['regs'] = sorted((b, e) for b, e, p in mu.mem_regions()); ctx['regs_n'] = len(ALLOCS_SEEN)
        info = None
        for b, e in ctx['regs']:
            if b <= addr <= e: info = (b, addr, e + 1 - addr, 0x1000, 0x40, 0x20000); break
        if info is None:
            nxt = min([b for b, e in ctx['regs'] if b > addr] + [0x7ffe0000])
            info = (0, addr, nxt - addr, 0x10000, 0x1, 0)
        ab, ba, size, state, prot, typ = info
        mu.mem_write(buf, struct.pack('<IIIIIII', ba, ab if state == 0x1000 else 0, prot, size, state, prot, typ))
        if a(5): w32(a(5), 28)
        return 6, 0
    if N in ('NtQuerySystemInformation', 'ZwQuerySystemInformation'): return 4, 0xc0000004
    if N in ('GetUserNameA', 'GetComputerNameA'): mu.mem_write(a(0), b'admin\0'); w32(a(1), 5); return 2, 1
    if N in ('GetFileAttributesA', 'GetFileAttributesW'): ev('file', api=N, path=S(N, a(0))); return 1, 0xffffffff
    if N in ('CreateFileA', 'CreateFileW'): ev('file', api=N, path=S(N, a(0)), access=a(1), disp=a(4)); return 7, 0xffffffff
    if N == 'SetErrorMode': return 1, 0
    if N == 'GetLastError': return 0, 0
    if N == 'RtlGetVersion': w32(a(0) + 4, 10); w32(a(0) + 8, 0); w32(a(0) + 12, 19045); return 1, 0
    # ---- mạng: không có kết nối thật ----
    if N in ('InternetOpenA', 'InternetOpenW'): ev('net', api=N, ua=S(N, a(0))); return 5, 0x2000
    if N in ('InternetSetOptionA', 'InternetSetOptionW'): ev('net', api=N, option=a(1), value=r32(a(2)) if a(3) == 4 else None); return 4, 1
    if N in ('InternetOpenUrlA', 'InternetOpenUrlW'):
        ev('net', api=N, url=S(N, a(1)), headers=S(N, a(2)), flags=a(4))
        if A.fake_dl: DL['got'] = 0; return 6, 0x2004
        return 6, 0   # thất bại -> lộ URL dự phòng/vòng thử lại
    if N == 'InternetReadFile' and A.fake_dl:
        got = DL.get('got', 0); k = min(a(2), A.fake_dl - got)
        mu.mem_write(a(1), FAKEDATA[got:got + k].ljust(k, b'\0') if FAKEDATA else bytes(k))
        w32(a(3), k); DL['got'] = got + k; DL.setdefault('bufs', []).append((a(1), k))
        if k == 0 or got == 0: ev('net', api=N, buf=a(1), total=DL['got'])
        return 4, 1
    if N in ('InternetReadFile', 'InternetCloseHandle'): return (4 if N == 'InternetReadFile' else 1), 0
    if N in ('HttpQueryInfoA', 'HttpQueryInfoW'): ev('net', api=N, info=a(1)); return 5, 0
    if N == 'WinHttpOpen': ev('net', api=N, ua=rwstr(a(0))); return 5, 0x3000
    if N == 'WinHttpConnect': ev('net', api=N, host=rwstr(a(1)), port=a(2)); return 4, 0x3004
    if N == 'WinHttpOpenRequest': ev('net', api=N, verb=rwstr(a(1)), path=rwstr(a(2))); return 7, 0x3008
    if N == 'WinHttpSendRequest': return 7, 0
    if N in ('URLDownloadToFileA', 'URLDownloadToFileW'): ev('net', api=N, url=S(N, a(1)), path=S(N, a(2))); return 5, 0x80004005
    # ---- tạo tiến trình / tiêm mã ----
    if N == 'CreateProcessInternalW':
        ev('proc_create', api=N, app=rwstr(a(1)), cmd=rwstr(a(2)), flags=a(6))
        mu.mem_write(a(10), struct.pack('<IIII', 0x200, 0x204, 4242, 4243)); return 12, 1
    if N in ('CreateProcessA', 'CreateProcessW'):
        ev('proc_create', api=N, app=S(N, a(0)), cmd=S(N, a(1)), flags=a(5)); return 10, 0
    if N in ('NtWriteVirtualMemory', 'ZwWriteVirtualMemory'):
        dst, src, n = a(1), a(2), a(3)
        data = bytes(mu.mem_read(src, n))
        if n > 0x100000:
            p = os.path.join(A.out, 'child_mem.bin')
            open(p, 'wb').write(struct.pack('<II', dst, n) + zlib.compress(data, 1))
            CHILD['big'] = (dst, n, p)
        CHILD.setdefault('writes', []).append((dst, n, data[:4]))
        ev('child_write', dst=dst, n=n, src=src, head=data[:16].hex())
        if a(4): w32(a(4), n)
        return 5, 0
    if N in ('NtReadVirtualMemory', 'ZwReadVirtualMemory'):
        src, dst, n = a(1), a(2), a(3)
        if src != dst: mu.mem_write(dst, bytes(mu.mem_read(src, n)))
        if CHILD.get('resumed') and n == 4:
            # cha chờ con khởi tạo xong (con trỏ trong ntdll của con đổi giá trị): giả lập sự thay đổi
            CHILD['polls'] = CHILD.get('polls', 0) + 1
            if CHILD['polls'] > 3: mu.mem_write(dst, struct.pack('<I', r32(dst) ^ A.poll_xor))
        elif CCOUNT[N] <= 5: ev('child_read', src=src, n=n)
        if a(4): w32(a(4), n)
        return 5, 0
    if N in ('NtGetContextThread', 'ZwGetContextThread'):
        c = a(1); mu.mem_write(c + 4, b'\0' * 0x2c8); w32(c + 0xb8, 0x401000); w32(c + 0xb0, 0x401000); w32(c + 0xc4, 0x12ff00)
        return 2, 0
    if N in ('NtSetContextThread', 'ZwSetContextThread'):
        c = a(1); CHILD['ctx'] = {k: r32(c + o) for k, o in dict(EAX=0xb0, EDX=0xa8, EIP=0xb8, ESP=0xc4).items()}
        ev('child_setcontext', **CHILD['ctx']); return 2, 0
    if N in ('NtResumeThread', 'ZwResumeThread', 'ResumeThread'):
        ev('child_resume'); CHILD['resumed'] = True; return (2 if N != 'ResumeThread' else 1), 0
    if N in ('NtOpenFile', 'ZwOpenFile', 'NtCreateFile', 'ZwCreateFile'):
        oa = a(2); ev('file', api=N, path=rustr(r32(oa + 8)) if oa and r32(oa + 8) else None)
        w32(a(0), 0x400); return (6 if 'Open' in N else 11), 0
    if N in ('NtCreateSection', 'ZwCreateSection'):
        w32(a(0), 0x300); ev('section', size=r32(a(3)) if a(3) else 0); return 7, 0
    if N in ('NtMapViewOfSection', 'ZwMapViewOfSection'):
        proc, pb, psz = a(1), a(2), a(6)
        want, size = r32(pb), r32(psz) if psz else 0
        ev('map_view', proc=proc, base=want, size=size)
        w32(pb, alloc(size or 0x1000, want) if proc == 0xffffffff else (want or 0x400000)); return 10, 0
    if N in ('GetEnvironmentVariableA', 'GetEnvironmentVariableW'): ev('env', name=S(N, a(0))); return 3, 0
    if N == 'RtlAdjustPrivilege': return 4, 0
    if N == 'GetCursorPos': ctx['cur'] += 7; w32(a(0), ctx['cur']); w32(a(0) + 4, ctx['cur'] // 2); return 1, 1
    if N == 'GetForegroundWindow': return 0, 0x10010
    if N == 'ShowWindow': return 2, 1
    if N in ('MessageBoxA', 'MessageBoxW'): ev('ui', text=S(N, a(1))); return 4, 1
    return None

def parse_at(s):
    if not s: return None, 0
    n, _, k = s.partition(':'); return n, int(k or 1)
SNAP_AT, SNAP_N = parse_at(A.snap_at)
STOP_AT, STOP_N = parse_at(A.stop_at)

def on_stub(uc, addr, size, _):
    if addr not in STUBS:
        slot = addr & ~0x1f
        if addr - slot == 5 and slot in STUBS and not STUBS[slot][1].startswith(('Nt', 'Zw')):
            # gọi API+5 (bỏ qua "mov edi,edi; push ebp; mov ebp,esp" để né hook). Nếu tự làm
            # "push ebp; mov ebp,esp" thì EBP==ESP: khôi phục EBP; còn lại (wrapper push 1 dword
            # thay lệnh đầu của API, vd CreateProcessInternalW) thì chỉ bỏ dword đó
            esp = uc.reg_read(UC_X86_REG_ESP)
            if uc.reg_read(UC_X86_REG_EBP) == esp: uc.reg_write(UC_X86_REG_EBP, r32(esp))
            uc.reg_write(UC_X86_REG_ESP, esp + 4)
            addr = slot
        else:
            return
    dll, name = STUBS[addr]
    if name == '__KiFastSystemCall':
        ssn = uc.reg_read(UC_X86_REG_EAX)
        # mã độc đánh số lại SSN theo thứ tự stub Nt/Zw: SSN k = stub Nt/Zw thứ k
        dll, name = STUBS.get(r32(uc.reg_read(UC_X86_REG_ESP)) - 12) or ('ntdll.dll', NTLIST[ssn] if ssn < len(NTLIST) else f'SSN_{ssn}')
        a = lambda i: arg(i, 8)   # [esp]=ret về stub, [esp+4]=ret về caller
        caller = r32(uc.reg_read(UC_X86_REG_ESP) + 4); is_sys = True
    else:
        a = lambda i: arg(i, 4); caller = r32(uc.reg_read(UC_X86_REG_ESP)); is_sys = False
    if SNAP_AT == name and not CTX.get('resumed_skip') and CCOUNT.get(name, 0) + 1 >= SNAP_N:
        save_snapshot(os.path.join(A.out, f'snap_{name}.bin'), addr); CTX['stop'] = True; uc.emu_stop(); return
    CTX['resumed_skip'] = False
    if STOP_AT == name and CCOUNT.get(name, 0) + 1 >= STOP_N:
        log(f'[stop_at] {name}'); dump_ring(); ev('stop_at', api=name); CTX['stop'] = True; uc.emu_stop(); return
    CALLS[0] += 1
    CCOUNT[name] = CCOUNT.get(name, 0) + 1
    if name not in SNIFF_SKIP:
        for i in range(6):
            try: p = a(i)
            except UcError: break
            s = sniff(p) if p > 0x10000 else None
            if s and s not in STRS:
                STRS.add(s); ev('argstr', api=name, i=i, s=s)
    res = api(dll, name, a, CTX)
    if CCOUNT[name] <= 5 or res is None:
        ev('api', dll=dll, name=name, args=[hex(a(i)) for i in range(4)], caller=caller, coff=caller - BASE,
           **({} if res is not None else {'unhandled': True}))
    if res is None:
        log(f'[api] {dll}!{name} chưa hỗ trợ, caller={caller:#x}')
        if A.snap_unhandled:   # lưu bộ đếm như trước lần gọi này: resume chạy lại stub và đếm lại nó (như --snap-at)
            CCOUNT[name] -= 1; save_snapshot(os.path.join(A.out, 'snap_unhandled.bin'), addr); CCOUNT[name] += 1
            ev('unhandled_snap', api=name, dll=dll)
        CTX['unhandled'] = f'{dll}!{name}'; CTX['stop'] = True; uc.emu_stop(); return
    if res == 'enumwindows':
        cb, lp, n = CTX['enumw']
        CTX['enumw_ret'] = caller; CTX['enumw_n'] = n
        uc.reg_write(UC_X86_REG_ESP, uc.reg_read(UC_X86_REG_ESP) + 4 + 8)
        call_cb(uc, cb, lp); return
    argc, rv = res
    esp = uc.reg_read(UC_X86_REG_ESP)
    uc.reg_write(UC_X86_REG_EAX, rv & 0xffffffff)
    if is_sys:
        # quay về sau "call edx" trong stub; stub giả là "ret 0" nên tự dọn tham số
        uc.reg_write(UC_X86_REG_ESP, esp + 8 + 4 * argc - 4); w32(esp + 8 + 4 * argc - 4, caller)
        uc.reg_write(UC_X86_REG_EIP, MAGIC + 0x10)
    else:
        uc.reg_write(UC_X86_REG_ESP, esp + 4 + 4 * argc); uc.reg_write(UC_X86_REG_EIP, r32(esp))

def call_cb(uc, cb, lp):
    esp = uc.reg_read(UC_X86_REG_ESP) - 12
    w32(esp, MAGIC + 0x100); w32(esp + 4, 0x10000 + CTX['enumw_n'] * 4); w32(esp + 8, lp)
    uc.reg_write(UC_X86_REG_ESP, esp); uc.reg_write(UC_X86_REG_EIP, cb)
    CTX['enumw_n'] -= 1

CTXREGS = dict(EDI=0x9c, ESI=0xa0, EBX=0xa4, EDX=0xa8, ECX=0xac, EAX=0xb0, EBP=0xb4, EIP=0xb8, EFLAGS=0xc0, ESP=0xc4)
def on_magic(uc, addr, size, _):
    if addr == MAGIC + 0x100:   # callback EnumWindows trả về
        if uc.reg_read(UC_X86_REG_EAX) and CTX['enumw_n'] > 0: call_cb(uc, CTX['enumw'][0], CTX['enumw'][1])
        else: uc.reg_write(UC_X86_REG_EAX, 1); uc.reg_write(UC_X86_REG_EIP, CTX['enumw_ret'])
    elif addr == MAGIC + 0x200:   # VEH handler trả về
        rv = uc.reg_read(UC_X86_REG_EAX)
        if rv & 0xffffffff != 0xffffffff:   # không phải EXCEPTION_CONTINUE_EXECUTION
            for c, a, e in EXH: log(f'    exc {c:#x} @ {a:#x} -> {e:#x}')
            log(f'[veh] handler không xử lý (ret {rv:#x}) code={r32(EXC):#x} addr={r32(EXC + 0xc):#x} fault={CTX.get("last_fault")}')
            ev('veh_unhandled', code=r32(EXC), addr=r32(EXC + 0xc)); dump_ring(); CTX['stop'] = True; uc.emu_stop(); return
        vals = {k: r32(CTX['excctx'] + o) for k, o in CTXREGS.items()}
        for k, v in vals.items(): uc.reg_write(R(k), v)
        CTX['veh_count'] = CTX.get('veh_count', 0) + 1
        EXH.append((r32(EXC), r32(EXC + 0xc), vals['EIP']))
mu.hook_add(UC_HOOK_CODE, on_magic, begin=MAGIC + 0x100, end=MAGIC + 0x200)

EXC = alloc(0x1000)
EXCN = collections.Counter()
def raise_exc(uc, code, addr, eip_ctx, tf=False):
    """Phát ngoại lệ tới VEH với EXCEPTION_RECORD + CONTEXT giống Windows."""
    CTX['exc_in_step'] = True
    if not VEH:
        log(f'[exc] {code:#x} @ {addr:#x} nhưng chưa có VEH'); ev('exc_no_veh', code=code, addr=addr); CTX['stop'] = True; uc.emu_stop(); return
    rec, ctxp, ptrs = EXC, EXC + 0x100, EXC + 0x400
    mu.mem_write(EXC, b'\0' * 0x500)
    w32(rec, code); w32(rec + 0xc, addr)
    if code == 0xc0000005:   # ExceptionInformation: [0]=đọc/ghi/thực thi, [1]=địa chỉ lỗi (handler đọc trường này)
        fa, fw = CTX.get('last_fault', (0, 0))
        w32(rec + 0x10, 2); w32(rec + 0x14, fw); w32(rec + 0x18, fa)
    w32(ctxp, 0x1003f)   # Dr0-Dr7 = 0: handler kiểm tra breakpoint phần cứng
    for k, o in CTXREGS.items():
        if k != 'EIP': w32(ctxp + o, uc.reg_read(R(k)))
    fl = r32(ctxp + 0xc0) & ~0x100   # Windows xóa TF khi phát single-step
    if tf: fl |= 0x100                # lệnh mang TF lại gây lỗi: lỗi thắng, TF còn nguyên trong CONTEXT
    w32(ctxp + 0xc0, fl)
    w32(ctxp + 0xb8, eip_ctx); w32(ctxp + 0xbc, 0x1b); w32(ctxp + 0xc8, 0x23)
    w32(ptrs, rec); w32(ptrs + 4, ctxp)
    CTX['excctx'] = ctxp
    esp = ((uc.reg_read(UC_X86_REG_ESP) - 0x800) & ~0xf) - 8
    w32(esp, MAGIC + 0x200); w32(esp + 4, ptrs)
    uc.reg_write(UC_X86_REG_ESP, esp); uc.reg_write(UC_X86_REG_EIP, VEH[0])
    uc.reg_write(UC_X86_REG_EFLAGS, uc.reg_read(UC_X86_REG_EFLAGS) & ~0x100)
    EXCN[code] += 1
    if EXCN[code] <= 3: log(f'[exc] {code:#x} @ {addr:#x}')

def on_intr(uc, intno, _):
    eip = uc.reg_read(UC_X86_REG_EIP)
    if intno == 3: raise_exc(uc, 0x80000003, eip - 1, eip - 1)
    elif intno == 1: raise_exc(uc, 0x80000004, eip, eip)
    elif intno in (13, 8): raise_exc(uc, 0xc0000096, eip, eip)   # #GP/#DF ở ring 3: invd, lmsw, lldt, clts...
    elif intno == 6: raise_exc(uc, 0xc000001d, eip, eip)
    else: log(f'[intr] {intno} @ {eip:#x}'); ev('intr', n=intno, eip=eip); CTX['stop'] = True; uc.emu_stop()
mu.hook_add(UC_HOOK_INTR, on_intr)

def on_cpuid(uc, _):
    a, b, c, d = {0: (0x16, 0x756e6547, 0x6c65746e, 0x49656e69), 1: (0x000906ea, 0x00100800, 0x7ffafbbf, 0xbfebfbff)}.get(uc.reg_read(UC_X86_REG_EAX), (0, 0, 0, 0))
    for r, v in zip((UC_X86_REG_EAX, UC_X86_REG_EBX, UC_X86_REG_ECX, UC_X86_REG_EDX), (a, b, c, d)): uc.reg_write(r, v)
    CTX['cpuid'] = CTX.get('cpuid', 0) + 1
    return True
mu.hook_add(UC_HOOK_INSN, on_cpuid, None, 1, 0, UC_X86_INS_CPUID)

def on_unmapped(uc, acc, addr, size, val, _):
    CTX['last_fault'] = (addr, 1 if acc in (UC_MEM_WRITE_UNMAPPED, UC_MEM_WRITE_PROT) else (8 if acc == UC_MEM_FETCH_UNMAPPED else 0))
    return False
mu.hook_add(UC_HOOK_MEM_UNMAPPED, on_unmapped)

RING = collections.deque(maxlen=A.ring or 1)
if A.ring:
    mu.hook_add(UC_HOOK_CODE, lambda uc, addr, size, _: RING.append((addr, uc.reg_read(UC_X86_REG_ESP))))
def dump_ring():
    for x, sp in RING:
        ins = next(md.disasm(bytes(mu.mem_read(x, 16)), x), None)
        log(f'    {x:#x}: [{sp:#x}] {ins.mnemonic} {ins.op_str}' if ins else f'    {x:#x}: ?')
    RING.clear()

# TF thủ công: unicorn không bẫy single-step tin cậy (nhất là ngay sau popfd và ở lệnh nhảy)
JCC = {'jo': lambda f: f & 0x800, 'jno': lambda f: not f & 0x800, 'jb': lambda f: f & 1, 'jae': lambda f: not f & 1,
       'je': lambda f: f & 0x40, 'jne': lambda f: not f & 0x40, 'jbe': lambda f: f & 0x41, 'ja': lambda f: not f & 0x41,
       'js': lambda f: f & 0x80, 'jns': lambda f: not f & 0x80, 'jp': lambda f: f & 4, 'jnp': lambda f: not f & 4,
       'jl': lambda f: bool(f & 0x80) != bool(f & 0x800), 'jge': lambda f: bool(f & 0x80) == bool(f & 0x800),
       'jle': lambda f: f & 0x40 or bool(f & 0x80) != bool(f & 0x800), 'jg': lambda f: not f & 0x40 and bool(f & 0x80) == bool(f & 0x800),
       'jmp': lambda f: True}
NBLK = [0]
def on_block(uc, addr, size, _):
    NBLK[0] += 1
    if uc.reg_read(UC_X86_REG_EFLAGS) & 0x100 and not CTX.get('tf_pend'):
        CTX['tf_pend'] = addr; uc.emu_stop()
mu.hook_add(UC_HOOK_BLOCK, on_block, begin=BASE, end=BASE + SIZE)

def save_snapshot(path, eip):
    pages = []
    for b, e, prot in mu.mem_regions():
        for c in range(b, e + 1, 0x100000):
            n = min(0x100000, e + 1 - c); data = bytes(mu.mem_read(c, n))
            for o in range(0, n, 0x1000):
                pg = data[o:o+0x1000]
                if pg.count(0) != len(pg): pages.append((c + o, pg))
    regs = {r: mu.reg_read(R(r)) for r in REGN + ('EFLAGS',)}; regs['EIP'] = eip
    keep = {k: v for k, v in CTX.items() if isinstance(v, (int, str, bool, list, tuple)) or v is None}
    st = {'regions': [(b, e) for b, e, p in mu.mem_regions()], 'regs': regs, 'ctx': keep, 'veh': VEH, 'mods': MODORDER,
          'alloc': ALLOC[0], 'heapp': HEAPP[0], 'ccount': CCOUNT, 'child': CHILD, 'strs': sorted(STRS)}
    with open(path, 'wb') as f:
        pickle.dump(st, f); f.write(zlib.compress(b''.join(struct.pack('<I', a) + pg for a, pg in pages), 1))
    log(f'[snap] {len(pages)} trang -> {path}'); ev('snapshot', path=path, api=STUBS.get(eip, ('', ''))[1])

# ---- module mặc định + plugin ----
make_module('ntdll.dll'); make_module('kernel32.dll'); make_module('kernelbase.dll')
build_ldr([(EXEPATH.split('\\')[-1], EXE, 0x80000)] + [(n, MODS[n]['base'], MODS[n]['size']) for n in ('ntdll.dll', 'kernel32.dll', 'kernelbase.dll')])
for spec in A.plugin:
    path, _, kv = spec.partition(':')
    opts = dict(x.split('=', 1) for x in kv.split(',') if x)
    sp = importlib.util.spec_from_file_location(os.path.basename(path)[:-3], path)
    m = importlib.util.module_from_spec(sp); sp.loader.exec_module(m)
    m.setup(globals(), opts)

for k, v in REGS.items(): mu.reg_write(R(k), v)
pc = REGS['EIP']
if A.resume:
    with open(A.resume, 'rb') as f:
        sn = pickle.load(f); blob = zlib.decompress(f.read())
    for m in sn['mods']:
        if m not in MODS: make_module(m)
    for b, e in sn['regions']:   # map phần chưa map theo khối liền
        mapped = sorted((bb, ee) for bb, ee, p in mu.mem_regions())
        cur = None
        for pg in range(b, e + 2, 0x1000):
            free = pg <= e and not any(bb <= pg <= ee for bb, ee in mapped)
            if free and cur is None: cur = pg
            if not free and cur is not None: mu.mem_map(cur, pg - cur); cur = None
    for o in range(0, len(blob), 0x1004):
        mu.mem_write(struct.unpack_from('<I', blob, o)[0], blob[o+4:o+0x1004])
    for mb, hb in MODHDR.items(): mu.mem_write(mb, hb)   # header module mới đè lên snapshot cũ
    ALLOC[0] = sn['alloc']; HEAPP[0] = sn['heapp']; VEH[:] = sn['veh']; CCOUNT.update(sn['ccount'])
    CHILD.update(sn['child']); STRS.update(sn['strs'])
    CTX.update(sn['ctx']); CTX['stop'] = False; CTX['resumed_skip'] = True
    REGS = sn['regs']; pc = REGS['EIP']
    for k, v in REGS.items():
        if k != 'EIP': mu.reg_write(R(k), v)
    ALLOCS_SEEN.append(0)
    log(f'[resume] {A.resume} eip={pc:#x}')
# khối biến môi trường (PEB->ProcessParameters->Environment, UTF-16)
ENVV = ['ALLUSERSPROFILE=C:\\ProgramData', 'APPDATA=C:\\Users\\admin\\AppData\\Roaming', 'CommonProgramFiles=C:\\Program Files (x86)\\Common Files',
        'COMPUTERNAME=DESKTOP-7Q2K4LM', 'ComSpec=C:\\Windows\\system32\\cmd.exe', 'HOMEDRIVE=C:', 'HOMEPATH=\\Users\\admin',
        'LOCALAPPDATA=C:\\Users\\admin\\AppData\\Local', 'NUMBER_OF_PROCESSORS=4', 'OS=Windows_NT',
        'Path=C:\\Windows\\system32;C:\\Windows;C:\\Windows\\System32\\Wbem', 'PROCESSOR_ARCHITECTURE=x86', 'PROCESSOR_ARCHITEW6432=AMD64',
        'ProgramData=C:\\ProgramData', 'ProgramFiles=C:\\Program Files (x86)', 'ProgramFiles(x86)=C:\\Program Files (x86)', 'ProgramW6432=C:\\Program Files',
        'PUBLIC=C:\\Users\\Public', 'SystemDrive=C:', 'SystemRoot=C:\\Windows', 'TEMP=C:\\Users\\admin\\AppData\\Local\\Temp',
        'TMP=C:\\Users\\admin\\AppData\\Local\\Temp', 'USERDOMAIN=DESKTOP-7Q2K4LM', 'USERNAME=admin', 'USERPROFILE=C:\\Users\\admin', 'windir=C:\\Windows']
ENVB = 0x7fd00000
try: mu.mem_map(ENVB, 0x2000)
except UcError: pass
envblob = ''.join(v + '\0' for v in ENVV).encode('utf-16le') + b'\0\0'
mu.mem_write(ENVB, envblob); w32(PP + 0x48, ENVB); w32(PP + 0x290, len(envblob))

# xuống ring 3 bằng iretd để lệnh đặc quyền (invd, lmsw, cli...) gây #GP như trên Windows
mu.mem_write(MAGIC + 0x300, b'\xcf')
esp0 = mu.reg_read(UC_X86_REG_ESP); fr = esp0 - 0x40
for i, v in enumerate((pc, 16 << 3 | 3, REGS['EFLAGS'] & ~0x3000 | 0x202, esp0, 15 << 3 | 3)): w32(fr + 4 * i, v)
mu.reg_write(UC_X86_REG_ESP, fr)
mu.emu_start(MAGIC + 0x300, pc, count=1)
mu.reg_write(UC_X86_REG_EFLAGS, REGS['EFLAGS'])
ev('start', eip=pc, off=pc - BASE, base=BASE, mode='child' if A.child else 'blob')

RESOLVED = set()
def finish(reason):
    ev('end', reason=reason, eip=mu.reg_read(UC_X86_REG_EIP), api_calls=CALLS[0], veh=CTX.get('veh_count', 0),
       exceptions={hex(k): v for k, v in EXCN.items()}, top_api=collections.Counter(CCOUNT).most_common(12),
       api_unused=sorted(n for n in RESOLVED if n and n not in CCOUNT),   # resolve qua GetProcAddress mà chưa gọi: hành vi chưa chạy tới
       seconds=round(time.time() - t0), **({'unhandled': CTX['unhandled']} if CTX.get('unhandled') else {}))
t0 = time.time()
reason = 'max-steps'
for i in range(A.max_steps):
    NBLK[0] = 0
    try:
        mu.emu_start(pc, 0xdeadbeef, count=5_000_000)
    except UcError as e:
        pc = mu.reg_read(UC_X86_REG_EIP); esp = mu.reg_read(UC_X86_REG_ESP)
        if e.errno in (UC_ERR_WRITE_UNMAPPED, UC_ERR_READ_UNMAPPED, UC_ERR_FETCH_UNMAPPED, UC_ERR_INSN_INVALID) and VEH and STK <= esp < 0x7f000000:
            try:
                raise_exc(mu, 0xc000001d if e.errno == UC_ERR_INSN_INVALID else 0xc0000005, pc, pc); pc = mu.reg_read(UC_X86_REG_EIP); continue
            except UcError:
                log(f'[raise fail] esp={esp:#x} pc={pc:#x}')
        try: ins = next(md.disasm(bytes(mu.mem_read(pc, 16)), pc), None)
        except UcError: ins = None
        log(f'ERR {e} @ {pc:#x} {ins.mnemonic + " " + ins.op_str if ins else ""}'); dump_ring()
        reason = f'error {e} @ {pc:#x} (+{pc - BASE:#x})'; break
    npc = mu.reg_read(UC_X86_REG_EIP)
    if CTX.get('tf_pend'):
        CTX.pop('tf_pend')
        mu.reg_write(UC_X86_REG_EFLAGS, mu.reg_read(UC_X86_REG_EFLAGS) & ~0x100)
        CTX['exc_in_step'] = False
        try:
            mu.emu_start(npc, 0xffffffff, count=1)
        except UcError as e:
            fpc = mu.reg_read(UC_X86_REG_EIP)
            raise_exc(mu, 0xc000001d if e.errno == UC_ERR_INSN_INVALID else 0xc0000005, fpc, fpc, tf=True); pc = mu.reg_read(UC_X86_REG_EIP); continue
        if CTX['stop']: reason = 'stop'; break
        n2 = mu.reg_read(UC_X86_REG_EIP)
        if n2 == npc:   # QEMU không chạy được lệnh: lệnh nhảy -> tự tính nhánh; còn lại coi là #UD
            ins = next(md.disasm(bytes(mu.mem_read(npc, 16)), npc), None)
            if ins and ins.mnemonic in JCC and ins.op_str.startswith('0x'):
                n2 = int(ins.op_str, 16) if JCC[ins.mnemonic](mu.reg_read(UC_X86_REG_EFLAGS)) else npc + ins.size
            else:
                raise_exc(mu, 0xc000001d, npc, npc, tf=True); pc = mu.reg_read(UC_X86_REG_EIP); continue
        if CTX.get('exc_in_step'):
            CTX['exc_in_step'] = False; pc = mu.reg_read(UC_X86_REG_EIP); continue
        mu.reg_write(UC_X86_REG_EIP, n2)
        raise_exc(mu, 0x80000004, n2, n2); pc = mu.reg_read(UC_X86_REG_EIP); continue
    if npc == pc and not CTX['stop'] and NBLK[0] <= 1:
        # unicorn dừng im lặng tại chỗ (không chạy khối nào): lệnh nhảy khi TF bật, hoặc lệnh không hợp lệ
        ins = next(md.disasm(bytes(mu.mem_read(pc, 8)) + bytes(8), pc), None)
        fl = mu.reg_read(UC_X86_REG_EFLAGS)
        if ins and ins.mnemonic in JCC and ins.op_str.startswith('0x'):
            nxt = int(ins.op_str, 16) if JCC[ins.mnemonic](fl) else pc + ins.size
            mu.reg_write(UC_X86_REG_EFLAGS, fl & ~0x100)
            raise_exc(mu, 0x80000004, nxt, nxt); pc = mu.reg_read(UC_X86_REG_EIP); continue
        raise_exc(mu, 0xc000001d, pc, pc); npc = mu.reg_read(UC_X86_REG_EIP)
    pc = npc
    if CTX['stop']: reason = 'stop'; dump_ring(); break
    if i % 5000 == 0: log(f'.. step {i} eip={pc:#x} veh={CTX.get("veh_count", 0)} api={CALLS[0]} t={time.time() - t0:.0f}s')
finish(reason)
LOG.close(); EVF.close()

# cha đã tiêm rồi tự thoát: điểm vào con = giá trị 4 byte cuối cùng cha ghi vào con trỏ trong tiến trình con
if A.chain_child and not A.child and CHILD.get('big'):
    dst, n, p = CHILD['big']
    ents = [struct.unpack('<I', h)[0] for d, k, h in CHILD['writes'] if k == 4 and dst <= struct.unpack('<I', h)[0] < dst + n]
    if ents:
        argv = [sys.executable, os.path.abspath(__file__), '--child', p, '--entry', hex(ents[-1] - dst), '--out', A.out, '--tag', 'child',
                '--exe-path', A.exe_path, '--max-steps', str(A.max_steps)]
        if A.exe: argv += ['--exe', A.exe]
        if A.fake_dl: argv += ['--fake-dl', hex(A.fake_dl)]
        if A.fake_dl_file: argv += ['--fake-dl-file', A.fake_dl_file]
        if A.stop_at: argv += ['--stop-at', A.stop_at]
        if A.snap_at: argv += ['--snap-at', A.snap_at]
        if A.ring: argv += ['--ring', str(A.ring)]
        for s in A.plugin: argv += ['--plugin', s]
        with open(os.path.join(A.out, 'events.jsonl'), 'a') as f:
            f.write(json.dumps({'proc': 'parent', 'kind': 'chain_child', 'entry_off': hex(ents[-1] - dst)}) + '\n')
        atexit._run_exitfuncs()   # execv không chạy atexit: plugin dump (stage-2…) của cha sẽ mất nếu bỏ dòng này
        os.execv(sys.executable, argv)
