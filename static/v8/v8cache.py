#!/usr/bin/env python3
# Đọc tĩnh code cache của V8 (file .jsc kiểu bytenode, có thể bọc brotli): phân tích cú pháp luồng snapshot thành đồ thị
# đối tượng rồi disassemble BytecodeArray. Không nạp cache vào V8, không thực thi gì của mẫu.
# Hỗ trợ: V8 10.2 (Node.js 18.x), không pointer compression. Bản khác: luồng không đọc hết -> báo lỗi rõ, không đoán.
import json, os, struct, sys
HERE = os.path.dirname(os.path.abspath(__file__))
sys.setrecursionlimit(100000)

def tables(ver='10.2'): return json.load(open(os.path.join(HERE, 'v8_%s.json' % ver.replace('.', '_')), encoding='utf-8'))

def is_cache(d):
    """Header SerializedCodeData: magic 0xC0DE.... (2 byte cao), payload_length ở offset 16."""
    return len(d) >= 24 and d[2:4] == b'\xde\xc0' and struct.unpack_from('<I', d, 16)[0] + 24 in (len(d), (len(d) + 7) & ~7)

def unwrap(d):
    """Trả (cache, lớp bọc). Lớp bọc: '' hoặc 'brotli'. Không phải code cache -> (None, '')."""
    if is_cache(d): return d, ''
    try:
        import brotli
        r = brotli.decompress(d)
        if is_cache(r): return r, 'brotli'
    except Exception: pass
    return None, ''

class Obj:
    __slots__ = ('i', 'space', 'size', 'raw', 'refs', 'off')
    def __init__(s, i, space, size, off): s.i = i; s.space = space; s.size = size; s.raw = bytearray(size * 8); s.refs = {}; s.off = off

class ParseError(Exception): pass

class Deserializer:
    """Ngữ pháp luồng snapshot (src/snapshot/deserializer.cc của V8 10.2). Tham chiếu: ('obj', i) | ('root', i) | ('ro', chunk, off)
    | ('att', i) | ('weak', ref) | ('cleared',). Chỉ số backref = thứ tự cấp phát; 8 hot object theo hàng đợi vòng."""
    def __init__(s, d, pos=24): s.d = d; s.p = pos; s.objs = []; s.hot = [None] * 8; s.hi = 0; s.weak = False; s.pending = {}; s.npend = 0
    def get(s): b = s.d[s.p]; s.p += 1; return b
    def getint(s):
        a = int.from_bytes(s.d[s.p:s.p + 4], 'little'); n = (a & 3) + 1; s.p += n; return (a & ((1 << (8 * n)) - 1)) >> 2
    def addhot(s, r): s.hot[s.hi] = r; s.hi = (s.hi + 1) & 7
    def read_object(s, space, off):
        size = s.getint(); mp = s.read_one()
        o = Obj(len(s.objs), space, size, off); s.objs.append(o); o.refs[0] = mp
        w = 1
        while w < size: w += s.read_into(o, w)
        if w != size: raise ParseError(f'đối tượng @{off:#x}: đọc {w} slot, khai báo {size}')
        return ('obj', o.i)
    def read_one(s):
        tmp = Obj(-1, 0, 1, s.p); n = 0
        while n == 0: n = s.read_into(tmp, 0)
        if n != 1: raise ParseError(f'@{s.p:#x}: cần 1 slot, được {n}')
        return tmp.refs[0]
    def read_into(s, o, w):
        off = s.p; b = s.get()
        def wr(r, k=1):
            if s.weak: r = ('weak', r); s.weak = False
            for j in range(k): o.refs[w + j] = r
            return k
        def raw(n): o.raw[w * 8:(w + n) * 8] = s.d[s.p:s.p + n * 8]; s.p += n * 8; return n
        if b < 4:
            wk = s.weak; s.weak = False; r = s.read_object(b, off); o.refs[w] = ('weak', r) if wk else r; return 1
        if b == 0x04: r = ('obj', s.getint()); s.addhot(r); return wr(r)
        if b == 0x05: c = s.getint(); return wr(('ro', c, s.getint()))
        if b == 0x06: return wr(('startup', s.getint()))
        if b == 0x07: r = ('root', s.getint()); s.addhot(r); return wr(r)
        if b == 0x08: return wr(('att', s.getint()))
        if b == 0x09: return wr(('rocache', s.getint()))
        if b == 0x0a: return wr(('shared', s.getint()))
        if b == 0x0b: return 0
        if b == 0x0d: k = s.getint() + 18; return wr(s.read_one(), k)
        if b == 0x11: return raw(s.getint())
        if b == 0x17: return wr(('cleared',))
        if b == 0x18: s.weak = True; return 0
        if b == 0x1a: pid = s.npend; s.npend += 1; s.pending[pid] = (o, w); o.refs[w] = ('pending', pid); return 1
        if b == 0x1b: po, pw = s.pending.pop(s.getint()); po.refs[pw] = ('obj', o.i); return 0
        if 0x40 <= b < 0x60: return wr(('root', b - 0x40))
        if 0x60 <= b < 0x80: return raw(b - 0x60 + 1)
        if 0x80 <= b < 0x90: return wr(s.read_one(), b - 0x80 + 2)
        if 0x90 <= b < 0x98: return wr(s.hot[b - 0x90])
        raise ParseError(f'bytecode snapshot lạ {b:#x} @{off:#x}')
    def run(s):
        root = s.read_one()
        while True:
            off = s.p; c = s.get()
            if c == 0x0c: break
            if c >= 4: raise ParseError(f'mục deferred lạ {c:#x} @{off:#x}')
            s.read_object(c, off)
        return root

def parse(d):
    """d: code cache đã gỡ lớp bọc. Trả (root, [(i, space, size, off, raw, refs)]); lỗi -> ParseError kèm lý do."""
    de = Deserializer(d)
    try: root = de.run()
    except (IndexError, KeyError, RecursionError, struct.error) as e: raise ParseError(f'luồng hỏng hoặc khác phiên bản V8 ({type(e).__name__} @{de.p:#x}, {len(de.objs)} đối tượng)')
    if de.pending: raise ParseError(f'còn {len(de.pending)} tham chiếu treo')
    if len(d) - de.p > 8: raise ParseError(f'dừng ở {de.p:#x}/{len(d):#x}: không đọc hết luồng')
    return root, [(o.i, o.space, o.size, o.off, bytes(o.raw), o.refs) for o in de.objs]

FIXED = {'Flag8': 1, 'IntrinsicId': 1, 'RuntimeId': 2, 'Flag16': 2}
SIGNED = {'Imm', 'Reg', 'RegList', 'RegPair', 'RegOut', 'RegOutList', 'RegOutPair', 'RegOutTriple'}
CONSTIDX = {'LdaConstant': 0, 'LdaGlobal': 0, 'LdaGlobalInsideTypeof': 0, 'StaGlobal': 0, 'GetNamedProperty': 1, 'GetNamedPropertyFromSuper': 1,
            'SetNamedProperty': 1, 'DefineNamedOwnProperty': 1, 'CreateClosure': 0, 'CreateArrayLiteral': 0, 'CreateObjectLiteral': 0,
            'CreateRegExpLiteral': 0, 'GetTemplateObject': 0, 'LdaLookupSlot': 0, 'LdaLookupGlobalSlot': 0, 'CreateBlockContext': 0,
            'CreateCatchContext': 1, 'CreateFunctionContext': 0, 'CreateWithContext': 1, 'ThrowReferenceErrorIfHole': 0, 'CreateEvalContext': 0,
            'StaLookupSlot': 0, 'LdaLookupContextSlot': 0}

def reg(v):
    """Operand -> tên: -1 ngữ cảnh hiện tại, -2 closure, tham số a<k> (a2 = this, a3 = tham số đầu), còn lại r<n> (StarN ghi r<n>)."""
    return '<context>' if v == -1 else '<closure>' if v == -2 else 'r%d' % (-v - 6) if v < 0 else 'a%d' % v

class Heap:
    def __init__(s, src, ver='10.2'):
        s.root, s.o = parse(open(src, 'rb').read()) if isinstance(src, str) else src   # src: đường dẫn cache đã gỡ vỏ, hoặc kết quả parse()
        T = tables(ver); s.ops = T['ops']; s.ro = T['ro_roots']; s.rstr = T['str_roots']; s.start = T['bytecode_start']; s._dis = {}
    def rootname(s, i):
        if i < len(s.ro): return s.ro[i]
        j = i - len(s.ro)
        return 'str:' + s.rstr[j] if j < len(s.rstr) else 'root#%d' % i
    def rootstr(s, i):
        if i < len(s.ro): return '' if s.ro[i] == 'empty_string' else None
        j = i - len(s.ro)
        return s.rstr[j] if j < len(s.rstr) else None
    def mapname(s, i):
        r = s.o[i][5].get(0)
        return s.rootname(r[1]) if r and r[0] == 'root' else str(r)
    def isstr(s, i): return 'string_map' in s.mapname(i)
    def smi(s, i, w): return struct.unpack_from('<q', s.o[i][4], w * 8)[0] >> 32
    def string(s, i):
        mn = s.mapname(i); raw = s.o[i][4]; n = struct.unpack_from('<I', raw, 12)[0]
        if 'one_byte' in mn: return raw[16:16 + n].decode('latin1')
        if 'string_map' in mn: return raw[16:16 + 2 * n].decode('utf-16le', 'replace')
        return None
    def slot(s, i, w):
        o = s.o[i]
        return o[5][w] if w in o[5] else ('smi', struct.unpack_from('<q', o[4], w * 8)[0] >> 32)
    def desc(s, r):
        t = r[0]
        if t == 'smi': return 'smi:%d' % r[1]
        if t == 'root': return '<' + s.rootname(r[1]) + '>'
        if t == 'weak': return 'weak:' + s.desc(r[1])
        if t != 'obj': return str(r)
        i = r[1]; mn = s.mapname(i)
        if 'string_map' in mn: return repr(s.string(i))
        if mn == 'heap_number_map': return 'num:%r' % struct.unpack_from('<d', s.o[i][4], 8)[0]
        if mn == 'shared_function_info_map': return 'SFI#%d' % i
        if mn == 'fixed_array_map': return 'FixedArray#%d[%d]' % (i, s.smi(i, 1))
        return '%s#%d' % (mn, i)
    def is_bc(s, i): return s.mapname(i) == 'bytecode_array_map'
    def bcs(s): return [o[0] for o in s.o if s.is_bc(o[0])]
    def bytecode(s, i): return s.o[i][4][s.start:s.start + s.smi(i, 1)]
    def blen(s, i): return s.smi(i, 1)
    def cpool(s, i):
        r = s.o[i][5].get(2); return r[1] if r and r[0] == 'obj' else None
    def const(s, bi, k):
        cp = s.cpool(bi); return s.slot(cp, 2 + k) if cp is not None else ('smi', 0)
    def bc_of(s, sfi):
        r = s.o[sfi][5].get(1)
        return r[1] if r and r[0] == 'obj' and s.is_bc(r[1]) else None
    def dis(s, i):
        if i in s._dis: return s._dis[i]
        bc = s.bytecode(i); p = 0; out = []
        while p < len(bc):
            st = p; scale = 1; op = bc[p]; p += 1
            if op < 2: scale = 2 if op == 0 else 4; op = bc[p]; p += 1
            name, ots, _ = s.ops[op]; args = []
            for ot in ots:
                n = FIXED.get(ot, scale); args.append((ot, int.from_bytes(bc[p:p + n], 'little', signed=ot in SIGNED and ot not in FIXED))); p += n
            out.append((st, name, args))
        if len(s._dis) < 200000: s._dis[i] = out
        return out
    def fmt(s, bi, ins):
        st, name, args = ins
        a = [reg(v) if ot.startswith('Reg') and ot != 'RegCount' else ('#%d' if ot == 'Imm' else '%d') % v for ot, v in args]
        ci = CONSTIDX.get(name); extra = ''
        if ci is not None and s.cpool(bi) is not None:
            try: extra = ' ; ' + s.desc(s.const(bi, args[ci][1]))
            except Exception: extra = ' ; ?'
        return '%5d %s %s%s' % (st, name, ', '.join(a), extra)
    def toplevel_names(s):
        """Hàm khai báo ở cấp cao nhất: tên -> SFI. Lấy từ mảng khai báo (hằng số 0 của script gốc) và ScopeInfo của từng SFI."""
        rb = s.bc_of(s.root[1]) if s.root[0] == 'obj' else None
        if rb is None: return {}
        r = s.const(rb, 0); out = {}
        if r[0] != 'obj' or s.mapname(r[1]) != 'fixed_array_map': return out
        for k in range(s.smi(r[1], 1)):
            e = s.slot(r[1], 2 + k)
            if e[0] != 'obj' or s.mapname(e[1]) != 'shared_function_info_map': continue
            nm = s.o[e[1]][5].get(2); name = None
            if nm and nm[0] == 'obj':
                if s.isstr(nm[1]): name = s.string(nm[1])
                else:
                    ss = [s.string(x[1]) for w, x in sorted(s.o[nm[1]][5].items()) if w > 0 and x[0] == 'obj' and s.isstr(x[1])]
                    name = ss[-1] if ss else None
            if name: out.setdefault(name, e[1])
        return out
    def cpool_strings(s, bi):
        cp = s.cpool(bi); out = []
        if cp is None: return out
        for w, r in s.o[cp][5].items():
            if w < 2: continue
            if r[0] == 'obj' and s.isstr(r[1]): out.append(s.string(r[1]))
            elif r[0] == 'root' and s.rootstr(r[1]): out.append(s.rootstr(r[1]))
        return out
