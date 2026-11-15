#!/usr/bin/env python3
# Giải chuỗi cho bytecode V8 bị làm rối kiểu obfuscator.io: mảng chuỗi + base64 (bảng chữ cái đảo hoa/thường) [+ RC4 khóa theo
# từng lời gọi] + xoay mảng + tách mảnh + wrapper cộng trừ offset. Cách làm: tự dò mảng, hàm giải mã, offset, hàm xoay; tái hiện
# thuật toán bằng Python; lan truyền hằng trên bytecode để gắn (chỉ số, khóa) cho từng lời gọi và ghép mảnh. Không chạy mã mẫu.
import base64, collections, math, os, re, struct, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
STD = b'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'
CUS = b'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+/'
TR = bytes.maketrans(CUS, STD)

def b64(s):
    b = s.encode('latin1').translate(TR); b = b[:len(b) - (len(b) % 4 == 1)]
    return base64.b64decode(b + b'=' * (-len(b) % 4)).decode('utf-8')

def rc4(ct, key):
    S = list(range(256)); j = 0
    for i in range(256): j = (j + S[i] + ord(key[i % len(key)])) & 255; S[i], S[j] = S[j], S[i]
    i = j = 0; out = []
    for c in ct:
        i = (i + 1) & 255; j = (j + S[i]) & 255; S[i], S[j] = S[j], S[i]; out.append(chr(ord(c) ^ S[(S[i] + S[j]) & 255]))
    return ''.join(out)

def parse_int(s):
    m = re.match(r'\s*([+-]?\d+)', s); return int(m.group(1)) if m else math.nan

class S:   # chuỗi hằng; t = có thành phần giải mã, used = đã bị ghép vào chuỗi dài hơn
    __slots__ = ('v', 't', 'used', 'pos')
    def __init__(s, v, t=False): s.v = v; s.t = t; s.used = False; s.pos = None
class JObj(dict): pass
class Ctx:
    __slots__ = ('parent', 'slots')
    def __init__(s, parent): s.parent = parent; s.slots = {}
class Clo:
    __slots__ = ('sfi', 'ctx')
    def __init__(s, sfi, ctx): s.sfi = sfi; s.ctx = ctx
class Glob:
    __slots__ = ('name',)
    def __init__(s, n): s.name = n
def num(x): return isinstance(x, (int, float)) and not isinstance(x, bool)
def jsstr(x): return x.v if isinstance(x, S) else str(int(x)) if isinstance(x, float) and x == int(x) else str(x)

def detect(h):
    """Dò cấu trúc làm rối. Trả dict {arr, n, offset, rc4, dec_name, dec_bc, rot_bc, target} hoặc None nếu không phải kiểu này."""
    alpha = [o[0] for o in h.o if h.isstr(o[0]) and (h.string(o[0]) or '').startswith(CUS.decode())]
    if not alpha: return None
    refs = collections.defaultdict(list)       # đối tượng -> các bc có constant pool trỏ tới nó
    cp2bc = {h.cpool(b): b for b in h.bcs() if h.cpool(b) is not None}
    sfi_of = {}
    for o in h.o:
        if h.mapname(o[0]) == 'shared_function_info_map' and h.bc_of(o[0]) is not None: sfi_of[h.bc_of(o[0])] = o[0]
        if o[0] in cp2bc:
            for w, r in o[5].items():
                if w >= 2 and r[0] == 'obj': refs[r[1]].append(cp2bc[o[0]])
    def parents(bc): return refs.get(sfi_of.get(bc), [])
    D = {}
    for a in alpha:
        for b64bc in refs.get(a, []):
            for inner in parents(b64bc):          # hàm giải mã thật: trừ offset rồi lấy phần tử mảng
                ins = h.dis(inner); off = None
                for k, (st, n, ar) in enumerate(ins[:14]):
                    if n in ('SubSmi', 'AddSmi') and k and ins[k - 1][1] == 'Ldar' and ins[k - 1][2][0][1] == 3:
                        off = ar[0][1] if n == 'SubSmi' else -ar[0][1]; break
                if off is None: continue
                kids = [h.bc_of(r[1]) for st, n, ar in ins if n == 'CreateClosure' for r in [h.const(inner, ar[0][1])] if r[0] == 'obj']
                D['rc4'] = any(k is not None and any(n == 'ModSmi' and ar[0][1] == 256 for st, n, ar in h.dis(k)) for k in kids)
                D['offset'] = off; D['dec_bc'] = inner
                for outer in parents(inner):
                    io = h.dis(outer)
                    for k, (st, n, ar) in enumerate(io):
                        if n == 'CreateClosure' and h.const(outer, ar[0][1]) == ('obj', sfi_of[inner]) and k + 1 < len(io) and io[k + 1][1] == 'StaGlobal':
                            r = h.const(outer, io[k + 1][2][0][1]); D['dec_name'] = h.string(r[1]) if r[0] == 'obj' else h.rootstr(r[1])
                break
            if 'offset' in D: break
        if 'offset' in D: break
    if 'dec_name' not in D: return None
    best = None
    for o in h.o:                                    # mảng chuỗi: mảng COW toàn chuỗi, lớn nhất
        if h.mapname(o[0]) == 'fixed_cow_array_map' and o[2] > 16 and (best is None or o[2] > h.o[best][2]):
            if all(r[0] == 'obj' and h.isstr(r[1]) for w, r in list(o[5].items())[1:40] if w >= 2): best = o[0]
    if best is None: return None
    D['arr'] = best; D['n'] = h.smi(best, 1); D['rot_bc'] = D['target'] = None
    for b in h.bcs():                                # hàm xoay mảng: parseInt + push + shift, so sánh với tham số thứ hai
        cs = set(h.cpool_strings(b))
        if {'parseInt', 'push', 'shift'} <= cs and h.blen(b) < 4000 and any(n == 'TestEqualStrict' for st, n, ar in h.dis(b)):
            D['rot_bc'] = b; sfi = sfi_of.get(b)
            for p in refs.get(sfi, []):
                ip = h.dis(p)
                for k, (st, n, ar) in enumerate(ip):
                    if n == 'CreateClosure' and h.const(p, ar[0][1]) == ('obj', sfi):
                        for st2, n2, ar2 in ip[k + 1:k + 10]:
                            if n2 == 'LdaSmi': D['target'] = ar2[0][1]
                            elif n2 == 'LdaConstant':
                                r = h.const(p, ar2[0][1])
                                if r[0] == 'obj' and h.mapname(r[1]) == 'heap_number_map': D['target'] = struct.unpack_from('<d', h.o[r[1]][4], 8)[0]
                            elif n2.startswith('Call'): break
            break
    return D

class Resolver:
    def __init__(s, h, D, rostr=None):
        s.h = h; s.D = D; s.rostr = rostr or {}; s.rot = 0; s.memo = True
        s.arr = [h.string(h.slot(D['arr'], 2 + k)[1]) for k in range(D['n'])]
        s.globals = {}; s.children = collections.OrderedDict(); s.found = {}; s.cache = {}
        s.sites = collections.Counter(); s.unres = collections.Counter(); s.curbc = None
        from v8cache import tables; s.wacc = {o[0] for o in tables()['ops'] if o[2]}; s._wr = {}
    def decode(s, i, k):
        if not isinstance(i, int) or (s.D['rc4'] and not isinstance(k, S)): return None
        j = i - s.D['offset']
        if not 0 <= j < len(s.arr): return None
        key = (j, k.v if s.D['rc4'] else '')
        if key in s.cache: v = s.cache[key]
        else:
            try: v = b64(s.arr[(j + s.rot) % len(s.arr)]); v = rc4(v, k.v) if s.D['rc4'] else v
            except Exception: v = None
            if s.memo: s.cache[key] = v
        return S(v, True) if v is not None else None
    def lit(s, r):
        if r[0] == 'smi': return r[1]
        if r[0] == 'obj':
            mn = s.h.mapname(r[1])
            if 'string_map' in mn: return S(s.h.string(r[1]))
            if mn == 'heap_number_map': return struct.unpack_from('<d', s.h.o[r[1]][4], 8)[0]
        if r[0] == 'root':
            v = s.h.rootstr(r[1]); return S(v) if v is not None else None
        if r[0] == 'ro': return S(s.rostr.get(r[2], '⟦ro%d⟧' % r[2]))   # chuỗi trong read-only heap: không có trong cache
        return None
    def const(s, bi, k): return s.lit(s.h.const(bi, k))
    def cname(s, bi, k): v = s.const(bi, k); return v.v if isinstance(v, S) else None
    def boiler(s, bi, k):
        r = s.h.const(bi, k); o = JObj()
        if r[0] != 'obj' or s.h.mapname(r[1]) != 'object_boilerplate_description_map': return o
        i = r[1]
        for w in range(3, s.h.o[i][2] - 1, 2):
            kn = s.lit(s.h.slot(i, w))
            if kn is not None: o[jsstr(kn)] = s.lit(s.h.slot(i, w + 1))
        return o
    def arith(s, op, a, b):
        try:
            if op == 'Add':
                if isinstance(a, S) or isinstance(b, S):
                    if not all(isinstance(x, S) or num(x) for x in (a, b)): return None
                    for x in (a, b):
                        if isinstance(x, S): x.used = True
                    return S(jsstr(a) + jsstr(b), any(isinstance(x, S) and x.t for x in (a, b)))
                return a + b if num(a) and num(b) else None
            if not (num(a) and num(b)): return None
            if op == 'Sub': return a - b
            if op == 'Mul': return a * b
            if op == 'Div': r = a / b; return int(r) if r == int(r) else r
            if op == 'Mod': return a % b if a >= 0 and b > 0 else None
        except Exception: return None
    def is_wrapper(s, f, d=0):
        """f (sau lan truyền hằng) là hàm giải mã hoặc wrapper chỉ chuyển tiếp tới nó."""
        if isinstance(f, Glob): return f.name == s.D['dec_name'] or (d < 4 and s.is_wrapper(s.globals.get(f.name), d + 1))
        if not isinstance(f, Clo): return False
        if f.sfi in s._wr: return s._wr[f.sfi]
        b = s.h.bc_of(f.sfi); ok = False
        if b is not None and s.h.blen(b) <= 40:
            ins = s.h.dis(b); g = [ar for st, n, ar in ins if n == 'LdaGlobal']
            if len(g) == 1 and any(n.startswith('CallUndefinedReceiver') for st, n, ar in ins):
                t = s.cname(b, g[0][0][1]); ok = t == s.D['dec_name'] or (d < 4 and s.is_wrapper(s.globals.get(t), d + 1))
        s._wr[f.sfi] = ok; return ok
    def call(s, f, args, depth):
        if depth == 0 and s.curbc is not None and s.is_wrapper(f): site = True
        else: site = False
        r = None
        if isinstance(f, Glob):
            if f.name == s.D['dec_name']: r = s.decode(args[0] if args else None, args[1] if len(args) > 1 else None); f = None
            elif f.name == 'parseInt': r = parse_int(args[0].v) if args and isinstance(args[0], S) else None; f = None
            else: f = s.globals.get(f.name)
        if isinstance(f, Clo) and depth < 6:
            b = s.h.bc_of(f.sfi)
            if b is not None and s.h.blen(b) <= 120: r = s.run(b, f.ctx, args, depth + 1, 'call')
        if site:
            body = s.h.blen(s.curbc) <= 40      # thân wrapper: định nghĩa wrapper, không phải điểm dùng chuỗi
            s.sites[('wrapper' if body else 'use', isinstance(r, S))] += 1
            if not body and not isinstance(r, S): s.unres[s.curbc] += 1
        return r
    def run(s, bi, ctx, args=None, depth=0, mode='', trace=None):
        """mode: '' duyệt cả hàm; 'call' diễn giải wrapper (thẳng, trả giá trị Return); 'probe' trả toán hạng của TestEqualStrict đầu."""
        h = s.h; regs = {}; acc = None; cur = ctx; call = mode == 'call'; outs = []
        if not mode: s.curbc = bi
        for k, a in enumerate(args or []): regs[3 + k] = a
        def up(c, d):
            for _ in range(d): c = c.parent if c is not None else None
            return c
        def sto(c, k, v):
            if c is None or call: return
            old = c.slots.get(k, '∅')
            if old is None or (isinstance(old, str) and old == '∅'): c.slots[k] = v
            elif v is None or isinstance(old, (JObj, Clo)) and not isinstance(v, (JObj, Clo)): pass
            elif isinstance(v, (JObj, Clo)): c.slots[k] = v
            elif not ((isinstance(old, S) and isinstance(v, S) and old.v == v.v) or old == v): c.slots[k] = '⊤'
        def lda(c, k): v = c.slots.get(k) if c is not None else None; return None if isinstance(v, str) else v
        for ins in h.dis(bi):
            st, name, ar = ins; a = [v for _, v in ar]; new = None; handled = True; regs[-1] = cur
            if name in ('Wide', 'ExtraWide'): continue
            if name == 'LdaZero': acc = 0
            elif name == 'LdaSmi': acc = a[0]
            elif name == 'LdaConstant': acc = s.const(bi, a[0])
            elif name == 'Ldar': acc = regs.get(a[0])
            elif name == 'Star': regs[a[0]] = acc
            elif name[:4] == 'Star' and name[4:].isdigit(): regs[-6 - int(name[4:])] = acc
            elif name == 'Mov': regs[a[1]] = regs.get(a[0])
            elif name == 'LdaGlobal':
                n = s.cname(bi, a[0]); acc = Glob(n) if n in s.globals or n in (s.D['dec_name'], 'parseInt') else None
            elif name == 'StaGlobal':
                n = s.cname(bi, a[0])
                if isinstance(acc, Clo) and n and n not in s.globals and not mode: s.globals[n] = acc
            elif name in ('CreateFunctionContext', 'CreateBlockContext', 'CreateCatchContext', 'CreateWithContext', 'CreateEvalContext'):
                if call: return None
                acc = Ctx(cur)
            elif name == 'PushContext': regs[a[0]] = cur; cur = acc if isinstance(acc, Ctx) else Ctx(cur)
            elif name == 'PopContext': c = regs.get(a[0]); cur = c if isinstance(c, Ctx) else cur
            elif name in ('LdaCurrentContextSlot', 'LdaImmutableCurrentContextSlot'): acc = lda(cur, a[0])
            elif name == 'StaCurrentContextSlot': sto(cur, a[0], acc)
            elif name in ('LdaContextSlot', 'LdaImmutableContextSlot'):
                c = regs.get(a[0]); acc = lda(up(c, a[2]), a[1]) if isinstance(c, Ctx) else None
            elif name == 'StaContextSlot':
                c = regs.get(a[0])
                if isinstance(c, Ctx): sto(up(c, a[2]), a[1], acc)
            elif name == 'CreateObjectLiteral': acc = s.boiler(bi, a[0])
            elif name == 'CreateEmptyObjectLiteral': acc = JObj()
            elif name == 'GetNamedProperty':
                o = regs.get(a[0]); n = s.cname(bi, a[1]); acc = o.get(n) if isinstance(o, JObj) and n is not None else None
            elif name == 'GetKeyedProperty':
                o = regs.get(a[0]); acc = o.get(jsstr(acc)) if isinstance(o, JObj) and isinstance(acc, (S, int)) else None
            elif name in ('SetNamedProperty', 'DefineNamedOwnProperty'):
                o = regs.get(a[0]); n = s.cname(bi, a[1])
                if isinstance(o, JObj) and n is not None and not call and n not in o: o[n] = acc
            elif name in ('Add', 'Sub', 'Mul', 'Div', 'Mod'): acc = new = s.arith(name, regs.get(a[0]), acc)
            elif name in ('AddSmi', 'SubSmi', 'MulSmi', 'DivSmi', 'ModSmi'): acc = new = s.arith(name[:3], acc, a[0])
            elif name == 'Negate': acc = -acc if num(acc) else None
            elif name == 'Inc': acc = acc + 1 if num(acc) else None
            elif name == 'Dec': acc = acc - 1 if num(acc) else None
            elif name in ('ToNumeric', 'ToNumber'): acc = acc if num(acc) else None
            elif name == 'CreateClosure':
                r = h.const(bi, a[0]); sfi = r[1] if r[0] == 'obj' else None
                acc = Clo(sfi, cur) if sfi is not None else None
                if sfi is not None and not mode and sfi not in s.children: s.children[sfi] = cur
            elif name.startswith('Call') and name not in ('CallRuntime', 'CallRuntimeForPair', 'CallJSRuntime', 'CallWithSpread'):
                f = regs.get(a[0]); g = regs.get
                A = {'CallUndefinedReceiver0': lambda: [], 'CallUndefinedReceiver1': lambda: [g(a[1])], 'CallUndefinedReceiver2': lambda: [g(a[1]), g(a[2])],
                     'CallUndefinedReceiver': lambda: [g(a[1] - k) for k in range(a[2])], 'CallProperty0': lambda: [], 'CallProperty1': lambda: [g(a[2])],
                     'CallProperty2': lambda: [g(a[2]), g(a[3])], 'CallProperty': lambda: [g(a[1] - k) for k in range(1, a[2])],
                     'CallAnyReceiver': lambda: [g(a[1] - k) for k in range(1, a[2])]}.get(name, lambda: [])()
                acc = new = s.call(f, A, depth if mode != 'probe' else 1) if isinstance(f, (Glob, Clo)) else None
            elif name == 'Return':
                if call: return acc
            elif name == 'TestEqualStrict' and mode == 'probe': return regs.get(a[0])
            elif name.startswith(('Jump', 'Switch')):
                if call: return None
            else:
                handled = False
                if name in s.wacc: acc = None
                if name not in ('ResumeGenerator', 'SuspendGenerator'):
                    for j, (ot, v) in enumerate(ar):
                        if ot.startswith('RegOut'):
                            for k in range({'RegOut': 1, 'RegOutPair': 2, 'RegOutTriple': 3}.get(ot) or (ar[j + 1][1] if j + 1 < len(ar) else 1)): regs.pop(v - k, None)
            if isinstance(new, S) and new.t and not mode: new.pos = st; outs.append(new)
            if trace is not None:
                an = '   => %r' % (acc.v if isinstance(acc, S) else acc) if handled and (isinstance(acc, S) or num(acc) and name not in ('LdaSmi', 'LdaZero')) else ''
                trace.append(h.fmt(bi, ins) + an)
        if not mode: s.found[bi] = [(x.pos, x.v) for x in outs if not x.used]
        return None
    def find_rotation(s, limit=None):
        """Thử lần lượt số lần xoay cho tới khi biểu thức kiểm của hàm xoay bằng đích. Không có hàm xoay -> 0."""
        b, tgt = s.D['rot_bc'], s.D['target']
        if b is None or tgt is None: return 0
        s.memo = False
        try:
            for rot in range(limit or len(s.arr)):
                s.rot = rot; v = s.run(b, Ctx(None), [None, tgt], mode='probe')
                if num(v) and v == tgt: return rot
        finally: s.memo = True; s.cache.clear()
        s.rot = 0; return None
    def all(s):
        h = s.h; rootctx = Ctx(None); rb = h.bc_of(h.root[1])
        for name, sfi in h.toplevel_names().items(): s.globals.setdefault(name, Clo(sfi, rootctx)); s.children.setdefault(sfi, rootctx)
        s.run(rb, rootctx); done = set()
        while True:
            todo = [(k, v) for k, v in s.children.items() if k not in done]
            if not todo: break
            for sfi, ctx in todo:
                done.add(sfi); b = h.bc_of(sfi)
                if b is not None and b != rb: s.run(b, ctx)
        s.ctxof = {h.bc_of(k): v for k, v in s.children.items()}
        for b in h.bcs():                       # hàm không tới được qua CreateClosure: vẫn duyệt để lấy chuỗi
            if b not in s.found: s.run(b, Ctx(None))
    def coverage(s): return s.sites[('use', True)], s.sites[('use', True)] + s.sites[('use', False)]
