#!/usr/bin/env python3
# CLI cho code cache V8 (gọi qua `flow.py v8`). Chỉ đọc file mẫu; kết quả ghi vào thư mục --out.
#   v8tool.py unpack FILE --out DIR     gỡ brotli, phân tích cú pháp, dò và giải chuỗi obfuscator.io; ghi summary.txt, strings.txt, modules.txt
#   v8tool.py dis DIR BC...             listing có chú giải hằng của các BytecodeArray (chỉ số đối tượng)
#   v8tool.py grep DIR REGEX            tìm trong chuỗi đã giải và hằng chuỗi constant pool; in "bc<TAB>nguồn<TAB>chuỗi"
#   v8tool.py big DIR [OBJ...]          liệt kê hằng chuỗi lớn (mã JS dạng rõ, base64 nhúng): độ dài, hash, đầu/cuối, loại, đếm từ khóa; ghi nội dung đầy đủ ra DIR/big/obj<N>.txt
import argparse, ast, collections, hashlib, json, os, re, struct, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import v8cache, obf

def _state_key(st): return hashlib.sha256(json.dumps(st, sort_keys=True).encode()).hexdigest()

def save_state(r, d, st):
    """Ghi r.globals và r.ctxof (đồ thị Ctx theo chỉ số) ra DIR/ctx.json để `dis` khỏi chạy lại r.all() (~50 giây). Chỉ JSON (không pickle); kiểu lạ thì không ghi."""
    ids, nodes = {}, []
    def cid(c):
        if c is None: return None
        if id(c) not in ids: ids[id(c)] = len(nodes); nodes.append(c)
        return ids[id(c)]
    def enc(v):
        t = type(v)
        if v is None or t in (bool, int, float, str): return v
        if t is obf.S: return {'S': [enc(v.v), v.t, v.used, enc(v.pos)]}
        if t is obf.JObj: return {'J': [[enc(k), enc(x)] for k, x in v.items()]}
        if t is obf.Clo: return {'C': [v.sfi, cid(v.ctx)]}
        if t is obf.Glob: return {'G': v.name}
        if t is obf.Ctx: return {'X': cid(v)}
        if t in (list, tuple): return {'L' if t is list else 'T': [enc(x) for x in v]}
        raise ValueError(t.__name__)
    try:
        g = {k: enc(v) for k, v in r.globals.items()}; c = {str(b): cid(x) for b, x in r.ctxof.items()}; i = 0; out = []
        while i < len(nodes): n = nodes[i]; out.append({'p': cid(n.parent), 's': [[enc(k), enc(x)] for k, x in n.slots.items()]}); i += 1
        json.dump({'key': _state_key(st), 'globals': g, 'ctxof': c, 'ctx': out}, open(os.path.join(d, 'ctx.json'), 'w'))
    except (ValueError, TypeError, RecursionError):
        try: os.remove(os.path.join(d, 'ctx.json'))
        except OSError: pass

def load_state(r, d, st):
    """Nạp r.globals/r.ctxof từ DIR/ctx.json; False nếu thiếu, sai khóa (state.json đã đổi) hoặc hỏng: khi đó phải chạy r.all()."""
    try:
        j = json.load(open(os.path.join(d, 'ctx.json')))
        if j['key'] != _state_key(st): return False
        cs = [obf.Ctx(None) for _ in j['ctx']]
        def dec(v):
            if not isinstance(v, dict): return v
            (k, x), = v.items()
            if k == 'S': o = obf.S(dec(x[0]), x[1]); o.used = x[2]; o.pos = dec(x[3]); return o
            if k == 'J': return obf.JObj((dec(a), dec(b)) for a, b in x)
            if k == 'C': return obf.Clo(x[0], cs[x[1]] if x[1] is not None else None)
            if k == 'G': return obf.Glob(x)
            if k == 'X': return cs[x]
            if k in 'LT': return [dec(e) for e in x] if k == 'L' else tuple(dec(e) for e in x)
            raise ValueError(k)
        for n, c in zip(j['ctx'], cs): c.parent = cs[n['p']] if n['p'] is not None else None; c.slots = {dec(a): dec(b) for a, b in n['s']}
        r.globals = {k: dec(v) for k, v in j['globals'].items()}; r.ctxof = {int(b): cs[i] if i is not None else None for b, i in j['ctxof'].items()}
        return True
    except (OSError, ValueError, KeyError, TypeError, IndexError): return False

def load(d):
    h = v8cache.Heap(os.path.join(d, 'cache.bin'))   # đọc lại từ cache đã gỡ vỏ, không lưu đồ thị đối tượng ra đĩa
    st = json.load(open(os.path.join(d, 'state.json')))
    r = None
    if st.get('obf'):
        r = obf.Resolver(h, st['obf'], {int(k): v for k, v in st.get('rostr', {}).items()}); r.rot = st['rot'] or 0
        if not load_state(r, d, st): r.all(); save_state(r, d, st)      # lần đầu (hoặc state.json đã sửa): ~50 giây, các lần sau chỉ đọc ctx.json
    return h, r, st

def modules(h, found):
    """Tóm tắt theo module cấp cao nhất: closure tạo ở script gốc rồi gán vào global."""
    rb = h.bc_of(h.root[1]); mods = []; last = None
    for st, n, ar in h.dis(rb):
        if n == 'CreateClosure': r = h.const(rb, ar[0][1]); last = r[1] if r[0] == 'obj' else None
        elif n == 'StaGlobal' and last is not None:
            r = h.const(rb, ar[0][1]); mods.append((last, h.string(r[1]) if r[0] == 'obj' else h.rootstr(r[1]) or '?')); last = None
    mods.sort(); allb = sorted(found); import bisect
    freq = collections.Counter(x for v in found.values() for x in {t for _, t in v}); out = []
    for i, (sfi, name) in enumerate(mods):
        end = mods[i + 1][0] if i + 1 < len(mods) else 10 ** 12; seen = []
        ss = [t for b in allb[bisect.bisect_left(allb, sfi):bisect.bisect_left(allb, end)] for _, t in found[b]]
        for t in ss:
            if len(t) >= 6 and freq[t] <= 6 and t not in seen and not re.fullmatch(r'[A-Za-z]{5}', t): seen.append(t)
        out.append('[%s sfi %d..%d n=%d] %s' % (name, sfi, end if end < 10 ** 12 else sfi, len(ss), ' '.join(repr(x) for x in seen)[:700]))
    return out

def unpack(A):
    os.makedirs(A.out, exist_ok=True); raw = open(A.file, 'rb').read(); d, wrap = v8cache.unwrap(raw); L = []; P = L.append
    if d is None: sys.exit('không phải code cache V8 (hoặc thiếu module brotli để gỡ lớp bọc)')
    P(f'file: {os.path.basename(A.file)} sha256 {hashlib.sha256(raw).hexdigest()} {len(raw)} B; lớp bọc: {wrap or "không"}')
    P(f'code cache: {len(d)} B sha256 {hashlib.sha256(d).hexdigest()}; magic {struct.unpack_from("<I", d, 0)[0]:#x}, version_hash {struct.unpack_from("<I", d, 4)[0]:#x}, flag_hash {struct.unpack_from("<I", d, 12)[0]:#x}')
    open(os.path.join(A.out, 'cache.bin'), 'wb').write(d)
    try: root, objs = v8cache.parse(d)
    except v8cache.ParseError as e:
        P(f'LỖI phân tích cú pháp: {e}'); P('chỉ hỗ trợ V8 10.2 (Node 18.x) không pointer compression; bản khác cần bảng opcode/root riêng (static/v8/v8_*.json)')
        open(os.path.join(A.out, 'summary.txt'), 'w').write('\n'.join(L) + '\n'); print('\n'.join(L)); sys.exit(1)
    h = v8cache.Heap((root, objs)); bcs = h.bcs()
    P(f'đối tượng: {len(objs)}; BytecodeArray: {len(bcs)}; luồng đọc hết, không còn tham chiếu treo')
    D = obf.detect(h); st = {'obf': D, 'rot': None, 'rostr': {}}; found = {}
    if D:
        r = obf.Resolver(h, D); rot = r.find_rotation(); st['rot'] = rot
        P(f'làm rối kiểu obfuscator.io: mảng chuỗi obj {D["arr"]} ({D["n"]} phần tử), hàm giải mã global {D["dec_name"]!r} (bc {D["dec_bc"]}), offset {D["offset"]}, '
          f'{"base64 + RC4 khóa theo từng lời gọi" if D["rc4"] else "base64"}; hàm xoay bc {D["rot_bc"]}, đích {D["target"]}, số lần xoay {rot}')
        if rot is None: P('KHÔNG tìm được số lần xoay: chuỗi giải ra sẽ sai, đọc hàm xoay bằng `dis` rồi tính tay'); r.rot = 0
        r.all(); ok, tot = r.coverage(); found = r.found
        P(f'điểm dùng chuỗi giải được: {ok}/{tot}; thân wrapper (định nghĩa, không tính): {r.sites[("wrapper", True)] + r.sites[("wrapper", False)]}; hàm còn điểm chưa giải: {len(r.unres)}')
        if r.unres: P('  nhiều nhất: ' + ', '.join(f'bc {b} ({n})' for b, n in r.unres.most_common(8)))
        ro = collections.Counter(m for v in found.values() for _, t in v for m in re.findall('⟦ro\\d+⟧', t))
        if ro: P(f'chuỗi read-only heap (không có trong cache, hiện dạng ⟦roN⟧): {len(ro)} loại, {sum(ro.values())} lần; suy theo ngữ cảnh rồi khai trong state.json mục rostr')
    else:
        P('không thấy cấu trúc obfuscator.io (không có bảng chữ cái base64 đảo hoa/thường): chỉ xuất hằng chuỗi constant pool')
    json.dump(st, open(os.path.join(A.out, 'state.json'), 'w'))
    if D: save_state(r, A.out, st)
    with open(os.path.join(A.out, 'strings.txt'), 'w') as f:
        for b in sorted(found):
            if found[b]: f.write('## bc %d\n' % b + ''.join('%d\t%r\n' % x for x in found[b]))
    with open(os.path.join(A.out, 'cpool.txt'), 'w') as f:
        for b in bcs: f.write(''.join('%d\t%r\n' % (b, x[:300]) for x in h.cpool_strings(b)))
    if found: open(os.path.join(A.out, 'modules.txt'), 'w').write('\n'.join(modules(h, found)) + '\n')
    # mã JS dạng rõ nhúng làm hằng chuỗi (thư viện, script tiêm vào trang): không qua bộ giải chuỗi, phải đọc riêng
    big = sorted(((len(h.string(o[0]) or ''), o[0]) for o in objs if h.isstr(o[0]) and o[2] > 512), reverse=True)
    if big: P(f'hằng chuỗi lớn (> 4 KB): {len(big)} chuỗi, tổng {sum(n for n, _ in big)} ký tự; lớn nhất: ' + ', '.join(f'obj {i} ({n})' for n, i in big[:5]) + '; có thể là mã JS dạng rõ, đọc bằng `dis`/`grep` hoặc trích riêng')
    allt = [t for v in found.values() for _, t in v] or [ast.literal_eval(l.split('\t', 1)[1]) for l in open(os.path.join(A.out, 'cpool.txt'))]
    urls = collections.Counter(u for t in allt for u in re.findall(r'(?:https?|wss?|ftp|tcp)://[^\s\'"\\<>]{3,120}', t))
    if urls: P('URL ứng viên (CHƯA là fact; cần xref tới mã): ' + ' '.join(u for u, _ in urls.most_common(40)))
    P('tiếp: đọc modules.txt để chọn module; `flow.py v8 CASE FILE grep REGEX`; `flow.py v8 CASE FILE dis BC...`; mỗi kết luận ghi fact kèm dòng listing')
    open(os.path.join(A.out, 'summary.txt'), 'w').write('\n'.join(L) + '\n'); print('\n'.join(L))

def dis(A):
    h, r, st = load(A.dir)
    for b in A.args:
        b = int(b); t = []
        if not 0 <= b < len(h.o) or not h.is_bc(b): print(f'#### {b}: không phải BytecodeArray'); continue
        if r: r.run(b, r.ctxof.get(b) or obf.Ctx(None), mode='', trace=t)
        else: t = [h.fmt(b, i) for i in h.dis(b)]
        print(f'#### bc {b} ({h.blen(b)} byte)'); print('\n'.join(t))

BIGKEYS = ('child_process', 'require(', 'fetch(', 'eval(', 'WebAssembly', 'XMLHttpRequest', 'WebSocket')

def big(A):
    """Hằng chuỗi lớn của constant pool (cùng tiêu chí với dòng 'hằng chuỗi lớn' của unpack). Đọc đúng đối tượng V8 nên không cắt nhầm ở byte lạ như quét ASCII liên tục."""
    h = v8cache.Heap(os.path.join(A.dir, 'cache.bin')); want = {int(x) for x in A.args}; od = os.path.join(A.dir, 'big'); os.makedirs(od, exist_ok=True)
    rows = sorted(((len(h.string(o[0]) or ''), o[0]) for o in h.o if h.isstr(o[0]) and o[2] > 512 and (not want or o[0] in want)), reverse=True)
    for n, i in rows:
        s = h.string(i) or ''; open(os.path.join(od, f'obj{i}.txt'), 'w', encoding='utf-8', errors='replace').write(s)
        head = s[:4096]; kind = 'WebAssembly base64' if s.startswith('AGFzbQ') else 'base64' if re.fullmatch(r'[A-Za-z0-9+/=\s]+', head) and len(head) > 64 else \
            'JS dạng rõ' if re.search(r'\b(function|var|const|let)\b|=>|exports|require\(', head) else 'khác'
        cnt = ' '.join(f'{k}={s.count(k)}' for k in BIGKEYS if s.count(k))
        print(f'obj {i}: {n} ký tự, sha256 {hashlib.sha256(s.encode("utf-8", "replace")).hexdigest()[:16]}, loại {kind}; đầu {s[:60]!r}; cuối {s[-60:]!r}' + (f'; {cnt}' if cnt else ''))
    if not rows: print('không có hằng chuỗi lớn' + (' khớp OBJ đã nêu' if want else ''))
    else: print(f'nội dung đầy đủ: {od}/obj<N>.txt (dữ liệu từ mẫu; đọc có giới hạn bằng sed -n/grep, không chạy)')

def grep(A):
    rx = re.compile(A.args[0], re.I); b = None
    for fn, tag in (('strings.txt', 'giải mã'), ('cpool.txt', 'hằng')):
        p = os.path.join(A.dir, fn)
        if not os.path.exists(p): continue
        for l in open(p):
            l = l.rstrip('\n')
            if l.startswith('## bc '): b = l[6:]; continue
            bb, t = (b, l.split('\t', 1)[1]) if tag == 'giải mã' else l.split('\t', 1)
            try: t = ast.literal_eval(t)      # strings.txt/cpool.txt lưu dạng repr: so khớp trên chuỗi thật để ^ và $ dùng được
            except Exception: pass
            if rx.search(t): print(f'{bb}\t{tag}\t{t[:300]!r}')

if __name__ == '__main__':
    ap = argparse.ArgumentParser(); ap.add_argument('cmd', choices=['unpack', 'dis', 'grep', 'big']); ap.add_argument('file'); ap.add_argument('args', nargs='*'); ap.add_argument('--out')
    A = ap.parse_args(); A.dir = A.file
    {'unpack': unpack, 'dis': dis, 'grep': grep, 'big': big}[A.cmd](A)
