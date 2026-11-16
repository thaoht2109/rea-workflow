#!/usr/bin/env python3
# Code cache V8 (static/v8): nhận dạng header, đọc luồng snapshot, disassemble, giải chuỗi obfuscator.io bằng lan truyền hằng.
# Dữ liệu tổng hợp: luồng snapshot và bytecode ráp tay trong test, không cần mẫu, không cần node.
#   python3 tests/check_v8.py
import base64, os, struct, sys
T = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path[:0] = [os.path.join(T, 'static', 'v8'), os.path.join(T, 'static'), T]
import v8cache, obf

TB = v8cache.tables(); OP = {o[0]: i for i, o in enumerate(TB['ops'])}; RO = {n: i for i, n in enumerate(TB['ro_roots'])}
def vint(n): n <<= 2; k = 1 if n < 1 << 8 else 2 if n < 1 << 16 else 3 if n < 1 << 24 else 4; return (n | (k - 1)).to_bytes(k, 'little')
def root(name): i = RO[name]; return bytes([0x40 + i]) if i < 32 else b'\x07' + vint(i)
def raw(b): assert len(b) % 8 == 0; n = len(b) // 8; return (bytes([0x60 + n - 1]) if n <= 32 else b'\x11' + vint(n)) + b
def smi(v): return struct.pack('<q', v << 32)
def obj(mapname, body_words, body): return b'\x01' + vint(1 + body_words) + root(mapname) + body
def string(s):
    b = s.encode('latin1'); pad = (-len(b)) % 8
    return obj('one_byte_internalized_string_map', 1 + (len(b) + pad) // 8, raw(struct.pack('<II', 0, len(b)) + b + b'\0' * pad))
def farr(items, mapname='fixed_array_map', n=None): n = n or len(items); return obj(mapname, 1 + n, raw(smi(n)) + b''.join(items))
def bcarr(code, consts, n=None):
    tail = struct.pack('<iiiBB', 0, 24, 0, 0, 0) + b'\0\0' + code; tail += b'\0' * ((-len(tail)) % 8)
    return obj('bytecode_array_map', 4 + len(tail) // 8, raw(smi(len(code))) + farr(consts, n=n) + root('empty_byte_array') + root('empty_byte_array') + raw(tail))
def sfi(bc): return obj('shared_function_info_map', 6, bc + root('empty_string') + root('empty_string') + root('empty_string') + raw(b'\0' * 16))
def cache(payload):
    payload += b'\x0c'; payload += b'\0' * ((-len(payload)) % 8)
    return struct.pack('<IIIIII', 0xC0DE0562, 1, 2, 3, len(payload), 0) + payload
R = lambda n: (-6 - n) & 0xff

# 1. header: nhận cache trần, từ chối dữ liệu khác; bọc brotli nếu có module
code = bytes([OP['LdaConstant'], 0, OP['Star0'], OP['Return']])
c1 = cache(sfi(bcarr(code, [string('xin chao')])))
assert v8cache.is_cache(c1) and not v8cache.is_cache(b'MZ' + b'\0' * 64) and v8cache.unwrap(b'A' * 64) == (None, '')
try:
    import brotli; assert v8cache.unwrap(brotli.compress(c1)) == (c1, 'brotli')
    assert v8cache.peek_wrap(brotli.compress(c1)) == 'brotli' and v8cache.peek_wrap(brotli.compress(b'x' * 4096)) is None and v8cache.peek_wrap(b'rac' * 50) is None
    bomb = brotli.compress(b'\0' * (8 << 20)); old = v8cache.MAX_OUT; v8cache.MAX_OUT = 1 << 20    # giải nén vượt trần: từ chối, không giữ hết trong RAM
    assert len(bomb) < 4096 and v8cache.unwrap(bomb) == (None, '') and v8cache._inflate(bomb, v8cache.MAX_OUT) is None; v8cache.MAX_OUT = old
except ImportError: print('  (bỏ qua bọc brotli: thiếu module brotli)')

# 2. đọc luồng + disassemble: đối tượng theo thứ tự cấp phát, hằng chuỗi hiện trong listing
h = v8cache.Heap(v8cache.parse(c1))
assert [h.mapname(i) for i in range(4)] == ['shared_function_info_map', 'bytecode_array_map', 'fixed_array_map', 'one_byte_internalized_string_map']
assert h.string(3) == 'xin chao' and h.bc_of(0) == 1 and h.blen(1) == 4 and h.cpool_strings(1) == ['xin chao']
assert [n for _, n, _ in h.dis(1)] == ['LdaConstant', 'Star0', 'Return'] and "'xin chao'" in h.fmt(1, h.dis(1)[0])

# 3. backref (0x04), hot object (0x91: ô 0 đã chứa root map của BytecodeArray), lặp (0x80): ba phần tử cùng trỏ một chuỗi; operand Wide
c2 = cache(sfi(bcarr(bytes([OP['Wide'], OP['LdaSmi'], 0x2c, 0x01, OP['Return']]), [string('k'), b'\x04' + vint(3), b'\x91', b'\x80' + b'\x04' + vint(3)], n=5)))
h2 = v8cache.Heap(v8cache.parse(c2))
assert [h2.slot(2, 2 + k) for k in range(5)] == [("obj", 3)] * 5, [h2.slot(2, 2 + k) for k in range(5)]
assert h2.dis(1)[0] == (0, "LdaSmi", [("Imm", 300)]), h2.dis(1)

# 4. luồng hỏng / khác phiên bản: báo ParseError, không trả kết quả đoán
for bad in (c1[:40], c1[:24] + b'\x3f' + c1[25:]):
    try: v8cache.parse(bad); raise SystemExit('phải lỗi')
    except v8cache.ParseError: pass

# 4b. kích thước và số lần lặp lấy từ luồng bị chặn: đối tượng khai 2^28 slot, lặp vượt đối tượng -> ParseError (không cấp phát)
hdr = lambda p: struct.pack('<IIIIII', 0xC0DE0562, 1, 2, 3, len(p), 0) + p
for bad in (hdr(b'\x01' + vint(1 << 28) + root('fixed_array_map') + b'\x0c' + b'\0' * 5),
            hdr(b'\x01' + vint(3) + root('fixed_array_map') + raw(smi(1)) + b'\x0d' + vint(1 << 20) + root('empty_string') + b'\x0c' + b'\0' * 3)):
    try: v8cache.parse(bad); raise SystemExit('phải lỗi')
    except v8cache.ParseError: pass

# 4c. v8tool unpack/grep/dis qua tiến trình con: hằng chuỗi có '\r\n' không làm vỡ cpool.txt, grep trả mã 0 và khớp trên chuỗi thật
import subprocess, tempfile, shutil
td = tempfile.mkdtemp(prefix='rea-v8-')
try:
    cr = cache(sfi(bcarr(code, [string('GET /a HTTP/1.1\r\nHost: h.test\r\n')]))); open(os.path.join(td, 'x.jsc'), 'wb').write(cr)
    tool = os.path.join(T, 'static', 'v8', 'v8tool.py'); run = lambda *a: subprocess.run([sys.executable, '-I', tool] + list(a), capture_output=True, text=True)
    r = run('unpack', os.path.join(td, 'x.jsc'), '--out', os.path.join(td, 'o')); assert r.returncode == 0 and 'BytecodeArray: 1' in r.stdout, (r.stdout, r.stderr)
    r = run('grep', os.path.join(td, 'o'), r'Host: h\.test\r$'); assert r.returncode == 0 and r.stdout.count('\n') == 1 and 'h.test' in r.stdout, (r.stdout, r.stderr)
    r = run('dis', os.path.join(td, 'o'), '1'); assert r.returncode == 0 and 'LdaConstant' in r.stdout, (r.stdout, r.stderr)
    # big: hằng chuỗi lớn liệt kê theo đối tượng (độ dài, loại, đếm từ khóa), nội dung ra big/obj<N>.txt
    js = 'var a=require("fs");function f(){return fetch("x")}\n' * 120
    open(os.path.join(td, 'z.jsc'), 'wb').write(cache(sfi(bcarr(code, [string(js)])))); r = run('unpack', os.path.join(td, 'z.jsc'), '--out', os.path.join(td, 'q')); assert r.returncode == 0 and 'hằng chuỗi lớn' in r.stdout, (r.stdout, r.stderr)
    r = run('big', os.path.join(td, 'q')); assert r.returncode == 0 and f'{len(js)} ký tự' in r.stdout and 'JS dạng rõ' in r.stdout and 'fetch(=120' in r.stdout and 'require(=120' in r.stdout, (r.stdout, r.stderr)
    oid = int(r.stdout.split()[1].rstrip(':')); assert open(os.path.join(td, 'q', 'big', f'obj{oid}.txt'), encoding='utf-8').read() == js
    assert 'không có' in run('big', os.path.join(td, 'q'), '999999').stdout      # OBJ không khớp: nói rõ
    # flow.py v8 big: bản đầy đủ và bản theo OBJ ghi ra hai tệp evidence khác nhau (không ghi đè nhau)
    cs = os.path.join(td, 'CASE'); os.makedirs(os.path.join(cs, 'report', 'evidence')); open(os.path.join(cs, 'facts.jsonl'), 'w').close(); fl = lambda *a: subprocess.run([sys.executable, os.path.join(T, 'flow.py'), 'v8', cs, os.path.join(td, 'z.jsc')] + list(a), capture_output=True, text=True)
    assert fl().returncode == 0; r = fl('big'); assert r.returncode == 0 and 'v8_z_jsc_big.txt' in r.stdout, (r.stdout, r.stderr)
    full = open(os.path.join(cs, 'report', 'evidence', 'v8_z_jsc_big.txt'), encoding='utf-8').read(); assert f'{len(js)} ký tự' in full
    r = fl('big', str(oid)); assert r.returncode == 0 and f'v8_z_jsc_big_obj{oid}.txt' in r.stdout, (r.stdout, r.stderr)
    assert open(os.path.join(cs, 'report', 'evidence', 'v8_z_jsc_big.txt'), encoding='utf-8').read() == full and os.path.exists(os.path.join(cs, 'report', 'evidence', f'v8_z_jsc_big_obj{oid}.txt'))
    open(os.path.join(td, 'y.jsc'), 'wb').write(b'khong phai cache' * 8); r = run('unpack', os.path.join(td, 'y.jsc'), '--out', os.path.join(td, 'p')); assert r.returncode != 0
finally: shutil.rmtree(td, ignore_errors=True)

# 5. base64 đảo hoa/thường + RC4, parseInt
def enc(s, key): return base64.b64encode(obf.rc4(s, key).encode('utf-8')).translate(bytes.maketrans(obf.STD, obf.CUS)).decode().rstrip('=')
assert obf.rc4(obf.b64(enc('http://a.test/x', 'k3y!')), 'k3y!') == 'http://a.test/x'
assert obf.parse_int('123abc') == 123 and obf.parse_int('x') != obf.parse_int('x')

# 6. lan truyền hằng: wrapper(idx, key) = dec(idx - 7, key), hai mảnh ghép lại bằng Add; số lần xoay áp vào chỉ số mảng
arr = [enc('exam', 'aaaa'), enc('ple.t', 'bbbb'), 'zzzz']; rot = 2; stored = arr[-rot:] + arr[:-rot]    # mảng trong file: chưa xoay
wrap = bytes([OP['LdaGlobal'], 0, 0, OP['Star0'], OP['Ldar'], 3, OP['SubSmi'], 7, 0, OP['Star1'],
              OP['CallUndefinedReceiver2'], R(0), R(1), 4, 0, OP['Return']])
main = bytes([OP['CreateClosure'], 1, 0, 0, OP['Star0'],
              OP['LdaSmi'], 12, OP['Star1'], OP['LdaConstant'], 2, OP['Star2'], OP['CallUndefinedReceiver2'], R(0), R(1), R(2), 0, OP['Star3'],
              OP['LdaSmi'], 13, OP['Star1'], OP['LdaConstant'], 3, OP['Star2'], OP['CallUndefinedReceiver2'], R(0), R(1), R(2), 0,
              OP['Add'], R(3), 0, OP['Return']])
c3 = cache(sfi(bcarr(main, [string('dec'), sfi(bcarr(wrap, [b'\x04' + vint(3)])), string('aaaa'), string('bbbb'),
                            farr([string(x) for x in stored], 'fixed_cow_array_map')])))
h3 = v8cache.Heap(v8cache.parse(c3)); cow = next(o[0] for o in h3.o if h3.mapname(o[0]) == 'fixed_cow_array_map')
D = {'arr': cow, 'n': 3, 'offset': 5, 'rc4': True, 'dec_name': 'dec', 'dec_bc': None, 'rot_bc': None, 'target': None}
r = obf.Resolver(h3, D); r.rot = rot; r.all()
assert r.found[1] == [(28, 'example.t')], r.found
tr = []; r.run(1, obf.Ctx(None), trace=tr); assert any("=> 'example.t'" in l for l in tr), tr
assert obf.detect(h3) is None       # không có bảng chữ cái base64 đảo -> không nhận là obfuscator.io
# 6b. lưu/nạp trạng thái r.all() (globals + ctxof) bằng JSON: nạp lại cho listing y hệt, không chạy lại all(); sai khóa hoặc file hỏng thì từ chối
import tempfile as _tf, v8tool
sd = _tf.mkdtemp(prefix='rea-v8st-')
try:
    r.ctxof[None] = obf.Ctx(None)      # SFI chưa biên dịch: bc_of = None, không được làm hỏng cache
    stt = {'obf': D, 'rot': rot, 'rostr': {}}; v8tool.save_state(r, sd, stt); assert os.path.exists(os.path.join(sd, 'ctx.json'))
    r2 = obf.Resolver(h3, D); r2.rot = rot; assert v8tool.load_state(r2, sd, stt) and sorted(r2.ctxof) == sorted(k for k in r.ctxof if k is not None) and sorted(r2.globals) == sorted(r.globals)
    t1, t2 = [], []; r.run(1, r.ctxof.get(1) or obf.Ctx(None), trace=t1); r2.run(1, r2.ctxof.get(1) or obf.Ctx(None), trace=t2); assert t1 == t2 and any("=> 'example.t'" in l for l in t2), (t1, t2)
    assert not v8tool.load_state(obf.Resolver(h3, D), sd, dict(stt, rostr={'1': 'x'}))      # state.json đã sửa (rostr): khóa lệch, phải chạy lại all()
    open(os.path.join(sd, 'cache.bin'), 'wb').write(b'cache A'); v8tool.save_state(r, sd, stt); assert v8tool.load_state(obf.Resolver(h3, D), sd, stt)
    open(os.path.join(sd, 'cache.bin'), 'wb').write(b'cache B'); assert not v8tool.load_state(obf.Resolver(h3, D), sd, stt)      # cache.bin dựng lại: khóa lệch
    open(os.path.join(sd, 'cache.bin'), 'wb').write(b'cache A'); real = obf.__file__; fake = os.path.join(sd, 'obf_fake.py'); open(fake, 'w').write('# v1\n'); obf.__file__ = fake
    try:
        v8tool.save_state(r, sd, stt); assert v8tool.load_state(obf.Resolver(h3, D), sd, stt); open(fake, 'a').write('# v2: bộ giải đổi\n'); assert not v8tool.load_state(obf.Resolver(h3, D), sd, stt)      # nâng cấp bộ giải: cache cũ mất hiệu lực
    finally: obf.__file__ = real
    v8tool.save_state(r, sd, stt); open(os.path.join(sd, 'ctx.json'), 'w').write('{hỏng'); assert not v8tool.load_state(obf.Resolver(h3, D), sd, stt)
    os.remove(os.path.join(sd, 'ctx.json')); assert not v8tool.load_state(obf.Resolver(h3, D), sd, stt)
    class Lạ: pass
    r.globals['lạ'] = Lạ(); v8tool.save_state(r, sd, stt); assert not os.path.exists(os.path.join(sd, 'ctx.json'))      # kiểu không mã hóa được: không ghi cache
finally: shutil.rmtree(sd, ignore_errors=True)

# 7. triage: nhận loại v8-cache và script nạp cachedData, định tuyến sang flow.py v8
import triage
assert triage.v8_wrap(c1, 'a.jsc') == '' and triage.v8_wrap(b'\x7fELF' + b'\0' * 64, 'a.jsc') is None
assert 'flow.py v8' in triage.route({'flags': [], 'type': 'v8-cache'}, '.') and 'flow.py v8' in triage.route({'flags': ['v8-loader'], 'type': 'script/javascript'}, '.')
assert triage.V8_LOADER.search("new vm.Script('', {cachedData: buf}).runInThisContext()") and not triage.V8_LOADER.search('console.log(1)')
print('OK check_v8')
