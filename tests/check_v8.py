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

# 7. triage: nhận loại v8-cache và script nạp cachedData, định tuyến sang flow.py v8
import triage
assert triage.v8_wrap(c1, 'a.jsc') == '' and triage.v8_wrap(b'\x7fELF' + b'\0' * 64, 'a.jsc') is None
assert 'flow.py v8' in triage.route({'flags': [], 'type': 'v8-cache'}, '.') and 'flow.py v8' in triage.route({'flags': ['v8-loader'], 'type': 'script/javascript'}, '.')
assert triage.V8_LOADER.search("new vm.Script('', {cachedData: buf}).runInThisContext()") and not triage.V8_LOADER.search('console.log(1)')
print('OK check_v8')
