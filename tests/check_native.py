#!/usr/bin/env python3
# static/native.py: entropy bằng Rust phải trùng bản Python (làm tròn 2 chữ số) trên dữ liệu tổng hợp; REA_CORE=py ép Python; thiếu thư viện thì lùi về Python.
# Lõi Rust cần thư viện đã build (cargo build --release trong rust/rea_hook). Trong CI (biến CI) thiếu thư viện là lỗi.
#   python3 tests/check_native.py
import os, random, subprocess, sys, tempfile
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
from static import native   # noqa: E402
CI = bool(os.environ.get('CI'))

rnd = random.Random(7)
data = [b'', b'a', bytes(300), b'ab' * 500, bytes(range(256)) * 40, os.urandom(1 << 16), bytearray(b'xyz' * 400), memoryview(b'hello world ' * 50)]
data += [bytes(rnd.choice(range(k)) for _ in range(n)) for k in (2, 3, 16, 100, 256) for n in (255, 256, 1000, 20000)]
data += [bytes(rnd.choices(range(256), weights=[1 + (i < 8) * 400 for i in range(256)], k=5000)) for _ in range(20)]
for b in data: assert native.entropy_py(b) == native.entropy_py(bytes(b))

lib = native.lib()
if lib is None:
    assert not CI, 'CI phải build thư viện Rust trước khi chạy test'
    assert all(native.entropy(b) == native.entropy_py(b) for b in data)
    print('OK check_native (chưa build thư viện Rust: chỉ kiểm bản Python)')
else:
    bad = [(len(b), native.entropy(b), native.entropy_py(b)) for b in data if native.entropy(b) != native.entropy_py(b)]
    assert not bad, f'Rust khác Python: {bad[:3]}'
    assert native.entropy(bytes(1000)) == 0.0 and native.entropy(bytes(range(256)) * 4) == 8.0
    print(f'OK check_native (Rust và Python khớp trên {len(data)} bộ dữ liệu)')

# strings: Rust quét, kết quả phải trùng re.findall (ASCII và UTF-16LE từ mọi offset), kể cả khi vượt bộ đệm ban đầu
wide = lambda t: ''.join(c + '\x00' for c in t).encode('latin1')
sd = [b'', b'abc', b'hello world, this is a test\x00\x01more text here', wide('Software\\Run') + b'\x00' * 3 + b'plain ascii run',
      b'x' + wide('offset one'), b'\x00' + wide('abcdefg') + b'\xff' + wide('abcde') + wide('abcdef'), bytearray(b'abcdefgh' * 100)]
alpha = [0, 0x20, 0x41, 0x7e, 0x7f, 0xff, 0x61]
sd += [bytes(rnd.choice(alpha) for _ in range(n)) for n in (300, 3000, 40000) for _ in range(6)] + [os.urandom(1 << 16)]
for n in (1, 4, 6, 9):
    for b in sd: assert native.scan_strings(b, n) == native.scan_strings_py(bytes(b), n), (n, bytes(b)[:40])
# bộ đệm ban đầu cố ý nhỏ (4 cặp) để buộc đường cấp lại: nhiều chuỗi hơn cap, cả ASCII và UTF-16
many = [b'abcdefgh ' * 50, b'\x01'.join(wide('abcdefgh') for _ in range(20)), bytes(rnd.choice([0x41, 0x20, 0]) for _ in range(30000))]
old_cap = native.CAP_MAX; native.CAP_MAX = 4
try:
    for b in many:
        for n in (1, 3, 6):
            r = native.scan_strings(b, n); assert r == native.scan_strings_py(b, n), n
    assert len(native.scan_strings(many[0], 6)[0]) > 4 and len(native.scan_strings(many[1], 6)[1]) > 4
finally: native.CAP_MAX = old_cap
assert native.CAP_MAX == 1 << 20
big = bytes(rnd.choice([0x41, 0x42, 0x20]) for _ in range(400000))
assert native.scan_strings(big, 1) == native.scan_strings_py(big, 1)
print('OK check_native (strings khớp re.findall)')

# REA_CORE: py ép Python, rust với thư viện hỏng thì dừng, auto với thư viện hỏng thì lùi về Python
code = "import sys; sys.path.insert(0, sys.argv[1]); from static import native; print(native.lib() is not None, native.entropy(bytes(range(256)) * 4))"
def probe(**kw):
    e = {k: v for k, v in os.environ.items() if k not in ('REA_CORE', 'REA_CORE_LIB')}; e.update(kw)
    return subprocess.run([sys.executable, '-I', '-c', code, ROOT], env=e, capture_output=True, text=True)
with tempfile.TemporaryDirectory() as d:
    bad = os.path.join(d, 'lib.so'); open(bad, 'wb').write(b'khong phai thu vien')
    r = probe(REA_CORE='py'); assert r.returncode == 0 and r.stdout.split() == ['False', '8.0'], r
    r = probe(REA_CORE='auto', REA_CORE_LIB=bad); assert r.returncode == 0 and r.stdout.split() == ['False', '8.0'], r
    r = probe(REA_CORE='rust', REA_CORE_LIB=bad); assert r.returncode != 0 and 'REA_CORE=rust' in r.stderr, r
    r = probe(REA_CORE='xyz'); assert r.returncode != 0 and 'không hợp lệ' in r.stderr, r
print('OK check_native (REA_CORE py/auto/rust)')
