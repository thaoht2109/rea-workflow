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
