#!/usr/bin/env python3
# winemu/rcore.py: lõi hook block (Rust) và bản Python phải cho cùng kết quả trên một chương trình x86 tổng hợp đặt cờ TF; nạp thư viện lỗi thì lùi về Python.
# Không chạy mẫu. Cần unicorn; lõi Rust cần thư viện đã build (cargo build --release trong rust/rea_hook). Trong CI (biến CI) thiếu một trong hai là lỗi.
#   python3 tests/check_winemu_rcore.py
import os, sys, struct, tempfile
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, 'winemu')); sys.path.insert(0, ROOT)
CI = bool(os.environ.get('CI'))
try:
    import reacfg  # noqa: F401  (thêm REA_PYLIB vào sys.path)
    from unicorn import Uc, UC_ARCH_X86, UC_MODE_32
    from unicorn.x86_const import UC_X86_REG_EFLAGS as EF, UC_X86_REG_EIP, UC_X86_REG_ESP
except ImportError:
    assert not CI, 'CI phải có unicorn (requirements-dev.txt)'
    print('OK check_winemu_rcore (không có unicorn: bỏ qua)'); sys.exit(0)
import rcore

CODE, STK = 0x10000000, 0x20000000
# pushfd; pop eax; or eax,0x100; push eax; popfd; nop; nop; nop; nop
PROG = bytes([0x9c, 0x58, 0x0d, 0x00, 0x01, 0x00, 0x00, 0x50, 0x9d, 0x90, 0x90, 0x90, 0x90])
PLAIN = bytes([0x90] * 8)   # không đặt TF

def run(core_mode, prog, lib_env=None):
    mu = Uc(UC_ARCH_X86, UC_MODE_32); mu.mem_map(CODE, 0x1000); mu.mem_map(STK, 0x1000)
    mu.mem_write(CODE, prog); mu.reg_write(UC_X86_REG_ESP, STK + 0x800); mu.reg_write(EF, 0x202)
    if lib_env is not None: os.environ['REA_CORE_LIB'] = lib_env
    core = rcore.attach(mu, CODE, CODE + 0x1000, EF, mode=core_mode)
    core.reset_count()
    mu.emu_start(CODE, CODE + len(prog), count=100)
    return core, mu

# 1. bản Python: có TF thì thấy pending, nblk >= 1; không TF thì không
c, mu = run('py', PROG); assert c.kind == 'python'
# TF đặt bằng popfd có hiệu lực từ block sau: hook phải bắt được (hoặc emu dừng trước khi tới đó)
a_py, n_py, fl_py = c.take_pending(), c.nblk, mu.reg_read(EF)
assert a_py is not None, 'chương trình thử phải kích hoạt TF'
c, mu = run('py', PLAIN); assert c.take_pending() is None and c.nblk >= 1

# 2. lõi Rust (nếu có thư viện) phải cho cùng kết quả như bản Python, trên cả hai chương trình
lib, why = rcore.load_lib()
if lib is None:
    assert not CI, 'CI phải build thư viện Rust trước khi chạy test: ' + why
    print('OK check_winemu_rcore (chưa build thư viện Rust: chỉ kiểm bản Python)')
else:
    c, mu = run('rust', PROG); assert c.kind == 'rust'
    assert (c.take_pending(), c.nblk, mu.reg_read(EF)) == (a_py, n_py, fl_py), 'Rust khác Python trên chương trình đặt TF'
    assert c.take_pending() is None, 'take_pending phải xóa cờ'
    c, mu = run('rust', PLAIN); assert c.take_pending() is None and c.nblk >= 1
    # reset_count đặt lại bộ đếm
    c.reset_count(); assert c.nblk == 0
    # 3. REA_CORE=auto chọn Rust khi có thư viện
    c, mu = run('auto', PLAIN); assert c.kind == 'rust'
    print('OK check_winemu_rcore (Rust và Python khớp)')

# 4. lùi về Python khi thư viện hỏng / sai đường dẫn; REA_CORE=rust thì báo lỗi rõ ràng
good = os.environ.get('REA_CORE_LIB')
try:
    with tempfile.TemporaryDirectory() as d:
        bad = os.path.join(d, rcore.NAME); open(bad, 'wb').write(b'khong phai thu vien')
        c, mu = run('auto', PLAIN, lib_env=bad); assert c.kind == 'python', 'thư viện hỏng phải lùi về Python'
        try: run('rust', PLAIN, lib_env=bad); raise AssertionError('REA_CORE=rust với thư viện hỏng phải lỗi')
        except SystemExit as e: assert 'REA_CORE=rust' in str(e)
        c, mu = run('auto', PLAIN, lib_env=os.path.join(d, 'khong-co')); assert c.kind == 'python'
        c, mu = run('py', PLAIN, lib_env=bad); assert c.kind == 'python'
        try: run('xyz', PLAIN)
        except SystemExit as e: assert 'không hợp lệ' in str(e)
finally:
    if good is None: os.environ.pop('REA_CORE_LIB', None)
    else: os.environ['REA_CORE_LIB'] = good
print('OK check_winemu_rcore (lùi về Python)')
