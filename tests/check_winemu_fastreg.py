#!/usr/bin/env python3
# winemu/fastreg.py: nhánh đọc nhanh phải khớp reg_read, không khớp hoặc lỗi thì lùi về reg_read. Dữ liệu tổng hợp, không chạy mẫu.
# Phần giả không cần unicorn; nếu unicorn có sẵn thì thêm một lượt thật (EFLAGS có/không bit TF); trong CI (biến CI) thiếu unicorn là lỗi.   python3 tests/check_winemu_fastreg.py
import os, sys, types
sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'winemu'))
import fastreg
TF = 0x100

class FakeMu:
    def __init__(self): self.v = 0x202; self._uch = 7; self.reads = 0
    def reg_read(self, r): self.reads += 1; return self.v
    def reg_write(self, r, x): self.v = x

def lib(mask=0xffffffffffffffff, raises=False):
    def uc_reg_read(h, r, ref):
        if raises: raise OSError('x')
        ref._obj.value = mu.v & mask
    return types.SimpleNamespace(uc_reg_read=uc_reg_read)

# 1. khớp: dùng nhánh nhanh (không gọi reg_read khi đọc), trả đúng giá trị và trạng thái cũ được khôi phục
mu = FakeMu(); mu.v = 0x246
f = fastreg.make_reader(mu, 9, uclib=lib())
assert mu.v == 0x246, 'phải khôi phục giá trị cũ sau khi thử'
mu.reads = 0
for v in (0x202, 0x302, 0x10246): mu.v = v; assert f(mu) == v
assert mu.reads == 0, 'nhánh nhanh không được qua reg_read'
assert (f(mu) & TF) == (mu.v & TF)

# 2. lệch (cắt còn 16 bit thấp, mô phỏng đổi kích thước ghi): lùi về reg_read
mu = FakeMu(); f = fastreg.make_reader(mu, 9, uclib=lib(mask=0xffff))
mu.reads = 0; mu.v = 0x10302; assert f(mu) == 0x10302 and mu.reads == 1, 'phải lùi về reg_read'

# 3. lệch ở bit TF
mu = FakeMu(); f = fastreg.make_reader(mu, 9, uclib=lib(mask=~TF & 0xffffffffffffffff))
mu.reads = 0; mu.v = 0x302; assert f(mu) == 0x302 and mu.reads == 1

# 4. uc_reg_read ném lỗi, hoặc thiếu _uch: lùi về reg_read
mu = FakeMu(); f = fastreg.make_reader(mu, 9, uclib=lib(raises=True)); mu.v = 0x302; assert f(mu) == 0x302
mu = FakeMu(); del mu._uch; f = fastreg.make_reader(mu, 9, uclib=lib()); mu.v = 0x302; assert f(mu) == 0x302

# 5. unicorn thật (nếu có): nhánh nhanh khớp reg_read với và không có TF
try:
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__)))); import reacfg  # noqa: F401  (thêm REA_PYLIB vào sys.path)
    from unicorn import Uc, UC_ARCH_X86, UC_MODE_32
    from unicorn.x86_const import UC_X86_REG_EFLAGS as EF
except ImportError:
    assert not os.environ.get('CI'), 'CI phải có unicorn (requirements-dev.txt): không được bỏ lượt thật'
    print('OK check_winemu_fastreg (không có unicorn: bỏ lượt thật)'); sys.exit(0)
real = Uc(UC_ARCH_X86, UC_MODE_32); real.reg_write(EF, 0x202)
f = fastreg.make_reader(real, EF)
assert f.__name__ == 'fast', 'unicorn thật phải dùng được nhánh nhanh'
for v in (0x202, 0x302, 0x246, 0x10246):
    real.reg_write(EF, v); assert f(real) == real.reg_read(EF), hex(v)
real.reg_write(EF, 0x302); assert f(real) & TF
real.reg_write(EF, 0x202); assert not f(real) & TF
print('OK check_winemu_fastreg')
