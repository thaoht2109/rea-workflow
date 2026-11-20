# Đọc nhanh thanh ghi cho hook nóng của winemu. reg_read của binding unicorn-Python tốn ~1/3 thời gian khi hook chạy mỗi basic block,
# nên gọi thẳng uc_reg_read vào bộ đệm dùng lại. Chỉ dùng nhánh nhanh khi đã tự kiểm khớp reg_read; không thì lùi về reg_read.
import ctypes


def make_reader(mu, reg_id, probes=(0x202, 0x302, 0x102, 0x246, 0x10246, 0xfffffff0), uclib=None):
    """Trả hàm f(uc) -> int đọc thanh ghi reg_id. Nhánh nhanh phải khớp mu.reg_read trên mọi giá trị thử, kể cả bit cao."""
    def slow(uc): return uc.reg_read(reg_id)
    try:
        if uclib is None:
            from unicorn.unicorn_py3.unicorn import uclib
        buf = ctypes.c_uint64(); ref = ctypes.byref(buf); uch = mu._uch
        def fast(uc):
            uclib.uc_reg_read(uch, reg_id, ref)
            return buf.value
        saved = mu.reg_read(reg_id)
        try:
            for v in probes:
                mu.reg_write(reg_id, v)
                if fast(mu) != mu.reg_read(reg_id): return slow
        finally:
            mu.reg_write(reg_id, saved)
        return fast
    except Exception:
        return slow
