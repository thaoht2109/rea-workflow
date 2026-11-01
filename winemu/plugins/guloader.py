# Plugin GuLoader cho winemu. Tham số (offset so với --base):
#   dec=   hàm giải mã f(data, len, keylen, key): XOR từng byte theo khóa lặp (stdcall, ret 0x10).
#          Dùng cho cả chuỗi lẫn payload (mỗi loại một khóa riêng): mỗi khóa khác nhau ra một event str_key
#   s2=, s2len=   vùng stage-2 để dump ra OUT/<tag>_stage2.bin khi kết thúc
# Tìm 'dec' ở mẫu mới: chạy một lần không có dec, xem events 'argstr' (tên DLL/URL đã giải mã được truyền
# vào API) -> đặt --ring và --stop-at LdrLoadDll để thấy hàm vừa trả chuỗi đó.
import os, atexit, hashlib
from unicorn import UC_HOOK_CODE
from unicorn.x86_const import UC_X86_REG_ESP

def setup(g, opts):
    mu, ev, r32, BASE, A = g['mu'], g['ev'], g['r32'], g['BASE'], g['A']
    if 'dec' in opts:
        dec, pend = BASE + int(opts['dec'], 16), {}
        def on_ret(uc, addr, size, _):
            if addr in pend:
                d, n, k, kn = pend.pop(addr)
                b = bytes(uc.mem_read(d, min(n, 4096)))
                txt = b.decode('utf-16le', 'replace') if len(b) > 3 and b[1] == 0 and b[3] == 0 else b.decode('latin1')
                ev('str', len=n, keylen=kn, key_off=k - BASE, s=txt.rstrip('\0'))
        def on_dec(uc, addr, size, _):
            esp = uc.reg_read(UC_X86_REG_ESP)
            ra, d, n, kn, k = [r32(esp + 4 * i) for i in range(5)]
            pend[ra] = (d, n, k, kn)
            seen = g['CTX'].setdefault('gl_keys', set())
            if (k, kn) not in seen:
                seen.add((k, kn)); key = bytes(uc.mem_read(k, kn))
                ev('str_key', key_off=k - BASE, keylen=kn, key=key[:256].hex(), sha256=hashlib.sha256(key).hexdigest())
            uc.hook_add(UC_HOOK_CODE, on_ret, None, ra, ra)
        mu.hook_add(UC_HOOK_CODE, on_dec, None, dec, dec)
    if 's2' in opts:
        s2, n = BASE + int(opts['s2'], 16), int(opts.get('s2len', '0x10000'), 16)
        atexit.register(lambda: open(os.path.join(A.out, f'{A.tag}_stage2.bin'), 'wb').write(bytes(mu.mem_read(s2, n))))
