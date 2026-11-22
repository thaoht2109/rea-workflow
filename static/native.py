# Hàm nóng của triage có bản Rust (rust/rea_hook, cùng thư viện với lõi winemu). Python điều phối, Rust chỉ nhận byte và trả số.
# REA_CORE (môi trường hoặc rea.env): auto (mặc định) dùng Rust nếu có thư viện mới đủ hàm, không thì Python; rust bắt buộc; py ép Python.
import ctypes, math, os, re, sys
from array import array
from collections import Counter
sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'winemu')); import rcore   # noqa: E402
import reacfg   # noqa: E402  (REA_CORE đọc được cả từ rea.env)

MIN_NATIVE = 256   # dưới ngưỡng này chi phí gọi ctypes lớn hơn lợi
_LIB = False
_NOSTR = False   # thư viện nạp được nhưng thiếu rea_strings


def entropy_py(b):
    if not b: return 0.0
    n = len(b); return round(-sum(c / n * math.log2(c / n) for c in Counter(b).values()), 2)


def lib():
    """CDLL có rea_entropy, hoặc None (REA_CORE=py, chưa build, thư viện cũ). REA_CORE=rust mà thiếu thì dừng."""
    global _LIB
    if _LIB is not False: return _LIB
    mode = (reacfg.get('REA_CORE', path=False) or 'auto').lower(); _LIB = None
    if mode not in ('auto', 'rust', 'py', 'python'): raise SystemExit(f'REA_CORE không hợp lệ: {mode} (auto|rust|py)')
    if mode in ('py', 'python'): return None
    l, why = rcore.load_lib()
    if l is not None:
        try:
            l.rea_entropy.restype = ctypes.c_double; l.rea_entropy.argtypes = [ctypes.c_char_p, ctypes.c_size_t]
            _LIB = l; return l
        except AttributeError: why = 'thư viện cũ, thiếu rea_entropy (build lại: cargo build --release)'
    if mode == 'rust': raise SystemExit(f'REA_CORE=rust nhưng không dùng được lõi Rust: {why}')
    return None


def entropy(b):
    """Entropy Shannon làm tròn 2 chữ số; kết quả giống entropy_py."""
    l = lib() if len(b) >= MIN_NATIVE else None
    if l is None: return entropy_py(b)
    if not isinstance(b, bytes): b = bytes(b)
    return round(l.rea_entropy(b, len(b)), 2)


def scan_strings_py(d, n=6):
    """(ASCII, UTF-16LE) chuỗi in được dài >= n, theo thứ tự xuất hiện."""
    return ([m.decode() for m in re.findall(rb'[\x20-\x7e]{%d,}' % n, d)],
            [m.decode('utf-16le') for m in re.findall(rb'(?:[\x20-\x7e]\x00){%d,}' % n, d)])


CAP_MAX = 1 << 20   # số cặp (offset, độ dài) cấp sẵn tối đa; vượt thì Rust báo tổng số và ta cấp lại đúng cỡ


def _runs(l, d, n, kind):
    cap = max(1, min(CAP_MAX, len(d) // (n + 1) + 1))   # cận trên số chuỗi: mỗi chuỗi >= n ký tự và cách nhau >= 1 byte (UTF-16 còn thưa hơn)
    while True:
        buf = array('Q', bytes(16 * cap))
        k = l.rea_strings(d, len(d), n, kind, buf.buffer_info()[0], cap)
        if k <= cap: v = buf[:2 * k].tolist(); return list(zip(v[0::2], v[1::2]))
        cap = k


def scan_strings(d, n=6):
    """Như scan_strings_py; Rust quét, Python giải mã. Thư viện cũ thiếu rea_strings thì dùng Python (REA_CORE=rust thì dừng)."""
    global _NOSTR
    l = lib() if len(d) >= MIN_NATIVE and n > 0 else None
    if l is not None and not _NOSTR:
        try:
            l.rea_strings.restype = ctypes.c_size_t
            l.rea_strings.argtypes = [ctypes.c_char_p, ctypes.c_size_t, ctypes.c_size_t, ctypes.c_uint32, ctypes.c_void_p, ctypes.c_size_t]
        except AttributeError:
            if (reacfg.get('REA_CORE', path=False) or '').lower() == 'rust': raise SystemExit('REA_CORE=rust nhưng thư viện cũ thiếu rea_strings (build lại: cargo build --release)')
            _NOSTR = True
    if l is None or _NOSTR: return scan_strings_py(d, n)
    if not isinstance(d, bytes): d = bytes(d)
    return ([d[o:o + k].decode() for o, k in _runs(l, d, n, 0)], [d[o:o + 2 * k].decode('utf-16le') for o, k in _runs(l, d, n, 1)])
