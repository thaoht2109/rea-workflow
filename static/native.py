# Hàm nóng của triage có bản Rust (rust/rea_hook, cùng thư viện với lõi winemu). Python điều phối, Rust chỉ nhận byte và trả số.
# REA_CORE (môi trường hoặc rea.env): auto (mặc định) dùng Rust nếu có thư viện mới đủ hàm, không thì Python; rust bắt buộc; py ép Python.
import ctypes, math, os, sys
from collections import Counter
sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'winemu')); import rcore   # noqa: E402
import reacfg   # noqa: E402  (REA_CORE đọc được cả từ rea.env)

MIN_NATIVE = 256   # dưới ngưỡng này chi phí gọi ctypes lớn hơn lợi
_LIB = False


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
