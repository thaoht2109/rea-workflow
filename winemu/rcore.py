# Hook basic-block nóng của winemu: kiểm cờ TF mỗi block. Có hai bản cùng giao diện:
#   RustCore: callback nằm trong thư viện Rust (rust/rea_hook), đăng ký thẳng bằng uc_hook_add, không quay lại Python mỗi block;
#   PyCore:   hook Python như trước (đọc EFLAGS qua fastreg), dùng khi chưa build thư viện Rust hoặc REA_CORE=py.
# REA_CORE=auto (mặc định): có thư viện hợp lệ thì dùng Rust, không thì Python. REA_CORE=rust: bắt buộc có Rust. REA_CORE_LIB: đường dẫn .so.
import ctypes, os, sys
import fastreg

UC_HOOK_BLOCK = 8
ABI = 1
HERE = os.path.dirname(os.path.abspath(__file__))
NAME = {'linux': 'librea_hook.so', 'darwin': 'librea_hook.dylib', 'win32': 'rea_hook.dll'}.get(sys.platform, 'librea_hook.so')


class State(ctypes.Structure):   # khớp `State` trong rust/rea_hook/src/lib.rs (kiểm bằng rea_state_size)
    _fields_ = [('nblk', ctypes.c_uint64), ('tf_addr', ctypes.c_uint64), ('tf_pend', ctypes.c_uint32), ('eflags_id', ctypes.c_int32),
                ('reg_read', ctypes.c_void_p), ('emu_stop', ctypes.c_void_p)]


def lib_candidates():
    env = os.environ.get('REA_CORE_LIB')
    if env: return [env]
    root = os.path.dirname(HERE)
    return [os.path.join(root, 'rust', 'rea_hook', 'target', 'release', NAME),
            os.path.join(os.environ.get('XDG_DATA_HOME') or os.path.expanduser('~/.local/share'), 'rea-flow', 'lib', NAME)]   # cùng gốc với reacfg.SHARE_PYLIB


def load_lib():
    """(CDLL | None, lý do). Chỉ nhận thư viện đúng ABI và đúng kích thước State."""
    why = 'không thấy ' + NAME
    for p in lib_candidates():
        if not os.path.isfile(p): continue
        try:
            lib = ctypes.CDLL(p)
            lib.rea_abi_version.restype = ctypes.c_uint32; lib.rea_state_size.restype = ctypes.c_size_t
            if lib.rea_abi_version() != ABI: why = f'{p}: sai ABI'; continue
            if lib.rea_state_size() != ctypes.sizeof(State): why = f'{p}: sai kích thước State'; continue
            return lib, p
        except (OSError, AttributeError) as e:
            why = f'{p}: {e}'
    return None, why


class PyCore:
    kind = 'python'

    def __init__(self, mu, begin, end, eflags_id, uc_hook_block=UC_HOOK_BLOCK):
        self.nblk = 0; self.addr = 0; self.pending = False
        eflags = fastreg.make_reader(mu, eflags_id)
        def on_block(uc, addr, size, _):
            self.nblk += 1
            if eflags(uc) & 0x100 and not self.pending:
                self.pending = True; self.addr = addr; uc.emu_stop()
        mu.hook_add(uc_hook_block, on_block, begin=begin, end=end)

    def reset_count(self): self.nblk = 0
    def take_pending(self):
        """Nếu có TF đang chờ: trả địa chỉ block và xóa cờ; không thì None."""
        if not self.pending: return None
        self.pending = False; return self.addr


class RustCore:
    kind = 'rust'

    def __init__(self, mu, begin, end, eflags_id, lib, uclib):
        self.st = State(); self.st.eflags_id = eflags_id
        addr = lambda f: ctypes.cast(f, ctypes.c_void_p).value
        self.st.reg_read = addr(uclib.uc_reg_read); self.st.emu_stop = addr(uclib.uc_emu_stop)
        cb = ctypes.cast(lib.rea_on_block, ctypes.c_void_p)
        self._h = ctypes.c_size_t(0); self._lib = lib   # giữ sống cùng engine
        err = uclib.uc_hook_add(mu._uch, ctypes.byref(self._h), UC_HOOK_BLOCK, cb, ctypes.byref(self.st), begin, end)
        if err: raise RuntimeError(f'uc_hook_add lỗi {err}')

    @property
    def nblk(self): return self.st.nblk
    def reset_count(self): self.st.nblk = 0
    def take_pending(self):
        if not self.st.tf_pend: return None
        self.st.tf_pend = 0; return self.st.tf_addr


def uclib_ok():
    """(ok, lý do): libunicorn của Python có đủ hàm C mà lõi Rust cần không (doctor và attach dùng chung)."""
    try:
        from unicorn.unicorn_py3.unicorn import uclib
        miss = [f for f in ('uc_reg_read', 'uc_emu_stop', 'uc_hook_add') if not hasattr(uclib, f)]
        return (not miss, 'thiếu ' + ', '.join(miss) if miss else 'đủ hàm')
    except Exception as e:
        return False, f'không nạp được unicorn: {type(e).__name__}: {e}'


def attach(mu, begin, end, eflags_id, mode=None, log=lambda *a: None):
    """Gắn hook block vào mu; trả đối tượng core (.nblk, .reset_count(), .take_pending(), .kind)."""
    mode = (mode or os.environ.get('REA_CORE') or 'auto').lower()
    if mode not in ('auto', 'rust', 'py', 'python'): raise SystemExit(f'REA_CORE không hợp lệ: {mode} (auto|rust|py)')
    if mode in ('auto', 'rust'):
        lib, why = load_lib()
        if lib is not None:
            try:
                from unicorn.unicorn_py3.unicorn import uclib
                c = RustCore(mu, begin, end, eflags_id, lib, uclib); log(f'[core] rust ({why})'); return c
            except Exception as e:
                why = f'khởi tạo Rust lỗi: {e}'
        if mode == 'rust': raise SystemExit(f'REA_CORE=rust nhưng không dùng được lõi Rust: {why}')
        log(f'[core] python ({why})')
    return PyCore(mu, begin, end, eflags_id)
