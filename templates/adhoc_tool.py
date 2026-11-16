#!/usr/bin/env python3
# Công cụ tự viết cho MỘT case (tầng T1b). Dùng khi triage trả loại chưa có đường đi.
# Skill KHÔNG chạy file này: agent tự chạy như mọi script phân tích khác, rồi niêm phong kết quả:
#   python3 -I work/tools/{NAME}.py FILE [tham số...] > work/runs/tool/{NAME}.out
#   flow.py tool CASE seal {NAME}
# Quy tắc không chạy mẫu vẫn nguyên: chỉ ĐỌC file mẫu, không mạng, không tiến trình con, không nạp mẫu vào trình thông dịch/runtime nào.
# Chạy từ thư mục case (case không nằm dưới /tmp). `seal` từ chối công cụ import socket/subprocess/ctypes/pickle/importlib... hoặc gọi exec/eval/os.system. Nên chạy trong vỏ không mạng:
#   bwrap --unshare-all --ro-bind / / --dev /dev --proc /proc --tmpfs /tmp --bind "$PWD/work/runs/tool" "$PWD/work/runs/tool" python3 -I work/tools/{NAME}.py FILE > work/runs/tool/{NAME}.out
# Viết selfcheck() TRƯỚC khi tin kết quả: công cụ sai thường vẫn cho ra kết quả trông hợp lý.
import hashlib, json, os, signal, sys, time
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))   # module phụ đặt cạnh file này: `import tên` (cũng vào dấu băm của công cụ)

FORMAT = ''   # BẮT BUỘC: tên định dạng, một dòng (vd 'code cache V8 10.2 bọc brotli'). Dùng để gom công cụ cùng loại giữa các case.
SCOPE = ''    # BẮT BUỘC: phạm vi hỗ trợ (phiên bản, biến thể). Ngoài phạm vi thì dừng với lỗi, không đoán.
TRIAL_SECONDS = 30   # giới hạn tối thiểu (giây) cho mỗi lần thử đột biến/đáp án; giới hạn thật là max(giá trị này, 4 x thời gian parse)
KAT_WAIVER = ''   # chỉ điền (một dòng lý do) khi KHÔNG dựng nổi dữ liệu tổng hợp cho known_answers(); lớp phản biện sẽ đọc lý do này.

def parse(path):
    """Đọc file mẫu, trả kết quả (dict). Gặp dữ liệu ngoài SCOPE: raise SystemExit('ngoài phạm vi: ...')."""
    raise SystemExit('chưa viết parse()')

def selfcheck(path, res):
    """Trả [(tên, đạt?, chi tiết)]; cần ít nhất một phép. Phép kiểm phải CÓ THỂ SAI khi công cụ sai. Gợi ý theo loại việc:
    - phân tích cú pháp: đọc hết dữ liệu, không dư byte, không còn tham chiếu treo; độ dài/checksum khai trong header khớp;
    - giải nén/giải mã: nén/mã hóa lại ra đúng byte gốc; magic của lớp trong hợp lệ; padding hợp lệ;
    - giải chuỗi: hằng kiểm của chính mẫu khớp (vd đích của phép xoay mảng); tỉ lệ đầu ra là văn bản hợp lệ;
    - disassemble: mọi hàm giải mã hết đúng độ dài, kết thúc bằng lệnh trả về.
    Phép kiểm kiểu 'không ném ngoại lệ' hay luôn True là vô nghĩa: lớp phản biện sẽ đọc hàm này."""
    return []

def known_answers():
    """Trả [(tên, bytes, kiểm)]: dữ liệu TỔNG HỢP có đáp án biết trước, dựng bằng thư viện chuẩn (zlib, struct...) chứ không bằng bộ mã hóa của chính công cụ này.
    `kiểm(res)` nhận kết quả parse() của dữ liệu đó, trả True nếu đúng đáp án. Bắt lỗi offset/thứ tự/thanh ghi mà round-trip tự thân không thấy.
    Cần ít nhất một ca (hoặc khai KAT_WAIVER). Khuôn tự chạy các ca này và ghi `KAT a/b`."""
    return []

def coverage(res):
    """Trả (a, b): a trên b đơn vị đã xử lý được (chuỗi đã giải / điểm dùng, hàm đã disassemble / tổng...). Không đo được: None."""
    return None

def show(res):
    """In phần kết quả cần làm bằng chứng ra stdout (có giới hạn). Dữ liệu lấy từ mẫu nên in bằng repr()."""

def status_path():
    name = os.path.splitext(os.path.basename(__file__))[0]; d = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'runs', 'tool'); os.makedirs(d, exist_ok=True)
    return os.path.join(d, name + '.status.json')

def _net():
    """Giao diện mạng (trừ lo) thấy được lúc chạy: [] = vỏ không mạng; None = không đọc được."""
    try: return sorted(x.split(':')[0].strip() for x in open('/proc/net/dev').read().splitlines()[2:] if x.split(':')[0].strip() != 'lo')
    except OSError: return None

def _trials(path, dt=0.0):
    """Hai phép thử do KHUÔN tự chạy (stdout bị chặn nên không vào dấu băm output; mỗi lần tối đa max(30, 4 x thời gian parse thật) giây):
    1. đột biến: lật 1 byte ở 8 vị trí rải đều trong bản sao của file mẫu, chạy lại parse()+selfcheck(); selfcheck phải báo hỏng (FAIL hoặc ném lỗi)
       ít nhất một lần, nếu không phép kiểm không phân biệt được dữ liệu đúng với dữ liệu hỏng;
    2. đáp án biết trước: known_answers() chạy qua parse() và so với đáp án."""
    import contextlib, io, tempfile
    timed = [False]
    def alarm(*a): timed[0] = True; raise TimeoutError('quá thời gian trên dữ liệu thử')      # cờ: parse() có nuốt TimeoutError rồi ném lỗi khác thì vẫn không tính là phát hiện
    def run(f):
        if hasattr(signal, 'SIGALRM'): signal.signal(signal.SIGALRM, alarm); signal.alarm(limit)
        try: return f()
        finally:
            if hasattr(signal, 'SIGALRM'): signal.alarm(0)
    limit = max(TRIAL_SECONDS, int(4 * dt) + 1); late = 0; data = open(path, 'rb').read(); mut, kat, note = [0, 0], [], ''
    n = 8 if len(data) <= 4 << 20 and dt * 8 <= 120 else 3 if dt * 3 <= 400 else 1      # parse chậm thì thử ít vị trí hơn
    with tempfile.TemporaryDirectory() as td, contextlib.redirect_stdout(io.StringIO()):
        tp = os.path.join(td, 'trial.bin')
        if data:      # đối chứng: bản KHÔNG đột biến trong thư mục tạm phải parse được, nếu không (quá giờ, cần file cạnh đầu vào...) thì phép thử vô hiệu, không tính là 'phát hiện'
            open(tp, 'wb').write(data)
            try:
                bad = [str(nm) for nm, ok, _ in run(lambda: selfcheck(tp, parse(tp))) if not ok]      # cả selfcheck: phép kiểm phụ thuộc file cạnh đầu vào cũng làm 'phát hiện' giả
                if bad: note = f"bản không đột biến bị selfcheck báo hỏng trong thư mục tạm ({', '.join(bad)[:80]})"
            except (Exception, SystemExit) as e: note = f'bản không đột biến cũng lỗi trong thư mục tạm ({type(e).__name__}: {str(e)[:80]})'
        for i in range(n if data and not note else 0):
            b = bytearray(data); b[len(data) * (2 * i + 1) // (2 * n)] ^= 0xFF; open(tp, 'wb').write(b)
            timed[0] = False
            try: bad = any(not ok for _, ok, _ in run(lambda: selfcheck(tp, parse(tp))))
            except (Exception, SystemExit): bad = True      # parse/selfcheck từ chối dữ liệu hỏng
            if timed[0]: late += 1; continue      # quá giờ không phải bằng chứng selfcheck phát hiện được, cũng không tính vào mẫu số
            mut[1] += 1; mut[0] += bad
        if late and not mut[1]: note = f'cả {late} lần thử đột biến đều quá giờ (giới hạn {limit} giây): parse() trên dữ liệu hỏng không kết thúc'
        try: cases = list((globals().get('known_answers') or list)())      # thiếu hàm = không có ca nào
        except (Exception, SystemExit) as e: cases = []; kat.append([f'known_answers() lỗi ({type(e).__name__}: {str(e)[:60]})', False])
        for cs in cases:
            try:
                name, fix, expect = cs; open(tp, 'wb').write(fix); ok = bool(run(lambda: expect(parse(tp))))
            except (Exception, SystemExit): name, ok = (cs[0] if isinstance(cs, (tuple, list)) and cs else cs), False      # ca sai dạng hoặc parse/kiểm lỗi = sai đáp án
            kat.append([str(name)[:80], ok])
    return {'mutation': mut, 'kat': kat, 'mut_note': note, 'empty': not data}

def status(checks, cov, trials=None):
    """Ghi kết quả tự kiểm ra file riêng (không qua stdout, nên chuỗi lấy từ mẫu không giả được). `flow.py tool CASE seal` đọc file này."""
    sys.stdout.flush()
    def sha(p):
        h = hashlib.sha256()
        with open(p, 'rb') as f:
            for b in iter(lambda: f.read(1 << 20), b''): h.update(b)
        return h.hexdigest()
    inputs = [[os.path.realpath(a), sha(a)] for a in sys.argv[1:] if os.path.isfile(a)]      # seal gắn evidence với đúng file đầu vào (đường dẫn thật + dấu băm)
    json.dump({'argv': sys.argv[1:], 'inputs': inputs, 'first': os.path.realpath(sys.argv[1]),      # đường dẫn thật tính lúc CHẠY: seal gọi từ thư mục khác vẫn đúng
               'checks': [[str(n), bool(ok), str(det)] for n, ok, det in checks], 'coverage': list(cov) if cov else None, 'time': time.time(),
               'mutation': (trials or {}).get('mutation'), 'kat': (trials or {}).get('kat'), 'mut_note': (trials or {}).get('mut_note', ''), 'empty': (trials or {}).get('empty', False), 'kat_waiver': KAT_WAIVER, 'net': _net(),
               'out_sha256': _OUT.h.hexdigest()}, open(status_path(), 'w', encoding='utf-8'), ensure_ascii=False)

class _Tee:
    """Băm mọi thứ công cụ in ra stdout: `tool seal` chỉ nhận file output có đúng dấu băm này, nên output và kết quả tự kiểm luôn cùng một lần chạy."""
    def __init__(s, real): s.real = real; s.h = hashlib.sha256()
    def write(s, t): s.h.update(t.encode('utf-8', 'surrogateescape')); return s.real.write(t)
    def flush(s): s.real.flush()
    def __getattr__(s, k): return getattr(s.real, k)      # encoding, fileno, isatty...; ghi thẳng qua .buffer thì không được băm: đừng dùng
_OUT = None

def main():
    if len(sys.argv) < 2: raise SystemExit('dùng: python3 -I work/tools/{NAME}.py FILE [tham số...] > work/runs/tool/{NAME}.out')
    global _OUT
    sys.stdout.reconfigure(encoding='utf-8', errors='surrogateescape', newline='\n'); _OUT = sys.stdout = _Tee(sys.stdout)   # stdout chuyển thẳng vào file output (không qua bộ lọc)
    # chỉ output in ra từ đây trở đi được băm: module phụ không được print lúc import
    try: os.remove(status_path())      # xóa trạng thái của lần chạy trước NGAY ĐẦU: lần này dừng giữa chừng thì không còn trạng thái cũ để seal nhầm
    except FileNotFoundError: pass
    path = sys.argv[1]; t0 = time.time(); res = parse(path); dt = time.time() - t0; show(res)
    checks = selfcheck(path, res); status(checks, coverage(res), _trials(path, dt))

if __name__ == '__main__': main()
