#!/usr/bin/env python3
# Công cụ tự viết cho MỘT case (tầng T1b). Dùng khi triage trả loại chưa có đường đi.
# Skill KHÔNG chạy file này: agent tự chạy như mọi script phân tích khác, rồi niêm phong kết quả:
#   python3 -I work/tools/{NAME}.py FILE [tham số...] > work/runs/tool/{NAME}.out
#   flow.py tool CASE seal {NAME}
# Quy tắc không chạy mẫu vẫn nguyên: chỉ ĐỌC file mẫu, không mạng, không tiến trình con, không nạp mẫu vào trình thông dịch/runtime nào.
# Viết selfcheck() TRƯỚC khi tin kết quả: công cụ sai thường vẫn cho ra kết quả trông hợp lý.
import hashlib, json, os, sys, time
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))   # module phụ đặt cạnh file này: `import tên` (cũng vào dấu băm của công cụ)

FORMAT = ''   # BẮT BUỘC: tên định dạng, một dòng (vd 'code cache V8 10.2 bọc brotli'). Dùng để gom công cụ cùng loại giữa các case.
SCOPE = ''    # BẮT BUỘC: phạm vi hỗ trợ (phiên bản, biến thể). Ngoài phạm vi thì dừng với lỗi, không đoán.

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

def coverage(res):
    """Trả (a, b): a trên b đơn vị đã xử lý được (chuỗi đã giải / điểm dùng, hàm đã disassemble / tổng...). Không đo được: None."""
    return None

def show(res):
    """In phần kết quả cần làm bằng chứng ra stdout (có giới hạn). Dữ liệu lấy từ mẫu nên in bằng repr()."""

def status_path():
    name = os.path.splitext(os.path.basename(__file__))[0]; d = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'runs', 'tool'); os.makedirs(d, exist_ok=True)
    return os.path.join(d, name + '.status.json')

def status(checks, cov):
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
    path = sys.argv[1]; res = parse(path); show(res)
    status(selfcheck(path, res), coverage(res))

if __name__ == '__main__': main()
