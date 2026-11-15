#!/usr/bin/env python3
# Công cụ tự viết cho MỘT case (tầng T1b). Dùng khi triage trả loại chưa có đường đi.
# Skill KHÔNG chạy file này: agent tự chạy như mọi script phân tích khác, rồi niêm phong kết quả:
#   python3 -I work/tools/{NAME}.py FILE [tham số...] > work/runs/tool/{NAME}.out
#   flow.py tool CASE seal {NAME}
# Quy tắc không chạy mẫu vẫn nguyên: chỉ ĐỌC file mẫu, không mạng, không tiến trình con, không nạp mẫu vào trình thông dịch/runtime nào.
# Viết selfcheck() TRƯỚC khi tin kết quả: công cụ sai thường vẫn cho ra kết quả trông hợp lý.
import json, os, sys, time
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

def status(checks, cov):
    """Ghi kết quả tự kiểm ra file riêng (không qua stdout, nên chuỗi lấy từ mẫu không giả được). `flow.py tool CASE seal` đọc file này."""
    name = os.path.splitext(os.path.basename(__file__))[0]; d = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'runs', 'tool'); os.makedirs(d, exist_ok=True)
    json.dump({'argv': sys.argv[1:], 'checks': [[str(n), bool(ok), str(det)] for n, ok, det in checks], 'coverage': list(cov) if cov else None, 'time': time.time()},
              open(os.path.join(d, name + '.status.json'), 'w', encoding='utf-8'), ensure_ascii=False)

def main():
    if len(sys.argv) < 2: raise SystemExit('dùng: python3 -I work/tools/{NAME}.py FILE [tham số...] > work/runs/tool/{NAME}.out')
    path = sys.argv[1]; res = parse(path); show(res)
    status(selfcheck(path, res), coverage(res))

if __name__ == '__main__': main()
