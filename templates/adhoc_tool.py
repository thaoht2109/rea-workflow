#!/usr/bin/env python3
# Công cụ tự viết cho MỘT case (tầng T1b), chạy bằng: flow.py tool CASE run {NAME} FILE [tham số...]
# Dùng khi triage trả loại chưa có đường đi. Chỉ ĐỌC file mẫu: không mạng, không tiến trình con, không nạp mẫu vào trình thông dịch nào.
# `tool run` quét script theo danh sách cho phép: chỉ import thư viện phân tích dữ liệu và phần đọc của os; không getattr/eval/exec/pickle.
# Lúc chạy có thêm lớp chặn: tạo tiến trình, socket và ghi file ngoài thư mục os.environ['REA_TOOL_OUT'] đều ném PermissionError.
# Cần xuất file (blob đã giải, bảng lớn): ghi vào REA_TOOL_OUT rồi in sha256 của nó ra output.
# Viết selfcheck() TRƯỚC khi tin kết quả: công cụ sai thường vẫn cho ra kết quả trông hợp lý.
import os, sys   # module phụ: đặt cạnh file này rồi `import tên` (cũng bị quét và băm); không được sửa sys.path

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
    """In phần kết quả cần làm bằng chứng (có giới hạn). Dữ liệu lấy từ mẫu in bằng repr() để không giả được dòng điều khiển."""

def main():
    if len(sys.argv) < 2: raise SystemExit('dùng: flow.py tool CASE run {NAME} FILE [tham số...]')
    path = sys.argv[1]; res = parse(path); show(res)
    n = os.environ.get('REA_TOOL_NONCE', '')      # dấu do flow.py cấp mỗi lần chạy: dòng thiếu dấu không được tính (mẫu không giả được)
    for name, ok, detail in selfcheck(path, res): print(f"SELFCHECK[{n}] {'PASS' if ok else 'FAIL'} {name}: {detail}")
    cov = coverage(res)
    if cov: print(f'COVERAGE[{n}] {cov[0]}/{cov[1]}')

if __name__ == '__main__': main()
