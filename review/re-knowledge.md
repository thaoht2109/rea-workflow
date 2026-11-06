## Bẫy thường gặp khi kết luận dịch ngược (nhất là khi xét cách giải thích khác và độ mạnh của `status`)

Mỗi mục: dấu hiệu → cách giải thích khác → cách kiểm rẻ.

**Chuỗi và IOC**
- URL/tên miền nằm trong vùng chữ ký Authenticode (security directory, cuối file) hoặc chuỗi chứng thư (CRL/OCSP/CA, timestamp) → hạ tầng CA, không phải C2. Kiểm: offset chuỗi có nằm trong `IMAGE_DIRECTORY_ENTRY_SECURITY` không.
- Chuỗi banner/phiên bản/bản quyền của thư viện tĩnh (OpenSSL, zlib, Qt, CRT, Go runtime/vendor) → mã của thư viện, không phải hành vi. Thư viện crypto/TLS vendor trong Go thường chỉ là TLS chuẩn.
- Số dạng `a.b.c.d` trong chuỗi phiên bản hay tài nguyên → không phải IP.
- Chuỗi có trong file nhưng không có tham chiếu (xref) từ mã → có thể là dữ liệu chết hoặc mồi nhử; chỉ tính là hành vi khi có đường gọi.

**Import và API**
- API có trong bảng import/được resolve nhưng không thấy lời gọi → khả năng, không phải hành vi. API resolve hàng loạt rồi không gọi thường là import của payload (loader tự nạp PE).
- Lời gọi lặp hàng nghìn lần tới cùng một API vô hại (OutputDebugString, SetLastError, GetTickCount…) với tham số rác → junk/mồi nhử chống phân tích, không phải chức năng.
- DLL hợp lệ bị build lại kèm thêm mã: export đúng tên nhưng hàm bị vá hoặc thêm code ở epilogue. Kiểm: có caller tĩnh nào gọi tới hàm bị vá không (tên, ordinal, call trực tiếp); không có thì đường kích hoạt chưa được chứng minh.

**Giả lập (src = E)**
- Mọi giá trị trả về từ API giả do stub của emulator quyết định: handle cố định dùng chung, kích thước/nội dung file rỗng, thời gian, tên máy, cửa sổ, bộ nhớ của DLL giả (ntdll/kernel32 dựng lại không có bố cục thật). Nhánh rẽ dựa trên các giá trị này có thể là do stub, không phải do mẫu.
- Một handle dùng chung cho nhiều file → không quy được thao tác đọc/ghi cho file cụ thể.
- Địa chỉ đích nằm trong vùng của DLL giả → nhãn ký hiệu (tên hàm/biến) không có nguồn.
- Hành vi chỉ thấy với một bộ tham số dòng lệnh/biến môi trường → điều kiện kích hoạt phải ghi cùng fact.
- Emulator dừng do lỗi (truy cập bộ nhớ chưa ánh xạ, exception không xử lý) → các nhánh sau đó chưa được quan sát; kết luận "không có X" không đủ độ phủ.

**Kỹ thuật tiêm/nạp**
- "Process hollowing" cần thấy: tạo tiến trình suspended + unmap/ghi đè image + đổi context/entry + resume. Thiếu bước nào thì chỉ được gọi là "ghi vào tiến trình con".
- Ghi một con trỏ/vài byte vào DLL của tiến trình con → hook/patch, không phải nạp payload.

**Cấu trúc PE và đóng gói**
- Vùng lớn `0xCC`/`0x00` giữa các hàm → đệm của incremental linking hoặc căn chỉnh, không phải code bị xóa hay mã hóa.
- Entropy cao chỉ ở `.rsrc`/overlay → có thể là tài nguyên nén hợp lệ (ảnh, installer data). Packer cần thêm dấu hiệu: section bất thường, EP ngoài `.text`, import tối thiểu.
- Chữ ký số: phải phân biệt "digest khớp nội dung" và "chuỗi chứng thư hợp lệ"; chứng thư hết hạn vẫn hợp lệ nếu có timestamp trước hạn; người ký phải đọc từ chứng thư, không suy từ tên file.

**Số liệu và phủ định**
- Con số trong fact (đếm lệnh, tổng byte, số file) phải cộng/đếm lại được từ evidence; tổng thành phần phải khớp tổng.
- "Không có", "chỉ có", "toàn bộ" cần nêu phạm vi đã quét (file nào, phương pháp nào). Không nêu thì là `weak`.
- Họ mã độc: trùng một kỹ thuật chung (VEH, XOR khóa lặp, tải từ dịch vụ đám mây) chưa đủ; cần đặc trưng riêng của họ.
