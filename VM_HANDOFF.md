# Tầng VM (T5): yêu cầu với lab và cách bật

Tài liệu cho người dựng và vận hành sandbox. Quy trình phân tích nằm ở `FLOW.md` (mục 2, tầng T5).

Tầng VM gửi mẫu sang một sandbox **tự dựng** để chạy thật, khi phân tích tĩnh và giả lập CPU không lấy được thông tin. Máy phân tích không bao giờ chạy mẫu và không gửi request nào tới hạ tầng của kẻ tấn công; chỉ guest trong sandbox chạy mẫu và ra mạng.

**Trạng thái hiện tại.** Bản này sinh đặc tả (`flow.py vmspec`) và in yêu cầu sẽ gửi (`flow.py vm-run --dry-run`). Phần gửi mẫu, nhận kết quả và ghi fact nguồn V chưa có. Ánh xạ tham số sang API của sandbox sẽ viết theo tài liệu đúng phiên bản bạn dựng và một báo cáo mẫu của file vô hại, không viết theo phỏng đoán.

## 1. Lab cần có gì

| Thành phần | Yêu cầu |
|---|---|
| Máy chủ sandbox | Máy riêng, không dùng chung với máy phân tích hay máy làm việc. Có ảo hóa lồng hoặc chạy trên máy thật. |
| Phần mềm | Sandbox mã nguồn mở tự dựng có REST API (dự kiến CAPEv2 cho Windows và Linux x86_64). Không dùng sandbox công khai trên Internet: đưa mẫu lên đó là vi phạm quy tắc của skill. |
| Guest Windows | Windows 10 x64, một snapshot sạch và một snapshot đã làm cứng chống phát hiện VM. Có thêm bản x86 nếu cần chạy mẫu 32-bit trong môi trường 32-bit. |
| Guest Linux x86_64 | Bản phân phối phổ biến, snapshot sạch. |
| Guest Linux MIPS/ARM | Sandbox phổ biến không hỗ trợ sẵn. Dự kiến một dịch vụ riêng chạy `qemu-system` trên máy lab (bản sau). Chưa cần dựng ở giai đoạn này. |
| Mạng quản trị | API của sandbox chỉ nghe trên mạng quản trị, có token. Máy phân tích tới được API; guest không tới được mạng quản trị. |

Không chia sẻ thư mục, clipboard hay thiết bị USB giữa máy chủ và guest. Sau mỗi task, guest quay về snapshot.

## 2. Mạng của guest

Skill có ba mức, tăng dần. Bạn đặt mức cao nhất được phép bằng `VM_NET_MAX`; đặc tả của một case không được vượt mức đó.

| Mức | Guest thấy gì | Dùng khi |
|---|---|---|
| `none` | Không có mạng | Câu hỏi chỉ về tiến trình, file, registry |
| `sink` | DNS nội bộ trả một địa chỉ giả; bộ hứng nhận kết nối, ghi lại rồi đóng. Bộ hứng không trả nội dung nào giống máy chủ điều khiển | Cần biết mẫu hỏi tên miền nào, gọi tới đâu |
| `internet` | Ra Internet thật qua một đường ra riêng (`VM_ROUTE`) | Cần hành vi sau khi mẫu nhận phản hồi thật: cấu hình, payload giai đoạn sau |

Với mức `internet`, router của lab **bắt buộc** có các luật sau, vì nhiều mẫu là bot sẽ quét, tấn công hoặc gửi thư rác tới bên thứ ba ngay khi có mạng:

- Đường ra riêng: VPN hoặc đường thuê riêng, không phải IP của cơ quan hay cá nhân. Máy chủ điều khiển sẽ thấy IP này và thời điểm chạy.
- Chặn mọi đích thuộc dải địa chỉ riêng (10/8, 172.16/12, 192.168/16, 169.254/16, dải nội bộ IPv6) và mạng quản trị.
- Chặn SMTP ra ngoài (cổng 25, 465, 587).
- Giới hạn băng thông và số kết nối mới mỗi giây của guest ở mức thấp, đủ cho một phiên điều khiển, không đủ cho quét hay tấn công từ chối dịch vụ.
- Ghi toàn bộ lưu lượng (pcap) ở router, ngoài tầm với của guest.
- Thời gian chạy có trần (`VM_TIMEOUT_MAX`); hết giờ thì ngắt mạng và hủy guest.

Skill không tự kiểm được các luật này. Chúng là trách nhiệm của người dựng lab.

## 3. Bật tầng VM

Khai trong `~/.config/rea-flow/rea.env` (mẫu ở `rea.env.example`):

```
VM_BACKEND=cape
VM_API_URL=http://<địa chỉ quản trị của sandbox>:<cổng>
VM_NET_MAX=sink
VM_ROUTE=
VM_MAX_ROUNDS=2
VM_MAX_TASKS=2
VM_TIMEOUT_MAX=1800
VM_GUESTS=windows-x64=<tên máy hoặc tag>,linux-x64=<tên máy hoặc tag>
```

Token đặt bằng biến môi trường `VM_API_TOKEN` trong shell của bạn, không ghi vào file.

Ý nghĩa của việc khai:

- Khai `VM_BACKEND` là **phê duyệt một lần cho mọi case**: từ đó flow được gửi mẫu của bất kỳ case nào đã qua cổng phản biện mà không hỏi lại. Để trống là tắt, các lệnh `vm-*` chỉ dry-run.
- Các khóa `VM_*` chỉ được đọc từ file cấu hình, không đọc từ biến môi trường, để một dòng lệnh không tự bật được tầng này. Đây là lớp chặn nhầm, không phải ranh giới bảo mật: cô lập thật nằm ở mạng của lab và ở token.
- Nên bắt đầu với `VM_NET_MAX=sink`. Chỉ nâng lên `internet` sau khi router có đủ luật ở mục 2 và đã khai `VM_ROUTE`.
- Chế độ không người trực (`flow.py watch`) không gửi mẫu: gặp case cần VM thì dừng case và báo.

Kiểm cấu hình: `python3 flow.py doctor` (dòng `VM_BACKEND`).

## 4. Luồng dùng

1. Người phân tích (hoặc agent) ghi fact `observe` (câu hỏi) và `env` (môi trường mẫu cần), rồi đưa qua cổng phản biện.
2. `flow.py vmspec CASE` sinh `work/vm/rN/vmspec.json` và `vm_task.md`. File sau là bản để người vận hành đọc trước khi cho chạy.
3. `flow.py vm-run CASE --dry-run` in sandbox, guest, mức mạng, thời gian, hash từng file và các câu hỏi. Lệnh này không mở kết nối mạng.
4. Gửi thật (bản sau): do người dùng chạy từ shell của mình. Sandbox bash của agent thường không tới được địa chỉ nội bộ của lab.

## 5. Ghi vào báo cáo

Mỗi case đã chạy trên VM phải nêu trong mục hạn chế/OPSEC: mức mạng đã dùng, đường ra, thời điểm chạy, và việc máy chủ điều khiển có thể đã thấy lần chạy đó. Hành vi quan sát trong sandbox có thể khác trên máy nạn nhân (mẫu nhận ra sandbox, máy chủ điều khiển trả nội dung khác theo thời điểm hoặc theo IP).
