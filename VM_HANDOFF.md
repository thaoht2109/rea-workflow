# Tầng VM (T5): cầu nối, yêu cầu với lab và cách bật

Tài liệu cho người dựng sandbox và viết cầu nối. Quy trình phân tích nằm ở `FLOW.md` (mục 2, tầng T5).

Tầng VM dùng khi phân tích tĩnh và giả lập CPU không lấy được thông tin: mẫu được chạy thật trong một sandbox **tự dựng**. Tầng này mặc định tắt.

## 1. Ai làm gì

| Thành phần | Ở đâu | Việc |
|---|---|---|
| Skill (repo này) | Máy phân tích | Sinh đặc tả từ fact (`flow.py vmspec`), kiểm cổng phản biện và các trần, gọi cầu nối, đọc kết quả trả về như dữ liệu không tin cậy |
| Cầu nối | Ngoài repo, do bạn tự viết và cài | Đọc đặc tả, gửi mẫu sang sandbox của bạn, chờ, mang kết quả về. Giữ địa chỉ, token và hiểu biết về API của sandbox |
| Sandbox | Máy chủ riêng của lab | Chạy mẫu trong máy ảo, ghi hành vi và lưu lượng mạng |

Skill không chứa mã gửi hay chạy mẫu, không biết địa chỉ hay token của sandbox. Máy phân tích không chạy mẫu và không gửi request nào tới hạ tầng của kẻ tấn công; chỉ guest trong sandbox chạy mẫu và ra mạng.

**Trạng thái hiện tại.** Skill sinh đặc tả, gọi cầu nối (`flow.py vm-run`) và kiểm bản kê kết quả theo giao kèo ở mục 4. Skill chưa đọc báo cáo sandbox thành fact nguồn V.

## 2. Lab cần có gì

| Thành phần | Yêu cầu |
|---|---|
| Máy chủ sandbox | Máy riêng, không dùng chung với máy phân tích hay máy làm việc. Có ảo hóa phần cứng (KVM). |
| Phần mềm | Sandbox mã nguồn mở tự dựng có REST API, guest là máy ảo thật. Container không phải máy ảo: không chạy mẫu trong container. Không dùng sandbox công khai trên Internet: đưa mẫu lên đó là vi phạm quy tắc của skill. |
| Guest Windows | Windows 10 x64, một snapshot sạch và một snapshot đã làm cứng chống phát hiện máy ảo. |
| Guest Linux x86_64 | Bản phân phối phổ biến, snapshot sạch. |
| Guest Linux MIPS/ARM | Sandbox phổ biến không hỗ trợ sẵn; cần dịch vụ riêng chạy giả lập toàn hệ thống trên máy lab. Chưa cần ở giai đoạn này. |
| Mạng quản trị | API của sandbox chỉ nghe trên mạng quản trị, có token. Guest không tới được mạng quản trị. |

Không chia sẻ thư mục, clipboard hay thiết bị USB giữa máy chủ và guest. Sau mỗi task, guest quay về snapshot.

## 3. Mạng của guest

Skill có ba mức, tăng dần. Bạn đặt mức cao nhất được phép bằng `VM_NET_MAX`; đặc tả của một case không được vượt mức đó. Cầu nối và lab là nơi thực thi mức ghi trong đặc tả.

| Mức | Guest thấy gì | Dùng khi |
|---|---|---|
| `none` | Không có mạng | Câu hỏi chỉ về tiến trình, file, registry |
| `sink` | DNS nội bộ trả một địa chỉ giả; bộ hứng nhận kết nối, ghi lại rồi đóng. Bộ hứng không trả nội dung nào giống máy chủ điều khiển | Cần biết mẫu hỏi tên miền nào, gọi tới đâu |
| `internet` | Ra Internet thật qua một đường ra riêng | Cần hành vi sau khi mẫu nhận phản hồi thật: cấu hình, payload giai đoạn sau |

Với mức `internet`, router của lab **bắt buộc** có các luật sau, vì nhiều mẫu là bot sẽ quét, tấn công hoặc gửi thư rác tới bên thứ ba ngay khi có mạng:

- Đường ra riêng: VPN hoặc đường thuê riêng, không phải IP của cơ quan hay cá nhân. Máy chủ điều khiển sẽ thấy IP này và thời điểm chạy.
- Chặn mọi đích thuộc dải địa chỉ riêng (10/8, 172.16/12, 192.168/16, 169.254/16, dải nội bộ IPv6) và mạng quản trị.
- Chặn SMTP ra ngoài (cổng 25, 465, 587).
- Giới hạn băng thông và số kết nối mới mỗi giây của guest ở mức thấp, đủ cho một phiên điều khiển, không đủ cho quét hay tấn công từ chối dịch vụ.
- Ghi toàn bộ lưu lượng (pcap) ở router, ngoài tầm với của guest.
- Thời gian chạy có trần (`VM_TIMEOUT_MAX`); hết giờ thì ngắt mạng và hủy guest.

Skill không tự kiểm được các luật này. Chúng là trách nhiệm của người dựng lab.

## 4. Giao kèo với cầu nối

Cầu nối là một lệnh không tương tác. Skill gọi nó một lần cho mỗi vòng, không qua shell:

```
<VM_BRIDGE_CMD> <đường dẫn vmspec.json> <thư mục case> <thư mục kết quả>
```

Mã thoát 0 là xong; khác 0 là lỗi. Skill ghi dấu "đã gửi" trước khi gọi và không gọi lại cùng vòng, kể cả khi cầu nối lỗi. Skill chỉ in ba dòng cuối của stdout, đã lọc ký tự điều khiển.

Đầu vào, lấy từ `vmspec.json`:

- `files`: tên trong guest (`name`), đường dẫn nguồn tính từ thư mục case (`src`), `sha256`. Cầu nối kiểm lại SHA256 trước khi gửi.
- `guest` (`os`, `arch`), `layout` (`dir`, `main`), `launches` (mỗi mục là một task: `mode`, `args`, tùy chọn `path`), `precond`.
- `net.mode` (`none`, `sink`, `internet`) và `time.timeout` (giây): cầu nối không được dùng mức mạng cao hơn hay thời gian dài hơn.
- `observe`: các câu hỏi, để cầu nối bật đúng phần thu thập.

Đầu ra: các file kết quả đặt thẳng trong thư mục kết quả (không thư mục con), và một bản kê `result.json`:

```json
{"net_mode": "sink",
 "tasks": [{"status": "reported", "route_verified": true, "timeout_effective": 300,
            "files": [{"name": "report_t1.json", "sha256": "…"}]}]}
```

Skill từ chối cả vòng khi một trong các điều sau sai:

- `net_mode` khác `net.mode` của đặc tả; số task khác số `launches`.
- Một task không có `route_verified: true`. Cầu nối chỉ được ghi `true` sau khi đã hỏi lại sandbox và thấy task chạy đúng route nó yêu cầu. Sandbox có thể bỏ qua tham số route và dùng đường mặc định, nên bước hỏi lại là bắt buộc; lệch thì cầu nối phải hủy task.
- `timeout_effective` lớn hơn `time.timeout`; `status` khác `reported`; không có file nào.
- Tên file không phải tên trần (`A-Z a-z 0-9 _ . -`, tối đa 80 ký tự), file là symlink, thiếu, quá 1 GiB, hoặc sai `sha256`.

Cầu nối chỉ vận chuyển. Nó không phân tích, không sửa kết quả, không ghi fact. Thư mục kết quả là dữ liệu do mẫu chi phối: skill đặt quyền 0400, `flow.py export` đưa vào gói 7z có mật khẩu, và phiên phản biện không được chép thư mục này.

## 5. Bật tầng VM

Khai trong `~/.config/rea-flow/rea.env` (mẫu ở `rea.env.example`):

```
VM_BRIDGE_CMD=<lệnh cầu nối của bạn>
VM_NET_MAX=sink
VM_MAX_ROUNDS=2
VM_MAX_TASKS=2
VM_TIMEOUT_MAX=1800
```

Ý nghĩa của việc khai:

- Khai `VM_BRIDGE_CMD` là **phê duyệt một lần cho mọi case**: từ đó flow được giao mẫu của bất kỳ case nào đã qua cổng phản biện cho cầu nối mà không hỏi lại. Để trống là tắt, các lệnh `vm-*` chỉ dry-run.
- Các khóa `VM_*` chỉ được đọc từ file cấu hình, không đọc từ biến môi trường, để một dòng lệnh không tự bật được tầng này. Đây là lớp chặn nhầm, không phải ranh giới bảo mật: cô lập thật nằm ở mạng của lab và ở token mà cầu nối giữ.
- Nên bắt đầu với `VM_NET_MAX=sink`. Chỉ nâng lên `internet` sau khi router có đủ luật ở mục 3.
- Chế độ không người trực (`flow.py watch`) không gọi cầu nối: gặp case cần VM thì dừng case và báo.

Kiểm cấu hình: `python3 flow.py doctor` (dòng `VM_BRIDGE_CMD`).

## 6. Luồng dùng

1. Người phân tích (hoặc agent) ghi fact `observe` (câu hỏi) và `env` (môi trường mẫu cần), rồi đưa qua cổng phản biện.
2. `flow.py vmspec CASE` sinh `work/vm/rN/vmspec.json` và `vm_task.md`. File sau là bản để người vận hành đọc.
3. `flow.py vm-run CASE --dry-run` in guest, mức mạng, thời gian, hash từng file và các câu hỏi. Lệnh này không gọi cầu nối và không mở kết nối mạng.
4. `flow.py vm-run CASE` giao đặc tả cho cầu nối và kiểm bản kê. Sandbox bash của agent thường không tới được mạng lab; khi đó người dùng chạy lệnh này từ shell của mình.

## 7. Ghi vào báo cáo

Mỗi case đã chạy trên VM phải nêu trong mục hạn chế/OPSEC: mức mạng đã dùng, đường ra, thời điểm chạy, và việc máy chủ điều khiển có thể đã thấy lần chạy đó. Hành vi quan sát trong sandbox có thể khác trên máy nạn nhân (mẫu nhận ra sandbox, máy chủ điều khiển trả nội dung khác theo thời điểm hoặc theo IP).
