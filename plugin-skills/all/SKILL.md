---
name: all
description: Phân tích dịch ngược MỌI mẫu mã độc trong một thư mục thu mẫu như MỘT case bằng một lệnh (flow.py scan) - thư mục có 1 mẫu thì phân tích 1 mẫu, có từ 2 mẫu thì phân tích tất cả, đối chiếu quan hệ giữa các mẫu và đưa cả bộ vào cổng phản biện trong một lượt, một báo cáo chung tiếng Việt. Dùng khi người dùng đưa một thư mục chứa các mẫu thu cùng nhau (cùng thiết bị, cùng sự cố). Use to analyze every sample in a collection folder as one case with cross-sample relations. Mỗi mẫu một case, không người trực thì dùng rea-workflow:auto; một file cụ thể thì rea-workflow:manual. Không bao giờ thực thi mẫu.
---

# rea-workflow:all: cả thư mục thu mẫu thành một case

Khác với `rea-workflow:auto` (mỗi mẫu một case, nhận định riêng từng mẫu, không người trực): skill này coi các mẫu trong thư mục là MỘT bộ thuộc cùng một chiến dịch/sự cố, phân tích tất cả trong một case và đưa ra nhận định về quan hệ giữa chúng trong một báo cáo chung.

`$SKILL` = `${CLAUDE_PLUGIN_ROOT}` (thư mục gốc của rea-workflow, hai cấp trên file này).

1. **Đọc `$SKILL/SKILL.md` trước khi làm gì khác** và làm đúng theo đó: mục "Quy tắc bắt buộc" (không bao giờ thực thi mẫu, mỗi kết luận là một fact có evidence, cổng phản biện tối đa 2 lần) và mục "Cách làm việc".
2. **Một lệnh dựng case.** Từ workspace nằm ngoài thư mục thu mẫu: `python3 $SKILL/flow.py scan <THƯ_MỤC> [CASE] --dry-run` để xem mẫu nào được nhận, mục nào bị bỏ (file ẩn, ghi chú thu mẫu, thư mục báo cáo, thư mục case) và báo người dùng danh sách đó; đúng thì chạy lại không có `--dry-run`. Lệnh gom mọi mẫu ở cấp một của thư mục vào MỘT case (tên mặc định là tên thư mục viết hoa), triage, rồi chạy lượt đọc nhanh cho từng mẫu dạng tệp (`quick`, `xref`, `syscalls`; mẫu dạng thư mục thì lệnh báo bỏ qua, tự chạy `quick` cho tệp đáng chú ý bên trong) và `link` khi có từ hai mẫu. Workspace và case phải nằm ngoài thư mục thu mẫu; lệnh từ chối nếu tên case mặc định trùng chính thư mục đó (đặt tên case khác). Lệnh chỉ gợi ý chế độ light, người dùng quyết. Quá 8 mẫu thì lệnh dừng: hỏi người dùng chia nhóm liên quan, hoặc dùng `rea-workflow:auto`. Case đã có thì lệnh chỉ in trạng thái, không tạo lại.
3. **Phân tích lần lượt từng mẫu** theo `python3 $SKILL/flow.py next <CASE>`: đọc evidence `quick_*`, `xref_*`, `syscalls_*` trước, rồi `disasm`/`dec` các hàm đáng ngờ. Id fact đặt tiền tố theo mẫu để không lẫn. Evidence của lượt đọc nhanh là ứng viên, chưa phải fact.
4. **Từ hai mẫu trở lên: nhận định quan hệ dựa trên kết quả dịch ngược.**
   - **Bối cảnh thu mẫu (đầu vào, không phải kết luận).** Hỏi người dùng nếu chưa rõ, rồi chép vào `report/evidence/host_collection.txt` một bảng: mẫu, thiết bị (cùng một thiết bị hay các thiết bị khác nhau), thời điểm được phản ánh, nguồn tin, vì sao nghi có liên quan. Ghi một fact `kind=relation src=V value='context: ...'` dẫn file này. Fact nguồn V không đủ cho C12.
   - **Tín hiệu kỹ thuật.** Đọc `report/evidence/link_samples.txt`: định danh chéo, chuỗi chung, đặc trưng pivot, mốc thời gian nhúng trong mẫu, và mục "Tín hiệu cho mức nhận định". Đây mới là phép so chuỗi; tìm tiếp trong kết quả dịch ngược của từng mẫu những thứ phép so chuỗi không thấy: chung địa chỉ máy chủ hay dead-drop, chung khóa hoặc thuật toán mã hóa riêng, chung giao thức/định dạng gói, mẫu này ghi tệp hay chạy lệnh mà mẫu kia đọc, cùng tác giả/builder (đường dẫn build, quy ước đặt tên, thư viện tùy biến).
   - **Nhận định.** Ghi fact `kind=relation src=S` (hoặc `E`) nêu tên các mẫu, `value` mở đầu bằng một mức:
     - `direct`: mẫu này tham chiếu, khởi chạy, tải hoặc cấu hình mẫu kia; hoặc chung C2, khóa, giao thức riêng.
     - `shared`: chung mã hoặc hạ tầng nhưng không tham chiếu nhau (cùng họ, cùng builder, đặc trưng riêng trùng nhau).
     - `context`: dịch ngược không thấy liên hệ kỹ thuật; chỉ còn bối cảnh thu mẫu. Nêu rõ đã tìm những gì.
     - `unrelated`: dịch ngược cho thấy khác tác giả, hạ tầng, mục đích; trùng bối cảnh là ngẫu nhiên.
     Mức đã có bằng chứng để `active`; mức mạnh hơn mà mới là suy luận (ví dụ "mẫu này có thể khởi chạy mẫu kia vì nó chạy lệnh từ máy chủ") để `status=hypothesis`. Mỗi nhận định nêu cả căn cứ ủng hộ lẫn căn cứ chống lại.
   - **Thiết bị và thời điểm.** Cùng một thiết bị chỉ là bối cảnh: hai mẫu có thể do hai lần xâm nhập khác nhau. Các thiết bị khác nhau thì chỉ khẳng định liên quan khi có mức `direct` hoặc `shared`. Đối chiếu thời điểm phản ánh với mốc thời gian nhúng trong mẫu (thời điểm build, ngày của hạ tầng nếu đã tra thụ động): mẫu build sau thời điểm bị phản ánh, hoặc hai mẫu cách nhau xa mà không có đặc trưng chung, là căn cứ chống lại.
   - **Báo cáo.** Mục "Quan hệ giữa các mẫu": bảng bối cảnh thu mẫu, bảng nhận định (nhận định / mức / trạng thái / fact làm căn cứ), một câu kết luận chung về bộ mẫu, và một sơ đồ chung. Phần chưa chứng minh ghi rõ là giả thuyết và nêu cần thêm dữ liệu gì để kiểm (log thiết bị, script khởi động, tra thụ động hạ tầng).
5. **Phản biện một lượt cho cả case.** Ghi đủ fact của mọi mẫu trước; chạy `python3 $SKILL/flow.py review <CASE>` (xem trước lớp máy, không tốn lượt) tới khi sạch, rồi MỘT lần `python3 $SKILL/flow.py review <CASE> --llm --detach`. FAIL thì sửa theo `where`/`redo` rồi chạy lượt 2; lượt 2 vẫn FAIL thì dừng và báo người dùng, không tự tạo `OVERRIDE`.
6. `flow.py next <CASE>` in `DONE` thì `python3 $SKILL/flow.py report <CASE> --final`, rồi chạy lệnh `audit` cho case đó (cú pháp trong `flow.py help`).

Phiên dài: tách theo mốc bằng `flow.py checkpoint <CASE>` (sau mỗi mẫu là một mốc tự nhiên) và làm tiếp bằng `flow.py resume <CASE>`.
