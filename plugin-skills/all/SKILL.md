---
name: all
description: Phân tích dịch ngược MỌI mẫu mã độc trong một thư mục thu mẫu như MỘT case bằng một lệnh (flow.py scan) - thư mục có 1 mẫu thì phân tích 1 mẫu, có từ 2 mẫu thì phân tích tất cả, đối chiếu quan hệ giữa các mẫu và đưa cả bộ vào cổng phản biện trong một lượt, một báo cáo chung tiếng Việt. Dùng khi người dùng đưa một thư mục chứa các mẫu thu cùng nhau (cùng thiết bị, cùng sự cố). Use to analyze every sample in a collection folder as one case with cross-sample relations. Mỗi mẫu một case, không người trực thì dùng rea-workflow:auto; một file cụ thể thì rea-workflow:manual. Không bao giờ thực thi mẫu.
---

# rea-workflow:all: cả thư mục thu mẫu thành một case

Khác với `rea-workflow:auto` (mỗi mẫu một case, nhận định riêng từng mẫu, không người trực): skill này coi các mẫu trong thư mục là MỘT bộ thuộc cùng một chiến dịch/sự cố, phân tích tất cả trong một case và đưa ra nhận định về quan hệ giữa chúng trong một báo cáo chung.

`$SKILL` = `${CLAUDE_PLUGIN_ROOT}` (thư mục gốc của rea-workflow, hai cấp trên file này).

1. **Đọc `$SKILL/SKILL.md` trước khi làm gì khác** và làm đúng theo đó: mục "Quy tắc bắt buộc" (không bao giờ thực thi mẫu, mỗi kết luận là một fact có evidence, cổng phản biện tối đa 2 lần) và mục "Cách làm việc".
2. **Một lệnh dựng case.** Từ workspace nằm ngoài thư mục thu mẫu: `python3 $SKILL/flow.py scan <THƯ_MỤC> [CASE] --dry-run` để xem mẫu nào được nhận, mục nào bị bỏ (file ẩn, ghi chú thu mẫu, thư mục báo cáo, thư mục case) và báo người dùng danh sách đó; đúng thì chạy lại không có `--dry-run`. Lệnh gom mọi mẫu ở cấp một của thư mục vào MỘT case (tên mặc định là tên thư mục viết hoa), triage, rồi chạy lượt đọc nhanh cho từng mẫu (`quick`, `xref`, `syscalls`) và `link` khi có từ hai mẫu. Quá 8 mẫu thì lệnh dừng: hỏi người dùng chia nhóm liên quan, hoặc dùng `rea-workflow:auto`. Case đã có thì lệnh chỉ in trạng thái, không tạo lại.
3. **Phân tích lần lượt từng mẫu** theo `python3 $SKILL/flow.py next <CASE>`: đọc evidence `quick_*`, `xref_*`, `syscalls_*` trước, rồi `disasm`/`dec` các hàm đáng ngờ. Id fact đặt tiền tố theo mẫu để không lẫn. Evidence của lượt đọc nhanh là ứng viên, chưa phải fact.
4. **Từ hai mẫu trở lên:** nếu người dùng (người thu mẫu) cho biết các mẫu thuộc cùng một chiến dịch, thiết bị hay sự cố, chép nguyên lời đó kèm thời điểm vào `report/evidence/host_collection.txt` và ghi một fact `kind=relation src=V` dẫn file này: đó là bối cảnh thu mẫu, không thay cho bằng chứng kỹ thuật. Rồi đọc `report/evidence/link_samples.txt`, ghi fact `kind=relation` nêu tên các mẫu (điều đã chứng minh để `active`, suy luận như "mẫu này khởi chạy mẫu kia" để `status=hypothesis`, không thấy liên hệ thì `n/a: lý do`) và viết mục "Quan hệ giữa các mẫu" trong báo cáo: bảng nhận định / trạng thái / fact làm căn cứ, kèm một sơ đồ chung của cả bộ mẫu.
5. **Phản biện một lượt cho cả case.** Ghi đủ fact của mọi mẫu trước; chạy `python3 $SKILL/flow.py review <CASE>` (xem trước lớp máy, không tốn lượt) tới khi sạch, rồi MỘT lần `python3 $SKILL/flow.py review <CASE> --llm --detach`. FAIL thì sửa theo `where`/`redo` rồi chạy lượt 2; lượt 2 vẫn FAIL thì dừng và báo người dùng, không tự tạo `OVERRIDE`.
6. `flow.py next <CASE>` in `DONE` thì `python3 $SKILL/flow.py report <CASE> --final`, rồi chạy lệnh `audit` cho case đó (cú pháp trong `flow.py help`).

Phiên dài: tách theo mốc bằng `flow.py checkpoint <CASE>` (sau mỗi mẫu là một mốc tự nhiên) và làm tiếp bằng `flow.py resume <CASE>`.
