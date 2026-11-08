---
name: rea-flow
description: Quy trình dịch ngược mã độc có kiểm chứng (PE, ELF, Go, .NET, shellcode, installer, script) - triage tĩnh, bóc vỏ, decompile, giả lập CPU, ghi fact có nguồn, cổng phản biện 2 lần, báo cáo tiếng Việt. Dùng khi được yêu cầu phân tích, dịch ngược hoặc viết báo cáo về một mẫu mã độc. Use for malware analysis, reverse engineering, unpacking, decompiling, string/config decryption, IOC extraction or a malware report on a sample. Không bao giờ thực thi mẫu (never executes the sample).
license: MIT
compatibility: Linux x86-64; Python >= 3.9; Node.js >= 22.20; JDK 21 + Ghidra 12; rea (npm rea-agents); 7z, pefile, capstone, unicorn 2.1.4. `flow.py setup` kiểm và in lệnh cài. Không cần mạng khi phân tích.
---

# rea-flow: dịch ngược mã độc theo fact có kiểm chứng

`$SKILL` dưới đây là thư mục chứa file này. Chạy mọi lệnh từ **workspace**: thư mục chứa các case (thường là thư mục hiện tại của người dùng). Trước case đầu tiên trên một máy, kiểm công cụ phân tích: `python3 $SKILL/flow.py setup` (chỉ kiểm, in kế hoạch). Thiếu thì báo người dùng và đề nghị `flow.py setup --yes` (cài bằng apt/sudo, tải Ghidra); không tự cài khi chưa được đồng ý. Cấu hình máy: `python3 $SKILL/flow.py doctor`. Quy trình đầy đủ: `$SKILL/FLOW.md`.

**Lần đầu dùng skill:** chạy `python3 $SKILL/flow.py rules --check`. Nếu báo `THIẾU`, chạy `python3 $SKILL/flow.py rules` để chép mục "Quy tắc bắt buộc" dưới đây vào file hướng dẫn của agent (skill cài toàn máy: `~/.claude/CLAUDE.md`, `~/.codex/AGENTS.md`…; cài theo project: `AGENTS.md` và `CLAUDE.md` của chính project đó), rồi báo người dùng đã ghi file nào. Nếu lệnh báo không đoán được phạm vi thì bỏ qua.

## Quy tắc bắt buộc

- **Không bao giờ thực thi mẫu.** Không chạy qua wine/qemu, không chạy script mẫu, không dùng `rea capture-*` hay `debug-with-gdb` trên mẫu. Không chạm C2 hay hạ tầng phát tán, không tra mẫu trên dịch vụ ngoài. Chỉ được phân tích tĩnh và giả lập CPU (`$SKILL/winemu`).
- Mỗi case bắt đầu bằng `flow.py new`. Mỗi kết luận là một fact trong `<CASE>/facts.jsonl` (ghi qua `case.py add`), có nguồn `src=S|E|V` (tĩnh / giả lập / VM) và evidence nằm trong `<CASE>/report/evidence/`. Sửa fact bằng fact mới có `supersedes=<id cũ>`, không sửa hay xóa dòng cũ.
- Báo cáo viết tiếng Việt, có bảng đính chính và mục hạn chế/OPSEC. Mỗi mẫu hoặc chiến dịch có báo cáo riêng, không quy kết chéo giữa các case.
- Đọc tóm tắt, không đọc log thô (dùng `grep`, `sed -n`, `head`).
- Tách phiên theo mốc để không đọc lại ngữ cảnh cũ: sau triage/bóc vỏ, sau mỗi cụm decompile (giải chuỗi, loader…), sau mỗi đợt giả lập, trước cổng phản biện, trước khi viết báo cáo. Ở mốc: ghi hết kết luận thành fact (ý còn nghi thì `status=hypothesis`), chép đoạn chứng minh vào `report/evidence/` kèm `#L`, chạy `flow.py checkpoint <CASE>`; OK thì đề nghị người dùng `/clear` (hoặc mở phiên mới). Không tách giữa chừng một bước chưa ghi.
- Sau khi ngữ cảnh bị nén hoặc `/clear`: chạy `flow.py resume <CASE>` trước khi làm tiếp. `facts.jsonl` là nguồn chân lý; fact không còn trong ngữ cảnh không có nghĩa là không tồn tại: tra `case.py show <CASE> --id ID` hoặc `case.py search <CASE> TỪ` trước khi kết luận.
- Trước khi đóng case phải qua cổng phản biện: `flow.py review` tối đa 2 lần; lần 2 vẫn FAIL thì dừng và báo người dùng (`work/review/STOP_REPORT.md`), không tự tạo `OVERRIDE`.

## Cách làm việc

Code dẫn đường, không cần đọc lại tài liệu:

1. `python3 $SKILL/flow.py new <CASE> <mẫu|zip>...` tạo case và triage.
2. `python3 $SKILL/flow.py next <CASE>` cho việc kế tiếp, đã điền sẵn tên case và lệnh cần chạy; `status` cho checklist, `resume` sau khi ngữ cảnh bị nén. Làm đúng theo output rồi gọi lại.
3. Mọi lệnh và tham số: `python3 $SKILL/flow.py help` (nguồn duy nhất). Ghi fact: `python3 $SKILL/case.py add <CASE> id=... kind=... value=... src=S evidence=report/evidence/F[#Ln]`; tra: `case.py search|show`.
4. Cổng phản biện: `python3 $SKILL/flow.py review <CASE> --llm --detach`. Lệnh in `BƯỚC KẾ`: FAIL thì sửa từng mục theo `where`/`redo` rồi chạy lại (tối đa 2 lần, lần 2 vẫn FAIL thì dừng và báo người dùng `STOP_REPORT.md`). Mã 0 = PASS, 1 = FAIL, 2 = STOPPED. Mã 6 = đang chạy nền, gọi lại **đúng lệnh đó** cho tới khi mã khác 6; mã 7 = tiến trình nền chết, gọi lại; mã 70 = tiến trình nền gặp lỗi (thường là lớp 2 bị ngắt), gọi lại, lặp lại thì đọc `work/review/run.log`; mã 4 = chờ manual, báo người dùng dán file prompt được in ra vào chat mới và lưu câu trả lời. Không tự bọc `timeout`/`nohup`, không chạy review thứ hai cho cùng case. `review-loop` tự động cả vòng khi backend là claude, api hoặc cmd, hoặc khi đã khai `ANALYST_LLM_CMD`; không thì mã 3 (HANDOFF): agent đang chạy tự sửa theo `where`/`redo`.
5. Xong: `python3 $SKILL/flow.py next <CASE>` in `DONE` thì `flow.py report <CASE> --final && flow.py audit <CASE>`.

Kho tra chéo giữa các case (`flow.py kb`): `new`/`triage` tự in gợi ý mẫu tương tự nếu kho đã dựng. Gợi ý **không phải fact**: không chép vào evidence hay báo cáo, không quy kết theo case khác; chỉ dùng để biết nên thử gì trước, rồi tự chứng minh lại trên mẫu của case này.

Giả lập shellcode/loader Windows x86: `$SKILL/winemu/README.md`. Lệnh `rea` được phép theo loại mẫu và lệnh bị cấm: `$SKILL/FLOW.md` mục 4a.
