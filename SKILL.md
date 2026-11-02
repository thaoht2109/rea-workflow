---
name: rea-flow
description: Quy trình dịch ngược mã độc có kiểm chứng (PE, ELF, Go, .NET, shellcode, installer, script) - triage tĩnh, bóc vỏ, decompile, giả lập CPU, ghi fact có nguồn, cổng phản biện 2 lần, báo cáo tiếng Việt. Dùng khi được yêu cầu phân tích, dịch ngược hoặc viết báo cáo về một mẫu mã độc. Không bao giờ thực thi mẫu.
---

# rea-flow: dịch ngược mã độc theo fact có kiểm chứng

`$SKILL` dưới đây là thư mục chứa file này. Chạy mọi lệnh từ **workspace**: thư mục chứa các case (thường là thư mục hiện tại của người dùng). Không cần bước cài đặt nào; nếu thiếu công cụ, chạy `python3 $SKILL/flow.py doctor` và làm theo gợi ý. Quy trình đầy đủ: `$SKILL/FLOW.md`.

**Lần đầu dùng skill:** chạy `python3 $SKILL/flow.py rules --check`. Nếu báo `THIẾU`, chạy `python3 $SKILL/flow.py rules` để chép mục "Quy tắc bắt buộc" dưới đây vào file hướng dẫn của agent (skill cài toàn máy: `~/.claude/CLAUDE.md`, `~/.codex/AGENTS.md`…; cài theo project: `AGENTS.md` và `CLAUDE.md` của chính project đó), rồi báo người dùng đã ghi file nào. Nếu lệnh báo không đoán được phạm vi thì bỏ qua.

## Quy tắc bắt buộc

- **Không bao giờ thực thi mẫu.** Không chạy qua wine/qemu, không chạy script mẫu, không dùng `rea capture-*` hay `debug-with-gdb` trên mẫu. Không chạm C2 hay hạ tầng phát tán, không tra mẫu trên dịch vụ ngoài. Chỉ được phân tích tĩnh và giả lập CPU (`$SKILL/winemu`).
- Mỗi case bắt đầu bằng `flow.py new`. Mỗi kết luận là một fact trong `<CASE>/facts.jsonl` (ghi qua `case.py add`), có nguồn `src=S|E|V` (tĩnh / giả lập / VM) và evidence nằm trong `<CASE>/report/evidence/`. Sửa fact bằng fact mới có `supersedes=<id cũ>`, không sửa hay xóa dòng cũ.
- Báo cáo viết tiếng Việt, có bảng đính chính và mục hạn chế/OPSEC. Mỗi mẫu hoặc chiến dịch có báo cáo riêng, không quy kết chéo giữa các case.
- Đọc tóm tắt, không đọc log thô (dùng `grep`, `sed -n`, `head`).
- Tách phiên theo mốc để không đọc lại ngữ cảnh cũ: sau triage/bóc vỏ, sau mỗi cụm decompile (giải chuỗi, loader…), sau mỗi đợt giả lập, trước cổng phản biện, trước khi viết báo cáo. Ở mốc: ghi hết kết luận thành fact (ý còn nghi thì `status=hypothesis`), chép đoạn chứng minh vào `report/evidence/` kèm `#L`, chạy `flow.py checkpoint <CASE>`; OK thì đề nghị người dùng `/clear` (hoặc mở phiên mới). Không tách giữa chừng một bước chưa ghi.
- Sau khi ngữ cảnh bị nén hoặc `/clear`: chạy `flow.py resume <CASE>` trước khi làm tiếp. `facts.jsonl` là nguồn chân lý; fact không còn trong ngữ cảnh không có nghĩa là không tồn tại: tra `case.py show <CASE> --id ID` hoặc `case.py search <CASE> TỪ` trước khi kết luận.
- Trước khi đóng case phải qua cổng phản biện: `flow.py review` tối đa 2 lần; lần 2 vẫn FAIL thì dừng và báo người dùng (`work/review/STOP_REPORT.md`), không tự tạo `OVERRIDE`.

## Lệnh

```bash
python3 $SKILL/flow.py new <CASE> <mẫu|zip>...     # tạo case, chép mẫu (0400), triage
python3 $SKILL/flow.py status <CASE>               # checklist C0-C11 và gợi ý bước kế
python3 $SKILL/flow.py checkpoint <CASE>           # chốt mốc: mọi kết quả đã thành fact/evidence chưa (mã 1 = còn việc)
python3 $SKILL/flow.py resume <CASE>               # làm tiếp sau khi ngữ cảnh bị nén: việc kế, cổng, fact kết luận, giả thuyết
python3 $SKILL/case.py search <CASE> TỪ... [--src S] | show <CASE> --id ID   # tra lại fact
python3 $SKILL/flow.py dec <CASE> <FILE> <hàm|list:chuỗi>...   # decompile (rea, hoặc Ghidra)
python3 $SKILL/case.py add <CASE> id=... kind=... value=... src=S evidence=report/evidence/F[#Ln]
python3 $SKILL/flow.py review <CASE> [--llm] [--detach]   # cổng phản biện: lớp 1 script, lớp 2 LLM bất kỳ (mã 4 = chờ manual, 6 = đang chạy nền)
python3 $SKILL/flow.py next <CASE> [--accept 'C4=lý do;...']   # DONE khi checklist đủ và cổng đạt, không cần VM
python3 $SKILL/flow.py report <CASE> --final && python3 $SKILL/flow.py audit <CASE>
```

Giả lập shellcode/loader Windows x86: `$SKILL/winemu/README.md`.

## Vòng phản biện (agent tự làm, không chờ người xác nhận giữa chừng)

1. `flow.py review <CASE> --llm`. PASS thì sang `flow.py next`.
2. FAIL: với từng mục `fail`/`weak` in ra, làm đúng `redo` tại `where`, ghi fact mới có `supersedes`, cập nhật báo cáo.
3. Chạy lại `flow.py review <CASE> --llm` (lần 2). Vẫn FAIL thì dừng, báo người dùng nội dung `STOP_REPORT.md`.

Lớp 2 chạy trên mọi LLM (`REVIEW_LLM=auto`: claude, codex, gemini, copilot, cursor-agent, API chuẩn OpenAI như ChatGPT/DeepSeek, cuối cùng `manual`). Với claude, phản biện là một phiên agent có công cụ chỉ đọc trên bản sao tạm; với LLM khác, mô hình không có công cụ: script gửi hồ sơ và thực hiện các thao tác chỉ đọc nó xin. `flow.py review` trả mã 4 nghĩa là đang chờ manual: báo người dùng dán file prompt được in ra vào một cuộc chat mới và lưu câu trả lời. Lớp 2 có thể chạy hàng chục phút: luôn thêm `--detach` cho `review --llm` và `review-loop` (mọi agent: Claude Code, Codex, agent dùng ChatGPT/DeepSeek...), rồi gọi lại **đúng lệnh đó** để xem tiến độ cho tới khi mã khác 6; không tự bọc bằng `timeout`/`nohup` và không chạy review thứ hai cho cùng case (lệnh tự chặn). Mã 7 = tiến trình nền chết, gọi lại để chạy tiếp (phiên claude bị ngắt giữ kết luận từng fact, chỉ gửi phần còn lại). `flow.py review-loop <CASE>` tự động cả 3 bước khi backend là claude; backend khác thì dừng với mã 3 sau review lỗi để chính agent đang chạy làm bước 2.
