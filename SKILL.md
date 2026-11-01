---
name: rea-flow
description: Quy trình dịch ngược mã độc có kiểm chứng (PE, ELF, Go, .NET, shellcode, installer, script) - triage tĩnh, bóc vỏ, decompile, giả lập CPU, ghi fact có nguồn, cổng phản biện 2 lần, báo cáo tiếng Việt. Dùng khi được yêu cầu phân tích, dịch ngược hoặc viết báo cáo về một mẫu mã độc. Không bao giờ thực thi mẫu.
---

# rea-flow: dịch ngược mã độc theo fact có kiểm chứng

`$SKILL` dưới đây là thư mục chứa file này. Chạy mọi lệnh từ **workspace**: thư mục chứa các case (thường là thư mục hiện tại của người dùng). Không cần bước cài đặt nào; nếu thiếu công cụ, chạy `python3 $SKILL/flow.py doctor` và làm theo gợi ý. Quy trình đầy đủ: `$SKILL/FLOW.md`.

## Quy tắc bắt buộc

- **Không bao giờ thực thi mẫu.** Không chạy qua wine/qemu, không chạy script mẫu, không dùng `rea capture-*` hay `debug-with-gdb` trên mẫu. Không chạm C2 hay hạ tầng phát tán, không tra mẫu trên dịch vụ ngoài. Chỉ được phân tích tĩnh và giả lập CPU (`$SKILL/winemu`).
- Mỗi case bắt đầu bằng `flow.py new`. Mỗi kết luận là một fact trong `<CASE>/facts.jsonl` (ghi qua `case.py add`), có nguồn `src=S|E|V` (tĩnh / giả lập / VM) và evidence nằm trong `<CASE>/report/evidence/`. Sửa fact bằng fact mới có `supersedes=<id cũ>`, không sửa hay xóa dòng cũ.
- Báo cáo viết tiếng Việt, có bảng đính chính và mục hạn chế/OPSEC. Mỗi mẫu hoặc chiến dịch có báo cáo riêng, không quy kết chéo giữa các case.
- Đọc tóm tắt, không đọc log thô (dùng `grep`, `sed -n`, `head`).
- Trước khi đóng case phải qua cổng phản biện: `flow.py review` tối đa 2 lần; lần 2 vẫn FAIL thì dừng và báo người dùng (`work/review/STOP_REPORT.md`), không tự tạo `OVERRIDE`.

## Lệnh

```bash
python3 $SKILL/flow.py new <CASE> <mẫu|zip>...     # tạo case, chép mẫu (0400), triage
python3 $SKILL/flow.py status <CASE>               # checklist C0-C11 và gợi ý bước kế
python3 $SKILL/flow.py dec <CASE> <FILE> <hàm|list:chuỗi>...   # decompile (rea, hoặc Ghidra)
python3 $SKILL/case.py add <CASE> id=... kind=... value=... src=S evidence=report/evidence/F[#Ln]
python3 $SKILL/flow.py review <CASE> [--llm]       # cổng phản biện: lớp 1 script, lớp 2 phiên LLM mới
python3 $SKILL/flow.py next <CASE> [--accept 'C4=lý do;...']   # DONE khi checklist đủ và cổng đạt, không cần VM
python3 $SKILL/flow.py report <CASE> --final && python3 $SKILL/flow.py audit <CASE>
```

Giả lập shellcode/loader Windows x86: `$SKILL/winemu/README.md`.

## Vòng phản biện (agent tự làm, không chờ người xác nhận giữa chừng)

1. `flow.py review <CASE> --llm`. PASS thì sang `flow.py next`.
2. FAIL: với từng mục `fail`/`weak` in ra, làm đúng `redo` tại `where`, ghi fact mới có `supersedes`, cập nhật báo cáo.
3. Chạy lại `flow.py review <CASE> --llm` (lần 2). Vẫn FAIL thì dừng, báo người dùng nội dung `STOP_REPORT.md`.

Với Claude Code, `flow.py review-loop <CASE>` làm cả 3 bước tự động. Với agent khác, đặt `REVIEW_LLM_CMD` (lệnh LLM không tương tác, prompt qua stdin, JSON ra stdout) để lớp 2 chạy bằng model đó; mức cô lập ghi là `partial`.
