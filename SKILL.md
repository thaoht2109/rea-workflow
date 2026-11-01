---
name: rea-flow
description: Quy trình dịch ngược mã độc có kiểm chứng (PE, ELF, Go, .NET, shellcode, installer, script) - triage tĩnh, bóc vỏ, decompile, giả lập CPU, ghi fact có nguồn, cổng phản biện 2 lần, báo cáo tiếng Việt. Dùng khi được yêu cầu phân tích, dịch ngược hoặc viết báo cáo về một mẫu mã độc. Không bao giờ thực thi mẫu.
---

# rea-flow: dịch ngược mã độc theo fact có kiểm chứng

Mọi đường dẫn dưới đây tính từ thư mục workspace (thư mục chứa `tools/`). Quy trình đầy đủ: `tools/FLOW.md`.

**Lần đầu (cài qua `npx skills add`):** nếu workspace chưa có `tools/flow.py`, chạy `python3 <thư mục chứa SKILL.md này>/install.py --workspace .` để tạo `tools/` trỏ về thư mục skill, file hướng dẫn cho agent và `tools/rea.env`; sửa `rea.env` theo kết quả `doctor`.

<!-- rules:begin -->
## Quy tắc bắt buộc

- **Không bao giờ thực thi mẫu.** Không chạy qua wine, không dùng `rea capture-*` hay `debug-with-gdb` trên mẫu. Không chạm C2 hay hạ tầng phát tán, không tra mẫu trên dịch vụ ngoài. Chỉ được phân tích tĩnh và giả lập CPU (`tools/winemu`).
- Mọi case mới theo `tools/FLOW.md`, bắt đầu bằng `python3 tools/flow.py new <CASE> <mẫu>`.
- Mỗi kết luận là một fact trong `<CASE>/facts.jsonl` (ghi qua `python3 tools/case.py add`), có nguồn `src=S|E|V` (tĩnh / giả lập / VM) và evidence nằm trong `<CASE>/report/evidence/`. Sửa fact bằng fact mới có `supersedes=<id cũ>`, không sửa hay xóa dòng cũ.
- Báo cáo viết tiếng Việt, có bảng đính chính và mục hạn chế/OPSEC. Mỗi mẫu hoặc chiến dịch có báo cáo riêng, không quy kết chéo giữa các case.
- Đọc tóm tắt, không đọc log thô (dùng `grep`, `sed -n`, `head`).
- Trước khi đóng case phải qua cổng phản biện: `flow.py review` tối đa 2 lần; lần 2 vẫn FAIL thì dừng và báo người dùng (`work/review/STOP_REPORT.md`), không tự tạo `OVERRIDE`.
- Cấu hình theo máy nằm ở `tools/rea.env`; không viết đường dẫn cứng vào code. Kiểm bằng `python3 tools/flow.py doctor`.
<!-- rules:end -->

## Lệnh

```bash
python3 tools/flow.py doctor                     # kiểm môi trường (lần đầu trên máy mới)
python3 tools/flow.py new <CASE> <mẫu|zip>...     # tạo case, chép mẫu (0400), triage
python3 tools/flow.py status <CASE>               # checklist C0-C11 và gợi ý bước kế
python3 tools/flow.py dec <CASE> <FILE> <hàm|list:chuỗi>...   # decompile (rea, hoặc Ghidra)
python3 tools/case.py add <CASE> id=... kind=... value=... src=S evidence=report/evidence/F[#Ln]
python3 tools/flow.py review <CASE> [--llm]       # cổng phản biện: lớp 1 script, lớp 2 phiên LLM mới
python3 tools/flow.py next <CASE> [--accept 'C4=lý do;...']   # DONE khi checklist đủ và cổng đạt, không cần VM
python3 tools/flow.py report <CASE> --final && python3 tools/flow.py audit <CASE>
```

Giả lập shellcode/loader Windows x86: `tools/winemu/README.md`.

## Vòng phản biện (agent tự làm, không chờ người xác nhận giữa chừng)

1. `flow.py review <CASE> --llm`. PASS thì sang `flow.py next`.
2. FAIL: với từng mục `fail`/`weak` in ra, làm đúng `redo` tại `where`, ghi fact mới có `supersedes`, cập nhật báo cáo.
3. Chạy lại `flow.py review <CASE> --llm` (lần 2). Vẫn FAIL thì dừng, báo người dùng nội dung `STOP_REPORT.md`.

Với Claude Code, `flow.py review-loop <CASE>` làm cả 3 bước tự động. Với agent khác, đặt `REVIEW_LLM_CMD` trong `tools/rea.env` (lệnh LLM không tương tác, đọc prompt từ stdin, in JSON ra stdout) để lớp 2 chạy bằng model đó; khi đó mức cô lập ghi là `partial`.
