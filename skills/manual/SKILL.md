---
name: manual
description: Phân tích dịch ngược MỘT mẫu mã độc (hoặc một file nén chứa mẫu) theo rea-workflow, có người theo dõi từng bước - triage tĩnh, bóc vỏ, decompile, giả lập CPU, ghi fact có nguồn, cổng phản biện 2 lần, báo cáo tiếng Việt. Dùng khi người dùng đưa một file/case cụ thể để phân tích, dịch ngược, giải chuỗi/config, trích IOC hay viết báo cáo. Use to reverse engineer or write a malware report on a single sample. Cả thư mục hoặc chạy liên tục thì dùng rea-workflow:auto. Không bao giờ thực thi mẫu.
---

# rea-workflow:manual: phân tích từng mẫu

`$SKILL` = `${CLAUDE_PLUGIN_ROOT}` (thư mục gốc của rea-workflow, hai cấp trên file này).

1. **Đọc `$SKILL/SKILL.md` trước khi làm gì khác** và làm đúng theo đó: mục "Quy tắc bắt buộc" (không bao giờ thực thi mẫu, mỗi kết luận là một fact có evidence, cổng phản biện tối đa 2 lần) và mục "Cách làm việc" (`flow.py new` → `next` → … → `report --final`). Trong file đó `$SKILL` cũng là thư mục trên.
2. Một mẫu hoặc một chiến dịch là một case, một báo cáo. Nhiều file rời không liên quan thì mỗi file một case; người dùng muốn xử lý cả thư mục không cần theo dõi từng bước thì đề nghị `rea-workflow:auto`.
3. Phiên dài: tách theo mốc bằng `flow.py checkpoint <CASE>` và làm tiếp bằng `flow.py resume <CASE>` như SKILL.md mô tả.

Case đang được `flow.py watch` quản lý (có `<CASE>/work/watch.json` chưa có khóa `stop`) thì không sửa song song: hỏi người dùng dừng watcher hoặc đặt `stop` cho case đó trước.
