---
name: auto
description: Chạy rea-workflow tự động cho cả một thư mục mẫu mã độc và theo dõi thư mục để xử lý mẫu mới (flow.py watch) - mỗi mẫu một case, mỗi mốc một phiên claude -p riêng, tự review và báo cáo, dừng và báo người khi cần. Dùng khi người dùng muốn phân tích hàng loạt, theo dõi inbox mẫu, chạy nền/không người trực. Use for batch or continuous unattended malware analysis of a folder. Một mẫu có người theo dõi từng bước thì dùng rea-workflow:manual. Không bao giờ thực thi mẫu.
---

# rea-workflow:auto: chạy cả thư mục và theo dõi

`$SKILL` = `${CLAUDE_PLUGIN_ROOT}` (thư mục gốc của rea-workflow, hai cấp trên file này). Mục "Quy tắc bắt buộc" trong `$SKILL/SKILL.md` áp dụng cho mọi phiên do watcher mở và cho chính bạn.

`python3 $SKILL/flow.py watch INBOX [--once] [--model M] [--report [TÊN]]`, chạy từ **workspace** (case tạo trong thư mục hiện tại; workspace không được trùng INBOX, nên đặt ngoài INBOX):
- File trong INBOX và mọi thư mục con (bỏ file/thư mục ẩn, symlink, thư mục `Report_*`, workspace và thư mục case nếu nằm trong INBOX) đứng yên đủ `REA_WATCH_SETTLE` giây thì được nhận; file nén được nhận nguyên như một mẫu; trùng sha256 với case đã có thì bỏ qua. Case tên `<tên file>_<sha8>`. Mỗi vòng nhận tối đa `REA_WATCH_MAX_NEW` mẫu mới.
- Ghi chú thu mẫu không thành case: `SHA256SUMS`/`*.sha256`, file `.txt/.log/.md/.note(s)` mà tên bắt đầu bằng tên một file cùng thư mục hoặc nội dung nhắc sha256 của file cùng thư mục; file có nội dung giống script (shebang, `| sh`, `curl`, `base64 -d`…) vẫn là mẫu. Mỗi file bị bỏ qua được ghi một dòng (thời điểm, đường dẫn, lý do) vào `.watch_notes.tsv` trong workspace: xem file này nếu nghi một mẫu dạng text bị bỏ nhầm.
- `REA_WATCH_ALIAS_SUFFIX` (vd `_extracted`): có `X_extracted/` thì bỏ `X/` cùng cấp (bản giải nén của file nén gốc).
- `--report [TÊN]`: case DONE thì báo cáo được chép vào `Report_<TÊN>` cạnh INBOX (không TÊN: `Report_<tên INBOX>`; TÊN có `/` thì đúng đường dẫn đó), theo cấu trúc thư mục con của INBOX, mỗi mẫu một `<tên file mẫu>_data/` có báo cáo `.md`/`.html` và `README.txt`; mẫu nằm thẳng trong INBOX hoặc thư mục cấp một thì thêm thư mục theo tên mẫu bỏ đuôi nén; `X_extracted/a` ra `X/a`. Mẫu đã có `<mẫu>_data/README.txt` trong thư mục báo cáo thì không phân tích lại, nên xóa case sau khi xuất vẫn an toàn. Đường dẫn ghi ở khóa `published` trong `work/watch.json`. Không `--report` thì không xuất.
- Mỗi vòng, mỗi case: `flow.py next` rồi NEED_MORE/NEED_FIX/NEED_REPORT → một phiên `claude -p` làm một mốc; NEED_REVIEW → `review --llm --detach`; DONE → `report --final`; STOPPED → dừng, báo người.
- Dừng case và báo khi: đủ `REA_WATCH_MAX_SESSIONS` phiên, `REA_WATCH_STALL` phiên liên tiếp không đổi facts/báo cáo, hậu kiểm thấy lệnh nghi chạy mẫu hoặc mở `flow.py watch` lồng, review lớp 2 cần người (mã 4/7), `flow.py new` lỗi. Trạng thái và lý do dừng ở `<CASE>/work/watch.json`; transcript từng phiên ở `<CASE>/work/runs/watch/`.

Các bước:

1. **Môi trường.** Phiên tự động không có người duyệt; hậu kiểm chỉ phát hiện sau khi phiên chạy xong. Hỏi người dùng xác nhận đang ở VM/máy phân tích không có mạng ra ngoài trước khi chạy liên tục. Kiểm công cụ: `flow.py setup`, `flow.py doctor`; cần `claude` CLI trên PATH.
2. **Model.** Bash của agent không có terminal nên watcher không tự hỏi được: hỏi người dùng dùng model nào (alias lấy từ `claude --help`, mục `--model`), truyền `--model M`; không chọn thì bỏ cờ (mặc định của claude) hoặc đặt `REA_WATCH_MODEL` trong `~/.config/rea-flow/rea.env`. Trần và nhịp quét: các biến `REA_WATCH_*` trong `$SKILL/rea.env.example`.
3. **Chạy.** Một lượt để thử: `flow.py watch INBOX --once` (một vòng quét, mỗi case tối đa một bước; mỗi phiên có thể tới `REA_WATCH_TIMEOUT` giây). Chạy liên tục: dùng chế độ lệnh nền của agent, hoặc đề nghị người dùng chạy trong tmux/systemd; không tự bọc `nohup`. Muốn song song nhiều case thì mở thêm watcher cùng workspace (khóa theo case).
4. **Theo dõi.** Đọc dòng log `DỪNG, cần người` / `XONG` và `work/watch.json`, không đọc transcript thô. Case STOPPED: báo người dùng nội dung `<CASE>/work/review/STOP_REPORT.md`, không tự tạo `OVERRIDE`. Hậu kiểm báo nghi chạy mẫu: báo ngay, không chạy tiếp case đó.
5. **Làm tiếp một case đã dừng** sau khi người dùng xử lý xong: xóa khóa `stop` trong `work/watch.json`; dừng vì không đổi facts thì đặt `stall` về 0, vì đủ trần thì đặt lại `sessions`. Muốn tự làm tay một case thì chuyển sang `rea-workflow:manual` và giữ `stop` để watcher không đụng vào.

Mọi lệnh và tham số: `python3 $SKILL/flow.py help`.
