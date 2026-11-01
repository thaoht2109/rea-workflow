# Flow phân tích dịch ngược cho mọi mẫu (rea-flow)

Áp dụng cho mọi file cần dịch ngược: PE, ELF (mọi kiến trúc), Go, .NET, shellcode, installer (NSIS…), file nén, script, Office/PDF.
File này là quy trình thao tác; quy tắc bắt buộc tóm tắt ở `SKILL.md`.

**Ba nguyên tắc:**

1. **Script làm việc lặp, LLM chỉ đọc tóm tắt và ra quyết định.** Không `cat` log, dump hay disassembly. Mọi lệnh trong flow đều in kết quả có giới hạn; dữ liệu đầy đủ được ghi vào `work/`.
2. **Mỗi kết luận là một fact** trong `<case>/facts.jsonl`. Fact phải có nguồn (S tĩnh / E giả lập / V VM) và trỏ tới file trong `report/evidence/`. Báo cáo được sinh từ fact.
3. **Chỉ leo lên tầng đắt hơn khi checklist còn thiếu** (`flow.py status`). Tầng rẻ nhất là triage tĩnh; tầng đắt nhất là VM bên ngoài.

## 0. OPSEC: kiểm tra trước mỗi case

- **Không bao giờ thực thi mẫu.** Cụ thể:
  - không chạy file mẫu trực tiếp, không chạy qua `wine`, `qemu-*`, `bash`/`python` (với script);
  - không dùng các lệnh `rea` có chạy target: `capture-process`, `debug-with-gdb`, `capture-*-scenario`, `capture-adb-*`.
- Được phép:
  - đọc byte, `pefile`, `readelf`, `go version -m`, `7z x`, `upx -d` (giải nén tĩnh);
  - `rea` decompile/inspect, Ghidra headless;
  - giả lập CPU bằng `winemu`.
- **Không chạm C2 hay hạ tầng phát tán**, không tra cứu mẫu trên dịch vụ ngoài. Muốn tải payload thì phải hỏi người dùng trước.
- Mẫu đặt ở `work/sample/` với quyền `0400`. Không đưa mẫu và thư mục case lên git.

## 1. Môi trường

Trong tài liệu này `$SKILL` là thư mục chứa `SKILL.md` (ví dụ `~/.claude/skills/rea-flow`). Mọi lệnh chạy từ **workspace**: thư mục chứa các case (thư mục hiện tại, hoặc `$REA_WORKSPACE`).

```bash
cd <workspace>
python3 $SKILL/flow.py doctor     # kiểm công cụ và cấu hình; rc=1 nếu thiếu mục bắt buộc
```

- Cài skill: `npx github:thaoht2109/rea-flow [-g]` (xem `README.md`): cài skill và chép "Quy tắc bắt buộc" vào `CLAUDE.md`/`AGENTS.md` đúng phạm vi (toàn máy hoặc chỉ project). Cài bằng `npx skills add` thì bước chép quy tắc là `python3 $SKILL/flow.py rules`.
- Cấu hình theo máy là **tùy chọn**: `~/.config/rea-flow/rea.env` (mẫu `$SKILL/rea.env.example`), đọc qua `reacfg.py`. Biến môi trường cùng tên ghi đè file. Không sửa đường dẫn trong code.

| Biến | Mặc định | Dùng cho |
|---|---|---|
| `REA_TMP` | `.tmp` (trong workspace) | `TMPDIR` khi gọi rea/Ghidra. `/tmp` dạng tmpfs nhỏ làm Ghidra chết khi khởi động |
| `REVIEW_WS_DIR` | `/var/tmp` | thư mục làm việc của phản biện lớp 2; phải ghi được và nằm ngoài workspace và mọi thư mục có file hướng dẫn agent (`CLAUDE.md`, `AGENTS.md`…) |
| `GHIDRA_INSTALL_DIR`, `JAVA_HOME` | trống | Ghidra headless khi rea không hỗ trợ kiến trúc (tùy chọn) |
| `REA_PYLIB` | `$SKILL/pylib` nếu có, không thì `~/.local/share/rea-flow/pylib` | unicorn cho winemu (tự thêm vào `sys.path`, không cần `PYTHONPATH`) |
| `WINE_DLL_DIR` | `/usr/lib/x86_64-linux-gnu/wine` | winemu đọc tên export DLL builtin (không chạy wine) |
| `REA_BIN`, `UPX_BIN`, `SEVENZ_BIN`, `CLAUDE_BIN` | `rea`, `upx`, `7z`, `claude` | công cụ ngoài; tên trên `PATH` hoặc đường dẫn tuyệt đối |

- Lớp 2 dùng backend LLM có trên máy (`REVIEW_LLM`, mặc định `auto`: claude > codex > gemini > copilot > cursor > api), dùng chung tài khoản đã đăng nhập của CLI đó.
- Nếu sandbox của agent coi workspace là chỉ đọc, các lệnh `flow.py` cần ghi file phải được cấp quyền ghi (với Claude Code: `/sandbox`).

## 2. Các bước

| Bước | Lệnh | Đọc gì | Ghi fact |
|---|---|---|---|
| 1. Tạo case | `python3 $SKILL/flow.py new <CASE> <mẫu hoặc zip>...` | tóm tắt triage, mỗi file ≤ 60 dòng | tự động: `hash`, `filetype`, `container`, `entry`; IOC ứng viên lấy từ strings ghi dạng `hypothesis` |
| 2. Định tuyến | `python3 $SKILL/flow.py status <CASE>` | checklist C1–C11 và dòng `next:` của từng file | |
| 3. Bóc vỏ (T1) | tự động: zip/7z/rar (mật khẩu `''`/`infected`/`malware`), UPX (`upx -d` ra bản sao `.unupx`), NSIS (header, giải nén file con, giải "sàng byte" để lộ `System::Call`) | `nsis_disasm.txt`, `nsis_syscalls.txt` | dạng khác thì tự viết script vào `work/` và ghi fact `container` |
| 4. Tĩnh có mục tiêu (T2) | `python3 $SKILL/flow.py dec <CASE> <FILE> <hàm\|địa chỉ\|list:chuỗi>...` | mã giả C, in tối đa 80 dòng mỗi hàm | ghi fact cho từng kết luận (§3) |
| 5. Giả lập (T3), chỉ cho shellcode/loader Windows x86‑32 | `winemu.py ...` rồi `summarize.py OUT/events.jsonl --facts <CASE>` (xem `winemu/README.md`) | tóm tắt vài chục dòng | tự động: `url`, `ua`, `str_key`, `inject`, `exit_reason`… với nguồn E |
| 6. Payload offline (T4) | giải mã bằng khóa và định dạng lấy được ở bước 4/5, rồi `flow.py triage <CASE> <payload>` | quay lại bước 2 | `payload_fmt`, `payload_key`, `payload_hash` |
| 7. VM ngoài (T5) | chỉ khi cần hành vi của payload cuối; người dùng quyết định | báo cáo sandbox | fact nguồn V |
| 7b. Phản biện facts | `flow.py review <CASE> --llm` (tối đa 2 lần; xem dưới) | danh sách fact fail kèm `where`/`redo` | ghi vào `work/review/` |
| 7c. Dừng sớm | `flow.py next <CASE> [--accept C4=lý do]` | `DONE` / `NEED_MORE` / `NEED_REVIEW` | |
| 8. Đóng case | `flow.py report <CASE> --final` và `flow.py audit <CASE>`; viết phần nhận định trong `report/README.md` | | |

**Chọn hàm cho bước 4.** Đi theo thứ tự này, dừng ngay khi đủ trả lời mục checklist còn thiếu:

1. Các export như `pam_sm_*`, `DllMain`, `ServiceMain`. Với Go: `main.main` và các hàm `main.*` (lấy danh sách bằng `list:main.`).
2. Hàm gọi tới import nhạy cảm:
   - mạng: `socket`/`connect`, WinINet/WinHTTP;
   - thực thi: `exec*`/`fork`/`CreateProcess`;
   - tiêm mã: `WriteProcessMemory`, `ptrace`;
   - crypto: `crypt*`;
   - registry, file hệ thống.
3. Hàm tham chiếu tới IOC ứng viên hoặc tới chuỗi rác/mã hóa (thường là hàm giải mã).
4. Entry point, nếu file bị pack hoặc có entropy cao, để tìm stub giải mã.

**Bộ máy decompile.** `rea` (Ghidra) hỗ trợ x86, x86_64, ARM, ARM64, mất khoảng 30 giây mỗi lần gọi và chạy song song 3 hàm. Với kiến trúc `rea` báo `capability_unavailable` (MIPS, PPC…), `flow.py` tự chuyển sang Ghidra headless (`static/ghidra/ExportDecomp.java`). Project Ghidra được giữ ở `work/ghidra/`: lần đầu phải phân tích cả file nên chậm (Go MIPS cỡ 5 MB mất khoảng 5 phút), các lần sau chỉ khoảng 10 giây.

Với Go bị strip, Ghidra không tự khôi phục tên hàm trên MIPS. Khi đó `flow.py` lấy tên từ `.gopclntab` bằng `static/gopclntab.py` và đặt vào project qua `ApplyNames.java`. Muốn tra nhanh địa chỉ hàm mà không cần Ghidra: `python3 -I $SKILL/static/gopclntab.py FILE main.`.

## 3. Ghi fact

```bash
python3 $SKILL/case.py add <CASE> id=<duy-nhất> kind=<loại> value='<giá trị>' src=S|E|V evidence=report/evidence/<file>[#Ln] \
        [status=active|hypothesis|retracted] [verified_by=S,E] [supersedes=<id cũ>] [note='...']
```

- **Evidence:** trước khi ghi fact, chép đoạn bằng chứng (mã giả, log rút gọn, file đã giải mã) từ `work/` sang `report/evidence/`. `case.py` từ chối fact trỏ ra ngoài thư mục này hoặc trỏ tới file không tồn tại.
- **`kind`:** xem biến `KINDS` trong `case.py`.
- **Mục không áp dụng:** ghi fact có giá trị bắt đầu bằng `n/a:` kèm lý do và bằng chứng, ví dụ `kind=payload_fmt value='n/a: không tải payload, mọi hàm mạng đã duyệt'`.
- **Độ phủ (C11)** đạt `ok` theo một trong hai đường:
  - Giả lập chạy tới thoát tự nhiên (E).
  - Có fact `kind=coverage` (S), liệt kê đã duyệt mọi xref của các import nhạy cảm, với evidence là danh sách hàm đã decompile.
- **Kết luận chưa chắc:** để `status=hypothesis`. Kết luận sai sau này thì không xóa: ghi fact mới có `supersedes` trỏ về fact cũ. Bảng đính chính được sinh tự động từ đó.

## 3b. Cổng phản biện và điểm dừng sớm (`review.py`)

- **Lớp 1 (máy):** evidence có thật và đúng dòng; hash tính lại; giá trị IOC phải có trong evidence; nguồn S/E/V khớp loại evidence; `api_unused` bị suy thành persistence.
- **Lớp 2 (`--llm`):** một phiên LLM mới, tách ngữ cảnh (backend `REVIEW_LLM`: claude, codex, gemini, copilot, cursor, api chuẩn OpenAI, hoặc lệnh tự khai), chạy trong `$REVIEW_WS_DIR/<case>-rK-*` (mặc định `/var/tmp`, ngoài cây project nên không nạp file hướng dẫn và memory của project), chỉ đọc `facts.jsonl`, evidence, mẫu, script. Mỗi fact `fail` bắt buộc có `where` và `redo`. Kết quả cô lập được ghi vào `review.json` (`isolation`); không hợp lệ thì review tính là FAIL. Tốn khoảng 10 phút mỗi lần. Mức cô lập: `full` (claude, kiểm từ sự kiện khởi động), `partial` (CLI khác: cwd + canary), `stateless` (api: request độc lập, dữ liệu nhúng trong prompt).
- **Tối đa 2 lần review.** Lần 1 FAIL thì sửa đúng các fact bị chỉ ra (fact mới có `supersedes`). Lần 2 FAIL thì `STOPPED`: in thông báo, sinh `work/review/STOP_REPORT.md`, chặn `report --final`. Chỉ người dùng mở lại (sửa tay, hoặc `work/review/OVERRIDE` có `facts_sha256=<hash>`).
- **`facts.jsonl` đổi thì review hết hiệu lực** (mục C0 về `missing`). Review lặp lại với facts không đổi thì không tính thêm lần.
- **`flow.py next`:** checklist đủ (hoặc `--accept Cx=lý do` ghi vào `work/accepted.json` để đưa vào mục hạn chế) và phản biện đạt thì in `DONE`: báo cáo và đóng case, **không cần VM**. VM (T5) chỉ cân nhắc khi mục còn thiếu mà T2/T3 không lấy được.

## 4. Định tuyến theo loại file

Dòng `next:` của triage sinh ra từ bảng này.

| Triage thấy | Bước tiếp |
|---|---|
| zip, 7z, rar, gzip | `flow.py new` giải nén rồi triage từng file |
| UPX | tự `upx -d`. Nếu thất bại (header UPX bị sửa) thì T2 tìm stub giải nén |
| NSIS có shellcode | T3: lệnh `winemu` đề xuất sẵn `--blob`, `--blob-off`, `--size` |
| PE .NET | T2: `rea inspect-managed-members` (chuỗi `ldstr`, PInvoke), rồi decompile lớp/hàm đáng ngờ |
| PE native | T2 decompile export/hàm có import nhạy cảm. Nếu entropy cao thì tìm stub giải mã, rồi chuyển T3 nếu là x86‑32 |
| ELF (mọi kiến trúc) | T2 decompile export/`main`. Không có T3 cho ELF trên server (thiếu qemu-user), nên phần giải mã phải tái hiện tĩnh bằng Python |
| Go (PE/ELF) | `rea inspect-go-binary` (nếu kiến trúc được hỗ trợ), `flow.py dec ... list:main.` rồi `main.main` |
| script | khử làm rối tĩnh bằng Python (base64, eval, char-code). **Không chạy script** |
| OLE, PDF | `rea inspect-artifact`; macro/JS nhúng phải tách thủ công (chưa cài olevba/pdf-parser) |
| DEX/APK | `rea inspect-android-package` / `inspect-android-method` |

## 5. Kỷ luật token

- Mỗi file chỉ đọc tóm tắt triage, mã giả của **những hàm đã chọn** và `status`. Không đọc toàn bộ danh sách hàm, strings hay disassembly.
- Tra cứu có mục tiêu bằng `grep -m`, `sed -n 'a,bp'`, `jq`. Không dùng `cat` trên file lớn.
- Cùng một lỗi công cụ sửa 3 lần không được thì dừng, ghi vào mục hạn chế và đổi hướng.
- Sau khi hội thoại bị nén: đọc lại `flow.py status` và `case.py show`. Không đọc lại log.

## 6. Kiểm tra công cụ (sau khi sửa)

```bash
python3 $SKILL/case.py --selftest
python3 $SKILL/review.py --selftest              # cổng phản biện: bộ fact cố tình sai, 2 lần review, STOPPED, sửa rồi PASS
python3 $SKILL/flow.py doctor
```

Hồi quy trên mẫu thật (triage/định tuyến, lõi winemu) phụ thuộc mẫu có trên từng máy nên không nằm trong skill: giữ chúng ngoài thư mục skill (ví dụ `<workspace>/local/tests/`) và chạy lại sau mỗi lần sửa lõi.

## 7. Giới hạn hiện tại

- **T3 chỉ có cho Windows x86‑32.** ELF, x64 và .NET chỉ phân tích tĩnh được.
- **`rea` không hỗ trợ MIPS/PPC,** nên phải dùng Ghidra headless. Lần phân tích đầu một file Go MIPS cỡ vài MB mất vài phút.
- **IOC ứng viên từ strings là heuristic.** Go nối liền các chuỗi nên URL có thể bị dính ký tự thừa. Mọi IOC ứng viên chỉ là `hypothesis` cho tới khi tìm thấy chỗ mã dùng nó.
- **Phần nhận định trong README vẫn do người phân tích viết.** Script chỉ sinh bảng (IOC, nguồn, đính chính, evidence).
