# rea-flow

**Skill dịch ngược mã độc có kiểm chứng cho AI coding agent.**

Repo: <https://github.com/thaoht2109/rea-flow> (private)

rea-flow biến một agent (Claude Code, Codex, Cursor, GitHub Copilot, Gemini CLI…) thành người phân tích mã độc làm việc có quy trình. Mỗi kết luận là một *fact* có nguồn và bằng chứng. Mọi fact phải qua cổng phản biện độc lập trước khi vào báo cáo cuối. Mẫu **không bao giờ được thực thi**: chỉ phân tích tĩnh và giả lập CPU.

| | |
|---|---|
| Đối tượng | PE, ELF (mọi kiến trúc), Go, .NET, shellcode, installer NSIS, file nén, script, Office/PDF, APK |
| Đầu ra | `facts.jsonl` (fact có nguồn S/E/V) + báo cáo tiếng Việt có bảng IOC, bảng đính chính, mục hạn chế/OPSEC |
| Yêu cầu | Linux, Python ≥ 3.9, `7z`, `pefile`. Tùy chọn: `rea`, Ghidra 12 + JDK 21, `upx`, unicorn, capstone |
| Agent hỗ trợ | Mọi agent hỗ trợ chuẩn [Agent Skills](https://agentskills.io) (`SKILL.md`): Claude Code, Codex, Cursor, GitHub Copilot, Gemini CLI, OpenCode… |

---

## Vì sao cần rea-flow

Khi để LLM tự dịch ngược, ba lỗi lặp lại liên tục:

1. **Kết luận không có bằng chứng.** Một IOC "nhìn giống C2" được ghi thẳng vào báo cáo.
2. **Lỗi lan truyền.** Một fact sai ở bước đầu (khóa giải mã, tham số persistence) làm sai mọi bước sau.
3. **Tốn token vào việc lặp.** Agent đọc nguyên log, dump, disassembly thay vì tóm tắt.

rea-flow xử lý từng lỗi bằng cơ chế, không bằng lời nhắc:

- **Fact có nguồn:** `case.py` từ chối fact không có nguồn `S|E|V` hoặc có evidence nằm ngoài `report/evidence/`.
- **Cổng phản biện hai lớp:** script kiểm máy móc, sau đó một phiên LLM *mới, tách ngữ cảnh* phản biện như một chuyên gia dịch ngược. Tối đa 2 lần; lần 2 vẫn FAIL thì dừng và sinh báo cáo lỗi.
- **Script làm việc lặp, LLM ra quyết định:** mọi lệnh in kết quả có giới hạn, dữ liệu đầy đủ ghi vào `work/`.

## Cách hoạt động

```
mẫu ─► T0 triage tĩnh ─► T1 bóc vỏ ─► T2 decompile có mục tiêu ─► T3 giả lập CPU ─► T4 payload offline
            │                                                                           │
            └──────────────── facts.jsonl (S / E / V) + report/evidence/ ◄──────────────┘
                                          │
                           cổng phản biện (≤ 2 lần) ──FAIL──► STOP_REPORT.md
                                          │PASS
                              checklist C0–C11 đủ? ──thiếu──► leo tầng kế tiếp
                                          │đủ
                                 báo cáo cuối, đóng case (không cần VM)
```

**Nguyên tắc leo tầng:** chỉ chuyển sang tầng đắt hơn khi checklist còn thiếu. Nhiều case đóng ngay ở T2/T3 mà không cần sandbox VM.

| Tầng | Công cụ | Nguồn fact |
|---|---|---|
| T0 Triage | `static/triage.py`: loại file, hash, entropy, import/export, IOC ứng viên, gợi ý bước tiếp | S |
| T1 Bóc vỏ | zip/7z/rar, `upx -d`, NSIS (header, file con, giải "sàng byte" lộ `System::Call`) | S |
| T2 Tĩnh có mục tiêu | `flow.py dec`: `rea`, tự chuyển sang Ghidra headless cho MIPS/PPC; khôi phục tên hàm Go từ `.gopclntab` | S |
| T3 Giả lập | `winemu`: Windows x86-32 giả trên Unicorn (PEB/TEB, SEH/VEH, DLL giả, mạng chỉ ghi lại), plugin theo họ | E |
| T4 Payload | giải mã offline bằng khóa/định dạng từ T2/T3, triage lại | S/E |
| T5 VM ngoài | chỉ khi người dùng quyết định | V |

**Checklist đóng case:** C0 Phản biện · C1 Nhận dạng · C2 Delivery và điểm vào · C3 Chống phân tích · C4 Giải mã chuỗi/config · C5 IOC mạng · C6 Tiêm mã · C7 Persistence · C8 Payload: định dạng và khóa · C9 Payload cuối · C10 Họ mã độc · C11 Độ phủ. Mục không đạt được có thể chấp nhận kèm lý do (`--accept`), lý do được ghi vào mục hạn chế của báo cáo.

## Cài đặt

```bash
npx skills add thaoht2109/rea-flow
```

Một lệnh, như mọi skill khác trên [skills CLI](https://github.com/vercel-labs/skills): CLI hỏi cài cho agent nào (Claude Code, Codex, Cursor, Copilot, Gemini CLI…) và cho project hiện tại hay toàn máy (`-g`). Không có bước dựng workspace hay sinh file hướng dẫn: agent tự nạp skill khi được giao việc phân tích mã độc.

```bash
# không hỏi: cài toàn máy cho một số agent cụ thể
DISABLE_TELEMETRY=1 npx skills add thaoht2109/rea-flow -g -a claude-code -a codex -y
npx skills update rea-flow -g        # cập nhật
npx skills remove rea-flow -g        # gỡ
```

- Repo đang private: máy cài cần quyền đọc repo (`gh auth login`, git credential hoặc SSH key).
- Không dùng Node: `git clone https://github.com/thaoht2109/rea-flow.git ~/.claude/skills/rea-flow` (thay bằng thư mục skill của agent khác, ví dụ `~/.agents/skills/rea-flow`).
- Lần đầu trên máy mới, kiểm công cụ: `python3 <thư mục skill>/flow.py doctor`.

### Quy tắc luôn bật (tùy chọn)

Skill chỉ được nạp khi agent nhận việc phân tích mã độc. Muốn quy tắc an toàn ("không bao giờ thực thi mẫu"…) **luôn** có trong ngữ cảnh, chép mục "Quy tắc bắt buộc" của `SKILL.md` vào file hướng dẫn của agent:

```bash
python3 <thư mục skill>/flow.py rules            # phạm vi tự theo cách cài skill
```

| Cài skill | File được ghi |
|---|---|
| toàn máy (`-g`, skill ở `~/.agents/skills/…`) | `~/.claude/CLAUDE.md`, `~/.codex/AGENTS.md`, `~/.gemini/GEMINI.md`, chỉ với agent đã có trên máy |
| theo project (skill ở `<project>/.agents/skills/…`) | `<project>/AGENTS.md`, `<project>/CLAUDE.md` (và `GEMINI.md` nếu project đã có) |

Ép phạm vi bằng `--global` hoặc `--project [DIR]`; kiểm bằng `--check`; gỡ bằng `--remove` (trước `npx skills remove`). Quy tắc nằm giữa cặp marker `rea-flow:rules`, nội dung khác trong file giữ nguyên; chạy lại sau `npx skills update` để cập nhật. Agent cũng tự chạy bước này ở lần đầu dùng skill.

## Cấu hình (tùy chọn)

Mặc định đủ cho máy có công cụ trên `PATH`. Chỉ khi cần đổi, tạo `~/.config/rea-flow/rea.env` từ `rea.env.example` (file nằm ngoài thư mục skill nên `npx skills update` không làm mất cấu hình). Biến môi trường cùng tên ghi đè file. Workspace, nơi chứa các case, là thư mục hiện tại (hoặc `REA_WORKSPACE`).

| Biến | Mặc định | Ý nghĩa |
|---|---|---|
| `REA_TMP` | `.tmp` (trong workspace) | `TMPDIR` cho rea/Ghidra; đặt trên đĩa thật nếu `/tmp` là tmpfs nhỏ |
| `REVIEW_WS_DIR` | `/var/tmp` | thư mục làm việc của phản biện lớp 2; phải nằm ngoài mọi thư mục có file hướng dẫn agent |
| `GHIDRA_INSTALL_DIR`, `JAVA_HOME` | trống | Ghidra headless cho kiến trúc `rea` không hỗ trợ |
| `REA_PYLIB` | `<skill>/pylib` | thư mục chứa unicorn cho winemu |
| `WINE_DLL_DIR` | `/usr/lib/x86_64-linux-gnu/wine` | chỉ để lấy tên export DLL; wine không bao giờ được chạy |
| `REA_BIN`, `UPX_BIN`, `SEVENZ_BIN`, `CLAUDE_BIN` | `rea`, `upx`, `7z`, `claude` | công cụ ngoài |
| `REVIEW_LLM_CMD` | trống | lớp 2 bằng LLM khác Claude: lệnh không tương tác, prompt qua stdin, JSON ra stdout |
| `ANALYST_LLM_CMD` | trống | phiên tự sửa fact cho `review-loop` khi dùng LLM khác |

Thiếu unicorn: `python3 -m pip install unicorn==2.1.4` (hoặc `--target <skill>/pylib`).

## Sử dụng

Thông thường chỉ cần giao việc cho agent ("phân tích mẫu trong thư mục X"); skill hướng dẫn agent đi đúng quy trình. Các lệnh bên dưới là những gì agent chạy (`$SKILL` là thư mục skill), cũng dùng được trực tiếp từ workspace:

```bash
python3 $SKILL/flow.py new  CASE mẫu.exe [file2 ...]   # tạo case, chép mẫu (quyền 0400), giải nén, triage
python3 $SKILL/flow.py status CASE                      # checklist C0–C11 và gợi ý bước kế
python3 $SKILL/flow.py dec  CASE FILE hàm|0xaddr|list:chuỗi ...
python3 $SKILL/case.py add CASE id=c2.main kind=c2 value='host:443' src=E evidence=report/evidence/emu.txt#L12
python3 $SKILL/flow.py review CASE --llm                # cổng phản biện (lần 1, rồi lần 2 sau khi sửa)
python3 $SKILL/flow.py review-loop CASE                 # review → tự sửa fact lỗi → review lần 2 (Claude Code)
python3 $SKILL/flow.py next CASE --accept 'C10=lý do;C11=lý do'   # DONE / NEED_MORE / NEED_REVIEW
python3 $SKILL/flow.py report CASE --final && python3 $SKILL/flow.py audit CASE
```

Cấu trúc một case:

```
CASE/
├── facts.jsonl            # nguồn sự thật duy nhất; chỉ nối thêm, sửa bằng fact mới có supersedes
├── report/
│   ├── README.md          # báo cáo (phần nhận định do người/agent viết)
│   ├── GENERATED.md       # bảng IOC, nguồn, đính chính, evidence: sinh từ facts
│   └── evidence/          # bằng chứng ngắn mà mọi fact trỏ tới
└── work/
    ├── sample/            # mẫu, chỉ đọc
    ├── runs/  scripts/  extract/
    └── review/            # r1/, r2/, state.json, STOP_REPORT.md, OVERRIDE
```

## Cổng phản biện

| | Lớp 1: script | Lớp 2: phiên LLM mới |
|---|---|---|
| Kiểm gì | evidence tồn tại và đúng dòng; hash tính lại; giá trị IOC có trong evidence; nguồn S/E/V khớp loại evidence; suy diễn persistence từ `api_unused` | phản biện từng fact như chuyên gia dịch ngược: giải thích thay thế, mức chắc chắn, chủ đề còn thiếu |
| Cô lập | không cần | tiến trình mới, chạy ngoài cây project, tắt hook/MCP/skill, chỉ công cụ đọc, câu hỏi canary phát hiện rò ngữ cảnh |
| Kết quả | `fail`/`weak` kèm `where` (vị trí lỗi) và `redo` (cách kiểm lại) | như lớp 1, ghi vào `work/review/rK/review.json` |

- Review hết hiệu lực khi `facts.jsonl` đổi; review lặp lại với facts không đổi không tính thêm lần.
- Lần 2 vẫn FAIL thì `STOPPED`: chặn `report --final`, sinh `STOP_REPORT.md`. Chỉ người dùng mở lại, bằng `work/review/OVERRIDE` chứa `facts_sha256` khớp.
- Với Claude Code, cô lập được kiểm từ sự kiện khởi động của phiên (`full`). Với LLM khác qua `REVIEW_LLM_CMD`, chỉ kiểm được thư mục làm việc và canary (`partial`); mức này được ghi vào kết quả review.

## An toàn và OPSEC

- **Không thực thi mẫu dưới bất kỳ hình thức nào:** không chạy trực tiếp, không wine/qemu, không chạy script mẫu, không dùng lệnh `rea` có chạy target.
- **Không chạm hạ tầng của kẻ tấn công:** không kết nối C2, không tra mẫu trên dịch vụ ngoài. Tải payload thật chỉ khi người dùng cho phép.
- `winemu` không có mạng thật: mọi API mạng chỉ được ghi lại. Snapshot dùng `pickle`, chỉ nạp snapshot do chính mình tạo.
- Không đưa mẫu và thư mục case lên git. Nên để repo skill ở chế độ **private**.
- Lớp 2 gửi `facts.jsonl`, evidence và chuỗi trích từ mẫu tới nhà cung cấp LLM đang dùng; cân nhắc chính sách dữ liệu trước khi đổi nhà cung cấp.
- Với agent không phải Claude Code, quy tắc "không thực thi mẫu" chỉ là hướng dẫn bằng chữ; hãy bật chế độ hỏi trước khi chạy lệnh hoặc sandbox của agent.

## Giới hạn

- Giả lập (T3) chỉ có cho Windows x86-32; ELF, x64 và .NET chỉ phân tích tĩnh.
- `rea` không hỗ trợ MIPS/PPC; Ghidra headless lần đầu chậm (vài phút cho file Go MIPS vài MB).
- IOC lấy từ strings chỉ là `hypothesis` cho tới khi tìm thấy chỗ mã dùng nó.
- Phần nhận định trong báo cáo vẫn do người phân tích (hoặc agent) viết; script chỉ sinh bảng.
- Hồi quy trên mẫu thật cần mẫu có trên từng máy nên không đóng gói trong skill.

## Cấu trúc skill

```
SKILL.md            điểm vào của skill: quy tắc bắt buộc + lệnh (agent nạp file này)
FLOW.md             quy trình thao tác chi tiết (agent đọc khi cần)
reacfg.py           cấu hình theo máy + doctor
rea.env.example     mẫu ~/.config/rea-flow/rea.env
flow.py             điều phối: new, triage, dec, status, review, next, report, audit, doctor
case.py             kho fact, checklist C0–C11, sinh báo cáo
review.py           cổng phản biện, review-loop, gate, next
review/             prompt cho người phản biện và phiên sửa fact
static/             triage, gopclntab, NSIS, script Ghidra
winemu/             giả lập Windows x86-32, summarize, plugin theo họ mã độc
templates/          khung báo cáo
```

## Kiểm tra sau khi sửa

```bash
python3 $SKILL/case.py --selftest
python3 $SKILL/review.py --selftest
python3 $SKILL/flow.py doctor
```
