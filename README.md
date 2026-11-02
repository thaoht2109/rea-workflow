# rea-flow

**Skill dịch ngược mã độc có kiểm chứng cho AI coding agent.**

Repo: <https://github.com/thaoht2109/rea-flow> (private)

rea-flow biến một agent (Claude Code, Codex, Cursor, GitHub Copilot, Gemini CLI…) thành người phân tích mã độc làm việc có quy trình. Mỗi kết luận là một *fact* có nguồn và bằng chứng. Mọi fact phải qua cổng phản biện độc lập trước khi vào báo cáo cuối. Mẫu **không bao giờ được thực thi**: chỉ phân tích tĩnh và giả lập CPU.

| | |
|---|---|
| Đối tượng | PE, ELF (mọi kiến trúc), Go, .NET, shellcode, installer NSIS, file nén, script, Office/PDF, APK |
| Đầu ra | `facts.jsonl` (fact có nguồn S/E/V) + báo cáo tiếng Việt có bảng IOC, bảng đính chính, mục hạn chế/OPSEC |
| Yêu cầu | Linux x86-64, Python ≥ 3.9, Node ≥ 22.20 (chỉ để cài), `7z`, `pefile`; chi tiết ở [Thiết lập](#thiết-lập) |
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

## Thiết lập

Bốn bước, mỗi bước một lệnh: chuẩn bị máy → cài skill → cài công cụ phân tích → kiểm tra.

### 1. Chuẩn bị máy

| Thành phần | Bắt buộc | Dùng cho |
|---|---|---|
| Linux x86-64, `python3` ≥ 3.9 | có | mọi script của skill |
| Node.js ≥ 22.20 (`npx`) | khi cài | chạy bộ cài và [skills CLI](https://github.com/vercel-labs/skills) |
| GitHub CLI (`gh`) đã `gh auth login` | khi cài | repo đang private; SSH key có quyền đọc repo cũng được |
| Một coding agent | có | Claude Code, Codex, Cursor, GitHub Copilot, Gemini CLI… |
| Một LLM cho lớp 2 phản biện | không bắt buộc | CLI `claude`/`codex`/`gemini`/`copilot`/`cursor-agent` đã đăng nhập, hoặc API key chuẩn OpenAI (ChatGPT, DeepSeek…). Không có gì thì dùng chế độ `manual` (dán vào chat web). Xem [Cổng phản biện](#cổng-phản-biện) |

### 2. Cài skill

```bash
npx github:thaoht2109/rea-flow         # cài cho project hiện tại (chạy trong thư mục project)
npx github:thaoht2109/rea-flow -g      # cài toàn máy
```

Lệnh làm hai việc:

1. Cài skill qua skills CLI. CLI hỏi cài cho agent nào; thêm `-a claude-code -a codex` để chọn sẵn, `-y` để không hỏi.
2. Chép mục "Quy tắc bắt buộc" của `SKILL.md` vào file hướng dẫn của agent, **đúng phạm vi vừa cài**, để quy tắc an toàn luôn có trong ngữ cảnh kể cả khi skill chưa được nạp:

| Phạm vi | Skill nằm ở | File được chép quy tắc |
|---|---|---|
| toàn máy (`-g`) | `~/.agents/skills/rea-flow` | `~/.claude/CLAUDE.md`, `~/.codex/AGENTS.md`, `~/.gemini/GEMINI.md`, chỉ với agent đã có trên máy |
| project | `<project>/.agents/skills/rea-flow` hoặc `<project>/.claude/skills/rea-flow` | `<project>/AGENTS.md`, `<project>/CLAUDE.md` (và `GEMINI.md` nếu project đã có) |

Quy tắc nằm giữa cặp marker `rea-flow:rules`; nội dung khác trong file giữ nguyên, cài lại không lặp nội dung.

Cách cài khác:

- Chỉ dùng skills CLI: `npx skills add thaoht2109/rea-flow [-g]`. Bước chép quy tắc khi đó do agent tự làm ở lần đầu dùng skill, hoặc chạy tay `python3 <thư mục skill>/flow.py rules`.
- Không có Node: `git clone https://github.com/thaoht2109/rea-flow.git ~/.claude/skills/rea-flow && python3 ~/.claude/skills/rea-flow/flow.py rules`.

### 3. Cài công cụ phân tích

Ví dụ trên Debian / Ubuntu / Kali:

```bash
sudo apt install 7zip python3-pefile python3-capstone upx-ucl      # 7zip: bản cũ là p7zip-full
python3 -m pip install --target ~/.local/share/rea-flow/pylib unicorn==2.1.4
```

| Công cụ | Bắt buộc | Dùng cho |
|---|---|---|
| `7z`, `pefile` | có | giải nén mẫu, triage PE |
| `capstone`, `unicorn` 2.1.4 | không | giả lập CPU (`winemu`) và disassembly; thiếu thì không có tầng T3 |
| `upx` | không | tự bóc vỏ UPX |
| `rea` | không | decompile nhanh x86/x86-64/ARM (T2); thiếu thì dùng Ghidra |
| Ghidra 12 + JDK 21 | không | decompile kiến trúc `rea` không hỗ trợ (MIPS, PPC…); khai `GHIDRA_INSTALL_DIR`, `JAVA_HOME` |
| DLL builtin của wine (`WINE_DLL_DIR`) | không | `winemu` chỉ đọc **tên export** của DLL giả. Không bao giờ chạy wine; nếu đã cài wine, `update-binfmts --display wine` phải báo "not in database" để file .exe không tự chạy |

`unicorn` cài vào `~/.local/share/rea-flow/pylib` (ngoài thư mục skill) nên cập nhật skill không làm mất; `pip --target` cũng chạy được trên hệ có PEP 668.

### 4. Kiểm tra

```bash
python3 ~/.agents/skills/rea-flow/flow.py doctor     # cài theo project: <project>/.agents/skills/rea-flow
# dòng "lớp 2 phản biện" cho biết backend sẽ dùng; CLI của backend đó phải đã đăng nhập
```

`doctor` in từng mục `OK` / `THIẾU` (bắt buộc) / `WARN` (tùy chọn) kèm gợi ý cài, trả mã 1 nếu thiếu mục bắt buộc. Đường dẫn skill của từng agent: `npx skills list [-g]`.

### Cấu hình (tùy chọn)

Mặc định đủ cho máy có công cụ trên `PATH`. Chỉ khi cần đổi, tạo file cấu hình từ mẫu:

```bash
mkdir -p ~/.config/rea-flow && cp <thư mục skill>/rea.env.example ~/.config/rea-flow/rea.env
```

File nằm ngoài thư mục skill nên cập nhật skill không làm mất. Biến môi trường cùng tên ghi đè file; `REA_ENV` trỏ tới file cấu hình khác. Workspace, nơi chứa các case, là thư mục hiện tại (hoặc `REA_WORKSPACE`).

| Biến | Mặc định | Ý nghĩa |
|---|---|---|
| `REA_TMP` | `.tmp` (trong workspace) | `TMPDIR` cho rea/Ghidra; đặt trên đĩa thật nếu `/tmp` là tmpfs nhỏ |
| `REVIEW_WS_DIR` | `/var/tmp` | thư mục làm việc của phản biện lớp 2; phải nằm ngoài workspace và mọi thư mục có file hướng dẫn agent |
| `GHIDRA_INSTALL_DIR`, `JAVA_HOME` | trống | Ghidra headless; `JAVA_HOME` trống thì dùng `java` trên `PATH` |
| `REA_PYLIB` | `<skill>/pylib` nếu có, không thì `~/.local/share/rea-flow/pylib` | thư mục chứa unicorn cho winemu |
| `WINE_DLL_DIR` | `/usr/lib/x86_64-linux-gnu/wine` | chỉ để lấy tên export DLL; wine không bao giờ được chạy |
| `REA_BIN`, `UPX_BIN`, `SEVENZ_BIN`, `CLAUDE_BIN` | `rea`, `upx`, `7z`, `claude` | công cụ ngoài: tên trên `PATH` hoặc đường dẫn tuyệt đối |
| `REVIEW_LLM` | `auto` | backend lớp 2: `auto`, `claude`, `codex`, `gemini`, `copilot`, `cursor`, `api`, `cmd`, `manual` |
| `REVIEW_BATCH`, `REVIEW_MAX_TURNS` | `20`, `6` | harness (backend khác claude): số fact mỗi lô; số lượt tối đa mỗi lô (mỗi lượt tối đa 8 thao tác đọc) |
| `REVIEW_API_BASE`, `REVIEW_API_KEY` | `https://api.openai.com/v1`, `$OPENAI_API_KEY` | backend `api` (endpoint chuẩn OpenAI). Nên đặt key bằng biến môi trường, không ghi vào file |
| `REVIEW_MODEL` | trống | model cho lớp 2: bắt buộc với `api`; với `claude` là `--model` (ví dụ `sonnet`) để giảm chi phí |
| `REVIEW_EFFORT` | `medium` | mức suy nghĩ của claude ở lớp 2 (`low`…`max`); ảnh hưởng trực tiếp token đầu ra |
| `REVIEW_LLM_CMD` | trống | backend `cmd`: lệnh không tương tác, prompt qua stdin, text ra stdout |
| `ANALYST_LLM_CMD` | trống | phiên tự sửa fact cho `review-loop` khi backend không phải `claude`; trống thì agent đang chạy tự sửa |

### Cập nhật và gỡ

```bash
npx github:thaoht2109/rea-flow [-g]            # cập nhật: chạy lại lệnh cài (skill và khối quy tắc đều được làm mới)
npx github:thaoht2109/rea-flow remove [-g]     # gỡ khối quy tắc rồi gỡ skill
```

Gỡ không xóa `~/.config/rea-flow`, `~/.local/share/rea-flow` và các case trong workspace.

### Dùng lần đầu

Mở agent trong thư mục sẽ chứa các case và giao việc, ví dụ: *"Phân tích mẫu `~/samples/invoice.zip` theo rea-flow"*. Agent tự nạp skill, chạy `flow.py new`, đi theo checklist và dừng khi cổng phản biện đạt.

## Sử dụng

Thông thường chỉ cần giao việc cho agent ("phân tích mẫu trong thư mục X"); skill hướng dẫn agent đi đúng quy trình. Các lệnh bên dưới là những gì agent chạy (`$SKILL` là thư mục skill), cũng dùng được trực tiếp từ workspace:

```bash
python3 $SKILL/flow.py new  CASE mẫu.exe [file2 ...]   # tạo case, chép mẫu (quyền 0400), giải nén, triage
python3 $SKILL/flow.py status CASE                      # checklist C0–C11 và gợi ý bước kế
python3 $SKILL/flow.py dec  CASE FILE hàm|0xaddr|list:chuỗi ...
python3 $SKILL/case.py add CASE id=c2.main kind=c2 value='host:443' src=E evidence=report/evidence/emu.txt#L12
python3 $SKILL/flow.py review CASE --llm                # cổng phản biện (lần 1, rồi lần 2 sau khi sửa)
python3 $SKILL/flow.py review-loop CASE                 # review → tự sửa fact lỗi → review lần 2
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

| | Lớp 1: script | Lớp 2: LLM bất kỳ, phiên mới |
|---|---|---|
| Kiểm gì | evidence tồn tại và đúng dòng; hash tính lại; giá trị IOC có trong evidence; nguồn S/E/V khớp loại evidence; suy diễn persistence từ `api_unused` | phản biện từng fact như chuyên gia dịch ngược: evidence có chứng minh không, giải thích thay thế, mức chắc chắn, chủ đề còn thiếu |
| Truy cập dữ liệu | đọc trực tiếp | claude: tự đọc bằng công cụ chỉ đọc (Read, Grep, `python3 -I`) trong bản sao tạm; LLM khác: **không có công cụ**, chỉ thấy hồ sơ script gửi và kết quả các thao tác chỉ đọc nó xin |
| Kết quả | `fail`/`weak` kèm `where` (vị trí lỗi) và `redo` (cách kiểm lại) | như lớp 1, ghi vào `work/review/rK/review.json` |

**Backend `claude`:** một phiên agent duy nhất, cwd là bản sao tạm ngoài project chỉ chứa các fact được chọn, `report/evidence/`, `work/sample|extract|scripts/`. Prompt chỉ có danh sách id; mô hình tự đọc phần cần. Công cụ: `Read`, `Grep`, `Bash(python3 -I:*)`; cấm ghi, Agent, mạng; không MCP/skill/hook/slash command (kiểm qua sự kiện `init` của `stream-json`). Cả lần review là một phiên nên mỗi lượt chỉ ghi phần mới vào prompt cache, phần cũ đọc lại với giá khoảng 10%. Đo trên một case thật: khoảng $0,06/fact, so với khoảng $0,31/fact khi tách thành nhiều phiên không công cụ (harness bên dưới).

**Lớp 2 chạy trên mọi LLM** (`reviewer.py`). Với backend khác claude, mô hình chỉ cần nhận text và trả JSON:

```
reviewer.py ── hồ sơ tự chứa + danh sách thao tác ──► LLM (chỉ text)
     ▲                                                   │
     │◄── {"requests":[{"op":"disasm","file":…,"va":…}]} ┘  tối đa REVIEW_MAX_TURNS lượt mỗi lô
     │── kết quả thao tác chỉ đọc (đã cắt gọn) ─────────►
     │◄── {"items":[…], "missing":[…]} kết luận ─────────┘
```

1. **Hồ sơ tự chứa:** với mỗi fact, script gửi giá trị, nguồn, trạng thái, fact cũ bị thay, kết quả lớp 1, đoạn evidence quanh dòng được trỏ, và các phép dò chạy sẵn (chuỗi của fact có trong mẫu không, disassembly tại địa chỉ nêu trong fact). Fact chia lô (`REVIEW_BATCH`, mặc định 20) để vừa cả model context ngắn.
2. **Thao tác chỉ đọc:** `read`, `grep`, `hex`, `strings`, `find`, `disasm`, `xrefs`, `pe`, `sha256`, `xor`; chỉ trong `facts.jsonl`, `report/evidence/`, `work/sample|extract|scripts/`. Mô hình không có shell, không tự đọc file, không thể chạy mẫu.
3. **Cô lập theo thiết kế:** script gửi toàn bộ nội dung nên biết chính xác mô hình thấy gì. Thêm một câu hỏi canary trước khi gửi dữ liệu để phát hiện ngữ cảnh cũ phía nhà cung cấp (bộ nhớ, hướng dẫn hệ thống khác).
4. **Kiểm toán, chạy lại được:** mỗi lượt lưu `work/review/llm_cache/<hash>.prompt.md` và `.answer.md`. Chạy lại với cùng dữ liệu dùng lại câu trả lời, không gọi lại LLM.
5. **An toàn trước prompt injection:** dữ liệu từ mẫu được đánh dấu là không tin cậy; mô hình không có công cụ nên chuỗi cài cắm không thể gây hành động. Lớp 2 chỉ thêm được lỗi, không gỡ được `fail` của lớp 1.

| Backend (`REVIEW_LLM`) | Kết nối |
|---|---|
| `claude` | `claude -p --no-session-persistence --allowedTools Read,Grep,Bash(python3 -I:*) --effort $REVIEW_EFFORT` (một phiên có công cụ chỉ đọc, xem trên) |
| `codex`, `gemini`, `copilot`, `cursor` | CLI tương ứng ở chế độ không tương tác, thư mục tạm rỗng ngoài project |
| `api` | API chat completions chuẩn OpenAI: ChatGPT/OpenAI, DeepSeek, GitHub Models, vLLM… (`REVIEW_API_BASE`, `REVIEW_API_KEY`, `REVIEW_MODEL`) |
| `cmd` | lệnh tự khai (`REVIEW_LLM_CMD`): prompt qua stdin, text ra stdout |
| `manual` | không cần gì: script ghi `…prompt.md`, người dùng dán vào một cuộc chat **mới** trên giao diện web bất kỳ, lưu câu trả lời vào `…answer.md` rồi chạy lại lệnh (mã thoát 4 = đang chờ) |

`auto` (mặc định) chọn CLI đầu tiên có trên máy theo thứ tự bảng, rồi `api` nếu có key và model, cuối cùng `manual`, nên lớp 2 **luôn chạy được**. Ví dụ DeepSeek: `REVIEW_LLM=api REVIEW_API_BASE=https://api.deepseek.com REVIEW_MODEL=deepseek-chat REVIEW_API_KEY=…`. Model khác họ với agent phân tích giúp phản biện độc lập hơn.

- Review hết hiệu lực khi `facts.jsonl` đổi; review lặp lại với facts không đổi không tính thêm lần.
- Lần 2 vẫn FAIL thì `STOPPED`: chặn `report --final`, sinh `STOP_REPORT.md`. Chỉ người dùng mở lại, bằng `work/review/OVERRIDE` chứa `facts_sha256` khớp.
- `review.json` ghi backend, số lô, số lượt, số thao tác, token và chi phí (`isolation.usage`, với claude và api), canary, sha256 của hồ sơ và prompt hệ thống.
- Chỉ gửi fact cần LLM: fact `hash`/`filetype` mà lớp 1 đã tính lại không lỗi thì không gửi; từ review 2 chỉ gửi fact đã đổi (nội dung fact hoặc file evidence) và fact bị chỉ ra ở review trước. Kết quả thao tác bị cắt ở 2.500 ký tự mỗi thao tác, 16.000 ký tự mỗi lượt.
- Không còn fact nào cần gửi (ví dụ review 2 mà chỉ còn fact không đổi) thì không mở phiên LLM.
- Chi phí với api: các lượt trong một lô gửi mảng messages, nhà cung cấp tự cache tiền tố. `REVIEW_BATCH`, `REVIEW_MAX_TURNS` chỉ áp dụng cho harness (backend khác claude).

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
install.mjs         bộ cài một lệnh (npx github:thaoht2109/rea-flow): skills add + flow.py rules
package.json        khai báo bin cho npx
flow.py             điều phối: new, triage, dec, status, review, next, report, audit, doctor
case.py             kho fact, checklist C0–C11, sinh báo cáo
review.py           cổng phản biện (lớp 1), review-loop, gate, next
reviewer.py         lớp 2: hồ sơ tự chứa, thao tác chỉ đọc, kết nối mọi LLM
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
