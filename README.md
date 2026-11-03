# rea-flow

**Skill dịch ngược mã độc có kiểm chứng cho AI coding agent.** Repo: <https://github.com/thaoht2109/rea-workflow> (public)

rea-flow biến một agent (Claude Code, Codex, Copilot, Cursor, Gemini CLI, OpenCode…) thành người phân tích mã độc làm việc có quy trình:

- **Không bao giờ thực thi mẫu.** Chỉ phân tích tĩnh và giả lập CPU.
- **Mỗi kết luận là một fact** có nguồn (`S` tĩnh, `E` giả lập, `V` VM) và bằng chứng trong `report/evidence/`; máy kiểm fact ngay khi ghi.
- **Cổng phản biện độc lập** (máy + một phiên LLM mới, cô lập) trước khi ra báo cáo cuối.
- **Báo cáo tiếng Việt** có bảng IOC, bảng đính chính, mục hạn chế/OPSEC.
- **Chạy được với LLM local** (Ollama, vLLM, llama.cpp… trên server tự dựng) cho phản biện, để dữ liệu mẫu không rời mạng nội bộ.

| | |
|---|---|
| Mẫu hỗ trợ | PE, ELF (mọi kiến trúc), Go, .NET, shellcode, installer NSIS, file nén, script, Office/PDF, APK |
| Đầu ra | `CASE/facts.jsonl` + `CASE/report/README.md`, `GENERATED.md`, `evidence/` |
| Nền tảng | Linux x86-64 (Debian/Ubuntu/Kali đã kiểm) |
| Phiên bản | tag `vX.Y.Z`; xem, cập nhật, lên/hạ bản: mục 8 |

**Mục lục:** [1. Yêu cầu](#1-yêu-cầu) · [2. Cài đặt](#2-cài-đặt) · [3. Chạy phân tích](#3-chạy-phân-tích) · [4. Cổng phản biện](#4-cổng-phản-biện) ([LLM local](#41-dùng-llm-local-ollama-qwen-vllm-trên-server-tự-dựng)) · [5. Cấu hình](#5-cấu-hình) · [6. An toàn và OPSEC](#6-an-toàn-và-opsec) · [7. Giới hạn](#7-giới-hạn) · [8. Phiên bản, cập nhật và gỡ](#8-phiên-bản-cập-nhật-và-gỡ) ([update --to](#83-đổi-sang-một-bản-cụ-thể-lên-hoặc-hạ---to)) · [9. Phát triển skill](#9-phát-triển-skill)

---

## 1. Yêu cầu

| Thành phần | Bắt buộc | Dùng cho |
|---|---|---|
| Linux x86-64, Python ≥ 3.9 | có | mọi script của skill |
| Node.js ≥ 22.20 (`npm`, `npx`) | có | bộ cài skill và CLI `rea` |
| Một coding agent | có | Claude Code (khuyên dùng), Codex, Copilot, Cursor, Gemini CLI, OpenCode… |
| `7z`, `pefile` | có | giải nén mẫu, triage PE |
| `capstone`, `unicorn` 2.1.4 | có | disassembly, giả lập CPU (`winemu`) |
| JDK 21 + **Ghidra 12** | có | engine decompile (của `rea` trên Linux, và Ghidra headless cho MIPS/PPC) |
| **`rea`** (gói npm [`rea-agents`](https://github.com/morluto/rea)) | có | decompile và inspect: PE/ELF/Mach-O, Go, .NET, Android, JS/Electron… |
| `upx` | không | tự bóc vỏ UPX |
| Một LLM cho phản biện lớp 2 | không | CLI `claude`/`codex`/`copilot`/`gemini`/`cursor-agent` đã đăng nhập, hoặc API chuẩn OpenAI (ChatGPT, DeepSeek…), hoặc **LLM local** chuẩn OpenAI (Ollama, vLLM, llama.cpp; mục 4.1). Không có thì dùng chế độ `manual` (dán vào chat web) |

Lệnh cài skill (mục 2.1) kiểm và cài luôn các công cụ phân tích ở trên; chỉ cần có sẵn Node.js, Python và agent. Không cần, và **không được**, cài wine để chạy mẫu.

---

## 2. Cài đặt

### 2.1. Cài skill và công cụ phân tích: một lệnh

```bash
npx github:thaoht2109/rea-workflow -g        # cài toàn máy; hỏi trước khi cài công cụ còn thiếu
npx github:thaoht2109/rea-workflow -g -y     # không hỏi gì: cài skill cho mọi agent và cài luôn công cụ thiếu
npx github:thaoht2109/rea-workflow           # chỉ cho project hiện tại (chạy trong thư mục project)
```

Lệnh làm ba việc:

1. Cài skill qua [skills CLI](https://github.com/vercel-labs/skills) (hỏi cài cho agent nào; `-a claude-code -a codex` để chọn sẵn).
2. Chép mục "Quy tắc bắt buộc" vào file hướng dẫn của agent đúng phạm vi: `~/.claude/CLAUDE.md`, `~/.codex/AGENTS.md`, `~/.gemini/GEMINI.md` (toàn máy) hoặc `AGENTS.md`, `CLAUDE.md`, `GEMINI.md` của project. Quy tắc nằm giữa cặp marker `rea-flow:rules`, cài lại không lặp.
3. Chạy `flow.py setup` (mục 2.2): in công cụ còn thiếu và kế hoạch cài, hỏi `[Y/n]` rồi cài (apt cần sudo). `-y` cài luôn không hỏi; `--no-tools` chỉ kiểm; `--no-ghidra` bỏ Ghidra. Chạy không có terminal tương tác mà không `-y` thì chỉ kiểm và in lệnh cài.

Dưới đây `$SKILL` là thư mục skill vừa cài (xem bằng `npx skills list -g`; thường là `~/.claude/skills/rea-flow` hoặc `~/.agents/skills/rea-flow`).

Cập nhật về sau: `npx github:thaoht2109/rea-workflow update -g` (mục 8).

Không có Node: `git clone https://github.com/thaoht2109/rea-workflow.git ~/.claude/skills/rea-flow && python3 ~/.claude/skills/rea-flow/flow.py rules --global`.

### 2.2. Công cụ phân tích (`flow.py setup`)

Bước 3 của lệnh cài ở trên. Chạy riêng khi cần kiểm lại hoặc cài sau:

```bash
python3 $SKILL/flow.py setup          # chỉ kiểm, in kế hoạch cài (mã 1 nếu thiếu); không thay đổi gì
python3 $SKILL/flow.py setup --yes    # cài phần thiếu; --no-ghidra để bỏ Ghidra (~550 MiB)
```

| Công cụ | `setup --yes` cài bằng |
|---|---|
| `7z`, `pefile`, `capstone`, `upx`, JDK 21 | `sudo apt-get install 7zip python3-pefile python3-capstone upx-ucl openjdk-21-jdk-headless` (bản cũ: `p7zip-full`; không có apt: in danh sách để cài tay) |
| `unicorn` 2.1.4 | `pip install --target ~/.local/share/rea-flow/pylib` (không cần sudo, chạy được với PEP 668) |
| Ghidra 12.1.4 | tải bản phát hành chính thức từ GitHub, **đối chiếu sha256** GitHub công bố (sai thì xoá và dừng), giải nén vào `~/.local/share/rea-flow/`, ghi `GHIDRA_INSTALL_DIR` vào `~/.config/rea-flow/rea.env` |
| `rea` | `npm install -g rea-agents@6.7.0` (thư mục npm toàn cục không ghi được thì `--prefix ~/.local`) |
| Node.js | chỉ hướng dẫn cài tay (nodejs.org hoặc nvm): apt của nhiều bản phân phối còn bản cũ |

Phiên bản Ghidra và `rea` được ghim ở bản đã kiểm với rea-flow. `setup` không bao giờ cài wine.

### 2.3. Kiểm tra cấu hình

```bash
python3 $SKILL/flow.py doctor
```

In từng mục `OK` / `THIẾU` / `WARN` kèm gợi ý, trả mã 1 nếu thiếu mục bắt buộc. Dòng "lớp 2 phản biện" cho biết backend LLM sẽ dùng; CLI của backend đó phải đã đăng nhập.

### 2.4. Phiên phân tích gọn (khuyên dùng với Claude Code, một lần)

```bash
cd ~/malware-cases                         # thư mục sẽ chứa các case (workspace)
python3 $SKILL/flow.py session --install   # gỡ: flow.py session --uninstall
```

Lệnh thêm một khối hàm shell vào `~/.bashrc`/`~/.zshrc`. Từ đó, **trong workspace** (kể cả thư mục case con):

| Gõ | Kết quả |
|---|---|
| `claude` | Phiên phân tích: giữ skill, MCP và plugin phục vụ dịch ngược (rea, Ghidra, IDA, radare/rizin, Frida, jadx, YARA…), tắt MCP/plugin không liên quan và hook; nạp rea-flow. Ngữ cảnh nền ít hơn khoảng 20%. `flow.py session --strict`: chỉ còn rea-flow (ít hơn khoảng 45%) |
| `codex`, `gemini`, `copilot`, `cursor-agent`, `opencode` | cập nhật khối quy tắc rea-flow vào `AGENTS.md`/`CLAUDE.md`/`GEMINI.md` rồi chạy như thường |

Ngoài workspace, mọi thứ chạy như cũ. Không cài hàm shell thì mở bằng `python3 $SKILL/flow.py session`.

---

## 3. Chạy phân tích

### 3.1. Cách nhanh nhất

```bash
cd ~/malware-cases && claude
```

Rồi giao việc bằng lời, ví dụ: *"Phân tích mẫu `~/samples/invoice.zip` (mật khẩu `infected`) theo rea-flow"*. Agent tự:

1. `flow.py new` tạo case, chép mẫu (quyền 0400), giải nén, triage tĩnh;
2. đi theo checklist, leo tầng rẻ → đắt (triage → bóc vỏ → decompile → giả lập → payload), ghi mỗi kết luận thành fact;
3. đến mốc thì `flow.py checkpoint` và đề nghị bạn `/clear` để giảm ngữ cảnh, rồi `flow.py resume` làm tiếp;
4. chạy cổng phản biện (tối đa 2 lần), hỏi bạn chấp nhận các mục checklist không đạt được (kèm lý do);
5. sinh báo cáo cuối và `audit`.

Bạn chỉ cần trả lời khi agent hỏi và gõ `/clear` khi được đề nghị.

### 3.2. Quy trình

```
mẫu ─► T0 triage ─► T1 bóc vỏ ─► T2 decompile có mục tiêu ─► T3 giả lập CPU ─► T4 payload offline
          │                                                                     │
          └──────────── facts.jsonl (S / E / V) + report/evidence/ ◄────────────┘
                                         │
                          cổng phản biện (≤ 2 lần) ──FAIL──► STOP_REPORT.md (người dùng quyết)
                                         │PASS
                             checklist C0–C11 đủ? ──thiếu──► leo tầng kế tiếp
                                         │đủ
                                báo cáo cuối, đóng case (không cần VM)
```

| Tầng | Công cụ | Nguồn fact |
|---|---|---|
| T0 Triage | `static/triage.py`: loại file, hash, entropy, import/export, IOC ứng viên (chỉ là gợi ý trong `triage_*.json`, không tự thành fact) | S |
| T1 Bóc vỏ | zip/7z/rar, `upx -d`, NSIS (giải "sàng byte" lộ `System::Call`) | S |
| T2 Tĩnh có mục tiêu | `flow.py dec` (rea, tự chuyển Ghidra headless cho MIPS/PPC), lệnh `rea` tĩnh theo loại mẫu (`FLOW.md` mục 4a), tên hàm Go từ `.gopclntab` | S |
| T3 Giả lập | `winemu`: Windows x86-32 giả trên Unicorn (PEB/TEB, SEH/VEH, DLL giả, mạng chỉ ghi lại) | E |
| T4 Payload | giải mã offline bằng khóa/định dạng từ T2/T3, triage lại | S/E |
| T5 VM ngoài | chỉ khi người dùng quyết định | V |

**Checklist đóng case:** C0 Phản biện · C1 Nhận dạng · C2 Delivery và điểm vào · C3 Chống phân tích · C4 Giải mã chuỗi/config · C5 IOC mạng · C6 Tiêm mã · C7 Persistence · C8 Payload: định dạng và khóa · C9 Payload cuối · C10 Họ mã độc · C11 Độ phủ. Mục không đạt được có thể chấp nhận kèm lý do (`--accept`), lý do vào mục hạn chế của báo cáo.

### 3.3. Lệnh

Agent chạy các lệnh này; bạn cũng chạy được trực tiếp từ workspace. Danh sách đầy đủ: `python3 $SKILL/flow.py help`. Việc kế tiếp của một case: `python3 $SKILL/flow.py next CASE`.

```bash
python3 $SKILL/flow.py new  CASE mẫu.exe [file2 ...]         # tạo case, chép mẫu, giải nén, triage
python3 $SKILL/case.py add CASE id=c2.main kind=c2 value='host:443' src=E evidence=report/evidence/emu.txt#L12
python3 $SKILL/case.py add CASE id=scan.hosts kind=string value='8 máy WIN-*' src=S evidence=report/evidence/scan.txt \
        recompute='distinct (WIN-[A-Z0-9]+) report/evidence/scan.txt = 8'     # con số: máy đếm lại
python3 $SKILL/flow.py review CASE --llm --detach            # cổng phản biện; gọi lại tới khi mã khác 6
```

Sửa fact bằng fact mới có `supersedes=<id cũ>`; không sửa hay xoá dòng cũ trong `facts.jsonl`.

### 3.4. Tách phiên theo mốc (giảm token)

Mỗi lần gọi model đọc lại toàn bộ ngữ cảnh, nên chi phí ≈ số lượt × độ lớn ngữ cảnh; phiên phân tích dài thường ở 200k+ token mỗi lượt. Mở phiên mới ở các mốc (sau triage/bóc vỏ, sau mỗi cụm decompile, sau mỗi đợt giả lập, trước cổng phản biện, trước báo cáo) giảm khoảng 20–40% trên phiên dài. Điều kiện để không mất chất lượng: mọi kết quả đã nằm trên đĩa. `checkpoint` chặn tách phiên khi còn fact lỗi lint hoặc kết quả chạy chưa ghi thành fact; `resume` dựng lại trạng thái từ `facts.jsonl` (việc kế, cổng, fact kết luận nguyên văn, giả thuyết). Không tách cho bước nhỏ: phiên mới hoà vốn sau khoảng 5 lượt.

### 3.5. Kết quả: cấu trúc một case

```
CASE/
├── facts.jsonl            # nguồn sự thật duy nhất; chỉ nối thêm
├── report/
│   ├── README.md          # báo cáo (phần nhận định do agent/người viết)
│   ├── GENERATED.md       # bảng IOC, nguồn, đính chính, evidence: sinh từ facts
│   └── evidence/          # bằng chứng ngắn mà mọi fact trỏ tới (kèm #L dòng)
└── work/
    ├── sample/            # mẫu, chỉ đọc
    ├── runs/  scripts/  extract/
    ├── accepted.json      # mục checklist chấp nhận hạn chế
    ├── checkpoint.json    # mốc chốt gần nhất
    └── review/            # r1/, r2/, state.json, usage.jsonl, llm_cache/, STOP_REPORT.md, OVERRIDE
```

---

## 4. Cổng phản biện

| | Lớp 1: máy | Lớp 2: LLM bất kỳ, phiên mới cô lập |
|---|---|---|
| Kiểm gì | evidence tồn tại, đúng dòng; hash tính lại; giá trị IOC có trong evidence; nguồn S/E/V khớp loại evidence; con số `recompute` đếm lại khớp | phản biện như chuyên gia: evidence có chứng minh không, giải thích thay thế (chuỗi chứng thư/thư viện, import chưa gọi, kết quả do stub giả lập…), mức chắc chắn, chủ đề còn thiếu |
| Cũng chạy khi | ghi fact (`case.py add`, `--strict` để từ chối) | — |

- **Tối đa 2 lần.** Lần 1 FAIL thì sửa đúng fact bị chỉ ra; lần 2 vẫn FAIL thì `STOPPED`, sinh `STOP_REPORT.md`, chặn báo cáo cuối. Chỉ người dùng mở lại (sửa tay, hoặc `work/review/OVERRIDE` có `facts_sha256` khớp).
- **Mức high/low do luật quyết định,** không do model: fail ở kiểm bằng chứng cứng hoặc ở fact IOC/kết luận luôn chặn.
- **Chỉ gửi fact cần LLM:** hash/filetype sạch không gửi; từ review 2 chỉ gửi fact đã đổi hoặc bị chỉ ra. Facts không đổi thì không tính thêm lần.
- **Cô lập:** phiên phản biện không nạp CLAUDE.md, skill, plugin, hook, MCP của máy; canary hỏi trước để phát hiện ngữ cảnh cũ. Kiến thức RE chung cho mọi backend nằm ở `review/re-knowledge.md`.
- **Chạy lâu:** `--detach` chạy nền; tiến trình LLM chỉ bị giết khi im lặng quá `REVIEW_IDLE` hoặc tổng quá `REVIEW_TIMEOUT`; phiên bị ngắt giữ kết luận từng fact đã xong, chạy lại chỉ gửi phần còn lại. Mọi lần gọi ghi token/chi phí vào `work/review/usage.jsonl`.

| Backend (`REVIEW_LLM`) | Cách chạy |
|---|---|
| `auto` (mặc định) | CLI đầu tiên có trên máy theo thứ tự bảng, rồi `api` nếu có key và model, cuối cùng `manual`: lớp 2 luôn chạy được |
| `claude` | một phiên agent có công cụ chỉ đọc (`Read`, `Grep`, `python3 -I`) trên bản sao tạm |
| `copilot`, `codex` | CLI không tương tác với `HOME` tạm chỉ mang xác thực (copilot: `COPILOT_MODEL` để chọn model) |
| `gemini`, `cursor` | CLI không tương tác; **chưa cô lập** khỏi cấu hình người dùng (in cảnh báo) |
| `api` | API chat completions chuẩn OpenAI: ChatGPT, DeepSeek, hoặc **LLM local** (Ollama, vLLM, llama.cpp, LM Studio…) (`REVIEW_API_BASE`, `REVIEW_MODEL`, `REVIEW_API_KEY`) |
| `cmd` | lệnh tự khai (`REVIEW_LLM_CMD`): prompt qua stdin, text ra stdout |
| `manual` | script ghi `…prompt.md`; dán vào một cuộc chat **mới**, lưu câu trả lời vào `…answer.md`, chạy lại (mã 4 = đang chờ) |

Với backend không có công cụ, script gửi hồ sơ tự chứa (fact, đoạn evidence, kết quả lớp 1, phép dò sẵn trên mẫu); mô hình xin thêm dữ liệu bằng các thao tác chỉ đọc (`read`, `grep`, `hex`, `strings`, `find`, `disasm`, `xrefs`, `pe`, `sha256`, `xor`). Mỗi lượt lưu ở `work/review/llm_cache/` nên chạy lại không gọi lại LLM.

### 4.1. Dùng LLM local (Ollama, Qwen, vLLM… trên server tự dựng)

Dữ liệu mẫu, evidence và IOC không rời mạng nội bộ. Ghi vào `~/.config/rea-flow/rea.env`:

```bash
REVIEW_LLM=api
REVIEW_API_BASE=http://10.0.0.5:11434/v1    # Ollama; vLLM / llama.cpp server thường là http://HOST:8000/v1
REVIEW_MODEL=qwen2.5-coder:32b              # đúng tên server khai (GET /v1/models)
REVIEW_BATCH=8                              # model nhỏ: ít fact mỗi lô
# REVIEW_API_KEY: không cần với server tự dựng (chỉ bắt buộc với OpenAI/DeepSeek)
```

- `flow.py doctor` gọi thử `GET {REVIEW_API_BASE}/models` và báo nếu không kết nối được hoặc server không có model.
- **Ngữ cảnh:** hồ sơ phản biện dài 20–70 KB; Ollama mặc định chỉ 2–4k token và **cắt im lặng**. Đặt `OLLAMA_CONTEXT_LENGTH=32768` cho server (hoặc `PARAMETER num_ctx 32768` trong Modelfile). Review tự báo lỗi (không tính một lần review) nếu server nhận ít token hơn nhiều so với prompt.
- **Chọn model:** nên từ khoảng 32B (Qwen2.5-Coder 32B, Qwen3 32B, Llama 3.3 70B…). Model 7–8B hay trả JSON sai hoặc bịa nhận định; canary và luật severity chặn được phần lớn nhưng giá trị phản biện giảm.

**Agent phân tích chính chạy model local:** chọn agent cho phép trỏ tới endpoint riêng và đọc `AGENTS.md`: OpenCode (Ollama/endpoint chuẩn OpenAI), GitHub Copilot CLI (`COPILOT_PROVIDER_BASE_URL=http://HOST:11434/v1`), Codex CLI (provider tùy chỉnh). Vòng phân tích dài, gọi nhiều công cụ nên model local nhỏ dễ lạc hướng; cấu hình nên dùng: agent chính model mạnh, phản biện lớp 2 model local. Nếu cả hai đều local: nên từ 70B.

---

## 5. Cấu hình

Mặc định đủ khi công cụ nằm trên `PATH` (và `setup --yes` tự ghi `GHIDRA_INSTALL_DIR`). Khi cần đổi:

```bash
mkdir -p ~/.config/rea-flow && cp $SKILL/rea.env.example ~/.config/rea-flow/rea.env
```

File nằm ngoài thư mục skill nên cập nhật skill không làm mất. Biến môi trường cùng tên ghi đè file; `REA_ENV` trỏ tới file khác; workspace là thư mục hiện tại (hoặc `REA_WORKSPACE`).

| Biến | Mặc định | Ý nghĩa |
|---|---|---|
| `GHIDRA_INSTALL_DIR`, `JAVA_HOME` | trống | Ghidra 12; JDK 21 (trống thì dùng `java` trên `PATH`) |
| `REA_BIN`, `UPX_BIN`, `SEVENZ_BIN`, `CLAUDE_BIN` | `rea`, `upx`, `7z`, `claude` | tên trên `PATH` hoặc đường dẫn tuyệt đối |
| `REA_PYLIB` | `~/.local/share/rea-flow/pylib` | thư mục chứa `unicorn` |
| `REA_TMP` | `.tmp` (trong workspace) | thư mục tạm cho rea/Ghidra; đặt trên đĩa thật nếu `/tmp` nhỏ |
| `WINE_DLL_DIR` | `/usr/lib/x86_64-linux-gnu/wine` | chỉ để `winemu` đọc tên export DLL; wine không bao giờ được chạy |
| `REVIEW_LLM` | `auto` | backend lớp 2 (mục 4) |
| `REVIEW_MODEL`, `REVIEW_EFFORT` | trống, `medium` | model lớp 2 (bắt buộc với `api`; với `claude` là `--model`); mức suy nghĩ của claude |
| `REVIEW_API_BASE`, `REVIEW_API_KEY` | OpenAI, `$OPENAI_API_KEY` | backend `api`; key bắt buộc với OpenAI/DeepSeek, không cần với LLM local (mục 4.1); đặt key bằng biến môi trường |
| `REVIEW_LLM_CMD`, `COPILOT_MODEL` | trống | backend `cmd`; model cho `copilot` |
| `REVIEW_BATCH`, `REVIEW_MAX_TURNS` | `20`, `6` | backend không công cụ: số fact mỗi lô, số lượt mỗi lô |
| `REVIEW_IDLE`, `REVIEW_TIMEOUT` | `300`, `3600` | giây im lặng / tổng tối đa của một lần gọi LLM |
| `REVIEW_WS_DIR` | `/var/tmp` | thư mục làm việc của phản biện; phải nằm ngoài mọi thư mục có file hướng dẫn agent |
| `ANALYST_LLM_CMD` | trống | phiên tự sửa fact cho `review-loop` khi backend không phải `claude` |
| `REA_SHELL_RC` | `~/.bashrc:~/.zshrc` | file rc mà `session --install` ghi |
| `REA_SESSION_MCP`, `REA_SESSION_PLUGINS` | trống | MCP/plugin giữ thêm trong `flow.py session` (tên, phân cách dấu phẩy) |

---

## 6. An toàn và OPSEC

- **Không thực thi mẫu dưới bất kỳ hình thức nào:** không chạy trực tiếp, không wine/qemu, không chạy script mẫu, không dùng lệnh `rea` chạy target (`capture-*`, `debug-*`, `observe-*`…; danh sách được phép/bị cấm ở `FLOW.md` mục 4a).
- **Không chạm hạ tầng của kẻ tấn công:** không kết nối C2, không tra mẫu trên dịch vụ ngoài. Tải payload thật chỉ khi người dùng cho phép.
- `winemu` không có mạng thật: mọi API mạng chỉ được ghi lại.
- Lớp 2 gửi `facts.jsonl`, evidence và chuỗi trích từ mẫu tới nhà cung cấp LLM đang dùng; cân nhắc chính sách dữ liệu trước khi chọn backend. Cần giữ dữ liệu trong mạng nội bộ thì dùng LLM local (mục 4.1).
- Repo skill là **public**: không đưa mẫu, thư mục case, IOC, tên case hay đường dẫn máy vào repo, commit message hay mô tả PR.
- Với agent không phải Claude Code, quy tắc "không thực thi mẫu" chỉ là hướng dẫn bằng chữ: bật chế độ hỏi trước khi chạy lệnh hoặc sandbox của agent.

## 7. Giới hạn

- Giả lập (T3) chỉ có cho Windows x86-32; ELF, x64 và .NET phân tích tĩnh.
- `rea` không hỗ trợ MIPS/PPC (dùng Ghidra headless; lần đầu chậm vài phút với file lớn).
- IOC ứng viên từ strings chỉ thành fact khi thấy chỗ mã dùng nó (xref, tham số API trong giả lập).
- Phiên gọn (`flow.py session`) chỉ có cho Claude Code; agent khác chỉ được bảo đảm quy tắc qua `AGENTS.md`/`GEMINI.md`.
- LLM local: chất lượng phản biện phụ thuộc model (nên từ khoảng 32B) và ngữ cảnh của server (≥ 32k token).
- Phần nhận định trong báo cáo do agent/người viết; script sinh bảng và kiểm bằng chứng.

## 8. Phiên bản, cập nhật và gỡ

Mỗi bản phát hành là một tag `vX.Y.Z` trên GitHub, lấy theo `version` trong `package.json` ([danh sách tag](https://github.com/thaoht2109/rea-workflow/tags)). Bộ cài `npx github:thaoht2109/rea-workflow` luôn lấy từ `main`, nên các lệnh dưới đây dùng được dù skill đang ở bản nào.

### 8.1. Xem phiên bản

```bash
npx github:thaoht2109/rea-workflow version [-g]   # hoặc: python3 $SKILL/flow.py version
```

```
rea-flow 1.1.0 (skills CLI, theo main) tại ~/.claude/skills/rea-flow
các bản: v1.0.0, [v1.1.0]
```

Dòng đầu: bản đang cài và nguồn cài: `skills CLI, theo main`, `skills CLI, ghim vX.Y.Z` (đọc từ lock của skills CLI), hoặc `clone git <git describe>`. Dòng hai: các bản trên GitHub, bản đang dùng trong `[...]`; có bản mới hơn thì báo `có bản mới vX.Y.Z`. Không có mạng thì in dòng đầu và báo không lấy được danh sách.

### 8.2. Cập nhật lên bản mới nhất

```bash
npx github:thaoht2109/rea-workflow update [-g] [-y] [--no-tools] [--no-ghidra]
```

Không tải lại cả bộ:

- Skill cài bằng `npx`: `skills update` kéo phần thay đổi, giữ các agent đã chọn.
- Skill là bản clone git (thư mục hoặc symlink tới clone): `git pull --ff-only`.
- Đang ghim một bản (mục 8.3): quay về `main` (`skills add` lại không ref, hoặc `git checkout main` rồi pull).

Sau đó chép lại khối quy tắc vào `CLAUDE.md`/`AGENTS.md`/`GEMINI.md` và kiểm công cụ (bản Ghidra/`rea` ghim có thể đổi theo phiên bản); thiếu thì hỏi trước khi cài, `-y` cài luôn, `--no-tools` chỉ kiểm. Chưa cài skill thì báo lỗi kèm lệnh cài.

### 8.3. Đổi sang một bản cụ thể (lên hoặc hạ): `--to`

```bash
npx github:thaoht2109/rea-workflow update -g --to v1.0.0    # hạ xuống (hoặc lên) đúng bản v1.0.0; "1.0.0" cũng được
npx github:thaoht2109/rea-workflow update -g                 # bỏ ghim, về bản mới nhất
```

- Skill cài bằng `npx`: `skills add` lại với ref là tag; lock của skills CLI ghi `ref`, `skills update` về sau giữ nguyên bản này cho tới khi chạy `update` không `--to`. Không có `-a` thì CLI hỏi cài cho agent nào (với `-y`: mọi agent).
- Bản clone git: `git fetch --tags` rồi `git checkout` tag (HEAD tách rời; thay đổi chưa commit được git giữ hoặc báo lỗi nếu xung đột).
- `--to` chỉ nhận dạng `vX.Y.Z`; tag không có thì skills CLI/git báo lỗi và bản đang cài giữ nguyên.
- `v1.0.0` chưa có lệnh `version`; khi đang ở bản đó vẫn `update` được bình thường.

Dùng khi bản mới làm hỏng một case đang làm dở, hoặc cần chạy lại đúng bản đã dùng để ra một báo cáo (ghi bản `version` vào mục hạn chế của báo cáo nếu cần tái lập).

### 8.4. Gỡ

```bash
python3 $SKILL/flow.py session --uninstall         # gỡ hàm shell (nếu đã cài)
npx github:thaoht2109/rea-workflow remove [-g]     # gỡ khối quy tắc rồi gỡ skill
```

Gỡ không xoá `~/.config/rea-flow`, `~/.local/share/rea-flow` (Ghidra, unicorn) và các case trong workspace.

## 9. Phát triển skill

```
SKILL.md            điểm vào của skill: quy tắc bắt buộc + lệnh (agent nạp file này)
FLOW.md             quy trình chi tiết: ghi fact, cổng phản biện, định tuyến theo loại file, lệnh rea được phép
flow.py             điều phối: new, triage, dec, status, resume, checkpoint, review, next, report, audit,
                    doctor, setup, rules, session
case.py             kho fact (add + lint + recompute, show, search), checklist C0–C11, sinh báo cáo
review.py           cổng phản biện lớp 1, review-loop, gate, next
reviewer.py         lớp 2: hồ sơ tự chứa, thao tác chỉ đọc, kết nối mọi LLM, cô lập
review/             prompt phản biện, kiến thức RE chung (re-knowledge.md), prompt sửa fact
install_tools.py    kiểm và cài công cụ phân tích (flow.py setup)
reacfg.py           cấu hình theo máy + doctor;  rea.env.example: mẫu cấu hình
install.mjs         bộ cài một lệnh (npx github:thaoht2109/rea-workflow [update|version|remove]): skills add/update + flow.py rules + flow.py setup
static/             triage, gopclntab, NSIS, script Ghidra
winemu/             giả lập Windows x86-32, summarize, plugin theo họ mã độc
templates/          khung báo cáo
```

Kiểm sau khi sửa:

```bash
python3 $SKILL/case.py --selftest && python3 $SKILL/review.py --selftest
python3 $SKILL/reviewer.py --selftest && python3 $SKILL/install_tools.py --selftest
python3 $SKILL/flow.py doctor
```

Hồi quy trên mẫu thật cần mẫu có trên từng máy nên không nằm trong repo.

Phát hành: tăng `version` trong `package.json` trong PR (sửa lỗi: số cuối; thêm tính năng: số giữa; đổi định dạng facts/cấu hình: số đầu). Khi PR vào `main`, workflow `.github/workflows/tag.yml` gắn tag `vX.Y.Z` cho commit đó; người dùng thấy bản mới qua `version` và chọn bản qua `update --to`.
