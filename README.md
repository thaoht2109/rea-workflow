<div align="center">

# rea-workflow

**Quy trình dịch ngược mã độc có kiểm chứng cho AI coding agent**

[![CI](https://github.com/thaoht2109/rea-workflow/actions/workflows/ci.yml/badge.svg)](https://github.com/thaoht2109/rea-workflow/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/tag/thaoht2109/rea-workflow?label=release&sort=semver)](https://github.com/thaoht2109/rea-workflow/tags)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
![Platform](https://img.shields.io/badge/platform-Linux%20x86--64-lightgrey)

[Tính năng](#tính-năng) · [Cách hoạt động](#cách-hoạt-động) · [Cài đặt](#cài-đặt) · [Sử dụng](#sử-dụng) · [AI local](#chạy-bằng-ai-local) · [Cấu hình](#cấu-hình) · [Bảo mật](#bảo-mật) · [Cập nhật](#cập-nhật-và-gỡ-cài-đặt)

</div>

---

rea-workflow là một *skill* biến coding agent (Claude Code, Codex, GitHub Copilot, Cursor, Gemini CLI, OpenCode…) thành người phân tích mã độc làm việc có quy trình. Agent đi từ triage đến báo cáo. Mỗi kết luận đều phải có bằng chứng mà máy kiểm được, và phải qua một phiên phản biện độc lập trước khi được đưa vào báo cáo cuối.

> Skill được cài với định danh `rea-flow`. Định danh này dùng cho thư mục cài (`~/.claude/skills/rea-flow`), thư mục cấu hình (`~/.config/rea-flow`) và khi gọi skill trong agent.

## Tính năng

| | |
|---|---|
| **Không bao giờ thực thi mẫu** | Chỉ phân tích tĩnh và giả lập CPU. Mọi lời gọi mạng của mẫu chỉ được ghi lại, không gửi đi. Mẫu luôn ở chế độ chỉ đọc. |
| **Kết luận có bằng chứng** | Mỗi kết luận là một *fact* ghi rõ nguồn (tĩnh, giả lập hay VM) và trỏ tới đoạn bằng chứng cụ thể. Ngay khi ghi, máy kiểm bằng chứng có tồn tại không, giá trị có nằm trong bằng chứng không, hash và con số có tính lại khớp không. |
| **Phản biện độc lập** | Trước báo cáo cuối, một phiên LLM mới, không thấy ngữ cảnh phân tích, soát lại toàn bộ fact. Cổng chạy tối đa hai lần. Lần hai vẫn không đạt thì dừng lại, chờ người quyết. |
| **Tiết kiệm token** | Script làm phần việc lặp, agent chỉ đọc tóm tắt. Skill dẫn đường từng bước, tách phiên theo mốc và làm tiếp được sau khi xóa ngữ cảnh. |
| **Học từ case cũ** | Khi triage mẫu mới, skill so với các case đã phân tích (imphash, PDB, chứng thư số, C2…) và gợi ý hướng điều tra. Kho này xuất/nhập được giữa các server. |
| **Báo cáo chuẩn hóa** | Báo cáo tiếng Việt có bảng IOC, bảng đính chính và mục hạn chế/OPSEC. Các bảng sinh tự động từ fact. |
| **Chạy được trong mạng nội bộ** | Cả phân tích lẫn phản biện chạy được bằng LLM tự dựng (Ollama, vLLM, llama.cpp). Dữ liệu mẫu không rời khỏi hạ tầng của bạn. |

**Định dạng hỗ trợ:** PE, ELF (mọi kiến trúc), Go, .NET, shellcode, installer NSIS, file nén, script, Office/PDF, APK.

## Cách hoạt động

```text
  mẫu ──► triage ──► bóc vỏ ──► decompile có mục tiêu ──► giả lập CPU ──► giải mã payload
             │                                                                  │
             └───────────────► facts.jsonl + bằng chứng ◄────────────────────────┘
                                         │
                              phản biện độc lập (≤ 2 lần)
                                         │ đạt
                                  báo cáo tiếng Việt
```

Agent chỉ chuyển sang bước tốn kém hơn khi checklist còn mục chưa trả lời được. Case đóng khi checklist đủ và phản biện đạt. Không cần máy ảo.

## Cài đặt

### Yêu cầu

- Linux x86-64 (đã kiểm trên Debian, Ubuntu, Kali)
- Python ≥ 3.9 và Node.js ≥ 22.20
- Một coding agent đã cài và đăng nhập

Bộ cài tự kiểm và cài các công cụ phân tích còn thiếu: 7-Zip, pefile, Capstone, Unicorn, JDK 21, Ghidra 12, [`rea`](https://github.com/morluto/rea). Không cần, và **không được**, cài wine.

### Cài một lệnh

```bash
npx github:thaoht2109/rea-workflow -g        # cài cho toàn máy, hỏi trước khi cài công cụ
npx github:thaoht2109/rea-workflow -g -y     # cài toàn bộ, không hỏi
npx github:thaoht2109/rea-workflow           # chỉ cho project hiện tại
```

Lệnh này làm ba việc: cài skill cho các agent bạn chọn, thêm quy tắc an toàn vào file hướng dẫn của agent (`CLAUDE.md`, `AGENTS.md`, `GEMINI.md`), rồi cài công cụ phân tích. Cài apt cần sudo. Ghidra nặng khoảng 550 MiB; bỏ qua Ghidra bằng `--no-ghidra`.

<details>
<summary>Cài không có Node.js</summary>

```bash
git clone https://github.com/thaoht2109/rea-workflow.git ~/.claude/skills/rea-flow
python3 ~/.claude/skills/rea-flow/flow.py rules --global
python3 ~/.claude/skills/rea-flow/flow.py setup --yes
```
</details>

### Kiểm tra

Trong tài liệu này, `$SKILL` là thư mục skill đã cài, thường là `~/.claude/skills/rea-flow` hoặc `~/.agents/skills/rea-flow`.

```bash
python3 $SKILL/flow.py doctor
```

Lệnh in trạng thái từng thành phần: `OK`, `THIẾU` hoặc `WARN`, kèm gợi ý cách khắc phục.

### Phiên phân tích gọn (khuyên dùng với Claude Code)

```bash
cd ~/malware-cases                         # thư mục sẽ chứa các case
python3 $SKILL/flow.py session --install   # cài một lần; gỡ bằng --uninstall
```

Từ đó, gõ `claude` trong thư mục này sẽ mở phiên chỉ giữ công cụ dịch ngược, nên ngữ cảnh nền nhẹ hơn. Ở thư mục khác, `claude` vẫn chạy như thường.

## Sử dụng

Mở agent trong thư mục chứa case và giao việc bằng lời:

> Phân tích mẫu `~/samples/invoice.zip` (mật khẩu `infected`) bằng skill rea-flow

Agent tự tạo case, triage, phân tích, ghi fact, chạy phản biện và viết báo cáo. Bạn chỉ cần trả lời khi agent hỏi, và gõ `/clear` khi được đề nghị để giảm ngữ cảnh.

**Lệnh thường dùng** (khi muốn tự điều khiển):

| Lệnh | Mục đích |
|---|---|
| `flow.py new CASE mẫu.exe` | Tạo case và triage |
| `flow.py next CASE` | Việc kế tiếp, lệnh đã điền sẵn |
| `flow.py review CASE --llm` | Chạy cổng phản biện |
| `flow.py report CASE --final` | Sinh báo cáo cuối (khi phản biện đạt) |
| `flow.py help` | Toàn bộ lệnh |

**Kết quả** nằm trong thư mục của từng case:

```text
CASE/
├── facts.jsonl          mọi kết luận kèm nguồn và bằng chứng
└── report/
    ├── README.md        báo cáo
    ├── GENERATED.md     bảng IOC, bảng đính chính, danh sách bằng chứng
    └── evidence/        đoạn bằng chứng
```

**Chia sẻ kinh nghiệm giữa các server.** Kho tra chéo tự dựng ở lần phân tích đầu tiên và tự cập nhật mỗi khi đóng case. Để chuyển sang server khác hoặc giữ bản dự phòng:

```bash
python3 $SKILL/flow.py kb export kb-srv1.jsonl.gz --name srv1   # trên server nguồn
python3 $SKILL/flow.py kb import kb-srv1.jsonl.gz               # trên server nhận
```

Gợi ý từ kho chỉ là điểm bắt đầu điều tra, không phải kết luận.

## Chạy bằng AI local

Muốn dữ liệu mẫu không rời mạng nội bộ thì dùng LLM tự dựng. Khai trong `~/.config/rea-flow/rea.env`:

```bash
REVIEW_LLM=api
REVIEW_API_BASE=http://10.0.0.5:11434/v1    # Ollama; vLLM / llama.cpp thường là :8000/v1
REVIEW_MODEL=qwen2.5-coder:32b
```

Nên dùng model từ khoảng 32B tham số, ngữ cảnh ≥ 32k token (Ollama: `OLLAMA_CONTEXT_LENGTH=32768`).

Để chạy **cả vòng phân tích** bằng AI local, dùng Ollama cho model và OpenCode hoặc Codex CLI làm runtime:

```bash
# 1. Ollama (chạy ở terminal hoặc dịch vụ riêng), rồi tải model
OLLAMA_CONTEXT_LENGTH=64000 ollama serve
ollama pull qwen3-coder:30b

# 2. Cài skill cho runtime và chép quy tắc vào workspace
npx github:thaoht2109/rea-workflow -g -a opencode -a codex
cd <workspace> && python3 $SKILL/flow.py rules --project .

# 3a. OpenCode
python3 $SKILL/flow.py opencode --model qwen3-coder:30b
OPENCODE_DISABLE_MODELS_FETCH=1 opencode

# 3b. hoặc Codex CLI
ollama launch codex --config
codex --profile ollama-launch --sandbox workspace-write -c 'web_search="disabled"'
```

- `flow.py opencode` sinh cấu hình chặn sẵn lệnh chạy mẫu và lệnh mạng. Luật này chỉ để tránh chạy nhầm, không phải ranh giới bảo mật. Vì vậy hãy chạy trong máy ảo không có Internet, và không dùng `opencode --auto`.
- Ollama không có xác thực. Đặt Ollama ở máy khác thì chỉ mở cổng cho mạng nội bộ (`OLLAMA_HOST=0.0.0.0` kèm firewall).
- Không dùng model có tag `-cloud`: các model này chạy trên hạ tầng bên ngoài.

## Cấu hình

Mặc định đủ dùng khi công cụ nằm trên `PATH`. Khi cần đổi:

```bash
mkdir -p ~/.config/rea-flow && cp $SKILL/rea.env.example ~/.config/rea-flow/rea.env
```

| Biến | Mặc định | Ý nghĩa |
|---|---|---|
| `GHIDRA_INSTALL_DIR` | bộ cài tự ghi | thư mục Ghidra 12 |
| `JAVA_HOME` | trống (dùng `java` trên `PATH`) | JDK 21 cho Ghidra |
| `REA_TMP` | `.tmp` | thư mục tạm; đặt trên đĩa thật nếu `/tmp` nhỏ |
| `REVIEW_LLM`, `REVIEW_MODEL` | `auto`, trống | LLM dùng để phản biện |
| `REA_KB` | `~/.cache/rea-flow/kb` | kho tra chéo; `off` để tắt |

File cấu hình nằm ngoài thư mục skill nên không mất khi cập nhật. Biến môi trường cùng tên được ưu tiên hơn file. Danh sách đầy đủ có giải thích nằm trong [`rea.env.example`](rea.env.example).

## Bảo mật

- **Không thực thi mẫu, không chạm hạ tầng của kẻ tấn công, không tra mẫu trên dịch vụ bên ngoài.** Quy tắc chi tiết nằm ở [`SKILL.md`](SKILL.md). Chỉ tải payload thật khi người dùng cho phép.
- Phản biện gửi fact, bằng chứng và chuỗi trích từ mẫu tới nhà cung cấp LLM bạn chọn. Dữ liệu nhạy cảm thì dùng LLM local.
- Kho tra chéo và file `kb export` chứa hash và IOC. File chỉ chủ máy đọc được (quyền 0600). Chỉ chép qua kênh tin cậy (SSH, ổ mã hoá); không gửi qua email hay chat, không đưa lên repo công khai.
- Với agent khác Claude Code, quy tắc không thực thi mẫu chỉ là hướng dẫn bằng chữ. Hãy bật chế độ xác nhận lệnh hoặc sandbox của agent.

## Cập nhật và gỡ cài đặt

```bash
npx github:thaoht2109/rea-workflow version -g               # bản đang dùng và các bản phát hành
npx github:thaoht2109/rea-workflow update -g                # lên bản mới nhất
npx github:thaoht2109/rea-workflow update -g --to v1.5.0    # lên hoặc hạ về đúng một bản
python3 $SKILL/flow.py session --uninstall                 # trước khi gỡ: bỏ hàm shell `claude` (nếu đã cài)
npx github:thaoht2109/rea-workflow remove -g                # gỡ skill và quy tắc
```

Mỗi bản phát hành là một [tag `vX.Y.Z`](https://github.com/thaoht2109/rea-workflow/tags). Gỡ cài đặt không xóa cấu hình, công cụ đã cài, kho tra chéo hay các case.

## Đóng góp

Mọi thay đổi đi qua pull request, có CI (lint, test, quét bảo mật) và review tự động. Trước khi gửi:

```bash
ruff check . && python3 -m pytest --import-mode=importlib -q -p no:cacheprovider tests
```

- Test chỉ dùng dữ liệu tổng hợp. Không đưa mẫu, tên case hay IOC vào repo, commit hoặc mô tả PR.
- Đổi hành vi thì tăng `version` trong `package.json` theo [SemVer](https://semver.org): sửa lỗi tăng số cuối, thêm tính năng tăng số giữa, đổi định dạng dữ liệu hoặc cấu hình tăng số đầu.
- Tài liệu cho agent: [`SKILL.md`](SKILL.md) (quy tắc và lệnh), [`FLOW.md`](FLOW.md) (quy trình chi tiết).

## Giấy phép

[MIT](LICENSE)
