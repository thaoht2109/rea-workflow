# rea-flow

**Skill dịch ngược mã độc có kiểm chứng cho AI coding agent.** Repo: <https://github.com/thaoht2109/rea-workflow> (public)

rea-flow giúp một coding agent (Claude Code, Codex, Copilot, Cursor, Gemini CLI, OpenCode…) phân tích mã độc theo quy trình rõ ràng. Mọi kết luận đều phải có bằng chứng, và có một phiên LLM độc lập phản biện trước khi ra báo cáo.

## Ưu điểm

- **An toàn:** không bao giờ thực thi mẫu. Skill chỉ phân tích tĩnh và giả lập CPU, mọi lời gọi mạng của mẫu chỉ được ghi lại, không gửi đi thật.
- **Kết luận kiểm chứng được:** mỗi kết luận là một *fact* có nguồn (tĩnh, giả lập hoặc VM) và trỏ tới bằng chứng cụ thể. Máy kiểm fact ngay khi ghi: bằng chứng có tồn tại không, giá trị có đúng trong bằng chứng không, hash và con số có tính lại khớp không.
- **Phản biện độc lập:** trước báo cáo cuối, một phiên LLM mới, cô lập khỏi ngữ cảnh phân tích, soát lại các fact. Cổng chạy tối đa 2 lần; lần 2 vẫn sai thì dừng và chờ người quyết.
- **Đỡ tốn token:** script làm phần việc lặp, agent chỉ đọc tóm tắt. Skill dẫn đường từng bước (`flow.py next`), tách phiên theo mốc và nối tiếp được sau `/clear`.
- **Rút kinh nghiệm từ case cũ:** khi triage mẫu mới, skill so với các case đã phân tích (imphash, PDB, chứng thư, C2…) và gợi ý hướng làm. Kho này chia sẻ được giữa các server.
- **Báo cáo tiếng Việt** có bảng IOC, bảng đính chính và mục hạn chế/OPSEC; các bảng sinh tự động từ fact.
- **Chạy được hoàn toàn bằng AI local** (Ollama, vLLM, llama.cpp…), để dữ liệu mẫu không rời mạng nội bộ.

| | |
|---|---|
| Mẫu hỗ trợ | PE, ELF (mọi kiến trúc), Go, .NET, shellcode, installer NSIS, file nén, script, Office/PDF, APK |
| Đầu ra | `CASE/facts.jsonl`, báo cáo `CASE/report/README.md` + `GENERATED.md`, bằng chứng `CASE/report/evidence/` |
| Nền tảng | Linux x86-64 (đã kiểm trên Debian/Ubuntu/Kali) |

**Mục lục:** [1. Yêu cầu](#1-yêu-cầu) · [2. Cài đặt](#2-cài-đặt) · [3. Sử dụng](#3-sử-dụng) · [4. Phản biện bằng LLM và AI local](#4-phản-biện-bằng-llm-và-ai-local) · [5. Cấu hình](#5-cấu-hình) · [6. An toàn](#6-an-toàn) · [7. Cập nhật và gỡ](#7-cập-nhật-và-gỡ) · [8. Phát triển](#8-phát-triển)

---

## 1. Yêu cầu

Chỉ cần có sẵn **Linux x86-64, Python ≥ 3.9, Node.js ≥ 22.20 và một coding agent**. Lệnh cài ở mục 2 tự kiểm và cài phần còn lại: `7z`, `pefile`, `capstone`, `unicorn`, JDK 21, Ghidra 12, CLI [`rea`](https://github.com/morluto/rea), cùng `upx`, `py-tlsh`, `cryptography` (tùy chọn).

Phản biện lớp 2 dùng LLM có sẵn trên máy: CLI `claude`/`codex`/`copilot`/`gemini`/`cursor-agent` đã đăng nhập, API chuẩn OpenAI, hoặc LLM local. Không có LLM nào thì dán prompt vào chat web.

Không cần, và **không được**, cài wine để chạy mẫu.

## 2. Cài đặt

```bash
npx github:thaoht2109/rea-workflow -g        # cài toàn máy; hỏi trước khi cài công cụ còn thiếu
npx github:thaoht2109/rea-workflow -g -y     # không hỏi gì
npx github:thaoht2109/rea-workflow           # chỉ cho project hiện tại
```

Lệnh này cài skill cho các agent bạn chọn, chép quy tắc bắt buộc vào `CLAUDE.md`/`AGENTS.md`/`GEMINI.md`, rồi kiểm và cài công cụ phân tích (apt cần sudo; Ghidra khoảng 550 MiB, bỏ bằng `--no-ghidra`).

Dưới đây `$SKILL` là thư mục skill vừa cài, thường là `~/.claude/skills/rea-flow` hoặc `~/.agents/skills/rea-flow` (xem bằng `npx skills list -g`).

```bash
python3 $SKILL/flow.py doctor     # kiểm cấu hình: OK / THIẾU / WARN cho từng mục
python3 $SKILL/flow.py setup      # kiểm lại công cụ; --yes để cài phần thiếu
```

**Khuyên dùng với Claude Code:** cài một lần hàm shell để mở phiên phân tích gọn, tức là chỉ giữ công cụ dịch ngược và ít ngữ cảnh nền hơn:

```bash
cd ~/malware-cases                         # thư mục chứa các case (workspace)
python3 $SKILL/flow.py session --install   # từ đó gõ `claude` trong workspace là mở phiên gọn; gỡ: --uninstall
```

Không có Node: `git clone https://github.com/thaoht2109/rea-workflow.git ~/.claude/skills/rea-flow && python3 ~/.claude/skills/rea-flow/flow.py rules --global`.

## 3. Sử dụng

Mở agent trong workspace rồi giao việc bằng lời, ví dụ: *"Phân tích mẫu `~/samples/invoice.zip` (mật khẩu `infected`) theo rea-flow"*. Agent tự làm các bước sau:

1. tạo case, chép mẫu ở chế độ chỉ đọc, giải nén, triage;
2. leo dần từ bước rẻ đến bước đắt (triage → bóc vỏ → decompile → giả lập → payload), ghi mỗi kết luận thành fact;
3. đến mốc thì đề nghị bạn `/clear` để giảm ngữ cảnh, rồi làm tiếp từ đúng chỗ dừng;
4. chạy cổng phản biện, hỏi bạn có chấp nhận các mục checklist không đạt được hay không;
5. sinh báo cáo cuối.

Bạn chỉ cần trả lời khi agent hỏi và gõ `/clear` khi được đề nghị. Muốn tự chạy thì dùng các lệnh chính sau:

```bash
python3 $SKILL/flow.py new CASE mẫu.exe        # tạo case và triage
python3 $SKILL/flow.py next CASE               # việc kế tiếp, lệnh đã điền sẵn
python3 $SKILL/flow.py review CASE --llm       # cổng phản biện
python3 $SKILL/flow.py report CASE --final     # báo cáo cuối (chỉ chạy khi phản biện đạt)
python3 $SKILL/flow.py help                    # mọi lệnh
```

**Chia sẻ kinh nghiệm giữa các server.** Kho tra chéo tự dựng ở lần phân tích đầu tiên và tự cập nhật khi đóng case. Muốn chuyển sang server khác, hoặc giữ một bản dự phòng:

```bash
python3 $SKILL/flow.py kb export kb-srv1.jsonl.gz --name srv1   # máy nguồn
python3 $SKILL/flow.py kb import kb-srv1.jsonl.gz               # máy nhận
```

File xuất ra không chứa mẫu nhưng có hash và IOC: chỉ chép qua kênh tin cậy (SSH, ổ mã hoá), không gửi qua email hay chat, không đưa lên repo public. Gợi ý từ kho chỉ là điểm bắt đầu, không phải kết luận.

## 4. Phản biện bằng LLM và AI local

Mặc định skill tự chọn LLM có trên máy để phản biện. Muốn dữ liệu không rời mạng nội bộ thì dùng LLM local, khai trong `~/.config/rea-flow/rea.env`:

```bash
REVIEW_LLM=api
REVIEW_API_BASE=http://10.0.0.5:11434/v1    # Ollama; vLLM / llama.cpp thường là http://HOST:8000/v1
REVIEW_MODEL=qwen2.5-coder:32b
```

Nên dùng model từ khoảng 32B và đặt ngữ cảnh server ≥ 32k token (Ollama: `OLLAMA_CONTEXT_LENGTH=32768`). Kiểm bằng `flow.py doctor`.

**Chạy cả vòng phân tích bằng AI local:** dùng Ollama làm model, OpenCode hoặc Codex CLI làm runtime.

```bash
OLLAMA_CONTEXT_LENGTH=64000 ollama serve && ollama pull qwen3-coder:30b
npx github:thaoht2109/rea-workflow -g -a opencode -a codex
cd <workspace> && python3 $SKILL/flow.py rules --project .
# OpenCode:  python3 $SKILL/flow.py opencode --model qwen3-coder:30b && opencode
# Codex CLI: ollama launch codex --config && codex --profile ollama-launch --sandbox workspace-write
```

`flow.py opencode` sinh cấu hình đã chặn sẵn lệnh chạy mẫu và lệnh mạng. Luật này chỉ để tránh chạy nhầm, không phải ranh giới bảo mật, nên hãy chạy trong VM không có Internet. Không dùng tag model `-cloud`.

## 5. Cấu hình

Mặc định đủ dùng khi công cụ nằm trên `PATH`. Cần đổi thì chép file mẫu rồi sửa:

```bash
mkdir -p ~/.config/rea-flow && cp $SKILL/rea.env.example ~/.config/rea-flow/rea.env
```

File cấu hình nằm ngoài thư mục skill nên cập nhật skill không làm mất. Biến môi trường cùng tên ghi đè file. Các biến hay dùng:

| Biến | Mặc định | Ý nghĩa |
|---|---|---|
| `GHIDRA_INSTALL_DIR`, `JAVA_HOME` | `setup` tự ghi | Ghidra 12, JDK 21 |
| `REA_TMP` | `.tmp` | thư mục tạm cho Ghidra; đặt trên đĩa thật nếu `/tmp` nhỏ |
| `REVIEW_LLM`, `REVIEW_MODEL` | `auto`, trống | LLM phản biện (mục 4) |
| `REA_KB` | `~/.cache/rea-flow/kb` | kho tra chéo; `off` để tắt |

Danh sách đầy đủ và giải thích từng biến nằm trong `rea.env.example`.

## 6. An toàn

- **Không thực thi mẫu, không chạm hạ tầng của kẻ tấn công**, không tra mẫu trên dịch vụ ngoài. Quy tắc nằm ở `SKILL.md`. Tải payload thật chỉ khi người dùng cho phép.
- Phản biện lớp 2 gửi fact, bằng chứng và chuỗi trích từ mẫu tới nhà cung cấp LLM đang dùng. Cần giữ dữ liệu trong nội bộ thì dùng LLM local.
- Kho tra chéo và file `kb export` có IOC: chỉ để trên máy (quyền 0600), chỉ chép qua kênh tin cậy.
- Với agent không phải Claude Code, quy tắc "không thực thi mẫu" chỉ là hướng dẫn bằng chữ: bật chế độ hỏi trước khi chạy lệnh, hoặc sandbox của agent.
- Không đưa mẫu, thư mục case hay IOC vào repo, commit hay PR.

## 7. Cập nhật và gỡ

```bash
npx github:thaoht2109/rea-workflow version -g               # bản đang cài và các bản có trên GitHub
npx github:thaoht2109/rea-workflow update -g                # lên bản mới nhất
npx github:thaoht2109/rea-workflow update -g --to v1.5.0    # lên hoặc hạ đúng một bản
npx github:thaoht2109/rea-workflow remove -g                # gỡ quy tắc và skill
```

Mỗi bản phát hành là một tag `vX.Y.Z` ([danh sách](https://github.com/thaoht2109/rea-workflow/tags)). Gỡ skill không xóa cấu hình, công cụ đã cài, kho tra chéo hay các case.

## 8. Phát triển

```bash
cd $SKILL && ruff check . && python3 -m pytest --import-mode=importlib -q -p no:cacheprovider tests
python3 $SKILL/flow.py doctor
```

Tài liệu cho agent: `SKILL.md` (quy tắc và lệnh), `FLOW.md` (quy trình chi tiết). Mỗi thay đổi đi qua PR có CI và AI review. Khi đổi hành vi thì tăng `version` trong `package.json`: sửa lỗi tăng số cuối, thêm tính năng tăng số giữa, đổi định dạng fact/cấu hình tăng số đầu. Giấy phép: MIT.
