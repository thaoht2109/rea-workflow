# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

# rea-flow: mã nguồn skill

Repo **công khai** chứa skill dịch ngược mã độc rea-flow, viết bằng Python thuần. Agent nạp `SKILL.md`. Quy trình chi tiết ở `FLOW.md`, hướng dẫn người dùng ở `README.md`. File này chỉ phục vụ việc **sửa mã của skill**, không phải việc phân tích một mẫu.

## Ràng buộc của repo

- Không đưa tên case, tên mẫu, IOC hay đường dẫn máy cá nhân vào mã, test, commit message hay mô tả PR.
- Không thêm bất kỳ đường nào thực thi mẫu: wine, qemu, chạy script của mẫu, `rea capture-*`, `debug-with-gdb`. Chỉ cho phép phân tích tĩnh và giả lập CPU (`winemu/`).
- Test trong `tests/` chỉ dùng dữ liệu tổng hợp. Hồi quy cần mẫu thật đặt ngoài repo, ví dụ `<workspace>/local/tests/`.
- Mã được viết nén có chủ ý. ruff chỉ bật `E9` và `F` (`ruff.toml`), đừng định dạng lại hay "dọn" style.
- Làm trên nhánh `feat/...` hoặc `fix/...` rồi mở PR vào `main`. Tăng `version` trong `package.json` ngay trong PR: sửa lỗi tăng số cuối, thêm tính năng tăng số giữa, đổi định dạng facts hoặc cấu hình tăng số đầu. `tag.yml` tự gắn tag `vX.Y.Z` khi PR vào `main`.

## Lệnh

```bash
pip install -r requirements-dev.txt                    # pytest, pefile
pip install -r .github/ci/requirements-ci-tools.txt    # ruff, bandit, pip-audit (bản CI dùng)
ruff check .
python -m pytest --import-mode=importlib -q -p no:cacheprovider tests   # giống CI
python3 tests/check_gate.py                            # chạy một test riêng: mỗi tests/check_*.py là script độc lập, mã 0 = đạt
python3 case.py --selftest && python3 review.py --selftest && python3 reviewer.py --selftest && python3 install_tools.py --selftest
python3 flow.py doctor                                 # kiểm cấu hình theo máy (~/.config/rea-flow/rea.env)
```

`tests/test_checks.py` chỉ là vỏ: nó tham số hóa pytest để chạy từng `check_*.py` thành một subprocess. Muốn thêm test thì tạo một file `tests/check_<tên>.py` mới, không cần đăng ký ở đâu.

CI (`.github/workflows/ci.yml`) gồm các job sau: lint (ruff + actionlint) → build (`compileall`, `pip check`) → unit-test, cùng với sast (bandit so theo `.bandit-baseline.json` qua `.github/ci/bandit_gate.sh`), secrets và deps (`pip-audit`). Thêm cảnh báo bandit mới so với baseline thì CI đỏ.

## Kiến trúc

- **`flow.py`** là bộ điều phối và là CLI duy nhất người dùng gọi. Logic nằm ở các module khác: `case` và `review` được import trực tiếp, `static/triage.py` chạy qua subprocess (`python3 -I`). Docstring đầu file là nguồn duy nhất của danh sách lệnh (`flow.py help`). SKILL/README/FLOW không chép lại danh sách này, nên thêm lệnh thì sửa ở docstring đó. `flow.py next` dẫn agent từng bước, nên khi đổi quy trình phải sửa cả output của `next`/`status`/`resume`.
- **`case.py`** là kho fact của một case: `facts.jsonl` chỉ ghi thêm, sửa một fact bằng fact mới có `supersedes`.
  - `add` chạy `lint_fact()` trước khi ghi, gồm các kiểm tra:
    - evidence nằm trong `report/evidence/`;
    - token của `value` có trong ±`WINDOW` dòng quanh `#L`;
    - `src` khớp loại evidence;
    - hash tính lại được;
    - `recompute` đếm lại các con số.
  - `KINDS` là danh sách loại fact hợp lệ.
  - `check` tính checklist C0–C11.
  - `report` sinh `GENERATED.md` cùng bảng đính chính từ chuỗi `supersedes`.
  - `audit` đối chiếu evidence được trích trong README với đĩa.
- **Cổng phản biện hai lớp:**
  - `review.py` là lớp 1: kiểm bằng máy, chạy lại `recompute`, giới hạn tối đa 2 lần review, có trạng thái STOPPED/`STOP_REPORT.md`. File này cũng chứa `review-loop`, `gate` và `next --accept`.
  - `reviewer.py` là lớp 2: dựng hồ sơ tự chứa, gửi cho một phiên LLM mới, cô lập, chỉ đọc, qua backend claude/codex/copilot/gemini/cursor, `api` (chuẩn OpenAI, kể cả LLM local), `cmd` hoặc `manual`. Backend được chọn ở `reacfg.review_backend()`. Hỗ trợ `--detach`: mã 6 là đang chạy nền, mã 7 là tiến trình chết, mã 4 là chờ manual.
  - Prompt và kiến thức RE dùng chung nằm ở `review/`.
  - `flow.py report --final` chỉ chạy khi cổng đạt.
- **`static/`**: `triage.py` sinh `triage_*.json` (`ioc_candidates` không tự thành fact) và định tuyến theo loại file. Ngoài ra có `gopclntab.py`, `nsis/` và các script Ghidra headless cho kiến trúc mà `rea` không hỗ trợ.
- **`winemu/`**: giả lập Windows x86-32 trên unicorn, bản vendored ở `pylib/` (bị gitignore và được cài bởi `install_tools.py`). `summarize.py` tóm tắt log. `plugins/` chứa plugin theo họ mã độc.
- **Cài đặt**: `install.mjs` là bộ cài npx, chạy `skills add/update`, `flow.py rules` và `flow.py setup`. `install_tools.py` kiểm và cài công cụ (`flow.py setup`). `reacfg.py` đọc `rea.env` và chạy `doctor`. `templates/` chứa khung báo cáo và `opencode.json`.
- **Quy tắc bắt buộc**: mục "Quy tắc bắt buộc" trong `SKILL.md` là bản gốc. `flow.py rules` chép nó vào CLAUDE.md/AGENTS.md của người dùng, đặt giữa cặp marker `rea-flow:rules`. Muốn đổi quy tắc thì sửa `SKILL.md`, không sửa bản chép.

## AI review của PR

`ai-review.yml` chạy **sau** CI (`workflow_run`), nên `gh pr checks` không hiện kết quả của nó. Kết quả nằm trong comment của bot trên PR. Bot có thể tự sửa và tự merge khi PASS, nhưng không tự đẩy bản sửa và không tự merge PR đụng tới các file cổng: `.github/`, `tests/`, `review/`, `review.py`, `reviewer.py`, `install_tools.py`, `install.mjs`, `ruff.toml`, `requirements-*.txt`, `.bandit-baseline.json` (danh sách đầy đủ ở `GATE_FILES_RE` trong `.github/ci/ai-review-lib.sh`). PR có nhãn `no-auto-merge` cũng không được tự merge.
