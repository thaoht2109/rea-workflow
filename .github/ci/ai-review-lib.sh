#!/usr/bin/env bash
# Hàm cho .github/workflows/ai-review.yml (trigger workflow_run sau workflow CI).
#
# Workflow chạy SAU workflow CI (trigger workflow_run), mỗi lượt làm tối đa MỘT việc:
#   cổng (gate) → review đầy đủ HOẶC kiểm lại → [FAIL ∧ còn lượt ∧ không có nhãn human] auto-fix + push → dừng.
# Push của bot dùng PUSH_TOKEN (PAT/GitHub App, KHÔNG phải GITHUB_TOKEN) nên KÍCH HOẠT CI thật; CI xanh
# lại gọi workflow này cho commit mới. Không có vòng lặp trong một lượt chạy: số lần đã fix = số commit
# auto-fix trong PR (count_fixes), tối đa MAX_FIXES; lỗi của các lượt trước nằm trong comment của bot.
#
# Workflow copy file này (bản trên nhánh mặc định, vì workflow_run luôn chạy từ đó) ra $RUNNER_TEMP rồi source từ
# đó — KHÔNG source từ workspace, vì bước auto-fix cho Claude quyền ghi file trong workspace.
#
# Env cần có: GH_TOKEN (token mặc định của job) PUSH_TOKEN (token của bot: push auto-fix + merge)
#   PR REPO EVENT_HEAD_SHA CI_CONCLUSION RUN_URL MAX_FIXES (+ RUNNER_TEMP);
#   BASE_REF / HEAD_REF do `gate` ghi vào GITHUB_ENV. Tuỳ chọn: AI_AUTO_MERGE (mặc định false),
#   EXTRA_GATE_FILES (regex ERE repo gọi tới THÊM vào GATE_FILES_RE).
# Code PR ở ./pr-head, input cho Claude ở ./.ai-review. 
set -euo pipefail

D=.ai-review
STATE=${STATE:-$RUNNER_TEMP/ai-review-state}   # ngoài workspace: Claude không ghi tới
FIX_PREFIX='fix(ai-review): auto-fix'
FIX_LABEL=ai-review-fix-needs-human   # người gắn: tắt auto-fix VÀ auto-merge cho PR này
STOP_LABEL=ai-review-needs-human      # bot gắn khi hết lượt fix mà vẫn FAIL: dừng, chờ người
# Git trong pr-head luôn chạy với hook/fsmonitor tắt: thư mục đó chứa file do PR quyết định.
# Sau before_fix, .git của pr-head nằm ở $STATE/pr.git (ngoài workspace, Claude không ghi tới) và
# pr-head chỉ còn là work-tree: file .git/config|commondir do bước fix dựng lại bị bỏ qua hoàn toàn.
# Mọi git chạy với gitconfig toàn cục/hệ thống tắt (~/.gitconfig, /etc/gitconfig có thể bị bước fix ghi).
# PGIT_EXTRA_CONFIG ("key=value") CHỈ DÀNH CHO TEST (test_lib.sh dùng để rewrite URL push); production không đặt.
pgit() {
  local -a extra=()
  # Bị bỏ qua trong GitHub Actions và nếu không phải dạng url.* (env bị tiêm không đổi được URL push/fsmonitor).
  if [ "${GITHUB_ACTIONS:-}" != true ] && [[ "${PGIT_EXTRA_CONFIG:-}" == url.* ]]; then extra=(-c "$PGIT_EXTRA_CONFIG"); fi
  if [ -d "$STATE/pr.git" ]; then
    env GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_NOSYSTEM=1 git --git-dir="$STATE/pr.git" --work-tree=pr-head \
      -c core.hooksPath=/dev/null -c core.fsmonitor= ${extra[@]+"${extra[@]}"} "$@"
  else
    env GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_NOSYSTEM=1 git -C pr-head \
      -c core.hooksPath=/dev/null -c core.fsmonitor= ${extra[@]+"${extra[@]}"} "$@"
  fi
}

# Đường dẫn cấu hình cổng CI: PR/bản fix sửa chúng thì không auto-push, không auto-merge (cần người duyệt).
# ruff/bandit đọc cả file cấu hình lồng trong thư mục con ⇒ chặn tên đó ở mọi nơi; pytest/conftest gốc quyết định unit/integration;
# gitleaks tự nạp .gitleaks.toml ở gốc; requirements-dev.txt cài plugin pytest vào stage test.
GATE_FILES_RE='^(\.github/|tests/|review/|reviewer\.py$|review\.py$|install_tools\.py$|install\.mjs$|ruff\.toml$|\.bandit-baseline\.json$|\.gitleaksignore$|\.pip-audit-ignore$|requirements-ci-tools\.txt$|requirements-dev\.txt$|\.gitleaks\.toml$|conftest\.py$|pytest\.ini$|tox\.ini$|setup\.cfg$)|(^|/)(\.?ruff\.toml|pyproject\.toml|\.bandit)$'
# Repo gọi tới chỉ được THÊM mẫu (nối `|` ở mức ngoài cùng ⇒ tập khớp chỉ lớn lên): chặn thêm, không nới được.
if [ -n "${EXTRA_GATE_FILES:-}" ]; then GATE_FILES_RE="$GATE_FILES_RE|$EXTRA_GATE_FILES"; fi
# 0 = có file cổng trong stdin, HOẶC regex hỏng (grep thoát 2 ⇒ fail closed); 1 = không có.
gate_match() { local rc=0; grep -qE "$GATE_FILES_RE" || rc=$?; [ "$rc" -ne 1 ]; }

labels() { gh pr view "$PR" --repo "$REPO" --json labels --jq '.labels[].name'; }
# blocked LABELS — PR có nhãn nào liên quan "cần người" thì không auto-fix, không auto-merge.
blocked() { grep -qxE "$FIX_LABEL|$STOP_LABEL" <<<"$1"; }

# ── comment của bot: nơi lưu trạng thái giữa các lượt chạy ──────────────────────────────────
# Một comment cố định mỗi PR, chỉ comment do workflow đăng. Cuối comment có khối ẩn
# `<!-- ai-review-findings: BASE64(JSON) -->` = lỗi blocker/major CỘNG DỒN của mọi lượt, và
# `<!-- ai-review-sha: <40 hex> -->` = commit đã được review ở lượt gần nhất. Luôn lấy marker CUỐI
# (marker giả nằm trong nội dung model đứng trước marker thật). Lỗi gọi gh ⇒ return 1, KHÔNG coi như rỗng.
bot_comment() {   # in {id, body} của comment bot mới nhất (không in gì nếu chưa có)
  gh api "repos/$REPO/issues/$PR/comments" --paginate \
    --jq '.[] | select(.user.login == "github-actions[bot]" and (.body | startswith("<!-- ai-review -->"))) | {id, body}' \
    | jq -s -c 'sort_by(.id) | last // empty'
}
upsert_comment() {
  local id
  id=$(bot_comment | jq -r '.id // empty') || return 1
  if [ -n "$id" ]; then
    gh api -X PATCH "repos/$REPO/issues/comments/$id" -F body=@"$1" >/dev/null || return 1
  else
    gh pr comment "$PR" --repo "$REPO" --body-file "$1" >/dev/null || return 1
  fi
}
cur_marker() {    # in lại cả hai khối ẩn hiện có (để comment "bỏ qua"/"dừng" không làm mất trạng thái)
  local body
  body=$(bot_comment | jq -r '.body // empty') || return 1
  grep -o '<!-- ai-review-findings: [A-Za-z0-9+/=]* -->' <<<"$body" | tail -1 || true
  grep -oE '<!-- ai-review-sha: [0-9a-f]{40} -->' <<<"$body" | tail -1 || true
}
load_prev() {     # ghi $STATE/prev_findings.json từ khối ẩn ([] nếu chưa có hoặc hỏng)
  local body b64
  body=$(bot_comment | jq -r '.body // empty') || return 1
  b64=$(grep -o 'ai-review-findings: [A-Za-z0-9+/=]*' <<<"$body" | tail -1 | cut -d' ' -f2 || true)
  if [ -n "$b64" ] && base64 -d <<<"$b64" 2>/dev/null | jq -e 'type == "array" and all(.[]; type == "object")' >/dev/null 2>&1; then
    base64 -d <<<"$b64" > "$STATE/prev_findings.json"
  else
    echo '[]' > "$STATE/prev_findings.json"
  fi
}
load_reviewed_sha() {   # in sha 40-hex đã review ở lượt gần nhất (rỗng nếu chưa có / không hợp lệ)
  local body
  body=$(bot_comment | jq -r '.body // empty') || return 1
  grep -oE 'ai-review-sha: [0-9a-f]{40} -->' <<<"$body" | tail -1 | cut -d' ' -f2 || true
}

# ── cổng ─────────────────────────────────────────────────────────────────────────────────────
# ci_failed — CI không xanh: không gọi AI. Nếu commit đầu PR là commit auto-fix của bot thì dừng hẳn
# (gắn nhãn STOP_LABEL), vì quyết định là không đưa lỗi CI cho Sonnet sửa tiếp.
# Chủ ý: MỌI kết luận khác `success` (failure, timed_out, startup_failure, action_required, neutral,
# skipped, stale...) đều coi là chưa xanh ⇒ trên commit auto-fix của bot thì dừng hẳn.
ci_failed() {
  local subject marker
  subject=$(gh api "repos/$REPO/commits/$EVENT_HEAD_SHA" --jq '.commit.message | split("\n")[0]') || return 1
  marker=$(cur_marker) || return 1
  {
    echo "<!-- ai-review -->"
    echo "## AI review: bỏ qua — CI chưa xanh (\`$CI_CONCLUSION\`)"
    echo
    echo "AI review chỉ chạy sau khi các kiểm tra cố định (tests, lint, sast, secrets, deps, workflows) xanh."
    if [[ "$subject" == "$FIX_PREFIX"* ]]; then
      echo
      echo "Commit này do bot auto-fix tạo ra và làm CI đỏ ⇒ **dừng tự động**, cần người kiểm tra."
    fi
    echo
    echo "$marker"
    echo "[Log lượt chạy]($RUN_URL)"
  } > "$STATE/ci_failed.md"
  upsert_comment "$STATE/ci_failed.md" || return 1
  if [[ "$subject" == "$FIX_PREFIX"* ]]; then
    gh label create "$STOP_LABEL" --repo "$REPO" --color b60205 --force \
       --description "AI review dừng — cần người kiểm tra" >/dev/null || return 1
    gh pr edit "$PR" --repo "$REPO" --add-label "$STOP_LABEL" >/dev/null || return 1
  fi
}

# gate — lượt chạy này có xử lý PR không? Output proceed=true|false; khi true ghi BASE_REF/HEAD_REF
# vào GITHUB_ENV. Chỉ xử lý: PR mở, không draft, cùng repo, head == commit vừa chạy CI, không phải
# PR chỉ sửa tài liệu, và CI xanh. Thiếu PUSH_TOKEN thì dừng to tiếng (không âm thầm không fix/merge).
gate() {
  local info files
  mkdir -p "$STATE" "$D"
  if [ -z "${PUSH_TOKEN:-}" ]; then
    echo "::error::Thiếu secret BOT_PUSH_TOKEN (token push/merge của bot)"; return 1
  fi
  info=$(gh pr view "$PR" --repo "$REPO" --json isDraft,state,headRefOid,baseRefName,headRefName,isCrossRepository) || return 1
  skip() { echo "::notice::Bỏ qua AI review: $1"; echo "proceed=false" >> "$GITHUB_OUTPUT"; }
  [ "$(jq -r .state <<<"$info")" = OPEN ] || { skip "PR không còn mở"; return 0; }
  [ "$(jq -r .isDraft <<<"$info")" = false ] || { skip "PR là draft"; return 0; }
  [ "$(jq -r .isCrossRepository <<<"$info")" = false ] || { skip "PR từ fork"; return 0; }
  # CI chỉ kiểm chứng so với main; một nhánh đầu của 2 PR có thể làm workflow_run trỏ tới PR vào nhánh khác.
  [ "$(jq -r .baseRefName <<<"$info")" = "${AI_BASE_BRANCH:-main}" ] || { skip "PR không nhắm nhánh main"; return 0; }
  [ "$(jq -r .headRefOid <<<"$info")" = "$EVENT_HEAD_SHA" ] || { skip "PR đã có commit mới hơn commit vừa chạy CI"; return 0; }
  # Danh sách file ĐẦY ĐỦ qua REST phân trang (gh pr view --json files bị cắt ở 100 file).
  # Mỗi file một dòng true/false (test theo TỪNG tên, nên tên có xuống dòng không giả được docs-only).
  # API cắt ở 3000 file ⇒ từ 3000 trở lên không thể khẳng định "chỉ tài liệu".
  files=$(gh api "repos/$REPO/pulls/$PR/files" --paginate --jq '.[].filename | test("\\Adocs/|[.]md\\z")') || return 1
  if [ -n "$files" ] && [ "$(grep -c . <<<"$files")" -lt 3000 ] && ! grep -qx false <<<"$files"; then
    skip "PR chỉ sửa tài liệu"; return 0
  fi
  if [ "$CI_CONCLUSION" != success ]; then
    ci_failed || return 1; skip "CI chưa xanh ($CI_CONCLUSION)"; return 0
  fi
  {
    echo "BASE_REF=$(jq -r .baseRefName <<<"$info")"
    echo "HEAD_REF=$(jq -r .headRefName <<<"$info")"
  } >> "${GITHUB_ENV:-/dev/null}"
  echo "proceed=true" >> "$GITHUB_OUTPUT"
}

# fetch_ci_report — tải artifact `ci-report` của lượt CI vừa xong (CI_RUN_ID = workflow_run.id) vào
# $D/ci-report/ci-report.md cho Opus/Sonnet đọc. Nội dung do code PR sinh ra ⇒ chỉ là DỮ LIỆU; cắt tối đa
# 60000 byte. Không tải được ⇒ ghi một dòng 'không có báo cáo' (KHÔNG chặn review: tới đây CI đã xanh).
fetch_ci_report() {
  local tmp src out="$D/ci-report/ci-report.md" ok=false
  rm -rf "$D/ci-report"; mkdir -p "$D/ci-report" "$STATE"
  if [ -z "${CI_RUN_ID:-}" ]; then
    echo "::warning::Thiếu CI_RUN_ID — không tải được báo cáo CI"
  else
    tmp=$(mktemp -d "$STATE/ci-report.XXXXXX") || return 1
    src="$tmp/ci-report.md"
    if gh run download "$CI_RUN_ID" --repo "$REPO" -n ci-report -D "$tmp" >/dev/null 2>&1 \
       && [ -f "$src" ] && [ ! -L "$src" ]; then
      head -c 60000 "$src" > "$out"; ok=true
      echo "::notice::Đã tải báo cáo CI ($(wc -c < "$out") byte)"
    else
      echo "::warning::Không tải được artifact ci-report của lượt CI $CI_RUN_ID"
    fi
    rm -rf "$tmp"
  fi
  if [ "$ok" != true ]; then echo "không có báo cáo CI (artifact ci-report không tải được)" > "$out"; fi
  return 0
}

# ── chuẩn bị lượt ────────────────────────────────────────────────────────────────────────────
prep_diff() {
  mkdir -p "$D" "$STATE"
  if [ "$(pgit rev-parse HEAD)" != "$EVENT_HEAD_SHA" ]; then
    echo "::error::pr-head không ở commit vừa chạy CI ($EVENT_HEAD_SHA) — huỷ"; return 1
  fi
  pgit rev-parse HEAD > "$STATE/head_sha"
  # Symlink trong PR: chặn TRƯỚC khi AI đọc/ghi (workflow bỏ qua các bước model khi blocked=true).
  if [ -n "$(find pr-head -type l -not -path 'pr-head/.git/*' -print -quit)" ]; then
    echo "::error::PR chứa symlink — dừng trước khi AI đọc"
    local marker
    marker=$(cur_marker) || return 1
    {
      echo "<!-- ai-review -->"
      echo "## AI review: dừng — PR chứa symlink"
      echo
      echo "Không chạy AI trên PR có symlink (rủi ro ghi/đọc ngoài workspace). Cần người xử lý."
      echo
      echo "$marker"
      echo "[Log lượt chạy]($RUN_URL)"
    } > "$STATE/blocked.md"
    upsert_comment "$STATE/blocked.md" || return 1
    gh label create "$STOP_LABEL" --repo "$REPO" --color b60205 --force \
       --description "AI review dừng — cần người kiểm tra" >/dev/null || return 1
    gh pr edit "$PR" --repo "$REPO" --add-label "$STOP_LABEL" >/dev/null || return 1
    echo "blocked=true" >> "$GITHUB_OUTPUT"; return 0
  fi
  echo "blocked=false" >> "$GITHUB_OUTPUT"
  pgit log --oneline "origin/$BASE_REF..HEAD" > "$D/log.txt"
  pgit diff --stat "origin/$BASE_REF...HEAD" > "$D/files.txt"
  pgit diff "origin/$BASE_REF...HEAD" > "$D/diff.patch"
}

# count_fixes — số commit auto-fix của bot trong PR (so với nhánh base).
count_fixes() {
  pgit log --format=%s "origin/$BASE_REF..HEAD" | awk -v p="$FIX_PREFIX" 'index($0, p) == 1 { n++ } END { print n + 0 }'
}

# prep_round — chọn loại lượt. kind=recheck CHỈ KHI comment bot có sha đã review, sha đó còn là tổ tiên
# của HEAD và PR có commit auto-fix: khi đó chỉ kiểm lỗi cũ (từ comment, KHÔNG từ workspace) + diff
# từ commit đã review gần nhất đến HEAD. Mọi trường hợp khác (chưa review, amend/rebase, commit giả
# tiền tố auto-fix) ⇒ kind=review: review cả PR.
prep_round() {
  local reviewed fixes
  load_prev || return 1
  reviewed=$(load_reviewed_sha) || return 1
  fixes=$(count_fixes) || return 1
  if [ -n "$reviewed" ] && [ "$fixes" -gt 0 ] && pgit merge-base --is-ancestor "$reviewed" HEAD 2>/dev/null; then
    cp "$STATE/prev_findings.json" "$D/prev_findings.json"
    pgit diff "$reviewed" HEAD > "$D/fix.patch" || return 1
    echo "kind=recheck" >> "$GITHUB_OUTPUT"
  else
    echo "kind=review" >> "$GITHUB_OUTPUT"
  fi
}

# ── ghi nhận kết quả ─────────────────────────────────────────────────────────────────────────
# record — đọc kết quả review từ env RESULT, ghi comment/summary. Output: verdict=PASS|FAIL,
# fix=true|false (có auto-fix tiếp không: FAIL có lỗi cụ thể, còn lượt, PR không có nhãn "cần người").
record() {
  local result=${RESULT:-} symlink prev_sha verdict blocking sha fixes round fix=false lbl all real=true shamark=
  # "Kết quả thật" = đúng cấu trúc: verdict PASS|FAIL, findings là mảng object.
  if ! jq -e '(.verdict | IN("PASS","FAIL")) and (.findings | type == "array") and all(.findings[]; type == "object")' >/dev/null 2>&1 <<<"$result"; then
    real=false
    result='{"verdict":"FAIL","summary":"Không nhận được kết quả review (lỗi action, token hết hạn/hết lượt). Xem log lượt chạy.","findings":[]}'
  fi
  # Fail closed: có finding blocker/major thì FAIL dù model trả PASS.
  blocking=$(jq '[.findings[] | select(.severity != "minor")]' <<<"$result") || return 1
  verdict=$(jq -r --argjson b "$blocking" 'if ($b | length) > 0 then "FAIL" elif .verdict == "PASS" then "PASS" else "FAIL" end' <<<"$result") || return 1
  echo "$blocking" > "$D/findings.json"       # cho Claude đọc (auto-fix ghi được vào đây)
  echo "$blocking" > "$STATE/findings.json"   # bản tin cậy, ngoài workspace
  # Cộng dồn lỗi của MỌI lượt (lấy từ comment, không từ workspace): lượt kiểm lại phải biết cả lỗi
  # lượt đầu để bắt trường hợp bản sửa sau hoàn tác bản sửa trước.
  load_prev || return 1
  all=$(jq -s 'add | unique_by([.file, (.line // 0), .title])' "$STATE/prev_findings.json" "$STATE/findings.json")
  echo "$all" > "$STATE/all_findings.json"
  echo "$verdict" > "$STATE/verdict"
  sha=$(cat "$STATE/head_sha"); fixes=$(count_fixes) || return 1; round=$((fixes + 1))

  # Symlink trong PR + bước fix có quyền ghi ⇒ có thể ghi xuyên ra ngoài workspace: không auto-fix.
  symlink=$(find pr-head -type l -not -path 'pr-head/.git/*' -print -quit) || return 1
  if [ "$verdict" = FAIL ] && [ "$(jq length <<<"$blocking")" -gt 0 ] && [ "$fixes" -lt "$MAX_FIXES" ] && [ -z "$symlink" ]; then
    lbl=$(labels) || return 1
    if ! blocked "$lbl"; then fix=true; fi
  fi

  # Chỉ ghi sha mới khi CÓ kết quả review thật; nếu không (kết quả rỗng/hỏng ⇒ FAIL tổng hợp) thì giữ
  # nguyên sha của lượt review thật trước đó — commit chưa được review KHÔNG được neo thành "đã review".
  if [ "$real" = true ]; then
    shamark="<!-- ai-review-sha: $sha -->"
  else
    prev_sha=$(load_reviewed_sha) || return 1
    if [ -n "$prev_sha" ]; then shamark="<!-- ai-review-sha: $prev_sha -->"; fi
  fi

  {
    echo "<!-- ai-review -->"
    echo "## AI review: $verdict — \`${sha::7}\` (lượt $round, đã auto-fix $fixes/$MAX_FIXES)"
    echo
    jq -r '.summary' <<<"$result"
    echo
    jq -r '.findings[] | "- **[\(.severity)]** `\(.file)\(if .line then ":\(.line)" else "" end)` — \(.title)\n  \(.detail)\(if .fix then "\n  _Sửa:_ \(.fix)" else "" end)"' <<<"$result"
    echo
    if [ -n "$symlink" ]; then echo "_PR chứa symlink — không auto-fix, cần người xử lý._"; fi
    if [ "$fix" = true ]; then echo "_Đang tự sửa (auto-fix $((fixes + 1))/$MAX_FIXES) — sau khi push, CI chạy lại rồi review lại._"; fi
    echo "<!-- ai-review-findings: $(base64 -w0 <<<"$all") -->"
    if [ -n "$shamark" ]; then echo "$shamark"; fi
    echo "[Log lượt chạy]($RUN_URL)"
  } > "$STATE/review.md"
  cat "$STATE/review.md" >> "$GITHUB_STEP_SUMMARY"
  upsert_comment "$STATE/review.md" || return 1

  echo "verdict=$verdict" >> "$GITHUB_OUTPUT"
  echo "fix=$fix" >> "$GITHUB_OUTPUT"
}

# Gọi TRƯỚC bước fix: tách .git của pr-head ra ngoài workspace (xem pgit). Bước fix (Claude có quyền
# ghi file) không thể đụng tới config/hook/commondir mà push_fix sẽ dùng với PUSH_TOKEN.
# Rồi bỏ quyền ghi (chống symlink trong PR trỏ tới pr.git); push_fix cấp lại quyền cho chính nó.
before_fix() {
  if [ ! -d pr-head/.git ]; then
    echo "::error::before_fix: pr-head/.git không còn (đã gọi before_fix rồi?)"; return 1
  fi
  if [ -d "$STATE/pr.git" ]; then chmod -R u+w "$STATE/pr.git" || return 1; fi
  rm -rf "$STATE/pr.git" || return 1
  mv pr-head/.git "$STATE/pr.git" || return 1
  chmod -R a-w "$STATE/pr.git" || return 1
}

# push_fix — commit + push thay đổi của auto-fix. Output pushed=true|false.
# Push bằng PUSH_TOKEN (không phải GITHUB_TOKEN) ⇒ KÍCH HOẠT CI thật cho commit này.
push_fix() {
  local fixes n names
  # Phải gọi before_fix trước (rc=1: lỗi cấu hình workflow, không phải "fix không push được").
  if [ ! -d "$STATE/pr.git" ]; then
    echo "::error::push_fix gọi trước before_fix — .git của pr-head chưa được tách khỏi workspace"
    echo "pushed=false" >> "$GITHUB_OUTPUT"; return 1
  fi
  chmod -R u+w "$STATE/pr.git" || return 1
  fixes=$(count_fixes) || return 1
  n=$((fixes + 1))
  pgit add -A || return 1
  # Tên file lấy từ diff --cached -z (không bị git quote, thấy cả đổi tên/xoá); không pipe thẳng vào grep -q (SIGPIPE).
  names=$(pgit diff --cached --name-only --no-renames -z | tr '\0' '\n') || return 1
  if [ -z "$names" ]; then
    echo "::warning::Auto-fix $n không thay đổi file nào"
    echo "pushed=false" >> "$GITHUB_OUTPUT"; return 0
  fi
  # Cổng review không được tự sửa mình; PAT cũng không có scope workflow.
  if gate_match <<<"$names"; then
    pgit reset -q || return 1
    echo "::error::Auto-fix $n sửa .github/ hoặc file cấu hình cổng CI — không push, cần người xử lý"
    echo "pushed=false" >> "$GITHUB_OUTPUT"; return 0
  fi
  pgit -c user.name="github-actions[bot]" \
       -c user.email="41898282+github-actions[bot]@users.noreply.github.com" \
       commit -q -m "$FIX_PREFIX $n/$MAX_FIXES cho PR #$PR" \
       -m "$(jq -r '.[] | "- \(.file): \(.title)"' "$STATE/findings.json")" || return 1
  # Non-fast-forward (người khác vừa push) ⇒ lỗi ⇒ dừng (return 1 tường minh: set -e không đáng tin trong hàm).
  if ! pgit push -q "https://x-access-token:${PUSH_TOKEN}@github.com/${REPO}.git" "HEAD:refs/heads/${HEAD_REF}"; then
    echo "::error::Push auto-fix $n thất bại (non-fast-forward?)"
    pgit reset -q --soft HEAD~1 || true   # gỡ commit cục bộ để count_fixes/finalize không đếm lố
    echo "pushed=false" >> "$GITHUB_OUTPUT"; return 1
  fi
  echo "pushed=true" >> "$GITHUB_OUTPUT"
}

# finalize [pushed] — kết thúc lượt chạy.
#   đã push auto-fix  ⇒ không làm gì thêm (CI sẽ chạy lại và gọi workflow này cho commit mới).
#   PASS              ⇒ merge (trừ khi có nhãn "cần người", no-auto-merge, hoặc AI_AUTO_MERGE != true).
#   FAIL không fix được (hết lượt / có nhãn / fix không thay đổi gì) ⇒ gắn STOP_LABEL, check đỏ.
finalize() {
  local pushed=${1:-false} verdict sha lbl files nf
  # pr.git có thể còn read-only nếu bước fix lỗi và push_fix không chạy: trả quyền để runner dọn được.
  if [ -d "$STATE/pr.git" ]; then chmod -R u+w "$STATE/pr.git" 2>/dev/null || true; fi
  verdict=$(cat "$STATE/verdict" 2>/dev/null || echo FAIL)
  sha=$(cat "$STATE/head_sha")
  if [ "$pushed" = true ]; then
    echo "::notice::Đã auto-fix và push; CI sẽ chạy lại rồi review lại"; return 0
  fi
  gh label create ai-review-failed --repo "$REPO" --color d73a4a --force >/dev/null
  gh label create "$STOP_LABEL" --repo "$REPO" --color b60205 --force \
     --description "AI review dừng — cần người kiểm tra" >/dev/null
  if [ "$verdict" = PASS ]; then
    gh pr edit "$PR" --repo "$REPO" --remove-label ai-review-failed >/dev/null || true
    lbl=$(labels) || return 1
    if blocked "$lbl" || grep -qx no-auto-merge <<<"$lbl"; then
      echo "::notice::PR có nhãn chặn merge (no-auto-merge hoặc nhãn cần người) — không tự merge"; return 0
    fi
    if [ "${AI_AUTO_MERGE:-false}" != true ]; then
      echo "::notice::AI_AUTO_MERGE tắt — PASS nhưng không tự merge"; return 0
    fi
    # Đã chạy bước fix trong job này (pr.git tồn tại) ⇒ chỉ xảy ra khi verdict là FAIL; file verdict có thể
    # đã bị ghi đè ⇒ không bao giờ merge.
    if [ -d "$STATE/pr.git" ]; then
      echo "::notice::Đã chạy bước auto-fix trong lượt này — không tự merge"; return 0
    fi
    # PR sửa .github/ (workflow có thể giả comment bot + marker) không bao giờ tự merge; lỗi gh ⇒ fail closed.
    # Danh sách file lấy CỤC BỘ từ git (đầy đủ; gh pr view --json files bị cắt ở 100). Rỗng = bất thường ⇒ fail closed.
    files=$(pgit diff --name-only --no-renames -z "origin/$BASE_REF...$sha" | tr '\0' '\n') || return 1
    if [ -z "$files" ]; then echo "::error::PR không có thay đổi so với base — không tự merge"; return 1; fi
    if gate_match <<<"$files"; then
      echo "::notice::PR sửa file cấu hình cổng CI — không tự merge, cần người duyệt"; return 0
    fi
    # Merge bằng PUSH_TOKEN (không phải GITHUB_TOKEN) để CI chạy tiếp trên main; ruleset (nếu có)
    # vẫn áp dụng cho token này. --match-head-commit: có push mới sau lượt review thì KHÔNG merge.
    if ! GH_TOKEN="$PUSH_TOKEN" gh pr merge "$PR" --repo "$REPO" --merge --match-head-commit "$sha"; then
      local mm=
      if [ ! -f "$STATE/review.md" ]; then mm=$(cur_marker) || return 1; fi
      {
        if [ -f "$STATE/review.md" ]; then cat "$STATE/review.md"; else echo "<!-- ai-review -->"; echo "$mm"; fi
        echo
        echo "**Merge thất bại (nhánh lạc hậu so với base, hết hạn token hoặc xung đột) — cần người xử lý.**"
      } > "$STATE/merge_failed.md"
      upsert_comment "$STATE/merge_failed.md" || return 1
      echo "::error::gh pr merge thất bại — xem comment trên PR #$PR"
      return 1
    fi
    return 0
  fi
  gh pr edit "$PR" --repo "$REPO" --add-label ai-review-failed --add-label "$STOP_LABEL" >/dev/null
  local marker=
  if [ ! -f "$STATE/review.md" ]; then marker=$(cur_marker) || return 1; fi
  {
    if [ -f "$STATE/review.md" ]; then
      cat "$STATE/review.md"
    else
      # Job lỗi trước khi record ghi review: giữ nguyên cả hai marker để lượt sau không mất trạng thái.
      echo "<!-- ai-review -->"
      echo "## AI review dừng do lỗi hạ tầng trước khi có kết quả review"
      echo
      echo "$marker"
      echo "[Log lượt chạy]($RUN_URL)"
    fi
    echo
    nf=$(count_fixes) || return 1
    if [ "$nf" -ge "$MAX_FIXES" ]; then
      echo "**Dừng tự động sau $nf/$MAX_FIXES lần auto-fix** — cần người kiểm tra." \
           "Xử lý xong thì gỡ nhãn \`$STOP_LABEL\` rồi push để chạy lại (không còn lượt auto-fix cho PR này);" \
           "gắn nhãn \`$FIX_LABEL\` nếu muốn tắt auto-fix và auto-merge."
    else
      echo "**Dừng tự động (đã auto-fix $nf/$MAX_FIXES):** bước fix không tạo được thay đổi hợp lệ, hoặc có nhãn chặn," \
           "hoặc lỗi hạ tầng — cần người kiểm tra; gỡ nhãn \`$STOP_LABEL\` rồi push để chạy lại, vẫn còn lượt auto-fix." \
           "Gắn nhãn \`$FIX_LABEL\` nếu muốn tắt auto-fix và auto-merge."
    fi
  } > "$STATE/final.md"
  upsert_comment "$STATE/final.md"
  echo "::error::AI review FAIL — xem comment trên PR #$PR"
  return 1
}
