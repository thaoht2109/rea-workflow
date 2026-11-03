#!/usr/bin/env bash
# Cổng bandit: so số lỗi theo (file, test_id) giữa kết quả hiện tại và baseline (cả hai là `bandit -f json`).
# `bandit -b` bỏ qua số dòng nên không bắt được lỗi MỚI giống hệt lỗi cũ trong cùng file (vd thêm f-string SQL ⇒ B608).
# Exit 0 = không vượt baseline; 1 = có (file, test_id) nhiều lỗi hơn baseline; 2 = JSON đọc/parse lỗi (fail closed).
set -euo pipefail

[ "$#" -eq 2 ] || { echo "usage: $0 CURRENT.json BASELINE.json" >&2; exit 2; }

# Đếm theo "file|test_id"; file mới không có trong baseline coi như 0.
count='[.results[] | "\(.filename)|\(.test_id)"] | group_by(.) | map({key: .[0], value: length}) | from_entries'
cur=$(jq -e "$count" "$1") || { echo "bandit_gate: không đọc được $1" >&2; exit 2; }
base=$(jq -e "$count" "$2") || { echo "bandit_gate: không đọc được $2" >&2; exit 2; }

over=$(jq -rn --argjson c "$cur" --argjson b "$base" \
  '$c | to_entries[] | select(.value > ($b[.key] // 0)) | "\(.key): \(.value) > baseline \($b[.key] // 0)"') \
  || { echo "bandit_gate: lỗi so sánh" >&2; exit 2; }

if [ -n "$over" ]; then
  echo "bandit_gate: có lỗi medium+ MỚI so với baseline (file|test_id):" >&2
  echo "$over" >&2
  exit 1
fi
echo "bandit_gate: OK, không vượt baseline"
