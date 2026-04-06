#!/usr/bin/env bash
set -euo pipefail

BASE_URL="${1:-http://localhost:5000}"

paths=(
  "/../.env"
  "/../main.ts"
  "/../data/fp.db"
  "/../../etc/passwd"
  "/%2e%2e/.env"
  "/%2e%2e/main.ts"
  "/%2e%2e/%2e%2e/etc/passwd"
  "/%252e%252e/%252e%252e/etc/passwd"
)

for path in "${paths[@]}"; do
  echo "[INFO] Testing ${path}"
  curl -si "${BASE_URL}${path}" | sed -n '1,20p'
  echo
done
