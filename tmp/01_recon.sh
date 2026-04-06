#!/usr/bin/env bash
set -euo pipefail

BASE_URL="${1:-http://localhost:5000}"

echo "[INFO] Recon against ${BASE_URL}"
echo "[INFO] GET / response headers"
curl -sSI "${BASE_URL}/"

echo
echo "[INFO] OPTIONS / response"
curl -si -X OPTIONS "${BASE_URL}/"

echo
echo "[INFO] GET /nonexistent response"
curl -si "${BASE_URL}/nonexistent"
