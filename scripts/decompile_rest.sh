#!/usr/bin/env bash
# 나머지 3종 바이너리를 크기순으로 순차 디컴파일 (백그라운드 실행용)
set -uo pipefail
ROOT="<REPO_ROOT>"
MASTER_LOG="$ROOT/logs/decompile_rest.log"
: > "$MASTER_LOG"

for BIN in edr-watchdog edr-extension-host edrctl; do
  echo "==================== $BIN ====================" >> "$MASTER_LOG"
  bash "$ROOT/scripts/decompile_one.sh" "$BIN" >> "$MASTER_LOG" 2>&1
  rc=$?
  echo "[exit=$rc] $BIN" >> "$MASTER_LOG"
done
echo "ALL_DONE" >> "$MASTER_LOG"
