#!/usr/bin/env bash
# decompile_one.sh <binary-name>
# Ghidra headless 분석 + decompile_all.py postScript 로 단일 바이너리 전 함수 디컴파일.
# 출력: bin/decompiled/<binary>_decompiled.c
set -euo pipefail

BIN_NAME="${1:?usage: decompile_one.sh <binary-name>}"
ROOT="<REPO_ROOT>"
BIN_PATH="$ROOT/bin/extracted/$BIN_NAME"
SCRIPT_DIR="$ROOT/scripts"
PROJ_DIR="$ROOT/bin/ghidra_proj"
OUT="$ROOT/bin/decompiled/${BIN_NAME}_decompiled.c"
LOG="$ROOT/logs/decompile_${BIN_NAME}.log"

mkdir -p "$PROJ_DIR" "$ROOT/bin/decompiled"

ANALYZE="$(command -v analyzeHeadless || echo /opt/homebrew/bin/analyzeHeadless)"

echo "[$(date '+%H:%M:%S')] START $BIN_NAME ($(ls -lh "$BIN_PATH" | awk '{print $5}'))" | tee "$LOG"

"$ANALYZE" "$PROJ_DIR" "edr_${BIN_NAME}" \
  -import "$BIN_PATH" \
  -scriptPath "$SCRIPT_DIR" \
  -postScript DecompileAll.java \
  -deleteProject \
  >> "$LOG" 2>&1

if [ -f "$OUT" ]; then
  echo "[$(date '+%H:%M:%S')] DONE $BIN_NAME -> $OUT ($(ls -lh "$OUT" | awk '{print $5}'), $(grep -c '^// Function:' "$OUT" 2>/dev/null || echo '?') funcs)" | tee -a "$LOG"
else
  echo "[$(date '+%H:%M:%S')] FAIL $BIN_NAME (no output produced) — see $LOG" | tee -a "$LOG"
  exit 1
fi
