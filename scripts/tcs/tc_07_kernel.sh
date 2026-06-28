#!/bin/bash
# tc_07_kernel.sh - TC-07 Low-Level Kernel Telemetry (corrected)
#
# FIX (2026-06-19): the old test opened a NON-EXISTENT path
# (/etc/hosts?marker=...) so the syscall returned -1 and nothing happened to
# capture. The "QEMU emulation limit" SKIP attribution was also wrong: direct
# syscall(2)/syscall(257) work fine under QEMU x86_64.
#
# This version runs a controlled experiment via syscall_file_probe.py:
#   CONTROL   arm: file create/write/delete via libc      (marker *_CTRL)
#   TREATMENT arm: file create/write/delete via DIRECT syscalls (marker *_SYSCALL)
# After the ingestion lag, query SIEM-X for each marker to see whether the
# eBPF sensor sees through direct-syscall evasion.

TIMESTAMP=$(date +%s)
MARKER="EDR_POC_TC07_${TIMESTAMP}"
PROBE="$(dirname "$0")/syscall_file_probe.py"

echo "[+] Starting TC-07: Low-Level Kernel Telemetry (libc vs direct-syscall)"
echo "[+] Marker ID: ${MARKER}"

cp "${PROBE}" /tmp/sfp.py 2>/dev/null && chmod 755 /tmp/sfp.py
python3 /tmp/sfp.py "${MARKER}"

echo "[+] TC-07 Simulation completed."
echo "${MARKER}" > /tmp/edr_poc_last_marker
