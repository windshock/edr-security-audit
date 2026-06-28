#!/bin/bash
# tc_06_socket.sh - TC-06 Unix Domain Socket IPC Analysis (root)
#
# FIX (2026-06-19): EDR-X IPC uses ABSTRACT-namespace (@-prefixed)
# SOCK_SEQPACKET sockets that never appear in the filesystem. The old
# `find /var/run -name '*edr*'` + `nc -U` approach could never reach
# them (always 0 events). We now enumerate /proc/net/unix and connect via
# Python SOCK_SEQPACKET against the abstract address.

TIMESTAMP=$(date +%s)
MARKER="EDR_POC_TC06_${TIMESTAMP}"
PROBE="$(dirname "$0")/abstract_socket_probe.py"

echo "[+] Starting TC-06: Abstract Unix Socket IPC Probe (root)"
echo "[+] Marker ID: ${MARKER}"

# Copy probe to a world-readable path so it also runs under non-root (TC-12).
cp "${PROBE}" /tmp/asp.py 2>/dev/null && chmod 755 /tmp/asp.py
python3 /tmp/asp.py "${MARKER}"

echo "[+] TC-06 Simulation completed."
echo "${MARKER}" > /tmp/edr_poc_last_marker
