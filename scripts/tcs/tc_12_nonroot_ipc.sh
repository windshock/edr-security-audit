#!/bin/bash
# tc_12_nonroot_ipc.sh - TC-12 Non-Root IPC Access (crtester)
#
# FIX (2026-06-19): Same abstract-socket fix as TC-06. This script must be
# invoked AS the non-root user, e.g.:
#   sudo -u crtester bash tc_12_nonroot_ipc.sh
# It relies on /tmp/asp.py having been staged (TC-06 stages it, or stage it
# manually: sudo cp abstract_socket_probe.py /tmp/asp.py && sudo chmod 755 /tmp/asp.py)

TIMESTAMP=$(date +%s)
MARKER="EDR_POC_TC12_${TIMESTAMP}"

echo "[+] Starting TC-12: Abstract Unix Socket IPC Probe (Running as: $(whoami))"
echo "[+] Marker ID: ${MARKER}"

if [ ! -r /tmp/asp.py ]; then
    echo "[!] /tmp/asp.py not staged. Run TC-06 first, or stage the probe as root."
    exit 1
fi
python3 /tmp/asp.py "${MARKER}"

echo "[+] TC-12 Simulation completed."
echo "${MARKER}" > /tmp/edr_poc_last_marker
