#!/bin/bash
# tc_14_nonroot_privilege.sh - TC-14 Non-Root Privilege Bypass Script

TIMESTAMP=$(date +%s)
MARKER="EDR_POC_TC14_${TIMESTAMP}"

echo "[+] Starting TC-14: Non-Root Privilege Bypass (Running as user: $(whoami))"
echo "[+] Marker ID: ${MARKER}"

commands=(
    "tcpdump --version"
    "iptables -L"
    "bpftool --version"
    "auditctl -l"
)

for cmd in "${commands[@]}"; do
    echo "[+] Running privileged command: ${cmd}"
    # Run the command and capture output
    ${cmd} 2>&1
done

echo "[+] TC-14 Simulation completed."
echo "${MARKER}" > /tmp/edr_poc_last_marker
