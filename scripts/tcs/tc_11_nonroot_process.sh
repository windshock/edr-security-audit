#!/bin/bash
# tc_11_nonroot_process.sh - TC-11 Non-Root Process Control Script

TIMESTAMP=$(date +%s)
MARKER="EDR_POC_TC11_${TIMESTAMP}"

echo "[+] Starting TC-11: Non-Root Process Control (Running as user: $(whoami))"
echo "[+] Marker ID: ${MARKER}"

AGENT_PID=$(pgrep -f edr-agent | head -n 1)
if [ -n "${AGENT_PID}" ]; then
    echo "[-] Found edr-agent PID: ${AGENT_PID}"
    echo "[+] Attempting to kill agent PID as low-privilege user..."
    kill -9 "${AGENT_PID}" 2>&1
else
    echo "[!] edr-agent PID not found."
fi

echo "[+] TC-11 Simulation completed."
echo "${MARKER}" > /tmp/edr_poc_last_marker
