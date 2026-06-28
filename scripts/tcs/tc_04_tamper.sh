#!/bin/bash
# tc_04_tamper.sh - TC-04 Anti-Tamper & Service Lifecycle Simulation Script

TIMESTAMP=$(date +%s)
MARKER="EDR_POC_TC04_${TIMESTAMP}"

echo "[+] Starting TC-04: Anti-Tamper"
echo "[+] Marker ID: ${MARKER}"

# 1. Attempt to stop edr-x without a passphrase
echo "[+] Attempting to stop agent via edrctl..."
sudo /opt/edr-x/bin/edrctl control stop --passphrase "invalid_passphrase" 2>&1

# 2. Attempt to kill process directly
AGENT_PID=$(pgrep -f edr-agent | head -n 1)
if [ -n "${AGENT_PID}" ]; then
    echo "[-] Found edr-agent PID: ${AGENT_PID}"
    echo "[+] Attempting to kill PID ${AGENT_PID} via SIGKILL..."
    sudo kill -9 "${AGENT_PID}" 2>&1
    
    # Wait and check if the agent is still running
    sleep 2
    NEW_PID=$(pgrep -f edr-agent | head -n 1)
    if [ -n "${NEW_PID}" ]; then
        if [ "${NEW_PID}" != "${AGENT_PID}" ]; then
            echo "[-] Agent process was killed but restarted automatically (New PID: ${NEW_PID})."
        else
            echo "[!] Agent process was NOT killed (Kernel self-protection blocked SIGKILL)."
        fi
    else
        echo "[!] Agent process is not running. Restarting agent..."
        sudo /opt/edr-x/bin/edrctl control start
    fi
else
    echo "[!] edr-agent process not found."
fi

echo "[+] TC-04 Simulation completed."
echo "${MARKER}" > /tmp/edr_poc_last_marker
