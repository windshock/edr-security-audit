#!/bin/bash
# tc_03_config.sh - TC-03 Configuration Manipulation Simulation Script

TIMESTAMP=$(date +%s)
MARKER="EDR_POC_TC03_${TIMESTAMP}"
TARGET_FILE="/etc/edr-x/${MARKER}.cfg"

echo "[+] Starting TC-03: Configuration Manipulation"
echo "[+] Marker ID: ${MARKER}"

# Attempt to write to the EDR-X config directory
echo "[+] Attempting to write mock config file: ${TARGET_FILE}"
if sudo touch "${TARGET_FILE}" 2>/dev/null; then
    echo "[-] Successfully wrote mock config file (expected if policy allows, but should trigger alert)."
    sudo rm -f "${TARGET_FILE}"
else
    echo "[!] Write to config directory blocked (Self-Protection is active)."
fi

# Attempt unauthorized configuration change via edrctl
echo "[+] Attempting to change management token without authorization"
sudo /opt/edr-x/bin/edrctl management token set "invalid_token_marker_${MARKER}" 2>&1

echo "[+] TC-03 Simulation completed."
echo "${MARKER}" > /tmp/edr_poc_last_marker
