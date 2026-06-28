#!/bin/bash
# tc_10_nonroot_perm.sh - TC-10 Non-Root Permission Boundary Script

TIMESTAMP=$(date +%s)
MARKER="EDR_POC_TC10_${TIMESTAMP}"

echo "[+] Starting TC-10: Non-Root Permission Boundary (Running as user: $(whoami))"
echo "[+] Marker ID: ${MARKER}"

# Attempt to write inside /opt/edr-x/bin
TARGET_PATH="/opt/edr-x/bin/${MARKER}.txt"
echo "[+] Attempting to write file inside EDR bin directory: ${TARGET_PATH}"
touch "${TARGET_PATH}" 2>&1

if [ -f "${TARGET_PATH}" ]; then
    echo "[!] Security Failure: Successfully wrote file into protected EDR directory!"
    rm -f "${TARGET_PATH}"
else
    echo "[-] Security Pass: Write to EDR directory blocked as expected."
fi

echo "[+] TC-10 Simulation completed."
echo "${MARKER}" > /tmp/edr_poc_last_marker
