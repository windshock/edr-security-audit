#!/bin/bash
# tc_02_tls.sh - TC-02 TLS Verification & Trust Abuse Simulation Script
# Safe Lab Principle: Benign simulation only, automatic cleanup.

TIMESTAMP=$(date +%s)
MARKER="EDR_POC_TC02_${TIMESTAMP}"
TARGET_CERT="/etc/ssl/certs/${MARKER}.crt"

echo "[+] Starting TC-02: TLS Verification"
echo "[+] Marker ID: ${MARKER}"

# Attempt to write a mock certificate file in the system trust store
echo "[+] Attempting to write mock certificate: ${TARGET_CERT}"
if sudo touch "${TARGET_CERT}" 2>/dev/null; then
    echo "[-] Successfully created mock certificate (expected as root)."
    # Cleanup immediately
    sudo rm -f "${TARGET_CERT}"
    echo "[-] Removed mock certificate."
else
    echo "[!] Failed to create mock certificate."
fi

echo "[+] TC-02 Simulation completed."
echo "${MARKER}" > /tmp/edr_poc_last_marker
