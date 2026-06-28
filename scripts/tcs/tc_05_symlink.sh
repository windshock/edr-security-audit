#!/bin/bash
# tc_05_symlink.sh - TC-05 Symlink/TOCTOU Race Simulation Script

TIMESTAMP=$(date +%s)
MARKER="EDR_POC_TC05_${TIMESTAMP}"
LINK_FILE="/tmp/${MARKER}_symlink"

echo "[+] Starting TC-05: Symlink/TOCTOU"
echo "[+] Marker ID: ${MARKER}"

# Create a symlink pointing to /etc/shadow
echo "[+] Creating symlink ${LINK_FILE} -> /etc/shadow"
ln -sf /etc/shadow "${LINK_FILE}"

# Attempt to read from the symlink
echo "[+] Attempting to read mock symlink target..."
head -n 1 "${LINK_FILE}" 2>&1

# Cleanup
echo "[+] Cleaning up symlink"
rm -f "${LINK_FILE}"

echo "[+] TC-05 Simulation completed."
echo "${MARKER}" > /tmp/edr_poc_last_marker
