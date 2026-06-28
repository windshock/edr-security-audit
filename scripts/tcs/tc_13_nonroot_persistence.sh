#!/bin/bash
# tc_13_nonroot_persistence.sh - TC-13 Non-Root User Persistence Script

TIMESTAMP=$(date +%s)
MARKER="EDR_POC_TC13_${TIMESTAMP}"

echo "[+] Starting TC-13: Non-Root User Persistence (Running as user: $(whoami))"
echo "[+] Marker ID: ${MARKER}"

# 1. Attempt to add marker to ~/.bashrc for persistence
echo "[+] Attempting to write persistence marker to ~/.bashrc..."
echo "# ${MARKER}" >> ~/.bashrc
echo "[-] Current ~/.bashrc tail:"
tail -n 3 ~/.bashrc

# Cleanup ~/.bashrc immediately
echo "[+] Cleaning up ~/.bashrc..."
sed -i "/${MARKER}/d" ~/.bashrc
echo "[-] ~/.bashrc cleaned."

echo "[+] TC-13 Simulation completed."
echo "${MARKER}" > /tmp/edr_poc_last_marker
