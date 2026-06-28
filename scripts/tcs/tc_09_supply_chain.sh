#!/bin/bash
# tc_09_supply_chain.sh - TC-09 Package Manipulation & Supply Chain Script

TIMESTAMP=$(date +%s)
MARKER="EDR_POC_TC09_${TIMESTAMP}"

echo "[+] Starting TC-09: Package Manipulation & Supply Chain"
echo "[+] Marker ID: ${MARKER}"

# Audit installer directory permissions
echo "[+] Auditing permissions of /opt/edr-x..."
ls -ld /opt/edr-x

echo "[+] Auditing permissions of agent binary executables..."
ls -l /opt/edr-x/bin/

echo "[+] TC-09 Simulation completed."
echo "${MARKER}" > /tmp/edr_poc_last_marker
