#!/bin/bash
# tc_01_telemetry.sh - TC-01 Detection Telemetry Simulation Script
# Safe Lab Principle: Benign simulation only, automatic cleanup.

TIMESTAMP=$(date +%s)
MARKER="EDR_POC_TC01_${TIMESTAMP}"
TEMP_PY="/tmp/edr_poc_tc01_${TIMESTAMP}.py"

echo "[+] Starting TC-01: Detection Telemetry Simulation"
echo "[+] Marker ID: ${MARKER}"

# Create a temporary Python script with markers and system reconnaissance commands
cat << EOF > "${TEMP_PY}"
import sys
import socket
import subprocess
import urllib.request

print("[-] Running TC-01 Python Helper inside VM - Marker: ${MARKER}")

# 1. DNS Query & HTTP Outbound Simulation
try:
    print("[-] Simulating DNS lookup and HTTP GET to example.com...")
    urllib.request.urlopen("http://example.com", timeout=5)
    print("[-] Outbound HTTP request success.")
except Exception as e:
    print(f"[!] Outbound request failed: {e}")

# 2. System Reconnaissance Commands
commands = [
    ["whoami"],
    ["id"],
    ["uname", "-a"],
    ["ip", "route"]
]

for cmd in commands:
    try:
        print(f"[-] Running recon command: {' '.join(cmd)}")
        res = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    except Exception as e:
        print(f"[!] Command execution failed: {e}")

print("[-] TC-01 Helper execution finished.")
EOF

chmod +x "${TEMP_PY}"

# Run the 3-stage process chain: bash (current) -> sh -> python3
echo "[+] Triggering 3-stage process chain (bash -> sh -> python3)"
sh -c "python3 ${TEMP_PY}"

# Cleanup (State Containment)
echo "[+] Cleaning up temporary script"
rm -f "${TEMP_PY}"

echo "[+] TC-01 Simulation completed successfully."
echo "${MARKER}" > /tmp/edr_poc_last_marker
