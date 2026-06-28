#!/bin/bash
# tc_08_burst.sh - TC-08 Short-Lived Process Burst Script

TIMESTAMP=$(date +%s)
MARKER="EDR_POC_TC08_${TIMESTAMP}"

echo "[+] Starting TC-08: Short-Lived Process Burst"
echo "[+] Marker ID: ${MARKER}"

echo "[+] Spawning 200 short-lived processes concurrently..."
for i in {1..200}; do
    /bin/echo "EDR_POC_TC08_BURST_${TIMESTAMP}_${i}" >/dev/null &
done

# Wait for all background processes to finish
wait
echo "[-] All 200 processes spawned and completed."

echo "[+] TC-08 Simulation completed."
echo "${MARKER}" > /tmp/edr_poc_last_marker
