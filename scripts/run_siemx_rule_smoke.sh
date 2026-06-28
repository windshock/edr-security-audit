#!/bin/bash
# run_siemx_rule_smoke.sh - benign SIEM-X MITRE rule trigger smoke test
#
# Scope:
#   Generates safe discovery-style activity mapped to the currently enabled
#   SIEM-X rules. This complements scripts/run_all.sh, which validates the
#   EDR-X EDR telemetry/control test cases but does not directly exercise
#   every SIEM correlation rule.

set -u

TIMESTAMP="$(date +%s)"
MARKER="EDR_POC_CRUX_RULES_${TIMESTAMP}"
CRON_FILE="/etc/cron.d/${MARKER}_cron"

echo "[+] Starting SIEM-X MITRE rule smoke test"
echo "[+] Marker ID: ${MARKER}"

run_marked() {
  local rule="$1"
  local command="$2"
  echo "----------------------------------------------------------"
  echo "[+] ${rule}"
  bash -c "echo ${MARKER} ${rule}; ${command}"
}

run_marked "MITRE_ReadPasswdFile_T1078" \
  "cat /etc/passwd >/dev/null"

run_marked "MITRE_ProcessDiscovery_T1057" \
  "ps aux >/dev/null; ps -ef >/dev/null"

run_marked "MITRE_FileAndDirectoryDiscovery_T1083" \
  "ls -la /etc >/dev/null; ls -la /home >/dev/null; find /etc -maxdepth 1 -type f >/dev/null"

run_marked "MITRE_RemoteSystemDiscovery_T1018" \
  "ip neigh show >/dev/null 2>&1; arp -a >/dev/null 2>&1; getent hosts localhost >/dev/null"

run_marked "MITRE_SystemOwnerUserDiscovery_T1033" \
  "whoami >/dev/null; id >/dev/null; getent passwd | head -n 5 >/dev/null"

run_marked "MITRE_SystemNetworkConnectionsDiscovery_T1049" \
  "ss -tuna >/dev/null 2>&1; netstat -antup >/dev/null 2>&1"

run_marked "MITRE_SystemNetworkConfigurationDiscovery_T1016" \
  "ip addr show >/dev/null; ip route show >/dev/null; ifconfig -a >/dev/null 2>&1; route -n >/dev/null 2>&1"

run_marked "MITRE_CryptoMinerResourceDiscovery_T1496" \
  "nproc >/dev/null; lscpu >/dev/null 2>&1; free -m >/dev/null; df -h / >/dev/null; cat /proc/cpuinfo >/dev/null"

run_marked "MITRE_LocalMachineReconnaissance_T1082_T1018_T1087_T1003" \
  "uname -a >/dev/null; hostname >/dev/null; hostnamectl >/dev/null 2>&1; id >/dev/null; cat /etc/os-release >/dev/null; cat /etc/passwd >/dev/null; ip route show >/dev/null"

echo "----------------------------------------------------------"
echo "[+] MITRE_CronModification_T1053_003"
if [ "$(id -u)" -ne 0 ]; then
  echo "[!] Cron smoke step requires root; skipping cron file write"
else
  bash -c "echo ${MARKER} MITRE_CronModification_T1053_003; printf '# ${MARKER} MITRE_CronModification_T1053_003\n' > '${CRON_FILE}'; chmod 0644 '${CRON_FILE}'; sleep 1; rm -f '${CRON_FILE}'"
fi

echo "${MARKER}" > /tmp/edr_poc_crux_rules_marker
echo "[+] SIEM-X MITRE rule smoke test completed."
echo "[+] Marker saved to /tmp/edr_poc_crux_rules_marker"
