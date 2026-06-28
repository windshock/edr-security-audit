#!/bin/bash
# run_all.sh - EDR-X EDR Security Validation Suite Runner (v2)
#
# v2 improvements (2026-06-19):
#   1. Two-phase design: EXECUTE all TCs first (collect markers), then a single
#      DEFERRED VERIFY pass after the Kafka ingestion lag (5-10 min). The old
#      5x10s=50s inline wait could never cover that lag.
#   2. Multi-key search: each TC is verified by BOTH its unique marker AND a
#      fallback script-name key (tc_08 / tc_09 / tc_14 don't embed the marker
#      in event data, so marker-only search returned 0 for them).
#   3. Two-AXIS evaluation (a single PASS/FAIL conflated detection-visibility
#      with security-posture). This suite auto-measures the VISIBILITY axis only;
#      the SECURITY-FINDING axis is a static analyst annotation per TC.
#        VISIBILITY:  OBSERVED     - telemetry present in SIEM-X (any index)
#                     SKIP         - not meaningful in this env
#                     INGEST_FAIL  - executed locally but telemetry never arrived
#        FINDING:     none | <text>  (carried in the TC table, not auto-derived)
#   4. SIEM-X is multi-index: query_count.py defaults to logs-edr*
#      (covers BOTH .edr raw telemetry AND .threats). Searching only .edr
#      previously produced a FALSE gap for Anti-Tamper threats (TC-04/11).
#
# Env knobs:
#   INGEST_WAIT   seconds to wait before the deferred verify pass (default 420)
#   VERIFY_RETRIES number of verify rounds (default 3), VERIFY_GAP secs between (default 60)

WORKSPACE="<REPO_ROOT>"
REPORT_FILE="${WORKSPACE}/docs/plans/validation_report_latest.md"
JSON_REPORT="${WORKSPACE}/docs/plans/validation_report.json"
INGEST_WAIT="${INGEST_WAIT:-420}"
VERIFY_RETRIES="${VERIFY_RETRIES:-3}"
VERIFY_GAP="${VERIFY_GAP:-60}"

echo "=========================================================="
echo " EDR-X EDR Security Validation Suite Runner (v2)"
echo "=========================================================="

# --- TC table: filename | name | privilege | fallback_search_key | class | finding ---
# class:   RUN (telemetry expected) | SKIP (env-limited)
# finding: static security-finding annotation (none = no concern)
tcs=(
  "tc_01_telemetry.sh|TC-01: Detection Telemetry|Root|tc_01|RUN|none"
  "tc_02_tls.sh|TC-02: TLS Verification|Root|tc_02|RUN|none"
  "tc_03_config.sh|TC-03: Configuration Manipulation|Root|tc_03|RUN|none"
  "tc_04_tamper.sh|TC-04: Anti-Tamper|Root|tc_04|RUN|none (blocked; threat in .threats)"
  "tc_05_symlink.sh|TC-05: Symlink/TOCTOU|Root|tc_05|RUN|none"
  "tc_06_socket.sh|TC-06: Abstract Unix Socket IPC|Root|asp.py|RUN|none (no socket-connect event)"
  "tc_07_kernel.sh|TC-07: Low-Level Kernel Telemetry|Root|_SYSCALL|RUN|none (direct-syscall evasion defeated)"
  "tc_08_burst.sh|TC-08: Short-Lived Process Burst|Root|tc_08|RUN|none"
  "tc_09_supply_chain.sh|TC-09: Package Manipulation|Root|tc_09|RUN|none"
  "tc_10_nonroot_perm.sh|TC-10: Non-Root Permissions|crtester|tc_10|RUN|none"
  "tc_11_nonroot_process.sh|TC-11: Non-Root Process Control|crtester|tc_11|RUN|none (blocked; threat in .threats)"
  "tc_12_nonroot_ipc.sh|TC-12: Non-Root IPC Access|crtester|asp.py|RUN|FINDING: non-root reaches all 9 IPC sockets"
  "tc_13_nonroot_persistence.sh|TC-13: Non-Root Persistence|crtester|tc_13|RUN|none"
  "tc_14_nonroot_privilege.sh|TC-14: Non-Root Privilege Bypass|crtester|tc_14|RUN|none"
)

# ---------------------------------------------------------------------------
# PHASE 1: stage scripts + execute all TCs, collect markers
# ---------------------------------------------------------------------------
echo "[+] Staging test scripts into VM /tmp/tcs..."
colima ssh -- sudo bash -c "mkdir -p /tmp/tcs && rm -rf /tmp/tcs/*"
colima ssh -- sudo bash -c "cp -r ${WORKSPACE}/scripts/tcs/* /tmp/tcs/ && chmod -R 755 /tmp/tcs"
# Stage the abstract-socket probe at a world-readable path for TC-06/12.
colima ssh -- sudo bash -c "cp /tmp/tcs/abstract_socket_probe.py /tmp/asp.py && chmod 755 /tmp/asp.py"

declare -a MARKERS LOCAL_STATUS

echo "[+] PHASE 1: executing ${#tcs[@]} test cases..."
for entry in "${tcs[@]}"; do
  IFS='|' read -r filename tc_name privilege fbkey class finding <<< "${entry}"
  tc_id=$(echo "${filename}" | cut -d'_' -f1-2 | tr '[:lower:]' '[:upper:]' | tr '_' '-')
  echo "----------------------------------------------------------"
  echo " Running ${tc_id}: ${tc_name} (${privilege})"

  colima ssh -- sudo rm -f /tmp/edr_poc_last_marker
  if [ "${class}" = "SKIP" ]; then
    echo " [SKIP] not meaningful under this environment."
    MARKERS+=("SKIPPED"); LOCAL_STATUS+=("SKIP"); continue
  fi
  if [ "${privilege}" = "Root" ]; then
    colima ssh -- sudo bash "/tmp/tcs/${filename}"
  else
    colima ssh -- sudo -u crtester bash "/tmp/tcs/${filename}"
  fi
  st=$?
  marker=$(colima ssh -- cat /tmp/edr_poc_last_marker 2>/dev/null | tr -d '\r\n')
  echo "[+] marker=${marker} local_exit=${st}"
  MARKERS+=("${marker}"); LOCAL_STATUS+=("${st}")
done

# ---------------------------------------------------------------------------
# PHASE 2: wait for ingestion lag, then deferred multi-key verification
# ---------------------------------------------------------------------------
echo "=========================================================="
echo "[+] PHASE 2: waiting ${INGEST_WAIT}s for Kafka->SIEM-X ingestion lag..."
sleep "${INGEST_WAIT}"

# report headers
echo "{"  > "${JSON_REPORT}"
echo "  \"timestamp\": \"$(date -u +%Y-%m-%dT%H:%M:%SZ)\"," >> "${JSON_REPORT}"
echo "  \"results\": [" >> "${JSON_REPORT}"
cat << EOF > "${REPORT_FILE}"
# EDR-X EDR Security Validation Report (v2)

* **Generated**: $(date -u +%Y-%m-%dT%H:%M:%SZ) UTC
* **Environment**: Colima VM (Ubuntu 24.04 LTS x86_64, QEMU)
* **Telemetry Source**: SIEM-X OpenSearch (\`<siemx_HOST>:5601\` proxy)
* **Verification**: deferred (${INGEST_WAIT}s wait) + multi-key (marker & script-name)

---

| TC ID | Name | Priv | Local | Visibility | SIEM-X (m/k) | Security Finding |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
EOF

verify_count() {
  # echo the max count across all verify rounds for a single key
  local key="$1" best=0
  for ((r=1; r<=VERIFY_RETRIES; r++)); do
    local c
    c=$(python3 "${WORKSPACE}/scripts/query_count.py" "${key}" 2>/dev/null)
    [[ "${c}" =~ ^[0-9]+$ ]] || c=0
    (( c > best )) && best=${c}
    (( best > 0 )) && break
    (( r < VERIFY_RETRIES )) && sleep "${VERIFY_GAP}"
  done
  echo "${best}"
}

idx=0
for entry in "${tcs[@]}"; do
  IFS='|' read -r filename tc_name privilege fbkey class finding <<< "${entry}"
  tc_id=$(echo "${filename}" | cut -d'_' -f1-2 | tr '[:lower:]' '[:upper:]' | tr '_' '-')
  marker="${MARKERS[idx]}"; st="${LOCAL_STATUS[idx]}"

  if [ "${class}" = "SKIP" ]; then
    visibility="SKIP"; mcount=0; kcount=0; local_disp="SKIP"
  else
    local_disp=$([ "${st}" = "0" ] && echo "SUCCESS" || echo "FAILED")
    mcount=0; [ -n "${marker}" ] && mcount=$(verify_count "${marker}")
    kcount=$(verify_count "${fbkey}")
    total=$((mcount > kcount ? mcount : kcount))
    if [ "${total}" -gt 0 ]; then
      visibility="OBSERVED"
    else
      visibility="INGEST_FAIL"
    fi
  fi

  echo " ${tc_id}: visibility=${visibility} (m:${mcount}/k:${kcount}) finding=${finding}"
  echo "| ${tc_id} | ${tc_name} | ${privilege} | ${local_disp} | **${visibility}** | m:${mcount} / k:${kcount} | ${finding} |" >> "${REPORT_FILE}"

  comma=","; [ ${idx} -eq $((${#tcs[@]} - 1)) ] && comma=""
  cat << EOF >> "${JSON_REPORT}"
    { "tc_id": "${tc_id}", "name": "${tc_name}", "privilege": "${privilege}", "marker": "${marker}", "local_status": "${st}", "marker_hits": ${mcount}, "key_hits": ${kcount}, "visibility": "${visibility}", "security_finding": "${finding}" }${comma}
EOF
  idx=$((idx + 1))
done

echo "  ]" >> "${JSON_REPORT}"
echo "}" >> "${JSON_REPORT}"

# summary
observed=$(grep -c "\*\*OBSERVED\*\*" "${REPORT_FILE}")
skip=$(grep -c "\*\*SKIP\*\*" "${REPORT_FILE}")
ifail=$(grep -c "\*\*INGEST_FAIL\*\*" "${REPORT_FILE}")
findings=$(grep -c "FINDING:" "${REPORT_FILE}")
cat << EOF >> "${REPORT_FILE}"

## Summary (two-axis)
**Visibility**: OBSERVED ${observed} / SKIP ${skip} / INGEST_FAIL ${ifail}
**Security findings**: ${findings} (see rows marked FINDING:)

> Visibility = did SIEM-X record the activity in ANY logs-edr* index
> (.edr raw telemetry OR .threats). It is orthogonal to whether the action was
> safe/blocked. A row can be OBSERVED yet still carry a security FINDING.
EOF

echo "=========================================================="
echo " Suite complete. Report: ${REPORT_FILE}"
echo " PASS=${pass} GAP=${gap} SKIP=${skip} INGEST_FAIL=${ifail}"
echo "=========================================================="
