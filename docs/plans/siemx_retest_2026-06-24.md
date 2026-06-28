# SIEM-X Rule Retest - 2026-06-24

## Scope

- Environment: Colima Ubuntu 24.04 x86_64, EDR-X Agent <agent-version>
- Kernel LSM baseline: `lockdown,capability,landlock,yama,apparmor`
- Explicit condition: `lsm=bpf` disabled
- GRUB rollback performed by renaming `/etc/default/grub.d/99-lsm-bpf.cfg` to `99-lsm-bpf.cfg.disabled-20260624080616`, followed by `update-grub` and VM reboot.

## Baseline Checks

- `/sys/kernel/security/lsm`: `lockdown,capability,landlock,yama,apparmor`
- `edrctl control status`: `Agent state Enabled`
- Runtime provider telemetry: agent file-protection providers such as `edr_file_open_write`, `edr_file_create`, and `edr_file_delete` are not loaded under this LSM baseline, while `edr_kill_attempt` remains loaded.

## Full 14-TC Suite

- Command: `INGEST_WAIT=600 VERIFY_RETRIES=2 VERIFY_GAP=60 bash scripts/run_all.sh`
- Report: `docs/plans/validation_report_latest.md`
- JSON: `docs/plans/validation_report.json`
- Result: `OBSERVED 14 / SKIP 0 / INGEST_FAIL 0`
- Security finding reproduced: `TC-12` non-root user can reach all 9 EDR-X abstract IPC sockets at transport level.

## SIEM-X MITRE Rule Smoke

Script added:

- `scripts/run_siemx_rule_smoke.sh`

Query helper added:

- `scripts/query_siemx_search.py`

### Smoke Run 1

- Marker: `EDR_POC_CRUX_RULES_1782256514`
- Raw telemetry: 37 documents in `logs-*`
- Alert index match: 0 documents in `*alert*`
- Threat match after smoke time: 0 documents in `logs-edr.threats*`

### Smoke Run 2

- Marker: `EDR_POC_CRUX_RULES_1782257688`
- Raw telemetry: 36 documents in `logs-*`
- Cron file marker: 6 documents for `EDR_POC_CRUX_RULES_1782257688_cron`
- Alert index match: 0 documents in `*alert*`
- Threat match after smoke time: 0 documents in `logs-edr.threats*`

Representative cron telemetry:

- `PROCESSCREATION` for the marked `bash -c` cron modification command
- `FILEMODIFICATION` for `/etc/cron.d/EDR_POC_CRUX_RULES_1782257688_cron`
- `FILEDELETION` for the same cron file
- `BEHAVIOR_INDICATOR` for the same activity

## Conclusion

The full EDR-X telemetry suite remains visible in SIEM-X under the `lsm=bpf` disabled baseline. The re-enabled SIEM-X MITRE smoke activities also produced raw EDR telemetry.

However, after raw ingestion and additional rule-cycle wait time, the smoke activities did not produce new documents in `*alert*` or `logs-edr.threats*`. This indicates that the active rules are not currently generating an observable alert/threat response for these validated raw events, or their response output is written to a different backend/index not covered by the available OpenSearch queries.
