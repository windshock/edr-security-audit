# EDR-X EDR Security Validation Report (v2)

* **Generated**: 2026-06-23T23:24:40Z UTC
* **Environment**: Colima VM (Ubuntu 24.04 LTS x86_64, QEMU)
* **Telemetry Source**: SIEM-X OpenSearch (`<siemx_HOST>:5601` proxy)
* **Verification**: deferred (600s wait) + multi-key (marker & script-name)

---

| TC ID | Name | Priv | Local | Visibility | SIEM-X (m/k) | Security Finding |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| TC-01 | TC-01: Detection Telemetry | Root | SUCCESS | **OBSERVED** | m:1 / k:59 | none |
| TC-02 | TC-02: TLS Verification | Root | SUCCESS | **OBSERVED** | m:4 / k:47 | none |
| TC-03 | TC-03: Configuration Manipulation | Root | SUCCESS | **OBSERVED** | m:4 / k:47 | none |
| TC-04 | TC-04: Anti-Tamper | Root | SUCCESS | **OBSERVED** | m:0 / k:62 | none (blocked; threat in .threats) |
| TC-05 | TC-05: Symlink/TOCTOU | Root | SUCCESS | **OBSERVED** | m:3 / k:44 | none |
| TC-06 | TC-06: Abstract Unix Socket IPC | Root | SUCCESS | **OBSERVED** | m:1 / k:41 | none (no socket-connect event) |
| TC-07 | TC-07: Low-Level Kernel Telemetry | Root | SUCCESS | **OBSERVED** | m:5 / k:12 | none (direct-syscall evasion defeated) |
| TC-08 | TC-08: Short-Lived Process Burst | Root | SUCCESS | **OBSERVED** | m:0 / k:635 | none |
| TC-09 | TC-09: Package Manipulation | Root | SUCCESS | **OBSERVED** | m:0 / k:41 | none |
| TC-10 | TC-10: Non-Root Permissions | crtester | SUCCESS | **OBSERVED** | m:1 / k:41 | none |
| TC-11 | TC-11: Non-Root Process Control | crtester | SUCCESS | **OBSERVED** | m:0 / k:53 | none (blocked; threat in .threats) |
| TC-12 | TC-12: Non-Root IPC Access | crtester | SUCCESS | **OBSERVED** | m:1 / k:41 | FINDING: non-root reaches all 9 IPC sockets |
| TC-13 | TC-13: Non-Root Persistence | crtester | SUCCESS | **OBSERVED** | m:4 / k:59 | none |
| TC-14 | TC-14: Non-Root Privilege Bypass | crtester | SUCCESS | **OBSERVED** | m:0 / k:44 | none |

## Summary (two-axis)
**Visibility**: OBSERVED 14 / SKIP 0 / INGEST_FAIL 0
**Security findings**: 1 (see rows marked FINDING:)

> Visibility = did SIEM-X record the activity in ANY logs-edr* index
> (.edr raw telemetry OR .threats). It is orthogonal to whether the action was
> safe/blocked. A row can be OBSERVED yet still carry a security FINDING.
