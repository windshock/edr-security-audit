# EDR-X Linux EDR Security Audit PoC

[Korean version](README.ko.md)

This repository contains a defensive security validation PoC for **EDR-X Linux EDR Agent** in an isolated Colima VM. It evaluates detection visibility, agent integrity controls, privilege boundaries, and resilience against low-level evasion using 14 test cases, static/dynamic analysis, and reproducible findings.

The repository has two roles:

* **Reference implementation**: a concrete EDR-X validation PoC in `docs/` and `scripts/`.
* **Reusable audit skill**: a product-agnostic EDR assessment methodology in [`skills/edr-security-audit/SKILL.md`](skills/edr-security-audit/SKILL.md), covering anti-tamper enforcement, io_uring and low-level evasion, LPE detection, IPC authorization, and the distinction between detection, blocking, and alerting.

> **Public release note:** only methodology, tools, analysis notes, and scrubbed evidence authored for this project should be published. Vendor-owned EDR-X assets such as installer packages, extracted binaries, decompiled `.c` files, eBPF `.o` objects, and vendor PDFs are excluded by `.gitignore`, as are credentials and internal operational data such as `.env`, console tokens, raw `logs/`, internal IPs, and unsanitized evidence containing agent identifiers. Check `git status` before publishing.

## Key Findings

| ID | Summary | Severity | Status |
|---|---|---|---|
| **[FND-001](docs/findings/FND-001_TC-04_anti_tamper_reevaluation.md)** | File integrity protection does not enforce when the kernel is booted without `lsm=bpf`; root can modify agent binaries/configuration while the console still reports the agent as enabled. | High* | Vendor-confirmed, with controlled `lsm=bpf` comparison |
| **[FND-002](docs/findings/FND-002_LPE_privilege_escalation_detection.md)** | Local privilege escalation via SUID backdoor creation is detected (`SUID_SET`, MITRE `T1548.001`), but the behavior remains raw telemetry and is not promoted to an actionable threat alert. | Medium | Detection logs collected |
| io_uring | File activity through io_uring is still detected at the VFS level; this evasion path did not bypass telemetry. | - | Validated |

\* Based on default installations of affected distributions such as Ubuntu 20/22+, Debian 11, Oracle Linux 9/10, and SLES 15. See FND-001 section 3-7 for the vendor-confirmed details.

## Repository Layout

```text
.
├── README.md                       # English overview
├── README.ko.md                    # Korean overview
├── edr-x_poc_handoff.md            # Ignored internal handoff notes
├── docs/
│   ├── plans/
│   │   ├── edr_validation_plan.md
│   │   ├── interim_test_report_2026-06-19.md
│   │   ├── validation_report_latest.md
│   │   └── executive_summary_1page.md
│   └── findings/
│       ├── FND-001_*.md  + repro_FND-001.txt
│       ├── FND-002_*.md  + repro_FND-002.txt
│       └── evidence/
├── scripts/
│   ├── tcs/
│   ├── run_all.sh
│   ├── query_siemx.py / query_event_types.py / analyze_privesc.py / dump_evidence.py
│   └── decompile_one.sh + DecompileAll.java
├── bin/                            # Ignored vendor-owned binaries/eBPF; analysis .md files are public
└── logs/                           # Ignored system and agent diagnostics
```

## Validation Scope

The test suite covers detection telemetry, TLS/certificate behavior, configuration tampering, anti-tamper controls, symlink and TOCTOU behavior, IPC control-plane exposure, low-level kernel paths such as eBPF, io_uring, and direct syscalls, short-lived process bursts, package/supply-chain checks, and four non-root privilege-boundary tests.

See the detailed [validation plan](docs/plans/edr_validation_plan.md).

## Environment and Reproduction

* Target: EDR-X Linux Agent `<agent-version>` on Ubuntu 24.04, kernel 6.8.0, Colima x86_64 VM.
* Integration: on-prem console plus SIEM-X/OpenSearch log lake. Endpoints and tokens are loaded from `.env`.
* Analysis tools: Ghidra `analyzeHeadless`, radare2 6.x, and r2ghidra `pdg`. Use `scripts/decompile_one.sh <binary>` for targeted decompilation.
* Test execution: `INGEST_WAIT=420 bash scripts/run_all.sh` to account for the observed Kafka ingestion lag.

## Ethics

This PoC is intended for defensive security validation in an authorized lab. Privilege escalation and tamper scenarios were run in an isolated VM, and temporary risky artifacts such as SUID backdoors and sudoers test entries were removed immediately after each test.

The findings are framed as operational configuration and visibility improvements, not as product exploitation guidance, and were shared with the vendor for coordination.
