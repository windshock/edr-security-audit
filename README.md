# EDR-X Linux EDR — 보안 점검 PoC

격리된 가상 환경(Colima VM)에서 **EDR-X Linux EDR Agent**의 위협 탐지 가시성, 에이전트
무결성(Anti-Tamper), 권한 경계, 저수준 회피 내성을 **방어적 관점에서 검증**한 PoC다. 14종 테스트케이스(TC)와
정적/동적 분석, 그리고 재현 가능한 finding으로 구성된다.

이 저장소는 두 층으로 쓰인다:
* **레퍼런스 구현** — EDR-X을 대상으로 한 실제 PoC(이 저장소의 docs/scripts).
* **재사용 점검 스킬** — 제품 불문 EDR 점검 방법론: [`skills/edr-security-audit/SKILL.md`](skills/edr-security-audit/SKILL.md).
  (anti-tamper enforcing 검증, io_uring/저수준 회피, LPE 탐지, IPC authz, 탐지/차단/알림 3단 구분 등)

> ⚠️ **공개 주의**: 본 저장소는 *우리가 작성한 방법론·도구·분석·(스크럽된)증거*만 공개 대상이다.
> **EDR-X 독점 자산**(설치 패키지, 추출 바이너리, 디컴파일 `.c`, eBPF `.o`, 벤더 PDF)과
> **자격증명/내부 운영 데이터**(`.env`, 관리 콘솔 토큰, `logs/`, 내부 IP·agent UUID 포함 증거 원본)는
> `.gitignore`로 제외된다. 공개 전 반드시 `git status`로 민감 파일 미포함을 확인할 것.
> (등록 토큰·site_key·내부 IP는 코드/문서에 하드코딩하지 말고 `.env`로만 관리.)

## 핵심 발견 (Findings)

| ID | 요약 | 등급 | 상태 |
|---|---|---|---|
| **[FND-001](docs/findings/FND-001_TC-04_anti_tamper_reevaluation.md)** | `lsm=bpf` 미설정 커널에서 **파일 무결성 보호(Anti-Tamper) 미작동** — root가 Agent 바이너리/설정 변조 가능. 콘솔은 정상(Enabled)으로 표시(silent). | High* | **벤더 공식 확인·사과** + `lsm=bpf` 대조 통제실험 |
| **[FND-002](docs/findings/FND-002_LPE_privilege_escalation_detection.md)** | 로컬 권한상승(SUID 백도어)은 **탐지됨**(`SUID_SET`, MITRE `T1548.001`). 단 행동지표가 **위협 알림으로 미승격**(raw에만). | Medium | 탐지 로그 확보 |
| io_uring | syscall 우회(io_uring) 파일작업도 **VFS-level로 정상 탐지** — 회피 무효(긍정). | — | 검증 완료 |

\* 영향 배포판(Ubuntu 20/22+, Debian 11, Oracle Linux 9/10, SLES 15 등)의 기본 설치 환경 기준. 자세히는 FND-001 §3-7(벤더 확인).

## 디렉토리 구조

```
.
├── README.md                       # (이 파일)
├── edr-x_poc_handoff.md      # 전체 진행 이력·의사결정 로그 (인계용)
├── docs/
│   ├── plans/
│   │   ├── edr_validation_plan.md     # 14개 TC 상세 계획 매트릭스
│   │   ├── interim_test_report_2026-06-19.md  # 상세 시험 보고서 (§4-4-A io_uring 등)
│   │   ├── validation_report_latest.md        # TC 결과 요약 (TC-04 PARTIAL 정정)
│   │   └── executive_summary_1page.md         # 1페이지 경영 요약
│   └── findings/
│       ├── FND-001_*.md  + repro_FND-001.txt  # anti-tamper / lsm=bpf
│       ├── FND-002_*.md  + repro_FND-002.txt  # LPE 탐지 (제조사 제출용)
│       └── evidence/                          # 실측 증거 (strace, 탐지 로그 JSON; 원본은 gitignore)
├── scripts/
│   ├── tcs/                         # TC별 프로브 (iouring_file.c, ipc_authz_*, syscall_file_probe …)
│   ├── run_all.sh                   # 14개 TC 자동화 스위트 (v2)
│   ├── query_siemx.py / query_event_types.py / analyze_privesc.py / dump_evidence.py
│   └── decompile_one.sh + DecompileAll.java   # Ghidra 헤드리스 디컴파일 드라이버
├── bin/        # (gitignore) 추출 바이너리·디컴파일·eBPF — 벤더 독점, 분석 .md만 공개
└── logs/       # (gitignore) 시스템/agent 진단 로그
```

## 검증 범위 (TC-01 ~ TC-14)

탐지 텔레메트리 / TLS·인증서 / 설정 변경 / **Anti-Tamper** / Symlink·TOCTOU / IPC 제어면 /
**저수준 커널(eBPF·io_uring·direct-syscall)** / 단명 프로세스 / 패키지·공급망 / 비특권 권한경계(4종).
상세: [validation_plan](docs/plans/edr_validation_plan.md).

## 환경 / 재현

* 대상: EDR-X Linux Agent <agent-version> / Ubuntu 24.04 · kernel 6.8.0 (Colima x86_64 VM)
* 연동: On-Prem 콘솔 + SIEM-X(OpenSearch) 로그 레이크 (엔드포인트·토큰은 `.env`)
* 도구 셋업: `analyzeHeadless`(Ghidra), radare2 6.x + r2ghidra(`pdg`). 디컴파일: `scripts/decompile_one.sh <binary>`.
* TC 실행: `INGEST_WAIT=420 bash scripts/run_all.sh` (Kafka 인제스천 래그 5~10분 반영).

## 면책 / 윤리

* 본 PoC는 **승인된 환경에서의 방어적 보안 검증**이다. 모든 권한상승·변조 재현은 격리 VM에서 수행했고,
  위험 자산(SUID 백도어·sudoers 오설정)은 테스트 직후 제거했다.
* finding은 제품 공격이 아니라 **운영 구성·가시성 개선**을 목적으로 하며, 벤더와 공유·협의되었다.
