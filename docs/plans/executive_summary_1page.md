# EDR-X Linux EDR PoC — 중간 보고 (1-Page Executive Summary)

**작성일** 2026-06-24 | **대상** EDR-X Linux Agent <agent-version> | **환경** Ubuntu 24.04 / kernel 6.8.0 (Colima VM) + 사내 On-Prem 콘솔(`edr-console.local`) + SIEM-X(OpenSearch)

---

## 종합 의견

EDR **탐지 엔진의 기본 역량은 견고**하다(저수준 syscall·io_uring 회피 무력화, 위협 차단, 권한상승 TTP 식별). 다만 **① 환경 구성 의존적 보호 공백**과 **② 탐지→위협 알림 승격의 운영 가시성 갭** 두 가지가 확인되어, 운영 단계에서 보완이 필요하다.

## 검증 결과 요약

* **TC 14종**: 탐지·텔레메트리·차단·권한경계 전반 정상. 단 TC-04(Anti-Tamper)는 **PARTIAL**로 정정(아래 FND-001).
* **텔레메트리 파이프라인**: Agent → EDR Gateway → Kafka → SIEM-X 정상(인제스천 5~10분 래그).

## 주요 발견

| ID | 내용 | 등급 | 상태 |
|---|---|---|---|
| **FND-001** | **`lsm=bpf` 미설정 커널에서 파일 무결성 보호(Anti-Tamper) 미작동.** root가 Agent 바이너리/설정 변조 가능. 콘솔은 정상(Enabled)으로 표시되어 인지 불가(silent). | **High**(영향 배포판 기본설치) | **벤더 공식 확인·사과 완료** |
| **FND-002** | **로컬 권한상승(SUID 백도어)은 탐지됨**(행동지표 `SUID_SET`, MITRE T1548.001). 단 행동지표가 **위협 알림으로 승격되지 않음**(raw에만 적재). | Medium(가시성) | 탐지 로그 확보 |
| io_uring | syscall 우회(io_uring) 파일작업도 **VFS-level로 정상 탐지**. 회피 무효(긍정). | — | 검증 완료 |
| 가시성 갭 | SIEM-X raw 약 **640만 건** vs actionable 위협 **16건** vs 상관분석 알림 **0건**. 정찰·IPC·지속성·권한 시도는 raw에만 적재. | Medium | 관찰 |

## 벤더(EDR-X/파트너사) 대응

* FND-001에 대해 EDR-X 공식 확인: 파일 보호는 **BPF LSM 기반이며 `lsm=bpf`가 전제조건**, Agent <agent-version-family> 적용. 영향 배포판 — **Ubuntu 20/22+**, Debian 11, Oracle Linux 9/10, SLES 15 등(기본 비활성 출하). Agent 업그레이드로 해소 불가. **초기 "불필요" 안내 정정 및 사과** 수령.

## 권고

1. **(필수) 영향 배포판 설치 시 `lsm=bpf` 커널 파라미터 적용을 표준 체크리스트화** + 호스트 측 `edrctl providers status`로 보호 상태 직접 점검(콘솔이 표시하지 않음).
2. 권한상승·SUID 등 **행동지표를 위협/알림으로 승격하는 correlation 상관분석 룰** 구성(현재 raw에만 머무는 갭 해소).
3. `sudoers`에서 `pip`/`python` 등 인터프리터 sudo 권한 제거 등 호스트 하드닝.

---
*상세: [FND-001](../findings/FND-001_TC-04_anti_tamper_reevaluation.md) · [FND-002](../findings/FND-002_LPE_privilege_escalation_detection.md) · [상세 시험 보고서](interim_test_report_2026-06-19.md)*
