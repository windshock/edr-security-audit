# FND-002 — 로컬 권한 상승(LPE) 탐지 평가: SUID 백도어 생성/euid=0

* **상태**: Confirmed (런타임 탐지 로그 확보) — EDR-X은 SUID LPE를 행동지표로 탐지. 단 위협(.threats) 미승격.
* **심각도(평가)**: 탐지 자체는 양호(긍정). **운영 가시성 갭은 Medium** — 행동지표가 actionable 위협/알림으로 승격되지 않음.
* **작성**: 2026-06-24
* **환경**: Colima VM, Ubuntu 24.04 / kernel 6.8.0, Agent <agent-version> (baseline: `lsm=bpf` 미설정)
* **관련**: [validation_plan TC-09/TC-14](file://<REPO_ROOT>/docs/plans/edr_validation_plan.md), [interim_report §4-5 가시성 갭](file://<REPO_ROOT>/docs/plans/interim_test_report_2026-06-19.md)

---

## 1. 배경 — 무엇을, 왜

* 사내 별도 리포트([담당자]/정보보호담당, 2026-03-25)에서 **`pip` 빌드 시스템(PEP 517) 악용 LPE**가 분석됨:
  `sudoers`에 `sudo pip install` 허용 → pip가 root로 `setup.py` 실행 → 임의 코드로 SUID 백도어 생성 → euid=0.
* ⚠️ **그 리포트의 "센서 미탐지 🔴 Critical"은 Cybereason(Rocky Linux 8.10) 테스트 결과**이며, **본 PoC 대상 제품(EDR-X)과 다른 제품·다른 환경**이다. 직접 비교 아님(타 제품 참고).
* 본 finding의 질문: **EDR-X이 이런 LPE(SUID 백도어 생성 + 권한 상승)를 탐지하는가?**

## 2. 방법 — pip 등가 LPE 체인 재현 (colima)

본 환경에 `pip` 미설치(외부 미러 차단)로, [담당자] 리포트 권고가 동일하게 지목한 **"인터프리터 sudo 오설정"** 안티패턴으로
등가 재현(`sudo python3`). pip든 python3든 핵심은 "sudo로 임의 root 코드 실행 → SUID 백도어 → euid=0"로 동일.

체인 (마커 `PRIVESC_PROBE_20260624`, 비파괴 — 산출물 즉시 정리):
1. `sudoers.d`에 `crtester ALL=(root) NOPASSWD:/usr/bin/python3` (취약 오설정)
2. 비-root `crtester`가 `sudo python3 evil.py` 실행 → root로 악성 코드
3. `cp /bin/bash /tmp/..._rootbash` → `chown root` → `chmod 4755` (SUID 백도어)
4. `crtester`가 `/tmp/..._rootbash -p` 실행 → **`uid=1000(crtester) euid=0(root)` 확인**
5. 정리: rootbash·poc 디렉토리·sudoers drop-in 삭제

도구: 재현 명령은 일회성(인라인). 탐지 분석: [`scripts/analyze_privesc.py`](../../scripts/analyze_privesc.py), [`scripts/query_event_types.py`](../../scripts/query_event_types.py).

## 3. 결과 — EDR-X 탐지 (SIEM-X 실측)

### 3-1. 이벤트 분포 (raw `.edr`, 마커 검색 46건)
| 프로세스 × 이벤트 | 의미 |
|---|---|
| `cp` → **BEHAVIOR_INDICATOR** + FILEMODIFICATION | bash 복사 탐지 |
| `chmod` → **BEHAVIOR_INDICATOR** | **SUID 설정 탐지** |
| `sudo`/`python3.12`/`bash`/`dash` → PROCESSCREATION | 공격 프로세스 계보 |
| `rm` → FILEDELETION | (정리 단계) |

### 3-2. 탐지 로그 원문 — SUID 설정 (핵심)
```
BEHAVIOR_INDICATOR
  timestamp : 2026-06-24T05:08:25.801Z
  endpoint  : colima   | agent: <agent-version>
  process   : chmod (pid 49755)
  cmdline   : chmod 4755 /tmp/PRIVESC_PROBE_20260624_rootbash
  indicator : identifier="SUID-IND"  name="SUID_SET"
              description="Set the setuid bit on a file"
  MITRE     : T1548.001 (Setuid and Setgid)
  category  : Privilege Escalation / Defense Evasion / Persistence
```
+ `cp /bin/bash /tmp/..._rootbash` 도 동일 시각 별도 BEHAVIOR_INDICATOR로 포착.

→ **EDR-X은 SUID 권한상승을 내장 행동지표 `SUID_SET` + MITRE `T1548.001`로 정확히 탐지·분류한다.**

### 3-3. 그러나 — 위협 미승격 (가시성 갭)
```
logs-edr.threats (actionable 위협, 마커 검색): 0건
```
행동지표(T1548.001)는 **raw `.edr`에만 적재**되고 **위협 알림(.threats)으로 승격되지 않음**.
→ [interim_report §4-5](file://<REPO_ROOT>/docs/plans/interim_test_report_2026-06-19.md)의 가시성 갭("raw 640만 vs 위협 16 vs 알림 0")과 일치.

## 4. 결론

* **"미탐지"가 아니라 "탐지되나 위협 알림으로 미승격"**:
  * **탐지 능력**: 양호 — SUID 권한상승을 `SUID_SET`·`T1548.001`로 정확 식별 (런타임 로그 확보). ✅
  * **운영 가시성 갭**: 행동지표가 actionable 위협으로 승격되지 않아, **SOC가 raw/BI를 능동 헌팅하지 않으면 알림 없이 묻힘**. ⚠️
* **제품 비교 주의**: Cybereason(Rocky8) "미탐지"는 타 제품·타 환경 결과로, EDR-X 평가의 직접 근거가 아님(참고용).
* **본질**: 이 LPE의 근본 원인은 **`sudoers` 오설정**(인터프리터에 sudo 허용)이며 EDR 결함이 아님. EDR 관점 평가는 "탐지 여부"이고, EDR-X은 탐지함.

## 5. 권고

* (호스트 하드닝) `sudoers`에서 `pip`/`python`/`easy_install` 등 인터프리터 계열 sudo 권한 제거. 불가피 시 와일드카드 금지·전체 경로 한정. ([담당자] 리포트 권고와 동일)
* (탐지 운영) `SUID_SET` 등 권한상승 **행동지표를 위협/알림으로 승격하는 correlation 룰/상관분석** 구성 검토 — 현재 raw에만 머무는 갭 해소.
* (주기 점검) `find / -perm -4000 -type f` 로 비인가 SUID 정기 스캔.

## 6. 후속 (미검증)
* `crtester`의 **euid=0 실행(`rootbash -p`) 자체**가 별도 행동지표로 잡히는지 — 현재 BI는 cp/chmod(생성 단계)에 집중. 실행/권한획득 단계 탐지는 미확정.
* 실제 `pip install .` 경로(PEP 517 빌드 백엔드) 재현 — 본 환경 pip 미설치로 등가(python3) 재현에 그침. pip 특유 프로세스 계보(pip→build→setup.py) 탐지는 미검증.
