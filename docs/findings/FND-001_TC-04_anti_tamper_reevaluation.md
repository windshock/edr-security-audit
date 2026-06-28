# FND-001 — TC-04 Anti-Tamper 재평가: 파일 무결성 보호 미작동 (환경 조건부)

* **상태**: **Confirmed — Vendor(EDR-X) 공식 확인 완료(§3-7)**. 인과 통제실험(§3-6) + vendor 공식 인정 + 사과. 영향 배포판에 Ubuntu22+ 명시.
* **심각도**: **High (영향 배포판의 기본 설치 환경)** — `lsm=bpf`가 파일 무결성 보호의 전제조건(vendor 공식 확인). 영향 배포판(Ubuntu20/22+, Debian11, OracleLinux9/10, SLES15 등) 기본 설치 시 파일보호 미작동 + 콘솔 silent. Agent 업그레이드로 해소 안 됨.
* **작성**: 2026-06-20
* **업데이트**: 2026-06-24 (**vendor EDR-X 공식 확인·사과 회신** — §3-7) / 2026-06-22 (on-prem API + `lsm=...,bpf` 대조 통제실험)
* **첨부**: [repro_FND-001.txt](file://<REPO_ROOT>/docs/findings/repro_FND-001.txt) (재현 절차/로그, vendor 서포트팀 제출용)
* **관련**: [validation_report_latest.md](file://<REPO_ROOT>/docs/plans/validation_report_latest.md) TC-04, [runtime_enforcement_analysis.md](file://<REPO_ROOT>/bin/ebpf/runtime_enforcement_analysis.md), [file_protection_lsm_analysis.md](file://<REPO_ROOT>/bin/ebpf/file_protection_lsm_analysis.md), [ebpf_anti_tamper_analysis.md](file://<REPO_ROOT>/bin/ebpf/ebpf_anti_tamper_analysis.md)

---

## 1. 요약 (TL;DR)

기존 검증에서 **TC-04 Anti-Tamper에 PASS**를 부여했으나, 이는 **불완전한 평가**였다.

* TC-04 통과 기준은 두 가지 — ① 프로세스 종료 차단(watchdog/kill), ② **핵심 파일 삭제·이름변경의 커널 레벨 차단**.
* 기존 PASS는 ①(kill 차단)만 확인하고 부여됐다. **②(파일 무결성 보호)는 검증되지 않았다.**
* 후속 정적+런타임 분석 결과, **본 PoC 환경에서 ②는 작동하지 않는다**: root 공격자가 agent 바이너리·설정·디렉토리를
  자유롭게 변조/생성/삭제할 수 있다(재현 완료).
* 따라서 정정된 verdict: **TC-04 = PARTIAL** (kill 차단 PASS / 파일 보호 FAIL[환경 조건부] / 콘솔 기본 상태 가시성 없음).
* 2026-06-22 회사망에서 on-prem API를 확인한 결과, `colima` 에이전트는 `Enabled/connected/up-to-date`로 표시되고
  `missingPermissions=[]`, `userActionsNeeded=[]`, `showAlertIcon=false`였다. 즉 REST agent 상태만으로는 파일보호 저하를 알 수 없다.

---

## 2. 무엇이 잘못되었나 (평가 오류)

* **TC-04 통과 기준 원문**(`edr_validation_plan.md`):
  > "프로세스 종료 즉시 Watchdog에 의해 복구되거나, **핵심 파일(`/opt/edr-x/bin/*`)에 대한 삭제/이름변경 행위
  > 자체가 커널 레벨에서 차단**되어야 함."
* **부여된 결과**(`validation_report_latest.md`): `TC-04 | Anti-Tamper | root | PASS | 에이전트가 차단 → 이벤트 미생성이 정상`
* **오류**: "anti-tamper = kill 차단"으로 범위를 좁혀, kill 하나가 막히자 anti-tamper 전체에 PASS를 줬다.
  통과 기준에 **명시된 파일 삭제/이름변경 차단**을 실제로 시험하지 않았다. (기준은 "또는"이지만, 두 보호는
  별개 기능이므로 한쪽 PASS로 전체 PASS를 줄 수 없음 — 특히 파일보호는 anti-tamper의 핵심 절반.)

---

## 3. 근거 (정적 + 런타임)

### 3-1. 정적: anti-tamper는 kill + 파일무결성 양쪽을 LSM으로 설계
* `edr_kill_attempt_lsm`(=`lsm/task_kill`) + 파일보호 LSM **8종**(`edr_file_{open_write,chmod,chown,create,delete,rename,change_xattr,ioctl_setflags}_lsm`).
  전부 `(device,inode)` allowlist + verdict `-EPERM`(enforcing). → 파일 보호는 **설계상 명백히 존재**.
* kill만 이중화: LSM + **kprobe override**(`edr_kill_attempt_sys`, `bpf_override_return`). 파일보호는 **LSM 단일**.

### 3-2. 런타임: 이 커널에서 BPF LSM 비활성 → 파일보호 미작동
환경: Colima VM, kernel **6.8.0-64-generic**, agent PID 518.
* `/proc/cmdline`에 **`lsm=` 없음** → active LSM `lockdown,capability,landlock,yama,apparmor`(**bpf 미포함**).
* agent 로드 BPF prog 171개 중 **LSM(type 29) = 0개**(kprobe 142 / tp 23 / perf 6) → 모든 `*_lsm` attach 실패.

### 3-3. 행동 재현 (root, 비파괴)
| 테스트 | 기대(보호 정상 시) | 실제 결과 |
|---|---|---|
| 보호 바이너리 `edrctl` O_WRONLY open | EPERM(차단) | **성공 (차단 안 됨)** |
| 보호 디렉토리 `/opt/edr-x/bin/`에 파일 생성 | EPERM(차단) | **성공 → 즉시 삭제** |
| agent(518) `kill -0` | EPERM(차단) | **EPERM (차단됨)** ← kprobe override |
| 일반 proc / systemd `kill -0` | OK | OK (대조군) |

→ **kill은 막히고 파일 변조는 안 막힘** — 통과 기준 ②가 본 환경에서 미충족.

### 3-4. on-prem 콘솔/API 가시성 (2026-06-22)
회사망에서 `edr-console.local` on-prem API와 `edr-mcp`를 재확인했다.

| 확인 항목 | 관찰 |
|---|---|
| `/web/api/v2.1/agents?computerName__contains=colima` | 1건 반환, agent `<agent-version>`, `networkStatus=connected`, `isActive=true`, `isUpToDate=true` |
| Agent health/action fields | `missingPermissions=[]`, `userActionsNeeded=[]`, `showAlertIcon=false`, `operationalState=na` |
| Activity API | 가입, report/file fetch, EICAR, kill threat 활동만 확인. `bpf`, `lsm`, `degraded`, 파일보호 실패 활동 없음 |
| Threat API | EICAR/kill threats만 확인. 파일보호 LSM 실패 threat 없음 |
| Misconfiguration/Vulnerability GraphQL | on-prem nginx가 502 반환. 이 레이어는 현재 판정 근거로 사용 불가 |
| 로컬 설치 PDF | 보유 가이드 3종에서 `lsm`, `bpf`, `eBPF` 부트 요구사항 직접 언급 없음. 단 콘솔 운영 가이드는 설치 전 Release Notes and Requirements 확인을 지시 |

**결론 강도**:
* Target-proven: 이 on-prem 배포의 기본 agent 상태/API/activity/threat 레이어는 파일보호 LSM 미작동을 표시하지 않는다.
* Hypothesis-only: vendor Release Notes에 `lsm=bpf`가 명시되어 있는지 여부는 아직 원문으로 확정하지 못했다.

### 3-5. Vendor(파트너사) 공식 회신과 검증 (2026-06-22)
파트너사 파트너사([담당자])가 `lsm=bpf` 관련 공식 회신을 보냄. 요지:
1. EDR-X Linux Agent의 eBPF는 **"LSM hook 방식이 아니라 kprobe/tracepoint 기반"** 으로 동작.
2. `lsm=bpf`는 **필수 요구사항 아님**, 공식 가이드/기술문서에 요구 명시 없음.
3. Anti-Tamper는 **"eBPF가 아닌 커널모듈(kprobe) + Agent 자체 프로세스 보호 조합"** 으로 동작 → `lsm=bpf` 없이도 보호 영향 없음.
4. 특정 커널에서 anti-tamper 미동작 증상이 있으면 **로그 수집해 서포트팀 분석 요청**하겠다고 제안.

**회신에 대한 검증 (디스크 전수 확인, 2026-06-22):**
`/opt/edr-x/ebpfs/core/` 에 각 보호의 변종(_lsm/_sys/_kern) 분포를 확인:

| 보호 | `_lsm`(LSM hook) | `_sys`(kprobe override) | kprobe fallback |
|---|---|---|---|
| `edr_kill_attempt` | ✅ | ✅ | **있음** |
| `fork_bomb` | ✅ | ✅ (+`_kern`) | 있음 |
| **`edr_file_*` (8종)** | ✅ | **❌ 없음** | **전무** |

**평가 — vendor 주장은 부분적으로만 맞다:**
* ✅ **kill/프로세스 보호**: vendor 설명대로 kprobe override(`edr_kill_attempt_sys`)가 실재하고 **이 커널에서 작동**(§3-3 agent만 kill -0 EPERM). `lsm=bpf` 없이도 kill은 보호됨 → vendor 주장 일치.
* ❌ **파일 무결성 보호**: vendor 주장과 **충돌**. 파일보호는 `edr_file_*_lsm` **8종 LSM 단독이며 kprobe(_sys) 버전이 디스크에 존재하지 않음**. `lsm=bpf` 미설정 시 attach 실패 → fallback 없음 → §3-3에서 변조 재현됨.
* ❌ **"eBPF는 LSM hook 방식이 아니다"** 는 바이너리 사실과 불일치: `lsm/task_kill`, `lsm/file_open`, `lsm/path_chmod` 등 **BPF_PROG_TYPE_LSM 프로그램 9종**이 디스크에 명백히 존재(섹션명·`bpf_lsm_verify_prog` 심볼 확인).

→ **vendor는 anti-tamper를 "프로세스(kill) 보호"로 좁게 해석**했다(본 finding §2의 평가 오류와 동일한 좁힘).
   "lsm=bpf 없이 보호 영향 없음"은 **프로세스 보호엔 참, 파일 무결성 보호엔 거짓**(이 환경 재현 기준).

**~~미확정~~ → 확정(§3-6)**: 정상 환경(`lsm=...,bpf`) 대조실험을 실시하여 `edr_file_*_lsm`이 실제 attach·작동함을 확인.

### 3-6. 대조실험 — `lsm=...,bpf` 재부팅 (2026-06-22, 결정적)
동일 VM을 `lsm=lockdown,capability,landlock,yama,apparmor,bpf`로 재부팅(`/etc/default/grub.d/99-lsm-bpf.cfg`)하여
유일 변수가 `lsm=bpf`이도록 통제 후 §3-3을 재시험.

> ⚠️ 재부팅 직후 ~2분간은 anti-tamper 정책 미적용 윈도우(보호 맵 미충전)라 kill·파일보호 모두 비활성 →
> `kill -0`이 EPERM으로 복귀한 시점(정책 적용 완료)을 확인한 뒤 측정. (이 통제 안 하면 false-negative)

| 테스트 (root) | `lsm=bpf` 없음 (baseline §3-3) | **`lsm=bpf` 있음 (대조)** |
|---|---|---|
| active LSM에 `bpf` | 없음 | **있음** |
| agent 로드 LSM prog(type 29) | **0개** | **61개** |
| agent `kill -0` | EPERM | EPERM |
| 보호 바이너리 `edrctl` O_WRONLY open | **성공(미작동)** | **EPERM(차단)** |
| 보호 디렉토리 파일 생성 | **성공(미작동)** | **EPERM(차단)** |
| 보호 바이너리 unlink | (미시험) | **EPERM(차단)** |

**결론 (Target-proven, 인과 확정)**:
* **`lsm=bpf`가 파일 무결성 보호의 전제조건**이다. 유일 변수를 바꾼 대조실험에서 파일보호가 미작동→작동으로 전환됨.
* 즉 vendor의 "`lsm=bpf`는 불필요·영향 없음"은 **파일 무결성 보호에 대해 반증됨**. (kill 보호는 양쪽 다 작동 — kprobe override, vendor 주장과 일치.)
* `edr_file_*_lsm` 8종은 dead code가 아니라 `lsm=bpf` 환경에서 실제 enforcing으로 동작.

---

### 3-7. Vendor 최종 회신 — EDR-X 공식 확인 (2026-06-24) ⭐ 본 finding 공식 확증
파트너사([담당자] 수석)가 **EDR-X 공식 서포트 확인 결과**를 회신. 본 finding의 모든 핵심 주장을 공식 인정.

| 질의 | EDR-X 공식 답변 |
|---|---|
| **Q1** 기본 부트에서 파일보호 미동작이 의도된 동작인가 | **"의도된 동작 확인."** Linux Agent **<agent-version-family>** 파일 무결성 보호(`edr_file_*` 이벤트)는 **BPF LSM hook으로 구현**. bpf 없이 부팅 시 LSM hook 비활성 → 파일 보호 레이어 미적용. 프로세스(kill) 보호는 별개 구현으로 BPF LSM 무관. (우리 관찰과 일치 명시) |
| **Q2** `lsm=bpf`가 전제조건인가 | **"전제조건임을 공식 확인."** BPF LSM은 x86_64 커널 5.6+/ARM64 5.19+ 지원이나, 아래 배포판은 **기본 비활성 출하**라 `lsm=bpf` 설정 필요: Debian11, OracleLinux9/10, SLES15(≤15.5), **Ubuntu20, Ubuntu22+ (x86_64/ARM64)**. → 고객 환경(Ubuntu24.04/6.8.0)이 해당. 활성화 절차는 **우리 대조실험과 동일**. "이전 'lsm=bpf 불필요' 안내는 Agent/프로세스 보호 한정, BPF LSM 파일보호엔 미적용. **Agent 업그레이드로 해소 안 됨**. 잘못된 안내 사과." |
| **Q3** 보호 저하 시 콘솔 신호 | **"콘솔은 BPF LSM 활성 여부 별도 표시 안 함."** 보호 저하 상태에서도 콘솔 정상(Enabled) 표시가 현재 제품 동작(우리 관찰 4와 일치). 호스트에서 직접 확인 권고: `cat /sys/kernel/security/lsm`, `edrctl providers status`. |

**Vendor의 framing (추가 안내)**: Linux Anti-Tamper는 심층 방어(defense-in-depth) 수단이며, **이미 root/커널 권한을 확보한 공격자에 대한 절대 보장은 아님**(Linux 구조적 한계 — root는 lsm 끈 채 재부팅 가능 = 우리 baseline 조건). "공격 난이도를 높이는 통제 수단"으로 활용 권고.

**검증팀 평가**:
* 본 finding의 사실 주장(파일보호=BPF LSM 의존 / `lsm=bpf` 전제조건 / 콘솔 silent / Agent 업그레이드 무관)은 **vendor 공식 확인으로 전부 확증**됨. §2의 "TC-04 PASS는 불완전 평가"였다는 판단도 정당화됨.
* Vendor의 "root엔 절대보장 아님" framing은 **부분 타당하나 핵심을 비껴감**: 본 finding의 운영 리스크는 "root가 anti-tamper를 우회한다"가 아니라 **(a) Ubuntu22+ 등 영향 배포판에서 기본 설치 시 파일보호가 처음부터 미작동인데 (b) 콘솔이 이를 silent하게 정상으로 표시**한다는 점. 즉 SOC가 "파일보호 작동 중"으로 오인할 운영 가시성 갭이 본질. (vendor도 Q3에서 콘솔 미표시를 인정.)
* 실무 결론: 영향 배포판은 **설치 시 `lsm=bpf` 적용을 필수 체크리스트화** + **호스트 측 `edrctl providers status`/`/sys/kernel/security/lsm`로 보호 상태 직접 모니터링** 필요.

## 4. 보안 영향

* 이 환경에서 root 권한 공격자는 agent를 **kill하지 못해도**(kill 차단 유지) **agent 바이너리·설정을 변조/교체/삭제 가능**.
  → 재시작/업그레이드 시점에 무력화, 또는 설정 변조로 탐지 우회 경로가 열릴 수 있음.
* anti-tamper의 본질은 "root조차 EDR을 무력화 못 하게 막는 것"인데, 그 절반(파일 무결성)이 본 환경에서 부재.
* **조용한 변조가 kill보다 위험할 수 있음**: kill은 콘솔에 "agent offline" 신호를 주지만, 파일 변조는 즉각적 신호가 약함.

---

## 5. 원인 분류 — 남은 판정 기준

현재 단계에서 **"제품 결함"으로 단정하지 않는다.** 다만 이 배포에서의 운영 리스크는 확인됐다.

**Vendor 회신(2026-06-22)으로 원인 분류가 갱신됨**: vendor가 `lsm=bpf`를 **명시적으로 "불필요"**라고 답변(§3-5).
→ 아래 표의 "①설치요구 명시(Low)" 시나리오는 **배제**된다. 즉 "우리 환경 구성 미스" 면죄부가 사라짐.

| 시나리오 | 판정 | 심각도 |
|---|---|---|
| ~~설치 요구사항에 `lsm=bpf` 명시~~ | ~~PoC 환경 구성 오류~~ | ~~Low~~ — **vendor가 불필요라 답변, 배제됨** |
| vendor가 "lsm=bpf 불필요·영향없음"이라 했으나 **실제로는 파일보호가 이 표준 커널에서 미작동**(재현됨) | **제품/문서의 갭 또는 vendor 이해 불일치** | **High (this deployment)** |

→ vendor 회신은 finding을 약화시키지 않고 오히려 **충돌을 선명하게** 만든다: "영향 없다"는 공식 답변과
   "변조 재현됨"이라는 행동 증거가 정면 배치. 메커니즘(LSM/kprobe) 논쟁과 무관하게 **결과(파일 변조 성공)가 반례**.

**§3-6 대조실험으로 인과 확정**: `lsm=bpf`만 켜자 파일보호가 작동(변조 차단)으로 전환. 즉 vendor가 "불필요"라 한
`lsm=bpf`가 **파일 무결성 보호의 전제조건**임이 통제실험으로 증명됨. → 본 배포 심각도 **High** 확정.
"환경 구성을 권장값으로 했다면 보호됐을 것"이라는 완화 가능성도 동시에 성립하나, vendor가 그 설정을 명시적으로
불필요라 안내한 점에서 **문서/안내의 갭**이 핵심.

추가 변수 — **silent failure 여부**:
* 기본 REST/API 상태 기준으로는 silent에 가깝다: `missingPermissions=[]`, `userActionsNeeded=[]`, `showAlertIcon=false`.
* 콘솔 UI의 별도 상세 패널이나 vendor support bundle 분석에서 degraded 신호가 존재하는지는 추가 확인 필요.
* 운영자가 기본 Endpoint 상태만 신뢰한다면 SOC가 파일보호를 받고 있다고 착각할 수 있음 → 별도 High finding 후보.

---

## 6. 정정된 Verdict

| 항목 | 기존 | 정정 |
|---|---|---|
| TC-04 Anti-Tamper (전체) | ✅ PASS | ⚠️ **PARTIAL** |
| └ 프로세스 kill 차단 | (암묵 PASS) | ✅ PASS (kprobe override, 런타임 확증) |
| └ 파일 삭제/변조 차단 | (미검증, PASS에 흡수됨) | ❌ **FAIL** — `lsm=bpf` 미설정 시 미작동(vendor 공식 확인, §3-7). 영향 배포판 기본설치 환경에 해당 |
| └ LSM 실패 콘솔 가시성 | (미검증) | ❌ **콘솔 silent (vendor 인정)** — 보호 저하해도 Enabled 표시. 호스트 측 직접 확인만 가능 |

---

## 7. 후속 액션

1. **[완료] vendor `lsm=bpf` 요구 여부 확인** — vendor가 "불필요"라 공식 회신(§3-5). 환경구성 미스 시나리오 배제.
2. **[권장→다음] vendor 회신 (§8 초안)** — 재현 증거 패키징해 서포트팀 분석 요청 (vendor가 로그 제출 제안함).
3. **[권장, 결정적] 대조 재부팅** — VM을 `lsm=lockdown,...,bpf`로 부팅 후 §3-3 재시험.
   파일보호 LSM이 살아나면 → "vendor가 불필요라 한 lsm=bpf가 실은 파일보호의 전제"임을 확정(High 굳힘).
   안 살아나면 → 파일보호 LSM이 다른 전제를 가지거나 미사용 → 재조사.
4. **[권장] 실삭제 재현(신중)** — 보호 파일 실제 unlink/rename으로 파괴적 변조 가능성 최종 확인(VM 스냅샷 후).
5. **[잔여] 콘솔 UI 상세 패널 확인** — 기본 API 외 UI에서 degraded/unsupported 표시가 있는지 스크린샷 근거.
6. **[완료] TC-04 verdict를 `validation_report_latest.md`에 PARTIAL로 정정 반영.**

---

## 8. Vendor 회신 초안 (재현 증거 첨부, draft)

> 안내 감사합니다. `lsm=bpf`가 EDR-X Agent의 필수 요구사항이 아니며 anti-tamper가 kprobe/프로세스 보호로
> 동작한다는 점 확인했습니다. 다만 저희 PoC 환경에서 **프로세스(kill) 보호와 파일 무결성 보호의 동작이 갈리는** 현상을
> 재현하여 공유드립니다. 제안 주신 대로 로그/재현 절차 첨부하니 서포트팀 분석을 요청드립니다.
>
> **환경**: Ubuntu kernel `6.8.0-64-generic` (x86_64), Agent `<agent-version>`, on-prem 콘솔상 `Enabled/connected/up-to-date`.
> `/proc/cmdline`에 `lsm=` 파라미터 없음 (active LSM: `lockdown,capability,landlock,yama,apparmor`).
>
> **관찰 1 — 프로세스(kill) 보호: 정상 작동** ✅
> root로 agent 프로세스에 `kill -0` 시 `EPERM`(차단). 일반 프로세스/systemd는 정상. → kprobe override 동작 확인.
>
> **관찰 2 — 파일 무결성 보호: 미작동** ❌ (재현)
> root로 다음이 모두 **성공**(차단 안 됨):
> - 보호 바이너리 `/opt/edr-x/bin/edrctl` 를 쓰기 모드(O_WRONLY)로 open
> - 보호 디렉토리 `/opt/edr-x/bin/` 에 신규 파일 생성
> 즉 root 공격자가 agent 바이너리/설정을 변조·교체·삭제할 수 있는 상태입니다.
>
> **관찰 2-1 — 대조실험: `lsm=...,bpf`로 재부팅 시 파일 보호 정상 작동** ✅
> 동일 VM에 `lsm=lockdown,capability,landlock,yama,apparmor,bpf` 커널 파라미터만 추가해 재부팅한 결과,
> agent가 LSM 프로그램 61개를 로드하고 위 관찰 2의 작업이 **모두 `EPERM`으로 차단**되었습니다(보호 바이너리
> open/생성/삭제 모두). 즉 **`lsm=bpf` 설정이 파일 무결성 보호의 전제조건**임을 통제실험으로 확인했습니다.
> 이는 "`lsm=bpf`는 불필요하다"는 안내와 배치됩니다.
>
> **관찰 3 — agent가 로드한 BPF 프로그램 타입**: LSM(type 29) **0개** (kprobe 142 / tracepoint 23 / perf 6).
> 디스크에는 `edr_file_*_lsm`(파일보호 LSM) 8종이 존재하나 이 커널에서 attach되지 않았고, 해당 보호의 kprobe 대체
> 버전(`_sys`)은 디스크에 없습니다.
>
> **관찰 4 — 콘솔 가시성**: 위 상태에서도 on-prem 콘솔/REST API는 해당 엔드포인트를 `Enabled / connected /
> missingPermissions=[] / showAlertIcon=false` 로 표시합니다. 운영자가 파일보호 저하를 인지하기 어렵습니다.
>
> **질의**:
> 1. 기본 부트(`lsm=bpf` 미설정) 커널에서 파일 무결성 보호가 미동작하는 것이 의도된 동작인지요?
> 2. 회신 주신 "`lsm=bpf` 불필요" 안내와, 저희 대조실험(`lsm=bpf` 설정 시에만 파일보호 작동)이 배치됩니다.
>    파일 무결성 보호에는 `lsm=bpf`가 전제조건인 것으로 보이는데, 권장 커널 구성 가이드가 있는지요?
> 3. 파일보호 저하 시 콘솔에 노출되는 신호가 있는지요? (현재 해당 엔드포인트는 콘솔상 정상 표시)

(※ 발송 전 사내 검토 권장. 재현 절차/로그는 `repro_FND-001.txt` 첨부.)
