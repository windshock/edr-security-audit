---
name: edr-security-audit
description: >
  Linux EDR(EDR-X·Cybereason 등) 보안 점검 방법론. 격리 환경에서 EDR 에이전트의
  탐지 가시성·자기보호(Anti-Tamper)·권한 경계·저수준 회피 내성을 방어적으로 검증한다.
  트리거 — "EDR 점검", "anti-tamper 검증", "EDR 탐지 평가", "EDR 우회 테스트",
  "엔드포인트 보안 PoC", "에이전트 무결성 검증", "LSM/eBPF enforcing 확인",
  "io_uring 우회", "권한상승 탐지", "EDR 텔레메트리 가시성".
---

# EDR 보안 점검 (Linux)

격리된 VM에서 Linux EDR 에이전트를 **방어적 관점**으로 점검하는 재사용 방법론.
레퍼런스 구현: EDR-X Linux PoC (이 저장소). 제품과 무관하게 적용 가능.

> ⚠️ **승인된 환경에서만.** 모든 변조·권한상승 재현은 격리 VM에서 수행하고, 위험 자산
> (SUID 백도어·sudoers 오설정 등)은 테스트 직후 제거한다. 벤더 독점물(바이너리·디컴파일·eBPF)은
> 저작권 대상 — 분석 결과(우리 저작)만 공유하고 원본은 비공개.

## 0. 평가 2축 — 혼동 금지

EDR 점검 결과는 **반드시 두 축으로 분리**한다. 단일 PASS/FAIL은 "PASS인데 발견 있음" 같은 혼동을 부른다.

* **가시성(Visibility)** — EDR이 행위를 *관측·기록*했는가. (보안성과 무관)
* **보안 발견(Security Finding)** — 결과에 우려할 점이 있는가.

추가로 **탐지(detection) ≠ 차단(enforcement) ≠ 알림 승격(alerting)** 세 단계를 항상 구분:
* 탐지 = 텔레메트리에 이벤트/행동지표 적재 (raw 인덱스)
* 차단 = 커널/정책 레벨에서 행위 거부 (예: LSM `-EPERM`)
* 알림 승격 = 행동지표가 actionable 위협/알림으로 올라감 (threat/alert 인덱스)
→ 흔한 갭: **"탐지는 되나 알림으로 승격 안 됨"** 또는 **"탐지는 되나 차단 안 됨"**.

## 1. 점검 매트릭스 (TC, 제품 불문)

| # | 항목 | 핵심 질문 |
|---|---|---|
| 1 | 탐지 텔레메트리 | 기본 프로세스/파일/네트워크 이벤트가 SIEM에 적재되나 |
| 2 | TLS·인증서 검증 | 서버 인증서 hostname/CN 검증 강제하나 (`InsecureSkipVerify` 흔적?) |
| 3 | 설정 변경 | 에이전트 설정/토큰 변경 시도가 탐지되나 |
| 4 | **Anti-Tamper** | 프로세스 kill·파일 변조 차단하나 (→ §2) |
| 5 | Symlink/TOCTOU | 경로 기반 처리에 race/symlink 우회 있나 |
| 6 | IPC 제어면 | 비특권 사용자가 에이전트 IPC 소켓에 도달/주입 가능한가 (→ §4) |
| 7 | **저수준 회피** | eBPF·**io_uring**·direct-syscall 우회를 탐지하나 (→ §3) |
| 8 | 단명 프로세스 | 짧게 명멸하는 프로세스를 놓치나 |
| 9 | 패키지·공급망 | 설치 체인(pip PEP517 등) 악용 탐지하나 (→ §5) |
| 10~14 | 비특권 권한경계 | 일반 사용자의 권한경계·권한상승·지속성 (→ §5) |

## 2. Anti-Tamper enforcing 검증 (가장 중요)

EDR 자기보호는 **커널 계층(BPF LSM / kprobe override)** 으로 root조차 막는 게 핵심. 점검 절차:

1. **메커니즘 식별** — 디스크 eBPF 오브젝트(`*_lsm` vs `*_sys`) + 디컴파일로 LSM/kprobe 구분.
   * `lsm/<hook>` 프로그램 = enforcing (return `-EPERM`으로 커널이 거부)
   * `kprobe + bpf_override_return` = enforcing fallback (syscall 강제 실패)
   * tracepoint/kprobe(override 없음) = 탐지 전용
2. **런타임 활성 확인** — `cat /sys/kernel/security/lsm` 에 `bpf` 포함 여부. agent가 로드한 BPF prog 타입 집계(`/proc/<pid>/fdinfo`, type 29=LSM).
   * ⚠️ **핵심 함정**: `lsm=bpf` 커널 파라미터가 없으면 BPF LSM 미활성 → `*_lsm` 보호가 **attach 실패**. 영향 배포판(Ubuntu 20/22+, Debian 11, OracleLinux 9/10, SLES 15 등)은 기본 비활성 출하.
3. **행동 재현(비파괴)** — root로 보호 파일 `O_WRONLY` open / 보호 디렉토리 파일 생성 → `EPERM`이면 차단, 성공이면 무방비.
4. **대조 통제실험** — `lsm=...,bpf`로 재부팅 후 재시험. 차단으로 전환되면 `lsm=bpf`가 전제조건임을 입증.
   * ⚠️ 재부팅 직후 ~2분은 정책 미적용 윈도우(보호 비활성). `kill -0 <agent>`가 EPERM 복귀(=정책 적용)한 뒤 측정.
5. **allowlist 앵커 확인** — 신뢰 caller 판정이 경로(`/proc/<pid>/exe` 문자열, mount-ns 우회 가능) vs `(device,inode)`(우회 불가) 중 무엇인지.
6. **콘솔 가시성** — 보호 저하 시 콘솔이 degraded를 표시하나, 아니면 silent(Enabled로 표시)인가.

> 레퍼런스 발견(FND-001): EDR-X 파일보호는 LSM 단독(kprobe fallback 없음) → `lsm=bpf` 미설정 시 무방비, 콘솔 silent. 벤더 공식 확인.

## 3. 저수준 회피 — io_uring / direct-syscall

* **direct-syscall**(libc 우회, `syscall(...)`): syscall은 발생 → syscall tracepoint가 탐지. 통과 기대.
* **io_uring**(ring buffer, syscall 없음): kprobe/tracepoint/seccomp **블라인드**. **VFS-level(fentry) 훅만 탐지**.
  * PoC: `IORING_OP_OPENAT`+`IORING_OP_WRITE`로 파일작업(`scripts/tcs/iouring_file.c`). `strace`로 `openat`/`write` 미발생 확인.
  * 탐지 검증: SIEM에 `FILEMODIFICATION` 적재되면 VFS-level 탐지(견고). 없으면 갭.
  * ⚠️ 탐지(VFS, lsm 무관)와 차단(LSM, lsm=bpf 필요)은 별개. 미검증 잔여: io_uring **네트워크/exec**.

## 4. IPC 제어면 authz

* abstract Unix socket은 `find -type s`/`nc -U`로 못 찾음 → `/proc/net/unix` + `SOCK_SEQPACKET` 프로브 사용(`scripts/tcs/abstract_socket_probe.py`).
* 연결 계층(connect/send) vs 메시지 계층(authz) 분리 확인. peer 검증이 `SO_PEERCRED`/`SCM_CREDENTIALS`인지, caller exe 경로 allowlist인지(→ mount-ns 우회 가설).

## 5. 권한상승(LPE) 탐지

* 패턴: sudo 가능한 인터프리터(pip/python) 오설정 → root로 임의코드 → SUID 백도어(`chmod 4755`) → 비-root `euid=0`.
* 탐지 검증: SUID 설정이 행동지표(예: EDR-X `SUID_SET`, MITRE `T1548.001`)로 잡히나 + **위협으로 승격되나**(threat 인덱스).
* 근본 원인은 보통 `sudoers` 오설정(EDR 결함 아님) — 평가는 "탐지 여부"에 한정.

## 6. 정적 분석 (선택, 심층)

* 디컴파일: Ghidra headless(`scripts/decompile_one.sh` + `DecompileAll.java`) 또는 radare2+r2ghidra(`pdg`).
  예외 많은 C++ 바이너리는 Ghidra 흐름복원 취약 → 핵심 함수는 r2 disasm 교차검증.
* eBPF: VM `/opt/<vendor>/ebpfs/` 에서 `.o` 추출 → radare2 BPF arch 디스어셈블. libbpf 빌드는 BTF/CO-RE 소스 주석이 임베드돼 로직 복원 가능.

## 7. 탐지 콘텐츠 성숙도 (운영)

raw 텔레메트리만 쌓이고 위협/알림 승격이 없으면 SIEM이 "raw 레이크"로만 기능. 측정:
`.edr`(raw) vs `.threats`(위협) vs `.alert`(상관분석) 인덱스 건수 비교. 격차가 크면 correlation 룰/정책 미설정.

## 8. Finding 작성 / 증거

* finding은 사실/전제/검증강도를 분리(`security-hypothesis-lab` 스킬 연계). 벤더 framing과 실측 충돌 시 **행동 재현 결과로** 반박.
* 증거 보존: strace(syscall 유무), SIEM 이벤트 JSON 원본(가공 없이 `_source`), 대조실험 표. **위험 자산만 정리, 무해 증거는 보존.**
* 템플릿: `docs/findings/FND-*.md` + `repro_*.txt`(제조사 제출용 재현절차+로그+질의).

## 참조
* 레퍼런스 케이스: `docs/findings/FND-001`(anti-tamper), `FND-002`(LPE), `docs/plans/interim_test_report*`(§4-4-A io_uring).
* 도구: `scripts/` (TC 프로브·SIEM-X 쿼리·디컴파일 드라이버), `scripts/tcs/`.
* 가설 검증 프레임: `security-hypothesis-lab` 스킬.
