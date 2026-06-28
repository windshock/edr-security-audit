# EDR-X EDR PoC — 중간 테스트 보고서

* **작성일**: 2026-06-19
* **대상**: 온프레미스 EDR-X EDR (Linux 센서) + SIEM-X(OpenSearch) 텔레메트리 파이프라인
* **검증 환경**: Colima VM (Ubuntu 24.04 LTS, x86_64 QEMU 에뮬레이션)
* **범위**: 14개 테스트 케이스(TC) 검증, 가시성/보안발견 2축 분석, 검증 자동화 개선
* **상태**: 동적 테스트 단계 완료. 정적 분석(디컴파일) 단계는 미착수(아래 §6 참조)

---

## 1. 요약 (Executive Summary)

14개 TC에 대한 동적 검증을 완료했다. 로컬 실행은 14개 전량 성공했다. 평가는 두 축으로
분리한다(§3).

* **가시성**: 관측됨 12 / 부분 2 (프로세스는 잡히나 소켓-연결 전용 이벤트 없음) / SKIP 0
* **보안 발견**: 있음 1 (TC-12) / 없음 13

> 주의: "가시성 관측됨"은 EDR이 해당 행위를 **기록했다**는 뜻일 뿐, 그 행위가 **안전하거나
> 차단됐다**는 뜻이 아니다. 반대로 "보안 발견 없음"이라도 가시성이 `부분`이면 SOC
> 모니터링 사각이 존재한다. 두 축은 독립적이다.

핵심 결과는 세 가지다.

1. **[보안 발견] IPC 공격 표면**: 비루트 로컬 사용자가 EDR-X 에이전트의 9개 IPC 소켓
   **전부에 연결(connect)하고 데이터를 전송(send)할 수 있다.** 연결 계층에는
   호출자 권한 검증(SO_PEERCRED 등)이 없으며, 거부는 메시지 레이어에서만 발생한다.
   유일한 미확정 보안 발견으로, STEP 4 정적 분석에서 메시지 인증 강도를 확인해야 한다(§4-1).
2. **[긍정 결과] 직접 syscall 회피 무력화**: 파일 작업을 libc 대신 직접 syscall로 수행해도
   eBPF 센서가 동일하게 포착한다. userspace API 훅 우회 회피가 통하지 않는다(§4-4).
3. **[운영 결론] 탐지 신호 계층 공백**: raw 약 640만 건 대비 actionable 위협 16건, 상관분석 알림
   0건. SIEM-X이 사실상 raw 이벤트 레이크로만 기능한다. EDR 무능력이 아니라 correlation 룰·정책 등
   탐지 콘텐츠 미설정(온프렘 운영 성숙도) 문제다(§4-5).

운영상 유의점으로 SIEM-X 검색은 `.edr`/`.threats`를 함께 보는 `logs-edr*` 와일드카드가
필수임을 확인했고(§4-2), 검증 스크립트(`run_all.sh`)의 구조적 한계도 식별·수정했다(§4-3).

---

## 2. 검증 환경 (Environment)

| 구성요소 | 주소 | 역할 | 상태 |
|---|---|---|---|
| `edr-console.local` | `<EDR_ONPREM_CONSOLE>` | 매니지먼트 콘솔 (등록·위협·API) | ✅ 정상 |
| `edr-gw.local` | `<EDR_TELEMETRY_GATEWAY>` | telemetry gateway | ✅ 정상 (hosts 분리 후 복구) |
| SIEM-X | `<siemx_HOST>:5601` | OpenSearch (raw telemetry) | ✅ 정상, 10,000+ 문서 |

* 에이전트 6개 프로세스 정상 구동(orchestrator/network/scanner/agent/firewall/log_collector).
* 외부 LISTEN TCP 포트 없음. 아웃바운드 연결 1개(→ 콘솔 443).
* 데이터 흐름: `Agent → edr-gw.local(telemetry) → Kafka → SIEM-X` (약 5~10분 인제스천 래그).
  위협 레이어는 별도로 `Agent → 콘솔` 로 보고됨.

---

## 3. 14개 TC 최종 판정 (2축 평가)

이 스위트는 서로 다른 두 가지를 평가한다. 기존 단일 "PASS/FAIL"은 이 둘을 한 라벨에
뭉뚱그려 "PASS인데 발견사항 있음" 같은 혼동을 일으켰으므로, 아래와 같이 **축을 분리**한다.

* **가시성(Visibility)** — EDR이 이 행위를 어디까지 관측·기록했는가. 보안성과 무관.
  * `관측됨` = SIEM-X에 인제스천됨 (raw `.edr` 또는 위협 `.threats` 인덱스 중 하나 이상)
  * `부분` = 관련 프로세스는 잡혔으나 해당 행위(예: 소켓 연결) 전용 이벤트는 없음
  * `SKIP` = 환경 제약으로 평가 불가

> ⚠️ **인덱스 주의**: SIEM-X은 단일 인덱스가 아니다. raw 텔레메트리는 `logs-edr.edr`,
> 위협(threat)은 `logs-edr.threats`에 분리 저장된다. `.edr`만 검색하면 Anti-Tamper
> 같은 위협 이벤트를 놓친다 — 반드시 `logs-edr*` 와일드카드로 검색해야 한다.
* **보안 발견(Security Finding)** — 결과에서 우려할 점이 있는가. 가시성과 별개 축.
  * `없음` = 우려 없음(정상 탐지/정상 차단 포함)
  * `있음` = 추가 조사/보완이 필요한 발견

| TC | 이름 | 권한 | 로컬실행 | 가시성 | SIEM-X 근거 | 보안 발견 |
|:--|:--|:--|:--:|:--:|:--:|:--|
| TC-01 | Detection Telemetry | root | ✅ | 관측됨 | 1 (BEHAVIOR_INDICATOR) | 없음 |
| TC-02 | TLS Verification | root | ✅ | 관측됨 | 4 (인증서 생성/삭제) | 없음 |
| TC-03 | Configuration Manipulation | root | ✅ | 관측됨 | 4 (토큰 변경 시도) | 없음 |
| TC-04 | Anti-Tamper | root | ✅ | 관측됨 | `.threats` 인덱스에 kill 위협 적재 | 없음 (차단 성공) |
| TC-05 | Symlink/TOCTOU | root | ✅ | 관측됨 | 27 (심볼릭 링크 이벤트) | 없음 |
| TC-06 | Abstract Unix Socket IPC | root | ✅ | **부분** | 6 (프로세스만, 소켓연결 이벤트 없음) | 없음 (root 도달은 정상) |
| TC-07 | Low-Level Kernel Telemetry | root | ✅ | 관측됨 | 직접 syscall 파일 작업이 libc와 동일하게 FILEMODIFICATION+FILEDELETION 포착 | 없음 (회피 차단, §4-4) |
| TC-08 | Short-Lived Process Burst | root | ✅ | 관측됨 | 421 (`tc_08`) | 없음 |
| TC-09 | Package Manipulation | root | ✅ | 관측됨 | 25 (`tc_09`) | 없음 |
| TC-10 | Non-Root Permissions | crtester | ✅ | 관측됨 | 1 (비루트 프로세스) | 없음 |
| TC-11 | Non-Root Process Control | crtester | ✅ | 관측됨 | `.threats` 인덱스에 kill 위협 적재 (TC-04와 동일) | 없음 (차단 성공) |
| TC-12 | Non-Root IPC Access | crtester | ✅ | **부분** | 6 (프로세스만) | **있음** — 비루트가 9개 IPC 소켓 전부 connect+send 성공 (§4-1) |
| TC-13 | Non-Root Persistence | crtester | ✅ | 관측됨 | 4 (.bashrc 쓰기) | 없음 |
| TC-14 | Non-Root Privilege Bypass | crtester | ✅ | 관측됨 | 27 (`tc_14`) | 없음 |

**가시성 집계**: 관측됨 12 / 부분 2 (TC-06, TC-12) / SKIP 0
**보안 발견 집계**: 있음 1 (TC-12) / 없음 13

> ▸ "보안 발견 없음"이라도 가시성이 `부분`이면 모니터링 사각이 존재한다(§4-1 후단).
> ▸ SIEM-X 근거 건수는 마커 또는 스크립트명 매칭 문서 수. TC-08/09/14는 마커가
>   이벤트 데이터에 박히지 않아 스크립트명으로 확인했다.
> ▸ TC-04/11 차단 위협은 `.threats` 인덱스에 적재되므로 **관측됨**으로 판정(§4-2).
> ▸ TC-07은 테스트 버그 수정 후 재평가하여 **관측됨**으로 확정(§4-4).

---

## 4. 핵심 발견 (Key Findings)

### 4-1. [Finding] 비루트 IPC 소켓 도달 가능 — 연결 계층 접근 제어 부재

**관찰**: EDR-X 에이전트는 9개 Abstract Unix Socket(`@` prefix, SOCK_SEQPACKET)을
프로세스 간 통신에 사용한다. 비루트 사용자(`crtester`, uid 1000, edr-agent 그룹 미소속)로
9개 소켓 전부에 대해:

* `connect()` — **9/9 성공**
* `send()` (마커 페이로드) — **8/9 성공** (1개는 broken pipe)
* `recv()` — 전부 `errno 104 (Connection reset by peer)`

**해석**: 연결 수립과 첫 패킷 전송에는 호출자 검증이 없고, 거부는 **메시지 레이어**에서만
일어난다. 즉 임의의 로컬 사용자가 에이전트의 IPC 엔드포인트에 도달할 수 있다.

**정적 분석 확정 (STEP 4, `edr-x-agent` 디컴파일/디스어셈블)**:
* IPC는 **gRPC over abstract UDS(SOCK_SEQPACKET)** 구조 (빌드 출처 `<agent-build-id>`).
* `getsockopt`/`setsockopt` 사용처가 **전부 성능·연결용**(SO_ERROR/REUSEADDR/REUSEPORT/RCVBUF/
  SNDBUF/TCP_NODELAY 등)이고 **`SO_PEERCRED`/`SCM_CREDENTIALS`/`getpeereid`는 부재** →
  소켓 계층에 peer uid/pid 검증 코드가 없음을 확정.
* gRPC `InsecureServerCredentials`/`InsecureServerSecurityConnector` RTTI가 인스턴스화됨 →
  로컬 UDS 서버가 insecure 자격증명(transport 인증 없음) 경로 사용.
* IPC 와이어 프로토콜 RE 완료(strace): `@agent_ipc` SEQPACKET, connect 전 `SO_PASSCRED=1`,
  프레이밍=8B LE 길이+페이로드, 요청=8B 정적 method-ID(`a2d6ed9cfc61e58c`=상태조회), 응답=평문.
  인증 핸드셰이크(nonce/토큰) 없음.
* **미확정 (진행 중, 토큰 소진으로 중단)**: 비루트가 권한 IPC 메서드를 실제 호출 가능한지.
  캡처한 정확한 바이트를 replay하면 **root로도 reset(errno 104)** → 아직 정상 클라이언트 완전 재현 실패.
  유력 가설: 서버가 **SCM_CREDENTIALS(SO_PASSCRED)로 peer uid를 검증** → `sendmsg` ancillary로 creds를
  명시 전송해야 하며, 그렇다면 비루트는 uid 위조 불가로 거부될 것(=authz 작동). 다음 LLM이 검증해야 함.
  상세 인계: 핸드오프 [결정 20] / PoC [`scripts/tcs/ipc_authz_poc.py`](../../scripts/tcs/ipc_authz_poc.py).

**증거**:
* 소켓 열거: `/proc/net/unix` state 01(LISTEN), `@edr_component*/@agent*/@log_collector*` 9종
* 프로브: [`scripts/tcs/abstract_socket_probe.py`](../../scripts/tcs/abstract_socket_probe.py)
* 정적 분석: [`bin/decompiled/ipc_auth_analysis.md`](../../bin/decompiled/ipc_auth_analysis.md)
  (+ `edr-x-agent_ipc_setup.asm`, `edr-x-agent_ipc_evidence.txt`)
* 기존 TC-06/12가 0건이던 원인: `find -type s`/`nc -U`는 abstract 소켓을 구조적으로 탐지 불가

### 4-2. [운영 노트] SIEM-X은 다중 인덱스 — `.edr` + `.threats` 모두 검색해야 함

SIEM-X은 단일 인덱스가 아니다. 데이터가 종류별로 분리 저장된다:

* `logs-edr.edr` — raw telemetry(프로세스/파일/네트워크 등)
* `logs-edr.threats` — 위협(threat) 레코드. Anti-Tamper(TC-04/11)의 kill 위협이 여기 적재된다.

**SOC 검색·대시보드·탐지룰은 반드시 `logs-edr*` 와일드카드로 구성해야 한다.** `.edr`만
조회하면 Anti-Tamper 같은 위협 이벤트를 통째로 놓친다. 본 PoC의 조회 도구(`query_count.py` 등)도
이 와일드카드를 기본값으로 사용하도록 설정했다.

> 참고: TC-04/11 kill 위협은 `agent.log`(`11:09:17 KST`) · 콘솔 Threats API · SIEM-X
> `.threats` 인덱스 세 곳에서 `createdAt=2026-06-19T02:09:17.507698Z | Malware | kill | suspicious`로
> 마이크로초까지 일치 확인됨. `not_mitigated`는 정책 `suspicious threats protection = off` 때문(§7).

### 4-3. [Finding] 검증 자동화(run_all.sh)의 구조적 한계 수정

| 한계 | 영향 | 수정 |
|---|---|---|
| 마커 문자열만 검색 | TC-08/09/14 false-0 | 스크립트명 fallback 멀티키 검색 추가 |
| 인라인 50초 대기 | Kafka 래그(5~10분) 미커버 | 2단계 분리 + 지연 검증(`INGEST_WAIT` 기본 420초) |
| 단일 `.edr` 인덱스만 검색 | 위협(threats) 인덱스 미조회 | 기본 인덱스를 `logs-edr*` 와일드카드로 변경(§4-2) |
| PASS/FAIL 2분법 | 가시성·보안발견 두 축 혼동 | 가시성/보안발견 2축 verdict 분리(§3) |

수정본: [`scripts/run_all.sh`](../../scripts/run_all.sh) (v2), 신규 [`scripts/query_count.py`](../../scripts/query_count.py).

### 4-4. [긍정 결과] 직접 syscall API-훅 회피 무력화 (TC-07)

**관찰**: 동일 파일 작업을 두 경로로 수행하는 대조 실험을 했다.

* **CONTROL (libc)**: Python `open()`/`write()`/`unlink()` — userspace API 경유
* **TREATMENT (직접 syscall)**: `syscall(2/1/3/87)`로 open/write/close/unlink 직접 호출 — libc 래퍼 우회

SIEM-X 결과: **두 arm 모두 `FILEMODIFICATION` + `FILEDELETION` 동일하게 포착**(각 2건).

**해석**: 센서는 **커널 모듈 없이 eBPF 기반**으로, syscall tracepoint(libc 계층 아래)에서 훅한다.
따라서 "직접 syscall로 userspace API 훅을 우회"하는 고전적 회피 기법이 **통하지 않는다.** EDR의
저수준 가시성이 견고함을 입증한 긍정적 결과다.

> 단, 읽기 전용 `open`은 별도 이벤트가 남지 않는데 이는 EDR 통상 동작(읽기는 비텔레메트리)이며
> 회피 갭이 아니다. 검증 대상은 파일 생성/수정/삭제다.
> 검증 도구: [`scripts/tcs/syscall_file_probe.py`](../../scripts/tcs/syscall_file_probe.py)

### 4-4-A. [긍정 결과] io_uring(syscall-less) 파일작업도 탐지 — TC-07 진짜 빈칸 검증 (2026-06-24)

**배경**: TC-07 계획엔 `io_uring`이 명시됐으나 §4-4는 **direct-syscall만** 검증했다. direct-syscall은 libc만
우회할 뿐 `openat`/`write` **syscall은 그대로 발생**하므로 syscall tracepoint가 잡는 게 당연하다. 반면
**io_uring은 ring buffer로 syscall 자체를 발생시키지 않아** 차원이 다른 회피다(참조: ARMO "Curing" io_uring rootkit).

**방법**: raw io_uring(`io_uring_setup`/`io_uring_enter`, liburing 불필요)으로 `IORING_OP_OPENAT(O_CREAT)` +
`IORING_OP_WRITE`를 수행해 파일 생성·기록. 환경은 baseline(`lsm=bpf` 미설정). 도구: [`scripts/tcs/iouring_file.c`](../../scripts/tcs/iouring_file.c).

* **strace 검증**: 마커 파일에 대한 `openat`/`write` syscall **전무**, `io_uring_setup`+`io_uring_enter`만 발생 → syscall-less 입증.
* **SIEM-X 결과(이벤트 타입 집계)**:
  * io_uring 마커: **`FILEMODIFICATION` 포착** (대상 = io_uring으로 만든 `/tmp/IOURING_PROBE_...txt`) + PROCESSCREATION/BEHAVIOR_INDICATOR.
  * libc 대조군: `FILEMODIFICATION` 포착(동일).

**해석 (§4-4 보강·정정)**: 센서는 syscall tracepoint **뿐 아니라 VFS 레벨**(fentry/tracepoint, 예: `vfs_write`)에서도
파일 변조를 감지한다. io_uring 작업도 결국 커널 VFS 경로를 거치므로 **syscall을 우회해도 파일 수정 탐지는 유지**된다.
ARMO 블로그의 "EDR-X은 io_uring 우회에 영향 없음"이 본 PoC(baseline)에서도 **파일 작업에 대해 확인**됨.

> ⚠️ **탐지 ≠ 차단**: 본 결과는 **telemetry(탐지)** 차원이며 VFS-level이라 `lsm=bpf`와 무관하게 작동한다.
> 반면 **파일 변조 차단(enforcement)**은 BPF LSM 기반이라 baseline에서 무방비(→ [FND-001](../findings/FND-001_TC-04_anti_tamper_reevaluation.md)).
> 즉 baseline에서 io_uring 파일 변조는 **"탐지되나 차단되지 않는"** 상태다.
> 미검증 잔여: io_uring **네트워크/프로세스 실행**(IORING_OP_*) 탐지 — ARMO Curing은 C2까지 io_uring으로 수행.

### 4-5. [Finding] 탐지 신호 계층 공백 — SIEM-X이 raw 이벤트 레이크로만 기능

**관찰**: SIEM-X 인덱스의 신호 분포를 정량화했다.

| 계층 | 문서 수 | 비고 |
|---|---:|---|
| `logs-edr.edr` (raw 텔레메트리) | **6,406,152** | 프로세스/파일/네트워크 원시 이벤트 |
| `logs-edr.threats` (고유 위협, `threat.id` 기준) | **16** | 배포 전체 이력(2026-05~) 누적 |
| `logs-edr.alert` (correlation/상관분석 알림) | **0** | 인덱스 비어 있음 |

즉 raw 약 **640만 건 대비 actionable 위협 16건, 상관분석 알림 0건**이다. 그 16건도 대부분
고신뢰 known-malware(EICAR, Lockbit, 테스트 kill)이며, 본 PoC의 정찰·IPC 접근·지속성·권한 시도
(TC-01·03·05·06·08~14)는 **전부 raw `.edr`에만 적재되고 위협/알림으로는 승격되지 않았다.**

**해석**: SIEM의 본래 가치는 분석가가 raw를 일일이 뒤지지 않도록 **고신호 알림을 산출**하는 것이다.
현재 배포는 그 중간 신호 계층이 거의 비어 있어, SIEM-X이 사실상 **raw 이벤트 레이크**로만 기능한다.
원인은 EDR 무능력이 아니라 **탐지 콘텐츠·정책 미설정**이며, 기전은 다음과 같다:

1. **correlation/커스텀 탐지·상관 룰 부재** (`.alert`=0) — raw telemetry를 이름 있는 알림으로 승격시키는 룰이 없음. (최대 지렛대)
2. **정책 `suspicious threats protection = off`** — suspicious 등급(예: anti-tamper kill)이 `not_mitigated`로 방치.
3. **에이전트 내장 엔진은 고신뢰 멀웨어만 위협 승격** — 행위 기반 TTP는 raw로만 떨어짐.
4. **콘솔 event correlation/context view을 SIEM으로 포워딩하는 설계 부재.**

**온프렘 함의**: 온프렘은 SaaS와 달리 raw 저장소(SIEM-X) 조립과 탐지 콘텐츠 작성을 **운영자 책임**으로
이관한다. 미설정 온프렘은 정확히 이 증상("raw는 많고 고신호는 없음")을 보인다. 능력 부재가 아니라
**운영 성숙도(detection engineering) 공백**이다.

> 범위 주의: 본 항목은 신호 분포(구조적 증거)에 근거한다. 실제 행위 기반 공격 체인을 정식으로
> 돌려본 것은 아니므로, 에이전트 행위 엔진의 탐지 성능 자체를 단정하지는 않는다. 이는 가시성 축과
> 별개인 **탐지 효용 축**의 결론이다.

| 항목 | 등급(잠정) | 비고 |
|---|---|---|
| 탐지 신호 계층 공백 (SIEM이 raw 레이크로만 기능) | **중–높음 (운영)** | 위협 16 / 알림 0 vs raw 640만. 탐지 콘텐츠·정책 미설정. 운영 성숙도 문제(§4-5) |
| 비루트 IPC 소켓 도달 가능 | **중 (조사 필요)** | 소켓 계층 peer 검증 부재 확정(SO_PEERCRED 없음, insecure gRPC). gRPC authz 유무는 미확정 — 그 결과에 따라 상향 가능(§4-1) |
| 검증 쿼리의 인덱스 스코프 맹점 | **정보(방법론)** | EDR 결함 아님. `.edr`만 검색 시 위협 누락 → 와일드카드로 수정 완료(§4-2) |

> 등급은 동적 테스트 기반 잠정치이며, 정적 분석(STEP 4) 후 재산정한다.
> Anti-Tamper(TC-04/11)는 탐지·차단·SIEM 적재가 모두 정상이므로 위험 항목이 아니다(§4-2).

---

## 6. 미착수 사항

* **정적 분석 부분 착수**: 핸드오프의 "5종 바이너리 디컴파일 완료(task-547)" 기록과 달리 산출물이
  전무했다(확인됨). STEP 4에서 `edr-x-agent`에 대한 **타깃 분석을 실제로 수행**해 IPC 인증
  결과(§4-1)를 도출하고 `bin/decompiled/`에 산출물을 생성했다. 나머지 4종 바이너리(edrctl,
  edr-extension-host, edr-netctl, watchdog)의 디컴파일과 gRPC authz 경로 심화 분석은 미착수.

---

## 7. 권고 / 다음 단계

1. **(탐지 엔지니어링 — 최우선, §4-5)** 신호 계층 공백 해소:
   - correlation/커스텀 탐지·상관 룰을 작성해 raw telemetry를 명명된 알림으로 승격(현재 `.alert`=0).
   - 콘솔 event correlation/alerts을 SIEM-X으로 포워딩하는 파이프라인 구성 검토.
   - 정찰·IPC·지속성·권한 시도 등 행위 기반 TTP에 대한 탐지 룰 우선 작성.
2. **(정책)** `suspicious threats protection` 활성화 검토 — 현재 off라 Anti-Tamper kill이 not_mitigated.
3. **(SOC 운영)** SIEM-X 검색·대시보드·탐지룰을 반드시 `logs-edr*` 전체 인덱스 기준으로
   구성 — `.edr`만 보면 위협(`.threats`)을 놓친다(§4-2).
4. **(STEP 4 진행 중)** 정적 분석: IPC 소켓 계층 peer 검증 부재는 **확정**(§4-1). 남은 표적 —
   ① gRPC 애플리케이션 계층 authz 유무(정상 gRPC 클라이언트 PoC로 비루트 메서드 호출 시도),
   ② Anti-Tamper/eBPF self-protection 경로, ③ telemetry gateway 인증서 검증 로직.
5. **(선택)** 개선된 `run_all.sh` v2로 14개 TC 전량 재실행 후 보고서 재생성.

---

## 부록 A. 산출물 인덱스

| 파일 | 설명 |
|---|---|
| [`scripts/tcs/abstract_socket_probe.py`](../../scripts/tcs/abstract_socket_probe.py) | Abstract Unix Socket SEQPACKET IPC 프로브 |
| [`scripts/tcs/tc_06_socket.sh`](../../scripts/tcs/tc_06_socket.sh) | TC-06 (root IPC 프로브) — 재작성 |
| [`scripts/tcs/tc_12_nonroot_ipc.sh`](../../scripts/tcs/tc_12_nonroot_ipc.sh) | TC-12 (비루트 IPC 프로브) — 재작성 |
| [`scripts/tcs/syscall_file_probe.py`](../../scripts/tcs/syscall_file_probe.py) | TC-07 직접 syscall vs libc 대조 프로브 |
| [`scripts/tcs/tc_07_kernel.sh`](../../scripts/tcs/tc_07_kernel.sh) | TC-07 — 재작성 |
| [`scripts/run_all.sh`](../../scripts/run_all.sh) | 검증 스위트 v2 |
| [`scripts/query_count.py`](../../scripts/query_count.py) | SIEM-X 매칭 건수 조회 |
| [`edr-x_poc_handoff.md`](../../edr-x_poc_handoff.md) | 전체 진행 이력 (결정 15~17 추가) |
