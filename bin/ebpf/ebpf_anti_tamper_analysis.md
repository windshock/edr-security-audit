# STEP 4.2 — eBPF anti-tamper: `edr_kill_attempt` enforcing vs detection 분석

* **일시**: 2026-06-19
* **질문**: agent 자기보호(누군가 agent를 kill 시도)는 **커널 레벨에서 차단(enforcing)** 되는가, **탐지만(detection-only)** 하는가?
* **결론**: **Enforcing 확정** — `lsm/task_kill` BPF LSM이 `-EPERM` 반환으로 kill을 **커널에서 거부**. 동시에 텔레메트리 발생. kprobe 변종은 별도 탐지.
* **방법**: VM(`/opt/edr-x/ebpfs/core/`)에서 실제 eBPF `.o` 추출 → radare2 6.1.6 BPF 디스어셈블.
* **산출물**: `bin/ebpf/edr_kill_attempt_lsm_kern.o`, `edr_kill_attempt_sys_kern.o`, `kill_kern.o`, `/tmp/lsm_task_kill.asm`

---

## 1. 두 개의 kill 감시 프로그램 (이중 구조)

| 오브젝트 | 섹션(attach) | BPF 타입 | 역할 |
|---|---|---|---|
| `edr_kill_attempt_lsm_kern.o` | **`lsm/task_kill`** | `BPF_PROG_TYPE_LSM` (BPF_LSM_MAC) | **차단(enforcing)** — return으로 kill 거부 |
| `edr_kill_attempt_sys_kern.o` | `kprobe/__x64_sys_kill`, `/SyS_tgkill`, `/SyS_rt_sigqueueinfo`, `/SyS_rt_tgsigqueueinfo` | `BPF_PROG_TYPE_KPROBE` | **탐지/텔레메트리** — syscall 진입 관측 |

* LSM(`security_task_kill`)은 kernel hook의 verdict를 BPF return으로 결정 → 음수 errno면 거부.
* kprobe는 진입 관측(verdict 권한 없음, override 미사용) → 탐지/이벤트.
* 프로그램 심볼: `int task_kill_prog(u64 *ctx)`, license=GPL.

---

## 2. `task_kill_prog` 반환값 = LSM verdict (r6)

전 경로가 `LBB0_32`(`0x148: r0 = r6 ; 0x150: exit`)로 수렴 → **r6가 곧 verdict**.
* `r6 = 0` → **ALLOW** (kill 허용)
* `r6 = 0xffffffff` (= int **-1 = -EPERM**) → **DENY** (kill 차단)

### 핵심 결정 블록 (0x6d8–0x6f0, `edr_kill_attempt_kern.h:102` / `exclusions.h:18`)
```asm
0x6d8  call 0x1                 ; is_excluded(caller)  → r0
0x6e0  mov64 r6, 0x0            ; exclusions.h:18  기본 verdict = ALLOW
0x6e8  jne r0, 0x0, +0xff4b     ; r0 != 0 (allowlist에 있음) → LBB0_32 로 점프 = ALLOW 반환
0x6f0  lddw r6, 0xffffffff      ; r0 == 0 (allowlist에 없음) → verdict = -EPERM = DENY
       ... event_ring_buffer.h: 이벤트 push (텔레메트리) ...
```

→ **default-deny**: 보호 대상을 죽이려는 호출자가 exclusion(신뢰 allowlist)에 없으면 **커널이 kill을 거부**.
신뢰 호출자(예: 정식 업그레이더/언인스톨러)는 allowlist로 허용.

## 3. 프로그램 로직 맵 (소스 헤더 기준)

디스어셈블 내 소스 참조로 재구성한 흐름:
1. `edr_kill_attempt_lsm_kern.c` — `task_kill` ctx에서 victim/signal/cred 추출, `ebpf_config.h`로 보호 enabled 확인.
2. `anti_tamper.h` + `inode_utils.h` — **호출자(killing process)의 실행 파일 inode/경로 해석**(caller 신원 확정).
3. `exclusions.h` — caller가 **exclusion(allowlist)** 인지 map lookup. 있으면 ALLOW, 없으면 DENY(-EPERM).
4. `event_ring_buffer.h` — kill 시도 이벤트를 ring buffer로 userspace에 전달(탐지 텔레메트리).

소스 라인 빈도: `edr_kill_attempt_kern.h`(15), `inode_utils.h`(12+), `anti_tamper.h`(12+), `exclusions.h`, `event_ring_buffer.h`.

---

## 4. 종합 / 함의

* **확정**: EDR-X agent self-protection은 **enforcing**이다. `lsm/task_kill` BPF LSM이 비-allowlist 호출자의
  agent kill 시도에 `-EPERM`을 반환해 **커널 레벨에서 차단**한다. (TC-04 "kill 차단" 런타임 관측과 코드 정합.)
* **이중 구조**: LSM(차단) + kprobe(`sys_kill` 계열, 탐지). 차단과 탐지가 분리되어 우회 시에도 탐지 경로 잔존.
* **공격 표면 메모**: verdict는 **exclusions allowlist**에 의존. allowlist 판정이 caller inode/경로 기반이면(§3-2)
  ipc_auth_analysis의 mount-ns 경로혼동류 우회 가능성을 같은 관점에서 점검할 가치가 있음(미검증, 후속).
* userspace 측(STEP 4.1)의 `kill_threat_handler`/`agent-enabled` 플래그와는 별개 계층: 이쪽은 **에이전트가 위협을
  죽이는** mitigation, eBPF LSM은 **에이전트가 죽임당하지 않도록** 막는 self-protection.

## 5. 후속 표적 (STEP 4.3)
1. `exclusions` map 채우는 userspace 경로 — allowlist 등록 기준(서명/경로/pid) 추적.
2. 동일 패턴 LSM 군 검증: `edr_file_*_lsm_kern.o`(open_write/chmod/chown/delete/rename/xattr/create), `fork_bomb_lsm`.
   → 파일 보호도 동일하게 enforcing인지(`lsm/file_*` return -EPERM).
3. mount-ns/exclusion 우회 가설의 LSM 측면 재현(런타임).
