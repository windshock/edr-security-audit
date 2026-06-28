# STEP 4.3 A — LSM enforcing 런타임 재현 (VM 로컬, 콘솔 불필요)

* **일시**: 2026-06-20
* **환경**: Colima VM, Ubuntu kernel **6.8.0-64-generic** (QEMU/Virtualization.framework x86_64), agent `edr-agent` PID 518.
* **질문**: 정적으로 확정한 BPF LSM enforcing(`-EPERM` deny)이 실제로 런타임에 작동하는가?
* **핵심 발견**: **이 커널에서 BPF LSM은 비활성 → LSM 기반 enforcing 미작동.**
  단, **kill 보호는 kprobe `bpf_override_return` fallback으로 여전히 작동**. **파일보호는 LSM 단일이라 완전 무방비.**

---

## 1. BPF LSM 비활성 — 근본 원인

* `/proc/cmdline`에 **`lsm=` 파라미터 없음** → 커널 기본 LSM만 활성:
  `lockdown,capability,landlock,yama,apparmor` (**`bpf` 미포함**).
* `CONFIG_BPF_LSM=y`로 빌드는 됐으나, `BPF_PROG_TYPE_LSM`을 attach하려면 `lsm=...,bpf` 부트 설정 필요 → 미충족.
* **런타임 증거** — agent(518)가 로드한 BPF prog 171개 타입 분포:

  | prog_type | 의미 | 개수 |
  |---|---|---|
  | 2 | KPROBE | 142 |
  | 5 | TRACEPOINT | 23 |
  | 17 | PERF_EVENT | 6 |
  | **29 (LSM)** | **BPF LSM** | **0** |

  → `edr_kill_attempt_lsm`, `edr_file_*_lsm`(8종) 등 **모든 LSM 프로그램이 attach 실패(0개 로드)**.

## 2. 행동 재현 결과

### 2-1. 파일보호: 미작동 ❌ (LSM 단일 → fallback 없음)
| 테스트(root, 비파괴) | 결과 |
|---|---|
| 보호 바이너리 `/opt/edr-x/bin/edrctl` O_WRONLY open | **성공** (file_open LSM 차단 없음) |
| 보호 디렉토리 `/opt/edr-x/bin/`에 새 파일 생성 | **성공** (path_mknod/file_open LSM 차단 없음) |

→ 이 환경에서 **anti-tamper 파일 무결성 보호가 완전 무력**. root가 agent 바이너리/설정/디렉토리를 자유롭게
   수정·생성·삭제 가능. (STEP 4.3 #2에서 정적 확인한 `edr_file_*_lsm` enforcing이 런타임엔 부재.)

### 2-2. kill 보호: **작동** ✅ (kprobe override fallback)
| 대상 | `kill -0` (root) |
|---|---|
| 일반 자식 프로세스 | OK |
| init/systemd (pid 1) | OK |
| **agent edr-agent (518)** | **EPERM (차단)** |
| watchdog (49 등) | OK (보호대상 아님) |

→ **agent(518)만 정확히 kill 차단**. BPF LSM 0개인데도 막힘. 원인 = **kprobe `bpf_override_return`**:
   `edr_kill_attempt_sys_kern.o` 임베드 소스 `bpf_override_return(ctx, ret);` + 심볼 `BPF_FUNC_override_return`,
   섹션 `kprobe/__x64_sys_kill`·`SyS_tgkill`·`SyS_rt_sigqueueinfo`. → sys_kill 계열 syscall을 kprobe에서
   `-EPERM`으로 강제 종료. (kill -0도 sys_kill 경유하므로 EPERM.)

## 3. 핵심 함의 — 이중화 비대칭

STEP 4.2에서 본 "kill = LSM + kprobe(sys) 이중구조" vs "파일보호 = LSM 단일"의 차이가 **런타임 보안에 직결**:

| 보호 | 메커니즘 | `lsm=bpf` 없는 커널에서 |
|---|---|---|
| **agent kill** | LSM **+ kprobe override(sys)** | ✅ **유지** (kprobe가 fallback) |
| **파일 무결성** | LSM 단독 (`edr_file_*_lsm`) | ❌ **무방비** (fallback 없음) |

* **공격 표면(이 환경 한정)**: `lsm=bpf` 미설정 커널(예: 기본 Ubuntu 부트, 본 colima/QEMU VM)에서 EDR-X의
  **anti-tamper 파일 보호가 작동하지 않는다.** root 권한 공격자는 agent를 **kill하지는 못해도**(kprobe override),
  바이너리/설정 파일 변조·교체·삭제가 가능 → 재시작/업그레이드 시점에 무력화 경로가 열릴 수 있음.
* 이는 **정적 분석만으로는 발견 불가** — 정적으론 LSM enforcing이 명백하나, 런타임에선 커널 부트 설정에 의해
  LSM 계층 전체가 silently 무력화됨. (가설검증 lab의 전형적 "전제 검증" 성과.)

## 4. 확정도 / 한계

* **확정**: 이 VM에서 BPF LSM 0개 로드(prog_type 집계), 파일보호 우회 행동 재현(open/create 성공),
  kill 차단 작동(agent만 EPERM) + kprobe override 코드 근거.
* **미확정**: kill 차단이 kprobe override 외 경로(watchdog 재생성 등)와 어떻게 결합되는지 정밀 추적은 미완.
* **환경 특이성**: 이 결론은 **`lsm=bpf` 미설정 커널**에 한정. 정상 배포(EDR-X 권장 부트 설정 + `lsm=...,bpf`)
  에서는 파일보호 LSM도 작동할 것으로 예상 — 즉 **배포 환경 의존적 갭**이지 제품 결함으로 단정 불가.
  설치 가이드가 `lsm=bpf` 커널 파라미터를 요구하는지 별도 확인 가치 있음.

## 5. 후속
* EDR-X Linux 설치 요구사항에 `lsm=bpf`(또는 `lsm=...,bpf`) 부트 파라미터 명시 여부 확인 → 갭이 "설정 미스"인지 "기본 무방비"인지 판정.
* (선택) `lsm=lockdown,...,bpf`로 VM 재부팅 후 동일 테스트 → 파일보호 LSM 작동 시 갭이 환경요인임을 대조 확증.
* userspace가 LSM attach 실패를 감지/보고하는지(`Failed to initialize libbpf_loader` 등) 로그·코드 확인 — agent가 degraded 상태를 콘솔에 알리는가.
