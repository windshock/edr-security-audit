# STEP 4.3 #1 — eBPF anti-tamper exclusions/allowlist 등록 기준 + mount-ns 우회 정적 평가

* **일시**: 2026-06-19 (오프라인 정적 분석 — VM 불필요)
* **출처**: `bin/ebpf/edr_kill_attempt_lsm_kern.o` 에 **임베드된 BTF/CO-RE 소스 주석**(libbpf 빌드가 .o에 원본 C 라인 보존).
* **질문**: anti-tamper allowlist는 무엇으로 호출자를 신뢰하는가? ipc_auth_analysis §8의 **mount-ns 경로혼동 우회가 LSM에도 통하는가?**
* **결론**: **LSM allowlist는 `(device, inode)` 기반 → mount-ns 경로혼동 우회는 LSM에 통하지 않음.**
  userspace IPC(경로 문자열 기반, 우회 가능)와 **신뢰 앵커가 다름**.

---

## 1. `lsm/task_kill` 보호 로직 (임베드 소스 재구성)

```c
// victim(죽임당하는 대상) 식별
pid_t pid = BPF_CORE_READ(task, tgid);            // kill 대상 tgid
if (bpf_map_lookup_elem(&agent_pids, &pid) == NULL) { ... }   // 대상이 보호 agent pid가 아니면 무관

// killer(호출자) 신원/네임스페이스
pid_t current_pid = BPF_CORE_READ(current, tgid);
unsigned int current_pid_ns_level = BPF_CORE_READ(current_pid_struct, level);  // 컨테이너 인식
if (current_pid == 1) { ... }                     // init 특례
if (current_pid_ns_level != 0) { ... }            // 중첩 PID ns(컨테이너) 처리

// 메인 게이트
if (sig != 0 && (!get_exclusions_enabled() || !is_pid_excluded(current_pid, false))) {
    // → 여기서 allowed_exes 검사 후 미허용이면 verdict=-EPERM (STEP 4.2)
}
```

### 두 개의 allowlist 계층
1. **pid 기반** — `is_pid_excluded()`:
   ```c
   u8 * excluded = bpf_map_lookup_elem(&edr_pex, &pid);   // per-pid exclusion map
   return *excluded & mask;                              // 비트마스크(이벤트종류별)
   ```
2. **실행파일 inode 기반** — `allowed_exes`:
   ```c
   const struct inode * exe_inode = BPF_CORE_READ(current, mm, exe_file, f_inode);
   file_id.device = inode_dev(inode);    // st_dev
   file_id.inode  = inode_id(inode);     // i_ino  (= BPF_CORE_READ(inode, i_ino))
   return bpf_map_lookup_elem(&allowed_exes, &exe_file_id) != NULL;
   ```

### 관련 BPF maps
| map | 용도 |
|---|---|
| `agent_pids` | 보호 대상(victim) agent pid 집합 |
| `allowed_exes` | kill 허용 실행파일 allowlist — **키 = {device, inode}** |
| `edr_pex` | per-pid exclusion(비트마스크) |
| `config_map` | `exclusions_enabled` 등 설정(`EDR_CONST_REWRITE_DEFINE(EBPF_CONFIG_STATIC_EXCLUSIONS_ENABLED)`) |

---

## 2. 핵심 보안 평가 — mount-ns 우회는 LSM에 통하지 않는다

| 계층 | 신뢰 앵커 | mount-ns 경로혼동 우회 |
|---|---|---|
| **userspace IPC authz** (ipc_auth_analysis §8) | `readlink(/proc/<pid>/exe)` **경로 문자열** 비교 | ✅ **취약** — bind-mount로 경로 위장 시 통과 |
| **eBPF LSM self-protection** (본 분석) | `current->mm->exe_file->f_inode`의 **`(device, inode)`** | ❌ **불통** — 커널 inode 객체 직접 판독 |

* LSM은 경로 문자열이 아니라 **실행 중인 파일의 커널 inode 객체**를 CO-RE로 in-kernel 판독한다.
  bind-mount로 신뢰 경로(`/opt/edr-x/bin/edrctl`) 위에 다른 바이너리를 덮어도 그 파일의 **inode가 다르므로**
  `allowed_exes`에 없음 → **deny(-EPERM)**. ipc_auth_analysis §8의 우회는 **kill 보호에는 적용 불가**.
* 역으로 `allowed_exes`에 들려면 **등록된 파일과 동일 inode**여야 함. 동일 inode를 갖는 hardlink는 결국 같은 파일
  (코드 치환 아님)이므로 의미 있는 우회가 아님. (userspace IPC는 hardlink를 경로 불일치로 거부 — §7-2와 정합, 두 계층 상보적.)

### 함의
* **EDR의 두 신뢰 계층이 서로 다른 앵커**를 쓴다: IPC=경로(약함), 커널 LSM=inode(강함). 커널 자기보호가 더 견고.
* ipc_auth_analysis의 mount-ns 우회는 **IPC 명령 표면**에 국한되며, **agent kill 차단(self-protection)을 깨지 못한다**.

---

## 3. 확정도 / 한계

* **확정(정적)**: allowlist 키 = (device, inode), pid 기반 보조 exclusion, 컨테이너(pid ns) 인식 — 임베드 소스 직접 근거.
* **추정**: `allowed_exes`/`edr_pex` map을 채우는 userspace 등록 기준(서명 검증 후 등록인지, 어떤 이벤트로 갱신되는지)은
  userspace(agent) 측 코드 — 별도 추적 필요(STEP 4.3 후속). 등록 자체가 서명 기반이면 매우 견고.
* **미검증(VM 필요)**: 런타임에서 mount-ns 덮어쓰기로 kill 시도 시 실제 -EPERM deny 재현. (서버 미연결로 보류)
* **일반 한계**: `exe_file`는 최종 execve 파일 기준 → 허용 프로세스의 사후 침해/ memfd·deleted-file 엣지케이스는 본 분석 범위 밖(미검증).

## 3.5 userspace 등록 경로 (STEP 4.3 #3, 오프라인 — agent 바이너리 pdg)

`allowed_exes` map을 채우는 userspace 등록 흐름:

* **등록 함수** `fcn.0x1924049` — 실행파일 **리스트를 순회**(`while (R14 != R13)`, stride 0x20)하며 각 항목을
  `func_0x019c46a0`(file_id 계산) → `func_0x01923aa0`(map 삽입)로 등록, 로그 `Added {} to anti-tamper allowed executables for {}`.
* **file_id = (device, inode)** — `func_0x019c46a0` 반환식 `arg1>>0xc & 0xfff00 | arg1&0xff | (arg1&0xfff00)<<0xc`
  은 Linux **`dev_t` major/minor 인코딩** 공식 → userspace가 파일의 **device 번호를 계산**(stat 기반)해 키 구성.
  커널 LSM의 `inode_dev(inode)`/`inode_id(inode)`와 정확히 대응 → **등록과 검증이 동일한 (dev,inode) 앵커 공유**.
* **리스트 출처 = 관리(mgmt) 정책** — config 키 `anti-tamper_executables_allowed_to_modify_files`.
  → allowlist는 **콘솔/관리정책으로 admin이 지정**한 실행파일 집합(로컬 임의 등록 아님).

### 서명 검증 관련 (확정도 구분)
* 바이너리에 **파일 서명 검증 서브시스템** 존재: `, signature verified:`, `UNAUTHORIZED_PUBLISHER`,
  `Microsoft Trust List Signing`, `is_cert_valid`/`cert_id`, `ValidSignature`/`SignedSignature`,
  `trusted_verification_root`/`trusted_verification_process`, `publisher_trust_type`.
* **추정/미확정**: 이 서명 검증이 **anti-tamper 등록을 게이트**하는지(서명 통과한 exe만 allowlist 추가)는 코드로
  단정 못 함. 등록의 1차 신뢰는 **mgmt 정책(admin 채널)**이고, 서명 검증은 주로 위협 평판/분류 경로로 보임.
  (등록까지 서명 게이트면 더 견고 — 후속 확인 대상.)

## 4. 후속 (STEP 4.3 잔여)
1. userspace에서 `allowed_exes`/`edr_pex`/`agent_pids` map 채우는 경로 — 등록 트리거·검증(서명?) 추적.
2. `edr_file_*_lsm_kern.o` 7종도 동일 (device,inode) allowlist + `lsm/file_*` deny 구조인지 확인(VM에서 .o 추출 필요).
3. (VM 복구 시) mount-ns 덮어쓰기 kill deny 런타임 재현 + memfd/deleted-exe 엣지 테스트.
