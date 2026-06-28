# STEP 4.3 #2 — 파일보호 LSM 군(edr_file_*_lsm) enforcing/allowlist 구조 검증

* **일시**: 2026-06-20 (VM 로컬 추출 — 콘솔 통신 불필요)
* **질문**: 파일보호 LSM 8종 + fork_bomb_lsm이 `edr_kill_attempt_lsm`(STEP 4.2)과 동일한
  `(device,inode)` allowlist + `-EPERM` deny(enforcing) 구조인가?
* **결론**: **그렇다 — 전 군이 동일 패턴.** 각자 의미에 맞는 `lsm/*` 훅에서 보호대상 파일 변경 시도를
  비-allowlist caller에 대해 `-EPERM`으로 **커널 차단**. anti-tamper가 kill뿐 아니라 **파일 무결성 전반에 enforcing**.
* **추출물**: `bin/ebpf/edr_file_*_lsm_kern.o` (8종), `fork_bomb_lsm_kern.o`. 공통 소스헤더 `edr_file_change_lsm_kern.h`.

---

## 1. LSM 훅 매핑 (각 보호 동작 → 커널 훅)

| 객체 | 메인 LSM 훅 | 보호 의미 |
|---|---|---|
| `edr_file_open_write_lsm` | `lsm/file_open`, `lsm/path_truncate` | 보호파일 쓰기열기/truncate |
| `edr_file_chmod_lsm` | `lsm/path_chmod` | 권한 변경 |
| `edr_file_chown_lsm` | `lsm/path_chown` | 소유자 변경 |
| `edr_file_create_lsm` | `lsm/path_{mknod,mkdir,symlink,link}` | 생성/심볼릭·하드링크 |
| `edr_file_delete_lsm` | `lsm/path_{unlink,rmdir}` | 삭제 |
| `edr_file_rename_lsm` | `lsm/path_rename` | 이름변경/이동 |
| `edr_file_change_xattr_lsm` | `lsm/inode_{setxattr,removexattr,set_acl,remove_acl}` | 확장속성/ACL |
| `edr_file_ioctl_setflags_lsm` | `lsm/file_ioctl(_compat)` | chattr(불변 플래그 등) |
| `fork_bomb_lsm` | `lsm/task_alloc` | fork 폭탄 억제 |

* **공통 보조 훅**: 전 객체가 `lsm/inode_rename` + `lsm/inode_rmdir` + `lsm/inode_init_security`를 함께 등록 →
  보호 대상이 **이름변경/디렉토리삭제 우회 경로로 빠져나가는 것을 방지**(side-channel 봉쇄).
* 프로그램 심볼: `main_<hook>_prog(u64 *ctx)`, 보조 `helper_inode_rmdir_prog`. license=GPL.

## 2. 공통 allowlist/verdict 패턴 — kill LSM과 동일 [확정]

8종 전부 동일한 임베드 소스 패턴(파일당 `allowed_exes`/`inode_dev`/`inode_id` 참조 12회):
```c
const struct inode * exe_inode = BPF_CORE_READ(current, mm, exe_file, f_inode);  // caller exe
file_id.device = inode_dev(inode);     // (device, inode) 키
file_id.inode  = inode_id(inode);
// bpf_map_lookup_elem(&allowed_exes, &exe_file_id)   ← caller가 신뢰 exe인가
u8 * match_flags_ptr = bpf_map_lookup_elem(&edr_afr, &root);   // 보호대상 룰 매칭
u8 * excluded = bpf_map_lookup_elem(&edr_pex, &pid);          // pid exclusion (kill LSM과 공유)
```

### 공유 BPF maps
| map | 역할 |
|---|---|
| `allowed_exes` | **신뢰 caller 실행파일 (device,inode)** — kill LSM과 동일 |
| `edr_pex` | per-pid exclusion(비트마스크) — kill LSM과 동일 |
| **`edr_afr`** | **Agent File Rule** — 보호 대상 파일/경로 룰 + match_flags (파일보호 전용 신규) |

### verdict = enforcing (-EPERM)
`edr_file_open_write_lsm`의 `lsm/file_open`(`main_file_open_prog`, 0xaa38) 디스어셈블:
```asm
0x08006298  lddw r6, 0xffffffff     ; path_utils.h:400  → verdict = -1 = -EPERM (DENY)
... r6 ∈ {0x0=allow, 0x10=관측/계속, 0x1, -1=deny, -2=0xfffffffe} ...
0x...       mov r0, r6 ; exit
```
→ kill LSM(STEP 4.2)과 동일하게 **r6=verdict, -1(-EPERM) 반환 시 커널이 작업 거부**. (allow=0, deny=-EPERM 확정.)

## 3. 종합

* **anti-tamper의 적용 범위 = kill + 파일 무결성 전반.** 에이전트 자기보호 파일(바이너리/설정/로그 등 `edr_afr` 등록 대상)에
  대한 **쓰기·삭제·이름변경·권한/소유자/속성 변경·chattr·하드/심볼릭링크**를 모두 **커널 LSM으로 enforcing 차단**.
* **신뢰 앵커 일관**: 전 LSM이 caller exe를 `(device,inode)`로 판정(`allowed_exes`) → STEP 4.3 #1 결론
  (**mount-ns 경로혼동 우회는 LSM 계열에 통하지 않음**)이 파일보호 전체로 확장됨.
* **side-channel 봉쇄**: 모든 객체가 `inode_rename`/`inode_rmdir`을 공통 등록 → 보호대상 우회 이동/삭제 차단.
* fork_bomb_lsm은 `lsm/task_alloc` + `edr_pex`로 fork 억제(파일 allowlist 대신 pid exclusion 중심).

## 4. 후속 (잔여)
* `edr_afr`(Agent File Rule) map을 채우는 userspace 등록 경로 — 보호 대상 파일 집합의 출처/갱신(정책?) 추적.
* (VM 로컬, 콘솔 불필요) 보호파일에 비-allowlist 프로세스로 write/unlink/chattr 시도 → -EPERM deny 런타임 재현.
* mount-ns 경로혼동을 파일보호 LSM에 시도해 #1 결론(우회 불가) 런타임 확증.
