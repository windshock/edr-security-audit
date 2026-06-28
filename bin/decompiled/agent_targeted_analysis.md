# STEP 4.1 — edr-x-agent(64MB) 타깃 디컴파일 분석 (r2ghidra)

* **일시**: 2026-06-19
* **대상**: `bin/extracted/edr-x-agent` (ELF64, x86-64, PIE, stripped, 62MB, `<agent-build-id>`)
* **방법**: **타깃 디컴파일** — 전수 Ghidra 디컴파일이 장시간(분석만 2h+) 소요되어, 핵심 문자열 xref →
  해당 함수만 r2ghidra `pdg`로 디컴파일. (전수 디컴파일은 별도 백그라운드 병행)
* **도구 셋업**: radare2 **5.9.8 → 6.1.6** 업그레이드(brew) 후 `r2pm -ci r2ghidra` 재빌드 →
  `core_ghidra.dylib` 설치, `pdg` 정상 동작 확인. (5.9.8에선 `RVecRArchValue` API 불일치로 빌드 실패)
* **레시피**: `r2 -e bin.relocs.apply=true -c 's <strref>; af; pdg' agent` (r2 `af`가 함수 시작점 자동 복원)
* **산출물**: `bin/decompiled/agent_targeted/{kill_threat_handler,anti_tamper_toggle_handler,handle_kill_event}.c`

---

## 1. 아키텍처 (문자열 증거)

에이전트는 **C++ + Rust 하이브리드** 단일 바이너리:
* **C++ (`edr::` 네임스페이스)** — 탐지/perf/eBPF 계층. GNU C++ 망글링, `detectors_manager`,
  `perf_manager`, `provider_perf`.
* **Rust (`<agent-comm-crate>`)** — 클라우드 통신/세션/telemetry/파일업로드/DB.
  경로 문자열 `/__w/<agent-comm-path>/src/...`, Rust async/runtime dependencies 의존.
* **embedded Lua runtime 임베드** — `<embedded-lua-runtime-path>` 경로 → correlation 탐지 룰 엔진용(아래 정정 참조).

---

## 2. 표적 1 정정 — anti_tamper "agent kill"은 **eBPF LSM**, Lua 아님 ⚠️

handoff의 `anti_tamper_agent_kill.lua`는 **오해**였다. agent 자기보호(누군가 agent를 kill하려는 시도 차단/탐지)는
**eBPF LSM + syscall 훅**으로 구현된다. 바이너리 임베드 eBPF 오브젝트:

```text
edr_kill_attempt_lsm        edr_kill_attempt_lsm_kern.o
edr_kill_attempt_sys        edr_kill_attempt_sys_kern.o
ebpf_edr_kill_attempt       make_edr_kill_attempt_ebpf_handler
system_edr_kill_attempt_event
handle_edr_kill_attempt_event: excluding pid: {}
handle_edr_kill_attempt_event: unknown agent pid: {}
```

바이너리의 `.lua`는 embedded Lua runtime 경로일 뿐, anti-tamper kill 로직과 무관.

### 2-1. eBPF 이벤트 핸들러 표면 (자기보호·탐지 텔레메트리)
`handle_*_event: excluding pid: {}` 패턴으로 **60+ eBPF/LSM 핸들러** 확인. 보안상 주목:
`handle_kill_event`, `handle_ptrace_trace_event`, `handle_process_injection_event`,
`handle_memory_protection_event`, `handle_software_packing_event`, `handle_unauthorized_splice_event`,
그리고 **namespace 계열** `handle_unshare_event`/`handle_mount_event`/`handle_umount_event`/
`handle_setns_event`/`handle_pivot_root_event` — ipc_auth_analysis의 mount-ns 경로혼동 우회와 직접 연결되는 가시성.

### 2-2. `handle_kill_event` 디컴파일 (자기보호 = 제외 PID 필터)
```c
void fcn.0186296b(int64_t arg1) {
    iVar2 = func_0x0123dfd0();              // 조건 A (LSM 모드?)
    uVar1 = func_0x0123e0f0(0);             // 조건 B (sys 모드?)
    if ((iVar2 != 0 & (uVar1 ^ 1)) == 0) {
        ...func("handle_kill_event: excluding pid: {}", ..., *arg1);  // 제외 대상 pid 로깅
        if (iVar2 == 0) { ... func_0x01202500(**lst1, 0, ...); }      // 핸들러 디스패치 (목록1)
        if (uVar1 != 0) { ... func_0x01202500(**lst2, 0, ...); }      // 핸들러 디스패치 (목록2)
    }
}
```
→ kill 이벤트를 두 경로(LSM/sys)로 받아 **제외 PID 목록**을 거쳐 핸들러로 디스패치. agent PID 보호의 입력 단.

---

## 3. 표적 2 — mitigation kill 의사결정 입력 (클라우드 명령)

### 3-1. mitigation 액션 enum (문자열)
```text
mitigation.action.kill-threat   mitigation.action.kill-proc   mitigation.action.kill-group
mitigation.action.file_quarantine  mitigation.action.shutdown  mitigation.action.disco-net
mitigation.action.none          MITIGATION_ACTION_KILL_THREAT
```
mitigation 명령/리포트 타입(Rust gen): `kill reportThreat`, `MitigationDataKill`, `OldMitigationKill`,
`NetworkQuarantineReport`, `RollbackReport`, `RemediationReport`. → **mitigation은 클라우드/콘솔에서 내려오는 명령**이고
결과는 `kill report` 등으로 보고됨.

### 3-2. `kill_threat_handler` 디컴파일 (의사결정 게이트)
fcn `0x01a92aca` (size 1866). 핵심:
```c
log(2, "Received kill threat command, id: {}, group_id: {}", ...);   // L36
if (*0x3dcab30 == '\0') goto disabled_path;                          // L37  agent-enabled 플래그 (lock 보호, L208~212)
if (*0x3dcaa80 != '\0') {                                            // L39  2차 게이트(mitigation enabled 추정)
    obj = alloc(0x30); obj->vtable = 0x3bbcf78;                      //      kill 액션 객체 생성
    bind(obj, group_id); dispatch(...);                             // L54  (**(vtbl+8))() vtable 디스패치
}
...
disabled_path: log("Cannot kill threat when agent is disabled");     // L87 (str 0x006d4b92, ref 0x1a92ce7 = 함수 내부 확정)
```
→ **kill 결정 로직**: ① 명령 수신·로깅 → ② **agent-enabled 전역 플래그**(`0x3dcab30`, 뮤텍스 보호) 확인,
disabled면 거부·로깅 → ③ enabled + mitigation 게이트(`0x3dcaa80`) 통과 시 kill 액션 객체를 생성해 vtable로 디스패치.

### 3-3. anti-tamper 토글 (`anti_tamper_toggle_handler`)
```c
log(2, "Received anti-tamper toggle request with value {0}", value@(R15+8));
... 요청 객체(vtable 0x3bc01c0) 생성, *result = obj; obj.flag = 1; ...   // 토글 요청 enqueue/dispatch
```
관련 정책/요청 타입: `agent_policy_anti_tamper_request`, `control_policy_anti_tamper_request`,
`policy_anti_tamper_request`, `Mgmt configuration does not contain 'antiTampering'`,
`Added {} to anti-tamper allowed executables for {}` (보호파일 수정 허용 실행파일 allowlist).
→ anti-tamper on/off 및 allowlist는 **관리(mgmt) 정책 + edrctl 일회용 패스프레이즈**(STEP 4 분석)로 게이트.

---

## 4. 종합 결론 (STEP 4.1)

| 항목 | 결과 | 확정도 |
|---|---|---|
| anti_tamper_agent_kill 메커니즘 | **eBPF LSM/sys 훅** (`edr_kill_attempt_lsm_kern.o`), Lua 아님 | 확정(문자열+핸들러 디컴파일) |
| 자기보호 kill 이벤트 처리 | `handle_kill_event`: LSM/sys 2경로 + 제외 PID 필터 → 디스패치 | 확정(디컴파일) |
| mitigation kill 트리거 | 클라우드/콘솔 mitigation 명령(`kill-threat/proc/group`), `kill report`로 보고 | 확정(문자열) |
| kill 결정 게이트 | agent-enabled 플래그(뮤텍스) + mitigation 게이트 통과 후 vtable 디스패치 | 확정(디컴파일) |
| STEP 2 가시성 갭 정합 | kill/차단이 mitigation 명령·kill report 경로 → 콘솔 Threats엔 적재, raw telemetry 인덱스엔 부재 | 정합 |

**남은 표적**
1. 전역 플래그 `0x3dcab30`(agent-enabled) / `0x3dcaa80`(mitigation gate)의 set 경로 추적 — 정책/disable 명령과의 연결.
2. eBPF `edr_kill_attempt_lsm_kern.o`의 실제 차단(LSM deny) vs 탐지전용 여부 — 커널 오브젝트 추출·분석.
3. (전수 Ghidra 디컴파일 완료 시) `_decompiled.c`로 함수 시작점 정확화 및 vtable 0x3bbcf78/0x3bc01c0 타입 식별.
