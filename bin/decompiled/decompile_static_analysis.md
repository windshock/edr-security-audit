# STEP 4 — 4종 바이너리 디컴파일 정적 분석 요약

* **일시**: 2026-06-19
* **대상**: `edrctl`, `edr-watchdog`, `edr-extension-host`, `edr-netctl` (`bin/extracted/`)
* **빌드**: `<agent-build-id>` (edrctl 문자열 확정)
* **도구**: Ghidra 12.1.2 headless + `DecompileAll.java` (PyGhidra 불필요 Java postScript) → `bin/decompiled/*_decompiled.c`
* **보완**: `strings` / `rabin2 -i` (stripped 바이너리이므로 문자열·import가 1차 신호)
* **선행 분석**: [ipc_auth_analysis.md](file://<REPO_ROOT>/bin/decompiled/ipc_auth_analysis.md) (edr-x-agent IPC authz)

> ⚠️ 모든 바이너리 stripped → 디컴파일 함수명은 `FUN_<addr>`. 확정도는 **[확정]** = 코드/syscall/import 근거,
> **[추정]** = 문자열·심볼 정황으로 표기.

---

## 0. 디컴파일 산출물 인벤토리

| 바이너리 | 크기 | 디컴파일 | 함수 수 | 실패 | 산출물 |
|---|---|---|---|---|---|
| edr-netctl | 26K | 35K | 99 | 0 | `edr-netctl_decompiled.c` |
| edr-watchdog | 5.1M | 16M | 12,310 | 1 | `edr-watchdog_decompiled.c` |
| edr-extension-host | 5.9M | 17M | 14,230 | 0 | `edr-extension-host_decompiled.c` |
| edrctl | 11M | 28M | 20,830 | 1 | `edrctl_decompiled.c` |

전 바이너리 x86-64 ELF PIE, 동적 링크, stripped. OpenSSL 정적 링크(`../../openssl/openssl/...` 경로 문자열 공통).

---

## 1. 바이너리별 역할

### 1-1. `edrctl` — 관리/제어 평면 CLI **[확정]**
* 에이전트에 `edr::control::*_request` RPC를 **agent_ipc**(`@agent_ipc_<token>` SEQPACKET)로 전송하는 클라이언트.
  → 선행 분석에서 입증된 **allowlist된 신뢰 caller**(`/proc/<pid>/exe == /opt/edr-x/bin/edrctl`).
* 관측된 control RPC 타입(mangled): `base_request`, `status_request`, `stop_request`, `flush_request`,
  `config_set_request`, `policy_kill_request`, `get_uuid_request`, `update_validator`, `passphrase_validator`,
  `validate_one_time_passphrase_request`, `policy_anti_tamper_request`.
* 명령 표면 키: `agent_start`, `agent_disabled`, `edr_kill_attempt`, `config_set`, `config_reset_local_enabled`,
  `config_override_enabled`, `policy`, `edr_file_{create,delete,move,chmod,chown,chattr,setfattr,open_write}`.

### 1-2. `edr-watchdog` — 슈퍼바이저 / self-protection 데몬 **[확정]**
* import: `fork`, `execvp`, `execvpe`, `waitid`, `kill`, `epoll_wait`, `signal` → **에이전트 (재)기동 + 프로세스 kill** 담당.
* `kill_process(pid, sig)` = `FUN_002c3620` (line 40952): `kill(pid,sig)` 직접 래핑, pid<=0 가드.
  로그 문자열 `kill_process: sending signal {} to process {}`.
* 재기동 로직: `Failed to restart the agent after an upgrade attempt`,
  `exceeded maximum allowed consecutive agent restarts` (연속 재기동 상한).
* mitigation/kill 정책 키: `mitigation_kill_out_of_model`, `mitigation_kill_limited_mode`, `oom_kill`,
  `resource_memory-limit-kills-{number,time-frame}`.
* 모니터: `decoy_files_monitor_interval`(랜섬웨어 미끼), `disk_usage_monitor-*`, `pam_policy_monitor_*`,
  `file_read_extended_monitoring_enabled`.

### 1-3. `edr-extension-host` — 아웃-오브-프로세스 애드온 호스트 **[확정]**
* `dlopen()`으로 애드온 `.so`를 로드, `edr::AgentAddonInterface` / `edr::agent::linux_agent_addon_interface` 구현.
* 라이프사이클 로그: `Addon host was created for: {}`, `Addon already running`, `Addon exited with result: {}`,
  `Failed creating addon: {}`, `dlopen() failed with:`.
* IPC 서버 측 path 보유: `addon_ipc_base_path`, `agent_general_process_ipc_path`, `network_process_ipc_path`,
  `scanner_process_express_ipc_path` → 에이전트와 동일한 IPC peer 군의 일원.
* 강한 OpenSSL/X509 사용(CA key usage·SAN 검증) → 인증서 동반 애드온 처리. `unauthorized_splice_monitored_files`(FIM 정황).

### 1-4. `edr-netctl` — 번들 nftables CLI **[확정]**
* `libnftables.so.1` 링크, 표준 `nft_ctx_*` API + `nft>` 프롬프트 + readline(`.nft.history`). 커스텀 로직 거의 없음.
* 용도: 에이전트의 **네트워크 격리/방화벽 룰 프로그래밍** 보조 도구. 실제 룰 로직은 외부 라이브러리에.

---

## 2. 표적별 분석 (handoff STEP 4 3대 표적)

### 표적 1 — IPC 소켓 peer 인증
* 선행 분석에서 **edr-x-agent**가 `getsockopt(SO_PEERCRED)` → `readlinkat(/proc/<pid>/exe)` 경로
  allowlist로 caller를 검증함이 **runtime-confirmed**. mount-namespace 경로 혼동 우회(root+CAP_SYS_ADMIN)도 입증됨.
* 이번 4종 교차 확인:
  * `edr-extension-host`도 동일 IPC peer 군(server paths 보유) + `SO_PEERCRED` 문자열 → 동일 authz 모델 **[추정]**.
  * `edrctl`은 **클라이언트** 측. `SO_PASSCRED` 설정 후 selector 송신 (선행 분석 §6과 일치).
* **결론**: 소켓 계층은 비루트 도달 가능(공격 표면), 메시지 계층은 경로 allowlist authz. 4종 분석으로 모델 변동 없음.

### 표적 2 — Anti-Tamper 메커니즘 **[신규 규명]**
디컴파일로 anti-tamper의 **2계층 구조**가 드러남:
1. **강제(enforcement) = watchdog**: 에이전트 종료 감지 시 `fork/execvp` 재기동, mitigation 정책에 따라 위협
   프로세스 `kill()`, 미끼파일/파일수정 모니터링. `anti-tamper_executables_allowed_to_modify_files`
   (보호 파일 수정 허용 실행파일 allowlist).
2. **해제(disable) 게이트 = edrctl**: `Anti-Tamper enabled (on/off)` / `Enter passphrase:` / `Invalid passphrase!`.
   해제는 `validate_one_time_passphrase_request` → `passphrase_validator`로 **서버(에이전트)측 검증**.
   즉 일회용 패스프레이즈 없이는 CLI로 보호 해제 불가 → **TC-04(edrctl 명령 차단)의 정확한 근거**.
* ⚠️ `anti_tamper_agent_kill.lua`는 이 3종 어디에도 **임베드되지 않음**(lua refs=0). 정책으로 배포되거나
  메인 에이전트(64MB)에 내장된 것으로 보임 → 추가 표적.

### 표적 3 — 인증서 검증 로직 (edr-gw.local CN 불일치 건) **[확정]**
* 3종 모두 OpenSSL `X509_verify_cert` + `X509_VERIFY_PARAM_set1` / `set1_ip`로 **hostname/IP 검증 수행**.
  문자열: `Expected hostname(s) =`, `hostname mismatch`, `certificate verify error`.
* `edr-extension-host`는 추가로 `CA cert does not include key usage extension`, `Empty Subject Alternative Name extension` 검증.
* **`InsecureSkipVerify` / `VERIFY_NONE` / self-signed 허용 류 비활성화 문자열은 발견되지 않음.**
* **결론**: TLS 인증서 검증은 정상 강제됨. 결정14의 `edr-gw.local` 실패는 **정당한 CN 불일치**였고 hosts 매핑으로
  해소된 것 → 우회/취약점이 아니라 환경 구성 이슈. (보안 관점 positive)

---

## 3. 종합 결론

| 표적 | 결과 | 확정도 |
|---|---|---|
| IPC peer 인증 | 경로 allowlist 모델, 4종 교차로 일관. edr-extension-host 동일 peer군 | 확정(agent)/추정(addon) |
| Anti-Tamper | watchdog 강제 + edrctl 패스프레이즈 해제 게이트 = TC-04 근거 | 확정 |
| 인증서 검증 | OpenSSL hostname 검증 정상 강제, 비활성화 흔적 없음 | 확정 |

**새 후속 표적**
1. `anti_tamper_agent_kill.lua` 로직 — 이 3종에 없음 → **메인 agent(64MB) 디컴파일** 또는 정책 아티팩트 추적 필요.
2. `mitigation_kill_out_of_model` 의 의사결정 입력 — watchdog FUN 추적으로 어떤 신호가 kill을 트리거하는지.
3. edr-extension-host IPC peer authz가 agent와 동일한지 runtime 확인(현재 추정).
