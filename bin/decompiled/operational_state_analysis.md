# STEP 4.3 #6 — agent operational state (enable/disable/suspend) 경로 분석

* **일시**: 2026-06-20 (오프라인)
* **질문**: agent의 진짜 enable/disable/suspend 운영 상태는 무엇이 set하고 어떻게 강제되는가? #4의 mitigation gate와의 관계.
* **방법**: 전수 Ghidra `.c`(234MB) grep + r2 disasm 교차검증 + plain strings.

---

## 1. 두 개의 별개 상태 — 정리

| 상태 | 표현 | 출처 | 효과 |
|---|---|---|---|
| **mitigation gate** (#4) | 전역 `0x3dcaa80` (byte) | config-apply가 mgmt policy 구조체 `+0x5b8`에서 set | kill_threat 등 mitigation 핸들러의 게이트 |
| **operational state** (#6) | `agent_operational_state`(+`_expiration`,`_reason`) Rust serde 필드 | **클라우드 `DisableAgentNotification` / enable·suspend 명령** | 에이전트 전반 기능 on/off (disabled mode) |

* kill_threat_handler의 `"Cannot kill threat when agent is disabled"` 분기는 r2상 **`cmp byte [0x3dcaa80], 0; je →`** 로
  확정 — 즉 이 핸들러가 말하는 "disabled"는 **mitigation gate=0** 상태를 가리킨다(핸들러는 읽기만, write 없음).
* 더 광역의 운영 상태(disabled mode 전체)는 `agent_operational_state`로 별도 관리된다(아래 §2).

---

## 2. operational state 적용 경로 [확정]

### 2-1. 클라우드 명령/통지로 수신
* **serde 구조체 필드** (register/keep-alive 응답·통지에 포함):
  `agent_operational_state`, `agent_operational_state_expiration`, `agent_operational_states_reason`
  (직렬화 함수 `FUN_02ccad80` line 3911266; 역직렬화 `FUN_*` line 4159893 등).
* **`DisableAgentNotification`** (line 4069602~) — 클라우드가 운영 상태/만료/사유를 통지하는 알림 타입.
* **명령 핸들러**:
  * `"Received enable agent command, id: {}"` (FUN_01b94db0, line 1081374)
  * `"Received suspend request, should enable agent: {}"` (line 46935)
  → enable/disable/**suspend**(만료 동반 일시정지)는 **mgmt 클라우드 명령**으로 트리거. `expiration` 필드로 시한부 disable 표현.

### 2-2. disabled 상태의 효과 (광역 거부 — plain strings)
disabled/suspended일 때 에이전트가 거부/스킵하는 동작:
```text
Agent started in disabled mode            , suspended = %d
Cannot kill threat when agent is disabled
Cannot quarantine when agent is disabled        Cannot unquarantine when agent is disabled
Cannot disconnect agent from network when disabled
Cannot initiate full disk scan when agent is disabled / Cannot abort full disk scan ...
Agent disabled, ignoring remote script execution ...
Agent disabled, ignoring remote shell ...        AgentRemoteShellDisabled
Auto file upload: disabled / timer suspended
: global assets were disabled by configuration
```
→ 운영 상태가 mitigation·격리·네트워크 차단·스캔·원격쉘·파일업로드 등 **거의 모든 활성 기능을 게이트**한다.

---

## 3. 종합

* **3계층 제어 구조 확정**:
  1. **operational state** (`agent_operational_state`, 클라우드 DisableAgentNotification/enable/suspend) — 광역 on/off, 시한부(expiration) 지원.
  2. **mitigation gate** (`0x3dcaa80`, mgmt policy 필드) — mitigation 계열 동작 게이트(#4).
  3. **eBPF LSM self-protection** (`edr_kill_attempt_lsm`) — 커널 차단, 위 둘과 독립(#4.2).
* **모든 비활성화 경로는 mgmt/클라우드 채널 기원** — 로컬 사용자가 임의로 끌 수 있는 단순 토글 아님. (suspend는 expiration으로 자동 복귀 설계.)
* **방법론**: enable 핸들러 본문이 Ghidra에서 try/catch로 단편화(`Subroutine does not return`)되어 wrapper만 남음 →
  운영 상태 set의 정확한 메모리 타깃은 r2 disasm 추가 추적 필요(미완, 아래 후속).

## 4. 후속 (잔여)
* enable/suspend 명령 핸들러(FUN_01b94db0 등)가 set하는 정확한 상태 변수 — r2로 핸들러 전체 흐름 추적.
* `agent_operational_state` enum 값 집합(streaming/disabled/suspended 등) 디코딩.
* (VM) DisableAgentNotification 수신 시 mitigation/LSM 동작 변화 런타임 관측.
