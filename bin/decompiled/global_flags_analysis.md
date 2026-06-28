# STEP 4.3 #4 — kill/mitigation 전역 플래그 set 경로 분석

* **일시**: 2026-06-20 (오프라인)
* **대상 플래그** (r2 주소 기준; Ghidra 이미지 베이스는 +0x10000 → `DAT_03ec*`):
  * `0x3dcab30` (Ghidra `DAT_03ecab30`) — kill_threat_handler 1차 게이트
  * `0x3dcaa80` (Ghidra `DAT_03ecaa80`) — kill_threat_handler 2차 게이트 (mitigation gate)
* **방법**: 전수 Ghidra `.c`(234MB) grep + r2 `/r`·`pdr` 교차검증.

---

## 1. ⚠️ STEP 4.1 추정 정정 — `0x3dcab30`은 "agent-enabled 플래그"가 아님

STEP 4.1에서 `0x3dcab30`을 "agent-enabled 전역 플래그(뮤텍스 보호)"로 추정했으나, 전수 디컴파일 재검증 결과
**부분적으로 오판**이었다:

* 전수 `.c`에서 `DAT_03ecab30` 참조 62회는 거의 전부 `FUN_03c2c660(&DAT_03ecab30)` 형태.
* **`FUN_03c2c660`은 `std::call_once`/guard-acquire 패턴**(pthread_once; `PTR___pthread_key_create`,
  `*param==0 → *param=0x100`, LOCK/UNLOCK 상태머신). 즉 `0x3dcab30`은 **어떤 정적 객체의 초기화 가드/상태**에
  더 가깝다(`= 0x100/0x10100` 상태값). STEP 4.1의 "뮤텍스로 보호되는 enabled bool"이라는 서술은 부정확.
* Ghidra가 try/catch를 `WARNING: Subroutine does not return`으로 잘라 kill_threat_handler 흐름을 왜곡 →
  STEP 4.1의 **r2 기반 디컴파일이 더 정확**했음(아래 §2에서 r2로 재확인).

> 교훈: 이 바이너리는 C++ 예외(try/catch)가 많아 Ghidra 흐름 복원이 취약. **핵심 함수는 r2 disasm로 교차검증** 필요.

---

## 2. `0x3dcaa80` (mitigation gate) — write는 단 1곳, config에서 설정 [확정]

### read/write 분리 (r2 `/r 0x3dcaa80`)
* **write 1곳**: `0x1a6018b` `mov byte [rip+...], al` — config-apply 함수 `fcn.0x1a6018b`(size 6114) 내부.
* 나머지(`0x1a92bac` 등 다수)는 전부 `cmp byte [0x3dcaa80], 0` = **읽기**(각 mitigation 핸들러의 게이트 검사).

### write 흐름 (config-apply, 0x1a60174~)
```asm
movzx eax, byte [0x3dcab30]    ; 정적 객체 init-guard 확인
test al, al
je   0x1a6138f                 ; 미초기화면 set 스킵
movzx eax, byte [r15 + 0x5b8]  ; config/policy 구조체 +0x5b8 필드 로드
mov  byte [rip+...], al         ; 0x3dcaa80 = config.field   ← mitigation gate 설정
```
→ **mitigation gate는 관리(mgmt) config/policy 구조체의 한 필드(+0x5b8)에서 적용**된다.
Ghidra 표현(`FUN_01b60040`): `if (DAT_03ecab30 != '\0') { DAT_03ecaa80 = *(undefined1*)(param_2 + 0x5b8); ... }`
— `param_2`가 config 구조체. (STEP 4.1에서 본 `kill_threat_handler`의 2차 게이트와 정합.)

### kill_threat_handler 측 read (r2 `pdr`)
```asm
0x1a92bac  cmp byte [0x3dcaa80], 0   ; mitigation gate 검사 (읽기 전용)
```
→ kill 명령 수신 시 이 게이트가 0이 아니어야 kill 액션 디스패치. handler는 이 플래그를 **쓰지 않음**(읽기만).

---

## 3. 종합

| 플래그 | 역할(수정) | write 경로 | 확정도 |
|---|---|---|---|
| `0x3dcab30` | 정적 객체 **init-guard/상태**(STEP 4.1 "enabled bool" 추정은 정정) | `call_once` guard (`FUN_03c2c660`) | 확정(정정) |
| `0x3dcaa80` | **mitigation gate** | config-apply 함수가 **mgmt policy 구조체 +0x5b8**에서 1회 set | 확정 |

* **결론**: kill/mitigation 동작의 on/off는 **관리 콘솔 정책(config 구조체 필드)** 으로 제어된다 — 로컬에서
  임의 토글되는 단순 전역이 아님. 실제 "agent enable/disable" 운영 상태는 별도로 **`agent_operational_state`**
  (`DisableAgentNotification`, `operational_state_expiration/reason`)로 관리됨(문자열 확인, 별도 경로).
* **방법론 산출**: Ghidra(전수) vs r2(타깃)의 상호보완 입증 — 예외 많은 C++ 바이너리에서 흐름은 r2 disasm가 우위.

## 4. 후속 (잔여)
* `agent_operational_state` set/적용 경로(진짜 enable/disable 운영 상태) 추적 — `FUN_*` @ line 3911266 부근(`agent_operational_state` 파싱) 출발점.
* config 구조체 +0x5b8 외 인접 필드(다른 mitigation 토글) 매핑.
* (VM) mitigation gate off 시 kill 명령 무시 런타임 재현.
