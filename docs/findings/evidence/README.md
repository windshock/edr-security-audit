# 증거 자료 (Evidence)

FND-001/FND-002 및 io_uring 검증의 원시 증거. 모두 **실측 산출물**이며, 탐지 로그 JSON은
SIEM-X(OpenSearch `logs-edr.edr`)에서 해당 마커로 검색해 덤프한 **EDR-X 원본 이벤트**다.

| 파일 | 내용 | 입증 |
|---|---|---|
| `io_uring_strace.txt` | io_uring 파일 생성/쓰기의 strace | 마커 파일에 대한 `openat`/`write` syscall **전무**, `io_uring_setup`/`enter`만 발생 → **syscall-less** |
| `io_uring_detection_events.json` | io_uring 마커 매칭 이벤트 25건 | `FILEMODIFICATION` 포함 → 센서가 **VFS-level로 탐지**(syscall 우회 무효) |
| `privesc_detection_events.json` | LPE 마커 매칭 이벤트 46건 | `BEHAVIOR_INDICATOR`(SUID_SET, **MITRE T1548.001**) → SUID 권한상승 탐지. `.threats`는 0건(위협 미승격) |

## 재현 방법
* io_uring strace: `scripts/tcs/iouring_file.c` 컴파일 후 `strace -f -e trace=openat,write,io_uring_setup,io_uring_enter`로 실행.
* 탐지 로그 덤프: `python3 scripts/dump_evidence.py "<marker>" <out.json>` (회사망 + SIEM-X 접근 필요).

## 무결성/안전
* 탐지 JSON은 가공 없이 `_source` 원본을 보존(필드 그대로).
* 재현 시 생성한 SUID 백도어·sudoers 오설정은 테스트 직후 삭제했으며(위험 자산), 본 증거는 비파괴 산출물·탐지 로그만 포함.
