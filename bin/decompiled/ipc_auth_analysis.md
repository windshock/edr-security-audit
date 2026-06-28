# edr-x-agent — IPC 인증 정적 분석 (TC-12 발견 확정)

* **대상**: `bin/extracted/edr-x-agent` (ELF64, x86-64, PIE, **stripped**, 64MB)
* **빌드 출처**: `<agent-build-id>` (문자열에서 추출)
* **분석 도구**: radare2 / rabin2 / strings (타깃 분석, 전체 디컴파일 아님)
* **목적**: TC-12("비루트가 9개 IPC 소켓 전부 connect+send 성공") 발견의 근본 원인 규명

---

## 1. 아키텍처

에이전트 IPC는 **gRPC over Abstract Unix Domain Socket(SOCK_SEQPACKET)** 기반이다.

* gRPC C-core + Rust 런타임(Rust async HTTP stack) 혼합 빌드.
* 9개 abstract 소켓(`@agent_ipc_*`, `@network_ipc_*`, `@scanner_ipc_*`, `@firewall_ipc_*`,
  `@log_collector_*` 등)을 프로세스 역할별로 LISTEN.
* IPC path 심볼: `agent_general_process_ipc_path`, `network_process_ipc_path`,
  `scanner_process_express_ipc_path`, `addon_ipc_base_path` 등.
* 핸들러 등록 루틴: `0x015f0e00` 부근(첨부 `edr-x-agent_ipc_setup.asm`). 각 IPC path 문자열을
  `lea rdi, str.<...>_ipc_path` 후 프로세스별 핸들러 생성 함수로 전달.

## 2. 핵심 증거

### 2-1. 정적 문자열만으로는 peer 검증을 놓칠 수 있음 (동적 분석으로 정정)
초기 정적 문자열 검색에서는 `SO_PEERCRED` / `SCM_CREDENTIALS` 문자열이 보이지 않아 peer 검증 부재로
추정했으나, 이는 오판이었다. `edr-agent` PID 518을 attach한 동적 trace에서 다음 syscall이 확인됐다:

```text
getsockopt(fd, SOL_SOCKET, SO_PEERCRED, {pid=<client>, uid=<uid>, gid=<gid>}, [12]) = 0
readlinkat(AT_FDCWD, "/proc/<client>/exe", "<resolved-exe-path>", 4097) = ...
```

따라서 transport connect 자체는 열려 있지만, 메시지 처리 전 단계에서 peer pid 기반 실행 파일 검증이
수행된다.

### 2-2. gRPC 서버가 insecure credentials 사용
링크된 gRPC security connector: `alts / fake / insecure / ssl / tls`.
RTTI 심볼로 `grpc_core::InsecureServerCredentials`, `grpc_core::InsecureServerSecurityConnector`
존재하며, 그 typeinfo 구조체가 `.data.rel.ro`(0x150b00)에서 참조됨 → **해당 타입이 인스턴스화됨**.
로컬 UDS IPC를 insecure 자격증명으로 띄우는 것은 gRPC의 전형적 로컬 IPC 패턴이며, 이는 transport
계층에 TLS·peer 인증이 없음을 의미한다.

### 2-3. 런타임 관찰과의 정합
* 비루트(`crtester`)·root 모두 9개 소켓에 `connect()` 성공, 첫 `send()` 성공.
* 이후 `recv()`에서 `errno 104 (Connection reset by peer)`.
→ 연결·첫 패킷은 transport 계층에서 수락되고 reset은 그 다음 단계에서 발생.
⚠️ **정정**: 초기엔 "프레이밍 단계 reset, uid 거부 아님"으로 추정했으나, §6에서 정상 클라이언트가
connect 전 `SO_PASSCRED`를 설정함을 발견 → reset 원인이 **SCM_CREDENTIALS 검증**일 수 있어 미확정으로 전환(§6).

## 3. 결론 (확정도 구분)

**확정 (런타임 + 바이너리 사실)**
1. **임의의 로컬 사용자(비루트 포함)가 9개 IPC 엔드포인트에 connect/send 가능** (소켓 파일권한 없음).
2. 서버는 `getsockopt(SO_PEERCRED)`로 peer pid/uid/gid를 얻고, `/proc/<pid>/exe`를 조회해 caller 실행
   파일 경로를 검사한다(§8, runtime-confirmed).
3. gRPC 서버는 insecure 자격증명(transport TLS 없음) 경로 사용(RTTI 증거).

**추가 검증으로 정정 (2026-06-19 13:20 KST)**
* 유효한 selector를 replay하는 임의 클라이언트(root Python, root C, 비루트 C)는 모두 reset/pipe로 거부됨.
* 원본 `/opt/edr-x/bin/edrctl` 및 이를 가리키는 symlink 실행은 동일 selector로 정상 응답을 받음.
* `/tmp`에 복사한 `edrctl`은 동일 파일 내용이어도 실패하고, 원본과 같은 inode를 공유하는 hardlink도
  `/tmp` 경로로 실행하면 실패함.
→ `agent_ipc`에는 **SCM_CREDENTIALS pid 기반 caller 실행 파일 경로 allowlist성 authz**가 동작하는 것으로
판단된다. 정확한 코드 경로는 아직 디컴파일로 확정하지 않았으므로 이 구현 세부는 `inferred mechanism`으로
취급한다.

## 4. 함의

소켓 계층 접근 제어 부재 자체는 즉시 권한 상승은 아니지만, **공격 표면을 비루트까지 확대**한다.
메시지/애플리케이션 계층에는 caller allowlist가 존재해 권한 있는 `agent_ipc` 메서드 호출은 현재
비루트 및 임의 root 바이너리에서 재현되지 않았다. 따라서 TC-12의 보안 의미는 **로컬 비루트가 IPC
transport까지 도달 가능한 공격 표면 노출**로 한정한다. 권한 있는 메서드 호출/권한상승 주장은 현재
증거로는 성립하지 않는다.

## 5. 첨부 산출물
* `edr-x-agent_ipc_setup.asm` — IPC 핸들러 등록 루틴 디스어셈블(0x15f0e00~)
* `edr-x-agent_ipc_evidence.txt` — 소켓 옵션·credential·IPC path 문자열 증거 덤프

---

## 6. IPC 와이어 프로토콜 (strace 동적 RE, 2026-06-19)

`strace -f -xx -s 99999 edrctl control status` 로 정상 클라이언트 캡처:

* 소켓: `@agent_ipc_<token>` (SOCK_SEQPACKET). token=`YGdebJGcb7Hj6mwPXbRs`(재부팅 시 변경).
* connect **전**: `setsockopt(SO_PASSCRED, 1)` + SO_SNDTIMEO/SO_RCVTIMEO.
* 프레이밍: `8B LE 길이` → `페이로드`, 각각 별도 `sendto` (SEQPACKET 메시지 경계).
* 요청 페이로드 = **8B 정적 method-ID** (control-status = `a2d6ed9cfc61e58c`, 2회 실행 동일). 다른 조회 = `7edd e7cd d0e4 47c0`.
* 응답 = `8B LE 길이` → 본문 (상태조회 64B, LE uint32 필드들; 평문).
* **인증 핸드셰이크 없음** (nonce/challenge/토큰 교환 부재). 클라가 method-ID 먼저 송신.

캡처 바이트를 `scripts/tcs/ipc_authz_poc.py`와 C 클라이언트(`scripts/tcs/ipc_authz_client.c`)로 replay 시
**root로도 reset/pipe**가 발생했다. `SO_PASSCRED`, timeout, len/payload 분리/결합 변형과 무관했다.

## 7. IPC authz 재검증 결과 (runtime-confirmed, mechanism inferred)

### 7-1. C 클라이언트 기준선
`scripts/tcs/ipc_authz_client.c`를 VM 내부에서 컴파일:

```bash
gcc -Wall -Wextra -O2 -o /tmp/ipc_authz_client \
  <REPO_ROOT>/scripts/tcs/ipc_authz_client.c
```

결과:

| 실행 주체/경로 | 결과 |
|---|---|
| `sudo /tmp/ipc_authz_client` | `recvfrom header: Connection reset by peer` |
| `sudo /tmp/ipc_authz_client --no-passcred` | `Connection reset by peer` |
| `sudo /tmp/ipc_authz_client --combined` | `Connection reset by peer` |
| `sudo -u crtester /tmp/ipc_authz_client` | `Connection reset by peer` |

### 7-2. `edrctl` 경로/파일 실체 대조

| 실행 파일 | inode/path 조건 | 결과 |
|---|---|---|
| `/opt/edr-x/bin/edrctl` | 원본 경로 | 정상 응답 |
| `/tmp/edrctl_link -> /opt/edr-x/bin/edrctl` | symlink가 원본으로 resolve | 정상 응답 |
| `/tmp/edrctl_copy` | 동일 내용, 다른 inode/path | `send failed: Broken pipe` |
| `/tmp/edrctl_hard` | 원본과 같은 inode, 실행 경로 `/tmp` | `receive failed: Connection reset by peer` |

성공 trace(`/tmp/edrctl_symlink.tr`)는 다음과 같이 기존 정상 클라이언트와 동일한 IPC 바이트를 보낸다:

```text
socket(AF_UNIX, SOCK_SEQPACKET, 0) = 5
setsockopt(5, SOL_SOCKET, SO_PASSCRED, [1], 4) = 0
connect(5, {sa_family=AF_UNIX, sun_path=@"agent_ipc_..."}, 33) = 0
sendto(5, "\x08\x00\x00\x00\x00\x00\x00\x00", 8, 0, NULL, 0) = 8
sendto(5, "\xa2\xd6\xed\x9c\xfc\x61\xe5\x8c", 8, 0, NULL, 0) = 8
recvfrom(5, "\x40\x00\x00\x00\x00\x00\x00\x00", 8, 0, NULL, NULL) = 8
recvfrom(5, <64-byte status body>, 64, 0, NULL, NULL) = 64
```

### 7-3. Updated conclusion

* **Confirmed**: arbitrary local users can connect/send to abstract IPC sockets.
* **Confirmed**: arbitrary local users and arbitrary root-owned binaries cannot replay the `control status` selector successfully.
* **Confirmed**: original `edrctl` path, including a symlink resolving to that path, is accepted.
* **Inferred**: the server uses `SO_PASSCRED`/SCM credentials to obtain pid and checks `/proc/<pid>/exe` or an equivalent
  canonical executable path allowlist.
* **Security impact**: TC-12 remains an attack-surface finding, not a proven local privilege escalation or command injection.

## 8. Pinpoint and bypass feasibility update (2026-06-19 13:27 KST)

### 8-1. Pinpointed authz mechanism

Attaching `strace` to `edr-agent` PID 518 while running both accepted and rejected clients confirmed the server-side
validation path:

```text
getsockopt(fd, SOL_SOCKET, SO_PEERCRED, {pid=<client>, uid=0, gid=0}, [12]) = 0
readlinkat(AT_FDCWD, "/proc/<client>/exe", "<resolved-exe-path>", 4097) = ...
newfstatat(AT_FDCWD, "<resolved-exe-path>", {...}, 0) = 0
openat(AT_FDCWD, "<resolved-exe-path>", O_RDONLY) = ...
```

Accepted client:

```text
readlinkat(..., "/proc/25944/exe", "/opt/edr-x/bin/edrctl", 4097) = 32
```

Rejected clients:

```text
readlinkat(..., "/proc/25946/exe", "/tmp/edrctl_copy", 4097) = 21
readlinkat(..., "/proc/25947/exe", "/tmp/edrctl_hard", 4097) = 21
readlinkat(..., "/proc/25817/exe", "/tmp/ipc_authz_client", 4097) = 21
```

This confirms the allow decision is path-based after `SO_PEERCRED` pid discovery. It is not purely UID-based, hash-based,
or inode-based: a hardlink sharing the original inode is rejected when `/proc/<pid>/exe` resolves to `/tmp/edrctl_hard`.

Relevant static strings in `edr-x-agent`:

```text
0x006557de "/proc/{}/exe"
0x006e36e0 "Received ipc connection from unauthorised process: {}"
0x006c8c55 "Failed to validate src ipc connection is from process {}: unknown error"
0x006f4ab4 "Failed to validate src ipc connection is from process {}: {}"
```

### 8-2. Conditional bypass reproduced: private mount namespace path confusion

A root process with `CAP_SYS_ADMIN` can create a private mount namespace, bind-mount an arbitrary executable over
`/opt/edr-x/bin/edrctl` inside that namespace, then execute that path. The host namespace file is unchanged,
but `edr-agent` sees the peer executable path as `/opt/edr-x/bin/edrctl` and accepts the IPC request.

Observed result using `scripts/tcs/ipc_authz_client.c` as the overlaid executable:

```text
uid=0 euid=0 exe=/opt/edr-x/bin/edrctl socket=@agent_ipc_YGdebJGcb7Hj6mwPXbRs passcred=1 combined=0
response_len=64
body_hex=fe5717b8a108b3e30200000006000000050000000b02000004000000080200000300000006020000020000000202000001000000ff01000000000000b0010000
```

Server trace:

```text
getsockopt(571, SOL_SOCKET, SO_PEERCRED, {pid=26198, uid=0, gid=0}, [12]) = 0
readlinkat(AT_FDCWD, "/proc/26198/exe", "/opt/edr-x/bin/edrctl", 4097) = 32
newfstatat(AT_FDCWD, "/opt/edr-x/bin/edrctl", {st_mode=S_IFREG|0700, st_size=11742072, ...}, 0) = 0
openat(AT_FDCWD, "/opt/edr-x/bin/edrctl", O_RDONLY) = 572
recvfrom(571, "\10\0\0\0\0\0\0\0", 8, 0, NULL, NULL) = 8
recvfrom(571, "\242\326\355\234\374a\345\214", 8, 0, NULL, NULL) = 8
sendto(571, "@\0\0\0\0\0\0\0", 8, 0, NULL, 0) = 8
```

Host integrity check after the test:

```text
host edrctl inode=262409 links=1 size=11742072
mount | grep 'edrctl\|ipc_authz' => no lingering bind mount
```

### 8-3. Non-root feasibility

Current lab result: non-root `crtester` cannot use this route.

```text
sudo -u crtester unshare -Ur -m ...
unshare: write failed /proc/self/uid_map: Operation not permitted
```

`crtester` also cannot execute the real `edrctl` because `/opt/edr-x/bin` and the binary permissions block it.

### 8-4. Security interpretation

* **Root+CAP_SYS_ADMIN conditional bypass confirmed**: arbitrary executable can impersonate the trusted `edrctl`
  IPC caller by mount-namespace path confusion.
* **Non-root bypass not confirmed** in the current VM.
* This is not a direct local privilege escalation from an ordinary user. It is a defense-in-depth weakness in caller
  authentication for IPC: path-string allowlisting can be confused by mount namespaces.

### 8-5. Hardening direction

The authz check should avoid trusting the string returned by `readlink("/proc/<pid>/exe")` alone. Safer options:

* validate the actual executable object via `/proc/<pid>/exe` (`stat`/open/hash that proc symlink target), not by reopening
  the returned path string in the agent's own mount namespace;
* compare device/inode or a signature/hash of the peer executable object;
* reject or separately handle peers in unexpected mount namespaces;
* bind IPC authorization to an unforgeable credential or brokered token rather than a namespace-sensitive pathname.
