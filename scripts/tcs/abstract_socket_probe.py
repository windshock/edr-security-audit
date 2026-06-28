#!/usr/bin/env python3
"""
abstract_socket_probe.py - Probe EDR-X agent Abstract Unix Sockets.

EDR-X IPC uses ABSTRACT namespace (@-prefixed) SOCK_SEQPACKET sockets,
which never appear in the filesystem. `find -type s` / `nc -U` cannot reach
them. This probe enumerates them from /proc/net/unix and attempts a real
SEQPACKET connect + send to measure the IPC attack surface and whether the
agent reports/blocks unauthorized connections.

Usage: abstract_socket_probe.py <MARKER>
Output: JSON to stdout.
"""
import json
import os
import socket
import sys
import time

MARKER = sys.argv[1] if len(sys.argv) > 1 else "EDR_POC_PROBE"
PAYLOAD = (MARKER + "_IPC_PROBE").encode()


def enumerate_listening_abstract():
    """Return list of abstract-namespace LISTEN socket names (with leading @)."""
    names = []
    try:
        with open("/proc/net/unix") as f:
            for line in f.readlines()[1:]:
                parts = line.split()
                if len(parts) < 8:
                    continue
                state = parts[5]
                path = parts[-1]
                # state 01 == LISTEN; abstract sockets render with leading '@'
                if state == "01" and path.startswith("@"):
                    if any(k in path for k in ("edr_component", "agent", "log_collector")):
                        names.append(path)
    except Exception as e:
        return {"error": str(e)}
    return sorted(set(names))


def probe(name):
    # Abstract address: leading '@' in /proc maps to a real NUL byte.
    addr = b"\0" + name[1:].encode()
    result = {"socket": name, "connect": None, "send": None, "recv": None}
    # EDR-X IPC sockets are SOCK_SEQPACKET; try that first, then STREAM.
    for stype, sname in ((socket.SOCK_SEQPACKET, "SEQPACKET"),
                         (socket.SOCK_STREAM, "STREAM")):
        s = socket.socket(socket.AF_UNIX, stype)
        s.settimeout(2.0)
        try:
            s.connect(addr)
            result["connect"] = f"OK ({sname})"
        except OSError as e:
            result["connect"] = f"FAIL ({sname}): errno={e.errno} {e.strerror}"
            s.close()
            continue
        # Connected — try to send the marker probe.
        try:
            s.send(PAYLOAD)
            result["send"] = "OK"
        except OSError as e:
            result["send"] = f"FAIL: errno={e.errno} {e.strerror}"
        # Try to read a response.
        try:
            data = s.recv(4096)
            result["recv"] = f"{len(data)} bytes: {data[:120]!r}"
        except socket.timeout:
            result["recv"] = "TIMEOUT (no response)"
        except OSError as e:
            result["recv"] = f"FAIL: errno={e.errno} {e.strerror}"
        s.close()
        break
    return result


def main():
    report = {
        "marker": MARKER,
        "whoami": f"uid={os.getuid()} ({_username()})",
        "epoch": int(time.time()),
        "sockets": [],
    }
    names = enumerate_listening_abstract()
    if isinstance(names, dict):
        report["enum_error"] = names["error"]
        print(json.dumps(report, indent=2))
        return
    report["socket_count"] = len(names)
    for n in names:
        report["sockets"].append(probe(n))
    print(json.dumps(report, indent=2))


def _username():
    try:
        import pwd
        return pwd.getpwuid(os.getuid()).pw_name
    except Exception:
        return "?"


if __name__ == "__main__":
    main()
