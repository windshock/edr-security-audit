#!/usr/bin/env python3
"""
delegation_test.py - Scenario T12: Connected socket fd inheritance.
Attempts to check if the agent validates per-message or only at connect-time.
Flow:
1. Connects to @agent_ipc_<token> as a trusted binary (via bind mount impersonation).
2. Spawns an untrusted helper (this python script itself) with the open connected socket descriptor.
3. The helper sends a message over the inherited socket fd.
4. Checks if the agent accepts it or resets the connection.
"""
import os
import socket
import struct
import sys
import subprocess

DEFAULT_SELECTOR = "a2d6ed9cfc61e58c" # 'control status' method

def find_agent_ipc():
    for line in open("/proc/net/unix").read().splitlines()[1:]:
        p = line.split()
        if len(p) >= 8 and p[-1].startswith("@agent_ipc_"):
            return p[-1]
    return None

def main_child(fd_num):
    # This is the untrusted helper executing from a python pathname (not /opt/edr-x/bin/edrctl)
    print(f"[Child] PID={os.getpid()} resolved_exe={os.readlink('/proc/self/exe')} using inherited fd={fd_num}")
    s = socket.fromfd(fd_num, socket.AF_UNIX, socket.SOCK_SEQPACKET)
    s.settimeout(3.0)
    
    selector = bytes.fromhex(DEFAULT_SELECTOR)
    try:
        # Send length header + payload
        s.send(struct.pack("<Q", len(selector)))
        s.send(selector)
        print("[Child] Message sent. Receiving response...")
        hdr = s.recv(8)
        if len(hdr) < 8:
            print(f"[Child] FAIL: short header ({len(hdr)}B)")
            return
        n = struct.unpack("<Q", hdr)[0]
        body = s.recv(n) if n else b""
        print(f"[Child] SUCCESS! Got {len(body)}-byte response: {body.hex()}")
    except OSError as e:
        print(f"[Child] FAIL: errno={e.errno} {e.strerror}")

def main_parent():
    name = find_agent_ipc()
    if not name:
        print("ERROR: agent_ipc not found")
        sys.exit(1)
        
    print(f"[Parent] PID={os.getpid()} Connecting to socket={name}...")
    addr = b"\0" + name[1:].encode()
    s = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
    s.connect(addr)
    fd = s.fileno()
    
    # We want to clear Close-On-Exec on the fd so that it stays open in the child process.
    # Python sets close-on-exec by default since 3.4. We can clear it using os.set_inheritable.
    os.set_inheritable(fd, True)
    
    print(f"[Parent] Connected successfully on fd={fd}. Spawning child process...")
    
    # Re-run this script with the --child argument, passing the fd number
    # This invokes python3, so /proc/<child_pid>/exe resolves to /usr/bin/python3.12 (untrusted).
    cmd = [sys.executable, __file__, "--child", str(fd)]
    p = subprocess.Popen(cmd, close_fds=False)
    p.wait()
    s.close()

if __name__ == "__main__":
    if len(sys.argv) > 2 and sys.argv[1] == "--child":
        main_child(int(sys.argv[2]))
    else:
        main_parent()
