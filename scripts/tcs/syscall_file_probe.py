#!/usr/bin/env python3
"""
syscall_file_probe.py - TC-07 Low-Level Kernel Telemetry (corrected).

Goal: determine whether the eBPF sensor captures file operations performed via
DIRECT syscalls (bypassing the libc/glibc wrappers that userspace API hooks
would normally intercept) — a common malware evasion technique.

Design = controlled experiment with a baseline and a treatment, each on its own
marker file so SIEM-X can be queried per-arm:

  CONTROL   (libc):           Python open()/write()/unlink()  -> expect CAPTURED
  TREATMENT (direct syscall): syscall(open/write/close/unlink) -> question

If both arms are captured, the eBPF sensor sees through direct-syscall evasion.
If only CONTROL is captured, there is a real telemetry-evasion gap.

x86_64 syscall numbers: open=2, write=1, close=3, unlink=87.
open flags: O_WRONLY(1)|O_CREAT(64)|O_TRUNC(512) = 577, mode 0o644.

Usage: syscall_file_probe.py <MARKER>
Output: JSON to stdout (arms + local fd/return results). SIEM-X verification
is done separately after the ingestion lag.
"""
import ctypes
import json
import os
import sys

MARKER = sys.argv[1] if len(sys.argv) > 1 else "EDR_POC_TC07"
O_WRONLY, O_CREAT, O_TRUNC = 1, 64, 512
FLAGS = O_WRONLY | O_CREAT | O_TRUNC

libc = ctypes.CDLL(None, use_errno=True)


def sc(num, *args):
    """Raw syscall; returns (ret, errno)."""
    ctypes.set_errno(0)
    libc.syscall.restype = ctypes.c_long
    ret = libc.syscall(ctypes.c_long(num), *args)
    return ret, ctypes.get_errno()


def control_arm(path):
    """File create+write+delete entirely via libc (Python stdlib)."""
    r = {"arm": "control_libc", "path": path}
    try:
        with open(path, "w") as f:
            f.write(f"{MARKER}_control\n")
        r["write"] = "OK"
        os.unlink(path)
        r["unlink"] = "OK"
    except OSError as e:
        r["error"] = str(e)
    return r


def treatment_arm(path):
    """File create+write+delete entirely via DIRECT syscalls (no libc wrappers)."""
    r = {"arm": "treatment_direct_syscall", "path": path}
    cpath = ctypes.c_char_p(path.encode())
    fd, err = sc(2, cpath, ctypes.c_int(FLAGS), ctypes.c_int(0o644))  # open
    r["open"] = f"fd={fd}" if fd >= 0 else f"FAIL errno={err} ({os.strerror(err)})"
    if fd >= 0:
        payload = (MARKER + "_treatment\n").encode()
        buf = ctypes.create_string_buffer(payload, len(payload))
        n, err = sc(1, ctypes.c_int(fd), buf, ctypes.c_size_t(len(payload)))  # write
        r["write"] = f"{n} bytes" if n >= 0 else f"FAIL errno={err}"
        ret, _ = sc(3, ctypes.c_int(fd))  # close
        r["close"] = "OK" if ret == 0 else f"ret={ret}"
        ret, err = sc(87, ctypes.c_char_p(path.encode()))  # unlink
        r["unlink"] = "OK" if ret == 0 else f"FAIL errno={err}"
    return r


def main():
    base = "/tmp"
    ctrl_path = f"{base}/{MARKER}_CTRL.txt"
    trt_path = f"{base}/{MARKER}_SYSCALL.txt"
    out = {
        "marker": MARKER,
        "whoami": f"uid={os.getuid()}",
        "control": control_arm(ctrl_path),
        "treatment": treatment_arm(trt_path),
        "note": ("verify in SIEM-X AFTER ingestion lag: search "
                 f"'{MARKER}_CTRL' (control) vs '{MARKER}_SYSCALL' (treatment) "
                 "across logs-edr*"),
    }
    print(json.dumps(out, indent=2))


if __name__ == "__main__":
    main()
