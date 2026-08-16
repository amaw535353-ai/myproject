from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import socket
import sys


def _status_value(name: str) -> str:
    for line in Path("/proc/self/status").read_text().splitlines():
        if line.startswith(name + ":"):
            return line.split(":", 1)[1].strip()
    return ""


def identity() -> int:
    print(json.dumps({
        "uid": os.getuid(),
        "gid": os.getgid(),
        "groups": os.getgroups(),
        "no_new_privs": _status_value("NoNewPrivs") == "1",
        "cap_eff": _status_value("CapEff"),
        "cap_bnd": _status_value("CapBnd"),
    }, sort_keys=True))
    return 0


def read_file(path: str) -> int:
    try:
        data = Path(path).read_text()
        print(json.dumps({"read": True, "content": data}, sort_keys=True))
        return 0
    except Exception as exc:
        print(json.dumps({"read": False, "error": type(exc).__name__}, sort_keys=True))
        return 13


def write_file(path: str) -> int:
    try:
        Path(path).write_text("sandbox-write\n")
        print(json.dumps({"write": True}, sort_keys=True))
        return 0
    except Exception as exc:
        print(json.dumps({"write": False, "error": type(exc).__name__}, sort_keys=True))
        return 13


def raw_socket() -> int:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
    except PermissionError:
        print(json.dumps({"raw_socket_denied": True}, sort_keys=True))
        return 0
    except OSError as exc:
        print(json.dumps({"raw_socket_denied": True, "errno": exc.errno}, sort_keys=True))
        return 0
    else:
        s.close()
        print(json.dumps({"raw_socket_denied": False}, sort_keys=True))
        return 1


def setuid_root() -> int:
    try:
        os.setuid(0)
    except PermissionError:
        print(json.dumps({"setuid_root_denied": True}, sort_keys=True))
        return 0
    except OSError as exc:
        print(json.dumps({"setuid_root_denied": True, "errno": exc.errno}, sort_keys=True))
        return 0
    print(json.dumps({"setuid_root_denied": False}, sort_keys=True))
    return 1


def signal_process(pid: int) -> int:
    try:
        os.kill(pid, 15)
    except PermissionError:
        print(json.dumps({"cross_tenant_signal_denied": True}, sort_keys=True))
        return 0
    except ProcessLookupError:
        print(json.dumps({"cross_tenant_signal_denied": False, "error": "target_missing"}, sort_keys=True))
        return 2
    print(json.dumps({"cross_tenant_signal_denied": False}, sort_keys=True))
    return 1


def read_proc_environ(pid: int) -> int:
    try:
        Path(f"/proc/{pid}/environ").read_bytes()
    except PermissionError:
        print(json.dumps({"cross_tenant_proc_environ_denied": True}, sort_keys=True))
        return 0
    except OSError as exc:
        print(json.dumps({"cross_tenant_proc_environ_denied": True, "errno": exc.errno}, sort_keys=True))
        return 0
    print(json.dumps({"cross_tenant_proc_environ_denied": False}, sort_keys=True))
    return 1


def unix_connect(path: str) -> int:
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        sock.connect(path)
        sock.sendall(b"probe")
        print(json.dumps({"unix_connect": True}, sort_keys=True))
        return 0
    except Exception as exc:
        print(json.dumps({"unix_connect": False, "error": type(exc).__name__}, sort_keys=True))
        return 13
    finally:
        sock.close()


def main() -> int:
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("identity")
    p = sub.add_parser("read-file"); p.add_argument("path")
    p = sub.add_parser("write-file"); p.add_argument("path")
    sub.add_parser("raw-socket")
    sub.add_parser("setuid-root")
    p = sub.add_parser("signal"); p.add_argument("pid", type=int)
    p = sub.add_parser("read-proc-environ"); p.add_argument("pid", type=int)
    p = sub.add_parser("unix-connect"); p.add_argument("path")
    args = parser.parse_args()
    if args.command == "identity": return identity()
    if args.command == "read-file": return read_file(args.path)
    if args.command == "write-file": return write_file(args.path)
    if args.command == "raw-socket": return raw_socket()
    if args.command == "setuid-root": return setuid_root()
    if args.command == "signal": return signal_process(args.pid)
    if args.command == "read-proc-environ": return read_proc_environ(args.pid)
    if args.command == "unix-connect": return unix_connect(args.path)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
