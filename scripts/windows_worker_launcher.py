#!/usr/bin/env python3
"""Bounded Windows-aware Fabric worker process lifecycle helper.

The helper manages only a PID recorded by this launcher and verifies a
process-start token before stopping it.  It is not a general remote-shell or
service manager.  On Linux it remains useful for tests, but Windows-native
detached process flags and ``taskkill`` are used only on Windows.
"""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import time
from typing import Any


def _now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _token(pid: int) -> str | None:
    if pid < 1:
        return None
    if os.name == "nt":
        # FILETIME returned by GetProcessTimes is stable for the process
        # lifetime and avoids killing a reused PID.
        import ctypes
        class FileTime(ctypes.Structure):
            _fields_ = [("low", ctypes.c_uint32), ("high", ctypes.c_uint32)]
        handle = ctypes.windll.kernel32.OpenProcess(0x1000, False, pid)
        if not handle:
            return None
        created = FileTime()
        exited = FileTime()
        kernel = FileTime()
        user = FileTime()
        try:
            if not ctypes.windll.kernel32.GetProcessTimes(handle, ctypes.byref(created), ctypes.byref(exited), ctypes.byref(kernel), ctypes.byref(user)):
                return None
            return f"{created.high:08x}{created.low:08x}"
        finally:
            ctypes.windll.kernel32.CloseHandle(handle)
    stat = Path(f"/proc/{pid}/stat")
    try:
        fields = stat.read_text(encoding="ascii").split()
        return fields[21] if len(fields) > 21 else None
    except (OSError, UnicodeError, IndexError):
        return None


def _identity(command: list[str]) -> str:
    return "sha256:" + hashlib.sha256(json.dumps(command, separators=(",", ":"), ensure_ascii=False).encode("utf-8")).hexdigest()


def _load(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise RuntimeError(f"launcher state is unreadable: {path}") from exc
    if not isinstance(value, dict) or not isinstance(value.get("pid"), int) or not isinstance(value.get("process_token"), str):
        raise RuntimeError("launcher state is malformed")
    return value


def _alive(state: dict[str, Any]) -> bool:
    return _token(int(state["pid"])) == state["process_token"]


def _write(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + ".tmp")
    temporary.write_text(json.dumps(value, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    temporary.replace(path)


def start(args: argparse.Namespace) -> int:
    state_path = Path(args.state).resolve()
    previous = _load(state_path) if state_path.exists() else None
    if previous is not None and _alive(previous):
        print(json.dumps({"outcome": "PASS", "pid": previous["pid"], "state": "ALREADY_RUNNING"}))
        return 0
    command = list(args.worker_command or [])
    if command and command[0] == "--":
        command.pop(0)
    if not command and previous is not None and isinstance(previous.get("command"), list):
        command = list(previous["command"])
    if not command:
        raise RuntimeError("start requires a bounded worker command after --")
    stdout_path = Path(args.stdout).resolve()
    stderr_path = Path(args.stderr).resolve()
    stdout_path.parent.mkdir(parents=True, exist_ok=True)
    stderr_path.parent.mkdir(parents=True, exist_ok=True)
    creationflags = 0
    if os.name == "nt":
        creationflags = (
            getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
            | getattr(subprocess, "DETACHED_PROCESS", 0)
            # OpenSSH sessions may place children in a job object. Request a
            # breakaway where the host policy permits it; the launcher still
            # owns and validates the resulting PID token.
            | getattr(subprocess, "CREATE_BREAKAWAY_FROM_JOB", 0)
        )
    with stdout_path.open("ab") as stdout, stderr_path.open("ab") as stderr:
        process = subprocess.Popen(command, cwd=str(Path(args.cwd).resolve()) if args.cwd else None, stdin=subprocess.DEVNULL, stdout=stdout, stderr=stderr, shell=False, creationflags=creationflags, start_new_session=(os.name == "posix"))
    token = _token(process.pid)
    if token is None:
        try:
            process.terminate()
        except OSError:
            pass
        raise RuntimeError("could not capture the launched process identity")
    _write(state_path, {"schema_version": "mncs-fabric.windows-worker-launcher.v0.1", "pid": process.pid, "process_token": token, "worker_id": args.worker_id, "command_identity": _identity(command), "command": command, "started_at": _now(), "stdout": str(stdout_path), "stderr": str(stderr_path)})
    print(json.dumps({"outcome": "PASS", "pid": process.pid, "state": str(state_path)}))
    return 0


def status(args: argparse.Namespace) -> int:
    state = _load(Path(args.state).resolve())
    result = {"outcome": "PASS", "state": "AVAILABLE" if _alive(state) else "STOPPED", "pid": state["pid"], "worker_id": state.get("worker_id"), "started_at": state.get("started_at"), "command_identity": state.get("command_identity"), "stdout": state.get("stdout"), "stderr": state.get("stderr")}
    print(json.dumps(result, sort_keys=True))
    return 0


def stop(args: argparse.Namespace) -> int:
    state_path = Path(args.state).resolve()
    state = _load(state_path)
    if not _alive(state):
        print(json.dumps({"outcome": "PASS", "state": "STOPPED", "pid": state["pid"]}, sort_keys=True))
        return 0
    pid = int(state["pid"])
    if os.name == "nt":
        # Do not use /T.  A tree kill also destroys the detached restart helper
        # when OpenSSH job breakaway is unavailable.
        subprocess.run(["taskkill", "/PID", str(pid), "/F"], check=False, capture_output=True, text=True, timeout=10)
    else:
        os.kill(pid, signal.SIGTERM)
    print(json.dumps({"outcome": "PASS", "state": "STOP_REQUESTED", "pid": pid}, sort_keys=True))
    return 0


def restart(args: argparse.Namespace) -> int:
    """Stop then start after a delay so the current worker can exit first."""

    delay = max(0.0, float(args.delay))
    if delay:
        time.sleep(delay)
    state_path = Path(args.state).resolve()
    previous = _load(state_path) if state_path.exists() else None
    if previous is not None:
        stop_ns = argparse.Namespace(state=str(state_path))
        stop(stop_ns)
        time.sleep(1.0)
        start_ns = argparse.Namespace(
            state=str(state_path),
            worker_id=str(previous.get("worker_id") or args.worker_id or "windows-worker"),
            stdout=str(previous.get("stdout") or args.stdout),
            stderr=str(previous.get("stderr") or args.stderr),
            cwd=args.cwd,
            worker_command=list(previous.get("command") or []),
        )
        return start(start_ns)
    raise RuntimeError("launcher state is missing; cannot restart")


def logs(args: argparse.Namespace) -> int:
    state = _load(Path(args.state).resolve())
    for stream in ("stdout", "stderr"):
        path = Path(state[stream])
        print(f"[{stream}] {path}")
        if path.is_file():
            print(path.read_text(encoding="utf-8", errors="replace")[-args.tail:])
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="bounded Fabric worker lifecycle helper")
    sub = parser.add_subparsers(dest="action", required=True)
    start_parser = sub.add_parser("start")
    start_parser.add_argument("--state", required=True)
    start_parser.add_argument("--worker-id", required=True)
    start_parser.add_argument("--stdout", required=True)
    start_parser.add_argument("--stderr", required=True)
    start_parser.add_argument("--cwd")
    start_parser.add_argument("worker_command", nargs=argparse.REMAINDER, help="worker command; place -- before it")
    sub.add_parser("status").add_argument("--state", required=True)
    sub.add_parser("stop").add_argument("--state", required=True)
    restart_parser = sub.add_parser("restart")
    restart_parser.add_argument("--state", required=True)
    restart_parser.add_argument("--delay", type=float, default=3.0)
    restart_parser.add_argument("--worker-id")
    restart_parser.add_argument("--stdout")
    restart_parser.add_argument("--stderr")
    restart_parser.add_argument("--cwd")
    log_parser = sub.add_parser("logs")
    log_parser.add_argument("--state", required=True)
    log_parser.add_argument("--tail", type=int, default=8192)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if args.action == "start":
            return start(args)
        if args.action == "status":
            return status(args)
        if args.action == "stop":
            return stop(args)
        if args.action == "restart":
            return restart(args)
        return logs(args)
    except (OSError, RuntimeError, ValueError) as exc:
        print(json.dumps({"outcome": "UNKNOWN", "error": str(exc)}))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
