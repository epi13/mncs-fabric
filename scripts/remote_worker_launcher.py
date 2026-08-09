#!/usr/bin/env python3
"""Start one bounded Fabric worker service and detach its output.

This is intentionally a narrow bootstrap helper for the two-host harness. It
does not accept arbitrary commands or provide a general remote shell.
"""

from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Start a bounded MNCS Fabric worker")
    for name in ("worker-id", "controller-id", "bundle-root", "state", "trust-state", "ca", "certificate", "key", "host", "port", "timeout", "max-requests", "idle-timeout", "max-concurrent-connections", "graceful-shutdown-timeout", "bundle-cache", "log"):
        parser.add_argument("--" + name, required=name not in {"host", "timeout", "max-requests", "idle-timeout", "max-concurrent-connections", "graceful-shutdown-timeout", "bundle-cache"})
    args = parser.parse_args(argv)
    log_path = Path(args.log).resolve()
    log_path.parent.mkdir(parents=True, exist_ok=True)
    command = [
        sys.executable, "-m", "mncs_fabric", "worker", "serve",
        "--worker-id", args.worker_id, "--controller-id", args.controller_id,
        "--bundle-root", args.bundle_root, "--state", args.state,
        "--trust-state", args.trust_state, "--ca", args.ca,
        "--certificate", args.certificate, "--key", args.key,
        "--host", args.host or "127.0.0.1", "--port", str(args.port),
        "--timeout", str(args.timeout or 30),
        "--max-requests", str(args.max_requests or 1),
        "--max-concurrent-connections", str(args.max_concurrent_connections or 1),
        "--graceful-shutdown-timeout", str(args.graceful_shutdown_timeout or 5),
    ]
    if args.bundle_cache is not None:
        command.extend(["--bundle-cache", args.bundle_cache])
    if args.idle_timeout is not None:
        command.extend(["--idle-timeout", str(args.idle_timeout)])
    with log_path.open("ab", buffering=0) as log:
        process = subprocess.Popen(
            command,
            stdin=subprocess.DEVNULL,
            stdout=log,
            stderr=subprocess.STDOUT,
            close_fds=True,
            start_new_session=True,
        )
    print(process.pid, flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
