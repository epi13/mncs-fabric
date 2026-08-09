#!/usr/bin/env python3
"""Config-aware wrapper for the generic Linux native-bundle harness.

The underlying harness is shared with Fedora/Linux workers.  This wrapper
only resolves an explicitly supplied Raspberry Pi operator configuration; it
does not discover hosts or alter the Fabric execution protocol.
"""

from __future__ import annotations

import argparse
from pathlib import Path
from typing import Sequence

from two_host_native_bundle_test import main as native_main

from linux_worker_preflight import DEFAULT_CONFIG
from linux_worker_preflight import _operator_values


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="run native Fabric transfer against an explicitly configured Raspberry Pi/Linux worker")
    parser.add_argument("--config", type=Path, default=DEFAULT_CONFIG)
    parser.add_argument("--ssh-host")
    parser.add_argument("--ssh-user")
    parser.add_argument("--ssh-key", type=Path)
    parser.add_argument("--worker-host")
    parser.add_argument("--expected-hostname")
    parser.add_argument("--worker-id")
    parser.add_argument("--controller-id")
    parser.add_argument("--worker-port", type=int)
    parser.add_argument("--output", type=Path, required=True)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _operator_values(build_parser().parse_args(argv))
    native_args = [
        "--ssh-host", args.ssh_host,
        "--ssh-user", args.ssh_user,
        "--ssh-key", str(args.ssh_key),
        "--worker-host", args.worker_host,
        "--worker-port", str(args.worker_port),
        "--expected-hostname", args.expected_hostname,
        "--controller-id", args.controller_id,
        "--worker-id", args.worker_id,
        "--output", str(args.output),
    ]
    return native_main(native_args)


if __name__ == "__main__":
    raise SystemExit(main())
