#!/usr/bin/env python3
"""Capture one dependency-free Fabric resource snapshot.

This is an observation tool. Discovery of an accelerator is deliberately not
treated as proof that its runtime can execute a kernel.
"""

from __future__ import annotations

import argparse
import json

from mncs_fabric.resources import capture_resource_snapshot


def main() -> int:
    parser = argparse.ArgumentParser(description="Capture a bounded Fabric resource snapshot")
    parser.add_argument("--worker-id", required=True)
    args = parser.parse_args()
    print(json.dumps(capture_resource_snapshot(args.worker_id), sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
