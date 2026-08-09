#!/usr/bin/env python3
"""Validate a sanitized Fabric two-host evidence record."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from mncs_fabric.evidence import validate_two_host_evidence


def main() -> int:
    parser = argparse.ArgumentParser(description="Validate sanitized Fabric two-host evidence")
    parser.add_argument("evidence", type=Path)
    args = parser.parse_args()
    report = validate_two_host_evidence(json.loads(args.evidence.read_text(encoding="utf-8")))
    print(json.dumps(report, sort_keys=True, separators=(",", ":")))
    return 0 if report["outcome"] == "PASS" else 2


if __name__ == "__main__":
    raise SystemExit(main())
