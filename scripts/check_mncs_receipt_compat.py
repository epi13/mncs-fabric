#!/usr/bin/env python3
"""Optional checker against a nearby machine-native-complexity-standard checkout."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from mncs_fabric.receipts import build_execution_receipt


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--schema", type=Path, required=True)
    parser.add_argument("--receipt", type=Path)
    args = parser.parse_args()
    schema = json.loads(args.schema.read_text(encoding="utf-8"))
    if schema.get("properties", {}).get("schema_version", {}).get("const") != "0.1-experimental":
        raise SystemExit("unsupported sibling receipt schema; refusing compatibility guessing")
    required = schema.get("required")
    if not isinstance(required, list) or "receipt_identity" not in required or "claim_boundary" not in required:
        raise SystemExit("sibling receipt schema is not the inspected experimental contract")
    if args.receipt:
        value = json.loads(args.receipt.read_text(encoding="utf-8"))
        if value.get("schema_version") != "0.1-experimental" or value.get("record_type") != "mncs-execution-receipt":
            raise SystemExit("receipt does not declare the supported sibling profile")
        missing = sorted(set(required) - set(value))
        if missing:
            raise SystemExit("receipt missing required fields: " + ", ".join(missing))
    print(json.dumps({"outcome": "PASS", "schema_version": "0.1-experimental", "required_fields": len(required)}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
