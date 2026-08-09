#!/usr/bin/env python3
"""Optional EA-NEXT-005 checker against a nearby MNCS checkout.

The sibling package is loaded from the operator-supplied read-only checkout;
Fabric does not vendor or depend on it at runtime.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from mncs_fabric.challenges import bind_challenge_to_receipt, validate_execution_challenge


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--challenge", type=Path, required=True)
    parser.add_argument("--receipt", type=Path, required=True)
    parser.add_argument("--mncs-root", type=Path, required=True)
    args = parser.parse_args(argv)

    challenge = json.loads(args.challenge.read_text(encoding="utf-8"))
    receipt = json.loads(args.receipt.read_text(encoding="utf-8"))
    local_challenge = validate_execution_challenge(challenge)
    local_binding = bind_challenge_to_receipt(challenge, receipt)
    sys.path.insert(0, str(args.mncs_root / "src"))
    from mncs_validator.execution_challenge import (
        bind_challenge_to_receipt as validate_binding,
        validate_execution_challenge_value,
    )
    from mncs_validator.execution_receipt import validate_execution_receipt_value

    sibling_challenge = validate_execution_challenge_value(challenge)
    sibling_receipt = validate_execution_receipt_value(receipt)
    sibling_binding = validate_binding(challenge, receipt)
    result = {
        "fabric": {"challenge": local_challenge.category, "binding": local_binding.category},
        "mncs": {"challenge": sibling_challenge.category, "receipt": sibling_receipt.category, "binding": sibling_binding.category},
        "source": str(args.mncs_root.resolve()),
    }
    print(json.dumps(result, sort_keys=True, indent=2))
    return 0 if all(value == "PASS" for value in result["fabric"].values()) and all(value == "PASS" for value in result["mncs"].values()) else 1


if __name__ == "__main__":
    raise SystemExit(main())
