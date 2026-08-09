#!/usr/bin/env python3
"""Optional checker against a nearby current MNCS checkout.

Fabric CI stays self-contained.  This tool is for an operator who has a
read-only ``machine-native-complexity-standard`` checkout available.
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import sys
from pathlib import Path

from mncs_fabric.bundles import verify_bundle_archive


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("archive", type=Path)
    parser.add_argument("--mncs-root", type=Path, required=True)
    args = parser.parse_args(argv)
    module_path = args.mncs_root / "src/mncs_validator/execution_bundle.py"
    spec = importlib.util.spec_from_file_location("nearby_mncs_execution_bundle", module_path)
    if spec is None or spec.loader is None:
        raise SystemExit("nearby MNCS execution_bundle.py could not be loaded")
    # The sibling module uses package-relative imports; use its normal source
    # package path rather than copying or vendoring its implementation.
    sys.path.insert(0, str(args.mncs_root / "src"))
    from mncs_validator.execution_bundle import verify_execution_bundle_archive

    fabric = verify_bundle_archive(args.archive)
    mncs = verify_execution_bundle_archive(args.archive)
    result = {"fabric": fabric.as_dict(), "mncs": mncs.as_dict(), "same_category": fabric.category == mncs.category, "same_bundle_identity": fabric.bundle_identity == mncs.bundle_identity, "same_archive_identity": fabric.archive_identity == mncs.archive_identity}
    print(json.dumps(result, sort_keys=True, indent=2))
    return 0 if result["same_category"] and result["same_bundle_identity"] and result["same_archive_identity"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
