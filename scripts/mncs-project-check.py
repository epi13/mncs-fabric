#!/usr/bin/env python3
"""Run the bounded Fabric MNCS check suite and emit a check-result document.

This is an adapter for mncs-actions, not an MNCS conformance verifier. The
result is deliberately scoped to the repository's MNCS-pressure surface:
ledger bounds, update provenance, the MNCS-executed update policy, evidence
conformance, and rollback. The full unit suite still runs in ci.yml.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path


TEST_COMMAND = (
    sys.executable,
    "-m",
    "unittest",
    "tests.test_ledger_compaction",
    "tests.test_supervisor_provenance",
    "tests.test_mncs_update_policy.TestUpdatePolicyCorpusAgreement",
    "tests.test_conformance",
    "tests.test_provenance",
    "tests.test_rollback",
)
RESULT_ID = "project-tests"
PROVIDER = "mncs-fabric-project"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--output",
        default=".mncs/project-check.json",
        help="path for the mncs.check-result/1 document",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    result_path = Path(args.output)

    try:
        completed = subprocess.run(TEST_COMMAND, check=False)
    except OSError as error:
        exit_code = 127
        summary = f"Could not execute test suite: {error}"
    else:
        exit_code = completed.returncode
        if exit_code == 0:
            summary = "Fabric bounded MNCS check suite passed."
        else:
            summary = f"Fabric bounded MNCS check suite failed with exit code {exit_code}."

    result = {
        "schema_version": "mncs.check-result/1",
        "id": RESULT_ID,
        "provider": PROVIDER,
        "verdict": "PASS" if exit_code == 0 else "FAIL",
        "scope": "mncs-fabric bounded MNCS pressure surface",
        "claim": "The repository's ledger, provenance, policy, conformance, and rollback checks completed successfully.",
        "summary": summary,
        "references": [
            {"kind": "test-suite", "path": "tests/test_ledger_compaction.py"},
            {"kind": "test-suite", "path": "tests/test_supervisor_provenance.py"},
            {"kind": "test-suite", "path": "tests/test_mncs_update_policy.py"},
            {"kind": "test-suite", "path": "tests/test_conformance.py"},
            {"kind": "test-suite", "path": "tests/test_provenance.py"},
            {"kind": "test-suite", "path": "tests/test_rollback.py"},
            {"kind": "source", "path": "mncs/update_lifecycle.mncs"},
        ],
    }

    result_path.parent.mkdir(parents=True, exist_ok=True)
    result_path.write_text(
        json.dumps(result, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )

    # run-check needs the provider command itself to complete so it can
    # validate and aggregate the explicit FAIL result. The test outcome is
    # carried by the result document; aggregation remains the boundary gate.
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
