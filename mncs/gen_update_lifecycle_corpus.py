#!/usr/bin/env python3
"""Generate the exhaustive execution corpus for mncs/update_lifecycle.mncs.

Reads the Python transition table and version parser (the current runtime
authority) and emits every state pair plus version-precedence cases as an
MNCS ExecutionCorpus. `mncs experiment run` executes the compiled module;
`tests/test_mncs_update_policy.py` asserts the execution agrees with Python
on every case.

Run from the repository root: python3 mncs/gen_update_lifecycle_corpus.py
"""

import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, os.path.join(ROOT, "src"))

from mncs_fabric.update_lifecycle import UPDATE_STATES, _TRANSITIONS  # noqa: E402
from mncs_fabric.versioning import RELEASE_PRERELEASE, parse_fabric_version  # noqa: E402

MODULE = "fabric.update_lifecycle"
STATES = list(UPDATE_STATES)
VERDICTS = ["ALLOWED", "DENIED"]


def finite(module, type_name, variant_name, discriminant):
    return {
        "finite": {
            "type_identity": f"mncs:0.2:finite-type:{module}::{type_name}",
            "variant_identity": (
                f"mncs:0.2:finite-variant:{module}::{type_name}::{variant_name}"
            ),
            "discriminant": discriminant,
        }
    }


def integer(value):
    return {"integer": {"value": value, "type": {"bits": 32, "signed": True}}}


def boolean(value):
    return {"boolean": {"value": value}}


def case(case_id, function, arguments, expected, step_budget=4096):
    return {
        "id": case_id,
        "request": {
            "schema_version": "0.1",
            "target": {"module": MODULE, "function": function},
            "arguments": list(arguments),
            "step_budget": step_budget,
        },
        "expected": [expected],
    }


def version_tuple(text):
    parsed = parse_fabric_version(text)
    assert parsed is not None, text
    return (parsed.major, parsed.minor, parsed.patch, parsed.prerelease)


def main():
    cases = []
    for source in STATES:
        for target in STATES:
            allowed = target in _TRANSITIONS[source]
            verdict = "ALLOWED" if allowed else "DENIED"
            cases.append(
                case(
                    f"transition-{source}-{target}",
                    "candidate",
                    [
                        finite(MODULE, "UpdateState", source, STATES.index(source)),
                        finite(MODULE, "UpdateState", target, STATES.index(target)),
                    ],
                    finite(MODULE, "TransitionVerdict", verdict, VERDICTS.index(verdict)),
                )
            )
    versions = [
        "0.2.0a21",
        "0.2.0a30",
        "0.2.0a31",
        "0.2.0",
        "0.2.1",
        "0.3.0a1",
        "1.0.0",
    ]
    for left in versions:
        for right in versions:
            a = version_tuple(left)
            b = version_tuple(right)
            expected = list(a) < list(b)
            args = [integer(x) for x in a] + [integer(x) for x in b]
            cases.append(
                case(f"version-{left}-lt-{right}", "version_candidate", args, boolean(expected))
            )
    document = {
        "schema_version": "0.1",
        "name": "fabric-update-lifecycle-exhaustive",
        "cases": cases,
    }
    out = os.path.join(HERE, "update_lifecycle_corpus.json")
    with open(out, "w") as handle:
        json.dump(document, handle, indent=1)
        handle.write("\n")
    print(f"wrote {out}: {len(cases)} cases")


if __name__ == "__main__":
    main()
