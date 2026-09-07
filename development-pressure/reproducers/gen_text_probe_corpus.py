#!/usr/bin/env python3
"""Generate the corpus for the P-005/P-014 text pressure reproducer.

Expectations come from the Python classifiers (the current authority)
for the covered tokens, plus plain integer semantics for digit parsing.
Run from the repository root: python3 development-pressure/reproducers/gen_text_probe_corpus.py
"""

import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
sys.path.insert(0, os.path.join(ROOT, "src"))

from mncs_fabric.capability_resolution import classify_arch  # noqa: E402

MODULE = "pressure.text_probe"


def boolean(value):
    return {"boolean": {"value": bool(value)}}


def integer64(value):
    return {"integer": {"value": int(value), "type": {"bits": 64, "signed": True}}}


def byte(value):
    return {"byte": {"value": int(value)}}


def sequence(values):
    return {"sequence": {"values": list(values)}}


def word(text):
    return sequence([byte(code) for code in text.encode("ascii")])


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


def main():
    cases = []
    # Exact-width tokens only (the entrypoint takes [byte; 6]). Matching
    # is byte-exact: the Python classifier folds case ("X86_64" matches
    # there), MNCS does not. The test pins that split explicitly.
    for token in ["x86_64", "aarch6", "X86_64", "x86_65"]:
        cases.append(case(f"x86-{token}", "candidate_x86", [word(token)], boolean(token == "x86_64")))
    for token in ["aarch64", "x86_64!", "AARCH64", "aarch65"]:
        cases.append(
            case(f"aarch64-{token}", "candidate_aarch64", [word(token)], boolean(token == "aarch64"))
        )
    for digits in [b"31", b"00", b"99", b"3x", b"ab"]:
        codes = [byte(digits[0]), byte(digits[1])]
        expect = int(digits) if digits.isdigit() else -1
        cases.append(case(f"digits-{digits.decode()}", "candidate_digits", codes, integer64(expect)))
    document = {"schema_version": "0.1", "name": "pressure-text-probe", "cases": cases}
    out = os.path.join(HERE, "text_probe_corpus.json")
    with open(out, "w") as handle:
        json.dump(document, handle, indent=1)
        handle.write("\n")
    print(f"wrote {out}: {len(cases)} cases")


if __name__ == "__main__":
    main()
