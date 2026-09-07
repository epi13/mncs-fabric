#!/usr/bin/env python3
"""Generate the execution corpus for mncs/fabric_availability.mncs.

Reads the Python window relation (the current runtime authority in
`src/mncs_fabric/availability.py::window_contains`) over boundary
minutes and emits every arm as an MNCS ExecutionCorpus.
`tests/test_mncs_availability.py` asserts agreement plus compiled
execution.

Run from the repository root: python3 mncs/gen_availability_corpus.py
"""

import json
import os
import sys
from datetime import time

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, os.path.join(ROOT, "src"))

from mncs_fabric.availability import window_contains  # noqa: E402

MODULE = "fabric.availability"
# Strategic boundary pairs (begin, finish): empty windows, degenerate
# edges, normal windows, midnight wraps, and full-day coverage.
PAIRS = [
    (0, 0), (720, 720), (1439, 1439),
    (0, 1), (0, 1439), (1, 1439),
    (360, 720), (60, 61), (0, 720), (720, 1439),
    (720, 360), (1439, 0), (1380, 60), (720, 719),
    (1, 0), (1439, 1438),
]


def boolean(value):
    return {"boolean": {"value": bool(value)}}


def integer32(value):
    return {"integer": {"value": int(value), "type": {"bits": 32, "signed": True}}}


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


def clock(minutes):
    return time(minutes // 60 % 24, minutes % 60)


def main():
    cases = []
    for day_in in (False, True):
        for begin, finish in PAIRS:
            # Representative instants per (begin, finish): edges around
            # both bounds plus midnight wrap probes.
            instants = sorted({0, begin - 1, begin, begin + 1, finish - 1, finish, finish + 1, 1439} - {-1, 1440})
            for now in instants:
                expected = day_in and window_contains(clock(begin), clock(finish), clock(now))
                cases.append(
                    case(
                        f"window-day{int(day_in)}-{begin}-{finish}-{now}",
                        "candidate",
                        [boolean(day_in), integer32(begin), integer32(finish), integer32(now)],
                        boolean(expected),
                    )
                )
    document = {"schema_version": "0.1", "name": "fabric-availability-window", "cases": cases}
    out = os.path.join(HERE, "fabric_availability_corpus.json")
    with open(out, "w") as handle:
        json.dump(document, handle, indent=1)
        handle.write("\n")
    print(f"wrote {out}: {len(cases)} cases")


if __name__ == "__main__":
    main()
