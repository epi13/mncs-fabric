#!/usr/bin/env python3
"""Generate the execution corpus for mncs/fabric_work_item.mncs.

Reads the Python work-item relations (the current runtime authority in
`src/mncs_fabric/work_queue.py`: terminal classification, priority
order, dispatch holds) and emits every arm as an MNCS ExecutionCorpus.
`tests/test_mncs_work_item.py` asserts agreement plus compiled
execution.

Run from the repository root: python3 mncs/gen_work_item_corpus.py
"""

import itertools
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, os.path.join(ROOT, "src"))

from mncs_fabric.work_queue import _TERMINAL  # noqa: E402  (the Python authority set)

MODULE = "fabric.work_item"

STATES = ["QUEUED", "DISPATCHED", "COMPLETED", "FAILED", "CANCELLED", "OTHER"]
STATE_MNCS = {"QUEUED": "Queued", "DISPATCHED": "Dispatched", "COMPLETED": "Completed",
              "FAILED": "Failed", "CANCELLED": "Cancelled", "OTHER": "NonTerminal"}
STATE_INDEX = {"Queued": 0, "Dispatched": 1, "Completed": 2, "Failed": 3, "Cancelled": 4, "NonTerminal": 5}
TERMINAL = set(_TERMINAL)
HOLD_MNCS = {"dispatch": "Dispatch", "paused": "PausedHold", "noeligible": "NoEligibleHold"}
HOLD_INDEX = {"Dispatch": 0, "PausedHold": 1, "NoEligibleHold": 2}


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


def boolean(value):
    return {"boolean": {"value": bool(value)}}


def integer64(value):
    return {"integer": {"value": int(value), "type": {"bits": 64, "signed": True}}}


I64_MIN = -(2**63)
I64_MAX = 2**63 - 1
# Domain boundaries: i64 extremes, +-2^31 edges (the old implicit
# boundary), negatives, zero (folds to default), small values, equality.
PRIORITIES = [I64_MIN, -2**31 - 1, -2**31, -1, 0, 1, 50, 100, 200, 2**31 - 1, 2**31, I64_MAX]


def effective(priority):
    # The queue's falsy-means-default read over stored ints.
    return 100 if priority == 0 else priority


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
    for state in STATES:
        variant = STATE_MNCS[state]
        cases.append(
            case(
                f"terminal-{state}",
                "candidate_terminal",
                [finite(MODULE, "WorkState", variant, STATE_INDEX[variant])],
                boolean(state in TERMINAL),
            )
        )
    for a_priority, b_priority in itertools.product(PRIORITIES, repeat=2):
        # Python authority: the queue sorts ascending by effective
        # (priority, work_id); stored zeros sort as the default 100.
        cases.append(
            case(
                f"priority-{a_priority}-{b_priority}",
                "candidate_priority",
                [integer64(effective(a_priority)), integer64(effective(b_priority))],
                boolean(effective(a_priority) < effective(b_priority)),
            )
        )
    for raw in PRIORITIES:
        cases.append(
            case(
                f"effective-{raw}",
                "candidate_effective",
                [integer64(raw)],
                integer64(effective(raw)),
            )
        )
    for paused, eligible in itertools.product((False, True), repeat=2):
        # Python authority: tick holds everything when paused, otherwise
        # dispatches when a worker is selected (eligible found).
        if paused:
            hold = "paused"
        elif eligible:
            hold = "dispatch"
        else:
            hold = "noeligible"
        variant = HOLD_MNCS[hold]
        cases.append(
            case(
                f"hold-paused{int(paused)}-eligible{int(eligible)}",
                "candidate_hold",
                [boolean(paused), boolean(eligible)],
                finite(MODULE, "HoldReason", variant, HOLD_INDEX[variant]),
            )
        )
    document = {"schema_version": "0.1", "name": "fabric-work-item", "cases": cases}
    out = os.path.join(HERE, "fabric_work_item_corpus.json")
    with open(out, "w") as handle:
        json.dump(document, handle, indent=1)
        handle.write("\n")
    print(f"wrote {out}: {len(cases)} cases")


if __name__ == "__main__":
    main()
