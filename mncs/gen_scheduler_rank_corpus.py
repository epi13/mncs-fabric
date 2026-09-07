#!/usr/bin/env python3
"""Generate the execution corpus for mncs/fabric_scheduler_rank.mncs.

Reads the Python ranking/admission relations (the current runtime
authority in `src/mncs_fabric/capability_resolution.py::resolve_fleet`
and `src/mncs_fabric/scheduler.py::schedule`) and emits every arm as an
MNCS ExecutionCorpus. `tests/test_mncs_scheduler_rank.py` asserts
agreement plus compiled execution.

The pairwise comparator mirrors the fleet sort key exactly
(-preferred_hits, constrained-flag, identity tie-break): rank_prefers
answers the strict question, and a full tie is false so the caller
falls through to the host-side identity order.

Run from the repository root: python3 mncs/gen_scheduler_rank_corpus.py
"""

import itertools
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, os.path.join(ROOT, "src"))

MODULE = "fabric.scheduler_rank"


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


def rank_key(pref_hits, constrained):
    return (-pref_hits, 1 if constrained else 0)


def main():
    cases = []
    for a_pref, a_con, b_pref, b_con in itertools.product(
        (0, 1, 2, 3), (False, True), (0, 1, 2, 3), (False, True)
    ):
        # Python authority: the sort key comparison behind resolve_fleet.
        expected = rank_key(a_pref, a_con) < rank_key(b_pref, b_con)
        cases.append(
            case(
                f"rank-{a_pref}-{int(a_con)}-{b_pref}-{int(b_con)}",
                "candidate_rank",
                [integer32(a_pref), boolean(a_con), integer32(b_pref), boolean(b_con)],
                boolean(expected),
            )
        )
    for eligible, replicas in itertools.product((0, 1, 2, 5, 64), (1, 2, 5, 64)):
        cases.append(
            case(
                f"replicas-{eligible}-{replicas}",
                "candidate_replicas",
                [integer32(eligible), integer32(replicas)],
                boolean(eligible >= replicas),
            )
        )
    for active, limit in itertools.product((0, 1, 2, 5), (1, 2, 5)):
        cases.append(
            case(
                f"slot-{active}-{limit}",
                "candidate_slot",
                [integer32(active), integer32(limit)],
                boolean(active < limit),
            )
        )
    for replicas in (-1, 0, 1, 2, 63, 64, 65, 100):
        cases.append(
            case(
                f"valid-{replicas}",
                "candidate_replicas_valid",
                [integer32(replicas)],
                boolean(1 <= replicas <= 64),
            )
        )
    document = {"schema_version": "0.1", "name": "fabric-scheduler-rank", "cases": cases}
    out = os.path.join(HERE, "fabric_scheduler_rank_corpus.json")
    with open(out, "w") as handle:
        json.dump(document, handle, indent=1)
        handle.write("\n")
    print(f"wrote {out}: {len(cases)} cases")


if __name__ == "__main__":
    main()
