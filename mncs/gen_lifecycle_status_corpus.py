#!/usr/bin/env python3
"""Generate the execution corpus for mncs/fabric_lifecycle_status.mncs.

Reads the Python enrollment-status derivation (the current runtime
authority in `src/mncs_fabric/lifecycle.py::_record_status` and
`_request_status`) over synthetic ledger shapes and emits every
precedence arm as an MNCS ExecutionCorpus. `mncs experiment run`
executes the compiled module; `tests/test_mncs_lifecycle_status.py`
asserts the execution agrees with Python on every case.

The synthetic records carry only the fields those two functions read
(authorization/request ids, event names, expiry instants, decisions);
clocks, digests, and identity checks stay host-side and are out of scope
for the MNCS module, which observes the reduced boolean facts.

Run from the repository root: python3 mncs/gen_lifecycle_status_corpus.py
"""

import itertools
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, os.path.join(ROOT, "src"))

from mncs_fabric.lifecycle import _record_status, _request_status  # noqa: E402

MODULE = "fabric.lifecycle_status"

AUTH_MNCS = {"ACTIVE": "Active", "CONSUMED": "Consumed", "EXPIRED": "Expired", "REVOKED": "Revoked"}
AUTH_INDEX = {"Active": 0, "Consumed": 1, "Expired": 2, "Revoked": 3}
DECISION_MNCS = {"APPROVED": "Approved", "DENIED": "Denied", "EXPIRED": "Expired"}
DECISION_INDEX = {"Approved": 0, "Denied": 1, "Expired": 2}
REQUEST_MNCS = {"PENDING": "Pending", "APPROVED": "Approved", "DENIED": "Denied", "EXPIRED": "Expired"}
REQUEST_INDEX = {"Pending": 0, "Approved": 1, "Denied": 2, "Expired": 3}

AUTH_ID = "auth-corpus-1"
REQUEST_ID = "req-corpus-1"
NOW = "2029-06-01T00:00:00Z"
FUTURE_EXPIRY = "2030-01-01T00:00:00Z"
PAST_EXPIRY = "2028-01-01T00:00:00Z"


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


def auth_records(expired_by_time, events):
    records = [
        {
            "record_type": "enrollment.authorization",
            "record": {
                "authorization_id": AUTH_ID,
                "expires_at": PAST_EXPIRY if expired_by_time else FUTURE_EXPIRY,
            },
        }
    ]
    for event in events:
        records.append(
            {
                "record_type": "enrollment.authorization",
                "record": {"authorization_id": AUTH_ID, "event": event},
            }
        )
    return records


def request_records(auth_events, expired_by_time, decision):
    records = auth_records(expired_by_time, auth_events)
    records.append(
        {
            "record_type": "enrollment.request",
            "record": {"request_id": REQUEST_ID, "authorization_id": AUTH_ID},
        }
    )
    if decision is not None:
        records.append(
            {
                "record_type": "enrollment.decision",
                "record": {"request_id": REQUEST_ID, "decision": decision},
            }
        )
    return records


def main():
    cases = []
    for revoked, expired_event, expired_by_time, consumed in itertools.product(
        (False, True), repeat=4
    ):
        events = []
        if consumed:
            events.append("consumed")
        if revoked:
            events.append("revoked")
        if expired_event:
            events.append("expired")
        status = _record_status(auth_records(expired_by_time, events), AUTH_ID, NOW)
        status_mncs = AUTH_MNCS[status]
        cases.append(
            case(
                f"auth-rev{int(revoked)}-exp{int(expired_event)}-time{int(expired_by_time)}-con{int(consumed)}",
                "candidate_authorization",
                [boolean(revoked), boolean(expired_event), boolean(expired_by_time), boolean(consumed)],
                finite(MODULE, "AuthStatus", status_mncs, AUTH_INDEX[status_mncs]),
            )
        )
    auth_shapes = {
        "Active": ([], False),
        "Consumed": (["consumed"], False),
        "Expired": ([], True),
        "Revoked": (["revoked"], False),
    }
    for auth_name, (auth_events, expired_by_time) in auth_shapes.items():
        for has_decision in (False, True):
            for decision in ("APPROVED", "DENIED", "EXPIRED"):
                records = request_records(
                    auth_events, expired_by_time, decision if has_decision else None
                )
                status = _request_status(records, REQUEST_ID, NOW)
                decision_mncs = DECISION_MNCS[decision]
                request_mncs = REQUEST_MNCS[status]
                cases.append(
                    case(
                        f"request-{auth_name.lower()}-dec{int(has_decision)}-{decision.lower()}",
                        "candidate_request",
                        [
                            boolean(has_decision),
                            finite(MODULE, "Decision", decision_mncs, DECISION_INDEX[decision_mncs]),
                            finite(MODULE, "AuthStatus", auth_name, AUTH_INDEX[auth_name]),
                        ],
                        finite(MODULE, "RequestStatus", request_mncs, REQUEST_INDEX[request_mncs]),
                    )
                )
    document = {
        "schema_version": "0.1",
        "name": "fabric-lifecycle-status-exhaustive",
        "cases": cases,
    }
    out = os.path.join(HERE, "fabric_lifecycle_status_corpus.json")
    with open(out, "w") as handle:
        json.dump(document, handle, indent=1)
        handle.write("\n")
    print(f"wrote {out}: {len(cases)} cases")


if __name__ == "__main__":
    main()
