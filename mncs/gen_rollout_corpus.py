#!/usr/bin/env python3
"""Generate the execution corpus for mncs/fabric_rollout_outcome.mncs.

Reads the Python outcome predicates (the current runtime authority in
`src/mncs_fabric/rollout.py`) over constructed outcome dicts and emits
every arm as an MNCS ExecutionCorpus.
`tests/test_mncs_rollout_outcome.py` asserts agreement plus compiled
execution.

Reductions (documented in the MNCS module): receipt/certification/
conformance questions fold to bools with two certification strictnesses
(deployment accepts an empty disposition, canary requires CERTIFIED);
transaction and management states fold to TxnClass/MgmtClass.

Run from the repository root: python3 mncs/gen_rollout_corpus.py
"""

import itertools
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, os.path.join(ROOT, "src"))

from mncs_fabric.rollout import (  # noqa: E402
    INTERMEDIATE_CANARY_STATES,
    canary_failed,
    canary_succeeded,
    deployment_succeeded,
)

MODULE = "fabric.rollout_outcome"

TXN_STATES = [None, "READY", "ROLLED_BACK", "FAILED", "QUARANTINED", "UPDATE_APPLYING"]
TXN_MNCS = {None: "Absent", "READY": "Ready", "ROLLED_BACK": "RolledBack",
            "FAILED": "Other", "QUARANTINED": "Other", "UPDATE_APPLYING": "Other"}
TXN_INDEX = {"Ready": 0, "RolledBack": 1, "Other": 2, "Absent": 3}
MGMT_STATES = ["READY", "QUARANTINED", "MAINTENANCE", "CERTIFYING", "BUSY", "DRAINING"]
MGMT_MNCS = {"READY": "Ready", "QUARANTINED": "Quarantined", "BUSY": "Other", "DRAINING": "Other"}
MGMT_INDEX = {"Ready": 0, "Quarantined": 1, "Intermediate": 2, "Other": 3}
CERT_DISPOSITIONS = [None, "CERTIFIED", "FAILED", "PENDING"]
OBSERVATIONS = [None, "RECONNECTED", "DEADLINE_EXPIRED", "WRONG_VERSION", "WRONG_IDENTITY",
                "STILL_CONNECTED", "MALFORMED_VERSION", "AWAITING_DISCONNECT"]
BAD_OBSERVATIONS = {"DEADLINE_EXPIRED", "WRONG_VERSION", "WRONG_IDENTITY", "STILL_CONNECTED", "MALFORMED_VERSION"}


def mgmt_class(state):
    if state == "READY":
        return "Ready"
    if state == "QUARANTINED":
        return "Quarantined"
    if state in INTERMEDIATE_CANARY_STATES:
        return "Intermediate"
    return "Other"


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


def main():
    cases = []
    for restart in (False, True):
        for receipt_fail in (False, True):
            for cert in CERT_DISPOSITIONS:
                cert_present_options = [False] if cert is None else [True]
                for cert_present in cert_present_options:
                    certification = {} if not cert_present else {"disposition": cert}
                    for txn_state in TXN_STATES:
                        transaction = {} if txn_state is None else {"state": txn_state}
                        outcome = {
                            "restart_required": restart,
                            "receipt": {"disposition": "FAIL" if receipt_fail else "PASS"},
                            "certification": certification,
                            "update_transaction": transaction,
                        }
                        expected = deployment_succeeded(outcome)
                        txn_mncs = TXN_MNCS[txn_state]
                        cert_ok_deploy = cert in (None, "CERTIFIED")
                        cases.append(
                            case(
                                f"deploy-restart{int(restart)}-receipt{int(receipt_fail)}"
                                f"-cert{cert}-txn{txn_state}",
                                "candidate_deployment",
                                [boolean(restart), boolean(receipt_fail),
                                 boolean(cert_present), boolean(cert_ok_deploy),
                                 finite(MODULE, "TxnClass", txn_mncs, TXN_INDEX[txn_mncs])],
                                boolean(expected),
                            )
                        )
    for restart in (False, True):
        for receipt_fail in (False, True):
            for mgmt_state in MGMT_STATES:
                for txn_state in TXN_STATES:
                    for cert in CERT_DISPOSITIONS:
                        for blocking in (False, True):
                            certification = {} if cert is None else {"disposition": cert}
                            transaction = {} if txn_state is None else {"state": txn_state}
                            conformance = {"blocking_failures": ["x"] if blocking else []}
                            outcome = {
                                "restart_required": restart,
                                "receipt": {"disposition": "FAIL" if receipt_fail else "PASS"},
                                "management": {"state": mgmt_state},
                                "update_transaction": transaction,
                                "certification": certification,
                                "conformance": conformance,
                            }
                            expected = canary_succeeded(outcome)
                            mgmt_mncs = MGMT_MNCS.get(mgmt_state, mgmt_class(mgmt_state))
                            txn_mncs = TXN_MNCS[txn_state]
                            cert_present = cert is not None
                            cert_ok_canary = cert == "CERTIFIED"
                            cases.append(
                                case(
                                    f"canary-restart{int(restart)}-receipt{int(receipt_fail)}"
                                    f"-mgmt{mgmt_state}-txn{txn_state}-cert{cert}-block{int(blocking)}",
                                    "candidate_canary",
                                    [boolean(restart), boolean(receipt_fail),
                                     finite(MODULE, "MgmtClass", mgmt_mncs, MGMT_INDEX[mgmt_mncs]),
                                     finite(MODULE, "TxnClass", txn_mncs, TXN_INDEX[txn_mncs]),
                                     boolean(cert_present), boolean(cert_ok_canary),
                                     boolean(blocking)],
                                    boolean(expected),
                                )
                            )
    for receipt_fail, mgmt_quar, disp_fail, obs, txn_bad in itertools.product(
        (False, True), (False, True), (False, True), OBSERVATIONS, (False, True)
    ):
        outcome = {
            "receipt": {"disposition": "FAIL" if receipt_fail else "PASS"},
            "management": {"state": "QUARANTINED" if mgmt_quar else "READY"},
            "disposition": "FAILED" if disp_fail else "PASS",
            "observation": {"observation": obs} if obs is not None else {},
            "update_transaction": {"state": "FAILED" if txn_bad else "READY"},
        }
        expected = canary_failed(outcome)
        cases.append(
            case(
                f"bad-receipt{int(receipt_fail)}-quar{int(mgmt_quar)}-disp{int(disp_fail)}"
                f"-obs{obs}-txn{int(txn_bad)}",
                "candidate_canary_bad",
                [boolean(receipt_fail), boolean(mgmt_quar), boolean(disp_fail),
                 boolean(obs in BAD_OBSERVATIONS), boolean(txn_bad)],
                boolean(expected),
            )
        )
    document = {"schema_version": "0.1", "name": "fabric-rollout-outcome", "cases": cases}
    out = os.path.join(HERE, "fabric_rollout_outcome_corpus.json")
    with open(out, "w") as handle:
        json.dump(document, handle, indent=1)
        handle.write("\n")
    print(f"wrote {out}: {len(cases)} cases")


if __name__ == "__main__":
    main()
