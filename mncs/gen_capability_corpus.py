#!/usr/bin/env python3
"""Generate the exhaustive execution corpus for mncs/worker_capability.mncs.

Reads the Python resolution tables (the current runtime authority) and
emits every decision arm as an MNCS ExecutionCorpus. `mncs experiment run`
executes the compiled module; `tests/test_mncs_capability_policy.py`
asserts the execution agrees with Python on every case.

Run from the repository root: python3 mncs/gen_capability_corpus.py
"""

import json
import os
import sys
import urllib.parse

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, os.path.join(ROOT, "src"))

from mncs_fabric.capability_resolution import (  # noqa: E402
    freshness_of,
    intent_allowed,
    is_eligible,
    provenance_trusted,
    resolve_code,
)

MODULE = "fabric.worker_capability"
MAX_AGE = 300

LIVENESS = ["Available", "Unavailable", "Disconnected"]
FRESHNESS = ["Fresh", "Stale"]
PROVENANCE = ["WorkerObserved", "OperatorAsserted", "ConsumerDeclared"]
INTENTS = ["Normal", "Mutating", "Privileged"]
CODES = [
    "Eligible",
    "CapabilityUnsatisfied",
    "PolicyDenied",
    "ProvenanceUnverified",
    "WorkerStale",
    "WorkerUnavailable",
    "WorkerDisconnected",
]

POLICIES = {
    "stable": {
        "experimental": False,
        "disposable": False,
        "allow_root_mutation": False,
        "allow_reboot": False,
        "allow_toolchain_install": False,
        "resource_constrained": False,
    },
    "experimental-bare": {
        "experimental": True,
        "disposable": False,
        "allow_root_mutation": False,
        "allow_reboot": False,
        "allow_toolchain_install": False,
        "resource_constrained": False,
    },
    "experimental-toolchain": {
        "experimental": True,
        "disposable": False,
        "allow_root_mutation": False,
        "allow_reboot": False,
        "allow_toolchain_install": True,
        "resource_constrained": False,
    },
    "experimental-root": {
        "experimental": True,
        "disposable": True,
        "allow_root_mutation": True,
        "allow_reboot": True,
        "allow_toolchain_install": True,
        "resource_constrained": False,
    },
    "experimental-reboot-only": {
        "experimental": True,
        "disposable": False,
        "allow_root_mutation": False,
        "allow_reboot": True,
        "allow_toolchain_install": False,
        "resource_constrained": False,
    },
    "constrained-toolchain": {
        "experimental": True,
        "disposable": False,
        "allow_root_mutation": False,
        "allow_reboot": False,
        "allow_toolchain_install": True,
        "resource_constrained": True,
    },
}


def finite(type_name, variant_name, discriminant):
    return {
        "finite": {
            "type_identity": f"mncs:0.2:finite-type:{MODULE}::{type_name}",
            "variant_identity": f"mncs:0.2:finite-variant:{MODULE}::{type_name}::{variant_name}",
            "discriminant": discriminant,
        }
    }


def boolean(value):
    return {"boolean": {"value": value}}


def integer(value):
    return {"integer": {"value": value, "type": {"bits": 64, "signed": True}}}


def policy_record(name):
    values = POLICIES[name]
    field_types = sorted((key, "bool") for key in values)
    joined = "".join(f"{n}:{t};" for n, t in field_types)
    return {
        "record": {
            "type_identity": f"mncs:0.2:record-type:{MODULE}::WorkerPolicy::{urllib.parse.quote(joined, safe='')}",
            "name": "WorkerPolicy",
            "fields": [[key, boolean(values[key])] for key, _ in field_types],
        }
    }


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


def liveness_arg(name):
    return finite("Liveness", name, LIVENESS.index(name))


def freshness_arg(name):
    return finite("Freshness", name, FRESHNESS.index(name))


def provenance_arg(name):
    return finite("Provenance", name, PROVENANCE.index(name))


def intent_arg(name):
    return finite("WorkloadIntent", name, INTENTS.index(name))


def code_arg(name):
    return finite("ResolutionCode", name, CODES.index(name))


PROVENANCE_PY = {
    "WorkerObserved": "worker-observed",
    "OperatorAsserted": "operator-asserted",
    "ConsumerDeclared": "consumer-declared",
}
LIVENESS_PY = {
    "Available": "AVAILABLE",
    "Unavailable": "UNAVAILABLE",
    "Disconnected": "DISCONNECTED",
}
FRESHNESS_PY = {"Fresh": "fresh", "Stale": "stale"}
INTENT_PY = {"Normal": "normal", "Mutating": "mutating", "Privileged": "privileged"}
CODE_PY = {
    "Eligible": "ELIGIBLE",
    "CapabilityUnsatisfied": "CAPABILITY_UNSATISFIED",
    "PolicyDenied": "POLICY_DENIED",
    "ProvenanceUnverified": "PROVENANCE_UNVERIFIED",
    "WorkerStale": "WORKER_STALE",
    "WorkerUnavailable": "WORKER_UNAVAILABLE",
    "WorkerDisconnected": "WORKER_DISCONNECTED",
}
CODE_MNCS = {value: key for key, value in CODE_PY.items()}


def main():
    cases = []
    for name in PROVENANCE:
        cases.append(
            case(
                f"provenance-{name.lower()}",
                "candidate_provenance",
                [provenance_arg(name)],
                boolean(provenance_trusted(PROVENANCE_PY[name])),
            )
        )
    for age in (-3600, -1, 0, 1, MAX_AGE - 1, MAX_AGE, MAX_AGE + 1, 10**6):
        fresh = freshness_of(float(age), MAX_AGE)
        cases.append(
            case(
                f"freshness-age-{age}",
                "candidate_freshness",
                [integer(age), integer(MAX_AGE)],
                freshness_arg("Fresh" if fresh == "fresh" else "Stale"),
            )
        )
    for policy_name in POLICIES:
        for intent in INTENTS:
            allowed = intent_allowed(POLICIES[policy_name], INTENT_PY[intent])
            cases.append(
                case(
                    f"intent-{policy_name}-{intent.lower()}",
                    "candidate_intent",
                    [policy_record(policy_name), intent_arg(intent)],
                    boolean(allowed),
                )
            )
    for live in LIVENESS:
        for fresh in FRESHNESS:
            for prov in (True, False):
                for env in (True, False):
                    for intent_ok in (True, False):
                        code = resolve_code(
                            liveness=LIVENESS_PY[live],
                            freshness=FRESHNESS_PY[fresh],
                            provenance_ok=prov,
                            env_ok=env,
                            intent_ok=intent_ok,
                        )
                        cases.append(
                            case(
                                f"resolve-{live.lower()}-{fresh.lower()}-prov{int(prov)}-env{int(env)}-intent{int(intent_ok)}",
                                "candidate_resolve",
                                [
                                    liveness_arg(live),
                                    freshness_arg(fresh),
                                    boolean(prov),
                                    boolean(env),
                                    boolean(intent_ok),
                                ],
                                code_arg(CODE_MNCS[code]),
                            )
                        )
    for code in CODES:
        cases.append(
            case(
                f"eligible-{code.lower()}",
                "candidate_eligible",
                [code_arg(code)],
                boolean(is_eligible(CODE_PY[code])),
            )
        )
    document = {
        "schema_version": "0.1",
        "name": "fabric-worker-capability-exhaustive",
        "cases": cases,
    }
    out = os.path.join(HERE, "worker_capability_corpus.json")
    with open(out, "w") as handle:
        json.dump(document, handle, indent=1)
        handle.write("\n")
    print(f"wrote {out}: {len(cases)} cases")


if __name__ == "__main__":
    main()
