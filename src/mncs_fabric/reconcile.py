from __future__ import annotations

from typing import Any, Iterable

from .canonical import attach_identity, verify_identity
from .errors import ValidationError
from .models import COHORT_SCHEMA, EXECUTION_SCHEMA


def _record_label(record: dict[str, Any]) -> str:
    node = record.get("node")
    return node.get("machine_label", "<unknown>") if isinstance(node, dict) else "<unknown>"


def reconcile_records(values: Iterable[Any], *, require_distinct_nodes: bool = True) -> dict[str, Any]:
    records = list(values)
    if not records:
        raise ValidationError("at least one execution record is required")
    reasons: list[str] = []
    valid_records: list[dict[str, Any]] = []
    for index, value in enumerate(records):
        if not isinstance(value, dict) or value.get("schema_version") != EXECUTION_SCHEMA:
            reasons.append(f"record[{index}] has an unsupported schema")
            continue
        if not verify_identity(value, "record_id"):
            reasons.append(f"record[{index}] identity does not verify")
            continue
        valid_records.append(value)
    if len(valid_records) != len(records):
        outcome = "FAIL"
    else:
        identity_fields = ("job_identity", "candidate_identity", "evaluator_identity", "artifact_manifest_identity")
        for field in identity_fields:
            values_for_field = {record.get(field) for record in valid_records}
            if len(values_for_field) != 1:
                reasons.append(f"records disagree on {field}")
        labels = [_record_label(record) for record in valid_records]
        if require_distinct_nodes and len(set(labels)) != len(labels):
            reasons.append("cohort contains duplicate machine labels")
        if reasons:
            outcome = "FAIL"
        elif any(record["outcome"] == "FAIL" for record in valid_records):
            outcome = "FAIL"
            reasons.append("one or more executions returned FAIL")
        elif any(record["outcome"] != "PASS" for record in valid_records):
            outcome = "UNKNOWN"
            reasons.append("one or more executions did not complete with PASS")
        else:
            result_vectors = [
                tuple((entry["path"], entry["size"], entry["sha256"]) for entry in record.get("results", []))
                for record in valid_records
            ]
            if len(set(result_vectors)) != 1:
                outcome = "FAIL"
                reasons.append("declared result artifacts disagree across records")
            else:
                outcome = "PASS"
                reasons.append("all verified records agree on declared result artifacts")
    labels = [_record_label(record) for record in valid_records]
    result = {
        "schema_version": COHORT_SCHEMA,
        "job_identity": valid_records[0].get("job_identity") if valid_records else None,
        "candidate_identity": valid_records[0].get("candidate_identity") if valid_records else None,
        "evaluator_identity": valid_records[0].get("evaluator_identity") if valid_records else None,
        "artifact_manifest_identity": valid_records[0].get("artifact_manifest_identity") if valid_records else None,
        "record_identities": [record["record_id"] for record in valid_records],
        "machine_labels": labels,
        "record_count": len(records),
        "outcome": outcome,
        "reasons": reasons,
        "evidence_class": "LOCAL_REPRODUCTION" if len(records) == 1 else "OPERATOR_CONTROLLED_CROSS_HOST",
        "independent_evaluation": "UNKNOWN",
        "protected_custody": "UNKNOWN",
        "limitations": [
            "A shared operator controls the controller and participating machines.",
            "A cohort PASS does not establish organizational independence, protected holdout, or formal MNCS conformance.",
        ],
    }
    return attach_identity(result, "cohort_id")
