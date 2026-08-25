"""Rights & Provenance evidence emission for Fabric executions.

Fabric is a primary *producer* of process evidence in the MNCS Rights &
Provenance subsystem. This module projects an execution record (and, when
available, its typed receipt) into a standalone, content-addressed
``mncs-rights-provenance`` evidence record:

    schema_version 0.2.0
    kind           fabric-execution
    evidence_id    mncs-fabric://execution/<record_id>/rights-evidence

Boundary rules preserved here:

- Fabric emits **process observations only**. It never classifies origin on
  its own authority, never decides licensing, and never renders a legal
  conclusion. An ``origin_proposal`` may be attached only when the caller
  explicitly supplies one; it is carried as a claim with the caller's stated
  confidence, not as Fabric's finding.
- The execution record itself is never rewritten. The evidence record
  references it by identity and digest.
- Oversized values are referenced by digest rather than embedded.
"""

from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
from typing import Any

EVIDENCE_SCHEMA_VERSION = "0.2.0"
PRODUCER_NAME = "mncs-fabric"

_LEGAL_LIMITATIONS = [
    "Fabric does not determine copyrightability, authorship, ownership, or licensing.",
    "Origin classifications supplied by callers are process-evidence claims, not conclusions.",
]


def _jcs(value: Any) -> bytes:
    """RFC 8785-compatible canonical encoding (mirrors receipts._mncs_jcs)."""
    if value is None:
        return b"null"
    if value is True:
        return b"true"
    if value is False:
        return b"false"
    if isinstance(value, int) and not isinstance(value, bool):
        return str(value).encode("ascii")
    if isinstance(value, float):
        if value == 0:
            return b"0"
        if value.is_integer():
            return str(int(value)).encode("ascii")
        return repr(value).lower().encode("ascii")
    if isinstance(value, str):
        return json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    if isinstance(value, list):
        return b"[" + b",".join(_jcs(item) for item in value) + b"]"
    if isinstance(value, dict):
        items = sorted(value.items(), key=lambda item: str(item[0]).encode("utf-16-be"))
        return b"{" + b",".join(_jcs(str(key)) + b":" + _jcs(item) for key, item in items) + b"}"
    raise TypeError(f"unsupported canonical JSON value: {type(value).__name__}")


def compute_content_digest(record: dict[str, Any]) -> str:
    reduced = {key: item for key, item in record.items() if key != "content_digest"}
    return "sha256:" + hashlib.sha256(_jcs(reduced)).hexdigest()


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def _artifact_ref(path_result: dict[str, Any], role: str) -> dict[str, Any]:
    ref: dict[str, Any] = {"id": str(path_result.get("path", "artifact")), "role": role}
    sha256_value = path_result.get("sha256")
    if isinstance(sha256_value, str) and len(sha256_value) == 64:
        ref["hash_algorithm"] = "sha256"
        ref["hash_value"] = sha256_value.lower()
    return ref


def build_provenance_evidence(
    record: dict[str, Any],
    *,
    receipt: dict[str, Any] | None = None,
    consumer_context_identity: str | None = None,
    run_id: str | None = None,
    task_id: str | None = None,
    parent_evidence_ids: list[str] | None = None,
    origin_proposal: dict[str, Any] | None = None,
    rights_manifest_reference: str | None = None,
) -> dict[str, Any]:
    """Project one execution into a rights/provenance evidence record.

    ``record`` is an ``mncs-fabric.execution-record.v0.1`` document. ``receipt``
    is the optional typed ``mncs-execution-receipt`` companion.

    ``origin_proposal``, when supplied by the caller, must be a mapping with
    ``classification`` and ``confidence`` keys; it becomes a claim attributed to
    the caller, never to Fabric.
    """

    record_id = record.get("record_id")
    if not isinstance(record_id, str) or not record_id:
        raise ValueError("execution record requires its record_id")

    results = record.get("results")
    artifact_refs: list[dict[str, Any]] = []
    if isinstance(results, list):
        artifact_refs.extend(
            _artifact_ref(item, "output") for item in results if isinstance(item, dict)
        )

    resolved_executable = record.get("resolved_executable")
    if isinstance(resolved_executable, str) and resolved_executable:
        artifact_refs.append({"id": resolved_executable, "role": "input"})

    subject: dict[str, Any] = {"artifact_refs": artifact_refs or [{"id": record_id, "role": "subject"}]}
    if run_id:
        subject["run_id"] = run_id
    if task_id:
        subject["task_id"] = task_id
    if parent_evidence_ids:
        subject["parent_evidence_ids"] = list(parent_evidence_ids)

    observations: list[dict[str, Any]] = [
        {"name": "outcome", "value": record.get("outcome", "UNKNOWN")},
        {"name": "termination_reason", "value": record.get("termination_reason")},
        {"name": "exit_code", "value": record.get("exit_code")},
    ]
    job_identity = record.get("job_identity")
    if isinstance(job_identity, str) and job_identity:
        observations.append({"name": "job_identity", "value": job_identity})
    candidate_identity = record.get("candidate_identity")
    if isinstance(candidate_identity, str) and candidate_identity:
        observations.append({"name": "candidate_identity", "value": candidate_identity})
    node = record.get("node")
    if isinstance(node, dict):
        fingerprint = node.get("node_fingerprint")
        if isinstance(fingerprint, str) and fingerprint:
            observations.append({"name": "node_fingerprint", "value": fingerprint})
    declared_argv = record.get("declared_argv")
    if isinstance(declared_argv, list) and declared_argv:
        observations.append(
            {
                "name": "declared_argv_digest",
                "value_digest": "sha256:" + hashlib.sha256(_jcs(declared_argv)).hexdigest(),
            }
        )
    started_at = record.get("started_at")
    finished_at = record.get("finished_at")
    duration_ms = record.get("duration_ms")

    references: list[dict[str, Any]] = []
    record_identity = record.get("identity") or record.get("record_sha256")
    if isinstance(record_identity, str) and record_identity:
        references.append({"kind": "fabric-execution-record", "reference": record_identity})
    else:
        references.append(
            {
                "kind": "fabric-execution-record",
                "reference": record_id,
                "sha256": hashlib.sha256(_jcs(record)).hexdigest(),
            }
        )
    if receipt is not None:
        receipt_identity = receipt.get("receipt_identity")
        if isinstance(receipt_identity, str) and receipt_identity:
            references.append(
                {"kind": "fabric-receipt", "reference": "sha256:" + receipt_identity}
            )
    if consumer_context_identity:
        references.append({"kind": "external-record", "reference": consumer_context_identity})
    if rights_manifest_reference:
        references.append({"kind": "external-record", "reference": rights_manifest_reference})

    claims: list[dict[str, Any]] = []
    if origin_proposal is not None:
        classification = origin_proposal.get("classification")
        confidence = origin_proposal.get("confidence", "low")
        if classification not in {
            "human-authored",
            "human-ai-assisted",
            "human-directed-machine-generated",
            "autonomous-machine-generated",
            "mixed-machine-origin",
            "third-party-derived",
            "generated-from-licensed-source",
            "generated-from-public-domain-source",
            "origin-uncertain",
        }:
            raise ValueError(f"unsupported origin classification: {classification!r}")
        claims.append(
            {
                "claim_type": "origin-classification-proposal",
                "statement": (
                    f"Caller proposed origin classification {classification!r} "
                    "for this execution's outputs."
                ),
                "confidence": confidence,
                "value": classification,
            }
        )
    else:
        claims.append(
            {
                "claim_type": "other",
                "statement": (
                    "No origin classification asserted by Fabric; outputs are "
                    "process evidence awaiting downstream rights evaluation."
                ),
                "confidence": "insufficient-evidence",
            }
        )

    evidence: dict[str, Any] = {
        "schema_version": EVIDENCE_SCHEMA_VERSION,
        "evidence_id": f"mncs-fabric://execution/{record_id}/rights-evidence",
        "kind": "fabric-execution",
        "producer": {
            "producer": PRODUCER_NAME,
            "recordKind": "RightsProvenanceEvidence",
            "schemaVersion": EVIDENCE_SCHEMA_VERSION,
            "stableId": f"mncs-fabric://execution/{record_id}/rights-evidence",
        },
        "subject": subject,
        "observations": [
            item
            for item in observations
            if item.get("value") is not None or "value_digest" in item
        ],
        "claims": claims,
        "references": references,
        "limitations": list(_LEGAL_LIMITATIONS),
    }
    context: dict[str, Any] = {}
    if isinstance(started_at, str) and started_at:
        context["timestamp"] = started_at
    else:
        context["timestamp"] = _utc_now()
    if isinstance(duration_ms, int):
        context["duration_ms"] = duration_ms
    environment_identity = record.get("environment_identity")
    if isinstance(environment_identity, str) and environment_identity:
        context["environment_identity"] = environment_identity
    if context:
        evidence["context"] = context

    evidence["content_digest"] = compute_content_digest(evidence)
    return evidence


def verify_provenance_evidence(evidence: dict[str, Any]) -> tuple[bool, str]:
    declared = evidence.get("content_digest")
    expected = compute_content_digest(evidence)
    return declared == expected, expected


__all__ = [
    "EVIDENCE_SCHEMA_VERSION",
    "build_provenance_evidence",
    "compute_content_digest",
    "verify_provenance_evidence",
]
