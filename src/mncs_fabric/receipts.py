"""Adapters from Fabric observations to the MNCS experimental receipt family.

The adapter is deliberately one-way and companion-record based. It does not
reinterpret ``mncs-fabric.execution-record.v0.1`` or create an assurance claim.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
import hashlib
import json
import math
from typing import Any

from .canonical import sha256_identity

RECEIPT_SCHEMA = "0.1-experimental"
RECEIPT_TYPE = "mncs-execution-receipt"
ASSURANCE_SCHEMA = "0.1"
ASSURANCE_TYPE = "mncs-execution-assurance"


def _raw(value: object) -> str:
    if isinstance(value, str) and value.startswith("sha256:"):
        return value[7:]
    if isinstance(value, str) and len(value) == 64 and all(char in "0123456789abcdef" for char in value):
        return value
    return "0" * 64


def _id(prefix: str, value: object) -> str:
    return prefix + _raw(value)


def _mncs_jcs(value: object) -> bytes:
    """Small RFC 8785-compatible encoder for the receipt JSON value types.

    Receipt keys are ASCII and all adapter numbers are finite bounded values;
    keeping this narrow avoids adding a runtime dependency solely for the
    external identity projection.
    """

    if value is None:
        return b"null"
    if value is True:
        return b"true"
    if value is False:
        return b"false"
    if isinstance(value, int) and not isinstance(value, bool):
        return str(value).encode("ascii")
    if isinstance(value, float):
        if not math.isfinite(value):
            raise ValueError("non-finite receipt number")
        if value == 0:
            return b"0"
        if value.is_integer():
            return str(int(value)).encode("ascii")
        text = repr(value).lower()
        if "e" in text:
            mantissa, exponent = text.split("e")
            sign = "+" if not exponent.startswith("-") else "-"
            exponent = exponent.lstrip("+-0") or "0"
            text = mantissa + "e" + sign + exponent
        return text.encode("ascii")
    if isinstance(value, str):
        return json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    if isinstance(value, list):
        return b"[" + b",".join(_mncs_jcs(item) for item in value) + b"]"
    if isinstance(value, dict):
        items = sorted(value.items(), key=lambda item: item[0].encode("utf-16-be"))
        return b"{" + b",".join(_mncs_jcs(str(key)) + b":" + _mncs_jcs(item) for key, item in items) + b"}"
    raise TypeError(f"unsupported receipt value: {type(value).__name__}")


def _mncs_sha256(value: object) -> str:
    return hashlib.sha256(_mncs_jcs(value)).hexdigest()


def _time(value: object, fallback: datetime) -> datetime:
    if isinstance(value, str):
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
            if parsed.tzinfo is not None and parsed.utcoffset() is not None:
                return parsed.astimezone(timezone.utc)
        except ValueError:
            pass
    return fallback


def _iso(value: datetime) -> str:
    return value.isoformat().replace("+00:00", "Z")


def execution_policy_identity_for_plan(plan: dict[str, Any]) -> str:
    """Return the raw EA-NEXT-compatible policy identity used by the adapter."""
    policy = plan.get("network_policy")
    argv = plan.get("argv") if isinstance(plan.get("argv"), list) else []
    # Preserve the existing receipt adapter's v0.2 projection: a Fabric
    # execution record carries the requested timeout separately, while the
    # policy identity only includes an observed termination timeout when that
    # companion observation exists.
    return _raw(sha256_identity({"network_policy": policy, "argv": argv, "timeout": None}))


def _stream(value: object, limit: int | None) -> dict[str, Any]:
    stream = value if isinstance(value, dict) else {}
    text = stream.get("captured_utf8") if isinstance(stream.get("captured_utf8"), str) else ""
    total = stream.get("bytes") if isinstance(stream.get("bytes"), int) else 0
    truncated = bool(stream.get("truncated", False))
    return {
        "total_bytes": max(0, total),
        "retained_bytes": len(text.encode("utf-8")),
        "retained_sha256": None,
        "complete_sha256": _raw(stream.get("sha256")) if isinstance(stream.get("sha256"), str) else None,
        "truncated": truncated,
        "limit_hit": truncated,
        "limit_bytes": limit,
    }


def _termination(record: dict[str, Any]) -> tuple[str, int | None, str | None, str | None]:
    reason = record.get("termination_reason")
    code = record.get("exit_code") if isinstance(record.get("exit_code"), int) else None
    mapping = {
        "TIMEOUT": "timeout",
        "OUTPUT_LIMIT": "output-limit",
        "PROCESS_UNTERMINATED": "internal-runner-error",
        "OUTPUT_CAPTURE_ERROR": "internal-runner-error",
        "CAPABILITY_UNAVAILABLE": "policy-rejected",
        "PLAN_INVALID": "policy-rejected",
        "INTEGRITY_FAILURE": "policy-rejected",
    }
    if reason in mapping:
        category = mapping[reason]
    elif isinstance(code, int) and code < 0:
        category = "signal"
    elif reason == "NONZERO_EXIT":
        category = "nonzero-exit"
    elif reason == "COMPLETED":
        category = "completed" if code == 0 else "nonzero-exit"
    else:
        category = "internal-runner-error"
    return category, abs(code) if category == "signal" and code is not None else None, None, reason if category == "internal-runner-error" else None


def _subject(record: dict[str, Any], *, family: str, kind: str) -> dict[str, Any]:
    candidate = record.get("candidate_identity")
    return {
        "family": family,
        "kind": kind,
        "record_id": _id("fabric-job-", record.get("job_identity")),
        "canonical_sha256": _raw(candidate),
        "candidate_id": _id("candidate-", candidate) if candidate else None,
    }


def build_execution_receipt(
    record: dict[str, Any],
    *,
    subject_family: str = "MNCS",
    subject_kind: str = "development-record",
    runner_identity: str = "mncs-fabric-local-runner-v1",
    runner_version: str = "0.2.0a2",
    placement_reference: dict[str, Any] | None = None,
    challenge: dict[str, Any] | None = None,
    bundle_identity: str | None = None,
    archive_identity: str | None = None,
) -> dict[str, Any]:
    """Build the current experimental MNCS typed receipt from one Fabric record."""

    baseline = datetime(1970, 1, 1, tzinfo=timezone.utc)
    started = _time(record.get("started_at"), baseline)
    finished = _time(record.get("finished_at"), started + timedelta(milliseconds=1))
    if finished <= started:
        finished = started + timedelta(milliseconds=1)
    rejected = record.get("termination_reason") in {"PLAN_INVALID", "INTEGRITY_FAILURE", "CAPABILITY_UNAVAILABLE"}
    category, signal, resource_name, internal_reason = _termination(record)
    if rejected:
        category = "policy-rejected"
    challenge_issued = started
    # The challenge is a deterministic binding window, not a freshness claim;
    # keep it open long enough for an offline validator to inspect the record.
    challenge_expires = max(finished, challenge_issued + timedelta(seconds=1)) + timedelta(hours=1)
    receipt_seed = {
        "record_id": record.get("record_id"),
        "job_identity": record.get("job_identity"),
        "candidate_identity": record.get("candidate_identity"),
        "artifact_manifest_identity": record.get("artifact_manifest_identity"),
    }
    nonce = "fabric-" + _raw(sha256_identity(receipt_seed))[:48]
    node = record.get("node") if isinstance(record.get("node"), dict) else {}
    executable_identity = record.get("resolved_executable_identity")
    runtime_identity = node.get("python_executable_identity")
    argv = record.get("declared_argv") if isinstance(record.get("declared_argv"), list) else []
    result_values = record.get("results") if isinstance(record.get("results"), list) else []
    result_identity = _raw(result_values[0].get("sha256")) if result_values and isinstance(result_values[0], dict) else None
    artifacts = [
        {"identity": _raw(item.get("sha256")), "kind": "declared-result:" + str(item.get("path")), "size_bytes": int(item.get("size", 0)), "retained": True}
        for item in result_values if isinstance(item, dict) and isinstance(item.get("sha256"), str)
    ]
    environment_identity = _id("environment-", sha256_identity({"node": node.get("node_fingerprint"), "environment": record.get("declared_environment", {}), "network_policy": record.get("policy_observations", {}).get("network_policy") if isinstance(record.get("policy_observations"), dict) else None}))
    policy_identity = _raw(sha256_identity({"network_policy": record.get("policy_observations", {}).get("network_policy") if isinstance(record.get("policy_observations"), dict) else None, "argv": argv, "timeout": record.get("termination_observations", {}).get("timeout_seconds") if isinstance(record.get("termination_observations"), dict) else None}))
    outcome = record.get("outcome") if record.get("outcome") in {"PASS", "FAIL", "UNKNOWN"} else "UNKNOWN"
    execution_status = outcome if not rejected else "UNKNOWN"
    challenge_observation = {
        "nonce": nonce,
        "issued_at": _iso(challenge_issued),
        "expires_at": _iso(challenge_expires),
    }
    if isinstance(challenge, dict):
        challenge_observation = {key: challenge[key] for key in ("nonce", "issued_at", "expires_at") if key in challenge}
    receipt: dict[str, Any] = {
        "schema_version": RECEIPT_SCHEMA,
        "record_type": RECEIPT_TYPE,
        "record_id": _id("fabric-execution-", record.get("record_id")),
        "receipt_identity": None,
        "subject": _subject(record, family=subject_family, kind=subject_kind),
        "bundle": {"test_bundle_identity": _raw(bundle_identity if bundle_identity is not None else record.get("artifact_manifest_identity")), "harness_identity": _raw(executable_identity) if executable_identity else None, "input_snapshot_identity": None},
        "policy": {"execution_policy_identity": policy_identity, "placement_policy_identity": None, "requested_limits": [{"resource": "timeout", "value": float(record.get("timeout_seconds", 0) or 0), "unit": "seconds"}] if record.get("timeout_seconds") else [], "result_semantics": "Fabric records declared result artifact identities; project evaluators define semantic result meaning."},
        "runner": {"runner_identity": runner_identity, "runner_version": runner_version, "executable_identity": _raw(executable_identity) if executable_identity else None, "runtime_identity": _id("runtime-", runtime_identity) if runtime_identity else "runtime-unknown", "command_identity": _raw(sha256_identity(argv))},
        "environment": {"environment_identity": environment_identity},
        "challenge": challenge_observation,
        "request": {"status": "rejected" if rejected else "accepted", "observed_at": _iso(challenge_issued)},
        "lifecycle": {"started_at": None if rejected else _iso(started), "ended_at": None if rejected else _iso(finished), "duration_seconds": None if rejected else max(0.0, (finished - started).total_seconds()), "termination_category": category},
        "process": {"exit_code": None if rejected else record.get("exit_code"), "signal": signal, "harness_status": "UNKNOWN" if rejected else outcome, "result_identity": result_identity},
        "termination_observations": {"timeout_seconds": float(record.get("timeout_seconds")) if category == "timeout" and record.get("timeout_seconds") is not None else None, "resource_name": resource_name or internal_reason},
        "streams": {"stdout": _stream(record.get("stdout"), record.get("output_limit_bytes")), "stderr": _stream(record.get("stderr"), record.get("output_limit_bytes"))},
        "aggregate_output": {"total_bytes": sum(item.get("bytes", 0) for item in (record.get("stdout"), record.get("stderr")) if isinstance(item, dict)), "retained_bytes": sum(len(item.get("captured_utf8", "").encode("utf-8")) for item in (record.get("stdout"), record.get("stderr")) if isinstance(item, dict)), "limit_bytes": record.get("output_limit_bytes"), "limit_hit": category == "output-limit"},
        "artifacts": artifacts,
        "resources": [{"metric": "wall-duration", "value": max(0.0, (finished - started).total_seconds()), "unit": "seconds", "source_identity": runner_identity, "phase": "whole-execution"}],
        "enforcement": {"command_binding": "enforced", "environment_binding": "unknown", "filesystem_restriction": "unknown", "network_restriction": "unknown", "process_restriction": "unknown", "resource_limits": "enforced" if category in {"completed", "nonzero-exit", "timeout", "output-limit"} else "unknown", "test_bundle_integrity": "enforced" if record.get("artifact_manifest_identity") else "unknown", "result_integrity": "enforced" if result_values else "unknown"},
        "placement": {"execution_placement_reference": placement_reference},
        "claim_boundary": {"conformance": "not-asserted", "correctness": "not-asserted", "security": "not-asserted", "sandbox": "not-asserted", "independence": "not-asserted", "protected_custody": "not-asserted", "promotion": "not-asserted"},
        "extensions": {"mncs-fabric:execution-record-identity": record.get("record_id"), "mncs-fabric:execution-outcome": execution_status, "mncs-fabric:node-label": node.get("machine_label", "unknown")},
    }
    if isinstance(challenge, dict) and isinstance(challenge.get("challenge_identity"), str):
        receipt["extensions"]["mncs-fabric:challenge-identity"] = challenge["challenge_identity"]
    if archive_identity is not None:
        receipt["extensions"]["mncs-fabric:archive-identity"] = archive_identity
    receipt["receipt_identity"] = _mncs_sha256({key: value for key, value in receipt.items() if key != "receipt_identity"})
    return receipt


def verify_execution_receipt(value: object) -> dict[str, Any]:
    """Verify a Fabric-produced experimental receipt without adding authority."""

    if not isinstance(value, dict) or value.get("schema_version") != RECEIPT_SCHEMA or value.get("record_type") != RECEIPT_TYPE:
        return {"outcome": "FAIL", "reason": "unsupported execution receipt schema"}
    identity = value.get("receipt_identity")
    if not isinstance(identity, str) or len(identity) != 64 or any(char not in "0123456789abcdef" for char in identity):
        return {"outcome": "FAIL", "reason": "receipt identity is malformed"}
    expected = _mncs_sha256({key: item for key, item in value.items() if key != "receipt_identity"})
    if identity != expected:
        return {"outcome": "FAIL", "reason": "receipt identity does not verify"}
    boundary = value.get("claim_boundary")
    if not isinstance(boundary, dict) or boundary.get("conformance") != "not-asserted":
        return {"outcome": "FAIL", "reason": "receipt claim boundary is missing"}
    return {"outcome": "PASS", "identity": identity}


def build_execution_assurance(receipt: dict[str, Any]) -> dict[str, Any]:
    """Build the companion assurance shape without upgrading UNKNOWN facts."""

    enforcement = receipt["enforcement"]
    status = receipt["extensions"].get("mncs-fabric:execution-outcome", "UNKNOWN")
    properties = {
        "command_bound": "PASS" if enforcement["command_binding"] == "enforced" else "UNKNOWN",
        "environment_bound": "UNKNOWN",
        "filesystem_isolation": "UNKNOWN",
        "network_isolation": "UNKNOWN",
        "process_isolation": "UNKNOWN",
        "resource_limits": "PASS" if enforcement["resource_limits"] == "enforced" else "UNKNOWN",
        "test_integrity": "PASS" if enforcement["test_bundle_integrity"] == "enforced" else "UNKNOWN",
        "result_integrity": "PASS" if enforcement["result_integrity"] == "enforced" else "UNKNOWN",
        "host_root_resistance": "UNKNOWN",
        "protected_custody": "UNKNOWN",
        "independent_operation": "UNKNOWN",
    }
    declared = "FAIL" if status == "FAIL" else "UNKNOWN" if "UNKNOWN" in properties.values() or status == "UNKNOWN" else "PASS"
    assurance = {
        "schema_version": ASSURANCE_SCHEMA,
        "record_type": ASSURANCE_TYPE,
        "record_id": _id("fabric-assurance-", receipt["receipt_identity"]),
        "subject": receipt["subject"],
        "test_result": {"status": status, "result_identity": receipt["receipt_identity"], "summary": "Fabric execution outcome is preserved separately from assurance."},
        "execution": {"test_bundle_identity": receipt["bundle"]["test_bundle_identity"], "policy_identity": receipt["policy"]["execution_policy_identity"], "runner_identity": receipt["runner"]["runner_identity"], "environment_identity": receipt["environment"]["environment_identity"], "challenge": receipt["challenge"], "properties": properties, "attestation": {"kind": "none", "identity": None, "signer_id": None, "verified": False, "fresh": False}},
        "required_properties": list(properties),
        "declared_assurance_status": declared,
        "execution_receipt": {"record_id": receipt["record_id"], "identity": receipt["receipt_identity"]},
        "limitations": ["Fabric did not establish sandboxing, network isolation, protected custody, attestation, independent evaluation, or conformance."],
        "extensions": {"mncs-fabric:source-receipt": receipt["receipt_identity"]},
    }
    return assurance
