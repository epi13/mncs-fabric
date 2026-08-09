"""Validation for sanitized operator-controlled physical-host evidence."""

from __future__ import annotations

import re
from typing import Any


_SHA256 = re.compile(r"^sha256:[0-9a-f]{64}$")
_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_COMMIT = re.compile(r"^[0-9a-f]{40}$")


def _identity(value: object, *, bare: bool = False) -> bool:
    return bool((_HEX64 if bare else _SHA256).fullmatch(value)) if isinstance(value, str) else False


def _contains_secret(value: object) -> bool:
    if isinstance(value, dict):
        return any(_contains_secret(key) or _contains_secret(item) for key, item in value.items())
    if isinstance(value, list):
        return any(_contains_secret(item) for item in value)
    if not isinstance(value, str):
        return False
    return "BEGIN PRIVATE KEY" in value or "BEGIN OPENSSH PRIVATE KEY" in value


def validate_two_host_evidence(evidence: object) -> dict[str, Any]:
    """Validate the bounded claims of ``two-host-experiment.v0.1``.

    This checks the sanitized evidence envelope and identity references. It
    does not independently recreate omitted raw records or establish any
    assurance beyond the claims explicitly recorded in the artifact.
    """

    if not isinstance(evidence, dict):
        return {"outcome": "FAIL", "issues": ["evidence must be an object"]}
    issues: list[str] = []
    required = {
        "schema_version", "record_type", "controller_fabric_commit", "worker_fabric_commit",
        "controller_identity", "worker_identity", "controller_certificate_fingerprint",
        "worker_certificate_fingerprint", "node_records", "execution", "challenge", "adversarial",
        "claim_boundary", "limitations",
    }
    issues.extend(f"missing:{field}" for field in sorted(required - evidence.keys()))
    if evidence.get("schema_version") != "mncs-fabric.two-host-experiment.v0.1":
        issues.append("unsupported evidence schema")
    if evidence.get("record_type") != "mncs-fabric.two-host-experiment":
        issues.append("record type is not the Fabric two-host experiment")
    if evidence.get("direct_fabric_tls") is not True or evidence.get("ssh_tunnel_used") is not False:
        issues.append("evidence does not establish direct Fabric TLS without an SSH tunnel")
    if evidence.get("bootstrap_material_staged_by_ssh") is not True:
        issues.append("bootstrap staging limitation is missing")
    for field in ("controller_fabric_commit", "worker_fabric_commit"):
        if not isinstance(evidence.get(field), str) or not _COMMIT.fullmatch(evidence[field]):
            issues.append(f"invalid:{field}")
    if evidence.get("controller_fabric_commit") != evidence.get("worker_fabric_commit"):
        issues.append("controller and worker revisions differ")
    if not isinstance(evidence.get("controller_identity"), str) or not isinstance(evidence.get("worker_identity"), str) or evidence.get("controller_identity") == evidence.get("worker_identity"):
        issues.append("controller and worker logical identities are not distinct")
    for field in ("controller_certificate_fingerprint", "worker_certificate_fingerprint"):
        if not _identity(evidence.get(field)):
            issues.append(f"invalid:{field}")
    if evidence.get("controller_certificate_fingerprint") == evidence.get("worker_certificate_fingerprint"):
        issues.append("controller and worker certificate fingerprints are not distinct")

    nodes = evidence.get("node_records")
    if not isinstance(nodes, dict) or not isinstance(nodes.get("controller"), dict) or not isinstance(nodes.get("worker"), dict):
        issues.append("node records are incomplete")
    else:
        controller_node = nodes["controller"]
        worker_node = nodes["worker"]
        for label, node in (("controller", controller_node), ("worker", worker_node)):
            for field in ("node_fingerprint", "record_id"):
                if not _identity(node.get(field)):
                    issues.append(f"invalid:{label}.{field}")
        if controller_node.get("node_fingerprint") == worker_node.get("node_fingerprint"):
            issues.append("controller and worker node fingerprints are not distinct")

    execution = evidence.get("execution")
    if not isinstance(execution, dict):
        issues.append("execution references are incomplete")
    else:
        for field in ("artifact_manifest_identity", "candidate_identity", "cohort_id", "controller_record_id", "worker_record_id"):
            if not _identity(execution.get(field)):
                issues.append(f"invalid:execution.{field}")
        for field in ("controller_receipt_identity", "worker_receipt_identity"):
            if not _identity(execution.get(field), bare=True):
                issues.append(f"invalid:execution.{field}")
        if execution.get("cohort_outcome") != "PASS":
            issues.append("cohort outcome is not PASS")
        if not isinstance(execution.get("result_identities"), list) or not execution["result_identities"] or not all(_identity(item) for item in execution["result_identities"]):
            issues.append("result identities are incomplete")

    challenge = evidence.get("challenge")
    if not isinstance(challenge, dict) or not all(_identity(challenge.get(field), bare=True) for field in ("challenge_identity", "replay_identity", "replay_store_entry_identity")):
        issues.append("challenge/replay identities are incomplete")
    adversarial = evidence.get("adversarial")
    if not isinstance(adversarial, dict):
        issues.append("adversarial dispositions are missing")
    else:
        if adversarial.get("duplicate_after_restart") != "DUPLICATE_IDEMPOTENT":
            issues.append("worker restart retry was not idempotent")
        if adversarial.get("controller_restart_retry") != "DUPLICATE_IDEMPOTENT":
            issues.append("controller restart retry was not idempotent")
        if adversarial.get("conflicting_replay") != "CONFLICTING_REPLAY":
            issues.append("conflicting replay was not rejected")
        revoked = adversarial.get("revoked_worker")
        if not isinstance(revoked, dict) or revoked.get("disposition") != "FAIL_CLOSED":
            issues.append("revoked worker was not rejected fail-closed")
    boundary = evidence.get("claim_boundary")
    for term in ("no sandbox", "correctness", "custody", "independence", "conformance", "certification"):
        if not isinstance(boundary, str) or term not in boundary.lower():
            issues.append(f"claim boundary omits:{term}")
    if not isinstance(evidence.get("limitations"), list) or not evidence["limitations"]:
        issues.append("limitations are missing")
    if _contains_secret(evidence):
        issues.append("private-key material is present")
    return {"outcome": "PASS" if not issues else "FAIL", "issues": issues}


def validate_persistent_two_host_evidence(evidence: object) -> dict[str, Any]:
    """Validate the bounded persistent-worker physical evidence profile."""

    if not isinstance(evidence, dict):
        return {"outcome": "FAIL", "issues": ["evidence must be an object"]}
    issues: list[str] = []
    if evidence.get("schema_version") != "mncs-fabric.persistent-two-host.v0.1":
        issues.append("unsupported persistent evidence schema")
    if evidence.get("record_type") != "mncs-fabric.persistent-two-host":
        issues.append("record type is not the persistent Fabric experiment")
    if evidence.get("direct_fabric_tls") is not True or evidence.get("ssh_tunnel_used") is not False or evidence.get("bootstrap_material_staged_by_ssh") is not True:
        issues.append("transport/bootstrap boundary is invalid")
    for field in ("controller_fabric_commit", "worker_fabric_commit"):
        if not isinstance(evidence.get(field), str) or not _COMMIT.fullmatch(evidence[field]):
            issues.append(f"invalid:{field}")
    if evidence.get("controller_fabric_commit") != evidence.get("worker_fabric_commit"):
        issues.append("controller and worker revisions differ")
    if not isinstance(evidence.get("controller_identity"), str) or not isinstance(evidence.get("worker_identity"), str) or evidence.get("controller_identity") == evidence.get("worker_identity"):
        issues.append("logical node identities are not distinct")
    nodes = evidence.get("node_records")
    if not isinstance(nodes, dict) or not isinstance(nodes.get("controller"), dict) or not isinstance(nodes.get("worker"), dict):
        issues.append("node records are incomplete")
    else:
        for label in ("controller", "worker"):
            node = nodes[label]
            for field in ("node_fingerprint", "record_id"):
                if not _identity(node.get(field)):
                    issues.append(f"invalid:{label}.{field}")
        if nodes["controller"].get("node_fingerprint") == nodes["worker"].get("node_fingerprint"):
            issues.append("node fingerprints are not distinct")
    service = evidence.get("persistent_service")
    if not isinstance(service, dict) or not isinstance(service.get("max_requests"), int) or service.get("max_requests") < 1 or service.get("max_concurrent_connections") != 1 or service.get("pid_stable") is not True:
        issues.append("persistent service bounds or PID continuity are invalid")
    execution = evidence.get("execution")
    if not isinstance(execution, dict):
        issues.append("execution references are incomplete")
    else:
        for field in ("job_identity", "candidate_identity", "artifact_manifest_identity", "worker_record_id", "cohort_id"):
            if not _identity(execution.get(field)):
                issues.append(f"invalid:execution.{field}")
        if execution.get("cohort_outcome") != "PASS":
            issues.append("cohort outcome is not PASS")
        if not isinstance(execution.get("result_identities"), list) or not execution["result_identities"] or not all(_identity(item) for item in execution["result_identities"]):
            issues.append("result identities are incomplete")
    requests = evidence.get("requests")
    if not isinstance(requests, list) or len(requests) < 6:
        issues.append("persistent request sequence is incomplete")
    else:
        dispositions = [item.get("disposition") for item in requests if isinstance(item, dict)]
        if dispositions.count("EXECUTED") < 4 or "DUPLICATE_IDEMPOTENT" not in dispositions or "CONFLICTING_REPLAY" not in dispositions:
            issues.append("persistent request dispositions are incomplete")
    adversarial = evidence.get("adversarial")
    if not isinstance(adversarial, dict) or adversarial.get("duplicate_request") != "DUPLICATE_IDEMPOTENT" or adversarial.get("conflicting_replay") != "CONFLICTING_REPLAY":
        issues.append("persistent replay dispositions are invalid")
    revoked = adversarial.get("revoked_controller_between_requests") if isinstance(adversarial, dict) else None
    if not isinstance(revoked, dict) or revoked.get("disposition") != "FAIL_CLOSED":
        issues.append("between-request revocation was not rejected fail-closed")
    boundary = evidence.get("claim_boundary")
    for term in ("no sandbox", "correctness", "custody", "independence", "conformance", "certification"):
        if not isinstance(boundary, str) or term not in boundary.lower():
            issues.append(f"claim boundary omits:{term}")
    limitations = evidence.get("limitations")
    if not isinstance(limitations, list) or not limitations or not any("SSH" in str(item) and "transfer" in str(item) for item in limitations):
        issues.append("bundle staging limitation is missing")
    if _contains_secret(evidence):
        issues.append("private-key material is present")
    return {"outcome": "PASS" if not issues else "FAIL", "issues": issues}


def validate_physical_evidence(evidence: object) -> dict[str, Any]:
    if isinstance(evidence, dict) and evidence.get("schema_version") == "mncs-fabric.two-host-experiment.v0.1":
        return validate_two_host_evidence(evidence)
    if isinstance(evidence, dict) and evidence.get("schema_version") == "mncs-fabric.persistent-two-host.v0.1":
        return validate_persistent_two_host_evidence(evidence)
    if isinstance(evidence, dict) and evidence.get("schema_version") == "mncs-fabric.native-bundle-two-host.v0.1":
        return validate_native_bundle_two_host_evidence(evidence)
    return {"outcome": "FAIL", "issues": ["unsupported physical evidence schema"]}


def validate_native_bundle_two_host_evidence(evidence: object) -> dict[str, Any]:
    """Validate sanitized evidence for native bundle transfer."""

    if not isinstance(evidence, dict):
        return {"outcome": "FAIL", "issues": ["evidence must be an object"]}
    issues: list[str] = []
    if evidence.get("record_type") != "mncs-fabric.native-bundle-two-host":
        issues.append("record type is invalid")
    if evidence.get("direct_fabric_tls") is not True or evidence.get("ssh_tunnel_used") is not False or evidence.get("ssh_staged_candidate_material") is not False:
        issues.append("native transport boundary is invalid")
    if not isinstance(evidence.get("fabric_commit"), str) or not _COMMIT.fullmatch(evidence["fabric_commit"]):
        issues.append("fabric commit is invalid")
    if evidence.get("fabric_commit") != evidence.get("worker_fabric_commit"):
        issues.append("controller and worker revisions differ")
    if not isinstance(evidence.get("controller_identity"), str) or evidence.get("controller_identity") == evidence.get("worker_identity"):
        issues.append("logical node identities are not distinct")
    bundle = evidence.get("bundle")
    if not isinstance(bundle, dict) or not _identity(bundle.get("archive_identity")) or not _identity(bundle.get("logical_identity"), bare=True) or bundle.get("transfer_status") not in {"COMMITTED", "ALREADY_PRESENT"}:
        issues.append("native bundle transfer identity or status is invalid")
    try:
        from .contracts import validate_consumer_context
        validate_consumer_context(evidence.get("consumer_context"), error_type=ValueError)
    except (ValueError, TypeError):
        issues.append("consumer context is invalid")
    requests = evidence.get("requests")
    dispositions = [item.get("disposition") for item in requests if isinstance(item, dict)] if isinstance(requests, list) else []
    if dispositions.count("EXECUTED") < 2 or "DUPLICATE_IDEMPOTENT" not in dispositions or "CONFLICTING_REPLAY" not in dispositions:
        issues.append("native request dispositions are incomplete")
    reconciliation = evidence.get("reconciliation")
    if not isinstance(reconciliation, dict) or reconciliation.get("outcome") != "PASS" or not _identity(evidence.get("local_record_identity")) or not _identity(evidence.get("remote_record_identity")):
        issues.append("native reconciliation is incomplete")
    adversarial = evidence.get("adversarial")
    if not isinstance(adversarial, dict) or adversarial.get("revoked_controller", {}).get("disposition") != "FAIL_CLOSED" or adversarial.get("challenge_replay") is not True:
        issues.append("native security dispositions are incomplete")
    boundary = evidence.get("claim_boundary")
    for term in ("no semantic", "sandbox", "correctness", "custody", "independence", "conformance", "certification"):
        if not isinstance(boundary, str) or term not in boundary.lower():
            issues.append(f"claim boundary omits:{term}")
    if not isinstance(evidence.get("limitations"), list) or not evidence["limitations"] or _contains_secret(evidence):
        issues.append("limitations or secret exclusion is invalid")
    return {"outcome": "PASS" if not issues else "FAIL", "issues": issues}
