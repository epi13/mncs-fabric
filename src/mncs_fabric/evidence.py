"""Validation for sanitized operator-controlled physical-host evidence."""

from __future__ import annotations

import re
from typing import Any

from .errors import FabricError


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
    if isinstance(evidence, dict) and evidence.get("schema_version") == "mncs-fabric.physical-worker-state.v0.1":
        return validate_physical_worker_state_evidence(evidence)
    if isinstance(evidence, dict) and evidence.get("schema_version") == "mncs-fabric.windows-gpu-worker.v0.1":
        return validate_windows_gpu_evidence(evidence)
    if isinstance(evidence, dict) and evidence.get("schema_version") == "mncs-fabric.heterogeneous-cross-os.v0.1":
        return validate_heterogeneous_cross_os_evidence(evidence)
    if isinstance(evidence, dict) and evidence.get("schema_version") == "mncs-fabric.windows-sequential-offload.v0.1":
        return validate_windows_sequential_offload_evidence(evidence)
    if isinstance(evidence, dict) and evidence.get("schema_version") == "mncs-fabric.three-node-heterogeneous.v0.1":
        return validate_three_node_heterogeneous_evidence(evidence)
    if isinstance(evidence, dict) and evidence.get("schema_version") == "mncs-fabric.heterogeneous-fault-profiles.v0.1":
        return validate_heterogeneous_fault_profile_evidence(evidence)
    if isinstance(evidence, dict) and evidence.get("schema_version") == "mncs-fabric.raspberry-pi-preflight.v0.1":
        return validate_raspberry_pi_preflight_evidence(evidence)
    return {"outcome": "FAIL", "issues": ["unsupported physical evidence schema"]}


def _validate_claim_boundary(evidence: dict[str, Any], issues: list[str]) -> None:
    boundary = evidence.get("claim_boundary")
    for term in ("operator-controlled", "attestation", "correctness", "custody", "independence", "conformance"):
        if not isinstance(boundary, str) or term not in boundary.lower():
            issues.append(f"claim boundary omits:{term}")
    if not isinstance(evidence.get("limitations"), list) or not evidence["limitations"]:
        issues.append("limitations are missing")
    if _contains_secret(evidence):
        issues.append("private-key material is present")


def validate_windows_gpu_evidence(evidence: object) -> dict[str, Any]:
    """Validate sanitized evidence for one physically proven Windows GPU worker."""

    if not isinstance(evidence, dict):
        return {"outcome": "FAIL", "issues": ["evidence must be an object"]}
    issues: list[str] = []
    if evidence.get("schema_version") != "mncs-fabric.windows-gpu-worker.v0.1":
        issues.append("unsupported Windows GPU evidence schema")
    if evidence.get("record_type") != "mncs-fabric.windows-gpu-worker":
        issues.append("record type is invalid")
    if evidence.get("direct_fabric_tls") is not True or evidence.get("ssh_tunnel_used") is not False or evidence.get("ssh_staged_candidate_material") is not False:
        issues.append("Fabric/SSH execution boundary is invalid")
    for field in ("fabric_commit", "worker_fabric_commit"):
        if not isinstance(evidence.get(field), str) or not _COMMIT.fullmatch(evidence[field]):
            issues.append(f"invalid:{field}")
    if evidence.get("fabric_commit") != evidence.get("worker_fabric_commit"):
        issues.append("controller and worker revisions differ")
    for field in ("node_fingerprint", "description_identity", "resource_snapshot_identity", "runtime_profile_identity", "runtime_observation_identity", "placement_request_identity", "admission_decision_identity", "record_identity", "runtime_binding_identity", "probe_identity"):
        if not _identity(evidence.get(field)):
            issues.append(f"invalid:{field}")
    if not _identity(evidence.get("receipt_identity"), bare=True) or not _identity(evidence.get("bundle_identity"), bare=True) or not _identity(evidence.get("archive_identity")):
        issues.append("execution/bundle identities are invalid")
    if evidence.get("worker_identity") != "collamore02-windows":
        issues.append("Windows worker identity is unexpected")
    gpu = evidence.get("gpu")
    if not isinstance(gpu, dict) or gpu.get("vendor") != "nvidia" or gpu.get("backend") != "cuda" or not isinstance(gpu.get("hardware_identity"), str) or not gpu["hardware_identity"]:
        issues.append("GPU discovery facts are invalid")
    runtime = evidence.get("runtime")
    if not isinstance(runtime, dict) or runtime.get("execution_probe") != "PASS" or runtime.get("torch") != "2.11.0+cu128" or runtime.get("torch_cuda") != "12.8":
        issues.append("synchronized runtime proof is invalid")
    if not isinstance(runtime, dict) or not isinstance(runtime.get("precision_probes"), dict) or runtime["precision_probes"].get("float32") != "PASS" or runtime["precision_probes"].get("float16") != "PASS":
        issues.append("required precision probes are incomplete")
    if evidence.get("execution_outcome") != "PASS" or evidence.get("admission_reason_code") != "FULL_ACCELERATOR_ELIGIBLE":
        issues.append("physical CUDA execution/admission did not pass")
    if evidence.get("revoked_controller_disposition") != "FAIL_CLOSED" or evidence.get("revocation_recovery") != "AVAILABLE":
        issues.append("Windows revocation/re-enrollment evidence is incomplete")
    if evidence.get("sequential_cpu_offload_evidence") is not False:
        issues.append("sequential-offload status is overstated")
    _validate_claim_boundary(evidence, issues)
    return {"outcome": "PASS" if not issues else "FAIL", "issues": issues}


def validate_heterogeneous_cross_os_evidence(evidence: object) -> dict[str, Any]:
    """Validate a sanitized portable Fedora/Windows cohort result."""

    if not isinstance(evidence, dict):
        return {"outcome": "FAIL", "issues": ["evidence must be an object"]}
    issues: list[str] = []
    if evidence.get("schema_version") != "mncs-fabric.heterogeneous-cross-os.v0.1":
        issues.append("unsupported heterogeneous evidence schema")
    if evidence.get("record_type") != "mncs-fabric.heterogeneous-cross-os":
        issues.append("record type is invalid")
    if evidence.get("direct_fabric_tls") is not True or evidence.get("ssh_tunnel_used") is not False or evidence.get("ssh_staged_candidate_material") is not False:
        issues.append("cross-OS transport boundary is invalid")
    if not isinstance(evidence.get("fabric_commit"), str) or not _COMMIT.fullmatch(evidence["fabric_commit"]):
        issues.append("invalid:fabric_commit")
    bundle = evidence.get("bundle")
    if not isinstance(bundle, dict) or not _identity(bundle.get("archive_identity")) or not _identity(bundle.get("bundle_identity"), bare=True):
        issues.append("bundle identities are invalid")
    records = evidence.get("records")
    if not isinstance(records, list) or len(records) != 2 or len({item.get("worker_identity") for item in records if isinstance(item, dict)}) != 2:
        issues.append("cross-OS records are incomplete or not distinct")
    else:
        for item in records:
            if not _identity(item.get("record_identity")) or not _identity(item.get("receipt_identity"), bare=True) or item.get("disposition") not in {"EXECUTED", "DUPLICATE_IDEMPOTENT"}:
                issues.append("cross-OS record reference is invalid")
    for field in ("cohort_identity", "collection_identity"):
        if not _identity(evidence.get(field)):
            issues.append(f"invalid:{field}")
    if evidence.get("reconciliation_outcome") != "PASS" or evidence.get("collection_outcome") != "PASS":
        issues.append("cross-OS reconciliation or collection did not pass")
    _validate_claim_boundary(evidence, issues)
    return {"outcome": "PASS" if not issues else "FAIL", "issues": issues}


def _validate_identity_fields(value: object, fields: tuple[str, ...], issues: list[str], *, bare: tuple[str, ...] = ()) -> None:
    if not isinstance(value, dict):
        issues.append("identity envelope is not an object")
        return
    for field in fields:
        if not _identity(value.get(field)):
            issues.append(f"invalid:{field}")
    for field in bare:
        if not _identity(value.get(field), bare=True):
            issues.append(f"invalid:{field}")


def validate_windows_sequential_offload_evidence(evidence: object) -> dict[str, Any]:
    """Validate bounded operator-controlled Windows offload evidence."""

    if not isinstance(evidence, dict):
        return {"outcome": "FAIL", "issues": ["evidence must be an object"]}
    issues: list[str] = []
    if evidence.get("schema_version") != "mncs-fabric.windows-sequential-offload.v0.1":
        issues.append("unsupported Windows offload evidence schema")
    if evidence.get("record_type") != "mncs-fabric.windows-sequential-offload":
        issues.append("record type is invalid")
    if evidence.get("direct_fabric_tls") is not True or evidence.get("ssh_tunnel_used") is not False or evidence.get("ssh_staged_candidate_material") is not False:
        issues.append("Fabric/SSH execution boundary is invalid")
    for field in ("fabric_commit", "worker_fabric_commit"):
        if not isinstance(evidence.get(field), str) or not _COMMIT.fullmatch(evidence[field]):
            issues.append(f"invalid:{field}")
    if evidence.get("fabric_commit") != evidence.get("worker_fabric_commit"):
        issues.append("controller and worker revisions differ")
    if evidence.get("worker_identity") != "collamore02-windows":
        issues.append("Windows worker identity is unexpected")
    _validate_identity_fields(evidence, ("runtime_profile_identity", "runtime_environment_identity", "runtime_capability_observation_identity", "placement_request_identity", "admission_decision_identity", "resource_snapshot_identity", "record_identity", "runtime_binding_identity"), issues, bare=("receipt_identity", "bundle_identity"))
    if not _identity(evidence.get("archive_identity")):
        issues.append("invalid:archive_identity")
    runtime = evidence.get("runtime")
    if not isinstance(runtime, dict) or runtime.get("torch") != "2.11.0+cu128" or runtime.get("torch_cuda") != "12.8" or runtime.get("execution_probe") != "PASS":
        issues.append("CUDA runtime proof is incomplete")
    capability = evidence.get("offload_capability")
    if not isinstance(capability, dict) or capability.get("status") != "PASS" or capability.get("actual_mode") != "sequential-cpu-offload" or capability.get("cuda_execution") != "PASS" or capability.get("mechanism") != "accelerate.cpu_offload":
        issues.append("sequential-offload capability proof is incomplete")
    if evidence.get("execution_outcome") != "PASS":
        issues.append("Fabric execution did not pass")
    admission = evidence.get("admission")
    if not isinstance(admission, dict) or admission.get("mode") != "sequential-cpu-offload" or admission.get("reason_code") != "SEQUENTIAL_CPU_OFFLOAD_ELIGIBLE":
        issues.append("sequential-offload admission is incomplete")
    comparison = evidence.get("comparison")
    if not isinstance(comparison, dict) or comparison.get("cuda_offload_result") != "EXACT" or not isinstance(comparison.get("full_cuda_peak_allocated_bytes"), int) or not isinstance(comparison.get("offload_peak_allocated_bytes"), int) or comparison["offload_peak_allocated_bytes"] >= comparison["full_cuda_peak_allocated_bytes"]:
        issues.append("full-CUDA/offload comparison is incomplete")
    if evidence.get("transfer_status") not in {"COMMITTED", "ALREADY_PRESENT"}:
        issues.append("native transfer status is invalid")
    _validate_claim_boundary(evidence, issues)
    return {"outcome": "PASS" if not issues else "FAIL", "issues": issues}


def validate_three_node_heterogeneous_evidence(evidence: object) -> dict[str, Any]:
    """Validate sanitized three-physical-node collection evidence."""

    if not isinstance(evidence, dict):
        return {"outcome": "FAIL", "issues": ["evidence must be an object"]}
    issues: list[str] = []
    if evidence.get("schema_version") != "mncs-fabric.three-node-heterogeneous.v0.1":
        issues.append("unsupported three-node evidence schema")
    if evidence.get("record_type") != "mncs-fabric.three-node-heterogeneous":
        issues.append("record type is invalid")
    if not isinstance(evidence.get("fabric_commit"), str) or not _COMMIT.fullmatch(evidence["fabric_commit"]):
        issues.append("fabric commit is invalid")
    if evidence.get("direct_fabric_tls") is not True or evidence.get("ssh_tunnel_used") is not False or evidence.get("ssh_staged_candidate_material") is not False:
        issues.append("transport boundary is invalid")
    nodes = evidence.get("nodes")
    if not isinstance(nodes, list) or len(nodes) != 3 or len(set(nodes)) != 3 or set(nodes) != {"fabric-controller-local", "fabric-worker-01", "collamore02-windows"}:
        issues.append("three distinct physical node identities are required")
    bundle = evidence.get("bundle")
    if not isinstance(bundle, dict) or not _identity(bundle.get("archive_identity")) or not _identity(bundle.get("bundle_identity"), bare=True):
        issues.append("bundle identities are invalid")
    records = evidence.get("records")
    if not isinstance(records, list) or len(records) != 3:
        issues.append("three execution records are required")
    else:
        if len({item.get("worker_identity") for item in records if isinstance(item, dict)}) != 3:
            issues.append("execution workers are not distinct")
        for item in records:
            if not isinstance(item, dict) or not _identity(item.get("record_identity")) or not _identity(item.get("receipt_identity"), bare=True) or item.get("disposition") not in {"EXECUTED", "DUPLICATE_IDEMPOTENT"}:
                issues.append("execution record reference is invalid")
    for field in ("collection_identity", "reconciliation_identity"):
        if not _identity(evidence.get(field)):
            issues.append(f"invalid:{field}")
    if evidence.get("collection_outcome") != "PASS" or evidence.get("reconciliation_outcome") != "PASS":
        issues.append("collection or reconciliation did not pass")
    transfers = evidence.get("native_bundle_transfer")
    if not isinstance(transfers, dict) or not all(transfers.get(node) in {"COMMITTED", "ALREADY_PRESENT"} for node in ("fabric-worker-01", "collamore02-windows")):
        issues.append("remote native bundle transfer evidence is incomplete")
    _validate_claim_boundary(evidence, issues)
    return {"outcome": "PASS" if not issues else "FAIL", "issues": issues}


def validate_heterogeneous_fault_profile_evidence(evidence: object) -> dict[str, Any]:
    """Validate expected/observed bounded fault dispositions."""

    if not isinstance(evidence, dict):
        return {"outcome": "FAIL", "issues": ["evidence must be an object"]}
    issues: list[str] = []
    if evidence.get("schema_version") != "mncs-fabric.heterogeneous-fault-profiles.v0.1":
        issues.append("unsupported fault-profile schema")
    if evidence.get("record_type") != "mncs-fabric.heterogeneous-fault-profiles":
        issues.append("record type is invalid")
    if not isinstance(evidence.get("fabric_commit"), str) or not _COMMIT.fullmatch(evidence["fabric_commit"]):
        issues.append("fabric commit is invalid")
    profiles = evidence.get("profiles")
    if not isinstance(profiles, dict) or not profiles:
        issues.append("fault profiles are missing")
    else:
        for name, profile in profiles.items():
            if not isinstance(name, str) or not isinstance(profile, dict) or profile.get("expected") != profile.get("observed"):
                issues.append(f"fault profile is not reproducible:{name}")
    _validate_claim_boundary(evidence, issues)
    return {"outcome": "PASS" if not issues else "FAIL", "issues": issues}


def validate_raspberry_pi_preflight_evidence(evidence: object) -> dict[str, Any]:
    """Validate strict, bounded Raspberry Pi/Linux bootstrap evidence.

    ``UNKNOWN`` is intentional here: a known host key and a failed or
    incomplete account mapping must not be promoted into worker or execution
    evidence.  A future PASS preflight still proves only bootstrap facts;
    Fabric execution requires a separate execution record.
    """

    if not isinstance(evidence, dict):
        return {"outcome": "FAIL", "issues": ["evidence must be an object"]}
    issues: list[str] = []
    if evidence.get("schema_version") != "mncs-fabric.raspberry-pi-preflight.v0.1":
        issues.append("unsupported Raspberry Pi preflight schema")
    if evidence.get("record_type") != "mncs-fabric.raspberry-pi-preflight":
        issues.append("record type is invalid")
    if evidence.get("outcome") not in {"PASS", "UNKNOWN"}:
        issues.append("preflight outcome must be PASS or UNKNOWN")
    for field in ("worker_identity", "controller_identity", "endpoint_configuration_source", "expected_hostname"):
        if not isinstance(evidence.get(field), str) or not evidence[field] or len(evidence[field]) > 256:
            issues.append(f"invalid:{field}")
    alias = evidence.get("ssh_alias")
    ssh_host = evidence.get("ssh_host_supplied")
    if alias is not None and (not isinstance(alias, str) or not alias or len(alias) > 256):
        issues.append("invalid:ssh_alias")
    if not isinstance(ssh_host, str) or not ssh_host or len(ssh_host) > 256:
        if not isinstance(alias, str) or not alias:
            issues.append("invalid:ssh_host_supplied")
    if evidence.get("strict_host_key_checking") is not True or evidence.get("public_key_only") is not True:
        issues.append("SSH host-key/public-key boundary is invalid")
    if evidence.get("ssh_tunnel_used") is not False or evidence.get("ssh_staged_candidate_material") is not False or evidence.get("fabric_execution_attempted") is not False:
        issues.append("preflight must not claim an SSH tunnel, candidate staging, or Fabric execution")
    if evidence.get("direct_fabric_tls") is not False:
        issues.append("preflight direct_fabric_tls must remain false")
    if evidence.get("outcome") == "UNKNOWN" and (not isinstance(evidence.get("blocker"), str) or not evidence["blocker"]):
        issues.append("UNKNOWN preflight requires a bounded blocker")
    if evidence.get("outcome") == "PASS":
        observed = evidence.get("observed")
        if not isinstance(observed, dict) or observed.get("os") != "linux" or not isinstance(observed.get("architecture"), str) or not observed["architecture"].startswith(("arm", "aarch")):
            issues.append("PASS preflight does not establish an observed Linux ARM substrate")
        if evidence.get("observed_hostname") != evidence.get("expected_hostname"):
            issues.append("observed hostname does not match expected hostname")
    _validate_claim_boundary(evidence, issues)
    return {"outcome": "PASS" if not issues else "FAIL", "issues": issues}


def validate_physical_worker_state_evidence(evidence: object) -> dict[str, Any]:
    """Validate sanitized description, loss/recovery, and collection evidence."""

    if not isinstance(evidence, dict):
        return {"outcome": "FAIL", "issues": ["evidence must be an object"]}
    issues: list[str] = []
    if evidence.get("record_type") != "mncs-fabric.physical-worker-state":
        issues.append("record type is invalid")
    if evidence.get("direct_fabric_tls") is not True or evidence.get("ssh_tunnel_used") is not False:
        issues.append("direct Fabric TLS boundary is invalid")
    if not isinstance(evidence.get("fabric_commit"), str) or not _COMMIT.fullmatch(evidence["fabric_commit"]) or evidence.get("fabric_commit") != evidence.get("worker_fabric_commit"):
        issues.append("controller and worker revisions are invalid or differ")
    if not isinstance(evidence.get("controller_identity"), str) or not isinstance(evidence.get("worker_identity"), str) or evidence["controller_identity"] == evidence["worker_identity"]:
        issues.append("logical worker identities are not distinct")
    bundle = evidence.get("bundle")
    if not isinstance(bundle, dict) or not _identity(bundle.get("archive_identity")) or not _identity(bundle.get("logical_identity"), bare=True) or bundle.get("transfer_status") not in {"COMMITTED", "ALREADY_PRESENT"}:
        issues.append("bundle transfer evidence is invalid")
    try:
        from .worker_state import validate_worker_description
        description = validate_worker_description(evidence.get("worker_description"), expected_worker_id=evidence.get("worker_identity"))
        if description["resource_snapshot"]["worker_identity"] != evidence.get("worker_identity"):
            issues.append("description resource binding is invalid")
    except (FabricError, ValueError, TypeError):
        issues.append("worker description is invalid")
    replication = evidence.get("replication")
    if not isinstance(replication, dict) or not isinstance(replication.get("results"), list) or len(replication["results"]) != 2 or replication.get("reconciliation", {}).get("outcome") != "PASS":
        issues.append("two-worker replication evidence is incomplete")
    elif len({item.get("worker_identity") for item in replication["results"]}) != 2 or not all(_identity(item.get("record_identity")) for item in replication["results"]):
        issues.append("replication worker or record identities are invalid")
    collection = evidence.get("collection")
    try:
        from .collections import validate_execution_collection
        checked_collection = validate_execution_collection(collection)
        if checked_collection["outcome"] != "PASS":
            issues.append("execution collection is not complete")
    except (FabricError, ValueError, TypeError):
        issues.append("execution collection is invalid")
    fault = evidence.get("fault_corpus")
    if not isinstance(fault, dict) or fault.get("worker_loss", {}).get("disposition") != "UNKNOWN" or fault.get("incomplete_replication", {}).get("disposition") != "UNKNOWN" or fault.get("duplicate_after_restart") != "DUPLICATE_IDEMPOTENT":
        issues.append("loss/recovery fault dispositions are invalid")
    boundary = evidence.get("claim_boundary")
    for term in ("sandbox", "correctness", "custody", "independence", "conformance", "certification"):
        if not isinstance(boundary, str) or term not in boundary.lower():
            issues.append(f"claim boundary omits:{term}")
    if not isinstance(evidence.get("limitations"), list) or not evidence["limitations"] or _contains_secret(evidence):
        issues.append("limitations or secret exclusion is invalid")
    return {"outcome": "PASS" if not issues else "FAIL", "issues": issues}


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
    resource_snapshot = evidence.get("resource_snapshot")
    if resource_snapshot is not None:
        try:
            from .resources import validate_resource_snapshot
            validate_resource_snapshot(resource_snapshot, error_type=ValueError)
            if resource_snapshot.get("worker_identity") != evidence.get("worker_identity"):
                issues.append("resource snapshot worker identity is invalid")
        except (ValueError, TypeError):
            issues.append("resource snapshot is invalid")
    placement = evidence.get("placement")
    if placement is not None:
        if not isinstance(placement, dict) or not all(_identity(placement.get(field)) for field in ("request_identity", "resource_snapshot_identity", "admission_decision_identity")) or placement.get("mode") != "cpu":
            issues.append("native placement admission evidence is invalid")
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
