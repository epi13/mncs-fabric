"""Versioned public consumer and provenance contracts owned by Fabric."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping

from .canonical import attach_identity, is_sha256_identity, sha256_identity, verify_identity
from .errors import ProtocolError, ValidationError


PUBLIC_CONTRACT_SCHEMA = "mncs-fabric.public-contract.v0.1"
PUBLIC_API_VERSION = "mncs-fabric.api.v0.1"
CONSUMER_CONTEXT_SCHEMA = "mncs-fabric.consumer-context.v0.1"
CONSUMER_RESULT_SCHEMA = "mncs-fabric.consumer-result.v0.1"
PROVENANCE_BINDING_SCHEMA = "mncs-fabric.consumer-provenance.v0.1"

PUBLIC_FEATURES = {
    "local_execution": True,
    "local_replication": True,
    "network_execution": True,
    "persistent_worker": True,
    "challenge_replay": True,
    "reconciliation": True,
    "bundle_verification": True,
    "native_bundle_transfer": True,
    "capability_scheduling": True,
    "resource_observation": True,
    "placement_request": True,
    "resource_aware_admission": True,
    "placement_evidence": True,
    "sequential_cpu_offload_evidence": True,
    "remote_worker_description": True,
    "remote_resource_refresh": True,
    "worker_liveness": True,
    "execution_collections": True,
    "runtime_profile": True,
    "runtime_observation": True,
    "runtime_capability_evidence": True,
    "runtime_aware_admission": True,
    "worker_capability_observation": True,
    "windows_worker_launcher": True,
    "cuda_execution_probe": True,
    "operator_worker_registry": True,
}

_FORBIDDEN_AUTHORITY_FIELDS = {
    "verdict",
    "evaluator_verdict",
    "conformance",
    "mncs_conformance",
    "mncds_conformance",
    "promotion",
    "promotion_authorized",
    "evaluator_authority",
    "selection_authority",
    "freeze_status",
}


def _bounded_text(value: object, field: str, maximum: int = 256) -> str:
    if not isinstance(value, str) or not value or len(value) > maximum or "\x00" in value:
        raise ValidationError(f"{field} must be bounded non-empty text")
    return value


def _identity(value: object, field: str, *, allow_none: bool = True) -> str | None:
    if value is None and allow_none:
        return None
    if not is_sha256_identity(value):
        raise ValidationError(f"{field} must be a sha256 identity")
    return str(value)


def _reject_authority(value: object) -> None:
    if isinstance(value, Mapping):
        for key, child in value.items():
            if str(key).lower() in _FORBIDDEN_AUTHORITY_FIELDS and child not in (None, False, "UNKNOWN", "not-asserted"):
                raise ValidationError(f"consumer context cannot grant authority through {key}")
            _reject_authority(child)
    elif isinstance(value, (list, tuple)):
        for child in value:
            _reject_authority(child)


@dataclass(frozen=True, slots=True)
class ConsumerContext:
    """Opaque consumer provenance, never consumer semantic authority."""

    source_project: str
    consumer_workload_identity: str
    experiment_identity: str | None = None
    forge_workflow_identity: str | None = None
    provider_identity: str | None = None
    partition_identity: str | None = None

    def __post_init__(self) -> None:
        _bounded_text(self.source_project, "source_project", 64)
        _identity(self.consumer_workload_identity, "consumer_workload_identity", allow_none=False)
        for field in ("experiment_identity", "forge_workflow_identity", "provider_identity", "partition_identity"):
            _identity(getattr(self, field), field)

    @property
    def context_identity(self) -> str:
        return sha256_identity(self.to_dict(include_identity=False))

    def to_dict(self, *, include_identity: bool = True) -> dict[str, Any]:
        value: dict[str, Any] = {
            "schema_version": CONSUMER_CONTEXT_SCHEMA,
            "source_project": self.source_project,
            "consumer_workload_identity": self.consumer_workload_identity,
            "experiment_identity": self.experiment_identity,
            "forge_workflow_identity": self.forge_workflow_identity,
            "provider_identity": self.provider_identity,
            "partition_identity": self.partition_identity,
            "authority": "provenance-only",
            "claim_boundary": "opaque consumer provenance; no semantic verdict, promotion, conformance, or evaluator authority",
        }
        if include_identity:
            value["context_identity"] = self.context_identity
        return value


def validate_consumer_context(value: object, *, error_type: type[Exception] = ProtocolError) -> dict[str, Any]:
    if not isinstance(value, dict) or value.get("schema_version") != CONSUMER_CONTEXT_SCHEMA:
        raise error_type("unsupported or malformed consumer context")
    required = {
        "schema_version", "source_project", "consumer_workload_identity", "experiment_identity",
        "forge_workflow_identity", "provider_identity", "partition_identity", "authority",
        "claim_boundary", "context_identity",
    }
    if set(value) != required or value.get("authority") != "provenance-only":
        raise error_type("consumer context fields or authority boundary are invalid")
    try:
        context = ConsumerContext(
            source_project=value["source_project"],
            consumer_workload_identity=value["consumer_workload_identity"],
            experiment_identity=value["experiment_identity"],
            forge_workflow_identity=value["forge_workflow_identity"],
            provider_identity=value["provider_identity"],
            partition_identity=value["partition_identity"],
        )
        _reject_authority(value)
    except ValidationError as exc:
        raise error_type(str(exc)) from exc
    checked = context.to_dict()
    if checked != value or not verify_identity(value, "context_identity"):
        raise error_type("consumer context identity does not verify")
    return checked


def build_public_contract(package_version: str) -> dict[str, Any]:
    value: dict[str, Any] = {
        "schema_version": PUBLIC_CONTRACT_SCHEMA,
        "public_api_version": PUBLIC_API_VERSION,
        "package_name": "mncs-fabric",
        "package_version": package_version,
        "job_plan_schema": "mncs-fabric.job-plan.v0.1",
        "execution_record_schema": "mncs-fabric.execution-record.v0.1",
        "cohort_schema": "mncs-fabric.cohort-result.v0.1",
        "node_capability_schema": "mncs-fabric.node-capabilities.v0.1",
        "node_resource_schema": "mncs-fabric.node-resources.v0.1",
        "placement_request_schema": "mncs-fabric.execution-placement-request.v0.1",
        "placement_admission_schema": "mncs-fabric.placement-admission.v0.1",
        "placement_observation_schema": "mncs-fabric.execution-placement-observation.v0.1",
        "placement_reference_schema": "mncs-fabric.placement-reference.v0.1",
        "worker_description_schema": "mncs-fabric.worker-description.v0.2",
        "worker_liveness_schema": "mncs-fabric.worker-liveness.v0.1",
        "work_item_schema": "mncs-fabric.work-item.v0.1",
        "execution_collection_schema": "mncs-fabric.execution-collection.v0.1",
        "runtime_profile_schema": "mncs-fabric.runtime-profile.v0.1",
        "runtime_observation_schema": "mncs-fabric.runtime-observation.v0.1",
        "runtime_binding_schema": "mncs-fabric.runtime-binding.v0.1",
        "runtime_environment_schema": "mncs-fabric.runtime-environment.v0.1",
        "runtime_capability_observation_schema": "mncs-fabric.runtime-capability-observation.v0.1",
        "runtime_capability_binding_schema": "mncs-fabric.runtime-capability-binding.v0.1",
        "worker_capability_observation_schema": "mncs-fabric.worker-capability-observation.v0.1",
        "protocol_schema": "mncs-fabric.protocol.v0.1",
        "receipt_profile": "0.1-experimental",
        "execution_bundle_profile": "0.1-experimental",
        "challenge_profile": "0.1-experimental",
        "features": dict(PUBLIC_FEATURES),
        "capability_namespace": "provider-neutral Fabric capability names; unknown requirements remain UNKNOWN",
        "claim_boundary": "compatibility metadata only; not conformance, assurance, correctness, custody, independence, or promotion authority",
    }
    value["contract_identity"] = sha256_identity(value)
    return value


def validate_public_contract(value: object) -> dict[str, Any]:
    if not isinstance(value, dict) or value.get("schema_version") != PUBLIC_CONTRACT_SCHEMA:
        raise ValidationError("unsupported public contract schema")
    if not verify_identity(value, "contract_identity"):
        raise ValidationError("public contract identity does not verify")
    if not isinstance(value.get("features"), dict) or value["features"].get("native_bundle_transfer") is not True or value["features"].get("resource_observation") is not True or value["features"].get("placement_request") is not True:
        raise ValidationError("public contract feature declaration is invalid")
    return dict(value)


def build_provenance_binding(
    *,
    context: ConsumerContext,
    request_identity: str | None,
    job_identity: str | None,
    worker_identity: str | None,
    record_identity: str | None,
    receipt_identity: str | None,
    bundle_identity: str | None,
    challenge_identity: str | None = None,
) -> dict[str, Any]:
    value: dict[str, Any] = {
        "schema_version": PROVENANCE_BINDING_SCHEMA,
        "consumer_context_identity": context.context_identity,
        "request_identity": request_identity,
        "job_identity": job_identity,
        "worker_identity": worker_identity,
        "record_identity": record_identity,
        "receipt_identity": receipt_identity,
        "bundle_identity": bundle_identity,
        "challenge_identity": challenge_identity,
        "claim_boundary": "provenance linkage only; Fabric does not establish consumer semantic truth or authority",
    }
    return attach_identity(value, "binding_identity")
