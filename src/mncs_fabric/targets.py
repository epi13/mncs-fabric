"""Typed, identity-addressed references for consumer-authorized execution targets.

The reference records where an already approved bounded workload must run and
which factual capabilities it requires.  It does not choose tools, grant model
requests authority, or permit shell/SSH fallback.
"""

from __future__ import annotations

from dataclasses import dataclass
import re
from datetime import datetime, timezone
from typing import Any, Iterable, Mapping

from .canonical import attach_identity, is_sha256_identity, sha256_identity, verify_identity
from .capabilities import validate_capability_observation
from .contracts import validate_consumer_context
from .errors import ValidationError


EXECUTION_TARGET_SCHEMA = "mncs-fabric.execution-target-reference.v0.1"
EXECUTION_CLASSES = frozenset({"bounded-argv-workload"})
MAX_REQUIRED_CAPABILITIES = 64
MAX_LIVENESS_AGE_SECONDS = 300.0
MAX_CAPABILITY_AGE_SECONDS = 3600.0
TARGET_CLAIM_BOUNDARY = (
    "consumer-authorized target and factual admission requirements only; not "
    "semantic tool choice, model permission, shell authority, attestation, or fallback authority"
)
TARGET_ADMISSION_SCHEMA = "mncs-fabric.target-admission.v0.1"
TARGET_EXECUTION_EVIDENCE_SCHEMA = "mncs-fabric.target-execution-evidence.v0.1"
TARGET_AUTHORIZATION_INTERPRETATION = "CONSUMER_PROVIDED_PROVENANCE_ONLY"
TARGET_ADMISSION_CODES = frozenset({
    "TARGET_ADMITTED",
    "TARGET_UNKNOWN",
    "TARGET_REVOKED",
    "TARGET_DISCONNECTED",
    "TARGET_LIVENESS_STALE",
    "TARGET_CAPABILITIES_STALE",
    "TARGET_CAPABILITY_MISSING",
    "TARGET_RUNTIME_MISMATCH",
    "TARGET_TOOL_CAPABILITY_MISMATCH",
    "TARGET_CONTEXT_MISMATCH",
    "TARGET_AUTHORIZATION_BINDING_INVALID",
    "TARGET_BECAME_UNAVAILABLE",
})
TARGET_ADMISSION_DISPOSITIONS = {
    "TARGET_ADMITTED": "PASS",
    "TARGET_REVOKED": "DENIED",
    "TARGET_CAPABILITY_MISSING": "DENIED",
    "TARGET_RUNTIME_MISMATCH": "DENIED",
    "TARGET_TOOL_CAPABILITY_MISMATCH": "DENIED",
    "TARGET_CONTEXT_MISMATCH": "DENIED",
    "TARGET_AUTHORIZATION_BINDING_INVALID": "DENIED",
    "TARGET_UNKNOWN": "UNKNOWN",
    "TARGET_DISCONNECTED": "UNKNOWN",
    "TARGET_LIVENESS_STALE": "UNKNOWN",
    "TARGET_CAPABILITIES_STALE": "UNKNOWN",
    "TARGET_BECAME_UNAVAILABLE": "UNKNOWN",
}
TARGET_EXECUTION_CLAIM_BOUNDARY = (
    "Fabric proves the same-OS-user authenticated local peer requested this exact "
    "bounded execution and target; consumer_authorization_identity is opaque "
    "consumer-provided provenance, not Fabric-verified semantic permission"
)
_FUTURE_SKEW_SECONDS = 60.0
_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:+/-]{0,255}$")
_WORKER_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")


def _name(value: object, field: str) -> str:
    if not isinstance(value, str) or not _NAME.fullmatch(value):
        raise ValidationError(f"{field} must be a bounded capability name")
    return value


def _identity(value: object, field: str, *, optional: bool = False) -> str | None:
    if value is None and optional:
        return None
    if not is_sha256_identity(value):
        raise ValidationError(f"{field} must be a sha256 identity")
    return str(value)


def _age(value: object, field: str, maximum: float) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValidationError(f"{field} must be a bounded number")
    checked = float(value)
    if not 0 < checked <= maximum:
        raise ValidationError(f"{field} is outside the bounded range")
    return checked


def _capabilities(values: Iterable[object]) -> tuple[str, ...]:
    if isinstance(values, (str, bytes)):
        raise ValidationError("required_capabilities must be a collection, not text")
    items = tuple(_name(value, "required_capability") for value in values)
    if not items or len(items) > MAX_REQUIRED_CAPABILITIES:
        raise ValidationError("required_capabilities must be a non-empty bounded collection")
    if len(set(items)) != len(items):
        raise ValidationError("required_capabilities must be unique")
    return tuple(sorted(items))


@dataclass(frozen=True, slots=True)
class ExecutionTargetReference:
    """One exact worker target selected by consumer policy.

    ``consumer_authorization_identity`` is opaque provenance. Its hash shape is
    never interpreted by Fabric as proof that the consumer policy allowed work.
    """

    worker_identity: str
    required_capabilities: tuple[str, ...]
    consumer_context_identity: str
    consumer_authorization_identity: str
    execution_class: str = "bounded-argv-workload"
    tool_capability_identity: str | None = None
    runtime_identity: str | None = None
    liveness_max_age_seconds: float = 30.0
    capability_max_age_seconds: float = 300.0

    def __post_init__(self) -> None:
        if not isinstance(self.worker_identity, str) or not _WORKER_ID.fullmatch(
            self.worker_identity
        ):
            raise ValidationError("worker_identity is invalid")
        if self.execution_class not in EXECUTION_CLASSES:
            raise ValidationError("execution_class is unsupported")
        normalized = _capabilities(self.required_capabilities)
        object.__setattr__(self, "required_capabilities", normalized)
        _identity(self.consumer_context_identity, "consumer_context_identity")
        _identity(self.consumer_authorization_identity, "consumer_authorization_identity")
        _identity(self.tool_capability_identity, "tool_capability_identity", optional=True)
        _identity(self.runtime_identity, "runtime_identity", optional=True)
        object.__setattr__(
            self,
            "liveness_max_age_seconds",
            _age(self.liveness_max_age_seconds, "liveness_max_age_seconds", MAX_LIVENESS_AGE_SECONDS),
        )
        object.__setattr__(
            self,
            "capability_max_age_seconds",
            _age(
                self.capability_max_age_seconds,
                "capability_max_age_seconds",
                MAX_CAPABILITY_AGE_SECONDS,
            ),
        )

    @property
    def target_identity(self) -> str:
        return sha256_identity(self.to_dict(include_identity=False))

    def to_dict(self, *, include_identity: bool = True) -> dict[str, Any]:
        value: dict[str, Any] = {
            "schema_version": EXECUTION_TARGET_SCHEMA,
            "worker_identity": self.worker_identity,
            "execution_class": self.execution_class,
            "required_capabilities": list(self.required_capabilities),
            "tool_capability_identity": self.tool_capability_identity,
            "runtime_identity": self.runtime_identity,
            "consumer_context_identity": self.consumer_context_identity,
            "consumer_authorization_identity": self.consumer_authorization_identity,
            "require_current_membership": True,
            "require_authenticated_presence": True,
            "required_availability": "AVAILABLE",
            "liveness_max_age_seconds": self.liveness_max_age_seconds,
            "capability_max_age_seconds": self.capability_max_age_seconds,
            "fallback_policy": "NONE",
            "claim_boundary": TARGET_CLAIM_BOUNDARY,
        }
        if include_identity:
            value["target_identity"] = self.target_identity
        return value


def validate_execution_target_reference(
    value: object,
    *,
    expected_worker_identity: str | None = None,
    expected_consumer_context_identity: str | None = None,
) -> dict[str, Any]:
    if not isinstance(value, dict) or value.get("schema_version") != EXECUTION_TARGET_SCHEMA:
        raise ValidationError("unsupported execution target schema")
    required = {
        "schema_version", "worker_identity", "execution_class", "required_capabilities",
        "tool_capability_identity", "runtime_identity", "consumer_context_identity",
        "consumer_authorization_identity", "require_current_membership",
        "require_authenticated_presence", "required_availability",
        "liveness_max_age_seconds", "capability_max_age_seconds", "fallback_policy",
        "claim_boundary", "target_identity",
    }
    if set(value) != required or not verify_identity(value, "target_identity"):
        raise ValidationError("execution target fields or identity are invalid")
    if (
        value["require_current_membership"] is not True
        or value["require_authenticated_presence"] is not True
        or value["required_availability"] != "AVAILABLE"
        or value["fallback_policy"] != "NONE"
        or value["claim_boundary"] != TARGET_CLAIM_BOUNDARY
    ):
        raise ValidationError("execution target authority or fallback boundary is invalid")
    capabilities = value["required_capabilities"]
    if not isinstance(capabilities, list):
        raise ValidationError("required_capabilities must be an array")
    rebuilt = ExecutionTargetReference(
        worker_identity=value["worker_identity"],
        execution_class=value["execution_class"],
        required_capabilities=tuple(capabilities),
        tool_capability_identity=value["tool_capability_identity"],
        runtime_identity=value["runtime_identity"],
        consumer_context_identity=value["consumer_context_identity"],
        consumer_authorization_identity=value["consumer_authorization_identity"],
        liveness_max_age_seconds=value["liveness_max_age_seconds"],
        capability_max_age_seconds=value["capability_max_age_seconds"],
    ).to_dict()
    if rebuilt != value:
        raise ValidationError("execution target is not canonically normalized")
    if expected_worker_identity is not None and value["worker_identity"] != expected_worker_identity:
        raise ValidationError("execution target is bound to another worker")
    if (
        expected_consumer_context_identity is not None
        and value["consumer_context_identity"] != expected_consumer_context_identity
    ):
        raise ValidationError("execution target is bound to another consumer context")
    return rebuilt


def _instant(value: object) -> datetime | None:
    if not isinstance(value, str) or len(value) > 64:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        return None
    return parsed.astimezone(timezone.utc)


def _capability_names(observation: Mapping[str, Any]) -> set[str]:
    names: set[str] = set()
    for entry in observation.get("capabilities", []):
        if not isinstance(entry, Mapping):
            continue
        kind = entry.get("kind")
        namespace = entry.get("namespace")
        name = entry.get("name")
        if isinstance(name, str):
            names.add(name)
            if isinstance(kind, str):
                names.add(f"{kind}:{name}")
            if isinstance(namespace, str):
                names.add(f"{namespace}:{name}")
    return names


def _target_admission(
    *,
    target: Mapping[str, Any],
    disposition: str,
    reason_code: str,
    evaluated_at: str,
    request_identity: str,
    execution_request_identity: str,
    authenticated_client_identity: str,
    client_label: str,
    consumer_context_identity: str,
    consumer_authorization_identity: str,
    job_identity: str,
    bundle_identity: str,
    worker_state: Mapping[str, Any] | None,
    capability_observation: Mapping[str, Any] | None,
    liveness_age_seconds: float | None,
    capability_age_seconds: float | None,
    observed_runtime_identity: str | None,
    checks: Mapping[str, str],
) -> dict[str, Any]:
    if reason_code not in TARGET_ADMISSION_CODES or disposition != TARGET_ADMISSION_DISPOSITIONS[reason_code]:
        raise ValidationError("target admission reason/disposition is unsupported")
    session_id = worker_state.get("session_id") if worker_state is not None else None
    session_generation = worker_state.get("session_generation") if worker_state is not None else None
    request_binding = attach_identity({
        "target_identity": target["target_identity"],
        "request_identity": request_identity,
        "execution_request_identity": execution_request_identity,
        "authenticated_client_identity": authenticated_client_identity,
        "client_label": client_label,
        "consumer_context_identity": consumer_context_identity,
        "consumer_authorization_identity": consumer_authorization_identity,
        "job_identity": job_identity,
        "bundle_identity": bundle_identity,
        "authorization_interpretation": TARGET_AUTHORIZATION_INTERPRETATION,
    }, "request_binding_identity")
    value = {
        "schema_version": TARGET_ADMISSION_SCHEMA,
        "target_identity": target["target_identity"],
        "target_reference": dict(target),
        "worker_identity": target["worker_identity"],
        "disposition": disposition,
        "reason_code": reason_code,
        "evaluated_at": evaluated_at,
        "request_binding": request_binding,
        "membership_status": worker_state.get("membership_status") if worker_state is not None else None,
        "availability": worker_state.get("availability") if worker_state is not None else None,
        "transport": worker_state.get("transport") if worker_state is not None else None,
        "session_id": session_id,
        "session_generation": session_generation,
        "liveness_observed_at": (
            worker_state.get("last_seen", worker_state.get("last_observed_at"))
            if worker_state is not None else None
        ),
        "liveness_age_seconds": liveness_age_seconds,
        "capability_observation_identity": (
            capability_observation.get("capability_observation_identity")
            if capability_observation is not None else None
        ),
        "capability_observed_at": capability_observation.get("captured_at") if capability_observation is not None else None,
        "capability_age_seconds": capability_age_seconds,
        "observed_capability_identities": sorted(
            str(entry["capability_identity"])
            for entry in capability_observation.get("capabilities", [])
            if isinstance(entry, Mapping) and isinstance(entry.get("capability_identity"), str)
        ) if capability_observation is not None else [],
        "observed_runtime_identity": observed_runtime_identity,
        "checks": dict(checks),
        "authorization_interpretation": TARGET_AUTHORIZATION_INTERPRETATION,
        "claim_boundary": TARGET_EXECUTION_CLAIM_BOUNDARY,
    }
    return attach_identity(value, "target_admission_identity")


def evaluate_target_admission(
    target: object,
    *,
    worker_state: Mapping[str, Any] | None,
    capability_observation: Mapping[str, Any] | None,
    consumer_context: object,
    consumer_authorization_identity: object,
    authenticated_client_identity: str,
    client_label: str,
    request_identity: str,
    execution_request_identity: str,
    job_identity: str,
    bundle_identity: str,
    now: str | None = None,
) -> dict[str, Any]:
    """Re-evaluate an exact target from current controller-owned observations."""

    checked_target = validate_execution_target_reference(target)
    evaluated = _instant(now) if now is not None else datetime.now(timezone.utc)
    if evaluated is None:
        raise ValidationError("target admission time is invalid")
    evaluated_at = evaluated.isoformat().replace("+00:00", "Z")
    context: dict[str, Any] | None = None
    try:
        context = validate_consumer_context(consumer_context, error_type=ValidationError)
    except ValidationError:
        pass
    checks: dict[str, str] = {}
    reason_code = "TARGET_ADMITTED"
    disposition = "PASS"
    checked_capability: dict[str, Any] | None = None
    liveness_age: float | None = None
    capability_age: float | None = None
    runtime_identity: str | None = None

    if context is None or context.get("context_identity") != checked_target["consumer_context_identity"]:
        checks["consumer_context"] = "FAIL"
        reason_code, disposition = "TARGET_CONTEXT_MISMATCH", "DENIED"
    else:
        checks["consumer_context"] = "PASS"
    if not is_sha256_identity(consumer_authorization_identity) or consumer_authorization_identity != checked_target["consumer_authorization_identity"]:
        checks["consumer_authorization_binding"] = "FAIL"
        if disposition == "PASS":
            reason_code, disposition = "TARGET_AUTHORIZATION_BINDING_INVALID", "DENIED"
    else:
        checks["consumer_authorization_binding"] = "PROVENANCE_ONLY"

    if worker_state is None:
        checks["membership"] = "UNKNOWN"
        if disposition == "PASS":
            reason_code, disposition = "TARGET_UNKNOWN", "UNKNOWN"
    elif worker_state.get("membership_status") == "REVOKED":
        checks["membership"] = "FAIL"
        if disposition == "PASS":
            reason_code, disposition = "TARGET_REVOKED", "DENIED"
    elif worker_state.get("membership_status") != "ENROLLED":
        checks["membership"] = "UNKNOWN"
        if disposition == "PASS":
            reason_code, disposition = "TARGET_UNKNOWN", "UNKNOWN"
    else:
        checks["membership"] = "PASS"

    if worker_state is not None and checks.get("membership") == "PASS":
        authenticated_presence = (
            isinstance(worker_state.get("session_id"), str)
            and isinstance(worker_state.get("session_generation"), int)
        ) or (
            worker_state.get("transport") == "tls-mutual-authenticated"
            and isinstance(worker_state.get("description_identity"), str)
        )
        if worker_state.get("availability") != "AVAILABLE" or not authenticated_presence:
            checks["authenticated_presence"] = "UNKNOWN"
            if disposition == "PASS":
                reason_code, disposition = "TARGET_DISCONNECTED", "UNKNOWN"
        else:
            checks["authenticated_presence"] = "PASS"
        observed_at = _instant(worker_state.get("last_seen", worker_state.get("last_observed_at")))
        if observed_at is not None:
            liveness_age = round((evaluated - observed_at).total_seconds(), 6)
        if liveness_age is None or liveness_age < -_FUTURE_SKEW_SECONDS or liveness_age > checked_target["liveness_max_age_seconds"]:
            checks["liveness_freshness"] = "UNKNOWN"
            if disposition == "PASS":
                reason_code, disposition = "TARGET_LIVENESS_STALE", "UNKNOWN"
        else:
            checks["liveness_freshness"] = "PASS"
        description = worker_state.get("description")
        profile = description.get("runtime_profile") if isinstance(description, Mapping) else None
        if isinstance(profile, Mapping) and isinstance(profile.get("runtime_profile_identity"), str):
            runtime_identity = str(profile["runtime_profile_identity"])

    if capability_observation is not None:
        try:
            checked_capability = validate_capability_observation(
                dict(capability_observation), expected_worker_id=checked_target["worker_identity"]
            )
        except ValidationError:
            checked_capability = None
    if checked_capability is not None:
        captured = _instant(checked_capability.get("captured_at"))
        if captured is not None:
            capability_age = round((evaluated - captured).total_seconds(), 6)
    capability_fresh = (
        checked_capability is not None
        and checked_capability.get("availability") == "AVAILABLE"
        and capability_age is not None
        and -_FUTURE_SKEW_SECONDS <= capability_age <= checked_target["capability_max_age_seconds"]
    )
    if not capability_fresh:
        checks["capability_freshness"] = "UNKNOWN"
        if disposition == "PASS":
            reason_code, disposition = "TARGET_CAPABILITIES_STALE", "UNKNOWN"
    else:
        checks["capability_freshness"] = "PASS"
        names = _capability_names(checked_capability)
        missing = sorted(set(checked_target["required_capabilities"]) - names)
        if missing:
            checks["required_capabilities"] = "FAIL"
            if disposition == "PASS":
                reason_code, disposition = "TARGET_CAPABILITY_MISSING", "DENIED"
        else:
            checks["required_capabilities"] = "PASS"
        tool_identities = {
            entry["capability_identity"]
            for entry in checked_capability["capabilities"]
            if entry["kind"] == "tool"
        }
        required_tool = checked_target.get("tool_capability_identity")
        if required_tool is not None and required_tool not in tool_identities:
            checks["tool_capability_identity"] = "FAIL"
            if disposition == "PASS":
                reason_code, disposition = "TARGET_TOOL_CAPABILITY_MISMATCH", "DENIED"
        else:
            checks["tool_capability_identity"] = "PASS" if required_tool is not None else "NOT_REQUIRED"
    required_runtime = checked_target.get("runtime_identity")
    if required_runtime is not None and runtime_identity != required_runtime:
        checks["runtime_identity"] = "FAIL"
        if disposition == "PASS":
            reason_code, disposition = "TARGET_RUNTIME_MISMATCH", "DENIED"
    else:
        checks["runtime_identity"] = "PASS" if required_runtime is not None else "NOT_REQUIRED"

    return _target_admission(
        target=checked_target,
        disposition=disposition,
        reason_code=reason_code,
        evaluated_at=evaluated_at,
        request_identity=request_identity,
        execution_request_identity=execution_request_identity,
        authenticated_client_identity=authenticated_client_identity,
        client_label=client_label,
        consumer_context_identity=(context or {}).get("context_identity", "INVALID"),
        consumer_authorization_identity=str(consumer_authorization_identity),
        job_identity=job_identity,
        bundle_identity=bundle_identity,
        worker_state=worker_state,
        capability_observation=checked_capability,
        liveness_age_seconds=liveness_age,
        capability_age_seconds=capability_age,
        observed_runtime_identity=runtime_identity,
        checks=checks,
    )


def build_target_execution_evidence(
    admission: Mapping[str, Any], result: Mapping[str, Any]
) -> dict[str, Any]:
    admission = validate_target_admission(dict(admission))
    if admission.get("disposition") != "PASS":
        raise ValidationError("target execution evidence requires a passing admission")
    if result.get("worker_identity") != admission.get("worker_identity"):
        raise ValidationError("target execution result worker differs from admission")
    binding = admission["request_binding"]
    if result.get("job_identity") != binding["job_identity"]:
        raise ValidationError("target execution result job differs from admission")
    if result.get("bundle_identity") != binding["bundle_identity"]:
        raise ValidationError("target execution result bundle differs from admission")
    if result.get("disposition") not in {"EXECUTED", "DUPLICATE_IDEMPOTENT"}:
        raise ValidationError("target execution result disposition is invalid")
    value = {
        "schema_version": TARGET_EXECUTION_EVIDENCE_SCHEMA,
        "target_identity": admission["target_identity"],
        "target_admission_identity": admission["target_admission_identity"],
        "request_binding_identity": binding["request_binding_identity"],
        "request_identity": binding["request_identity"],
        "execution_request_identity": binding["execution_request_identity"],
        "authenticated_client_identity": binding["authenticated_client_identity"],
        "client_label": binding["client_label"],
        "worker_identity": result.get("worker_identity"),
        "session_id": admission.get("session_id"),
        "session_generation": admission.get("session_generation"),
        "capability_observation_identity": admission.get("capability_observation_identity"),
        "observed_capability_identities": list(admission.get("observed_capability_identities", [])),
        "observed_runtime_identity": admission.get("observed_runtime_identity"),
        "consumer_context_identity": binding["consumer_context_identity"],
        "consumer_authorization_identity": binding["consumer_authorization_identity"],
        "authorization_interpretation": TARGET_AUTHORIZATION_INTERPRETATION,
        "bundle_identity": result.get("bundle_identity"),
        "job_identity": result.get("job_identity"),
        "record_identity": result.get("record_identity"),
        "receipt_identity": result.get("receipt_identity"),
        "disposition": result.get("disposition"),
        "claim_boundary": TARGET_EXECUTION_CLAIM_BOUNDARY,
    }
    return attach_identity(value, "target_execution_evidence_identity")


def validate_target_admission(value: object) -> dict[str, Any]:
    required = {
        "schema_version", "target_identity", "target_reference", "worker_identity", "disposition",
        "reason_code", "evaluated_at", "request_binding", "membership_status",
        "availability", "transport", "session_id", "session_generation",
        "liveness_observed_at", "liveness_age_seconds",
        "capability_observation_identity", "capability_observed_at",
        "capability_age_seconds", "observed_capability_identities",
        "observed_runtime_identity", "checks", "authorization_interpretation",
        "claim_boundary", "target_admission_identity",
    }
    if not isinstance(value, dict) or set(value) != required or value.get("schema_version") != TARGET_ADMISSION_SCHEMA or not verify_identity(value, "target_admission_identity"):
        raise ValidationError("target admission fields or identity are invalid")
    reason_code = value.get("reason_code")
    if reason_code not in TARGET_ADMISSION_CODES or value.get("disposition") != TARGET_ADMISSION_DISPOSITIONS[reason_code]:
        raise ValidationError("target admission disposition is invalid")
    if value.get("authorization_interpretation") != TARGET_AUTHORIZATION_INTERPRETATION or value.get("claim_boundary") != TARGET_EXECUTION_CLAIM_BOUNDARY:
        raise ValidationError("target admission authority boundary is invalid")
    binding = value.get("request_binding")
    binding_fields = {
        "target_identity", "request_identity", "execution_request_identity",
        "authenticated_client_identity", "client_label", "consumer_context_identity",
        "consumer_authorization_identity", "job_identity", "bundle_identity",
        "authorization_interpretation", "request_binding_identity",
    }
    if not isinstance(binding, dict) or set(binding) != binding_fields or not verify_identity(binding, "request_binding_identity") or binding.get("authorization_interpretation") != TARGET_AUTHORIZATION_INTERPRETATION:
        raise ValidationError("target admission request binding is invalid")
    target = validate_execution_target_reference(value.get("target_reference"))
    if target["target_identity"] != value["target_identity"] or binding["target_identity"] != value["target_identity"] or target["worker_identity"] != value["worker_identity"]:
        raise ValidationError("target admission target binding is invalid")
    for field in ("request_identity", "execution_request_identity", "authenticated_client_identity", "job_identity"):
        if not is_sha256_identity(binding.get(field)):
            raise ValidationError("target admission request identity is invalid")
    if not isinstance(binding.get("bundle_identity"), str) or not re.fullmatch(r"[0-9a-f]{64}", binding["bundle_identity"]):
        raise ValidationError("target admission bundle identity is invalid")
    if not isinstance(binding.get("client_label"), str) or not _WORKER_ID.fullmatch(binding["client_label"]):
        raise ValidationError("target admission client label is invalid")
    if value["disposition"] == "PASS" and (
        binding.get("consumer_context_identity") != target["consumer_context_identity"]
        or binding.get("consumer_authorization_identity") != target["consumer_authorization_identity"]
        or value.get("membership_status") != "ENROLLED"
        or value.get("availability") != "AVAILABLE"
    ):
        raise ValidationError("passing target admission facts are inconsistent")
    for field in ("capability_observation_identity", "observed_runtime_identity"):
        if value.get(field) is not None and not is_sha256_identity(value.get(field)):
            raise ValidationError("target admission observation identity is invalid")
    observed = value.get("observed_capability_identities")
    if not isinstance(observed, list) or any(not is_sha256_identity(item) for item in observed):
        raise ValidationError("target admission capability identities are invalid")
    if _instant(value.get("evaluated_at")) is None:
        raise ValidationError("target admission evaluation time is invalid")
    return dict(value)


def validate_target_execution_evidence(value: object) -> dict[str, Any]:
    required = {
        "schema_version", "target_identity", "target_admission_identity",
        "request_binding_identity", "request_identity", "execution_request_identity",
        "authenticated_client_identity", "client_label", "worker_identity", "session_id",
        "session_generation", "capability_observation_identity",
        "observed_capability_identities", "observed_runtime_identity",
        "consumer_context_identity", "consumer_authorization_identity",
        "authorization_interpretation", "bundle_identity", "job_identity",
        "record_identity", "receipt_identity", "disposition", "claim_boundary",
        "target_execution_evidence_identity",
    }
    if not isinstance(value, dict) or set(value) != required or value.get("schema_version") != TARGET_EXECUTION_EVIDENCE_SCHEMA or not verify_identity(value, "target_execution_evidence_identity"):
        raise ValidationError("target execution evidence fields or identity are invalid")
    if value.get("authorization_interpretation") != TARGET_AUTHORIZATION_INTERPRETATION or value.get("claim_boundary") != TARGET_EXECUTION_CLAIM_BOUNDARY:
        raise ValidationError("target execution evidence authority boundary is invalid")
    sha_fields = (
        "target_identity", "target_admission_identity", "request_binding_identity",
        "request_identity", "execution_request_identity", "authenticated_client_identity",
        "consumer_context_identity", "consumer_authorization_identity", "job_identity",
        "record_identity", "target_execution_evidence_identity",
    )
    if any(not is_sha256_identity(value.get(field)) for field in sha_fields):
        raise ValidationError("target execution evidence identity field is invalid")
    optional_sha_fields = ("capability_observation_identity", "observed_runtime_identity")
    if any(value.get(field) is not None and not is_sha256_identity(value.get(field)) for field in optional_sha_fields):
        raise ValidationError("target execution evidence optional identity is invalid")
    if not isinstance(value.get("bundle_identity"), str) or not re.fullmatch(r"[0-9a-f]{64}", value["bundle_identity"]):
        raise ValidationError("target execution evidence bundle identity is invalid")
    receipt_identity = value.get("receipt_identity")
    if not isinstance(receipt_identity, str) or not re.fullmatch(r"[0-9a-f]{64}", receipt_identity):
        raise ValidationError("target execution evidence receipt identity is invalid")
    if value.get("disposition") not in {"EXECUTED", "DUPLICATE_IDEMPOTENT"}:
        raise ValidationError("target execution evidence disposition is invalid")
    if not isinstance(value.get("client_label"), str) or not _WORKER_ID.fullmatch(value["client_label"]):
        raise ValidationError("target execution evidence client label is invalid")
    return dict(value)
