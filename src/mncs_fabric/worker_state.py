"""Authenticated worker descriptions and expiring controller observations.

Descriptions are worker-produced observations, not attestation.  They contain
only bounded Fabric-owned node, resource, protocol, and public-contract facts.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Mapping

from . import __version__
from .canonical import attach_identity, is_sha256_identity, verify_identity
from .contracts import build_public_contract
from .errors import ValidationError
from .node import utc_now
from .models import NODE_SCHEMA
from .resources import validate_resource_snapshot
from .runtime import build_runtime_profile, validate_runtime_profile

LEGACY_DESCRIPTION_SCHEMA = "mncs-fabric.worker-description.v0.1"
DESCRIPTION_SCHEMA = "mncs-fabric.worker-description.v0.2"
LIVENESS_SCHEMA = "mncs-fabric.worker-liveness.v0.1"
DESCRIPTION_LEASE_SECONDS = 300.0
LIVENESS_STATES = {"AVAILABLE", "UNAVAILABLE", "UNKNOWN"}


def _text(value: object, field: str, maximum: int = 256) -> str:
    if not isinstance(value, str) or not value or len(value) > maximum or "\x00" in value:
        raise ValidationError(f"{field} must be bounded non-empty text")
    return value


def _timestamp(value: object, field: str) -> str:
    _text(value, field, 64)
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValidationError(f"{field} must be an RFC 3339 timestamp") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValidationError(f"{field} must include a timezone")
    return parsed.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def build_worker_description(
    *,
    worker_id: str,
    node: Mapping[str, Any],
    resource_snapshot: Mapping[str, Any],
    runtime_profile: Mapping[str, Any] | None = None,
    captured_at: str | None = None,
) -> dict[str, Any]:
    """Build a fresh, self-identifying worker-owned description."""

    captured = captured_at or utc_now()
    value: dict[str, Any] = {
        "schema_version": DESCRIPTION_SCHEMA,
        "worker_identity": _text(worker_id, "worker_identity"),
        "node": dict(node),
        "resource_snapshot": dict(resource_snapshot),
        "worker_service_version": __version__,
        "protocol_schema": "mncs-fabric.protocol.v0.1",
        "public_contract_identity": build_public_contract(__version__)["contract_identity"],
        "capability_source": "worker-observed",
        "resource_source": "worker-observed",
        "captured_at": _timestamp(captured, "captured_at"),
        "claim_boundary": "authenticated worker report; not attestation, custody, independence, correctness, or conformance",
    }
    value["runtime_profile"] = dict(runtime_profile) if runtime_profile is not None else build_runtime_profile(worker_id)
    return attach_identity(value, "description_identity")


def validate_worker_description(value: object, *, expected_worker_id: str | None = None) -> dict[str, Any]:
    if not isinstance(value, dict) or value.get("schema_version") not in {LEGACY_DESCRIPTION_SCHEMA, DESCRIPTION_SCHEMA}:
        raise ValidationError("unsupported worker description schema")
    required = {
        "schema_version", "worker_identity", "node", "resource_snapshot",
        "worker_service_version", "protocol_schema", "public_contract_identity",
        "capability_source", "resource_source", "captured_at", "claim_boundary",
        "description_identity",
    }
    schema = value["schema_version"]
    expected_fields = required | {"runtime_profile"} if schema == DESCRIPTION_SCHEMA else required
    if set(value) != expected_fields or not verify_identity(value, "description_identity"):
        raise ValidationError("worker description fields or identity are invalid")
    worker_id = _text(value["worker_identity"], "worker_identity")
    if expected_worker_id is not None and worker_id != expected_worker_id:
        raise ValidationError("worker description identity does not match the registered worker")
    node = value["node"]
    if not isinstance(node, dict) or node.get("schema_version") != NODE_SCHEMA or node.get("machine_label") != worker_id or not isinstance(node.get("record_id"), str) or not verify_identity(node, "record_id"):
        raise ValidationError("worker description node binding is invalid")
    snapshot = validate_resource_snapshot(value["resource_snapshot"])
    if snapshot["worker_identity"] != worker_id:
        raise ValidationError("worker description resource snapshot is bound to another worker")
    for field in ("worker_service_version", "protocol_schema", "capability_source", "resource_source", "claim_boundary"):
        _text(value[field], field, 512)
    if value["protocol_schema"] != "mncs-fabric.protocol.v0.1":
        raise ValidationError("worker description protocol schema is unsupported")
    if not is_sha256_identity(value["public_contract_identity"]):
        raise ValidationError("worker description public contract identity is invalid")
    if value["capability_source"] != "worker-observed" or value["resource_source"] != "worker-observed":
        raise ValidationError("worker description observations must identify their source")
    _timestamp(value["captured_at"], "captured_at")
    if schema == DESCRIPTION_SCHEMA:
        validate_runtime_profile(value["runtime_profile"], expected_worker_id=worker_id)
    return dict(value)


def build_liveness_observation(
    *,
    worker_id: str,
    state: str,
    observed_at: str | None,
    description_identity: str | None,
    lease_seconds: float = DESCRIPTION_LEASE_SECONDS,
    last_failure: str | None = None,
) -> dict[str, Any]:
    if state not in LIVENESS_STATES:
        raise ValidationError("worker liveness state is invalid")
    if lease_seconds <= 0 or lease_seconds > 86400:
        raise ValidationError("worker liveness lease is outside its bound")
    value: dict[str, Any] = {
        "schema_version": LIVENESS_SCHEMA,
        "worker_identity": _text(worker_id, "worker_identity"),
        "state": state,
        "observed_at": _timestamp(observed_at or utc_now(), "observed_at"),
        "description_identity": description_identity,
        "lease_seconds": lease_seconds,
        "last_failure": last_failure,
        "claim_boundary": "authenticated contact observation; not continuous availability or worker honesty",
    }
    return attach_identity(value, "liveness_identity")


def validate_liveness(value: object, *, expected_worker_id: str | None = None) -> dict[str, Any]:
    if not isinstance(value, dict) or value.get("schema_version") != LIVENESS_SCHEMA:
        raise ValidationError("unsupported worker liveness schema")
    required = {"schema_version", "worker_identity", "state", "observed_at", "description_identity", "lease_seconds", "last_failure", "claim_boundary", "liveness_identity"}
    if set(value) != required or not verify_identity(value, "liveness_identity"):
        raise ValidationError("worker liveness fields or identity are invalid")
    worker_id = _text(value["worker_identity"], "worker_identity")
    if expected_worker_id is not None and worker_id != expected_worker_id:
        raise ValidationError("worker liveness is bound to another worker")
    if value["state"] not in LIVENESS_STATES:
        raise ValidationError("worker liveness state is invalid")
    _timestamp(value["observed_at"], "observed_at")
    if value["description_identity"] is not None and not is_sha256_identity(value["description_identity"]):
        raise ValidationError("worker liveness description identity is invalid")
    if not isinstance(value["lease_seconds"], (int, float)) or isinstance(value["lease_seconds"], bool) or not 0 < value["lease_seconds"] <= 86400:
        raise ValidationError("worker liveness lease is invalid")
    if value["last_failure"] is not None:
        _text(value["last_failure"], "last_failure", 512)
    _text(value["claim_boundary"], "claim_boundary", 512)
    return dict(value)


def liveness_is_fresh(value: Mapping[str, Any], *, now: str | None = None) -> bool:
    checked = validate_liveness(dict(value))
    if checked["state"] != "AVAILABLE":
        return False
    current = datetime.now(timezone.utc) if now is None else datetime.fromisoformat(now.replace("Z", "+00:00"))
    observed = datetime.fromisoformat(checked["observed_at"].replace("Z", "+00:00"))
    return (current.astimezone(timezone.utc) - observed.astimezone(timezone.utc)).total_seconds() <= float(checked["lease_seconds"])


def worker_description_is_fresh(value: Mapping[str, Any], *, max_age_seconds: float = DESCRIPTION_LEASE_SECONDS, now: str | None = None) -> bool:
    checked = validate_worker_description(dict(value))
    if max_age_seconds < 0:
        raise ValidationError("worker description freshness bound cannot be negative")
    current = datetime.now(timezone.utc) if now is None else datetime.fromisoformat(now.replace("Z", "+00:00"))
    captured = datetime.fromisoformat(checked["captured_at"].replace("Z", "+00:00"))
    return (current.astimezone(timezone.utc) - captured.astimezone(timezone.utc)).total_seconds() <= max_age_seconds
