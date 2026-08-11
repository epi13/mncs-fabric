"""Provider-neutral, identity-addressed worker capability observations.

Capability observations are authenticated/registered-worker facts supplied to
Fabric by a consumer or bounded probe.  They are not attestations,
authorizations, placement decisions, or semantic recommendations.
"""

from __future__ import annotations

import re
from math import isfinite
from datetime import datetime, timezone
from typing import Any, Iterable, Mapping

from .canonical import attach_identity, canonical_json_bytes, verify_identity
from .errors import ValidationError
from .node import utc_now

CAPABILITY_OBSERVATION_SCHEMA = "mncs-fabric.worker-capability-observation.v0.1"
CAPABILITY_KINDS = frozenset({"model", "runtime", "tool", "mcp", "service", "other"})
CAPABILITY_AVAILABILITY = frozenset({"AVAILABLE", "UNAVAILABLE", "UNKNOWN"})
CAPABILITY_CLAIM_BOUNDARY = (
    "identity-bound capability observation supplied by an authenticated or "
    "registered worker workflow; not attestation, authorization, availability "
    "guarantee, semantic suitability, correctness, or conformance"
)
MAX_CAPABILITY_AGE_SECONDS = 300.0
MAX_CAPABILITY_ENTRIES = 256
MAX_CAPABILITY_ATTRIBUTES = 24
MAX_ATTRIBUTE_LIST_ITEMS = 32
MAX_CAPABILITY_OBSERVATION_BYTES = 256 * 1024
MAX_FUTURE_SKEW_SECONDS = 60.0
_ATTRIBUTE_KEY = re.compile(r"^[a-z][a-z0-9_.-]{0,63}$")


def _text(value: object, field: str, maximum: int = 256) -> str:
    if not isinstance(value, str) or not value or len(value) > maximum:
        raise ValidationError(f"{field} must be bounded non-empty text")
    if any(ord(character) < 32 or 127 <= ord(character) <= 159 for character in value):
        raise ValidationError(f"{field} must not contain control characters")
    return value


def _optional_text(value: object, field: str, maximum: int = 256) -> str | None:
    if value is None:
        return None
    return _text(value, field, maximum)


def _timestamp(value: object) -> str:
    _text(value, "captured_at", 64)
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValidationError("captured_at must be an RFC 3339 timestamp") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValidationError("captured_at must include a timezone")
    return parsed.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _attribute_value(value: object, field: str) -> str | int | bool | None | list[str]:
    if value is None or isinstance(value, bool):
        return value
    if isinstance(value, int):
        if value < 0 or value > 2**63 - 1:
            raise ValidationError(f"{field} integer is outside the bounded range")
        return value
    if isinstance(value, str):
        return _text(value, field, 512)
    if isinstance(value, (list, tuple)):
        if len(value) > MAX_ATTRIBUTE_LIST_ITEMS:
            raise ValidationError(f"{field} list exceeds the item bound")
        items = [_text(item, field, 256) for item in value]
        if len(set(items)) != len(items):
            raise ValidationError(f"{field} list items must be unique")
        return sorted(items)
    raise ValidationError(f"{field} must be a bounded JSON scalar or string list")


def _normalize_attributes(value: object) -> dict[str, Any]:
    if not isinstance(value, Mapping) or len(value) > MAX_CAPABILITY_ATTRIBUTES:
        raise ValidationError("capability attributes must be a bounded object")
    normalized: dict[str, Any] = {}
    for raw_key, raw_value in value.items():
        if not isinstance(raw_key, str) or not _ATTRIBUTE_KEY.fullmatch(raw_key):
            raise ValidationError("capability attribute names must use the bounded factual namespace")
        normalized[raw_key] = _attribute_value(raw_value, f"attributes.{raw_key}")
    return normalized


def build_capability_entry(value: Mapping[str, Any]) -> dict[str, Any]:
    """Build one generic factual capability entry with a canonical identity."""

    if not isinstance(value, Mapping):
        raise ValidationError("capability entry must be an object")
    allowed = {"kind", "namespace", "name", "version", "subject_identity", "attributes"}
    if set(value) - allowed:
        raise ValidationError("capability entry contains unsupported fields")
    kind = _text(value.get("kind"), "kind", 32)
    if kind not in CAPABILITY_KINDS:
        raise ValidationError("capability kind is unsupported")
    entry: dict[str, Any] = {
        "kind": kind,
        "namespace": _text(value.get("namespace"), "namespace", 128),
        "name": _text(value.get("name"), "name", 256),
        "version": _optional_text(value.get("version"), "version", 128),
        "subject_identity": _optional_text(
            value.get("subject_identity"), "subject_identity", 256
        ),
        "attributes": _normalize_attributes(value.get("attributes", {})),
    }
    return attach_identity(entry, "capability_identity")


def validate_capability_entry(value: object) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ValidationError("capability entry must be an object")
    required = {
        "kind", "namespace", "name", "version", "subject_identity", "attributes",
        "capability_identity",
    }
    if set(value) != required or not verify_identity(value, "capability_identity"):
        raise ValidationError("capability entry fields or identity are invalid")
    rebuilt = build_capability_entry(
        {key: value[key] for key in required if key != "capability_identity"}
    )
    if rebuilt != value:
        raise ValidationError("capability entry is not canonically normalized")
    return dict(value)


def build_capability_observation(
    *,
    worker_identity: str,
    capabilities: Iterable[Mapping[str, Any]],
    availability: str = "AVAILABLE",
    captured_at: str | None = None,
    observation_source: str = "consumer-bounded-worker-probe",
    status_reason: str | None = None,
) -> dict[str, Any]:
    """Build a bounded observation for exactly one worker identity."""

    worker = _text(worker_identity, "worker_identity")
    if availability not in CAPABILITY_AVAILABILITY:
        raise ValidationError("capability observation availability is invalid")
    entries: list[dict[str, Any]] = []
    for index, item in enumerate(capabilities):
        if index >= MAX_CAPABILITY_ENTRIES:
            raise ValidationError("capability observation exceeds the entry bound")
        entries.append(build_capability_entry(item))
    if availability != "AVAILABLE" and entries:
        raise ValidationError("unavailable or unknown observations cannot claim capabilities")
    entries.sort(key=lambda item: canonical_json_bytes(item))
    identities = [item["capability_identity"] for item in entries]
    if len(set(identities)) != len(identities):
        raise ValidationError("capability observation entries must be unique")
    value: dict[str, Any] = {
        "schema_version": CAPABILITY_OBSERVATION_SCHEMA,
        "worker_identity": worker,
        "availability": availability,
        "capabilities": entries,
        "captured_at": _timestamp(captured_at or utc_now()),
        "observation_source": _text(observation_source, "observation_source", 256),
        "status_reason": _optional_text(status_reason, "status_reason", 512),
        "attestation": "NOT_ASSERTED",
        "claim_boundary": CAPABILITY_CLAIM_BOUNDARY,
    }
    observed = attach_identity(value, "capability_observation_identity")
    if len(canonical_json_bytes(observed)) > MAX_CAPABILITY_OBSERVATION_BYTES:
        raise ValidationError("capability observation exceeds the encoded-size bound")
    return observed


def validate_capability_observation(
    value: object,
    *,
    expected_worker_id: str | None = None,
) -> dict[str, Any]:
    if not isinstance(value, dict) or value.get("schema_version") != CAPABILITY_OBSERVATION_SCHEMA:
        raise ValidationError("unsupported capability observation schema")
    required = {
        "schema_version", "worker_identity", "availability", "capabilities", "captured_at",
        "observation_source", "status_reason", "attestation", "claim_boundary",
        "capability_observation_identity",
    }
    if set(value) != required or not verify_identity(value, "capability_observation_identity"):
        raise ValidationError("capability observation fields or identity are invalid")
    if len(canonical_json_bytes(value)) > MAX_CAPABILITY_OBSERVATION_BYTES:
        raise ValidationError("capability observation exceeds the encoded-size bound")
    worker = _text(value["worker_identity"], "worker_identity")
    if expected_worker_id is not None and worker != expected_worker_id:
        raise ValidationError("capability observation is bound to another worker")
    availability = value["availability"]
    if availability not in CAPABILITY_AVAILABILITY:
        raise ValidationError("capability observation availability is invalid")
    if not isinstance(value["capabilities"], list) or len(value["capabilities"]) > MAX_CAPABILITY_ENTRIES:
        raise ValidationError("capability observation entries are invalid")
    entries = [validate_capability_entry(item) for item in value["capabilities"]]
    if availability != "AVAILABLE" and entries:
        raise ValidationError("unavailable or unknown observations cannot claim capabilities")
    if entries != sorted(entries, key=lambda item: canonical_json_bytes(item)):
        raise ValidationError("capability observation entries are not canonically ordered")
    identities = [item["capability_identity"] for item in entries]
    if len(set(identities)) != len(identities):
        raise ValidationError("capability observation entries must be unique")
    _timestamp(value["captured_at"])
    _text(value["observation_source"], "observation_source", 256)
    _optional_text(value["status_reason"], "status_reason", 512)
    if value["attestation"] != "NOT_ASSERTED":
        raise ValidationError("capability observations cannot assert attestation")
    if value["claim_boundary"] != CAPABILITY_CLAIM_BOUNDARY:
        raise ValidationError("capability observation claim boundary is invalid")
    return dict(value)


def capability_observation_is_fresh(
    value: Mapping[str, Any],
    *,
    max_age_seconds: float = MAX_CAPABILITY_AGE_SECONDS,
    now: str | None = None,
) -> bool:
    checked = validate_capability_observation(dict(value))
    if (
        isinstance(max_age_seconds, bool)
        or not isinstance(max_age_seconds, (int, float))
        or not isfinite(max_age_seconds)
        or max_age_seconds < 0
        or max_age_seconds > 86400
    ):
        raise ValidationError("capability freshness bound is outside the supported range")
    current = (
        datetime.now(timezone.utc)
        if now is None
        else datetime.fromisoformat(_timestamp(now).replace("Z", "+00:00"))
    )
    captured = datetime.fromisoformat(checked["captured_at"].replace("Z", "+00:00"))
    age = (current - captured.astimezone(timezone.utc)).total_seconds()
    return -MAX_FUTURE_SKEW_SECONDS <= age <= max_age_seconds
