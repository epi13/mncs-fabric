"""Typed, identity-addressed references for consumer-authorized execution targets.

The reference records where an already approved bounded workload must run and
which factual capabilities it requires.  It does not choose tools, grant model
requests authority, or permit shell/SSH fallback.
"""

from __future__ import annotations

from dataclasses import dataclass
import re
from typing import Any, Iterable

from .canonical import is_sha256_identity, sha256_identity, verify_identity
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
    """One exact worker target selected and authorized by a consumer policy."""

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
