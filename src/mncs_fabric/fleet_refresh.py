"""Composable fleet-refresh deadlines and classified probe results.

The persistent service frame TTL is a control-plane bound: the controller must
answer ``fleet.refresh`` before that expiry. Worker probes have their own
deadlines. A slow or unreachable worker is classified on that worker; it must
not discard completed probes or turn the service request itself into UNKNOWN.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Iterable, Mapping

from .canonical import attach_identity
from .errors import ValidationError
from .node import utc_now

FLEET_REFRESH_SCHEMA = "mncs-fabric.fleet-refresh.v0.1"
SERVICE_RESPONSE_RESERVE_SECONDS = 1.0
DEFAULT_PER_WORKER_DEADLINE_SECONDS = 5.0
MAX_CONCURRENT_REFRESHES = 16
MIN_WORKER_DEADLINE_SECONDS = 0.05
REFRESH_STATUSES = {"PASS", "TIMEOUT", "UNAVAILABLE", "UNKNOWN"}
DEADLINE_OWNERS = {None, "worker", "operation", "service"}
CLAIM_BOUNDARY = (
    "bounded worker probe result; TIMEOUT retains last-known availability; "
    "not continuous availability, honesty, or capability freshness"
)


def remaining_request_seconds(
    request: Mapping[str, Any], *, now: datetime | None = None
) -> float:
    expires = request.get("expires_at")
    if not isinstance(expires, str):
        raise ValidationError("service request expiry is missing")
    deadline = datetime.fromisoformat(expires.replace("Z", "+00:00"))
    current = now or datetime.now(timezone.utc)
    if current.tzinfo is None or deadline.tzinfo is None:
        raise ValidationError("service request expiry must be timezone-aware")
    return (deadline.astimezone(timezone.utc) - current.astimezone(timezone.utc)).total_seconds()


def operation_deadline_seconds(remaining_ttl: float) -> float:
    remaining = max(0.0, float(remaining_ttl))
    if remaining <= 0:
        return 0.0
    reserve = min(SERVICE_RESPONSE_RESERVE_SECONDS, max(0.05, remaining * 0.1))
    return max(0.0, remaining - reserve)


def per_worker_deadline_seconds(
    *,
    remaining_operation: float | None,
    configured: float | None = None,
    default: float = DEFAULT_PER_WORKER_DEADLINE_SECONDS,
) -> float:
    bound = default if configured is None else float(configured)
    if bound <= 0:
        raise ValidationError("per-worker refresh deadline must be positive")
    if remaining_operation is None:
        return bound
    return max(0.0, min(bound, float(remaining_operation)))


def select_refresh_targets(arguments: Mapping[str, Any] | None) -> list[str] | None:
    args = arguments or {}
    selected: list[str] = []
    worker_id = args.get("worker_id")
    if worker_id is not None:
        if not isinstance(worker_id, str) or not worker_id or len(worker_id) > 128:
            raise ValidationError("worker_id is invalid")
        selected.append(worker_id)
    worker_ids = args.get("worker_ids")
    if worker_ids is not None:
        if not isinstance(worker_ids, list) or len(worker_ids) > 128:
            raise ValidationError("worker_ids is invalid")
        for item in worker_ids:
            if not isinstance(item, str) or not item or len(item) > 128:
                raise ValidationError("worker_ids is invalid")
            if item not in selected:
                selected.append(item)
    return selected or None


def classify_refresh_outcome(workers: Iterable[Mapping[str, Any]]) -> str:
    statuses = [str(worker.get("refresh") or "UNKNOWN") for worker in workers]
    if not statuses or all(status == "PASS" for status in statuses):
        return "PASS"
    if all(status in {"PASS", "UNAVAILABLE"} for status in statuses):
        return "PASS"
    if any(status in {"PASS", "UNAVAILABLE"} for status in statuses):
        return "PARTIAL"
    return "UNKNOWN"


def project_runtime_identity(worker: Mapping[str, Any]) -> dict[str, Any]:
    description = worker.get("description") if isinstance(worker.get("description"), dict) else {}
    projected: dict[str, Any] = {}
    version = worker.get("worker_service_version") or description.get("worker_service_version")
    captured = worker.get("description_captured_at") or description.get("captured_at")
    if version:
        projected["worker_service_version"] = version
    if captured:
        projected["description_captured_at"] = captured
    identity = worker.get("runtime_identity") or description.get("runtime_identity")
    if isinstance(identity, dict):
        projected["runtime_identity"] = dict(identity)
        if identity.get("source_commit"):
            projected["worker_source_commit"] = identity.get("source_commit")
        if identity.get("artifact_digest"):
            projected["worker_artifact_digest"] = identity.get("artifact_digest")
    return projected


def annotate_refresh(
    state: Mapping[str, Any],
    *,
    status: str,
    deadline_fired: str | None = None,
    diagnostic: str | None = None,
    refresh_generation: str | None = None,
) -> dict[str, Any]:
    if status not in REFRESH_STATUSES:
        raise ValidationError("refresh status is invalid")
    if deadline_fired not in DEADLINE_OWNERS:
        raise ValidationError("refresh deadline owner is invalid")
    annotated = dict(state)
    annotated["refresh"] = status
    annotated["deadline_fired"] = deadline_fired
    annotated.update(project_runtime_identity(annotated))
    if diagnostic:
        annotated["refresh_diagnostic"] = str(diagnostic)[:512]
    if refresh_generation:
        annotated["refresh_generation"] = refresh_generation
    return annotated


def build_refresh_generation(worker_ids: Iterable[str], *, started_at: str | None = None) -> dict[str, Any]:
    return attach_identity(
        {
            "schema_version": FLEET_REFRESH_SCHEMA,
            "started_at": started_at or utc_now(),
            "worker_ids": list(worker_ids),
        },
        "refresh_generation",
    )


def build_refresh_report(
    workers: list[Mapping[str, Any]],
    *,
    observation_mode: str = "probed",
    generation: Mapping[str, Any] | None = None,
    service_deadline_seconds: float | None = None,
    operation_deadline_seconds_value: float | None = None,
    per_worker_deadline_seconds_value: float | None = None,
) -> dict[str, Any]:
    classified = [dict(worker) for worker in workers]
    report: dict[str, Any] = {
        "schema_version": FLEET_REFRESH_SCHEMA,
        "outcome": classify_refresh_outcome(classified),
        "observation_mode": observation_mode,
        "claim_boundary": CLAIM_BOUNDARY,
        "workers": classified,
        "refreshed_at": utc_now(),
    }
    if generation is not None:
        report["refresh_generation"] = generation.get("refresh_generation")
        report["refresh_started_at"] = generation.get("started_at")
    if service_deadline_seconds is not None:
        report["service_deadline_seconds"] = float(service_deadline_seconds)
    if operation_deadline_seconds_value is not None:
        report["operation_deadline_seconds"] = float(operation_deadline_seconds_value)
    if per_worker_deadline_seconds_value is not None:
        report["per_worker_deadline_seconds"] = float(per_worker_deadline_seconds_value)
    return report


def merge_refresh_into_workers(
    projected: Iterable[Mapping[str, Any]],
    refreshed: Iterable[Mapping[str, Any]],
) -> list[dict[str, Any]]:
    extras = {
        str(worker.get("worker_id")): dict(worker)
        for worker in refreshed
        if isinstance(worker, dict) and worker.get("worker_id")
    }
    merged: list[dict[str, Any]] = []
    seen: set[str] = set()
    for worker in projected:
        item = dict(worker)
        worker_id = str(item.get("worker_id") or "")
        extra = extras.get(worker_id, {})
        for key in (
            "refresh",
            "deadline_fired",
            "refresh_diagnostic",
            "refresh_generation",
            "worker_service_version",
            "description_captured_at",
        ):
            if key in extra:
                item[key] = extra[key]
        item.update(project_runtime_identity(item))
        merged.append(item)
        if worker_id:
            seen.add(worker_id)
    for worker_id, extra in extras.items():
        if worker_id not in seen:
            item = dict(extra)
            item.update(project_runtime_identity(item))
            merged.append(item)
    return merged
