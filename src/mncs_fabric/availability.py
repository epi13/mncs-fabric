"""Operator-declared worker availability windows.

This is permission to accept work, not a command to execute something.
Schedules are never hardcoded; operators supply policy. Overnight windows
may wrap midnight.
"""

from __future__ import annotations

from datetime import datetime, time, timezone
from typing import Any, Mapping

from .errors import ValidationError

AVAILABILITY_POLICY_SCHEMA = "mncs-fabric.availability-policy.v0.1"
_DAYS = ("mon", "tue", "wed", "thu", "fri", "sat", "sun")
_WEEKDAY = {name: index for index, name in enumerate(_DAYS)}


def _parse_clock(value: object, field: str) -> time:
    if not isinstance(value, str) or len(value) > 8:
        raise ValidationError(f"{field} must be HH:MM")
    try:
        hour, minute = value.split(":", 1)
        parsed = time(int(hour), int(minute), tzinfo=None)
    except ValueError as exc:
        raise ValidationError(f"{field} must be HH:MM") from exc
    return parsed


def _timezone(name: str):
    """Resolve a timezone without requiring tzdata for UTC.

    Windows CI images often lack the IANA database. UTC is a first-class
    datetime timezone and must not depend on ZoneInfo/tzdata.
    """

    if name.upper() == "UTC":
        return timezone.utc
    try:
        from zoneinfo import ZoneInfo

        return ZoneInfo(name)
    except Exception as exc:
        raise ValidationError("availability timezone is unknown") from exc


def validate_availability_policy(value: object) -> dict[str, Any]:
    if not isinstance(value, Mapping) or value.get("schema_version") != AVAILABILITY_POLICY_SCHEMA:
        raise ValidationError("availability policy schema is unsupported")
    timezone_name = value.get("timezone", "UTC")
    if not isinstance(timezone_name, str) or not timezone_name:
        raise ValidationError("availability timezone is invalid")
    _timezone(timezone_name)
    workers = value.get("workers")
    if not isinstance(workers, dict):
        raise ValidationError("availability policy workers must be an object")
    checked: dict[str, Any] = {}
    for worker_id, spec in workers.items():
        if not isinstance(worker_id, str) or not worker_id or not isinstance(spec, Mapping):
            raise ValidationError("availability worker entry is invalid")
        windows = spec.get("windows", [])
        if not isinstance(windows, list):
            raise ValidationError(f"{worker_id} windows must be an array")
        normalized_windows = []
        for window in windows:
            if not isinstance(window, Mapping):
                raise ValidationError(f"{worker_id} window is invalid")
            days = window.get("days")
            if not isinstance(days, list) or not days or any(day not in _WEEKDAY for day in days):
                raise ValidationError(f"{worker_id} window days are invalid")
            start = _parse_clock(window.get("start"), f"{worker_id}.start")
            end = _parse_clock(window.get("end"), f"{worker_id}.end")
            normalized_windows.append(
                {
                    "days": [str(day) for day in days],
                    "start": start.strftime("%H:%M"),
                    "end": end.strftime("%H:%M"),
                }
            )
        classes = spec.get("allowed_workload_classes", [])
        if classes is None:
            classes = []
        if not isinstance(classes, list) or any(not isinstance(item, str) for item in classes):
            raise ValidationError(f"{worker_id} allowed_workload_classes are invalid")
        checked[worker_id] = {
            "windows": normalized_windows,
            "paused": bool(spec.get("paused", False)),
            "allowed_workload_classes": [str(item) for item in classes],
        }
    return {
        "schema_version": AVAILABILITY_POLICY_SCHEMA,
        "timezone": timezone_name,
        "paused": bool(value.get("paused", False)),
        "workers": checked,
    }


def _clock_minutes(value: time) -> int:
    return value.hour * 60 + value.minute


def window_contains(start: time, end: time, current: time) -> bool:
    now = _clock_minutes(current)
    begin = _clock_minutes(start)
    finish = _clock_minutes(end)
    if begin == finish:
        return True
    if begin < finish:
        return begin <= now < finish
    return now >= begin or now < finish


def evaluate_availability(
    policy: Mapping[str, Any],
    worker_id: str,
    *,
    now: datetime | None = None,
    workload_class: str | None = None,
) -> dict[str, Any]:
    checked = validate_availability_policy(policy)
    if checked.get("paused"):
        return {"eligible": False, "reason": "OPERATOR_PAUSE", "worker_id": worker_id}
    spec = checked["workers"].get(worker_id)
    if spec is None:
        return {"eligible": False, "reason": "NO_AVAILABILITY_POLICY", "worker_id": worker_id}
    if spec.get("paused"):
        return {"eligible": False, "reason": "WORKER_PAUSE", "worker_id": worker_id}
    allowed = spec.get("allowed_workload_classes") or []
    if workload_class and allowed and workload_class not in allowed:
        return {"eligible": False, "reason": "WORKLOAD_CLASS_DENIED", "worker_id": worker_id}
    zone = _timezone(checked["timezone"])
    current = (now or datetime.now(timezone.utc)).astimezone(zone)
    weekday = _DAYS[current.weekday()]
    clock = time(current.hour, current.minute)
    for window in spec["windows"]:
        if weekday not in window["days"]:
            continue
        start = _parse_clock(window["start"], "start")
        end = _parse_clock(window["end"], "end")
        if window_contains(start, end, clock):
            return {
                "eligible": True,
                "reason": "INSIDE_WINDOW",
                "worker_id": worker_id,
                "timezone": checked["timezone"],
                "local_time": current.isoformat(),
            }
    return {
        "eligible": False,
        "reason": "OUTSIDE_WINDOW",
        "worker_id": worker_id,
        "timezone": checked["timezone"],
        "local_time": current.isoformat(),
    }
