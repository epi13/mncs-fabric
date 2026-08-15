"""Versioned desired-state documents, reusable worker profiles, and diffs.

Desired state is operator policy.  It is inspectable, identity-addressed, and
never interpreted as a shell script.  Profiles compose; worker assignments may
override profile requirements without becoming machine-name special cases.
"""

from __future__ import annotations

from typing import Any, Iterable, Mapping

from .canonical import attach_identity, verify_identity
from .errors import ValidationError
from .inventory import (
    UPDATE_CLASSES,
    inventory_runtime,
    inventory_service,
    inventory_tool,
    validate_worker_inventory,
)
from .node import utc_now

DESIRED_STATE_SCHEMA = "mncs-fabric.desired-state.v0.1"
PROFILE_SCHEMA = "mncs-fabric.worker-profile.v0.1"
DIFF_SCHEMA = "mncs-fabric.desired-state-diff.v0.1"
REQUIREMENT_LEVELS = frozenset({"present", "supported-current", "mncs-supported", "running", "absent"})
REQUIREMENT_KINDS = frozenset({"tool", "runtime", "service", "model", "package", "config"})
OS_UPDATE_POLICIES = frozenset({"none", "security", "manual"})
MAX_PROFILES = 8
MAX_REQUIREMENTS = 64
MAX_MODELS = 32

PROFILE_CATALOG: dict[str, dict[str, Any]] = {
    "mncs-linux-worker": {
        "summary": "Baseline Linux MNCS worker host",
        "requirements": (
            {"kind": "package", "name": "fabric-worker", "update_class": "A", "level": "supported-current"},
            {"kind": "package", "name": "local-harness", "update_class": "A", "level": "present"},
            {"kind": "tool", "name": "git", "update_class": "B", "level": "present"},
            {"kind": "tool", "name": "gh", "update_class": "B", "level": "supported-current"},
            {"kind": "tool", "name": "python", "update_class": "B", "level": "present"},
            {"kind": "service", "name": "fabric-worker", "update_class": "E", "level": "running"},
        ),
        "os_updates": "security",
    },
    "mncs-windows-worker": {
        "summary": "Baseline Windows MNCS worker host",
        "requirements": (
            {"kind": "package", "name": "fabric-worker", "update_class": "A", "level": "supported-current"},
            {"kind": "package", "name": "local-harness", "update_class": "A", "level": "present"},
            {"kind": "tool", "name": "git", "update_class": "B", "level": "present"},
            {"kind": "tool", "name": "gh", "update_class": "B", "level": "supported-current"},
            {"kind": "tool", "name": "python", "update_class": "B", "level": "present"},
            {"kind": "service", "name": "fabric-worker", "update_class": "E", "level": "running"},
        ),
        "os_updates": "security",
    },
    "mncs-inference-worker": {
        "summary": "Model-agnostic local inference worker",
        "requirements": (
            {"kind": "runtime", "name": "ollama", "update_class": "C", "level": "mncs-supported"},
            {"kind": "service", "name": "ollama", "update_class": "C", "level": "running"},
        ),
        "os_updates": "security",
    },
    "mncs-build-worker": {
        "summary": "Compilation and repository-analysis worker",
        "requirements": (
            {"kind": "tool", "name": "git", "update_class": "B", "level": "present"},
            {"kind": "tool", "name": "gcc", "update_class": "B", "level": "present"},
            {"kind": "tool", "name": "rustc", "update_class": "B", "level": "present"},
            {"kind": "tool", "name": "cargo", "update_class": "B", "level": "present"},
            {"kind": "tool", "name": "joern", "update_class": "B", "level": "mncs-supported"},
            {"kind": "tool", "name": "forge", "update_class": "B", "level": "mncs-supported"},
        ),
        "os_updates": "security",
    },
    "mncs-ravel-worker": {
        "summary": "RAVEL-oriented Linux build worker",
        "requirements": (
            {"kind": "package", "name": "fabric-worker", "update_class": "A", "level": "supported-current"},
            {"kind": "tool", "name": "git", "update_class": "B", "level": "present"},
            {"kind": "tool", "name": "python", "update_class": "B", "level": "present"},
        ),
        "os_updates": "security",
    },
    "mncs-mnel-worker": {
        "summary": "MNEL-oriented inference-capable worker",
        "requirements": (
            {"kind": "package", "name": "fabric-worker", "update_class": "A", "level": "supported-current"},
            {"kind": "runtime", "name": "ollama", "update_class": "C", "level": "mncs-supported"},
        ),
        "os_updates": "security",
    },
}


def _text(value: object, field: str, maximum: int = 256) -> str:
    if not isinstance(value, str) or not value or len(value) > maximum or "\x00" in value:
        raise ValidationError(f"{field} must be bounded non-empty text")
    return value


def _optional_text(value: object, field: str, maximum: int = 256) -> str | None:
    if value is None:
        return None
    return _text(value, field, maximum)


def known_profiles() -> tuple[str, ...]:
    return tuple(sorted(PROFILE_CATALOG))


def _requirement(value: Mapping[str, Any]) -> dict[str, Any]:
    allowed = {"kind", "name", "update_class", "level", "version"}
    if set(value) - allowed:
        raise ValidationError("desired-state requirement contains unsupported fields")
    kind = _text(value.get("kind"), "requirement.kind", 32)
    level = _text(value.get("level"), "requirement.level", 32)
    update_class = _text(value.get("update_class"), "requirement.update_class", 1)
    if kind not in REQUIREMENT_KINDS:
        raise ValidationError("desired-state requirement kind is unsupported")
    if level not in REQUIREMENT_LEVELS:
        raise ValidationError("desired-state requirement level is unsupported")
    if update_class not in UPDATE_CLASSES:
        raise ValidationError("desired-state update class is unsupported")
    return {
        "kind": kind,
        "name": _text(value.get("name"), "requirement.name", 128),
        "update_class": update_class,
        "level": level,
        "version": _optional_text(value.get("version"), "requirement.version", 128),
    }


def build_profile(profile_id: str, *, captured_at: str | None = None) -> dict[str, Any]:
    if profile_id not in PROFILE_CATALOG:
        raise ValidationError(f"unknown worker profile: {profile_id}")
    source = PROFILE_CATALOG[profile_id]
    requirements = [_requirement(item) for item in source["requirements"]]
    requirements.sort(key=lambda item: (item["kind"], item["name"]))
    value = {
        "schema_version": PROFILE_SCHEMA,
        "profile_id": profile_id,
        "summary": source["summary"],
        "requirements": requirements,
        "policy": {
            "os_updates": source["os_updates"],
            "auto_apply_classes": ["A", "B", "E"],
            "require_drain": True,
            "require_certification": True,
        },
        "captured_at": captured_at or utc_now(),
        "claim_boundary": "reusable operator profile; not a host identity or attestation",
    }
    return attach_identity(value, "profile_identity")


def validate_profile(value: object) -> dict[str, Any]:
    if not isinstance(value, dict) or value.get("schema_version") != PROFILE_SCHEMA:
        raise ValidationError("unsupported worker profile schema")
    required = {
        "schema_version", "profile_id", "summary", "requirements", "policy",
        "captured_at", "claim_boundary", "profile_identity",
    }
    if set(value) != required or not verify_identity(value, "profile_identity"):
        raise ValidationError("worker profile fields or identity are invalid")
    _text(value["profile_id"], "profile_id", 64)
    _text(value["summary"], "summary", 256)
    if not isinstance(value["requirements"], list) or len(value["requirements"]) > MAX_REQUIREMENTS:
        raise ValidationError("worker profile requirements are invalid")
    [_requirement(item) for item in value["requirements"]]
    _validate_policy(value["policy"])
    return dict(value)


def _validate_policy(value: object) -> dict[str, Any]:
    required = {"os_updates", "auto_apply_classes", "require_drain", "require_certification"}
    if not isinstance(value, dict) or set(value) != required:
        raise ValidationError("desired-state policy fields are invalid")
    if value["os_updates"] not in OS_UPDATE_POLICIES:
        raise ValidationError("os_updates policy is unsupported")
    classes = value["auto_apply_classes"]
    if not isinstance(classes, list) or any(item not in UPDATE_CLASSES for item in classes):
        raise ValidationError("auto_apply_classes is invalid")
    if not isinstance(value["require_drain"], bool) or not isinstance(value["require_certification"], bool):
        raise ValidationError("desired-state policy flags are invalid")
    return {
        "os_updates": value["os_updates"],
        "auto_apply_classes": [str(item) for item in classes],
        "require_drain": value["require_drain"],
        "require_certification": value["require_certification"],
    }


def _merge_requirements(groups: Iterable[Iterable[Mapping[str, Any]]]) -> list[dict[str, Any]]:
    merged: dict[tuple[str, str], dict[str, Any]] = {}
    rank = {"present": 1, "supported-current": 2, "mncs-supported": 3, "running": 4, "absent": 5}
    for group in groups:
        for item in group:
            requirement = _requirement(item)
            key = (requirement["kind"], requirement["name"])
            current = merged.get(key)
            if current is None or rank[requirement["level"]] >= rank[current["level"]]:
                merged[key] = requirement
    return [merged[key] for key in sorted(merged)]


def resolve_desired_state(
    *,
    worker_id: str,
    profiles: Iterable[str],
    overrides: Iterable[Mapping[str, Any]] | None = None,
    models: Mapping[str, Mapping[str, Any]] | None = None,
    supported_current: Mapping[str, str] | None = None,
    captured_at: str | None = None,
) -> dict[str, Any]:
    names = [_text(name, "profiles[]", 64) for name in profiles]
    if not names or len(names) > MAX_PROFILES:
        raise ValidationError("desired state requires a bounded non-empty profile list")
    if len(set(names)) != len(names):
        raise ValidationError("desired-state profiles must be unique")
    unknown = [name for name in names if name not in PROFILE_CATALOG]
    if unknown:
        raise ValidationError("unknown worker profile: " + ",".join(unknown))
    loaded = [build_profile(name, captured_at=captured_at) for name in names]
    requirements = _merge_requirements([profile["requirements"] for profile in loaded] + [overrides or ()])
    model_requirements: list[dict[str, Any]] = []
    for name, spec in sorted((models or {}).items()):
        if not isinstance(spec, Mapping):
            raise ValidationError("model desired-state entry must be an object")
        model_requirements.append(
            _requirement(
                {
                    "kind": "model",
                    "name": name,
                    "update_class": spec.get("update_class", "C"),
                    "level": spec.get("state") or spec.get("level") or "present",
                    "version": spec.get("version"),
                }
            )
        )
        if len(model_requirements) > MAX_MODELS:
            raise ValidationError("desired-state model list exceeds its bound")
    requirements = _merge_requirements([requirements, model_requirements])
    policy = {
        "os_updates": loaded[-1]["policy"]["os_updates"],
        "auto_apply_classes": list(loaded[-1]["policy"]["auto_apply_classes"]),
        "require_drain": any(profile["policy"]["require_drain"] for profile in loaded),
        "require_certification": any(profile["policy"]["require_certification"] for profile in loaded),
    }
    versions = dict(supported_current or {})
    value = {
        "schema_version": DESIRED_STATE_SCHEMA,
        "worker_identity": _text(worker_id, "worker_identity"),
        "profiles": names,
        "profile_identities": [profile["profile_identity"] for profile in loaded],
        "requirements": requirements,
        "supported_current": {key: _text(item, f"supported_current.{key}", 128) for key, item in sorted(versions.items())},
        "policy": policy,
        "captured_at": captured_at or utc_now(),
        "claim_boundary": "operator-declared desired state; not a command interpreter or attestation",
    }
    return attach_identity(value, "desired_state_identity")


def validate_desired_state(value: object, *, expected_worker_id: str | None = None) -> dict[str, Any]:
    if not isinstance(value, dict) or value.get("schema_version") != DESIRED_STATE_SCHEMA:
        raise ValidationError("unsupported desired-state schema")
    required = {
        "schema_version", "worker_identity", "profiles", "profile_identities",
        "requirements", "supported_current", "policy", "captured_at",
        "claim_boundary", "desired_state_identity",
    }
    if set(value) != required or not verify_identity(value, "desired_state_identity"):
        raise ValidationError("desired-state fields or identity are invalid")
    worker_id = _text(value["worker_identity"], "worker_identity")
    if expected_worker_id is not None and worker_id != expected_worker_id:
        raise ValidationError("desired state is bound to another worker")
    if not isinstance(value["profiles"], list) or not value["profiles"] or len(value["profiles"]) > MAX_PROFILES:
        raise ValidationError("desired-state profiles are invalid")
    if not isinstance(value["requirements"], list) or len(value["requirements"]) > MAX_REQUIREMENTS:
        raise ValidationError("desired-state requirements are invalid")
    [_requirement(item) for item in value["requirements"]]
    if not isinstance(value["supported_current"], dict):
        raise ValidationError("supported_current must be an object")
    _validate_policy(value["policy"])
    return dict(value)


def default_profiles_for_platform(platform_name: str) -> tuple[str, ...]:
    if platform_name.lower() == "windows":
        return ("mncs-windows-worker",)
    return ("mncs-linux-worker",)


def _actual_for(inventory: Mapping[str, Any], requirement: Mapping[str, Any]) -> tuple[str, str]:
    kind = requirement["kind"]
    name = requirement["name"]
    if kind == "tool":
        tool = inventory_tool(inventory, name)
        if tool is None or not tool.get("present"):
            return "absent", "tool not present"
        if requirement["level"] in {"supported-current", "mncs-supported"} and not tool.get("version"):
            return "present-unversioned", "tool present without a version"
        return "present", tool.get("version") or "present"
    if kind == "runtime":
        runtime = inventory_runtime(inventory, name)
        if runtime is None or not runtime.get("present"):
            return "absent", "runtime not present"
        if requirement["level"] == "running" and not runtime.get("reachable"):
            return "present-unreachable", "runtime present but endpoint is not reachable"
        if requirement["level"] == "mncs-supported" and not runtime.get("reachable"):
            return "present-unverified", "runtime present but not verified reachable"
        return "present", runtime.get("version") or runtime.get("service_type") or "present"
    if kind == "service":
        service = inventory_service(inventory, name)
        if service is None or not service.get("present"):
            return "absent", "service not discovered"
        if requirement["level"] == "running" and service.get("state") != "running":
            return service.get("state") or "unknown", f"service manager={service.get('manager')}"
        return service.get("state") or "present", f"manager={service.get('manager')}"
    if kind == "model":
        runtime = inventory_runtime(inventory, "ollama")
        names = [item.get("name") for item in (runtime or {}).get("models", [])]
        present = any(isinstance(item, str) and (item == name or item.startswith(name + ":")) for item in names)
        return ("present", name) if present else ("absent", "model not in runtime inventory")
    if kind == "package":
        fabric = inventory.get("fabric", {})
        if name == "fabric-worker":
            version = fabric.get("worker_version")
            desired = requirement.get("version") or inventory.get("_supported_current", {}).get("fabric-worker")
            if not version:
                return "absent", "fabric worker version unknown"
            if requirement["level"] == "supported-current" and desired and version != desired:
                return "version-drift", f"{version} != {desired}"
            return version, "installed"
        if name == "local-harness":
            version = fabric.get("harness_version")
            return (version or "absent", "harness package") if version else ("absent", "harness package not importable")
        return "unknown", "package observation is not implemented"
    if kind == "config":
        return "unknown", "configuration observation is provider-specific"
    return "unknown", "requirement kind has no inspector"


def diff_desired_state(
    desired: Mapping[str, Any],
    inventory: Mapping[str, Any],
    *,
    classes: Iterable[str] | None = None,
) -> dict[str, Any]:
    checked_desired = validate_desired_state(desired, expected_worker_id=str(inventory.get("worker_identity")) if inventory.get("worker_identity") else None)
    checked_inventory = validate_worker_inventory(inventory, expected_worker_id=checked_desired["worker_identity"])
    allowed = set(classes) if classes is not None else set(UPDATE_CLASSES)
    if allowed - UPDATE_CLASSES:
        raise ValidationError("diff update class filter is invalid")
    changes: list[dict[str, Any]] = []
    annotated = dict(checked_inventory)
    annotated["_supported_current"] = checked_desired["supported_current"]
    for requirement in checked_desired["requirements"]:
        if requirement["update_class"] not in allowed:
            continue
        actual, detail = _actual_for(annotated, requirement)
        compliant = _is_compliant(requirement, actual)
        if compliant:
            continue
        desired_value = requirement["level"] if requirement["version"] is None else f"{requirement['level']}:{requirement['version']}"
        if requirement["kind"] == "package" and requirement["name"] == "fabric-worker":
            pin = requirement.get("version") or annotated.get("_supported_current", {}).get("fabric-worker")
            if pin:
                desired_value = str(pin)
        changes.append(
            {
                "kind": requirement["kind"],
                "name": requirement["name"],
                "update_class": requirement["update_class"],
                "desired": desired_value,
                "actual": actual,
                "detail": detail[:256],
                "authorization": _authorization_for(requirement, actual),
            }
        )
    value = {
        "schema_version": DIFF_SCHEMA,
        "worker_identity": checked_desired["worker_identity"],
        "desired_state_identity": checked_desired["desired_state_identity"],
        "inventory_identity": checked_inventory["inventory_identity"],
        "change_count": len(changes),
        "changes": changes,
        "compliant": not changes,
        "captured_at": utc_now(),
        "claim_boundary": "deterministic desired-versus-actual comparison; not a repair or attestation",
    }
    return attach_identity(value, "diff_identity")


def _is_compliant(requirement: Mapping[str, Any], actual: str) -> bool:
    level = requirement["level"]
    if level == "absent":
        return actual == "absent"
    if actual == "absent":
        return False
    if actual == "version-drift":
        return False
    if level == "running":
        return actual == "running" or actual == "present"
    if level in {"present", "supported-current", "mncs-supported"}:
        return actual not in {"absent", "present-unverified", "present-unreachable", "version-drift"}
    return False


def _authorization_for(requirement: Mapping[str, Any], actual: str) -> str:
    if requirement["update_class"] == "D":
        return "privilege"
    if requirement["kind"] == "package" and requirement["name"] == "fabric-worker" and actual not in {"absent"}:
        return "operator"
    if requirement["kind"] in {"tool", "package"} and actual == "absent":
        return "privilege"
    if requirement["kind"] == "model":
        return "operator"
    return "none"


def validate_diff(value: object) -> dict[str, Any]:
    if not isinstance(value, dict) or value.get("schema_version") != DIFF_SCHEMA:
        raise ValidationError("unsupported desired-state diff schema")
    required = {
        "schema_version", "worker_identity", "desired_state_identity",
        "inventory_identity", "change_count", "changes", "compliant",
        "captured_at", "claim_boundary", "diff_identity",
    }
    if set(value) != required or not verify_identity(value, "diff_identity"):
        raise ValidationError("desired-state diff fields or identity are invalid")
    if not isinstance(value["changes"], list) or value["change_count"] != len(value["changes"]):
        raise ValidationError("desired-state diff change count is inconsistent")
    return dict(value)
