"""Typed capability brokerage for privileged worker operations.

The broker is deliberately an intent boundary.  It accepts versioned,
structured requests and dispatches them to a platform adapter; it never
accepts a command string, a shell fragment, or a caller supplied executable.

The module is usable in-process for tests and worker services.  The existing
Fabric protocol carries the same request/result contracts when a broker is
attached to a worker.  A protected profile can be broad without becoming a
root shell: every operation still has a fixed operation schema, a host policy,
and (for destructive operations) a bounded capability lease.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import socket
import stat
import struct
import subprocess
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from threading import Event
from typing import Any, Protocol

from .canonical import attach_identity, canonical_json_bytes, is_sha256_identity, verify_identity
from .errors import ProtocolError, StorageError, ValidationError
from .node import utc_now
from .store import FabricLedger, iter_ledger_records


CAPABILITY_REQUEST_SCHEMA = "mncs-fabric.capability-request.v0.1"
CAPABILITY_RESULT_SCHEMA = "mncs-fabric.capability-result.v0.1"
CAPABILITY_LEASE_SCHEMA = "mncs-fabric.capability-lease.v0.1"
CAPABILITY_AUDIT_SCHEMA = "mncs-fabric.capability-audit.v0.1"
CAPABILITY_RECONCILE_SCHEMA = "mncs-fabric.capability-reconcile-result.v0.1"
PRIVILEGE_PROFILE_SCHEMA = "mncs-fabric.host-privilege-profile.v0.1"
EXPERIMENT_REQUIREMENTS_SCHEMA = "mncs-fabric.experiment-requirements.v0.1"
CAPABILITY_BROKER_PROTOCOL = "mncs-fabric.capability-broker.v0.1"

MAX_REQUEST_BYTES = 256 * 1024
MAX_ARGUMENT_BYTES = 32 * 1024
MAX_PACKAGE_COUNT = 64
MAX_PACKAGE_NAME = 128
MAX_SERVICE_NAME = 128
MAX_PATH_TEXT = 512
MAX_LEASE_SECONDS = 24 * 60 * 60
MAX_AUDIT_OUTPUT = 4096

CAPABILITY_FAMILIES = frozenset(
    {
        "package-management",
        "service-management",
        "system-reboot",
        "system-shutdown",
        "kernel-parameter-management",
        "kernel-module-management",
        "performance-counters",
        "ebpf",
        "device-access",
        "mount-management",
        "namespace-management",
        "cgroup-management",
        "experiment-directory-management",
        "experiment-user-management",
        "container-management",
        "driver-management",
        "firewall-management",
        "boot-management",
        "hardware-observation",
        "system-observation",
    }
)

CAPABILITY_OPERATIONS: dict[str, frozenset[str]] = {
    "package-management": frozenset({"install", "remove", "query", "refresh"}),
    "service-management": frozenset({"start", "stop", "restart", "enable", "disable", "status"}),
    "system-reboot": frozenset({"request"}),
    "system-shutdown": frozenset({"request"}),
    "kernel-parameter-management": frozenset({"get", "set"}),
    "kernel-module-management": frozenset({"load", "unload", "status"}),
    "performance-counters": frozenset({"status", "enable", "disable"}),
    "ebpf": frozenset({"status", "enable", "disable"}),
    "device-access": frozenset({"inspect"}),
    "mount-management": frozenset({"mount", "unmount", "list"}),
    "namespace-management": frozenset({"create", "cleanup", "status"}),
    "cgroup-management": frozenset({"create", "set", "cleanup", "status"}),
    "experiment-directory-management": frozenset({"create", "cleanup", "inspect"}),
    "experiment-user-management": frozenset({"create", "remove", "inspect"}),
    "container-management": frozenset({"start", "stop", "remove", "status"}),
    "driver-management": frozenset({"install", "remove", "start", "stop", "status"}),
    "firewall-management": frozenset({"add-rule", "remove-rule", "status"}),
    "boot-management": frozenset({"inspect", "configure"}),
    "hardware-observation": frozenset({"collect"}),
    "system-observation": frozenset({"collect"}),
}

LINUX_CAPABILITIES = frozenset(
    {
        "package-management",
        "service-management",
        "system-reboot",
        "system-shutdown",
        "kernel-parameter-management",
        "kernel-module-management",
        "performance-counters",
        "ebpf",
        "device-access",
        "mount-management",
        "namespace-management",
        "cgroup-management",
        "experiment-directory-management",
        "experiment-user-management",
        "container-management",
        "driver-management",
        "firewall-management",
        "boot-management",
        "hardware-observation",
        "system-observation",
    }
)
WINDOWS_CAPABILITIES = frozenset(
    {
        "package-management",
        "service-management",
        "system-reboot",
        "system-shutdown",
        "device-access",
        "experiment-directory-management",
        "experiment-user-management",
        "container-management",
        "driver-management",
        "firewall-management",
        "hardware-observation",
        "system-observation",
    }
)

# These keys cover the normal perf/eBPF/large-page preparation path without
# allowing a protected worker to rewrite authentication, SSH, kernel module,
# forwarding, or boot security policy through a generic sysctl setter.
DEFAULT_SYSCTL_ALLOWLIST = frozenset(
    {
        "kernel.perf_event_paranoid",
        "kernel.nmi_watchdog",
        "kernel.unprivileged_bpf_disabled",
        "kernel.bpf_stats_enabled",
        "vm.nr_hugepages",
        "vm.max_map_count",
        "vm.overcommit_memory",
        "kernel.sched_autogroup_enabled",
    }
)
DEFAULT_EXPERIMENT_ROOTS = (
    "/opt/mncs",
    "/var/lib/mncs",
    "/var/lib/mncs/experiments",
    "/run/mncs",
)
DEFAULT_DEVICE_ROOTS = ("/dev/dri", "/dev/kvm")
DEFAULT_OBSERVATION_PATHS = {
    "cpuinfo": "/proc/cpuinfo",
    "meminfo": "/proc/meminfo",
    "perf_event_paranoid": "/proc/sys/kernel/perf_event_paranoid",
    "bpf_disabled": "/proc/sys/kernel/unprivileged_bpf_disabled",
    "cpu_online": "/sys/devices/system/cpu/online",
}
HIGH_RISK_CAPABILITIES = frozenset(
    {
        "package-management",
        "service-management",
        "system-reboot",
        "system-shutdown",
        "kernel-module-management",
        "mount-management",
        "namespace-management",
        "cgroup-management",
        "experiment-user-management",
        "container-management",
        "driver-management",
        "firewall-management",
        "boot-management",
    }
)
HIGH_RISK_OPERATIONS = frozenset({"install", "remove", "refresh", "set", "load", "unload", "enable", "disable", "mount", "unmount", "create", "cleanup", "configure", "add-rule", "remove-rule", "start", "stop", "restart", "request"})

_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:@+-]{0,127}$")
_MODULE = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}$")
_RELATIVE_PATH = re.compile(r"^(?!/)(?!.*(?:^|/)\.\.(?:/|$))[A-Za-z0-9][A-Za-z0-9_.@+:/-]{0,511}$")
_CGROUP_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")
_SYSCTL_KEY = re.compile(r"^[A-Za-z0-9_.-]{1,128}$")
_PORT = re.compile(r"^(?:[1-9][0-9]{0,4})$")
_SAFE_VALUE = re.compile(r"^[A-Za-z0-9_.:/+-]{1,128}$")
_PIPE_NAME = re.compile(r"^\\\\\.\\pipe\\[A-Za-z0-9_.-]{1,128}$")


def _text(value: object, field: str, maximum: int = 256) -> str:
    if not isinstance(value, str) or not value or len(value) > maximum or "\x00" in value:
        raise ValidationError(f"{field} must be bounded non-empty text")
    if any(ord(character) < 32 or 127 <= ord(character) <= 159 for character in value):
        raise ValidationError(f"{field} must not contain control characters")
    return value


def _optional_text(value: object, field: str, maximum: int = 256) -> str | None:
    if value is None:
        return None
    return _text(value, field, maximum)


def _identity_or_text(value: object, field: str, maximum: int = 256) -> str:
    # Worker and session identities may be local labels. Experiment identities
    # are usually sha256 references, but the broker does not invent semantic
    # ownership for a caller supplied label.
    return _text(value, field, maximum)


def _bounded_list(value: object, field: str, *, maximum: int, item: Callable[[object, str], str]) -> list[str]:
    if not isinstance(value, list) or not value or len(value) > maximum:
        raise ValidationError(f"{field} must be a bounded non-empty list")
    return [item(child, f"{field}[]") for child in value]


def _package_name(value: object, field: str = "package") -> str:
    result = _text(value, field, MAX_PACKAGE_NAME)
    if result.startswith("-") or not _IDENTIFIER.fullmatch(result):
        raise ValidationError(f"{field} is not a valid package identifier")
    return result


def _service_name(value: object, field: str = "service") -> str:
    result = _text(value, field, MAX_SERVICE_NAME)
    if result.startswith("-") or not _IDENTIFIER.fullmatch(result):
        raise ValidationError(f"{field} is not a valid service identifier")
    return result


def _module_name(value: object, field: str = "module") -> str:
    result = _text(value, field, 128)
    if not _MODULE.fullmatch(result):
        raise ValidationError(f"{field} is not a valid module identifier")
    return result


def _absolute_path(value: object, field: str = "path") -> str:
    result = _text(value, field, MAX_PATH_TEXT)
    windows_absolute = bool(re.match(r"^(?:[A-Za-z]:[\\/]|\\\\)", result))
    if not (Path(result).is_absolute() or windows_absolute) or "\n" in result or "\r" in result:
        raise ValidationError(f"{field} must be an absolute path")
    return result


def _relative_path(value: object, field: str = "path") -> str:
    result = _text(value, field, MAX_PATH_TEXT)
    if not _RELATIVE_PATH.fullmatch(result) or result in {".", ".."}:
        raise ValidationError(f"{field} must be a safe relative path")
    return result


def _empty_arguments(arguments: Mapping[str, Any]) -> dict[str, Any]:
    if arguments:
        raise ValidationError("capability operation does not accept arguments")
    return {}


def validate_capability_arguments(capability: str, operation: str, arguments: object) -> dict[str, Any]:
    """Validate one operation's exact structured argument shape."""

    _validate_capability_operation(capability, operation)
    if not isinstance(arguments, dict):
        raise ValidationError("capability arguments must be an object")
    value = dict(arguments)
    if len(canonical_json_bytes(value)) > MAX_ARGUMENT_BYTES:
        raise ValidationError("capability arguments exceed their bound")

    if capability == "package-management":
        if operation in {"install", "remove", "query"}:
            if set(value) != {"packages"}:
                raise ValidationError("package operation requires only packages")
            packages = _bounded_list(value["packages"], "packages", maximum=MAX_PACKAGE_COUNT, item=_package_name)
            return {"packages": packages}
        return _empty_arguments(value)
    if capability == "service-management":
        if operation == "status":
            if set(value) not in ({"service"}, {"service", "state"}):
                raise ValidationError("service status fields are invalid")
            result = {"service": _service_name(value.get("service"))}
            if "state" in value:
                state = _text(value["state"], "state", 16)
                if state not in {"running", "stopped", "enabled", "disabled"}:
                    raise ValidationError("service status state is unsupported")
                result["state"] = state
            return result
        if set(value) != {"service"}:
            raise ValidationError("service operation requires only service")
        return {"service": _service_name(value.get("service"))}
    if capability in {"system-reboot", "system-shutdown"}:
        allowed = {"reason", "delay_seconds"}
        if set(value) - allowed:
            raise ValidationError("machine power operation contains unsupported fields")
        reason = _optional_text(value.get("reason"), "reason", 256)
        delay = value.get("delay_seconds", 0)
        if not isinstance(delay, int) or isinstance(delay, bool) or not 0 <= delay <= 3600:
            raise ValidationError("delay_seconds must be an integer between 0 and 3600")
        return {"reason": reason, "delay_seconds": delay}
    if capability == "kernel-parameter-management":
        expected_fields = {"key"} if operation == "get" else {"key", "value"}
        if set(value) != expected_fields:
            raise ValidationError("sysctl operation fields are invalid")
        key = _text(value.get("key"), "key", 128)
        if not _SYSCTL_KEY.fullmatch(key):
            raise ValidationError("sysctl key contains unsupported characters")
        result: dict[str, Any] = {"key": key}
        if operation == "set":
            raw = value.get("value")
            if isinstance(raw, bool) or not isinstance(raw, (str, int, float)):
                raise ValidationError("sysctl value must be a scalar")
            text_value = str(raw)
            if not _SAFE_VALUE.fullmatch(text_value):
                raise ValidationError("sysctl value contains unsupported characters")
            result["value"] = text_value
        return result
    if capability == "kernel-module-management":
        if set(value) != {"module"}:
            raise ValidationError("module operation requires only module")
        return {"module": _module_name(value.get("module"))}
    if capability in {"performance-counters", "ebpf"}:
        return _empty_arguments(value)
    if capability == "device-access":
        if set(value) != {"path"}:
            raise ValidationError("device inspection requires only path")
        return {"path": _absolute_path(value.get("path"))}
    if capability == "mount-management":
        if operation == "mount":
            allowed = {"source", "target", "filesystem", "options"}
            if set(value) != allowed:
                raise ValidationError("mount operation fields are invalid")
            source = _text(value.get("source"), "source", MAX_PATH_TEXT)
            filesystem = _text(value.get("filesystem"), "filesystem", 32)
            if filesystem not in {"tmpfs"} or source != "tmpfs":
                raise ValidationError("only structured tmpfs mounts are supported")
            options = value.get("options")
            if not isinstance(options, list) or len(options) > 8:
                raise ValidationError("mount options are invalid")
            checked_options: list[str] = []
            for option in options:
                text_option = _text(option, "options[]", 64)
                if not re.fullmatch(r"(?:nosuid|nodev|noexec|size=[0-9]+[KMG]?|mode=[0-7]{3,4})", text_option):
                    raise ValidationError("mount option is not allowlisted")
                checked_options.append(text_option)
            return {"source": source, "target": _absolute_path(value.get("target"), "target"), "filesystem": filesystem, "options": checked_options}
        if operation == "unmount":
            if set(value) != {"target"}:
                raise ValidationError("unmount operation requires only target")
            return {"target": _absolute_path(value.get("target"), "target")}
        return _empty_arguments(value)
    if capability == "namespace-management":
        if set(value) != {"name", "kind"}:
            raise ValidationError("namespace operation fields are invalid")
        kind = _text(value.get("kind"), "kind", 16)
        if kind not in {"mount", "uts", "ipc", "net", "pid", "cgroup", "user"}:
            raise ValidationError("namespace kind is unsupported")
        return {"name": _module_name(value.get("name"), "name"), "kind": kind}
    if capability == "cgroup-management":
        if operation in {"create", "cleanup", "status"}:
            if set(value) != {"name"}:
                raise ValidationError("cgroup operation requires only name")
            return {"name": _module_name(value.get("name"), "name")}
        if set(value) - {"name", "cpu_max", "memory_max"} or "name" not in value:
            raise ValidationError("cgroup set fields are invalid")
        result = {"name": _module_name(value.get("name"), "name")}
        for field in ("cpu_max", "memory_max"):
            if field in value:
                item = _text(value[field], field, 64)
                if item != "max" and not re.fullmatch(r"[0-9]+(?: [0-9]+)?", item):
                    raise ValidationError(f"{field} is not a valid cgroup value")
                result[field] = item
        if len(result) == 1:
            raise ValidationError("cgroup set requires cpu_max or memory_max")
        return result
    if capability == "experiment-directory-management":
        if set(value) != {"path"}:
            raise ValidationError("experiment directory operation requires only path")
        return {"path": _absolute_path(value.get("path"))}
    if capability == "experiment-user-management":
        if set(value) != {"username"}:
            raise ValidationError("experiment user operation requires only username")
        username = _text(value.get("username"), "username", 64)
        if not re.fullmatch(r"[a-z_][a-z0-9_-]{0,31}\$?", username):
            raise ValidationError("username is invalid")
        return {"username": username}
    if capability == "container-management":
        if set(value) != {"name"}:
            raise ValidationError("container operation requires only name")
        return {"name": _module_name(value.get("name"), "name")}
    if capability == "driver-management":
        if operation in {"install", "remove"}:
            if set(value) != {"path"}:
                raise ValidationError("driver operation requires only path")
            return {"path": _absolute_path(value.get("path"))}
        if set(value) != {"name"}:
            raise ValidationError("driver operation requires only name")
        return {"name": _module_name(value.get("name"), "name")}
    if capability == "firewall-management":
        if operation == "status":
            return _empty_arguments(value)
        allowed = {"name", "direction", "action", "protocol", "local_port"}
        if set(value) != allowed:
            raise ValidationError("firewall rule fields are invalid")
        name = _text(value.get("name"), "name", 128)
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_. -]{0,127}", name):
            raise ValidationError("firewall rule name is invalid")
        direction = _text(value.get("direction"), "direction", 8).lower()
        action = _text(value.get("action"), "action", 8).lower()
        protocol = _text(value.get("protocol"), "protocol", 8).lower()
        if direction not in {"in", "out"} or action not in {"allow", "block"} or protocol not in {"tcp", "udp", "any"}:
            raise ValidationError("firewall rule enum is invalid")
        port = _text(value.get("local_port"), "local_port", 5)
        if port != "any" and not _PORT.fullmatch(port):
            raise ValidationError("firewall local_port is invalid")
        return {"name": name, "direction": direction, "action": action, "protocol": protocol, "local_port": port}
    if capability == "boot-management":
        if operation == "inspect":
            return _empty_arguments(value)
        if set(value) != {"setting", "value"}:
            raise ValidationError("boot configuration fields are invalid")
        setting = _text(value.get("setting"), "setting", 64)
        if not re.fullmatch(r"[A-Za-z0-9_.-]+", setting):
            raise ValidationError("boot setting is invalid")
        return {"setting": setting, "value": _text(value.get("value"), "value", 128)}
    if capability in {"hardware-observation", "system-observation"}:
        if set(value) != {"observations"}:
            raise ValidationError("observation operation requires only observations")
        return {"observations": _bounded_list(value["observations"], "observations", maximum=16, item=lambda item, field: _text(item, field, 64))}
    raise ValidationError("capability family is unsupported")


def _validate_capability_operation(capability: object, operation: object) -> tuple[str, str]:
    family = _text(capability, "capability", 64)
    action = _text(operation, "operation", 32)
    if family not in CAPABILITY_FAMILIES or action not in CAPABILITY_OPERATIONS[family]:
        raise ValidationError("capability family or operation is unsupported")
    return family, action


def build_capability_request(
    *,
    worker_identity: str,
    capability: str,
    operation: str,
    arguments: Mapping[str, Any] | None = None,
    experiment_identity: str | None = None,
    agent_session: str | None = None,
    lease_identity: str | None = None,
    requested_at: str | None = None,
) -> dict[str, Any]:
    family, action = _validate_capability_operation(capability, operation)
    checked_arguments = validate_capability_arguments(family, action, dict(arguments or {}))
    value = {
        "schema_version": CAPABILITY_REQUEST_SCHEMA,
        "protocol": CAPABILITY_BROKER_PROTOCOL,
        "worker_identity": _identity_or_text(worker_identity, "worker_identity"),
        "capability": family,
        "operation": action,
        "arguments": checked_arguments,
        "experiment_identity": _optional_text(experiment_identity, "experiment_identity", 256),
        "agent_session": _optional_text(agent_session, "agent_session", 256),
        "lease_identity": _optional_text(lease_identity, "lease_identity", 128),
        "requested_at": requested_at or utc_now(),
        "claim_boundary": "structured capability intent; not a shell, root session, or attestation",
    }
    return attach_identity(value, "request_identity")


def validate_capability_request(value: object, *, expected_worker_id: str | None = None) -> dict[str, Any]:
    if not isinstance(value, dict) or value.get("schema_version") != CAPABILITY_REQUEST_SCHEMA:
        raise ValidationError("unsupported capability request schema")
    required = {
        "schema_version", "protocol", "worker_identity", "capability", "operation", "arguments",
        "experiment_identity", "agent_session", "lease_identity", "requested_at", "claim_boundary", "request_identity",
    }
    if set(value) != required or value.get("protocol") != CAPABILITY_BROKER_PROTOCOL or not verify_identity(value, "request_identity"):
        raise ValidationError("capability request fields or identity are invalid")
    worker_id = _identity_or_text(value["worker_identity"], "worker_identity")
    if expected_worker_id is not None and worker_id != expected_worker_id:
        raise ValidationError("capability request is bound to another worker")
    family, action = _validate_capability_operation(value["capability"], value["operation"])
    checked = validate_capability_arguments(family, action, value["arguments"])
    if checked != value["arguments"]:
        raise ValidationError("capability arguments are not canonical")
    _optional_text(value["experiment_identity"], "experiment_identity", 256)
    _optional_text(value["agent_session"], "agent_session", 256)
    _optional_text(value["lease_identity"], "lease_identity", 128)
    _timestamp(value["requested_at"], "requested_at")
    _text(value["claim_boundary"], "claim_boundary", 256)
    return dict(value)


def _timestamp(value: object, field: str) -> datetime:
    text = _text(value, field, 64)
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValidationError(f"{field} must be RFC 3339") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValidationError(f"{field} must contain a timezone")
    return parsed.astimezone(timezone.utc)


def _iso(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def build_capability_lease(
    *,
    worker_identity: str,
    capabilities: Iterable[str],
    ttl_seconds: int,
    experiment_identity: str | None = None,
    operations: Mapping[str, Iterable[str]] | None = None,
    granted_by: str = "fabric-policy",
    granted_at: str | None = None,
) -> dict[str, Any]:
    if not isinstance(ttl_seconds, int) or isinstance(ttl_seconds, bool) or not 1 <= ttl_seconds <= MAX_LEASE_SECONDS:
        raise ValidationError("capability lease ttl is outside the bounded range")
    names = sorted(set(_text(item, "capabilities[]", 64) for item in capabilities))
    if any(item not in CAPABILITY_FAMILIES for item in names):
        raise ValidationError("capability lease contains an unsupported capability")
    if not names or len(names) > len(CAPABILITY_FAMILIES):
        raise ValidationError("capability lease must contain at least one capability")
    operation_map: dict[str, list[str]] = {}
    if operations is not None and set(operations) - set(names):
        raise ValidationError("capability lease operation scope names are invalid")
    for name in names:
        requested = list(operations.get(name, CAPABILITY_OPERATIONS[name]) if operations else CAPABILITY_OPERATIONS[name])
        if not requested or any(item not in CAPABILITY_OPERATIONS[name] for item in requested):
            raise ValidationError("capability lease contains an unsupported operation")
        operation_map[name] = sorted(set(requested))
    start = _timestamp(granted_at or utc_now(), "granted_at")
    value = {
        "schema_version": CAPABILITY_LEASE_SCHEMA,
        "protocol": CAPABILITY_BROKER_PROTOCOL,
        "worker_identity": _identity_or_text(worker_identity, "worker_identity"),
        "experiment_identity": _optional_text(experiment_identity, "experiment_identity", 256),
        "capabilities": names,
        "operations": operation_map,
        "granted_at": _iso(start),
        "expires_at": _iso(start + timedelta(seconds=ttl_seconds)),
        "granted_by": _text(granted_by, "granted_by", 128),
        "claim_boundary": "bounded broker lease; not host ownership, attestation, or a root shell",
    }
    return attach_identity(value, "lease_identity")


def validate_capability_lease(value: object, *, expected_worker_id: str | None = None) -> dict[str, Any]:
    if not isinstance(value, dict) or value.get("schema_version") != CAPABILITY_LEASE_SCHEMA:
        raise ValidationError("unsupported capability lease schema")
    required = {
        "schema_version", "protocol", "worker_identity", "experiment_identity", "capabilities", "operations",
        "granted_at", "expires_at", "granted_by", "claim_boundary", "lease_identity",
    }
    if set(value) != required or value.get("protocol") != CAPABILITY_BROKER_PROTOCOL or not verify_identity(value, "lease_identity"):
        raise ValidationError("capability lease fields or identity are invalid")
    worker_id = _identity_or_text(value["worker_identity"], "worker_identity")
    if expected_worker_id is not None and worker_id != expected_worker_id:
        raise ValidationError("capability lease is bound to another worker")
    _optional_text(value["experiment_identity"], "experiment_identity", 256)
    caps = value["capabilities"]
    if not isinstance(caps, list) or not caps or len(caps) != len(set(caps)):
        raise ValidationError("capability lease capabilities are invalid")
    for capability in caps:
        if capability not in CAPABILITY_FAMILIES:
            raise ValidationError("capability lease contains an unsupported capability")
    operations = value["operations"]
    if not isinstance(operations, dict) or set(operations) != set(caps):
        raise ValidationError("capability lease operation scope is invalid")
    for capability in caps:
        items = operations[capability]
        if not isinstance(items, list) or not items or len(items) != len(set(items)) or any(item not in CAPABILITY_OPERATIONS[capability] for item in items):
            raise ValidationError("capability lease contains an invalid operation scope")
    granted = _timestamp(value["granted_at"], "granted_at")
    expires = _timestamp(value["expires_at"], "expires_at")
    if expires <= granted or expires - granted > timedelta(seconds=MAX_LEASE_SECONDS):
        raise ValidationError("capability lease expiry is invalid")
    _text(value["granted_by"], "granted_by", 128)
    _text(value["claim_boundary"], "claim_boundary", 256)
    return dict(value)


def build_host_privilege_profile(
    *,
    worker_identity: str,
    mode: str,
    platform: str = "linux",
    allowed_capabilities: Iterable[str] | None = None,
    experiment_roots: Iterable[str] | None = None,
    device_roots: Iterable[str] | None = None,
    sysctl_allowlist: Iterable[str] | None = None,
    service_allowlist: Iterable[str] | None = None,
    cgroup_root: str | None = None,
    lease_required: Iterable[str] | None = None,
    automatic_leases: bool = False,
) -> dict[str, Any]:
    mode_text = _text(mode, "mode", 64)
    if mode_text not in {"unrestricted", "capability-broker", "windows-capability-broker"}:
        raise ValidationError("host privilege mode is unsupported")
    platform_text = _text(platform, "platform", 32).lower()
    if platform_text not in {"linux", "windows"}:
        raise ValidationError("host privilege platform is unsupported")
    if mode_text == "windows-capability-broker" and platform_text != "windows":
        raise ValidationError("windows capability-broker mode requires a Windows platform")
    defaults = WINDOWS_CAPABILITIES if platform_text == "windows" else LINUX_CAPABILITIES
    caps = sorted(set(defaults if allowed_capabilities is None else allowed_capabilities))
    if not caps or any(item not in CAPABILITY_FAMILIES for item in caps):
        raise ValidationError("host profile capability allowlist is invalid")
    default_roots = DEFAULT_EXPERIMENT_ROOTS if platform_text == "linux" else (r"C:\ProgramData\MNCS", r"C:\ProgramData\MNCS\experiments")
    roots = [_absolute_path(item, "experiment_roots[]") for item in (default_roots if experiment_roots is None else experiment_roots)]
    default_devices = DEFAULT_DEVICE_ROOTS if platform_text == "linux" else ()
    devices = [_absolute_path(item, "device_roots[]") for item in (default_devices if device_roots is None else device_roots)]
    sysctls = sorted(set(DEFAULT_SYSCTL_ALLOWLIST if sysctl_allowlist is None else sysctl_allowlist))
    if any(not _SYSCTL_KEY.fullmatch(item) for item in sysctls):
        raise ValidationError("host profile sysctl allowlist is invalid")
    default_services = () if mode_text == "unrestricted" else ("fabric-worker", "mncs-experiment")
    services = sorted(set(_service_name(item, "service_allowlist[]") for item in (service_allowlist if service_allowlist is not None else default_services)))
    default_leases = HIGH_RISK_CAPABILITIES & set(caps) if mode_text != "unrestricted" else set()
    required_leases = sorted(set(lease_required if lease_required is not None else default_leases))
    if any(item not in caps for item in required_leases):
        raise ValidationError("lease-required capability is not allowed by the profile")
    group_root = _absolute_path(cgroup_root, "cgroup_root") if cgroup_root is not None else ("/sys/fs/cgroup/mncs" if platform_text == "linux" else None)
    if not isinstance(automatic_leases, bool):
        raise ValidationError("automatic_leases must be a boolean")
    value = {
        "schema_version": PRIVILEGE_PROFILE_SCHEMA,
        "worker_identity": _identity_or_text(worker_identity, "worker_identity"),
        "platform": platform_text,
        "mode": mode_text,
        "allowed_capabilities": caps,
        "experiment_roots": roots,
        "device_roots": devices,
        "sysctl_allowlist": sysctls,
        "service_allowlist": services,
        "cgroup_root": group_root,
        "lease_required": required_leases,
        "automatic_leases": automatic_leases,
        "claim_boundary": "operator host policy; not hostname-derived authorization or attestation",
    }
    return attach_identity(value, "profile_identity")


def validate_host_privilege_profile(value: object, *, expected_worker_id: str | None = None) -> dict[str, Any]:
    if not isinstance(value, dict) or value.get("schema_version") != PRIVILEGE_PROFILE_SCHEMA:
        raise ValidationError("unsupported host privilege profile schema")
    required = {
        "schema_version", "worker_identity", "platform", "mode", "allowed_capabilities", "experiment_roots",
        "device_roots", "sysctl_allowlist", "service_allowlist", "cgroup_root", "lease_required", "automatic_leases",
        "claim_boundary", "profile_identity",
    }
    if set(value) != required or not verify_identity(value, "profile_identity"):
        raise ValidationError("host privilege profile fields or identity are invalid")
    worker_id = _identity_or_text(value["worker_identity"], "worker_identity")
    if expected_worker_id is not None and worker_id != expected_worker_id:
        raise ValidationError("host privilege profile is bound to another worker")
    # Rebuild validation ensures all nested values and mode/platform pairings
    # obey the same rules used by the trusted profile loader.
    rebuilt = build_host_privilege_profile(
        worker_identity=worker_id,
        mode=value["mode"],
        platform=value["platform"],
        allowed_capabilities=value["allowed_capabilities"],
        experiment_roots=value["experiment_roots"],
        device_roots=value["device_roots"],
        sysctl_allowlist=value["sysctl_allowlist"],
        service_allowlist=value["service_allowlist"],
        cgroup_root=value["cgroup_root"],
        lease_required=value["lease_required"],
        automatic_leases=value["automatic_leases"],
    )
    if rebuilt != value:
        raise ValidationError("host privilege profile is not canonical")
    return dict(value)


def host_privilege_profile(worker_identity: str, mode: str, *, platform: str = "linux", **kwargs: Any) -> dict[str, Any]:
    """Short factory used by inventory/configuration loaders."""

    return build_host_privilege_profile(worker_identity=worker_identity, mode=mode, platform=platform, **kwargs)


def load_host_privilege_profile(path: Path, *, worker_identity: str) -> dict[str, Any]:
    """Load one explicitly selected profile from a JSON operator config.

    Fabric's existing operator configuration is JSON rather than YAML.  The
    accepted shape is either a profile object or ``{"profiles": [...]}``; no
    hostname matching or implicit default mode is performed.
    """

    target = Path(path)
    try:
        value = json.loads(target.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ValidationError("host privilege profile configuration is unreadable") from exc
    if isinstance(value, dict) and "profiles" in value:
        profiles = value.get("profiles")
        if not isinstance(profiles, list):
            raise ValidationError("host privilege profile catalog is invalid")
        matches = [item for item in profiles if isinstance(item, dict) and item.get("worker_identity") == worker_identity]
        if len(matches) != 1:
            raise ValidationError("host privilege profile must explicitly select exactly one worker")
        value = matches[0]
    return validate_host_privilege_profile(value, expected_worker_id=worker_identity)


def _validate_requirements_list(value: object, field: str, *, max_items: int = 64) -> list[str]:
    return _bounded_list(value, field, maximum=max_items, item=lambda item, child: _text(item, child, 128))


def build_experiment_requirements(
    *,
    worker_identity: str,
    experiment_identity: str,
    capabilities: Iterable[str] = (),
    packages: Iterable[str] = (),
    sysctl: Mapping[str, str | int | float] | None = None,
    services: Mapping[str, str] | None = None,
    reboot: bool = False,
    shutdown: bool = False,
    experiment_directory: str | None = None,
    captured_at: str | None = None,
) -> dict[str, Any]:
    cap_names = sorted(set(_text(item, "capabilities[]", 64) for item in capabilities))
    if any(item not in CAPABILITY_FAMILIES for item in cap_names):
        raise ValidationError("experiment capability requirement is unsupported")
    package_names = sorted(set(_package_name(item, "packages[]") for item in packages)) if packages else []
    if len(package_names) > MAX_PACKAGE_COUNT:
        raise ValidationError("experiment package requirement exceeds its bound")
    sysctl_value: dict[str, str] = {}
    for key, raw in sorted((sysctl or {}).items()):
        checked_key = _text(key, "sysctl key", 128)
        if not _SYSCTL_KEY.fullmatch(checked_key) or isinstance(raw, bool) or not isinstance(raw, (str, int, float)):
            raise ValidationError("experiment sysctl requirement is invalid")
        text_value = str(raw)
        if not _SAFE_VALUE.fullmatch(text_value):
            raise ValidationError("experiment sysctl value is invalid")
        sysctl_value[checked_key] = text_value
    service_value: dict[str, str] = {}
    for service, state in sorted((services or {}).items()):
        checked_service = _service_name(service, "services.name")
        checked_state = _text(state, "services.state", 16)
        if checked_state not in {"running", "stopped", "enabled", "disabled"}:
            raise ValidationError("experiment service state is unsupported")
        service_value[checked_service] = checked_state
    if not isinstance(reboot, bool) or not isinstance(shutdown, bool) or (reboot and shutdown):
        raise ValidationError("experiment power requirements are invalid")
    directory = _absolute_path(experiment_directory, "experiment_directory") if experiment_directory is not None else None
    value = {
        "schema_version": EXPERIMENT_REQUIREMENTS_SCHEMA,
        "worker_identity": _identity_or_text(worker_identity, "worker_identity"),
        "experiment_identity": _identity_or_text(experiment_identity, "experiment_identity"),
        "capabilities": cap_names,
        "packages": package_names,
        "sysctl": sysctl_value,
        "services": service_value,
        "system": {"reboot": reboot, "shutdown": shutdown},
        "experiment_directory": directory,
        "captured_at": captured_at or utc_now(),
        "claim_boundary": "structured desired machine state; not a command script or attestation",
    }
    return attach_identity(value, "requirements_identity")


def validate_experiment_requirements(value: object, *, expected_worker_id: str | None = None) -> dict[str, Any]:
    if not isinstance(value, dict) or value.get("schema_version") != EXPERIMENT_REQUIREMENTS_SCHEMA:
        raise ValidationError("unsupported experiment requirements schema")
    required = {
        "schema_version", "worker_identity", "experiment_identity", "capabilities", "packages", "sysctl", "services",
        "system", "experiment_directory", "captured_at", "claim_boundary", "requirements_identity",
    }
    if set(value) != required or not verify_identity(value, "requirements_identity"):
        raise ValidationError("experiment requirement fields or identity are invalid")
    worker_id = _identity_or_text(value["worker_identity"], "worker_identity")
    if expected_worker_id is not None and worker_id != expected_worker_id:
        raise ValidationError("experiment requirements are bound to another worker")
    _identity_or_text(value["experiment_identity"], "experiment_identity")
    caps = _validate_requirements_list(value["capabilities"], "capabilities") if value["capabilities"] else []
    if any(item not in CAPABILITY_FAMILIES for item in caps) or caps != sorted(set(caps)):
        raise ValidationError("experiment capabilities are not canonical")
    if not isinstance(value["packages"], list):
        raise ValidationError("experiment package requirements are invalid")
    packages = [_package_name(item, "packages[]") for item in value["packages"]]
    if packages != sorted(set(packages)):
        raise ValidationError("experiment packages are not canonical")
    if not isinstance(value["sysctl"], dict):
        raise ValidationError("experiment sysctl requirements are invalid")
    for key, item in value["sysctl"].items():
        validate_capability_arguments("kernel-parameter-management", "set", {"key": key, "value": item})
    if not isinstance(value["services"], dict):
        raise ValidationError("experiment service requirements are invalid")
    for service, state in value["services"].items():
        _service_name(service, "services.name")
        if state not in {"running", "stopped", "enabled", "disabled"}:
            raise ValidationError("experiment service state is unsupported")
    system = value["system"]
    if not isinstance(system, dict) or set(system) != {"reboot", "shutdown"} or not isinstance(system["reboot"], bool) or not isinstance(system["shutdown"], bool) or system["reboot"] and system["shutdown"]:
        raise ValidationError("experiment system requirements are invalid")
    if value["experiment_directory"] is not None:
        _absolute_path(value["experiment_directory"], "experiment_directory")
    _text(value["captured_at"], "captured_at", 64)
    _text(value["claim_boundary"], "claim_boundary", 256)
    return dict(value)


@dataclass(frozen=True, slots=True)
class HostPrivilegeProfile:
    """Validated host policy; mode selection is explicit and identity-bound."""

    value: dict[str, Any]

    def __post_init__(self) -> None:
        object.__setattr__(self, "value", validate_host_privilege_profile(self.value))

    @property
    def worker_identity(self) -> str:
        return str(self.value["worker_identity"])

    @property
    def mode(self) -> str:
        return str(self.value["mode"])

    @property
    def platform(self) -> str:
        return str(self.value["platform"])

    def allows(self, capability: str, operation: str) -> bool:
        return capability in self.value["allowed_capabilities"] and operation in CAPABILITY_OPERATIONS.get(capability, ())

    def requires_lease(self, capability: str, operation: str) -> bool:
        return self.mode != "unrestricted" and capability in self.value["lease_required"] and operation in HIGH_RISK_OPERATIONS


class CapabilityAdapter(Protocol):
    def execute(self, request: Mapping[str, Any]) -> Mapping[str, Any]: ...


def _redact(value: object, *, field: str | None = None) -> object:
    secret_fields = {"password", "token", "secret", "credential", "private_key", "authorization"}
    if field and field.lower() in secret_fields:
        return "[redacted]"
    if isinstance(value, Mapping):
        return {str(key): _redact(child, field=str(key)) for key, child in value.items()}
    if isinstance(value, list):
        return [_redact(child) for child in value]
    if isinstance(value, str):
        return value[:MAX_AUDIT_OUTPUT]
    return value


def _command_result(
    *,
    outcome: str,
    detail: str,
    changed: bool = False,
    previous_state: object = None,
    new_state: object = None,
    data: Mapping[str, Any] | None = None,
    stdout: str = "",
    stderr: str = "",
) -> dict[str, Any]:
    if outcome not in {"PASS", "FAIL", "UNKNOWN", "SKIPPED"}:
        raise ValidationError("capability result outcome is invalid")
    return {
        "outcome": outcome,
        "detail": str(detail)[:512],
        "changed": bool(changed),
        "previous_state": _redact(previous_state),
        "new_state": _redact(new_state),
        "data": _redact(dict(data or {})),
        "stdout": _redact(str(stdout))[:MAX_AUDIT_OUTPUT],
        "stderr": _redact(str(stderr))[:MAX_AUDIT_OUTPUT],
    }


def _validate_result_body(value: object) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ValidationError("capability operation result body must be an object")
    required = {"outcome", "detail", "changed", "previous_state", "new_state", "data", "stdout", "stderr"}
    if set(value) != required:
        raise ValidationError("capability operation result body fields are invalid")
    if value["outcome"] not in {"PASS", "FAIL", "UNKNOWN", "SKIPPED"} or not isinstance(value["changed"], bool):
        raise ValidationError("capability operation result body status is invalid")
    _text(value["detail"], "detail", 512)
    if not isinstance(value["data"], dict):
        raise ValidationError("capability operation result body data is invalid")
    for field in ("stdout", "stderr"):
        output = value[field]
        if not isinstance(output, str) or len(output) > MAX_AUDIT_OUTPUT:
            raise ValidationError(f"capability operation result body {field} is invalid")
    if len(canonical_json_bytes(value)) > MAX_ARGUMENT_BYTES:
        raise ValidationError("capability operation result body exceeds its bound")
    return dict(value)


def _run_fixed(argv: list[str], *, timeout: float = 120.0) -> dict[str, Any]:
    if not argv or any(not isinstance(item, str) or not item or "\x00" in item for item in argv):
        raise ValidationError("privileged argv is invalid")
    try:
        completed = subprocess.run(argv, shell=False, check=False, capture_output=True, text=True, timeout=timeout)
    except FileNotFoundError:
        return {"returncode": None, "stdout": "", "stderr": "not-found", "timed_out": False}
    except subprocess.TimeoutExpired:
        return {"returncode": None, "stdout": "", "stderr": "timeout", "timed_out": True}
    except OSError as exc:
        return {"returncode": None, "stdout": "", "stderr": str(exc)[:512], "timed_out": False}
    return {"returncode": completed.returncode, "stdout": (completed.stdout or "")[:MAX_AUDIT_OUTPUT], "stderr": (completed.stderr or "")[:MAX_AUDIT_OUTPUT], "timed_out": False}


def _result_from_process(probed: Mapping[str, Any], *, success_detail: str, failure_detail: str, changed: bool = False, data: Mapping[str, Any] | None = None, previous_state: object = None, new_state: object = None) -> dict[str, Any]:
    if probed.get("timed_out") or probed.get("returncode") is None:
        return _command_result(outcome="UNKNOWN", detail=failure_detail, changed=False, data=data, stdout=str(probed.get("stdout") or ""), stderr=str(probed.get("stderr") or ""))
    if probed.get("returncode") == 0:
        return _command_result(outcome="PASS", detail=success_detail, changed=changed, data=data, previous_state=previous_state, new_state=new_state, stdout=str(probed.get("stdout") or ""), stderr=str(probed.get("stderr") or ""))
    return _command_result(outcome="FAIL", detail=failure_detail, changed=False, data=data, previous_state=previous_state, new_state=new_state, stdout=str(probed.get("stdout") or ""), stderr=str(probed.get("stderr") or ""))


def _system_executable(name: str) -> str | None:
    # A root broker must not resolve executables from a caller-controlled PATH.
    candidates = (f"/usr/bin/{name}", f"/usr/sbin/{name}", f"/bin/{name}", f"/sbin/{name}")
    for candidate in candidates:
        path = Path(candidate)
        try:
            link = path.lstat()
            target = path.resolve(strict=True)
            target_info = target.stat()
            mode = target_info.st_mode
            parent = path.parent.stat()
        except OSError:
            continue
        # Fedora and several other distributions ship modprobe/lsmod as
        # root-owned symlinks to kmod. Permit that packaging detail only when
        # both link and target are root-owned and not group/other writable.
        if (
            stat.S_ISREG(mode)
            and link.st_uid == 0
            and target_info.st_uid == 0
            and mode & 0o022 == 0
            and parent.st_uid == 0
            and parent.st_mode & 0o022 == 0
            and os.access(path, os.X_OK)
        ):
            return candidate
    return None


class LinuxCapabilityBroker:
    """Root-side Linux adapter with fixed argv and path/service policy."""

    def __init__(self, profile: HostPrivilegeProfile | Mapping[str, Any], *, runner: Callable[[list[str]], dict[str, Any]] | None = None, package_manager: str | None = None) -> None:
        self.profile = profile if isinstance(profile, HostPrivilegeProfile) else HostPrivilegeProfile(dict(profile))
        if self.profile.platform != "linux":
            raise ValidationError("Linux capability broker requires a Linux profile")
        self.runner = runner or (lambda argv: _run_fixed(argv))
        self.package_manager = package_manager

    def _path(self, raw: str, *, roots: Iterable[str]) -> Path:
        candidate = Path(raw)
        if not candidate.is_absolute():
            raise ValidationError("broker path must be absolute")
        candidate_abs = Path(os.path.abspath(str(candidate)))
        for root_text in roots:
            root = Path(os.path.abspath(root_text))
            try:
                if os.path.commonpath((str(candidate_abs), str(root))) == str(root) and candidate_abs != root:
                    # Reject an existing symlink anywhere below a designated
                    # root. This keeps cleanup/create operations from crossing
                    # the configured boundary after a filesystem race.
                    current = root
                    for part in candidate_abs.relative_to(root).parts:
                        current = current / part
                        if current.is_symlink():
                            raise ValidationError("broker path contains a symbolic link")
                    return candidate_abs
            except ValueError:
                continue
        raise ValidationError("path is outside the configured experiment roots")

    def _service(self, name: str) -> str:
        allowlist = self.profile.value["service_allowlist"]
        if self.profile.mode != "unrestricted" and name not in allowlist:
            raise ValidationError("service is not allowlisted by the host profile")
        return name

    def _sysctl(self, key: str, value: str | None = None) -> dict[str, Any]:
        if key not in self.profile.value["sysctl_allowlist"]:
            raise ValidationError("sysctl key is not allowlisted by the host profile")
        executable = _system_executable("sysctl")
        if executable is None:
            return _command_result(outcome="UNKNOWN", detail="sysctl executable is unavailable")
        if value is None:
            probed = self.runner([executable, "-n", key])
            result = _result_from_process(probed, success_detail=f"read {key}", failure_detail=f"unable to read {key}", data={"key": key})
            if result["outcome"] == "PASS":
                result["data"] = {"key": key, "value": str(probed.get("stdout") or "").strip()}
            return result
        return _result_from_process(self.runner([executable, "-w", f"{key}={value}"]), success_detail=f"set {key}", failure_detail=f"unable to set {key}", changed=True, data={"key": key, "value": value}, new_state=value)

    def _package_command(self, operation: str, packages: list[str] | None = None) -> list[str] | None:
        manager = self.package_manager
        if manager is None:
            for name in ("dnf", "apt-get", "zypper", "pacman"):
                if _system_executable(name):
                    manager = name
                    break
        if manager not in {"dnf", "apt-get", "zypper", "pacman"}:
            return None
        binary = _system_executable(str(manager))
        if binary is None:
            return None
        package_args = list(packages or [])
        if operation == "query":
            return [binary, "--query", *package_args]
        if operation == "refresh":
            if manager == "dnf":
                return [binary, "makecache", "--timer"]
            if manager == "apt-get":
                return [binary, "update"]
            if manager == "zypper":
                return [binary, "--non-interactive", "refresh"]
            return [binary, "--sync", "--refresh"]
        if manager == "dnf":
            return [binary, operation, "--assumeyes", "--", *package_args]
        if manager == "apt-get":
            return [binary, operation, "--yes", "--no-install-recommends", "--", *package_args]
        if manager == "zypper":
            return [binary, "--non-interactive", operation, "--", *package_args]
        return [binary, "--noconfirm", "--sync" if operation == "install" else "--remove", *package_args]

    def execute(self, request: Mapping[str, Any]) -> Mapping[str, Any]:
        checked = validate_capability_request(request, expected_worker_id=self.profile.worker_identity)
        family = checked["capability"]
        operation = checked["operation"]
        args = checked["arguments"]
        if family == "package-management":
            packages = args.get("packages", [])
            if operation == "query":
                manager = self.package_manager
                if manager is None:
                    for name in ("dnf", "apt-get", "zypper", "pacman"):
                        if _system_executable(name):
                            manager = name
                            break
                if manager == "apt-get":
                    query_binary = _system_executable("dpkg-query")
                    query_args = lambda package: [query_binary, "-W", "-f=${Status}", "--", package]
                elif manager == "pacman":
                    query_binary = _system_executable("pacman")
                    query_args = lambda package: [query_binary, "--query", package]
                else:
                    query_binary = _system_executable("rpm") if manager in {"dnf", "zypper"} else None
                    query_args = lambda package: [query_binary, "-q", "--", package]
                if query_binary is None:
                    return _command_result(outcome="UNKNOWN", detail="package query tool is unavailable")
                installed: dict[str, bool] = {}
                for package in packages:
                    probed = self.runner(query_args(package))
                    if probed.get("timed_out") or probed.get("returncode") is None:
                        return _command_result(outcome="UNKNOWN", detail=f"package query failed for {package}")
                    if probed.get("returncode") not in {0, 1}:
                        return _command_result(outcome="FAIL", detail=f"package query failed for {package}")
                    installed[package] = probed.get("returncode") == 0
                return _command_result(outcome="PASS", detail="package state queried", data={"packages": installed})
            command = self._package_command(operation, packages)
            if command is None:
                return _command_result(outcome="UNKNOWN", detail="supported Linux package manager is unavailable")
            result = _result_from_process(self.runner(command), success_detail=f"package {operation} completed", failure_detail=f"package {operation} failed", changed=operation in {"install", "remove", "refresh"})
            if operation == "query":
                result["data"] = {"packages": {package: result["outcome"] == "PASS" for package in packages}}
            return result
        if family == "service-management":
            service = self._service(args["service"])
            executable = _system_executable("systemctl")
            if executable is None:
                return _command_result(outcome="UNKNOWN", detail="systemctl executable is unavailable")
            if operation == "status":
                command = [executable, "is-enabled" if args.get("state") in {"enabled", "disabled"} else "is-active", service]
            else:
                command = [executable, operation, service]
            result = _result_from_process(self.runner(command), success_detail=f"service {operation} completed", failure_detail=f"service {operation} failed", changed=operation != "status", data={"service": service})
            if operation == "status":
                result["data"] = {"service": service, "state": str(result.get("stdout") or "").strip() or "unknown"}
            return result
        if family in {"system-reboot", "system-shutdown"}:
            if args.get("delay_seconds", 0) != 0:
                return _command_result(outcome="SKIPPED", detail="delayed power operations are not implemented")
            executable = _system_executable("systemctl")
            if executable is None:
                return _command_result(outcome="UNKNOWN", detail="systemctl executable is unavailable")
            command = [executable, "reboot" if family == "system-reboot" else "poweroff"]
            return _result_from_process(self.runner(command), success_detail=f"{family} requested", failure_detail=f"{family} request failed", changed=True)
        if family == "kernel-parameter-management":
            return self._sysctl(args["key"], args.get("value") if operation == "set" else None)
        if family == "kernel-module-management":
            executable = _system_executable("modprobe")
            if executable is None:
                return _command_result(outcome="UNKNOWN", detail="modprobe executable is unavailable")
            if operation == "status":
                lsmod = _system_executable("lsmod")
                if lsmod is None:
                    return _command_result(outcome="UNKNOWN", detail="lsmod executable is unavailable")
                command = [lsmod]
            else:
                command = [executable, "-r", args["module"]] if operation == "unload" else [executable, args["module"]]
            if operation == "status":
                result = _result_from_process(self.runner(command), success_detail="module inventory collected", failure_detail="module inventory failed")
                result["data"] = {"module": args["module"], "present": args["module"] in str(result.get("stdout") or "").split()}
                return result
            return _result_from_process(self.runner(command), success_detail=f"module {operation} completed", failure_detail=f"module {operation} failed", changed=True, data={"module": args["module"]})
        if family in {"performance-counters", "ebpf"}:
            key = "kernel.perf_event_paranoid" if family == "performance-counters" else "kernel.unprivileged_bpf_disabled"
            if operation == "status":
                return self._sysctl(key)
            return self._sysctl(key, "-1" if family == "performance-counters" and operation == "enable" else "0" if family == "ebpf" and operation == "enable" else "2" if family == "performance-counters" else "1")
        if family == "experiment-directory-management":
            target = self._path(args["path"], roots=self.profile.value["experiment_roots"])
            if operation == "inspect":
                exists = target.exists()
                return _command_result(outcome="PASS", detail="experiment directory inspected", data={"path": str(target), "exists": exists, "directory": target.is_dir() if exists else False})
            if operation == "create":
                if target.exists() and not target.is_dir():
                    return _command_result(outcome="FAIL", detail="experiment path exists but is not a directory")
                existed = target.exists()
                target.mkdir(parents=True, exist_ok=True)
                return _command_result(outcome="PASS", detail="experiment directory is ready", changed=not existed, data={"path": str(target)})
            if not target.exists():
                return _command_result(outcome="PASS", detail="experiment directory already absent", data={"path": str(target)})
            if not target.is_dir():
                return _command_result(outcome="FAIL", detail="experiment cleanup target is not a directory")
            shutil.rmtree(target)
            return _command_result(outcome="PASS", detail="experiment directory cleaned up", changed=True, data={"path": str(target)})
        if family == "cgroup-management":
            root_text = self.profile.value.get("cgroup_root")
            if not root_text:
                return _command_result(outcome="SKIPPED", detail="cgroup root is not configured")
            if not _CGROUP_NAME.fullmatch(args["name"]):
                raise ValidationError("cgroup name is invalid")
            target = Path(root_text) / args["name"]
            if operation == "status":
                return _command_result(outcome="PASS", detail="cgroup inspected", data={"path": str(target), "exists": target.is_dir()})
            if operation == "create":
                existed = target.exists()
                target.mkdir(parents=False, exist_ok=True)
                return _command_result(outcome="PASS", detail="cgroup is ready", changed=not existed, data={"path": str(target)})
            if operation == "cleanup":
                if not target.exists():
                    return _command_result(outcome="PASS", detail="cgroup already absent")
                target.rmdir()
                return _command_result(outcome="PASS", detail="cgroup cleaned up", changed=True)
            if not target.is_dir():
                return _command_result(outcome="FAIL", detail="cgroup does not exist")
            changed: list[str] = []
            for field, filename in (("cpu_max", "cpu.max"), ("memory_max", "memory.max")):
                if field in args:
                    (target / filename).write_text(args[field], encoding="ascii")
                    changed.append(field)
            return _command_result(outcome="PASS", detail="cgroup limits applied", changed=bool(changed), data={"fields": changed})
        if family == "device-access":
            target = self._path(args["path"], roots=self.profile.value["device_roots"])
            try:
                info = target.stat()
            except OSError as exc:
                return _command_result(outcome="UNKNOWN", detail=f"device observation failed: {exc}")
            return _command_result(outcome="PASS", detail="device metadata collected", data={"path": str(target), "mode": stat.filemode(info.st_mode), "size": info.st_size})
        if family in {"hardware-observation", "system-observation"}:
            data: dict[str, str] = {}
            for observation in args["observations"]:
                path = DEFAULT_OBSERVATION_PATHS.get(observation)
                if path is None:
                    return _command_result(outcome="SKIPPED", detail=f"observation is not allowlisted: {observation}")
                try:
                    data[observation] = Path(path).read_text(encoding="utf-8", errors="replace")[:2048]
                except OSError as exc:
                    return _command_result(outcome="UNKNOWN", detail=f"observation failed: {exc}")
            return _command_result(outcome="PASS", detail="bounded host observations collected", data=data)
        # These operations intentionally remain explicit unsupported results
        # until they have a narrowly reviewable Linux implementation. A
        # protected broker never falls back to shell or a generic privileged
        # command to satisfy them.
        return _command_result(outcome="SKIPPED", detail=f"{family}.{operation} has no Linux adapter")


class WindowsCapabilityBroker:
    """Structured Windows adapter intended to run inside a LocalSystem service."""

    def __init__(self, profile: HostPrivilegeProfile | Mapping[str, Any], *, runner: Callable[[list[str]], dict[str, Any]] | None = None) -> None:
        self.profile = profile if isinstance(profile, HostPrivilegeProfile) else HostPrivilegeProfile(dict(profile))
        if self.profile.platform != "windows":
            raise ValidationError("Windows capability broker requires a Windows profile")
        self.runner = runner or (lambda argv: _run_fixed(argv))

    def _path(self, raw: str) -> Path:
        if re.match(r"^(?:[A-Za-z]:[\\/]|\\\\)", raw) and os.name != "nt":
            raise ProtocolError("Windows path adapter cannot run on a non-Windows host")
        candidate = Path(raw)
        if not candidate.is_absolute():
            raise ValidationError("broker path must be absolute")
        candidate_abs = Path(os.path.abspath(str(candidate)))
        for root_text in self.profile.value["experiment_roots"]:
            root = Path(os.path.abspath(root_text))
            try:
                if os.path.commonpath((str(candidate_abs).casefold(), str(root).casefold())) == str(root).casefold() and candidate_abs != root:
                    current = root
                    for part in candidate_abs.relative_to(root).parts:
                        current = current / part
                        if current.is_symlink():
                            raise ValidationError("broker path contains a symbolic link")
                    return candidate_abs
            except ValueError:
                continue
        raise ValidationError("path is outside the configured Windows experiment roots")

    @staticmethod
    def _windows_executable(name: str) -> str:
        known = {
            "sc": r"C:\Windows\System32\sc.exe",
            "shutdown": r"C:\Windows\System32\shutdown.exe",
            "netsh": r"C:\Windows\System32\netsh.exe",
            "pnputil": r"C:\Windows\System32\pnputil.exe",
            # winget is installed as a Windows App Execution Alias.  Keeping
            # this path fixed still prevents a caller from selecting an
            # executable or injecting a shell fragment.
            "winget": r"C:\Windows\System32\winget.exe",
        }
        if name.lower().endswith(".exe"):
            return name
        return known.get(name, rf"C:\Windows\System32\{name}.exe")

    def execute(self, request: Mapping[str, Any]) -> Mapping[str, Any]:
        checked = validate_capability_request(request, expected_worker_id=self.profile.worker_identity)
        family = checked["capability"]
        operation = checked["operation"]
        args = checked["arguments"]
        if family == "service-management":
            service = args["service"]
            if self.profile.mode != "unrestricted" and service not in self.profile.value["service_allowlist"]:
                raise ValidationError("service is not allowlisted by the host profile")
            executable = self._windows_executable("sc")
            if operation == "restart":
                stopped = self.runner([executable, "stop", service])
                if stopped.get("timed_out") or stopped.get("returncode") not in {0, 1060, 1062}:
                    return _result_from_process(stopped, success_detail="Windows service restart completed", failure_detail="Windows service restart stop phase failed", changed=False)
                started = self.runner([executable, "start", service])
                return _result_from_process(started, success_detail="Windows service restart completed", failure_detail="Windows service restart start phase failed", changed=True, data={"service": service})
            if operation == "enable":
                command = [executable, "config", service, "start=", "auto"]
            elif operation == "disable":
                command = [executable, "config", service, "start=", "disabled"]
            else:
                command = [executable, operation if operation != "status" else "query", service]
            return _result_from_process(self.runner(command), success_detail=f"Windows service {operation} completed", failure_detail=f"Windows service {operation} failed", changed=operation != "status", data={"service": service})
        if family in {"system-reboot", "system-shutdown"}:
            if args.get("delay_seconds", 0) != 0:
                return _command_result(outcome="SKIPPED", detail="delayed power operations are not implemented")
            command = [self._windows_executable("shutdown"), "/r" if family == "system-reboot" else "/s", "/t", "0"]
            return _result_from_process(self.runner(command), success_detail=f"{family} requested", failure_detail=f"{family} request failed", changed=True)
        if family == "package-management":
            packages = args.get("packages", [])
            if operation in {"install", "remove", "query"} and len(packages) != 1:
                return _command_result(outcome="SKIPPED", detail="Windows package operations currently accept one package identifier")
            if operation == "refresh":
                command = [self._windows_executable("winget"), "source", "update"]
            elif operation == "query":
                command = [self._windows_executable("winget"), "list", "--id", packages[0], "--exact"] if packages else [self._windows_executable("winget"), "list"]
            elif operation == "install":
                command = [self._windows_executable("winget"), "install", "--id", packages[0], "--exact", "--silent", "--accept-source-agreements", "--accept-package-agreements"]
            else:
                command = [self._windows_executable("winget"), "uninstall", "--id", packages[0], "--exact", "--silent"]
            return _result_from_process(self.runner(command), success_detail=f"Windows package {operation} completed", failure_detail=f"Windows package {operation} failed", changed=operation in {"install", "remove", "refresh"})
        if family == "experiment-directory-management":
            target = self._path(args["path"])
            if operation == "inspect":
                return _command_result(outcome="PASS", detail="experiment directory inspected", data={"path": str(target), "exists": target.exists(), "directory": target.is_dir() if target.exists() else False})
            if operation == "create":
                existed = target.exists()
                if existed and not target.is_dir():
                    return _command_result(outcome="FAIL", detail="experiment path exists but is not a directory")
                target.mkdir(parents=True, exist_ok=True)
                return _command_result(outcome="PASS", detail="experiment directory is ready", changed=not existed)
            if not target.exists():
                return _command_result(outcome="PASS", detail="experiment directory already absent")
            if not target.is_dir():
                return _command_result(outcome="FAIL", detail="experiment cleanup target is not a directory")
            shutil.rmtree(target)
            return _command_result(outcome="PASS", detail="experiment directory cleaned up", changed=True)
        if family == "firewall-management":
            if operation == "status":
                command = [self._windows_executable("netsh"), "advfirewall", "show", "allprofiles"]
            elif operation == "add-rule":
                command = [self._windows_executable("netsh"), "advfirewall", "firewall", "add", "rule", f"name={args['name']}", f"dir={args['direction']}", f"action={args['action']}", f"protocol={args['protocol']}", f"localport={args['local_port']}"]
            else:
                command = [self._windows_executable("netsh"), "advfirewall", "firewall", "delete", "rule", f"name={args['name']}"]
            return _result_from_process(self.runner(command), success_detail=f"Windows firewall {operation} completed", failure_detail=f"Windows firewall {operation} failed", changed=operation != "status")
        if family == "driver-management" and operation in {"install", "remove"}:
            path = self._path(args["path"])
            if path.suffix.lower() != ".inf":
                raise ValidationError("Windows driver path must be an INF file")
            command = [self._windows_executable("pnputil"), "/add-driver", str(path), "/install"] if operation == "install" else [self._windows_executable("pnputil"), "/delete-driver", path.name, "/uninstall"]
            return _result_from_process(self.runner(command), success_detail=f"Windows driver {operation} completed", failure_detail=f"Windows driver {operation} failed", changed=True)
        return _command_result(outcome="SKIPPED", detail=f"{family}.{operation} has no Windows adapter")


class UnrestrictedCapabilityBroker(LinuxCapabilityBroker):
    """Named adapter for a sacrificial Linux host.

    It still consumes structured requests. "Unrestricted" means the host
    policy does not require leases or narrow capability allowlists; it does not
    turn the Fabric API into a generic root command runner.
    """


def check_noninteractive_root(*, runner: Callable[[list[str]], dict[str, Any]] | None = None) -> dict[str, Any]:
    """Check the fixed worker-03 prerequisite without prompting for a secret."""

    if runner is None and os.name == "posix" and hasattr(os, "geteuid") and os.geteuid() == 0:
        return {"outcome": "PASS", "detail": "process already has root identity", "command": ["root"]}
    result = (runner or (lambda argv: _run_fixed(argv)))(["sudo", "-n", "true"])
    return _result_from_process(result, success_detail="non-interactive sudo is configured", failure_detail="non-interactive sudo is unavailable")


class CapabilityLeaseStore:
    """Append-only lease events with explicit revoke/expiry/cleanup semantics."""

    def __init__(self, path: Path) -> None:
        self.ledger = FabricLedger(Path(path))

    def grant(self, lease: Mapping[str, Any]) -> dict[str, Any]:
        checked = validate_capability_lease(dict(lease))
        self.ledger.append("capability.lease.grant", checked)
        return checked

    def _events(self, lease_identity: str) -> list[dict[str, Any]]:
        events: list[dict[str, Any]] = []
        for entry in iter_ledger_records(self.ledger):
            record = entry.get("record", {})
            if record.get("lease_identity") == lease_identity:
                events.append(record)
        return events

    def inspect(self, lease_identity: str, *, now: str | None = None) -> dict[str, Any]:
        _text(lease_identity, "lease_identity", 128)
        events = self._events(lease_identity)
        if not events:
            raise ValidationError("capability lease was not found")
        lease = validate_capability_lease(events[0])
        state = "ACTIVE"
        reason = None
        for event in events[1:]:
            state = str(event.get("state") or state)
            reason = event.get("reason")
        checked_now = _timestamp(now or utc_now(), "now")
        if state == "ACTIVE" and checked_now >= _timestamp(lease["expires_at"], "expires_at"):
            state = "EXPIRED"
        return {"lease": lease, "state": state, "reason": reason, "checked_at": _iso(checked_now)}

    def is_active(self, lease_identity: str, *, worker_identity: str, capability: str, operation: str, experiment_identity: str | None = None, now: str | None = None) -> bool:
        try:
            inspected = self.inspect(lease_identity, now=now)
        except ValidationError:
            return False
        lease = inspected["lease"]
        return bool(
            inspected["state"] == "ACTIVE"
            and lease["worker_identity"] == worker_identity
            and capability in lease["capabilities"]
            and operation in lease["operations"].get(capability, [])
            and (lease["experiment_identity"] is None or lease["experiment_identity"] == experiment_identity)
        )

    def _set_state(self, lease_identity: str, state: str, reason: str) -> dict[str, Any]:
        inspected = self.inspect(lease_identity)
        if inspected["state"] == state:
            return {
                "schema_version": CAPABILITY_LEASE_SCHEMA,
                "lease_identity": lease_identity,
                "worker_identity": inspected["lease"]["worker_identity"],
                "state": state,
                "reason": inspected.get("reason") or _text(reason, "reason", 256),
                "changed_at": utc_now(),
            }
        record = {
            "schema_version": CAPABILITY_LEASE_SCHEMA,
            "lease_identity": lease_identity,
            "worker_identity": inspected["lease"]["worker_identity"],
            "state": state,
            "reason": _text(reason, "reason", 256),
            "changed_at": utc_now(),
        }
        self.ledger.append(f"capability.lease.{state.lower()}", record)
        return record

    def revoke(self, lease_identity: str, *, reason: str = "operator revoked lease") -> dict[str, Any]:
        return self._set_state(lease_identity, "REVOKED", reason)

    def expire(self, *, now: str | None = None, worker_identity: str | None = None) -> list[dict[str, Any]]:
        checked_now = _timestamp(now or utc_now(), "now")
        identities: set[str] = set()
        for entry in iter_ledger_records(self.ledger):
            record = entry.get("record", {})
            identity = record.get("lease_identity")
            if isinstance(identity, str):
                identities.add(identity)
        expired: list[dict[str, Any]] = []
        for identity in sorted(identities):
            try:
                inspected = self.inspect(identity, now=_iso(checked_now))
            except ValidationError:
                continue
            lease = inspected["lease"]
            if worker_identity is not None and lease["worker_identity"] != worker_identity:
                continue
            if inspected["state"] == "EXPIRED" and not any(event.get("state") == "EXPIRED" for event in self._events(identity)[1:]):
                expired.append(self._set_state(identity, "EXPIRED", "lease ttl elapsed"))
        return expired

    def cleanup(self, *, worker_identity: str | None = None, now: str | None = None) -> list[dict[str, Any]]:
        # Cleanup is an auditable state transition, not destructive ledger
        # deletion. Historical grants remain available for evidence review.
        self.expire(now=now, worker_identity=worker_identity)
        removed: list[dict[str, Any]] = []
        identities: set[str] = set()
        for entry in iter_ledger_records(self.ledger):
            record = entry.get("record", {})
            identity = record.get("lease_identity")
            if isinstance(identity, str):
                identities.add(identity)
        for identity in sorted(identities):
            try:
                inspected = self.inspect(identity, now=now)
            except ValidationError:
                continue
            if worker_identity is not None and inspected["lease"]["worker_identity"] != worker_identity:
                continue
            if inspected["state"] in {"EXPIRED", "REVOKED"}:
                removed.append(self._set_state(identity, "CLEANED", "lease cleanup completed"))
        return removed


class CapabilityAuditStore:
    """Machine-readable append-only audit records with secret redaction."""

    def __init__(self, path: Path) -> None:
        self.ledger = FabricLedger(Path(path))

    def record(self, *, request: Mapping[str, Any], result: Mapping[str, Any], worker_identity: str, experiment_identity: str | None = None, agent_session: str | None = None, lease_identity: str | None = None) -> dict[str, Any]:
        checked_request = validate_capability_request(dict(request), expected_worker_id=worker_identity)
        checked_result = _validate_result_body(dict(result))
        value = {
            "schema_version": CAPABILITY_AUDIT_SCHEMA,
            "worker_identity": _identity_or_text(worker_identity, "worker_identity"),
            "experiment_identity": _optional_text(experiment_identity or checked_request.get("experiment_identity"), "experiment_identity", 256),
            "agent_session": _optional_text(agent_session or checked_request.get("agent_session"), "agent_session", 256),
            "lease_identity": _optional_text(lease_identity or checked_request.get("lease_identity"), "lease_identity", 128),
            "request_identity": checked_request["request_identity"],
            "capability": checked_request["capability"],
            "operation": checked_request["operation"],
            "arguments": _redact(checked_request["arguments"]),
            "result": _redact(checked_result),
            "recorded_at": utc_now(),
            "claim_boundary": "broker operation audit; not proof of host honesty or independent assurance",
        }
        return validate_capability_audit(attach_identity(value, "audit_identity"), expected_worker_id=worker_identity)

    def append(self, record: Mapping[str, Any]) -> dict[str, Any]:
        value = validate_capability_audit(dict(record))
        self.ledger.append("capability.audit", value)
        return value

    def records(self, *, worker_identity: str | None = None) -> list[dict[str, Any]]:
        result = []
        for entry in iter_ledger_records(self.ledger):
            if entry.get("record_type") != "capability.audit":
                continue
            record = entry.get("record")
            if isinstance(record, dict):
                checked = validate_capability_audit(record, expected_worker_id=worker_identity)
                result.append(checked)
        return result


class CapabilityResultStore:
    """Durable idempotency records for exact capability request identities."""

    def __init__(self, path: Path) -> None:
        self.ledger = FabricLedger(Path(path))

    def find(self, request_identity: str, *, worker_identity: str) -> dict[str, Any] | None:
        candidate: dict[str, Any] | None = None
        for entry in iter_ledger_records(self.ledger, record_type="capability.result"):
            record = entry.get("record")
            if not isinstance(record, dict) or record.get("request_identity") != request_identity:
                continue
            checked = validate_capability_result(record, expected_worker_id=worker_identity)
            if candidate is not None and candidate != checked:
                raise StorageError("capability request identity has conflicting durable results")
            candidate = checked
        return candidate

    def append(self, result: Mapping[str, Any]) -> dict[str, Any]:
        checked = validate_capability_result(dict(result))
        self.ledger.append("capability.result", checked)
        return checked


def build_capability_result(request: Mapping[str, Any], *, outcome: str, detail: str, audit_identity: str | None = None, changed: bool = False, previous_state: object = None, new_state: object = None, data: Mapping[str, Any] | None = None, stdout: str = "", stderr: str = "") -> dict[str, Any]:
    checked = validate_capability_request(request)
    value: dict[str, Any] = {
        "schema_version": CAPABILITY_RESULT_SCHEMA,
        "protocol": CAPABILITY_BROKER_PROTOCOL,
        "worker_identity": checked["worker_identity"],
        "request_identity": checked["request_identity"],
        "capability": checked["capability"],
        "operation": checked["operation"],
        **_command_result(outcome=outcome, detail=detail, changed=changed, previous_state=previous_state, new_state=new_state, data=data, stdout=stdout, stderr=stderr),
        "audit_identity": audit_identity,
        "claim_boundary": "broker operation result; not host attestation or execution correctness",
    }
    return attach_identity(value, "result_identity")


def validate_capability_result(value: object, *, expected_worker_id: str | None = None) -> dict[str, Any]:
    if not isinstance(value, dict) or value.get("schema_version") != CAPABILITY_RESULT_SCHEMA:
        raise ValidationError("unsupported capability result schema")
    required = {
        "schema_version", "protocol", "worker_identity", "request_identity", "capability", "operation", "outcome",
        "detail", "changed", "previous_state", "new_state", "data", "stdout", "stderr", "audit_identity", "claim_boundary", "result_identity",
    }
    if set(value) != required or value.get("protocol") != CAPABILITY_BROKER_PROTOCOL or not verify_identity(value, "result_identity"):
        raise ValidationError("capability result fields or identity are invalid")
    worker_id = _identity_or_text(value["worker_identity"], "worker_identity")
    if expected_worker_id is not None and worker_id != expected_worker_id:
        raise ValidationError("capability result is bound to another worker")
    if not is_sha256_identity(value["request_identity"]):
        raise ValidationError("capability result request identity is invalid")
    _validate_capability_operation(value["capability"], value["operation"])
    if value["outcome"] not in {"PASS", "FAIL", "UNKNOWN", "SKIPPED"} or not isinstance(value["changed"], bool):
        raise ValidationError("capability result status is invalid")
    _text(value["detail"], "detail", 512)
    if not isinstance(value["data"], dict) or not isinstance(value["stdout"], str) or not isinstance(value["stderr"], str):
        raise ValidationError("capability result output is invalid")
    if len(value["stdout"]) > MAX_AUDIT_OUTPUT or len(value["stderr"]) > MAX_AUDIT_OUTPUT:
        raise ValidationError("capability result output exceeds its bound")
    if value["audit_identity"] is not None and not is_sha256_identity(value["audit_identity"]):
        raise ValidationError("capability result audit identity is invalid")
    return dict(value)


def validate_capability_audit(value: object, *, expected_worker_id: str | None = None) -> dict[str, Any]:
    if not isinstance(value, dict) or value.get("schema_version") != CAPABILITY_AUDIT_SCHEMA:
        raise ValidationError("unsupported capability audit schema")
    required = {
        "schema_version", "worker_identity", "experiment_identity", "agent_session", "lease_identity",
        "request_identity", "capability", "operation", "arguments", "result", "recorded_at", "claim_boundary",
        "audit_identity",
    }
    if set(value) != required or not verify_identity(value, "audit_identity"):
        raise ValidationError("capability audit fields or identity are invalid")
    worker_id = _identity_or_text(value["worker_identity"], "worker_identity")
    if expected_worker_id is not None and worker_id != expected_worker_id:
        raise ValidationError("capability audit is bound to another worker")
    if not is_sha256_identity(value["request_identity"]):
        raise ValidationError("capability audit request identity is invalid")
    family, operation = _validate_capability_operation(value["capability"], value["operation"])
    checked_arguments = validate_capability_arguments(family, operation, value["arguments"])
    if checked_arguments != value["arguments"]:
        raise ValidationError("capability audit arguments are not canonical")
    _optional_text(value["experiment_identity"], "experiment_identity", 256)
    _optional_text(value["agent_session"], "agent_session", 256)
    _optional_text(value["lease_identity"], "lease_identity", 128)
    _validate_result_body(value["result"])
    _timestamp(value["recorded_at"], "recorded_at")
    expected_claim = "broker operation audit; not proof of host honesty or independent assurance"
    if value["claim_boundary"] != expected_claim:
        raise ValidationError("capability audit claim boundary is invalid")
    return dict(value)


def build_capability_reconcile_result(
    *,
    worker_identity: str,
    experiment_identity: str,
    requirements_identity: str,
    lease_identity: str | None,
    disposition: str,
    requests: Iterable[Mapping[str, Any]],
    observations: Iterable[Mapping[str, Any]],
    results: Iterable[Mapping[str, Any]],
    changed: bool,
) -> dict[str, Any]:
    value = {
        "schema_version": CAPABILITY_RECONCILE_SCHEMA,
        "worker_identity": _identity_or_text(worker_identity, "worker_identity"),
        "experiment_identity": _identity_or_text(experiment_identity, "experiment_identity"),
        "requirements_identity": requirements_identity,
        "lease_identity": lease_identity,
        "disposition": disposition,
        "requests": [dict(item) for item in requests],
        "observations": [dict(item) for item in observations],
        "results": [dict(item) for item in results],
        "changed": changed,
        "claim_boundary": "typed desired-state reconciliation; not proof of machine honesty or experiment correctness",
    }
    return validate_capability_reconcile_result(attach_identity(value, "reconcile_identity"), expected_worker_id=worker_identity)


def validate_capability_reconcile_result(value: object, *, expected_worker_id: str | None = None) -> dict[str, Any]:
    if not isinstance(value, dict) or value.get("schema_version") != CAPABILITY_RECONCILE_SCHEMA:
        raise ValidationError("unsupported capability reconciliation schema")
    required = {
        "schema_version", "worker_identity", "experiment_identity", "requirements_identity", "lease_identity",
        "disposition", "requests", "observations", "results", "changed", "claim_boundary", "reconcile_identity",
    }
    if set(value) != required or not verify_identity(value, "reconcile_identity"):
        raise ValidationError("capability reconciliation fields or identity are invalid")
    worker_id = _identity_or_text(value["worker_identity"], "worker_identity")
    if expected_worker_id is not None and worker_id != expected_worker_id:
        raise ValidationError("capability reconciliation is bound to another worker")
    _identity_or_text(value["experiment_identity"], "experiment_identity")
    if not is_sha256_identity(value["requirements_identity"]):
        raise ValidationError("capability reconciliation requirements identity is invalid")
    if value["lease_identity"] is not None and not is_sha256_identity(value["lease_identity"]):
        raise ValidationError("capability reconciliation lease identity is invalid")
    if value["disposition"] not in {"PASS", "FAIL", "UNKNOWN"} or not isinstance(value["changed"], bool):
        raise ValidationError("capability reconciliation status is invalid")
    for field, validator in (
        ("requests", validate_capability_request),
        ("observations", validate_capability_result),
        ("results", validate_capability_result),
    ):
        items = value[field]
        if not isinstance(items, list) or len(items) > 1024:
            raise ValidationError(f"capability reconciliation {field} are invalid")
        for item in items:
            validator(item, expected_worker_id=worker_id)
    expected_claim = "typed desired-state reconciliation; not proof of machine honesty or experiment correctness"
    if value["claim_boundary"] != expected_claim:
        raise ValidationError("capability reconciliation claim boundary is invalid")
    if len(canonical_json_bytes(value)) > MAX_REQUEST_BYTES:
        raise ValidationError("capability reconciliation exceeds its bound")
    return dict(value)


class CapabilityBroker:
    """Policy and audit facade shared by local, Linux, and Windows workers."""

    def __init__(self, profile: HostPrivilegeProfile | Mapping[str, Any], *, adapter: CapabilityAdapter | None = None, lease_store: CapabilityLeaseStore | None = None, audit_store: CapabilityAuditStore | None = None, state_path: Path | None = None) -> None:
        self.profile = profile if isinstance(profile, HostPrivilegeProfile) else HostPrivilegeProfile(dict(profile))
        base = Path(state_path) if state_path is not None else None
        self.leases = lease_store or (CapabilityLeaseStore(base.with_name(base.stem + ".leases.jsonl")) if base else None)
        self.audit = audit_store or (CapabilityAuditStore(base.with_name(base.stem + ".audit.jsonl")) if base else None)
        self.results = CapabilityResultStore(base.with_name(base.stem + ".results.jsonl")) if base else None
        if adapter is not None:
            self.adapter = adapter
        elif self.profile.platform == "windows":
            self.adapter = WindowsCapabilityBroker(self.profile)
        elif self.profile.mode == "unrestricted":
            self.adapter = UnrestrictedCapabilityBroker(self.profile)
        else:
            self.adapter = LinuxCapabilityBroker(self.profile)

    def grant_lease(self, *, experiment_identity: str | None, capabilities: Iterable[str], ttl_seconds: int, operations: Mapping[str, Iterable[str]] | None = None, granted_by: str = "fabric-policy") -> dict[str, Any]:
        if self.leases is None:
            raise ProtocolError("capability lease persistence is not configured")
        names = list(capabilities)
        for capability in names:
            if capability not in self.profile.value["allowed_capabilities"]:
                raise ValidationError("lease requests a capability outside the host profile")
        lease = build_capability_lease(worker_identity=self.profile.worker_identity, experiment_identity=experiment_identity, capabilities=names, ttl_seconds=ttl_seconds, operations=operations, granted_by=granted_by)
        return self.leases.grant(lease)

    def inspect_lease(self, lease_identity: str, *, now: str | None = None) -> dict[str, Any]:
        if self.leases is None:
            raise ProtocolError("capability lease persistence is not configured")
        return self.leases.inspect(lease_identity, now=now)

    def revoke_lease(self, lease_identity: str, *, reason: str = "operator revoked lease") -> dict[str, Any]:
        if self.leases is None:
            raise ProtocolError("capability lease persistence is not configured")
        return self.leases.revoke(lease_identity, reason=reason)

    def expire_leases(self, *, now: str | None = None) -> list[dict[str, Any]]:
        if self.leases is None:
            raise ProtocolError("capability lease persistence is not configured")
        return self.leases.expire(now=now, worker_identity=self.profile.worker_identity)

    def cleanup_leases(self, *, now: str | None = None) -> list[dict[str, Any]]:
        if self.leases is None:
            raise ProtocolError("capability lease persistence is not configured")
        return self.leases.cleanup(now=now, worker_identity=self.profile.worker_identity)

    def request(self, request: Mapping[str, Any] | dict[str, Any]) -> dict[str, Any]:
        checked = validate_capability_request(request, expected_worker_id=self.profile.worker_identity)
        if self.results is not None:
            prior = self.results.find(checked["request_identity"], worker_identity=self.profile.worker_identity)
            if prior is not None:
                return prior
        # A crash after the adapter completed but before the result ledger was
        # appended must not repeat a privileged operation. The audit ledger is
        # written first and contains the bounded result body needed for recovery.
        if self.audit is not None:
            for audit in self.audit.records(worker_identity=self.profile.worker_identity):
                if audit.get("request_identity") != checked["request_identity"]:
                    continue
                if not verify_identity(audit, "audit_identity") or not isinstance(audit.get("result"), dict):
                    raise StorageError("capability audit recovery record is invalid")
                prior_body = audit["result"]
                recovered = build_capability_result(
                    checked,
                    outcome=str(prior_body.get("outcome", "UNKNOWN")),
                    detail=str(prior_body.get("detail", "recovered capability result")),
                    audit_identity=audit["audit_identity"],
                    changed=bool(prior_body.get("changed", False)),
                    previous_state=prior_body.get("previous_state"),
                    new_state=prior_body.get("new_state"),
                    data=prior_body.get("data") if isinstance(prior_body.get("data"), dict) else {},
                    stdout=str(prior_body.get("stdout", "")),
                    stderr=str(prior_body.get("stderr", "")),
                )
                if self.results is not None:
                    self.results.append(recovered)
                return validate_capability_result(recovered, expected_worker_id=self.profile.worker_identity)
        family = checked["capability"]
        operation = checked["operation"]
        result_body: Mapping[str, Any]
        if not self.profile.allows(family, operation):
            result_body = _command_result(outcome="FAIL", detail="capability is not allowed by the host profile")
        elif self.profile.requires_lease(family, operation):
            lease_id = checked.get("lease_identity")
            if self.leases is None or not lease_id or not self.leases.is_active(lease_id, worker_identity=self.profile.worker_identity, capability=family, operation=operation, experiment_identity=checked.get("experiment_identity")):
                result_body = _command_result(outcome="SKIPPED", detail="operation requires an active capability lease")
            else:
                try:
                    result_body = self.adapter.execute(checked)
                except (ValidationError, OSError) as exc:
                    result_body = _command_result(outcome="FAIL", detail=str(exc))
        else:
            try:
                result_body = self.adapter.execute(checked)
            except (ValidationError, OSError) as exc:
                result_body = _command_result(outcome="FAIL", detail=str(exc))
        audit_identity = None
        if self.audit is not None:
            audit = self.audit.record(request=checked, result=result_body, worker_identity=self.profile.worker_identity)
            self.audit.append(audit)
            audit_identity = audit["audit_identity"]
        result = build_capability_result(checked, outcome=str(result_body.get("outcome", "UNKNOWN")), detail=str(result_body.get("detail", "broker returned no detail")), audit_identity=audit_identity, changed=bool(result_body.get("changed", False)), previous_state=result_body.get("previous_state"), new_state=result_body.get("new_state"), data=result_body.get("data") if isinstance(result_body.get("data"), dict) else {}, stdout=str(result_body.get("stdout", "")), stderr=str(result_body.get("stderr", "")))
        if self.results is not None:
            self.results.append(result)
        return validate_capability_result(result, expected_worker_id=self.profile.worker_identity)

    def reconcile(self, requirements: Mapping[str, Any], *, apply: bool = True, lease_identity: str | None = None, auto_grant_ttl_seconds: int | None = None) -> dict[str, Any]:
        checked = validate_experiment_requirements(requirements, expected_worker_id=self.profile.worker_identity)
        required_caps = list(checked["capabilities"])
        risky_names = set(required_caps)
        if checked["packages"]:
            risky_names.add("package-management")
        if checked["services"]:
            risky_names.add("service-management")
        if checked["system"]["reboot"]:
            risky_names.add("system-reboot")
        if checked["system"]["shutdown"]:
            risky_names.add("system-shutdown")
        risky = sorted(risky_names & set(self.profile.value["lease_required"]))
        active_lease = lease_identity
        if risky and active_lease is None and auto_grant_ttl_seconds is not None:
            if not self.profile.value["automatic_leases"]:
                raise ProtocolError("automatic capability leases are disabled by host policy")
            lease = self.grant_lease(experiment_identity=checked["experiment_identity"], capabilities=risky, ttl_seconds=auto_grant_ttl_seconds, granted_by="experiment-reconciler")
            active_lease = lease["lease_identity"]
        requests: list[dict[str, Any]] = []
        observations: list[dict[str, Any]] = []

        def probe(request: dict[str, Any]) -> dict[str, Any] | None:
            if not apply:
                return None
            result = self.request(request)
            observations.append(result)
            return result

        def schedule_if_needed(request: dict[str, Any], current: dict[str, Any] | None, compliant: Callable[[dict[str, Any]], bool]) -> None:
            if current is None or current.get("outcome") != "PASS" or not compliant(current):
                requests.append(request)

        for capability in required_caps:
            if capability not in self.profile.value["allowed_capabilities"]:
                requests.append(build_capability_request(worker_identity=self.profile.worker_identity, capability=capability, operation="status", arguments={}, experiment_identity=checked["experiment_identity"], lease_identity=active_lease))
        for package in checked["packages"]:
            query = build_capability_request(worker_identity=self.profile.worker_identity, capability="package-management", operation="query", arguments={"packages": [package]}, experiment_identity=checked["experiment_identity"], lease_identity=active_lease)
            current = probe(query)
            schedule_if_needed(
                build_capability_request(worker_identity=self.profile.worker_identity, capability="package-management", operation="install", arguments={"packages": [package]}, experiment_identity=checked["experiment_identity"], lease_identity=active_lease),
                current,
                lambda item, package=package: item.get("data", {}).get("packages", {}).get(package) is True,
            )
        for key, value in checked["sysctl"].items():
            query = build_capability_request(worker_identity=self.profile.worker_identity, capability="kernel-parameter-management", operation="get", arguments={"key": key}, experiment_identity=checked["experiment_identity"], lease_identity=active_lease)
            current = probe(query)
            schedule_if_needed(
                build_capability_request(worker_identity=self.profile.worker_identity, capability="kernel-parameter-management", operation="set", arguments={"key": key, "value": value}, experiment_identity=checked["experiment_identity"], lease_identity=active_lease),
                current,
                lambda item, value=value: item.get("data", {}).get("value") == value,
            )
        for service, state in checked["services"].items():
            operation = {"running": "start", "stopped": "stop", "enabled": "enable", "disabled": "disable"}[state]
            query = build_capability_request(worker_identity=self.profile.worker_identity, capability="service-management", operation="status", arguments={"service": service, "state": state}, experiment_identity=checked["experiment_identity"], lease_identity=active_lease)
            current = probe(query)
            schedule_if_needed(
                build_capability_request(worker_identity=self.profile.worker_identity, capability="service-management", operation=operation, arguments={"service": service}, experiment_identity=checked["experiment_identity"], lease_identity=active_lease),
                current,
                lambda item, state=state: item.get("data", {}).get("state") in {state, "active" if state == "running" else "inactive" if state == "stopped" else state},
            )
        if checked["experiment_directory"]:
            query = build_capability_request(worker_identity=self.profile.worker_identity, capability="experiment-directory-management", operation="inspect", arguments={"path": checked["experiment_directory"]}, experiment_identity=checked["experiment_identity"], lease_identity=active_lease)
            current = probe(query)
            schedule_if_needed(
                build_capability_request(worker_identity=self.profile.worker_identity, capability="experiment-directory-management", operation="create", arguments={"path": checked["experiment_directory"]}, experiment_identity=checked["experiment_identity"], lease_identity=active_lease),
                current,
                lambda item: item.get("data", {}).get("exists") is True and item.get("data", {}).get("directory") is True,
            )
        if checked["system"]["reboot"]:
            requests.append(build_capability_request(worker_identity=self.profile.worker_identity, capability="system-reboot", operation="request", arguments={}, experiment_identity=checked["experiment_identity"], lease_identity=active_lease))
        if checked["system"]["shutdown"]:
            requests.append(build_capability_request(worker_identity=self.profile.worker_identity, capability="system-shutdown", operation="request", arguments={}, experiment_identity=checked["experiment_identity"], lease_identity=active_lease))
        if not apply:
            results = [build_capability_result(item, outcome="SKIPPED", detail="plan only") for item in requests]
        else:
            results = [self.request(item) for item in requests]
        failed = any(item["outcome"] == "FAIL" for item in results)
        unknown = any(item["outcome"] in {"UNKNOWN", "SKIPPED"} for item in results)
        disposition = "FAIL" if failed else "UNKNOWN" if unknown else "PASS"
        return build_capability_reconcile_result(
            worker_identity=self.profile.worker_identity,
            experiment_identity=checked["experiment_identity"],
            requirements_identity=checked["requirements_identity"],
            lease_identity=active_lease,
            disposition=disposition,
            requests=requests,
            observations=observations,
            results=results,
            changed=any(item.get("changed") for item in results),
        )


def _recv_exact(stream: socket.socket, size: int) -> bytes:
    data = bytearray()
    while len(data) < size:
        chunk = stream.recv(size - len(data))
        if not chunk:
            raise ProtocolError("capability broker connection ended mid-frame")
        data.extend(chunk)
    return bytes(data)


def _frame_bytes(value: Mapping[str, Any], *, max_frame_bytes: int = MAX_REQUEST_BYTES) -> bytes:
    raw = canonical_json_bytes(dict(value))
    if len(raw) > max_frame_bytes:
        raise ProtocolError("capability broker frame exceeds its bound")
    return struct.pack("!I", len(raw)) + raw


def _send_frame(stream: socket.socket, value: Mapping[str, Any]) -> None:
    stream.sendall(_frame_bytes(value))


class UnixCapabilityBrokerServer:
    """Root-owned local broker endpoint with exact peer-UID authorization."""

    def __init__(self, broker: CapabilityBroker, socket_path: Path, *, allowed_uids: Iterable[int], timeout: float = 30.0, max_frame_bytes: int = MAX_REQUEST_BYTES) -> None:
        self.broker = broker
        self.socket_path = Path(socket_path)
        self.allowed_uids = frozenset(int(uid) for uid in allowed_uids)
        if not self.allowed_uids or timeout <= 0 or not 1 <= max_frame_bytes <= MAX_REQUEST_BYTES:
            raise ValidationError("Unix broker server bounds or peer policy are invalid")
        self.timeout = timeout
        self.max_frame_bytes = max_frame_bytes
        self._listener: socket.socket | None = None
        self._stop = Event()
        self.handled_requests = 0
        self.last_error: str | None = None

    def bind(self) -> None:
        if os.name != "posix":
            raise ProtocolError("Unix capability broker is only available on POSIX")
        self.socket_path.parent.mkdir(parents=True, exist_ok=True)
        if self.socket_path.exists() or self.socket_path.is_symlink():
            if self.socket_path.is_symlink() or not stat.S_ISSOCK(self.socket_path.stat().st_mode):
                raise ProtocolError("capability broker socket path is not a safe stale socket")
            self.socket_path.unlink()
        listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        listener.settimeout(self.timeout)
        listener.bind(str(self.socket_path))
        os.chmod(self.socket_path, 0o660)
        listener.listen(1)
        self._listener = listener

    def _peer_uid(self, stream: socket.socket) -> int:
        if not hasattr(socket, "SO_PEERCRED"):
            raise ProtocolError("peer credential checks are unavailable")
        raw = stream.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i"))
        pid, uid, _gid = struct.unpack("3i", raw)
        del pid
        return uid

    def _handle(self, stream: socket.socket) -> None:
        with stream:
            stream.settimeout(self.timeout)
            if self._peer_uid(stream) not in self.allowed_uids:
                raise ProtocolError("capability broker peer UID is not authorized")
            header = _recv_exact(stream, 4)
            size = struct.unpack("!I", header)[0]
            if not 1 <= size <= self.max_frame_bytes:
                raise ProtocolError("capability broker frame size is invalid")
            raw_request = _recv_exact(stream, size)
            try:
                request = json.loads(raw_request.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                raise ProtocolError("capability broker frame is not canonical JSON") from exc
            if not isinstance(request, dict) or canonical_json_bytes(request) != raw_request:
                raise ProtocolError("capability broker frame is not canonical JSON")
            result = self.broker.request(request)
            _send_frame(stream, result)

    def serve_once(self) -> None:
        if self._listener is None:
            self.bind()
        assert self._listener is not None
        try:
            stream, _ = self._listener.accept()
            try:
                self._handle(stream)
                self.handled_requests += 1
            except (ProtocolError, ValidationError, OSError) as exc:
                self.last_error = str(exc)
        finally:
            self.close()

    def serve_forever(self, *, max_requests: int | None = None, idle_timeout: float | None = None) -> None:
        if max_requests is not None and max_requests < 1:
            raise ValidationError("max_requests must be positive")
        if idle_timeout is not None and idle_timeout <= 0:
            raise ValidationError("idle_timeout must be positive")
        if self._listener is None:
            self.bind()
        assert self._listener is not None
        self._listener.settimeout(idle_timeout or self.timeout)
        accepted = 0
        try:
            while not self._stop.is_set() and (max_requests is None or accepted < max_requests):
                try:
                    stream, _ = self._listener.accept()
                except socket.timeout:
                    if idle_timeout is not None:
                        break
                    continue
                accepted += 1
                try:
                    self._handle(stream)
                    self.handled_requests += 1
                except (ProtocolError, ValidationError, OSError) as exc:
                    self.last_error = str(exc)
        finally:
            self.close()

    def close(self) -> None:
        self._stop.set()
        listener, self._listener = self._listener, None
        if listener is not None:
            try:
                listener.close()
            except OSError:
                pass
        try:
            if self.socket_path.exists() and self.socket_path.is_socket():
                self.socket_path.unlink()
        except OSError:
            pass


class UnixCapabilityBrokerClient:
    """Unprivileged Fabric-side client for the root-owned Unix broker."""

    def __init__(self, socket_path: Path, *, timeout: float = 30.0, max_frame_bytes: int = MAX_REQUEST_BYTES) -> None:
        if timeout <= 0 or not 1 <= max_frame_bytes <= MAX_REQUEST_BYTES:
            raise ValidationError("Unix broker client bounds are invalid")
        self.socket_path = Path(socket_path)
        self.timeout = timeout
        self.max_frame_bytes = max_frame_bytes

    def request(self, request: Mapping[str, Any]) -> dict[str, Any]:
        validate_capability_request(request)
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as stream:
            stream.settimeout(self.timeout)
            stream.connect(str(self.socket_path))
            _send_frame(stream, request)
            size = struct.unpack("!I", _recv_exact(stream, 4))[0]
            if not 1 <= size <= self.max_frame_bytes:
                raise ProtocolError("capability broker response frame size is invalid")
            raw_result = _recv_exact(stream, size)
            try:
                result = json.loads(raw_result.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                raise ProtocolError("capability broker response is not JSON") from exc
            if not isinstance(result, dict) or canonical_json_bytes(result) != raw_result:
                raise ProtocolError("capability broker response is not canonical JSON")
            return validate_capability_result(result)


class WindowsCapabilityBrokerServer:
    """LocalSystem named-pipe endpoint with an explicit Windows DACL.

    The endpoint never opens TCP. Its ACL permits LocalSystem,
    Administrators, and one configured worker SID; the payload remains the
    same canonical, identity-bound capability contract used on Unix.
    """

    def __init__(self, broker: CapabilityBroker, pipe_name: str, *, allowed_sid: str, timeout: float = 30.0, max_frame_bytes: int = MAX_REQUEST_BYTES) -> None:
        if not _PIPE_NAME.fullmatch(pipe_name):
            raise ValidationError("Windows broker pipe name is invalid")
        if not re.fullmatch(r"S-1-[0-9-]{3,80}", allowed_sid):
            raise ValidationError("Windows broker worker SID is invalid")
        if timeout <= 0 or not 1 <= max_frame_bytes <= MAX_REQUEST_BYTES:
            raise ValidationError("Windows broker bounds are invalid")
        self.broker = broker
        self.pipe_name = pipe_name
        self.allowed_sid = allowed_sid
        self.timeout = timeout
        self.max_frame_bytes = max_frame_bytes
        self.handled_requests = 0
        self.last_error: str | None = None
        self._stop = False

    @staticmethod
    def _api() -> tuple[Any, Any, Any, Any, Any]:
        if os.name != "nt":
            raise ProtocolError("Windows capability broker is only available on Windows")
        import ctypes
        from ctypes import wintypes

        class SecurityAttributes(ctypes.Structure):
            _fields_ = [("nLength", wintypes.DWORD), ("lpSecurityDescriptor", wintypes.LPVOID), ("bInheritHandle", wintypes.BOOL)]

        return ctypes, wintypes, ctypes.WinDLL("kernel32", use_last_error=True), ctypes.WinDLL("advapi32", use_last_error=True), SecurityAttributes

    def _new_pipe(self) -> tuple[tuple[Any, Any, Any], Any]:
        ctypes, wintypes, kernel32, advapi32, attributes_type = self._api()
        descriptor = wintypes.LPVOID()
        sddl = f"D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GRGW;;;{self.allowed_sid})"
        if not advapi32.ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl, 1, ctypes.byref(descriptor), None):
            raise OSError(ctypes.get_last_error(), "unable to create broker pipe security descriptor")
        attributes = attributes_type(ctypes.sizeof(attributes_type), descriptor, False)
        kernel32.CreateNamedPipeW.restype = wintypes.HANDLE
        handle = kernel32.CreateNamedPipeW(self.pipe_name, 0x00000003, 0x00000000, 1, self.max_frame_bytes, self.max_frame_bytes, int(self.timeout * 1000), ctypes.byref(attributes))
        advapi32.LocalFree(descriptor)
        if handle == wintypes.HANDLE(-1).value:
            raise OSError(ctypes.get_last_error(), "unable to create broker named pipe")
        return (ctypes, wintypes, kernel32), handle

    @staticmethod
    def _read_exact(ctypes: Any, wintypes: Any, kernel32: Any, handle: Any, size: int) -> bytes:
        output = bytearray()
        while len(output) < size:
            buffer = ctypes.create_string_buffer(size - len(output))
            count = wintypes.DWORD()
            if not kernel32.ReadFile(handle, buffer, len(buffer), ctypes.byref(count), None):
                raise OSError(ctypes.get_last_error(), "broker named pipe read failed")
            if count.value == 0:
                raise ProtocolError("capability broker pipe ended mid-frame")
            output.extend(buffer.raw[:count.value])
        return bytes(output)

    @staticmethod
    def _write_all(ctypes: Any, wintypes: Any, kernel32: Any, handle: Any, value: bytes) -> None:
        offset = 0
        while offset < len(value):
            count = wintypes.DWORD()
            if not kernel32.WriteFile(handle, value[offset:], len(value) - offset, ctypes.byref(count), None):
                raise OSError(ctypes.get_last_error(), "broker named pipe write failed")
            if count.value == 0:
                raise ProtocolError("capability broker pipe write made no progress")
            offset += count.value

    def _handle(self, handle: Any, ctypes: Any, wintypes: Any, kernel32: Any) -> None:
        header = self._read_exact(ctypes, wintypes, kernel32, handle, 4)
        size = struct.unpack("!I", header)[0]
        if not 1 <= size <= self.max_frame_bytes:
            raise ProtocolError("capability broker frame size is invalid")
        raw = self._read_exact(ctypes, wintypes, kernel32, handle, size)
        try:
            request = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ProtocolError("capability broker frame is not canonical JSON") from exc
        if not isinstance(request, dict) or canonical_json_bytes(request) != raw:
            raise ProtocolError("capability broker frame is not canonical JSON")
        self._write_all(ctypes, wintypes, kernel32, handle, _frame_bytes(self.broker.request(request), max_frame_bytes=self.max_frame_bytes))

    def serve_forever(self, *, max_requests: int | None = None) -> None:
        if max_requests is not None and max_requests < 1:
            raise ValidationError("max_requests must be positive")
        accepted = 0
        try:
            while not self._stop and (max_requests is None or accepted < max_requests):
                api, handle = self._new_pipe()
                ctypes, wintypes, kernel32 = api
                try:
                    connected = kernel32.ConnectNamedPipe(handle, None)
                    if not connected and ctypes.get_last_error() != 535:  # ERROR_PIPE_CONNECTED
                        raise OSError(ctypes.get_last_error(), "broker named pipe connection failed")
                    accepted += 1
                    try:
                        self._handle(handle, ctypes, wintypes, kernel32)
                        self.handled_requests += 1
                    except (ProtocolError, ValidationError, OSError) as exc:
                        self.last_error = str(exc)
                    kernel32.FlushFileBuffers(handle)
                    kernel32.DisconnectNamedPipe(handle)
                finally:
                    kernel32.CloseHandle(handle)
        finally:
            self._stop = True

    def close(self) -> None:
        self._stop = True


class WindowsCapabilityBrokerClient:
    """Named-pipe client; the Windows ACL authenticates the OS principal."""

    def __init__(self, pipe_name: str, *, timeout: float = 30.0, max_frame_bytes: int = MAX_REQUEST_BYTES) -> None:
        if not _PIPE_NAME.fullmatch(pipe_name):
            raise ValidationError("Windows broker pipe name is invalid")
        if timeout <= 0 or not 1 <= max_frame_bytes <= MAX_REQUEST_BYTES:
            raise ValidationError("Windows broker client bounds are invalid")
        self.pipe_name = pipe_name
        self.timeout = timeout
        self.max_frame_bytes = max_frame_bytes

    def request(self, request: Mapping[str, Any]) -> dict[str, Any]:
        validate_capability_request(request)
        if os.name != "nt":
            raise ProtocolError("Windows capability broker is only available on Windows")
        ctypes, wintypes, kernel32, _advapi32, _attributes_type = WindowsCapabilityBrokerServer._api()
        kernel32.CreateFileW.restype = wintypes.HANDLE
        handle = kernel32.CreateFileW(self.pipe_name, 0xC0000000, 0, None, 3, 0, None)
        if handle == wintypes.HANDLE(-1).value:
            raise OSError(ctypes.get_last_error(), "unable to connect to broker named pipe")
        try:
            WindowsCapabilityBrokerServer._write_all(ctypes, wintypes, kernel32, handle, _frame_bytes(request, max_frame_bytes=self.max_frame_bytes))
            header = WindowsCapabilityBrokerServer._read_exact(ctypes, wintypes, kernel32, handle, 4)
            size = struct.unpack("!I", header)[0]
            if not 1 <= size <= self.max_frame_bytes:
                raise ProtocolError("capability broker response frame size is invalid")
            raw = WindowsCapabilityBrokerServer._read_exact(ctypes, wintypes, kernel32, handle, size)
            try:
                result = json.loads(raw.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                raise ProtocolError("capability broker response is not canonical JSON") from exc
            if not isinstance(result, dict) or canonical_json_bytes(result) != raw:
                raise ProtocolError("capability broker response is not canonical JSON")
            return validate_capability_result(result)
        finally:
            kernel32.CloseHandle(handle)


def run_broker_server(*, profile_path: Path, socket_path: Path | None = None, allowed_uid: int | None = None, state_path: Path, pipe_name: str | None = None, allowed_sid: str | None = None) -> None:
    raw = json.loads(Path(profile_path).read_text(encoding="utf-8"))
    if isinstance(raw, dict) and "profiles" in raw:
        raise ValidationError("broker service profile must be a single explicit profile object")
    if not isinstance(raw, dict) or not raw.get("worker_identity"):
        raise ValidationError("broker service profile must name one worker identity")
    profile = HostPrivilegeProfile(load_host_privilege_profile(profile_path, worker_identity=str(raw["worker_identity"])))
    broker = CapabilityBroker(profile, state_path=state_path)
    if profile.platform == "windows":
        if pipe_name is None or allowed_sid is None:
            raise ValidationError("Windows broker service requires --pipe-name and --allowed-sid")
        WindowsCapabilityBrokerServer(broker, pipe_name, allowed_sid=allowed_sid).serve_forever()
    else:
        if socket_path is None or allowed_uid is None:
            raise ValidationError("Unix broker service requires --socket and --allowed-uid")
        UnixCapabilityBrokerServer(broker, socket_path, allowed_uids=(allowed_uid,)).serve_forever()


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Run a bounded Fabric capability broker endpoint")
    parser.add_argument("--profile", type=Path, required=True)
    parser.add_argument("--socket", type=Path)
    parser.add_argument("--allowed-uid", type=int)
    parser.add_argument("--pipe-name")
    parser.add_argument("--allowed-sid")
    parser.add_argument("--state", type=Path, required=True)
    args = parser.parse_args()
    run_broker_server(profile_path=args.profile, socket_path=args.socket, allowed_uid=args.allowed_uid, state_path=args.state, pipe_name=args.pipe_name, allowed_sid=args.allowed_sid)


__all__ = [
    "CAPABILITY_AUDIT_SCHEMA", "CAPABILITY_BROKER_PROTOCOL", "CAPABILITY_FAMILIES", "CAPABILITY_LEASE_SCHEMA", "CAPABILITY_OPERATIONS", "CAPABILITY_RECONCILE_SCHEMA", "CAPABILITY_REQUEST_SCHEMA", "CAPABILITY_RESULT_SCHEMA", "DEFAULT_SYSCTL_ALLOWLIST", "EXPERIMENT_REQUIREMENTS_SCHEMA", "HostPrivilegeProfile", "CapabilityAdapter", "CapabilityAuditStore", "CapabilityBroker", "CapabilityLeaseStore", "CapabilityResultStore", "LinuxCapabilityBroker", "UnrestrictedCapabilityBroker", "UnixCapabilityBrokerClient", "UnixCapabilityBrokerServer", "WindowsCapabilityBroker", "WindowsCapabilityBrokerClient", "build_capability_lease", "build_capability_request", "build_capability_reconcile_result", "build_capability_result", "build_experiment_requirements", "build_host_privilege_profile", "check_noninteractive_root", "host_privilege_profile", "load_host_privilege_profile", "validate_capability_arguments", "validate_capability_audit", "validate_capability_lease", "validate_capability_reconcile_result", "validate_capability_request", "validate_capability_result", "validate_experiment_requirements", "validate_host_privilege_profile",
]
