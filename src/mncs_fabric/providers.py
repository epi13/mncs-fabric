"""Typed maintenance providers.  Providers never accept a shell string.

Each provider inspects current inventory, decides whether a change is required,
and either applies a fixed argv / local API action or classifies the work as
requiring privilege or a human.  Unknown Ollama install types are rediscovered
instead of assuming systemd.
"""

from __future__ import annotations

from typing import Any, Callable, Mapping

import shutil
import sys

from .errors import ValidationError
from .inventory import (
    collect_ollama_models,
    discover_service,
    first_line,
    inventory_runtime,
    inventory_service,
    inventory_tool,
    redact_text,
    run_argv,
)

FAILURE_CLASSES = frozenset({
    "NETWORK_FAILURE",
    "AUTH_FAILURE",
    "PACKAGE_FAILURE",
    "VERSION_CONFLICT",
    "SERVICE_FAILURE",
    "VALIDATION_FAILURE",
    "MODEL_FAILURE",
    "DISK_FAILURE",
    "ACTIVE_WORKLOAD",
    "ROLLBACK_FAILURE",
    "UNSUPPORTED_PLATFORM",
    "CONFIGURATION_DRIFT",
    "PRIVILEGE_REQUIRED",
    "HUMAN_REQUIRED",
    "UNSUPPORTED_ACTION",
})
ROLLBACK_CAPABILITIES = frozenset({"full", "partial", "unsupported", "manual"})
AUTHORIZATIONS = frozenset({"none", "operator", "privilege", "human"})
ACTIONS = frozenset({"inspect", "install", "update", "remove", "configure", "restart", "verify", "pull", "rediscover"})


def _text(value: object, field: str, maximum: int = 256) -> str:
    if not isinstance(value, str) or not value or len(value) > maximum or "\x00" in value:
        raise ValidationError(f"{field} must be bounded non-empty text")
    return value


def validate_action(value: object) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ValidationError("maintenance action must be an object")
    required = {
        "action", "target", "update_class", "provider", "disruptive", "rollback",
        "authorization", "current", "desired", "reason",
    }
    if set(value) != required:
        raise ValidationError("maintenance action fields are invalid")
    action = {
        "action": _text(value["action"], "action", 32),
        "target": _text(value["target"], "target", 128),
        "update_class": _text(value["update_class"], "update_class", 1),
        "provider": _text(value["provider"], "provider", 64),
        "disruptive": value["disruptive"] is True,
        "rollback": _text(value["rollback"], "rollback", 32),
        "authorization": _text(value["authorization"], "authorization", 32),
        "current": _text(value["current"], "current", 256),
        "desired": _text(value["desired"], "desired", 256),
        "reason": _text(value["reason"], "reason", 512),
    }
    if action["action"] not in ACTIONS:
        raise ValidationError("maintenance action type is unsupported")
    if action["rollback"] not in ROLLBACK_CAPABILITIES:
        raise ValidationError("maintenance rollback capability is unsupported")
    if action["authorization"] not in AUTHORIZATIONS:
        raise ValidationError("maintenance authorization class is unsupported")
    if action["update_class"] not in {"A", "B", "C", "D", "E"}:
        raise ValidationError("maintenance update class is unsupported")
    return action


def action_result(
    *,
    action: Mapping[str, Any],
    disposition: str,
    failure_class: str | None = None,
    detail: str,
    changed: bool,
    restart_required: bool = False,
    rollback: Mapping[str, Any] | None = None,
    stdout: str = "",
    stderr: str = "",
) -> dict[str, Any]:
    if disposition not in {"PASS", "FAIL", "UNKNOWN", "SKIPPED"}:
        raise ValidationError("action result disposition is invalid")
    if failure_class is not None and failure_class not in FAILURE_CLASSES:
        raise ValidationError("action failure class is unsupported")
    return {
        "action": validate_action(action)["action"],
        "target": action["target"],
        "provider": action["provider"],
        "disposition": disposition,
        "failure_class": failure_class,
        "detail": redact_text(detail)[:512],
        "changed": bool(changed),
        "restart_required": bool(restart_required),
        "rollback": dict(rollback) if rollback else {"capability": action.get("rollback", "unsupported")},
        "stdout": redact_text(stdout)[:2048],
        "stderr": redact_text(stderr)[:2048],
    }


def _skipped(action: Mapping[str, Any], reason: str, failure_class: str) -> dict[str, Any]:
    return action_result(
        action=action,
        disposition="SKIPPED",
        failure_class=failure_class,
        detail=reason,
        changed=False,
    )


def apply_inspect_tool(action: Mapping[str, Any], inventory: Mapping[str, Any]) -> dict[str, Any]:
    tool = inventory_tool(inventory, action["target"])
    if tool and tool.get("present"):
        return action_result(action=action, disposition="PASS", detail=tool.get("version") or tool.get("path") or "present", changed=False)
    return action_result(action=action, disposition="FAIL", failure_class="VALIDATION_FAILURE", detail="tool not present", changed=False)


def apply_verify_gh(action: Mapping[str, Any], inventory: Mapping[str, Any]) -> dict[str, Any]:
    tool = inventory_tool(inventory, "gh")
    if not tool or not tool.get("present") or not tool.get("path"):
        return action_result(action=action, disposition="FAIL", failure_class="VALIDATION_FAILURE", detail="gh is not present", changed=False)
    probed = run_argv([str(tool["path"]), "auth", "status"], timeout=5.0)
    output = redact_text((probed["stdout"] or "") + "\n" + (probed["stderr"] or ""))
    if probed["returncode"] == 0 and "Logged in" in output:
        return action_result(action=action, disposition="PASS", detail="gh authenticated", changed=False, stdout=output)
    return action_result(
        action=action,
        disposition="FAIL",
        failure_class="AUTH_FAILURE",
        detail="gh executable present but GitHub authentication is unavailable",
        changed=False,
        stdout=output,
        stderr=probed["stderr"],
    )


def apply_verify_joern(action: Mapping[str, Any], inventory: Mapping[str, Any]) -> dict[str, Any]:
    tool = inventory_tool(inventory, "joern")
    if not tool or not tool.get("present") or not tool.get("path"):
        return action_result(action=action, disposition="FAIL", failure_class="VALIDATION_FAILURE", detail="joern is not present", changed=False)
    probed = run_argv([str(tool["path"]), "--help"], timeout=8.0)
    if probed["returncode"] in {0, 1, 2} and not probed["timed_out"]:
        return action_result(action=action, disposition="PASS", detail="joern executable responded", changed=False, stdout=first_line(probed["stdout"]) or "")
    return action_result(action=action, disposition="FAIL", failure_class="VALIDATION_FAILURE", detail="joern invocation failed", changed=False, stderr=probed["stderr"])


def apply_verify_forge(action: Mapping[str, Any], inventory: Mapping[str, Any]) -> dict[str, Any]:
    path = None
    tool = inventory_tool(inventory, "forge")
    if tool and tool.get("path"):
        path = tool["path"]
    path = path or shutil.which("forge") or shutil.which("mncs-forge")
    if not path:
        return action_result(action=action, disposition="FAIL", failure_class="VALIDATION_FAILURE", detail="forge is not present", changed=False)
    probed = run_argv([path, "--help"], timeout=6.0)
    if probed["timed_out"]:
        return action_result(action=action, disposition="FAIL", failure_class="VALIDATION_FAILURE", detail="forge probe timed out", changed=False)
    return action_result(action=action, disposition="PASS", detail="forge executable responded", changed=False, stdout=first_line(probed["stdout"]) or "")


def apply_rediscover_ollama(action: Mapping[str, Any], inventory: Mapping[str, Any]) -> dict[str, Any]:
    service = discover_service("ollama", units=("ollama.service", "ollama"), listen_port=11434)
    models, endpoint = collect_ollama_models()
    detail = (
        f"manager={service['manager']} state={service['state']} "
        f"endpoint={endpoint or 'unreachable'} models={len(models)}"
    )
    previous = inventory_runtime(inventory, "ollama") or {}
    changed = previous.get("service_type") != service["manager"] or previous.get("reachable") != bool(endpoint)
    if action["desired"] == "running" and service["state"] != "running" and not endpoint:
        return action_result(
            action=action,
            disposition="FAIL",
            failure_class="SERVICE_FAILURE",
            detail=detail,
            changed=changed,
        )
    return action_result(action=action, disposition="PASS", detail=detail, changed=changed)


def apply_restart_service(action: Mapping[str, Any], inventory: Mapping[str, Any]) -> dict[str, Any]:
    service = inventory_service(inventory, action["target"]) or discover_service(action["target"])
    manager = service.get("manager")
    unit = service.get("unit")
    if manager in {"absent", None}:
        return action_result(action=action, disposition="FAIL", failure_class="SERVICE_FAILURE", detail="service was not discovered", changed=False)
    if manager == "unknown":
        return _skipped(action, "service manager is unknown; rediscover rather than guessing systemd", "CONFIGURATION_DRIFT")
    if manager == "process":
        return _skipped(action, "process-managed services cannot be restarted without a supervisor", "UNSUPPORTED_ACTION")
    if manager == "systemd-system":
        return _skipped(action, "system systemd restart requires host privilege and is not performed automatically", "PRIVILEGE_REQUIRED")
    if manager == "windows-service":
        return _skipped(action, "Windows service restart requires operator privilege", "PRIVILEGE_REQUIRED")
    if manager == "systemd-user" and action["target"] != "fabric-worker" and unit:
        probed = run_argv(["systemctl", "--user", "restart", unit], timeout=20.0)
        if probed["returncode"] == 0:
            return action_result(action=action, disposition="PASS", detail=f"restarted {unit} via systemd-user", changed=True, stdout=probed["stdout"], stderr=probed["stderr"])
        return action_result(action=action, disposition="FAIL", failure_class="SERVICE_FAILURE", detail=f"systemctl --user restart {unit} failed", changed=False, stdout=probed["stdout"], stderr=probed["stderr"])
    if manager in {"systemd-user", "windows-scheduled-task", "supervisor"}:
        # Restarting the worker process itself is deferred until after the
        # maintenance result is acknowledged.  The supervisor performs the
        # actual stop/start so this process does not suicide mid-response.
        return action_result(
            action=action,
            disposition="PASS",
            detail=f"requested {manager} restart of {action['target']}; supervisor restart required",
            changed=True,
            restart_required=True,
        )
    return _skipped(action, f"no restart adapter for manager {manager}", "UNSUPPORTED_ACTION")


def apply_update_fabric(action: Mapping[str, Any], inventory: Mapping[str, Any]) -> dict[str, Any]:
    current = inventory.get("fabric", {}).get("worker_version")
    desired = str(action.get("desired") or "")
    if desired.startswith("supported-current:"):
        desired = desired.split(":", 1)[1]
    staged_same = None
    if current and desired and current == desired:
        from .supervisor import resolve_upgrade_source

        staged_same = resolve_upgrade_source(desired)
        if staged_same is None or action["authorization"] not in {"none", "operator"}:
            return action_result(action=action, disposition="PASS", detail="fabric worker already at the desired version", changed=False)
    if action["authorization"] == "privilege":
        return _skipped(action, "fabric worker package update is classified as privileged", "PRIVILEGE_REQUIRED")
    if action["authorization"] not in {"none", "operator"}:
        return _skipped(action, "fabric worker package update requires an explicit operator apply of a pinned version", "HUMAN_REQUIRED")
    if desired in {"", "present", "supported-current", "mncs-supported"}:
        return _skipped(action, "fabric worker update needs an explicit version pin or staged source", "VERSION_CONFLICT")
    from .supervisor import (
        apply_staged_upgrade,
        inspect_supervisor,
        resolve_upgrade_source,
        write_upgrade_request,
    )

    source = resolve_upgrade_source(desired)
    if source is None:
        return _skipped(
            action,
            f"no staged Fabric source for {desired}; place an sdist/wheel at the worker upgrade stage directory",
            "HUMAN_REQUIRED",
        )
    observed = inspect_supervisor(worker_id=str(inventory.get("worker_identity") or "local-worker"))
    write_upgrade_request(source=str(source), version=desired)
    python = observed.get("python_executable") or inventory.get("fabric", {}).get("python_executable") or sys.executable
    if observed.get("kind") == "systemd-user":
        started = run_argv(["systemctl", "--user", "start", "mncs-fabric-worker-upgrade.service"], timeout=180.0)
        if started["returncode"] == 0:
            return action_result(
                action=action,
                disposition="PASS",
                detail=f"activated staged {source} via systemd-user upgrade unit; worker restart required",
                changed=True,
                restart_required=True,
                rollback={"capability": "partial", "previous_version": current},
                stdout=started["stdout"],
                stderr=started["stderr"],
            )
    activated = apply_staged_upgrade(python=str(python), source=str(source), previous=current)
    if activated.get("disposition") == "PASS":
        return action_result(
            action=action,
            disposition="PASS",
            detail=str(activated.get("detail") or f"activated staged {source}; worker restart required"),
            changed=True,
            restart_required=True,
            rollback={"capability": "partial", "previous_version": current},
            stdout=str(activated.get("stdout") or ""),
            stderr=str(activated.get("stderr") or ""),
        )
    return action_result(
        action=action,
        disposition="FAIL",
        failure_class=str(activated.get("failure_class") or "PACKAGE_FAILURE"),
        detail=str(activated.get("detail") or "pip install of staged Fabric source failed"),
        changed=False,
        stdout=str(activated.get("stdout") or ""),
        stderr=str(activated.get("stderr") or ""),
    )


def apply_pull_model(action: Mapping[str, Any], inventory: Mapping[str, Any]) -> dict[str, Any]:
    runtime = inventory_runtime(inventory, "ollama")
    if not runtime or not runtime.get("present"):
        return action_result(action=action, disposition="FAIL", failure_class="MODEL_FAILURE", detail="ollama runtime is not present", changed=False)
    path = shutil.which("ollama")
    if not path:
        return _skipped(action, "ollama executable is not on PATH", "UNSUPPORTED_ACTION")
    if action["authorization"] != "none":
        return _skipped(action, "model pull requires explicit operator authorization", "HUMAN_REQUIRED")
    probed = run_argv([path, "pull", action["target"]], timeout=300.0)
    if probed["returncode"] == 0:
        return action_result(action=action, disposition="PASS", detail=f"pulled model {action['target']}", changed=True, stdout=first_line(probed["stdout"]) or "")
    return action_result(action=action, disposition="FAIL", failure_class="MODEL_FAILURE", detail=f"ollama pull {action['target']} failed", changed=False, stdout=probed["stdout"], stderr=probed["stderr"])


def apply_verify_python(action: Mapping[str, Any], inventory: Mapping[str, Any]) -> dict[str, Any]:
    executable = inventory.get("fabric", {}).get("python_executable") or sys.executable
    probed = run_argv([str(executable), "-c", "import sys; print(sys.version.split()[0])"], timeout=5.0)
    if probed["returncode"] == 0:
        return action_result(action=action, disposition="PASS", detail=first_line(probed["stdout"]) or "python ok", changed=False)
    return action_result(action=action, disposition="FAIL", failure_class="VALIDATION_FAILURE", detail="worker python failed to execute", changed=False, stderr=probed["stderr"])


def apply_verify_git(action: Mapping[str, Any], inventory: Mapping[str, Any]) -> dict[str, Any]:
    tool = inventory_tool(inventory, "git")
    if not tool or not tool.get("path"):
        return action_result(action=action, disposition="FAIL", failure_class="VALIDATION_FAILURE", detail="git is not present", changed=False)
    probed = run_argv([str(tool["path"]), "--version"])
    if probed["returncode"] == 0:
        return action_result(action=action, disposition="PASS", detail=first_line(probed["stdout"]) or "git ok", changed=False)
    return action_result(action=action, disposition="FAIL", failure_class="VALIDATION_FAILURE", detail="git version probe failed", changed=False, stderr=probed["stderr"])


PROVIDER_HANDLERS: dict[str, Callable[[Mapping[str, Any], Mapping[str, Any]], dict[str, Any]]] = {
    "tool.inspect": apply_inspect_tool,
    "tool.git": apply_verify_git,
    "tool.gh": apply_verify_gh,
    "tool.joern": apply_verify_joern,
    "tool.forge": apply_verify_forge,
    "tool.python": apply_verify_python,
    "runtime.ollama": apply_rediscover_ollama,
    "service.restart": apply_restart_service,
    "package.fabric": apply_update_fabric,
    "model.ollama": apply_pull_model,
}


def provider_for_change(change: Mapping[str, Any]) -> str:
    kind = change.get("kind")
    name = change.get("name")
    if kind == "tool" and name in {"git", "gh", "joern", "forge", "python"}:
        return f"tool.{name}"
    if kind == "tool":
        return "tool.inspect"
    if kind == "runtime" and name == "ollama":
        return "runtime.ollama"
    if kind == "service":
        return "service.restart" if change.get("desired") == "running" else "runtime.ollama"
    if kind == "package" and name == "fabric-worker":
        return "package.fabric"
    if kind == "model":
        return "model.ollama"
    return "tool.inspect"


def plan_action_from_change(change: Mapping[str, Any]) -> dict[str, Any]:
    provider = provider_for_change(change)
    action_name = "verify"
    disruptive = False
    rollback = "unsupported"
    if provider == "service.restart":
        action_name = "restart"
        disruptive = True
        rollback = "unsupported"
    elif provider == "package.fabric":
        action_name = "update"
        disruptive = True
        rollback = "partial"
    elif provider == "model.ollama":
        action_name = "pull"
        rollback = "manual"
    elif provider == "runtime.ollama":
        action_name = "rediscover"
        rollback = "unsupported"
    return validate_action(
        {
            "action": action_name,
            "target": change["name"],
            "update_class": change["update_class"],
            "provider": provider,
            "disruptive": disruptive,
            "rollback": rollback,
            "authorization": change.get("authorization", "none"),
            "current": str(change.get("actual", "unknown")),
            "desired": str(change.get("desired", "present")),
            "reason": str(change.get("detail") or change.get("reason") or "desired-state drift"),
        }
    )


def apply_action(action: Mapping[str, Any], inventory: Mapping[str, Any]) -> dict[str, Any]:
    checked = validate_action(action)
    handler = PROVIDER_HANDLERS.get(checked["provider"])
    if handler is None:
        return _skipped(checked, f"no provider registered for {checked['provider']}", "UNSUPPORTED_ACTION")
    if checked["authorization"] == "privilege" and checked["action"] not in {"inspect", "verify", "rediscover"}:
        return _skipped(checked, "privilege-bearing mutation is not auto-applied", "PRIVILEGE_REQUIRED")
    if checked["authorization"] == "human":
        return _skipped(checked, "human intervention is required", "HUMAN_REQUIRED")
    return handler(checked, inventory)


def rollback_action(result: Mapping[str, Any], inventory: Mapping[str, Any]) -> dict[str, Any]:
    rollback = result.get("rollback") if isinstance(result.get("rollback"), Mapping) else {}
    capability = rollback.get("capability", "unsupported")
    if capability in {"unsupported", "manual"}:
        return {
            "disposition": "SKIPPED",
            "failure_class": "ROLLBACK_FAILURE" if capability == "manual" else "UNSUPPORTED_ACTION",
            "detail": f"rollback capability is {capability}",
        }
    previous = rollback.get("previous_version")
    if result.get("provider") == "package.fabric" and previous:
        pip = shutil.which("pip") or shutil.which("pip3")
        if not pip:
            return {"disposition": "FAIL", "failure_class": "ROLLBACK_FAILURE", "detail": "pip unavailable for fabric rollback"}
        probed = run_argv([pip, "install", f"mncs-fabric=={previous}"], timeout=120.0)
        if probed["returncode"] == 0:
            return {"disposition": "PASS", "failure_class": None, "detail": f"restored mncs-fabric=={previous}", "restart_required": True}
        return {"disposition": "FAIL", "failure_class": "ROLLBACK_FAILURE", "detail": "fabric package rollback failed"}
    return {"disposition": "SKIPPED", "failure_class": "UNSUPPORTED_ACTION", "detail": "no rollback adapter"}
