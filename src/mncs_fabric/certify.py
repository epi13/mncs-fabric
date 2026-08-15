"""Capability-aware MNCS worker certification.

Certification tests the layers that the worker actually claims.  A build-only
node is not failed for missing models.  An installer exit code of 0 is never
treated as certification.
"""

from __future__ import annotations

from typing import Any, Mapping

from .canonical import attach_identity, verify_identity
from .errors import ValidationError
from .inventory import inventory_runtime, inventory_service, inventory_tool, validate_worker_inventory, HTTP_PROBE_TIMEOUT
from .node import utc_now
from .providers import apply_action, plan_action_from_change

CERTIFICATION_SCHEMA = "mncs-fabric.certification-result.v0.1"
LAYER_ORDER = (
    "connectivity",
    "execution",
    "repository_access",
    "github",
    "forge",
    "joern",
    "ollama",
    "model_discovery",
    "inference",
    "harness",
)


def _text(value: object, field: str, maximum: int = 256) -> str:
    if not isinstance(value, str) or not value or len(value) > maximum or "\x00" in value:
        raise ValidationError(f"{field} must be bounded non-empty text")
    return value


def _layer(name: str, status: str, detail: str, *, applicable: bool = True) -> dict[str, Any]:
    if status not in {"PASS", "FAIL", "SKIP", "UNKNOWN"}:
        raise ValidationError("certification layer status is invalid")
    return {
        "name": name,
        "applicable": applicable,
        "status": "SKIP" if not applicable else status,
        "detail": detail[:256],
    }


def _requires(inventory: Mapping[str, Any], kind: str, name: str) -> bool:
    if kind == "tool":
        tool = inventory_tool(inventory, name)
        return bool(tool and tool.get("present"))
    if kind == "runtime":
        runtime = inventory_runtime(inventory, name)
        return bool(runtime and runtime.get("present"))
    if kind == "service":
        service = inventory_service(inventory, name)
        return bool(service and service.get("present"))
    if kind == "package":
        if name == "local-harness":
            return bool(inventory.get("fabric", {}).get("harness_version"))
        if name == "fabric-worker":
            return True
    return False


def probe_inference(inventory: Mapping[str, Any]) -> dict[str, Any] | None:
    """Run a model-agnostic generate against the first discovered local model."""

    runtime = inventory_runtime(inventory, "ollama")
    if not runtime or not runtime.get("reachable") or not runtime.get("endpoint"):
        return None
    models = runtime.get("models") or []
    names = [item.get("name") for item in models if isinstance(item, Mapping) and item.get("name")]
    if not names:
        return {"status": "UNKNOWN", "detail": "runtime reachable but no models are installed"}
    import json
    import urllib.error
    import urllib.request

    payload = json.dumps({"model": names[0], "prompt": "ping", "stream": False}).encode("utf-8")
    request = urllib.request.Request(
        str(runtime["endpoint"]).rstrip("/") + "/api/generate",
        data=payload,
        method="POST",
        headers={"Content-Type": "application/json", "User-Agent": "mncs-fabric-certify"},
    )
    try:
        with urllib.request.urlopen(request, timeout=max(HTTP_PROBE_TIMEOUT, 20.0)) as response:
            raw = response.read(64 * 1024)
    except (urllib.error.URLError, TimeoutError, OSError, ValueError) as exc:
        return {"status": "FAIL", "detail": f"inference probe of {names[0]} failed: {exc}"[:256]}
    try:
        body = json.loads(raw.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError):
        return {"status": "FAIL", "detail": f"inference probe of {names[0]} returned non-JSON"}
    if isinstance(body, dict) and (body.get("response") is not None or body.get("done") is True):
        return {"status": "PASS", "detail": f"generic generate succeeded on {names[0]}"}
    error = body.get("error") if isinstance(body, dict) else None
    return {"status": "FAIL", "detail": f"inference probe of {names[0]} failed: {error or 'empty response'}"}


def certify_inventory(
    inventory: Mapping[str, Any],
    *,
    profiles: list[str] | None = None,
    inference_probe: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    checked = validate_worker_inventory(inventory)
    profiles = list(profiles or [])
    inference_required = "mncs-inference-worker" in profiles or "mncs-mnel-worker" in profiles
    if inference_probe is None and inference_required:
        inference_probe = probe_inference(checked)
    layers = [
        _layer("connectivity", "PASS", "inventory collected from the worker process"),
        _certify_execution(checked),
        _certify_repository(checked),
        _optional_tool(checked, "github", "gh", verify=True),
        _optional_tool(checked, "forge", "forge", verify=True),
        _optional_tool(checked, "joern", "joern", verify=True),
        _certify_ollama(checked, required=inference_required),
        _certify_models(checked, required=inference_required),
        _certify_inference(checked, required=inference_required, probe=inference_probe),
        _certify_harness(checked),
    ]
    applicable = [layer for layer in layers if layer["applicable"]]
    failed = [layer for layer in applicable if layer["status"] == "FAIL"]
    unknown = [layer for layer in applicable if layer["status"] == "UNKNOWN"]
    if failed:
        disposition = "FAILED"
        failing_layer = failed[0]["name"]
    elif unknown:
        disposition = "UNKNOWN"
        failing_layer = unknown[0]["name"]
    else:
        disposition = "CERTIFIED"
        failing_layer = None
    value = {
        "schema_version": CERTIFICATION_SCHEMA,
        "worker_identity": checked["worker_identity"],
        "inventory_identity": checked["inventory_identity"],
        "profiles": profiles,
        "layers": layers,
        "disposition": disposition,
        "failing_layer": failing_layer,
        "created_at": utc_now(),
        "claim_boundary": "capability-aware worker certification; not independence, honesty, or MNCS conformance",
    }
    return attach_identity(value, "certification_identity")


def _certify_execution(inventory: Mapping[str, Any]) -> dict[str, Any]:
    result = apply_action(
        plan_action_from_change({"kind": "tool", "name": "python", "update_class": "B", "desired": "present", "actual": "present", "authorization": "none", "detail": "python execution"}),
        inventory,
    )
    status = "PASS" if result["disposition"] == "PASS" else "FAIL"
    return _layer("execution", status, result["detail"])


def _certify_repository(inventory: Mapping[str, Any]) -> dict[str, Any]:
    tool = inventory_tool(inventory, "git")
    if not tool or not tool.get("present"):
        return _layer("repository_access", "SKIP", "git is not on PATH for this worker", applicable=False)
    result = apply_action(
        plan_action_from_change({"kind": "tool", "name": "git", "update_class": "B", "desired": "present", "actual": "present", "authorization": "none", "detail": "git"}),
        inventory,
    )
    return _layer("repository_access", "PASS" if result["disposition"] == "PASS" else "FAIL", result["detail"])


def _optional_tool(inventory: Mapping[str, Any], layer: str, name: str, *, verify: bool) -> dict[str, Any]:
    if not _requires(inventory, "tool", name):
        return _layer(layer, "SKIP", f"{name} not present on this worker", applicable=False)
    result = apply_action(
        plan_action_from_change({"kind": "tool", "name": name, "update_class": "B", "desired": "mncs-supported", "actual": "present", "authorization": "none", "detail": name}),
        inventory,
    )
    if result["disposition"] == "PASS":
        return _layer(layer, "PASS", result["detail"])
    if result.get("failure_class") == "AUTH_FAILURE":
        return _layer(
            layer,
            "SKIP",
            result["detail"] + "; GitHub login is a one-time user credential bootstrap",
            applicable=False,
        )
    return _layer(layer, "FAIL", result["detail"])


def _certify_ollama(inventory: Mapping[str, Any], *, required: bool) -> dict[str, Any]:
    runtime = inventory_runtime(inventory, "ollama")
    if not runtime or not runtime.get("present"):
        return _layer("ollama", "FAIL" if required else "SKIP", "ollama runtime not present", applicable=required)
    if runtime.get("reachable"):
        return _layer("ollama", "PASS", f"endpoint {runtime.get('endpoint')} manager={runtime.get('service_type')}")
    return _layer("ollama", "FAIL", f"ollama present via {runtime.get('service_type')} but endpoint is not reachable")


def _certify_models(inventory: Mapping[str, Any], *, required: bool) -> dict[str, Any]:
    runtime = inventory_runtime(inventory, "ollama")
    if not runtime or not runtime.get("present"):
        return _layer("model_discovery", "FAIL" if required else "SKIP", "no runtime from which to discover models", applicable=required)
    if not runtime.get("reachable"):
        return _layer("model_discovery", "FAIL", "runtime endpoint is not reachable")
    models = runtime.get("models") or []
    names = [item.get("name") for item in models if isinstance(item, Mapping)]
    return _layer("model_discovery", "PASS", f"{len(names)} models: " + ", ".join(str(name) for name in names[:8]))


def _certify_inference(inventory: Mapping[str, Any], *, required: bool, probe: Mapping[str, Any] | None) -> dict[str, Any]:
    runtime = inventory_runtime(inventory, "ollama")
    if not runtime or not runtime.get("present"):
        return _layer("inference", "FAIL" if required else "SKIP", "inference runtime not present", applicable=required)
    if probe is None:
        if required:
            return _layer("inference", "UNKNOWN", "no inference probe was supplied; inventory reachability is not inference")
        return _layer("inference", "SKIP", "inference probe not requested", applicable=False)
    status = probe.get("status")
    detail = str(probe.get("detail") or "inference probe")
    if not required and status == "UNKNOWN":
        return _layer("inference", "SKIP", detail, applicable=False)
    if status in {"PASS", "FAIL", "UNKNOWN"}:
        return _layer("inference", status, detail)
    return _layer("inference", "UNKNOWN", "inference probe status was not PASS/FAIL/UNKNOWN")


def _certify_harness(inventory: Mapping[str, Any]) -> dict[str, Any]:
    version = inventory.get("fabric", {}).get("harness_version")
    if version:
        return _layer("harness", "PASS", f"harness {version}")
    return _layer("harness", "SKIP", "local harness package is not importable on this worker", applicable=False)


def validate_certification(value: object, *, expected_worker_id: str | None = None) -> dict[str, Any]:
    if not isinstance(value, dict) or value.get("schema_version") != CERTIFICATION_SCHEMA:
        raise ValidationError("unsupported certification schema")
    required = {
        "schema_version", "worker_identity", "inventory_identity", "profiles",
        "layers", "disposition", "failing_layer", "created_at", "claim_boundary",
        "certification_identity",
    }
    if set(value) != required or not verify_identity(value, "certification_identity"):
        raise ValidationError("certification fields or identity are invalid")
    worker_id = _text(value["worker_identity"], "worker_identity")
    if expected_worker_id is not None and worker_id != expected_worker_id:
        raise ValidationError("certification is bound to another worker")
    if value["disposition"] not in {"CERTIFIED", "FAILED", "UNKNOWN"}:
        raise ValidationError("certification disposition is invalid")
    if not isinstance(value["layers"], list):
        raise ValidationError("certification layers are invalid")
    return dict(value)


def format_certification(result: Mapping[str, Any]) -> str:
    checked = validate_certification(result)
    width = max(len(layer["name"]) for layer in checked["layers"])
    lines = [checked["worker_identity"], "", "Fabric Node Certification", ""]
    labels = {
        "connectivity": "Connectivity",
        "execution": "Execution",
        "repository_access": "Repository access",
        "github": "GitHub capability",
        "forge": "Forge",
        "joern": "Joern",
        "ollama": "Ollama",
        "model_discovery": "Model discovery",
        "inference": "Inference",
        "harness": "Harness integration",
    }
    for layer in checked["layers"]:
        label = labels.get(layer["name"], layer["name"])
        status = layer["status"]
        lines.append(f"{label:<{max(width + 6, 20)}} {status}")
    lines.extend(["", checked["disposition"]])
    if checked["failing_layer"]:
        lines.append(f"failing layer: {checked['failing_layer']}")
    return "\n".join(lines)
