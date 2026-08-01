from __future__ import annotations

import re
from pathlib import PurePosixPath
from typing import Any

from .canonical import is_sha256_identity, sha256_identity
from .errors import ValidationError

JOB_SCHEMA = "mncs-fabric.job-plan.v0.1"
MANIFEST_SCHEMA = "mncs-fabric.artifact-manifest.v0.1"
NODE_SCHEMA = "mncs-fabric.node-capabilities.v0.1"
EXECUTION_SCHEMA = "mncs-fabric.execution-record.v0.1"
COHORT_SCHEMA = "mncs-fabric.cohort-result.v0.1"

_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,199}$")
_ENV_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,127}$")
_WINDOWS_ABS_RE = re.compile(r"^[A-Za-z]:[\\/]")


def _safe_relative_path(value: object, field: str, *, allow_dot: bool = False) -> str:
    if not isinstance(value, str) or not value:
        raise ValidationError(f"{field} must be a non-empty string")
    normalized = value.replace("\\", "/")
    if normalized == "." and allow_dot:
        return normalized
    path = PurePosixPath(normalized)
    if path.is_absolute() or ".." in path.parts or normalized.startswith("/"):
        raise ValidationError(f"{field} must stay within the declared bundle root")
    if any(part in ("", ".") for part in path.parts):
        raise ValidationError(f"{field} must be normalized")
    return path.as_posix()


def validate_job_plan(plan: Any) -> dict[str, Any]:
    if not isinstance(plan, dict):
        raise ValidationError("job plan must be a JSON object")
    required = {
        "schema_version", "job_id", "candidate_identity",
        "artifact_manifest_identity", "argv", "working_directory",
        "timeout_seconds", "output_limit_bytes", "environment",
        "required_capabilities", "result_paths", "network_policy",
    }
    missing = sorted(required - set(plan))
    if missing:
        raise ValidationError(f"job plan missing required fields: {', '.join(missing)}")
    if plan["schema_version"] != JOB_SCHEMA:
        raise ValidationError(f"schema_version must be {JOB_SCHEMA}")
    if not isinstance(plan["job_id"], str) or not _ID_RE.fullmatch(plan["job_id"]):
        raise ValidationError("job_id contains unsupported characters or is too long")
    for field in ("candidate_identity", "artifact_manifest_identity"):
        if not is_sha256_identity(plan[field]):
            raise ValidationError(f"{field} must be a lowercase sha256 identity")
    evaluator = plan.get("evaluator_identity")
    if evaluator is not None and not is_sha256_identity(evaluator):
        raise ValidationError("evaluator_identity must be null or a lowercase sha256 identity")
    argv = plan["argv"]
    if not isinstance(argv, list) or not argv or not all(isinstance(x, str) and x for x in argv):
        raise ValidationError("argv must be a non-empty array of non-empty strings")
    executable = argv[0]
    if executable != "@python" and not executable.startswith("/") and not _WINDOWS_ABS_RE.match(executable):
        raise ValidationError("argv[0] must be @python or an absolute executable path")
    _safe_relative_path(plan["working_directory"], "working_directory", allow_dot=True)
    timeout = plan["timeout_seconds"]
    if not isinstance(timeout, (int, float)) or isinstance(timeout, bool) or not (0.05 <= timeout <= 86400):
        raise ValidationError("timeout_seconds must be between 0.05 and 86400")
    limit = plan["output_limit_bytes"]
    if not isinstance(limit, int) or isinstance(limit, bool) or not (1 <= limit <= 64 * 1024 * 1024):
        raise ValidationError("output_limit_bytes must be an integer between 1 and 67108864")
    env = plan["environment"]
    if not isinstance(env, dict) or len(env) > 64:
        raise ValidationError("environment must be an object with at most 64 entries")
    for key, value in env.items():
        if not isinstance(key, str) or not _ENV_RE.fullmatch(key):
            raise ValidationError(f"invalid environment key: {key!r}")
        if not isinstance(value, str) or len(value) > 8192:
            raise ValidationError(f"environment value for {key} must be a bounded string")
    capabilities = plan["required_capabilities"]
    if not isinstance(capabilities, list) or not all(isinstance(x, str) and x for x in capabilities):
        raise ValidationError("required_capabilities must be an array of strings")
    if len(set(capabilities)) != len(capabilities):
        raise ValidationError("required_capabilities must not contain duplicates")
    result_paths = plan["result_paths"]
    if not isinstance(result_paths, list):
        raise ValidationError("result_paths must be an array")
    normalized_results = [_safe_relative_path(value, "result_paths[]") for value in result_paths]
    if len(set(normalized_results)) != len(normalized_results):
        raise ValidationError("result_paths must not contain duplicates")
    if plan["network_policy"] not in {"UNSPECIFIED", "DECLARED_OFFLINE", "UNRESTRICTED"}:
        raise ValidationError("network_policy has an unsupported value")
    normalized = dict(plan)
    normalized["working_directory"] = _safe_relative_path(plan["working_directory"], "working_directory", allow_dot=True)
    normalized["result_paths"] = normalized_results
    normalized["job_identity"] = sha256_identity({k: v for k, v in normalized.items() if k != "job_identity"})
    return normalized


def safe_relative_path(value: object, field: str = "path") -> str:
    return _safe_relative_path(value, field)
