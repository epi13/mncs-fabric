from __future__ import annotations

import hashlib
import json
import os
import shutil
import signal
import subprocess
import sys
import tempfile
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, BinaryIO

from .artifacts import copy_manifest_files, file_identity, verify_manifest
from .canonical import attach_identity, sha256_identity
from .errors import FabricError, IntegrityError, ValidationError
from .models import EXECUTION_SCHEMA, validate_job_plan
from .node import capability_names, collect_node_capabilities, utc_now

_INHERITED_ENV = ("SYSTEMROOT", "WINDIR", "TEMP", "TMP", "TMPDIR", "HOME", "USERPROFILE", "LANG", "LC_ALL", "PATH")


@dataclass
class _CapturedStream:
    total_bytes: int
    sha256: str
    captured_text: str
    truncated: bool


class _StreamCollector(threading.Thread):
    def __init__(self, stream: BinaryIO, limit: int) -> None:
        super().__init__(daemon=True)
        self.stream = stream
        self.limit = limit
        self.total = 0
        self.digest = hashlib.sha256()
        self.captured = bytearray()
        self.exceeded = threading.Event()
        self.error: BaseException | None = None

    def run(self) -> None:
        try:
            while True:
                chunk = self.stream.read(8192)
                if not chunk:
                    break
                self.total += len(chunk)
                self.digest.update(chunk)
                remaining = self.limit - len(self.captured)
                if remaining > 0:
                    self.captured.extend(chunk[:remaining])
                if self.total > self.limit:
                    self.exceeded.set()
        except BaseException as exc:  # defensive capture from background thread
            self.error = exc
            self.exceeded.set()

    def result(self) -> _CapturedStream:
        return _CapturedStream(
            total_bytes=self.total,
            sha256="sha256:" + self.digest.hexdigest(),
            captured_text=bytes(self.captured).decode("utf-8", errors="replace"),
            truncated=self.total > len(self.captured),
        )


def _minimal_environment(overrides: dict[str, str]) -> dict[str, str]:
    environment = {key: os.environ[key] for key in _INHERITED_ENV if key in os.environ}
    environment.update(overrides)
    return environment


def _terminate_process(proc: subprocess.Popen[bytes]) -> None:
    if proc.poll() is not None:
        return
    try:
        if os.name == "posix":
            os.killpg(proc.pid, signal.SIGTERM)
        else:
            proc.terminate()
        proc.wait(timeout=1.0)
    except (ProcessLookupError, subprocess.TimeoutExpired):
        try:
            if os.name == "posix":
                os.killpg(proc.pid, signal.SIGKILL)
            else:
                proc.kill()
        except ProcessLookupError:
            pass


def _resolve_argv(argv: list[str]) -> list[str]:
    resolved = list(argv)
    if resolved[0] == "@python":
        resolved[0] = str(Path(sys.executable).resolve())
    return resolved


def _stream_record(value: _CapturedStream) -> dict[str, Any]:
    return {
        "bytes": value.total_bytes,
        "sha256": value.sha256,
        "captured_utf8": value.captured_text,
        "truncated": value.truncated,
    }


def _failure_record(
    *, plan: dict[str, Any], manifest_identity: str | None, node: dict[str, Any],
    started_at: str, started_monotonic: float, reason: str, detail: str,
) -> dict[str, Any]:
    record = {
        "schema_version": EXECUTION_SCHEMA,
        "job_id": plan.get("job_id"),
        "job_identity": plan.get("job_identity"),
        "candidate_identity": plan.get("candidate_identity"),
        "evaluator_identity": plan.get("evaluator_identity"),
        "artifact_manifest_identity": manifest_identity,
        "node": node,
        "started_at": started_at,
        "finished_at": utc_now(),
        "duration_ms": round((time.monotonic() - started_monotonic) * 1000, 3),
        "declared_argv": plan.get("argv"),
        "declared_environment": plan.get("environment"),
        "timeout_seconds": plan.get("timeout_seconds"),
        "output_limit_bytes": plan.get("output_limit_bytes"),
        "resolved_executable": None,
        "resolved_executable_identity": None,
        "outcome": "FAIL" if reason == "INTEGRITY_FAILURE" else "UNKNOWN",
        "termination_reason": reason,
        "detail": detail,
        "exit_code": None,
        "stdout": {"bytes": 0, "sha256": "sha256:" + hashlib.sha256(b"").hexdigest(), "captured_utf8": "", "truncated": False},
        "stderr": {"bytes": 0, "sha256": "sha256:" + hashlib.sha256(b"").hexdigest(), "captured_utf8": "", "truncated": False},
        "results": [],
        "policy_observations": {
            "network_policy": plan.get("network_policy"),
            "network_enforcement": "UNKNOWN",
        },
        "limitations": ["No hardware-backed attestation or independent custody was established."],
    }
    return attach_identity(record, "record_id")


def execute_local(
    plan_value: Any, bundle_root: Path, manifest_value: Any, machine_label: str,
    *, results_dir: Path | None = None, work_root: Path | None = None,
) -> dict[str, Any]:
    started_at = utc_now()
    started_monotonic = time.monotonic()
    node = collect_node_capabilities(machine_label)
    try:
        plan = validate_job_plan(plan_value)
    except FabricError as exc:
        fallback = dict(plan_value) if isinstance(plan_value, dict) else {}
        return _failure_record(plan=fallback, manifest_identity=None, node=node, started_at=started_at, started_monotonic=started_monotonic, reason="PLAN_INVALID", detail=str(exc))
    try:
        manifest = verify_manifest(bundle_root, manifest_value)
        if manifest["manifest_identity"] != plan["artifact_manifest_identity"]:
            raise IntegrityError("job plan and artifact manifest identities differ")
    except (IntegrityError, ValidationError, OSError) as exc:
        return _failure_record(plan=plan, manifest_identity=manifest_value.get("manifest_identity") if isinstance(manifest_value, dict) else None, node=node, started_at=started_at, started_monotonic=started_monotonic, reason="INTEGRITY_FAILURE", detail=str(exc))

    missing_capabilities = sorted(set(plan["required_capabilities"]) - capability_names(node))
    if missing_capabilities:
        return _failure_record(plan=plan, manifest_identity=manifest["manifest_identity"], node=node, started_at=started_at, started_monotonic=started_monotonic, reason="CAPABILITY_UNAVAILABLE", detail=f"missing capabilities: {missing_capabilities}")

    temporary_parent = None if work_root is None else str(work_root)
    with tempfile.TemporaryDirectory(prefix="mncs-fabric-", dir=temporary_parent) as temporary:
        workdir = Path(temporary) / "bundle"
        copy_manifest_files(bundle_root, workdir, manifest)
        cwd = workdir if plan["working_directory"] == "." else workdir / plan["working_directory"]
        if not cwd.is_dir():
            return _failure_record(plan=plan, manifest_identity=manifest["manifest_identity"], node=node, started_at=started_at, started_monotonic=started_monotonic, reason="WORKING_DIRECTORY_MISSING", detail=plan["working_directory"])
        argv = _resolve_argv(plan["argv"])
        executable = Path(argv[0])
        try:
            executable_size, executable_identity = file_identity(executable)
        except OSError as exc:
            return _failure_record(plan=plan, manifest_identity=manifest["manifest_identity"], node=node, started_at=started_at, started_monotonic=started_monotonic, reason="EXECUTABLE_UNAVAILABLE", detail=str(exc))
        creationflags = getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0) if os.name == "nt" else 0
        try:
            proc = subprocess.Popen(
                argv,
                cwd=cwd,
                env=_minimal_environment(plan["environment"]),
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                shell=False,
                start_new_session=(os.name == "posix"),
                creationflags=creationflags,
            )
        except OSError as exc:
            return _failure_record(plan=plan, manifest_identity=manifest["manifest_identity"], node=node, started_at=started_at, started_monotonic=started_monotonic, reason="LAUNCH_ERROR", detail=str(exc))
        assert proc.stdout is not None and proc.stderr is not None
        stdout_collector = _StreamCollector(proc.stdout, plan["output_limit_bytes"])
        stderr_collector = _StreamCollector(proc.stderr, plan["output_limit_bytes"])
        stdout_collector.start()
        stderr_collector.start()
        reason = "COMPLETED"
        deadline = time.monotonic() + float(plan["timeout_seconds"])
        while proc.poll() is None:
            if stdout_collector.exceeded.is_set() or stderr_collector.exceeded.is_set():
                reason = "OUTPUT_LIMIT"
                _terminate_process(proc)
                break
            if time.monotonic() >= deadline:
                reason = "TIMEOUT"
                _terminate_process(proc)
                break
            time.sleep(0.01)
        try:
            proc.wait(timeout=2.0)
        except subprocess.TimeoutExpired:
            reason = "PROCESS_UNTERMINATED"
            _terminate_process(proc)
        stdout_collector.join(timeout=2.0)
        stderr_collector.join(timeout=2.0)
        proc.stdout.close()
        proc.stderr.close()
        if stdout_collector.error or stderr_collector.error:
            reason = "OUTPUT_CAPTURE_ERROR"
        elif reason == "COMPLETED" and (stdout_collector.exceeded.is_set() or stderr_collector.exceeded.is_set()):
            reason = "OUTPUT_LIMIT"
        stdout = stdout_collector.result()
        stderr = stderr_collector.result()
        if reason == "COMPLETED":
            outcome = "PASS" if proc.returncode == 0 else "FAIL"
            if proc.returncode != 0:
                reason = "NONZERO_EXIT"
        else:
            outcome = "UNKNOWN"
        results: list[dict[str, Any]] = []
        if outcome == "PASS":
            for relative in plan["result_paths"]:
                candidate = workdir / relative
                if candidate.is_symlink():
                    outcome, reason = "FAIL", "RESULT_SYMLINK"
                    break
                path = candidate.resolve()
                try:
                    path.relative_to(workdir.resolve())
                except ValueError:
                    outcome, reason = "FAIL", "RESULT_ESCAPE"
                    break
                if not path.is_file():
                    outcome, reason = "FAIL", "RESULT_MISSING"
                    break
                size, identity = file_identity(path)
                results.append({"path": relative, "size": size, "sha256": identity})
                if results_dir is not None:
                    destination = results_dir / relative
                    destination.parent.mkdir(parents=True, exist_ok=True)
                    shutil.copyfile(path, destination)
        record = {
            "schema_version": EXECUTION_SCHEMA,
            "job_id": plan["job_id"],
            "job_identity": plan["job_identity"],
            "candidate_identity": plan["candidate_identity"],
            "evaluator_identity": plan.get("evaluator_identity"),
            "artifact_manifest_identity": manifest["manifest_identity"],
            "node": node,
            "started_at": started_at,
            "finished_at": utc_now(),
            "duration_ms": round((time.monotonic() - started_monotonic) * 1000, 3),
            "declared_argv": plan["argv"],
            "declared_environment": plan["environment"],
            "timeout_seconds": plan["timeout_seconds"],
            "output_limit_bytes": plan["output_limit_bytes"],
            "resolved_executable": str(executable),
            "resolved_executable_size": executable_size,
            "resolved_executable_identity": executable_identity,
            "outcome": outcome,
            "termination_reason": reason,
            "detail": None,
            "exit_code": proc.returncode,
            "stdout": _stream_record(stdout),
            "stderr": _stream_record(stderr),
            "results": sorted(results, key=lambda item: item["path"]),
            "policy_observations": {
                "network_policy": plan["network_policy"],
                "network_enforcement": "UNKNOWN",
            },
            "limitations": [
                "Execution is bounded but not a security sandbox.",
                "No hardware-backed attestation or independent custody was established.",
                "Network policy is recorded but not enforced by the local executor.",
            ],
        }
        return attach_identity(record, "record_id")
