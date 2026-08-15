"""Reporting-only runtime build identity for a running Fabric process.

This is not part of inventory identity. Adding or omitting these fields must
not rotate certification or conformance hashes.
"""

from __future__ import annotations

import hashlib
import os
import subprocess
from pathlib import Path
from typing import Any

from . import __version__


def _git_head(root: Path) -> str | None:
    if not (root / ".git").exists():
        return None
    try:
        result = subprocess.run(
            ["git", "-C", str(root), "rev-parse", "HEAD"],
            capture_output=True,
            text=True,
            timeout=3,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    value = (result.stdout or "").strip()
    return value or None


def _package_root() -> Path:
    return Path(__file__).resolve().parents[2]


def _revision_file() -> str | None:
    configured = os.environ.get("MNCS_FABRIC_SOURCE_COMMIT")
    if configured:
        return configured.strip() or None
    candidates = [
        Path.home() / ".local" / "share" / "mncs-fabric" / "fabric-revision.txt",
        _package_root() / "fabric-revision.txt",
    ]
    for path in candidates:
        try:
            value = path.read_text(encoding="utf-8").strip()
        except OSError:
            continue
        if value:
            return value
    return _git_head(_package_root())


def collect_runtime_identity(*, role: str = "controller") -> dict[str, Any]:
    source_commit = _revision_file()
    artifact_digest = (os.environ.get("MNCS_FABRIC_ARTIFACT_DIGEST") or "").strip() or None
    identity = {
        "package": "mncs-fabric",
        "version": __version__,
        "role": role,
        "source_commit": source_commit,
        "artifact_digest": artifact_digest,
    }
    digest_source = f"{identity['package']}|{identity['version']}|{source_commit or ''}|{artifact_digest or ''}|{role}"
    identity["build_identity"] = (
        "sha256:" + hashlib.sha256(digest_source.encode("utf-8")).hexdigest()
        if source_commit or artifact_digest
        else None
    )
    return identity
