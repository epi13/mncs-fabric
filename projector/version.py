"""Repo-owned renderer for the mncs-fabric:version projection.

Derives the authoritative Fabric version statement from
``pyproject.toml`` (``[project].version``), the single canonical package
version source. README prose must not hardcode the current version; it
either states release history (CHANGELOG) or omits the version and lets this
projection carry it.
"""


from __future__ import annotations

import hashlib
import json
import tomllib
from typing import Any


def _digest_text(value: str) -> str:
    return "sha256:" + hashlib.sha256(value.encode("utf-8")).hexdigest()


def render_fabric_version(model: dict[str, Any]) -> str:
    """Render the version statement from the observed pyproject text."""
    values = model.get("values") or {}
    text = values.get("pyproject")
    if not isinstance(text, str) or not text.strip():
        raise ValueError("pyproject subject unavailable")
    try:
        data = tomllib.loads(text)
    except tomllib.TOMLDecodeError as error:
        raise ValueError("pyproject unparseable: %s" % error) from error
    project = data.get("project") or {}
    version = project.get("version")
    name = project.get("name")
    if not isinstance(version, str) or not version:
        raise ValueError("pyproject [project].version missing")
    if not isinstance(name, str) or not name:
        raise ValueError("pyproject [project].name missing")
    statement = {
        "schema_version": "mncs.fabric-version/1",
        "name": name,
        "version": version,
        "source": {
            "file": "pyproject.toml",
            "selector": "/project/version",
            "source_identity": _digest_text(text),
        },
    }
    return json.dumps(statement, indent=2, sort_keys=True) + "\n"
