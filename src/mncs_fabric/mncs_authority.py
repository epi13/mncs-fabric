"""Production runtime boundary to compiled MNCS decision artifacts (pilot).

This module lets production Fabric obtain a decision from a compiled MNCS
implementation instead of recalculating it in Python. It is an explicit,
fail-hard boundary:

- the caller provides the MNCS CLI and a pinned backend artifact;
- the artifact bytes are read once at construction, verified against
  the pin, and retained immutably in memory;
- every execution materializes exactly those bytes into a fresh
  exclusively-created file, so the bytes executed are byte-identical to
  the bytes verified: replacing or modifying the artifact path later
  cannot affect execution (no TOCTOU);
- evidence binds the declared artifact identity, the SHA-256 of the
  executed bytes, and the backend name;
- answers are correlated by stable case identity (duplicates, missing,
  extra, or reordered answers fail closed);
- any toolchain absence, identity mismatch, timeout, oversize output,
  or malformed answer raises :class:`AuthorityError`.

There is deliberately no silent fallback to the Python implementation.
Callers opt in by passing an authority explicitly; the default paths
keep the legacy Python calculation and its documented MNCS owner.

Trust assumptions (documented, not hidden): the caller trusts the MNCS
CLI binary the way it trusts the Python interpreter (the CLI path is
recorded in evidence but the binary itself is not hashed); the process
umask/temp directory must not grant other users write access to the
materialization directory (``mkstemp`` creates files ``0600``).

Current scope (pilot): the ordered resolution code
(``fabric.worker_capability::candidate_resolve``), i.e. the exact
decision ``capability_resolution.resolve_code`` mirrors. Text-dependent
refinements (toolchain/runtime-missing classification, forbidden-token
policy denial) stay Python-side: MNCS cannot observe capability strings
(see pressure P-005/P-014).
"""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import tempfile
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Sequence

MODULE = "fabric.worker_capability"
FUNCTION = "candidate_resolve"
EXPECTED_KIND = "research_bytecode"

LIVENESS_MNCS = {"AVAILABLE": "Available", "UNAVAILABLE": "Unavailable", "DISCONNECTED": "Disconnected"}
FRESHNESS_MNCS = {"fresh": "Fresh", "stale": "Stale"}
CODE_PY = {
    "Eligible": "ELIGIBLE",
    "CapabilityUnsatisfied": "CAPABILITY_UNSATISFIED",
    "PolicyDenied": "POLICY_DENIED",
    "ProvenanceUnverified": "PROVENANCE_UNVERIFIED",
    "WorkerStale": "WORKER_STALE",
    "WorkerUnavailable": "WORKER_UNAVAILABLE",
    "WorkerDisconnected": "WORKER_DISCONNECTED",
}

# Bound on subprocess output held in memory. A resolve batch carries one
# small observation per row; anything beyond this is a malfunctioning or
# hostile CLI, and the call fails rather than consuming the host.
_MAX_OUTPUT_BYTES = 64 * 1024 * 1024


class AuthorityError(Exception):
    """MNCS authority is unavailable or refused to answer. Never a fallback signal."""


def _finite(type_name: str, variant_name: str, discriminant: int) -> dict[str, Any]:
    return {
        "finite": {
            "type_identity": f"mncs:0.2:finite-type:{MODULE}::{type_name}",
            "variant_identity": f"mncs:0.2:finite-variant:{MODULE}::{type_name}::{variant_name}",
            "discriminant": discriminant,
        }
    }


def _boolean(value: object) -> dict[str, Any]:
    return {"boolean": {"value": bool(value)}}


@dataclass(frozen=True)
class ResolveInputs:
    """The five scalars the ordered resolution code decides over."""

    liveness: str
    freshness: str
    provenance_ok: bool
    env_ok: bool
    intent_ok: bool


class MncsAuthority:
    """Executes pinned MNCS decision artifacts for production callers.

    Immutable after construction and safe to share across threads: every
    call works from the in-memory verified bytes and unique temp files.
    """

    def __init__(
        self,
        *,
        cli: str | Path,
        artifact: str | Path,
        expected_artifact_identity: str,
        timeout_seconds: float = 120.0,
    ) -> None:
        cli_path = Path(cli)
        if not cli_path.is_file():
            raise AuthorityError(f"MNCS toolchain CLI is unavailable: {cli_path}")
        artifact_path = Path(artifact)
        try:
            raw = artifact_path.read_bytes()
        except OSError as exc:
            raise AuthorityError(f"MNCS authority artifact is unreadable: {exc}") from exc
        try:
            document = json.loads(raw.decode("utf-8"))
        except ValueError as exc:
            raise AuthorityError(f"MNCS authority artifact is not valid JSON: {exc}") from exc
        if not isinstance(document, dict):
            raise AuthorityError("MNCS authority artifact is not a JSON object")
        identity = document.get("identity")
        if identity != expected_artifact_identity:
            raise AuthorityError(
                "MNCS authority artifact identity does not match the pin: "
                f"expected {expected_artifact_identity!r}, found {identity!r}"
            )
        if document.get("artifact_kind") != EXPECTED_KIND:
            raise AuthorityError(
                f"MNCS authority artifact kind {document.get('artifact_kind')!r} "
                f"is not {EXPECTED_KIND!r}"
            )
        backend = document.get("backend") or {}
        if not isinstance(backend, dict):
            raise AuthorityError("MNCS authority artifact backend block is malformed")
        self._cli = str(cli_path)
        self._artifact_bytes = bytes(raw)
        self._artifact_sha256 = hashlib.sha256(raw).hexdigest()
        self._identity = str(identity)
        self._backend = str(backend.get("name", "unknown"))
        self._timeout = float(timeout_seconds)

    @property
    def artifact_identity(self) -> str:
        return self._identity

    @property
    def artifact_sha256(self) -> str:
        """SHA-256 of the exact bytes this authority executes."""
        return self._artifact_sha256

    @property
    def backend_name(self) -> str:
        return self._backend

    def evidence(self) -> dict[str, str]:
        """Identity facts for receipts: which bytes answered.

        ``mncs_artifact`` is the pinned declared identity;
        ``mncs_artifact_sha256`` binds the exact executed bytes, so a
        file swap that preserves the identity string is still detectable
        against independently recorded hashes.
        """
        return {
            "mncs_artifact": self._identity,
            "mncs_artifact_sha256": self._artifact_sha256,
            "mncs_backend": self._backend,
            "mncs_cli": self._cli,
        }

    def resolve_codes(self, rows: Sequence[ResolveInputs]) -> list[str]:
        """Answer one ordered resolution code per row from compiled MNCS.

        Raises :class:`AuthorityError` unless every row is answered
        exactly once. Answers are correlated by case identity, so
        duplicates, omissions, extras, or reordering fail closed. The
        caller applies text-dependent refinements (toolchain/runtime
        classification) that MNCS cannot express.
        """
        if not rows:
            return []
        cases = [self._case(index, row) for index, row in enumerate(rows)]
        expected_ids = [case["id"] for case in cases]
        corpus = {"schema_version": "0.1", "name": "fabric-authority-batch", "cases": cases}
        observations = self._execute(corpus)
        by_id: dict[str, Any] = {}
        for observation in observations:
            if not isinstance(observation, Mapping):
                raise AuthorityError("MNCS authority returned a malformed observation")
            case_id = observation.get("case_id")
            if case_id in by_id:
                raise AuthorityError(f"MNCS authority answered {case_id!r} more than once")
            by_id[case_id] = observation
        missing = [case_id for case_id in expected_ids if case_id not in by_id]
        if missing:
            raise AuthorityError(f"MNCS authority did not answer: {missing!r}")
        extra = [case_id for case_id in by_id if case_id not in set(expected_ids)]
        if extra:
            raise AuthorityError(f"MNCS authority answered unexpected cases: {extra!r}")
        return [self._decode(by_id[case_id], case_id) for case_id in expected_ids]

    @staticmethod
    def _case(index: int, row: ResolveInputs) -> dict[str, Any]:
        try:
            live_variant = LIVENESS_MNCS[row.liveness]
        except KeyError as exc:
            raise AuthorityError(f"authority row {index} carries unknown liveness {row.liveness!r}") from exc
        try:
            fresh_variant = FRESHNESS_MNCS[row.freshness]
        except KeyError as exc:
            raise AuthorityError(f"authority row {index} carries unknown freshness {row.freshness!r}") from exc
        # No "expected" key: the caller, not the corpus, judges the
        # answer (an empty expected list is rejected by the CLI: P-013).
        return {
            "id": f"authority-{index}",
            "request": {
                "schema_version": "0.1",
                "target": {"module": MODULE, "function": FUNCTION},
                "arguments": [
                    _finite("Liveness", live_variant, list(LIVENESS_MNCS).index(row.liveness)),
                    _finite("Freshness", fresh_variant, list(FRESHNESS_MNCS).index(row.freshness)),
                    _boolean(row.provenance_ok),
                    _boolean(row.env_ok),
                    _boolean(row.intent_ok),
                ],
                "step_budget": 4096,
            },
        }

    @staticmethod
    def _decode(observation: Mapping[str, Any], case_id: str) -> str:
        returned = observation.get("returned")
        if observation.get("status") != "returned" or not returned:
            raise AuthorityError(
                f"MNCS authority did not answer {case_id}: "
                f"{observation.get('status')} {observation.get('failure_reason')}"
            )
        first = returned[0] if isinstance(returned, list) else None
        variant = ""
        if isinstance(first, Mapping):
            finite = first.get("finite")
            if isinstance(finite, Mapping):
                variant_identity = finite.get("variant_identity")
                if isinstance(variant_identity, str):
                    variant = variant_identity.rsplit("::", 1)[-1]
        if variant not in CODE_PY:
            raise AuthorityError(f"MNCS authority answered {case_id} with unknown code {variant!r}")
        return CODE_PY[variant]

    def _execute(self, corpus: dict[str, Any]) -> list[Any]:
        """Execute the verified in-memory bytes against one batch corpus.

        The artifact file is materialized fresh from memory into an
        exclusively-created file for this call only, so the executed
        bytes are byte-identical to the verified bytes regardless of
        what happens to the artifact path afterwards.
        """
        corpus_fd, corpus_path = tempfile.mkstemp(prefix="fabric-mncs-authority-corpus-", suffix=".json")
        artifact_fd, artifact_path = tempfile.mkstemp(prefix="fabric-mncs-authority-artifact-", suffix=".json")
        try:
            with os.fdopen(corpus_fd, "w", encoding="utf-8") as handle:
                json.dump(corpus, handle)
            with os.fdopen(artifact_fd, "wb") as handle:
                handle.write(self._artifact_bytes)
            try:
                completed = subprocess.run(
                    [self._cli, "experiment", "execute", artifact_path, corpus_path],
                    capture_output=True,
                    text=True,
                    timeout=self._timeout,
                )
            except (OSError, subprocess.SubprocessError) as exc:
                raise AuthorityError(f"MNCS authority execution failed: {exc}") from exc
        finally:
            for path in (corpus_path, artifact_path):
                try:
                    os.unlink(path)
                except OSError:
                    pass
        if completed.returncode != 0:
            raise AuthorityError(
                "MNCS authority execution exited "
                f"{completed.returncode}: {completed.stderr[-1000:]}"
            )
        if len(completed.stdout.encode("utf-8")) > _MAX_OUTPUT_BYTES:
            raise AuthorityError(
                f"MNCS authority output exceeded {_MAX_OUTPUT_BYTES} bytes; refusing to parse"
            )
        try:
            observations = json.loads(completed.stdout)
        except ValueError as exc:
            raise AuthorityError(f"MNCS authority returned unparseable output: {exc}") from exc
        if not isinstance(observations, list):
            raise AuthorityError("MNCS authority did not return an observation list")
        return observations


def build_authority_from_environment(
    mapping: Mapping[str, str] | None = None,
) -> MncsAuthority | None:
    """Build an authority from explicit configuration, else None.

    ``mapping`` must carry ``MNCS_CLI``, ``MNCS_AUTHORITY_ARTIFACT``, and
    ``MNCS_AUTHORITY_IDENTITY``. Missing configuration returns None (the
    caller keeps the legacy path openly, chosen by deployment, never as
    a per-decision silent fallback). Present-but-invalid configuration
    raises :class:`AuthorityError`.
    """
    import os

    source: Mapping[str, str] = mapping if mapping is not None else os.environ
    cli = source.get("MNCS_CLI")
    artifact = source.get("MNCS_AUTHORITY_ARTIFACT")
    identity = source.get("MNCS_AUTHORITY_IDENTITY")
    if cli is None and artifact is None and identity is None:
        return None
    if not cli or not artifact or not identity:
        raise AuthorityError(
            "partial MNCS authority configuration: MNCS_CLI, "
            "MNCS_AUTHORITY_ARTIFACT, and MNCS_AUTHORITY_IDENTITY are all required"
        )
    return MncsAuthority(cli=cli, artifact=artifact, expected_artifact_identity=identity)
