"""Production runtime boundary to compiled MNCS decision artifacts (pilot).

This module lets production Fabric obtain a decision from a compiled MNCS
implementation instead of recalculating it in Python. It is an explicit,
fail-hard boundary:

- the caller provides the MNCS CLI and a pinned backend artifact;
- artifact identity is verified against the pin before any execution;
- inputs are marshalled to typed MNCS execution requests;
- one ``mncs experiment execute`` subprocess answers a whole batch
  (~280 ms fixed cost per batch, ~0 marginal per decision);
- any toolchain absence, identity mismatch, timeout, or non-returned
  case raises :class:`AuthorityError`.

There is deliberately no silent fallback to the Python implementation.
When MNCS authority is unavailable, scheduling must fail loudly rather
than silently recalculate, otherwise the MNCS module could diverge
without anyone noticing. Callers opt in by passing an authority
explicitly; the default paths keep the legacy Python calculation and
its documented MNCS owner.

Current scope (pilot): the ordered resolution code
(``fabric.worker_capability::candidate_resolve``), i.e. the exact
decision ``capability_resolution.resolve_code`` mirrors. Text-dependent
refinements (toolchain/runtime-missing classification, forbidden-token
policy denial) stay Python-side: MNCS cannot observe capability strings
(see pressure P-005).
"""

from __future__ import annotations

import json
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping, Sequence



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
    """Executes pinned MNCS decision artifacts for production callers."""

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
        if not artifact_path.is_file():
            raise AuthorityError(f"MNCS authority artifact is unavailable: {artifact_path}")
        try:
            document = json.loads(artifact_path.read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            raise AuthorityError(f"MNCS authority artifact is unreadable: {exc}") from exc
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
        self._cli = str(cli_path)
        self._artifact = str(artifact_path)
        self._identity = str(identity)
        self._backend = str(backend.get("name", "unknown"))
        self._timeout = float(timeout_seconds)

    @property
    def artifact_identity(self) -> str:
        return self._identity

    @property
    def backend_name(self) -> str:
        return self._backend

    def evidence(self) -> dict[str, str]:
        """Identity facts for receipts: which artifact answered."""
        return {"mncs_artifact": self._identity, "mncs_backend": self._backend}

    def resolve_codes(self, rows: Sequence[ResolveInputs]) -> list[str]:
        """Answer one ordered resolution code per row from compiled MNCS.

        Raises :class:`AuthorityError` unless every row returns. The
        caller applies text-dependent refinements (toolchain/runtime
        classification) that MNCS cannot express.
        """
        if not rows:
            return []
        cases = []
        for index, row in enumerate(rows):
            try:
                live_variant = LIVENESS_MNCS[row.liveness]
            except KeyError as exc:
                raise AuthorityError(f"authority row {index} carries unknown liveness {row.liveness!r}") from exc
            try:
                fresh_variant = FRESHNESS_MNCS[row.freshness]
            except KeyError as exc:
                raise AuthorityError(f"authority row {index} carries unknown freshness {row.freshness!r}") from exc
            # No "expected" key: the caller, not the corpus, judges the
            # answer (an empty expected list is rejected by the CLI).
            cases.append(
                {
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
            )
        corpus = {"schema_version": "0.1", "name": "fabric-authority-batch", "cases": cases}
        with tempfile.TemporaryDirectory(prefix="fabric-mncs-authority-") as tmp:
            corpus_path = Path(tmp) / "batch.json"
            corpus_path.write_text(json.dumps(corpus), encoding="utf-8")
            try:
                completed = subprocess.run(
                    [self._cli, "experiment", "execute", self._artifact, str(corpus_path)],
                    capture_output=True,
                    text=True,
                    timeout=self._timeout,
                )
            except (OSError, subprocess.SubprocessError) as exc:
                raise AuthorityError(f"MNCS authority execution failed: {exc}") from exc
        if completed.returncode != 0:
            raise AuthorityError(
                "MNCS authority execution exited "
                f"{completed.returncode}: {completed.stderr[-1000:]}"
            )
        try:
            observations = json.loads(completed.stdout)
        except ValueError as exc:
            raise AuthorityError(f"MNCS authority returned unparseable output: {exc}") from exc
        if not isinstance(observations, list) or len(observations) != len(rows):
            raise AuthorityError(
                f"MNCS authority returned {len(observations) if isinstance(observations, list) else '?'} "
                f"observations for {len(rows)} rows"
            )
        codes: list[str] = []
        for index, observation in enumerate(observations):
            if observation.get("status") != "returned" or not observation.get("returned"):
                raise AuthorityError(
                    f"MNCS authority did not answer row {index}: "
                    f"{observation.get('status')} {observation.get('failure_reason')}"
                )
            variant = (
                observation["returned"][0]
                .get("finite", {})
                .get("variant_identity", "")
                .rsplit("::", 1)[-1]
            )
            if variant not in CODE_PY:
                raise AuthorityError(f"MNCS authority answered row {index} with unknown code {variant!r}")
            codes.append(CODE_PY[variant])
        return codes


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
