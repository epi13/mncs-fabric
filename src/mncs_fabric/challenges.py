"""Compatibility boundary for MNCS EA-NEXT-005 execution challenges.

Fabric protocol replay protection and MNCS freshness are separate layers. This
module implements the current experimental challenge shape and a Fabric-owned
durable single-use replay ledger without importing MNCS validator internals.
Freshness remains local replay-store evidence, not assurance or authority.
"""

from __future__ import annotations

import hashlib
import re
import secrets
from copy import deepcopy
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from .canonical import sha256_identity
from .errors import ProtocolError
from .jcs import canonical_jcs_bytes
from .store import FabricLedger

SCHEMA_VERSION = "0.1-experimental"
CHALLENGE_TYPE = "mncs-execution-challenge"
REQUEST_TYPE = "mncs-execution-challenge-request"
REPLAY_TYPE = "mncs-replay-receipt"
_HASH = re.compile(r"^[0-9a-f]{64}$")
_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_NONCE = re.compile(r"^[A-Za-z0-9_-]{43,128}$")


@dataclass
class ChallengeReport:
    valid: bool = True
    supported: bool = True
    challenge: dict[str, Any] | None = None
    issues: list[str] = field(default_factory=list)

    @property
    def category(self) -> str:
        if not self.supported:
            return "UNKNOWN"
        return "PASS" if self.valid else "FAIL"

    def fail(self, message: str) -> None:
        self.valid = False
        self.issues.append(message)


@dataclass
class ReplayReport:
    valid: bool = True
    supported: bool = True
    replay_receipt: dict[str, Any] | None = None
    issues: list[str] = field(default_factory=list)

    @property
    def category(self) -> str:
        if not self.supported:
            return "UNKNOWN"
        return "PASS" if self.valid else "FAIL"

    def fail(self, message: str) -> None:
        self.valid = False
        self.issues.append(message)


def _raw(value: object) -> str:
    if isinstance(value, str) and value.startswith("sha256:"):
        return value[7:]
    return value if isinstance(value, str) else ""


def _time(value: object) -> datetime:
    if not isinstance(value, str):
        raise ValueError("challenge timestamps must be strings")
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError("challenge timestamps must include a UTC offset")
    return parsed.astimezone(UTC)


def _iso(value: datetime) -> str:
    return value.astimezone(UTC).isoformat(timespec="microseconds").replace("+00:00", "Z")


def _raw_identity(value: object) -> str:
    return hashlib.sha256(canonical_jcs_bytes(value)).hexdigest()


def _without(value: dict[str, Any], field_name: str) -> str:
    material = deepcopy(value)
    material.pop(field_name, None)
    return _raw_identity(material)


def _claim_boundary() -> dict[str, str]:
    return {"freshness": "local-replay-scope-only", "authority": "not-asserted", "isolation": "not-asserted", "custody": "not-asserted", "independence": "not-asserted", "conformance": "not-asserted", "promotion": "not-asserted"}


def _scope_from_receipt(receipt: dict[str, Any]) -> dict[str, Any]:
    subject = receipt.get("subject") if isinstance(receipt.get("subject"), dict) else {}
    bundle = receipt.get("bundle") if isinstance(receipt.get("bundle"), dict) else {}
    policy = receipt.get("policy") if isinstance(receipt.get("policy"), dict) else {}
    runner = receipt.get("runner") if isinstance(receipt.get("runner"), dict) else {}
    return {"subject_identity": _raw(subject.get("canonical_sha256")), "candidate_id": subject.get("candidate_id"), "bundle_identity": _raw(bundle.get("test_bundle_identity")), "execution_policy_identity": _raw(policy.get("execution_policy_identity")), "runner_identity": runner.get("runner_identity")}


def issue_execution_challenge(*, issuer_identity: str, scope: dict[str, Any], ttl_seconds: float = 300, now: datetime | None = None) -> ChallengeReport:
    if not _ID.fullmatch(issuer_identity) or not isinstance(ttl_seconds, (int, float)) or ttl_seconds <= 0 or ttl_seconds > 604800:
        report = ChallengeReport()
        report.fail("issuer identity or TTL is invalid")
        return report
    required = {"subject_identity", "candidate_id", "bundle_identity", "execution_policy_identity", "runner_identity"}
    if set(scope) != required or not _HASH.fullmatch(str(scope.get("subject_identity"))) or not _HASH.fullmatch(str(scope.get("bundle_identity"))) or not _HASH.fullmatch(str(scope.get("execution_policy_identity"))):
        report = ChallengeReport()
        report.fail("challenge scope is invalid")
        return report
    if scope["candidate_id"] is not None and not _ID.fullmatch(str(scope["candidate_id"])):
        report = ChallengeReport()
        report.fail("candidate_id is invalid")
        return report
    if scope["runner_identity"] is not None and not _ID.fullmatch(str(scope["runner_identity"])):
        report = ChallengeReport()
        report.fail("runner_identity is invalid")
        return report
    issued = now or datetime.now(UTC)
    nonce = secrets.token_urlsafe(32)
    challenge: dict[str, Any] = {"schema_version": SCHEMA_VERSION, "record_type": CHALLENGE_TYPE, "challenge_id": "challenge." + _raw_identity({"scope": scope, "nonce": nonce})[:24] + "." + nonce[:12], "challenge_identity": "0" * 64, "issuer_identity": issuer_identity, "issued_at": _iso(issued), "expires_at": _iso(issued + timedelta(seconds=float(ttl_seconds))), "nonce": nonce, "scope": deepcopy(scope), "replay_policy": "single-use", "claim_boundary": _claim_boundary(), "extensions": {"mncs-fabric:issuer-role": "operator-controlled-challenge-adapter"}}
    challenge["challenge_identity"] = _without(challenge, "challenge_identity")
    return validate_execution_challenge(challenge)


def challenge_for_receipt(receipt: dict[str, Any], *, issuer_identity: str, ttl_seconds: float = 300, now: datetime | None = None) -> ChallengeReport:
    return issue_execution_challenge(issuer_identity=issuer_identity, scope=_scope_from_receipt(receipt), ttl_seconds=ttl_seconds, now=now)


def validate_execution_challenge(value: object, *, at: datetime | None = None) -> ChallengeReport:
    report = ChallengeReport()
    if not isinstance(value, dict):
        report.fail("challenge must be an object")
        return report
    if value.get("schema_version") != SCHEMA_VERSION:
        report.supported = False
        report.fail("unsupported challenge schema version")
        return report
    required = {"schema_version", "record_type", "challenge_id", "challenge_identity", "issuer_identity", "issued_at", "expires_at", "nonce", "scope", "replay_policy", "claim_boundary", "extensions"}
    if set(value) != required:
        report.fail("challenge field set is invalid")
        return report
    if value.get("record_type") != CHALLENGE_TYPE or not _ID.fullmatch(str(value.get("challenge_id"))) or not _ID.fullmatch(str(value.get("issuer_identity"))) or not _HASH.fullmatch(str(value.get("challenge_identity"))) or value.get("replay_policy") != "single-use" or not isinstance(value.get("extensions"), dict):
        report.fail("challenge identity or type fields are invalid")
    if not isinstance(value.get("nonce"), str) or not _NONCE.fullmatch(value["nonce"]):
        report.fail("challenge nonce is invalid")
    scope = value.get("scope")
    if not isinstance(scope, dict) or set(scope) != {"subject_identity", "candidate_id", "bundle_identity", "execution_policy_identity", "runner_identity"}:
        report.fail("challenge scope field set is invalid")
    else:
        for field_name in ("subject_identity", "bundle_identity", "execution_policy_identity"):
            if not _HASH.fullmatch(str(scope.get(field_name))):
                report.fail("challenge scope hash is invalid: " + field_name)
        for field_name in ("candidate_id", "runner_identity"):
            if scope.get(field_name) is not None and not _ID.fullmatch(str(scope[field_name])):
                report.fail("challenge scope ID is invalid: " + field_name)
    if value.get("claim_boundary") != _claim_boundary():
        report.fail("challenge claim boundary is invalid")
    try:
        issued = _time(value.get("issued_at"))
        expires = _time(value.get("expires_at"))
        if expires <= issued:
            report.fail("challenge expiry must follow issuance")
        if at is not None and (at < issued or at >= expires):
            report.fail("challenge is outside its validity window")
    except ValueError as exc:
        report.fail(str(exc))
    if value.get("challenge_identity") != _without(value, "challenge_identity"):
        report.fail("challenge identity does not reconstruct")
    report.challenge = deepcopy(value)
    return report


def bind_challenge_to_receipt(challenge: dict[str, Any], receipt: dict[str, Any]) -> ReplayReport:
    report = ReplayReport()
    challenge_report = validate_execution_challenge(challenge)
    if not challenge_report.valid:
        report.fail("challenge is invalid")
        return report
    if not isinstance(receipt, dict) or not _HASH.fullmatch(str(receipt.get("receipt_identity"))):
        report.fail("receipt identity is invalid")
        return report
    if receipt.get("receipt_identity") != _without(receipt, "receipt_identity"):
        report.fail("receipt identity does not reconstruct")
        return report
    expected = _scope_from_receipt(receipt)
    if expected != challenge["scope"]:
        report.fail("receipt scope differs from challenge scope")
    observed = receipt.get("challenge") if isinstance(receipt.get("challenge"), dict) else {}
    for field_name in ("nonce", "issued_at", "expires_at"):
        if observed.get(field_name) != challenge.get(field_name):
            report.fail("receipt challenge observation differs: " + field_name)
    return report


class ChallengeReplayStore:
    """Fabric-owned durable single-use challenge ledger."""

    def __init__(self, path: Path) -> None:
        self.ledger = FabricLedger(Path(path))

    def _entries(self) -> list[dict[str, Any]]:
        return [entry["record"] for entry in self.ledger.records(record_type="mncs-fabric.challenge-replay", limit=100000)]

    def consume(self, challenge: dict[str, Any], receipt: dict[str, Any], *, now: datetime | None = None) -> ReplayReport:
        report = bind_challenge_to_receipt(challenge, receipt)
        if not report.valid:
            return report
        entries = self._entries()
        challenge_id = challenge["challenge_identity"]
        nonce_digest = hashlib.sha256(challenge["nonce"].encode("utf-8")).hexdigest()
        if any(entry.get("challenge_identity") == challenge_id or entry.get("nonce_digest") == nonce_digest for entry in entries):
            report.fail("challenge has already been consumed")
            return report
        current = (now or datetime.now(UTC)).astimezone(UTC)
        prior = max((_time(entry["time_watermark"]) for entry in entries), default=None)
        effective = max(current, prior) if prior is not None else current
        issued, expires = _time(challenge["issued_at"]), _time(challenge["expires_at"])
        if effective < issued or effective >= expires:
            report.fail("challenge is outside the replay store validity window")
            return report
        previous = entries[-1]["entry_identity"] if entries else None
        entry: dict[str, Any] = {"schema_version": SCHEMA_VERSION, "record_type": "mncs-replay-entry", "sequence": len(entries) + 1, "entry_identity": "0" * 64, "challenge_identity": challenge_id, "nonce_digest": nonce_digest, "receipt_identity": receipt["receipt_identity"], "scope": deepcopy(challenge["scope"]), "consumed_at": _iso(effective), "previous_entry_identity": previous, "time_watermark": _iso(effective)}
        entry["entry_identity"] = _without(entry, "entry_identity")
        self.ledger.append("mncs-fabric.challenge-replay", entry)
        replay: dict[str, Any] = {"schema_version": SCHEMA_VERSION, "record_type": REPLAY_TYPE, "replay_id": "replay." + entry["entry_identity"][:32], "replay_identity": "0" * 64, "challenge_identity": challenge_id, "receipt_identity": receipt["receipt_identity"], "scope": deepcopy(challenge["scope"]), "consumed_at": entry["consumed_at"], "store_sequence": entry["sequence"], "nonce_digest": nonce_digest, "store_entry_identity": entry["entry_identity"], "previous_entry_identity": previous, "store_head_identity": entry["entry_identity"], "time_watermark": entry["time_watermark"], "limitations": ["Replay detection is limited to this operator-controlled local store.", "A host administrator can replace or delete the local replay store.", "Freshness does not establish correctness, isolation, custody, independence, conformance, or promotion."], "extensions": {}}
        replay["replay_identity"] = _without(replay, "replay_identity")
        report.replay_receipt = replay
        return report


def verify_replay_receipt(replay: dict[str, Any], challenge: dict[str, Any], receipt: dict[str, Any], *, store: ChallengeReplayStore | None = None) -> ReplayReport:
    report = ReplayReport(replay_receipt=deepcopy(replay))
    if not isinstance(replay, dict) or replay.get("schema_version") != SCHEMA_VERSION or replay.get("record_type") != REPLAY_TYPE or replay.get("replay_identity") != _without(replay, "replay_identity"):
        report.fail("replay receipt identity or version is invalid")
        return report
    bound = bind_challenge_to_receipt(challenge, receipt)
    if not bound.valid:
        report.issues.extend(bound.issues)
        report.valid = False
        return report
    if replay.get("challenge_identity") != challenge.get("challenge_identity") or replay.get("receipt_identity") != receipt.get("receipt_identity") or replay.get("nonce_digest") != hashlib.sha256(challenge["nonce"].encode("utf-8")).hexdigest():
        report.fail("replay receipt is bound to different challenge evidence")
    if store is not None and report.valid:
        matches = [entry for entry in store._entries() if entry.get("entry_identity") == replay.get("store_entry_identity")]
        if not matches:
            report.fail("replay entry is absent from the supplied store")
    return report
