"""Durable, controller-local worker commissioning and presence state.

This module is deliberately additive to the explicit endpoint registry and to
TrustStore.  It records operator decisions and authenticated session facts; it
does not issue certificates, discover peers, attest machines, or grant shell
authority.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import os
import re
import secrets
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Mapping

from .canonical import attach_identity, is_sha256_identity, sha256_identity
from .errors import ProtocolError, StorageError, ValidationError
from .node import utc_now
from .store import FabricLedger

AUTHORIZATION_SCHEMA = "mncs-fabric.enrollment-authorization.v0.1"
REQUEST_SCHEMA = "mncs-fabric.enrollment-request.v0.1"
DECISION_SCHEMA = "mncs-fabric.enrollment-decision.v0.1"
MEMBERSHIP_SCHEMA = "mncs-fabric.fleet-membership.v0.1"
PRESENCE_SCHEMA = "mncs-fabric.session-presence.v0.1"
LIFECYCLE_SCHEMA = "mncs-fabric.lifecycle.v0.1"

AUTHORIZATION_STATES = {"ACTIVE", "CONSUMED", "EXPIRED", "REVOKED"}
DECISIONS = {"APPROVED", "DENIED", "EXPIRED"}
MEMBERSHIP_STATES = {"ENROLLED", "REVOKED", "DECOMMISSIONED"}
MAX_TTL_SECONDS = 7 * 24 * 60 * 60
MAX_METADATA_ITEMS = 16
MAX_METADATA_TEXT = 256
MAX_PUBLIC_KEY_BYTES = 8192
SESSION_MAX_AGE_SECONDS = 300.0
_IDENTITY_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_SESSION_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_SECRET_WORDS = ("token", "secret", "private", "password", "credential")
_SUPPORTED_RECORD_SCHEMAS = {
    AUTHORIZATION_SCHEMA, REQUEST_SCHEMA, DECISION_SCHEMA, MEMBERSHIP_SCHEMA,
    PRESENCE_SCHEMA, LIFECYCLE_SCHEMA,
}


def default_state_dir() -> Path:
    """Return the platform-neutral user state directory used by the CLI."""

    if os.name == "nt":
        root = os.environ.get("LOCALAPPDATA") or os.environ.get("APPDATA")
        return Path(root) / "mncs-fabric" if root else Path.home() / "AppData" / "Local" / "mncs-fabric"
    root = os.environ.get("XDG_STATE_HOME")
    return Path(root) / "mncs-fabric" if root else Path.home() / ".local" / "state" / "mncs-fabric"


def default_lifecycle_path() -> Path:
    return default_state_dir() / "lifecycle.jsonl"


def _text(value: object, field: str, maximum: int = 256, *, allow_empty: bool = False) -> str:
    if not isinstance(value, str) or len(value) > maximum or "\x00" in value or (not allow_empty and not value):
        raise ValidationError(f"{field} must be bounded text")
    return value


def _identity(value: object, field: str) -> str:
    result = _text(value, field, 128)
    if not _IDENTITY_RE.fullmatch(result):
        raise ValidationError(f"{field} is malformed")
    return result


def _session_id(value: object) -> str:
    result = _text(value, "session_id", 128)
    if not _SESSION_RE.fullmatch(result):
        raise ValidationError("session_id is malformed")
    return result


def _timestamp(value: object, field: str) -> str:
    raw = _text(value, field, 64)
    try:
        parsed = datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValidationError(f"{field} must be an RFC 3339 timestamp") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValidationError(f"{field} must include a timezone")
    return parsed.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _instant(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(timezone.utc)


def _metadata(value: object) -> dict[str, str]:
    if value is None:
        return {}
    if not isinstance(value, Mapping) or len(value) > MAX_METADATA_ITEMS:
        raise ValidationError("metadata must be a bounded object")
    result: dict[str, str] = {}
    for key, item in value.items():
        key_text = _text(key, "metadata key", 64)
        if any(word in key_text.casefold() for word in _SECRET_WORDS):
            raise ValidationError("metadata key cannot name secret material")
        result[key_text] = _text(item, f"metadata[{key_text}]", MAX_METADATA_TEXT)
    return dict(sorted(result.items()))


def _public_key(value: object) -> str:
    pem = _text(value, "public_key_pem", MAX_PUBLIC_KEY_BYTES)
    if "PRIVATE KEY" in pem or "CERTIFICATE REQUEST" in pem:
        raise ValidationError("public_key_pem must not contain private or CSR material")
    match = re.fullmatch(
        r"-----BEGIN (?:PUBLIC KEY|RSA PUBLIC KEY|EC PUBLIC KEY)-----\n"
        r"([A-Za-z0-9+/=\n]+)"
        r"-----END (?:PUBLIC KEY|RSA PUBLIC KEY|EC PUBLIC KEY)-----\n?",
        pem,
    )
    if match is None:
        raise ValidationError("public_key_pem is not a supported PEM public key")
    try:
        decoded = base64.b64decode("".join(match.group(1).split()), validate=True)
    except (ValueError, binascii.Error) as exc:
        raise ValidationError("public_key_pem contains invalid base64") from exc
    if not 16 <= len(decoded) <= MAX_PUBLIC_KEY_BYTES:
        raise ValidationError("public_key_pem has invalid bounded key material")
    return pem


def public_key_identity(public_key_pem: str) -> str:
    return "sha256:" + hashlib.sha256(public_key_pem.encode("ascii")).hexdigest()


def _token(value: object) -> str:
    token = _text(value, "enrollment token", 128)
    if len(token) < 40 or not re.fullmatch(r"[A-Za-z0-9_-]+", token):
        raise ProtocolError("enrollment authorization is invalid")
    return token


def _token_digest(token: str) -> str:
    return "sha256:" + hashlib.sha256(token.encode("ascii")).hexdigest()


def _record_status(records: list[dict[str, Any]], authorization_id: str, now: str) -> str:
    created = next(
        (entry["record"] for entry in records
         if entry["record_type"] == "enrollment.authorization"
         and entry["record"].get("authorization_id") == authorization_id),
        None,
    )
    if created is None:
        raise ProtocolError("enrollment authorization is unknown")
    events = [
        entry["record"] for entry in records
        if entry["record"].get("authorization_id") == authorization_id
        and entry["record"].get("event") in {"consumed", "revoked", "expired"}
    ]
    event_names = {event["event"] for event in events}
    if "revoked" in event_names:
        return "REVOKED"
    if "expired" in event_names or _instant(now) >= _instant(created["expires_at"]):
        return "EXPIRED"
    return "CONSUMED" if "consumed" in event_names else "ACTIVE"


def _request_status(records: list[dict[str, Any]], request_id: str, now: str) -> str:
    request = next(
        (entry["record"] for entry in records
         if entry["record_type"] == "enrollment.request"
         and entry["record"].get("request_id") == request_id),
        None,
    )
    if request is None:
        raise ProtocolError("enrollment request is unknown")
    decisions = [
        entry["record"] for entry in records
        if entry["record_type"] == "enrollment.decision"
        and entry["record"].get("request_id") == request_id
    ]
    if decisions:
        return str(decisions[-1]["decision"])
    auth_state = _record_status(records, request["authorization_id"], now)
    return "EXPIRED" if auth_state in {"EXPIRED", "REVOKED"} else "PENDING"


def _latest_membership(records: list[dict[str, Any]], worker_id: str) -> dict[str, Any] | None:
    values = [
        entry["record"] for entry in records
        if entry["record_type"] in {"fleet.membership", "fleet.revocation"}
        and entry["record"].get("worker_id") == worker_id
    ]
    return values[-1] if values else None


def _redact_authorization(record: Mapping[str, Any], status: str) -> dict[str, Any]:
    return {
        "schema_version": AUTHORIZATION_SCHEMA,
        "authorization_id": record["authorization_id"],
        "issued_at": record["issued_at"],
        "expires_at": record["expires_at"],
        "expected_worker_identity": record.get("expected_worker_identity"),
        "metadata": dict(record.get("metadata", {})),
        "status": status,
    }


class LifecycleStore:
    """Controller-local durable lifecycle state backed by one append-only ledger."""

    def __init__(self, state_path: Path) -> None:
        self.path = Path(state_path).expanduser()
        self.ledger = FabricLedger(self.path)

    def _records(self) -> list[dict[str, Any]]:
        records = self.ledger.records(limit=100000)
        for entry in records:
            record = entry.get("record")
            if not isinstance(record, dict) or record.get("schema_version") not in _SUPPORTED_RECORD_SCHEMAS:
                raise StorageError("lifecycle ledger contains an unsupported record schema")
        return records

    def create_authorization(
        self,
        *,
        ttl_seconds: float = 600.0,
        expected_worker_identity: str | None = None,
        metadata: Mapping[str, str] | None = None,
        issued_at: str | None = None,
    ) -> dict[str, Any]:
        if not 1 <= ttl_seconds <= MAX_TTL_SECONDS:
            raise ValidationError("authorization TTL is outside the bounded range")
        issued = _timestamp(issued_at or utc_now(), "issued_at")
        expires = (_instant(issued) + timedelta(seconds=ttl_seconds)).isoformat().replace("+00:00", "Z")
        if expected_worker_identity is not None:
            expected_worker_identity = _identity(expected_worker_identity, "expected_worker_identity")
        token = secrets.token_urlsafe(32)
        record = attach_identity({
            "schema_version": AUTHORIZATION_SCHEMA,
            "issued_at": issued,
            "expires_at": expires,
            "token_digest": _token_digest(token),
            "expected_worker_identity": expected_worker_identity,
            "metadata": _metadata(metadata),
            "event": "created",
        }, "authorization_id")
        self.ledger.append("enrollment.authorization", record)
        return {**_redact_authorization(record, "ACTIVE"), "token": token}

    def authorization(self, authorization_id: str, *, now: str | None = None) -> dict[str, Any]:
        _text(authorization_id, "authorization_id", 80)
        records = self._records()
        created = next(
            (entry["record"] for entry in records
             if entry["record_type"] == "enrollment.authorization"
             and entry["record"].get("authorization_id") == authorization_id),
            None,
        )
        if created is None:
            raise ProtocolError("enrollment authorization is unknown")
        return _redact_authorization(created, _record_status(records, authorization_id, _timestamp(now or utc_now(), "now")))

    def list_authorizations(self, *, now: str | None = None) -> list[dict[str, Any]]:
        current = _timestamp(now or utc_now(), "now")
        records = self._records()
        values = [entry["record"] for entry in records if entry["record_type"] == "enrollment.authorization"]
        return [_redact_authorization(value, _record_status(records, value["authorization_id"], current)) for value in values]

    def revoke_authorization(self, authorization_id: str, *, reason: str, now: str | None = None) -> dict[str, Any]:
        reason = _text(reason, "reason", 512)
        current = self.authorization(authorization_id, now=now)
        if current["status"] != "ACTIVE":
            raise ProtocolError(f"authorization is {current['status'].lower()}")
        event = attach_identity({
            "schema_version": AUTHORIZATION_SCHEMA,
            "authorization_id": authorization_id,
            "event": "revoked",
            "revoked_at": _timestamp(now or utc_now(), "revoked_at"),
            "reason": reason,
        }, "event_identity")
        self.ledger.append("enrollment.authorization-revoked", event)
        return self.authorization(authorization_id, now=now)

    def _consume_locked(self, records: list[dict[str, Any]], authorization_id: str, worker_id: str, now: str) -> None:
        state = _record_status(records, authorization_id, now)
        if state != "ACTIVE":
            raise ProtocolError(f"enrollment authorization is {state.lower()}")
        created = next(entry["record"] for entry in records if entry["record"].get("authorization_id") == authorization_id and entry["record"].get("event") == "created")
        expected = created.get("expected_worker_identity")
        if expected is not None and expected != worker_id:
            raise ProtocolError("enrollment authorization does not match worker identity")

    def consume_authorization(self, token: str, *, worker_identity: str, now: str | None = None) -> dict[str, Any]:
        worker_identity = _identity(worker_identity, "worker_identity")
        token = _token(token)
        current = _timestamp(now or utc_now(), "now")
        records = self._records()
        created = next((entry["record"] for entry in records if entry["record_type"] == "enrollment.authorization" and entry["record"].get("token_digest") == _token_digest(token)), None)
        if created is None:
            raise ProtocolError("enrollment authorization is invalid")
        authorization_id = created["authorization_id"]
        event = attach_identity({
            "schema_version": AUTHORIZATION_SCHEMA,
            "authorization_id": authorization_id,
            "worker_identity": worker_identity,
            "consumed_at": current,
            "event": "consumed",
        }, "event_identity")
        self.ledger.append_if(
            "enrollment.authorization-consumed",
            event,
            lambda current_records: self._consume_locked(current_records, authorization_id, worker_identity, current),
        )
        return self.authorization(authorization_id, now=current)

    @staticmethod
    def build_request(
        *,
        worker_identity: str,
        public_key_pem: str,
        hostname_hint: str,
        operating_system: str,
        architecture: str,
        authorization_id: str,
        requested_at: str | None = None,
        metadata: Mapping[str, str] | None = None,
    ) -> dict[str, Any]:
        value = {
            "schema_version": REQUEST_SCHEMA,
            "worker_identity": _identity(worker_identity, "worker_identity"),
            "public_key_pem": _public_key(public_key_pem),
            "public_key_identity": public_key_identity(public_key_pem),
            "hostname_hint": _text(hostname_hint, "hostname_hint", 255),
            "operating_system": _text(operating_system, "operating_system", 64),
            "architecture": _text(architecture, "architecture", 64),
            "requested_at": _timestamp(requested_at or utc_now(), "requested_at"),
            "authorization_id": _text(authorization_id, "authorization_id", 80),
            "metadata": _metadata(metadata),
        }
        return attach_identity(value, "request_id")

    def submit_request(self, request: Mapping[str, Any], token: str, *, now: str | None = None) -> dict[str, Any]:
        if not isinstance(request, Mapping):
            raise ValidationError("enrollment request must be an object")
        expected = {"schema_version", "worker_identity", "public_key_pem", "public_key_identity", "hostname_hint", "operating_system", "architecture", "requested_at", "authorization_id", "metadata", "request_id"}
        if set(request) != expected or request.get("schema_version") != REQUEST_SCHEMA:
            raise ValidationError("enrollment request fields or schema are invalid")
        checked = self.build_request(
            worker_identity=request["worker_identity"], public_key_pem=request["public_key_pem"],
            hostname_hint=request["hostname_hint"], operating_system=request["operating_system"],
            architecture=request["architecture"], authorization_id=request["authorization_id"],
            requested_at=request["requested_at"], metadata=request["metadata"],
        )
        if checked != dict(request) or request.get("request_id") != checked["request_id"]:
            raise ValidationError("enrollment request identity or fields do not verify")
        current = _timestamp(now or utc_now(), "now")
        authorization_id = checked["authorization_id"]
        worker_id = checked["worker_identity"]
        consumption = attach_identity({
            "schema_version": AUTHORIZATION_SCHEMA,
            "authorization_id": authorization_id,
            "worker_identity": worker_id,
            "consumed_at": current,
            "request_id": checked["request_id"],
            "event": "consumed",
        }, "event_identity")

        def precondition(records: list[dict[str, Any]]) -> None:
            existing = [entry["record"] for entry in records if entry["record_type"] == "enrollment.request" and entry["record"].get("request_id") == checked["request_id"]]
            if existing:
                raise ProtocolError("duplicate enrollment request")
            current_membership = _latest_membership(records, worker_id)
            conflicting = [
                entry["record"] for entry in records
                if entry["record_type"] == "enrollment.request"
                and entry["record"].get("worker_identity") == worker_id
                and (
                    _request_status(records, entry["record"]["request_id"], current) == "PENDING"
                    or (
                        _request_status(records, entry["record"]["request_id"], current) == "APPROVED"
                        and current_membership is not None
                        and current_membership.get("membership_status") == "ENROLLED"
                    )
                )
            ]
            if conflicting and any(item["public_key_identity"] != checked["public_key_identity"] for item in conflicting):
                raise ProtocolError("worker identity already has conflicting enrollment material")
            self._consume_locked(records, authorization_id, worker_id, current)

        self.ledger.append_many_if([
            ("enrollment.authorization-consumed", consumption),
            ("enrollment.request", checked),
        ], precondition)
        return self.public_request(checked, "PENDING")

    @staticmethod
    def public_request(request: Mapping[str, Any], status: str) -> dict[str, Any]:
        return {**dict(request), "status": status}

    def request(self, request_id: str, *, now: str | None = None) -> dict[str, Any]:
        records = self._records()
        value = next((entry["record"] for entry in records if entry["record_type"] == "enrollment.request" and entry["record"].get("request_id") == request_id), None)
        if value is None:
            raise ProtocolError("enrollment request is unknown")
        return self.public_request(value, _request_status(records, request_id, _timestamp(now or utc_now(), "now")))

    def pending_requests(self, *, now: str | None = None) -> list[dict[str, Any]]:
        current = _timestamp(now or utc_now(), "now")
        records = self._records()
        return [self.public_request(entry["record"], _request_status(records, entry["record"]["request_id"], current)) for entry in records if entry["record_type"] == "enrollment.request" and _request_status(records, entry["record"]["request_id"], current) == "PENDING"]

    def _decision(self, request_id: str, decision: str, *, worker_id: str | None = None, reason: str | None = None, now: str | None = None) -> dict[str, Any]:
        if decision not in DECISIONS:
            raise ValidationError("enrollment decision is invalid")
        current = _timestamp(now or utc_now(), "decided_at")
        records = self._records()
        request = next((entry["record"] for entry in records if entry["record_type"] == "enrollment.request" and entry["record"].get("request_id") == request_id), None)
        if request is None:
            raise ProtocolError("enrollment request is unknown")
        status = _request_status(records, request_id, current)
        if decision != "EXPIRED" and status != "PENDING":
            raise ProtocolError(f"enrollment request is already {status.lower()}")
        if decision == "EXPIRED" and status != "EXPIRED":
            raise ProtocolError("enrollment request has not expired")
        chosen_worker = _identity(worker_id or request["worker_identity"], "worker_id")
        if decision == "APPROVED":
            membership = _latest_membership(records, chosen_worker)
            if membership and membership.get("membership_status") in {"ENROLLED"}:
                if membership.get("public_key_identity") != request["public_key_identity"]:
                    raise ProtocolError("active worker identity cannot be rebound to new key material")
                raise ProtocolError("worker identity is already enrolled")
        if decision == "EXPIRED" and _record_status(records, request["authorization_id"], current) not in {"EXPIRED", "REVOKED"}:
            raise ProtocolError("enrollment authorization has not expired")
        decision_record = attach_identity({
            "schema_version": DECISION_SCHEMA,
            "request_id": request_id,
            "worker_id": chosen_worker,
            "decision": decision,
            "public_key_identity": request["public_key_identity"],
            "decided_at": current,
            "reason": _text(reason, "reason", 512) if reason is not None else None,
            "event": "decision",
        }, "decision_id")
        additions: list[tuple[str, dict[str, Any]]] = [("enrollment.decision", decision_record)]
        if decision == "APPROVED":
            membership = attach_identity({
                "schema_version": MEMBERSHIP_SCHEMA,
                "worker_id": chosen_worker,
                "public_key_identity": request["public_key_identity"],
                "membership_status": "ENROLLED",
                "current_lifecycle": "ENROLLED",
                "enrollment_request_id": request_id,
                "decision_id": decision_record["decision_id"],
                "created_at": request["requested_at"],
                "approved_at": current,
                "operator_labels": dict(request.get("metadata", {})),
                "event": "enrolled",
            }, "membership_id")
            additions.append(("fleet.membership", membership))

        def precondition(latest: list[dict[str, Any]]) -> None:
            expected_status = "EXPIRED" if decision == "EXPIRED" else "PENDING"
            if _request_status(latest, request_id, current) != expected_status:
                raise ProtocolError("enrollment request decision changed concurrently")
            if decision == "APPROVED":
                existing = _latest_membership(latest, chosen_worker)
                if existing and existing.get("membership_status") == "ENROLLED" and existing.get("public_key_identity") != request["public_key_identity"]:
                    raise ProtocolError("active worker identity cannot be rebound to new key material")
            if _record_status(latest, request["authorization_id"], current) not in {"ACTIVE", "CONSUMED"} and decision == "APPROVED":
                raise ProtocolError("enrollment authorization is no longer active")

        self.ledger.append_many_if(additions, precondition)
        return decision_record

    def approve_request(self, request_id: str, *, worker_id: str | None = None, now: str | None = None) -> dict[str, Any]:
        return self._decision(request_id, "APPROVED", worker_id=worker_id, now=now)

    def deny_request(self, request_id: str, *, reason: str = "operator denied enrollment", now: str | None = None) -> dict[str, Any]:
        return self._decision(request_id, "DENIED", reason=reason, now=now)

    def expire_request(self, request_id: str, *, now: str | None = None) -> dict[str, Any]:
        return self._decision(request_id, "EXPIRED", reason="enrollment authorization expired", now=now)

    def revoke_worker(self, worker_id: str, *, reason: str, now: str | None = None) -> dict[str, Any]:
        worker_id = _identity(worker_id, "worker_id")
        reason = _text(reason, "reason", 512)
        records = self._records()
        current = _latest_membership(records, worker_id)
        if current is None:
            raise ProtocolError("worker membership is unknown")
        if current.get("membership_status") != "ENROLLED":
            raise ProtocolError(f"worker membership is {str(current.get('membership_status')).lower()}")
        record = attach_identity({
            "schema_version": MEMBERSHIP_SCHEMA,
            "worker_id": worker_id,
            "public_key_identity": current["public_key_identity"],
            "membership_status": "REVOKED",
            "current_lifecycle": "REVOKED",
            "revoked_at": _timestamp(now or utc_now(), "revoked_at"),
            "reason": reason,
            "event": "revoked",
        }, "membership_id")
        def precondition(latest: list[dict[str, Any]]) -> None:
            current_membership = _latest_membership(latest, worker_id)
            if current_membership is None or current_membership.get("membership_status") != "ENROLLED":
                raise ProtocolError("worker membership changed concurrently")

        self.ledger.append_if("fleet.revocation", record, precondition)
        return self.membership(worker_id, now=now)

    def membership(self, worker_id: str, *, now: str | None = None) -> dict[str, Any]:
        worker_id = _identity(worker_id, "worker_id")
        records = self._records()
        value = _latest_membership(records, worker_id)
        if value is None:
            raise ProtocolError("worker membership is unknown")
        return {**dict(value), **self.status(worker_id, now=now)}

    def memberships(self, *, now: str | None = None) -> list[dict[str, Any]]:
        records = self._records()
        workers = sorted({entry["record"].get("worker_id") for entry in records if entry["record_type"] in {"fleet.membership", "fleet.revocation"} and isinstance(entry["record"].get("worker_id"), str)})
        return [self.membership(worker, now=now) for worker in workers]

    def authenticate_session(self, worker_id: str, *, public_key_identity_value: str, session_id: str, generation: int, now: str | None = None) -> dict[str, Any]:
        worker_id = _identity(worker_id, "worker_id")
        if not is_sha256_identity(public_key_identity_value):
            raise ProtocolError("session credential identity is malformed")
        session_id = _session_id(session_id)
        if not isinstance(generation, int) or generation < 1 or generation > 2**31:
            raise ValidationError("session generation is outside the bounded range")
        current_time = _timestamp(now or utc_now(), "authenticated_at")
        event = {
            "schema_version": PRESENCE_SCHEMA,
            "worker_id": worker_id,
            "public_key_identity": public_key_identity_value,
            "session_id": session_id,
            "generation": generation,
            "observed_at": current_time,
            "event": "authenticated",
        }
        def admit(records: list[dict[str, Any]]) -> None:
            # Membership, current-session selection, duplicate detection, and
            # the append must share one FabricLedger lock.  Reading current
            # presence before append would allow two controller threads to
            # both admit different sessions for the same logical identity.
            member = _latest_membership(records, worker_id)
            if member is None or member.get("membership_status") != "ENROLLED":
                raise ProtocolError("worker is not enrolled")
            if member.get("public_key_identity") != public_key_identity_value:
                raise ProtocolError("session credential does not match enrolled worker")
            current = self._current_session(records, worker_id)
            if current is None:
                event.update(attach_identity(event, "presence_event_id"))
                return
            if generation < current["generation"]:
                raise ProtocolError("session generation regressed")
            if current["session_id"] == session_id:
                event["event"] = "heartbeat" if generation == current["generation"] else "reconnected"
                event.update(attach_identity(event, "presence_event_id"))
                return
            age = (_instant(current_time) - _instant(current["observed_at"])).total_seconds()
            if generation > current["generation"] and age > SESSION_MAX_AGE_SECONDS:
                event["event"] = "reconnected"
                event["replaces_session_id"] = current["session_id"]
                event["replaces_generation"] = current["generation"]
                event.update(attach_identity(event, "presence_event_id"))
                return
            event["event"] = "duplicate-identity"
            event["conflicts_with_session_id"] = current["session_id"]
            event["conflicts_with_generation"] = current["generation"]
            event.update(attach_identity(event, "presence_event_id"))

        self.ledger.append_if("presence.session", event, admit)
        # The conflict evidence is intentionally retained in the same scoped
        # presence ledger record.  status() projects it to UNKNOWN rather than
        # allowing it to masquerade as current availability.
        return self.status(worker_id, now=current_time)

    def _current_session(self, records: list[dict[str, Any]], worker_id: str) -> dict[str, Any] | None:
        sessions = [entry["record"] for entry in records if entry["record_type"] in {"presence.session", "presence.session-ended", "presence.session-conflict"} and entry["record"].get("worker_id") == worker_id]
        active: dict[str, Any] | None = None
        for event in sessions:
            if event.get("event") in {"authenticated", "heartbeat", "reconnected"}:
                if active is None or (event["generation"], event["observed_at"]) >= (active["generation"], active["observed_at"]):
                    active = event
            elif event.get("event") == "ended" and active and event.get("session_id") == active["session_id"] and event.get("generation") == active["generation"]:
                active = None
        return active

    def disconnect_session(self, worker_id: str, *, session_id: str, generation: int, now: str | None = None) -> dict[str, Any]:
        worker_id = _identity(worker_id, "worker_id")
        session_id = _session_id(session_id)
        event = attach_identity({
            "schema_version": PRESENCE_SCHEMA,
            "worker_id": worker_id,
            "session_id": session_id,
            "generation": generation,
            "observed_at": _timestamp(now or utc_now(), "disconnected_at"),
            "event": "ended",
        }, "presence_event_id")
        def disconnect(records: list[dict[str, Any]]) -> None:
            current = self._current_session(records, worker_id)
            if current is None or current["session_id"] != session_id or current["generation"] != generation:
                raise ProtocolError("session is not current")

        self.ledger.append_if("presence.session-ended", event, disconnect)
        return self.status(worker_id, now=now)

    def status(self, worker_id: str, *, now: str | None = None, max_age_seconds: float = SESSION_MAX_AGE_SECONDS) -> dict[str, Any]:
        worker_id = _identity(worker_id, "worker_id")
        if not 0 < max_age_seconds <= MAX_TTL_SECONDS:
            raise ValidationError("session freshness bound is invalid")
        current_time = _timestamp(now or utc_now(), "now")
        records = self._records()
        member = _latest_membership(records, worker_id)
        if member is None:
            raise ProtocolError("worker membership is unknown")
        session = self._current_session(records, worker_id)
        conflict = next((entry["record"] for entry in reversed(records) if entry["record"].get("worker_id") == worker_id and entry["record"].get("event") == "duplicate-identity"), None)
        conflict_after_session = bool(conflict and (session is None or conflict.get("observed_at", "") >= session.get("observed_at", "")))
        age = None if session is None else (_instant(current_time) - _instant(session["observed_at"])).total_seconds()
        fresh = session is not None and 0 <= age <= max_age_seconds
        if member.get("membership_status") != "ENROLLED":
            presence, availability = "REVOKED", "UNAVAILABLE"
        elif conflict_after_session:
            presence, availability = "DUPLICATE_IDENTITY", "UNKNOWN"
        elif session is None:
            presence, availability = "ABSENT", "UNAVAILABLE"
        elif fresh:
            presence, availability = "PRESENT", "AVAILABLE"
        else:
            presence, availability = "STALE", "UNKNOWN"
        return {
            "schema_version": PRESENCE_SCHEMA,
            "worker_id": worker_id,
            "membership_status": member.get("membership_status"),
            "current_lifecycle": member.get("current_lifecycle"),
            "presence": presence,
            "availability": availability,
            "authenticated": bool(session is not None and member.get("membership_status") == "ENROLLED"),
            "session_id": session.get("session_id") if session else None,
            "session_generation": session.get("generation") if session else None,
            "last_authenticated_at": session.get("observed_at") if session else None,
            "session_age_seconds": age,
            "session_fresh": fresh,
            "capability_freshness": "UNKNOWN",
            "resource_freshness": "UNKNOWN",
            "claim_boundary": "membership, authenticated presence, liveness, capability freshness, and resource freshness are separate claims",
        }

    def doctor(self, *, now: str | None = None) -> dict[str, Any]:
        verification = self.ledger.verify()
        try:
            workers = self.memberships(now=now)
        except (ProtocolError, StorageError) as exc:
            return {"outcome": "UNKNOWN", "ledger": verification, "error": str(exc)}
        return {"outcome": verification["outcome"], "ledger": verification, "worker_count": len(workers), "workers": workers}
