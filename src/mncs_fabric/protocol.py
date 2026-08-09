"""Versioned, canonical controller/worker messages.

The protocol is transport-independent. It carries declared argv job plans and
identities; it never carries an instruction to invoke a shell or an arbitrary
remote command.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from .auth import Keyring
from .canonical import is_sha256_identity, sha256_identity, verify_identity
from .errors import ProtocolError
from .models import validate_job_plan

PROTOCOL_VERSION = "mncs-fabric.protocol.v0.1"
MESSAGE_TYPES = {
    "worker.announce",
    "worker.capabilities",
    "dispatch.request",
    "dispatch.ack",
    "execution.result",
    "status.request",
    "status.response",
    "result.collect",
    "replay.disposition",
}
_ID_FIELDS = ("controller_id", "worker_id", "request_id", "job_id", "nonce")


def _timestamp(value: str) -> datetime:
    if not isinstance(value, str):
        raise ProtocolError("message timestamps must be RFC 3339 values")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ProtocolError("message timestamps must be RFC 3339 values") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ProtocolError("message timestamps must include a UTC offset")
    return parsed.astimezone(timezone.utc)


def _require_text(value: object, field: str, *, maximum: int = 256) -> str:
    if not isinstance(value, str) or not value or len(value) > maximum or "\x00" in value:
        raise ProtocolError(f"{field} must be a bounded non-empty string")
    return value


def _auth_payload(envelope: dict[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in envelope.items() if key != "authentication"}


def _validate_payload(message_type: str, payload: object) -> dict[str, Any]:
    if not isinstance(payload, dict):
        raise ProtocolError("message payload must be an object")
    value = dict(payload)
    if message_type == "dispatch.request":
        try:
            plan = validate_job_plan(value.get("job_plan"))
        except Exception as exc:
            raise ProtocolError(f"dispatch job plan is invalid: {exc}") from exc
        manifest = value.get("artifact_manifest")
        if not isinstance(manifest, dict) or not is_sha256_identity(manifest.get("manifest_identity")):
            raise ProtocolError("dispatch must include a self-identifying artifact manifest")
        if plan["artifact_manifest_identity"] != manifest["manifest_identity"]:
            raise ProtocolError("dispatch plan and manifest identities differ")
        if value.get("request_identity") != sha256_identity({"job_plan": plan, "artifact_manifest": manifest}):
            raise ProtocolError("dispatch request identity does not match its payload")
    elif message_type == "execution.result":
        record = value.get("record")
        if not isinstance(record, dict) or not is_sha256_identity(record.get("record_id")) or not verify_identity(record, "record_id"):
            raise ProtocolError("execution result must contain a self-identifying Fabric record")
        if value.get("result_identity") != record["record_id"]:
            raise ProtocolError("execution result identity does not match its record")
    elif message_type in {"status.request", "result.collect"}:
        if not is_sha256_identity(value.get("job_identity")):
            raise ProtocolError("status and collection requests require a job identity")
    elif message_type == "status.response":
        _require_text(value.get("disposition"), "status disposition")
    elif message_type == "dispatch.ack":
        _require_text(value.get("disposition"), "dispatch disposition")
    elif message_type == "replay.disposition":
        _require_text(value.get("disposition"), "replay disposition")
    elif message_type == "worker.announce":
        if not isinstance(value.get("node"), dict):
            raise ProtocolError("worker announcement requires a node record")
    elif message_type == "worker.capabilities":
        if not isinstance(value.get("capabilities"), list) or not all(isinstance(item, str) for item in value["capabilities"]):
            raise ProtocolError("capability report must contain a string array")
    return value


def make_envelope(
    message_type: str,
    *,
    controller_id: str,
    worker_id: str,
    request_id: str,
    job_id: str,
    nonce: str,
    payload: dict[str, Any],
    created_at: str,
    expires_at: str,
    keyring: Keyring | None = None,
    key_id: str | None = None,
) -> dict[str, Any]:
    if message_type not in MESSAGE_TYPES:
        raise ProtocolError(f"unsupported protocol message type: {message_type}")
    for field, value in (("controller_id", controller_id), ("worker_id", worker_id), ("request_id", request_id), ("job_id", job_id), ("nonce", nonce)):
        _require_text(value, field)
    if len(nonce) < 16:
        raise ProtocolError("message nonce must contain at least 16 characters")
    created = _timestamp(created_at)
    expires = _timestamp(expires_at)
    if expires <= created:
        raise ProtocolError("message expiry must be later than creation")
    checked_payload = _validate_payload(message_type, payload)
    envelope: dict[str, Any] = {
        "protocol_version": PROTOCOL_VERSION,
        "message_type": message_type,
        "message_id": None,
        "controller_id": controller_id,
        "worker_id": worker_id,
        "request_id": request_id,
        "job_id": job_id,
        "nonce": nonce,
        "created_at": created_at,
        "expires_at": expires_at,
        "payload": checked_payload,
    }
    envelope["message_id"] = sha256_identity({key: value for key, value in envelope.items() if key != "message_id"})
    if keyring is not None:
        if key_id is None:
            raise ProtocolError("key_id is required when signing a message")
        envelope["authentication"] = {"algorithm": "HMAC-SHA256", "key_id": key_id, "mac": keyring.sign(key_id, _auth_payload(envelope))}
    elif key_id is not None:
        raise ProtocolError("key_id cannot be supplied without a keyring")
    return envelope


def validate_envelope(
    envelope: object,
    *,
    now: str | None = None,
    keyring: Keyring | None = None,
    require_authentication: bool = False,
) -> dict[str, Any]:
    if not isinstance(envelope, dict):
        raise ProtocolError("protocol envelope must be an object")
    value = dict(envelope)
    if value.get("protocol_version") != PROTOCOL_VERSION:
        raise ProtocolError("unsupported protocol version")
    message_type = value.get("message_type")
    if message_type not in MESSAGE_TYPES:
        raise ProtocolError("unsupported protocol message type")
    for field in _ID_FIELDS:
        _require_text(value.get(field), field)
    created = _timestamp(value.get("created_at"))
    expires = _timestamp(value.get("expires_at"))
    if expires <= created:
        raise ProtocolError("message expiry must be later than creation")
    if now is not None and _timestamp(now) > expires:
        raise ProtocolError("stale protocol message")
    payload = _validate_payload(message_type, value.get("payload"))
    expected_id = sha256_identity({key: item for key, item in value.items() if key not in {"message_id", "authentication"}})
    if value.get("message_id") != expected_id:
        raise ProtocolError("message identity does not match its canonical envelope")
    authentication = value.get("authentication")
    if require_authentication and keyring is None:
        raise ProtocolError("authenticated verification requires a keyring")
    if authentication is not None:
        if keyring is None or not isinstance(authentication, dict) or authentication.get("algorithm") != "HMAC-SHA256":
            raise ProtocolError("message authentication is unsupported")
        keyring.verify(authentication.get("key_id"), _auth_payload(value), authentication.get("mac"))
    elif require_authentication:
        raise ProtocolError("unsigned protocol message rejected")
    value["payload"] = payload
    return value
