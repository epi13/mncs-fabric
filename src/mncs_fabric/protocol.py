"""Versioned, canonical controller/worker messages.

The protocol is transport-independent. It carries declared argv job plans and
identities; it never carries an instruction to invoke a shell or an arbitrary
remote command.
"""

from __future__ import annotations

import base64
from datetime import datetime, timezone
from typing import Any

from .auth import Keyring
from .challenges import validate_execution_challenge
from .canonical import is_sha256_identity, sha256_identity, verify_identity
from .contracts import validate_consumer_context
from .errors import ProtocolError, ValidationError
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
    "bundle.offer",
    "bundle.chunk",
    "bundle.commit",
    "bundle.response",
    "worker.describe.request",
    "worker.describe.result",
    "worker.inventory.request",
    "worker.inventory.result",
    "worker.maintenance.request",
    "worker.maintenance.result",
    "worker.certify.request",
    "worker.certify.result",
    "worker.package-artifact.request",
    "worker.package-artifact.result",
    "worker.management.request",
    "worker.management.result",
    "worker.session.open",
    "worker.session.accept",
    "worker.heartbeat",
    "worker.heartbeat.ack",
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


def dispatch_binding_identity(envelope: dict[str, Any]) -> str:
    """Return the stable identity of a dispatch's semantic request.

    ``message_id`` intentionally includes the envelope timestamps and nonce,
    so a freshly constructed retry has a different message identity.  Replay
    protection must distinguish that harmless reconstruction from a changed
    job, bundle, challenge, or authenticated peer binding.  This identity is
    therefore derived only from the fixed dispatch scope and payload.
    """

    return sha256_identity(
        {
            "protocol_version": envelope.get("protocol_version"),
            "message_type": envelope.get("message_type"),
            "controller_id": envelope.get("controller_id"),
            "worker_id": envelope.get("worker_id"),
            "request_id": envelope.get("request_id"),
            "job_id": envelope.get("job_id"),
            "payload": envelope.get("payload"),
        }
    )


def dispatch_request_identity(*, plan: dict[str, Any], manifest: dict[str, Any], challenge: object = None, consumer_context: object = None, execution_bundle: object = None, placement_request: object = None, runtime_observation: object = None, runtime_capability_observation: object = None) -> str:
    """Derive the stable semantic request identity used by controller and worker."""

    value: dict[str, Any] = {"job_plan": plan, "artifact_manifest": manifest}
    if challenge is not None:
        value["execution_challenge"] = challenge
    if consumer_context is not None:
        value["consumer_context"] = consumer_context
    if execution_bundle is not None:
        value["execution_bundle"] = execution_bundle
    if placement_request is not None:
        value["placement_request"] = placement_request
    if runtime_observation is not None:
        value["runtime_observation"] = runtime_observation
    if runtime_capability_observation is not None:
        value["runtime_capability_observation"] = runtime_capability_observation
    return sha256_identity(value)


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
        consumer_context = value.get("consumer_context")
        if consumer_context is not None:
            validate_consumer_context(consumer_context)
        execution_bundle = value.get("execution_bundle")
        if execution_bundle is not None:
            if set(execution_bundle) != {"bundle_identity", "archive_identity"} or not isinstance(execution_bundle.get("bundle_identity"), str) or len(execution_bundle["bundle_identity"]) != 64 or any(char not in "0123456789abcdef" for char in execution_bundle["bundle_identity"]) or not is_sha256_identity(execution_bundle.get("archive_identity")):
                raise ProtocolError("dispatch execution-bundle binding is invalid")
        placement_request = value.get("placement_request")
        if placement_request is not None:
            from .resources import validate_placement_request
            validate_placement_request(placement_request)
        runtime_observation = value.get("runtime_observation")
        if runtime_observation is not None:
            from .runtime import validate_runtime_observation
            validate_runtime_observation(runtime_observation)
        runtime_capability_observation = value.get("runtime_capability_observation")
        if runtime_capability_observation is not None:
            from .runtime import validate_runtime_capability_observation
            validate_runtime_capability_observation(runtime_capability_observation)
        if value.get("request_identity") != dispatch_request_identity(plan=plan, manifest=manifest, challenge=value.get("execution_challenge"), consumer_context=consumer_context, execution_bundle=execution_bundle, placement_request=placement_request, runtime_observation=runtime_observation, runtime_capability_observation=runtime_capability_observation):
            raise ProtocolError("dispatch request identity does not match its payload")
        if "execution_challenge" in value and not validate_execution_challenge(value["execution_challenge"]).valid:
            raise ProtocolError("dispatch execution challenge is invalid")
    elif message_type == "execution.result":
        record = value.get("record")
        if not isinstance(record, dict) or not is_sha256_identity(record.get("record_id")) or not verify_identity(record, "record_id"):
            raise ProtocolError("execution result must contain a self-identifying Fabric record")
        if value.get("result_identity") != record["record_id"]:
            raise ProtocolError("execution result identity does not match its record")
        if "receipt" in value:
            receipt = value["receipt"]
            if not isinstance(receipt, dict) or not isinstance(receipt.get("receipt_identity"), str) or len(receipt["receipt_identity"]) != 64 or any(char not in "0123456789abcdef" for char in receipt["receipt_identity"]):
                raise ProtocolError("execution result receipt identity is invalid")
        if "execution_bundle" in value:
            bundle = value["execution_bundle"]
            if not isinstance(bundle, dict) or set(bundle) != {"bundle_identity", "archive_identity"}:
                raise ProtocolError("execution result bundle binding is invalid")
            if not isinstance(bundle.get("bundle_identity"), str) or len(bundle["bundle_identity"]) != 64 or any(char not in "0123456789abcdef" for char in bundle["bundle_identity"]):
                raise ProtocolError("execution result logical bundle identity is invalid")
            if not is_sha256_identity(bundle.get("archive_identity")):
                raise ProtocolError("execution result archive identity is invalid")
        if "bundle_binding" in value:
            binding = value["bundle_binding"]
            if not isinstance(binding, dict) or not isinstance(binding.get("binding_identity"), str) or not verify_identity(binding, "binding_identity"):
                raise ProtocolError("execution result bundle binding identity is invalid")
        if "resource_snapshot" in value:
            from .resources import validate_resource_snapshot
            validate_resource_snapshot(value["resource_snapshot"])
        if "placement_admission" in value:
            from .resources import validate_admission
            validate_admission(value["placement_admission"])
        if "placement_observation" in value:
            from .resources import validate_placement_observation
            validate_placement_observation(value["placement_observation"])
        if "placement_binding" in value:
            from .resources import validate_placement_binding
            validate_placement_binding(value["placement_binding"])
        if "runtime_observation" in value:
            from .runtime import validate_runtime_observation
            validate_runtime_observation(value["runtime_observation"])
        if "runtime_binding" in value:
            from .runtime import validate_runtime_binding
            validate_runtime_binding(value["runtime_binding"])
        if "runtime_capability_observation" in value:
            from .runtime import validate_runtime_capability_observation
            validate_runtime_capability_observation(value["runtime_capability_observation"])
        if "runtime_capability_binding" in value:
            from .runtime import validate_runtime_capability_binding
            validate_runtime_capability_binding(value["runtime_capability_binding"])
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
        if "resource_snapshot" in value:
            from .resources import validate_resource_snapshot
            validate_resource_snapshot(value["resource_snapshot"])
    elif message_type == "worker.capabilities":
        if not isinstance(value.get("capabilities"), list) or not all(isinstance(item, str) for item in value["capabilities"]):
            raise ProtocolError("capability report must contain a string array")
    elif message_type in {"worker.session.open", "worker.heartbeat"}:
        required = {"protocol_version", "service_contract", "description"}
        if set(value) != required or value.get("protocol_version") != PROTOCOL_VERSION:
            raise ProtocolError("worker session request version or fields are invalid")
        if not isinstance(value.get("service_contract"), str) or not value["service_contract"]:
            raise ProtocolError("worker session service contract is invalid")
        from .worker_state import validate_worker_description
        validate_worker_description(value.get("description"))
    elif message_type == "worker.session.accept":
        required = {"session_id", "generation", "heartbeat_seconds", "controller_contract_identity"}
        if set(value) != required or not isinstance(value.get("session_id"), str) or not value["session_id"]:
            raise ProtocolError("worker session acceptance is invalid")
        if not isinstance(value.get("generation"), int) or value["generation"] < 1:
            raise ProtocolError("worker session generation is invalid")
        if not isinstance(value.get("heartbeat_seconds"), (int, float)) or not 0 < value["heartbeat_seconds"] <= 60:
            raise ProtocolError("worker heartbeat interval is invalid")
        if not is_sha256_identity(value.get("controller_contract_identity")):
            raise ProtocolError("worker controller contract identity is invalid")
    elif message_type == "worker.heartbeat.ack":
        required = {"session_id", "generation", "command"}
        if set(value) != required or not isinstance(value.get("session_id"), str) or not isinstance(value.get("generation"), int) or value["generation"] < 1:
            raise ProtocolError("worker heartbeat acknowledgement is invalid")
        if value.get("command") is not None:
            if not isinstance(value["command"], dict):
                raise ProtocolError("worker heartbeat command is invalid")
            validate_envelope(value["command"])
    elif message_type == "worker.describe.request":
        required = {"description_request_identity"}
        if set(value) != required or not is_sha256_identity(value.get("description_request_identity")):
            raise ProtocolError("worker description request identity is invalid")
    elif message_type == "worker.describe.result":
        from .worker_state import validate_worker_description
        required = {"description"}
        if set(value) != required:
            raise ProtocolError("worker description result fields are invalid")
        validate_worker_description(value.get("description"))
    elif message_type == "worker.inventory.request":
        required = {"inventory_request_identity"}
        if set(value) != required or not is_sha256_identity(value.get("inventory_request_identity")):
            raise ProtocolError("worker inventory request identity is invalid")
    elif message_type == "worker.inventory.result":
        from .inventory import validate_worker_inventory
        required = {"inventory"}
        if set(value) != required:
            raise ProtocolError("worker inventory result fields are invalid")
        validate_worker_inventory(value.get("inventory"))
    elif message_type == "worker.maintenance.request":
        from .providers import validate_action
        required = {"maintenance_request_identity", "mode", "actions", "force"}
        if set(value) != required or not is_sha256_identity(value.get("maintenance_request_identity")):
            raise ProtocolError("worker maintenance request identity is invalid")
        if value.get("mode") not in {"plan", "apply"}:
            raise ProtocolError("worker maintenance mode is invalid")
        if not isinstance(value.get("force"), bool):
            raise ProtocolError("worker maintenance force flag is invalid")
        actions = value.get("actions")
        if not isinstance(actions, list) or len(actions) > 64:
            raise ProtocolError("worker maintenance actions are invalid")
        try:
            [validate_action(item) for item in actions]
        except ValidationError as exc:
            raise ProtocolError(f"worker maintenance action is invalid: {exc}") from exc
    elif message_type == "worker.maintenance.result":
        required = {"results"}
        if set(value) != required or not isinstance(value.get("results"), list) or len(value["results"]) > 64:
            raise ProtocolError("worker maintenance result fields are invalid")
    elif message_type == "worker.certify.request":
        required = {"certify_request_identity", "profiles"}
        if set(value) != required or not is_sha256_identity(value.get("certify_request_identity")):
            raise ProtocolError("worker certify request identity is invalid")
        profiles = value.get("profiles")
        if not isinstance(profiles, list) or len(profiles) > 8 or any(not isinstance(item, str) or not item or len(item) > 64 for item in profiles):
            raise ProtocolError("worker certify profiles are invalid")
    elif message_type == "worker.certify.result":
        from .certify import validate_certification
        required = {"certification"}
        if set(value) != required:
            raise ProtocolError("worker certify result fields are invalid")
        validate_certification(value.get("certification"))
    elif message_type == "worker.package-artifact.request":
        from .package_artifact import MAX_ARTIFACT_BYTES, MAX_CHUNK_BYTES, validate_package_artifact
        required = {"artifact_request_identity", "mode"}
        if not required <= set(value) or not is_sha256_identity(value.get("artifact_request_identity")):
            raise ProtocolError("package artifact request identity is invalid")
        if value.get("mode") not in {"offer", "chunk", "commit"}:
            raise ProtocolError("package artifact mode is invalid")
        if value["mode"] == "offer":
            if "artifact" not in value:
                raise ProtocolError("package artifact offer is missing the descriptor")
            validate_package_artifact(value["artifact"])
            if not isinstance(value.get("total_bytes"), int) or not 1 <= value["total_bytes"] <= MAX_ARTIFACT_BYTES:
                raise ProtocolError("package artifact size is invalid")
        elif value["mode"] == "chunk":
            if not isinstance(value.get("sequence"), int) or value["sequence"] < 0 or not isinstance(value.get("data"), str):
                raise ProtocolError("package artifact chunk is invalid")
            try:
                decoded = base64.b64decode(value["data"], validate=True)
            except (ValueError, TypeError) as exc:
                raise ProtocolError("package artifact chunk is not canonical base64") from exc
            if not 0 < len(decoded) <= MAX_CHUNK_BYTES:
                raise ProtocolError("package artifact chunk exceeds its bound")
    elif message_type == "worker.package-artifact.result":
        required = {"disposition", "detail"}
        if not required <= set(value) or value.get("disposition") not in {"PASS", "FAIL"}:
            raise ProtocolError("package artifact result is invalid")
    elif message_type == "worker.management.request":
        required = {"management_request_identity", "command", "reason"}
        if set(value) != required or not is_sha256_identity(value.get("management_request_identity")):
            raise ProtocolError("worker management request identity is invalid")
        if value.get("command") not in {"drain", "resume", "quarantine", "status"}:
            raise ProtocolError("worker management command is invalid")
        _require_text(value.get("reason"), "management reason", maximum=512)
    elif message_type == "worker.management.result":
        from .management import validate_management_state
        required = {"state"}
        if set(value) != required:
            raise ProtocolError("worker management result fields are invalid")
        validate_management_state(value.get("state"))
    elif message_type in {"bundle.offer", "bundle.chunk", "bundle.commit"}:
        from .bundle_transfer import MAX_CHUNK_BYTES, MAX_CHUNKS, MAX_ARCHIVE_BYTES, TRANSFER_SCHEMA
        required = {"transfer_schema", "transfer_id", "bundle_identity", "archive_identity", "total_bytes", "chunk_bytes", "chunk_count"}
        if set(value) - (required | {"sequence", "data"}) or not required <= set(value) or value.get("transfer_schema") != TRANSFER_SCHEMA or not isinstance(value.get("transfer_id"), str) or not is_sha256_identity(value.get("archive_identity")) or not (isinstance(value.get("bundle_identity"), str) and len(value["bundle_identity"]) == 64 and all(char in "0123456789abcdef" for char in value["bundle_identity"])):
            raise ProtocolError("bundle transfer identity or schema is invalid")
        if not all(isinstance(value.get(name), int) and not isinstance(value.get(name), bool) for name in ("total_bytes", "chunk_bytes", "chunk_count")) or not 1 <= value["total_bytes"] <= MAX_ARCHIVE_BYTES or not 1 <= value["chunk_bytes"] <= MAX_CHUNK_BYTES or not 1 <= value["chunk_count"] <= MAX_CHUNKS or value["chunk_count"] != (value["total_bytes"] + value["chunk_bytes"] - 1) // value["chunk_bytes"]:
            raise ProtocolError("bundle transfer bounds are invalid")
        if message_type == "bundle.chunk":
            if not isinstance(value.get("sequence"), int) or value["sequence"] < 0 or not isinstance(value.get("data"), str):
                raise ProtocolError("bundle chunk sequence or data is invalid")
            try:
                decoded = base64.b64decode(value["data"], validate=True)
            except (ValueError, TypeError) as exc:
                raise ProtocolError("bundle chunk data is not canonical base64") from exc
            if not 0 < len(decoded) <= MAX_CHUNK_BYTES:
                raise ProtocolError("bundle chunk exceeds its bound")
        elif "sequence" in value or "data" in value:
            raise ProtocolError("bundle offer/commit cannot carry chunk data")
    elif message_type == "bundle.response":
        if value.get("transfer_schema") != "mncs-fabric.bundle-transfer.v0.1" or not isinstance(value.get("transfer_id"), str) or value.get("status") not in {"ALREADY_PRESENT", "TRANSFER_REQUIRED", "ACCEPTED", "COMMITTED", "FAIL", "UNKNOWN"}:
            raise ProtocolError("bundle response is invalid")
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
