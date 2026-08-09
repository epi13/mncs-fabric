"""Locally executable worker service over the versioned protocol."""

from __future__ import annotations

from datetime import timedelta
from pathlib import Path
from typing import Any

from .canonical import sha256_identity
from .challenges import validate_execution_challenge
from .errors import ProtocolError, StorageError
from .executor import execute_local
from .node import capability_names, collect_node_capabilities, utc_now
from .protocol import dispatch_binding_identity, make_envelope, validate_envelope
from .store import FabricLedger
from .receipts import build_execution_receipt


class LocalWorker:
    """A worker callable in-process; no unauthenticated listener is created."""

    def __init__(self, worker_id: str, bundle_root: Path, state_path: Path, *, concurrency_limit: int = 1) -> None:
        if not worker_id or concurrency_limit < 1:
            raise ValueError("worker_id and a positive concurrency limit are required")
        self.worker_id = worker_id
        self.bundle_root = Path(bundle_root)
        self.ledger = FabricLedger(Path(state_path))
        self.concurrency_limit = concurrency_limit

    def node(self) -> dict[str, Any]:
        return collect_node_capabilities(self.worker_id)

    def capabilities(self) -> frozenset[str]:
        return frozenset(capability_names(self.node()))

    def announcement(self, controller_id: str) -> dict[str, Any]:
        created = utc_now()
        expires = (self._parse_time(created) + timedelta(minutes=5)).isoformat().replace("+00:00", "Z")
        node = self.node()
        return make_envelope("worker.announce", controller_id=controller_id, worker_id=self.worker_id, request_id="announce-" + self.worker_id, job_id="node-announcement", nonce="announce-" + sha256_identity(node)[7:23], payload={"node": node}, created_at=created, expires_at=expires)

    @staticmethod
    def _parse_time(value: str):
        from datetime import datetime, timezone
        return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(timezone.utc)

    def _entries(self, record_type: str) -> list[dict[str, Any]]:
        return self.ledger.records(record_type=record_type, limit=100000)

    def _prior_dispatch(self, request_id: str) -> tuple[dict[str, Any] | None, dict[str, Any] | None]:
        dispatches = [entry["record"] for entry in self._entries("protocol.dispatch") if entry["record"].get("request_id") == request_id]
        if not dispatches:
            return None, None
        dispatch = dispatches[-1]
        results = [entry["record"] for entry in self._entries("protocol.result") if entry["record"].get("request_id") == request_id]
        return dispatch, results[-1] if results else None

    def handle(self, envelope: object, *, now: str | None = None) -> dict[str, Any]:
        message = validate_envelope(envelope, now=now)
        if message["message_type"] != "dispatch.request":
            raise ProtocolError("worker accepts dispatch.request messages only")
        if message["worker_id"] != self.worker_id:
            raise ProtocolError("dispatch is bound to a different worker")
        request_id = message["request_id"]
        payload = message["payload"]
        challenge = payload.get("execution_challenge")
        if challenge is not None and not validate_execution_challenge(challenge).valid:
            raise ProtocolError("dispatch execution challenge is invalid")
        dispatch_binding = dispatch_binding_identity(message)
        prior, result = self._prior_dispatch(request_id)
        if prior is not None:
            # Records created before the stable binding field was introduced
            # cannot prove that a reconstructed retry is identical.  Treat
            # them as conflicting rather than weakening replay protection.
            if prior.get("dispatch_binding_identity") != dispatch_binding:
                return self._response(message, "replay.disposition", {"disposition": "CONFLICTING_REPLAY", "reason": "request_id was previously bound to a different dispatch"})
            if result is not None:
                duplicate_payload: dict[str, Any] = {"result_identity": result["record"]["record_id"], "record": result["record"], "disposition": "DUPLICATE_IDEMPOTENT"}
                if result.get("receipt") is not None:
                    duplicate_payload["receipt"] = result["receipt"]
                return self._response(message, "execution.result", duplicate_payload)
            return self._response(message, "dispatch.ack", {"disposition": "DUPLICATE_IN_PROGRESS", "dispatch_identity": dispatch_binding})
        self.ledger.append("protocol.dispatch", {"request_id": request_id, "dispatch_identity": message["message_id"], "dispatch_binding_identity": dispatch_binding, "worker_id": self.worker_id, "job_identity": payload["job_plan"]["job_identity"]})
        try:
            record = execute_local(payload["job_plan"], self.bundle_root, payload["artifact_manifest"], self.worker_id)
        except Exception as exc:
            raise StorageError(f"worker execution failed before a record was published: {exc}") from exc
        receipt = build_execution_receipt(record, runner_identity=f"mncs-fabric-worker-{self.worker_id}", runner_version="0.2.0a0", challenge=challenge) if challenge is not None else None
        result_record = {"request_id": request_id, "dispatch_identity": message["message_id"], "dispatch_binding_identity": dispatch_binding, "record": record, "receipt": receipt}
        self.ledger.append("protocol.result", result_record)
        response_payload: dict[str, Any] = {"result_identity": record["record_id"], "record": record, "disposition": "EXECUTED"}
        if receipt is not None:
            response_payload["receipt"] = receipt
        return self._response(message, "execution.result", response_payload)

    def _response(self, request: dict[str, Any], message_type: str, payload: dict[str, Any]) -> dict[str, Any]:
        created = utc_now()
        expires = (self._parse_time(created) + timedelta(minutes=5)).isoformat().replace("+00:00", "Z")
        return make_envelope(message_type, controller_id=request["controller_id"], worker_id=self.worker_id, request_id=request["request_id"], job_id=request["job_id"], nonce=request["nonce"], payload=payload, created_at=created, expires_at=expires)
