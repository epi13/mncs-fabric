"""In-process controller facade for safe Phase-1 protocol development."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path
import threading
from typing import Any

from .canonical import sha256_identity
from .challenges import bind_challenge_to_receipt
from .errors import ProtocolError
from .models import validate_job_plan
from .node import utc_now
from .protocol import dispatch_request_identity, make_envelope, validate_envelope
from .scheduler import WorkerSlot, schedule
from .store import FabricLedger
from .transport import EnvelopeTransport, InProcessTransport
from .worker import LocalWorker


class LocalController:
    """Controller using explicit in-process worker calls, suitable for tests and Forge."""

    def __init__(self, controller_id: str, state_path: Path) -> None:
        self.controller_id = controller_id
        self.ledger = FabricLedger(Path(state_path))
        self.workers: dict[str, LocalWorker] = {}

    def register(self, worker: LocalWorker) -> dict[str, Any]:
        if worker.worker_id in self.workers:
            raise ProtocolError(f"worker is already registered: {worker.worker_id}")
        self.workers[worker.worker_id] = worker
        announcement = worker.announcement(self.controller_id)
        validate_envelope(announcement)
        self.ledger.append("protocol.announcement", announcement)
        return announcement

    def inspect(self) -> list[dict[str, Any]]:
        result = []
        for worker_id in sorted(self.workers):
            worker = self.workers[worker_id]
            result.append({"worker_id": worker_id, "capabilities": sorted(worker.capabilities()), "concurrency_limit": worker.concurrency_limit, "available": True})
        return result

    def dispatch(self, plan: object, manifest: object, *, replicas: int = 1, request_id: str | None = None, consumer_context: dict[str, Any] | None = None, execution_bundle: dict[str, str] | None = None) -> list[dict[str, Any]]:
        checked = validate_job_plan(plan)
        if not isinstance(manifest, dict) or manifest.get("manifest_identity") != checked["artifact_manifest_identity"]:
            raise ProtocolError("controller dispatch requires a matching manifest")
        decision = schedule(checked, [WorkerSlot(worker_id=worker_id, capabilities=worker.capabilities()) for worker_id, worker in self.workers.items()], replicas=replicas)
        if decision.disposition != "PASS":
            return [{"disposition": decision.disposition, "reason": decision.reason, "worker_ids": list(decision.worker_ids)}]
        outputs = []
        for worker_id in decision.worker_ids:
            response = self.dispatch_via(
                InProcessTransport(self.workers[worker_id]), checked, manifest,
                worker_id=worker_id,
                request_id=request_id or sha256_identity({"job_identity": checked["job_identity"], "worker_id": worker_id, "replica": len(outputs)}),
                consumer_context=consumer_context, execution_bundle=execution_bundle,
            )
            outputs.append(response)
        return outputs

    def dispatch_via(self, transport: EnvelopeTransport, plan: object, manifest: object, *, worker_id: str, request_id: str, challenge: dict[str, Any] | None = None, consumer_context: dict[str, Any] | None = None, execution_bundle: dict[str, str] | None = None) -> dict[str, Any]:
        """Dispatch through a transport without moving protocol semantics into it."""
        checked = validate_job_plan(plan)
        if not isinstance(manifest, dict) or manifest.get("manifest_identity") != checked["artifact_manifest_identity"]:
            raise ProtocolError("controller dispatch requires a matching manifest")
        created = utc_now()
        expires = (datetime.fromisoformat(created.replace("Z", "+00:00")).astimezone(timezone.utc) + timedelta(minutes=5)).isoformat().replace("+00:00", "Z")
        payload = {"job_plan": checked, "artifact_manifest": manifest, "request_identity": dispatch_request_identity(plan=checked, manifest=manifest, challenge=challenge, consumer_context=consumer_context, execution_bundle=execution_bundle)}
        if challenge is not None:
            payload["execution_challenge"] = challenge
        if consumer_context is not None:
            payload["consumer_context"] = consumer_context
        if execution_bundle is not None:
            payload["execution_bundle"] = execution_bundle
        envelope = make_envelope("dispatch.request", controller_id=self.controller_id, worker_id=worker_id, request_id=request_id, job_id=checked["job_id"], nonce="dispatch-" + sha256_identity({"request": request_id, "worker": worker_id})[7:55], payload=payload, created_at=created, expires_at=expires)
        self.ledger.append("protocol.controller-dispatch", envelope)
        response = transport.request(envelope)
        if response.get("message_type") == "execution.result":
            return self.verify_response(response, worker_id=worker_id, job_identity=checked["job_identity"], candidate_identity=checked["candidate_identity"], artifact_manifest_identity=checked["artifact_manifest_identity"], challenge=challenge)
        return validate_envelope(response)

    def verify_response(self, response: object, *, worker_id: str, job_identity: str, candidate_identity: str | None = None, artifact_manifest_identity: str | None = None, challenge: dict[str, Any] | None = None) -> dict[str, Any]:
        value = validate_envelope(response)
        record = value["payload"].get("record", {})
        if value["worker_id"] != worker_id or record.get("job_identity") != job_identity or (candidate_identity is not None and record.get("candidate_identity") != candidate_identity) or (artifact_manifest_identity is not None and record.get("artifact_manifest_identity") != artifact_manifest_identity):
            raise ProtocolError("controller response identity binding does not match the dispatch")
        if challenge is not None:
            receipt = value["payload"].get("receipt")
            if not isinstance(receipt, dict) or not bind_challenge_to_receipt(challenge, receipt).valid:
                raise ProtocolError("controller response receipt does not bind to its execution challenge")
        return value


class NetworkController(LocalController):
    """Controller facade for registered remote transports.

    Worker capability reports are operator-supplied observations.  This class
    does not turn connectivity or a successful command into assurance.
    """

    def __init__(self, controller_id: str, state_path: Path) -> None:
        super().__init__(controller_id, state_path)
        self.remote_workers: dict[str, tuple[EnvelopeTransport, WorkerSlot]] = {}
        self._remote_lock = threading.Lock()

    def register_remote(self, worker_id: str, capabilities: frozenset[str], transport: EnvelopeTransport, *, concurrency_limit: int = 1) -> None:
        if worker_id in self.remote_workers:
            raise ProtocolError(f"worker is already registered: {worker_id}")
        self.remote_workers[worker_id] = (transport, WorkerSlot(worker_id=worker_id, capabilities=capabilities, concurrency_limit=concurrency_limit))

    def dispatch_remote(self, plan: object, manifest: object, *, replicas: int = 1, request_id: str | None = None, challenge: dict[str, Any] | None = None, consumer_context: dict[str, Any] | None = None, execution_bundle: dict[str, str] | None = None) -> list[dict[str, Any]]:
        checked = validate_job_plan(plan)
        if not isinstance(manifest, dict) or manifest.get("manifest_identity") != checked["artifact_manifest_identity"]:
            raise ProtocolError("controller dispatch requires a matching manifest")
        with self._remote_lock:
            decision = schedule(checked, [slot for _, slot in self.remote_workers.values()], replicas=replicas)
            if decision.disposition == "PASS":
                for worker_id in decision.worker_ids:
                    transport, slot = self.remote_workers[worker_id]
                    self.remote_workers[worker_id] = (transport, WorkerSlot(worker_id=slot.worker_id, capabilities=slot.capabilities, active=slot.active + 1, concurrency_limit=slot.concurrency_limit, available=slot.available))
        if decision.disposition != "PASS":
            return [{"disposition": decision.disposition, "reason": decision.reason, "worker_ids": list(decision.worker_ids)}]
        outputs: list[dict[str, Any]] = []
        try:
            for worker_id in decision.worker_ids:
                transport, _ = self.remote_workers[worker_id]
                request = request_id or sha256_identity({"job_identity": checked["job_identity"], "worker_id": worker_id, "replica": len(outputs)})
                try:
                    outputs.append(self.dispatch_via(transport, checked, manifest, worker_id=worker_id, request_id=request, challenge=challenge, consumer_context=consumer_context, execution_bundle=execution_bundle))
                except (ProtocolError, OSError, TimeoutError) as exc:
                    outputs.append({"disposition": "UNKNOWN", "reason": "WORKER_UNAVAILABLE", "worker_id": worker_id, "diagnostic": str(exc)})
        finally:
            with self._remote_lock:
                for worker_id in decision.worker_ids:
                    transport, slot = self.remote_workers[worker_id]
                    self.remote_workers[worker_id] = (transport, WorkerSlot(worker_id=slot.worker_id, capabilities=slot.capabilities, active=max(0, slot.active - 1), concurrency_limit=slot.concurrency_limit, available=slot.available))
        return outputs

    def reconcile_dispatch(self, responses: list[dict[str, Any]], *, require_distinct_nodes: bool = True) -> dict[str, Any]:
        records = [response.get("payload", {}).get("record") for response in responses if response.get("message_type") == "execution.result" and isinstance(response.get("payload", {}).get("record"), dict)]
        if len(records) != len(responses):
            return {"outcome": "UNKNOWN", "reason": "one or more worker results are unavailable", "record_count": len(records), "response_count": len(responses)}
        return self._reconcile(records, require_distinct_nodes=require_distinct_nodes)

    def _reconcile(self, records: list[dict[str, Any]], *, require_distinct_nodes: bool) -> dict[str, Any]:
        from .reconcile import reconcile_records
        return reconcile_records(records, require_distinct_nodes=require_distinct_nodes)
