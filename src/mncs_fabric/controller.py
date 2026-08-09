"""In-process controller facade for safe Phase-1 protocol development."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from .canonical import sha256_identity
from .errors import ProtocolError
from .models import validate_job_plan
from .node import utc_now
from .protocol import make_envelope, validate_envelope
from .scheduler import WorkerSlot, schedule
from .store import FabricLedger
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

    def dispatch(self, plan: object, manifest: object, *, replicas: int = 1, request_id: str | None = None) -> list[dict[str, Any]]:
        checked = validate_job_plan(plan)
        if not isinstance(manifest, dict) or manifest.get("manifest_identity") != checked["artifact_manifest_identity"]:
            raise ProtocolError("controller dispatch requires a matching manifest")
        decision = schedule(checked, [WorkerSlot(worker_id=worker_id, capabilities=worker.capabilities()) for worker_id, worker in self.workers.items()], replicas=replicas)
        if decision.disposition != "PASS":
            return [{"disposition": decision.disposition, "reason": decision.reason, "worker_ids": list(decision.worker_ids)}]
        outputs = []
        for worker_id in decision.worker_ids:
            request = request_id or sha256_identity({"job_identity": checked["job_identity"], "worker_id": worker_id, "replica": len(outputs)})
            created = utc_now()
            expires = (datetime.fromisoformat(created.replace("Z", "+00:00")).astimezone(timezone.utc) + timedelta(minutes=5)).isoformat().replace("+00:00", "Z")
            payload = {"job_plan": checked, "artifact_manifest": manifest, "request_identity": sha256_identity({"job_plan": checked, "artifact_manifest": manifest})}
            envelope = make_envelope("dispatch.request", controller_id=self.controller_id, worker_id=worker_id, request_id=request, job_id=checked["job_id"], nonce="dispatch-" + sha256_identity({"request": request, "worker": worker_id})[7:55], payload=payload, created_at=created, expires_at=expires)
            self.ledger.append("protocol.controller-dispatch", envelope)
            response = self.workers[worker_id].handle(envelope)
            if response.get("message_type") == "execution.result":
                self.verify_response(response, worker_id=worker_id, job_identity=checked["job_identity"], candidate_identity=checked["candidate_identity"], artifact_manifest_identity=checked["artifact_manifest_identity"])
            else:
                validate_envelope(response)
            outputs.append(response)
        return outputs

    def verify_response(self, response: object, *, worker_id: str, job_identity: str, candidate_identity: str | None = None, artifact_manifest_identity: str | None = None) -> dict[str, Any]:
        value = validate_envelope(response)
        record = value["payload"].get("record", {})
        if value["worker_id"] != worker_id or record.get("job_identity") != job_identity or (candidate_identity is not None and record.get("candidate_identity") != candidate_identity) or (artifact_manifest_identity is not None and record.get("artifact_manifest_identity") != artifact_manifest_identity):
            raise ProtocolError("controller response identity binding does not match the dispatch")
        return value
