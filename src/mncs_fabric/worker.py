"""Locally executable worker service over the versioned protocol."""

from __future__ import annotations

from datetime import timedelta
from pathlib import Path
from typing import Any

from .canonical import sha256_identity
from .bundle_transfer import BundleCache
from .bundles import build_bundle_binding
from .challenges import validate_execution_challenge
from .errors import ProtocolError, StorageError
from .executor import execute_local
from . import __version__
from .node import capability_names, collect_node_capabilities, utc_now
from .resources import build_placement_reference, capture_resource_snapshot, evaluate_placement, validate_placement_request
from .protocol import dispatch_binding_identity, make_envelope, validate_envelope
from .store import FabricLedger
from .receipts import build_execution_receipt
from .worker_state import build_worker_description
from .runtime import build_runtime_binding, build_runtime_profile, validate_runtime_observation


class LocalWorker:
    """A worker callable in-process; no unauthenticated listener is created."""

    def __init__(self, worker_id: str, bundle_root: Path, state_path: Path, *, concurrency_limit: int = 1, bundle_cache_root: Path | None = None) -> None:
        if not worker_id or concurrency_limit < 1:
            raise ValueError("worker_id and a positive concurrency limit are required")
        self.worker_id = worker_id
        self.bundle_root = Path(bundle_root)
        self.ledger = FabricLedger(Path(state_path))
        self.concurrency_limit = concurrency_limit
        self.bundle_cache = BundleCache(Path(bundle_cache_root)) if bundle_cache_root is not None else None
        # The profile describes the interpreter that launched this worker
        # process. Capture it once so repeated descriptions do not rotate the
        # profile identity merely because contact time changed.
        self._runtime_profile = build_runtime_profile(self.worker_id)

    def node(self) -> dict[str, Any]:
        return collect_node_capabilities(self.worker_id)

    def capabilities(self) -> frozenset[str]:
        return frozenset(capability_names(self.node()))

    def resource_snapshot(self) -> dict[str, Any]:
        node = self.node()
        return capture_resource_snapshot(self.worker_id, node_fingerprint=node.get("node_fingerprint"))

    def runtime_profile(self) -> dict[str, Any]:
        """Describe the exact Python environment that launched this worker."""

        return dict(self._runtime_profile)

    def description(self) -> dict[str, Any]:
        """Return a fresh bounded description owned by this worker."""

        node = self.node()
        snapshot = capture_resource_snapshot(self.worker_id, node_fingerprint=node.get("node_fingerprint"))
        return build_worker_description(worker_id=self.worker_id, node=node, resource_snapshot=snapshot, runtime_profile=self.runtime_profile())

    def announcement(self, controller_id: str) -> dict[str, Any]:
        created = utc_now()
        expires = (self._parse_time(created) + timedelta(minutes=5)).isoformat().replace("+00:00", "Z")
        node = self.node()
        return make_envelope("worker.announce", controller_id=controller_id, worker_id=self.worker_id, request_id="announce-" + self.worker_id, job_id="node-announcement", nonce="announce-" + sha256_identity(node)[7:23], payload={"node": node, "resource_snapshot": self.resource_snapshot()}, created_at=created, expires_at=expires)

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
        if message["message_type"] in {"bundle.offer", "bundle.chunk", "bundle.commit"}:
            return self._handle_bundle_message(message)
        if message["message_type"] == "worker.describe.request":
            if message["worker_id"] != self.worker_id:
                raise ProtocolError("description is bound to a different worker")
            description = self.description()
            self.ledger.append("protocol.description", {"request_id": message["request_id"], "controller_id": message["controller_id"], "worker_id": self.worker_id, "description": description})
            return self._response(message, "worker.describe.result", {"description": description})
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
        placement_request = payload.get("placement_request")
        runtime_observation = payload.get("runtime_observation")
        if runtime_observation is not None:
            if placement_request is None:
                raise ProtocolError("runtime observation requires a placement request")
            validate_runtime_observation(runtime_observation, expected_worker_id=self.worker_id, expected_profile_identity=self.runtime_profile()["runtime_profile_identity"])
        placement_admission = None
        resource_snapshot = None
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
                for field in ("execution_bundle", "bundle_binding"):
                    if result.get(field) is not None:
                        duplicate_payload[field] = result[field]
                for field in ("placement_admission", "resource_snapshot"):
                    if result.get(field) is not None:
                        duplicate_payload[field] = result[field]
                for field in ("runtime_observation", "runtime_binding"):
                    if result.get(field) is not None:
                        duplicate_payload[field] = result[field]
                return self._response(message, "execution.result", duplicate_payload)
            return self._response(message, "dispatch.ack", {"disposition": "DUPLICATE_IN_PROGRESS", "dispatch_identity": dispatch_binding})
        if placement_request is not None:
            validate_placement_request(placement_request)
            resource_snapshot = self.resource_snapshot()
            placement_admission = evaluate_placement(placement_request, resource_snapshot, self.capabilities(), runtime_observation)
            if placement_admission["disposition"] != "PASS":
                return self._response(message, "dispatch.ack", {"disposition": "UNKNOWN", "reason": placement_admission["reason_code"], "placement_admission": placement_admission, "resource_snapshot": resource_snapshot})
        bundle_info = payload.get("execution_bundle")
        execution_root = self.bundle_root
        bundle_report = None
        if bundle_info is not None:
            if self.bundle_cache is None:
                raise ProtocolError("dispatch requires a bundle cache that is not configured")
            execution_root = self.bundle_cache.root_for(bundle_info["bundle_identity"], bundle_info["archive_identity"])
            bundle_report = self.bundle_cache.report_for(bundle_info["bundle_identity"], bundle_info["archive_identity"])
        self.ledger.append("protocol.dispatch", {"request_id": request_id, "dispatch_identity": message["message_id"], "dispatch_binding_identity": dispatch_binding, "worker_id": self.worker_id, "job_identity": payload["job_plan"]["job_identity"], "bundle_identity": bundle_info.get("bundle_identity") if isinstance(bundle_info, dict) else None, "archive_identity": bundle_info.get("archive_identity") if isinstance(bundle_info, dict) else None})
        try:
            record = execute_local(payload["job_plan"], execution_root, payload["artifact_manifest"], self.worker_id)
        except Exception as exc:
            raise StorageError(f"worker execution failed before a record was published: {exc}") from exc
        placement_reference = build_placement_reference(placement_admission) if placement_admission is not None else None
        receipt = build_execution_receipt(record, runner_identity=f"mncs-fabric-worker-{self.worker_id}", runner_version=__version__, challenge=challenge, bundle_identity=bundle_report.bundle_identity if bundle_report is not None else None, archive_identity=bundle_report.archive_identity if bundle_report is not None else None, placement_reference=placement_reference)
        response_payload: dict[str, Any] = {"result_identity": record["record_id"], "record": record, "disposition": "EXECUTED"}
        if receipt is not None:
            response_payload["receipt"] = receipt
        if bundle_report is not None and receipt is not None:
            response_payload["execution_bundle"] = {"bundle_identity": bundle_report.bundle_identity, "archive_identity": bundle_report.archive_identity}
            response_payload["bundle_binding"] = build_bundle_binding(job_identity=record["job_identity"], candidate_identity=record.get("candidate_identity"), receipt_identity=receipt["receipt_identity"], bundle=bundle_report)
        if placement_admission is not None:
            response_payload["placement_admission"] = placement_admission
            response_payload["resource_snapshot"] = resource_snapshot
        if runtime_observation is not None:
            response_payload["runtime_observation"] = runtime_observation
            response_payload["runtime_binding"] = build_runtime_binding(observation=runtime_observation, worker_identity=self.worker_id, request_identity=payload["request_identity"], record_identity=record["record_id"], receipt_identity=receipt["receipt_identity"] if receipt is not None else None)
        result_record = {"request_id": request_id, "dispatch_identity": message["message_id"], "dispatch_binding_identity": dispatch_binding, "record": record, "receipt": receipt}
        for field in ("execution_bundle", "bundle_binding"):
            if response_payload.get(field) is not None:
                result_record[field] = response_payload[field]
        for field in ("placement_admission", "resource_snapshot"):
            if response_payload.get(field) is not None:
                result_record[field] = response_payload[field]
        for field in ("runtime_observation", "runtime_binding"):
            if response_payload.get(field) is not None:
                result_record[field] = response_payload[field]
        self.ledger.append("protocol.result", result_record)
        return self._response(message, "execution.result", response_payload)

    def _handle_bundle_message(self, message: dict[str, Any]) -> dict[str, Any]:
        if self.bundle_cache is None:
            return self._bundle_response(message, "FAIL", "worker bundle cache is not configured")
        payload = message["payload"]
        try:
            if message["message_type"] == "bundle.offer":
                status = self.bundle_cache.begin(transfer_id=payload["transfer_id"], bundle_identity=payload["bundle_identity"], archive_identity=payload["archive_identity"], total_bytes=payload["total_bytes"], chunk_bytes=payload["chunk_bytes"], chunk_count=payload["chunk_count"])
            elif message["message_type"] == "bundle.chunk":
                import base64
                status = self.bundle_cache.chunk(transfer_id=payload["transfer_id"], bundle_identity=payload["bundle_identity"], archive_identity=payload["archive_identity"], sequence=payload["sequence"], data=base64.b64decode(payload["data"], validate=True))
            else:
                status, report, _ = self.bundle_cache.commit(transfer_id=payload["transfer_id"], bundle_identity=payload["bundle_identity"], archive_identity=payload["archive_identity"])
                if report is not None and report.category == "UNKNOWN":
                    status = "UNKNOWN"
            return self._bundle_response(message, status, None)
        except (ProtocolError, StorageError, OSError, ValueError) as exc:
            return self._bundle_response(message, "FAIL" if isinstance(exc, ProtocolError) else "UNKNOWN", str(exc))

    def _bundle_response(self, request: dict[str, Any], status: str, diagnostic: str | None) -> dict[str, Any]:
        payload: dict[str, Any] = {"transfer_schema": "mncs-fabric.bundle-transfer.v0.1", "transfer_id": request["payload"]["transfer_id"], "status": status}
        if diagnostic:
            payload["diagnostic"] = diagnostic
        return self._response(request, "bundle.response", payload)

    def _response(self, request: dict[str, Any], message_type: str, payload: dict[str, Any]) -> dict[str, Any]:
        created = utc_now()
        expires = (self._parse_time(created) + timedelta(minutes=5)).isoformat().replace("+00:00", "Z")
        return make_envelope(message_type, controller_id=request["controller_id"], worker_id=self.worker_id, request_id=request["request_id"], job_id=request["job_id"], nonce=request["nonce"], payload=payload, created_at=created, expires_at=expires)
