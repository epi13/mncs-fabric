"""In-process controller facade for safe Phase-1 protocol development."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path
import threading
import time
from concurrent.futures import ThreadPoolExecutor, wait
from typing import Any

from .canonical import sha256_identity, verify_identity
from .challenges import bind_challenge_to_receipt
from .errors import ProtocolError, TransportTimeoutError
from .fleet_refresh import (
    DEFAULT_PER_WORKER_DEADLINE_SECONDS,
    MAX_CONCURRENT_REFRESHES,
    MIN_WORKER_DEADLINE_SECONDS,
    annotate_refresh,
    build_refresh_generation,
    build_refresh_report,
    per_worker_deadline_seconds,
    project_runtime_identity,
)
from .models import validate_job_plan
from .node import utc_now
from .protocol import dispatch_request_identity, make_envelope, validate_envelope
from .resources import validate_admission, validate_resource_snapshot, validate_placement_request
from .runtime import validate_runtime_capability_observation, validate_runtime_observation
from .scheduler import WorkerSlot, schedule
from .store import FabricLedger
from .transport import EnvelopeTransport, InProcessTransport
from .worker import LocalWorker
from .worker_state import (
    DESCRIPTION_LEASE_SECONDS,
    build_liveness_observation,
    liveness_is_fresh,
    validate_liveness,
    worker_description_is_fresh,
    validate_worker_description,
)
from .certify import validate_certification
from .fleet_ops import FleetManager
from .inventory import validate_worker_inventory
from .management import ManagementStore
from .providers import validate_action


class LocalController:
    """Controller using explicit in-process worker calls, suitable for tests and Forge."""

    def __init__(self, controller_id: str, state_path: Path) -> None:
        self.controller_id = controller_id
        self.ledger = FabricLedger(Path(state_path))
        self.workers: dict[str, LocalWorker] = {}
        management_path = Path(state_path).with_name(Path(state_path).stem + ".management.jsonl")
        self.fleet_manager = FleetManager(ManagementStore(management_path), controller_id=controller_id)

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
            snapshot = worker.resource_snapshot()
            description = worker.description()
            management = self.fleet_manager.status(worker_id)
            result.append({"worker_id": worker_id, "capabilities": sorted(worker.capabilities()), "concurrency_limit": worker.concurrency_limit, "available": worker.accepts_work(), "availability": "AVAILABLE", "observation_source": "worker-observed", "last_observed_at": description["captured_at"], "description_identity": description["description_identity"], "node_record_identity": description["node"]["record_id"], "resource_snapshot": snapshot, "resource_snapshot_identity": snapshot["resource_snapshot_identity"], "network_topology": description.get("node", {}).get("network_topology"), "topology_identity": description.get("node", {}).get("network_topology", {}).get("topology_identity"), "management_state": management["management"]["state"], "schedulable": management["schedulable"], "profiles": management["profiles"]})
        return result

    def _local_transport(self, worker_id: str) -> EnvelopeTransport:
        if worker_id not in self.workers:
            raise ProtocolError(f"worker is not registered: {worker_id}")
        return InProcessTransport(self.workers[worker_id])

    def _worker_transport(self, worker_id: str) -> EnvelopeTransport:
        return self._local_transport(worker_id)

    def inventory_via(self, transport: EnvelopeTransport, *, worker_id: str, request_id: str | None = None, timeout: float | None = 90.0) -> dict[str, Any]:
        created = utc_now()
        expires = (datetime.fromisoformat(created.replace("Z", "+00:00")).astimezone(timezone.utc) + timedelta(minutes=2)).isoformat().replace("+00:00", "Z")
        request = request_id or "inventory-" + sha256_identity({"controller_id": self.controller_id, "worker_id": worker_id, "scope": "current-worker-inventory"})[7:]
        scope_identity = sha256_identity({"protocol_version": "mncs-fabric.protocol.v0.1", "message_type": "worker.inventory.request", "controller_id": self.controller_id, "worker_id": worker_id, "request_id": request, "scope": "current-worker-inventory"})
        envelope = make_envelope("worker.inventory.request", controller_id=self.controller_id, worker_id=worker_id, request_id=request, job_id="worker-inventory", nonce="inventory-" + sha256_identity({"request": request, "worker": worker_id})[7:55], payload={"inventory_request_identity": scope_identity}, created_at=created, expires_at=expires)
        self.ledger.append("worker.inventory.request", envelope)
        response = validate_envelope(self._transport_request(transport, envelope, timeout=timeout) if hasattr(self, "_transport_request") else transport.request(envelope))
        if response.get("message_type") != "worker.inventory.result" or response.get("worker_id") != worker_id:
            raise ProtocolError("worker inventory response identity is invalid")
        inventory = validate_worker_inventory(response["payload"].get("inventory"), expected_worker_id=worker_id)
        self.ledger.append("worker.inventory", inventory)
        return inventory

    def transfer_package_artifact(self, worker_id: str, path: Path, *, version: str, source: str = "operator-staged") -> dict[str, Any]:
        import base64

        from .package_artifact import MAX_CHUNK_BYTES, build_transfer_identity, chunk_bounds, describe_package_artifact, transfer_deadline

        artifact = describe_package_artifact(Path(path), version=version, source=source)
        raw = Path(path).read_bytes()
        chunk_bytes, chunk_count = chunk_bounds(len(raw))
        transport = self._worker_transport(worker_id)
        created = utc_now()
        expires = transfer_deadline(seconds=300.0)

        def _send(payload: dict[str, Any]) -> dict[str, Any]:
            request = "artifact-" + sha256_identity({"controller_id": self.controller_id, "worker_id": worker_id, "mode": payload["mode"], "digest": artifact["digest"]})[7:40]
            scope = sha256_identity({"protocol_version": "mncs-fabric.protocol.v0.1", "message_type": "worker.package-artifact.request", "controller_id": self.controller_id, "worker_id": worker_id, "request_id": request})
            payload = dict(payload)
            payload["artifact_request_identity"] = scope
            envelope = make_envelope("worker.package-artifact.request", controller_id=self.controller_id, worker_id=worker_id, request_id=request, job_id="package-artifact", nonce="artifact-" + scope[7:23], payload=payload, created_at=created, expires_at=expires)
            response = validate_envelope(transport.request(envelope))
            if response.get("message_type") != "worker.package-artifact.result":
                raise ProtocolError("package artifact response identity is invalid")
            return response["payload"]

        transfer_identity = build_transfer_identity(
            worker_identity=worker_id,
            controller_identity=self.controller_id,
            artifact_identity=artifact["artifact_identity"],
            expected_chunk_count=chunk_count,
            expected_total_bytes=artifact["size_bytes"],
        )
        offered = _send({
            "mode": "offer",
            "artifact": artifact,
            "total_bytes": artifact["size_bytes"],
            "chunk_bytes": chunk_bytes,
            "chunk_count": chunk_count,
            "transfer_identity": transfer_identity,
            "expires_at": expires,
        })
        if offered.get("disposition") != "PASS":
            return offered
        for sequence in range(chunk_count):
            piece = raw[sequence * MAX_CHUNK_BYTES:(sequence + 1) * MAX_CHUNK_BYTES]
            chunked = _send({
                "mode": "chunk",
                "sequence": sequence,
                "data": base64.b64encode(piece).decode("ascii"),
                "transfer_identity": transfer_identity,
            })
            if chunked.get("disposition") != "PASS":
                return chunked
        committed = _send({"mode": "commit", "transfer_identity": transfer_identity})
        self.ledger.append("package.artifact.transfer", {"worker_id": worker_id, "artifact": artifact, "result": committed})
        return {"artifact": artifact, "result": committed}

    def inspect_worker(self, worker_id: str) -> dict[str, Any]:
        inventory = self.inventory_via(self._worker_transport(worker_id), worker_id=worker_id)
        self.fleet_manager.desired_for(worker_id, inventory)
        return {"inventory": inventory, "management": self.fleet_manager.status(worker_id)}

    def plan_worker(self, worker_id: str, *, profiles: list[str] | None = None, classes: list[str] | None = None) -> dict[str, Any]:
        inventory = self.inventory_via(self._worker_transport(worker_id), worker_id=worker_id)
        return self.fleet_manager.plan(worker_id, inventory, profiles=profiles, classes=classes, active_jobs=0)

    def reconcile_worker(self, worker_id: str, *, apply: bool = False, profiles: list[str] | None = None, classes: list[str] | None = None, force: bool = False) -> dict[str, Any]:
        transport = self._worker_transport(worker_id)
        inventory = self.inventory_via(transport, worker_id=worker_id)

        def apply_actions(actions: list[dict[str, Any]]) -> list[dict[str, Any]]:
            return self.maintenance_via(transport, worker_id=worker_id, actions=actions, mode="apply")

        def certify(current: dict[str, Any]) -> dict[str, Any]:
            desired = self.fleet_manager.desired_for(worker_id, current, profiles=profiles)
            certified = self.certify_via(transport, worker_id=worker_id, profiles=list(desired["profiles"]))
            if certified.get("inventory") is None:
                raise ProtocolError("remote certification did not return the inventory that was certified")
            return {
                "certification": certified["certification"],
                "certified_inventory": certified["inventory"],
            }

        return self.fleet_manager.reconcile(worker_id, inventory, apply_actions, apply=apply, profiles=profiles, classes=classes, force=force, certify=certify)

    def certify_worker(self, worker_id: str, *, profiles: list[str] | None = None) -> dict[str, Any]:
        transport = self._worker_transport(worker_id)
        inspected = self.inventory_via(transport, worker_id=worker_id)
        desired = self.fleet_manager.desired_for(worker_id, inspected, profiles=profiles)
        certified = self.certify_via(transport, worker_id=worker_id, profiles=list(desired["profiles"]))
        if certified.get("inventory") is None:
            raise ProtocolError("remote certification did not return the inventory that was certified")
        inventory = certified["inventory"]
        return self.fleet_manager.certify(worker_id, inventory, profiles=profiles, certification=certified["certification"])

    def drain_worker(self, worker_id: str, *, reason: str = "operator drain") -> dict[str, Any]:
        self.management_via(self._worker_transport(worker_id), worker_id=worker_id, command="drain", reason=reason)
        return self.fleet_manager.drain(worker_id, reason=reason)

    def resume_worker(self, worker_id: str, *, reason: str = "operator resume") -> dict[str, Any]:
        result = self.fleet_manager.resume(worker_id, reason=reason)
        state = result.get("state")
        if state == "READY":
            command = "resume"
        elif state == "QUARANTINED":
            command = "quarantine"
        else:
            command = "drain"
        self.management_via(self._worker_transport(worker_id), worker_id=worker_id, command=command, reason=result.get("reason") or reason)
        return result

    def quarantine_worker(self, worker_id: str, *, reason: str) -> dict[str, Any]:
        self.management_via(self._worker_transport(worker_id), worker_id=worker_id, command="quarantine", reason=reason)
        return self.fleet_manager.quarantine(worker_id, reason=reason)

    def maintenance_via(self, transport: EnvelopeTransport, *, worker_id: str, actions: list[dict[str, Any]], mode: str = "apply", force: bool = False, timeout: float | None = 90.0) -> list[dict[str, Any]]:
        created = utc_now()
        expires = (datetime.fromisoformat(created.replace("Z", "+00:00")).astimezone(timezone.utc) + timedelta(minutes=10)).isoformat().replace("+00:00", "Z")
        checked = [validate_action(item) for item in actions]
        request = "maintenance-" + sha256_identity({"controller_id": self.controller_id, "worker_id": worker_id, "actions": checked})[7:]
        scope_identity = sha256_identity({"protocol_version": "mncs-fabric.protocol.v0.1", "message_type": "worker.maintenance.request", "controller_id": self.controller_id, "worker_id": worker_id, "request_id": request})
        envelope = make_envelope(
            "worker.maintenance.request",
            controller_id=self.controller_id,
            worker_id=worker_id,
            request_id=request,
            job_id="worker-maintenance",
            nonce="maintain-" + sha256_identity({"request": request, "worker": worker_id})[7:55],
            payload={"maintenance_request_identity": scope_identity, "mode": mode, "actions": checked, "force": force},
            created_at=created,
            expires_at=expires,
        )
        response = validate_envelope(self._transport_request(transport, envelope, timeout=timeout) if hasattr(self, "_transport_request") else transport.request(envelope))
        if response.get("message_type") != "worker.maintenance.result":
            raise ProtocolError("worker maintenance response is invalid")
        results = response["payload"]["results"]
        if not isinstance(results, list):
            raise ProtocolError("worker maintenance results are invalid")
        return [dict(item) for item in results if isinstance(item, dict)]

    def certify_via(self, transport: EnvelopeTransport, *, worker_id: str, profiles: list[str], timeout: float | None = 90.0) -> dict[str, Any]:
        created = utc_now()
        expires = (datetime.fromisoformat(created.replace("Z", "+00:00")).astimezone(timezone.utc) + timedelta(minutes=5)).isoformat().replace("+00:00", "Z")
        request = "certify-" + sha256_identity({"controller_id": self.controller_id, "worker_id": worker_id, "profiles": profiles})[7:]
        scope_identity = sha256_identity({"protocol_version": "mncs-fabric.protocol.v0.1", "message_type": "worker.certify.request", "controller_id": self.controller_id, "worker_id": worker_id, "request_id": request})
        envelope = make_envelope(
            "worker.certify.request",
            controller_id=self.controller_id,
            worker_id=worker_id,
            request_id=request,
            job_id="worker-certify",
            nonce="certify-" + sha256_identity({"request": request, "worker": worker_id})[7:55],
            payload={"certify_request_identity": scope_identity, "profiles": profiles},
            created_at=created,
            expires_at=expires,
        )
        response = validate_envelope(self._transport_request(transport, envelope, timeout=timeout) if hasattr(self, "_transport_request") else transport.request(envelope))
        if response.get("message_type") != "worker.certify.result":
            raise ProtocolError("worker certify response is invalid")
        certification = validate_certification(response["payload"].get("certification"), expected_worker_id=worker_id)
        inventory = None
        if response["payload"].get("inventory") is not None:
            from .inventory import validate_worker_inventory

            inventory = validate_worker_inventory(response["payload"]["inventory"], expected_worker_id=worker_id)
        return {"certification": certification, "inventory": inventory}

    def management_via(self, transport: EnvelopeTransport, *, worker_id: str, command: str, reason: str, timeout: float | None = 30.0) -> dict[str, Any]:
        created = utc_now()
        expires = (datetime.fromisoformat(created.replace("Z", "+00:00")).astimezone(timezone.utc) + timedelta(minutes=2)).isoformat().replace("+00:00", "Z")
        request = "manage-" + sha256_identity({"controller_id": self.controller_id, "worker_id": worker_id, "command": command, "reason": reason})[7:]
        scope_identity = sha256_identity({"protocol_version": "mncs-fabric.protocol.v0.1", "message_type": "worker.management.request", "controller_id": self.controller_id, "worker_id": worker_id, "request_id": request})
        envelope = make_envelope(
            "worker.management.request",
            controller_id=self.controller_id,
            worker_id=worker_id,
            request_id=request,
            job_id="worker-management",
            nonce="manage-" + sha256_identity({"request": request, "worker": worker_id})[7:55],
            payload={"management_request_identity": scope_identity, "command": command, "reason": reason},
            created_at=created,
            expires_at=expires,
        )
        response = validate_envelope(self._transport_request(transport, envelope, timeout=timeout) if hasattr(self, "_transport_request") else transport.request(envelope))
        if response.get("message_type") != "worker.management.result":
            raise ProtocolError("worker management response is invalid")
        return response["payload"]["state"]

    def dispatch(self, plan: object, manifest: object, *, replicas: int = 1, request_id: str | None = None, consumer_context: dict[str, Any] | None = None, execution_bundle: dict[str, str] | None = None, placement_request: dict[str, Any] | None = None, runtime_observation: dict[str, Any] | None = None, runtime_capability_observation: dict[str, Any] | None = None) -> list[dict[str, Any]]:
        checked = validate_job_plan(plan)
        if not isinstance(manifest, dict) or manifest.get("manifest_identity") != checked["artifact_manifest_identity"]:
            raise ProtocolError("controller dispatch requires a matching manifest")
        if placement_request is not None:
            validate_placement_request(placement_request)
        decision = schedule(checked, [WorkerSlot(worker_id=worker_id, capabilities=worker.capabilities(), resource_snapshot=worker.resource_snapshot() if placement_request is not None else None, runtime_observation=runtime_observation, runtime_capability_observation=runtime_capability_observation, management_state=worker.management_state()["state"]) for worker_id, worker in self.workers.items()], replicas=replicas, placement=placement_request)
        if decision.disposition != "PASS":
            return [{"disposition": decision.disposition, "reason": decision.reason, "worker_ids": list(decision.worker_ids), "admissions": [dict(item) for item in decision.admissions]}]
        outputs = []
        for worker_id in decision.worker_ids:
            response = self.dispatch_via(
                InProcessTransport(self.workers[worker_id]), checked, manifest,
                worker_id=worker_id,
                request_id=request_id or sha256_identity({"job_identity": checked["job_identity"], "worker_id": worker_id, "replica": len(outputs)}),
                consumer_context=consumer_context, execution_bundle=execution_bundle, placement_request=placement_request, runtime_observation=runtime_observation, runtime_capability_observation=runtime_capability_observation,
            )
            outputs.append(response)
        return outputs

    def dispatch_via(self, transport: EnvelopeTransport, plan: object, manifest: object, *, worker_id: str, request_id: str, challenge: dict[str, Any] | None = None, consumer_context: dict[str, Any] | None = None, execution_bundle: dict[str, str] | None = None, placement_request: dict[str, Any] | None = None, runtime_observation: dict[str, Any] | None = None, runtime_capability_observation: dict[str, Any] | None = None) -> dict[str, Any]:
        """Dispatch through a transport without moving protocol semantics into it."""
        checked = validate_job_plan(plan)
        if not isinstance(manifest, dict) or manifest.get("manifest_identity") != checked["artifact_manifest_identity"]:
            raise ProtocolError("controller dispatch requires a matching manifest")
        created = utc_now()
        expires = (datetime.fromisoformat(created.replace("Z", "+00:00")).astimezone(timezone.utc) + timedelta(minutes=5)).isoformat().replace("+00:00", "Z")
        if placement_request is not None:
            validate_placement_request(placement_request)
        if runtime_observation is not None:
            validate_runtime_observation(runtime_observation, expected_worker_id=worker_id)
        if runtime_capability_observation is not None:
            validate_runtime_capability_observation(runtime_capability_observation, expected_worker_id=worker_id)
        payload = {"job_plan": checked, "artifact_manifest": manifest, "request_identity": dispatch_request_identity(plan=checked, manifest=manifest, challenge=challenge, consumer_context=consumer_context, execution_bundle=execution_bundle, placement_request=placement_request, runtime_observation=runtime_observation, runtime_capability_observation=runtime_capability_observation)}
        if challenge is not None:
            payload["execution_challenge"] = challenge
        if consumer_context is not None:
            payload["consumer_context"] = consumer_context
        if execution_bundle is not None:
            payload["execution_bundle"] = execution_bundle
        if placement_request is not None:
            payload["placement_request"] = placement_request
        if runtime_observation is not None:
            payload["runtime_observation"] = runtime_observation
        if runtime_capability_observation is not None:
            payload["runtime_capability_observation"] = runtime_capability_observation
        envelope = make_envelope("dispatch.request", controller_id=self.controller_id, worker_id=worker_id, request_id=request_id, job_id=checked["job_id"], nonce="dispatch-" + sha256_identity({"request": request_id, "worker": worker_id})[7:55], payload=payload, created_at=created, expires_at=expires)
        self.ledger.append("protocol.controller-dispatch", envelope)
        response = transport.request(envelope)
        if response.get("message_type") == "execution.result":
            return self.verify_response(response, worker_id=worker_id, job_identity=checked["job_identity"], candidate_identity=checked["candidate_identity"], artifact_manifest_identity=checked["artifact_manifest_identity"], challenge=challenge, execution_bundle=execution_bundle, placement_request=placement_request, runtime_observation=runtime_observation, runtime_capability_observation=runtime_capability_observation)
        return validate_envelope(response)

    def verify_response(self, response: object, *, worker_id: str, job_identity: str, candidate_identity: str | None = None, artifact_manifest_identity: str | None = None, challenge: dict[str, Any] | None = None, execution_bundle: dict[str, str] | None = None, placement_request: dict[str, Any] | None = None, runtime_observation: dict[str, Any] | None = None, runtime_capability_observation: dict[str, Any] | None = None) -> dict[str, Any]:
        value = validate_envelope(response)
        record = value["payload"].get("record", {})
        if value["worker_id"] != worker_id or record.get("job_identity") != job_identity or (candidate_identity is not None and record.get("candidate_identity") != candidate_identity) or (artifact_manifest_identity is not None and record.get("artifact_manifest_identity") != artifact_manifest_identity):
            raise ProtocolError("controller response identity binding does not match the dispatch")
        if execution_bundle is not None:
            payload = value["payload"]
            if payload.get("execution_bundle") != execution_bundle:
                raise ProtocolError("controller response bundle identity does not match the dispatch")
            binding = payload.get("bundle_binding")
            receipt = payload.get("receipt")
            if not isinstance(binding, dict) or binding.get("job_identity") != job_identity or binding.get("candidate_identity") != candidate_identity or binding.get("bundle_identity") != execution_bundle["bundle_identity"] or binding.get("archive_identity") != execution_bundle["archive_identity"] or not isinstance(receipt, dict) or binding.get("receipt_identity") != receipt.get("receipt_identity") or not verify_identity(binding, "binding_identity"):
                raise ProtocolError("controller response bundle binding does not match the dispatch")
        if challenge is not None:
            receipt = value["payload"].get("receipt")
            if not isinstance(receipt, dict) or not bind_challenge_to_receipt(challenge, receipt).valid:
                raise ProtocolError("controller response receipt does not bind to its execution challenge")
        if placement_request is not None:
            validate_placement_request(placement_request)
            payload = value["payload"]
            admission = payload.get("placement_admission")
            snapshot = payload.get("resource_snapshot")
            if not isinstance(admission, dict) or not isinstance(snapshot, dict):
                raise ProtocolError("controller response is missing placement evidence")
            validate_admission(admission)
            validate_resource_snapshot(snapshot)
            if admission.get("placement_request_identity") != placement_request["placement_request_identity"] or admission.get("worker_identity") != worker_id or snapshot.get("worker_identity") != worker_id:
                raise ProtocolError("controller response placement binding does not match the dispatch")
            receipt = value["payload"].get("receipt")
            reference = receipt.get("placement", {}).get("execution_placement_reference") if isinstance(receipt, dict) else None
            if not isinstance(reference, dict) or reference.get("placement_request_identity") != placement_request["placement_request_identity"] or reference.get("resource_snapshot_identity") != snapshot["resource_snapshot_identity"] or reference.get("admission_decision_identity") != admission["decision_identity"]:
                raise ProtocolError("controller response receipt placement reference does not match the dispatch")
        if runtime_observation is not None:
            expected = validate_runtime_observation(runtime_observation, expected_worker_id=worker_id)
            returned = value["payload"].get("runtime_observation")
            if not isinstance(returned, dict) or returned.get("runtime_observation_identity") != expected["runtime_observation_identity"]:
                raise ProtocolError("controller response runtime observation does not match the dispatch")
            validate_runtime_observation(returned, expected_worker_id=worker_id, expected_profile_identity=expected["runtime_profile_identity"])
            binding = value["payload"].get("runtime_binding")
            if not isinstance(binding, dict) or binding.get("runtime_observation_identity") != expected["runtime_observation_identity"] or not verify_identity(binding, "runtime_binding_identity"):
                raise ProtocolError("controller response runtime binding is invalid")
        if runtime_capability_observation is not None:
            expected = validate_runtime_capability_observation(runtime_capability_observation, expected_worker_id=worker_id)
            returned = value["payload"].get("runtime_capability_observation")
            if not isinstance(returned, dict) or returned.get("runtime_capability_observation_identity") != expected["runtime_capability_observation_identity"]:
                raise ProtocolError("controller response runtime capability observation does not match the dispatch")
            validate_runtime_capability_observation(returned, expected_worker_id=worker_id, expected_profile_identity=expected["runtime_profile_identity"], expected_environment_identity=expected["runtime_environment_identity"])
            binding = value["payload"].get("runtime_capability_binding")
            if not isinstance(binding, dict) or binding.get("runtime_capability_observation_identity") != expected["runtime_capability_observation_identity"] or not verify_identity(binding, "runtime_capability_binding_identity"):
                raise ProtocolError("controller response runtime capability binding is invalid")
        return value


class NetworkController(LocalController):
    """Controller facade for registered remote transports.

    Worker capability reports are operator-supplied observations.  This class
    does not turn connectivity or a successful command into assurance.
    """

    def __init__(self, controller_id: str, state_path: Path) -> None:
        super().__init__(controller_id, state_path)
        self.remote_workers: dict[str, tuple[EnvelopeTransport, WorkerSlot]] = {}
        self.remote_descriptions: dict[str, dict[str, Any]] = {}
        self.runtime_observations: dict[str, dict[str, Any]] = {}
        self.runtime_capability_observations: dict[str, dict[str, Any]] = {}
        self.remote_liveness: dict[str, dict[str, Any]] = {}
        self._remote_lock = threading.Lock()

    def register_remote(self, worker_id: str, capabilities: frozenset[str], transport: EnvelopeTransport, *, concurrency_limit: int = 1, resource_snapshot: dict[str, Any] | None = None) -> None:
        if worker_id in self.remote_workers:
            raise ProtocolError(f"worker is already registered: {worker_id}")
        if resource_snapshot is not None:
            validate_resource_snapshot(resource_snapshot)
        self.remote_workers[worker_id] = (transport, WorkerSlot(worker_id=worker_id, capabilities=capabilities, concurrency_limit=concurrency_limit, resource_snapshot=resource_snapshot))
        self.remote_liveness[worker_id] = build_liveness_observation(worker_id=worker_id, state="UNKNOWN", observed_at=utc_now(), description_identity=None, lease_seconds=DESCRIPTION_LEASE_SECONDS)

    def _worker_transport(self, worker_id: str) -> EnvelopeTransport:
        if worker_id in self.remote_workers:
            return self.remote_workers[worker_id][0]
        return super()._worker_transport(worker_id)

    def inspect(self) -> list[dict[str, Any]]:
        result = super().inspect()
        for worker_id in sorted(self.remote_workers):
            state = self.worker_state(worker_id, apply_lease=False)
            management = self.fleet_manager.status(worker_id)
            result.append({
                "worker_id": worker_id,
                "capabilities": state.get("capabilities", []),
                "available": state.get("available"),
                "availability": state.get("availability"),
                "observation_source": state.get("observation_source"),
                "last_observed_at": state.get("last_observed_at"),
                "description_identity": state.get("description_identity"),
                "management_state": management["management"]["state"],
                "schedulable": management["schedulable"],
                "profiles": management["profiles"],
            })
        return result

    def set_runtime_observation(self, worker_id: str, observation: dict[str, Any]) -> None:
        if worker_id not in self.remote_workers:
            raise ProtocolError(f"worker is not registered: {worker_id}")
        checked = validate_runtime_observation(observation, expected_worker_id=worker_id)
        description = self.remote_descriptions.get(worker_id)
        profile = description.get("runtime_profile") if description else None
        if not isinstance(profile, dict) or profile.get("runtime_profile_identity") != checked["runtime_profile_identity"]:
            raise ProtocolError("runtime observation does not match the current worker runtime profile")
        self.runtime_observations[worker_id] = checked
        transport, slot = self.remote_workers[worker_id]
        self.remote_workers[worker_id] = (transport, WorkerSlot(worker_id=slot.worker_id, capabilities=slot.capabilities, active=slot.active, concurrency_limit=slot.concurrency_limit, available=slot.available, resource_snapshot=slot.resource_snapshot, runtime_observation=checked))
        self.ledger.append("runtime.observation", checked)

    def set_runtime_capability_observation(self, worker_id: str, observation: dict[str, Any]) -> None:
        if worker_id not in self.remote_workers:
            raise ProtocolError(f"worker is not registered: {worker_id}")
        checked = validate_runtime_capability_observation(observation, expected_worker_id=worker_id)
        description = self.remote_descriptions.get(worker_id)
        profile = description.get("runtime_profile") if description else None
        if not isinstance(profile, dict) or profile.get("runtime_profile_identity") != checked["runtime_profile_identity"]:
            raise ProtocolError("runtime capability observation does not match the current worker runtime profile")
        self.runtime_capability_observations[worker_id] = checked
        transport, slot = self.remote_workers[worker_id]
        self.remote_workers[worker_id] = (transport, WorkerSlot(worker_id=slot.worker_id, capabilities=slot.capabilities, active=slot.active, concurrency_limit=slot.concurrency_limit, available=slot.available, resource_snapshot=slot.resource_snapshot, runtime_observation=slot.runtime_observation, runtime_capability_observation=checked))
        self.ledger.append("runtime.capability-observation", checked)

    def describe_via(self, transport: EnvelopeTransport, *, worker_id: str, request_id: str | None = None, timeout: float | None = None) -> dict[str, Any]:
        """Request one authenticated, bounded worker description."""

        created = utc_now()
        expires = (datetime.fromisoformat(created.replace("Z", "+00:00")).astimezone(timezone.utc) + timedelta(minutes=2)).isoformat().replace("+00:00", "Z")
        request = request_id or "describe-" + sha256_identity({"controller_id": self.controller_id, "worker_id": worker_id, "scope": "current-worker-description"})[7:]
        scope_identity = sha256_identity({"protocol_version": "mncs-fabric.protocol.v0.1", "message_type": "worker.describe.request", "controller_id": self.controller_id, "worker_id": worker_id, "request_id": request, "scope": "current-worker-description"})
        envelope = make_envelope("worker.describe.request", controller_id=self.controller_id, worker_id=worker_id, request_id=request, job_id="worker-description", nonce="describe-" + sha256_identity({"request": request, "worker": worker_id})[7:55], payload={"description_request_identity": scope_identity}, created_at=created, expires_at=expires)
        self.ledger.append("worker.description.request", envelope)
        response = validate_envelope(self._transport_request(transport, envelope, timeout=timeout))
        if response.get("message_type") != "worker.describe.result" or response.get("worker_id") != worker_id or response.get("controller_id") != self.controller_id:
            raise ProtocolError("worker description response identity is invalid")
        description = validate_worker_description(response["payload"].get("description"), expected_worker_id=worker_id)
        self.ledger.append("worker.description", description)
        return description

    @staticmethod
    def _transport_request(transport: EnvelopeTransport, envelope: dict[str, Any], *, timeout: float | None) -> dict[str, Any]:
        if timeout is None:
            return transport.request(envelope)
        try:
            return transport.request(envelope, timeout=timeout)
        except TypeError:
            return transport.request(envelope)

    def _set_remote_state(self, worker_id: str, *, description: dict[str, Any] | None, state: str, failure: str | None = None) -> dict[str, Any]:
        if worker_id not in self.remote_workers:
            raise ProtocolError(f"worker is not registered: {worker_id}")
        with self._remote_lock:
            transport, slot = self.remote_workers[worker_id]
            liveness = build_liveness_observation(worker_id=worker_id, state=state, observed_at=utc_now(), description_identity=description.get("description_identity") if description else (self.remote_liveness.get(worker_id, {}).get("description_identity")), lease_seconds=DESCRIPTION_LEASE_SECONDS, last_failure=failure)
            self.remote_liveness[worker_id] = liveness
            if description is not None:
                self.remote_descriptions[worker_id] = description
                node = description["node"]
                from .node import capability_names
                snapshot = description["resource_snapshot"]
                current_runtime = self.runtime_observations.get(worker_id)
                current_capability = self.runtime_capability_observations.get(worker_id)
                profile = description.get("runtime_profile")
                if current_runtime is not None and (not isinstance(profile, dict) or current_runtime.get("runtime_profile_identity") != profile.get("runtime_profile_identity")):
                    self.runtime_observations.pop(worker_id, None)
                    current_runtime = None
                if current_capability is not None and (not isinstance(profile, dict) or current_capability.get("runtime_profile_identity") != profile.get("runtime_profile_identity")):
                    self.runtime_capability_observations.pop(worker_id, None)
                    current_capability = None
                slot = WorkerSlot(worker_id=slot.worker_id, capabilities=frozenset(capability_names(node)), active=slot.active, concurrency_limit=slot.concurrency_limit, available=True, resource_snapshot=snapshot, runtime_observation=current_runtime, runtime_capability_observation=current_capability)
                self.remote_workers[worker_id] = (transport, slot)
                self.ledger.append("worker.state", {"worker_id": worker_id, "description": description, "liveness": liveness})
            else:
                slot = WorkerSlot(worker_id=slot.worker_id, capabilities=slot.capabilities, active=slot.active, concurrency_limit=slot.concurrency_limit, available=state == "AVAILABLE", resource_snapshot=slot.resource_snapshot, runtime_observation=slot.runtime_observation, runtime_capability_observation=slot.runtime_capability_observation)
                self.remote_workers[worker_id] = (transport, slot)
                self.ledger.append("worker.liveness", liveness)
            return self._worker_state_unlocked(worker_id, apply_lease=False)

    def refresh_remote(self, worker_id: str, *, deadline_seconds: float | None = None) -> dict[str, Any]:
        result, error = self._probe_remote(worker_id, deadline_seconds=deadline_seconds)
        if error is not None:
            raise error
        return result

    def _probe_remote(
        self, worker_id: str, *, deadline_seconds: float | None = None
    ) -> tuple[dict[str, Any], BaseException | None]:
        if worker_id not in self.remote_workers:
            raise ProtocolError(f"worker is not registered: {worker_id}")
        transport, _ = self.remote_workers[worker_id]
        try:
            description = self.describe_via(transport, worker_id=worker_id, timeout=deadline_seconds)
        except TransportTimeoutError as exc:
            return annotate_refresh(
                self.worker_state(worker_id, apply_lease=False),
                status="TIMEOUT",
                deadline_fired="worker",
                diagnostic=str(exc),
            ), exc
        except (ProtocolError, OSError, TimeoutError) as exc:
            state = self._set_remote_state(worker_id, description=None, state="UNAVAILABLE", failure=str(exc))
            return annotate_refresh(state, status="UNAVAILABLE", diagnostic=str(exc)), exc
        if not worker_description_is_fresh(description):
            state = self._set_remote_state(worker_id, description=None, state="UNKNOWN", failure="worker description is stale")
            return annotate_refresh(state, status="UNKNOWN", diagnostic="worker description is stale"), None
        return annotate_refresh(self._set_remote_state(worker_id, description=description, state="AVAILABLE"), status="PASS"), None

    def worker_state(self, worker_id: str, *, apply_lease: bool = True) -> dict[str, Any]:
        with self._remote_lock:
            return self._worker_state_unlocked(worker_id, apply_lease=apply_lease)

    def _worker_state_unlocked(self, worker_id: str, *, apply_lease: bool = True) -> dict[str, Any]:
        if worker_id not in self.remote_workers:
            raise ProtocolError(f"worker is not registered: {worker_id}")
        _, slot = self.remote_workers[worker_id]
        description = self.remote_descriptions.get(worker_id)
        liveness = validate_liveness(self.remote_liveness[worker_id], expected_worker_id=worker_id)
        fresh = liveness_is_fresh(liveness)
        if apply_lease and not fresh and liveness["state"] == "AVAILABLE":
            availability = "UNKNOWN"
        else:
            availability = liveness["state"]
        state = {
            "worker_id": worker_id,
            "transport": "tls-mutual-authenticated",
            "observation_source": "worker-observed" if description else "operator-declared",
            "availability": availability,
            "liveness_fresh": fresh,
            "last_observed_at": liveness["observed_at"],
            "liveness_identity": liveness["liveness_identity"],
            "description_identity": description.get("description_identity") if description else None,
            "description": dict(description) if description else None,
            "node_record_identity": description.get("node", {}).get("record_id") if description else None,
            "network_topology": dict(description["node"]["network_topology"]) if description and isinstance(description.get("node", {}).get("network_topology"), dict) else None,
            "topology_identity": description.get("node", {}).get("network_topology", {}).get("topology_identity") if description else None,
            "capabilities": sorted(slot.capabilities),
            "resource_snapshot": slot.resource_snapshot,
            "resource_snapshot_identity": slot.resource_snapshot.get("resource_snapshot_identity") if slot.resource_snapshot else None,
            "runtime_observation": dict(slot.runtime_observation) if slot.runtime_observation else None,
            "runtime_observation_identity": slot.runtime_observation.get("runtime_observation_identity") if slot.runtime_observation else None,
            "runtime_capability_observation": dict(slot.runtime_capability_observation) if slot.runtime_capability_observation else None,
            "runtime_capability_observation_identity": slot.runtime_capability_observation.get("runtime_capability_observation_identity") if slot.runtime_capability_observation else None,
            "concurrency_limit": slot.concurrency_limit,
            "available": slot.available,
        }
        state.update(project_runtime_identity(state))
        return state

    def _worker_control_timeout(self, worker_id: str) -> float:
        transport, _ = self.remote_workers[worker_id]
        configured = getattr(transport, "control_timeout", None)
        if configured is None:
            configured = getattr(transport, "timeout", DEFAULT_PER_WORKER_DEADLINE_SECONDS)
        try:
            value = float(configured)
        except (TypeError, ValueError):
            return DEFAULT_PER_WORKER_DEADLINE_SECONDS
        return value if value > 0 else DEFAULT_PER_WORKER_DEADLINE_SECONDS

    def refresh_all(
        self,
        *,
        worker_ids: list[str] | None = None,
        operation_deadline: float | None = None,
        per_worker_deadline: float | None = None,
    ) -> list[dict[str, Any]]:
        return list(
            self.refresh_fleet(
                worker_ids=worker_ids,
                operation_deadline=operation_deadline,
                per_worker_deadline=per_worker_deadline,
            ).get("workers", [])
        )

    def refresh_fleet(
        self,
        *,
        worker_ids: list[str] | None = None,
        operation_deadline: float | None = None,
        per_worker_deadline: float | None = None,
    ) -> dict[str, Any]:
        started = time.monotonic()
        started_at = utc_now()
        requested = list(worker_ids) if worker_ids is not None else sorted(self.remote_workers)
        targets = [worker_id for worker_id in requested if worker_id in self.remote_workers]
        unknown = [worker_id for worker_id in requested if worker_id not in self.remote_workers]
        generation = build_refresh_generation(targets + unknown, started_at=started_at)
        generation_id = str(generation["refresh_generation"])
        results: dict[str, dict[str, Any]] = {}

        def remaining_operation() -> float | None:
            if operation_deadline is None:
                return None
            return float(operation_deadline) - (time.monotonic() - started)

        def timeout_state(worker_id: str, owner: str, diagnostic: str) -> dict[str, Any]:
            return annotate_refresh(
                self.worker_state(worker_id, apply_lease=False),
                status="TIMEOUT",
                deadline_fired=owner,
                diagnostic=diagnostic,
                refresh_generation=generation_id,
            )

        for worker_id in unknown:
            results[worker_id] = annotate_refresh(
                {
                    "worker_id": worker_id,
                    "availability": "UNKNOWN",
                    "available": False,
                    "observation_source": "operator-declared",
                },
                status="UNKNOWN",
                diagnostic="worker is not registered",
                refresh_generation=generation_id,
            )

        pending: dict[Any, str] = {}
        workers = min(MAX_CONCURRENT_REFRESHES, max(1, len(targets))) if targets else 1
        with ThreadPoolExecutor(max_workers=workers) as pool:
            for worker_id in targets:
                remaining = remaining_operation()
                if remaining is not None and remaining < MIN_WORKER_DEADLINE_SECONDS:
                    results[worker_id] = timeout_state(
                        worker_id, "operation", "fleet refresh operation deadline expired before probe"
                    )
                    continue
                configured = per_worker_deadline if per_worker_deadline is not None else self._worker_control_timeout(worker_id)
                budget = per_worker_deadline_seconds(remaining_operation=remaining, configured=configured)
                if budget < MIN_WORKER_DEADLINE_SECONDS:
                    results[worker_id] = timeout_state(
                        worker_id, "operation", "remaining refresh budget is below the per-worker bound"
                    )
                    continue
                pending[pool.submit(self._probe_remote, worker_id, deadline_seconds=budget)] = worker_id
            wait_for = remaining_operation()
            if pending:
                wait(pending, timeout=None if wait_for is None else max(0.0, wait_for))
            for future, worker_id in pending.items():
                if future.done():
                    try:
                        probed, _error = future.result()
                        result = dict(probed)
                    except Exception as exc:
                        result = timeout_state(worker_id, "worker", str(exc))
                    result["refresh_generation"] = generation_id
                    results[worker_id] = result
                else:
                    results[worker_id] = timeout_state(
                        worker_id, "operation", "worker probe exceeded the fleet refresh operation deadline"
                    )

        ordered = [results[worker_id] for worker_id in sorted(results)]
        return build_refresh_report(
            ordered,
            observation_mode="probed",
            generation=generation,
            operation_deadline_seconds_value=operation_deadline,
            per_worker_deadline_seconds_value=per_worker_deadline,
        )

    def restore_last_known(self) -> dict[str, Any]:
        """Rebuild in-memory last-known observations from the controller ledger."""

        def _resume(worker_id: str, item: object) -> dict[str, Any]:
            del item
            connected = False
            inventory = None
            if worker_id in self.remote_workers:
                try:
                    inventory = self.inventory_via(
                        self._worker_transport(worker_id),
                        worker_id=worker_id,
                        timeout=15.0,
                    )
                    connected = True
                except Exception:
                    connected = False
                    inventory = None

            def certify(current: dict[str, Any]) -> dict[str, Any]:
                desired = self.fleet_manager.desired_for(worker_id, current)
                certified = self.certify_via(
                    self._worker_transport(worker_id),
                    worker_id=worker_id,
                    profiles=list(desired["profiles"]),
                )
                if certified.get("inventory") is None:
                    raise ProtocolError("remote certification did not return the inventory that was certified")
                return {
                    "certification": certified["certification"],
                    "certified_inventory": certified["inventory"],
                }

            return self.fleet_manager.resume_update_after_restart(
                worker_id,
                connected=connected,
                inventory=inventory,
                certify=certify if connected and inventory is not None else None,
            )

        update_recovery = self.fleet_manager.recover_unresolved_updates(resume=_resume)

        latest_state: dict[str, dict[str, Any]] = {}
        for entry in self.ledger.all_records(record_type="worker.state"):
            record = entry["record"]
            worker_id = record.get("worker_id")
            if isinstance(worker_id, str) and worker_id in self.remote_workers:
                latest_state[worker_id] = record
        latest_liveness: dict[str, dict[str, Any]] = {}
        for entry in self.ledger.all_records(record_type="worker.liveness"):
            record = entry["record"]
            worker_id = record.get("worker_identity") or record.get("worker_id")
            if isinstance(worker_id, str) and worker_id in self.remote_workers:
                latest_liveness[worker_id] = record
        restored = 0
        with self._remote_lock:
            for worker_id in self.remote_workers:
                record = latest_state.get(worker_id)
                description = None
                liveness = None
                if record is not None:
                    raw_description = record.get("description")
                    raw_liveness = record.get("liveness")
                    if isinstance(raw_description, dict):
                        try:
                            description = validate_worker_description(raw_description, expected_worker_id=worker_id)
                        except Exception:
                            description = None
                    if isinstance(raw_liveness, dict):
                        try:
                            liveness = validate_liveness(raw_liveness, expected_worker_id=worker_id)
                        except Exception:
                            liveness = None
                if liveness is None and worker_id in latest_liveness:
                    try:
                        liveness = validate_liveness(latest_liveness[worker_id], expected_worker_id=worker_id)
                    except Exception:
                        liveness = None
                if description is None and liveness is None:
                    continue
                transport, slot = self.remote_workers[worker_id]
                if description is not None:
                    self.remote_descriptions[worker_id] = description
                    from .node import capability_names
                    snapshot = description["resource_snapshot"]
                    slot = WorkerSlot(
                        worker_id=slot.worker_id,
                        capabilities=frozenset(capability_names(description["node"])),
                        active=slot.active,
                        concurrency_limit=slot.concurrency_limit,
                        available=True,
                        resource_snapshot=snapshot,
                        runtime_observation=slot.runtime_observation,
                        runtime_capability_observation=slot.runtime_capability_observation,
                    )
                    self.remote_workers[worker_id] = (transport, slot)
                if liveness is not None:
                    self.remote_liveness[worker_id] = liveness
                restored += 1
        return {
            "restored_workers": restored,
            "known_workers": sorted(self.remote_workers),
            "update_recovery": update_recovery,
        }

    def dispatch_remote(self, plan: object, manifest: object, *, replicas: int = 1, request_id: str | None = None, challenge: dict[str, Any] | None = None, consumer_context: dict[str, Any] | None = None, execution_bundle: dict[str, str] | None = None, placement_request: dict[str, Any] | None = None, runtime_observation: dict[str, Any] | None = None, runtime_capability_observation: dict[str, Any] | None = None) -> list[dict[str, Any]]:
        checked = validate_job_plan(plan)
        if not isinstance(manifest, dict) or manifest.get("manifest_identity") != checked["artifact_manifest_identity"]:
            raise ProtocolError("controller dispatch requires a matching manifest")
        if placement_request is not None:
            # Dynamic resource admission is made from a fresh authenticated
            # worker observation, not from an operator's stale registration.
            self.refresh_all()
        with self._remote_lock:
            decision = schedule(checked, [slot for _, slot in self.remote_workers.values()], replicas=replicas, placement=placement_request)
            if decision.disposition == "PASS":
                for worker_id in decision.worker_ids:
                    transport, slot = self.remote_workers[worker_id]
                    self.remote_workers[worker_id] = (transport, WorkerSlot(worker_id=slot.worker_id, capabilities=slot.capabilities, active=slot.active + 1, concurrency_limit=slot.concurrency_limit, available=slot.available, resource_snapshot=slot.resource_snapshot, runtime_observation=slot.runtime_observation, runtime_capability_observation=slot.runtime_capability_observation))
        if decision.disposition != "PASS":
            return [{"disposition": decision.disposition, "reason": decision.reason, "worker_ids": list(decision.worker_ids)}]
        outputs: list[dict[str, Any]] = []
        try:
            for worker_id in decision.worker_ids:
                transport, _ = self.remote_workers[worker_id]
                request = request_id or sha256_identity({"job_identity": checked["job_identity"], "worker_id": worker_id, "replica": len(outputs)})
                try:
                    outputs.append(self.dispatch_via(transport, checked, manifest, worker_id=worker_id, request_id=request, challenge=challenge, consumer_context=consumer_context, execution_bundle=execution_bundle, placement_request=placement_request, runtime_observation=runtime_observation or self.runtime_observations.get(worker_id), runtime_capability_observation=runtime_capability_observation or self.runtime_capability_observations.get(worker_id)))
                except (ProtocolError, OSError, TimeoutError) as exc:
                    self._set_remote_state(worker_id, description=None, state="UNAVAILABLE", failure=str(exc))
                    reason = (
                        "TRANSPORT_TIMEOUT"
                        if isinstance(exc, TransportTimeoutError)
                        else "WORKER_UNAVAILABLE"
                    )
                    outputs.append({"disposition": "UNKNOWN", "reason": reason, "worker_id": worker_id, "diagnostic": str(exc)})
        finally:
            with self._remote_lock:
                for worker_id in decision.worker_ids:
                    transport, slot = self.remote_workers[worker_id]
                    self.remote_workers[worker_id] = (transport, WorkerSlot(worker_id=slot.worker_id, capabilities=slot.capabilities, active=max(0, slot.active - 1), concurrency_limit=slot.concurrency_limit, available=slot.available, resource_snapshot=slot.resource_snapshot, runtime_observation=slot.runtime_observation, runtime_capability_observation=slot.runtime_capability_observation))
        return outputs

    def reconcile_dispatch(self, responses: list[dict[str, Any]], *, require_distinct_nodes: bool = True) -> dict[str, Any]:
        records = [response.get("payload", {}).get("record") for response in responses if response.get("message_type") == "execution.result" and isinstance(response.get("payload", {}).get("record"), dict)]
        if len(records) != len(responses):
            return {"outcome": "UNKNOWN", "reason": "one or more worker results are unavailable", "record_count": len(records), "response_count": len(responses)}
        return self._reconcile(records, require_distinct_nodes=require_distinct_nodes)

    def _reconcile(self, records: list[dict[str, Any]], *, require_distinct_nodes: bool) -> dict[str, Any]:
        from .reconcile import reconcile_records
        return reconcile_records(records, require_distinct_nodes=require_distinct_nodes)
