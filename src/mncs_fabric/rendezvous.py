"""Controller-owned worker sessions for persistent Fabric service mode."""

from __future__ import annotations

import secrets
import threading
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable, Mapping

from .canonical import attach_identity, sha256_identity
from .contracts import build_public_contract
from .errors import ProtocolError, TransportTimeoutError, ValidationError
from .node import utc_now
from .node import capability_names
from .protocol import make_envelope, validate_envelope
from .scheduler import WorkerSlot, schedule
from .store import FabricLedger
from .worker_state import validate_worker_description

RENDEZVOUS_SCHEMA = "mncs-fabric.worker-rendezvous.v0.1"


def _expiry(seconds: float) -> str:
    return (datetime.now(timezone.utc) + timedelta(seconds=seconds)).isoformat().replace("+00:00", "Z")


class _SessionTransport:
    def __init__(self, session: "RendezvousSession") -> None:
        self.session = session

    def request(self, envelope: dict[str, object]) -> dict[str, object]:
        return self.session.submit(envelope)


class RendezvousSession:
    def __init__(self, coordinator: "RendezvousCoordinator", worker_id: str, session_id: str, generation: int, certificate_fingerprint: str, description: Mapping[str, Any]) -> None:
        self.coordinator = coordinator
        self.worker_id = worker_id
        self.session_id = session_id
        self.generation = generation
        self.certificate_fingerprint = certificate_fingerprint
        self.description = validate_worker_description(description, expected_worker_id=worker_id)
        self.last_seen = time.monotonic()
        self.closed = False
        self._condition = threading.Condition()
        self._pending: tuple[dict[str, object], dict[str, object] | None, BaseException | None] | None = None

    @property
    def transport(self) -> _SessionTransport:
        return _SessionTransport(self)

    def heartbeat(self, description: Mapping[str, Any]) -> dict[str, object] | None:
        checked = validate_worker_description(description, expected_worker_id=self.worker_id)
        with self._condition:
            self.description = checked
            self.last_seen = time.monotonic()
            if self._pending is None:
                return None
            return self._pending[0]

    def complete(self, response: Mapping[str, object]) -> None:
        checked = validate_envelope(response)
        with self._condition:
            pending = self._pending
            if pending is None:
                raise ProtocolError("worker returned a response without a pending rendezvous command")
            if checked.get("request_id") != pending[0].get("request_id"):
                raise ProtocolError("worker response is not bound to the rendezvous command")
            self._pending = (pending[0], dict(checked), None)
            self._condition.notify_all()

    def submit(self, command: dict[str, object], *, timeout: float | None = None) -> dict[str, object]:
        validate_envelope(command)
        bound = timeout or self.coordinator.command_timeout
        deadline = time.monotonic() + bound
        with self._condition:
            if self.closed:
                raise ProtocolError("worker rendezvous session is closed")
            if self._pending is not None:
                raise ProtocolError("worker rendezvous session already has a command in flight")
            self._pending = (command, None, None)
            self._condition.notify_all()
            while self._pending is not None and self._pending[1] is None and self._pending[2] is None and not self.closed:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    self._pending = None
                    raise TransportTimeoutError("worker rendezvous command timed out")
                self._condition.wait(remaining)
            pending = self._pending
            self._pending = None
            if self.closed:
                raise ProtocolError("worker rendezvous session disconnected")
            if pending is None or pending[1] is None:
                raise ProtocolError("worker rendezvous command did not produce a response")
            return pending[1]

    def close(self) -> None:
        with self._condition:
            self.closed = True
            self._condition.notify_all()


class RendezvousCoordinator:
    """Durable observation projection plus live session coordination."""

    def __init__(self, controller_id: str, state_path: Path, *, known_workers: Mapping[str, Mapping[str, Any]] | None = None, membership_provider: Callable[[], Mapping[str, Mapping[str, Any]]] | None = None, heartbeat_seconds: float = 5.0, command_timeout: float = 300.0) -> None:
        if not 0.5 <= heartbeat_seconds <= 60 or not 1 <= command_timeout <= 3600:
            raise ValidationError("rendezvous bounds are invalid")
        self.controller_id = controller_id
        self.ledger = FabricLedger(Path(state_path))
        self.heartbeat_seconds = heartbeat_seconds
        self.command_timeout = command_timeout
        self.known_workers = dict(known_workers or {})
        self.membership_provider = membership_provider
        self.membership_authority = known_workers is not None or membership_provider is not None
        self.sessions: dict[str, RendezvousSession] = {}
        self._lock = threading.RLock()

    def open(self, worker_id: str, fingerprint: str, opening: Mapping[str, Any]) -> dict[str, object]:
        description = opening["payload"]["description"]
        with self._lock:
            known = self._known_workers()
            if self.membership_authority and worker_id not in known:
                raise ProtocolError("worker is not a known Fabric member")
            if not self._member_allowed(known.get(worker_id)):
                raise ProtocolError("worker Fabric membership is not active")
            if any(session.worker_id == worker_id and not session.closed for session in self.sessions.values()):
                raise ProtocolError("worker identity already has an active rendezvous session")
            generation = 1 + max((self._generation(worker_id),), default=0)
            session_id = "session-" + secrets.token_urlsafe(18)
            session = RendezvousSession(self, worker_id, session_id, generation, fingerprint, description)
            self.sessions[session_id] = session
            self._record("connected", session)
        contract = build_public_contract(__import__("mncs_fabric", fromlist=["__version__"]).__version__)
        return make_envelope(
            "worker.session.accept", controller_id=self.controller_id, worker_id=worker_id,
            request_id=str(opening["request_id"]), job_id="worker-session", nonce=sha256_identity({"session": session_id})[7:39],
            payload={"session_id": session_id, "generation": generation, "heartbeat_seconds": self.heartbeat_seconds, "controller_contract_identity": contract["contract_identity"]},
            created_at=utc_now(), expires_at=_expiry(60),
        )

    def message(self, session_id: str, message: Mapping[str, Any]) -> dict[str, object]:
        with self._lock:
            session = self.sessions.get(session_id)
            allowed = self._member_allowed(
                self._known_workers().get(session.worker_id) if session is not None else None
            )
        if session is None or session.closed:
            raise ProtocolError("worker rendezvous session is unknown")
        if not allowed:
            session.close()
            self._record("revoked", session)
            raise ProtocolError("worker Fabric membership is not active")
        if message.get("worker_id") != session.worker_id or message.get("controller_id") != self.controller_id:
            raise ProtocolError("worker rendezvous message identity is invalid")
        if message["message_type"] == "worker.heartbeat":
            command = session.heartbeat(message["payload"]["description"])
            self._record("heartbeat", session)
            return self._ack(session, command)
        if message["message_type"] in {"execution.result", "bundle.response", "dispatch.ack", "replay.disposition"}:
            session.complete(message)
            return self._ack(session, None)
        raise ProtocolError("worker rendezvous message type is unsupported")

    def close(self, session_id: str) -> None:
        with self._lock:
            session = self.sessions.pop(session_id, None)
        if session is not None:
            session.close()
            self._record("disconnected", session)

    def ready(self) -> bool:
        return True

    def states(self) -> list[dict[str, Any]]:
        now = time.monotonic()
        with self._lock:
            active = {session.worker_id: session for session in self.sessions.values() if not session.closed}
            known = self._known_workers()
        result: list[dict[str, Any]] = []
        for worker_id in sorted(set(known) | set(active)):
            session = active.get(worker_id)
            membership = known.get(worker_id, {})
            if not self._member_allowed(membership):
                if session is not None:
                    session.close()
                result.append({
                    **dict(membership),
                    "worker_id": worker_id,
                    "availability": "UNAVAILABLE",
                    "available": False,
                    "transport": "worker-initiated-tls-rendezvous",
                    "observation_source": "controller-owned-membership",
                    "liveness": "REVOKED",
                })
                continue
            if session is None:
                base = dict(known.get(worker_id, {}))
                result.append({**base, "worker_id": worker_id, "availability": "UNAVAILABLE", "available": False, "transport": "worker-initiated-tls-rendezvous", "observation_source": "controller-owned-rendezvous"})
                continue
            fresh = now - session.last_seen <= self.heartbeat_seconds * 3
            description = session.description
            snapshot = description.get("resource_snapshot")
            result.append({
                "worker_id": worker_id, "availability": "AVAILABLE" if fresh else "UNKNOWN", "available": fresh,
                "transport": "worker-initiated-tls-rendezvous", "observation_source": "worker-observed",
                "source": membership.get("source", "rendezvous"),
                "membership_id": membership.get("membership_id"),
                "session_id": session.session_id, "session_generation": session.generation,
                "last_seen": description.get("captured_at"), "capabilities": sorted(capability_names(description["node"])),
                "description": dict(description), "resource_snapshot": snapshot,
                "resource_snapshot_identity": snapshot.get("resource_snapshot_identity") if isinstance(snapshot, dict) else None,
                "concurrency_limit": int(known.get(worker_id, {}).get("concurrency_limit", 1)),
                "liveness": "FRESH" if fresh else "STALE",
            })
        return result

    def dispatch(self, plan: object, manifest: object, *, worker_id: str | None = None, replicas: int = 1, request_id: str | None = None, challenge: dict[str, Any] | None = None, consumer_context: dict[str, Any] | None = None, execution_bundle_archive: Path | None = None, placement: Mapping[str, Any] | None = None, runtime_observation: Mapping[str, Any] | None = None, runtime_capability_observation: Mapping[str, Any] | None = None, expected_session_id: str | None = None, expected_session_generation: int | None = None) -> list[dict[str, Any]]:
        from .api import _consumer_result
        from .bundle_transfer import transfer_archive
        from .controller import NetworkController
        from .models import validate_job_plan

        checked = validate_job_plan(plan)
        if not isinstance(manifest, dict) or manifest.get("manifest_identity") != checked["artifact_manifest_identity"]:
            raise ProtocolError("controller dispatch requires a matching manifest")
        with self._lock:
            sessions = {session.worker_id: session for session in self.sessions.values() if not session.closed and time.monotonic() - session.last_seen <= self.heartbeat_seconds * 3}
            known = self._known_workers()
        sessions = {
            identity: session
            for identity, session in sessions.items()
            if self._member_allowed(known.get(identity))
        }
        if worker_id is not None:
            if worker_id in known and not self._member_allowed(known.get(worker_id)):
                raise ProtocolError("worker Fabric membership is not active")
            sessions = {worker_id: sessions[worker_id]} if worker_id in sessions else {}
        if expected_session_id is not None or expected_session_generation is not None:
            if worker_id is None:
                raise ProtocolError("session-bound dispatch requires one exact worker")
            session = sessions.get(worker_id)
            if (
                session is None
                or session.session_id != expected_session_id
                or session.generation != expected_session_generation
            ):
                raise ProtocolError("worker rendezvous session changed after target admission")
        slots = [WorkerSlot(worker_id=key, capabilities=frozenset(capability_names(value.description["node"])), concurrency_limit=int(known.get(key, {}).get("concurrency_limit", 1)), resource_snapshot=value.description.get("resource_snapshot")) for key, value in sessions.items()]
        decision = schedule(checked, slots, replicas=replicas, placement=placement)
        if decision.disposition != "PASS":
            return [{"disposition": decision.disposition, "reason": decision.reason, "worker_ids": list(decision.worker_ids), "admissions": list(decision.admissions)}]
        network = NetworkController(self.controller_id, self.ledger.path)
        results: list[dict[str, Any]] = []
        for selected in decision.worker_ids:
            session = sessions[selected]
            transport = session.transport
            bundle = None
            if execution_bundle_archive is not None:
                report = transfer_archive(transport, controller_id=self.controller_id, worker_id=selected, archive=Path(execution_bundle_archive))
                bundle = {"bundle_identity": report["bundle_identity"], "archive_identity": report["archive_identity"]}
            response = network.dispatch_via(transport, checked, manifest, worker_id=selected, request_id=request_id or sha256_identity({"job": checked["job_identity"], "worker": selected}), challenge=challenge, consumer_context=consumer_context, execution_bundle=bundle, placement_request=placement, runtime_observation=runtime_observation, runtime_capability_observation=runtime_capability_observation)
            results.append(_consumer_result(response, None))
        return results

    def _ack(self, session: RendezvousSession, command: dict[str, object] | None) -> dict[str, object]:
        return make_envelope("worker.heartbeat.ack", controller_id=self.controller_id, worker_id=session.worker_id, request_id="ack-" + session.session_id, job_id="worker-session", nonce=sha256_identity({"session": session.session_id, "seen": session.last_seen})[7:39], payload={"session_id": session.session_id, "generation": session.generation, "command": command}, created_at=utc_now(), expires_at=_expiry(60))

    def _generation(self, worker_id: str) -> int:
        values = [entry["record"].get("generation", 0) for entry in self.ledger.records(record_type="worker.rendezvous") if entry["record"].get("worker_id") == worker_id]
        return max((int(value) for value in values), default=0)

    def _known_workers(self) -> dict[str, Mapping[str, Any]]:
        values: dict[str, Mapping[str, Any]] = dict(self.known_workers)
        if self.membership_provider is not None:
            values.update(self.membership_provider())
        return values

    def _member_allowed(self, membership: Mapping[str, Any] | None) -> bool:
        """Treat lifecycle tombstones as authoritative over registry presence."""

        if membership is None:
            return not self.membership_authority
        status = membership.get("membership_status")
        return status is None or status == "ENROLLED"

    def revoke_worker(self, worker_id: str) -> list[str]:
        """Immediately terminate every live session for a revoked identity."""

        with self._lock:
            revoked = [
                session
                for session in self.sessions.values()
                if session.worker_id == worker_id and not session.closed
            ]
            for session in revoked:
                session.close()
                self._record("revoked", session)
        return [session.session_id for session in revoked]

    def _record(self, event: str, session: RendezvousSession) -> None:
        record = {"schema_version": RENDEZVOUS_SCHEMA, "event": event, "worker_id": session.worker_id, "session_id": session.session_id, "generation": session.generation, "certificate_fingerprint": session.certificate_fingerprint, "observed_at": utc_now(), "description": dict(session.description)}
        self.ledger.append("worker.rendezvous", attach_identity(record, "rendezvous_event_id"))
