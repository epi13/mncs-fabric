"""Platform-neutral foreground controller service.

The runtime owns durable lifecycle state independently of any consumer
process. Worker endpoint configuration remains controller-owned for direct
compatibility mode; consumers never load the registry or worker credentials.
When explicitly configured, workers may instead establish an authenticated
worker-initiated rendezvous session owned by this runtime.
"""

from __future__ import annotations

import signal
import time
import os
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from threading import Event, Thread
from typing import Any, Mapping

from .canonical import attach_identity
from .errors import FabricError, ProtocolError, ValidationError
from .lifecycle import LifecycleStore, default_lifecycle_path, default_state_dir
from .node import utc_now
from .store import FabricLedger
from .enrollment import TrustStore
from .rendezvous import RendezvousCoordinator
from .transport import TLSRendezvousServer

CONTROLLER_CONFIG_SCHEMA = "mncs-fabric.controller-config.v0.2"
CONTROLLER_SERVICE_SCHEMA = "mncs-fabric.controller-service.v0.1"


@dataclass(frozen=True, slots=True)
class ControllerConfig:
    controller_id: str
    lifecycle_state: Path
    heartbeat_seconds: float = 5.0
    service_log: Path | None = None
    socket_path: Path | None = None
    admin_socket_path: Path | None = None
    worker_registry_path: Path | None = None
    worker_state_path: Path | None = None
    execution_bundle_root: Path | None = None
    rendezvous_host: str | None = None
    rendezvous_port: int | None = None
    rendezvous_ca: Path | None = None
    rendezvous_certificate: Path | None = None
    rendezvous_key: Path | None = None
    rendezvous_trust_state: Path | None = None

    def __post_init__(self) -> None:
        if not self.controller_id or len(self.controller_id) > 128 or "\x00" in self.controller_id:
            raise ValidationError("controller_id is invalid")
        if not 0.5 <= self.heartbeat_seconds <= 60:
            raise ValidationError("controller heartbeat is outside the bounded range")
        if self.rendezvous_port is not None and not 0 <= self.rendezvous_port <= 65535:
            raise ValidationError("rendezvous port is outside the bounded range")
        paths = (self.rendezvous_ca, self.rendezvous_certificate, self.rendezvous_key, self.rendezvous_trust_state)
        if any(value is not None for value in paths) and not all(value is not None for value in paths):
            raise ValidationError("rendezvous TLS configuration must be complete")

    def public_dict(self) -> dict[str, Any]:
        return {
            "schema_version": CONTROLLER_CONFIG_SCHEMA,
            "controller_id": self.controller_id,
            "lifecycle_state": str(self.lifecycle_state),
            "heartbeat_seconds": self.heartbeat_seconds,
            "service_log": str(self.service_log_path),
            "socket_path": str(self.socket_path_value),
            "admin_socket_path": str(self.admin_socket_path_value),
            "worker_registry_path": str(self.worker_registry_path_value) if self.worker_registry_path is not None else None,
            "execution_bundle_root": str(self.execution_bundle_root_value),
            "rendezvous_host": self.rendezvous_host,
            "rendezvous_port": self.rendezvous_port,
            "administrative_transport": "separate local operator socket",
            "worker_rendezvous": "configured" if self.rendezvous_configured else "planned",
        }

    @property
    def service_log_path(self) -> Path:
        return Path(self.service_log) if self.service_log is not None else self.lifecycle_state.with_name("controller-service.jsonl")

    @property
    def socket_path_value(self) -> Path:
        return Path(self.socket_path) if self.socket_path is not None else self.lifecycle_state.with_name("controller.sock")

    @property
    def admin_socket_path_value(self) -> Path:
        return Path(self.admin_socket_path) if self.admin_socket_path is not None else self.lifecycle_state.with_name("controller-admin.sock")

    @property
    def worker_registry_path_value(self) -> Path | None:
        return Path(self.worker_registry_path).expanduser() if self.worker_registry_path is not None else None

    @property
    def worker_state_path_value(self) -> Path:
        return Path(self.worker_state_path).expanduser() if self.worker_state_path is not None else self.lifecycle_state.with_name("controller-workers.jsonl")

    @property
    def execution_bundle_root_value(self) -> Path:
        return Path(self.execution_bundle_root).expanduser() if self.execution_bundle_root is not None else self.lifecycle_state.parent / "execution-bundles"

    @property
    def rendezvous_configured(self) -> bool:
        return self.rendezvous_host is not None and self.rendezvous_port is not None and all(value is not None for value in (self.rendezvous_ca, self.rendezvous_certificate, self.rendezvous_key, self.rendezvous_trust_state))


def default_controller_config() -> ControllerConfig:
    return ControllerConfig("local", default_lifecycle_path())


def controller_paths() -> dict[str, Path]:
    root = default_state_dir()
    return {"config_dir": root, "state_dir": root, "lifecycle": root / "lifecycle.jsonl", "service_log": root / "controller-service.jsonl", "socket": root / "controller.sock", "admin_socket": root / "controller-admin.sock"}


class ControllerService:
    """A restart-safe lifecycle owner suitable for a thin OS supervisor."""

    def __init__(self, config: ControllerConfig | None = None) -> None:
        self.config = config or default_controller_config()
        self.lifecycle = LifecycleStore(self.config.lifecycle_state)
        self.service_ledger = FabricLedger(self.config.service_log_path)
        self._stop = Event()
        self._worker_client: Any | None = None
        self._worker_registry_report: dict[str, Any] | None = None
        self._rendezvous: RendezvousCoordinator | None = None
        self._rendezvous_server: TLSRendezvousServer | None = None
        if self.config.worker_registry_path_value is not None:
            from .api import FabricClient

            self._worker_client = FabricClient(
                self.config.controller_id,
                self.config.worker_state_path_value,
                lifecycle_state_path=self.config.lifecycle_state,
            )
            self._worker_registry_report = self._worker_client.load_registry(
                self.config.worker_registry_path_value
            )
            if self.config.rendezvous_configured:
                known = {
                    str(worker_id): dict(worker)
                    for worker_id, worker in getattr(self._worker_client, "registry_entries", {}).items()
                    if isinstance(worker, dict)
                }
                self._rendezvous = RendezvousCoordinator(
                    self.config.controller_id,
                    self.config.worker_state_path_value.with_name("rendezvous.jsonl"),
                    known_workers=known,
                    heartbeat_seconds=self.config.heartbeat_seconds,
                )

    @property
    def worker_backend_enabled(self) -> bool:
        return self._worker_client is not None

    @property
    def rendezvous_ready(self) -> bool:
        return self._rendezvous is not None and self._rendezvous_server is not None

    def _worker_backend_status(self) -> tuple[list[dict[str, Any]], dict[str, Any] | None]:
        if self._worker_client is None:
            return [], self._worker_registry_report
        if self.rendezvous_ready and self._rendezvous is not None:
            return self._rendezvous.states(), self._worker_registry_report
        try:
            self._worker_client.refresh_workers()
        except Exception as exc:
            self._worker_registry_report = {
                **(self._worker_registry_report or {}),
                "refresh_error": str(exc),
            }
        return [dict(worker) for worker in self._worker_client.workers()], self._worker_registry_report

    def status(self, *, now: str | None = None) -> dict[str, Any]:
        # Import lazily to keep the controller-service module importable while
        # the package surface is being initialized.
        from . import __version__
        from .contracts import build_public_contract

        health = self.lifecycle.doctor(now=now)
        service_health = self.service_ledger.verify()
        service_events = self.service_ledger.records(record_type="controller.service")
        latest_event = service_events[-1]["record"].get("event") if service_events else None
        runtime = "RUNNING" if latest_event == "started" else "STOPPED" if latest_event == "stopped" else "NOT_STARTED"
        public_contract = build_public_contract(__version__)
        workers, registry = self._worker_backend_status()
        from .contracts import service_feature_projection

        service_features = service_feature_projection(worker_backend=self.worker_backend_enabled, worker_rendezvous=self.rendezvous_ready)
        return {
            "schema_version": CONTROLLER_SERVICE_SCHEMA,
            "fabric_version": __version__,
            "service_contract": CONTROLLER_SERVICE_SCHEMA,
            "public_api_version": public_contract["public_api_version"],
            "public_contract_identity": public_contract["contract_identity"],
            "outcome": "PASS" if health["outcome"] == "PASS" and service_health["outcome"] == "PASS" else "UNKNOWN",
            "controller_id": self.config.controller_id,
            "service_owner": "mncs-fabric-controller",
            "configured": True,
            "persistent_state": str(self.config.lifecycle_state),
            "service_log": str(self.config.service_log_path),
            "service_ledger": service_health,
            "service_runtime": runtime,
            "consumer_socket": str(self.config.socket_path_value),
            "admin_socket": str(self.config.admin_socket_path_value),
            "rendezvous_endpoint": f"{self.config.rendezvous_host}:{self.config.rendezvous_port}" if self.config.rendezvous_configured else None,
            "lifecycle": health,
            "worker_rendezvous": "RUNNING" if self.rendezvous_ready else "CONFIGURED" if self._rendezvous is not None else "PLANNED",
            "consumer_transport": "LOCAL_UNIX_SOCKET" if os.name == "posix" else "PLANNED_WINDOWS_LOCAL_TRANSPORT",
            "claim_boundary": "controller health is independent from worker availability and consumer connection",
            "fleet": {"workers": workers, "registry": registry},
            "service_features": service_features,
        }

    def doctor(self, *, now: str | None = None) -> dict[str, Any]:
        result = self.status(now=now)
        result["checks"] = {
            "config": "PASS",
            "lifecycle_ledger": result["lifecycle"]["outcome"],
            "service_ledger": result["service_ledger"]["outcome"],
            "administrative_listener": "LOCAL_OPERATOR_SOCKET" if os.name == "posix" else "NOT_IMPLEMENTED",
            "worker_rendezvous": "PASS" if self.rendezvous_ready else "CONFIGURED_NOT_STARTED" if self._rendezvous is not None else "NOT_CONFIGURED",
            "persistent_service_execution": "CONTROLLER_MANAGED_ENDPOINTS" if self.worker_backend_enabled else "NOT_CONFIGURED",
        }
        return result

    def handle_service_request(self, request: Mapping[str, Any], *, role: str) -> dict[str, Any]:
        """Serve one already-framed local consumer or operator request."""

        from .service_transport import (
            _ADMIN_OPERATIONS,
            _OPERATIONS,
            _response,
            _validate_request,
        )

        request = _validate_request(request)
        operation = request["operation"]
        if role not in {"consumer", "admin"} or operation not in _OPERATIONS:
            return _response(request, self.config.controller_id, "FAIL", error={"code": "UNAUTHORIZED_OPERATION", "message": "service operation is not authorized"})
        now = datetime.now(timezone.utc)
        expires = datetime.fromisoformat(request["expires_at"].replace("Z", "+00:00"))
        if expires <= now:
            return _response(request, self.config.controller_id, "UNKNOWN", error={"code": "REQUEST_EXPIRED", "message": "service request deadline has expired"})
        event = {
            "schema_version": CONTROLLER_SERVICE_SCHEMA,
            "event": "request",
            "request_id": request["request_id"],
            "client_identity": request["client_identity"],
            "role": role,
            "operation": operation,
            "observed_at": utc_now(),
        }

        def new_request(records: list[dict[str, Any]]) -> None:
            if any(entry["record"].get("event") == "request" and entry["record"].get("request_id") == request["request_id"] for entry in records):
                raise ProtocolError("service request replay detected")

        self.service_ledger.append_if("controller.service-request", attach_identity(event, "service_event_id"), new_request)
        if operation in _ADMIN_OPERATIONS and role != "admin":
            return _response(request, self.config.controller_id, "FAIL", error={"code": "UNAUTHORIZED_ADMIN_OPERATION", "message": "administrative operation requires the operator service surface"})
        args = request["arguments"]
        try:
            if operation == "controller.status":
                payload = self.status()
            elif operation == "controller.doctor":
                payload = self.doctor()
            elif operation == "fleet.list":
                payload = {"workers": self._worker_backend_status()[0] if self._worker_client is not None else self.lifecycle.memberships()}
            elif operation in {"fleet.status", "worker.status", "worker.observations"}:
                worker_id = str(args.get("worker_id"))
                if self._worker_client is not None:
                    payload = next((worker for worker in self._worker_backend_status()[0] if worker.get("worker_id") == worker_id), None)
                    if payload is None:
                        raise ProtocolError("worker is not known to the controller")
                else:
                    payload = self.lifecycle.membership(worker_id)
            elif operation == "fleet.doctor":
                payload = self.lifecycle.doctor()
            elif operation == "enrollment.create":
                payload = self.lifecycle.create_authorization(
                    ttl_seconds=float(args.get("ttl_seconds", 600.0)),
                    expected_worker_identity=args.get("expected_worker_identity"),
                    metadata=args.get("metadata"),
                )
            elif operation == "enrollment.list":
                payload = {"authorizations": self.lifecycle.list_authorizations()}
            elif operation == "enrollment.pending":
                payload = {"requests": self.lifecycle.pending_requests()}
            elif operation == "enrollment.inspect":
                payload = self.lifecycle.request(str(args.get("request_id")))
            elif operation == "enrollment.approve":
                payload = self.lifecycle.approve_request(str(args.get("request_id")), worker_id=args.get("worker_id"))
            elif operation == "enrollment.deny":
                payload = self.lifecycle.deny_request(str(args.get("request_id")), reason=str(args.get("reason", "operator denied enrollment")))
            elif operation == "enrollment.expire":
                payload = self.lifecycle.expire_request(str(args.get("request_id")))
            elif operation == "worker.revoke":
                payload = self.lifecycle.revoke_worker(str(args.get("worker_id")), reason=str(args.get("reason", "operator revoked worker")))
            elif operation == "execution.dispatch":
                if self._worker_client is None:
                    raise ProtocolError("persistent execution backend is not configured")
                archive = Path(str(args.get("execution_bundle_archive", ""))).expanduser().resolve(strict=True)
                try:
                    archive.relative_to(self.config.execution_bundle_root_value.resolve())
                except ValueError as exc:
                    raise ProtocolError("execution bundle is outside the controller bundle root") from exc
                if self.rendezvous_ready and self._rendezvous is not None:
                    results = self._rendezvous.dispatch(
                        args["plan"], args["manifest"], worker_id=args.get("worker_id"), replicas=int(args.get("replicas", 1)), request_id=args.get("request_id"), challenge=args.get("challenge"), consumer_context=args.get("consumer_context"), execution_bundle_archive=archive, placement=args.get("placement"), runtime_observation=args.get("runtime_observation"), runtime_capability_observation=args.get("runtime_capability_observation"),
                    )
                    execution_transport = "worker-initiated-persistent-rendezvous"
                else:
                    results = self._worker_client.execute(
                        args["plan"], args["manifest"], worker_id=args.get("worker_id"), replicas=int(args.get("replicas", 1)), request_id=args.get("request_id"), challenge=args.get("challenge"), consumer_context=args.get("consumer_context"), execution_bundle_archive=archive, placement=args.get("placement"), runtime_observation=args.get("runtime_observation"), runtime_capability_observation=args.get("runtime_capability_observation"),
                    )
                    execution_transport = "controller-managed-authenticated-worker-endpoint"
                payload = {"results": results, "execution_transport": execution_transport, "fleet_authority": "persistent-controller"}
            elif operation == "worker.capability.ingest":
                if self._worker_client is None:
                    raise ProtocolError("persistent capability backend is not configured")
                worker_id = str(args.get("worker_id", ""))
                capabilities = args.get("capabilities")
                if not isinstance(capabilities, list):
                    raise ValidationError("capabilities must be an array")
                payload = {
                    "observation": self._worker_client.ingest_capability_observation(
                        worker_id,
                        capabilities,
                        availability=str(args.get("availability", "AVAILABLE")),
                        captured_at=args.get("captured_at"),
                        observation_source=str(
                            args.get("observation_source", "consumer-bounded-worker-probe")
                        ),
                        status_reason=args.get("status_reason"),
                    ),
                    "fleet_authority": "persistent-controller",
                }
            elif operation == "worker.capability.observations":
                if self._worker_client is None:
                    raise ProtocolError("persistent capability backend is not configured")
                worker_id = str(args.get("worker_id", ""))
                payload = {
                    "observations": self._worker_client.capability_observations(
                        worker_id,
                        limit=int(args.get("limit", 1000)),
                    ),
                    "fleet_authority": "persistent-controller",
                }
            else:
                return _response(request, self.config.controller_id, "FAIL", error={"code": "UNKNOWN_OPERATION", "message": "service operation is unsupported"})
        except (FabricError, ValueError) as exc:
            return _response(request, self.config.controller_id, "FAIL", error={"code": "OPERATION_FAILED", "message": str(exc)})
        return _response(request, self.config.controller_id, "PASS", payload=payload)

    def request_stop(self) -> None:
        self._stop.set()

    def run(self, *, max_seconds: float | None = None) -> dict[str, Any]:
        if max_seconds is not None and not 0 < max_seconds <= 24 * 60 * 60:
            raise ValidationError("max_seconds is outside the bounded range")
        started = time.monotonic()
        self._stop.clear()
        events = self.service_ledger
        from .service_transport import ControllerServiceServer, ControllerServiceOwnership

        ownership = ControllerServiceOwnership(self.config.lifecycle_state.with_name("controller.owner.lock"))
        ownership.acquire()
        server = ControllerServiceServer(self)
        rendezvous_server: TLSRendezvousServer | None = None
        previous_handlers: dict[int, Any] = {}

        def stop_handler(signum: int, _frame: Any) -> None:
            self.request_stop()

        try:
            start = attach_identity({
                "schema_version": CONTROLLER_SERVICE_SCHEMA,
                "controller_id": self.config.controller_id,
                "event": "started",
                "observed_at": utc_now(),
            }, "service_event_id")
            events.append("controller.service", start)
            for signum in (signal.SIGTERM, signal.SIGINT):
                try:
                    previous_handlers[signum] = signal.getsignal(signum)
                    signal.signal(signum, stop_handler)
                except (OSError, ValueError):
                    pass
            try:
                server.start()
                if self._rendezvous is not None and self.config.rendezvous_configured:
                    rendezvous_server = TLSRendezvousServer(
                        self.config.rendezvous_host or "127.0.0.1",
                        int(self.config.rendezvous_port or 0),
                        ca_file=Path(self.config.rendezvous_ca),
                        server_cert=Path(self.config.rendezvous_certificate),
                        server_key=Path(self.config.rendezvous_key),
                        controller_id=self.config.controller_id,
                        trust_store=TrustStore(Path(self.config.rendezvous_trust_state)),
                        on_open=self._rendezvous.open,
                        on_message=self._rendezvous.message,
                        on_close=self._rendezvous.close,
                        timeout=self.config.heartbeat_seconds,
                    )
                    rendezvous_server.bind()
                    self._rendezvous_server = rendezvous_server
                    Thread(target=rendezvous_server.serve_forever, daemon=True, name="mncs-fabric-rendezvous").start()
            except ProtocolError:
                if os.name == "posix":
                    raise
                # The platform-neutral runtime remains useful under a Windows
                # supervisor while named-pipe transport is still planned.
                server = ControllerServiceServer(self)
            while not self._stop.is_set():
                if max_seconds is not None and time.monotonic() - started >= max_seconds:
                    break
                time.sleep(min(self.config.heartbeat_seconds, 0.25))
        finally:
            if rendezvous_server is not None:
                rendezvous_server.close()
                self._rendezvous_server = None
            if self._worker_client is not None:
                self._worker_client.close()
            try:
                server.close()
            finally:
                for signum, handler in previous_handlers.items():
                    try:
                        signal.signal(signum, handler)
                    except (OSError, ValueError):
                        pass
                try:
                    stop = attach_identity({
                        "schema_version": CONTROLLER_SERVICE_SCHEMA,
                        "controller_id": self.config.controller_id,
                        "event": "stopped",
                        "observed_at": utc_now(),
                    }, "service_event_id")
                    events.append("controller.service", stop)
                finally:
                    ownership.release()
        return {"outcome": "PASS", "controller_id": self.config.controller_id, "event": "stopped"}
