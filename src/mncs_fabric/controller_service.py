"""Platform-neutral foreground controller service foundation.

The runtime owns durable lifecycle state independently of any consumer
process.  It intentionally has no LAN administrative listener and no worker
rendezvous transport yet; systemd or another supervisor can invoke the same
bounded foreground command later.
"""

from __future__ import annotations

import signal
import time
import os
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from threading import Event
from typing import Any, Mapping

from .canonical import attach_identity
from .errors import FabricError, ProtocolError, ValidationError
from .lifecycle import LifecycleStore, default_lifecycle_path, default_state_dir
from .node import utc_now
from .store import FabricLedger

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

    def __post_init__(self) -> None:
        if not self.controller_id or len(self.controller_id) > 128 or "\x00" in self.controller_id:
            raise ValidationError("controller_id is invalid")
        if not 0.5 <= self.heartbeat_seconds <= 60:
            raise ValidationError("controller heartbeat is outside the bounded range")

    def public_dict(self) -> dict[str, Any]:
        return {
            "schema_version": CONTROLLER_CONFIG_SCHEMA,
            "controller_id": self.controller_id,
            "lifecycle_state": str(self.lifecycle_state),
            "heartbeat_seconds": self.heartbeat_seconds,
            "service_log": str(self.service_log_path),
            "socket_path": str(self.socket_path_value),
            "admin_socket_path": str(self.admin_socket_path_value),
            "administrative_transport": "separate local operator socket",
            "worker_rendezvous": "planned",
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
            "lifecycle": health,
            "worker_rendezvous": "PLANNED",
            "consumer_transport": "LOCAL_UNIX_SOCKET" if os.name == "posix" else "PLANNED_WINDOWS_LOCAL_TRANSPORT",
            "claim_boundary": "controller health is independent from worker availability and consumer connection",
        }

    def doctor(self, *, now: str | None = None) -> dict[str, Any]:
        result = self.status(now=now)
        result["checks"] = {
            "config": "PASS",
            "lifecycle_ledger": result["lifecycle"]["outcome"],
            "service_ledger": result["service_ledger"]["outcome"],
            "administrative_listener": "LOCAL_OPERATOR_SOCKET" if os.name == "posix" else "NOT_IMPLEMENTED",
            "worker_rendezvous": "NOT_IMPLEMENTED",
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
                payload = {"workers": self.lifecycle.memberships()}
            elif operation in {"fleet.status", "worker.status", "worker.observations"}:
                payload = self.lifecycle.membership(str(args.get("worker_id")))
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
