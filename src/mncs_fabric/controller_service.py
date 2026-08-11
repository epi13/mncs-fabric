"""Platform-neutral foreground controller service foundation.

The runtime owns durable lifecycle state independently of any consumer
process.  It intentionally has no LAN administrative listener and no worker
rendezvous transport yet; systemd or another supervisor can invoke the same
bounded foreground command later.
"""

from __future__ import annotations

import signal
import time
from dataclasses import dataclass
from pathlib import Path
from threading import Event
from typing import Any

from .canonical import attach_identity
from .errors import ValidationError
from .lifecycle import LifecycleStore, default_lifecycle_path, default_state_dir
from .node import utc_now

CONTROLLER_CONFIG_SCHEMA = "mncs-fabric.controller-config.v0.1"
CONTROLLER_SERVICE_SCHEMA = "mncs-fabric.controller-service.v0.1"


@dataclass(frozen=True, slots=True)
class ControllerConfig:
    controller_id: str
    lifecycle_state: Path
    heartbeat_seconds: float = 5.0

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
            "administrative_transport": "none; foreground/local supervisor only",
            "worker_rendezvous": "planned",
        }


def default_controller_config() -> ControllerConfig:
    return ControllerConfig("local", default_lifecycle_path())


def controller_paths() -> dict[str, Path]:
    root = default_state_dir()
    return {"config_dir": root, "state_dir": root, "lifecycle": root / "lifecycle.jsonl", "service_log": root / "controller-service.jsonl"}


class ControllerService:
    """A restart-safe lifecycle owner suitable for a thin OS supervisor."""

    def __init__(self, config: ControllerConfig | None = None) -> None:
        self.config = config or default_controller_config()
        self.lifecycle = LifecycleStore(self.config.lifecycle_state)
        self._stop = Event()

    def status(self, *, now: str | None = None) -> dict[str, Any]:
        health = self.lifecycle.doctor(now=now)
        return {
            "schema_version": CONTROLLER_SERVICE_SCHEMA,
            "outcome": health["outcome"],
            "controller_id": self.config.controller_id,
            "service_owner": "mncs-fabric-controller",
            "configured": True,
            "persistent_state": str(self.config.lifecycle_state),
            "lifecycle": health,
            "worker_rendezvous": "PLANNED",
            "consumer_transport": "IN_PROCESS_OR_SHARED_STATE",
            "claim_boundary": "controller health is independent from worker availability and consumer connection",
        }

    def doctor(self, *, now: str | None = None) -> dict[str, Any]:
        result = self.status(now=now)
        result["checks"] = {
            "config": "PASS",
            "lifecycle_ledger": result["lifecycle"]["outcome"],
            "administrative_listener": "NOT_EXPOSED",
            "worker_rendezvous": "NOT_IMPLEMENTED",
        }
        return result

    def request_stop(self) -> None:
        self._stop.set()

    def run(self, *, max_seconds: float | None = None) -> dict[str, Any]:
        if max_seconds is not None and not 0 < max_seconds <= 24 * 60 * 60:
            raise ValidationError("max_seconds is outside the bounded range")
        started = time.monotonic()
        events = self.lifecycle.ledger
        start = attach_identity({
            "schema_version": CONTROLLER_SERVICE_SCHEMA,
            "controller_id": self.config.controller_id,
            "event": "started",
            "observed_at": utc_now(),
        }, "service_event_id")
        events.append("controller.service", start)
        previous_handlers: dict[int, Any] = {}

        def stop_handler(signum: int, _frame: Any) -> None:
            self.request_stop()

        for signum in (signal.SIGTERM, signal.SIGINT):
            try:
                previous_handlers[signum] = signal.getsignal(signum)
                signal.signal(signum, stop_handler)
            except (OSError, ValueError):
                pass
        try:
            while not self._stop.is_set():
                if max_seconds is not None and time.monotonic() - started >= max_seconds:
                    break
                time.sleep(min(self.config.heartbeat_seconds, 0.25))
        finally:
            for signum, handler in previous_handlers.items():
                signal.signal(signum, handler)
            stop = attach_identity({
                "schema_version": CONTROLLER_SERVICE_SCHEMA,
                "controller_id": self.config.controller_id,
                "event": "stopped",
                "observed_at": utc_now(),
            }, "service_event_id")
            events.append("controller.service", stop)
        return {"outcome": "PASS", "controller_id": self.config.controller_id, "event": "stopped"}
