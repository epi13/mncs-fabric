"""Small deterministic transport fault controls for adversarial tests only."""

from __future__ import annotations

import time
from dataclasses import dataclass

from .errors import ProtocolError
from .transport import EnvelopeTransport


@dataclass(frozen=True)
class FaultPlan:
    mode: str
    delay_seconds: float = 0.0


class FaultInjectingTransport:
    """Bounded wrapper; it is not a general network manipulation facility."""

    def __init__(self, transport: EnvelopeTransport, plan: FaultPlan) -> None:
        if plan.mode not in {"delay", "drop-request", "duplicate-request"} or plan.delay_seconds < 0 or plan.delay_seconds > 30:
            raise ValueError("unsupported or unbounded fault plan")
        self.transport = transport
        self.plan = plan

    def request(self, envelope: dict[str, object]) -> dict[str, object]:
        if self.plan.mode == "delay":
            time.sleep(self.plan.delay_seconds)
        if self.plan.mode == "drop-request":
            raise ProtocolError("FAULT_INJECTED: request dropped")
        first = self.transport.request(envelope)
        if self.plan.mode == "duplicate-request":
            duplicate = self.transport.request(envelope)
            first_result = first.get("payload", {}).get("result_identity") if isinstance(first.get("payload"), dict) else None
            duplicate_result = duplicate.get("payload", {}).get("result_identity") if isinstance(duplicate.get("payload"), dict) else None
            if first.get("message_type") != duplicate.get("message_type") or first_result != duplicate_result:
                raise ProtocolError("FAULT_INJECTED: duplicate response differed")
        return first
