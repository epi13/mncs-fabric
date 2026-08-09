"""Operator-managed controller/worker trust state.

Fabric is not a certificate authority.  This ledger records which certificate
fingerprint is currently authorized for a logical Fabric identity.  Enrollment
and revocation are append-only decisions and unknown identities fail closed.
"""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any

from .errors import ProtocolError
from .store import FabricLedger


def certificate_fingerprint(certificate_der: bytes) -> str:
    return "sha256:" + hashlib.sha256(certificate_der).hexdigest()


class TrustStore:
    def __init__(self, state_path: Path) -> None:
        self.ledger = FabricLedger(Path(state_path))

    def enroll(self, identity_type: str, identity: str, fingerprint: str, *, metadata: dict[str, Any] | None = None) -> dict[str, Any]:
        if identity_type not in {"controller", "worker"} or not identity or not fingerprint.startswith("sha256:"):
            raise ProtocolError("trust enrollment requires a controller/worker and certificate fingerprint")
        current = self.lookup(identity_type, identity)
        if current and current["active"] and current["certificate_fingerprint"] != fingerprint:
            raise ProtocolError("active identity cannot be rebound without explicit revocation")
        record = {"identity_type": identity_type, "identity": identity, "certificate_fingerprint": fingerprint, "active": True, "metadata": metadata or {}, "event": "enrolled"}
        return self.ledger.append("trust.enrollment", record)

    def revoke(self, identity_type: str, identity: str, *, reason: str) -> dict[str, Any]:
        current = self.lookup(identity_type, identity)
        if current is None:
            raise ProtocolError("cannot revoke an unknown identity")
        record = {"identity_type": identity_type, "identity": identity, "certificate_fingerprint": current["certificate_fingerprint"], "active": False, "metadata": {"reason": reason}, "event": "revoked"}
        return self.ledger.append("trust.revocation", record)

    def lookup(self, identity_type: str, identity: str) -> dict[str, Any] | None:
        values = [entry["record"] for entry in self.ledger.records() if entry["record"].get("identity_type") == identity_type and entry["record"].get("identity") == identity and entry["record"].get("event") in {"enrolled", "revoked"}]
        return values[-1] if values else None

    def authorize(self, identity_type: str, identity: str, fingerprint: str) -> None:
        current = self.lookup(identity_type, identity)
        if current is None:
            raise ProtocolError("unknown certificate identity")
        if not current.get("active"):
            raise ProtocolError("certificate identity is revoked")
        if current.get("certificate_fingerprint") != fingerprint:
            raise ProtocolError("certificate fingerprint does not match enrolled identity")
