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
from .store import FabricLedger, iter_ledger_records


def certificate_fingerprint(certificate_der: bytes) -> str:
    return "sha256:" + hashlib.sha256(certificate_der).hexdigest()


class TrustStore:
    def __init__(self, state_path: Path) -> None:
        self.ledger = FabricLedger(Path(state_path))
        self._cache: dict[tuple[str, str], dict[str, Any]] = {}
        self._cache_token: tuple[int, int] | None = None

    def _ensure_cache(self) -> dict[tuple[str, str], dict[str, Any]]:
        if not self.ledger.path.exists():
            self._cache = {}
            self._cache_token = None
            return self._cache
        stat = self.ledger.path.stat()
        token = (stat.st_size, stat.st_mtime_ns)
        if token != self._cache_token:
            cache: dict[tuple[str, str], dict[str, Any]] = {}
            for entry in iter_ledger_records(self.ledger):
                rec = entry.get("record", {})
                itype = rec.get("identity_type")
                ident = rec.get("identity")
                event = rec.get("event")
                if itype and ident and event in {"enrolled", "revoked"}:
                    cache[(str(itype), str(ident))] = rec
            self._cache = cache
            self._cache_token = token
        return self._cache

    def enroll(self, identity_type: str, identity: str, fingerprint: str, *, metadata: dict[str, Any] | None = None) -> dict[str, Any]:
        if identity_type not in {"controller", "worker"} or not identity or not fingerprint.startswith("sha256:"):
            raise ProtocolError("trust enrollment requires a controller/worker and certificate fingerprint")
        current = self.lookup(identity_type, identity)
        if current and current["active"] and current["certificate_fingerprint"] != fingerprint:
            raise ProtocolError("active identity cannot be rebound without explicit revocation")
        record = {"identity_type": identity_type, "identity": identity, "certificate_fingerprint": fingerprint, "active": True, "metadata": metadata or {}, "event": "enrolled"}
        entry = self.ledger.append("trust.enrollment", record)
        self._cache[(identity_type, identity)] = record
        if self.ledger.path.exists():
            stat = self.ledger.path.stat()
            self._cache_token = (stat.st_size, stat.st_mtime_ns)
        return entry

    def revoke(self, identity_type: str, identity: str, *, reason: str) -> dict[str, Any]:
        current = self.lookup(identity_type, identity)
        if current is None:
            raise ProtocolError("cannot revoke an unknown identity")
        record = {"identity_type": identity_type, "identity": identity, "certificate_fingerprint": current["certificate_fingerprint"], "active": False, "metadata": {"reason": reason}, "event": "revoked"}
        entry = self.ledger.append("trust.revocation", record)
        self._cache[(identity_type, identity)] = record
        if self.ledger.path.exists():
            stat = self.ledger.path.stat()
            self._cache_token = (stat.st_size, stat.st_mtime_ns)
        return entry

    def lookup(self, identity_type: str, identity: str) -> dict[str, Any] | None:
        # Authorization decisions require the complete trust ledger; a bounded
        # read could hide an enrollment or revocation and fail open/closed for
        # the wrong reason. We project the latest state per identity and memoize
        # on the ledger stat token.
        cache = self._ensure_cache()
        return cache.get((identity_type, identity))

    def authorize(self, identity_type: str, identity: str, fingerprint: str) -> None:
        current = self.lookup(identity_type, identity)
        if current is None:
            raise ProtocolError("unknown certificate identity")
        if not current.get("active"):
            raise ProtocolError("certificate identity is revoked")
        if current.get("certificate_fingerprint") != fingerprint:
            raise ProtocolError("certificate fingerprint does not match enrolled identity")
