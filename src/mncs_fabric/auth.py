"""Optional message authentication for the local protocol boundary.

This module authenticates canonical messages; it does not encrypt transport or
make an operator-controlled worker independent. Keys are supplied by the
operator and are never generated or persisted by Fabric.
"""

from __future__ import annotations

import hashlib
import hmac
from dataclasses import dataclass
from typing import Mapping

from .canonical import canonical_json_bytes
from .errors import ProtocolError


@dataclass(frozen=True)
class KeyRecord:
    key_id: str
    secret: bytes
    active: bool = True
    revoked: bool = False


class Keyring:
    """Explicit key-id lookup with fail-closed unknown and revoked keys."""

    def __init__(self, records: Mapping[str, KeyRecord]) -> None:
        self._records = dict(records)

    def sign(self, key_id: str, value: object) -> str:
        if not isinstance(key_id, str):
            raise ProtocolError("authentication key ID must be a string")
        record = self._records.get(key_id)
        if record is None or record.revoked or not record.active:
            raise ProtocolError(f"authentication key is unavailable: {key_id}")
        return hmac.new(record.secret, canonical_json_bytes(value), hashlib.sha256).hexdigest()

    def verify(self, key_id: str, value: object, mac: object) -> None:
        if not isinstance(key_id, str):
            raise ProtocolError("authentication key ID must be a string")
        record = self._records.get(key_id)
        if record is None or record.revoked or not record.active:
            raise ProtocolError(f"authentication key is unknown or revoked: {key_id}")
        if not isinstance(mac, str):
            raise ProtocolError("authentication MAC must be a hexadecimal string")
        expected = hmac.new(record.secret, canonical_json_bytes(value), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(expected, mac):
            raise ProtocolError("message authentication failed")
