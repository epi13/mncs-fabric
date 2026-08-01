from __future__ import annotations

import hashlib
import json
from typing import Any, Mapping

IDENTITY_PREFIX = "sha256:"


def canonical_json_bytes(value: Any) -> bytes:
    """Return deterministic UTF-8 JSON bytes suitable for identity derivation."""
    return json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def sha256_identity_bytes(data: bytes) -> str:
    return IDENTITY_PREFIX + hashlib.sha256(data).hexdigest()


def sha256_identity(value: Any) -> str:
    return sha256_identity_bytes(canonical_json_bytes(value))


def identity_payload(record: Mapping[str, Any], identity_field: str) -> dict[str, Any]:
    payload = dict(record)
    payload.pop(identity_field, None)
    return payload


def attach_identity(record: Mapping[str, Any], identity_field: str) -> dict[str, Any]:
    payload = identity_payload(record, identity_field)
    payload[identity_field] = sha256_identity(payload)
    return payload


def verify_identity(record: Mapping[str, Any], identity_field: str) -> bool:
    actual = record.get(identity_field)
    return isinstance(actual, str) and actual == sha256_identity(identity_payload(record, identity_field))


def is_sha256_identity(value: object) -> bool:
    if not isinstance(value, str) or not value.startswith(IDENTITY_PREFIX):
        return False
    digest = value[len(IDENTITY_PREFIX):]
    return len(digest) == 64 and all(ch in "0123456789abcdef" for ch in digest)
