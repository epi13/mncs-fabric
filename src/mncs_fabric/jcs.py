"""Small RFC 8785-compatible JSON projection used by MNCS identities.

The EA-NEXT bundle contract uses raw SHA-256 digests of JCS bytes.  Fabric
keeps this narrow implementation local so bundle verification does not make
the runtime depend on another repository or a third-party package.
"""

from __future__ import annotations

import json
import math
from typing import Any


def _encode(value: Any) -> bytes:
    if value is None:
        return b"null"
    if value is True:
        return b"true"
    if value is False:
        return b"false"
    if isinstance(value, int) and not isinstance(value, bool):
        return str(value).encode("ascii")
    if isinstance(value, float):
        if not math.isfinite(value):
            raise ValueError("non-finite JSON number")
        if value == 0:
            return b"0"
        if value.is_integer():
            return str(int(value)).encode("ascii")
        text = repr(value).lower()
        if "e" in text:
            mantissa, exponent = text.split("e")
            exponent_value = int(exponent)
            text = mantissa + "e" + ("+" if exponent_value >= 0 else "") + str(exponent_value)
        return text.encode("ascii")
    if isinstance(value, str):
        return json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    if isinstance(value, list):
        return b"[" + b",".join(_encode(item) for item in value) + b"]"
    if isinstance(value, dict):
        items = sorted(value.items(), key=lambda item: str(item[0]).encode("utf-16-be"))
        return b"{" + b",".join(_encode(str(key)) + b":" + _encode(item) for key, item in items) + b"}"
    raise TypeError(f"unsupported JSON value: {type(value).__name__}")


def canonical_jcs_bytes(value: Any) -> bytes:
    return _encode(value)
