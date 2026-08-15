"""Canonical controller-owned worker backend surface.

The persistent controller talks to an embedded FabricClient in production.
Tests and Control fixtures may supply a narrower backend. Read operations
must not crash when that backend only implements ``workers()``.
"""

from __future__ import annotations

import inspect
from typing import Any, Protocol, runtime_checkable

from .errors import ProtocolError


@runtime_checkable
class WorkerBackend(Protocol):
    """Minimum controller-owned fleet backend.

    ``workers()`` returns last-known worker projections. ``apply_lease`` is
    optional: FabricClient uses it so last-known reads can retain the last
    observed availability. Backends that omit it already return last-known
    state as they define it.

    ``refresh_workers()`` is the explicit probe. ``refresh_fleet()`` is the
    classified, deadline-aware probe when the backend implements it.
    """

    def workers(self, *args: Any, **kwargs: Any) -> list[dict[str, Any]]: ...

    def refresh_workers(self) -> Any: ...

    def close(self) -> None: ...


def backend_supports_apply_lease(backend: Any) -> bool:
    method = getattr(backend, "workers", None)
    if not callable(method):
        return False
    try:
        signature = inspect.signature(method)
    except (TypeError, ValueError):
        return False
    parameters = signature.parameters
    if "apply_lease" in parameters:
        return True
    return any(item.kind is item.VAR_KEYWORD for item in parameters.values())


def list_backend_workers(backend: Any, *, apply_lease: bool = True) -> list[dict[str, Any]]:
    """List last-known workers without requiring a FabricClient-shaped backend."""

    method = getattr(backend, "workers", None)
    if not callable(method):
        raise ProtocolError("worker backend does not expose workers()")
    if backend_supports_apply_lease(backend):
        values = method(apply_lease=apply_lease)
    else:
        values = method()
    return [dict(item) for item in values if isinstance(item, dict)]
