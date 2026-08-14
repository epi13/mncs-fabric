"""Bounded local transport for a persistent Fabric controller.

The service contract is intentionally separate from the controller/worker
protocol.  It has two local-only surfaces: a consumer socket for reads and a
distinct operator socket for lifecycle administration.  It does not expose
Python objects, ledger paths, worker credentials, or a LAN listener.
"""

from __future__ import annotations

import errno
try:
    import fcntl
except ImportError:  # pragma: no cover - Windows backend is intentionally planned.
    fcntl = None  # type: ignore[assignment]
import os
import re
import socket
import stat
import struct
import threading
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Mapping

from .canonical import attach_identity, canonical_json_bytes, verify_identity
from .errors import FabricError, ProtocolError, TransportTimeoutError, ValidationError
from .node import utc_now
from .transport import receive_frame, send_frame

SERVICE_REQUEST_SCHEMA = "mncs-fabric.service-request.v0.1"
SERVICE_RESPONSE_SCHEMA = "mncs-fabric.service-response.v0.1"
SERVICE_EVENT_SCHEMA = "mncs-fabric.controller-service.v0.1"
SERVICE_MAX_FRAME_BYTES = 4 * 1024 * 1024
SERVICE_REQUEST_TTL_SECONDS = 30.0
SERVICE_MAX_CONNECTIONS = 32
_IDENTITY_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_OPERATIONS = {
    "controller.status", "controller.doctor", "fleet.list", "fleet.status",
    "fleet.refresh", "worker.status", "worker.observations", "fleet.doctor",
    "execution.bundle.begin", "execution.bundle.chunk", "execution.bundle.commit",
    "execution.dispatch", "execution.submit", "execution.status",
    "execution.result", "execution.list", "execution.target.dispatch",
    "worker.capability.ingest", "worker.capability.observations",
    "schedule.enqueue", "schedule.list", "schedule.tick",
    "schedule.pause", "schedule.resume", "schedule.policy",
    "enrollment.create", "enrollment.list", "enrollment.pending",
    "enrollment.inspect", "enrollment.approve", "enrollment.deny",
    "enrollment.expire", "enrollment.submit", "worker.revoke",
}
_ADMIN_OPERATIONS = {
    "fleet.doctor", "enrollment.create", "enrollment.list",
    "enrollment.pending", "enrollment.inspect", "enrollment.approve",
    "enrollment.deny", "enrollment.expire", "enrollment.submit", "worker.revoke",
}


def _bounded_identity(value: object, field: str) -> str:
    if not isinstance(value, str) or not _IDENTITY_RE.fullmatch(value):
        raise ValidationError(f"{field} is malformed")
    return value


def _timestamp(value: object, field: str) -> str:
    if not isinstance(value, str) or len(value) > 64:
        raise ValidationError(f"{field} must be an RFC 3339 timestamp")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValidationError(f"{field} must be an RFC 3339 timestamp") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValidationError(f"{field} must include a timezone")
    return parsed.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _validate_request(value: Mapping[str, Any]) -> dict[str, Any]:
    expected = {"schema_version", "request_id", "client_identity", "operation", "arguments", "created_at", "expires_at"}
    if set(value) != expected or value.get("schema_version") != SERVICE_REQUEST_SCHEMA:
        raise ProtocolError("service request schema is unsupported")
    request = dict(value)
    if not isinstance(request.get("request_id"), str) or not verify_identity(request, "request_id"):
        raise ProtocolError("service request identity is invalid")
    _bounded_identity(request["client_identity"], "client_identity")
    if not isinstance(request["operation"], str) or request["operation"] not in _OPERATIONS:
        raise ProtocolError("service operation is unsupported")
    if not isinstance(request["arguments"], dict) or len(request["arguments"]) > 32:
        raise ProtocolError("service arguments are invalid")
    _timestamp(request["created_at"], "created_at")
    _timestamp(request["expires_at"], "expires_at")
    if len(canonical_json_bytes(request["arguments"])) > 64 * 1024:
        raise ProtocolError("service arguments exceed the configured bound")
    if datetime.fromisoformat(request["expires_at"].replace("Z", "+00:00")) < datetime.fromisoformat(request["created_at"].replace("Z", "+00:00")):
        raise ProtocolError("service request expiry precedes creation")
    return request


def _validate_response(value: Mapping[str, Any], request_id: str) -> dict[str, Any]:
    expected = {"schema_version", "response_id", "request_id", "disposition", "payload", "error", "served_at", "controller_id"}
    if set(value) != expected or value.get("schema_version") != SERVICE_RESPONSE_SCHEMA:
        raise ProtocolError("service response schema is unsupported")
    response = dict(value)
    if not isinstance(response.get("response_id"), str) or not verify_identity(response, "response_id"):
        raise ProtocolError("service response identity is invalid")
    if response.get("request_id") != request_id:
        raise ProtocolError("service response is bound to another request")
    if response.get("disposition") not in {"PASS", "FAIL", "UNKNOWN"}:
        raise ProtocolError("service response disposition is invalid")
    if not isinstance(response.get("payload"), dict) or (response.get("error") is not None and not isinstance(response.get("error"), dict)):
        raise ProtocolError("service response payload is invalid")
    _timestamp(response["served_at"], "served_at")
    _bounded_identity(response["controller_id"], "controller_id")
    return response


def _response(request: Mapping[str, Any], controller_id: str, disposition: str, *, payload: Mapping[str, Any] | None = None, error: Mapping[str, Any] | None = None) -> dict[str, Any]:
    return attach_identity({
        "schema_version": SERVICE_RESPONSE_SCHEMA,
        "request_id": request["request_id"],
        "disposition": disposition,
        "payload": dict(payload or {}),
        "error": dict(error) if error is not None else None,
        "served_at": utc_now(),
        "controller_id": controller_id,
    }, "response_id")


def _safe_endpoint_path(path: Path) -> None:
    path = Path(path).expanduser()
    path.parent.mkdir(parents=True, exist_ok=True)
    parent = path.parent
    parent_stat = os.lstat(parent)
    if stat.S_ISLNK(parent_stat.st_mode) or not stat.S_ISDIR(parent_stat.st_mode):
        raise ProtocolError("service socket parent is not a real directory")
    if os.name == "posix" and parent_stat.st_uid != os.getuid():
        raise ProtocolError("service socket parent is owned by another account")
    if os.name == "posix" and parent_stat.st_mode & 0o022:
        raise ProtocolError("service socket parent is writable by another account")
    if path.exists() or path.is_symlink():
        entry = os.lstat(path)
        if stat.S_ISLNK(entry.st_mode) or not stat.S_ISSOCK(entry.st_mode):
            raise ProtocolError("service socket path is not a safe socket")
        if os.name == "posix" and entry.st_uid != os.getuid():
            raise ProtocolError("service socket is owned by another account")


def _remove_socket_if_owned(path: Path, identity: tuple[int, int] | None) -> None:
    if identity is None:
        return
    try:
        entry = os.lstat(path)
    except FileNotFoundError:
        return
    if (entry.st_dev, entry.st_ino) == identity and stat.S_ISSOCK(entry.st_mode):
        path.unlink()


class ControllerServiceOwnership:
    """Exclusive controller-state ownership held for the process lifetime."""

    def __init__(self, path: Path) -> None:
        self.path = Path(path).expanduser()
        self._handle: Any = None

    def acquire(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        parent_stat = os.lstat(self.path.parent)
        if stat.S_ISLNK(parent_stat.st_mode) or not stat.S_ISDIR(parent_stat.st_mode) or (os.name == "posix" and parent_stat.st_uid != os.getuid()) or (os.name == "posix" and parent_stat.st_mode & 0o022):
            raise ProtocolError("controller ownership directory is unsafe")
        if self.path.is_symlink():
            raise ProtocolError("controller ownership path is a symlink")
        self._handle = self.path.open("a+b", buffering=0)
        try:
            os.chmod(self.path, 0o600)
            if os.name == "posix" and fcntl is not None:
                fcntl.flock(self._handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            elif os.name == "nt":
                import msvcrt

                self._handle.seek(0, os.SEEK_END)
                if self._handle.tell() == 0:
                    self._handle.write(b"\0")
                    self._handle.flush()
                self._handle.seek(0)
                msvcrt.locking(self._handle.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                raise ProtocolError("controller ownership is not implemented on this platform")
        except (BlockingIOError, OSError) as exc:
            self._handle.close()
            self._handle = None
            if isinstance(exc, BlockingIOError) or getattr(exc, "errno", None) in {errno.EACCES, errno.EAGAIN}:
                raise ProtocolError("controller state is already owned") from exc
            raise

    def release(self) -> None:
        if self._handle is not None:
            try:
                if fcntl is not None:
                    fcntl.flock(self._handle.fileno(), fcntl.LOCK_UN)
            finally:
                self._handle.close()
                self._handle = None


class ControllerServiceServer:
    """One-request-per-connection AF_UNIX service server."""

    def __init__(self, owner: Any, *, max_connections: int = SERVICE_MAX_CONNECTIONS) -> None:
        if not 1 <= max_connections <= SERVICE_MAX_CONNECTIONS:
            raise ValidationError("service connection bound is invalid")
        self.owner = owner
        self.max_connections = max_connections
        self._stop = threading.Event()
        self._listeners: list[tuple[socket.socket, Path, tuple[int, int] | None, str]] = []
        self._threads: list[threading.Thread] = []
        self._slots = threading.BoundedSemaphore(max_connections)

    @staticmethod
    def _prepare(path: Path) -> None:
        _safe_endpoint_path(path)
        if path.exists():
            original = os.lstat(path)
            probe = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            try:
                probe.settimeout(0.1)
                probe.connect(str(path))
            except OSError:
                pass
            else:
                probe.close()
                raise ProtocolError("service socket is already in use")
            finally:
                try:
                    probe.close()
                except OSError:
                    pass
            current = os.lstat(path)
            if (current.st_dev, current.st_ino) != (original.st_dev, original.st_ino) or not stat.S_ISSOCK(current.st_mode):
                raise ProtocolError("service socket path changed while checking stale state")
            path.unlink()

    def _bind(self, path: Path, role: str) -> None:
        if os.name != "posix" or not hasattr(socket, "AF_UNIX"):
            raise ProtocolError("local service transport is not implemented on this platform")
        self._prepare(path)
        listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        bound_identity: tuple[int, int] | None = None
        try:
            listener.bind(str(path))
            os.chmod(path, 0o600)
            listener.listen(self.max_connections)
            listener.settimeout(0.2)
            entry = os.lstat(path)
            bound_identity = (entry.st_dev, entry.st_ino)
            self._listeners.append((listener, path, bound_identity, role))
        except BaseException:
            listener.close()
            try:
                if bound_identity is not None:
                    _remove_socket_if_owned(path, bound_identity)
            except OSError:
                pass
            raise

    def start(self) -> None:
        if self._listeners:
            raise ProtocolError("service server is already running")
        self._stop.clear()
        self._bind(self.owner.config.socket_path_value, "consumer")
        try:
            self._bind(self.owner.config.admin_socket_path_value, "admin")
        except BaseException:
            self.close()
            raise
        for listener, _path, _identity, role in self._listeners:
            thread = threading.Thread(target=self._accept_loop, args=(listener, role), daemon=True, name=f"mncs-fabric-{role}")
            self._threads.append(thread)
            thread.start()

    def _peer_identity(self, connection: socket.socket) -> str | None:
        if not hasattr(socket, "SO_PEERCRED"):
            return None
        raw = connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i"))
        _pid, uid, _gid = struct.unpack("3i", raw)
        return f"local-uid:{uid}" if uid == os.getuid() else None

    def _accept_loop(self, listener: socket.socket, role: str) -> None:
        while not self._stop.is_set():
            try:
                connection, _address = listener.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            if not self._slots.acquire(blocking=False):
                connection.close()
                continue
            thread = threading.Thread(target=self._handle, args=(connection, role), daemon=True, name=f"mncs-fabric-request-{role}")
            self._threads.append(thread)
            thread.start()

    def _handle(self, connection: socket.socket, role: str) -> None:
        try:
            peer_identity = self._peer_identity(connection)
            if peer_identity is None:
                return
            deadline = time.monotonic() + 10.0
            request = _validate_request(receive_frame(connection, max_frame_bytes=SERVICE_MAX_FRAME_BYTES, deadline=deadline))
            response = self.owner.handle_service_request(
                request, role=role, peer_identity=peer_identity
            )
            send_frame(connection, response, max_frame_bytes=SERVICE_MAX_FRAME_BYTES)
        except (FabricError, OSError):
            # A malformed or unauthorized request is not allowed to disclose
            # controller internals.  Valid requests receive an explicit error;
            # failures before validation simply close the bounded connection.
            try:
                if "request" in locals():
                    send_frame(connection, _response(request, self.owner.config.controller_id, "UNKNOWN", error={"code": "SERVICE_REQUEST_REJECTED", "message": "service request was rejected"}), max_frame_bytes=SERVICE_MAX_FRAME_BYTES)
            except OSError:
                pass
        finally:
            try:
                connection.close()
            finally:
                self._slots.release()

    def close(self) -> None:
        self._stop.set()
        listeners = list(self._listeners)
        self._listeners.clear()
        for listener, _path, _identity, _role in listeners:
            try:
                listener.close()
            except OSError:
                pass
        for thread in list(self._threads):
            if thread is not threading.current_thread():
                thread.join(timeout=1.0)
        self._threads.clear()
        for _listener, path, identity, _role in listeners:
            _remove_socket_if_owned(path, identity)


class ServiceClientTransport:
    def __init__(self, socket_path: Path, *, client_identity: str, admin: bool = False, timeout: float = 5.0) -> None:
        if os.name != "posix" or not hasattr(socket, "AF_UNIX"):
            raise ProtocolError("local service transport is not implemented on this platform")
        if not 0 < timeout <= 30:
            raise ValidationError("service timeout is outside the bounded range")
        self.socket_path = Path(socket_path).expanduser()
        self.client_identity = _bounded_identity(client_identity, "client_identity")
        self.admin = admin
        self.timeout = timeout

    def request(self, operation: str, arguments: Mapping[str, Any] | None = None) -> dict[str, Any]:
        if operation not in _OPERATIONS:
            raise ProtocolError("service operation is unsupported")
        created = utc_now()
        expires = (datetime.fromisoformat(created.replace("Z", "+00:00")) + timedelta(seconds=min(self.timeout, SERVICE_REQUEST_TTL_SECONDS))).isoformat().replace("+00:00", "Z")
        request = attach_identity({
            "schema_version": SERVICE_REQUEST_SCHEMA,
            "client_identity": self.client_identity,
            "operation": operation,
            "arguments": dict(arguments or {}),
            "created_at": created,
            "expires_at": expires,
        }, "request_id")
        return self.request_envelope(request)

    def request_envelope(self, request: Mapping[str, Any]) -> dict[str, Any]:
        """Send one pre-identified request, primarily for deterministic clients/tests."""

        request = _validate_request(request)
        deadline = time.monotonic() + self.timeout
        try:
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as stream:
                stream.settimeout(self.timeout)
                stream.connect(str(self.socket_path))
                send_frame(stream, request, max_frame_bytes=SERVICE_MAX_FRAME_BYTES)
                response = _validate_response(receive_frame(stream, max_frame_bytes=SERVICE_MAX_FRAME_BYTES, deadline=deadline), request["request_id"])
        except socket.timeout as exc:
            raise TransportTimeoutError("persistent Fabric service request timed out") from exc
        if response["disposition"] != "PASS":
            error = response.get("error") or {}
            raise ProtocolError(str(error.get("message", "persistent Fabric service rejected the request")))
        return response["payload"]


__all__ = [
    "SERVICE_REQUEST_SCHEMA", "SERVICE_RESPONSE_SCHEMA", "SERVICE_EVENT_SCHEMA",
    "ControllerServiceOwnership", "ControllerServiceServer", "ServiceClientTransport",
]
