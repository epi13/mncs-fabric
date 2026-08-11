"""Bounded transports for the versioned Fabric protocol.

The protocol and replay semantics remain in controller/worker services.  This
module only moves one validated envelope at a time.  The network transport is
TLS-only and requires client certificates; there is no plaintext fallback.
"""

from __future__ import annotations

import json
import socket
import ssl
import struct
import threading
import time
from pathlib import Path
from typing import Protocol

from .canonical import canonical_json_bytes
from .enrollment import TrustStore, certificate_fingerprint
from .errors import ProtocolError, TransportTimeoutError
from .protocol import validate_envelope

MAX_FRAME_BYTES = 2 * 1024 * 1024
FRAME_PREFIX_BYTES = 4


class EnvelopeTransport(Protocol):
    def request(self, envelope: dict[str, object]) -> dict[str, object]: ...


def _read_exact(stream: socket.socket, size: int, *, deadline: float | None = None) -> bytes:
    result = bytearray()
    while len(result) < size:
        if deadline is not None:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise socket.timeout("protocol frame deadline exceeded")
            stream.settimeout(remaining)
        chunk = stream.recv(size - len(result))
        if not chunk:
            raise ProtocolError("connection closed before a complete frame was received")
        result.extend(chunk)
    return bytes(result)


def send_frame(stream: socket.socket, envelope: dict[str, object], *, max_frame_bytes: int = MAX_FRAME_BYTES) -> None:
    payload = canonical_json_bytes(envelope)
    if len(payload) > max_frame_bytes:
        raise ProtocolError("protocol frame exceeds the configured maximum")
    stream.sendall(struct.pack(">I", len(payload)) + payload)


def receive_frame(
    stream: socket.socket,
    *,
    max_frame_bytes: int = MAX_FRAME_BYTES,
    deadline: float | None = None,
) -> dict[str, object]:
    prefix = _read_exact(stream, FRAME_PREFIX_BYTES, deadline=deadline)
    length = struct.unpack(">I", prefix)[0]
    if length == 0 or length > max_frame_bytes:
        raise ProtocolError("protocol frame length is outside the bounded range")
    payload = _read_exact(stream, length, deadline=deadline)
    try:
        value = json.loads(payload.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ProtocolError("protocol frame is not valid UTF-8 JSON") from exc
    if not isinstance(value, dict):
        raise ProtocolError("protocol frame must contain an envelope object")
    if canonical_json_bytes(value) != payload:
        raise ProtocolError("protocol frame is not canonical JSON")
    return value


class InProcessTransport:
    def __init__(self, worker: object) -> None:
        self.worker = worker

    def request(self, envelope: dict[str, object]) -> dict[str, object]:
        validate_envelope(envelope)
        response = self.worker.handle(envelope)  # type: ignore[attr-defined]
        return validate_envelope(response)


class TLSNetworkTransport:
    """One-request-per-TLS-connection transport with certificate pinning."""

    def __init__(
        self,
        host: str,
        port: int,
        *,
        ca_file: Path,
        client_cert: Path,
        client_key: Path,
        expected_worker_id: str,
        trust_store: TrustStore,
        timeout: float = 5.0,
        connect_timeout: float | None = None,
        control_timeout: float | None = None,
        execution_timeout_overhead: float = 5.0,
        max_frame_bytes: int = MAX_FRAME_BYTES,
    ) -> None:
        connect_bound = timeout if connect_timeout is None else connect_timeout
        control_bound = timeout if control_timeout is None else control_timeout
        if (
            not 1 <= port <= 65535
            or timeout <= 0
            or connect_bound <= 0
            or control_bound <= 0
            or not 0 < execution_timeout_overhead <= 300
        ):
            raise ValueError("invalid TLS transport endpoint")
        self.host = host
        self.port = port
        self.expected_worker_id = expected_worker_id
        self.trust_store = trust_store
        # ``timeout`` remains the compatibility spelling for the short control
        # bound. Dispatch responses derive a separate bound from the validated
        # job plan and never widen connect, handshake, refresh, or idle waits.
        self.timeout = control_bound
        self.connect_timeout = connect_bound
        self.control_timeout = control_bound
        self.execution_timeout_overhead = execution_timeout_overhead
        self.max_frame_bytes = max_frame_bytes
        self.last_error: str | None = None
        context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=str(ca_file))
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.check_hostname = False
        context.load_cert_chain(certfile=str(client_cert), keyfile=str(client_key))
        self.context = context

    def request(self, envelope: dict[str, object]) -> dict[str, object]:
        message = validate_envelope(envelope)
        if message["worker_id"] != self.expected_worker_id:
            raise ProtocolError("transport request is bound to a different worker")
        response_timeout = self.control_timeout
        if message["message_type"] == "dispatch.request":
            plan = message["payload"]["job_plan"]
            response_timeout = max(
                self.control_timeout,
                float(plan["timeout_seconds"]) + self.execution_timeout_overhead,
            )
        phase = "connect"
        phase_timeout = self.connect_timeout
        try:
            with socket.create_connection(
                (self.host, self.port), timeout=self.connect_timeout
            ) as raw:
                phase = "TLS handshake"
                phase_timeout = self.control_timeout
                raw.settimeout(self.control_timeout)
                with self.context.wrap_socket(raw, server_hostname=self.host) as stream:
                    peer = stream.getpeercert(binary_form=True)
                    if not peer:
                        raise ProtocolError("TLS peer did not present a certificate")
                    self.trust_store.authorize(
                        "worker", self.expected_worker_id, certificate_fingerprint(peer)
                    )
                    phase = "request send"
                    phase_timeout = self.control_timeout
                    send_frame(stream, message, max_frame_bytes=self.max_frame_bytes)
                    phase = (
                        "execution response"
                        if message["message_type"] == "dispatch.request"
                        else "control response"
                    )
                    phase_timeout = response_timeout
                    response = validate_envelope(
                        receive_frame(
                            stream,
                            max_frame_bytes=self.max_frame_bytes,
                            deadline=time.monotonic() + response_timeout,
                        )
                    )
                    stream.settimeout(min(self.control_timeout, 0.2))
                    try:
                        extra = stream.recv(1)
                    except socket.timeout:
                        extra = b""
                    if extra:
                        raise ProtocolError("TLS peer sent trailing frame data")
                    return response
        except (socket.timeout, TimeoutError) as exc:
            raise TransportTimeoutError(
                f"Fabric {phase} timed out after {phase_timeout:.3f}s"
            ) from exc


class TLSWorkerServer:
    """Explicit bounded TLS worker endpoint.

    ``serve_once`` remains the conservative compatibility mode.  The
    ``serve_forever`` path keeps the listener open between requests but always
    requires explicit operational bounds; it is not an unbounded daemon by
    accident.
    """

    def __init__(self, worker: object, host: str, port: int, *, ca_file: Path, server_cert: Path, server_key: Path, controller_id: str, worker_id: str, trust_store: TrustStore, timeout: float = 5.0, max_frame_bytes: int = MAX_FRAME_BYTES, max_concurrent_connections: int = 1, graceful_shutdown_timeout: float = 5.0) -> None:
        if not 0 <= port <= 65535 or timeout <= 0 or max_frame_bytes <= 0 or max_concurrent_connections < 1 or graceful_shutdown_timeout <= 0:
            raise ValueError("invalid TLS worker endpoint")
        self.worker = worker
        self.host = host
        self.port = port
        self.controller_id = controller_id
        self.worker_id = worker_id
        self.trust_store = trust_store
        self.timeout = timeout
        self.max_frame_bytes = max_frame_bytes
        self.max_concurrent_connections = max_concurrent_connections
        self.graceful_shutdown_timeout = graceful_shutdown_timeout
        self.last_error: str | None = None
        self.context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH, cafile=str(ca_file))
        self.context.minimum_version = ssl.TLSVersion.TLSv1_2
        self.context.verify_mode = ssl.CERT_REQUIRED
        self.context.load_cert_chain(certfile=str(server_cert), keyfile=str(server_key))
        self._listener: socket.socket | None = None
        self._stop_event = threading.Event()
        self._threads: set[threading.Thread] = set()
        self._threads_lock = threading.Lock()
        self.handled_requests = 0

    def bind(self) -> int:
        if self._listener is not None:
            return self._listener.getsockname()[1]
        listener = socket.socket(socket.AF_INET6 if ":" in self.host else socket.AF_INET, socket.SOCK_STREAM)
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.settimeout(self.timeout)
        listener.bind((self.host, self.port))
        listener.listen(self.max_concurrent_connections)
        self._listener = listener
        self.port = listener.getsockname()[1]
        return self.port

    def serve_once(self) -> None:
        listener = self._listener
        if listener is None:
            self.bind()
            listener = self._listener
        assert listener is not None
        self.last_error = None
        try:
            raw, _ = listener.accept()
            self._handle_connection(raw)
        except (ProtocolError, OSError, ssl.SSLError) as exc:
            # A rejected peer is an explicit endpoint diagnostic, not a
            # successful fallback or an unobserved exception in a daemon.
            self.last_error = str(exc)
        finally:
            self.close()

    def serve_forever(
        self,
        *,
        max_requests: int | None = None,
        idle_timeout: float | None = None,
        max_concurrent_connections: int | None = None,
        graceful_shutdown_timeout: float | None = None,
    ) -> None:
        """Serve bounded sequential or concurrent requests until stopped.

        ``max_requests`` is required by the CLI, but the library accepts
        ``None`` for an explicitly managed service.  ``idle_timeout`` stops a
        quiet service cleanly; it never turns a missing request into PASS.
        Trust authorization is performed for every connection, so revocation
        becomes effective between requests without restarting the process.
        """

        if max_requests is not None and max_requests < 1:
            raise ValueError("max_requests must be positive when supplied")
        limit = max_concurrent_connections if max_concurrent_connections is not None else self.max_concurrent_connections
        shutdown = graceful_shutdown_timeout if graceful_shutdown_timeout is not None else self.graceful_shutdown_timeout
        if limit < 1 or shutdown <= 0 or (idle_timeout is not None and idle_timeout <= 0):
            raise ValueError("invalid bounded worker service limits")
        self.max_concurrent_connections = limit
        self.last_error = None
        self.handled_requests = 0
        listener = self._listener
        if listener is None:
            self.bind()
            listener = self._listener
        assert listener is not None
        if self._stop_event.is_set():
            self._close_listener()
            return
        try:
            listener.listen(limit)
        except OSError:
            if self._stop_event.is_set():
                return
            raise
        listener.settimeout(idle_timeout if idle_timeout is not None else self.timeout)
        semaphore = threading.BoundedSemaphore(limit)
        accepted = 0
        try:
            while not self._stop_event.is_set() and (max_requests is None or accepted < max_requests):
                try:
                    raw, _ = listener.accept()
                except socket.timeout:
                    if idle_timeout is not None:
                        break
                    continue
                except OSError:
                    if self._stop_event.is_set():
                        break
                    raise
                accepted += 1
                if not semaphore.acquire(timeout=self.timeout):
                    self.last_error = "connection concurrency limit reached"
                    raw.close()
                    continue
                if limit == 1:
                    try:
                        self._handle_connection(raw)
                    finally:
                        semaphore.release()
                    continue
                thread = threading.Thread(target=self._threaded_connection, args=(raw, semaphore), daemon=False)
                with self._threads_lock:
                    self._threads.add(thread)
                thread.start()
        except (ProtocolError, OSError, ssl.SSLError) as exc:
            self.last_error = str(exc)
        finally:
            self._stop_event.set()
            self._close_listener()
            deadline = time.monotonic() + shutdown
            with self._threads_lock:
                threads = list(self._threads)
            for thread in threads:
                thread.join(max(0.0, deadline - time.monotonic()))

    def request_stop(self) -> None:
        """Request bounded service shutdown without changing ledger state."""

        self._stop_event.set()
        self._close_listener()

    def _threaded_connection(self, raw: socket.socket, semaphore: threading.BoundedSemaphore) -> None:
        current = threading.current_thread()
        try:
            self._handle_connection(raw)
        finally:
            semaphore.release()
            with self._threads_lock:
                self._threads.discard(current)

    def _handle_connection(self, raw: socket.socket) -> None:
        try:
            raw.settimeout(self.timeout)
            with raw:
                with self.context.wrap_socket(raw, server_side=True) as stream:
                    peer = stream.getpeercert(binary_form=True)
                    if not peer:
                        raise ProtocolError("TLS controller did not present a certificate")
                    message = validate_envelope(
                        receive_frame(
                            stream,
                            max_frame_bytes=self.max_frame_bytes,
                            deadline=time.monotonic() + self.timeout,
                        )
                    )
                    if message["controller_id"] != self.controller_id or message["worker_id"] != self.worker_id:
                        raise ProtocolError("message logical identity does not match TLS endpoint")
                    # Reloads the append-only trust ledger on every request.
                    self.trust_store.authorize("controller", self.controller_id, certificate_fingerprint(peer))
                    response = self.worker.handle(message)  # type: ignore[attr-defined]
                    send_frame(stream, validate_envelope(response), max_frame_bytes=self.max_frame_bytes)
                    stream.settimeout(min(self.timeout, 0.2))
                    try:
                        extra = stream.recv(1)
                    except socket.timeout:
                        extra = b""
                    if extra:
                        raise ProtocolError("controller sent trailing frame data")
                    self.handled_requests += 1
        except (ProtocolError, OSError, ssl.SSLError) as exc:
            # Rejected requests do not stop a bounded service.  The diagnostic
            # is retained for the operator and the next connection is still
            # independently authenticated.
            self.last_error = str(exc)

    def close(self) -> None:
        self._stop_event.set()
        self._close_listener()

    def _close_listener(self) -> None:
        if self._listener is not None:
            listener, self._listener = self._listener, None
            try:
                listener.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            listener.close()
