from __future__ import annotations

import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from mncs_fabric.api import FabricClient
from mncs_fabric.errors import ProtocolError, TransportTimeoutError
from mncs_fabric.service_transport import SERVICE_REQUEST_TTL_SECONDS


class _FakeServiceTransport:
    def __init__(self, script: list[tuple[str, dict[str, object]]]) -> None:
        self.script = list(script)
        self.calls: list[tuple[str, dict[str, object]]] = []

    def request(self, operation: str, arguments: dict[str, object] | None = None) -> dict[str, object]:
        payload = dict(arguments or {})
        self.calls.append((operation, payload))
        if not self.script:
            raise ProtocolError(f"unexpected service operation: {operation}")
        expected, response = self.script.pop(0)
        if expected != operation:
            raise ProtocolError(f"expected {expected}, received {operation}")
        return dict(response)


class PersistentExecutionDeadlineTests(unittest.TestCase):
    def _client(self, script: list[tuple[str, dict[str, object]]]) -> tuple[FabricClient, _FakeServiceTransport]:
        client = FabricClient.__new__(FabricClient)
        transport = _FakeServiceTransport(script)
        client._service_transport = transport
        client.blocked_worker_ids = set()
        return client, transport

    def test_short_jobs_use_synchronous_dispatch(self) -> None:
        client, transport = self._client(
            [("execution.dispatch", {"results": [{"disposition": "EXECUTED"}]})]
        )
        results = client._execute_persistent_service(
            {"plan": {"timeout_seconds": SERVICE_REQUEST_TTL_SECONDS}},
            {"timeout_seconds": SERVICE_REQUEST_TTL_SECONDS},
        )
        self.assertEqual(results[0]["disposition"], "EXECUTED")
        self.assertEqual([name for name, _ in transport.calls], ["execution.dispatch"])

    def test_long_jobs_submit_and_wait_for_observable_completion(self) -> None:
        client, transport = self._client(
            [
                ("execution.submit", {"work_id": "sha256:" + "a" * 64, "state": "QUEUED"}),
                ("execution.status", {"work_id": "sha256:" + "a" * 64, "state": "RUNNING"}),
                ("execution.status", {"work_id": "sha256:" + "a" * 64, "state": "COMPLETED"}),
                (
                    "execution.result",
                    {
                        "work_id": "sha256:" + "a" * 64,
                        "state": "COMPLETED",
                        "result": {"results": [{"disposition": "EXECUTED", "record": {"outcome": "PASS"}}]},
                    },
                ),
            ]
        )
        results = client._execute_persistent_service(
            {"plan": {"timeout_seconds": 120}, "request_id": "inference-1"},
            {"timeout_seconds": 120},
        )
        self.assertEqual(results[0]["record"]["outcome"], "PASS")
        self.assertEqual(
            [name for name, _ in transport.calls],
            ["execution.submit", "execution.status", "execution.status", "execution.result"],
        )
        self.assertEqual(transport.calls[0][1]["idempotency_key"], "inference-1")

    def test_failed_detached_work_is_not_reported_as_a_transport_timeout(self) -> None:
        client, _transport = self._client(
            [
                ("execution.submit", {"work_id": "sha256:" + "b" * 64, "state": "QUEUED"}),
                ("execution.status", {"work_id": "sha256:" + "b" * 64, "state": "FAILED"}),
                (
                    "execution.result",
                    {
                        "work_id": "sha256:" + "b" * 64,
                        "state": "FAILED",
                        "reason": "worker-local Ollama invocation failed",
                    },
                ),
            ]
        )
        with self.assertRaisesRegex(ProtocolError, "worker-local Ollama"):
            client._execute_persistent_service(
                {"plan": {"timeout_seconds": 90}},
                {"timeout_seconds": 90},
            )

    def test_deadline_records_last_observed_state(self) -> None:
        client, _transport = self._client(
            [
                ("execution.submit", {"work_id": "sha256:" + "c" * 64, "state": "QUEUED"}),
                ("execution.status", {"work_id": "sha256:" + "c" * 64, "state": "RUNNING"}),
                ("execution.status", {"work_id": "sha256:" + "c" * 64, "state": "RUNNING"}),
            ]
        )
        with self.assertRaisesRegex(
            TransportTimeoutError,
            r"work_id=sha256:c{64} last_state=RUNNING",
        ):
            client._wait_for_detached_execution({"plan": {"timeout_seconds": 90}}, 0.01)
