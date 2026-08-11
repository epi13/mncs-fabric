from __future__ import annotations

import tempfile
import unittest
from itertools import repeat
from pathlib import Path

from mncs_fabric.api import FabricClient, LocalWorkerConfig
from mncs_fabric.capabilities import (
    MAX_CAPABILITY_ENTRIES,
    build_capability_observation,
    capability_observation_is_fresh,
    validate_capability_observation,
)
from mncs_fabric.canonical import attach_identity, verify_identity
from mncs_fabric.errors import ProtocolError, ValidationError
from mncs_fabric.transport import InProcessTransport
from mncs_fabric.worker import LocalWorker


def _model(name: str = "gpt-oss:20b") -> dict[str, object]:
    return {
        "kind": "model",
        "namespace": "ollama",
        "name": name,
        "subject_identity": "sha256:" + "a" * 64,
        "attributes": {
            "size_bytes": 13_793_441_244,
            "family": "gptoss",
            "parameter_size": "20B",
            "quantization": "MXFP4",
            "declared_features": ["completion", "tools"],
        },
    }


class CapabilityObservationTests(unittest.TestCase):
    def test_valid_observation_is_deterministic_and_not_attestation(self) -> None:
        arguments = {
            "worker_identity": "worker-a",
            "capabilities": [_model(), {"kind": "runtime", "namespace": "ollama", "name": "ollama", "attributes": {}}],
            "captured_at": "2026-01-01T00:00:00Z",
        }
        first = build_capability_observation(**arguments)
        second = build_capability_observation(**arguments)
        self.assertEqual(first, second)
        self.assertTrue(verify_identity(first, "capability_observation_identity"))
        self.assertEqual(first["attestation"], "NOT_ASSERTED")
        self.assertIn("not attestation", first["claim_boundary"])
        self.assertEqual(validate_capability_observation(first)["worker_identity"], "worker-a")

    def test_malformed_oversized_and_wrong_worker_inputs_fail_closed(self) -> None:
        with self.assertRaises(ValidationError):
            build_capability_observation(
                worker_identity="worker-a",
                capabilities=[{"kind": "model", "namespace": "ollama", "name": "bad\nname"}],
            )
        with self.assertRaises(ValidationError):
            build_capability_observation(
                worker_identity="worker-a",
                capabilities=[{"kind": "model", "namespace": "ollama", "name": "x", "attributes": {"nested": {"bad": True}}}],
            )
        with self.assertRaises(ValidationError):
            build_capability_observation(
                worker_identity="worker-a",
                capabilities=[_model(f"model:{index}") for index in range(MAX_CAPABILITY_ENTRIES + 1)],
            )
        with self.assertRaises(ValidationError):
            build_capability_observation(
                worker_identity="worker-a",
                capabilities=repeat(_model()),
            )
        observation = build_capability_observation(
            worker_identity="worker-a",
            capabilities=[_model()],
            captured_at="2026-01-01T00:00:00Z",
        )
        with self.assertRaises(ValidationError):
            validate_capability_observation(observation, expected_worker_id="worker-b")
        altered = dict(observation)
        altered["claim_boundary"] = "attested and authorized"
        altered.pop("capability_observation_identity")
        altered = attach_identity(altered, "capability_observation_identity")
        with self.assertRaises(ValidationError):
            validate_capability_observation(altered)

    def test_freshness_distinguishes_stale_and_future_observations(self) -> None:
        observation = build_capability_observation(
            worker_identity="worker-a",
            capabilities=[_model()],
            captured_at="2026-01-01T00:00:00Z",
        )
        self.assertTrue(
            capability_observation_is_fresh(
                observation, now="2026-01-01T00:04:00Z", max_age_seconds=300
            )
        )
        self.assertFalse(
            capability_observation_is_fresh(
                observation, now="2026-01-01T00:06:00Z", max_age_seconds=300
            )
        )
        self.assertFalse(
            capability_observation_is_fresh(
                observation, now="2025-12-31T23:00:00Z", max_age_seconds=300
            )
        )
        with self.assertRaises(ValidationError):
            capability_observation_is_fresh(observation, max_age_seconds=float("nan"))

    def test_public_api_persists_latest_local_observation_and_exposes_workers(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            bundle = root / "bundle"
            bundle.mkdir()
            state = root / "controller.jsonl"
            client = FabricClient("controller", state)
            client.register_local_worker(LocalWorkerConfig("local-worker", bundle, root / "worker.jsonl"))
            first = client.ingest_capability_observation(
                "local-worker", [_model("gemma4:e4b")], captured_at="2026-01-01T00:00:00Z"
            )
            latest = client.ingest_capability_observation(
                "local-worker", [_model("gpt-oss:20b")]
            )
            self.assertEqual(len(client.capability_observations("local-worker")), 2)
            self.assertEqual(client.latest_capability_observation("local-worker"), latest)
            workers = client.workers()
            self.assertEqual(workers[0]["capability_inventory_status"], "CURRENT")
            self.assertEqual(
                workers[0]["capability_observation"]["capability_observation_identity"],
                latest["capability_observation_identity"],
            )
            restarted = FabricClient("controller", state)
            restarted.register_local_worker(
                LocalWorkerConfig("local-worker", bundle, root / "worker-restarted.jsonl")
            )
            self.assertEqual(
                restarted.latest_capability_observation("local-worker"), latest
            )
            self.assertNotEqual(first["capability_observation_identity"], latest["capability_observation_identity"])

    def test_remote_loss_does_not_preserve_current_capability_availability(self) -> None:
        class Down:
            def request(self, _envelope):
                raise ConnectionRefusedError("fixture worker down")

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            bundle = root / "bundle"
            bundle.mkdir()
            remote_worker = LocalWorker("remote-worker", bundle, root / "remote-worker.jsonl")
            client = FabricClient("controller", root / "controller.jsonl")
            client.network.register_remote(
                "remote-worker",
                frozenset({"python"}),
                InProcessTransport(remote_worker),
            )
            client.remote_configs["remote-worker"] = object()  # type: ignore[assignment]
            client.refresh_worker("remote-worker")
            observation = client.ingest_capability_observation(
                "remote-worker", [_model()], captured_at="2026-01-01T00:00:00Z"
            )
            current = client.capability_inventory(
                "remote-worker", now="2026-01-01T00:01:00Z"
            )
            self.assertEqual(current["status"], "CURRENT")
            transport, slot = client.network.remote_workers["remote-worker"]
            client.network.remote_workers["remote-worker"] = (Down(), slot)
            with self.assertRaises(ConnectionRefusedError):
                client.refresh_worker("remote-worker")
            unavailable = client.capability_inventory(
                "remote-worker", now="2026-01-01T00:01:00Z"
            )
            self.assertEqual(unavailable["status"], "UNAVAILABLE")
            self.assertEqual(unavailable["observation"], observation)

    def test_unavailable_observation_replaces_current_claim_and_unknown_identity_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            bundle = root / "bundle"
            bundle.mkdir()
            client = FabricClient("controller", root / "controller.jsonl")
            client.register_local_worker(LocalWorkerConfig("worker", bundle, root / "worker.jsonl"))
            client.ingest_capability_observation("worker", [_model()])
            failed = client.ingest_capability_observation(
                "worker",
                [],
                availability="UNAVAILABLE",
                status_reason="bounded probe failed",
            )
            self.assertEqual(client.capability_inventory("worker")["status"], "UNAVAILABLE")
            self.assertEqual(failed["capabilities"], [])
            with self.assertRaises(ProtocolError):
                client.ingest_capability_observation("other-worker", [_model()])


if __name__ == "__main__":
    unittest.main()
