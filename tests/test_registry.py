from __future__ import annotations

import json
from pathlib import Path
import ssl
from tempfile import TemporaryDirectory
import unittest

from mncs_fabric.api import FabricClient
from mncs_fabric.enrollment import TrustStore, certificate_fingerprint
from mncs_fabric.errors import ProtocolError, ValidationError
from mncs_fabric.registry import (
    RegistryWorker,
    WorkerRegistry,
    WORKER_REGISTRY_SCHEMA,
)
from tests.test_transport import _certificates


class WorkerRegistryTests(unittest.TestCase):
    def _worker(
        self,
        root: Path,
        worker_id: str = "worker-a",
        host: str = "worker-a.example",
        port: int = 7443,
    ) -> RegistryWorker:
        certificates = _certificates(root)
        trust = root / f"{worker_id}-trust.jsonl"
        TrustStore(trust).enroll(
            "worker",
            worker_id,
            certificate_fingerprint(
                ssl.PEM_cert_to_DER_cert(
                    certificates["server"].read_text(encoding="ascii")
                )
            ),
        )
        return RegistryWorker(
            worker_id=worker_id,
            host=host,
            port=port,
            capabilities=("python",),
            ca_file=str(certificates["ca"]),
            client_certificate=str(certificates["client"]),
            client_key=str(certificates["client_key"]),
            trust_state=str(trust),
            labels=(("site", "operator-lab"),),
        )

    def test_register_update_list_validate_and_remove_are_durable(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            registry = WorkerRegistry(root / "workers.json", "controller-a")
            worker = self._worker(root)
            self.assertEqual(registry.register(worker)["action"], "REGISTERED")
            self.assertEqual(registry.validate()["outcome"], "PASS")
            self.assertEqual(registry.load(), (worker,))
            updated = RegistryWorker.from_dict(
                {**worker.to_dict(), "labels": {"site": "operator-lab", "tier": "gpu"}}
            )
            self.assertEqual(registry.update(updated)["action"], "UPDATED")
            self.assertEqual(dict(registry.load()[0].labels)["tier"], "gpu")
            self.assertEqual(registry.remove("worker-a")["action"], "REMOVED")
            self.assertEqual(registry.load(), ())

    def test_duplicate_identity_and_conflicting_endpoint_fail_closed(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            registry = WorkerRegistry(root / "workers.json", "controller-a")
            first = self._worker(root)
            registry.register(first)
            with self.assertRaises(ProtocolError):
                registry.register(first)
            second_root = root / "second"
            second_root.mkdir()
            second = self._worker(second_root, "worker-b", first.host, first.port)
            with self.assertRaises(ProtocolError):
                registry.register(second)

    def test_malformed_unknown_version_and_duplicate_document_are_rejected(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / "workers.json"
            path.write_text("{bad", encoding="utf-8")
            self.assertEqual(WorkerRegistry(path, "controller-a").validate()["outcome"], "FAIL")
            worker = self._worker(root)
            value = {
                "schema_version": "mncs-fabric.worker-registry.v9",
                "controller_id": "controller-a",
                "workers": [],
            }
            path.write_text(json.dumps(value), encoding="utf-8")
            self.assertEqual(WorkerRegistry(path, "controller-a").validate()["outcome"], "FAIL")
            value["schema_version"] = WORKER_REGISTRY_SCHEMA
            value["workers"] = [worker.to_dict(), worker.to_dict()]
            path.write_text(json.dumps(value), encoding="utf-8")
            with self.assertRaises(ValidationError):
                WorkerRegistry(path, "controller-a").load()

    def test_missing_modified_and_revoked_trust_references_never_register(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            worker = self._worker(root)
            missing = RegistryWorker.from_dict(
                {**worker.to_dict(), "client_key": str(root / "missing.key")}
            )
            self.assertEqual(missing.reference_status()["outcome"], "UNKNOWN")
            with self.assertRaises(ProtocolError):
                WorkerRegistry(root / "missing.json", "controller-a").register(missing)

            Path(worker.trust_state).write_text("modified", encoding="utf-8")
            self.assertEqual(worker.reference_status()["outcome"], "UNKNOWN")

            revoked_root = root / "revoked"
            revoked_root.mkdir()
            revoked = self._worker(revoked_root, "worker-revoked")
            TrustStore(Path(revoked.trust_state)).revoke(
                "worker", "worker-revoked", reason="operator test"
            )
            self.assertEqual(revoked.reference_status()["code"], "REGISTRY_WORKER_REVOKED")
            with self.assertRaises(ProtocolError):
                revoked.to_remote_config()

    def test_public_client_loads_registry_and_keeps_invalid_known_nodes_visible(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            registry = WorkerRegistry(root / "workers.json", "controller-a")
            worker = self._worker(root)
            registry.register(worker)
            client = FabricClient("controller-a", root / "controller.jsonl")
            report = client.load_registry(registry.path)
            self.assertEqual(report["registered_workers"], ["worker-a"])
            state = client.workers()[0]
            self.assertEqual(state["worker_id"], "worker-a")
            self.assertNotEqual(state["availability"], "AVAILABLE")

    def test_same_endpoint_cannot_be_bound_to_two_explicit_identities(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            first = self._worker(root)
            second_root = root / "second"
            second_root.mkdir()
            second = self._worker(second_root, "worker-b", first.host, first.port)
            client = FabricClient("controller-a", root / "controller.jsonl")
            client.register_remote_worker(first.to_remote_config())
            with self.assertRaises(ProtocolError):
                client.register_remote_worker(second.to_remote_config())


if __name__ == "__main__":
    unittest.main()
