from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path

from mncs_fabric.commissioning import (
    activate_worker_credentials,
    build_enrollment_material,
    issue_worker_credentials,
    prepare_join_request,
    submit_join_request,
)
from mncs_fabric.enrollment import TrustStore
from mncs_fabric.errors import ProtocolError, ValidationError
from mncs_fabric.lifecycle import LifecycleStore
from tests.test_rendezvous import _certificates


class CommissioningTests(unittest.TestCase):
    @unittest.skipUnless(os.name == "posix", "Fedora commissioning requires POSIX")
    def test_private_key_stays_local_and_approved_credentials_activate(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            cert = _certificates(root)
            lifecycle = LifecycleStore(root / "controller" / "lifecycle.jsonl")
            authorization = lifecycle.create_authorization(
                expected_worker_identity="worker-commissioned"
            )
            material = build_enrollment_material(
                authorization,
                controller_id="controller-home",
                controller_host="controller.example.test",
                controller_port=7444,
                controller_certificate_pem=cert["server"].read_text(encoding="ascii"),
            )
            worker_root = root / "worker"
            join = prepare_join_request(
                material,
                worker_id="worker-commissioned",
                state_root=worker_root,
                hostname="worker-dhcp-a",
                operating_system="linux",
                architecture="x86_64",
            )
            private_key = worker_root / "tls" / "worker.key"
            original_key = private_key.read_bytes()
            self.assertNotIn("PRIVATE KEY", str(join))
            if os.name == "posix":
                self.assertEqual(private_key.stat().st_mode & 0o777, 0o600)

            submitted = submit_join_request(lifecycle, join)
            self.assertEqual(submitted["status"], "PENDING")
            with self.assertRaisesRegex(ProtocolError, "explicit enrollment approval"):
                issue_worker_credentials(
                    lifecycle,
                    join,
                    ca_certificate=cert["ca"],
                    ca_key=cert["ca_key"],
                    controller_certificate=cert["server"],
                    controller_trust_state=root / "controller-trust.jsonl",
                )
            lifecycle.approve_request(str(submitted["request_id"]))
            credentials = issue_worker_credentials(
                lifecycle,
                join,
                ca_certificate=cert["ca"],
                ca_key=cert["ca_key"],
                controller_certificate=cert["server"],
                controller_trust_state=root / "controller-trust.jsonl",
            )
            installation = activate_worker_credentials(credentials, state_root=worker_root)
            self.assertEqual(installation["lifecycle"], "ENROLLED")
            self.assertEqual(private_key.read_bytes(), original_key)
            self.assertNotIn("PRIVATE KEY", (worker_root / "worker.env").read_text())
            self.assertEqual((worker_root / "worker.env").stat().st_mode & 0o777, 0o600)
            self.assertEqual((worker_root / "installation.json").stat().st_mode & 0o777, 0o600)
            self.assertTrue((worker_root / "tls" / "worker.pem").is_file())
            trusted = TrustStore(root / "controller-trust.jsonl").lookup(
                "worker", "worker-commissioned"
            )
            self.assertIsNotNone(trusted)
            self.assertTrue(trusted["active"])
            controller = TrustStore(worker_root / "worker-trust.jsonl").lookup(
                "controller", "controller-home"
            )
            self.assertIsNotNone(controller)

            repeated = prepare_join_request(
                material,
                worker_id="worker-commissioned",
                state_root=worker_root,
                hostname="worker-dhcp-b",
                operating_system="linux",
                architecture="x86_64",
            )
            self.assertEqual(private_key.read_bytes(), original_key)
            self.assertEqual(
                repeated["request"]["public_key_identity"],
                join["request"]["public_key_identity"],
            )

    def test_enrollment_material_rejects_environment_injection_host(self) -> None:
        authorization = {
            "authorization_id": "sha256:" + "0" * 64,
            "token": "token",
            "expires_at": "2099-01-01T00:00:00Z",
            "expected_worker_identity": "worker-a",
        }
        with self.assertRaisesRegex(ValidationError, "controller host"):
            build_enrollment_material(
                authorization,
                controller_id="controller-a",
                controller_host="host\nMNCS_FABRIC_CERTIFICATE_KEY=/tmp/stolen",
                controller_port=7444,
                controller_certificate_pem="-----BEGIN CERTIFICATE-----\nAA==\n-----END CERTIFICATE-----\n",
            )


if __name__ == "__main__":
    unittest.main()
