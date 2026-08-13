from __future__ import annotations

import os
import shutil
import subprocess
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
from mncs_fabric.canonical import attach_identity
from mncs_fabric.enrollment import TrustStore
from mncs_fabric.errors import ProtocolError, ValidationError
from mncs_fabric.lifecycle import LifecycleStore
from tests.test_rendezvous import _certificates


class CommissioningTests(unittest.TestCase):
    def _approved_join(self, root: Path, cert: dict[str, Path]):
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
        submitted = submit_join_request(lifecycle, join)
        lifecycle.approve_request(str(submitted["request_id"]))
        return lifecycle, worker_root, join

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

    @unittest.skipUnless(os.name == "posix", "Fedora commissioning requires POSIX")
    def test_issuance_rejects_mismatched_ca_key_and_controller_chain(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            first = root / "first"
            second = root / "second"
            first.mkdir()
            second.mkdir()
            cert = _certificates(first)
            other = _certificates(second)
            lifecycle, _worker_root, join = self._approved_join(root, cert)
            trust = root / "controller-trust.jsonl"
            with self.assertRaisesRegex(ProtocolError, "CA certificate does not match"):
                issue_worker_credentials(
                    lifecycle,
                    join,
                    ca_certificate=cert["ca"],
                    ca_key=other["ca_key"],
                    controller_certificate=cert["server"],
                    controller_trust_state=trust,
                )
            self.assertFalse(trust.exists())
            with self.assertRaisesRegex(ProtocolError, "openssl commissioning operation"):
                issue_worker_credentials(
                    lifecycle,
                    join,
                    ca_certificate=other["ca"],
                    ca_key=other["ca_key"],
                    controller_certificate=cert["server"],
                    controller_trust_state=trust,
                )
            self.assertFalse(trust.exists())
            with self.assertRaisesRegex(ProtocolError, "does not match enrollment material"):
                issue_worker_credentials(
                    lifecycle,
                    join,
                    ca_certificate=other["ca"],
                    ca_key=other["ca_key"],
                    controller_certificate=other["server"],
                    controller_trust_state=trust,
                )
            self.assertFalse(trust.exists())

    @unittest.skipUnless(os.name == "posix", "Fedora commissioning requires POSIX")
    def test_issuance_rejects_csr_identity_substitution(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            cert = _certificates(root)
            lifecycle, worker_root, join = self._approved_join(root, cert)
            substituted = root / "substituted.csr"
            subprocess.run(
                [
                    shutil.which("openssl") or "openssl",
                    "req",
                    "-new",
                    "-key",
                    str(worker_root / "tls" / "worker.key"),
                    "-subj",
                    "/CN=worker-impostor",
                    "-out",
                    str(substituted),
                ],
                check=True,
                capture_output=True,
            )
            tampered = attach_identity(
                {
                    **{key: value for key, value in join.items() if key != "join_identity"},
                    "certificate_request_pem": substituted.read_text(encoding="ascii"),
                },
                "join_identity",
            )
            with self.assertRaisesRegex(ProtocolError, "subject does not match"):
                issue_worker_credentials(
                    lifecycle,
                    tampered,
                    ca_certificate=cert["ca"],
                    ca_key=cert["ca_key"],
                    controller_certificate=cert["server"],
                    controller_trust_state=root / "controller-trust.jsonl",
                )

    @unittest.skipUnless(os.name == "posix", "Fedora commissioning requires POSIX")
    def test_activation_validates_all_credentials_before_installing(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            cert = _certificates(root)
            lifecycle, worker_root, join = self._approved_join(root, cert)
            credentials = issue_worker_credentials(
                lifecycle,
                join,
                ca_certificate=cert["ca"],
                ca_key=cert["ca_key"],
                controller_certificate=cert["server"],
                controller_trust_state=root / "controller-trust.jsonl",
            )
            replaced_certificate = attach_identity(
                {
                    **{
                        key: value
                        for key, value in credentials.items()
                        if key != "credential_identity"
                    },
                    "worker_certificate_pem": cert["client"].read_text(encoding="ascii"),
                },
                "credential_identity",
            )
            with self.assertRaises(ProtocolError):
                activate_worker_credentials(replaced_certificate, state_root=worker_root)
            self.assertFalse((worker_root / "tls" / "worker.pem").exists())

            original_key = worker_root / "tls" / "worker.key"
            replacement = root / "replacement.key"
            subprocess.run(
                [
                    shutil.which("openssl") or "openssl",
                    "genpkey",
                    "-algorithm",
                    "RSA",
                    "-pkeyopt",
                    "rsa_keygen_bits:2048",
                    "-out",
                    str(replacement),
                ],
                check=True,
                capture_output=True,
            )
            original_key.write_bytes(replacement.read_bytes())
            with self.assertRaisesRegex(ProtocolError, "local worker private key"):
                activate_worker_credentials(credentials, state_root=worker_root)
            self.assertFalse((worker_root / "tls" / "worker.pem").exists())
            self.assertFalse((worker_root / "installation.json").exists())

    @unittest.skipUnless(os.name == "posix", "Fedora commissioning requires POSIX")
    def test_join_rejects_worker_identity_mismatch(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            cert = _certificates(root)
            lifecycle = LifecycleStore(root / "controller" / "lifecycle.jsonl")
            authorization = lifecycle.create_authorization(
                expected_worker_identity="worker-expected"
            )
            material = build_enrollment_material(
                authorization,
                controller_id="controller-home",
                controller_host="controller.example.test",
                controller_port=7444,
                controller_certificate_pem=cert["server"].read_text(encoding="ascii"),
            )
            with self.assertRaisesRegex(ProtocolError, "another worker identity"):
                prepare_join_request(
                    material,
                    worker_id="worker-substituted",
                    state_root=root / "worker",
                )


if __name__ == "__main__":
    unittest.main()
