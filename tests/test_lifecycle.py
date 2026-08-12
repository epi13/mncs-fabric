from __future__ import annotations

import json
import os
import threading
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from mncs_fabric.api import FabricClient
from mncs_fabric.controller_service import ControllerConfig, ControllerService
from mncs_fabric.errors import ProtocolError, StorageError, ValidationError
from mncs_fabric.canonical import verify_identity
from mncs_fabric.lifecycle import (
    AUTHORIZATION_SCHEMA,
    LifecycleStore,
    public_key_identity,
)


PUBLIC_KEY = """-----BEGIN PUBLIC KEY-----
MDEyMzQ1Njc4OWFiY2RlZg==
-----END PUBLIC KEY-----
"""


class LifecycleTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.store = LifecycleStore(self.root / "lifecycle.jsonl")

    def tearDown(self) -> None:
        self.temp.cleanup()

    def _authorization(self, *, worker_id: str = "worker-a", now: str = "2026-01-01T00:00:00Z", ttl: float = 600) -> dict[str, object]:
        return self.store.create_authorization(
            ttl_seconds=ttl,
            expected_worker_identity=worker_id,
            metadata={"site": "lab"},
            issued_at=now,
        )

    def _request(self, authorization: dict[str, object], *, worker_id: str = "worker-a", key: str = PUBLIC_KEY) -> dict[str, object]:
        return self.store.build_request(
            worker_identity=worker_id,
            public_key_pem=key,
            hostname_hint="worker-a.local",
            operating_system="linux",
            architecture="x86_64",
            authorization_id=str(authorization["authorization_id"]),
            requested_at="2026-01-01T00:01:00Z",
            metadata={"display": "test worker"},
        )

    def _enroll(self, *, worker_id: str = "worker-a", key: str = PUBLIC_KEY) -> dict[str, object]:
        authorization = self._authorization(worker_id=worker_id)
        request = self._request(authorization, worker_id=worker_id, key=key)
        self.store.submit_request(request, str(authorization["token"]), now="2026-01-01T00:02:00Z")
        self.store.approve_request(str(request["request_id"]), now="2026-01-01T00:03:00Z")
        return {"authorization": authorization, "request": request}

    def test_authorization_is_redacted_and_one_time(self) -> None:
        authorization = self._authorization()
        authorization_id = str(authorization["authorization_id"])
        self.assertIn("token", authorization)
        self.assertNotIn("token_digest", authorization)
        public = self.store.authorization(authorization_id, now="2026-01-01T00:00:01Z")
        self.assertNotIn("token", public)
        self.assertNotIn("token_digest", public)
        self.store.consume_authorization(str(authorization["token"]), worker_identity="worker-a", now="2026-01-01T00:00:02Z")
        self.assertEqual(self.store.authorization(authorization_id, now="2026-01-01T00:00:03Z")["status"], "CONSUMED")
        with self.assertRaises(ProtocolError):
            self.store.consume_authorization(str(authorization["token"]), worker_identity="worker-a", now="2026-01-01T00:00:04Z")
        with self.assertRaises(ProtocolError):
            self.store.consume_authorization("not-a-valid-token", worker_identity="worker-a")

    def test_expiry_wrong_identity_revoke_and_bounded_metadata(self) -> None:
        expired = self._authorization(ttl=1)
        with self.assertRaises(ProtocolError):
            self.store.consume_authorization(str(expired["token"]), worker_identity="worker-a", now="2026-01-01T00:00:02Z")
        self.assertEqual(self.store.authorization(str(expired["authorization_id"]), now="2026-01-01T00:00:02Z")["status"], "EXPIRED")
        authorization = self._authorization()
        with self.assertRaises(ProtocolError):
            self.store.consume_authorization(str(authorization["token"]), worker_identity="worker-b")
        self.store.revoke_authorization(str(authorization["authorization_id"]), reason="operator test", now="2026-01-01T00:00:02Z")
        with self.assertRaises(ProtocolError):
            self.store.consume_authorization(str(authorization["token"]), worker_identity="worker-a")
        with self.assertRaises(ValidationError):
            self.store.create_authorization(metadata={"private_key": "must reject"})
        with self.assertRaises(ValidationError):
            self.store.create_authorization(metadata={str(index): "x" for index in range(17)})

    def test_double_consumption_is_atomic(self) -> None:
        authorization = self._authorization()
        results: list[str] = []
        barrier = threading.Barrier(2)

        def consume() -> None:
            barrier.wait()
            try:
                self.store.consume_authorization(str(authorization["token"]), worker_identity="worker-a", now="2026-01-01T00:00:02Z")
                results.append("PASS")
            except ProtocolError:
                results.append("REJECTED")

        threads = [threading.Thread(target=consume) for _ in range(2)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        self.assertEqual(sorted(results), ["PASS", "REJECTED"])

    def test_request_validation_replay_and_conflicting_identity(self) -> None:
        authorization = self._authorization()
        request = self._request(authorization)
        submitted = self.store.submit_request(request, str(authorization["token"]), now="2026-01-01T00:02:00Z")
        self.assertEqual(submitted["status"], "PENDING")
        self.assertEqual(submitted["public_key_identity"], public_key_identity(PUBLIC_KEY))
        with self.assertRaises(ProtocolError):
            self.store.submit_request(request, str(authorization["token"]), now="2026-01-01T00:02:01Z")
        second_auth = self._authorization(now="2026-01-01T00:05:00Z")
        conflicting = self._request(second_auth, key=PUBLIC_KEY.replace("MDEy", "MDIy"))
        with self.assertRaises(ProtocolError):
            self.store.submit_request(conflicting, str(second_auth["token"]), now="2026-01-01T00:05:01Z")
        invalid = dict(request)
        invalid["unexpected"] = True
        with self.assertRaises(ValidationError):
            self.store.submit_request(invalid, str(authorization["token"]))
        with self.assertRaises(ValidationError):
            self.store.build_request(worker_identity="bad worker", public_key_pem=PUBLIC_KEY, hostname_hint="x", operating_system="linux", architecture="x86_64", authorization_id="a")
        with self.assertRaises(ValidationError):
            self.store.build_request(worker_identity="worker-z", public_key_pem="PRIVATE KEY", hostname_hint="x", operating_system="linux", architecture="x86_64", authorization_id="a")

    def test_decisions_bind_exact_request_and_retain_history(self) -> None:
        enrolled = self._enroll()
        request_id = str(enrolled["request"]["request_id"])
        decision = self.store.ledger.records(record_type="enrollment.decision")[0]["record"]
        self.assertEqual(decision["request_id"], request_id)
        self.assertEqual(decision["public_key_identity"], enrolled["request"]["public_key_identity"])
        self.assertEqual(self.store.request(request_id, now="2026-01-01T00:04:00Z")["status"], "APPROVED")
        with self.assertRaises(ProtocolError):
            self.store.deny_request(request_id)
        other_auth = self._authorization(worker_id="worker-b", now="2026-01-02T00:00:00Z")
        other_request = self._request(other_auth, worker_id="worker-b")
        self.store.submit_request(other_request, str(other_auth["token"]), now="2026-01-02T00:01:00Z")
        self.store.deny_request(str(other_request["request_id"]), reason="not commissioned", now="2026-01-02T00:02:00Z")
        with self.assertRaises(ProtocolError):
            self.store.approve_request(str(other_request["request_id"]))

    def test_active_identity_cannot_rebind_after_recommission(self) -> None:
        self._enroll()
        authorization = self._authorization(now="2026-01-03T00:00:00Z")
        request = self._request(authorization, key=PUBLIC_KEY.replace("MDEy", "MDIy"))
        with self.assertRaises(ProtocolError):
            self.store.submit_request(request, str(authorization["token"]), now="2026-01-03T00:01:00Z")

    def test_explicit_revocation_allows_recommission_with_new_key(self) -> None:
        enrolled = self._enroll()
        worker_id = str(enrolled["request"]["worker_identity"])
        self.store.revoke_worker(worker_id, reason="key rotation", now="2026-01-04T00:00:00Z")
        authorization = self._authorization(worker_id=worker_id, now="2026-01-04T00:01:00Z")
        request = self._request(authorization, key=PUBLIC_KEY.replace("MDEy", "MDIy"))
        self.store.submit_request(request, str(authorization["token"]), now="2026-01-04T00:02:00Z")
        self.store.approve_request(str(request["request_id"]), now="2026-01-04T00:03:00Z")
        self.assertEqual(self.store.membership(worker_id, now="2026-01-04T00:04:00Z")["membership_status"], "ENROLLED")

    def test_expired_request_gets_explicit_expired_decision(self) -> None:
        authorization = self._authorization(ttl=1)
        request = self._request(authorization)
        self.store.submit_request(request, str(authorization["token"]), now="2026-01-01T00:00:00Z")
        decision = self.store.expire_request(str(request["request_id"]), now="2026-01-01T00:01:00Z")
        self.assertEqual(decision["decision"], "EXPIRED")

    def test_membership_restart_revoke_and_presence_are_separate(self) -> None:
        enrolled = self._enroll()
        request = enrolled["request"]
        worker_id = str(request["worker_identity"])
        key_identity = str(request["public_key_identity"])
        before = self.store.status(worker_id, now="2026-01-01T00:04:00Z")
        self.assertEqual(before["membership_status"], "ENROLLED")
        self.assertEqual(before["presence"], "ABSENT")
        restarted = LifecycleStore(self.root / "lifecycle.jsonl")
        self.assertEqual(restarted.memberships(now="2026-01-01T00:04:00Z")[0]["worker_id"], worker_id)
        present = restarted.authenticate_session(worker_id, public_key_identity_value=key_identity, session_id="session-a", generation=1, now="2026-01-01T00:05:00Z")
        self.assertEqual(present["availability"], "AVAILABLE")
        stale = restarted.status(worker_id, now="2026-01-01T00:11:00Z")
        self.assertEqual(stale["presence"], "STALE")
        self.assertEqual(stale["availability"], "UNKNOWN")
        disconnected = restarted.disconnect_session(worker_id, session_id="session-a", generation=1, now="2026-01-01T00:12:00Z")
        self.assertEqual(disconnected["availability"], "UNAVAILABLE")
        self.assertEqual(disconnected["capability_freshness"], "UNKNOWN")
        revoked = restarted.revoke_worker(worker_id, reason="decommissioned", now="2026-01-01T00:13:00Z")
        self.assertEqual(revoked["membership_status"], "REVOKED")
        with self.assertRaises(ProtocolError):
            restarted.authenticate_session(worker_id, public_key_identity_value=key_identity, session_id="session-b", generation=1)

    def test_duplicate_identity_and_generation_are_deterministic(self) -> None:
        enrolled = self._enroll()
        worker_id = str(enrolled["request"]["worker_identity"])
        key_identity = str(enrolled["request"]["public_key_identity"])
        self.store.authenticate_session(worker_id, public_key_identity_value=key_identity, session_id="session-a", generation=1, now="2026-01-01T00:05:00Z")
        duplicate = self.store.authenticate_session(worker_id, public_key_identity_value=key_identity, session_id="session-b", generation=1, now="2026-01-01T00:06:00Z")
        self.assertEqual(duplicate["presence"], "DUPLICATE_IDENTITY")
        self.assertEqual(duplicate["availability"], "UNKNOWN")
        with self.assertRaises(ValidationError):
            self.store.authenticate_session(worker_id, public_key_identity_value=key_identity, session_id="session-a", generation=0)
        self.store.disconnect_session(worker_id, session_id="session-a", generation=1, now="2026-01-01T00:07:00Z")
        reconnect = self.store.authenticate_session(worker_id, public_key_identity_value=key_identity, session_id="session-b", generation=2, now="2026-01-01T00:08:00Z")
        self.assertEqual(reconnect["presence"], "PRESENT")
        self.assertEqual(reconnect["session_generation"], 2)

    def test_corrupt_state_is_unknown_and_secrets_are_absent(self) -> None:
        authorization = self._authorization()
        raw = self.store.path.read_text(encoding="utf-8")
        self.assertNotIn(str(authorization["token"]), raw)
        self.assertIn(AUTHORIZATION_SCHEMA, raw)
        self.store.path.write_text(raw + "{broken\n", encoding="utf-8")
        with self.assertRaises(StorageError):
            LifecycleStore(self.store.path).doctor()

    def test_public_client_can_address_shared_fabric_owned_state(self) -> None:
        enrolled = self._enroll()
        client = FabricClient("consumer", self.root / "consumer.jsonl", lifecycle_state_path=self.store.path)
        self.assertEqual(client.fleet_status(str(enrolled["request"]["worker_identity"]), now="2026-01-01T00:04:00Z")["membership_status"], "ENROLLED")
        self.assertEqual(client.fleet_status(str(enrolled["request"]["worker_identity"]), now="2026-01-01T00:04:00Z")["presence"], "ABSENT")

    def test_controller_runtime_owns_state_without_consumer_lifetime_claims(self) -> None:
        config = ControllerConfig("controller-a", self.store.path)
        service = ControllerService(config)
        initial_status = service.status(now="2026-01-01T00:00:00Z")
        self.assertEqual(initial_status["outcome"], "PASS")
        self.assertEqual(initial_status["fabric_version"], __import__("mncs_fabric").__version__)
        self.assertEqual(initial_status["service_contract"], "mncs-fabric.controller-service.v0.1")
        self.assertTrue(initial_status["public_contract_identity"].startswith("sha256:"))
        result = service.run(max_seconds=0.01)
        self.assertEqual(result["outcome"], "PASS")
        doctor = service.doctor(now="2026-01-01T00:00:01Z")
        expected_listener = "LOCAL_OPERATOR_SOCKET" if os.name == "posix" else "NOT_IMPLEMENTED"
        self.assertEqual(doctor["checks"]["administrative_listener"], expected_listener)
        self.assertEqual(doctor["checks"]["worker_rendezvous"], "NOT_IMPLEMENTED")
        self.assertEqual(LifecycleStore(self.store.path).doctor()["outcome"], "PASS")
        self.assertEqual(LifecycleStore(self.store.path).memberships(), [])
        restarted_service = ControllerService(config)
        self.assertEqual(restarted_service.status()["service_ledger"]["outcome"], "PASS")

    def test_concurrent_sessions_are_decided_under_one_ledger_lock(self) -> None:
        enrolled = self._enroll()
        worker_id = str(enrolled["request"]["worker_identity"])
        key_identity = str(enrolled["request"]["public_key_identity"])
        barrier = threading.Barrier(2)
        results: list[dict[str, object]] = []
        errors: list[Exception] = []

        def authenticate(session_id: str) -> None:
            try:
                barrier.wait()
                results.append(self.store.authenticate_session(worker_id, public_key_identity_value=key_identity, session_id=session_id, generation=1, now="2026-01-01T00:05:00Z"))
            except Exception as exc:  # pragma: no cover - assertion below diagnoses unexpected failures.
                errors.append(exc)

        threads = [threading.Thread(target=authenticate, args=(session,)) for session in ("session-a", "session-b")]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        self.assertEqual(errors, [])
        self.assertEqual(len(results), 2)
        events = [entry["record"] for entry in self.store.ledger.records() if entry["record_type"] == "presence.session"]
        self.assertEqual(len(events), 2)
        self.assertEqual(sum(event["event"] == "authenticated" for event in events), 1)
        self.assertEqual(sum(event["event"] == "duplicate-identity" for event in events), 1)
        self.assertEqual(self.store.status(worker_id, now="2026-01-01T00:05:01Z")["availability"], "UNKNOWN")

    def test_stale_session_reconnect_and_old_generation_reject(self) -> None:
        enrolled = self._enroll()
        worker_id = str(enrolled["request"]["worker_identity"])
        key_identity = str(enrolled["request"]["public_key_identity"])
        self.store.authenticate_session(worker_id, public_key_identity_value=key_identity, session_id="old", generation=1, now="2026-01-01T00:00:00Z")
        reconnect = self.store.authenticate_session(worker_id, public_key_identity_value=key_identity, session_id="new", generation=2, now="2026-01-01T00:06:00Z")
        self.assertEqual(reconnect["session_id"], "new")
        self.assertEqual(reconnect["presence"], "PRESENT")
        for entry in self.store.ledger.records(record_type="presence.session"):
            self.assertTrue(verify_identity(entry["record"], "presence_event_id"))
        with self.assertRaises(ProtocolError):
            self.store.authenticate_session(worker_id, public_key_identity_value=key_identity, session_id="old", generation=1, now="2026-01-01T00:07:00Z")


if __name__ == "__main__":
    unittest.main()
