from __future__ import annotations

import unittest

from mncs_fabric.desired_state import (
    PROFILE_CATALOG,
    default_profiles_for_platform,
    diff_desired_state,
    known_profiles,
    resolve_desired_state,
    validate_desired_state,
)
from mncs_fabric.errors import ValidationError
from tests.test_inventory import sample_inventory


class DesiredStateTests(unittest.TestCase):
    def test_profile_catalog_is_host_agnostic(self) -> None:
        self.assertIn("mncs-linux-worker", known_profiles())
        self.assertIn("mncs-windows-worker", known_profiles())
        self.assertIn("mncs-inference-worker", known_profiles())
        for name in PROFILE_CATALOG:
            self.assertNotIn("fabric-worker-01", name)
            self.assertNotIn("collamore", name)

    def test_platform_defaults_and_composition(self) -> None:
        self.assertEqual(default_profiles_for_platform("windows"), ("mncs-windows-worker",))
        desired = resolve_desired_state(
            worker_id="any-worker",
            profiles=["mncs-linux-worker", "mncs-inference-worker"],
            models={"qwen3": {"state": "present"}},
            supported_current={"fabric-worker": "0.2.0a21"},
            captured_at="2026-08-14T00:00:00Z",
        )
        checked = validate_desired_state(desired, expected_worker_id="any-worker")
        names = {(item["kind"], item["name"]) for item in checked["requirements"]}
        self.assertIn(("package", "fabric-worker"), names)
        self.assertIn(("runtime", "ollama"), names)
        self.assertIn(("model", "qwen3"), names)

    def test_stronger_override_wins(self) -> None:
        desired = resolve_desired_state(
            worker_id="any-worker",
            profiles=["mncs-linux-worker"],
            overrides=[{"kind": "tool", "name": "git", "update_class": "B", "level": "mncs-supported"}],
            captured_at="2026-08-14T00:00:00Z",
        )
        git = next(item for item in desired["requirements"] if item["name"] == "git")
        self.assertEqual(git["level"], "mncs-supported")

    def test_diff_is_idempotent_when_compliant(self) -> None:
        inventory = sample_inventory()
        desired = resolve_desired_state(
            worker_id="worker-a",
            profiles=["mncs-linux-worker", "mncs-inference-worker"],
            supported_current={"fabric-worker": "0.2.0a21"},
            captured_at="2026-08-14T00:00:00Z",
        )
        first = diff_desired_state(desired, inventory)
        second = diff_desired_state(desired, inventory)
        self.assertEqual(first["change_count"], second["change_count"])
        self.assertEqual(first["changes"], second["changes"])

    def test_diff_detects_missing_tool_and_version_drift(self) -> None:
        inventory = sample_inventory(git=False)
        desired = resolve_desired_state(
            worker_id="worker-a",
            profiles=["mncs-linux-worker"],
            supported_current={"fabric-worker": "9.9.9"},
            captured_at="2026-08-14T00:00:00Z",
        )
        diff = diff_desired_state(desired, inventory)
        names = {item["name"] for item in diff["changes"]}
        self.assertIn("git", names)
        self.assertIn("fabric-worker", names)
        self.assertFalse(diff["compliant"])

    def test_unknown_profile_is_rejected(self) -> None:
        with self.assertRaises(ValidationError):
            resolve_desired_state(worker_id="w", profiles=["not-a-profile"])
