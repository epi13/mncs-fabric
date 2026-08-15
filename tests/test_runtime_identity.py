from __future__ import annotations

import unittest

from mncs_fabric import __version__
from mncs_fabric.runtime_identity import collect_runtime_identity


class RuntimeIdentityTests(unittest.TestCase):
    def test_runtime_identity_reports_package_and_version(self) -> None:
        identity = collect_runtime_identity(role="controller")
        self.assertEqual(identity["package"], "mncs-fabric")
        self.assertEqual(identity["version"], __version__)
        self.assertEqual(__version__, "0.2.0a30")
        self.assertIn("source_commit", identity)
        self.assertIn("artifact_digest", identity)
        self.assertIn("build_identity", identity)

    def test_commit_or_digest_produces_build_identity(self) -> None:
        identity = collect_runtime_identity()
        if identity["source_commit"] or identity["artifact_digest"]:
            self.assertTrue(str(identity["build_identity"]).startswith("sha256:"))
        else:
            self.assertIsNone(identity["build_identity"])
