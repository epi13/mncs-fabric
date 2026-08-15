from __future__ import annotations

import unittest

from mncs_fabric.versioning import FabricVersion, classify_worker_version, parse_fabric_version


class VersioningTests(unittest.TestCase):
    def test_prereleases_sort_and_releases_follow_alphas(self) -> None:
        self.assertLess(parse_fabric_version("0.2.0a19"), parse_fabric_version("0.2.0a21"))
        self.assertLess(parse_fabric_version("0.2.0a99"), parse_fabric_version("0.2.0"))
        self.assertEqual(classify_worker_version("0.2.0a24", minimum=FabricVersion(0, 2, 0, 21)), "current")
        self.assertEqual(classify_worker_version("0.2.0a10", minimum=FabricVersion(0, 2, 0, 21)), "upgradeable")
        self.assertEqual(classify_worker_version("0.1.0", minimum=FabricVersion(0, 2, 0, 21)), "bootstrap-required")

    def test_malformed_versions_are_none_not_mixed_tuples(self) -> None:
        for value in (None, "", "nope", "0.2.0a", "0.2.0ab", "1.2.3.4", "v1", "0.2.0a-1"):
            self.assertIsNone(parse_fabric_version(value), value)
        self.assertEqual(classify_worker_version("garbage", minimum=FabricVersion(0, 2, 0, 21)), "unsupported")
