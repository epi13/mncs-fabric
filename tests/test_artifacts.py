import tempfile
import unittest
from pathlib import Path

from mncs_fabric.artifacts import build_manifest, verify_manifest
from mncs_fabric.errors import IntegrityError


class ArtifactTests(unittest.TestCase):
    def test_manifest_detects_mutation_and_extras(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "a.txt").write_text("alpha", encoding="utf-8")
            manifest = build_manifest(root)
            verify_manifest(root, manifest)
            (root / "a.txt").write_text("beta", encoding="utf-8")
            with self.assertRaises(IntegrityError):
                verify_manifest(root, manifest)
            (root / "a.txt").write_text("alpha", encoding="utf-8")
            (root / "extra.txt").write_text("extra", encoding="utf-8")
            with self.assertRaises(IntegrityError):
                verify_manifest(root, manifest)

    def test_manifest_is_deterministic(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "z.txt").write_text("z", encoding="utf-8")
            (root / "a.txt").write_text("a", encoding="utf-8")
            self.assertEqual(build_manifest(root), build_manifest(root))
