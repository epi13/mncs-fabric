from __future__ import annotations

import json
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from mncs_fabric.bundle_transfer import BundleCache, TRANSFER_SCHEMA


def _publish(cache: BundleCache, name: str, payload: bytes) -> Path:
    identity = name if len(name) == 64 else (name + "0" * 64)[:64]
    target = cache.bundle_root / identity
    target.mkdir(parents=True)
    (target / "archive.zip").write_bytes(payload)
    (target / "content").mkdir()
    (target / "content" / "task.py").write_text("print(1)\n", encoding="utf-8")
    (target / "metadata.json").write_text(
        json.dumps(
            {
                "schema_version": TRANSFER_SCHEMA,
                "bundle_identity": "sha256:" + identity,
                "archive_identity": "sha256:" + "b" * 64,
            }
        ),
        encoding="utf-8",
    )
    return target


class BundleCacheGcTests(unittest.TestCase):
    def test_gc_preserves_in_use_and_evicts_unused(self) -> None:
        with TemporaryDirectory() as directory:
            cache = BundleCache(Path(directory), max_cache_bytes=64 * 1024)
            keep = _publish(cache, "a", b"keep" * 100)
            drop = _publish(cache, "b", b"drop" * 100)
            Path(keep / "archive.zip").touch()
            status = cache.status(in_use={"sha256:" + keep.name})
            self.assertGreater(status["reclaimable_bytes"], 0)
            dry = cache.gc(dry_run=True, confirm=False, in_use={"sha256:" + keep.name})
            self.assertEqual(dry["action"], "dry-run")
            self.assertTrue(drop.exists())
            result = cache.gc(
                dry_run=False,
                confirm=True,
                in_use={"sha256:" + keep.name},
                needed_bytes=1,
            )
            self.assertEqual(result["action"], "collected")
            self.assertTrue(keep.exists())
            self.assertFalse(drop.exists())

    def test_gc_fails_closed_when_only_active_entries_remain(self) -> None:
        with TemporaryDirectory() as directory:
            cache = BundleCache(Path(directory), max_cache_bytes=32)
            keep = _publish(cache, "c", b"0123456789" * 8)
            result = cache.gc(
                dry_run=False,
                confirm=True,
                in_use={"sha256:" + keep.name},
                needed_bytes=10_000,
            )
            self.assertEqual(result["action"], "failed")
            self.assertEqual(result["reason"], "SAFE_RECLAMATION_INSUFFICIENT")
            self.assertTrue(keep.exists())


if __name__ == "__main__":
    unittest.main()
