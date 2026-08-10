from __future__ import annotations

from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from mncs_fabric.bundle_transfer import BundleCache
from mncs_fabric.bundles import build_bundle_archive
from mncs_fabric.errors import StorageError


class BundleCacheRepairTests(unittest.TestCase):
    @staticmethod
    def _transfer(cache: BundleCache, archive: Path, bundle_identity: str, archive_identity: str) -> str:
        chunk_bytes = 64
        chunk_count = (archive.stat().st_size + chunk_bytes - 1) // chunk_bytes
        transfer_id = "repair-transfer"
        status = cache.begin(
            transfer_id=transfer_id,
            bundle_identity=bundle_identity,
            archive_identity=archive_identity,
            total_bytes=archive.stat().st_size,
            chunk_bytes=chunk_bytes,
            chunk_count=chunk_count,
        )
        if status == "ALREADY_PRESENT":
            return status
        with archive.open("rb") as stream:
            for sequence in range(chunk_count):
                data = stream.read(chunk_bytes)
                cache.chunk(
                    transfer_id=transfer_id,
                    bundle_identity=bundle_identity,
                    archive_identity=archive_identity,
                    sequence=sequence,
                    data=data,
                )
        committed, _, _ = cache.commit(
            transfer_id=transfer_id,
            bundle_identity=bundle_identity,
            archive_identity=archive_identity,
        )
        return committed

    def test_same_identity_offer_retransfers_when_published_content_was_mutated(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "source"
            source.mkdir()
            original = "print('healthy')\n"
            (source / "task.py").write_text(original, encoding="utf-8")
            archive = root / "bundle.zip"
            report = build_bundle_archive(source, archive)
            assert report.bundle_identity is not None
            assert report.archive_identity is not None
            cache = BundleCache(root / "cache")

            self.assertEqual(
                self._transfer(cache, archive, report.bundle_identity, report.archive_identity),
                "COMMITTED",
            )
            content = cache.root_for(report.bundle_identity, report.archive_identity)
            (content / "task.py").write_text("print('mutated')\n", encoding="utf-8")

            with self.assertRaisesRegex(StorageError, "content identity mismatch"):
                cache.root_for(report.bundle_identity, report.archive_identity)

            # A fresh offer for the same immutable archive must discard the derived
            # corrupted content and request the bytes again rather than saying the
            # bundle is already present forever.
            self.assertEqual(
                self._transfer(cache, archive, report.bundle_identity, report.archive_identity),
                "COMMITTED",
            )
            repaired = cache.root_for(report.bundle_identity, report.archive_identity)
            self.assertEqual((repaired / "task.py").read_text(encoding="utf-8"), original)

    def test_missing_published_content_is_rebuilt_from_same_archive(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "source"
            source.mkdir()
            (source / "task.py").write_text("print('ok')\n", encoding="utf-8")
            archive = root / "bundle.zip"
            report = build_bundle_archive(source, archive)
            assert report.bundle_identity is not None
            assert report.archive_identity is not None
            cache = BundleCache(root / "cache")
            self.assertEqual(
                self._transfer(cache, archive, report.bundle_identity, report.archive_identity),
                "COMMITTED",
            )

            content = cache.root_for(report.bundle_identity, report.archive_identity)
            (content / "task.py").unlink()
            self.assertEqual(
                self._transfer(cache, archive, report.bundle_identity, report.archive_identity),
                "COMMITTED",
            )
            repaired = cache.root_for(report.bundle_identity, report.archive_identity)
            self.assertTrue((repaired / "task.py").is_file())


if __name__ == "__main__":
    unittest.main()
