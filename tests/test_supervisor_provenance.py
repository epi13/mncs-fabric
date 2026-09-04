"""Apply-time artifact provenance: verify staged bytes before pip install.

A substituted staged wheel must fail closed; an undescribed staged file or
a live checkout may only proceed as explicitly unverified, never as
validated.
"""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from mncs_fabric.package_artifact import (
    describe_package_artifact,
    write_artifact_descriptor,
)
from mncs_fabric.supervisor import _verify_apply_provenance, apply_staged_upgrade


def _stage(tmp: str, *, version: str = "0.2.0a31") -> Path:
    directory = Path(tmp) / "stage"
    directory.mkdir()
    wheel = directory / "mncs_fabric-0.2.0a31-py3-none-any.whl"
    wheel.write_bytes(b"fabric-test-wheel-bytes" * 64)
    descriptor = describe_package_artifact(wheel, version=version, source="test-staged")
    digest = descriptor["digest"].split(":", 1)[1]
    stored = directory / f"{digest}.whl"
    wheel.rename(stored)
    write_artifact_descriptor(directory, descriptor)
    return stored


class TestApplyProvenance(unittest.TestCase):
    def test_matching_descriptor_verifies(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            stored = _stage(tmp)
            provenance = _verify_apply_provenance(stored)
            self.assertEqual(provenance["status"], "VERIFIED")
            self.assertEqual(provenance["mode"], "descriptor")
            self.assertTrue(str(provenance["artifact_identity"]).startswith("sha256:"))

    def test_substituted_bytes_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            stored = _stage(tmp)
            with stored.open("r+b") as handle:
                handle.write(b"TAMPERED")
            provenance = _verify_apply_provenance(stored)
            self.assertEqual(provenance.get("disposition"), "FAIL")
            self.assertEqual(provenance.get("failure_class"), "PACKAGE_FAILURE")

    def test_apply_refuses_tampered_artifact_without_pip(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            stored = _stage(tmp)
            with stored.open("r+b") as handle:
                handle.write(b"TAMPERED")
            with patch("mncs_fabric.supervisor.run_argv") as pip:
                result = apply_staged_upgrade(
                    python="python3", source=str(stored), previous="0.2.0a30"
                )
            pip.assert_not_called()
            self.assertEqual(result.get("disposition"), "FAIL")
            self.assertEqual(result.get("failure_class"), "PACKAGE_FAILURE")

    def test_undescribed_file_is_explicitly_unverified(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            wheel = Path(tmp) / "mncs_fabric-0.2.0a31-py3-none-any.whl"
            wheel.write_bytes(b"operator-placed-bytes" * 64)
            with patch("mncs_fabric.supervisor.default_stage_dir", return_value=Path(tmp)):
                provenance = _verify_apply_provenance(wheel)
            self.assertEqual(provenance["status"], "UNVERIFIED")
            self.assertEqual(provenance["mode"], "operator-file")

    def test_checkout_directory_is_explicitly_unverified(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            checkout = Path(tmp) / "source"
            checkout.mkdir()
            (checkout / "pyproject.toml").write_text("[project]\nname='x'\n")
            provenance = _verify_apply_provenance(checkout)
            self.assertEqual(provenance["status"], "UNVERIFIED")
            self.assertEqual(provenance["mode"], "operator-checkout")


if __name__ == "__main__":
    unittest.main()
