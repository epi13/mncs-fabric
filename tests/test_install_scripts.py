from __future__ import annotations

from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]


class InstallScriptTests(unittest.TestCase):
    def test_controller_installer_records_checkout_revision(self) -> None:
        script = (ROOT / "deploy/systemd/install-or-update-controller.sh").read_text(encoding="utf-8")
        self.assertIn('git -C "$fabric_source" rev-parse --verify HEAD', script)
        self.assertIn('"$install_root/fabric-revision.txt"', script)
        self.assertIn('rm -f "$install_root/fabric-revision.txt"', script)
        self.assertIn('MNCS_FABRIC_SOURCE_COMMIT=', script)
        self.assertIn('sed -i "s/^MNCS_FABRIC_SOURCE_COMMIT=', script)

    def test_controller_and_worker_installers_share_revision_marker(self) -> None:
        controller = (ROOT / "deploy/systemd/install-or-update-controller.sh").read_text(encoding="utf-8")
        worker = (ROOT / "deploy/systemd/install-or-update-worker.sh").read_text(encoding="utf-8")
        self.assertIn('"$install_root/fabric-revision.txt"', controller)
        self.assertIn('"$install_root/fabric-revision.txt"', worker)


if __name__ == "__main__":
    unittest.main()
