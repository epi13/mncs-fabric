from __future__ import annotations

from pathlib import Path
import shutil
import subprocess
import unittest


ROOT = Path(__file__).resolve().parents[1]
INSTALLER = ROOT / "deploy" / "windows" / "Install-FabricWorker.ps1"
LAUNCHER = ROOT / "deploy" / "windows" / "fabric_worker.ps1"
WINDOWS_LAUNCHER = ROOT / "scripts" / "windows_worker_launcher.py"
DOC = ROOT / "docs" / "WINDOWS_WORKER.md"


class WindowsInstallationContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.installer = INSTALLER.read_text(encoding="utf-8")
        cls.launcher = LAUNCHER.read_text(encoding="utf-8")
        cls.helper = WINDOWS_LAUNCHER.read_text(encoding="utf-8")
        cls.doc = DOC.read_text(encoding="utf-8")

    def test_installer_has_explicit_idempotent_lifecycle(self) -> None:
        for action in ("Install", "Start", "Stop", "Restart", "Update", "Repair", "Status", "Uninstall"):
            self.assertIn(action, self.installer)
        self.assertIn("if ($Start) { $Action = \"Start\" }", self.installer)
        self.assertIn("task-already-correct", self.installer)
        self.assertIn("legacy_watch_removed", self.installer)

    def test_task_is_logon_only_and_never_minute_repeating(self) -> None:
        self.assertNotIn("-RepetitionInterval", self.installer)
        self.assertNotIn('Register-ScheduledTask -TaskName "MNCS-Fabric-Worker-Watch"', self.installer)
        self.assertIn("$triggers.Count -ne 1", self.installer)
        self.assertIn("-MultipleInstances IgnoreNew", self.installer)
        self.assertIn("RestartCount -ne 0", self.installer)
        self.assertIn("New-ScheduledTaskTrigger -AtLogOn", self.installer)

    def test_installer_copies_only_repository_artifacts(self) -> None:
        self.assertIn("$sourceLauncher", self.installer)
        self.assertIn("$sourceHelper", self.installer)
        self.assertIn("Copy-Item -LiteralPath $sourceLauncher", self.installer)
        self.assertIn("Copy-Item -LiteralPath $sourceHelper", self.installer)
        self.assertIn('Remove-Item -LiteralPath $legacyInstaller', self.installer)
        self.assertNotIn('Copy-Item -LiteralPath $PSScriptRoot -Destination', self.installer)

    def test_launcher_correlates_worker_identity_and_port(self) -> None:
        for marker in (
            "Get-CimInstance Win32_Process",
            "Get-NetTCPConnection",
            "netstat -ano",
            "--worker-id",
            "--controller-id",
            "PORT_CONFLICT",
            "port-conflict",
            "already-running",
            "Start-Process",
            "Stop-Process",
            "startup_timeout_seconds",
            "$PSScriptRoot",
        ):
            self.assertIn(marker, self.launcher)

    def test_launcher_does_not_kill_unrelated_port_owner(self) -> None:
        self.assertIn('if ($health.state -eq "PORT_CONFLICT") { throw', self.launcher)
        self.assertIn("Get-ExpectedProcesses $Settings | Sort-Object ProcessId -Descending", self.launcher)
        self.assertNotIn("taskkill", self.launcher)

    def test_deployed_helper_remains_a_repository_artifact(self) -> None:
        self.assertIn("process-start token", self.helper)
        self.assertIn("CREATE_BREAKAWAY_FROM_JOB", self.helper)
        self.assertIn("--state", self.helper)

    def test_documentation_describes_migration_and_process_model(self) -> None:
        for marker in (
            "deploy/windows/Install-FabricWorker.ps1",
            "MNCS-Fabric-Worker",
            "AtLogOn",
            "redirector",
            "7443",
            "port-conflict",
            "Uninstall",
        ):
            self.assertIn(marker, self.doc)

    @unittest.skipUnless(shutil.which("powershell") or shutil.which("pwsh"), "PowerShell is not installed")
    def test_powerShell_scripts_parse(self) -> None:
        shell = shutil.which("powershell") or shutil.which("pwsh")
        command = (
            "$errors=@(); [System.Management.Automation.Language.Parser]::ParseFile('"
            + str(INSTALLER).replace("'", "''")
            + "',[ref]$null,[ref]$errors)|Out-Null; if($errors.Count){exit 1}; "
            + "[System.Management.Automation.Language.Parser]::ParseFile('"
            + str(LAUNCHER).replace("'", "''")
            + "',[ref]$null,[ref]$errors)|Out-Null; if($errors.Count){exit 1}"
        )
        completed = subprocess.run([shell, "-NoProfile", "-NonInteractive", "-Command", command], capture_output=True, text=True)
        self.assertEqual(completed.returncode, 0, completed.stderr or completed.stdout)


if __name__ == "__main__":
    unittest.main()

