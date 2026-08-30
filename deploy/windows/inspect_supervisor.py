"""Report Windows Fabric supervisor state. Repair is explicit via --repair."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path


def _run(argv: list[str], timeout: float = 20.0) -> dict[str, object]:
    try:
        completed = subprocess.run(
            argv,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return {"argv": argv, "returncode": None, "stdout": "", "stderr": str(exc)}
    return {
        "argv": argv,
        "returncode": completed.returncode,
        "stdout": completed.stdout[-4000:],
        "stderr": completed.stderr[-2000:],
    }


def main() -> int:
    home = Path.home()
    root = home / "mncs-fabric-worker"
    report = {
        "schema": "mncs-fabric.windows-supervisor-inspect.v0.1",
        "user": os.environ.get("USERNAME"),
        "home": str(home),
        "python": sys.executable,
        "python_version": sys.version.split()[0],
        "root": str(root),
        "paths": {
            "gpu_python": str(home / "mncs-fabric-gpu" / ".venv" / "Scripts" / "python.exe"),
            "worker_python": str(root / ".venv" / "Scripts" / "python.exe"),
            "launcher": str(root / "launcher" / "fabric_worker.ps1"),
            "ca": str(root / "certs" / "ca.pem"),
            "worker_pem": str(root / "certs" / "worker.pem"),
            "worker_key": str(root / "certs" / "worker.key"),
            "trust": str(root / "trust" / "worker-trust.jsonl"),
        },
        "path_exists": {},
        "tasks": {},
        "repair": None,
    }
    for key, value in report["paths"].items():
        report["path_exists"][key] = Path(value).is_file()
    for name in ("MNCS-Fabric-Worker", "MNCS-Fabric-Worker-Watch"):
        report["tasks"][name] = _run(["schtasks", "/Query", "/TN", name, "/FO", "LIST"])
    report["python_mncs_fabric"] = _run(
        [sys.executable, "-c", "import mncs_fabric; print(mncs_fabric.__version__)"]
    )
    repair = "--repair" in sys.argv[1:]
    installer = Path(__file__).with_name("Install-FabricWorker.ps1")
    bundled_launcher = Path(__file__).with_name("fabric_worker.ps1")
    if repair:
        steps: list[dict[str, object]] = []
        launcher_dest = root / "launcher" / "fabric_worker.ps1"
        if bundled_launcher.is_file():
            launcher_dest.parent.mkdir(parents=True, exist_ok=True)
            launcher_dest.write_bytes(bundled_launcher.read_bytes())
            steps.append({"step": "copy-launcher", "destination": str(launcher_dest), "copied": True})
            report["path_exists"]["launcher"] = launcher_dest.is_file()
        else:
            steps.append({"step": "copy-launcher", "copied": False, "detail": "bundled fabric_worker.ps1 missing"})
        if not installer.is_file():
            report["repair"] = {"disposition": "FAIL", "detail": "Install-FabricWorker.ps1 missing from bundle", "steps": steps}
        else:
            installed = _run(
                [
                    "powershell.exe",
                    "-NoProfile",
                    "-NonInteractive",
                    "-ExecutionPolicy",
                    "Bypass",
                    "-File",
                    str(installer),
                ],
                timeout=60.0,
            )
            steps.append({"step": "install-scheduled-task", **installed})
            report["repair"] = {
                "disposition": "PASS" if installed.get("returncode") == 0 else "FAIL",
                "steps": steps,
            }
            report["tasks_after"] = {
                name: _run(["schtasks", "/Query", "/TN", name, "/FO", "LIST"])
                for name in ("MNCS-Fabric-Worker", "MNCS-Fabric-Worker-Watch")
            }
    encoded = json.dumps(report, indent=2, sort_keys=True)
    print(encoded)
    Path("supervisor-inspect.json").write_text(encoded + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
