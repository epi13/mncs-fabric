"""Small, explicit worker-side containment provider boundary.

Bubblewrap is the first Linux/Fedora provider.  Compatibility execution remains
available only when it is selected explicitly; it never reports OS containment.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Mapping, Sequence


CONTAINMENT_MODES = frozenset({"required", "compatibility-uncontained"})


class ContainmentUnavailable(RuntimeError):
    """Raised when required OS containment cannot be constructed."""


@dataclass(frozen=True)
class ContainmentLaunch:
    argv: list[str]
    cwd: Path
    environment: dict[str, str]
    provider: str
    filesystem_enforcement: str
    network_enforcement: str
    limitations: tuple[str, ...]


class BubblewrapProvider:
    """Construct a no-shell bubblewrap invocation around one staged bundle."""

    name = "bubblewrap"

    def __init__(self, executable: str | None = None) -> None:
        self.executable = executable or shutil.which("bwrap")

    @property
    def available(self) -> bool:
        return (
            os.name == "posix"
            and sys.platform.startswith("linux")
            and bool(self.executable)
            and Path(str(self.executable)).is_file()
            and os.access(str(self.executable), os.X_OK)
        )

    def user_namespace_available(self) -> bool:
        """True when this process can create a Bubblewrap user namespace."""

        if not self.available or self.executable is None:
            return False
        try:
            completed = subprocess.run(
                [
                    self.executable,
                    "--die-with-parent",
                    "--unshare-user",
                    "--unshare-pid",
                    "/bin/true",
                ],
                check=False,
                capture_output=True,
                timeout=2,
            )
        except (OSError, subprocess.TimeoutExpired):
            return False
        return completed.returncode == 0

    def launch(
        self,
        argv: Sequence[str],
        *,
        workdir: Path,
        cwd: Path,
        environment: Mapping[str, str],
        network_policy: str,
    ) -> ContainmentLaunch:
        if not self.available or self.executable is None:
            raise ContainmentUnavailable(
                "required bubblewrap containment is unavailable on this worker"
            )
        if not self.user_namespace_available():
            raise ContainmentUnavailable(
                "required bubblewrap user namespace is unavailable "
                "(nested sandbox or kernel userns restriction)"
            )
        if not argv or Path(argv[0]).resolve() != Path(sys.executable).resolve():
            raise ContainmentUnavailable(
                "bubblewrap containment currently supports only the worker-local Python runtime"
            )
        root = workdir.resolve()
        current = cwd.resolve()
        try:
            relative_cwd = current.relative_to(root)
        except ValueError as exc:
            raise ContainmentUnavailable("contained working directory escapes the staged bundle") from exc

        command = [
            self.executable,
            "--die-with-parent",
            "--new-session",
            "--unshare-user",
            "--unshare-pid",
            "--unshare-ipc",
            "--unshare-uts",
            "--unshare-cgroup-try",
            "--proc",
            "/proc",
            "--dev",
            "/dev",
            "--tmpfs",
            "/tmp",
            "--dir",
            "/work",
            "--bind",
            str(root),
            "/work",
        ]
        if network_policy == "DECLARED_OFFLINE":
            command.append("--unshare-net")
        else:
            # Preserve ordinary host-network behavior without exposing all of
            # /etc.  These are the resolver and public trust roots commonly
            # required by Python network clients on Fedora and Debian-family
            # workers.
            command.extend(("--dir", "/etc"))
            for network_file in (
                Path("/etc/hosts"),
                Path("/etc/nsswitch.conf"),
                Path("/etc/resolv.conf"),
            ):
                if network_file.exists():
                    command.extend(("--ro-bind", str(network_file), str(network_file)))
            for trust_root in (Path("/etc/pki"), Path("/etc/ssl")):
                if trust_root.exists():
                    command.extend(("--ro-bind", str(trust_root), str(trust_root)))

        for system_root in (Path("/usr"), Path("/lib"), Path("/lib64"), Path("/bin")):
            if system_root.exists():
                command.extend(("--ro-bind", str(system_root), str(system_root)))

        runtime_root = Path(sys.prefix).resolve()
        if runtime_root != Path("/usr") and Path("/usr") not in runtime_root.parents:
            command.extend(("--dir", "/runtime", "--ro-bind", str(runtime_root), "/runtime"))
            runtime_python = Path("/runtime/bin") / Path(sys.executable).name
            if not (runtime_root / "bin" / Path(sys.executable).name).exists():
                runtime_python = Path("/usr/bin") / Path(sys.executable).name
        else:
            runtime_python = Path(sys.executable).resolve()

        contained_environment = {
            key: value
            for key, value in environment.items()
            if key not in {"HOME", "USERPROFILE"}
        }
        contained_environment.update(
            {
                "PATH": "/runtime/bin:/usr/bin:/bin",
                "PYTHONNOUSERSITE": "1",
                "TMPDIR": "/tmp",
            }
        )
        command.append("--clearenv")
        for key, value in sorted(contained_environment.items()):
            command.extend(("--setenv", key, value))
        command.extend(("--chdir", str(Path("/work") / relative_cwd)))
        command.append(str(runtime_python))
        command.extend(argv[1:])
        return ContainmentLaunch(
            argv=command,
            cwd=Path("/"),
            environment={},
            provider=self.name,
            filesystem_enforcement="BUBBLEWRAP_BUNDLE_ONLY",
            network_enforcement=(
                "BUBBLEWRAP_NETWORK_NAMESPACE" if network_policy == "DECLARED_OFFLINE" else "HOST_NETWORK"
            ),
            limitations=(
                "Bubblewrap isolation is host-kernel enforced but is not hardware-backed attestation.",
                "The staged bundle is writable during execution so declared result files can be produced.",
            ),
        )


def prepare_launch(
    argv: Sequence[str],
    *,
    workdir: Path,
    cwd: Path,
    environment: Mapping[str, str],
    network_policy: str,
    mode: str,
    provider: BubblewrapProvider | None = None,
) -> ContainmentLaunch:
    """Return the exact process invocation and truthful enforcement facts."""

    if mode not in CONTAINMENT_MODES:
        raise ValueError(f"unsupported containment mode: {mode}")
    if mode == "required":
        return (provider or BubblewrapProvider()).launch(
            argv,
            workdir=workdir,
            cwd=cwd,
            environment=environment,
            network_policy=network_policy,
        )
    return ContainmentLaunch(
        argv=list(argv),
        cwd=cwd,
        environment=dict(environment),
        provider="none",
        filesystem_enforcement="COMPATIBILITY_UNCONTAINED",
        network_enforcement="UNKNOWN",
        limitations=(
            "Compatibility execution is bounded but not an operating-system sandbox.",
            "The worker service account retains its ambient filesystem and network authority.",
        ),
    )
