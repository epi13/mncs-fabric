# Windows Fabric worker operations

The canonical installer is `deploy/windows/Install-FabricWorker.ps1` in the
MNCS/Fabric repository. The repository copy is the source of truth. It installs
the generated launcher, `windows_worker_launcher.py` for bounded helper use,
and `launcher/worker-config.json` under the worker root. It does not replace
certificates, trust state, worker ledgers, bundles, or bundle caches.

## Installed layout

For the default worker, the layout is:

```text
C:\Users\<user>\mncs-fabric-worker\
  launcher\fabric_worker.ps1
  launcher\windows_worker_launcher.py
  launcher\worker-config.json
  certs\ca.pem, worker.pem, worker.key
  trust\worker-trust.jsonl
  state\worker-ledger.jsonl, worker-process.json
  logs\worker.stdout.log, worker.stderr.log, supervisor.log
  bundle-root\
  bundle-cache\
```

The installer no longer copies itself into `launcher`. A previous
`launcher/Install-FabricWorker.ps1` is removed by the canonical installer; run
future installation, update, and repair operations from the repository path.

## Lifecycle

Run PowerShell with `-NoProfile -NonInteractive -ExecutionPolicy Bypass` when
automating. The installer is current-user scoped and uses a Scheduled Task
with `LogonType Interactive`, `RunLevel Limited`; elevation is not required.

```powershell
$i = 'C:\path\to\mncs-fabric\deploy\windows\Install-FabricWorker.ps1'
& powershell -NoProfile -File $i -Action Install
& powershell -NoProfile -File $i -Action Start
& powershell -NoProfile -File $i -Action Status
& powershell -NoProfile -File $i -Action Restart
& powershell -NoProfile -File $i -Action Stop
& powershell -NoProfile -File $i -Action Update
& powershell -NoProfile -File $i -Action Repair
& powershell -NoProfile -File $i -Action Uninstall
```

`-Start` remains a compatibility alias for `-Action Start`. Start is
idempotent: a healthy worker returns `already-running` and is not relaunched.
Stop is idempotent: an absent worker returns `stopped`. Restart stops only a
worker whose command line matches the configured worker/controller/root/port,
waits for the listener to close, and then verifies the replacement is healthy.
Uninstall removes the task and generated launcher artifacts but preserves
operator data and identity material.

## Scheduled Task architecture

`MNCS-Fabric-Worker` has exactly one trigger: `AtLogOn` for the current user.
It can also be started explicitly with `Start-ScheduledTask`; manual startup is
not a second trigger. `MultipleInstances=IgnoreNew` prevents overlapping task
actions. The task has no one-minute repetition and no automatic restart loop.
The launcher starts the detached worker, then verifies both the expected
process command and the listener on port 7443 before reporting success.

The old `MNCS-Fabric-Worker-Watch` task is retired. A time trigger with
`Repetition.Interval=PT1M` repeatedly attempted to start a second worker and
recorded exit code 1 when the existing worker already owned port 7443.

## Python process model

On Windows, a venv `python.exe` is a redirector. It can appear as a parent
process while the base Python installation appears as its child and owns the
listening socket. Two Python PIDs with the same creation time and the same
`mncs_fabric worker serve` command can therefore represent one logical worker.
Do not kill one merely because its executable path is the base interpreter.

The launcher correlates the worker ID, controller ID, installation root,
worker command, and port owner. It reports `HEALTHY` only when the port owner
is one of the expected worker processes. If another process owns 7443 it
reports `port-conflict` and never kills that process.

Useful diagnostics:

```powershell
Get-ScheduledTask -TaskName MNCS-Fabric-Worker | Format-List *
Get-ScheduledTaskInfo -TaskName MNCS-Fabric-Worker | Format-List *
Get-NetTCPConnection -State Listen -LocalPort 7443
Get-CimInstance Win32_Process | Where-Object { $_.CommandLine -match 'mncs_fabric.*worker serve' } |
  Select-Object ProcessId,ParentProcessId,ExecutablePath,CreationDate,CommandLine
Get-Content C:\Users\<user>\mncs-fabric-worker\logs\worker.stderr.log -Tail 50
```

## Repair and migration

For an existing installation, first run the repository installer with
`-Action Repair` (or `-Start`). It synchronizes the launcher/configuration,
removes the stale watch task and copied installer, repairs the main task, and
leaves a healthy worker running. If the old task is currently in a one-minute
repetition loop, the repair replaces it with the single logon trigger.

An old task created by an elevated administrator can reject replacement from a
limited current-user shell even though the task itself runs at `Limited`.
That is a one-time migration permission issue, not a requirement for ordinary
operation: run the repository installer once from an elevated PowerShell, then
use the normal current-user lifecycle commands thereafter.

If status reports `port-conflict`, identify the owner before stopping anything.
Only stop an unrelated owner through its own service/application controls;
never use a broad `taskkill /IM python.exe`. If the owner is an old Fabric
worker, use `-Action Stop` or `-Action Restart` after confirming its command
line and installation paths.

The task's limited current-user privilege is intentional for a worker using
user-owned files and an interactive logon token. A Windows service or
machine-wide privileged installation is a separate deployment mode and is not
silently substituted by this installer.

