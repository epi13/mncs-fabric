# Fleet management and desired-state reconciliation

Fabric now has a management plane beside the existing work plane.

```text
                    FABRIC CONTROLLER
                           │
          ┌────────────────┴────────────────┐
          │                                 │
     Work Plane                       Management Plane
     dispatch / execute               inspect / plan /
     target admission                 reconcile / certify
          │                                 │
          └───────────────┬─────────────────┘
                          │
              Authenticated worker agent
```

The worker reports **actual state**. The controller holds **desired state**.
Fabric diffs the two, plans typed actions, optionally applies them, certifies
the result, and records an append-only receipt.

This is not `controller → SSH → shell`. Remote argv execution remains the
existing job path. Routine maintenance uses named actions over the same
mutual-TLS protocol as `worker.describe`.

## What is functioning

Physical deployments observed in 0.2.0a22:

- Linux `fabric-worker-01` uses systemd-user unit `mncs-fabric-worker.service`
  under `/home/fabric/mncs-fabric-worker/current` with linger enabled.
- Windows `collamore02-windows` uses a current-user Scheduled Task
  `MNCS-Fabric-Worker` plus the existing detached launcher. The task is
  registered without elevation. Starting it from a non-interactive SSH
  session is unreliable; AtLogOn and the detached launcher are the
  supported restart paths.

The following path is implemented and unit-tested in-process and over
`InProcessTransport`:

```text
inspect → desired state → plan → drain → apply typed actions → certify → READY or QUARANTINE
```

Live CLI against the current process:

```bash
mncs-fabric worker inspect --local --label local-worker --json
mncs-fabric worker plan --local --label local-worker --profile mncs-linux-worker
mncs-fabric worker certify --local --label local-worker --profile mncs-linux-worker
```

Against a persistent controller:

```bash
mncs-fabric worker inspect WORKER --socket STATE/controller.sock
mncs-fabric worker plan WORKER --socket STATE/controller.sock --profile mncs-linux-worker
mncs-fabric worker reconcile WORKER --admin-socket STATE/controller-admin.sock --apply --class A
mncs-fabric worker certify WORKER --admin-socket STATE/controller-admin.sock
mncs-fabric worker drain WORKER --admin-socket STATE/controller-admin.sock
mncs-fabric worker resume WORKER --admin-socket STATE/controller-admin.sock
mncs-fabric fleet inspect --admin-socket STATE/controller-admin.sock
mncs-fabric fleet status WORKER --socket STATE/controller.sock
```

`--apply` is explicit. Plan-only is the default.

## Inventory

`mncs-fabric.worker-inventory.v0.1` is a companion to
`worker-description.v0.2`. It does not replace describe/liveness.

The worker collects:

- identity and OS/distribution facts
- CPU, RAM, disk, accelerators
- Fabric/harness versions
- tools (`git`, `gh`, Python, pip, uv, rustc, cargo, gcc/clang, Joern, Forge, Ollama)
- runtimes with **discovered** install/service type
- configured or nearby Git repositories (never a blind `git pull`)
- services without assuming systemd
- health and credential availability (`gh auth` is tested, tokens are redacted)

Ollama is discovered as one of:

```text
systemd-system | systemd-user | windows-service | process | unknown | absent
```

`sudo systemctl restart ollama` against a missing `ollama.service` is exactly
the failure this adapter exists to prevent. Restart only runs when the
discovered manager is `systemd-user`. System and Windows service restarts
require privilege and are planned, not auto-applied.

## Desired state and profiles

Profiles are reusable and host-agnostic:

```text
mncs-linux-worker
mncs-windows-worker
mncs-inference-worker
mncs-build-worker
mncs-ravel-worker
mncs-mnel-worker
```

They compose. Machine names are not encoded in generic logic.

Requirement levels: `present`, `supported-current`, `mncs-supported`,
`running`, `absent`.

Update classes:

| Class | Meaning | Default auto-apply |
| --- | --- | --- |
| A | Fabric / harness runtime | plan; apply only with `--apply` and authorization `none` |
| B | Developer tooling | verify; install is privilege |
| C | AI runtime / models | rediscover; pull needs operator authorization |
| D | Operating system | never auto-applied |
| E | Service/config | user-systemd restart only |

`supported-current` for `fabric-worker` means the controller's package version.

## Worker states

Liveness remains `AVAILABLE` / `UNAVAILABLE` / `UNKNOWN`.

Management state is separate:

```text
READY → BUSY | DRAINING | MAINTENANCE | QUARANTINED | DEGRADED
DRAINING → MAINTENANCE | READY | QUARANTINED | DEGRADED
MAINTENANCE → VERIFYING | DEGRADED | QUARANTINED | READY
VERIFYING → READY | DEGRADED | QUARANTINED | MAINTENANCE
QUARANTINED → DRAINING | MAINTENANCE | VERIFYING | READY
```

`READY` requires **health CERTIFIED** and **no blocking desired-state
nonconformance**. A later passing certification/conformance pair may recover a
quarantined worker. Health failure still cannot be READY.

The scheduler ignores any worker whose management state is not `READY` or
`BUSY`. The worker also refuses `dispatch.request` while drained, in
maintenance, or quarantined.

## Certification versus conformance

**Health certification** tests advertised capabilities. Missing optional tools
are `SKIP` / not applicable. This is not profile conformance.

**Desired-state conformance** evaluates assigned profiles. A required `git`
that is absent is `NOT_INSTALLED` and **blocks READY** even if health is
`CERTIFIED`. Privilege-gated or one-time items (`local-harness`, `gh` auth)
are recorded as nonconformance but are advisory for scheduling.

Claim boundary: health is not conformance; conformance is not attestation.

## Certification

Certification tests layers the node actually has. A build node is not failed
for missing models. An installer exit code is never treated as certification.

Layers: connectivity, execution, repository access, GitHub, Forge, Joern,
Ollama, model discovery, inference, harness.

Inference generate is model-agnostic: first discovered local model, prompt
`ping`. It runs only when an inference profile is assigned.

## Rollback

Rollback capability is explicit per action: `full`, `partial`, `unsupported`,
`manual`. Fabric package updates record the previous version and can attempt
a pinned `pip install` restore. Most tooling installs are `unsupported` or
`privilege`. Rollback failure quarantines the worker.

## Security and privilege

- Maintenance travels on the existing enrolled mTLS protocol.
- Payloads are typed actions, never a shell string.
- No sudo password, no root shell, no controller-side command interpolation.
- Privilege-bearing mutations are `SKIPPED` with `PRIVILEGE_REQUIRED`.
- Receipts redact GitHub tokens, PEM keys, and `password=`/`token=` values.
- `worker.exec` is not a protocol message. Emergency work uses the existing
  fixed-argv `dispatch.request` job path.
- Inventory and certification are worker-observed, not attestation.

One-time bootstrap remains the existing commissioning flow in
[WORKER_INSTALL.md](../deploy/systemd/WORKER_INSTALL.md). After that, routine
inspect/plan/reconcile/certify is controller-driven.

## Self-update

A Fabric package update is a class A action bound to a **content-addressed
artifact** (`digest`, `size`, `package`, `version`). The controller transfers
those bytes over mTLS (`worker.package-artifact.*`). Filenames are not
trusted. The worker verifies the digest before apply and returns
`restart_required` **before** the process exits.

The controller records an update transaction in `DISCONNECT_EXPECTED` so the
authorized restart is not mistaken for an unexplained outage.

Linux uses `mncs-fabric-worker-upgrade.service` (no `ProtectHome`) to rewrite
the worker venv, then `systemctl --user restart mncs-fabric-worker.service`.

Windows uses current-user Scheduled Tasks `MNCS-Fabric-Worker` (AtLogOn) and
`MNCS-Fabric-Worker-Watch` (1-minute idempotent start) plus
`windows_worker_launcher.py` (detached / `CREATE_BREAKAWAY_FROM_JOB`).
`schtasks /Run` from SSH is not the supported restart path.

The first time a pre-0.2.0a21 worker is brought onto this path, the staged
package must be copied onto the host once. After that, the controller can
request the same upgrade/restart cycle without a login.

Controller self-update is designed the same way and is not auto-applied.

## Commons

Routine successful updates do not publish Commons objects. Unusual
discoveries (for example Ollama not managed by system `ollama.service`) emit
`mncs-fabric.operational-knowledge.v0.1` Finding/Decision companions. Commons
ingestion is a separate step; Fabric does not import Commons.

## Scheduling

Availability windows remain operator policy in `availability.py`. Maintenance
should be requested when the worker is idle or explicitly drained. Fabric does
not hard-code a person's calendar.

Canary rollout is represented as sequential per-worker reconcile with
`stop_on_failure` left to the operator/CLI loop. A built-in multi-worker
orchestrator is not claimed in this version.

## Bootstrapping (unavoidable one-time)

1. Install and enroll the worker with the existing commissioning helpers.
2. Keep the worker under a supervisor that can restart it after a staged
   package update.
3. Do not give the controller a sudo password.

After those steps, Alexander should not need to log into each machine for
inventory, planning, verification, certification, or user-level repairs.

## Troubleshooting

| Symptom | Layer |
| --- | --- |
| `Unit ollama.service not found` | inventory `service_type` is not `systemd-system`; rediscover |
| plan shows `PRIVILEGE_REQUIRED` | install needs host package manager; not auto-applied |
| `gh` FAIL / `AUTH_FAILURE` | binary present, `gh auth login` still required on the worker |
| certification `failing layer: inference` | runtime reachable but generate failed |
| worker stays `QUARANTINED` | cert failed or rollback failed; inspect receipt, repair, certify |
| `fleet inspect` without backend | persistent controller has no worker backend configured |
