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
`InProcessTransport`. Classifications:

```text
implemented / unit-tested / CI-tested / integration-tested / live-tested
```

```text
inspect → desired state → plan → drain → apply typed actions
  → UPDATE_PLANNED → DRAINING → UPDATE_APPLYING → UPDATE_APPLIED
  → RESTART_PENDING → DISCONNECT_EXPECTED → RECONNECTING
  → VERSION_VERIFYING → CERTIFYING → READY
```

This closure pass is **implemented + unit-tested**. It is not live-tested on
the physical fleet until GitHub Actions is green and a24/a25 is installed.

Live processes remain on **0.2.0a23** until those gates pass.

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

## READY invariant

`READY` is a single predicate (`evaluate_ready`). Certify, reconcile, resume,
quarantine recovery, and rollout all use it. A worker is READY only when:

```text
current health result = CERTIFIED
AND current desired-state conformance has no blocking failure
AND certification and conformance are bound to the current inventory identity
AND conformance is bound to the current desired_state_identity
AND no unresolved update/restart transaction makes the worker unverified
AND management policy allows READY
```

Missing evidence is `VERIFYING` (or `DEGRADED` / `MAINTENANCE` as
appropriate), never READY. Legacy a23 ledgers that have a certification but
no conformance record cannot become READY until conformance is evaluated
against the current desired state.

`resume` does not promote a previously certified worker to READY. It
re-evaluates the predicate.

## Certification

Certification tests layers the node actually has. A build node is not failed
for missing models. An installer exit code is never treated as certification.

Layers: connectivity, execution, repository access, GitHub, Forge, Joern,
Ollama, model discovery, inference, harness.

Inference generate is model-agnostic: first discovered local model, prompt
`ping`. It runs only when an inference profile is assigned.

## Rollback

Rollback capability is explicit per action: `exact`, `partial`, `unsupported`,
`manual`. Do not call Fabric package rollback `full`.

When a content-addressed artifact is staged, the previous descriptor and
bytes are retained under `stage/previous/` if they exist. The update
transaction records FROM version/artifact and TO version/artifact.

If the previously running version predates content-addressed storage:

```text
previous artifact identity = UNKNOWN / unavailable
rollback capability = partial
```

Exact rollback is proven in-process: restore retained bytes, restart,
reconnect, observe the previous version, certify, conform, READY. A missing
or corrupt previous artifact is `ROLLBACK_FAILURE` and quarantines the
worker. That path is unit-tested, not live-tested.

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
trusted.

Transfer sessions are identity-bound:

```text
worker identity + controller identity + artifact identity
+ transfer identity + expected chunk count + expected total bytes
+ digest + expiry
```

Sequences must satisfy `0 <= sequence < expected_chunk_count`. Out-of-range,
conflicting duplicate, missing, extra, expired, oversized, malformed
base64, digest/size mismatch, mid-transfer identity switch, and a second
active offer are rejected. Temporary `.part` files are not valid staged
artifacts until digest verification succeeds.

When the archive is a recognizable wheel or sdist, package metadata is
inspected without executing package code and must match
`package == mncs-fabric` and `version == descriptor.version`. Unrecognized
bytes remain content-addressed; that provenance gap is recorded, not
invented.

The worker verifies the digest before apply and returns `restart_required`
**before** the process exits.

The update transaction begins before mutation and advances as evidence is
obtained:

```text
UPDATE_PLANNED → DRAINING → UPDATE_APPLYING → UPDATE_APPLIED
→ RESTART_PENDING → DISCONNECT_EXPECTED → RECONNECTING
→ VERSION_VERIFYING → CERTIFYING → READY
```

Failure paths are explicit (`ROLLBACK_APPLYING`, `FAILED`, `QUARANTINED`,
`ROLLED_BACK`). Transitions are evidence-backed. The controller can answer
whether a disconnect was expected, whether the same enrolled worker
reconnected before the deadline, and which version came back. A reconnect
with the old or malformed version fails `VERSION_VERIFYING` and does not
become READY.

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

Canary success requires post-restart READY, not a successful apply.
`restart_required=True` or any of `MAINTENANCE`, `DISCONNECT_EXPECTED`,
`RECONNECTING`, `VERSION_VERIFYING`, `CERTIFYING`, `DEGRADED`,
`QUARANTINED` is not a successful canary.

Statuses: `CANARY_PENDING`, `CANARY_SUCCEEDED`, `CANARY_FAILED`,
`ROLLOUT_CONTINUING`, `ROLLOUT_STOPPED`. With `stop_on_failure=true`,
worker #2 is not reconciled until worker #1 is confirmed READY. A failed
canary mutates nothing in the remainder. `stop_on_failure=false` may
continue and is recorded as `FAILED` if any worker failed.

This orchestrator is unit-tested. It is not live-tested on the physical
fleet in this closure pass.

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
