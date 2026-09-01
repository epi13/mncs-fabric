# Fabric capability broker

The capability broker is the privileged-worker control boundary. It lets the
management plane express machine preparation and recovery as typed intents
without turning Fabric into a remote shell.

```text
agent / operator
       |
       | versioned capability request (identity-bound JSON)
       v
Fabric controller -- enrolled mTLS --> worker protocol
                                      |
                                      v
                           worker-local capability broker
                           | profile + lease + replay check
                           v
                 fixed Linux adapter / Windows service adapter
                                      |
                                      v
                      bounded result + append-only audit
```

## Contracts

The capability broker uses `mncs-fabric.capability-broker.v0.1`. Requests
contain the worker identity, capability family, operation, exact argument
object, experiment/session provenance, optional lease identity, timestamp, and
a canonical `request_identity`. Results contain the same request binding plus
`PASS`, `FAIL`, `UNKNOWN`, or `SKIPPED`, bounded output, change state, and an
optional audit identity. Contract schemas live in `schemas/`.

The supported family namespace covers package and service management, reboot
and shutdown, kernel parameters/modules, performance counters, eBPF, devices,
mounts/namespaces/cgroups, experiment directories/users, containers, drivers,
firewall, boot settings, and bounded hardware/system observation. Each family
has an enumerated operation set and an exact argument shape. Unknown families,
operations, fields, shell metacharacters, unsafe paths, and oversized values
fail closed.

Neither the request nor the result is an attestation. A `PASS` means the
selected adapter reported success; it does not prove the host, kernel, driver,
service, or experiment is honest or semantically correct.

## Host profiles

Authorization is selected by an explicit identity-bound profile. It is never
inferred from a hostname, IP address, or a default “Linux means root” branch.
The checked-in example profiles are:

| Worker | Platform | Mode | Policy |
| --- | --- | --- | --- |
| `worker-03` | Linux | `unrestricted` | Sacrificial host; structured families are available without leases, but no shell endpoint exists. |
| `worker-02` | Linux | `capability-broker` | Broad family namespace, explicit service/experiment/device/sysctl boundaries, and leases for destructive families. |
| `windows-worker` | Windows | `windows-capability-broker` | Explicit Windows service, package, firewall, driver, directory, and machine-operation policy. |

The source example is
[`capability-profiles.example.json`](/home/epi13/Documents/Projects/mncs-fabric/deploy/systemd/capability-profiles.example.json).
An operator should generate or edit a host-specific profile and verify its
identity before deployment; the example identities are fixtures, not proof of
the local host configuration.

## Leases and audit

Protected profiles require a bounded lease for high-risk families such as
package/service changes, module load/unload, mounts, cgroups, firewall, driver,
boot, container, user, reboot, and shutdown. A lease is bound to a worker,
optional experiment, capability set, operation set, grant time, and expiry;
the maximum TTL is 24 hours. Grant, revoke, expiry, and cleanup are append-only
state transitions. Cleanup retains historical evidence and never erases the
ledger.

Every request is recorded with its redacted arguments and bounded result. The
broker also keeps an exact request-result ledger. Retrying an identical request
returns the durable result without invoking the adapter again. If a process
dies after the audit append but before the result append, the audit body is
used to recover the result and close the replay window.

## Experiment requirements and reconciliation

Experiment definitions can be normalized into
`mncs-fabric.experiment-requirements.v0.1` with package, sysctl, service,
directory, capability, and reboot/shutdown requirements. The broker
reconciler probes current state before scheduling mutation requests:

```python
requirements = build_experiment_requirements(
    worker_identity="worker-02",
    experiment_identity="exp-2026-08-31",
    capabilities=["package-management", "kernel-parameter-management"],
    packages=["fio"],
    sysctl={"kernel.perf_event_paranoid": "-1"},
    services={"fabric-worker": "running"},
    experiment_directory="/var/lib/mncs/experiments/exp-2026-08-31",
)
report = broker.reconcile(requirements, apply=True, lease_identity=lease_id)
```

The reconciler is state-based and idempotent for package, sysctl, service, and
experiment-directory preparation. It reports `UNKNOWN` when the adapter cannot
establish current state and never treats that as compliance. Reboot and
shutdown remain explicit disruptive requests and are never silently inferred
from a package or service result.

An operator can route one request through the persistent controller admin
surface with the CLI. The argument object is supplied as a JSON file and is
validated as the exact operation shape:

```bash
mncs-fabric worker capability-request worker-02 package-management install \
  --arguments install-fio.json --lease-identity LEASE_ID \
  --admin-socket /var/lib/mncs-fabric/controller-admin.sock
```

## Platform adapters

Linux invokes only fixed absolute system executables with `shell=False` and
allowlisted arguments. The current adapter covers package query/install/remove/
refresh, systemd service operations, reboot/shutdown, allowlisted sysctl and
perf/eBPF controls, kernel module load/unload/status, experiment directories,
cgroup directories/limits, device metadata, and bounded observations. Mount,
namespace, experiment-user, container, driver, firewall, and boot operations
return explicit `SKIPPED` until their narrower implementations are reviewed.

Windows uses fixed `sc.exe`, `shutdown.exe`, `netsh.exe`, `pnputil.exe`, and
`winget.exe` argument shapes for the implemented service, machine, package,
firewall, driver, and experiment-directory operations. The broker service
transport is a LocalSystem named pipe with a DACL for LocalSystem,
Administrators, and one configured worker SID. It does not open a TCP listener.
Unsupported Windows families return `SKIPPED`; they do not fall back to
PowerShell or `cmd.exe`.

## Deployment and recovery

Linux deployment is described in
[`CAPABILITY_BROKER_INSTALL.md`](/home/epi13/Documents/Projects/mncs-fabric/deploy/systemd/CAPABILITY_BROKER_INSTALL.md)
and uses the root-owned
[`mncs-fabric-capability-broker.service`](/home/epi13/Documents/Projects/mncs-fabric/deploy/systemd/mncs-fabric-capability-broker.service).
The worker account receives only the local socket access it needs. `worker-03`
must be deliberately selected and its noninteractive prerequisite is checked
with the fixed `sudo -n true` probe; no secret is requested or stored.

Windows deployment must run the broker as LocalSystem, pass a verified worker
SID and host-specific profile, and validate the service/package/driver image
on the actual Windows build. The current-user worker launcher remains
unprivileged and separate from the broker.

On restart, the append-only lease, audit, and result ledgers are reopened and
verified by the existing Fabric ledger implementation. Active leases retain
their original expiry; expired or revoked leases cannot authorize a request.
Corrupt state, invalid profile identity, malformed frames, wrong worker
identity, unauthorized peer credentials, or unsupported operations fail closed.

## Explicit non-goals and deferred work

- No arbitrary privileged command, shell string, script body, SSH/WinRM action,
  caller-selected executable, or interactive password is accepted.
- The broker does not attest to the machine or decide experiment semantics.
- A protected operation that is not implemented is `SKIPPED`/`UNKNOWN`, never a
  best-effort command or silent fallback.
- The persistent controller service exposes capability requests only through
  its explicit admin socket when a worker backend is configured; the consumer
  socket cannot invoke them. Lease administration remains a host/broker-local
  operator boundary.
- Linux mount/namespace/user/container/driver/firewall/boot adapters and
  Windows service installation/image validation need target-host integration
  tests before production rollout.
- No claim is made that the checked-in examples have been validated on a
  physical worker-02, worker-03, or Windows host in this change.
