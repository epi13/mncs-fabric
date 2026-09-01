# Capability broker deployment

The capability broker is an explicit host service for operations that cannot
run in the unprivileged worker account. The worker sends a versioned,
identity-bound request to a root-owned local endpoint. The broker validates the
host profile, applies a fixed platform adapter, records an append-only audit
entry, and returns a bounded result. It never accepts `sudo bash`, a shell
string, an executable path supplied by the caller, SSH/WinRM fallback, or an
interactive password.

## Linux

1. Copy one profile object from
   `capability-profiles.example.json` to `/etc/mncs-fabric/worker-02.capability.json`
   or `/etc/mncs-fabric/worker-03.capability.json`. Preserve the profile
   identity after generation; do not edit identity-bearing fields by hand.
2. Set `MNCS_FABRIC_WORKER_UID` in the systemd unit environment to the numeric
   UID of the worker service account. The socket is created mode `0660` and
   peer credentials are checked again by the broker.
3. Create `/run/mncs-fabric`, `/var/lib/mncs-fabric`, and the configured
   experiment roots with root ownership and the intended worker group ACL.
4. Install the unit as `mncs-fabric-capability-broker@worker-02.service` and
   enable it only for the explicitly selected worker.

`worker-02` is the protected profile: package/service/machine-change families
require an active bounded lease, and services are restricted to the explicit
allowlist. `worker-03` is the explicitly selected unrestricted profile for a
sacrificial host. “Unrestricted” removes the lease requirement and narrow
family allowlist, but still keeps the structured operation boundary and fixed
argv adapters. The worker-03 prerequisite check is `sudo -n true`; it never
prompts and never records a password.

Lease grants, revocation, expiry, cleanup, request results, and audit entries
are append-only under `/var/lib/mncs-fabric`. Exact request identities are
replayed from durable results after restart, so a retry does not re-run a
privileged operation.

## Windows

The Python Windows adapter and named-pipe server are implemented in
`mncs_fabric.capability_broker`. Run the service as `LocalSystem` and pass an
explicit worker SID to `--allowed-sid`; the server creates a protected named
pipe ACL for LocalSystem, Administrators, and that SID. Use
`--pipe-name \\.\pipe\mncs-fabric-capability-broker` and the Windows profile
with `mode=windows-capability-broker`. The Windows adapter uses fixed
`sc.exe`, `shutdown.exe`, `netsh.exe`, `pnputil.exe`, and `winget.exe` argv
shapes. Service installation, SID selection, and driver/package behavior must
be validated on the target Windows image before production use.

The repository installer
`deploy/windows/Install-FabricCapabilityBroker.ps1` creates or updates the
LocalSystem service and requires an explicit worker SID. Run it from an
elevated PowerShell session with `-Action Install`, then use `-Action Start`.
The installer is idempotent for the service definition and does not replace
profiles, credentials, or ledgers.

The existing current-user worker launcher remains a separate, limited worker
deployment. It does not grant the launcher administrative authority.
