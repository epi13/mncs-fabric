# Worker version and update protocol

Fabric updates a worker through an explicit state machine, not a restart
loop. `src/mncs_fabric/update_lifecycle.py` owns the transaction states:

`UPDATE_PLANNED -> DRAINING -> UPDATE_APPLYING -> UPDATE_APPLIED ->`
`RESTART_PENDING -> DISCONNECT_EXPECTED -> RECONNECTING ->`
`VERSION_VERIFYING -> CERTIFYING -> READY`

with `ROLLBACK_APPLYING`, `ROLLED_BACK`, `FAILED`, and `QUARANTINED`
for recovery. Only the listed transitions are legal; the same relation
is reconstructed in `mncs/update_lifecycle.mncs` and executed by the
MNCS toolchain (see `docs/MNCS_UPDATE_POLICY.md`).

## Stages

1. **Version discovery.** `supervisor.inspect_supervisor` observes the
   local supervisor kind (`systemd-user`, `windows-scheduled-task`,
   `windows-service`, `process`, `absent`), unit state, restart policy,
   and package version. `classify_worker_version` reports `current`,
   `upgradeable`, `bootstrap-required`, or `unsupported` against the
   management minimum.
2. **Staging.** The controller transfers a content-addressed package
   artifact (`worker.artifact.stage` / `transfer_package_artifact`) with
   a digest/size descriptor (`artifact.json`). Workers stage bytes and
   the descriptor; nothing executes at stage time.
3. **Apply-time provenance.** `supervisor.apply_staged_upgrade` verifies
   the staged bytes against the descriptor (`digest` plus `size_bytes`)
   before pip install. A mismatch fails closed (`PACKAGE_FAILURE`) so a
   substituted artifact is never installed as a trusted update. A staged
   file with no descriptor, or a live operator checkout directory, may
   only proceed as explicitly `UNVERIFIED` (`operator-file` /
   `operator-checkout`); the result carries `provenance` verbatim so
   evidence distinguishes verified updates from operator trust. The
   descriptor covers content addressing, not signature attestation.
4. **Drain and restart.** Maintenance plans drain ordinary work first;
   the scheduler and the worker both refuse new work while draining,
   in maintenance, degraded, or quarantined. The worker stages work and
   asks the supervisor to restart; the worker process never kills
   itself. Linux uses the `mncs-fabric-worker-upgrade.service` oneshot
   (`apply-staged`); Windows uses the detached launcher restart helper.
5. **Reconnect and verify.** The worker re-establishes its rendezvous
   session (new generation, never a regressed one), the controller
   observes the reported version (`VERSION_VERIFYING`), and
   certification plus desired-state checks must pass before `READY`.
   A missed reconnect deadline quarantines the worker; a later
   operator-requested certification may recover it only after exact
   expected-version, health, and desired-state checks.
6. **Rollout and rollback.** `rollout.py` runs sequential per-worker
   reconcile with canary gating and stop-on-failure; a canary counts
   only after post-restart `READY`, not after apply. Rollback restores
   the previous artifact (verified against its descriptor when one
   exists) or the previous package version.

## Platform notes

- **Linux/systemd** (`deploy/systemd`): `Restart=on-failure` with a 2s
  delay on the rendezvous worker unit. The worker dials out, so
  controller restarts and network blips resolve into a fresh session
  generation without manual intervention.
- **Windows** (`deploy/windows`, `scripts/windows_worker_launcher.py`):
  a current-user scheduled task plus a detached restart helper; the
  install is idempotent and a bundled inspect/repair script restores
  `MNCS-Fabric-Worker` without elevation. There is no OS-level
  `on-failure` supervision equivalent, so recovery depends on the
  launcher state file surviving the failure.
- **Controllers** restart under the same `on-failure` unit; all session
  and lifecycle state is ledger-owned, so a controller restart is a
  reconnect event for workers, not a state loss.

## Observed reliability

`worker-03` (Fedora, systemd rendezvous unit) held one session to
generation 51 across the 9-day controller uptime window: the
worker-initiated session plus OS supervision absorbs both worker-side
and controller-side restarts. The Windows worker and `worker-02` take
the polling/launcher path with more operator-visible failure modes.
The systematic fix is the protocol above (drain, verified apply,
generation-safe reconnect, quarantine with certified recovery), not
per-node hand-tuning; per-node differences that remain are supervision
and network environment, documented in the worker inventory.
