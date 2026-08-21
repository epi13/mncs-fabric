# Fedora worker commissioning and updates

The supported commissioning helper is intentionally explicit and file-mediated.
It does not discover controllers, move private keys, disable TLS verification,
change firewall rules, or use SSH as the Fabric execution path.

Install or upgrade the controller first. This preserves
`~/.config/mncs-fabric/` and the authoritative ledgers below
`~/.local/state/mncs-fabric/`:

```bash
deploy/systemd/install-or-update-controller.sh /path/to/mncs-fabric
systemctl --user is-active mncs-fabric-controller.service
mncs-fabric controller doctor \
  --socket ~/.local/state/mncs-fabric/controller.sock
```

Edit the protected `~/.config/mncs-fabric/controller.env` before enrollment when
worker rendezvous is required, then restart the controller. Set all six rendezvous
TLS/listener values together. The Fabric-native controller identity defaults to
`mncs-fabric-controller` and can be changed through that environment file.

1. On the controller, create a one-time authorization and protected material file:

   ```bash
   mncs-fabric enrollment create --admin-socket STATE/controller-admin.sock \
     --worker-id WORKER --ttl 10m --material-output enrollment.json \
     --controller-id CONTROLLER --controller-host CONTROLLER_ADDRESS \
     --controller-port 7444 --controller-certificate controller.pem
   ```

2. Transfer `enrollment.json` using an operator-approved channel. On the worker,
   generate its durable private key and join request:

   ```bash
   mncs-fabric worker join --material enrollment.json --worker-id WORKER \
     --state-root ~/.local/state/mncs-fabric/workers/WORKER \
     --request-output join-request.json
   ```

3. Return only `join-request.json`. On the controller, submit, inspect, approve,
   and issue the public credential document:

   ```bash
   mncs-fabric enrollment submit join-request.json \
     --admin-socket STATE/controller-admin.sock
   mncs-fabric enrollment pending --admin-socket STATE/controller-admin.sock
   mncs-fabric enrollment approve REQUEST_ID --admin-socket STATE/controller-admin.sock
   # Stop the controller before the explicit offline signing operation.
   mncs-fabric enrollment issue join-request.json \
     --offline-state STATE/lifecycle.jsonl \
     --ca ca.pem --ca-key ca.key --controller-certificate controller.pem \
     --trust-state controller-trust.jsonl --output worker-credentials.json
   ```

4. Transfer the public credential document to the worker, activate it, then
   install or update its isolated environment and user service:

   ```bash
   mncs-fabric worker activate --credentials worker-credentials.json \
     --state-root ~/.local/state/mncs-fabric/workers/WORKER
   deploy/systemd/install-or-update-worker.sh WORKER /path/to/mncs-fabric
   ```

   On Fedora/Linux the generated environment requests bubblewrap containment and
   the installer fails if `bwrap` is unavailable. Install it with the host package
   manager before continuing. The worker private key is generated and remains only
   below its worker-local state root.

Rerunning either installer upgrades the isolated environment and restarts the
unit without deleting the private key, trust ledger, installation identity, or
worker execution ledger. A Git checkout also produces a protected
`~/.local/share/mncs-fabric/fabric-revision.txt` acceptance marker for both the
controller and worker. This prevents a same-version controller update from
silently retaining stale source provenance. The controller installer also
refreshes its installer-owned `MNCS_FABRIC_SOURCE_COMMIT` line while preserving
all operator rendezvous settings. Uninstall is deliberately not implicit.

Enabling a user unit does not by itself prove boot-before-login behavior. If the
deployment requires the worker to reconnect before interactive login, the
operator must enable the user's systemd manager at boot (normally
`loginctl enable-linger USER`) and verify `loginctl show-user USER -p Linger`
reports `Linger=yes`. This is a host-administration action and is intentionally
not performed by the installer.

## Upgrade, disconnect, revoke, and retire

Rerun either installer with the new source/release directory to upgrade. Controller
and worker identities, trust state, append-only ledgers, and worker installation
identity are preserved. After an upgrade or process restart, verify automatic
reconnection through the consumer socket:

```bash
systemctl --user --no-pager status mncs-fabric-controller.service
systemctl --user --no-pager status 'mncs-fabric-worker-rendezvous@WORKER.service'
mncs-fabric fleet status WORKER \
  --socket ~/.local/state/mncs-fabric/controller.sock
```

These are distinct operator actions:

- `systemctl --user stop mncs-fabric-worker-rendezvous@WORKER.service` disconnects
  the worker without deleting software or membership;
- `deploy/systemd/uninstall-worker.sh WORKER` disables its local unit, retires the
  installed environment file, and preserves private keys/ledgers; it does not revoke;
- `mncs-fabric worker revoke WORKER --reason REASON --admin-socket
  ~/.local/state/mncs-fabric/controller-admin.sock` appends authoritative controller
  revocation history; and
- `deploy/systemd/uninstall-controller.sh` removes the local controller unit while
  preserving Fabric configuration/state and does not revoke any worker.

Do not edit registry JSON for a rendezvous-enrolled worker. SSH may transfer the
file-mediated enrollment documents or assist diagnostics, but Fabric mTLS remains
the only job transport.

## Physical reboot acceptance

The acceptance helper is intentionally split around the disruptive reboot. It
records an AVAILABLE session, certificate/install identities, boot ID, network
addresses, linger state, and registry digest (or explicit registry absence):

```bash
python scripts/fedora_reboot_acceptance.py prepare \
  --socket STATE/controller.sock --controller-id CONTROLLER --worker-id WORKER \
  --fabric-commit "$(git rev-parse HEAD)" \
  --controller-trust-state STATE/controller-trust.jsonl \
  --worker-state-root /home/USER/.local/state/mncs-fabric/workers/WORKER \
  --ssh-alias WORKER_SSH_ALIAS --state reboot-prepared.json
```

An operator may reboot separately, or invoke the explicit disruptive step:

```bash
python scripts/fedora_reboot_acceptance.py request-reboot \
  --state reboot-prepared.json --ssh-alias WORKER_SSH_ALIAS \
  --worker-state-root /home/USER/.local/state/mncs-fabric/workers/WORKER \
  --yes-reboot
```

The verifier first waits on the Fabric consumer socket for a higher AVAILABLE
session generation. Only then does it make its first post-boot SSH diagnostic,
verify the changed boot ID and unchanged identities/state, and execute the
supplied bundle on the exact worker through Fabric:

```bash
python scripts/fedora_reboot_acceptance.py verify \
  --state reboot-prepared.json --output reboot-evidence.json \
  --socket STATE/controller.sock \
  --controller-trust-state STATE/controller-trust.jsonl \
  --worker-state-root /home/USER/.local/state/mncs-fabric/workers/WORKER \
  --ssh-alias WORKER_SSH_ALIAS --bundle-root examples/portable-python/bundle \
  --manifest examples/portable-python/artifact-manifest.json \
  --plan examples/portable-python/job-plan.json
```

Omit `--registry` for a rendezvous-only deployment; the evidence then records
registry absence. If supplied, the exact registry bytes must remain unchanged.
The consumer never receives the worker address or credentials. Address changes
are recorded as operational history, not authorization state.

Until `prepare`, a real physical reboot, and `verify` all complete on the commissioned
host, reboot survival remains `UNKNOWN`. Process-restart tests do not change that
claim. The manual acceptance checklist is: confirm lingering; run `prepare`; reboot
the physical worker; wait for a higher AVAILABLE session generation; run `verify`;
retain `reboot-evidence.json`; and confirm its unchanged identities plus exact-worker
dispatch result before reporting physical reboot acceptance.
