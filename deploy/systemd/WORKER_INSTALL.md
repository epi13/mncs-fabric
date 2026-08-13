# Fedora worker commissioning and updates

The supported commissioning helper is intentionally explicit and file-mediated.
It does not discover controllers, move private keys, disable TLS verification,
change firewall rules, or use SSH as the Fabric execution path.

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

Rerunning the installer upgrades the isolated environment and restarts the unit
without deleting the private key, trust ledger, installation identity, or worker
execution ledger. Uninstall is deliberately not implicit.

Enabling a user unit does not by itself prove boot-before-login behavior. If the
deployment requires the worker to reconnect before interactive login, the
operator must enable the user's systemd manager at boot (normally
`loginctl enable-linger USER`) and verify `loginctl show-user USER -p Linger`
reports `Linger=yes`. This is a host-administration action and is intentionally
not performed by the installer.
