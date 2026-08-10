# Raspberry Pi / Linux ARM worker

Fabric treats ARM as an observed substrate, not a device-brand special case.
The worker capability record uses the actual `platform.machine()` value (for
example `aarch64` or `armv7l`) and the existing `os:linux`/`arch:*` vocabulary.
Resource observations remain separate from the stable node fingerprint.

## Explicit operator configuration

Copy the sanitized example to the ignored local path and fill in the real
account, key, hostname, and TLS address:

```bash
mkdir -p .fabric/operator
cp examples/raspberry-pi/operator.local.example.json \
  .fabric/operator/raspberry-pi-worker.local.json
```

The same values may be supplied with explicit CLI arguments or the
`MNCS_FABRIC_PI_*` environment variables. The helpers never scan the LAN or
guess a username, key, hostname, or address. The SSH host key must already be
present in the operator's `known_hosts` under strict verification.

When the working connection is an existing OpenSSH alias or agent-backed
configuration, use the alias example instead:

```bash
cp examples/raspberry-pi/operator.alias.example.json \
  .fabric/operator/raspberry-pi-worker.local.json
```

Alias mode resolves only bounded effective host/user/port and boolean
configuration facts through `ssh -G`; it does not store identity-file paths,
agent data, or unrelated SSH configuration. The alias remains the SSH
bootstrap endpoint. `worker_host` is the separate direct Fabric TLS address.

## Preflight and native execution

Run the bounded diagnostic first:

```bash
python scripts/linux_worker_preflight.py \
  --config .fabric/operator/raspberry-pi-worker.local.json \
  --output build/raspberry-pi-preflight.json
```

It records the observed Linux release, architecture, Python identity, CPU
count, and hostname. A failed account/key mapping is `UNKNOWN`; it is not
worker or execution evidence.

After trust material and the exact Fabric revision have been staged through
the operator bootstrap path, run:

```bash
python scripts/raspberry_pi_native_bundle_test.py \
  --config .fabric/operator/raspberry-pi-worker.local.json \
  --output build/raspberry-pi-native
```

This delegates to the generic native EA-NEXT-002 harness. SSH stages only
Fabric bootstrap material and lifecycle state. The candidate bundle is
offered, chunked, independently verified, atomically cached, and dispatched
over direct mutually authenticated Fabric TLS. No SSH tunnel or arbitrary
remote shell is part of the Fabric execution path.

## Evidence boundary

A successful run can establish operator-controlled development evidence for a
Linux/ARM worker, portable bundle execution, records, receipts, collections,
and reconciliation. It does not establish hardware attestation, worker
honesty, sandboxing, correctness, protected custody, independent evaluation,
MNCS conformance, or certification. A Raspberry Pi that lacks a required
capability is explicitly ineligible or `UNKNOWN`; Fabric does not silently
fall back or infer capabilities from the device name.

The checked-in `development-evidence/raspberry-pi-preflight.json` is historical
evidence from the earlier run: a known-host alias was present, but no usable
SSH account and key mapping was available at that time. The later
`raspberry-pi-preflight-current.json` records a separate strict attempt with
the operator-supplied endpoint and key mapping; the host accepted the offered
public key but rejected the signature, so commissioning remains `UNKNOWN` and
no Fabric execution was attempted. Neither record overwrites the other.
