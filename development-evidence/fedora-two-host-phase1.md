# First Fedora-to-Fedora Fabric evidence

This is sanitized, operator-controlled development evidence for the direct
run `fedora-two-host-20260809T162507Z`, using Fabric commit
`642129bccc14b40196ab028b25a248f7fed2449e` on both hosts.

- Controller: `fabric-controller-01`, Linux/x86_64, 8 CPUs.
- Worker: `fabric-worker-01`, Fedora 43 development host, Linux/x86_64, 8 CPUs.
- Transport: direct controller-to-worker Fabric TLS on port 7443; no SSH tunnel.
- SSH was used only to stage the exact source, certificates, trust state, and
  verified portable execution material, because bulk Fabric bundle transfer is
  not implemented.
- The worker executed the portable deterministic Python workload through the
  Fabric protocol and returned an identity-bound record and EA-NEXT-005 receipt.
- The controller consumed the challenge once in its durable replay store and
  reconciled local and remote records with distinct node identities.
- Worker restart retry and controller restart retry were
  `DUPLICATE_IDEMPOTENT`; changed material under the retained request identity
  was `CONFLICTING_REPLAY`; a revoked worker certificate was rejected
  `FAIL_CLOSED` over a real TLS connection.

This does not establish sandboxing, correctness, execution assurance,
protected custody, independent evaluation, conformance, certification, or
independence. Both hosts were operated in one trust domain, the worker was a
bounded one-request service, and the raw ledgers remain operator-controlled.
See `fedora-two-host-phase1.json` for machine-readable identity references.
