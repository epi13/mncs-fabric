# Changelog

## 0.2.0a0

- Adopt the current MNCS EA-NEXT-002 immutable execution-bundle shape with
  bounded offline ZIP verification, logical/archive identity separation, and
  companion receipt binding.
- Add transport-independent dispatch, bounded canonical framing, standard
  library TLS 1.2+ mutual certificate transport, operator-managed enrollment
  and revocation, registered remote dispatch, explicit worker-loss UNKNOWN,
  and bounded transport fault controls.
- Add additive EA-NEXT-005 challenge/replay compatibility with scoped nonces,
  receipt binding, and a durable single-use Fabric replay ledger.
- Add current experimental MNCS typed execution-receipt and companion
  execution-assurance adapters without changing Fabric v0.1 record meaning.
- Add the public `FabricService` boundary and project-local Forge Provider
  Protocol validation workflow.
- Add canonical controller/worker envelopes, optional HMAC authentication,
  durable append-only local ledgers, duplicate/replay protection, and
  deterministic capability-aware in-process scheduling.
- Add adversarial receipt, protocol, storage, scheduler, and integration tests.
  Real second-host evidence, bulk bundle transfer, protected custody,
  attestation, and independent evaluation remain deferred.

## 0.1.0a0 — unreleased

- Establish canonical record identities and artifact manifests.
- Add cross-platform node capability capture.
- Add bounded local argv execution and result collection.
- Add execution-record verification and cohort reconciliation.
- Add versioned schemas, tests, CI, documentation, and a portable example.
