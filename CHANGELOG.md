# Changelog

## 0.2.0a5 - runtime profiles and Windows worker preparation

- added identity-addressable Python runtime profiles to authenticated worker
  descriptions without serializing private executable paths;
- added bounded runtime-observation and post-execution binding contracts for
  optional provider probes;
- added a dependency-free synchronized Torch CUDA probe workload that never
  promotes `nvidia-smi` or `torch.cuda.is_available()` alone to CUDA proof;
- added Windows-aware PID-token lifecycle and explicit-endpoint preflight
  helpers without SSH tunneling or candidate execution over SSH; and
- preserved CUDA and sequential-offload public feature flags as false because
  no physical Windows endpoint was available for acceptance in this iteration.

## 0.2.0a4 - worker state and execution collections

- added authenticated worker descriptions containing bounded worker-observed
  node/resource/public-contract references;
- added expiring liveness state and controller-side remote observation refresh;
- added generic identity-addressed work-item and execution-collection
  contracts with explicit missing and conflicting-result dispositions; and
- added public-facade physical worker-state, scheduling, and loss/recovery
  evidence paths.

## Unreleased

- add `0.2.0a3` provider-neutral resource snapshots, placement requests,
  deterministic resource admission, freshness bounds, explicit accelerator
  rejection reasons, placement receipt references, schemas, and adversarial
  CPU/fake-accelerator tests;
- add a dependency-free Fabric resource probe and Forge validation for the
  resource/placement fixture boundary; physical CUDA remains optional and is
  not advertised without a real execution probe;

- publish `mncs-fabric.public-contract.v0.1`, `FabricClient`, typed remote
  worker configuration, consumer provenance bindings, and Fabric-owned
  consumer results/receipts;
- add bounded native EA-NEXT-002 bundle transfer with worker-side verification,
  atomic publication, and immutable cache;
- record direct physical native-transfer evidence and extend Forge validation
  to the public contract, consumer boundary, cache, and evidence profile;

- add an explicitly bounded persistent TLS worker service with request, idle,
  concurrency, and graceful-shutdown limits;
- add repeated physical-worker evidence covering PID continuity, challenge
  replay, duplicate/conflicting requests, and between-request revocation;
- derive worker receipt runner versions from the package version so deployed
  receipts do not retain the pre-0.2.0a1 bootstrap label;

## 0.2.0a2

- public distributed consumer contract and Fabric-generated receipts;
- generic provenance binding for consumer workload and Forge workflow
  references;
- bounded native execution-bundle transfer over authenticated Fabric
  envelopes, with immutable worker cache and direct Fedora evidence.

## 0.2.0a1

- bounded persistent worker service and repeatable physical two-node evidence;
- explicit between-request trust revocation and persistent replay tests;
- machine-readable validation for persistent physical evidence;

- repaired Windows ledger locking using handle-scoped release and deterministic
  cleanup, without an unlocked fallback;
- made dispatch replay identity stable across reconstructed retries while
  retaining the envelope message identity as an observation;
- added a bounded remote worker launcher and recorded the first direct
  Fedora-to-Fedora Fabric mTLS execution, restart/replay, revocation, and
  reconciliation evidence;
- added Forge validation for the sanitized physical-host evidence envelope.

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
