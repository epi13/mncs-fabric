# Changelog

## 0.2.0a18 - reusable deployment, containment, and durable lookup

- replace consumer-specific controller identity/state paths with Fabric-owned,
  configurable systemd deployment plus idempotent controller/worker update and
  explicit non-revoking uninstall helpers;
- add an explicit worker containment provider boundary, fail-closed required mode,
  and a concrete Fedora/Linux bubblewrap backend with bundle-only filesystem access,
  ambient-home removal, and offline network namespace enforcement;
- replace bounded retry scans with restart-rebuilt in-memory worker replay state and
  an identity-validated, stale-detecting derived target-evidence index whose JSONL
  ledger remains authoritative; and
- publish additive containment feature flags and controller config v0.3 without
  expanding the ordinary consumer authority surface.

## 0.2.0a17 - persistent substrate hardening and exact-target execution

- make lifecycle revocation authoritative over legacy registry entries, active
  rendezvous sessions, direct dispatch, and configured transport trust while
  retaining append-only history;
- route online enrollment mutations through the operator service, make offline
  signing explicit, and validate CA/controller/worker certificate, key, identity,
  and pin bindings before issuance or activation;
- add a two-phase Fedora reboot acceptance helper that verifies the Fabric consumer
  projection before post-reboot SSH and preserves physical status as `UNKNOWN` until
  a real reboot is completed;
- add exact no-fallback persistent target dispatch with current membership,
  authenticated presence, liveness, capability, runtime, context, and provenance
  re-admission plus first-class identity-addressed evidence;
- preserve deterministic worker-ledger idempotence across exact-target retry and
  expose stable target failure codes; and
- make rendezvous heartbeat deadlines tolerate the negotiated interval and declared
  job bound while advancing multi-command verified bundle transfer without a full
  heartbeat delay per chunk.

## 0.2.0a16 - persistent worker rendezvous and service execution

- route bounded execution requests through the persistent controller-owned worker
  backend instead of requiring consumers to own worker registry/trust material;
- add authenticated worker-initiated mTLS rendezvous sessions with controller-owned
  heartbeat/liveness projection, duplicate-session rejection, scheduling, and
  execution over the live worker session;
- expose running-service feature projection for persistent execution, capability
  ingestion, worker observations, and rendezvous without overstating unconfigured
  runtime features;
- allow the supervised controller to load rendezvous listener/TLS paths from a
  protected environment file so deployment does not hard-code operator trust paths
  into the shipped unit; and
- keep the registered direct-worker endpoint as an explicit compatibility path
  when worker-initiated rendezvous is not configured.

## 0.2.0a15 - persistent controller transport foundation

- separate controller service start/stop/request evidence from the lifecycle
  ledger, preserving lifecycle reads across service restarts;
- make authenticated session admission and disconnect checks atomic under the
  Fabric ledger lock, with stale-session replacement and generation regression
  handling;
- add bounded versioned local AF_UNIX consumer and operator service transport,
  exclusive controller ownership, peer/path safety checks, request deadlines,
  and replay rejection;
- add `FabricClient.connect()` and explicit `FabricAdminClient` modes while
  preserving embedded compatibility and denying consumer administrative calls;
- add controller/fleet/enrollment CLI paths for persistent local service use; and
- leave worker rendezvous, certificate provisioning, discovery, Windows service
  transport, and physical reboot validation planned.

## 0.2.0a14 - worker lifecycle foundation

- add Fabric-owned, append-only enrollment authorization, request, decision,
  fleet membership, revocation, and authenticated session-presence records;
- enforce bounded one-time authorization tokens, atomic consumption, explicit
  replay/expiry/conflict failures, exact key binding, and deterministic duplicate
  session handling without making TrustStore a certificate authority;
- expose lifecycle state through `FabricClient`, controller-side CLI commands,
  versioned JSON schemas, and a platform-neutral foreground controller runtime;
- keep lifecycle state independent from consumer object lifetime while retaining
  the embedded/in-process API for tests and compatibility; and
- retain worker-initiated rendezvous, certificate provisioning, discovery, and
  OS installation as planned work.

## 0.2.0a13 - persistent operator worker registry

- add the local `mncs-fabric.worker-registry.v0.1` catalog and consumer API;
- retain known unavailable/misconfigured workers in status without weakening
  mTLS identity or TrustStore authorization;
- reject duplicate identities, conflicting endpoints, malformed versions, and
  missing or revoked trust references; and
- advertise factual loaded-model attributes through the existing generic worker
  capability observation contract without adding semantic scheduling authority.

## 0.2.0a12 - bounded long-running distributed execution

- separate connection and control-plane timeouts from execution-response waits;
- derive each dispatch response deadline from the validated job timeout plus a
  small bounded protocol overhead while keeping refresh and handshake waits short;
- apply a total frame deadline so a malformed peer cannot extend a response by
  dribbling bytes indefinitely;
- report execution-response expiry as `TRANSPORT_TIMEOUT`, distinct from a worker
  execution record whose job terminates with `TIMEOUT`; and
- add real mTLS regression coverage for inference longer than the old control bound
  and for explicitly over-bound jobs.

## 0.2.0a11 - provider-neutral worker capability observations

- add `mncs-fabric.worker-capability-observation.v0.1` with strict bounded
  entries, deterministic identities, an explicit source/claim boundary, and
  non-attestation semantics;
- extend `FabricClient` with durable worker-bound ingestion, history/latest reads,
  freshness evaluation, and explicit current/stale/unknown/unavailable exposure in
  `workers()` for both local and remote workers;
- reject wrong-worker claims and preserve prior evidence without preserving false
  current availability after worker loss or failed scans; and
- ensure an explicitly supplied request bundle cannot reuse an older cached bundle
  selected during a previous capability probe.

## Unreleased - Raspberry Pi commissioning and four-node cohort

- add an explicit Linux/ARM worker preflight and config-aware native-bundle
  harness without LAN discovery, password fallback, or SSH candidate staging;
- accept an explicitly operator-selected OpenSSH alias or configured agent for
  Linux/ARM bootstrap while retaining strict public-key-only authentication and
  bounded, secret-free diagnostics;
- record the earlier failed Pi key-mapping attempt as historical evidence and
  add chronological PASS evidence after the operator's strict agent-backed
  mapping was commissioned;
- add a bounded four-node Fedora/Fedora/Windows/Raspberry Pi collection harness
  using Fabric native transfer for candidate material and the Windows lifecycle
  helper for GPU-host bootstrap;
- validate cross-architecture node/record/receipt identities, constrained Pi
  accelerator admission, and Pi stop/restart UNKNOWN/recovery evidence offline
  through Forge; and
- validate sanitized Raspberry Pi bootstrap evidence offline through Forge;
- retain the current `0.2.0a7` version pending the repository's next release
  decision.

## 0.2.0a7 - physical sequential offload and three-node heterogeneous evidence

- add identity-addressable runtime-environment and runtime-capability evidence
  for sequential CPU offload without adding provider dependencies to Fabric;
- require fresh exact-runtime offload proof for explicit and AUTO sequential
  offload admission, while retaining consumer capability declaration as intent;
- preserve Windows platform user identity variables in bounded child execution
  environments so Accelerate/Torch Windows workloads run through Fabric;
- record operator-controlled Windows sequential-offload evidence, a Fedora /
  Fedora / Windows portable three-node collection, and bounded timeout/stale
  resource fault profiles; and
- advertise the runtime-capability/offload evidence path as physically proven
  only within that bounded development evidence scope.

## 0.2.0a6 - runtime-aware placement admission and Windows CUDA evidence

- bind a validated worker runtime observation to accelerator admission without
  changing the machine resource snapshot meaning;
- carry runtime profile/observation identities through dispatch replay,
  worker results, and runtime bindings; and
- add an explicit local Windows operator configuration path with strict
  public-key-only bootstrap diagnostics and case-insensitive Windows hostname
  comparison.

The physical Windows CUDA result is recorded as operator-controlled
development evidence only; sequential CPU-offload evidence remains unavailable.

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
