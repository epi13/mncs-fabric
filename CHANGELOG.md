# Changelog

## Unreleased

- Allow an operator-requested certification to recover a worker that returned
  after an update reconnect deadline, but only after exact expected-version,
  health-certification, and desired-state checks pass. The failed observation
  remains in the append-only history and package apply is never repeated.
- Refresh worker capability evidence in the background on a bounded interval
  shorter than capability observation age, so inventories do not go stale
  merely because no client asked.
- Make the Windows worker scheduled-task install idempotent: one logon-triggered
  hidden supervisor, no duplicate timer watcher, and a bundled inspect/repair
  script that restores `MNCS-Fabric-Worker` without elevation.
- Treat missing `gh` as advisory, matching `local-harness`: do not FAIL a
  Windows inference-worker maintenance receipt or roll back a Fabric apply.
- When a pre-0.2.0a30 worker certifies without echoing inventory, bind the
  inspect that selected the profiles instead of failing the certification.

## 0.2.0a31 - transport topology observation

- carry bounded passive network interface, route, and neighbor observations in
  node records without changing the v0.2 worker-description wire schema;
- classify USB-backed IP interfaces as a first-class link medium while keeping
  execution on the existing mutually authenticated TLS/IP transport;
- surface topology evidence and identity in local, remote, and rendezvous fleet
  status and derive direct worker links from matching passive neighbor evidence;
- document the OS/Fabric responsibility boundary for routed USB node chains.

## 0.2.0a30 - installable staged artifacts

- copy a digest-named staged wheel to its descriptor/PEP 427 filename
  before `pip install`, so Fabric-native apply no longer fails with
  `Invalid wheel filename`;
- treat missing `local-harness` as advisory: do not FAIL the maintenance
  receipt or roll back a Fabric package apply;
- keep advisory verifies on the controller so pre-0.2.0a30 workers do
  not see a blocking `tool not present` during class A apply.

## 0.2.0a29 - runtime build identity

- report a process-local `runtime_identity` from controller status:
  package, version, source commit, artifact digest, and build identity
  when available;
- keep that identity off inventory and conformance hashes so existing
  CERTIFIED workers are not rotated by observation-only reporting;
- project optional worker source commit / artifact digest on fleet
  refresh when a worker advertises them.

## 0.2.0a28 - self-recovering fleet updates

- separate fleet-refresh concurrency unit tests from LocalWorker host
  inventory time so a slow Windows WMI/tool probe cannot turn PARTIAL
  into UNKNOWN;
- wait for TLS listener readiness and keep connect timeout distinct from
  the job execution deadline, so job-timeout tests do not race
  `socket.create_connection()`;
- make the certified-inventory invariant universal: reconcile,
  post-maintenance verify, certify, update completion, and restart
  recovery evaluate READY only against the inventory the worker actually
  certified;
- resume DISCONNECT_EXPECTED / RECONNECTING / VERSION_VERIFYING /
  CERTIFYING transactions after controller restart without re-applying
  packages; mutation-phase states fail closed with explicit uncertainty;
- resolve `retain_identities` through a content-addressed object index so
  GC keeps referenced non-current artifacts, not merely a returned list;
- derive live artifact references from current/previous deployments,
  unresolved transactions, and persisted rollouts;
- persist sequential canary rollout progress so a controller restart
  does not re-mutate a successful canary;
- discover Windows tools from process PATH plus durable user/machine
  PATH and environment-relative well-known layouts, without host-specific
  hard-coded executable paths.

## 0.2.0a27 - live Fabric-native transfer

- expose `transfer_package_artifact` on the persistent FabricClient
  backend so `worker.artifact.stage` can reach enrolled mTLS workers;
- bind certification and conformance to the inventory the worker actually
  certified, so READY cannot fail closed on two live inventory snapshots;
- recover unresolved update transactions after controller restart without
  re-applying packages;
- garbage-collect unreferenced staged package artifacts while retaining
  current and previous known-good identities;
- distinguish rollout `deployment_succeeded` from scheduler READY.

- close the 0.2.0a24 fleet-autonomy architecture before live canary:
  GitHub Actions portability (UTC without tzdata, host-reachable fixture
  paths, drain/resume READY predicate, fleet-refresh deadlines);
- make READY a single `evaluate_ready` invariant bound to current
  inventory, desired-state identity, certification, conformance, and any
  unresolved update transaction;
- walk Fabric updates through the full transaction
  (`UPDATE_PLANNED` … `DISCONNECT_EXPECTED` … `VERSION_VERIFYING` …
  `CERTIFYING` → `READY`) with evidence-backed reconnect observation;
- require post-restart READY before a canary proceeds; stop the remainder
  when `stop_on_failure` is set;
- bind artifact transfer sessions to worker/controller/artifact/transfer
  identity, expected sequences, digest, size, and expiry;
- retain the previous content-addressed artifact for exact rollback and
  quarantine when that artifact is missing or corrupt;
- inspect wheel/sdist metadata without executing package code.

## 0.2.0a24 - fleet autonomy architecture

- separate health certification from desired-state conformance so a
  required missing Git (or other blocking profile requirement) can no
  longer yield CERTIFIED READY;
- bind Fabric package updates to content-addressed artifacts with digest,
  size, and version checks, transferred over the existing mTLS protocol;
- record authorized restart as an explicit update transaction
  (DISCONNECT_EXPECTED) instead of an unexplained outage;
- add a bounded canary rollout planner with stop-on-failure;
- treat GitHub AUTH_FAILURE as health SKIP / conformance AUTH_REQUIRED
  (advisory) rather than a hard health failure.

## 0.2.0a21 - desired-state fleet management

- add a first-class desired-state fleet-management plane: worker inventory,
  reusable profiles, typed maintenance actions, drain/resume/quarantine,
  capability-aware certification, and append-only maintenance receipts
  (`mncs-fabric worker inspect|plan|reconcile|certify|drain` and
  `mncs-fabric fleet inspect|plan|reconcile|certify`);
- discover how Ollama and other services are actually installed instead of
  assuming `systemd` `*.service` units, and refuse to auto-apply privilege
  or OS-class mutations;
- keep management state separate from liveness so a worker in maintenance or
  a failed certification cannot receive ordinary work;
- emit Commons-shaped operational companions only for unusual discoveries,
  without importing Commons or flooding routine success.

## 0.2.0a21 - classified fleet refresh

- `fleet.refresh` answers within the 30s service-frame TTL with classified
  per-worker results instead of letting sequential worker probes expire the
  persistent request as an ambiguous `UNKNOWN` timeout;
- worker probes run concurrently with an explicit per-worker deadline, so one
  slow or unreachable worker cannot discard another worker's completed
  observation;
- a worker `TIMEOUT` retains last-known availability and is distinct from
  `UNAVAILABLE` (unreachable) and from `STALE` capability inventory;
- fleet projections expose `worker_service_version` and
  `description_captured_at` so an operator can verify the process serving a
  worker after an in-place upgrade;
- controller restart restores last-known worker descriptions from the network
  ledger so refresh can resume against retained observations;
- persistent `FabricClient.execute()` no longer holds the 30s service-frame
  TTL open for jobs whose plan timeout exceeds that bound; those jobs submit
  as detached work and poll `execution.status`/`execution.result` until the
  job deadline, so controller request timeouts cannot expire before
  legitimate worker execution;
- advertise `persistent_execution_deadline_wait` so consumers can detect the
  split between control-plane TTL and execution deadline without guessing
  package versions;
- bundle cache GC can evict unused published bundles under pressure, never
  evicts in-use or pinned identities, and fails closed when safe reclamation
  cannot free enough space (`mncs-fabric cache status|gc`);
- 0.2.0a19 advertises `service_capabilities` including last-known status,
  explicit `fleet.refresh`, detached execution, and a scheduled work queue so
  clients can detect a stale running controller without trusting package
  versions alone;
- controller-owned worker backends may implement `workers()` without
  `apply_lease`; last-known reads remain compatible with Control fixtures;
- `controller.status`, `fleet.list`, and other service reads now project
  last-known worker state without calling `refresh_workers()`; live describe
  probes are explicit through `fleet.refresh` so a busy worker no longer
  stalls unrelated persistent clients;
- required Bubblewrap mode now fails closed with `CONTAINMENT_UNAVAILABLE` when
  this process cannot create a user namespace, instead of reporting a generic
  `FAIL` from a nested sandbox or kernel restriction;
- the containment test still enforces filesystem and offline-network isolation
  wherever user namespaces are available; and
- Windows job cancellation uses `taskkill /T` so aborted inference does not
  routinely leave a detached child tree.

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
