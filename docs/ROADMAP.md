# Roadmap

## Phase 0 — foundation (complete)

- canonical identities;
- artifact manifests;
- node capability capture;
- bounded local execution;
- execution records;
- deterministic reconciliation;
- schemas, tests, CI, and threat model.

## Phase 1 — controller/worker foundation (partially implemented)

- [x] in-process controller and worker services;
- [x] encrypted TLS transport and mutual certificate authentication in bounded loopback integration;
- [x] operator-managed enrollment/revocation and certificate-to-logical-identity binding;
- [x] fixed request/response envelopes;
- [x] durable local controller/worker ledgers;
- [x] replay and duplicate rejection;
- [x] local concurrency/admission limits;
- [x] additive EA-NEXT-005 challenge/replay compatibility;
- [x] Fedora-to-Fedora two-node evidence run (direct Fabric mTLS; see
  `development-evidence/fedora-two-host-phase1.md`).
- [x] bounded persistent worker mode with repeated physical-request evidence
  (`development-evidence/fedora-persistent-two-host.md`);
- [x] identity-addressable public consumer contract and `FabricClient` facade;
- [x] Fabric-owned receipts and generic consumer provenance bindings;
- [x] bounded native EA-NEXT-002 bundle transfer with worker-side verification
  and immutable cache, including direct physical execution evidence;

- [~] bounded worker lifecycle is experimental; production multi-host operation
  and certificate provisioning remain operator responsibilities;

The experimental two-host acceptance run, bounded persistent-worker run, and
native-transfer run are complete. Fabric does not claim production Phase 1
lifecycle completion: certificate provisioning is operator-managed and worker
supervision remains bounded/operator-controlled.

EA-NEXT-005 challenge/replay compatibility has bounded physical deployment
evidence. Its replay authority remains an operator-controlled local store and
does not establish independent freshness or custody.

## Phase 2 — scheduler foundation (partially implemented)

- [x] exact capability-aware deterministic local admission;
- [x] stable tie breaking and explicit unsupported disposition;
- [x] simple in-process and registered-transport replicated dispatch ordering;
- [ ] four-node Fedora fabric;
- [~] generic execution collection is implemented; semantic sharded experiment
  scheduling remains consumer-owned;
- [~] node-loss and delayed-result handling (explicit UNKNOWN for transport loss);
- scaling measurements separated from semantic evidence;
- [x] explicit dispatch reconciliation preserving missing results as UNKNOWN.
- [~] physical two-node public-facade scheduling and recovery evidence;
- [x] authenticated remote worker self-description and immutable refresh history;
- [x] bounded worker liveness with explicit physical loss/recovery evidence;
- [~] physical two-node public-facade scheduling/recovery is demonstrated for
  CPU placement; four-node operation remains incomplete;
- [~] generic identified execution collections are implemented; semantic
  sharded workloads remain consumer-owned and untested;
- [x] identity-addressable host/accelerator resource observations with
  explicit freshness and unknown-value handling;
- [x] provider-neutral CPU/full-accelerator/sequential-offload admission
  fixtures with deterministic decision identities;
- [x] a Windows NVIDIA worker produced synchronized CUDA runtime evidence that
  was ingested and bound to resource-aware full-accelerator admission;
- [x] physical Windows sequential-offload runtime evidence is bound to an
  identity-addressed runtime environment and used for explicit/AUTO admission;
- [ ] enforced resource reservations or production-grade accelerator sharing;

## Phase 3 — heterogeneous cohort

- [x] Windows worker packaging and bounded native lifecycle helper; direct
  Fedora-to-Windows Fabric mTLS/native-bundle execution is recorded;
- [x] runtime-profile identity and synchronized CUDA probe evidence for the
  commissioned Windows Python environment;
- Raspberry Pi OS ARM worker packaging;
- portable frozen bundles;
- [x] Fedora controller/local, Fedora remote, and Windows remote completed one
  exact portable three-physical-node collection and cross-OS reconciliation;
- [~] timeout and stale-resource profiles are physically recorded; controlled
  slow-node/resource-pressure breadth remains incomplete;

## Phase 4 — controlled fault injection

- [~] bounded dropped, delayed, and duplicated request controls at the transport test boundary;
- [x] physical worker-stop/restart, incomplete-replication, and duplicate-after-restart corpus;
- corrupted bundles and checkpoints;
- worker termination and restart;
- capability disappearance;
- bounded bandwidth and latency profiles;
- harness self-tests with expected dispositions.

## Phase 5 — distributed RAVEL study

Begin only after the execution fabric has a frozen protocol and passing fault corpus. First distribute independent trials, then replicated trials, then sharded workloads. Distributed expert execution and adaptation require a separate preregistered RAVEL epoch and must compare against single-host correctness and performance baselines.

## Later assurance work

- hardware-backed node keys and measured boot;
- read-only worker images;
- signed bundles and transparency logs;
- external result replication;
- independent evaluator and protected-custody workflows; and
- accelerator and energy-utilization evidence profiles.
