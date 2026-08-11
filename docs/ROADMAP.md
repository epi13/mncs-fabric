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
- [x] provider-neutral, identity-bound worker capability observations with bounded
  model/runtime entries, durable history, public API exposure, and explicit
  freshness/availability (additive to authenticated worker descriptions);
- [ ] explicit capability references for worker-local tools and MCP endpoints
  without making Fabric the semantic tool router;
- [~] a first consumer now carries typed inference/workspace/tool target metadata;
  Fabric retains independent execution placement and grants no implicit remote
  authority, while a shared Fabric target-reference contract remains future work;
- [ ] bounded target-aware execution requests for consumer-authorized remote
  tools, preserving argv-only execution and Fabric evidence boundaries;
- [ ] physical evidence that a model placed on one host can participate in a
  consumer-owned agent session whose workspace/tool execution remains on another
  host, with no ambient cross-host filesystem or shell authority;
- [ ] enforced resource reservations or production-grade accelerator sharing;

The distributed capability work in this phase remains provider-neutral. Fabric may
report authenticated facts such as installed runtimes, models, tools, MCP endpoint
identities, hardware, liveness, and resource observations. The consuming harness
retains semantic model selection, task decomposition, workspace meaning, permissions,
tool choice, verification, reduction, and escalation.

## Phase 3 — heterogeneous cohort

- [x] Windows worker packaging and bounded native lifecycle helper; direct
  Fedora-to-Windows Fabric mTLS/native-bundle execution is recorded;
- [x] runtime-profile identity and synchronized CUDA probe evidence for the
  commissioned Windows Python environment;
- [x] explicit Linux/ARM worker preflight and config-aware native-bundle
  harness are implemented; the operator-supplied strict agent-backed mapping
  commissioned `mncs-pi` as an authenticated `aarch64` worker;
- portable frozen bundles;
- [x] Fedora controller/local, Fedora remote, and Windows remote completed one
  exact portable three-physical-node collection and cross-OS reconciliation;
- [x] Raspberry Pi participation in a four-node Fedora/Fedora/Windows/Linux
  ARM collection with cross-architecture reconciliation;
- [~] timeout and stale-resource profiles are physically recorded; a bounded
  Pi loss/recovery profile is now recorded, while slow-node/resource-pressure
  breadth remains incomplete;
- [ ] heterogeneous capability-graph evidence spanning models, worker-local
  tools, controller-proxied capabilities, and execution targets without
  weakening worker identity or admission semantics;

## Phase 4 — controlled fault injection

- [~] bounded dropped, delayed, and duplicated request controls at the transport test boundary;
- [x] physical worker-stop/restart, incomplete-replication, and duplicate-after-restart corpus;
- [x] bounded Raspberry Pi worker loss, incomplete dispatch, and recovery
  evidence in the four-node cohort;
- corrupted bundles and checkpoints;
- worker termination and restart;
- capability disappearance;
- bounded bandwidth and latency profiles;
- harness self-tests with expected dispositions;
- target-routing faults where inference worker, workspace authority, and
  execution target disagree, disappear, or become stale;
- verify that a failed or stale remote target becomes UNKNOWN/denied rather than
  falling back to ambient SSH, shell, or filesystem authority.

## Phase 5 — distributed RAVEL study

Begin only after the execution fabric has a frozen protocol and passing fault corpus. First distribute independent trials, then replicated trials, then sharded workloads. Distributed expert execution and adaptation require a separate preregistered RAVEL epoch and must compare against single-host correctness and performance baselines.

## Later assurance work

- hardware-backed node keys and measured boot;
- read-only worker images;
- signed bundles and transparency logs;
- external result replication;
- independent evaluator and protected-custody workflows; and
- accelerator and energy-utilization evidence profiles.
