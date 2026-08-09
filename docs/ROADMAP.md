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

- [~] bounded worker lifecycle is experimental; production multi-host operation
  and certificate provisioning remain operator responsibilities;

The experimental two-host acceptance run and bounded persistent-worker run are
complete. Fabric does not claim production Phase 1 lifecycle completion:
certificate provisioning is operator-managed and bulk execution-bundle
transfer is not yet implemented.

EA-NEXT-005 challenge/replay compatibility has bounded physical deployment
evidence. Its replay authority remains an operator-controlled local store and
does not establish independent freshness or custody.

## Phase 2 — scheduler foundation (partially implemented)

- [x] exact capability-aware deterministic local admission;
- [x] stable tie breaking and explicit unsupported disposition;
- [x] simple in-process and registered-transport replicated dispatch ordering;
- [ ] four-node Fedora fabric;
- sharded experiment collection;
- [~] node-loss and delayed-result handling (explicit UNKNOWN for transport loss);
- scaling measurements separated from semantic evidence;
- [x] explicit dispatch reconciliation preserving missing results as UNKNOWN.

## Phase 3 — heterogeneous cohort

- Windows worker packaging and service operation;
- Raspberry Pi OS ARM worker packaging;
- portable frozen bundles;
- cross-OS and cross-architecture result comparison;
- slow-node, timeout, and resource-pressure profiles.

## Phase 4 — controlled fault injection

- [~] bounded dropped, delayed, and duplicated request controls at the transport test boundary;
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
