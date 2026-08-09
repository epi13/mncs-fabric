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
- [ ] encrypted transport and mutual host authentication/enrollment;
- [x] fixed request/response envelopes;
- [x] durable local controller/worker ledgers;
- [x] replay and duplicate rejection;
- [x] local concurrency/admission limits;
- [ ] Fedora-to-Fedora two-node evidence run.

The network and real second-host items remain blocked on TLS/certificate
provisioning, enrollment/revocation, and adversarial deployment testing. Fabric
does not claim Phase 1 complete.

## Phase 2 — scheduler foundation (partially implemented)

- [x] exact capability-aware deterministic local admission;
- [x] stable tie breaking and explicit unsupported disposition;
- [x] simple in-process replicated dispatch ordering;
- [ ] four-node Fedora fabric;
- sharded experiment collection;
- node-loss and delayed-result handling;
- scaling measurements separated from semantic evidence;
- automatic result reconciliation.

## Phase 3 — heterogeneous cohort

- Windows worker packaging and service operation;
- Raspberry Pi OS ARM worker packaging;
- portable frozen bundles;
- cross-OS and cross-architecture result comparison;
- slow-node, timeout, and resource-pressure profiles.

## Phase 4 — controlled fault injection

- dropped, delayed, duplicated, and stale results;
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
