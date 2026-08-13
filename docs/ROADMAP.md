# Roadmap

## Completed in 0.2.0a13

- Versioned operator-owned persistent worker registry with reference validation,
  migration-friendly consumer loading, and visibility for unavailable members.
- Generic factual loaded-model attributes carried without semantic model choice.

Resident-model selection, tool policy, Commons meaning, and model-role routing
remain Harness responsibilities. Distributed DAG scheduling and arbitrary remote
MCP invocation remain future work.

Future residency work must preserve this boundary. Fabric may carry factual loaded
state, provider timing/memory observations, transition history, and opaque session
provenance, but it must not choose resident models, evictions, session affinity, or
speculative warming. See
[Provider-neutral residency and session observations](PROVIDER_RESIDENCY_OBSERVATIONS.md).

## Worker bootstrap, discovery, and lifecycle

### Implemented in 0.2.0a15 — Phase A and local controller transport

- [x] versioned short-lived, single-use enrollment authorization with hashed
  token material, bounded metadata, expiry, revocation, and atomic replay state;
- [x] bounded versioned enrollment requests with strict fields, public-key
  validation, untrusted descriptive bootstrap claims, and duplicate/conflict
  rejection;
- [x] immutable approval/denial/expiry decisions bound to the exact request and
  public-key identity, with active identity rebind rejection;
- [x] additive fleet membership/revocation records separate from
  `mncs-fabric.worker-registry.v0.1` endpoint configuration;
- [x] authenticated session generations, stale/disconnected/duplicate identity
  handling, and separate capability/resource freshness outputs;
- [x] Fabric-owned lifecycle paths usable across client/process restarts;
- [x] controller `status`, `doctor`, and bounded foreground `service run`
-  foundation;
- [x] separate controller-service evidence ledger and lifecycle ledger with
  restart-safe reads;
- [x] atomic session admission/disconnect decisions with stale reconnect,
  generation checks, and duplicate-identity evidence;
- [x] bounded local versioned AF_UNIX consumer/operator transport with exclusive
  controller ownership and replay rejection;
- [x] embedded `FabricClient` compatibility plus `FabricClient.connect()` and
  explicit `FabricAdminClient`; and
- [x] deterministic CLI inspection and machine-readable lifecycle output.

The controller now has a usable local foreground service transport and persistent
state ownership. Authenticated worker-initiated rendezvous, leases, live
observations, and bounded dispatch over the session are implemented as an
explicitly configured network path. mDNS/DNS-SD, certificate issuance, Windows
transport packaging, and OS installation are not claimed. Consumers do not own
worker presence or disconnect state. The rendezvous path has deterministic
automated service-level tests but is not physically verified under systemd or
across hosts.

### Implemented commissioning foundation

- [x] protected identity-addressed enrollment material and join handoff;
- [x] durable worker-local private-key generation and exact approved-key binding;
- [x] explicit post-approval operator-CA issuance with controller pinning;
- [x] protected credential activation and idempotent Fedora user-service helper;
- [x] approved enrollment automatically authorizes rendezvous membership without
  controller registry editing; and
- [x] lifecycle revocation tombstones override legacy registry membership,
  terminate live rendezvous sessions, revoke configured transport trust, and
  prevent direct compatibility scheduling;
- [x] explicit online admin versus offline operator lifecycle ownership,
  including controller-admin enrollment submission; and
- [x] CA/key, controller-chain, worker-chain, subject, pin, and approved-key
  validation before credential issuance or activation;
- [x] the installed rendezvous worker reuses its identity and reconnects under
  systemd supervision.

Online bootstrap/discovery, physical reboot commissioning evidence, Windows
service packaging, and Linux/ARM installer evidence remain planned.

The Fedora reboot acceptance helper now verifies linger boot semantics, a
changed kernel boot ID, reconnect before its first post-boot SSH diagnostic, a
higher rendezvous generation, unchanged certificate/install/registry state, and
successful exact-worker dispatch. Checked-in physical status remains `UNKNOWN`
until that helper runs on a reboot-capable commissioned host.

### Planned after Phase A

Fabric's current explicit endpoint registry and physical multi-host evidence prove the
execution substrate, but commissioning remains too manual for normal fleet operation.
The next lifecycle milestone is an installable worker that can find or be told about a
controller, request explicit enrollment, establish authenticated worker-initiated
presence, refresh capabilities, and return after reboot without manual certificate,
endpoint, registry, and process reconstruction.

See [Worker bootstrap, discovery, and lifecycle](WORKER_BOOTSTRAP_DISCOVERY.md) for the
full design, state machine, trust boundaries, compatibility requirements, threat model,
and phased acceptance criteria.

Key roadmap constraints:

- discovery remains advisory and never grants trust;
- TrustStore remains authorization state rather than certificate-issuance authority;
- worker private keys are generated and retained locally;
- direct controller-to-worker endpoint mode remains supported;
- worker-initiated rendezvous remains additive and uses its explicit versioned
  session/transport representation rather than changing existing endpoint schemas;
- authenticated presence, liveness, resource freshness, and capability freshness stay
  distinct;
- Fabric owns installation/connectivity/identity facts while Local Harness retains
  model, residency, task, tool, and semantic-routing policy; and
- SSH/WinRM may later assist explicit bootstrap but never become an ambient Fabric job
  execution fallback.

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
- [x] local service transport for `FabricClient` to connect to a running
  controller; LAN/Windows transport remains planned;
- [~] production-shaped systemd user units exist for the controller and Fedora
  worker-rendezvous process; Windows service installation and physical reboot
  commissioning remain incomplete;
- [x] authenticated worker-initiated rendezvous with bounded reconnect/session state,
  deterministic service-level tests, and no claim of physical systemd/cross-host proof;
- [x] explicit post-approval TrustStore issuance and automatic approved fleet
  projection into rendezvous membership;
- [ ] optional local controller discovery with cryptographic controller verification;

- [~] bounded worker lifecycle is experimental; production multi-host operation
  and certificate provisioning remain operator responsibilities;

The experimental two-host acceptance run, bounded persistent-worker run, and
native-transfer run are complete. Fabric does not claim production Phase 1
lifecycle completion: certificate provisioning is operator-managed and worker
supervision remains bounded/operator-controlled.

Phase 1 lifecycle completion should eventually mean that a previously enrolled worker
survives reboot, reconnects to its configured controller, and returns to authenticated
presence without an operator manually rebuilding its endpoint, certificate, registry,
or launch command. Fresh-machine enrollment remains explicit and operator-controlled.

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
- [x] short control-plane waits separated from validated job-bounded execution
  response waits, with explicit executor and transport timeout dispositions;
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
- [ ] extend provider-neutral model/runtime observations with optional factual residency
  fields such as loaded state, observed load duration, provider-reported memory/cache
  usage, and exact runtime/model identity while preserving UNKNOWN for unsupported
  facts;
- [ ] add bounded load/unload/reuse transition history without inventing eviction
  causality when a provider reports only weaker state changes;
- [ ] carry opaque provider-session references as consumer provenance bound to exact
  worker/runtime/model identities, with tests proving those references grant no
  filesystem, shell, MCP, workspace, or execution authority;
- [ ] support explicit consumer/provider warm-operation evidence as a bounded operation
  without adding autonomous Fabric prefetch, eviction, or residency policy;
- [ ] explicit capability references for worker-local tools and MCP endpoints
  without making Fabric the semantic tool router;
- [x] a first consumer carries typed inference/workspace/tool target metadata and
  Fabric now publishes an identity-addressed execution-target reference with exact
  worker, capability, provenance, freshness, and no-fallback requirements; neither
  side grants implicit remote authority;
- [ ] bounded target-aware execution requests for consumer-authorized remote
  tools, preserving argv-only execution and Fabric evidence boundaries;
- [x] deterministic and operator-controlled physical Local Harness integration proves
  that `gemma4:e4b` on `collamore02-windows` can request controller-owned Commons while
  workspace/tools remain on Fedora; the companion evidence is retained by Local
  Harness and does not convert execution success into Commons verification;
- [ ] broader physical evidence that a model placed on one host can participate in a
  consumer-owned agent session whose workspace/tool execution remains on another
  host, with no ambient cross-host filesystem or shell authority;
- [ ] enforced resource reservations or production-grade accelerator sharing;

The distributed capability work in this phase remains provider-neutral. Fabric may
report authenticated facts such as installed runtimes, models, tools, MCP endpoint
identities, hardware, liveness, resource observations, and bounded provider residency
observations. The consuming harness retains semantic model selection, task decomposition,
workspace meaning, permissions, session-affinity policy, resident working-set policy,
speculative warming, tool choice, verification, reduction, and escalation.

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
- [ ] end-to-end installer/enrollment/rendezvous commissioning evidence on Fedora,
  Windows, and Linux ARM without manual registry JSON editing;
- [ ] DHCP/address-change recovery evidence proving logical identity is independent of
  a transient worker endpoint in rendezvous mode;
- [ ] heterogeneous capability-graph evidence spanning models, worker-local
  tools, controller-proxied capabilities, and execution targets without
  weakening worker identity or admission semantics;
- [ ] heterogeneous residency-observation evidence across supported CPU/GPU,
  Windows/Linux/ARM, and multiple provider runtimes, explicitly documenting fields a
  provider cannot establish instead of inventing normalized values;

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
- enrollment-token replay/expiry, spoofed discovery, duplicate worker identity,
  credential replacement, rendezvous reconnect storms, and stale-session faults;
- target-routing faults where inference worker, workspace authority, and
  execution target disagree, disappear, or become stale;
- provider-residency faults where loaded state disappears, a session reference becomes
  stale, a warm operation fails, or transition telemetry conflicts, preserving UNKNOWN
  rather than silently fabricating current state or causality;
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
