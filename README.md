# MNCS Fabric

Fabric 0.2.0a16 includes a versioned controller-local registry for explicitly
known worker endpoints. Registry membership is not discovery, trust, or
availability; mTLS identity, TrustStore authorization, and authenticated refresh
remain authoritative. See [`docs/WORKER_REGISTRY.md`](docs/WORKER_REGISTRY.md).

The worker lifecycle foundation is now implemented as Fabric-owned append-only
state: short-lived enrollment authorization, bounded enrollment requests,
immutable approval/denial/expiry decisions, fleet membership/revocation, and
authenticated session presence. `FabricClient` can open a controller-owned
lifecycle ledger explicitly; closing a consumer does not record worker loss.
The foreground controller service and local AF_UNIX consumer/operator transport
are available through `mncs-fabric controller status|doctor|service run` and
`FabricClient.connect()`/`FabricAdminClient.connect()`. An explicitly
configured controller can also accept authenticated worker-initiated TLS
rendezvous sessions. Fedora workers can now use a protected, file-mediated
commissioning path that generates their private key locally, requires explicit
operator approval and CA issuance, activates pinned credentials, and installs an
idempotent user service. Online bootstrap, discovery, and non-Fedora packaging
remain deployment work.

Loaded-model attributes are factual generic capability observations. Fabric does
not choose resident models or semantic routes; Local Harness owns those policies.

MNCS Fabric is an experimental, operator-controlled execution and evidence fabric for the Machine-Native Complexity Standard project family. It provides bounded local execution, content-addressed artifact manifests, host capability records, raw execution records, and deterministic cross-host reconciliation.

> **Status:** `0.2.0a16` experimental execution substrate. Provider-neutral capability/resource observations, controller-owned worker leases, authenticated worker-initiated rendezvous, protected file-mediated Fedora commissioning, bounded persistent-service execution, and the direct endpoint compatibility path are implemented and covered by tests. Cross-platform worker packaging, resource reservation, sandboxing, protected custody, and independent evaluation remain out of scope.

## Authority boundary

MNCS Fabric moves identified computation and observations across machines. It does **not** define MNCS, issue conformance decisions, create independent evaluation, or establish protected custody.

```text
Forge or operator declares work
          |
          v
MNCS Fabric verifies and executes bounded jobs
          |
          v
Harnesses/providers emit observations
          |
          v
Separate evaluators and MNCS/MNCDS validators derive bounded results
```

A Fabric `PASS` means the declared execution and reconciliation checks passed. It is not formal MNCS conformance. `FAIL` dominates `UNKNOWN`, and `UNKNOWN` dominates `PASS`.

## Implemented foundation

- canonical JSON and SHA-256 record identities;
- deterministic, ordered artifact manifests with mutation and extra-file rejection;
- cross-platform node capability records for Linux and Windows hosts;
- argv-only execution with no shell, bounded time, bounded stdout/stderr, isolated temporary work copies, and declared result artifacts;
- explicit `PASS`, `FAIL`, and `UNKNOWN` execution outcomes;
- deterministic local or operator-controlled cross-host reconciliation;
- companion adapters for the current experimental MNCS typed execution receipt and execution-assurance shape;
- offline verification and receipt binding for the current experimental MNCS immutable execution-bundle shape, retaining logical and archive transport identities separately;
- a stable `FabricService` boundary shared by the CLI and future Forge adapters;
- fixed, canonical controller/worker envelopes with optional operator-supplied HMAC authentication;
- durable append-only controller/worker ledgers with explicit recovery diagnostics and duplicate protection; and
- deterministic capability-aware in-process scheduling with explicit `UNKNOWN` admission failures;
- an identity-addressed execution-target reference that binds one consumer-authorized
  bounded argv workload to an exact worker, factual capability requirements,
  freshness expectations, and an explicit no-fallback policy;
- a transport-independent envelope boundary, bounded framing, TLS 1.2+ mutual certificate authentication, operator-managed enrollment/revocation, and registered remote-worker dispatch;
- a versioned `FabricClient` consumer facade with identity-addressable public-contract metadata, typed remote-worker configuration, consumer provenance bindings, replication, reconciliation, and Fabric-owned receipts;
- bounded native EA-NEXT-002 bundle transfer over Fabric envelopes with independent worker verification, chunk limits, atomic publication, and an immutable content-addressed cache;
- request-scoped verified execution-bundle staging after placement admission for remote consumers;
- identity-addressable host/CPU/accelerator resource observations, placement requests, deterministic admission, freshness bounds, and explicit no-fallback decisions;
- placement references in Fabric-generated receipts, with optional runtime placement observations kept separate from hardware or semantic claims; and
- authenticated worker descriptions, immutable remote observation history,
  expiring liveness, and public refresh/state operations; and
- generic identity-addressed work items and execution collections that retain
  missing and conflicting results; and
- explicit transport fault controls for bounded replay/drop/delay adversarial tests; and
- identity-addressable runtime profiles and optional runtime observations tied to
  the exact worker interpreter, without adding provider dependencies; and
- bounded provider-neutral worker capability observations with durable history,
  explicit freshness/availability, and public `FabricClient` access; and
- a strict Windows worker preflight/lifecycle helper and optional synchronized
  Torch CUDA probe workload; and
- a strict explicit-configuration Linux/ARM worker preflight and reusable
  Raspberry Pi native-bundle harness; and
- a Fabric-owned persistent-controller foundation with separate lifecycle and
  service ledgers, exclusive state ownership, local AF_UNIX consumer/operator
  transport, bounded request framing, replay rejection, and embedded/service
  `FabricClient` modes; and
- additive EA-NEXT-005 scoped execution challenges and durable single-use replay evidence; and
- JSON schemas, tests, CI, architecture documentation, and a portable example; and
- standard-library-only runtime for Python 3.11 or newer.

The executor is bounded but is **not a security sandbox**. Network policy is recorded but not enforced. TLS protects the transport and certificate enrollment authenticates the configured peer; neither establishes independent evaluation, protected custody, attestation, conformance, or correctness. HMAC authenticates message contents but does not encrypt transport. See [THREAT_MODEL.md](THREAT_MODEL.md).

## Quick start

```bash
python -m venv .venv
source .venv/bin/activate       # Windows: .venv\Scripts\activate
python -m pip install -e .
python -m unittest discover -s tests -v
```

Validate and run the portable example:

```bash
mncs-fabric artifacts verify \
  examples/portable-python/bundle \
  examples/portable-python/artifact-manifest.json

mncs-fabric plan validate examples/portable-python/job-plan.json

mncs-fabric run local examples/portable-python/job-plan.json \
  --root examples/portable-python/bundle \
  --manifest examples/portable-python/artifact-manifest.json \
  --label fedora-a \
  --output build/fedora-a.json \
  --results-dir build/fedora-a-results

mncs-fabric reconcile build/fedora-a.json \
  --output build/local-cohort.json
```

Run the same frozen bundle on another machine with a different label and reconcile both records:

```bash
mncs-fabric reconcile build/fedora-a.json build/fedora-b.json \
  --output build/operator-cohort.json
```

## CLI

```text
mncs-fabric node inspect --label NAME
mncs-fabric artifacts create ROOT --output MANIFEST.json
mncs-fabric artifacts verify ROOT MANIFEST.json
mncs-fabric plan validate PLAN.json
mncs-fabric run local PLAN.json --root ROOT --manifest MANIFEST.json --label NAME
mncs-fabric record verify RECORD.json
mncs-fabric reconcile RECORD.json [RECORD.json ...]
mncs-fabric bundle verify BUNDLE.zip
mncs-fabric worker serve --worker-id ID --controller-id ID --bundle-root ROOT \
  --state worker.jsonl --trust-state trust.jsonl --ca ca.pem \
  --certificate worker.pem --key worker.key --port PORT \
  [--max-requests N --idle-timeout SECONDS]
mncs-fabric worker rendezvous --worker-id ID --controller-id ID \
  --controller-host HOST --controller-port PORT --bundle-root ROOT \
  --state worker.jsonl --trust-state trust.jsonl --ca ca.pem \
  --certificate worker.pem --key worker.key
mncs-fabric worker join --material MATERIAL.json --worker-id ID \
  --state-root STATE --request-output JOIN.json
mncs-fabric worker activate --credentials CREDENTIALS.json --state-root STATE
mncs-fabric enrollment create --ttl 10m [--worker-id ID] \
  [--material-output MATERIAL.json --controller-id ID --controller-host HOST \
   --controller-port PORT --controller-certificate controller.pem]
mncs-fabric enrollment submit JOIN.json
mncs-fabric enrollment list|pending|inspect REQUEST_ID
mncs-fabric enrollment approve|deny REQUEST_ID
mncs-fabric enrollment issue JOIN.json --ca ca.pem --ca-key ca.key \
  --controller-certificate controller.pem --trust-state trust.jsonl \
  --output CREDENTIALS.json
mncs-fabric fleet list|status WORKER_ID|doctor
mncs-fabric worker revoke WORKER_ID --reason REASON
mncs-fabric controller status|doctor
mncs-fabric controller service run
```

The controller service is a foreground persistent transport runtime.
When started with `--registry`, the registry is controller-owned runtime
configuration: consumers never load it or receive its trust references. The
controller performs authenticated worker description refreshes and accepts
validated execution requests over the consumer socket.

```bash
mncs-fabric controller service run --state STATE/lifecycle.jsonl
mncs-fabric controller status --socket STATE/controller.sock
mncs-fabric fleet list --socket STATE/controller.sock
mncs-fabric enrollment create --admin-socket STATE/controller-admin.sock --ttl 10m

mncs-fabric controller service run \
  --state STATE/lifecycle.jsonl \
  --registry STATE/workers.json \
  --worker-state STATE/controller-workers.jsonl \
  --execution-bundle-root STATE/execution-bundles
# Add --rendezvous-host/--rendezvous-port and the four rendezvous TLS paths
# to enable worker-initiated sessions.
```

For a user-supervised Fedora deployment, install
`deploy/systemd/mncs-fabric-controller.service` under
`~/.config/systemd/user/`, then enable it. The unit owns only the persistent
controller lifecycle/socket state; it does not imply that a worker is present.
The unit optionally reads `~/.config/mncs-fabric/controller.env`; copy
`deploy/systemd/mncs-fabric-controller.env.example` there and replace the TLS
paths to activate the worker-initiated listener without embedding operator trust
paths in the unit. A complete rendezvous environment supplies
`MNCS_FABRIC_RENDEZVOUS_HOST`, `MNCS_FABRIC_RENDEZVOUS_PORT`,
`MNCS_FABRIC_RENDEZVOUS_CA`, `MNCS_FABRIC_RENDEZVOUS_CERTIFICATE`,
`MNCS_FABRIC_RENDEZVOUS_KEY`, and `MNCS_FABRIC_RENDEZVOUS_TRUST_STATE`.
Bind only to an operator-selected interface and restrict the listener with the
host firewall even though peer authentication remains mandatory.

For a Fedora worker that should survive login/session restarts, follow
[`deploy/systemd/WORKER_INSTALL.md`](deploy/systemd/WORKER_INSTALL.md). The
commissioning commands create protected state and the idempotent installer owns
an isolated virtual environment plus
`mncs-fabric-worker-rendezvous@WORKER_ID.service`. The worker dials the
controller; no inbound worker port is required. Approval automatically makes
the enrolled identity eligible for rendezvous, so no worker-registry JSON edit
is required.

Worker-initiated rendezvous is opt-in and requires the controller listener TLS
paths plus a worker process using `worker rendezvous`; otherwise the direct
registry endpoint remains the compatibility path. Worker presence is never
inferred from registry JSON alone. After changing Fabric code or controller
configuration, restart the controller and verify the running service feature
projection before attempting dispatch.

`FabricClient.connect(socket_path)` is the ordinary consumer mode for the
persistent controller. `FabricAdminClient.connect(socket_path)` is the explicit
operator mode; consumer sockets cannot approve enrollment or revoke workers.
The local service is implemented on POSIX with restrictive Unix-socket checks.
Windows local transport and service installation remain planned. Fedora
commissioning and installation are deterministic-test verified but have not yet
been physically verified across reboot in this change. Closing a consumer does
not publish worker disconnect state.

`worker serve` is explicit and serves one bounded TLS request by default. An
operator can opt into a bounded persistent service with `--max-requests` and
optional `--idle-timeout`; every connection is independently authenticated and
the listener never falls back to plaintext. The controller-side Python API is
`NetworkController` plus `TLSNetworkTransport`.

The repeatable physical-host harness is `scripts/two_host_fedora_test.py`. SSH
is limited to bootstrap, staging, diagnostics, and worker lifecycle; the
candidate request is sent through direct Fabric mTLS. It requires explicit
operator arguments and never uses SSH host-key bypasses.

The Windows-specific preflight is `scripts/two_host_windows_gpu_test.py` and
requires an explicit operator endpoint; it does not discover LAN hosts. The
bounded process helper is `scripts/windows_worker_launcher.py`. The optional
`scripts/probe_torch_cuda.py` workload must run in the same Python environment
that launches the worker and reports synchronized kernel evidence separately
from NVIDIA discovery. See [docs/RUNTIME_PROFILES.md](docs/RUNTIME_PROFILES.md).

For Linux/ARM workers, `scripts/linux_worker_preflight.py` reads only the
explicit `.fabric/operator/raspberry-pi-worker.local.json` configuration (or
explicit CLI/environment overrides). `scripts/raspberry_pi_native_bundle_test.py`
then delegates to the generic native-transfer harness. These helpers do not
scan, guess accounts, disable host-key verification, open tunnels, or stage
candidate material over SSH. See [docs/RASPBERRY_PI.md](docs/RASPBERRY_PI.md).

`scripts/two_host_persistent_test.py` exercises repeated requests, persistent
PID continuity, replay dispositions, and trust revocation between requests.

External consumers should import `FabricClient`, `FabricAdminClient`, `LocalWorkerConfig`,
`RemoteWorkerConfig`, and
`ConsumerContext` from `mncs_fabric.api`. The machine-readable compatibility
descriptor is available without a worker or network:

```bash
mncs-fabric contract show --json
```

`FabricClient.ensure_bundle()` transfers only a verified typed execution bundle;
it is not general file transfer. `FabricClient.execute()` returns a versioned
consumer result containing the Fabric record, Fabric-generated MNCS receipt,
and optional provenance binding. Request-scoped consumers may pass an
`execution_bundle_archive`; Fabric admits placement first, then stages the verified
archive only to the selected remote worker. In persistent service mode the client
first transfers the archive in bounded, identity-bound chunks to a controller-owned
cache; it never asks the controller to open a consumer pathname. Consumer projects retain semantic
workload, evaluation, promotion, and learning authority.

`FabricClient.refresh_worker()` obtains the current authenticated worker
description. `FabricClient.workers()` exposes observation source, availability,
last contact, description/resource identities, and current/stale/unknown capability
inventory. Consumers publish normalized facts with
`ingest_capability_observation()` over the ordinary consumer service when the
controller advertises capability ingestion; Fabric never calls a provider or
treats inventory as authorization. See
[docs/CAPABILITY_OBSERVATIONS.md](docs/CAPABILITY_OBSERVATIONS.md).
Use
`collect_work_items()` for generic partitioned collection; Fabric does not
interpret MNEL or RAVEL partition semantics. See
[docs/WORKER_STATE.md](docs/WORKER_STATE.md) and
[docs/COLLECTIONS.md](docs/COLLECTIONS.md).

Resource-aware consumers can pass a `PlacementRequest` to `execute()` or
`replicate()`. Fabric chooses an eligible worker from fresh resource evidence;
it does not move model layers or choose a provider runtime policy. A discovered
NVIDIA device remains `execution_probe=UNKNOWN` until a separate runtime
performs a real synchronized kernel probe. See
[docs/RESOURCE_PLACEMENT.md](docs/RESOURCE_PLACEMENT.md).

`FabricService` remains the stable local/service boundary for node inspection,
plan validation, local execution, verification, collection, and reconciliation.
For external distributed consumers, the documented entrypoint is
`mncs_fabric.api.FabricClient`; both boundaries are public and neither requires
consumers to assemble private transport, trust, or receipt internals.

Fabric is intended to become persistent authenticated compute infrastructure.
The current controller runtime foundation owns durable lifecycle state and can
be supervised independently of consumers, while `FabricClient` remains the
ordinary consumer boundary. Local Harness, Forge, and MNCS Control retain
semantic model, residency, task, tool, workspace, verification, and escalation
policy; they do not own worker presence or Fabric process lifetime.

## Repository map

- `src/mncs_fabric/` — canonical identities, manifests, node capture, execution, receipts, bundle compatibility, service boundary, protocol, transports, enrollment, scheduler, and ledger;
- `schemas/` — versioned interchange schemas;
- `examples/portable-python/` — a deterministic cross-platform example bundle;
- `docs/` — protocol, integration, and roadmap documents; and
- `tests/` — standard-library unit and integration tests.

## Intended cluster

The first physical deployment targets four similarly specified Fedora systems on a 2.5 GbE switch, plus a heterogeneous cohort of Fedora, Windows, and Raspberry Pi OS machines. The homogeneous group is intended for scaling and sharded trials. The heterogeneous group is intended for portability, degradation, architecture, and evidence-integrity testing.

See [ARCHITECTURE.md](ARCHITECTURE.md) and [docs/ROADMAP.md](docs/ROADMAP.md).

## License

Apache License 2.0.
