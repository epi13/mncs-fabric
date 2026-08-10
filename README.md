# MNCS Fabric

MNCS Fabric is an experimental, operator-controlled execution and evidence fabric for the Machine-Native Complexity Standard project family. It provides bounded local execution, content-addressed artifact manifests, host capability records, raw execution records, and deterministic cross-host reconciliation.

> **Status:** `0.2.0a8` experimental execution substrate. The commissioned Windows NVIDIA worker has produced identity-bound synchronized CUDA and sequential CPU-offload runtime evidence, and Fedora local, Fedora remote, Windows, and Raspberry Pi/Linux ARM workers have completed a portable four-node cross-architecture collection. Production lifecycle, resource reservation, sandboxing, protected custody, and independent evaluation remain out of scope.

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
- a strict Windows worker preflight/lifecycle helper and optional synchronized
  Torch CUDA probe workload; and
- a strict explicit-configuration Linux/ARM worker preflight and reusable
  Raspberry Pi native-bundle harness; and
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
```

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

External consumers should import `FabricClient`, `LocalWorkerConfig`,
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
archive only to the selected remote worker. Consumer projects retain semantic
workload, evaluation, promotion, and learning authority.

`FabricClient.refresh_worker()` obtains the current authenticated worker
description. `FabricClient.workers()` exposes observation source, availability,
last contact, and description/resource identities. Use
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
