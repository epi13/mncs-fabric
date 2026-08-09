# MNCS Fabric

MNCS Fabric is an experimental, operator-controlled execution and evidence fabric for the Machine-Native Complexity Standard project family. It provides bounded local execution, content-addressed artifact manifests, host capability records, raw execution records, and deterministic cross-host reconciliation.

> **Status:** `0.2.0a0` experimental Phase-1 foundation. Local execution, EA-NEXT-001 receipt adaptation, EA-NEXT-002 offline bundle verification, Forge-controlled validation, durable replay-safe protocol state, deterministic scheduling, and a TLS/mutual-certificate loopback transport are implemented. A real second-host run and bulk bundle transfer remain incomplete.

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
- explicit transport fault controls for bounded replay/drop/delay adversarial tests; and
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
  --certificate worker.pem --key worker.key --port PORT
```

`worker serve` is explicit and serves one bounded TLS request; it defaults to
loopback only when `--host` is omitted and never falls back to plaintext. The
controller-side Python API is `NetworkController` plus `TLSNetworkTransport`.

The repeatable physical-host harness is `scripts/two_host_fedora_test.py`. SSH
is limited to bootstrap, staging, diagnostics, and worker lifecycle; the
candidate request is sent through direct Fabric mTLS. It requires explicit
operator arguments and never uses SSH host-key bypasses.

The public application boundary is `mncs_fabric.service.FabricService`:
`nodes`, `capabilities`, `validate_plan`, `execute_local`, `verify_record`,
`collect`, and `reconcile`. A future Forge provider should call this boundary
or the bounded CLI, never private implementation modules.

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
