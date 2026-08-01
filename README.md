# MNCS Fabric

MNCS Fabric is an experimental, operator-controlled execution and evidence fabric for the Machine-Native Complexity Standard project family. It provides bounded local execution, content-addressed artifact manifests, host capability records, raw execution records, and deterministic cross-host reconciliation.

> **Status:** `0.1.0a0` foundation. The local executor is functional. Remote transport, worker enrollment, authenticated dispatch, and distributed RAVEL execution are planned but are not yet implemented.

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
- JSON schemas, tests, CI, architecture documentation, and a portable example; and
- standard-library-only runtime for Python 3.11 or newer.

The executor is bounded but is **not a security sandbox**. Network policy is recorded but not yet enforced. See [THREAT_MODEL.md](THREAT_MODEL.md).

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
```

## Repository map

- `src/mncs_fabric/` — canonical identities, manifests, node capture, execution, and reconciliation;
- `schemas/` — versioned interchange schemas;
- `examples/portable-python/` — a deterministic cross-platform example bundle;
- `docs/` — protocol, integration, and roadmap documents; and
- `tests/` — standard-library unit and integration tests.

## Intended cluster

The first physical deployment targets four similarly specified Fedora systems on a 2.5 GbE switch, plus a heterogeneous cohort of Fedora, Windows, and Raspberry Pi OS machines. The homogeneous group is intended for scaling and sharded trials. The heterogeneous group is intended for portability, degradation, architecture, and evidence-integrity testing.

See [ARCHITECTURE.md](ARCHITECTURE.md) and [docs/ROADMAP.md](docs/ROADMAP.md).

## License

Apache License 2.0.
