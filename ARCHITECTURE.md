# Architecture

## Purpose

MNCS Fabric is the execution plane between a development control plane such as MNCS Forge and project-owned harnesses or evaluators. Its core responsibility is to preserve identity and evidence boundaries while moving a declared job onto one or more physical machines.

## Components

### Controller

`LocalController` maintains an in-process worker registry, deterministic
capability admission, immutable dispatch identities, and durable dispatch
history. `NetworkController` registers capability snapshots with a typed
transport and reuses the same dispatch/replay logic. It is an operator service,
not a conformance authority. Remote worker loss is returned as `UNKNOWN` and
never fabricated into a result.

### Worker

A worker verifies a job bundle and manifest, checks required capabilities, creates an isolated working copy, executes a fixed argv without a shell, captures bounded observations, and returns a self-identifying execution record.

The current alpha implements this behavior locally through `LocalWorker.handle`
and exposes an explicit `TLSWorkerServer` endpoint. The endpoint requires a
client certificate, verifies the enrolled controller fingerprint and logical
identity, accepts one bounded canonical envelope, and closes the connection.
It does not offer plaintext or HMAC-only fallback.

### Public application boundary

`FabricService` is the stable boundary for node inspection, capability inspection, plan validation, local execution, record verification, collection, and reconciliation. The CLI delegates to it. Forge invokes the same bounded service contract through its declared Provider Protocol workflow; it does not import Fabric internals.

### Protocol and durable state

`protocol.py` defines `mncs-fabric.protocol.v0.1` fixed envelopes. `transport.py`
adds bounded four-byte-length framing, canonical JSON validation, timeouts, and
TLS. `enrollment.py` provides an operator-managed append-only identity trust
ledger. `store.py` provides a Fabric-owned append-only JSONL ledger with
sequence and SHA-256 linkage, exclusive writer locking, bounded reads, `fsync`,
corruption detection, and explicit tail recovery. `controller.py` and
`worker.py` use the ledger to distinguish idempotent duplicate delivery from
conflicting replay.

### Family receipt adapter

`receipts.py` produces the current experimental MNCS typed execution receipt as a companion observation. It maps only facts present in a Fabric execution record and emits UNKNOWN or `not-asserted` for sandboxing, network isolation, custody, independence, attestation, correctness, and conformance. See [docs/FAMILY_COMPATIBILITY.md](docs/FAMILY_COMPATIBILITY.md).

### Execution-bundle compatibility

`bundles.py` verifies the current MNCS EA-NEXT-002 ZIP shape without extracting
untrusted content. It keeps the raw logical bundle identity distinct from the
exact `sha256:` archive identity and binds receipts through a companion record.
Bulk cross-host archive transfer is deferred; network dispatch uses
pre-positioned verified artifacts.

### Artifact store

Artifacts are addressed by ordered SHA-256 manifests. Manifest verification rejects missing, altered, symbolic-link, and undeclared extra files. Workers execute a copy of the verified bundle rather than the source bundle.

### Reconciler

The reconciler verifies execution-record identities and requires agreement on job, candidate, evaluator, and artifact identities. A cohort fails when declared result artifacts disagree. A cohort remains `UNKNOWN` when any execution is incomplete or unsupported.

## Data flow

1. A generator or operator creates a candidate bundle.
2. Fabric creates an ordered artifact manifest.
3. A job plan binds the candidate, evaluator, artifact manifest, argv, resource limits, capabilities, and expected result paths.
4. A worker verifies the inputs before launch.
5. The command runs in a temporary working copy with bounded output and time.
6. Fabric identifies declared result artifacts and emits a raw execution record.
7. The reconciler compares records without rewriting their observations.
8. Separate project evaluators or MNCS/MNCDS validators consume the resulting evidence.

## Status ordering

- `FAIL`: a declared check contradicted the artifact, execution, or cohort requirements.
- `UNKNOWN`: execution could not establish the declared result, including timeout, unavailable capability, output limit, or launch failure.
- `PASS`: every implemented declared check passed.

Across a cohort, `FAIL` dominates `UNKNOWN`, and `UNKNOWN` dominates `PASS`.

## Current non-goals

- Kubernetes or general-purpose cluster orchestration;
- arbitrary remote shell access;
- independent certification;
- protected holdout custody;
- network or kernel sandboxing;
- hardware attestation;
- a distributed RAVEL mechanism; and
- claiming Phase-1 multi-host completion without a real second host.
