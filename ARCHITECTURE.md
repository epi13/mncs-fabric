# Architecture

## Purpose

MNCS Fabric is the execution plane between a development control plane such as MNCS Forge and project-owned harnesses or evaluators. Its core responsibility is to preserve identity and evidence boundaries while moving a declared job onto one or more physical machines.

## Components

### Controller

`LocalController` maintains an in-process worker registry, deterministic
capability admission, immutable dispatch identities, and durable dispatch
history. `NetworkController` registers endpoint configuration with a typed
transport and can request an authenticated worker description. Worker-observed
capability and resource records replace the current scheduling observation
while prior records remain in the controller ledger. Liveness expires after a
bounded lease; remote worker loss is returned as `UNKNOWN` and never fabricated
into a result. It is an operator service, not a conformance authority.

### Worker

A worker verifies a job bundle and manifest, checks required capabilities, creates an isolated working copy, executes a fixed argv without a shell, captures bounded observations, and returns a self-identifying execution record.

The current alpha implements this behavior locally through `LocalWorker.handle`
and exposes an explicit `TLSWorkerServer` endpoint. The endpoint requires a
client certificate, verifies the enrolled controller fingerprint and logical
identity for every connection, and accepts one bounded canonical envelope per
connection. `serve_once()` preserves the original one-request behavior;
`serve_forever()` is an explicitly bounded persistent service with request,
idle, connection, and graceful-shutdown limits. It does not offer plaintext or
HMAC-only fallback.

### Public application boundary

`FabricService` is the stable boundary for node inspection, capability inspection, plan validation, local execution, record verification, collection, and reconciliation. The CLI delegates to it. Forge invokes the same bounded service contract through its declared Provider Protocol workflow; it does not import Fabric internals.

`mncs_fabric.api.FabricClient` is the consumer-facing distributed facade. It
composes local and registered mTLS workers, typed `RemoteWorkerConfig`, bundle
transfer, replication, reconciliation, Fabric-owned receipts, and optional
`ConsumerContext` provenance. Consumers do not construct
`NetworkController`, `TLSNetworkTransport`, or `TrustStore` for ordinary use;
those remain supported advanced interfaces. The identity-addressable
`mncs-fabric.public-contract.v0.1` descriptor reports the supported schemas and
features.

`resources.py` is the provider-neutral placement boundary. A `ResourceSnapshot`
is a time-varying identity-addressed observation, not part of the stable node
fingerprint. A `PlacementRequest` binds consumer resource intent without
importing MNEL, RAVEL, Torch, or Accelerate. The scheduler evaluates it against
a fresh snapshot and emits an identity-addressable admission with explicit
reasons. A provider runtime may attach an
`ExecutionPlacementObservation`; Fabric records and binds it but does not
attest to its truth. CPU, full accelerator, and sequential CPU offload are
placement modes, not implementations of model-layer movement.

`worker_state.py` owns bounded worker-description and worker-liveness profiles.
Descriptions are authenticated worker reports, not attestation.
`collections.py` owns generic work-item and collection completeness; consumer
projects retain partition meaning and semantic aggregation.

### Distributed capability and target separation

Fabric should support distributed agent harnesses without becoming an agent harness
itself. A consumer may need to place inference on one worker while the authoritative
workspace and tool execution remain on another host. Fabric therefore treats these
as separate consumer concepts rather than collapsing them into a single worker:

- **inference placement** identifies the worker/runtime selected to host model
  execution;
- **workspace authority** remains a consumer-owned reference to the host or service
  that owns mutable task state; and
- **tool execution target** identifies the enrolled worker or controller-local
  executor on which an explicitly authorized bounded tool operation runs.

Fabric may carry identity-addressed references and evidence for those targets, but it
does not decide their semantic relationship. A remote model receiving inference
placement does not thereby gain filesystem, SSH, shell, MCP, or workspace authority.
Any tool request must return to the consuming harness or other control plane, which
applies its own policy and then submits a separate bounded execution request if the
tool truly belongs on a remote worker.

Future authenticated worker descriptions may advertise provider-neutral capability
facts such as:

- installed model/runtime identities and declared runtime features;
- worker-local executable/tool capabilities;
- worker-local MCP endpoint identities;
- CPU, accelerator, memory, architecture, and resource observations; and
- bounded workspace or service references explicitly configured by the operator.

These observations are inputs to consumer routing, not semantic recommendations.
Fabric must not assert that one model is better for coding, that a particular MCP
should be called, or that a task should be decomposed. Model suitability, task DAGs,
reduction, verification, approval, and escalation remain consumer-owned.

Controller-hosted capabilities do not need to be replicated onto every worker merely
because inference runs remotely. A consumer may proxy a tool or MCP call through its
own control plane and send only the bounded result back on the next inference turn.
Conversely, worker-local tools may be invoked through an explicit Fabric execution
target when the resource is inherently attached to that worker. Both paths preserve
the distinction between inference authority and execution authority.

Shell access remains intentionally narrow. Fabric's execution primitive continues to
be fixed argv without an ambient shell. If a consumer introduces Bash or PowerShell
script execution, the script must be represented as an explicit bounded workload and
subject to consumer policy before Fabric receives it. Fabric must never fall back to
arbitrary SSH or interactive remote shell access when a target is unavailable.

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

`challenges.py` is an additive EA-NEXT-005 compatibility boundary. A
controller may carry a verifier-scoped challenge through dispatch; the worker
copies only its nonce/window observations into the receipt, and the controller
consumes the challenge once in a separate durable local replay ledger. Fabric
protocol request replay and MNCS freshness replay are deliberately distinct.

### Execution-bundle compatibility

`bundles.py` verifies the current MNCS EA-NEXT-002 ZIP shape without extracting
untrusted content. It keeps the raw logical bundle identity distinct from the
exact `sha256:` archive identity and binds receipts through a companion record.
`bundle_transfer.py` adds bounded Fabric-native offer/chunk/commit transfer.
Workers independently verify the archive, materialize only verified regular
members, and atomically publish an immutable cache entry. SSH remains an
operator bootstrap channel for source, trust, and worker startup; it is no
longer required to stage candidate execution material in the native-transfer
path.

The bounded Linux operator harness in `scripts/two_host_fedora_test.py` stages the
exact source, trust material, and verified execution material over SSH, then
uses direct Fabric mTLS for the request. SSH is not a candidate execution
path, and the harness requires explicit host/key arguments.

`scripts/linux_worker_preflight.py` and
`scripts/raspberry_pi_native_bundle_test.py` reuse this Linux path for ARM
workers. The Raspberry Pi configuration is explicit and local-only; a known
host key without a configured account/key mapping is recorded as `UNKNOWN`,
not converted into a worker claim. The current ARM preflight evidence is
therefore bootstrap evidence only and does not establish a commissioned Pi.

### Artifact store

Artifacts are addressed by ordered SHA-256 manifests. Manifest verification rejects missing, altered, symbolic-link, and undeclared extra files. Workers execute a copy of the verified bundle rather than the source bundle.

### Reconciler

The reconciler verifies execution-record identities and requires agreement on job, candidate, evaluator, and artifact identities. A cohort fails when declared result artifacts disagree. A cohort remains `UNKNOWN` when any execution is incomplete or unsupported.

Resource admission is time-of-check/time-of-use bounded: the snapshot used for
a decision is retained in the result, but Fabric does not reserve VRAM or
guarantee that resources remain available at launch. Dynamic resource
quantities are operational evidence, not correctness or assurance.

The bounded two-host harness uses SSH only for exact-revision bootstrap and
material staging. It launches a narrow worker process and performs the actual
request over direct Fabric TLS. The sanitized result in
`development-evidence/` is operator-controlled development evidence; it does
not elevate a receipt, bundle, or physical host count into assurance.

## Data flow

1. A generator or operator creates a candidate bundle.
2. Fabric creates an ordered artifact manifest.
3. A job plan binds the candidate, evaluator, artifact manifest, argv, resource limits, capabilities, and expected result paths.
4. A worker verifies the inputs before launch.
5. The command runs in a temporary working copy with bounded output and time.
6. Fabric identifies declared result artifacts and emits a raw execution record.
7. The reconciler compares records without rewriting their observations.
8. Separate project evaluators or MNCS/MNCDS validators consume the resulting evidence.

For a consumer-owned distributed agent session, an additional control loop may occur
outside Fabric: the consumer places inference on one worker, receives a tool request,
applies policy, optionally submits a separate bounded execution request to the
controller or another worker, and returns the bounded result on a later inference
turn. Fabric records each admitted execution independently and does not merge those
steps into semantic agent authority.

## Status ordering

- `FAIL`: a declared check contradicted the artifact, execution, or cohort requirements.
- `UNKNOWN`: execution could not establish the declared result, including timeout, unavailable capability, output limit, or launch failure.
- `PASS`: every implemented declared check passed.

Across a cohort, `FAIL` dominates `UNKNOWN`, and `UNKNOWN` dominates `PASS`.

## Current non-goals

- Kubernetes or general-purpose cluster orchestration;
- arbitrary remote shell access;
- granting a remote inference worker ambient authority over another host's workspace;
- semantic model selection, task decomposition, agent planning, reduction, or escalation;
- independent certification;
- protected holdout custody;
- network or kernel sandboxing;
- hardware attestation;
- a distributed RAVEL mechanism; and
- public semantic ownership for MNEL/RAVEL workloads or collection aggregation; and
- production daemon supervision or unlimited worker service operation.
