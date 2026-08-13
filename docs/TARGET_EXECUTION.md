# Exact target execution

Fabric `0.2.0a18` provides persistent-service execution on one exact
`ExecutionTargetReference`. The consumer chooses the worker and the bounded job.
Fabric re-evaluates current controller-owned membership, authenticated presence,
liveness, capability observation, runtime, context, and provenance bindings before
dispatch. It never substitutes a scheduler-selected worker and never falls back to
local execution.

```python
from mncs_fabric import ConsumerContext, ExecutionTargetReference, FabricClient

client = FabricClient.connect("/run/user/1000/mncs-fabric/controller.sock")
context = ConsumerContext(
    source_project="example-consumer",
    consumer_workload_identity="sha256:" + "a" * 64,
)
observation = client.latest_capability_observation("worker-a")
tool = next(item for item in observation["capabilities"] if item["kind"] == "tool")
worker = client.fleet_status("worker-a")
target = ExecutionTargetReference(
    worker_identity="worker-a",
    required_capabilities=("python", "tool:git"),
    tool_capability_identity=tool["capability_identity"],
    runtime_identity=worker["description"]["runtime_profile"]["runtime_profile_identity"],
    consumer_context_identity=context.context_identity,
    consumer_authorization_identity="sha256:" + "b" * 64,
)
result = client.execute_target(
    target,
    plan,
    manifest,
    consumer_context=context,
    consumer_authorization_identity="sha256:" + "b" * 64,
    execution_bundle_archive=bundle_archive,
)
```

The client uploads the verified archive into controller-owned content-addressed
storage. The controller forwards it through the selected worker's authenticated
transport. The consumer receives no endpoint, CA path, private key, TrustStore,
registry path, bundle-cache path, or rendezvous object.

## Admission and failure contract

A passing admission is `mncs-fabric.target-admission.v0.1`. It contains the full
canonical target reference, an identity-addressed authenticated request binding,
the current worker/session facts, current capability/runtime identities, freshness
ages, individual checks, and `TARGET_ADMITTED`. Non-passing requests use stable
codes:

- `DENIED`: `TARGET_REVOKED`, `TARGET_CAPABILITY_MISSING`,
  `TARGET_RUNTIME_MISMATCH`, `TARGET_TOOL_CAPABILITY_MISMATCH`,
  `TARGET_CONTEXT_MISMATCH`, or `TARGET_AUTHORIZATION_BINDING_INVALID`;
- `UNKNOWN`: `TARGET_UNKNOWN`, `TARGET_DISCONNECTED`,
  `TARGET_LIVENESS_STALE`, `TARGET_CAPABILITIES_STALE`, or
  `TARGET_BECAME_UNAVAILABLE`.

The authorization identity is opaque consumer-provided provenance. Its SHA-256
shape is not semantic permission. Fabric's narrow guarantee is that the
same-OS-user authenticated local peer requested this exact bounded job and target.
The consumer remains responsible for tool policy and result acceptance.

## Evidence and retry behavior

Successful and idempotently repeated executions return
`mncs-fabric.target-execution-evidence.v0.1`. It binds the target/admission,
authenticated client, service and durable execution request identities, worker and
session generation, capability observation, runtime, consumer context and
authorization provenance, bundle, job, execution record, receipt, and disposition.

When no request identity is supplied, `FabricClient.execute_target()` derives one
from the exact target, job, manifest, archive, context, and authorization provenance.
The worker's durable replay ledger returns `DUPLICATE_IDEMPOTENT` with the known
record for an identical retry and rejects a changed-payload replay. This avoids
accidental re-execution; it is not a distributed transaction or a guarantee that an
unobserved in-flight operation completed.

The append-only `target-execution.jsonl` ledger is authoritative. The controller's
`target-evidence-index.json` is only a rebuildable request-identity cache. Missing,
malformed, identity-invalid, or ledger-stale cache state is discarded and rebuilt
from the complete verified ledger. A retry can return original evidence only when
the target, authenticated client/context/authorization, worker, job, bundle, record,
and receipt bindings all match; request-identity reuse with different bindings is
rejected.

Exact targeting and immutable bundles are logical confinement, not OS isolation.
The execution record separately reports `containment_mode`, provider, filesystem
enforcement, and network enforcement. Fedora/Linux deployed workers use required
bubblewrap containment for Python targets and fail closed when it is unavailable.
An explicitly configured `compatibility-uncontained` worker retains the service
account's ambient authority and must not be treated as sandboxed.

Capability observations are factual, retained, non-attested inputs supplied by an
authenticated same-user consumer or bounded probe. Presence of `git`, `python`, a
runtime, model, or MCP identity never grants permission to use it. Admission is based
on current observations and is not a capacity reservation; a worker can still
disappear after admission, which is reported as `TARGET_BECAME_UNAVAILABLE`.

The operation and feature flags are additive. The controller/worker wire protocol
and local service contract remain `v0.1`; the new admission and evidence records use
new schema identifiers rather than changing the meaning of existing records.
