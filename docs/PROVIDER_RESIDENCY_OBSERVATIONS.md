# Provider-neutral residency and session observations

## Purpose

MNCS Fabric already reports provider-neutral worker capabilities and resource state while
leaving semantic model choice, task decomposition, and agent policy to the consumer.
As MNCS Harness evolves from a single preferred resident model toward measured
working sets and session-affine routing, Fabric may need to carry a richer set of
**factual provider observations** without becoming a model scheduler or inference
runtime.

A useful external systems reference is Picchio (`benmaster82/picchio`), a GPT-OSS MoE
runtime that explicitly measures resident versus streamed state, cache hits/misses,
eviction, persistent session reuse, and the costs of speculative prefetch. The reusable
lesson for Fabric is not to copy Picchio's inference engine. It is to preserve enough
identity-bound runtime facts that a consumer can reconstruct placement and residency
cost without Fabric assigning semantic meaning to those facts.

## Boundary

The implemented Harness lifecycle uses this boundary today: Harness submits a
bounded exact-target provider-loopback warm or release job, Fabric persists its
execution/receipt evidence, and Harness publishes the resulting provider model
inventory as a capability observation. Fabric still does not hold a model lease,
choose a keep-alive value, or decide when another model should be evicted. The
provider's `/api/ps`-equivalent observation, not dispatch completion or wall-clock
latency, establishes loaded/absent state.

Conversation state remains outside this contract. Messages, KV/session semantics,
tool results, and experiment handoffs are not reconstructed from loaded weights.

Fabric may answer questions such as:

- Which worker/runtime reported this model as installed or loaded?
- Was the model already loaded before execution?
- What memory/resource state was observed near admission?
- Did a provider report a load, unload, displacement, or restoration transition?
- What load or initialization duration did the provider observe?
- Did the consumer bind this execution to an opaque provider session reference?
- Was that same opaque session reference reused on a later execution?
- What execution placement and worker identity were bound to the observation?

Fabric must **not** answer questions such as:

- Which model is best for this task?
- Which model should stay resident?
- Which model should be evicted?
- Should another model be prefetched?
- Is a warm model semantically acceptable?
- Should a task remain sticky to a worker?
- Should work be decomposed or reduced differently?

Those remain consumer decisions.

## Observation model

A future additive observation should remain factual, bounded, identity-addressable, and
provider-specific only where necessary. Candidate normalized fields include:

```text
schema_version
observation_identity
worker_id
runtime_profile_identity
provider_name
provider_version
model_identity
model_name
observed_at

installed
loaded
warm_state
loaded_memory_bytes
provider_reported_context_bytes
provider_reported_cache_bytes

load_started_at
load_completed_at
load_duration_ms
unload_observed
last_used_at

resource_snapshot_identity
execution_placement_identity

provider_session_ref
provider_session_state
session_created_at
session_last_used_at

transition
transition_reason
prior_model_identity
replacement_model_identity

source
confidence
limitations
```

Fields should be omitted or explicitly UNKNOWN when the provider cannot establish them.
Zero must never substitute for missing memory, timing, or load information.

`warm_state` should use a small factual vocabulary such as `LOADED`, `NOT_LOADED`, or
`UNKNOWN`. It must not imply semantic suitability or a promise that the model will
remain resident.

## Provider session references

A provider may expose an opaque session identifier for persistent KV/cache/process state.
Fabric may carry and bind that identifier as consumer provenance, but the reference:

- is not an authorization token;
- grants no filesystem, shell, MCP, workspace, or worker-management authority;
- must not be interpreted by Fabric;
- should be scoped to the provider/runtime identity that issued it;
- may become stale or invalid independently of Fabric worker liveness; and
- must be treated as UNKNOWN when the provider cannot confirm reuse.

The consuming harness decides whether session affinity is useful and whether a task may
continue using the reference.

## Transition observations

Loaded-model state is time-varying. Fabric should represent observed transitions rather
than infer hidden provider behavior. Candidate transition values include:

```text
LOAD
UNLOAD
EVICT
RESTORE
REUSE
UNKNOWN
```

A provider may not distinguish an eviction from a normal unload. In that case Fabric
must record the weaker fact it actually received.

If a consumer requests model A, then model B appears loaded afterward and model A
vanishes, Fabric must not invent causality unless the provider explicitly reports it.
The consumer may later correlate the timeline in its own metrics.

## Placement cost inputs

Fabric may carry measurements that a consumer can use in a route-cost model:

- observed model load/initialization time;
- current and total host RAM;
- current and total accelerator memory;
- loaded-model memory when the provider can report it;
- provider process/runtime identity;
- network/dispatch timing already available through Fabric execution records;
- worker liveness and capability freshness;
- placement mode and provider execution observation;
- whether a model/session was already loaded/reused at execution start.

Fabric must not combine those facts into a semantic route score. At most it may expose
provider-neutral deterministic eligibility or resource admission already within the
existing placement contract.

## Prefetch and speculative warming

Speculative warming is a consumer/provider policy, not a Fabric scheduling primitive.
Picchio's documented experiments are a useful warning that prefetch can make constrained
systems slower by competing with the useful working set.

If MNCS Harness later asks a provider to warm a model, Fabric may transport that bounded
operation and record observations such as bytes, duration, resulting loaded state, and
subsequent use. Fabric should not autonomously initiate, repeat, cancel, or prioritize
model warming.

Useful factual observations may include:

```text
warm_request_identity
warm_started_at
warm_completed_at
warm_duration_ms
loaded_after_warm
used_before_unload
```

Whether the warming was useful, wasted, or harmful is a consumer evaluation.

## Cache and hierarchy language

Consumers may reason about a fleet as an operational hierarchy:

```text
active session
  -> loaded model on preferred worker
  -> loaded model elsewhere
  -> installed model on preferred worker
  -> installed model elsewhere
  -> available artifact/provisioning source
```

Fabric should expose the underlying facts but avoid naming these levels as quality or
priority tiers. A slower or colder placement may be semantically required; an already
loaded model may be unsuitable.

## Provider-runtime responsibility

Fabric continues to treat model execution internals as provider-owned. It does not move
transformer experts, layers, KV blocks, or tensors between workers. It does not implement
quantization, GPU offload, MoE routing, cache replacement, or model-specific prefetch.

If distributed model execution is explored later, a dedicated provider runtime may use
Fabric to place bounded processes or data movement, but the model runtime remains above
the Fabric execution substrate.

## Evidence and trust

Residency observations are operational evidence, not correctness evidence, attestation,
or conformance.

Every observation should retain:

- exact worker identity;
- provider/runtime identity when available;
- source and freshness;
- referenced resource snapshot/placement identities;
- explicit UNKNOWN for unsupported facts;
- enough timing/context to reconstruct the consumer decision later.

Provider-reported facts are only as trustworthy as the provider and operator-controlled
runtime that produced them. Fabric must not upgrade them into protected custody,
hardware attestation, semantic correctness, or MNCS conformance.

## Staged work

### Stage A — normalize observations

- extend existing model/runtime capability observations with clearly factual loaded-state
  and optional provider timing/memory fields;
- retain current compatibility for providers that only report installed model names;
- add fixtures proving absent values remain UNKNOWN rather than zero.

### Stage B — transition history

- record bounded load/unload/reuse transitions in the controller ledger;
- bind transition observations to worker/runtime/model identities;
- prove stale or missing observations never become current availability.

### Stage C — opaque session provenance

- carry provider session references as uninterpreted consumer provenance;
- bind session reuse observations to exact worker/runtime/model identities;
- add tests proving session references grant no execution or capability authority.

### Stage D — warm-operation evidence

- transport explicit consumer/provider warm requests as bounded operations when needed;
- record resulting provider observations without implementing autonomous prefetch;
- preserve separate request, execution, placement, and residency identities.

### Stage E — heterogeneous evidence

- collect the same normalized residency observations from CPU-only, GPU, Windows,
  Linux, and ARM/provider combinations where supported;
- document unsupported provider fields rather than normalizing them into invented facts.

## Non-goals

This design does not add semantic model routing, learned scheduling, autonomous
prefetch, model eviction policy, model migration policy, distributed transformer
execution, KV transfer, or cross-worker expert routing to Fabric.
