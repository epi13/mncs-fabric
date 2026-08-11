# Worker capability observations

`mncs-fabric.worker-capability-observation.v0.1` is Fabric's provider-neutral,
identity-addressed inventory record for facts obtained about one registered worker.
The schema supports `model`, `runtime`, `tool`, `mcp`, `service`, and `other` entries.
Fabric does not import or call a model provider: a consumer or bounded worker probe
normalizes provider-specific output before ingestion.

Every observation binds exactly one `worker_identity`, a UTC capture time, an
availability state, an observation source, a fixed non-attestation claim boundary,
canonically ordered capability entries, and a deterministic SHA-256 identity. Each
entry has its own canonical identity and contains a kind, namespace, name, optional
version/subject identity, and bounded factual attributes. Nested attributes, control
characters, duplicate entries/list values, unsupported fields, negative integers,
more than 256 entries, and encoded observations over 256 KiB are rejected.

An observation is a retained claim, not authorization, attestation, semantic model
suitability, correctness, conformance, or proof that the capability remains usable.
Authentication or registration prevents worker A's observation from being ingested
under worker B's identity; it does not make the reported facts honest.

## Public API

`FabricClient` exposes the complete boundary:

- `ingest_capability_observation(worker_id, capabilities, ...)` validates, binds,
  canonically identifies, and appends an observation to the worker's Fabric ledger;
- `capability_observations(worker_id)` returns retained history;
- `latest_capability_observation(worker_id)` returns the latest retained claim;
- `capability_inventory(worker_id, max_age_seconds=...)` evaluates worker liveness,
  observation freshness, and observation availability; and
- `workers(capability_max_age_seconds=...)` includes the observation and an explicit
  `CURRENT`, `STALE`, `UNKNOWN`, or `UNAVAILABLE` inventory status.

The default freshness bound is 300 seconds and timestamps more than 60 seconds in
the future are not fresh. A stale observation remains durable evidence but is never
reported as current. A lost/unavailable worker similarly retains its last observation
while its current inventory status becomes `UNAVAILABLE` or `UNKNOWN`. Publishing a
failed fresh scan as an empty `UNAVAILABLE` observation prevents an older successful
inventory from silently remaining the current claim.

This additive API is advertised by `FabricClient.contract()` through the
`worker_capability_observation` feature and schema identifier. Existing execution,
resource, runtime-observation, and worker-description schemas retain their meanings.
Resource/runtime evidence can be viewed alongside capability inventory, but none of
these facts gives a consumer tool, workspace, filesystem, shell, SSH, or MCP authority.
