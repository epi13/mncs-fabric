# Fabric records and protocol 0.1

The initial protocol consists of five versioned JSON record families. Their JSON Schemas are under `schemas/`. Canonical identities use UTF-8 JSON with sorted keys, no insignificant whitespace, and SHA-256 prefixed by `sha256:`. The identity field itself is omitted while deriving the identity.

## Artifact manifest

An ordered list of regular bundle files, byte sizes, and SHA-256 identities. Verification rejects symbolic links and, by default, any undeclared extra file.

## Job plan

Binds a human-readable job ID to candidate, evaluator, and manifest identities; an argv; a relative working directory; time and output limits; environment overrides; required capabilities; result paths; and a declared network policy.

`argv[0]` must be an absolute executable path or the portable `@python` alias. The local executor resolves `@python` to its running interpreter and records that executable's identity.

## Node-capability record

Captures a user-supplied machine label, operating system, architecture, Python runtime, CPU count, and selected discovered tools. The node fingerprint is informational and is not hardware-backed attestation.

## Execution record

Captures the verified identities, host record, timing, executable identity, exit disposition, exact output byte counts and digests, bounded UTF-8 previews, result-file identities, policy observations, and limitations.

The executable does not authoritatively declare the Fabric outcome. Fabric derives the outcome from launch, resource, exit, and result checks. Project-specific semantic gates belong in a separate evaluator.

## Controller/worker envelope

`mncs-fabric.protocol.v0.1` is a transport-independent fixed envelope. Its
message type, controller and worker IDs, request/job IDs, nonce, expiry,
payload, and canonical `message_id` are bound together. Dispatch payloads carry
a validated fixed-argv job plan and matching artifact manifest identity; they
do not carry arbitrary shell commands. Unknown protocol versions fail closed.

The implemented local message families are worker announcement/capabilities,
authenticated worker description, dispatch request/acknowledgement, execution
result, status, collection, and replay disposition. Optional HMAC-SHA256 uses
an operator-supplied key ID and
rejects unknown, inactive, revoked, wrong, or tampered keys. It is message
authentication, not encrypted transport.

`InProcessTransport` and `TLSNetworkTransport` implement the same envelope
interface. The TLS variant requires a CA-validated client/server certificate,
enrolled certificate fingerprints, explicit controller/worker identity
agreement, timeouts, and a bounded four-byte length frame. One request and one
response are allowed per connection; a bounded persistent worker may accept
multiple such connections without restarting. Truncated, oversized,
noncanonical, or trailing data is rejected. TLS protects transport only. It does not establish
independence, protected custody, attestation, correctness, or conformance.

EA-NEXT-002 execution bundles are verified by a separate companion boundary.
Their raw logical identity and exact archive transport identity are retained
separately. `mncs-fabric.bundle-transfer.v0.1` adds bounded offer/chunk/commit
messages over the authenticated envelope transport. The worker verifies and
atomically publishes the archive before dispatch can use it; this is typed
bundle transfer, not arbitrary file transfer.

The public consumer layer may add a validated
`mncs-fabric.consumer-context.v0.1` provenance object. It contains opaque
consumer/workflow/provider references and grants no evaluator, promotion,
conformance, or semantic verdict authority. Dispatch replay identity includes
this context and any typed execution-bundle binding.

Resource-aware dispatch may add a validated
`mncs-fabric.execution-placement-request.v0.1`. The worker captures a fresh
`mncs-fabric.node-resources.v0.1` snapshot and returns a
`mncs-fabric.placement-admission.v0.1` with explicit mode, decision identity,
snapshot identity, and rejection reason. A placement request is part of the
stable dispatch request identity. Explicit accelerator and sequential-offload
requests remain `UNKNOWN` when executable runtime/resource evidence is not
established; there is no silent CPU fallback. Placement references in a
receipt remain observations, not hardware attestation.

`worker.describe.request` / `worker.describe.result` are additive message
types. The result carries the bounded `mncs-fabric.worker-description.v0.1`
record, including node/resource/public-contract references and capture time.
The controller validates the logical worker binding and retains the result in
its append-only ledger. It derives `mncs-fabric.worker-liveness.v0.1` from
authenticated contact; an expired lease is `UNKNOWN`, not presumed available.

An optional EA-NEXT-005 challenge is carried as a validated dispatch companion.
Its exact subject/candidate/bundle/policy/runner scope, nonce, and validity
window are identity-bound into the request payload. The worker copies the
challenge observations into the returned receipt; the controller verifies the
receipt binding. `ChallengeReplayStore` consumes the challenge once in a
durable Fabric-owned ledger. This freshness layer is distinct from protocol
request replay protection and remains local operator-controlled evidence.

## Receipt compatibility

Fabric v0.2 adds a companion adapter for the experimental MNCS typed execution
receipt and assurance record. The original Fabric execution-record v0.1 is not
rewritten. Receipt identity, bundle, candidate, runner, environment, streams,
artifacts, and actual termination observations are preserved where available;
missing assurance facts remain UNKNOWN and claim boundaries remain
`not-asserted`.

## Durable local state

Controller and worker dispatch/result state is appended to a versioned local
ledger with record identity, sequence, previous-entry identity, and entry
identity. Corruption and unsupported versions fail closed. A truncated tail is
diagnosed and can only be removed by an explicit recovery call. See
[STORAGE.md](STORAGE.md).

## Cohort result

Verifies each execution-record identity, checks bound identities, applies `FAIL > UNKNOWN > PASS`, and compares declared result artifacts. One record is classified as local reproduction. Multiple distinct machine labels are classified as operator-controlled cross-host reproduction. Neither classification implies independence.
