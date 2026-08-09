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
dispatch request/acknowledgement, execution result, status, collection, and
replay disposition. Optional HMAC-SHA256 uses an operator-supplied key ID and
rejects unknown, inactive, revoked, wrong, or tampered keys. It is message
authentication, not encrypted transport.

`InProcessTransport` and `TLSNetworkTransport` implement the same envelope
interface. The TLS variant requires a CA-validated client/server certificate,
enrolled certificate fingerprints, explicit controller/worker identity
agreement, timeouts, and a bounded four-byte length frame. One request and one
response are allowed per connection; truncated, oversized, noncanonical, or
trailing data is rejected. TLS protects transport only. It does not establish
independence, protected custody, attestation, correctness, or conformance.

EA-NEXT-002 execution bundles are verified by a separate companion boundary.
Their raw logical identity and exact archive transport identity are retained
separately. Network dispatch currently uses pre-positioned verified artifacts;
bulk archive transfer is deferred until a bounded transfer profile exists.

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
