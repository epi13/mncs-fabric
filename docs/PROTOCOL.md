# Local protocol 0.1

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

## Cohort result

Verifies each execution-record identity, checks bound identities, applies `FAIL > UNKNOWN > PASS`, and compares declared result artifacts. One record is classified as local reproduction. Multiple distinct machine labels are classified as operator-controlled cross-host reproduction. Neither classification implies independence.
