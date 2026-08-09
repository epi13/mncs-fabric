# MNCS-family compatibility

This iteration was aligned against these local sibling snapshots:

| Project | Commit used | Boundary used | Status |
| --- | --- | --- | --- |
| `machine-native-complexity-standard` | `49400a41f3b7b36de8a25e6cac1141d3980878be` | EA-NEXT-001 typed receipt and EA-NEXT-002 immutable execution bundle `0.1-experimental` | receipt adapter and offline bundle verifier; assurance remains UNKNOWN where Fabric cannot establish a property |
| `MNCS-Commons` | `108ce56000a879c0b2595cab8665b1656c0a1bd5` | append/recovery, locking, and structured adapter concepts | Fabric-owned ledger; no private Commons dependency |
| `mncs-forge-mcp` | `5a5691709b26a2f923e14674138bdb215471a5a7` | Runner/LocalProcessRunner, service boundary, Provider Protocol, local threat harness | Forge-controlled workflow and public service boundary |
| `mncs-language` | `26cd7f015cb857abe3f0601780de096e04dea7b4` | executable semantic/HIR and provider vocabulary | no new authority vocabulary |
| `RAVEL` | `2dfedd2a7edbab12b7e301228d56b1416f172f78` | lifecycle/episode identity awareness | no RAVEL conformance claim |
| `Machine-Native-Experimental-Learning` | `3a44380c56ded6a1fae1aa7a6a908f28ad1dd953` | identity/lifecycle and native artifact vocabulary | no imported private contract |
| `gimp-local-mcp` | `e824c6a25db2a262c4f9f55801d77d96c95eae43` | provider-neutral CPU/accelerator/offload placement direction | no CUDA-specific requirement imported |

## Supported receipt assumptions

Fabric supports the exact current receipt top-level shape, raw 64-hex SHA-256
fields, explicit claim boundary, separate enforcement states, nullable
placement reference, and `PASS`/`FAIL`/`UNKNOWN` observations. It preserves
Fabric record identity in a namespaced extension and binds the receipt to the
Fabric job, candidate, manifest, runner, and environment observations.

Unknown receipt versions fail closed. The self-contained shape snapshot is
`compat/mncs-execution-receipt-0.1.snapshot.json`; the optional checker accepts
a sibling schema path but is never required by CI.

## EA-NEXT-002 bundle assumptions

`compat/mncs-execution-bundle-0.1-experimental.snapshot.json` pins the bundle
shape and source commit. `mncs_fabric.bundles.verify_bundle_archive` verifies
the current bounded ZIP shape offline, without extraction, and retains two
different identities: raw logical `bundle_identity` and exact transport
`archive_identity`. `bind_receipt_to_bundle` and the companion binding record
require logical bundle, harness, input, and policy agreement.

Fabric currently consumes and verifies bundle archives; it does not yet stream
bulk bundle material as a network dispatch payload. A network worker therefore
requires pre-positioned verified artifacts until the transfer profile is added.

Fabric does not emit MNCS/MNCDS conformance, execution assurance, protected
custody, independent evaluation, sandbox, encryption, or attestation claims.
