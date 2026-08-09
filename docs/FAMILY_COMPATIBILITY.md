# MNCS-family compatibility

## Fabric public consumer contract

Fabric publishes `mncs-fabric.public-contract.v0.1`, available through
`mncs-fabric contract show --json` and `FabricClient.contract()`. Its
identity-addressable descriptor pins the public API, record, capability,
protocol, receipt, bundle, and challenge profiles plus feature declarations.
The descriptor is compatibility metadata, not authority or conformance.

External consumers should use `FabricClient`, `RemoteWorkerConfig`, and
`ConsumerContext` from `mncs_fabric.api`. Fabric produces the execution record
and the companion MNCS receipt for both local and network execution; consumer
receipt reconstruction is not required. `ConsumerContext` retains opaque
workload, experiment, provider, partition, and Forge workflow references as
provenance only.

## Native bundle transfer

`mncs-fabric.bundle-transfer.v0.1` transfers a verified EA-NEXT-002 archive in
bounded chunks. Logical bundle identity and exact archive identity remain
distinct. The worker independently verifies the archive and atomically
publishes an immutable cache entry. This establishes package-integrity and
identity linkage observations only; it does not prove execution, correctness,
sandboxing, assurance, custody, independence, or conformance.

This iteration was aligned against these local sibling snapshots:

| Project | Commit used | Boundary used | Status |
| --- | --- | --- | --- |
| `machine-native-complexity-standard` | `80f08d312dce963265c7f69ac5b4bae8245bd692` | EA-NEXT-001 typed receipt, EA-NEXT-002 immutable execution bundle, and EA-NEXT-005 challenge/replay `0.1-experimental` | receipt, bundle, and additive challenge/replay adapters; assurance remains UNKNOWN where Fabric cannot establish a property |
| `MNCS-Commons` | `b1eb5a1081bbb63ee3a6284e8046035bd72a47bc` | append/recovery, locking, structured adapter, and public-node boundary concepts | Fabric-owned ledger/network; no private Commons dependency |
| `mncs-forge-mcp` | `7710ea606bd592e0be95957c96132e8732fbb955` | Runner/LocalProcessRunner, service boundary, Provider Protocol, local threat harness | Forge-controlled workflow and public service boundary |
| `mncs-language` | `f234cc8079faa5895a38b7abce0c96031f7d2565` | executable semantic/HIR and provider vocabulary | no new authority vocabulary |
| `RAVEL` | `99d39a1ce184c814a3ae6b15fe52612f6e708d92` | lifecycle/episode identity awareness | no RAVEL conformance claim |
| `Machine-Native-Experimental-Learning` | `57b07b2d25a8ea9dad93ea396ae5cc0dff7f9f5b` | identity/lifecycle and native artifact vocabulary | no imported private contract |
| `gimp-local-mcp` | `e824c6a25db2a262c4f9f55801d77d96c95eae43` | provider-neutral CPU/accelerator/offload placement direction | no CUDA-specific requirement imported |

## Supported receipt assumptions

Fabric supports the exact current receipt top-level shape, raw 64-hex SHA-256
fields, explicit claim boundary, separate enforcement states, nullable
placement reference, and `PASS`/`FAIL`/`UNKNOWN` observations. It preserves
Fabric record identity in a namespaced extension and binds the receipt to the
Fabric job, candidate, manifest, runner, and environment observations.

Unknown receipt versions fail closed. The self-contained shape snapshot is
`compat/mncs-execution-receipt-0.1.snapshot.json`; the optional checker accepts
a sibling schema path but is never required by CI. The corresponding
`scripts/check_mncs_challenge_compat.py` checks the current challenge, receipt,
and binding validators together when a read-only sibling checkout is present.

## EA-NEXT-002 bundle assumptions

`compat/mncs-execution-bundle-0.1-experimental.snapshot.json` pins the bundle
shape and source commit. `mncs_fabric.bundles.verify_bundle_archive` verifies
the current bounded ZIP shape offline, without extraction, and retains two
different identities: raw logical `bundle_identity` and exact transport
`archive_identity`. `bind_receipt_to_bundle` and the companion binding record
require logical bundle, harness, input, and policy agreement.

Fabric now transfers verified bundle archives through the bounded
`mncs-fabric.bundle-transfer.v0.1` profile. SSH may still bootstrap source,
trust, certificates, and worker lifecycle, but candidate execution material is
transported by Fabric in the native-transfer path. The cache and transfer are
experimental and operator-controlled.

## EA-NEXT-005 challenge/replay assumptions

`compat/mncs-execution-challenge-0.1-experimental.snapshot.json` pins the
current challenge, scope, and replay-receipt shape. Fabric carries an optional
scoped challenge in dispatch envelopes, copies its nonce/window into the typed
receipt, and consumes it once in a Fabric-owned durable replay ledger. The
protocol request ID and the MNCS challenge identity remain separate replay
layers. Bounded physical persistent-worker evidence now exists, but the replay
store is operator-controlled and does not establish freshness beyond that
store, correctness, isolation, custody, independence, conformance, or
promotion.

Fabric does not emit MNCS/MNCDS conformance, execution assurance, protected
custody, independent evaluation, sandbox, encryption, or attestation claims.

## Resource/placement assumptions

Fabric's additive resource profiles are provider-neutral. They preserve the
generic concepts needed by MNEL and RAVEL—host memory, accelerator discovery,
precision, reserves, model/workspace estimates, and placement identity—without
importing either consumer's runtime policy. CUDA discovery is not a CUDA
execution capability until a real runtime probe passes. Sequential CPU offload
is a consumer/provider runtime behavior; Fabric only checks resource admission
and retains a runtime observation if supplied.
