# MNCS Forge integration boundary

MNCS Forge is expected to remain the optional agent and operator control plane. MNCS Fabric is the execution and transport plane. Neither replaces offline MNCS or MNCDS validation.

A Forge provider should invoke the public `mncs_fabric.service.FabricService` boundary for local service operations or `mncs_fabric.api.FabricClient` for declared distributed consumer operations, and retain the returned identities. It should not import private Fabric internals or silently convert missing capabilities into source reading, grep, or a weaker substitute.

Proposed bounded operations:

```text
fabric.nodes
fabric.capabilities
fabric.plan.validate
fabric.dispatch
fabric.status
fabric.collect
fabric.reconcile
fabric.replay
fabric.fault.inject
```

Implemented operations are exposed by `FabricService.nodes`, `capabilities`,
`validate_plan`, `execute_local`, `verify_record`, `collect`, `reconcile`,
`verify_execution_bundle`, and `bind_receipt_to_execution_bundle`. CLI
commands delegate to this boundary. `LocalController.dispatch_via` accepts the
same public transport interface used by `NetworkController`; Forge need not
import private transport or worker modules.

## Project-local Forge workflow

`mncs-forge.toml` declares the required local `mncs-fabric-local` Provider
Protocol 0.1 provider and the `fabric-validation` development workflow. Forge
executes the provider in a bounded copied workspace. The provider runs the
Fabric unit/integration suite, source compilation, the portable example and
reconciliation, receipt, EA-NEXT-002 bundle, and EA-NEXT-005 challenge
compatibility snapshots, bounded
protocol/framing tests, TLS loopback, enrollment/revocation, replay, scheduler,
and storage checks. Forge records the result as operator-controlled development
evidence. It is not independent certification or an MNCS conformance decision.
The two-host harness has static safety coverage in this workflow. When the
sanitized `development-evidence/fedora-two-host-phase1.json` artifact is
present, the provider also runs bounded `two-host-evidence-validation` checks
for schema, identity references, direct-TLS/tunnel declarations,
restart/replay dispositions, revocation disposition, limitations, and secret
exclusion. The provider also validates the bounded persistent-worker evidence
profile when its sanitized record is present. Forge does not impersonate a
remote operator or run a second host; the physical runs remain
operator-controlled. The provider also validates the public contract,
consumer-result/provenance shape, native bundle-transfer/cache tests, and
sanitized native-transfer evidence. Independent certification remains
unsupported.

Resource placement is covered by `fabric-validation` through dependency-free
fixtures for resource snapshots, stale/unknown handling, explicit no-fallback
admission, deterministic identities, and receipt references. The provider
advertises `resource-observation`, `placement-admission`, and
`placement-evidence`; it does not advertise physical CUDA or sequential-
offload evidence where no executable accelerator probe was performed. Physical
resource runs remain optional operator-controlled evidence and are never
required by CI.

The checked-in `development-evidence/fedora-resource-placement.json` is a
bounded direct-mTLS CPU-placement run with native bundle transfer and a
sanitized worker resource snapshot. It records the Quadro P620 as discovery
only (`execution_probe=UNKNOWN`); it is not CUDA or sequential-offload
evidence.
