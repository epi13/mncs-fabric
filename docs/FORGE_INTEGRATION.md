# MNCS Forge integration boundary

MNCS Forge is expected to remain the optional agent and operator control plane. MNCS Fabric is the execution and transport plane. Neither replaces offline MNCS or MNCDS validation.

A Forge provider should invoke the public `mncs_fabric.service.FabricService` boundary or a bounded Fabric CLI operation and retain the returned identities. It should not import private Fabric internals or silently convert missing capabilities into source reading, grep, or a weaker substitute.

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
exclusion. Forge does not impersonate a remote operator or run a second host;
the physical run remains operator-controlled. Bulk bundle transfer and
independent certification remain explicit unsupported constructs.
