# MNCS Forge integration boundary

MNCS Forge is expected to remain the optional agent and operator control plane. MNCS Fabric is the execution and transport plane. Neither replaces offline MNCS or MNCDS validation.

A future Forge provider should invoke a bounded Fabric CLI or protocol operation and retain the returned identities. It should not import private Fabric internals or silently convert missing capabilities into source reading, grep, or a weaker substitute.

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

Only the local equivalents of node inspection, plan validation, execution, collection, and reconciliation exist in 0.1. Remote dispatch and fault injection remain future work.
