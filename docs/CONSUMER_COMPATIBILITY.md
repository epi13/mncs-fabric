# Consumer compatibility notes

This iteration inspected the live consumer worktrees without modifying them:

| Consumer | Commit/branch inspected | Current pressure | Fabric path |
| --- | --- | --- | --- |
| MNEL | `57b07b2d25a8ea9dad93ea396ae5cc0dff7f9f5b`, `agent/distributed-mnel-fabric-08` | low-level controller/transport wiring, consumer-side receipt reconstruction, and pre-staged bundle assumptions | `FabricClient`, `ConsumerContext`, Fabric-generated receipt, native `ensure_bundle` |
| RAVEL | `99d39a1ce184c814a3ae6b15fe52612f6e708d92`, `agent/ravel-forge-world-abi` | RAVEL-owned semantic workload and development evidence need stable Fabric references | same facade; context remains opaque; reconciliation remains Fabric-owned |

Fabric does not special-case either project. `source_project`, workload,
experiment, provider, partition, and Forge workflow values are bounded opaque
references. Fabric does not interpret MNEL provider semantics or RAVEL question,
candidate, promotion, freeze, or adaptation authority.

Migration guidance for consumers:

1. Read and pin `FabricClient.contract()` / `mncs-fabric contract show --json`.
2. Construct a `ConsumerContext` from consumer-owned identities.
3. Use `FabricClient.execute`/`replicate`; do not reconstruct Fabric receipts.
4. Use `RemoteWorkerConfig` rather than assembling TLS transport and trust
   objects for ordinary distributed execution.
5. Use `ensure_bundle` for typed EA-NEXT-002 archives; SSH pre-staging is not
   required for candidate execution material in this path.

Optional live sibling integration remains outside Fabric CI. A missing sibling
is `UNKNOWN`, not a self-contained Fabric failure.

Placement migration: MNEL/RAVEL may translate their own resource budget into
`PlacementRequest` and continue to own provider/runtime decisions. Fabric
returns worker snapshot and admission identities; consumers may attach a
runtime-produced placement observation through the public binding helper.
