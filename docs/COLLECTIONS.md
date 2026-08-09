# Generic execution collections

Fabric provides two domain-neutral additive records:

- `mncs-fabric.work-item.v0.1` identifies one declared job/partition binding;
- `mncs-fabric.execution-collection.v0.1` records assignments and returned
  Fabric record/receipt identities.

Fabric does not interpret a partition as a training shard, RAVEL trial, or
semantic evaluator unit. The consumer owns that meaning and aggregation.

An undeclared item is rejected, a missing declared item makes the collection
`UNKNOWN`, an exact duplicate is classified `DUPLICATE_IDEMPOTENT`, and
different records for one item are `CONFLICTING_DUPLICATE` and make the
collection `FAIL`. `FabricClient.collect_work_items()` and
`verify_collection()` are the public operations.
