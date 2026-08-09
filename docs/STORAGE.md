# Fabric local ledger

`mncs_fabric.store.FabricLedger` is a Fabric-owned append-only JSONL ledger.
Each entry binds a schema version, sequence, previous entry identity, record
identity, and entry identity. Appends use a platform-specific exclusive lock,
flush, and `fsync`; reads are bounded and verify the full hash chain.

Startup and reads do not silently repair history. A malformed complete line,
future schema version, invalid record identity, or broken linkage raises a
storage error. A truncated tail is diagnosed as `TRUNCATED_TAIL` and may only
be removed by an explicit `recover(repair_truncated_tail=True)` call. Immutable
historical records are never rewritten.

This is local operator-controlled durability, not protected custody or an
external witness.
