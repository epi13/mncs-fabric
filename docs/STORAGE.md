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

## Ledger compaction

Older controller builds recorded a rendezvous heartbeat entry with a full
embedded worker description on every beat. Long-lived sessions grew
`rendezvous.jsonl` without bound (observed: 1.1 GB / ~200k entries), and
reader caches that retained full history grew resident memory into the
multi-gigabyte range with it. Current builds only record rendezvous
`connected`, `description_changed`, `revoked`, and `disconnected` events,
and `FabricLedger` verifies streams without retaining history.
`description_changed` fires only on material change: change detection
compares a normalized key that ignores sample times, derived identities
that embed those times, and volatile telemetry (available memory, load,
free VRAM). Capability, version, topology-membership, and resource-total
changes still record. Live scheduling always reads the full latest
description from the session.

`FabricLedger.compact(keep=..., reason=...)` reclaims a flooded ledger:
the keep predicate selects retention while streaming, kept records are
rewritten with contiguous sequences and a resealed hash chain (record
bytes and `record_identity` values are unchanged), and a
`ledger.compaction` receipt binding the pre-compact head identity, counts,
and operator reason is appended last. The kept set is capped (`max_kept`)
so compaction itself cannot buffer unbounded history.

`mncs-fabric ledger compact PATH --policy rendezvous-heartbeats --reason
TEXT` drops every heartbeat superseded by a later beat for the same
(worker, session), keeping the newest heartbeat per session plus all
non-heartbeat events. Heartbeat entry identities are never referenced by
other records, and per-worker generation maxima survive on the retained
`connected` and latest-heartbeat records. `--dry-run` compacts a copy and
reports without touching history. Observed production result: 199,649
records / 1.1 GB compacted to 160 records / 884 KB with a PASS verify and
the worker generation maximum intact.

Compaction rewrites entry linkage, so pre-compact `entry_identity` values
are superseded; the receipt's `pre_compact_head` preserves the audit link.
Only entries no other record references may be dropped.
