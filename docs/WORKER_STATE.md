# Worker description, refresh, and liveness

`worker.describe.request` and `worker.describe.result` are additive message
types in `mncs-fabric.protocol.v0.1`. They use the existing mutual TLS and
logical worker enrollment boundary. A description contains a validated node
capability record, a current resource snapshot, worker service/protocol and
public-contract references, capture time, and `description_identity`.

The facts are worker-observed reports. Authentication proves which enrolled
worker sent them; it does not prove that the worker is honest, that hardware
exists, or that a runtime satisfies consumer semantics.

`FabricClient.refresh_worker(worker_id)` requests a fresh description and
stores it as an immutable controller-ledger observation. Older descriptions
and snapshots are never edited. `FabricClient.workers()` reports current
description/liveness references without exposing controller internals.

Availability is bounded: `AVAILABLE` means recent authenticated contact,
`UNAVAILABLE` records a failed contact, and `UNKNOWN` means no current contact
or an expired lease. A refresh `TIMEOUT` is not unavailability: the last-known
state is retained and the probe is classified separately. Capability inventory
`STALE` means the worker is reachable (or was) but the model/capability
observation is older than its lease; it is not a contact failure.
`worker_service_version` and `description_captured_at` are projected from the
worker description so an operator can verify the process that answered describe.
The default description lease is five minutes. Resource-
Sensitive scheduling refreshes registered remote workers before admission. A
description older than the five-minute description bound is retained as
history but cannot restore `AVAILABLE`; it produces `UNKNOWN` until a fresh
description arrives. After a controller restart, last-known descriptions are
restored from the network ledger before the first explicit refresh.
Snapshots are observations, not RAM/VRAM reservations.

There is no unauthenticated discovery, broadcast, filesystem inspection,
remote shell, or general administration operation.

Management state is a separate, controller-owned lifecycle
(`READY`/`BUSY`/`DRAINING`/`MAINTENANCE`/`VERIFYING`/`DEGRADED`/`QUARANTINED`).
It does not replace liveness. A `TIMEOUT` refresh is still not unavailability.
A quarantined or maintenance worker is not schedulable even if liveness is
`AVAILABLE`. See [Fleet management](FLEET_MANAGEMENT.md).
