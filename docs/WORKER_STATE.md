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
or an expired lease. The default description lease is five minutes. Resource-
sensitive scheduling refreshes registered remote workers before admission.
Snapshots are observations, not RAM/VRAM reservations.

There is no unauthenticated discovery, broadcast, filesystem inspection,
remote shell, or general administration operation.
