# Persistent two-host Fabric evidence

Run `persistent-two-host-20260809T164916Z` used Fabric commit
`dcda0f37642b6c0077592ad01cc3b831406591c2` on both Fedora systems.

The worker remained under one PID and one direct mTLS listener while handling
three fresh challenged requests, an idempotent duplicate, a conflicting replay,
and a fourth fresh challenged request. Replacing the worker trust ledger while
the service remained alive caused the next request to fail closed without a
worker restart. Local and remote execution observations reconciled to `PASS`.

The service was explicitly bounded to seven accepted requests, one concurrent
connection, and a 30-second idle timeout. SSH staged code, certificates,
trust state, and the verified portable material; Fabric did not yet transport
the EA-NEXT-002 bundle itself.

This remains operator-controlled development evidence. It does not establish
sandboxing, correctness, custody, independence, conformance, certification,
or independent freshness authority.
