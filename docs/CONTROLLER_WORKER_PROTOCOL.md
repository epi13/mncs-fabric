# Controller/worker protocol foundation

Implemented in this iteration:

- versioned canonical envelopes (`mncs-fabric.protocol.v0.1`);
- fixed message types and validated job-plan/artifact bindings;
- optional operator-supplied HMAC-SHA256 authentication with key IDs and
  revocation/activation state;
- in-process controller and worker services;
- durable dispatch/result publication before duplicate retries are answered;
- stale, changed-payload, wrong-worker, wrong-job, and conflicting-replay
  rejection; and
- deterministic capability-aware local admission.

The protocol is transport-independent. `InProcessTransport` preserves local
behavior, while `TLSNetworkTransport` and `TLSWorkerServer` move one bounded
canonical envelope per mutually authenticated TLS connection. TLS 1.2+
certificate verification, enrolled certificate fingerprints, explicit logical
controller/worker IDs, bounded framing, and timeouts are required. There is no
plaintext or HMAC-only remote fallback. HMAC remains a separate optional
message-authentication facility; it is not encryption.

Additive management messages in the same protocol version are
`worker.inventory.request/result`, `worker.maintenance.request/result`,
`worker.certify.request/result`, and `worker.management.request/result`.
They carry typed inventory, actions, certification, and drain/resume commands.
They do not carry a shell string.

Dispatch payloads contain a validated fixed argv job plan and a verified
content-addressed manifest identity. They do not contain arbitrary shell
commands. A duplicate request with the same request identity is idempotent;
the same request ID bound to a different dispatch is `CONFLICTING_REPLAY`.

`TrustStore` is an operator-managed append-only enrollment/revocation ledger,
not a public CA. Unknown, revoked, mismatched, or substituted certificate
identities fail closed. The worker endpoint may run in conservative one-request
mode or an explicitly bounded persistent mode. The public `FabricClient` can
transfer an EA-NEXT-002 archive through bounded `bundle.offer`, `bundle.chunk`,
and `bundle.commit` messages; the worker independently verifies it and
publishes an immutable cache entry before execution. SSH remains bootstrap
only in the native-transfer path.

An optional `execution_challenge` dispatch field uses the current MNCS
EA-NEXT-005 experimental shape. It is not a replacement for the protocol
nonce/request replay layer: the challenge binds freshness scope and is consumed
separately by the controller's local replay store.
