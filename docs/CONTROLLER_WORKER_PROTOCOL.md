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

The current transport is deliberately in-process. Fabric does not open a
network listener, provide an unauthenticated fallback, or claim encrypted
transport. HMAC authenticates message contents only. A later network transport
requires mutually authenticated encrypted transport, enrollment, rotation,
revocation, and real second-host tests.

Dispatch payloads contain a validated fixed argv job plan and a verified
content-addressed manifest identity. They do not contain arbitrary shell
commands. A duplicate request with the same request identity is idempotent;
the same request ID bound to a different dispatch is `CONFLICTING_REPLAY`.
