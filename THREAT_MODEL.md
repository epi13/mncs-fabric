# Threat model

## Security posture

MNCS Fabric `0.2.0a0` is a bounded execution harness plus an experimental
TLS/mutual-certificate transport foundation, not a hardened hostile-code
sandbox. Only run bundles you are willing to execute under the worker account.
The first direct Fedora-to-Fedora run is recorded as operator-controlled
development evidence; it is not independent assurance.

## Protected assets

- candidate and evaluator identities;
- artifact manifests and job plans;
- raw stdout, stderr, and result identities;
- node and environment observations;
- execution and cohort records; and
- the distinction between operator-controlled and independent evidence.

## Addressed threats

The current implementation detects or bounds:

- source-bundle mutation after manifest creation;
- missing or undeclared extra bundle files;
- symbolic-link path escapes in bundles and results;
- shell interpolation through job argv;
- unbounded execution time;
- unbounded captured stdout and stderr;
- missing declared result artifacts;
- record mutation after identity derivation;
- mixed candidate, evaluator, job, or manifest identities in a cohort; and
- divergent result-artifact identities across hosts.
- duplicate dispatch and conflicting replay in the durable local worker ledger;
- stale, changed-payload, wrong-worker, wrong-job, and unsupported-version protocol messages; and
- deterministic capability mismatch and local admission exhaustion.
- EA-NEXT-002 archive traversal, absolute/drive/UNC paths, Unicode/case
  collisions, duplicate members, special files, expansion limits, canonical
  manifest, entry, logical identity, and exact archive identity checks;
- TLS loopback encryption, CA validation, client-certificate requirement,
  certificate-fingerprint enrollment, logical identity binding, revocation,
  bounded frames, and truncated/oversized/canonical framing rejection; and
- remote worker loss and incomplete replicated responses as explicit `UNKNOWN`.
- scoped EA-NEXT-005 challenge identity, nonce/window copying into receipts,
  single-use replay consumption, and persisted replay-store linkage;

The optional protocol HMAC boundary detects message tampering and unknown or
revoked key IDs. It authenticates canonical contents only; it does not provide
transport encryption, peer enrollment, or independence. TLS protects bytes in
transit and authenticates the enrolled certificate peer; it does not make that
peer independent or honest.

## Residual threats

The current implementation does not prevent:

- a root or administrator replacing the worker, interpreter, kernel, or returned evidence;
- a malicious child process escaping the worker account's ordinary permissions;
- descendant processes surviving termination on every supported platform;
- network access, despite recording the declared network policy;
- timing manipulation or dishonest host facts;
- a controller selectively omitting unfavorable records;
- shared-operator collusion across every machine;
- compromise of GitHub, package distribution, or the development workstation; or
- inference of independence from machine count alone.

The current transport does not provide certificate issuance, automated key
rotation, hardware-backed identity, production listener supervision, bulk
bundle transfer, or cross-host liveness guarantees. The tested endpoint is a
bounded one-request service. The physical run does not remove these residual
limitations.

These gaps must remain explicit `UNKNOWN` or limitations. They must not be rewritten as PASS.

## Remote transport requirements

A network worker must retain:

- mutual authentication and explicit node enrollment;
- replay-resistant job and response identifiers;
- encrypted transport;
- allowlisted controller identities;
- fixed protocol messages rather than remote shell strings;
- job admission limits and concurrency bounds;
- durable append-only local execution records;
- revocation and key rotation; and
- tests for stale, duplicate, reordered, truncated, and substituted messages.

The following explicit threats are modeled but not fully solved by this
iteration:

- network attacker: TLS prevents passive/plaintext transport observation when
  configured correctly; endpoint availability and operator trust remain
  UNKNOWN;
- stolen worker or controller certificate: revocation is operator-managed and
  must be propagated to every trust ledger; a stolen active certificate remains
  trusted until revocation;
- replayed valid TLS request: durable request identity and worker replay state
  prevent duplicate execution, but TLS itself provides no replay semantics;
- replayed valid MNCS challenge: the separate challenge replay ledger rejects a
  consumed challenge, but this remains bounded by the operator-controlled local
  store;
- authenticated malicious worker/controller: Fabric records observations and
  identity mismatches, but cannot make an authenticated peer truthful;
- connection exhaustion, oversized frame, slow sender, dropped connection, and
  bundle substitution: bounded time/frame checks and identity validation fail
  or remain `UNKNOWN`; they do not provide availability;
- DNS/address confusion: current client pins the enrolled certificate
  fingerprint and logical worker, but operators must configure the intended
  address and CA; and
- local root replacing certificate/trust state: out of scope for Fabric’s
  ordinary account controls and remains UNKNOWN.

The boundaries are intentionally separate: TLS protects transport; HMAC
authenticates a message; bundle verification protects package integrity;
receipts record execution observations; and reconciliation compares evidence.
None establishes independent custody, hardware attestation, root-resistant
evidence, MNCS/MNCDS conformance, or certification.

## Reporting

Report security vulnerabilities according to [SECURITY.md](SECURITY.md). Do not publish secrets, private node addresses, authentication keys, or unredacted exploit details in a public issue.
