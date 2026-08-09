# Threat model

## Security posture

MNCS Fabric `0.2.0a0` is a bounded execution harness and in-process protocol foundation, not a hardened hostile-code sandbox. Only run bundles you are willing to execute under the worker account.

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

The optional protocol HMAC boundary detects message tampering and unknown or
revoked key IDs. It authenticates canonical contents only; it does not provide
transport encryption, peer enrollment, or independence.

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

The current controller/worker implementation also does not provide a remote
listener, TLS, certificate provisioning, key rotation distribution, or
cross-host liveness guarantees. It is intentionally limited to in-process
execution until those controls and adversarial second-host tests exist.

These gaps must remain explicit `UNKNOWN` or limitations. They must not be rewritten as PASS.

## Remote transport requirements

A network worker must not be added until the protocol includes:

- mutual authentication and explicit node enrollment;
- replay-resistant job and response identifiers;
- encrypted transport;
- allowlisted controller identities;
- fixed protocol messages rather than remote shell strings;
- job admission limits and concurrency bounds;
- durable append-only local execution records;
- revocation and key rotation; and
- tests for stale, duplicate, reordered, truncated, and substituted messages.

## Reporting

Report security vulnerabilities according to [SECURITY.md](SECURITY.md). Do not publish secrets, private node addresses, authentication keys, or unredacted exploit details in a public issue.
