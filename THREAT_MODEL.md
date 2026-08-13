# Threat model

## Security posture

MNCS Fabric `0.2.0a16` is a bounded execution harness plus an experimental
TLS/mutual-certificate transport foundation, not a hardened hostile-code
sandbox. Only run bundles you are willing to execute under the worker account.
The first direct Fedora-to-Fedora run is recorded as operator-controlled
development evidence; it is not independent assurance.

The public consumer facade accepts opaque provenance only. A consumer may lie
about its semantic workload identity; Fabric can bind the supplied reference
but cannot establish its truth. Public-contract drift is rejected by identity
validation rather than silently accepted.

Native bundle transfer adds bounded chunk flooding, partial-transfer
accumulation, cache exhaustion/corruption, archive substitution, and stale
capability observations to the threat surface. Transfer is typed, size-bounded,
sequenced, independently verified by the worker, and atomically published;
partial material is unavailable to execution. These controls protect package
integrity and protocol state, not execution isolation or worker honesty.

Worker self-description adds an authenticated but worker-reported view of
capabilities, resources, and service references. Authentication binds the
report to an enrolled logical worker; it is not attestation or independent
observation. The controller keeps every description/resource snapshot as
immutable history and expires availability after a bounded lease.

Worker capability observations add consumer-normalized model/runtime/tool/MCP/service
facts. Fabric binds them to exactly one registered worker, rejects unsupported or
oversized metadata, and retains history in its append-only ledger. Freshness and
worker liveness are evaluated separately: retained evidence cannot remain a current
availability claim after expiry or worker loss. Capability presence never grants
execution, workspace, filesystem, shell, SSH, MCP, or semantic routing authority.

Resource placement adds consumer context and dynamic capacity to the protocol.
Fabric rejects malformed or substituted placement requests and binds the
resource snapshot and admission decision into the dispatch/receipt reference.
It does not make a consumer's model-size or offload declaration true, and it
does not make a worker's free RAM, VRAM, driver, or runtime report truthful.
Accelerator discovery is separate from executable-kernel proof; the current
dependency-free probe reports NVIDIA discovery as UNKNOWN when `nvidia-smi`
or a real runtime probe is unavailable.

Runtime profiles add a second boundary: a machine GPU, an NVIDIA driver,
`nvidia-smi`, and the Python environment that launches Fabric are distinct
claims. The optional runtime probe is operator-controlled input. A real
synchronized kernel is required before its execution status is `PASS`, but
the resulting record is still not hardware attestation. Runtime-profile
replacement, driver changes, Python-environment drift, stale probe evidence,
Torch architecture incompatibility, Windows PID reuse, path/case collisions,
and launcher attempts to stop an unrelated process are explicitly considered.

The Linux/ARM preflight adds no discovery or trust shortcut. It requires an
explicit operator endpoint, strict known-host verification, and public-key-only
SSH. A host-key entry without a usable account/key mapping is an UNKNOWN
bootstrap result. An explicitly named OpenSSH alias may supply the configured
user, key, proxy, or agent path; the helper retains only bounded effective
endpoint facts and never stores private key or agent material. The native
Linux/ARM harness uses SSH only for source, certificate, trust, and worker
lifecycle bootstrap; candidate execution material remains on the Fabric
bundle-transfer path.

### Worker bootstrap and rendezvous boundary

The proposed [worker bootstrap, discovery, and lifecycle](docs/WORKER_BOOTSTRAP_DISCOVERY.md)
adds an installation/enrollment plane around the existing execution plane. It does not
make LAN presence, mDNS, a hostname, an IP address, an installer, or an enrollment
request authoritative. Discovery is advisory; durable worker trust still requires an
operator-approved cryptographic binding between logical worker identity and key
material.

The implemented opt-in topology adds worker-initiated persistent rendezvous to
the controller while retaining current explicit controller-to-worker endpoint mode.
Rendezvous must use mutual TLS after enrollment, bind the worker certificate to active
TrustStore state, preserve replay and bounded framing semantics, distinguish session
presence from durable membership, and expose loss/reconnect as operational evidence
rather than silently carrying old liveness or capability observations forward.

Pre-enrollment bootstrap cannot rely on an already enrolled worker certificate, so it
requires a separate narrow protocol and threat surface. Short-lived single-use
bootstrap authorization, controller identity pinning/verification, explicit operator
approval, bounded request shapes, replay state, rate/time/size limits, and local worker
private-key generation are required before this can be treated as a supported
commissioning path. The bootstrap service must never accept Fabric jobs, arbitrary
commands, or remote shell requests from an unenrolled peer.

TrustStore remains an authorization ledger rather than a certificate authority.
Certificate issuance may use an external operator-managed CA or a separate bounded
provisioning helper, but CA private keys must never be embedded in worker installers,
registry records, enrollment tokens, diagnostics, or remote state.

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
- placement-request substitution, stale/unknown resource snapshots,
  unsupported precision, insufficient host/accelerator memory, and explicit
  no-fallback admission behavior;
- EA-NEXT-002 archive traversal, absolute/drive/UNC paths, Unicode/case
  collisions, duplicate members, special files, expansion limits, canonical
  manifest, entry, logical identity, and exact archive identity checks;
- local-service bundle requests that attempt to make the controller open a
  consumer-chosen pathname; the client instead transfers bounded verified chunks
  and dispatches by identities resolved only inside the controller-owned cache;
- TLS loopback encryption, CA validation, client-certificate requirement,
  certificate-fingerprint enrollment, logical identity binding, revocation,
  bounded frames, and truncated/oversized/canonical framing rejection; and
- remote worker loss and incomplete replicated responses as explicit `UNKNOWN`.
- wrong-worker capability substitution, stale/future capability observations,
  malformed names, nested/unbounded metadata, and false-current inventory after
  worker loss or a failed replacement scan;
- worker-description substitution, wrong-worker resource binding, stale
  descriptions, expired liveness, and scheduling from an exact retained
  observation;
- missing work items, exact duplicate collection results, and conflicting
  duplicate results with `UNKNOWN`/`FAIL` dominance; and
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
- consumer lies about model/workspace sizes or sequential-offload support;
- resource exhaustion, VRAM/RAM changes between admission and execution,
  CUDA architecture/kernel incompatibility, and placement-observation
  substitution;
- authenticated malicious workers can lie about capabilities, resources,
  liveness, or service version; Fabric records the claim but cannot establish
  its truth;
- an authenticated consumer can normalize dishonest provider output before
  capability ingestion; the observation source and non-attestation boundary retain
  that limitation but cannot independently detect the lie;
- description/resource TOCTOU remains because observations are not locks or
  hardware reservations; and
- a consumer can lie about the meaning of a work-item or partition identity;
  Fabric only preserves the opaque reference;
- a controller selectively omitting unfavorable records;
- shared-operator collusion across every machine;
- compromise of GitHub, package distribution, or the development workstation; or
- inference of independence from machine count alone.

The current transport does not provide certificate issuance, automated key
rotation, hardware-backed identity, production listener supervision, or
cross-host liveness guarantees. Native bundle transfer is bounded and
experimental; it does not provide a general package registry or delivery
guarantee. The worker now has an
experimental bounded persistent mode, but this is not production supervision
or unlimited daemon operation. The physical run does not remove these
residual limitations.

Phase A of the lifecycle is implemented as controller-local append-only state.
Authenticated worker-initiated rendezvous, bounded reconnect/session handling,
worker observations, and controller-owned service dispatch are implemented and
covered by deterministic integration tests when explicitly configured. No automated
commissioning or physical systemd/reboot claim is made: the implementation does not
discover controllers or issue certificates. The foreground controller runtime owns
lifecycle and worker state independently of consumers; the embedded `FabricClient`
path remains a compatibility mode.

The experimental persistent-controller transport is local-only on POSIX. It uses
separate restrictive AF_UNIX consumer and operator sockets, peer-UID checks,
bounded canonical frames, request deadlines, service-ledger replay rejection,
and an exclusive controller-state lock. Socket parents and stale endpoints are
checked for symlink, ownership, type, and unsafe-permission conditions. The
operator socket is an explicit local administrative boundary, not an anonymous
LAN API; a same-account local compromise remains able to act as that operator.
Malformed, oversized, truncated, expired, replayed, or unauthorized requests
fail closed. The service ledger is separate from the lifecycle ledger so service
events cannot make lifecycle projections unreadable.

Phase A mitigations include hashed one-time enrollment tokens with atomic
consumption, bounded exact-field requests, immutable decision records, exact
public-key binding, durable active-identity rebind rejection, explicit fleet
revocation, session generation checks, and deterministic duplicate-session
`DUPLICATE_IDENTITY` state. Lifecycle diagnostics omit raw tokens and private key
material. Controller status/doctor does not expose a LAN administrative listener.
The consumer service boundary carries bounded dispatch only when the running
controller has a configured worker backend. Rendezvous is authenticated on its
separate worker-facing mTLS listener and is projected to consumers only while that
listener is running. Neither feature grants administrative authority to consumers.

Remaining service threats include controller daemon compromise, unauthorized local
clients, restart/reconnect storms, and state corruption/recovery. They remain
bounded by local filesystem permissions and ledger corruption diagnostics but are
not solved by this phase. Worker presence is never inferred from controller health
or consumer connection state.

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

Further bootstrap/rendezvous work must retain:

- discovery that is advisory only and cannot create TrustStore authority;
- cryptographic verification of the selected controller before durable worker trust;
- short-lived, single-use enrollment authorization with durable replay handling;
- explicit approval or equivalently explicit pre-bound operator authorization;
- local-only private-key generation and secret-redacted diagnostics;
- rejection of silent active-identity rebinding after reinstall or key replacement;
- deterministic handling of duplicate sessions claiming one logical worker identity;
- distinct durable membership, current session presence, liveness, capability freshness,
  and resource freshness;
- bounded rendezvous connection counts, handshakes, idle periods, reconnect behavior,
  and backpressure; and
- no fallback from failed Fabric connectivity to SSH, WinRM, shell, or anonymous
  execution.

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
- persistent trust revocation: the worker reloads its append-only trust ledger
  before each request, so an operator-revoked controller certificate is
  rejected between requests; replacing the local trust state remains an
  operator trust assumption;
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
- resource reservations: Fabric does not reserve VRAM or host RAM; concurrent
  accelerator workloads can invalidate an otherwise fresh admission.
- runtime proof can become stale when the worker interpreter, Torch/CUDA
  versions, driver, or GPU identity changes; Fabric does not install or manage
  those environments;
- Windows worker lifecycle state can be lost or become stale, although the
  launcher binds stop operations to a recorded process-start token; and
- `nvidia-smi` discovery and `torch.cuda.is_available()` are insufficient proof
  of executable CUDA kernels.
- consumer-declared sequential-offload support is not proof that the provider
  runtime can execute it;
- runtime-capability evidence can be substituted, become stale, or describe a
  different Torch/Accelerate environment unless its profile and environment
  identities are checked; and
- the Windows bounded child environment must preserve only the platform
  identity variables needed by the provider runtime; broad environment
  inheritance would weaken the execution boundary.

For the proposed lifecycle specifically, additional modeled threats include:

- spoofed mDNS/DNS-SD advertisements selecting an attacker-controlled bootstrap
  endpoint before controller fingerprint verification;
- stolen, guessed, logged, or replayed enrollment authorization;
- an enrollment request racing the intended worker and consuming a one-time token;
- an operator approving misleading hostname/platform hints that are not attested facts;
- a cloned worker credential creating simultaneous authenticated presence;
- a reinstalled worker attempting to take over an existing logical identity with a new
  key;
- reconnect storms exhausting controller handshake/session capacity;
- a disconnected session leaving stale observations incorrectly visible as current;
- bootstrap/provisioning code accidentally gaining execution-plane command authority;
  and
- an installer or support bundle leaking worker, controller, token, or CA private
  material.

The design requires explicit mitigations and adversarial tests for these cases before
automated commissioning can be treated as more than experimental convenience.

The boundaries are intentionally separate: TLS protects transport; HMAC
authenticates a message; bundle verification protects package integrity;
receipts record execution observations; and reconciliation compares evidence.
Discovery locates candidates; enrollment authorizes an identity binding; neither makes
a worker honest or independent. None establishes independent custody, hardware
attestation, root-resistant evidence, MNCS/MNCDS conformance, or certification.

## Reporting

Report security vulnerabilities according to [SECURITY.md](SECURITY.md). Do not publish secrets, private node addresses, authentication keys, or unredacted exploit details in a public issue.
