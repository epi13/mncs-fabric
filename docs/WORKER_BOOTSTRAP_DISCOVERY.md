# Worker bootstrap, discovery, and lifecycle

Status: **Phase A and authenticated worker-initiated rendezvous implemented;
discovery and installed service supervision remain planned**

Implemented in `0.2.0a15`:

- versioned, append-only enrollment authorization, request, decision, fleet
  membership, revocation, and session-presence records;
- hashed short-lived single-use token material with atomic consumption and
  explicit replay/expiry handling;
- strict bounded request validation and exact public-key approval binding;
- durable separation of membership, authenticated presence, liveness,
  capability freshness, and resource freshness;
- controller `status`, `doctor`, and foreground `service run` foundations;
- separate lifecycle and controller-service ledgers;
- atomic session admission, stale-session replacement, generation checks, and
  duplicate-identity evidence; and
- authenticated worker-initiated TLS sessions with bounded heartbeat leases,
  live descriptions, capability/resource observations, and session dispatch;
- a bounded local AF_UNIX consumer/operator service transport with
  `FabricClient.connect()` and explicit `FabricAdminClient` authority.

The controller runtime owns this state independently of Local Harness or any
other consumer process. `FabricClient` remains the ordinary consumer boundary
and retains embedded/in-process compatibility. No Windows service transport,
mDNS/DNS-SD discovery, certificate issuance, installer, or production OS
service is implemented by this phase. The rendezvous and local transports are
deterministic-test verified but not physically verified under systemd, Windows
services, or cross-host deployment.

This document describes a path from Fabric's current explicitly commissioned
multi-host alpha to an operator-controlled fleet that can be installed, enrolled,
and rejoined without manually reproducing SSH, certificate, endpoint, registry,
and service-start steps on every machine.

The goal is not zero-trust-by-magic or autonomous cluster membership. The goal is
**low-friction commissioning with explicit trust**.

The design preserves the existing authority boundaries:

- discovery is not enrollment;
- enrollment is not liveness;
- registry membership is not authorization;
- authentication is not attestation;
- capability observation is not semantic routing;
- Fabric does not grant remote shell or ambient workspace authority; and
- Local Harness or another consumer remains responsible for model choice, agent
  policy, tool meaning, task decomposition, and semantic routing.

MNCS Fabric is intended to become persistent authenticated compute
infrastructure. A configured controller owns fleet lifecycle and worker
presence; Local Harness, Forge, MNCS Control, and other consumers connect through
`FabricClient` and do not own the controller or worker process lifetime.

## Motivation

Fabric already has most of the execution-side substrate needed for a real local
fleet: logical worker identities, mutual TLS, an append-only TrustStore,
revocation, authenticated worker descriptions, resource and capability
observations, liveness, durable worker state, native bundle transfer, a
controller-local worker registry, and physical Fedora/Windows/Linux-ARM evidence.

What remains manual is the **node lifecycle around those primitives**. Adding a
new machine currently tends to involve some combination of:

1. installing Python/Fabric and provider dependencies;
2. arranging SSH or another bootstrap channel;
3. choosing a worker identity and endpoint;
4. provisioning CA/certificate/key material;
5. enrolling the logical identity and certificate fingerprint in TrustStore;
6. creating worker state directories and service arguments;
7. starting or supervising the worker;
8. adding the endpoint and trust references to the controller registry;
9. refreshing worker facts and testing connectivity; and
10. configuring a consumer such as Local Harness to use the registry.

That process is acceptable for proving the transport, but it does not scale to a
household lab, a heterogeneous test cohort, or a future group of machines that
may appear and disappear over time.

The desired operator experience is closer to:

```text
install Fabric worker
        |
        v
find or name controller
        |
        v
present one-time enrollment authorization
        |
        v
controller shows pending worker identity + facts
        |
        v
operator approves
        |
        v
worker receives its credentials and starts/restarts as a service
        |
        v
worker establishes authenticated presence
        |
        v
controller records membership and refreshes capabilities
        |
        v
consumers see the worker through FabricClient
```

A machine becoming easy to add must not make it easy to impersonate.

## Design principles

### 1. Discovery is advisory only

An mDNS advertisement, hostname, DHCP address, LAN scan result, or bootstrap
probe can answer **where might a controller be?** It can never answer **should
this peer be trusted?**

Discovery records are untrusted hints until a cryptographic enrollment flow
binds a logical identity to operator-approved key material.

### 2. Prefer worker-initiated rendezvous

The current direct mode requires a controller to know a worker endpoint and
connect to the worker listener. That mode should remain supported, especially
for controlled test fixtures and explicitly addressed deployments.

For ordinary installed nodes, the preferred future mode should be a
**worker-initiated persistent authenticated session to the controller**.

```text
Current explicit endpoint mode

Controller ------------------------------> Worker listener
          connect(worker_host, worker_port)

Preferred installed-worker mode

Worker service --------------------------> Controller rendezvous
               authenticated session

Controller -------- dispatch/control ----> existing session
Worker     <------- response/evidence ---- existing session
```

This reduces dependence on static worker IP addresses, inbound worker firewall
rules, hostname stability, and manual endpoint maintenance. A worker can reboot,
receive a new DHCP address, reconnect, authenticate as the same logical worker,
and become available again without rewriting its identity.

Worker-initiated rendezvous is **an additional transport/lifecycle mode**, not a
silent reinterpretation of `mncs-fabric.protocol.v0.1` or
`mncs-fabric.worker-registry.v0.1`. Any incompatible wire or registry shape must
receive a new version.

### 3. Private keys remain local

Each node generates its own private key locally. Enrollment transports public
key or certificate-request material, never the worker private key.

Controller private keys likewise remain controller-local. Installers and
registry records must not copy or embed private-key bytes.

### 4. TrustStore stays an authorization ledger, not a CA

`TrustStore` currently records which certificate fingerprint is authorized for
a logical controller or worker identity. That responsibility should remain
narrow.

Certificate issuance belongs to a distinct bootstrap/provisioning component or
an external operator-owned CA. A future built-in helper may sign an approved CSR,
but doing so does not turn TrustStore into certificate-issuance authority.

### 5. Installed service does not imply semantic authority

The worker service reports factual, bounded observations and accepts only Fabric
operations authorized by the existing protocol and consumer policy. Installing a
worker does not grant it permission to choose models, invoke arbitrary MCP
servers, access controller files, or execute arbitrary shell strings.

### 6. Fail closed and preserve UNKNOWN

A failed discovery, stale enrollment token, fingerprint mismatch, expired
certificate, lost session, changed worker identity, missing capability probe, or
registry synchronization failure must remain visible as a denial, `UNKNOWN`, or
other explicit operational state. No bootstrap convenience may silently convert
those conditions into availability.

## Component model

The proposed lifecycle adds four bounded responsibilities around the existing
Fabric execution plane.

```text
                         operator
                            |
                create/approve/revoke
                            |
                            v
+-----------------------------------------------------------+
|                    Fabric controller                       |
|                                                           |
|  bootstrap provisioner   rendezvous service               |
|          |                       |                         |
|          v                       v                         |
|      TrustStore <------ authenticated sessions             |
|          |                       |                         |
|          +------> fleet/registry state                     |
|                                  |                         |
|                                  v                         |
|                             FabricClient                   |
+-----------------------------------------------------------+
                 ^                         |
                 | enrollment              | dispatch/control
                 |                         v
+-----------------------------------------------------------+
|                    installed worker                        |
|                                                           |
| local key + identity   Fabric worker service              |
|          |                     |                           |
|          +---------------------+                           |
|                                |                           |
|             provider-neutral probes/adapters               |
+-----------------------------------------------------------+
```

### Bootstrap provisioner

A narrowly scoped controller-side component should own:

- creating bounded, short-lived, single-use enrollment authorizations;
- receiving a worker enrollment request;
- presenting pending worker facts to the operator;
- binding an approved logical worker identity to presented key material;
- optionally signing an approved CSR using an operator-owned CA;
- recording the resulting certificate fingerprint in TrustStore;
- returning only the worker's approved public certificate chain and controller
  trust material needed for its Fabric role; and
- durable audit records for creation, use, approval, denial, expiration, and
  replay of enrollment authorizations.

The bootstrap endpoint is **not** a general Fabric execution endpoint. Before
worker enrollment it cannot rely on normal worker mTLS identity, so it requires a
separate protocol and a separate threat model. A one-time enrollment secret is
an authorization to request enrollment, not automatic authorization to become an
active worker.

### Rendezvous service

A controller-side rendezvous listener accepts already enrolled worker sessions.
It must:

- require mutual TLS after enrollment;
- validate the certificate against controller trust and active TrustStore state;
- bind the authenticated certificate to the claimed logical worker identity;
- reject unknown, revoked, mismatched, or duplicate/conflicting identities;
- use bounded framing, connection, control, idle, and execution-response limits;
- maintain explicit session identities and reconnect generations;
- expose session loss as liveness loss/`UNKNOWN`, never fabricated completion;
- preserve replay/idempotence protections for dispatch identities; and
- provide no plaintext, HMAC-only, or anonymous execution fallback.

The exact multiplexing shape is an implementation decision. A first version may
allow one in-flight dispatch per worker session to preserve current concurrency
semantics. Later versions may multiplex only after ordering, cancellation,
backpressure, replay, and reconnection behavior are explicitly specified and
tested.

### Installed worker service

The worker package should expose a durable service mode with platform-specific
supervision rather than requiring an interactive terminal to keep Fabric alive.
Its responsibilities are:

- load local worker identity and credential references;
- locate or use an explicitly configured controller;
- establish/re-establish the authenticated session with bounded backoff;
- expose existing Fabric worker execution semantics;
- refresh self-description, resources, runtimes, models, tools, and other
  provider-neutral observations when requested or on bounded lifecycle events;
- retain Fabric-owned append-only local execution/trust state;
- never obtain ambient controller filesystem or shell authority; and
- stop accepting work when its identity, trust, configuration, or service state
  is invalid.

### Fleet/registry state

The existing `worker-registry.v0.1` describes explicit controller-to-worker
endpoints and controller-side key/trust references. Its meaning should remain
unchanged.

Worker-initiated sessions require an additive or new versioned representation.
The controller needs to distinguish at least:

```text
membership: known / pending / revoked
transport mode: explicit-endpoint / rendezvous
presence: connected / disconnected / unknown
identity: worker_id + certificate fingerprint
session: current authenticated connection generation, if any
last contact: bounded operational observation
capability/resource references: current/stale/unknown observations
operator labels: placement/inspection metadata only
```

The durable membership record should not store a transient DHCP address as the
worker's identity. Session endpoint information may be retained as operational
history without becoming authorization.

Consumers should continue to reach workers through `FabricClient`; they should
not need to understand sockets, mDNS, certificate issuance, or bootstrap tokens.

## Worker lifecycle state machine

A useful conceptual state machine is:

```text
UNINSTALLED
    |
    v
INSTALLED_UNCONFIGURED
    |
    +---- explicit controller configuration ----+
    |                                           |
    +---- advisory discovery -------------------+
                                                v
                                         CONTROLLER_SELECTED
                                                |
                                                v
                                        ENROLLMENT_REQUESTED
                                                |
                          +---------------------+------------------+
                          |                     |                  |
                          v                     v                  v
                        DENIED               EXPIRED            PENDING
                                                                    |
                                                          operator approval
                                                                    |
                                                                    v
                                                                 ENROLLED
                                                                    |
                                                              mTLS session
                                                                    |
                                                                    v
                                                              AUTHENTICATED
                                                                    |
                                                         description/resource
                                                               refresh
                                                                    |
                                                                    v
                                                                 AVAILABLE
                                                                    |
                              +----------------------+-------------------------+
                              |                      |                         |
                              v                      v                         v
                         DISCONNECTED              STALE                    REVOKED
                              |                                                |
                           reconnect                                         deny
                              |
                              v
                         AUTHENTICATED
```

`AVAILABLE` is always a current operational conclusion, not a durable trust
property. An enrolled worker can be disconnected, stale, incompatible, or unable
to satisfy a placement request.

## Controller discovery

### Local-network default: mDNS/DNS-SD

For a household or lab LAN, the controller may optionally advertise a service
such as:

```text
_mncs-fabric._tcp.local
```

An advertisement may include bounded, non-secret hints such as:

- display name;
- rendezvous/bootstrap port or service version;
- controller logical identity;
- supported bootstrap protocol version; and
- a public key/certificate fingerprint hint if useful for operator comparison.

The advertisement is untrusted. A malicious host can spoof it. The worker must
verify the controller through enrollment material and TLS before persisting a
trusted controller relationship.

### Explicit endpoint remains first-class

Discovery must never be required. Headless systems, segmented networks, VPNs,
enterprise DNS, test fixtures, and remote deployments should be able to use an
explicit controller URI or configuration file.

Example conceptual flows:

```bash
mncs-fabric worker join --controller fabric-controller.local --token <token>
```

or:

```bash
mncs-fabric worker discover
mncs-fabric worker join --controller <selected-controller> --token <token>
```

### Avoid autonomous LAN scanning as the trust mechanism

An optional operator command may inspect reachable hosts for installation
opportunities in the future, but periodic `/24` scanning should not be Fabric's
membership mechanism. It is brittle across subnets/VLANs and creates the wrong
mental model: network presence is not Fabric identity.

## Enrollment authorization

A practical first enrollment UX is a short-lived single-use token created on the
controller:

```bash
mncs-fabric enrollment create --ttl 10m
```

Conceptually the controller returns:

```text
controller: fabric-controller.local
controller identity: epi13-fabric
bootstrap version: v0.1
controller fingerprint: sha256:...
one-time secret: ...
expires: ...
```

The material could later be represented as a compact join URI or QR code, but the
security semantics are the same.

On the worker:

```bash
mncs-fabric worker join --token <enrollment-material>
```

The worker then:

1. generates a local private key if it does not already have an unbound pending
   identity;
2. connects to the named/discovered bootstrap service;
3. verifies the expected controller key/certificate identity carried by the
   enrollment material;
4. presents the single-use secret plus a bounded enrollment request containing
   logical identity proposal, public-key/CSR material, platform facts, and
   protocol versions;
5. waits in `PENDING` unless policy explicitly permits an operator-created token
   to pre-authorize a specific identity; and
6. persists returned credentials only after approval and validation.

On the controller:

```bash
mncs-fabric enrollment pending
mncs-fabric enrollment approve <request-id> --worker-id <worker-id>
```

The approval view should show enough bounded facts to make accidental approval
less likely, for example hostname hint, operating system, architecture, public
key fingerprint, requested worker ID, discovered source address, and bootstrap
protocol version. These are operator aids, not hardware attestation.

### Token properties

Enrollment authorizations should be:

- cryptographically random;
- bounded in lifetime;
- single use;
- stored hashed when feasible;
- bound to controller identity;
- optionally bound to an expected worker ID or labels;
- consumed atomically;
- replay-detectable through durable state; and
- redacted from normal logs and diagnostics.

A leaked valid token remains a risk until expiration/consumption. Operator
approval and controller fingerprint verification reduce but do not eliminate
that risk.

## Certificate provisioning

The initial implementation can support two modes without changing TrustStore's
meaning.

### External/operator-managed CA

Fabric accepts a CSR/public-key enrollment request, the operator provisions the
certificate externally, and Fabric records the resulting worker certificate
fingerprint. This is the least magical path and preserves today's CA model.

### Bounded built-in provisioning helper

A later bootstrap helper may sign an approved CSR with an explicitly configured
operator-owned Fabric CA key. The CA key must remain separate from registry and
TrustStore state, use restrictive filesystem permissions, and never be sent to a
worker.

In both cases:

```text
certificate issuance != TrustStore authorization
```

TrustStore still records whether the resulting logical identity/fingerprint is
currently active or revoked.

Key rotation should be a separate explicit lifecycle operation. An active
identity must not silently rebind to a new key merely because a machine
reinstalled itself.

## Persistent worker rendezvous

The first authenticated worker-initiated rendezvous transport is now
implemented by `TLSRendezvousServer` and `TLSRendezvousWorker`. A controller
must be configured with the rendezvous listener address and its controller
certificate, key, CA, and worker TrustStore. An installed worker runs:

```text
mncs-fabric worker rendezvous \
  --worker-id <worker-id> --controller-id <controller-id> \
  --controller-host <controller-host> --controller-port <port> \
  --bundle-root <worker-state>/bundles --state <worker-state>/worker.jsonl \
  --trust-state <worker-state>/trust.jsonl \
  --ca <ca.pem> --certificate <worker.pem> --key <worker.key>
```

The session is mutually authenticated, rejects unknown or duplicate logical
identities, persists connect/heartbeat/disconnect observations, and makes the
worker eligible for controller scheduling only while its bounded heartbeat
lease is fresh. Dispatch and bundle transfer use the existing validated Fabric
envelope protocol over the established session. The direct controller-to-
worker registry transport remains available as an explicit compatibility mode.

After enrollment, the installed service should normally dial the controller.

A conceptual session startup is:

```text
worker                                     controller
  |                                             |
  | ---- TCP/TLS connect ---------------------> |
  | <--- controller certificate --------------- |
  | ---- worker certificate ------------------> |
  |                                             |
  |      mutual trust + identity binding        |
  |                                             |
  | ---- session.open(worker_id, versions) ---> |
  | <--- session.accept(session_id, bounds) ----|
  | ---- worker.describe ---------------------> |
  | ---- resource/capability observations ----> |
  |                                             |
  | <--- bounded dispatch --------------------- |
  | ---- execution result/evidence -----------> |
```

The service reconnects after bounded failures with jittered backoff. Reconnect
must not erase the previous immutable session, liveness, dispatch, or failure
history.

A controller may allow only one active rendezvous session for a logical worker
unless an explicit future multi-endpoint identity model is defined. Concurrent
connections claiming the same worker identity should fail closed or require a
deterministic replacement policy with evidence of the transition.

## Registry synchronization

The current manual registry is valuable because it separates known membership
from current availability. Automation should preserve that distinction.

After approved enrollment, the controller may atomically create/update durable
fleet membership. After authenticated rendezvous, it may attach a current
session to that member and refresh operational observations.

The controller must not automatically turn an arbitrary discovered machine into
a registry member. The sequence is:

```text
discovered hint
    -> enrollment request
    -> operator-approved logical identity
    -> TrustStore enrollment
    -> durable fleet membership
    -> authenticated session
    -> current liveness/capability state
```

If the future fleet format replaces or extends `worker-registry.v0.1`, migration
must be explicit. Existing endpoint-mode entries remain valid and retain their
current semantics.

## Installation model

The product surface should feel like one Fabric worker installer with
platform-specific implementation underneath it.

### Common installation responsibilities

An installer should:

1. detect supported OS and architecture;
2. install a pinned/supported Fabric worker runtime;
3. create restricted configuration, state, log, cache, trust, and credential
   directories;
4. create the platform service definition;
5. optionally launch interactive discovery/enrollment;
6. validate service configuration before enabling it;
7. start the service only when it has sufficient configuration to fail safely;
8. run a local doctor/preflight check; and
9. provide an uninstall path that does **not** silently revoke the controller's
   durable identity record.

Uninstalling a worker and revoking a worker are different actions.

### Linux

Target a systemd service for normal Fedora/Raspberry Pi/Linux use, with explicit
support for either system-wide or carefully defined user-service installation.

Conceptual paths:

```text
/etc/mncs-fabric/              configuration/trust references
/var/lib/mncs-fabric/          durable worker state
/var/cache/mncs-fabric/        verified bundle cache
/var/log/mncs-fabric/          service logs if not journal-only
```

The exact filesystem layout should follow distribution conventions and minimize
privilege. Running as root should not be the default merely because systemd owns
the service definition.

### Windows

Install a Windows Service with durable state under a restricted ProgramData
location and explicit service-account behavior. The existing bounded Windows
launcher/preflight work should inform process identity, PID reuse protection,
provider environment preservation, and shutdown behavior.

### macOS and other substrates

A later macOS implementation can use launchd. Other Linux architectures should
reuse the Linux service path when supported. Installer support is a packaging
concern; protocol identity and evidence semantics remain platform-neutral.

## Capability and resource bootstrap

Enrollment may carry only minimal descriptive facts needed by the operator. Full
capability/resource state should be refreshed **after authentication** through
normal Fabric mechanisms.

On first authenticated presence, Fabric should be able to obtain or ingest
bounded facts such as:

- OS and architecture;
- CPU and host memory;
- accelerator identity and memory observations;
- Python/runtime identities;
- provider/runtime availability;
- installed model identities;
- factual loaded/resident model state where supported;
- worker-local tool capability identities; and
- worker-local MCP/service references explicitly configured by the operator.

Those facts remain observations. Fabric does not infer that a discovered GPU is
usable without the corresponding runtime evidence, that an installed model is
semantically appropriate for a task, or that a tool should be invoked.

A consumer such as Local Harness can react to the refreshed fleet through
`FabricClient` while preserving the current authority split:

```text
Fabric: "worker X is authenticated; these are its current observed facts"
Harness: "given my semantic policy, model residency policy, and task, use X"
```

## Operator CLI surface

Names are illustrative, but the lifecycle should be inspectable from a coherent
CLI rather than hidden side effects.

Controller examples:

```bash
mncs-fabric fleet list
mncs-fabric fleet status <worker-id>
mncs-fabric enrollment create --ttl 10m
mncs-fabric enrollment pending
mncs-fabric enrollment approve <request-id> --worker-id <worker-id>
mncs-fabric enrollment deny <request-id>
mncs-fabric worker revoke <worker-id> --reason "..."
mncs-fabric fleet doctor
```

Worker examples:

```bash
mncs-fabric worker install
mncs-fabric worker discover
mncs-fabric worker join --token <token-or-join-uri>
mncs-fabric worker status
mncs-fabric worker doctor
mncs-fabric worker service start
mncs-fabric worker service stop
mncs-fabric worker uninstall
```

A future Local Harness fleet view can remain consumer-facing:

```bash
elh fabric workers
elh fabric refresh
elh models --worker <worker-id>
elh residency status
```

Harness should not duplicate Fabric enrollment or certificate lifecycle.

## Optional controller-driven bootstrap

Once local installation is reliable, Fabric may add an **operator-invoked**
bootstrap convenience for machines where the operator already has SSH/WinRM or
another administrative channel.

Example concept:

```text
mncs-fabric bootstrap inspect <explicit-host>
mncs-fabric bootstrap install <explicit-host>
```

or a bounded discovery command that merely lists possible installation targets.

This path must remain distinct from Fabric execution:

- SSH/WinRM is an installer/bootstrap channel only;
- host verification is strict;
- credentials are operator supplied and not retained as Fabric execution
  authority;
- candidate bundles still use Fabric's native verified transfer path;
- failure never falls back to ambient remote shell for a Fabric job; and
- Fabric never silently installs itself onto discovered hosts.

## Security and threat-model additions

The lifecycle introduces threats beyond the current explicitly configured
endpoint model.

### Discovery spoofing

An attacker may advertise a fake `_mncs-fabric._tcp` service. Mitigation:
discovery is advisory; enrollment material pins/verifies the intended controller
identity before durable trust is written.

### Enrollment-token theft or replay

A leaked token may be used by the wrong machine. Mitigations include short TTL,
single use, random entropy, hashed durable token state, operator approval,
optional expected worker binding, atomic consumption, and replay evidence.

### Unauthorized auto-enrollment

Discovery must never cause automatic TrustStore enrollment. Default behavior
requires explicit operator approval unless the operator deliberately creates a
pre-bound enrollment authorization whose semantics are equally explicit.

### Bootstrap service exposure

The bootstrap listener must be narrowly typed, rate/size/time bounded, and
separate from execution. It cannot accept arbitrary commands or Fabric jobs from
an unenrolled peer.

### Key exfiltration

Installers must never transmit generated private keys. Private credentials must
be stored with restrictive local permissions and excluded/redacted from logs,
registry exports, diagnostics, and support bundles.

### Identity takeover after reinstall

A machine presenting a new key for an existing active worker ID must not be
silently accepted. Replacement requires explicit rotation/recommissioning or
revocation of the old binding.

### Duplicate authenticated presence

Two sessions claiming one logical worker ID can indicate a stale service,
cloned credentials, or compromise. The controller must use an explicit bounded
policy and record the conflict; it must not nondeterministically dispatch across
both as if they were one worker.

### Rendezvous denial of service

Persistent sessions add connection and idle-resource pressure. The controller
needs bounded connection counts, handshake deadlines, authenticated admission,
per-worker/session limits, backpressure, and explicit overload outcomes.

### Stale session/capability confusion

Reconnect does not make old observations current. Session generation, liveness,
capability freshness, and resource freshness remain separately bounded.

### Malicious authenticated worker

Nothing in automated installation or rendezvous makes worker self-description
truthful. Authentication proves possession of approved identity credentials,
not hardware integrity or honest execution.

## Compatibility requirements

Implementation must preserve these compatibility rules:

1. `mncs-fabric.protocol.v0.1` meaning is immutable. Introduce a new/additive
   protocol version if rendezvous requires incompatible envelope behavior.
2. `mncs-fabric.worker-registry.v0.1` continues to mean explicit known worker
   endpoints with controller-side trust references. Do not reinterpret it as a
   rendezvous/fleet schema.
3. Direct controller-to-worker mTLS remains supported during migration and for
   explicit deployments.
4. TrustStore enrollment/revocation semantics remain fail-closed.
5. FabricClient remains the ordinary consumer API; consumers do not acquire
   bootstrap secrets or transport authority.
6. No new lifecycle path may enable arbitrary shell or ambient SSH execution.

## Delivery phases

### Phase A — lifecycle contracts and durable state

- freeze terminology and state transitions;
- define versioned enrollment-request and enrollment-decision records;
- define durable single-use enrollment authorization/replay state;
- define a versioned fleet membership/session representation without changing
  registry v0.1 meaning;
- define controller/worker configuration paths and secret-redaction rules; and
- add threat-model fixtures for spoofing, replay, replacement, and duplicate
  identity cases.

Acceptance: lifecycle state can be tested entirely in-process with deterministic
records and no network discovery dependency.

### Phase B — worker service supervision

- production-shaped Linux systemd worker service;
- Windows Service packaging using the existing bounded lifecycle lessons;
- durable reconnect configuration;
- service `status`/`doctor` commands;
- clean startup/shutdown and bounded backoff; and
- packaging/version compatibility diagnostics.

Acceptance: a previously enrolled worker survives reboot and returns to an
explicit controller without manual terminal startup.

### Phase C — authenticated worker-initiated rendezvous

- controller rendezvous listener;
- mutual TLS worker-initiated sessions;
- session identity/generation and duplicate presence handling;
- bounded dispatch over established sessions;
- liveness and reconnection evidence;
- registry/fleet presence integration; and
- adversarial transport tests.

Acceptance: a worker can change DHCP address, reconnect as the same logical
identity, refresh facts, receive bounded work, and leave no fabricated result
when connectivity is lost.

### Phase D — enrollment provisioning

- short-lived single-use enrollment authorization;
- pending/approve/deny flow;
- local worker key generation;
- CSR/public-key binding;
- external CA path first, optional bounded signing helper later;
- automatic TrustStore + fleet membership update after approval; and
- replay/expiration/identity-replacement tests.

Acceptance: a fresh machine can become an authenticated worker without manually
copying controller private keys or editing registry JSON.

### Phase E — local controller discovery

- optional mDNS/DNS-SD advertisement and lookup;
- explicit endpoint fallback;
- controller fingerprint verification from enrollment material;
- spoofed-advertisement tests; and
- multiple-controller selection UX.

Acceptance: a worker on the same LAN can find a candidate controller, but cannot
become trusted or execute work solely because discovery succeeded.

### Phase F — cross-platform installer UX

- Linux installer/uninstaller;
- Windows installer/uninstaller;
- Raspberry Pi/ARM validation through the Linux path;
- upgrade compatibility checks;
- first-run join flow; and
- end-to-end physical commissioning evidence.

Acceptance: adding a new supported Fedora/Windows/ARM machine requires installation,
one explicit enrollment action, and controller approval—not manual certificate,
service, endpoint, and registry assembly.

### Phase G — optional remote bootstrap convenience

- strict explicit-host SSH bootstrap for Linux;
- optional Windows administrative bootstrap only if it can preserve equivalent
  host/credential constraints;
- no background network installation;
- no execution fallback to bootstrap channels; and
- operator-visible evidence of what was installed and configured.

This phase is convenience, not a prerequisite for a self-forming authenticated
fleet.

## End-state operator experience

The intended local-lab experience is:

```text
New machine boots
    |
Fabric worker package is installed
    |
worker discovers or is told about controller
    |
operator supplies one-time enrollment authorization
    |
controller shows pending identity
    |
operator approves
    |
worker service receives its public credentials and connects outward
    |
Fabric records authenticated presence and current observations
    |
Harness/Forge/other consumers see the node through FabricClient
```

After that first commissioning, ordinary reboot/reconnect should be automatic.
Turning a known machine on or off should change liveness and capability state,
not require the operator to reconstruct the network.

That is the target distinction:

> Fabric should evolve from a set of manually commissioned remote endpoints into
> a dynamic pool of **explicitly enrolled, authenticated, observable compute
> resources**—without confusing dynamic presence with automatic trust.
