# Capability-aware scheduling

Fabric resolves eligibility *before* execution. A workload declares what
it requires; each worker carries observed capabilities, a classified
environment, declared policy, liveness, and observation freshness; the
scheduler admits only workers that satisfy all of them. When none
qualify, the result is `NO_ELIGIBLE_WORKER` with per-worker
machine-readable reasons — a first-class scheduling outcome, not a
generic execution failure.

```text
MNCS workload
 ↓
derive required capabilities
 ↓
query Fabric worker capability graph
 ↓
determine eligible workers
 ↓
select worker according to policy
 ↓
execute
 ↓
return evidence
```

## Source of truth

The decision relation is owned by MNCS source:

- `library/std/platform.mncs` (`mncs.std.platform.v1`, in mncs-language)
  owns reusable environment matching: OS, architecture (including the
  emulation path), libc, CUDA compute floors, eBPF/WASM/PTX flags, and
  resource bounds. Proven across all five executable backends by
  `examples/execution/platform-capability-corpus.json`.
- `mncs/worker_capability.mncs` (`fabric.worker_capability`) owns
  resolution ordering: liveness → freshness → provenance → environment →
  policy/intent, plus the reason codes. Proven by
  `mncs/worker_capability_corpus.json` (84 exhaustive cases).

The Python runtime (`src/mncs_fabric/capability_resolution.py`) mirrors
those arms exactly; `tests/test_mncs_capability_policy.py` pins every
arm mechanically so the two cannot drift. Add a decision arm to the
`.mncs` first, extend the corpus, then mirror it — never the reverse.

## Observed capability vs declared policy

Fabric keeps these strictly separate:

- **Observed capability** is worker-observed fact: OS, kernel,
  architecture, libc, init, shells, CPU, RAM, GPU/CUDA compute, eBPF/BTF,
  WASM runtimes, compilers, emulation. Collected by bounded probes
  (`src/mncs_fabric/platform_probe.py`, no shell, short timeouts) and
  carried on the node record's `platform` section plus capability tokens
  (`libc:gnu`, `init:systemd`, `accel:cuda`, `cuda:compute-6-1`,
  `kernel:ebpf`, `runtime:wasm`, `compiler:ptx`, `shell:bash`,
  `emulation:riscv64`, ...).
- **Declared policy** is operator configuration, never inferred: the
  `experimental` role, `disposable` lifetime, and the `allow_root_mutation`,
  `allow_reboot`, `allow_toolchain_install` permissions, plus
  `resource_constrained`. Declared via
  `LocalController.set_worker_policy` (persisted to the controller
  ledger); workers without an entry resolve under the stable reference
  policy where every permission is denied. That `sudo` happens to work
  proves nothing — authorization is declared or it does not exist.

Provenance has three classes: `worker-observed` and `operator-asserted`
prove capability for admission; `consumer-declared` never does
(`PROVENANCE_UNVERIFIED`).

## Workload requirements

`CapabilityQuery` (`capability_resolution.py`) expresses, in capability
vocabulary rather than hostnames:

- `require_all`: every token must hold (`os:linux`, `kernel:ebpf`);
- `require_any`: alternative groups, each needing one token (native
  RISC-V *or* declared emulation);
- `forbid`: tokens that must not hold (a production workload forbidding
  `policy:disposable`);
- `prefer`: ranking only — never promotes an ineligible worker (a musl
  test preferring `libc:musl`);
- `req_env`: structured floors the token set cannot express — CUDA
  compute minimum, eBPF/WASM/PTX flags, architecture with an explicit
  emulation permission, memory/CPU minimums;
- `intent`: `normal`, `mutating` (toolchain install, system modification,
  reboot), or `privileged` (root-level mutation).

`schedule()` derives `require_all` from the job plan and additionally
accepts `intent`, `prefer`, and a full `query` (unioned with the plan).
`dispatch`/`dispatch_remote` accept `intent`.

## Resolution order and reason codes

`resolve_code` evaluates in a fixed, pinned order — each stage answers
one question and later stages never re-decide earlier ones, so every
rejection names exactly one cause:

| Order | Check | Code when failing |
| --- | --- | --- |
| 1 | liveness | `WORKER_UNAVAILABLE`, `WORKER_DISCONNECTED` |
| 2 | freshness (300 s bound; `None` = derived live) | `WORKER_STALE` |
| 3 | provenance trusted | `PROVENANCE_UNVERIFIED` |
| 4 | environment + tokens | `CAPABILITY_UNSATISFIED`, `TOOLCHAIN_MISSING`, `RUNTIME_MISSING` |
| 5 | intent vs declared policy | `POLICY_DENIED` |

`resolve_fleet` aggregates per-worker resolutions. With no eligible
worker the verdict is `NO_ELIGIBLE_WORKER` carrying every worker's code
and `missing` list. Selection among eligible workers is deterministic
and name-free: more `prefer` hits first, then non-resource-constrained,
then lexicographic id. Experimental status alone never wins selection;
intent gating already ran.

`ScheduleDecision` carries the same explanation in `resolution`
(`explain_selection` shape), and the reason string leads with
`NO_ELIGIBLE_WORKER` plus per-worker codes. `Why wasn't worker-04
eligible?` and `Why can no worker run this?` are answered from the same
graph that selected — there is no second diagnostic system.

## Stable and experimental workers

Policy is composable booleans, not a brittle enum. A stable reference
worker declares everything false: normal work schedules normally, while
`mutating` and `privileged` intents resolve `POLICY_DENIED`. An
experimental worker (worker-03/worker-04 class) declares `experimental`
plus exactly the granted permissions. Experimental never means
unrestricted: a normal test remains schedulable everywhere, and a kernel
experiment must still request the matching intent — Fabric never picks
an experimental worker merely because it has root.

## Freshness and refresh

Capabilities change (packages, reboot, kernel/driver updates, rebuilds).
A stored description is aged from its own `captured_at` at schedule
time; anything past the bound resolves `WORKER_STALE` instead of
executing on memory. `fleet.refresh` re-probes; ledger restores after a
restart age honestly instead of inheriting zero. See
`development-evidence/capability-fleet-2026-09-06.json` for a live
snapshot with real query outcomes.

## Failure taxonomy

Scheduling and execution failures stay distinct:

- `NO_ELIGIBLE_WORKER` — nothing satisfies the workload (with reasons);
- `WORKER_UNAVAILABLE` / `WORKER_DISCONNECTED` — a compatible machine
  exists but is down or undescribed (different from nothing existing);
- `WORKER_STALE` — observations exist but are too old to trust;
- `POLICY_DENIED` — capable but unauthorized (or forbidden);
- `TOOLCHAIN_MISSING` / `RUNTIME_MISSING` — uniform missing class;
- `EXECUTION_FAILED` / `TEST_FAILED` / `INFRASTRUCTURE_FAILED` remain
  execution/record-level outcomes, never scheduling conflations.

## Cross-platform pressure

`tests/test_capability_resolution.py` proves selection and rejection
over a synthetic fleet (linux-only, windows-native, x86-64 vs ARM, CUDA
floors, eBPF, PTX, RISC-V native vs emulation, musl preference, NixOS
environmental difference, privileged intent, stable protection,
name-independence). `scripts/collect_fleet_capability_evidence.py`
replays the same query shapes against the live fleet; the checked-in
snapshot shows the real outcomes (Windows worker refused Linux-only
work with `missing os:linux`; CUDA/eBPF work selected only the
controller; privileged work returned `NO_ELIGIBLE_WORKER` under stable
defaults).

## Adding a new OS or architecture

1. Extend the probe (`platform_probe.py`) to observe it — bounded,
   honest `unknown` when unobservable.
2. Extend the finite enums in `mncs.std.platform.v1` (and the Python
   mirror tables) with the new arms; extend the corpus generator and
   corpus.
3. Add the token synthesis (`node.capability_names`, `env_tokens`).
4. Add selection/rejection tests; re-run the evidence collector.
5. Never add hostname branches to the scheduler; never shim the worker
   to look like another OS (no FHS fakes, no compatibility bash, no
   quasi-Fedora Alpine). Diversity is evidence — fix the workload
   declaration, stdlib, backend, or selection instead.

## Host boundary (explicit, pressured toward MNCS)

Python owns what MNCS cannot express today: unbounded text
classification (`classify_*`), subprocess discovery, clocks, hashing,
transport, persistence, and fleet aggregation. The pure decision core
stays in MNCS. If the language gains bounded text/IO surfaces, move
classification inward through the same corpus-evidence loop. Do not
weaken determinism to inflate MNCS percentage.

Known pressure carried forward: `mncs.core.version.v1::satisfies`
pins first-arg `>=` second-arg for directed envelopes across its green
192-case corpus; `mncs.std.platform.v1::version_satisfies` deliberately
reads the bound as a lower floor instead. The two agree on Any/Exact;
call sites must not swap them blindly. Upstream clarification is owed,
not a silent edit — the family corpus and its callers depend on the
exact current shape.
