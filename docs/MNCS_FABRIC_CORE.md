# Fabric MNCS core

Six MNCS-language modules now execute real Fabric decisions on the real
`mncs-language` toolchain (`research-bytecode`, Source Profile 0.6).
This document describes what each module owns, what stays host-side,
and how to add the next one. The rule for everything below:

> MNCS owns the decision over already-validated finite values. The host
> owns strings, clocks, ledgers, transport, hashing, and every absent
> value. The boundary is documented per module and pinned by tests; a
> transcription error fails the suite rather than diverging silently.

## Modules

- `mncs/worker_capability.mncs` (`fabric.worker_capability`, 84 cases):
  provenance trust, freshness lattice, intent/policy compatibility, and
  the ordered resolution codes ending in `Eligible` or a
  machine-readable reason (`NO_ELIGIBLE_WORKER` is the fleet-level
  verdict built on top). Python mirror:
  `src/mncs_fabric/capability_resolution.py` Sec. 2.
- `mncs/update_lifecycle.mncs` (`fabric.update_lifecycle`, 245 cases):
  the 14-state update transition relation plus lexicographic version
  precedence over parsed tuples. Python mirrors:
  `src/mncs_fabric/update_lifecycle.py` (`_TRANSITIONS`),
  `src/mncs_fabric/versioning.py`.
- `mncs/fabric_management.mncs` (`fabric.management`, 70 cases):
  the 7-state controller management machine, the READY/BUSY scheduling
  gate, and the READY/certification invariant. The strict table has no
  reflexive arm: Python's `can_transition` self-transition closure and
  the `None`-means-schedulable default stay host-side. Python mirror:
  `src/mncs_fabric/management.py`.
- `mncs/fabric_platform_decision.mncs` (`fabric.platform_decision`,
  449 cases): OS/arch/libc/CUDA/resource/flag predicates plus the
  composed `env_satisfies` over `WorkerEnv`/`WorkloadReq` records. An
  `Unknown` observation satisfies nothing; only requirements say `Any`.
  Re-declares the `mncs.std.platform.v1` vocabulary (imports are not
  yet stable enough to reuse it; see pressure P-004). Python mirror:
  `src/mncs_fabric/capability_resolution.py` Sec. 1.
- `mncs/fabric_reconnect.mncs` (`fabric.reconnect`, 328 cases): the
  `observe_reconnect` classification (observation + next state) over
  reduced boolean facts. Identity text folds to `same_identity`,
  version/artifact comparison folds to `version_matched`, parse failure
  folds to `version_malformed`, recovery folds to `present_at_expected`;
  states outside the reconnect lifecycle fold to `Other` (with the
  not-applicable observation pinned as `AwaitingDisconnect`, exactly as
  Python reports it). Python mirror:
  `src/mncs_fabric/update_lifecycle.py::observe_reconnect`.
- `mncs/fabric_lifecycle_status.mncs` (`fabric.lifecycle_status`,
  40 cases): enrollment authorization precedence (REVOKED > EXPIRED >
  CONSUMED > ACTIVE) and request status (recorded decision wins,
  otherwise expired/revoked authorization expires the request). Unknown
  authorizations/requests stay host-side errors, never status values.
  Python mirrors: `src/mncs_fabric/lifecycle.py::_record_status`,
  `_request_status`.

## Authority model (transitional, explicit)

For each module, Python is still the production runtime authority and
the corpus generator reads the Python tables. The MNCS module is the
CI-executed authority: `mncs experiment run` compiles and executes every
case, and `tests/test_mncs_*` fails on any divergence. Removing the
Python arms waits on a host-callable artifact story (pressure P-010);
until then, duplication is pinned, named, and bounded — never silent.

## How to add the next module

1. Pick a pure decision: finite inputs, finite/boolean/integer outputs,
   no strings, no IO, no absent values (or document the folding).
2. Write `mncs/fabric_<name>.mncs` at Profile 0.6 (enums, records,
   exhaustive match, strict booleans, same-width comparisons only).
   Expose `candidate_*` wrappers as the executed entrypoints.
3. Write `mncs/gen_<name>_corpus.py` reading the Python authority (not
   reimplementing it). Encode records exactly as `mncs abi` reports
   them: `mncs:0.2:record-type:{module}::{Type}::{percent-encoded
   name:type; spec}`, `name`, and alphabetically ordered `[name, value]`
   field lists. Enum-typed fields name the bare type.
4. Write `tests/test_mncs_<name>.py` with both tiers: corpus-vs-Python
   agreement (always runs; rebuild the Python-side evidence from the
   decoded arguments, never trust the corpus) and gated toolchain
   execution (the `MNCS_FABRIC_RUN_TOOLCHAIN_TESTS=1` pattern).
5. Wire the workflow: source-study line, generator line, and test name
   in `.github/workflows/mncs-conformance.yml`.
6. Record new gaps in `development-pressure/mncs-language-pressure.json`
   (never work around the language); update
   `development-pressure/conversion-inventory.json`.

## Security invariants preserved

Scheduling is by capability, never worker name (no name appears in any
`.mncs` source, corpus, or test). Evidence rules are untouched:
emulated stays emulated-shaped, compile-only stays compile-only, and no
remote/local fallback logic moved or changed. No new network behavior;
the threat model is unchanged.
