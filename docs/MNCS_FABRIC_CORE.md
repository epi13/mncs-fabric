# Fabric MNCS core

Ten MNCS modules execute real Fabric decisions on the real
`mncs-language` toolchain (pin `0216d64`; `research-bytecode`
everywhere, `mncs-portable-wasm-mvp` + `mncs-c11` spot evidence).
This document describes what each module owns, what stays host-side,
and how to add the next one. The rule for everything below:

> MNCS owns the decision over already-validated finite values. The host
> owns strings, clocks, ledgers, transport, hashing, and every absent
> value. The boundary is documented per module and pinned by tests; a
> transcription error fails the suite rather than diverging silently.

## Modules

- `fabric.worker_capability` (84 cases): provenance trust, freshness
  lattice, intent/policy compatibility, and the ordered resolution
  codes ending in `Eligible` or a machine-readable reason. Production
  decisions can additionally be answered from its compiled artifact
  through `MncsAuthority` (see below). Python mirror:
  `src/mncs_fabric/capability_resolution.py` Sec. 2.
- `fabric.update_lifecycle` (245 cases): the 14-state update transition
  relation plus lexicographic version precedence over parsed tuples.
- `mncs.std.platform.v1` (461 cases, **not a Fabric file**): the shared
  standard library owns the platform vocabulary and decision
  (OS/arch/libc/CUDA/resources/flags plus `env_satisfies`).
  Fabric's former duplicate (`fabric.platform_decision`) was deleted;
  `tests/test_mncs_platform_decision.py` executes the stdlib file
  itself against Python-computed expectations, including an
  init-independence proof. Python mirror:
  `src/mncs_fabric/capability_resolution.py` Sec. 1.
- `fabric.management` (70 cases): the 7-state controller management
  machine, the READY/BUSY scheduling gate, and the READY/certification
  invariant. Also green on WASM and C11.
- `fabric.reconnect` (328 cases): the `observe_reconnect`
  classification (observation + next state) over reduced boolean facts.
- `fabric.lifecycle_status` (40 cases): enrollment authorization
  precedence (REVOKED > EXPIRED > CONSUMED > ACTIVE) and request status.
- `fabric.availability` (168 cases): window openness over normalized
  minutes, including the always-open empty window and midnight wrap.
  The model split lives here: the host reduces clocks/timezones/
  day-sets to `(day_in, begin, finish, now)`; MNCS decides.
- `fabric.rollout_outcome` (1376 cases): deployment success, canary
  success (stricter certification gate), and canary-failure
  classification over reduced facts.
- `fabric.scheduler_rank` (104 cases): the pairwise fleet-rank
  comparator behind the sort key, replica sufficiency, slot admission,
  and replica bounds. The sort and the identity tie-break stay
  host-side (P-007).
- `fabric.work_item` (166 cases): terminal classification (reads the
  real `_TERMINAL` set), signed-64-bit priority order with the
  documented zero-folds-to-100 read, and dispatch holds (pause outranks
  missing eligibility). The priority domain is a clarified contract,
  not a narrowing: `checked_priority` validates new inputs explicitly
  while stored history is untouched.
- `pressure.text_probe` (13 cases, reproducer): bounded byte-token
  matching and digit accumulation at profile 0.7 with
  `mncs.core.bytes.v1` reuse, green on 3 backends. Pins the remaining
  text gap (P-014): fixed widths and byte-exactness only.

## Authority model: pilot reversal

For most modules Python is still the production runtime authority and
the corpus generator reads the Python tables, while MNCS is the
CI-executed authority. One subsystem goes further:
`src/mncs_fabric/mncs_authority.py` (`MncsAuthority`) reads the pinned
artifact bytes once, verifies the declared identity, retains the bytes
immutably, and executes exactly those bytes: every call materializes
them into a fresh exclusively-created file, so replacing or modifying
the artifact path afterwards cannot affect execution (no TOCTOU).
Answers correlate by case identity (duplicates, omissions, extras, and
reordering fail closed); output is bounded; evidence carries the
declared identity, the SHA-256 of the executed bytes, and the backend
name. `resolve_fleet`/`schedule` take `authority=` explicitly. There is
no silent fallback: misconfiguration raises `AuthorityError`. The
production default stays Python for measured latency and deployment
reasons; flipping it needs a real embedding API (P-010 remainder).
`tests/test_mncs_authority.py` proves MNCS answers all 48 resolve arms,
agrees with legacy verdict-for-verdict, survives artifact tampering,
and matches `mncs abi` output field-for-field.

## How to add the next module

1. Pick a pure decision: finite inputs, finite/boolean/integer outputs,
   no strings, no IO, no absent values (or document the folding).
2. Check whether the standard library already owns it (`library/` in
   mncs-language). If yes, write a parity corpus against the std file
   instead of a new module. If a new module needs std vocabulary,
   `use` it (imports work; see the text reproducer) — never re-declare.
3. Write `mncs/fabric_<name>.mncs` at Profile 0.6 (enums, records,
   exhaustive match, strict booleans, same-width comparisons only).
   Expose `candidate_*` wrappers as the executed entrypoints.
4. Write `mncs/gen_<name>_corpus.py` reading the Python authority (not
   reimplementing it). Encode records exactly as `mncs abi` reports
   them: `mncs:0.2:record-type:{module}::{Type}::{percent-encoded
   name:type; spec}`, `name`, and alphabetically ordered `[name, value]`
   field lists. Enum-typed fields name the bare type.
5. Write `tests/test_mncs_<name>.py` with both tiers: corpus-vs-Python
   agreement (always runs; rebuild the Python-side evidence from the
   decoded arguments, never trust the corpus) and gated toolchain
   execution (the `MNCS_FABRIC_RUN_TOOLCHAIN_TESTS=1` pattern).
6. Wire the workflow: source-study line, generator line, and test name
   in `.github/workflows/mncs-conformance.yml`.
7. Record new gaps in `development-pressure/mncs-language-pressure.json`
   (never work around the language); update
   `development-pressure/conversion-inventory.json`.

## Security invariants preserved

Scheduling is by capability, never worker name (no name appears in any
`.mncs` source, corpus, or test; the rank comparator answers a strict
question and the identity tie-break stays host-side). Evidence rules
are untouched: emulated stays emulated-shaped, compile-only stays
compile-only, and no remote/local fallback logic moved or changed. No
new network behavior; the threat model is unchanged. The authority
pilot records artifact identity in evidence rather than hiding the
answering implementation.
