# MNCS language pressure ledger

Machine-readable source: `mncs-language-pressure.json` (schema
`mncs-fabric.language-pressure.v0.1`). Per-subsystem conversion state:
`conversion-inventory.json`. This document ranks the findings for the
follow-up mncs-language campaign. Nothing here was worked around: every
blocked conversion below names the exact boundary where Python remains
the runtime authority.

Toolchain observed: mncs-language `8d79250` (feature branch
`feat/std-platform-capability`; CI pin unchanged at `4f3146a`),
`research-bytecode` backend, Source Profile 0.6.

## What converted (executed, not merely parsed)

Six MNCS modules, 1216 corpus cases, all PASS on the real toolchain:

| module | cases | owns |
| --- | --- | --- |
| `fabric.worker_capability` (pre-existing) | 84 | provenance/freshness/intent ordering |
| `fabric.update_lifecycle` (pre-existing) | 245 | update transitions, version precedence |
| `fabric.management` (new) | 70 | mgmt transitions, sched gate, READY invariant |
| `fabric.platform_decision` (new) | 449 | OS/arch/libc/CUDA/resource/flag + `env_satisfies` |
| `fabric.reconnect` (new) | 328 | reconnect classification + next state |
| `fabric.lifecycle_status` (new) | 40 | auth/request status lattice |

Each has a generator (`mncs/gen_*_corpus.py`), a checked-in corpus, and a
parity test (`tests/test_mncs_*`) with two tiers: corpus-vs-Python
agreement (always runs) and compiled execution (gated behind
`MNCS_FABRIC_RUN_TOOLCHAIN_TESTS=1`, runs in `mncs-conformance`).

Zero subsystems are fully MNCS-authoritative at runtime yet: Python
remains the production runtime authority everywhere (see P-010). Eight
subsystem cores are MNCS-pinned and CI-executed (`MNCS_PARTIAL`); the
rest is inventoried in `conversion-inventory.json`.

## Ranked pressure for the next campaign

### Tier 1 — unlocks the most Fabric code

1. **P-010 host-callable MNCS artifacts** (`FFI_HOST_BOUNDARY`, blocked,
   high). Every duplicated arm is pinned, but nothing can call the MNCS
   side in production. A call-into-compiled-MNCS contract (value
   encoding, artifact identity in receipts) lets `resolve_code` pilot the
   reversal, then the other five decision cores, deleting ~1.5k lines of
   mirrored Python logic over time.
2. **P-006 IO effects** (`RUNTIME`, blocked, high). Transport, storage,
   evidence hashing, clocks, subprocess: the entire controller/worker/
   evidence half of Fabric. Start with clock + hash + file effects; the
   Fabric transport is the designated first consumer. Nothing here was
   weakened: evidence guarantees are intact because the move did not
   happen.
3. **P-007 sets/maps/iteration/sorting** (`LANGUAGE_SEMANTICS`, blocked,
   high). Fleet aggregation, token-set algebra, ledger folding. Moving
   `resolve_fleet` ranking into MNCS removes the second semantic layer
   in scheduling. Depends on bounded-collection semantics; coordinate
   with profiles 0.7–0.10 owners.
4. **P-005 bounded text** (`STDLIB`, blocked, high). All classifiers and
   version/identity parsing. The host-classifies/MNCS-decides split is
   sound and documented, but every new platform string still means
   editing Python. Needs an RFC before any classifier moves.

### Tier 2 — multiplies velocity / removes drift risk

5. **P-004 stable module imports** (`MODULE_SYSTEM`, awkward, medium).
   Removes the std-platform vocabulary duplication (`fabric` re-declares
   7 enums). Delete ~150 lines of mirrored declarations once imports
   reconcile nominal finite/record identities.
6. **P-008 services/concurrency** (`RUNTIME`, blocked, high but
   longer-term). Heartbeats, leases, queue ticks, retries. State
   relations are already extracted; the loops come after P-006.
7. **P-002 argument-mismatch diagnostics** (`DIAGNOSTICS`, awkward,
   medium). One-line fix (print expected vs received identities),
   found the hard way during this campaign. Immediate payoff for every
   future corpus author.
8. **P-003 shared corpus-value builder** (`TOOLING`, awkward, medium).
   One supported encoder (or `mncs corpus lint` against `mncs abi`)
   replaces per-module copy-paste that already caused one real bug here.

### Tier 3 — known costs, tracked

9. **P-009 execution/observation cost** (`PERFORMANCE`, awkward, medium).
   ~2 s/case for deeply-nested relations (update corpus) vs seconds for
   887 small-decision cases; cost scales with relation complexity. The
   six-module conformance job keeps a 150 min timeout. Profile
   canonical-hash volume per trivial case first.
10. **P-011 multi-backend evidence** (`BACKEND`, awkward, medium). All
    Fabric evidence is single-backend. Weekly matrix over the six
    corpora; file backend findings separately.
11. **P-001 mixed-width comparison** (`TYPE_SYSTEM`, awkward, medium).
    Decide promotion or bless conversions; small, well-isolated.
12. **P-012 Option/None** (`TYPE_SYSTEM`, awkward, low). Three absence
    policies waiting (freshness-None, management-None, artifact-None).

## Dependencies between fixes

- P-010 before any Python-arm deletion (else coverage without authority).
- P-006 before P-008 (effects before services).
- P-007 before fleet-aggregation migration; independent of P-005.
- P-002/P-003 independent, cheapest, do first.
- P-011 (matrix) should ride along with any backend-affecting fix to
  catch accidental single-backend reliance.
