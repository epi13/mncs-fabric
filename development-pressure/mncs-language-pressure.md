# MNCS language pressure ledger

Machine-readable source: `mncs-language-pressure.json` (schema
`mncs-fabric.language-pressure.v0.1`). Per-subsystem conversion state:
`conversion-inventory.json`. This document ranks the findings for the
mncs-language repair campaign. Nothing here was worked around: every
blocked conversion names the exact boundary where Python remains
the runtime authority.

## Evidence baseline (one truth)

- Fabric tree: this campaign (post-PR #73 continuation).
- Language: `0216d64` (mncs-language origin/main; CI pin). The PR #73
  review flagged dev-rev `8d79250` vs pin `4f3146a` drift; resolved by
  bumping to mainline `0216d64` (which contains
  `library/std/platform.mncs`) and re-executing all six PR #73 corpora
  PASS there (1216/1216) before migrating. All new corpora are
  generated and executed at `0216d64`.
- Profiles `0.6` (core) and `0.7` (text pressure reproducer only).
- Backends: `research-bytecode` everywhere; `mncs-portable-wasm-mvp`
  and `mncs-c11` spot evidence (management 70/70, text probe 13/13).

## What converted this campaign

- **Authority pilot (P-010)**: `MncsAuthority` answers ordered
  resolution codes from the compiled artifact in one
  `experiment execute` batch (~280 ms fixed, ~0 marginal);
  `resolve_fleet`/`schedule` take `authority=` explicitly and bind
  artifact/backend identity into evidence. MNCS answers all 48 resolve
  arms; fleet+scheduler agree with legacy verdict-for-verdict.
- **Std reuse (P-004 resolved)**: `fabric.platform_decision` (~302
  lines) deleted; the parity corpus executes `mncs.std.platform.v1`
  itself (461 cases, incl. init-independence proof).
- **New cores**: availability windows (168), rollout outcomes (1376),
  scheduler rank (104), work item (166) — all PASS at the pin.
- **Text pressure**: `pressure.text_probe` proves byte-token matching
  and digit accumulation on 3 backends; pins exact-width and
  case-sensitivity limits (P-014).
- Corpus total: 1216 -> 3055 executable cases.

## Resolved / narrowed since PR #73

- **P-004 imports**: RESOLVED. `use` elaborates, executes, preserves
  declaring-module identities; duplication deleted (see above).
- **P-005 text**: NARROWED. Byte mechanics + `mncs.core.bytes.v1`
  reuse proven; remainder moves to P-014 (views, folding, feeding).
- **P-010 embedding**: PILOT-PROVEN. Mechanism exists and is measured;
  default flip needs a real embedding API (ms cost, no subprocess).
- **P-011 backends**: EVIDENCE-ADDED. First 3-backend Fabric results.

## Ranked pressure for the repair campaign

### Tier 1 — unlocks the most Fabric code

1. **P-014 variable-length text/views** (new, blocked, high).
   `classify_arch/os/libc`, version parsing, protocol validation.
   Fixed-width proof exists; views-based variable matching is the next
   step, then move classifier arms one by one (~600 lines Python).
2. **P-006 IO effects** (still blocked, high). Transport, storage,
   evidence hashing, clocks, subprocess. Start with clock + hash +
   file; Fabric transport is the designated consumer.
3. **P-007 sets/sorting** (still blocked, high). Fleet aggregation,
   token-set algebra, ledger folding. The rank comparator moved; the
   sort itself waits on bounded collections.
4. **Embedding API** (P-010 remainder, awkward, high). Host-callable
   entrypoints with ms cost so the proven pilot can become the
   default; unlocks deleting the mirrored resolve arms.

### Tier 2 — velocity / drift risk

5. **P-008 services/timers** (blocked, high, longer-term). State
   relations extracted (management, update, reconnect, rollout, work
   item); loops wait on P-006.
6. **P-002 mismatch diagnostics + P-003 corpus builder + P-013 empty
   expected** (awkward, low/medium). Cheap, immediate payoff.
7. **Weekly multi-backend matrix** (P-011 remainder). LLVM/Cranelift/
   RV32/eBPF/PTX still uncovered.

### Tier 3 — tracked

8. **P-009 cost** (awkward, medium). Heavy corpora need the 150 min
   budget; small relations run in seconds.
9. **P-001 mixed-width ints, P-012 Option types** (awkward, low/medium).
   Small, isolated.

## Dependencies

- P-014 before classifier migration; independent of P-007.
- P-006 before P-008.
- Embedding API before Python-arm deletion (coverage without authority
  is the current pinned state, not the destination).
- Matrix job rides along with any backend-affecting fix.

## Fabric-side hardening audit (not upstreamed)

The hardening pass fixed three Fabric mistakes in place; none of them
is a language pressure and none was sent upstream:

- artifact TOCTOU (review): `MncsAuthority` now executes verified
  in-memory bytes via fresh exclusive files, correlates answers by
  case ID, bounds output, and is tamper-tested. Evidence carries the
  SHA-256 of the executed bytes.
- semantic worker IDs (review): authority and capability fixtures now
  use opaque identities with rename-invariance proof.
- priority domain (review): clarified as signed 64-bit with explicit
  `checked_priority` validation; the MNCS relation widened to match.
  The zero-folds-to-100 read is preserved byte-for-byte, not narrowed.

Audit conclusion: every remaining ledger item above is a genuine
language/compiler/runtime/stdlib limitation, evidenced by a minimal
reproducer that reaches the language's limits rather than Fabric's.
No Fabric defect materially contaminates the pressure evidence.
