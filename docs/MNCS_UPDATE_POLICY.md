# Fabric update policy in MNCS

`mncs/update_lifecycle.mncs` reconstructs two Fabric decisions as
language-owned source, executed by the real `mncs-language` toolchain:

- `transition_allowed` / `candidate`: the worker update-state machine
  from `src/mncs_fabric/update_lifecycle.py` (`_TRANSITIONS`), all 14
  states over a `TransitionVerdict { ALLOWED, DENIED }` finite domain;
- `version_less` / `version_candidate`: lexicographic Fabric version
  precedence over parsed integer tuples, matching
  `src/mncs_fabric/versioning.py` (releases sort after alphas of the
  same X.Y.Z via a large prerelease sentinel the caller supplies).

`mncs/gen_update_lifecycle_corpus.py` emits the exhaustive corpus
(`mncs/update_lifecycle_corpus.json`, 196 state pairs plus version
cases) from the Python tables. `mncs experiment run` compiles the module
(Source Profile 0.6: finite enums with exhaustive match, boolean guards)
and executes every case; `tests/test_mncs_update_policy.py` asserts the
execution agrees with Python on every case (`expectation_met`) and that
the checked-in corpus matches the Python authority (drift check).

## Boundary

Python remains authoritative for transport, timers, draining, artifact
transfer, restart, and persistence. The `.mncs` module owns the
transition relation and version ordering only. The corpus generator
reads the Python tables, so Python is still the authoring-time source
of truth; the value is that an independent compiler now parses,
lowers, and executes the decision Fabric depends on, and any divergence
fails the test rather than hiding. Moving runtime authority into MNCS
requires broader language support (process/async/IO effects) that does
not exist yet; see the pressure notes in the final report.

## CI

- `mncs-conformance.yml`: builds `mncs-language` at the pinned
  revision, runs `source-study`, regenerates the corpus (fails on
  drift), and executes the full conformance test. Path-filtered to the
  policy, its corpus, and the workflow itself, plus weekly: full
  finite-domain execution is minutes-long (see pressure notes below),
  so it does not ride every unrelated push.
- `mncs-family.yml`: the bounded Python suite
  (`scripts/mncs-project-check.py`, seconds) is projected into
  `mncs.check-result/1` and aggregated by `mncs-actions` under the
  `fabric-mncs-checks` boundary, backing the README badge.

## Pressure notes

- Exhaustive finite-domain execution is expensive: 245 cases over this
  14-state decision function took 9.4 min of host CPU (~2.3 s/case) on
  the research-bytecode backend, with ~8k canonical-hash operations per
  trivial case. Compile happens once; the cost is per-case
  observation/validation. Status is `PASS` with all 245
  `expectation_met`, so this is scale cost, not a correctness cliff,
  but it bounds how large an executable Fabric policy can grow before
  the edit/execute loop degrades. Candidate owner: `mncs-language`
  execution/observation cost.
- The language has no string, time, IO, process, or async effects, so
  the runtime authority for transport, timers, draining, transfer, and
  restart stays in Python by necessity, not by choice. The `.mncs`
  module owns the pure decision relation; widening that boundary needs
  language-level effects, which is a roadmap-scale gap, not a Fabric
  workaround.
