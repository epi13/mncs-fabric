# Experiment Record Transport Boundary

Status: architecture proposal / non-normative

## Purpose

Fabric participates in Concept Reconstruction Experiments (CREs) as the distributed execution and observation layer. It should make experiment executions durable, identifiable and portable without taking ownership of experiment validity, language semantics, evaluator meaning or MNCS conformance.

## Core boundary

> Fabric records what ran, where it ran, what environment was observed, what output/receipt was produced and how execution was placed. It does not decide what those observations prove.

A Fabric execution `PASS` remains a Fabric execution outcome. It is not automatically a Forge verdict, a successful scientific experiment, an MNCDS selection or an MNCS PASS.

## Family Record Spine role

The proposed Family Record Spine should reference Fabric-native identities rather than copying execution facts into a new cross-family schema. Relevant references may include:

- execution/job identity;
- worker/node identity;
- environment and capability observations;
- exact model/runtime placement where observable;
- artifact/bundle identity;
- execution receipt;
- cohort/reconciliation result;
- failure and recovery events.

A producer-neutral Concept Experiment envelope may point to these records while Fabric retains ownership of their semantics.

## Initial topology

The first CREs should continue to use the existing controller/worker split:

```text
Control / Harness
      -> Fabric worker execution
      -> Fabric-native receipts and records
      -> controller mediation
      -> Commons references / publication
```

Workers do not need direct Commons persistence authority. They should not receive Commons store paths, operator sockets or credentials simply because an experiment will eventually be indexed in Commons.

## Temporary RAVEL/MNEL-like roles

Additional Fabric nodes may host models assigned Harness roles such as `experiment-investigator` or `adaptive-experiment-critic`. Fabric should treat them exactly as what they are: resolved workers/models executing bounded jobs.

Fabric MUST NOT label their outputs as RAVEL or MNEL records. Exact worker, provider/runtime and execution identity should remain available so future RAVEL/MNEL studies can compare against these baselines.

## Rerun discipline

A frozen CRE should be rerunnable across Linux, Windows and Raspberry Pi where the concept and backend make that meaningful. Cross-host comparison should preserve:

- unchanged experiment/candidate identity where appropriate;
- changed worker/environment/target identity;
- exact toolchain/runtime observations;
- missing or unsupported capabilities as `UNKNOWN` rather than invented equivalence.

A target-specific failure is useful evidence and should remain addressable.

## Failure preservation

Fabric should preserve execution failure and uncertainty without collapsing them into semantic conclusions. Timeouts, disconnects, provider errors, placement mismatches, recovery events and unavailable capabilities are execution observations. Higher layers may classify their implications, but Fabric should retain the original evidence.

## Future federation

Fabric may later carry inert Commons Agent Exchange envelopes between controller-local and worker-local Commons nodes if locality requires it. That future transport must preserve source record identity and must not turn authenticated transport into correctness, independence, acceptance or conformance.

Federation is not required for the initial concept-experiment program.

## First exercise

The first end-to-end CRE can use the MNCS tri-state result lattice and run independent language candidates on available Fabric hosts. The study should make it possible to distinguish language/compiler disagreement from target/runtime/execution disagreement by following exact Fabric identities through the record spine.
