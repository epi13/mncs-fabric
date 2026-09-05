# Agent instructions

MNCS Fabric is an evidence-sensitive project. Before changing code, read `ARCHITECTURE.md`, `THREAT_MODEL.md`, and `CONTRIBUTING.md`.

Do not add remote shell execution, unauthenticated listeners, silent capability fallbacks, mutable evidence rewriting, or claims of independence. New network behavior requires an explicit threat-model update and adversarial tests. Existing schema versions are immutable in meaning; create a new version for incompatible changes.

Run:

```bash
python -m unittest discover -s tests -v
python -m compileall -q src
```

## MNCS agent execution contract

The ecosystem-wide agent contract lives in mncs-actions (`AGENTS.md` there,
enforced by its `test_agent_contract.py`) with the language-side mirror in
mncs-language (`AGENTS.md` there). This repository follows both: MNCS-language
first, stdlib preferred over local substitutes, missing capability recorded
as development-pressure evidence routed to the owning authority (language
capability gaps belong to mncs-language), upstream repaired before the task
resumes, no foreign-language workaround hiding a genuine MNCS deficiency.

Fabric-specific rules:

- Schedule by capability, never by machine name. Workloads request
  capabilities such as `os.linux`, `os.windows`, `arch.x86_64`,
  `arch.arm64`, `arch.riscv64`, `execution.native`, `execution.emulated`,
  `accelerator.nvidia`, `runtime.cuda`, `kernel.ebpf`, `tool.qemu`.
  Worker names are deployment details and must not appear in scheduling
  logic, tests, or evidence.
- Execution evidence must identify where execution happened: node/worker
  identity, host OS and architecture, target architecture, native versus
  emulated (plus emulator identity and version), backend and compiler,
  stdlib, and runtime versions, relevant kernel/CUDA versions, artifact
  hash, and timestamp. A requested remote run that silently fell back
  locally is a failure, not a pass.
- Emulated results must never be presented as physical results
  (`execution.emulated` plus `emulator.*` is honest; bare arch claims are
  not). Compile-only targets stay compile-only until bytes have run and
  produced a checked result.
