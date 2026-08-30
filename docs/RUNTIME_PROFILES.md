# Runtime profiles and optional accelerator probes

Fabric records the execution environment that launches a worker separately
from the machine capability and resource snapshot. The current profile is the
worker's Python interpreter, identified by an executable content identity;
the local path is deliberately not portable semantic identity.

The public records are:

- `mncs-fabric.runtime-profile.v0.1`: operator-provisioned interpreter facts;
- `mncs-fabric.runtime-observation.v0.1`: bounded output normalized from an
  optional runtime probe; and
- `mncs-fabric.runtime-binding.v0.1`: linkage from an observation to a Fabric
  request, execution record, and receipt after execution completes.
- `mncs-fabric.runtime-environment.v0.1`: a small identity of material
  operator-provisioned components such as Torch and Accelerate; it is not a
  package lock or package-manager contract; and
- `mncs-fabric.runtime-capability-observation.v0.1` plus its binding: proof
  that one exact worker runtime physically exercised a bounded capability such
  as `sequential-cpu-offload`, before Fabric creates the final receipt.

Worker descriptions carrying a runtime profile use additive
`mncs-fabric.worker-description.v0.2`; historical v0.1 descriptions remain
valid and retain their original meaning.

Fabric core has no Torch, CUDA, Accelerate, NVML, or other provider dependency.
The optional `scripts/probe_torch_cuda.py` workload may run in an operator-owned
Python environment. It reports GPU discovery, `torch.cuda.is_available()`, and
precision statuses separately, but marks execution proof `PASS` only after a
real operation and `torch.cuda.synchronize()` complete. `nvidia-smi` success or
`torch.cuda.is_available()` alone is never CUDA execution proof.

The probe runs before a receipt exists. A controller can ingest its bounded
JSON through `FabricClient.ingest_runtime_observation()` and later bind it with
`FabricClient.bind_runtime_observation()`. This avoids a circular identity
requirement and preserves the distinction between runtime evidence and
hardware attestation, semantic correctness, or worker honesty.

The Windows helper `scripts/windows_worker_launcher.py` manages only an
explicitly recorded worker PID and process-start token. Its detached process,
state, log, and stop operations are Windows-aware; it is not a general remote
shell or service manager. `scripts/two_host_windows_gpu_test.py` requires an
explicit operator endpoint and uses strict SSH host-key checking for bootstrap
preflight only. It does not create an SSH tunnel or execute candidate work over
SSH.

A representative Windows worker is commissioned through an explicit operator
endpoint with strict key-only SSH bootstrap, then runs the Fabric worker from
an operator-provisioned Python GPU environment. A synchronized CUDA probe can
record FP32, FP16, and BF16 operations on a discrete NVIDIA GPU. The runtime
observation is ingested before dispatch and bound to the resource snapshot,
admission decision, execution record, and receipt. This is bounded
operator-controlled evidence; it is not attestation, semantic correctness, or
independent evaluation.

## Sequential CPU offload

The consumer field `runtime_supports_sequential_cpu_offload` remains a
declaration of provider intent/capability. It is not execution proof. An
explicit sequential-offload request is strongly admitted only when the worker
has a fresh `sequential-cpu-offload` capability observation bound to the same
runtime profile and material runtime environment. Without that proof Fabric
returns `UNKNOWN` and never silently falls back to CPU or full CUDA.

The commissioned Windows runtime reported Torch 2.11.0+cu128 and Accelerate
1.14.0. Its bounded layered MLP probe used `accelerate.cpu_offload`, executed
real synchronized CUDA kernels, installed seven offload hooks, retained zero
persistent CUDA parameter bytes after execution, and produced the same result
digest as the full-CUDA baseline. This remains provider-runtime evidence, not
hardware attestation or a claim that every worker supports offload.
