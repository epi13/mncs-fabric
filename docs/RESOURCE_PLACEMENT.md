# Resource and execution placement

Fabric chooses a compatible worker; the consumer/provider runtime chooses how
its model executes on that worker. Fabric does not import Torch, Accelerate,
MNEL, RAVEL, or GIMP runtime code.

## Contracts

The additive profiles are:

- `mncs-fabric.node-resources.v0.1`: time-varying host, CPU, and accelerator
  observations;
- `mncs-fabric.execution-placement-request.v0.1`: consumer-declared intent;
- `mncs-fabric.placement-admission.v0.1`: deterministic Fabric eligibility;
- `mncs-fabric.execution-placement-observation.v0.1`: optional runtime facts;
  and
- `mncs-fabric.placement-reference.v0.1`: receipt linkage to request,
  snapshot, and admission.

`FabricClient.execute(..., placement=PlacementRequest(...))` is the public
entrypoint. Existing calls without placement remain compatible. A request
identity changes when device, offload, precision, memory estimate, reserve, or
runtime capability declarations change.

## Resource observations

Host RAM and CPU observations are dependency-free. NVIDIA discovery through
`nvidia-smi` or `lspci` is useful hardware evidence, but it is not CUDA
execution evidence. A worker must report a real synchronized runtime operation
before a consumer may use an accelerator execution capability. Dynamic values
remain in the resource snapshot rather than symbolic capabilities. Snapshots
expire after five minutes by default and are retained by identity for decision
reconstruction.

The current authorized Fedora worker has a NVIDIA Quadro P620, but only the
`nouveau` driver is active, `nvidia-smi`/CUDA are unavailable, and the
unprivileged test account cannot install a driver. Fabric therefore records
accelerator discovery as UNKNOWN and makes no CUDA or offload claim.

## Admission

CPU admission checks host-memory requirements. Full accelerator admission
requires executable accelerator and precision probes plus an effective budget:

```text
min(observed free VRAM, configured maximum) - reserve
```

Sequential CPU offload requires executable accelerator evidence, a consumer
declaration that its runtime supports offload, enough host memory, and a
minimum accelerator working-memory requirement. It does not require the whole
model to fit in VRAM. Actual layer movement remains the provider runtime's
responsibility.

Explicit accelerator/offload requests return `UNKNOWN` when requirements are
not established; they do not silently run on CPU. AUTO admission records the
selected mode, rejected workers, reasons, and snapshot identities. Fabric does
not reserve VRAM, so admission has an explicit time-of-check/time-of-use
limitation.

## Evidence boundary

Placement observations are operator-controlled runtime observations. They are
not hardware attestation, correctness, sandboxing, protected custody,
independence, MNCS conformance, or a consumer semantic verdict. Lower VRAM or
latency is operational telemetry; MNEL/RAVEL decide whether a placement is
useful for their own studies.

## Consumer mapping

MNEL may map its provider-owned CPU/full-CUDA/sequential-offload policy into a
generic request, while keeping runtime probes, model placement, fallback, and
semantic evaluation in MNEL/provider code. RAVEL may map a resource budget and
capability requirement into the same request without importing MNEL policy.
Neither consumer needs to invent Fabric capability names or reconstruct a
receipt. GIMP's GPU reserve, effective budget, real kernel probe, and separate
CPU/offload observations informed this boundary, but its vision-specific
runtime remains outside Fabric.
