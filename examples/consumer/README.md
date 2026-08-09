# Public consumer fixture

This fixture demonstrates the stable Fabric consumer surface without importing
MNEL, RAVEL, Forge, or any sibling implementation. Install Fabric, then run:

```bash
python examples/consumer/public_local.py
```

The example uses `FabricClient`, `LocalWorkerConfig`, and `ConsumerContext`.
Fabric creates the execution record and MNCS receipt; the example does not
reconstruct either one. The consumer context is opaque provenance and grants
no semantic or promotion authority.
