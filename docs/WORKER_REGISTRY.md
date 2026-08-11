# Operator worker registry

`mncs-fabric.worker-registry.v0.1` is a controller-local, versioned catalog of
worker endpoints that an operator has explicitly commissioned. It is not a wire
protocol, discovery mechanism, enrollment record, liveness result, or grant of
authority.

Registry entries contain a worker identity, endpoint, bounded timeout profile,
operator labels, and filesystem references to the existing CA, controller
certificate/key, and TrustStore. Private-key bytes are never embedded. References
must be regular non-symbolic files and the TrustStore must actively enroll the
same worker before Fabric constructs an mTLS transport.

```bash
mncs-fabric registry validate ~/.local/state/mncs-fabric/workers.json
mncs-fabric registry list ~/.local/state/mncs-fabric/workers.json
```

Applications may call `FabricClient.load_registry(path)`. Every structurally
valid member remains visible through `workers()`: ready references become normal
remote workers and invalid/missing/revoked references remain `KNOWN` with
`availability=UNKNOWN`. No entry silently becomes `AVAILABLE`; authenticated
refresh remains authoritative.

The registry schema does not change `mncs-fabric.protocol.v0.1`. Explicit consumer
configuration wins only when it names the same identity and endpoint; a conflict
fails closed.
