# MNCS-family compatibility

This iteration was aligned against these local sibling snapshots:

| Project | Commit used | Boundary used | Status |
| --- | --- | --- | --- |
| `machine-native-complexity-standard` | `160358365c4bec8c2c0038e2e2e69da7c4b06911` | experimental typed execution receipt `0.1-experimental`, execution assurance `0.1`, placement reference shape | adapter implemented; assurance remains UNKNOWN where Fabric cannot establish a property |
| `MNCS-Commons` | `985b187b819f607b8c5571ab243f259209eb5dd7` | append/recovery and writer-coordination concepts | Fabric-owned ledger; no private Commons dependency |
| `mncs-forge-mcp` | `bc9388d0ad8e8be554791def5d8aa6ff2f44d72d` | Runner/LocalProcessRunner, typed service ports, Provider Protocol 0.1 | local provider workflow and public service boundary |
| `mncs-language` | `bbc3cef7142844443a5f75e8be01f4a148572fa8` | stable provider/status vocabulary | no new authority vocabulary |
| `RAVEL` | `2dfedd2a7edbab12b7e301228d56b1416f172f78` | lifecycle/episode identity awareness | no RAVEL conformance claim |
| `Machine-Native-Experimental-Learning` | `7e11fbd15680a034a27e14db32762451c2bd7d17` | identity/lifecycle vocabulary | no imported private contract |

## Supported receipt assumptions

Fabric supports the exact current receipt top-level shape, raw 64-hex SHA-256
fields, explicit claim boundary, separate enforcement states, nullable
placement reference, and `PASS`/`FAIL`/`UNKNOWN` observations. It preserves
Fabric record identity in a namespaced extension and binds the receipt to the
Fabric job, candidate, manifest, runner, and environment observations.

Unknown receipt versions fail closed. The self-contained shape snapshot is
`compat/mncs-execution-receipt-0.1.snapshot.json`; the optional checker accepts
a sibling schema path but is never required by CI.

Fabric does not emit MNCS/MNCDS conformance, execution assurance, protected
custody, independent evaluation, sandbox, encryption, or attestation claims.
