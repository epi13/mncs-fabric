# Compatibility snapshots

This directory contains small, pinned shape snapshots rather than a vendored
copy of a sibling implementation. The receipt, bundle, and challenge snapshots
were inspected against `machine-native-complexity-standard` commit
`80f08d312dce963265c7f69ac5b4bae8245bd692`.

Fabric emits the experimental MNCS typed execution receipt as a companion
observation. It does not emit conformance, assurance, independence, custody,
sandbox, or attestation claims. Unknown future receipt, bundle, and challenge
versions are rejected.
