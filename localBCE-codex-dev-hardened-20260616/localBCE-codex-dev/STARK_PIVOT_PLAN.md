# Native STARK Completion Plan

The pivot away from the previous proof architecture is complete at the package
level. The active work now is finishing the native STARK production path.

## Remaining Work

- Supply audited native STARK verifier artifacts.
- Pin the real verifier artifact hash in a production successor to
  `ops/verifier_artifact_pin.example.json`.
- Wire deployment to the real verifier and public input schema.
- Complete external cryptographic audit and operational launch signoff.

No deleted proof lane should be restored to satisfy these items.
