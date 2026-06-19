# Winterfell Verifier Path

Status: Rust/off-chain verifier works. Production on-chain verifier artifacts
are not generated in this run.

## Works

- `src/bin/verify_artifact.rs` verifies serialized Winterfell proof bytes
  against public inputs.
- Local proof artifacts can be generated and verified by the Rust binaries.

## Pending

- Choose or build the native verifier implementation.
- Bind the verifier to `ops/native_stark_public_inputs_v1.json`.
- Pin source and artifact hashes in an ops manifest.
- Add a Forge test that verifies a real proof through the production verifier.
- Measure gas and complete cryptographic audit.

Until then, the Solidity settlement path remains blocked for production launch.
