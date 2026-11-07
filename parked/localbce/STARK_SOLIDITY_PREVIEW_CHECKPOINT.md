# STARK Solidity Preview Checkpoint

## Status

The active Solidity settlement path is still Groth16:

```text
rust-engine
-> Groth16 proof artifacts
-> Verifier.sol
-> ClaimsRegistry.sol
```

The STARK Solidity work is preview-only. It defines future interface and adapter
expectations without wiring STARK proofs into the active `ClaimsRegistry.sol`.

## Preview Interfaces

The current preview surface includes:

- `blind-ledger/src/IStarkClaimsVerifierPreview.sol`
- `blind-ledger/src/IStarkClaimsVerifierWithRootPreview.sol`
- `blind-ledger/src/IStarkClaimsRegistryAdapterPreview.sol`

These interfaces are intentionally marked `UNLICENSED` and preview-oriented.
They are not production ABIs yet.

## Preview Tests

The current preview tests include:

- `blind-ledger/test/StarkClaimsVerifierPreview.t.sol`
- `blind-ledger/test/StarkVerifierHarness.t.sol`
- `blind-ledger/test/StarkClaimsRegistryAdapterPreview.t.sol`

These tests cover:

- claim hash, decision, failure code, and proof commitment checks
- public input root compatibility
- verifier disabled/rejection behavior
- approved STARK claim accounting
- denied STARK claim accounting
- duplicate STARK claim rejection
- retry after invalid proof
- interface-call compatibility
- approved, denied, and rejected-proof event compatibility

## Validation

Run the focused STARK Solidity preview validation from the repo root:

```bash
bash scripts/validate_stark_solidity_preview.sh
```

This command runs only the `blind-ledger/test/Stark*.t.sol` preview suites.

The full repo validator also includes this focused check:

```bash
bash scripts/validate_localbce.sh
```

## Important Non-Claims

This checkpoint does not mean:

- a real STARK Solidity verifier exists
- STARK proofs are verified on-chain
- `ClaimsRegistry.sol` accepts STARK proofs
- Groth16 has been replaced
- Winterfell proof bytes have a production ABI
- production deployment scripts use these preview interfaces

## Next Safe Step

The next low-risk step is to keep the active contracts unchanged and add a
documented adapter migration plan:

1. Define the minimal production STARK verifier ABI candidate.
2. Define public input root and proof commitment encoding requirements.
3. Define the exact conditions for adding a separate STARK adapter contract.
4. Keep `ClaimsRegistry.sol` Groth16-only until the real verifier exists.
