# STARK Verifier ABI Candidate

## Status

This is a candidate ABI for future production STARK verification. It is not
active runtime behavior and is not wired into `ClaimsRegistry.sol`.

Active settlement remains Groth16 until a real STARK verifier/prover path is
implemented and explicitly enabled.

## Candidate Interface

The candidate Solidity interface is:

```text
blind-ledger/src/IStarkClaimsVerifierV1Candidate.sol
```

It exposes:

```solidity
function verifyStarkClaim(
    PublicInputs calldata publicInputs,
    bytes calldata proof
) external view returns (bool);
```

## Public Inputs

The candidate `PublicInputs` struct contains:

- `claimHash`
- `decision`
- `failureCode`
- `publicInputRoot`
- `claimSourceRoot`
- `oracleFactsRoot`
- `feeScheduleRoot`
- `nullifierRootBefore`
- `nullifierRootAfter`
- `batchRoot`

## Encoding Expectations

The candidate assumes:

- `decision` is `1` for approved and `0` for denied
- approved claims require `failureCode == 0`
- denied claims require `failureCode != 0`
- all root fields are nonzero
- `proof` is an opaque STARK proof byte payload
- the verifier, not the adapter, owns proof validity

The exact production encoding of `proof` is still blocked on the real prover
boundary.

## Current Tests

The candidate behavior is covered by:

```text
blind-ledger/test/StarkClaimsVerifierV1Candidate.t.sol
stark-engine/tests/phase7_solidity_abi_candidate_alignment.rs
```

The Solidity tests cover:

- approved public inputs
- denied public inputs
- invalid decision values
- approved claims with failure codes
- denied claims without failure codes
- missing required roots
- mismatched public input root
- mismatched proof bytes
- disabled verifier behavior

The `stark-engine` alignment tests cover:

- generated Solidity interface plan name
- generated function signature expectation
- exact V1 candidate public input field names
- exact Solidity types for every field
- future root fields marked unavailable until root generation exists
- validator rejection when a V1 candidate field is missing

The generated planning object is:

```text
stark_solidity_verifier_interface_plan.json
```

It is produced by:

```bash
cd stark-engine
cargo run --features winterfell-poc --bin generate_stark_solidity_verifier_interface_plan -- \
  stark_settlement_boundary_artifact.json stark_solidity_verifier_interface_plan.json
```

The strict ABI-candidate alignment validator is:

```bash
cd stark-engine
cargo run --features winterfell-poc --bin validate_stark_verifier_abi_candidate_alignment -- \
  stark_solidity_verifier_interface_plan.json
```

The full STARK smoke chain runs this validator automatically through:

```bash
bash scripts/validate_stark_bridge_chain.sh
```

## Non-Claims

This ABI candidate does not mean:

- a real STARK verifier exists
- real STARK proofs are generated
- `ClaimsRegistry.sol` accepts STARK proofs
- Groth16 has been replaced
- deployment scripts use this interface

## Next Step

Keep this candidate stable while Phase 8 real-prover work determines the actual
proof bytes, verifier artifact, and public-input commitment requirements.
