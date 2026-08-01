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

The feature-gated production proof encoding is lower-case hex over canonical
Winterfell 0.13.1 serialized proof bytes. Runtime use remains blocked on root
semantics and a real Solidity verifier implementation.

The feature-gated production AIR now emits real Winterfell proof bytes in
`stark-production-proof-artifact-v5`. A separate
`stark-production-verifier-handoff-v5` envelope aligns those bytes, the 26
ordered AIR public inputs, and the packed `publicInputRoot`,
`claimSourceRoot`, `oracleFactsRoot`, and `feeScheduleRoot` values with this
candidate interface.

`publicInputRoot` is now constrained by the production AIR. It is an
`Rp64_256` digest of a domain-separated preimage containing the claim hash, the
internal G1-G10 fact commitment, decision, and failure code. Its four canonical
field elements are packed as four big-endian `u64` values into Solidity
`bytes32`.

`claimSourceRoot` is now constrained by the production AIR. The AIR validates a
canonical 36-field claim-source leaf, links it to the adjudication claim hash
and service date, executes its fixed depth-10 `Rp64_256` Merkle path, and binds
the final four root elements to public inputs. The handoff packs those elements
as Solidity `bytes32`.

`oracleFactsRoot` is now constrained by the production AIR. Its canonical leaf
commits the source manifest, normalized verified facts, HTTPS source references,
and attestation references, then executes a fixed depth-10 `Rp64_256` Merkle
path. The references are committed but not externally attested by the proof.

`feeScheduleRoot` is now constrained by the production AIR. Its canonical leaf
commits a verified HTTPS USD fee schedule and exact effective-date service-line
matches. The AIR validates the fixed depth-10 path and links the fee leaf to the
claim-source service digest, service date, and total charge. Governance approval
of that schedule remains external.

The handoff remains intentionally non-call-ready because three state roots are
unavailable, the claim-source, oracle-facts, and fee-schedule roots are not
governed, external oracle attestations are not verified, and no Solidity STARK
verifier exists.

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

Define governance for the AIR-bound `claimSourceRoot` and `oracleFactsRoot`,
define external oracle attestation verification, implement the four remaining
source/state roots, then build and independently test a Solidity-compatible
verifier for the locked proof and public-input encoding. Do not wire
ClaimsRegistry until those roots and the verifier pass positive and negative
proof tests.
