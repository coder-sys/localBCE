# STARK Verifier ABI Candidate

## Status

This document records the ABI design history that led to the implemented
controlled-attestation STARK settlement path. The active opt-in contracts are
`StarkAttestationVerifier.sol` and `StarkClaimsRegistry.sol`; the existing
Groth16 contracts remain the default path and are unchanged.

The selected STARK profile generates and locally verifies a real Winterfell
proof, then verifies an authorized secp256k1 attestation on-chain over the
exact public inputs, proof commitment, target registry, and claim amount. It
is not a native Solidity Winterfell verifier. See `STARK_RUNTIME.md` for the
current runtime contract.

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
`stark-production-proof-artifact-v6`. A separate
`stark-production-verifier-handoff-v6` envelope aligns those bytes, the 34
ordered AIR public inputs, and the packed `publicInputRoot`,
`claimSourceRoot`, `oracleFactsRoot`, `feeScheduleRoot`,
`nullifierRootBefore`, and `nullifierRootAfter` values with this candidate
interface.

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

The nullifier roots are constrained by a canonical depth-10 empty-tree
bootstrap at leaf zero. Approved claims insert the claim-hash-derived
nullifier; denied claims preserve the root. This is not persistent state and
does not handle concurrent claims.

The handoff remains intentionally non-call-ready because `batchRoot` is
unavailable, the nullifier state provider and source-root governance do not
exist, external oracle attestations are not verified, and no Solidity STARK
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

- a Solidity-compatible STARK verifier exists
- `ClaimsRegistry.sol` accepts STARK proofs
- Groth16 has been replaced
- deployment scripts use this interface

## Next Step

Define governance for the AIR-bound source roots and external oracle
attestation verification, replace bootstrap nullifier state with a persistent
provider, implement `batchRoot`, then build and independently test a Solidity-compatible
verifier for the locked proof and public-input encoding. Do not wire
ClaimsRegistry until those roots and the verifier pass positive and negative
proof tests.
