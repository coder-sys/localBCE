# ZK Run Report

Status: soundness-checked prototype circuit, PENDING regulatory-spec review.

## Toolchain

- Node: local portable Node `v24.16.0`, SHA256 verified against official Node `SHASUMS256.txt`.
- npm: `11.13.0`.
- Circom: `2.2.3`, built locally from `iden3/circom` tag `v2.2.3`.
- snarkjs: `0.7.6`.
- circomlib: `2.0.5`.
- circomlibjs: `0.1.7`.
- circomspect: `0.9.0`.

npm audit caveat: local ZK npm dependencies currently report 18 vulnerabilities: 12 low, 3 moderate, 3 high. These are tooling dependencies, not app runtime dependencies, but they need review before productionizing the proving toolchain.

## Circuit Coverage

Circuit: `circuits/claim_adjudication_core.circom`.

What is enforced:

- Poseidon claim commitment over normalized private gate inputs.
- Poseidon nullifier from member id and claim nonce.
- G1 member id present.
- G2 eligibility active.
- G3 provider NPI present.
- G4 provider enrolled.
- G5 service line count present.
- G6 diagnosis count present.
- G7 prior-authorization-ok normalized flag.
- G8 charge positive and charge less than or equal to max charge.
- G9 duplicate flag is false.
- G10 program integrity hold is false.
- Public decision equals the product of all gate pass bits.
- Public failure code equals the first failed gate index, or `0` if approved.

What is not yet enforced:

- Raw 837 parsing inside the circuit.
- CARC/RARC selection.
- Global duplicate nullifier non-membership against an on-chain/nullifier-set root.
- Prior-authorization policy derivation from procedure/date/provider rules; the circuit uses a normalized `priorAuthOk` input.
- Regulatory correctness against Medi-Cal/DHCS policy. The checks here prove circuit math, not law.

## Build

- Constraints: 2,338.
- Wires: 2,340.
- Public inputs: 4: `claimCommitment`, `nullifier`, `decision`, `failureCode`.
- Private inputs: 12.
- R1CS/WASM/SYM generated successfully.

## Keys And Proofs

- Dev Powers-of-Tau: `keys/pot12_final.ptau`.
- Dev proving key: `keys/claim_adjudication_core_final.zkey`.
- Verification key: `keys/verification_key.json`.
- Generated Solidity verifier: `../contracts/src/GeneratedClaimVerifier.sol`.

This is a DEV trusted setup. A production Groth16 deployment requires a real ceremony or an accepted production-grade setup process.

Proofs generated and verified off-chain:

- `approved`: verified.
- `duplicateDenied`: verified.
- `ineligibleDenied`: verified.

Timings are in `proofs/proof_timings.json`.

## Soundness Checks

- `snarkjs wtns check`: passed for all three witnesses.
- `snarkjs zkey verify`: passed.
- `circomspect`: no issues found.
- Local R1CS sanity check: no findings.

Soundness caveat: static analysis and witness checks reduce the risk of unconstrained-signal and malformed-circuit bugs, but they are not a formal proof that the circuit encodes Medi-Cal law correctly.

## Contract Integration

- Added generated verifier contract.
- Added `ClaimVerifierAdapter` implementing the existing `IVerifier` interface.
- Kept `StubVerifier` available.
- Forge tests include a real Groth16 proof recording a claim and a tampered-public-input rejection.
- Forge tests pass.
