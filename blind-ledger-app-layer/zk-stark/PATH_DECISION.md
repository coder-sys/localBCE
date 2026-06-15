# Path Decision

Status: architecture decision, not production ratification. Both paths remain side by side.

## Groth16/BN254 Path

What is real today:

- Existing Groth16 circuit path remains in `../zk/`.
- Existing app, contracts, and tests stay green.
- It is good for a working demo because proofs are small and EVM verification is practical.

Limits:

- It is not post-quantum.
- It requires a trusted setup ceremony.
- Its on-chain security rests on pairing-based cryptography.

Decision:

- Keep it as the demo and compatibility path.
- Do not call it the production PQ architecture.

## STARK Path

What is real today:

- `zk-stark/` has a runnable Winterfell STARK core for G1-G10 normalized adjudication.
- It proves and verifies approved, ineligible-denied, duplicate-denied, and excessive-charge-denied cases.
- It needs no trusted setup.
- Its off-chain proof/verify path is hash/FRI based and therefore PQ-capable in the proof layer.

Limits:

- The current runnable core uses Winterfell on Windows, not the final Plonky3/BabyBear/Poseidon2 stack.
- The current claim commitment is a local AIR-bound algebraic commitment for the PoC, not a production-audited hash commitment.
- The native on-chain STARK verifier is not built yet.
- Human cryptographic audit and Medi-Cal/legal logic review remain mandatory.

Decision:

- STARK is the production direction.
- The funded frontier piece is native STARK verification at the chain anchor, plus batching so one proof covers many claims.

## What The Raise Builds

- Production STARK backend choice: Plonky3/BabyBear/Poseidon2 or another audited STARK stack with an on-chain path.
- Native verifier strategy: direct FRI verifier, verifier precompile/app-chain, or regulated off-chain verification with commitment anchoring.
- Batch proving: one proof per batch, not one proof per claim.
- Nullifier non-membership integration in the STARK batch proof.
- External cryptographic audit.
- Domain ratification of adjudication gates and remittance-code behavior.

## Plain-English Bottom Line

Groth16 proves the app idea works today, but it is not quantum-resistant. STARKs are the smart production bet because they avoid trusted setup and are PQ-capable, but the on-chain verifier is the expensive frontier. Until that verifier exists, the honest position is "parallel STARK proof core built; PQ-at-anchor pending."
