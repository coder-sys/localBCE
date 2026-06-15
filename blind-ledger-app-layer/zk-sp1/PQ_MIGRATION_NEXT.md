# PQ Migration Next Steps

Status: proposed post-raise audit track. None of these items are production-ratified.

1. Poseidon2 over BabyBear for duplicate/nullifier construction
   - Replace the current BN254/Poseidon duplicate/nullifier path with a STARK-native field/hash design.
   - Target: Poseidon2 over BabyBear or the field/hash pairing recommended by the chosen STARK stack.
   - Done looks like: circuit/program implementation, cross-language test vectors, non-membership proof tests, and ZK auditor review.

2. SPHINCS+ / SLH-DSA oracle signatures
   - Add post-quantum signatures for external facts used by the proving path.
   - Target: signed eligibility/provider/ruleset/oracle payloads with deterministic public-key pinning and rotation.
   - Done looks like: key-management policy, replay protection, signature verification in the proving input path, and cryptography review.

3. Native STARK/FRI on-chain verification
   - Avoid the pairing-based Groth16/PLONK EVM wrap if the trust anchor itself must be post-quantum.
   - Target: native FRI/STARK verifier contract or a chain/runtime with native STARK verification support.
   - Done looks like: measured verifier gas/cost, formal verification of verifier contract, and external ZK audit.

4. Migration sequencing
   - Keep Groth16 live path untouched until the PQ path has full proofs, verification, and audit sign-off.
   - Run SP1/STARK proofs in parallel first, compare outputs against the canonical Rust engine, then decide on anchoring.
   - Treat regulatory correctness and cryptographic soundness as separate sign-offs.

Explicit caveat: SP1 proving is Plonky3/STARK and PQ-aligned off-chain, but SP1 EVM verification normally uses a Groth16/PLONK wrap. That EVM anchor is pairing-based and is not post-quantum.
