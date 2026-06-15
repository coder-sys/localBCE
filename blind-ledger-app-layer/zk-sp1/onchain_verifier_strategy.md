# SP1 On-chain Verifier Strategy

Status of this run: SP1 guest execution worked, but local SP1 core proving did not complete on this machine. The prover was OOM-killed by WSL before producing the first proof. Therefore there is no measured SP1 wrapped EVM proof gas number from this run.

Ceiling label: soundness-checked work only after proof generation and verifier checks pass, PENDING CRYPTOGRAPHIC AUDIT. Nothing here is production-secure or domain-ratified.

Important PQ caveat: SP1 core proofs are STARK-style and do not need a trusted setup. SP1's normal EVM path wraps the proof in Groth16 or PLONK for cheap Solidity verification. That wrap is pairing-based, so the on-chain trust anchor is not post-quantum. Do not call SNARK-wrapped SP1 end-to-end PQ.

Measured numbers available from this run:

- Existing Groth16 app-layer Forge test, accepted proof path: 2,312,072 gas.
- Existing Groth16 app-layer Forge test, tampered public input rejection path: 2,214,770 gas.
- These are real Forge numbers from the existing app-layer contracts, not SP1 EVM verifier numbers.
- SP1 EVM accepted-proof gas: not measured, blocked by local SP1 proof generation/wrap prerequisites.
- SP1 EVM tampered-rejected gas: not measured, blocked by local SP1 proof generation/wrap prerequisites.

## Option A: SNARK-wrap for EVM

What it is: Prove the adjudication in SP1, then wrap the SP1 proof into Groth16 or PLONK so an EVM contract can verify it cheaply.

Gas/cost:

- This run did not measure SP1 wrapped EVM gas.
- The current non-SP1 Groth16 verifier path in the app-layer measured 2,312,072 gas for accepted proof recording and 2,214,770 gas for tampered public input rejection.
- A SNARK wrap is usually the cheapest practical EVM route compared with native FRI/STARK verification, but the exact SP1 number still needs to be measured locally or through the Succinct prover path.

PQ status at on-chain trust anchor:

- Not post-quantum at the EVM anchor.
- The inner SP1 proof may be STARK-style, but the EVM-verified wrapper is Groth16 or PLONK, which relies on pairing-based elliptic-curve assumptions.

Build effort:

- Medium if using SP1's supported wrap flow and prover network.
- Harder locally because wrapping needs heavy RAM and native dependencies.
- This machine hit WSL RAM limits before core proof generation completed.

Audit burden:

- Audit the adjudication guest.
- Audit public-value encoding and verifier binding.
- Audit wrapper verification and contract integration.
- Still requires regulatory review because cryptographic correctness does not prove Medi-Cal policy correctness.

Best use:

- Demo, near-term EVM compatibility, and cheap public verification when full PQ-at-anchor is not mandatory.
- Not the final answer if the federal payment L2 requires a post-quantum on-chain trust anchor.

## Option B: Native FRI/STARK verifier contract

What it is: Verify the STARK proof directly on-chain using a native FRI/STARK verifier instead of wrapping into Groth16 or PLONK.

Gas/cost:

- No measured gas number from this run.
- Expected to be much higher than SNARK wrapping because FRI verification is hash-heavy and calldata-heavy.
- The exact number must be measured with the specific verifier, field, hash, proof format, and target chain. Do not rely on generic estimates.

PQ status at on-chain trust anchor:

- Post-quantum at the on-chain trust anchor if the verifier is truly hash-based and avoids pairing-based wraps.
- This is the cleanest end-to-end PQ route.

Build effort:

- High.
- Needs expert implementation or a mature system with a production-grade Solidity verifier.
- Not a one-shot Codex task.

Audit burden:

- Very high.
- Requires ZK cryptography audit, Solidity audit, gas griefing review, calldata review, and integration review.
- Also requires regulatory review of the adjudication logic.

Best use:

- Long-term route if the requirement is "the chain itself verifies a post-quantum proof."
- Not the fastest route to a working product.

## Option C: Off-chain verification in secure gov environment, on-chain commitments plus attestation

What it is: Generate and verify STARK proofs off-chain inside a controlled government or approved operating environment. Put only commitments, batch roots, timestamps, and attestations on-chain.

Gas/cost:

- No SP1 EVM proof gas needed because the chain is not verifying the full proof.
- On-chain cost becomes mostly storage, events, hashing, and signature or attestation checks.
- This run did not measure a dedicated attestation contract.

PQ status at on-chain trust anchor:

- Depends on the attestation scheme.
- If the on-chain anchor is only a conventional signature, it is not automatically PQ.
- If the chain stores commitments and the PQ proof is verified off-chain, the cryptographic proof can be PQ, but the chain is trusting the attesting environment rather than independently verifying the proof.

Build effort:

- Medium for the first version.
- Requires secure operations, key management, audit logs, role controls, and clear incident procedures.

Audit burden:

- Infra/security audit instead of pure verifier audit.
- Need controls around who can attest, what gets logged, what gets re-run, and how disputes are handled.
- Still needs regulatory review of the rules.

Best use:

- Practical federal-payment architecture if cheap public EVM verification and end-to-end PQ are in tension.
- Works well with batching and compliance/audit trails.

## Recommendation

Use a hybrid architecture:

1. Short-term: keep the existing Groth16 verifier path only as an EVM-compatible demo and comparison baseline.
2. Build the production path around batches, commitments, and off-chain proof verification in a controlled environment.
3. Anchor batch roots on-chain, not every individual claim proof.
4. If a public EVM proof is needed, verify one aggregate proof per batch, not one proof per claim.
5. Treat native FRI/STARK on-chain verification as a careful-track research and audit project.

The core reason: 2.3 million gas per proof is too expensive if paid per claim. The architecture should make one expensive verification cover many claims, or move full proof verification off-chain and put only compact commitments on-chain.

## Concrete gas-reduction plan

1. Stop verifying one proof per claim on-chain.

   The current model makes every claim pay the fixed verifier cost. That is the bloat. If one proof costs about 2.3 million gas, then 1,000 claims costs about 2.3 billion gas before normal registry/payment overhead. That does not scale.

2. Batch claims.

   Create a batch containing many claim commitments. For example, each claim contributes:

   - claim commitment
   - adjudication decision
   - failure gate or denial code
   - payment amount or zero
   - nullifier
   - timestamp or batch id

   Build a Merkle tree over those per-claim records. Put the Merkle root on-chain.

3. Prove the batch, not the claim.

   The proof should say: "For every claim inside this batch root, the rules engine was applied correctly, duplicate/nullifier checks were applied, and the published result root matches the private claim data."

   Then the chain verifies one proof for N claims.

   Effective gas per claim becomes:

   - fixed proof verification gas divided by batch size
   - plus cheap per-claim inclusion or settlement overhead

   If one verification is 2.3 million gas and the batch has 1,000 claims, the fixed verification part becomes about 2,300 gas per claim before the rest of the contract work. That is the architectural way out.

4. Store less on-chain.

   Do not store the full claim, full proof, full denial text, or all metadata on-chain.

   Store:

   - batch root
   - result root
   - nullifier root
   - verifier key id
   - policy/ruleset version
   - attester/prover id if using off-chain verification
   - compact event logs

   Keep detailed claim data in the secure off-chain environment.

5. Use Merkle inclusion for disputes and lookups.

   If someone needs to prove claim X was included in batch Y, they submit the leaf plus a Merkle path. That is much cheaper than verifying a whole ZK proof per claim.

6. Net payments by batch.

   Do not trigger a separate heavy on-chain payment action for every approved claim. Produce a batch payment root or net settlement instruction. The payment rail can consume the batch output.

7. Separate "audit truth" from "payment execution."

   The ZK proof should attest correctness of adjudication. Payment execution can be a simpler on-chain/off-chain workflow keyed by batch result roots.

8. Keep claim-level rechecks off-chain unless disputed.

   Normal path: batch root and attestation.

   Dispute path: reveal one claim leaf, inclusion proof, and the minimal supporting audit data needed for review.

9. Use L2 or app-rollup settlement.

   If every verification must be public and on-chain, do it on an L2 or app-specific rollup, then settle a compressed root to L1. Do not run federal payment volume directly through a per-claim L1 verifier.

10. Decide the PQ trust-anchor requirement explicitly.

    - If "PQ proof exists somewhere" is enough: off-chain STARK verification plus on-chain commitments may be acceptable.
    - If "the chain independently verifies PQ proofs" is required: native FRI/STARK verifier is the right direction, but it is expensive and audit-heavy.
    - If "cheap EVM verification now" is required: SNARK wrap is practical, but not PQ at the chain anchor.

Bottom line: the way out of 2.3 million gas per proof is not shaving tiny Solidity operations. The way out is batching, aggregation, and anchoring roots instead of per-claim proofs.
