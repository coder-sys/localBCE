# Blind Ledger ZK Batch Nullifier Audit Handoff

Label: soundness-checked, PROTOTYPE, PENDING CRYPTO AUDIT.

## Phase 1: Multi-Claim Circuit

Path: `zk/batch_multiclaim/batch_nullifier_nonmembership.circom`

Construction: fixed-N indexed Merkle non-membership. For each claim i, the circuit proves an old predecessor leaf is in root_i, proves `predecessor.value < nullifier_i < predecessor.nextValue`, updates the predecessor to point to the new nullifier, proves the insertion slot is empty, inserts the new leaf, and emits root_i+1. The next claim consumes root_i+1. Public inputs are `rootBefore`, `rootAfter`, and `batchNullifierCommitment`. Private inputs are the N nullifiers and the predecessor/insertion Merkle witnesses.

What is genuinely constrained: all N nullifier transitions. This is not "prove one, claim N." The largest locally proven N is 8.

What is assumed: the app computes nullifiers correctly from claim data; pepper/key management is correct; the eventual contract adapter binds the circuit's nullifier commitment to claim/result/payment roots; local prototype Groth16 setup is not production ceremony.

Scaling table:

| N | Constraints | Proof size | Witness | Prove | Verify | Result |
|---|---:|---:|---:|---:|---:|---|
| 4 | 293,812 | 805 bytes | 553 ms | 11,689 ms | 678 ms | ACCEPTED |
| 8 | 587,624 | 806 bytes | 937 ms | 21,286 ms | 665 ms | ACCEPTED |

Wall: N=16 was not attempted after N=8 because N=8 already required pot20. N=16 is expected to require pot21 based on linear scaling, and earlier pot20 phase2 preparation consumed roughly 104 minutes locally. Treat N=8 as the largest genuinely proven local N in this run, not a production limit.

Required tests at chosen N=8:

| Test | Result | Evidence |
|---|---|---|
| all distinct nullifiers | ACCEPTED | snarkjs verify OK |
| one duplicate already in tree | REJECTED | witness assert failed |
| in-batch repeat | REJECTED | witness assert failed |
| tampered sub-witness | REJECTED | witness assert failed |

Additional executed attacks:

| Attack | Result | Evidence |
|---|---|---|
| reorder nullifiers but keep old witnesses | REJECTED | witness assert failed |
| zero padding slot | REJECTED | witness assert failed |
| field modulus/wraparound nullifier | REJECTED | witness assert failed |
| cross-batch gap root | REJECTED | witness assert failed |
| cross-batch overlap | REJECTED | witness assert failed |
| insert-index witness malleability | REJECTED | witness assert failed |
| N=1 boundary | ACCEPTED | snarkjs verify OK |
| N=0 boundary | REJECTED before circuit | input builder rejects empty batches |

## Phase 2: Aggregation Prototype

Path: `zk/batch_agg/aggregation_attempt_report.json`

Status: walled clean at local tooling. No aggregate proof was generated.

Method attempted: local snarkjs/circom recursion capability check. snarkjs 0.7.6 exposes Groth16/PLONK/FFLONK setup, prove, verify, and Solidity verifier export, but no folding or aggregation command. Local circomlib contains primitives such as Poseidon, bitify, comparators, EdDSA, SMT, and SHA-256, but no Groth16 verifier circuit, pairing verifier, Miller loop, final exponentiation, or recursive aggregation template.

Conclusion: aggregation is cloud/audit-track here. A real aggregation build needs a supported recursion stack or a circuit-level verifier for the sub-proof system. Hashing sub-proof files or sampling one proof would be fake security, so this run did not do it.

## Head-to-Head

| Path | Local result | Production suitability here | Main reason |
|---|---|---|---|
| Multi-claim circuit | N=8 proved and attacked | Better near-term path | Simple fixed-N circuit, directly constrains all N transitions |
| Recursive aggregation | N=0 aggregated | Not local-ready | Missing recursion/folding tooling in this stack |

Recommendation: use the multi-claim circuit path first. Scale by compiling audited fixed sizes such as N=8, N=16, N=32, or powers of two with padding explicitly constrained. Keep aggregation as a later specialist track.

## Fresh Attack Surfaces

1. Pepper rotation can reopen duplicates. Executed check: same BL-CLAIM-0001 under pepper_epoch_A and pepper_epoch_B produced different duplicate nullifiers. Fix: govern pepper epochs and keep historical epochs active until migrated.
2. Proof-to-claim binding is not complete yet. The circuit proves nullifier roots and a batch nullifier commitment, but the current registry inputs do not include `batchNullifierCommitment`. A future adapter must bind claim/result/payment roots to the same nullifier set.
3. Verifier-key mismatch was blocked. Executed checks: N4 proof under N8 vkey and N8 proof under N4 vkey both returned invalid proof.
4. Public-input length is loose. `BatchClaimsRegistry._batchInputsMatch` accepts `batchInputs.length >= 7`; a real verifier adapter should require exact length per verifier key.
5. Trusted setup is prototype-only. pot19/pot20 files are local artifacts, not a production MPC/beacon ceremony.

## Auditor Attack List

Attack first:

1. The two-path insert transition: predecessor update root and empty insertion slot root must be impossible to fake.
2. Claim-to-nullifier binding: prove the nullifier in the ZK circuit is the same duplicate key embedded in claim/result leaves.
3. Pepper epoch migration and historical duplicate checks.
4. Public-input ordering and exact-length enforcement in the future Solidity adapter.
5. Setup provenance and toxic-waste assumptions.
6. Whether fixed-N padding can be safely added without introducing zero/null slots.
7. Whether root stitching across batches remains safe under concurrent submitters and delayed proofs.

Production status: not wired live, not production-secure, and not domain/audit-ratified.
