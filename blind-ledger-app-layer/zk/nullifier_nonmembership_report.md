# Nullifier Non-Membership Circuit Run Report

Status: soundness-checked by local tests and static analysis, PENDING CRYPTOGRAPHIC AUDIT. The circuit is standalone and is not wired into `claim_adjudication_core` or the app-layer adjudication path.

## Tooling

- Node: v24.16.0.
- npm: 11.13.0.
- snarkjs: 0.7.6.
- circom: 2.2.3.
- circomspect: local 0.9.0 binary.
- Foundry: forge/anvil 1.7.1.
- Rust: cargo/rustc 1.96.0.
- Python: 3.14.4.

## npm Audit Cleanup

- Initial audit during this cleanup: 13 low, 3 moderate, 3 high, 0 critical.
- `npm audit fix`: no automatic safe fix; the suggested force path would change `circomlibjs` in a breaking way.
- Applied safe overrides: `bfj@9.1.3`, `underscore@1.13.8`, `ws@8.21.0`.
- Final audit: 15 low, 0 moderate, 0 high, 0 critical.
- Remaining findings are low-severity transitive `ethers` / `elliptic` findings through `circomlibjs@0.1.7`; not force-upgraded because that would risk breaking circom/snarkjs tooling.
- Existing `claim_adjudication_core` still compiles and verifies proof `approved.after_audit`: OK.

## Construction

Circuit: `circuits/nullifier_nonmembership.circom`.

Construction used: indexed Merkle-tree non-membership proof over a depth-32 sparse tree, with Poseidon hashes. The witness supplies the predecessor leaf and Merkle path. The circuit enforces `leafValue < nullifier < nextValue`, recomputes the predecessor leaf hash, constrains every path direction bit, recomputes the Merkle root, and constrains the reconstructed tree index to equal `leafIndex`.

Why this construction: indexed-tree non-membership is a standard auditable pattern for proving a key falls in an open interval between adjacent indexed leaves, while binding that interval to a committed tree root.

## Circuit Build

- Template instances: 148.
- Non-linear constraints: 8,398.
- Linear constraints: 9,311.
- Public inputs: 2 (`root`, `nullifier`).
- Private inputs: 68.
- Wires: 17,737.
- Labels: 26,215.
- Total constraints: 17,709.

## A/B/C Results

- Test A, fresh nullifier 20 in interval `(10, 30)`: witness calculation passed, witness check passed, proof generated, proof verified.
- Test B, duplicate nullifier 10 already present: rejected. Witness calculation failed at the strict interval assertion (`nullifier < nextValue`), witness check failed, proof generation failed.
- Test C, tampered witness for present nullifier 10 with forged interval `(0, 30)`: rejected. Witness calculation failed at the Merkle-root binding, witness check failed, proof generation failed.

## Soundness Checks

- `snarkjs wtns check`: passed for fresh witness; duplicate and tampered witnesses rejected.
- `snarkjs zkey verify`: passed for `keys_nullifier/nullifier_nonmembership_final.zkey`.
- `snarkjs groth16 verify`: passed for fresh proof.
- `circomspect`: no issues found.

Constraint reasoning:

- Range: `nullifier`, `leafValue`, `nextValue`, `leafIndex`, and `nextIndex` are constrained to 32 bits.
- Interval: predecessor and successor checks are strict, so an existing nullifier equal to a boundary cannot pass as fresh.
- Position: every `pathIndices[i]` is boolean and the reconstructed bit-index is constrained to equal `leafIndex`.
- Root binding: the predecessor leaf and every Merkle level are Poseidon-hashed to the public `root`; a forged interval at a real position fails root equality.

This is not a production security sign-off. Circomspect and snarkjs checks catch many unconstrained-signal and malformed-artifact failures, but they do not prove the non-membership design is conceptually flawless. Human ZK audit is required before wiring into the live path.

## App Layer Regression Check

- Rust rules engine: 27 total tests passed (23 unit, 4 integration/doc-test buckets as reported by cargo), 0 failed.
- Python app tests: 40 passed, 0 failed via `unittest`; `pytest` is not installed.
- Forge contracts: 10 passed, 0 failed.

