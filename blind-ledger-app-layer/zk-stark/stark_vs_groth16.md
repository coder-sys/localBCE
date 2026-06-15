# STARK vs Groth16 Comparison

Status: working PQ STARK core, soundness-checked, PENDING CRYPTOGRAPHIC AUDIT.

The STARK core is a proof-of-concept alongside the existing Groth16 system. It does not replace the existing `zk/` circuit or app-layer contracts.

## Toolchain Status

| System | Status | Notes |
|---|---:|---|
| SP1 | Blocked | Official install docs state native SP1 runs are Linux/macOS. This host is Windows. |
| RISC Zero | Blocked | CLI not installed; Docker unavailable; current cargo-risczero docs note Docker is needed for the zkVM build path and prebuilt host targets are Linux/macOS. |
| Winterfell | Used | Rust crate `winterfell 0.13.1` compiled and produced/verifies STARK proofs on this Windows machine. |

## Gate Coverage

All ten normalized adjudication gates are covered:

- G1 member id present.
- G2 eligibility active.
- G3 provider NPI present.
- G4 provider enrolled.
- G5 service line present.
- G6 diagnosis present.
- G7 prior authorization ok.
- G8 charge positive and less than or equal to max charge.
- G9 duplicate flag false.
- G10 program integrity hold false.

The STARK AIR also constrains:

- u32 bit decomposition for charge, max charge, and comparison witnesses.
- first-failed-gate failure code.
- decision bit as the product of all gate pass bits.
- an AIR-bound algebraic claim commitment over the normalized private inputs.

Production TODO: replace the PoC algebraic commitment with an audited standard hash construction inside the AIR, such as Rescue/Poseidon/Blake3-style hashing appropriate for the chosen STARK field.

## Proof Results

| Case | Decision | Failure Code | Proof Size | Prove Time | Verify Time | Verified |
|---|---:|---:|---:|---:|---:|---:|
| approved | 1 | 0 | 103,809 bytes | 18.392 ms | 1.158 ms | yes |
| ineligible_denied | 0 | 2 | 100,913 bytes | 16.444 ms | 0.706 ms | yes |
| duplicate_denied | 0 | 9 | 100,591 bytes | 22.226 ms | 0.827 ms | yes |
| excessive_charge_denied | 0 | 8 | 103,675 bytes | 22.131 ms | 0.730 ms | yes |

Tampered public input test: flipping the approved proof's public decision bit is rejected.

No trusted setup was needed for the STARK proof core.

## Tradeoff Table

| Dimension | Winterfell STARK PoC | Existing Groth16 Core |
|---|---:|---:|
| Proof size | about 100-104 KB | about 983 bytes for approved proof JSON + public JSON |
| Approved prove time | 18.392 ms | 1,074.89 ms from existing snarkjs timing log |
| Approved verify time | 1.158 ms off-chain Rust verifier | 810.75 ms from existing snarkjs timing log |
| Trusted setup | none | required; existing dev Powers-of-Tau/zkey |
| Quantum resistance | yes, hash-based STARK assumption | no, pairing-based SNARK assumption |
| On-chain verifier | not available in this Winterfell PoC | works in Forge; real Groth16 proof test gas: 2,312,072 |
| EVM gas | unavailable | measured in existing Forge suite |
| Production audit status | pending cryptographic audit | pending cryptographic/regulatory audit |

## Pending List

- Human cryptographic audit of the STARK AIR and proof parameters.
- Regulatory review that the G1-G10 normalized logic correctly encodes Medi-Cal policy.
- Replace the PoC algebraic commitment with an audited production commitment.
- Port the nullifier non-membership circuit/logic to the STARK path.
- Pick and implement a real on-chain STARK verifier strategy.
- Decide whether to migrate fully, keep Groth16 for on-chain use, or use STARK off-chain with aggregation/wrapping.

## Sources Checked

- SP1 install docs: https://docs.succinct.xyz/docs/sp1/getting-started/install
- RISC Zero cargo-risczero docs: https://docs.rs/cargo-risczero/latest/cargo_risczero/
- Winterfell docs: https://docs.rs/winterfell/latest/winterfell/

