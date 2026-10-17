# Threat model (summary; full analysis is in the original plan)

- Forged proofs: STARK verifier accepts traces with unconstrained after-path siblings, claim-source limbs, and nullifier preimage limbs (D-02, D-03). Reproduced by modifying trace generation only, verified by the unmodified verifier.
- Groth16 path: circuit binds nothing (`valid <== 1`), and `submitVerifiedClaim` records claims on failed proofs (D-01). Fenced, not removed.
- Duplicate claims and payments: claim identity hashes claim_id and amount (N-03); remittance dedup uses a caller-chosen ID (N-04).
- Local key exposure: Anvil key in default config (N-07).
- Off-chain journal: a second writer alongside RightRail's owner would split financial truth. Retire in Phase 4.
- Lock files: O_EXCL locks left by a crash block all writes (N-05, D-06).
