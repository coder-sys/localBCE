# Threat model (summary; full analysis is in the original plan)

Updated 2026-11-07: the proof and chain items below concern code now parked under
`parked/localbce/` (`RIGHTRAIL_BASE_PLAN.md`); they stay listed for anyone who revives it.

- Forged proofs (parked STARK code): the verifier accepted traces with unconstrained after-path siblings, claim-source limbs, nullifier preimage limbs, and oracle and fee-schedule claim limbs (D-02). PR #5 (merged at `bc50dd62`, now parked) fixes those five gaps and the fee and oracle presence flags and reserved zeros, each tested by modifying trace generation only and checking the unmodified verifier. The claim-source tags and presence flags are still asserted at row 0 only (not tested).
- Groth16 path (parked): circuit binds nothing (`valid <== 1`), and `submitVerifiedClaim` recorded claims on failed proofs (D-01). The runtime route was retired in PR #4; `groth16` is refused as a proof backend.
- Duplicate claims and payments: claim identity hashes claim_id and amount (N-03); remittance dedup uses a caller-chosen ID (N-04).
- Local key exposure: the Anvil key was in the default config (N-07). Removed from active config and code in Phase 1; it remains in Git history and in parked chain tooling. It is Anvil's public test key, not a secret.
- Off-chain journal: a second writer alongside RightRail's owner would split financial truth. Retire in Phase 4.
- Lock files: O_EXCL locks left by a crash block all writes (N-05, D-06).
