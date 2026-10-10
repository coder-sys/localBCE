# Inactive Post-Quantum Compatibility Lane

RightRail ML-DSA and other post-quantum material is represented only by the
hash-pinned records in
`../reports/handoff_20261003_pq_compatibility_v1.json`.

No signer, executable, library, preserved vector bytes, or production
dependency is copied from the handoff. The lane records format-family labels,
source hashes, and review blockers so future cryptographic review can reproduce
the source lineage without confusing it with an active implementation.

Production behavior is unchanged:

- controlled STARK attestations continue to use secp256k1;
- the STARK envelope remains 129 bytes;
- ML-DSA-87 is not accepted by contracts or runtime code;
- `runtime_eligible=false` and `proof_binding=false` apply to every record.
