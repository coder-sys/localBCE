# Experimental implementations

This directory contains the sealed Wave 1 semantic references and the active Wave 2 proof
prototype. It is not production-activated or a settlement path.

The current integration target is
`docs/BL_PQ512_HETEROGENEOUS_HASH_COPROCESSOR.md`: sealed M31 semantic AIR plus one hiding committed
bus, masked Fp16 Boolean GKR SHA3 coprocessor, Construction 8.2 PCS, authenticated public coin, and
Rust-authoritative independent verifier. Standalone RISC Zero and Stwo source trees were removed
because they are not imported by or compatible with the selected proof boundary.

## Current implementation

- `fixed_shape_claim_air/`: sealed, nonactivating semantic relation and exact hash-call schedule.
- `bl_pq512_crypto_foundation/`: current cross-language semantic and cryptographic references.
- `bl_pq512_crypto_core/`: authoritative Rust proof core plus untrusted CUDA workers.
- `bl_pq512_hint_mlwe_392/`: Retired Gate 2E state/commitment research reference only; not an
  active gate or selected suite.

Removed backend evidence is retained in `../docs/REJECTED_ARCHITECTURES.md` and Git history, not as
buildable alternative stacks.

Read `docs/EXPERIMENTAL_PROVING_AND_PRIVACY.md` before evaluating performance or security claims.
