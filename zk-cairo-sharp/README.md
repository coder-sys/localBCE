# Cairo Native-STARK Binding Reference

This directory contains a hardened Cairo semantic/KAT reference. It is no longer the retired flat
trusted-flag prototype, but it is also not the active release proof lane. The current target is the
heterogeneous semantic-STARK/shared-bus/Boolean-GKR proof in
`../docs/BL_PQ512_HETEROGENEOUS_HASH_COPROCESSOR.md`.

## Status

- Scarb/Cairo target: Cairo 2 / Scarb 2.18.
- Entry points: `main` for one `MultiLineDecisionInput`, `batch_main` for `BatchClaimInput`.
- Commitments: domain-and-arity-bound Poseidon over the Cairo/Stark field.
- Facts: bound through governed oracle commitments, not raw free flags.
- Policy: fee and TAR membership are merged under governed `policyRoot`.
- Nullifiers: approved-only indexed-tree transitions with sentinel denied outputs.
- Generated proof artifacts: not packaged in this source handoff; regenerate locally when needed.
- Native database-boundary verifier integration: represented by the Rust candidate; production
  artifact audit, database qualification, and governance pin remain pending.
- Release role: differential semantics only; it cannot replace the shared bus, SHA3 coprocessor, or
  atomic BL-PQ512 verifier.

## Proof evidence

A previous developer checkout produced a real local Cairo proof checkpoint for this statement family. The generated proof JSON is intentionally excluded from this optimized source archive.

Use `PROOF_PROVENANCE.md` in the app-layer root for the current handoff-level proof note. Do not claim this archive contains proof evidence unless a proof is regenerated and verified in the current environment.
