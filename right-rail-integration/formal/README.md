# Isolated Formal Lane

This directory contains localBCE-specific specifications derived from reviewed
RightRail control evidence. It is excluded from runtime builds and has no proof,
settlement, rules, or activation authority.

- Lean is pinned by `lean-toolchain` to `v4.33.1`.
- `LocalBCE/Settlement.lean` states small settlement and authorization lemmas.
- `Settlement.tla` models the journal progression and fail-closed retry guards.
- `settlement_model_v1.json` drives an independent exhaustive Python check.

Passing these artifacts qualifies only this formal lane. It does not establish
runtime equivalence, cryptographic correctness, production readiness, or legal
approval. The Python model is a deterministic fallback validation when Lean or
TLC is unavailable; it is not presented as a Lean/TLA build.
