# Blind Ledger Stwo batch AIR experiment

This isolated experiment proves and verifies a deliberately narrow Blind Ledger batch statement
with official Stwo. It does not replace the selected 12-field Privacy V2 application ABI, a complete
claim AIR, or a production verifier.

Current role: validity/performance control only. The active release path is the heterogeneous
semantic-STARK/shared-bus/Boolean-GKR construction in
`../../docs/BL_PQ512_HETEROGENEOUS_HASH_COPROCESSOR.md`; this experiment's QM31/Blake2s and
non-hiding defaults remain rejected for that path.

For each claim row, the AIR enforces:

- `decision` is exactly zero or one.
- `approved = requested * decision`.
- `paid = approved`.
- The approved and paid running totals transition through a LogUp relation.
- The LogUp claimed sum reconciles the trace with the public initial and final totals.

Claim rows are represented in Stwo's SIMD backend, which processes packed M31 lanes, and the
prover is built with Stwo's Rayon `parallel` feature. The dependency is a workspace-vendored copy
of exact upstream commit `aeceb74c58184d7886ebd7f34a7453fee714ca40`, with one allocator-safety
patch documented in `VENDORED_STWO_PATCH.md`.

Run from WSL:

```sh
CARGO_TARGET_DIR=/tmp/blind-ledger-stwo-target \
  cargo run --release --manifest-path experiments/stwo_batch_air/Cargo.toml \
  --bin blind-ledger-stwo-batch-air -- \
  --claim-count 1024 --threads 16 --security-mode validity-only
```

The mode witness-hiding-required fails with WITNESS_HIDING_UNAVAILABLE
before claims or trace columns are allocated. The default remains
validity-only for the pinned synthetic baseline.

The sealed R25 rerun passed format, compile, strict Clippy, 12 unit tests, and one allocator
integration test. Its 1,024-row validity-only execution reported `0.118095s` proving and
`0.000956s` verification with `proof_verified=true`, `witness_hiding=false`, and security scope
`aggregate_decision_and_value_conservation_only`. The paired hiding-required execution exited
nonzero with `WITNESS_HIDING_UNAVAILABLE` and emitted no claim-generation, trace, commitment, or
proof timing. No proof artifact was retained.

Z02 currently provides only a standard-library fail-closed entropy interface,
stable ENTROPY_FAILURE, and an owned byte buffer erased on explicit clearing
and drop. The OS provider is deliberately unwired, deterministic filling is
compiled only in unit tests, and entropy is not connected to proof masks.

Committed-oracle inventory: the main trace, LogUp interaction trace,
composition polynomial and splits, OODS samples and quotients, every FRI
layer, and queried trace and interaction values currently have no hiding
coverage. Z03-Z12 cryptography remains blocked pending field, PCS/FRI, QROM,
simulator, and independent hiding review.

Security boundary: this proof does not bind claim identities, governed Merkle roots, policy
evidence, nullifiers, the selected 12-field statement, encrypted data, or the authoritative wide
sidecar/state. It has no native witness hiding. Its QM31/Blake2s/default proof configuration is
explicitly rejected for the `BL-PQ512-v1` security target in
`docs/BL_PQ512_SECURITY_FREEZE.md`. This crate remains a measured validity and throughput prototype,
not a private or production prover.

`src/checked_money.rs` is a dependency-free host reference for exact u32 values, 16-bit limbs,
checked u64 K128/K256/K512 aggregates, and debit/credit/payable conservation. It prevents the
earlier single-M31 aggregate mistake from returning. It is not wired into trace columns or AIR
constraints and therefore is not physical-AIR qualification evidence.
