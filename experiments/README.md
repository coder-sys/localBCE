# Experimental implementations

The active native-v3 work is:

- `native_v3_phase0/` and `native_v3_phase0_rust/`: five-directive canonical business KATs.
- `native_v3_trust_boundary/` and `native_v3_trust_boundary_rust/`: interactive framing,
  authentication, and independent parsing profile.
- `native_v3_plaintext_continuity/`: synthetic read-only provider credential/enrollment wedge.
- `native_v3_dp_nucleus/`: ideal-vector-oracle research only; not a proof backend.

The BL-PQ512, H4/CUDA, fixed-shape, Privacy V2, binary-field, and Binius64 directories are retained
code evidence. Their former design claims are retired. They cannot select a backend, qualify a
suite, authorize PHI or payments, or activate production.

Current authority is `ARCHITECTURE.md`, `docs/NATIVE_V3_ARCHITECTURE.md`,
`docs/DATABASE_ZK_ARCHITECTURE.md`, and `CURRENT_TASK.md`.
