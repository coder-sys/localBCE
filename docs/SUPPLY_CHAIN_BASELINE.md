# Supply-chain baseline

Updated: 2026-08-14
Owner: source, dependency, build, and release hygiene baseline. Detailed Python lock behavior belongs
to `docs/PYTHON_DEPENDENCY_LOCKING.md`; this document keeps only the cross-cutting rules.

This repository is developed and verified with existing offline Python and Rust toolchains.
Dependency acquisition is a separate reviewed activity; routine verification must not silently
resolve or download packages.

## Active requirements

- Use the checked-in Python dependency inputs and artifact locks described in
  `docs/PYTHON_DEPENDENCY_LOCKING.md`.
- Use Rust manifests with `--locked --offline` for current native-v3 independent verifiers.
- Treat full-width SHA3-512 source and artifact identities as authoritative.
- Keep generated outputs, Cargo targets, proof artifacts, logs, and private data outside release
  archives.
- Record the Git commit plus dirty-worktree scope for every run and archive candidate.
- Verify release archives with the deterministic builder, canonical ZIP/CRC readback, exact entry
  allowlist, byte length, and SHA-256.
- Never use real credentials, PHI, or payment data in this unqualified repository.

## Retained dependencies

Legacy BL-PQ512/H4/CUDA, Cairo, Privacy V2, and binary-field manifests remain only to reproduce
retained tests and differential evidence. Their presence does not select a production stack or
authorize network acquisition, GPU execution, backend qualification, or activation.

A production baseline remains open until the private or direct evaluator profile, production
database, key custody, source governance, reproducible build, license inventory, vulnerability
review, independent audit, and activation policy are selected and verified.
