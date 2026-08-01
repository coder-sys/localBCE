# BLH-001: wide challenge and proof commitments

Priority: critical

Status: conditional architecture proposal; not an activated suite.

Current disposition: selected as a requirement inside the heterogeneous construction in
`docs/BL_PQ512_HETEROGENEOUS_HASH_COPROCESSOR.md`. It applies to the semantic PCS, shared-bus hiding
PCS, Boolean-GKR challenges, authenticated transcript, and atomic verifier; it does not imply that
the suite has qualified.

## Problem

QM31 supplies less than 124 raw classical bits to field-error events and Blake2s-256 supplies only
about 85.33 idealized quantum collision bits. Queries and grinding cannot repair either ceiling.

## Proposal

Retain M31 semantic trace columns and SIMD FFTs. Use the pinned degree-16 tower for semantic-STARK,
shared-bus, bridge, GKR/sumcheck, OODS, and FRI challenge work. Replace every Merkle and PCS digest
with full-width SHA3-512 under typed, length-delimited domains. Use the PQ-authenticated interactive public-coin
transcript in `docs/BL_PQ512_S09_INTERNAL_SOLUTION.md`, pin the complete suite outside the proof, then
absorb its identity, all 12 fields, and the fixed sidecar before the first challenge.

Use only an interactive Circle-FRI regime and query layout covered by the invoked theorem. Give
grinding zero security credit. Require a conservative pre-code AIR envelope and recalculate every
round, retry, and abort term from the completed AIR and challenge-service policy before release.

## Alternatives

- Four independently repeated QM31 checks may reuse mature arithmetic, but need their own parallel-
  repetition proof and likely multiply proof work.
- A wide different base field would abandon the measured M31 advantage and is not preferred without
  evidence that the degree-16 route fails.
- Octic extension and current Blake2s are rejected.

## Acceptance evidence

- irreducibility and canonical encoding proof for the field tower;
- unbiased challenge-sampling vectors across independent implementations;
- theorem-instantiated LogUp, composition, OODS, batching, fold, and query bounds;
- SHA3-512 leaf/node/transcript KATs with domain-collision negative tests;
- verifier rejection of every suite/config mutation before allocation;
- Python/Rust/Cairo/RISC/S-two semantic parity where applicable; and
- internal cryptographic qualification followed by independent review of the sealed release.
