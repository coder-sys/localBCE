# Current technology stack

Updated: 2026-08-14

## Active implementation

- Python 3.14 synthetic reference code and focused `unittest` suites.
- Rust independent parsers/verifiers for Phase 0 and the trust-boundary profile.
- Canonical injective byte grammars and full-width SHA3-512 identities.
- A verifier-owned deterministic `DIRECT_STATE_OWNED` provider continuity evaluator.
- One logical `ClearanceDecisionRow` joined exactly to chronological `StateAccessRow` records.
- A narrow `TrustBoundaryAdapter` that can later accept a qualified private-proof implementation
  without allowing caller-selected mode or downgrade.
- Local synthetic transactional database references in `app/`; none is a production selection.

## Conditional private-proof requirements

No backend is selected. Any future `PRIVATE_ZK` backend must be transparent, post-quantum,
setup-free, non-ECC, natively witness-hiding, fixed-shape, independently verifiable, and CPU-usable
under the 5,000,000,000-byte complete process-tree memory cap. It must close one honest finite
`<=2^-128` false-acceptance bound after all composition and union terms.

The trust-boundary profile supplies protocol framing and authentication evidence only. Its retained
DP24 ideal-vector-oracle calculation is nonproduction caveat evidence, not a proof backend.

## Approved formal kernel target

Lean 4 is approved for the executable clearance semantic and legal state-transition kernel. The
planned kernel covers canonical semantic decoding, the five directives, control-set evaluation,
authoritative absence, chronology, governed exceptions, observation-only separation, replay,
decision/access joins, and allowed after-state. Rust continues to own cryptographic proof
acceptance and the database continues to own concurrency and durability.

No Lean project or deployed formal kernel is implemented yet. Cross-language KATs and independent
parsers are evidence, not a refinement proof. The exact implementation and claim gates are in
`LEAN_FORMAL_KERNEL.md`.

## External system boundary

The State Control Pack owns approved deterministic controls. Mirror is the separate evidence and
reconciliation layer. Blind Ledger issues state-local clearance directives. The incumbent
adjudicates, and the official state payment system moves money. No L2 is in the current design.

## Retained compatibility code

Privacy V2, BL-PQ512/H4/CUDA, fixed-shape AIR, binary-field K128, Binius64, Cairo, and older batch
code remain for regression, differential comparison, or staged deletion. They are not the active
architecture and cannot supply production credit.

## Current flags

- `proofSuiteId=null`
- `production_usable=false`
- activation false
- private backend unselected
- synthetic-only
- no real PHI or payments
- no deployed formally verified kernel claim
