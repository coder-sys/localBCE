# RightRail Database And State Ownership Crosswalk

This crosswalk adapts selected ownership concepts from the external
`RightRail-handoff-2026-10-03_0916` package. It does not import, open, migrate,
or depend on the RightRail SQLite database.

| RightRail concept | localBCE owner | Integration rule |
| --- | --- | --- |
| SQLite `FinancialOwner` | Operational-state reference only | The single-writer and atomic-history ideas may inform tests; SQLite is not an active localBCE store. |
| Rules, sources, extraction, review | PostgreSQL rules corpus | PostgreSQL remains the sole bulk rules/source/review database. It does not own proof or settlement state. |
| Adjudication and proof inputs | `rust-engine` | Rust remains the active adjudication boundary. Hardcoded G1-G10 remains its default rules backend. |
| STARK proof and nullifier state | Rust/STARK state files and settlement journal | Existing compare-and-swap, finality, reconciliation, and recovery behavior remains authoritative. |
| On-chain claim and root state | Existing Groth16 and governed STARK contracts | No RightRail database or adapter may write contract state. |
| Review UI or analytics | Read-only projections | A UI, support tool, verifier, replay tool, or analytics process never becomes an authoritative writer. |

## Non-Negotiable Boundaries

- No second active writer is introduced for any localBCE state domain.
- No cross-database transaction or two-phase-commit dependency is introduced.
- Rules PostgreSQL records never mutate proof or settlement state directly.
- Proof and settlement code never treats a RightRail SQLite row as authority.
- Read-only replay and verification may compare state, but may not repair it
  without an explicit, existing localBCE recovery command and authorization.
- RightRail archives, Git refs, patches, executables, and SQLite artifacts remain
  external, inactive, and hash-pinned.

The selected mapping is therefore conceptual: it ports the one-writer, atomic
history, idempotent retry, and independent replay guarantees into localBCE
review evidence without making RightRail an active dependency.
