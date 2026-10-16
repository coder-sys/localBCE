# RightRail Database And State Ownership Crosswalk

This crosswalk adapts selected ownership concepts from the external
`RightRail-handoff-2026-10-03_0916` package. It does not import, open, migrate,
or depend on the RightRail SQLite database.

| RightRail concept | localBCE owner | Integration rule |
| --- | --- | --- |
| SQLite `FinancialOwner` | `bridge/rightrail_offchain.py` adaptation | The external SQLite code stays inactive. A localBCE-owned append-only JSONL journal ports only the single-writer, hash-linked history, idempotency, and replay controls. |
| Rules, sources, extraction, review | PostgreSQL rules corpus | PostgreSQL remains the sole bulk rules/source/review database. It does not own proof or settlement state. |
| Adjudication | `rust-engine` | Rust remains the active adjudication boundary. Hardcoded G1-G10 remains its default rules backend. |
| Off-chain operational history | `bridge/rightrail_offchain.py` | One writer records proof-free adjudications and synthetic redacted remittance events. Projections are rebuilt from the journal. |
| Retained proof and chain code | Dormant Groth16/STARK folders | `proof_execution_enabled=false`; no RightRail database or adapter may activate or write proof/contract state. |
| Review UI or analytics | Read-only projections | A UI, support tool, verifier, replay tool, or analytics process never becomes an authoritative writer. |

## Non-Negotiable Boundaries

- No second active writer is introduced for any localBCE state domain.
- No cross-database transaction or two-phase-commit dependency is introduced.
- Rules PostgreSQL records never mutate adjudication or ledger state directly.
- The bridge never treats an external RightRail SQLite row as authority.
- Read-only replay and verification may compare state, but may not repair it
  or append compensating events without an explicit authorized command.
- RightRail archives, Git refs, patches, executables, and SQLite artifacts remain
  external, inactive, and hash-pinned.

The selected mapping is an active localBCE adaptation, not an activation of the
external runtime. The JSONL journal is authoritative only for off-chain
operational reconciliation; it has no proof, chain, treasury, or payment power.
