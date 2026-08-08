# Blind Ledger

Blind Ledger is a private payment-decision system built around a state-owned database and mandatory zero-knowledge proofs.

A payment-relevant decision is accepted only when the pinned native verifier accepts the private proof and the database applies the corresponding state transition atomically. Signed government and oracle records provide authenticated inputs. The application proof hides private claim data while binding policy, source, replay protection, value conservation, and settlement commitments.

This repository is research and nonactivating: `proofSuiteId` is null, `production_usable=false`, and real PHI/payments are forbidden.

Start with:

- `docs/DATABASE_ZK_ARCHITECTURE.md` for the system boundary.
- `docs/CURRENT_TECH_STACK.md` for implemented components.
- `docs/IMPLEMENTATION_ROADMAP.md` for Phase 0-2 scope.
- `docs/PQ_ZK_SECURITY_ARCHITECTURE.md` for cryptographic detail.
- `QUICKSTART.md` for local verification.

The published source-complete archive intentionally omits the full-workspace continuation records
`STATE.md` and `WAVE2_HANDOFF_2026-07-26.md`; use the current documents and
`RELEASE_FILE_MANIFEST.json` when working from the archive.

No L2 is part of the design. Ethereum may later receive periodic compact checkpoints directly on L1, but it is not a Phase 0-2 dependency.
