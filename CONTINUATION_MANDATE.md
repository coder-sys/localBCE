# Continuation mandate

Updated: 2026-08-08

Continue only from the architecture in `docs/DATABASE_ZK_ARCHITECTURE.md`.

## Non-negotiable decisions

1. The state-owned database is authoritative for workflow and payment state.
2. ZK is mandatory whenever private evidence drives an automated payment decision.
3. The native verifier result and the resulting state mutation are one fail-closed atomic operation.
4. Exact policy, ruleset, oracle, claim-source, state-before, state-after, value-conservation, and settlement commitments remain bound.
5. The fixed 12-field Privacy V2 ABI, fixed-shape privacy, SHA3-512 authority, M31/Fp16 proof core, interactive public coin, and dual-PQ signatures remain.
6. No L2 or rollup is being built.
7. Ethereum is outside Phase 0-2. Any later L1 checkpoint is additive and cannot become the operational database.

## Recovery order

After interruption or compaction, read:

1. `AGENTS.md`
2. the newest `STATE.md` entry
3. `docs/DATABASE_ZK_ARCHITECTURE.md`
4. `docs/CURRENT_TECH_STACK.md`
5. `docs/IMPLEMENTATION_ROADMAP.md`
6. `docs/PQ_ZK_SECURITY_ARCHITECTURE.md`

Historical documents describe evidence and rejected paths; they are not current architecture authority.

## Stop conditions

Stop rather than guess if proof-to-state atomicity, authoritative roots, retry/idempotency behavior, anti-rollback, signer authority, proof-suite identity, or production activation state cannot be established from repository evidence.
