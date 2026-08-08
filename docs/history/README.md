# Blind Ledger historical documentation

Updated: 2026-08-02

Status: non-executable audit history. Files in this directory preserve former active documents
verbatim except for an `Archived` title marker. They can explain provenance, rejected decisions,
and measurement lineage but cannot authorize implementation or restore a retired path.

## Authority rule

Use current source, fail-closed tests, the newest verified `STATE.md` section,
`CURRENT_TECH_STACK.md`, `ARCHITECTURE.md`, and the active `IMPLEMENTATION_ROADMAP.md` for work.
Never execute a `next`, `current`, `remaining`, `rerun`, or `resume` sentence found here.

## Archived documents

| File | Preserved scope | Active replacement |
| --- | --- | --- |
| `IMPLEMENTATION_ROADMAP_THROUGH_2026-08-01.md` | Former 2,072-line roadmap, package narrative, dated runs, and superseded execution language | `../IMPLEMENTATION_ROADMAP.md` |
| `BL_PQ512_THROUGHPUT_RECOVERY_PLAN_THROUGH_2026-08-01.md` | Former recovery research, intermediate profiles, measurements, and dated closure records | `../BL_PQ512_THROUGHPUT_RECOVERY_PLAN.md` |
| `BL_PQ512_HETEROGENEOUS_HASH_COPROCESSOR_THROUGH_2026-08-01.md` | Former architecture evolution from early controls through H4 | `../BL_PQ512_HETEROGENEOUS_HASH_COPROCESSOR.md` |
| `BL_PQ512_CRYPTO_CORE_README_THROUGH_2026-08-01.md` | Former crate checkpoint narrative and superseded measurements | `../../experiments/bl_pq512_crypto_core/README.md` |
| `PROVING_OPTIMIZATION_REVIEW_THROUGH_2026-08-01.md` | Former paper screen, experimental mechanisms, and superseded prototype order | `../PROVING_OPTIMIZATION_REVIEW.md` |

Chronological cross-document evidence remains in dated `STATE.md` sections. Architectures that are
affirmatively rejected are indexed in `../REJECTED_ARCHITECTURES.md`. Exact pre-split bytes remain
recoverable from Git commit `e640e88` and its parents.

Some preserved files still contain `authoritative`, `current`, or `next` wording that was accurate
at the time they governed the workspace. The `Archived` title marker and the authority rule above
override those historical words; they do not authorize present implementation.
