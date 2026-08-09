# Current technical stack

Updated: 2026-08-08

## Product architecture

Blind Ledger is a database-backed private payment system. Signed source records feed a fixed-shape claim relation. A mandatory application zero-knowledge proof must pass the native verifier before the database applies the payment transition atomically.

No L2, rollup, sequencer, bridge, Solidity settlement, or public data-availability layer is active or planned through Phase 2. Ethereum is only a possible later checkpoint destination.

## Application and state

- Python 3.14 application and adapters under `app/`.
- Canonical serialization and the frozen 12-field Privacy V2 boundary.
- Fixed-shape K128/K512 batches.
- SHA3-512 nullifier, accumulator, policy, ruleset, source, payment, and settlement bindings.
- `app/production_boundary.py` direct native-verifier-to-state transition seam.
- `app/transactional_database_boundary.py` qualification-only SQLite transaction, per-store keyed
  verifier authorization, submitter-bound state/provenance audit, replay, backup/restore, and
  write-ahead anti-rollback state machine; it is not a production database or custody selection.
- `app/privacy_v2_migration.py` plus the SQLite schema-v2 migration ledger: OS-random sealed fresh
  evidence, exact restart retry, in-transaction cutover compare-and-swap, immutable
  profile/domain history, rollback/recovery rotation, and atomic root/configuration publication.
- Fail-closed readiness, operator, oracle, audit, retry, and recovery checks.

## Proof system

- Rust proof candidate under `experiments/bl_pq512_crypto_core/`.
- M31 base field with degree-16 Fp16 extensions.
- Fixed-shape semantic AIR and GKR composition.
- SHA3-512 authoritative commitment layer.
- Construction-8.2 native witness hiding.
- Authenticated interactive public coin.
- FRI and verifier/parser/resource checks.
- Strict-PQ signing boundaries using ML-DSA-87 and SLH-DSA-SHAKE-256f.
- The ordered public schema is `ops/native_stark_public_inputs_v2.json`.
- The current selected-AIR package grammar is version 2 with an exact 64 MiB container and
  authenticated all-zero padding; selected workers own fresh OS entropy and zeroize it on exit.

H5 evidence recorded p95 32.360845 seconds for K128 and 148.861885 seconds for K512. These measurements do not select a production suite.

The current Rust `BLPQENV1` version-2 lane independently replays one selected AIR/FRI proof and its
dual-PQ authenticated transcript. It is not the complete Wave1A semantic-bus plus typed-state plus
H4 proof. The aggregate evidence verifier is intentionally unimplemented and caller-paired
receipt/digest input is rejected, so no current code path reaches `BUILT_AUDIT_PENDING`.

## Source and policy trust

Government and oracle adapters authenticate exact source bytes, signer authority, version, tenant, freshness, and completeness/absence evidence. ZK proves that the encoded program accepted authenticated inputs. Neither signatures nor ZK guarantee real-world honesty or policy correctness.

## Operational state

- `proofSuiteId=null`
- `production_usable=false`
- activation forbidden
- aggregate release status `AGGREGATE_UNQUALIFIED`
- real PHI and payments forbidden
- independent audit not started
- production database, HSM/FIPS custody, durable external anti-rollback, production backup/restore,
  and live adapter credentials not qualified

## Retained research

Cairo and earlier proof experiments remain as evidence. Historical documents under `docs/history/` and `STATE.md` may describe the abandoned L2 path; they are not active authority.
