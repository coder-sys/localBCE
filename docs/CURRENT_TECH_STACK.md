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

H5 evidence recorded p95 32.360845 seconds for K128 and 148.861885 seconds for K512. These measurements do not select a production suite.

## Source and policy trust

Government and oracle adapters authenticate exact source bytes, signer authority, version, tenant, freshness, and completeness/absence evidence. ZK proves that the encoded program accepted authenticated inputs. Neither signatures nor ZK guarantee real-world honesty or policy correctness.

## Operational state

- `proofSuiteId=null`
- `production_usable=false`
- activation forbidden
- real PHI and payments forbidden
- independent audit not started
- production database, HSM/FIPS custody, external anti-rollback, backup/restore, and live adapter credentials not qualified

## Retained research

Cairo and earlier proof experiments remain as evidence. Historical documents under `docs/history/` and `STATE.md` may describe the abandoned L2 path; they are not active authority.
