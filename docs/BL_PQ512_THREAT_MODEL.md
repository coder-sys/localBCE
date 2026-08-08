# Blind Ledger threat model

Updated: 2026-08-08

## Security objective

A payment-relevant state transition may occur only when the exact pinned private relation accepts authenticated inputs and the native verifier result is committed atomically with the corresponding database update. No PHI may enter public fields, logs, release artifacts, or optional future L1 checkpoints.

## Governing boundaries

| Boundary | Primary threats | Required controls |
| --- | --- | --- |
| Provider/API input | Forged, malformed, cross-tenant, oversized, replayed data | Authentication, tenant isolation, canonical parsing, size/rate limits |
| Government/oracle source | Compromised signer, stale epoch, omitted record, semantic ambiguity | Dual-PQ signatures, source/version/freshness binding, completeness/absence evidence |
| Policy and rules | Unauthorized or stale policy, normalization mismatch | Governed roots, deterministic canonicalization, version pinning, review/timelock |
| Prover | Invalid witness, omitted constraint, cross-proof substitution, leakage | Complete fixed-shape relation, hiding, exact transcript/session binding, adversarial tests |
| Native verifier | Parser differential, resource exhaustion, mock/fallback verdict | Canonical bounded grammar, pinned artifact, independent verification, fail closed |
| Database transition | TOCTOU, stale state, double spend, conflicting retry, partial write | Serializable transaction, locked roots, unique nullifiers, idempotency, one commit |
| Custody | Key theft, mixed authority, rollback | HSM/FIPS boundary, separated roles, rotation, external anti-rollback |
| Operations | Data loss, unavailable database, unsafe recovery, PHI logs | Replication, backup/restore drills, signed append-only audit commitments, redaction |
| Build/release | Dependency or artifact substitution | Locked offline builds, SBOM, exact hashes, reproducibility, independent audit |

## Explicit limitations

A valid proof establishes that the encoded program accepted the authenticated inputs. It does not establish that an authorized source was honest, that the governing policy was correct or lawful, or that the database will remain available.

The repository is synthetic and nonactivating. `proofSuiteId=null`, `production_usable=false`, and real PHI/payments are forbidden.

No L2 is treated as a mitigating boundary. A future Ethereum L1 checkpoint can add public timestamping or tamper evidence, but cannot replace source governance, mandatory application ZK, database atomicity, availability, or recovery.

## Required adversarial stories

Tests must reject forged verifier receipts, proof/schema/suite mismatch, stale roots, duplicate nullifiers, cross-batch replay, conflicting retries, transaction races, crash-before-commit, rollback to an old governance epoch, unauthorized signer rotation, malformed or oversized proofs, PHI-bearing logs, and incomplete recovery.

