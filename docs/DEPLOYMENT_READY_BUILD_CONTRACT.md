# Deployment-ready build contract

Updated: 2026-08-08

Blind Ledger must produce a complete audit-pending database + mandatory-zero-knowledge release candidate without requiring an outside party to design or implement it.

## Three boundaries

### Internal engineering

The 81 surviving packages cover the proof core, fixed-shape semantics, signed sources, direct atomic database boundary, adapters, custody interfaces, reproducibility, monitoring, and recovery. The current ledger is 33 complete and 48 open. L2-only R01-R12 packages were retired and are not silently counted as completed work.

### Independent audit

One uncounted external audit gate reviews AIR soundness, witness hiding and PQ assumptions, signatures and commitments, native verifier/parser, database transaction safety, adapters, custody, supply chain, privacy, and operations.

### Operator activation

Operators later provide production database coordinates, HSM/KMS handles, governance signers, government/oracle credentials, payment accounts, legal authority, and any optional Ethereum L1 checkpoint configuration.

## Mandatory release properties

- Every payment-relevant private decision has a mandatory zero-knowledge proof.
- The native verifier and payment state transition form one fail-closed atomic boundary.
- State-before, state-after, nullifier, value-conservation, policy, ruleset, source, settlement, schema, suite, and verifier identities are exact.
- No mock result, caller-supplied proof verdict, fallback policy, stale root, or unpinned artifact enters the boundary.
- Fixed-shape privacy, non-PHI logs, bounded resources, idempotency, concurrency, retry, rollback, recovery, and anti-rollback are tested.
- Builds are locked, reproducible, SBOM-complete, and independently readable.
- No L2 is required.

## Proof-suite lifecycle

| State | Meaning | Activation |
| --- | --- | --- |
| `UNSELECTED` | Global `proofSuiteId` is null. | Forbidden |
| `BUILT_AUDIT_PENDING` | Exact local candidate proof and native receipt passed pinned checks. | Synthetic/release-candidate tests only |
| `AUDIT_ACCEPTED` | Independent audit accepted the exact release identities. | Eligible for separately authorized activation |

Until audit and activation pass, `production_usable` remains `false`; real PHI and real payments remain forbidden.

## Ethereum

Ethereum is not an internal Phase 0-2 package or a launch dependency. A future direct-L1 checkpoint must be separately designed, measured, audited, and activated.
