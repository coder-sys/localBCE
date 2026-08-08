# Privacy V2 internal audit

Updated: 2026-08-08

## Accepted local properties

- The ordered V2 public boundary has exactly 12 `bytes32` fields.
- Forbidden private values are absent from the public manifest.
- Native projection is lossless and rejects noncanonical values.
- The proof envelope, sidecar, statement, suite, schema, verifier, and state identities are bound.
- `LocalSettlementV2` publishes state only after native verification succeeds.
- Failure paths are nonactivating and must not expose witness-dependent detail.

## Open production findings

1. No independently audited production proof suite is selected.
2. Production database isolation, crash recovery, backup/restore, and external anti-rollback are not qualified.
3. HSM/FIPS custody and live signer rotation are not qualified.
4. Official source credentials, legal authority, and payment rails are absent.
5. Whole-product privacy and side-channel review is not complete.

No L2 finding remains because no L2 is part of the current architecture. Real PHI and payments remain forbidden.
