# Privacy V2 internal audit

Updated: 2026-08-08

## Accepted local properties

- The ordered V2 public boundary has exactly 12 `bytes32` fields.
- Forbidden private values are absent from the public manifest.
- Native projection is lossless and rejects noncanonical values.
- The proof envelope, sidecar, statement, suite, schema, verifier, and state identities are bound.
- `LocalSettlementV2` models the transition, and the SQLite reference publishes durable state only
  after the exact native receipt succeeds and all locked roots are rechecked.
- Failure paths are nonactivating and must not expose witness-dependent detail.

## Open production findings

1. No independently audited production proof suite is selected.
2. The local SQLite isolation, keyed verifier authorization, submitter-bound state with
   commitment-only audit provenance, crash/replay, backup/restore, and write-ahead anti-rollback
   state machine pass; the production database and independently durable external anchor are not
   selected or qualified.
3. HSM/FIPS custody and live signer rotation are not qualified.
4. Official source credentials, legal authority, and payment rails are absent.
5. Whole-product privacy and side-channel review is not complete.

No L2 finding remains because no L2 is part of the current architecture. Real PHI and payments remain forbidden.
