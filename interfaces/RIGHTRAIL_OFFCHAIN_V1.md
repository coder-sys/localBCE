# RightRail Off-Chain Interface V1

This interface connects the existing Rust adjudicator to a local, synthetic,
off-chain ledger and reconciliation projection. It does not generate a proof,
submit a transaction, move money, or execute the external RightRail runtime.

## Canonical Encoding

Every hash uses SHA-256 over UTF-8 JSON with:

- object keys sorted lexicographically;
- no insignificant whitespace;
- ASCII escapes for non-ASCII characters;
- integers encoded as JSON integers;
- no floats, NaN, or infinity.

Ledger events are one canonical JSON object per line. `event_sha256` hashes the
entire event except `event_sha256`. `previous_event_sha256` is the prior event
hash or 64 zeroes for the first event. The authoritative journal is rewritten
through a same-directory temporary file and atomic replace while a single-writer
lock is held.

## Adjudication Handoff

`record-adjudication` consumes the existing `adjudication_result.json`. It
requires `tx_submitted=false` and `tx_hash=null`, then adds explicit program,
jurisdiction, owed cents, source-file hash, and these fixed safety fields:

```json
{
  "proof_execution": false,
  "settlement_backend": "none",
  "synthetic_data": true
}
```

The idempotency key is `adjudication:<claim_hash>`. An exact retry returns the
existing event. Reusing that key with different content is a conflict and no
write occurs.

## Remittance Handoff

The remittance interface accepts synthetic, redacted events only. It stores a
claim hash, signed cent delta, event kind, payer-trace hash, source-artifact
hash, and timestamp. It rejects raw member/provider identifiers and unknown
fields. Positive deltas represent payments or repayments; reversals and
recoupments must be negative. PLB adjustment direction is explicit in its
signed delta.

The idempotency key is `remittance:<remittance_id>`.

## Reconciliation

Reconciliation replays the journal without writing it. Reports are sorted by
claim hash and identify matching payments, underpayments, overpayments,
payments against denied claims, and orphan remittances. Reports always declare:

```json
{
  "runtime_activation": false,
  "proof_binding": false,
  "proof_execution": false,
  "settlement_backend": "none",
  "money_movement": false
}
```

The external RightRail SQLite owner, Lean worker, UI, signers, binaries, and
payment actions remain inactive. Source lineage is the external
`RightRail.bundle` at commit
`af020b268094ae3fd6ef5e68fe575b7e5ac40a23`; the bundle remains external and
hash-pinned.
