# Financial core: history segments and the receiver cash file

Both are built. This file holds the rules the code and tests keep to. XI.2 records are in commit bodies
(`git log --grep '^XI.2:'`); records before 2026-10-01 are in rrb/archive/xi2-records-20261001.md.

Store format: v8 only (`RR/FINANCIAL/OWNER/v8`, `RR/FINANCIAL/CONTINUITY/v8`; CONSTITUTION V.4). Older stores,
v7 conversion and `OPENING_BALANCE` are retired. Open: more transitions move to Lean.

Protected (V.4): `tests/rightrail_financial_expected_cases.py`, Lean KAT/vector files,
`artifacts/engine-correction/vectors/`, the correction engine pin, wire formats and digest domains, theorem
statements, and `tests/test_right_rail_financial_constitution_invariants.py`.

## History segments

Ceiling: 10,000 events, because Lean's `maxRows`/`maxRevision` (Types.lean) bound what the proof and checker accept.
The owner refuses the 10,001st event, revision or row of any table with `history_capacity` before commit. Raising it
is a Lean change. The 8 MiB package export stays, refused at export, not at write.

- Domain `RR/GATE/SEGMENT/v1` (one format for Continuity and the gate): SHA3-512 over `RR/GATE/SEGMENT/v1\0` and
  length-prefixed parts; `projection_root = D("rows", rows)`, `segment_digest = D("seal", seal)`,
  `manifest_digest = D("manifest", body)`; canonical JSON.
- Seal: `format`, `segment_index`, `first_sequence`, `last_sequence`, `event_count`, `previous_digest` (zero for
  segment 0), `event_head`, `projection_root`. A segment file adds its events, the sorted final images of the rows
  they touched, `segment_digest`, and a reserved `signature` (null, outside the digest).
- Bounds: seal after the write reaching 4,096 events or 4 MiB. A write carrying the open segment past 10,000 events
  or 16 MiB fails `history_segment_size`.
- Writes note touched rows in `history_pending`: O(this write) (IX.3). Older v8 stores are replayed on open and
  sealed as segment 0. The checker recomputes sealed segments' chain, counts and event heads; sealed rows are
  append-only.
- `export_history`: one fsynced file per segment; an existing file is compared, never rewritten.
  `restore_continuity(history=...)`: the checker verifies manifest, chains and seals; a fresh owner replays each
  segment and must reseal it byte-identically.
- Next: a Lean codec for the seal with a round-trip proof; then the signature.

## Receiver cash-file boundary (XI.2)

An implementation lead previews one fictional receiver file against the reviewed ledger, then records its cash
evidence as one transaction: no repeated manual entry, exact retries, all-or-nothing. No money moves.

- Contract: `RR/FINANCIAL/RECEIVER-CASH-FILE/v1`, canonical ASCII JSON of at most 1 MiB, 1-500 ordered rows, at most
  6 per item (more: `cash_file_row_cap`). Root fields: `contract`, `source_class` (`SYNTHETIC_RECEIVER_CASH`),
  `scope`, `source`, `row_count`, `total_cents`, `rows`. Each row has exactly eight fields: `item_id`, `payment_id`,
  `common_origin_id`, `evidence_id`, `amount_cents`, `event_at_ms`, `pays_action_id` (null or an ID),
  `expected_revision`. The code (`app/right_rail_financial_cash_file.py`) holds the field grammar and number bounds.
- Refuse completely: duplicate JSON keys, missing or extra fields, noncanonical bytes, duplicate payment/evidence
  IDs or item/origin pairs, count/total disagreement. MCO reports, X12 820/835 and MMIS extracts are unsupported.
  Untrusted input never skips a row, turns acknowledgment or reporting into cash, or commits a partial file.
  No caller-provided callback or success flag authorizes acceptance.
- Evidence: `record_payment_evidence` can return CONFLICT or an alias DUPLICATE after recording evidence, and
  `run_batch` rolls back exceptions, not those statuses. So the final check must follow history sealing and precede
  COMMIT.
- Binding: the caller supplies trusted scope, source context, source SHA-256, baseline SHA-256, owner ID/mode and
  authority. F is the exact file bytes; B is the exact `manifest.json` bytes that `export-history` wrote (about
  1.9 KB). Every derived command binds `local_ref = UPPER(SHA256(F)) || UPPER(SHA256(B))`. A retry never replaces B
  with a fresh export. The verifier does not import the producer. It accepts B only if canonical and it passes the
  export verifier's manifest checks (`_verify_manifest`).
- Under one BEGIN IMMEDIATE, the store must match B: same identity row and event head at B's sequence, and B's
  `segment_count` and `last_segment_digest` equal the live `history_segments` row sealed there. New work requires the
  store still at B's sequence; on an older baseline only rows that write nothing (RETRY, ALIAS) are allowed.
- After final sealing the checker verifies row and command order, each new event onto the chain, payment/evidence/
  action links, revisions, every table's before/after difference and per-item cash deltas, then runs its own rules on
  the touched obligations. Other cash, acknowledgments and reporting stay unchanged. A file with no NEW or OVERLAP
  row leaves durable state identical and makes zero SQL changes. Any mismatch rolls back the whole file. The receipt
  is published only after COMMIT.
- Preview (the default) runs the checked file on a private SQLite-backup copy (`<store>.cash-preview`, swept
  hourly), rolls it back and deletes it. Apply uses the same checked boundary. CLI apply opens only an existing,
  current store with the reviewed mode/ID (`mode=rw`); a missing or empty store is refused.
- Rows: NEW; RETRY (exact stored row); OVERLAP (a repeat of a stored payment under new IDs: DUPLICATE, one alias
  event, no cash); ALIAS (a stored repeat: nothing written); or refused. A row that reuses stored IDs must be the
  exact stored row, else the whole file refuses.
- Receipt `RR/FINANCIAL/RECEIVER-CASH-RECEIPT/v2` (v1 receipts stay valid): `contract`, `mode` (PREVIEW or APPLIED),
  `source_sha256`, `baseline_sha256`, `row_count`, `recorded_count`, `duplicate_count` (includes OVERLAP rows),
  `file_total_cents`, `recorded_cents`, `duplicate_cents`, `cash_before_cents`, `cash_after_cents`,
  `cash_delta_cents`, `proofSuiteId` (null), `production_usable` (false), `activation` (false). Amounts are the
  checker's sums. RETRY and ALIAS rows add zero cash, including payments reversed after their receipt; a new repeat
  of a reversed payment is DUPLICATE only if dated no later than the reversal, else `conflict`.
- Scope: local synthetic receiver cash evidence only; no live transport, source authentication, payment or
  activation claim.

### Cash-file capacity

Target: the largest state's hospital-level program, about 600 hospitals with up to 3 lines a month (2,000 rows a
month, under Lean's `maxRows`). With the manifest baseline a month is four full files and a quarter twelve (locks:
`STATUS.md`). All-provider refund flows need sharding or evaluations that bind evidence by digest (constant size) and are not claimed.

- One file is one `run_batch`: at most 500 rows, at most 6 per item (each payment re-binds every earlier payment of
  its item), bounded by the 5 s writer busy timeout. One evaluation per payment is kept (founder, 2026-09-28).
- The quarter-end lock must stay under the 5 s writer busy timeout; the measured time is in `STATUS.md`.
- Before COMMIT the checker runs its own rules (never copies) on the touched rows. A structural test lists each
  whole-store rule not run before COMMIT, with its reason. Corruption that bypassed the owner is caught at the next
  open or by `verify-integrity`.

### Cash-file refusals

Fixed classes only; no input or error text is ever printed (`ERROR:receiver_cash_file_refused:{code}`). `input`: the
CLI could not read an input. `format`: not the contract. `row_cap`: split the file. `binding`: hashes, scope,
owner/mode or baseline do not match this store. `stale`: prepare against a new baseline. `conflict`: an origin is
recorded with another amount or link, or was paid and reversed; investigate. `already_recorded`: an ID is reused.
`busy`: retry later. `failed`: checker or store refused; escalate.
