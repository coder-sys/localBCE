# Financial core redesign (approved by the founder 2026-09-24)

Approved 2026-09-24/25: the v8 rebuild and store format (RR/FINANCIAL/CONTINUITY/v8, CONSTITUTION V.4); v5/v6/v7 stores,
v7 conversion and `OPENING_BALANCE` retired (decision C3). Any step weakening a safety property needs a separate founder decision.

## Gaps found (under-enforcement, not just size)

- Every staff read runs the full checker over the whole database (IX.3).
- Two canonical encodings (SHA3/ASCII and SHA-256/UTF-8 staff snapshot).
- The successor verifies and views but cannot continue the work (VII.2).

## Migration (each step leaves a working system; one guarded run per step)

Done (history in git): v8 owner, Continuity and replay reuse. Rules: one typed decoder per record, no re-validating own writes;
read-set binding plus a pre-COMMIT per-obligation checker replace Python re-derivation of Lean; the checker is replay + compare
with an incremental mode, and all 25 tamper tests still detect.
Open: more transitions move to Lean.

## History segments (approved by the founder 2026-09-25)

Replaces the per-write whole-history size admission (which refused every write after
~900 commands); the 8 MiB package export stays, refused at export, not at write.

Ceiling: 10,000 events, because Lean's `maxRows`/`maxRevision` (Types.lean) bound what the
proof and checker accept. The owner refuses the 10,001st event, revision or row of any
table with `history_capacity` before commit; raising it is a Lean change.

- Domain `RR/GATE/SEGMENT/v1` (one format for Continuity and the gate): SHA3-512 over
  `RR/GATE/SEGMENT/v1\0` and length-prefixed parts; `projection_root = D("rows", rows)`,
  `segment_digest = D("seal", seal)`, `manifest_digest = D("manifest", body)`; canonical JSON.
- Seal: `format`, `segment_index`, `first_sequence`, `last_sequence`, `event_count`,
  `previous_digest` (zero for segment 0), `event_head`, `projection_root`. A segment file adds
  its events, the sorted final images of the rows they touched, `segment_digest`, and a
  reserved `signature` (null; ML-DSA-87 later, outside the digest).
- Bounds: seal after the write reaching 4,096 events or 4 MiB; a write carrying the open
  segment past 10,000 events or 16 MiB (so any store the old cap admitted fits one segment)
  fails `history_segment_size`.
- Writes note touched rows in `history_pending`: O(this write) (IX.3). Older v8 stores
  are replayed on open and sealed as segment 0 in the same transaction. The checker
  recomputes sealed segments' chain, counts and event heads; sealed rows are append-only.
- `export_history`: one fsynced file per segment; an existing file is compared, never rewritten.
  `restore_continuity(history=...)`: the checker verifies manifest, chains and seals; a
  fresh owner replays each segment and must reseal it byte-identically; `verify_database`
  replays the result and the checker binds its rows to the final images.
- Next: Lean codec for the seal with a round-trip proof; then the signature.

Protected throughout (V.4): `tests/rightrail_financial_expected_cases.py`, Lean KAT/vector
files, `artifacts/engine-correction/vectors/`, the correction engine pin, wire formats and digest
domains, theorem statements, and `tests/test_right_rail_financial_constitution_invariants.py`.

## Receiver cash-file boundary (XI.2 design, 2026-09-26)

Felt effect: an implementation lead previews one fictional receiver file
against the reviewed ledger, then records its cash evidence as one transaction:
no repeated manual entry, exact retries, all-or-nothing. No money moves.

- Predicate: accept only `RR/FINANCIAL/RECEIVER-CASH-FILE/v1`, canonical ASCII
  JSON of at most 1 MiB, with 1-500 ordered rows, at most 6 per item (more: `cash_file_row_cap`). Root fields are exactly
  `contract`, `source_class`, `scope`, `source`, `row_count`, `total_cents`,
  `rows`; `source_class` is `SYNTHETIC_RECEIVER_CASH`. Scope has exactly the
  existing state/deployment/program/period/currency fields, currency USD.
  Source has `source_id`, `version`, `receiver_system_id`, `capture_id`,
  `captured_at_ms`. Each row has exactly eight fields: `item_id`, `payment_id`,
  `common_origin_id`, `evidence_id`, `amount_cents`, `event_at_ms`,
  `pays_action_id`, `expected_revision`. The action link is explicitly null or
  an ID.
- Invariant/failure: untrusted input never skips a row, turns acknowledgment or
  reporting into cash, substitutes an ID with the same total, or commits a
  partial file. IDs/version use the owner's 128-character grammar. Cents are
  positive integers and their sum is at most 2^63-1; times are integers from
  zero through 2^63-1, event time no later than capture time; revision is an
  integer from zero through 9,999. Booleans are not integers. Reject duplicate
  JSON keys, missing/extra fields, noncanonical bytes, duplicate payment/evidence
  IDs or item/origin pairs, and count/total disagreement. MCO reports, X12
  820/835 and MMIS extracts are unsupported formats and refuse completely.
- Evidence: `record_payment_evidence` can return CONFLICT or an alias DUPLICATE
  after recording evidence, and `run_batch` rolls back exceptions, not those
  statuses, so checking only the returned report would accept partial work.
  `_write` can seal history after the batch body: the final check must follow
  sealing and precede COMMIT.
- Disposition: add this explicitly fictional input contract; retain all owner
  commands, cash rules, existing wire/digest domains, expected answers and
  limits. No caller-provided callback or success flag authorizes acceptance.
- Replacement control: the caller separately supplies trusted scope, source
  context, source SHA-256, baseline SHA-256, owner ID/mode and authority.
  Let F be exact file bytes and B the exact `manifest.json` bytes `export-history`
  wrote (the owner's history manifest, about 1.9 KB whatever the history).
  Every derived command binds `local_ref = UPPER(SHA256(F)) || UPPER(SHA256(B))`.
  A retry never replaces B with a fresh export. Producer and verifier parse
  and reconstruct independently; the verifier does not import the producer.
  It accepts B only if canonical and it passes the export verifier's manifest checks
  (`_verify_manifest`: digest, meta and identity against the trusted scope, owner, mode
  LIVE or TEST and authority; no null sequence or head).
  Freeze commands before comparison. Under the same BEGIN IMMEDIATE, bind the
  store to B: the same identity row and event head at B's sequence (the owner
  verified the whole store at open; later history is append-only), and B's
  `segment_count` and `last_segment_digest` equal to the live `history_segments`
  row sealed at B's sequence (none: 0 and the zero digest). New work requires the store still at B's sequence; on an
  older baseline only rows that write nothing (RETRY, ALIAS) are allowed.
  After final sealing the checker verifies row/command order, each new event
  onto the chain, payment/evidence/action links, revisions, every table's
  before/after difference and per-item cash deltas, then runs its own rules on
  the touched obligations (see Cash-file capacity); other cash, acknowledgments
  and reporting remain unchanged. A file with no NEW or OVERLAP
  row must leave durable state identical and make zero SQL changes. Any mismatch rolls
  back the whole file. Publish the receipt only after COMMIT succeeds.
  Preview (the default) runs the checked file on a private SQLite-backup copy of the live
  store, rolls it back and deletes it; no writer opens on the live file. Apply uses the same
  checked boundary; cleanup failures are visible. CLI apply opens only an existing, current
  store with the reviewed mode/ID (`mode=rw`; setup checks refuse missing segment/index/
  append-only metadata rather than migrate it); a missing, empty or disappearing store is refused.
- Scope: local synthetic receiver cash evidence only; Switch's owed
  comparison schema is unchanged; no live transport, source authentication/truth,
  payment or activation claim.
- Receipt: `RR/FINANCIAL/RECEIVER-CASH-RECEIPT/v2` (v1 receipts stay valid) has exactly `contract`,
  `mode` (PREVIEW or APPLIED), `source_sha256`, `baseline_sha256`, `row_count`,
  `recorded_count`, `duplicate_count`, `file_total_cents`, `recorded_cents`,
  `duplicate_cents`, `cash_before_cents`, `cash_after_cents`, `cash_delta_cents`,
  `proofSuiteId` (null), `production_usable` (false), `activation` (false).
  Amounts are the checker's sums of the rows before the write and the per-item
  cash deltas it proved.
  RETRY and ALIAS rows add zero cash, including payments reversed after their
  receipt; a new repeat of a reversed payment is DUPLICATE only if dated no later than the reversal, else `conflict`. No intermediate
  owner projection or raw file/error data is exported in this result.
- Duration: v1 has no implicit legacy migration; changes need a new compatibility decision and fresh evidence.
- Claims withdrawn: this design is not implementation or verification.

### Cash-file capacity (2026-09-28)

Target: the largest state's hospital-level program, about 600 hospitals with up
to 3 lines a month (2,000 rows a month, under Lean's `maxRows`). The 8 MiB package
baseline capped a store near 950 payments; with the manifest baseline (1b) a month
is four full files and a quarter twelve (locks: `STATUS.md`). All-provider refund
flows need sharding or Phase 2 and are not claimed.

- One file is one `run_batch`: at most 500 rows, at most 6 per item (each
  payment re-binds every earlier payment of its item), bounded by the 5 s writer
  busy timeout. One evaluation per payment is kept
  (founder, 2026-09-28).
- Quarter-end lock, 7.4 s: owner path 5.3 (Lean worker 1.3, SQL 1.5, canonical
  JSON 0.8), checker 1.8, COMMIT 0.4 (`cqe-prof9`). A 64 MiB page cache and the
  collector paused in one write: 5.9-6.9 s (`cqe-red1`-`3`), still over 5 s; a row
  memo gained nothing. The rest is 0.1-0.3 s items: under 5 s needs a limit or a
  check restructure (rr-core).
- Art. XI.2 record. Disposition: the whole-store verify no longer runs twice per
  import under the lock (it runs at each open). Replacement control, before
  COMMIT: each new event onto the chain, every table's before/after difference,
  and the checker's own rules (never copies) on the touched rows: current
  evaluation, determinations, action amount, requestable and `payment:link`,
  correction follow-up records, evidence digests. A structural test lists each
  whole-store rule not run before COMMIT with its reason. Claims withdrawn: that the store, or
  a cash file's totals, is independently verified before COMMIT. Corruption
  that bypassed the owner is caught at the next open or by `verify-integrity`.
- Art. XI.2 record, Phase 1b (2026-09-29). Felt effect: a reviewer hashes a 1.9 KB
  manifest, not a 2.4 to 15.7 MB package. Disposition: B is the `export-history` manifest (it prints its SHA-256); the
  receipt is v2 (same 16 keys); a SHADOW store is no longer a target
  (`cash_file_binding`; `--mode` is LIVE or TEST). No stored format, digest or `local_ref`
  construction changes (a `local_ref` prefix is declined: the 128-char grammar bounds it).
  Review fixes: B's segment fields bind to the live row; a preview refuses a copy whose
  deferred keys COMMIT would refuse; `export-history` replaces `manifest.json` only with a
  later export of the same identity whose old last segment matches this store's at that
  index; the preview copy lives in `<store>.cash-preview`, swept hourly. Withdrawn: "B is
  the original reviewed Continuity bytes", "preview restores B into isolated TEST storage".
- Visible changes: `--baseline` takes the manifest (a package is `cash_file_format`);
  preview needs `--database`; the CLI prints `ERROR:receiver_cash_file_refused:{code}`, nine
  fixed classes; `duplicate_count` includes OVERLAP rows, which write alias evidence.
- A row is NEW, RETRY, OVERLAP (a repeat of a stored payment under new ids:
  DUPLICATE, one alias event, no cash), ALIAS (a stored repeat: nothing written)
  or refused. Overlap needs new ids: a row that reuses stored ids must be the
  exact stored row, else the whole file refuses. An exact alias repeat writes
  nothing whatever its expected revision.
- An existing-only writer (the CLI) refuses an index set older than the current
  one; a read-only SHADOW may keep the previous set.
- Phase 2 (deferred): evaluations that bind evidence by digest, constant size.

### Cash-file refusals

Fixed classes only; no input or error text is ever printed. `input`: the CLI
could not read an input. `format`: not the contract. `row_cap`: split the file.
`binding`: hashes, scope, owner/mode or baseline do not match this store.
`stale`: prepare against a new baseline. `conflict`: an origin is recorded with
another amount or link, or was paid and reversed; investigate. `already_recorded`: an id is reused.
`busy`: retry later. `failed`: checker or store refused; escalate.

## Browser conformance correction (2026-09-26)

Felt effect: staff receiving a busy or lost response recover without a second
cash/decision write, and read failures disable unsafe commands. The declared
model states the retained exact-retry bodies and the busy/uncertain responses;
a read error reaches the declared unavailable state with a working refresh. The
original command body is kept after uncertainty, confirmed refusal is
distinguished from unknown outcome, and a fresh verified read precedes a new
command. Financial API payloads, authority and owner decisions are unchanged.
The scorecard's simulated DOM does not establish browser conformance: a real
browser over the same HTTP server exercises each declared role, control,
response, enabled state, message, destination and recovery; no old model pass
is inherited.

XI.2 records live in commit bodies: `git log --grep '^XI.2:'`; records before 2026-10-01 are archived at rrb/archive/xi2-records-20261001.md
