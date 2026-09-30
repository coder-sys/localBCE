# Financial core redesign (approved by the founder 2026-09-24)

Approval (2026-09-24): founder approved the v8 rebuild and retiring v5/v6 stores, conditional on every step complying with CONSTITUTION.md; any step weakening a safety property or protected answer needs a separate founder decision.

Format approval (2026-09-24, CONSTITUTION V.4): the founder approved the v8 store/package format (RR/FINANCIAL/CONTINUITY/v8) in session chat ("Yes, approve v8"). The only protected change is CASE_11's export version string in `tests/rightrail_financial_expected_cases.py`. History-completeness approval (same date): one sealed opening-balance event, then full facts on every later event. Both v7 provisions (migration on open, opening-balance conversion) were superseded 2026-09-25 (decision C3): v7 conversion and `OPENING_BALANCE` were removed.

## Verdict

### Current-source Lean reproduction (2026-09-26, XI.2 record)

Superseded by the correction-v2 re-pin (below). r67 reproduced the then-pinned 6,279,168-byte
engine byte-for-byte from 46 source files at `61a24519`; the manifest-order and CRLF guard-log
predicates were fixed prospectively; no claim for later source. Full record: `2ec89a0:docs/CORE_REDESIGN.md`.

### Current-engine service-kit connection (2026-09-26, XI.2 record)

Superseded by the correction-v2 re-pin. The release producer and kit require the current
pinned transition and reuse vectors and the retired-engine registry, and compare actual with
expected bytes; stale CMD01/RES1 pins were replaced. Old reuse evidence does not verify v2.
Full record: `2ec89a0:docs/CORE_REDESIGN.md`.

### Kit evidence source binding (2026-09-28, XI.2 record)

- **Predicate:** `artifacts/engine-correction/PROVENANCE.md` may cite a run only
  for the source it actually packaged. **Failure:** r80/r84/r85/r88 were
  recorded as evidence for `86390ab`, but r80 packaged an uncommitted tree
  (cash-file modules, Owner `existing_only`) (rr-review H1).
- **Evidence:** a file-by-file comparison of the r80 archive with commit
  `707ba78`: every Lean source and 26 of 27 source files identical; the one
  difference, `right_rail_financial_engine.py`, has a derived reject map equal to
  the archive's literal.
- **Disposition:** append a source-binding paragraph; edit no earlier text.
  **Control:** the comparison script is rerunnable against any commit; a new kit
  is assembled from a clean checkout before any release claim.
- **Scope:** provenance text only; no pin, digest, vector or gate change.
  **Claims withdrawn:** r80/r84/r85/r88 are not evidence for `86390ab`.

### Correction follow-up changed dependencies (2026-09-28, XI.2 record)

- **Predicate:** `CORRECTION-EXPLANATION/v1` and `CORRECTION-REPORT/v1` gain a
  required `changed_dependencies`: sorted, unique keys such as
  `COLLECTION(OFFSET_EVIDENCE, <item>)`. Mirror allowlists and checks it.
- **Invariant / failure:** REOPENED iff a later event touches a key
  (`_FOLLOWUP_TOUCHES`) and re-reading it at head gives a new value. An unknown
  event kind, stored family or engine, or a moved key no event explains (a
  cancelled action: no event records a delivery rejection yet) is
  REVIEW_REQUIRED. An acknowledgment, the payment the correction requested
  (`pays_action_id`), and a re-sent confirmation (DUPLICATE: no payment or
  conflict of its own, same origin and amount as the named payment) do not
  reopen; a new payment, reversal, conflict, support or offset evidence does.
- **Evidence:** G2 Mirror and acceptance tests, including a forged DUPLICATE
  label over a new payment, run through the guard.
- **Disposition:** a derived field added to both v1 contracts without a version
  bump, acceptable only because the output is derived, synthetic and has no
  outside consumer. `OBLIGATION_REVISION` and `CURRENT_EVALUATION_RECEIPT` stay
  in the stored `dependency_families` but are retired. No store, event, digest
  or Lean change.
- **Replacement control:** the independent checker verifies the stored basis at
  open and refuses a DUPLICATE label that does not bind as above. Mirror refuses
  the field unless it is sorted, unique, equal in both views, and non-empty
  exactly when REOPENED.
- **Scope / follow-ups:** financial correction follow-up. REPORT evidence has no
  link to a correction, so the correction's own report still reopens it. The
  status scan is O(corrections x events).
- **Claims withdrawn:** reopening on any change to the obligation revision,
  evaluation id/revision/result/receipt digests, case id or status, or action
  identity, kind, status, reference or attempt; an acknowledgment no longer reopens.

### Safe support package v2 (2026-09-28, XI.2 record)

- **Predicate:** `CORPORATE-SUPPORT/v1` becomes `/v2`, built from approved fields
  only, never a redacted dump. Fields: software version, rule version, adapter
  versions, `work_ref_count`, reproduction. Consumers: the correction follow-up
  (Owner builds, Mirror re-checks) and a failed Continuity restore (Mirror
  builds in `_restore_continuity` and attaches it to the raised error as
  `corporate_support`; only the staff endpoint's 409 response returns it, the
  403, 503 and 400 responses do not).
- **Sources:** rule version = the pack the correction was decided under,
  `accepted_basis.control_pack` `{pack_id, version, digest}` (NONE without an
  accepted basis); adapter `population` = the population manifest contract for a
  follow-up, NONE for a restore failure; `work_ref_count` = 0 when CURRENT, else 1
  (this correction), with no work id and no store counter; reproduction = `{vector_file_digest, case_id}` of the
  published correction vector, only when the artifact is the pinned engine (a
  test checks the digest and that the case is in the pinned result file).
  **NONE**: software version (no commit or kit digest is bound to a running
  owner) and the Trust Graph source profile (the owner has no source of it). A
  restore failure's `error_class` is its code only when it is a `FinancialError`
  or `FinancialMirrorError` whose text is in the closed tuple
  `CONTINUITY_ERROR_CODES` (defined once in the Owner, imported by the Mirror);
  anything else is `UNCLASSIFIED`; never message text.
- **Invariant / failure:** Mirror compares the Owner's raw package with the
  approved one by JSON equality (so `false` is not `0`) before any projection,
  so an extra key at any level is refused, not dropped; pack fields have fixed
  shapes (id pattern, positive int version, 128-digit upper hex). Tests run
  `tests/instruments/privacy_artifact_scan.py` on the follow-up and restore packages and
  require nothing beyond its unapproved-schema notice; that is what is checked,
  not a proof that no package can leak.
- **Raw evidence:** v1 (`82a2087`) held no rule, adapter or software version, no affected work, nothing rerunnable and no restore-failure package.
- **Disposition:** v1 replaced, not versioned alongside (derived, synthetic, no
  outside consumer). Deleted: the Owner's `_corporate_support` and
  `continuity_restore_support` builders and `restore_test_continuity` wrapper
  (use `restore_continuity(restore_mode="TEST")`), and Mirror's restore re-check
  and restore-mode check (the Owner's validation and refusal come first).
- **Replacement control:** Mirror, staff-server and acceptance tests, run through
  the guard.
- **Scope / follow-ups:** correction follow-up and restore failure only. A
  failure raised by the staff workflow after a successful restore (package size,
  decision-package mismatch) carries no package yet. `work_ref_count` is 0/1
  until the G2 reopened set is cheap to read at build time. Real software and
  Trust Graph versions need a bound source first.
- **Claims withdrawn:** `reproduction {SYNTHETIC_CORRECTION, real_data: false}`;
  the earlier `affected_work {count, ids}` with the event sequence.

## Gaps found (under-enforcement, not just size)

- Every staff read runs the full checker over the whole database (IX.3).
- Two canonical encodings (SHA3/ASCII and SHA-256/UTF-8 staff snapshot).
- The successor verifies and views but cannot continue the work (VII.2).

## Migration (each step leaves a working system; one guarded run per step)

Done (history in git): v8 owner, Continuity and replay reuse. Standing rules:
one typed decoder per record, no re-validating own writes; Python re-derivation
of Lean is replaced by read-set binding plus a pre-COMMIT per-obligation
checker; the checker is replay + compare with an incremental mode and all 25
tamper tests still detect.
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

## Synthetic NC capture clock (XI.2, 2026-09-26)

1. Predicate: replace the 1900/197 prefix heuristic with strict calendar parsing
   and `0 <= fetch_utc - marker <= 365 * 86400` seconds, inclusive. COMPLETE
   requires no failure and complete pages; a failed capture never becomes FRESH
   or enters graph admission. Date-only markers cannot establish instant age.
2. Invariant/failure: an invalid, future or too-old marker cannot claim freshness;
   logical capture ticks cannot silently become Unix time; contradictory failure
   fields cannot authorize admission.
3. Evidence: the profile defined ticks 7000/7010 and a 365-day limit, but the
   producer and verifier checked only `startswith(("1900", "197"))` and
   admission omitted failure_code. Guarded r32 passes all 72 checks; independent
   review also closed a numeric-to-string context bypass.
4. Disposition: replace the heuristic and refuse old profile bindings; retain
   raw-envelope v2, logical capture fields, graph windows, bounds and nonclaims.
   Replacement: immutable profile clock `SYNTHETIC_LOGICAL_SECONDS_V1`, reference
   tick 7010 at `2026-08-14T12:00:00Z`, one second per tick; producer and
   verifier calculate age independently; admission binds all six expected
   context fields (omitted context means the fixed fixture, never
   envelope-supplied identity/time). Source contract/schema/domain become v3;
   source profile and verifier v5/epoch 5; envelope v2, resource digests v2,
   generic graph profile v3 and the unbound capability-statement identity are
   unchanged. Boundary, rebinding, calendar, context and failure-state tests
   must pass before new claims.
5. Scope: synthetic NC capture only; no live transport, payment authority,
   read-model freshness upgrade or changed resource limit. Felt effect: the
   implementation lead sees stale or invalid captures refused during onboarding,
   not a falsely fresh observation downstream. Duration: until explicitly
   replaced; old bytes stay historical evidence and fail the new binding.
6. Withdrawn claims: old tests and profile/envelope/graph/receipt identities do
   not establish the new rule. FRESH means marker age at synthetic capture time,
   never current source truth. Current regression evidence and build
   requirements are in `STATUS.md`.

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
- 2026-09-29: BLFIN02 bytes of each evidence and payment record are cached (same
  typed values, same bytes). Quarter-end, no profiler: encoding 0.85 to 0.43 s; lock
  still 8-11.5 s, over 5 s: worker 2.6 s, whole-store checks 2.9 s (`lk-break1`).
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

## Correction-v2 protected changes (2026-09-26; XI.2 record written 2026-09-28)

This record replaces the one STATUS lost in `b9aa6a2` (last at `d79aceb`); facts are from `git show` of the commits named.

Felt effect: a hospital short part of its claim is asked for exactly what is
still unpaid, and no older engine record can ask for more.

- **Predicate:**
  - Lean `actionBindingWellFormed` (`Financial/Types.lean`) required the action
    amount `=` the determination amount; it now requires `≤` for
    `OFFSET_REJECTED_CORRECTION_AUTHORIZED` and still `=` otherwise. The amount
    is pinned instead by `applyCorrectionTransition_action_amount_eq_b2`:
    min(claim, shortfall less what unpaid earlier requests still ask). New:
    `_outstanding_within_shortfall`, `_zero_shortfall_has_no_mutation`,
    `_amounts_conserved`, `evaluate_positive_shortfall_balance`, `CodecLaws/Correction*.lean`.
  - Wire: BLFCMD01 to 02 (adds the paid-request list), BLFCRES1 to 3, BLFCRU01 to
    02, BLFCRV01 to 02. Lean no longer computes the determination digest, the
    action idempotency key, the outbox digest and key or the event base payload
    (BLFCRES3 has no slot for them; reuse lost `DETERMINATION_DIGEST_CHANGED`).
    The owner and checker still compute them under the same domains
    (`RR/FINANCIAL/ACTION/v1`, `RR/FINANCIAL/IDEMPOTENCY/v1`); Lean computes the
    action payload digest.
  - Statements changed with it: `CorrectionMutationLinkFacts` (digest and key
    equations dropped; paid-list, kind, claim-amount, amount-rule and
    input-shortfall facts added) and the reuse-independence theorem (no
    determination-digest parameter).
  - Artifacts: `artifacts/engine-correction/` re-pinned, built from `79b6913`
    (`1A7A1833…D3AF`, 6,279,168 bytes); `artifacts/engine-correction-e911/`
    deleted (recoverable at `f1de262`); `RETIRED_PINS` added (E911
    `correction-rule-v1`, 88D8 `b2-v1`; SHA-256 pinned in the checker);
    `native/guard/pins.json` names the current executable and vectors (guard
    runner unchanged). New checker rules: `action:requestable`,
    `action:engine-order`, `action:event-amount`, `payment:link`,
    `history:correction-retired-pins`.
  - Protected test `tests/test_right_rail_financial_constitution_invariants.py`:
    `11ff5ee` (BLFCRES2 literals, a `NO_SHORTFALL` rejection row, new test
    `test_correction_requests_only_the_unpaid_balance`), `c10106b` (artifact path
    in docstrings), `7722e23` (literals to BLFCMD02/BLFCRES3), `3656bf5` (a setup
    clock only; no assertion changed). Expectations changed only where they name
    a changed format.
- **Invariant / failure:** a correction never requests more than the unpaid
  shortfall (II, III.4). The old equality requested the whole claim.
- **Evidence:** subtest `e911-whole-claim` (300,000 requested on 100,000 unpaid)
  was flipped to refused on purpose; rr-review round 3 and H1/M1/M3 found the rest.
- **Disposition:** weaken (`=` to `≤`, corrections only) and replace (exact
  amount theorem, wire formats, engine pin); E911 and 88D8 stay only as history.
- **Replacement control:** the theorem above; KATs at B2-1, B2+1 and full
  shortfall (42/42, `cv2-r3-kat-clean-a1`); the checker bound `action:requestable`
  on every correction whatever engine decided it; `action:engine-order` refuses a
  store whose corrections name an older engine after a newer one, checked across
  the whole store in event order, stricter than `PROVENANCE.md` ("an obligation's
  corrections"); that protected file stays unedited and this record is the
  correction.
  Mutants without the bound or the order check fail as intended
  (`cv2-r3-mut-universal-a6`, `cv2-r3-mut-order-a1`).
- **Scope:** the synthetic correction path. **Duration:** until the next re-pin.
- **Claims withdrawn:** the old exact-amount statement and the E911/88D8 pins as
  deciders of new corrections; any claim that Lean checks the determination digest
  or idempotency key (the checker's `determination:digest`, `outbox:binding` and
  `action:idempotency` do). Reuse still trusts the recorded shortfall and ignores
  the paid list.

## Gate decision rules: statement changes (2026-09-28, XI.2 record)

Baseline trunk `6cccb84`; changes in `78eabc7` and `4bffc1e` (merged as
gate-rules-2). Felt effect: an analyst sees an unusable source
as a review item with the fact it still lists, never a hold or allow resting on
unchecked rows, and a store that rolls back cannot earn ALLOW.

- **Predicate:** `lean/BlindLedger/Gate/Rules/Theorems.lean`.
  - `usable_iff` and `Usable`: the row check takes the snapshot's `asOf`
    (`ok : Nat → α → Bool`), so a death dated after its snapshot's `asOf` makes
    the snapshot unusable.
  - `ids_disjoint`: hypothesis and conclusion move from the sets read to the
    gate's views (`releasedSet c`, `unresolvedSet c`) and next checkpoints
    (`.released.entries`, `.unresolved.entries`). Restated over the views the same
    way: `seenAt`, `decideBatch_get`, `fail_closed`, `allow_clear`, `decided_kept`.
  - `later_allow_clear` assumed `entries c₂.released = (decideBatch c b₁).released`;
    it now assumes `c₂.releasedPrior` (and unresolved) is the checkpoint the batch
    produced. `Fact` and `fires_iff` gain `MEMBER_DECEASED_UNVERIFIED`,
    `MEMBER_NOT_ENROLLED_UNVERIFIED`, `PROVIDER_DECEASED_UNVERIFIED`,
    `PROVIDER_EXCLUDED_UNVERIFIED` and `FFS_DUPLICATE_UNVERIFIED`.
  - Added: `allow_clear_store`, `later_allow_clear_many`, `view_chained`,
    `prior_view`, `prior_advance`, `mem_iterate`, `looseKeys_grows`,
    `isSome_of_mem`; new axiom pins ([propext, Quot.sound]).
- **Invariant / failure:** X.1-X.2, XI.8, XI.10: no HOLD rests on data not
  checked against the gate's checkpoint, and no rollback or dropped row earns ALLOW.
- **Evidence:** the changed vector answers are listed in 78eabc7's message.
- **Disposition:** replace. Nothing is disabled.
- **Replacement control:** all proofs compile with pinned axioms; the vectors, demo lines
  and mutants pass (counts: `STATUS.md`); the unittest fails if the runner is older than its sources.
- **Scope:** decision rules R1-R5 as tests; not the token path (no signed
  checkpoints or release path). **Duration:** until the gate-v1 token path lands.
- **Claims withdrawn:** the earlier statements above and the vector and mutant
  counts taken before these commits; STATUS names only the new counts.

## Line pack: CMS deferral response (2026-09-28, XI.2 record)

Felt effect: when CMS defers a CMS-64.9 line, a state finance lead gets that
line and quarter reconciled to the cent in minutes, not weeks. Coverage is
shown on the pack's face.

- **Predicate:** `app/right_rail_financial_line_pack.py` emits canonical
  `RR/LINE-PACK/CMS-64.9/v1` JSON from a Continuity package that
  `verify_database` binds row for row to a fully verified store opened
  read-only (the package digest is public, so package checks alone prove
  nothing), and a line map. Exactly one `line-map:sha256:<hex>` entry in an
  approved Control Pack's `source_refs` binds the map, so the schema is
  unchanged. Verification holds a read transaction that writers wait on (busy
  timeout): run it on a quiet store or a copy.
- **What each pack carries:**
  - rows of payments matching the map's program/source predicate, paid in the
    federal fiscal quarter (UTC boundaries), recorded before its end and not
    reversed by a record before its end. "Recorded" is the evidence's
    owner-clock `received_at_ms`, never a caller's date: the Owner reads its
    clock once per command (a clock behind the history writes nothing); the
    checker requires it to equal the writing event's `committed_at_ms`, commit
    times never to decrease, and never to precede `event_at_ms`;
  - `prior_quarter_adjustments`: each payment, reversal or amount conflict
    (`CONFLICT`) of an earlier quarter's payment, listed once in the quarter
    that recorded it, never netted;
  - every field reads only what was recorded before quarter end, so a closed
    quarter's pack changes only in `source`, `generated_at_ms` and `supersedes`:
    the last evaluation before the end, the Control Pack and population
    published before it, and the manifest bound to that population unless
    superseded before it (the Owner refuses to supersede a published roster
    and never changes a pack's status);
  - each row's evidence digest, evaluation receipt and rule version;
  - a service-period split, the member-manifest digest and a provenance root;
  - coverage as integer cents over the reported line.
- **Invariant/failure:** the pack is documentation only and carries no
  determination.
  - A reversed payment, a row not decided under the bound pack, no single
    unsuperseded published roster at quarter end, a map window short of the
    quarter, an amount conflict recorded before quarter end, and a cents gap
    in either direction are each listed in `unavailable`; any gap rules out
    FULL.
  - Five never-held items are always listed.
  - A superseding pack must have the same line, quarter and store (genesis,
    owner, mode, scope), a later time, and a head that is this history's
    head at its sequence.
- **Format:** stays `v1` though its fields changed after 17142e3; no earlier
  pack is kept as evidence. **Evidence:** `tests/test_right_rail_financial_line_pack.py`.
- **Scope:** derived artifact, plus the clock binding above: support evidence
  takes no caller received time (a retry keeps the first), and a
  `decision_at_ms` after the owner clock is refused (`decision_time_future`;
  Lean needs the same guard, a follow-up). When the host clock steps back (NTP,
  a restored VM, host skew), every write is refused (`event_commit_order`) until
  the clock passes the last committed time; history is never reordered. Stores written by trunk
  `6cccb84` or earlier are not readable (`replay:evidence-received-at`);
  recreate the synthetic workspace. `signer` is null: no PQ signing path exists.
- **Proposed Lean (not written):** `line_pack_sum_eq_ledger`,
  `line_pack_rule_version_bound`, `line_pack_complete_or_declares_gap`,
  `line_pack_deterministic`, `line_pack_chronology_strict`,
  `line_pack_documentation_only`.
- **Kill criteria:** (1) the synthetic pack does not reconcile to a synthetic
  64.9 line to the cent; (2) coverage is under about 50% on lines a state
  actually had deferred; (3) reviewers mostly ask for allowability evidence the
  Ledger never holds.
- **Follow-up:** the W0 growth breakdown needs units, rates and multiple
  periods, which the Ledger does not hold; there is no per-claim service date,
  so the split uses the obligation period.

## Gate formats rounds 7 and 8 (2026-09-28 and 09-29, XI.2 record)

These rounds reissued the golden vectors, pins, keys and signatures. Felt effect: a biweekly or
monthly payer's stale ALLOW is re-decided, not stranded in review, and no line is paid twice.

- **Round 7:** request lines (at most 569 bytes) bound to flow, member key,
  payee and amount; leaf `decided_at`; nonzero `lines_root` for FFS_CLAIM;
  checkpoint `state_digest` (never zero), previous digest only after the first,
  a non-adjacent link is a fork; one certificate per (tenant, epoch);
  `sign_batch` refuses a leaf routed to another shard, stateless (unbuilt: STATUS).
- **Round 8:** age per flow (`maxDecisionAge`), replacing round 7's single
  14-day age; a second certificate for an installed (tenant, epoch) is recorded
  (`equivocations`) and blocks it; FFS_CYCLE and CAP_820 need lines, SDP and
  PLAN_PAY leaves are HUMAN_REVIEW; `redecides` makes revision `latest + 1`.
  Rules: `redo`/`own` re-decision; only ALLOW payments' lines are released
  (`payOutcome`); binary set pins (`pinInput`); `Ctx.anchor`. Theorems:
  `verifyToken_unforked` adds equivocation; `released_iff`,
  `one_payment_per_line`, `Steps.at_most_once`, `installCert_equivocation`
  proved. Withdrawn: round 7's FFS_CLAIM-only lines and counts.

## Gate PQ signing M1 (2026-09-29, XI.2 record; founder-approved R1-R4, laptop root, ACVP download)

Felt effect: every checkpoint signature is checked by an independent Lean
verifier before it can leave the gate, post-quantum only.

- **R1, KEY-CERT/v1 (the one wire change; new digest domain):** `KEY-CERT NUL ‖
  alg u8 1 ‖ tenant ‖ epoch u64 ‖ shard_count u32 ‖ public key (2592)`, then
  `u16 4627 ‖ root signature`; no id; 8 KiB. `certChainOk` holds iff it decodes and
  the root key verifies the body. Unlike target §11, the
  root is ML-DSA-87 in laptop DPAPI custody, not HSM LMS/XMSS.
- **R2:** pure ML-DSA-87, empty context; hedged (rnd = 0 in vectors only).
- **R3:** `EpochCert` drops `certId`, gains `signed`; `AXIOMS.txt` unchanged. Statement change: below.
- **R4:** `artifacts/gate-verify/` (Lean `gate_verify`, the signer's self-check) and a new worker pin.
- **Speed:** each pinned exe is copied once per process, held open and hash-checked per run.
- **Claim:** vector-verified, not proved.

**Certificate equivocation (XI.2 record).**
- **Predicate:** `installCert_equivocation` and the `installCert` filter:
  a second chain-valid certificate for an installed (tenant, epoch) was equivocation if it differed at all
  (`x ≠ e`); now only if its public key or shard count differs.
- **Invariant / failure:** one key and shard count per (tenant, epoch); a hedged re-signature has new
  bytes, so re-issuing blocked its own epoch.
- **Evidence and replacement control:** vectors `other8` re-signed (not flagged), `twin` (other key), `eq5`
  (same key, 8 shards; both flagged, block); 256/256, build `pqm1-lean4-a1`; four `gate__mutants` mutants.
- **Disposition:** weaken. **Scope:** the spec-level payer model until M2 persists `PayerState`.
- **Claims withdrawn:** that any second, different certificate is equivocation (round 8).

## Follow-through decision event (M2, 2026-09-29, XI.2 record)

- **Felt effect.** An auditor sees, for every close or assignment, the official, the role, the reason code and the AI or contractor suggestion that preceded it, side by side, with whether the two agree.
- **Predicate.** `_EVENT_KINDS["OBLIGATION"]` and `_COMMAND_SOURCES`: the `financial_events.kind` values a Continuity v8 package may carry.
- **Change.** One kind, `FOLLOWTHROUGH_DECIDED`, on OBLIGATION: before = after = the current revision; the payload has exactly `decision_id`, `item_id`, `act`, `reason_code`, `owner_id`, `suggestion`, `actor_id`, `actor_role`, `authority_id`, `authority_epoch` and `authority_digest`; no row images. One command kind, `FOLLOWTHROUGH_DECISION:<decision_id>`, has the request `{command, key, payload_digest}`.
- **Invariant.** Every history act is known and fully re-verified; an unknown or forged act cannot change what an auditor reads.
- **Evidence.** The set has no act for an official's assign or close; the alternatives break other controls: SUPPORT evidence flips `verification_status` to SUPPORTED, so a suggestion would read as proof (I.3); a side file sits outside the hash chain.
- **Disposition.** Retain the gate: the set stays closed, extended by one kind.
- **Control.** One `_verify_followthrough_event` checks shape, revision, roster, pack role, authority and suggestion time. It runs before COMMIT (`verify_followthrough_connection`, called by the owner inside the write; `verify_obligation_connection` also runs it on touched obligations) and on open (`_verify_followthrough_decisions`), so no decision the checker rejects can commit. The command row is re-derived from the event. Checkers from before M2 fail closed with `history:event-kind`.
- **Format.** Unchanged: Continuity v8 and its table columns; the EVENT v2, COMMAND v1 and CONTINUITY v8 digest domains. Stores without a decision are byte-identical.
- **Scope.** All stores; permanent.
- **Claims withdrawn.** "Any v8 checker verifies any v8 package" no longer holds: a package that contains a decision needs a checker at or after M2. No Lean theorem covers the decision act; the Lean-controlled claim still covers only the correction transition.
- **Kill criteria.** Stop if an existing test expectation or digest changes, a table column or digest domain is needed, or the correction follow-up leaves CURRENT.

## Lean-live M1: Lean is the only evaluator (2026-09-29, XI.2 record)

- **Predicate:** the `artifacts/engine-evaluator/` worker pin and frame (u32 big-endian length; BLFIN02 in; tag 0 plus BLFRES02, or byte 1-3, out); the invariants test `_python_decision_paths_forbidden` drops its `evaluate_financial_snapshot` patch.
- **Invariant / failure:** III.1, V.1, V.2: one decider; an undecidable write is refused. Failure: a second evaluator that differs.
- **Evidence:** 59,756 shadow answers agree, none differ; a worker hid a Lean panic behind stderr and now aborts on it.
- **Disposition:** replace. Python evaluator, snapshot comparison and tests deleted.
- **Replacement control:** worker laws on `propext`, `Classical.choice`, `Quot.sound`; checker re-check before COMMIT; every failure closed.
- **Scope, duration:** live evaluation only; until M3.
- **Withdrawn:** "evaluation is a read-only comparison"; the r74 snapshot evidence.
- **Open:** closed in M1.5.

## Lean-live M1.5: evaluator worker memory (2026-09-29, XI.2 record)

- **Predicate:** the `artifacts/engine-evaluator/` pin, re-pinned from `405812e` (`PROVENANCE.md`); frame and laws unchanged.
- **Cause:** `libleanrt.a` links mimalloc 2.2.3 statically and its start-up hook (`DllMain`) never runs, so it has no arena: every 32 MiB segment is a direct OS allocation, and a freed one is never reused or returned (17 allocated, 3 live, 576 MiB reserved). No Lean object was retained.
- **Change:** the worker reserves a 1 GiB uncommitted arena (`mi_reserve_os_memory`) before its first frame; exit 70 if refused. The 1e9-byte job cap lies inside it.
- **Evidence:** `test_large_requests_keep_the_worker_flat` fails on the M1 pin (137 to 776 MB over 20 requests of 600 KB) and passes on this pin (`leak-pin-t1`); two fresh stage builds gave the same bytes. Bisection and option sweep: `rrb/designs/lean-leak-bisect.md`.
- **Disposition:** fixed at the root; restart at 1,000 requests or 400 MB stays as a backstop. The cursor decoder is not needed for memory.
- **Rejected:** other options: the bisection note.

## Lean-live M1.6: dead decoder (2026-09-30, XI.2 record)

- **Change.** `Fast.listEqAt`, `decodeFinancialInputBA`, their theorems and `AxiomCheck` line go: unreachable code and theorems about it. No executed-path statement changes; `decodeFinancialInputBA₂_eq` covers it.
- **Why.** Lead decision, anti-bloat and max auditability: the dead theorem made the audit trail cite the wrong proof.

## Lean paid sum (2026-09-29, XI.2 record; Lean boundary inventory move 1)

Lean used to take `command.correctionPaid`, per-action totals Python summed, on
trust. It now derives the paid list from payment rows. Design and builder handoff:
`40e802f:docs/CORE_REDESIGN.md`.

- **Felt effect:** no caller can make a paid request look unpaid, or the reverse, to
  change what the next hospital is asked for.
- **Predicate:** the BLFCMD02 wire (`correctionPaid`, version 2); theorems
  `applyCorrectionTransition_action_amount_eq_b2` (B2) and
  `applyCorrectionTransition_outstanding_within_shortfall` (H1), both over
  `request.command.correctionPaid`, and their manifest pins; `CorrectionMutationLinkFacts.
  dependencyCorrectionPaid` and the `correctionPaid` clause of `commandWireAdmissible`; the
  protected literal at `tests/test_right_rail_financial_constitution_invariants.py:338`
  (`BLFCMD02`, now `BLFCMD03`).
- **Invariant / failure:** a correction never requests more than the unpaid shortfall less
  what open requests still ask (II, III.4); failure: a wrong or forged paid total silently
  moving the request amount.
- **Evidence:** `Transition.lean` made Lean's paid list equal the command's, so B2 and H1
  held for whatever list a caller sent; the only checks were Python twins (the Owner's
  payment cap, the checker's `paid_at`). `ARCHITECTURE.md` "Lean decides" overstated this.
- **Disposition:** replace.
- **Replacement control:** Lean derives the list. New proved statements: `PaidSum.lean` (3
  row laws), `CodecLaws/PaymentLinks.lean`, `PaidSumTheorems.lean` (7, including
  `derivedCorrectionPaid_sound`/`_complete` and the main theorem
  `applyCorrectionTransition_paid_eq_linked`). The two removed theorems are replaced by
  stronger ones over the derived list: `applyCorrectionTransition_action_amount_eq_linked`
  (B2) and `_outstanding_within_shortfall_linked` (H1). Not "none edited": in
  `CorrectionMutationLinkFacts`, `amountRule` and `inputShortfall` were restated over
  `mutation.dependencies.correctionPaid` and a `derivedPaid` field replaced
  `dependencyCorrectionPaid`. Tests:
  `test_forged_links_move_the_lean_request_exactly_as_the_theorem_says`,
  `test_lean_paid_sum_matches_the_rows_and_the_independent_checker`,
  `test_correction_request_vector_is_blfcmd03_and_its_mutants_are_refused`; the checker's
  `action:payload-binding` and `action:requestable`, unchanged.
- **Scope / duration:** the synthetic correction path, until the next re-pin.
- **Kill criteria:** stop if a stored row, digest domain or BLFIN02/BLFCRES3 byte must
  change, if completeness needs more than a well-formed input that evaluates, or if the
  derivation needs a quadratic step.
- **Format.** `BLFCMD03` (version field 3): `paymentLinks` replaces `correctionPaid`:
  u16 count, then per link `paymentId` and `actionId` (u16-length strings), strictly
  ascending by `paymentId`, one per row whose PAYMENT_RECEIVED event names
  `pays_action_id`. BLFIN02, BLFCRES3, BLFCRU02/BLFCRV02 and every digest domain are
  unchanged; `dependencies.correctionPaid` echoes Lean's derived list. Hard cut, no dual
  read; nothing stored holds BLFCMD bytes; contract string and artifact version unchanged.
- **What Lean decides.** Decode refuses unordered or duplicate links (Owner:
  `correction_transition_failed`, not `INVALID_INPUT`). Preflight (`derivedCorrectionPaid`,
  O(n + k log k + a)) makes a link naming no payment row, or an action that is not a
  correction request of the input, `INVALID_INPUT` (Owner: `correction_input_invalid`); a row
  counts only if ACTIVE. Links naming real rows are accepted and move the request by exactly
  the linked active cents. Which rows may be linked, payment timing and the per-request cap are
  enforced by the Python owner (`right_rail_financial_owner.py` ~4089 via `_correction_paid`
  ~434-445) and the independent checker (`paid_at` ~2828, ~2912), which refuses a forged list
  before COMMIT (`action:payload-binding`).
- **Claims withdrawn:** B2 and H1 as stated over a caller list; `1A7A1833...D3AF` as
  decider of new corrections (history only, rule `h1-v1`). Not covered: reuse ignores the
  paid list; Lean does not enforce payment timing or the per-request cap.
- **Execution (rr-eng, 2026-09-29).** All 10 new statements proved against rr-core's text,
  axioms `propext`, `Classical.choice`, `Quot.sound` only; `lpsb-x2`/`-x3` (93-job builds, no
  `sorry`), `lpsb-kat2` (44 of 44, two new KATs). Re-pin: `PROVENANCE.md`.

## Slim-1b PR-2: guard naming and instrument classification (2026-09-29, XI.2 record)

- **Felt effect.** A reviewer reads the guard that actually runs.
- **Predicate.** Article X.2, the wrapper that heavy runs must use; and the split size budget (founder 2026-09-28, `tests/test_bloat_budget.py`).
- **Change.** X.2 names `rr_guarded.ps1` running `work/rightrail-guard-host/native/guard/run_guarded_v7.ps1`, with an explicit exception for engine and release builds (v4). The trunk copy (`run.ps1`, `run_guarded_v4.ps1`, `pins.json`, `suites.json`, README, direct-mask fixture) moves to `parked/`. `semantic_assurance_gate.py` and its manifest move to `lean/tools/`; the privacy scanner pair moves to `tests/instruments/`; the budget counts both as evidence.
- **Invariant.** A heavy run cannot start or continue below the memory floor, is contained, cleaned up and logged. Failure: certifying a control that does not run.
- **Evidence.** The floor moved from v4's 2,190,433,321 to v7's 2,029,372,048 (1 GiB in away mode) under the grants cited in the amendment log. No test or product path reaches trunk `run.ps1` or v4; only the parked `-Light` lane did. The producer (`build_financial_correction_release.ps1:26,774`) and the kit (`kit.py:51,495-519`) accept only v4, and read the external v4 copy. 
- **Disposition.** Retain the gate; park the redundant copy; name the live one.
- **Replacement control.** The runner's hash check and the guard logs in `C:/Users/neers/rrb/logs/`; the producer's and kit's v4 hash checks are unchanged.
- **Format.** No wire format, digest domain or theorem statement changes.
- **Scope.** Laptop runs; permanent until the producer and kit move to v7, which is planned, not done.
- **Claims withdrawn.** "v4 is the guarded wrapper" and "the floor is 2,190,433,321" no longer hold for tests. Engine and release builds still run at v4's floor.
- **Kill criteria.** Restore from `parked/native_guard/` if `-Light` is revived or a release step needs the trunk v4 path.

## gate_verify re-pin after slim and quick-wins (2026-09-29, XI.2 record)

- **Felt effect.** The signer runs a verifier built from the Lean tree it ships with.
- **Predicate.** `test_gate_verify_pin_names_the_current_lean_tree`: the `lean/` manifest recorded in `artifacts/gate-verify/PROVENANCE.txt` equals the tree's, and the tree's build is the pinned exe.
- **Change.** `gate_verify.exe` rebuilt: the hash is unchanged, so `gate_verify.sha256` is not re-pinned; the Source manifest in `PROVENANCE.txt` is re-recorded (tracked `lean/` files only). Two causes moved the manifest. Slim moved `semantic_assurance_gate.py` and its manifest under `lean/tools/`. Quick-wins changed `lakefile.toml` (comment, default targets), gave `AxiomCheck.lean` `#guard_msgs` pins for the theorems the gate does not check (the gate's own are printed, not pinned) and moved the retired Semantic kernel to `parked/`. No theorem statement or wire format changes.
- **Invariant.** A change under `lean/` cannot ship with a stale verifier pin. Failure: the signer trusts a build no one reproduced.
- **Disposition.** Retain the gate. **Replacement control.** None. **Scope.** Until the next `lean/` edit.
- **Kill criteria.** Drop the manifest check if the pin moves to a hash of the exe's own import closure.

## gate_verify and worker re-pin after the lean-leak merge (2026-09-30, XI.2 record)

- **Felt effect.** The signer and the evaluator worker run binaries built from the Lean tree they ship with; a payer's checkpoint is never checked by an unreproduced build.
- **Predicate.** `test_gate_verify_pin_names_the_current_lean_tree` (the `lean/` manifest in `artifacts/gate-verify/PROVENANCE.txt` equals the tree's); the worker pin (`EVALUATOR_ARTIFACT_SIZE_BYTES`, SHA-256 in `app/right_rail_financial_engine.py` and `artifacts/engine-evaluator/PROVENANCE.md`); `PINNED_EXES` in `lean/tools/semantic_assurance_gate.py`, which now lists `blind_financial_worker` beside the correction exe.
- **Change.** Merge of trunk `1e1579c` into `lean-leak` (`b6bc647`, lean tree `da3d331a`). Manifest re-recorded: 60 files (was 54), `00e28f0e...`. Gate exe: unchanged `fc45ce6d...`. Worker: new 5,727,744 bytes, `E95C6D52...3D97`, from the M1.6 dead-decoder removal; two fresh stages `leakint-stagea`/`leakint-stageb` byte-identical. Correction engine `1A5821FA...DDBE`: reproduced byte for byte by the same two stage builds (its pin is not re-recorded); the release producer has not run on this tree, see `artifacts/engine-correction/PROVENANCE.md`. No theorem statement, wire format or digest changes.
- **Invariant.** A change under `lean/` cannot ship with a stale verifier or worker pin; the worker's import closure holds no proof-side module (V.3). Failure: the signer or the write path trusts a build no one reproduced, or a proof edit moves the worker's bytes.
- **Evidence.** Guard logs `leakint-stagea`, `leakint-stageb`, `leakint-probe`, `leakint-full1` (SUMMARY in its console log). The ten `WorkerLaws` theorems use `propext`, `Classical.choice`, `Quot.sound` only, some fewer (stage log).
- **Disposition.** Retain the gates. Re-record the manifest, re-pin the worker, add the worker to the closure check. **Replacement control.** None. **Scope.** Until the next `lean/` edit.
- **Claims withdrawn.** The worker pin `0AE566ED...` (5,728,256 bytes); the `lean-paid-sum` builds do not vouch for the merged tree.
- **Kill criteria.** Stop if the two stages differ, the gate exe moves without a source change in its closure, or the correction engine is not reproduced.

## The worker's frame loop as a checked fixpoint (2026-09-30, XI.2 record, lean-partials-v1 commit A)

- **Felt effect.** None for any user today. Auditors and the TCB gate lose three standing "partial" holes (`WorkerCli.serve`, `WorkerCli.readExact`, `Runtime.readFinancialBounded`); "the worker answers every frame and keeps no state" becomes a checked theorem instead of a claim.
- **Predicate.** Plan item 5 (M1.5) and the three financial `VIOLATION-TODO` entries on trunk `48d6e9b`.
- **Change.** One total, well-founded `readUpTo` replaces `readExact`, both `readFinancialBounded` copies and the Cli wrapper. `serveWorker` is a `partial_fixpoint` over any `MonadTail` monad, `@[specialize]`d into a jump in the worker (`serveWorker._at_.WorkerCli.main.spec_0`, `goto _start`). `WorkerLaws.lean` models it as a total `workerRun` over a pure pipe with arbitrary chunking; `serveWorker_run` equates the two and `serveWorker_stateless`, `workerRun_frames/oversize/truncated`, `readUpTo_pipe` are proved and pinned in `AxiomCheck.lean` (standard three axioms only). Lean 4.33.1 needs one local attribute (`partial_fixpoint_monotone` on `MonadTail.monotone_bind_right`) that the design did not foresee. The TCB gate gains a `fixpoint` kind and one allowlist entry, `BlindLedger.Financial.serveWorker`.
- **Invariant.** The same stdout bytes and exit codes for every input to the worker and the correction exe (`tests/test_lean_io_loops.py`, 11 tests, passing on the current pins: guard log `prtb2-targ2`, and the reviewer's advisory run `rvw-prt-io`; no run against a retired pin is recorded). A new `partial_fixpoint` anywhere else fails the gate unless named.
- **Evidence.** Fresh stages `lpsm-stagea`, `lpsm-stageb` of `fa53ef1`: worker `EE651742...7C21` identical in both, `gate_verify` `FC45CE6D...CB06` unchanged, correction exe `D5A06E9F...0CBB` identical in both. Live TCB report: 0 violations, worker and correction TODO sets empty, `gate_verify` keeps `rejNtt` and `sampleInBall`.
- **Disposition.** Retain. Re-pin the worker; the correction pin waits for the release producer. **Replacement control.** The `fixpoint` kind replaces three name-by-name TODOs. **Scope.** Worker, correction and Cli exes and the TCB gate. Not the ML-DSA samplers or the `loop` kind (commit B), not batch frames.
- **Claims withdrawn.** The worker pin `E95C6D52...3D97`; "the financial exes contain unproved partial loops".
- **Kill criteria.** Any `test_lean_io_loops` failure; a non-jump self-call in the specialised loop; a theorem that cannot be proved as written.

## Bounded ML-DSA sampling and the loop kind (2026-09-30, XI.2 record, lean-partials-v1 commit B)

- **Felt effect.** None for any user today. Auditors and the TCB gate lose the last two standing "partial" holes (`MlDsa87.rejNtt`, `sampleInBall`); the sampler's reads become a stated, tested bound instead of an open loop.
- **Predicate.** Plan item 5 (M1.5) and the two remaining `VIOLATION-TODO` entries in `tools/tcb_report.txt`.
- **Change.** `rejNtt` and `sampleInBall` read at most FIPS 204 Appendix C Table 3's bytes (894 of SHAKE128 for RejNTTPoly, 221 of SHAKE256 for SampleInBall) and return `none` past them; `verify` turns `none` into `false`. `ntt`, `invNtt`, `hintUnpack` and the Keccak squeeze are range loops. Six new theorems in `Gate/MlDsa87Laws.lean`, pinned in `AxiomCheck` (statements as designed, none weakened). The gate gains the `loop` kind (`Lean.Loop.mk`, `repeatM`, and project use of `IO.iterate` or `for` over a `Stream`), so a new `while`, `repeat`, `IO.iterate` or stream loop fails unless named; a negative fixture in `tests/test_tcb_gate.py` proves it. The Keccak duplicate is left alone.
- **Invariant.** The same ACCEPT/REJECT for every input whose samplers finish within Table 3's bytes. Passing run `prtb2-targ2` (with the pinned `rr_gate_mldsa87.exe` copied in): the ACVP sigVer cases (`mldsa87_acvp.vectors`, 30, six accepting) through the Lean verifier and AWS-LC, ACVP keyGen and sigGen, the custody tests, and the Lean/AWS-LC differential on mutated signatures and keys. The accepting ACVP cases and every Rust-signed signature Lean verifies in those tests are the evidence that the bounds reject no valid signature. The 2^-256 figure is FIPS 204's, not measured.
- **Evidence.** Fresh stages `prtb-stagea/b` (117ad71) and `prtb2-stagea/b` (351cfa0), each a `git archive` build in its own directory: gate_verify `B9696F2E...D171C` identical in all four; correction `D5A06E9F...0CBB` identical and unchanged. Live TCB report from `tools/tcb_pin.ps1` (no override): 0 violations, 0 `VIOLATION-TODO`; the only non-Init allowlist entries are `serveWorker` (fixpoint) and `reserveArena`. Loop kinds the gate flags in project code: `while`/`repeat` (`Lean.Loop.mk`, `repeatM`), `IO.iterate` and `for` over a `Stream` (negative fixtures `spin`, `spinIter`, `spinStream`). Gap, stated: an Init/Std `partial` helper that loops on a caller's continuation is caught only if named in `loopHelpers`; the 27 such helpers in this toolchain were enumerated (`prt-list1`), only those three are reachable-and-user-callable in ordinary code, and none of the rest appears in the `--list` output of any pinned exe (`prt-reach`).
- **Disposition.** Retain. A behaviour change only in gate_verify, where more-than-Table-3 inputs are rejected (probability at most 2^-256, as FIPS 204 Appendix C allows); not a format change. Re-pin gate_verify `FC45CE6D...CB06` (retired) to `B9696F2E...D171C`. Worker re-pinned `EE651742...7C21` (retired) to `86299A0D...712B` because commit `ea42222` (one line of `FastEncode.lean`: `natBEPush` consumes its accumulator, removing a quadratic copy in the canonical re-encode) was cherry-picked before the stage builds; commit B alone did not change the worker. The correction exe is re-pinned `1A5821FA...DDBE` (retired, in `RETIRED_PINS`, rule `h1-v1`) to `D5A06E9F...0CBB` after the release producer (`engine-release-partials-p1`, receipt PASS) reproduced the stage-built bytes; the transition and reuse vectors are byte-identical, so no amount rule or digest moved.
- **Replacement control.** The `loop` kind replaces two name-by-name TODOs; any new such loop in our code fails the gate unless named. **Scope.** gate_verify, worker, correction, the TCB gate. Not the Keccak duplicate, batch frames or the cursor decoder.
- **Claims withdrawn.** "gate_verify runs FIPS 204's unbounded sampling loops"; the worker pin `EE651742...7C21`.
- **Kill criteria.** Any ACVP or differential flip; a theorem that cannot be proved as written; axioms outside the standard three; a valid signature rejected by the bounds.

## F1 regression test, expected failure (2026-09-30, XI.2 record 3, branch `r1-link-cap`)

- **Predicate.** `test_linked_payment_never_pays_past_the_balance`, section 7 of the constitution-invariants test, is `expectedFailure` until record 2 lands (log `r1-red-a39-L1`).
- **Claims withdrawn.** "Requests never collect unowed money": a linked 300,000 is accepted after an unlinked 300,000 has settled the balance. **Disposition.** Add.

## A linked payment never exceeds the balance (2026-09-30, XI.2 record 2, branch `r1-link-cap`)

- **Felt effect.** A payer who settles a shortfall directly, or whose linked payment is reversed after an unlinked one, can no longer have the same cents collected again through the request. R1 does not close the request: it stays open and unpayable until R2 (payer-facing cancellation, held for the founder).
- **Predicate.** `record_payment_evidence` refuses a linked payment above the shortfall at that moment (`payment_exceeds_unpaid_balance`), as well as above the request's unpaid part; the checker's `payment:link` applies the same limit against the evaluation before the payment. A linked payment whose whole amount is still owed is never refused.
- **Invariant.** No linked cent exceeds the balance it pays into. Failure: F1 scenario A (10,000,000 owed, 9,700,000 cash, request 300,000, an unlinked 300,000, then a linked 300,000 accepted). Scope: permanent. The Lean half stays with M3 step 2.
- **Stored format.** No wire or digest change. The rule covers all history with no version gate: a pre-R1 store holding a linked payment beyond the balance fails `open_verification:payment:link` by design and cannot be repaired (it holds an overcollection). Scanned (`r1-storescan-a1-L3`, read-only): 101 financial stores under `work/rightrail-main` and `rrb`, none with a linked payment; the six handoff zips hold no store. None was opened with the new checker, whose new limit reads only linked payments.
- **Evidence.** `r1-green2-a1-L1` (41 run, 40 passed), `r1-s4-a1-L3` (35 run, 34 passed), `r1-full-a7-L1` (607 run, 578 passed, 1 failed, 13 errors, 15 skipped). The 13 errors are the missing `gate_verify` and `rr_gate_mldsa87` exes; the failure is the quarter-end timing test (7.3-8.3 s on trunk too, `humancue-cash-trunk-a59-L3`). Uncommitted scratch mutations: deleting the checker's request clause fails S4 (`r1-mutreq-a7-L2`), its balance clause fails the acceptance test (`r1-mutbal-a4-L1`).
- **Disposition.** Replace the weaker control with a stronger one. **Claims withdrawn.** None; record 3's is restored for linked payments.

## Decision package verdict no longer depends on the page window (2026-09-30, XI.2 record; branch dpk-window-fix)

- **Predicate.** `FinancialOwner.decision_package` and the independent checker's rebuild of it (`tests/financial_decision_package_oracle.py`): the amount-support ladder in the conclusions.
- **Change.** Amount support was `SUPPORTED` only if the current page held an active payment or authorized-claim row, so a page of reversed payments, or a page past the payment and claim rows, gave `NO_LINKED_EVIDENCE`. It is now `SUPPORTED` iff the obligation has any active payment or authorized claim (`active_payment_count`, `authorized_claim_count`, already counted over all rows). The verdict fields (`evidence_status`, `required_conditions`, `missing_requirements`, `assessment`) now read only whole-obligation counts and sums; `supporting_evidence_ids` and the `*_references_complete` flags stay page-scoped, as paging, not a verdict. No query was added and no product line was added or removed (one condition replaced).
- **Invariant.** Verdicts on partial windows change; the old value was a bug. On the complete window (`limit=100, offset=0` when every list fits) the result is byte-identical, so no stored record, digest or contract shape moves and the contract stays `RR/FINANCIAL/DECISION-PACKAGE/v2`. Measured before the fix (`dpk-probe1-a1-L2`): on resolved item H, `limit=100, offset=0` gave amount SUPPORTED and assessment SUPPORTED, while `limit=1, offset=2`, `limit=2, offset=2` and `limit=1, offset=3` gave `NO_LINKED_EVIDENCE`, `amount_satisfied` UNKNOWN and assessment UNKNOWN.
- **Evidence.** Two new tests in `tests/test_right_rail_financial_acceptance.py` compare every `(limit, offset)` window over the evidence with the full window (cash, amount, reporting, delivery, assessment, required conditions, missing list, conflict count), on resolved H and on H after a payment is reversed and replaced (a page of only a reversed payment); the checker also verifies a partial window. Red on the unfixed tree: `dpkfix-red1-a2-L3` and `dpkfix-red2-a2-L1` (both fail on the window comparison). Green on the fixed tree: `dpkfix-green1-a3-L1` (acceptance and mirror modules, 137 run, 137 passed).
- **Disposition.** Retain. Behaviour change only for partial windows; reads only, no money or stored format change. A UI paging by evidence, or any auditor paging references, now sees one verdict.
- **Replacement control.** The new window tests; the oracle keeps its independent ladder with the same one-condition fix (S4), so an auditor can re-check without Lean.
- **Claims withdrawn.** "A package read at any window carries the same verdict" was untrue before this fix and is true after it.
- **Kill criteria.** Any window whose verdict differs from the full window; a change to the full-window package bytes.

## Lean-live M3 step 1: the payment model and the form-A codec (2026-09-30, XI.2 record, branch m3-step1)

- **Felt effect.** None for any user today: nothing calls the new Lean code. It is the checked model the payment path will be moved onto in later steps.
- **Predicate.** `designs/lean-live-m3-v1.md` rev 1.1, section 5: the payment ledger's step, run and codec theorems, as stated.
- **Change.** `lean/BlindLedger/Financial/Payment/` (Types, Transition, Laws, Ledger, Bridge, Codec, CodecLaws, KAT). 27 theorems proved as stated and pinned in `AxiomCheck.lean` on the standard three axioms; the BLFPAY01 form-A request codec with its decode-only-canonical round trip. Two lemmas in `CorrectionTransition/PaidSumTheorems.lean` became public. Not proved, not restated: the section 5 items that are false or undefined as written (`run_conflict_retry_unchanged`, `step_wellFormed`, `stepView_state`, `stepView_eq`, `paymentRespond_decode_none`, and the second conjunct of `chain_fold_eq_full`), reported to rr-core for revision; the form-B and answer codec, `Chain`, `ChainLaws` and the worker theorems are not built.
- **Invariant.** No compiled artifact moved: `gate_verify` `B9696F2E...D171C`, the worker `86299A0D...712B` and the correction exe `D5A06E9F...0CBB` are byte-identical to their pins (guard logs `m3s1-gv1-a10-L3`, `m3s1-exes-a1-L1`, 85 jobs, exit 0). The `lean/` manifest moved, 62 files `4ad07c06...` to 70 files `e6976e2e...`; `tools/tcb_report.txt` changes only that line, 0 violations (`tcb-live-20260930112008-a6-L3`, 7 of 7).
- **Disposition.** Retain. No money behaviour, stored format or digest changes. Builds are in-tree and incremental, not fresh stage pairs; a fresh pair before any release is still owed.
- **Replacement control, claims withdrawn.** None. **Scope.** Lean only.
- **Kill criteria.** An axiom outside the standard three; any pinned exe hash moving; a theorem statement edited to pass.

## lean/ manifest hashes LF bytes (2026-09-30, XI.2 record; trunk, after the m3-step1 merge)

- **Predicate.** The `lean/` source manifest in `tests/test_tcb_gate.py::_lean_manifest` and `tests/test_right_rail_gate_formats.py::test_gate_verify_pin_names_the_current_lean_tree`, recorded in `artifacts/gate-verify/PROVENANCE.txt` and `tools/tcb_report.txt`.
- **Change.** Each tracked file is hashed after CRLF→LF, which equals its git blob under `* text=auto eol=lf`. Before, the hash read raw checkout bytes, so a worktree holding CRLF copies of LF blobs gave a different manifest for the same commit: trunk computed `cea66658...` and m3-step1 recorded `e6976e2e...` for one tree. The canonical value is `9666e4e3...`, recomputed from the blobs with `git show` in both trees.
- **Invariant.** Any change to a tracked `lean/` file's content still moves the manifest. Only line-ending noise is ignored. Exe pins are unchanged.
- **Evidence.** Guard log `trunk-m3s1-merge-a2-L3` (the two manifest failures before the fix) and `trunk-lfmanifest` (after).
- **Kill criteria.** A content change under `lean/` that leaves the manifest unchanged.
## One Keccak and the last WorkerLaws pins (2026-09-30, XI.2 record, branch keccak-dedupe)

- **Felt effect.** None for any user. An auditor reads one SHA-3 sponge, not two; the last four `WorkerLaws` axiom lines can no longer drift unseen.
- **Predicate.** Lean-expansion plan item 11 ("remove the duplicate Keccak"); the ML-DSA ACVP vectors and `tests/test_lean_io_loops.py` are unchanged and pass.
- **Change.** `BlindLedger/Keccak.lean` is deleted. `Sha3.lean` now holds the compact sponge, keeping `BlindLedger.Semantic.sha3_512` and adding `shake128` and `shake256`; `MlDsa87`, `MlDsa87Laws` and `Verify` use it. `AxiomCheck` pins `decodeWorkerOutcome_encodeWorkerOutcome` (`propext`), `evaluateWire_evaluated` and `workerRespond_length_le` (the standard three) and `maxWorkerFrameBytes_fits_u32` (no axioms). No theorem statement, digest domain, wire format or output byte changes; Lean is 112 lines shorter. The `Bytes` alias in `Sha3.lean` is gone (only the parked, unbuilt `ExactKernel.lean` used it). `MlDsa87Laws` gains block-boundary KATs against Python `hashlib`: SHA3-512 at 71, 72 and 73 bytes, SHAKE128 at 167 to 169, SHAKE256 at 135 to 137.
- **Invariant.** Every SHA3-512 and SHAKE output is the same for every input: the gate's ACVP known answers exercise all three functions, and the correction vectors are byte-identical.
- **Evidence.** Guard logs `kd-dev3-a1-L3` (axioms printed), `kd-dev5-a1-L3` (in-tree build, 83 jobs, every pin holds), `kd-stagea-a1-L3` and `kd-stageb-a13-L1` (fresh `git archive` stages of `3485bf6`, 75 jobs, byte-identical), `tcb-live-20260930105616-a10-L3` (7 of 7, 0 violations), `kd-t2-a1-L3` (46 tests: ACVP, differential, io loops, rules runner, engine; 44 passed, 2 skipped as the live TCB gate, which the previous log ran). Full suite `kd-full-a2-L3`: 605 run, 591 passed, 13 skipped (panic probe unbuilt, live TCB gate, external candidate), 1 failed: `test_quarter_end_file_within_writer_timeout` (7.5 s against 5 s), which also fails on trunk `cb15263` (8.4 s, `kd-cash-trunk-a1-L3`) and does not touch this change.
- **Disposition.** Retain. Re-pin: correction `D5A06E9F...0CBB` (retired, `RETIRED_PINS`, rule `h1-v1`) to `FB659DA3...A785` (6,300,160 bytes); gate_verify `B9696F2E...D171C` to `9BD2602B...C9916` (4,205,568 bytes); worker `86299A0D...712B` unchanged. The release producer was not run: the correction pin is stage-built, as in lean-leak. **Replacement control.** None. **Scope.** Correction, gate_verify, the TCB report.
- **Claims withdrawn.** The correction pin `D5A06E9F...0CBB` and the gate_verify pin `B9696F2E...D171C` for new work; "the Keccak duplicate is left alone" (partials B record).
- **Kill criteria.** Any ACVP or correction-vector difference; a pinned axiom line that changes; two stages that differ.
- **Merged tree and throughput.** On merge commit `60a434e` (Payment/* is outside the correction closure): stage build `kd-stagec-a7-L1` reproduces `FB659DA3`, `86299A0D` and `9BD2602B`; `tcb-live-20260930131202-a5-L1` 7 of 7; `kd-t3-a4-L1` 153 passed, 2 skipped. Throughput did not regress: old against new correction exe on the same request, 7 alternating runs each (`kd-time-a2-L1`), no difference beyond noise; `sha3_512` over 1.5 MB (`kd-mbrun4-a1-L1`, 9 runs each) takes a median of about 1.06 s on the compact sponge against 1.6 to 1.7 s on the old `Sha3.lean` one, and 294 against 476 microseconds for 300 bytes.

## Open correction requests shrink with the balance (2026-09-30, XI.2 record 4, branch `r2-shrink`; design `rrb/designs/r2-request-shrink-v1.md`)

- **Felt effect.** The finance officer records a payer's check against a request and the auditor re-checks it. Before, after the balance fell the request still showed its full amount, and a payment to the newer of two requests could collect what the older one was owed. Now the package shows what each request still has open, the workspace offers "record cash" only when that payment fits, and the checker proves every linked cent was open when paid.
- **Predicate.** `record_payment_evidence`'s link rule and the checker's `payment:link`. `open(a) = min(unpaid(a), max(balance - unpaid of older counted requests, 0))`, served in `(revision, action_id)` order: the oldest keeps, the newest shrinks first. It is derived from recorded facts and never stored (no write site, no status, no migration).
- **Change.** R1's `amount > shortfall` becomes `amount > open` (same code `payment_exceeds_unpaid_balance`); `open <= shortfall`, so R1's clause is removed in owner and checker. Checker: `amount > owed - older`, a closed form per payment, run before the history bookkeeping so the forged-store test is answered by `payment:link`. Read contract `RR/FINANCIAL/DECISION-PACKAGE/v2` to `v3`: each action gains `open_cents` (an int for a correction request, 0 when cancelled, `null` otherwise); owner, Mirror allowlist, oracle and workspace move together. Workspace: "record cash" needs `open_cents` to cover the payment, and one line "Requested $X, open $Y" shows when they differ.
- **Invariant.** Every open amount is in `[0, unpaid]`, `sum open = min(sum unpaid, shortfall)`, and a request with open cents has every older request fully open. Scope: permanent, after every command, including `authorize_offset`. Failure: the S1 case (two requests of 300,000 on 600,000, 200,000 paid unlinked; a linked 100,001 to the newer was accepted).
- **Stored format.** No wire, digest or stored-format change; the package contract string is the only identifier that moves. An existing store fails the new checker only if it holds a linked payment to a newer request above its open amount then; `r1-storescan-a1-L3` found no store with any linked payment. Lean (M3 step 2) is not started: `tools/r2_request_shrink_goals.lean` holds the statements, and the pinned engine is unaffected.
- **Evidence.** Before the build, `r2-tests-a4-L3` (12 tests, 5 passed, 7 failed, each at the R2 assertion). After: `r2b-t1-a1-L1` (acceptance, invariants, Mirror, cash file, staff server: 213 run, 212 passed, 1 failed, the quarter-end timing test, 8.2 s on trunk too). Not yet run: the full suite and `tests.test_bloat_budget` (guard floor stops, `r2b-full`, `r2b-full2`, `r2b-t2`, six and three kills at 1.7-2.0 GB free); the ceilings were set from a file count that copies the test's own logic.
- **Disposition.** Replace the weaker control with a stronger one; no existing test changed. **Claims withdrawn.** None; R1's statement `record_link_within_shortfall` becomes a corollary. Not in this record: the delivery verdict "not required" for a request with nothing open, payer notices (dispatch is disabled), and the first `CANCELLED` transition, which must exclude it in both loops.
- **Kill criteria.** Any accepted linked payment above the request's open amount; an `open_cents` that differs from the oracle's recomputation; any oldest-keeps property test that needs the newest to hold cents first; a stored store that fails `payment:link` after legitimate use. Any of these reverts to R1.
