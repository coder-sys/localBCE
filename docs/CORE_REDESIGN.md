# Financial core redesign (approved by the founder 2026-09-24)

Approval (2026-09-24): founder approved the v8 rebuild and retiring v5/v6 stores, conditional on every step complying with CONSTITUTION.md; any step weakening a safety property or protected answer needs a separate founder decision.

Format approval (2026-09-24, CONSTITUTION V.4): the founder approved the v8 store/package format (RR/FINANCIAL/CONTINUITY/v8) in session chat ("Yes, approve v8"). The only protected change is CASE_11's export version string in `tests/rightrail_financial_expected_cases.py`. History-completeness approval (same date): one sealed opening-balance event, then full facts on every later event. Both v7 provisions (migration on open, opening-balance conversion) were superseded 2026-09-25 (decision C3): v7 conversion and `OPENING_BALANCE` were removed.

## Verdict

### Current-source Lean reproduction (2026-09-26, XI.2 record)

- Guard-log line endings: r78 refused the r77 kit (`engine_guard_log_policy_mismatch`):
  its 99 CRLF records hold the exact v4 policy but the kit's LF-only anchors match
  none. Predicate unchanged (parse the actual guard evidence; exact fields, counts,
  floors, exits, cleanup and mutex release; no pass from a receipt alone). Only the
  three record-ending patterns accept LF or CRLF; control: positive checks for both
  forms, malformed-ending and adverse-record mutations, independent review, a new
  complete kit run. Raw log bytes and digest binding are unchanged. Withdrawn: r78
  verifies no kit.
- Canonical manifest: r75 refused the r67 kit
  (`engine_source_manifest_not_canonical_or_current`): the producer sorted native
  Windows paths before replacing backslashes; the kit requires ordinal order of
  portable slash paths. Keep that predicate and all identity checks; normalize
  before sorting, compare with independently built Python canonical bytes, make
  a new guarded release. Scope: prospective manifests; r67 gains no kit claim.
- **Predicate:** an exact-source build claim binds the guarded producer receipt,
  all selected Lean/config bytes, toolchain, executable and both pinned vectors.
  **Failure:** an older binary's build does not establish reproducibility from a
  later combined source tree.
- **Evidence:** r67 built the 46-file source manifest at `61a24519` and
  reproduced the existing 6,279,168-byte executable byte-for-byte; transition and
  reuse outputs match both independent expected files. Guard exit zero, cleanup
  PASS, mutex released. r68 separately compiled all six Lake targets.
- **Disposition:** extend provenance with this reproduction; keep the historical
  origin, executable pin and retired-pin registry. **Control:** hashes, raw logs
  and exact comparisons stay inspectable; the producer's empty stream/process
  repairs passed a binary I/O regression and independent review.
- **Scope:** local synthetic build evidence for the recorded source and artifacts; no theorem statement, wire format, decision rule, executable bytes
  or allowed axiom changed. **Claims withdrawn:** no assurance for later source,
  whole-system qualification or all-theorem axiom hygiene; native diagnostic
  axioms and 21 r68 linter warnings remain visible.

### Current-engine service-kit connection (2026-09-26, XI.2 record)

- **Predicate:** the release producer requires four exact pinned vector inputs,
  then requires transition and reuse actual bytes to equal their pinned
  expected bytes; the kit checks the guarded receipt and the same inventory.
- **Invariant / failure:** a package exercises the exact engine protocol and
  carries the checker's pinned retired-engine registry; missing or stale inputs
  refuse packaging.
- **Evidence:** the producer still pinned BLFCMD01/BLFCRES1 and BLFCRU01/BLFCRV01
  (the engine uses CMD02/RES3 and RU02/RV02 and lacks reuse fixtures), and
  `STATE_FILES` omitted the registry the checker always requires.
- **Disposition:** replace stale fixture pins with current canonical vectors;
  retain all comparisons, provenance, resource checks and exact inventory.
- **Replacement control:** an independent reader derived the reuse baseline from
  the old immutable fixture (removing only fields ReuseCodec v2 removed);
  expected assessment bytes were specified before engine execution. A guarded
  actual/expected comparison, fresh release build and extracted-kit scenario
  remain required before a packaged-runtime claim.
- **Scope:** this synthetic current-engine release and kit inventory; no
  theorem, protocol semantics, guard, authority or cash rule is weakened;
  fixtures stay pinned until another release record replaces them. **Claims
  withdrawn:** old reuse-vector evidence does not verify v2; this unchanged-state
  baseline does not resolve paid-list/stale-shortfall reuse limitations or
  authorize using reuse to decide live commands.

Felt effect: replacement operators can install and verify the same correction
engine and history checker, then exercise retry and restore without rebuilding
package contents by hand. Finance staff's cash command now names the correction
it pays; an acknowledgment still has zero cash effect.

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

- Python alone computes every evaluation; Lean's BLFIN02 evaluator runs only in tests (V.1/V.2).
- Every staff read runs the full checker over the whole database (IX.3).
- Two canonical encodings (SHA3/ASCII and SHA-256/UTF-8 staff snapshot).
- The successor verifies and views but cannot continue the work (VII.2).

## Migration (each step leaves a working system; one guarded run per step)

Done: golden baselines; v5/v6 retired (XI.2 record); `commands` table, required
revision and actor, append-only triggers, FKs; complete-fact events and the
`apply` reducer (OWNER/CONTINUITY v8); Continuity v8 restore by replay; Switch
and Mirror reuse the replay. Standing rules: one typed decoder per record, no
re-validating own writes; Python re-derivation of Lean is replaced by read-set
binding plus a pre-COMMIT per-obligation checker; the checker is replay +
compare with an incremental mode and all 25 tamper tests still detect.
Open: after a guarded Lean rebuild, BLFIN02 becomes the live evaluator and more
transitions move to Lean.

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
- **Evidence:** 78eabc7's message lists the changed vector answers (205-208 and
  149 gain `*_UNVERIFIED`; 175 and 177 gain the checkpoint's counterpart reason).
  4bffc1e's "No committed theorem statement's text changes" holds only for it.
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

## Gate formats round 7 (2026-09-28, XI.2 record)

Formats are not frozen (D1) and are specified once, in target §4-§5 (with
the `RR/GATE` registry); round 7 changed them and reissued the golden vectors.

- **DECIDE-REQUEST:** lines are parsed (at most 569 bytes each) and bound to the
  request's flow, member key, payee and amount; an FFS_CLAIM request without
  lines is refused.
- **TOKEN leaf:** new `decided_at` before `epoch`, `decided_at <= issued_at`,
  kept across reissues. An FFS_CLAIM leaf needs a nonzero `lines_root`.
- **CHECKPOINT:** the zero field is now `state_digest` = H(`STATE/v1` NUL ‖
  released pin ‖ unresolved pin), never zero; a first checkpoint has no previous
  digest, a later one must.
- **Payer, codec, NUL:** fork, one-certificate-per-(tenant, epoch), `encode_line`,
  shard-checked stateless `sign_batch(..., state_digest, shard_count)` (unbuilt
  preconditions: target §4-§5, STATUS) and the NUL after every domain, including the
  rules pins and `TEST-ONLY-SEED`/`TEST-ONLY-MEMBER` keys, are specified in target §4-§5.
  Every `rules_v1` and `demo_zz` pin, synthetic key and signature was reissued.

## Gate formats round 8 (2026-09-29, XI.2 record)

The lead's round-7 review decisions, specified in target §4-§6; vectors and
pins reissued. Felt effect: a biweekly or monthly payer's stale ALLOW is
re-decided, not stranded in review, and no line is paid twice.

- **Payer:** age per flow (`maxDecisionAge`); a second certificate for an
  installed (tenant, epoch) is recorded (`equivocations`) and blocks it.
- **Formats:** FFS_CYCLE and CAP_820 need lines too; SDP and PLAN_PAY leaves
  are HUMAN_REVIEW; `redecides` makes revision `latest + 1`.
- **Rules:** `redo`/`own` re-decision; only ALLOW payments' lines are released
  (`payOutcome`); binary set pins (`pinInput`); `Ctx.anchor`.
- **Theorems:** `verifyToken_unforked` adds equivocation; `released_iff`,
  `one_payment_per_line`, `Steps.at_most_once`, `installCert_equivocation` proved.
- **Withdrawn:** round 7's single 14-day age, FFS_CLAIM-only lines, counts.

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
- **Open:** two large Lists alive at once leak about 34 MB per call in the compiled worker, cause unknown; one list kept, restart at 1,000 requests or 400 MB, cursor decoder queued (M1.5).

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
