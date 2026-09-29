# Financial core redesign (approved by the founder 2026-09-24)

Approval (2026-09-24): founder approved the v8 rebuild and retiring v5/v6 stores, conditional on every step complying with CONSTITUTION.md; any step weakening a safety property or protected answer needs a separate founder decision.

Format approval (2026-09-24, CONSTITUTION V.4): asked in session chat whether to move to the v8 store/package format (RR/FINANCIAL/CONTINUITY/v8), with v7 stores migrating all-or-nothing on owner open and v7 packages still verifiable, the founder answered "Yes, approve v8". The only protected change is CASE_11's export version string in `tests/rightrail_financial_expected_cases.py`.

History-completeness approval (2026-09-24, CONSTITUTION V.4): asked in session chat how v7 histories lacking full facts (payment item/time, evidence) become rebuildable, the founder chose "Opening balance": on conversion the owner writes one sealed opening-balance event holding every converted row, under a new, distinctly named digest domain, and thereafter every event records the full facts needed to rebuild all projections by apply(event). The alternative (rebuild from events plus side tables) was declined.

Source: first-principles review of the financial core (owner, checker, successor,
Mirror, Switch, engine path; ~25,100 Python lines). Constitution articles cited inline.

## Verdict

### Current-source Lean reproduction (2026-09-26, XI.2 record)

- Guard-log line endings: r78 refused the fresh r77 kit with
  `engine_guard_log_policy_mismatch`. Its 99 CRLF records contain the exact
  required v4 policy, but the kit's LF-only line anchors match zero policies.
  Predicate/invariant: parse the actual guard evidence and retain exact fields,
  counts, floors, exits, cleanup and mutex release; do not infer a pass from a
  receipt alone. Disposition: replace only the three record-ending patterns
  with LF-or-CRLF anchors. Replacement control: positive checks for both forms,
  malformed-ending and adverse-record mutations, independent review and a new
  complete kit run. Raw log bytes and their digest binding remain unchanged.
  Scope/duration: this v4 text-log parser until a separately reviewed format
  change. Claims withdrawn: r78 verifies no kit; no prior run is relabelled.
- Canonical manifest correction: r75 refused the r67 kit with
  `engine_source_manifest_not_canonical_or_current`. The producer sorted native
  Windows paths before replacing backslashes, placing `CodecLawsCheck.lean`
  before `CodecLaws/Correction.lean`; the existing kit requires ordinal ordering
  of the portable slash paths. Retain that exact canonical-byte predicate and
  all source identity checks. Normalize before sorting in the producer, compare
  its actual manifest against independently constructed Python canonical bytes,
  then create a new guarded release. Scope/duration: prospective manifests only;
  r67 evidence remains unchanged and does not acquire a kit-compatibility claim.
- **Predicate:** an exact-source build claim binds the guarded producer receipt,
  all selected Lean/config bytes, toolchain, executable and both pinned vectors.
- **Invariant / failure:** an older binary's historical build does not establish
  reproducibility from a later combined source tree.
- **Evidence:** r67 built the 46-file current source manifest at `61a24519` and
  reproduced the existing 6,279,168-byte executable byte-for-byte; transition
  and reuse outputs match both independent expected files. Guard exits are zero,
  cleanup PASS, mutex released. r68 separately compiled all six Lake targets.
- **Disposition:** extend provenance with this separately identified reproduction;
  retain the historical origin, executable pin and retired-pin registry unchanged.
- **Replacement control:** the source-manifest and receipt hashes, original raw
  guard/child logs and exact comparisons remain inspectable. The producer's empty
  stream/process-result repairs passed a binary I/O regression and independent
  review; resource, toolchain, source-identity and expected-answer checks remain.
- **Scope:** local synthetic build evidence only; no theorem statement, wire
  format, decision rule, executable bytes or allowed axiom is changed.
- **Duration:** this evidence applies only to the recorded source and artifacts;
  later changes require their own verification.
- **Claims withdrawn:** no assurance for later source, whole-system qualification
  or all-theorem axiom hygiene follows from reproducibility. Native diagnostic
  axioms and 21 r68 linter warnings remain visible; the formal gate has its own
  explicitly bounded declaration scope.

### Current-engine service-kit connection (2026-09-26, XI.2 record)

- **Predicate:** the release producer requires four exact pinned vector inputs,
  then requires transition and reuse actual bytes to equal their pinned
  expected bytes; the kit checks the guarded receipt and the same inventory.
- **Invariant / failure:** a package must exercise the exact engine protocol and
  carry the checker's pinned retired-engine registry. Missing or stale inputs
  must refuse packaging, not be omitted from its assurance.
- **Evidence:** the producer still pins BLFCMD01/BLFCRES1 and BLFCRU01/BLFCRV01;
  the current engine uses CMD02/RES3 and RU02/RV02, and lacks reuse fixtures.
  `STATE_FILES` also omitted the registry that the checker always requires.
- **Disposition:** replace stale fixture pins with current canonical vectors;
  retain all comparisons, provenance, resource checks and exact inventory.
- **Replacement control:** an independent reader derived the reuse baseline
  from the old immutable fixture, replacing its embedded accepted result and
  removing only fields removed by ReuseCodec v2. Expected assessment bytes were
  specified before engine execution; provenance records hashes and construction.
  Guarded actual/expected comparison, fresh release build and extracted-kit
  scenario remain required before a packaged-runtime claim.
- **Scope:** only this synthetic current-engine release and its kit inventory;
  no theorem, protocol semantics, guard, authority or cash rule is weakened.
- **Duration:** these fixtures remain pinned until another explicit release
  record replaces them; prior fixtures remain in Git history.
- **Claims withdrawn:** old reuse-vector evidence does not verify v2. This
  unchanged-state baseline does not resolve paid-list/stale-shortfall reuse
  limitations and does not authorize using reuse to decide live commands.

Felt effect: replacement operators can install and verify the same correction
engine and history checker, then exercise retry and restore without rebuilding
missing package contents by hand. Finance staff's cash command now identifies
the correction it pays; an acknowledgment still has zero cash effect.

### Kit evidence source binding (2026-09-28, XI.2 record)

- **Predicate:** `artifacts/engine-correction/PROVENANCE.md` may cite a run only
  for the source it actually packaged.
- **Invariant / failure:** r80/r84/r85/r88 were recorded as evidence for
  `86390ab`, but r80 packaged an uncommitted tree (cash-file modules, Owner
  `existing_only`) (rr-review H1).
- **Evidence:** a file-by-file comparison of the r80 archive with commit
  `707ba78` found every Lean source and 26 of 27 source files identical. The one
  difference is `right_rail_financial_engine.py`, whose derived reject map equals
  the archive's literal.
- **Disposition:** append a source-binding paragraph; edit no earlier text.
- **Replacement control:** the comparison script is rerunnable against any
  commit. A new kit is assembled from a clean checkout before any release claim.
- **Scope/duration:** provenance text only; no pin, digest, vector or gate changes.
- **Claims withdrawn:** r80/r84/r85/r88 are not evidence for `86390ab`.

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
- **Claims withdrawn:** reopening on any change to the obligation revision;
  evaluation id, revision, result or receipt digests; case id or status; or
  action identity, kind, status, reference or attempt. An acknowledgment no
  longer reopens.

### Safe support package v2 (2026-09-28, XI.2 record)

- **Predicate:** `CORPORATE-SUPPORT/v1` becomes `/v2`, built from approved fields
  only, never a redacted dump. Fields: software version, rule version, adapter
  versions, `work_ref_count`, reproduction. Consumers: the correction follow-up
  (Owner builds, Mirror re-checks) and a failed Continuity restore (Mirror
  builds in `_restore_continuity` and attaches it to the raised error as
  `corporate_support`; only the staff endpoint's 409 response returns it, the
  403, 503 and 400 responses do not).
- **Sources:** rule version = the pack the correction was decided under,
  `accepted_basis.control_pack` `{pack_id, version, digest}`, NONE if there is no
  accepted basis; adapter `population` = the population manifest contract for a
  follow-up and NONE for a restore failure (nothing was read);
  `work_ref_count` = 0 when CURRENT, else 1 (this correction), with no work id and
  no store counter; reproduction = `{vector_file_digest, case_id}` of the
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
  so an extra key at any level is refused, not dropped; the pack fields must
  also have fixed shapes (id pattern, positive int version, 128-digit upper hex). Tests run
  `tools/privacy_artifact_scan.py` on the follow-up and restore packages and
  require that it reports nothing beyond its unapproved-schema notice; that is
  what is checked, not a proof that no package can leak.
- **Raw evidence the old version is unsuitable:** v1 (commit `82a2087`) had no
  rule, adapter or software version and no affected work, and its reproduction
  `{scenario: SYNTHETIC_CORRECTION, real_data: false}` held nothing a
  corporate-support engineer could rerun; the restore failure had no package.
- **Disposition:** v1 replaced, not versioned alongside: it is derived, synthetic
  and has no outside consumer. Deleted: the Owner's `_corporate_support` and
  `continuity_restore_support` builders, its `restore_test_continuity` wrapper
  (callers use `restore_continuity(restore_mode="TEST")`) and Mirror's restore
  re-check, which the Owner's package validation already made, and the Mirror's
  own restore-mode check (the Owner refuses a bad mode first, before it creates
  anything).
- **Replacement control:** Mirror, staff-server and acceptance tests, run through
  the guard.
- **Scope / follow-ups:** correction follow-up and restore failure only. A
  failure raised by the staff workflow after a successful restore (package size,
  decision-package mismatch) carries no package yet. `work_ref_count` is 0/1
  until the G2 reopened set is cheap to read at build time. Real software and
  Trust Graph versions need a bound source first.
- **Claims withdrawn:** `reproduction {SYNTHETIC_CORRECTION, real_data: false}`;
  the earlier `affected_work {count, ids}` with the event sequence.

The core is ~2.5x larger than the invariants need. Root cause: state lives in
~20 editable tables with history as a side log, so every consumer (checker, successor,
continuity, Switch, Mirror) re-validates all tables in its own copy. Target shape:
one command log + one append-only, hash-chained history of complete facts + projections
rebuilt from it by one `apply(event)` per event kind. Estimated total ~9,300 lines
(8,000-11,000); owner ~3,000.

## Gaps found (under-enforcement, not just size)

- No command table: each handler invents its own retry/conflict rule (III.3).
- `expected_revision` optional on 10 handlers; 5 default the actor to a
  synthetic identity (III.3, I.2, XI.13).
- `financial_events` has no append-only trigger; FKs enabled but none declared (III.4).
- Python alone computes every evaluation; Lean's BLFIN02 evaluator runs only in tests (V.1/V.2).
- Every staff read runs the full checker over the whole database (IX.3).
- Two canonical encodings (SHA3/ASCII and SHA-256/UTF-8 staff snapshot).
- The successor verifies and views but cannot continue the work (VII.2).
- v5/v6 store versions cannot hold obligations and no such store exists (speculative).

## Target sizes

| Component | Today | Target |
|---|---|---|
| Owner package | ~7,100-7,400 | ~3,000 |
| Independent checker | 4,942 | ~1,800 (replay + compare; stays code-independent) |
| Continuity successor | 2,330 | ~300-800 (replay + TEST writer that can continue) |
| Mirror | 1,674 | ~500 |
| Switch | 1,408 | ~500 (reuses replay) |
| Engine + semantic adapter | 3,799 | ~1,300 |
| Process runner | 1,844 | ~800 (uncertain) |
| Staff server + CLI | 1,712 | ~1,100 |

## Migration (each step leaves a working system; one guarded run per step)

0. Baseline: run the financial suites through the guard; capture golden outputs
   (events, heads, decision packages, v7 package bytes) for the 12 cases.
1. Retire v5/v6 stores (XI.2 record; founder approval — they appear in contracts).
2. Close gaps: `commands` table, required revision and actor, append-only triggers, FKs.
3. Replace per-handler retry logic with the command log (goldens byte-identical).
4. Stop re-validating own writes; one typed decoder per record; version staff snapshot id.
5. Remove Python re-derivation of Lean (replacement: read-set binding + pre-COMMIT
   per-obligation checker).
6. Complete-fact events + `apply` reducer: new OWNER/CONTINUITY v8 contract with explicit
   v7->v8 conversion on owner open. Removed 2026-09-25 (decision C3): the conversion, the
   `OPENING_BALANCE` event and the v7 receiver are gone; a non-v8 store fails
   `unsupported_store_version`.
7. Checker becomes replay + compare with an incremental mode; all 25 tamper tests still detect.
8. Continuity v8, restore by replay, successor that can continue.
9. Switch and Mirror reuse the replay.
10. After a guarded Lean rebuild: BLFIN02 becomes the live evaluator; more transitions move to Lean.

## History segments (approved by the founder 2026-09-25)

Replaces the per-write whole-history size admission, which refused every write after
~900 commands. Kept: the 8 MiB package export, now refused at export, not at write.

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
- Writes note touched rows in `history_pending`: O(this write) (IX.3). Older stores (v8
  before segments) are replayed on open and sealed as segment 0 in the same transaction.
- The checker recomputes sealed segments' chain, counts and event heads from the events and
  the open segment's bookkeeping; sealed rows are append-only, bound by digest.
- `export_history`: one fsynced file per segment; an existing file is compared, never rewritten.
  `restore_continuity(history=...)`: the checker verifies manifest, chain, event chains and
  seals; a fresh owner replays each segment and must reseal it byte-identically;
  `verify_database` replays the result and the checker binds its rows to the final images.
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
   logical capture ticks cannot silently become Unix time. Contradictory failure
   fields cannot authorize admission.
3. Evidence before editing: profile lines 48-51 define ticks 7000/7010 and a
   365-day limit; producer line 310 checks only `startswith(("1900", "197"))`;
   verifier lines 351-356 repeat it, and lines 528-533 omit failure_code from
   admission. Guarded r32 now passes all 72 source/consumer/budget checks; the
   independent post-edit review also closed a numeric-to-string context bypass.
4. Disposition: replace the heuristic and refuse old profile bindings. Retain
   raw-envelope v2, logical capture fields, graph windows, bounds and nonclaims.
5. Replacement: immutable profile clock `SYNTHETIC_LOGICAL_SECONDS_V1`, reference
   tick 7010 at `2026-08-14T12:00:00Z`, one second per tick. Producer and verifier
   calculate age independently. Admission binds all six expected context fields;
   omitted context means the fixed fixture, not envelope-supplied identity/time.
   Source contract/schema/domain become v3; source profile and verifier become
   v5/epoch 5. Envelope v2, resource digests v2, generic graph profile v3 and the
   unbound capability-statement identity remain unchanged. Boundary, rebinding,
   calendar, context and failure-state tests must pass before new claims.
6. Scope: synthetic NC capture only. No live transport, payment authority,
   read-model freshness upgrade or changed resource limit. Felt effect: the
   implementation lead sees stale or invalid source captures refused during
   onboarding instead of troubleshooting a falsely fresh observation downstream.
7. Duration: the new synthetic contract remains until explicitly replaced;
   old bytes remain historical evidence and fail the new binding.
8. Withdrawn claims: old tests and profile/envelope/graph/receipt identities do
   not establish the new rule. FRESH means marker age at synthetic capture time,
   never current source truth. Independent post-edit review found no remaining
   source-boundary blocker. Current combined-source regression evidence and
   outstanding build requirements are recorded only in `STATUS.md`.

## Receiver cash-file boundary (XI.2 design, 2026-09-26)

Felt effect: during reconciliation, an implementation lead can preview one
fictional receiver file against the reviewed ledger, then explicitly record its
cash evidence as one transaction. This removes repeated manual entry while
preserving exact retries and a visible all-or-nothing result. No money moves.

- Predicate: accept only `RR/FINANCIAL/RECEIVER-CASH-FILE/v1`, canonical ASCII
  JSON of at most 1 MiB, with 1-500 ordered rows, at most 6 per item (more: `cash_file_row_cap`; measured limits in `STATUS.md`). Root fields are exactly
  `contract`, `source_class`, `scope`, `source`, `row_count`, `total_cents`,
  `rows`; `source_class` is `SYNTHETIC_RECEIVER_CASH`. Scope has exactly the
  existing state/deployment/program/period/currency fields, currency USD.
  Source has `source_id`, `version`, `receiver_system_id`, `capture_id`,
  `captured_at_ms`. Each row has exactly eight fields: `item_id`, `payment_id`,
  `common_origin_id`, `evidence_id`, `amount_cents`, `event_at_ms`,
  `pays_action_id`, `expected_revision`. The action link is explicitly null or
  an ID. Earlier planning called this nine fields but listed only these eight;
  eight is the intended exact set, with no implicit extra field.
- Invariant/failure: untrusted input never skips a row, turns acknowledgment or
  reporting into cash, substitutes an ID with the same total, or commits a
  partial file. IDs/version use the owner's 128-character grammar. Cents are
  positive integers and their sum is at most 2^63-1; times are integers from
  zero through 2^63-1, event time no later than capture time; revision is an
  integer from zero through 9,999. Booleans are not integers. Reject duplicate
  JSON keys, missing/extra fields, noncanonical bytes, duplicate payment/evidence
  IDs or item/origin pairs, and count/total disagreement. MCO reports, X12
  820/835 and MMIS extracts are unsupported formats and refuse completely.
- Evidence: `record_payment_evidence` can return CONFLICT after recording
  conflict evidence, or DUPLICATE with a different payment ID after recording
  alias evidence. `run_batch` rolls back exceptions, not those statuses. Checking
  only its returned report would accept partial or differently bound work.
  `_write` can also seal history after the batch body, so the final independent
  check must occur after sealing and before COMMIT.
- Disposition: add this explicitly fictional input contract; retain all owner
  commands, cash rules, existing wire/digest domains, expected answers and
  limits. No caller-provided callback or success flag authorizes acceptance.
- Replacement control: the caller separately supplies trusted scope, source
  context, source SHA-256, original baseline SHA-256, owner ID/mode and authority.
  Let F be exact file bytes and B the ORIGINAL reviewed Continuity bytes.
  Every derived command binds `local_ref = UPPER(SHA256(F)) || UPPER(SHA256(B))`.
  A retry never replaces B with a fresh snapshot. Producer and verifier parse
  and reconstruct independently; the verifier does not import the producer.
  Freeze commands before comparison. Under the same BEGIN IMMEDIATE, bind the
  store to B: the same identity row and the same event head at B's sequence (the
  whole store was verified when the owner opened it; later history is
  append-only in the database). New work requires the store to still be at B's
  sequence. On an older baseline only rows that write nothing (RETRY, ALIAS)
  are allowed.
  After final sealing, independently verify the store, row/command order,
  payment/evidence/action links, revisions and per-item cash deltas; other cash,
  acknowledgments and reporting remain unchanged. A file with no NEW or OVERLAP
  row must leave durable state identical and make zero SQL changes. Any mismatch rolls
  back the whole file. Publish the receipt only after COMMIT succeeds.
  Preview is the default: independently verify and restore B into isolated TEST
  storage, using that restore's snapshot as execution baseline while retaining
  F and original B as retry identity. Preview never opens an incumbent writer.
  Explicit apply uses the same checked boundary. Cleanup failures are visible.
  CLI apply opens only an existing, current store with the reviewed mode/ID:
  SQLite `mode=rw` prevents accidental creation; read-only setup checks refuse
  missing segment/index/append-only metadata instead of migrating it before
  the import transaction. A missing, empty or disappearing store is refused.
- Scope: local synthetic receiver cash evidence only. Switch's existing owed
  comparison schema is unchanged; this is separate cash reconciliation, with
  no live transport, source authentication/truth, payment or activation claim.
- Receipt: `RR/FINANCIAL/RECEIVER-CASH-RECEIPT/v1` has exactly `contract`,
  `mode` (PREVIEW or APPLIED), `source_sha256`, `baseline_sha256`, `row_count`,
  `recorded_count`, `duplicate_count`, `file_total_cents`, `recorded_cents`,
  `duplicate_cents`, `cash_before_cents`, `cash_after_cents`, `cash_delta_cents`,
  `proofSuiteId` (null), `production_usable` (false), `activation` (false).
  Amounts come from independently checked pre/post cash; duplicates add zero
  cash, including payments reversed after their original receipt. No intermediate
  owner projection or raw file/error data is exported in this result.
- Duration: v1 is a new contract with no implicit legacy migration. Subsequent
  changes require a new explicit compatibility decision and fresh evidence.
- Claims withdrawn: this design is not implementation or verification. Required
  evidence covers field/context/identity mutations, altered command order,
  exact bounds, original-baseline retry and reversal, stale/concurrent/mixed
  batches, overlap labelled DUPLICATE, conflict and reuse refused, action limits, crashes/lost responses,
  no ACK/report effects, source preservation, privacy and cleanup, independent
  verification, Continuity and existing consumers. Status records actual runs.

### Cash-file capacity (2026-09-28)

Target: the largest state's hospital-level program, about 600 hospitals with up
to 3 remittance or recovery lines a month (2,000 rows a month, three monthly
files a quarter, under Lean's `maxRows`). All-provider refund flows need
sharding or Phase 2 below and are not claimed.

- One file is one `run_batch`: at most 500 rows, at most 6 per item (each
  payment re-binds every earlier payment of its item). The bound is the 5 s
  writer busy timeout. Measured locks are in `STATUS.md`.
- Waste cut, results unchanged: the checker's schema and meta are read once per
  call, sealing checks only the tables a write inserted into, and the control
  pack is built and digest-checked once per owner for each exact row.
- One evaluation per payment is kept (founder, 2026-09-28).
- Verification moves from each import to each open: the whole-store verify no
  longer runs twice per import under the lock. The import still checks every
  obligation it touches, each new event onto the verified chain, and every
  table by before/after comparison in the same transaction. A corruption that
  bypassed the owner and its triggers after the open would be caught at the next
  open, by `verify-integrity` or by an export verify.
- A row is NEW, RETRY, OVERLAP (a new repeat of a stored payment: DUPLICATE, one
  alias event, no cash), ALIAS (a stored repeat: nothing written) or refused.
  An exact alias repeat writes nothing whatever its expected revision.
- An existing-only writer (the CLI) refuses an index set older than the current
  one; a read-only SHADOW may keep the previous set.
- Phase 2 (deferred): evaluations that bind evidence by digest, constant size.

### Cash-file refusals

Fixed classes only; no input or error text is ever printed. `input`: the CLI
could not read an input. `format`: the file is not the contract. `row_cap`:
split the file. `binding`: the hashes, scope, owner/mode or baseline do not
match this store. `stale`: prepare against a new baseline. `conflict`: an origin
is already recorded with another amount or link; investigate. `already_recorded`:
an id is reused. `busy`: retry later. `failed`: the checker or store refused;
escalate.

## Browser conformance correction (2026-09-26)

Felt effect: staff receiving a busy or lost response can recover without a
second cash/decision write, and read failures clearly disable unsafe commands.
The declared model currently omits retained exact-retry bodies and busy/uncertain
responses; some read failures also leave a different screen/message than it
declares. Replace those incomplete predicates with the actual reviewed retry
states and fixed response vocabulary. Preserve the original command body after
uncertainty, distinguish confirmed refusal from unknown outcome, and require a
fresh verified read before a new command. A read error reaches the declared
unavailable state with a working refresh path; commands remain disabled there.
Keep financial API payloads, authority and owner decisions unchanged.

The scorecard's simulated DOM does not establish browser conformance. Replace
that implementation with a real browser over the same HTTP server while
retaining the existing scorecard answers, journeys and fault checks. Exercise
each declared role/control/response, actual enabled state, message, destination
and recovery; distinguish injected HTTP response rendering from actual owner
refusal and crash tests. Isolate and close only the test browser. No old model
pass is inherited as evidence for the corrected model or actual browser.

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
    clock once per command (a clock behind the history writes nothing), and
    the checker requires it to equal the writing event's `committed_at_ms`,
    commit times never to decrease, and it never to precede `event_at_ms`;
  - `prior_quarter_adjustments`: each payment, reversal or amount conflict
    (`CONFLICT`) of an earlier quarter's payment, listed once in the quarter
    that recorded it, never netted;
  - every field reads only what was recorded before quarter end, so a closed
    quarter's pack changes only in `source`, `generated_at_ms` and
    `supersedes`: the last evaluation before the end, the
    Control Pack and population whose publish events committed before it, and
    the manifest bound to that population unless superseded before it (the
    Owner refuses to supersede a published roster and never changes a pack's
    status);
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
- **Format:** stays `v1` though its fields changed after 17142e3; no pack
  built before this record is kept as evidence.
- **Evidence:** `tests/test_right_rail_financial_line_pack.py`.
- **Scope:** derived artifact, plus the clock binding above: support
  evidence no longer takes a caller received time (a retry keeps the first
  one), and a `decision_at_ms` after the owner clock is refused
  (`decision_time_future`; Lean needs the same guard, a follow-up). When the
  host clock steps back (NTP, a restored VM, skew between hosts sharing a
  store), every write is refused (`event_commit_order`) until the clock passes
  the last committed time: it fails closed, never reorders or rewrites the
  history, and nothing is lost. No table, Lean, wire or digest changes. `signer` is null because no
  PQ signing path exists.
- **Proposed Lean (not written):**
  - `line_pack_sum_eq_ledger`
  - `line_pack_rule_version_bound`
  - `line_pack_complete_or_declares_gap`
  - `line_pack_deterministic`
  - `line_pack_chronology_strict`
  - `line_pack_documentation_only`
- **Kill criteria:**
  1. The synthetic pack does not reconcile to a synthetic 64.9 line to the cent.
  2. Coverage is under about 50% on lines a state actually had deferred.
  3. Reviewers mostly ask for allowability evidence the Ledger never holds.
- **Follow-up:**
  - The W0 growth breakdown needs units, rates and multiple periods, which the
    Ledger does not hold.
  - There is no per-claim service date, so the split uses the obligation
    period.
