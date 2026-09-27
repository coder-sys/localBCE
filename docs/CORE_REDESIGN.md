# Financial core redesign (approved by the founder 2026-09-24)

Approval (2026-09-24): founder approved the v8 rebuild and retiring v5/v6 stores, conditional on every step complying with CONSTITUTION.md. Any step that would weaken a safety property or protected answer needs a separate founder decision.

Format approval (2026-09-24, CONSTITUTION V.4): asked in session chat whether to move to the v8 store/package format (RR/FINANCIAL/CONTINUITY/v8), with v7 stores migrating all-or-nothing on owner open and v7 packages still verifiable, the founder answered "Yes, approve v8". The only protected change is CASE_11's export version string in `tests/rightrail_financial_expected_cases.py`.

History-completeness approval (2026-09-24, CONSTITUTION V.4): asked in session chat how v7 histories that lack full facts (payment item/time, evidence) become rebuildable, the founder chose "Opening balance": on conversion the owner writes one sealed opening-balance event holding every converted row, under a new, distinctly named digest domain, and from then on every event records the full facts needed to rebuild all projections by apply(event). The alternative (rebuild from events plus side tables) was declined.

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

The core is roughly 2.5x larger than the invariants need. Root cause: state lives in
~20 editable tables with history as a side log, so every consumer (checker, successor,
continuity, Switch, Mirror) re-validates all tables in its own copy. Target shape:
one command log + one append-only, hash-chained history of complete facts + projections
rebuilt from it by one `apply(event)` per event kind. Estimated total ~9,300 lines
(8,000-11,000); owner ~3,000.

## Gaps found (under-enforcement, not just size)

- No command table: each handler invents its own retry/conflict rule (III.3).
- `expected_revision` optional on 10 handlers; 5 handlers default the actor to a
  synthetic identity (III.3, I.2, XI.13).
- `financial_events` has no append-only trigger; foreign keys enabled but none declared (III.4).
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
