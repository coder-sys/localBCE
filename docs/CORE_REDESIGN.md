# Financial core redesign (approved by the founder 2026-09-24)

Approval (2026-09-24): founder approved the v8 rebuild and retiring v5/v6 stores, conditional on every step complying with CONSTITUTION.md. Any step that would weaken a safety property or protected answer needs a separate founder decision.

Format approval (2026-09-24, CONSTITUTION V.4): asked in session chat whether to move to the v8 store/package format (RR/FINANCIAL/CONTINUITY/v8), with v7 stores migrating all-or-nothing on owner open and v7 packages still verifiable, the founder answered "Yes, approve v8". The only protected change is CASE_11's export version string in `tests/rightrail_financial_expected_cases.py`.

History-completeness approval (2026-09-24, CONSTITUTION V.4): asked in session chat how v7 histories that lack full facts (payment item/time, evidence) become rebuildable, the founder chose "Opening balance": on conversion the owner writes one sealed opening-balance event holding every converted row, under a new, distinctly named digest domain, and from then on every event records the full facts needed to rebuild all projections by apply(event). The alternative (rebuild from events plus side tables) was declined.

Source: first-principles review of the financial core (owner, checker, successor,
Mirror, Switch, engine path; ~25,100 Python lines). Constitution articles cited inline.

## Verdict

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
