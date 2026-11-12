# G4 (share of cost) as RightRail gate rule — design for lead approval

Status: approved by the owner on 2026-11-11 (all defaults in section 11) and implemented in the commit that adds this file; section 12 records where the implementation differs from the text below. Under RIGHTRAIL_BASE_PLAN.md:138-145 the owner, as RightRail lead, authors or approves every change inside `rightrail/`. Every Lean run goes through `scripts/rr_guarded_interim.ps1` and is labelled interim evidence (plan:130-137).

All paths are under `rightrail/` unless noted. Lean rule files are under `lean/BlindLedger/Gate/Rules/`. Line numbers are at HEAD f16a61f4 of `codex/rightrail-g2`. The docs-only commit aa826750 on top changes nothing under `rightrail/`.

## 1. Summary

- **Source rule.** localBCE G4 is at rust-engine/src/main.rs:246-248. It denies `G4_SHARE_OF_COST_FAILED` when `soc_amount > 0 && soc_met != 1`. It is the fifth check, and only the first failure is reported (main.rs:231-275). Both are raw claim fields, `soc_amount: u64` and `soc_met: u8` (main.rs:135-136). There is no member key, no month and no amount arithmetic. The rule is synthetic and not legally verified (rules_active_v1.json:5-6; rules_active_v1.json:39-48 is the same predicate).
- **Why a new snapshot.** A RightRail `Line` has no share-of-cost field (Spec.lean:139-150), and every per-member fact comes from a pinned snapshot in `Ctx` (Spec.lean:189-204). Nothing in `rightrail/` models share of cost today. The 835 `patient_cents` and CAS PR are post-payment and never reach the gate.
- **Design.** A new member-keyed reference snapshot, SNAPSHOT/v1 kind 8 `soc`, one row per member and service month, never for a month after the snapshot's own month. It is read as G2 reads `elig`, with three owner-safe additions:
  - certain, every covering row agrees the month is unmet, the line is dated on or before the snapshot, and the snapshot is at most 1 day old → HOLD;
  - the snapshot cannot settle the line → `_UNVERIFIED` (review). That is: an unusable snapshot whose rows still show an unmet share of cost; conflicting rows for the member-month; a line dated after the snapshot's asOf that a row shows unmet; a row showing the line unmet on a snapshot more than 1 day old (S5); or a line in a month after the snapshot's month;
  - missing, stale (more than 7 days old) or malformed (including a row for a month after the snapshot's month) → `STALE_SHARE_OF_COST` (review);
  - every reason reported.
  This is Decision 6 (plan:156-161): in every stale, unverified or ambiguous case G4 contributes only review reasons, so G4 alone never HOLDs on them and never silently ALLOWs. Such a line is HUMAN_REVIEW unless another rule's certain reason holds it (`fail_closed_shareOfCost`; `outcomeOf`, Spec.lean:398-400).
- **Reason count.** 3 new codes: 28 → 31 of `maxReasonCodes` 32 (Gate/Spec.lean:32).
- **What does not change.** The gate token (Gate/Spec.lean), `maxReasonCodes`, `maxTokenBytes` (Gate/Spec.lean:35), artifacts/** and every pinned executable. `proof_execution_enabled` stays false and is not touched.
- **What does change (protected):**
  - the reason set, `Fact` and `Grows`;
  - new kind 8 and the new domain READ-SHARE-OF-COST/v2;
  - READ-SET/v4 and READ-MANIFEST/v4 (six pins);
  - a "Gate rules v3" conformance contract, with v2 retired.
- **Evidence path.** As for G2 (G2_DESIGN.md:25-29), G4's evidence is the pinned snapshot, not the owner typed-evidence path that plan:100 names for "share of cost". The owner must amend plan:100 for share of cost.

**Approach chosen.** This takes the budget-first design as the base: three codes on G4's own kind-8 snapshot, the cap kept at 32, and a build-time tripwire on the reason count. It grafts the member-and-month row key from the other two designs, and the semantic framing from the third: the gate holds, it never reprices, and the amount is used only for `> 0`. The other two designs were not taken whole for these reasons. The G2-parallel design proposed a growth-shaped `Grows` field and left the budget to G6 with no guard. The semantics-first design added a per-line month-currency clause to STALE, which breaks the uniform STALE shape that `fail_closed`, the twin theorem and the mutant patterns rely on, and a 1-day maximum age for the whole snapshot that puts every 1st of the month into review. This design closes the same month gap on the `_UNVERIFIED` arm instead (owner-safe default S2), so STALE stays uniform, and applies the 1-day age only to an unmet HOLD, also on the `_UNVERIFIED` arm (S5). The STALE clause and the 1-day age for everything stay available as owner alternatives (section 11, items 9 and 11).

Owner-safe defaults adopted after review (each replaces a choice of the first draft, which stays listed as an alternative in section 11):
- **S1, the snapshot date bounds its rows and its HOLDs.** `okSoc` reads the snapshot's asOf: a row for a month after asOf's month is malformed (the snapshot is unusable, so STALE review). A HOLD also needs the line dated on or before asOf; a later line that a row shows unmet goes to `_UNVERIFIED` review.
- **S2, month coverage.** A valid line whose month is after the snapshot's month has no usable statement, so `_UNVERIFIED` review, not a silent ALLOW. "No row for a covered month means no share of cost" stays.
- **S3, conflicting rows.** The certain fact is "some covering row unmet and no covering row met". Mixed rows go to `_UNVERIFIED` review.
- **S4, reason budget.** G5's new conditions are counted (section 2).
- **S5, maximum age.** 7 days for usability, 1 day for an unmet HOLD. A snapshot up to 7 days old stays usable, so met and no-row lines still ALLOW on it; a row that shows the line unmet on a snapshot more than 1 day old (`dayNum asOf + 1 < dayNum today`) goes to `_UNVERIFIED` review. The source's TTL is 24h (section 2, item 11 of section 11). The STALE arm is untouched. The first draft used 7 days for everything.

What the G2 implementation taught, and how this design uses it:
- **Mutant anchors collide with near-identical predicates.** G2 had to re-anchor the okExclusion mutants because okElig shared their text (gate_rules_mutants.py:97-101). Every G4 anchor here is checked to occur once (section 6). The row variable is `q`, because `e`, `s`, `d`, `y` and `m` already appear in anchors (mutants:71-76, 98-103). The certain-arm anchor starts with `=> ` to match the style of the other CERTAIN entries. The month disjunct of `Ix.socDoubt` stays on the same line as its `||`, so the "G4 next month allowed" anchor ` || x.socDate / 100 < l.date / 100` matches on one line. `Ix.socMet` tests `q.cents == 0 || q.met == 1`, not the negation of the unmet test, so the unmet anchors `0 < q.cents && ` and `q.met != 1` each occur once in Fast.lean.
- **Bloat ceilings sit at zero headroom.** All four counters are exact actuals (test_bloat_budget.py:16, 18, 21, 22). G4 raises each by its measured delta, with the felt effect named.
- **The review-completeness `#guard`** (Run.lean:55) forces both new review codes into `review`. G4 adds its line FIRST in `review`, as G2 did (Spec.lean:391), so the REVIEW mutant text (mutants:28-31) still matches.
- **`test_proofs_are_current` runs `lake build --no-build`** over FastEq, Resident, Theorems, Sha3FastEq and ReadManifest (tests/test_gate_rules_vectors.py:19-20, 32-35). Those modules must be rebuilt before the suite runs, or the test reports stale proofs.
- **Axiom pins went in Theorems.lean only** (Theorems.lean:868-877). G2_DESIGN.md:144 also named Gate/AxiomCheck.lean and Gate/AXIOMS.txt, but f16a61f4 did not touch them: no `g2_` theorem or axiom pin appears outside Theorems.lean (AxiomCheck.lean and AXIOMS.txt unchanged). G4 follows the commit, not the design text.
- **Snapshots persist across cases** (rules_v2.vectors:4). A case block must sit where the snapshots it assumes are active. G4's cases go after the head eligibility restore (section 6).
- **The runner counts pay lines.** A commit adds the batch's lines plus its `pay` lines (Run.lean:330, `checked := st.checked + (if ok then n + st.pays.length else 0)`).
- **The rules_v1 manifest mismatch stays untouched.** conformance/MANIFEST.sha256:1 does not match `rules_v1.vectors` (OPEN_QUESTIONS.md:21). G4 adds lines and edits none.
- **Signer-dependent tests cannot run here.** 76 tests need the ML-DSA-87 signer exe, which is not built on this machine (OPEN_QUESTIONS.md:20; LOG.md:246-250). G2 was committed on the owner's word with those failures recorded.
- **Plan:99's "pinned worker re-pinned" did not apply to G2** (LOG.md:250-252). It does not apply to G4 either.

## 2. Semantics

Defaults:
- today = the `today` directive;
- maxAge(soc) = 7 days for usability, a placeholder like eligibility (Spec.lean:352-355), and 1 day for an unmet HOLD (S5). The source's TTL is 24h (rust-engine/rules.json:356-373: `ttl_hours` 24 and a stale rule of the response timestamp against the adjudication time minus 24 hours). S1 does not limit the age of the met flag: it bounds the line's date and the rows' months by asOf, not asOf by today. The age limit on the flag is S5's age disjunct: a row that shows the line unmet on a snapshot more than 1 day old goes to review. A met row or no row still ALLOWs on a snapshot up to 7 days old, which is past the 24h TTL (section 9). 7 days for everything and 1 day for everything stay the listed alternatives (section 11, item 11);
- coverage = same member, and row month = `l.date / 100` (CCYYMM);
- the snapshot's month = `asOf / 100`. A usable snapshot has rows only for months up to it (S1);
- for CAP_820 the date is the period start (Spec.lean:137-138), so its month is the period month, the same month as the CAP near key (Spec.lean:279);
- G4 applies to every flow, as localBCE has no flow concept.

Helper predicates:
- `socCovers l q`: `q.member == l.member && q.month == l.date / 100`.
- `socUnmet c l`: some covering row has `0 < q.cents && q.met != 1`. This is localBCE's predicate verbatim, applied to the member-month row.
- `socMet c l`: some covering row has `q.cents == 0 || q.met == 1` (it shows nothing owed).
- `socAsOf c`: the snapshot's asOf (0 when missing; only read when the snapshot is usable).
- `socDoubt c l`: `socUnmet c l && (socMet c l || socAsOf c < l.date || dayNum (socAsOf c) + 1 < dayNum c.today) || socAsOf c / 100 < l.date / 100`. The snapshot cannot settle the line: a row shows it unmet and either the rows conflict (S3), or the line is dated after asOf (S1), or the snapshot is more than 1 day old (S5); or the line's month is after the snapshot's month (S2). The age disjunct sits inside the `socUnmet` conjunct, so it never touches a met or no-row line. `dayNum` is the day count `usable` already uses (Spec.lean:220-224, 242).

| Reason (new) | Fires when | review? | Outcome alone |
|---|---|---|---|
| SHARE_OF_COST_UNMET | certain(soc) ∧ socUnmet ∧ ¬socDoubt | no | HOLD |
| SHARE_OF_COST_UNMET_UNVERIFIED | (unverified(soc) ∧ socUnmet) ∨ (certain(soc) ∧ socDoubt) | yes | HUMAN_REVIEW |
| STALE_SHARE_OF_COST | ¬usable today 7 okSoc soc | yes | HUMAN_REVIEW |

How the table reads:
- `certain` means usable and a valid service date (Spec.lean:290-293). `unverified` means isSome, not usable, and a valid date (Spec.lean:295-298). `usable` (Spec.lean:236-243) rejects: missing; a bad pin, which reads as missing; an invalid or future asOf; an invalid today; older than 7 days; a count mismatch; an empty snapshot; and a malformed row. `okSoc` receives the snapshot's asOf (`s.entries.all (ok s.asOf)`, Spec.lean:243), as okDeath already uses it (Spec.lean:227).
- **The HOLD is certain four ways.** The snapshot is usable, every covering row agrees the month is unmet (`socUnmet ∧ ¬socMet`), the line is dated on or before asOf, and the snapshot is at most 1 day old (`dayNum today ≤ dayNum asOf + 1`). ¬socDoubt gives the last three, and `l.date ≤ asOf` implies the line's month is covered.
- **An unmet row on a snapshot more than 1 day old goes to review (S5).** The snapshot is still usable up to 7 days, so a met row or no row ALLOWs and other lines are unaffected; only a line that a row shows unmet gets `_UNVERIFIED`. STALE is unchanged.
- **No row for a covered month means no share of cost.** A line whose month is at or before the snapshot's month and has no row passes. This is the list reading of the DMF and exclusion snapshots, and it matches localBCE, where an amount of 0 passes whatever `soc_met` says. A line dated after asOf in the snapshot's own month with no row also passes: S1 sends such a line to review only when a row shows it unmet.
- **A line in a month after the snapshot's month goes to review (S2),** whatever the rows say: a usable snapshot holds no rows for that month, so it cannot say the month is clear. With today fixed and maxAge 7, this happens in the first days of a month until a snapshot dated in the new month is pinned.
- **A row for a month after the snapshot's month is malformed (S1).** `okSoc` requires `q.month ≤ asOf / 100`, so the snapshot is unusable: STALE for every line, plus `_UNVERIFIED` for a line its rows show unmet.
- **A met flag other than 0 or 1 is malformed.** `okSoc` requires `met ≤ 1`, so such a row makes the snapshot unusable: STALE for every line, plus `_UNVERIFIED` for the member it shows unmet. localBCE would have denied; here a person decides. This mirrors okElig's `level ≤ 1` (Spec.lean:233-234).
- **Conflicting rows** for one member and month (one unmet, one met or owing nothing) go to `_UNVERIFIED` review (S3). The SNAPSHOT/v1 pin sorts rows and does not de-duplicate (Spec.lean:513-518). Several unmet rows that agree still HOLD.
- **The certain and unverified codes never fire together on a line** (`g4_exclusive`): the unverified arm needs either an unusable snapshot or socDoubt, and the certain arm needs a usable one and ¬socDoubt.
- **An invalid service date silences G4.** SERVICE_DATE_INVALID carries the line. Both the certain arm and the doubt branch need `validDate l.date`.
- **No suppression.** G4 co-fires with R1, R5 and G2, and every reason is reported.
- **Per payment, at most 2 of the 3 codes appear together.** On a usable snapshot: HOLD and UNVERIFIED (on different lines, by `g4_exclusive`). On an unusable one: UNVERIFIED and STALE. All lines of a batch share one `Ctx`.
- **The gate never reprices.** `Outcome` is only ALLOW, HOLD or HUMAN_REVIEW (Spec.lean:115). The rules never produce BLOCK (Spec.lean:67).

Divergences from localBCE, all under Decision 6:
- stale, missing or malformed data goes to review, not DENY;
- every reason is reported, not only the first;
- `soc_met` of 2 or more goes to review, not DENY;
- the check is per member and month, not per claim;
- conflicting rows, a line dated after the snapshot that a row shows unmet, a row showing the line unmet on a snapshot more than 1 day old, and a line in a month after the snapshot's month go to review; localBCE has one claim field and no snapshot date;
- localBCE's DENY is RAD 022, not appealable (rust-engine/rules.json:873-905); here it is HOLD, which a person can release.

Byte order (enforced by the #guard at Run.lean:49 and StateV2.lean:6689 `decide +kernel`):
- SHARE_OF_COST_UNMET, then SHARE_OF_COST_UNMET_UNVERIFIED, go after SERVICE_DATE_INVALID ('E' < 'H') and before STALE_DMF ('H' < 'T'). The bare name is a prefix of its twin, so it sorts first.
- STALE_SHARE_OF_COST goes after STALE_RELEASED ('R' < 'S') and before STALE_UNRESOLVED ('S' < 'U').
- The longest new code is 30 characters, under BENEFIT_LEVEL_MISSING_UNVERIFIED's 32. Codes match codeOk (Gate/Spec.lean:119-122). No token change.

Parity map:
- G4_SHARE_OF_COST_FAILED ↔ SHARE_OF_COST_UNMET.
- `soc_amount` ↔ `cents`. Only `> 0` is read, so localBCE's unknown scale does not affect parity.
- `soc_met` ↔ `met`.
- localBCE has no counterpart of the snapshot date, so the S1/S2/S5 review cases have no localBCE twin; a parity vector must date its line on or before asOf, in the snapshot's month, on a snapshot at most 1 day old.

### Reason budget (G4, G5, G6, G8, G10)

What the cap binds:
- `maxReasonCodes` is enforced per token, by the decoder (Gate/Spec.lean:460), and mirrored in Python (app/right_rail_gate_codec.py:67, 402).
- A token's codes are the payment's line reasons, filtered from `reasons` (StateV2.lean:6754). So a token never has more codes than `reasons` has members.
- No Lean statement ties `reasons.length` to the cap. G2_DESIGN.md:63 and 505 treat 32 as the total budget.

Totals. G5's new conditions (provider not enrolled, provider type invalid; main.rs:249-254, plan:61, plan:99) are counted, assuming they read their own provider snapshot:

| After | New codes | Total | Fits 32? |
|---|---|---|---|
| G2 (now) | — | 28 | yes |
| G4 (this design) | 3 | 31 | yes, headroom 1 |
| G5 new conditions, two facts, G2 shape (2 certain, 2 unverified, 1 STALE) | 5 | 36 | no |
| G6, two facts (main.rs:255-260), G2 shape | 5 | 41 | no |
| G8 (main.rs:264-266), 3-code shape | 3 | 44 | no |
| G10 (main.rs:270-272), 3-code shape | 3 | 47 | no |

- Even the leanest shapes do not fit: G5 at 3 (two certain codes, one STALE), G6 at 3, G8 at 2 and G10 at 2 give 31 + 10 = 41.
- No shape keeps the total at or below 32 after G5 without merging distinct certain facts into one code or sharing one STALE code across sources. Both weaken "every reason is reported".
- A 2-code G4 that shares STALE_ELIGIBILITY would save one code. It would change kind 7's row layout, re-pin every v2 elig row and make G2 go stale on a share-of-cost fault. Rejected.

Per-token estimate (a derivation from `Fact`, Theorems.lean:43-80; not proved):
- FFS today: at most 21 distinct codes per payment (6 line-key codes, 2 date codes, 2 set codes, 2 each for DMF, provider death, exclusion and enrollment, 3 for eligibility).
- After G4: 23 (at most 2 of its 3 codes per payment, section 2).
- G2 shape: G5 +3 (two unverified and STALE on an unusable snapshot), G6 +3, G8 +2, G10 +2: about 33, over 32.
- Lean shape: G5 +2, G6 +2, G8 +1, G10 +1: about 29, under 32.
- So once G5 lands, the per-token limit likely fails after G10 unless codes are shared (the lean shapes) or the cap rises. Only an estimate says either way.

What this design does about it:
- **G4 fits as a total.** 31 ≤ 32, so every token fits trivially.
- **A tripwire now.** Run.lean gains `#guard reasons.length ≤ BlindLedger.Gate.maxReasonCodes` next to Run.lean:49-55. Run imports Rules.Fast (Run.lean:2), which imports Gate.Spec (Fast.lean:3), and Run's namespace is under `BlindLedger.Gate` (Run.lean:8). The next rule with more than one code (G5 or G6) fails this guard at build time, so it cannot overflow silently.
- **The decision is the owner's, before the next rule starts** (section 11, item 14). Default: replace the guard with a proved per-payment bound near `rowOf` (StateV2.lean:6745-6754), so no wire change is needed. That route likely fails once G5 lands (about 33 after G10 at G2 shape) unless codes are shared or the cap rises. The fallback is raising the cap: that edits Gate/Spec.lean:32 and probably `maxTokenBytes` (a worst-case token at a cap of 48 is about 4,956 bytes, over 4,096), bumps TOKEN/v1, re-pins gate_verify, and needs the signer exe that this machine lacks.

## 3. Data model

- Row `Soc {member, month, cents, met}`.
- `Soc.fields = [(idWidth, member), (4, month), (8, cents), (1, met)]`, giving 142-byte rows under pinInput "RR/GATE/SNAPSHOT/v1" kind 8 (Spec.lean:513-518; idWidth = 129, Spec.lean:491).
- `month` is CCYYMM. `cents` is the month's share-of-cost amount, 8 bytes like `Line.cents` (Spec.lean:511). `met` is 1 when the source certifies the month met, else 0. A value that does not fit fails the pin, and the snapshot reads as missing.
- `okSoc asOf q := validDate (q.month * 100 + 1) && q.month ≤ asOf / 100 && q.met ≤ 1`. `validDate` (Spec.lean:214-217) rejects month 00, month 13 and year 0. A month after the snapshot's month, or any other `met`, makes the snapshot unusable, which goes to review and never to HOLD.
- Units are cents. localBCE's u64 has no stated scale (main.rs:135); the spec types `o1_soc_amount` as decimal (rust-engine/rules.json:329-331). Parity only reads `> 0`.
- Ctx gains `shareOfCost : Option (Snapshot Soc)` with no default, so every literal must name it.
- Python: `tools/gate_rules_data.py` KINDS (line 15) appends `"soc"` LAST, so it is number 8 by position (line 43) and kinds 1-7 keep their numbers. WIDTHS (19-20) gains `"soc": (ID, 4, 8, 1)`.

## 4. Lean changes per file

### Rules/Spec.lean (protected)
- Reason (117-125) and `reasons` (128-135): add the 3 constructors at the positions in section 2.
- After Elig (173-178): `structure Soc where member month cents met : Nat`, with a doc comment saying it is synthetic G4 (rust-engine/src/main.rs:246-248) and not legally verified.
- Ctx (189-204): add `shareOfCost : Option (Snapshot Soc)` after `eligibility` (195).
- After okElig (234):
```lean
/-- A share-of-cost row: a calendar month not after the snapshot's month, and a met flag of 0 or 1 (any other
    value is malformed). -/
def okSoc (asOf : Nat) (q : Soc) : Bool := validDate (q.month * 100 + 1) && q.month ≤ asOf / 100 && q.met ≤ 1
```
- After levelEligible (335-336):
```lean
def socCovers (l : Line) (q : Soc) : Bool := q.member == l.member && q.month == l.date / 100
/-- localBCE G4 (rust-engine/src/main.rs:246): a covering row owes a share of cost not met.  Synthetic. -/
def socUnmet (c : Ctx) (l : Line) : Bool :=
  (entries c.shareOfCost).any fun q => socCovers l q && 0 < q.cents && q.met != 1
/-- A covering row shows nothing owed: no amount, or met. -/
def socMet (c : Ctx) (l : Line) : Bool :=
  (entries c.shareOfCost).any fun q => socCovers l q && (q.cents == 0 || q.met == 1)
def socAsOf (c : Ctx) : Nat := (c.shareOfCost.map (·.asOf)).getD 0
/-- The snapshot cannot settle the line: a row shows it unmet and the rows for the month conflict, the line is
    dated after the snapshot, or the snapshot is more than 1 day old; or the line's month is after the
    snapshot's month. -/
def socDoubt (c : Ctx) (l : Line) : Bool :=
  socUnmet c l && (socMet c l || socAsOf c < l.date || dayNum (socAsOf c) + 1 < dayNum c.today) ||
    socAsOf c / 100 < l.date / 100
```
- fires (356-386), new arms. The rule-table doc at 352-355 adds "share of cost (G4) 7 days usable and 1 day for an unmet HOLD, placeholders (the source's TTL is 24 hours)".
```lean
  | .SHARE_OF_COST_UNMET => certain c 7 okSoc c.shareOfCost l && socUnmet c l && !socDoubt c l
  | .SHARE_OF_COST_UNMET_UNVERIFIED =>
      unverified c 7 okSoc c.shareOfCost l && socUnmet c l || certain c 7 okSoc c.shareOfCost l && socDoubt c l
  | .STALE_SHARE_OF_COST => !usable c.today 7 okSoc c.shareOfCost
```
- review (390-396): add a new FIRST line `| .SHARE_OF_COST_UNMET_UNVERIFIED | .STALE_SHARE_OF_COST => true` before 391. Lines 392-395 stay verbatim for the REVIEW mutant text (mutants:28-31).
- After Elig.fields (505-507): `def Soc.fields`, with a one-line doc "Kind 8 (G4 share of cost)".
- Docs:
  - a G4 bullet after the G2 bullet (32-35), naming the asOf bound, month coverage, conflicting rows and the 1-day bound on an unmet HOLD;
  - add G4 to the certain sentences (48-50);
  - add "a share-of-cost month that is not a calendar month or is after the snapshot's month, or a met flag other than 0 or 1" to the malformed-row text (59-61);
  - add G4 to the `*_UNVERIFIED` sentence (64-66), with "or a usable share-of-cost snapshot that cannot settle the line";
  - add "8 share of cost" to the pin-kind doc (485).
- Do not touch `claim`, `keys`, `order` or `seen0`. G4 stays out of them, like G2 (G2_DESIGN.md:114).

### Rules/Theorems.lean (protected)
- After 41:
```lean
/-! The facts of G4 (synthetic, from localBCE; not legally verified). -/
abbrev SocUnmet (c : Ctx) (l : Line) : Prop :=
  ∃ q ∈ entries c.shareOfCost, q.member = l.member ∧ q.month = l.date / 100 ∧ 0 < q.cents ∧ q.met ≠ 1
abbrev SocMet (c : Ctx) (l : Line) : Prop :=
  ∃ q ∈ entries c.shareOfCost, q.member = l.member ∧ q.month = l.date / 100 ∧ (q.cents = 0 ∨ q.met = 1)
abbrev SocDoubt (c : Ctx) (l : Line) : Prop :=
  SocUnmet c l ∧ (SocMet c l ∨ socAsOf c < l.date ∨ dayNum (socAsOf c) + 1 < dayNum c.today) ∨
    socAsOf c / 100 < l.date / 100
```
- Fact (43-80), three arms in the style of 45-48 and 75:
  - certain: `Usable c.today 7 okSoc c.shareOfCost ∧ validDate l.date = true ∧ SocUnmet c l ∧ ¬SocDoubt c l`;
  - unverified: `c.shareOfCost.isSome ∧ ¬Usable c.today 7 okSoc c.shareOfCost ∧ validDate l.date = true ∧ SocUnmet c l ∨ Usable c.today 7 okSoc c.shareOfCost ∧ validDate l.date = true ∧ SocDoubt c l`;
  - STALE: `¬Usable c.today 7 okSoc c.shareOfCost` (unchanged by S1-S3 and S5).
- fires_iff (94-96): add `socUnmet, socMet, socDoubt, socCovers` to the simp set. If `!= 1` does not normalise to `≠ 1`, add `bne_iff_ne`; if simp normalises `¬(a ∨ b)` or the disjunction's association differently from the Fact text, state the Fact arm in simp's normal form instead. Unbuilt; uncertain.
- Grows (608-622): add `shareOfCost : c'.shareOfCost = c.shareOfCost` after `eligibility` (611), and extend the docstring (603-607). Equality, as for G2. The transition that matters for share of cost is a row flipping from unmet to met, which is a replacement, not growth. `socAsOf` reads only `c.shareOfCost`, so the equality covers it.
- fact_mono (646-676), one grouped arm for all three codes: `simpa only [Fact, SocUnmet, SocMet, SocDoubt, socAsOf, g.today, g.shareOfCost] using h`, as at 652-654. `g.today` also rewrites the age disjunct's `dayNum c.today`.
- fail_closed (267-281) stays byte-identical. Its docstring (265-266) names the eighth source: "G4's share-of-cost snapshot (the eighth) is `fail_closed_shareOfCost`". Add the twin after 289 (S1-S3 and S5 do not touch STALE, so it is as first drafted):
```lean
theorem fail_closed_shareOfCost {c b d} (h : ¬Usable c.today 7 okSoc c.shareOfCost)
    (hd : d ∈ (decideBatch c b).decisions) :
    d.outcome = .HUMAN_REVIEW ∨ (d.outcome = .HOLD ∧ ∃ r ∈ d.reasons, review r = false) := by
  obtain ⟨_, l, rfl⟩ := mem_decideAll (seen := seen0 c b) (ls := order c b) hd
  exact outcome_cases (line_complete (r := .STALE_SHARE_OF_COST) h)
```
- New G4 theorems (additions only), after g2_allow (309-318):
  - `g4_review`: `review .SHARE_OF_COST_UNMET = false ∧ review .SHARE_OF_COST_UNMET_UNVERIFIED = true ∧ review .STALE_SHARE_OF_COST = true`, `by decide`. Unchanged by S1-S3.
  - `g4_exclusive` (new, from S1-S3): `¬(Fact c seen l .SHARE_OF_COST_UNMET ∧ Fact c seen l .SHARE_OF_COST_UNMET_UNVERIFIED)`. A term proof: the certain arm's Usable refutes the first unverified branch, and its ¬SocDoubt refutes the second. The first draft had no exclusivity theorem because its one certain code could not conflict; with the doubt branch, the certain and unverified codes share a usable snapshot, so exclusivity is now a statement worth pinning.
  - `g4_hold_usable` (restated): `Fact c seen l .SHARE_OF_COST_UNMET → Usable c.today 7 okSoc c.shareOfCost ∧ l.date ≤ socAsOf c ∧ dayNum c.today ≤ dayNum (socAsOf c) + 1 ∧ ¬SocMet c l`. A G4 HOLD rests on a usable snapshot at most 1 day old, a line dated on or before it, and no covering row that shows nothing owed. A term proof from the Fact arm: SocUnmet is in hand, so ¬SocDoubt refutes each disjunct of the inner parenthesis (`Nat.le_of_not_lt` for the date and for the age).
  - `g4_allow` (restated): `(decideLine c seen l).outcome = .ALLOW → Usable c.today 7 okSoc c.shareOfCost ∧ ¬SocUnmet c l ∧ l.date / 100 ≤ socAsOf c / 100`. It follows g2_allow (309-318): STALE_SHARE_OF_COST gives usable, SERVICE_DATE_INVALID a valid date, SHARE_OF_COST_UNMET and SHARE_OF_COST_UNMET_UNVERIFIED (by cases on SocDoubt) give ¬SocUnmet, and SHARE_OF_COST_UNMET_UNVERIFIED's month branch gives the month bound.
- Axiom pins next to 868-877, expectations to confirm when built, by analogy with G2's pins (g2_review [propext], g2_exclusive none, g2_hold_usable none, g2_allow [propext, Classical.choice, Quot.sound], fail_closed_eligibility [propext, Quot.sound]):
  - fail_closed_shareOfCost [propext, Quot.sound];
  - g4_review [propext];
  - g4_exclusive none;
  - g4_hold_usable none (it may gain [propext] if the date or age step is closed by `simp` or `omega` instead of a term);
  - g4_allow [propext, Classical.choice, Quot.sound].

### Rules/Fast.lean
- Ix (63-93): add `socSome socOk : Bool`, `socDate : Nat` and `soc : HashMap Nat (List Soc)`. The date field is `socDate`, not `socAsOf`: inside `def Ix.build` the `Ix` namespace is open, so a field named `socAsOf` would make the bare `socAsOf c` resolve to the projection `Ix.socAsOf` (applied to a `Ctx`, a type error) instead of the Spec function. No Ix field may share a name with a Spec function that Ix.build calls bare.
- Ix.build (96-115): `socSome := c.shareOfCost.isSome`, `socOk := usable c.today 7 okSoc c.shareOfCost`, `socDate := socAsOf c`, `soc := group (·.member) (entries c.shareOfCost)`. Ix.build calls no other G4 Spec name bare; `Ix.socUnmet`, `Ix.socMet` and `Ix.socDoubt` are functions, not fields, and Ix.build does not call them.
- After 143:
```lean
def Ix.socUnmet (x : Ix) (l : Line) : Bool := (x.soc.getD l.member []).any fun q => socCovers l q && 0 < q.cents && q.met != 1
def Ix.socMet (x : Ix) (l : Line) : Bool := (x.soc.getD l.member []).any fun q => socCovers l q && (q.cents == 0 || q.met == 1)
def Ix.socDoubt (x : Ix) (l : Line) : Bool :=
  x.socUnmet l && (x.socMet l || x.socDate < l.date || dayNum x.socDate + 1 < dayNum x.today) || x.socDate / 100 < l.date / 100
```
  `x.today` is the existing field (Fast.lean:64, `today := c.today` at 103), the same one SERVICE_DATE_FUTURE reads (185).
- Ix.fires (163-193): arms in the textual pattern of 165-167, 175-176 and 187, so the mutants' CHECKS, CERTAIN and `unverified_rows` (mutants:48-55, 132-136) extend with tag `soc`:
  - `| .SHARE_OF_COST_UNMET => x.socOk && validDate l.date && x.socUnmet l && !x.socDoubt l`
  - `| .SHARE_OF_COST_UNMET_UNVERIFIED =>` then, indented on the next line, `x.socSome && !x.socOk && validDate l.date && x.socUnmet l || x.socOk && validDate l.date && x.socDoubt l`
  - `| .STALE_SHARE_OF_COST => !x.socOk`

### Rules/FastEq.lean
- Add `socCovers_member`, modelled on eligCovers_member (293).
- Add `build_soc` (rfl) and `socUnmet_eq` and `socMet_eq`, modelled on build_elig and aidEligible_eq (385-394).
- Add `build_socOk`, `build_socSome` and `build_socDate` (rfl; `(Ix.build c b).socDate = socAsOf c`), as at 405-406, and `socDoubt_eq` from `socUnmet_eq`, `socMet_eq`, `build_socDate` and `(Ix.build c b).today = c.today` (rfl).
- Append `socUnmet_eq, socMet_eq, socDoubt_eq, build_socOk, build_socSome` to the fires_eq simp list (513-518).
- No statement changes.

### Rules/Resident.lean
- refresh (136-146): set the four new fields (`socSome`, `socOk`, `socDate := socAsOf c`, `soc`) and update the docstring (136, "six snapshots"). The same name rule as Ix.build applies.
- breaks (383-384): add `"soc"`.
- refresh_eq (1376), ix_extend_eq (1405) and step_keep (1917) keep their text. They are the safety net if a field or keyword is forgotten.

### Rules/Run.lean (runner; text feeds RULES_SOURCE, tests/test_gate_rules_vectors.py:26-30)
- Doc (16): add `soc` with rows `MEMBER MONTH CENTS MET`.
- Pinned (132-141): docstring "eight pinned inputs … six kinds"; add `soc : Option (Snapshot Soc × List UInt8)`.
- St.pin (216-233): add `let soc := snapshot st "soc" (fun r => match r.mapM String.toNat? with | some [m, y, a, f] => some ⟨m, y, a, f⟩ | _ => none) "RR/GATE/SNAPSHOT/v1" 8 Soc.fields`, the record field, and a sixth `← readPin "RR/GATE/READ-SHARE-OF-COST/v2" 8 Soc.fields soc` in `kinds`.
- St.ctx (235-241): `shareOfCost := p.soc.map (·.1)`.
- reads (272-277): literal tag "RR/GATE/READ-SET/v4"; doc says six pins.
- Row whitelist (391): add `"soc"`.
- Next to 49-55, the budget tripwire (section 2):
```lean
-- Every reason fits one token while the set is no larger than the cap (Gate.Spec maxReasonCodes, TOKEN/v1).
#guard reasons.length ≤ BlindLedger.Gate.maxReasonCodes
```
- Guards 49 and 55 need no edit. They check the order and that both new review codes are in `review`. No constant guard is needed: G4 pins no constant.

### Rules/DecideLayer.lean:205
- Add `shareOfCost := none` to the Ctx literal.

### StateV2.lean (protected)
- pm_fires (6225-6238): add `(h9 : c.shareOfCost = c'.shareOfCost)`, include it in `simp only at` and `subst` (6235-6236), and add `socUnmet, socMet, socDoubt, socAsOf, socCovers` to the simp list (6237-6238). The age disjunct reads `c.today`, which pm_fires already equates for the existing usable checks. The single call site (6348) gains one `rfl`.
- reasonName (6667-6684): add the three names. g1_reasons_pw (6689) and reasonCode_ascending (6700) re-check the order.
- readSetTag (6721): READ-SET/v3 → v4; the doc names v3 retired.
- readSetOf (6723-6732): after `g`, add `let s ← optPin "RR/GATE/READ-SHARE-OF-COST/v2" 8 Soc.fields c₀.shareOfCost`, hash `… ++ g ++ s ++ r …`, and say "six external snapshots" in the doc.
- firesQ: no change, as for G2 (G2_DESIGN.md:190).

### ReadManifest.lean (protected)
- manifestTag (20) → READ-MANIFEST/v4. Update the doc (6-14): pin₁..₆, the sixth is G4's share of cost, kind 8, READ-SET/v4, v3 retired, and S2's pay/reg roots move from v4 to v5.
- kindPins (38-41) and readSetPre (44-52): add a sixth kind and slot.
- decodeReads (81-104): cut p6; pins `[p1..p6]`.
- Statements that change (three):
  - kindPins_some (183-196), restated for six pins: a sixth `(p6, a6)` and `kindOf "RR/GATE/READ-SHARE-OF-COST/v2" 8 Soc.fields c.shareOfCost = some (p6, a6)`;
  - reads_exact (295-328), restated for six pins: `∃ p1 … p6 Pre`, `[p1, …, p6]`, adding `Exact 8 Soc.fields i.ctx.shareOfCost p6`, and "six pins" in the docstring (297);
  - readSetTag_eq (121), whose statement quotes the tag literal. Old: `theorem readSetTag_eq : readSetTag = "RR/GATE/READ-SET/v3".toUTF8.toList ++ [0] := rfl`. New: `theorem readSetTag_eq : readSetTag = "RR/GATE/READ-SET/v4".toUTF8.toList ++ [0] := rfl`. The proof stays `rfl`.
- Statements unchanged, new proof text (three):
  - kindPins_pre (198-206): the destructuring at 203 and the rewrite at 205 gain `p6`, `a6`, `h6`;
  - readSetOf_pre (208-215): one more `cases optPin "RR/GATE/READ-SHARE-OF-COST/v2" 8 Soc.fields c.shareOfCost <;>`;
  - decodeReads_encode (232-269): the `kindPins_some hks` destructuring at 252 gains `p6, a6` and `h6` (`⟨p1, a1, …, p6, a6, rfl, h1, …, h6⟩`), a sixth `kindOf_some h6` step (after 257), and `cut_app l6`, `s6` in the final simp (266-269).
- run_reads_eq (219-230) and encodeReads_inj (272-282): no text change expected. Among these two, f16a61f4's only text change was run_reads_eq's `dom2_eq` → `readSetTag_eq` rename (229). G4 renames nothing, so neither changes.

### No change
- Gate/Spec.lean (token), Gate/AxiomCheck.lean, Gate/AXIOMS.txt, Engine/OneProc.lean (text is re-hashed only), RulesMain.lean.
- tests/_gate_shards.py: f16a61f4 did not touch it, and the `shards_v1.vectors` head carries the new block.
- The Financial tree and the gate_verify closure (VerifyCli.lean:1-3).

## 5. Proof plan

Re-proved by existing text:
- mem_all and reasons_nodup (Theorems.lean:98, 205);
- fires_eq (once the simp list is extended) and the decide*_eq family;
- refresh_eq, ix_extend_eq and step_keep;
- g1_reasons_pw and reasonCode_ascending;
- sound, complete, hold_complete and line_complete (through fires_iff);
- allow_facts, claim_keys, the allow_clear family, one_payment_per_line, deterministic, and claim/own/order/seenAt_grows. G4 never enters claim, keys, order or seen0;
- ReadManifest run_reads_eq and encodeReads_inj.

New proof text, with the statement unchanged:
- fires_iff (extended simp set);
- fact_mono (one new arm);
- private StateV2 pm_fires (one more hypothesis);
- ReadManifest kindPins_pre, readSetOf_pre and decodeReads_encode (one more pin each).

Statements that change (XI.2):
- Fact (3 arms; the certain arm carries ¬SocDoubt and the unverified arm the doubt branch, from S1-S3 and S5);
- Grows (shareOfCost field), which strengthens the hypothesis of `monotone` (684) while leaving its text unchanged;
- ReadManifest kindPins_some and reads_exact (six pins);
- ReadManifest readSetTag_eq (the v3 → v4 tag literal). Old: `readSetTag = "RR/GATE/READ-SET/v3".toUTF8.toList ++ [0]`. New: `readSetTag = "RR/GATE/READ-SET/v4".toUTF8.toList ++ [0]`. Proof `rfl` in both.

Additions:
- fail_closed_shareOfCost, g4_review, g4_exclusive, g4_hold_usable, g4_allow (statements in section 4);
- FastEq helper lemmas.

No sorry, no ofReduceBool.

Build stages, each a separate guarded `-Modules` run that stops on the first failure:
1. Freeze Spec.lean (Reason, Soc, Ctx field, okSoc, the soc helpers, fires, review, fields), then build Rules.Theorems.
2. Rules.FastEq, Rules.Resident, Rules.Shards.
3. Rules.ShardRun, Rules.DecideLayer, then exe gate_rules, so the vectors can run early.
4. Gate.StateV2, Gate.ReadManifest.
5. Gate.AxiomCheck, then exes gate_engine and gate_axioms.
6. Sha3FastEq, so every module in test_gate_rules_vectors.py:19-20 is built before `test_proofs_are_current`.

Then run:
- test_gate_rules_vectors: test_runner_is_current, test_proofs_are_current and test_vectors_pass;
- test_gate_rules_worker, the shards tests, test_right_rail_gate_formats and test_bloat_budget;
- gate_rules_mutants.py by hand (Windows).

## 6. Vectors

Published files stay untouched: rules_v2.vectors and demo_zz_v2.vectors are immutable (conformance/MANIFEST.sha256:9-10; conformance/README.md:52-58).

**New tests/gate_rules/rules_v3.vectors** is rules_v2 verbatim plus the following.

(a) Header comment (line 1) names v3 and G4. Head, after the elig block (v2 lines 29-39):
```
snap soc 20270314 10 ?
soc 1001 202703 0 1
soc 1002 202703 0 1
soc 1003 202703 0 1
soc 1004 202703 0 1
soc 1005 202703 0 1
soc 1006 202703 0 1
soc 1007 202703 0 1
soc 1009 202703 0 1
soc 9001 202703 0 1
soc 9002 202703 0 1
```
These are the same members as the elig head block. Every row owes nothing and is for the snapshot's own month (S1), so no head row is unmet, S1 and S5 never fire under the head, and all v2 expectations are unchanged except (b) and (c). A snapshot needs at least one row to be usable (Spec.lean:242). Every v2 line under this head is dated in March 2027 or earlier except line 103 (b) and the invalid dates of lines 113-114 (v2:332-333), which G4 ignores.

(b) Two v2 expectations gain a G4 code:
- today_invalid (v2:623-626): line 154 expects `HUMAN_REVIEW STALE_DMF,STALE_ELIGIBILITY,STALE_ENROLLMENT,STALE_EXCLUSION,STALE_PROVIDER_DEATH,STALE_SHARE_OF_COST`.
- service_date_future (v2:315-318): line 103 (CAP_820, 20270401, v2:317) is in a month after the head snapshot's month, so S2 fires: `HUMAN_REVIEW SERVICE_DATE_FUTURE,SHARE_OF_COST_UNMET_UNVERIFIED`.

(c) Leap cases (v2:1143-1209): after each `today`, re-declare `snap soc <same asOf as the elig line> 1 ?` with one row for the snapshot's own month (a March 2027 row would be after the 2000 snapshot's month and malformed under S1):
- 20280315: asOf 20280310 (v2:1146), row `soc 1001 202803 0 1`;
- 21000315: asOf 21000314 (v2:1168), row `soc 1001 210003 0 1`;
- 20000315: asOf 20000314 (v2:1189), row `soc 1001 200003 0 1`.
Every leap line is dated in or before its snapshot's month (v2:1156-1157, 1163, 1178, 1184, 1201, 1207).

(d) G4 cases, inserted after the head eligibility restore (v2:1130-1141) and before the leap-case comment (v2:1143), so the head elig snapshot (all members aid 78131, level 1) is active again. Inserting before the restore (v2:1130) would run them under g2_line_dates' one-row elig snapshot (v2:1125-1126), which holds every other member PROGRAM_NOT_ELIGIBLE. Snapshots persist across cases (v2:4), so the block ends by restoring every snapshot and directive it changed: `today` and the span and elig snapshots (changed only by g4_month_turn) and the soc snapshot. Line ids start at 355, because v2 uses ids up to 354. Today is 20270315 except in g4_month_turn. Payee and rendering are 7001 (501, the plan, for the CAP_820 line 363).
```
# G4 share of cost (synthetic, not legally verified): a member-month row owing cents and not met holds;
# conflicting rows, a line after the snapshot that a row shows unmet, an unmet row on a snapshot more than
# 1 day old, and a later month go to review
case g4_share_of_cost
snap soc 20270314 8 ?
soc 1002 202703 0 0
soc 1003 202703 15000 0
soc 1005 202703 15000 0
soc 1006 202702 15000 0
soc 1007 202703 15000 0
soc 1007 202703 15000 1
soc 1009 202703 15000 1
soc 1009 202603 15000 0
line 355 FFS_CLAIM 1001 7001 7001 20270305 99213 1 12500 ALLOW -
line 356 FFS_CLAIM 1002 7001 7001 20270305 99213 1 12500 ALLOW -
line 357 FFS_CLAIM 1005 7001 7001 20270305 99213 1 12500 HOLD SHARE_OF_COST_UNMET
line 358 FFS_CLAIM 1005 7001 7001 20270315 99214 1 13100 HUMAN_REVIEW SHARE_OF_COST_UNMET_UNVERIFIED
line 359 FFS_CLAIM 1006 7001 7001 20270228 99213 1 12500 HOLD SHARE_OF_COST_UNMET
line 360 FFS_CLAIM 1006 7001 7001 20270301 99213 1 12500 ALLOW -
line 361 FFS_CLAIM 1007 7001 7001 20270305 99213 1 12500 HUMAN_REVIEW SHARE_OF_COST_UNMET_UNVERIFIED
line 362 FFS_CLAIM 1009 7001 7001 20270305 99213 1 12500 ALLOW -
line 363 CAP_820 1005 501 501 20270301 0 1 45000 HOLD SHARE_OF_COST_UNMET
line 364 FFS_CLAIM 1003 7001 7001 20270305 99213 1 12500 HOLD MEMBER_NOT_ENROLLED,SHARE_OF_COST_UNMET
commit
case g4_payment
snap soc 20270314 1 ?
soc 1005 202703 15000 0
line 365:901 FFS_CLAIM 1001 7001 7001 20270305 99213 1 12500 ALLOW -
line 366:901 FFS_CLAIM 1005 7001 7001 20270305 99214 1 13100 HOLD SHARE_OF_COST_UNMET
pay 901 HOLD
commit
case g4_age_7
snap soc 20270308 1 ?
soc 1005 202703 15000 0
line 367 FFS_CLAIM 1005 7001 7001 20270305 99213 1 12500 HUMAN_REVIEW SHARE_OF_COST_UNMET_UNVERIFIED
line 368 FFS_CLAIM 1001 7001 7001 20270305 99213 1 12500 ALLOW -
commit
case g4_unmet_age_2
snap soc 20270313 1 ?
soc 1005 202703 15000 0
line 369 FFS_CLAIM 1005 7001 7001 20270305 99213 1 12500 HUMAN_REVIEW SHARE_OF_COST_UNMET_UNVERIFIED
commit
case g4_age_8
snap soc 20270307 1 ?
soc 1005 202703 15000 0
line 370 FFS_CLAIM 1005 7001 7001 20270305 99213 1 12500 HUMAN_REVIEW SHARE_OF_COST_UNMET_UNVERIFIED,STALE_SHARE_OF_COST
line 371 FFS_CLAIM 1001 7001 7001 20270305 99213 1 12500 HUMAN_REVIEW STALE_SHARE_OF_COST
commit
case g4_future_asof
snap soc 20270316 1 ?
soc 1005 202703 15000 0
line 372 FFS_CLAIM 1005 7001 7001 20270305 99213 1 12500 HUMAN_REVIEW SHARE_OF_COST_UNMET_UNVERIFIED,STALE_SHARE_OF_COST
commit
case g4_count_mismatch
snap soc 20270314 2 ?
soc 1005 202703 15000 0
line 373 FFS_CLAIM 1005 7001 7001 20270305 99213 1 12500 HUMAN_REVIEW SHARE_OF_COST_UNMET_UNVERIFIED,STALE_SHARE_OF_COST
commit
case g4_empty
snap soc 20270314 0 ?
line 374 FFS_CLAIM 1005 7001 7001 20270305 99213 1 12500 HUMAN_REVIEW STALE_SHARE_OF_COST
commit
case g4_bad_met
snap soc 20270314 2 ?
soc 1001 202703 15000 2
soc 1005 202703 15000 1
line 375 FFS_CLAIM 1001 7001 7001 20270305 99213 1 12500 HUMAN_REVIEW SHARE_OF_COST_UNMET_UNVERIFIED,STALE_SHARE_OF_COST
line 376 FFS_CLAIM 1005 7001 7001 20270305 99213 1 12500 HUMAN_REVIEW STALE_SHARE_OF_COST
commit
case g4_bad_month
snap soc 20270314 1 ?
soc 1005 202700 15000 0
line 377 FFS_CLAIM 1005 7001 7001 20270305 99213 1 12500 HUMAN_REVIEW STALE_SHARE_OF_COST
commit
case g4_row_after_asof
snap soc 20270314 2 ?
soc 1001 202703 0 1
soc 1005 202704 15000 0
line 378 FFS_CLAIM 1005 7001 7001 20270305 99213 1 12500 HUMAN_REVIEW STALE_SHARE_OF_COST
commit
case g4_missing
drop soc
line 379 FFS_CLAIM 1005 7001 7001 20270305 99213 1 12500 HUMAN_REVIEW STALE_SHARE_OF_COST
line 380 FFS_CLAIM 9001 7001 7001 20270305 99213 1 12500 HOLD MEMBER_DECEASED,STALE_SHARE_OF_COST
commit
case g4_bad_pin
snap soc 20270314 1 00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
soc 1005 202703 15000 0
line 381 FFS_CLAIM 1005 7001 7001 20270305 99213 1 12500 HUMAN_REVIEW STALE_SHARE_OF_COST
commit
case g4_line_dates
snap soc 20270314 2 ?
soc 1005 202702 15000 0
soc 1005 202703 15000 0
line 382 FFS_CLAIM 1005 7001 7001 20270230 99213 1 12500 HUMAN_REVIEW SERVICE_DATE_INVALID
line 383 FFS_CLAIM 1005 7001 7001 20270320 99213 1 12500 HUMAN_REVIEW SERVICE_DATE_FUTURE,SHARE_OF_COST_UNMET_UNVERIFIED
commit
case g4_next_month
snap soc 20270314 1 ?
soc 1001 202703 0 1
line 384 FFS_CLAIM 1001 7001 7001 20270401 99213 1 12500 HUMAN_REVIEW SERVICE_DATE_FUTURE,SHARE_OF_COST_UNMET_UNVERIFIED
commit
# S2 on a line that is not future-dated: the 1st of a month before a snapshot dated in that month is pinned
case g4_month_turn
today 20270402
snap span 20270331 1 ?
span 1005 501 20270301 20271231
snap elig 20270331 1 ?
elig 1005 78131 1 19000101 99991231
snap soc 20270331 1 ?
soc 1005 202703 0 1
line 385 FFS_CLAIM 1005 7001 7001 20270401 99213 1 12500 HUMAN_REVIEW SHARE_OF_COST_UNMET_UNVERIFIED
commit
# restore today and the head enrollment, eligibility and share-of-cost snapshots (same rows, same pins)
today 20270315
```
followed by the 12 lines of v2:17-28 (the head span snapshot with its pin), the 11 lines of v2:29-39 (the head elig snapshot with its pin) and the 11 lines of (a) (the head soc snapshot with its pin), all verbatim. The block then ends, and the leap-case comment (v2:1143) follows, so the insertion point stays after the head elig restore (v2:1130-1141) and before v2:1143. These cases follow the line shapes of the G2 cases (v2:1020-1129), which reuse the same members and keys across cases. The expectations are drafts: the runner confirms them before the pins are filled.

Snapshot restore check (snapshots persist across cases, v2:4):
- soc: changed by every G4 case; restored to the head by the final soc block.
- today, span and elig: changed only by g4_month_turn; restored by the final `today 20270315` and the span and elig blocks. g4_month_turn re-declares span and elig because at today 20270402 the head span and elig snapshots (asOf 20270314, maxAge 7, v2:17, 29) are 19 days old and STALE.
- dmf, pdeath, excl, released, unresolved: not changed. At today 20270402 they stay usable: dmf and pdeath asOf 20270301 are 32 days old (maxAge 90), excl asOf 20270310 is 23 days old (maxAge 31), and released and unresolved (asOf 20270315, v2:6-7) are checked by `chained`, which has no age bound (as leap_year_90_days relies on at today 20280315, v2:1144-1158).
- The leap cases then re-declare today and their own snapshots, including soc (c).

What each case shows:
- 355: another member's unmet row does not count. It documents the behaviour only: "G4 any member" is killed by proof, because Fast reads `x.soc.getD l.member` and never sees another member's rows.
- 356: an amount of 0 passes whatever `met` says (localBCE's first arm); with `0 < q.cents` dropped, 1002's row would be unmet and met at once, so review.
- 357: the certain HOLD (usable, agreed unmet, dated before asOf, snapshot 1 day old).
- 358: S1 on a line that is not future-dated. The line is dated today (20270315), the day after asOf, and a row shows it unmet, so review, not HOLD. The snapshot is 1 day old, so the S5 age disjunct does not fire: S1 alone sends it to review. It differs from 357 in date and procedure, the pattern of v2 lines 1-2 (v2:43-44), so no duplicate rule fires.
- 359/360: the month boundary (kills "month is the day" and "month key dropped"); 360 also shows that no row for a covered month passes.
- 361: conflicting rows go to review, not HOLD (S3; kills "mixed rows hold").
- 362: a met row this month passes; an unmet row in the same month a year earlier does not count.
- 363: CAP_820 uses the period month.
- 364: every reason is reported (1003's span ends 20270131, v2:21).
- 367/368: age 7 is usable (368, no row, ALLOWs, so no STALE) but an unmet row on it cannot HOLD (367, S5). Kills "6 days" (368 gains STALE) and "G4 unmet age off" (367 holds).
- 369: an unmet row on a 2-day-old snapshot goes to review (S5 boundary). Kills "G4 unmet HOLD 2 days" and "G4 unmet age off".
- 370/371: age 8 is not usable (kills "8 days": 371 would ALLOW).
- 374: an empty snapshot shows no fact, so STALE only. G2's empty case differs, because "no row" is G2's fact (v2:1090-1093).
- 375: the only case that kills `met != 1` → `met == 0`, since okSoc forces `met ≤ 1` on a usable snapshot.
- 377: month 00 is not a calendar month, so the snapshot is unusable. The month is before the snapshot's month, so only the validDate test catches it.
- 378: a row for a month after the snapshot's month makes the snapshot unusable (S1).
- 381: a bad pin reads as missing, so no `_UNVERIFIED`.
- 382: an invalid date silences G4.
- 383: a future line dated after asOf that a row shows unmet goes to review, not HOLD (S1). It is also SERVICE_DATE_FUTURE, so it cannot by itself tell the asOf test from the future-date test; 358 can.
- 384: a future line in the month after the snapshot's month goes to review although no row shows it unmet (S2); v2 line 103 (b) shows the same on CAP_820. Both are future-dated.
- 385: S2 on a line that is not future-dated. Today is 20270402, the snapshot (asOf 20270331, 2 days old, usable) is for March, and the line is dated 20270401: `_UNVERIFIED` alone. Its only row owes nothing, so neither S1 nor S5 fires and nothing else reasons on the line.

Before committing the file:
- `end`: the runner adds each passing batch's lines plus its `pay` lines (Run.lean:330). v2 ends at 308 (v2:1210). The G4 block adds 31 expectation lines (ids 355-385) and 1 pay line (`pay 901 HOLD`), and (b), (c) and the restore lines add none, so `end` = 308 + 31 + 1 = 340. Recount it with the runner before committing.
- Fill the pins with `python3 tools/gate_rules_data.py pin`.

**New tests/gate_rules/demo_zz_v3.vectors.**
- Written by `gate_rules_data.py demo`. It adds `snap soc` with one row per member, `soc {m} 202701 0 1`, and `("soc", 20270404)` to the head loop (gate_rules_data.py:129-130).
- The rows are fixed and NEVER drawn from `Rng r` (as for elig, gate_rules_data.py:86-87), so the 3,616 expectations and the SEEDED totals are unchanged. Every row month (202701) and every demo line month (MONTHS, gate_rules_data.py:64) is at or before the snapshot's month 202704, so S1 and S2 do not fire, and no row is unmet, so S5 does not either.

**tests/gate_rules/shards_v1.vectors (unpublished, edited in place).**
- Add the head `snap soc` block after its elig block (shards:25-35). The header comment (41) says "copied from rules_v3.vectors".
- Its lines are dated in March 2027 or earlier, so S2 does not fire, and the head rows owe nothing, so S1 and S5 do not. It stays 39/39 (`end 39`, shards:204), and test_gate_rules_worker.py:481 stays `{10: "ALLOW -"}`.

Python evidence edits (line-neutral where possible):
- test_gate_rules_vectors.py:38: switch to rules_v3, demo_zz_v3 and shards_v1.
- test_gate_rules_vectors.py:117-120: add `("soc", 8, "SHARE-OF-COST", None, None)`.
- test_gate_rules_vectors.py:99 and 132: tag READ-SET/v4.
- test_gate_rules_worker.py:78: switch to the v3 file names.
- test_gate_rules_worker.py:461-463: `h` becomes `52522f474154452f524541442d5345542f763400` (READ-SET/v4), and the mutation becomes `h[:-4] + "33" + h[-2:]` with the comment "retired v3". It must differ from `h`, or the edit is a no-op.

Product edits:
- app/right_rail_gate_decide.py:144-151 `_reads_ok`: 328 → 392 (4 + 6×64 + 4), 324:328 → 388:392, tag v4, docstring "six 64-byte pins". The call site is 218.

Outside rightrail/ (as f16a61f4 did, scripts/g_rule_parity.py, 7 lines):
- scripts/g_rule_parity.py:6-9 docstring: "the current runner adds G2 and G4 and checks rules_v3.vectors, not v1, so these v1 expectations are what the Lean runner checked before G2, not what it checks today." Docstring only; the substantive parity work stays a follow-up (section 11, item 20).

Mutants (tools/gate_rules_mutants.py):
- Docstring (7): rules_v3.vectors.
- CHECKS (48-49) gains `("soc", "x.socUnmet l")`. Its unverified pattern `x.socSome && !x.socOk && validDate l.date && x.socUnmet l` occurs once (the first disjunct of the unverified arm).
- CERTAIN (132-136) gains `"=> x.socOk && validDate l.date && x.socUnmet l && !x.socDoubt l"`. The `=> ` prefix matches the style of the other CERTAIN entries. The doubt disjunct `|| x.socOk && validDate l.date && x.socDoubt l` has its validDate guard gets its own mutant ("G4 doubt on an invalid service date") instead of joining the CERTAIN aggregate, so its kill is named.
- New lists, appended to `chosen` (419-422) AFTER G2_FAST, so the existing slice positions stay the same.
- `G4_SPEC` (Spec.lean anchors; each occurs once):
  - "G4 any member": drop `q.member == l.member && ` from socCovers. Killed by proof only (FastEq `socCovers_member`/`socUnmet_eq`): Fast reads `x.soc.getD l.member`, so no vector can see it; 355 documents the behaviour;
  - "G4 month is the day": `q.month == l.date / 100` → `q.month == l.date` (kill 357);
  - "G4 month key dropped": drop ` && q.month == l.date / 100` (kill 360, 362);
  - "share-of-cost month unchecked": drop `validDate (q.month * 100 + 1) && ` (kill 377);
  - "share-of-cost row after asOf accepted": drop ` && q.month ≤ asOf / 100` (kill 378);
  - "share-of-cost met unchecked": drop ` && q.met ≤ 1` (kill 375).
- `G4_FAST` (Fast.lean anchors; each occurs once):
  - "G4 off": `| .SHARE_OF_COST_UNMET => x.socOk && validDate l.date && x.socUnmet l && !x.socDoubt l` → `| .SHARE_OF_COST_UNMET => false` (kill 357);
  - "G4 on an unusable snapshot": `=> x.socOk && validDate l.date && x.socUnmet l && !x.socDoubt l` → `=> x.socUnmet l && !x.socDoubt l` (kill 372, 373, 375: each is unusable with an unmet row on or before asOf and at most 1 day old, so doubt is false and the mutant adds a HOLD; 370 cannot kill it, because its 8-day-old row already sets doubt);
  - "G4 unverified off": `x.socSome && !x.socOk && validDate l.date && x.socUnmet l` → `false` (kill 370);
  - "G4 doubt off": ` || x.socOk && validDate l.date && x.socDoubt l` → `` (kill 358, 361, 367, 369, 383, 384, 385);
  - "G4 doubt on an invalid service date": `|| x.socOk && validDate l.date && x.socDoubt l` → `|| x.socOk && x.socDoubt l` (kill v2 lines 113-114, v2:332-333, copied verbatim into v3: their dates 100000101 and 21000229 are invalid, and their months 1000001 and 210002 are after the head snapshot's month 202703, so S2 would add `_UNVERIFIED`);
  - "mixed rows hold": `(x.socMet l || x.socDate < l.date` → `(x.socDate < l.date` (kill 361);
  - "G4 line after the snapshot holds": ` || x.socDate < l.date` → `` (kill 358, which is dated today and so not masked by SERVICE_DATE_FUTURE; 383 also dies);
  - "G4 unmet age off": ` || dayNum x.socDate + 1 < dayNum x.today` → `` (kill 367, 369);
  - "G4 unmet HOLD 2 days": `dayNum x.socDate + 1 < dayNum x.today` → `dayNum x.socDate + 2 < dayNum x.today` (kill 369);
  - "G4 next month allowed": ` || x.socDate / 100 < l.date / 100` → `` (kill 385, which is not future-dated; 384 and v2 line 103 also die);
  - "share-of-cost staleness off": `| .STALE_SHARE_OF_COST => !x.socOk` → `=> false` (kill 371);
  - "share of cost 6 days" (kill 367, 368) and "8 days" (kill 370, 371): `usable c.today 7 okSoc` → 6 or 8;
  - "share-of-cost usability read from eligibility": `socOk := usable c.today 7 okSoc c.shareOfCost` → `socOk := usable c.today 7 okElig c.eligibility` (kill 375);
  - "share-of-cost rows unread": `soc := group (·.member) (entries c.shareOfCost)` → `soc := ∅` (kill 357);
  - "G4 amount unchecked": drop `0 < q.cents && ` from Ix.socUnmet (kill 356);
  - "G4 met reads 0 only": `q.met != 1` → `q.met == 0` in Ix.socUnmet (kill 375).
- Lines 358 and 385 are dated on or before today, so the S1 and S2 tests are no longer masked by SERVICE_DATE_FUTURE. A mutant that gates either test on the future-date test instead (`x.socDate < l.date` → `x.today < l.date`, or `x.socDate / 100 < l.date / 100` → `x.today < l.date`) passes 383, 384 and v2 line 103, which are all future-dated, and now dies on 358 or 385. These variants are not in the list; the two named mutants above already cover the same kills.
- Anchor uniqueness: `x.socDate < l.date` and `x.socDate / 100 < l.date / 100` differ in text, `dayNum x.socDate` occurs only in Ix.socDoubt, and the doubt-guard anchor `|| x.socOk && validDate l.date && x.socDoubt l` is used by two separate mutants, each applied alone. Unbuilt; a SCRIPT_ERROR line would show a collision.
- Total 23 new mutants (6 Spec, 17 Fast). Expected tally: 22 killed by vectors, 1 by proof ("G4 any member"). G2 had 19, 18 by vectors and 1 by proof (LOG.md:245; f16a61f4 message).
- `review`'s G4 entries are checked by the Run.lean `#guard` at 55, not counted as kills (mutants:322-324).

## 7. Protected changes and XI.2 record draft

There is one commit whose body has one "XI.2:" paragraph per item, in the b7831a8c shape, as for f16a61f4. The owner authors or approves it (plan:138-145; CONSTITUTION.md:166-175).

1. **XI.2: Rule set.**
   - Predicate: the three `fires` arms verbatim; `socUnmet` = localBCE's `soc_amount > 0 && soc_met != 1` (main.rs:246) on the member-month row; `socMet` and `socDoubt` as in section 2; `okSoc` bounds rows to months up to the snapshot's month.
   - maxAge 7 days for usability and 1 day for an unmet HOLD, placeholders. The source's TTL is 24h (rust-engine/rules.json:356-373). A row that shows the line unmet on a snapshot more than 1 day old goes to `_UNVERIFIED` review (`dayNum asOf + 1 < dayNum today` in socDoubt); a met row or no row still ALLOWs on a snapshot up to 7 days old, which is past the 24h TTL. The date ≤ asOf condition bounds the line's date and the rows' months, not the age of the flag.
   - Invariant: a G4 HOLD rests only on a usable pinned share-of-cost snapshot at most 1 day old, a valid service date on or before its asOf, and covering rows that agree the month is unmet. For a valid line in a month after the snapshot's month, a line after asOf that a row shows unmet, an unmet row on a snapshot more than 1 day old, conflicting rows, and stale, missing, malformed or unverified data, G4 contributes only review reasons, so G4 alone never HOLDs on them and never silently ALLOWs; the line is HUMAN_REVIEW unless another rule's certain reason holds it (fail_closed_shareOfCost; `outcomeOf`, Spec.lean:398-400). No row for a covered month means no share of cost. Every reason is reported (Decision 6).
   - Disposition: retain R1-R5 and G2; add G4.
   - Evidence of the gap: localBCE G4 has no R-rule (plan:62).
   - Named differences: localBCE DENY RAD 022, not appealable (rust-engine/rules.json:873-905), becomes HOLD; `soc_met` ≥ 2 goes to review; no row for a covered month means no share of cost; conflicting rows, later-dated lines with an unmet row, unmet rows on a snapshot more than 1 day old, and later months go to review; v9's payment reduction (rust-engine/rules_v9.json:6187-6239) and non-negative precondition (rules_v9.json:3235-3245) are not modelled.
   - Synthetic, not legally verified, overridden by a state answer.
   - Reasons go from 28 to 31 of 32. The tripwire `#guard reasons.length ≤ maxReasonCodes` is added.
2. **XI.2: Lean statements.**
   - Fact gains 3 arms, which changes what sound, complete and hold_complete cover.
   - Grows gains shareOfCost equality, so the hypothesis of `monotone` is stronger. Withdrawn: none, because monotone never covered share of cost.
   - fail_closed's statement is byte-identical; its docstring now names the eighth source, covered by fail_closed_shareOfCost.
   - Three ReadManifest theorems are restated (old and new statements quoted): kindPins_some and reads_exact for six pins, and readSetTag_eq (ReadManifest.lean:121) for the tag literal, old `readSetTag = "RR/GATE/READ-SET/v3".toUTF8.toList ++ [0]`, new `readSetTag = "RR/GATE/READ-SET/v4".toUTF8.toList ++ [0]`, proof `rfl` in both. kindPins_pre, readSetOf_pre and decodeReads_encode keep their statements with new proof text (decodeReads_encode's `kindPins_some` destructuring at ReadManifest.lean:252 gains `p6, a6, h6`).
   - Private StateV2.pm_fires gains a hypothesis.
   - Additions: g4_review, g4_exclusive, g4_hold_usable (which also gives the 1-day age bound, `dayNum c.today ≤ dayNum (socAsOf c) + 1`), g4_allow, fail_closed_shareOfCost.
   - Axiom pins listed (expected: g4_review [propext], g4_exclusive none, g4_hold_usable none, g4_allow [propext, Classical.choice, Quot.sound], fail_closed_shareOfCost [propext, Quot.sound]; the commit quotes the built ones); no sorry.
3. **XI.2: Digest domain.**
   - RR/GATE/SNAPSHOT/v1 kind 8 = share of cost, row `member(129) ‖ month(4) ‖ cents(8) ‖ met(1)`, rows sorted. Kinds 1-7 unchanged.
   - New RR/GATE/READ-SHARE-OF-COST/v2. The /v2 keeps the READ-<kind>/v2 family; no v1 of this name ever existed.
4. **XI.2: Read-set and manifest formats.**
   - RR/GATE/READ-SET/v4: tag ‖ DMF, PROVIDER-DEATH, EXCLUSION, ENROLLMENT, ELIGIBILITY, SHARE-OF-COST slots ‖ u32 redo count ‖ redo ‖ base.
   - RR/GATE/READ-MANIFEST/v4: … ‖ pin1..pin6 ‖ u32 |P| ‖ P.
   - RULES_READS is u32 today ‖ 6×64-byte pins ‖ u32 |P| ‖ P, 392 bytes before P. Consumer: right_rail_gate_decide.py `_reads_ok`.
   - READ-SET/v3 and READ-MANIFEST/v3 are RETIRED and never reused. Custody never established the manifest (`manifestOk`, ReadManifest.lean:112-114).
   - S2's pay/reg roots are re-reserved from v4 to v5 (ReadManifest.lean:7-8), as G2 moved them from v3 to v4 (G2_DESIGN.md:457).
   - docs/RIGHTRAIL_FULL_STACK_TARGET.md:139 is updated (v4, six pins).
5. **XI.2: Conformance.**
   - New contract "Gate rules v3": rules_v3.vectors and demo_zz_v3.vectors, with two new MANIFEST.sha256 lines.
   - "Gate rules v2" is marked RETIRED (dated) in conformance/README.md:22-28. Its files and manifest lines 9-10 stay.
   - Withdrawn claim: the current gate_rules runner conforms to v2. A v2 file declares no `soc` snapshot, so every line would gain STALE_SHARE_OF_COST.
   - The rules_v1 manifest mismatch (OPEN_QUESTIONS.md:21) is left untouched.
6. **Artifacts.**
   - None move. gate_verify does not import Gate.Rules (VerifyCli.lean:1-3). gate_rules and gate_engine are test-only and unpinned.
   - The plan's "pinned worker re-pinned" (plan:99) is recorded as not applicable, as for G2 (LOG.md:250-252).
   - RULES_SOURCE changes and is recomputed by test_gate_rules_vectors.py:26-30.
   - `proof_execution_enabled` is untouched.
7. **Bloat (Decision 5, plan:151-155; Art. XII, CONSTITUTION.md:238).**
   - Ceilings are at zero headroom (test_bloat_budget.py:16, 18, 21, 22).
   - Raise each by the exact measured delta. Estimates only:
     - PRODUCT_CODE_LINES (36,952): about +50 to +62 (mutants about +45 to +58 for 23 mutants, gate_rules_data.py about +3, decide.py 0). G2 was +44 with 19.
     - EVIDENCE_CODE_LINES (41,287): 0 to +1 (test edits line-neutral if they fit; G2 was 0).
     - MARKDOWN_BYTES (93,972): about +10 to +50 (the TARGET row).
     - CONFORMANCE_MARKDOWN_BYTES (31,338): about +370 (the v3 entry and v2's retirement line; G2 was +368).
   - Felt effect: "a line whose member owes an unmet share of cost for the service month, on a snapshot at most a day old, is held; for a stale, missing, malformed or ambiguous share-of-cost snapshot, an unmet flag more than a day old, or a line the snapshot does not cover, share of cost adds only a review reason, so the line goes to review unless another rule holds it".
   - .lean and .vectors files are not counted. The scripts/g_rule_parity.py docstring edit is line-neutral.
8. **Runs.**
   - Interim guard, labelled interim.
   - List the modules built, the pytest files run, the mutant totals (23 G4 mutants: 22 by vectors, 1 by proof expected), and what was not run: the signer-dependent tests (OPEN_QUESTIONS.md:20) and the real rr_guarded v7 limits.

## 8. Rebuild estimate

Rebuilt (everything downstream of Rules/Spec.lean), as for G2:
- Rules.*;
- Anchor, AnchorTheorems, CheckpointV2Theorems;
- StateV2 (the long pole: `decide +kernel` over 31 names and the readSetOf lemmas);
- ReadManifest;
- Engine.Log/Frame/Snap/*Vectors/OneProc;
- AxiomCheck;
- exes gate_rules, gate_engine and gate_axioms.

Not rebuilt: the Financial tree, the gate_verify closure, blind_financial_worker. Gate/Spec.lean is not edited, so gate_verify does not move.

Estimated time on the emulated x86_64 toolchain: about 4-9h wall time for the first pass, the same as G2's estimate (G2_DESIGN.md:490-494). S1-S3 and S5 add three small Spec definitions, one theorem and four FastEq lemmas, which should not change the order of magnitude; the extra simp work in fires_iff, fact_mono and pm_fires is the likeliest place for a slower or failing first build. The G2 log records the full build passing (138/138) but not its wall time (LOG.md:242-243), so this is still an estimate, not a measurement. Every edit to Spec.lean restarts the chain, so freeze Spec first and stage as in section 5.

## 9. Risks

- **No real producer.** There is no 270/271 source (G2_DESIGN.md:506). All share-of-cost rows are synthetic. No share-of-cost legal source is in the tree: the RAD 022 citation points to a spreadsheet that is not present (rust-engine/rules.json:874).
- **HOLD versus payment reduction.** v9 reduces payment by min(SOC, gross) (rust-engine/rules_v9.json:6187-6239) instead of blocking. In real Medi-Cal, share of cost is a monthly liability met over time. HOLD may hold lines that would be paid net of share of cost. The gate cannot reprice.
- **List completeness.** No row for a covered month means no share of cost. A producer that omits a member-month at or before the snapshot's month causes a silent ALLOW. This is the same trust placed in the DMF and exclusion lists, and a producer contract, not enforced in Lean.
- **Review at the turn of the month (S2).** Until a snapshot dated in the new month is pinned, every valid line of that month goes to review, whatever the rows say. Producers should publish on the 1st. With maxAge 7, an old-month snapshot stays usable for earlier months, so only the new month's lines are affected.
- **Lines after asOf (S1).** A line dated after asOf in the snapshot's own month goes to review only when a row shows it unmet; with no row it passes, as any covered month does.
- **Age of the flag (S5).** An unmet row older than 1 day goes to review, so a producer that does not publish daily turns every unmet HOLD into review load. The other direction is not covered: a met row or no row ALLOWs on a snapshot up to 7 days old, past the source's 24h TTL, so a month that became unmet after asOf is a silent ALLOW for up to 7 days. Closing that needs 1 day for everything (section 11, item 11), which puts every line into review on a missed daily publish.
- **Conflicting rows (S3).** A producer that emits several rows per member-month that disagree causes review load. Several unmet rows that agree still hold.
- **Simp normal forms.** The doubt branch puts a disjunction into two Fact arms. fires_iff, fact_mono and pm_fires may need the Fact text in simp's normal form. Unbuilt.
- **Reason budget.** Headroom becomes 1. G5 or G6 cannot land without an owner decision (section 2), and with G5 counted the per-payment-bound route likely fails unless codes are shared or the cap rises. The per-token figures are estimates, not theorems.
- **The READ-SET/READ-MANIFEST bump must ship together with Ctx.shareOfCost.** Otherwise decisions depend on rows that custody's input commitment never hashes.
- **Kind numbering is by position in KINDS.** Append last.
- **Resident.refresh uses `{ i with .. }`.** refresh_eq catches a forgotten field only if test_proofs_are_current runs on freshly built modules.
- **Mutant anchors.** Each new anchor is chosen to occur once, but this is unbuilt; a SCRIPT_ERROR line (mutants:428-430) shows a collision.
- **Vector placement.** Snapshots persist across cases (v2:4). The G4 block must sit after the head elig restore (v2:1141); placed before v2:1130 it would run under g2_line_dates' one-row elig snapshot and every expectation would gain PROGRAM_NOT_ELIGIBLE. g4_month_turn changes `today`, span and elig as well as soc; the block's final restore must put all four back (section 6).
- **Signer-dependent tests stay unrun on this machine** (OPEN_QUESTIONS.md:20). Under the checks-gate-every-commit rule, the commit waits for the owner's explicit word, as G2's did.
- **Parity.** scripts/g_rule_parity.py:50-61 still holds `soc_amount` 0 and `soc_met` 1, its note at 78 still says no Lean rule exists, and G_TO_LEAN (41-47) has no G4 entry. The G4 commit updates only the docstring (6-9). G4 parity is not evidenced until a follow-up outside rightrail.
- **Name collision.** rust-engine/rules.json also has an unrelated "G4_ORDERING_PROVIDER_VALID" gate. Docs should say "G4 share of cost".

## 10. Out of scope

- Line, Span, Elig and the token.
- Raising maxReasonCodes or maxTokenBytes.
- Payment reduction, partial met, spend-down tracking and any SOC month tally.
- v9's RAD 178 non-negative precondition (moot for natural numbers).
- The owner typed-evidence route.
- A real share-of-cost producer.
- G5's new conditions, G6, G8 and G10 (counted in the reason budget only).
- S2 roots.
- The rules_v1 manifest mismatch.
- The parity harness beyond its docstring (a separate commit outside rightrail).
- The localBCE rust-engine, which stays the shadow reference per AGENTS.md.

## 11. Decisions for the owner

Each item has a default. "Approve defaults" accepts all of them; each item can also be approved alone in one word.

1. **Approach.** G4 is 3 codes on its own SNAPSHOT/v1 kind 8 `soc`; maxReasonCodes stays 32; Gate/Spec.lean is untouched.
2. **Code names.** SHARE_OF_COST_UNMET (HOLD), SHARE_OF_COST_UNMET_UNVERIFIED (review), STALE_SHARE_OF_COST (review).
3. **Row and key.** `Soc {member, month CCYYMM, cents, met}`; a row covers a line when the member matches and `month = l.date / 100`.
4. **Units.** `cents`, 8 bytes like `Line.cents`; the amount is read only as `> 0`.
5. **Met semantics.** The fact uses localBCE's `met != 1`; `okSoc` requires `met ≤ 1`, so any other value sends the batch to review.
6. **Missing row.** No row for a covered member-month (at or before the snapshot's month) means no share of cost (pass), like the DMF list.
7. **Conflicting rows.** Default: the certain fact is "some covering row unmet and no covering row met"; mixed rows go to `_UNVERIFIED` review. (Alternative: any unmet row holds the line, as first drafted.)
8. **Snapshot date bound.** Default: `okSoc` rejects a row for a month after the snapshot's month (STALE review), and a HOLD needs the line dated on or before asOf; a later line that a row shows unmet goes to `_UNVERIFIED` review. (Alternative: asOf unused by `okSoc` and the certain arm, as first drafted.)
9. **Month coverage.** Default: a valid line in a month after the snapshot's month fires `_UNVERIFIED` (review); STALE, fail_closed and the STALE mutant patterns are untouched. (Alternatives: no clause, the first-of-month gap left as a producer contract with a silent ALLOW, as first drafted; or STALE also fires for such a line, which changes the STALE Fact, the twin and the mutant pattern.)
10. **Flows.** All flows; CAP_820 uses its period-start month. (Alternative: FFS only.)
11. **Maximum age.** Default: 7 days for usability (a placeholder like G2), and 1 day for an unmet HOLD: a row that shows the line unmet on a snapshot more than 1 day old goes to `_UNVERIFIED` review, while met and no-row lines still ALLOW on a snapshot up to 7 days old; the STALE arm is untouched. The source's TTL is 24h (rust-engine/rules.json:356-373). The date ≤ asOf bound of item 8 does not limit the flag's age. (Alternatives: 7 days for the HOLD too, as first drafted, which lets a HOLD rest on a flag up to 7 days old, past the source's 24h TTL; or 1 day for everything, closest to the TTL, which needs a daily refresh and sends every line to STALE review on a missed day and every 1st of the month to S2 review until the new month's snapshot is pinned.)
12. **Disposition.** Certain unmet share of cost is HOLD; no repricing, partial met or spend-down.
13. **Grows.** Equality field `shareOfCost`, as for G2.
14. **Reason budget.** Add the tripwire `#guard reasons.length ≤ BlindLedger.Gate.maxReasonCodes` now; before G5 or G6 starts, decide the route. Default: a proved per-payment bound near `rowOf`. With G5's two new conditions counted, that route likely fails (about 33 per payment after G10 at G2 shape) unless codes are shared or the cap rises. (Alternative: raise the cap with a TOKEN version bump and a gate_verify re-pin.)
15. **Formats.** New READ-SHARE-OF-COST/v2; READ-SET v3 → v4; READ-MANIFEST v3 → v4, with S2's pay/reg roots re-reserved to v5; v3s retired.
16. **Conformance.** "Gate rules v3" (rules_v3, demo_zz_v3); v2 retired; the rules_v1 manifest mismatch left untouched.
17. **Axiom pins.** In Theorems.lean only, as f16a61f4 did.
18. **Evidence path.** The pinned snapshot, not owner typed evidence; amend plan:100 for share of cost.
19. **v9 RAD 178 precondition.** Not ported.
20. **Parity harness.** The G4 commit updates only the scripts/g_rule_parity.py:6-9 docstring (G4, rules_v3.vectors), as f16a61f4 did for G2. A separate follow-up commit outside rightrail/ derives `soc_amount` and `soc_met` from the snapshot rows and adds G4 to G_TO_LEAN.
21. **Commit with unrunnable tests.** As for G2: run every check that can run, record the signer-dependent failures, and commit only on the owner's explicit word.

## 12. Implementation record (2026-11-12)

Where the implementation differs from the text above:
- **Two proofs needed a manual step.** `fires_iff`'s SHARE_OF_COST_UNMET case left a goal simp could not close (the unmet row in hand makes "every positive row is met" false); it is closed by a short `all_goals` term after the simp. StateV2's private `pm_fires` left goals whose two sides print identically; `all_goals rfl` closes them. No statement changed.
- **Axiom pins.** As expected: g4_review [propext], g4_exclusive none, g4_hold_usable none, g4_allow [propext, Classical.choice, Quot.sound], fail_closed_shareOfCost [propext, Quot.sound]. Every other pin is unchanged.
- **Review additions.** An adversarial review of the built change (four lenses, two skeptics per finding) found coverage gaps only. Added:
  - vector line 386, an unmet line dated on the snapshot's asOf, which holds (the inclusive S1 boundary);
  - case `g4_bad_date_stale`, line 387, an invalid service date on an unusable snapshot whose row for that month is unmet, which gives only SERVICE_DATE_INVALID and STALE_SHARE_OF_COST;
  - the mutants "G4 line on asOf to review" and "G4 unverified on an invalid service date", killed by those two lines;
  - a share-of-cost snapshot with rows in `test_reads_are_the_read_set_bytes`, so the Python recomputation checks the sixth pin and the READ-SHARE-OF-COST/v2 slot.
- **Counts.** rules_v3 `end` is 342 (section 6 said 340 before the review lines). 25 G4 mutants (6 Spec, 19 Fast): 24 killed by vectors, 1 by proof ("G4 any member").
- **Bloat, exact.** PRODUCT_CODE_LINES +42, EVIDENCE_CODE_LINES +2, MARKDOWN_BYTES +5, CONFORMANCE_MARKDOWN_BYTES +278.
