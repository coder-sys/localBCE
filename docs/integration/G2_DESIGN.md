# G2 (aid code / benefit level) as RightRail gate rule — design for lead approval

Status: design only. Nothing has been edited, built or staged. Under RIGHTRAIL_BASE_PLAN.md:138-145 the owner, as RightRail lead, authors or approves every change inside `rightrail/`. Every Lean run goes through `scripts/rr_guarded_interim.ps1` and is labelled interim evidence (plan:130-137).

All paths are under `rightrail/` unless noted. Line numbers are at HEAD dc586d87 of `codex/rightrail-base-phases`.

## 1. Summary

- **Source rule.** localBCE G2 is at rust-engine/src/main.rs:235-240. It denies `G2_PROGRAM_ELIGIBILITY_FAILED` unless `aid_code` is in {13,23,53,103,104}, then denies `G2_BENEFIT_LEVEL_MISSING` unless `benefit_level_exists == 1`. Only the first failure is reported. Both are raw claim fields (main.rs:128-129). The rule is synthetic and not legally verified (RULES_ENGINE.md; rules_active_v1.json:5-6).
- **Why a new snapshot.** A RightRail `Line` has no aid or benefit field (lean/BlindLedger/Gate/Rules/Spec.lean:130-141), and every per-member fact comes from a pinned snapshot in `Ctx` (Spec.lean:170-184).
  - Adding fields to Line would change `enc`, `Line.fields`, RULES_ADDS, the RELEASED/UNRESOLVED pins and STATE/v1 (Spec.lean:375-376, 458-460; Run.lean:96-119). Rejected.
  - Widening `Span` would change every kind-4 SNAPSHOT/v1 pin and every READ-ENROLLMENT/v2 slot (Spec.lean:456). Rejected.
- **Design.** A new member-keyed reference snapshot, SNAPSHOT/v1 kind 7 `elig`, read exactly as R5 reads `span`:
  - certain → HOLD;
  - present but unusable → `_UNVERIFIED` (review);
  - missing, stale or malformed → `STALE_ELIGIBILITY` (review);
  - every reason reported.
  This is Decision 6 (plan:156-161).
- **What does not change.** The gate token (Gate/Spec.lean), artifacts/** and every pinned executable.
- **What does change (protected):**
  - the reason set, `Fact` and `Grows`;
  - new kind 7 and the new domain READ-ELIGIBILITY/v2;
  - READ-SET/v3 and READ-MANIFEST/v3 (five pins);
  - a "Gate rules v2" conformance contract, with v1 retired.
- **Evidence path.** G2's evidence is the pinned snapshot, not the owner typed-evidence path of plan:100:
  - owner EvidenceRecord is post-decision and scoped to one obligation (app/right_rail_financial_owner.py:1360-1405, 4038-4061);
  - no Lean `evidenceAccounted` exists (the conjunct is Financial/Types.lean:715-720);
  - the gate reads only `Ctx` snapshots.
  The owner must amend plan:100.

## 2. Semantics

Defaults:
- today = the `today` directive;
- maxAge(elig) = 7 days, a placeholder like enrollment (Spec.lean:312-314); localBCE's O1 TTL is 24h (rules.json:356);
- coverage = same member, and start ≤ date ≤ stop (inclusive);
- for CAP_820 the date is the period start (Spec.lean:128-129);
- there is no plan test, because the aid code is per member.

Helper predicates:
- `aidEligible c l`: some covering row has `aid ∈ allowedAid`.
- `levelEligible c l`: some single covering row has `aid ∈ allowedAid ∧ level = 1`. The pairing is deliberate: an allowed-aid row with no level plus a leveled row with a bad aid does not pass.

| Reason (new) | Fires when | review? | Outcome alone |
|---|---|---|---|
| BENEFIT_LEVEL_MISSING | certain(elig) ∧ aidEligible ∧ ¬levelEligible | no | HOLD |
| BENEFIT_LEVEL_MISSING_UNVERIFIED | unverified(elig) ∧ aidEligible ∧ ¬levelEligible | yes | HUMAN_REVIEW |
| PROGRAM_NOT_ELIGIBLE | certain(elig) ∧ ¬aidEligible | no | HOLD |
| PROGRAM_NOT_ELIGIBLE_UNVERIFIED | unverified(elig) ∧ ¬aidEligible | yes | HUMAN_REVIEW |
| STALE_ELIGIBILITY | ¬usable today 7 okElig elig | yes | HUMAN_REVIEW |

How the table reads:
- `certain` means usable and a valid service date (Spec.lean:268-270). `unverified` means isSome, not usable, and a valid date (Spec.lean:273-275). `usable` (Spec.lean:216-220) rejects: missing; a bad pin, which reads as missing (Run.lean:182); an invalid or future asOf; an invalid today; older than 7 days; a count mismatch; an empty snapshot; and a malformed row.
- The two certain codes are mutually exclusive. That reproduces localBCE's order (main.rs:235-240) without suppressing any other rule's reasons.
- An invalid service date silences G2. SERVICE_DATE_INVALID carries the line.
- Overlap with R5 is deliberately not suppressed. A member with no span and no eligible row gets `MEMBER_NOT_ENROLLED,PROGRAM_NOT_ELIGIBLE`, so G2's Fact stays independent of enrollment.
- The rules never produce BLOCK (Spec.lean:62).

Byte order (enforced by the #guard at Run.lean:49 and StateV2.lean:6684 `decide +kernel`):
- BENEFIT_* go after ALREADY_DECIDED and before CAP_MEMBER_MONTH_DUPLICATE.
- PROGRAM_* go after MEMBER_NOT_ENROLLED_UNVERIFIED and before PROVIDER_DECEASED ('G' < 'V').
- STALE_ELIGIBILITY goes after STALE_DMF and before STALE_ENROLLMENT ('L' < 'N').
- Total 28 of maxReasonCodes 32 (Gate/Spec.lean:32, 460).
- Codes match codeOk (Gate/Spec.lean:119-122). No token change.

Parity map:
- G2_PROGRAM_ELIGIBILITY_FAILED ↔ PROGRAM_NOT_ELIGIBLE.
- G2_BENEFIT_LEVEL_MISSING ↔ BENEFIT_LEVEL_MISSING.
- aid int n ↔ identifier of `toString n`.

## 3. Data model

- Row `Elig {member, aid, level, start, stop}`.
- `Elig.fields = [(idWidth, member), (idWidth, aid), (1, level), (4, start), (4, stop)]`, giving 267-byte rows under pinInput "RR/GATE/SNAPSHOT/v1" kind 7 (Spec.lean:462-467).
- `aid` is an identifier: 0x01 followed by the bytes, read big-endian (Spec.lean:91-95).
- `level`: 1 = a benefit level exists, 0 = none.
- `okElig _ e := validDate e.start && validDate e.stop && e.start ≤ e.stop && e.level ≤ 1`. Any other level value makes the snapshot unusable, which goes to review and never to HOLD.
- `allowedAid : List Nat := [78131, 78387, 79155, 20000819, 20000820]`, the identifiers of "13","23","53","103","104".
  - It is a literal, so Spec and Fast share one expression.
  - A `#guard allowedAid == ["13","23","53","103","104"].map aidId` sits next to Run.lean:49.
  - D3/D4 (rules.json:420-426) would be the one-constant swap 82995/82996.
- Ctx gains `eligibility : Option (Snapshot Elig)` with no default, so every literal must name it.
- Python: `tools/gate_rules_data.py` KINDS (line 15) appends `"elig"` LAST, so it is number 7 by position (line 43) and released/unresolved keep 5/6. WIDTHS (19-20) gains `"elig": (ID, ID, 1, 4, 4)`.

## 4. Lean changes per file

### Rules/Spec.lean (protected)
- Reason (112-118) and `reasons` (121-126): add the 5 constructors at the positions in section 2.
- After Span (160): `structure Elig where member aid level start stop : Nat`, with a doc comment saying it is synthetic G2 and not legally verified.
- Ctx (170-184): add `eligibility : Option (Snapshot Elig)` after `enrollment`.
- After okSpan (211): `okElig` as in section 3.
- After overlap (296):
```lean
def aidId (s : String) : Nat := s.toUTF8.foldl (fun n b => n * 256 + b.toNat) 1
/-- localBCE G2's aid codes (rust-engine/src/main.rs:235) as identifiers. Synthetic, not legally verified. -/
def allowedAid : List Nat := [78131, 78387, 79155, 20000819, 20000820]
def eligCovers (l : Line) (e : Elig) : Bool := e.member == l.member && e.start ≤ l.date && l.date ≤ e.stop
def aidEligible (c : Ctx) (l : Line) : Bool :=
  (entries c.eligibility).any fun e => eligCovers l e && allowedAid.contains e.aid
def levelEligible (c : Ctx) (l : Line) : Bool :=
  (entries c.eligibility).any fun e => eligCovers l e && allowedAid.contains e.aid && e.level == 1
```
- fires (315-340), new arms. The rule-table doc at 312-314 adds "eligibility 7 days, a placeholder (localBCE O1 TTL 24h)".
```lean
  | .BENEFIT_LEVEL_MISSING => certain c 7 okElig c.eligibility l && aidEligible c l && !levelEligible c l
  | .BENEFIT_LEVEL_MISSING_UNVERIFIED => unverified c 7 okElig c.eligibility l && aidEligible c l && !levelEligible c l
  | .PROGRAM_NOT_ELIGIBLE => certain c 7 okElig c.eligibility l && !aidEligible c l
  | .PROGRAM_NOT_ELIGIBLE_UNVERIFIED => unverified c 7 okElig c.eligibility l && !aidEligible c l
  | .STALE_ELIGIBILITY => !usable c.today 7 okElig c.eligibility
```
- review (344-349): add a new FIRST line `| .BENEFIT_LEVEL_MISSING_UNVERIFIED | .PROGRAM_NOT_ELIGIBLE_UNVERIFIED | .STALE_ELIGIBILITY` before `| .COLLIDES…`. This keeps gate_rules_mutants.py REVIEW (28-31) matching verbatim.
- After 456: `def Elig.fields`.
- Docs: add a G2 bullet to the module doc (16-61), add "R1, R3, R5, G2" to the certain/unverified sentences (44-61), and add "7 eligibility" to the pin-kind doc (435-441).
- G2 stays out of `claim`, `keys`, `order` and `seen0` (299-310, 384-389). Do not touch them. `carried` (505-506) is a struct update, so it carries eligibility with no change.

### Rules/Theorems.lean (protected)
- After 33:
```lean
abbrev AidEligible (c : Ctx) (l : Line) : Prop :=
  ∃ e ∈ entries c.eligibility, e.member = l.member ∧ e.start ≤ l.date ∧ l.date ≤ e.stop ∧ e.aid ∈ allowedAid
abbrev LevelEligible (c : Ctx) (l : Line) : Prop :=
  ∃ e ∈ entries c.eligibility, e.member = l.member ∧ e.start ≤ l.date ∧ l.date ≤ e.stop ∧ e.aid ∈ allowedAid ∧ e.level = 1
```
- Fact (35-64), five arms in the style of 44-49 and 59-60:
  - certain arms: `Usable c.today 7 okElig c.eligibility ∧ validDate l.date = true ∧ …`;
  - unverified arms: `c.eligibility.isSome ∧ ¬Usable … ∧ validDate l.date = true ∧ …`;
  - STALE arm: `¬Usable c.today 7 okElig c.eligibility`.
- fires_iff (78-80): add `aidEligible, levelEligible, eligCovers` to the simp set. Keep `allowedAid` folded (do not list it). If `List.contains` does not normalise to `∈`, add `List.elem_iff` or `List.contains_iff_mem`.
- Grows (552-565): add `eligibility : c'.eligibility = c.eligibility` and extend the docstring (548-551). Equality is required, because added rows can clear PROGRAM_NOT_ELIGIBLE, so G2 is not monotone in row growth. Grows is constructed nowhere else (grep).
- fact_mono (589-616), one grouped arm for all five reasons: `simpa only [Fact, g.today, g.eligibility] using h`.
- fail_closed (249-263) stays byte-identical (it remains true). Add a twin:
```lean
theorem fail_closed_eligibility {c b d} (h : ¬Usable c.today 7 okElig c.eligibility)
    (hd : d ∈ (decideBatch c b).decisions) :
    d.outcome = .HUMAN_REVIEW ∨ (d.outcome = .HOLD ∧ ∃ r ∈ d.reasons, review r = false) := by
  obtain ⟨_, l, rfl⟩ := mem_decideAll (seen := seen0 c b) (ls := order c b) hd
  exact outcome_cases (line_complete (r := .STALE_ELIGIBILITY) h)
```
- New G2 theorems (additions only):
  - `g2_review`: certain codes have `review = false`; the three others are `review`. Proved `by decide`.
  - `g2_exclusive`: `¬(Fact … .PROGRAM_NOT_ELIGIBLE ∧ Fact … .BENEFIT_LEVEL_MISSING)`, a term proof.
  - `g2_hold_usable`: a G2 certain Fact implies Usable (`h.1`).
  - `g2_allow`: `(decideLine c seen l).outcome = .ALLOW → Usable c.today 7 okElig c.eligibility ∧ LevelEligible c l`. It follows the `no r` pattern of allow_facts (154-157), using STALE_ELIGIBILITY, SERVICE_DATE_INVALID, PROGRAM_NOT_ELIGIBLE and BENEFIT_LEVEL_MISSING with fires_iff and by_contra.
- Axiom pins: add pins next to 778-807 and in Gate/AxiomCheck.lean and Gate/AXIOMS.txt.

### Rules/Fast.lean
- Ix (79-90): add `eligSome eligOk : Bool` and `elig : HashMap Nat (List Elig)`.
- Ix.build (105-110): `eligSome := c.eligibility.isSome`, `eligOk := usable c.today 7 okElig c.eligibility`, `elig := group (·.member) (entries c.eligibility)`.
- Probe-only queries (doc 15-16):
  - `Ix.aidEligible x l := (x.elig.getD l.member []).any fun e => eligCovers l e && allowedAid.contains e.aid`;
  - `Ix.levelEligible` likewise, with `&& e.level == 1`.
- Ix.fires (152-176): arms in the exact textual pattern of 161-164, so the mutants' CHECKS/`unverified_rows` (gate_rules_mutants.py:48-54) extend with tag `elig`:
  - `x.eligOk && validDate l.date && x.aidEligible l && !x.levelEligible l`
  - `x.eligSome && !x.eligOk && validDate l.date && x.aidEligible l && !x.levelEligible l`
  - `x.eligOk && validDate l.date && !x.aidEligible l`
  - `x.eligSome && !x.eligOk && validDate l.date && !x.aidEligible l`
  - `!x.eligOk`
- `&&` is left-associative, so these unfold to the same shape as Spec's `certain …` forms.

### Rules/FastEq.lean
- Add `build_eligOk`, `build_eligSome` and `build_elig` (rfl) next to 370-388.
- Add `eligCovers_member`, modelled on covers_member (288-291).
- Add `aidEligible_eq` and `levelEligible_eq`, modelled on enrolled_eq (372-378) via mem_group.
- Append these to the fires_eq simp list (488-491).
- No statement changes. decideLine_eq, decideBatchFIn_eq (537) and pinBytes_eq (747, generic) are untouched, and the axiom pins (785-802) are unchanged.

### Rules/Resident.lean
- refresh (137-144): set the three new fields and update the docstring (136, "five snapshots").
- breaks (381-383): add `"elig"`.
- refresh_eq (1374-1378), ix_extend_eq (1403-1421) and step_keep (1915-1923) keep their text. They are the safety net if a field or keyword is forgotten.

### Rules/Run.lean (runner; text feeds RULES_SOURCE, 59-63)
- Doc (15-16): add `elig` with rows `MEMBER AID LEVEL START STOP`.
- Pinned (127-134): add `elig : Option (Snapshot Elig × List UInt8)`.
- St.pin (209-222): add `let elig := snapshot st "elig" (fun r => match r.mapM String.toNat? with | some [m, a, v, s, t] => some ⟨m, a, v, s, t⟩ | _ => none) "RR/GATE/SNAPSHOT/v1" 7 Elig.fields`, and a fifth `← readPin "RR/GATE/READ-ELIGIBILITY/v2" 7 Elig.fields elig` in `kinds`.
- St.ctx (224-235): `eligibility := p.elig.map (·.1)`.
- reads (260-266): literal tag "RR/GATE/READ-SET/v3"; doc says five pins.
- Row whitelist (379): add `"elig"`.
- Next to 49, two guards:
  - the allowedAid guard;
  - a review-completeness guard: `#guard reasons.all fun r => review r || !((name r).endsWith "_UNVERIFIED" || (name r).startsWith "STALE_")`. This closes the silent-HOLD trap of `| _ => false` (Spec.lean:349) for every future rule.

### Rules/DecideLayer.lean:205
- Add `eligibility := none` to the Ctx literal.

### StateV2.lean (protected)
- reasonName (6666-6679): add the five names. g1_reasons_pw (6684) re-checks the order.
- readSetOf (6716-6723): after `n`, add `let g ← optPin "RR/GATE/READ-ELIGIBILITY/v2" 7 Elig.fields c₀.eligibility` and hash `"RR/GATE/READ-SET/v3".toUTF8.toList ++ [0] ++ a ++ b ++ e ++ n ++ g ++ …`. `dom2` is fixed at /v2 (line 59), so add a `readSetTag` def; do not edit dom2. Update the doc at 6715 ("five external snapshots").
- **pm_fires (6225-6237), a private lemma missed by all three designs:** add the hypothesis `(h8 : c.eligibility = c'.eligibility)` and include it in `simp only at`/`subst`. The single call site (6347) gains one `rfl`.
- firesQ (2673-2686): no change. New reasons fall through to `fires x.c₀ [] l r` (2686), and `carried` keeps eligibility.

### ReadManifest.lean (protected)
- manifestTag (18) → READ-MANIFEST/v3. Update the doc (6-12), moving the S2 reservation to v4.
- kindPins (36-38) and readSetPre (41-48): add a fifth kind and slot; use the READ-SET/v3 tag.
- decodeReads (77-98): cut p5; pins `[p1..p5]`.
- Restate for five pins: kindPins_some (178-189), kindPins_pre, readSetOf_pre (201-207), run_reads_eq (211-222, with a readSetTag rfl lemma in place of dom2_eq), decodeReads_encode (224-260), encodeReads_inj (263-273), and reads_exact (290-317, adding `Exact 7 Elig.fields i.ctx.eligibility p5`).
- Do not keep v2 as dead code. Retire it by record: custody never established v2 (`manifestOk`, 11-12).

### No change
- Gate/Spec.lean (token), Engine/OneProc.lean (text is re-hashed only), RulesMain.lean.
- Shards.lean: fact_idSeen (27-35) re-closes.
- ShardRun.lean: it uses only the statement of decideBatchFIn_eq.
- Anchor.lean: struct updates only.
- The Financial tree and the gate_verify closure (VerifyCli.lean:1-3).

## 5. Proof plan

Re-proved by existing text:
- mem_all and reasons_nodup (Theorems.lean:82, 189);
- fact_idSeen (Shards.lean:35);
- fires_eq (once the simp list is extended) and decideLine_eq, decideAll_eq, decideBatchFIn_eq, decideBatchF_eq;
- refresh_eq, ix_extend_eq and step_keep;
- g1_reasons_pw and reasonCode_ascending;
- sound, complete, hold_complete and line_complete (through fires_iff);
- allow_facts, claim_keys, the allow_clear family, one_payment_per_line, deterministic, and claim/own/order/seenAt_grows. G2 never enters claim, keys, order or seen0.

New proof text, with the statement unchanged:
- fires_iff (extended simp set);
- fact_mono (one new arm);
- private StateV2 pm_fires (one more hypothesis);
- the custody and c15 lemmas that unfold readSetOf (one more bind step).

Statements that change (XI.2):
- Fact (5 arms);
- Grows (eligibility field), which strengthens the hypothesis of `monotone` (624) while leaving its text unchanged;
- ReadManifest kindPins_some, kindPins_pre, readSetOf_pre, run_reads_eq, decodeReads_encode, encodeReads_inj and reads_exact (five pins).

Additions:
- fail_closed_eligibility, g2_review, g2_exclusive, g2_hold_usable, g2_allow;
- FastEq helper lemmas;
- readSetTag lemmas.

All are expected to depend on [propext, Classical.choice, Quot.sound] or a subset. No sorry, no ofReduceBool.

Build stages, each a separate guarded `-Modules` run that stops on the first failure:
1. Freeze Spec.lean (Reason, Elig, Ctx field, fires, review, fields), then build Rules.Theorems.
2. Rules.FastEq, Rules.Resident, Rules.Shards.
3. Rules.ShardRun, Rules.DecideLayer, then exe gate_rules, so the vectors can run early.
4. Gate.StateV2, Gate.ReadManifest.
5. Gate.AxiomCheck, then exes gate_engine and gate_axioms.

Then run:
- test_gate_rules_vectors: test_runner_is_current and test_proofs_are_current (`--no-build`, 19-20, 32-35);
- test_gate_rules_worker, the shards tests, test_right_rail_gate_formats and test_bloat_budget;
- gate_rules_mutants.py by hand (Windows).

## 6. Vectors

Published files stay untouched: rules_v1.vectors and demo_zz.vectors are immutable (conformance/MANIFEST.sha256:1-2; conformance/README.md:49-53).

**New tests/gate_rules/rules_v2.vectors** is rules_v1 verbatim plus the following.

(a) Head, after the span block (v1 line 28):
```
snap elig 20270314 10 ?
elig 1001 78131 1 19000101 99991231
elig 1002 78131 1 19000101 99991231
elig 1003 78131 1 19000101 99991231
elig 1004 78131 1 19000101 99991231
elig 1005 78131 1 19000101 99991231
elig 1006 78131 1 19000101 99991231
elig 1007 78131 1 19000101 99991231
elig 1009 78131 1 19000101 99991231
elig 9001 78131 1 19000101 99991231
elig 9002 78131 1 19000101 99991231
```
These are exactly the members on v1 `line` directives (1008 appears only in span rows). The rows cover every date, so all v1 expectations are unchanged except (b) and (c).

(b) today_invalid (v1:612-614): line 154 expects `HUMAN_REVIEW STALE_DMF,STALE_ELIGIBILITY,STALE_ENROLLMENT,STALE_EXCLUSION,STALE_PROVIDER_DEATH`.

(c) Leap cases (v1:1007-1065): after each `today`, re-declare `snap elig <asOf ≤ today, within 7 days> 1 ?` with `elig 1001 78131 1 19000101 99991231`.
- 20280315: asOf 20280310.
- 21000315: asOf 21000314.
- 20000315: asOf 20000314.
- Optional: an elig age case across 29 Feb 2028.

(d) G2 cases, inserted before the leap cases. Line ids start at 301, because v1 uses ids up to 262. Today is 20270315. Payee and rendering are 7001.

Encodings: "13"=78131, "23"=78387, "53"=79155, "103"=20000819, "104"=20000820, "105"=20000821, "999"=20527417, "D3"=82995.
```
# G2 (synthetic, not legally verified): allowed aid and a benefit level on one covering row
case g2_aid_and_level
snap elig 20270314 7 ?
elig 1001 78131 1 20260101 20271231
elig 1005 20527417 1 20260101 20271231
elig 1006 79155 0 20260101 20271231
elig 1007 20527417 1 20260101 20271231
elig 1007 78387 0 20260101 20271231
elig 1009 20000819 1 20270310 20270312
elig 1002 20000820 1 20260101 20271231
line 301 FFS_CLAIM 1001 7001 7001 20270305 99213 1 12500 ALLOW -
line 302 FFS_CLAIM 1005 7001 7001 20270305 99213 1 12500 HOLD PROGRAM_NOT_ELIGIBLE
line 303 FFS_CLAIM 1006 7001 7001 20270305 99213 1 12500 HOLD BENEFIT_LEVEL_MISSING
line 304 FFS_CLAIM 1007 7001 7001 20270305 99213 1 12500 HOLD BENEFIT_LEVEL_MISSING
line 305 FFS_CLAIM 1009 7001 7001 20270309 99213 1 12500 HOLD PROGRAM_NOT_ELIGIBLE
line 306 FFS_CLAIM 1009 7001 7001 20270310 99214 1 13100 ALLOW -
line 307 FFS_CLAIM 1009 7001 7001 20270312 99215 1 18400 ALLOW -
line 308 FFS_CLAIM 1009 7001 7001 20270313 85025 1 1100 HOLD PROGRAM_NOT_ELIGIBLE
line 309 FFS_CLAIM 1002 7001 7001 20270305 99213 1 12500 ALLOW -
line 310 FFS_CLAIM 1003 7001 7001 20270305 99213 1 12500 HOLD MEMBER_NOT_ENROLLED,PROGRAM_NOT_ELIGIBLE
line 311 CAP_820 1005 501 501 20270301 0 1 45000 HOLD PROGRAM_NOT_ELIGIBLE
line 312 FFS_CLAIM 9001 7001 7001 20270305 99213 1 12500 HOLD MEMBER_DECEASED,PROGRAM_NOT_ELIGIBLE
commit
case g2_encoding
snap elig 20270314 2 ?
elig 1001 82995 1 20260101 20271231
elig 1005 20000821 1 20260101 20271231
line 320 FFS_CLAIM 1001 7001 7001 20270305 99213 1 12500 HOLD PROGRAM_NOT_ELIGIBLE
line 321 FFS_CLAIM 1005 7001 7001 20270305 99213 1 12500 HOLD PROGRAM_NOT_ELIGIBLE
commit
case g2_payment
snap elig 20270314 1 ?
elig 1001 78131 1 20260101 20271231
line 330:900 FFS_CLAIM 1001 7001 7001 20270305 99213 1 12500 ALLOW -
line 331:900 FFS_CLAIM 1005 7001 7001 20270305 99214 1 13100 HOLD PROGRAM_NOT_ELIGIBLE
pay 900 HOLD
commit
case g2_age_7
snap elig 20270308 1 ?
elig 1001 78131 1 20260101 20271231
line 340 FFS_CLAIM 1001 7001 7001 20270305 99213 1 12500 ALLOW -
commit
case g2_age_8
snap elig 20270307 3 ?
elig 1001 78131 1 20260101 20271231
elig 1005 20527417 1 20260101 20271231
elig 1006 79155 0 20260101 20271231
line 341 FFS_CLAIM 1001 7001 7001 20270305 99213 1 12500 HUMAN_REVIEW STALE_ELIGIBILITY
line 342 FFS_CLAIM 1005 7001 7001 20270305 99213 1 12500 HUMAN_REVIEW PROGRAM_NOT_ELIGIBLE_UNVERIFIED,STALE_ELIGIBILITY
line 343 FFS_CLAIM 1006 7001 7001 20270305 99213 1 12500 HUMAN_REVIEW BENEFIT_LEVEL_MISSING_UNVERIFIED,STALE_ELIGIBILITY
commit
case g2_future_asof
snap elig 20270316 1 ?
elig 1001 78131 1 20260101 20271231
line 344 FFS_CLAIM 1001 7001 7001 20270305 99213 1 12500 HUMAN_REVIEW STALE_ELIGIBILITY
commit
case g2_count_mismatch
snap elig 20270314 2 ?
elig 1005 20527417 1 20260101 20271231
line 345 FFS_CLAIM 1005 7001 7001 20270305 99213 1 12500 HUMAN_REVIEW PROGRAM_NOT_ELIGIBLE_UNVERIFIED,STALE_ELIGIBILITY
commit
case g2_empty
snap elig 20270314 0 ?
line 346 FFS_CLAIM 1001 7001 7001 20270305 99213 1 12500 HUMAN_REVIEW PROGRAM_NOT_ELIGIBLE_UNVERIFIED,STALE_ELIGIBILITY
commit
case g2_bad_level
snap elig 20270314 2 ?
elig 1001 78131 2 20260101 20271231
elig 1005 78131 1 20260101 20271231
line 347 FFS_CLAIM 1005 7001 7001 20270305 99213 1 12500 HUMAN_REVIEW STALE_ELIGIBILITY
line 348 FFS_CLAIM 1001 7001 7001 20270305 99213 1 12500 HUMAN_REVIEW BENEFIT_LEVEL_MISSING_UNVERIFIED,STALE_ELIGIBILITY
commit
case g2_reversed_row
snap elig 20270314 2 ?
elig 1001 78131 1 20260101 20271231
elig 1008 78131 1 20271231 20260101
line 349 FFS_CLAIM 1001 7001 7001 20270305 99213 1 12500 HUMAN_REVIEW STALE_ELIGIBILITY
commit
case g2_missing
drop elig
line 350 FFS_CLAIM 1001 7001 7001 20270305 99213 1 12500 HUMAN_REVIEW STALE_ELIGIBILITY
line 351 FFS_CLAIM 9001 7001 7001 20270305 99213 1 12500 HOLD MEMBER_DECEASED,STALE_ELIGIBILITY
commit
case g2_bad_pin
snap elig 20270314 1 00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
elig 1005 20527417 1 20260101 20271231
line 352 FFS_CLAIM 1005 7001 7001 20270305 99213 1 12500 HUMAN_REVIEW STALE_ELIGIBILITY
commit
case g2_line_dates
snap elig 20270314 1 ?
elig 1001 20527417 1 20260101 20271231
line 353 FFS_CLAIM 1001 7001 7001 20270230 99213 1 12500 HUMAN_REVIEW SERVICE_DATE_INVALID
line 354 FFS_CLAIM 1001 7001 7001 20270320 99213 1 12500 HOLD PROGRAM_NOT_ELIGIBLE,SERVICE_DATE_FUTURE
commit
# restore the head elig block (same 10 rows, same pin)
```

What each case shows:
- 304: pairing. An allowed aid with no level plus a bad aid with a level does not pass.
- 305-308: inclusive boundaries.
- 310: every reason is reported (1003's span ends 20270131).
- 312: R1 alongside G2.
- 320: localBCE's numeric set does not contain "D3".
- 345, 346, 348: present-but-unusable snapshots keep their `_UNVERIFIED` facts. These are the cases Design 2 got wrong.

Before committing the file:
- `end` becomes 276 + 32 checked lines (+1 pay) and must be recounted with the runner.
- Fill the pins with `python3 tools/gate_rules_data.py pin`.

**New tests/gate_rules/demo_zz_v2.vectors.**
- Written by `gate_rules_data.py demo`, which adds `snap elig` with one row per member (`78131 1 19000101 99991231`, asOf the same as the demo span).
- The rows are built deterministically and NEVER drawn from `Rng r` (gate_rules_data.py:52-73, 100), so the 3,616 expectations and the SEEDED totals are unchanged.

**tests/gate_rules/shards_v1.vectors (unpublished, edited in place)** and **tests/_gate_shards.py:24-29 `_HEAD`.**
- Add a `snap elig` block covering their members.
- test_gate_rules_worker.py:481 then stays `{10: "ALLOW -"}`.

Python evidence edits:
- test_gate_rules_vectors.py:38: switch to rules_v2, demo_zz_v2 and shards_v1.
- test_gate_rules_vectors.py:117-120: add `("elig", 7, "ELIGIBILITY", None, None)`.
- test_gate_rules_vectors.py:132: tag READ-SET/v3.
- test_gate_rules_worker.py:78: switch to the v2 file names.
- test_gate_rules_worker.py:461-463: the hex becomes READ-SET/v3, and the mutation byte must change, or the edit becomes a no-op. That would fail loudly.

Product edits:
- app/right_rail_gate_decide.py:144-151 `_reads_ok`: 264 → 328, 260:264 → 324:328, tag v3, docstring "five pins".

Mutants (tools/gate_rules_mutants.py):
- FIRST, in a separate prior commit, fix the 5 stale RUN_MUTANTS anchors (276-289 against Run.lean:288, 314, 345-347). Until then main() cannot return 0.
- Then:
  - CHECKS (48) gains `("elig","!x.aidEligible l")` and `("elig","x.aidEligible l && !x.levelEligible l")`;
  - CERTAIN (129-131) gains the elig entries.
- New G2 mutants:
  - G2 off;
  - a code dropped from allowedAid;
  - "999" added to allowedAid;
  - `level == 1` changed to `level != 0`;
  - the pairing broken (levelEligible without the aid conjunct);
  - certain on an unusable snapshot (drop `x.eligOk &&`);
  - unverified off;
  - maxAge 7 changed to 6 or 8 (Spec and Fast);
  - STALE_ELIGIBILITY off;
  - a G2 code moved into or out of `review`;
  - Ix.build eligOk using okSpan;
  - refresh omitting eligOk;
  - eligCovers `≤` changed to `<`.
- Kills: 304 kills pairing, 340/341 kill age, 309/320/321 kill set membership, 348 kills level.

## 7. Protected changes and XI.2 record draft

There is one commit whose body has one "XI.2:" paragraph per item, in the b7831a8c shape. The owner authors or approves it (plan:138-145; CONSTITUTION.md:166-175).

1. **XI.2: Rule set.**
   - Predicate: the five `fires` arms verbatim, `allowedAid` = identifiers of "13","23","53","103","104" (main.rs:235), and maxAge 7 (a placeholder).
   - Invariant: a G2 HOLD rests only on a usable pinned eligibility snapshot and a valid service date. Stale, missing, malformed or unverified data gives HUMAN_REVIEW. Every reason is reported (Decision 6).
   - Disposition: retain R1-R5; add G2.
   - Evidence of the gap: localBCE G2 has no R-rule (plan:62).
   - Named unresolved differences: rules.json:834-838 (manual review) and rules.json:420-426 (D3/D4, a long-term-care list).
   - Synthetic, not legally verified, overridden by a state answer.
   - Reasons go from 23 to 28 of 32.
2. **XI.2: Lean statements.**
   - Fact gains 5 arms, which changes what sound, complete and hold_complete cover.
   - Grows gains eligibility equality, so the hypothesis of `monotone` is stronger. Withdrawn: none, because monotone never covered eligibility. Recorded: adding eligibility rows is not monotone.
   - fail_closed is byte-identical. Its six-source list no longer enumerates every source; the twin fail_closed_eligibility covers the seventh.
   - The seven ReadManifest theorems are restated for five pins (old and new statements quoted).
   - Private StateV2.pm_fires gains a hypothesis.
   - Additions: g2_review, g2_exclusive, g2_hold_usable, g2_allow.
   - Axiom pins listed; no sorry.
3. **XI.2: Digest domain.**
   - RR/GATE/SNAPSHOT/v1 kind 7 = eligibility, row `member(129) ‖ aid(129) ‖ level(1) ‖ start(4) ‖ stop(4)`, rows sorted. Kinds 1-6 unchanged.
   - New RR/GATE/READ-ELIGIBILITY/v2. The /v2 keeps the READ-<kind>/v2 family; no v1 of this name ever existed.
4. **XI.2: Read-set and manifest formats.**
   - RR/GATE/READ-SET/v3: tag ‖ DMF, PROVIDER-DEATH, EXCLUSION, ENROLLMENT, ELIGIBILITY slots ‖ u32 redo count ‖ redo ‖ base.
   - RR/GATE/READ-MANIFEST/v3: … ‖ pin1..pin5 ‖ u32 |P| ‖ P.
   - RULES_READS is u32 today ‖ 5×64-byte pins ‖ u32 |P| ‖ P. Consumer: right_rail_gate_decide.py `_reads_ok`.
   - READ-SET/v2 and READ-MANIFEST/v2 are RETIRED and never reused. Custody never established v2 and no custody exe is pinned.
   - S2's pay/reg roots are re-reserved from v3 to v4 (ReadManifest.lean:7).
   - docs/RIGHTRAIL_FULL_STACK_TARGET.md:139 is updated.
5. **XI.2: Conformance.**
   - New contract "Gate rules v2": rules_v2.vectors and demo_zz_v2.vectors, with new MANIFEST.sha256 lines.
   - "Gate rules v1" is marked RETIRED (dated) in conformance/README.md:22-26. Its files and manifest lines 1-2 stay.
   - Withdrawn claim: the current gate_rules runner conforms to v1.
   - test_gate_producer_design.py:14 and test_right_rail_gate_formats.py:30 still read v1 statically. They read only the anchor and set pins, which are unchanged.
6. **Artifacts.**
   - None move. gate_verify does not import Gate.Rules (VerifyCli.lean:1-3; artifacts/gate-verify/PROVENANCE.txt:48, 50). gate_rules and gate_engine are test-only and unpinned.
   - The plan's "pinned worker re-pinned" (plan:99) is recorded as not applicable.
   - RULES_SOURCE changes and is recomputed by test_gate_rules_vectors.py:26-30.
7. **Bloat (Decision 5, plan:151-155).**
   - Ceilings are at zero headroom (test_bloat_budget.py:16-23).
   - Raise PRODUCT_CODE_LINES (gate_rules_data.py about +6, mutants about +20, gate_decide 0), EVIDENCE_CODE_LINES (about +3), MARKDOWN_BYTES (table row) and CONFORMANCE_MARKDOWN_BYTES (README) by the exact measured deltas.
   - Felt effect: "a line whose member has no allowed aid code with a benefit level on the service date is held; a stale or missing eligibility file sends the batch to review".
   - .lean and .vectors files are not counted.
8. **Runs.**
   - Interim guard, labelled interim.
   - List the modules built, the pytest files run, and the mutant totals, and what was not run (the real rr_guarded v7 limits).

## 8. Rebuild estimate

Rebuilt (everything downstream of Rules/Spec.lean):
- Rules.*;
- Anchor, AnchorTheorems, CheckpointV2Theorems;
- StateV2 (the long pole: `decide +kernel` over 28 names and the readSetOf lemmas);
- ReadManifest;
- Engine.Log/Frame/Snap/*Vectors/OneProc;
- AxiomCheck;
- exes gate_rules, gate_engine and gate_axioms.

Not rebuilt: the Financial tree (including Payment.CodecLaws), the gate_verify closure, blind_financial_worker.

Estimated time on the emulated x86_64 toolchain (CodecLaws ≈ 2h):
- Rules through Resident: about 1-3h;
- StateV2: about 2-5h;
- the rest: about 0.5-1.5h;
- first pass: about 4-9h wall time.

Every edit to Spec.lean restarts the chain, so freeze Spec first and stage as in section 5. This is an estimate, not a measurement.

## 9. Risks

- The published v1 contract is retired. A second implementation pinned to v1 is no longer comparable.
- The READ-SET/READ-MANIFEST bump must ship together with Ctx.eligibility. Otherwise decisions depend on rows that custody's inputCommitment never hashes (StateV2.lean:7734).
- review's `| _ => false` is a trap. The new #guard and g2_review close it.
- Resident.refresh uses `{ i with .. }`. refresh_eq catches a forgotten field only if test_proofs_are_current runs.
- Kind numbering is by position in KINDS. Append last.
- Reason budget: 28 of 32 after G2. G4, G6, G8 and G10 in the same 5-code shape would exceed the cap, and raising it edits Gate/Spec.lean and moves the gate_verify pin.
- No real producer of eligibility rows exists (the 837 does not carry them; there is no 270/271 producer). Phase 3 uses synthetic rows only.
- scripts/g_rule_parity.py:49-50 still holds G2 at passing values. Parity evidence for G2 needs that harness to read elig rows (a follow-up outside rightrail).
- grind in step_keep and fact_idSeen, and `decide +kernel`, may slow under the guard's memory cap.

## 10. Out of scope

- Line, Span and the token.
- The owner typed-evidence route.
- A real eligibility producer.
- LTC or flow scoping.
- G4-G10.
- Raising maxReasonCodes.
- S2 roots.
- The localBCE rust-engine, which stays the shadow reference per AGENTS.md.
- Re-benchmarking the worker for the fifth per-frame group rebuild.
