# Trunk step 3: G2 on the trunk — design for owner approval

## Status

- **Owner decision, 2026-11-17: "Approve defaults"** — all 23 decisions of section 11 at their defaults. In particular: author (a) now as WIP (1), land the step 3 commit only after step 2's request side (2), hold it for the signer (11), the signed path reads no eligibility (15).
- Draft for owner approval, 2026-11-17, revision 2: review findings applied. Revision 2 applies the accuracy and completeness reviews (22 findings: one blocker, seven majors, fourteen minors, each checked against the cited files; several overlap and are applied once; two had small citation errors that were corrected, not copied): the signed path made fail-closed in Scoped (4.6a), the signed-path guard fallout (4.6b), the `lim_loc` and constructor-tuple sites of the `FCtxInv` change, the (a)/(b) split of Engine3 and Frame/Spec, the full statement-pin list, the plan's scratch-copy build for the proof-killed mutant, Route A as decided, the step 2 sequencing risk, the in-trunk docs and `input_file` check, and several line corrections. Nothing in this design has been built, edited or committed beyond the work listed below.
- Worktree `C:\Users\sruja\Downloads\localBCE-trunk`, branch `codex/rightrail-trunk-step3` at 845e7b9c (local). `rightrail/` is RightRail trunk fc89f9e5, a zip import.
- This makes exact TRUNK_MIGRATION_PLAN.md step 3 (docs/integration/TRUNK_MIGRATION_PLAN.md:278-343) under its decisions 4-14 (:450-460), which the owner approved with all defaults. It ports the October G2 (commit f16a61f4, design f16a61f4:docs/integration/G2_DESIGN.md).
- The owner is RightRail lead and authors or approves every change inside `rightrail/`. Every protected change carries the 8-field record of rightrail/CONSTITUTION.md:174-183 (section 9). Checks gate every commit: a failed or skipped check stops the commit.
- Every Lean or TCB run goes through `scripts/rr_guarded_interim.ps1` and is labelled interim evidence.
- Paths: trunk paths as rightrail/path:line at 845e7b9c; Lean paths are under rightrail/lean/BlindLedger/Gate/ when written short; October paths as f16a61f4:path:line. The lines in sections 3, 5 and 6 and the Rules, Authority and bound sites of section 4 were re-read for this document. The Flat, DecideRows, DecideCut, Signed and Engine3 lines in section 4 come from the read-only site surveys of 2026-11-17 and were spot-checked (DecideRows.lean:61, :76, :1604, :1672, :1991, :2066, :2087, :3015, :4640; Flat/Model.lean:232, :256, :356, :421; Flat/Signed.lean:111, :127; STMT_PIN.txt:3118, :3137-3150, :3486, :3504, :3563-3564).

### Already built on `codex/rightrail-trunk-step3` (WIP, local)

The per-payment reason bound of plan decision 6, over the 24 trunk reasons, with no G2:

- 379b487c: `Bits` (4 sources `dmf`/`pd`/`ex`/`en`), `bitsOf`, `may`, `may_sound`, `budget`, `pay_budget`, the headroom pins and `decideAll_may` in Rules/Theorems.lean:314-390; the Flat corollary in Flat/PayTheorems.lean.
- 4d715f52: the capped path (`capD`, POSTING_CAP always possible).
- fcd29193, 0319ec32, 6655362e: Flat/RowsBudget.lean, the Engine3 lane, leaf and payment-mask bounds.
- 845e7b9c: Flat/PayNumbering.lean, Engine3 payment numbering.

The plan's "Run.name injectivity lemma" (TRUNK_MIGRATION_PLAN.md:298) was not needed: `codes_le` says "No name injectivity is needed" (rightrail/lean/BlindLedger/Gate/Flat/PayTheorems.lean:97-99). That plan item is closed.

### What step 3 depends on from step 2

- Built: answer header v3, u64 reason fields at `Reason.idx` bits, leaf-only bits 62/63 (19e001c7); the `Elig` and `Soc` types and the idx lemmas (9330572b; Rules/Spec.lean:150-164, :208-216, :565-566).
- **Not built: the request side** (FRAME/v3 with the eligibility and share-of-cost feeds, CONTEXT/v2). The owner chose Route A on 2026-11-15 (docs/integration/TRUNK_STEP2_FRAME_DESIGN.md:5); what is awaited is rr-core's answer on carrying the feeds in its v2, or the 2026-11-22 bound, after which Route A is built here (:6). Route B (a v3 over the FRAME_V1 body) needs a separate explicit owner word (docs/integration/TRUNK_MIGRATION_PLAN.md:443) and is not assumed. Today every engine `Ctx` is built from kinds 1-4 only (Frame/Spec.lean:326-330; Flat/Worker.lean:253-260), and the host sends four feeds (rightrail/app/right_rail_gate_decide.py:497). So the eligibility feed cannot reach the engine.
- Step 2 deferred to step 3: `Ctx.eligibility`, `ctxOf` snaps, `Feeds`/`FCtxInv`/`feedCapped`, `fcap_line`, `Ix`/`Ix.build`, `FeedsX`, ReadB reads, Engine3 `feedPins`/`snapK` and the 1,024-fact cap for the new feeds (TRUNK_STEP2_FRAME_DESIGN.md:193, :618).

## 1. Summary

### What G2 does

- localBCE G2 (synthetic, not legally verified) as a RightRail gate rule. It reads a pinned, member-keyed eligibility snapshot, SNAPSHOT/v1 kind 7 (Rules/Spec.lean:545), exactly as R5 reads enrollment (f16a61f4:docs/integration/G2_DESIGN.md:13-18).
- Five reasons, with idx 24-28 (TRUNK_MIGRATION_PLAN.md:281-286):

  | idx | Reason | Outcome alone | review | bypassable |
  |---|---|---|---|---|
  | 24 | BENEFIT_LEVEL_MISSING | HOLD | no | no |
  | 25 | BENEFIT_LEVEL_MISSING_UNVERIFIED | HUMAN_REVIEW | yes | yes |
  | 26 | PROGRAM_NOT_ELIGIBLE | HOLD | no | no |
  | 27 | PROGRAM_NOT_ELIGIBLE_UNVERIFIED | HUMAN_REVIEW | yes | yes |
  | 28 | STALE_ELIGIBILITY | HUMAN_REVIEW | yes | yes |

- Because answer bits are numbered by idx since step 2, no existing frame bit moves (TRUNK_MIGRATION_PLAN.md:288).

### What changes on the trunk

- The rules layer (Rules/Spec, Run, Theorems, Fast, FastEq), the bound (`Bits.el`, headroom pins), Authority (`reasonMask` 2^29, bypassable count 18), the Flat model and its proofs, the signed path (Scoped `kRules`/`Ctx.plain`, Flat/Signed, and the Scoped/Consume/Signed guards), DecideRows/DecideCut/RowsBudget, Engine3, the host tables, the GATE_RULES_V2 contract, the in-trunk STATUS.md and ARCHITECTURE.md, the mutant module and the parity harness copy.
- `gate_engine` moves (section 4.9). `gate_hist3`/`gate_verify3` move with it. `gate_verify` does not.

### The honest split

- **(a) Can be built now** (on this branch, against the text runner and generic `Ctx`/`FCtx` proofs): every Rules change; the bound; Authority; Flat/Model, Flat/Theorems, PayTheorems, Signed, and every anonymous-constructor proof of `FCtxInv` (Frame/Spec `fcOf_inv`, PayTheorems `feedsOf_inv`, Signed `specFeeds_inv`); Frame/Spec and Worker `feedsOf`, with `eligibility := none` in `ctxOf` and `commitBin`; Scoped `kRules`/`Ctx.plain` and the signed-path guards (4.6); DecideRows, DecideCut, RowsBudget, DecideBench; Engine3 `FeedsX.el` with an absent-feed placeholder in `FeedsX.decode` and ReadB `feedsW`, and `assemble`; `REASONS`/`REASON_IDX`/`cause_actions`; `gate_rules_data.py`; the GATE_RULES_V2 page, reference checker and all four vector files (the text runner reads `snap elig` directly, Run.lean:188-194, so no frame is needed); the in-Lean mutants; the frozen v1 copy for the parity harness.
- **(b) Needs step 2's request side** (the eligibility feed in the frame): the kind-7 `snap` in Frame/Spec `ctxOf`; Worker `commitBin` reading kind 7 through `snapF`; the real fifth-source decode in Engine3 `FeedsX.decode`, the fifth `feedW` with its offsets in ReadB `feedsW`, `feedPins`/`feedAt`/`snapK` and the StepH/Verify loops with the 5-tuple `pres`; the host feed; every ALLOW fixture; `PAIRS_DIGEST`.
- **Sequencing.** Step 2's request side rewrites the same functions (Frame/Spec, Flat/Worker, Rules/Spec change in step 2, TRUNK_STEP2_FRAME_DESIGN.md:188; the host reads exactly four descriptors today, rightrail/app/right_rail_gate_decide.py:570-571; ReadB computes offsets for four feeds, rightrail/lean/BlindLedger/Gate/Engine3/ReadB.lean:104-109). So the (a) edits in Frame/Spec `ctxOf`/`feedsOf`, Worker `feedsOf`/`commitBin`, RowsStore and ReadB are kept to the smallest form (one field, an `eligibility := none`, an absent placeholder) and are rebased onto the request side when it lands. Expected conflicts: Frame/Spec `ctxOf`/`feedsOf`, Worker `commitBin`, RowsStore `FeedsX.decode`, ReadB `feedsW`; about half a day to resolve (section 8).
- **(c) Needs the signer** (`rr_gate_mldsa87.exe`, absent here): `OUTPUT_DIGEST`/`REALISTIC_DIGEST`, the golden `gate_v1.vectors` regeneration, and the signer-dependent tests of section 7.4.
- **Consequence.** (a) must not reach a committed `gate_engine` pin before (b). With the feed absent, `eligibility` is `none` in the engine and Engine3's `el` is the absent placeholder, so the Flat engine and Engine3 alike decide STALE_ELIGIBILITY on every line until (b), and every ALLOW becomes HUMAN_REVIEW. (a) is authored now as WIP; the step 3 commit lands after the step 2 request side (decisions 1 and 2).

## 2. Status of the plan's step 3 text

Read against the trunk, the plan is right in shape. These items change:

- **Stale lines.** `bypassable` is at Rules/Spec.lean:166-173, not :153-160; `review` at :420-427, not :390-395 (TRUNK_MIGRATION_PLAN.md:291-292). Step 2 inserted the idx lemmas at :153-164. Host `_names` is at rightrail/app/right_rail_gate_decide.py:555-561 and the mask checks at :660 and :672, not :542/:642/:654 (plan :301, :312). `DEFAULT_VECTORS` is at scripts/g_rule_parity.py:35, not :38-39 (plan :328).
- **Already done.** The "bit beyond the reasons" guard already reads `2 ^ Rules.reasons.length` (AuthorityLaws.lean:491), from step 2's 19e001c7. Plan :310 becomes "verify it now tests bit 29".
- **Not needed.** The `Run.name` injectivity lemma (plan :298); see Status.
- **Already exists.** The Python-versus-Lean `REASONS` test (plan :301) is rightrail/tests/test_gate_answer_v3.py:55-69; step 3 updates its constants only.
- **Missing from the plan**, each placed in sections 3-7: the G2 helper definitions and the `allowedAid` `#guard`; every `Ctx` literal; the Theorems statement changes (`Fact`, `Grows.eligibility`, `fact_mono`) and the new `g2_*` theorems; Flat/Model `Feeds`/`FCtxInv`/`feedCapped`/`work` (statement-pinned); Flat/Theorems `fires_loc`/`unc_feed`/`work_le`/`lim_loc` and PayTheorems `fires_part`/`part_feed`/`feedBits`; Flat/Signed; Scoped `kRules`/`Ctx.plain` set to read no eligibility, and the signed-path guards that assert ALLOW (4.6). Plan :340 ("Scoped/Consume kind maps only if the signed path is extended") does not cover these: they are needed because `kRules` copies the caller's `base`, not to extend the path. Also DecideCut; DecideBench; the step 2 `#guard` at DecideRows.lean:1672 that must be removed; the AuthorityLaws.lean:477 guard that forces `reasonMask`; the headroom pins; the v1-retirement fallout in tests; two tests that build a bypass bit from list position.
- **Kept from the plan, now placed**: the in-trunk docs, STATUS.md edited once and ARCHITECTURE.md (plan :341; rightrail/AGENTS.md:20), in section 5; the `input_file` rule for embedded files (plan :337), in section 5.
- **Proof-killed mutant.** Plan :333 and decision 7 (:453) are followed: a one-off scratch-copy build, recorded in the commit message (7.1). An extra Spec-level `#guard` pair for the same mutant is offered as an optional addition, not a replacement; adding it is an amendment to plan :333 for the owner (decision 12).
- **Unstated dependency.** Plan :330 says ALLOW fixtures "get usable eligibility feeds". No frame path can carry one until step 2's request side exists.
- **October files with no trunk home.** StateV2 (`pm_fires` h8, `g1_reasons_pw`, the READ-SET/v3 binding), ReadManifest and Resident are absent on the trunk. Their G2 changes are dropped, not ported (section 4.10). On the trunk the eligibility pin is bound by Run's READ-SET/v5 bytes (runner) and, after step 2, by CONTEXT/v2 (engine).

## 3. Exact rule specification

Ported from f16a61f4:rightrail/lean/BlindLedger/Gate/Rules/Spec.lean and f16a61f4:docs/integration/G2_DESIGN.md:31-60. Differences from October are listed in 3.7.

### 3.1 Reasons and idx

- Constructors appended after POSTING_CAP (Rules/Spec.lean:119-120), under a comment like :119, so no constructor moves: BENEFIT_LEVEL_MISSING, BENEFIT_LEVEL_MISSING_UNVERIFIED, PROGRAM_NOT_ELIGIBLE, PROGRAM_NOT_ELIGIBLE_UNVERIFIED, STALE_ELIGIBILITY.
- `reasons` (Rules/Spec.lean:124-129) stays in byte order of name, checked by the `#guard` at Run.lean:47:
  - BENEFIT_LEVEL_MISSING, BENEFIT_LEVEL_MISSING_UNVERIFIED after ALREADY_DECIDED;
  - PROGRAM_NOT_ELIGIBLE, PROGRAM_NOT_ELIGIBLE_UNVERIFIED after POSTING_CAP, before PROVIDER_DECEASED ("POS" < "PRO", "PROG" < "PROV");
  - STALE_ELIGIBILITY between STALE_DMF and STALE_ENROLLMENT.
  - October's list (no POSTING_CAP) is not copied verbatim.
- `Reason.idx` (Rules/Spec.lean:136-144) gains 24-28 as in the table of section 1, "the next free number" (:133). `idx_inj` (:147), the dense `#guard` (:151), `idx_dense` (:154), `reasons_len_le` ≤ 62 (:157), `idx_len` (:160) and `reasons_list_nodup` (:164) keep their text and re-check by `decide`/`cases`.

### 3.2 Data

- `Elig` (Rules/Spec.lean:211-216) and `Elig.fields` (:565-566) exist. Drop "No rule reads it yet" from the docstring (:210).
- `Ctx` (Rules/Spec.lean:236-255) gains `eligibility : Option (Snapshot Elig)`. No default (decision 3), as October (f16a61f4:docs/integration/G2_DESIGN.md:82).
- After `okSpan` (Rules/Spec.lean:282), from f16a61f4:.../Rules/Spec.lean:234:

  ```lean
  def okElig (_ : Nat) (e : Elig) : Bool := validDate e.start && validDate e.stop && e.start ≤ e.stop && e.level ≤ 1
  ```

  A level above 1 makes the whole snapshot unusable: review, never HOLD.
- After `overlap` (Rules/Spec.lean:362-367), from f16a61f4:.../Rules/Spec.lean:321-336:

  ```lean
  def aidId (s : String) : Nat := s.toUTF8.foldl (fun n b => n * 256 + b.toNat) 1
  def allowedAid : List Nat := [78131, 78387, 79155, 20000819, 20000820]
  def eligCovers (l : Line) (e : Elig) : Bool := e.member == l.member && e.start ≤ l.date && l.date ≤ e.stop
  def aidEligible (c : Ctx) (l : Line) : Bool :=
    (entries c.eligibility).any fun e => eligCovers l e && allowedAid.contains e.aid
  def levelEligible (c : Ctx) (l : Line) : Bool :=
    (entries c.eligibility).any fun e => eligCovers l e && allowedAid.contains e.aid && e.level == 1
  ```

  `allowedAid` holds the identifiers of "13", "23", "53", "103", "104" (localBCE rust-engine/src/main.rs:235). The pairing in `levelEligible` is deliberate: an allowed-aid row with no level plus a leveled row with a bad aid does not pass (f16a61f4:docs/integration/G2_DESIGN.md:42).

### 3.3 Fires

Five arms in `fires` (Rules/Spec.lean:392-418), from f16a61f4:.../Rules/Spec.lean:358-359, :372-373, :381:

```lean
| .BENEFIT_LEVEL_MISSING => certain c 7 okElig c.eligibility l && aidEligible c l && !levelEligible c l
| .BENEFIT_LEVEL_MISSING_UNVERIFIED => unverified c 7 okElig c.eligibility l && aidEligible c l && !levelEligible c l
| .PROGRAM_NOT_ELIGIBLE => certain c 7 okElig c.eligibility l && !aidEligible c l
| .PROGRAM_NOT_ELIGIBLE_UNVERIFIED => unverified c 7 okElig c.eligibility l && !aidEligible c l
| .STALE_ELIGIBILITY => !usable c.today 7 okElig c.eligibility
```

- `certain` is usable and a valid service date (Rules/Spec.lean:339-341). `unverified` is present, not usable, and a valid date (:344-346). `usable` (:287-291) rejects: missing; invalid today or asOf; asOf after today; older than `maxAge`; a count mismatch; an empty snapshot; a malformed row.
- A bad pin reads as missing: the runner's `snapshot` guards the pin (Run.lean:193) and the worker's `snapF` returns `none` on a mismatch (Flat/Worker.lean:161-166). So a bad pin gives STALE_ELIGIBILITY alone, no `_UNVERIFIED`, as October's g2_bad_pin case expects. This answers the survey question on pin-failure semantics for kind 7.
- The two certain codes are mutually exclusive (localBCE's first-failure order), with no suppression of other rules (f16a61f4:docs/integration/G2_DESIGN.md:54).
- An invalid service date silences G2; SERVICE_DATE_INVALID carries the line (:55).
- Overlap with R5 is not suppressed: a member with no span and no eligible row gets MEMBER_NOT_ENROLLED and PROGRAM_NOT_ELIGIBLE (:56).
- For CAP_820 the date is the period start; no plan test (:37-38).
- The rule-table docstring (Rules/Spec.lean:389-391) adds "eligibility 7 days, a placeholder (localBCE's O1 TTL is 24 hours)" (decision 7).

### 3.4 Review

- `review` (Rules/Spec.lean:422-427) gains `| .BENEFIT_LEVEL_MISSING_UNVERIFIED | .PROGRAM_NOT_ELIGIBLE_UNVERIFIED | .STALE_ELIGIBILITY => true`.
- October put this arm first only to keep the Python mutants' anchor verbatim (f16a61f4:docs/integration/G2_DESIGN.md:111). The trunk does not port those mutants (plan decision 7), so the arm goes as its own line before `| _ => false` (decision 5).
- `outcomeOf` (:430-431) is unchanged: a certain code means HOLD.

### 3.5 Bypassable

- `bypassable` (Rules/Spec.lean:168-173) gains STALE_ELIGIBILITY, PROGRAM_NOT_ELIGIBLE_UNVERIFIED and BENEFIT_LEVEL_MISSING_UNVERIFIED (plan decision 12, TRUNK_MIGRATION_PLAN.md:458). The certain codes are not added.
- October had no `bypassable`; there is nothing to port and nothing October left open.
- The docstring (:166-167) says every other reason "guards the release-once rule or is malformed input". With G2 that is false: the two certain codes are deliberately not bypassable but are neither. New text: "Every other reason guards the release-once rule, is malformed input, or is a certain eligibility finding that must be fixed at the source (decision 12); a new reason is not bypassable until listed here."

### 3.6 Runner guards (Rules/Run.lean)

After the name-order `#guard` at Run.lean:47, from f16a61f4:.../Rules/Run.lean:51-55:

```lean
#guard allowedAid == ["13", "23", "53", "103", "104"].map aidId
#guard reasons.all fun r => review r || !((name r).endsWith "_UNVERIFIED" || (name r).startsWith "STALE_")
```

The second cannot live in Rules/Spec: `name` is defined in Run (Run.lean:43), and Run imports Spec (plan :294). Today's 24 reasons satisfy it: every `_UNVERIFIED` and `STALE_` code is listed in `review` (Rules/Spec.lean:423-426).

### 3.7 Differences from October

| | October f16a61f4 | Trunk |
|---|---|---|
| Reason order | inserted by name, no idx | appended constructors, idx 24-28 |
| `bypassable` | absent | three review codes added (decision 12) |
| `review` arm | first, for Python mutants | own line before the wildcard |
| Row numerals | `String.toNat?` | trunk `nat?` (Run.lean:197), which refuses `_` |
| Read set | READ-SET/v3, READ-MANIFEST/v3 | READ-SET/v5 only; no READ-MANIFEST change (plan :319-321) |
| StateV2, ReadManifest, Resident | changed | absent on the trunk; dropped (4.10) |
| Python mutants | 19 in gate_rules_mutants.py | in-Lean `Mutant:` defs (plan decision 7) |
| Host | `_reads_ok` 264 to 328 bytes | `REASONS`/`REASON_IDX`, cause_actions; feed is step 2's |
| Contract | v1 RETIRED but files kept | v1 files and lines deleted (README rule 3), with a frozen copy outside `rightrail/` |
| Engine | no Flat/Engine3 decider | Flat, DecideRows and Engine3 twins (section 4) |

The owner approved "the twelve defaults" on 2026-11-09 (b5f806df:docs/integration/LOG.md:237-238), but G2_DESIGN.md has no numbered list of twelve. This design keeps every rule default of f16a61f4:docs/integration/G2_DESIGN.md:33-56 and lists each trunk departure above.

## 4. Lean changes, in build-dependency order

"Pin" means the `gate_engine` closure (Rules/{Fast, FastEq, Request, Run, Spec, Theorems}, Flat/{Bin, Chunk, ChunkIo, ChunkTheorems, Io, Model, Store, StoreLog, StoreTheorems, StoreTombs, Theorems, Worker}, Frame/{Spec, Fast}, Authority; TRUNK_STEP2_FRAME_DESIGN.md:185-187). Flat/Signed, Scoped and Consume are outside it: they are imported only by rightrail/lean/BlindLedger.lean:12, :14, :15, rightrail/lean/BlindLedger/Gate/AxiomCheck.lean:16, :17, :25, and each other (Flat/Signed.lean:1, Consume.lean:1). They are in the default build and statement-pinned (STMT_PIN), which is a different pin. (a), (b) as in section 1.

### 4.1 Rules/Spec.lean (pin; (a))

- Section 3.1-3.5: constructors, `reasons`, idx, `Ctx.eligibility`, `okElig`, the G2 helpers, five `fires` arms, `review`, `bypassable` and their docstrings.
- Module docstring: a G2 bullet after the R5 bullet (:30), "R1, R3, R5, G2" in the usable-snapshot sentence (:45-46), the malformed-row list (:56), the `_UNVERIFIED` sentence (:60), as f16a61f4 did.
- Every `Ctx` literal names `eligibility` (decision 3):
  - Run.lean:317 (`St.ctx`, `eligibility := p.elig.map (·.1)`);
  - Rules/DecideLayer.lean:175-176 and Flat/DecideBench.lean:570: `eligibility := none` (test and layer code);
  - Scoped.lean:477-480, the test fixture `vBase` (next to `vE6` and `vL`, not the signed path): `eligibility := none` (4.6b);
  - Frame/Spec.lean:326-330 and Flat/Worker.lean:257-260: `eligibility := none` in WIP; the kind-7 snap in (b).
  - `{ c with ... }` updates carry it unchanged: Rules/Spec.lean:585-586 (`carried`, as October noted, f16a61f4:docs/integration/G2_DESIGN.md:114), Anchor.lean:43, :51, AnchorTheorems.lean:77-85.
  - The signed decision contexts Scoped `kRules` (:68-74) and `Ctx.plain` (:92-97) are `{ base with ... }` updates too, so today they would carry the caller's unsigned `base.eligibility`. They gain `eligibility := none` (4.6a, decision 15).

### 4.2 Rules/Run.lean (pin; (a))

- Doc (:15-24): add `elig` with rows `MEMBER AID LEVEL START STOP`.
- `Pinned` (:117-124): add `elig : Option (Snapshot Elig × List UInt8)`; docstring "five kinds".
- `St.pin` (:241-254): `let elig := snapshot st "elig" (fun r => match r.mapM nat? with | some [m, a, v, s, t] => some ⟨m, a, v, s, t⟩ | _ => none) "RR/GATE/SNAPSHOT/v1" 7 Elig.fields`, and a fifth `← readPin "RR/GATE/READ-ELIGIBILITY/v2" 7 Elig.fields elig` in `kinds`.
- `St.ctx` (:308-319): `eligibility`.
- `reads` (:598-604): tag `RR/GATE/READ-SET/v5`; five slots follow from `kinds`. Fix the docstring ("five pins") and the stale ReadManifest citations at :9 and :599 (`ReadManifest.run_reads_eq`) and :232 (`ReadManifest.kindOf`): no ReadManifest module exists on the trunk (decision 19).
- Row whitelist (:705): add `"elig"`.
- The two guards of 3.6.
- `factsDigest` (:256-260) has no caller (TRUNK_MIGRATION_PLAN.md:436). Leave it at four pins and record it (decision 16).
- Every Spec, Fast or Run edit changes `RULES_SOURCE` (rightrail/tests/test_gate_rules_vectors.py:16-21).

### 4.3 Rules/Theorems.lean (pin; (a))

Statement changes (XI.2, section 9):
- `AidEligible`/`LevelEligible` abbrevs and five `Fact` arms (:94-124), from f16a61f4:.../Rules/Theorems.lean:36-48 and the `_UNVERIFIED`/stale twins. `sound`, `complete` and `hold_complete` then cover G2.
- `fires_iff` (:138-140): simp set gains `aidEligible`, `levelEligible`, `eligCovers`.
- `Grows` (:751-765) gains `eligibility : c'.eligibility = c.eligibility`. This strengthens `monotone`'s hypothesis: an added eligibility row can clear PROGRAM_NOT_ELIGIBLE, so eligibility must be equal, not grown. Its docstring (:747-750) adds "eligibility" to the equal fields and the sentence "Eligibility must be equal, not grown: an added eligibility row can clear `PROGRAM_NOT_ELIGIBLE`", as f16a61f4:.../Rules/Theorems.lean:603-607 did.
- `fact_mono` (:789-817): five arms, `simpa [Fact, AidEligible, LevelEligible, g.today, g.eligibility]`.
- `fail_closed` (:398-412): statement byte-identical; docstring notes the seventh source.

New theorems, from f16a61f4:.../Rules/Theorems.lean:283-316, with in-file axiom pins next to the existing ones at :1012-1019 and lines in tools/gate_print_axioms.lean, Gate/AxiomCheck.lean and Gate/AXIOMS.txt:
- `fail_closed_eligibility` (October axioms [propext, Quot.sound]);
- `g2_review` (by `decide`, [propext]);
- `g2_exclusive` (no axioms);
- `g2_hold_usable` (no axioms);
- `g2_allow` ([propext, Classical.choice, Quot.sound]).

The bound (built WIP; re-pinned here):
- `Bits` (:317-322) gains `el : Bool`; the docstring (:314-316) already says "G2 adds `el`".
- `bitsOf` (:325-327) gains `usable c.today 7 okElig c.eligibility`.
- `may` (:333-345) gains `| .BENEFIT_LEVEL_MISSING | .PROGRAM_NOT_ELIGIBLE => b.el` and `| .BENEFIT_LEVEL_MISSING_UNVERIFIED | .PROGRAM_NOT_ELIGIBLE_UNVERIFIED | .STALE_ELIGIBILITY => !b.el`.
- `may_sound` (:348-350): the simp set gains `okElig`, `aidEligible`, `levelEligible` if `cases r <;> simp +contextual` does not close as is.
- `budget_bool` (:353-354) and `budget` (:357-358): five Bool binders; the bound stays 32.
- Headroom pins (:369-382). Today: 12 always-possible codes (:334-337), 8 `_UNVERIFIED`/`STALE_` codes, 4 certain codes, so all-false 20 and all-true 16. With G2:

  | Pin | Today | After G2 |
  |---|---|---|
  | `headroom_le` (max over all tuples) | ≤ 20 | ≤ 23 |
  | `headroom_eq` (all false) | 20 | 23 = 12 + 11 |
  | `headroom_all` (all true) | 16 | 18 = 12 + 6 |

  Counted by hand from `may`; each is closed by `decide +kernel`, which is the check. The comment at :369-374 is updated. Headroom left for steps 4-5: 32 - 23 = 9.

### 4.4 Rules/Fast.lean and Rules/FastEq.lean (pin; (a))

- Fast: `Ix` (:64-95) gains `eligSome`, `eligOk`, `elig : HashMap Nat (List Elig)`; `Ix.build` (:98-115) sets `elig := group (·.member) (entries c.eligibility)`; `Ix.aidEligible`/`Ix.levelEligible` look up `x.elig.getD l.member`; five `Ix.fires` arms (:165-190). Port of the f16a61f4 Fast diff.
- FastEq: `eligCovers_member`, `build_elig`, `aidEligible_eq`, `levelEligible_eq`, `build_eligOk`, `build_eligSome`; extend the `fires_eq` simp list (:500-505). `decideLine_eq` and `decideBatchFIn_eq` keep their statements. October's delta was about 29 lines.

### 4.5 Flat/Model.lean (pin; (a); statement-pinned)

- `Feeds` (:232-244) gains `eligSome`, `eligOk`, `elig : Nat → List Elig` (STMT_PIN.txt:3137-3150).
- `FCtxInv` (:256-265) gains, appended at the END: `eligSome = c.eligibility.isSome ∧ eligOk = usable c.today 7 okElig c.eligibility ∧ ∀ i, elig i = (entries c.eligibility).filter (·.member == i)` (STMT_PIN.txt:3118). What appending keeps and what it does not (decision 14):
  - Kept: the positional `obtain`s whose last pattern is `-` (Flat/Theorems.lean:742, :748, :754, :760, :926 `byp_loc`, :1042; PayTheorems.lean:682), since a trailing `-` absorbs the appended conjuncts. PayTheorems.lean:877 (`feedBits_inv`) also still elaborates, but is extended to bind the new `eligOk` conjunct (4.6).
  - Breaks: Flat/Theorems.lean:929-931 `lim_loc`, whose pattern ends `-, h⟩` and binds the LAST conjunct `fc.lim = c.lim` (Flat/Model.lean:265). After appending, `h` is `fc.lim = c.lim ∧ ...` and `exact h` fails. The pattern becomes `..., h, -⟩` (17 entries).
  - Breaks: every exact anonymous-constructor proof of `FCtxInv` (16 entries today) needs three more entries: Frame/Spec.lean:344-346 `fcOf_inv` (`rfl, rfl, fun _ => rfl`), PayTheorems.lean:29-33 `feedsOf_inv` (`rfl, rfl, group_getD ...`) and Flat/Signed.lean:151-152 `specFeeds_inv` (`rfl, rfl, fun _ => rfl`). All three are in (a), next to the `FCtxInv` change.
- `localIx` (:338-348) sets the three fields (STMT_PIN.txt:3523).
- `feedCapped` (:356-358) adds `feedOver (fd.elig l.member)`: the 1,024-fact cap step 2 deferred, a new POSTING_CAP source (decision 13; STMT_PIN.txt:3504).
- `work` (:415-417) adds a `factWork fd.elig (members b)` term (STMT_PIN.txt:3562); `workC` (:421) grows by one feed id per line (STMT_PIN.txt:3563); `work_le` moves (STMT_PIN.txt:3564).
- Statement pins that move with this design, in all (STMT_PIN.txt lines; each regenerated in 4.10):
  - Rules: `Ctx` :4409, `Reason.idx` :4538, `bypassable` :4699, `fires` :4727, `reasons` :4778, `review` :4784;
  - Authority: `reasonMask` :2335;
  - Flat: `FCtxInv` :3118, `Feeds` :3137 and its fields :3139-3150, `Feeds.Same` :3138, `feedCapped` :3504, `localIx` :3523, `signedFeeds` :3548, `work` :3562, `workC` :3563, `work_le` :3564;
  - Frame: `ctxOf` :3690, `feedsOf` :3747;
  - Scoped: `Ctx.plain` :4808, `kRules` :4834 (4.6a).

### 4.6 Flat/Theorems.lean, Flat/PayTheorems.lean, Flat/Signed.lean, Scoped.lean, Consume.lean ((a))

- Flat/Theorems (pin): `unc_feed` (:622-629) gets a 7th conjunct; add `elig_get`, `aidEligible_loc`, `levelEligible_loc` (modelled on `dmf_get`, :739-762); `fires_loc` (:1006-1053) gets the elig flags and the two `_loc` rewrites; `lim_loc` (:929-931) its pattern (4.5); `work_le` (:1608-1629) gets the new term. `decideBatchIdx_eq` (STMT_PIN.txt:3486) keeps its statement; its proof is re-checked.
- PayTheorems (outside the pin): `feedsOf_inv` (:29-33) gains three tuple entries, one a `group_getD` over the eligibility rows; `codes_le` (`cases y <;> decide`, :110) grows by five cases; `part_feed` (:410-417) a 7th conjunct; `fires_part` (:641-693) the `_loc` rewrites; `feedBits`/`ixBits` (:869, :872) add `eligOk`; `feedBits_inv` (:876-878) binds the new conjunct. `ix_may_sound`, `decideFetched_may` and `pay_codes_le_all` (:881-930) keep their statements.

#### 4.6a The signed path reads no eligibility (outside the pin; statement-pinned)

- The problem. `Scoped.kRules` (Scoped.lean:68-74) and `Ctx.plain` (:92-97) are `{ base with ... }`, and `Consume.decideSigned` decides on `(b.ctx base).rules` with `base : Rules.Ctx` a parameter (Consume.lean:77-84). Once `Ctx` has `eligibility`, the caller's unsigned `base.eligibility` would reach K3's decision. A usable one would let a line ALLOW on unsigned eligibility, while the MONEY theorem `allow_signed` (Consume.lean:299-314) names only the four signed kinds. And `Flat/Signed.decideSignedIdx_eq` (Flat/Signed.lean:326-343), which holds for any `c`, equates `signedFeeds` with `specFeeds` of that same `rules` through `same_all`/`fetched_feeds`: with eligibility absent on the `signedFeeds` side and `c.eligibility` passed through on the other, `Feeds.Same` fails whenever `c.eligibility` is `some`. So changing `signedFeeds` alone does not build.
- The fix (decision 15). `kRules` and `Ctx.plain` gain `eligibility := none`, so K3 never reads the base's eligibility. Both definitions are statement-pinned (STMT_PIN.txt:4834, :4808). The statements of Scoped's `STMT-CHANGE r2` theorems `allow_live` (:285-290), `allow_tightens` (:302-304) and `allow_attached` (:440-446) and of `Consume.allow_signed` keep their text. Their proofs are re-checked: an ALLOW is now impossible on the signed path (STALE_ELIGIBILITY always fires), and `allow_tightens`' field-by-field proof gains the eligibility field, equal on both sides by the new `:= none`. The theorems hold vacuously until the signed path is extended (plan decision 5).
- Flat/Signed: `signedFeeds` (:111-118) sets eligibility absent (`eligSome := false`, `eligOk := false`, `elig := fun _ => []`). `Feeds.Same` (:127-133), `specFeeds` (:142-149), `specFeeds_inv` (:151-152, three more tuple entries), `over_same`/`uncapped_same` (:164-176) gain the fifth feed. With `kRules` reading none, `specFeeds ((readAll ...).ctx c).rules` has eligibility absent too, so `same_all` and `decideSignedIdx_eq` (:326-343) re-prove with no statement change.
- Rejected alternative: a `c.eligibility = none` hypothesis on `decideSignedIdx_eq`. It is a recorded statement change and leaves `Consume.decideSigned` able to ALLOW on unsigned eligibility.
- Consequence: every signed-path line gets STALE_ELIGIBILITY and so HUMAN_REVIEW. Plan :340 does not record this.

#### 4.6b Signed-path guard fallout

Every guard that asserts ALLOW or an exact reason list on the signed path changes, because STALE_ELIGIBILITY is now in every decision there. The fixture `vBase` (Scoped.lean:477-480) gains `eligibility := none`, so v1's read (`vV1`, `{ vBase with ... }`, :491-494) and K3's read (`vDec`) both carry STALE_ELIGIBILITY and stay comparable.

- Scoped.lean, ALLOW asserts: :520, :526, :532, :535, :537. Each becomes `reasons == [Reason.STALE_ELIGIBILITY]` (HUMAN_REVIEW). A decision whose only reason is STALE_ELIGIBILITY says every other rule was silent, which is what the ALLOW asserted about R1-R5. :532's `vDec vC == vV1 vC` keeps its text and still holds. :520/:535/:537 keep their meaning ("v1 is silent, K3 reviews") as v1 `[STALE_ELIGIBILITY]` against K3 with its STALE reason added.
- Scoped.lean, exact reason lists: :521, :538, :539, :542, :543-544, :546, :553-554, :555-557 each gain `Reason.STALE_ELIGIBILITY` in name order (after STALE_DMF, before STALE_ENROLLMENT/STALE_EXCLUSION). :545 (HUMAN_REVIEW) and :547 (HOLD) hold as they are: MEMBER_NOT_ENROLLED is certain, and PROGRAM_NOT_ELIGIBLE cannot fire on absent eligibility.
- Consume.lean:425 `== [.ALLOW]` becomes `== [.HUMAN_REVIEW]` with a reasons check `[STALE_ELIGIBILITY]`. The never-ALLOW helper (:417-419) and its users (:432-450) keep their text.
- Flat/Signed.lean:385 `== [(.ALLOW, [])]` becomes `== [(.HUMAN_REVIEW, [.STALE_ELIGIBILITY])]`.
- Mutant-kill evidence (Flat/Signed.lean:360-362). "`Ok` ignoring `counted`" is still killed by :390's `reasons.contains .STALE_DMF` (the mutant drops STALE_DMF); its `outcome != .ALLOW` half becomes trivially true. The short-count mutant is still killed by :394 (`contains .STALE_DMF`). The `take capN` mutant is killed by the 1,025-fact vector through `vSame`, which compares the feed read with the row read and does not depend on ALLOW; this is re-checked when the guards are rebuilt. What is lost: no signed-path vector exercises an ALLOW, so the ALLOW path itself has no vector until the signed path is extended. Recorded in section 9 field 8.
- Amendment (stage 2, approved by the owner 2026-11-17, "Approve, start stage 3"; to record with the plan corrections of decision 23). Three guards outside the list above were changed, each stronger than the one it replaces: Scoped.lean HEAD :536 (K3 on an ENR enrollment fact) keeps HUMAN_REVIEW and adds `reasons == [STALE_ELIGIBILITY, STALE_ENROLLMENT]`; HEAD :634-635 (the attached `vCtx` ALLOW) becomes `reasons == [STALE_ELIGIBILITY]`; HEAD :636 (another batch keyset digest, "none counts") keeps HUMAN_REVIEW and adds that the reasons contain all four of STALE_DMF, STALE_PROVIDER_DEATH, STALE_EXCLUSION and STALE_ENROLLMENT.

### 4.7 Frame/Spec.lean and Flat/Worker.lean (pin)

- (a) Worker `feedsOf` (:83-93) and Frame/Spec `feedsOf` (:332-339): the eligibility map and flags, generic over `Ctx`. Frame/Spec `fcOf_inv` (:344-346): three more tuple entries (`rfl`, `rfl`, `fun _ => rfl`), which hold with `eligibility := none` in `ctxOf`.
- (a) Frame/Spec `ctxOf` (:326-330) and Worker `commitBin` (:253-260): `eligibility := none` (4.1).
- (b) Frame/Spec `ctxOf`: `eligibility := snap H 7 Elig.fields q.elig`. Needs `Req.elig` from step 2. `fcOf_inv` stays `rfl` per entry.
- (b) Worker `commitBin`: `let el := snapF 7 Elig.fields q.elig` and `eligibility := el.map (·.1)`. Needs `Frame.Req.elig`.

### 4.8 Flat/DecideRows, DecideCut, RowsBudget, PayNumbering, DecideBench (outside the pin; `gate_hist3`/`gate_verify3`; (a))

- DecideRows:
  - An `EligF` fact `{mOk, aidOk := allowedAid.contains e.aid, level, start, stop}` so the scan stays word-only like `SpanF` (decision 18).
  - `LineIn` (:61) gains `elig : Rg`; `Lay` (:76) gains `eligSome`, `eligOk`, `eligs : Array EligF`; one more `readFacts` in the layout loop (:182-207).
  - Bits `bBenMiss`, `bBenMissU`, `bProgNE`, `bProgNEU`, `bStaleElig`; `aidIn`/`levelIn` range scans like `enrolledIn` (:268-273).
  - Five terms in `base` (:356-363) AND, textually identical, in `baseOf` (:1991-2006): `on (x.eligOk && v && aid && !lvl) bBenMiss | on (x.eligSome && !x.eligOk && v && aid && !lvl) bBenMissU | on (x.eligOk && v && !aid) bProgNE | on (x.eligSome && !x.eligOk && v && !aid) bProgNEU | on (!x.eligOk) bStaleElig`; `|| li.elig.over` in `fcap` (:364). Keep the 5-array per-line tuple so `forIn_push5` and `hF1` (:4649-4677) keep their shape.
  - `Rep.feeds`/`Rep.flags` (:540-571), `LineOk`/`Inv3`/`Inv3_step` (:927-1000), `layout_rep` (from :1069): the new slice and flags. The costliest layout work.
  - `loc_elig`, `aid_line`, `level_line`, `aidIn_eq` (like `enrolledIn_eq`), `locIx_eligOk`/`locIx_eligSome`; `base_has` (:2066) simp set; `fcap_line` (:2087) from 6 to 7 Bools (64 to 128 cases).
  - `mask_has` (:3015, `cases cp <;> cases r` with `grind`) and `line_dec` (`cases r`, :3398) grow with the reasons; `decideRows_both` (:4644, already `maxHeartbeats 4000000` at :4640) re-runs.
  - **Remove** the step 2 `#guard reasons.zipIdx.all fun (r, i) => r.idx == i` (:1671-1672), whose comment says it is expected to fail at step 3: BENEFIT_LEVEL_MISSING sorts second but has idx 24.
  - Unchanged in text: `reasons_len_le32` (:1604, 29 ≤ 32), `idx_lt32` (:1606), `Lo`, `has_maskOf`, `outOf_eq`. The line mask stays UInt32.
- DecideCut: `Cut` (:56-76) gains `eligSome`, `eligOk`, `eligs`; the `decideRows_cut` simp list (:567-568) gains them.
- RowsBudget: no proof change beyond the `feedBits` field; the module text "`reasons` has 24 members" (:14) becomes 29, and the `rows_leaf_le` docstring "with 24 reasons this does not yet constrain anything" (:85-86) becomes 29.
- PayNumbering: generic in reasons; re-check only.
- DecideBench (test exe): every `Feeds`/`LineIn` literal (:156-160, :364-365, :404-407, :842, :915) and a random elig feed generator, so `decide_bench check` exercises the G2 bits. The random grant-hold and bypass masks, today capped at 2^24 (:122 `x / 7 % 2 ^ 24`; :142 `2 ^ 24 - 1` and `x % 2 ^ 24`), widen to `2 ^ Rules.reasons.length`, so the bench also exercises a bypass or HOLD-level lift over bits 25, 27 and 28.

### 4.9 Engine3 (outside the pin)

- (a) RowsStore `FeedsX` (:342-346) gains `el : FeedIx EligF`; `assemble` (:424-432) sets `elig`, `eligSome`, `eligOk`, `eligs`. Adding the field breaks the two places that build a `FeedsX` by anonymous constructor, `FeedsX.decode` (`pure ⟨dmf, pd, ex, sp⟩`, RowsStore.lean:370) and ReadB `feedsW` (ReadB.lean:114-123), so both gain, in (a), an absent-feed placeholder for `el` of the `none_` form (present = false, ReadB.lean:87). With it Engine3 decides STALE_ELIGIBILITY on every line until (b). `reasonTab`/`leafBits` (Step.lean:72-84) need no change: `Rows.bit` stays UInt32 and bits 24-28 fit.
- (b) The real fifth source in `FeedsX.decode` (RowsStore.lean:350-370), stride 62 on Route A (TRUNK_STEP2_FRAME_DESIGN.md:49) unless rr-core's v2 specifies another layout; ReadB `feedsW` (ReadB.lean:103-123) a fifth `feedW` with its offset, `maxAge` 7 and `okElig`; `feedPins`/`feedAt`/`snapK` (Step.lean:326-347); StepH (:117-132) and Verify (:206-220) loop over 5 and pass a 5-tuple `pres` to `Hist.read`/`VMirror.read`.

### 4.10 Authority, pins, and what is dropped

- Authority.lean:19-20 (pin): `reasonMask := 2 ^ 29`, docstring "the 29 reasons use bits 0..28". `holds` and overrides are read with `nat 4` (:89, :107), so 29 bits fit. APPROVAL/v2 is widened in place (plan decision 10).
- AuthorityLaws.lean: `reasonMask_eq` (:25) becomes `536870912`; its `omega` users (:71, :109, :176, :207) re-check. The guard `reasonMask == 2 ^ Rules.reasons.length` (:477) is what catches a missed Authority edit. The bypassable count (:478) goes from 15 to 18. :475 holds (idx fixed). :491 needs no change; it now tests bit 29.
- rightrail/lean/BlindLedger/Gate/AXIOMS.txt, rightrail/lean/BlindLedger/Gate/AxiomCheck.lean and rightrail/tools/gate_print_axioms.lean: entries for the five new theorems. Decision 17 also adds the Rules-level bound theorems `may_sound`, `decideAll_may`, `budget`, `pay_budget` to all three: today the tool prints only the Flat, Rows and PayNum bound theorems (gate_print_axioms.lean:330-366), while the Rules ones already carry in-file `#guard_msgs in #print axioms` pins (Rules/Theorems.lean:1012-1019).
- STMT_PIN regen after the three builds; the entries that move are listed in 4.5.
- Dropped, with no trunk home: StateV2 `pm_fires` h8, `g1_reasons_pw` and the READ-SET/v3 `readSetOf` (f16a61f4:rightrail/lean/BlindLedger/Gate/StateV2.lean:6225-6236, :6689, :6721-6732); ReadManifest v3 (f16a61f4:.../ReadManifest.lean:20, :121, :183-306); Resident refresh (f16a61f4:.../Rules/Resident.lean:137-143, :384). The trunk's name order is the Run `#guard` (:47) and the payment bound needs no injectivity (Status).

### 4.11 What moves which pin

- `gate_engine`: Rules/Spec, Run, Theorems, Fast, FastEq; Flat/Model, Theorems, Worker; Frame/Spec; Authority. Run's digest moves too.
- `gate_hist3`/`gate_verify3`: DecideRows and Engine3, in step with `gate_engine`.
- No executable pin, but the default build, STMT_PIN and AXIOMS: Flat/Signed, Scoped, Consume (4.6a, 4.6b).
- `gate_verify`: no Rules, Frame, Flat or Engine3 import (TRUNK_STEP2_FRAME_DESIGN.md:190); does not move.

## 5. Host, runner and tables

- `REASONS` (rightrail/app/right_rail_gate_decide.py:477-481): insert the five names in byte order as in 3.1 (checked at rightrail/tests/test_gate_answer_v3.py:62). List positions shift; answer bits do not.
- `REASON_IDX` (:484-491): add 24-28. The import-time assert (:491) then holds at 29.
- `LEAF_ONLY` and `RULE_MASK` (:492-493): no text change; `RULE_MASK` becomes 2^29-1. `_names` (:555-561) and the record and leaf checks (:660, :672) accept bits 24-28 with no code change.
- Host feed (:497, :508-520, :523-535, :564-571): step 2's. Note for step 2: `feed()` numbers a kind by its position plus one (:518), so appending `"elig"` would pin kind 5, not 7. The request side needs an explicit kind map.
- `app/cause_actions.json` (rows in byte order; ALREADY_DECIDED :2, POSTING_CAP :13, PROVIDER_DECEASED :14, STALE_ENROLLMENT :22): five rows, `emitters ["gate_rules"]`, kind `data`. Draft wording for approval (decision 22); each meaning and action ends with "." and avoids " or ", "; " and "investigate" (rightrail/tests/test_cause_actions.py:158-161):
  - BENEFIT_LEVEL_MISSING (after :2): "The eligibility file shows an allowed aid code for the member on the service date, but no row with that aid code has a benefit level." / "Hold payment until the source confirms the member's benefit level."
  - BENEFIT_LEVEL_MISSING_UNVERIFIED (after :2): "The eligibility file cannot be used, and the rows it has show no benefit level for the member on the service date." / "Load a current eligibility file and decide the line again."
  - PROGRAM_NOT_ELIGIBLE (after :13): "The eligibility file shows no allowed aid code for the member on the service date." / "Hold payment until the source corrects the member's aid code."
  - PROGRAM_NOT_ELIGIBLE_UNVERIFIED (after :13): "The eligibility file cannot be used, and the rows it has show no allowed aid code for the member on the service date." / "Load a current eligibility file and decide the line again."
  - STALE_ELIGIBILITY (before :22): "The eligibility file is missing, too old, or cannot be used, so eligibility checks could not be made." / "Load a current eligibility file." (The meaning's "too old, or" contains " or "; that rule applies to actions only, test :160-161.)
- `tools/gate_rules_data.py`: `KINDS` (:14) appends `"elig"` last, so kind 7 by position (`pin` uses `KINDS.index + 1`); `WIDTHS` (:18-19) adds `"elig": (ID, ID, 1, 4, 4)`. The demo generator was deleted (:7-8), so demo_zz_v2 needs another method (decision 10).
- `tests/test_gate_rules_vectors.py`: run `rules_v2.vectors`, `demo_zz_v2.vectors`, `shards_v1.vectors` (:83); READ-SET/v5 at :144 and :177; add `("elig", 7, "ELIGIBILITY", None, None)` to the kinds (:162-165). `PROOFS` (:23-25) does not list PayTheorems, RowsBudget, PayNumbering or DecideRows, so `test_proofs_are_current` cannot see them go stale (decision 17).
- Tags: READ-SET/v5 new (skips October's v3 and v4); READ-ELIGIBILITY/v2 and SNAPSHOT/v1 kind 7 kept; no READ-MANIFEST or SNAPSHOT/v3 change (plan :318-321).
- Embedded files (plan :337): G2 adds no file that `RulesMain` embeds with `include_str`; it edits files already declared as `input_file`s (rightrail/lean/lakefile.toml:144-151 and the entries from :153). So no `input_file` entry is added, and `test_every_embedded_file_rebuilds_the_runner` (rightrail/tests/test_gate_rules_vectors.py:49-67) is the check. If the in-Lean mutant module or anything else becomes embedded, it gets an entry.
- Docs inside the trunk (plan :341): rightrail/STATUS.md, edited once for this merge, replacing what it supersedes (rightrail/AGENTS.md:20): G2 as a gate rule, 29 reasons, Gate rules v2, the signed path at HUMAN_REVIEW on STALE_ELIGIBILITY. rightrail/ARCHITECTURE.md: the eligibility feed (kind 7) in the rules layer and the fifth Engine3 feed. Both are in the XI.2 scope (section 9 field 7).

## 6. Contract and vectors

- **GATE_RULES_V2** (plan decision 11): a new `conformance/GATE_RULES_V2.md` written from GATE_RULES_V1.md (which is immutable, MANIFEST.sha256:9): kind 7 in the grammar and kinds list; the elig row encoding (member 129, aid 129, level 1, start 4, stop 4); 7-day maximum age with the `okElig` row check; `allowedAid`; five rules-table rows; READ-SET/v5. A `gate_rules_v2_ref.py` written from the page alone, and `tests/test_gate_rules_v2_spec.py`. Covers G2 now and is extended in place at step 4 if nothing is published between.
- **Vectors**:
  - `rules_v2.vectors`: trunk `rules_v1.vectors` plus a head elig block (October: 10 rows, aid 78131, level 1, 19000101-99991231, f16a61f4:rightrail/tests/gate_rules/rules_v2.vectors:29), STALE_ELIGIBILITY on the invalid-today case (:625), the G2 cases (:1017-1129: aid and level, encoding, payment, age 7/8, future asOf, count mismatch, empty, bad level, reversed row, missing, bad pin, line dates), re-pinned with `gate_rules_data.py` and `end` recounted. Trunk v1 has POSTING_CAP-era content, so the base is the trunk file, not October's.
  - `demo_zz_v2.vectors`: `demo_zz.vectors` plus one fixed elig row per member (October: `elig {m} 78131 1 19000101 99991231`, never drawn from the RNG). With those rows G2 never fires, so every existing expectation stays.
  - `rules_v2_negative.vectors` and `.expected` from the exe.
  - `shards_v1.vectors` has no manifest line; it gains the elig head block in place, as October did. Its header also feeds `_gate_shards.HEAD` (rightrail/tests/_gate_shards.py:33-37), which matters only once the frame carries the feed.
- **Retire v1** (README rule 3, rightrail/conformance/README.md:63-67 "Retiring a version deletes its vector files and manifest lines"): delete `rules_v1.vectors`, `demo_zz.vectors`, `rules_v1_negative.vectors`/`.expected` (MANIFEST.sha256:1-2, :11-12), mark v1 RETIRED with its date in README.md:23-29. `test_conformance_manifest` requires every file under `conformance/` to be pinned, so GATE_RULES_V1.md and `gate_rules_v1_ref.py` (MANIFEST.sha256:9-10) are deleted too (decision 9), and `test_gate_rules_v1_spec.py` with them.
- **Fallout of retiring v1**, not in the plan:
  - `gate_rules_v1_ref.pin_bytes` imported by test_gate_authority_frames.py:20, test_right_rail_gate_ffs.py:21 and _gate_shards.py:25: switch to `gate_rules_v2_ref.pin_bytes` (kinds 1-4 pins unchanged).
  - `rules_v1.vectors` read by test_right_rail_gate_formats.py:32, test_gate_producer_design.py:14 and engine3_compare.py:259-262: point at `rules_v2.vectors`.
- **MANIFEST.sha256**: add lines for the v2 vectors, negative vectors and expected, GATE_RULES_V2.md and gate_rules_v2_ref.py; remove the v1 lines.
- **Parity harness (plan decision 13)**: before deleting, copy `rules_v1.vectors` to `tests/fixtures/rightrail_rules_v1.vectors` with a sidecar recording the source path, trunk fc89f9e5 and SHA-256 `15aef4c9e742d12052c1574d4eabdce6435810f0de63e5167a41db32e1ab8d2a` (MANIFEST.sha256:1). Repoint `DEFAULT_VECTORS` (scripts/g_rule_parity.py:35) and its docstring. G2 stays an always-passing gate in the harness (decision 20).
- **Answer-bit tests**: test_gate_answer_v3.py `RULE_MASK == 2**24 - 1` (:63) becomes `2**29 - 1`; the "record bit 24" and "leaf bit 24" rejects (:87, :90) move to bit 29, with bit-28 accept cases added (plan :312). gate_v1.vectors' `leaf-reason-bit-24` must-reject (test_right_rail_gate_formats.py:313) becomes legal and moves to bit 29; regenerating gate_v1.vectors signs through `det_sign` and needs the signer (decision 11). Amended by the owner 2026-11-19 (decision 11): the case is now `leaf-reason-bit-29`, its answer line rewritten signer-free with `--signer-free` (one byte, `end 303` unchanged); bit 29 is the first bit beyond idx 0-28 and below the leaf-only 62/63. No record-bit-24 case exists in gate_v1.vectors.
- **Bypass bits by position**: test_right_rail_gate_ffs.py:674 and test_engine3_redo_cut.py:25 build `1 << decider.REASONS.index("FFS_NEAR_DUPLICATE")`. After G2 the index is 8 (MEMBER_DECEASED_UNVERIFIED's idx) while the idx stays 6. Change both to `decider.REASON_IDX[...]`.

## 7. Evidence and checks

### 7.1 Mutants (plan decision 7)

A module outside the `gate_engine` closure (trunk style, AuthorityLaws.lean:494-506), with `Mutant:` defs and killing `#guard` pairs:

- G2_SPEC (f16a61f4:rightrail/tools/gate_rules_mutants.py:326-332): any member; row start exclusive; row stop exclusive; level unchecked (`okElig`); row order unchecked (`okElig`). Killed on `eligCovers`/`okElig` and on `fires` over a small `Ctx`.
- G2_FAST (:333-354): program off; benefit level off; program on an unusable snapshot; benefit level on an unusable snapshot; program unverified off; benefit level unverified off; staleness off; pairing broken; any nonzero level; benefit level without an allowed aid; 6 days; 8 days; usability read from enrollment; rows unread. Killed on `Ix.fires` over `Ix.build` of a small `Ctx`.
- `allowedAid` and `review` membership stay `#guard`-checked in Run (3.6), as October chose (:322-324).
- **The proof-killed mutant.** October killed 18 by vectors and 1 by proof (b5f806df:docs/integration/LOG.md:245); no record names it. The likely one is "G2 any member": Fast looks rows up by member, so the runner's output does not change, and FastEq `eligCovers_member` fails to build. This is an inference, unverified. As plan :333 and decision 7 (:453) require, it is killed by a one-off scratch-copy build of the trunk tree with G2 (not of f16a61f4), under the guard: apply the mutant to Spec `eligCovers`, build FastEq, and record the failure in the commit message. That one build also confirms the inference: if FastEq builds, the mutant is not the proof-killed one and the owner is told before the commit. Optional addition (an amendment to plan :333, decision 12): a Spec-level `#guard` pair (a row of another member) that also kills it in the mutant module.
- DecideRows twins: the `base`/`baseOf` terms are checked by `decide_bench check` with a random elig feed (4.8), not by mutants.

### 7.2 Protected digests

- `PAIRS_DIGEST`, `OUTPUT_DIGEST`, `REALISTIC_DIGEST` (rightrail/tests/test_gate_throughput.py:37-48) all move, on purpose. The trunk says a re-pin must keep `PAIRS_DIGEST` (:43), so this is a protected change with its own XI.2 paragraph (plan :331).
- The new `PAIRS_DIGEST` depends on whether the corpus carries an eligibility feed, which needs the request side (b). It can be recomputed signer-free with rightrail/tests/gate_unsigned_pairs.py (needs `gate_engine_unsigned`).
- The step 2 signer-free decision check (a0da49e8) is re-run with a usable elig feed on every line (expect the before pairs, since G2 does not fire) and with none (expect HUMAN_REVIEW STALE_ELIGIBILITY on every former ALLOW).

### 7.3 ALLOW fixtures

Once STALE_ELIGIBILITY fires on an absent feed, every engine ALLOW becomes HUMAN_REVIEW. Fixtures need a usable eligibility feed, which needs the request side (b): `app/right_rail_gate_ffs.py` `feeds()` (:98-171), `tests/_gate_shards.py` `feeds_of` (:84-102) and `_with_members` (:62-81, which must add harness members to the elig rows), `tests/_gate_bars.py`; then test_right_rail_gate_ffs, test_gate_authority_frames, test_engine3_recovery, test_flat_host, test_right_rail_gate_shards. October solved this only in vector files.

### 7.4 What runs here

- Runs here (signer-free): every Lean build and `#guard`, including the mutant module; `test_gate_rules_vectors` and the v2 spec test (gate_rules exe, the ~10 min build); `test_cause_actions`; `test_conformance_manifest`; `test_gate_answer_v3`; `test_gate_producer_design`; statement and axiom pins (up to 1,800 s per Lean call, rightrail/tests/test_statement_pin.py:45); the parity harness on the frozen copy and its unit tests; localBCE `cargo test`/`cargo check`; `PAIRS_DIGEST` via `gate_unsigned_pairs.py`; the signer-free decision check; `decide_bench check`.
- Needs the signer: `OUTPUT_DIGEST`/`REALISTIC_DIGEST`; gate_v1.vectors regeneration; test_right_rail_gate_ffs, test_gate_authority_frames, test_flat_host, test_right_rail_gate_shards, test_engine3_redo_cut, test_engine3_recovery (probably), test_tcb_gate, and `_gate_bars` runs unless `RR_GATE_UNSIGNED=1` works for them.
- These go on the "not run here" list for the owner's explicit acceptance, unless the signer arrives first (step 2 decision 20 holds the commit for it by default).

### 7.5 Checks for the step 3 commit

The step 2 list, plus: the parity harness on the frozen v1 copy, `test_gate_rules_vectors`, the v2 spec test, `test_cause_actions`, `test_conformance_manifest`, the in-Lean mutant module, `decide_bench check`, three byte-matched builds, the TCB live run and check, STMT_PIN regen, localBCE `cargo test` and `cargo check` (plan :342).

## 8. Effort

Authoring days. Machine time: a DecideRows build is about 10 minutes, and each proof-repair loop on it pays that again.

| Part | Split | Days |
|---|---|---|
| Rules/Spec, Run, Theorems (statements, `g2_*`, `fact_mono`), Fast, FastEq | (a) | 2-3 |
| Bound: `Bits.el`, `may`, budget and headroom re-pins | (a) | 0.5 |
| Flat/Model, Flat/Theorems, PayTheorems, Signed, Worker/Frame `feedsOf` and `fcOf_inv` | (a) | 3-5 |
| Scoped `kRules`/`Ctx.plain`, Scoped/Consume/Signed proofs re-checked and about 20 guards rewritten (4.6a, 4.6b) | (a) | 1-1.5 |
| DecideRows (layout, `Rep`, `base`/`baseOf`, `fcap_line`, `mask_has`, `decideRows_both`), DecideCut, RowsBudget, DecideBench | (a) | 4-7 |
| Engine3 `FeedsX`/`assemble`, absent placeholders in `decode`/`feedsW` | (a) | 0.5-1 |
| Authority, AuthorityLaws, host tables, cause_actions, STATUS.md, ARCHITECTURE.md | (a) | 1-1.5 |
| GATE_RULES_V2 page, ref checker, four vector files, v2 spec test, v1 retirement fallout | (a) | 3-5 |
| In-Lean mutant module; proof-killed mutant by one trunk scratch-copy build (about 10 min machine time per try) | (a) | 1.5-2.5 |
| Frozen v1 copy, parity repoint | (a) | 0.5 |
| **Subtotal, can start now** | | **17-27.5** |
| Rebase of the (a) edits onto step 2's request side (Frame/Spec, Worker, RowsStore, ReadB) | (b) | 0.5 |
| Frame `ctxOf` kind-7 snap, Worker `snapF`, Engine3 decode/ReadB/Step/StepH/Verify | (b) | 1.5-2.5 |
| ALLOW fixtures, shared builders, signer-free check re-run, `PAIRS_DIGEST` | (b) | 2-3 |
| Pins, XI.2 record, re-pin and evidence | (b) | 1-2 |
| After the signer: digests, gate_v1.vectors, signer tests, fallout | (c) | 0.5-1.5 |
| **Total** | | **about 22.5-37 working days (4.5-7.5 weeks)** |

- The high end allows one restated DecideRows proof (`mask_has` with `grind`, `decideRows_both` at 4,000,000 heartbeats) needing a split, for example the elig `base` terms in their own lemma.
- (b) cannot start before step 2's request side, which itself waits on rr-core's answer or the 2026-11-22 bound (Route A is decided).

## 9. XI.2 record draft

One record in the commit message, 8 fields (rightrail/CONSTITUTION.md:174-183). The owner authors or approves it.

1. **Predicate.**
   - The rule set: 24 reasons, `fires`, `review`, `bypassable`, `Ctx` without eligibility (Rules/Spec.lean:113-173, :236-255, :392-427).
   - The Theorems statements `Fact`, `Grows`, `fact_mono` and, through `Fact`, `sound`/`complete`/`hold_complete` (Rules/Theorems.lean:94-124, :751-817); the bound pins `budget_bool` and `headroom_*` (:353-382).
   - The statement-pinned definitions that move (rightrail/tools/STMT_PIN.txt): Rules `Ctx` :4409, `Reason.idx` :4538, `bypassable` :4699, `fires` :4727, `reasons` :4778, `review` :4784; `Authority.reasonMask` :2335; Flat `FCtxInv` :3118, `Feeds` :3137 and :3139-3150, `Feeds.Same` :3138, `feedCapped` :3504, `localIx` :3523, `signedFeeds` :3548, `work` :3562, `workC` :3563, `work_le` :3564; Frame `ctxOf` :3690, `feedsOf` :3747; Scoped `Ctx.plain` :4808, `kRules` :4834.
   - `Authority.reasonMask = 2^24`, `reasonMask_eq`, the bypassable count 15 (Authority.lean:20; AuthorityLaws.lean:25, :478).
   - The signed path's decision context: Scoped `kRules`/`Ctx.plain` copy the caller's `base` (Scoped.lean:68-74, :92-97), now with `eligibility := none`; the proofs of `allow_live`, `allow_tightens`, `allow_attached`, `Consume.allow_signed` and `Flat.decideSignedIdx_eq` are re-checked with unchanged statements; the signed-path guards of 4.6b.
   - READ-SET/v2 (Run.lean:602); the "Gate rules v1" contract (MANIFEST.sha256:1-2, :9-12).
   - `PAIRS_DIGEST`, `OUTPUT_DIGEST`, `REALISTIC_DIGEST` (test_gate_throughput.py:37-48); artifacts/** (the `gate_engine` pin); tools/STMT_PIN.txt.
2. **Invariant.** A G2 HOLD rests only on a usable pinned eligibility snapshot and a valid service date; stale, missing, malformed or unverified data gives HUMAN_REVIEW; every reason is reported. A signed mask bit names one reason forever. At most 32 reason codes per payment.
3. **Failure it protects against.** Paying a line for a member the eligibility data shows without an allowed aid code or benefit level; a silent HOLD of a review code; a bypass releasing a certain eligibility finding.
4. **Evidence it is unsuitable.** localBCE G2 has no RightRail rule (f16a61f4:docs/integration/G2_DESIGN.md:437); the trunk `Ctx` has no eligibility; a 2^24 mask cannot carry idx 24-28; v1 vectors have no eligibility, so every v1 answer changes once STALE_ELIGIBILITY exists.
5. **Disposition.** Retain R1-R5; add G2. Replace v1 with "Gate rules v2". Widen APPROVAL/v2 masks in place. Replace READ-SET/v2 with READ-SET/v5.
6. **Replacement control.** The five `fires` arms; `allowedAid` and review-completeness `#guard`s; `fail_closed_eligibility`, `g2_review`, `g2_exclusive`, `g2_hold_usable`, `g2_allow` with axiom pins; `may_sound`, `budget` (≤ 32), headroom 23/18; FastEq, Flat and DecideRows equivalences re-proved; AuthorityLaws.lean:477-478, :491; GATE_RULES_V2 with an independent checker; the 19 mutants killed; three byte-matched builds and the TCB check; the parity harness on the frozen v1 copy.
7. **Scope and duration.** `gate_engine`, `gate_hist3`/`gate_verify3`, the signed-path modules Scoped, Consume and Flat/Signed (outside `gate_engine`), the host tables, the text runner, the conformance kit, and rightrail/STATUS.md and ARCHITECTURE.md, from this commit, permanent. `gate_verify` does not move. Synthetic, not legally verified; maxAge 7 days is a placeholder.
8. **Claims withdrawn and left open.**
   - Withdrawn: the runner conforms to v1; `PAIRS_DIGEST` is unchanged.
   - Recorded, not withdrawn: adding eligibility rows is not monotone; `Grows` now requires equal eligibility. Nothing is withdrawn here because `monotone` never covered eligibility (the trunk `Grows`, Rules/Theorems.lean:751-765, has no eligibility field), as the October record said (f16a61f4 commit message).
   - Open: no real eligibility producer exists, so production lines go to HUMAN_REVIEW on STALE_ELIGIBILITY (plan :360); the signed path reads no eligibility and so never ALLOWs (decision 15); its ALLOW theorems hold vacuously, and no signed-path vector exercises an ALLOW until the path is extended (4.6b); `factsDigest` stays four-pin and has no caller.
   - Open: `decide_bench rowscheck` does not cover the eligibility layout path until (b). The Engine3 side reads eligibility as `FeedIx.absent` (RowsStore.lean `FeedsX.decode`) and the model side's `viewOf` sets `eligibility := none` (Flat/DecideBench.lean `viewOf`), so `sameLay`'s `runEq eligEq` compares two empty runs, and `viewSame` has no eligibility comparison. In (b), `viewSame` gains an elig `factSet` comparison. (`decide_bench check` does exercise the G2 bits through its random elig feed, 4.8.)
   - Named unresolved differences: localBCE manual review (rules.json:834-838) and D3/D4 (rules.json:420-426), as October recorded (f16a61f4:docs/integration/G2_DESIGN.md:438).
   - If signer-dependent tests did not run: the "not run here" list.

## 10. Risks

- **Landing before the feed.** If any part of (a) reaches a committed `gate_engine` pin before step 2's request side, every engine line goes to HUMAN_REVIEW. Decisions 1-2 keep it on the branch.
- **Step 2 layout.** Route A is decided (TRUNK_STEP2_FRAME_DESIGN.md:5) and fixes the elig row stride at 62 (:49). If rr-core takes the feeds into its own v2, its layout sets the stride, body offsets and member width in ReadB and `FeedsX.decode` instead. Writing (b) before rr-core's answer or 2026-11-22 risks rework. Route B (stride 63) is not assumed: it needs a separate owner word (TRUNK_MIGRATION_PLAN.md:443).
- **Step 2 sequencing.** The (a) edits in Frame/Spec, Worker, RowsStore and ReadB touch functions the request side rewrites (TRUNK_STEP2_FRAME_DESIGN.md:188). They are kept minimal and rebased when the request side is committed (section 1, Sequencing; section 8).
- **Signed-path evidence.** With K3 never ALLOWing, the signed-path ALLOW vectors become STALE_ELIGIBILITY-only vectors (4.6b); the ALLOW path itself has no vector until the signed path is extended.
- **DecideRows proof cost.** `mask_has` (`grind` over `cases cp × cases r`, 48 to 58 goals) and `decideRows_both` (already 4,000,000 heartbeats) may time out; each try is a 10-minute build.
- **Statement-pinned definitions.** The STMT_PIN entries of 4.5 all move. Appending to `FCtxInv` keeps the `obtain`s that end in `-`, but `lim_loc` and the three exact-tuple proofs must change (4.5).
- **New POSTING_CAP source.** Capping the elig member read adds POSTING_CAP holds for members with more than 1,024 eligibility rows.
- **Fail-closed by design.** Signed path and production go to HUMAN_REVIEW until eligibility is produced. The gate releases nothing without review.
- **Silent wrong-bit tests.** Two tests build bypass bits from list position (section 6); missed, they test MEMBER_DECEASED_UNVERIFIED without failing.
- **The signer.** Without it the step is not complete (7.4).
- **Rule budget.** 23 of 32 at the all-false tuple after G2; step 4 adds G4's source.

## 11. Decisions for the owner

Each has a one-word default.

1. **Build order relative to step 2.** Author all of (a) now on `codex/rightrail-trunk-step3` as WIP, in the order of section 4, checked with the text runner, the rules_v2 vectors and the mutant module. Do not wait for 2026-11-22. Default: **author-now**.
2. **Land G2 before or after the request side.** After: one step 3 commit and one re-pin, made only once step 2's request side is committed, so no committed `gate_engine` ever sends every line to review for a missing feed. Default: **after**.
3. **`Ctx.eligibility` default.** No default, as October: every construction site is edited and visible (4.1). Not `:= none`, which would compile silently into fail-closed sites. Default: **none-default**.
4. **idx 24-28 in name order** (plan :281-286), permanent in signed masks. Default: **confirm**.
5. **`review` arm position.** Its own line before `| _ => false`; October's first-arm reason (Python mutants) does not apply. Default: **own-line**.
6. **`bypassable`** per plan decision 12 (three review codes; count 15 to 18), with the docstring of 3.5. October left nothing open here. Default: **yes**.
7. **Eligibility maximum age.** Keep the 7-day placeholder, not localBCE's 24-hour O1 TTL. Default: **7**.
8. **Contract versioning.** One GATE_RULES_V2 for G2, extended in place at step 4 (plan decision 11). Default: **v2**.
9. **v1 retirement.** Delete all v1 conformance files and lines (vectors, negatives, GATE_RULES_V1.md, gate_rules_v1_ref.py, test_gate_rules_v1_spec.py), and repoint the six test importers and readers of section 6 to v2. Default: **delete-and-repoint**.
10. **demo_zz_v2.** Copy demo_zz.vectors and insert one fixed elig row per member with a script kept outside `rightrail/`, rather than restoring the deleted generator into `rightrail/tools`. Default: **insert**.
11. **Vectors while the signer is missing.** Do every signer-free file now (four gate_rules vector files, test_gate_answer_v3, cause_actions, MANIFEST); edit the gate_v1.vectors bit-24 must-reject case to bit 29 only with the signer; hold the commit for the signer as step 2 decision 20 does. Default: **hold**. *Owner amendment 2026-11-19 ("Bit-29 fix"):* the bit-24 case moves to bit 29 now, without the signer. `answer` lines are signer-free (`signer_free_vectors`, rewritten by `python -m tests.test_right_rail_gate_formats --signer-free` as at step 2, 19e001c7), so `gate_vectors` passes here; only full byte reproduction by `build_vectors` (`test_python_reproduces_every_vector_byte`) still needs the signer.
12. **The proof-killed mutant.** As plan :333 and decision 7: one scratch-copy build of the trunk tree with G2 and the "G2 any member" mutant, under the guard, its FastEq failure recorded in the commit message; if FastEq builds, the inference is wrong and the owner is told before the commit. Optionally also a Spec-level `#guard` pair in the mutant module, which amends plan :333. Default: **scratch** (no `#guard` addition unless the owner says so).
13. **Eligibility over-cap.** `feedCapped` adds the member's elig read, so more than 1,024 eligibility facts give POSTING_CAP like the other feeds. Default: **cap**.
14. **`FCtxInv` conjunct placement.** Append at the end. This keeps the `obtain`s that end in `-`; it still needs `lim_loc` (Flat/Theorems.lean:929-931) re-patterned and the exact-tuple proofs `fcOf_inv`, `feedsOf_inv` and `specFeeds_inv` given three more entries (4.5). Default: **append**.
15. **Signed path.** Keep it at four kinds (plan decision 5). Make it read no eligibility: `eligibility := none` in Scoped `kRules` and `Ctx.plain` (statement-pinned definitions; the theorem statements keep their text), with Flat/Signed `signedFeeds` setting the feed absent so `decideSignedIdx_eq` still holds. Record that every signed-path line now goes to HUMAN_REVIEW on STALE_ELIGIBILITY and that its ALLOW vectors are rewritten (4.6a, 4.6b). Rejected: a `c.eligibility = none` hypothesis on `decideSignedIdx_eq`, which leaves `Consume.decideSigned` able to ALLOW on unsigned eligibility. Default: **none-in-kRules**.
16. **`factsDigest`.** Leave it four-pin, record it as dead code. Default: **leave**.
17. **Proof coverage.** Add Flat/PayTheorems, RowsBudget, PayNumbering and DecideRows to `PROOFS` (test_gate_rules_vectors.py:23-25). Add `Rules.may_sound`, `decideAll_may`, `budget`, `pay_budget` and the five G2 theorems to rightrail/tools/gate_print_axioms.lean, Gate/AxiomCheck.lean and Gate/AXIOMS.txt; the four bound theorems already have in-file pins (Rules/Theorems.lean:1012-1019), the G2 ones get them. Default: **add**.
18. **DecideRows fact shape.** Precompute `aidOk` per fact in layout (`EligF`), keeping the scan word-only like `SpanF`. Default: **precompute**.
19. **Stale ReadManifest citations** at Run.lean:9, :232 and :599: fix in this commit. Default: **fix**.
20. **Parity harness.** Only repoint `DEFAULT_VECTORS` to the frozen copy (plan decision 13); G2 comparison in the harness is a later localBCE change. Default: **repoint-only**.
21. **Evidence path.** Keep October's position: G2's evidence is the pinned snapshot, not the owner typed-evidence path (f16a61f4:docs/integration/G2_DESIGN.md:25-29), and keep D3/D4 as a named unresolved difference. Default: **keep**.
22. **cause_actions wording.** Approve the five rows of section 5 as drafted. Default: **approve**.
23. **Plan corrections.** Record section 2 (stale lines, the done and unneeded items, the missing sites including the Scoped `kRules` change, the request-side dependency) as amendments to plan step 3. Default: **record**.
