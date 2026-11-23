# Trunk-move assessment (2026-11-22, generated, read-only)

BASE is RightRail fc89f9e5, NEW is af4c7c52, OURS is localBCE's rightrail/ tree at c99a2375. Paths under a Temp scratchpad folder name working scripts on the machine that ran this and are not in the repository. Read with HANDOFF.md; the review corrects the assessment.

TRUNK-MOVE ASSESSMENT: localBCE rightrail/ from fc89f9e5 (BASE) to af4c7c52 (NEW)

Read-only. Nothing was built, run, fetched or edited, so every "compiles / proof closes / test passes" statement below is from reading source, not observed. I re-opened the upstream files behind the claims I lean on (script: C:\Users\sruja\AppData\Local\Temp\claude\b061ecdf984ca40a\ffcabc84-6f1a-4da3-b3c7-7eaec394f939\scratchpad\trunkmove\syn1.sh). Verified by me: items marked [v]. Everything else is taken from the five area reports.

Day estimates are working days at the pace of 2026-11-14..11-21, the week in which all of the localBCE work below was built. They assume the interim guard and this machine's memory limits hold for a tree 25% larger; that is not measured.

## 1. What changed upstream that matters to localBCE

- **Answer version 3 is taken.** The fact answer is `RRDA` version 3 (af4c7c52:lean/BlindLedger/Gate/FactFrame.lean:39 [v]; df9ed249, 2026-11-17 "Fact frame codec: RRDF request, RRDA fact answer, retry rule"). The rows-file engine tells fact answers from decision answers by that number alone (af4c7c52:lean/BlindLedger/Gate/Engine3/Step.lean:68, :71, :74 [v]). localBCE's decision answer is also version 3 (b7c80442:lean/BlindLedger/Gate/Frame/Spec.lean:126 [v]). Merged as is, every localBCE decision answer is read as a fact answer.
- **The request frame localBCE designed against was withdrawn.** Request version 2 is one hash `H(dom FRAME2 ‖ body)`, carried by the engine and recomputed only by the checker. The §17 `body′ ‖ rd_i` form "was never built" (af4c7c52:conformance/ENGINE_V3.md:970-975, :985-987 [v]; 62b07e7d). Decision answers stay version 1 (ENGINE_V3.md:998 [v]; Frame/Spec.lean:127-129 [v]). §19 sorted 32-byte-member rows are still not built.
- **Upstream chose a different route for eligibility: persistent facts, not per-request feeds.** Fact kind 1 ELIG, an `RRELIG01` extract reader with an independent verifier (af4c7c52:conformance/ELIG_EXTRACT_V1.md:1-8 [v]; 79e3018f), the `RRDF` fact frame, a `facts` file and checker replay. It stops there: the Python twin says "Nothing in the gate, owner or engine uses it" (af4c7c52:app/right_rail_fact_frame.py:3-4 [v]); only tests import it [v]; `FactBelief` is imported only by the library root and axiom files [v]; no file under Rules/, Engine3/, Frame/ or Flat/ mentions eligibility [v]; "Fact signatures do not exist yet" (af4c7c52:STATUS.md:75 [v]). Nothing upstream for share of cost (whole-tree grep empty [v]).
- **The rule table did not move.** Rules/Spec.lean is byte-identical BASE..NEW [v]: 24 reasons, no eligibility in `Ctx`. localBCE's five G2 reasons at idx 24-28 collide with no upstream reason, but upstream leaf-only bits are still 24 and 25 and leaves are bounded at 2^26.
- **Three new layers sit around the rules.** Exact duplicates answered at once (outcome 3 ANSWERED, leaf flag 2 with an earlier list; 80973834, d4971721); release by cause (afe7fb6c); signed rule sets (RULESET/v1, RuleSet/Spec.lean, Engine3/RuleGate.lean; 750f6f22, 8e56eecc). The authority record grew 208 -> 276 bytes; the request authority section gained `rsv`, `rs` and rule-set records; INPUT is v7, TOKEN v3.
- **`pack1_fires` pins "rule-set pack 1 = Rules.fires" for every reason** (af4c7c52:lean/BlindLedger/Gate/RuleSet/Spec.lean:1205-1206 [v]; in upstream's statement pin). Adding G2 to `Rules.fires` makes it false until G2 is added to `coreFires` or eligibility becomes a rule-set source. That is the cofounder's file and architecture.
- **Every pin moved, and there is a fourth pinned program.** gate_verify exe, gate_engine pin, STMT_PIN (+2,064 lines), tcb_report, MANIFEST, gate_v1.vectors (nearly all lines), OUTPUT/REALISTIC digests; new `obligations_shard` pin; three new exes outside defaultTargets that tests require. Toolchain, lake manifest, signer pin, Constitution and worker exe are unchanged.
- **Much of the range is work in progress.** 25 of 560 commit subjects say WIP/unpinned/tests pending [v]. The eligibility reader was merged, reverted and re-merged on 2026-11-17 (1a4aa63a, 628e1bd9, ca172480 [v]). STATUS.md:183-185 says no gate executable calls `gateStep` while Engine3/RuleGate.lean:59-62 defines the engine step through it [v both texts; not resolved which is current]. Fact frames are admitted only by the unpinned gate_hist3.

## 2. What happens to each piece of localBCE work on NEW

| Piece | Verdict | Why | Days |
|---|---|---|---|
| Import record, self-check, zip check, baseline build/test record | Redo | All name fc89f9e5; baseline figures void; four programs and three by-name exes now | 1-2 |
| Step 2 answer side: Elig/Soc types, reason-index lemmas (9330572b) | Keep | Upstream-neutral | 0-0.5 |
| Step 2 answer side: header v3, u64 masks, 20-byte records (19e001c7, 21 files) | Redo on upstream's leaf, under a new number | Version 3 taken; upstream changed the same bytes (outcome 3, flag 2, earlier list, authLen 276). Unflagged upstream sites hard-code 16-byte records and u32 masks: Engine3/Step.lean:71, HLinks.lean:83/:91, and the links-file tail stores reasons in 4 bytes (af4c7c52:lean/BlindLedger/Gate/FactStore.lean:538-539 [v]), a stored format. Frame/Spec, Answer, Fast are 3.5k-3.9k-line proof files | 2-4, after the cofounder assigns a number; more if the links tail must widen |
| 379b487c, 4d715f52 (per-payment bound 32, capped path) | Replay with fixes | Rules/Theorems untouched; PayTheorems grew +629 upstream; one probable name clash (`leafReasons_filter`); lemmas were proved against a leaf with no ANSWERED case | 0.5-1.5 |
| fcd29193 (RowsBudget) | Keep, rebuild | Depends only on untouched DecideRows/DecideCut | 0-0.5 |
| 0319ec32 (`leafIn` mask lemmas) | Re-prove | `leafIn` changed signature and body (cause leaf, ANSWERED override); statements stay true | 0.5-1 |
| 6655362e, 845e7b9c (payFlags, payIdx/payLines) | Re-apply by hand, re-prove part | StepH/Verify conflict; upstream inserted `answeringB`/`unr1`; AdmitB changed (+63 -17, not read) | 1-2 |
| Uncommitted PayNumbering.lean (+88 -3) | Carry as a patch, re-prove | Sits on numbering upstream touched | 0.5-1 |
| G2 (a) rule logic, reasons, GATE_RULES_V2 text, mutants, DecideRows work (bbd0e947, 51 files) | Replay with fixes | Most files untouched upstream. New debts: three upstream `Ctx` literals lack `eligibility`; `FCtxInv` proofs meet +600 upstream lines; rule-set "reads no SPAN" lemmas need eligibility twins; `pack1_fires` goes false; vectors recount (expected 326, unconfirmed); test_flat_worker.py:342/:417 NameError on `GENESIS`; v1->v2 rename now fights an upstream that keeps editing v1 | 2-4, plus 1-2 for `pack1_fires` if the answer is "add to coreFires"; redo (5-10+) if the answer is "rule-set source" or "read belief" |
| S0 host draft (36fb3603) | Drop the digest/walk/context code; keep the layout idea | Implements the withdrawn `rd_i` digest and the old authority order; §19 strides it assumes are not built. Six descriptors at 76+77*slot with rows at 538 is still a valid extension. Nothing in production calls it | 0 to drop; 1-2 to rewrite on FRAME2 if feeds stay |
| scripts/elig_snapshot.py and 75 tests | Keep as is (outside rightrail/) | No collision. If eligibility goes the fact route, retarget output to kind 1 rows plus a receipt, keyed by upstream's `member_key` | 0 now; 2-4 to retarget |
| Planned Lean request side (FRAME/v3 walk/digest/parse) | Redesign before building | Designed on §17. On NEW it is one hash over the body, no engine digest check, new authority section. Smaller than planned if feeds stay; moot if facts replace feeds | 3-6 if feeds stay |
| G2 (b) wiring of kind 7 | Blocked on the route | Snapshot kinds 7/8 are free upstream, but upstream's stated direction is facts. Upstream has no belief-to-decision path at all | 2-4 if feeds stay; not estimable on the fact route |
| Combined re-pin | Redo scope | Four programs, rooted-count test {15, 0, 5, 16}, signer now present | 1-2 |
| The seven held-pin reds | Do not fix at BASE | Every pin they compare against was replaced upstream | 0 |

Decisions (the step 2 design lists 22, not 21: TRUNK_STEP2_FRAME_DESIGN.md:613-634):

- **Moot:** 4 check order and 5 literal §17 preimage (engine no longer checks a digest); 2 waiting for rr-core (he has now spoken); 20 signer-blocked regenerations (signer present); the `rd_i` part of 12.
- **Void, need a new decision:** 7 one version constant 3 (:619); 16 number reservation (:628), which failed for answer v3.
- **Need re-approval because the premise changed:**
  - 1 Route A (:613): built on a v2 that no longer exists.
  - 9 `Leaf.ok` (:621): must absorb outcome 3 and the earlier-list conjuncts.
  - 11 host read set (:623) and 13 vectors file (:625): upstream signatures and a regenerated file.
  - 8 "gate_verify does not move" (:620): upstream moved it repeatedly; re-check.
  - 3 §20 in gate_engine (:615): FRAME2 is now in every engine.
  - 15 stale-doc fixes (:627): partly overtaken; the FLAT_V1 `rq` correction is still right at INPUT/v7 and worth offering upstream.
- **D1 combined re-pin (decision 18, :630):** stands in intent; re-approve as "one re-pin on NEW, four programs".
- **D2 replacement check (decision 19, :631):** needs re-approval. Form (B) compares against "recorded pre-step-2 pairs"; those are BASE pairs, and upstream's ANSWERED rule changes decisions for exact duplicates. The baseline must be re-recorded on unmodified NEW. With the signer present, the signed PAIRS_DIGEST check can replace the unsigned substitute.
- **D4 elig header split (decision 21, :633):** "Route A only". It depends on §19's 32-byte-member rows, which upstream has not built. Moot unless the feed route is re-approved.
- **Stand unchanged:** 6, 10, 14, 17, 22 (the unsigned harness merges with one trivial conflict).
- **G2 decisions (TRUNK_STEP3_G2_DESIGN.md:461-483):**
  - 4 idx 24-28 (:464): needs the cofounder, since upstream's leaf bits sit on 24/25.
  - 3 no default for `Ctx.eligibility` (:463): reconsider; every future upstream `Ctx` literal will break on merge.
  - 8 and 9 rules v2 with v1 deleted (:468-469): re-approve; upstream still maintains v1 in place, so each move repeats the rename merge.
  - 21 "evidence is the pinned snapshot" (:481): this is exactly the open route question.
  - 20 frozen v1 fixture: keep at fc89f9e5 or re-freeze at NEW.
  - 2 combined re-pin: as D1. 13, 14, 18, 22 stand. 17 becomes "regenerate AXIOMS/AxiomCheck".

## 3. Options

**(A) Move now: re-import NEW, replay everything, keep the two-feeds plan.**
- Effort: 8-15 days to be back where localBCE is today, on NEW. Then 6-12 more for request side, G2 (b) and the re-pin. Total 14-27.
- Risk: high in the middle. The answer redo and G2 (a) both rest on cofounder decisions not yet given (answer number, leaf bits, `pack1_fires`, route). Guessing them risks a second redo of the most expensive proofs.
- Unblocks: real history, signed regeneration, upstream PRs, a one-command next move.

**(B) Stay on fc89f9e5, finish steps 2/3 there, move later.**
- Effort: 6-12 days now, then the full move (8-15), then the request side again (3-6) because it would be built on the withdrawn §17 form, and a second re-pin. Total 17-33.
- Risk: highest. The gap grows about 70 commits a day; the re-pin at BASE is thrown away whole; the answer format ships with a number upstream reads as something else; it goes against the cofounder's stated condition.
- Unblocks: nothing upstream can use. I do not recommend it.

**(C) Move, and re-plan eligibility around upstream's fact store.**
- Effort: the move core (baseline, merge, proofs) 4-7 days. Then localBCE's part: retarget the builder 2-4, re-type the G2 rule on upstream's ELIG value 3-6. The belief-to-decision path does not exist upstream, so the end date is the cofounder's, not localBCE's. Not estimable; weeks at least.
- Risk: dependency on unbuilt, unsigned, unpinned upstream work. Upstream's ELIG value has no benefit level and belief reads status only (af4c7c52:lean/BlindLedger/Gate/FactBelief.lean:211-216 [v]); share of cost has no home. S0, kinds 7/8, CONTEXT/v2, READ-SET/v5 and D4 are dropped.
- Unblocks: alignment with the owner's architecture, no per-batch re-hash of eligibility.

**(D) Staged move (recommended): move the route-independent work now, hold the format and transport work until the cofounder answers.**
- Stage 1, no cofounder input needed: join history, import NEW, baseline unmodified NEW, replay the Elig/Soc types and the six proof commits on upstream's answer format, take upstream's side in every answer-format hunk. 4-7 days.
- Stage 2, after his answers: G2 (a) plus whichever answer format and transport he agrees to. 5-10 days on the feed route with widening; longer on the fact route (as C).
- Stage 3: request side or fact producer, G2 (b), one re-pin. 6-12 days on the feed route.
- Total on the feed route about 15-29, the same as A, but the expensive proofs are written once. Risk: stage 1 may not separate cleanly (see unknowns).

## 4. Recommendation

Do (D). The cofounder is right that the move comes first: the two things localBCE was about to build next (Lean request side, combined re-pin) are both invalid on NEW, and none of the seven held reds has a future at BASE. But do not replay 19e001c7, S0 or the G2 transport until he has answered, because upstream took the answer number and stated a different eligibility route.

Mechanics: join real upstream history (`merge -s ours --allow-unrelated-histories fc89f9e5`, then `git merge -X subtree=rightrail af4c7c52`), on a new branch in a new worktree cut from c99a2375. Same 24 conflicts as the trial merge, and the next move becomes one merge. If the owner does not want RightRail history in the localBCE repo, apply `git diff --binary BASE NEW` with `--3way --directory=rightrail` instead. Do not replay commit by commit.

First three steps:
1. Send the cofounder the questions below. Stage 2 waits on them; stage 1 does not.
2. Create the new branch and worktree, bring in upstream history, and record a clean baseline on unmodified NEW: guarded build including obligations_shard, ruleset_admit, obligations_cost and tools/obligations_format; byte-match of four programs; full test run with the signer; decision pairs recorded.
3. Merge, taking upstream's side in Frame/Spec, Frame/Answer, Frame/Fast, Engine3/Step/Store/Verify answer hunks and the formats test; re-apply `payIdx`/`payFlags`; fix the two `GENESIS` uses; rebuild; regenerate AXIOMS/AxiomCheck. Hold uncommitted until the gated checks are green or the owner accepts named reds.

Needs the owner's word:
- Fetching upstream history into the localBCE repo (a download), and later pushing it, which publishes RightRail's 4,201 commits to github.com/coder-sys/localBCE. Precedent exists (961434e1), but it is the RightRail owner's call.
- Creating the branch and worktree; what to do with the uncommitted PayNumbering.lean (commit on step3 after checks, or carry as a patch).
- Parking Route A, D4, S0 and the Lean request side until the cofounder answers.
- Re-approval of D1 and D2 in their NEW form; keep or re-freeze the v1 fixture; whether the merge may be committed with named reds.
- Sending the message to the cofounder.

Questions for the cofounder:
1. Route: should G2 read a per-request snapshot feed (kinds 7 and 8, free at NEW) or belief over fact kind 1? If belief, when does a decision frame read the store, and who builds that?
2. Answer format: 3 is now the fact answer. Which version number may the decision answer take? Or would you rather stay on u32 and version 1: 29 reasons plus two leaf-only codes is 31 bits, if the leaf-only codes move off 24/25? (My inference, not checked against Reason.idx used as a wire number in cause records and rule sets, nor against later G rules.)
3. If masks widen: may the links-file tail (`tailC`, 4-byte reasons) and the 16-byte record stride in HLinks change, or must the stored mask stay under 2^32?
4. `pack1_fires`: should G2 be fixed Lean in `coreFires`, or a rule-set source and pack? Rule sets may fire only thirteen reasons today (af4c7c52:conformance/RULESET_V1.md:86 [v]).
5. ELIG value: will kind 1 take a benefit level, and is there a planned kind for share of cost? Upstream has neither.
6. Will you build §19 sorted 32-byte-member rows soon? It changes the strides of any six-feed frame.
7. Rules version: you keep GATE_RULES_V1 and amend it in place; localBCE renamed to V2 and deleted v1. Which do you want?
8. May localBCE carry RightRail history and offer branches upstream (the FLAT_V1 `rq` correction is a first candidate)?
9. Which head is stable to move onto: af4c7c52, or a later pinned commit? Is the signed-rule-set and fact-frame work expected to change shape again?
10. The fact-record design document cited by section in the Lean headers is not in the tree; can he share it?

## 5. Unknowns that could change the recommendation

- Whether the merged tree builds at all, and how many of localBCE's 58 theorems re-prove unchanged. No build was run. If PayTheorems or Frame/Spec re-proofs go badly, every range above stretches.
- Whether stage 1 separates: the six proof commits were written on top of 19e001c7 and may name its constants (for example `Frame.leafUnencodable`). Not checked.
- Build cost on this machine at NEW: the BASE build peaked at 81% of the job cap and the tree is 25% larger. If it does not fit, the move needs a different machine or guard settings.
- The cofounder's answers to questions 1, 2 and 4. A "facts only" answer turns D into C and makes S0, D4 and the request-side plan permanent drops.
- Whether upstream's new vector cases pass under G2, and the true `end` count.
- Whether localBCE's Lean changes fall in obligations_shard's closure (a fourth re-pin) or move the hard-coded rooted counts.
- Whether GitHub push protection or a history secret scan would block pushing upstream history (the PEM fixture literal).
- Upstream stability: STATUS.md and RuleGate.lean disagree about whether an engine runs `gateStep`; I could not tell which is current, nor whether the tip's own tests and pins are green.
- Why the cofounder said 511: the range is 560 commits (495 without merges) [v]; he probably counted at an earlier head.
- Whether the cofounder ever replied to the reservation request; the tree shows only that 3 was used.
