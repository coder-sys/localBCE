# Adversarial review of the trunk-move assessment (2026-11-22, generated, read-only)

BASE is RightRail fc89f9e5, NEW is af4c7c52, OURS is localBCE's rightrail/ tree at c99a2375. Paths under a Temp scratchpad folder name working scripts on the machine that ran this and are not in the repository. Read with HANDOFF.md; the review corrects the assessment.

ADVERSARIAL CHECK OF THE TRUNK-MOVE ASSESSMENT (read-only; nothing built, fetched, edited or committed)

How I checked: read-only git in the scratch clone and in C:\Users\sruja\Downloads\localBCE-trunk, plus one SHA-256 of the local signer exe. Scripts: C:\Users\sruja\AppData\Local\Temp\claude\b061ecdf984ca40a\ffcabc84-6f1a-4da3-b3c7-7eaec394f939\scratchpad\trunkmove\adv1.sh, adv2.sh, adv3.sh, adv4.sh (same folder). No proof or test was run, so "compiles / closes" remains unobserved here too.

Verdict: the facts about upstream hold up well. The recommendation (D) has one structural flaw (stage 1 does not separate the way it is described), the history/publication facts are wrong in the owner's favour, one "unknown" is resolvable and resolves against the plan, and the day estimates are inconsistent with the stated pace.

## A. CORRECTIONS (most important first)

1. Stage 1 of option D is not achievable as described; it contradicts the merge mechanics.
   - What is wrong: stage 1 says "replay the Elig/Soc types and the six proof commits on upstream's answer format, take upstream's side in every answer-format hunk", with G2 (a), 19e001c7 and S0 held for stage 2. But the mechanic is one merge of the whole OURS tree, which contains 19e001c7, bbd0e947 and 36fb3603. Picking upstream's side only in conflicted hunks leaves the cleanly merged halves of those commits in the tree.
   - Evidence (merged tree 4774fc69): Frame/Spec.lean:133 `def ansVersion : Nat := 3` and :656; Frame/Answer.lean:64, :68, :518 (`20 * nr`, `ansVersion`); Frame/Fast.lean:3856, :3859; Engine3/StepH.lean:193 and Verify.lean:344 (`20 * out.ds.size`); Engine3/Step.lean:374. All merged without conflict. G2's 29 reasons also merge clean, and upstream's leaf keeps leaf-only codes at bits 24/25 with `l.reasons < 2 ^ 26` (af4c7c52:lean/BlindLedger/Gate/Frame/Spec.lean:517; Engine3/Step.lean:318, :325), so G2 idx 24 and 25 land on the leaf-only bits. `pack1_fires` goes false the moment G2 is in `Rules.fires`, so the stage 1 tree cannot go green without the cofounder's answer to question 4.
   - Corrected statement: stage 1 needs an explicit back-out of the rightrail/ parts of 19e001c7, bbd0e947, 013a686c and 36fb3603 inside the merge resolution (or a path-limited replay of only a0da49e8, 9330572b, c7ad3c65 and the six proof commits, which is the commit-by-commit replay the assessment rejects). Either way the branch tip temporarily loses G2 (a), which the owner approved and committed; that needs the owner's word and is missing from the "needs the owner's word" list. The 4-7 day figure for stage 1 does not include it.

2. The "unknown" about whether the six proof commits name 19e001c7's constants is resolvable: they do.
   - Evidence (localBCE-trunk): 0319ec32 adds `Frame.leafScope` / `Frame.leafUnencodable` to Flat/RowsBudget.lean (b7c80442:lean/BlindLedger/Gate/Flat/RowsBudget.lean:148-149) and cites `Rules.reasons_len_le` ("at most 62 reasons"); fcd29193 cites `reasons_len_le32` and `Reason.idx`-numbered `leafBits`; 6655362e states its result by `r.idx`. `reasons_len_le` comes from 9330572b/19e001c7. 379b487c, 4d715f52 and 845e7b9c add no such names.
   - Corrected statement: the table row "fcd29193 Keep, rebuild: depends only on untouched DecideRows/DecideCut" is wrong; RowsBudget also depends on Engine3 `leafBits` and, after 0319ec32, on the v3 leaf constants. On upstream's answer format 0319ec32 and parts of fcd29193/6655362e must be restated (2^24/2^25, position-numbered bits: upstream `maskOf` and `reasonTab` number by list position, af4c7c52:Frame/Spec.lean:443-445, Engine3/Step.lean:80), then restated again if the answer later widens. That is the "written once" benefit of D partly lost.

3. RightRail history is already in the localBCE repo and already pushed; the publication and fetch claims are overstated.
   - Evidence: in localBCE-trunk, `merge-base --is-ancestor 961434e1 HEAD` and `--is-ancestor af020b26 HEAD` both succeed. 961434e1 is contained in at least eight origin branches (rightrail-base-phases, rightrail-g2, rightrail-g4, rightrail-import-history, phase0/phase1 and others); the three trunk branches descend from it. Counts in the scratch clone: 1,927 commits up to af020b26, 2,274 in af020b26..af4c7c52, 4,201 total.
   - Corrected statements: (a) a push would newly publish 2,274 commits, not 4,201; 1,927 are already on GitHub. (b) "Precedent exists (961434e1)" is not one side branch, it is the ancestry of every current branch. (c) `--allow-unrelated-histories` is not needed: the histories are related through af020b26. Without the `-s ours` join, `git merge -X subtree=rightrail af4c7c52` would use af020b26 as merge base, not BASE, and would not reproduce the 24-conflict trial merge; the join commit is therefore required, not optional plumbing. (d) RIGHTRAIL_IMPORTED_FROM.md:11 "History: not available" is true only for af020b26..fc89f9e5.
   - Still true: fc89f9e5 itself is not in the localBCE object store (cat-file fails), so a fetch is needed and is the owner's call.

4. The u32 fallback in cofounder question 2 does not survive G4.
   - Evidence: docs/integration/G4_DESIGN.md:19 "3 new codes ... of `maxReasonCodes` 32". On the trunk that is 29 + 3 = 32 rule reasons, plus two leaf-only codes = 34 bits. Upstream also holds masks as UInt32 (`Rows.bit : UInt32`, af4c7c52:lean/BlindLedger/Gate/Flat/DecideRows.lean:215; `Lo m := m.toNat < 2 ^ 24`, :1654; `reasonMask := 2 ^ 24`, Authority.lean:20).
   - Corrected statement: "29 reasons plus two leaf-only codes is 31 bits" holds only until G4. Ask the question as "u32 through G2 only, or widen now"; do not present u32 as a way to avoid the answer redo. Moving the leaf-only codes off 24/25 is itself a change to upstream's version 1 answer (FRAME_V1.md:143, "a reason bit over 25 is refused", :151), so it is a protected change on his side either way.

5. "Upstream stated a different eligibility route" is stronger than the evidence. Claim (1) of the brief: upstream neither supersedes nor replaces the two-feeds plan today.
   - Evidence for "facts are intended to be read by decisions": only a doc comment, "The part of a value a decision reads. Eligibility: the status" (af4c7c52:lean/BlindLedger/Gate/FactBelief.lean:212-213), and STATUS.md:237 calling re-sent feeds "a speed gap". No upstream text says a payment rule will read belief; grep for it in docs/, conformance/, STATUS.md is empty.
   - Evidence against "feeds are being replaced": upstream's newest decision-path work, signed rule sets (ca460a93 2026-11-19, 750f6f22 2026-11-20), takes exactly the four per-request feeds as sources: `inductive Src | DMF | PDEATH | EXCL | SPAN` (af4c7c52:lean/BlindLedger/Gate/RuleSet/Spec.lean:61). RULESET_V1.md mentions neither belief nor the fact store. The eligibility fact work is framed in the architecture doc as a "determination warrant" (required verifications, notice; af4c7c52:docs/STATE_EVIDENCE_ARCHITECTURE.md:477, :664), which is evidence about the determination, not an aid-code/benefit-level test on a service date.
   - Corrected statement: "Upstream built an eligibility fact intake that no decision reads, and its latest rule work still reads per-request feeds. Its intent for a G2-style rule is unknown." This raises the weight of question 4 (a new rule-set `Src` for eligibility is the upstream-shaped form of the feed route) and lowers the likelihood that option C is forced.

6. The STATUS.md vs RuleGate.lean disagreement is resolvable: STATUS is stale.
   - Evidence: STATUS.md:183-185 was last edited by bc751b3f (2026-11-19). 750f6f22 (2026-11-20, "work in progress") wired `RuleGate.after` into the rows-file engine: af4c7c52:lean/BlindLedger/Gate/Engine3/StepH.lean:45-49; Verify.lean:4 imports it; HStore.lean:216 uses `RuleGate.passedBy`. gate_hist3's root is Engine3.HMain, which imports HStore.
   - Corrected statement: gate_hist3 and gate_verify3 run the rule gate at NEW. The pinned gate_engine does not: its closure is EngineMain -> OneProc -> Flat.Worker, PublishSpec, with no Engine3.Step import.

7. The answer-version collision is real but its scope is narrower than "every localBCE decision answer is read as a fact answer".
   - Evidence: `factAns` is used only at af4c7c52:lean/BlindLedger/Gate/Engine3/Step.lean:68, :71, :75 (headAt and the `an` binding domain). Importers of Engine3.Step are the rows-file engine, its checker, LeafCheck and Bench. Neither gate_hist3 nor gate_verify3 appears in artifacts/, tcb_report.txt or test_tcb_gate.py (grep empty), so both are unpinned.
   - Corrected statement: "In the rows-file engine and its checker (unpinned gate_hist3, gate_verify3) a version 3 decision answer is bound under ANSWER3 with a 7-byte stride. The pinned gate_engine and the Python host do not branch on that number." The renumbering is still needed, because localBCE's 19e001c7 edits those Engine3 files and the number is upstream's now.

8. Citation error: `pack1_fires` is not at RuleSet/Spec.lean:1205-1206.
   - Evidence: :1205 is `pack1_fires_aux`; `theorem pack1_fires` is at af4c7c52:lean/BlindLedger/Gate/RuleSet/Spec.lean:1232, `pack1_decideBatch` :1236, `live_pack1` :2026. STATEMENTS line is :814 (confirmed). `coreFires` :462-476, `dataReason` :270-274.

9. Day estimates are inconsistent with the stated pace, in both directions.
   - Too high: the reference week built everything in seven calendar days (70b4e4b6 2026-11-14 15:02 to c99a2375 2026-11-21 14:35), including the baseline, three designs and owner approvals. All six proof commits are dated one afternoon (2026-11-17 13:51 to 17:22); 19e001c7 was committed 42 minutes after 9330572b on 2026-11-15; G2 (a) landed about 1.5 days after its design approval. Against that, "8-15 days to be back where localBCE is today", 2.5-6 days for the six proof commits and 2-4 for the answer side are 2 to 10 times the original authoring time. Commit times bound effort only loosely, but the assessment gives no reason a replay costs more than the first build. A range of roughly 4-8 days for option A's first leg is more consistent with its own yardstick.
   - Too low or missing: (a) "0-0.5" for fcd29193 (see correction 2). (b) G2 (b) "2-4 if feeds stay" omits what NEW added on that path: the rule-set gate, `pack1_fires`, READ-SET, Engine3 pins and rows for two more feeds; treat it as not estimated. (c) The baseline "1-2" assumes a build that fits memory; the assessment's own unknown says the BASE build peaked at 81% of the cap and the tree is 25% larger. (d) If the answer widens, the links-file tail (`tailC` `.num 4` reasons, af4c7c52:lean/BlindLedger/Gate/FactStore.lean:538-540, width 17 proved at :544) is a stored format in the cofounder's files; that is his protected change, not localBCE days.

10. Standing-rule gaps in the recommended steps.
    - Commit gate: `merge -s ours ... fc89f9e5` creates a commit at once. It is not in the "needs the owner's word" list, and the gated checks must run before it (memory: checks gate every commit; G2 commit needed "the owner's word again if they are still red").
    - Pins before the (b) re-pin: step 3 does not say how the conflicted pin files are resolved. conformance/MANIFEST.sha256, tests/gate_vectors/gate_v1.vectors and the `end` count of rules_v2.vectors cannot be committed with markers; recomputing them is a pin regeneration before the combined re-pin. Corrected step: take upstream's side for MANIFEST and gate_v1.vectors in stage 1, list the resulting reds by name for the owner, and regenerate only at the one re-pin. "Regenerate AXIOMS/AxiomCheck" has precedent (every proof commit did it) but should be named to the owner as not a pin.
    - Long-lived merge state: "hold uncommitted until green" after `git merge` leaves the worktree mid-merge for days; a `merge --abort` there discards the resolution, which is the reset-over-uncommitted-work the rules forbid. Add: keep dated patch backups of the resolution, as was done for G2 (a).
    - Signer: I hashed the local exe; the first 16 hex digits match the pin file (a1a6e9e45b11be50), file time 2026-11-22 10:38. The assessment relied on the task text for this. Whether the owner approved obtaining and running it is not in anything I read; say so before "full test run with the signer".
    - No breach found on: force-push (new branch, descendant only), reset/checkout/stash of the dirty step3 worktree (explicitly excluded; I confirmed its only change is PayNumbering.lean), `proof_execution_enabled` (not touched by any step), fetch and branch creation (both listed for the owner).

11. Missing options.
    - Baseline first, outside the localBCE repo: build and test unmodified af4c7c52 in a standalone checkout of the existing scratch clone before any merge decision. It answers the top unknown (does NEW build within this machine's limits, are the tip's pins and tests green) with no fetch into localBCE, no branch, no publication question. It needs only the owner's word to build. The assessment folds this into step 2 behind the history import.
    - Wait for a pinned head: 7a6b552d says "pins and TCB report take the branch side, to be regenerated by land_check"; after the last gate PROVENANCE change (3ac3a160, 2026-11-21 10:33) three commits changed Engine3/HStore.lean, Engine3/RuleGate.lean and RuleSet/Spec.lean (666c80a3, 4b96164e, 14865147). Whether the gate_engine pin is current at the tip is not determined. Question 9 should come before stage 1, not alongside it.
    - Upstream the route-independent pieces instead of carrying them: the payIdx/payFlags naming commits edit upstream's StepH/Verify and will conflict at every later move; offered upstream (with the FLAT_V1 `rq` fix) they stop being a carry cost. The assessment mentions offering only the doc fix.
    - Append-only numbering as a third answer-format variant: keep upstream's leaf-only codes at 24/25 and number G2 above them. It changes no existing bit. It needs idx-based (not position-based) masks upstream and fails the same u32 limit at G4; I did not check it against the Lean proofs. Listed only so the cofounder sees all three shapes.

12. Smaller points.
    - "70 commits a day" and the 511 puzzle: sorted by commit date, the range was 511 commits long at about 2026-11-21 05:11 -0500 (13c6a545). So the cofounder's count is roughly 26 hours older than NEW, and 49 more commits arrived in that time. This replaces "he probably counted at an earlier head" with a date.
    - "Rule sets may fire only thirteen reasons (RULESET_V1.md:86)": confirmed, same file :34 says the rule's `reason` byte is `Reason.idx`, which supports "appending idx 24-28 is compatible".
    - Held reds: the session memory says eight for bbd0e947, LOG.md:393 says seven after 013a686c cleared the vector line. Seven is the current figure; say which commit each count belongs to.
    - "25% larger tree" and the 81% memory peak are taken from an area report and LOG.md; I did not re-derive them.

## B. CLAIMS I CONFIRMED BY OPENING THE SOURCE

- Range: 560 commits, 495 without merges, 118 first-parent; 25 subjects match WIP/unpinned/tests pending. Heads and dates as stated.
- `FactFrame.ansVersion := 3` (af4c7c52:lean/BlindLedger/Gate/FactFrame.lean:39); `factAns`, `headAt` (7 else 16), `ANSWER3` (Engine3/Step.lean:68, :71, :75); ours `ansVersion := 3` (b7c80442:lean/BlindLedger/Gate/Frame/Spec.lean:126); upstream `version := 1`, `reqVersion := 2` (:127-129).
- The section 17 `rd_i` form "was never built" and "the answer's version stays 1" (af4c7c52:conformance/ENGINE_V3.md:970-976, :998).
- Fact frame twin: "Nothing in the gate, owner or engine uses it" (af4c7c52:app/right_rail_fact_frame.py:3-4); imported only by tests (hist3_crash.py, test_engine3_facts*.py, test_fact_frame.py). "Fact signatures do not exist yet" (STATUS.md:75). FactBelief imported only by BlindLedger.lean:25, AxiomCheck.lean:53, tools/gate_print_axioms.lean:53.
- No file under Rules/, Engine3/, Frame/ or Flat/ contains "elig" (case-insensitive grep empty). No share of cost, spend-down or patient liability anywhere at NEW (grep empty).
- Rules/Spec.lean is identical BASE..NEW (empty diff).
- ELIG value fields are status, basis, program, aid, determined, notice with no benefit level (FactCodec.lean:217 onward); belief reads status only (FactBelief.lean:212-216).
- Eligibility reader merged, reverted, re-merged on 2026-11-17 (1a4aa63a, 628e1bd9, ca172480).
- Snapshot pin kinds: 1-4 feeds (af4c7c52:lean/BlindLedger/Gate/Rules/Run.lean:244-256), 5 and 6 released/unresolved (Rules/DecideLayer.lean:141-142). Kinds 7 and 8 are free. `FRAME/v3`, `CONTEXT/v2`, `READ-SET/v5`, `READ-ELIGIBILITY`, `READ-SHARE-OF-COST` appear nowhere at NEW (the one "FRAME3" hit is `STORE/FRAME3`, unrelated).
- Leaf-only bits 24/25 and bound 2^26 upstream (Frame/Spec.lean:517; Step.lean:318, :325; Flat/Worker.lean:259; decide.py:899 `mask >> 26`); FRAME_V1.md:142-151 text.
- Unflagged 16-byte/u32 sites: HLinks.lean:83, :91; `tailC` 4-byte reasons (FactStore.lean:538-540).
- Upstream `Ctx` literal sites: 29 `enrollment :=` at NEW, 14 of them in RuleSet/Spec.lean, one in Engine3/Step.lean, two in Flat/PayTheorems.lean.
- test_flat_worker.py in the merged tree uses bare `GENESIS` at :342 and :417 beside a module `__getattr__` at :42 (NameError as stated).
- `leafReasons_filter` appears twice in merged PayTheorems.lean (:1057 public, :1274 private); the clash is likely, not observed.
- Rooted-count test {15, 0, 5, 16} at af4c7c52:tests/test_tcb_gate.py:250. Three new exes outside the default build exist in lean/lakefile.toml (obligations_shard, ruleset_admit, obligations_cost); 20 exes in all.
- Step 2 design lists 22 decisions (TRUNK_STEP2_FRAME_DESIGN.md:613-634); the texts of 1, 4, 5, 7, 8, 16, 18-22 match how the assessment uses them.
- localBCE-trunk: branch codex/rightrail-trunk-step3 at c99a2375, one modified tracked file (PayNumbering.lean); the 20-commit list and order match.

## C. NOT DETERMINED BY ME

- Anything that needs a build or a test run, including whether the tip's own pins and tests are green.
- The cofounder's intent on route, numbering and `pack1_fires`; nothing in the tree settles them.
- Whether coder-sys/localBCE is public or has push protection; I did not query the remote.
- Whether the owner approved obtaining the signer exe now present.
- Area-report details I did not re-open: pin hash values, PROVENANCE line numbers, the per-file conflict hunk descriptions outside the lines cited above, AdmitB.lean, the 208 -> 276 authority record, the bloat count, G2 design decision texts (TRUNK_STEP3_G2_DESIGN.md:461-483).
