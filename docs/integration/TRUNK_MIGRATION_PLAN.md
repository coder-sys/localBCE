# Moving localBCE's RightRail work onto the 2026-11-14 trunk

## Status

- Written 2026-11-14 and revised the same day after a 24-finding review. **Approved by the owner on 2026-11-14 ("Approve defaults", all 19 decisions).** Step 0 is the commit that adds this file (variant B: no trunk history yet).
- It builds on `docs/integration/G2_G4_TRUNK_REBASE_ASSESSMENT.md` ("the assessment") and does not repeat it.
- The owner is the RightRail lead. Every change inside `rightrail/` needs the owner's approval (docs/integration/RIGHTRAIL_BASE_PLAN.md:138-145).
- Each step below is one reviewable commit. Each step stops for the owner's "continue" (docs/integration/GOVERNANCE.md).
- Checks gate every commit. A failed or skipped check stops the step until the owner gives an explicit word for that check in that commit.
- Owner decisions already in force, which this plan follows and does not reopen:
  - decision 6: stale, unverified or missing data goes to HUMAN_REVIEW, never HOLD, and every reason is reported;
  - option 1: a proved per-payment reason bound replaces a total-count guard (docs/integration/REASON_BOUND_DESIGN.md, approved; its D8 deletes the guard in the same commit as the theorems);
  - the approved lean shapes: one shared `_UNVERIFIED` per source for G5 and G6 (RB D6), 3-code G8 and G10 (RB D5), and "any rule after G10 needs the flow fact (D4) first, then a shape review" (RB D12).
- How paths are cited:
  - `trunk:path:line` is under `C:\Users\sruja\Downloads\rightrail-rightrail-main\rightrail-rightrail-main`.
  - `sha:path:line` is `git show sha:path` in this repository.
  - A bare `path:line` is in this working tree.

## Summary

**What moves.** The vendored `rightrail/` tree moves from October RightRail (`af020b2`, rightrail/IMPORTED_FROM.md) to trunk commit `fc89f9e5ceaacfbfb0cb50173a4fd870e3872a3f`. Phase 3 rules are then rebuilt on that trunk.

**New finding: the trunk commit is known.** The GitHub zip `C:\Users\sruja\Downloads\rightrail-rightrail-main.zip` names it in its archive comment:
- archive comment `fc89f9e5ceaacfbfb0cb50173a4fd870e3872a3f`;
- SHA-256 `1AFBC74DC3CF3F5A97C494A196F0C0E0A2D3938ABDD16C76B8CE09D36BA0AB71`;
- 9,656,995 bytes, written 2026-11-14 13:35;
- 627 files, the same count as the extracted folder.

That commit is not in this repository. This answers the assessment's question 1 in part: we know the commit, but we still have no history to branch from.

**What carries over.**
- The G2 and G4 rule meaning, defaults and owner decisions.
- The `Elig` and `Soc` row types and their `.fields` (90ffd3f9:rightrail/lean/BlindLedger/Gate/Rules/Spec.lean:186-200,558-562). On the trunk they land in step 2, not step 3.
- The `fires` cases and the `review` arms.
- The `fires_iff`, `g2_*`, `g4_*` and `fail_closed_*` theorem statements.
- The vector files, used as a source for new contract vectors.
- SNAPSHOT/v1 kinds 7 and 8 (90ffd3f9:rightrail/lean/BlindLedger/Gate/Rules/Spec.lean:534-562) and the tags `READ-ELIGIBILITY/v2` and `READ-SHARE-OF-COST/v2` (90ffd3f9:rightrail/lean/BlindLedger/Gate/Rules/Run.lean:241; 90ffd3f9:rightrail/lean/BlindLedger/Gate/ReadManifest.lean:41-42). The trunk does not use any of them.
- The approved per-payment bound (`Bits`, `bitsOf`, `may`, `may_sound`, `budget`, `pay_budget`) from REASON_BOUND_DESIGN.md. Its `Rules/Theorems.lean` part ports as written. Its StateV2 parts are replaced by a corollary next to `leafReasons_codes` (step 3).
- The Phase 1-2 work on PR #7: STARK parking and the parity harness. The harness reads `rules_v1.vectors`, which is byte-identical on the trunk until step 3 retires it; step 3 keeps a frozen copy outside `rightrail/` for the harness.

**What does not carry over.**
- All wiring: Fast, FastEq, DecideRows, Engine3, Run, host, runner slots, the read set and the manifest.
- The mutant tool.
- The `StateV2`-based reason-bound proofs.
- The October manifest version numbers. They collide with trunk tags: G2's `READ-MANIFEST/v3` with trunk:lean/BlindLedger/Gate/SnapshotV2.lean:7, and G4's v4 with :11-13.
- The October read-set numbers do not collide: the trunk uses only `READ-SET/v2` (trunk:lean/BlindLedger/Gate/Rules/Run.lean:602; trunk:lean/BlindLedger/Gate/SnapshotV2.lean:32). Using v5 and v6 is a choice to skip the October v3 and v4, not a forced move.

**Recommended route: "Route A".** Carry eligibility and share of cost as two more feed slots in the request frame:
1. Ask the RightRail maintainers (rr-core) whether these two feeds can go into frame version 2. Version 2 is specified but not built: ENGINE_V3 §17 fixes its digest (`H("RR/GATE/FRAME/v2" 0 ‖ body′ ‖ rd_1 ‖ … ‖ rd_n)`, trunk:conformance/ENGINE_V3.md:603-616) and §19 its feed rows (trunk:conformance/ENGINE_V3.md:661-685). The host still sends version 1 (trunk:app/right_rail_gate_decide.py:522).
2. If not, use `FRAME/v3`, built on top of the specified v2: the §17 digest construction and the §19 row layout, plus the two new feeds. A `FRAME/v3` on the FRAME_V1 body would carry a higher number than v2 with the older layout and fork from upstream's queued v2 work; that is only allowed as an explicit owner decision (Decision 2).
3. In the same frame step, number answer bits by `Reason.idx`, widen the leaf and record reason fields to u64, and put the leaf-only codes at bits 62 and 63, so no later rule changes the answer format.
4. Then add G2, then G4, as Lean rules inside the pinned `gate_engine`, with the per-payment bound ported in step 3.

Do not use the FactRegistry or the signed-snapshot path for this. Both are unwired:
- FactRegistry: "Nothing calls this yet" (trunk:lean/BlindLedger/Gate/FactCodec.lean:4).
- Signed snapshots: trunk:lean/BlindLedger/Gate/Flat/Signed.lean:1-10.

FactRegistry is also blocked on a design document we do not have and on a fact-kind number that rr-core has not assigned.

**Rough effort on this machine.** This is honest but unmeasured for the trunk.
- The trunk has 193 Lean files against 117 in October.
- In October one full guarded build of 138 jobs took three runs; its total wall time was not recorded. The two slowest modules took about two hours each under x64 emulation: `Payment.CodecLaws` at 7,410 s and `CorrectionTransition.Theorems.Core` at 7,087 s (b5f806df:docs/integration/LOG.md:225-230).
- The G4 mutant run hit a 10-hour limit (b5f806df:docs/integration/LOG.md:264-266).
- Every protected step that moves `gate_engine` needs three full builds: the in-tree build and two fresh `git archive` stage builds that must byte-match it (trunk:artifacts/gate-verify/PROVENANCE.txt:31-33).
- Expected machine time:
  - more than one working day for the baseline build;
  - three to nine days for each protected step (frame, G2, G4): three builds at one to three days each. The one to three days per build is an extrapolation from the October module times, not a measurement; step 1's measured build time replaces it;
  - more for each proof-repair loop under emulation, and steps 3 and 4 are dominated by proof repair (DecideRows, FastEq, Engine3), not by the rule bodies.
- The frame step needs new codec round-trip and fast-decoder equivalence proofs, and possibly the ENGINE_V3 §17/§19 v2 work itself. That is real proof work, with an authoring time that is uncertain and could run to weeks.
- Some evidence cannot be produced here as the machine stands (Prerequisites item 5 and Risks).

## Prerequisites

1. **Trunk history.** Ask the RightRail maintainers for a git bundle or clone that contains `fc89f9e5`.
   - Where the zip came from: it is a GitHub archive download. Its top folder `rightrail-rightrail-main` fits two readings:
     - repo `rightrail` with branch `rightrail-main`;
     - repo `rightrail-rightrail` with branch `main`.
   - The owning account is unknown. No URL is in the tree.
   - CONSTITUTION.md calls the trunk `rightrail-main` (trunk:CONSTITUTION.md:129). So did the October bundle (rightrail/IMPORTED_FROM.md:3).
   - Commits named inside the snapshot that the bundle should also contain:
     - `b99355cc`, the commit of the current `gate_engine` pin (trunk:artifacts/gate-verify/PROVENANCE.txt:124-125: the re-pin paragraph names the commit, the next line is the `pin gate_engine` line);
     - `7cae185e`, the worker rebuild (trunk:artifacts/engine-evaluator/PROVENANCE.md).
   - Check on receipt:
     - `git cat-file -t fc89f9e5` must print `commit`;
     - `git archive fc89f9e5` must equal the zip tree file for file.
2. **If git history is unavailable.** Import the zip tree as a snapshot commit (step 0, variant B).
   - RIGHTRAIL_IMPORTED_FROM records the zip's SHA-256, its archive comment and "history not available".
   - When history arrives later, a `merge -s ours` of `fc89f9e5` plus `git diff 'fc89f9e5^{tree}' HEAD:rightrail` (expect only our listed changes) joins the histories, and no file is rewritten.
   - Without history:
     - no branch can be offered upstream as a pull request;
     - XI.2 records cite the zip hash instead of a parent commit.
3. **The pending I.4 amendment upstream.** Exact repeats of paid lines are now answered at once (trunk:CONSTITUTION.md:437-441). This is approved but not built (trunk:STATUS.md:213-214).
   - It will touch the same reasons, vectors and pins as G2 and G4.
   - Ask whether it lands first. If it does, import the commit that has it.
4. **Machine.**
   - Lean v4.33.1 x64 runs under emulation; elan is installed (docs/integration/RIGHTRAIL_BASE_PLAN.md:136-137).
   - The interim guard is `scripts/rr_guarded_interim.ps1`, with an owner-approved floor of 1.5 GiB.
   - Disk is fine: 635 GB free on C:.
   - The trunk pin script calls a guard that is not on this machine (trunk:tools/tcb_pin.ps1:6).
5. **Test runtimes, before step 1 (Decision 16).**
   - A Windows Rust toolchain, so the ML-DSA-87 signer `rr_gate_mldsa87.exe` builds and its gate tests run. In October 76 tests failed for want of it (b5f806df:docs/integration/LOG.md:246-250).
   - SQLite 3.53.1 for the test runner, so `test_history_growth` runs (this machine has 3.40.1).
   - Both are downloads and need the owner's approval when they happen.
   - If the owner declines either, those tests are marked "not run here" in every step, and each step's commit needs the owner's explicit acceptance of that list. They are never silently skipped.

## Ordered steps

All protected steps carry a full 8-field XI.2 record in the commit message (trunk:CONSTITUTION.md:174-183).

Every Lean or TCB run goes through the interim guard. Each such run is labelled interim evidence.

"No build" means Python or git only.

**Re-pin procedure for every step that moves `gate_engine` (steps 2, 3 and 4, Decision 9).** This follows trunk:artifacts/gate-verify/PROVENANCE.txt:31-33:
1. the in-tree guarded build;
2. two fresh stages, `git archive HEAD:rightrail/lean` into two new empty directories, each built under the interim guard;
3. a byte match of `gate_engine` across all three builds;
4. the TCB re-pin, interim: `tools/tcb_pin.ps1` cannot run here as written, because it calls an absent guard path with a 3.75 GiB floor (trunk:tools/tcb_pin.ps1:5-6). Its equivalent is run instead and labelled interim:
   - set `RR_TCB_LIVE=1` and `RR_TCB_REGEN=1`, and run `tests.test_tcb_gate` through `scripts/rr_guarded_interim.ps1 -Modules tests.test_tcb_gate` at the 1.5 GiB floor (the regen run);
   - then set `RR_TCB_REGEN` to empty (keeping `RR_TCB_LIVE=1`) and run the same command again (the check run);
   - restore both variables afterwards, as the trunk script does (trunk:tools/tcb_pin.ps1:3,7);
5. the PROVENANCE re-pin paragraph naming the new hashes and the three build directories, and the new `pin gate_engine` line (trunk:artifacts/gate-verify/PROVENANCE.txt:124-125);
6. `AXIOMS.txt` and `AxiomCheck.lean`;
7. `python tests/test_statement_pin.py regen`, after the TCB re-pin, because STMT_TCB includes the TCB report.

If the three builds disagree, the step stops before the regen run: all three hashes are recorded, and nothing is re-pinned until the owner decides (Decision 8).

### Step 0. Import the trunk as the new vendored base

- **Branch.** New branch `codex/rightrail-trunk` from `codex/rightrail-base-phases` (dc586d87, PR #7's head).
- **Variant A (history available).**
  1. Fetch the bundle.
  2. `git merge -s ours --allow-unrelated-histories fc89f9e5`.
  3. `git rm -r -q rightrail`.
  4. `git read-tree --prefix=rightrail/ -u fc89f9e5`.

  This is the same method as the October import (rightrail/IMPORTED_FROM.md:9-10).
- **Variant B (zip only).** Replace `rightrail/` with the zip tree in one commit, as described in Prerequisites item 2.
- **Local changes to re-apply.**
  - Split the PEM header literal again. The trunk still has it unsplit (trunk:tests/test_privacy_artifact_scan.py:188), and our fix was e292cedc.
  - **IMPORTED_FROM.md.** It cannot stay inside `rightrail/`. The trunk doc rule refuses any hand-written `.md` that is not in its `OWNERS` list (trunk:tests/test_doc_shape.py:14-21,51-53).
    - Default: move it to `docs/integration/RIGHTRAIL_IMPORTED_FROM.md`. This changes no trunk file.
    - Record:
      - commit `fc89f9e5` and the zip hash;
      - the date;
      - the method;
      - every local change;
      - the check command.
- **Docs carried from the October branches.** Copy, docs only and outside `rightrail/`:
  - `G2_DESIGN.md`, `G4_DESIGN.md` and `REASON_BOUND_DESIGN.md` from b5f806df;
  - the LOG entries from b5f806df:docs/integration/LOG.md:237-272;
  - the assessment;
  - this plan.

  Mark each design "implemented on the October base only; superseded on the trunk by step N".
- **localBCE-side changes and checks.**
  - **Self-check.** `scripts/integration_selfcheck.sh` requires `rightrail/IMPORTED_FROM.md` to exist and to name af020b2 (dc586d87:scripts/integration_selfcheck.sh:87-91), and its ancestor check at :23 is pinned to af020b2. Edit both in this commit:
    - read `docs/integration/RIGHTRAIL_IMPORTED_FROM.md` instead;
    - variant A: check that it names `fc89f9e5` and that `fc89f9e5` is an ancestor of HEAD;
    - variant B: check that it names the zip SHA-256 `1AFBC74D…0AB71` and the archive comment `fc89f9e5`.
  - **Parity harness.** `scripts/g_rule_parity.py` still reads `rightrail/tests/gate_rules/rules_v1.vectors`, which has the same bytes. The "v1 is retired" note in the working tree (scripts/g_rule_parity.py:6-9) exists only on the g2, g4 and reason-bound branches. The step 0 branch starts from dc586d87, whose copy has no such note, so no change is needed here.
  - Re-check the worker-binary pin check from 9cd7b79b against the trunk's `artifacts/`.
  - Keep `rightrail/lean/.lake/` gitignored.
- **Protected formats.** None changed: the trunk files are imported byte for byte, except the PEM split.
- **Tests.** No Lean build.
  - localBCE: `cargo test`, `cargo check`, the parity harness, the localBCE local gate with the edited self-check.
  - Cheap trunk tests run directly: `test_doc_shape`, `test_bloat_budget`, `test_conformance_manifest`, `test_cause_actions`, `test_privacy_artifact_scan`.
  - The committed-report part of `test_tcb_gate` (it needs no build).
- **Build cost.** Minutes.

### Step 1. Baseline the unmodified trunk on this machine (log only, no `rightrail/` change)

- **Before it.** Prerequisites item 5 (Decision 16) is settled: either the Rust toolchain and SQLite 3.53.1 are installed, or the owner has accepted the "not run here" list.
- **Run, through the interim guard:**
  - a full `lake build` of `rightrail/lean` (default targets trunk:lean/lakefile.toml:3);
  - then the whole trunk `pytest` suite.
- **Record:**
  - every failure;
  - every skip;
  - the time for each run.
- **Expected environment failures if Decision 16 is declined, as in October:**
  - tests that need the ML-DSA-87 signer `rr_gate_mldsa87.exe`;
  - `test_history_growth`, which wants SQLite 3.53.1. See b5f806df:docs/integration/LOG.md:246-250.
- **Reproduction check.**
  - Compare the SHA of the `gate_engine` we build with the pinned `2d720b52…` (trunk:tools/tcb_report.txt:5).
  - A match is new evidence that a byte-identical build works under emulation.
  - A mismatch means later re-pins made here cannot be reproduced upstream. The owner must then decide (Decision 8).
- **Why this step is separate.** Every later step needs a known-good baseline. Without one, failures caused by the machine cannot be told apart from failures we cause.
- **Build cost.** The largest single unknown. Plan for a full day or more, with resumes.

### Step 2. The frame and width change, with no new rule

Coordinate this step with rr-core first (Decision 2).

- **Request side.**
  - Frame version 2 is specified, not reserved (trunk:conformance/ENGINE_V3.md:603-616 §17, :661-685 §19, :687-698 §20). Default: the two new feeds are added on top of that v2: its `rd_i` digest construction and its §19 row layout.
    - If rr-core takes the two feeds into v2, we import their v2 and add nothing of our own to the format.
    - If rr-core declines, we build `FRAME/v3` (header version 3) as "v2 plus two feeds". ENGINE_V3 §20 orders the §19 feed rows and the §17 request after the store-width steps 1-2; if those are not upstream yet, building on v2 means carrying them too, and that cost is reported to the owner before work starts.
    - A `FRAME/v3` over the FRAME_V1 body (82-byte v1 header, FRAME_V1 row widths) diverges from §17 and needs an explicit owner decision (Decision 2).
  - Six feed descriptors. The two new ones are appended at body offsets 384 and 461, so the existing four offsets (76/153/230/307) and `prev` stay put.
  - The context grows from 384 to 538 bytes.
  - Row widths, in the §19 style (member as 32 bytes with `0x01` implied, ids at 21):
    - eligibility: `member 32 ‖ aid 21 ‖ level u8 ‖ start u32 ‖ stop u32`, 62 bytes;
    - share of cost: `member 32 ‖ month u32 ‖ cents u64 ‖ met u8`, 45 bytes.
    - On the divergent v1-body route they are 63 and 46 bytes (`member n33`).
  - The digest domain is `FRAME/v3`, header version 3, or v2 if rr-core folds the feeds in.
- **Context.** `CONTEXT/v2`. The context hash does not cover the header version, so a new domain is needed to separate old and new bodies (trunk:lean/BlindLedger/Gate/Frame/Spec.lean:172-180). `INPUT/v6` stays.
- **Answer side: bit numbering.** Today frame record and leaf bits are positions in the name-sorted `reasons` list (trunk:lean/BlindLedger/Gate/Frame/Spec.lean:420,422; trunk:lean/BlindLedger/Gate/Flat/Worker.lean:172; trunk:lean/BlindLedger/Gate/Engine3/Step.lean:74). Signed-mask bits are `Reason.idx`, fixed per reason (trunk:lean/BlindLedger/Gate/Rules/Spec.lean:131-144). The two agree today only because the 24 idx numbers were assigned in name order. A new reason gets the next idx but sorts into the middle of `reasons` (trunk:lean/BlindLedger/Gate/Rules/Run.lean:47 guards strict name order), so under position numbering G2 would move every existing reason after ALREADY_DECIDED to a different answer bit.
  - Default (Decision 4): in this step, number frame and leaf bits by `Reason.idx`. It is append-stable: a new rule never moves an existing bit, and frame bits equal signed-mask bits.
  - Every site that changes:
    - `Frame.maskOf` and `Frame.unmask` (trunk:lean/BlindLedger/Gate/Frame/Spec.lean:420,422): `2 ^ r.idx` instead of `zipIdx`;
    - `Worker.reasonBits` (trunk:lean/BlindLedger/Gate/Flat/Worker.lean:172) and `leafMask` (:174-178);
    - Engine3 `reasonTab`/`leafBits` (trunk:lean/BlindLedger/Gate/Engine3/Step.lean:72-79): the leaf bit becomes `2 ^ r.idx`;
    - Python `REASONS` becomes idx-ordered, or gains an explicit idx map, and `_names` decodes by idx (trunk:app/right_rail_gate_decide.py:477,542);
    - `idx_get` (trunk:lean/BlindLedger/Gate/Flat/DecideRows.lean:1669-1673) states `reasons[j].idx = j`, which is false once an idx sits at another name position. Replace it with a density lemma, `∀ j < reasons.length, ∃ r ∈ reasons, r.idx = j`, proved from the dense-idx `#guard` (trunk:lean/BlindLedger/Gate/Rules/Spec.lean:151), and restate `eq_zero_of_has` (:1675-1683) over it;
    - the frame round-trip and `has_maskOf` lemmas that go through `zipIdx`;
    - the host answer parser `_answer` and its `_names` decoding (trunk:app/right_rail_gate_decide.py:626-656, listed under Host below);
    - tests: trunk:tests/test_right_rail_gate_formats.py:320-323 (record reason `1 << 4` and leaf `1 << 24`) and :331 (`leaf-reason-bit-26`), the hostile-frame tests, and every test that builds a reason mask by list position.
    - `conformance/FRAME_V1.md:140,144` ("bit i is reasons[i] … in the byte order of their names") is replaced in the new frame page by "bit `Reason.idx`".
- **Answer side: widths.** Any new rule reason collides with a leaf bit today:
  - Bit 24 is UNENCODABLE_PAYMENT and bit 25 is SCOPE (trunk:lean/BlindLedger/Gate/Flat/Worker.lean:174-178; trunk:conformance/FRAME_V1.md:125-128), and `Leaf.ok` caps reasons at `2 ^ 26` (trunk:lean/BlindLedger/Gate/Frame/Spec.lean:489-490).
  - So a 25th reason lands on bit 24.
  - (A study note said six new codes would fit without a frame change. That is wrong. It is also wrong that a token could need 34 codes: the two leaf-only codes always appear alone.)

  Default fix: answer header version 3 (on top of the §17 answer extension if v2 is used), with:
  - a u64 leaf reasons field (`leAll [1, 8, 1]`, trunk:lean/BlindLedger/Gate/Frame/Spec.lean:495);
  - leaf-only codes at the top of that field: UNENCODABLE_PAYMENT at bit 62, SCOPE at bit 63;
  - rule bits 0-61 by `Reason.idx`;
  - a u64 record reasons field (`encRec`, trunk:lean/BlindLedger/Gate/Frame/Spec.lean:578-581; `Rec.ok` :568-576).

  With this, step 5 and every later rule up to idx 61 need no new answer format.
- **Code.**
  - Frame spec: `Req`, `Pre`, `encodeBody`, `decodePre`, `ctxOf`, `feedsOf` and the round-trip theorems (trunk:lean/BlindLedger/Gate/Frame/Spec.lean:90-104,154-164,267-341,1945-2044). Also `Leaf.ok`, `encLeaf`, `Rec.ok` and `encRec` (:489-497,566-581).
  - The fast decoder and its equivalence proof (trunk:lean/BlindLedger/Gate/Frame/Fast.lean:2431-2442,3031-3051).
  - The model `Feeds` structure (trunk:lean/BlindLedger/Gate/Flat/Model.lean:232) and its `feedsOf` builders (trunk:lean/BlindLedger/Gate/Flat/Worker.lean:80; trunk:lean/BlindLedger/Gate/Frame/Spec.lean:327), which are the view the proofs use (trunk:conformance/ENGINE_V3.md:683-685).
  - `Ix` and `Ix.build` (trunk:lean/BlindLedger/Gate/Rules/Fast.lean:84-113) and their equivalence (trunk:lean/BlindLedger/Gate/Rules/FastEq.lean:383-504).
  - Worker's feed reads (trunk:lean/BlindLedger/Gate/Flat/Worker.lean:250-257) and `leafMask`.
  - Engine3, which hard-codes four feeds and the 384-byte context:
    - `ReadB.feedsW` (trunk:lean/BlindLedger/Gate/Engine3/ReadB.lean:103-123: `o0 := Frame.hdrBytes + 384` and four `feedW` calls);
    - `Step.feedAt` and `feedKnown` (trunk:lean/BlindLedger/Gate/Engine3/Step.lean:330-340: the width table `#[37, 25, 29, 62]` and `Frame.hdrBytes + 384`);
    - `RowsStore.FeedsX` and `FeedsX.decode` (trunk:lean/BlindLedger/Gate/Engine3/RowsStore.lean:341-350) with their proofs;
    - `leafIn` (trunk:lean/BlindLedger/Gate/Engine3/Step.lean:240-257).

    The last re-pin moved `gate_engine` for exactly this kind of feed-reader change (trunk:artifacts/gate-verify/PROVENANCE.txt:124).
  - **Rules/Spec, types only.** The `Elig` and `Soc` structures and their `.fields` pin encodings (from 90ffd3f9:rightrail/lean/BlindLedger/Gate/Rules/Spec.lean:186-200,558-562), with no reasons and no rules, so the frame can decode and pin kinds 7 and 8. This changes Rules/Spec and so Run's digest; the XI.2 record says so.
  - The 1,024-fact cap must cover the two new feeds (trunk:conformance/FLAT_V1.md:123).
  - Replace the hard-coded 24s with `Rules.reasons.length`, now valid because bits are idx-numbered:
    - `idx_lt` and `Lo` (trunk:lean/BlindLedger/Gate/Flat/DecideRows.lean:1603-1683), with `idx_get` replaced as above;
    - `e5` (trunk:lean/BlindLedger/Gate/Frame/Spec.lean:3124).
- **Host.**
  - `REASONS` (idx order, as above) and `FEED_WIDTHS` (trunk:app/right_rail_gate_decide.py:477-484).
  - An explicit feed-to-pin-kind map, so the new feeds get kinds 7 and 8. Appending them would yield kinds 5 and 6, which are RELEASED and UNRESOLVED (trunk:app/right_rail_gate_decide.py:505; trunk:conformance/GATE_RULES_V1.md:75-86).
  - Per-field canonical widths taken from the pin fields. Today the width is `129 if w > 4 else 4` (trunk:app/right_rail_gate_decide.py:502), which does not fit `cents` u64 or the u8 flags.
  - Six descriptors in `_requests` (:546-553).
  - `request_frame` (trunk:app/right_rail_gate_decide.py:510-522): it hard-codes header version 1 and the `FRAME/v1` digest over the body (:522). It moves to the new header version and the §17 digest with the `rd_i` terms (trunk:conformance/ENGINE_V3.md:603-616), or the v2 header if rr-core folds the feeds in.
  - `_answer` (trunk:app/right_rail_gate_decide.py:626-656). Today it refuses any answer whose version is not 1 (:632), reads record and leaf masks as u32 (:641, :652), and refuses a record mask with any bit at or above 24 (:642) and a leaf mask with any bit at or above 26 (:654). Without this change every engine answer after this step is `rules_refused`. It changes to:
    - accept the new answer header version;
    - read the record and leaf reason fields as u64;
    - rewrite the bit-range checks as "every set bit is a rule idx `< len(REASONS)`, or, in a leaf mask only, bit 62 or 63";
    - decode names by idx through `_names` (:542).
  - The feeds builder emits empty elig and soc feeds until there is a source (trunk:app/right_rail_gate_ffs.py:164-171).
- **Spec pages.**
  - A new `conformance/FRAME_V3.md` (or the v2 page from rr-core). Top-level conformance specs are exempt from the doc cap (trunk:tests/test_doc_shape.py:36-39).
  - FRAME_V1.md marked superseded.
  - ENGINE_V3.md §17 and §19 cross-referenced; §19's table gains the two rows.
  - `conformance/MANIFEST.sha256` updated.
- **Re-pins.** The full procedure above, three builds. `gate_verify` does not move as long as `Gate/Spec.lean` is untouched. Existing stores and logs no longer open. That is acceptable while the engine is not activated (trunk:conformance/FRAME_V1.md:300-301).
- **Evidence.**
  - Hostile-frame tests for the new layout (trunk:tests/test_hostile_worker_frames.py).
  - Round-trip theorems.
  - `test_right_rail_gate_formats` updated: the leaf bit-24 case (:320-323) moves to bit 62, the record reason case stays `1 << 4` but now means idx 4 (FFS_DUPLICATE_LINE, unchanged today), and the must-reject `leaf-reason-bit-26` case (:331) moves to a bit that is neither a rule idx nor 62/63 (for example bit 61 with 24 rules, or a mask above 2^64).
  - Test helpers that hard-code the v1 frame digest or the v1 answer header, updated to the new versions: trunk:tests/test_decode_fuzz.py:22, trunk:tests/test_gate_authority_frames.py:91, trunk:tests/test_flat_worker.py:90, trunk:tests/_gate_bars.py:102 (`FRAME/v1` digest), and trunk:tests/test_right_rail_gate_decide.py:44, trunk:tests/test_flat_host.py:271 (`RRDA` version 1 answers).
  - Host tests for the rewritten `_answer` checks: a u64 record or leaf mask with a rule idx bit is accepted, bit 62/63 is accepted only in a leaf, and any other bit is refused.
  - Throughput digests re-checked (trunk:tests/test_gate_throughput.py:35-48). `PAIRS_DIGEST` must not move in this step: no decision changes.
  - `test_history_growth` (SQLite pin trunk:tests/test_history_growth.py:55, asserted at :234) runs if Decision 16 installed SQLite 3.53.1; otherwise it is on the "not run here" list for the owner's explicit acceptance.
- **Build cost.** Three full builds of the Gate tree, the TCB live run (3-5 GB, trunk:tests/test_tcb_gate.py:5,208) and the statement-pin run (up to 1,800 s per Lean call, trunk:tests/test_statement_pin.py:45). Expect one to three weeks of machine time, plus proof authoring.

### Step 3. G2 on the trunk

- **Rules (Rules/Spec).**
  - Five reasons appended as constructors, with `Reason.idx` assigned in name order as step 4 does for G4 (trunk:lean/BlindLedger/Gate/Rules/Spec.lean:131-151):
    - idx 24: BENEFIT_LEVEL_MISSING;
    - idx 25: BENEFIT_LEVEL_MISSING_UNVERIFIED;
    - idx 26: PROGRAM_NOT_ELIGIBLE;
    - idx 27: PROGRAM_NOT_ELIGIBLE_UNVERIFIED;
    - idx 28: STALE_ELIGIBILITY.

    Because step 2 numbered answer bits by idx, no existing frame bit moves.
  - The rest of the rules changes:
    - the name-ordered `reasons` and the dense `#guard` (:151);
    - `bypassable` per Decision 12 (:153-160), with the count `#guard` at trunk:lean/BlindLedger/Gate/AuthorityLaws.lean:478 changed from 15 to 18;
    - the `review` arms for BENEFIT_LEVEL_MISSING_UNVERIFIED, PROGRAM_NOT_ELIGIBLE_UNVERIFIED and STALE_ELIGIBILITY. Today `review` ends in `| _ => false` (trunk:lean/BlindLedger/Gate/Rules/Spec.lean:390-395), so an unlisted review code would silently HOLD against decision 6;
    - the `fires` cases, `Ctx.eligibility`, `okElig`. `Elig` and `.fields` are already there from step 2.
- **Rules (Rules/Run).** G2's review-completeness guard, `#guard reasons.all fun r => review r || !((name r).endsWith "_UNVERIFIED" || (name r).startsWith "STALE_")` (G2_DESIGN.md:172,179-181), goes in Rules/Run.lean next to the name-order guard at trunk:lean/BlindLedger/Gate/Rules/Run.lean:47. It cannot go in Rules/Spec: it uses `name`, defined only in Run (trunk:lean/BlindLedger/Gate/Rules/Run.lean:43), and Run imports Spec. It changes Run's hashed source, and the XI.2 record says so.
  - The rule bodies and theorem statements are ported from f16a61f4.
- **Per-payment bound (option 1, RB D8).** Not deferred.
  - Port `Bits`, `bitsOf`, `may`, `may_sound`, `decideAll_may`, `budget` (with the private `budget_bool`), `headroom_le`/`headroom_eq` and `pay_budget` into trunk:lean/BlindLedger/Gate/Rules/Theorems.lean after `mem_decideAll` (:297-305), as REASON_BOUND_DESIGN.md sections 4-5 and its proof list describe, with `may` covering the 24 trunk reasons and the five G2 reasons.
  - Add the payment/leaf corollary next to `leafReasons_codes` (trunk:lean/BlindLedger/Gate/Flat/PayTheorems.lean:62): every payment's leaf carries at most `maxReasonCodes` (32) rule codes. It uses a `Run.name` injectivity lemma (today only a `#guard`, trunk:lean/BlindLedger/Gate/Rules/Run.lean:47). This replaces the StateV2 corollaries of the October design.
  - No total-count guard is added: no `#guard Rules.reasons.length ≤ Gate.maxReasonCodes`, honouring option 1 and D8. The trunk has none today (`maxReasonCodes` appears only at trunk:lean/BlindLedger/Gate/Spec.lean:32,483 and trunk:lean/BlindLedger/Gate/PublishFast.lean:92).
  - Axiom pins for the new theorems.
  - A test that Python `REASONS` matches the Lean list by name and idx, because names become text in Python (trunk:app/right_rail_gate_decide.py:542).
  - If the trunk payment corollary needs more than RB's estimate, it may move to step 4; `Bits`/`may`/`budget` stay in step 3 either way.
- **Fast deciders and their equivalence (the bulk of the work).**
  - `Flat/DecideRows`: the `Lay` per-feed flags (trunk:lean/BlindLedger/Gate/Flat/DecideRows.lean:205-208) gain the eligibility flags; one `on … bX` mask term per new reason (:351-363, :1995-2005); the `outOf_eq`/`has_maskOf` lemmas; the tie to `Ix.fires` (:2015, :2073); and the `decideRows` equivalence with `reasons.filter (has d.mask ·)` (:3302-3303, :3823).
  - `Rules/Fast` `Ix.fires` twin and `Rules/FastEq` (kept decision-rule modules, trunk:conformance/ENGINE_V3.md:598).
  - Engine3 row decider and assembly (`Rows.bit`, the eligibility feed lookup).
- **Authority.**
  - `reasonMask` becomes 2^29 (trunk:lean/BlindLedger/Gate/Authority.lean:20; docstring :19).
  - `reasonMask_eq` changes (trunk:lean/BlindLedger/Gate/AuthorityLaws.lean:25).
  - The "bit beyond the reasons" guard `#guard !bv (bx (2 ^ 24) [a1, a2])` (trunk:lean/BlindLedger/Gate/AuthorityLaws.lean:491) becomes `2 ^ Rules.reasons.length`. Once G2 lands, 2^24 is a real reason bit, whichever reason holds it (here BENEFIT_LEVEL_MISSING), so the guard would no longer test a bit beyond the reasons. Because idx 24 is non-bypassable (Decision 12), the old guard would keep passing silently while testing the wrong thing.
  - APPROVAL/v2 grant and override fields then accept bits 24-28 (Decision 10).
- **Host answer check.** The host `_answer` record and leaf checks rewritten in step 2 (trunk:app/right_rail_gate_decide.py:642,654) must accept bits 24-28 once `REASONS` gains the G2 codes; a host test asserts that a record mask with bit 28 is accepted and bit 29 is refused.
- **Runner.**
  - Row parsing for `elig`.
  - `RULES_READS` moves to `READ-SET/v5` with five slots: the four trunk kinds plus kind 7 (trunk:lean/BlindLedger/Gate/Rules/Run.lean:598-604; one slot per pinned kind).
  - `tools/gate_rules_data.py` `KINDS`/`WIDTHS`.
  - `tests/test_gate_rules_vectors.py` (:16-25, :83, :143-179).
- **Tags.**
  - `READ-SET/v5`, five slots: new. It skips the October v3 and v4 by choice.
  - `READ-ELIGIBILITY/v2` and SNAPSHOT/v1 kind 7: kept.
  - No READ-MANIFEST or SNAPSHOT/v3 change. Both tags are in the engine's import closure (through SnapshotV2), but the decide path reads neither: the worker builds its context from the four SNAPSHOT/v1 feeds through `snapF` (trunk:lean/BlindLedger/Gate/Flat/Worker.lean:250-257), and the rules read set uses only `READ-SET/v2` (trunk:lean/BlindLedger/Gate/Rules/Run.lean:602).
- **Contract.** STALE_ELIGIBILITY fires when the feed is absent, so every v1 answer changes. Published vector files are immutable (trunk:conformance/README.md "Versioning").
  - New `conformance/GATE_RULES_V2.md` and `gate_rules_v2_ref.py`, written from the page alone.
  - `rules_v2.vectors`, `demo_zz_v2.vectors`, `rules_v2_negative.vectors`, `.expected` from the exe.
  - A v2 spec test.
  - v1 retired with its manifest lines. Retiring deletes its vector files (trunk:conformance/README.md:66), including `rightrail/tests/gate_rules/rules_v1.vectors`.
  - These names do not collide on the trunk. Our October `rules_v2.vectors` lived only on our branch.
- **Parity harness (localBCE side, same commit; Decision 13).** Before v1 is deleted, copy it outside `rightrail/` as a frozen fixture (for example `tests/fixtures/rightrail_rules_v1.vectors`) with a sidecar recording its source path, trunk commit and SHA-256 (`15aef4c9…`, full value in the sidecar). Point `DEFAULT_VECTORS` (scripts/g_rule_parity.py:38-39 on the step 0 branch) at the copy. Any self-check or CI line that names the old path changes with it.
- **Evidence beyond the contract.**
  - ALLOW-path fixtures get usable eligibility feeds. Once STALE_ELIGIBILITY fires on an absent feed, every engine ALLOW flips to HUMAN_REVIEW. Affected: trunk:tests/test_right_rail_gate_ffs.py (ALLOW asserts at :77, :484, :528, :554 and others), test_gate_authority_frames.py, test_engine3_recovery.py, test_flat_host.py, test_right_rail_gate_shards.py, and the shared builders `app/right_rail_gate_ffs.py` feeds, `tests/_gate_shards.py` and `tests/_gate_bars.py`.
  - `PAIRS_DIGEST` and `OUTPUT_DIGEST`/`REALISTIC_DIGEST` (trunk:tests/test_gate_throughput.py:40-48) are recorded as protected changes with their own XI.2 justification: the trunk says a re-pin must keep `PAIRS_DIGEST`, and this step changes decisions on purpose.
  - Most of these tests need the ML-DSA-87 signer. Without Decision 16 they cannot run here and go on the "not run here" list for the owner's explicit acceptance.
- **Mutation evidence (Decision 7).** The 19 G2 mutants: the 18 killed by vectors in October become in-Lean `Mutant:` definitions with killing `#guard` pairs, in a module that `gate_engine` does not import (the trunk's style, trunk:lean/BlindLedger/Gate/AuthorityLaws.lean:494-506; trunk:lean/BlindLedger/Gate/Scoped.lean:463). The one killed only by a proof (b5f806df:docs/integration/LOG.md:244-245) cannot be killed by a `#guard`: it is a one-off scratch-copy build under the guard whose failure is recorded in the commit message (RB D13 style).
- **Pins.**
  - The new theorems are added to `tools/gate_print_axioms.lean`.
  - The full re-pin procedure, three builds, then STMT_PIN regen.
  - Add an `input_file` in `lean/lakefile.toml` for any embedded file (trunk:tests/test_gate_rules_vectors.py:49-67).
- **Host and tables.**
  - `REASONS` and one `app/cause_actions.json` row per new code (trunk:tests/test_cause_actions.py:114-115).
  - Scoped/Consume kind maps only if the signed path is extended (Decision 5: no).
- **Docs inside the trunk.** STATUS.md, edited once (trunk:AGENTS.md:20), and ARCHITECTURE.md.
- **Checks for this commit.** The step 2 list, plus: the parity harness on the frozen v1 copy, `test_gate_rules_vectors`, the v2 spec test, `test_cause_actions`, `test_conformance_manifest`, the in-Lean mutant module, and localBCE `cargo test` and `cargo check`.
- **Build cost.** Proof-repair dominated: DecideRows, FastEq and Engine3 equivalence work on top of three full builds. Comparable to step 2 or larger: one to three weeks of machine time.

### Step 4. G4 on the trunk

- Same shape as step 3.
  - Three reasons with idx 29-31: SHARE_OF_COST_UNMET, SHARE_OF_COST_UNMET_UNVERIFIED, STALE_SHARE_OF_COST.
  - `review` arms for SHARE_OF_COST_UNMET_UNVERIFIED and STALE_SHARE_OF_COST; the review-completeness `#guard` in Rules/Run from step 3 covers them.
  - The host `_answer` checks accept bits 29-31.
  - `bypassable` per Decision 12; the count `#guard` goes from 18 to 20.
  - `may` and `Bits` extended for the G4 source; `budget` and `pay_budget` re-checked. If the payment corollary moved here from step 3, it lands now.
  - DecideRows `Lay` flags and mask terms, Rules/Fast plus FastEq, and Engine3 assembly for the share-of-cost feed, as in step 3.
  - `reasonMask` becomes 2^32. The `holds` and override fields are read with `nat 4`, so 32 bits still fit (trunk:lean/BlindLedger/Gate/Authority.lean:89,107).
  - `RULES_READS` moves to `READ-SET/v6` with six slots (adds kind 8). A new tag, because the slot layout changes.
  - `READ-SHARE-OF-COST/v2`, kind 8.
  - The 25 G4 mutants: 24 as `#guard` pairs, 1 proof-killed as a scratch-copy build recorded in the commit message (b5f806df:docs/integration/LOG.md:260-261).
- **Contract.** Extend the GATE_RULES_V2 files from step 3 in place, provided nothing has been published between steps 3 and 4 (Decision 11). This follows the G6 in-place precedent (trunk:conformance/README.md).
- **Evidence.** As step 3: ALLOW-path fixtures gain usable share-of-cost feeds; `PAIRS_DIGEST`/`OUTPUT_DIGEST` changes recorded as protected changes with XI.2; signer-dependent tests run only with Decision 16; the parity harness on the frozen v1 copy.
- **Operational effect.** Until a producer emits eligibility and share-of-cost feeds, every line goes to HUMAN_REVIEW on STALE_ELIGIBILITY and STALE_SHARE_OF_COST. That is fail-closed, and it means the gate releases nothing without review.
- **Build cost.** Like step 3: proof-repair dominated, three full builds.

### Step 5. Reason widths past 32: the prerequisite for G5 to G10

- G5's first new reason is idx 32.
- POSTING_CAP takes the October plan's last spare code, so the approved G5, G6 (shared `_UNVERIFIED`), G8 and G10 (3-code) shapes reach a classification maximum of 33 per payment, against a proved bound of 32. Per RB D12 and Decision 14, the flow fact (RB D4) comes first: proving that every line of a payment shares the request flow removes one code and brings the maximum to 32.
- The answer format does not change: step 2 already numbers bits by idx in u64 fields with the leaf-only codes at 62 and 63.
- This step needs:
  - UInt64 line masks in DecideRows and Engine3 `Rows.bit` (today UInt32, trunk:lean/BlindLedger/Gate/Flat/DecideRows.lean:1675);
  - an APPROVAL/v3 with 8-byte masks, since `reasonMask` passes 2^32;
  - the flow fact;
  - for each later rule, extending `Bits` and `may` with its source and re-checking `budget`. The bound itself is already proved from step 3; there is no restart.
- `maxReasonCodes` and TOKEN/v2 stay, so `gate_verify` is not re-pinned. That is the point of the owner's option 1.

### Step 6. The remaining Phase 3 rules: G5's new conditions, then G6, G8 and G10

Each rule gets:
- a design document in the approved shape (G5 and G6: one shared `_UNVERIFIED` per source; G8 and G10: 3-code);
- owner approval;
- one protected commit in the step 3 shape, including `review` arms, `bypassable` choices and the `may` extension;
- its own feed or request data, through a frame version (the answer format stays).

G6 note: the trunk already sets aside zero, fractional or missing units on the host (cause `units`, trunk:app/right_rail_gate_ffs.py:68-72). Only the billing-code table part is new.

G8 and G10 need claim-side data that the request does not carry. Diagnoses are not passed (trunk:app/right_rail_gate_ffs.py:77-79). So each of them is also a request-format change.

Any rule after G10 needs the flow fact first, then a shape review (RB D12).

### Step 7. Phase 4, adjusted to what the trunk provides

- **837 adapter.** Dropped as a port.
  - The trunk's reader (trunk:app/right_rail_x12_837.py) and request builder (trunk:app/right_rail_gate_ffs.py:43-90) are stronger than ours (blind-ledger-app-layer/app/ingestion.py:17-58).
  - A second 837 module would break CONST IX.1 (trunk:CONSTITUTION.md:129).
  - What remains is a test-only fixture converter outside `rightrail/`: `claim_input.json` to a synthetic 837/834/LEIE set. The parity harness can then run end to end through `decide_claims` (trunk:app/right_rail_gate_ffs.py:201-251).
- **Lean decides payments.** Already true for FFS_CLAIM on the trunk (trunk:STATUS.md:126-132). This row shrinks to Phase 3.
- **Retire the bridge.**
  - Retire the adjudication half, because the sealed checkpoints and tokens are the record.
  - Retire the remittance half too, with no replacement for now. The trunk 835 reader exists but is not wired (trunk:STATUS.md:206).
  - Restate the "single writer" check: the bridge is not a writer, and only `FinancialOwner` and the gate producers write (trunk:ARCHITECTURE.md:30,46; trunk:app/right_rail_gate_producer.py:1).
- **Retire Rust.** Unchanged in kind, after Phase 3 parity. Re-run the G7/R4 parity row once the trunk builds I.4.
- **Entry point.** Nothing in the trunk calls the 837 path outside tests (trunk:STATUS.md:20-21). Wait for upstream; do not build our own.

## Existing branches and pull requests

Nothing is deleted. docs/integration/GOVERNANCE.md requires a CLEANUP_PROPOSAL entry for deletions, and none is proposed.

| Branch or PR | Head | Default |
|---|---|---|
| PR #7, `codex/rightrail-base-phases` into `integration/rightrail` | dc586d87 | **Keep and merge** after review. Phases 1-2 do not depend on the RightRail version. Step 0 branches from it. |
| PR #8, `codex/rightrail-g2` into base-phases | aa826750 (G2 f16a61f4) | **Close unmerged** with a comment pointing to step 3. Keep the branch as the record of the October implementation. |
| PR #9, `codex/rightrail-g4` into `codex/rightrail-g2` | 7fa9c383 (G4 90ffd3f9) | **Close unmerged** in the same way. Keep the branch. |
| `codex/rightrail-reason-bound` (pushed, no PR) | b5f806df | **Keep as record, open no PR.** Its Rules/Theorems part is ported in step 3. Its StateV2 proofs are replaced by the trunk payment corollary. |
| New `codex/rightrail-trunk` | | Steps 0-4 as one draft PR into base-phases, or into `integration/rightrail` once #7 merges. One commit per step. |

Merging #8 and #9 first would add October-only code that step 0 replaces anyway, plus 15,073 vector lines that would then be deleted. Closing them keeps the record without that churn.

The design docs and LOG entries reach the new branch in step 0.

## Risks

- **No history.** Without `fc89f9e5` history, nothing can go upstream as a pull request. XI.2 records then rest on a zip hash.
- **Upstream moves.** The I.4 amendment and frame version 2 (specified in ENGINE_V3 §17/§19, unbuilt) are both pending upstream and touch the same surface. A trunk that moves during steps 2-4 means a second migration. Building our own v2-plus-two-feeds may also mean carrying ENGINE_V3 §20 steps 1-2.
- **Reproducibility.** If step 1 cannot reproduce the pinned `gate_engine` bytes, our re-pins are local-only evidence. If our own three builds disagree under emulation, no re-pin is possible until the owner decides (Decision 8).
- **The guard.** The interim guard is not the real `rr_guarded.ps1` v7 (trunk:CONSTITUTION.md:160).
  - The trunk's 3.75 GiB floor is often above the free memory here.
  - The TCB live test wants 3-5 GB.
  - Every run is interim evidence.
- **Cannot be done on this machine as it stands:**
  - the ML-DSA-87 signer tests and `test_history_growth`, unless Decision 16 installs a Rust toolchain and SQLite 3.53.1; otherwise each step commits over a "not run here" list that the owner accepts explicitly;
  - the real guard;
  - upstream CI. The trunk has none: "merge evidence, not release qualification" (trunk:STATUS.md:16).
  - rr-core authorship and rr-review review (the owner stands in, docs/integration/RIGHTRAIL_BASE_PLAN.md:138-145).
- **Proof work.** The frame codec, fast-decoder, DecideRows and FastEq proofs are large. The emulated build makes every repair loop slow, and each step needs three builds.
- **Every line goes to review.** After step 4, every line goes to HUMAN_REVIEW until real eligibility and share-of-cost feeds exist.
- **The rule budget.** The per-payment bound is 32. At the approved shapes, G10 needs the flow fact (step 5) first.
- **An earlier assessment error.** The assessment's §6 item 5 is wrong: `factsDigest` has no caller (trunk:lean/BlindLedger/Gate/Rules/Run.lean:258-260). The feeds bind into a checkpoint through the frame body's `CONTEXT/v1` digest. A plan built on that item would have pinned the wrong thing.

## Decisions for the owner

Each decision has a recommended default that can be approved with one word.

1. **Target commit and how to import it.** Ask the maintainers for a `fc89f9e5` bundle. If none arrives, use the zip snapshot (variant B) and join histories later. Default: **yes**.
2. **The frame route.** Ask rr-core to carry eligibility and share of cost in frame version 2 (ENGINE_V3 §17/§19). If they decline, build `FRAME/v3` as the specified v2 plus two feeds (v2 digest and §19 rows), header version 3, with `CONTEXT/v2`, and report first if that means carrying ENGINE_V3 §20 steps 1-2. A v3 over the FRAME_V1 body, diverging from §17, only by a separate explicit owner word. Not FactRegistry, not the signed path. (This answers the assessment's question 2.) Default: **Route A**.
3. **Version tags.** (This answers the assessment's question 3.) Default: **approve**.
   - `READ-SET/v5` with five slots at step 3, `READ-SET/v6` with six slots at step 4;
   - no READ-MANIFEST change, with READ-MANIFEST/v6 reserved for a future signed path;
   - `SNAPSHOT/v4` reserved;
   - kinds 7 and 8 and `READ-ELIGIBILITY/v2` / `READ-SHARE-OF-COST/v2` kept;
   - answer header version 3, with u64 leaf and record reason fields and leaf-only codes at bits 62 and 63.
4. **Answer bit numbering.** Number frame record and leaf bits by `Reason.idx` from step 2 (`maskOf`/`unmask`, `reasonBits`, Engine3 `reasonTab`, Python `REASONS`/`_names`, tests), replacing `idx_get` with a density lemma, rather than by name position with a frame version bump at each rule step. Default: **idx**.
5. **Leave the signed-snapshot path (Scoped/Consume) at four kinds for now.** Keep the names consistent so it can absorb the new kinds later. Default: **yes**.
6. **The per-payment bound on the trunk.** (This answers the assessment's question 5.) Port `Bits`/`may`/`may_sound`/`budget`/`pay_budget` into trunk Rules/Theorems.lean at step 3, and the payment/leaf corollary next to `leafReasons_codes` at step 3 (step 4 at the latest). No total-count guard at any step, as option 1 and RB D8 require. Keep b5f806df as the record. Default: **port**.
7. **Mutation evidence.** (This answers the assessment's question 4.) Vector-killed mutants as in-Lean `Mutant:` definitions with killing `#guard` pairs in a module outside `gate_engine`; the proof-killed ones (one G2, one G4) as one-off scratch-copy builds recorded in the commit message. Do not port `gate_rules_mutants.py`. Default: **in-Lean**.
8. **Reproducibility.** If step 1 cannot reproduce the pinned `gate_engine` bytes, continue with local re-pins labelled "built locally, not byte-matched upstream", and ask upstream for a reproduction. If our own in-tree build and two stage builds disagree, that is a failed check: stop before `-Regen`, record all three hashes, and re-pin only on the owner's explicit word. Default: **continue**.
9. **Running the TCB pin.** At steps 2, 3 and 4, run the trunk procedure's equivalent through the interim guard and record it as interim evidence: two fresh `git archive` stage builds byte-matched with the in-tree build; then `RR_TCB_LIVE=1` and `RR_TCB_REGEN=1` with `tests.test_tcb_gate` run through `scripts/rr_guarded_interim.ps1` at the 1.5 GiB floor; then the same run with `RR_TCB_REGEN` empty as the check. `tools/tcb_pin.ps1` itself is not run, because it calls an absent guard path at a 3.75 GiB floor (trunk:tools/tcb_pin.ps1:5-6). Do not edit the trunk script. Keep the 1.5 GiB floor and 6,144 MB job cap. Raise the timeout to 24 hours for full builds. Default: **yes**.
10. **Widening APPROVAL/v2 in place.** Keep APPROVAL/v2 and widen its accepted mask range in place, with an XI.2 record, up to 32 bits (anticipated at trunk:lean/BlindLedger/Gate/Rules/Spec.lean:131-135). Use APPROVAL/v3 only at step 5. Default: **yes**.
11. **The gate rules contract.** Use one new GATE_RULES_V2 contract that covers G2 and G4 together, extended in place at step 4 because nothing is published between the two steps. Retire v1. Default: **yes**.
12. **Bypassable new codes.** A signed two-approver bypass may release a line held only on stale or unverifiable eligibility or share-of-cost data, like their R1/R3/R5 analogues (trunk:lean/BlindLedger/Gate/Rules/Spec.lean:155-160): STALE_ELIGIBILITY, PROGRAM_NOT_ELIGIBLE_UNVERIFIED, BENEFIT_LEVEL_MISSING_UNVERIFIED (step 3, count guard 15 to 18), STALE_SHARE_OF_COST, SHARE_OF_COST_UNMET_UNVERIFIED (step 4, 18 to 20). The certain codes PROGRAM_NOT_ELIGIBLE, BENEFIT_LEVEL_MISSING and SHARE_OF_COST_UNMET are not bypassable: a line the data says is ineligible or unmet must be fixed at the source. This is stricter than the trunk, where the certain codes MEMBER_DECEASED, MEMBER_NOT_ENROLLED and PROVIDER_* are bypassable. Default: **yes**.
13. **The parity harness after v1 retires.** Keep a frozen copy of the v1 vectors outside `rightrail/` with its source path, commit and SHA-256, and repoint `scripts/g_rule_parity.py` to it in step 3; run the harness in steps 3 and 4. Default: **freeze**.
14. **Headroom past 32 per payment, for step 5.** Prove the flow fact first (RB D4, as RB D12 requires), and keep 3-code G8 and G10 (RB D5) and shared `_UNVERIFIED` G5 and G6 (RB D6). Two-code G8 and G10 is only available as an explicit reversal of RB D5, and it drops the review code for a present but unusable snapshot. Default: **flow-fact**.
15. **Branches and pull requests.** Merge #7, close #8 and #9 as record, open no PR for reason-bound, and open a new `codex/rightrail-trunk`. Default: **yes**.
16. **Test runtimes before step 1.** Install a Windows Rust toolchain (for the ML-DSA-87 signer and its gate tests) and SQLite 3.53.1 for the test runner (for `test_history_growth`) before step 1. Both are downloads and need the owner's approval when they happen. If declined, those tests are "not run here" and each step's commit needs the owner's explicit acceptance of that list. Default: **install**.
17. **Where IMPORTED_FROM lives.** Move it out of `rightrail/` to `docs/integration/RIGHTRAIL_IMPORTED_FROM.md`, rather than adding a trunk `OWNERS` entry, and update `scripts/integration_selfcheck.sh` to read it and check `fc89f9e5` (or the zip SHA-256). Default: **move**.
18. **The pending I.4 change upstream.** If upstream builds I.4 before step 3 starts, import that commit instead. Otherwise proceed and re-run the G7 parity row later. Default: **wait-if-soon**.
19. **Phase 4.** Drop the 837 port. Add a test-only fixture converter. Retire both halves of the bridge. Restate "single writer" as "the bridge does not write". Default: **yes**.
