# Handoff: localBCE on the RightRail trunk (2026-11-23)

Written for whoever takes this work over on another machine. It says where the work stands, what is and is not on GitHub, what to do first, and the rules the work has been done under. The running record is `LOG.md`; this page is the entry point.

## 1. Read this first

- **The maintainer answered the five questions on 2026-11-23. Read section 5 before anything else: the answers supersede parts of sections 2 to 4.** In short: move onto `e5d0f36b`; take trunk's decision answer version 4 and drop ours; eligibility is a signed rule-set v2 pack reading the fact store, not a fixed rule and not extra feeds.
- **Do not continue on the current base.** The work sits on RightRail trunk `fc89f9e5` (2026-11-14). Upstream `rightrail-main` was at `af4c7c52` on 2026-11-22, 560 commits ahead, and at `e5d0f36b` on 2026-11-23. The RightRail maintainer has asked that localBCE move onto the current trunk before any further wiring.
- **Nothing is live.** No payment decision goes through RightRail. localBCE still decides with its own Rust rules. `proof_execution_enabled` is false and stays false.
- **Repository visibility.** `github.com/coder-sys/localBCE` is public. `github.com/RightRail/rightrail` is private. This repository holds RightRail code under `rightrail/` and RightRail history up to `af020b26` (2026-10-15). Whether that is intended is the RightRail owner's call and was raised with the localBCE owner on 2026-11-23; check the outcome before pushing more RightRail code or history here.

## 2. Where the work stands

Active branch: `codex/rightrail-trunk-step3` (pushed). Plan: `TRUNK_MIGRATION_PLAN.md`, steps 0 to 7.

| Step | State |
|---|---|
| 0. Import the trunk | Done at `fc89f9e5` (zip snapshot, commit `70b4e4b6`). Must be redone at the new trunk. |
| 1. Baseline build and tests | Done at `fc89f9e5`. Must be redone. A baseline of the unmodified new trunk was started on the old machine and did not finish (section 4). |
| 2. Frame and width change | Answer side built (`19e001c7`, `9330572b`). Request side: stage S0 host draft only (`36fb3603`), not called by production. Parts need redoing (section 3). |
| 3. G2 (eligibility) | Part (a), the rule logic, reasons and rules v2, is built (`bbd0e947`). Part (b), the feed wiring, and part (c), the signer-dependent regeneration, are not. Six supporting proof commits are in (`379b487c`..`845e7b9c`). |
| 4. G4 (share of cost) | Designed only (`G4_DESIGN.md`, on the October base). |
| 5 to 7 | Not started. Step 7 is the live wiring. |

Outside `rightrail/`: the eligibility snapshot builder `scripts/elig_snapshot.py` with 75 tests (`2205b5cb`), test-only.

Rule parity today (`G_RULE_PARITY_REPORT.md`): of 265 shared test lines the two systems agree on 140. G2, G4, G6, G8 and G10 have no RightRail rule yet.

Seven `rightrail/` checks are knowingly red on this branch and were accepted by the owner: the statement pin (2), `tcb_gate` (2) and `gate_rules_worker` (3). They compare against pins that G2 (a) moved and that were deliberately not re-pinned. On the new trunk every one of those pins is replaced, so do not fix them on `fc89f9e5`.

Owner decisions recorded on 2026-11-21 (all in the design documents and `LOG.md`): one combined re-pin for the step 2 request side and G2 (b); a two-form replacement decision check; the test-header split extended to eligibility rows. The trunk move makes these need re-approval in a new form (section 3).

## 3. What the trunk move does to this work

Full text: `TRUNK_MOVE_ASSESSMENT.md` and its adversarial review `TRUNK_MOVE_ASSESSMENT_REVIEW.md`. Read the review; it corrects the assessment in several places. No build was run for either, so every "compiles" or "proof closes" claim in them is from reading source.

In short:

- **Answer version 3 is taken upstream** (the fact answer, `RRDA`). The localBCE decision answer needs a new number from the maintainer. The answer-side commit `19e001c7` must be redone on upstream's changed leaf.
- **The request design localBCE built on was withdrawn upstream.** ENGINE_V3 section 17's per-feed digest form "was never built"; upstream request version 2 is one hash over the body. The S0 draft's digest and walk code is dropped; its six-descriptor layout idea survives.
- **Upstream built an eligibility fact intake that no rule reads.** Its newest rule work (signed rule sets) still reads the four per-request feeds. Snapshot kinds 7 and 8 are still free. Upstream's intent for a G2-style rule is unknown; this is question 4 in section 5.
- **Upstream's `pack1_fires` theorem goes false** when G2 is added to `Rules.fires`. How to fix it is the maintainer's design choice.
- **Reason bits.** localBCE's five G2 reasons sit at idx 24 to 28; upstream's leaf-only codes are at bits 24 and 25 with leaves bounded at 2^26.
- **Every pin moved** and there is a fourth pinned program. The signer pin did not move.
- **Trial merge** of localBCE's `rightrail/` changes against `af4c7c52`: 24 conflicted files of 78 changed. The heaviest are `app/right_rail_gate_decide.py`, `lean/BlindLedger/Gate/Frame/Spec.lean`, `conformance/ENGINE_V3.md` and four `Engine3` Lean files.
- **Staging the move is not clean.** The answer side, G2 (a) and the S0 draft merge as one tree; holding them back means backing them out on the new branch, which needs the owner's word. The six proof commits also name constants from the answer-side commit.

## 4. First jobs on the new machine

1. Clone `github.com/coder-sys/localBCE` and check out `codex/rightrail-trunk-step3`.
2. Get access to `github.com/RightRail/rightrail` (private). The localBCE owner has admin rights there.
3. **Baseline the unmodified new trunk before touching this repository.** Clone RightRail, check out `e5d0f36b` (the maintainer's answer 1; it uses Lean v4.36.0, not v4.33.1), build with `lake build` in `lean/`, and run the test suite. This was under way on the new machine on 2026-11-23 (clone at `C:\work\rightrail`, about 329 of 516 build jobs done with no failures when last seen). On the old machine (16 GB, Windows on ARM64) this build was stopped three times by the memory guard: it reached 57 of 231 Lean modules with no errors, at a peak of 3.1 GiB for the build itself. The old trunk's build peaked near 5 GiB. Nothing from that partial build is worth transferring.
4. Download the signer from the RightRail release `signer-a1a6e9e4` (`rr_gate_mldsa87.exe`, 1,671,680 bytes). Check its SHA-256 equals `a1a6e9e45b11be50792fe2f797fb4510d892662cec652a65c92a238e15686141` (the pin in `rightrail/rust/gate_mldsa87/rr_gate_mldsa87.sha256`) before placing it at `rust\gate_mldsa87\target\release\`. `app/right_rail_gate_signer.py` refuses any other binary.
5. Make a test signing seed with the signer's keygen command. RightRail's own handoff notes say the seed is bound to the Windows account that made it and cannot be moved between machines. This was not tried on the old machine.
6. Only then plan the move, with the maintainer's answers in hand.

Tools: Lean through elan (toolchain `leanprover/lean4:v4.33.1`; the Lean project has no outside packages), Rust, Python 3.11 or newer, git, the GitHub CLI. On the old machine all git ran inside WSL because Windows had no git, Rust or MSVC; several test groups could not run there for that reason and because it is ARM64. A standard x64 Windows machine should run more of the suite; that is not verified.

## 5. The maintainer's answers (2026-11-23)

The questions in `RR_MAINTAINER_QUESTIONS_DRAFT.md` were sent and answered on 2026-11-23. The answers below are as relayed by the localBCE owner. localBCE has not checked them against the tree, except that a build of `e5d0f36b` on the new machine did select Lean v4.36.0. Verify each against `e5d0f36b` before building on it.

1. **Commit.** Move onto trunk `rightrail-main`, `e5d0f36b`. `af4c7c52` is an ancestor. Pins and the TCB report were regenerated after it (Lean 4.36 re-pin, X12 reader re-pin, throughput digests). Signed rule sets and fact frames have merged. Do not base on anything newer that is still marked WIP.
2. **Answer version.** Already on trunk: the decision answer is version 4, with u64 reason masks and 20-byte records (`conformance/FRAME_V1.md` section 8, change record 2026-11-22). Version 3 stays the fact answer (RRDA). Drop localBCE's version 3 and take trunk's, with its tests (`tests/test_gate_answer_v4.py`) and golden vectors.
3. **Reason bits.** A reason's bit is its number and never moves. The leaf-only codes are bit 62 (UNENCODABLE_PAYMENT) and bit 63 (SCOPE). localBCE's five eligibility reasons at 24 to 28 match the numbers trunk uses. Rule reasons can go up to 61, so share of cost (29 and up) fits with no more widening.
4. **Eligibility data.** Neither extra feeds nor kinds 7 and 8. Rule set v2 (`conformance/RULESET_V2.md`) reads eligibility belief from the fact store: it adds source 7, an aid-code table and an ELIG condition node; the read is `elRead` in `lean/BlindLedger/Gate/RuleSet/Spec.lean`. The engine does not carry that read yet, so `runnable` is false for v2. The ELIG fact carries status and aid code only; there is no benefit level and no share-of-cost fact in the tree. Whether to add them is for the RightRail founder to decide; do not build them as feeds meanwhile.
5. **`pack1_fires`.** Do not add the eligibility rule to `coreFires`. The fixed rules never set reasons 24 to 28; only a signed rule set may (`FRAME_V1.md` section 4). Eligibility goes in as a rule-set v2 source and pack.

Smaller answers:

- Section 19 sorted rows are designed (`ENGINE_V3.md` section 19, revision 2) but not built. They will change the feed strides; hold off on six-feed frames until they land.
- Keep the name `GATE_RULES_V1` and amend it in place under a dated change record. Revert localBCE's V2 rename.
- The links-file tail keeps its 4-byte reasons field, and a record whose reasons do not fit is refused (`tailsOf`). So a reason at 24 to 28 cannot reach the links file yet; it has to widen before rule sets can emit those reasons. That is a protected wire-format change: draft it, but do not merge it without a change record and the founder's approval.
- Whether localBCE carries the newer history and sends changes back as pull requests is for the founder to decide. The FLAT_V1 doc fix can be sent as a pull request against trunk.
- The fact-record design is in the private repository `RightRail/rightrail-workspace` under `designs/` (`fact-record-20261108.md`, with one-store, resharding, root-rotation and an `INDEX.md` that says which designs are current).

What the answers do to localBCE's work (the localBCE side's reading, not the maintainer's words):

- **Dropped:** the answer-side commit `19e001c7` (take trunk's version 4); the S0 request-side draft `36fb3603`, the planned Lean request side and kinds 7 and 8; G2 as fixed Lean in `Rules.fires` (`bbd0e947`'s rule logic) and the rules V2 rename; the 2026-11-21 owner decisions on the combined re-pin, the replacement decision check and the eligibility header split.
- **Kept or to recheck:** the reason numbering 24 to 28; the parity harness; `scripts/elig_snapshot.py`, which must be retargeted to fact records or dropped; the six reason-bound proof commits, which were proved for a cap of 32 and must be rechecked now that rule reasons run to 61.
- **New work:** an eligibility pack for rule set v2; a draft of the links-file widening.
- **Blocked on the RightRail side:** the engine does not carry the eligibility read; the fact has no benefit level (localBCE's G2 tests one) and no share of cost (G4).
- **Still for the founder:** benefit level and share of cost in the fact store; approval of the links-file widening; history and pull requests; and, not yet asked, who builds the engine's eligibility read.

Sections 2 to 4 of this page and `TRUNK_MOVE_ASSESSMENT.md` were written against `af4c7c52` before these answers. Where they disagree with this section, this section wins.

The questions as drafted, for reference:

1. Which commit to move onto: `af4c7c52` or a later one with regenerated pins.
2. Which version number the widened decision answer may take, or whether decision answers stay version 1 with u32 masks.
3. Whether localBCE's reasons are numbered above the leaf-only bits 24 and 25, or the leaf-only codes move.
4. Whether the eligibility rule reads two more per-request feeds (kinds 7 and 8) or belief from the fact store, and whether the fact store will carry benefit level and share of cost.
5. Whether G2 goes into `coreFires` as fixed Lean or becomes a rule-set source and pack.

Earlier requests (`RR_CORE_REQUEST_DRAFT.md`, sent 2026-11-15) are now settled in practice: the git history is available from the private repository, and the signer is on its Releases page. "rr-core" in older documents is the name of a helper role in the RightRail maintainer's tooling, not a person.

## 6. What was only on the old machine

Everything committed is pushed; no branch has unpushed commits. These were not in git on 2026-11-23:

- `rightrail/lean/BlindLedger/Gate/Flat/PayNumbering.lean`: a lemma section (`assemble_pay_lt`, `assemble_payC_lt`: every layout line's payment is below `np`) that was committed as work in progress later on 2026-11-23 without ever being built. Treat it as unchecked text: it may not compile. It has no axiom pins because those need a green build, so `test_proofs_are_current` is red. It sits on numbering code upstream has since changed, so it must be re-proved on the new trunk.
- Helper scripts in a temporary folder: the gated-commit script (it stages named paths, runs every check in a detached worktree and commits only if all pass), a patch-backup script and the guarded build wrappers. They contain that machine's paths. The check list they ran is in section 7.
- Uncommitted notes in older worktrees of the same repository (`codex/phase1-d02-d03-air-bindings`: `STATUS.md`, `LOG.md`, `OPEN_QUESTIONS.md`; `codex/rightrail-reason-bound`: two untracked documents that look like older copies of files now on this branch). The owner decides whether any still matter.
- Local caches and build outputs. None is worth transferring.

## 7. Rules the work has been done under

These are the localBCE owner's standing rules. `AGENTS.md` at the repository root has the project's own constraints as well.

- Commits use the identity `coder-sys`. No other author is invented.
- Nothing is committed or pushed without the owner's word. Pushes name an exact commit and are never forced.
- Every commit passes the full check set first. If a check fails or is skipped, stop and report the exact failure; do not weaken the check. A commit with known reds needs the owner's explicit acceptance, recorded in the commit message and `LOG.md`.
- The check set: `cargo check`, `cargo test` and `cargo build` in `rust-engine`; unittest discovery of `scripts/tests` and `tests`; the `rightrail` bloat budget test; the workflow YAML parse; `scripts/validate_ops_scaffold.py`; `scripts/scan_secrets.py`; `scripts/build_rightrail_operating_plan_review_queue.py --check`; `scripts/integration_selfcheck.sh` (its one FAIL in a detached check tree is the expected "branch" line).
- Never reset, checkout, clean or stash a working copy that has uncommitted work.
- Every download needs the owner's approval. So does closing anyone's applications.
- Inside `rightrail/`: protected changes (formats, digest domains, pinned statements) need an XI.2 record; heavy runs go through the memory guard (`scripts/rr_guarded_interim.ps1` is an interim stand-in sized for the old machine); the owner approves each design before it is built.
- No `gate_engine`, TCB or statement pin is committed on a tree that holds G2 (a) without the eligibility feed: it would turn every ALLOW into HUMAN_REVIEW with STALE_ELIGIBILITY.
- Never print credentials.

## 8. Document map

| File | What it is |
|---|---|
| `LOG.md` | Dated record of everything done and decided |
| `TRUNK_MIGRATION_PLAN.md` | The eight-step plan and its decisions |
| `TRUNK_STEP2_FRAME_DESIGN.md` | Step 2 design, 22 decisions, with the 2026-11-21 amendments |
| `TRUNK_STEP3_G2_DESIGN.md` | G2 on the trunk, the (a)/(b)/(c) split |
| `TRUNK_STEP3_ELIG_PRODUCER_DESIGN.md` | The eligibility snapshot builder design |
| `REASON_BOUND_DESIGN.md` | The 32-reason bound and what follows it |
| `G2_DESIGN.md`, `G4_DESIGN.md` | The October rule designs |
| `G_RULE_PARITY_REPORT.md` | Generated comparison of the two rule sets |
| `OPEN_QUESTIONS.md` | Open and decided questions |
| `TRUNK_MOVE_ASSESSMENT.md`, `TRUNK_MOVE_ASSESSMENT_REVIEW.md` | The 2026-11-22 assessment of moving to `af4c7c52`, and its review |
| `RR_MAINTAINER_QUESTIONS_DRAFT.md` | The open questions, as a message |
| `RIGHTRAIL_IMPORTED_FROM.md` | Record of the `fc89f9e5` import |
