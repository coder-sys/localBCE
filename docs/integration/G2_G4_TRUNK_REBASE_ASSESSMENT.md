# G2 and G4 against the 2026-11-14 RightRail trunk snapshot

Status: assessment only, written 2026-11-14. No code changed. Not approved by the owner.

## 1. Inputs

- **Trunk snapshot:** `C:\Users\sruja\Downloads\rightrail-rightrail-main\rightrail-rightrail-main`, a GitHub zip
  export dropped on 2026-11-14 13:36. It has no `.git`, so no commit hash. The newest pinned executable's
  `artifacts/engine-evaluator/PROVENANCE.md` names a Lean tree built 2026-11-10, so the snapshot is at least that new.
- **Base:** the `rightrail/` import at `af020b2` (2026-10-17), as it stands at `76dc54ad` on `codex/rightrail-g2`.
- **Ours:** G2 at `f16a61f4` (`codex/rightrail-g2`) and G4 at `90ffd3f9` (`codex/rightrail-g4`), designs in
  `G2_DESIGN.md` and `G4_DESIGN.md`.

Method: `git diff --name-status 76dc54ad 90ffd3f9 -- rightrail/`, then for each file a SHA-256 of the base version
against the trunk file, and `diff | grep -c '^[<>]'` line counts for drift. Git ran through WSL (`git version 2.43.0`);
the Windows shell has no git on PATH.

## 2. Verdict

G2 and G4 do not rebase onto the trunk. Every one of the 21 files they touch under `rightrail/` either changed upstream
or no longer exists. The rule semantics, row types, theorem statements, vectors and design documents carry over; the
wiring around them has to be redone against the trunk. Plan line 99 ("pinned worker re-pinned per `PROVENANCE.md`") now
applies: the rules sit inside the pinned `gate_engine`.

## 3. Trunk versus base, whole tree

| | Files |
|---|---|
| Unchanged | 175 |
| Changed | 161 |
| New in the trunk | 291 |
| Removed from the trunk | 65 |

Large additions: `Gate/Engine3/`, `Gate/Flat/`, `Gate/Cosign/`, `Gate/FactRegistry.lean`, `tools/STMT_PIN.txt`,
Python readers `app/right_rail_x12_{820,834,835,837}.py` and `right_rail_reader_{death,evv,leie,lines}.py`,
`conformance/{ENGINE_V3,FLAT_V1,FRAME_V1,GATE_RULES_V1,SEGMENT_V1}.md`. Removed: the id registry, `StateV2`, the old
shard and batch modules, several benchmarks. Products are now six, as in the planning notes.

## 4. Files G2/G4 edit

| File | Trunk | Trunk drift from base (diff lines) | G2+G4 edit (diff lines) |
|---|---|---|---|
| `lean/BlindLedger/Gate/ReadManifest.lean` | **missing** | | 140 |
| `lean/BlindLedger/Gate/StateV2.lean` | **missing** | | 51 |
| `lean/BlindLedger/Gate/Rules/Resident.lean` | **missing** | | 20 |
| `tools/gate_rules_mutants.py` | **missing** | | 103 |
| `tests/gate_rules/{rules,demo_zz}_v{2,3}.vectors` | missing (ours, new) | | 15,073 added |
| `lean/BlindLedger/Gate/Rules/Run.lean` | changed | 513 | 35 |
| `lean/BlindLedger/Gate/Rules/Theorems.lean` | changed | 303 | 158 |
| `lean/BlindLedger/Gate/Rules/Spec.lean` | changed | 146 | 136 |
| `lean/BlindLedger/Gate/Rules/Fast.lean` | changed | 78 | 39 |
| `lean/BlindLedger/Gate/Rules/FastEq.lean` | changed | 66 | 63 |
| `lean/BlindLedger/Gate/Rules/DecideLayer.lean` | changed | 70 | 3 |
| `app/right_rail_gate_decide.py` | changed, 246 to 1,011 lines | 1,131 | 6 |
| `tests/test_gate_rules_worker.py` | changed, 484 to 146 lines | 526 | 6 |
| `tests/test_gate_rules_vectors.py` | changed | 73 | 10 |
| `tests/gate_rules/shards_v1.vectors` | changed, 193 to 60 lines | 145 | 24 |
| `tests/test_bloat_budget.py` | changed, line caps removed | 56 | 8 |
| `tools/gate_rules_data.py` | changed, 158 to 62 lines | 110 | 11 |
| `conformance/README.md`, `MANIFEST.sha256`, `docs/RIGHTRAIL_FULL_STACK_TARGET.md` | changed | | small |

### Where the missing files went

- **`ReadManifest.lean`:** the read set and read manifest live in `Gate/SnapshotV2.lean`
  (`READ-MANIFEST/v4`, `readSetPre`, slots). The trunk's `SnapshotV2.lean:13` guards
  `manTag == "RR/GATE/READ-MANIFEST/v4"`. G4 also named its manifest v4 and its read set `READ-SET/v4`
  (`StateV2.readSetTag`). Same tag, different layout: a protected digest-domain collision. The G2/G4 manifest and read
  set need fresh version numbers chosen against the trunk, not against October.
- **`StateV2.lean`:** gone. Only a comment in `Gate/Rules/Request.lean:5` still names it. The reason-name table,
  `pm_fires` and the read-set digest that G2/G4 edited there have new homes (`Gate/Frame/Spec.lean`, `SnapshotV2.lean`)
  that need locating per edit. The uncommitted work on `codex/rightrail-reason-bound` also edits `StateV2.lean`.
- **`Rules/Resident.lean`:** gone; STATUS line 116 still describes a resident rules worker, now elsewhere.
- **`tools/gate_rules_mutants.py`:** gone, and no mutant harness replaces it (`grep -ri mutant` finds only test names
  and a comment in `FastEq.lean:6`). The 19 G2 and 25 G4 killed mutants have no trunk harness.

## 5. Reason-code budget

Trunk `Gate/Spec.lean:32`: `maxReasonCodes : Nat := 32`. Trunk `Rules/Spec.lean` has 24 reasons (codes 0 to 23); the
base had 23 and the trunk added `POSTING_CAP`. G2 adds 5 (`BENEFIT_LEVEL_MISSING`, `_UNVERIFIED`,
`PROGRAM_NOT_ELIGIBLE`, `_UNVERIFIED`, `STALE_ELIGIBILITY`) and G4 adds 3 (`SHARE_OF_COST_UNMET`, `_UNVERIFIED`,
`STALE_SHARE_OF_COST`). On the trunk: 24 + 8 = 32, the cap exactly. The G4 tripwire
`#guard reasons.length ≤ maxReasonCodes` would pass with zero headroom. The owner's reason-budget decision
(G4_DESIGN.md section 11, item 14; option 1 chosen 2026-11-12) is now a prerequisite for landing G2 and G4, not only G5.

## 6. Obligations the trunk added since October

1. **Rules are in the pinned decision program.** `Gate/Flat/Worker.lean:3` imports `BlindLedger.Gate.Rules.Run`;
   STATUS line 58 names `gate_engine` as "the one decision program", pinned in `tools/tcb_report.txt` (STATUS 133, 183).
   A `Rules/Spec.lean` change means a guarded rebuild, `tools/tcb_pin.ps1`, and a re-pin.
2. **Fixed four-feed frame.** `conformance/FRAME_V1.md` section "Body": a 384-byte context with four feed descriptors
   at offsets 76, 153, 230, 307 (DMF, provider deaths, exclusions, enrollment), then feed rows in that order with fixed
   widths. Eligibility (kind 7) and share of cost (kind 8) need a frame layout change, a new tag, `ENGINE_V3.md`
   review, and the Python host `app/right_rail_gate_decide.py` (1,011 lines) and `conformance/FRAME_V1.md` updated.
3. **Normative spec page plus independent checker.** `conformance/GATE_RULES_V1.md` section 3 enumerates "the six
   kinds" with widths and domains, section 5 the rules; `conformance/gate_rules_v1_ref.py` (352 lines) is a Python
   re-implementation "written from this page alone", run by `tests/test_gate_rules_v1_spec.py`; must-reject cases are in
   `tests/gate_rules/rules_v1_negative.vectors` (205 lines). G2/G4 need sections, checker code and negative vectors.
4. **Statement pin.** `tools/STMT_PIN.txt` is a SHA3-512 root over every pinned theorem statement
   (`tests/test_statement_pin.py`, regen `python tests/test_statement_pin.py regen`, needs the built `lean/.lake`).
   Adding G2/G4 theorems to `tools/gate_print_axioms.lean` changes it.
5. **`factsDigest`** (`Rules/Run.lean:256-260`) hashes the four reference pins into the checkpoint. Six pins change
   checkpoint content.
6. **`RULES_READS` shape** in `app/right_rail_gate_decide.py:_reads_ok` and `tests/test_gate_rules_vectors.py` still
   assumes four pins and `READ-SET/v2`; G2/G4 made it six pins and v4. Must be redone against the trunk's reader.
7. **Doc shape.** A new hand-written `.md` inside `rightrail/` needs an entry in `tests/test_doc_shape.py`
   (trunk `AGENTS.md`). Design documents under localBCE's `docs/integration/` are outside that rule.

Easier than before: `tests/test_bloat_budget.py` dropped its line caps (duplication checks only), so the exact bloat
deltas in G4_DESIGN.md section 12 no longer matter.

## 7. What carries over

- `Elig` and `Soc` row types, `Elig.fields` and `Soc.fields`, and the `RR/GATE/SNAPSHOT/v1` pin domain for kinds 7
  and 8 (the trunk states SNAPSHOT/v1 "does not change", `ENGINE_V3.md:675`).
- `Ctx` fields `eligibility` and `shareOfCost`; the `fires_iff`, `g2_*`, `g4_*` and `fail_closed_*` theorem statements
  and their axiom pins.
- The vector files. The grammar in `GATE_RULES_V1.md` section 2 (`snap KIND ASOF COUNT PIN`, `KIND f...`, `line ...`,
  `commit`, `end N`) matches what `rules_v3.vectors` and `demo_zz_v3.vectors` use; `snap` accepts any kind, and row
  parsing for `elig` and `soc` is the same addition to `Run.lean` as before.
- The designs' semantics, defaults and owner decisions.

## 8. Recommended order

1. Obtain the real trunk repository with history and record the commit the work targets. The zip cannot anchor a
   branch or an XI.2 record.
2. Settle the reason budget (section 5) before any rule code.
3. Write one addendum to `G2_DESIGN.md` and `G4_DESIGN.md` covering: manifest and read-set version numbers against the
   trunk; the frame extension from four to six feeds; `GATE_RULES_V1.md` and `gate_rules_v1_ref.py` changes; negative
   vectors; the mutant evidence replacement; the re-pin plan (`gate_engine`, TCB, `STMT_PIN`).
4. Re-apply G2, then G4, as fresh commits with XI.2 records on a branch from the trunk commit. Keep the `codex/rightrail-g2`
   and `codex/rightrail-g4` commits as the record of the October-base implementation.
5. Guarded `lake build`, statement-pin regen, TCB regen, `gate_engine` re-pin, then the trunk test suite. On this
   machine (Windows ARM64, emulated x64 Lean, 1.5 GiB guard floor) the last full build and mutant runs took hours; plan
   the budget accordingly.

Rough effort: the Lean rule bodies are about a third of each original commit and reusable. The remainder is new wiring
plus a full pin cycle.

## 9. Open questions for the owner

1. Which trunk commit does the snapshot correspond to, and is the trunk repository available to branch from?
2. Does the frame get two more feed slots (a FRAME v2) or do eligibility and share of cost arrive another way
   (for example through the new `FactRegistry`)?
3. Which version numbers do the G2/G4 read set and manifest take, given the trunk already used v4?
4. Is the retired mutant tool to be carried into the trunk, or is another form of mutation evidence acceptable?
5. The reason-bound work on `codex/rightrail-reason-bound` edits `StateV2.lean`, which the trunk removed. Continue it
   against the October base or restart it against the trunk?
