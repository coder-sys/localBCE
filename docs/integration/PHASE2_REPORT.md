# Phase 2 report: G-rule parity harness and rule content format

Date: 2026-11-06; decisions added and figures revised 2026-11-07 after an independent review of
the branch. Plan: `docs/integration/RIGHTRAIL_BASE_PLAN.md` §5, Phase 2. Phase 2 changes nothing
under `rightrail/`. The questions below were answered on 2026-11-07 by plan §7 item 6 (items 1-4:
accepted as R-rule semantics) and are recorded in `OPEN_QUESTIONS.md` items 7-11; item 5 stays open.

## What was added

| File | Purpose |
|---|---|
| `scripts/g_rule_parity.py` | Test-only harness: runs `denial_reason()` (the built `rust-engine` binary) on every line of `rightrail/tests/gate_rules/rules_v1.vectors` and compares it with the Lean result recorded in that file |
| `scripts/tests/test_g_rule_parity.py` | 22 tests: vector parsing, snapshot pins, fact derivation, payment and redo handling, classification, end-to-end on synthetic and real vectors |
| `docs/integration/G_RULE_PARITY_REPORT.{md,json}` | The generated difference report |
| `scripts/rules_content_v1.py` | Proposed `RR/RULES/CONTENT/v1`: exports the corpus promotion queue as a non-authoritative, hash-pinned PROPOSAL; `verify` accepts exactly what `export` can produce |
| `scripts/tests/test_rules_content_v1.py` | 14 tests: round trip, digest, refusals of malformed documents and corpus rows, and a CLI export of the real 221-item queue |

## Checks

Each commit's staged tree is checked before committing (see `LOG.md`): `cargo check --all-targets`
and `cargo test` for rust-engine, `scripts/tests` and `tests` with a CI-like Python 3.12 venv,
the workflow YAML, RightRail's `tests.test_bloat_budget` where `rightrail/` changes, and the
self-check. Not run: the Lean runner and the RightRail suite (no Lean toolchain, no
`rr_guarded.ps1`; plan §7 item 1). The Lean results compared are the expectations in
`rules_v1.vectors`, which the Lean runner checks wherever it is built. The harness's snapshot pin
computation reproduces 115 of the file's 122 declared pins; the other 7 are its deliberately wrong
`*_wrong_pin`/`*_bad_pin` cases (tested).

## Parity result (G1/G3/G5/G7/G9 against R1/R3/R4/R5)

265 lines: 140 agree, 124 differ, 1 not compared (the vector records no Lean result for it: its
batch ends `commit UNANCHORED`, which Lean refuses at its checkpoint).

**No line has a mapped rule disagreeing on the same usable facts with Lean allowing it**
(`local_denies_lean_allows`: 0). Each difference falls in one of these groups:

| Group | Lines | Cause |
|---|---|---|
| Lean HUMAN_REVIEW, localBCE approves | 81 | localBCE has no review outcome. Lean refuses to rule on stale, unusable or missing snapshots, invalid or future service dates, and near duplicates; localBCE trusts its flags |
| Lean HUMAN_REVIEW, localBCE denies | 17 | Same cause, the other way: localBCE denies on facts Lean treats as unverified (stale DMF, exclusion, enrollment), on a missing enrollment snapshot (including one failing its pin), or on an invalid date |
| Lean HOLD on a rule localBCE has no input for | 22 | `DUPLICATE_OF_UNRESOLVED`, `ALREADY_DECIDED` (line identity), `CAP_MEMBER_MONTH_DUPLICATE` |
| Both stop the line, different reason | 3 | localBCE stops at the first failing gate (G1 before G7); a capitation member-month duplicate is G7 in localBCE but R2 in Lean |
| Lean HOLD on a mapped rule, localBCE approves | 1 | `p6_released_rollback` line 175: Lean uses its own checkpoint of the released set when the set read does not chain; localBCE has no checkpoint |

Revision note (2026-11-07): the first version treated a snapshot that fails its pin as present,
which Lean does not; lines 148 and 153 moved from "approves" to "denies" (83/15 became 81/17).

## Questions raised (answered 2026-11-07, plan §7 item 6)

1. HUMAN_REVIEW: RightRail's review outcome replaces localBCE's approve/deny for stale or unverified data and bad dates (98 lines). Accepted.
2. G7 and capitation: G7 maps to R2 (`CAP_MEMBER_MONTH_DUPLICATE`) as well as R4. Accepted; plan §3 updated.
3. Unresolved set and line identity (22 lines): R-rule semantics with no localBCE counterpart. Accepted.
4. First failing gate versus all reasons: RightRail reports every reason. Accepted.
5. `RR/RULES/CONTENT/v1` is a localBCE proposal. RightRail treats formats and digest domains as protected (CONST XI.2), so adopting it needs an XI.2 record and an `rr-core` review. Open.

## Not done, and why

- Phase 3 (new Lean rules G2, G4, G6, G8, G10 and their evidence) and Phase 4 (837 adapter inside
  `rightrail/`, retiring the bridge and the Rust reference) change `rightrail/`. They need a Lean
  toolchain, `rr_guarded.ps1` and a RightRail lead (plan §7 items 1-2; `OPEN_QUESTIONS.md` item 12).
