# Phase 2 report: G-rule parity harness and rule content format

Date: 2026-11-06, decisions added 2026-11-07. Plan: `docs/integration/RIGHTRAIL_BASE_PLAN.md`
§5, Phase 2. Nothing under `rightrail/` changed for Phase 2. The open questions below were
answered on 2026-11-07 by plan §7 item 6 (items 1-4: accepted as R-rule semantics) and are
recorded in `OPEN_QUESTIONS.md` items 7-11; item 5 stays open.

## What was added

| File | Purpose |
|---|---|
| `scripts/g_rule_parity.py` | Test-only harness: runs `denial_reason()` (the built `rust-engine` binary) on every line of `rightrail/tests/gate_rules/rules_v1.vectors` and compares it with the Lean result recorded in that file |
| `scripts/tests/test_g_rule_parity.py` | 20 tests: vector parsing, fact derivation, payment and redo handling, classification, end-to-end on synthetic and real vectors |
| `docs/integration/G_RULE_PARITY_REPORT.{md,json}` | The generated difference report |
| `scripts/rules_content_v1.py` | Proposed `RR/RULES/CONTENT/v1`: exports the corpus promotion queue as a non-authoritative, hash-pinned PROPOSAL; `verify` checks it |
| `scripts/tests/test_rules_content_v1.py` | 11 round-trip, digest and refusal tests, plus a CLI export of the real 221-item queue |

## Checks run (WSL, verification copy)

| Check | Result |
|---|---|
| `cargo check --all-targets` (rust-engine) | pass |
| `cargo test` (rust-engine) | 45 passed |
| `pytest scripts/tests` | 37 passed, 6 subtests passed |
| `pytest tests` | 46 passed, 5 subtests passed; `tests/test_rightrail_pdf_documents.py` NOT RUN (`pypdf` is not installed here) |
| `scripts/integration_selfcheck.sh` | 8 PASS, 2 FAIL, 4 NOT-YET. FAIL `branch`: the verification copy is detached. FAIL `tracked files`: parked `.zkey`/`.ptau`/`.wtns` and two RightRail `.exe` files, open question 1 |
| Lean runner / RightRail suite | NOT RUN: no Lean toolchain on this machine, and no `rr_guarded.ps1` (plan §7 item 1). The Lean results used are the expectations in `rules_v1.vectors`, which the Lean runner checks wherever it is built |

## Parity result (G1/G3/G5/G7/G9 against R1/R3/R4/R5)

265 lines: 140 agree, 124 differ, 1 not compared (Lean refuses that batch at its checkpoint).

**No line has a mapped rule disagreeing on the same usable facts with Lean allowing it.**
Each difference falls in one of the groups below; each needs a decision, listed under open questions.

| Group | Lines | Cause |
|---|---|---|
| Lean HUMAN_REVIEW, localBCE approves | 83 | localBCE has no review outcome. Lean refuses to rule on stale or unusable snapshots, invalid or future service dates, and near duplicates; localBCE trusts its flags |
| Lean HUMAN_REVIEW, localBCE denies | 15 | Same cause, the other way: localBCE denies on facts Lean treats as unverified (stale DMF, exclusion, enrollment) or on an invalid date |
| Lean HOLD on a rule localBCE has no input for | 22 | `DUPLICATE_OF_UNRESOLVED`, `ALREADY_DECIDED` (line identity), `CAP_MEMBER_MONTH_DUPLICATE` |
| Both stop the line, different reason | 3 | localBCE stops at the first failing gate (G1 before G7); a capitation member-month duplicate is G7 in localBCE but R2 in Lean, and the plan maps G7 only to R4 |
| Lean HOLD on a mapped rule, localBCE approves | 1 | `p6_released_rollback` line 175: Lean uses its own checkpoint of the released set when the set read does not chain; localBCE has no checkpoint |

## Open questions raised (proposed additions to OPEN_QUESTIONS.md)

1. HUMAN_REVIEW: accept that RightRail's review outcome replaces localBCE's approve/deny for stale or unverified data and bad dates (98 lines)? Proposed: yes, as R-rule semantics.
2. G7 and capitation: map G7 to R2 (`CAP_MEMBER_MONTH_DUPLICATE`) as well as R4? Proposed: yes; the plan's §3 table names R4 only.
3. Unresolved set and line identity (22 lines): accept as R-rule semantics with no localBCE counterpart? Proposed: yes.
4. First-failing-gate versus all reasons: accept that RightRail reports every reason? Proposed: yes.
5. `RR/RULES/CONTENT/v1` is a localBCE proposal. RightRail treats formats and digest domains as protected (CONST XI.2), so adopting it needs an XI.2 record and an `rr-core` review.

## Not done, and why

- Phase 3 (new Lean rules G2, G4, G6, G8, G10 and their evidence) and Phase 4 (837 adapter inside
  `rightrail/`, retiring the bridge and the Rust reference) change `rightrail/`. They need plan §7
  decisions 1 (guard script), 2 (who leads RightRail changes), 5 (bloat budget) and 6 (G-rule
  semantics, partly answered by the questions above), plus a Lean toolchain.
- Phase 1 line endings: the main checkout's uncommitted edits turned 10 LF files into CRLF
  (including `scripts/integration_selfcheck.sh`, which then fails to run under bash). The
  committed versions are LF; the main checkout's working copy was left untouched.
