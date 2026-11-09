# RightRail as the base: integration plan for localBCE

Status: **Approved by the project owner in chat on 2026-11-07.** On 2026-11-06 the owner chose
the direction ("rightrail as base with stark parked and localbce wired with rightrail"); on
2026-11-07 they approved proceeding with this plan and delegated the §7 decisions to the agent.
An earlier version of this line said the plan was approved on 2026-10-22; no record of that
approval exists, so it was removed. Phases 1-2 implemented on `codex/rightrail-base-phases`;
Phases 3-4 blocked (see §7 and `docs/integration/PHASE2_REPORT.md`).
Drafted 2026-10-22 against `integration/rightrail` at `e746f58`, when PR #5 (STARK AIR) was at
`418ad60`. PR #5 grew to the five forgery-gap fixes plus the presence-flag pins and was merged
into `integration/rightrail` at `bc50dd62` on 2026-11-06. STARK stays parked (owner,
2026-11-07): this branch merges `bc50dd62` and parks that code, with PR #5's fixes, under
`parked/localbce/stark-engine/`.

## 1. Decision

RightRail (`rightrail/`, its own `CONSTITUTION.md`) becomes the base system. localBCE
components are wired into it **without** Groth16, STARK, or any Solidity/on-chain
settlement. Proof and chain code is parked, not deleted.

Carried over, in a form RightRail's constitution allows:

| localBCE component | Carried over as |
|---|---|
| `rust-engine/` G1-G10 adjudication | Rule content and Lean rules inside RightRail; the Rust engine is a transitional, test-only shadow reference |
| `gov-rules-kg-prototype/` rules corpus | An upstream rules-authoring tool, kept outside the trunk, that produces versioned, hash-pinned rule content for state review |
| `blind-ledger-app-layer/` app/audit layer | Selected adapters only (837 intake, audit reports); its duplicate G1-G10 engine and fallback are not carried |

## 2. Constraints that decide the shape

These come from `rightrail/CONSTITUTION.md` (CONST) and `rightrail/AGENTS.md`. A
plan that copies localBCE code into RightRail unchanged would break most of them.

| Rule | What it means here |
|---|---|
| CONST I.3 | A model output is a lead, never a determination. The rules corpus (Claude inference) can only produce proposals for state review. |
| CONST III.1 | One authoritative writer: `FinancialOwner`. The off-chain bridge and app-layer JSON registry cannot remain writers. |
| CONST V.1 | Executed decision logic belongs in Lean. A Rust or Python adjudicator cannot decide inside RightRail. |
| CONST V.2 | No permanent duplicate policy and no silent fallback. Overlapping G-rules map onto existing Lean rules; the app-layer fallback engine is not carried. |
| CONST IX.1 | All product code lives in the trunk, one home per module. |
| CONST IX.2 | No custom database or service-per-module before measured need. RightRail stays on owner-local SQLite; Postgres does not enter the trunk (also `docs/RIGHTRAIL_FULL_STACK_TARGET.md` §8). |
| CONST X.2 | Heavy runs go only through `C:/Users/neers/rrb/tools/rr_guarded.ps1`. **That script does not exist on this machine.** |
| CONST XI.2 | Theorem statements, `artifacts/**`, wire formats and digest domains are protected; changes need an XI.2 record. |
| `tests/test_bloat_budget.py` | Product/test line caps; any added code fails until caps are raised deliberately. |
| `tests/attacks/test_python_supply_chain_attacks.py` | The dev dependency set is pinned to six packages. psycopg, httpx, FastAPI, etc. cannot enter the trunk. |

localBCE's own `docs/integration/GOVERNANCE.md` also applies: PRs only, no force-push,
deletions need an approved `CLEANUP_PROPOSAL.md` entry, stop at phase boundaries.

## 3. Rule mapping: G1-G10 against RightRail's Lean gate rules

RightRail already decides claim-line rules R1-R5 in Lean
(`rightrail/lean/BlindLedger/Gate/Rules/Spec.lean:16-30`). Under CONST V.2 an
overlapping G-rule must map onto the existing R-rule, not be added again.

| localBCE gate (`denial_reason()` in `rust-engine/src/main.rs`) | RightRail rule | Treatment |
|---|---|---|
| G9 recipient deceased | R1 `MEMBER_DECEASED` | Map to R1; no new rule |
| G7 duplicate claim | R4 `FFS_DUPLICATE_LINE`; for CAP_820, R2 `CAP_MEMBER_MONTH_DUPLICATE` | Map to R4 and R2 (R2 added by §7 decision 6); no new rule |
| G1 identity/eligibility active, G3 month of service | R5 `MEMBER_NOT_ENROLLED` | Map to R5; record any semantic difference as an open question |
| G5 provider not enrolled / type invalid | R3 `PROVIDER_EXCLUDED` / `PROVIDER_DECEASED` | Partial; "not enrolled" and "type invalid" are new conditions |
| G2 aid code / benefit level, G4 share of cost, G6 billing code / units, G8 disability determination, G10 physician certification | none | New Lean rules, each with its evidence source |

None of the G-rules is legally verified (`RULES_ENGINE.md`; `rules_active_v1.json` is
`runtime_status: opt_in_exact_g1_g10_parity`). They enter RightRail as synthetic rule
content under its standing claims (CONST VI.2), not as state policy.

## 4. Target shape

```text
gov-rules-kg-prototype (outside trunk, Postgres, Claude inference)
   |  proposals only (CONST I.3)
   v
versioned, hash-pinned rule content  --state review-->  rightrail/ Lean gate rules (R1-R5 + new G-derived rules)
                                                              |
837 intake adapter (from app layer) --> typed evidence -->  FinancialOwner (single writer, SQLite)
                                                              |
                                                     Mirror / Continuity / Switch (unchanged)

rust-engine denial_reason(): test-only shadow reference, compared against the Lean rules
until parity, then retired.

Parked (moved, not deleted): zk/, stark-engine/, blind-ledger/ (Foundry), deprecated/groth16/,
zk-prover/, app-layer contracts/, l2/, zk*/, proof/chain scripts and CI jobs.
```

## 5. Phased PRs

Each phase ends with a report and waits for "continue" (GOVERNANCE.md). Every PR targets
`integration/rightrail`.

| Phase | PR | Change | Done when |
|---|---|---|---|
| 0 | this document | Approve the plan and the decisions in §7 | Reviewer sign-off |
| 1 | Park proofs and chain | Move the folders listed in §4 under `parked/localbce/` with a README; add CLEANUP_PROPOSAL entries; drop the `foundry`, `stark-bridge`, `governed-v2-anvil` CI jobs and the STARK/Sepolia steps of `rust`, `rules-and-ops`, `windows-smoke`; PR #5 was merged at `bc50dd62` before the parking landed; its code is parked with the rest | CI green on remaining jobs; `git log --follow` shows moves, not deletions |
| 1 | Adjudicator without chain | Make `AppConfig` chain fields optional (`rust-engine/src/main.rs:193-224`); feature-gate or park `stark_activation.rs` and the STARK paths (main.rs 257-530, 678-698, 903-974, 1013-1297); remove the Anvil key (N-07) | `cargo test`, `cargo check` pass with `proof_backend=none` and no chain fields; `denial_reason()` and `adjudication_result.json` unchanged |
| 2 | Rule content format | Define `RR/RULES/CONTENT/v1`: versioned, hash-pinned, test-vectored rule data (target doc §9); export from the corpus promotion queue as proposals | Round-trip and digest tests; proposals marked non-authoritative |
| 2 | G-rule parity harness | Test-only harness: run `denial_reason()` and the Lean gate rules on the same synthetic vectors (`rightrail/tests/gate_rules/`) and report differences for G1/G3/G5/G7/G9 | Difference report reviewed; every difference either accepted as R-rule semantics or raised as an open question |
| 3 | New Lean rules | Add G2, G4, G6, G8, G10 (and G5's new conditions) as Lean gate rules with theorems and vectors; XI.2 record; `rr-core` author, `rr-review` review | Lean build plus the guarded suite; pinned worker re-pinned per `PROVENANCE.md` |
| 3 | Evidence for new rules | Add the evidence each new rule needs (aid code, share of cost, billing code table, disability determination, physician certification) through the owner's typed-evidence process (owner, independent checker, Lean `evidenceAccounted`, codec, `test_history_growth`) | Owner and checker tests; history-growth pins hold |
| 4 | 837 intake adapter | Port the app layer's 837 parsing into a narrow RightRail adapter that emits typed evidence; no decisions, no registry | Adapter tests with synthetic 837s; zero PHI |
| 4 | Retire the bridge | Retire `bridge/rightrail_offchain.py` (CLEANUP_PROPOSAL item 3) once the owner is the only writer; keep its tests as migration fixtures | Self-check "single writer" passes |
| 4 | Retire the Rust reference | Once the parity harness shows no unexplained difference, park `rust-engine/` decision code | Parity report archived |

Not carried at all: the app layer's second G1-G10 engine (`rules-engine-rust/`,
`rules_engine_fallback.py`), its JSON registry, its FastAPI/JWT reviewer API (Mirror's
staff server covers staff work), and its payment-bridge stubs.

## 6. Testing standard per PR

- Rust: `cargo test` and `cargo check` (localBCE `AGENTS.md`).
- RightRail: the full `pytest` suite plus Lean build, run through the guard (CONST X.2).
- Each PR states which suites ran, on which commit, in which mode, with raw logs. Skips and
  failures are reported as-is (CONST VI.3).
- Changes to protected RightRail paths carry an XI.2 record and a human reviewer.

## 7. Decisions

Made by the agent on 2026-11-07 under the owner's delegation of that day. Each can be
reversed by the owner; none is a state-policy determination.

1. **Guard script.** `C:/Users/neers/rrb/tools/rr_guarded.ps1` is not on this machine, and
   neither is a Lean toolchain (`lake`, `lean`, `elan` absent on Windows and WSL).
   **Decision: no interim substitute.** The script's limits come from a driver-root
   `AGENTS.md` that is not in this repository, so a stand-in would only guess at them, and
   CONST X.2 forbids weakening or bypassing the guard. localBCE checks and single light
   RightRail test files (for example `tests/test_bloat_budget.py`) run directly; the full
   RightRail suite and every Lean build stay unrun until the real guard and toolchain exist.
   Consequence: Phase 3 is blocked.
   **Overridden by the owner on 2026-11-08:** the owner approved installing Lean and writing a
   stand-in guard. `scripts/rr_guarded_interim.ps1` takes the real guard's call interface
   (`-Worktree`, `-Suffix`, `-MinFree`, `-Modules` or `-Exe`) and enforces this repository's
   own limits: a start floor on free memory, a Windows job object with a memory cap holding the
   whole process tree, a free-memory watchdog, a timeout and low priority. It is not the real
   `rr_guarded.ps1` (v7) and does not know the driver-root limits; RightRail runs through it
   are interim evidence and say so in every log. Elan with `leanprover/lean4:v4.33.1` (the
   `lean-toolchain` pin, x86_64, emulated on this ARM64 PC) is installed for this user.
2. **Who leads RightRail changes.** No `rr-core` or `rr-review` agent definitions exist on
   this machine (`~/.claude/agents/` is empty). **Decision: the project owner is the
   RightRail lead for Phases 3-4.** Agent sessions may add provenance documents inside
   `rightrail/`, but do not change Lean, formats, digest domains, theorem statements, money
   logic or `artifacts/**` there without an `rr-core` author and an `rr-review` review.
   Consequence: the Phase 4 837 adapter inside `rightrail/` waits for that lead.
   Confirmed by the owner on 2026-11-08 ("You stay lead"): the agent proposes, and the owner
   authors or approves each change inside `rightrail/`.
3. **Where parked code lives.** **Decision: `parked/localbce/` on the branch** (the
   recommended default). It keeps history with `git log --follow` and needs no extra branch.
4. **Rules corpus home.** **Decision: keep `gov-rules-kg-prototype/` in this repository,
   outside the RightRail trunk** (the recommended default). It produces proposals only
   (`RR/RULES/CONTENT/v1`, `authoritative: false`).
5. **Bloat budget.** **Decision: raise a RightRail ceiling only for a change that is made,
   by its exact measured delta, with the felt effect named in the commit message (Art. XII),
   as `tests/test_bloat_budget.py` requires.** In this pass the only raise is one Markdown
   file and its bytes for `rightrail/IMPORTED_FROM.md`. No code ceiling is raised in advance
   for Phases 3-4.
6. **G-rule semantics.** **Decision: accept the RightRail R-rule semantics for every
   difference the Phase 2 parity harness found** (`docs/integration/G_RULE_PARITY_REPORT.md`):
   human review on stale or unverified data and bad dates; R2 for capitation member-month
   duplicates in addition to R4; the unresolved set and line identity; every reason reported
   rather than the first. This is a synthetic-rule decision under RightRail's standing claims;
   a state-owned answer overrides it.

## 8. Risks

- Porting rules into Lean is the bulk of the work and needs the Lean toolchain and the
  Windows-pinned workers; tests that need them skip elsewhere.
- Raising bloat caps and re-pinning workers are protected changes and slow by design.
- The checked-in `rust-engine/adjudication_result.json` showed a submitted transaction; Phase 1
  regenerated it (`tx_submitted: false`, `tx_hash: null`).
- `rules-and-ops` CI failed on `418ad60` in a Postgres concurrency test unrelated to the
  STARK change; see §9 before treating it as a Phase 1 blocker.

## 9. Open CI item: `rules-and-ops` on `418ad60`

On GitHub, `rules-and-ops` passed on `8d73f40` and failed on `418ad60` in
`test_concurrent_inference_workers_claim_distinct_jobs`
(`gov-rules-kg-prototype/tests/test_postgres_corpus_integration.py:1362`): one of
the expected job IDs was not claimed. The diff between those commits touches only
`stark-engine/`, and nothing the failing step runs reads `stark-engine/`.

A local base-vs-fix reproduction (`e746f58` and `418ad60`, Postgres 16, fresh
database) has not produced a result yet: the first attempt failed on a PyPI
download timeout, and the second hung in the Postgres-backed tests. The failure is
therefore **not yet classified**; it is not called flaky without a passing and a
failing run of the same commit. Later data from PR #5's branch: run 40949974519 on
`ba4896fb` (2026-10-29) passed all 8 jobs, including `rules-and-ops`; runs on `418ad60` and
`4e6d7a74` failed and were not examined. That still gives no same-commit pass/fail pair.
Phase 1 CI on `codex/rightrail-base-phases` is the next data point.
