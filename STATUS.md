# RightRail status

Updated: 2026-09-26. This is the one current status file for the single codebase
`rightrail-main`. Code is still being copied in from the older checkouts.

Standing rules: see CONSTITUTION.md (supreme; every change must comply).

Older detailed status files are archived word for word in
`work/_retired-research-20260924/trunk-docs-history-20260924/` (outside the trunk; also in Git history before 2026-09-24's removal commit). Raw run logs live in
`work/pq-wide-seed-native-20260913/build-filter-native/`.

## What RightRail is

RightRail gives a state Medicaid agency one operating record for a consequential
responsibility that crosses plans, providers and contractors, starting with one
recurring financial responsibility such as a state-directed hospital payment program.
It keeps the approved rule, evidence, open disagreements, the official's decision and
the next action connected until the work is done, while existing processors and
payment systems keep moving the money. It is five parts on one small foundation
(Control Pack, Blind Ledger, Mirror, Continuity State, Switch): Lean decides each
consequential step and the Python owner commits it.

## Standing claims

Pre-state build phase (the plan; CONSTITUTION VI.4): synthetic data,
`proofSuiteId=null`, `production_usable=false`, `activation=false`.

## What actually runs today and was verified

Only items with a recorded passing guarded test run. "Evidence" is the archived file
in that archive that holds the raw record.

1. **Lean-controlled financial correction** (the plan's Hospital H $3,000 shortfall).
   2026-09-24: 9 of 9 selected tests passed (run r7; r1-r6 failed and were fixed).
   The owner rejects the disallowed offset and authorizes the correction only through
   the Lean transition inside one database transaction; crashes before and after commit
   and exact retries were checked. 2026-09-26 (branch `correction-v2`): the pinned
   engine is built from the current source and asks for exactly min(claim, the unpaid
   balance no earlier unpaid request asks for). Evidence: `rightrail-financial-workflow-20260913-STATE.md`; rules below.
   A payment counts against a correction request only when it names it (`pays_action_id`;
   owner, Mirror and CLI `--pays-action-id`); a source re-sent with a different link is
   `payment_request_conflict`. By design (only synthetic data exists; as decision C3), a store
   from before links whose cash stayed unlinked is refused a second correction; no grandfather path.
   Known gap: the staff demo's cash command never links (its cash may precede the request).
2. **Engine correction program self-checks (current source).** 2026-09-26: two clean
   guarded builds byte-identical, correction KAT 42 of 42 (`cv2-r3-kat-clean-a1`).
   Evidence: `artifacts/engine-correction/PROVENANCE.md`.
3. **Continuity admission (v7 at this run; now v8, see the rules below) and correction follow-up through Mirror.**
   2026-09-24: 11 of 11 passed (run r6; r3-r5 failed and were fixed).
   Evidence: `rightrail-financial-workflow-20260913-STATE.md`.
4. **Private snapshot indexes** (fast per-obligation reads, safe migration).
   2026-09-24: 6 of 6 passed; no tested query still scans a whole table.
   Evidence: `rightrail-financial-workflow-20260913-STATE.md`.
   Downgrade index set v2 to v1 (no owner open): `DROP INDEX rr_financial_v2_events_aggregate_kind; PRAGMA user_version=1;` — a writing (LIVE/TEST) owner re-upgrades on open; SHADOW never does.
   Row-count cache: a table within 5% of the 10,000-row cap, and every seal, is counted exactly; only an undercount above 500 rows could pass the cap, which needs tampering with the store or the owner process.
5. **Queue claim path (Python).** 2026-09-24: 29 of 29 focused tests passed. The last
   broader Queue run (122 tests) still has 1 failure and 5 errors. Earlier Lean/Rust
   admission integration (2026-09-19): 4 of 4. Evidence: `lean-queue-20260913-STATE.md`.
6. **Security Lean proof target** (opportunity-accounting reducer). 2026-09-24: build
   succeeded on run r7 (r1-r6 failed): 18 theorems with no `sorry`, 39 examples,
   30 style warnings. Local compile only, not an independent kernel check.
   Evidence: `lean-security-20260913-STATE.md`.
7. **v5 financial owner, checker, Mirror, CLI, Continuity.** Withdrawn 2026-09-24 (XI.2):
   v5/v6 stores are retired, so this acceptance (focused runs of 63 and 5 tests, about
   2026-09-20) no longer describes current code.
   Evidence: `rightrail-financial-workflow-20260913-STATE.md`.
8. **Provider App pre-submission checker core.** 2026-09-23: 13 of 13 Python tests and
   one Lean compile. Its later Lean comparison extension never built successfully.
   Evidence: `rightrail-provider-app-20260923-STATE.md`.
9. **Gate failover design model (TLA+).** 2026-09-25: TLC found no error in the
   safety model (2 nodes, 2 payments, 3 epochs; 3,516,192 distinct states): no
   conflicting tokens, no fenced token accepted, no release without a token or
   bypass, at most one release, no lost decision, stale primaries cannot sign.
   Bypass reconciliation (liveness) holds on a 1-payment model. A design model,
   not the code; the deeper model is still to run (memory). Evidence: `docs/formal/gate_failover/README.md`.
10. **Gate decision rules R1-R5 (Lean).** 2026-09-26: `BlindLedger.Gate.Rules` builds;
    sound, complete, hold_complete, fail_closed, monotone and arrival-order deterministic
    are proved, axioms pinned. Each line has an identity and claims its exact key, near
    key and identity whatever its outcome or enrollment (only a CAP_820 line known not
    enrolled with its plan claims no member-month). Certain reasons, a duplicate of an
    unresolved line and a reused identity (`ALREADY_DECIDED`) HOLD; unusable data, bad
    or future dates, near duplicates and FFS near collisions with unresolved lines
    review; neither ALLOWs. The key guarantees are `allow_clear` (an ALLOW line shares
    no key with a released or unresolved line but that member-month) and
    `allowed_decideAll` (ALLOW lines of a batch share none); `ids_disjoint` keeps an
    identity in at most one set. Both sets are append-only in v1: each must extend the
    gate's checkpoint of it, else `STALE_*`. `gate_rules` passes 210 of 210 vectors and
    all 3,616 demo lines (134 held, $46,987.00; 6 review; state ZZ), also as a unittest;
    all 155 mutants are killed on a scratch copy. Tests only, not the token path.
    REQUIRED trusted input: the gate's signed checkpoint of both sets (gate-v1); the
    runner holds it in memory. REQUIRED for the unbuilt release path: it removes lines
    from the unresolved set by identity, on release and on reject, under a new signed
    checkpoint; before releasing it checks exact keys, near keys and member-months,
    not-enrolled lines included, against the released set; a retry after an outage
    must reuse the original identities. It must refuse to release an `ALREADY_DECIDED`
    decision and bind each release to the exact reviewed row's identity. Before
    releasing a stale-feed review it must re-run R1, R3 and R5 on fresh snapshots: that
    review can hide known-bad facts. Corrections of held CAP member-months wait on it.
    OPEN, fixed next on gate-rules-2 and REQUIRED before any token-path use: the
    checkpoint must also take the gate's own new identities when the read set was
    unusable; until then a rollback after an unresolved-set outage lets a later batch
    ALLOW.

## What is written but has never run

- **Offline service kit** (assemble, verify, run, serve; lost-response retry; SHADOW
  restore). 0 runs; archive never assembled; needs an Engine build receipt.
- **Switch** shadow replay module and CLI: 10 tests written, 0 run.
- **Staff server additions** (read bundle, envelope, browser checks): 3 test files skipped.
- **Release producer script and service kit** (`tools/build_financial_correction_release.ps1`,
  `tools/right_rail_financial_service_kit.py`): still expect the retired pin's reuse vectors,
  whose request embeds a BLFCRES1 result; a BLFCRU01 vector from the current engine has
  yet to be produced. Never run against `artifacts/engine-correction/`.
- **Queue source-bound lifecycle mode**: still closed; the program is on its old pin.
- **State BLSDRQ01 clearance route**: run r2 (2026-09-24) was 45 passed, 1 failing (a
  retry-conflict test got the wrong error type). Later fixes are unrun; the production
  pin is still pending. Evidence: `lean-state-20260913-STATE.md`.
- **Provider Trust Graph** read model and local browser view: 12 tests written, 0 run.
- **Qualification bundle**: 17 tests written, 0 run; 8 evidence slots empty.
- **Security calculator cleanup**: its 64-test module not rerun.

## Known blockers

1. **One heavy run at a time.** All builds and tests share one guarded lane.

## Parked

Nothing product-facing. Private zero-knowledge (`PRIVATE_ZK`) was un-parked on 2026-09-25 as an
evidence-only prototype track (Constitution IX.4); old code under `parked/` is reference.
The native work in `pq-wide-seed-native-20260913` is frozen as history. Retired research
history lives in bundles under `work/_retired-research-20260924`.

## Next 6 concrete steps

1. **Run the service kit end-to-end**: assemble, verify, run the scenario, serve the
   staff app on loopback, on the `artifacts/engine-correction/` pin.
2. **correction-v3** (rr-review deferrals): M2, a READY request can go stale after later
   money events: add a cancel/reduce transition and `excessRequested`, then have the checker
   count earlier actions by their status at decision time, not today's; L5, reject at zero
   shortfall without writing a correction; L1, retired pins ignore time: add a
   pin-transition event. Also: correction reuse trusts the accepted result's recorded input
   shortfall and ignores the paid list; fix before any app path calls
   `--assess-correction-reuse` (none does). From round 3: a tighter theorem (amount +
   outstanding(existing) <= shortfall) and paid-list well-formedness, with no existing
   statement changed; and why a duplicate payment after an evaluation gives
   `correction_transition_failed` with a "reopen and try again" message.
3. **Make `rightrail-main` the only place code changes**; old checkouts become read-only.
4. **Hospital-payment full cycle demo** per the plan: 20 hospitals, $1M, Hospital H
   short $3,000, with incomplete files, disputed offsets, late records, partial
   corrections, repeat messages, crash recovery and restore, all visible in Mirror.
5. **Second, nonfinancial workflow via the Provider Trust Graph**: run its 12 written
   tests, then expose it read-only through an authenticated staff route.
6. **Owner writes don't re-verify the funding projection**: a tampered projection still accepted 70 writes on top.
   Writer store_busy 0 during checker re-checks was measured on small stores; where a full check exceeds about 5 s, owner writes during a re-check can get store_busy (safe: changed:false, the held-body retry works).

## Current rules and limits

Past entries, approvals and gate-change records (B2, 11ff5ee, round 3 #7) are in
`git log` and in STATUS.md at d79aceb.

- **Correction amount.** Lean decides min(claim, max(shortfall - unpaid earlier requests, 0));
  unpaid = requested less active payments linked to the request. With nothing left the
  owner returns `correction_no_requestable_balance` and records nothing; zero shortfall is
  NO_SHORTFALL first. Theorems `applyCorrectionTransition_action_amount_eq_b2` and
  `applyCorrectionTransition_outstanding_within_shortfall`.
- **Checker on corrections.** `action:requestable` (every correction, whatever engine it
  names, within the bound, plus its engine's own rule), `action:engine-order` (no older
  engine after a newer one), `action:event-amount` (decision event = claim),
  `action:status` (CANCELLED refused; v2 never cancels), `payment:link` (link to an
  unknown, foreign or later request, or one that overpays it).
- **Engine pins.** The current pin (rule `h1-v1`) decides every new correction. Retired
  pins in the append-only `artifacts/engine-correction/RETIRED_PINS` (E911
  `correction-rule-v1`, 88D8 `b2-v1`) are accepted for committed history only; the
  checker pins the registry's SHA-256, and a missing, edited or malformed registry fails
  `history:correction-retired-pins`, an unlisted engine
  `history:correction-followup-artifact-binding`.
- **Pinned artifacts.** Engine `blind_financial_correction.exe` 1A7A1833...D3AF
  (6,279,168 B); request vector B658DCEE...D067 (BLFCMD02, empty paid list); result
  83BB53D1...E0D6 (BLFCRES3). Reuse wire BLFCRV02/BLFCRU02, inner version 2.
- **Continuity v8.** History is sealed into chained segments, exported and restored by
  replay (`docs/CORE_REDESIGN.md`); at most 10,000 events or rows per table, refused
  before commit. Stores from before v8 fail `unsupported_store_version` (decision C3).
- **Staff surface.** `app/staff_workspace/interaction-model.json` declares every screen,
  control, route and response message; `tests/test_right_rail_mirror_interaction_model.py`
  walks it. `tools/right_rail_scorecard.py` measures the Hospital H journey per role
  (`docs/SCORECARD.md`); `tests/test_right_rail_scorecard.py` fails if a unit gets worse.
- **Budgets.** `tests/test_bloat_budget.py` ratchets live code, core file and duplicated
  windows down; STATUS.md at most 40,000 B, Markdown at most 180,000 B.

Known limits, not fixed:

- Reuse trusts the accepted result's recorded shortfall, ignores the paid list and
  compares the determination record but not its stored digest (the checker catches a
  mismatch on open). No app path calls `--assess-correction-reuse`.
- The command log does not record `pays_action_id` (the event chain does).
- `tools/build_financial_correction_release.ps1` names an old request vector (never run).
- Opening a store and the staff snapshot run the whole checker: about 27 s at 10,000
  rows, over the 5 s target. Not done: Lean seal codec; staff TEST restore via the
  history export.
- Staff server: UI-only roles, no refusal log, no connection cap; its 403/404/400 POST
  refusals do not read the body. The replacement operator cannot take over unfinished
  work.
