# RightRail status

Current truth only; the lead replaces what a merge supersedes, once per trunk merge (nobody else edits this file). History is
`git log`; protected-change records are `git log --grep '^XI.2:'`. The old log-style STATUS.md is archived at
`rrb/archive/STATUS-20261001.md`. `CONSTITUTION.md` is supreme; `ARCHITECTURE.md` says how the code fits together. Git state, raw guard
logs and artifact provenance govern; a branch's pass does not verify another branch or their combination.

## Product and standing claims

One state-controlled record connects approved rules, evidence, unresolved work, official decisions and follow-through. Control Pack,
Blind Ledger, Mirror, Continuity and Switch share the financial owner; Provider App is separate. The payment gate is one authority
level within that product. Existing payment systems move money. Synthetic, non-PHI, nonpayment; `proofSuiteId=null`,
`production_usable=false`, `activation=false`.

## What runs (raw output: the guard host's `native/guard/guarded-command-*.stdout.log`; exits in `C:/Users/neers/rrb/logs/`)

- **Owner and checker (v8 only).** One verified writer connection, WAL with `synchronous=FULL`, a pre-COMMIT per-obligation checker
  (44 to 13 ms at 2,500 events), the table SQL pin (any other schema object is refused at open), at most 10,000 events or rows per
  table. Older stores fail without mutation; recreate the workspace.
- **Lean decides.** The pinned evaluator worker and correction exe; Lean derives each request's paid-so-far from linked payments and
  the checker re-checks it before COMMIT. A linked payment may not exceed its request's derived open amount (package contract v3 adds
  `open_cents`); delivery waits on every action that still asks. The decision-package verdict reads whole-obligation counts, not the
  page window. The BLFCRES3 decoder re-encodes what it decoded; a worker frame with stray bytes fails closed.
- **Gate.** Decision rules R1-R5 in Lean (274/274 vectors, 204/204 mutants killed; tests only, not the token path). CHECKPOINT/v1,
  TOKEN/v1 and the payer's twelve-check `verifyToken` (256/256 golden vectors with real ML-DSA-87; theorems on `propext` and
  `Quot.sound` only). PQ signing M1: the Lean `gate_verify` checks every checkpoint signature; the signer is checked against NIST
  ACVP (115 vectors) and AWS-LC (4,944 cases).
- **TCB gate** (`tools/tcb_report.txt`, live run `tools/tcb_pin.ps1`): every constant each pinned exe reaches is proof-backed, no open
  `partial`, `while`, `repeat`, `IO.iterate` or stream `for`. Trusted, not proved: the pinned toolchain's `Init` and `Std`, the worker's
  one C call `WorkerCli.reserveArena`, and the placeholder axiom `lcProof`. The report's `manifest` line is the one copy of the source
  hash: each pinned exe's import closure plus `lakefile.toml`, `lean-toolchain` and `lake-manifest.json`.
- **Packs and follow-through.** CMS-64.9 line pack and follow-through pack (derived, documentation-only); an official's ASSIGN or
  CLOSE is one protected event checked before COMMIT. Correction follow-up reopens only when a derived dependency key moves.
- **Cash file.** At most 500 rows a file, 6 per item; funding, clock, connectors and staff workspace (direction 6, three-step
  decision, a lost answer stays retryable) have guarded runs; browser runs cover the success path only.
- **Size.** The Rust engine, oracle and proof instruments are out of product code; the limits are in
  `tests/test_bloat_budget.py`.

## Artifact boundary

- Pinned exes: correction `441EB3E8...F4A8A` (6,431,232 bytes), worker `86299A0D...1712B`, `gate_verify` `9BD2602B...C9916`; exact
  pins and construction in `artifacts/*/PROVENANCE.*`; superseded pins are in `RETIRED_PINS`.
- Engine runs r67-r89 in `artifacts/engine-correction/PROVENANCE.md` cover the retired h1 engine's tree, not the current pin; retained
  failures r75, r78, r81-r83, r85 are unresolved.
- The offline kit archive binds its assembly tree; these checks do not qualify the connector or browser tracks.

## Written but unrun or unbuilt

- Lean-live M3 payment model (`Payment/*`, `Rev12.lean`) and decision-package Lean step 1 (`DecisionPackage/Conclude`, `Wire`, `Laws`):
  proved and pinned in `AxiomCheck.lean`, but nothing calls them yet. The R2 request-shrink Lean half is M3 step 2.
- Gate: the checkpoint producer, the payer pin before send and the prior-digest check are unbuilt; no integrated payer gate and no
  durable token or release path. Failover TLC is a bounded model (3,516,192 states), not running failover.
- The NC capture path is synthetic file intake. Financial file adapters (MCO reports, X12 820/835, MMIS extracts), shared
  provider/gate rules, payee-identity consumption, a second synthetic state (G3) and a Lean seal codec are unbuilt.

## Blockers and open risks

- The full suite is never fully green: `test_quarter_end_file_within_writer_timeout` fails (the twelfth cash file's writer lock is
  about 6 s against a 5 s bound), and a fresh worktree shows about 13 errors from missing ignored build outputs.
- Cash-file open verifies the whole store under the lock: 10.05 s at 6,000 payments, 7.11 s warm apply with 66 earlier payments per
  item. Whole-history checking was about 27 s at 10,000 rows (target 5 s). Lock contention may return `store_busy`.
- Staff roles are UI-only: no authentication, refusal logging or connection caps; a replacement operator can restore and read but not
  take over work.
- No cancel or reduce command for stale corrections; CANCELLED is never written. The receipt's `delivery_status` is the newest
  action's, not the verdict, which lives in Python until M3 step 2.
- Core size targets unmet: owner about 3,000 lines targeted against 7,327, checker about 1,800 against 5,225.
- Isolated TEST restore uses the system clock. The command log omits `pays_action_id`; the event chain carries it.

Next: connector and browser completion is paused at the founder's request; final combined-source verification is outstanding. This
candidate is a local commit, not a qualified release; no local check activates production.
