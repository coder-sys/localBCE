# RightRail status

Current truth only, replaced once per trunk merge. History is `git log`; protected-change records are `git log --grep '^XI.2:'`.
`CONSTITUTION.md` is supreme; `ARCHITECTURE.md` says how the code fits together. Git state, raw guard logs and artifact provenance
govern; a branch's pass does not verify another branch or their combination. Describes trunk `70f9606`.

## Product and standing claims

One state-controlled record connects approved rules, evidence, unresolved work, official decisions and follow-through. Control Pack,
Blind Ledger, Mirror, Continuity and Switch share the financial owner; Provider App is separate. The payment gate is one authority
level within that product. Existing payment systems move money. Synthetic, state-local, non-PHI, nonpayment; `proofSuiteId=null`,
`production_usable=false`, `activation=false`. Guarded local runs are merge evidence, not release qualification.

## What landed on trunk 70f9606 (raw output: `native/guard/guarded-command-*.stdout.log`; exits in `C:/Users/neers/rrb/logs/`)

- **Gate fast SHA3.** The gate's SHA3 call sites run the proved-equal fast sponge (`Sha3Fast.lean`; `sha3_512_eq`, `shake128_eq`,
  `shake256_eq` hold for all inputs on `propext`, `Classical.choice`, `Quot.sound` only). No gate theorem's axioms changed. Rules
  decide went from 99.5 to 251.6 lines/s on 20,000 lines.
- **Worker payments as ByteArray.** Payment frames (BLFPAY01) are read from the byte array, not a `List UInt8`. The held-memory leak
  is fixed: an 8.1 MB item grew the worker from 650 to 952 MB (then hit the 1 GB cap at item 6); it now stays flat near 62 MB. Old
  and new workers answered 51,539 frames identically.
- **M3 step 3, flag off.** Lean-side payment decision path with a differential against the current path; the flag stays off, so no
  live behaviour moved. T2 passes (Lean 23.05 ms against a 23.76 ms bound).
- **M4 P1 corrections on the worker.** The one-shot correction exe is retired; corrections run on the evaluator worker. Its answers
  over 1,558 inputs equal the retired exe's (`tests/fixtures/correction_exe_answers.json`).
- **Pins.** Worker `58CDA012...` (`artifacts/engine-evaluator`), `gate_verify` `724de1bd...` (`artifacts/gate-verify`), `tcb_pin`
  8/8. Superseded pins are in each PROVENANCE file and `RETIRED_PINS`. Last full suite `i6-full2`: 725 run, 713 pass, 1 fail
  (`test_quarter_end_file_within_writer_timeout`, advisory), 11 skipped.

## Standing design

- **Owner and checker (v8 only).** One verified writer connection, WAL with `synchronous=FULL`, a pre-COMMIT per-obligation checker,
  the table SQL pin, at most 10,000 events or rows per table. Older stores fail without mutation.
- **Lean decides.** The pinned worker; Lean derives each request's paid-so-far from linked payments and the checker re-checks it
  before COMMIT. A worker frame with stray bytes fails closed.
- **Gate.** Decision rules R1-R5 in Lean, CHECKPOINT/v1, TOKEN/v1, the payer's `verifyToken`; the Lean `gate_verify` checks every
  checkpoint signature (ML-DSA-87; signer checked against NIST ACVP and AWS-LC).
- **TCB gate** (`tools/tcb_report.txt`, live run `tools/tcb_pin.ps1`): every constant each pinned exe reaches is proof-backed.
  Trusted, not proved: the toolchain's `Init` and `Std`, `WorkerCli.reserveArena`, and the placeholder axiom `lcProof`.
- **Size.** Limits are in `tests/test_bloat_budget.py`.

## Open items

- **Correction capacity** is about quadratic in rows: 2,000 rows take 2.6 s; 5,000 rows give a 3.65 MB frame over the 5 s bound.
  Refusal 14 is unreachable, so no capacity test exists. A profiler and byte-array encoders are in work.
- **Quarter-end advisory timing:** the twelfth cash file's writer lock is about 5.5 s against a 5 s bound; the test fails and is
  advisory. A fresh worktree also shows errors from missing ignored build outputs.
- **M3 binding fixes** from the integ6 review (one Medium, two Low, all on the flag-off path) must land before the step-4 flag flip.
  The D4 live behaviour and a crash test belong to step 4.
- **Rules throughput:** 252 lines/s against a 2,000 lines/s target.
- **Gate unbuilt:** the checkpoint producer, the payer pin before send, the prior-digest check, an integrated payer gate and a durable
  token or release path. Failover TLC is a bounded model, not running failover.
- **Unbuilt:** financial file adapters (MCO reports, X12 820/835, MMIS extracts), payee-identity consumption, a second synthetic state,
  a Lean seal codec. The NC capture path is synthetic file intake.
- **Carried from earlier, not re-measured:** cash-file open verifies the whole store under the lock (10.05 s at 6,000 payments;
  `store_busy` possible); staff roles are UI-only (no authentication or refusal logging); no cancel or reduce command for stale
  corrections; the receipt's `delivery_status` is the newest action's, not the verdict; core size targets unmet (owner 7,327 lines
  against about 3,000, checker 4,594 against about 1,800); isolated TEST restore uses the system clock.

Next: M3 binding fixes, then the step-4 flag flip; connector and browser completion is paused at the founder's request. This
candidate is a local commit, not a qualified release; no local check activates production.
