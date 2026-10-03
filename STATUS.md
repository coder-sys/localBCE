# RightRail status

Current truth only, replaced once per trunk merge. History is `git log`; protected-change records are `git log --grep '^XI.2:'`.
`CONSTITUTION.md` is supreme; `ARCHITECTURE.md` says how the code fits together. Git state, raw guard logs and artifact provenance
govern; a branch's pass does not verify another branch or their combination. Describes trunk `1f5a7d6`.

## Product and standing claims

One state-controlled record connects approved rules, evidence, unresolved work, official decisions and follow-through. Control Pack,
Blind Ledger, Mirror, Continuity and Switch share the financial owner; Provider App is separate. The payment gate is one authority
level within that product. Existing payment systems move money. Synthetic, state-local, non-PHI, nonpayment; `proofSuiteId=null`,
`production_usable=false`, `activation=false`. Guarded local runs are merge evidence, not release qualification.

## What landed on trunk 1f5a7d6 (raw output: `native/guard/guarded-command-*.stdout.log`; exits in `C:/Users/neers/rrb/logs/`)

- **M3 answer binding (flag off).** Every payment-answer evidence and conflict field, DUPLICATE and ALIAS included, is bound;
  closes the integ6 review. `mb-int-1`: all pass but quarter-end timing; gate `mb-int-6` 29/29 (stale `.lake` exe rebuilt).
- **Correction frames as ByteArray.** Corrections re-encode through proved-equal byte-array twins (`CorrectionFast.lean`, `_eq`
  theorems pinned). Accepted 5 MB: 3.73 s / 846 MB before, 1.83 s / 259 MB now; the 7 MB cap frame 2.58 s / 164 MB. The worker
  stays flat within 16 MB across requests. Worker re-pinned `58CDA012` -> `8EB77363`.
- **M4 claim item laws.** BLFOFC01 request, BLFOCR01 answer and `decideClaim`, with the six section F theorems proved and pinned.

- **Gate fast SHA3.** The gate's SHA3 call sites run the proved-equal fast sponge (`Sha3Fast.lean`; `sha3_512_eq`, `shake128_eq`,
  `shake256_eq` hold for all inputs on `propext`, `Classical.choice`, `Quot.sound` only). No gate theorem's axioms changed. Rules
  decide went from 99.5 to 251.6 lines/s on 20,000 lines (target 2,000).
- **Worker payments as ByteArray.** BLFPAY01 frames are read as a byte array; an 8.1 MB item now holds the worker near 62 MB (was
  952 MB). Corrections run on the evaluator worker (one-shot exe retired; 1,558 answers equal).
- **M3 step 3, flag off.** Lean-side payment decision path with a differential; the flag stays off, so no live behaviour moved.
- **Pins.** Worker `8EB77363...` (`artifacts/engine-evaluator`), `gate_verify` `724de1bd...` (`artifacts/gate-verify`), `tcb_pin`
  8/8. Superseded pins are in each PROVENANCE file and `RETIRED_PINS`. Merged tree: full lake build `cc-int-1` exit 0 with both
  built exes byte-identical to the pins; full suite `cc-int-2` plus rerun `cc-int-3`: every module passes except
  `test_quarter_end_file_within_writer_timeout` (fails on trunk too).

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

- **Correction result cap:** a BLFCRES3 result embeds its input, so an accepted correction near 7 MB is refused (tag 3) at the
  result cap. Request cap against result cap is an open design question.
- **Quarter-end timing fails:** the twelfth cash file's writer lock is 5.9-6.1 s against a 5 s bound (`cash-trunk-2`, `cash-cc-1`).
  A fresh worktree also needs the ignored `rr_gate_mldsa87.exe` copied in, or the signer tests error.
- **Real-world data:** a seeded dirty Medicaid corpus (branch `dirty-corpus`, not on trunk) shows six unrepresentable cases:
  advance payments, member crosswalk, PLB balances, death after release, upward retro rates, one bad cash row refusing a file.
- **M3 step 4:** the D4 live behaviour and a crash test come with the flag flip.
- **Gate unbuilt:** the checkpoint producer, the payer pin before send, the prior-digest check, an integrated payer gate and a durable
  token or release path. Failover TLC is a bounded model, not running failover.
- **Unbuilt:** financial file adapters (MCO reports, X12 820/835, MMIS extracts), payee-identity consumption, a second synthetic state,
  a Lean seal codec. The NC capture path is synthetic file intake.
- **Carried from earlier, not re-measured:** cash-file open verifies the whole store under the lock (10.05 s at 6,000 payments;
  `store_busy` possible); staff roles are UI-only (no authentication or refusal logging); no cancel or reduce command for stale
  corrections; the receipt's `delivery_status` is the newest action's, not the verdict; core size targets unmet (owner 7,327 lines
  against about 3,000, checker 4,594 against about 1,800); isolated TEST restore uses the system clock.

Next: the M3 step-4 flag flip; connector and browser completion is paused at the founder's request. This
candidate is a local commit, not a qualified release; no local check activates production.
