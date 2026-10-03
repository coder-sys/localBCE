# RightRail status

Current truth only, replaced once per trunk merge. History is `git log`; protected-change records are `git log --grep '^XI.2:'`.
`CONSTITUTION.md` is supreme; `ARCHITECTURE.md` says how the code fits together. Git state, raw guard logs and artifact provenance
govern; a branch's pass does not verify another branch or their combination. Describes trunk `a6c0125`.

## Product and standing claims

One state-controlled record connects approved rules, evidence, unresolved work, official decisions and follow-through. Control Pack,
Blind Ledger, Mirror, Continuity and Switch share the financial owner; Provider App is separate. The payment gate is one authority
level within that product. Existing payment systems move money. Synthetic, state-local, non-PHI, nonpayment; `proofSuiteId=null`,
`production_usable=false`, `activation=false`. Guarded local runs are merge evidence, not release qualification.

## What landed on trunk a6c0125

Full suite `os-full-2` on this tree: 785 pass, 0 fail, 14 skips (logs: `native/guard/`, `C:/Users/neers/rrb/logs/`).

- **Cash file (design d).** Plan on a copy, commit under the lock; a stale plan re-plans (3 tries, then `cash_file_busy`).
  Quarter-end lock 1.44-1.65 s (was 5.9-6.1 s; bound 5 s).
- **M3 answer binding (flag off).** Every payment-answer evidence and conflict field, DUPLICATE and ALIAS included, is bound.
- **Correction frames as ByteArray.** Corrections re-encode through proved-equal byte-array twins (`CorrectionFast.lean`, `_eq`
  theorems pinned). Accepted 5 MB: 3.73 s / 846 MB before, 1.83 s / 259 MB now; the 7 MB cap frame 2.58 s / 164 MB. The worker
  stays flat within 16 MB across requests.
- **M4 claim and offset laws.** BLFOFC01/BLFOCR01 and `decideClaim` (section F theorems); offset laws served by Lean (BLFOFA01,
  tag 24); a decision dated before its pack's approval or effective start is refused, as is an item due before its pack. The checker verifies `RETIRED_PINS` once per file state,
  so per-operation work no longer grows with each re-pin.
- **M1 offset cap.** Offset plus unpaid open requests <= shortfall.
- **Shards.** Lean proves one payment per line across shards (`Gate/Rules/Shards.lean`). Registry and producer
  keep a checked SHA3 mark refusing a restored older store.
- **Gate fast SHA3.** The proved-equal fast sponge (`Sha3Fast.lean`). Rules decide 99.5 ->
  251.6 lines/s on 20,000 lines (target 2,000).
- **Worker payments as ByteArray.** BLFPAY01 frames are read as a byte array; an 8.1 MB item now holds the worker near 62 MB (was
  952 MB). Corrections run on the evaluator worker.
- **Pins.** Worker `7C1EAB94...` (`artifacts/engine-evaluator`), `gate_verify` `724de1bd...` (`artifacts/gate-verify`), `tcb_pin`
  8/8. Superseded pins: each PROVENANCE file and `RETIRED_PINS`. Stage builds `m1-9a`/`m1-9b` byte-identical.

## Standing design

- **Owner and checker (v8 only).** One verified writer connection, WAL with `synchronous=FULL`, a pre-COMMIT per-obligation checker,
  the table SQL pin, at most 10,000 events or rows per table. Older stores fail without mutation.
- **Lean decides.** The pinned worker; Lean derives each request's paid-so-far from linked payments and the checker re-checks it
  before COMMIT. A worker frame with stray bytes fails closed.
- **Gate.** Decision rules R1-R5 in Lean, CHECKPOINT/v1, TOKEN/v1, the payer's `verifyToken`; the Lean `gate_verify` checks every
  checkpoint signature (ML-DSA-87; signer checked against NIST ACVP and AWS-LC).
- **TCB gate** (`tools/tcb_report.txt`, live run `tools/tcb_pin.ps1`): every constant each pinned exe reaches is proof-backed.
  Trusted, not proved: the toolchain's `Init` and `Std`, `WorkerCli.reserveArena`, and the placeholder axiom `lcProof`.

## Open items

- **Correction result cap:** a BLFCRES3 result embeds its input, so an accepted correction near 7 MB is refused (tag 3) at the
  result cap.
- **Cash residuals:** a foreign commit before the first write costs a whole-store verify under the lock (~10 s at 6,000
  payments). A ROLLBACK that raises fails the next write once (untested).
- **Fresh worktrees** need the ignored `rr_gate_mldsa87.exe` copied in, or signer tests error.
- **Real-world data:** a seeded dirty Medicaid corpus (branch `dirty-corpus`, not on trunk) shows six unrepresentable cases:
  advance payments, member crosswalk, PLB balances, death after release, upward retro rates, one bad cash row refusing a file.
- **M3 step 4:** the D4 live behaviour and a crash test come with the flag flip.
- **Gate unbuilt:** a decide layer calling the producer and registry (until then multi-shard is unsafe; a
  whole-directory restore passes the mark), the payer pin before send, the prior-digest check, an integrated payer gate and a durable
  token or release path. Failover TLC is a bounded model, not running failover.
- **Unbuilt:** financial file adapters (MCO reports, X12 820/835, MMIS extracts), payee-identity consumption, a second synthetic state,
  a Lean seal codec. The NC capture path is synthetic file intake.
- **Carried from earlier, not re-measured:** staff roles are UI-only (no authentication or refusal logging); no cancel or reduce command for stale
  corrections (so an unpaid request blocks offsetting that amount); the receipt's `delivery_status` is the newest action's, not the
  verdict; core size targets unmet (owner 7,441 lines against about 3,000, checker 4,631 against about 1,800);
  isolated TEST restore uses the system clock; published items cannot be re-stated (`item:duplicate`).

Next: runtime multi-shard, M3 step 4; connector and browser work paused by the founder.
A local commit, not a qualified release; no local check activates production.
