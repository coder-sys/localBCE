# RightRail status

Current truth only, replaced once per trunk merge. History is `git log`; protected-change records are `git log --grep '^XI.2:'`.
`CONSTITUTION.md` is supreme; `ARCHITECTURE.md` says how the code fits together. Git state, raw guard logs and artifact provenance
govern; a branch's pass does not verify another branch or their combination. Describes trunk `c4c5cb9`.

## Product and standing claims

One state-controlled record connects approved rules, evidence, unresolved work, official decisions and follow-through. Control Pack,
Blind Ledger, Mirror, Continuity and Switch share the financial owner; Provider App is separate. The payment gate is one authority
level within that product. Existing payment systems move money. Synthetic, state-local, non-PHI, nonpayment; `proofSuiteId=null`,
`production_usable=false`, `activation=false`. Guarded local runs are merge evidence, not release qualification.

## What landed on trunk c4c5cb9

Full suite `land-c4c5cb9-full` on this tree: 823 run: 809 pass, 0 fail, 14 skips.

- **Cash file (design d).** Plan on a copy, commit under the lock; a stale plan re-plans (3 tries, then `cash_file_busy`).
  Quarter-end lock 1.44-1.65 s (was 5.9-6.1 s; bound 5 s).
- **Lean decides every payment (M3 step 4).** The owner asks Lean for every payment and reversal; every answer field is bound, and
  the pre-COMMIT checker re-reads payment links itself (`payment:link`). While the clock is behind the last update, only an exact
  retry is answered. Payment frame 0.62-0.65 ms against evaluation 0.31-0.32 ms. The Python decider stays until step 5.
- **ByteArray frames.** Corrections and BLFPAY01 run through proved-equal byte-array twins: accepted 5 MB correction 1.83 s / 259 MB
  (was 3.73 s / 846 MB); an 8.1 MB item holds the worker near 62 MB (was 952 MB).
- **M4 claim and offset laws.** BLFOFC01/BLFOCR01 and `decideClaim` (section F theorems); offset laws served by Lean (BLFOFA01,
  tag 24); a decision dated before its pack's approval or effective start is refused, as is an item due before its pack. The checker verifies `RETIRED_PINS` once per file state,
  so per-operation work no longer grows with each re-pin.
- **M1 offset cap.** Offset plus unpaid open requests <= shortfall.
- **Runtime multi-shard with a decide layer.** Lean proves one payment per line across shards (`Gate/Rules/Shards.lean`). The decide
  layer reserves ids, carries per-shard sets into Lean, seals, then settles the registry before any token leaves. It refuses a
  restored store or registry (checked at boot and at every reserve) and a stale answer (`stale_answer`). Registry and producer keep a
  checked SHA3 mark.
- **Gate fast SHA3** (`Sha3Fast.lean`, proved equal): rules decide 251.6 lines/s on 20,000 lines (target 2,000).
- **Pins.** Worker `7C1EAB94...` (`artifacts/engine-evaluator`), `gate_verify` `a9f47312...` (`artifacts/gate-verify`), `tcb_pin`
  passes. Superseded pins: each PROVENANCE file and `RETIRED_PINS`. Stage builds `dp-3a`/`dp-3b` byte-identical.

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
- **Real-world data:** a seeded dirty Medicaid corpus (branch `dirty-corpus`, not on trunk) shows six unrepresentable cases
  (advance payments, member crosswalk, PLB balances, death after release, upward retro rates, one bad row refusing a file).
- **M3 step 5:** retire the Python decider; a crash test of the Lean payment path is still owed.
- **Gate:** a second decider on one shard and an open, unsigned row are not yet refused (fix on `gate-chaos`). A decide
  costs ~1.8 s, mostly a cold `gate_rules` process. Unbuilt: payer pin before send, prior-digest check, integrated payer gate,
  durable token or release path. Failover TLC is a bounded model.
- **Unbuilt:** financial file adapters (MCO reports, X12 820/835, MMIS extracts), payee-identity consumption, a second synthetic state,
  a Lean seal codec. The NC capture path is synthetic file intake.
- **Carried, not re-measured:** staff roles are UI-only; no cancel or reduce command for stale corrections; receipt
  `delivery_status` is the newest action's, not the verdict; core size targets unmet (owner 7,441 vs ~3,000 lines, checker 4,631 vs
  ~1,800); TEST restore uses the system clock; published items cannot be re-stated (`item:duplicate`).

Next: land `gate-chaos` and `hostile-fuzz` (in review), M3 step 5, a persistent `gate_rules` worker.
A local commit, not a qualified release; no local check activates production.
