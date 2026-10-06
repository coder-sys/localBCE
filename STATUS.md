# RightRail status

Current truth only, replaced once per trunk merge. History is `git log`; protected-change records are `git log --grep '^XI.2:'`.
`CONSTITUTION.md` is supreme; `ARCHITECTURE.md` says how the code fits together. Git state, raw guard logs and artifact provenance
govern; a branch's pass does not verify another branch or their combination. Describes trunk `d7192b0`.

## Product and standing claims

One state-controlled record connects approved rules, evidence, unresolved work, official decisions and follow-through. Control Pack,
Blind Ledger, Mirror, Continuity and Switch share the financial owner; Provider App is separate. The payment gate is one authority
level within that product. Existing payment systems move money. Synthetic, state-local, non-PHI, nonpayment; `proofSuiteId=null`,
`production_usable=false`, `activation=false`. Guarded local runs are merge evidence, not release qualification.

## What landed on trunk d7192b0

No full suite on `d7192b0` yet: `land-d7192b0-full` a1-a3 each stopped at the memory floor (no test result). Last full suite
`land-b319c53-full`: 842 run: 828 pass, 0 fail, 14 skips. Branch `m3-step5` (`m3s5-t-3`): 469 run: 468 pass, 1 skip.

- **Python decider retired (M3 step 5).** Payments are decided only in the contained Lean worker; the Python copy and its
  differential test are deleted; a new crash test kills the worker mid-payment.
- **Gate chaos.** A per-shard decider lease (`shard_busy` for a second decider, dropped on process death); an open row is never
  settled or freed (`unsealed_reservation`); producer and shard are paired by construction.
- **Hostile fuzz.** Typed refusals for hostile frames, clocks, text and certs; payer cert size and count caps.
- **Gate rules speed.** A decide 1.47 s -> 0.10 s; the persistent `gate_rules_worker` takes a 20-line decide to 0.009 s.

- **Cash file (design d).** Plan on a copy, commit under the lock; a stale plan re-plans (3 tries, then `cash_file_busy`).
  Quarter-end lock 1.44-1.65 s (was 5.9-6.1 s; bound 5 s).
- **Lean decides every payment (M3 step 4).** The owner asks Lean for every payment and reversal; every answer field is bound, and
  the pre-COMMIT checker re-reads payment links itself (`payment:link`). While the clock is behind the last update, only an exact
  retry is answered. Payment frame 0.62-0.65 ms against evaluation 0.31-0.32 ms.
- **ByteArray frames** (proved equal): a 5 MB correction 1.83 s / 259 MB (was 3.73 s / 846 MB); an 8.1 MB item ~62 MB (was 952 MB).
- **M4 claim and offset laws.** BLFOFC01/BLFOCR01 and `decideClaim` (section F theorems); offset laws served by Lean (BLFOFA01,
  tag 24); decisions dated before their pack's approval or start, and items due before their pack, are refused. The checker
  verifies `RETIRED_PINS` once per file state, so per-operation work no longer grows with each re-pin.
- **M1 offset cap.** Offset plus unpaid open requests <= shortfall.
- **Runtime multi-shard with a decide layer.** Lean proves one payment per line across shards (`Gate/Rules/Shards.lean`). The decide
  layer reserves ids, carries per-shard sets into Lean, seals, then settles the registry before any token leaves. It refuses a
  restored store or registry (checked at boot and at every reserve) and a stale answer (`stale_answer`). Registry and producer keep a
  checked SHA3 mark.
- **Pins.** Worker `7C1EAB94...`, `gate_verify` `a9f47312...` (see `artifacts/`), `tcb_pin` passes. Superseded pins: each
  PROVENANCE file and `RETIRED_PINS`. Stage builds `dp-3a`/`dp-3b` byte-identical.

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

- **Correction result cap:** a BLFCRES3 result embeds its input, so a correction near 7 MB is refused (tag 3).
- **Cash residuals:** a foreign commit before the first write costs a whole-store verify under the lock (~10 s at 6,000
  payments); a raising ROLLBACK fails the next write once (untested).
- **Real-world data:** a dirty Medicaid corpus (branch `dirty-corpus`) shows six unrepresentable cases
  (advance payments, member crosswalk, PLB balances, death after release, upward retro rates, one bad row refusing a file).
- **M3 step 5 review** (no money bug): crash test is timing-sensitive; a dead decider worker is not restarted (fails safe);
  no owner zero-amount test.
- **Gate:** 145-166 lines/s at batch 100, 628-690 at batch 2,000 (target 50,000). Before live use the rules worker
  needs a pinned `RULES_SOURCE` and a memory cap, BLFPAY01 a Lean length check (re-pin). Unbuilt: payer pin before send,
  prior-digest check, integrated payer gate, durable token or release path. Failover TLC is a bounded model.
- **Unbuilt:** financial file adapters (MCO reports, X12 820, MMIS extracts; 835 intake is synthetic, read-only), payee-identity consumption, a second synthetic state,
  a Lean seal codec. The NC capture path is synthetic file intake.
- **Carried, not re-measured:** the staff role header is a claim the server enforces, not a login; no cancel or reduce command for stale corrections; receipt
  `delivery_status` is the newest action's, not the verdict; core size targets unmet (owner 7,262 vs ~3,000 lines, checker 4,638 vs
  ~1,800); TEST restore uses the system clock; published items cannot be re-stated (`item:duplicate`).
- **Acknowledger not stored (open, needs rr-core):** `ACTION_ACKNOWLEDGED` records no actor, so the rule that a decider may not
  acknowledge is claim-level and cannot be re-verified by the checker or Lean; fixing it needs a versioned ACK record.

Next: STATE/v2 and the cash-line hold ledger.
A local commit, not a qualified release; no local check activates production.
