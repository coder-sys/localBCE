# RightRail status

Current truth only, replaced once per trunk merge. History is `git log`; protected-change records are `git log --grep '^XI.2:'`.
`CONSTITUTION.md` is supreme; `ARCHITECTURE.md` says how the code fits together. Git state, raw guard logs and artifact provenance
govern; a branch's pass does not verify another branch or their combination. Describes trunk
`237940be`.

## Product and standing claims

One state-controlled record connects approved rules, evidence, unresolved work, official decisions and follow-through. Control Pack,
Blind Ledger, Mirror, Continuity and Switch share the financial owner; Provider App is separate. The payment gate is one authority
level within that product. Existing payment systems move money. Synthetic, state-local, non-PHI, nonpayment; `proofSuiteId=null`,
`production_usable=false`, `activation=false`. Guarded local runs are merge evidence, not release qualification.

## What landed since d7192b0

Trunk `237940be`: full suite `pfafull2` 914 run, 899 pass, 0 fail, 15 skip. `fe031708`: Lean `sv2t1` 120 jobs,
semgate `sv2t3` 23/23.

- **STATE/v2 custody (Lean, unwired).** Custody state folds one append-only off-machine log; an epoch-keyed TPM
  counter catches rollback; activation once per shard; a payment's ALLOWs share one checkpoint (`never_twice`).
- **Payer release batch (BATCH-P1, Lean).** A batch answers each item exactly as single-token RELEASE (`releaseBatch_eq`);
  ACCEPT is exactly the payer's twelve checks, earned in the call (`releaseBatch_spec`, `_accept_verified`); a bad item or
  unnamed checkpoint changes no other answer; an already-released item never accepts (`releaseBatch_once`). Axioms pinned.
- **Deployment slots (D7).** An empty slot reads its strictest value, logs `DEPLOYMENT_SLOT_EMPTY`, refuses activation.
- **APPROVAL/v1 line digest.** Raw 64-byte SHA3-512 `line_digest`; Lean checks it, then decodes stored bytes, never re-encodes.
- **835 absorb.** Two parsers, no shared code, agree row for row; a faulty claim or PLB block becomes a RAW row; an unreadable
  amount holds the file; only an unreadable BPR02 refuses it. A 6.9x fast fold (92.2k lines/s/core)
  matches the slow parser on all fixtures and seeded mutations.
- **Payer release (S7a).** Lean decision and every write under one lock; append-only `closed` table; one hold row per refusal.
- **Absorb ladder (cash file).** A bad row is held with a reason, a repeat is a `DUPLICATE`, the rest records; a file that
  cannot be absorbed whole is refused with nothing written.
- **Bypass only per verified payment** (XI.2). **Python decider retired:** only the contained Lean worker decides.
- **Gate/cash file.** Per-shard decider lease; plan on a copy, commit under the lock (quarter-end lock 1.44-1.65 s, bound 5 s).
- **Lean decides every payment (M3);** ByteArray frames proved equal; M4 claim and offset laws; M1 offset cap.
- **Pins.** Worker `7C1EAB94...`, `gate_verify` `a9f47312...` (`artifacts/`), `tcb_pin` passes. Superseded pins:
  PROVENANCE files, `RETIRED_PINS`.

## Standing design

- **Owner and checker (v8 only).** One verified writer connection, WAL with `synchronous=FULL`, a per-obligation pre-COMMIT checker,
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
  payments); a raising ROLLBACK fails the next write once (untested). The fallback `run_batch` path grows with an
  item's history (2.7 -> 4.6 s over four files); the production route is flat (~1 s).
- **Real-world data:** a dirty Medicaid corpus (branch `dirty-corpus`) shows unrepresentable cases (advance payments, member
  crosswalk, PLB balances, death after release, upward retro rates).
- **Gate:** 145-166 lines/s at batch 100, 628-690 at batch 2,000 (target 50,000). Before live use the rules worker
  needs a pinned `RULES_SOURCE` and a memory cap, BLFPAY01 a Lean length check (re-pin). Unbuilt: payer pin before send,
  prior-digest check, integrated payer gate, durable token (payer release: S7a, above). Failover TLC is a bounded model.
- **Unbuilt:** financial file adapters (MCO reports, X12 820, MMIS extracts), payee-identity consumption, a second synthetic state,
  a Lean seal codec. The NC capture path is synthetic file intake.
- **Carried, not re-measured:** the staff role header is a claim the server enforces, not a login; no cancel or reduce command for stale corrections; receipt
  `delivery_status` is the newest action's, not the verdict; core size targets unmet (owner 6,756 vs ~3,000 lines, checker 4,451 vs
  ~1,800); TEST restore uses the system clock; published items cannot be re-stated (`item:duplicate`); a dead decider worker is not
  restarted (fails safe).
- **Acknowledger not stored (open, needs rr-core):** `ACTION_ACKNOWLEDGED` records no actor, so the rule that a decider may not
  acknowledge is claim-level and cannot be re-verified by checker or Lean; fixing it needs a versioned ACK record.

Next: STATE/v2 wiring, hold-release S3b+ (slot consumers), cash-line hold ledger.
A local commit, not a qualified release; no local check activates production.
