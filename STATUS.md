# RightRail status

Current truth only, replaced once per trunk merge. History is `git log`; protected-change records are `git log --grep '^XI.2:'`.
`CONSTITUTION.md` is supreme; `ARCHITECTURE.md` says how the code fits together. Git state, raw guard logs and artifact provenance
govern; a branch's pass does not verify another branch or their combination. Describes trunk `85e4b097` (merge-b2: hold-release
slices S0, S2, S3a, S7a on `fd7ccf72`).

## Product and standing claims

One state-controlled record connects approved rules, evidence, unresolved work, official decisions and follow-through. Control Pack,
Blind Ledger, Mirror, Continuity and Switch share the financial owner; Provider App is separate. The payment gate is one authority
level within that product. Existing payment systems move money. Synthetic, state-local, non-PHI, nonpayment; `proofSuiteId=null`,
`production_usable=false`, `activation=false`. Guarded local runs are merge evidence, not release qualification.

## What landed since d7192b0

Trunk `85e4b097`, full suite `mb2full1`: 909 run: 894 pass, 0 fail, 15 skips. Semantic gate `mb2sem1` PASS (26 properties;
artifact `061b5cad...`).

- **Deployment slots (S0, founder D7).** Five slots in one table with one reader. An unauthored or authored-empty slot reads
  its strictest value, logs `DEPLOYMENT_SLOT_EMPTY`, and activation is refused. Contradictory packs are refused, each with its own code. No consumer yet.
- **APPROVAL/v1 line digest (S2).** Each move carries a raw 64-byte `line_digest` (SHA3-512, domain `RR/APPROVAL/LINE/v1`); no
  other length has an encoding. Lean `Approval.admitMoves` checks the stored digest, then decodes the stored bytes, never
  re-encodes. Four canonical-decoder theorems (`ApprovalLaws.lean`) are `#guard_msgs` pins: a sorry fails the build.
- **835 absorb (S3a).** Both parsers agree row for row with no shared code. A faulty claim or PLB
  block becomes a RAW row; an unreadable amount leaves totals `None` with `balance_unverified`, which holds the file. Only an
  unreadable BPR02 refuses the whole file.
- **Payer release (S7a).** `release()` runs the Lean decision and every write under one write lock; an append-only `closed`
  table is the only double-release guard. Every refusal writes exactly one hold row.
- **Absorb ladder (cash file).** A bad row is held with a reason (`conflict`, `already_recorded`, `unknown_item`,
  `depends_on_held`), a repeat is a `DUPLICATE`, and the rest of the file records. A file that cannot be absorbed whole (revision
  conflict, unknown action, payment past the unpaid balance) is still refused with nothing written. Receipt contract v3.
- **XI.2 amendment: a bypass only per verified payment** (I.2, target 6).
- **Python decider retired (M3 step 5).** Payments are decided only in the contained Lean worker.
- **Gate.** Per-shard decider lease (`shard_busy`); an open row is never settled or freed; a reproducible throughput bench with a pinned digest.
- **Cash file (design d).** Plan on a copy, commit under the lock; a stale plan re-plans (3 tries, then `cash_file_busy`).
  Quarter-end lock 1.44-1.65 s (bound 5 s).
- **Lean decides every payment (M3 step 4);** ByteArray frames (proved equal); M4 claim and offset laws; M1 offset cap;
  multi-shard decide layer.
- **Pins.** Worker `7C1EAB94...`, `gate_verify` `a9f47312...` (see `artifacts/`), `tcb_pin` passes. Superseded pins: each
  PROVENANCE file and `RETIRED_PINS`.

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
  payments); a raising ROLLBACK fails the next write once (untested). The direct `run_batch` path (the fallback) grows with an
  item's history (2.7 -> 4.6 s over four files); the production route is flat (~1 s).
- **Real-world data:** a dirty Medicaid corpus (branch `dirty-corpus`) shows unrepresentable cases (advance payments, member
  crosswalk, PLB balances, death after release, upward retro rates).
- **Gate:** 145-166 lines/s at batch 100, 628-690 at batch 2,000 (target 50,000). Before live use the rules worker
  needs a pinned `RULES_SOURCE` and a memory cap, BLFPAY01 a Lean length check (re-pin). Unbuilt: payer pin before send,
  prior-digest check, integrated payer gate, durable token (the payer release path is S7a, above). Failover TLC is a bounded model.
- **Unbuilt:** financial file adapters (MCO reports, X12 820, MMIS extracts), payee-identity consumption, a second synthetic state,
  a Lean seal codec. The NC capture path is synthetic file intake.
- **Carried, not re-measured:** the staff role header is a claim the server enforces, not a login; no cancel or reduce command for stale corrections; receipt
  `delivery_status` is the newest action's, not the verdict; core size targets unmet (owner 6,756 vs ~3,000 lines, checker 4,451 vs
  ~1,800); TEST restore uses the system clock; published items cannot be re-stated (`item:duplicate`); a dead decider worker is not
  restarted (fails safe).
- **Acknowledger not stored (open, needs rr-core):** `ACTION_ACKNOWLEDGED` records no actor, so the rule that a decider may not
  acknowledge is claim-level and cannot be re-verified by the checker or Lean; fixing it needs a versioned ACK record.

Next: STATE/v2 (proofs in progress on `state-v2`), hold-release S3b+ (slot consumers), the cash-line hold ledger.
A local commit, not a qualified release; no local check activates production.
