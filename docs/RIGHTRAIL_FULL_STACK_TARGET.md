# RightRail full-stack target: the payment gate

Updated: 2026-09-25. Owner: the target architecture for the complete RightRail
government service and, within it, Blind Ledger as an inline payment gate.

`CONSTITUTION.md` is supreme; this document elaborates it and cannot weaken
it. [`ARCHITECTURE.md`](../ARCHITECTURE.md) describes how today's code fits
together; [`STATUS.md`](../STATUS.md) is the only status record. This
document holds no status and selects no state, program, deployment profile,
evidence mode, authority level, or receiver. It draws on two design notes
held with the founder outside this repository's markdown budget, cited by
name rather than copied: `gate-design.md` (the gate's transport, signing,
failover and audit design, 2026-09-25) and `fv-plan.md` (the formal-
verification plan, 2026-09-25), both reviewed by three 2026-09-25 red-team
passes (crypto/ZK, engineering, policy/market) whose corrections this
document folds in. Everything below the state of `STATUS.md` is design, not
built, run, or approved: `proofSuiteId=null`, `production_usable=false`,
`activation=false`.

## 1. The end state

Every Medicaid payment a state routes through RightRail — fee-for-service and
managed care alike — passes Blind Ledger before money goes out, at full state
scale (New York's eMedNY cycle is the sizing reference: about 12.6M claims
and $1.8B paid per weekly cycle, audited by the NY Comptroller). RightRail
still never moves money (Constitution I.4): the state's own payment system
checks the gate's decision and remains the party that holds or releases.
No legal precedent exists for a private vendor to hold the 42 CFR 455.23
suspension trigger itself, so every document and interface says "the gate
produces the determination the state's system consults," never "the gate
holds the payment."

Gating is **off by default**. A state turns on only the authority it grants,
per flow, through a state-signed `AUTHORITY-GRANT` (section 3). Nothing here
selects a state, a flow, or a go-live date.

## 2. Gate points and rollout order

The gated unit is one payment: one payee, one amount, one release, with
claim or member-month lines underneath it.

| Flow | Payment unit | Lines under it | Gate point |
| --- | --- | --- | --- |
| FFS weekly cycle (`FFS_CYCLE`) | Per-provider EFT/check | Claim lines | Cycle close, about 5 days before issue |
| FFS per-claim (`FFS_CLAIM`) | Adjudicated claim | Itself | At adjudication |
| Capitation release (`CAP_820`) | Per-plan capitation payment | Member-month lines | Monthly release |
| Directed payment (`SDP`) | Disbursement | Provider lines | Preprint schedule |
| Plan-to-provider (`PLAN_PAY`) | Plan payment to a provider | Claim lines | Needs a contract clause; no precedent today |

Rollout order: **FFS weekly cycle first, then FFS per-claim; managed care
capitation release first, then directed payments, then plan-to-provider.**
Pharmacy stays retrospective through PBMs and is never gated inline. This
order follows feasibility and existing measurement, not fraud exposure: GAO
found CMS does not measure plan-to-provider payments at all (GAO-25-107770),
so gating capitation before plan-to-provider risks moving fraud into the one
channel nobody watches. Pairing early capitation gating with a plan-to-
provider sampling commitment is a named mitigation, not yet designed.

## 3. Authority ladder

A state-signed `AUTHORITY-GRANT` sets one of three levels per flow. Levels
move up only by a new grant, never automatically:

1. **OBSERVE.** The gate checks nothing; RightRail assembles evidence and
   prepares a decision package for a human. This is the intended first
   posture for any new flow.
2. **HOLD.** Narrow automation: the gate may return a non-ALLOW outcome only
   for the rules the grant names; any other finding stays advisory, carried
   as an ALLOW reason. Everything else the gate finds is a lead, not a hold.
3. **TRANSFER.** The full control set applies and every in-scope payment
   needs a token (section 5).

The grant also carries the flow's fail policy (section 6). Progression is
never automatic and passing a comparison or proof gate does not itself grant
the next level.

## 4. Decide, token, and the payer's checks

One schema runs over synchronous HTTPS (hybrid ML-KEM TLS, mutual auth) and
batch SFTP for cycle and 820 runs. A decide call takes 1 to 1,000 items and
answers each independently, keyed by the payer's idempotency key
(`command_key`), so an exact retry returns `DUPLICATE` and never decides
twice. The response status is `DECIDED`, `DUPLICATE`, `REJECTED` (malformed
input or a reused key with different bytes), or `UNAVAILABLE` (with a retry
time; a full batch commits atomically or not at all). `outcome` is ALLOW,
HOLD, HUMAN_REVIEW, or BLOCK — the engine's existing `CLEAR`/non-`CLEAR`
distinction, unchanged.

Before releasing money, the payer runs nine ordered checks against the
token: canonical parse and domain, epoch certificate chain and signature,
checkpoint signature and Merkle path, epoch at or above the payer's fence,
not expired, payment fields match exactly, outcome is ALLOW, `rule_version`
and `engine_release` are on the payer's approved list, and the payment has
not already been released. These nine checks are one Lean predicate
(`verifyToken`), proved to accept only when all nine hold, and published to
payers as a reference verifier with conformance vectors. A release with no
token and no bypass is a payer-side violation visible in Mirror.

## 5. Batch signing, checkpoints, and inclusion tokens

**Batching is a hard invariant, not a tuning option.** One SQLite commit and
one ML-DSA-87 checkpoint signature cover an entire batch (up to 1,000 items,
closing at a 150 ms window). A per-payment token is a Merkle-inclusion path
of a few hundred bytes against that checkpoint's `token_root`, not a
separately signed token.

This corrects an earlier design that signed every token individually. At New
York's volume, signing 12.6M tokens a week individually costs roughly
45–90 TB over 7 years of retention and exhausts a shared HSM/KMS signing
quota (a documented AWS KMS default is 1,000 requests/second per account,
shared with every other use of that account's keys) — the crypto and
engineering red-teams independently reached the same correction. Batch
signing turns that into on the order of hundreds to a few thousand HSM
signatures a week, with per-payment cost reduced to a Merkle path and a hash
comparison.

Every batch commit produces a checkpoint (tenant, program, sequence range,
epoch, previous-checkpoint digest, event-chain head, token/evidence/
projection roots, count, time), signed with the epoch's ML-DSA-87 key.
Checkpoints stream to an independent witness — a separate state agency or
auditor, outside the database administrator's control — which cosigns only
after checking sequence monotonicity, epoch monotonicity, and that no two
checkpoints share a sequence with different digests; a mismatch raises a
fork alarm. The witness is asynchronous; payers never wait for it. History
is sealed into segments (per day or per 1,000,000 events, whichever comes
first) bound to the checkpoint that closes them, replacing the current
10,000-row Continuity package cap. Records are retained 7 years (Pub 1075
AU-11) in WORM storage, onshore, in the state tenant. A daily anchor
checkpoint carries an additional LMS/XMSS signature so a 7-year-old record
stays verifiable under hash-based assumptions alone.

## 6. Hold, release, fail policy, and bypass

**States.** `PENDING -> ALLOWED | HELD | REVIEW | BLOCKED`, and
`HELD | REVIEW | BLOCKED -> RELEASED | DENIED` only by a determination: a new
decision revision with a new token. Holds are monotone — adding only adverse
facts never moves a decision toward ALLOW. Only named state officials,
authenticated through the state IdP with phishing-resistant MFA, may release
or deny: one releaser distinct from the raiser for HOLD/REVIEW, a releaser
plus a program-integrity supervisor (both distinct from the raiser) for
BLOCK. **RightRail staff hold no release or deny role in any tenant.** SLA
timers follow the flow's clock — the 42 CFR 447.45 prompt-pay budget for
non-fraud FFS holds, the 42 CFR 455.23 5-day suspension clock for fraud
reasons, before-the-next-820 for capitation, contract terms for plan-to-
provider — and Mirror is the exception queue holding every non-ALLOW item.

**Fail policy.** Each flow's grant sets `FAIL_CLOSED` (the default for the
weekly cycle, capitation, and directed payments — a payer holds the
payments, and the weekly cycle has about 5 days of slack before issue) or
`FAIL_OPEN` (allowed only where a state explicitly chooses it, for
real-time flows, as a standing pre-signed bypass that activates only while
the gate is down — the analogue of NCPDP Reject 92 with a 420-DK=13
override). There is no other fallback: Constitution III.5 makes fail-closed
the universal default, and a stand-in-processing outage can still produce a
hard 0%-approval outcome in practice even when the fallback path is designed
to degrade gracefully (Visa STIP's documented February 2019 outage is the
cited precedent) — an inline block on a $1.8B weekly cycle is a provider
cash-flow crisis, not an abstract SLA miss.

**Emergency bypass.** Two distinct state officials — the payment authority
and a program-integrity or CIO official — sign a `BYPASS-GRANT` with keys
held in the state's own HSM; RightRail cannot issue, extend, or countersign
one. The grant names its tenant, program, flows, amount ceiling, payee
exclusions, reason, and expiry, capped at 72 hours and enforced by the
payer's own check; the payer stops bypassing when the ceiling is reached.
Every bypassed payment is logged as its own release record and, once the
gate recovers, re-decided post hoc against the rule version in force at
release time: ALLOW closes it, anything else opens a recoupment case in
Mirror, and every bypassed payment is reconciled within 5 business days with
a signed summary to the state.

Fail-closed is proved today as an unconditional invariant (`outcome ≠
Accepted → delta = ∅`, fv-plan's T1). A time-boxed, bounded, logged Bypass
outcome needs its own theorem — that a bypass cannot outlive its
authorization and cannot be exercised silently — so that T1 becomes
conditional on the absence of an active bypass grant rather than being
weakened. This theorem and the bypass path are designed, not built.

## 7. Primary, fenced standby, and the operational runbook

The 99.8%-monthly availability target (about 87.6 minutes of allowed
downtime a month, matching a real state Medicaid MCO SLA exhibit) is met by
one primary and one synchronous standby — no consensus cluster. A fencer in
the state tenant is the sole writer of the epoch, using an HSM monotonic
counter plus a short primary lease; safety never depends on clocks, only on
when to promote. A stale primary cannot forge a valid token for three
independent reasons: it cannot commit (no standby of its own epoch will
acknowledge it), it cannot sign (its epoch key is disabled in the HSM), and
payers refuse it (a payer that has seen the higher epoch rejects the old
one). A TLA+ model (`gate_failover.tla`) checks these properties —
`NoConflictingTokens`, `NoFencedTokenAccepted`, `AtMostOnceRelease`,
`NoLostDecision`, `StaleCannotSign`, `EpochMonotone`,
`BypassEventuallyReconciled` — as bounded state-space search, not proof;
finding a counterexample interleaving is worth more here than a proof that
covers only the model. The bounds have not yet been run.

This architecture makes 99.8% achievable; it does not make it automatic. The
engineering red-team's finding stands: the trunk today has no CI, no on-call
rotation, and no tested failover drill, and fencing systems fail in practice
when a watchdog is disabled during maintenance or the failover path itself
is degraded. **A tested failover drill and an operational runbook (source
outage, database outage, key loss, corrupted package, partial release,
receiver timeout, operator exit) are acceptance prerequisites for claiming
99.8%, not a property that falls out of the primary/standby architecture by
itself.**

## 8. Sharding by member key

Data shards by person/member key, never by program or plan. Sharding by
program or plan would blind the one cross-boundary check the gate exists to
do — catching the same person double-billed across FFS and managed care, or
across two plans — by scattering one member's payments across shards with
only an asynchronous, staleness-bounded reconciliation pass to catch them.
Sharding by member key keeps cross-program and cross-plan duplicate
detection inside one shard instead. No Postgres migration and no
multi-region work happen before a measured SQLite ceiling shows the need; a
warm-worker throughput benchmark (branch `load-test`) is the first thing to
measure, not the last (Constitution IX.3).

## 9. The proof boundary: prove the interpreter, version the rule data

Formal verification goes where a defect can release, withhold, or misstate
money, or forge or replay authority — concentrated in four places: the
decision function, the bytes into and out of it, the replay checker, and the
signed token. Those are Lean, with proofs; interleavings (crash, failover,
fencing) get TLA+ model checking instead; everything else gets tests.

**Core invariants are proved once, over the interpreter, never over one
rule's content.** `step`/`batch` (a pure `ReadSet -> Command -> Outcome`
function) carries eleven universal theorems: fail-closed, revision
discipline, idempotence and retry identity, conservation of amounts, a
single completion-time definition proved permutation-invariant, no double
release, monotone holds, authority against a versioned roster, bounded
arithmetic, evidence-mode fixity (a missing or wrong evidence mode rejects
rather than silently downgrading), and non-dispatch. **Fee schedules, NCCI
edit pairs, and per-state coverage tables ship as versioned, hash-pinned,
test-vectored data, with no theorem review per update.** This split is the
answer to a real risk the engineering red-team named: Medicaid rule content
changes on independent cadences (NCCI quarterly, fee schedules ad hoc, SPAs
continuously), and gating every content change behind a founder-reviewed
theorem change would make ordinary rule maintenance too slow to be usable.
`CAP-REL`, the capitation-release relation, is written as data-shaped Lean
evaluated by the interpreter (section 10), not baked into a bespoke theorem,
so it stays on the interpreter's proof, not a new one.

Today, of 14 command types, Lean decides exactly one —
`reject_offset_and_authorize_correction` — and the live command codec
(`BLFCMD01`/`BLFCRES1`) carries zero codec laws, while a comparison-only
codec that nothing decides with has full ones; the pinned decision binary
was built from source that can no longer be recovered. Closing that gap —
proof hygiene, a reproducible rebuild, codec parity, then the live
evaluator, then the remaining thirteen commands, then the signed token and
checkpoint predicates, then a Lean checker — is `fv-plan.md`'s ordered
roadmap; its first four steps remove most of the risk in the fewest weeks.

## 10. Evidence modes: the non-ZK path ships first

- **`DIRECT_STATE_OWNED`** uses canonical facts lawfully held in the state
  boundary directly; a fact does not need a cryptographic wrapper merely
  because it is sensitive.
- **`AUTHORITATIVE_ASSERTION`** uses a narrowly scoped, signed assertion from
  a qualified source; signature acceptance proves provenance, not truth,
  population completeness, or state disposition.
- **`PRIVATE_ZK`** stays parked and conditional (Constitution IX.4): it
  verifies a source-bound hidden predicate without disclosing its inputs.

**The non-ZK evidence path ships first, as the whole answer for most
auditors:** signed batch checkpoints, the independent witness cosign chain,
Merkle inclusion proofs for selective disclosure, and a reproducible Lean
checker an auditor reruns in the state's own tenant. GAGAS auditors already
work this way with IT-generated evidence, and no CMS, OIG, GAO, or state
auditor guidance accepts ZK proofs as audit evidence as of this writing —
the policy red-team found no precedent anywhere. This path alone gets an
estimated 90% of the value a full ZK design would add.

`PRIVATE_ZK` is a **parallel add-on**, not a prerequisite, scoped narrowly:
the crypto red-team's correction is that ZK's marginal value is not
"anyone can verify," since the state and the entity signing the roots ZK
proves against are the same side. Its real value is the cross-organizational
case with an unmotivated verifier — for example, proving to an MCO or a
federal partner that no member in a release is on a death-match file,
without disclosing the eligibility list. The cheap, useful step now is
writing `CAP-REL-v1` (the capitation-release relation) as a plain Lean
predicate evaluated directly — useful today as `DIRECT_STATE_OWNED`
evidence — so that if a state, CMS, or OIG later asks for a hidden-input
proof, the circuit has an exact specification to be proved against rather
than a new one invented at that point. Circuit and verifier proofs stay
research-grade work (a corrected 20–35 engineer-weeks for the circuit,
40–80 for a verified verifier) and are not scheduled.

If `PRIVATE_ZK` is ever selected, its parameters come from one canonical
source, `zk-spike/params.md`'s P128-R set (128-bit classical soundness,
about 64-bit under a quantum random oracle, 100-bit under the
conjecture-free unique-decoding bound), superseding two earlier,
inconsistent parameter drafts. Salt sizing, custody, and the choice between
7-year retained salts and scheduled destruction are open (section 12).

## 11. Post-quantum cryptography

- **ML-DSA-87**, through AWS-LC in a FIPS 140-3 HSM in the state tenant,
  signs batch and checkpoint bytes — one signature per batch, not per
  payment (section 5).
- **Long-lived root and anchor keys use LMS/XMSS** (SP 800-208), not
  SLH-DSA: no FIPS-140-3-validated cloud HSM offers SLH-DSA today, while
  LMS/XMSS is HSM-backed now (for example, Thales Luna T7, FIPS 140-3 Level
  3 certificate #5450, announced 2026-07-29, covering ML-DSA, ML-KEM, and
  LMS). SLH-DSA stays available as an optional software-verified second
  signature, never the only one on a root key. LMS/XMSS keys are stateful
  and need the SP 800-208 no-backup-restore operational discipline.
- **SHA3-512, domain-separated, through AWS-LC** — not the hand-written Lean
  implementation, which is not constant-time and not reviewed like a crypto
  library.
- **Hybrid ML-KEM TLS (X25519MLKEM768)** protects the gate-to-payer and
  gate-to-standby channels. Confirmed available on AWS GovCloud
  load-balancer policies as of late 2025; Azure Government's support is
  unconfirmed as of this writing, so the design terminates TLS on the
  gate's own backend (AWS-LC or OpenSSL 3.5+) behind an ordinary L4 load
  balancer where a PQ-capable managed front end is not available.

We verify none of these primitives ourselves; we consume AWS-LC's
machine-checked proofs (HOL Light and CBMC, for ML-KEM and, as it lands,
ML-DSA), run ACVP/KAT vectors in CI against the exact library build, and
prove only the binding — that signed bytes name exactly one decision. ML-DSA
integration into AWS-LC's FIPS-validated path was still landing as of the
most recent research pass; a non-PQ fallback signature for token and
checkpoint signing until that validation completes is open (section 12).

## 12. What exists today vs. the target

Labelled honestly, per Constitution VI and XI.11. See `STATUS.md` for the
current source of truth on anything marked measured.

- **Measured.** The Lean-controlled correction transition (9 of 9 focused
  tests passed) — but the pinned binary it runs was built from Lean source
  that can no longer be recovered, so no proof today covers the binary that
  actually runs. Continuity admission and correction follow-up through
  Mirror. The felt-value scorecard and the Article XIII interaction-model
  crawl.
- **Designed, not built.** The gate API (decide/decide-batch), the token and
  checkpoint formats, the independent witness, batch signing, segmented
  Continuity, member-key sharding, the fenced primary/standby protocol, the
  Bypass outcome and its theorem, and all thirteen remaining command ports
  into Lean. `gate-design.md` states this explicitly: nothing in it is
  built, run, or approved.
- **Not yet run.** The single most important missing measurement, named by
  both `fv-plan.md` and the engineering red-team: a warm-worker Lean
  evaluator benchmark against a batch of synthetic decisions, with no
  process spawn. Every throughput number in this document (the batch
  window, the worker pool sizing, the "about 0.66 s" per-batch latency
  budget) is a target, not a measurement, until that benchmark exists. The
  TLA+ failover model is written but not checked. The `PRIVATE_ZK` spike's
  corrected speed estimate (about 150–350 ms p50, up to about 500 ms p95,
  per 2^11–2^12-line segment, roughly 3x the original estimate) is itself
  unmeasured and carries an explicit ±2–3x uncertainty band until a spike
  runs it.

## 13. Path

The ordered path removes the most risk per week first (`fv-plan.md`'s
roadmap, steps 1–4 first): proof hygiene on the existing theorem manifest
and a reproducible rebuild of the pinned binary from current source; codec
laws for the live command path; the existing `evaluate` proof made the live
evaluator; the remaining thirteen command types ported in order of money
impact. In parallel: the warm-worker throughput benchmark and the owner
throughput harness (branch `load-test`), which must exist before any claim
about batch sizing or worker-pool count is more than a guess. Signed token,
checkpoint, and segment formats, the Lean checker, and the TLA+ failover
model follow, each gated on founder approval where it touches a protected
format (Constitution V.4). `CAP-REL` as a plain Lean rule and the X12/NCPDP
tokenizer are scheduled with the adapter build, not ahead of it. `PRIVATE_ZK`
work stays parked (Constitution IX.4) until a state, CMS, or OIG asks for a
hidden-input proof.

## 14. PENDING FOUNDER DECISION

None of the following is decided. Each needs an explicit founder call before
it is built, under Constitution V.4 (protected formats) or IX.4 (parked
work):

1. **The 13 new gate wire and storage formats** named in `gate-design.md`
   (decide-request/response, token, checkpoint, key-cert, authority-grant,
   bypass-grant, release-record, witness-cosig, segment, the Lean worker
   batch frame, three digest domains, and the CAP-REL evidence entry) —
   named only; none is built.
2. **Un-parking `PRIVATE_ZK` under Constitution IX.4**, and where its work
   lives (a separate proof/Lake workspace, never the product library with
   its zero external dependencies).
3. **A non-PQ fallback signature** for tokens and checkpoints, to use until
   a FIPS-140-3-validated ML-DSA implementation is confirmed available in a
   consumable library.
4. **The default fail policy**, and which flows may offer `FAIL_OPEN` at
   all — a real addition to Constitution III.5's unconditional fail-closed
   invariant, not a tuning knob, per the engineering red-team.
5. **Salt custody for any future `PRIVATE_ZK` use**: a 7-year HSM-wrapped
   salt vault (which itself becomes a PHI-equivalent asset) versus scheduled
   destruction (which drops the 7-year selective-disclosure promise). Not
   both.
6. **Segmented Continuity as a new store/package version** (day- or
   million-event-sealed segments bound to checkpoints, replacing the
   current 10,000-row cap) — a protected format change.
7. **Dropping v7 store-version compatibility, the `OPENING_BALANCE`
   migration path, and `tools/continuity_successor_v7.py`**, and starting
   the gate's store fresh from genesis instead, per the recommendation that
   this carries real cost (about 2,800 lines) for a migration path no real
   v7 store will ever use, since all current data is synthetic.

## 15. Beyond the gate

The gate sits inside the same five-part product described in
`ARCHITECTURE.md`: the state-approved Control Pack, the Blind Ledger owner
as the one financial writer, the Mirror staff workspace as the exception
queue and audit surface, Continuity as the state's exit path, and Switch as
the pre-cutover shadow comparator. None of those roles changes: the owner
still commits atomically with integer cents and explicit retry identity: a
UI, connector, verifier, or shadow copy never becomes a second writer.
Connectors stay allow-listed, bounded, and read-only by default; the
official receiver and payment system keep money-movement authority; Provider
App remains a separate provider-side product that does not gate on the
government service. Cross-state reuse stays limited to versioned,
non-sensitive interface schemas and conformance vectors — no state's
population, rates, or findings cross to another state.

Commercial terms are unchanged from the founder's direction: about $2M/year
operations plus the marginal 10/7/5-basis-point covered-flow schedule with a
5-basis-point floor, Provider App priced separately, and no share of
denials, recoveries, penalties, sanctions, or savings (Constitution VIII).
Nothing here selects a procurement route, funding classification, or go-live
date.

## Related documents

- [Constitution](../CONSTITUTION.md)
- [Status](../STATUS.md)
- [How the code fits together](../ARCHITECTURE.md)
- [Design ideology](DESIGN_IDEOLOGY.md)
- [Provider App](../provider_app/README.md)
- [Parked private-proof track](../parked/README.md)
