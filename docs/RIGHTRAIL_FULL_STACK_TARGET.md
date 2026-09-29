# RightRail full-stack target

Updated: 2026-09-26. Owner: the target architecture for the complete RightRail
government service and, within it, Blind Ledger as an inline payment gate.

`CONSTITUTION.md` is supreme; this document elaborates it and cannot weaken
it. [`ARCHITECTURE.md`](../ARCHITECTURE.md) describes today's code;
[`STATUS.md`](../STATUS.md) is the only status record. This document holds no
status and selects no state, program, deployment profile, evidence mode,
authority level, or receiver. It draws on design notes held outside the repo,
cited by name: `next-phase.md` (build order after the core rebuild),
`gate-design.md` (gate transport/signing/failover/audit, 2026-09-25) and
`fv-plan.md` (formal-verification plan, 2026-09-25), the last two reviewed by
three 2026-09-25 red-team passes (crypto/ZK, engineering, policy/market) whose
corrections it folds in. Everything below the state of `STATUS.md` is design,
not built, run, or approved: `proofSuiteId=null`, `production_usable=false`,
`activation=false`.

## 1. The end state

The gate below is one authority level within the product `ARCHITECTURE.md`
describes, not the whole product; the core financial cycle, provider evidence,
independent exit and reuse remain useful without an inline payment gate.

Every Medicaid payment a state routes through RightRail — FFS and managed
care alike — passes Blind Ledger before money goes out, at full state scale
(New York's eMedNY cycle is the sizing reference: ~12.6M claims and $1.8B
paid per weekly cycle, audited by the NY Comptroller). RightRail still never
moves money (Constitution I.4): the state's own payment system checks the
gate's decision and remains the party that holds or releases. No legal
precedent exists for a private vendor to hold the 42 CFR 455.23 suspension
trigger itself, so every document/interface says "the gate produces the
determination the state's system consults," never "the gate holds the
payment."

Gating is **off by default**. A state turns on only the authority it grants,
per flow, through a state-signed `AUTHORITY-GRANT` (§3). Nothing here
selects a state, a flow, or a go-live date.

## 2. Gate points and rollout order

The gated unit is one payment: one payee, one amount, one release, with
claim or member-month lines underneath it.

| Flow | Payment unit | Lines under it | Gate point |
| --- | --- | --- | --- |
| FFS weekly cycle (`FFS_CYCLE`) | Per-provider EFT/check | Claim lines | Cycle close, ~5 days before issue |
| FFS per-claim (`FFS_CLAIM`) | Adjudicated claim | Itself | At adjudication |
| Capitation release (`CAP_820`) | Per-plan capitation payment | Member-month lines | Monthly release |
| Directed payment (`SDP`) | Disbursement | Provider lines | Preprint schedule |
| Plan-to-provider (`PLAN_PAY`) | Plan payment to a provider | Claim lines | Needs a contract clause; no precedent today |

Rollout order: **FFS weekly cycle first, then FFS per-claim; managed care
capitation release first, then directed payments, then plan-to-provider.**
Pharmacy stays retrospective through PBMs, never gated inline. This order
follows feasibility and existing measurement, not fraud exposure: GAO found CMS
does not measure plan-to-provider payments (GAO-25-107770), so gating capitation
first risks moving fraud into the one channel nobody watches. Pairing early capitation gating with a plan-to-
provider sampling commitment is a named mitigation, not yet designed.

## 3. Authority ladder

A state-signed `AUTHORITY-GRANT` sets one of three levels per flow. Levels
move up only by a new grant, never automatically:

1. **OBSERVE.** Gate checks nothing; RightRail assembles evidence and
 prepares a decision package for a human. Intended first posture for any
 new flow.
2. **HOLD.** Narrow automation: the gate may return a non-ALLOW outcome only
 for rules the grant names; any other finding stays advisory, carried as
 an ALLOW reason. Everything else the gate finds is a lead, not a hold.
3. **TRANSFER.** Full control set applies; every in-scope payment needs a
 token (§5).

The grant also carries the flow's fail policy (§6). Progression is never
automatic; passing a comparison or proof gate does not itself grant the next
level.

## 4. Decide, token, and the payer's checks

One schema runs over synchronous HTTPS (hybrid ML-KEM TLS, mutual auth) and
batch SFTP for cycle and 820 runs. A decide call takes 1 to 1,000 items and
answers each independently, keyed by the payer's idempotency key
(`command_key`), so an exact retry returns `DUPLICATE` and never decides
twice. Response status: `DECIDED`, `DUPLICATE`, `REJECTED` (malformed input
or a reused key with different bytes), or `UNAVAILABLE` (with a retry time;
a full batch commits atomically or not at all). `outcome` is ALLOW, HOLD,
HUMAN_REVIEW or BLOCK — the engine's existing `CLEAR`/non-`CLEAR`
distinction, unchanged. A ruled flow's request (FFS_CYCLE, FFS_CLAIM,
CAP_820) carries at least one line, each repeating its flow, member key and
payee, together summing to its amount, so `lines_root` commits to exactly the
lines the rules decided; SDP and PLAN_PAY have no rules: HUMAN_REVIEW. An
already-decided answer of another ruled flow fails closed (lines carry their
flow).

Before releasing money, the payer runs twelve checks against the token:
canonical parse and domain; a stored checkpoint verified under its epoch
certificate; that checkpoint's Merkle path; epoch at or above the payer's
fence; not expired, and decided within the run it was decided for plus one
missed (fixed across reissues: FFS_CLAIM 14 days, as checkwrites run weekly or
biweekly; FFS_CYCLE 28; CAP_820 62, monthly); payment fields match exactly; the token comes from the
shard the member key routes to; outcome is ALLOW; `rule_version` and
`engine_release` are on the payer's approved list; the payment has not
already been released; no fork or equivocation is recorded for the tenant and epoch; and
the payer sent a command for the payment and the member key is the one its
first command pinned (a changed key is refused as `member_key_changed` until
an official determination, not in v1). Unbuilt precondition of any payer
adapter (none exists): the pin is durably persisted before the first command
leaves the payer, and every command path (retry, new command key, another
flow) checks the same pin store; required test: a kill between pin-persist
and send leaves a pin and no command, never the reverse. These twelve checks are one Lean predicate
(`verifyToken`), proved to accept only when all twelve hold, and published to
payers as a reference verifier with conformance vectors. A release with no
token and no bypass is a payer-side violation visible in Mirror.

## 5. Batch signing, checkpoints, and inclusion tokens

**Batching is a hard invariant, not a tuning option.** One SQLite commit and
one ML-DSA-87 checkpoint signature cover an entire batch (up to 1,000 items,
closing at a 150 ms window). A per-payment token is a Merkle-inclusion path
of a few hundred bytes against that checkpoint's `token_root`, not a
separately signed token.

Signing every token individually would cost ~45–90 TB over 7 years of
retention at New York's volume (12.6M tokens a week) and exhaust a shared
HSM/KMS signing quota (a documented AWS KMS default is 1,000 requests/second
per account). Batch signing needs hundreds to a few thousand HSM signatures a
week; per-payment cost is a Merkle path and a hash comparison.

Every batch commit produces a checkpoint (tenant, program, shard, sequence
range, epoch, previous-checkpoint digest, event-chain head, token/evidence/
projection roots, a never-zero state digest over the rules' released and
unresolved pins, count, time), signed with the epoch's ML-DSA-87 key. Pins
hash sorted fixed-width big-endian rows after a count. The rules extend the
sets of the payment's shard's latest signed checkpoint; unbuilt: the runtime
verifier that the priors hash to its `state_digest`.
There is one sequence counter per (tenant, shard, epoch), shared by all of
the tenant's programs and starting at 0 in each epoch: no two checkpoints in
that scope share a sequence, whatever their program, each names the
checkpoint ending just before it as its previous, and an epoch's first
checkpoint has an all-zero previous digest; a previous link to a
non-adjacent checkpoint is a fork. Unbuilt preconditions (the codec's
`sign_batch` is stateless; no producer or KEY-CERT exists): the producer
serializes checkpoints per (tenant, shard), persists each before publishing
it, and checks it against its own stored checkpoints for a fork before
publishing, with the required test that a crash between sign and persist
never publishes the unpersisted checkpoint nor reuses its sequence with
other bytes; the KEY-CERT that carries an epoch key signs every field, the
tenant's shard count included, and a payer accepts one certificate per
(tenant, epoch); a second, different one is recorded as equivocation and
blocks it.

Every `RR/GATE` hash or signature input starts with its name, `/v1` and a
NUL byte:

| Name | Covers |
|---|---|
| DECIDE-REQUEST, DECIDE-RESPONSE, TOKEN, CHECKPOINT | the signed or parsed wire formats |
| DECISION-ID, INPUT, SHARD | decision identity, decided-input digest, shard routing |
| MERKLE-NODE, LINES-NODE | token and claim-line Merkle trees |
| STATE; SNAPSHOT, RELEASED, UNRESOLVED | checkpoint state digest; the rules' read-set pins |
| SEGMENT | financial history segments |
| KEY-CERT | epoch key certificate (planned) |
| TEST-ONLY-SEED, TEST-ONLY-MEMBER | synthetic test keys, never product |

Checkpoints stream to an independent witness — a separate
state agency or auditor, outside the database administrator's control —
which cosigns only after checking sequence monotonicity, epoch monotonicity,
and that no two checkpoints of one (tenant, shard, epoch) share a sequence
with different digests or break that link; a mismatch raises a fork alarm,
and payers holding one refuse the whole (tenant, epoch). The witness is asynchronous; payers never wait for it. History
is sealed into segments (per day or per 1,000,000 events, whichever comes
first) bound to the checkpoint that closes them, replacing the current
10,000-row Continuity package cap. Records are retained 7 years (Pub 1075
AU-11) in WORM storage, onshore, in the state tenant. A daily anchor
checkpoint carries an additional LMS/XMSS signature so a 7-year-old record
stays verifiable under hash-based assumptions alone.

## 6. Hold, release, fail policy, and bypass

**States.** `PENDING -> ALLOWED | HELD | REVIEW | BLOCKED`, and
`HELD | REVIEW | BLOCKED -> RELEASED | DENIED` only by a determination: a new
decision revision with a new token. An unreleased ALLOW past its age (§4) is
re-decided on current data as the next revision, excluding its own released
lines: a line is released at most once. Holds are monotone — adding only adverse
facts never moves a decision toward ALLOW. Only named state officials,
authenticated through the state IdP with phishing-resistant MFA, may release
or deny: one releaser distinct from the raiser for HOLD/REVIEW, a releaser
plus a program-integrity supervisor (both distinct from the raiser) for
BLOCK. **RightRail staff hold no release or deny role in any tenant.** SLA
timers follow the flow's clock — the 42 CFR 447.45 prompt-pay budget for
non-fraud FFS holds, the 42 CFR 455.23 5-day suspension clock for fraud
reasons, before-the-next-820 for capitation, contract terms for
plan-to-provider — and Mirror is the exception queue holding every
non-ALLOW item.

**Fail policy.** Each flow's grant sets `FAIL_CLOSED` (default for the
weekly cycle, capitation and directed payments — a payer holds the
payments, and the weekly cycle has ~5 days of slack before issue) or
`FAIL_OPEN` (allowed only where a state explicitly chooses it, for real-time
flows, as a standing pre-signed bypass that activates only while the gate
is down — the analogue of NCPDP Reject 92 with a 420-DK=13 override). There
is no other fallback: Constitution III.5 makes fail-closed the universal
default, and an inline block on a $1.8B weekly cycle is a provider cash-flow
crisis, not an abstract SLA miss (Visa STIP's February 2019 outage shows a
degrade-gracefully fallback can still end at 0% approval).

**Emergency bypass.** Two distinct state officials — the payment authority
and a program-integrity or CIO official — sign a `BYPASS-GRANT` with keys
held in the state's own HSM; RightRail cannot issue, extend or countersign
one. The grant names its tenant, program, flows, amount ceiling, payee
exclusions, reason and expiry, capped at 72 hours and enforced by the
payer's own check; the payer stops bypassing when the ceiling is reached.
Every bypassed payment is logged as its own release record and, once the
gate recovers, re-decided post hoc against the rule version in force at
release time: ALLOW closes it, anything else opens a recoupment case in
Mirror, and every bypassed payment is reconciled within 5 business days with
a signed summary to the state.

Fail-closed is proved today as an unconditional invariant (`outcome ≠
Accepted → delta = ∅`, fv-plan's T1). A time-boxed, bounded, logged Bypass
outcome needs its own theorem — that a bypass cannot outlive its
authorization and cannot be exercised silently — so T1 becomes conditional
on the absence of an active bypass grant rather than being weakened. This
theorem and the bypass path are designed, not built.

## 7. Primary, fenced standby, and the operational runbook

The 99.8%-monthly availability target (~87.6 minutes of allowed downtime a
month, matching a real state Medicaid MCO SLA exhibit) is met by one primary
and one synchronous standby — no consensus cluster. A fencer in the state
tenant is the sole writer of the epoch, using an HSM monotonic counter plus
a short primary lease; safety never depends on clocks, only on when to
promote. A stale primary cannot forge a valid token for three independent
reasons: it cannot commit (no standby of its own epoch will acknowledge
it), it cannot sign (its epoch key is disabled in the HSM), and payers
refuse it (a payer that has seen the higher epoch rejects the old one). A
TLA+ model (`gate_failover.tla`) checks these properties —
`NoConflictingTokens`, `NoFencedTokenAccepted`, `AtMostOnceRelease`,
`NoLostDecision`, `StaleCannotSign`, `EpochMonotone`,
`BypassEventuallyReconciled` — as bounded state-space search, not proof;
finding a counterexample interleaving is worth more here than a proof that
covers only the model. Checked bounds and remaining larger runs belong in
`STATUS.md` and `docs/formal/gate_failover/README.md`.

This architecture makes 99.8% achievable, not automatic: the trunk has no CI,
no on-call rotation and no tested failover drill, and fencing systems fail in
practice when a watchdog is disabled or the failover path is degraded. **A tested failover drill and an operational runbook (source
outage, database outage, key loss, corrupted package, partial release,
receiver timeout, operator exit) are acceptance prerequisites for claiming
99.8%, not a property that falls out of the primary/standby architecture by
itself.**

## 8. Sharding by member key

Data shards by person/member key, never by program or plan, which would scatter
one member's payments and leave the gate's core cross-boundary check (the same
person double-billed across FFS and managed care, or two plans) to an
asynchronous, staleness-bounded reconciliation pass. Member-key sharding keeps
that detection inside one shard. No Postgres migration and no
multi-region work happen before a measured SQLite ceiling shows the need; a
warm-worker throughput benchmark is the first thing to
measure, not the last (Constitution IX.3).

## 9. The proof boundary: prove the interpreter, version the rule data

Formal verification goes where a defect can release, withhold or misstate
money, or forge or replay authority — concentrated in four places: the
decision function, the bytes into and out of it, the replay checker and the
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
edit pairs and per-state coverage tables ship as versioned, hash-pinned,
test-vectored data, with no theorem review per update**: Medicaid rule content
changes on independent cadences (NCCI quarterly, fee schedules ad hoc, SPAs
continuously), so a theorem change per content change would make ordinary
maintenance unusable (an engineering red-team finding).
`CAP-REL`, the capitation-release relation, is written as data-shaped Lean
evaluated by the interpreter (§10), not baked into a bespoke theorem, so it
stays on the interpreter's proof, not a new one.

Today Lean decides one of 14 command types (`ARCHITECTURE.md`); §13 orders
the rest.

## 10. Evidence modes: the non-ZK path ships first

- **`DIRECT_STATE_OWNED`** uses canonical facts lawfully held in the state
 boundary directly; a fact does not need a cryptographic wrapper merely
 because it is sensitive.
- **`AUTHORITATIVE_ASSERTION`** uses a narrowly scoped, signed assertion from
 a qualified source; signature acceptance proves provenance, not truth,
 population completeness, or state disposition.
- **`PRIVATE_ZK`** is an active, evidence-only prototype (Constitution IX.4):
 it verifies a source-bound hidden predicate without disclosing its inputs.
 It never creates hold or payment authority and never blocks the core or gate.

**The non-ZK evidence path ships first, as the whole answer for most
auditors:** signed batch checkpoints, the independent witness cosign chain,
Merkle inclusion proofs for selective disclosure, and a reproducible Lean
checker an auditor reruns in the state's own tenant. GAGAS auditors already
work this way with IT-generated evidence, and no CMS, OIG, GAO or state
auditor guidance accepts ZK proofs as audit evidence (the policy red-team found
no precedent). This path alone gets an estimated 90% of a full ZK design's value.

`PRIVATE_ZK` is a **parallel add-on**, not a prerequisite, scoped narrowly:
ZK's marginal value is not "anyone can verify," since the state and the
entity signing the roots ZK proves against are the same side (crypto red-team).
Its real value is the cross-organizational case with an unmotivated verifier,
e.g. proving to an MCO or a federal partner that no member in a release is on a
death-match file without disclosing the eligibility list. The cheap step now is writing `CAP-REL-v1`
(the capitation-release relation) as a plain Lean predicate evaluated directly
(useful today as `DIRECT_STATE_OWNED` evidence), so a later hidden-input proof
has an exact spec. Circuit and verifier proofs stay research-grade work (20–35
engineer-weeks for the circuit, 40–80 for a verified verifier) and are not
scheduled.

If `PRIVATE_ZK` is ever selected, its parameters come from one canonical
source, `zk-spike/params.md`'s P128-R set (128-bit classical soundness,
~64-bit under a quantum random oracle, 100-bit under the conjecture-free
unique-decoding bound), superseding two earlier, inconsistent parameter
drafts. Salt sizing, custody, and the choice between 7-year retained salts
and scheduled destruction are open (§12).

## 11. Post-quantum cryptography

- **ML-DSA-87**, through AWS-LC in a FIPS 140-3 HSM in the state tenant,
 signs batch and checkpoint bytes — one signature per batch, not per
 payment (§5).
- **Long-lived root and anchor keys use LMS/XMSS** (SP 800-208), not
 SLH-DSA: no FIPS-140-3-validated cloud HSM offers SLH-DSA today, while
 LMS/XMSS is HSM-backed now (e.g. Thales Luna T7, certificate #5450). SLH-DSA stays available as an optional software-verified second
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
most recent research pass. Certification availability must be checked for
the selected deployment. Constitution VI.5 forbids RSA/ECDSA fallback
signatures; certification delay does not authorize a downgrade.

## 12. Evidence and integration

A format model, compiled rules, a pinned executable and an integrated workflow
are separate claims, and one branch's results do not verify another's or their
combination. `STATUS.md` is the evidence record, `ARCHITECTURE.md` the connected
implementation, `artifacts/engine-correction/PROVENANCE.md` the engine pin.

The payer gate needs both authenticated checkpoint ancestry and admission of
signed, tenant/program-scoped, current authority grants. A checkpoint
signature alone does not establish continuity with an unseen predecessor.
An in-memory list of active grant identifiers does not establish state
authority. Persisted fences, released/unresolved identities, rules, tokens
and payer release must be connected and exercised through restart, retry
and partial failure before an end-to-end gate claim; the format model
assumes some of them (STATUS).

Batch windows, worker counts and private-proof latency estimates remain
targets until measured against the exact executed source and artifact. A
model crawl does not replace Article XIII's real-browser crawl.

## 13. Path

The ordered path removes the most risk per week first (`fv-plan.md`'s
roadmap, steps 1–4 first): proof hygiene on the existing theorem manifest
and a reproducible rebuild of the pinned binary from current source; codec
laws for the live command path; the existing `evaluate` proof made the live
evaluator; the remaining thirteen command types ported in order of money
impact. In parallel: the warm-worker throughput benchmark and the owner
throughput harness (branch `load-test`), needed before any batch-sizing or
worker-pool claim is more than a guess. `CAP-REL` as a plain Lean rule and the
X12/NCPDP tokenizer are scheduled with the adapter build, not ahead of it.
`PRIVATE_ZK` continues in its separate prototype repository under
Constitution IX.4; it produces evidence only and requires a third-party
audit before a PRIVATE_ZK claim.

## 14. Remaining design decisions

Protected format, digest and theorem changes need the record and review in
Constitution XI.2; implementations and evidence belong in `STATUS.md`.

- Complete the authority-grant, bypass, release and witness admission
 contracts, including checkpoint ancestry, scope, revocation and durable
 recovery.
- A state selects its flows, fail policy and any bounded emergency bypass
 through signed authority. Fail-closed remains the default; there is no
 implicit outage permission to release.
- Resolve salt custody for any future private-proof deployment: retained
 wrapped salts and scheduled destruction have different disclosure
 guarantees.
- Establish measured segment and worker bounds before increasing the
 current store/export limits. Existing segmented Continuity does not
 prove million-event operation.

Private ZK, post-quantum-only signatures and activation are governed by the
constitution; local build or test results grant no activation.

## 15. Beyond the gate

The gate sits inside the same five-part product (`README.md`, `ARCHITECTURE.md`)
and changes no role in it: Mirror is the exception queue and audit surface, and
the owner stays the one financial writer: a UI, connector, verifier or shadow copy never becomes a second
writer. Connectors stay allow-listed, bounded and read-only by default; the
official receiver and payment system keep money-movement authority; Provider App
remains a separate provider-side product that does not gate on the government
service. Cross-state reuse stays limited to versioned, non-sensitive interface
schemas and conformance vectors; no state's population, rates or findings cross
to another state.

Commercial terms are the founder's (Constitution VIII). Nothing here selects a
procurement route, funding classification or go-live date.

## Related documents

- [Constitution](../CONSTITUTION.md)
- [Status](../STATUS.md)
- [How the code fits together](../ARCHITECTURE.md)
- [Design ideology](DESIGN_IDEOLOGY.md)
- [Provider App](../provider_app/README.md)
- [Historical private-proof reference](../parked/README.md)
