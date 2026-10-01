# RightRail full-stack target

Updated: 2026-09-26. The target architecture for the complete RightRail
service and, within it, Blind Ledger as an inline payment gate.

`CONSTITUTION.md` is supreme; this document elaborates it and cannot weaken
it. [`ARCHITECTURE.md`](../ARCHITECTURE.md) describes today's code;
[`STATUS.md`](../STATUS.md) is the only status record. This document holds no
status and selects no state, program, deployment profile, evidence mode,
authority level, or receiver. It draws on design notes held outside the repo
(`next-phase.md`, `gate-design.md`, `fv-plan.md`; the last two reviewed by three
2026-09-25 red-team passes whose corrections it folds in). Everything here is
design, not built, run, or approved: `proofSuiteId=null`,
`production_usable=false`, `activation=false`.

## 1. The end state

The gate is one authority level within the product `ARCHITECTURE.md` describes;
the core financial cycle, provider evidence, independent exit and reuse remain
useful without it.

Every Medicaid payment a state routes through RightRail — FFS and managed
care alike — passes Blind Ledger before money goes out, at full state scale
(New York's eMedNY cycle is the sizing reference: ~9.6M claims and $1.9B
paid per weekly cycle, per the NY Comptroller audit of 2025-06-18,
https://www.osc.ny.gov/state-agencies/audits/2025/06/18/medicaid-program-claims-processing-activity-april-1-2024-through-september-30-2024).
RightRail still never
moves money (Constitution I.4): the state's own payment system checks the
gate's decision and remains the party that holds or releases. No legal
precedent exists for a private vendor to hold the 42 CFR 455.23 suspension
trigger itself, so every document/interface says "the gate produces the
determination the state's system consults," never "the gate holds the
payment."

Gating is **off by default**. A state turns on only the authority it grants,
per flow, through a state-signed `AUTHORITY-GRANT` (§3).

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
Pharmacy stays retrospective through PBMs, never gated inline. The order
follows feasibility and existing measurement, not fraud exposure: GAO found CMS
does not measure plan-to-provider payments (GAO-25-107770), so gating capitation
first risks moving fraud into that channel. A plan-to-provider sampling
commitment is a named mitigation, not yet designed.

## 3. Authority ladder

A state-signed `AUTHORITY-GRANT` sets one of three levels per flow. Levels
move up only by a new grant, never automatically:

1. **OBSERVE.** Gate checks nothing; RightRail assembles evidence and
 prepares a decision package for a human. The first posture for any
 new flow.
2. **HOLD.** Narrow automation: the gate may return a non-ALLOW outcome only
 for rules the grant names; any other finding stays advisory, carried as
 an ALLOW reason.
3. **TRANSFER.** Full control set applies; every in-scope payment needs a
 token (§5).

The grant also carries the flow's fail policy (§6). Passing a comparison or
proof gate does not itself grant the next level.

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

Signing each token would cost ~45–90 TB over 7 years at New York's volume
(12.6M tokens a week) and exhaust a shared HSM/KMS quota (AWS KMS default:
1,000 requests/second per account).

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
`sign_batch` is stateless; no producer exists): the producer
serializes checkpoints per (tenant, shard), persists each before publishing
it, and checks it against its own stored checkpoints for a fork before
publishing, with the required test that a crash between sign and persist
never publishes the unpersisted checkpoint nor reuses its sequence with
other bytes. The KEY-CERT (v1, built) signs every field, the shard count
included; a payer accepts one certificate per (tenant, epoch); a second with another
key or shard count is recorded as equivocation and blocks it (a re-signature of
the same body is not one).

Every `RR/GATE` hash or signature input starts with its name, `/v1` and a
NUL byte:

| Name | Covers |
|---|---|
| DECIDE-REQUEST, DECIDE-RESPONSE, TOKEN, CHECKPOINT | the signed or parsed wire formats |
| DECISION-ID, INPUT, SHARD | decision identity, decided-input digest, shard routing |
| MERKLE-NODE, LINES-NODE | token and claim-line Merkle trees |
| STATE; SNAPSHOT, RELEASED, UNRESOLVED | checkpoint state digest; the rules' read-set pins |
| SEGMENT | financial history segments |
| KEY-CERT | epoch key certificate (v1, built) |
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
default.

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
on the absence of an active bypass grant rather than being weakened.

## 7. Primary, fenced standby, and the operational runbook

The 99.8%-monthly availability target (~87.6 minutes of downtime a month) is
met by one primary and one synchronous standby, no consensus cluster. A fencer in the state
tenant is the sole writer of the epoch, using an HSM monotonic counter plus
a short primary lease; safety never depends on clocks, only on when to
promote. A stale primary cannot forge a valid token: it cannot commit (no standby of its
own epoch will acknowledge it), it cannot sign (its epoch key is disabled in the
HSM), and payers refuse it (a payer that has seen the higher epoch rejects the
old one). A
TLA+ model (`gate_failover.tla`) checks these properties —
`NoConflictingTokens`, `NoFencedTokenAccepted`, `AtMostOnceRelease`,
`NoLostDecision`, `StaleCannotSign`, `EpochMonotone`,
`BypassEventuallyReconciled` — as bounded state-space search, not proof. Checked bounds and remaining larger runs belong in
`STATUS.md` and `docs/formal/gate_failover/README.md`.

**A tested failover drill and an operational runbook (source outage, database
outage, key loss, corrupted package, partial release, receiver timeout,
operator exit) are acceptance prerequisites for claiming 99.8%**; the trunk has
neither.

## 8. Sharding by member key

Data shards by person/member key, never by program or plan, so the gate's core
cross-boundary check (one person double-billed across FFS and managed care, or
two plans) stays in one shard instead of an asynchronous reconciliation pass. No Postgres migration and no
multi-region work happen before a measured SQLite ceiling shows the need
(Constitution IX.3).

## 9. The proof boundary: prove the interpreter, version the rule data

Formal verification goes where a defect can release, withhold or misstate
money, or forge or replay authority: the decision function, the bytes into and
out of it, the replay checker and the signed token. Those are Lean, with
proofs; interleavings (crash, failover, fencing) get TLA+ model checking;
everything else gets tests.

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
maintenance unusable.
`CAP-REL` (§10) is data-shaped Lean evaluated by the interpreter, so it stays
on the interpreter's proof.

## 10. Evidence modes: the non-ZK path ships first

- **`DIRECT_STATE_OWNED`** uses canonical facts lawfully held in the state
 boundary directly, with no cryptographic wrapper.
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
auditor guidance accepts ZK proofs as audit evidence.

`PRIVATE_ZK` is a **parallel add-on**, not a prerequisite. Its marginal value
is not "anyone can verify," since the state and the entity signing the roots ZK
proves against are the same side; it is the cross-organizational case with an
unmotivated verifier, e.g. proving to an MCO or a federal partner that no member
in a release is on a death-match file without disclosing the eligibility list.
The cheap step now is writing `CAP-REL-v1` (the capitation-release relation) as
a plain Lean predicate (useful today as `DIRECT_STATE_OWNED` evidence), so a
later hidden-input proof has an exact spec. Circuit and verifier proofs (20–35
engineer-weeks for the circuit, 40–80 for a verified verifier) are not scheduled.

If `PRIVATE_ZK` is ever selected, its parameters come from `zk-spike/params.md`'s
P128-R set (128-bit classical soundness, ~64-bit under a quantum random oracle,
100-bit under the conjecture-free unique-decoding bound). Salt sizing, custody,
and 7-year retained salts versus scheduled destruction are open (§14).

## 11. Post-quantum cryptography

- **ML-DSA-87** (FIPS 204 algorithm, non-validated AWS-LC build) signs batch and
 checkpoint bytes, one signature per batch (§5). Synthetic tenants: a
 DPAPI-sealed key behind a pinned worker, each signature checked by the Lean
 `gate_verify`; the M1 root is a laptop key, not the HSM root below.
- **Long-lived root and anchor keys use LMS/XMSS** (SP 800-208), not
 SLH-DSA: no FIPS-140-3-validated cloud HSM offers SLH-DSA today, while
 LMS/XMSS is HSM-backed now (e.g. Thales Luna T7, certificate #5450). SLH-DSA stays available as an optional software-verified second
 signature, never the only one on a root key. LMS/XMSS keys are stateful
 and need the SP 800-208 no-backup-restore operational discipline.
- **SHA3-512, domain-separated, through AWS-LC**; the Lean verifier's own SHA3
 sees public inputs only.
- **Hybrid ML-KEM TLS (X25519MLKEM768)** protects the gate-to-payer and
 gate-to-standby channels. Confirmed available on AWS GovCloud
 load-balancer policies as of late 2025; Azure Government's support is
 unconfirmed, so the design terminates TLS on the gate's own backend (AWS-LC
 or OpenSSL 3.5+) behind an ordinary L4 load balancer where a PQ-capable
 managed front end is unavailable.

We verify none of these primitives ourselves; we consume AWS-LC's
machine-checked proofs (HOL Light and CBMC, for ML-KEM and, as it lands,
ML-DSA), run ACVP/KAT vectors in CI against the exact library build, and
prove only the binding — that signed bytes name exactly one decision. ML-DSA
integration into AWS-LC's FIPS-validated path was still landing; check
certification per deployment.
Constitution VI.5 forbids RSA/ECDSA fallback signatures; certification delay
does not authorize a downgrade.

## 12. Evidence and integration

A format model, compiled rules, a pinned executable and an integrated workflow
are separate claims, and one branch's results do not verify another's or their
combination. `artifacts/engine-correction/PROVENANCE.md` is the engine pin.

The payer gate needs authenticated checkpoint ancestry and admission of signed,
tenant/program-scoped, current authority grants; persisted fences,
released/unresolved identities, rules, tokens and payer release must be
connected and exercised through restart, retry and partial failure before an
end-to-end gate claim (STATUS). Batch windows, worker counts and private-proof latency
estimates remain targets until measured.

## 13. Path

Port the remaining command types in order of money impact (`fv-plan.md`), with the
warm-worker and owner throughput benchmarks (branch `load-test`) before any
batch-sizing or worker-pool claim. The X12/NCPDP tokenizer comes with the
adapter build. `PRIVATE_ZK` stays in its separate prototype repository
(Constitution IX.4) and needs a third-party audit before any claim.

## 14. Remaining design decisions

Protected format, digest and theorem changes need the record and review in
Constitution XI.2; implementations and evidence belong in `STATUS.md`.

- Complete the authority-grant, bypass, release and witness admission
 contracts, including checkpoint ancestry, scope, revocation and durable
 recovery.
- Resolve salt custody for any future private-proof deployment: retained
 wrapped salts and scheduled destruction have different disclosure
 guarantees.
- Establish measured segment and worker bounds before increasing the
 current store/export limits. Existing segmented Continuity does not
 prove million-event operation.

## 15. Beyond the gate

The gate changes no role in the five-part product (`README.md`,
`ARCHITECTURE.md`): Mirror is the exception queue and audit surface, and the
owner stays the one financial writer (Constitution III.1). The official receiver
and payment system keep money-movement authority; Provider App remains a
separate provider-side product. Cross-state reuse stays limited to versioned,
non-sensitive interface schemas and conformance vectors. Commercial terms are
the founder's (Constitution VIII).
