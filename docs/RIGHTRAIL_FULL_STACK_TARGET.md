# RightRail full-stack target

The target architecture for the complete RightRail service and, within it,
Blind Ledger as an inline payment gate.

`CONSTITUTION.md` is supreme; this document elaborates it and cannot weaken
it. [`ARCHITECTURE.md`](../ARCHITECTURE.md) describes today's code;
[`STATUS.md`](../STATUS.md) is the only status record. It holds no status and
selects no state, program, profile, evidence mode, authority level or receiver. It draws on design notes held outside the repo
(`next-phase.md`, `gate-design.md`, `fv-plan.md`). Everything here is design,
not built, run, or approved: `proofSuiteId=null`, `production_usable=false`,
`activation=false`.

## 1. The end state

The gate is one authority level within the product `ARCHITECTURE.md` describes;
the core financial cycle and independent exit stay useful without it.

Every Medicaid payment a state routes through RightRail — FFS and managed
care alike — passes Blind Ledger before money goes out, at full state scale
(New York's eMedNY cycle is the sizing reference: ~9.6M claims and $1.9B
paid per weekly cycle, per the NY Comptroller audit of 2025-06-18).
RightRail still never
moves money (Constitution I.4): the state's own payment system checks the
gate's decision and remains the party that holds or releases. No legal
precedent exists for a private vendor to hold the 42 CFR 455.23 suspension
trigger itself, so every document/interface says "the gate produces the
determination the state's system consults," never "the gate holds the
payment."

Gating is **off by default**; a state turns on only the authority it grants,
per flow, through a state-signed `AUTHORITY-GRANT` (§3).

## 2. Gate points and rollout order

The gated unit is one payment: one payee, one amount, one release, with claim
or member-month lines underneath.

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
follows feasibility and existing measurement, not fraud exposure: CMS does not
measure plan-to-provider payments (GAO-25-107770), so gating capitation first
risks moving fraud there.

## 3. Authority ladder

A state-signed `AUTHORITY-GRANT` sets one of three levels per flow. Levels move up
only by a new grant:

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
answers each independently, keyed by the payer's `command_key`, so an exact
retry returns `DUPLICATE` and never decides twice. Response status: `DECIDED`, `DUPLICATE`, `REJECTED` (malformed input
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
missed (fixed across reissues: FFS_CLAIM 14 days, FFS_CYCLE 28, CAP_820 62);
payment fields match exactly; the token comes from the
shard the member key routes to; outcome is ALLOW; `rule_version` and
`engine_release` are on the payer's approved list; the payment has not
already been released; no fork or equivocation is recorded for the tenant and epoch; and
the payer sent a command for the payment and the member key is the one its
first command pinned (a changed key is refused as `member_key_changed` until
an official determination, not in v1). These twelve checks are one Lean predicate
(`verifyToken`), proved to accept only when all twelve hold, and published to
payers as a reference verifier with conformance vectors. A release with no
token and no bypass is a payer-side violation visible in Mirror.

## 5. Batch signing, checkpoints, and inclusion tokens

**Batching is a hard invariant, not a tuning option.** One SQLite commit and
one ML-DSA-87 checkpoint signature cover an entire batch (up to 1,000 items,
closing at a 150 ms window). A per-payment token is a Merkle-inclusion path
of a few hundred bytes against that checkpoint's `token_root`, not a
separately signed token.

Signing each token would cost ~45–90 TB over 7 years at New York's volume and
exhaust a shared HSM/KMS request quota.

Every batch commit produces a checkpoint (tenant, program, shard, sequence
range, epoch, previous-checkpoint digest, event-chain head, token/evidence/
projection roots, a never-zero state digest over the rules' released and
unresolved pins, count, time), signed with the epoch's ML-DSA-87 key. The rules extend the
sets of the payment's shard's latest signed checkpoint. A runtime verifier
that the priors hash to the checkpoint's `state_digest` is not built.
There is one sequence counter per (tenant, shard, epoch), shared by the
tenant's programs and starting at 0: each checkpoint names the one ending just
before it as its previous (all-zero for an epoch's first); a link to a
non-adjacent checkpoint is a fork. The producer persists each checkpoint before signing and checks its stored
checkpoints for a fork before publishing.
The KEY-CERT signs every field, the shard count included; a payer accepts one certificate per (tenant, epoch); a second with another
key or shard count is recorded as equivocation and blocks it (a re-signature of
the same body is not one).

Every `RR/GATE` hash or signature input starts with its name, `/v1` (unless
shown) and a NUL byte:

| Name | Covers |
|---|---|
| DECIDE-REQUEST, DECIDE-RESPONSE, TOKEN, CHECKPOINT | the signed or parsed wire formats |
| DECISION-ID, INPUT, SHARD | decision identity, decided-input digest, shard routing |
| MERKLE-NODE, LINES-NODE | token and claim-line Merkle trees |
| STATE; SNAPSHOT, RELEASED, UNRESOLVED | checkpoint state digest; the rules' read-set pins |
| SEGMENT | financial history segments |
| KEY-CERT | epoch key certificate |
| CHECKPOINT/v2, ID-REG/v2 | v1 plus registry head; the id registry chain |
| TEST-ONLY-SEED, TEST-ONLY-MEMBER | synthetic test keys, never product |

Checkpoints stream to an independent witness (a separate state agency or
auditor, outside the database administrator's control), which cosigns only
after checking sequence and epoch monotonicity and that no two checkpoints of
one (tenant, shard, epoch) share a sequence with different digests or break the
link. A mismatch raises a fork alarm; payers holding one refuse the whole
(tenant, epoch). Payers never wait for the witness. History is sealed into
segments bound to the checkpoint that closes them. Records are retained 7 years
(Pub 1075 AU-11) in WORM storage, onshore, in the state tenant. A daily anchor
checkpoint carries an extra LMS/XMSS signature so a 7-year-old record stays
verifiable under hash-based assumptions alone.

## 6. Hold, release, fail policy, and bypass

**States.** `PENDING -> ALLOWED | HELD | REVIEW | BLOCKED`, and
`HELD | REVIEW | BLOCKED -> RELEASED | DENIED` only by a determination: a new
decision revision with a new token. An unreleased ALLOW past its age (§4) is
re-decided on current data as the next revision, excluding its own released
lines: a line is released at most once. Holds are monotone: adverse facts never move a decision toward ALLOW. Only named state officials,
authenticated through the state IdP with phishing-resistant MFA, may release
or deny: one releaser distinct from the raiser for HOLD/REVIEW, a releaser
plus a program-integrity supervisor (both distinct from the raiser) for
BLOCK. **RightRail staff hold no release or deny role in any tenant.** SLA
timers follow the flow's clock: 42 CFR 447.45 prompt-pay for non-fraud FFS
holds, the 42 CFR 455.23 5-day suspension clock for fraud reasons,
before-the-next-820 for capitation, contract terms for plan-to-provider.
Mirror is the exception queue holding every non-ALLOW item and every bypassed
payment.

**Fail policy.** Every flow fails closed (Constitution III.5): if the gate is
down or does not allow a payment, the payer holds it. There is no `FAIL_OPEN`
setting and no standing or pre-signed bypass.

**Bypass.** A bypass releases one named payment before it goes. Named state
officials from the state-signed roster first fully verify it against every
item of the Control Pack's bypass checklist for its hold reason, then sign an
`APPROVAL` of kind `BYPASS`. The approval commits to the exact payment (the
hash of its moves), the deployment and mode, the Control Pack, and an expiry
no later than the pack's. Signers follow the release rules above: distinct
from the raiser and from every author of the payment's lines; a releaser plus
a program-integrity supervisor for a BLOCK; and two distinct officials with
distinct identity-provider subjects once one official's single-signer total
for the claim, the payee cycle or the held line reaches the program threshold.
While the gate is down, the payer's own check verifies the approval and,
because it cannot see the hold class or the single-signer totals, requires
their strictest values: a releaser plus a program-integrity supervisor. The
payer records each released payment once and refuses a second release of it.
RightRail cannot issue, extend or countersign a bypass. A bypass names its
payment, so it can release no other and cannot outlive its admission. There is
no grant, time window, post-hoc re-decision or recoupment: a payment is
verified before it goes, never chased after.

Fail-closed is the invariant T1' (`fail_closed_unless_bypass`): `outcome ≠
Accepted → delta = ∅`, unless a verified `BYPASS` approval admitted in the
same step commits to exactly that delta and none of its payments was released
before (`bypass_attributed`, `bypass_no_window`).

## 7. Primary, fenced standby, and the operational runbook

The 99.8%-monthly availability target (~87.6 minutes of downtime a month) is
met by one primary and one synchronous standby, no consensus cluster. A fencer
in the state tenant is the sole writer of the epoch, using an HSM monotonic
counter plus a short primary lease; safety never depends on clocks. A stale primary cannot forge a valid token: it cannot commit (no standby of its
own epoch will acknowledge it), it cannot sign (its epoch key is disabled in the
HSM), and payers refuse it (a payer that has seen the higher epoch rejects the
old one). A TLA+ model checks these properties as bounded state-space search,
not proof (`docs/formal/gate_failover/README.md`).

**A tested failover drill and an operational runbook (source or database
outage, key loss, corrupted package, partial release, receiver timeout,
operator exit) are acceptance prerequisites for claiming 99.8%.**

## 8. Sharding by member key

Data shards by person/member key, never by program or plan, so the gate's core
cross-boundary check (one person double-billed across FFS and managed care, or
two plans) stays in one shard. No Postgres migration and no multi-region work
happen before a measured SQLite ceiling shows the need (Constitution IX.3).

## 9. The proof boundary: prove the interpreter, version the rule data

Formal verification goes where a defect can release, withhold or misstate
money, or forge or replay authority: the decision function, the bytes into and
out of it, the replay checker and the signed token. Those are Lean, with
proofs; interleavings (crash, failover, fencing) get TLA+ model checking;
everything else gets tests.

**Core invariants are proved once, over the interpreter, never over one
rule's content.** `step`/`batch` (a pure `ReadSet -> Command -> Outcome`
function) carries eleven universal theorems: fail-closed, revision
discipline, idempotence and retry identity, conservation of amounts, one
permutation-invariant completion time, no double release, monotone holds,
authority against a versioned roster, bounded arithmetic, evidence-mode fixity,
and non-dispatch. **Fee schedules, NCCI edit pairs and per-state coverage
tables ship as versioned, hash-pinned, test-vectored data, with no theorem
review per update**: their cadences differ (NCCI quarterly, fee schedules ad
hoc, SPAs continuously). `CAP-REL` (§10) is data-shaped Lean evaluated by the
interpreter, so it stays on the interpreter's proof.

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
auditors:** signed batch checkpoints, the witness cosign chain, Merkle
inclusion proofs for selective disclosure, and a reproducible Lean checker an
auditor reruns in the state's own tenant. No CMS, OIG, GAO or state auditor
guidance accepts ZK proofs as audit evidence.

`PRIVATE_ZK` is a **parallel add-on**, not a prerequisite. Its value is the
cross-organizational case with an unmotivated verifier, e.g. proving to an MCO
or a federal partner that no member in a release is on a death-match file
without disclosing the eligibility list. `CAP-REL-v1` (the capitation-release
relation) is to be a plain Lean predicate (not yet written), useful as `DIRECT_STATE_OWNED` evidence and
as the exact spec for a later hidden-input proof. Circuit and verifier proofs
are not scheduled.

## 11. Post-quantum cryptography

- **ML-DSA-87** (FIPS 204 algorithm, non-validated AWS-LC build) signs batch and
 checkpoint bytes, one signature per batch (§5). Synthetic tenants: a
 DPAPI-sealed key behind a pinned worker, each signature checked by the Lean
 `gate_verify`; the M1 root is a laptop key, not the HSM root below.
- **Long-lived root and anchor keys use LMS/XMSS** (SP 800-208), not
 SLH-DSA: no FIPS-140-3-validated cloud HSM offers SLH-DSA today, while
 LMS/XMSS is HSM-backed now. SLH-DSA stays available as an optional
 software-verified second signature, never the only one on a root key.
 LMS/XMSS keys are stateful and need the SP 800-208 no-backup-restore
 discipline.
- **SHA3-512, domain-separated, through AWS-LC**.
- **Hybrid ML-KEM TLS (X25519MLKEM768)** protects the gate-to-payer and
 gate-to-standby channels. Where a PQ-capable managed front end is
 unavailable, TLS terminates on the gate's own backend (AWS-LC or OpenSSL
 3.5+) behind an ordinary L4 load balancer.

We verify none of these primitives ourselves; we consume AWS-LC's
machine-checked proofs, run ACVP/KAT vectors in CI against the exact library
build, and prove only the binding — that signed bytes name exactly one decision.
Check FIPS certification per deployment. Constitution VI.5 forbids RSA/ECDSA
fallback; certification delay does not authorize a downgrade.

## 12. Evidence and integration

A format model, compiled rules, a pinned executable and an integrated workflow
are separate claims. `artifacts/engine-correction/PROVENANCE.md` is the engine
pin. Before any end-to-end gate claim (STATUS), the payer gate needs authenticated
checkpoint ancestry and admission of signed, scoped, current authority grants,
with fences, released/unresolved identities, rules, tokens and payer release
exercised through restart, retry and partial failure. Batch windows, worker
counts and private-proof latency remain targets until measured.

## 13. Path and open decisions

Port the remaining command types in order of money impact (`fv-plan.md`), with
throughput benchmarks before any batch-sizing or worker-pool claim. The
X12/NCPDP tokenizer comes with the adapter build.
`PRIVATE_ZK` stays in its separate prototype repository (Constitution IX.4) and
needs a third-party audit before any claim. Cross-state reuse is limited to
versioned, non-sensitive interface schemas and conformance vectors. Protected format, digest and
theorem changes need the record and review in Constitution XI.2. Open:

- The authority-grant, bypass, release and witness admission contracts,
 including checkpoint ancestry, scope, revocation and durable recovery.
- Salt custody for any future private-proof deployment: retained wrapped salts
 and scheduled destruction differ in what they disclose.
- Measured segment and worker bounds, before raising the current store/export
 limits; segmented Continuity does not prove million-event operation.
