# RightRail full-stack target

Target architecture for RightRail and, within it, the Blind Ledger operating record as an inline payment gate.

`CONSTITUTION.md` is supreme; this document elaborates it and cannot weaken
it. `ARCHITECTURE.md` describes today's code;
`STATUS.md` is the only status record. This document selects no state, program, profile, evidence mode, authority level or receiver. Everything here is design, not run or approved, except what `STATUS.md` lists as built. Standing claims: CONSTITUTION VI.2.

## 1. The end state

The gate is one authority level within the product `ARCHITECTURE.md` describes;
the core financial cycle and independent exit stay useful without it.

Every Medicaid payment a state routes through RightRail — FFS and managed
care alike — passes the Blind Ledger gate before money goes out, at full state scale
(New York's eMedNY cycle is the sizing reference: ~9.6M claims and $1.9B
paid per weekly cycle, per the NY Comptroller audit of 2025-06-18).
RightRail still never
moves money (Constitution I.4): the state's own payment system checks the
gate's decision and remains the party that holds or releases. No legal
precedent exists for a private vendor to hold the 42 CFR 455.23 suspension
trigger itself, so every interface says "the gate produces the
determination the state's system consults," never "the gate holds the
payment."

RightRail enters beside one responsibility and then shrinks the old work it
makes unnecessary. Each responsibility names, before go-live, the old tasks it
retires and their measured baseline (staff hours, contract dollars);
rebuilding, chasing, recoding, reconciling, reporting and re-procuring are the
target.

Gating is **off by default**; a state turns on only the authority it grants,
per flow, through a state-signed `AUTHORITY-GRANT` (§3).

The evidence model, roles and growth path: `docs/STATE_EVIDENCE_ARCHITECTURE.md`. The six products: `ARCHITECTURE.md`.

## 2. First jobs, gate points and rollout order

**First jobs.** The evidence record is the product, and the gate is its end state, not the first sale. Tamper
evidence, post-quantum signing and holds before payment can be bought elsewhere. What only a neutral record across
every state system can do is answer for a line as of its date, wherever the evidence sits, and name which system's
step caused a difference. The first paid jobs, from 2028, are built on that, in order:

1. Audit folder. When a federal deferral or audit sample arrives, the state gets a line-level data pull within days;
   for each sampled line, one folder across every state system as of the service date (claim, enrolment, provider
   licence and screening, background study, service authorisation, assessment, plan of care, visit verification),
   listing the paper that is missing and who holds it; and a recompute of the federal sample frame and extrapolation.
   Most deferred dollars turn on provider paper and policy judgement; the folder makes those quick to settle, it does
   not decide them.
2. System and vendor at fault. From the same data, each difference between systems names the system and the vendor
   whose step caused it, at every seam between systems, so the state can apply the remedies its contracts already
   hold. Switch uses the same report as a tool the state or its independent tester runs: the old and the new claims
   system process the same record before a replacement goes live, and the differences are listed by cause, owner,
   system and dollars.
3. Determination and notice check. Each eligibility determination and its notice are checked independently against
   the record: the facts used, when they were known, the rule applied and whether the notice states them.
4. Caseworker desk. For the cases automatic matching cannot settle, Mirror gives caseworkers and county offices a
   read-only side-by-side view of the evidence; the decision stays the worker's and the view records what was shown.

None of these depends on a dated federal penalty: they answer deferrals, court orders, go-live dates and staff
shortage, which already happen. Price (Constitution VIII): about $2M a year for operating the service, plus the marginal 10/7/5-basis-point covered-flow schedule with a 5 bp floor; the Provider App is priced separately. The build order serves these jobs first:
rules as signed data under one proved interpreter, facts kept under two times, readers for files the state already
exports, the replay difference report by cause and system, and the eligibility determination record. The readers
cover sources beyond claims (licensure and screening, background studies, service authorisations, assessments, plans
of care, visit verification) and records other systems already keep (eligibility evidence history, rule-engine
traces), each checked independently rather than trusted; provider paper is read with its origin kept. The record
format, the checker and the interpreter test vectors are to be published so any buyer can check the record without
us. Speed is measured once at replay volume and then keeps a fixed share of the work; screens follow these.

**Rollout stages.** A state takes the state-side products together (every product except Provider App, which is sold
to providers on its own) and switches them on in four stages. No stage holds a payment until the stage before it has
earned that, and every stage must make staff work radically easier and faster from its first month.

1. Answer. Federal deferrals, audit and error-rate samples are answered from the record with the documents attached;
   determinations and notices are checked against the record; Mirror pre-fills renewals from claims data and shows
   exemptions and proof before any coverage ends; Switch replays before a new claims system goes live; an exact duplicate payment line is answered at once (Constitution I.4). Nothing is held.
2. Watch. Every product runs on live flows and holds nothing. Each hold it would have made is recorded and checked,
   which gives the measured false-hold rate per cause.
3. Hold by cause. A hold cause is switched on only once its measured false-hold rate is at most 5%, and its holds are
   released by cause (Constitution I.2).
4. Gate. The payment gate at the authority the state grants (§3), in the order below.

Before a stage starts it names the staff tasks it makes faster or removes, with their measured baseline (§1), and it
is judged on that. Views show evidence and gaps, never a recommended decision.

**Gate points.**

The gated unit is one payment: one payee, one amount, one release, with claim
or member-month lines underneath.

| Flow | Payment unit | Lines under it | Gate point |
| --- | --- | --- | --- |
| FFS weekly cycle (`FFS_CYCLE`) | Per-provider EFT/check | Claim lines | Cycle close, ~5 days before issue |
| FFS per-claim (`FFS_CLAIM`) | Adjudicated claim | Itself | At adjudication |
| Capitation release (`CAP_820`) | Per-plan capitation payment | Member-month lines | Monthly release |
| Directed payment (`SDP`) | Disbursement | Provider lines | Preprint schedule |
| Plan-to-provider (`PLAN_PAY`) | Plan payment to a provider | Claim lines | Needs a contract clause; no precedent today |

Rollout order for the gate when it comes: FFS first (cycle, then per-claim), then capitation release
(`CAP_820`), then directed payments (`SDP`) released on proof of service use
(an accepted encounter, or the hospital's claim agreeing with the plan's 835
payment). FFS comes first because the state adjudicates and pays those claims
itself, so the gate sits on the state's own payment run with no plan in between.
Pharmacy lines are gated like any other flow, read against public price files.
`PLAN_PAY` stays in the format but is not on the rollout path.

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

What is built of this is in `STATUS.md`.

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

**Batching is a hard invariant.** One SQLite commit and
one ML-DSA-87 checkpoint signature cover a whole batch (up to 1,000 items,
closing at a 150 ms window). A per-payment token is a Merkle-inclusion path
of a few hundred bytes against that checkpoint's `token_root`, not a
separately signed token.

Signing each token would cost ~45–90 TB over 7 years at New York's volume and
exhaust a shared HSM/KMS request quota.

Every batch commit produces a checkpoint (tenant, program, shard, sequence
range, epoch, previous-checkpoint digest, event-chain head, token/evidence/
projection roots, a never-zero state digest over the rules' released and
unresolved pins, count, time), signed with the epoch's ML-DSA-87 key. The rules extend the
sets of the payment's shard's latest signed checkpoint.
There is one sequence counter per (tenant, shard, epoch), shared by the
tenant's programs, from 0: each checkpoint names the one just
before it as its previous (all-zero for an epoch's first); a link to a
non-adjacent checkpoint is a fork. The producer persists a checkpoint before signing it and checks its stored
ones for a fork before publishing.
The KEY-CERT signs every field, shard count included; a payer accepts one certificate per (tenant, epoch); a second with another
key or shard count is equivocation and blocks it (re-signing the
same body is not).

Every `RR/GATE` hash or signature input starts with its name, `/v1` (unless
shown) and a NUL byte:

| Name | Covers |
|---|---|
| DECIDE-REQUEST, DECIDE-RESPONSE, TOKEN, CHECKPOINT | the signed or parsed wire formats |
| DECISION-ID, INPUT, SHARD | decision identity, decided-input digest, shard routing |
| MERKLE-NODE, LINES-NODE | token and claim-line Merkle trees |
| STATE; SNAPSHOT, RELEASED, UNRESOLVED | checkpoint state digest; the rules' read-set pins |
| SEGMENT, KEY-CERT | financial history segments; epoch key certificate |
| READ-<kind>/v2, READ-SET/v2, READ-MANIFEST/v2 | read manifest |
| CHECKPOINT/v3 | what the producer emits: the v1 fields plus the shard's counter value |
| KEYSET/v2 (+/SIG, /REINIT/v1), KEY/v1 | key set, successor signature, ratchet re-init; key file (`RR/` tags, no `GATE/`) |
| SNAPSHOT/v3 (+/v3/SIG), READ-MANIFEST/v4 | signed k-of-n rules-read snapshot with validity window; v4 manifest (Lean `Gate/SnapshotV2.lean`) |
| CUTOVER/v3 | cut tag over the shard chain (`CUT_DOM`) |
| TEST-ONLY-SEED, TEST-ONLY-MEMBER | synthetic test keys, never product |

Checkpoints stream to an independent witness (a separate state agency or
auditor, outside the database administrator's control), which cosigns only
after checking sequence and epoch monotonicity and that no two checkpoints of
one (tenant, shard, epoch) share a sequence with different digests or break the
link. A mismatch raises a fork alarm; payers holding one refuse the whole
(tenant, epoch). A payer releases a batch's payments only after the witness has cosigned its
checkpoint; per-claim payments (FFS_CLAIM) do not wait for the agency witness,
but still pass the machine cosign check of every batch. History is sealed into
segments, each bound to the closing checkpoint. Records are retained 7 years
(Pub 1075 AU-11) in WORM storage, onshore, in the state tenant. A daily anchor
checkpoint carries an extra LMS/XMSS signature so a 7-year-old record stays
verifiable on hash-based assumptions alone.

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
payment. Staff see one item per cause, not one per payment (Constitution
XII.9). The item lists its payments, and one action settles the cause. Each
payment is still decided and recorded on its own.

**Release by cause** (Constitution I.2; built in the engine, `Rules/Run.lean` `admit` and `approvals`; Lean statements
in `Gate/CauseRelease.lean`). The
officials sign one decision naming one cause and the exact list of held payments it releases. The list selects; the
scope only narrows it, so a payment held for the cause but not listed when the decision is signed stays held, and so
does any later one.

- *Record.* `APPROVAL/v2` kind 3, under the same domain and signature tag as the grant (kind 1) and the bypass
  (kind 2), whose bytes do not change: kind byte 3, state digest, tenant, not-before and not-after (valid dates at
  most 31 days apart, the batch day inside them), the cause (one byte: the reason's fixed bit number, `Reason.idx`),
  the program, a flow mask (1-31), a service-date range (valid dates, from not after to), the total in cents (u64),
  and 1 to 4,096 entries in strictly ascending payment-id byte order, each a payment id, the SHA3-512 digest of the
  exact `DECIDE-REQUEST` bytes it was held under, and its amount in cents (u64). The total must equal the sum of the
  amounts exactly, and like every u64 field each is at most 2^63 - 1. Then the signature block. The record's id is the
  SHA3-512 digest of its unsigned bytes.
- *Who signs.* Two live APPROVER keys of the batch head's key set, held by distinct employees with distinct
  identity-provider subjects: the bypass's quorum. A revoked or expired key, or a key set below the tenant's floor,
  cannot admit it. The record has no serial and does not touch the grant or key-set floors.
- *Which causes.* Only a reason a bypass may override (`Rules.bypassable`): facts about members and providers, stale
  reference files, a near duplicate or near collision, a future service date. A reason that guards release-once or marks
  malformed input (an already-decided line, an exact, unverified or unresolved duplicate, a capitation member-month
  duplicate, an invalid date, the posting cap, a stale released or unresolved set) is never a cause.
- *What it releases.* The record travels in the frame's approval list, beside bypasses (at most 64 approvals are
  read per batch; each record can list 4,096 payments). A listed payment is released in a batch when every one of
  these holds: the batch carries its request and the request's digest is the listed one; the request's amount is the
  listed amount; its program is the record's, its flow is in the mask and every line's service date is in the range;
  the grant entry covering it has TRANSFER authority; it is not decided again in this batch; a line of it is in the
  gate's unresolved set; no other admitted approval of the batch names it; and every reason on every line of it, as
  decided now, is the record's cause. A payment held for the cause and something else as well is not released. A
  listed payment whose facts have since cleared is released, and the record is the recorded cause of its release, as
  for a bypass. The released payment's leaf is ALLOW with the record's id in the bypass field, so the payer runs its
  usual twelve checks and needs no new one. Each payment is still decided and recorded on its own.
- *Shards and batches.* Payments route by member key, so one record lists payments of many shards and cycles. Every
  shard reads the same record and releases only the listed payments it decides; a listed payment that is not in the
  batch, or a payment of another program with a listed id, is not an error and gets no note. The host sends a record
  only with a batch that carries one of its payments.
- *Once.* A released payment's lines join the released set, so a resend is `ALREADY_DECIDED` and no record or bypass
  releases it again (`bypass_once` covers both). A record can be read in many batches during its window, but it never
  releases a payment that is not on its list. A payment that did not exist when the record was signed cannot match a
  listed request digest, except through a SHA3-512 collision. The amounts released under one record never exceed its
  total.
- *With the bypass.* Both reach the rules the same way, as a (payment, override mask) pair. A cause record's mask is
  its single cause bit; a bypass can name several reasons. If a bypass and a cause record, or two cause records, name
  one payment in one batch, neither releases it (`DUPLICATE` for each) and it stays held.
- *With the grant.* A cause release needs TRANSFER authority, as a bypass does. At HOLD authority the payer does not
  pay on the gate's token (check 8), and the gate does not learn when the payer pays, so a release recorded there would
  claim money moved that the gate cannot see. Stage 3 (hold by cause at HOLD authority) can use cause releases only
  once the payer reports its releases to the gate (STATUS, "Held batches").
- *Refusals.* Approval bytes are a cause record when they begin with the approval tag and kind byte 3; any other bytes
  are read as a bypass, as today, so kind 4 or a relabeled record is `RULES_BYPASS - MALFORMED`. For the whole record,
  each line is `RULES_CAUSE - <why>`: `MALFORMED`, `SCOPE` (another state or tenant),
  `EXPIRED`, `REASONS` (a cause no bypass may override), `UNSIGNED`, `TOO_MANY` (past the 64 approvals read). For one
  listed payment in the batch, each line is `RULES_CAUSE <payment> <why>`: `WRONG_REQUEST`, `AMOUNT`, `SCOPE`
  (a flow outside the mask, a date outside the range, or an entry without TRANSFER), `REDO`,
  `DUPLICATE`, `NOT_HELD` (not held, held for another cause as well, or already released). A refusal releases nothing
  and the rest of the batch is decided. These are notes, like the bypass notes, and need no new row in
  `app/cause_actions.json`.
- *Not covered,* as for the bypass: separation from the raiser and from the authors of the payment's lines (the
  decide request carries no author identity), and the payer verifying a release while the gate is down.

**Exact duplicates** (Constitution I.4; built in the engine, `Rules/Run.lean` `answering` over
`ExactDuplicate.decideBatchX`; Lean statements in `Gate/Rules/ExactDuplicate.lean`).

- *Definition.* A line exactly repeats a paid line when that paid line is in the gate's view of the released set
  (the chained set, or else the gate's own checkpoint of it, never an unchained set's loose rows), and its canonical
  line bytes equal the line's in every field except the line id: flow, member key, payee, rendering party, service
  date, procedure, units and cents. A re-decided payment's own released lines are excluded. Any other match stays
  with a person as it does today: a line that differs in any one of those fields (a near duplicate, or the same exact
  key with another rendering party), a repeat of an earlier line of the same batch (not paid yet:
  `FFS_DUPLICATE_LINE`), or a match with only a loose row (`FFS_DUPLICATE_UNVERIFIED`). Both lines carry the same
  member key and so route to the same shard, so this check in one shard finds every exact repeat.
- *Answer.* A payment with one or more exactly repeated lines gets the new outcome `ANSWERED` in the batch that
  carries it, as a whole payment even if its other lines are clean or held: as sent, its amount includes a paid line,
  so it can never go. The sender resends it without those lines, and the rest is decided then; a near duplicate among
  them then goes to a person. An unencodable payment stays HOLD. The leaf keeps the reasons as decided (the repeated
  line carries `FFS_DUPLICATE_LINE` or `CAP_MEMBER_MONTH_DUPLICATE`) and commits to the list of earlier payments: for
  each repeated line, ascending by line id, its line id, the earlier program and payment id, and the earlier line id.
  The sender-facing code is X12 claim adjustment reason 18 (exact duplicate claim or service), with that list. Today
  the sender gets the outcome and the list in `DECIDE-RESPONSE/v2`, and the reason-18 wording is in the staff table
  (`app/cause_actions.json`); no X12 reply to senders is built.
- *No money moves twice.* `ANSWERED` is not ALLOW, so the payer's check 8 refuses it at every authority. The repeated
  line carries a reason that no bypass, cause release or HOLD-level lift can override, so nothing releases it. Its
  lines join neither set, so no person is asked and a resend is answered the same way. The released set is exactly what
  it would be without the amendment.
- *Contest in one step.* The sender resends the same request with the contest flag set. A contested payment is decided
  as before the amendment: the repeated line holds for a person (`FFS_DUPLICATE_LINE` or `CAP_MEMBER_MONTH_DUPLICATE`),
  and releasing it is a determination, which is not a bypass or a cause release and is not built.
- *Formats.* `TOKEN/v3`: `TOKEN/v2` plus the outcome `ANSWERED` (tag 5) and `earlier_root` after the bypass field,
  zero unless the outcome is `ANSWERED` and nonzero when it is. `earlier_root` is the SHA3-512 digest of
  `RR/GATE/EARLIER/v1`, a NUL, the u16 count and the entries, each an identifier, two identifiers and an identifier.
  The list itself travels in `DECIDE-RESPONSE/v2`, and the requester checks it against the root. The shard's producer
  store keeps each answered payment's list with its batch, so an exact retry is given it again with the same tokens,
  and the row the owner signs for that batch says the list was stored. If such a batch's list is later missing, the
  retry is refused as `store_tampered` and the batch is kept as evidence; the list is not rebuilt. A batch sealed
  before the store kept lists has no such mark and has its lists rebuilt once from the shard's stored frames. A stored
  or rebuilt list that does not match its token's root is never served. The mark only moves forward: a producer from
  before it reads a marked row as `store_tampered`. Each batch row also pledges the root of the set of retry keys, so
  a retries row deleted or rekeyed is `store_tampered` when its exact retry arrives, never decided again. The root
  starts at a store's first commit under it (a row deleted before then is not caught), and a producer from before it
  refuses the store. `DECIDE-REQUEST/v2`
  is `v1` plus a one-byte contest flag (0 or 1) after the evidence references. The engine's answer leaf gains the
  outcome and the list. The checkpoint format is unchanged; its token root covers `v3` leaves. Each of these is a
  protected change under Constitution XI.2.

**Build order for both.** Every step below is built and proved: `tests/test_gate_cause_release.py`,
`tests/test_gate_exact_duplicate.py` and `tests/test_cause_actions.py` pass with no skips, the
`tests/test_gate_authority_frames.py` cases are unchanged, and `tests/lean_sorry_allowlist.txt` is empty. The P4
theorems have axiom pins in `Gate/AxiomCheck.lean`; the P1-P3 theorems do not yet. What remains is the staff screen
per cause (STATUS).

- *E1, cause record.* Build `CauseRelease.decode` and `admit` into the engine's approval reading (the kind byte picks
  the reader; `TOO_MANY` past 64), the per-entry judgement, `merge` and the `RULES_CAUSE` notes, and put the record's
  id on each payment it releases. The host binds a record's id only to a payment that the record lists. The frame, the
  leaf, the checkpoint and kinds 1 and 2 keep their bytes; kind 3 is a new wire format and the engine pins move, so
  E1 lands with its own XI.2 record. Acceptance: every case in `test_gate_cause_release.py`, including
  `CauseReleasePaidTests`.
- *E2, exact-duplicate answer.* Build `decideBatchX` over the rules and the engine (the unresolved additions leave
  out answered payments); `ANSWERED` and the earlier list in the engine answer and `Pay`; `TOKEN/v3` and
  `RR/GATE/EARLIER/v1` in the codec, the producer, the publish check and the payer's leaf reader; `DECIDE-REQUEST/v2`
  with the contest flag; and `DECIDE-RESPONSE/v2`. One XI.2 record covers these changes and re-pins the golden
  vectors, gate-rules vectors and engine pins they move. Acceptance: every case in `test_gate_exact_duplicate.py`,
  and the format and vector suites after re-pinning.
- *E3, staff and senders.* Update the `app/cause_actions.json` text for `FFS_DUPLICATE_LINE` (answered at once,
  contested in one step) and the reason-18 mapping to senders, then STATUS. Acceptance: `tests/test_cause_actions.py`.
- *P1.* Prove `encode_decode`, `kinds_disjoint`, `decode_list`, `admit_sound`, `pairs_listed`, `fits_within_total`
  and `mem_merge`. *P2.* Prove `releases_only_listed`, `never_other_cause` and `releases_every_listed_held` from
  `Rules.bypassed`. *P3.* Prove the `ExactDuplicate` statements; `twin_reason` and `near_never_exact` come from the
  claim order (a re-decision's own lines first). *P4.* Extend the Fast/Spec equality to `decideBatchX` and the
  approval reading of E1.

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

What is built of this is in `STATUS.md`.

Fail-closed is the invariant T1' (`fail_closed_unless_bypass`): `outcome ≠
Accepted → delta = ∅`, unless a verified `BYPASS` approval admitted in the
same step commits to exactly that delta and none of its payments was released
before (`bypass_attributed`, `bypass_no_window`).

## 7. Primary, fenced standby, and the operational runbook

The 99.8% monthly availability target (~87.6 minutes of downtime) is
met by one primary and one synchronous standby, no consensus cluster. A fencer
in the state tenant is the sole writer of the epoch, using an HSM monotonic
counter on the gate machine (a TPM counter), with the second agency's
cosignature as the off-machine check, plus a short primary lease; safety never depends on clocks. A stale primary cannot forge a valid token: it cannot commit (no standby of its
own epoch will acknowledge it), it cannot sign (its epoch key is disabled in the
HSM), and payers refuse it (a payer that has seen the higher epoch rejects the
old one). A TLA+ model checks these properties as bounded state-space search,
not proof (`docs/formal/gate_failover/README.md`).

**A tested failover drill and runbook (source or database outage, key loss,
corrupted package, partial release, receiver timeout, operator exit) are
prerequisites for claiming 99.8%.**

## 8. Sharding by member key

Data shards by member key, never by program or plan, so the core check (one
person double-billed across FFS and managed care, or two plans) stays in one shard. No Postgres migration and no multi-region work
happen before a measured SQLite ceiling shows the need (Constitution IX.3).

## 9. The proof boundary: prove the interpreter, version the rule data

Formal verification covers what can release, withhold or misstate
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
auditor reruns in the state's own tenant. No CMS, OIG, GAO or state auditor guidance accepts ZK proofs as audit evidence.

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
 `gate_verify`; the root is a laptop key, not the HSM root below.
- **Long-lived root and anchor keys use LMS/XMSS** (SP 800-208), not
 SLH-DSA: on-premises FIPS-140-3-validated hardware now offers SLH-DSA (CMVP certificate 5503,
 validated 2026-08-25); cloud HSMs are unchecked.  LMS/XMSS is HSM-backed now. SLH-DSA stays available as an optional
 software-verified second signature, never the only one on a root key.
 LMS/XMSS keys are stateful and need the SP 800-208 no-backup-restore
 discipline.
- **A new root after a re-genesis** is installed by the payer only on the
  agency's written instruction, with the fingerprint confirmed by the
  countersigning agency and two payer staff, recorded as a fact; RightRail
  never delivers or confirms an anchor, and payments hold until then.
- **SHA3-512, domain-separated, through AWS-LC**.
- **Hybrid ML-KEM TLS (X25519MLKEM768)** protects the gate-to-payer and
 gate-to-standby channels. Without a PQ-capable managed front end, TLS terminates on the gate's own backend (AWS-LC or OpenSSL
 3.5+) behind an ordinary L4 load balancer.

We verify none of these primitives ourselves; we use AWS-LC's
machine-checked proofs, run ACVP/KAT vectors against the exact library
build, and prove only the binding: signed bytes name exactly one decision.
Check FIPS certification per deployment. Constitution VI.5 forbids RSA/ECDSA
fallback; certification delay does not authorize a downgrade.

## 12. Evidence and integration

A format model, compiled rules, a pinned executable and an integrated workflow
are separate claims. `artifacts/engine-evaluator/PROVENANCE.md` is the engine
pin. Before any end-to-end gate claim (STATUS), the payer gate needs authenticated
checkpoint ancestry and admission of signed, scoped, current authority grants,
with fences, released/unresolved identities, rules, tokens and payer release
exercised through restart, retry and partial failure. Batch windows, worker
counts and private-proof latency remain targets until measured. The speed bars
and measurements are in `STATUS.md` (Speed bars).

## 13. Path and open decisions

Port the remaining command types in order of money impact; benchmark
throughput before any batch-sizing or worker-pool claim. The
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
- Whether revoking a roster or grant key holds all new releases within one
 batch.
- Provider notice and appeal duties for holds (counsel).
- The pre-approved list of lossless repairs that readers may apply.
- The minimum retention period and the long-horizon target.
- YubiHSM and 2 CFR 200.334 checks.
- Whether a bypass may pass a hold on a certain fact (counsel).
- How the counters are held under resharding.
- Which agency is the witness, and under what agreement.
