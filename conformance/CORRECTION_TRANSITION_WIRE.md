# Correction transition wire formats

Contract `RR/FINANCIAL/CORRECTION-TRANSITION/v1`: request `BLFCMD02` (version 2),
result `BLFCRES3` (version 3). Contract `RR/FINANCIAL/CORRECTION-REUSE/v1`: request
`BLFCRU02`, assessment `BLFCRV02` (version 2 each).

Normative source: the Lean codec at base commit `d5853b1`,
`lean/BlindLedger/Financial/CorrectionTransition/{Types,Codec,ReuseCodec,Runtime}.lean`,
with primitives from `lean/BlindLedger/Financial/Codec.lean` and the receipt codec in
`lean/BlindLedger/Financial/DecisionPackage/Codec.lean`. The engine pinned in
`artifacts/engine-correction/PROVENANCE.md` implements it. Where this page and the Lean
disagree, the Lean wins and this page is wrong. The Python consumer is
`app/right_rail_financial_engine.py`; where it differs from the Lean, see
[Open discrepancies](#open-discrepancies).

Synthetic, non-PHI, nonpayment: `proofSuiteId=null`, `production_usable=false`,
`activation=false`.

## 1. Primitives

All integers are unsigned big-endian. Nothing is aligned or padded.

| Notation | Bytes | Rule a decoder enforces while parsing |
|---|---|---|
| `u8`, `u16`, `u32`, `u64` | 1, 2, 4, 8 | fewer bytes left: reject |
| `str` | `u16` length, then UTF-8 | length > bytes left or invalid UTF-8: reject |
| `d64` | 64 raw bytes | digest; only its length is checked |
| `bool` | `u8` | 0 = false, 1 = true, other: reject |
| `opt<T>` | `u8` tag, then `T` if tag 1 | 0 = absent, 1 = present, other: reject |
| `list<T>` | `u16` count, then items | count > 10,000: reject |
| `blob` | `u32` length, then bytes | length > 8,388,608 or > bytes left: reject |
| tag | `u8` | only values in the tables below; anything else: reject |

A `u64` parses over its full 64-bit range; the value bounds come from the
well-formedness rules in section 2.

Value classes (`lean/BlindLedger/Financial/Types.lean`, lines 19-28 and 313-341):

- **id**: 1..128 bytes; first byte `[A-Za-z0-9]`, the rest `[A-Za-z0-9._:-]`.
- **role**: 1..64 bytes; first byte `[A-Z]`, the rest `[A-Z0-9_]`.
- **text**: 1..512 bytes, no NUL.
- **amount** and **time**: ≤ 2^63-1. **revision**: ≤ 10,000. **sequence**: ≤ 10,000.
  **epoch**: 1..2^63-1.
- **canonical id list**: ≤ 10,000 ids in strictly ascending order. Lean compares
  strings by code point, which is byte order for ids.

## 2. How to decode

A conforming decoder accepts a byte string only if all of these hold. This is
exactly what the Lean `decode*` functions do.

1. The total length is at most 8,388,608 bytes (the reuse request allows 25,165,824).
2. The magic, `u16` version and contract string are exactly as specified.
3. Every field parses as in sections 3-6, including each nested blob, and **no byte
   is left over**, either at the top level or inside the receipt blob.
4. The value is well-formed. The decoder re-encodes the value and requires the
   same bytes back. The encoder refuses any value that fails the well-formedness
   predicate, so every predicate below is a rejection rule.

Process interface: `blind_financial_correction.exe --apply-correction-transition`
or `--assess-correction-reuse`. The request goes on stdin; the result comes on
stdout with exit code 0. On failure there is no stdout and stderr carries
`FINANCIAL_ERROR=<reason>`. Exit 72 means the transition input was too large or
failed to decode, 73 that the transition result failed to encode, 75 and 76 are
the same for reuse, and 64 is a usage error.

## 3. `BLFCMD02` request

| # | Field | Encoding | Well-formed |
|---|---|---|---|
| 1 | magic | 8 bytes `BLFCMD02` | exact |
| 2 | version | `u16` | = 2 |
| 3 | contract | `str` | = `RR/FINANCIAL/CORRECTION-TRANSITION/v1` (fields 1-3 fill bytes 0-48) |
| 4-7 | itemId, claimId, actionId, actorId | `str` ×4 | id |
| 8 | actorRole | `str` | role |
| 9 | currentAuthorityId | `str` | id |
| 10 | currentAuthorityEpoch | `u64` | epoch |
| 11 | currentAuthorityDigest | `d64` | |
| 12 | expectedRevision | `u64` | revision |
| 13 | evaluationId | `str` | id |
| 14 | evaluationResultDigest | `d64` | |
| 15 | decisionAtMs | `u64` | time |
| 16 | ownerNowMs | `u64` | time |
| 17 | actionLookup | [3.1](#31-actionlookup) | |
| 18 | queries | 3 × [3.2](#32-queryobservation), in the order ACTION_ID, DETERMINATION_ID, EVALUATION_CONSUMED | the order is not checked on the command, only on an ACCEPTED result |
| 19 | currentEventSequence | `u64` | sequence |
| 20 | previousHistoryHead | `d64` | |
| 21 | correctionPaid | `list<str actionId, u64 paidCents>` | canonical id list; each paidCents 1..2^63-1 |
| 22 | currentInput | `blob` holding a `BLFIN02` value ([6.1](#61-blfin02-financial-input)) | decodes on its own |
| 23 | currentReceipt | `blob` holding a receipt ([3.3](#33-evaluation-receipt)) | nothing left over inside the blob |

### 3.1 ActionLookup

`u8` tag: **1** absent, **3** conflicting (neither has a body), or **2** existing,
followed by:

`str actionId, str actionObligationId, str determinationId, str determinationObligationId,
str actionKind, str claimId, str actorId, str actorRole, str authorityId, u64 authorityEpoch,
d64 authorityDigest, u8 decision, str inputEvaluationId, d64 inputEvaluationResultDigest,
u64 expectedRevision, u64 decidedAtMs`

The ids must be ids, actorRole a role, the epoch an epoch, expectedRevision a revision
and decidedAtMs a time. The decision tag is 1 or 2 ([table 5](#5-tag-tables)).

### 3.2 QueryObservation

`u8 predicate (1 ACTION_ID, 2 DETERMINATION_ID, 3 EVALUATION_CONSUMED), str subject,
bool complete, u64 matchCount, opt<str> resultIdentity, u64 versionSequence,
d64 versionHead`

The subject must be an id and matchCount ≤ 1. resultIdentity is absent exactly
when matchCount = 0, and is an id otherwise. versionSequence must be a sequence.

### 3.3 Evaluation receipt

The receipt is contract `RR/FINANCIAL/EVALUATION-RECEIPT/v1` (no magic).
`DecisionPackage/Codec.lean` lines 262-271 define it, and
`DecisionPackage/Projection.lean` lines 102-129 give its well-formedness.

`str contractVersion (= RR/FINANCIAL/EVALUATION-RECEIPT/v1);
scope: str stateId, str deploymentId, str programId, str periodId, str currency (all ids);
pack: str packId (id), u64 version (1..10,000), d64 digest;
list<str evidenceId (id), d64 recordDigest> evidenceBindings;
opt<d64> inputSnapshotDigest;
u64 authorityEpoch (epoch), d64 authorityDigest;
result: str evaluationId, str obligationId (ids), u64 revision (revision), u64 ruleVersion (1..10,000),
list<str> evidenceIds (ids), str authorityId (id), u64 evaluatedAtMs (time),
u64 owedCents, claimedAdjustmentCents, lawfulAdjustmentCents, receivedCashCents, shortfallCents, overageCents (amounts),
bool cashSatisfied, amountSatisfied, timely, reportingComplete,
str verificationStatus, caseStatus, deliveryStatus (text);
d64 resultDigest, d64 receiptDigest, d64 evaluationResultDigest`

Cross-field rules: evaluationResultDigest must equal resultDigest, and the binding
ids, in order, must equal `result.evidenceIds`. An absent inputSnapshotDigest is
well-formed on the wire; the transition then rejects with reason 19.

## 4. `BLFCRES3` result

| # | Field | Encoding |
|---|---|---|
| 1 | magic | 8 bytes `BLFCRES3` |
| 2 | version | `u16` = 3 |
| 3 | status | `u8`: 1 ACCEPTED, 2 DUPLICATE, 3 REJECTED |
| 4 | contract | `str` = `RR/FINANCIAL/CORRECTION-TRANSITION/v1` (fields 1-4 fill bytes 0-49) |
| 5 | rejectReason | `opt<u8 reason>` |
| 6 | explanation | `u8 code; opt<u8 transitionKind>; opt<u8 reason>; opt<u8 requirement>; opt<str> claimId; opt<str> actionId; opt<str> inputEvaluationId; opt<u64> expectedRevision; opt<u64> resultingRevision` |
| 7 | actionId | `opt<str>` |
| 8 | determinationId | `opt<str>` |
| 9 | mutation | `opt<Mutation>` (4.1) |

### 4.1 Mutation (present only when ACCEPTED)

In order:

1. `u8 transitionKind`, which must be 1.
2. `list<u8 effect>`, which must be exactly `[1,2,3,4,5,6,7]`.
3. **dependencies**: `str artifactContract, u64 artifactVersion, str authorityId,
   u64 authorityEpoch, d64 authorityDigest, str controlPackId, u64 controlPackVersion,
   d64 controlPackDigest, str inputEvaluationId, d64 inputEvaluationResultDigest,
   u64 inputEvaluationRevision, u64 inputEvaluationEvaluatedAtMs,
   d64 inputEvaluationSnapshotDigest, u64 inputShortfallCents, u64 decisionAtMs,
   u64 ownerNowMs`, then a claimBefore **Claim** ([6.1](#61-blfin02-financial-input)),
   `list<str evidenceId, d64 recordDigest> supportingEvidence`, 3 × QueryObservation,
   `u64 currentEventSequence, d64 previousHistoryHead`, and
   `list<str actionId, u64 paidCents> correctionPaid`.
4. **followUps**: `str actionId, str outboxActionId, str caseId,
   str resultingEvaluationId, u64 eventSequence`.
5. `blob resultingInput` (`BLFIN02`) and `blob resultingResult` (`BLFRES02`, [6.2](#62-blfres02-financial-result)).
   Each must decode on its own.
6. **Determination** and **Action** records ([6.1](#61-blfin02-financial-input)).
7. The case: a **Case** record, then `str contractualAccountability,
   bool amountSatisfied, bool reportingComplete,
   bool deliveryAcknowledgedOrNotRequired, bool inserted`.
8. The outbox: `str actionId, u8 actionStatus, u64 attempt,
   opt<str> acknowledgmentReference, u64 updatedAtMs`.
9. The event: `u64 sequence, d64 previousHead, str aggregateType, str aggregateId,
   str kind, u64 beforeRevision, u64 afterRevision, u64 committedAtMs`.

### 4.2 Shape rules (the `resultWellFormed` predicate)

The full predicate is `Codec.lean` lines 649-812. Any other combination is rejected.

- **REJECTED**: rejectReason is present and equals explanation.rejectReason.
  The explanation code is 3 and the transition is absent. The requirement is
  present and has the **same tag number** as the reason. actionId,
  determinationId, mutation and resultingRevision are absent. The optional
  explanation ids must be ids, and expectedRevision a revision.
- **DUPLICATE**: rejectReason is absent, the code is 2, the transition is 1, and
  the explanation reason and requirement are absent. actionId is an id and
  determinationId is exactly `determination:` + actionId. The explanation carries
  claimId (an id), actionId equal to actionId, inputEvaluationId (an id) and
  expectedRevision (a revision). resultingRevision and mutation are absent.
- **ACCEPTED**: rejectReason is absent, the code is 1, the transition is 1, and
  the explanation reason and requirement are absent. actionId, determinationId
  and mutation are present, plus these groups of rules:
  - **Explanation**: it mirrors claimId, actionId, inputEvaluationId,
    expectedRevision and resultingRevision from the mutation.
  - **Resulting result**: it matches the resulting input's context, authority and
    pack, with afterRevision = beforeRevision + 1.
  - **Determination**: decision 2, amount 1..2^63-1, resultingRevision =
    expectedRevision + 1, and decidedAt = dependencies.decisionAtMs.
  - **Action**: kind `CORRECTION_PAYMENT_REQUEST` with status READY, its
    currency, revision = the determination's resultingRevision, and
    createdAt = event.committedAtMs. Its amount is
    `min(determination.amountCents, inputShortfallCents − outstanding)`,
    where outstanding sums, over the resulting input's other
    `CORRECTION_PAYMENT_REQUEST` actions that are not CANCELLED,
    `amount − paid` (floored at 0), and the whole subtraction is floored at 0.
    inputShortfallCents is 1..2^63-1.
  - **Outbox**: READY, attempt 0, no acknowledgment reference, and
    updatedAtMs = event.committedAtMs.
  - **Event**: sequence = currentEventSequence + 1, previousHead =
    previousHistoryHead, aggregateType `OBLIGATION`, aggregateId = the
    obligation id, kind `OFFSET_REJECTED_CORRECTION_AUTHORIZED`, before and
    after revision equal to the determination's, and committedAtMs =
    max(decisionAtMs, ownerNowMs).
  - **Case**: caseId `case:` + the obligation id, reason `CORRECTION_REQUIRED`,
    nextActionOwner `CASE_OWNER`, dueAt = claimBefore.deadlineAt, status = the
    resulting result's caseStatus, accountability `PROGRAM_ACCOUNTABILITY`, and
    all three completion booleans true.
  - **FollowUps**: resultingEvaluationId `evaluation:<obligationId>:r<afterRevision>`.
  - **Dependencies**: artifactContract is the contract and artifactVersion = 1.
    inputEvaluationId is `evaluation:<obligationId>:r<inputEvaluationRevision>`,
    with inputEvaluationRevision = expectedRevision and evaluatedAt ≤ decisionAt.
    claimBefore is CLAIMED and the same claim appears REJECTED in the resulting
    input. The supporting evidence includes claimBefore's evidence, and its ids
    equal the determination's supportingEvidenceIds.
  - **Queries**: the three queries have predicates 1, 2, 3 in order and subjects
    actionId, determinationId and inputEvaluationId. Each is complete, with
    matchCount 0 and no result identity, and each is at currentEventSequence and
    previousHistoryHead.
  - **correctionPaid**: a canonical id list with positive amounts.

## 5. Tag tables

Use these numbers, **not** the declaration order in `Types.lean`. Reasons 17-19 are
declared in a different order from their wire tags.

| Tag | Reject reason | Unresolved requirement (same tag) |
|---|---|---|
| 1 | INVALID_REQUEST | VALID_COMMAND |
| 2 | INVALID_INPUT | WELL_FORMED_FINANCIAL_SNAPSHOT |
| 3 | SHADOW_READ_ONLY | ACTIONABLE_OWNER_MODE |
| 4 | SCOPE_MISMATCH | REQUEST_SCOPE_MATCH |
| 5 | AUTHORITY_STALE | CURRENT_AUTHORITY_MATCH |
| 6 | ACTOR_UNAUTHORIZED | AUTHORIZED_ACTOR_ROLE |
| 7 | CONTROL_PACK_REJECTED | APPROVED_CONTROL_PACK |
| 8 | REVISION_CONFLICT | CURRENT_REVISION_MATCH |
| 9 | EVALUATION_CONFLICT | CURRENT_EVALUATION_BINDING |
| 10 | EVALUATION_CONSUMED | UNIQUE_EVALUATION_USE |
| 11 | EVIDENCE_COVERAGE | CLAIM_EVIDENCE_COVERAGE |
| 12 | CLAIM_MISSING | CLAIM_EXISTS_IN_SCOPE |
| 13 | CLAIM_NOT_CLAIMED | CLAIM_IS_CLAIMED |
| 14 | ACTION_CONFLICT | ACTION_IDENTITY_MATCH |
| 15 | DETERMINATION_CONFLICT | DETERMINATION_ID_AVAILABLE |
| 16 | CHRONOLOGY | RECEIPT_PRECEDES_DECISION |
| 17 | CAPACITY | HISTORY_CAPACITY_AVAILABLE |
| 18 | QUERY_OBSERVATION_INVALID | COMPLETE_QUERY_OBSERVATIONS |
| 19 | INPUT_SNAPSHOT_MISSING | INPUT_SNAPSHOT_DIGEST_AVAILABLE |
| 20 | NO_SHORTFALL | POSITIVE_SHORTFALL |
| 21 | NO_REQUESTABLE_BALANCE | UNREQUESTED_SHORTFALL |

| Enumeration | Tags |
|---|---|
| explanation code | 1 CORRECTION_AUTHORIZED, 2 EXACT_RETRY, 3 REJECTED |
| transition kind | 1 OFFSET_REJECTED_CORRECTION_AUTHORIZED |
| effect | 1 DETERMINATION_RECORDED, 2 CLAIM_REJECTED, 3 CASE_UPSERTED, 4 ACTION_CREATED, 5 OUTBOX_CREATED, 6 PROJECTION_RECOMPUTED, 7 EVENT_APPENDED |
| decision | 1 OFFSET_AUTHORIZED, 2 OFFSET_REJECTED_CORRECTION_AUTHORIZED |
| claim status | 1 CLAIMED, 2 AUTHORIZED, 3 REJECTED |
| action / outbox status | 1 READY, 2 ACKNOWLEDGED, 3 CANCELLED |
| case status | 1 OPEN, 2 AUTHORIZED, 3 CORRECTION_REQUIRED, 4 ACTIONED, 5 RESOLVED |
| owner mode | 1 LIVE, 2 SHADOW, 3 TEST |
| provenance | 1 ROOT, 2 CONTINUITY_RESTORE |
| pack status | 1 APPROVED, 2 REVOKED |
| payment status | 1 ACTIVE, 2 REVERSED |
| verification status | 1 MISSING_EVIDENCE, 2 SUPPORTED, 3 CONFLICT_VISIBLE |
| delivery status | 1 NONE, 2 READY, 3 ACKNOWLEDGED, 4 CANCELLED |

## 6. Embedded financial formats

Layouts come from `lean/BlindLedger/Financial/Codec.lean`. Well-formedness is
`financialInputWellFormed` (`Types.lean` line 660) and `financialResultWellFormed`
(line 721). Those are semantic rules (scope agreement, canonical id lists, evidence
coverage and more), and they are **not restated here**. A decoder must apply them.

### 6.1 `BLFIN02` financial input

The magic is **7 bytes**, `BLFIN02`. It is followed by Context, Authority, ControlPack,
Obligation, `u64 beforeRevision`, `u64 evaluatedAt`, and then `list<Payment>`,
`list<Claim>`, `list<Determination>`, `list<Evidence>`, `list<Conflict>`,
`list<Case>` and `list<Action>`. Nothing may follow.

- **Context**: `str ownerId, u8 mode, u8 provenance, str stateId, str deploymentId,
  str programId, str periodId, str populationId, str itemId, str obligationId,
  str currency`
- **Authority**: `str authorityId, u64 epoch, d64 digest, bool syntheticOnly`, then
  `list<str actorId, list<str> roles>`
- **ControlPack**: `str packId, str stateId, str deploymentId, str programId,
  str periodId, str currency, u64 version, list<str> sourceRefs, u64 effectiveStart,
  u64 effectiveEnd, u64 recordedAt, u64 approvedAt, str calculationRuleId,
  str adjustmentRuleId, list<str> authorizedRoles, list<str> expectedTests,
  d64 digest, u8 packStatus`
- **Obligation**: `str populationId, str itemId, str obligationId, u64 owedCents,
  u64 dueAt, u64 ruleVersion, bool reportingComplete`
- **Payment**: `str paymentId, str obligationId, str itemId, str evidenceId,
  str commonOriginId, u64 amountCents, u64 eventAt, opt<str> reversalEvidenceId,
  u8 paymentStatus`
- **Claim**: `str claimId, str obligationId, str evidenceId, u64 amountCents,
  str ownerRole, u64 deadlineAt, u8 claimStatus`
- **Determination**: `str determinationId, str obligationId, str claimId, str actorId,
  str actorRole, str authorityId, u64 authorityEpoch, d64 authorityDigest, u8 decision,
  u64 amountCents, list<str> supportingEvidenceIds, u64 expectedRevision,
  u64 resultingRevision, u64 decidedAt`
- **Evidence**: `str evidenceId, str obligationId, str itemId, str kind,
  str commonOriginId, str sourceId, str sourceVersion, str localRef, u64 applicableAt,
  u64 eventAt, u64 receivedAt, opt<u64> amountCents, opt<str> reversalOf,
  opt<str> supersedes`
- **Conflict**: `str conflictId, str obligationId, str commonOriginId,
  str existingPaymentId, str candidateEvidenceId, u64 existingAmountCents,
  u64 candidateAmountCents, str reason, u64 visibleAt`
- **Case**: `str caseId, str obligationId, str reason, str nextActionOwner, u64 dueAt,
  u8 caseStatus, u64 updatedAt`
- **Action**: `str actionId, str obligationId, opt<str> determinationId, str kind,
  u64 amountCents, str currency, u64 revision, u8 actionStatus, d64 payloadDigest,
  u64 createdAt`

### 6.2 `BLFRES02` financial result

The magic is 8 bytes, `BLFRES02`, followed by:

`Context, str authorityId, u64 authorityEpoch, d64 authorityDigest, str packId,
d64 packDigest, u64 beforeRevision, u64 afterRevision, u64 evaluatedAt,
u64 ruleVersion, list<str> evidenceIds, opt<u64> completionAt, u64 owedCents,
u64 claimedAdjustmentCents, u64 lawfulAdjustmentCents, u64 receivedCashCents,
u64 shortfallCents, u64 overageCents, bool cashSatisfied, bool amountSatisfied,
bool timely, bool reportingComplete, u8 verificationStatus, u8 caseStatus,
u8 deliveryStatus`

Nothing may follow.

## 7. Reuse: `BLFCRU02` request and `BLFCRV02` assessment

The request (`ReuseCodec.lean` lines 88-136) is:

`8 bytes BLFCRU02, u16 = 2, str = RR/FINANCIAL/CORRECTION-REUSE/v1,
blob acceptedResult (BLFCRES3, must itself decode), blob currentInput (BLFIN02),
blob currentReceipt (3.3), opt<Determination> currentDetermination,
opt<outbox as in 4.1 step 8> currentOutbox, 3 × QueryObservation,
u64 currentEventSequence (sequence), d64 currentHistoryHead, u64 currentOwnerNowMs (time)`

Each blob is at most 8,388,608 bytes and the total at most 25,165,824.
A present determination needs its ids, role and digest well-formed. A present
outbox needs an id actionId, attempt ≤ 10,000 and a time updatedAtMs. The
assessment of whether the prior correction still holds is Lean's
(`Reuse.lean`), not the codec's.

The assessment (`ReuseCodec.lean` lines 293-357) is:

`8 bytes BLFCRV02, u16 = 2, str contract, u8 calculationValidity (1 VALID, 2 INVALID),
opt<u8 calculationReason>, u8 humanApprovalValidity (1, 2), opt<u8 approvalReason>,
u8 localExecutionPermission (1 ALLOWED, 2 DENIED), opt<u8 executionDenial>,
u8 deadlineStatus (0 none, 1 BEFORE_DEADLINE, 2 DEADLINE_REACHED),
bool unrelatedWatermarkAdvanced, bool externalDispatchPermitted`

| Enumeration | Tags |
|---|---|
| calculation reason | 1 ACCEPTED_TRANSITION_REQUIRED, 2 QUERY_OBSERVATION_INVALID, 3 RELEVANT_FINANCIAL_FACT_CHANGED, 4 EVIDENCE_BINDING_CHANGED, 5 CURRENT_RECEIPT_INVALID, 6 CURRENT_RESULT_CHANGED |
| approval reason | 1 ACCEPTED_TRANSITION_REQUIRED, 2 DETERMINATION_MISSING, 3 DETERMINATION_CHANGED |
| execution denial | 1 CALCULATION_INVALID, 2 HUMAN_APPROVAL_INVALID, 3 SHADOW_MODE, 4 AUTHORITY_STALE, 5 ACTOR_NOT_AUTHORIZED, 6 CONTROL_PACK_NOT_APPROVED, 7 ACTION_MISSING, 8 ACTION_CHANGED, 9 ACTION_NOT_READY, 10 OUTBOX_MISSING, 11 OUTBOX_CHANGED, 12 OUTBOX_NOT_READY |

The assessment must also satisfy these rules:

- Each reason is present exactly when its validity is INVALID (or DENIED).
- ALLOWED requires both validities to be VALID.
- `unrelatedWatermarkAdvanced` requires VALID, VALID and ALLOWED.
- `externalDispatchPermitted` must be false.

## 8. Worked examples (pinned vectors)

The offsets below were decoded by hand from the pinned files, using only the
layout above. All four pinned files parse to the end, with nothing left over:
the request (3,359 bytes), the result (5,099), the reuse request (9,204) and
the reuse result (53). Notation: `NNx64` means a digest of 64 bytes, all equal
to 0xNN.

`request.bin`, first 0x60 bytes:

```
00000000: 424c 4643 4d44 3032 0002 0025 5252 2f46  BLFCMD02...%RR/F
00000010: 494e 414e 4349 414c 2f43 4f52 5245 4354  INANCIAL/CORRECT
00000020: 494f 4e2d 5452 414e 5349 5449 4f4e 2f76  ION-TRANSITION/v
00000030: 3100 0669 7465 6d2d 6800 0e63 6c61 696d  1..item-h..claim
00000040: 3a68 3a6f 6666 7365 7400 1661 6374 696f  :h:offset..actio
00000050: 6e3a 636f 7272 6563 7469 6f6e 3a68 3a76  n:correction:h:v
```

```
offset len  field                              value
     0   8  magic                              BLFCMD02
     8   2  version                            0x0002
    10  39  contract                           0x0025 + 'RR/FINANCIAL/CORRECTION-TRANSITION/v1'
    49   8  itemId                             'item-h'
    57  16  claimId                            'claim:h:offset'
    73  24  actionId                           'action:correction:h:v1'
    97  20  actorId                            'synthetic-official'
   117  18  actorRole                          'FINANCE_DECISION'
   135  24  currentAuthorityId                 'synthetic-authority-v1'
   159   8  currentAuthorityEpoch              1
   167  64  currentAuthorityDigest             00x64
   231   8  expectedRevision                   4
   239  43  evaluationId                       'evaluation:obligation:item-h:period-01:r4'
   282  64  evaluationResultDigest             a5x64
   346   8  decisionAtMs                       1774922400010
   354   8  ownerNowMs                         1774922400020
   362   1  actionLookup                       1 absent
   363   1  query[0].predicate                 1 ACTION_ID
   364  24  query[0].subject                   'action:correction:h:v1'
   388   1  query[0].complete                  1
   389   8  query[0].matchCount                0
   397   1  query[0].resultIdentity            0 absent
   398   8  query[0].versionSequence           10
   406  64  query[0].versionHead               2ax64
   470 247  query[1], query[2]                 DETERMINATION_ID 'determination:action:correction:h:v1',
                                               EVALUATION_CONSUMED 'evaluation:obligation:item-h:period-01:r4'; same shape
   717   8  currentEventSequence               10
   725  64  previousHistoryHead                2ax64
   789   2  correctionPaid.count               0
   791   4  currentInput length                1610
   795 1610 currentInput                       BLFIN02 ...
  2405   4  currentReceipt length              950
  2409  36  receipt.contractVersion            'RR/FINANCIAL/EVALUATION-RECEIPT/v1'
  2445  89  receipt.scope                      fixture-state, fixture-rightrail, fixture-provider-payment,
                                               fixture-2026-period-01, USD
  2534 105  receipt.pack                       'control-pack:fixture-2026-01:v1', 1, 00x64
  2639 162  receipt.evidenceBindings           2: evidence:cash 44x64, evidence:offset 44x64
  2801  65  receipt.inputSnapshotDigest        present, 5bx64
  2866  72  receipt.authority                  epoch 1, 00x64
  2938 229  receipt.result                     r4, rule 1, owed 10000000, claimed 300000, received 9700000,
                                               shortfall 300000, SUPPORTED / OPEN / NONE
  3167 192  receipt digests                    result a5x64, receipt 5ax64, evaluationResult a5x64
  3359      end, nothing left over
```

`result.expected.bin`:

```
offset len  field                              value
     0   8  magic                              BLFCRES3
     8   2  version                            0x0003
    10   1  status                             1 ACCEPTED
    11  39  contract                           'RR/FINANCIAL/CORRECTION-TRANSITION/v1'
    50   1  rejectReason                       0 absent
    51   1  explanation.code                   1 CORRECTION_AUTHORIZED
    52   2  explanation.transition             1, 1
    54   2  explanation.reason, requirement    0, 0
    56  17  explanation.claimId                1 + 'claim:h:offset'
    73  25  explanation.actionId               1 + 'action:correction:h:v1'
    98  44  explanation.inputEvaluationId      1 + 'evaluation:obligation:item-h:period-01:r4'
   142  18  explanation.expected/resulting     1 + 4, 1 + 5
   160  25  actionId                           1 + 'action:correction:h:v1'
   185  39  determinationId                    1 + 'determination:action:correction:h:v1'
   224   1  mutation                           1 present
   225   1  transitionKind                     1
   226   9  effects                            count 7: 01 02 03 04 05 06 07
   235 1140 dependencies                       contract, v1, authority, pack, evaluation r4,
                                               shortfall 300000, claimBefore CLAIMED 300000, 2 evidence,
                                               3 queries at sequence 10 / 2ax64, correctionPaid count 0
  1375 133  followUps                          action, action, 'case:obligation:item-h:period-01',
                                               'evaluation:obligation:item-h:period-01:r5', 11
  1508 2225 resultingInput                     length 2221, BLFIN02 ...
  3733 509  resultingResult                    length 505, BLFRES02 ...
  4242 284  determination                      decision 2, amount 300000, r4 -> r5, decidedAt ...010
  4526 214  action                             CORRECTION_PAYMENT_REQUEST, 300000 USD, r5, READY, createdAt ...020
  4740 141  case                               CORRECTION_REQUIRED, CASE_OWNER, status 3, PROGRAM_ACCOUNTABILITY, 1 1 1 1
  4881  42  outbox                             READY, attempt 0, no reference, ...020
  4923 176  event                              sequence 11, prev 2ax64, OBLIGATION, r4 -> r5, ...020
  5099      end, nothing left over
```

Here the action amount is min(300000, 300000 − 0) = 300000.

`reuse-result.expected.bin` (complete):

```
424C4643525630320002 0020 52522F...2F7631  BLFCRV02, v2, contract (34 bytes, to offset 44)
01 00 | 01 00 | 01 00 | 02 | 00 | 00        VALID, -, VALID, -, ALLOWED, -, DEADLINE_REACHED, false, false
```

## Open discrepancies

These were found by reading the code. None has been run.

**A. Money behaviour (escalate to rr-core; not changed here)**

1. The rule for what earlier correction requests still ask for differs. Lean
   (`outstandingCorrectionCents`, `Types.lean`) skips CANCELLED
   `CORRECTION_PAYMENT_REQUEST` actions. The Owner's commit binding
   (`app/right_rail_financial_owner.py`, `correction_action_binding`, around line
   4549) sums every such row whatever its status. Nothing sets CANCELLED today,
   so the paths cannot currently disagree. Once cancel lands, the Owner would
   refuse Lean's larger amount: the command fails closed rather than paying the
   wrong amount.

**B. Result decoding: Lean `decodeCorrectionTransitionResult` vs Python `decode_correction_transition_result`**

2. For ACCEPTED, Python requires determinationId = `determination:` + actionId.
   The Lean codec requires this only for DUPLICATE. The Lean transition always
   emits that form, but the codec would admit another.
3. Python requires the resulting BLFRES02's `evaluatedAt = event.committedAtMs`
   and `deliveryStatus = READY`. The Lean codec requires neither.
4. The Python decoder does not itself enforce several Lean rules:
   - It checks only the resulting BLFIN02's magic and does not decode or
     well-form check it. The Owner later compares it to its own re-encoding
     (`right_rail_financial_semantic_adapter.py` line 2130).
   - It skips the resulting result's context, authority and pack agreement with
     the resulting input.
   - It skips the action-amount formula, which the Owner re-checks at commit
     under the rule in A1.
   - It skips `committedAtMs = max(decisionAt, ownerNow)`, the
     `evaluation:<obligation>:r<n>` form of inputEvaluationId,
     `evaluatedAt ≤ decisionAt`, the rejected claim in the resulting input, and
     supporting evidence covering claimBefore's evidence.
   - It skips the correctionPaid order, uniqueness and positivity; the Owner
     compares the list for equality.
   - It skips the revision bounds (≤ 10,000).

   Lead audit (2026-09-28, by reading `app/right_rail_financial_owner.py`
   4458-4840) found that every one of these is covered at commit, so the Owner
   does not depend on the Python decoder for them:
   - The Owner derives the determination id, `evaluation:<obligation>:r<n>`,
     the resulting revision (expected + 1) and the mutation time (the max rule)
     itself, and writes only those.
   - It requires the action amount to match the rule in A1.
   - It requires correctionPaid to equal its own SQL-ordered list.
   - `bind_resulting_state` re-encodes the post-write snapshot and requires it
     to equal the resulting BLFIN02 bytes, then binds the result context.
   - Before COMMIT, the independent checker (`verify_obligation_connection`,
     line 4833) recomputes the written evaluation from the exact rows.

   A replacement engine that violates one of these rules is refused before
   anything is committed.
5. In DUPLICATE and REJECTED results, Python accepts an explanation
   expectedRevision up to 2^63-1, where Lean allows at most 10,000.

**C. Request encoding: Python `encode_correction_transition_request` vs Lean decoder**

When Python is laxer, as in items 6-8, Lean refuses the bytes (exit 72, fail
closed).

6. Python emits values Lean rejects:
   - authority epoch 0;
   - receipt pack version 0 or above 10,000;
   - receipt revision above 10,000;
   - ruleVersion 0 or above 10,000;
   - currentEventSequence, query versionSequence or lookup expectedRevision
     above 10,000;
   - a receipt contractVersion other than the constant (Python does not check it);
   - a scope currency that is 1..128 bytes of text but not an id.
7. Python does not check that query matchCount agrees with resultIdentity, and
   does not check that the receipt's binding ids equal `result.evidenceIds`.
8. Python does not check the order, uniqueness or positivity of correctionPaid.
   It relies on the SQL `ORDER BY` and on `SUM` over active payments.
9. Python is stricter in these places:
   - The receipt's evidence lists must be strictly ascending; Lean requires only
     that the two lists are equal.
   - The receipt status strings must be ids; Lean allows 1..512-byte text.
   - The existing-lookup decision must be tag 2; Lean allows 1 or 2.
   - inputSnapshotDigest is always present, so reason 19 (INPUT_SNAPSHOT_MISSING)
     cannot occur for Owner-built requests.

**D. Specification gaps**

10. Python has no reuse (`BLFCRU02` / `BLFCRV02`) codec; a test compares the
    reuse vector bytes only. The reuse format therefore has one implementation.
11. `ARCHITECTURE.md` records that codec round-trip and trailing-byte laws are
    proved only for admissible values, and that nothing yet proves every value
    Lean emits is admissible.
12. The semantic well-formedness of the embedded BLFIN02 and BLFRES02 (section 6)
    exists only as Lean predicates and has no prose specification.
