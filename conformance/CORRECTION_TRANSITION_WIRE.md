# Correction transition wire formats

Contract `RR/FINANCIAL/CORRECTION-TRANSITION/v1`: request `BLFCMD03` (v3),
result `BLFCRES3` (v3). Contract `RR/FINANCIAL/CORRECTION-REUSE/v1`: request
`BLFCRU02`, assessment `BLFCRV02` (v2 each).

Normative source: Lean codec at base commit `d5853b1`,
`lean/BlindLedger/Financial/CorrectionTransition/{Types,Codec,ReuseCodec,Runtime}.lean`,
primitives in `lean/BlindLedger/Financial/Codec.lean`, receipt codec in
`lean/BlindLedger/Financial/DecisionPackage/Codec.lean`. Pinned engine:
`artifacts/engine-evaluator/PROVENANCE.md`. Where this page and Lean
disagree, Lean wins. Python consumer: `app/right_rail_financial_engine.py`;
divergences in [Open discrepancies](#open-discrepancies).

Synthetic, non-PHI, nonpayment: `proofSuiteId=null`, `production_usable=false`,
`activation=false`.

## 1. Primitives

Unsigned big-endian, unpadded. In field lists a type applies to each
following name until the next type.

| Notation | Bytes | Reject if |
|---|---|---|
| `u8`,`u16`,`u32`,`u64` | 1,2,4,8 | too few bytes left |
| `str` | `u16` len + UTF-8 | len > remaining, or invalid UTF-8 |
| `d64` | 64 raw bytes | (digest; only length checked) |
| `bool` | `u8` | not 0/1 |
| `opt<T>` | `u8` tag, `T` if 1 | tag not 0/1 |
| `list<T>` | `u16` count + items | count > 10,000 |
| `blob` | `u32` len + bytes | len > 8,388,608 or > remaining |
| tag | `u8` | value not in the table below |

`u64` parses its full range; bounds are well-formedness.

Value classes (`Types.lean` 19-28, 313-341): **id** 1..128B, `[A-Za-z0-9][A-Za-z0-9._:-]*`.
**role** 1..64B, `[A-Z][A-Z0-9_]*`. **text** 1..512B, no NUL. **amount**/**time**
≤ 2^63-1. **revision**/**sequence** ≤ 10,000. **epoch** 1..2^63-1. **canonical id
list**: ≤ 10,000 ids, strictly ascending (Lean code-point order = byte order for ids).

## 2. Decoding

Accept iff: (1) total length ≤ 8,388,608 (reuse request: 25,165,824); (2)
magic, `u16` version, contract string exact; (3) every field parses per §3-6,
incl. nested blobs, **no byte left over** at top level or inside the receipt
blob; (4) value well-formed: re-encode it and require the same bytes (the
encoder refuses values failing the predicate, so every predicate below is a
rejection rule).

Process: the evaluator worker (`artifacts/engine-evaluator/`), one frame in,
tag byte then body out: 00 + `BLFCRES3`; 01 = too large/decode fail; 03 =
encode fail. The retired one-shot exe (git 99ec957) answered the same on stdin
and stdout, exit 0, 72 or 73, and also served reuse (75/76, retired with it).

## 3. `BLFCMD03` request

| # | Field | Encoding | Well-formed |
|---|---|---|---|
| 1 | magic | 8B `BLFCMD03` | exact |
| 2 | version | `u16` | = 3 |
| 3 | contract | `str` | `RR/FINANCIAL/CORRECTION-TRANSITION/v1` (1-3 fill bytes 0-48) |
| 4-7 | itemId, claimId, actionId, actorId | `str`×4 | id |
| 8 | actorRole | `str` | role |
| 9 | currentAuthorityId | `str` | id |
| 10 | currentAuthorityEpoch | `u64` | epoch |
| 11 | currentAuthorityDigest | `d64` | |
| 12 | expectedRevision | `u64` | revision |
| 13 | evaluationId | `str` | id |
| 14 | evaluationResultDigest | `d64` | |
| 15 | decisionAtMs | `u64` | time |
| 16 | ownerNowMs | `u64` | time |
| 17 | actionLookup | §3.1 | |
| 18 | queries | 3×§3.2, order ACTION_ID, DETERMINATION_ID, EVALUATION_CONSUMED | order checked only on ACCEPTED result |
| 19 | currentEventSequence | `u64` | sequence |
| 20 | previousHistoryHead | `d64` | |
| 21 | paymentLinks | `list<str paymentId, str actionId>` | strictly ascending paymentId (else decode fails); each a payment row of the input, actionId a correction request of the input (else INVALID_INPUT); Lean derives paid-so-far from the active rows |
| 22 | currentInput | `blob`→`BLFIN02` (§6.1) | decodes standalone |
| 23 | currentReceipt | `blob`→receipt (§3.3) | nothing left over inside |

### 3.1 ActionLookup

`u8` tag (1 absent, 3 conflicting — neither has a body,
2 existing) then `str actionId, actionObligationId, determinationId,
determinationObligationId, actionKind, claimId, actorId, actorRole,
authorityId, u64 authorityEpoch, d64 authorityDigest, u8 decision, str
inputEvaluationId, d64 inputEvaluationResultDigest, u64 expectedRevision,
decidedAtMs`. Ids are ids, actorRole a role, authorityEpoch an epoch,
expectedRevision a revision, decidedAtMs a time, decision tag 1 or 2 (§5).

### 3.2 QueryObservation

`u8 predicate` (1 ACTION_ID, 2 DETERMINATION_ID, 3
EVALUATION_CONSUMED), `str subject` (id), `bool complete`, `u64 matchCount`
(≤1), `opt<str> resultIdentity` (absent iff matchCount=0, else id), `u64
versionSequence` (sequence), `d64 versionHead`.

### 3.3 Evaluation receipt

Contract `RR/FINANCIAL/EVALUATION-RECEIPT/v1`
(no magic; `DecisionPackage/Codec.lean` 262-271, well-formedness in
`Projection.lean` 102-129): `str contractVersion` (= that constant); scope:
`str stateId, deploymentId, programId, periodId, currency` (ids); pack: `str
packId` (id), `u64 version` (1..10,000), `d64 digest`; `list<str evidenceId
(id), d64 recordDigest> evidenceBindings`; `opt<d64> inputSnapshotDigest`;
`u64 authorityEpoch` (epoch), `d64 authorityDigest`; result: `str
evaluationId, obligationId` (ids), `u64 revision` (revision), `ruleVersion`
(1..10,000), `list<str> evidenceIds` (ids), `str authorityId` (id), `u64
evaluatedAtMs` (time), `u64 owedCents, claimedAdjustmentCents,
lawfulAdjustmentCents, receivedCashCents, shortfallCents, overageCents`
(amounts), `bool cashSatisfied, amountSatisfied, timely, reportingComplete`,
`str verificationStatus, caseStatus, deliveryStatus` (text); `d64
resultDigest, receiptDigest, evaluationResultDigest`. Cross-field:
evaluationResultDigest = resultDigest; binding ids in order =
`result.evidenceIds`. An absent inputSnapshotDigest is wire-well-formed; the
transition then rejects reason 19.

## 4. `BLFCRES3` result

| # | Field | Encoding |
|---|---|---|
| 1 | magic | 8B `BLFCRES3` |
| 2 | version | `u16` = 3 |
| 3 | status | `u8`: 1 ACCEPTED, 2 DUPLICATE, 3 REJECTED |
| 4 | contract | `str` = const (1-4 fill bytes 0-49) |
| 5 | rejectReason | `opt<u8 reason>` |
| 6 | explanation | `u8 code; opt<u8 transitionKind>; opt<u8 reason>; opt<u8 requirement>; opt<str> claimId; opt<str> actionId; opt<str> inputEvaluationId; opt<u64> expectedRevision; opt<u64> resultingRevision` |
| 7 | actionId | `opt<str>` |
| 8 | determinationId | `opt<str>` |
| 9 | mutation | `opt<Mutation>` (§4.1), present only if ACCEPTED |

### 4.1 Mutation

In order: (1) `u8 transitionKind` = 1. (2) `list<u8
effect>` = exactly `[1,2,3,4,5,6,7]`. (3) dependencies: `str
artifactContract, u64 artifactVersion, str authorityId, u64 authorityEpoch,
d64 authorityDigest, str controlPackId, u64 controlPackVersion, d64
controlPackDigest, str inputEvaluationId, d64 inputEvaluationResultDigest,
u64 inputEvaluationRevision, inputEvaluationEvaluatedAtMs, d64
inputEvaluationSnapshotDigest, u64 inputShortfallCents, decisionAtMs,
ownerNowMs`, then claimBefore **Claim** (§6.1), `list<str evidenceId, d64
recordDigest> supportingEvidence`, 3×QueryObservation, `u64
currentEventSequence, d64 previousHistoryHead`, `list<str actionId, u64
paidCents> correctionPaid`. (4) followUps: `str actionId, outboxActionId,
caseId, resultingEvaluationId, u64 eventSequence`. (5) `blob resultingInput`
(`BLFIN02`) and `blob resultingResult` (`BLFRES02`, §6.2), each decodes
standalone. (6) **Determination** and **Action** records (§6.1). (7) case: a
**Case** record, then `str contractualAccountability, bool amountSatisfied,
reportingComplete, deliveryAcknowledgedOrNotRequired, inserted`. (8) outbox:
`str actionId, u8 actionStatus, u64 attempt, opt<str>
acknowledgmentReference, u64 updatedAtMs`. (9) event: `u64 sequence, d64
previousHead, str aggregateType, aggregateId, kind, u64 beforeRevision,
afterRevision, committedAtMs`.

**§4.2 Shape rules** (`resultWellFormed`, `Codec.lean` 649-812 — any other
combination rejected):

- **REJECTED**: rejectReason present = explanation.rejectReason; code 3,
  transition absent; requirement present, same tag# as reason; actionId,
  determinationId, mutation, resultingRevision absent; explanation ids well-
  formed ids; expectedRevision a revision.
- **DUPLICATE**: rejectReason absent; code 2, transition 1, explanation
  reason & requirement absent; actionId an id; determinationId =
  `determination:`+actionId; explanation carries claimId (id), actionId
  (= actionId), inputEvaluationId (id), expectedRevision (revision);
  resultingRevision & mutation absent.
- **ACCEPTED**: rejectReason absent; code 1, transition 1, explanation reason
  & requirement absent; actionId, determinationId, mutation present, plus:
  explanation mirrors claimId/actionId/inputEvaluationId/expectedRevision/
  resultingRevision from the mutation; resulting result matches resulting
  input's context/authority/pack, afterRevision = beforeRevision+1;
  determination decision=2, amount 1..2^63-1, resultingRevision =
  expectedRevision+1, decidedAt = dependencies.decisionAtMs; action kind
  `CORRECTION_PAYMENT_REQUEST` status READY, currency, revision =
  determination.resultingRevision, createdAt = event.committedAtMs; amount =
  `min(determination.amountCents, max(inputShortfallCents − outstanding, 0))`,
  where outstanding sums, over the resulting input's other non-CANCELLED
  `CORRECTION_PAYMENT_REQUEST` actions, per-action `max(amount−paid, 0)`
  (inputShortfallCents 1..2^63-1); outbox READY, attempt 0, no ack
  reference, updatedAtMs = event.committedAtMs; event sequence =
  currentEventSequence+1, previousHead = previousHistoryHead, aggregateType
  `OBLIGATION`, aggregateId = obligation id, kind
  `OFFSET_REJECTED_CORRECTION_AUTHORIZED`, before/after revision =
  determination's, committedAtMs = `max(decisionAtMs, ownerNowMs)`; case
  caseId = `case:`+obligationId, reason `CORRECTION_REQUIRED`, nextActionOwner
  `CASE_OWNER`, dueAt = claimBefore.deadlineAt, status = resulting result's
  caseStatus, accountability `PROGRAM_ACCOUNTABILITY`, all 3 completion
  booleans true; followUps.resultingEvaluationId =
  `evaluation:<obligationId>:r<afterRevision>`; dependencies.artifactContract
  = contract, artifactVersion = 1, inputEvaluationId =
  `evaluation:<obligationId>:r<inputEvaluationRevision>` with
  inputEvaluationRevision = expectedRevision, evaluatedAt ≤ decisionAt,
  claimBefore CLAIMED and the same claim REJECTED in the resulting input,
  supportingEvidence includes claimBefore's evidence with ids =
  determination.supportingEvidenceIds; the 3 queries have predicates 1,2,3 in
  order, subjects actionId/determinationId/inputEvaluationId, each complete,
  matchCount 0, no resultIdentity, each at currentEventSequence/
  previousHistoryHead; dependencies.correctionPaid is Lean's derived list, a canonical id list with positive amounts.

## 5. Tag tables

Use these numbers, **not** `Types.lean` declaration order (reasons 17-19
differ).

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

Layouts: `lean/BlindLedger/Financial/Codec.lean`. Well-formedness is
`financialInputWellFormed` (`Types.lean` 660) / `financialResultWellFormed`
(721) — semantic rules (scope agreement, canonical id lists, evidence
coverage, more) **not restated here**; a decoder must apply them.

### 6.1 `BLFIN02` financial input

Magic 7B `BLFIN02`, then Context, Authority, ControlPack,
Obligation, `u64 beforeRevision, evaluatedAt`, `list<Payment>, list<Claim>,
list<Determination>, list<Evidence>, list<Conflict>, list<Case>,
list<Action>`. Nothing after.

- Context: `str ownerId, u8 mode, provenance, str stateId, deploymentId,
  programId, periodId, populationId, itemId, obligationId, currency`
- Authority: `str authorityId, u64 epoch, d64 digest, bool syntheticOnly,
  list<str actorId, list<str> roles>`
- ControlPack: `str packId, stateId, deploymentId, programId, periodId,
  currency, u64 version, list<str> sourceRefs, u64 effectiveStart,
  effectiveEnd, recordedAt, approvedAt, str calculationRuleId,
  adjustmentRuleId, list<str> authorizedRoles, expectedTests, d64 digest, u8
  packStatus`
- Obligation: `str populationId, itemId, obligationId, u64 owedCents, dueAt,
  ruleVersion, bool reportingComplete`
- Payment: `str paymentId, obligationId, itemId, evidenceId, commonOriginId,
  u64 amountCents, eventAt, opt<str> reversalEvidenceId, u8 paymentStatus`
- Claim: `str claimId, obligationId, evidenceId, u64 amountCents, str
  ownerRole, u64 deadlineAt, u8 claimStatus`
- Determination: `str determinationId, obligationId, claimId, actorId,
  actorRole, authorityId, u64 authorityEpoch, d64 authorityDigest, u8
  decision, u64 amountCents, list<str> supportingEvidenceIds, u64
  expectedRevision, resultingRevision, decidedAt`
- Evidence: `str evidenceId, obligationId, itemId, kind, commonOriginId,
  sourceId, sourceVersion, localRef, u64 applicableAt, eventAt, receivedAt,
  opt<u64> amountCents, opt<str> reversalOf, supersedes`
- Conflict: `str conflictId, obligationId, commonOriginId, existingPaymentId,
  candidateEvidenceId, u64 existingAmountCents, candidateAmountCents, str
  reason, u64 visibleAt`
- Case: `str caseId, obligationId, reason, nextActionOwner, u64 dueAt, u8
  caseStatus, u64 updatedAt`
- Action: `str actionId, obligationId, opt<str> determinationId, str kind,
  u64 amountCents, str currency, u64 revision, u8 actionStatus, d64
  payloadDigest, u64 createdAt`

### 6.2 `BLFRES02` financial result

Magic 8B, then `Context, str authorityId, u64
authorityEpoch, d64 authorityDigest, str packId, d64 packDigest, u64
beforeRevision, afterRevision, evaluatedAt, ruleVersion, list<str>
evidenceIds, opt<u64> completionAt, u64 owedCents, claimedAdjustmentCents,
lawfulAdjustmentCents, receivedCashCents, shortfallCents, overageCents, bool
cashSatisfied, amountSatisfied, timely, reportingComplete, u8
verificationStatus, caseStatus, deliveryStatus`. Nothing after.

## 7. Reuse: `BLFCRU02` request and `BLFCRV02` assessment

Request (`ReuseCodec.lean` 88-136): `8B BLFCRU02, u16=2, str=
RR/FINANCIAL/CORRECTION-REUSE/v1, blob acceptedResult (BLFCRES3, must itself
decode), blob currentInput (BLFIN02), blob currentReceipt (§3.3), opt<
Determination> currentDetermination, opt<outbox as §4.1 step 8>
currentOutbox, 3×QueryObservation, u64 currentEventSequence (sequence), d64
currentHistoryHead, u64 currentOwnerNowMs (time)`. Each blob ≤ 8,388,608, total
≤ 25,165,824. A present determination needs its ids/role/digest well-formed;
a present outbox needs id actionId, attempt ≤ 10,000, time updatedAtMs. The
prior-correction-still-holds assessment is Lean's (`Reuse.lean`), not the
codec's.

Assessment (`ReuseCodec.lean` 293-357): `8B BLFCRV02, u16=2, str contract, u8
calculationValidity (1 VALID, 2 INVALID), opt<u8 calculationReason>, u8
humanApprovalValidity (1,2), opt<u8 approvalReason>, u8
localExecutionPermission (1 ALLOWED, 2 DENIED), opt<u8 executionDenial>, u8
deadlineStatus (0 none, 1 BEFORE_DEADLINE, 2 DEADLINE_REACHED), bool
unrelatedWatermarkAdvanced, externalDispatchPermitted`.

| Enumeration | Tags |
|---|---|
| calculation reason | 1 ACCEPTED_TRANSITION_REQUIRED, 2 QUERY_OBSERVATION_INVALID, 3 RELEVANT_FINANCIAL_FACT_CHANGED, 4 EVIDENCE_BINDING_CHANGED, 5 CURRENT_RECEIPT_INVALID, 6 CURRENT_RESULT_CHANGED |
| approval reason | 1 ACCEPTED_TRANSITION_REQUIRED, 2 DETERMINATION_MISSING, 3 DETERMINATION_CHANGED |
| execution denial | 1 CALCULATION_INVALID, 2 HUMAN_APPROVAL_INVALID, 3 SHADOW_MODE, 4 AUTHORITY_STALE, 5 ACTOR_NOT_AUTHORIZED, 6 CONTROL_PACK_NOT_APPROVED, 7 ACTION_MISSING, 8 ACTION_CHANGED, 9 ACTION_NOT_READY, 10 OUTBOX_MISSING, 11 OUTBOX_CHANGED, 12 OUTBOX_NOT_READY |

Rules: each reason present iff its validity is INVALID/DENIED. ALLOWED
requires both validities VALID. `unrelatedWatermarkAdvanced` requires
VALID, VALID, ALLOWED. `externalDispatchPermitted` MUST be false.

## 8. Worked examples (pinned vectors)

The offsets below were decoded by hand from the pinned files, using only the
layout above. All four pinned files parse to the end, with nothing left
over: the request (3,359 bytes), the result (5,099), the reuse request
(9,204) and the reuse result (53); the reuse files left the tree with the exe
(git 99ec957). Notation: `NNx64` means a digest of 64
bytes, all equal to 0xNN. Verified against `artifacts/engine-correction/vectors/`.

`request.bin`:

```
offset len field value
0 8 magic BLFCMD03
8 2 version 0x0003
10 39 contract 0x0025 + 'RR/FINANCIAL/CORRECTION-TRANSITION/v1'
49 8 itemId 'item-h'
57 16 claimId 'claim:h:offset'
73 24 actionId 'action:correction:h:v1'
97 20 actorId 'synthetic-official'
117 18 actorRole 'FINANCE_DECISION'
135 24 currentAuthorityId 'synthetic-authority-v1'
159 8 currentAuthorityEpoch 1
167 64 currentAuthorityDigest 00x64
231 8 expectedRevision 4
239 43 evaluationId 'evaluation:obligation:item-h:period-01:r4'
282 64 evaluationResultDigest a5x64
346 8 decisionAtMs 1774922400010
354 8 ownerNowMs 1774922400020
362 1 actionLookup 1 absent
363 1 query[0].predicate 1 ACTION_ID
364 24 query[0].subject 'action:correction:h:v1'
388 1 query[0].complete 1
389 8 query[0].matchCount 0
397 1 query[0].resultIdentity 0 absent
398 8 query[0].versionSequence 10
406 64 query[0].versionHead 2ax64
470 247 query[1], query[2] DETERMINATION_ID 'determination:action:correction:h:v1',
  EVALUATION_CONSUMED 'evaluation:obligation:item-h:period-01:r4'; same shape
717 8 currentEventSequence 10
725 64 previousHistoryHead 2ax64
789 2 paymentLinks.count 0
791 4 currentInput length 1610
795 1610 currentInput BLFIN02 ...
2405 4 currentReceipt length 950
2409 36 receipt.contractVersion 'RR/FINANCIAL/EVALUATION-RECEIPT/v1'
2445 89 receipt.scope fixture-state, fixture-rightrail, fixture-provider-payment,
  fixture-2026-period-01, USD
2534 105 receipt.pack 'control-pack:fixture-2026-01:v1', 1, 00x64
2639 162 receipt.evidenceBindings 2: evidence:cash 44x64, evidence:offset 44x64
2801 65 receipt.inputSnapshotDigest present, 5bx64
2866 72 receipt.authority epoch 1, 00x64
2938 229 receipt.result r4, rule 1, owed 10000000, claimed 300000, received 9700000,
  shortfall 300000, SUPPORTED / OPEN / NONE
3167 192 receipt digests result a5x64, receipt 5ax64, evaluationResult a5x64
3359 end, nothing left over
```

`result.expected.bin`:

```
offset len field value
0 8 magic BLFCRES3
8 2 version 0x0003
10 1 status 1 ACCEPTED
11 39 contract 'RR/FINANCIAL/CORRECTION-TRANSITION/v1'
50 1 rejectReason 0 absent
51 1 explanation.code 1 CORRECTION_AUTHORIZED
52 2 explanation.transition 1, 1
54 2 explanation.reason, requirement 0, 0
56 17 explanation.claimId 1 + 'claim:h:offset'
73 25 explanation.actionId 1 + 'action:correction:h:v1'
98 44 explanation.inputEvaluationId 1 + 'evaluation:obligation:item-h:period-01:r4'
142 18 explanation.expected/resulting 1 + 4, 1 + 5
160 25 actionId 1 + 'action:correction:h:v1'
185 39 determinationId 1 + 'determination:action:correction:h:v1'
224 1 mutation 1 present
225 1 transitionKind 1
226 9 effects count 7: 01 02 03 04 05 06 07
235 1140 dependencies contract, v1, authority, pack, evaluation r4,
  shortfall 300000, claimBefore CLAIMED 300000, 2 evidence,
  3 queries at sequence 10 / 2ax64, correctionPaid count 0
1375 133 followUps action, action, 'case:obligation:item-h:period-01',
  'evaluation:obligation:item-h:period-01:r5', 11
1508 2225 resultingInput length 2221, BLFIN02 ...
3733 509 resultingResult length 505, BLFRES02 ...
4242 284 determination decision 2, amount 300000, r4 -> r5, decidedAt ...010
4526 214 action CORRECTION_PAYMENT_REQUEST, 300000 USD, r5, READY, createdAt ...020
4740 141 case CORRECTION_REQUIRED, CASE_OWNER, status 3, PROGRAM_ACCOUNTABILITY, 1 1 1 1
4881 42 outbox READY, attempt 0, no reference, ...020
4923 176 event sequence 11, prev 2ax64, OBLIGATION, r4 -> r5, ...020
5099 end, nothing left over
```

Here the action amount is min(300000, 300000 − 0) = 300000.

## Open discrepancies

Found by reading the code; none has been run.

The Python semantic adapter currently refuses CANCELLED rows at load
(`right_rail_financial_semantic_adapter.py` :1593, :1613-1614, :1624-1625), so the behaviour
test for Lean skipping a CANCELLED request lands with the command that first writes CANCELLED.
When cancel lands, the checker must count a cancellation only from the revision it happened at (as
`paid_at` does for payments), not by current status; today it counts every request and refuses CANCELLED.

**B. Result decoding** — Lean `decodeCorrectionTransitionResult` vs Python
`decode_correction_transition_result`.
2. ACCEPTED: Python requires determinationId = `determination:`+actionId;
   Lean requires this only for DUPLICATE (the transition always emits that
   form; the codec would admit another).
3. Python requires resulting BLFRES02's `evaluatedAt = event.committedAtMs`
   and `deliveryStatus = READY`; Lean requires neither.
4. Python's decoder skips several Lean rules, all covered at commit instead
   (lead audit 2026-09-28, by reading `app/right_rail_financial_owner.py`
   4458-4840): checks only resulting
   BLFIN02's magic, not well-formedness (Owner compares it to its own
   re-encoding, `right_rail_financial_semantic_adapter.py` line 2130); skips
   resulting result's context/authority/pack agreement with resulting
   input; skips the action-amount formula (the checker applies its own amount and requestable rule before COMMIT); skips
   `committedAtMs = max(decisionAt, ownerNow)`, the `evaluation:<obligation>:
   r<n>` form of inputEvaluationId, `evaluatedAt ≤ decisionAt`, the rejected
   claim in the resulting input, and supporting-evidence coverage of
   claimBefore's evidence; skips revision bounds (≤10,000).
   Owner derives determination id, `evaluation:<obligation>:r<n>`, resulting
   revision and mutation time itself and writes only those;
   `bind_resulting_state` requires the post-write snapshot
   re-encoding to equal the resulting BLFIN02 bytes, then binds the result
   context; before COMMIT, `verify_obligation_connection` (Owner :4874)
   recomputes the written evaluation from the exact rows and applies the checker's action rules
   to the obligation's correction actions, amount included. A replacement
   engine violating any of these is refused before anything commits.
5. DUPLICATE/REJECTED: Python accepts explanation expectedRevision up to
   2^63-1; Lean caps at 10,000.

**C. Request encoding** — Python `encode_correction_transition_request` vs
Lean decoder. Where Python is laxer (6-8), Lean refuses the bytes (exit 72,
fail closed).
6. Python emits values Lean rejects: authority epoch 0; receipt pack
   version 0 or above 10,000; receipt revision above 10,000; ruleVersion 0
   or above 10,000; currentEventSequence/query versionSequence/lookup
   expectedRevision above 10,000; a receipt contractVersion other than the
   constant (Python doesn't check it); a scope currency that is 1..128
   bytes of text but not an id.
7. Python doesn't check that query matchCount agrees with resultIdentity,
   or that the receipt's binding ids equal `result.evidenceIds`.
8. Python doesn't check paymentLinks order, uniqueness or targets (relies on
   SQL `ORDER BY`). Lean refuses only structurally invalid links: unordered or
   duplicate fail at decode (Owner `correction_transition_failed`), a link naming
   no payment row or non-request is INVALID_INPUT. Links naming real rows are
   accepted; payment timing and the per-request cap are the Owner's and the
   independent checker's.
9. Python is stricter: receipt evidence lists must be strictly ascending
   (Lean requires only equal lists); receipt status strings must be ids
   (Lean allows 1..512-byte text); existing-lookup decision must be tag 2
   (Lean allows 1 or 2); inputSnapshotDigest is always present, so reason
   19 cannot occur for Owner-built requests.

**D. Spec gaps.**
10. Python has no reuse (`BLFCRU02`/`BLFCRV02`) codec and no reuse vector file
    (retired with the one-shot exe, M4 P1) — one implementation exists.
11. `ARCHITECTURE.md` records codec round-trip and trailing-byte laws
    proved only for admissible values; nothing yet proves every value Lean
    emits is admissible.
12. The semantic well-formedness of the embedded BLFIN02/BLFRES02 (§6)
    exists only as Lean predicates, with no prose spec.
