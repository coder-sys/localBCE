import BlindLedger.Financial.Codec
import BlindLedger.Financial.CodecLaws.Primitives

namespace BlindLedger.Financial
/-! The record laws below keep the implementation's admissibility obligations
    explicit.  In particular, list admissibility contains only the encoded
    count bound and a parser law for each stored member.  It deliberately does
    not add uniqueness: `ControlPack.sourceRefs` is an ordered stored list and
    repeated bounded references are part of the supported v2 domain. -/

def nat8WireAdmissible (value : Nat) : Prop := value < 256 ^ 8

theorem readNat8_natBE_append
    (value : Nat) (rest : Bytes)
    (hValue : nat8WireAdmissible value) :
    readNatBE 8 (natBE 8 value ++ rest) = some (value, rest) := by
  exact readNatBE_natBE_append 8 value rest (by
    simpa [nat8WireAdmissible, natFits] using hValue)

theorem readDigest_wire_append
    (value rest : Bytes)
    (hValue : digestWireAdmissible value) :
    readDigest (encodeDigest value ++ rest) = some (value, rest) := by
  exact readDigest_encodeDigest_append value rest hValue

def wireListAdmissible {α : Type} (values : List α) (element : α → Prop) : Prop :=
  listCountAdmissible values ∧ ∀ value, value ∈ values → element value

def stringListWireAdmissible (values : List String) : Prop :=
  wireListAdmissible values stringWireAdmissible

def contextWireAdmissible (context : FinancialContext) : Prop :=
  stringWireAdmissible context.ownerId ∧
    stringWireAdmissible context.stateId ∧
    stringWireAdmissible context.deploymentId ∧
    stringWireAdmissible context.programId ∧
    stringWireAdmissible context.periodId ∧
    stringWireAdmissible context.populationId ∧
    stringWireAdmissible context.itemId ∧
    stringWireAdmissible context.obligationId ∧
    stringWireAdmissible context.currency

def authorityActorWireAdmissible (actor : AuthorityActor) : Prop :=
  stringWireAdmissible actor.actorId ∧ stringListWireAdmissible actor.roles

def authorityWireAdmissible (authority : TrustedAuthority) : Prop :=
  stringWireAdmissible authority.authorityId ∧
    nat8WireAdmissible authority.epoch ∧
    digestWireAdmissible authority.digest ∧
    wireListAdmissible authority.actors authorityActorWireAdmissible

def controlPackWireAdmissible (pack : ControlPack) : Prop :=
  stringWireAdmissible pack.packId ∧
    stringWireAdmissible pack.stateId ∧
    stringWireAdmissible pack.deploymentId ∧
    stringWireAdmissible pack.programId ∧
    stringWireAdmissible pack.periodId ∧
    stringWireAdmissible pack.currency ∧
    nat8WireAdmissible pack.version ∧
    stringListWireAdmissible pack.sourceRefs ∧
    nat8WireAdmissible pack.effectiveStart ∧
    nat8WireAdmissible pack.effectiveEnd ∧
    nat8WireAdmissible pack.recordedAt ∧
    nat8WireAdmissible pack.approvedAt ∧
    stringWireAdmissible pack.calculationRuleId ∧
    stringWireAdmissible pack.adjustmentRuleId ∧
    stringListWireAdmissible pack.authorizedRoles ∧
    stringListWireAdmissible pack.expectedTests ∧
    digestWireAdmissible pack.digest

def obligationWireAdmissible (obligation : Obligation) : Prop :=
  stringWireAdmissible obligation.populationId ∧
    stringWireAdmissible obligation.itemId ∧
    stringWireAdmissible obligation.obligationId ∧
    nat8WireAdmissible obligation.owedCents ∧
    nat8WireAdmissible obligation.dueAt ∧
    nat8WireAdmissible obligation.ruleVersion

def paymentWireAdmissible (payment : Payment) : Prop :=
  stringWireAdmissible payment.paymentId ∧
    stringWireAdmissible payment.obligationId ∧
    stringWireAdmissible payment.itemId ∧
    stringWireAdmissible payment.evidenceId ∧
    stringWireAdmissible payment.commonOriginId ∧
    nat8WireAdmissible payment.amountCents ∧
    nat8WireAdmissible payment.eventAt ∧
    optionStringWireAdmissible payment.reversalEvidenceId

def claimWireAdmissible (claim : Claim) : Prop :=
  stringWireAdmissible claim.claimId ∧
    stringWireAdmissible claim.obligationId ∧
    stringWireAdmissible claim.evidenceId ∧
    nat8WireAdmissible claim.amountCents ∧
    stringWireAdmissible claim.ownerRole ∧
    nat8WireAdmissible claim.deadlineAt

def determinationWireAdmissible (determination : OffsetDetermination) : Prop :=
  stringWireAdmissible determination.determinationId ∧
    stringWireAdmissible determination.obligationId ∧
    stringWireAdmissible determination.claimId ∧
    stringWireAdmissible determination.actorId ∧
    stringWireAdmissible determination.actorRole ∧
    stringWireAdmissible determination.authorityId ∧
    nat8WireAdmissible determination.authorityEpoch ∧
    digestWireAdmissible determination.authorityDigest ∧
    nat8WireAdmissible determination.amountCents ∧
    stringListWireAdmissible determination.supportingEvidenceIds ∧
    nat8WireAdmissible determination.expectedRevision ∧
    nat8WireAdmissible determination.resultingRevision ∧
    nat8WireAdmissible determination.decidedAt

def evidenceWireAdmissible (evidence : EvidenceRecord) : Prop :=
  stringWireAdmissible evidence.evidenceId ∧
    stringWireAdmissible evidence.obligationId ∧
    stringWireAdmissible evidence.itemId ∧
    stringWireAdmissible evidence.kind ∧
    stringWireAdmissible evidence.commonOriginId ∧
    stringWireAdmissible evidence.sourceId ∧
    stringWireAdmissible evidence.sourceVersion ∧
    stringWireAdmissible evidence.localRef ∧
    nat8WireAdmissible evidence.applicableAt ∧
    nat8WireAdmissible evidence.eventAt ∧
    nat8WireAdmissible evidence.receivedAt ∧
    optionNatWireAdmissible evidence.amountCents ∧
    optionStringWireAdmissible evidence.reversalOf ∧
    optionStringWireAdmissible evidence.supersedes

def conflictWireAdmissible (conflict : FinancialConflict) : Prop :=
  stringWireAdmissible conflict.conflictId ∧
    stringWireAdmissible conflict.obligationId ∧
    stringWireAdmissible conflict.commonOriginId ∧
    stringWireAdmissible conflict.existingPaymentId ∧
    stringWireAdmissible conflict.candidateEvidenceId ∧
    nat8WireAdmissible conflict.existingAmountCents ∧
    nat8WireAdmissible conflict.candidateAmountCents ∧
    stringWireAdmissible conflict.reason ∧
    nat8WireAdmissible conflict.visibleAt

def caseWireAdmissible (caseRecord : CaseRecord) : Prop :=
  stringWireAdmissible caseRecord.caseId ∧
    stringWireAdmissible caseRecord.obligationId ∧
    stringWireAdmissible caseRecord.reason ∧
    stringWireAdmissible caseRecord.nextActionOwner ∧
    nat8WireAdmissible caseRecord.dueAt ∧
    nat8WireAdmissible caseRecord.updatedAt

def actionWireAdmissible (action : ActionRecord) : Prop :=
  stringWireAdmissible action.actionId ∧
    stringWireAdmissible action.obligationId ∧
    optionStringWireAdmissible action.determinationId ∧
    stringWireAdmissible action.kind ∧
    nat8WireAdmissible action.amountCents ∧
    stringWireAdmissible action.currency ∧
    nat8WireAdmissible action.revision ∧
    digestWireAdmissible action.payloadDigest ∧
    nat8WireAdmissible action.createdAt

def financialInputWireAdmissible (input : FinancialInput) : Prop :=
  financialInputWellFormed input = true ∧
    contextWireAdmissible input.context ∧
    authorityWireAdmissible input.authority ∧
    controlPackWireAdmissible input.pack ∧
    obligationWireAdmissible input.obligation ∧
    nat8WireAdmissible input.beforeRevision ∧
    nat8WireAdmissible input.evaluatedAt ∧
    wireListAdmissible input.payments paymentWireAdmissible ∧
    wireListAdmissible input.claims claimWireAdmissible ∧
    wireListAdmissible input.determinations determinationWireAdmissible ∧
    wireListAdmissible input.evidence evidenceWireAdmissible ∧
    wireListAdmissible input.conflicts conflictWireAdmissible ∧
    wireListAdmissible input.cases caseWireAdmissible ∧
    wireListAdmissible input.actions actionWireAdmissible ∧
    (rawEncodeFinancialInput input).length ≤ maxTotalEncodedBytes

def financialResultWireAdmissible (result : FinancialResult) : Prop :=
  financialResultWellFormed result = true ∧
    contextWireAdmissible result.context ∧
    stringWireAdmissible result.authorityId ∧
    nat8WireAdmissible result.authorityEpoch ∧
    digestWireAdmissible result.authorityDigest ∧
    stringWireAdmissible result.packId ∧
    digestWireAdmissible result.packDigest ∧
    nat8WireAdmissible result.beforeRevision ∧
    nat8WireAdmissible result.afterRevision ∧
    nat8WireAdmissible result.evaluatedAt ∧
    nat8WireAdmissible result.ruleVersion ∧
    stringListWireAdmissible result.evidenceIds ∧
    optionNatWireAdmissible result.completionAt ∧
    nat8WireAdmissible result.owedCents ∧
    nat8WireAdmissible result.claimedAdjustmentCents ∧
    nat8WireAdmissible result.lawfulAdjustmentCents ∧
    nat8WireAdmissible result.receivedCashCents ∧
    nat8WireAdmissible result.shortfallCents ∧
    nat8WireAdmissible result.overageCents ∧
    (rawEncodeFinancialResult result).length ≤ maxTotalEncodedBytes

theorem readMagic_accepts_prefix (rest : Bytes) :
    readMagic (financialCodecMagic ++ rest) = some rest := by
  simp [readMagic, financialCodecMagic]

theorem readResultMagic_accepts_prefix (rest : Bytes) :
    readResultMagic (financialResultCodecMagic ++ rest) = some rest := by
  simp [readResultMagic, financialResultCodecMagic]

theorem decodeContext_encodeContext_append
    (context : FinancialContext) (rest : Bytes)
    (hContext : contextWireAdmissible context) :
    decodeContext (encodeContext context ++ rest) = some (context, rest) := by
  rcases hContext with
    ⟨hOwnerId, hStateId, hDeploymentId, hProgramId, hPeriodId,
      hPopulationId, hItemId, hObligationId, hCurrency⟩
  simp [decodeContext, encodeContext, List.append_assoc,
    readString_encodeString_append, readByte, decodeMode_encodeMode,
    decodeProvenance_encodeProvenance, hOwnerId, hStateId, hDeploymentId,
    hProgramId, hPeriodId, hPopulationId, hItemId, hObligationId, hCurrency]

theorem decodeAuthorityActor_encodeAuthorityActor_append
    (actor : AuthorityActor) (rest : Bytes)
    (hActor : authorityActorWireAdmissible actor) :
    decodeAuthorityActor (encodeAuthorityActor actor ++ rest) =
      some (actor, rest) := by
  rcases hActor with ⟨hActorId, hRoles⟩
  rcases hRoles with ⟨hRolesCount, hRole⟩
  have hRolesRead : ∀ tail : Bytes,
      readList readString (encodeList encodeString actor.roles ++ tail) =
        some (actor.roles, tail) := by
    intro tail
    exact readList_encodeString_append actor.roles tail hRolesCount.1 hRole
  simp [decodeAuthorityActor, encodeAuthorityActor, List.append_assoc,
    readString_encodeString_append, hActorId, hRolesRead]

theorem decodeAuthority_encodeAuthority_append
    (authority : TrustedAuthority) (rest : Bytes)
    (hAuthority : authorityWireAdmissible authority) :
    decodeAuthority (encodeAuthority authority ++ rest) =
      some (authority, rest) := by
  rcases hAuthority with ⟨hAuthorityId, hEpoch, hDigest, hActors⟩
  rcases hActors with ⟨hActorsCount, hActor⟩
  have hActorRead : ∀ actor, actor ∈ authority.actors → ∀ tail : Bytes,
      decodeAuthorityActor (encodeAuthorityActor actor ++ tail) =
        some (actor, tail) := by
    intro actor hMem tail
    exact decodeAuthorityActor_encodeAuthorityActor_append actor tail
      (hActor actor hMem)
  have hActorsRead : ∀ tail : Bytes,
      readList decodeAuthorityActor
          (encodeList encodeAuthorityActor authority.actors ++ tail) =
        some (authority.actors, tail) := by
    intro tail
    exact readList_encodeList_append_of_mem encodeAuthorityActor decodeAuthorityActor
      authority.actors tail hActorsCount.1 hActorsCount.2 hActorRead
  simp [decodeAuthority, encodeAuthority, List.append_assoc,
    readString_encodeString_append,
    readNat8_natBE_append _ _ hEpoch,
    readDigest_wire_append _ _ hDigest, readBool_encodeBool_append, readByte,
    hAuthorityId, hActorsRead]

theorem decodeControlPack_encodeControlPack_append
    (pack : ControlPack) (rest : Bytes)
    (hPack : controlPackWireAdmissible pack) :
    decodeControlPack (encodeControlPack pack ++ rest) = some (pack, rest) := by
  rcases hPack with
    ⟨hPackId, hStateId, hDeploymentId, hProgramId, hPeriodId, hCurrency,
      hVersion, hSourceRefs, hEffectiveStart, hEffectiveEnd, hRecordedAt,
      hApprovedAt, hCalculationRuleId, hAdjustmentRuleId, hAuthorizedRoles,
      hExpectedTests, hDigest⟩
  rcases hSourceRefs with ⟨hSourceRefsCount, hSourceRef⟩
  rcases hAuthorizedRoles with ⟨hAuthorizedRolesCount, hAuthorizedRole⟩
  rcases hExpectedTests with ⟨hExpectedTestsCount, hExpectedTest⟩
  have hSourceRefsRead : ∀ tail : Bytes,
      readList readString (encodeList encodeString pack.sourceRefs ++ tail) =
        some (pack.sourceRefs, tail) := by
    intro tail
    exact readList_encodeString_append pack.sourceRefs tail hSourceRefsCount.1
      hSourceRef
  have hAuthorizedRolesRead : ∀ tail : Bytes,
      readList readString (encodeList encodeString pack.authorizedRoles ++ tail) =
        some (pack.authorizedRoles, tail) := by
    intro tail
    exact readList_encodeString_append pack.authorizedRoles tail
      hAuthorizedRolesCount.1 hAuthorizedRole
  have hExpectedTestsRead : ∀ tail : Bytes,
      readList readString (encodeList encodeString pack.expectedTests ++ tail) =
        some (pack.expectedTests, tail) := by
    intro tail
    exact readList_encodeString_append pack.expectedTests tail
      hExpectedTestsCount.1 hExpectedTest
  simp [decodeControlPack, encodeControlPack, List.append_assoc,
    readString_encodeString_append,
    readNat8_natBE_append _ _ hVersion,
    readNat8_natBE_append _ _ hEffectiveStart,
    readNat8_natBE_append _ _ hEffectiveEnd,
    readNat8_natBE_append _ _ hRecordedAt,
    readNat8_natBE_append _ _ hApprovedAt,
    readDigest_wire_append _ _ hDigest, readByte,
    decodePackStatus_encodePackStatus,
    hPackId, hStateId, hDeploymentId, hProgramId, hPeriodId, hCurrency,
    hSourceRefsRead, hCalculationRuleId, hAdjustmentRuleId,
    hAuthorizedRolesRead, hExpectedTestsRead]

theorem decodeObligation_encodeObligation_append
    (obligation : Obligation) (rest : Bytes)
    (hObligation : obligationWireAdmissible obligation) :
    decodeObligation (encodeObligation obligation ++ rest) =
      some (obligation, rest) := by
  rcases hObligation with
    ⟨hPopulationId, hItemId, hObligationId, hOwedCents, hDueAt, hRuleVersion⟩
  simp [decodeObligation, encodeObligation, List.append_assoc,
    readString_encodeString_append,
    readNat8_natBE_append _ _ hOwedCents,
    readNat8_natBE_append _ _ hDueAt,
    readNat8_natBE_append _ _ hRuleVersion,
    readBool_encodeBool_append, readByte,
    hPopulationId, hItemId, hObligationId,
    hOwedCents, hDueAt, hRuleVersion]

theorem decodePayment_encodePayment_append
    (payment : Payment) (rest : Bytes)
    (hPayment : paymentWireAdmissible payment) :
    decodePayment (encodePayment payment ++ rest) = some (payment, rest) := by
  rcases hPayment with
    ⟨hPaymentId, hObligationId, hItemId, hEvidenceId, hCommonOriginId,
      hAmountCents, hEventAt, hReversalEvidenceId⟩
  simp [decodePayment, encodePayment, List.append_assoc,
    readString_encodeString_append,
    readNat8_natBE_append _ _ hAmountCents,
    readNat8_natBE_append _ _ hEventAt,
    readOptionString_encodeOptionString_append _ _ hReversalEvidenceId,
    readByte, decodePaymentStatus_encodePaymentStatus,
    hPaymentId, hObligationId,
    hItemId, hEvidenceId, hCommonOriginId]

theorem decodeClaim_encodeClaim_append
    (claim : Claim) (rest : Bytes)
    (hClaim : claimWireAdmissible claim) :
    decodeClaim (encodeClaim claim ++ rest) = some (claim, rest) := by
  rcases hClaim with
    ⟨hClaimId, hObligationId, hEvidenceId, hAmountCents, hOwnerRole,
      hDeadlineAt⟩
  simp [decodeClaim, encodeClaim, List.append_assoc,
    readString_encodeString_append,
    readNat8_natBE_append _ _ hAmountCents,
    readNat8_natBE_append _ _ hDeadlineAt,
    readByte, decodeClaimStatus_encodeClaimStatus,
    hClaimId, hObligationId,
    hEvidenceId, hOwnerRole]

theorem decodeDetermination_encodeDetermination_append
    (determination : OffsetDetermination) (rest : Bytes)
    (hDetermination : determinationWireAdmissible determination) :
    decodeDetermination (encodeDetermination determination ++ rest) =
      some (determination, rest) := by
  rcases hDetermination with
    ⟨hDeterminationId, hObligationId, hClaimId, hActorId, hActorRole,
      hAuthorityId, hAuthorityEpoch, hAuthorityDigest, hAmountCents,
      hSupportingEvidenceIds, hExpectedRevision, hResultingRevision,
      hDecidedAt⟩
  rcases hSupportingEvidenceIds with ⟨hSupportingCount, hSupportingEvidenceId⟩
  have hSupportingRead : ∀ tail : Bytes,
      readList readString
          (encodeList encodeString determination.supportingEvidenceIds ++ tail) =
        some (determination.supportingEvidenceIds, tail) := by
    intro tail
    exact readList_encodeString_append determination.supportingEvidenceIds tail
      hSupportingCount.1 hSupportingEvidenceId
  simp [decodeDetermination, encodeDetermination, List.append_assoc,
    readString_encodeString_append,
    readNat8_natBE_append _ _ hAuthorityEpoch,
    readNat8_natBE_append _ _ hAmountCents,
    readNat8_natBE_append _ _ hExpectedRevision,
    readNat8_natBE_append _ _ hResultingRevision,
    readNat8_natBE_append _ _ hDecidedAt,
    readDigest_wire_append _ _ hAuthorityDigest, readByte,
    decodeDecision_encodeDecision,
    hDeterminationId, hObligationId, hClaimId, hActorId, hActorRole,
    hAuthorityId, hSupportingRead]

theorem decodeEvidence_encodeEvidence_append
    (evidence : EvidenceRecord) (rest : Bytes)
    (hEvidence : evidenceWireAdmissible evidence) :
    decodeEvidence (encodeEvidence evidence ++ rest) =
      some (evidence, rest) := by
  rcases hEvidence with
    ⟨hEvidenceId, hObligationId, hItemId, hKind, hCommonOriginId, hSourceId,
      hSourceVersion, hLocalRef, hApplicableAt, hEventAt, hReceivedAt,
      hAmountCents, hReversalOf, hSupersedes⟩
  simp [decodeEvidence, encodeEvidence, List.append_assoc,
    readString_encodeString_append,
    readNat8_natBE_append _ _ hApplicableAt,
    readNat8_natBE_append _ _ hEventAt,
    readNat8_natBE_append _ _ hReceivedAt,
    readOptionNat_encodeOptionNat_append _ _ hAmountCents,
    readOptionString_encodeOptionString_append _ _ hReversalOf,
    readOptionString_encodeOptionString_append _ _ hSupersedes,
    hEvidenceId, hObligationId,
    hItemId, hKind, hCommonOriginId, hSourceId, hSourceVersion, hLocalRef]

theorem decodeConflict_encodeConflict_append
    (conflict : FinancialConflict) (rest : Bytes)
    (hConflict : conflictWireAdmissible conflict) :
    decodeConflict (encodeConflict conflict ++ rest) =
      some (conflict, rest) := by
  rcases hConflict with
    ⟨hConflictId, hObligationId, hCommonOriginId, hExistingPaymentId,
      hCandidateEvidenceId, hExistingAmountCents, hCandidateAmountCents,
      hReason, hVisibleAt⟩
  simp [decodeConflict, encodeConflict, List.append_assoc,
    readString_encodeString_append,
    readNat8_natBE_append _ _ hExistingAmountCents,
    readNat8_natBE_append _ _ hCandidateAmountCents,
    readNat8_natBE_append _ _ hVisibleAt,
    hConflictId,
    hObligationId, hCommonOriginId, hExistingPaymentId, hCandidateEvidenceId,
    hReason]

theorem decodeCase_encodeCase_append
    (caseRecord : CaseRecord) (rest : Bytes)
    (hCase : caseWireAdmissible caseRecord) :
    decodeCase (encodeCase caseRecord ++ rest) =
      some (caseRecord, rest) := by
  rcases hCase with
    ⟨hCaseId, hObligationId, hReason, hNextActionOwner, hDueAt, hUpdatedAt⟩
  simp [decodeCase, encodeCase, List.append_assoc,
    readString_encodeString_append,
    readNat8_natBE_append _ _ hDueAt,
    readNat8_natBE_append _ _ hUpdatedAt,
    readByte, decodeCaseStatus_encodeCaseStatus,
    hCaseId, hObligationId, hReason,
    hNextActionOwner]

theorem decodeAction_encodeAction_append
    (action : ActionRecord) (rest : Bytes)
    (hAction : actionWireAdmissible action) :
    decodeAction (encodeAction action ++ rest) = some (action, rest) := by
  rcases hAction with
    ⟨hActionId, hObligationId, hDeterminationId, hKind, hAmountCents,
      hCurrency, hRevision, hPayloadDigest, hCreatedAt⟩
  simp [decodeAction, encodeAction, List.append_assoc,
    readString_encodeString_append,
    readNat8_natBE_append _ _ hAmountCents,
    readNat8_natBE_append _ _ hRevision,
    readNat8_natBE_append _ _ hCreatedAt,
    readOptionString_encodeOptionString_append _ _ hDeterminationId,
    readDigest_wire_append _ _ hPayloadDigest,
    readByte, decodeActionStatus_encodeActionStatus,
    hActionId, hObligationId, hDeterminationId, hKind, hAmountCents,
    hCurrency]



end BlindLedger.Financial
