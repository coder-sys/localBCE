import BlindLedger.Financial.CodecLaws
import BlindLedger.Financial.CorrectionTransition.Codec
import BlindLedger.Financial.CodecLaws.PaymentLinks

/-! Correction-wire codec laws, part 1: primitives, wire admissibility and the
    record parser laws that `CodecLaws.Correction` composes.  A separate module
    so each Lean process stays under the guarded build's memory floor. -/

namespace BlindLedger.Financial.CorrectionTransition

open BlindLedger.Financial
open BlindLedger.Financial.DecisionPackage

theorem length_natBE (width value : Nat) : (natBE width value).length = width := by
  induction width generalizing value with
  | zero => rfl
  | succ width ih => simp [natBE, ih]

theorem length_encodeSizedBytes (value : Bytes) :
    (encodeSizedBytes value).length = 4 + value.length := by
  simp [encodeSizedBytes, length_natBE]

theorem length_le_of_append_sized (pre value : Bytes) {bound : Nat}
    (h : (pre ++ encodeSizedBytes value).length ≤ bound) : value.length ≤ bound := by
  simp only [List.length_append, length_encodeSizedBytes] at h
  omega

theorem isPrefixOf_append_self (magic rest : Bytes) : magic.isPrefixOf (magic ++ rest) = true := by
  induction magic with
  | nil => simp
  | cons byte magic ih => simp [ih]

theorem readSizedBytes_encodeSizedBytes_append (value rest : Bytes)
    (hValue : value.length ≤ maxCorrectionTransitionBytes) :
    readSizedBytes maxCorrectionTransitionBytes (encodeSizedBytes value ++ rest) =
      some (value, rest) := by
  have hFits : value.length < 256 ^ 4 := Nat.lt_of_le_of_lt hValue (by decide)
  unfold readSizedBytes encodeSizedBytes
  simp only [List.append_assoc]
  rw [readNatBE_natBE_append 4 value.length (value ++ rest) hFits]
  simp [Nat.not_lt.mpr hValue]

/-! The contract string is a literal, so its wire admissibility is proved from
    its character count: UTF-8 uses at most four bytes per character, and the
    String/ByteArray round trip is exact. -/

theorem byteArray_toList_loop (data : Array UInt8) :
    ∀ n i r, data.size - i = n →
      ByteArray.toList.loop ⟨data⟩ i r = r.reverse ++ data.toList.drop i := by
  intro n
  induction n with
  | zero =>
      intro i r hSize
      have hGe : ¬ i < (ByteArray.mk data).size := by show ¬ i < data.size; omega
      have hLe : data.toList.length ≤ i := by simp only [Array.length_toList]; omega
      rw [ByteArray.toList.loop, if_neg hGe, List.drop_eq_nil_of_le hLe, List.append_nil]
  | succ n ih =>
      intro i r hSize
      have hLt : i < data.size := by omega
      have hLt' : i < (ByteArray.mk data).size := hLt
      have hLtList : i < data.toList.length := by simpa using hLt
      have hGet : (ByteArray.mk data).get! i = data.toList[i]'hLtList := by
        simp [ByteArray.get!, hLt]
      rw [ByteArray.toList.loop, if_pos hLt', ih (i + 1) _ (by omega), hGet,
        List.drop_eq_getElem_cons (l := data.toList) (i := i) hLtList]
      simp

theorem byteArray_toList_eq (bytes : ByteArray) : bytes.toList = bytes.data.toList := by
  cases bytes with
  | mk data =>
      show ByteArray.toList.loop ⟨data⟩ 0 [] = data.toList
      rw [byteArray_toList_loop data _ 0 [] rfl]
      simp

theorem byteArray_toList_toByteArray (bytes : ByteArray) : bytes.toList.toByteArray = bytes := by
  apply ByteArray.ext
  apply Array.toList_inj.mp
  rw [List.toList_data_toByteArray, byteArray_toList_eq]

theorem stringWireAdmissible_of_length (value : String)
    (hLength : value.toUTF8.toList.length < 65536) : stringWireAdmissible value :=
  ⟨Nat.lt_of_lt_of_le hLength (by decide), by
    rw [byteArray_toList_toByteArray]
    exact string_fromUTF8_toUTF8 value⟩

theorem utf8EncodeFlat_length_le (chars : List Char) :
    (chars.flatMap String.utf8EncodeChar).length ≤ 4 * chars.length := by
  induction chars with
  | nil => simp
  | cons char chars ih =>
      simp only [List.flatMap_cons, List.length_append, String.length_utf8EncodeChar,
        List.length_cons]
      have := Char.utf8Size_le_four char
      omega

theorem string_utf8_length_le (value : String) :
    value.toUTF8.toList.length ≤ 4 * value.toList.length := by
  rw [byteArray_toList_eq, String.toUTF8_eq_toByteArray, ← String.utf8Encode_toList]
  unfold List.utf8Encode
  rw [List.toList_data_toByteArray]
  exact utf8EncodeFlat_length_le value.toList

theorem correctionTransitionContract_wireAdmissible :
    stringWireAdmissible correctionTransitionContract := by
  apply stringWireAdmissible_of_length
  have hBound := string_utf8_length_le correctionTransitionContract
  have hChars : correctionTransitionContract.toList.length = 37 := by
    simp [correctionTransitionContract]
  omega

/-! One-byte enum tags. -/

theorem readQueryPredicate_cons (value : CorrectionQueryPredicate) (rest : Bytes) :
    readQueryPredicate (encodeQueryPredicate value :: rest) = some (value, rest) := by
  cases value <;> simp [readQueryPredicate, encodeQueryPredicate, readByte]

theorem readTransitionKind_cons (value : TransitionKind) (rest : Bytes) :
    readTransitionKind (encodeTransitionKind value :: rest) = some (value, rest) := by
  cases value <;> simp [readTransitionKind, encodeTransitionKind, readByte]

theorem readExplanationCode_cons (value : ExplanationCode) (rest : Bytes) :
    readExplanationCode (encodeExplanationCode value :: rest) = some (value, rest) := by
  cases value <;> simp [readExplanationCode, encodeExplanationCode, readByte]

theorem readCorrectionEffect_cons (value : CorrectionEffect) (rest : Bytes) :
    readCorrectionEffect (encodeCorrectionEffect value :: rest) = some (value, rest) := by
  cases value <;> simp [readCorrectionEffect, encodeCorrectionEffect, readByte]

theorem readTransitionRequirement_cons (value : TransitionRequirement) (rest : Bytes) :
    readTransitionRequirement (encodeTransitionRequirement value :: rest) = some (value, rest) := by
  cases value <;> simp [readTransitionRequirement, encodeTransitionRequirement, readByte]

theorem decodeRejectReason_encodeRejectReason (value : TransitionRejectReason) :
    decodeRejectReason (encodeRejectReason value) = some value := by
  cases value <;> simp [decodeRejectReason, encodeRejectReason]

theorem readOptionalRejectReason_append (value : Option TransitionRejectReason) (rest : Bytes) :
    readOptionalRejectReason (encodeOptionalRejectReason value ++ rest) = some (value, rest) := by
  cases value <;> simp [readOptionalRejectReason, encodeOptionalRejectReason, readByte,
    decodeRejectReason_encodeRejectReason]

theorem readOptionalRequirement_append (value : Option TransitionRequirement) (rest : Bytes) :
    readOptionalRequirement (encodeOptionalRequirement value ++ rest) = some (value, rest) := by
  cases value <;> simp [readOptionalRequirement, encodeOptionalRequirement, readByte,
    readTransitionRequirement_cons]

theorem readCorrectionEffects_append (effects : List CorrectionEffect) (rest : Bytes)
    (hCount : listCountAdmissible effects) :
    readList readCorrectionEffect
        (encodeList (fun effect => [encodeCorrectionEffect effect]) effects ++ rest) =
      some (effects, rest) :=
  readList_encodeList_append _ _ effects rest hCount.1 hCount.2
    (fun effect tail => by simpa using readCorrectionEffect_cons effect tail)

/-! Wire admissibility: every string fits its u16 length prefix with valid
    UTF-8, every u64 fits eight bytes, every digest has its exact width, and
    every list count fits its bound. -/

def optionDigestWireAdmissible : Option Bytes → Prop
  | none => True
  | some digest => digestWireAdmissible digest

def queryObservationWireAdmissible (observation : CorrectionQueryObservation) : Prop :=
  correctionQueryObservationWellFormed observation = true ∧
    stringWireAdmissible observation.subject ∧ nat8WireAdmissible observation.matchCount ∧
    optionStringWireAdmissible observation.resultIdentity ∧
    nat8WireAdmissible observation.versionSequence ∧ digestWireAdmissible observation.versionHead

def queryObservationsWireAdmissible (observations : CorrectionQueryObservations) : Prop :=
  queryObservationWireAdmissible observations.actionId ∧
    queryObservationWireAdmissible observations.determinationId ∧
    queryObservationWireAdmissible observations.evaluationConsumed

def actionIdentityWireAdmissible (identity : ExistingCorrectionIdentity) : Prop :=
  stringWireAdmissible identity.actionId ∧ stringWireAdmissible identity.actionObligationId ∧
    stringWireAdmissible identity.determinationId ∧
    stringWireAdmissible identity.determinationObligationId ∧
    stringWireAdmissible identity.actionKind ∧ stringWireAdmissible identity.claimId ∧
    stringWireAdmissible identity.actorId ∧ stringWireAdmissible identity.actorRole ∧
    stringWireAdmissible identity.authorityId ∧ nat8WireAdmissible identity.authorityEpoch ∧
    digestWireAdmissible identity.authorityDigest ∧
    stringWireAdmissible identity.inputEvaluationId ∧
    digestWireAdmissible identity.inputEvaluationResultDigest ∧
    nat8WireAdmissible identity.expectedRevision ∧ nat8WireAdmissible identity.decidedAtMs

def actionLookupWireAdmissible : ActionIdentityLookup → Prop
  | .existing identity => actionIdentityWireAdmissible identity
  | _ => True

def correctionPaidWireAdmissible (entry : CorrectionPaid) : Prop :=
  stringWireAdmissible entry.actionId ∧ nat8WireAdmissible entry.paidCents

def commandWireAdmissible (command : CorrectionCommand) : Prop :=
  stringWireAdmissible command.itemId ∧ stringWireAdmissible command.claimId ∧
    stringWireAdmissible command.actionId ∧ stringWireAdmissible command.actorId ∧
    stringWireAdmissible command.actorRole ∧ stringWireAdmissible command.currentAuthorityId ∧
    nat8WireAdmissible command.currentAuthorityEpoch ∧
    digestWireAdmissible command.currentAuthorityDigest ∧
    nat8WireAdmissible command.expectedRevision ∧ stringWireAdmissible command.evaluationId ∧
    digestWireAdmissible command.evaluationResultDigest ∧
    nat8WireAdmissible command.decisionAtMs ∧ nat8WireAdmissible command.ownerNowMs ∧
    actionLookupWireAdmissible command.actionLookup ∧
    queryObservationsWireAdmissible command.queryObservations ∧
    nat8WireAdmissible command.currentEventSequence ∧
    digestWireAdmissible command.previousHistoryHead ∧
    wireListAdmissible command.paymentLinks paymentLinkWireAdmissible

def evidenceBindingWireAdmissible (binding : EvidenceBinding) : Prop :=
  stringWireAdmissible binding.evidenceId ∧ digestWireAdmissible binding.recordDigest

def ownerResultWireAdmissible (result : OwnerEvaluationResult) : Prop :=
  stringWireAdmissible result.evaluationId ∧ stringWireAdmissible result.obligationId ∧
    nat8WireAdmissible result.revision ∧ nat8WireAdmissible result.ruleVersion ∧
    stringListWireAdmissible result.evidenceIds ∧ stringWireAdmissible result.authorityId ∧
    nat8WireAdmissible result.evaluatedAtMs ∧ nat8WireAdmissible result.owedCents ∧
    nat8WireAdmissible result.claimedAdjustmentCents ∧
    nat8WireAdmissible result.lawfulAdjustmentCents ∧
    nat8WireAdmissible result.receivedCashCents ∧ nat8WireAdmissible result.shortfallCents ∧
    nat8WireAdmissible result.overageCents ∧ stringWireAdmissible result.verificationStatus ∧
    stringWireAdmissible result.caseStatus ∧ stringWireAdmissible result.deliveryStatus

def receiptWireAdmissible (receipt : EvaluationReceipt) : Prop :=
  stringWireAdmissible receipt.contractVersion ∧ stringWireAdmissible receipt.scope.stateId ∧
    stringWireAdmissible receipt.scope.deploymentId ∧
    stringWireAdmissible receipt.scope.programId ∧ stringWireAdmissible receipt.scope.periodId ∧
    stringWireAdmissible receipt.scope.currency ∧
    stringWireAdmissible receipt.controlPack.packId ∧
    nat8WireAdmissible receipt.controlPack.version ∧
    digestWireAdmissible receipt.controlPack.digest ∧
    wireListAdmissible receipt.evidenceBindings evidenceBindingWireAdmissible ∧
    optionDigestWireAdmissible receipt.inputSnapshotDigest ∧
    nat8WireAdmissible receipt.authority.authorityEpoch ∧
    digestWireAdmissible receipt.authority.authorityDigest ∧
    ownerResultWireAdmissible receipt.result ∧ digestWireAdmissible receipt.resultDigest ∧
    digestWireAdmissible receipt.receiptDigest ∧
    digestWireAdmissible receipt.evaluationResultDigest

def requestWireAdmissible (request : CorrectionTransitionRequest) : Prop :=
  commandWireAdmissible request.command ∧ financialInputWireAdmissible request.currentInput ∧
    receiptWireAdmissible request.currentReceipt

def dependencyFactsWireAdmissible (facts : CorrectionDependencyFacts) : Prop :=
  stringWireAdmissible facts.artifactContract ∧ nat8WireAdmissible facts.artifactVersion ∧
    stringWireAdmissible facts.authorityId ∧ nat8WireAdmissible facts.authorityEpoch ∧
    digestWireAdmissible facts.authorityDigest ∧ stringWireAdmissible facts.controlPackId ∧
    nat8WireAdmissible facts.controlPackVersion ∧ digestWireAdmissible facts.controlPackDigest ∧
    stringWireAdmissible facts.inputEvaluationId ∧
    digestWireAdmissible facts.inputEvaluationResultDigest ∧
    nat8WireAdmissible facts.inputEvaluationRevision ∧
    nat8WireAdmissible facts.inputEvaluationEvaluatedAtMs ∧
    digestWireAdmissible facts.inputEvaluationSnapshotDigest ∧
    nat8WireAdmissible facts.inputShortfallCents ∧ nat8WireAdmissible facts.decisionAtMs ∧
    nat8WireAdmissible facts.ownerNowMs ∧ claimWireAdmissible facts.claimBefore ∧
    wireListAdmissible facts.supportingEvidence evidenceBindingWireAdmissible ∧
    queryObservationsWireAdmissible facts.queryObservations ∧
    nat8WireAdmissible facts.currentEventSequence ∧ digestWireAdmissible facts.previousHistoryHead ∧
    wireListAdmissible facts.correctionPaid correctionPaidWireAdmissible

def followUpsWireAdmissible (followUps : CorrectionFollowUps) : Prop :=
  stringWireAdmissible followUps.actionId ∧ stringWireAdmissible followUps.outboxActionId ∧
    stringWireAdmissible followUps.caseId ∧
    stringWireAdmissible followUps.resultingEvaluationId ∧
    nat8WireAdmissible followUps.eventSequence

def explanationWireAdmissible (explanation : TransitionExplanation) : Prop :=
  optionStringWireAdmissible explanation.claimId ∧
    optionStringWireAdmissible explanation.actionId ∧
    optionStringWireAdmissible explanation.inputEvaluationId ∧
    optionNatWireAdmissible explanation.expectedRevision ∧
    optionNatWireAdmissible explanation.resultingRevision

def mutationWireAdmissible (mutation : CorrectionMutation) : Prop :=
  listCountAdmissible mutation.orderedEffects ∧
    dependencyFactsWireAdmissible mutation.dependencies ∧
    followUpsWireAdmissible mutation.followUps ∧
    financialInputWireAdmissible mutation.resultingInput ∧
    financialResultWireAdmissible mutation.resultingResult ∧
    determinationWireAdmissible mutation.determination ∧
    actionWireAdmissible mutation.action ∧ caseWireAdmissible mutation.caseDelta.record ∧
    stringWireAdmissible mutation.caseDelta.contractualAccountability ∧
    stringWireAdmissible mutation.outbox.actionId ∧ nat8WireAdmissible mutation.outbox.attempt ∧
    optionStringWireAdmissible mutation.outbox.acknowledgmentReference ∧
    nat8WireAdmissible mutation.outbox.updatedAtMs ∧ nat8WireAdmissible mutation.event.sequence ∧
    digestWireAdmissible mutation.event.previousHead ∧
    stringWireAdmissible mutation.event.aggregateType ∧
    stringWireAdmissible mutation.event.aggregateId ∧ stringWireAdmissible mutation.event.kind ∧
    nat8WireAdmissible mutation.event.beforeRevision ∧
    nat8WireAdmissible mutation.event.afterRevision ∧
    nat8WireAdmissible mutation.event.committedAtMs

def optionalMutationWireAdmissible : Option CorrectionMutation → Prop
  | none => True
  | some mutation => mutationWireAdmissible mutation

def resultWireAdmissible (result : CorrectionTransitionResult) : Prop :=
  explanationWireAdmissible result.explanation ∧ optionStringWireAdmissible result.actionId ∧
    optionStringWireAdmissible result.determinationId ∧
    optionalMutationWireAdmissible result.mutation

/-! Record parser laws. -/

theorem readQueryObservation_append (observation : CorrectionQueryObservation) (rest : Bytes)
    (h : queryObservationWireAdmissible observation) :
    readQueryObservation (encodeQueryObservation observation ++ rest) =
      some (observation, rest) := by
  obtain ⟨predicate, subject, complete, matchCount, resultIdentity, versionSequence,
    versionHead⟩ := observation
  simp only [queryObservationWireAdmissible] at h
  obtain ⟨hWellFormed, h1, h2, h3, h4, h5⟩ := h
  simp [readQueryObservation, encodeQueryObservation, List.append_assoc, readQueryPredicate_cons,
    readString_encodeString_append _ _ h1, readBool_encodeBool_append,
    readNat8_natBE_append _ _ h2, readOptionString_encodeOptionString_append _ _ h3,
    readNat8_natBE_append _ _ h4, readDigest_wire_append _ _ h5, hWellFormed]

theorem readQueryObservations_append (observations : CorrectionQueryObservations) (rest : Bytes)
    (h : queryObservationsWireAdmissible observations) :
    readQueryObservations (encodeQueryObservations observations ++ rest) =
      some (observations, rest) := by
  obtain ⟨h1, h2, h3⟩ := h
  simp [readQueryObservations, encodeQueryObservations, List.append_assoc,
    readQueryObservation_append _ _ h1, readQueryObservation_append _ _ h2,
    readQueryObservation_append _ _ h3]

theorem readActionLookup_append (lookup : ActionIdentityLookup) (rest : Bytes)
    (h : actionLookupWireAdmissible lookup) :
    readActionLookup (encodeActionLookup lookup ++ rest) = some (lookup, rest) := by
  cases lookup with
  | absent => simp [readActionLookup, encodeActionLookup, readByte]
  | conflicting => simp [readActionLookup, encodeActionLookup, readByte]
  | existing identity =>
      have hIdentity : actionIdentityWireAdmissible identity := h
      obtain ⟨h1, h2, h3, h4, h5, h6, h7, h8, h9, h10, h11, h12, h13, h14, h15⟩ := hIdentity
      simp [readActionLookup, encodeActionLookup, List.append_assoc, readByte,
        readString_encodeString_append _ _ h1, readString_encodeString_append _ _ h2,
        readString_encodeString_append _ _ h3, readString_encodeString_append _ _ h4,
        readString_encodeString_append _ _ h5, readString_encodeString_append _ _ h6,
        readString_encodeString_append _ _ h7, readString_encodeString_append _ _ h8,
        readString_encodeString_append _ _ h9, readNat8_natBE_append _ _ h10,
        readDigest_wire_append _ _ h11, readString_encodeString_append _ _ h12,
        readDigest_wire_append _ _ h13, readNat8_natBE_append _ _ h14,
        readNat8_natBE_append _ _ h15, decodeDecision_encodeDecision]

theorem readEvidenceBinding_append (binding : EvidenceBinding) (rest : Bytes)
    (h : evidenceBindingWireAdmissible binding) :
    readEvidenceBinding (encodeEvidenceBinding binding ++ rest) = some (binding, rest) := by
  simp [readEvidenceBinding, encodeEvidenceBinding, List.append_assoc,
    readString_encodeString_append _ _ h.1, readDigest_wire_append _ _ h.2]

theorem readEvidenceBindings_append (bindings : List EvidenceBinding) (rest : Bytes)
    (h : wireListAdmissible bindings evidenceBindingWireAdmissible) :
    readList readEvidenceBinding (encodeList encodeEvidenceBinding bindings ++ rest) =
      some (bindings, rest) :=
  readList_encodeList_append_of_mem _ _ bindings rest h.1.1 h.1.2
    (fun binding hMember tail => readEvidenceBinding_append binding tail (h.2 binding hMember))

theorem readCorrectionPaid_append (entry : CorrectionPaid) (rest : Bytes)
    (h : correctionPaidWireAdmissible entry) :
    readCorrectionPaid (encodeCorrectionPaid entry ++ rest) = some (entry, rest) := by
  simp [readCorrectionPaid, encodeCorrectionPaid, List.append_assoc,
    readString_encodeString_append _ _ h.1, readNat8_natBE_append _ _ h.2]

theorem readCorrectionPaids_append (paid : List CorrectionPaid) (rest : Bytes)
    (h : wireListAdmissible paid correctionPaidWireAdmissible) :
    readList readCorrectionPaid (encodeList encodeCorrectionPaid paid ++ rest) =
      some (paid, rest) :=
  readList_encodeList_append_of_mem _ _ paid rest h.1.1 h.1.2
    (fun entry hMember tail => readCorrectionPaid_append entry tail (h.2 entry hMember))

theorem readOptionalDigest_append (value : Option Bytes) (rest : Bytes)
    (h : optionDigestWireAdmissible value) :
    readOptional readDigest (encodeOptional encodeDigest value ++ rest) = some (value, rest) := by
  cases value with
  | none => simp [readOptional, encodeOptional]
  | some digest =>
      have hDigest : digestWireAdmissible digest := h
      simp [readOptional, encodeOptional, readDigest_wire_append _ _ hDigest]

theorem readOwnerEvaluationResult_append (result : OwnerEvaluationResult) (rest : Bytes)
    (h : ownerResultWireAdmissible result) :
    readOwnerEvaluationResult (encodeOwnerEvaluationResult result ++ rest) =
      some (result, rest) := by
  obtain ⟨h1, h2, h3, h4, ⟨hCount, hIds⟩, h6, h7, h8, h9, h10, h11, h12, h13, h14, h15,
    h16⟩ := h
  have hIdsRead : ∀ tail : Bytes,
      readList readString (encodeList encodeString result.evidenceIds ++ tail) =
        some (result.evidenceIds, tail) :=
    fun tail => readList_encodeString_append _ tail hCount.1 hIds
  -- Unfold by `delta`: generating `simp`'s equation lemma for a reader this long
  -- exceeds the default heartbeat budget.
  delta readOwnerEvaluationResult encodeOwnerEvaluationResult
  simp [List.append_assoc,
    readString_encodeString_append _ _ h1, readString_encodeString_append _ _ h2,
    readNat8_natBE_append _ _ h3, readNat8_natBE_append _ _ h4, hIdsRead,
    readString_encodeString_append _ _ h6, readNat8_natBE_append _ _ h7,
    readNat8_natBE_append _ _ h8, readNat8_natBE_append _ _ h9, readNat8_natBE_append _ _ h10,
    readNat8_natBE_append _ _ h11, readNat8_natBE_append _ _ h12,
    readNat8_natBE_append _ _ h13, readBool_encodeBool_append,
    readString_encodeString_append _ _ h14, readString_encodeString_append _ _ h15,
    readString_encodeString_append _ _ h16]

theorem readEvaluationReceipt_append (receipt : EvaluationReceipt) (rest : Bytes)
    (h : receiptWireAdmissible receipt) :
    readEvaluationReceipt (encodeEvaluationReceipt receipt ++ rest) = some (receipt, rest) := by
  obtain ⟨h1, h2, h3, h4, h5, h6, h7, h8, h9, h10, h11, h12, h13, h14, h15, h16, h17⟩ := h
  simp [readEvaluationReceipt, encodeEvaluationReceipt, readPackageScope, encodePackageScope,
    readReceiptControlPack, encodeReceiptControlPack, readReceiptAuthority,
    encodeReceiptAuthority, List.append_assoc, readString_encodeString_append _ _ h1,
    readString_encodeString_append _ _ h2, readString_encodeString_append _ _ h3,
    readString_encodeString_append _ _ h4, readString_encodeString_append _ _ h5,
    readString_encodeString_append _ _ h6, readString_encodeString_append _ _ h7,
    readNat8_natBE_append _ _ h8, readDigest_wire_append _ _ h9,
    readEvidenceBindings_append _ _ h10, readOptionalDigest_append _ _ h11,
    readNat8_natBE_append _ _ h12, readDigest_wire_append _ _ h13,
    readOwnerEvaluationResult_append _ _ h14, readDigest_wire_append _ _ h15,
    readDigest_wire_append _ _ h16, readDigest_wire_append _ _ h17]

theorem readDependencyFacts_append (facts : CorrectionDependencyFacts) (rest : Bytes)
    (h : dependencyFactsWireAdmissible facts) :
    readDependencyFacts (encodeDependencyFacts facts ++ rest) = some (facts, rest) := by
  obtain ⟨h1, h2, h3, h4, h5, h6, h7, h8, h9, h10, h11, h12, h13, h14, h15, h16, h17, h18,
    h19, h20, h21, h22⟩ := h
  delta readDependencyFacts encodeDependencyFacts
  simp [List.append_assoc,
    readString_encodeString_append _ _ h1, readNat8_natBE_append _ _ h2,
    readString_encodeString_append _ _ h3, readNat8_natBE_append _ _ h4,
    readDigest_wire_append _ _ h5, readString_encodeString_append _ _ h6,
    readNat8_natBE_append _ _ h7, readDigest_wire_append _ _ h8,
    readString_encodeString_append _ _ h9, readDigest_wire_append _ _ h10,
    readNat8_natBE_append _ _ h11, readNat8_natBE_append _ _ h12,
    readDigest_wire_append _ _ h13, readNat8_natBE_append _ _ h14,
    readNat8_natBE_append _ _ h15, readNat8_natBE_append _ _ h16,
    decodeClaim_encodeClaim_append _ _ h17, readEvidenceBindings_append _ _ h18,
    readQueryObservations_append _ _ h19, readNat8_natBE_append _ _ h20,
    readDigest_wire_append _ _ h21, readCorrectionPaids_append _ _ h22]

theorem readFollowUps_append (followUps : CorrectionFollowUps) (rest : Bytes)
    (h : followUpsWireAdmissible followUps) :
    readFollowUps (encodeFollowUps followUps ++ rest) = some (followUps, rest) := by
  obtain ⟨h1, h2, h3, h4, h5⟩ := h
  simp [readFollowUps, encodeFollowUps, List.append_assoc, readString_encodeString_append _ _ h1,
    readString_encodeString_append _ _ h2, readString_encodeString_append _ _ h3,
    readString_encodeString_append _ _ h4, readNat8_natBE_append _ _ h5]

theorem readExplanation_append (explanation : TransitionExplanation) (rest : Bytes)
    (h : explanationWireAdmissible explanation) :
    readExplanation (encodeExplanation explanation ++ rest) = some (explanation, rest) := by
  obtain ⟨code, transition, rejectReason, requirement, claimId, actionId, inputEvaluationId,
    expectedRevision, resultingRevision⟩ := explanation
  simp only [explanationWireAdmissible] at h
  obtain ⟨h1, h2, h3, h4, h5⟩ := h
  cases transition <;>
    simp [readExplanation, encodeExplanation, List.append_assoc, readByte,
      readExplanationCode_cons, readTransitionKind_cons, readOptionalRejectReason_append,
      readOptionalRequirement_append, readOptionString_encodeOptionString_append _ _ h1,
      readOptionString_encodeOptionString_append _ _ h2,
      readOptionString_encodeOptionString_append _ _ h3,
      readOptionNat_encodeOptionNat_append _ _ h4, readOptionNat_encodeOptionNat_append _ _ h5]

end BlindLedger.Financial.CorrectionTransition
