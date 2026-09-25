import BlindLedger.Financial.CodecLaws
import BlindLedger.Financial.CorrectionTransition.Codec

/-! Codec laws for the correction wire: the BLFCMD01 request and the BLFCRES2
    result.  Canonicality (a decoded value re-encodes to the same bytes) holds
    for every byte string.  Round trip and trailing-byte rejection hold for
    every value inside the wire bounds, stated as explicit admissibility
    premises in the style of the BLFIN02/BLFRES02 laws. -/

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

theorem isPrefixOf_append_self (magic rest : Bytes) : magic.isPrefixOf (magic ++ rest) = true := by
  induction magic with
  | nil => simp
  | cons byte magic ih => simp [List.isPrefixOf, ih]

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
  cases value; simp [readTransitionKind, encodeTransitionKind, readByte]

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
    digestWireAdmissible command.previousHistoryHead

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
    nat8WireAdmissible facts.currentEventSequence ∧ digestWireAdmissible facts.previousHistoryHead

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
    readString_encodeString_append, readBool_encodeBool_append, readNat8_natBE_append,
    readOptionString_encodeOptionString_append, readDigest_wire_append, hWellFormed,
    h1, h2, h3, h4, h5]

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
        readString_encodeString_append, readNat8_natBE_append, readDigest_wire_append,
        decodeDecision_encodeDecision, h1, h2, h3, h4, h5, h6, h7, h8, h9, h10, h11, h12, h13,
        h14, h15]

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
  simp [readOwnerEvaluationResult, encodeOwnerEvaluationResult, List.append_assoc,
    readString_encodeString_append, readNat8_natBE_append, readBool_encodeBool_append, hIdsRead,
    h1, h2, h3, h4, h6, h7, h8, h9, h10, h11, h12, h13, h14, h15, h16]

set_option maxHeartbeats 1000000 in
theorem readEvaluationReceipt_append (receipt : EvaluationReceipt) (rest : Bytes)
    (h : receiptWireAdmissible receipt) :
    readEvaluationReceipt (encodeEvaluationReceipt receipt ++ rest) = some (receipt, rest) := by
  obtain ⟨h1, h2, h3, h4, h5, h6, h7, h8, h9, h10, h11, h12, h13, h14, h15, h16, h17⟩ := h
  simp [readEvaluationReceipt, encodeEvaluationReceipt, readPackageScope, encodePackageScope,
    readReceiptControlPack, encodeReceiptControlPack, readReceiptAuthority,
    encodeReceiptAuthority, List.append_assoc, readString_encodeString_append,
    readNat8_natBE_append, readDigest_wire_append, readEvidenceBindings_append _ _ h10,
    readOptionalDigest_append _ _ h11, readOwnerEvaluationResult_append _ _ h14,
    h1, h2, h3, h4, h5, h6, h7, h8, h9, h12, h13, h15, h16, h17]

set_option maxHeartbeats 1000000 in
theorem readDependencyFacts_append (facts : CorrectionDependencyFacts) (rest : Bytes)
    (h : dependencyFactsWireAdmissible facts) :
    readDependencyFacts (encodeDependencyFacts facts ++ rest) = some (facts, rest) := by
  obtain ⟨h1, h2, h3, h4, h5, h6, h7, h8, h9, h10, h11, h12, h13, h14, h15, h16, h17, h18,
    h19, h20, h21⟩ := h
  simp [readDependencyFacts, encodeDependencyFacts, List.append_assoc,
    readString_encodeString_append, readNat8_natBE_append, readDigest_wire_append,
    decodeClaim_encodeClaim_append _ _ h17, readEvidenceBindings_append _ _ h18,
    readQueryObservations_append _ _ h19, h1, h2, h3, h4, h5, h6, h7, h8, h9, h10, h11, h12,
    h13, h14, h15, h16, h20, h21]

theorem readFollowUps_append (followUps : CorrectionFollowUps) (rest : Bytes)
    (h : followUpsWireAdmissible followUps) :
    readFollowUps (encodeFollowUps followUps ++ rest) = some (followUps, rest) := by
  obtain ⟨h1, h2, h3, h4, h5⟩ := h
  simp [readFollowUps, encodeFollowUps, List.append_assoc, readString_encodeString_append,
    readNat8_natBE_append, h1, h2, h3, h4, h5]

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
      readOptionalRequirement_append, readOptionString_encodeOptionString_append,
      readOptionNat_encodeOptionNat_append, h1, h2, h3, h4, h5]

set_option maxHeartbeats 1000000 in
theorem readOptionalMutation_of_encode (mutation : Option CorrectionMutation) (bytes rest : Bytes)
    (hMutation : optionalMutationWireAdmissible mutation)
    (hEncode : encodeOptionalMutation mutation = some bytes) :
    readOptionalMutation (bytes ++ rest) = some (mutation, rest) := by
  cases mutation with
  | none =>
      simp [encodeOptionalMutation] at hEncode
      subst hEncode
      simp [readOptionalMutation, readByte]
  | some mutation =>
      have hAdmissible : mutationWireAdmissible mutation := hMutation
      obtain ⟨hEffects, hDependencies, hFollowUps, hInput, hResult, hDetermination, hAction,
        hCase, h9, h10, h11, h12, h13, h14, h15, h16, h17, h18, h19, h20, h21⟩ := hAdmissible
      have hInputLength : (rawEncodeFinancialInput mutation.resultingInput).length ≤
          maxCorrectionTransitionBytes := hInput.2.2.2.2.2.2.2.2.2.2.2.2.2.2
      have hResultLength : (rawEncodeFinancialResult mutation.resultingResult).length ≤
          maxCorrectionTransitionBytes := hResult.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2
      simp [encodeOptionalMutation, encodeFinancialInput_rawEncode _ hInput,
        encodeFinancialResult_rawEncode _ hResult] at hEncode
      subst hEncode
      simp [readOptionalMutation, List.append_assoc, readByte, readTransitionKind_cons,
        readCorrectionEffects_append _ _ hEffects, readDependencyFacts_append _ _ hDependencies,
        readFollowUps_append _ _ hFollowUps,
        readSizedBytes_encodeSizedBytes_append _ _ hInputLength,
        readSizedBytes_encodeSizedBytes_append _ _ hResultLength,
        decodeFinancialInput_rawEncode _ hInput, decodeFinancialResult_rawEncode _ hResult,
        decodeDetermination_encodeDetermination_append _ _ hDetermination,
        decodeAction_encodeAction_append _ _ hAction, decodeCase_encodeCase_append _ _ hCase,
        readString_encodeString_append, readBool_encodeBool_append, readNat8_natBE_append,
        readOptionString_encodeOptionString_append, readDigest_wire_append,
        decodeActionStatus_encodeActionStatus, h9, h10, h11, h12, h13, h14, h15, h16, h17, h18,
        h19, h20, h21]

/-! Whole-wire laws.  The parse lemmas read an encoding followed by any tail. -/

set_option maxHeartbeats 2000000 in
theorem parseCorrectionTransitionRequest_of_encode (request : CorrectionTransitionRequest)
    (bytes tail : Bytes) (hRequest : requestWireAdmissible request)
    (hEncode : encodeCorrectionTransitionRequest request = some bytes) :
    bytes.length ≤ maxCorrectionTransitionBytes ∧
      parseCorrectionTransitionRequest (bytes ++ tail) = some (request, tail) := by
  obtain ⟨hCommand, hInput, hReceipt⟩ := hRequest
  obtain ⟨h1, h2, h3, h4, h5, h6, h7, h8, h9, h10, h11, h12, h13, h14, h15, h16, h17⟩ :=
    hCommand
  have hInputLength : (rawEncodeFinancialInput request.currentInput).length ≤
      maxCorrectionTransitionBytes := hInput.2.2.2.2.2.2.2.2.2.2.2.2.2.2
  have hReceiptRead : readEvaluationReceipt (encodeEvaluationReceipt request.currentReceipt) =
      some (request.currentReceipt, []) := by
    simpa using readEvaluationReceipt_append request.currentReceipt [] hReceipt
  unfold encodeCorrectionTransitionRequest encodeInputBody at hEncode
  cases hCommandWellFormed : commandWellFormed request.command
  · simp [hCommandWellFormed] at hEncode
  cases hReceiptWellFormed : evaluationReceiptWellFormed request.currentReceipt
  · simp [hCommandWellFormed, hReceiptWellFormed] at hEncode
  simp [hCommandWellFormed, hReceiptWellFormed, hInput.1, length_encodeSizedBytes,
    encodeFinancialInput_rawEncode _ hInput] at hEncode
  obtain ⟨hLength, rfl⟩ := hEncode
  have hReceiptLength : (encodeEvaluationReceipt request.currentReceipt).length ≤
      maxCorrectionTransitionBytes := by omega
  refine ⟨by simpa [length_encodeSizedBytes] using hLength, ?_⟩
  simp [parseCorrectionTransitionRequest, List.append_assoc, isPrefixOf_append_self,
    List.drop_left, readNatBE_natBE_append 2 1 _ (by decide), readString_encodeString_append,
    correctionTransitionContract_wireAdmissible, readNat8_natBE_append, readDigest_wire_append,
    readActionLookup_append _ _ h14, readQueryObservations_append _ _ h15,
    readSizedBytes_encodeSizedBytes_append _ _ hInputLength,
    readSizedBytes_encodeSizedBytes_append _ _ hReceiptLength,
    decodeFinancialInput_rawEncode _ hInput, hReceiptRead, h1, h2, h3, h4, h5, h6, h7, h8, h9,
    h10, h11, h12, h13, h16, h17]

set_option maxHeartbeats 2000000 in
theorem parseCorrectionTransitionResult_of_encode (result : CorrectionTransitionResult)
    (bytes tail : Bytes) (hResult : resultWireAdmissible result)
    (hEncode : encodeCorrectionTransitionResult result = some bytes) :
    bytes.length ≤ maxCorrectionTransitionBytes ∧
      parseCorrectionTransitionResult (bytes ++ tail) = some (result, tail) := by
  obtain ⟨hExplanation, hActionId, hDeterminationId, hMutation⟩ := hResult
  unfold encodeCorrectionTransitionResult at hEncode
  cases hWellFormed : resultWellFormed result
  · simp [hWellFormed] at hEncode
  cases hMutationBytes : encodeOptionalMutation result.mutation with
  | none => simp [hWellFormed, hMutationBytes] at hEncode
  | some mutationBytes =>
      have hMutationRead :=
        readOptionalMutation_of_encode result.mutation mutationBytes tail hMutation hMutationBytes
      simp [hWellFormed, hMutationBytes] at hEncode
      obtain ⟨hLength, rfl⟩ := hEncode
      refine ⟨by simpa using hLength, ?_⟩
      obtain ⟨status, rejectReason, explanation, actionId, determinationId, mutation⟩ := result
      dsimp only at hExplanation hActionId hDeterminationId hMutationRead
      cases status <;>
        simp [parseCorrectionTransitionResult, List.append_assoc, isPrefixOf_append_self,
          List.drop_left, readNatBE_natBE_append 2 2 _ (by decide), readByte,
          readString_encodeString_append, correctionTransitionContract_wireAdmissible,
          readOptionalRejectReason_append, readExplanation_append _ _ hExplanation,
          readOptionString_encodeOptionString_append, hActionId, hDeterminationId,
          hMutationRead]

/-- P1: an admissible request round-trips through its canonical encoding. -/
theorem decodeCorrectionTransitionRequest_of_encode (request : CorrectionTransitionRequest)
    (bytes : Bytes) (hRequest : requestWireAdmissible request)
    (hEncode : encodeCorrectionTransitionRequest request = some bytes) :
    decodeCorrectionTransitionRequest bytes = some request := by
  obtain ⟨hLength, hParse⟩ :=
    parseCorrectionTransitionRequest_of_encode request bytes [] hRequest hEncode
  rw [List.append_nil] at hParse
  simp [decodeCorrectionTransitionRequest, hParse, hEncode, Nat.not_lt.mpr hLength]

/-- P2: every accepted request is canonical; no second byte string decodes to it. -/
theorem encodeCorrectionTransitionRequest_of_decode (bytes : Bytes)
    (request : CorrectionTransitionRequest)
    (hDecode : decodeCorrectionTransitionRequest bytes = some request) :
    encodeCorrectionTransitionRequest request = some bytes := by
  unfold decodeCorrectionTransitionRequest at hDecode
  split at hDecode
  · simp at hDecode
  · split at hDecode
    · split at hDecode
      · rename_i hCanonical
        cases hDecode
        exact hCanonical
      · simp at hDecode
    · simp at hDecode

/-- P3: bytes after an admissible request are rejected. -/
theorem decodeCorrectionTransitionRequest_rejects_trailing
    (request : CorrectionTransitionRequest) (bytes tail : Bytes)
    (hRequest : requestWireAdmissible request)
    (hEncode : encodeCorrectionTransitionRequest request = some bytes) (hTail : tail ≠ []) :
    decodeCorrectionTransitionRequest (bytes ++ tail) = none := by
  obtain ⟨-, hParse⟩ := parseCorrectionTransitionRequest_of_encode request bytes tail hRequest hEncode
  cases tail with
  | nil => exact absurd rfl hTail
  | cons head rest =>
      unfold decodeCorrectionTransitionRequest
      split
      · rfl
      · simp [hParse]

/-- P1: an admissible result round-trips through its canonical encoding. -/
theorem decodeCorrectionTransitionResult_of_encode (result : CorrectionTransitionResult)
    (bytes : Bytes) (hResult : resultWireAdmissible result)
    (hEncode : encodeCorrectionTransitionResult result = some bytes) :
    decodeCorrectionTransitionResult bytes = some result := by
  obtain ⟨hLength, hParse⟩ :=
    parseCorrectionTransitionResult_of_encode result bytes [] hResult hEncode
  rw [List.append_nil] at hParse
  simp [decodeCorrectionTransitionResult, hParse, hEncode, Nat.not_lt.mpr hLength]

/-- P2: every accepted result is canonical; no second byte string decodes to it. -/
theorem encodeCorrectionTransitionResult_of_decode (bytes : Bytes)
    (result : CorrectionTransitionResult)
    (hDecode : decodeCorrectionTransitionResult bytes = some result) :
    encodeCorrectionTransitionResult result = some bytes := by
  unfold decodeCorrectionTransitionResult at hDecode
  split at hDecode
  · simp at hDecode
  · split at hDecode
    · split at hDecode
      · rename_i hCanonical
        cases hDecode
        exact hCanonical
      · simp at hDecode
    · simp at hDecode

/-- P3: bytes after an admissible result are rejected. -/
theorem decodeCorrectionTransitionResult_rejects_trailing
    (result : CorrectionTransitionResult) (bytes tail : Bytes)
    (hResult : resultWireAdmissible result)
    (hEncode : encodeCorrectionTransitionResult result = some bytes) (hTail : tail ≠ []) :
    decodeCorrectionTransitionResult (bytes ++ tail) = none := by
  obtain ⟨-, hParse⟩ := parseCorrectionTransitionResult_of_encode result bytes tail hResult hEncode
  cases tail with
  | nil => exact absurd rfl hTail
  | cons head rest =>
      unfold decodeCorrectionTransitionResult
      split
      · rfl
      · simp [hParse]

end BlindLedger.Financial.CorrectionTransition
