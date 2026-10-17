import BlindLedger.Financial.CursorCorrection
import BlindLedger.Financial.FastEncode

/-! `ByteArray` twins of the `BLFCMD03` canonical re-encode and the `BLFCRES3` result encoder.  The
    reference encoders join their fields with left-nested `List` `++`, which copies the growing
    prefix, so the embedded input (up to megabytes) was copied once per later field.  Each twin
    builds the small head and tail as lists and appends the large input and receipt as arrays;
    its `_eq` theorem states it is the reference encoding converted with `List.toByteArray`. -/

namespace BlindLedger.Financial.Fast

open BlindLedger.Financial.CorrectionTransition BlindLedger.Financial.DecisionPackage

theorem size_toByteArray (l : List UInt8) : l.toByteArray.size = l.length := by
  rw [← length_toList, ← toByteArray_toList l.toByteArray]
  simp [toList_eq]

def encodeFinancialInputBA (input : FinancialInput) : Option ByteArray :=
  if financialInputWellFormed input then
    let wire := rawEncodeFinancialInputBA input
    if wire.size ≤ maxTotalEncodedBytes then some wire else none
  else none

theorem encodeFinancialInputBA_eq (input : FinancialInput) :
    encodeFinancialInputBA input = (encodeFinancialInput input).map List.toByteArray := by
  unfold encodeFinancialInputBA encodeFinancialInput
  by_cases hw : financialInputWellFormed input = true
  · simp only [hw, if_true, rawEncodeFinancialInputBA_eq, size_toByteArray]
    split <;> simp
  · simp [hw]

def sizedBA (value : ByteArray) : ByteArray := (natBE 4 value.size).toByteArray ++ value

theorem sizedBA_eq (l : Bytes) : sizedBA l.toByteArray = (encodeSizedBytes l).toByteArray := by
  simp [sizedBA, encodeSizedBytes, List.toByteArray_append]

/-- Everything of the request body before the two length-prefixed sections. -/
def inputBodyHead (request : CorrectionTransitionRequest) : Bytes :=
  correctionTransitionInputMagic ++ natBE 2 3 ++
    encodeString correctionTransitionContract ++
    encodeString request.command.itemId ++ encodeString request.command.claimId ++
    encodeString request.command.actionId ++ encodeString request.command.actorId ++
    encodeString request.command.actorRole ++ encodeString request.command.currentAuthorityId ++
    natBE 8 request.command.currentAuthorityEpoch ++ encodeDigest request.command.currentAuthorityDigest ++
    natBE 8 request.command.expectedRevision ++ encodeString request.command.evaluationId ++
    encodeDigest request.command.evaluationResultDigest ++ natBE 8 request.command.decisionAtMs ++
    natBE 8 request.command.ownerNowMs ++ encodeActionLookup request.command.actionLookup ++
    encodeQueryObservations request.command.queryObservations ++
    natBE 8 request.command.currentEventSequence ++
    encodeDigest request.command.previousHistoryHead ++
    encodeList encodePaymentLink request.command.paymentLinks

def encodeCorrectionTransitionRequestBA (request : CorrectionTransitionRequest) : Option ByteArray := do
  if !commandWellFormed request.command ||
      !financialInputWellFormed request.currentInput ||
      !evaluationReceiptWellFormed request.currentReceipt then
    none
  let inputBytes ← encodeFinancialInputBA request.currentInput
  let body := (inputBodyHead request).toByteArray ++ sizedBA inputBytes ++
    sizedBA (encodeEvaluationReceipt request.currentReceipt).toByteArray
  if body.size > maxCorrectionTransitionBytes then none else pure body

theorem sizedBA_eq_append (H ib rc : Bytes) :
    H.toByteArray ++ sizedBA ib.toByteArray ++ sizedBA rc.toByteArray =
      (H ++ encodeSizedBytes ib ++ encodeSizedBytes rc).toByteArray := by
  simp only [sizedBA_eq, List.toByteArray_append]

theorem gate_gt (n : Nat) (l : Bytes) :
    (if l.toByteArray.size > n then (none : Option ByteArray) else some l.toByteArray) =
      (if l.length > n then none else some l).map List.toByteArray := by
  rw [size_toByteArray]; split <;> simp

theorem gate_le (n : Nat) (l : Bytes) :
    (if l.toByteArray.size ≤ n then some l.toByteArray else none) =
      (if l.length ≤ n then some l else none).map List.toByteArray := by
  rw [size_toByteArray]; split <;> simp

theorem encodeInputBody_head (request : CorrectionTransitionRequest) :
    encodeInputBody request = (do
      if !commandWellFormed request.command ||
          !financialInputWellFormed request.currentInput ||
          !evaluationReceiptWellFormed request.currentReceipt then
        none
      let inputBytes ← encodeFinancialInput request.currentInput
      pure (inputBodyHead request ++ encodeSizedBytes inputBytes ++
        encodeSizedBytes (encodeEvaluationReceipt request.currentReceipt))) := rfl

theorem encodeCorrectionTransitionRequestBA_eq (request : CorrectionTransitionRequest) :
    encodeCorrectionTransitionRequestBA request =
      (encodeCorrectionTransitionRequest request).map List.toByteArray := by
  unfold encodeCorrectionTransitionRequestBA encodeCorrectionTransitionRequest
  rw [encodeInputBody_head]
  by_cases h : (!commandWellFormed request.command ||
      !financialInputWellFormed request.currentInput ||
      !evaluationReceiptWellFormed request.currentReceipt) = true
  · simp [h]
  · cases hI : encodeFinancialInput request.currentInput with
    | none => simp [h, encodeFinancialInputBA_eq, hI]
    | some inputBytes =>
      simp only [h, encodeFinancialInputBA_eq, hI, Bool.false_eq_true, if_false, Option.map_some,
        Option.bind_eq_bind, Option.bind_some, sizedBA_eq_append, Option.pure_def]
      exact gate_gt _ _

theorem beq_toByteArray_iff (l : Bytes) (ba : ByteArray) : (l.toByteArray == ba) = true ↔ l = ba.toList := by
  rw [beq_iff, toByteArray_eq_iff]

/-- `Cursor.decodeCorrectionTransitionRequest` with the canonical re-encode on the array twin. -/
def decodeCorrectionTransitionRequestBA₂ (ba : ByteArray) : Option CorrectionTransitionRequest :=
  if ba.size > maxCorrectionTransitionBytes then none else
  (Cursor.parseCorrectionTransitionRequest ba).bind fun (request, i) =>
    if i = ba.size ∧ encodeCorrectionTransitionRequestBA request == some ba then some request
    else none

theorem decodeCorrectionTransitionRequestBA₂_eq (ba : ByteArray) :
    decodeCorrectionTransitionRequestBA₂ ba = Cursor.decodeCorrectionTransitionRequest ba := by
  unfold decodeCorrectionTransitionRequestBA₂ Cursor.decodeCorrectionTransitionRequest
  by_cases hs : ba.size > maxCorrectionTransitionBytes
  · simp [hs]
  · simp only [hs, if_false]
    congr 1
    funext p
    rw [encodeCorrectionTransitionRequestBA_eq]
    cases hE : encodeCorrectionTransitionRequest p.1 with
    | none => simp
    | some l => simp [beq_toByteArray_iff]

def mutationHead (mutation : CorrectionMutation) : Bytes :=
  [UInt8.ofNat 1, encodeTransitionKind mutation.transition] ++
    encodeList (fun effect => [encodeCorrectionEffect effect]) mutation.orderedEffects ++
    encodeDependencyFacts mutation.dependencies ++ encodeFollowUps mutation.followUps

/-- The pieces after the two sized sections, in order; `mutationTail` joins them left-nested like the reference. -/
def mutationTailPieces (mutation : CorrectionMutation) : List Bytes :=
  [encodeDetermination mutation.determination, encodeAction mutation.action,
    encodeCase mutation.caseDelta.record, encodeString mutation.caseDelta.contractualAccountability,
    encodeBool mutation.caseDelta.completionConditionsAmountSatisfied,
    encodeBool mutation.caseDelta.completionConditionsReportingComplete,
    encodeBool mutation.caseDelta.completionConditionsDeliveryAcknowledgedOrNotRequired,
    encodeBool mutation.caseDelta.inserted, encodeString mutation.outbox.actionId,
    [encodeActionStatus mutation.outbox.status], natBE 8 mutation.outbox.attempt,
    encodeOptionString mutation.outbox.acknowledgmentReference, natBE 8 mutation.outbox.updatedAtMs,
    natBE 8 mutation.event.sequence, encodeDigest mutation.event.previousHead,
    encodeString mutation.event.aggregateType, encodeString mutation.event.aggregateId,
    encodeString mutation.event.kind, natBE 8 mutation.event.beforeRevision,
    natBE 8 mutation.event.afterRevision, natBE 8 mutation.event.committedAtMs]

def mutationTail (mutation : CorrectionMutation) : Bytes :=
  (mutationTailPieces mutation).foldl (· ++ ·) []

theorem foldl_append_regroup (Y : Bytes) (l : List Bytes) :
    l.foldl (· ++ ·) Y = Y ++ l.foldl (· ++ ·) [] := by
  induction l generalizing Y with
  | nil => simp
  | cons a t ih => simp only [List.foldl_cons, List.nil_append, ih (Y ++ a), ih a, List.append_assoc]

def encodeOptionalMutationBA : Option CorrectionMutation → Option ByteArray
  | none => some [UInt8.ofNat 0].toByteArray
  | some mutation => do
      let inputBytes ← encodeFinancialInputBA mutation.resultingInput
      let resultBytes ← (encodeFinancialResult mutation.resultingResult).map List.toByteArray
      pure ((mutationHead mutation).toByteArray ++ sizedBA inputBytes ++ sizedBA resultBytes ++
        (mutationTail mutation).toByteArray)

theorem encodeOptionalMutation_head (mutation : CorrectionMutation) :
    encodeOptionalMutation (some mutation) = (do
      let inputBytes ← encodeFinancialInput mutation.resultingInput
      let resultBytes ← encodeFinancialResult mutation.resultingResult
      pure (mutationHead mutation ++ encodeSizedBytes inputBytes ++ encodeSizedBytes resultBytes ++
        mutationTail mutation)) := by
  dsimp only [encodeOptionalMutation]
  generalize encodeFinancialInput mutation.resultingInput = oi
  generalize encodeFinancialResult mutation.resultingResult = orr
  cases oi with
  | none => simp
  | some ib =>
    cases orr with
    | none => simp
    | some rb =>
      exact congrArg some (foldl_append_regroup (mutationHead mutation ++ encodeSizedBytes ib ++
        encodeSizedBytes rb) (mutationTailPieces mutation))

theorem encodeOptionalMutationBA_eq (mutation : Option CorrectionMutation) :
    encodeOptionalMutationBA mutation = (encodeOptionalMutation mutation).map List.toByteArray := by
  cases mutation with
  | none => simp [encodeOptionalMutationBA, encodeOptionalMutation]
  | some m =>
    rw [encodeOptionalMutation_head]
    unfold encodeOptionalMutationBA
    cases hI : encodeFinancialInput m.resultingInput <;> simp [encodeFinancialInputBA_eq, hI]
    cases hR : encodeFinancialResult m.resultingResult <;> simp
    simp only [sizedBA_eq, ByteArray.append_assoc]

def resultHead (result : CorrectionTransitionResult) : Bytes :=
  correctionTransitionResultMagic ++ natBE 2 3 ++
    [match result.status with
      | .ACCEPTED => UInt8.ofNat 1
      | .DUPLICATE => UInt8.ofNat 2
      | .REJECTED => UInt8.ofNat 3] ++
    encodeString correctionTransitionContract ++
    encodeOptionalRejectReason result.rejectReason ++ encodeExplanation result.explanation ++
    encodeOptionString result.actionId ++ encodeOptionString result.determinationId

def encodeCorrectionTransitionResultBA (result : CorrectionTransitionResult) : Option ByteArray := do
  if !resultWellFormed result then none
  let mutationBytes ← encodeOptionalMutationBA result.mutation
  let wire := (resultHead result).toByteArray ++ mutationBytes
  if wire.size ≤ maxCorrectionTransitionBytes then some wire else none

theorem encodeCorrectionTransitionResult_head (result : CorrectionTransitionResult) :
    encodeCorrectionTransitionResult result = (do
      if !resultWellFormed result then none
      let mutationBytes ← encodeOptionalMutation result.mutation
      let wire := resultHead result ++ mutationBytes
      if wire.length ≤ maxCorrectionTransitionBytes then some wire else none) := rfl

theorem encodeCorrectionTransitionResultBA_eq (result : CorrectionTransitionResult) :
    encodeCorrectionTransitionResultBA result =
      (encodeCorrectionTransitionResult result).map List.toByteArray := by
  unfold encodeCorrectionTransitionResultBA
  rw [encodeCorrectionTransitionResult_head]
  generalize resultHead result = H
  by_cases h : resultWellFormed result = true
  · simp only [h, Bool.not_true, Bool.false_eq_true, if_false, Option.bind_eq_bind]
    cases hM : encodeOptionalMutation result.mutation with
    | none => simp [encodeOptionalMutationBA_eq, hM]
    | some mb =>
      simp only [encodeOptionalMutationBA_eq, hM, Option.map_some, Option.bind_some,
        ← List.toByteArray_append]
      exact gate_le _ _
  · simp [h]

end BlindLedger.Financial.Fast
