import BlindLedger.Financial.CodecLaws.CorrectionRecords

/-! Codec laws for the correction wire: the BLFCMD01 request and the BLFCRES2
    result.  Canonicality (a decoded value re-encodes to the same bytes) holds
    for every byte string.  Round trip and trailing-byte rejection hold for
    every value inside the wire bounds, stated as explicit admissibility
    premises in the style of the BLFIN02/BLFRES02 laws. -/

namespace BlindLedger.Financial.CorrectionTransition

open BlindLedger.Financial
open BlindLedger.Financial.DecisionPackage

set_option maxHeartbeats 2000000 in
theorem readOptionalMutation_of_encode (mutation : Option CorrectionMutation) (bytes rest : Bytes)
    (hMutation : optionalMutationWireAdmissible mutation)
    (hEncode : encodeOptionalMutation mutation = some bytes) :
    readOptionalMutation (bytes ++ rest) = some (mutation, rest) := by
  cases mutation with
  | none =>
      simp [encodeOptionalMutation] at hEncode
      subst hEncode
      rfl
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
      -- Unfold by `delta`: generating `simp`'s equation lemma for a reader this long
      -- exceeds the default heartbeat budget.
      delta readOptionalMutation
      simp [List.append_assoc, readByte, readTransitionKind_cons,
        readCorrectionEffects_append _ _ hEffects, readDependencyFacts_append _ _ hDependencies,
        readFollowUps_append _ _ hFollowUps,
        readSizedBytes_encodeSizedBytes_append _ _ hInputLength,
        readSizedBytes_encodeSizedBytes_append _ _ hResultLength,
        decodeFinancialInput_rawEncode _ hInput, decodeFinancialResult_rawEncode _ hResult,
        decodeDetermination_encodeDetermination_append _ _ hDetermination,
        decodeAction_encodeAction_append _ _ hAction, decodeCase_encodeCase_append _ _ hCase,
        readString_encodeString_append _ _ h9, readBool_encodeBool_append,
        readString_encodeString_append _ _ h10, decodeActionStatus_encodeActionStatus,
        readNat8_natBE_append _ _ h11, readOptionString_encodeOptionString_append _ _ h12,
        readNat8_natBE_append _ _ h13, readNat8_natBE_append _ _ h14,
        readDigest_wire_append _ _ h15, readString_encodeString_append _ _ h16,
        readString_encodeString_append _ _ h17, readString_encodeString_append _ _ h18,
        readNat8_natBE_append _ _ h19, readNat8_natBE_append _ _ h20,
        readNat8_natBE_append _ _ h21]

/-! Whole-wire laws.  The parse lemmas read an encoding followed by any tail. -/

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
  unfold encodeCorrectionTransitionRequest at hEncode
  rcases hBody : encodeInputBody request with _ | body
  · simp [hBody] at hEncode
  simp [hBody] at hEncode
  obtain ⟨hLength, rfl⟩ := hEncode
  refine ⟨hLength, ?_⟩
  unfold encodeInputBody at hBody
  cases hCommandWellFormed : commandWellFormed request.command
  · simp [hCommandWellFormed] at hBody
  cases hReceiptWellFormed : evaluationReceiptWellFormed request.currentReceipt
  · simp [hCommandWellFormed, hReceiptWellFormed] at hBody
  -- Keep the appends left-nested so the receipt field stays the last operand.
  simp [-List.append_assoc, hCommandWellFormed, hReceiptWellFormed, hInput.1,
    encodeFinancialInput_rawEncode _ hInput] at hBody
  subst hBody
  have hReceiptLength := length_le_of_append_sized _ _ hLength
  delta parseCorrectionTransitionRequest
  simp [List.append_assoc, isPrefixOf_append_self,
    readNatBE_natBE_append 2 1 _ (by decide),
    readString_encodeString_append _ _ correctionTransitionContract_wireAdmissible,
    readString_encodeString_append _ _ h1, readString_encodeString_append _ _ h2,
    readString_encodeString_append _ _ h3, readString_encodeString_append _ _ h4,
    readString_encodeString_append _ _ h5, readString_encodeString_append _ _ h6,
    readNat8_natBE_append _ _ h7, readDigest_wire_append _ _ h8, readNat8_natBE_append _ _ h9,
    readString_encodeString_append _ _ h10, readDigest_wire_append _ _ h11,
    readNat8_natBE_append _ _ h12, readNat8_natBE_append _ _ h13,
    readActionLookup_append _ _ h14, readQueryObservations_append _ _ h15,
    readNat8_natBE_append _ _ h16, readDigest_wire_append _ _ h17,
    readSizedBytes_encodeSizedBytes_append _ _ hInputLength,
    readSizedBytes_encodeSizedBytes_append _ _ hReceiptLength,
    decodeFinancialInput_rawEncode _ hInput, hReceiptRead]

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
          readNatBE_natBE_append 2 2 _ (by decide), readByte,
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
