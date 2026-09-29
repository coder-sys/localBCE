import BlindLedger.Financial.Worker
import BlindLedger.Financial.CodecLaws.CorrectionRecords
import BlindLedger.Financial.Theorems.Correspondence

namespace BlindLedger.Financial

/-! What the worker's frames prove.  The outcome codec round-trips, tag 0 carries
    exactly the specified evaluation of the decoded input, and no response exceeds
    the frame bound (which fits the u32 length prefix). -/

theorem decodeWorkerOutcome_encodeWorkerOutcome (outcome : WorkerOutcome) :
    decodeWorkerOutcome (encodeWorkerOutcome outcome) = some outcome := by
  cases outcome <;> simp [encodeWorkerOutcome, decodeWorkerOutcome]

private theorem idWire {value : String} (h : idWellFormed value = true) :
    stringWireAdmissible value := by
  refine CorrectionTransition.stringWireAdmissible_of_length value ?_
  unfold idWellFormed at h
  simp only [Bool.and_eq_true, decide_eq_true_eq] at h
  have hLen := h.1.2
  unfold maxIdBytes at hLen
  omega

private theorem nat8Wire {value bound : Nat} (h : value ≤ bound) (hBound : bound < 256 ^ 8) :
    nat8WireAdmissible value :=
  Nat.lt_of_le_of_lt h hBound

/-- Every well-formed result whose canonical bytes fit the cap is wire-admissible. -/
private theorem resultWire_of_wellFormed {result : FinancialResult}
    (hWell : financialResultWellFormed result = true)
    (hLen : (rawEncodeFinancialResult result).length ≤ maxTotalEncodedBytes) :
    financialResultWireAdmissible result := by
  have hWell0 := hWell
  have hCents : maxCents < 256 ^ 8 := by decide
  have hRevisions : maxRevision < 256 ^ 8 := by decide
  have hRows : maxRows < 256 ^ 2 := by decide
  unfold financialResultWellFormed contextWellFormed at hWell
  simp only [Bool.and_eq_true, decide_eq_true_eq, List.all_eq_true, amountWellFormed,
    positiveAmountWellFormed, timeWellFormed, revisionWellFormed, digestWellFormed,
    canonicalIdList, and_assoc] at hWell
  obtain ⟨hCtx, hCurrency, _, hAuthorityId, _, hEpoch, hAuthorityDigest, hPackId, hPackDigest,
    _, hBefore, _, hAfter, hEvaluated, _, hRule, hIdsLen, hIdsAll, _, hCompletion, _, hOwed,
    hClaimed, hLawful, hCash, hShortfall, hOverage⟩ := hWell
  refine ⟨hWell0, ⟨idWire (hCtx _ (by simp)), idWire (hCtx _ (by simp)), idWire (hCtx _ (by simp)),
    idWire (hCtx _ (by simp)), idWire (hCtx _ (by simp)), idWire (hCtx _ (by simp)),
    idWire (hCtx _ (by simp)), idWire (hCtx _ (by simp)), ?_⟩, idWire hAuthorityId,
    nat8Wire hEpoch hCents, hAuthorityDigest, idWire hPackId, hPackDigest, nat8Wire hBefore hRevisions,
    nat8Wire hAfter hRevisions, nat8Wire hEvaluated hCents, nat8Wire hRule hRevisions,
    ⟨⟨hIdsLen, Nat.lt_of_le_of_lt hIdsLen hRows⟩, fun value hValue => idWire (hIdsAll value hValue)⟩,
    ?_, nat8Wire hOwed hCents, nat8Wire hClaimed hCents, nat8Wire hLawful hCents,
    nat8Wire hCash hCents, nat8Wire hShortfall hCents, nat8Wire hOverage hCents, hLen⟩
  · rw [hCurrency]
    refine CorrectionTransition.stringWireAdmissible_of_length _ ?_
    have hBytes := CorrectionTransition.string_utf8_length_le "USD"
    have hChars : "USD".toList.length = 3 := by decide
    omega
  · cases hDone : result.completionAt with
    | none => trivial
    | some completion =>
        rw [hDone] at hCompletion
        exact nat8Wire (bound := maxTime) (by simpa using hCompletion) hCents

/-- A result the encoder accepts is wire-admissible, so the decoder returns it. -/
private theorem admissible_of_encoded {result : FinancialResult} {wire : Bytes}
    (h : encodeFinancialResult result = some wire) :
    financialResultWireAdmissible result ∧ wire.length ≤ maxTotalEncodedBytes := by
  unfold encodeFinancialResult at h
  by_cases hWell : financialResultWellFormed result = true
  · by_cases hLen : (rawEncodeFinancialResult result).length ≤ maxTotalEncodedBytes
    · simp only [hWell, hLen, if_true] at h
      obtain rfl := Option.some.inj h
      exact ⟨resultWire_of_wellFormed hWell hLen, hLen⟩
    · simp [hWell, hLen] at h
  · simp [hWell] at h

theorem evaluateWire_evaluated {wire result : Bytes}
    (h : evaluateWire wire = .evaluated result) :
    ∃ input decided,
      decodeFinancialInput wire = some input ∧
      evaluate input = some decided ∧
      satisfiesSpecification input decided ∧
      decodeFinancialResult result = some decided ∧
      result.length ≤ maxTotalEncodedBytes := by
  unfold evaluateWire at h
  cases hIn : decodeFinancialInput wire with
  | none => simp [hIn] at h
  | some input =>
      cases hEval : evaluate input with
      | none => simp [hIn, hEval] at h
      | some decided =>
          cases hEnc : encodeFinancialResult decided with
          | none => simp [hIn, hEval, hEnc] at h
          | some output =>
              simp [hIn, hEval, hEnc] at h
              subst h
              have hAdm := admissible_of_encoded hEnc
              exact ⟨input, decided, rfl, hEval, evaluate_satisfies_specification input decided hEval,
                decodeFinancialResult_of_encodeFinancialResult decided hAdm.1 output hEnc, hAdm.2⟩

theorem workerRespond_length_le (wire : Bytes) :
    (workerRespond wire).length ≤ maxWorkerFrameBytes := by
  unfold workerRespond maxWorkerFrameBytes
  cases hOut : evaluateWire wire with
  | evaluated result =>
      obtain ⟨_, _, _, _, _, _, hLen⟩ := evaluateWire_evaluated hOut
      simp only [encodeWorkerOutcome, List.length_cons]
      omega
  | decodeRejected => simp [encodeWorkerOutcome]
  | evaluationRejected => simp [encodeWorkerOutcome]
  | encodingRejected => simp [encodeWorkerOutcome]

theorem maxWorkerFrameBytes_fits_u32 : maxWorkerFrameBytes < 256 ^ 4 := by
  decide

end BlindLedger.Financial
