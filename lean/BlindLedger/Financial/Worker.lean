import BlindLedger.Financial.FastEncode
import BlindLedger.Financial.Evaluation

namespace BlindLedger.Financial

/-! Evaluator worker frames. On the pipe each frame is a u32 big-endian length
    and its bytes. A request frame is one BLFIN02 input. A response frame is one
    outcome: tag 0 then the BLFRES02 result, or the single byte 1 (decode),
    2 (evaluation) or 3 (encoding) rejection. The worker adds no policy; it decodes with the length-free twin
    `Fast.decodeFinancialInput`, proved equal to `decodeFinancialInput`. -/

inductive WorkerOutcome where
  | evaluated (result : Bytes)
  | decodeRejected
  | evaluationRejected
  | encodingRejected
deriving DecidableEq, Repr

def evaluateWire (wire : Bytes) : WorkerOutcome :=
  match Fast.decodeFinancialInput wire with
  | none => .decodeRejected
  | some input =>
      match evaluate input with
      | none => .evaluationRejected
      | some result =>
          match encodeFinancialResult result with
          | none => .encodingRejected
          | some output => .evaluated output

def encodeWorkerOutcome : WorkerOutcome → Bytes
  | .evaluated result => UInt8.ofNat 0 :: result
  | .decodeRejected => [UInt8.ofNat 1]
  | .evaluationRejected => [UInt8.ofNat 2]
  | .encodingRejected => [UInt8.ofNat 3]

def decodeWorkerOutcome : Bytes → Option WorkerOutcome
  | [] => none
  | tag :: rest =>
      if tag.toNat = 0 then some (.evaluated rest)
      else if rest ≠ [] then none
      else if tag.toNat = 1 then some .decodeRejected
      else if tag.toNat = 2 then some .evaluationRejected
      else if tag.toNat = 3 then some .encodingRejected
      else none

/-- The worker's whole policy: one BLFIN02 frame in, one outcome frame out. -/
def workerRespond (wire : Bytes) : Bytes := encodeWorkerOutcome (evaluateWire wire)

theorem financialInputWellFormed_of_decodeFinancialInput {bytes : Bytes} {input : FinancialInput}
    (h : decodeFinancialInput bytes = some input) : financialInputWellFormed input = true := by
  rw [← Fast.decodeFinancialInputFast_eq] at h
  unfold Fast.decodeFinancialInput Fast.decodeInputWith at h
  split at h
  · simp at h
  · obtain ⟨x, hx⟩ := Fast.parseInputWith_some h
    by_cases hw : financialInputWellFormed x = true
    · simp only [hw, if_true] at hx
      rcases hE : encodeFinancialInput x with _ | c <;> simp only [hE] at hx
      · simp at hx
      · by_cases hc : c = bytes
        · simp [hc] at hx; subst hx; exact hw
        · simp [hc] at hx
    · simp [hw] at hx

theorem evaluate_eq_evaluateWellFormed {input : FinancialInput}
    (h : financialInputWellFormed input = true) : evaluate input = evaluateWellFormed input := by
  simp [evaluate, h]

/-- The frame arrives as a `ByteArray`; `Fast.decodeFinancialInputBA₂` is proved equal to the list
    decoder on `wire.toList`, and its input is already well-formed, so this is `workerRespond`
    with one well-formedness pass and no second large list. -/
def workerRespondBA (wire : ByteArray) : Bytes :=
  encodeWorkerOutcome
    (match Fast.decodeFinancialInputBA₂ wire with
      | none => .decodeRejected
      | some input =>
          match evaluateWellFormed input with
          | none => .evaluationRejected
          | some result =>
              match encodeFinancialResult result with
              | none => .encodingRejected
              | some output => .evaluated output)

theorem workerRespondBA_eq (wire : ByteArray) : workerRespondBA wire = workerRespond wire.toList := by
  unfold workerRespondBA workerRespond evaluateWire
  rw [Fast.decodeFinancialInputBA₂_eq]
  cases hd : Fast.decodeFinancialInput wire.toList with
  | none => rfl
  | some input =>
    have hw := financialInputWellFormed_of_decodeFinancialInput
      (by rw [← Fast.decodeFinancialInputFast_eq]; exact hd)
    simp only [evaluate_eq_evaluateWellFormed hw]

def maxWorkerFrameBytes : Nat := maxTotalEncodedBytes + 1

end BlindLedger.Financial
