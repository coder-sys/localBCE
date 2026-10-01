import BlindLedger.Financial.FastEncode
import BlindLedger.Financial.Evaluation
import BlindLedger.Financial.ReadUpTo
import BlindLedger.Financial.Payment.Codec

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

/-- The worker's whole policy, one frame in and one answer out: a frame that starts with the payment
    magic is one payment step; any other is one BLFIN02 input. -/
def workerRespond (wire : Bytes) : Bytes :=
  if Payment.paymentMagic.isPrefixOf wire then Payment.paymentRespond wire
  else encodeWorkerOutcome (evaluateWire wire)

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
    with one well-formedness pass and no second large list. The payment test reads only the first
    bytes of the array, so an evaluator frame is never copied into a list. -/
def workerRespondBA (wire : ByteArray) : Bytes :=
  if Payment.paymentMagic.isPrefixOf (wire.extract 0 Payment.paymentMagic.length).toList then
    Payment.paymentRespond wire.toList
  else
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

theorem magic_prefix_extract (wire : ByteArray) :
    Payment.paymentMagic.isPrefixOf (wire.extract 0 Payment.paymentMagic.length).toList =
      Payment.paymentMagic.isPrefixOf wire.toList := by
  have hx : (wire.extract 0 Payment.paymentMagic.length).toList =
      wire.toList.take Payment.paymentMagic.length := by
    rw [Fast.toList_eq, ByteArray.data_extract, Array.toList_extract, Fast.toList_eq]
    simp
  rw [hx, Bool.eq_iff_iff, List.isPrefixOf_iff_prefix, List.isPrefixOf_iff_prefix, List.prefix_take_iff]
  exact ⟨fun h => h.1, fun h => ⟨h, Nat.le_refl _⟩⟩

theorem workerRespondBA_eq (wire : ByteArray) : workerRespondBA wire = workerRespond wire.toList := by
  unfold workerRespondBA workerRespond evaluateWire
  rw [magic_prefix_extract]
  split
  · rfl
  rw [Fast.decodeFinancialInputBA₂_eq]
  cases hd : Fast.decodeFinancialInput wire.toList with
  | none => rfl
  | some input =>
    have hw := financialInputWellFormed_of_decodeFinancialInput
      (by rw [← Fast.decodeFinancialInputFast_eq]; exact hd)
    simp only [evaluate_eq_evaluateWellFormed hw]

def maxWorkerFrameBytes : Nat := maxTotalEncodedBytes + 1

def workerExitFrame : UInt32 := 65

-- `open Lean.Order` does not switch this scoped lemma on in Lean 4.33.1, so the monotonicity step is named here.
attribute [local partial_fixpoint_monotone] Lean.Order.MonadTail.monotone_bind_right

/-- The worker: answer each `u32 BE length || frame` with `u32 BE length || workerRespond frame` until end of input
    (0), or stop on a bad frame (65).  Generic in the monad so `WorkerLaws` can run it on a pure pipe model. -/
@[specialize] def serveWorker {m : Type → Type} [Monad m] [Lean.Order.MonadTail m]
    (read : USize → m ByteArray) (write : ByteArray → m Unit) : m UInt32 := do
  let header ← readUpTo read 4 .empty
  if header.size = 0 then return 0
  let some (length, _) := readNatBE 4 header.toList | return workerExitFrame
  if length > maxWorkerFrameBytes then return workerExitFrame
  let frame ← readUpTo read length .empty
  if frame.size < length then return workerExitFrame
  let response := workerRespondBA frame
  write (natBE 4 response.length ++ response).toByteArray
  serveWorker read write
partial_fixpoint

end BlindLedger.Financial
