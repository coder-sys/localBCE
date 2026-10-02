import BlindLedger.Financial.FastEncode
import BlindLedger.Financial.Evaluation
import BlindLedger.Financial.ReadUpTo
import BlindLedger.Financial.Payment.Codec
import BlindLedger.Financial.CursorCorrection
import BlindLedger.Financial.CorrectionTransition.Transition

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

open CorrectionTransition in
/-- The retired exe's `--apply-correction-transition` as one worker frame: exe stdout is this answer
    without its leading 0; exe exit 72 is `[1]`; exe exit 73 is `[3]`. -/
def correctionRespond (w : Bytes) : Bytes :=
  match decodeCorrectionTransitionRequest w with
  | none => [UInt8.ofNat 1]
  | some request =>
    match encodeCorrectionTransitionResult (applyCorrectionTransition request) with
    | none => [UInt8.ofNat 3]
    | some b => UInt8.ofNat 0 :: b

/-- Every item magic the worker dispatches on, in dispatch order. A later item is added here and in
    `workerRespond`; `workerRespond_evaluator_unchanged₂` keeps its text. -/
def itemMagics : List Bytes := [Payment.paymentMagic, CorrectionTransition.correctionTransitionInputMagic]

/-- The worker's whole policy, one frame in and one answer out: a frame that starts with an item magic
    is one item decision; any other is one BLFIN02 input. -/
def workerRespond (wire : Bytes) : Bytes :=
  if Payment.paymentMagic.isPrefixOf wire then Payment.paymentRespond wire
  else if CorrectionTransition.correctionTransitionInputMagic.isPrefixOf wire then correctionRespond wire
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

/-- `correctionRespond` on the array: the cursor decoder reads the frame in place. -/
def correctionRespondBA (wire : ByteArray) : Bytes :=
  match Cursor.decodeCorrectionTransitionRequest wire with
  | none => [UInt8.ofNat 1]
  | some request =>
    match CorrectionTransition.encodeCorrectionTransitionResult
        (CorrectionTransition.applyCorrectionTransition request) with
    | none => [UInt8.ofNat 3]
    | some b => UInt8.ofNat 0 :: b

/-- The frame arrives as a `ByteArray`; `Fast.decodeFinancialInputBA₂` is proved equal to the list
    decoder on `wire.toList`, and its input is already well-formed, so this is `workerRespond`
    with one well-formedness pass and no second large list. The magic tests read only the first
    bytes of the array, so an evaluator or correction frame is never copied into a list. -/
def workerRespondBA (wire : ByteArray) : Bytes :=
  if Payment.paymentMagic.isPrefixOf (wire.extract 0 Payment.paymentMagic.length).toList then
    Payment.paymentRespond wire.toList
  else if CorrectionTransition.correctionTransitionInputMagic.isPrefixOf
      (wire.extract 0 CorrectionTransition.correctionTransitionInputMagic.length).toList then
    correctionRespondBA wire
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

theorem isPrefixOf_extract (m : Bytes) (wire : ByteArray) :
    m.isPrefixOf (wire.extract 0 m.length).toList = m.isPrefixOf wire.toList := by
  have hx : (wire.extract 0 m.length).toList = wire.toList.take m.length := by
    rw [Fast.toList_eq, ByteArray.data_extract, Array.toList_extract, Fast.toList_eq]
    simp
  rw [hx, Bool.eq_iff_iff, List.isPrefixOf_iff_prefix, List.isPrefixOf_iff_prefix, List.prefix_take_iff]
  exact ⟨fun h => h.1, fun h => ⟨h, Nat.le_refl _⟩⟩

theorem magic_prefix_extract (wire : ByteArray) :
    Payment.paymentMagic.isPrefixOf (wire.extract 0 Payment.paymentMagic.length).toList =
      Payment.paymentMagic.isPrefixOf wire.toList :=
  isPrefixOf_extract _ wire

theorem correctionRespondBA_eq (wire : ByteArray) : correctionRespondBA wire = correctionRespond wire.toList := by
  unfold correctionRespondBA correctionRespond
  rw [Cursor.decodeCorrectionTransitionRequest_eq]

theorem workerRespondBA_eq (wire : ByteArray) : workerRespondBA wire = workerRespond wire.toList := by
  unfold workerRespondBA workerRespond evaluateWire
  rw [magic_prefix_extract, isPrefixOf_extract]
  split
  · rfl
  split
  · exact correctionRespondBA_eq wire
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
