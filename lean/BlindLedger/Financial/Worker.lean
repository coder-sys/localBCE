import BlindLedger.Financial.FastEncode
import BlindLedger.Financial.Evaluation
import BlindLedger.Financial.ReadUpTo
import BlindLedger.Financial.Payment.Cursor
import BlindLedger.Financial.CursorCorrection
import BlindLedger.Financial.CorrectionFast
import BlindLedger.Financial.CorrectionTransition.Transition

namespace BlindLedger.Financial

/-! Evaluator worker frames. On the pipe each frame is a u32 big-endian length
    and its bytes. A request frame is one BLFIN02 input. A response frame is one
    outcome: tag 0 then the BLFRES02 result, or the single byte 1 (decode),
    2 (evaluation) or 3 (encoding) rejection. The worker adds no policy; it decodes with the length-free twin
    `Fast.decodeFinancialInput`, proved equal to `decodeFinancialInput`. Item frames start with a magic:
    BLFPAY01 (payment), BLFCMD03 (correction transition) and BLFOFA01 (offset authorization: the magic
    then one unchanged BLFCMD03 request, answered `0 :: BLFCRES3`, `[1]` or `[3]`). -/

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

/-- The BLFOFA01 frame magic. The frame is this magic and then one unchanged BLFCMD03 request. -/
def offsetAuthorizationMagic : Bytes := "BLFOFA01".toUTF8.toList

open CorrectionTransition in
def encodeOffsetAuthorizationRequest (r : CorrectionTransitionRequest) : Option Bytes :=
  (offsetAuthorizationMagic ++ ·) <$> encodeCorrectionTransitionRequest r

open CorrectionTransition in
def decodeOffsetAuthorizationRequest (w : Bytes) : Option CorrectionTransitionRequest :=
  if offsetAuthorizationMagic.isPrefixOf w then
    decodeCorrectionTransitionRequest (w.drop offsetAuthorizationMagic.length)
  else none

open CorrectionTransition in
/-- One offset authorization decision, `applyOffsetAuthorization`, as one worker answer. -/
def offsetRespond (w : Bytes) : Bytes :=
  match decodeOffsetAuthorizationRequest w with
  | none => [UInt8.ofNat 1]
  | some request =>
    match encodeCorrectionTransitionResult (applyOffsetAuthorization request) with
    | none => [UInt8.ofNat 3]
    | some b => UInt8.ofNat 0 :: b

/-- Every item magic the worker dispatches on, in dispatch order. A later item is added here and in
    `workerRespond`; `workerRespond_evaluator_unchanged₂` keeps its text. -/
def itemMagics : List Bytes :=
  [Payment.paymentMagic, CorrectionTransition.correctionTransitionInputMagic, offsetAuthorizationMagic]

/-- The worker's whole policy, one frame in and one answer out: a frame that starts with an item magic
    is one item decision; any other is one BLFIN02 input. -/
def workerRespond (wire : Bytes) : Bytes :=
  if Payment.paymentMagic.isPrefixOf wire then Payment.paymentRespond wire
  else if CorrectionTransition.correctionTransitionInputMagic.isPrefixOf wire then correctionRespond wire
  else if offsetAuthorizationMagic.isPrefixOf wire then offsetRespond wire
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

/-- `correctionRespondBA` with the canonical re-encode and the result encoder on the array twins
    of `Fast/CorrectionFast.lean`, so the embedded input is never copied once per field. -/
def correctionRespondBA₂ (wire : ByteArray) : Bytes :=
  match Fast.decodeCorrectionTransitionRequestBA₂ wire with
  | none => [UInt8.ofNat 1]
  | some request =>
    match Fast.encodeCorrectionTransitionResultBA (CorrectionTransition.applyCorrectionTransition request) with
    | none => [UInt8.ofNat 3]
    | some b => UInt8.ofNat 0 :: b.toList

/-- `offsetRespond` on the array, for a frame that starts with the magic: one copy of the BLFCMD03
    body, then the same array decoder and result encoder as `correctionRespondBA₂`. -/
def offsetRespondBA₂ (wire : ByteArray) : Bytes :=
  match Fast.decodeCorrectionTransitionRequestBA₂ (wire.extract offsetAuthorizationMagic.length wire.size) with
  | none => [UInt8.ofNat 1]
  | some request =>
    match Fast.encodeCorrectionTransitionResultBA (CorrectionTransition.applyOffsetAuthorization request) with
    | none => [UInt8.ofNat 3]
    | some b => UInt8.ofNat 0 :: b.toList

/-- The frame arrives as a `ByteArray`; `Fast.decodeFinancialInputBA₂` is proved equal to the list
    decoder on `wire.toList`, and its input is already well-formed, so this is `workerRespond`
    with one well-formedness pass and no second large list. The magic tests read only the first
    bytes of the array, so an evaluator or correction frame is never copied into a list. -/
def workerRespondBA (wire : ByteArray) : Bytes :=
  if Payment.paymentMagic.isPrefixOf (wire.extract 0 Payment.paymentMagic.length).toList then
    Payment.paymentRespondBA wire
  else if CorrectionTransition.correctionTransitionInputMagic.isPrefixOf
      (wire.extract 0 CorrectionTransition.correctionTransitionInputMagic.length).toList then
    correctionRespondBA₂ wire
  else if offsetAuthorizationMagic.isPrefixOf (wire.extract 0 offsetAuthorizationMagic.length).toList then
    offsetRespondBA₂ wire
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

theorem correctionRespondBA₂_eq (wire : ByteArray) : correctionRespondBA₂ wire = correctionRespondBA wire := by
  unfold correctionRespondBA₂ correctionRespondBA
  rw [Fast.decodeCorrectionTransitionRequestBA₂_eq]
  cases Cursor.decodeCorrectionTransitionRequest wire with
  | none => rfl
  | some request =>
    simp only [Fast.encodeCorrectionTransitionResultBA_eq]
    cases CorrectionTransition.encodeCorrectionTransitionResult (CorrectionTransition.applyCorrectionTransition request) with
    | none => rfl
    | some b => exact congrArg (UInt8.ofNat 0 :: ·) ((Fast.toByteArray_eq_iff b _).1 rfl).symm

theorem extract_drop_toList (wire : ByteArray) (n : Nat) :
    (wire.extract n wire.size).toList = wire.toList.drop n := by
  rw [Fast.toList_eq, ByteArray.data_extract, Array.toList_extract, Fast.toList_eq]
  simp
  exact List.take_of_length_le (by simp)

/-- The array answer to a BLFOFA01 frame is `offsetRespond` on its list. -/
theorem offsetRespondBA₂_eq (wire : ByteArray)
    (h : offsetAuthorizationMagic.isPrefixOf wire.toList = true) :
    offsetRespondBA₂ wire = offsetRespond wire.toList := by
  unfold offsetRespondBA₂ offsetRespond decodeOffsetAuthorizationRequest
  rw [Fast.decodeCorrectionTransitionRequestBA₂_eq, Cursor.decodeCorrectionTransitionRequest_eq,
    extract_drop_toList, if_pos h]
  cases CorrectionTransition.decodeCorrectionTransitionRequest
      (wire.toList.drop offsetAuthorizationMagic.length) with
  | none => rfl
  | some request =>
    simp only [Fast.encodeCorrectionTransitionResultBA_eq]
    cases CorrectionTransition.encodeCorrectionTransitionResult
        (CorrectionTransition.applyOffsetAuthorization request) with
    | none => rfl
    | some b => exact congrArg (UInt8.ofNat 0 :: ·) ((Fast.toByteArray_eq_iff b _).1 rfl).symm

theorem workerRespondBA_eq (wire : ByteArray) : workerRespondBA wire = workerRespond wire.toList := by
  unfold workerRespondBA workerRespond evaluateWire
  rw [magic_prefix_extract, isPrefixOf_extract]
  split
  · exact Payment.paymentRespondBA_eq wire
  split
  · exact (correctionRespondBA₂_eq wire).trans (correctionRespondBA_eq wire)
  rw [isPrefixOf_extract]
  split
  next h => exact offsetRespondBA₂_eq wire h
  rw [Fast.decodeFinancialInputBA₂_eq]
  cases hd : Fast.decodeFinancialInput wire.toList with
  | none => rfl
  | some input =>
    have hw := financialInputWellFormed_of_decodeFinancialInput
      (by rw [← Fast.decodeFinancialInputFast_eq]; exact hd)
    simp only [evaluate_eq_evaluateWellFormed hw]

def maxWorkerFrameBytes : Nat := maxTotalEncodedBytes + 8

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
