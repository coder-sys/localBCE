import BlindLedger.Financial.CursorCorrection
import BlindLedger.Financial.Payment.Codec

/-! Cursor twin of the payment-item decoder (`Payment/Codec.lean`).  The frame stays a `ByteArray`:
    the embedded `BLFIN02` is read as one slice by the proved `Cursor.decodeFinancialInput`, and the
    canonical re-encode of a form-A request is one `memcmp` against the rebuilt array, so the 8 MB
    input is never turned into a list.  Everything else in the request is small and keeps its list
    encoder.  The list decoder stays the specification. -/

namespace BlindLedger.Financial.Cursor

open BlindLedger.Financial.Payment (Receipt Foreign Command PaymentRequest ItemState PaymentView RequestPaid paymentMagic)

def readReceipt : Reader Receipt := fun ba i => do
  let (paymentId, i) ← readString ba i
  let (recordedRevision, i) ← readNatBE 8 ba i
  let (paysActionId, i) ← readOptionString ba i
  pure ({ paymentId, recordedRevision, paysActionId }, i)

def readForeign : Reader Foreign := fun ba i => do
  let (flags, i) ← readByte ba i
  if flags.toNat < 4 then some ({ paymentId := flags.toNat % 2 = 1, evidenceId := flags.toNat / 2 = 1 }, i)
  else none

def readCommand : Reader Command := fun ba i => do
  let (tag, i) ← readByte ba i
  if tag.toNat = 1 then do
    let (paymentId, i) ← readString ba i
    let (evidenceId, i) ← readString ba i
    let (commonOriginId, i) ← readString ba i
    let (sourceId, i) ← readString ba i
    let (sourceVersion, i) ← readString ba i
    let (localRef, i) ← readOptionString ba i
    let (amountCents, i) ← readNatBE 8 ba i
    let (eventAt, i) ← readNatBE 8 ba i
    let (paysActionId, i) ← readOptionString ba i
    pure (.record ⟨paymentId, evidenceId, commonOriginId, sourceId, sourceVersion, localRef,
      amountCents, eventAt, paysActionId⟩, i)
  else if tag.toNat = 2 then do
    let (paymentId, i) ← readString ba i
    let (evidenceId, i) ← readString ba i
    let (commonOriginId, i) ← readOptionString ba i
    let (eventAt, i) ← readOptionNat ba i
    pure (.reverse ⟨paymentId, evidenceId, commonOriginId, eventAt⟩, i)
  else none

def readEnv : Reader Env := fun ba i => do
  let (context, i) ← decodeContext ba i
  let (authority, i) ← decodeAuthority ba i
  let (pack, i) ← decodeControlPack ba i
  let (obligation, i) ← decodeObligation ba i
  let (beforeRevision, i) ← readNatBE 8 ba i
  let (evaluatedAt, i) ← readNatBE 8 ba i
  pure (⟨context, authority, pack, obligation, beforeRevision, evaluatedAt⟩, i)

def readContribution : Reader EvalContribution := fun ba i => do
  let (time, i) ← readNatBE 8 ba i
  let (identity, i) ← readString ba i
  let (amountCents, i) ← readNatBE 8 ba i
  pure (⟨time, identity, amountCents⟩, i)

def readRequestPaid : Reader RequestPaid := fun ba i => do
  let (actionId, i) ← readString ba i
  let (amountCents, i) ← readNatBE 8 ba i
  let (paidCents, i) ← readNatBE 8 ba i
  let (revision, i) ← readNatBE 8 ba i
  let (counted, i) ← readBool ba i
  pure (⟨actionId, amountCents, paidCents, revision, counted⟩, i)

def readItemState : Reader ItemState := fun ba i => do
  let (revision, i) ← readNatBE 8 ba i
  let (cash, i) ← readNatBE 8 ba i
  let (claimed, i) ← readNatBE 8 ba i
  let (lawful, i) ← readNatBE 8 ba i
  let (n, i) ← readNatBE 2 ba i
  let (contributions, i) ← if n > 2 * maxRows then none else readMany readContribution n ba i
  let (caseByte, i) ← readByte ba i
  let latestCase ← decodeCaseStatus caseByte
  let (deliveryByte, i) ← readByte ba i
  let delivery ← decodeDeliveryStatus deliveryByte
  let (conflictCount, i) ← readNatBE 2 ba i
  let (evidenceIds, i) ← readList readString ba i
  let (requests, i) ← readList readRequestPaid ba i
  let (anchorBytes, i) ← readNatBE 4 ba i
  pure ({ revision, cash, claimed, lawful, contributions, latestCase, delivery, conflictCount,
          evidenceIds, requests, anchorBytes }, i)

def readByIdRow : Reader (Payment × Receipt) := fun ba i => do
  let (p, i) ← decodePayment ba i
  let (k, i) ← readReceipt ba i
  pure ((p, k), i)

def readByOriginRow : Reader (Payment × Receipt × Option EvidenceRecord) := fun ba i => do
  let (p, i) ← decodePayment ba i
  let (k, i) ← readReceipt ba i
  let (e, i) ← readOptional decodeEvidence ba i
  pure ((p, k, e), i)

instance : SimOf readReceipt Payment.readReceipt := ⟨by unfold readReceipt Payment.readReceipt; sim_steps⟩
instance : SimOf readForeign Payment.readForeign := ⟨by unfold readForeign Payment.readForeign; sim_steps⟩
instance : SimOf readCommand Payment.readCommand := ⟨by unfold readCommand Payment.readCommand; sim_steps⟩
instance : SimOf readEnv Payment.readEnv := ⟨by unfold readEnv Payment.readEnv; sim_steps⟩
instance : SimOf readContribution Payment.readContribution := ⟨by unfold readContribution Payment.readContribution; sim_steps⟩
instance : SimOf readRequestPaid Payment.readRequestPaid := ⟨by unfold readRequestPaid Payment.readRequestPaid; sim_steps⟩
instance : SimOf readItemState Payment.readItemState := ⟨by
  unfold readItemState Payment.readItemState
  repeat (refine Sim.bind SimOf.sim fun _ => ?_)
  dsimp only
  refine Sim.ite (_ > 2 * maxRows) ?_ ?_
  · intro ba i hi
    simp
  · refine Sim.bind (sim_readMany (p := readContribution) (P := Payment.readContribution) SimOf.sim _) fun _ => ?_
    repeat (dsimp only; sim_steps)⟩
instance {α : Type} {p : Reader α} {P} [SimOf p P] : SimOf (readOptional p) (Payment.readOpt P) :=
  ⟨by unfold readOptional Payment.readOpt; sim_steps⟩
instance : SimOf readByIdRow (fun b => do
    let (p, b) ← Financial.decodePayment b
    let (k, b) ← Payment.readReceipt b
    pure ((p, k), b)) := ⟨by unfold readByIdRow; sim_steps⟩
instance : SimOf readByOriginRow (fun b => do
    let (p, b) ← Financial.decodePayment b
    let (k, b) ← Payment.readReceipt b
    let (e, b) ← Payment.readOpt Financial.decodeEvidence b
    pure ((p, k, e), b)) := ⟨by unfold readByOriginRow; sim_steps⟩

def parsePaymentRequest (ba : ByteArray) : Option PaymentRequest := do
  let (n, i) ← readNatBE 4 ba (paymentMagic.length + 1)
  if i + n > ba.size then none else
  let input ← decodeFinancialInput (ba.extract i (i + n))
  let (receipts, i) ← readList readReceipt ba (i + n)
  let (foreign, i) ← readForeign ba i
  let (expectedRevision, i) ← readOptionNat ba i
  let (command, _) ← readCommand ba i
  pure { input, inputBytes := n, receipts, foreign, expectedRevision, command }

def parseFormB (ba : ByteArray) : Option PaymentView := do
  let (env, i) ← readEnv ba (paymentMagic.length + 1)
  let (state, i) ← readItemState ba i
  let (pending, i) ← readList decodeEvidence ba i
  let (byId, i) ← readOptional readByIdRow ba i
  let (byOrigin, i) ← readOptional readByOriginRow ba i
  let (evidence, i) ← readOptional decodeEvidence ba i
  let (conflictVisible, i) ← readBool ba i
  let (foreign, i) ← readForeign ba i
  let (expectedRevision, i) ← readOptionNat ba i
  let (command, _) ← readCommand ba i
  pure { env, state, pending, byId, byOrigin, evidence, conflictVisible, foreign, expectedRevision, command }

/-- `Payment.encodePaymentRequest` with the embedded input built as an array. -/
def encodePaymentRequestBA (r : PaymentRequest) : ByteArray :=
  (paymentMagic ++ [UInt8.ofNat 1] ++ natBE 4 r.inputBytes).toByteArray ++
    Fast.rawEncodeFinancialInputBA r.input ++
    (encodeList Payment.encodeReceipt r.receipts ++ Payment.encodeForeign r.foreign ++
      encodeOptionNat r.expectedRevision ++ Payment.encodeCommand r.command).toByteArray

theorem encodePaymentRequestBA_eq (r : PaymentRequest) :
    encodePaymentRequestBA r = (Payment.encodePaymentRequest r).toByteArray := by
  simp only [encodePaymentRequestBA, Payment.encodePaymentRequest, Fast.rawEncodeFinancialInputBA_eq,
    List.toByteArray_append, ByteArray.append_assoc]

theorem beq_list (l : Bytes) (ba : ByteArray) : (l.toByteArray == ba) = (l == ba.toList) := by
  rw [Bool.eq_iff_iff, Fast.beq_iff, beq_iff_eq, Fast.toByteArray_eq_iff]

theorem parsePaymentRequest_eq (ba : ByteArray) (h : paymentMagic.length + 1 ≤ ba.size) :
    parsePaymentRequest ba = Payment.parsePaymentRequest ba.toList := by
  unfold parsePaymentRequest Payment.parsePaymentRequest
  simp only [Option.bind_eq_bind]
  refine Sim.bind0 SimOf.sim h fun n j hj => ?_
  dsimp only
  by_cases hc : j + n ≤ ba.size
  · rw [if_neg (by omega)]
    refine bindEq (by rw [decodeFinancialInput_eq, extract_toList]) fun input => ?_
    rw [List.drop_drop]
    repeat (refine Sim.bind0 SimOf.sim (by assumption) fun _ _ _ => ?_)
    rfl
  · have hd : ba.toList.drop (j + n) = [] := drop_nil (by omega)
    rw [if_pos (by omega), List.drop_drop, hd]
    cases Financial.decodeFinancialInput ((ba.toList.drop j).take n) <;>
      simp [Financial.readList, Financial.readNatBE, Financial.readByte]

theorem parseFormB_eq (ba : ByteArray) (h : paymentMagic.length + 1 ≤ ba.size) :
    parseFormB ba = Payment.parseFormB ba.toList := by
  unfold parseFormB Payment.parseFormB
  simp only [Option.bind_eq_bind]
  repeat (refine Sim.bind0 SimOf.sim (by assumption) fun _ _ _ => ?_)
  rfl

end BlindLedger.Financial.Cursor

namespace BlindLedger.Financial.Payment

def decodePaymentRequestBA (ba : ByteArray) : Option PaymentRequest :=
  (Cursor.parsePaymentRequest ba).filter fun r => requestWellFormed r &&
    r.inputBytes == (Fast.rawEncodeFinancialInputBA r.input).size && Cursor.encodePaymentRequestBA r == ba

def decodePaymentItemBA (ba : ByteArray) : Option PaymentView :=
  if h : paymentMagic.length < ba.size then
    if ba[paymentMagic.length].toNat = 1 then (decodePaymentRequestBA ba).bind viewOfAnchor
    else if ba[paymentMagic.length].toNat = 2 then
      (Cursor.parseFormB ba).filter fun v => viewWellFormed v && coherent v && (encodeFormB v).toByteArray == ba
    else none
  else none

theorem decodePaymentRequestBA_eq (ba : ByteArray) (h : paymentMagic.length + 1 ≤ ba.size) :
    decodePaymentRequestBA ba = decodePaymentRequest ba.toList := by
  unfold decodePaymentRequestBA decodePaymentRequest
  rw [Cursor.parsePaymentRequest_eq ba h]
  congr 1
  funext r
  rw [Cursor.encodePaymentRequestBA_eq, Cursor.beq_list, Fast.rawEncodeFinancialInputBA_eq,
    List.size_toByteArray]

theorem decodePaymentItemBA_eq (ba : ByteArray) : decodePaymentItemBA ba = decodePaymentItem ba.toList := by
  unfold decodePaymentItemBA decodePaymentItem
  by_cases h : paymentMagic.length < ba.size
  · rw [dif_pos h, Cursor.drop_cons h]
    by_cases h1 : ba[paymentMagic.length].toNat = 1
    · simp only [h1, if_true]
      rw [decodePaymentRequestBA_eq ba (by omega)]
    · by_cases h2 : ba[paymentMagic.length].toNat = 2
      · simp only [h1, h2, Nat.reduceEqDiff, ↓reduceIte]
        rw [Cursor.parseFormB_eq ba (by omega)]
        simp only [Cursor.beq_list]
      · simp [h1, h2]
  · rw [dif_neg h, Cursor.drop_nil (by omega)]

def paymentRespondBA (ba : ByteArray) : Bytes :=
  match decodePaymentItemBA ba with
  | none => [UInt8.ofNat 1]
  | some v =>
    match encodeStepOutcome (stepView v) with
    | none => [UInt8.ofNat 3]
    | some b => UInt8.ofNat 0 :: b

theorem paymentRespondBA_eq (ba : ByteArray) : paymentRespondBA ba = paymentRespond ba.toList := by
  unfold paymentRespondBA paymentRespond
  rw [decodePaymentItemBA_eq]
  rfl

end BlindLedger.Financial.Payment
