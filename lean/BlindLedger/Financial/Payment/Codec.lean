import BlindLedger.Financial.Payment.Chain

namespace BlindLedger.Financial.Payment

open BlindLedger.Financial

/-! Lean-live M3 (docs: rrb/designs/lean-live-m3-v1.md, section 3.1): the form-A item.
    `BLFPAY01`, form byte 1, u32 n and one canonical BLFIN02 input, the receipts, the two
    foreign-id flags, the expected revision and the command.  As in BLFCMD03, the decoder
    parses and then requires that the request re-encodes to exactly the input bytes, so
    canonicality needs no per-reader inverse.  Nothing calls this yet. -/

def readReceipt (bytes : Bytes) : Option (Receipt × Bytes) := do
  let (paymentId, rest) ← readString bytes
  let (recordedRevision, rest) ← readNatBE 8 rest
  let (paysActionId, rest) ← readOptionString rest
  pure ({ paymentId, recordedRevision, paysActionId }, rest)

/-- Bit 0: foreign payment id.  Bit 1: foreign evidence id. -/
def encodeForeign (f : Foreign) : Bytes :=
  [UInt8.ofNat ((if f.paymentId then 1 else 0) + (if f.evidenceId then 2 else 0))]

def readForeign (bytes : Bytes) : Option (Foreign × Bytes) := do
  let (flags, rest) ← readByte bytes
  if flags.toNat < 4 then some ({ paymentId := flags.toNat % 2 = 1, evidenceId := flags.toNat / 2 = 1 }, rest)
  else none

def encodeCommand : Command → Bytes
  | .record c => UInt8.ofNat 1 :: (encodeString c.paymentId ++ encodeString c.evidenceId ++
      encodeString c.commonOriginId ++ encodeString c.sourceId ++ encodeString c.sourceVersion ++
      encodeOptionString c.localRef ++ natBE 8 c.amountCents ++ natBE 8 c.eventAt ++
      encodeOptionString c.paysActionId)
  | .reverse c => UInt8.ofNat 2 :: (encodeString c.paymentId ++ encodeString c.evidenceId ++
      encodeOptionString c.commonOriginId ++ encodeOptionNat c.eventAt)

def readCommand (bytes : Bytes) : Option (Command × Bytes) := do
  let (tag, rest) ← readByte bytes
  if tag.toNat = 1 then do
    let (paymentId, rest) ← readString rest
    let (evidenceId, rest) ← readString rest
    let (commonOriginId, rest) ← readString rest
    let (sourceId, rest) ← readString rest
    let (sourceVersion, rest) ← readString rest
    let (localRef, rest) ← readOptionString rest
    let (amountCents, rest) ← readNatBE 8 rest
    let (eventAt, rest) ← readNatBE 8 rest
    let (paysActionId, rest) ← readOptionString rest
    pure (.record ⟨paymentId, evidenceId, commonOriginId, sourceId, sourceVersion, localRef,
      amountCents, eventAt, paysActionId⟩, rest)
  else if tag.toNat = 2 then do
    let (paymentId, rest) ← readString rest
    let (evidenceId, rest) ← readString rest
    let (commonOriginId, rest) ← readOptionString rest
    let (eventAt, rest) ← readOptionNat rest
    pure (.reverse ⟨paymentId, evidenceId, commonOriginId, eventAt⟩, rest)
  else none

/-- `inputBytes` is written as the u32 length of the embedded BLFIN02. -/
def encodePaymentRequest (r : PaymentRequest) : Bytes :=
  paymentMagic ++ [UInt8.ofNat 1] ++ natBE 4 r.inputBytes ++ rawEncodeFinancialInput r.input ++
    encodeList encodeReceipt r.receipts ++ encodeForeign r.foreign ++
    encodeOptionNat r.expectedRevision ++ encodeCommand r.command

def parsePaymentRequest (w : Bytes) : Option PaymentRequest := do
  let (n, rest) ← readNatBE 4 (w.drop (paymentMagic.length + 1))
  let input ← decodeFinancialInput (rest.take n)
  let (receipts, rest) ← readList readReceipt (rest.drop n)
  let (foreign, rest) ← readForeign rest
  let (expectedRevision, rest) ← readOptionNat rest
  let (command, _) ← readCommand rest
  pure { input, inputBytes := n, receipts, foreign, expectedRevision, command }

def decodePaymentRequest (w : Bytes) : Option PaymentRequest :=
  (parsePaymentRequest w).filter fun r => requestWellFormed r &&
    r.inputBytes == (rawEncodeFinancialInput r.input).length && encodePaymentRequest r == w

def encodeOpt {α : Type} (f : α → Bytes) : Option α → Bytes
  | none => [UInt8.ofNat 0]
  | some a => UInt8.ofNat 1 :: f a

def readOpt {α : Type} (f : Bytes → Option (α × Bytes)) (b : Bytes) : Option (Option α × Bytes) := do
  let (tag, b) ← readByte b
  if tag.toNat = 0 then pure (none, b)
  else if tag.toNat = 1 then do
    let (a, b) ← f b
    pure (some a, b)
  else none

def encodeEnv (e : Env) : Bytes :=
  encodeContext e.context ++ encodeAuthority e.authority ++ encodeControlPack e.pack ++
    encodeObligation e.obligation ++ natBE 8 e.beforeRevision ++ natBE 8 e.evaluatedAt

def readEnv (b : Bytes) : Option (Env × Bytes) := do
  let (context, b) ← decodeContext b
  let (authority, b) ← decodeAuthority b
  let (pack, b) ← decodeControlPack b
  let (obligation, b) ← decodeObligation b
  let (beforeRevision, b) ← readNatBE 8 b
  let (evaluatedAt, b) ← readNatBE 8 b
  pure (⟨context, authority, pack, obligation, beforeRevision, evaluatedAt⟩, b)

def encodeContribution (x : EvalContribution) : Bytes :=
  natBE 8 x.time ++ encodeString x.identity ++ natBE 8 x.amountCents

def readContribution (b : Bytes) : Option (EvalContribution × Bytes) := do
  let (time, b) ← readNatBE 8 b
  let (identity, b) ← readString b
  let (amountCents, b) ← readNatBE 8 b
  pure (⟨time, identity, amountCents⟩, b)

def encodeRequestPaid (q : RequestPaid) : Bytes :=
  encodeString q.actionId ++ natBE 8 q.amountCents ++ natBE 8 q.paidCents ++ natBE 8 q.revision ++
    encodeBool q.counted

def readRequestPaid (b : Bytes) : Option (RequestPaid × Bytes) := do
  let (actionId, b) ← readString b
  let (amountCents, b) ← readNatBE 8 b
  let (paidCents, b) ← readNatBE 8 b
  let (revision, b) ← readNatBE 8 b
  let (counted, b) ← readBool b
  pure (⟨actionId, amountCents, paidCents, revision, counted⟩, b)

/-- Contributions: u16 count up to 2 * maxRows (payments plus determinations). -/
def encodeItemState (s : ItemState) : Bytes :=
  natBE 8 s.revision ++ natBE 8 s.cash ++ natBE 8 s.claimed ++ natBE 8 s.lawful ++
    encodeList encodeContribution s.contributions ++
    [encodeCaseStatus s.latestCase, encodeDeliveryStatus s.delivery] ++ natBE 2 s.conflictCount ++
    encodeList encodeString s.evidenceIds ++ encodeList encodeRequestPaid s.requests ++ natBE 4 s.anchorBytes

def readItemState (b : Bytes) : Option (ItemState × Bytes) := do
  let (revision, b) ← readNatBE 8 b
  let (cash, b) ← readNatBE 8 b
  let (claimed, b) ← readNatBE 8 b
  let (lawful, b) ← readNatBE 8 b
  let (n, b) ← readNatBE 2 b
  let (contributions, b) ← if n > 2 * maxRows then none else readMany readContribution n b
  let (caseByte, b) ← readByte b
  let latestCase ← decodeCaseStatus caseByte
  let (deliveryByte, b) ← readByte b
  let delivery ← decodeDeliveryStatus deliveryByte
  let (conflictCount, b) ← readNatBE 2 b
  let (evidenceIds, b) ← readList readString b
  let (requests, b) ← readList readRequestPaid b
  let (anchorBytes, b) ← readNatBE 4 b
  pure ({ revision, cash, claimed, lawful, contributions, latestCase, delivery, conflictCount,
          evidenceIds, requests, anchorBytes }, b)

def encodeFormB (v : PaymentView) : Bytes :=
  paymentMagic ++ [UInt8.ofNat 2] ++ encodeEnv v.env ++ encodeItemState v.state ++
    encodeList encodeEvidence v.pending ++
    encodeOpt (fun (x : Payment × Receipt) => encodePayment x.1 ++ encodeReceipt x.2) v.byId ++
    encodeOpt (fun (x : Payment × Receipt × Option EvidenceRecord) =>
      encodePayment x.1 ++ encodeReceipt x.2.1 ++ encodeOpt encodeEvidence x.2.2) v.byOrigin ++
    encodeOpt encodeEvidence v.evidence ++ encodeBool v.conflictVisible ++
    encodeForeign v.foreign ++ encodeOptionNat v.expectedRevision ++ encodeCommand v.command

def parseFormB (w : Bytes) : Option PaymentView := do
  let (env, b) ← readEnv (w.drop (paymentMagic.length + 1))
  let (state, b) ← readItemState b
  let (pending, b) ← readList decodeEvidence b
  let (byId, b) ← readOpt (fun b => do
    let (p, b) ← decodePayment b
    let (k, b) ← readReceipt b
    pure ((p, k), b)) b
  let (byOrigin, b) ← readOpt (fun b => do
    let (p, b) ← decodePayment b
    let (k, b) ← readReceipt b
    let (e, b) ← readOpt decodeEvidence b
    pure ((p, k, e), b)) b
  let (evidence, b) ← readOpt decodeEvidence b
  let (conflictVisible, b) ← readBool b
  let (foreign, b) ← readForeign b
  let (expectedRevision, b) ← readOptionNat b
  let (command, _) ← readCommand b
  pure { env, state, pending, byId, byOrigin, evidence, conflictVisible, foreign, expectedRevision, command }

/-- The head conjuncts of `financialInputWellFormed` (the port extracts them there, once). -/

def stateWellFormed (s : ItemState) : Bool :=
  s.revision < maxRevision && s.cash ≤ maxCents && s.claimed ≤ maxCents && s.lawful ≤ maxCents &&
    s.contributions.length ≤ 2 * maxRows &&
    s.contributions.all (fun x => timeWellFormed x.time && idWellFormed x.identity && x.amountCents ≤ maxCents) &&
    s.conflictCount ≤ maxRows && s.evidenceIds.length ≤ maxRows && canonicalIdList s.evidenceIds &&
    s.requests.length ≤ maxRows &&
    s.requests.all (fun q => idWellFormed q.actionId && q.amountCents ≤ maxCents && q.paidCents ≤ maxCents &&
      revisionWellFormed q.revision) &&
    s.anchorBytes ≤ maxTotalEncodedBytes

def viewWellFormed (v : PaymentView) : Bool :=
  let ctx := v.env.context
  let rowOk (p : Payment) (k : Receipt) := paymentWellFormed ctx p && k.paymentId = p.paymentId &&
    k.recordedRevision < v.env.beforeRevision && k.paysActionId.all idWellFormed
  envWellFormed v.env && stateWellFormed v.state && v.pending.length ≤ maxRows &&
    canonicalIdList (v.pending.map (·.evidenceId)) && v.pending.all (evidenceWellFormed ctx) &&
    v.byId.all (fun x => rowOk x.1 x.2) &&
    v.byOrigin.all (fun x => rowOk x.1 x.2.1 && x.2.2.all (evidenceWellFormed ctx)) &&
    v.evidence.all (evidenceWellFormed ctx) &&
    commandWellFormed v.command && v.expectedRevision.all (· < 2 ^ 63)

/-- Section 2.6 coherence: the rows are the ones the command names, and agree with the state.
    An ACTIVE row's contribution is in the state (`advance` erases it). A REVERSED row is not
    checked: an authorized determination may carry the same (time, id, amount) contribution. -/
def coherent (v : PaymentView) : Bool :=
  let contributes (p : Payment) :=
    !decide (p.status = .ACTIVE) || v.state.contributions.contains ⟨p.eventAt, p.paymentId, p.amountCents⟩
  v.state.revision = v.env.beforeRevision &&
    v.byId.all (fun x => x.1.paymentId = cmdPaymentId v.command && contributes x.1) &&
    v.evidence.all (·.evidenceId = cmdEvidenceId v.command) &&
    v.pending.all (fun e => !v.state.evidenceIds.contains e.evidenceId) &&
    (match v.command with
     | .record c => v.byOrigin.all fun x => x.1.commonOriginId = c.commonOriginId && contributes x.1 &&
         x.2.2.all fun e => some e.evidenceId = x.1.reversalEvidenceId
     | .reverse _ => v.byOrigin.isNone && !v.conflictVisible)

def decodePaymentItem (w : Bytes) : Option PaymentView :=
  match w.drop paymentMagic.length with
  | f :: _ =>
    if f.toNat = 1 then (decodePaymentRequest w).bind viewOfAnchor
    else if f.toNat = 2 then
      (parseFormB w).filter fun v => viewWellFormed v && coherent v && encodeFormB v == w
    else none
  | [] => none

def answerMagic : Bytes := "BLFPRS01".toUTF8.toList
def mutations : List Mutation := [.RECORDED, .REVERSED, .CONFLICT_RECORDED]
def refusals : List Refusal :=
  [.AMOUNT_ZERO, .REQUEST_CONFLICT, .ORIGIN_REVERSED, .REVISION_CONFLICT, .EVIDENCE_CONFLICT,
   .CHRONOLOGY, .LINK_UNKNOWN, .LINK_EXCEEDS_UNPAID, .PAYMENT_MISSING, .ALREADY_REVERSED,
   .ORIGIN_FORM, .LOCAL_REF_FORM, .CONFLICT_ID_FORM, .CAPACITY, .POST_REJECTED, .SHADOW_READ_ONLY]

def rawEncodeStepOutcome : StepOutcome → Bytes
  | .mutated k w s r =>
    let res := rawEncodeFinancialResult r
    answerMagic ++ [UInt8.ofNat (mutations.findIdx (· == k) + 1)] ++
      encodeOpt encodeEvidence w.evidence ++ encodeOpt encodePayment w.payment ++
      encodeOpt encodeConflict w.conflict ++ encodeOpt encodeReceipt w.receipt ++
      encodeItemState s ++ natBE 4 res.length ++ res
  | .conflictUnchanged id => answerMagic ++ [UInt8.ofNat 4] ++ encodeString id
  | .alias pid e => answerMagic ++ [UInt8.ofNat 5] ++ encodeString pid ++ encodeEvidence e
  | .duplicate pid => answerMagic ++ [UInt8.ofNat 6] ++ encodeOptionString pid
  | .refused f => answerMagic ++ [UInt8.ofNat 7, UInt8.ofNat (refusals.findIdx (· == f) + 1)]

def parseStepOutcome (b : Bytes) : Option StepOutcome := do
  let (tag, b) ← readByte (b.drop answerMagic.length)
  if tag.toNat = 4 then return .conflictUnchanged (← readString b).1
  if tag.toNat = 5 then
    let (pid, b) ← readString b
    let (e, _) ← decodeEvidence b
    return .alias pid e
  if tag.toNat = 6 then return .duplicate (← readOptionString b).1
  if tag.toNat = 7 then
    let (f, _) ← readByte b
    return .refused (← refusals[f.toNat - 1]?)
  let k ← mutations[tag.toNat - 1]?
  let (evidence, b) ← readOpt decodeEvidence b
  let (payment, b) ← readOpt decodePayment b
  let (conflict, b) ← readOpt decodeConflict b
  let (receipt, b) ← readOpt readReceipt b
  let (s, b) ← readItemState b
  let (m, b) ← readNatBE 4 b
  let r ← decodeFinancialResult (b.take m)
  return .mutated k { evidence, payment, conflict, receipt } s r

/-- Canonical by re-encoding, as `decodePaymentRequest`. -/
def decodeStepOutcome (b : Bytes) : Option StepOutcome :=
  (parseStepOutcome b).filter fun o => rawEncodeStepOutcome o == b

/-- An answer is sent only if it fits a worker frame and decodes to exactly the outcome;
    otherwise worker byte 3. -/
def encodeStepOutcome (o : StepOutcome) : Option Bytes :=
  let b := rawEncodeStepOutcome o
  if b.length ≤ maxTotalEncodedBytes ∧ decodeStepOutcome b = some o then some b else none

def paymentRespond (w : Bytes) : Bytes :=
  match decodePaymentItem w with
  | none => [UInt8.ofNat 1]
  | some v =>
    match encodeStepOutcome (stepView v) with
    | none => [UInt8.ofNat 3]
    | some b => UInt8.ofNat 0 :: b


end BlindLedger.Financial.Payment
