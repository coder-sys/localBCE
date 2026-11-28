import BlindLedger.Gate.Obligations.Ident
import BlindLedger.Financial.CodecLaws.Primitives
import BlindLedger.Financial.CorrectionTransition.Transition
import BlindLedger.Financial.Payment.Transition

namespace BlindLedger.Gate.Obligations

open BlindLedger.Gate.FactCodec
open BlindLedger.Financial (DeterminationDecision stringWireAdmissible digestWireAdmissible
  optionStringWireAdmissible optionNatWireAdmissible encodeString encodeDigest natBE encodeOptionString
  encodeOptionNat readString readDigest readNatBE readOptionString readOptionNat encodeDecision
  readString_encodeString_append readDigest_encodeDigest_append readNatBE_natBE_append
  readOptionString_encodeOptionString_append readOptionNat_encodeOptionNat_append
  encodeString_injective_of_admissible)
open BlindLedger.Financial.CorrectionTransition (CorrectionCommand CorrectionTransitionRequest
  ExistingCorrectionIdentity decisionActionKind decisionTimeMatches offsetIdentityMatches)
open BlindLedger.Financial (Payment findEvidence)
open BlindLedger.Financial.Payment (RecordCommand PaymentRequest recordRetry confirmation formRefusal receiptOf
  nonEmpty)

/-! The request map `M` of design `one-store` §3.1: a command's canonical bytes

        canon = ckind u8 ‖ lp16 command_id ‖ scope 64 ‖ body

    whose `H` (under domain `CMDREQ`) is the command record's `rqd`.  `body` holds exactly the fields the owner's
    logged request holds for the kind, each in the financial codec's own wire form (big-endian numbers, u16-length
    strings, 64-byte digests), so the map adds no second encoding of a field.

    `request_map_faithful`: two well-formed requests have the same canonical bytes exactly when they are the same
    request.  `offset_request_faithful`: for an offset decision, the stored identity and a new request have the
    same canonical bytes exactly when Lean's `offsetIdentityMatches` holds, expected revision and decision time as
    given included.  `payment_request_faithful`: for a payment, exactly when Lean's `recordRetry` answers
    duplicate (Constitution III.3). -/

/-- The wire form of one body field. -/
inductive WFld where
  | str | dig | u64 | u8 | optStr | optU64
  deriving DecidableEq, Repr

/-- One body field's value; `n` is a u64 and `b` a u8. -/
inductive WCell where
  | s (v : String)
  | d (v : Bytes)
  | n (v : Nat)
  | b (v : Nat)
  | os (v : Option String)
  | on (v : Option Nat)
  deriving DecidableEq, Repr

def WCell.fld : WCell → WFld
  | .s _ => .str
  | .d _ => .dig
  | .n _ => .u64
  | .b _ => .u8
  | .os _ => .optStr
  | .on _ => .optU64

/-- Each value is admissible on the financial wire. -/
def WCell.ok : WCell → Prop
  | .s v => stringWireAdmissible v
  | .d v => digestWireAdmissible v
  | .n v => v < 256 ^ 8
  | .b v => v < 256 ^ 1
  | .os v => optionStringWireAdmissible v
  | .on v => optionNatWireAdmissible v

def WCell.enc : WCell → Bytes
  | .s v => encodeString v
  | .d v => encodeDigest v
  | .n v => natBE 8 v
  | .b v => natBE 1 v
  | .os v => encodeOptionString v
  | .on v => encodeOptionNat v

def wdec1 : WFld → Bytes → Option (WCell × Bytes)
  | .str, b => (readString b).map fun p => (.s p.1, p.2)
  | .dig, b => (readDigest b).map fun p => (.d p.1, p.2)
  | .u64, b => (readNatBE 8 b).map fun p => (.n p.1, p.2)
  | .u8, b => (readNatBE 1 b).map fun p => (.b p.1, p.2)
  | .optStr, b => (readOptionString b).map fun p => (.os p.1, p.2)
  | .optU64, b => (readOptionNat b).map fun p => (.on p.1, p.2)

theorem wdec1_enc (c : WCell) (r : Bytes) (h : c.ok) : wdec1 c.fld (c.enc ++ r) = some (c, r) := by
  cases c with
  | s v => simp [wdec1, WCell.fld, WCell.enc, readString_encodeString_append v r h]
  | d v => simp [wdec1, WCell.fld, WCell.enc, readDigest_encodeDigest_append v r h]
  | n v => simp [wdec1, WCell.fld, WCell.enc, readNatBE_natBE_append 8 v r h]
  | b v => simp [wdec1, WCell.fld, WCell.enc, readNatBE_natBE_append 1 v r h]
  | os v => simp [wdec1, WCell.fld, WCell.enc, readOptionString_encodeOptionString_append v r h]
  | on v => simp [wdec1, WCell.fld, WCell.enc, readOptionNat_encodeOptionNat_append v r h]

def wenc : List WCell → Bytes
  | [] => []
  | c :: cs => c.enc ++ wenc cs

def wdec : List WFld → Bytes → Option (List WCell × Bytes)
  | [], b => some ([], b)
  | f :: fs, b =>
    match wdec1 f b with
    | some (c, b) => (wdec fs b).map fun p => (c :: p.1, p.2)
    | none => none

theorem wdec_wenc : ∀ (cs : List WCell) (r : Bytes), (∀ c ∈ cs, c.ok) →
    wdec (cs.map WCell.fld) (wenc cs ++ r) = some (cs, r)
  | [], _, _ => rfl
  | c :: cs, r, h => by
    simp [wdec, wenc, List.append_assoc, wdec1_enc c _ (h c (by simp)),
      wdec_wenc cs r (fun x hx => h x (by simp [hx]))]

/-- The owner's command kinds (`_COMMAND_EVENTS`), and `EVALUATE`, which this design adds. -/
def kindName : Nat → String
  | 1 => "CONTROL_PACK"
  | 2 => "POPULATION_MANIFEST"
  | 3 => "FUNDING_RECEIPT"
  | 4 => "SUPPORT_EVIDENCE"
  | 5 => "PAYMENT"
  | 6 => "PAYMENT_REVERSAL"
  | 7 => "OFFSET_CLAIM"
  | 8 => "OFFSET_DECISION"
  | 9 => "ACTION_ACKNOWLEDGMENT"
  | 10 => "REPORT"
  | 11 => "FOLLOWTHROUGH_DECISION"
  | 12 => "EVALUATE"
  | _ => ""

/-- The body of each kind (§3.1 table).  Kind 5: item, evidence, common origin, amount, event time, source id,
    source version, local reference, the request it pays, a revision: a stored identity always holds the recorded
    one (`paymentIdentityReq`), a retry its expected one, none if it gave none.  Kind 8: obligation, claim,
    decision, actor, role, evaluation id, evaluation result digest, expected revision, decision time as given. -/
def schema : Nat → List WFld
  | 1 | 2 | 3 | 11 => [.dig]
  | 4 | 10 => [.str, .dig]
  | 5 => [.str, .str, .str, .u64, .u64, .str, .str, .str, .optStr, .optU64]
  | 6 => [.str, .str, .dig]
  | 7 => [.str, .str, .u64, .str, .u64]
  | 8 => [.str, .str, .u8, .str, .str, .str, .dig, .u64, .optU64]
  | 9 | 12 => [.str]
  | _ => []

/-- A command as the request map sees it: its kind, the key in its `command_id`, its scope and its body. -/
structure Req where
  ckind : Nat
  key : Bytes
  scope : Bytes
  body : List WCell
  deriving DecidableEq, Repr

/-- The owner's `command_id`: `<kind>:<key>`. -/
def cmdId (r : Req) : Bytes := (kindName r.ckind ++ ":").toUTF8.toList ++ r.key

def canon (r : Req) : Bytes :=
  leBytes 1 r.ckind ++ (leBytes 2 (cmdId r).length ++ (cmdId r ++ (r.scope ++ wenc r.body)))

def Req.WF (r : Req) : Prop :=
  (1 ≤ r.ckind ∧ r.ckind ≤ 12) ∧ (cmdId r).length < 256 ^ 2 ∧ r.scope.length = 64 ∧
    r.body.map WCell.fld = schema r.ckind ∧ ∀ c ∈ r.body, c.ok

/-- A left inverse of `canon`, used only to prove it injective. -/
def canonInv (b : Bytes) : Option Req :=
  match rdLE 1 b with
  | none => none
  | some (k, b) =>
    match rdLE 2 b with
    | none => none
    | some (n, b) =>
      match rdBlk n b with
      | none => none
      | some (id, b) =>
        match rdBlk 64 b with
        | none => none
        | some (scope, b) =>
          match wdec (schema k) b with
          | some (body, []) => some ⟨k, id.drop (kindName k ++ ":").toUTF8.toList.length, scope, body⟩
          | _ => none

theorem canon_inv {r : Req} (h : r.WF) : canonInv (canon r) = some r := by
  obtain ⟨⟨hk1, hk2⟩, h2, h3, h4, h5⟩ := h
  have h1 : r.ckind < 256 ^ 1 := by simp only [Nat.pow_one]; omega
  have hb := wdec_wenc r.body [] h5
  rw [List.append_nil, h4] at hb
  unfold canon canonInv
  simp only [rdLE_enc _ h1, rdLE_enc _ h2, rdBlk_enc _ (rfl : (cmdId r).length = _), rdBlk_enc _ h3, hb]
  simp [cmdId]

/-- `request_map_faithful` (§9.2), for every command kind. -/
theorem request_map_faithful {r1 r2 : Req} (h1 : r1.WF) (h2 : r2.WF) : canon r1 = canon r2 ↔ r1 = r2 := by
  constructor
  · intro h
    have := canon_inv h1
    rw [h, canon_inv h2] at this
    exact (Option.some.inj this).symm
  · intro h
    rw [h]

/-! ## Offset decisions -/

/-- The decision time as the caller gave it: none when left to the writer's clock. -/
def cmdTime (c : CorrectionCommand) : Option Nat := if c.decisionTimeGiven then some c.decisionAtMs else none

/-- The stored decision time as given: none when the original left it to the clock; a row stored before the flag
    was kept holds only the resolved time, which counts as given (§3.2). -/
def storedTime (i : ExistingCorrectionIdentity) : Option Nat :=
  match i.decisionTimeGiven with
  | some false => none
  | _ => some i.decidedAtMs

def offsetReq (scope : Bytes) (decision : DeterminationDecision) (req : CorrectionTransitionRequest) : Req :=
  ⟨8, req.command.actionId.toUTF8.toList, scope,
    [.s req.currentInput.context.obligationId, .s req.command.claimId, .b (encodeDecision decision).toNat,
      .s req.command.actorId, .s req.command.actorRole, .s req.command.evaluationId,
      .d req.command.evaluationResultDigest, .n req.command.expectedRevision, .on (cmdTime req.command)]⟩

def identityReq (scope : Bytes) (i : ExistingCorrectionIdentity) : Req :=
  ⟨8, i.actionId.toUTF8.toList, scope,
    [.s i.actionObligationId, .s i.claimId, .b (encodeDecision i.decision).toNat, .s i.actorId, .s i.actorRole,
      .s i.inputEvaluationId, .d i.inputEvaluationResultDigest, .n i.expectedRevision, .on (storedTime i)]⟩

/-- How the owner writes a stored identity: its determination and action kind follow from its action and
    decision. -/
def IdentityWF (i : ExistingCorrectionIdentity) : Prop :=
  i.determinationId = "determination:" ++ i.actionId ∧ i.determinationObligationId = i.actionObligationId ∧
    i.actionKind = decisionActionKind i.decision

theorem utf8_inj {a b : String} (ha : stringWireAdmissible a) (hb : stringWireAdmissible b)
    (h : a.toUTF8.toList = b.toUTF8.toList) : a = b :=
  encodeString_injective_of_admissible a b ha hb (by simp only [encodeString, h])

theorem time_faithful (c : CorrectionCommand) (i : ExistingCorrectionIdentity) :
    storedTime i = cmdTime c ↔ decisionTimeMatches c i = true := by
  unfold storedTime cmdTime decisionTimeMatches
  cases c.decisionTimeGiven <;> cases i.decisionTimeGiven with
  | none => simp [eq_comm]
  | some g => cases g <;> simp [eq_comm]

theorem decision_code_faithful (a b : DeterminationDecision) :
    (encodeDecision a).toNat = (encodeDecision b).toNat ↔ a = b := by
  cases a <;> cases b <;> decide

/-- `request_map_faithful` for an offset decision (§9.2): the canonical bytes of a stored identity and of a new
    request are equal exactly when `offsetIdentityMatches` holds. -/
theorem offset_request_faithful {scope : Bytes} {d : DeterminationDecision} {req : CorrectionTransitionRequest}
    {i : ExistingCorrectionIdentity} (h1 : (identityReq scope i).WF) (h2 : (offsetReq scope d req).WF)
    (ha1 : stringWireAdmissible i.actionId) (ha2 : stringWireAdmissible req.command.actionId)
    (hi : IdentityWF i) :
    canon (identityReq scope i) = canon (offsetReq scope d req) ↔ offsetIdentityMatches d req i = true := by
  rw [request_map_faithful h1 h2]
  have hkey : i.actionId.toUTF8.toList = req.command.actionId.toUTF8.toList ↔ i.actionId = req.command.actionId :=
    ⟨utf8_inj ha1 ha2, fun h => by rw [h]⟩
  obtain ⟨hd1, hd2, hd3⟩ := hi
  clear h1 h2 ha1 ha2
  simp only [identityReq, offsetReq, offsetIdentityMatches, Req.mk.injEq, List.cons.injEq, WCell.s.injEq,
    WCell.b.injEq, WCell.d.injEq, WCell.n.injEq, WCell.on.injEq, hkey, decision_code_faithful,
    time_faithful, hd1, hd2, hd3, Bool.and_eq_true, decide_eq_true_eq, and_true, true_and]
  constructor <;> intro h <;> simp_all

/-! ## Payments -/

/-- The local reference as the owner compares it: none or empty means `payment:<payment id>`. -/
def localRefOf (c : RecordCommand) : String := (nonEmpty c.localRef).getD ("payment:" ++ c.paymentId)

/-- `M` for a payment (§3.1 row 5): the command's fields, the request it pays, and a revision. -/
def paymentReq (scope : Bytes) (item : String) (c : RecordCommand) (pays : Option String) (rev : Option Nat) :
    Req :=
  ⟨5, c.paymentId.toUTF8.toList, scope,
    [.s item, .s c.evidenceId, .s c.commonOriginId, .n c.amountCents, .n c.eventAt, .s c.sourceId,
      .s c.sourceVersion, .s (localRefOf c), .os pays, .on rev]⟩

/-- The stored identity of an applied payment: the request it pays and the revision it was recorded at, both from
    its receipt.  The revision is always present, so a retry that gives no expected revision never has these
    bytes and is never a duplicate. -/
def paymentIdentityReq (scope : Bytes) (item : String) (c : RecordCommand)
    (k : BlindLedger.Financial.Payment.Receipt) : Req :=
  paymentReq scope item c k.paysActionId (some k.recordedRevision)

/-- The stored identity of an alias: a payment id stored only as a second confirmation of a payment with the same
    common origin and amount (`aliasOf`), with no payment row and no receipt.  Lean answers a retry of it in
    `recordNew`, where its stored evidence makes it a prior confirmation: the revision is never compared, and the
    request it pays may be absent or the existing payment's.  So the identity holds no revision, and the request
    it pays is the command's, else the existing payment's (`existingPays`); a retry is compared in the same form,
    whatever revision it expects. -/
def aliasIdentityReq (scope : Bytes) (item : String) (c : RecordCommand) (existingPays : Option String) : Req :=
  paymentReq scope item c (c.paysActionId <|> existingPays) none

/-- An alias's identity and a recorded payment's never have the same canonical bytes: the alias holds no
    revision and the recorded payment always holds one.  So a retry compared in the alias form matches only an
    alias, and a retry compared in the recorded form only a recorded payment. -/
theorem alias_ne_recorded {scope : Bytes} {item item' : String} {c c' : RecordCommand} {e : Option String}
    {k : BlindLedger.Financial.Payment.Receipt} (h1 : (aliasIdentityReq scope item c e).WF)
    (h2 : (paymentIdentityReq scope item' c' k).WF) :
    canon (aliasIdentityReq scope item c e) ≠ canon (paymentIdentityReq scope item' c' k) := by
  rw [Ne, request_map_faithful h1 h2]
  simp [aliasIdentityReq, paymentIdentityReq, paymentReq]

/-- A retry of an alias that pays nothing or the existing payment's request has the alias's own pays field, so
    only its other fields decide whether it is the same request. -/
theorem alias_pays_same {c : RecordCommand} {existingPays : Option String}
    (h : c.paysActionId = none ∨ c.paysActionId = existingPays) :
    (c.paysActionId <|> existingPays) = existingPays := by
  rcases h with h | h <;> rw [h] <;> cases existingPays <;> rfl

/-- How the owner stores a payment recorded by `c`: its row, its confirmation evidence received at `recv`, which
    passed the form and time checks, and its receipt. -/
def PaymentStored (r : PaymentRequest) (c : RecordCommand) (p : Payment) (k : BlindLedger.Financial.Payment.Receipt)
    (recv : Nat) : Prop :=
  p.paymentId = c.paymentId ∧ p.evidenceId = c.evidenceId ∧ p.commonOriginId = c.commonOriginId ∧
    p.amountCents = c.amountCents ∧ p.eventAt = c.eventAt ∧
    findEvidence r.input.evidence c.evidenceId = some (confirmation r.input c recv) ∧
    formRefusal (confirmation r.input c recv) = none ∧ c.eventAt ≤ recv ∧ receiptOf r.receipts c.paymentId = some k

theorem confirmation_inj (i : BlindLedger.Financial.FinancialInput) (c c' : RecordCommand) (t : Nat) :
    confirmation i c t = confirmation i c' t ↔
      c.evidenceId = c'.evidenceId ∧ c.commonOriginId = c'.commonOriginId ∧ c.amountCents = c'.amountCents ∧
      c.eventAt = c'.eventAt ∧ c.sourceId = c'.sourceId ∧ c.sourceVersion = c'.sourceVersion ∧
      localRefOf c = localRefOf c' := by
  constructor
  · intro h
    exact ⟨congrArg (·.evidenceId) h, congrArg (·.commonOriginId) h,
      Option.some.inj (congrArg (·.amountCents) h), congrArg (·.eventAt) h, congrArg (·.sourceId) h,
      congrArg (·.sourceVersion) h, congrArg (·.localRef) h⟩
  · rintro ⟨h1, h2, h3, h4, h5, h6, h7⟩
    unfold localRefOf at h7
    simp only [confirmation, h1, h2, h3, h4, h5, h6, h7]

/-- `request_map_faithful` for a payment (§9.2): the canonical bytes of a stored payment's identity and of a
    retry of its payment id are equal exactly when Lean's `recordRetry` answers duplicate.  A retry with no expected
    revision differs from every stored identity, so it is never a duplicate. -/
theorem payment_request_faithful {scope : Bytes} {r : PaymentRequest} {c0 c : RecordCommand} {p : Payment}
    {k : BlindLedger.Financial.Payment.Receipt} {recv : Nat}
    (h1 : (paymentIdentityReq scope r.input.context.itemId c0 k).WF)
    (h2 : (paymentReq scope r.input.context.itemId c c.paysActionId r.expectedRevision).WF)
    (hs : PaymentStored r c0 p k recv) (hp : p.paymentId = c.paymentId) :
    canon (paymentIdentityReq scope r.input.context.itemId c0 k) =
        canon (paymentReq scope r.input.context.itemId c c.paysActionId r.expectedRevision) ↔
      recordRetry r c p = .duplicate (some c.paymentId) := by
  rw [request_map_faithful h1 h2]
  obtain ⟨hpid, hpe, hpo, hpa, hpt, hfe, hfr, hrt, hk⟩ := hs
  have hid : c0.paymentId = c.paymentId := hpid.symm.trans hp
  have hk' : receiptOf r.receipts p.paymentId = some k := by rw [hpid]; exact hk
  have hreq : paymentIdentityReq scope r.input.context.itemId c0 k =
      paymentReq scope r.input.context.itemId c c.paysActionId r.expectedRevision ↔
      c0.evidenceId = c.evidenceId ∧ c0.commonOriginId = c.commonOriginId ∧ c0.amountCents = c.amountCents ∧
        c0.eventAt = c.eventAt ∧ c0.sourceId = c.sourceId ∧ c0.sourceVersion = c.sourceVersion ∧
        localRefOf c0 = localRefOf c ∧ k.paysActionId = c.paysActionId ∧
        some k.recordedRevision = r.expectedRevision := by
    simp only [paymentIdentityReq, paymentReq, Req.mk.injEq, List.cons.injEq, WCell.s.injEq, WCell.n.injEq,
      WCell.os.injEq, WCell.on.injEq, hid, true_and, and_true]
  rw [hreq]
  simp only [recordRetry, hk']
  by_cases he : c.evidenceId = c0.evidenceId
  · have hs' : findEvidence r.input.evidence c.evidenceId = some (confirmation r.input c0 recv) := by
      rw [he]; exact hfe
    have hrv : (confirmation r.input c0 recv).receivedAt = recv := rfl
    simp only [hs', hrv]
    constructor
    · rintro ⟨e1, e2, e3, e4, e5, e6, e7, e8, e9⟩
      have hce : confirmation r.input c recv = confirmation r.input c0 recv :=
        (confirmation_inj _ _ _ _).2 ⟨e1.symm, e2.symm, e3.symm, e4.symm, e5.symm, e6.symm, e7.symm⟩
      simp only [hce, hfr]
      rw [if_neg (by omega), if_pos ⟨e9.symm, e8, by rw [hpe, e1], by rw [hpo, e2], by rw [hpa, e3],
        by rw [hpt, e4], trivial⟩]
    · intro h
      split at h
      · cases h
      · split at h
        · cases h
        · split at h
          · rename_i hc
            obtain ⟨e9, e8, -, -, -, -, hce⟩ := hc
            obtain ⟨c1, c2, c3, c4, c5, c6, c7⟩ := (confirmation_inj _ _ _ _).1 hce
            exact ⟨c1.symm, c2.symm, c3.symm, c4.symm, c5.symm, c6.symm, c7.symm, e8, e9.symm⟩
          · cases h
  · constructor
    · rintro ⟨e1, -⟩
      exact absurd e1.symm he
    · intro h
      exfalso
      repeat' (split at h)
      all_goals first
        | (rename_i hc; exact he (hc.2.2.1.symm.trans hpe))
        | cases h

end BlindLedger.Gate.Obligations
