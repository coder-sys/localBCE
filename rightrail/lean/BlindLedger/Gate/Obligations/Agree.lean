import BlindLedger.Gate.Obligations.Ident
import BlindLedger.Financial.Codec
import BlindLedger.Financial.FollowThrough

namespace BlindLedger.Gate.Obligations

open BlindLedger.Gate.FactCodec
open BlindLedger.Financial (FinancialResult FinancialContext Payment Claim CaseRecord ActionRecord
  VerificationStatus CaseStatus DeliveryStatus encodeVerificationStatus encodeCaseStatus encodeDeliveryStatus)
open BlindLedger.Financial.FollowThrough (civilFromDays dayMs)

/-! The defining functions of the fixed fields (design `one-store` §2.6): each fixed field of a stored record is
    a function of the element that arrives beside it, and the engine refuses a record whose fields differ
    (`ELEMENT_MISMATCH`).  `element_fixed_agree` says each check holds exactly when every such field equals its
    function.

    Covered here: the state row from its financial result and the amount of its causing element, the action and
    case records from their elements, and the CASH and CLAIM fact rows from the payment and the claim, each on the
    obligation of its financial context.

    Not checked here, each for a stated reason:
    - Fields that a later record changes (an action's status, a payment's reversal) are read from the newest record
      and are not fixed.
    - Roles and reasons are indexes in the pack's lists and are checked against the pack.
    - OBLIG, FUND and ACTACK have no element in the financial codec (§2.1); the owner's row follows them as text.
    - CASH `pays` is the request the payment pays, which its receipt holds and the payment element does not.
    - CLAIM `eventMs` is the event time of the claim's evidence element, which this check does not take; its day
      is checked against `vstart` and `vstop`.
    - `ecls`, `lineUntil`, `receipt` and `roff` are set from the batch and its receipt, not from an element. -/

def utf8 (s : String) : Bytes := s.toUTF8.toList

def scopeOfCtx (c : FinancialContext) : Bytes :=
  scopeOf (utf8 c.stateId) (utf8 c.deploymentId) (utf8 c.programId) (utf8 c.periodId) (utf8 c.currency)

def obOfCtx (c : FinancialContext) : Bytes := obOf (scopeOfCtx c) (utf8 c.itemId)

/-- A display field (base design §7.3): the identifier when it fits, else `0xFF` and the first bytes of its
    `H256`, then zeros. -/
def display (w : Nat) (s : String) : Bytes :=
  if (utf8 s).length < w then UInt8.ofNat (utf8 s).length :: (utf8 s ++ List.replicate (w - 1 - (utf8 s).length) 0)
  else 0xFF :: ((H256 (utf8 s) ++ List.replicate 32 0).take (min 32 (w - 1)) ++
    List.replicate (w - 1 - min 32 (w - 1)) 0)

theorem drop_app {α} (a b : List α) (n : Nat) (h : a.length ≤ n) : (a ++ b).drop n = b.drop (n - a.length) := by
  induction a generalizing n with
  | nil => simp
  | cons x a ih =>
    cases n with
    | zero => simp at h
    | succ n => simp only [List.cons_append, List.drop_succ_cons, List.length_cons]; rw [ih n (by simp at h; omega)]; all_goals simp

/-- A display field is never refused: it always has the width and the form the codecs accept. -/
theorem display_ok (w : Nat) (s : String) (h1 : 1 ≤ w) (h2 : w ≤ 256) :
    dispOk w (display w s) = true ∧ (display w s).length = w := by
  unfold display
  split
  · rename_i hl
    have hn : (UInt8.ofNat (utf8 s).length).toNat = (utf8 s).length := by simp; omega
    have hlen : (UInt8.ofNat (utf8 s).length :: (utf8 s ++ List.replicate (w - 1 - (utf8 s).length) 0)).length = w := by
      simp; omega
    refine ⟨?_, hlen⟩
    simp only [dispOk, idOk, hlen, beq_self_eq_true, Bool.true_and, hn, List.drop_left, allZero_replicate,
      Bool.or_eq_true, Bool.and_eq_true, decide_eq_true_eq]
    exact Or.inl ⟨hl, trivial⟩
  · have hA : ((H256 (utf8 s) ++ List.replicate 32 0).take (min 32 (w - 1))).length = min 32 (w - 1) := by
      simp; omega
    refine ⟨?_, by simp only [List.length_cons, List.length_append, hA, List.length_replicate]; omega⟩
    have hd : ((H256 (utf8 s) ++ List.replicate 32 0).take (min 32 (w - 1)) ++
        List.replicate (w - 1 - min 32 (w - 1)) 0).drop 32 = List.replicate (w - 1 - 32) 0 := by
      rw [drop_app _ _ _ (by omega), hA, List.drop_replicate]
      congr 1
      omega
    simp only [dispOk, List.head?_cons, List.drop_succ_cons, hd, allZero_replicate, Bool.or_eq_true,
      Bool.and_eq_true, beq_self_eq_true, and_self, or_true]

def flagsOf (r : FinancialResult) : Nat :=
  (if r.cashSatisfied then 1 else 0) + (if r.amountSatisfied then 2 else 0) + (if r.timely then 4 else 0) +
    (if r.reportingComplete then 8 else 0)

theorem flagsOf_lt (r : FinancialResult) : flagsOf r < 16 := by
  unfold flagsOf; split <;> split <;> split <;> split <;> omega

/-- The owner's action kinds as codes; any other kind has no code, so no record agrees with it. -/
def akindCode (kind : String) : Option Nat :=
  if kind = "OFFSET_AUTHORIZATION" then some 1 else if kind = "CORRECTION_PAYMENT_REQUEST" then some 2 else none

/-- `cents` is the amount of the element that caused the row: the CASH, the CLAIM or the action; 0 when the cause
    has none. -/
def stateAgree (r : FinancialResult) (cents : Nat) (x : StateRow) : Bool :=
  x.ob == obOfCtx r.context && x.cents == cents && x.owed == r.owedCents && x.received == r.receivedCashCents &&
    x.claimed == r.claimedAdjustmentCents && x.lawful == r.lawfulAdjustmentCents &&
    x.shortfall == r.shortfallCents && x.overage == r.overageCents && x.flags == flagsOf r &&
    x.verification == (encodeVerificationStatus r.verificationStatus).toNat &&
    x.caseStatus == (encodeCaseStatus r.caseStatus).toNat &&
    x.delivery == (encodeDeliveryStatus r.deliveryStatus).toNat && x.rev == r.afterRevision

/-- `scope` and `ob` are the obligation's, from its own records.  The first record of an action (CREATE) is stamped
    with the time the element was created. -/
def actionAgree (scope ob : Bytes) (a : ActionRecord) (x : ActionRec) : Bool :=
  x.ak == akOf scope (utf8 a.actionId) && x.ob == ob && some x.akind == akindCode a.kind &&
    x.amount == a.amountCents && x.payload == a.payloadDigest && x.rev == a.revision &&
    decide (x.op = 1 → x.atMs = a.createdAt)

def caseAgree (scope ob : Bytes) (c : CaseRecord) (x : CaseRec) : Bool :=
  x.ck == ckOf scope (utf8 c.caseId) && x.ob == ob && x.status == (encodeCaseStatus c.status).toNat &&
    x.dueMs == c.dueAt && x.atMs == c.updatedAt

/-- The UTC day (`yyyymmdd`, as a fact row dates it) of a time in milliseconds. -/
def utcDate (ms : Nat) : Nat :=
  match civilFromDays (ms / dayMs) with
  | (y, m, d) => y * 10000 + m * 100 + d

#guard utcDate 1767225600000 == 20260101 && utcDate 1767225599999 == 20251231 && utcDate 951782400000 == 20000229

/-- A CASH row asserts the payment of its element on the obligation of `c`, dated on the payment's UTC day.  A void
    row (op 1) follows its reversal evidence, not a payment, and is not checked here. -/
def cashAgree (c : FinancialContext) (p : Payment) (x : CashF) : Bool :=
  x.h.op == 0 && p.obligationId == c.obligationId && p.itemId == c.itemId && x.h.subject == obOfCtx c &&
    x.h.sid == sidOf 15 [obOfCtx c, utf8 p.commonOriginId] && x.h.vstart == utcDate p.eventAt &&
    x.h.vstop == utcDate p.eventAt && x.amount == p.amountCents && x.eventMs == p.eventAt &&
    x.pid == cidOf (scopeOfCtx c) (utf8 ("PAYMENT:" ++ p.paymentId)) && x.origin == display 51 p.commonOriginId

/-- A CLAIM row asserts the claim of its element on the obligation of `c`, dated on the UTC day of its `eventMs`. -/
def claimAgree (c : FinancialContext) (cl : Claim) (x : ClaimF) : Bool :=
  x.h.op == 0 && cl.obligationId == c.obligationId && x.h.subject == obOfCtx c &&
    x.h.sid == sidOf 22 [obOfCtx c, utf8 cl.claimId] && x.h.vstart == utcDate x.eventMs &&
    x.h.vstop == utcDate x.eventMs && x.amount == cl.amountCents && x.deadlineMs == cl.deadlineAt &&
    x.claim == display 51 cl.claimId

/-- `element_fixed_agree` (§9.2): each check holds exactly when every fixed field equals its function of the
    element. -/
theorem element_fixed_agree :
    (∀ r cents x, stateAgree r cents x = true ↔
      x.ob = obOfCtx r.context ∧ x.cents = cents ∧ x.owed = r.owedCents ∧ x.received = r.receivedCashCents ∧
      x.claimed = r.claimedAdjustmentCents ∧ x.lawful = r.lawfulAdjustmentCents ∧
      x.shortfall = r.shortfallCents ∧ x.overage = r.overageCents ∧ x.flags = flagsOf r ∧
      x.verification = (encodeVerificationStatus r.verificationStatus).toNat ∧
      x.caseStatus = (encodeCaseStatus r.caseStatus).toNat ∧
      x.delivery = (encodeDeliveryStatus r.deliveryStatus).toNat ∧ x.rev = r.afterRevision) ∧
    (∀ scope ob a x, actionAgree scope ob a x = true ↔
      x.ak = akOf scope (utf8 a.actionId) ∧ x.ob = ob ∧ some x.akind = akindCode a.kind ∧
      x.amount = a.amountCents ∧ x.payload = a.payloadDigest ∧ x.rev = a.revision ∧
      (x.op = 1 → x.atMs = a.createdAt)) ∧
    (∀ scope ob c x, caseAgree scope ob c x = true ↔
      x.ck = ckOf scope (utf8 c.caseId) ∧ x.ob = ob ∧ x.status = (encodeCaseStatus c.status).toNat ∧
      x.dueMs = c.dueAt ∧ x.atMs = c.updatedAt) ∧
    (∀ c p x, cashAgree c p x = true ↔
      x.h.op = 0 ∧ p.obligationId = c.obligationId ∧ p.itemId = c.itemId ∧ x.h.subject = obOfCtx c ∧
      x.h.sid = sidOf 15 [obOfCtx c, utf8 p.commonOriginId] ∧ x.h.vstart = utcDate p.eventAt ∧
      x.h.vstop = utcDate p.eventAt ∧ x.amount = p.amountCents ∧ x.eventMs = p.eventAt ∧
      x.pid = cidOf (scopeOfCtx c) (utf8 ("PAYMENT:" ++ p.paymentId)) ∧ x.origin = display 51 p.commonOriginId) ∧
    (∀ c cl x, claimAgree c cl x = true ↔
      x.h.op = 0 ∧ cl.obligationId = c.obligationId ∧ x.h.subject = obOfCtx c ∧
      x.h.sid = sidOf 22 [obOfCtx c, utf8 cl.claimId] ∧ x.h.vstart = utcDate x.eventMs ∧
      x.h.vstop = utcDate x.eventMs ∧ x.amount = cl.amountCents ∧ x.deadlineMs = cl.deadlineAt ∧
      x.claim = display 51 cl.claimId) := by
  refine ⟨?_, ?_, ?_, ?_, ?_⟩ <;> intros <;>
    simp only [stateAgree, actionAgree, caseAgree, cashAgree, claimAgree, Bool.and_eq_true, beq_iff_eq, and_assoc,
      decide_eq_true_eq]

theorem status_codes (v : VerificationStatus) (s : CaseStatus) (d : DeliveryStatus) :
    1 ≤ (encodeVerificationStatus v).toNat ∧ (encodeVerificationStatus v).toNat ≤ 3 ∧
      1 ≤ (encodeCaseStatus s).toNat ∧ (encodeCaseStatus s).toNat ≤ 5 ∧
      1 ≤ (encodeDeliveryStatus d).toNat ∧ (encodeDeliveryStatus d).toNat ≤ 4 := by
  cases v <;> cases s <;> cases d <;> decide

/-- The state row's status ranges are exactly the codes a financial result can hold: a row that agrees with a
    result, with its fields in their widths and its event and legacy codes in range, reads back as itself. -/
theorem state_row_roundtrip {r : FinancialResult} {cents : Nat} {x : StateRow} (hf : fit stateC.L (stateC.toC x))
    (hm : 13 ≤ x.mkind ∧ x.mkind ≤ 25) (hl : x.lg < 4) (ha : stateAgree r cents x = true) :
    stateC.dec (stateC.enc x) = some x := by
  obtain ⟨-, -, -, -, -, -, -, -, hfl, hv, hc, hd, -⟩ := (element_fixed_agree.1 r cents x).1 ha
  have hs := status_codes r.verificationStatus r.caseStatus r.deliveryStatus
  have hfr := flagsOf_lt r
  refine RecCodec.dec_enc stateC_ok.1 ⟨hf, ?_⟩
  simp only [stateC, decide_eq_true_eq]
  omega

end BlindLedger.Gate.Obligations
