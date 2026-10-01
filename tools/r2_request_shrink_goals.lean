import BlindLedger.Financial.Payment.Bridge

/-! R2, open correction requests shrink and regrow with the unpaid balance: the theorem STATEMENTS
    of design C:\Users\neers\rrb\designs\r2-request-shrink-v1.md §7.  Every proof is `sorry`.
    This file is outside `lean/`, so no executable, library target, TCB report or pin manifest sees it.
    Check: from `lean/`, `lake env lean ../tools/r2_request_shrink_goals.lean` over a build of
    `BlindLedger.Financial.Payment.Bridge`.
    Status against trunk d02458a: the definitions and statements 1-5 and 8 are true of trunk's code.
    6, 6a and 7 are FALSE of trunk's `decideRecord` (it has no open-amount refusal) and become
    provable only with the M3 step 2 link rule (design §7.2).  The M3 step 2 builder moves the
    definitions to a new `lean/BlindLedger/Financial/Payment/Open.lean`, each statement, unchanged,
    beside them with its proof and an axiom pin, and deletes it here. -/

namespace BlindLedger.Financial.Payment

open BlindLedger.Financial BlindLedger.Financial.CorrectionTransition

/-- A request that still asks for money: exactly the filter of `linkedOutstandingCents`. -/
def countedRequest (x : ActionRecord) : Bool :=
  x.kind == "CORRECTION_PAYMENT_REQUEST" && x.status != .CANCELLED

/-- `b` is served before `a`: made at an earlier revision, then by action id. -/
def servedBefore (b a : ActionRecord) : Bool :=
  b.revision < a.revision || (b.revision == a.revision && decide (b.actionId < a.actionId))

/-- What request `x` asks for that active linked payments have not paid. -/
def unpaidOf (ps : List Payment) (ls : List PaymentLink) (x : ActionRecord) : Nat :=
  x.amountCents - linkedActivePaidCents ps ls x.actionId

/-- The unpaid parts of the counted requests served before `a`. -/
def unpaidBefore (ps : List Payment) (ls : List PaymentLink) (xs : List ActionRecord)
    (a : ActionRecord) : Nat :=
  ((xs.filter fun b => countedRequest b && servedBefore b a).map (unpaidOf ps ls)).sum

/-- R2: what request `a` may still collect when the unpaid balance is `s`.  Older requests keep
    their unpaid part first; the newest are reduced first. -/
def openCents (s : Nat) (ps : List Payment) (ls : List PaymentLink) (xs : List ActionRecord)
    (a : ActionRecord) : Nat :=
  if countedRequest a then min (unpaidOf ps ls a) (s - unpaidBefore ps ls xs a) else 0

def openTotal (s : Nat) (ps : List Payment) (ls : List PaymentLink) (xs : List ActionRecord) : Nat :=
  (xs.map (openCents s ps ls xs)).sum

/-! Known answers (executed by `lake env lean`): two requests of 300,000 at revisions 1 and 2. -/

private def kReq (id : String) (rev : Nat) : ActionRecord :=
  { actionId := id, obligationId := "o", determinationId := none, kind := "CORRECTION_PAYMENT_REQUEST",
    amountCents := 300000, currency := "USD", revision := rev, status := .READY, payloadDigest := [],
    createdAt := rev }
private def kPay (id : String) (cents : Nat) : Payment :=
  { paymentId := id, obligationId := "o", itemId := "i", evidenceId := id, commonOriginId := id,
    amountCents := cents, eventAt := 0, reversalEvidenceId := none, status := .ACTIVE }
private def kXs : List ActionRecord := [kReq "b" 2, kReq "a" 1]  -- list order is not service order

-- Balance 400,000 after 200,000 unlinked: the older request keeps 300,000, the newer is cut to 100,000.
#guard kXs.map (openCents 400000 [] [] kXs) == [100000, 300000]
-- Balance 0: both are cut to nothing; balance back to 600,000 (a reversal): both regrow to 300,000.
#guard kXs.map (openCents 0 [] [] kXs) == [0, 0]
#guard kXs.map (openCents 600000 [] [] kXs) == [300000, 300000]
-- 100,000 paid on the older one at balance 500,000: it keeps 200,000, the newer keeps all 300,000.
#guard kXs.map (openCents 500000 [kPay "p" 100000] [⟨"p", "a"⟩] kXs) == [300000, 200000]
-- A cancelled request asks for nothing and gives way to the next.
#guard openCents 300000 [] [] [kReq "b" 2, { kReq "a" 1 with status := .CANCELLED }] (kReq "b" 2) == 300000
#guard openTotal 400000 [] [] kXs == min (linkedOutstandingCents [] [] kXs) 400000

/-! ## Statements -/

/-- 1. The allocation identity: the open amounts add up to the outstanding requests, capped by
    the balance.  The substance of R2; statements 2, 3, 4 and 8 follow from it. -/
theorem openTotal_eq_min (s : Nat) (ps : List Payment) (ls : List PaymentLink)
    (xs : List ActionRecord) (hn : (xs.map ActionRecord.actionId).Nodup) :
    openTotal s ps ls xs = min (linkedOutstandingCents ps ls xs) s := by
  sorry

/-- 2. The literal core-theorems item-1 invariant, for every state Lean evaluates, whatever
    command produced it (payment, reversal, correction or offset authorization).  From 1: `evaluate`
    answers only well-formed inputs, whose action ids are distinct (`nodup_actions_of_wf`). -/
theorem requests_within_balance (i : FinancialInput) (res : FinancialResult) (ls : List PaymentLink)
    (h : evaluate i = some res) :
    openTotal res.shortfallCents i.payments ls i.actions ≤ res.shortfallCents := by
  sorry

/-- 3. R2 is invisible while the requests fit the balance, in particular right after every
    correction (with T1.1, `applyCorrectionTransition_post_within_shortfall`). -/
theorem openCents_eq_unpaid_of_within (s : Nat) (ps : List Payment) (ls : List PaymentLink)
    (xs : List ActionRecord) (hn : (xs.map ActionRecord.actionId).Nodup)
    (hw : linkedOutstandingCents ps ls xs ≤ s) {a : ActionRecord} (ha : a ∈ xs)
    (hc : countedRequest a = true) :
    openCents s ps ls xs a = unpaidOf ps ls a := by
  sorry

/-- 4. The pinned correction engine already decides by open amounts: its refusal
    `NO_REQUESTABLE_BALANCE` and its new request amount (`amountRule`, through
    `outstandingCorrectionCents_eq_linked`) are unchanged when outstanding requests are replaced by
    their open total.  No engine change and no re-pin. -/
theorem engine_requestable_agrees (s : Nat) (ps : List Payment) (ls : List PaymentLink)
    (xs : List ActionRecord) (hn : (xs.map ActionRecord.actionId).Nodup) :
    (linkedOutstandingCents ps ls xs < s ↔ openTotal s ps ls xs < s) ∧
      s - linkedOutstandingCents ps ls xs = s - openTotal s ps ls xs := by
  sorry

/-- 5. Paying request `a` by at most its open amount lowers `a`'s open amount by exactly the
    payment and leaves every other request's open amount unchanged. -/
theorem openCents_pay_local (s m : Nat) (ps ps' : List Payment) (ls ls' : List PaymentLink)
    (xs : List ActionRecord) (hn : (xs.map ActionRecord.actionId).Nodup)
    {a : ActionRecord} (ha : a ∈ xs) (hm : m ≤ openCents s ps ls xs a)
    (hpaid : ∀ x ∈ xs, linkedActivePaidCents ps' ls' x.actionId =
      linkedActivePaidCents ps ls x.actionId + (if x.actionId = a.actionId then m else 0)) :
    ∀ x ∈ xs, openCents (s - m) ps' ls' xs x + (if x.actionId = a.actionId then m else 0) =
      openCents s ps ls xs x := by
  sorry

/-- 6. (M3 step 2, `Payment/Laws.lean`) A recorded linked payment is within its request's open
    amount at the moment it is recorded.  False of trunk's `decideRecord`; true after §7.2. -/
theorem record_link_within_open {r : PaymentRequest} {c : RecordCommand} {w : Writes}
    {post : FinancialInput} {result : FinancialResult} {a : String}
    (hc : r.command = .record c) (ha : c.paysActionId = some a)
    (h : paymentTransition r = .mutated .RECORDED w post result) :
    ∃ before x, evaluate r.input = some before ∧ x ∈ r.input.actions ∧ x.actionId = a ∧
      x.kind = "CORRECTION_PAYMENT_REQUEST" ∧
      c.amountCents ≤ openCents before.shortfallCents r.input.payments (linksOf r.receipts)
        r.input.actions x := by
  sorry

/-- 6a. R1 (core-theorems-v1 §4.4, statement unchanged), now a corollary of 6. -/
theorem record_link_within_shortfall {r c w post result a}
    (hc : r.command = .record c) (ha : c.paysActionId = some a)
    (h : paymentTransition r = .mutated .RECORDED w post result) :
    ∃ before, evaluate r.input = some before ∧ c.amountCents ≤ before.shortfallCents := by
  sorry

/-- 7. (M3 step 2, `Payment/Bridge.lean`) Over any command sequence, every cent recorded to a
    request was within that request's open amount just before.  Replaces R1-run
    (`run_linked_within_shortfall`), which becomes its corollary. -/
theorem run_linked_within_open (L : Ledger) (hL : ledgerWellFormed L) (calls : List Call)
    (hc : clocksOk L calls) (n : Nat) (call : Call) (hn : calls[n]? = some call) (a : String) :
    recordedTo1 a ((run L (calls.take n)).outcome call) = 0 ∨
      ∃ before x, evaluate ((run L (calls.take n)).request call).input = some before ∧
        x ∈ (run L (calls.take n)).input.actions ∧ x.actionId = a ∧
        recordedTo1 a ((run L (calls.take n)).outcome call) ≤
          openCents before.shortfallCents (run L (calls.take n)).input.payments
            (linksOf (run L (calls.take n)).receipts) (run L (calls.take n)).input.actions x := by
  sorry

/-- 8. core-theorems-v1 §4.4 `run_requests_within_balance`: after any command sequence, the open
    requests fit the unpaid balance.  Statement 2 at every prefix; it needs no well-formedness or
    clock premise because statement 2 holds in every state Lean evaluates. -/
theorem run_requests_within_balance (L : Ledger) (calls : List Call) (n : Nat) (res : FinancialResult)
    (h : evaluate (run L (calls.take n)).input = some res) :
    openTotal res.shortfallCents (run L (calls.take n)).input.payments
        (linksOf (run L (calls.take n)).receipts) (run L (calls.take n)).input.actions ≤
      res.shortfallCents := by
  sorry

end BlindLedger.Financial.Payment
