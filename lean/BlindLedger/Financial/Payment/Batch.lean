import BlindLedger.Financial.Payment.Chain

namespace BlindLedger.Financial.Payment

open BlindLedger.Financial

/-! Owner batch (hold-release r4.2 section 11). Not imported by any executable.
    Per call the store keeps the rows and the event, never the intermediate evaluation
    (semantic_adapter.py:1146-1175; owner.py:3992 moves to once per obligation per chunk). -/

/-- What section 11 stores of one call: `PaymentOutcome` without `post`, and of the result only
    the event's before/after revision. -/
inductive Erased where
  | mutated (kind : Mutation) (writes : Writes) (beforeRevision afterRevision : Nat)
  | alias (paymentId : String) (evidence : EvidenceRecord)
  | duplicate (paymentId : Option String)
  | conflictUnchanged (conflictId : String)
  | refused (reason : Refusal)
deriving DecidableEq, Repr

def erase : PaymentOutcome → Erased
  | .mutated k w _ res => .mutated k w res.beforeRevision res.afterRevision
  | .alias pid e _ => .alias pid e
  | .duplicate pid => .duplicate pid
  | .conflictUnchanged id => .conflictUnchanged id
  | .refused f => .refused f

/-- The stored part of a view step: its summary and result are not stored per call. -/
def Erased.ofStep : StepOutcome → Erased
  | .mutated k w _ res => .mutated k w res.beforeRevision res.afterRevision
  | .alias pid e => .alias pid e
  | .duplicate pid => .duplicate pid
  | .conflictUnchanged id => .conflictUnchanged id
  | .refused f => .refused f

/-- What one write needs of the pre-state to decide `evaluate (applyWrites i w)` (`evaluate_delta`):
    two row counts, the active cash (unbounded: a REVERSE can bring it back under `maxCents`) and
    the lawful sum when both claim sums exist. O(1) to carry per call. The head, the payment count
    and the new rows' well-formedness are not carried: under `requestWellFormed` they hold for
    every write a transition makes (`evaluate_delta`). -/
structure Summary where
  evidence : Nat
  conflicts : Nat
  cash : Nat
  lawful : Option Nat

/-- The specification of the carried summary (O(input); `batchFast` never calls it per call). -/
def summary (i : FinancialInput) : Summary :=
  { evidence := i.evidence.length, conflicts := i.conflicts.length, cash := activeCents i.payments,
    lawful := (evalClaimedSum i.claims).bind fun _ => evalLawfulSum i.claims }

/-- `evaluate (applyWrites i w)` is `some`, read from the summary (`evaluate_delta`). A payment
    write with a receipt inserts an ACTIVE row (RECORDED); without one it replaces an ACTIVE row by
    its REVERSED image, same amount. -/
def deltaOk (s : Summary) (w : Writes) : Bool :=
  let cash := match w.payment with
    | none => s.cash
    | some p => if w.receipt.isSome then s.cash + p.amountCents else s.cash - p.amountCents
  s.evidence + (if w.evidence.isSome then 1 else 0) ≤ maxRows &&
    s.conflicts + (if w.conflict.isSome then 1 else 0) ≤ maxRows &&
    s.lawful.any fun l => cash + l ≤ maxCents

end BlindLedger.Financial.Payment
