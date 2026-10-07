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

end BlindLedger.Financial.Payment
