import Admission.Model

namespace BlindLedger.Admission

def checkerEq {α : Type} [DecidableEq α] (left right : α) : Bool :=
  decide (left = right)

def checkerInputBounded (input : Input) : Bool :=
  decide (input.proofUsed ≤ input.proofCap) &&
    decide (input.proofCap ≤ counterMax) &&
    decide (input.sourceAUsed ≤ input.sourceACap) &&
    decide (input.sourceACap ≤ counterMax) &&
    decide (input.sourceSUsed ≤ input.sourceSCap) &&
    decide (input.sourceSCap ≤ counterMax) &&
    decide (input.sourceMUsed ≤ input.sourceMCap) &&
    decide (input.sourceMCap ≤ counterMax) &&
    decide (input.sourceUUsed ≤ input.sourceUCap) &&
    decide (input.sourceUCap ≤ counterMax) &&
    decide (input.verifierVUsed ≤ input.verifierVCap) &&
    decide (input.verifierVCap ≤ counterMax)

def checkerNoRefund (input : Input) (decision : Decision) : Bool :=
  decide (input.proofUsed ≤ decision.proofUsed) &&
    decide (input.sourceAUsed ≤ decision.sourceAUsed) &&
    decide (input.sourceSUsed ≤ decision.sourceSUsed) &&
    decide (input.sourceMUsed ≤ decision.sourceMUsed) &&
    decide (input.sourceUUsed ≤ decision.sourceUUsed) &&
    decide (input.verifierVUsed ≤ decision.verifierVUsed)

def checkerWithinCaps (decision : Decision) : Bool :=
  decide (decision.proofUsed ≤ decision.proofCap) &&
    decide (decision.sourceAUsed ≤ decision.sourceACap) &&
    decide (decision.sourceSUsed ≤ decision.sourceSCap) &&
    decide (decision.sourceMUsed ≤ decision.sourceMCap) &&
    decide (decision.sourceUUsed ≤ decision.sourceUCap) &&
    decide (decision.verifierVUsed ≤ decision.verifierVCap)

def checkerCapsPreserved (input : Input) (decision : Decision) : Bool :=
  decide (decision.proofCap = input.proofCap) &&
    decide (decision.sourceACap = input.sourceACap) &&
    decide (decision.sourceSCap = input.sourceSCap) &&
    decide (decision.sourceMCap = input.sourceMCap) &&
    decide (decision.sourceUCap = input.sourceUCap) &&
    decide (decision.verifierVCap = input.verifierVCap)

def checkerStateValid (decision : Decision) : Bool :=
  match decision.batch, decision.source, decision.verifier, decision.terminal with
  | .verified, .absent, .completed, .accepted => true
  | .verified, .authorized, .completed, .accepted => true
  | .verified, .started, .completed, .accepted => true
  | .verified, .completed, .completed, .accepted => true
  | .verified, .unknown, .completed, .accepted => true
  | .rejected, .absent, .completed, .rejected => true
  | .rejected, .authorized, .completed, .rejected => true
  | .rejected, .started, .completed, .rejected => true
  | .rejected, .completed, .completed, .rejected => true
  | .rejected, .unknown, .completed, .rejected => true
  | .held, .absent, .unreserved, .aborted => true
  | .held, .completed, .unreserved, .aborted => true
  | .held, .completed, .unknown, .aborted => true
  | .held, .completed, .unknown, .unknown => true
  | .held, .unknown, .unreserved, .unknown => true
  | .held, .unknown, .unknown, .unknown => true
  | .awaiting, .absent, .unreserved, .none => true
  | .awaiting, .authorized, .unreserved, .none => true
  | .awaiting, .started, .unreserved, .none => true
  | .awaiting, .completed, .unreserved, .none => true
  | .queued, .completed, .unreserved, .none => true
  | .queued, .absent, .unreserved, .none => true
  | .leased, .absent, .unreserved, .none => true
  | .leased, .completed, .unreserved, .none => true
  | .leased, .absent, .started, .none => true
  | .leased, .completed, .started, .none => true
  | _, _, _, _ => false

def checkerPreserved (input : Input) (decision : Decision) : Bool :=
  decide (decision.proofUsed = input.proofUsed) &&
    decide (decision.sourceAUsed = input.sourceAUsed) &&
    decide (decision.sourceSUsed = input.sourceSUsed) &&
    decide (decision.sourceMUsed = input.sourceMUsed) &&
    decide (decision.sourceUUsed = input.sourceUUsed) &&
    decide (decision.verifierVUsed = input.verifierVUsed) &&
    checkerCapsPreserved input decision

def checkerAccepted (label : String) (input : Input)
    (batch : BatchPhase) (source : SourcePhase)
    (verifier : VerifierPhase) (terminal : TerminalKind) : Except String Unit :=
  let decision := evaluate input
  if checkerInputBounded input && decision.accepted &&
      checkerEq decision.code .ok && checkerEq decision.op input.op &&
      checkerEq decision.batch batch && checkerEq decision.source source &&
      checkerEq decision.verifier verifier && checkerEq decision.terminal terminal &&
      checkerStateValid decision && checkerNoRefund input decision &&
      checkerWithinCaps decision && checkerCapsPreserved input decision then
    .ok ()
  else
    .error label

def checkerRejected (label : String) (input : Input)
    (code : DecisionCode) : Except String Unit :=
  let decision := evaluate input
  if checkerInputBounded input && !decision.accepted &&
      checkerEq decision.code code && checkerEq decision.op input.op &&
      checkerPreserved input decision then
    .ok ()
  else
    .error label

def base (op : Op) (batch : BatchPhase) (source : SourcePhase)
    (verifier : VerifierPhase) (terminal : TerminalKind) : Input :=
  { op := op
    batch := batch
    source := source
    verifier := verifier
    terminal := terminal
    proofUsed := 0
    proofCap := counterMax
    sourceAUsed := 0
    sourceACap := counterMax
    sourceSUsed := 0
    sourceSCap := counterMax
    sourceMUsed := 0
    sourceMCap := counterMax
    sourceUUsed := 0
    sourceUCap := counterMax
    verifierVUsed := 0
    verifierVCap := counterMax }

def issueOverflow : Input :=
  { base .issue .awaiting .absent .unreserved .none with
    proofUsed := counterMax - 50 }

def sourceAdmissionOverflow : Input :=
  { base .sourceAdmit .awaiting .absent .unreserved .none with
    sourceSUsed := counterMax - 100 }

def verifierReservationOverflow : Input :=
  { base .verifierReserve .leased .completed .unreserved .none with
    verifierVUsed := counterMax }

def checks : List (String × Except String Unit) :=
  [
    ("issue", checkerAccepted "issue" (base .issue .awaiting .absent .unreserved .none)
      .awaiting .absent .unreserved .none),
    ("source_admit", checkerAccepted "source_admit"
      (base .sourceAdmit .awaiting .absent .unreserved .none)
      .awaiting .authorized .unreserved .none),
    ("source_start", checkerAccepted "source_start"
      (base .sourceStart .awaiting .authorized .unreserved .none)
      .awaiting .started .unreserved .none),
    ("source_finish_success", checkerAccepted "source_finish_success"
      (base .sourceFinishSuccess .awaiting .started .unreserved .none)
      .awaiting .completed .unreserved .none),
    ("source_finish_unknown", checkerAccepted "source_finish_unknown"
      (base .sourceFinishUnknown .awaiting .started .unreserved .none)
      .held .unknown .unreserved .unknown),
    ("verifier_reserve", checkerAccepted "verifier_reserve"
      (base .verifierReserve .leased .completed .unreserved .none)
      .leased .completed .started .none),
    ("verifier_reserve_absent", checkerAccepted "verifier_reserve_absent"
      (base .verifierReserve .leased .absent .unreserved .none)
      .leased .absent .started .none),
    ("verifier_finish_accepted", checkerAccepted "verifier_finish_accepted"
      (base .verifierFinishAccepted .leased .completed .started .none)
      .verified .completed .completed .accepted),
    ("verifier_finish_accepted_absent", checkerAccepted "verifier_finish_accepted_absent"
      (base .verifierFinishAccepted .leased .absent .started .none)
      .verified .absent .completed .accepted),
    ("verifier_finish_rejected", checkerAccepted "verifier_finish_rejected"
      (base .verifierFinishRejected .leased .completed .started .none)
      .rejected .completed .completed .rejected),
    ("verifier_finish_aborted", checkerAccepted "verifier_finish_aborted"
      (base .verifierFinishAborted .leased .completed .started .none)
      .held .completed .unknown .aborted),
    ("verifier_finish_unknown", checkerAccepted "verifier_finish_unknown"
      (base .verifierFinishUnknown .leased .completed .started .none)
      .held .completed .unknown .unknown),
    ("recover_clean_absent", checkerAccepted "recover_clean_absent"
      (base .recover .awaiting .absent .unreserved .none)
      .held .absent .unreserved .aborted),
    ("recover_clean_completed", checkerAccepted "recover_clean_completed"
      (base .recover .awaiting .completed .unreserved .none)
      .held .completed .unreserved .aborted),
    ("recover_source_authorized", checkerAccepted "recover_source_authorized"
      (base .recover .awaiting .authorized .unreserved .none)
      .held .unknown .unreserved .unknown),
    ("recover_source_started", checkerAccepted "recover_source_started"
      (base .recover .awaiting .started .unreserved .none)
      .held .unknown .unreserved .unknown),
    ("recover_queued_absent", checkerAccepted "recover_queued_absent"
      (base .recover .queued .absent .unreserved .none)
      .held .absent .unreserved .aborted),
    ("recover_leased_verifier_started", checkerAccepted "recover_leased_verifier_started"
      (base .recover .leased .completed .started .none)
      .held .completed .unknown .unknown),
    ("recover_leased_absent", checkerAccepted "recover_leased_absent"
      (base .recover .leased .absent .unreserved .none)
      .held .absent .unreserved .aborted),
    ("issue_overflow", checkerRejected "issue_overflow" issueOverflow .overflow),
    ("source_admit_overflow", checkerRejected "source_admit_overflow"
      sourceAdmissionOverflow .overflow),
    ("verifier_reserve_overflow", checkerRejected "verifier_reserve_overflow"
      verifierReservationOverflow .overflow)
  ]

def main : IO Unit := do
  let mut passed := 0
  for (label, result) in checks do
    match result with
    | .ok _ => passed := passed + 1
    | .error error => throw (IO.userError s!"INDEPENDENT_ADMISSION_CHECKER=FAIL case={label};error={error}")
  IO.println s!"INDEPENDENT_ADMISSION_CHECKER=PASS cases={passed} accepted=19 rejected=3"

end BlindLedger.Admission

def main : IO Unit := BlindLedger.Admission.main
