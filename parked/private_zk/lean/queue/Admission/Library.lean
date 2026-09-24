import Admission.Model

namespace BlindLedger.Admission

def exportedRun (data : Bytes) : Bytes :=
  decisionBytes (match decodeInput data with
    | some input => evaluate input
    | none => malformedDecision)

@[export blind_ledger_admission_run_bytes]
def exportedRunBytes (data : Bytes) : Bytes := exportedRun data

end BlindLedger.Admission
