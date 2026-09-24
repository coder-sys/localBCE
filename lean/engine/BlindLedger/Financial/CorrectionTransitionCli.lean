import BlindLedger.Financial.CorrectionTransition.Runtime

namespace BlindLedger.Financial.CorrectionTransitionCli

def financialExitUsage : UInt8 := UInt8.ofNat 64

def main (args : List String) : IO Unit := do
  match args with
  | ["--apply-correction-transition"] =>
      BlindLedger.Financial.CorrectionTransition.Runtime.runApplyCorrectionTransition
  | ["--assess-correction-reuse"] =>
      BlindLedger.Financial.CorrectionTransition.Runtime.runAssessCorrectionReuse
  | _ =>
      IO.eprintln "FINANCIAL_ERROR=usage expected --apply-correction-transition or --assess-correction-reuse"
      IO.Process.exit financialExitUsage

end BlindLedger.Financial.CorrectionTransitionCli

def main (args : List String) : IO Unit := BlindLedger.Financial.CorrectionTransitionCli.main args
