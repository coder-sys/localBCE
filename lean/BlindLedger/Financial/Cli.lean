import BlindLedger.Financial.Executable
import BlindLedger.Financial.DecisionPackage
import BlindLedger.Financial.CorrectionTransition
import BlindLedger.Financial.CorrectionTransition.Runtime

namespace BlindLedger.Financial

open BlindLedger.Financial.DecisionPackage
open BlindLedger.Financial.CorrectionTransition

def financialExitUsage : UInt8 := UInt8.ofNat 64
def financialExitKat : UInt8 := UInt8.ofNat 70
def financialExitPackageDecode : UInt8 := UInt8.ofNat 68
def financialExitPackageProjection : UInt8 := UInt8.ofNat 69
def financialExitPackageKat : UInt8 := UInt8.ofNat 71
def financialExitTransitionDecode : UInt8 :=
  BlindLedger.Financial.CorrectionTransition.Runtime.financialExitTransitionDecode
def financialExitTransitionEncoding : UInt8 :=
  BlindLedger.Financial.CorrectionTransition.Runtime.financialExitTransitionEncoding
def financialExitTransitionKat : UInt8 := UInt8.ofNat 74
def financialExitReuseDecode : UInt8 :=
  BlindLedger.Financial.CorrectionTransition.Runtime.financialExitReuseDecode
def financialExitReuseEncoding : UInt8 :=
  BlindLedger.Financial.CorrectionTransition.Runtime.financialExitReuseEncoding

def printGate (entry : String × Bool) : IO Unit := do
  IO.println ("GATE name=" ++ entry.1 ++ " result=" ++
    (if entry.2 then "PASS" else "FAIL"))

def runFailure (code : UInt8) (reason : String) : IO Unit := do
  IO.eprintln ("FINANCIAL_ERROR=" ++ reason)
  IO.Process.exit code

def runKat : IO Unit := do
  IO.println "BLFIN02"
  IO.println "claim=PURE_SYNTHETIC_NONACTIVATING"
  IO.println ("KAT_COUNT=" ++ toString executableGateLines.length)
  for entry in executableGateLines do
    printGate entry
  IO.println ("THEOREM_MANIFEST_COUNT=" ++ toString financialTheoremNames.length)
  for name in financialTheoremNames do
    IO.println ("THEOREM_DECLARATION name=" ++ name)
  if executableGatesPass then
    IO.println "FINANCIAL_KERNEL_RESULT=PASS"
  else
    runFailure financialExitKat "kat-gate-failure"

partial def readFinancialBounded
    (stream : IO.FS.Stream) (remaining : Nat) (accumulator : ByteArray) : IO ByteArray :=
  BlindLedger.Financial.CorrectionTransition.Runtime.readFinancialBounded
    stream remaining accumulator

def runKatInput : IO Unit := do
  let stdout ← IO.getStdout
  stdout.write katWire.toByteArray
  stdout.flush

def runDecisionPackageKat : IO Unit := do
  IO.println "BLFDCP01/BLFDPR01"
  IO.println "claim=PURE_SYNTHETIC_NONACTIVATING"
  IO.println ("DECISION_PACKAGE_KAT_COUNT=" ++ toString decisionPackageKatCount)
  for entry in decisionPackageKatLines do
    IO.println ("DECISION_PACKAGE_GATE name=" ++ entry.1 ++ " result=" ++
      (if entry.2 then "PASS" else "FAIL"))
  if decisionPackageKatsPass then
    IO.println "FINANCIAL_DECISION_PACKAGE_RESULT=PASS"
  else
    runFailure financialExitPackageKat "decision-package-kat-failure"

def runProjectDecisionPackage : IO Unit := do
  let stdin ← IO.getStdin
  let bounded ← readFinancialBounded stdin (maxDecisionPackageBytes + 1) ByteArray.empty
  if bounded.size > maxDecisionPackageBytes then
    runFailure financialExitPackageDecode "decision-package-input-too-large"
  else
    match decodeDecisionPackageInput bounded.toList with
    | none => runFailure financialExitPackageDecode "decision-package-input-decode"
    | some input =>
        match projectDecisionPackage input with
        | none => runFailure financialExitPackageProjection "decision-package-binding-rejected"
        | some projection =>
            match encodeDecisionPackageProjection projection with
            | none => runFailure financialExitPackageProjection "decision-package-output-encoding"
            | some output =>
                let stdout ← IO.getStdout
                stdout.write output.toByteArray
                stdout.flush

def runCorrectionTransitionKat : IO Unit := do
  IO.println "BLFCMD02/BLFCRES3"
  IO.println "contract=RR/FINANCIAL/CORRECTION-TRANSITION/v1"
  IO.println "claim=PURE_SYNTHETIC_NONACTIVATING"
  IO.println ("CORRECTION_TRANSITION_KAT_COUNT=" ++ toString correctionTransitionKatCount)
  for entry in correctionTransitionKatLines do
    IO.println ("CORRECTION_TRANSITION_GATE name=" ++ entry.1 ++ " result=" ++
      (if entry.2 then "PASS" else "FAIL"))
  if correctionTransitionKatsPass then
    IO.println "FINANCIAL_CORRECTION_TRANSITION_RESULT=PASS"
  else
    runFailure financialExitTransitionKat "correction-transition-kat-failure"

def runApplyCorrectionTransition : IO Unit :=
  BlindLedger.Financial.CorrectionTransition.Runtime.runApplyCorrectionTransition

def runAssessCorrectionReuse : IO Unit :=
  BlindLedger.Financial.CorrectionTransition.Runtime.runAssessCorrectionReuse

def main (args : List String) : IO Unit := do
  match args with
  | ["--kat"] => runKat
  | ["--decision-package-kat"] => runDecisionPackageKat
  | ["--emit-kat-input"] => runKatInput
  | ["--project-decision-package"] => runProjectDecisionPackage
  | ["--correction-transition-kat"] => runCorrectionTransitionKat
  | ["--apply-correction-transition"] => runApplyCorrectionTransition
  | ["--assess-correction-reuse"] => runAssessCorrectionReuse
  | _ =>
      IO.eprintln "FINANCIAL_ERROR=usage expected --kat, --emit-kat-input, --decision-package-kat, --project-decision-package, --correction-transition-kat, --apply-correction-transition, or --assess-correction-reuse"
      IO.Process.exit financialExitUsage

end BlindLedger.Financial

def main (args : List String) : IO Unit := BlindLedger.Financial.main args
