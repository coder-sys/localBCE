import BlindLedger.Financial.CorrectionTransition.Codec
import BlindLedger.Financial.CorrectionTransition.ReuseCodec
import BlindLedger.Financial.ReadUpTo
import BlindLedger.Financial.CursorCorrection

namespace BlindLedger.Financial.CorrectionTransition.Runtime

open BlindLedger.Financial.CorrectionTransition

def financialExitTransitionDecode : UInt8 := UInt8.ofNat 72
def financialExitTransitionEncoding : UInt8 := UInt8.ofNat 73
def financialExitReuseDecode : UInt8 := UInt8.ofNat 75
def financialExitReuseEncoding : UInt8 := UInt8.ofNat 76

private def runCorrectionRuntimeFailure (code : UInt8) (reason : String) : IO Unit := do
  IO.eprintln ("FINANCIAL_ERROR=" ++ reason)
  IO.Process.exit code

def runApplyCorrectionTransition : IO Unit := do
  let stdin ← IO.getStdin
  let bounded ← readUpTo stdin.read (maxCorrectionTransitionBytes + 1) .empty
  if bounded.size > maxCorrectionTransitionBytes then
    runCorrectionRuntimeFailure financialExitTransitionDecode "correction-transition-input-too-large"
  else
    match Cursor.decodeCorrectionTransitionRequest bounded with
    | none =>
        runCorrectionRuntimeFailure financialExitTransitionDecode "correction-transition-input-decode"
    | some request =>
        let result := applyCorrectionTransition request
        match encodeCorrectionTransitionResult result with
        | none =>
            runCorrectionRuntimeFailure financialExitTransitionEncoding
              "correction-transition-result-encoding"
        | some output =>
            let stdout ← IO.getStdout
            stdout.write output.toByteArray
            stdout.flush

def runAssessCorrectionReuse : IO Unit := do
  let stdin ← IO.getStdin
  let bounded ← readUpTo stdin.read (maxCorrectionReuseBytes + 1) .empty
  if bounded.size > maxCorrectionReuseBytes then
    runCorrectionRuntimeFailure financialExitReuseDecode "correction-reuse-input-too-large"
  else
    match decodeCorrectionReuseRequest bounded.toList with
    | none =>
        runCorrectionRuntimeFailure financialExitReuseDecode "correction-reuse-input-decode"
    | some request =>
        match encodeCorrectionReuseAssessment (assessCorrectionReuse request) with
        | none =>
            runCorrectionRuntimeFailure financialExitReuseEncoding "correction-reuse-result-encoding"
        | some output =>
            let stdout ← IO.getStdout
            stdout.write output.toByteArray
            stdout.flush

end BlindLedger.Financial.CorrectionTransition.Runtime
