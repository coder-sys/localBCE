import BlindLedger.Financial.Worker

namespace BlindLedger.Financial.WorkerCli

open BlindLedger.Financial

/-! Long-lived evaluator worker.  Each stdin frame is a u32 length and one
    `BLFIN02` input; each stdout frame is a u32 length and the outcome from
    `workerRespond`, which cannot fail.  Clean end of input exits 0.  A broken
    or oversize frame exits 65 without output, so no error echoes input. -/

def main : IO UInt32 := do
  let stdin ← IO.getStdin
  let stdout ← IO.getStdout
  serveWorker stdin.read fun b => do stdout.write b; stdout.flush

end BlindLedger.Financial.WorkerCli

def main : IO UInt32 := BlindLedger.Financial.WorkerCli.main
