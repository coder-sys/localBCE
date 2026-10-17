import BlindLedger.Financial.Worker

namespace BlindLedger.Financial.WorkerCli

open BlindLedger.Financial

/-! Long-lived evaluator worker.  Each stdin frame is a u32 length and one
    `BLFIN02` input; each stdout frame is a u32 length and the outcome from
    `workerRespond`, which cannot fail.  Clean end of input exits 0.  A broken
    or oversize frame exits 65 without output, so no error echoes input. -/

-- mimalloc's start-up hook is DllMain-only in a static exe: no arena, so freed 32 MiB segments were never reused.
@[extern c inline "lean_io_result_mk_ok(lean_box_uint32((uint32_t)mi_reserve_os_memory(#1, #2, #3)))"]
opaque reserveArena (bytes : USize) (commit allowLarge : Bool) : IO UInt32

/-- A 1 GiB uncommitted arena first (docs/CORE_REDESIGN.md, Lean-live M1.5); exit 70 without it. -/
def main : IO UInt32 := do
  if (← reserveArena 1073741824 false false) != 0 then
    return 70
  let stdin ← IO.getStdin
  let stdout ← IO.getStdout
  serveWorker stdin.read fun b => do stdout.write b; stdout.flush

end BlindLedger.Financial.WorkerCli

def main : IO UInt32 := BlindLedger.Financial.WorkerCli.main
