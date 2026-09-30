import BlindLedger.Financial.Worker

namespace BlindLedger.Financial.WorkerCli

open BlindLedger.Financial

/-! Long-lived evaluator worker.  Each stdin frame is a u32 length and one
    `BLFIN02` input; each stdout frame is a u32 length and the outcome from
    `workerRespond`, which cannot fail.  Clean end of input exits 0.  A broken
    or oversize frame exits 65 without output, so no error echoes input. -/

def workerExitFrame : UInt32 := 65

/-- Reads until `accumulator` holds `count` bytes; `none` if the stream ends first. -/
partial def readExact (stream : IO.FS.Stream) (count : Nat) (accumulator : ByteArray) :
    IO (Option ByteArray) := do
  if accumulator.size ≥ count then
    return some accumulator
  let chunk ← stream.read (USize.ofNat (min (count - accumulator.size) 65536))
  if chunk.isEmpty then
    return none
  readExact stream count (accumulator ++ chunk)

partial def serve (stdin stdout : IO.FS.Stream) : IO UInt32 := do
  let first ← stdin.read 4
  if first.isEmpty then
    return 0
  let some header ← readExact stdin 4 first | return workerExitFrame
  let some (length, _) := readNatBE 4 header.toList | return workerExitFrame
  if length > maxWorkerFrameBytes then
    return workerExitFrame
  let some frame ← readExact stdin length ByteArray.empty | return workerExitFrame
  let response := workerRespondBA frame
  stdout.write (natBE 4 response.length ++ response).toByteArray
  stdout.flush
  serve stdin stdout

/-- mimalloc's process-load hook.  Lean's Windows runtime links mimalloc without the initializer that
    calls it, so mimalloc stays in its start-up mode: it never reserves an arena and never reuses or
    returns a freed 32 MiB segment, and every large request grew the worker (docs/CORE_REDESIGN.md,
    Lean-live M1.5).  Idempotent. -/
@[extern c inline "({ extern void _Z16_mi_process_loadv(void); _Z16_mi_process_loadv(); lean_io_result_mk_ok(lean_box(0)); })"]
opaque mimallocProcessLoad : IO Unit

def main : IO UInt32 := do
  mimallocProcessLoad
  serve (← IO.getStdin) (← IO.getStdout)

end BlindLedger.Financial.WorkerCli

def main : IO UInt32 := BlindLedger.Financial.WorkerCli.main
