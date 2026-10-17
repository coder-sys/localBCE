/-! Test-only exe, never a product path: a worker-shaped loop that panics or writes to stderr
    on request (first frame byte 1, 2 or 3), so tests/test_lean_worker_panic.py can prove the
    parent fails closed.  The product worker has no such switch. -/

partial def serve (stdin stdout : IO.FS.Stream) : IO UInt32 := do
  let header ← stdin.read 4
  if header.isEmpty then
    return 0
  let frame ← stdin.read (header.get! 3).toNat.toUSize
  let mode := frame.get! 0
  if mode == 2 then
    let stderr ← IO.getStderr
    stderr.putStr "x"
    stderr.flush
  let answer : Nat := if mode == 1 then panic! "probe panic" else 0
  stdout.write (ByteArray.mk #[0, 0, 0, 1, answer.toUInt8])
  stdout.flush
  if mode == 3 then
    let stderr ← IO.getStderr
    stderr.putStr "x"
    stderr.flush
  serve stdin stdout

def main : IO UInt32 := do
  serve (← IO.getStdin) (← IO.getStdout)
