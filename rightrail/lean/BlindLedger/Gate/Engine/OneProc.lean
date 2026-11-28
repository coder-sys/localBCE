import BlindLedger.Gate.Flat.Worker
import BlindLedger.Gate.PublishSpec

open BlindLedger.Gate

/-! `gate_engine`, the resident one-process gate: started once per shard, it answers every frame in-process.  A frame is a
    u32 BE length then its bytes; an answer the same.  The first byte tags the kind: 0x01 then `gate_verify`'s PUBLISH frame
    after its mode byte, answered `GATE_VERIFY=ACCEPT`, `REJECT` or `FRAME` by `publishFrame`; 0x04 then a request frame
    (conformance/FRAME_V1.md) on the shard's store in DIR: the answer is the answer frame's bytes, and the worker keeps the
    open store across frames.  Decisions are the proved defs; this file only frames
    them.  Any other tag, like a bad length or bad UTF-8, ends the process (65). -/

namespace BlindLedger.Gate.Engine.OneProc

/-- A tag 1 frame's answer; any other tag is none. -/
def answer (f : ByteArray) : Option String :=
  if f.data[0]? == some 1 then
    some (match publishFrame (f.extract 1 f.size).toList with
      | some true => "GATE_VERIFY=ACCEPT\n" | some false => "GATE_VERIFY=REJECT\n" | none => "GATE_VERIFY=FRAME\n")
  else none

/-- A frame's u32 BE length header. -/
def be32 (n : Nat) : ByteArray := ByteArray.mk #[(n >>> 24).toUInt8, (n >>> 16).toUInt8, (n >>> 8).toUInt8, n.toUInt8]

/-- The length a header names; none if it is short or past `maxFrame` (`serve` then exits 65). -/
def frameLen (h : ByteArray) : Option Nat :=
  let n := h.foldl (fun a b => a * 256 + b.toNat) 0
  if h.size < 4 || n > Rules.Run.maxFrame then none else some n

/-- The frames `serve` reads from input `b` from offset `o`, by its own `frameLen`: none where it exits 65 before
    answering (short header, oversize length, short body); the end of input ends the list. -/
def splitFramesFrom (b : ByteArray) (o : Nat) : Option (List ByteArray) :=
  if h : o < b.size then
    match frameLen (b.extract o (o + 4)) with
    | none => none
    | some n => if b.size < o + 4 + n then none else (b.extract (o + 4) (o + 4 + n) :: ·) <$> splitFramesFrom b (o + 4 + n)
  else some []
termination_by b.size - o
decreasing_by omega

def splitFrames (b : ByteArray) : Option (List ByteArray) := splitFramesFrom b 0

/-- Fuel for `serve`: one unit per frame, and a frame takes at least its 4 header bytes from input, so 2^64 frames is more than
     any process can be fed.  Running out (or `readN` running out) exits 66 before anything is written. -/
def serveFuel : Nat := 2 ^ 64

def serve (dir : String) (shard : Nat) (read : USize → IO ByteArray) (write : ByteArray → IO Unit) (fw : Flat.Worker.FlatW) : Nat → IO UInt32
  | 0 => return 66
  | fuel + 1 => do
  let some h ← Rules.Run.readN read 4 .empty 5 | return 66
  if h.size = 0 then return 0
  let some n := frameLen h | return 65
  let some f ← Rules.Run.readN read n .empty (n + 1) | return 66
  if f.size < n then return 65
  let (fw, resp) ← if f.data[0]? == some 4 then
      Flat.Worker.handle fw dir shard (f.extract 1 f.size)
    else do
      let some text := answer f | return 65
      pure (fw, text.toUTF8)
  if resp.size > Rules.Run.maxFrame then return 65
  write (be32 resp.size ++ resp)
  serve dir shard read write fw fuel

def run (crash : IO String) (args : List String) : IO UInt32 := do
  let [dir, sh] := args | return 64
  let some shard := sh.toNat? | return 64
  let stdin ← IO.getStdin
  let stdout ← IO.getStdout
  serve dir shard stdin.read (fun b => do stdout.write b; stdout.flush) { crash := ← crash } serveFuel

end BlindLedger.Gate.Engine.OneProc
