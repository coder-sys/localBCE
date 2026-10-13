import BlindLedger.Gate.Rules.Run
import BlindLedger.Gate.Batch

open BlindLedger.Gate

/-! `gate_engine`, the resident one-process gate (blueprint A, S4): started once per shard, it answers every frame of
    the batch loop in-process, so no batch spawns, reloads or rehashes.  A frame is a u32 BE length then its bytes; an
    answer the same.  A frame whose first byte is 0x01 is `gate_verify`'s PUBLISH frame after its mode byte, answered
    `GATE_VERIFY=ACCEPT`, `REJECT` or `FRAME` by `publishOkTreeAny`; any other frame is a rules vector text, answered by
    `Run.runFrom` (the lines `gate_rules_worker` gives).  The only state kept between frames is the sets-digest `Memo`,
    which carries its own proof (`Memo.ok`).  Decisions are the proved defs; this file only frames them. -/

namespace BlindLedger.Gate.Engine.OneProc

@[extern c inline "lean_io_result_mk_ok(lean_box_uint32((uint32_t)mi_reserve_os_memory(#1, #2, #3)))"]
opaque reserveArena (bytes : USize) (commit allowLarge : Bool) : IO UInt32

def publish : P Bool := do
  let rootPk ← take mlDsa87Key
  let cert ← take (← nat 4)
  let last ← take (← nat 4)
  let new ← take (← nat 4)
  let tokens ← many (do take (← nat 4)) (← nat 2)
  pure (publishOkTreeAny rootPk cert (if last.isEmpty then none else some last) new tokens)

/-- One frame's answer and the memo for the next. -/
def answer (memo : Option Rules.Run.Memo) (f : ByteArray) : Option (String × Option Rules.Run.Memo) :=
  if f.size > 0 && f.get! 0 == 1 then
    let b := (f.extract 1 f.size).toList
    some (match parse publish b.length b with
      | some true => "GATE_VERIFY=ACCEPT\n" | some false => "GATE_VERIFY=REJECT\n" | none => "GATE_VERIFY=FRAME\n", memo)
  else
    (String.fromUTF8? f).map fun text =>
      let (out, _, st) := Rules.Run.runFrom memo text
      (String.join (out.toList.map (· ++ "\n")), st.memo)

partial def serve (read : USize → IO ByteArray) (write : ByteArray → IO Unit) (memo : Option Rules.Run.Memo) : IO UInt32 := do
  let h ← Rules.Run.readN read 4
  if h.size = 0 then return 0
  let n := h.foldl (fun a b => a * 256 + b.toNat) 0
  if h.size < 4 || n > Rules.Run.maxFrame then return 65
  let f ← Rules.Run.readN read n
  if f.size < n then return 65
  let some (text, memo) := answer memo f | return 65
  let resp := text.toUTF8
  if resp.size > Rules.Run.maxFrame then return 65
  write (ByteArray.mk #[(resp.size >>> 24).toUInt8, (resp.size >>> 16).toUInt8, (resp.size >>> 8).toUInt8, resp.size.toUInt8] ++ resp)
  serve read write memo

def main : IO UInt32 := do
  if (← reserveArena 1073741824 false false) != 0 then
    return 70
  let stdin ← IO.getStdin
  let stdout ← IO.getStdout
  serve stdin.read (fun b => do stdout.write b; stdout.flush) none

end BlindLedger.Gate.Engine.OneProc

def main : IO UInt32 := BlindLedger.Gate.Engine.OneProc.main
