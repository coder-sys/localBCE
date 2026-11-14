import BlindLedger.Gate.Engine3.Step

/-! `leaf_check`: the model run's comparison of an answer with the spec's leaves (`Step.leavesMatch`) catches a leaf the
engine built wrongly.  Test only. -/

open BlindLedger.Gate BlindLedger.Gate.Engine3 BlindLedger.Gate.Engine3.Run BlindLedger.Gate.Flat.Worker

def z64 : ByteArray := ByteArray.mk (Array.replicate 64 0)

def answer (ls : List Frame.Leaf) : ByteArray :=
  Frame.Fast.encodeAnsFast ⟨.OK, 0, 1, z64, [], z64, z64, ⟨ByteArray.mk (Array.replicate 16 0), z64, ByteArray.mk (Array.replicate 208 0), [], ls, []⟩⟩

def main : IO UInt32 := do
  let bad ← IO.mkRef (0 : Nat)
  let chk (name : String) (b : Bool) : IO Unit := do
    if !b then bad.modify (· + 1); IO.println s!"FAIL {name}"
  let rq := ByteArray.mk (Array.replicate 64 7)
  -- the spec: payment 0 goes to human review, no reason, observe level, no bypass
  let pay : Rules.Run.Pay := ⟨0, .HUMAN_REVIEW, "-", .OBSERVE, [], zeroDigest⟩
  let leaf : Frame.Leaf := leafOf pay rq
  chk "right leaf" (leavesMatch [pay] (answer [leaf]))
  -- a wrong flag: the engine's leaf releases the payment
  chk "wrong outcome" (!leavesMatch [pay] (answer [{ leaf with outcome := Frame.outCode .ALLOW }]))
  chk "wrong reason bit" (!leavesMatch [pay] (answer [{ leaf with reasons := 1 }]))
  chk "wrong authority" (!leavesMatch [pay] (answer [{ leaf with authority := 1 }]))
  chk "invented bypass" (!leavesMatch [pay] (answer [{ leaf with bypass := ByteArray.mk (Array.replicate 64 9) }]))
  chk "one leaf too few" (!leavesMatch [pay, pay] (answer [leaf]))
  chk "one leaf too many" (!leavesMatch [pay] (answer [leaf, leaf]))
  chk "not an answer" (!leavesMatch [pay] (ByteArray.mk #[1, 2, 3]))
  let n ← bad.get
  IO.println s!"8 checks, {n} failures"
  return if n == 0 then 0 else 1
