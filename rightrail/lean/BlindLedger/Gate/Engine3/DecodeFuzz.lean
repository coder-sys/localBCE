import BlindLedger.Gate.Engine3.DecodeB

/-! `decode_fuzz FILE`: FILE is frames, each a u32 BE length then its bytes.  Every frame goes to the byte decoder and to the
    list decoder; they must agree (`sameDec`: the same refusal word, or the same request).  Prints the counts; exit 1 on any
    difference.  Synthetic, nonpayment, non-PHI, activation=false. -/

open BlindLedger.Gate

def main (args : List String) : IO UInt32 := do
  let some path := args.head? | IO.eprintln "usage: decode_fuzz FILE"; return 2
  let raw ← IO.FS.readBinFile path
  let mut pos := 0
  let mut n := 0
  let mut acc := 0
  let mut bad := 0
  while pos + 4 ≤ raw.size do
    let len := ((raw.get! pos).toNat <<< 24) + ((raw.get! (pos + 1)).toNat <<< 16) + ((raw.get! (pos + 2)).toNat <<< 8) + (raw.get! (pos + 3)).toNat
    if raw.size < pos + 4 + len then break
    let bs := raw.extract (pos + 4) (pos + 4 + len)
    pos := pos + 4 + len
    n := n + 1
    let a := Frame.Fast.decodeB bs
    if !Frame.Fast.sameDec a (Frame.Fast.decodeReqFast bs) then
      bad := bad + 1
      IO.eprintln s!"FUZZ_MISMATCH frame {n - 1}"
    if let .ok _ := a then acc := acc + 1
  IO.println s!"FUZZ frames={n} accepted={acc} refused={n - acc} mismatches={bad}"
  return if bad == 0 && n > 0 then 0 else 1
