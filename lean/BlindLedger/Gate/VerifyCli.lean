import BlindLedger.Gate.Verify

open BlindLedger.Gate

/-- `gate_verify`: stdin `root_pk (2592) ‖ u32 BE cert length ‖ KEY-CERT ‖ signed checkpoint`; prints
    `GATE_VERIFY=ACCEPT` (exit 0) or `REJECT` (exit 1), exit 2 when the frame is malformed. -/
def main : IO UInt32 := do
  let input ← (← IO.getStdin).readBinToEnd
  let cert := mlDsa87Key + 4
  let n := if input.size < cert then cert else (List.range 4).foldl (fun a i => a * 256 + (input.get! (mlDsa87Key + i)).toNat) 0
  if input.size < cert || input.size < cert + n then
    IO.eprintln "GATE_VERIFY=FRAME"
    return 2
  let ok := accepts (input.extract 0 mlDsa87Key).toList (input.extract cert (cert + n)).toList
    (input.extract (cert + n) input.size).toList
  IO.println (if ok then "GATE_VERIFY=ACCEPT" else "GATE_VERIFY=REJECT")
  return (if ok then 0 else 1)
