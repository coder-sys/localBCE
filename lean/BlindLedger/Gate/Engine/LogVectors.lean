import BlindLedger.Gate.Engine.Log

/-! ENGINE-0 S1 conformance runner for the v3 log-entry decoder.  Not a lakefile target (no TCB pin
    moves): `lake env lean --run BlindLedger/Gate/Engine/LogVectors.lean <vectors>` in `lean/`.
    Each `name hex` line prints `name ok <entryDigest3 hex>` or `name refuse` (`name malformed`
    for bad hex, which fails the run).  Compared with Python by `tests/test_engine_log_vectors.py`.
    Test-only; never a release path. -/

namespace BlindLedger.Gate.Engine.LogVectors

open BlindLedger.Gate

def nibble (c : Char) : Option Nat :=
  if '0' ≤ c && c ≤ '9' then some (c.toNat - 48)
  else if 'a' ≤ c && c ≤ 'f' then some (c.toNat - 87) else none

def unhex : List Char → Option Bytes
  | [] => some []
  | a :: b :: rest => do pure (UInt8.ofNat ((← nibble a) * 16 + (← nibble b)) :: (← unhex rest))
  | _ => none

def hexDigit (n : Nat) : Char := Char.ofNat (if n < 10 then 48 + n else 87 + n)
def toHex (b : Bytes) : String :=
  String.ofList (b.flatMap fun x => [hexDigit (x.toNat / 16), hexDigit (x.toNat % 16)])

def answer (hex : String) : Option String := do
  let bs ← unhex hex.toList
  pure (match decodeEntry3B (ByteArray.mk bs.toArray) with
    | some e => "ok " ++ toHex (entryDigest3 e)
    | none => "refuse")

end BlindLedger.Gate.Engine.LogVectors

open BlindLedger.Gate.Engine.LogVectors in
def main (args : List String) : IO UInt32 := do
  let [path] := args | do
    IO.eprintln "LOG_VECTORS=USAGE LogVectors <vectors>"
    return 2
  let mut bad := false
  for line in (← IO.FS.readFile path).splitOn "\n" do
    let fields := ((String.ofList (line.toList.filter (· ≠ '\r'))).splitOn " ").filter (· ≠ "")
    match fields with
    | [] => continue
    | "#" :: _ => continue
    | [name, hex] =>
      if let some r := answer hex then
        IO.println s!"{name} {r}"
      else
        IO.println s!"{name} malformed"
        bad := true
    | name :: _ =>
      IO.println s!"{name} malformed"
      bad := true
  return (if bad then 1 else 0)
