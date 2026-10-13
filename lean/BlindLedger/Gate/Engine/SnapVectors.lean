import BlindLedger.Gate.Engine.Snap

/-! ENGINE-0 S2/S3b conformance runner for the ENGINE-SNAP/v2 decoder and the `pushM` fold.  Not a lakefile target (no TCB pin
    moves): `lake env lean --run BlindLedger/Gate/Engine/SnapVectors.lean <vectors>` in `lean/`.
    Each `name hex` line prints `name ok <snapDigest hex>` (the digest of the decoded state's own
    encoding, so a non-canonical accept shows as a digest mismatch) or `name refuse` (`name malformed`
    for bad hex, which fails the run).  A `name fold hex1 hex2 ...` line folds `pushM` over the entries
    from `LogStateM.init` and prints `name ok <snapDigest hex>` of the result or `name refuse`.  Compared with Python by `tests/test_engine_snap_vectors.py`.
    Test-only; never a release path. -/

namespace BlindLedger.Gate.Engine.SnapVectors

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
  pure (match decodeSnap (ByteArray.mk bs.toArray) with
    | some m => "ok " ++ toHex (snapDigest m)
    | none => "refuse")

def answerFold (hexes : List String) : Option String := do
  let es ← hexes.mapM fun h => (unhex h.toList).map fun bs => ByteArray.mk bs.toArray
  pure (match es.foldlM pushM LogStateM.init with
    | some m => "ok " ++ toHex (snapDigest m)
    | none => "refuse")

end BlindLedger.Gate.Engine.SnapVectors

open BlindLedger.Gate.Engine.SnapVectors in
def main (args : List String) : IO UInt32 := do
  let [path] := args | do
    IO.eprintln "SNAP_VECTORS=USAGE SnapVectors <vectors>"
    return 2
  let mut bad := false
  for line in (← IO.FS.readFile path).splitOn "\n" do
    match (String.ofList (line.toList.filter (· ≠ '\r'))).splitOn " " with
    | [] | [""] => continue
    | "#" :: _ => continue
    | [name, hex] =>
      if let some r := answer hex then
        IO.println s!"{name} {r}"
      else
        IO.println s!"{name} malformed"
        bad := true
    | name :: "fold" :: hexes =>
      if let some r := answerFold hexes then
        IO.println s!"{name} {r}"
      else
        IO.println s!"{name} malformed"
        bad := true
    | name :: _ =>
      IO.println s!"{name} malformed"
      bad := true
  return (if bad then 1 else 0)
