import Admission.Model

namespace BlindLedger.Admission

def hexDigit (value : Nat) : String :=
  if value < 10 then
    ToString.toString value
  else
    match value with
    | 10 => "a"
    | 11 => "b"
    | 12 => "c"
    | 13 => "d"
    | 14 => "e"
    | 15 => "f"
    | _ => "?"

def hexByte (value : UInt8) : String :=
  hexDigit (value.toNat / 16) ++ hexDigit (value.toNat % 16)

def hexString (data : Bytes) : String :=
  data.toList.foldl (fun output value => output ++ hexByte value) ""

partial def readBounded
    (stream : IO.FS.Stream) (remaining : Nat) (accumulator : Bytes) : IO Bytes := do
  if remaining = 0 then
    pure accumulator
  else
    let chunk ← stream.read (USize.ofNat remaining)
    if chunk.isEmpty then
      pure accumulator
    else
      readBounded stream (remaining - chunk.size) (ByteArray.append accumulator chunk)

def main : IO Unit := do
  let stdin ← IO.getStdin
  let data ← readBounded stdin 1_000_001 ByteArray.empty
  let decision := match decodeInput data with
    | some input => evaluate input
    | none => malformedDecision
  let stdout ← IO.getStdout
  stdout.write ((hexString (decisionBytes decision)).toUTF8)
  stdout.write (ByteArray.mk #[UInt8.ofNat 10])

end BlindLedger.Admission

def main : IO Unit := BlindLedger.Admission.main
