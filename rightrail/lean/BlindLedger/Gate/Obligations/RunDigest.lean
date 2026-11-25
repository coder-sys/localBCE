import BlindLedger.Gate.Obligations.Check
import BlindLedger.Gate.Engine3.Sha3Fused

namespace BlindLedger.Gate.Obligations

open BlindLedger.Gate.FactCodec

/-! The run-end digest as the program computes it, from the bytes of the log read back, and what it equals: the
    checker's model of the digest (`spanDig`). -/

/-- Record `i` of the first `n` records of `b`. -/
def recOf (b : ByteArray) (n i : Nat) : Option Bytes :=
  if i < n then some (b.extract (i * recBytes) ((i + 1) * recBytes)).toList else none

/-- What a digest starts with: the domain, the number `s` of the run's first record (5 bytes) and `prev`, the digest
    of the run-end record before it (64 zero bytes when there is none). -/
def digHdr (s : Nat) (prev : Bytes) : ByteArray := ⟨(runEndDom ++ leBytes 5 s ++ prev).toArray⟩

/-- The digest of records `s` to `i` of `b`, not counting `i`, after the run-end record whose digest is `prev`. -/
def digOf (b : ByteArray) (s : Nat) (prev : Bytes) (i : Nat) : Bytes :=
  (BlindLedger.Gate.Engine3.sha3_512Into ByteArray.empty (digHdr s prev) b (s * recBytes) ((i - s) * recBytes)).toList

/-- Record `k` of a log whose first `base` records are those of `old` and whose next `m` are those of `tail`. -/
def recAt (old tail : ByteArray) (base m k : Nat) : Option Bytes :=
  if k < base then recOf old base k else recOf tail m (k - base)

/-- `digOf` on the log of `recAt`: the run from record `s` lies in `tail`, in `old`, or in both. -/
def digAt (old tail : ByteArray) (base s : Nat) (prev : Bytes) (i : Nat) : Bytes :=
  if base ≤ s then
    (BlindLedger.Gate.Engine3.sha3_512Into ByteArray.empty (digHdr s prev) tail ((s - base) * recBytes)
      ((i - s) * recBytes)).toList
  else if i ≤ base then digOf old s prev i
  else (BlindLedger.Gate.Engine3.sha3_512Into ByteArray.empty
    (digHdr s prev ++ old.extract (s * recBytes) (base * recBytes)) tail 0 ((i - base) * recBytes)).toList

end BlindLedger.Gate.Obligations
