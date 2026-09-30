namespace BlindLedger.Financial

/-- The first `n` bytes of a stream after `acc`: reads chunks of at most 64 KiB until `n` bytes or end of input
    (an empty read).  Callers compare the size with what they needed. -/
def readUpTo {m : Type → Type} [Monad m] (read : USize → m ByteArray) (n : Nat) (acc : ByteArray) : m ByteArray := do
  if acc.size < n then
    let chunk ← read (USize.ofNat (min (n - acc.size) 65536))
    if chunk.size = 0 then return acc
    else readUpTo read n (acc ++ chunk)
  else return acc
termination_by n - acc.size
decreasing_by simp only [ByteArray.size_append]; omega

end BlindLedger.Financial
