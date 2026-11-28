import BlindLedger.Gate.Batch
import BlindLedger.Gate.Cosign.Link

/-! The PUBLISH frame as the specification reads it (`gate_verify` mode 0x01, `gate_engine` tag 0x01): a reader over
    `List UInt8` and the `publishOkTree` decision on what it read.  `PublishFast.lean` reads the same frame over a
    `ByteArray` and `PublishFastEq.lean` proves the two answers equal. -/
namespace BlindLedger.Gate

/-- `u32 length ‖ bytes`. -/
def pFramed : P Bytes := do take (← nat 4)

/-- u32‖link (the held authority link the certificate stands under) · u32‖cert · u32‖last (empty = genesis) · u32‖signed new · u16 k · (u32‖token)^k · u64 tpm (the shard's TPM counter before this checkpoint). -/
def pPublishArgs : P (Bytes × Bytes × Bytes × Bytes × List Bytes × Nat) := do
  let link ← pFramed
  let cert ← pFramed
  let last ← pFramed
  let new ← pFramed
  let tokens ← many pFramed (← nat 2)
  let tpm ← nat 8
  pure (link, cert, last, new, tokens, tpm)

def publishArgsOk : Bytes × Bytes × Bytes × Bytes × List Bytes × Nat → Bool
  | (link, cert, last, new, tokens, tpm) =>
    (Cosign.decodeLink link).any fun n =>
      publishOkTree (n.link sha3) cert (if last.isEmpty then none else some last) new tokens tpm

/-- The whole frame: none if it is malformed (no trailing bytes allowed), else `publishOkTree`'s answer. -/
def publishFrame (b : Bytes) : Option Bool := (parse pPublishArgs b.length b).map publishArgsOk

end BlindLedger.Gate
