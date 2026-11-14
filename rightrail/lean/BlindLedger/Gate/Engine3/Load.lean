import BlindLedger.Gate.Engine3.Frame3

/-! The log of an engine v3 store read by frame header and trailer only (`scanLog`, `readTrailer`), so the work follows the number
    of batches, not the rows (conformance/ENGINE_V3.md section 6). -/

namespace BlindLedger.Gate.Engine3

open BlindLedger.Gate.Rules BlindLedger.Gate.Flat BlindLedger.Semantic
open Std (HashMap)

/-- What a load needs of a frame without keeping its trailer. -/
structure FrameInfo where
  ref : FrameRef
  batches : Nat
  sealEv : Option Nat
  installEv : Option (Nat × ByteArray)
  reclaimEv : Option Nat
  deriving Inhabited

/-- Every whole frame of the log by header and trailer, in order; the offset of the first torn byte; the open log.  Bytes that
    are not a whole frame (a header or trailer that does not decode, or a frame the file ends inside) are a torn tail, as
    `ChunkIo.readFrameAt` reads them: the count against the signed head decides whether a sealed frame is missing. -/
def scanLog (path : String) : IO (Except String (Array FrameInfo × Nat × UInt32)) := do
  let size := (← System.FilePath.metadata path).byteSize.toNat
  let fd ← Io.pgOpen path
  if fd == 0xFFFFFFFF then return .error "LOG"
  let mut fs : Array FrameInfo := #[]
  let mut pos := 0
  for _ in [0:size + 1] do
    if pos + 16 > size then break
    match parseHdr (← Io.pgRead fd pos.toUInt64 16) pos with
    | none => break
    | some f =>
      if pos + f.len > size then break
      let tr ← Io.pgRead fd (pos + 16 + f.rq + f.an).toUInt64 f.tr.toUSize
      match Trailer.decode tr with
      | none => break
      | some t =>
        if t.batches != fs.size + 1 then let _ ← Io.pgClose fd; return .error "LOG"
        fs := fs.push ⟨f, t.batches, t.sealEv, t.installEv, t.reclaimEv⟩
        pos := pos + f.len
  return .ok (fs, pos, fd)

def readTrailer (log : UInt32) (f : FrameInfo) : IO (Option Trailer) := do
  pure (Trailer.decode (← Io.pgRead log (f.ref.off + 16 + f.ref.rq + f.ref.an).toUInt64 f.ref.tr.toUSize))

end BlindLedger.Gate.Engine3
