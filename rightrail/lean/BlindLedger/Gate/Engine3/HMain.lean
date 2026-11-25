import BlindLedger.Gate.Engine3.HStore
import BlindLedger.Gate.Engine3.AdmitB
import BlindLedger.Gate.Engine3.PipeIO
import BlindLedger.Gate.Engine.OneProc

/-! `gate_hist3 DIR SHARD`: the engine over the rows-file history (`HStore`).  The same pipe: a frame is a u32 BE length
    then its bytes, the answer the same; tag 0x04 then a request frame, a decision frame (`RRDQ`) or a fact frame (`RRDF`).  Any other tag, a bad length or a short read ends
    the process (65 or 66).  Synthetic, nonpayment, non-PHI, activation=false. -/

namespace BlindLedger.Gate.Engine3.Run

open BlindLedger.Gate

/-- The open store when it has a committed batch, stands at the head the request follows (or at the request's own batch) and
    its log has the length it left and its key-set pin is the request's; else the log is opened again (which refuses a pin that
    is not the store's).  `dq` is the decision request, none for a fact frame. -/
def storeForH (dir : String) (st : Option StoreH) (shard batch : Nat) (prev pin : ByteArray) (dq : Option Frame.Req) :
    IO (Except Frame.Word StoreH) := do
  if let some s := st then
    let sz ← try pure (← System.FilePath.metadata s!"{dir}/log").byteSize.toNat catch _ => pure 0
    if 0 < s.bt && sz == s.logLen && (← s.h.get).isSome && (s.bt == batch || (s.bt + 1 == batch && s.head == prev)) &&
        s.au.extract 0 64 == pin then
      return .ok s
    closeFds s
  openStoreH dir shard batch prev pin dq

/-- A fact frame (`FactFrame.decodeReq`) on the store, by `FactFrame.retry`: the shard, then batch 1 (a fact frame never opens
    the chain) and, on an open store, a batch that is neither its last nor the next one are `NOT_NEXT` before any file is
    touched; then `handleF`. -/
def oneF (dir : String) (shard : Nat) (st : Option StoreH) (bs : ByteArray) : IO (Option StoreH × ByteArray) := do
  match FactFrame.decodeReq FactFrame.sha bs.toList with
  | .error wd => return (st, refusal bs wd)
  | .ok (q, dg) =>
    if q.shard != shard then return (st, refusal bs .SHARD)
    if q.batch ≤ 1 then return (st, refusal bs .NOT_NEXT)
    if let some s := st then
      if (← s.h.get).isSome && q.batch != s.bt && q.batch != s.bt + 1 then return (st, refusal bs .NOT_NEXT)
    match ← (try storeForH dir st shard q.batch q.prev.toByteArray q.pin.toByteArray none catch _ => pure (.error .IO)) with
    | .error wd => return (none, refusal bs wd)
    | .ok s =>
      try
        let (s, out) ← handleF s bs q dg.toByteArray
        return (some s, out)
      catch _ =>
        closeFds s
        return (none, refusal bs .IO)

def oneH (dir : String) (shard : Nat) (st : Option StoreH) (bs : ByteArray) : IO (Option StoreH × ByteArray) := do
  if isFact bs then return ← oneF dir shard st bs
  let td ← IO.monoNanosNow
  let dec ← evalNow (Frame.Fast.decodeB bs)
  let td ← tick 23 td
  -- the first batch and every `RR_E3_SPEC`-th (default 64) is also read by the list decoder, which must agree
  if ← specDue (if bs.size < 18 then 1 else getN bs 10 8) then
    let tc ← IO.monoNanosNow
    let same := Frame.Fast.sameDec dec (Frame.Fast.decodeReqFast bs)
    let _ ← tick 40 tc
    unless same do
      IO.eprintln "SPEC_MISMATCH decode"
      return (st, refusal bs .CORRUPT)
  match dec with
  | .error wd => return (st, refusal bs wd)
  | .ok (q, dg) =>
    if q.shard != shard then return (st, refusal bs .SHARD)
    match ← (try storeForH dir st q.shard q.batch q.prev.toByteArray q.auth.pin.toByteArray (some q) catch _ => pure (.error .IO)) with
    | .error wd => return (none, refusal bs wd)
    | .ok s =>
      try
        let (s, out) ← handleH s bs q dg
        let _ ← tick 24 td
        return (some s, out)
      catch _ =>
        closeFds s
        return (none, refusal bs .IO)

/-- The loop: a frame is read into `buf`, which the loop owns and reads into again every turn, and the answer is written in its
    parts (the head and root a committed batch returns are not copied into it). -/
def loopH (dir : String) (shard : Nat) : Option StoreH → ByteArray → Nat → IO UInt32
  | _, _, 0 => return 66
  | st, buf, fuel + 1 => do
    let buf ← readFull buf 4
    if buf.size = 0 then
      if let some s := st then closeH s
      return 0
    let some n := Engine.OneProc.frameLen buf | return 65
    -- the tag, then the frame, both at the start of the same buffer
    let t0 ← IO.monoNanosNow
    let buf ← readFull buf 1
    if n == 0 || buf.size < 1 || buf.get! 0 != 4 then return 65
    let buf ← readFull buf (n - 1)
    if buf.size < n - 1 then return 65
    let _ ← tick 22 t0
    let (st, resp) ← oneH dir shard st buf
    if resp.size > Rules.Run.maxFrame then return 65
    let tw ← IO.monoNanosNow
    let hd := Engine.OneProc.be32 resp.size
    let pt := st.bind (·.patch)
    let ok ← match pt with
      | none => pure ((← writeRange hd 0 4) == 0 && (← writeRange resp 0 resp.size.toUSize) == 0)
      | some (head, root) =>
        let h := headAt resp
        pure ((← writeRange hd 0 4) == 0 && (← writeRange resp 0 h.toUSize) == 0 && (← writeRange head 0 head.size.toUSize) == 0 &&
          (← writeRange root 0 root.size.toUSize) == 0 && (← writeRange resp (h + 128).toUSize (resp.size - h - 128).toUSize) == 0)
    if !ok then return 66
    let _ ← tick 25 tw
    let _ ← tick 26 t0
    let st := st.map fun s => { s with patch := none }
    if let some s := st then
      if let some hv ← s.h.get then memDiagH hv s.bt
    loopH dir shard st buf fuel

end BlindLedger.Gate.Engine3.Run

def main (args : List String) : IO UInt32 := do
  BlindLedger.Gate.Engine3.Run.allocLoad
  BlindLedger.Gate.Engine3.Run.lazyCommit
  let [dir, sh] := args | return 64
  let some shard := sh.toNat? | return 64
  let some _ ← BlindLedger.Gate.Flat.Worker.lockDir {} dir | return 67
  BlindLedger.Gate.Engine3.Run.loopH dir shard none .empty BlindLedger.Gate.Engine.OneProc.serveFuel
