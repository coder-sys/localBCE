import BlindLedger.Gate.Engine3.RowsStore
import BlindLedger.Gate.Frame.Fast

/-! The pieces of a batch's reads that the rows-file engine and the checker share (conformance/ENGINE_V3.md section 12):
    a request line as its 245-byte store line (`storeLine`), the feeds indexed from the frame's rows at their wire
    widths (`feedsW`), the entry slots a batch gains (`entryB`) and the table size (`tabSize`).  Synthetic, nonpayment,
    non-PHI. -/

namespace BlindLedger.Gate.Engine3

/-- `a` computed before the call returns, so a clock read after it times it. -/
@[noinline] def evalNow {α : Type} (a : α) : IO α := pure a

end BlindLedger.Gate.Engine3

namespace BlindLedger.Gate.Engine3.ReadB

open BlindLedger.Gate BlindLedger.Gate.Rules BlindLedger.Gate.Flat BlindLedger.Gate.Flat.Rows
open Std (HashSet)

/-! ## Store lines from request lines -/

/-- `o` with the `k` bytes `b[s, s + k)` written reversed from byte `d` (a big-endian number little-endian). -/
def setRev (o : ByteArray) (b : @& ByteArray) (s d : Nat) : Nat → ByteArray
  | 0 => o
  | k + 1 => setRev (o.set! d b[s + k]!) b s (d + 1) k

/-- `o` with the number `1 ‖ b[s, s + n)` (big-endian) written little-endian from byte `d`: the bytes reversed, then
    the 1 (the zeros after it are already there). -/
@[inline] def setIdent (o : ByteArray) (b : @& ByteArray) (s n d : Nat) : ByteArray := (setRev o b s d n).set! (d + n) 1

/-- `lineW2` zero bytes. -/
def lineZero : ByteArray := ⟨Array.replicate lineW2 0⟩

/-- The store field of a payment (`payW` bytes of `idNatA payKey`), `payKey` being `identField program ‖ identField
    payment`; none when it does not fit. -/
def payField (program payment : ByteArray) : Option ByteArray :=
  let be2 (b : ByteArray) (n : Nat) : ByteArray := b.push (n / 256).toUInt8 |>.push (n % 256).toUInt8
  let pk := be2 (be2 (ByteArray.emptyWithCapacity (program.size + payment.size + 4)) program.size ++ program) payment.size
    ++ payment
  if payW < pk.size + 1 then none else some (setIdent (lineZero.extract 0 payW) pk 0 pk.size 0)

/-- Appends the store line (`putLine (Fast.lineOfBytes pay ln)`) of request line `ln`, which `decodeRows` accepted,
    in the payment whose store field is `pf`: `lineW2` zeros copied on, then each field written in place.  Appends
    nothing when a field does not fit its store width or the line's own lengths do not end at its last byte.  Total, so
    the caller's buffer is never held across the call (an `Option` result would keep it alive for the failure path and
    copy it on every line). -/
def storeLine (out ln pf : ByteArray) : ByteArray :=
  let len (p : Nat) : Nat := ln[p]!.toNat * 256 + ln[p + 1]!.toNat
  let ie := 3 + len 1
  let pe := ie + 34 + len (ie + 32)
  let re := pe + 2 + len pe
  let oe := re + 6 + len (re + 4)
  if !(ln.size == oe + 12 && pf.size == payW && ie - 3 < idW && pe - ie - 34 < provW && re - pe - 2 < provW &&
      oe - re - 6 < procW) then out
  else
    let d := out.size
    let dm := d + idW + payW + 1
    let dp := dm + 32
    let dt := dp + 2 * provW
    let o := lineZero.copySlice 0 out d lineW2
    let o := setIdent o ln 3 (ie - 3) d
    let o := pf.copySlice 0 o (d + idW) payW
    let o := o.set! (dm - 1) ln[0]!
    let o := setRev o ln ie dm 32
    let o := setIdent o ln (ie + 34) (pe - ie - 34) dp
    let o := setIdent o ln (pe + 2) (re - pe - 2) (dp + provW)
    let o := setRev o ln re dt 4
    let o := setIdent o ln (re + 6) (oe - re - 6) (dt + 4)
    setRev (setRev o ln oe (dt + 4 + procW) 4) ln (oe + 4) (dt + 8 + procW) 8

/-- The smallest power of two, at least 16, that is at least `2 * n`. -/
def tabSize (n : Nat) : Nat := Id.run do
  let mut s := 16
  while s < 2 * n do s := 2 * s
  return s

/-! ## Feeds at their wire widths -/

abbrev K4 := UInt64 × UInt64 × UInt64 × UInt64

/-- A feed of `n` rows of `stride` bytes from byte `o0` of `b` as `FeedIx` (`present` its snapshot's state 1 and pin
    checked): each key's facts are its rows in feed order (`feedsOf`), and `ok` is `usable`.  A row with no key (a
    member whose top byte is not 1, which no line has) is counted and checked but read by no line. -/
def feedW {α : Type} (present : Bool) (today maxAge asOf count : Nat) (seed : UInt64) (n stride o0 : Nat)
    (key : Nat → Option K4) (fact : Nat → α) (rowOk : Nat → Bool) : FeedIx α := Id.run do
  let none_ : FeedIx α := ⟨false, false, #[], ByteArray.mk (Array.replicate 80 0), 1, seed⟩
  if !present then return none_
  let mut good := true
  let mut ks : Array (K4 × Nat) := Array.emptyWithCapacity n
  for j in [0:n] do
    let o := o0 + stride * j
    good := good && rowOk o
    if let some k := key o then ks := ks.push (k, o)
  let ss := ks.qsort fun x y => keyLt x.1 y.1 || x.1 == y.1 && x.2 < y.2
  let mut runs := 0
  for j in [0:ss.size] do
    if j == 0 || ss[j]!.1 != ss[j - 1]!.1 then runs := runs + 1
  let (tab, mask) := runTable seed ss.size runs fun j => ss[j]!.1
  let ok := dateOk today maxAge asOf && n == count && 0 < n && good
  return ⟨true, ok, ss.map (fact ·.2), tab, mask, seed⟩

/-- The four feeds of request frame `bs` (decoded as `q`), each present as `snapF` found it (`pres`). -/
def feedsW (bs : ByteArray) (q : Frame.Req) (pres : Bool × Bool × Bool × Bool) (seed : UInt64) : FeedsX :=
  let nrows (k : Nat) : Nat := getN bs (Frame.hdrBytes + 76 + 77 * k + 9) 4
  let o0 := Frame.hdrBytes + 384
  let o1 := o0 + 37 * nrows 0
  let o2 := o1 + 25 * nrows 1
  let o3 := o2 + 29 * nrows 2
  let mem (o : Nat) : Option K4 := if bs[o + 32]! == 1 then some (memAt bs o).key else none
  let prov (o : Nat) : Option K4 := some (provAt bs o).key
  let okD (asOf : Nat) (o : Nat) : Bool := let x := ld32 bs o; validDate x && x ≤ asOf
  let okW (o : Nat) : Bool := let a := ld32 bs o; let z := ld32 bs (o + 4); validDate a && validDate z && a ≤ z
  ⟨feedW pres.1 q.today 90 q.dmf.asOf q.dmf.count seed (nrows 0) 37 o0 mem
     (fun o => (⟨getN bs o 33, ld32 bs (o + 33)⟩ : Death)) (fun o => okD q.dmf.asOf (o + 33)),
   feedW pres.2.1 q.today 90 q.pdeath.asOf q.pdeath.count seed (nrows 1) 25 o1 prov
     (fun o => (⟨getN bs o 21, ld32 bs (o + 21)⟩ : Death)) (fun o => okD q.pdeath.asOf (o + 21)),
   feedW pres.2.2.1 q.today 31 q.excl.asOf q.excl.count seed (nrows 2) 29 o2 prov
     (fun o => (⟨getN bs o 21, ld32 bs (o + 21), ld32 bs (o + 25)⟩ : Exclusion)) (fun o => okW (o + 21)),
   feedW pres.2.2.2 q.today 7 q.span.asOf q.span.count seed (nrows 3) 62 o3 mem
     (fun o => let p := provAt bs (o + 33)
       (⟨getN bs (o + 33) 21, true, p.a, p.b, p.c, ld32 bs (o + 54), ld32 bs (o + 58), true⟩ : SpanF))
     (fun o => okW (o + 54))⟩

/-! ## The batch -/

/-! ## Puts -/

/-- `b` with one posting slot appended: sort hash, flags, `seq`, count, and the store line at byte `o` of `lb`. -/
@[inline] def postSlot (b : ByteArray) (kh : UInt64) (fl : UInt8) (seq cnt : Nat) (lb : @& ByteArray) (o : Nat) : ByteArray :=
  let h := putN (putN ((put64 b kh).push fl) seq 5) cnt 5
  lb.copySlice o h h.size lineW2 false

/-- The slots of a key's entry after the batch, in one buffer of their final size: the entry read (`old`, `cnt`
    postings; empty when none) extended by the postings `seq0 + k` for each `k` in `adds`, whose line is line `rows[k]`
    of `lb`.  As `extendSlots` of `EntryA.push` over those postings: the first slot's count is set, a posting past
    `capN` goes into the tail digest (its line read back from the store line) and the others get slots after the old
    ones.  None when a store line past `capN` does not read back. -/
def entryB (old : @& ByteArray) (cnt : Nat) (kh : UInt64) (fl : UInt8) (lb : @& ByteArray) (rows : @& Array Nat)
    (seq0 : Nat) (adds : @& Array Nat) : Option ByteArray := Id.run do
  let c' := cnt + adds.size
  let t0 := if capN < cnt then 1 else 0
  let mut b := ByteArray.emptyWithCapacity (slotLen * (min c' capN + if capN < c' then 1 else 0))
  let mut from_ := 0
  if cnt == 0 then
    let some k := adds[0]? | return none
    b := postSlot b kh (fl ||| flagFirst) (seq0 + k) c' lb (lineW2 * rows[k]!)
    from_ := 1
  else b := setN (old.copySlice 0 b 0 slotLen false) 14 c' 5
  if capN < c' then
    let mut tl : ByteArray := if t0 == 1 then old.extract (slotLen + 19) (slotLen + 83) else Bin.bytesOf zeroDigest
    for j in [0:adds.size] do
      if capN ≤ cnt + j then
        let k := adds[j]!
        let some l := getLine lb (lineW2 * rows[k]!) | return none
        tl := Bin.HB (Bin.bytesOf (domain "INDEX/TAIL") ++ tl ++ Bin.bytesOf (encPosting ⟨seq0 + k, l⟩))
    b := putTailSlot b kh (fl ||| flagTail) tl.toList
  if 0 < cnt then b := old.copySlice ((1 + t0) * slotLen) b b.size (old.size - (1 + t0) * slotLen) false
  for j in [from_:adds.size] do
    if cnt + j < capN then
      let k := adds[j]!
      b := postSlot b kh fl (seq0 + k) 0 lb (lineW2 * rows[k]!)
  return some b

end BlindLedger.Gate.Engine3.ReadB
