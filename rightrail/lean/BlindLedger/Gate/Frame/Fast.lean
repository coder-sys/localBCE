import BlindLedger.Gate.Frame.Spec
import BlindLedger.Gate.Flat.Bin

/-! The request decoder and the answer encoder over `ByteArray`: what the engine runs (formats conformance/FRAME_V1.md).
    `Frame.Spec` states the same functions over byte lists; the `_eq` theorems say they agree (`encodeAnsFast_eq` is proved in `Frame.Answer`). -/

namespace BlindLedger.Gate.Frame.Fast

open BlindLedger.Gate.Rules BlindLedger.Gate.Flat

/-- A reader over the request: the bytes, a position, and the word of the first failure. -/
abbrev P (α : Type) := ReaderT ByteArray (StateT Nat (Except Word)) α

/-- The `w`-byte little-endian number at the position. -/
def num (w : Nat) : P Nat := do
  let bs ← read
  let p ← get
  if p + w ≤ bs.size then
    set (p + w)
    let mut v := 0
    for i in [0:w] do v := v * 256 + (bs.get! (p + w - 1 - i)).toNat
    pure v
  else throw .LENGTH

def cutA (n : Nat) : P ByteArray := do
  let bs ← read
  let p ← get
  if p + n ≤ bs.size then
    set (p + n)
    pure (bs.extract p (p + n))
  else throw .LENGTH

def cutB (n : Nat) : P Bytes := do pure (← cutA n).toList

def blobP : P Bytes := do cutB (← num 4)

def descP : P (Nat × Nat × Nat × Nat × Bytes) := do
  let st ← num 1
  let a ← num 4
  let c ← num 4
  let n ← num 4
  let pin ← cutB 64
  unless st ≤ 2 && (st == 1 || (a == 0 && c == 0 && n == 0 && pin == zeroDigest)) do throw .RECORD
  pure (st, a, c, n, pin)

def rowP {α : Type} (c : RowCodec α) : P α := do
  let ns ← c.widths.mapM num
  let some x := c.ofNums ns | throw .RECORD
  pure x

def feedP {α : Type} (c : RowCodec α) (d : Nat × Nat × Nat × Nat × Bytes) : P (Feed α) := do
  let (st, a, n, k, pin) := d
  let mut rows : Array α := #[]
  for _ in [0:k] do rows := rows.push (← rowP c)
  pure ⟨st, a, n, rows.toList, pin⟩

/-! ### The payment request over bytes -/

@[simp] theorem toModel_ofModel (r : Gate.Request) : (RequestBA.ofModel r).toModel = r := by
  cases r
  simp [RequestBA.toModel, RequestBA.ofModel, Bin.toList_toByteArray, Function.comp_def]

/-! A payment request is read in one pass over its bytes into the fixed-width fields of a line (`LineRow`, the fields of the
    decider's `Row`), with no list or string; its signed bytes stay one byte array. -/

/-- A line at store widths: the line id and member as their low 32 bytes (high word first; the leading 0x01 of the
    number is implicit), the other numbers as machine words. -/
structure LineRow where
  i0 : UInt64
  i1 : UInt64
  i2 : UInt64
  i3 : UInt64
  pay : UInt64
  m0 : UInt64
  m1 : UInt64
  m2 : UInt64
  m3 : UInt64
  payee : UInt64
  rend : UInt64
  proc : UInt64
  cents : UInt64
  date : UInt32
  units : UInt32
  flow : UInt8
  deriving BEq

/-- Word `k` (low word first) of `n`. -/
def word (n k : Nat) : UInt64 := (n >>> (64 * k)).toUInt64

/-- The row of a rules line: each number cut to its width. -/
def LineRow.of (l : Line) : LineRow :=
  ⟨word l.id 3, word l.id 2, word l.id 1, word l.id 0, l.pay.toUInt64, word l.member 3, word l.member 2,
   word l.member 1, word l.member 0, l.payee.toUInt64, l.rendering.toUInt64, l.proc.toUInt64, l.cents.toUInt64,
   l.date.toUInt32, l.units.toUInt32, l.flow.tag.toUInt8⟩

/-- The flow of a request tag 1 to 3. -/
def flowOfTag (t : UInt8) : Flow := if t == 1 then .FFS_CYCLE else if t == 2 then .FFS_CLAIM else .CAP_820

/-- 1 for a letter or digit, 2 for `.` `_` `:` `-`, else 0 (`Gate.identOk`: the first byte is a 1, the rest not 0). -/
def identTab : ByteArray :=
  ⟨(Array.range 256).map fun i =>
    let c := i.toUInt8
    if alnum c then 1 else if c == 46 || c == 95 || c == 58 || c == 45 then 2 else 0⟩

/-- Every byte of `b[i, e)` is an identifier byte after the first. -/
def identRest (b : ByteArray) (i e : Nat) : Bool :=
  if i < e then identTab.get! (b.get! i).toNat != 0 && identRest b (i + 1) e else true
termination_by e - i

/-- The end of the identifier at `p` (two-byte length, then `Gate.identOk` bytes) if it ends by `lim`; 0 if there is none. -/
def identEnd (b : ByteArray) (p lim : Nat) : Nat :=
  if lim < p + 3 || b.size < lim then 0 else
  let n := (b.get! p).toNat * 256 + (b.get! (p + 1)).toNat
  let s := p + 2
  if n == 0 || 128 < n || lim < s + n || identTab.get! (b.get! s).toNat != 1 || !identRest b (s + 1) (s + n) then 0
  else s + n

/-- The 8, 4 or 2 bytes at `p`, big-endian. -/
def be8 (b : ByteArray) (p : Nat) : UInt64 :=
  (b.get! p).toUInt64 <<< 56 ||| (b.get! (p + 1)).toUInt64 <<< 48 ||| (b.get! (p + 2)).toUInt64 <<< 40 |||
  (b.get! (p + 3)).toUInt64 <<< 32 ||| (b.get! (p + 4)).toUInt64 <<< 24 ||| (b.get! (p + 5)).toUInt64 <<< 16 |||
  (b.get! (p + 6)).toUInt64 <<< 8 ||| (b.get! (p + 7)).toUInt64

def be4 (b : ByteArray) (p : Nat) : UInt64 :=
  (b.get! p).toUInt64 <<< 24 ||| (b.get! (p + 1)).toUInt64 <<< 16 ||| (b.get! (p + 2)).toUInt64 <<< 8 ||| (b.get! (p + 3)).toUInt64

def be2 (b : ByteArray) (p : Nat) : UInt64 := (b.get! p).toUInt64 <<< 8 ||| (b.get! (p + 1)).toUInt64

/-- `v` with bytes `t` to `n - 1` of the number ending at `e` added, from byte `k0`. -/
def lowBytes (b : ByteArray) (e n k0 t : Nat) (v : UInt64) : UInt64 :=
  if t < n then lowBytes b e n k0 (t + 1) (v ||| ((b.get! (e - 1 - t)).toUInt64 <<< (8 * (t - k0)).toUInt64)) else v
termination_by n - t

/-- Word `k` (low word first) of the number `1 ‖ b[s, s + n)`, big-endian. -/
def wordOf (b : ByteArray) (s n k : Nat) : UInt64 :=
  if 8 * k + 8 ≤ n then be8 b (s + n - 8 * k - 8)
  else if n < 8 * k then 0
  else lowBytes b (s + n) n (8 * k) (8 * k) (1 <<< (8 * (n - 8 * k)).toUInt64)

/-- The `n` bytes of `a` at `p` and of `b` at `q` are equal. -/
def sameBytes (a b : ByteArray) (p q n : Nat) : Bool :=
  if 8 ≤ n then be8 a p == be8 b q && sameBytes a b (p + 8) (q + 8) (n - 8)
  else if 0 < n then a.get! p == b.get! q && sameBytes a b (p + 1) (q + 1) (n - 1)
  else true
termination_by n

/-- The line in `b[p, e)`, if it is canonical and carries the request's flow tag, member (at `mem`) and payee (the
    identifier in `b[ps, ps + pn)`); `payW` is the low word of the payment number. -/
def lineRow (b : ByteArray) (p e : Nat) (flow : UInt8) (mem ps pn : Nat) (payW : UInt64) : Option LineRow := Id.run do
  if e < p + 1 || b.get! p != flow then return none
  let ie := identEnd b (p + 1) e
  if ie == 0 || e < ie + 32 || !sameBytes b b ie mem 32 then return none
  let pe := identEnd b (ie + 32) e
  if pe == 0 || pe - (ie + 34) != pn || !sameBytes b b (ie + 34) ps pn then return none
  let re := identEnd b pe e
  if re == 0 || e < re + 4 then return none
  let oe := identEnd b (re + 4) e
  if oe == 0 || oe + 12 != e then return none
  let cents := be8 b (oe + 4)
  if 9223372036854775807 < cents then return none
  let (is, rs, os) := (p + 3, pe + 2, re + 6)
  let (idn, rn, pn2) := (ie - is, re - rs, oe - os)
  return some ⟨wordOf b is idn 3, wordOf b is idn 2, wordOf b is idn 1, wordOf b is idn 0, payW,
    wordOf b mem 32 3, wordOf b mem 32 2, wordOf b mem 32 1, wordOf b mem 32 0, wordOf b ps pn 0, wordOf b rs rn 0,
    wordOf b os pn2 0, cents, (be4 b re).toUInt32, (be4 b oe).toUInt32, flow⟩

/-- The 64 bytes at `p` in `b` are less than those at `q`, read as big-endian words from word `w`. -/
def lt64 (b : ByteArray) (p q w : Nat) : Bool :=
  if h : w < 8 then
    let a := be8 b (p + 8 * w)
    let c := be8 b (q + 8 * w)
    if a == c then lt64 b p q (w + 1) else decide (a < c)
  else false
termination_by 8 - w

/-- A request read in one pass: the request, the bytes `identField program ‖ identField payment` (the payment number
    is `idNatA` of them) and, for a ruled flow, its lines as rows. -/
structure RowsReq where
  ra : RequestBA
  payKey : ByteArray
  rows : Array LineRow

def requestDomain : ByteArray := (domain "DECIDE-REQUEST").toByteArray

/-- `Gate.decodeRequest`, in one pass.  It fails exactly where the byte-list reader fails. -/
def decodeRows (x : ByteArray) : Option RowsReq := Id.run do
  let n := x.size
  let dn := requestDomain.size
  if maxRequestBytes < n || n < dn || !sameBytes x requestDomain 0 0 dn then return none
  let te := identEnd x dn n
  let ge := identEnd x te n
  if te == 0 || ge == 0 || n < ge + 1 then return none
  let tag := x.get! ge
  if tag == 0 || 5 < tag then return none
  let ce := identEnd x (ge + 1) n
  let ye := identEnd x ce n
  if ce == 0 || ye == 0 || n < ye + 32 then return none
  let ee := identEnd x (ye + 32) n
  if ee == 0 || n < ee + 8 then return none
  let amount := be8 x ee
  if 9223372036854775807 < amount then return none
  let ke := identEnd x (ee + 8) n
  if ke == 0 || n < ke + 2 then return none
  let nl := (be2 x ke).toNat
  let payKey := x.copySlice ce (x.extract te ge) (ge - te) (ye - ce)
  let payW := wordOf payKey 0 payKey.size 0
  let ruled := tag ≤ 3
  let mut q := ke + 2
  let mut sum := 0
  let mut lines : Array ByteArray := Array.mkEmpty nl
  let mut rows : Array LineRow := Array.mkEmpty (if ruled then nl else 0)
  for _ in [0:nl] do
    if n < q + 2 then return none
    let ln := (be2 x q).toNat
    if ln == 0 || 569 < ln || n < q + 2 + ln then return none
    let some r := lineRow x (q + 2) (q + 2 + ln) tag ye (ye + 34) (ee - ye - 34) payW | return none
    sum := sum + r.cents.toNat
    lines := lines.push (x.extract (q + 2) (q + 2 + ln))
    if ruled then rows := rows.push r
    q := q + 2 + ln
  if (ruled && nl == 0) || (nl != 0 && sum != amount.toNat) || n < q + 2 then return none
  let ec := (be2 x q).toNat
  if 256 < ec || n < q + 2 + 64 * ec then return none
  q := q + 2
  let mut evid : Array ByteArray := Array.mkEmpty ec
  for i in [0:ec] do
    if 0 < i && !lt64 x (q - 64) q 0 then return none
    evid := evid.push (x.extract q (q + 64))
    q := q + 64
  if q != n then return none
  return some ⟨⟨x.extract (dn + 2) te, x.extract (te + 2) ge, flows.getD (tag.toNat - 1) .FFS_CYCLE, x.extract (ge + 3) ce,
    x.extract (ce + 2) ye, x.extract ye (ye + 32), x.extract (ye + 34) ee, amount.toNat, x.extract (ee + 10) ke, lines.toList,
    evid.toList⟩, payKey, rows⟩

/-- `beNat` of bytes `i` to `j` after `acc`, seven bytes per big-number step. -/
def beNatA (b : ByteArray) (i j acc : Nat) : Nat := Id.run do
  let mut acc := acc
  let k := (j - i) / 7
  for g in [0:k] do
    let mut c : UInt64 := 0
    for t in [i + 7 * g:i + 7 * g + 7] do c := (c <<< 8) ||| (b.get! t).toUInt64
    acc := acc * 72057594037927936 + c.toNat
  for t in [i + 7 * k:j] do acc := acc * 256 + (b.get! t).toNat
  pure acc

/-- `idNat` over bytes. -/
def idNatA (b : ByteArray) : Nat := beNatA b 0 b.size 1

/-- The rules' line of a line `decodeRows` accepted (its own bytes `ln`) in the payment numbered `pay`: what the decider
    reads until it takes rows.  A ruled flow only. -/
def lineOfBytes (pay : Nat) (ln : ByteArray) : Line :=
  let ie := identEnd ln 1 ln.size
  let pe := identEnd ln (ie + 32) ln.size
  let re := identEnd ln pe ln.size
  let oe := identEnd ln (re + 4) ln.size
  ⟨beNatA ln 3 ie 1, pay, flowOfTag (ln.get! 0), beNatA ln ie (ie + 32) 1, beNatA ln (ie + 34) pe 1, beNatA ln (pe + 2) re 1,
    (be4 ln re).toNat, beNatA ln (re + 6) oe 1, (be4 ln oe).toNat, (be8 ln (oe + 4)).toNat⟩

/-! The byte reader's identifier and number steps against the spec reader's (`Gate.ident`, `take`, `nat`) on the bytes
    `b[0, lim)` read from `p`: the spec reader's state is the list `(b.toList.take lim).drop p`. -/

theorem get!_getD (b : ByteArray) (i : Nat) : b.get! i = b.toList.getD i 0 := by
  rcases b with ⟨d⟩
  simp only [ByteArray.get!, Bin.toList_eq', List.getD_eq_getElem?_getD, Array.getElem?_toList]
  by_cases h : i < d.size
  · simp [h, getElem!_pos]
  · simp [h, getElem!_neg]; rfl

theorem get!_lt (b : ByteArray) (i : Nat) (h : i < b.toList.length) : b.get! i = b.toList[i] := by
  rw [get!_getD, List.getD_eq_getElem?_getD, List.getElem?_eq_getElem h]; rfl

theorem identTab_nat : ∀ n, n < 256 → identTab.get! n =
    if alnum n.toUInt8 then 1 else if n.toUInt8 == 46 || n.toUInt8 == 95 || n.toUInt8 == 58 || n.toUInt8 == 45 then 2 else 0 := by
  decide +kernel

theorem identTab_get (c : UInt8) : identTab.get! c.toNat =
    if alnum c then 1 else if c == 46 || c == 95 || c == 58 || c == 45 then 2 else 0 := by
  have := identTab_nat c.toNat c.toNat_lt
  simpa using this

theorem identRest_eq (b : ByteArray) (i e : Nat) (he : e ≤ b.size) :
    identRest b i e = ((b.toList.drop i).take (e - i)).all
      (fun x => alnum x || x == 46 || x == 95 || x == 58 || x == 45) := by
  induction h : e - i generalizing i with
  | zero =>
    unfold identRest; simp; omega
  | succ k ih =>
    unfold identRest
    have hi : i < e := by omega
    have hl : i < b.toList.length := by rw [← Bin.size_eq_length']; omega
    rw [if_pos hi, ih (i + 1) (by omega), List.drop_eq_getElem_cons hl, identTab_get, get!_getD]
    simp only [List.getD_eq_getElem?_getD, List.getElem?_eq_getElem hl, Option.getD_some, List.take_succ_cons,
      List.all_cons]
    by_cases h1 : alnum b.toList[i] <;> by_cases h2 : (b.toList[i] == 46 || b.toList[i] == 95 || b.toList[i] == 58 || b.toList[i] == 45) <;>
      simp_all

theorem take_run' (n : Nat) (b : Bytes) : (take n).run b = if n ≤ b.length then some (b.take n, b.drop n) else none := rfl
theorem need_run' (ok : Bool) (b : Bytes) : (need ok).run b = if ok then some ((), b) else none := rfl

theorem ident_cons (s : Bytes) : Gate.ident.run s = match s with
    | a :: c :: r =>
      if 1 ≤ a.toNat * 256 + c.toNat ∧ a.toNat * 256 + c.toNat ≤ r.length ∧ identOk (r.take (a.toNat * 256 + c.toNat)) = true
      then some (r.take (a.toNat * 256 + c.toNat), r.drop (a.toNat * 256 + c.toNat)) else none
    | _ => none := by
  rcases s with _ | ⟨a, _ | ⟨c, r⟩⟩
  · rfl
  · rfl
  · have hb : a.toNat * 256 + c.toNat ≤ 65535 := by have := a.toNat_lt; have := c.toNat_lt; omega
    simp only [Gate.ident, Gate.blob, nat, StateT.run_bind, take_run', need_run', StateT.run_pure, List.length_cons]
    simp [beNat, hb]
    by_cases h1 : 1 ≤ a.toNat * 256 + c.toNat <;> by_cases h2 : a.toNat * 256 + c.toNat ≤ r.length <;>
      by_cases h3 : identOk (r.take (a.toNat * 256 + c.toNat)) = true <;> simp [h1, h2, h3]

theorem ident_len {s v r : Bytes} (h : Gate.ident.run s = some (v, r)) : 3 ≤ s.length := by
  rw [ident_cons] at h
  rcases s with _ | ⟨a, _ | ⟨c, r⟩⟩
  · simp at h
  · simp at h
  · simp only at h
    split at h
    · simp; omega
    · simp at h

/-- The identifier at `p` in `b[0, lim)` as the spec reader takes it: `identEnd` is where it ends. -/
theorem ident_run (b : ByteArray) (p lim : Nat) (hl : lim ≤ b.size) :
    Gate.ident.run ((b.toList.take lim).drop p) =
      if identEnd b p lim = 0 then none
      else some ((b.toList.drop (p + 2)).take (identEnd b p lim - (p + 2)), (b.toList.take lim).drop (identEnd b p lim)) := by
  have hL : b.toList.length = b.size := (Bin.size_eq_length' b).symm
  have hL' : lim ≤ b.toList.length := by omega
  by_cases h3 : lim < p + 3
  · have e0 : identEnd b p lim = 0 := by unfold identEnd; simp [h3]
    rw [e0]; simp only [if_true]
    cases h : Gate.ident.run ((b.toList.take lim).drop p) with
    | none => rfl
    | some vr =>
      have := ident_len (v := vr.1) (r := vr.2) h
      simp at this; omega
  · have hp0 : p < (b.toList.take lim).length := by simp; omega
    have hp1 : p + 1 < (b.toList.take lim).length := by simp; omega
    have hs : (b.toList.take lim).drop p = b.toList[p] :: b.toList[p + 1] :: (b.toList.take lim).drop (p + 2) := by
      rw [List.drop_eq_getElem_cons hp0, List.drop_eq_getElem_cons hp1]
      simp
    rw [hs, ident_cons]
    simp only
    have g0 := get!_lt b p (by omega)
    have g1 := get!_lt b (p + 1) (by omega)
    generalize hn : b.toList[p].toNat * 256 + b.toList[p + 1].toNat = n
    have hlen : ((b.toList.take lim).drop (p + 2)).length = lim - (p + 2) := by simp; omega
    unfold identEnd
    rw [g0, g1, hn]
    simp only [show ¬ (lim < p + 3) from h3, show ¬ (b.size < lim) by omega, decide_false, Bool.false_or, hlen,
      Bool.false_eq_true, if_false]
    by_cases hn0 : n = 0
    · simp [hn0]
    by_cases hnl : lim < p + 2 + n
    · simp [hnl]; omega
    have hp2 : p + 2 < b.toList.length := by omega
    have hv : (b.toList.drop (p + 2)).take n = b.toList[p + 2] :: (b.toList.drop (p + 3)).take (n - 1) := by
      rw [List.drop_eq_getElem_cons hp2, show n = (n - 1) + 1 by omega, List.take_succ_cons]
      simp
    have hk : ((b.toList.take lim).drop (p + 2)).take n = b.toList[p + 2] :: (b.toList.drop (p + 3)).take (n - 1) := by
      rw [List.drop_take, List.take_take, show min n (lim - (p + 2)) = n by omega, hv]
    have g2 := get!_lt b (p + 2) hp2
    rw [hk, g2, identTab_get, identRest_eq b _ _ (by omega)]
    simp only [identOk, List.length_take, List.length_drop, List.drop_drop]
    have e1 : p + 2 + n - (p + 2 + 1) = n - 1 := by omega
    have e2 : p + 2 + 1 = p + 3 := by omega
    have e3 : p + 2 + n - (p + 2) = n := by omega
    rw [e1, e2]
    by_cases h128 : 128 < n
    · have : ¬ (min (n - 1) (b.toList.length - (p + 3)) ≤ 127) := by omega
      simp [h128, this]
    have h127 : min (n - 1) (b.toList.length - (p + 3)) ≤ 127 := by omega
    have hnl' : n ≤ lim - (p + 2) := by omega
    have hn1 : 1 ≤ n := by omega
    by_cases ha : alnum b.toList[p + 2] = true
    · by_cases hall : ((b.toList.drop (p + 3)).take (n - 1)).all
          (fun x => alnum x || x == 46 || x == 95 || x == 58 || x == 45) = true
      · simp [h128, ha, hall, hn0, hnl, h127, hnl', hn1, e3, hv]
      · simp [h128, ha, hall, hnl, h127, hnl', hn1]
    · simp [h128, ha, hnl, h127, hnl', hn1]; split <;> simp

theorem take_pos (b : ByteArray) (lim p k : Nat) (hl : lim ≤ b.size) (hp : p ≤ lim) :
    (take k).run ((b.toList.take lim).drop p) =
      if p + k ≤ lim then some ((b.toList.drop p).take k, (b.toList.take lim).drop (p + k)) else none := by
  have hL : b.toList.length = b.size := (Bin.size_eq_length' b).symm
  rw [take_run']
  simp only [List.length_drop, List.length_take, List.drop_drop]
  by_cases h : p + k ≤ lim
  · rw [if_pos (by omega), if_pos h, List.drop_take, List.take_take, show min k (lim - p) = k by omega]
  · rw [if_neg (by omega), if_neg h]

theorem nat_pos (b : ByteArray) (lim p k lo hi : Nat) (hl : lim ≤ b.size) (hp : p ≤ lim) :
    (nat k lo hi).run ((b.toList.take lim).drop p) =
      if p + k ≤ lim ∧ lo ≤ beNat ((b.toList.drop p).take k) ∧ beNat ((b.toList.drop p).take k) ≤ hi
      then some (beNat ((b.toList.drop p).take k), (b.toList.take lim).drop (p + k)) else none := by
  simp only [nat, StateT.run_bind, take_pos b lim p k hl hp]
  by_cases h : p + k ≤ lim
  · simp only [h, if_true, true_and, Option.bind_eq_bind, Option.bind_some, need_run']
    by_cases h2 : lo ≤ beNat ((b.toList.drop p).take k) ∧ beNat ((b.toList.drop p).take k) ≤ hi
    · simp [h2]
    · simp only [Bool.and_eq_true, decide_eq_true_eq, h2, if_false]; rfl
  · simp [h]

theorem obind_some {α β : Type} {x : Option α} {f : α → Option β} {y : β} (h : (x >>= f) = some y) :
    ∃ a, x = some a ∧ f a = some y := by
  cases x with
  | none => cases h
  | some a => exact ⟨a, rfl, h⟩

theorem beNat_foldl (xs : Bytes) : ∀ acc, xs.foldl (fun acc x => acc * 256 + x.toNat) acc = acc * 256 ^ xs.length + beNat xs := by
  induction xs with
  | nil => intro acc; simp [beNat]
  | cons a xs ih =>
    intro acc
    simp only [List.foldl_cons, beNat] at *
    rw [ih, ih (0 * 256 + a.toNat), List.length_cons, Nat.pow_succ]
    simp [Nat.add_mul, Nat.mul_assoc, Nat.add_assoc]
    rw [Nat.mul_comm 256 (256 ^ xs.length)]

theorem beNat_cons (a : UInt8) (xs : Bytes) : beNat (a :: xs) = a.toNat * 256 ^ xs.length + beNat xs := by
  have := beNat_foldl xs (0 * 256 + a.toNat)
  simp only [beNat, List.foldl_cons] at *
  rw [this]; simp

/-- A number `idNat` makes is below `256 ^ w` exactly when its bytes are fewer than `w`. -/
theorem idNat_lt (xs : Bytes) (w : Nat) : idNat xs < 256 ^ w ↔ xs.length < w := by
  unfold idNat
  rw [beNat_cons]
  have h1 := Keyset.beNat_lt_pow xs.length xs rfl
  simp only [show (1 : UInt8).toNat = 1 from rfl, Nat.one_mul]
  constructor
  · intro h
    rcases Nat.lt_or_ge xs.length w with h' | h'
    · exact h'
    · have : 256 ^ w ≤ 256 ^ xs.length := Nat.pow_le_pow_right (by omega) h'
      omega
  · intro h
    have : 256 ^ (xs.length + 1) ≤ 256 ^ w := Nat.pow_le_pow_right (by omega) h
    rw [Nat.pow_succ] at this
    omega

theorem identEnd_bounds {b : ByteArray} {p lim : Nat} (h : identEnd b p lim ≠ 0) :
    p + 3 ≤ identEnd b p lim ∧ identEnd b p lim ≤ lim := by
  unfold identEnd at *
  split at h
  · exact absurd rfl h
  · rename_i h1
    rw [if_neg h1]
    simp only at h ⊢
    split at h
    · exact absurd rfl h
    · rename_i h2
      rw [if_neg h2]
      simp only [Bool.or_eq_true, decide_eq_true_eq, beq_iff_eq, not_or] at h1 h2
      omega

theorem ident_step {b : ByteArray} {p lim : Nat} {v m : Bytes} (hl : lim ≤ b.size)
    (h : Gate.ident.run ((b.toList.take lim).drop p) = some (v, m)) :
    identEnd b p lim ≠ 0 ∧ v = (b.toList.drop (p + 2)).take (identEnd b p lim - (p + 2)) ∧
      m = (b.toList.take lim).drop (identEnd b p lim) := by
  rw [ident_run b p lim hl] at h
  split at h
  · cases h
  · simp only [Option.some.injEq, Prod.mk.injEq] at h
    exact ⟨by assumption, h.1.symm, h.2.symm⟩

theorem take_step {b : ByteArray} {p lim k : Nat} {v m : Bytes} (hl : lim ≤ b.size) (hp : p ≤ lim)
    (h : (take k).run ((b.toList.take lim).drop p) = some (v, m)) :
    p + k ≤ lim ∧ v = (b.toList.drop p).take k ∧ m = (b.toList.take lim).drop (p + k) := by
  rw [take_pos b lim p k hl hp] at h
  split at h
  · simp only [Option.some.injEq, Prod.mk.injEq] at h
    exact ⟨by assumption, h.1.symm, h.2.symm⟩
  · cases h

theorem nat_step {b : ByteArray} {p lim k lo hi v : Nat} {m : Bytes} (hl : lim ≤ b.size) (hp : p ≤ lim)
    (h : (nat k lo hi).run ((b.toList.take lim).drop p) = some (v, m)) :
    p + k ≤ lim ∧ v = beNat ((b.toList.drop p).take k) ∧ lo ≤ v ∧ v ≤ hi ∧ m = (b.toList.take lim).drop (p + k) := by
  rw [nat_pos b lim p k lo hi hl hp] at h
  split at h
  · rename_i hc
    simp only [Option.some.injEq, Prod.mk.injEq] at h
    obtain ⟨rfl, rfl⟩ := h
    exact ⟨hc.1, rfl, hc.2.1, hc.2.2, rfl⟩
  · cases h

theorem parse_some {α : Type} {p : Gate.P α} {lim : Nat} {b : Bytes} {x : α} (h : parse p lim b = some x) :
    p.run b = some (x, []) := by
  unfold parse at h
  split at h
  · cases h
  · split at h
    · rename_i y heq; cases h; exact heq
    · cases h

private theorem or_shift (a c k : Nat) (h : c < 2 ^ k) : a <<< k ||| c = a * 2 ^ k + c := by
  rw [← Nat.shiftLeft_add_eq_or_of_lt h, Nat.shiftLeft_eq]

private theorem or_mul (a c k : Nat) (h : c < 2 ^ k) : a * 2 ^ k ||| c = a * 2 ^ k + c := by
  rw [← Nat.shiftLeft_eq, or_shift a c k h, Nat.shiftLeft_eq]

private theorem shl_mod (a k : Nat) (ha : a < 256) (hk : k ≤ 56) : a <<< k % 2 ^ 64 = a * 2 ^ k := by
  rw [Nat.shiftLeft_eq, Nat.mod_eq_of_lt]
  have : 2 ^ k ≤ 2 ^ 56 := Nat.pow_le_pow_right (by omega) hk
  have : a * 2 ^ k < 256 * 2 ^ k := Nat.mul_lt_mul_of_pos_right ha (Nat.two_pow_pos k)
  have : 256 * 2 ^ k ≤ 256 * 2 ^ 56 := Nat.mul_le_mul_left 256 (by assumption)
  have : (256 : Nat) * 2 ^ 56 = 2 ^ 64 := by decide
  omega

private theorem or8 {a0 a1 a2 a3 a4 a5 a6 a7 : Nat} (h0 : a0 < 256) (h1 : a1 < 256) (h2 : a2 < 256) (h3 : a3 < 256)
    (h4 : a4 < 256) (h5 : a5 < 256) (h6 : a6 < 256) (h7 : a7 < 256) :
    (a0 <<< 56 % 2 ^ 64 ||| a1 <<< 48 % 2 ^ 64 ||| a2 <<< 40 % 2 ^ 64 ||| a3 <<< 32 % 2 ^ 64 ||| a4 <<< 24 % 2 ^ 64 |||
      a5 <<< 16 % 2 ^ 64 ||| a6 <<< 8 % 2 ^ 64 ||| a7) =
    a0 * 256 ^ 7 + (a1 * 256 ^ 6 + (a2 * 256 ^ 5 + (a3 * 256 ^ 4 + (a4 * 256 ^ 3 + (a5 * 256 ^ 2 +
      (a6 * 256 ^ 1 + (a7 * 256 ^ 0 + 0))))))) := by
  rw [shl_mod a0 56 h0 (by omega), shl_mod a1 48 h1 (by omega), shl_mod a2 40 h2 (by omega),
    shl_mod a3 32 h3 (by omega), shl_mod a4 24 h4 (by omega), shl_mod a5 16 h5 (by omega), shl_mod a6 8 h6 (by omega)]
  simp only [Nat.or_assoc]
  rw [or_mul a6 a7 8 (by simp only [Nat.reducePow]; omega)]
  rw [or_mul a5 _ 16 (by simp only [Nat.reducePow]; omega)]
  rw [or_mul a4 _ 24 (by simp only [Nat.reducePow]; omega)]
  rw [or_mul a3 _ 32 (by simp only [Nat.reducePow]; omega)]
  rw [or_mul a2 _ 40 (by simp only [Nat.reducePow]; omega)]
  rw [or_mul a1 _ 48 (by simp only [Nat.reducePow]; omega)]
  rw [or_mul a0 _ 56 (by simp only [Nat.reducePow]; omega)]
  simp only [Nat.reducePow]
  omega

private theorem take_succ_drop (L : List UInt8) (p k : Nat) (h : p < L.length) :
    (L.drop p).take (k + 1) = L[p] :: (L.drop (p + 1)).take k := by
  rw [List.drop_eq_getElem_cons h, List.take_succ_cons]

private theorem beNat_slice (L : List UInt8) (p k : Nat) (h : p + k + 1 ≤ L.length) :
    beNat ((L.drop p).take (k + 1)) = L[p].toNat * 256 ^ k + beNat ((L.drop (p + 1)).take k) := by
  rw [take_succ_drop L p k (by omega), beNat_cons]
  simp only [List.length_take, List.length_drop]
  rw [show min k (L.length - (p + 1)) = k by omega]

private theorem be8_toNat (b : ByteArray) (p : Nat) (h : p + 8 ≤ b.size) :
    (be8 b p).toNat = beNat ((b.toList.drop p).take 8) := by
  have hL : b.toList.length = b.size := (Bin.size_eq_length' b).symm
  have g : ∀ i (hi : i < 8), b.get! (p + i) = b.toList[p + i]'(by omega) := fun i hi => get!_lt b (p + i) (by omega)
  rw [beNat_slice _ p 7 (by omega), beNat_slice _ (p + 1) 6 (by omega), beNat_slice _ (p + 1 + 1) 5 (by omega),
    beNat_slice _ (p + 1 + 1 + 1) 4 (by omega), beNat_slice _ (p + 1 + 1 + 1 + 1) 3 (by omega),
    beNat_slice _ (p + 1 + 1 + 1 + 1 + 1) 2 (by omega), beNat_slice _ (p + 1 + 1 + 1 + 1 + 1 + 1) 1 (by omega),
    beNat_slice _ (p + 1 + 1 + 1 + 1 + 1 + 1 + 1) 0 (by omega)]
  unfold be8
  have g0 := g 0 (by omega); have g1 := g 1 (by omega); have g2 := g 2 (by omega); have g3 := g 3 (by omega)
  have g4 := g 4 (by omega); have g5 := g 5 (by omega); have g6 := g 6 (by omega); have g7 := g 7 (by omega)
  simp only [Nat.add_zero] at g0
  rw [g0, g1, g2, g3, g4, g5, g6, g7]
  simp only [UInt64.toNat_or, UInt64.toNat_shiftLeft, UInt8.toNat_toUInt64, List.take_zero, beNat, List.foldl_nil,
    Nat.add_assoc]
  simp only [UInt64.reduceToNat, Nat.reduceMod, Nat.reduceAdd]
  exact or8 (UInt8.toNat_lt _) (UInt8.toNat_lt _) (UInt8.toNat_lt _) (UInt8.toNat_lt _) (UInt8.toNat_lt _)
    (UInt8.toNat_lt _) (UInt8.toNat_lt _) (UInt8.toNat_lt _)

private theorem be2_toNat (b : ByteArray) (p : Nat) (h : p + 2 ≤ b.size) :
    (be2 b p).toNat = beNat ((b.toList.drop p).take 2) := by
  have hL : b.toList.length = b.size := (Bin.size_eq_length' b).symm
  rw [beNat_slice _ p 1 (by omega), beNat_slice _ (p + 1) 0 (by omega)]
  unfold be2
  rw [get!_lt b p (by omega), get!_lt b (p + 1) (by omega)]
  simp only [UInt64.toNat_or, UInt64.toNat_shiftLeft, UInt8.toNat_toUInt64, List.take_zero, beNat, List.foldl_nil,
    UInt64.reduceToNat, Nat.reduceMod]
  rw [shl_mod _ 8 (UInt8.toNat_lt _) (by omega), or_mul _ _ 8 (by simp only [Nat.reducePow]; exact UInt8.toNat_lt _)]
  simp only [Nat.reducePow]; omega

private theorem beNat_inj : ∀ (xs ys : Bytes), xs.length = ys.length → beNat xs = beNat ys → xs = ys
  | [], [], _, _ => rfl
  | [], _ :: _, hl, _ => by simp at hl
  | _ :: _, [], hl, _ => by simp at hl
  | a :: as, b :: bs, hl, h => by
    simp only [List.length_cons, Nat.add_right_cancel_iff] at hl
    rw [beNat_cons, beNat_cons, hl] at h
    have h1 := Keyset.beNat_lt_pow bs.length as hl
    have h2 := Keyset.beNat_lt_pow bs.length bs rfl
    have hpos : 0 < 256 ^ bs.length := Nat.pow_pos (by decide)
    have d : ∀ (c : UInt8) (r : Nat), r < 256 ^ bs.length → (c.toNat * 256 ^ bs.length + r) / 256 ^ bs.length = c.toNat := by
      intro c r hr
      rw [Nat.mul_comm, Nat.mul_add_div hpos, Nat.div_eq_of_lt hr, Nat.add_zero]
    have hab : a.toNat = b.toNat := by rw [← d a _ h1, ← d b _ h2, h]
    have hr : beNat as = beNat bs := by rw [hab] at h; omega
    rw [UInt8.toNat_inj.mp hab, beNat_inj as bs hl hr]

private theorem len_slice (L : List UInt8) (p k : Nat) (h : p + k ≤ L.length) : ((L.drop p).take k).length = k := by
  simp; omega

private theorem sameBytes_eq (a b : ByteArray) : ∀ (k p q : Nat), p + k ≤ a.size → q + k ≤ b.size →
    sameBytes a b p q k = decide ((a.toList.drop p).take k = (b.toList.drop q).take k) := by
  intro k
  induction k using Nat.strongRecOn with
  | ind k ih =>
    intro p q ha hb
    have hLa : a.toList.length = a.size := (Bin.size_eq_length' a).symm
    have hLb : b.toList.length = b.size := (Bin.size_eq_length' b).symm
    unfold sameBytes
    by_cases h8 : 8 ≤ k
    · rw [if_pos h8, ih (k - 8) (by omega) (p + 8) (q + 8) (by omega) (by omega)]
      have e : k = 8 + (k - 8) := by omega
      rw [e, List.take_add, List.take_add, List.drop_drop, List.drop_drop, show 8 + (k - 8) - 8 = k - 8 by omega]
      have hw : (be8 a p == be8 b q) = decide ((a.toList.drop p).take 8 = (b.toList.drop q).take 8) := by
        rw [Bool.eq_iff_iff, beq_iff_eq, decide_eq_true_iff, ← UInt64.toNat_inj, be8_toNat a p (by omega),
          be8_toNat b q (by omega)]
        exact ⟨beNat_inj _ _ (by rw [len_slice _ _ _ (by omega), len_slice _ _ _ (by omega)]), fun h => by rw [h]⟩
      rw [hw, Bool.eq_iff_iff]
      simp only [Bool.and_eq_true, decide_eq_true_iff]
      constructor
      · rintro ⟨h1, h2⟩; rw [h1, h2]
      · intro h
        exact List.append_inj h (by rw [len_slice _ _ _ (by omega), len_slice _ _ _ (by omega)])
    · rw [if_neg h8]
      by_cases h0 : 0 < k
      · rw [if_pos h0, ih (k - 1) (by omega) (p + 1) (q + 1) (by omega) (by omega)]
        have e : k = (k - 1) + 1 := by omega
        rw [e, take_succ_drop _ p _ (by omega), take_succ_drop _ q _ (by omega), show k - 1 + 1 - 1 = k - 1 by omega,
          get!_lt a p (by omega), get!_lt b q (by omega)]
        rw [Bool.eq_iff_iff]
        simp only [List.cons.injEq, Bool.and_eq_true, beq_iff_eq, decide_eq_true_iff]
      · rw [if_neg h0, show k = 0 by omega]
        simp

private theorem lexLt_beNat : ∀ (xs ys : Bytes), xs.length = ys.length → lexLt xs ys = decide (beNat xs < beNat ys)
  | [], [], _ => by simp [lexLt, beNat]
  | [], _ :: _, hl => by simp at hl
  | _ :: _, [], hl => by simp at hl
  | a :: as, b :: bs, hl => by
    simp only [List.length_cons, Nat.add_right_cancel_iff] at hl
    rw [lexLt, beNat_cons, beNat_cons, hl, lexLt_beNat as bs hl]
    have h1 := Keyset.beNat_lt_pow bs.length as hl
    have h2 := Keyset.beNat_lt_pow bs.length bs rfl
    rw [Bool.eq_iff_iff]
    simp only [Bool.or_eq_true, Bool.and_eq_true, beq_iff_eq, decide_eq_true_iff]
    rcases Nat.lt_trichotomy a.toNat b.toNat with hab | hab | hab
    · have : (a.toNat + 1) * 256 ^ bs.length ≤ b.toNat * 256 ^ bs.length := Nat.mul_le_mul_right _ hab
      rw [Nat.add_mul, Nat.one_mul] at this
      have : a < b := hab
      constructor
      · intro _; omega
      · intro _; exact Or.inl this
    · have hab' : a = b := UInt8.toNat_inj.mp hab
      subst hab'
      constructor
      · rintro (h | ⟨_, h⟩)
        · exact absurd h (UInt8.lt_irrefl a)
        · omega
      · intro h; exact Or.inr ⟨rfl, by omega⟩
    · have : (b.toNat + 1) * 256 ^ bs.length ≤ a.toNat * 256 ^ bs.length := Nat.mul_le_mul_right _ hab
      rw [Nat.add_mul, Nat.one_mul] at this
      have hn : ¬ a < b := fun h => by have : a.toNat < b.toNat := h; omega
      have hn' : a ≠ b := fun h => by subst h; omega
      constructor
      · rintro (h | ⟨h, _⟩)
        · exact absurd h hn
        · exact absurd h hn'
      · intro _; omega

private theorem lexLt_append : ∀ (A C A' C' : Bytes), A.length = C.length →
    lexLt (A ++ A') (C ++ C') = (lexLt A C || (A == C && lexLt A' C'))
  | [], [], _, _, _ => by simp [lexLt]
  | [], _ :: _, _, _, hl => by simp at hl
  | _ :: _, [], _, _, hl => by simp at hl
  | a :: A, c :: C, A', C', hl => by
    simp only [List.length_cons, Nat.add_right_cancel_iff] at hl
    simp only [List.cons_append, lexLt, lexLt_append A C A' C' hl, List.cons_beq_cons]
    cases (decide (a < c)) <;> cases (a == c) <;> simp

private theorem lt64_eq (b : ByteArray) (p q : Nat) (hp : p + 64 ≤ b.size) (hq : q + 64 ≤ b.size) :
    ∀ w, w ≤ 8 → lt64 b p q w = lexLt ((b.toList.drop (p + 8 * w)).take (64 - 8 * w)) ((b.toList.drop (q + 8 * w)).take (64 - 8 * w)) := by
  have hL : b.toList.length = b.size := (Bin.size_eq_length' b).symm
  intro w
  induction h : 8 - w generalizing w with
  | zero =>
    intro hw
    rw [show w = 8 by omega]
    unfold lt64
    simp [lexLt]
  | succ m ih =>
    intro hw
    unfold lt64
    rw [dif_pos (by omega), ih (w + 1) (by omega) (by omega)]
    have e : 64 - 8 * w = 8 + (64 - 8 * (w + 1)) := by omega
    have heq : ((b.toList.drop (p + 8 * w)).take 8 == (b.toList.drop (q + 8 * w)).take 8) = (be8 b (p + 8 * w) == be8 b (q + 8 * w)) := by
      rw [Bool.eq_iff_iff, beq_iff_eq, beq_iff_eq, ← UInt64.toNat_inj, be8_toNat b _ (by omega), be8_toNat b _ (by omega)]
      exact ⟨fun h => by rw [h], beNat_inj _ _ (by rw [len_slice _ _ _ (by omega), len_slice _ _ _ (by omega)])⟩
    rw [e, List.take_add, List.take_add, List.drop_drop, List.drop_drop,
      show p + 8 * w + 8 = p + 8 * (w + 1) by omega, show q + 8 * w + 8 = q + 8 * (w + 1) by omega,
      lexLt_append _ _ _ _ (by rw [len_slice _ _ _ (by omega), len_slice _ _ _ (by omega)]),
      lexLt_beNat ((b.toList.drop (p + 8 * w)).take 8) ((b.toList.drop (q + 8 * w)).take 8)
        (by rw [len_slice _ _ _ (by omega), len_slice _ _ _ (by omega)]),
      ← be8_toNat b _ (by omega), ← be8_toNat b _ (by omega), heq]
    show (if (be8 b (p + 8 * w) == be8 b (q + 8 * w)) = true then _ else _) = _
    by_cases hc : be8 b (p + 8 * w) = be8 b (q + 8 * w)
    · simp [hc]
    · have : (be8 b (p + 8 * w) == be8 b (q + 8 * w)) = false := by simpa using hc
      rw [this, Bool.false_and, Bool.or_false]
      simp [UInt64.lt_iff_toNat_lt]

private theorem idxFold (b : ByteArray) : ∀ (m s acc : Nat), s + m ≤ b.size →
    (List.range' s m).foldl (fun acc t => acc * 256 + (b.get! t).toNat) acc =
      acc * 256 ^ m + beNat ((b.toList.drop s).take m)
  | 0, s, acc, _ => by simp [beNat]
  | m + 1, s, acc, h => by
    have hL : b.toList.length = b.size := (Bin.size_eq_length' b).symm
    rw [List.range'_succ, List.foldl_cons, idxFold b m (s + 1) _ (by omega), beNat_slice _ s m (by omega),
      get!_lt b s (by omega), Nat.pow_succ]
    have : acc * 256 * 256 ^ m = acc * (256 ^ m * 256) := by rw [Nat.mul_assoc, Nat.mul_comm 256]
    simp only [Nat.add_mul, Nat.add_assoc, this]

private theorem u64Fold (b : ByteArray) : ∀ (m s : Nat) (c : UInt64), m ≤ 7 → c.toNat < 256 ^ (7 - m) →
    ((List.range' s m).foldl (fun (c : UInt64) t => c <<< 8 ||| (b.get! t).toUInt64) c).toNat =
      (List.range' s m).foldl (fun acc t => acc * 256 + (b.get! t).toNat) c.toNat
  | 0, s, c, _, _ => by simp
  | m + 1, s, c, hm, hc => by
    rw [List.range'_succ, List.foldl_cons, List.foldl_cons]
    have hc6 : c.toNat < 72057594037927936 := by
      have : 256 ^ (7 - (m + 1)) ≤ 256 ^ 6 := Nat.pow_le_pow_right (by omega) (by omega)
      have : (256 : Nat) ^ 6 < 72057594037927936 := by decide
      omega
    have hx : (b.get! s).toNat < 256 := UInt8.toNat_lt _
    have step : (c <<< 8 ||| (b.get! s).toUInt64).toNat = c.toNat * 256 + (b.get! s).toNat := by
      rw [UInt64.toNat_or, UInt64.toNat_shiftLeft, UInt8.toNat_toUInt64]
      simp only [UInt64.reduceToNat, Nat.reduceMod]
      rw [Nat.shiftLeft_eq, Nat.mod_eq_of_lt (by simp only [Nat.reducePow]; omega),
        or_mul _ _ 8 (by simp only [Nat.reducePow]; omega)]
    rw [u64Fold b m (s + 1) _ (by omega) (by
      rw [step]
      have : 256 ^ (7 - m) = 256 ^ (7 - (m + 1)) * 256 := by rw [← Nat.pow_succ]; congr 1; omega
      omega), step]

private theorem range'_app1 (s m n : Nat) : List.range' s m ++ List.range' (s + m) n = List.range' s (m + n) := by
  have := List.range'_append (s := s) (m := m) (n := n) (step := 1)
  simp only [Nat.one_mul] at this
  exact this

private theorem outerFold (b : ByteArray) (i : Nat) : ∀ (k acc : Nat), i + 7 * k ≤ b.size →
    (List.range' 0 k).foldl (fun acc g => acc * 72057594037927936 +
      ((List.range' (i + 7 * g) 7).foldl (fun (c : UInt64) t => c <<< 8 ||| (b.get! t).toUInt64) 0).toNat) acc =
    (List.range' i (7 * k)).foldl (fun acc t => acc * 256 + (b.get! t).toNat) acc
  | 0, acc, _ => by simp
  | k + 1, acc, h => by
    rw [← range'_app1 0 k 1, List.foldl_append, outerFold b i k acc (by omega), Nat.mul_succ, ← range'_app1 i (7 * k) 7,
      List.foldl_append]
    simp only [Nat.zero_add, List.range'_one, List.foldl_cons, List.foldl_nil]
    rw [u64Fold b 7 _ 0 (by omega) (by decide), idxFold b 7 _ _ (by omega), idxFold b 7 _ _ (by omega)]
    simp

private theorem beNatA_eq (b : ByteArray) (i j acc : Nat) (hj : j ≤ b.size) (hij : i ≤ j) :
    beNatA b i j acc = acc * 256 ^ (j - i) + beNat ((b.toList.drop i).take (j - i)) := by
  unfold beNatA
  simp only [Id.run, Std.Legacy.Range.forIn_eq_forIn_range', List.forIn_pure_yield_eq_foldl, pure_bind,
    Std.Legacy.Range.size, Nat.add_sub_cancel_left, Nat.add_sub_cancel, Nat.div_one, Nat.sub_zero]
  have hk : 7 * ((j - i) / 7) ≤ j - i := Nat.mul_div_le (j - i) 7
  rw [outerFold b i _ _ (by omega), ← List.foldl_append, range'_app1, show 7 * ((j - i) / 7) + (j - (i + 7 * ((j - i) / 7))) = j - i by omega,
    idxFold b _ _ _ (by omega)]
  rfl

private theorem copySlice_toList (src dest : ByteArray) (so d len : Nat) (hd : d = dest.size) :
    (src.copySlice so dest d len).toList = dest.toList ++ (src.toList.drop so).take len := by
  subst hd
  simp only [ByteArray.copySlice, Bin.toList_eq', Array.toList_append, Array.toList_extract, List.extract_eq_take_drop, List.drop_zero, Nat.sub_zero]
  have e : dest.size = dest.data.toList.length := by rw [Bin.size_eq_length', Bin.toList_eq']
  rw [e, List.take_length, Nat.add_sub_cancel_left, List.drop_eq_nil_of_le (Nat.le_add_right _ _), List.take_nil,
    List.append_nil]

private theorem ident_ok {b : ByteArray} {p lim : Nat} (hl : lim ≤ b.size) (h : identEnd b p lim ≠ 0) :
    Gate.ident.run ((b.toList.take lim).drop p) =
      some ((b.toList.drop (p + 2)).take (identEnd b p lim - (p + 2)), (b.toList.take lim).drop (identEnd b p lim)) := by
  rw [ident_run b p lim hl, if_neg h]

private theorem take_ok {b : ByteArray} {p lim k : Nat} (hl : lim ≤ b.size) (hp : p + k ≤ lim) :
    (take k).run ((b.toList.take lim).drop p) = some ((b.toList.drop p).take k, (b.toList.take lim).drop (p + k)) := by
  rw [take_pos b lim p k hl (by omega), if_pos hp]

private theorem nat_ok {b : ByteArray} {p lim k lo hi : Nat} (hl : lim ≤ b.size) (hp : p + k ≤ lim)
    (h1 : lo ≤ beNat ((b.toList.drop p).take k)) (h2 : beNat ((b.toList.drop p).take k) ≤ hi) :
    (nat k lo hi).run ((b.toList.take lim).drop p) = some (beNat ((b.toList.drop p).take k), (b.toList.take lim).drop (p + k)) := by
  rw [nat_pos b lim p k lo hi hl (by omega), if_pos ⟨hp, h1, h2⟩]

private theorem beNat_one (b : ByteArray) (p : Nat) (h : p < b.size) : beNat ((b.toList.drop p).take 1) = (b.get! p).toNat := by
  have hL : b.toList.length = b.size := (Bin.size_eq_length' b).symm
  rw [take_succ_drop _ p 0 (by omega), get!_lt b p (by omega)]
  simp [beNat]

private theorem flows_get (t : Nat) (h : t < 5) : flows[t]? = some (flows.getD t .FFS_CYCLE) := by
  match t, h with
  | 0, _ => rfl
  | 1, _ => rfl
  | 2, _ => rfl
  | 3, _ => rfl
  | 4, _ => rfl

private theorem drop_full (b : ByteArray) (e : Nat) : (b.toList.take e).drop e = [] := by
  simp

/-- A line `lineRow` accepts at `b[p, e)` is the spec reader's line there, with the request's flow, member and payee. -/
private theorem lineRow_spec {x : ByteArray} {p e : Nat} {tag : UInt8} {mem ps pn : Nat} {payW : UInt64} {r : LineRow}
    (he : e ≤ x.size) (hm : mem + 32 ≤ x.size) (hps : ps + pn ≤ x.size) (ht1 : 1 ≤ tag.toNat) (ht5 : tag.toNat ≤ 5)
    (h : lineRow x p e tag mem ps pn payW = some r) :
    pLine.run ((x.toList.take e).drop p) =
      some (⟨flows.getD (tag.toNat - 1) .FFS_CYCLE, (x.toList.drop mem).take 32, (x.toList.drop ps).take pn,
        r.cents.toNat⟩, []) := by
  have hL : x.toList.length = x.size := (Bin.size_eq_length' x).symm
  unfold lineRow at h
  simp only at h
  split at h
  · cases h
  rename_i c1
  simp only [Bool.or_eq_true, decide_eq_true_eq, bne_iff_ne, ne_eq, not_or, Decidable.not_not] at c1
  generalize hie : identEnd x (p + 1) e = ie at h
  split at h
  · cases h
  rename_i c2
  simp only [Bool.or_eq_true, decide_eq_true_eq, beq_iff_eq, not_or, Bool.not_eq_true', Bool.not_eq_false] at c2
  generalize hpe : identEnd x (ie + 32) e = pe at h
  split at h
  · cases h
  rename_i c3
  simp only [Bool.or_eq_true, beq_iff_eq, bne_iff_ne, ne_eq, not_or, Decidable.not_not, Bool.not_eq_true',
    Bool.not_eq_false] at c3
  generalize hre : identEnd x pe e = re at h
  split at h
  · cases h
  rename_i c4
  simp only [Bool.or_eq_true, decide_eq_true_eq, beq_iff_eq, not_or] at c4
  generalize hoe : identEnd x (re + 4) e = oe at h
  split at h
  · cases h
  rename_i c5
  simp only [Bool.or_eq_true, beq_iff_eq, bne_iff_ne, ne_eq, not_or, Decidable.not_not] at c5
  split at h
  · cases h
  rename_i c6
  cases h
  obtain ⟨c1a, c1b⟩ := c1
  obtain ⟨⟨c2a, c2b⟩, c2c⟩ := c2
  obtain ⟨⟨c3a, c3b⟩, c3c⟩ := c3
  obtain ⟨c4a, c4b⟩ := c4
  obtain ⟨c5a, c5b⟩ := c5
  have i1 : identEnd x (p + 1) e ≠ 0 := by rw [hie]; exact c2a
  have i2 : identEnd x (ie + 32) e ≠ 0 := by rw [hpe]; exact c3a
  have i3 : identEnd x pe e ≠ 0 := by rw [hre]; exact c4a
  have i4 : identEnd x (re + 4) e ≠ 0 := by rw [hoe]; exact c5a
  have bi := identEnd_bounds i1
  have bp := identEnd_bounds i2
  have br := identEnd_bounds i3
  have bo := identEnd_bounds i4
  rw [hie] at bi; rw [hpe] at bp; rw [hre] at br; rw [hoe] at bo
  rw [sameBytes_eq x x 32 ie mem (by omega) hm] at c2c
  rw [sameBytes_eq x x pn (ie + 34) ps (by omega) hps] at c3c
  simp only [decide_eq_true_eq] at c2c c3c
  simp only [UInt64.lt_iff_toNat_lt, UInt64.reduceToNat, be8_toNat x (oe + 4) (by omega)] at c6
  have hpmax : ∀ k q, k ≤ 7 → q + k ≤ x.size → beNat ((x.toList.drop q).take k) ≤ maxNat := by
    intro k q hk hq
    have h1 := Keyset.beNat_lt_pow k ((x.toList.drop q).take k) (len_slice _ _ _ (by omega))
    have h2 : 256 ^ k ≤ 256 ^ 7 := Nat.pow_le_pow_right (by omega) hk
    have h3 : (256 : Nat) ^ 7 ≤ maxNat := by decide
    omega
  simp only [pLine, Gate.tag, StateT.run_bind, memberKeyBytes]
  rw [nat_ok he (by omega : p + 1 ≤ e) (by rw [beNat_one x p (by omega), c1b]; exact ht1)
    (by rw [beNat_one x p (by omega), c1b]; simpa [flows] using ht5)]
  simp only [Option.bind_eq_bind, Option.bind_some]
  rw [beNat_one x p (by omega), c1b, flows_get _ (by omega)]
  simp only [StateT.run_pure, Option.pure_def, Option.bind_some]
  rw [ident_ok he i1, hie]
  simp only [Option.bind_some]
  rw [take_ok he (by omega : ie + 32 ≤ e)]
  simp only [Option.bind_some]
  rw [ident_ok he i2, hpe]
  simp only [Option.bind_some]
  rw [ident_ok he i3, hre]
  simp only [Option.bind_some]
  rw [nat_ok he (by omega : re + 4 ≤ e) (Nat.zero_le _) (hpmax 4 re (by omega) (by omega))]
  simp only [Option.bind_some]
  rw [ident_ok he i4, hoe]
  simp only [Option.bind_some]
  rw [nat_ok he (by omega : oe + 4 ≤ e) (Nat.zero_le _) (hpmax 4 oe (by omega) (by omega))]
  simp only [Option.bind_some]
  rw [nat_ok he (by omega : oe + 4 + 8 ≤ e) (Nat.zero_le _) (by simp only [maxNat]; omega)]
  simp only [Option.bind_some, StateT.run_pure]
  rw [show oe + 4 + 8 = e by omega, drop_full x e, c2c, show ie + 32 + 2 = ie + 34 by omega, c3b, c3c,
    be8_toNat x (oe + 4) (by omega)]

private theorem flows_inj (a b : Nat) (ha1 : 1 ≤ a) (ha5 : a ≤ 5) (hb1 : 1 ≤ b) (hb5 : b ≤ 5)
    (h : flows.getD (a - 1) .FFS_CYCLE = flows.getD (b - 1) .FFS_CYCLE) : a = b := by
  have ha : a = 1 ∨ a = 2 ∨ a = 3 ∨ a = 4 ∨ a = 5 := by omega
  have hb : b = 1 ∨ b = 2 ∨ b = 3 ∨ b = 4 ∨ b = 5 := by omega
  rcases ha with rfl | rfl | rfl | rfl | rfl <;> rcases hb with rfl | rfl | rfl | rfl | rfl <;> simp_all [flows]

private theorem lineRow_some {x : ByteArray} {p e : Nat} {tag : UInt8} {mem ps pn : Nat} {payW : UInt64} {w : WireLine}
    (he : e ≤ x.size) (hpe : p ≤ e) (hm : mem + 32 ≤ x.size) (hps : ps + pn ≤ x.size) (ht1 : 1 ≤ tag.toNat) (ht5 : tag.toNat ≤ 5)
    (hw : pLine.run ((x.toList.take e).drop p) = some (w, []))
    (hf : w.flow = flows.getD (tag.toNat - 1) .FFS_CYCLE) (hmk : w.memberKey = (x.toList.drop mem).take 32)
    (hpr : w.payeeRef = (x.toList.drop ps).take pn) :
    ∃ r, lineRow x p e tag mem ps pn payW = some r := by
  have hL : x.toList.length = x.size := (Bin.size_eq_length' x).symm
  simp only [pLine, Gate.tag, StateT.run_bind, memberKeyBytes] at hw
  obtain ⟨⟨v0, s0⟩, h0, hw⟩ := obind_some hw
  obtain ⟨⟨vn, sn⟩, hn, h0⟩ := obind_some h0
  obtain ⟨hp1, hvn, hv1, hv5, rfl⟩ := nat_step he hpe (show (nat 1 1 flows.length).run _ = _ from hn)
  have hv5' : vn ≤ 5 := hv5
  simp only [flows_get (vn - 1) (by omega)] at h0
  simp only [StateT.run_pure, Option.pure_def] at h0
  obtain ⟨rfl, rfl⟩ : v0 = flows.getD (vn - 1) .FFS_CYCLE ∧ s0 = (x.toList.take e).drop (p + 1) := by
    simpa [and_comm] using h0.symm
  obtain ⟨⟨a1, s1⟩, h1, hw⟩ := obind_some hw
  obtain ⟨i1, ha1, rfl⟩ := ident_step he h1
  have b1 := identEnd_bounds i1
  obtain ⟨⟨a2, s2⟩, h2, hw⟩ := obind_some hw
  obtain ⟨t2, ha2, rfl⟩ := take_step he (by omega) h2
  obtain ⟨⟨a3, s3⟩, h3, hw⟩ := obind_some hw
  obtain ⟨i3, ha3, rfl⟩ := ident_step he h3
  have b3 := identEnd_bounds i3
  obtain ⟨⟨a4, s4⟩, h4, hw⟩ := obind_some hw
  obtain ⟨i4, ha4, rfl⟩ := ident_step he h4
  have b4 := identEnd_bounds i4
  obtain ⟨⟨a5, s5⟩, h5, hw⟩ := obind_some hw
  obtain ⟨n5, ha5, -, hh5, rfl⟩ := nat_step he (by omega) h5
  obtain ⟨⟨a6, s6⟩, h6, hw⟩ := obind_some hw
  obtain ⟨i6, ha6, rfl⟩ := ident_step he h6
  have b6 := identEnd_bounds i6
  obtain ⟨⟨a7, s7⟩, h7, hw⟩ := obind_some hw
  obtain ⟨n7, ha7, -, hh7, rfl⟩ := nat_step he (by omega) h7
  obtain ⟨⟨a8, s8⟩, h8, hw⟩ := obind_some hw
  obtain ⟨n8, ha8, -, hh8, rfl⟩ := nat_step he (by omega) h8
  simp only [StateT.run_pure, Option.pure_def, Option.some.injEq, Prod.mk.injEq] at hw
  obtain ⟨hww, hend⟩ := hw
  subst hww
  simp only at hf hmk hpr
  have hpL : p < x.size := by omega
  have hvt : vn = tag.toNat := flows_inj vn tag.toNat hv1 hv5' ht1 ht5 hf
  have hget : x.get! p = tag := UInt8.toNat_inj.mp (by rw [← hvt, hvn, beNat_one x p hpL])
  generalize hie : identEnd x (p + 1) e = ie at *
  generalize hpe' : identEnd x (ie + 32) e = pe at *
  generalize hre : identEnd x pe e = re at *
  generalize hoe : identEnd x (re + 4) e = oe at *
  have hlen3 : a3.length = pe - (ie + 34) := by
    rw [ha3, len_slice _ _ _ (by omega)]
  have hlen3' : a3.length = pn := by rw [hpr, len_slice _ _ _ (by omega)]
  have hpn : pe - (ie + 34) = pn := by omega
  have hse : sameBytes x x ie mem 32 = true := by
    rw [sameBytes_eq x x 32 ie mem (by omega) hm]; simp only [decide_eq_true_eq]; rw [← ha2, ← hmk]
  have hse' : sameBytes x x (ie + 34) ps pn = true := by
    rw [sameBytes_eq x x pn (ie + 34) ps (by omega) hps]; simp only [decide_eq_true_eq]
    rw [← hpr, ha3, show ie + 32 + 2 = ie + 34 by omega, hpn]
  have hcents : ¬ (9223372036854775807 : UInt64) < be8 x (oe + 4) := by
    rw [UInt64.lt_iff_toNat_lt, be8_toNat x (oe + 4) (by omega)]
    simp only [UInt64.reduceToNat]
    have : a8 ≤ maxNat := hh8
    rw [← ha8]; simp only [maxNat] at this; omega
  have hoe12 : oe + 12 = e := by
    have := congrArg List.length hend
    simp only [List.length_drop, List.length_take, List.length_nil] at this
    have : e ≤ x.toList.length := by omega
    omega
  unfold lineRow
  simp only [hie, hpe', hre, hoe]
  split
  · rename_i c; simp only [Bool.or_eq_true, beq_iff_eq, bne_iff_ne, ne_eq, decide_eq_true_eq, Bool.not_eq_true', hse, hse', Bool.true_eq_false, or_false] at c
    rcases c with c | c
    · omega
    · exact (c hget).elim
  split
  · rename_i c; simp only [Bool.or_eq_true, beq_iff_eq, bne_iff_ne, ne_eq, decide_eq_true_eq, Bool.not_eq_true', hse, hse', Bool.true_eq_false, or_false] at c; omega
  split
  · rename_i c; simp only [Bool.or_eq_true, beq_iff_eq, bne_iff_ne, ne_eq, decide_eq_true_eq, Bool.not_eq_true', hse, hse', Bool.true_eq_false, or_false] at c; omega
  split
  · rename_i c; simp only [Bool.or_eq_true, beq_iff_eq, bne_iff_ne, ne_eq, decide_eq_true_eq, Bool.not_eq_true', hse, hse', Bool.true_eq_false, or_false] at c; omega
  split
  · rename_i c; simp only [Bool.or_eq_true, beq_iff_eq, bne_iff_ne, ne_eq, decide_eq_true_eq, Bool.not_eq_true', hse, hse', Bool.true_eq_false, or_false] at c; omega
  exact ⟨_, rfl⟩

private theorem many_succ {α : Type} (p : Gate.P α) (k : Nat) (s : Bytes) :
    (Gate.many p (k + 1)).run s = (p.run s).bind fun a => ((Gate.many p k).run a.2).map fun b => (a.1 :: b.1, b.2) := by
  simp only [Gate.many, StateT.run_bind]
  cases p.run s with
  | none => rfl
  | some a =>
    simp only [Option.bind_eq_bind, Option.bind_some, StateT.run_pure, Option.pure_def]
    cases (Gate.many p k).run a.2 <;> rfl

private theorem blob_run (x : ByteArray) (q : Nat) (hq : q ≤ x.size) :
    (Gate.blob 1 maxLineBytes).run ((x.toList.take x.size).drop q) =
      if q + 2 ≤ x.size ∧ 1 ≤ (be2 x q).toNat ∧ (be2 x q).toNat ≤ 569 ∧ q + 2 + (be2 x q).toNat ≤ x.size
      then some ((x.toList.drop (q + 2)).take (be2 x q).toNat, (x.toList.take x.size).drop (q + 2 + (be2 x q).toNat))
      else none := by
  have hn := nat_pos x x.size q 2 1 maxLineBytes (Nat.le_refl _) hq
  simp only [Gate.blob, StateT.run_bind, hn]
  by_cases h2 : q + 2 ≤ x.size
  · rw [be2_toNat x q h2]
    by_cases h3 : 1 ≤ beNat ((x.toList.drop q).take 2) ∧ beNat ((x.toList.drop q).take 2) ≤ maxLineBytes
    · rw [if_pos ⟨h2, h3⟩]
      simp only [Option.bind_eq_bind, Option.bind_some]
      rw [take_pos x x.size (q + 2) _ (Nat.le_refl _) h2]
      by_cases h4 : q + 2 + beNat ((x.toList.drop q).take 2) ≤ x.size
      · rw [if_pos h4, if_pos ⟨h2, h3.1, h3.2, h4⟩]
      · rw [if_neg h4, if_neg (fun h => h4 h.2.2.2)]
    · rw [if_neg (fun h => h3 ⟨h.2.1, h.2.2⟩), if_neg (fun h => h3 ⟨h.2.1, h.2.2.1⟩)]; rfl
  · rw [if_neg (fun h => h2 h.1), if_neg (fun h => h2 h.1)]; rfl

private theorem ba_ext (a b : ByteArray) (h : a.toList = b.toList) : a = b := by
  rw [Bin.toList_eq', Bin.toList_eq'] at h
  exact ByteArray.ext (Array.toList_inj.mp h)

private abbrev SL (x : ByteArray) (q : Nat) : Bytes := (x.toList.take x.size).drop q

private abbrev LSt := Option (Option RowsReq) × Nat × Nat × Array ByteArray × Array LineRow

private abbrev lineStep (x : ByteArray) (tag : UInt8) (ye ee : Nat) (payW : UInt64) (ruled : Prop) [Decidable ruled] (_i : Nat) (s : LSt) :
    Id (ForInStep LSt) :=
  if x.size < s.2.1 + 2 then pure (.done (some none, s.2))
  else if ((be2 x s.2.1).toNat == 0 || decide (569 < (be2 x s.2.1).toNat) ||
      decide (x.size < s.2.1 + 2 + (be2 x s.2.1).toNat)) = true then pure (.done (some none, s.2))
  else match lineRow x (s.2.1 + 2) (s.2.1 + 2 + (be2 x s.2.1).toNat) tag ye (ye + 34) (ee - ye - 34) payW with
    | some r => if ruled then pure (.yield (none, s.2.1 + 2 + (be2 x s.2.1).toNat, s.2.2.1 + r.cents.toNat,
          s.2.2.2.1.push (x.extract (s.2.1 + 2) (s.2.1 + 2 + (be2 x s.2.1).toNat)), s.2.2.2.2.push r))
        else pure (.yield (none, s.2.1 + 2 + (be2 x s.2.1).toNat, s.2.2.1 + r.cents.toNat,
          s.2.2.2.1.push (x.extract (s.2.1 + 2) (s.2.1 + 2 + (be2 x s.2.1).toNat)), s.2.2.2.2))
    | none => pure (.done (some none, s.2))

private theorem lineLoop (x : ByteArray) (tag : UInt8) (ye ee : Nat) (payW : UInt64) (ruled : Prop) [Decidable ruled]
    (hy : ye + 32 ≤ x.size) (hee : ye + 35 ≤ ee) (hex : ee ≤ x.size) (ht1 : 1 ≤ tag.toNat) (ht5 : tag.toNat ≤ 5) :
    ∀ (k s q sum : Nat) (lines : Array ByteArray) (rows : Array LineRow) (R : LSt), q ≤ x.size →
      Id.run (forIn (List.range' s k) ((none : Option (Option RowsReq)), q, sum, lines, rows)
        (lineStep x tag ye ee payW ruled)) = R →
      (R.1 = none ∧ ∃ ls ws q', (Gate.many (Gate.blob 1 maxLineBytes) k).run (SL x q) = some (ls, SL x q') ∧
          ls.filterMap (parse pLine maxLineBytes) = ws ∧ ws.length = ls.length ∧
          ws.all (fun w => w.flow == flows.getD (tag.toNat - 1) .FFS_CYCLE && w.memberKey == (x.toList.drop ye).take 32 &&
            w.payeeRef == (x.toList.drop (ye + 34)).take (ee - ye - 34)) = true ∧
          R.2.1 = q' ∧ q' ≤ x.size ∧ R.2.2.1 = ws.foldl (fun a w => a + w.cents) sum ∧
          R.2.2.2.1.toList = lines.toList ++ ls.map List.toByteArray) ∨
      (R.1 = some none ∧ ¬ ∃ ls q', (Gate.many (Gate.blob 1 maxLineBytes) k).run (SL x q) = some (ls, SL x q') ∧
          (ls.filterMap (parse pLine maxLineBytes)).length = ls.length ∧
          (ls.filterMap (parse pLine maxLineBytes)).all (fun w => w.flow == flows.getD (tag.toNat - 1) .FFS_CYCLE &&
            w.memberKey == (x.toList.drop ye).take 32 && w.payeeRef == (x.toList.drop (ye + 34)).take (ee - ye - 34)) = true) := by
  intro k
  induction k with
  | zero =>
    intro s q sum lines rows R hq hR
    simp only [List.range'_zero, List.forIn_nil, Id.run_pure] at hR
    subst hR
    left
    exact ⟨rfl, [], [], q, rfl, rfl, rfl, rfl, rfl, hq, rfl, by simp⟩
  | succ k ih =>
    intro s q sum lines rows R hq hR
    rw [List.range'_succ] at hR
    simp only [Id.run, List.forIn_cons, lineStep] at hR
    have hL : x.toList.length = x.size := (Bin.size_eq_length' x).symm
    -- the first blob fails: the spec reader fails the same way
    have failBlob : ¬ (q + 2 ≤ x.size ∧ 1 ≤ (be2 x q).toNat ∧ (be2 x q).toNat ≤ 569 ∧ q + 2 + (be2 x q).toNat ≤ x.size) →
        ¬ ∃ ls q', (Gate.many (Gate.blob 1 maxLineBytes) (k + 1)).run (SL x q) = some (ls, SL x q') ∧
          (ls.filterMap (parse pLine maxLineBytes)).length = ls.length ∧
          (ls.filterMap (parse pLine maxLineBytes)).all (fun w => w.flow == flows.getD (tag.toNat - 1) .FFS_CYCLE &&
            w.memberKey == (x.toList.drop ye).take 32 && w.payeeRef == (x.toList.drop (ye + 34)).take (ee - ye - 34)) = true := by
      intro hc ⟨ls, q', hm, _⟩
      rw [many_succ, blob_run x q hq, if_neg hc] at hm
      simp at hm
    by_cases hA : x.size < q + 2
    · simp only [hA, ↓reduceIte, pure_bind] at hR
      subst hR
      exact Or.inr ⟨rfl, failBlob (by omega)⟩
    by_cases hB : ((be2 x q).toNat == 0 || decide (569 < (be2 x q).toNat) || decide (x.size < q + 2 + (be2 x q).toNat)) = true
    · simp only [hA, hB, ↓reduceIte, pure_bind] at hR
      subst hR
      refine Or.inr ⟨rfl, failBlob ?_⟩
      simp only [Bool.or_eq_true, beq_iff_eq, decide_eq_true_eq] at hB
      omega
    have hB' : 1 ≤ (be2 x q).toNat ∧ (be2 x q).toNat ≤ 569 ∧ q + 2 + (be2 x q).toNat ≤ x.size := by
      simp only [Bool.or_eq_true, beq_iff_eq, decide_eq_true_eq] at hB
      omega
    obtain ⟨ln, hln⟩ : ∃ ln, (be2 x q).toNat = ln := ⟨_, rfl⟩
    rw [hln] at hB' hR hB
    have hblob : (Gate.blob 1 maxLineBytes).run (SL x q) =
        some ((x.toList.drop (q + 2)).take ln, SL x (q + 2 + ln)) := by
      rw [blob_run x q hq, hln, if_pos ⟨by omega, hB'.1, hB'.2.1, hB'.2.2⟩]
    have hlenl : ((x.toList.drop (q + 2)).take ln).length = ln := len_slice _ _ _ (by omega)
    have hdt : (x.toList.take (q + 2 + ln)).drop (q + 2) = (x.toList.drop (q + 2)).take ln := by
      rw [List.drop_take]; congr 1; omega
    simp only [hA, hB, ↓reduceIte, Bool.false_eq_true, pure_bind] at hR
    rcases hl : lineRow x (q + 2) (q + 2 + ln) tag ye (ye + 34) (ee - ye - 34) payW with _ | r
    · rw [hl] at hR
      simp only [pure_bind] at hR
      subst hR
      refine Or.inr ⟨rfl, ?_⟩
      rintro ⟨ls, q', hm, hlen, hall⟩
      rw [many_succ, hblob] at hm
      simp only [Option.bind_some, Option.map_eq_some_iff, Prod.mk.injEq] at hm
      obtain ⟨⟨ls', q''⟩, hm', hls, -⟩ := hm
      rw [← hls] at hlen hall
      rcases hp : parse pLine maxLineBytes ((x.toList.drop (q + 2)).take ln) with _ | w0
      · rw [List.filterMap_cons_none hp] at hlen
        have := List.length_filterMap_le (parse pLine maxLineBytes) ls'
        simp at hlen; omega
      · rw [List.filterMap_cons_some hp] at hall
        simp only [List.all_cons, Bool.and_eq_true, beq_iff_eq] at hall
        have hpr := parse_some hp
        rw [← hdt] at hpr
        obtain ⟨r', hr'⟩ := lineRow_some (x := x) (p := q + 2) (e := q + 2 + ln) (tag := tag) (mem := ye) (ps := ye + 34)
          (pn := ee - ye - 34) (payW := payW) (w := w0) (by omega) (by omega) hy (by omega) ht1 ht5 hpr
          hall.1.1.1 hall.1.1.2 hall.1.2
        rw [hl] at hr'; cases hr'
    · rw [hl] at hR
      obtain ⟨rows', hR⟩ : ∃ rows', Id.run (forIn (List.range' (s + 1) k) ((none : Option (Option RowsReq)),
          q + 2 + ln, sum + r.cents.toNat, lines.push (x.extract (q + 2) (q + 2 + ln)), rows')
          (lineStep x tag ye ee payW ruled)) = R := by
        by_cases hrl : ruled
        · simp only [if_pos hrl, pure_bind] at hR; exact ⟨_, hR⟩
        · simp only [if_neg hrl, pure_bind] at hR; exact ⟨_, hR⟩
      have hspec := lineRow_spec (x := x) (p := q + 2) (e := q + 2 + ln) (tag := tag) (mem := ye) (ps := ye + 34)
        (pn := ee - ye - 34) (payW := payW) (r := r) (by omega) hy (by omega) ht1 ht5 hl
      have hp : parse pLine maxLineBytes ((x.toList.drop (q + 2)).take ln) = some
          ⟨flows.getD (tag.toNat - 1) .FFS_CYCLE, (x.toList.drop ye).take 32, (x.toList.drop (ye + 34)).take (ee - ye - 34),
            r.cents.toNat⟩ := by
        unfold parse
        rw [if_neg (by rw [hlenl]; unfold maxLineBytes; omega), ← hdt, hspec]
      have hext : x.extract (q + 2) (q + 2 + ln) = ((x.toList.drop (q + 2)).take ln).toByteArray :=
        ba_ext _ _ (by rw [Bin.toList_extract', Bin.toList_toByteArray, show q + 2 + ln - (q + 2) = ln by omega])
      rcases ih (s + 1) (q + 2 + ln) _ _ _ R (by omega) hR with
        ⟨hfl, ls', ws', q'', hm', hf', hlen', hall', hq1, hq2, hsum, hlines⟩ | ⟨hfl, hnot⟩
      · refine Or.inl ⟨hfl, ((x.toList.drop (q + 2)).take ln) :: ls', (⟨flows.getD (tag.toNat - 1) .FFS_CYCLE, (x.toList.drop ye).take 32, (x.toList.drop (ye + 34)).take (ee - ye - 34), r.cents.toNat⟩ : WireLine) :: ws', q'', ?_, ?_, ?_, ?_, hq1, hq2, ?_, ?_⟩
        · rw [many_succ, hblob]
          simp only [Option.bind_some, hm', Option.map_some]
        · rw [List.filterMap_cons_some hp, hf']
        · simp [hlen']
        · simp only [List.all_cons, Bool.and_eq_true, beq_self_eq_true, Bool.true_and, hall']
        · rw [hsum, List.foldl_cons]
        · rw [hlines, hext]; simp
      · refine Or.inr ⟨hfl, ?_⟩
        rintro ⟨ls, q', hm, hlen, hall⟩
        rw [many_succ, hblob] at hm
        simp only [Option.bind_some, Option.map_eq_some_iff, Prod.mk.injEq] at hm
        obtain ⟨⟨ls', q''⟩, hm', hls, hq⟩ := hm
        simp only at hm' hls hq
        subst hls hq
        rw [List.filterMap_cons_some hp] at hlen hall
        simp only [List.length_cons, Nat.add_right_cancel_iff, List.all_cons, Bool.and_eq_true] at hlen hall
        exact hnot ⟨ls', q', hm', hlen, hall.2⟩

private abbrev ESt := Option (Option RowsReq) × Nat × Array ByteArray

private def evStep (x : ByteArray) (i : Nat) (s : ESt) : Id (ForInStep ESt) :=
  if (decide (0 < i) && !lt64 x (s.2.1 - 64) s.2.1 0) = true then pure (.done (some none, s.2))
  else pure (.yield (none, s.2.1 + 64, s.2.2.push (x.extract s.2.1 (s.2.1 + 64))))

private theorem digest_run (x : ByteArray) (q : Nat) (h : q + 64 ≤ x.size) :
    Gate.digest.run (SL x q) = some ((x.toList.drop q).take 64, SL x (q + 64)) := by
  have := take_pos x x.size q 64 (Nat.le_refl _) (by omega)
  unfold Gate.digest; unfold digestBytes
  rw [this, if_pos h]

private theorem evLoop (x : ByteArray) :
    ∀ (k s q : Nat) (evid : Array ByteArray) (R : ESt), q + 64 * k ≤ x.size → (s = 0 ∨ 64 ≤ q) →
      Id.run (forIn (List.range' s k) ((none : Option (Option RowsReq)), q, evid) (evStep x)) = R →
      (R.1 = none ∧ ∃ rs, (Gate.many Gate.digest k).run (SL x q) = some (rs, SL x (q + 64 * k)) ∧
          ascending ((if s = 0 then [] else [(x.toList.drop (q - 64)).take 64]) ++ rs) = true ∧
          R.2.1 = q + 64 * k ∧ R.2.2.toList = evid.toList ++ rs.map List.toByteArray) ∨
      (R.1 = some none ∧ ¬ ∃ rs q', (Gate.many Gate.digest k).run (SL x q) = some (rs, SL x q') ∧
          ascending ((if s = 0 then [] else [(x.toList.drop (q - 64)).take 64]) ++ rs) = true) := by
  intro k
  induction k with
  | zero =>
    intro s q evid R hq hs hR
    simp only [List.range'_zero, List.forIn_nil, Id.run_pure] at hR
    subst hR
    left
    refine ⟨rfl, [], rfl, ?_, by simp, by simp⟩
    split <;> simp [ascending]
  | succ k ih =>
    intro s q evid R hq hs hR
    rw [List.range'_succ] at hR
    simp only [Id.run, List.forIn_cons, evStep] at hR
    have hdg := digest_run x q (by omega)
    have hext : x.extract q (q + 64) = ((x.toList.drop q).take 64).toByteArray :=
      ba_ext _ _ (by rw [Bin.toList_extract', Bin.toList_toByteArray, show q + 64 - q = 64 by omega])
    have hmany : ∀ rs' : List Bytes, (Gate.many Gate.digest (k + 1)).run (SL x q) =
        ((Gate.many Gate.digest k).run (SL x (q + 64))).map fun b => ((x.toList.drop q).take 64 :: b.1, b.2) := by
      intro _; rw [many_succ, hdg]; rfl
    by_cases hc : (decide (0 < s) && !lt64 x (q - 64) q 0) = true
    · simp only [hc, ↓reduceIte, pure_bind] at hR
      subst hR
      refine Or.inr ⟨rfl, ?_⟩
      rintro ⟨rs, q', hm, hasc⟩
      rw [hmany []] at hm
      simp only [Option.map_eq_some_iff, Prod.mk.injEq] at hm
      obtain ⟨⟨rs', q''⟩, hm', hrs, -⟩ := hm
      simp only [Bool.and_eq_true, decide_eq_true_eq, Bool.not_eq_true'] at hc
      have hs0 : s ≠ 0 := by omega
      rw [← hrs, if_neg hs0] at hasc
      simp only [List.singleton_append, ascending, Bool.and_eq_true] at hasc
      have h64 := lt64_eq x (q - 64) q (by omega) (by omega) 0 (by omega)
      simp only [Nat.mul_zero, Nat.add_zero, Nat.sub_zero] at h64
      rw [h64] at hc
      rw [hc.2] at hasc
      exact absurd hasc.1 (by simp)
    · have hlt : s ≠ 0 → lexLt ((x.toList.drop (q - 64)).take 64) ((x.toList.drop q).take 64) = true := by
        intro s0
        have h64 := lt64_eq x (q - 64) q (by omega) (by omega) 0 (by omega)
        simp only [Nat.mul_zero, Nat.add_zero, Nat.sub_zero] at h64
        have : lt64 x (q - 64) q 0 = true := by
          cases hb : lt64 x (q - 64) q 0
          · exact absurd (by simp [hb, Nat.pos_of_ne_zero s0]) hc
          · rfl
        rw [h64] at this; exact this
      have hiff : ∀ rs' : List Bytes, ascending ((if s = 0 then [] else [(x.toList.drop (q - 64)).take 64]) ++
          (x.toList.drop q).take 64 :: rs') = true ↔ ascending ((x.toList.drop q).take 64 :: rs') = true := by
        intro rs'
        by_cases s0 : s = 0
        · simp [s0]
        · simp [s0, ascending, hlt s0]
      simp only [hc, Bool.false_eq_true, ↓reduceIte, pure_bind] at hR
      rcases ih (s + 1) (q + 64) _ R (by omega) (Or.inr (by omega)) hR with
        ⟨hfl, rs', hm', hasc', hq1, hlines⟩ | ⟨hfl, hnot⟩
      · have hasc'' : ascending ((x.toList.drop q).take 64 :: rs') = true := by simpa using hasc'
        refine Or.inl ⟨hfl, (x.toList.drop q).take 64 :: rs', ?_, (hiff rs').mpr hasc'', by rw [hq1]; omega, ?_⟩
        · rw [hmany [], hm']; simp only [Option.map_some]
          rw [show q + 64 * (k + 1) = q + 64 + 64 * k by omega]
        · rw [hlines, hext]; simp
      · refine Or.inr ⟨hfl, ?_⟩
        rintro ⟨rs, q', hm, hasc⟩
        rw [hmany []] at hm
        simp only [Option.map_eq_some_iff, Prod.mk.injEq] at hm
        obtain ⟨⟨rs', q''⟩, hm', hrs, hq⟩ := hm
        simp only at hm' hrs hq
        subst hrs hq
        refine hnot ⟨rs', q', hm', ?_⟩
        have := (hiff rs').mp hasc
        simpa using this

private theorem expect_run (x : ByteArray) (d : Bytes) :
    (Gate.expect d).run (SL x 0) =
      if d.length ≤ x.size ∧ (x.toList.take d.length = d) then some ((), SL x d.length) else none := by
  have h := take_pos x x.size 0 d.length (Nat.le_refl _) (Nat.zero_le _)
  simp only [Gate.expect, StateT.run_bind]
  rw [h]
  by_cases h1 : d.length ≤ x.size
  · rw [if_pos (by omega : 0 + d.length ≤ x.size)]
    simp only [Option.bind_eq_bind, Option.bind_some, List.drop_zero, Nat.zero_add, need_run']
    by_cases h2 : x.toList.take d.length = d
    · simp [h1, h2, SL]
    · simp [h1, h2]
  · rw [if_neg (by omega : ¬ 0 + d.length ≤ x.size), if_neg (fun h => h1 h.1)]; rfl

private theorem tag_run (x : ByteArray) (p : Nat) (hp : p ≤ x.size) :
    (Gate.tag flows).run (SL x p) =
      if p + 1 ≤ x.size ∧ 1 ≤ (x.get! p).toNat ∧ (x.get! p).toNat ≤ 5
      then some (flows.getD ((x.get! p).toNat - 1) .FFS_CYCLE, SL x (p + 1)) else none := by
  have hL : x.toList.length = x.size := (Bin.size_eq_length' x).symm
  have hfl : flows.length = 5 := rfl
  have h := nat_pos x x.size p 1 1 flows.length (Nat.le_refl _) hp
  rw [hfl] at h
  simp only [Gate.tag, StateT.run_bind, h, hfl]
  by_cases h1 : p + 1 ≤ x.size
  · have hb := beNat_one x p (by omega)
    rw [hb]
    by_cases h2 : 1 ≤ (x.get! p).toNat ∧ (x.get! p).toNat ≤ 5
    · rw [if_pos ⟨h1, h2⟩, if_pos ⟨h1, h2⟩]
      simp only [Option.bind_eq_bind, Option.bind_some]
      rw [flows_get _ (by omega)]
      rfl
    · rw [if_neg (fun h => h2 ⟨h.2.1, h.2.2⟩), if_neg (fun h => h2 ⟨h.2.1, h.2.2⟩)]; rfl
  · rw [if_neg (fun h => h1 h.1), if_neg (fun h => h1 h.1)]; rfl

private theorem ident_none' {x : ByteArray} {p e : Nat} (he : e = identEnd x p x.size) (h0 : e = 0) :
    Gate.ident.run (SL x p) = none := by
  rw [ident_run x p x.size (Nat.le_refl _), ← he, if_pos h0]

private theorem ident_some' {x : ByteArray} {p e : Nat} (he : e = identEnd x p x.size) (h0 : e ≠ 0) :
    Gate.ident.run (SL x p) = some ((x.toList.drop (p + 2)).take (e - (p + 2)), SL x e) := by
  rw [ident_run x p x.size (Nat.le_refl _), ← he, if_neg h0]

private theorem ib {x : ByteArray} {p e : Nat} (he : e = identEnd x p x.size) (h : e ≠ 0) : p + 3 ≤ e ∧ e ≤ x.size := by
  subst he; exact identEnd_bounds h

private theorem dom_iff (x : ByteArray) (dn : Nat) (hdn : dn = requestDomain.size) (h1 : dn ≤ x.size) :
    sameBytes x requestDomain 0 0 dn = true ↔ x.toList.take dn = domain "DECIDE-REQUEST" := by
  have hrdl : requestDomain.toList = domain "DECIDE-REQUEST" := Bin.toList_toByteArray _
  have hdnl : dn = (domain "DECIDE-REQUEST").length := by
    rw [hdn, Bin.size_eq_length', hrdl]
  rw [sameBytes_eq x requestDomain dn 0 0 (by omega) (by omega)]
  simp only [List.drop_zero, hrdl, decide_eq_true_eq]
  constructor
  · intro h; rw [h, hdnl, List.take_length]
  · intro h; rw [h, hdnl, List.take_length]

private theorem u8_c2 (t : UInt8) : (t == 0 || decide (5 < t)) = true ↔ (t.toNat = 0 ∨ 5 < t.toNat) := by
  simp only [Bool.or_eq_true, beq_iff_eq, decide_eq_true_eq, UInt8.lt_iff_toNat_lt]
  constructor
  · rintro (h | h)
    · left; rw [h]; rfl
    · right; exact h
  · rintro (h | h)
    · left; exact UInt8.toNat_inj.mp (by simpa using h)
    · right; exact h

private theorem u64_gt (a : UInt64) : 9223372036854775807 < a ↔ maxNat < a.toNat := by
  rw [UInt64.lt_iff_toNat_lt]
  have : maxNat = (9223372036854775807 : UInt64).toNat := by decide
  rw [this]

private theorem ruled_iff (t : Nat) (h1 : 1 ≤ t) (h5 : t ≤ 5) : (flows.getD (t - 1) .FFS_CYCLE).ruled = true ↔ t ≤ 3 := by
  match t, h1, h5 with
  | 1, _, _ => decide
  | 2, _, _ => decide
  | 3, _, _ => decide
  | 4, _, _ => decide
  | 5, _, _ => decide

private theorem be2_lt (b : ByteArray) (p : Nat) (h : p + 2 ≤ b.size) : (be2 b p).toNat < 65536 := by
  have hL : b.toList.length = b.size := (Bin.size_eq_length' b).symm
  rw [be2_toNat b p h, beNat_slice _ p 1 (by omega), beNat_slice _ (p + 1) 0 (by omega)]
  have h1 := UInt8.toNat_lt (b.toList[p]'(by omega))
  have h2 := UInt8.toNat_lt (b.toList[p + 1]'(by omega))
  simp only [List.take_zero, beNat, List.foldl_nil, Nat.reducePow]
  omega

private theorem many_len {α : Type} (p : Gate.P α) : ∀ (k : Nat) (s s' : Bytes) (ls : List α),
    (Gate.many p k).run s = some (ls, s') → ls.length = k := by
  intro k
  induction k with
  | zero =>
    intro s s' ls h
    simp only [Gate.many, StateT.run_pure, Option.pure_def, Option.some.injEq, Prod.mk.injEq] at h
    rw [← h.1]; rfl
  | succ k ih =>
    intro s s' ls h
    rw [many_succ] at h
    rcases hp : p.run s with _ | ⟨a, t⟩
    · rw [hp] at h; simp at h
    · rw [hp] at h
      simp only [Option.bind_some, Option.map_eq_some_iff, Prod.mk.injEq] at h
      obtain ⟨⟨b1, b2⟩, hm, hl, -⟩ := h
      simp only at hl hm
      rw [← hl]; simp [ih _ _ _ hm]

private theorem many_state (x : ByteArray) : ∀ (k q : Nat) (ls : List Bytes) (s' : Bytes), q ≤ x.size →
    (Gate.many (Gate.blob 1 maxLineBytes) k).run (SL x q) = some (ls, s') → ∃ q', s' = SL x q' := by
  intro k
  induction k with
  | zero =>
    intro q ls s' hq h
    simp only [Gate.many, StateT.run_pure, Option.pure_def, Option.some.injEq, Prod.mk.injEq] at h
    exact ⟨q, h.2.symm⟩
  | succ k ih =>
    intro q ls s' hq h
    rw [many_succ, blob_run x q hq] at h
    by_cases hc : q + 2 ≤ x.size ∧ 1 ≤ (be2 x q).toNat ∧ (be2 x q).toNat ≤ 569 ∧ q + 2 + (be2 x q).toNat ≤ x.size
    · rw [if_pos hc] at h
      simp only [Option.bind_some, Option.map_eq_some_iff, Prod.mk.injEq] at h
      obtain ⟨⟨b1, b2⟩, hm, -, hs⟩ := h
      simp only at hm hs
      obtain ⟨q', hq'⟩ := ih (q + 2 + (be2 x q).toNat) b1 b2 (by omega) hm
      exact ⟨q', by rw [← hs, hq']⟩
    · rw [if_neg hc] at h; simp at h

private theorem many_digest_ok (x : ByteArray) : ∀ (k q : Nat), q + 64 * k ≤ x.size →
    ∃ rs, (Gate.many Gate.digest k).run (SL x q) = some (rs, SL x (q + 64 * k)) := by
  intro k
  induction k with
  | zero => intro q _; exact ⟨[], by simp [Gate.many]⟩
  | succ k ih =>
    intro q hq
    obtain ⟨rs, hrs⟩ := ih (q + 64) (by omega)
    refine ⟨(x.toList.drop q).take 64 :: rs, ?_⟩
    rw [many_succ, digest_run x q (by omega)]
    simp only [Option.bind_some, hrs, Option.map_some]
    rw [show q + 64 + 64 * k = q + 64 * (k + 1) by omega]

private theorem many_digest_none (x : ByteArray) : ∀ (k q : Nat), q ≤ x.size → x.size < q + 64 * k →
    (Gate.many Gate.digest k).run (SL x q) = none := by
  intro k
  induction k with
  | zero => intro q h1 h2; omega
  | succ k ih =>
    intro q h1 h2
    rw [many_succ]
    by_cases hc : q + 64 ≤ x.size
    · rw [digest_run x q hc]; simp only [Option.bind_some]
      rw [ih (q + 64) hc (by omega)]; rfl
    · have hd : Gate.digest.run (SL x q) = none := by
        unfold Gate.digest; unfold digestBytes
        rw [take_pos x x.size q 64 (Nat.le_refl _) h1, if_neg hc]
      rw [hd]; rfl

private theorem cond78' (r : Prop) [Decidable r] (nl s a : Nat) :
    (decide r && nl == 0 || nl != 0 && s != a) = false ↔
      ((nl == 0 || s == a) = true ∧ (!decide r || !(nl == 0)) = true) := by
  by_cases hr : r <;> by_cases h0 : nl = 0 <;> by_cases hs : s = a <;> simp [hr, h0, hs]

private theorem SL_nil (x : ByteArray) (q : Nat) : SL x q = [] ↔ x.size ≤ q := by
  have hL : x.toList.length = x.size := (Bin.size_eq_length' x).symm
  unfold SL; rw [List.drop_eq_nil_iff, List.length_take]; omega

private theorem ex_eq (x : ByteArray) (a b t : Nat) (h : b - a = t) : x.extract a b = ((x.toList.drop a).take t).toByteArray :=
  ba_ext _ _ (by rw [Bin.toList_extract', Bin.toList_toByteArray, h])

private theorem identEnd_key {b : ByteArray} {p lim : Nat} (h : identEnd b p lim ≠ 0) :
    identEnd b p lim = p + 2 + ((b.get! p).toNat * 256 + (b.get! (p + 1)).toNat) := by
  unfold identEnd at *
  split at h
  · exact absurd rfl h
  · rename_i h1
    rw [if_neg h1]
    simp only at h ⊢
    split at h
    · exact absurd rfl h
    · rename_i h2
      rw [if_neg h2]

private theorem identEnd_field {b : ByteArray} {p : Nat} (h : identEnd b p b.size ≠ 0) :
    (b.toList.drop p).take (identEnd b p b.size - p) =
      identField ((b.toList.drop (p + 2)).take (identEnd b p b.size - (p + 2))) := by
  have hb := identEnd_bounds h
  have hL : b.toList.length = b.size := (Bin.size_eq_length' b).symm
  have key := identEnd_key h
  have g0 := get!_lt b p (by omega)
  have g1 := get!_lt b (p + 1) (by omega)
  rw [g0, g1] at key
  have hlo := UInt8.toNat_lt b.toList[p + 1]
  have hhi := UInt8.toNat_lt b.toList[p]
  have hp0 : p < b.toList.length := by omega
  have hp1 : p + 1 < b.toList.length := by omega
  have hs : b.toList.drop p = b.toList[p] :: b.toList[p + 1] :: b.toList.drop (p + 2) := by
    rw [List.drop_eq_getElem_cons hp0, List.drop_eq_getElem_cons hp1]
  obtain ⟨n, hn⟩ : ∃ n, n = b.toList[p].toNat * 256 + b.toList[p + 1].toNat := ⟨_, rfl⟩
  rw [← hn] at key
  have hnb : natBE 2 n = [b.toList[p], b.toList[p + 1]] := by
    have e : natBE 2 n = [UInt8.ofNat (n / 256 ^ 1 % 256), UInt8.ofNat (n / 256 ^ 0 % 256)] := by
      unfold natBE; rfl
    rw [e]
    simp only [Nat.pow_one, Nat.pow_zero, Nat.div_one]
    have e1 : n / 256 % 256 = b.toList[p].toNat := by omega
    have e2 : n % 256 = b.toList[p + 1].toNat := by omega
    rw [e1, e2]
    simp
  rw [key]
  have hlen : ((b.toList.drop (p + 2)).take n).length = n := by
    simp only [List.length_take, List.length_drop]; omega
  rw [show p + 2 + n - p = 2 + n by omega, show p + 2 + n - (p + 2) = n by omega, List.take_add]
  unfold identField
  rw [hlen, hnb, List.drop_drop, hs]
  simp only [List.take_succ_cons, List.take_zero]
  try (congr 3; omega)

private theorem idNatA_eq (b : ByteArray) : idNatA b = idNat b.toList := by
  have hL : b.toList.length = b.size := (Bin.size_eq_length' b).symm
  unfold idNatA idNat
  rw [beNatA_eq b 0 b.size 1 (Nat.le_refl _) (Nat.zero_le _), beNat_cons]
  simp only [Nat.sub_zero, List.drop_zero]
  have ht : b.toList.take b.size = b.toList := by rw [← hL]; exact List.take_length
  rw [ht, hL]
  simp

private theorem payKey_idNat (x : ByteArray) (te ge ce ye : Nat) (h1 : ge = identEnd x te x.size)
    (h2 : ye = identEnd x ce x.size) (h1' : ge ≠ 0) (h2' : ye ≠ 0) :
    idNatA (x.copySlice ce (x.extract te ge) (ge - te) (ye - ce)) =
      payNat ((x.toList.drop (te + 2)).take (ge - (te + 2))) ((x.toList.drop (ce + 2)).take (ye - (ce + 2))) := by
  have hL : x.toList.length = x.size := (Bin.size_eq_length' x).symm
  have b1 := ib h1 h1'
  have b2 := ib h2 h2'
  have f1 := identEnd_field (b := x) (p := te) (by rw [← h1]; exact h1')
  have f2 := identEnd_field (b := x) (p := ce) (by rw [← h2]; exact h2')
  rw [← h1] at f1
  rw [← h2] at f2
  have hd : ge - te = (x.extract te ge).size := by
    rw [Bin.size_eq_length', Bin.toList_extract']
    simp only [List.length_take, List.length_drop]; omega
  rw [idNatA_eq, copySlice_toList x _ ce (ge - te) (ye - ce) hd, Bin.toList_extract', f1, f2]
  rfl

/-- The links to the byte-list reader (proofs owed): the request and payment number, the rules' lines, the rows. -/
theorem decodeRows_eq (x : ByteArray) :
    (decodeRows x).map (fun d => (d.ra, idNatA d.payKey)) =
      (decodeRequest x.toList).map fun r => (RequestBA.ofModel r, payNat r.programId r.paymentId) := by
  have hL : x.toList.length = x.size := (Bin.size_eq_length' x).symm
  have hS0 : x.toList = SL x 0 := by
    show x.toList = (x.toList.take x.size).drop 0
    rw [List.drop_zero, List.take_of_length_le (by omega)]
  have hlen0 : (SL x 0).length = x.size := by simp [SL, hL]
  unfold decodeRows
  extract_lets n dn te ge tag ce ye ee amount ke nl payKey payW ruled q0 sum0 lines0 rows0
  have hn : n = x.size := rfl
  have hdn : dn = requestDomain.size := rfl
  have hte : te = identEnd x dn n := rfl
  have hge : ge = identEnd x te n := rfl
  have htag : tag = x.get! ge := rfl
  have hce : ce = identEnd x (ge + 1) n := rfl
  have hye : ye = identEnd x ce n := rfl
  have hee : ee = identEnd x (ye + 32) n := rfl
  have hamount : amount = be8 x ee := rfl
  have hke : ke = identEnd x (ee + 8) n := rfl
  have hnl : nl = (be2 x ke).toNat := rfl
  have hpayKey : payKey = x.copySlice ce (x.extract te ge) (ge - te) (ye - ce) := rfl
  have hpayW : payW = wordOf payKey 0 payKey.size 0 := rfl
  have hq0 : q0 = ke + 2 := rfl
  have hsum0 : sum0 = 0 := rfl
  have hlines0 : lines0 = Array.mkEmpty nl := rfl
  have hrows0 : rows0 = Array.mkEmpty (if ruled then nl else 0) := rfl
  clear_value rows0 lines0 sum0 q0 payW payKey nl ke amount ee ye ce tag ge te dn n
  subst hn
  rw [hS0]
  unfold decodeRequest parse
  simp only [pRequest, StateT.run_bind]
  rw [hlen0]
  have hdnl : dn = (domain "DECIDE-REQUEST").length := by
    rw [hdn, Bin.size_eq_length']; simp [requestDomain, Bin.toList_toByteArray]
  by_cases hmax : maxRequestBytes < x.size
  · rw [if_pos (show (decide (maxRequestBytes < x.size) || decide (x.size < dn) || !sameBytes x requestDomain 0 0 dn) = true by simp [hmax]),
      if_pos (show x.size > maxRequestBytes from hmax)]
    rfl
  rw [if_neg (show ¬ (x.size > maxRequestBytes) by omega)]
  rw [expect_run, ← hdnl]
  by_cases hdom : dn ≤ x.size ∧ x.toList.take dn = domain "DECIDE-REQUEST"
  case neg =>
    have : (decide (maxRequestBytes < x.size) || decide (x.size < dn) || !sameBytes x requestDomain 0 0 dn) = true := by
        by_cases h1 : dn ≤ x.size
        · have h2 := dom_iff x dn hdn h1
          have : sameBytes x requestDomain 0 0 dn = false := by
            cases hb : sameBytes x requestDomain 0 0 dn
            · rfl
            · exact absurd ⟨h1, h2.mp hb⟩ hdom
          simp [this]
        · simp; omega
    rw [if_pos this, if_neg hdom]; rfl
  rw [if_neg (show ¬ ((decide (maxRequestBytes < x.size) || decide (x.size < dn) || !sameBytes x requestDomain 0 0 dn) = true) by
      have := (dom_iff x dn hdn hdom.1).mpr hdom.2
      simp [this, hmax]; omega), if_pos hdom]
  simp only [Option.bind_eq_bind, Option.bind_some]
  -- the first two identifiers and the tag
  by_cases hte0 : te = 0
  · rw [if_pos (show (te == 0 || ge == 0 || decide (x.size < ge + 1)) = true by simp [hte0]), ident_none' hte hte0]; rfl
  rw [ident_some' hte hte0]
  simp only [Option.bind_eq_bind, Option.bind_some]
  have hteb := ib hte hte0
  by_cases hge0 : ge = 0
  · rw [if_pos (show (te == 0 || ge == 0 || decide (x.size < ge + 1)) = true by simp [hge0]), ident_none' hge hge0]; rfl
  rw [ident_some' hge hge0]
  simp only [Option.bind_eq_bind, Option.bind_some]
  have hgeb := ib hge hge0
  rw [tag_run x ge (by omega), ← htag]
  by_cases htg : ge + 1 ≤ x.size ∧ 1 ≤ tag.toNat ∧ tag.toNat ≤ 5
  case neg =>
    by_cases hsz : x.size < ge + 1
    · rw [if_pos (show (te == 0 || ge == 0 || decide (x.size < ge + 1)) = true by simp [hsz]), if_neg htg]; rfl
    · rw [if_neg (show ¬ ((te == 0 || ge == 0 || decide (x.size < ge + 1)) = true) by simp [hte0, hge0, hsz]),
        if_pos ((u8_c2 tag).mpr (by omega)), if_neg htg]; rfl
  rw [if_pos htg]
  simp only [Option.bind_eq_bind, Option.bind_some]
  rw [if_neg (show ¬ ((te == 0 || ge == 0 || decide (x.size < ge + 1)) = true) by simp [hte0, hge0]; omega),
    if_neg (show ¬ ((tag == 0 || decide (5 < tag)) = true) from fun h => by have := (u8_c2 tag).mp h; omega)]
  -- command key, payment id, member key
  by_cases hce0 : ce = 0
  · rw [if_pos (show (ce == 0 || ye == 0 || decide (x.size < ye + 32)) = true by simp [hce0]), ident_none' hce hce0]; rfl
  rw [ident_some' hce hce0]
  simp only [Option.bind_eq_bind, Option.bind_some]
  have hceb := ib hce hce0
  by_cases hye0 : ye = 0
  · rw [if_pos (show (ce == 0 || ye == 0 || decide (x.size < ye + 32)) = true by simp [hye0]), ident_none' hye hye0]; rfl
  rw [ident_some' hye hye0]
  simp only [Option.bind_eq_bind, Option.bind_some]
  have hyeb := ib hye hye0
  by_cases hs3 : x.size < ye + 32
  · rw [if_pos (show (ce == 0 || ye == 0 || decide (x.size < ye + 32)) = true by simp [hs3]),
      take_pos x x.size ye memberKeyBytes (Nat.le_refl _) (by omega),
      if_neg (show ¬ (ye + memberKeyBytes ≤ x.size) by unfold memberKeyBytes; omega)]; rfl
  rw [if_neg (show ¬ ((ce == 0 || ye == 0 || decide (x.size < ye + 32)) = true) by simp [hce0, hye0, hs3]),
    take_ok (Nat.le_refl _) (show ye + memberKeyBytes ≤ x.size by unfold memberKeyBytes; omega)]
  simp only [Option.bind_eq_bind, Option.bind_some, memberKeyBytes]
  -- payee, amount
  by_cases hee0 : ee = 0
  · rw [if_pos (show (ee == 0 || decide (x.size < ee + 8)) = true by simp [hee0]), ident_none' hee hee0]; rfl
  rw [ident_some' hee hee0]
  simp only [Option.bind_eq_bind, Option.bind_some]
  have heeb := ib hee hee0
  rw [nat_pos x x.size ee 8 0 maxNat (Nat.le_refl _) heeb.2]
  by_cases hs4 : x.size < ee + 8
  · rw [if_pos (show (ee == 0 || decide (x.size < ee + 8)) = true by simp [hs4]),
      if_neg (show ¬ (ee + 8 ≤ x.size ∧ 0 ≤ beNat ((x.toList.drop ee).take 8) ∧ beNat ((x.toList.drop ee).take 8) ≤ maxNat) by omega)]; rfl
  rw [if_neg (show ¬ ((ee == 0 || decide (x.size < ee + 8)) = true) by simp [hee0, hs4])]
  have hbe : beNat ((x.toList.drop ee).take 8) = amount.toNat := by
    rw [hamount, be8_toNat x ee (by omega)]
  by_cases hamt : 9223372036854775807 < amount
  · rw [if_pos hamt,
      if_neg (show ¬ (ee + 8 ≤ x.size ∧ 0 ≤ beNat ((x.toList.drop ee).take 8) ∧ beNat ((x.toList.drop ee).take 8) ≤ maxNat) by
        rw [hbe]; have := (u64_gt amount).mp hamt; omega)]; rfl
  have hamt' : amount.toNat ≤ maxNat := Nat.le_of_not_lt (fun h => hamt ((u64_gt amount).mpr h))
  rw [if_neg hamt, if_pos (show ee + 8 ≤ x.size ∧ 0 ≤ beNat ((x.toList.drop ee).take 8) ∧ beNat ((x.toList.drop ee).take 8) ≤ maxNat from
    ⟨by omega, Nat.zero_le _, by rw [hbe]; exact hamt'⟩)]
  simp only [Option.bind_eq_bind, Option.bind_some]
  -- period and the line count
  by_cases hke0 : ke = 0
  · rw [if_pos (show (ke == 0 || decide (x.size < ke + 2)) = true by simp [hke0]), ident_none' hke hke0]; rfl
  rw [ident_some' hke hke0]
  simp only [Option.bind_eq_bind, Option.bind_some]
  have hkeb := ib hke hke0
  rw [nat_pos x x.size ke 2 0 maxLines (Nat.le_refl _) hkeb.2]
  by_cases hs6 : x.size < ke + 2
  · rw [if_pos (show (ke == 0 || decide (x.size < ke + 2)) = true by simp [hs6]),
      if_neg (show ¬ (ke + 2 ≤ x.size ∧ 0 ≤ beNat ((x.toList.drop ke).take 2) ∧ beNat ((x.toList.drop ke).take 2) ≤ maxLines) by omega)]; rfl
  rw [if_neg (show ¬ ((ke == 0 || decide (x.size < ke + 2)) = true) by simp [hke0, hs6])]
  have hnlb : beNat ((x.toList.drop ke).take 2) = nl := by rw [hnl, be2_toNat x ke (by omega)]
  have hnl16 : nl < 65536 := by
    rw [hnl]; exact be2_lt x ke (by omega)
  rw [if_pos (show ke + 2 ≤ x.size ∧ 0 ≤ beNat ((x.toList.drop ke).take 2) ∧ beNat ((x.toList.drop ke).take 2) ≤ maxLines from
    ⟨by omega, Nat.zero_le _, by rw [hnlb]; unfold maxLines; omega⟩), hnlb]
  simp only [Option.bind_eq_bind, Option.bind_some]
  subst hq0 hsum0 hlines0 hrows0
  simp only [Std.Legacy.Range.forIn_eq_forIn_range', Std.Legacy.Range.size, Nat.sub_zero, Nat.add_sub_cancel, Nat.div_one]
  rw [show ye + 32 + 2 = ye + 34 from rfl, show ee - (ye + 34) = ee - ye - 34 from by omega]
  letI hdec : Decidable ruled := inferInstanceAs (Decidable (tag ≤ 3))
  have ht1 : 1 ≤ tag.toNat := htg.2.1
  have ht5 : tag.toNat ≤ 5 := htg.2.2
  obtain ⟨R, hR⟩ : ∃ R, Id.run (forIn (List.range' 0 nl) ((none : Option (Option RowsReq)), ke + 2, (0 : Nat),
      (Array.mkEmpty nl : Array ByteArray), (Array.mkEmpty (if ruled then nl else 0) : Array LineRow))
      (lineStep x tag ye ee payW ruled)) = R := ⟨_, rfl⟩
  have hloop := lineLoop x tag ye ee payW ruled (by omega) (by omega) (by omega) ht1 ht5 nl 0 (ke + 2) 0
    (Array.mkEmpty nl) (Array.mkEmpty (if ruled then nl else 0)) R (by omega) hR
  have hR' : forIn (m := Id) (List.range' 0 nl) ((none : Option (Option RowsReq)), ke + 2, (0 : Nat),
      (Array.mkEmpty nl : Array ByteArray), (Array.mkEmpty (if ruled then nl else 0) : Array LineRow))
      (lineStep x tag ye ee payW ruled) = R := hR
  generalize hX : (forIn (m := Id) (List.range' 0 nl) ((none : Option (Option RowsReq)), ke + 2, (0 : Nat),
      (Array.mkEmpty nl : Array ByteArray), (Array.mkEmpty (if ruled then nl else 0) : Array LineRow)) _) = X
  have hXR : X = R := by
    rw [← hX]
    refine Eq.trans ?_ hR'
    congr 1
    funext i s
    unfold lineStep
    cases lineRow x (s.snd.fst + 2) (s.snd.fst + 2 + (be2 x s.snd.fst).toNat) tag ye (ye + 34) (ee - ye - 34) payW <;> rfl
  subst hXR
  rcases hloop with ⟨hfl, ls, ws, q', hm, hf, hlen, hall, hq1, hq2, hsum, hlines⟩ | ⟨hfl, hnot⟩
  case inr =>
    dsimp only [bind, Bind.bind, Id.run, pure, Pure.pure]
    rw [hfl]
    show Option.map _ (none : Option RowsReq) = _
    rw [Option.map_none]
    symm
    rw [Option.map_eq_none_iff]
    rcases hmr : (Gate.many (Gate.blob 1 maxLineBytes) nl).run (SL x (ke + 2)) with _ | ⟨ls, s'⟩
    · rfl
    · obtain ⟨q', hs'⟩ := many_state x nl (ke + 2) ls s' (by omega) hmr
      subst hs'
      simp only [Option.bind_some, need_run']
      by_cases h1 : ((ls.filterMap (parse pLine maxLineBytes)).length == ls.length) = true
      · by_cases h2 : ((ls.filterMap (parse pLine maxLineBytes)).all fun w => w.flow == flows.getD (tag.toNat - 1) .FFS_CYCLE &&
            w.memberKey == (x.toList.drop ye).take 32 && w.payeeRef == (x.toList.drop (ye + 34)).take (ee - ye - 34)) = true
        · exact absurd ⟨ls, q', hmr, by simpa using h1, h2⟩ hnot
        · simp only [h1, h2, if_true, if_false, Option.bind_some, Option.bind_none]
          try rfl
      · simp only [h1, if_true, if_false, Option.bind_some, Option.bind_none]
        try rfl
  case inl =>
    subst hf
    have hnl' : ls.length = nl := many_len _ nl _ _ _ hm
    have hE : ls.isEmpty = (nl == 0) := by rw [← hnl']; cases ls <;> simp
    have hrul : ruled ↔ tag.toNat ≤ 3 := by
      show tag ≤ 3 ↔ _
      rw [UInt8.le_iff_toNat_le]; rfl
    have hRb : (flows.getD (tag.toNat - 1) .FFS_CYCLE).ruled = decide ruled := by
      rw [Bool.eq_iff_iff, ruled_iff _ ht1 ht5, decide_eq_true_iff]; exact hrul.symm
    dsimp only [bind, Bind.bind, Id.run, pure, Pure.pure]
    rw [hfl]
    dsimp only
    rw [hq1, hsum, hlines]
    rw [hm]
    simp only [Option.bind_some, need_run']
    have hA : ((List.filterMap (parse pLine maxLineBytes) ls).length == ls.length) = true := by simp [hlen]
    simp only [hA, hall, if_true, Option.bind_some, hE, hbe, hRb]
    generalize hS : List.foldl (fun a (w : WireLine) => a + w.cents) 0 (List.filterMap (parse pLine maxLineBytes) ls) = sum
    have hcond := cond78' ruled nl sum amount.toNat
    by_cases h78 : (nl == 0 || sum == amount.toNat) = true ∧ (!decide ruled || !(nl == 0)) = true
    · have hc0 := hcond.mpr h78
      simp only [h78.1, h78.2, if_true, Option.bind_some]
      by_cases hsz : x.size < q' + 2
      · rw [if_pos (show (decide ruled && nl == 0 || nl != 0 && sum != amount.toNat || decide (x.size < q' + 2)) = true by simp [hc0, hsz]),
          nat_pos x x.size q' 2 0 maxEvidenceRefs (Nat.le_refl _) hq2,
          if_neg (show ¬ (q' + 2 ≤ x.size ∧ 0 ≤ beNat ((x.toList.drop q').take 2) ∧ beNat ((x.toList.drop q').take 2) ≤ maxEvidenceRefs) by omega)]
        rfl
      · have hecb := (be2_toNat x q' (by omega)).symm
        rw [if_neg (show ¬ ((decide ruled && nl == 0 || nl != 0 && sum != amount.toNat || decide (x.size < q' + 2)) = true) by simp [hc0, hsz])]
        by_cases hec : 256 < (be2 x q').toNat
        · rw [if_pos (show (decide (256 < (be2 x q').toNat) || decide (x.size < q' + 2 + 64 * (be2 x q').toNat)) = true by simp [hec]),
            nat_pos x x.size q' 2 0 maxEvidenceRefs (Nat.le_refl _) hq2,
            if_neg (show ¬ (q' + 2 ≤ x.size ∧ 0 ≤ beNat ((x.toList.drop q').take 2) ∧ beNat ((x.toList.drop q').take 2) ≤ maxEvidenceRefs) by unfold maxEvidenceRefs; omega)]
          rfl
        · by_cases hsz2 : x.size < q' + 2 + 64 * (be2 x q').toNat
          · rw [if_pos (show (decide (256 < (be2 x q').toNat) || decide (x.size < q' + 2 + 64 * (be2 x q').toNat)) = true by simp [hsz2]),
              nat_pos x x.size q' 2 0 maxEvidenceRefs (Nat.le_refl _) hq2,
              if_pos (show q' + 2 ≤ x.size ∧ 0 ≤ beNat ((x.toList.drop q').take 2) ∧ beNat ((x.toList.drop q').take 2) ≤ maxEvidenceRefs from ⟨by omega, Nat.zero_le _, by unfold maxEvidenceRefs; omega⟩)]
            simp only [Option.bind_some]
            rw [hecb, many_digest_none x (be2 x q').toNat (q' + 2) (by omega) (by omega)]
            rfl
          · rw [if_neg (show ¬ ((decide (256 < (be2 x q').toNat) || decide (x.size < q' + 2 + 64 * (be2 x q').toNat)) = true) by simp [hec, hsz2]),
              nat_pos x x.size q' 2 0 maxEvidenceRefs (Nat.le_refl _) hq2,
              if_pos (show q' + 2 ≤ x.size ∧ 0 ≤ beNat ((x.toList.drop q').take 2) ∧ beNat ((x.toList.drop q').take 2) ≤ maxEvidenceRefs from ⟨by omega, Nat.zero_le _, by unfold maxEvidenceRefs; omega⟩)]
            simp only [Option.bind_some]
            rw [hecb]
            obtain ⟨R2, hR2⟩ : ∃ R2, Id.run (forIn (List.range' 0 (be2 x q').toNat) ((none : Option (Option RowsReq)), q' + 2,
                (Array.mkEmpty (be2 x q').toNat : Array ByteArray)) (evStep x)) = R2 := ⟨_, rfl⟩
            have hev := evLoop x (be2 x q').toNat 0 (q' + 2) (Array.mkEmpty (be2 x q').toNat) R2 (by omega) (Or.inl rfl) hR2
            have hR2' : forIn (m := Id) (List.range' 0 (be2 x q').toNat) ((none : Option (Option RowsReq)), q' + 2,
                (Array.mkEmpty (be2 x q').toNat : Array ByteArray)) (evStep x) = R2 := hR2
            generalize hY : forIn (m := Id) (List.range' 0 (be2 x q').toNat) ((none : Option (Option RowsReq)), q' + 2,
                (Array.mkEmpty (be2 x q').toNat : Array ByteArray)) _ = Y
            have hYR : Y = R2 := by
              rw [← hY]
              refine Eq.trans ?_ hR2'
              congr 1
            subst hYR
            rcases hev with ⟨hf1, rs, hmany, hasc, hs2, hevl⟩ | ⟨hf1, hnot2⟩
            · have hasc' : ascending rs = true := by simpa using hasc
              rw [hf1]
              dsimp only
              rw [hs2, hevl, hmany]
              simp only [Option.bind_some]
              rw [if_pos hasc']
              simp only [Option.bind_some]
              by_cases hqe : q' + 2 + 64 * (be2 x q').toNat = x.size
              · rw [if_neg (show ¬ ((q' + 2 + 64 * (be2 x q').toNat != x.size) = true) by rw [bne_iff_ne]; exact fun h => h hqe)]
                have hnil : SL x (q' + 2 + 64 * (be2 x q').toNat) = [] := (SL_nil _ _).mpr (by omega)
                rw [hnil]
                refine congrArg some (Prod.ext ?_ ?_)
                · simp only [RequestBA.ofModel, RequestBA.mk.injEq]
                  exact ⟨ex_eq x _ _ _ rfl, ex_eq x _ _ _ rfl, trivial, ex_eq x _ _ _ rfl, ex_eq x _ _ _ rfl,
                    ex_eq x _ _ _ (by omega), ex_eq x _ _ _ (by omega), trivial, ex_eq x _ _ _ (by omega),
                    by simp, by simp⟩
                · show idNatA payKey = _
                  rw [hpayKey]
                  dsimp only
                  exact payKey_idNat x te ge ce ye hge hye hge0 hye0
              · rw [if_pos (show ((q' + 2 + 64 * (be2 x q').toNat != x.size) = true) from bne_iff_ne.mpr hqe)]
                rcases hSL : SL x (q' + 2 + 64 * (be2 x q').toNat) with _ | ⟨a, t⟩
                · exact absurd ((SL_nil _ _).mp hSL) (by omega)
                · rfl
            · rw [hf1]
              dsimp only
              obtain ⟨rs, hrs⟩ := many_digest_ok x (be2 x q').toNat (q' + 2) (by omega)
              rw [hrs]
              simp only [Option.bind_some]
              have hna : ¬ ascending rs = true := fun h => hnot2 ⟨rs, _, hrs, by simpa using h⟩
              rw [if_neg hna]
              rfl
    · have hc1 : (decide ruled && nl == 0 || nl != 0 && sum != amount.toNat || decide (x.size < q' + 2)) = true := by
        rcases Bool.eq_false_or_eq_true (decide ruled && nl == 0 || nl != 0 && sum != amount.toNat) with hA | hA
        · simp [hA]
        · exact absurd (hcond.mp hA) h78
      rw [if_pos hc1]
      by_cases h7 : (nl == 0 || sum == amount.toNat) = true
      · have h8 : ¬ ((!decide ruled || !(nl == 0)) = true) := fun h => h78 ⟨h7, h⟩
        rw [if_pos h7]
        simp only [Option.bind_some]
        rw [if_neg h8]
        rfl
      · rw [if_neg h7]
        rfl

private theorem pLine_eq : pLine = (do let w ← pLineFull; pure (⟨w.flow, w.memberKey, w.payeeRef, w.cents⟩ : WireLine)) := by
  simp only [pLine, pLineFull, bind_assoc, pure_bind]

private theorem pLine_full (s : Bytes) :
    pLine.run s = (pLineFull.run s).map fun (w, r) => (⟨w.flow, w.memberKey, w.payeeRef, w.cents⟩, r) := by
  rw [pLine_eq]
  simp only [StateT.run_bind, StateT.run_pure, Option.pure_def]
  cases pLineFull.run s <;> rfl

private theorem beNat_append (xs ys : Bytes) : beNat (xs ++ ys) = beNat xs * 256 ^ ys.length + beNat ys := by
  have h := beNat_foldl ys (beNat xs)
  unfold beNat at h ⊢
  rw [List.foldl_append]
  exact h

private theorem or4 {a0 a1 a2 a3 : Nat} (h0 : a0 < 256) (h1 : a1 < 256) (h2 : a2 < 256) (h3 : a3 < 256) :
    (a0 <<< 24 % 2 ^ 64 ||| a1 <<< 16 % 2 ^ 64 ||| a2 <<< 8 % 2 ^ 64 ||| a3) =
    a0 * 256 ^ 3 + (a1 * 256 ^ 2 + (a2 * 256 ^ 1 + (a3 * 256 ^ 0 + 0))) := by
  rw [shl_mod a0 24 h0 (by omega), shl_mod a1 16 h1 (by omega), shl_mod a2 8 h2 (by omega)]
  simp only [Nat.or_assoc]
  rw [or_mul a2 a3 8 (by simp only [Nat.reducePow]; omega)]
  rw [or_mul a1 _ 16 (by simp only [Nat.reducePow]; omega)]
  rw [or_mul a0 _ 24 (by simp only [Nat.reducePow]; omega)]
  simp only [Nat.reducePow]
  omega

private theorem be4_toNat (b : ByteArray) (p : Nat) (h : p + 4 ≤ b.size) :
    (be4 b p).toNat = beNat ((b.toList.drop p).take 4) := by
  have hL : b.toList.length = b.size := (Bin.size_eq_length' b).symm
  rw [beNat_slice _ p 3 (by omega), beNat_slice _ (p + 1) 2 (by omega), beNat_slice _ (p + 1 + 1) 1 (by omega),
    beNat_slice _ (p + 1 + 1 + 1) 0 (by omega)]
  unfold be4
  rw [get!_lt b p (by omega), get!_lt b (p + 1) (by omega), get!_lt b (p + 2) (by omega), get!_lt b (p + 3) (by omega)]
  simp only [UInt64.toNat_or, UInt64.toNat_shiftLeft, UInt8.toNat_toUInt64, List.take_zero, beNat, List.foldl_nil,
    Nat.add_assoc]
  simp only [UInt64.reduceToNat, Nat.reduceMod, Nat.reduceAdd]
  exact or4 (UInt8.toNat_lt _) (UInt8.toNat_lt _) (UInt8.toNat_lt _) (UInt8.toNat_lt _)

private theorem or_low (c a M sh : Nat) (hc : c < 2 ^ sh) (ha : a < 256) (hM : sh + 8 ≤ M) :
    (2 ^ M + c) ||| (a <<< sh) = 2 ^ M + c + a * 2 ^ sh := by
  have hP : 2 ^ sh * 256 ≤ 2 ^ M := by
    have : 2 ^ (sh + 8) ≤ 2 ^ M := Nat.pow_le_pow_right (by omega) hM
    rw [Nat.pow_add] at this; simpa using this
  have hX : a * 2 ^ sh + c < 2 ^ M := by
    have : (a + 1) * 2 ^ sh ≤ 256 * 2 ^ sh := Nat.mul_le_mul_right _ (by omega)
    rw [Nat.add_mul] at this
    omega
  have hc' : c < 2 ^ M := by omega
  have h1 : 2 ^ M + c = c ||| 2 ^ M := by rw [Nat.or_two_pow_eq_add_of_lt hc']; omega
  have h2 : (a <<< sh) ||| c = a <<< sh + c := (Nat.shiftLeft_add_eq_or_of_lt hc a).symm
  calc (2 ^ M + c) ||| (a <<< sh) = 2 ^ M ||| ((a <<< sh) ||| c) := by rw [h1]; ac_rfl
    _ = 2 ^ M ||| (a * 2 ^ sh + c) := by rw [h2, Nat.shiftLeft_eq]
    _ = (a * 2 ^ sh + c) ||| 2 ^ M := Nat.or_comm _ _
    _ = a * 2 ^ sh + c + 2 ^ M := Nat.or_two_pow_eq_add_of_lt hX
    _ = 2 ^ M + c + a * 2 ^ sh := by omega

private theorem pow256 (j : Nat) : (256 : Nat) ^ j = 2 ^ (8 * j) := by
  rw [Nat.pow_mul]

private theorem lowBytes_eq (b : ByteArray) (e n k0 : Nat) (hk : k0 ≤ n) (hm : n - k0 ≤ 7) (hne : n ≤ e) (he : e ≤ b.size) :
    ∀ (d t : Nat) (v : UInt64), t + d = n → k0 ≤ t →
      v.toNat = 256 ^ (n - k0) + beNat ((b.toList.drop (e - t)).take (t - k0)) →
      (lowBytes b e n k0 t v).toNat = 256 ^ (n - k0) + beNat ((b.toList.drop (e - n)).take (n - k0)) := by
  have hL : b.toList.length = b.size := (Bin.size_eq_length' b).symm
  intro d
  induction d with
  | zero =>
    intro t v ht hkt hv
    have : t = n := by omega
    subst this
    rw [lowBytes, if_neg (by omega)]; exact hv
  | succ d ih =>
    intro t v ht hkt hv
    rw [lowBytes, if_pos (by omega)]
    refine ih (t + 1) _ (by omega) (by omega) ?_
    have hc := Keyset.beNat_lt_pow (t - k0) ((b.toList.drop (e - t)).take (t - k0)) (len_slice _ _ _ (by omega))
    have hsl : (b.toList.drop (e - (t + 1))).take (t + 1 - k0) =
        b.toList[e - (t + 1)]'(by omega) :: (b.toList.drop (e - t)).take (t - k0) := by
      rw [show t + 1 - k0 = (t - k0) + 1 by omega, take_succ_drop _ _ _ (by omega), show e - (t + 1) + 1 = e - t by omega]
    rw [hsl, beNat_cons, len_slice _ _ _ (by omega)]
    have hg : b.get! (e - 1 - t) = b.toList[e - (t + 1)]'(by omega) := by
      rw [get!_lt b _ (by omega)]; congr 1; omega
    rw [hg]
    have hsh : ((8 * (t - k0)).toUInt64).toNat = 8 * (t - k0) := by
      simp only [Nat.toUInt64, UInt64.toNat_ofNat']; omega
    simp only [UInt64.toNat_or, UInt64.toNat_shiftLeft, UInt8.toNat_toUInt64, hsh]
    rw [Nat.mod_eq_of_lt (by omega : 8 * (t - k0) < 64), hv, Nat.mod_eq_of_lt]
    · rw [pow256 (n - k0), pow256 (t - k0)] at *
      rw [or_low _ _ _ _ hc (UInt8.toNat_lt _) (by omega)]
      omega
    · have h48 : 2 ^ (8 * (t - k0)) ≤ 2 ^ 48 := Nat.pow_le_pow_right (by omega) (by omega)
      have hb := UInt8.toNat_lt (b.toList[e - (t + 1)]'(by omega))
      rw [Nat.shiftLeft_eq]
      have := Nat.mul_le_mul (Nat.le_of_lt_succ hb) h48
      omega

private theorem pow64 (k : Nat) : (2 : Nat) ^ (64 * k) = 256 ^ (8 * k) := by
  rw [pow256 (8 * k)]; congr 1; omega

private theorem word_toNat (N k : Nat) : (word N k).toNat = (N / 256 ^ (8 * k)) % 2 ^ 64 := by
  unfold word
  simp only [Nat.toUInt64, UInt64.toNat_ofNat', Nat.shiftRight_eq_div_pow, pow64]

private theorem slice_in (l : List UInt8) (s a n j : Nat) (hj : j ≤ n - a) :
    (l.drop (s + a)).take j = (((l.drop s).take n).drop a).take j := by
  rw [List.drop_take, List.take_take, List.drop_drop, show min j (n - a) = j by omega, Nat.add_comm]

private theorem wordOf_eq (b : ByteArray) (s n k : Nat) (h : s + n ≤ b.size) :
    wordOf b s n k = word (idNat ((b.toList.drop s).take n)) k := by
  have hL : b.toList.length = b.size := (Bin.size_eq_length' b).symm
  have hX : 0 < 256 ^ (8 * k) := Nat.pow_pos (by decide)
  unfold wordOf
  obtain ⟨L, hLd⟩ : ∃ L, (b.toList.drop s).take n = L := ⟨_, rfl⟩
  have hlen : L.length = n := by rw [← hLd]; exact len_slice _ _ _ (by omega)
  have hB : beNat L < 256 ^ n := Keyset.beNat_lt_pow n L hlen
  have hN : idNat L = 256 ^ n + beNat L := by
    unfold idNat; rw [beNat_cons, hlen]; simp
  rw [hLd]
  by_cases hA : 8 * k + 8 ≤ n
  · rw [if_pos hA]
    obtain ⟨a, ha⟩ : ∃ a, a = n - 8 * k - 8 := ⟨_, rfl⟩
    have hna : n = a + 8 + 8 * k := by omega
    have hQ : (b.toList.drop (s + n - 8 * k - 8)).take 8 = (L.drop a).take 8 := by
      rw [← hLd, show s + n - 8 * k - 8 = s + a by omega]; exact slice_in _ _ _ _ _ (by omega)
    have hdec : L = L.take a ++ (L.drop a).take 8 ++ L.drop (a + 8) := by
      conv =>
        lhs
        rw [← List.take_append_drop a L, ← List.take_append_drop 8 (L.drop a)]
      simp [List.drop_drop, Nat.add_comm]
    have hl1 : ((L.drop a).take 8).length = 8 := len_slice _ _ _ (by omega)
    have hl2 : (L.drop (a + 8)).length = 8 * k := by simp; omega
    have hQlt := Keyset.beNat_lt_pow 8 ((L.drop a).take 8) hl1
    have hRlt := Keyset.beNat_lt_pow (8 * k) (L.drop (a + 8)) hl2
    have hbe : beNat L = (beNat (L.take a) * 256 ^ 8 + beNat ((L.drop a).take 8)) * 256 ^ (8 * k) + beNat (L.drop (a + 8)) := by
      conv =>
        lhs
        rw [hdec]
      rw [beNat_append, beNat_append, hl1, hl2]
    have hn256 : (256 : Nat) ^ n = 256 ^ a * 256 ^ 8 * 256 ^ (8 * k) := by
      rw [hna, Nat.pow_add, Nat.pow_add]
    have e1 : idNat L = ((256 ^ a + beNat (L.take a)) * 256 ^ 8 + beNat ((L.drop a).take 8)) * 256 ^ (8 * k) + beNat (L.drop (a + 8)) := by
      rw [hN, hbe, hn256]; simp only [Nat.add_mul, Nat.mul_assoc, Nat.add_assoc]
    apply UInt64.toNat_inj.mp
    rw [be8_toNat _ _ (by omega), hQ, word_toNat, e1, Nat.add_comm, Nat.add_mul_div_right _ _ hX,
      Nat.div_eq_of_lt hRlt, Nat.zero_add, show (2 : Nat) ^ 64 = 256 ^ 8 by rfl,
      Nat.add_comm, Nat.add_mul_mod_self_right, Nat.mod_eq_of_lt hQlt]
  · rw [if_neg hA]
    by_cases hB' : n < 8 * k
    · rw [if_pos hB']
      apply UInt64.toNat_inj.mp
      rw [word_toNat, hN]
      have : 256 ^ (n + 1) ≤ 256 ^ (8 * k) := Nat.pow_le_pow_right (by omega) (by omega)
      rw [Nat.pow_succ] at this
      rw [Nat.div_eq_of_lt (by omega)]
      rfl
    · rw [if_neg hB']
      obtain ⟨m, hm⟩ : ∃ m, m = n - 8 * k := ⟨_, rfl⟩
      have hn : n = m + 8 * k := by omega
      have hdec : L = L.take m ++ L.drop m := (List.take_append_drop m L).symm
      have hl2 : (L.drop m).length = 8 * k := by simp; omega
      have hl1 : (L.take m).length = m := by simp; omega
      have hAlt := Keyset.beNat_lt_pow m (L.take m) hl1
      have hRlt := Keyset.beNat_lt_pow (8 * k) (L.drop m) hl2
      have e1 : idNat L = (256 ^ m + beNat (L.take m)) * 256 ^ (8 * k) + beNat (L.drop m) := by
        rw [hN]
        conv =>
          lhs
          rw [hdec]
        rw [beNat_append, hl2, hn, Nat.pow_add]; simp only [Nat.add_mul, Nat.mul_assoc, Nat.add_assoc]
      have hpm : 256 ^ m ≤ 256 ^ 7 := Nat.pow_le_pow_right (by omega) (by omega)
      have hv0 : (1 <<< (8 * (n - 8 * k)).toUInt64 : UInt64).toNat = 256 ^ (n - 8 * k) + beNat ((b.toList.drop (s + n - 8 * k)).take (8 * k - 8 * k)) := by
        have hsh : ((8 * (n - 8 * k)).toUInt64).toNat = 8 * (n - 8 * k) := by
          simp only [Nat.toUInt64, UInt64.toNat_ofNat']; omega
        rw [Nat.sub_self, List.take_zero, UInt64.toNat_shiftLeft, hsh, Nat.mod_eq_of_lt (by omega : 8 * (n - 8 * k) < 64)]
        show (1 <<< (8 * (n - 8 * k))) % 2 ^ 64 = 256 ^ (n - 8 * k) + beNat []
        rw [Nat.shiftLeft_eq, Nat.one_mul, pow256, Nat.mod_eq_of_lt (Nat.pow_lt_pow_right (by decide) (by omega))]
        rfl
      have hT : (b.toList.drop (s + n - n)).take (n - 8 * k) = L.take m := by
        rw [← hLd, List.take_take, Nat.add_sub_cancel, hm, show min (n - 8 * k) n = n - 8 * k by omega]
      have hdiv : ((256 ^ m + beNat (L.take m)) * 256 ^ (8 * k) + beNat (L.drop m)) / 256 ^ (8 * k) = 256 ^ m + beNat (L.take m) := by
        rw [Nat.add_comm ((256 ^ m + beNat (L.take m)) * 256 ^ (8 * k)), Nat.add_mul_div_right _ _ hX,
          Nat.div_eq_of_lt hRlt, Nat.zero_add]
      apply UInt64.toNat_inj.mp
      rw [lowBytes_eq b (s + n) n (8 * k) (by omega) (by omega) (by omega) (by omega) (n - 8 * k) (8 * k) _ (by omega) (Nat.le_refl _) hv0,
        word_toNat, e1, hdiv, hT, ← hm, Nat.mod_eq_of_lt]
      have : (256 : Nat) ^ 7 < 2 ^ 63 := by decide
      omega

private theorem line_walk {b : ByteArray} {p e : Nat} {wf : WireLineFull} (he : e ≤ b.size) (hpe : p ≤ e)
    (h : pLineFull.run ((b.toList.take e).drop p) = some (wf, [])) :
    ∃ ie pe re oe, p + 1 ≤ e ∧ (1 ≤ (b.get! p).toNat ∧ (b.get! p).toNat ≤ 5) ∧
      wf.flow = flows.getD ((b.get! p).toNat - 1) .FFS_CYCLE ∧
      identEnd b (p + 1) e = ie ∧ identEnd b (ie + 32) e = pe ∧ identEnd b pe e = re ∧ identEnd b (re + 4) e = oe ∧
      ie ≠ 0 ∧ pe ≠ 0 ∧ re ≠ 0 ∧ oe ≠ 0 ∧
      p + 1 + 3 ≤ ie ∧ ie + 32 + 3 ≤ pe ∧ pe + 3 ≤ re ∧ re + 4 + 3 ≤ oe ∧ oe + 4 + 8 = e ∧
      wf.lineId = (b.toList.drop (p + 1 + 2)).take (ie - (p + 1 + 2)) ∧
      wf.memberKey = (b.toList.drop ie).take 32 ∧
      wf.payeeRef = (b.toList.drop (ie + 32 + 2)).take (pe - (ie + 32 + 2)) ∧
      wf.rendering = (b.toList.drop (pe + 2)).take (re - (pe + 2)) ∧
      wf.date = beNat ((b.toList.drop re).take 4) ∧
      wf.proc = (b.toList.drop (re + 4 + 2)).take (oe - (re + 4 + 2)) ∧
      wf.units = beNat ((b.toList.drop oe).take 4) ∧
      wf.cents = beNat ((b.toList.drop (oe + 4)).take 8) := by
  have hL : b.toList.length = b.size := (Bin.size_eq_length' b).symm
  simp only [pLineFull, Gate.tag, StateT.run_bind, memberKeyBytes] at h
  obtain ⟨⟨v0, s0⟩, h0, h⟩ := obind_some h
  obtain ⟨⟨vn, sn⟩, hn, h0⟩ := obind_some h0
  obtain ⟨hp1, hvn, hv1, hv5, rfl⟩ := nat_step he hpe (show (nat 1 1 flows.length).run _ = _ from hn)
  have hv5' : vn ≤ 5 := hv5
  simp only [flows_get (vn - 1) (by omega)] at h0
  simp only [StateT.run_pure, Option.pure_def] at h0
  obtain ⟨rfl, rfl⟩ : v0 = flows.getD (vn - 1) .FFS_CYCLE ∧ s0 = (b.toList.take e).drop (p + 1) := by
    simpa [and_comm] using h0.symm
  obtain ⟨⟨a1, s1⟩, h1, h⟩ := obind_some h
  obtain ⟨i1, ha1, rfl⟩ := ident_step he h1
  have b1 := identEnd_bounds i1
  obtain ⟨⟨a2, s2⟩, h2, h⟩ := obind_some h
  obtain ⟨t2, ha2, rfl⟩ := take_step he (by omega) h2
  obtain ⟨⟨a3, s3⟩, h3, h⟩ := obind_some h
  obtain ⟨i3, ha3, rfl⟩ := ident_step he h3
  have b3 := identEnd_bounds i3
  obtain ⟨⟨a4, s4⟩, h4, h⟩ := obind_some h
  obtain ⟨i4, ha4, rfl⟩ := ident_step he h4
  have b4 := identEnd_bounds i4
  obtain ⟨⟨a5, s5⟩, h5, h⟩ := obind_some h
  obtain ⟨n5, ha5, -, hh5, rfl⟩ := nat_step he (by omega) h5
  obtain ⟨⟨a6, s6⟩, h6, h⟩ := obind_some h
  obtain ⟨i6, ha6, rfl⟩ := ident_step he h6
  have b6 := identEnd_bounds i6
  obtain ⟨⟨a7, s7⟩, h7, h⟩ := obind_some h
  obtain ⟨n7, ha7, -, hh7, rfl⟩ := nat_step he (by omega) h7
  obtain ⟨⟨a8, s8⟩, h8, h⟩ := obind_some h
  obtain ⟨n8, ha8, -, hh8, rfl⟩ := nat_step he (by omega) h8
  simp only [StateT.run_pure, Option.pure_def, Option.some.injEq, Prod.mk.injEq] at h
  obtain ⟨hww, hend⟩ := h
  subst hww
  have hpL : p < b.size := by omega
  have hvt : vn = (b.get! p).toNat := by rw [hvn, beNat_one b p hpL]
  have hlenE := congrArg List.length hend
  simp only [List.length_drop, List.length_take, List.length_nil] at hlenE
  generalize hie : identEnd b (p + 1) e = ie at *
  generalize hpe2 : identEnd b (ie + 32) e = pe at *
  generalize hre : identEnd b pe e = re at *
  generalize hoe : identEnd b (re + 4) e = oe at *
  exact ⟨ie, pe, re, oe, hp1, ⟨by omega, by omega⟩, by rw [← hvt], (by first | rfl | assumption), (by first | rfl | assumption), (by first | rfl | assumption), (by first | rfl | assumption), i1, i3, i4, i6, b1.1, b3.1, b4.1, b6.1,
    by omega, ha1, ha2, ha3, ha4, ha5, ha6, ha7, ha8⟩

private theorem flowOfTag_eq (c : UInt8) (f : Flow) (wf : WireFlow) (h1 : 1 ≤ c.toNat) (h5 : c.toNat ≤ 5)
    (hw : wf = flows.getD (c.toNat - 1) .FFS_CYCLE) (hf : Rules.flowOf wf = some f) : flowOfTag c = f := by
  have hc : c = 1 ∨ c = 2 ∨ c = 3 ∨ c = 4 ∨ c = 5 := by
    have : c.toNat = 1 ∨ c.toNat = 2 ∨ c.toNat = 3 ∨ c.toNat = 4 ∨ c.toNat = 5 := by omega
    rcases this with h | h | h | h | h
    · exact Or.inl (UInt8.toNat_inj.mp (by simpa using h))
    · exact Or.inr (Or.inl (UInt8.toNat_inj.mp (by simpa using h)))
    · exact Or.inr (Or.inr (Or.inl (UInt8.toNat_inj.mp (by simpa using h))))
    · exact Or.inr (Or.inr (Or.inr (Or.inl (UInt8.toNat_inj.mp (by simpa using h)))))
    · exact Or.inr (Or.inr (Or.inr (Or.inr (UInt8.toNat_inj.mp (by simpa using h)))))
  rcases hc with rfl | rfl | rfl | rfl | rfl <;> simp_all [flows, flowOfTag, Rules.flowOf]

private theorem idA (b : ByteArray) (i j : Nat) (hj : j ≤ b.size) (hij : i ≤ j) :
    beNatA b i j 1 = idNat ((b.toList.drop i).take (j - i)) := by
  have hL : b.toList.length = b.size := (Bin.size_eq_length' b).symm
  rw [beNatA_eq b i j 1 hj hij]
  unfold idNat
  rw [beNat_cons, len_slice _ _ _ (by omega)]
  simp

private theorem lineOfBytes_eq (ln : ByteArray) (pay : Nat) (wf : WireLineFull) (L : Line)
    (hp : parse pLineFull maxLineBytes ln.toList = some wf) (hL : lineOf pay wf = some L) :
    lineOfBytes pay ln = L := by
  have hs : ln.toList.length = ln.size := (Bin.size_eq_length' ln).symm
  have h0 : pLineFull.run ((ln.toList.take ln.size).drop 0) = some (wf, []) := by
    rw [List.drop_zero, List.take_of_length_le (by omega)]; exact parse_some hp
  obtain ⟨ie, pe, re, oe, -, ⟨ht1, ht5⟩, hfl, hie, hpe, hre, hoe, i1, i3, i4, i6, b1, b3, b4, b6, hend, hid, hmk, hpay,
    hrend, hdate, hproc, hunits, hcents⟩ := line_walk (Nat.le_refl _) (Nat.zero_le _) h0
  simp only [lineOf, Option.map_eq_some_iff] at hL
  obtain ⟨f, hf, rfl⟩ := hL
  simp only [Nat.zero_add, Nat.reduceAdd, Nat.add_assoc] at hie hid hpe hpay hproc hre hoe b1 b3 b4 b6 hend
  unfold lineOfBytes
  simp only [hie, hpe, hre, hoe, Line.mk.injEq]
  refine ⟨?_, trivial, flowOfTag_eq _ f wf.flow ht1 ht5 hfl hf, ?_, ?_, ?_, ?_, ?_, ?_, ?_⟩
  · rw [idA ln 3 ie (by omega) (by omega), hid]
  · rw [idA ln ie (ie + 32) (by omega) (by omega), hmk, Nat.add_sub_cancel_left]
  · rw [idA ln (ie + 34) pe (by omega) (by omega), hpay]
  · rw [idA ln (pe + 2) re (by omega) (by omega), hrend]
  · rw [be4_toNat ln re (by omega), hdate]
  · rw [idA ln (re + 6) oe (by omega) (by omega), hproc]
  · rw [be4_toNat ln oe (by omega), hunits]
  · rw [be8_toNat ln (oe + 4) (by omega), hcents]

private theorem flowOf_tag (t : UInt8) (h1 : 1 ≤ t.toNat) (h3 : t.toNat ≤ 3) :
    Rules.flowOf (flows.getD (t.toNat - 1) .FFS_CYCLE) = some (flowOfTag t) ∧ (flowOfTag t).tag.toUInt8 = t := by
  have : t.toNat = 1 ∨ t.toNat = 2 ∨ t.toNat = 3 := by omega
  rcases this with h | h | h
  · have : t = 1 := UInt8.toNat_inj.mp (by simpa using h)
    subst this; decide
  · have : t = 2 := UInt8.toNat_inj.mp (by simpa using h)
    subst this; decide
  · have : t = 3 := UInt8.toNat_inj.mp (by simpa using h)
    subst this; decide

private theorem toUInt64_toNat (u : UInt64) : u.toNat.toUInt64 = u := by simp [Nat.toUInt64]

private theorem toUInt32_toNat (u : UInt64) : u.toUInt32 = u.toNat.toUInt32 := by
  apply UInt32.toNat_inj.mp
  simp [Nat.toUInt32]

private theorem word_zero (n : Nat) : word n 0 = n.toUInt64 := by simp [word]

private theorem lineRow_row {x : ByteArray} {p e : Nat} {tag : UInt8} {mem ps pn : Nat} {payW : UInt64} {r : LineRow} {pay : Nat}
    (he : e ≤ x.size) (hpe : p ≤ e) (hm : mem + 32 ≤ x.size) (hps : ps + pn ≤ x.size) (ht1 : 1 ≤ tag.toNat) (ht3 : tag.toNat ≤ 3)
    (hpay : payW = pay.toUInt64)
    (h : lineRow x p e tag mem ps pn payW = some r) :
    ∃ wf L, pLineFull.run ((x.toList.take e).drop p) = some (wf, []) ∧ lineOf pay wf = some L ∧ r = LineRow.of L := by
  have hspec := lineRow_spec he hm hps ht1 (by omega) h
  rw [pLine_full] at hspec
  rcases hf : pLineFull.run ((x.toList.take e).drop p) with _ | ⟨wf, rest⟩
  · rw [hf] at hspec; simp at hspec
  rw [hf] at hspec
  simp only [Option.map_some, Option.some.injEq, Prod.mk.injEq, WireLine.mk.injEq] at hspec
  obtain ⟨⟨hwfl, hwmk, hwpy, hwc⟩, rfl⟩ := hspec
  obtain ⟨ie, pe, re, oe, hp1, ⟨hg1, hg5⟩, hfl, hie, hpe', hre, hoe, i1, i3, i4, i6, b1, b3, b4, b6, hend, hid, hmk, hpayee,
    hrend, hdate, hproc, hunits, hcents⟩ := line_walk he hpe hf
  obtain ⟨hft, hftag⟩ := flowOf_tag tag ht1 ht3
  refine ⟨wf, ⟨idNat wf.lineId, pay, flowOfTag tag, idNat wf.memberKey, idNat wf.payeeRef, idNat wf.rendering, wf.date,
    idNat wf.proc, wf.units, wf.cents⟩, rfl, ?_, ?_⟩
  · simp only [lineOf, hwfl, hft, Option.map_some]
  · simp only [Nat.add_assoc, Nat.reduceAdd] at hid hpayee hproc b1 b3 b4 b6 hend
    unfold lineRow at h
    simp only at h
    rw [hie, hpe', hre, hoe] at h
    split at h
    · cases h
    rename_i c1
    split at h
    · cases h
    rename_i c2
    split at h
    · cases h
    rename_i c3
    split at h
    · cases h
    rename_i c4
    split at h
    · cases h
    rename_i c5
    split at h
    · cases h
    rename_i c6
    cases h
    unfold LineRow.of
    simp only [LineRow.mk.injEq]
    have hc8 : (be8 x (oe + 4)).toNat = wf.cents := by rw [be8_toNat x (oe + 4) (by omega), hcents]
    have hd4 : (be4 x re).toNat = wf.date := by rw [be4_toNat x re (by omega), hdate]
    have hu4 : (be4 x oe).toNat = wf.units := by rw [be4_toNat x oe (by omega), hunits]
    refine ⟨?_, ?_, ?_, ?_, hpay, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_⟩
    · rw [wordOf_eq x _ _ _ (by omega), hid]
    · rw [wordOf_eq x _ _ _ (by omega), hid]
    · rw [wordOf_eq x _ _ _ (by omega), hid]
    · rw [wordOf_eq x _ _ _ (by omega), hid]
    · rw [wordOf_eq x mem 32 _ hm, hwmk]
    · rw [wordOf_eq x mem 32 _ hm, hwmk]
    · rw [wordOf_eq x mem 32 _ hm, hwmk]
    · rw [wordOf_eq x mem 32 _ hm, hwmk]
    · rw [wordOf_eq x ps pn 0 hps, hwpy, word_zero]
    · rw [wordOf_eq x (pe + 2) (re - (pe + 2)) 0 (by omega), hrend, word_zero]
    · rw [wordOf_eq x (re + 6) (oe - (re + 6)) 0 (by omega), hproc, word_zero]
    · rw [← hc8, toUInt64_toNat]
    · rw [toUInt32_toNat, hd4]
    · rw [toUInt32_toNat, hu4]
    · exact hftag.symm

private theorem parse_of_run {α : Type} {p : Gate.P α} {lim : Nat} {b : Bytes} {v : α} (h : p.run b = some (v, []))
    (hl : b.length ≤ lim) : parse p lim b = some v := by
  unfold parse
  rw [if_neg (by omega), h]

private abbrev GoodLn (pay : Nat) (ln : ByteArray) : Prop :=
  ∃ wf L, parse pLineFull maxLineBytes ln.toList = some wf ∧ lineOf pay wf = some L

private theorem lineLoop2 (x : ByteArray) (tag : UInt8) (ye ee : Nat) (payW : UInt64) (pay : Nat) (ruled : Prop) [Decidable ruled]
    (hy : ye + 32 ≤ x.size) (hee : ye + 35 ≤ ee) (hex : ee ≤ x.size) (ht1 : 1 ≤ tag.toNat) (ht3 : ruled → tag.toNat ≤ 3)
    (hpay : payW = pay.toUInt64) :
    ∀ (k s q sum : Nat) (lines : Array ByteArray) (rows : Array LineRow) (R : LSt),
      Id.run (forIn (List.range' s k) ((none : Option (Option RowsReq)), q, sum, lines, rows)
        (lineStep x tag ye ee payW ruled)) = R →
      (R.1 = none ∨ R.1 = some none) ∧
      (R.1 = none → ∃ ls : List ByteArray, R.2.2.2.1.toList = lines.toList ++ ls ∧
        R.2.2.2.2.toList = rows.toList ++ (if ruled then ls.map (fun ln => LineRow.of (lineOfBytes pay ln)) else []) ∧
        (ruled → ∀ ln ∈ ls, GoodLn pay ln)) := by
  intro k
  induction k with
  | zero =>
    intro s q sum lines rows R hR
    simp only [List.range'_zero, List.forIn_nil, Id.run_pure] at hR
    subst hR
    exact ⟨Or.inl rfl, fun _ => ⟨[], by simp, by simp, by simp⟩⟩
  | succ k ih =>
    intro s q sum lines rows R hR
    rw [List.range'_succ] at hR
    simp only [Id.run, List.forIn_cons, lineStep] at hR
    by_cases hA : x.size < q + 2
    · simp only [hA, ↓reduceIte, pure_bind] at hR
      subst hR
      exact ⟨Or.inr rfl, fun h => by simp at h⟩
    by_cases hB : ((be2 x q).toNat == 0 || decide (569 < (be2 x q).toNat) || decide (x.size < q + 2 + (be2 x q).toNat)) = true
    · simp only [hA, hB, ↓reduceIte, pure_bind] at hR
      subst hR
      exact ⟨Or.inr rfl, fun h => by simp at h⟩
    have hB' : 1 ≤ (be2 x q).toNat ∧ (be2 x q).toNat ≤ 569 ∧ q + 2 + (be2 x q).toNat ≤ x.size := by
      simp only [Bool.or_eq_true, beq_iff_eq, decide_eq_true_eq] at hB
      omega
    obtain ⟨ln, hln⟩ : ∃ ln, (be2 x q).toNat = ln := ⟨_, rfl⟩
    rw [hln] at hB' hR hB
    simp only [hA, hB, ↓reduceIte, Bool.false_eq_true, pure_bind] at hR
    rcases hl : lineRow x (q + 2) (q + 2 + ln) tag ye (ye + 34) (ee - ye - 34) payW with _ | r
    · rw [hl] at hR
      simp only [pure_bind] at hR
      subst hR
      exact ⟨Or.inr rfl, fun h => by simp at h⟩
    · rw [hl] at hR
      by_cases hrl : ruled
      · simp only [if_pos hrl, pure_bind] at hR
        obtain ⟨wf, L, hwf, hL, hrL⟩ := lineRow_row (x := x) (p := q + 2) (e := q + 2 + ln) (tag := tag) (mem := ye)
          (ps := ye + 34) (pn := ee - ye - 34) (payW := payW) (r := r) (pay := pay) (by omega) (by omega) hy (by omega)
          ht1 (ht3 hrl) hpay hl
        obtain ⟨hor, hrest⟩ := ih (s + 1) _ _ _ _ R hR
        refine ⟨hor, fun hfl => ?_⟩
        obtain ⟨ls, h1, h2, h3⟩ := hrest hfl
        have hdt : (x.toList.take (q + 2 + ln)).drop (q + 2) = (x.toList.drop (q + 2)).take ln := by
          rw [List.drop_take]; congr 1; omega
        have hlenl : ((x.toList.drop (q + 2)).take ln).length = ln := len_slice _ _ _ (by
          rw [(Bin.size_eq_length' x).symm]; omega)
        have hext : (x.extract (q + 2) (q + 2 + ln)).toList = (x.toList.drop (q + 2)).take ln := by
          rw [Bin.toList_extract', show q + 2 + ln - (q + 2) = ln by omega]
        have hpe : parse pLineFull maxLineBytes (x.extract (q + 2) (q + 2 + ln)).toList = some wf := by
          rw [hext]
          exact parse_of_run (by rw [← hdt]; exact hwf) (by rw [hlenl]; unfold maxLineBytes; omega)
        refine ⟨x.extract (q + 2) (q + 2 + ln) :: ls, ?_, ?_, ?_⟩
        · rw [h1]; simp
        · rw [h2, hrL]; simp [hrl, lineOfBytes_eq _ pay wf L hpe hL]
        · intro _ l hl
          rcases List.mem_cons.mp hl with rfl | hl
          · exact ⟨wf, L, hpe, hL⟩
          · exact h3 hrl l hl
      · simp only [if_neg hrl, pure_bind] at hR
        obtain ⟨hor, hrest⟩ := ih (s + 1) _ _ _ _ R hR
        refine ⟨hor, fun hfl => ?_⟩
        obtain ⟨ls, h1, h2, -⟩ := hrest hfl
        refine ⟨x.extract (q + 2) (q + 2 + ln) :: ls, ?_, ?_, fun h => absurd h hrl⟩
        · rw [h1]; simp
        · rw [h2]; simp [hrl]

private theorem lineOf_pay (pay P : Nat) (wf : WireLineFull) (L : Line) (h : lineOf P wf = some L) :
    ∃ L', lineOf pay wf = some L' := by
  simp only [lineOf, Option.map_eq_some_iff] at h ⊢
  obtain ⟨f, hf, -⟩ := h
  exact ⟨_, f, hf, rfl⟩

private theorem rel_lines (pay P : Nat) : ∀ (ls : List ByteArray), (∀ ln ∈ ls, GoodLn P ln) →
    ((ls.map (·.toList)).mapM fun x => (parse pLineFull maxLineBytes x).bind (lineOf pay)) = some (ls.map (lineOfBytes pay)) := by
  intro ls
  induction ls with
  | nil => intro _; rfl
  | cons ln ls' ih =>
    intro h
    obtain ⟨wf, L, hp, hL⟩ := h ln (List.mem_cons_self ..)
    obtain ⟨L', hL'⟩ := lineOf_pay pay P wf L hL
    rw [List.map_cons, List.mapM_cons, hp]
    simp only [Option.bind_some, hL', ih (fun l hl => h l (List.mem_cons_of_mem _ hl)), List.map_cons,
      lineOfBytes_eq ln pay wf L' hp hL']
    rfl

private theorem decodeRows_good (x : ByteArray) (d : RowsReq) (h : decodeRows x = some d) (hr : d.ra.flow.ruled = true) :
    ∃ ls : List ByteArray, d.ra.lines = ls ∧
      d.rows.toList = ls.map (fun ln => LineRow.of (lineOfBytes (idNatA d.payKey) ln)) ∧ ∀ ln ∈ ls, GoodLn (idNatA d.payKey) ln := by
  unfold decodeRows at h
  extract_lets n dn te ge tag ce ye ee amount ke nl payKey payW ruled q0 sum0 lines0 rows0 at h
  have hn : n = x.size := rfl
  have hte : te = identEnd x dn n := rfl
  have hge : ge = identEnd x te n := rfl
  have hce : ce = identEnd x (ge + 1) n := rfl
  have hye : ye = identEnd x ce n := rfl
  have hee : ee = identEnd x (ye + 32) n := rfl
  have hpayW : payW = wordOf payKey 0 payKey.size 0 := rfl
  have hq0 : q0 = ke + 2 := rfl
  have hsum0 : sum0 = 0 := rfl
  have hlines0 : lines0 = Array.mkEmpty nl := rfl
  have hrows0 : rows0 = Array.mkEmpty (if ruled then nl else 0) := rfl
  clear_value rows0 lines0 sum0 q0 payW payKey nl ke amount ee ye ce tag ge te dn n
  subst hn
  letI hdec : Decidable ruled := inferInstanceAs (Decidable (tag ≤ 3))
  by_cases c1 : (decide (maxRequestBytes < x.size) || decide (x.size < dn) || !sameBytes x requestDomain 0 0 dn) = true
  · rw [if_pos c1] at h; simp at h
  rw [if_neg c1] at h
  by_cases c2 : (te == 0 || ge == 0 || decide (x.size < ge + 1)) = true
  · rw [if_pos c2] at h; simp at h
  rw [if_neg c2] at h
  by_cases c3 : (tag == 0 || decide (5 < tag)) = true
  · rw [if_pos c3] at h; simp at h
  rw [if_neg c3] at h
  by_cases c4 : (ce == 0 || ye == 0 || decide (x.size < ye + 32)) = true
  · rw [if_pos c4] at h; simp at h
  rw [if_neg c4] at h
  by_cases c5 : (ee == 0 || decide (x.size < ee + 8)) = true
  · rw [if_pos c5] at h; simp at h
  rw [if_neg c5] at h
  by_cases c6 : 9223372036854775807 < amount
  · rw [if_pos c6] at h; simp at h
  rw [if_neg c6] at h
  by_cases c7 : (ke == 0 || decide (x.size < ke + 2)) = true
  · rw [if_pos c7] at h; simp at h
  rw [if_neg c7] at h
  have ht : 1 ≤ tag.toNat ∧ tag.toNat ≤ 5 := by
    by_cases hc : 1 ≤ tag.toNat ∧ tag.toNat ≤ 5
    · exact hc
    · exact absurd ((u8_c2 tag).mpr (by omega)) c3
  simp only [Bool.or_eq_true, beq_iff_eq, decide_eq_true_eq, not_or] at c4 c5
  obtain ⟨⟨hce0, hye0⟩, hs3⟩ := c4
  obtain ⟨hee0, -⟩ := c5
  have heeb := ib hee hee0
  subst hq0 hsum0 hlines0 hrows0
  simp only [Std.Legacy.Range.forIn_eq_forIn_range', Std.Legacy.Range.size, Nat.sub_zero, Nat.add_sub_cancel, Nat.div_one] at h
  have hpay : payW = (idNatA payKey).toUInt64 := by
    have hL : payKey.toList.length = payKey.size := (Bin.size_eq_length' payKey).symm
    rw [hpayW, wordOf_eq payKey 0 payKey.size 0 (by omega), idNatA_eq, List.drop_zero, List.take_of_length_le (by omega), word_zero]
  have hrul : ruled → tag.toNat ≤ 3 := by
    intro hrl
    have : tag ≤ 3 := hrl
    rw [UInt8.le_iff_toNat_le] at this
    exact this
  obtain ⟨R, hR⟩ : ∃ R, Id.run (forIn (List.range' 0 nl) ((none : Option (Option RowsReq)), ke + 2, (0 : Nat),
      (Array.mkEmpty nl : Array ByteArray), (Array.mkEmpty (if ruled then nl else 0) : Array LineRow))
      (lineStep x tag ye ee payW ruled)) = R := ⟨_, rfl⟩
  obtain ⟨hor, hrest⟩ := lineLoop2 x tag ye ee payW (idNatA payKey) ruled (by omega) (by omega) (by omega) ht.1 hrul hpay
    nl 0 (ke + 2) 0 (Array.mkEmpty nl) (Array.mkEmpty (if ruled then nl else 0)) R hR
  have hR' : forIn (m := Id) (List.range' 0 nl) ((none : Option (Option RowsReq)), ke + 2, (0 : Nat),
      (Array.mkEmpty nl : Array ByteArray), (Array.mkEmpty (if ruled then nl else 0) : Array LineRow))
      (lineStep x tag ye ee payW ruled) = R := hR
  generalize hX : (forIn (m := Id) (List.range' 0 nl) ((none : Option (Option RowsReq)), ke + 2, (0 : Nat),
      (Array.mkEmpty nl : Array ByteArray), (Array.mkEmpty (if ruled then nl else 0) : Array LineRow)) _) = X at h
  have hXR : X = R := by
    rw [← hX]
    refine Eq.trans ?_ hR'
    congr 1
    funext i s
    unfold lineStep
    cases lineRow x (s.snd.fst + 2) (s.snd.fst + 2 + (be2 x s.snd.fst).toNat) tag ye (ye + 34) (ee - ye - 34) payW <;> rfl
  subst hXR
  dsimp only [bind, Bind.bind, Id.run, pure, Pure.pure] at h
  rcases hor with hfl | hfl
  case inr =>
    rw [hfl] at h; dsimp only at h; simp at h
  rw [hfl] at h
  dsimp only at h
  by_cases c8 : (decide ruled && nl == 0 || nl != 0 && X.2.2.1 != amount.toNat || decide (x.size < X.2.1 + 2)) = true
  · rw [if_pos c8] at h; simp at h
  rw [if_neg c8] at h
  by_cases c9 : (decide (256 < (be2 x X.2.1).toNat) || decide (x.size < X.2.1 + 2 + 64 * (be2 x X.2.1).toNat)) = true
  · rw [if_pos c9] at h; simp at h
  rw [if_neg c9] at h
  simp only [Bool.or_eq_true, decide_eq_true_eq, not_or] at c8 c9
  obtain ⟨R2, hR2⟩ : ∃ R2, Id.run (forIn (List.range' 0 (be2 x X.2.1).toNat) ((none : Option (Option RowsReq)), X.2.1 + 2,
      (Array.mkEmpty (be2 x X.2.1).toNat : Array ByteArray)) (evStep x)) = R2 := ⟨_, rfl⟩
  have hev := evLoop x (be2 x X.2.1).toNat 0 (X.2.1 + 2) (Array.mkEmpty _) R2 (by omega) (Or.inl rfl) hR2
  have hR2' : forIn (m := Id) (List.range' 0 (be2 x X.2.1).toNat) ((none : Option (Option RowsReq)), X.2.1 + 2,
      (Array.mkEmpty (be2 x X.2.1).toNat : Array ByteArray)) (evStep x) = R2 := hR2
  generalize hY : forIn (m := Id) (List.range' 0 (be2 x X.2.1).toNat) ((none : Option (Option RowsReq)), X.2.1 + 2,
      (Array.mkEmpty (be2 x X.2.1).toNat : Array ByteArray)) _ = Y at h
  have hYR : Y = R2 := by
    rw [← hY]
    refine Eq.trans ?_ hR2'
    congr 1
  subst hYR
  rcases hev with ⟨hf1, -⟩ | ⟨hf1, -⟩
  case inr =>
    rw [hf1] at h; dsimp only at h; simp at h
  rw [hf1] at h
  dsimp only at h
  by_cases c10 : (Y.2.1 != x.size) = true
  · rw [if_pos c10] at h; simp at h
  rw [if_neg c10] at h
  simp only [Option.some.injEq] at h
  subst h
  dsimp only at hr
  have hrr : ruled := by
    have := (ruled_iff tag.toNat ht.1 ht.2).mp hr
    show tag ≤ 3
    rw [UInt8.le_iff_toNat_le]; exact this
  obtain ⟨ls, h1, h2, h3⟩ := hrest hfl
  refine ⟨ls, ?_, ?_, h3 hrr⟩
  · show X.2.2.2.1.toList = ls
    rw [h1]; simp
  · show X.2.2.2.2.toList = _
    rw [h2]; simp only [hrr, ↓reduceIte]; exact List.nil_append _

theorem decodeRows_lines (x : ByteArray) (d : RowsReq) (h : decodeRows x = some d) (hr : d.ra.flow.ruled = true)
    (pay : Nat) : some (d.ra.lines.map (lineOfBytes pay)) = linesOfPay pay d.ra.toModel := by
  obtain ⟨ls, h1, -, h3⟩ := decodeRows_good x d h hr
  have e : d.ra.toModel.lines = ls.map (·.toList) := by rw [← h1]; rfl
  unfold linesOfPay
  rw [e, rel_lines pay (idNatA d.payKey) ls h3, h1]

theorem decodeRows_rows (x : ByteArray) (d : RowsReq) (h : decodeRows x = some d) (hr : d.ra.flow.ruled = true) :
    (linesOfPay (idNatA d.payKey) d.ra.toModel).map (·.map LineRow.of) = some d.rows.toList := by
  obtain ⟨ls, h1, h2, h3⟩ := decodeRows_good x d h hr
  have e : d.ra.toModel.lines = ls.map (·.toList) := by rw [← h1]; rfl
  unfold linesOfPay
  rw [e, rel_lines (idNatA d.payKey) (idNatA d.payKey) ls h3, h2]
  simp only [Option.map_some, List.map_map]
  rfl

/-- `Run.reqOf`, each byte read once. -/
def reqOfFast (x : ByteArray) : Option Run.Req := do
  let d ← decodeRows x
  let q := idNatA d.payKey
  pure ⟨q, d.ra, if d.ra.flow.ruled then d.ra.lines.map (lineOfBytes q) else [], x⟩

theorem reqOfFast_eq (x : ByteArray) : reqOfFast x = Run.reqOf x := by
  have h1 := decodeRows_eq x
  unfold reqOfFast Run.reqOf
  cases hd : decodeRows x with
  | none =>
    cases hm : decodeRequest x.toList <;> simp_all
  | some d =>
    cases hm : decodeRequest x.toList with
    | none => simp_all
    | some m =>
      simp only [hd, hm, Option.map_some, Option.some.injEq, Prod.mk.injEq] at h1
      obtain ⟨h1, h2⟩ := h1
      have hr : d.ra = .ofModel m := h1
      cases hf : m.flow.ruled
      · simp [hd, hm, hr, h2, hf, RequestBA.ofModel]
      · have hl := decodeRows_lines x d hd (by simp [hr, RequestBA.ofModel, hf]) (payNat m.programId m.paymentId)
        simp only [hr, toModel_ofModel] at hl
        have e : linesOf m = linesOfPay (payNat m.programId m.paymentId) m := rfl
        simp [hd, hm, hr, h2, hf, e, ← hl, RequestBA.ofModel, List.map_map, Function.comp_def]

def reqP : P Run.Req := do
  let x ← cutA (← num 4)
  unless x.size ≤ maxRequestBytes do throw .RECORD
  let some e := reqOfFast x | throw .RECORD
  pure e

def manyP {α : Type} (n : Nat) (f : P α) : P (List α) := do
  let mut out : Array α := #[]
  for _ in [0:n] do out := out.push (← f)
  pure out.toList

def authP : P Auth := do
  let pin ← cutB 64
  let fp ← num 1
  let fv ← num 8
  unless fp ≤ 1 && (fp == 1 || fv == 0) do throw .RECORD
  let kfloor ← num 4
  let grant ← blobP
  let keyset ← blobP
  let release ← blobP
  unless release.length == 0 || release.length == 64 do throw .RECORD
  let ksteps ← manyP (← num 4) (do pure ((← num 4), (← blobP)))
  let byps ← manyP (← num 4) blobP
  let reqs ← manyP (← num 4) reqP
  unless (match reqs with
      | [] => true
      | e0 :: _ => reqs.all fun e => e.ra.tenantId == e0.ra.tenantId && e.ra.programId == e0.ra.programId) &&
      (reqs.foldl (fun s e => s.insert e.q) (∅ : Std.HashSet Nat)).size == reqs.length do throw .RECORD
  pure { pin, floor := if fp == 1 then some fv else none, kfloor, grant, keyset, release, ksteps, byps, reqs }

def bodyP (shard batch : Nat) : P Req := do
  let today ← num 4
  let asOf ← num 4
  let prev ← cutB 64
  let nr ← num 4
  let d1 ← descP
  let d2 ← descP
  let d3 ← descP
  let d4 ← descP
  unless batch == 1 || asOf == 0 do throw .RECORD
  let dmf ← feedP dmfC d1
  let pdeath ← feedP pdeathC d2
  let excl ← feedP exclC d3
  let span ← feedP spanC d4
  let redo ← manyP nr (num payWidth)
  let auth ← authP
  pure { shard, batch, today, asOf, prev, dmf, pdeath, excl, span, redo, auth }

/-- `Frame.decodeReq` over `ByteArray`: the request and its digest. -/
def decodeReqFast (bs : ByteArray) : Except Word (Req × ByteArray) := do
  if bs.size < hdrBytes then throw .LENGTH
  unless (bs.extract 0 4).toList == magicReq && ((bs.get! 4).toNat + 256 * (bs.get! 5).toNat) == version do throw .MAGIC
  let body := bs.extract hdrBytes bs.size
  let dg := bs.extract 18 hdrBytes
  unless Bin.HB (⟨(domain "FRAME").toArray⟩ ++ body) == dg do throw .DIGEST
  let rd (p w : Nat) : Nat := Id.run do
    let mut v := 0
    for i in [0:w] do v := v * 256 + (bs.get! (p + w - 1 - i)).toNat
    pure v
  let (q, pos) ← (bodyP (rd 6 4) (rd 10 8)).run body |>.run 0
  unless pos == body.size do throw .LENGTH
  pure (q, dg)

/-- The reader `m` agrees with the spec reader `f` on the bytes from position `p`. -/
private def Mt {α β : Type} (φ : α → β) (m : P α) (f : Bytes → Except Word (β × Bytes)) : Prop :=
  ∀ (bs : ByteArray) (p : Nat), p ≤ bs.size →
    match f (bs.toList.drop p) with
    | .error w => (m.run bs).run p = .error w
    | .ok (b, r) => ∃ a p', φ a = b ∧ p ≤ p' ∧ p' ≤ bs.size ∧ r = bs.toList.drop p' ∧ (m.run bs).run p = .ok (a, p')

private theorem Mt_pure {α : Type} (a : α) : Mt id (pure a : P α) (fun r => .ok (a, r)) := by
  intro bs p hp
  exact ⟨a, p, rfl, Nat.le_refl _, hp, rfl, rfl⟩

private theorem Mt_throw {α β : Type} (φ : α → β) (w : Word) : Mt φ (throw w : P α) (fun _ => .error w) := by
  intro bs p hp
  rfl

private theorem run_bind_ok {α γ : Type} (m : P α) (g : α → P γ) (bs : ByteArray) (p : Nat) (a : α) (p' : Nat)
    (h : (m.run bs).run p = .ok (a, p')) : ((m >>= g).run bs).run p = ((g a).run bs).run p' := by
  show StateT.run (ReaderT.run m bs >>= fun a => ReaderT.run (g a) bs) p = _
  rw [StateT.run_bind, h]
  rfl

private theorem run_bind_err {α γ : Type} (m : P α) (g : α → P γ) (bs : ByteArray) (p : Nat) (w : Word)
    (h : (m.run bs).run p = .error w) : ((m >>= g).run bs).run p = .error w := by
  show StateT.run (ReaderT.run m bs >>= fun a => ReaderT.run (g a) bs) p = _
  rw [StateT.run_bind, h]
  rfl

private theorem Mt_bind {α β γ δ : Type} {φ : α → β} {ψ : γ → δ} {m : P α} {f : Bytes → Except Word (β × Bytes)}
    {g : α → P γ} {h : β → Bytes → Except Word (δ × Bytes)} (hm : Mt φ m f) (hg : ∀ a, Mt ψ (g a) (h (φ a))) :
    Mt ψ (m >>= g) (fun r => f r >>= fun x => h x.1 x.2) := by
  intro bs p hp
  have h1 := hm bs p hp
  dsimp only
  cases hf : f (bs.toList.drop p) with
  | error w =>
    rw [hf] at h1
    simp only [bind, Except.bind]
    exact run_bind_err m g bs p w h1
  | ok x =>
    obtain ⟨b, r⟩ := x
    rw [hf] at h1
    obtain ⟨a, p', hab, hpp, hp', hr, hrun⟩ := h1
    have h2 := hg a bs p' hp'
    subst hab hr
    simp only [bind, Except.bind]
    rcases hh : h (φ a) (bs.toList.drop p') with w | ⟨c, r2⟩
    · rw [hh] at h2
      simp only
      exact (run_bind_ok m g bs p a p' hrun).trans h2
    · rw [hh] at h2
      obtain ⟨a2, p2, hc, hpp2, hp2, hr2, hrun2⟩ := h2
      simp only
      exact ⟨a2, p2, hc, Nat.le_trans hpp hpp2, hp2, hr2, (run_bind_ok m g bs p a p' hrun).trans hrun2⟩

/-- `unless c do throw w`. -/
private theorem Mt_unless (c : Bool) (w : Word) :
    Mt id (if c = true then pure () else throw w : P Unit) (fun r => if c = true then .ok ((), r) else .error w) := by
  cases c
  · exact Mt_throw id w
  · exact Mt_pure ()

private theorem run_read (bs : ByteArray) (p : Nat) : ((read : P ByteArray).run bs).run p = .ok (bs, p) := rfl
private theorem run_get (bs : ByteArray) (p : Nat) : (((get : P Nat)).run bs).run p = .ok (p, p) := rfl

private theorem num_run' (w : Nat) (bs : ByteArray) (p : Nat) :
    ((num w).run bs).run p = if p + w ≤ bs.size then
      .ok ((List.range' 0 w).foldl (fun v i => v * 256 + (bs.get! (p + w - 1 - i)).toNat) 0, p + w) else .error .LENGTH := by
  unfold num
  refine (run_bind_ok _ _ bs p bs p (run_read bs p)).trans ?_
  refine (run_bind_ok _ _ bs p p p (run_get bs p)).trans ?_
  simp only [Std.Legacy.Range.forIn_eq_forIn_range', Std.Legacy.Range.size, Nat.sub_zero, Nat.add_sub_cancel, Nat.div_one, bind_pure_comp, pure_bind, List.forIn_pure_yield_eq_foldl]
  by_cases h : p + w ≤ bs.size
  · rw [if_pos h, if_pos h]; rfl
  · rw [if_neg h, if_neg h]; rfl

private theorem cutA_run (n : Nat) (bs : ByteArray) (p : Nat) :
    ((cutA n).run bs).run p = if p + n ≤ bs.size then .ok (bs.extract p (p + n), p + n) else .error .LENGTH := by
  unfold cutA
  refine (run_bind_ok _ _ bs p bs p (run_read bs p)).trans ?_
  refine (run_bind_ok _ _ bs p p p (run_get bs p)).trans ?_
  by_cases h : p + n ≤ bs.size
  · rw [if_pos h, if_pos h]; rfl
  · rw [if_neg h, if_neg h]; rfl


private theorem Mt_congr {α β : Type} {φ : α → β} {m : P α} {f f' : Bytes → Except Word (β × Bytes)}
    (h : ∀ r, f r = f' r) (hm : Mt φ m f) : Mt φ m f' := by
  intro bs p hp
  have := hm bs p hp
  rw [← h]; exact this

private theorem Mt_bind0 {α γ δ : Type} {ψ : γ → δ} {m : P α} {f : Bytes → Except Word (α × Bytes)}
    {g : α → P γ} {h : α → Bytes → Except Word (δ × Bytes)} (hm : Mt id m f) (hg : ∀ a, Mt ψ (g a) (h a)) :
    Mt ψ (m >>= g) (fun r => f r >>= fun x => h x.1 x.2) :=
  Mt_bind hm hg

private theorem rq_len (b : ByteArray) : b.toList.length = b.size := (Bin.size_eq_length' b).symm

private theorem rq_foldl (M : List UInt8) (bs : ByteArray) (p w : Nat) (hl : M.length = w)
    (hM : ∀ j (hj : j < M.length), bs.get! (p + j) = M[j]) :
    ∀ k, k ≤ w → (List.range' 0 k).foldl (fun v i => v * 256 + (bs.get! (p + w - 1 - i)).toNat) 0 = unle (M.drop (w - k)) := by
  intro k
  induction k with
  | zero =>
    intro _
    have h0 : M.drop (w - 0) = [] := by rw [Nat.sub_zero, ← hl]; exact List.drop_length
    rw [h0]; rfl
  | succ k ih =>
    intro hk
    rw [List.range'_concat, List.foldl_append, ih (by omega)]
    simp only [List.foldl_cons, List.foldl_nil, Nat.zero_add, Nat.one_mul]
    have e1 : w - (k + 1) = w - 1 - k := by omega
    have hj : w - 1 - k < M.length := by omega
    rw [e1, List.drop_eq_getElem_cons hj]
    have e2 : w - 1 - k + 1 = w - k := by omega
    rw [e2]
    have e3 : p + w - 1 - k = p + (w - 1 - k) := by omega
    rw [e3, hM _ hj]
    simp [unle]
    omega

private theorem rq_slice (bs : ByteArray) (p w : Nat) (h : p + w ≤ bs.size) :
    (List.range' 0 w).foldl (fun v i => v * 256 + (bs.get! (p + w - 1 - i)).toNat) 0 = unle ((bs.toList.drop p).take w) := by
  have hl : ((bs.toList.drop p).take w).length = w := by
    simp [rq_len]; omega
  have := rq_foldl ((bs.toList.drop p).take w) bs p w hl (by
    intro j hj
    have hj' : p + j < bs.toList.length := by
      rw [rq_len]; rw [hl] at hj; omega
    rw [get!_lt bs _ hj']
    simp) w (Nat.le_refl _)
  rw [this]; simp

private theorem rq_cut (n : Nat) (L : List UInt8) (h : n ≤ L.length) : cut n L = .ok (L.take n, L.drop n) := by
  simp [cut, takeN, h]

private theorem rq_cut_err (n : Nat) (L : List UInt8) (h : ¬ n ≤ L.length) : cut n L = .error .LENGTH := by
  simp [cut, takeN, h]

private theorem Mt_num (w : Nat) : Mt id (num w) (numRec w) := by
  intro bs p hp
  rw [num_run']
  by_cases h : p + w ≤ bs.size
  · have hw : w ≤ (bs.toList.drop p).length := by simp [rq_len]; omega
    have e : numRec w (bs.toList.drop p) = .ok (unle ((bs.toList.drop p).take w), bs.toList.drop (p + w)) := by
      have hd : bs.toList.drop (p + w) = (bs.toList.drop p).drop w := by rw [List.drop_drop, Nat.add_comm]
      rw [hd]; unfold numRec; rw [rq_cut w _ hw]; rfl
    rw [e, if_pos h]
    exact ⟨_, p + w, (rq_slice bs p w h).symm ▸ rfl, by omega, h, rfl, rfl⟩
  · have hw : ¬ w ≤ (bs.toList.drop p).length := by simp [rq_len]; omega
    simp only [numRec, rq_cut_err w _ hw, if_neg h]
    rfl

private theorem Mt_cutA (n : Nat) : Mt ByteArray.toList (cutA n) (cut n) := by
  intro bs p hp
  rw [cutA_run]
  by_cases h : p + n ≤ bs.size
  · have hw : n ≤ (bs.toList.drop p).length := by simp [rq_len]; omega
    rw [rq_cut n _ hw, if_pos h]
    refine ⟨_, p + n, ?_, by omega, h, ?_, rfl⟩
    · rw [Bin.toList_extract']; simp
    · simp [List.drop_drop, Nat.add_comm]
  · have hw : ¬ n ≤ (bs.toList.drop p).length := by simp [rq_len]; omega
    rw [rq_cut_err n _ hw, if_neg h]

private theorem Mt_cutB (n : Nat) : Mt id (cutB n) (cut n) := by
  refine Mt_congr ?_ (Mt_bind (Mt_cutA n) (fun a => Mt_pure a.toList) (h := fun b r => .ok (b, r)))
  intro r
  cases cut n r <;> rfl

private theorem Mt_blobP : Mt id blobP blobRec := by
  refine Mt_congr ?_ (Mt_bind0 (Mt_num 4) (fun a => Mt_cutB a) (h := fun a r => cut a r))
  intro r
  rfl


private theorem nums_cons (w : Nat) (ws : List Nat) (r : Bytes) :
    nums (w :: ws) r = (numRec w r >>= fun x => nums ws x.2 >>= fun y => .ok (x.1 :: y.1, y.2)) := by
  simp only [nums]
  unfold numRec
  rcases cut w r with e | ⟨a, r1⟩
  · rfl
  · rcases nums ws r1 with e | ⟨l, r2⟩ <;> rfl

private theorem Mt_mapM (ws : List Nat) : Mt id (ws.mapM num) (nums ws) := by
  induction ws with
  | nil => exact Mt_congr (fun r => rfl) (Mt_pure ([] : List Nat))
  | cons w ws ih =>
    rw [List.mapM_cons]
    refine Mt_congr (fun r => (nums_cons w ws r).symm) (Mt_bind0 (h := fun a r => nums ws r >>= fun y => .ok (a :: y.1, y.2))
      (Mt_num w) (fun a => ?_))
    exact Mt_bind0 (h := fun l r => .ok (a :: l, r)) ih (fun l => Mt_pure (a :: l))

private theorem Mt_opt {α : Type} (o : Option α) (w : Word) :
    Mt id (match o with | some x => pure x | _ => throw w : P α) (fun r => match o with | some x => .ok (x, r) | _ => .error w) := by
  cases o
  · exact Mt_throw id w
  · exact Mt_pure _

private theorem Mt_rowP {α : Type} (c : RowCodec α) : Mt id (rowP c) (feedRow c) := by
  unfold rowP
  refine Mt_congr (fun r => ?_) (Mt_bind0 (h := fun ns r => match c.ofNums ns with | some x => Except.ok (x, r) | _ => .error .RECORD)
    (Mt_mapM c.widths) (fun ns => Mt_opt (c.ofNums ns) .RECORD))
  unfold feedRow
  rcases nums c.widths r with e | ⟨ns, r1⟩ <;> rfl

private theorem rq_many_succ {α : Type} (g : Bytes → Except Word (α × Bytes)) (k : Nat) (r : Bytes) :
    many g (k + 1) r = (g r >>= fun x => (many g k x.2).map (fun y => (x.1 :: y.1, y.2))) := by
  simp only [many]
  rcases g r with e | ⟨a, r1⟩
  · rfl
  · rcases many g k r1 with e | ⟨l, r2⟩ <;> rfl

private theorem Mt_forIn_aux {α : Type} {f : P α} {g : Bytes → Except Word (α × Bytes)} (hf : Mt id f g)
    (step : Nat → Array α → P (ForInStep (Array α)))
    (hs : ∀ i acc, step i acc = (f >>= fun x => pure (ForInStep.yield (acc.push x)))) :
    ∀ (k s : Nat) (acc : Array α), Mt id (forIn (List.range' s k) acc step)
      (fun r => (many g k r).map (fun y => (acc ++ y.1.toArray, y.2))) := by
  intro k
  induction k with
  | zero =>
    intro s acc
    show Mt id (forIn ([] : List Nat) acc step) _
    rw [List.forIn_nil]
    exact Mt_congr (fun r => by simp [many] <;> rfl) (Mt_pure acc)
  | succ k ih =>
    intro s acc
    rw [List.range'_succ, List.forIn_cons, hs]
    simp only [bind_assoc, pure_bind]
    refine Mt_congr (fun r => ?_) (Mt_bind0 (h := fun x r => (many g k r).map (fun y => (acc.push x ++ y.1.toArray, y.2)))
      hf (fun x => ih (s + 1) (acc.push x)))
    rw [rq_many_succ]
    cases hg : g r with
    | error e => rfl
    | ok x =>
      obtain ⟨a, r1⟩ := x
      cases hm : many g k r1 with
      | error e => simp [bind, Except.bind, hm] <;> rfl
      | ok y =>
        obtain ⟨l, r2⟩ := y
        simp [bind, Except.bind, hm] <;> rfl


private theorem Mt_manyP {α : Type} {f : P α} {g : Bytes → Except Word (α × Bytes)} (hf : Mt id f g) (n : Nat) :
    Mt id (manyP n f) (many g n) := by
  unfold manyP
  simp only [Std.Legacy.Range.forIn_eq_forIn_range', Std.Legacy.Range.size, Nat.sub_zero, Nat.add_sub_cancel, Nat.div_one]
  refine Mt_congr (fun r => ?_) (Mt_bind0 (h := fun (a : Array α) r => .ok (a.toList, r))
    (Mt_forIn_aux hf _ (by intro i acc; rfl) n 0 #[]) (fun a => Mt_pure a.toList))
  cases many g n r with
  | error e => rfl
  | ok y => simp [bind, Except.bind] <;> rfl

private theorem Mt_feedP {α : Type} (c : RowCodec α) (d : Nat × Nat × Nat × Nat × Bytes) : Mt id (feedP c d) (feed c d) := by
  obtain ⟨st, a, n, k, pin⟩ := d
  unfold feedP
  simp only [Std.Legacy.Range.forIn_eq_forIn_range', Std.Legacy.Range.size, Nat.sub_zero, Nat.add_sub_cancel, Nat.div_one]
  refine Mt_congr (fun r => ?_) (Mt_bind0 (h := fun (rows : Array α) r => .ok (⟨st, a, n, rows.toList, pin⟩, r))
    (Mt_forIn_aux (Mt_rowP c) _ (by intro i acc; rfl) k 0 #[]) (fun rows => Mt_pure _))
  unfold feed
  dsimp only
  cases many (feedRow c) k r with
  | error e => rfl
  | ok y => simp [bind, Except.bind] <;> rfl

private theorem desc_eq (r : Bytes) : desc r = (numRec 1 r >>= fun x1 => numRec 4 x1.2 >>= fun x2 => numRec 4 x2.2 >>=
    fun x3 => numRec 4 x3.2 >>= fun x4 => cut 64 x4.2 >>= fun x5 =>
      if (x1.1 ≤ 2 && (x1.1 == 1 || (x2.1 == 0 && x3.1 == 0 && x4.1 == 0 && x5.1 == zeroDigest))) = true
      then Except.ok ((x1.1, x2.1, x3.1, x4.1, x5.1), x5.2) else Except.error .RECORD) := by
  simp only [desc, nums_cons, nums, numRec]
  rcases cut 1 r with e | ⟨a1, r1⟩
  · rfl
  dsimp only [bind, Except.bind, pure, Except.pure]
  rcases cut 4 r1 with e | ⟨a2, r2⟩
  · rfl
  dsimp only [bind, Except.bind, pure, Except.pure]
  rcases cut 4 r2 with e | ⟨a3, r3⟩
  · rfl
  dsimp only [bind, Except.bind, pure, Except.pure]
  rcases cut 4 r3 with e | ⟨a4, r4⟩
  · rfl
  dsimp only [bind, Except.bind, pure, Except.pure]
  rcases cut 64 r4 with e | ⟨a5, r5⟩
  · rfl
  dsimp only [bind, Except.bind, pure, Except.pure]
  by_cases hc : (decide (unle a1 ≤ 2) && (unle a1 == 1 || unle a2 == 0 && unle a3 == 0 && unle a4 == 0 && a5 == zeroDigest)) = true
  · rw [if_pos hc, if_pos hc]
  · rw [if_neg hc, if_neg hc]; rfl

private theorem Mt_chk {α : Type} (c : Bool) (w : Word) (v : α) :
    Mt id (do
      unless c do throw w
      pure v : P α) (fun r => if c = true then .ok (v, r) else .error w) := by
  cases c
  · exact Mt_congr (fun r => rfl) (Mt_bind0 (h := fun _ r => .ok (v, r)) (Mt_unless false w) (fun _ => Mt_pure v))
  · exact Mt_congr (fun r => rfl) (Mt_bind0 (h := fun _ r => .ok (v, r)) (Mt_unless true w) (fun _ => Mt_pure v))

private theorem Mt_descP : Mt id descP desc := by
  unfold descP
  refine Mt_congr ?_ (Mt_bind0 (h := fun st r => numRec 4 r >>= fun x2 => numRec 4 x2.2 >>=
    fun x3 => numRec 4 x3.2 >>= fun x4 => cut 64 x4.2 >>= fun x5 =>
      if (st ≤ 2 && (st == 1 || (x2.1 == 0 && x3.1 == 0 && x4.1 == 0 && x5.1 == zeroDigest))) = true
      then Except.ok ((st, x2.1, x3.1, x4.1, x5.1), x5.2) else Except.error .RECORD) (Mt_num 1) (fun st => ?_))
  · intro r; exact (desc_eq r).symm
  refine Mt_bind0 (h := fun a r => numRec 4 r >>= fun x3 => numRec 4 x3.2 >>= fun x4 => cut 64 x4.2 >>= fun x5 =>
      if (st ≤ 2 && (st == 1 || (a == 0 && x3.1 == 0 && x4.1 == 0 && x5.1 == zeroDigest))) = true
      then Except.ok ((st, a, x3.1, x4.1, x5.1), x5.2) else Except.error .RECORD) (Mt_num 4) (fun a => ?_)
  refine Mt_bind0 (h := fun c r => numRec 4 r >>= fun x4 => cut 64 x4.2 >>= fun x5 =>
      if (st ≤ 2 && (st == 1 || (a == 0 && c == 0 && x4.1 == 0 && x5.1 == zeroDigest))) = true
      then Except.ok ((st, a, c, x4.1, x5.1), x5.2) else Except.error .RECORD) (Mt_num 4) (fun c => ?_)
  refine Mt_bind0 (h := fun n r => cut 64 r >>= fun x5 =>
      if (st ≤ 2 && (st == 1 || (a == 0 && c == 0 && n == 0 && x5.1 == zeroDigest))) = true
      then Except.ok ((st, a, c, n, x5.1), x5.2) else Except.error .RECORD) (Mt_num 4) (fun n => ?_)
  refine Mt_congr (fun r => rfl) (Mt_bind0 (h := fun pin r =>
      if (st ≤ 2 && (st == 1 || (a == 0 && c == 0 && n == 0 && pin == zeroDigest))) = true
      then Except.ok ((st, a, c, n, pin), r) else Except.error .RECORD) (Mt_cutB 64)
    (fun pin => Mt_chk _ .RECORD (st, a, c, n, pin)))


private theorem Mt_chkP {α β : Type} {φ : α → β} {m : P α} {f : Bytes → Except Word (β × Bytes)} (c : Prop) [Decidable c]
    (w : Word) (hm : Mt φ m f) :
    Mt φ (do
      unless c do throw w
      m) (fun r => if c then f r else .error w) := by
  by_cases hc : c
  · have e : (do
        unless c do throw w
        m : P α) = m := by simp [hc]
    rw [e]
    exact Mt_congr (fun r => by rw [if_pos hc]) hm
  · have e : (do
        unless c do throw w
        m : P α) = (throw w : P Unit) >>= fun _ => m := by simp [hc]
    rw [e]
    exact Mt_congr (fun r => by rw [if_neg hc]; rfl) (Mt_bind0 (h := fun _ r => f r) (Mt_throw (id : Unit → Unit) w) (fun _ => hm))

private theorem rq_ba (a : ByteArray) : a.toList.toByteArray = a := by
  apply ByteArray.ext
  apply Array.toList_inj.mp
  rw [← Bin.toList_eq', ← Bin.toList_eq', Bin.toList_toByteArray]

private theorem Mt_reqP : Mt id reqP reqRec := by
  unfold reqP
  refine Mt_congr (fun r => ?_) (Mt_bind0 (h := fun n r => cut n r >>= fun x =>
      if x.1.length ≤ maxRequestBytes then
        (match Run.reqOf x.1.toByteArray with | some e => Except.ok (e, x.2) | _ => Except.error .RECORD)
      else Except.error .RECORD) (Mt_num 4) (fun n => ?_))
  · unfold reqRec blobRec
    rcases numRec 4 r with e | ⟨n, r1⟩
    · rfl
    dsimp only [bind, Except.bind, pure, Except.pure]
    rcases cut n r1 with e | ⟨x, r2⟩
    · rfl
    dsimp only [bind, Except.bind, pure, Except.pure]
    by_cases hc : x.length ≤ maxRequestBytes
    · rw [if_pos hc, if_pos hc]; rfl
    · rw [if_neg hc, if_neg hc]; rfl
  · refine Mt_bind (φ := ByteArray.toList) (h := fun b r =>
      if b.length ≤ maxRequestBytes then
        (match Run.reqOf b.toByteArray with | some e => Except.ok (e, r) | _ => Except.error .RECORD)
      else Except.error .RECORD) (Mt_cutA n) (fun a => ?_)
    have hm : Mt id (do
        let some e := reqOfFast a | throw .RECORD
        pure e : P Run.Req) (fun r => match reqOfFast a with | some e => Except.ok (e, r) | _ => Except.error .RECORD) := by
      rcases reqOfFast a with _ | e
      · exact Mt_throw id _
      · exact Mt_pure e
    refine Mt_congr (fun r => ?_) (Mt_chkP (a.size ≤ maxRequestBytes) .RECORD hm)
    rw [rq_ba, rq_len, reqOfFast_eq]

private abbrev S := StateT Bytes (Except Word)

private def MtS {α β : Type} (φ : α → β) (m : P α) (s : S β) : Prop := Mt φ m (fun r => s.run r)

private theorem MtS_pure {α : Type} (a : α) : MtS id (pure a : P α) (pure a : S α) := Mt_pure a

private theorem MtS_throw {α β : Type} (φ : α → β) (w : Word) : MtS φ (throw w : P α) (throw w : S β) := Mt_throw φ w

private theorem MtS_bind {α β γ δ : Type} {φ : α → β} {ψ : γ → δ} {m : P α} {s : S β} {g : α → P γ} {t : β → S δ}
    (hm : MtS φ m s) (hg : ∀ a, MtS ψ (g a) (t (φ a))) : MtS ψ (m >>= g) (s >>= t) :=
  Mt_bind (h := fun b r => (t b).run r) hm hg

private theorem MtS_unless {α β : Type} {φ : α → β} {m : P α} {s : S β} (c1 c2 : Prop) [Decidable c1] [Decidable c2]
    (w : Word) (h : c1 ↔ c2) (hm : MtS φ m s) :
    MtS φ (do
      unless c1 do throw w
      m) (do
      unless c2 do throw w
      s) := by
  by_cases hc : c1
  · have hc2 := h.mp hc
    have e1 : (do
        unless c1 do throw w
        m : P α) = m := by simp [hc]
    have e2 : (do
        unless c2 do throw w
        s : S β) = s := by simp [hc2]
    rw [e1, e2]; exact hm
  · have hc2 : ¬ c2 := fun h2 => hc (h.mpr h2)
    have e1 : (do
        unless c1 do throw w
        m : P α) = (throw w : P Unit) >>= fun _ => m := by simp [hc]
    have e2 : (do
        unless c2 do throw w
        s : S β) = (throw w : S Unit) >>= fun _ => s := by simp [hc2]
    rw [e1, e2]
    exact MtS_bind (φ := (id : Unit → Unit)) (MtS_throw id w) (fun _ => hm)

private def numS (w : Nat) : S Nat := fun r => numRec w r
private def cutS (n : Nat) : S Bytes := fun r => cut n r
private def blobS : S Bytes := fun r => blobRec r
private def reqS : S Run.Req := fun r => reqRec r
private def kstepS : S (Nat × Bytes) := fun r => kstepRec r
private def descS : S (Nat × Nat × Nat × Nat × Bytes) := fun r => desc r
private def feedS {α : Type} (c : RowCodec α) (d : Nat × Nat × Nat × Nat × Bytes) : S (Feed α) := fun r => feed c d r
private def manyS {α : Type} (f : S α) (n : Nat) : S (List α) := fun r => many (fun r => f.run r) n r

private theorem MtS_num (w : Nat) : MtS id (num w) (numS w) := Mt_num w
private theorem MtS_cutB (n : Nat) : MtS id (cutB n) (cutS n) := Mt_cutB n
private theorem MtS_blobP : MtS id blobP blobS := Mt_blobP
private theorem MtS_reqP : MtS id reqP reqS := Mt_reqP
private theorem MtS_descP : MtS id descP descS := Mt_descP
private theorem MtS_feedP {α : Type} (c : RowCodec α) (d : Nat × Nat × Nat × Nat × Bytes) : MtS id (feedP c d) (feedS c d) :=
  Mt_feedP c d
private theorem MtS_manyP {α : Type} {f : P α} {s : S α} (hf : MtS id f s) (n : Nat) : MtS id (manyP n f) (manyS s n) :=
  Mt_manyP hf n

private theorem MtS_kstep : MtS id (do pure ((← num 4), (← blobP)) : P (Nat × Bytes)) kstepS := by
  have e : kstepS = (do let d ← numS 4; let x ← blobS; pure (d, x) : S (Nat × Bytes)) := rfl
  rw [e]
  exact MtS_bind (MtS_num 4) (fun d => MtS_bind MtS_blobP (fun x => MtS_pure _))

private theorem hs_fold_le (l : List Run.Req) : ∀ s : Std.HashSet Nat,
    (l.foldl (fun s e => s.insert e.q) s).size ≤ s.size + l.length := by
  induction l with
  | nil => intro s; simp
  | cons e t ih =>
    intro s
    simp only [List.foldl_cons, List.length_cons]
    have := ih (s.insert e.q)
    have h2 : (s.insert e.q).size ≤ s.size + 1 := Std.HashSet.size_insert_le
    omega

private theorem hs_iff (l : List Run.Req) : ∀ s : Std.HashSet Nat,
    ((l.foldl (fun s e => s.insert e.q) s).size = s.size + l.length) ↔
    (l.Pairwise (fun a b => a.q != b.q) ∧ ∀ e ∈ l, e.q ∉ s) := by
  induction l with
  | nil => intro s; simp
  | cons e t ih =>
    intro s
    simp only [List.foldl_cons, List.length_cons, List.pairwise_cons, List.mem_cons, forall_eq_or_imp]
    have hle := hs_fold_le t (s.insert e.q)
    have hsz : (s.insert e.q).size = if e.q ∈ s then s.size else s.size + 1 := Std.HashSet.size_insert
    by_cases hm : e.q ∈ s
    · rw [if_pos hm] at hsz
      constructor
      · intro h; omega
      · intro h; exact absurd hm h.2.1
    · rw [if_neg hm] at hsz
      have key : ((t.foldl (fun s e => s.insert e.q) (s.insert e.q)).size = s.size + (t.length + 1)) ↔
          ((t.foldl (fun s e => s.insert e.q) (s.insert e.q)).size = (s.insert e.q).size + t.length) := by omega
      rw [key, ih (s.insert e.q)]
      simp only [Std.HashSet.mem_insert, not_or]
      constructor
      · rintro ⟨hp, hall⟩
        refine ⟨⟨fun b hb => ?_, hp⟩, hm, fun x hx => (hall x hx).2⟩
        have := (hall b hb).1
        simpa using this
      · rintro ⟨⟨h1, hp⟩, _, h3⟩
        refine ⟨hp, fun x hx => ⟨?_, h3 x hx⟩⟩
        have := h1 x hx
        simpa using this

private theorem hs_pw (l : List Run.Req) :
    ((l.foldl (fun s e => s.insert e.q) (∅ : Std.HashSet Nat)).size == l.length) = true ↔
      l.Pairwise (fun a b => a.q != b.q) := by
  have := hs_iff l ∅
  simp only [Std.HashSet.size_empty, Nat.zero_add, Std.HashSet.not_mem_empty, not_false_eq_true, implies_true, and_true] at this
  simpa using this

/-- `hs_pw`, for the engine's request decoder. -/
theorem hs_pw_pub (l : List Run.Req) :
    ((l.foldl (fun s e => s.insert e.q) (∅ : Std.HashSet Nat)).size == l.length) = true ↔
      l.Pairwise (fun a b => a.q != b.q) := hs_pw l

private def authS : S Auth := do
  let pin ← cutS 64
  let fp ← numS 1
  let fv ← numS 8
  unless fp ≤ 1 && (fp == 1 || fv == 0) do throw .RECORD
  let kfloor ← numS 4
  let grant ← blobS
  let keyset ← blobS
  let release ← blobS
  unless release.length == 0 || release.length == 64 do throw .RECORD
  let ksteps ← manyS kstepS (← numS 4)
  let byps ← manyS blobS (← numS 4)
  let reqs ← manyS reqS (← numS 4)
  unless reqs.Pairwise (fun a b => a.q != b.q) && (match reqs with | [] => true | e0 :: _ => reqs.all fun e => e.r.tenantId == e0.r.tenantId && e.r.programId == e0.r.programId) do
    throw .RECORD
  pure { pin, floor := if fp == 1 then some fv else none, kfloor, grant, keyset, release, ksteps, byps, reqs }

private theorem nums2e (w1 w2 : Nat) (r : Bytes) : nums [w1, w2] r =
    (numRec w1 r >>= fun a => numRec w2 a.2 >>= fun b => Except.ok ([a.1, b.1], b.2)) := by
  simp only [nums, numRec]
  rcases cut w1 r with e | ⟨a1, r1⟩
  · rfl
  dsimp only [bind, Except.bind, pure, Except.pure]
  rcases cut w2 r1 with e | ⟨a2, r2⟩
  · rfl
  dsimp only [bind, Except.bind, pure, Except.pure]

private theorem ite_app {α : Type} (c : Prop) [Decidable c] (f g : S α) (x : Bytes) :
    (if c then f else g) x = if c then f x else g x := by split <;> rfl

private theorem authRec_eq (r : Bytes) : authRec r = authS.run r := by
  have e1 : (cutS 64).run r = cut 64 r := rfl
  unfold authRec authS
  rw [StateT.run_bind, e1]
  rcases cut 64 r with e | ⟨pin, r1⟩
  · rfl
  dsimp only [bind, Except.bind]
  rw [nums2e 1 8]
  try unfold StateT.bind
  try simp only [StateT.run, numS]
  rcases numRec 1 r1 with e | ⟨fp, r2⟩
  · rfl
  dsimp only [bind, Except.bind]
  try unfold StateT.bind
  try simp only [StateT.run, numS]
  rcases numRec 8 r2 with e | ⟨fv, r3⟩
  · rfl
  dsimp only [bind, Except.bind]
  simp only [ite_app]
  rfl

private theorem ba_beq (a b : ByteArray) : (a == b) = true ↔ a = b :=
  (beq_iff_eq (a := a.data) (b := b.data)).trans ByteArray.ext_iff.symm

private theorem ba_toList_inj (a b : ByteArray) : a.toList = b.toList ↔ a = b := by
  constructor
  · intro h; rw [← rq_ba a, ← rq_ba b, h]
  · intro h; rw [h]

private theorem same_tp (e e0 : Run.Req) :
    (e.ra.tenantId == e0.ra.tenantId && e.ra.programId == e0.ra.programId) =
    (e.r.tenantId == e0.r.tenantId && e.r.programId == e0.r.programId) := by
  rw [Bool.eq_iff_iff]
  simp only [Bool.and_eq_true, ba_beq, beq_iff_eq, Run.Req.r, RequestBA.toModel, ba_toList_inj]

private theorem MtS_authP : MtS id authP authS := by
  unfold authP authS
  refine MtS_bind (MtS_cutB 64) (fun pin => MtS_bind (MtS_num 1) (fun fp => MtS_bind (MtS_num 8) (fun fv => ?_)))
  refine MtS_unless _ _ .RECORD Iff.rfl ?_
  refine MtS_bind (MtS_num 4) (fun kfloor => ?_)
  refine MtS_bind MtS_blobP (fun grant => MtS_bind MtS_blobP (fun keyset => MtS_bind MtS_blobP (fun release => ?_)))
  refine MtS_unless _ _ .RECORD Iff.rfl ?_
  refine MtS_bind (MtS_num 4) (fun nk => MtS_bind (MtS_manyP MtS_kstep nk) (fun ksteps => ?_))
  refine MtS_bind (MtS_num 4) (fun nb => MtS_bind (MtS_manyP MtS_blobP nb) (fun byps => ?_))
  refine MtS_bind (MtS_num 4) (fun nq => MtS_bind (MtS_manyP MtS_reqP nq) (fun reqs => ?_))
  refine MtS_unless _ _ .RECORD ?_ (MtS_pure _)
  dsimp only [id]
  simp only [Bool.and_eq_true, decide_eq_true_eq, hs_pw]
  cases reqs with
  | nil => simp
  | cons e0 t => simp only [same_tp]; exact and_comm

private def bodyS (shard batch : Nat) : S Req := do
  let today ← numS 4
  let asOf ← numS 4
  let prev ← cutS 64
  let nr ← numS 4
  let d1 ← descS
  let d2 ← descS
  let d3 ← descS
  let d4 ← descS
  unless batch == 1 || asOf == 0 do throw .RECORD
  let dmf ← feedS dmfC d1
  let pdeath ← feedS pdeathC d2
  let excl ← feedS exclC d3
  let span ← feedS spanC d4
  let redo ← manyS (numS payWidth) nr
  let auth ← authS
  pure { shard, batch, today, asOf, prev, dmf, pdeath, excl, span, redo, auth }

private theorem MtS_bodyP (shard batch : Nat) : MtS id (bodyP shard batch) (bodyS shard batch) := by
  unfold bodyP bodyS
  refine MtS_bind (MtS_num 4) (fun today => MtS_bind (MtS_num 4) (fun asOf => MtS_bind (MtS_cutB 64) (fun prev =>
    MtS_bind (MtS_num 4) (fun nr => MtS_bind MtS_descP (fun d1 => MtS_bind MtS_descP (fun d2 =>
    MtS_bind MtS_descP (fun d3 => MtS_bind MtS_descP (fun d4 => ?_))))))))
  refine MtS_unless _ _ .RECORD Iff.rfl ?_
  refine MtS_bind (MtS_feedP _ _) (fun dmf => MtS_bind (MtS_feedP _ _) (fun pdeath => MtS_bind (MtS_feedP _ _)
    (fun excl => MtS_bind (MtS_feedP _ _) (fun span => MtS_bind (MtS_manyP (MtS_num payWidth) nr) (fun redo =>
    MtS_bind MtS_authP (fun auth => MtS_pure _))))))

private theorem bind_ok' {α β : Type} (a : α) (f : α → Except Word β) : (Except.ok a >>= f) = f a := rfl

private theorem bodyRec_eq (s b : Nat) (dg : Bytes) (r : Bytes) : decodeBody ⟨s, b, dg⟩ r = (bodyS s b).run r := by
  unfold decodeBody decodePre bodyS
  have e1 : (numS 4).run r = numRec 4 r := rfl
  rw [nums2e 4 4, StateT.run_bind, e1]
  rcases numRec 4 r with e | ⟨a, r1⟩
  · (try dsimp only [bind, Except.bind]); (try rfl)
  simp only [bind_ok']
  have e2 : (numS 4).run r1 = numRec 4 r1 := rfl
  rw [StateT.run_bind, e2]
  rcases numRec 4 r1 with e | ⟨b2, r2⟩
  · (try dsimp only [bind, Except.bind]); (try rfl)
  simp only [bind_ok']
  by_cases hc : (b == 1 || b2 == 0) = true
  · simp only [bind_ok', bind_assoc, pure_bind, if_pos hc, ite_app, authRec_eq]
    rfl
  · simp only [bind_ok', bind_assoc, pure_bind, if_neg hc, ite_app, authRec_eq]
    rfl

private theorem body_fin (sh b : Nat) (body : ByteArray) (dgA : ByteArray) :
    ((do
      let (q, pos) ← ((bodyP sh b).run body).run 0
      unless pos == body.size do throw .LENGTH
      pure (q, dgA) : Except Word (Req × ByteArray))).map (fun (q, d) => (q, d.toList)) =
    (do
      let (q, rest) ← decodeBody ⟨sh, b, dgA.toList⟩ body.toList
      unless rest.isEmpty do throw .LENGTH
      pure (q, dgA.toList) : Except Word (Req × Bytes)) := by
  have hM := MtS_bodyP sh b body 0 (Nat.zero_le _)
  simp only [List.drop_zero] at hM
  rw [← bodyRec_eq sh b dgA.toList] at hM
  rcases hd : decodeBody ⟨sh, b, dgA.toList⟩ body.toList with w | ⟨q, rest⟩
  · rw [hd] at hM
    simp only [hM]
    rfl
  · rw [hd] at hM
    obtain ⟨a, p', hq, _, hp', hr, hrun⟩ := hM
    simp only [hrun]
    subst hq
    by_cases hz : p' = body.size
    · have h0 : rest = [] := by
        rw [hr, List.drop_eq_nil_iff, rq_len]; omega
      subst h0
      dsimp only [bind, Except.bind, pure, Except.pure]
      first | (simp [hz]; done) | (simp [hz]; rfl) | rfl
    · have h0 : rest ≠ [] := by
        intro h
        rw [hr, List.drop_eq_nil_iff, rq_len] at h
        omega
      dsimp only [bind, Except.bind, pure, Except.pure]
      first | (simp [hz, h0]; done) | (simp [hz, h0]; rfl) | rfl

private theorem rd_eq (bs : ByteArray) (p w : Nat) (h : p + w ≤ bs.size) :
    (Id.run do
      let mut v := 0
      for i in [0:w] do v := v * 256 + (bs.get! (p + w - 1 - i)).toNat
      pure v) = unle ((bs.toList.drop p).take w) := by
  rw [← rq_slice bs p w h]
  simp only [Std.Legacy.Range.forIn_eq_forIn_range', Std.Legacy.Range.size, Nat.sub_zero, Nat.add_sub_cancel, Nat.div_one, bind_pure_comp, pure_bind, List.forIn_pure_yield_eq_foldl]
  rfl

private theorem hdr_slice (L : List UInt8) (p w : Nat) (h : p + w ≤ 82) :
    ((L.take 82).drop p).take w = (L.drop p).take w := by
  rw [List.drop_take, List.take_take]
  congr 1
  omega

private theorem ver_eq (bs : ByteArray) (h : 6 ≤ bs.size) :
    unle ((bs.toList.drop 4).take 2) = (bs.get! 4).toNat + 256 * (bs.get! 5).toNat := by
  have := rq_slice bs 4 2 (by omega)
  rw [← this]
  simp [List.range']
  omega

private theorem body_list (bs : ByteArray) : (bs.extract hdrBytes bs.size).toList = bs.toList.drop hdrBytes := by
  rw [Bin.toList_extract']
  apply List.take_of_length_le
  rw [List.length_drop, rq_len]
  omega

private theorem decodeReqFast_eq' (H : Bytes → Bytes) (hH : ∀ b, H b = (Bin.HB ⟨b.toArray⟩).toList) (bs : ByteArray) :
    (decodeReqFast bs).map (fun (q, d) => (q, d.toList)) = decodeReq H bs.toList := by
  by_cases hs : bs.size < hdrBytes
  · have h2 : ¬ hdrBytes ≤ bs.toList.length := by rw [rq_len]; omega
    have hT : takeN hdrBytes bs.toList = none := by simp [takeN, h2]
    unfold decodeReqFast decodeReq decodeHdr
    rw [if_pos hs, hT]
    rfl
  · have hs' : hdrBytes ≤ bs.size := by omega
    have h2 : hdrBytes ≤ bs.toList.length := by rw [rq_len]; exact hs'
    have h82 : hdrBytes = 82 := rfl
    have hmag : ((bs.extract 0 4).toList == magicReq && ((bs.get! 4).toNat + 256 * (bs.get! 5).toNat) == version) =
        ((bs.toList.take hdrBytes).take 4 == magicReq && unle (((bs.toList.take hdrBytes).drop 4).take 2) == version) := by
      rw [h82, hdr_slice _ 4 2 (by omega), ver_eq bs (by omega), Bin.toList_extract', List.take_take]
      simp
    have hdg : (bs.extract 18 hdrBytes).toList = (bs.toList.take hdrBytes).drop 18 := by
      rw [Bin.toList_extract', List.drop_take]
    have hdig : (Bin.HB (⟨(domain "FRAME").toArray⟩ ++ bs.extract hdrBytes bs.size) == bs.extract 18 hdrBytes) =
        (H (domain "FRAME" ++ bs.toList.drop hdrBytes) == (bs.toList.take hdrBytes).drop 18) := by
      have hA : (⟨(domain "FRAME").toArray⟩ ++ bs.extract hdrBytes bs.size : ByteArray) =
          ⟨(domain "FRAME" ++ bs.toList.drop hdrBytes).toArray⟩ := by
        rw [← ba_toList_inj, Bin.toList_append', body_list]
        simp [Bin.toList_eq']
      rw [Bool.eq_iff_iff, ba_beq, beq_iff_eq, ← ba_toList_inj, hdg, hH, hA]
    have hr6 : (Id.run do
        let mut v := 0
        for i in [0:4] do v := v * 256 + (bs.get! (6 + 4 - 1 - i)).toNat
        pure v) = unle (((bs.toList.take hdrBytes).drop 6).take 4) := by
      rw [rd_eq bs 6 4 (by omega), h82, hdr_slice _ 6 4 (by omega)]
    have hr10 : (Id.run do
        let mut v := 0
        for i in [0:8] do v := v * 256 + (bs.get! (10 + 8 - 1 - i)).toNat
        pure v) = unle (((bs.toList.take hdrBytes).drop 10).take 8) := by
      rw [rd_eq bs 10 8 (by omega), h82, hdr_slice _ 10 8 (by omega)]
    have hT : takeN hdrBytes bs.toList = some (bs.toList.take hdrBytes, bs.toList.drop hdrBytes) := by
      simp [takeN, h2]
    unfold decodeReqFast decodeReq decodeHdr
    rw [if_neg hs, hT, hmag]
    dsimp only
    by_cases hm : ((bs.toList.take hdrBytes).take 4 == magicReq &&
        unle (((bs.toList.take hdrBytes).drop 4).take 2) == version) = true
    · simp only [hm, if_true, pure_bind]
      rw [hdig]
      by_cases hd2 : (H (domain "FRAME" ++ bs.toList.drop hdrBytes) == (bs.toList.take hdrBytes).drop 18) = true
      · simp only [hd2, if_true]
        dsimp only at hr6 hr10
        rw [hr6, hr10]
        have key := body_fin (unle (((bs.toList.take hdrBytes).drop 6).take 4))
          (unle (((bs.toList.take hdrBytes).drop 10).take 8)) (bs.extract hdrBytes bs.size) (bs.extract 18 hdrBytes)
        rw [body_list, hdg] at key
        exact key
      · simp only [hd2, Bool.false_eq_true, if_false]
        rfl
    · simp only [hm, Bool.false_eq_true, if_false]
      rfl

/-- `Frame.decodeReq` read as bytes. -/
theorem decodeReqFast_eq (H : Bytes → Bytes) (hH : ∀ b, H b = (Bin.HB ⟨b.toArray⟩).toList) (bs : ByteArray) :
    (decodeReqFast bs).map (fun (q, d) => (encodeReq H q, d.toList)) =
      (decodeReq H bs.toList).map (fun (q, d) => (encodeReq H q, d)) := by
  rw [← decodeReqFast_eq' H hH bs]
  cases decodeReqFast bs with
  | error w => rfl
  | ok x => rfl

/-- The body read in place at the header's end is the body read from its own start, the positions shifted. -/
theorem bodyP_shift (sh b : Nat) (bs : ByteArray) (h : hdrBytes ≤ bs.size) :
    ((bodyP sh b).run bs).run hdrBytes =
      (((bodyP sh b).run (bs.extract hdrBytes bs.size)).run 0).map (fun (a, p) => (a, p + hdrBytes)) := by
  have h1 := MtS_bodyP sh b bs hdrBytes h
  have h2 := MtS_bodyP sh b (bs.extract hdrBytes bs.size) 0 (Nat.zero_le _)
  have hl : (bs.extract hdrBytes bs.size).size = bs.size - hdrBytes := by
    rw [← rq_len, body_list, List.length_drop, rq_len]
  rw [List.drop_zero, body_list] at h2
  dsimp only at h1 h2
  rcases hX : (bodyS sh b).run (bs.toList.drop hdrBytes) with w | ⟨q, r⟩
  · rw [hX] at h1 h2
    rw [h1, h2]
    rfl
  · rw [hX] at h1 h2
    obtain ⟨a, p', hq, hp1, hp2, hr, hrun⟩ := h1
    obtain ⟨a2, p2, hq2, _, hp3, hr2, hrun2⟩ := h2
    have e1 : r.length = bs.size - p' := by rw [hr, List.length_drop, rq_len]
    have e2 : r.length = (bs.extract hdrBytes bs.size).size - p2 := by
      rw [hr2, List.length_drop, List.length_drop, rq_len]; omega
    have hp : p' = p2 + hdrBytes := by omega
    rw [hrun, hrun2, hp]
    subst hq hq2
    rfl

/-- `idNatA` is one-to-one. -/
theorem idNatA_inj (a b : ByteArray) (h : idNatA a = idNatA b) : a = b := by
  rw [idNatA_eq, idNatA_eq] at h
  have l1 := (idNat_lt a.toList (b.toList.length + 1)).mp (by rw [h]; exact (idNat_lt _ _).mpr (Nat.lt_succ_self _))
  have l2 := (idNat_lt b.toList (a.toList.length + 1)).mp (by rw [← h]; exact (idNat_lt _ _).mpr (Nat.lt_succ_self _))
  have h2 : (1 :: a.toList) = (1 :: b.toList) :=
    beNat_inj _ _ (by simp; omega) h
  have h3 : a.toList = b.toList := List.cons.inj h2 |>.2
  rwa [ba_toList_inj] at h3

/-! ### The answer -/

/-- The `w`-byte little-endian number: byte `i` is `n / 256 ^ i % 256`, read as a shift (`toUInt8` keeps the low byte). -/
def put (b : ByteArray) (w n : Nat) : ByteArray := Id.run do
  let mut b := b
  for i in [0:w] do b := b.push (n >>> (8 * i)).toUInt8
  pure b

def putL (b : ByteArray) (xs : Bytes) : ByteArray := xs.foldl (·.push ·) b

theorem toList_putL (b : ByteArray) (xs : Bytes) : (putL b xs).toList = b.toList ++ xs := by
  induction xs generalizing b with
  | nil => simp [putL]
  | cons x xs ih =>
    simp only [putL, List.foldl_cons] at ih ⊢
    rw [ih]; simp [Bin.toList_eq', ByteArray.data_push]

/-- The `w`-byte big-endian number, pushed byte by byte (`natBE` as a list is the cost of the input digest otherwise). -/
def putBE (b : ByteArray) : Nat → Nat → ByteArray
  | 0, _ => b ++ ByteArray.empty -- consumes `b`: returned bare, Lean infers it borrowed and copies it at every push
  | w + 1, n => putBE (b.push (UInt8.ofNat (n >>> (8 * w) % 256))) w n

theorem div_256_pow (n w : Nat) : n / 256 ^ w = n >>> (8 * w) := by
  simp [Nat.shiftRight_eq_div_pow, Nat.pow_mul]

theorem natBE_succ (w v : Nat) : natBE (w + 1) v = UInt8.ofNat (v >>> (8 * w) % 256) :: natBE w v := by
  simp [natBE, List.range_succ, div_256_pow]

theorem toList_putBE (b : ByteArray) (w n : Nat) : (putBE b w n).toList = b.toList ++ natBE w n := by
  induction w generalizing b with
  | zero => simp [putBE, natBE]
  | succ w ih =>
    rw [putBE, ih, natBE_succ]
    simp [Bin.toList_eq', ByteArray.data_push]

/-! ### The commitments: context, payment digest, input and batch identity -/

def contextDomain : ByteArray := (domain "CONTEXT").toByteArray
def paymentDomain : ByteArray := (domain "PAYMENT").toByteArray
def inputDomain : ByteArray := ("RR/GATE/INPUT/v6".toUTF8.toList ++ [0]).toByteArray
def batchDomain : ByteArray := (domain "BATCH-INPUT").toByteArray

/-- Where frame `bs`'s request count starts: its body ends with the count, then each request after its 4-byte length. -/
def ctxEnd (bs : ByteArray) (q : Req) : Nat := bs.size - 4 - q.auth.reqs.foldl (fun n e => n + 4 + e.x.size) 0

/-- `Gate.context` of `Frame.ctxBytes` over the engine's hash, for the request count at `e` (`ctxEnd`): the body is
    copied once, after the domain. -/
def contextAt (bs : ByteArray) (e : Nat) : ByteArray :=
  Bin.HB (bs.copySlice hdrBytes contextDomain contextDomain.size (e - hdrBytes))

/-- `Gate.payDigest` of request `e` over the engine's hash, given its lines root: the request's bytes before its lines
    and after them are cut by their lengths (each line is 2 bytes of length and its bytes, each reference 64 bytes). -/
def payDigestR (e : Run.Req) (root : ByteArray) : ByteArray :=
  let x := e.x
  let ts := x.size - 2 - 64 * e.ra.evidenceRefs.length
  let he := ts - e.ra.lines.foldl (fun n l => n + 2 + l.size) 0
  let b := putBE (ByteArray.emptyWithCapacity (paymentDomain.size + 4 + he + 64 + x.size - ts) ++ paymentDomain) 4 he
  let b := x.copySlice 0 b b.size he
  Bin.HB (x.copySlice ts (b ++ root) (b.size + root.size) (x.size - ts))

/-- `Gate.inputV6` over the engine's hash. -/
def inputV6Fast (ctx rd : ByteArray) : ByteArray := Bin.HB (inputDomain ++ ctx ++ rd)

theorem inputV6Fast_eq (ctx rd : ByteArray) :
    (inputV6Fast ctx rd).toList = Gate.inputV6 (fun b => (Bin.HB ⟨b.toArray⟩).toList) ctx.toList rd.toList := by
  have hl : (inputDomain ++ ctx ++ rd).toList = Gate.inputV6Pre ctx.toList rd.toList := by
    simp only [inputDomain, Gate.inputV6Pre, Bin.toList_append', Bin.toList_toByteArray, List.append_assoc]
  have : inputDomain ++ ctx ++ rd = ⟨(Gate.inputV6Pre ctx.toList rd.toList).toArray⟩ :=
    ByteArray.ext (by rw [← hl, Bin.toList_eq', Array.toArray_toList])
  simp only [inputV6Fast, Gate.inputV6, this]

/-- `Gate.batchInput` over the engine's hash, in one buffer of its final size. -/
def batchInputFast (ctx : ByteArray) (rqs : Array ByteArray) : ByteArray :=
  Bin.HB (rqs.foldl (· ++ ·) (ByteArray.emptyWithCapacity (batchDomain.size + 64 * (rqs.size + 1)) ++ batchDomain ++ ctx))

def linesDomain : ByteArray := (domain "LINES-NODE").toByteArray

def pairUpA : List ByteArray → List ByteArray
  | a :: b :: rest => Bin.HB (linesDomain.push 1 ++ a ++ b) :: pairUpA rest
  | xs => xs

def treeRootA : Nat → List ByteArray → ByteArray
  | _, [x] => x
  | 0, _ => .empty
  | fuel + 1, xs => treeRootA fuel (pairUpA xs)

/-- `Gate.linesRoot` over the engine's hash, on byte arrays. -/
def linesRootA (ls : List ByteArray) : ByteArray :=
  if ls.isEmpty then Gate.zeroDigest.toByteArray else treeRootA treeFuel (ls.map fun x => Bin.HB (linesDomain.push 0 ++ x))

private theorem ba_mk_toList (x : ByteArray) : (⟨x.toList.toArray⟩ : ByteArray) = x :=
  ByteArray.ext (by rw [Bin.toList_eq', Array.toArray_toList])

private theorem HB_toList' (x : ByteArray) : (Bin.HB x).toList = (Bin.HB ⟨x.toList.toArray⟩).toList := by
  rw [ba_mk_toList]

theorem empty_toList (n : Nat) : (ByteArray.emptyWithCapacity n).toList = [] := by
  simp [Flat.Bin.toList_eq', ByteArray.emptyWithCapacity]
  rfl

private theorem linesDomain_toList : linesDomain.toList = domain "LINES-NODE" := Bin.toList_toByteArray _

private theorem linesDomain_push (c : UInt8) (x : ByteArray) :
    (linesDomain.push c ++ x).toList = domain "LINES-NODE" ++ (c :: x.toList) := by
  have : (linesDomain.push c).toList = domain "LINES-NODE" ++ [c] := by
    rw [Bin.toList_eq', ByteArray.data_push, Array.toList_push, ← Bin.toList_eq', linesDomain_toList]
  rw [Bin.toList_append', this]; simp

private theorem pairUpA_eq (xs : List ByteArray) :
    (pairUpA xs).map (·.toList) =
      Gate.pairUp (fun b => (Bin.HB ⟨b.toArray⟩).toList) (domain "LINES-NODE") (xs.map (·.toList)) := by
  induction xs using pairUpA.induct with
  | case1 a b rest ih =>
    simp only [pairUpA, List.map_cons, Gate.pairUp, ih, Gate.nodeHash]
    refine List.cons_eq_cons.mpr ⟨?_, rfl⟩
    rw [HB_toList', Bin.toList_append', linesDomain_push]
    simp
  | case2 xs h =>
    cases xs with
    | nil => simp [pairUpA, Gate.pairUp]
    | cons a t =>
      cases t with
      | nil => simp [pairUpA, Gate.pairUp]
      | cons b r => exact absurd rfl (h a b r)

private theorem treeRootA_eq (fuel : Nat) (xs : List ByteArray) :
    (treeRootA fuel xs).toList =
      Gate.treeRoot (fun b => (Bin.HB ⟨b.toArray⟩).toList) (domain "LINES-NODE") fuel (xs.map (·.toList)) := by
  induction fuel generalizing xs with
  | zero =>
    match xs with
    | [] => simp [treeRootA, Gate.treeRoot, Bin.toList_eq']
    | [x] => simp [treeRootA, Gate.treeRoot]
    | _ :: _ :: _ => simp [treeRootA, Gate.treeRoot, Bin.toList_eq']
  | succ n ih =>
    match xs with
    | [] => simpa [treeRootA, Gate.treeRoot, pairUpA, Gate.pairUp] using ih []
    | [x] => simp [treeRootA, Gate.treeRoot]
    | a :: b :: r =>
      simp only [List.map_cons, treeRootA, Gate.treeRoot]
      rw [ih, pairUpA_eq]
      simp only [List.map_cons]

theorem linesRootA_eq (ls : List ByteArray) :
    (linesRootA ls).toList = Gate.linesRoot (fun b => (Bin.HB ⟨b.toArray⟩).toList) (ls.map (·.toList)) := by
  unfold linesRootA Gate.linesRoot
  by_cases h : ls.isEmpty
  · have : ls = [] := List.isEmpty_iff.mp h
    subst this
    simpa using Bin.toList_toByteArray _
  · have h' : (ls.map (·.toList)).isEmpty = false := by simpa using h
    rw [if_neg h, if_neg (by simpa using h'), treeRootA_eq]
    have hm : (ls.map fun x => Bin.HB (linesDomain.push 0 ++ x)).map (·.toList) =
        (ls.map (·.toList)).map (Gate.leafHash (fun b => (Bin.HB ⟨b.toArray⟩).toList) (domain "LINES-NODE")) := by
      simp only [List.map_map]
      apply List.map_congr_left
      intro x _
      simp only [Function.comp, Gate.leafHash]
      rw [HB_toList', linesDomain_push]
    rw [hm]

/-- `Frame.ident` over the engine's hash, and each request's input (`INPUT/v6`) in frame order. -/
def identFast (bs : ByteArray) (q : Req) : ByteArray × Array ByteArray :=
  let c := contextAt bs (ctxEnd bs q)
  let rqs := q.auth.reqs.toArray.map fun e => inputV6Fast c (payDigestR e (linesRootA e.ra.lines))
  (batchInputFast c rqs, rqs)

/-! ### A decoded payment request's bytes: its head, its lines, its tail -/

private theorem beNat_snoc (d : Bytes) (x : UInt8) : beNat (d ++ [x]) = beNat d * 256 + x.toNat := by
  simp [beNat, List.foldl_append]

private theorem natBE_snoc (w v : Nat) : natBE (w + 1) v = natBE w (v / 256) ++ [UInt8.ofNat (v % 256)] := by
  unfold natBE
  rw [List.range_succ_eq_map]
  simp only [List.reverse_cons, List.map_append, List.map_cons, List.map_nil, Nat.pow_zero, Nat.div_one]
  rw [← List.map_reverse, List.map_map]
  congr 1
  apply List.map_congr_left
  intro i _
  simp [Nat.pow_succ, Nat.div_div_eq_div_mul, Nat.mul_comm]

private theorem natBE_beNat : ∀ (n : Nat) (d : Bytes), d.length = n → natBE n (beNat d) = d
  | 0, d, h => by
    cases d with
    | nil => rfl
    | cons _ _ => simp at h
  | n + 1, d, h => by
    have hne : d ≠ [] := by
      rintro rfl
      simp at h
    obtain ⟨d', x, rfl⟩ : ∃ d' x, d = d' ++ [x] := ⟨d.dropLast, d.getLast hne, (List.dropLast_concat_getLast hne).symm⟩
    have hl : d'.length = n := by simpa using h
    have hx : x.toNat < 256 := UInt8.toNat_lt x
    have h1 : (beNat d' * 256 + x.toNat) / 256 = beNat d' := by omega
    have h2 : (beNat d' * 256 + x.toNat) % 256 = x.toNat := by omega
    rw [beNat_snoc, natBE_snoc, h1, h2, natBE_beNat n d' hl, UInt8.ofNat_toNat]

private theorem natBE_len (w v : Nat) : (natBE w v).length = w := by simp [natBE]

private theorem sbind {α β : Type} {x : Gate.P α} {f : α → Gate.P β} {b : Bytes} {y : β × Bytes}
    (h : (x >>= f).run b = some y) : ∃ a r, x.run b = some (a, r) ∧ (f a).run r = some y := by
  rw [StateT.run_bind] at h
  cases hx : x.run b with
  | none => rw [hx] at h; simp at h
  | some p => rw [hx] at h; exact ⟨p.1, p.2, rfl, by simpa using h⟩

private theorem spure {α : Type} {a v : α} {b r : Bytes} (h : (pure a : Gate.P α).run b = some (v, r)) : a = v ∧ b = r := by
  have h' : some (a, b) = some (v, r) := h
  simp only [Option.some.injEq, Prod.mk.injEq] at h'
  exact h'

private theorem take_inv {n : Nat} {b v r : Bytes} (h : (Gate.take n).run b = some (v, r)) : b = v ++ r ∧ v.length = n := by
  change (if n ≤ b.length then some (b.take n, b.drop n) else none) = some (v, r) at h
  split at h
  · simp only [Option.some.injEq, Prod.mk.injEq] at h
    obtain ⟨rfl, rfl⟩ := h
    exact ⟨(List.take_append_drop _ _).symm, by simp; omega⟩
  · simp at h

private theorem need_inv {c : Bool} {b r : Bytes} {u : Unit} (h : (Gate.need c).run b = some (u, r)) : r = b ∧ c = true := by
  change (if c then some ((), b) else none) = some (u, r) at h
  split at h
  · simp only [Option.some.injEq, Prod.mk.injEq] at h
    exact ⟨h.2.symm, by assumption⟩
  · simp at h

private theorem nat_inv' {w lo hi v : Nat} {b r : Bytes} (h : (Gate.nat w lo hi).run b = some (v, r)) :
    ∃ d, b = d ++ r ∧ d.length = w ∧ v = beNat d ∧ lo ≤ v ∧ v ≤ hi := by
  unfold Gate.nat at h
  obtain ⟨d, r1, h1, h⟩ := sbind h
  obtain ⟨u, r2, h2, h⟩ := sbind h
  obtain ⟨rfl, rfl⟩ := spure h
  obtain ⟨rfl, hc⟩ := need_inv h2
  obtain ⟨rfl, hl⟩ := take_inv h1
  simp only [Bool.and_eq_true, decide_eq_true_eq] at hc
  exact ⟨d, rfl, hl, rfl, hc⟩

private theorem nat_inv {w lo hi v : Nat} {b r : Bytes} (h : (Gate.nat w lo hi).run b = some (v, r)) :
    b = natBE w v ++ r := by
  obtain ⟨d, rfl, hl, rfl, -⟩ := nat_inv' h
  rw [natBE_beNat w d hl]

private theorem blob_inv {lo hi : Nat} {b v r : Bytes} (h : (Gate.blob lo hi).run b = some (v, r)) :
    b = natBE 2 v.length ++ v ++ r := by
  unfold Gate.blob at h
  obtain ⟨n, r1, h1, h⟩ := sbind h
  obtain ⟨rfl, rfl⟩ := take_inv h
  rw [nat_inv h1, List.append_assoc]

private theorem ident_inv {b v r : Bytes} (h : Gate.ident.run b = some (v, r)) : b = identField v ++ r := by
  unfold Gate.ident at h
  obtain ⟨x, r1, h1, h⟩ := sbind h
  obtain ⟨u, r2, h2, h⟩ := sbind h
  obtain ⟨rfl, rfl⟩ := spure h
  obtain ⟨rfl, -⟩ := need_inv h2
  exact blob_inv h1

private theorem expect_inv {d b r : Bytes} {u : Unit} (h : (Gate.expect d).run b = some (u, r)) : b = d ++ r := by
  unfold Gate.expect at h
  obtain ⟨x, r1, h1, h⟩ := sbind h
  obtain ⟨rfl, hc⟩ := need_inv h
  obtain ⟨rfl, -⟩ := take_inv h1
  rw [beq_iff_eq.mp hc]

private theorem tag_inv {f : WireFlow} {b r : Bytes} (h : (Gate.tag flows).run b = some (f, r)) : b = [f.tag] ++ r := by
  unfold Gate.tag at h
  obtain ⟨t, r1, h1, h⟩ := sbind h
  obtain ⟨d, rfl, hl, rfl, h5⟩ := nat_inv' h1
  split at h
  · rename_i x hx
    obtain ⟨rfl, rfl⟩ := spure h
    match d, hl with
    | [c], _ =>
      have e : beNat [c] = c.toNat := by simp [beNat]
      have hf : flows.length = 5 := rfl
      rw [e, hf] at h5
      rw [e] at hx
      have hc : c.toNat = 1 ∨ c.toNat = 2 ∨ c.toNat = 3 ∨ c.toNat = 4 ∨ c.toNat = 5 := by omega
      congr 2
      apply UInt8.toNat_inj.mp
      rcases hc with hc | hc | hc | hc | hc <;> rw [hc] at hx <;> simp [flows] at hx <;> subst hx <;> rw [hc] <;> rfl
  · exact absurd h (by simp [Gate.fail, StateT.run])

private theorem many_inv {α : Type} {p : Gate.P α} (enc : α → Bytes) (Q : α → Prop)
    (hp : ∀ b v r, p.run b = some (v, r) → b = enc v ++ r ∧ Q v) :
    ∀ (k : Nat) (b r : Bytes) (vs : List α), (Gate.many p k).run b = some (vs, r) →
      b = (vs.map enc).flatten ++ r ∧ vs.length = k ∧ ∀ v ∈ vs, Q v := by
  intro k
  induction k with
  | zero =>
    intro b r vs h
    obtain ⟨rfl, rfl⟩ := spure h
    simp
  | succ k ih =>
    intro b r vs h
    unfold Gate.many at h
    obtain ⟨x, r1, h1, h⟩ := sbind h
    obtain ⟨xs, r2, h2, h⟩ := sbind h
    obtain ⟨rfl, rfl⟩ := spure h
    obtain ⟨rfl, hq⟩ := hp _ _ _ h1
    obtain ⟨rfl, hl, hqs⟩ := ih _ _ _ h2
    refine ⟨by simp, by simp [hl], ?_⟩
    intro v hv
    rcases List.mem_cons.mp hv with rfl | hv
    · exact hq
    · exact hqs v hv

/-- A decoded request's bytes are its head, its lines (each with its two-byte length) and its tail, each reference 64
    bytes. -/
private theorem decodeRequest_bytes {x : Bytes} {m : Gate.Request} (h : Gate.decodeRequest x = some m) :
    x = requestHead m ++ (m.lines.map identField).flatten ++ requestTail m ∧ ∀ v ∈ m.evidenceRefs, v.length = 64 := by
  unfold Gate.decodeRequest Gate.parse at h
  split at h
  · simp at h
  split at h
  · rename_i r0 hr
    simp only [Option.some.injEq] at h
    subst h
    unfold Gate.pRequest at hr
    obtain ⟨u0, b1, h1, hr⟩ := sbind hr
    obtain ⟨tenantId, b2, h2, hr⟩ := sbind hr
    obtain ⟨programId, b3, h3, hr⟩ := sbind hr
    obtain ⟨flow, b4, h4, hr⟩ := sbind hr
    obtain ⟨commandKey, b5, h5, hr⟩ := sbind hr
    obtain ⟨paymentId, b6, h6, hr⟩ := sbind hr
    obtain ⟨memberKey, b7, h7, hr⟩ := sbind hr
    obtain ⟨payeeRef, b8, h8, hr⟩ := sbind hr
    obtain ⟨amountCents, b9, h9, hr⟩ := sbind hr
    obtain ⟨period, b10, h10, hr⟩ := sbind hr
    obtain ⟨k, b11, h11, hr⟩ := sbind hr
    obtain ⟨lines, b12, h12, hr⟩ := sbind hr
    obtain ⟨u1, b13, h13, hr⟩ := sbind hr
    obtain ⟨u2, b14, h14, hr⟩ := sbind hr
    obtain ⟨u3, b15, h15, hr⟩ := sbind hr
    obtain ⟨u4, b16, h16, hr⟩ := sbind hr
    obtain ⟨k2, b17, h17, hr⟩ := sbind hr
    obtain ⟨refs, b18, h18, hr⟩ := sbind hr
    obtain ⟨u5, b19, h19, hr⟩ := sbind hr
    obtain ⟨rfl, rfl⟩ := spure hr
    obtain ⟨rfl, -⟩ := need_inv h19
    obtain ⟨rfl, -⟩ := need_inv h16
    obtain ⟨rfl, -⟩ := need_inv h15
    obtain ⟨rfl, -⟩ := need_inv h14
    obtain ⟨rfl, -⟩ := need_inv h13
    obtain ⟨e18, hk2, hrefs⟩ := many_inv id (fun v => v.length = 64)
      (fun b v r h => ⟨(take_inv h).1, (take_inv h).2⟩) _ _ _ _ h18
    obtain ⟨e12, hk, -⟩ := many_inv identField (fun _ => True)
      (fun b v r h => ⟨by rw [blob_inv h, identField, List.append_assoc], trivial⟩) _ _ _ _ h12
    subst hk hk2
    refine ⟨?_, hrefs⟩
    rw [expect_inv h1, ident_inv h2, ident_inv h3, tag_inv h4, ident_inv h5, ident_inv h6, (take_inv h7).1, ident_inv h8,
      nat_inv h9, ident_inv h10, nat_inv h11, e12, nat_inv h17, e18]
    simp [Gate.requestHead, Gate.requestTail, List.append_assoc]
  · simp at h

private theorem obind {α β : Type} {x : Option α} {f : α → Option β} {b : β} (h : (x >>= f) = some b) :
    ∃ a, x = some a ∧ f a = some b := by
  cases x with
  | none => cases h
  | some a => exact ⟨a, rfl, h⟩

/-- `Run.reqOf` keeps the bytes it read and the request they decode to. -/
private theorem reqOf_inv {x : ByteArray} {e : Run.Req} (h : Run.reqOf x = some e) :
    e.x = x ∧ ∃ m, Gate.decodeRequest x.toList = some m ∧ e.ra = RequestBA.ofModel m := by
  unfold Run.reqOf at h
  obtain ⟨m, hm, h⟩ := obind h
  obtain ⟨ls, -, h⟩ := obind h
  cases h
  exact ⟨rfl, m, hm, rfl⟩

private theorem flat64 (l : List Bytes) (h : ∀ v ∈ l, v.length = 64) : l.flatten.length = 64 * l.length := by
  induction l with
  | nil => rfl
  | cons v l ih =>
    simp only [List.flatten_cons, List.length_append, List.length_cons, h v (List.mem_cons_self ..),
      ih (fun w hw => h w (List.mem_cons_of_mem _ hw))]
    omega

private theorem lines_fold (ls : List Bytes) (a : Nat) :
    (ls.map List.toByteArray).foldl (fun n (l : ByteArray) => n + 2 + l.size) a =
      a + ((ls.map Gate.identField).flatten).length := by
  induction ls generalizing a with
  | nil => rfl
  | cons l ls ih =>
    rw [List.map_cons, List.foldl_cons, ih]
    simp only [List.map_cons, List.flatten_cons, List.length_append, Gate.identField, natBE_len, Bin.size_eq_length',
      Bin.toList_toByteArray]
    omega

/-- `payDigestR` cuts a request's bytes where its lines start and end: it is `Gate.payDigest` of the request the bytes
    decode to. -/
private theorem payDigestR_eq (e : Run.Req) (h : Run.reqOf e.x = some e) :
    (payDigestR e (linesRootA e.ra.lines)).toList =
      Gate.payDigest (fun b => (Bin.HB ⟨b.toArray⟩).toList) e.ra.toModel := by
  obtain ⟨-, m, hm, hra⟩ := reqOf_inv h
  obtain ⟨hx, hrefs⟩ := decodeRequest_bytes hm
  have hroot : (linesRootA e.ra.lines).toList = Gate.linesRoot (fun b => (Bin.HB ⟨b.toArray⟩).toList) m.lines := by
    rw [linesRootA_eq, hra]
    simp [RequestBA.ofModel, List.map_map, Function.comp_def, Bin.toList_toByteArray]
  have hL := lines_fold m.lines 0
  have htl : (Gate.requestTail m).length = 2 + 64 * e.ra.evidenceRefs.length := by
    rw [hra]; simp [Gate.requestTail, RequestBA.ofModel, natBE_len, flat64 _ hrefs]
  have hsz : e.x.size = (Gate.requestHead m).length + ((m.lines.map Gate.identField).flatten).length +
      (Gate.requestTail m).length := by
    rw [Bin.size_eq_length', hx]; simp only [List.length_append]
  have hts : e.x.size - 2 - 64 * e.ra.evidenceRefs.length =
      (Gate.requestHead m).length + ((m.lines.map Gate.identField).flatten).length := by omega
  have hfold : e.ra.lines.foldl (fun n l => n + 2 + l.size) 0 = ((m.lines.map Gate.identField).flatten).length := by
    rw [hra]; exact hL.trans (Nat.zero_add _)
  unfold payDigestR
  dsimp only
  rw [HB_toList', copySlice_toList _ _ _ _ _ ByteArray.size_append.symm, Bin.toList_append',
    copySlice_toList _ _ _ _ _ rfl, toList_putBE, Bin.toList_append', hroot, hts, hfold, Nat.add_sub_cancel,
    show e.x.size - ((Gate.requestHead m).length + ((m.lines.map Gate.identField).flatten).length) =
      (Gate.requestTail m).length by omega, hx]
  rw [hra, toModel_ofModel, empty_toList]
  simp [Gate.payDigest, Gate.paymentPre, Gate.lp32, paymentDomain, Bin.toList_eq', List.append_assoc]

private theorem reqs_fold (l : List Run.Req) (a : Nat) :
    l.foldl (fun n e => n + 4 + e.x.size) a = a + (l.map fun e => 4 + e.x.size).sum := by
  induction l generalizing a with
  | nil => rfl
  | cons e l ih => simp only [List.foldl_cons, ih, List.map_cons, List.sum_cons]; omega

private theorem contextAt_eq (bs : ByteArray) (q : Req) :
    (contextAt bs (ctxEnd bs q)).toList = Gate.context (fun b => (Bin.HB ⟨b.toArray⟩).toList) (ctxBytes bs.toList q) := by
  unfold contextAt Gate.context Gate.contextPre ctxBytes ctxEnd
  dsimp only
  rw [HB_toList', copySlice_toList _ _ _ _ _ rfl, reqs_fold, List.length_drop, ← Bin.size_eq_length',
    show bs.size - 4 - (0 + (q.auth.reqs.map fun e => 4 + e.x.size).sum) - hdrBytes =
      bs.size - hdrBytes - 4 - (q.auth.reqs.map fun e => 4 + e.x.size).sum by omega]
  simp [contextDomain, Bin.toList_toByteArray]

private theorem batchInputFast_eq (c : ByteArray) (rqs : Array ByteArray) :
    (batchInputFast c rqs).toList = Gate.batchInput (fun b => (Bin.HB ⟨b.toArray⟩).toList) c.toList (rqs.toList.map (·.toList)) := by
  have hf : ∀ (l : List ByteArray) (i : ByteArray), (l.foldl (· ++ ·) i).toList = i.toList ++ (l.map (·.toList)).flatten := by
    intro l
    induction l with
    | nil => intro i; simp
    | cons x l ih => intro i; simp [ih, Bin.toList_append', List.append_assoc]
  unfold batchInputFast Gate.batchInput Gate.batchInputPre
  rw [HB_toList', ← Array.foldl_toList, hf, Bin.toList_append', Bin.toList_append', empty_toList]
  simp [batchDomain, Bin.toList_eq', List.append_assoc]

private theorem ex_bind {ε α β : Type} {x : Except ε α} {f : α → Except ε β} {b : β} (h : (x >>= f) = .ok b) :
    ∃ a, x = .ok a ∧ f a = .ok b := by
  cases x with
  | error e => cases h
  | ok a => exact ⟨a, rfl, h⟩

private theorem reqRec_inv {bs r : Bytes} {e : Run.Req} (h : reqRec bs = .ok (e, r)) : Run.reqOf e.x = some e := by
  unfold reqRec at h
  obtain ⟨⟨x, r1⟩, -, h⟩ := ex_bind h
  dsimp only at h
  split at h
  · split at h
    · rename_i e' he
      cases h
      rw [(reqOf_inv he).1]; exact he
    · cases h
  · cases h

private theorem many_reqRec_inv : ∀ (n : Nat) (bs r : Bytes) (l : List Run.Req), Frame.many reqRec n bs = .ok (l, r) →
    ∀ e ∈ l, Run.reqOf e.x = some e := by
  intro n
  induction n with
  | zero => intro bs r l h; cases h; simp
  | succ n ih =>
    intro bs r l h
    unfold Frame.many at h
    obtain ⟨⟨a, r1⟩, h1, h⟩ := ex_bind h
    dsimp only at h
    obtain ⟨⟨as, r2⟩, h2, h⟩ := ex_bind h
    cases h
    intro e he
    rcases List.mem_cons.mp he with rfl | he
    · exact reqRec_inv h1
    · exact ih _ _ _ h2 e he

private theorem authRec_reqs {bs r : Bytes} {a : Auth} (h : authRec bs = .ok (a, r)) :
    ∀ e ∈ a.reqs, Run.reqOf e.x = some e := by
  unfold authRec at h
  obtain ⟨⟨pin, r1⟩, -, h⟩ := ex_bind h
  try dsimp only at h
  obtain ⟨⟨l2, r2⟩, -, h⟩ := ex_bind h
  try dsimp only at h
  split at h
  case h_2 => cases h
  split at h
  case isFalse => cases h
  obtain ⟨⟨kf, r3⟩, -, h⟩ := ex_bind h
  try dsimp only at h
  obtain ⟨⟨g, r4⟩, -, h⟩ := ex_bind h
  try dsimp only at h
  obtain ⟨⟨k, r5⟩, -, h⟩ := ex_bind h
  try dsimp only at h
  obtain ⟨⟨rl, r6⟩, -, h⟩ := ex_bind h
  try dsimp only at h
  split at h
  case isFalse => cases h
  obtain ⟨⟨nk, r7⟩, -, h⟩ := ex_bind h
  try dsimp only at h
  obtain ⟨⟨ks, r8⟩, -, h⟩ := ex_bind h
  try dsimp only at h
  obtain ⟨⟨nb, r9⟩, -, h⟩ := ex_bind h
  try dsimp only at h
  obtain ⟨⟨bys, r10⟩, -, h⟩ := ex_bind h
  try dsimp only at h
  obtain ⟨⟨nq, r11⟩, -, h⟩ := ex_bind h
  try dsimp only at h
  obtain ⟨⟨reqs, r12⟩, hq, h⟩ := ex_bind h
  try dsimp only at h
  -- the last check matches on the request list, then tests it
  split at h <;> split at h <;> cases h <;> exact many_reqRec_inv _ _ _ _ hq

private theorem decodeBody_reqs {hd : Hdr} {bs r : Bytes} {q : Req} (h : decodeBody hd bs = .ok (q, r)) :
    ∀ e ∈ q.auth.reqs, Run.reqOf e.x = some e := by
  unfold decodeBody at h
  obtain ⟨⟨p, r1⟩, -, h⟩ := ex_bind h
  try dsimp only at h
  obtain ⟨⟨au, r2⟩, ha, h⟩ := ex_bind h
  cases h
  exact authRec_reqs ha

/-- Every payment request of a decoded frame is what its bytes decode to. -/
private theorem decodeReq_reqs {H : Bytes → Bytes} {bs dg : Bytes} {q : Req} (h : decodeReq H bs = .ok (q, dg)) :
    ∀ e ∈ q.auth.reqs, Run.reqOf e.x = some e := by
  unfold decodeReq at h
  obtain ⟨⟨hd, body⟩, -, h⟩ := ex_bind h
  try dsimp only at h
  split at h
  case isFalse => cases h
  obtain ⟨⟨q', rest⟩, hb, h⟩ := ex_bind h
  try dsimp only at h
  split at h
  case isFalse => cases h
  cases h
  exact decodeBody_reqs hb

/-- The identity of a decoded frame is `Frame.ident`: the context bytes and each request's head and tail are cut where
    the decoder read them. -/
theorem identFast_eq (bs : ByteArray) (q : Req) (dg : ByteArray) (h : decodeReqFast bs = .ok (q, dg)) :
    (identFast bs q).1.toList = Frame.ident (fun b => (Bin.HB ⟨b.toArray⟩).toList) bs.toList q := by
  have hd : decodeReq (fun b => (Bin.HB ⟨b.toArray⟩).toList) bs.toList = .ok (q, dg.toList) := by
    rw [← decodeReqFast_eq' _ (fun _ => rfl) bs, h]; rfl
  have hr := decodeReq_reqs hd
  unfold identFast Frame.ident
  dsimp only
  rw [batchInputFast_eq, contextAt_eq, Array.toList_map, List.map_map]
  congr 1
  apply List.map_congr_left
  intro e he
  simp only [Function.comp_apply]
  rw [inputV6Fast_eq, contextAt_eq, payDigestR_eq e (hr e (by simpa using he))]


def putBlob2 (b x : ByteArray) : ByteArray := put b 2 x.size ++ x

def putRec (b : ByteArray) (r : Rec) : ByteArray :=
  let (c, w) := r.ref.getD (noChunk, noRow)
  put (put (put (put (put (put b 3 r.index) 1 r.outcome) 1 (Frame.rules.idxOf r.rule)) 4 r.reasons) 4 c) 3 w

/-- The zero id: no bypass. -/
def zero64B : ByteArray := ⟨Array.replicate 64 0⟩

def putLeaf (b : ByteArray) (l : Leaf) : ByteArray :=
  let b := put (put (put b 1 l.outcome) 4 l.reasons) 1 l.authority
  let b := if l.bypass == zero64B then b.push 0 else b.push 1 ++ l.bypass
  b ++ l.input

def putExt (b : ByteArray) (e : Ext) : ByteArray :=
  let b := b ++ e.hold ++ e.grant ++ e.auth
  let b := e.notes.foldl putBlob2 (put b 4 e.notes.length)
  let b := e.leaves.foldl putLeaf (put b 4 e.leaves.length)
  e.adds.foldl putBlob2 (put b 4 e.adds.length)

/-- `Frame.encodeAns` over `ByteArray`, for an answer that encodes. -/
def encodeAnsFast (a : AnsFrame) : ByteArray :=
  -- the buffer sized once for the whole answer, so no append copies it
  let blobs (xs : List ByteArray) := xs.foldl (fun n x => n + 2 + x.size) 4
  let cap := 160 + 16 * a.recs.length + a.ext.hold.size + a.ext.grant.size + a.ext.auth.size + blobs a.ext.notes + blobs a.ext.adds +
    136 * a.ext.leaves.length + 4
  let b := putL (ByteArray.emptyWithCapacity cap) magicAns
  let b := put (put (put (put (put b 2 version) 1 a.word.code) 4 a.shard) 8 a.batch) 4 a.recs.length
  let b := b ++ a.digest
  let b := a.recs.foldl putRec b
  let b := b ++ a.head ++ a.root
  if a.word == .OK then putExt b a.ext else b

end BlindLedger.Gate.Frame.Fast
