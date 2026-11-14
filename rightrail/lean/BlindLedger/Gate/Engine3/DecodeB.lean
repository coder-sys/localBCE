import BlindLedger.Gate.Frame.Fast
import BlindLedger.Gate.Engine3.Sha3Range
import BlindLedger.Gate.Engine3.Layout

/-! The engine's request decoder: `Frame.Fast.decodeReqFast` with the payment requests read in place.  A request is checked
    where it sits (`Fast.decodeRows`' checks), with no list, no big number and no row built for it, and the whole-request
    FRAME digest is one hash over the frame's bytes, run on another core while the body is read.  It fails where
    `decodeReqFast` fails, with the same word.

    What differs from `decodeReqFast`'s request: a payment request carries `q := 0` and `ls := []` (its payment number and
    its `Line`s are not built).  The payment key (`payKeyOf`) and whether every line fits the store widths (`reqFits`,
    `lineFits`) are read from the request's bytes instead; `Frame.encodeReq` reads only the request bytes, so
    `decodeB_eq` has the shape of `decodeReqFast_eq`.
    Synthetic, nonpayment, non-PHI, activation=false. -/

namespace BlindLedger.Gate.Frame.Fast

open BlindLedger.Gate.Rules BlindLedger.Gate.Flat

/-- The FRAME digest's domain, once. -/
def frameDomain : ByteArray := (domain "FRAME").toByteArray

/-- `decodeRows`' test of one line `b[p, e)` (flow tag, member at `mem`, payee identifier `b[ps, ps + pn)`): its cents, or all
    ones when `lineRow` would refuse it.  No cents reach 2^63. -/
def lineChk (b : ByteArray) (p e : Nat) (flow : UInt8) (mem ps pn : Nat) : UInt64 :=
  if e < p + 1 || b.get! p != flow then 0xFFFFFFFFFFFFFFFF else
  let ie := identEnd b (p + 1) e
  if ie == 0 || e < ie + 32 || !sameBytes b b ie mem 32 then 0xFFFFFFFFFFFFFFFF else
  let pe := identEnd b (ie + 32) e
  if pe == 0 || pe - (ie + 34) != pn || !sameBytes b b (ie + 34) ps pn then 0xFFFFFFFFFFFFFFFF else
  let re := identEnd b pe e
  if re == 0 || e < re + 4 then 0xFFFFFFFFFFFFFFFF else
  let oe := identEnd b (re + 4) e
  if oe == 0 || oe + 12 != e then 0xFFFFFFFFFFFFFFFF else
  let cents := be8 b (oe + 4)
  if 9223372036854775807 < cents then 0xFFFFFFFFFFFFFFFF else cents

/-- A line `b[p, e)` that `lineChk` accepted fits the store widths: the number `1 ‖ s` of an identifier of `n` bytes is below
    `256 ^ w` exactly when `n < w`; the member is 33 bytes, the date, units and cents are 4, 4 and 8 (`Engine3.fitsLine2`,
    `fitsS`).  `pk` is the length of the payment key (the payment number `1 ‖ key`). -/
def lineFits (b : ByteArray) (p e pk : Nat) : Bool :=
  let ie := identEnd b (p + 1) e
  let pe := identEnd b (ie + 32) e
  let re := identEnd b pe e
  let oe := identEnd b (re + 4) e
  let w (n lim : Nat) : Bool := n < lim
  w (ie - (p + 3)) (min Engine3.idW idWidth) && w pk (min Engine3.payW payWidth) && w (pe - (ie + 34)) (min Engine3.provW idWidth) &&
  w (re - (pe + 2)) (min Engine3.provW idWidth) && w (oe - (re + 6)) (min Engine3.procW idWidth)

/-- A payment request as `decodeRows` reads it, in one pass over its bytes `x`: the request and its payment key (the bytes
    `identField program ‖ identField payment`). -/
structure ReqB where
  ra : RequestBA
  payKey : ByteArray
  x : ByteArray

/-- `decodeRows x`' verdict and values, with no `LineRow`. -/
def reqB (x : ByteArray) : Option ReqB := Id.run do
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
  let ruled := tag ≤ 3
  let mut q := ke + 2
  let mut sum := 0
  let mut lines : Array ByteArray := Array.mkEmpty nl
  for _ in [0:nl] do
    if n < q + 2 then return none
    let ln := (be2 x q).toNat
    if ln == 0 || 569 < ln || n < q + 2 + ln then return none
    let c := lineChk x (q + 2) (q + 2 + ln) tag ye (ye + 34) (ee - ye - 34)
    if c == 0xFFFFFFFFFFFFFFFF then return none
    sum := sum + c.toNat
    lines := lines.push (x.extract (q + 2) (q + 2 + ln))
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
    evid.toList⟩, payKey, x⟩

/-- The payment key of a decoded request: `identField program ‖ identField payment`. -/
def payKeyOf (ra : RequestBA) : ByteArray :=
  let f (s : ByteArray) : ByteArray := (ByteArray.empty.push (s.size >>> 8).toUInt8 |>.push s.size.toUInt8) ++ s
  f ra.programId ++ f ra.paymentId

/-- Whether every line of a decoded request fits the store widths (a flow with no rules has no lines to fit). -/
def reqFits (ra : RequestBA) : Bool :=
  let pk := (payKeyOf ra).size
  !ra.flow.ruled || ra.lines.all fun ln => lineFits ln 0 ln.size pk

/-- The `n` payment requests at the position. -/
def reqsB (n : Nat) : P (Array ReqB) := do
  let bs ← read
  let mut out : Array ReqB := #[]
  for _ in [0:n] do
    let len ← num 4
    let p ← get
    if bs.size < p + len then throw .LENGTH
    set (p + len)
    let x := bs.extract p (p + len)
    unless x.size ≤ maxRequestBytes do throw .RECORD
    let some e := reqB x | throw .RECORD
    out := out.push e
  pure out

def authB : P Auth := do
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
  let es ← reqsB (← num 4)
  if let some e0 := es[0]? then
    unless es.all (fun e => e.ra.tenantId == e0.ra.tenantId && e.ra.programId == e0.ra.programId) &&
        (es.foldl (fun s e => s.insert e.payKey) (∅ : Std.HashSet ByteArray)).size == es.size do throw .RECORD
  pure { pin, floor := if fp == 1 then some fv else none, kfloor, grant, keyset, release, ksteps, byps,
         reqs := es.toList.map fun e => ⟨0, e.ra, [], e.x⟩ }

def bodyB (shard batch : Nat) : P Req := do
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
  let auth ← authB
  pure { shard, batch, today, asOf, prev, dmf, pdeath, excl, span, redo, auth }

/-- `decodeReqFast`, with the digest hashed in place beside the body read (the digest's word comes first, as there). -/
def decodeB (bs : ByteArray) : Except Word (Req × ByteArray) := do
  if bs.size < hdrBytes then throw .LENGTH
  unless bs.get! 0 == 0x52 && bs.get! 1 == 0x52 && bs.get! 2 == 0x44 && bs.get! 3 == 0x51 &&
      ((bs.get! 4).toNat + 256 * (bs.get! 5).toNat) == version do throw .MAGIC
  let dg := bs.extract 18 hdrBytes
  let t := Task.spawn fun _ => Engine3.sha3_512Into .empty frameDomain bs hdrBytes (bs.size - hdrBytes)
  let rd (p w : Nat) : Nat := Id.run do
    let mut v := 0
    for i in [0:w] do v := v * 256 + (bs.get! (p + w - 1 - i)).toNat
    pure v
  let r := (bodyB (rd 6 4) (rd 10 8)).run bs |>.run hdrBytes
  unless t.get == dg do throw .DIGEST
  let (q, pos) ← r
  unless pos == bs.size do throw .LENGTH
  pure (q, dg)

/-- Whether two decodings agree: the same word, or the same digest, shard, batch and body (`encodeBody` reads every field
    but the shard and batch, and a request only by its bytes). -/
def sameDec (a b : Except Word (Req × ByteArray)) : Bool :=
  match a, b with
  | .error x, .error y => x.code == y.code
  | .ok (p, d), .ok (r, e) =>
    let bare (q : Req) : Req := { q with auth := { q.auth with reqs := [] } }
    d == e && p.shard == r.shard && p.batch == r.batch && encodeBody (bare p) == encodeBody (bare r) &&
      p.auth.reqs.length == r.auth.reqs.length && (p.auth.reqs.zip r.auth.reqs).all fun (a, b) => a.x == b.x
  | _, _ => false

/-! ## `decodeB_eq`: the pieces (private) -/

private theorem lineChk_eq (b : ByteArray) (p e : Nat) (flow : UInt8) (mem ps pn : Nat) (payW : UInt64) :
    lineChk b p e flow mem ps pn = match lineRow b p e flow mem ps pn payW with
      | none => 0xFFFFFFFFFFFFFFFF
      | some r => r.cents := by
  unfold lineChk lineRow
  dsimp only [Id.run, bind, pure]
  repeat' split
  all_goals simp_all
  all_goals (subst_vars; rfl)

private abbrev LD := Option (Option RowsReq) × Nat × Nat × Array ByteArray × Array LineRow
private abbrev LB := Option (Option ReqB) × Nat × Nat × Array ByteArray
private abbrev ED := Option (Option RowsReq) × Nat × Array ByteArray
private abbrev EB := Option (Option ReqB) × Nat × Array ByteArray

private def cv (x : ByteArray) (d : RowsReq) : ReqB := ⟨d.ra, d.payKey, x⟩
private def pL (x : ByteArray) (s : LD) : LB := (s.1.map (Option.map (cv x)), s.2.1, s.2.2.1, s.2.2.2.1)
private def pE (x : ByteArray) (s : ED) : EB := (s.1.map (Option.map (cv x)), s.2.1, s.2.2)

private def mapF {α β : Type} (f : α → β) : ForInStep α → ForInStep β
  | .done a => .done (f a)
  | .yield a => .yield (f a)

private def stepD' (x : ByteArray) (ruled : Prop) [Decidable ruled] (q sm : Nat) (ls : Array ByteArray) (rs : Array LineRow)
    (lr : Option LineRow) : ForInStep LD :=
  if x.size < q + 2 then (.done (some none, q, sm, ls, rs))
  else if ((be2 x q).toNat == 0 || decide (569 < (be2 x q).toNat) ||
      decide (x.size < q + 2 + (be2 x q).toNat)) = true then (.done (some none, q, sm, ls, rs))
  else match lr with
    | some r => if ruled then (.yield (none, q + 2 + (be2 x q).toNat, sm + r.cents.toNat,
          ls.push (x.extract (q + 2) (q + 2 + (be2 x q).toNat)), rs.push r))
        else (.yield (none, q + 2 + (be2 x q).toNat, sm + r.cents.toNat,
          ls.push (x.extract (q + 2) (q + 2 + (be2 x q).toNat)), rs))
    | none => (.done (some none, q, sm, ls, rs))

private def stepD (x : ByteArray) (tag : UInt8) (ye ee : Nat) (payW : UInt64) (ruled : Prop) [Decidable ruled] (_i : Nat) (s : LD) :
    Id (ForInStep LD) :=
  stepD' x ruled s.2.1 s.2.2.1 s.2.2.2.1 s.2.2.2.2
    (lineRow x (s.2.1 + 2) (s.2.1 + 2 + (be2 x s.2.1).toNat) tag ye (ye + 34) (ee - ye - 34) payW)

private def stepB' (x : ByteArray) (q sm : Nat) (ls : Array ByteArray) (c3 : UInt64) : ForInStep LB :=
  if x.size < q + 2 then (.done (some none, q, sm, ls))
  else if ((be2 x q).toNat == 0 || decide (569 < (be2 x q).toNat) ||
      decide (x.size < q + 2 + (be2 x q).toNat)) = true then (.done (some none, q, sm, ls))
  else if c3 == 0xFFFFFFFFFFFFFFFF then (.done (some none, q, sm, ls))
  else (.yield (none, q + 2 + (be2 x q).toNat, sm + c3.toNat, ls.push (x.extract (q + 2) (q + 2 + (be2 x q).toNat))))

private def stepB (x : ByteArray) (tag : UInt8) (ye ee : Nat) (_i : Nat) (s : LB) : Id (ForInStep LB) :=
  stepB' x s.2.1 s.2.2.1 s.2.2.2
    (lineChk x (s.2.1 + 2) (s.2.1 + 2 + (be2 x s.2.1).toNat) tag ye (ye + 34) (ee - ye - 34))

private theorem lineRow_cases (b : ByteArray) (p e : Nat) (flow : UInt8) (mem ps pn : Nat) (payW : UInt64) :
    (lineRow b p e flow mem ps pn payW = none ∧ lineChk b p e flow mem ps pn = 0xFFFFFFFFFFFFFFFF) ∨
    ∃ r, lineRow b p e flow mem ps pn payW = some r ∧ lineChk b p e flow mem ps pn = r.cents ∧
      r.cents ≤ 9223372036854775807 := by
  unfold lineChk lineRow
  dsimp only [Id.run, bind, pure]
  repeat' split
  all_goals simp_all

private theorem stepSim' (x : ByteArray) (ruled : Prop) [Decidable ruled] (q sm : Nat) (ls : Array ByteArray) (rs : Array LineRow)
    (c3 : UInt64) (lr : Option LineRow)
    (hlc : (lr = none ∧ c3 = 0xFFFFFFFFFFFFFFFF) ∨ ∃ r, lr = some r ∧ c3 = r.cents ∧ r.cents ≤ 9223372036854775807) :
    stepB' x q sm ls c3 = mapF (pL x) (stepD' x ruled q sm ls rs lr) := by
  unfold stepB' stepD'
  by_cases h1 : x.size < q + 2
  · simp only [h1, if_true]; rfl
  · simp only [h1, if_false]
    generalize ((be2 x q).toNat == 0 || decide (569 < (be2 x q).toNat) ||
        decide (x.size < q + 2 + (be2 x q).toNat)) = c2
    cases c2
    · rcases hlc with ⟨rfl, rfl⟩ | ⟨r, rfl, rfl, hm⟩
      · rfl
      · have hn : (r.cents == 0xFFFFFFFFFFFFFFFF) = false := by
          cases hh : (r.cents == 0xFFFFFFFFFFFFFFFF)
          · rfl
          · have := beq_iff_eq.mp hh
            rw [this] at hm
            exact absurd hm (by decide)
        by_cases hr : ruled
        · simp only [hr, hn, if_true]; rfl
        · simp only [hr, hn, if_false]; rfl
    · rfl

private theorem stepSim (x : ByteArray) (tag : UInt8) (ye ee : Nat) (payW : UInt64) (ruled : Prop) [Decidable ruled] (i : Nat) (s : LD) :
    stepB x tag ye ee i (pL x s) = mapF (pL x) (stepD x tag ye ee payW ruled i s) := by
  obtain ⟨a, q, sm, ls, rs⟩ := s
  exact stepSim' x ruled q sm ls rs _ _ (lineRow_cases x (q + 2) (q + 2 + (be2 x q).toNat) tag ye (ye + 34) (ee - ye - 34) payW |>.imp
    (fun h => ⟨h.1, h.2⟩) (fun ⟨r, h1, h2, h3⟩ => ⟨r, h1, h2, h3⟩))

private theorem loop1_sim (x : ByteArray) (tag : UInt8) (ye ee : Nat) (payW : UInt64) (ruled : Prop) [Decidable ruled] :
    ∀ (k s : Nat) (st : LD), Id.run (forIn (List.range' s k) (pL x st) (stepB x tag ye ee)) =
      pL x (Id.run (forIn (List.range' s k) st (stepD x tag ye ee payW ruled))) := by
  intro k
  induction k with
  | zero => intro s st; simp [List.range'_zero]
  | succ k ih =>
    intro s st
    rw [List.range'_succ, List.forIn_cons, List.forIn_cons]
    have h := stepSim x tag ye ee payW ruled s st
    rw [h]
    cases hD : stepD x tag ye ee payW ruled s st with
    | done b => rfl
    | yield b => exact ih (s + 1) b

private def stepE (x : ByteArray) (i : Nat) (s : ED) : Id (ForInStep ED) :=
  if (decide (0 < i) && !lt64 x (s.2.1 - 64) s.2.1 0) = true then (.done (some none, s.2))
  else (.yield (none, s.2.1 + 64, s.2.2.push (x.extract s.2.1 (s.2.1 + 64))))

private def stepEB (x : ByteArray) (i : Nat) (s : EB) : Id (ForInStep EB) :=
  if (decide (0 < i) && !lt64 x (s.2.1 - 64) s.2.1 0) = true then (.done (some none, s.2))
  else (.yield (none, s.2.1 + 64, s.2.2.push (x.extract s.2.1 (s.2.1 + 64))))

private theorem stepESim (x : ByteArray) (i : Nat) (s : ED) : stepEB x i (pE x s) = mapF (pE x) (stepE x i s) := by
  obtain ⟨a, q, ev⟩ := s
  unfold stepEB stepE
  dsimp only [pE]
  by_cases c : (decide (0 < i) && !lt64 x (q - 64) q 0) = true
  · simp only [c, if_true]; rfl
  · simp only [c, if_false]; rfl

private theorem loop2_sim (x : ByteArray) : ∀ (k s : Nat) (st : ED),
    Id.run (forIn (List.range' s k) (pE x st) (stepEB x)) = pE x (Id.run (forIn (List.range' s k) st (stepE x))) := by
  intro k
  induction k with
  | zero => intro s st; simp [List.range'_zero]
  | succ k ih =>
    intro s st
    rw [List.range'_succ, List.forIn_cons, List.forIn_cons]
    have h := stepESim x s st
    rw [h]
    cases hD : stepE x s st with
    | done b => rfl
    | yield b => exact ih (s + 1) b

set_option maxHeartbeats 1600000 in
private theorem reqB_eq (x : ByteArray) : reqB x = (decodeRows x).map (cv x) := by
  unfold reqB decodeRows
  simp only [Std.Legacy.Range.forIn_eq_forIn_range', Std.Legacy.Range.size, Nat.sub_zero, Nat.add_sub_cancel, Nat.div_one]
  generalize identEnd x requestDomain.size x.size = te
  generalize identEnd x te x.size = ge
  generalize x.get! ge = tag
  generalize identEnd x (ge + 1) x.size = ce
  generalize identEnd x ce x.size = ye
  generalize identEnd x (ye + 32) x.size = ee
  generalize identEnd x (ee + 8) x.size = ke
  by_cases h0 : (decide (maxRequestBytes < x.size) || decide (x.size < requestDomain.size) || !sameBytes x requestDomain 0 0 requestDomain.size) = true
  · (rw [if_pos h0, if_pos h0]) <;> rfl
  rw [if_neg h0, if_neg h0]
  by_cases h1 : (te == 0 || ge == 0 || decide (x.size < ge + 1)) = true
  · (rw [if_pos h1, if_pos h1]) <;> rfl
  rw [if_neg h1, if_neg h1]
  by_cases h2 : (tag == 0 || decide (5 < tag)) = true
  · (rw [if_pos h2, if_pos h2]) <;> rfl
  rw [if_neg h2, if_neg h2]
  by_cases h3 : (ce == 0 || ye == 0 || decide (x.size < ye + 32)) = true
  · (rw [if_pos h3, if_pos h3]) <;> rfl
  rw [if_neg h3, if_neg h3]
  by_cases h4 : (ee == 0 || decide (x.size < ee + 8)) = true
  · (rw [if_pos h4, if_pos h4]) <;> rfl
  rw [if_neg h4, if_neg h4]
  by_cases h5 : 9223372036854775807 < be8 x ee
  · (rw [if_pos h5, if_pos h5]) <;> rfl
  rw [if_neg h5, if_neg h5]
  by_cases h6 : (ke == 0 || decide (x.size < ke + 2)) = true
  · (rw [if_pos h6, if_pos h6]) <;> rfl
  rw [if_neg h6, if_neg h6]
  generalize x.copySlice ce (x.extract te ge) (ge - te) (ye - ce) = pk
  generalize wordOf pk 0 pk.size 0 = payW
  generalize hn : (be2 x ke).toNat = nl
  generalize hY : forIn (m := Id) (List.range' 0 nl) ((none : Option (Option ReqB)), ke + 2, 0, (Array.mkEmpty nl : Array ByteArray)) _ = Y
  generalize hX : forIn (m := Id) (List.range' 0 nl) ((none : Option (Option RowsReq)), ke + 2, 0, (Array.mkEmpty nl : Array ByteArray), (Array.mkEmpty (if tag ≤ 3 then nl else 0) : Array LineRow)) _ = X
  have hYX : Y = pL x X := by
    rw [← hY, ← hX]
    refine Eq.trans (b := forIn (m := Id) (List.range' 0 nl) ((none : Option (Option ReqB)), ke + 2, 0, (Array.mkEmpty nl : Array ByteArray)) (stepB x tag ye ee)) ?_ ?_
    · congr 1
    · refine (loop1_sim x tag ye ee payW (tag ≤ 3) nl 0 ((none : Option (Option RowsReq)), ke + 2, 0, (Array.mkEmpty nl : Array ByteArray), (Array.mkEmpty (if tag ≤ 3 then nl else 0) : Array LineRow))).trans ?_
      congr 2
      refine congrArg (fun f => (forIn (m := Id) (List.range' 0 nl) ((none : Option (Option RowsReq)), ke + 2, 0, (Array.mkEmpty nl : Array ByteArray), (Array.mkEmpty (if tag ≤ 3 then nl else 0) : Array LineRow)) f : Id LD)) ?_
      funext i s
      unfold stepD stepD'
      generalize lineRow x (s.2.1 + 2) (s.2.1 + 2 + (be2 x s.2.1).toNat) tag ye (ye + 34) (ee - ye - 34) payW = lr
      cases lr <;> rfl
  rw [hYX]
  obtain ⟨a, q, sm, ls, rs⟩ := X
  dsimp only [pL]
  cases a with
  | some r => rfl
  | none =>
    dsimp only [Id.run, bind, pure]
    by_cases c1 : (decide (tag ≤ 3) && nl == 0 || nl != 0 && sm != (be8 x ee).toNat || decide (x.size < q + 2)) = true
    · rw [if_pos c1, if_pos c1]; rfl
    rw [if_neg c1, if_neg c1]
    by_cases c2 : (decide (256 < (be2 x q).toNat) || decide (x.size < q + 2 + 64 * (be2 x q).toNat)) = true
    · rw [if_pos c2, if_pos c2]; rfl
    rw [if_neg c2, if_neg c2]
    generalize hY2 : forIn (m := Id) (List.range' 0 (be2 x q).toNat) ((none : Option (Option ReqB)), q + 2, (Array.mkEmpty (be2 x q).toNat : Array ByteArray)) _ = Y2
    generalize hX2 : forIn (m := Id) (List.range' 0 (be2 x q).toNat) ((none : Option (Option RowsReq)), q + 2, (Array.mkEmpty (be2 x q).toNat : Array ByteArray)) _ = X2
    have hYX2 : Y2 = pE x X2 := by
      rw [← hY2, ← hX2]
      refine Eq.trans (b := forIn (m := Id) (List.range' 0 (be2 x q).toNat) ((none : Option (Option ReqB)), q + 2, (Array.mkEmpty (be2 x q).toNat : Array ByteArray)) (stepEB x)) ?_ ?_
      · congr 1
      · refine (loop2_sim x (be2 x q).toNat 0 ((none : Option (Option RowsReq)), q + 2, (Array.mkEmpty (be2 x q).toNat : Array ByteArray))).trans ?_
        congr 2
    rw [hYX2]
    obtain ⟨a2, q2, ev⟩ := X2
    dsimp only [pE]
    cases a2 with
    | some r => rfl
    | none =>
      dsimp only [Option.map]
      by_cases c3 : (q2 != x.size) = true
      · simp only [c3, if_true]; try rfl
      · simp only [c3, if_false]; try rfl

private def ExR {α β : Type} (R : α → β → Prop) : Except Word (α × Nat) → Except Word (β × Nat) → Prop
  | .error w, .error w' => w = w'
  | .ok (a, p), .ok (b, p') => R a b ∧ p = p'
  | _, _ => False

private def Pt {α β : Type} (bs : ByteArray) (R : α → β → Prop) (m1 : P α) (m2 : P β) : Prop :=
  ∀ p, ExR R ((m1.run bs).run p) ((m2.run bs).run p)

private theorem Pt_pure {α β : Type} {R : α → β → Prop} (bs : ByteArray) (a : α) (b : β) (h : R a b) :
    Pt bs R (pure a) (pure b) := fun p => ⟨h, rfl⟩

private theorem Pt_throw {α β : Type} {R : α → β → Prop} (bs : ByteArray) (w : Word) :
    Pt bs R (throw w : P α) (throw w : P β) := fun p => (rfl : w = w)

private theorem Pt_bind {α β γ δ : Type} {R : α → β → Prop} {S : γ → δ → Prop} (bs : ByteArray)
    {m1 : P α} {m2 : P β} {f : α → P γ} {g : β → P δ} (hm : Pt bs R m1 m2)
    (hf : ∀ a b, R a b → Pt bs S (f a) (g b)) : Pt bs S (m1 >>= f) (m2 >>= g) := by
  intro p
  have h := hm p
  show ExR S (((m1.run bs).run p) >>= fun r => ((f r.1).run bs).run r.2) (((m2.run bs).run p) >>= fun r => ((g r.1).run bs).run r.2)
  generalize (m1.run bs).run p = r1 at h ⊢
  generalize (m2.run bs).run p = r2 at h ⊢
  cases r1 with
  | error w =>
    cases r2 with
    | error w' => exact h
    | ok _ => exact h.elim
  | ok r =>
    cases r2 with
    | error w' => exact h.elim
    | ok r' =>
      obtain ⟨a, q⟩ := r
      obtain ⟨b, q'⟩ := r'
      obtain ⟨h1, h2⟩ := h
      subst h2
      exact hf a b h1 q

private theorem Pt_refl {α : Type} (bs : ByteArray) (m : P α) : Pt bs Eq m m := by
  intro p
  generalize (m.run bs).run p = r
  cases r with
  | error w => exact rfl
  | ok r => exact ⟨rfl, rfl⟩

private def FR {σ τ : Type} (R : σ → τ → Prop) : ForInStep σ → ForInStep τ → Prop
  | .done a, .done b => R a b
  | .yield a, .yield b => R a b
  | _, _ => False

private theorem Pt_forIn {σ τ : Type} {R : σ → τ → Prop} (bs : ByteArray) (l : List Nat) :
    ∀ (a : σ) (b : τ) (f : Nat → σ → P (ForInStep σ)) (g : Nat → τ → P (ForInStep τ)), R a b →
    (∀ i s t, R s t → Pt bs (FR R) (f i s) (g i t)) → Pt bs R (forIn l a f) (forIn l b g) := by
  induction l with
  | nil => intro a b f g hab _; rw [List.forIn_nil, List.forIn_nil]; exact Pt_pure bs a b hab
  | cons i l ih =>
    intro a b f g hab hfg
    rw [List.forIn_cons, List.forIn_cons]
    refine Pt_bind bs (hfg i a b hab) ?_
    intro r1 r2 h
    cases r1 with
    | done a' =>
      cases r2 with
      | done b' => exact Pt_pure bs _ _ h
      | yield b' => exact h.elim
    | yield a' =>
      cases r2 with
      | done b' => exact h.elim
      | yield b' => exact ih a' b' f g h hfg

private def cvP (e : ReqB) : Run.Req :=
  ⟨idNatA e.payKey, e.ra, if e.ra.flow.ruled then e.ra.lines.map (lineOfBytes (idNatA e.payKey)) else [], e.x⟩

private theorem reqOfFast_reqB (x : ByteArray) : reqOfFast x = (reqB x).map cvP := by
  rw [reqB_eq]
  unfold reqOfFast
  cases decodeRows x <;> rfl

private theorem Pt_read {α β : Type} {R : α → β → Prop} (bs : ByteArray) {f : ByteArray → P α} {m2 : P β}
    (h : Pt bs R (f bs) m2) : Pt bs R (read >>= f) m2 := fun p => h p

private theorem run_get {α : Type} (f : Nat → P α) (bs : ByteArray) (p : Nat) :
    (((get : P Nat) >>= f).run bs).run p = ((f p).run bs).run p := rfl
private theorem run_read {α : Type} (f : ByteArray → P α) (bs : ByteArray) (p : Nat) :
    (((read : P ByteArray) >>= f).run bs).run p = ((f bs).run bs).run p := rfl
private theorem run_set {α : Type} (q : Nat) (f : PUnit → P α) (bs : ByteArray) (p : Nat) :
    (((set q : P PUnit) >>= f).run bs).run p = ((f ⟨⟩).run bs).run q := rfl
private theorem run_throw_bind {α β : Type} (w : Word) (f : α → P β) (bs : ByteArray) (p : Nat) :
    (((throw w : P α) >>= f).run bs).run p = Except.error w := rfl
private theorem run_pure {α : Type} (a : α) (bs : ByteArray) (p : Nat) :
    (((pure a : P α)).run bs).run p = Except.ok (a, p) := rfl

private theorem reqs_rel (bs : ByteArray) (n : Nat) :
    Pt bs (fun (es : Array ReqB) (rs : List Run.Req) => rs = es.toList.map cvP) (reqsB n) (manyP n reqP) := by
  unfold reqsB manyP
  refine Pt_read bs ?_
  simp only [Std.Legacy.Range.forIn_eq_forIn_range', Std.Legacy.Range.size, Nat.sub_zero, Nat.add_sub_cancel, Nat.div_one]
  refine Pt_bind bs (R := fun (a : Array ReqB) (b : Array Run.Req) => b.toList = a.toList.map cvP)
    (Pt_forIn bs _ #[] #[] _ _ rfl ?_) ?_
  · intro i s t h
    unfold reqP
    simp only [bind_assoc, pure_bind]
    refine Pt_bind bs (Pt_refl bs (num 4)) (fun len _ hl => ?_)
    subst hl
    intro p
    unfold cutA
    simp only [bind_assoc, pure_bind, run_get, run_read, run_set, run_throw_bind, run_pure]
    by_cases h1 : p + len ≤ bs.size
    · have h1' : ¬ bs.size < p + len := by omega
      simp only [h1, h1', if_true, if_false, bind_assoc, pure_bind, run_set, run_throw_bind, run_pure]
      by_cases h2 : (bs.extract p (p + len)).size ≤ maxRequestBytes
      · simp only [h2, if_true, reqOfFast_reqB]
        cases hreq : reqB (bs.extract p (p + len)) with
        | none =>
          simp only [hreq, Option.map_none]
          exact rfl
        | some e =>
          simp only [hreq, Option.map_some]
          refine ⟨?_, rfl⟩
          show (t.push (cvP e)).toList = (s.push e).toList.map cvP
          simp [Array.toList_push, h]
      · simp only [h2, if_false]
        exact rfl
    · have h1' : bs.size < p + len := by omega
      simp only [h1, h1', if_true, if_false, bind_assoc, pure_bind, run_set, run_throw_bind, run_pure]
      exact rfl
  · intro a b h
    exact Pt_pure bs _ _ h
private instance : LawfulBEq ByteArray where
  rfl {a} := show (a.data == a.data) = true from beq_self_eq_true _
  eq_of_beq {a b} h := ByteArray.ext (beq_iff_eq.mp (show (a.data == b.data) = true from h))

private theorem hsB_le (l : List ReqB) : ∀ s : Std.HashSet ByteArray,
    (l.foldl (fun s e => s.insert e.payKey) s).size ≤ s.size + l.length := by
  induction l with
  | nil => intro s; simp
  | cons e t ih =>
    intro s
    simp only [List.foldl_cons, List.length_cons]
    have := ih (s.insert e.payKey)
    have h2 : (s.insert e.payKey).size ≤ s.size + 1 := Std.HashSet.size_insert_le
    omega

private theorem hsB_iff (l : List ReqB) : ∀ s : Std.HashSet ByteArray,
    ((l.foldl (fun s e => s.insert e.payKey) s).size = s.size + l.length) ↔
    (l.Pairwise (fun a b => a.payKey != b.payKey) ∧ ∀ e ∈ l, e.payKey ∉ s) := by
  induction l with
  | nil => intro s; simp
  | cons e t ih =>
    intro s
    simp only [List.foldl_cons, List.length_cons, List.pairwise_cons, List.mem_cons, forall_eq_or_imp]
    have hle := hsB_le t (s.insert e.payKey)
    have hsz : (s.insert e.payKey).size = if e.payKey ∈ s then s.size else s.size + 1 := Std.HashSet.size_insert
    by_cases hm : e.payKey ∈ s
    · rw [if_pos hm] at hsz
      constructor
      · intro h; omega
      · intro h; exact absurd hm h.2.1
    · rw [if_neg hm] at hsz
      have key : ((t.foldl (fun s e => s.insert e.payKey) (s.insert e.payKey)).size = s.size + (t.length + 1)) ↔
          ((t.foldl (fun s e => s.insert e.payKey) (s.insert e.payKey)).size = (s.insert e.payKey).size + t.length) := by omega
      rw [key, ih (s.insert e.payKey)]
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

private theorem hsB_pw (l : List ReqB) :
    ((l.foldl (fun s e => s.insert e.payKey) (∅ : Std.HashSet ByteArray)).size == l.length) = true ↔
      l.Pairwise (fun a b => a.payKey != b.payKey) := by
  have := hsB_iff l ∅
  simp only [Std.HashSet.size_empty, Nat.zero_add, Std.HashSet.not_mem_empty, not_false_eq_true, implies_true, and_true] at this
  simpa using this

private theorem Pt_ite {α β : Type} {R : α → β → Prop} (bs : ByteArray) (c : Prop) [Decidable c]
    {a b : P α} {a' b' : P β} (h1 : c → Pt bs R a a') (h2 : ¬ c → Pt bs R b b') :
    Pt bs R (if c then a else b) (if c then a' else b') := by
  by_cases h : c
  · rw [if_pos h, if_pos h]; exact h1 h
  · rw [if_neg h, if_neg h]; exact h2 h

private theorem Pt_ite_pos {α β : Type} {R : α → β → Prop} (bs : ByteArray) (c : Prop) [Decidable c] {a : P α} {a' b' : P β}
    (hc : c) (h : Pt bs R a a') : Pt bs R a (if c then a' else b') := by
  rw [if_pos hc]; exact h

private theorem Pt_ite2 {α β : Type} {R : α → β → Prop} (bs : ByteArray) (c c' : Prop) [Decidable c] [Decidable c']
    {a b : P α} {a' b' : P β} (hc : c ↔ c') (h1 : c → Pt bs R a a') (h2 : ¬ c → Pt bs R b b') :
    Pt bs R (if c then a else b) (if c' then a' else b') := by
  by_cases h : c
  · rw [if_pos h, if_pos (hc.mp h)]; exact h1 h
  · rw [if_neg h, if_neg (fun h' => h (hc.mpr h'))]; exact h2 h

private theorem Pt_throw_bind {α β γ δ : Type} {S : γ → δ → Prop} (bs : ByteArray) (w : Word) (f : α → P γ) (g : β → P δ) :
    Pt bs S ((throw w : P α) >>= f) ((throw w : P β) >>= g) :=
  Pt_bind bs (R := fun _ _ => False) (Pt_throw bs w) (fun _ _ h => h.elim)

private def AuthRel (a1 a2 : Auth) : Prop :=
  a1 = { a2 with reqs := a1.reqs } ∧ a1.reqs.map (·.x) = a2.reqs.map (·.x)

private theorem pw_iff (l : List ReqB) :
    l.Pairwise (fun a b => a.payKey != b.payKey) ↔ (l.map cvP).Pairwise (fun a b => a.q != b.q) := by
  rw [List.pairwise_map]
  apply List.Pairwise.iff
  intro a b
  simp only [cvP, bne_iff_ne, ne_eq]
  constructor
  · intro h h2; exact h (idNatA_inj _ _ h2)
  · intro h h2; exact h (by rw [h2])

private theorem chk_iff (es : Array ReqB) (e0 : ReqB) (hz : es[0]? = some e0) :
    ((es.all fun e => e.ra.tenantId == e0.ra.tenantId && e.ra.programId == e0.ra.programId) &&
      (Array.foldl (fun (s : Std.HashSet ByteArray) e => s.insert e.payKey) ∅ es).size == es.size) = true ↔
    ((match es.toList.map cvP with
      | [] => true
      | e0' :: _ => (es.toList.map cvP).all fun e => e.ra.tenantId == e0'.ra.tenantId && e.ra.programId == e0'.ra.programId) &&
      (List.foldl (fun (s : Std.HashSet Nat) e => s.insert e.q) ∅ (es.toList.map cvP)).size == (es.toList.map cvP).length) = true := by
  obtain ⟨L⟩ := es
  cases L with
  | nil => simp at hz
  | cons a t =>
    have ha : a = e0 := by simpa using hz
    subst ha
    have e1 : (Array.foldl (fun (s : Std.HashSet ByteArray) e => s.insert e.payKey) ∅ (⟨a :: t⟩ : Array ReqB)) =
        (a :: t).foldl (fun (s : Std.HashSet ByteArray) e => s.insert e.payKey) ∅ := (Array.foldl_toList _).symm
    have e2 : (⟨a :: t⟩ : Array ReqB).size = (a :: t).length := rfl
    have e3 : ((⟨a :: t⟩ : Array ReqB).all fun e => e.ra.tenantId == a.ra.tenantId && e.ra.programId == a.ra.programId) =
        ((a :: t).all fun e => e.ra.tenantId == a.ra.tenantId && e.ra.programId == a.ra.programId) := Array.all_toList.symm
    have e4 : ((List.map cvP (a :: t)).all fun e => e.ra.tenantId == (cvP a).ra.tenantId && e.ra.programId == (cvP a).ra.programId) =
        ((a :: t).all fun e => e.ra.tenantId == a.ra.tenantId && e.ra.programId == a.ra.programId) := by
      rw [List.all_map]; rfl
    simp only [List.map_cons, Bool.and_eq_true]
    rw [← List.map_cons, e1, e3, e2, e4, hsB_pw, hs_pw_pub, pw_iff]

private theorem chk_none (es : Array ReqB) (hz : es[0]? = none) :
    ((match es.toList.map cvP with
      | [] => true
      | e0' :: _ => (es.toList.map cvP).all fun e => e.ra.tenantId == e0'.ra.tenantId && e.ra.programId == e0'.ra.programId) &&
      (List.foldl (fun (s : Std.HashSet Nat) e => s.insert e.q) ∅ (es.toList.map cvP)).size == (es.toList.map cvP).length) = true := by
  obtain ⟨L⟩ := es
  cases L with
  | nil => simp
  | cons a t => simp at hz

private theorem auth_rel (bs : ByteArray) : Pt bs AuthRel authB authP := by
  unfold authB authP
  simp only []
  repeat (first
    | (refine Pt_bind bs (Pt_refl bs _) (fun _ _ h => ?_); subst h)
    | (refine Pt_ite bs _ (fun _ => ?_) (fun _ => Pt_throw_bind bs _ _ _)))
  refine Pt_bind bs (reqs_rel bs _) (fun es reqs h => ?_)
  subst h
  have hAR : ∀ (a1 a2 : Auth), a1 = { a2 with reqs := a1.reqs } → a1.reqs.map (·.x) = a2.reqs.map (·.x) → AuthRel a1 a2 :=
    fun a1 a2 h1 h2 => ⟨h1, h2⟩
  cases hz : es[0]? with
  | none =>
    dsimp only
    refine Pt_ite_pos bs _ (chk_none es hz) ?_
    refine Pt_pure bs _ _ (hAR _ _ rfl ?_)
    simp only [List.map_map]
    rfl
  | some e0 =>
    dsimp only
    refine Pt_ite2 bs _ _ (chk_iff es e0 hz) (fun _ => Pt_pure bs _ _ (hAR _ _ rfl ?_)) (fun _ => Pt_throw_bind bs _ _ _)
    simp only [List.map_map]
    rfl

private def ReqEq (q1 q2 : Req) : Prop :=
  ∃ a1 : Auth, q1 = { q2 with auth := a1 } ∧ AuthRel a1 q2.auth

set_option maxHeartbeats 1600000 in
private theorem body_rel (bs : ByteArray) (sh b : Nat) : Pt bs ReqEq (bodyB sh b) (bodyP sh b) := by
  unfold bodyB bodyP
  simp only []
  iterate 8 (refine Pt_bind bs (Pt_refl bs _) (fun _ _ h => ?_); subst h)
  refine Pt_ite bs _ (fun _ => ?_) (fun _ => Pt_throw_bind bs _ _ _)
  iterate 5 (refine Pt_bind bs (Pt_refl bs _) (fun _ _ h => ?_); subst h)
  refine Pt_bind bs (auth_rel bs) (fun a1 a2 h => Pt_pure bs _ _ ⟨a1, rfl, h⟩)

private theorem mapM_x : ∀ (l1 l2 : List Run.Req), l1.map (·.x) = l2.map (·.x) →
    l1.mapM (fun e => blob e.x.toList) = l2.mapM (fun e => blob e.x.toList)
  | [], [], _ => rfl
  | [], _ :: _, h => by simp at h
  | _ :: _, [], h => by simp at h
  | a :: t, b :: u, h => by
    simp only [List.map_cons, List.cons.injEq] at h
    simp only [List.mapM_cons, h.1, mapM_x t u h.2]

private theorem encAuth_congr (a1 a2 : Auth) (h : AuthRel a1 a2) : encAuth a1 = encAuth a2 := by
  obtain ⟨h1, h2⟩ := h
  generalize a1.reqs = L at h1 h2
  subst h1
  have hm := mapM_x L a2.reqs h2
  have hl : L.length = a2.reqs.length := by simpa using congrArg List.length h2
  unfold encAuth
  dsimp only
  rw [hm, hl]

private theorem encodeReq_congr (H : Bytes → Bytes) (q1 q2 : Req) (h : ReqEq q1 q2) : encodeReq H q1 = encodeReq H q2 := by
  obtain ⟨a1, h1, h2⟩ := h
  subst h1
  have := encAuth_congr a1 q2.auth h2
  simp only [encodeReq, encodeBody, this]

private theorem magic_get (bs : ByteArray) (h : 6 ≤ bs.size) :
    ((bs.extract 0 4).toList == magicReq) =
      (bs.get! 0 == 0x52 && bs.get! 1 == 0x52 && bs.get! 2 == 0x44 && bs.get! 3 == 0x51) := by
  have hl : bs.toList.length = bs.size := (Bin.size_eq_length' bs).symm
  have g : ∀ i, i < bs.size → bs.get! i = bs.toList.getD i 0 := fun i hi => by
    have : i < bs.toList.length := by omega
    rw [Engine3.get!_eq', Bin.getBang' bs i hi]
    simp [List.getD_eq_getElem?_getD, this]
  have hm : magicReq = [0x52, 0x52, 0x44, 0x51] := by decide +kernel
  rw [g 0 (by omega), g 1 (by omega), g 2 (by omega), g 3 (by omega), Bin.toList_extract', hm]
  rcases hL : bs.toList with _ | ⟨a, _ | ⟨b, _ | ⟨c, _ | ⟨d, t⟩⟩⟩⟩ <;> rw [hL] at hl <;> simp at hl ⊢ <;> try omega
  simp [Bool.and_assoc]

private theorem dig_eq (bs : ByteArray) (h : hdrBytes ≤ bs.size) :
    Engine3.sha3_512Into .empty frameDomain bs hdrBytes (bs.size - hdrBytes) =
      Bin.HB (⟨(domain "FRAME").toArray⟩ ++ bs.extract hdrBytes bs.size) := by
  have e : frameDomain = ⟨(domain "FRAME").toArray⟩ := by
    apply ByteArray.ext
    apply Array.toList_inj.mp
    unfold frameDomain
    rw [List.toList_data_toByteArray]
  rw [Engine3.sha3_512Into_eq _ _ _ _ _ (by omega), show hdrBytes + (bs.size - hdrBytes) = bs.size by omega, e,
    ByteArray.empty_append]
  simp only [Bin.HB, Engine3.sha3_512Into_all, ByteArray.empty_append]

private theorem core(H : Bytes → Bytes) (bs : ByteArray) (hs' : hdrBytes ≤ bs.size) (dg : ByteArray) (sh b : Nat) :
    (do let (q, pos) ← ((bodyB sh b).run bs).run hdrBytes
        unless pos == bs.size do throw .LENGTH
        pure (q, dg) : Except Word (Req × ByteArray)).map (fun (q, d) => (encodeReq H q, d.toList)) =
    (do let (q, pos) ← ((bodyP sh b).run (bs.extract hdrBytes bs.size)).run 0
        unless pos == (bs.extract hdrBytes bs.size).size do throw .LENGTH
        pure (q, dg) : Except Word (Req × ByteArray)).map (fun (q, d) => (encodeReq H q, d.toList)) := by
  have hb := bodyP_shift sh b bs hs'
  have hr := body_rel bs sh b hdrBytes
  rw [hb] at hr
  have hsz : (bs.extract hdrBytes bs.size).size = bs.size - hdrBytes := by
    simp [ByteArray.size_extract]
  rw [hsz]
  rcases h1 : ((bodyB sh b).run bs).run hdrBytes with w | ⟨q1, p1⟩ <;>
    rcases h2 : ((bodyP sh b).run (bs.extract hdrBytes bs.size)).run 0 with w' | ⟨q2, p2⟩ <;> rw [h1, h2] at hr
  · have : w = w' := hr
    subst this
    rfl
  · exact (show False from hr).elim
  · exact (show False from hr).elim
  · obtain ⟨hq, hp⟩ := show ReqEq q1 q2 ∧ p1 = p2 + hdrBytes from hr
    have hcong := encodeReq_congr H q1 q2 hq
    by_cases hcc : p2 = bs.size - hdrBytes
    · have hc' : p1 = bs.size := by omega
      dsimp only [bind, Except.bind]
      simp [hcc, hc', hcong]
      dsimp only [Except.map, pure, Except.pure]
      rw [hcong]
    · have hc' : ¬ p1 = bs.size := by omega
      dsimp only [bind, Except.bind]
      simp [hcc, hc']
      rfl

/-- `decodeB` reads what `decodeReqFast` reads: the same request bytes and digest, the same word on a refusal. -/
theorem decodeB_eq (H : Bytes → Bytes) (hH : ∀ b, H b = (Bin.HB ⟨b.toArray⟩).toList) (bs : ByteArray) :
    (decodeB bs).map (fun (q, d) => (encodeReq H q, d.toList)) =
      (decodeReq H bs.toList).map (fun (q, d) => (encodeReq H q, d)) := by
  rw [← decodeReqFast_eq H hH bs]
  by_cases hs : bs.size < hdrBytes
  · unfold decodeB decodeReqFast; rw [if_pos hs, if_pos hs]; rfl
  · have hs' : hdrBytes ≤ bs.size := by omega
    have hmg := magic_get bs (by have : hdrBytes = 82 := rfl; omega)
    have hdg := dig_eq bs hs'
    unfold decodeB decodeReqFast
    rw [if_neg hs, if_neg hs]
    dsimp only
    have ht : (Task.spawn fun _ => Engine3.sha3_512Into ByteArray.empty frameDomain bs hdrBytes (bs.size - hdrBytes)).get =
        Engine3.sha3_512Into ByteArray.empty frameDomain bs hdrBytes (bs.size - hdrBytes) := rfl
    rw [ht, hdg]
    by_cases hm : (bs.get! 0 == 0x52 && bs.get! 1 == 0x52 && bs.get! 2 == 0x44 && bs.get! 3 == 0x51 &&
        (bs.get! 4).toNat + 256 * (bs.get! 5).toNat == version) = true
    · have hm' : ((bs.extract 0 4).toList == magicReq && (bs.get! 4).toNat + 256 * (bs.get! 5).toNat == version) = true := by
        rw [hmg]; exact hm
      rw [if_pos hm, if_pos hm']
      by_cases hd : (Bin.HB ({ data := List.toArray (domain "FRAME") } ++ bs.extract hdrBytes bs.size) ==
          bs.extract 18 hdrBytes) = true
      · rw [if_pos hd, if_pos hd]
        exact core H bs hs' _ _ _
      · rw [if_neg hd, if_neg hd]
        dsimp only [bind, Except.bind, throw, throwThe, MonadExceptOf.throw, Except.map]
    · have hm' : ¬ ((bs.extract 0 4).toList == magicReq && (bs.get! 4).toNat + 256 * (bs.get! 5).toNat == version) = true := by
        rw [hmg]; exact hm
      rw [if_neg hm, if_neg hm']
      dsimp only [bind, Except.bind, throw, throwThe, MonadExceptOf.throw, Except.map]

end BlindLedger.Gate.Frame.Fast
