import BlindLedger.Gate.Engine3.ExactRows
import BlindLedger.Gate.Flat.QSortSpec
import BlindLedger.Gate.Flat.Theorems
import BlindLedger.Gate.Rules.Theorems

/-! A prototype of the decision step on fixed-width rows (conformance/ENGINE_V3.md §12): what `decideBatchIdx` decides,
    computed from arrays of fixed fields in one pass per batch.

    `layout` turns the fetched entries, the feed facts and the batch into arrays: each distinct key read gets a slot
    (its kind, its released and unresolved heads, their counts); each line and each fetched row becomes a `RowX` of
    machine words; feed facts are read once per id; payments get dense numbers.  It does what the probes and read tasks
    hand the decision thread, and is timed apart from it.

    `decideRows` then reads no list, string or key: per slot it computes once whether a released row is seen
    (`seen0`), whether it is hot (cut short), and the first unresolved row that claims it; per line the rule bits as a
    mask, the claims carried forward as slot bits and the first counterpart; per payment, in one pass over the
    decisions, the payment outcome and bypass (`payOutcomeG_eq`).  The record keeps only the first counterpart, so the
    reference is compared through `project`.  Not part of the engine; synthetic, nonpayment, non-PHI. -/

namespace BlindLedger.Gate.Flat.Rows

open BlindLedger.Gate.Rules BlindLedger.Gate.Rules.Fast BlindLedger.Gate.Flat
open BlindLedger.Gate.Engine3 (fitsLine2 RowX W9 redoW word rowX_lt_eq)
open Std (HashMap HashSet)
open BlindLedger.Gate.OnepIndex (capD)

/-! ## Layout -/

/-- A run of facts or rows: start, length, and whether the source held more than `capN`. -/
structure Rg where
  s : Nat
  n : Nat
  over : Bool
  deriving Inhabited

/-- A span as read under one member: whether its member is that member, and its plan as three words when it can be a
    payee. -/
structure SpanF where
  plan : Nat
  small : Bool
  p0 : UInt64
  p1 : UInt64
  p2 : UInt64
  start : Nat
  stop : Nat
  mOk : Bool
  deriving Inhabited

/-- A key read: its kind, its released heads `[rs, rs + rn)` of `rc` rows and unresolved heads `[us, us + un)` of
    `uc` rows; a count is the key's core's when the core holds more than `capN` rows (`capCount`). -/
structure Slot where
  kind : Nat
  rs : Nat
  rn : Nat
  rc : Nat
  us : Nat := 0
  un : Nat := 0
  uc : Nat := 0
  deriving Inhabited

structure LineIn where
  row : RowX
  ke : Nat
  kn : Nat
  ki : Nat
  pay : Nat
  dmf : Rg
  span : Rg
  pdP : Rg
  pdR : Rg
  exP : Rg
  exR : Rg
  fseen : Bool
  deriving Inhabited

structure Lay where
  today : Nat
  relCh : Bool
  unrCh : Bool
  dmfSome : Bool
  pdSome : Bool
  exclSome : Bool
  spanSome : Bool
  dmfOk : Bool
  pdOk : Bool
  exclOk : Bool
  spanOk : Bool
  lines : Array LineIn
  slots : Array Slot
  relP : Array RowX
  relSeq : Array Nat
  unrP : Array RowX
  unrSeq : Array Nat
  /-- Per unresolved row: its member's spans and the slot of its id key among the released reads (`slots.size` if
      none). -/
  uSpan : Array Rg
  uId : Array Nat
  dmf : Array Death
  pdeath : Array Death
  excl : Array Exclusion
  spans : Array SpanF
  redo : HashSet W9
  pRedo : Array Bool
  pByp : Array (Option UInt32)
  /-- Per line: the holds mask of its payment's HOLD-level grant entry (`FCtx.lim`), as for `pByp`. -/
  lLim : Array (Option UInt32)
  /-- For `toRef` only: the source lines and rows. -/
  src : Array Line
  relSrc : Array Line
  unrSrc : Array Line

def nilLine : Line := ⟨0, 0, .FFS_CLAIM, 0, 0, 0, 0, 0, 0, 0⟩

instance : Inhabited Death := ⟨⟨0, 0⟩⟩

instance : Inhabited Exclusion := ⟨⟨0, 0, 0⟩⟩

abbrev Facts (α : Type) := HashMap Nat Rg × Array α

/-- The facts of id `i`, read once per batch. -/
def readFacts {α : Type} (g : Nat → List α) (st : Facts α) (i : Nat) : Rg × Facts α :=
  match st.1.get? i with
  | some r => (r, st)
  | none =>
    let xs := g i
    let fs := facts xs
    let r : Rg := ⟨st.2.size, fs.length, feedOver xs⟩
    (r, (st.1.insert i r, st.2 ++ fs.toArray))

def spanF (i : Nat) (s : Span) : SpanF :=
  ⟨s.plan, decide (s.plan < 2 ^ 192), word s.plan 2, word s.plan 1, word s.plan 0, s.start, s.stop, s.member == i⟩

def layout (s : St) (fc : FCtx) (f : List Nat) (b : List Line) : Lay := Id.run do
  let fe := fetch s fc.redo b
  let fd := fc.feeds
  let mut slotOf : HashMap Key Nat := ∅
  let mut slots : Array Slot := #[]
  let mut relP : Array RowX := #[]
  let mut relSeq : Array Nat := #[]
  let mut relSrc : Array Line := #[]
  for (k, e) in fe.rel do
    let hs := heads e
    slotOf := slotOf.insert k slots.size
    slots := slots.push { kind := k.headD 9, rs := relP.size, rn := hs.length, rc := capCount fe.relCore k e }
    for p in hs do
      relP := relP.push (RowX.of p.row)
      relSeq := relSeq.push p.seq
      relSrc := relSrc.push p.row
  let none_ := slots.size
  let mut sp : Facts SpanF := (∅, #[])
  let mut unrP : Array RowX := #[]
  let mut unrSeq : Array Nat := #[]
  let mut unrSrc : Array Line := #[]
  let mut uSpan : Array Rg := #[]
  let mut uId : Array Nat := #[]
  for (k, e) in fe.unr do
    let hs := heads e
    match slotOf.get? k with
    | some j =>
      slots := slots.modify j fun sl => { sl with us := unrP.size, un := hs.length, uc := capCount fe.unrCore k e }
    | none =>
      slotOf := slotOf.insert k slots.size
      slots := slots.push
        { kind := k.headD 9, rs := 0, rn := 0, rc := 0, us := unrP.size, un := hs.length,
          uc := capCount fe.unrCore k e }
    for p in hs do
      unrP := unrP.push (RowX.of p.row)
      unrSeq := unrSeq.push p.seq
      unrSrc := unrSrc.push p.row
      let (r, sp') := readFacts (fun i => (fd.span i).map (spanF i)) sp p.row.member
      sp := sp'
      uSpan := uSpan.push r
      uId := uId.push ((slotOf.get? (idKey p.row)).filter (· < none_) |>.getD none_)
  let mut dm : Facts Death := (∅, #[])
  let mut pd : Facts Death := (∅, #[])
  let mut ex : Facts Exclusion := (∅, #[])
  let mut payOf : HashMap Nat Nat := ∅
  let mut pRedo : Array Bool := #[]
  let mut pByp : Array (Option UInt32) := #[]
  let fs := HashSet.ofList f
  let mut lines : Array LineIn := #[]
  for l in b do
    let (rd, dm') := readFacts fd.dmf dm l.member
    dm := dm'
    let (rp, pd') := readFacts fd.pdeath pd l.payee
    let (rr, pd'') := readFacts fd.pdeath pd' l.rendering
    pd := pd''
    let (xp, ex') := readFacts fd.excl ex l.payee
    let (xr, ex'') := readFacts fd.excl ex' l.rendering
    ex := ex''
    let (rs, sp') := readFacts (fun i => (fd.span i).map (spanF i)) sp l.member
    sp := sp'
    let mut pj := 0
    match payOf.get? l.pay with
    | some j => pj := j
    | none =>
      pj := pRedo.size
      payOf := payOf.insert l.pay pRedo.size
      pRedo := pRedo.push (fc.redo.contains l.pay)
      pByp := pByp.push ((fc.byp.lookup l.pay).map fun m => (m % 2 ^ 32).toUInt32)
    lines := lines.push
      { row := RowX.of l, ke := slotOf.getD (exactKey l) 0, kn := slotOf.getD (nearKey l) 0,
        ki := slotOf.getD (idKey l) 0, pay := pj, dmf := rd, span := rs, pdP := rp, pdR := rr, exP := xp,
        exR := xr, fseen := fs.contains l.id }
  { today := fc.today, relCh := s.rel.head.chained fc.today, unrCh := s.unr.head.chained fc.today,
    dmfSome := fd.dmfSome, pdSome := fd.pdSome, exclSome := fd.exclSome, spanSome := fd.spanSome,
    dmfOk := fd.dmfOk, pdOk := fd.pdOk, exclOk := fd.exclOk, spanOk := fd.spanOk,
    lines, slots, relP, relSeq, unrP, unrSeq, uSpan, uId, dmf := dm.2, pdeath := pd.2, excl := ex.2, spans := sp.2,
    redo := redoW fc.redo, pRedo, pByp,
    lLim := b.toArray.map fun l => (fc.lim.lookup l.pay).map fun m => (m % 2 ^ 32).toUInt32,
    src := b.toArray, relSrc, unrSrc }

/-! ## Masks: bit `r.idx` for reason `r` -/

def bit (r : Reason) : UInt32 := 1 <<< r.idx.toUInt32

def maskOf (p : Reason → Bool) : UInt32 := reasons.foldl (fun a r => if p r then a ||| bit r else a) 0

def reviewM : UInt32 := maskOf review
def bypM : UInt32 := maskOf bypassable
def bAlready : UInt32 := bit .ALREADY_DECIDED
def bCapMM : UInt32 := bit .CAP_MEMBER_MONTH_DUPLICATE
def bCollides : UInt32 := bit .COLLIDES_WITH_UNRESOLVED_NEAR
def bDupUnr : UInt32 := bit .DUPLICATE_OF_UNRESOLVED
def bFfsDup : UInt32 := bit .FFS_DUPLICATE_LINE
def bFfsNear : UInt32 := bit .FFS_NEAR_DUPLICATE
def bMemDead : UInt32 := bit .MEMBER_DECEASED
def bMemDeadU : UInt32 := bit .MEMBER_DECEASED_UNVERIFIED
def bNotEnr : UInt32 := bit .MEMBER_NOT_ENROLLED
def bNotEnrU : UInt32 := bit .MEMBER_NOT_ENROLLED_UNVERIFIED
def bCap : UInt32 := bit .POSTING_CAP
def bProvDead : UInt32 := bit .PROVIDER_DECEASED
def bProvDeadU : UInt32 := bit .PROVIDER_DECEASED_UNVERIFIED
def bExcl : UInt32 := bit .PROVIDER_EXCLUDED
def bExclU : UInt32 := bit .PROVIDER_EXCLUDED_UNVERIFIED
def bFuture : UInt32 := bit .SERVICE_DATE_FUTURE
def bInvalid : UInt32 := bit .SERVICE_DATE_INVALID
def bStaleDmf : UInt32 := bit .STALE_DMF
def bStaleEnr : UInt32 := bit .STALE_ENROLLMENT
def bStaleExcl : UInt32 := bit .STALE_EXCLUSION
def bStalePd : UInt32 := bit .STALE_PROVIDER_DEATH
def bStaleRel : UInt32 := bit .STALE_RELEASED
def bStaleUnr : UInt32 := bit .STALE_UNRESOLVED

/-- 0 ALLOW, 1 HOLD, 2 HUMAN_REVIEW (`outcomeOf`). -/
@[inline] def outOf (m : UInt32) : UInt8 := if m == 0 then 0 else if m &&& ~~~reviewM != 0 then 1 else 2

/-! ## The decision -/

@[inline] def on (c : Bool) (b : UInt32) : UInt32 := if c then b else 0

def anySame (ps : Array RowX) (s n : Nat) (r : RowX) : Bool := Id.run do
  for j in [s:s + n] do
    if ps[j]!.same r then return true
  return false

def deadIn (ds : Array Death) (g : Rg) (d : Nat) : Bool := Id.run do
  for j in [g.s:g.s + g.n] do
    if ds[j]!.date < d then return true
  return false

def exclIn (es : Array Exclusion) (g : Rg) (d : Nat) : Bool := Id.run do
  for j in [g.s:g.s + g.n] do
    let e := es[j]!
    if e.start ≤ d && d ≤ e.stop then return true
  return false

def enrolledIn (ss : Array SpanF) (g : Rg) (r : RowX) : Bool := Id.run do
  let d := r.date.toNat
  for j in [g.s:g.s + g.n] do
    let s := ss[j]!
    if s.mOk && s.start ≤ d && d ≤ s.stop && (!r.cap || s.small && s.p0 == r.a0 && s.p1 == r.a1 && s.p2 == r.a2) then return true
  return false

def overlapIn (ss : Array SpanF) (g : Rg) (d : Nat) : Bool := Id.run do
  let first := d / 100 * 100 + 1
  let last := d / 100 * 100 + monthDays (d / 10000) (d / 100 % 100)
  for j in [g.s:g.s + g.n] do
    for k in [g.s:g.s + g.n] do
      let s := ss[j]!
      let t := ss[k]!
      if s.plan != t.plan && max first (max s.start t.start) ≤ min last (min s.stop t.stop) then return true
  return false

/-- A fetched row is its own payment's released row (`own`), read through the slot of its id key. -/
def ownRow (x : Lay) (slot : Nat) (y : RowX) : Bool :=
  if y.payIn x.redo && slot < x.slots.size then
    let si := x.slots[slot]!
    anySame x.relP si.rs si.rn y
  else false

@[inline] def seenAt (sn seen0 : Array Bool) (k : Nat) : Bool := sn[k]! || seen0[k]!

/-- `pending` on slot `k` for line `r`: a claimer, other than `r` itself when a bypass names `r`'s payment. -/
@[inline] def pendAt (x : Lay) (cfirst : Array Nat) (csame : Array Bool) (byp : Bool) (r : RowX) (k : Nat) : Bool :=
  let f := cfirst[k]!
  f < x.unrP.size && (!byp || !(csame[k]! && x.unrP[f]!.same r))

/-- The earliest released head on slot `k`, against the best so far `(cp, seq)`. -/
@[inline] def relC (x : Lay) (k : Nat) (acc : Nat × Nat) : Nat × Nat :=
  let sl := x.slots[k]!
  if sl.rn > 0 then
    let q := x.relSeq[sl.rs]!
    if acc.1 == 0 || q < acc.2 then (2 * sl.rs + 1, q) else acc
  else acc

/-- The earliest unresolved head on slot `k` whose claim meets the line's keys. -/
def unrC (x : Lay) (capClaim : Array Bool) (r : RowX) (k : Nat) (acc : Nat × Nat) : Nat × Nat := Id.run do
  let sl := x.slots[k]!
  for j in [sl.us:sl.us + sl.un] do
    let y := x.unrP[j]!
    if r.exactEq y || r.idEq y || !capClaim[j]! && r.nearEq y then
      let q := x.unrSeq[j]!
      return if acc.1 == 0 || q < acc.2 then (2 * j + 2, q) else acc
  return acc

structure Dec where
  line : Nat
  mask : UInt32
  out : UInt8
  /-- 0 none, `2j + 1` released row `j`, `2j + 2` unresolved row `j`. -/
  cp : Nat
  deriving Inhabited

/-- The decisions, the lines each set gains, per payment whether a bypass releases it (`byd`) and per line whether its
    payment goes at HOLD authority (`lft`, `Rules.limitedPay`). -/
structure Out where
  ds : Array Dec
  rel : Array Nat
  unr : Array Nat
  byd : Array Bool
  lft : Array Bool

def decideRows (x : Lay) : Out := Id.run do
  let ns := x.slots.size
  let nl := x.lines.size
  -- Per line, independent of order: own, held, not enrolled, the feed and date bits, capped by a feed.
  let mut own : Array Bool := Array.emptyWithCapacity nl
  let mut held : Array Bool := Array.emptyWithCapacity nl
  let mut notEnr : Array Bool := Array.emptyWithCapacity nl
  let mut base : Array UInt32 := Array.emptyWithCapacity nl
  let mut fcap : Array Bool := Array.emptyWithCapacity nl
  for li in x.lines do
    let r := li.row
    let d := r.date.toNat
    let v := validDate d
    let si := x.slots[li.ki]!
    own := own.push (x.pRedo[li.pay]! && anySame x.relP si.rs si.rn r)
    held := held.push (anySame x.unrP si.us si.un r)
    let enr := enrolledIn x.spans li.span r
    let ne := x.spanOk && v && !enr
    notEnr := notEnr.push ne
    let md := deadIn x.dmf li.dmf d
    let pdd := deadIn x.pdeath li.pdP d || deadIn x.pdeath li.pdR d
    let exd := exclIn x.excl li.exP d || exclIn x.excl li.exR d
    base := base.push (
      on (x.dmfOk && v && md) bMemDead ||| on (x.dmfSome && !x.dmfOk && v && md) bMemDeadU |||
      on ne bNotEnr ||| on (x.spanSome && !x.spanOk && v && !enr) bNotEnrU |||
      on (x.pdOk && v && pdd) bProvDead ||| on (x.pdSome && !x.pdOk && v && pdd) bProvDeadU |||
      on (x.exclOk && v && exd) bExcl ||| on (x.exclSome && !x.exclOk && v && exd) bExclU |||
      on (x.today < d) bFuture ||| on (!v) bInvalid ||| on (!x.dmfOk) bStaleDmf ||| on (!x.spanOk) bStaleEnr |||
      on (!x.exclOk) bStaleExcl ||| on (!x.pdOk) bStalePd ||| on (!x.relCh) bStaleRel ||| on (!x.unrCh) bStaleUnr |||
      on (r.cap && x.spanOk && v && overlapIn x.spans li.span d) bCapMM)
    fcap := fcap.push (li.dmf.over || li.span.over || li.pdP.over || li.exP.over || li.pdR.over || li.exR.over)
  -- Per unresolved row: its claim drops the near key (CAP, not enrolled, not its own payment's released row).
  let mut capClaim : Array Bool := Array.emptyWithCapacity x.unrP.size
  for j in [0:x.unrP.size] do
    let y := x.unrP[j]!
    let c := y.cap && (x.spanOk && validDate y.date.toNat && !enrolledIn x.spans x.uSpan[j]! y) &&
      !ownRow x x.uId[j]! y
    capClaim := capClaim.push c
  -- Per slot: own lines on it (for `seen0`), hot, the first unresolved claimer and whether all claimers are one line.
  let mut ownAt : Array (Array Nat) := Array.replicate ns #[]
  let mut hot : Array Bool := x.slots.map fun sl => capN < sl.rc || capN < sl.uc
  for i in [0:nl] do
    let li := x.lines[i]!
    if own[i]! then
      ownAt := (ownAt.modify li.ke (·.push i)).modify li.kn (·.push i) |>.modify li.ki (·.push i)
    if li.row.cap && li.span.over then
      hot := (hot.set! li.ke true).set! li.kn true |>.set! li.ki true
  let mut ic := false
  let mut seen0 : Array Bool := Array.emptyWithCapacity ns
  let mut cfirst : Array Nat := Array.emptyWithCapacity ns
  let mut csame : Array Bool := Array.emptyWithCapacity ns
  for k in [0:ns] do
    let sl := x.slots[k]!
    if sl.kind == 4 && capN < sl.rc then ic := true
    let oa := ownAt[k]!
    let mut s0 := false
    for j in [sl.rs:sl.rs + sl.rn] do
      let y := x.relP[j]!
      if !oa.any fun i => x.lines[i]!.row.same y then
        s0 := true
        break
    seen0 := seen0.push s0
    let near := sl.kind == 0 || sl.kind == 2
    let mut first := none
    let mut same := true
    let mut h := hot[k]!
    for j in [sl.us:sl.us + sl.un] do
      let y := x.unrP[j]!
      if y.cap && x.uSpan[j]!.over then h := true
      if !near || !capClaim[j]! then
        match first with
        | none => first := some j
        | some f => if !(x.unrP[f]!.same y) then same := false
    hot := hot.set! k h
    cfirst := cfirst.push (first.getD x.unrP.size)
    csame := csame.push same
  -- Decision order: own lines, then the rest, each in `enc` order.
  let lt := fun (i j : Nat) => x.lines[i]!.row.lt x.lines[j]!.row
  let ord := ((Array.range nl).filter (own[·]!)).qsort lt ++ ((Array.range nl).filter (!own[·]!)).qsort lt
  let mut sn : Array Bool := Array.replicate ns false
  for li in x.lines do
    if li.fseen then sn := sn.set! li.ki true
  let mut ds : Array Dec := Array.emptyWithCapacity nl
  let np := x.pRedo.size
  let mut pHold : Array Bool := Array.replicate np false
  let mut pAllow : Array Bool := Array.replicate np true
  let mut pHeld : Array Bool := Array.replicate np false
  let mut pByp : Array Bool := Array.replicate np true
  for i in ord do
    let li := x.lines[i]!
    let r := li.row
    let byp := x.pByp[li.pay]!
    let bp := byp.isSome
    let sE := seenAt sn seen0 li.ke
    let sN := seenAt sn seen0 li.kn
    let pE := pendAt x cfirst csame bp r li.ke
    let pN := pendAt x cfirst csame bp r li.kn
    let c := r.cap
    let m := base[i]! |||
      on (seenAt sn seen0 li.ki || pendAt x cfirst csame bp r li.ki) bAlready ||| on (c && (sE || sN)) bCapMM |||
      on (!c && pN && !pE) bCollides ||| on (pE || c && pN) bDupUnr ||| on (!c && sE) bFfsDup |||
      on (!c && sN && !sE) bFfsNear
    let capped := ic || hot[li.ke]! || hot[li.kn]! || hot[li.ki]! || fcap[i]!
    let m := if capped then m ||| bCap else m
    -- First counterpart: the earliest released row on a key of the line, else the earliest unresolved row whose
    -- claim meets the line's keys.
    let a := relC x li.ki (relC x li.kn (relC x li.ke (0, 0)))
    let cp := if a.1 != 0 then a.1 else (unrC x capClaim r li.ki (unrC x capClaim r li.kn (unrC x capClaim r li.ke (0, 0)))).1
    let o := outOf m
    ds := ds.push ⟨i, m, o, cp⟩
    sn := sn.set! li.ke true |>.set! li.ki true
    if !(c && notEnr[i]! && !own[i]!) then sn := sn.set! li.kn true
    let p := li.pay
    if o == 1 then pHold := pHold.set! p true
    if !(o == 0 && (!x.pRedo[p]! || own[i]!)) then pAllow := pAllow.set! p false
    if held[i]! then pHeld := pHeld.set! p true
    match byp with
    | some bm => if m &&& ~~~(bypM &&& bm) != 0 then pByp := pByp.set! p false
    | none => pure ()
  -- Per payment, once: outcome, bypass and lift (every reason on its lines is one a bypass may override and its entry's
  -- holds mask does not name); then the rows each set gains, in decision order.
  let bypassed := fun (p : Nat) => x.pByp[p]!.isSome && !x.pRedo[p]! && pHeld[p]! && pByp[p]!
  let mut pLift : Array Bool := Array.replicate np true
  for d in ds do
    match x.lLim[d.line]! with
    | some lm => if d.mask &&& ~~~(bypM &&& ~~~lm) != 0 then pLift := pLift.set! x.lines[d.line]!.pay false
    | none => pure ()
  let lifted := fun (i p : Nat) => x.lLim[i]!.isSome && !x.pRedo[p]! && (pHold[p]! || !pAllow[p]!) && pLift[p]!
  let mut rel : Array Nat := #[]
  let mut unr : Array Nat := #[]
  for d in ds do
    let p := x.lines[d.line]!.pay
    let bp := bypassed p
    let lf := lifted d.line p
    if d.out == 0 && !x.pRedo[p]! && !pHold[p]! && pAllow[p]! || bp || lf && !own[d.line]! then rel := rel.push d.line
    if d.out != 0 && d.mask &&& bAlready == 0 && !own[d.line]! && !(x.pByp[p]!.isSome && held[d.line]!) && !bp && !lf then
      unr := unr.push d.line
  return ⟨ds, rel, unr, (Array.range np).map bypassed, (Array.range nl).map fun i => lifted i x.lines[i]!.pay⟩

/-! ## Against the reference -/

def outcomeOf8 : UInt8 → Outcome
  | 0 => .ALLOW
  | 1 => .HOLD
  | _ => .HUMAN_REVIEW

def cpId (x : Lay) (cp : Nat) : Option Nat :=
  if cp == 0 then none
  else if cp % 2 == 1 then some (x.relSrc.getD (cp / 2) nilLine).id
  else some (x.unrSrc.getD (cp / 2 - 1) nilLine).id

abbrev Proj := List (Line × Outcome × List Reason × Option Nat) × List Line × List Line

def Out.toRef (x : Lay) (o : Out) : Proj :=
  (o.ds.toList.map fun d => (x.src.getD d.line nilLine, outcomeOf8 d.out,
      reasons.filter (fun r => d.mask &&& bit r != 0), cpId x d.cp),
   o.rel.toList.map (x.src.getD · nilLine), o.unr.toList.map (x.src.getD · nilLine))

/-- What the record keeps of a decision: line, outcome, reasons, first counterpart. -/
def project (r : List Decision × List Line × List Line) : Proj :=
  (r.1.map fun d => (d.line, d.outcome, d.reasons, d.counterparts.head?), r.2.1, r.2.2)

/-! ## Proof plan for `decideRows_eq`

    `Rep` says what `layout` builds, in terms of the fetched entries; the scan lemmas turn each range scan into the
    list scan of the reference; the sort lemma matches the `qsort` order to `canonical`; the last three lemmas are the
    fold over the decision order, and the payment pass. -/

/-- `r` reads `x` from `a`. -/
def Slice {α : Type} (a : Array α) (r : Rg) (x : List α) : Prop :=
  r.s + r.n ≤ a.size ∧ (a.toList.drop r.s).take r.n = x

/-- `layout`'s arrays, read through `fetch`: slot `j` is the `j`-th released read; line `i` holds the slots of its
    three keys; each feed range holds the facts of its id (cut to `capN`). -/
structure Rep (L : Lay) (s : St) (fc : FCtx) (f : List Nat) (b : List Line) : Prop where
  src : L.src = b.toArray
  rows : L.lines.toList.map (·.row) = b.map RowX.of
  scalars : L.today = fc.today ∧ L.relCh = s.rel.head.chained fc.today ∧ L.unrCh = s.unr.head.chained fc.today
  nslots : L.slots.size = (fetch s fc.redo b).rel.length
  relSlot : ∀ j (h : j < (fetch s fc.redo b).rel.length),
    let ke := (fetch s fc.redo b).rel[j]
    L.slots[j]!.kind = ke.1.headD 9 ∧ L.slots[j]!.rc = capCount (fetch s fc.redo b).relCore ke.1 ke.2 ∧
    L.slots[j]!.rn = (heads ke.2).length ∧
    ((L.relP.toList.drop L.slots[j]!.rs).take L.slots[j]!.rn = (heads ke.2).map (RowX.of ·.row)) ∧
    ((L.relSeq.toList.drop L.slots[j]!.rs).take L.slots[j]!.rn = (heads ke.2).map (·.seq)) ∧
    ((L.relSrc.toList.drop L.slots[j]!.rs).take L.slots[j]!.rn = (heads ke.2).map (·.row))
  unrSlot : ∀ j (h : j < (fetch s fc.redo b).rel.length),
    let ke := (fetch s fc.redo b).rel[j]
    match (fetch s fc.redo b).unr.lookup ke.1 with
    | some e => L.slots[j]!.uc = capCount (fetch s fc.redo b).unrCore ke.1 e ∧ L.slots[j]!.un = (heads e).length ∧
        ((L.unrP.toList.drop L.slots[j]!.us).take L.slots[j]!.un = (heads e).map (RowX.of ·.row)) ∧
        ((L.unrSeq.toList.drop L.slots[j]!.us).take L.slots[j]!.un = (heads e).map (·.seq)) ∧
        ((L.unrSrc.toList.drop L.slots[j]!.us).take L.slots[j]!.un = (heads e).map (·.row))
    | none => L.slots[j]!.un = 0 ∧ L.slots[j]!.uc = 0
  lineKeys : ∀ i (h : i < b.length),
    ((fetch s fc.redo b).rel[L.lines[i]!.ke]?.map (·.1) = some (exactKey b[i])) ∧
    ((fetch s fc.redo b).rel[L.lines[i]!.kn]?.map (·.1) = some (nearKey b[i])) ∧
    ((fetch s fc.redo b).rel[L.lines[i]!.ki]?.map (·.1) = some (idKey b[i]))
  unrId : ∀ j (h : j < L.unrP.size), L.uId[j]! < L.slots.size →
    ((fetch s fc.redo b).rel[L.uId[j]!]?.map (·.1) = some (idKey (L.unrSrc.getD j nilLine)))
  unrRowX : ∀ j (h : j < L.unrP.size), L.unrP[j]! = RowX.of (L.unrSrc.getD j nilLine)
  unrHead : ∀ j (h : j < L.unrP.size), ∃ ke ∈ (fetch s fc.redo b).unr, ∃ p ∈ heads ke.2,
    p.row = L.unrSrc.getD j nilLine
  unrIdTot : ∀ j (h : j < L.unrP.size),
    (∃ i, ∃ hi : i < (fetch s fc.redo b).rel.length, (fetch s fc.redo b).rel[i].1 = idKey (L.unrSrc.getD j nilLine)) →
    L.uId[j]! < L.slots.size
  feeds : ∀ i (h : i < b.length),
    let li := L.lines[i]!
    let l := b[i]
    (Slice L.dmf li.dmf (facts (fc.feeds.dmf l.member)) ∧
      li.dmf.over = feedOver (fc.feeds.dmf l.member)) ∧
    (Slice L.pdeath li.pdP (facts (fc.feeds.pdeath l.payee)) ∧
      li.pdP.over = feedOver (fc.feeds.pdeath l.payee)) ∧
    (Slice L.pdeath li.pdR (facts (fc.feeds.pdeath l.rendering)) ∧
      li.pdR.over = feedOver (fc.feeds.pdeath l.rendering)) ∧
    (Slice L.excl li.exP (facts (fc.feeds.excl l.payee)) ∧
      li.exP.over = feedOver (fc.feeds.excl l.payee)) ∧
    (Slice L.excl li.exR (facts (fc.feeds.excl l.rendering)) ∧
      li.exR.over = feedOver (fc.feeds.excl l.rendering)) ∧
    (Slice L.spans li.span (facts ((fc.feeds.span l.member).map (spanF l.member))) ∧
      li.span.over = feedOver (fc.feeds.span l.member))
  unrSpan : ∀ j (h : j < L.unrP.size),
    let g := L.uSpan[j]!
    let m := (L.unrSrc.getD j nilLine).member
    Slice L.spans g (facts ((fc.feeds.span m).map (spanF m))) ∧ g.over = feedOver (fc.feeds.span m)
  relBnd : ∀ j (h : j < (fetch s fc.redo b).rel.length),
    L.slots[j]!.rs + L.slots[j]!.rn ≤ L.relP.size ∧ L.slots[j]!.rs + L.slots[j]!.rn ≤ L.relSeq.size
  unrBnd : ∀ j (h : j < (fetch s fc.redo b).rel.length), 0 < L.slots[j]!.un →
    L.slots[j]!.us + L.slots[j]!.un ≤ L.unrP.size ∧ L.slots[j]!.us + L.slots[j]!.un ≤ L.unrSeq.size
  pay : ∀ i (h : i < b.length), L.lines[i]!.pay < L.pRedo.size ∧
    L.pRedo[L.lines[i]!.pay]! = fc.redo.contains b[i].pay ∧
    L.pByp[L.lines[i]!.pay]! = (fc.byp.lookup b[i].pay).map fun m => (m % 2 ^ 32).toUInt32
  paySame : ∀ i j (hi : i < b.length) (hj : j < b.length),
    L.lines[i]!.pay = L.lines[j]!.pay ↔ b[i].pay = b[j].pay
  fseen : ∀ i (h : i < b.length), L.lines[i]!.fseen = (idSeen f).contains (idKey b[i])
  flags : L.dmfOk = fc.feeds.dmfOk ∧ L.pdOk = fc.feeds.pdOk ∧ L.exclOk = fc.feeds.exclOk ∧ L.spanOk = fc.feeds.spanOk ∧
    L.dmfSome = fc.feeds.dmfSome ∧ L.pdSome = fc.feeds.pdSome ∧ L.exclSome = fc.feeds.exclSome ∧
    L.spanSome = fc.feeds.spanSome
  redoEq : L.redo = redoW fc.redo
  lim : ∀ i (h : i < b.length), L.lLim[i]! = (fc.lim.lookup b[i].pay).map fun m => (m % 2 ^ 32).toUInt32

/-! Loop and cache lemmas for `layout`. -/

/-- An invariant over a `for` loop in `Id`: it holds before the first element and each step keeps it. -/
theorem forIn_inv {α β : Type} (l : List α) (init : β) (f : α → β → Id (ForInStep β)) (P : List α → β → Prop)
    (h0 : P [] init)
    (hs : ∀ pre a post st, l = pre ++ a :: post → P pre st → ∃ st', f a st = .yield st' ∧ P (pre ++ [a]) st') :
    ∃ r, forIn l init f = r ∧ P l r := by
  suffices H : ∀ post pre st, l = pre ++ post → P pre st → ∃ r, forIn post st f = r ∧ P l r by
    exact H l [] init rfl h0
  intro post
  induction post with
  | nil => intro pre st h hp; exact ⟨st, rfl, by rw [h, List.append_nil]; exact hp⟩
  | cons a post ih =>
    intro pre st h hp
    obtain ⟨st', e, hp'⟩ := hs pre a post st h hp
    obtain ⟨r, er, hr⟩ := ih (pre ++ [a]) st' (by rw [h]; simp) hp'
    exact ⟨r, by rw [List.forIn_cons, e]; exact er, hr⟩

theorem Slice.mono {α : Type} {a a' : Array α} {r : Rg} {x : List α} (h : Slice a r x)
    (hp : a.toList <+: a'.toList) : Slice a' r x := by
  obtain ⟨t, ht⟩ := hp
  obtain ⟨h1, h2⟩ := h
  have hl : a.toList.length = a.size := by simp
  refine ⟨?_, ?_⟩
  · have : a'.toList.length = a'.size := by simp
    rw [← this, ← ht]; simp only [List.length_append]; omega
  · rw [← ht, List.drop_append_of_le_length (by omega), List.take_append_of_le_length (by simp; omega)]
    exact h2

/-- What a feed cache promises: each cached id's range reads its facts from the array. -/
def FOk {α : Type} (g : Nat → List α) (st : Facts α) : Prop :=
  ∀ j r, st.1.get? j = some r → Slice st.2 r (facts (g j)) ∧ r.over = feedOver (g j)

theorem readFacts_ok {α : Type} (g : Nat → List α) (st : Facts α) (i : Nat) (h : FOk g st) :
    FOk g (readFacts g st i).2 ∧ st.2.toList <+: (readFacts g st i).2.2.toList ∧
    Slice (readFacts g st i).2.2 (readFacts g st i).1 (facts (g i)) ∧ (readFacts g st i).1.over = feedOver (g i) := by
  unfold readFacts
  split
  · rename_i r hr
    obtain ⟨h1, h2⟩ := h i r hr
    exact ⟨h, List.prefix_refl _, h1, h2⟩
  · rename_i hn
    dsimp only
    have hpre : st.2.toList <+: (st.2 ++ (facts (g i)).toArray).toList := by simp
    refine ⟨?_, hpre, ?_, rfl⟩
    · intro j r hj
      rw [Std.HashMap.get?_insert] at hj
      split at hj
      · rename_i e
        cases hj
        obtain rfl := beq_iff_eq.1 e
        exact ⟨⟨by simp [facts], by simp [facts]; exact List.take_of_length_le (by simp)⟩, rfl⟩
      · obtain ⟨h1, h2⟩ := h j r hj
        exact ⟨h1.mono hpre, h2⟩
    · refine ⟨by simp [facts], ?_⟩
      simp [facts]; exact List.take_of_length_le (by simp)

theorem uniq_foldl_nodup : ∀ (ks : List Key) (acc : HashSet Key × List Key), (∀ x, acc.1.contains x = true ↔ x ∈ acc.2) →
    acc.2.Nodup → (ks.foldl uniqStep acc).2.Nodup
  | [], acc, _, hn => hn
  | a :: t, acc, h, hn => by
    rw [List.foldl_cons]
    by_cases ha : acc.1.contains a = true
    · have : uniqStep acc a = acc := by simp [uniqStep, ha]
      rw [this]; exact uniq_foldl_nodup t acc h hn
    · have hs : uniqStep acc a = (acc.1.insert a, a :: acc.2) := by simp [uniqStep, ha]
      rw [hs]
      refine uniq_foldl_nodup t _ (fun y => ?_) ?_
      · simp only [HashSet.contains_insert, Bool.or_eq_true, beq_iff_eq, List.mem_cons]
        rw [h y]; constructor <;> rintro (h1 | h1) <;> first | exact Or.inl h1.symm | exact Or.inr h1 | exact Or.inl h1 | exact Or.inr h1
      · exact List.nodup_cons.2 ⟨fun hm => ha ((h a).2 hm), hn⟩

theorem nodup_uniq (ks : List Key) : (uniq ks).Nodup := by
  unfold uniq
  have := uniq_foldl_nodup ks (∅, []) (fun y => by simp) List.nodup_nil
  unfold List.Nodup at this ⊢
  rw [List.pairwise_reverse]
  exact this.imp (fun h => Ne.symm h)

theorem round2_nodup (redo : List Nat) (ks : List Key) (u : List (Key × Entry)) : (round2 redo ks u).Nodup :=
  nodup_uniq _

theorem round2_notin (redo : List Nat) (ks : List Key) (u : List (Key × Entry)) {x : Key} (h : x ∈ round2 redo ks u) :
    x ∉ ks := by
  unfold round2 at h
  rw [mem_uniq] at h
  have := (List.mem_filter.1 h).2
  intro hx
  simp at this
  exact this (by simpa using hx)

theorem rel_keys_nodup (s : St) (redo : List Nat) (b : List Line) :
    ((fetch s redo b).rel.map (·.1)).Nodup := by
  rw [fetch_rel']
  simp only [List.map_map, Function.comp_def]
  rw [List.map_id']
  unfold ksR
  rw [List.nodup_append]
  refine ⟨nodup_uniq _, round2_nodup _ _ _, fun x hx y hy hxy => ?_⟩
  subst hxy
  exact round2_notin _ _ _ hy hx

theorem unr_keys (s : St) (redo : List Nat) (b : List Line) :
    (fetch s redo b).unr.map (·.1) = probeKeys b := by
  rw [fetch_unr']; unfold uEs; simp [List.map_map, Function.comp_def]

theorem arr_push_get {α : Type} [Inhabited α] (a : Array α) (x : α) (i : Nat) :
    (a.push x)[i]! = if i < a.size then a[i]! else if i = a.size then x else default := by
  simp only [Array.getElem!_eq_getD, Array.getD_eq_getD_getElem?, Array.getElem?_push]
  by_cases h1 : i = a.size
  · subst h1; simp
  · by_cases h2 : i < a.size
    · simp [h1, h2]
    · simp [h1, h2, Array.getElem?_eq_none (show a.size ≤ i by omega)]

theorem arr_modify_get {α : Type} [Inhabited α] (a : Array α) (j : Nat) (f : α → α) (i : Nat) :
    (a.modify j f)[i]! = if i = j ∧ j < a.size then f a[i]! else a[i]! := by
  simp only [Array.getElem!_eq_getD, Array.getD_eq_getD_getElem?, Array.getElem?_modify]
  by_cases h : i = j
  · subst h
    by_cases h2 : i < a.size
    · simp [h2, Array.getElem?_eq_getElem h2]
    · simp [h2, Array.getElem?_eq_none (show a.size ≤ i by omega)]
  · simp [h, Ne.symm h]


theorem forIn_inv' {α β : Type} (l : List α) (init : β) (f : α → β → Id (ForInStep β)) (P : List α → β → Prop)
    (h0 : P [] init)
    (hs : ∀ pre a post st, l = pre ++ a :: post → P pre st → ∃ st', f a st = .yield st' ∧ P (pre ++ [a]) st')
    (r : β) (hr : forIn (m := Id) l init f = r) : P l r := by
  obtain ⟨r', e, h⟩ := forIn_inv l init f P h0 hs
  rw [← hr, e]; exact h

theorem forIn_push3 {α A B C : Type} (l : List α) (a : Array A) (b : Array B) (c : Array C) (f : α → A) (g : α → B)
    (h : α → C) :
    forIn (m := Id) l (a, b, c) (fun p s => ForInStep.yield (s.1.push (f p), s.2.1.push (g p), s.2.2.push (h p))) =
      (a ++ (l.map f).toArray, b ++ (l.map g).toArray, c ++ (l.map h).toArray) := by
  obtain ⟨r, e, hr⟩ := forIn_inv l (a, b, c) (fun p s => ForInStep.yield (s.1.push (f p), s.2.1.push (g p), s.2.2.push (h p)))
    (fun pre st => st = (a ++ (pre.map f).toArray, b ++ (pre.map g).toArray, c ++ (pre.map h).toArray))
    (by simp)
    (fun pre p post st _ hp => ⟨_, rfl, by subst hp; refine Prod.ext ?_ (Prod.ext ?_ ?_) <;> apply Array.ext' <;> simp⟩)
  rw [e, hr]

def Inv1 (C : Key → Nat) (pre : List (Key × Entry))
    (st : HashMap Key Nat × Array Slot × Array BlindLedger.Gate.Engine3.RowX × Array Nat × Array Line) : Prop :=
  (∀ j (h : j < pre.length), st.1.get? pre[j].1 = some j) ∧
  (∀ k, k ∉ pre.map (·.1) → st.1.get? k = none) ∧
  st.2.1.size = pre.length ∧
  (∀ j (h : j < pre.length), st.2.1[j]! =
    { kind := pre[j].1.headD 9, rs := ((pre.take j).flatMap fun ke => heads ke.2).length,
      rn := (heads pre[j].2).length, rc := capCount C pre[j].1 pre[j].2 }) ∧
  st.2.2.1.toList = (pre.flatMap fun ke => heads ke.2).map (BlindLedger.Gate.Engine3.RowX.of ·.row) ∧
  st.2.2.2.1.toList = (pre.flatMap fun ke => heads ke.2).map (·.seq) ∧
  st.2.2.2.2.toList = (pre.flatMap fun ke => heads ke.2).map (·.row)

theorem Inv1_step (C : Key → Nat) (pre post : List (Key × Entry)) (x : Key × Entry)
    (hnd : ((pre ++ x :: post).map (·.1)).Nodup)
    (m : HashMap Key Nat) (sl : Array Slot) (rp : Array BlindLedger.Gate.Engine3.RowX) (rs : Array Nat) (rr : Array Line)
    (h : Inv1 C pre (m, sl, rp, rs, rr)) :
    Inv1 C (pre ++ [x]) (m.insert x.1 sl.size,
      sl.push { kind := x.1.headD 9, rs := rp.size, rn := (heads x.2).length, rc := capCount C x.1 x.2 },
      rp ++ ((heads x.2).map (BlindLedger.Gate.Engine3.RowX.of ·.row)).toArray,
      rs ++ ((heads x.2).map (·.seq)).toArray, rr ++ ((heads x.2).map (·.row)).toArray) := by
  obtain ⟨h1, h2, h3, h4, h5, h6, h7⟩ := h
  simp only at h1 h2 h3 h4 h5 h6 h7
  have hx : x.1 ∉ pre.map (·.1) := by
    simp only [List.map_append, List.map_cons, List.nodup_append, List.nodup_cons] at hnd
    intro hm; exact hnd.2.2 _ hm _ (by simp) rfl
  have hsz : rp.size = (pre.flatMap fun ke => heads ke.2).length := by
    have := congrArg List.length h5; simpa using this
  refine ⟨?_, ?_, ?_, ?_, ?_, ?_, ?_⟩
  · intro j hj
    simp only [Std.HashMap.get?_insert]
    by_cases hlt : j < pre.length
    · have e : (pre ++ [x])[j] = pre[j] := List.getElem_append_left hlt
      rw [e]
      have : ¬ (x.1 == pre[j].1) = true := by
        intro hb; exact hx (by rw [beq_iff_eq.1 hb]; exact List.mem_map_of_mem (List.getElem_mem hlt))
      rw [if_neg this]; exact h1 j hlt
    · have hj' : j = pre.length := by simp at hj; omega
      subst hj'
      have e : (pre ++ [x])[pre.length] = x := by simp
      rw [e]; simp [h3]
  · intro k hk
    simp only [List.map_append, List.map_cons, List.map_nil, List.mem_append, List.mem_singleton, not_or] at hk
    simp only [Std.HashMap.get?_insert]
    rw [if_neg (by intro hb; exact hk.2 (beq_iff_eq.1 hb).symm)]
    exact h2 k hk.1
  · simp [h3]
  · intro j hj
    rw [arr_push_get]
    by_cases hlt : j < pre.length
    · rw [if_pos (by omega)]
      have e : (pre ++ [x])[j] = pre[j] := List.getElem_append_left hlt
      simp only [e, List.take_append_of_le_length (show j ≤ pre.length by omega)]
      exact h4 j hlt
    · have hj' : j = pre.length := by simp at hj; omega
      subst hj'
      rw [if_neg (by omega), if_pos h3.symm]
      simp [hsz]
  · simp [h5, List.flatMap_append, List.map_append]
  · simp [h6, List.flatMap_append, List.map_append]
  · simp [h7, List.flatMap_append, List.map_append]


def Inv2P (g : Nat → List SpanF) (m : HashMap Key Nat) (n : Nat) (ps : List Posting)
    (st : Facts SpanF × Array BlindLedger.Gate.Engine3.RowX × Array Nat × Array Line × Array Rg × Array Nat) : Prop :=
  FOk g st.1 ∧ st.2.1.toList = ps.map (BlindLedger.Gate.Engine3.RowX.of ·.row) ∧ st.2.2.1.toList = ps.map (·.seq) ∧
  st.2.2.2.1.toList = ps.map (·.row) ∧ st.2.2.2.2.1.size = ps.length ∧ st.2.2.2.2.2.size = ps.length ∧
  (∀ q (hq : q < ps.length), Slice st.1.2 st.2.2.2.2.1[q]! (facts (g ps[q].row.member)) ∧
    st.2.2.2.2.1[q]!.over = feedOver (g ps[q].row.member) ∧
    st.2.2.2.2.2[q]! = ((m.get? (idKey ps[q].row)).filter (· < n)).getD n)

theorem Inv2P_step (g : Nat → List SpanF) (m : HashMap Key Nat) (n : Nat) (ps : List Posting) (p : Posting)
    (sp : Facts SpanF) (up : Array BlindLedger.Gate.Engine3.RowX) (us : Array Nat) (usrc : Array Line)
    (usp : Array Rg) (uid : Array Nat) (h : Inv2P g m n ps (sp, up, us, usrc, usp, uid)) :
    Inv2P g m n (ps ++ [p]) ((readFacts g sp p.row.member).2, up.push (BlindLedger.Gate.Engine3.RowX.of p.row),
      us.push p.seq, usrc.push p.row, usp.push (readFacts g sp p.row.member).1,
      uid.push (((m.get? (idKey p.row)).filter (· < n)).getD n)) := by
  obtain ⟨h1, h2, h3, h4, h5, h6, h7⟩ := h
  simp only at h1 h2 h3 h4 h5 h6 h7
  obtain ⟨k1, k2, k3, k4⟩ := readFacts_ok g sp p.row.member h1
  refine ⟨k1, by simp [h2], by simp [h3], by simp [h4], by simp [h5], by simp [h6], ?_⟩
  intro q hq
  simp only [List.length_append, List.length_singleton] at hq
  rw [arr_push_get, arr_push_get]
  by_cases hlt : q < ps.length
  · have e : (ps ++ [p])[q] = ps[q] := List.getElem_append_left hlt
    simp only [e, if_pos (show q < usp.size by omega), if_pos (show q < uid.size by omega)]
    obtain ⟨c1, c2, c3⟩ := h7 q hlt
    exact ⟨Slice.mono c1 k2, c2, c3⟩
  · have hq' : q = ps.length := by omega
    subst hq'
    have e : (ps ++ [p])[ps.length] = p := by simp
    simp only [e, if_neg (show ¬ ps.length < usp.size by omega), if_pos h5.symm, if_neg (show ¬ ps.length < uid.size by omega), if_pos h6.symm]
    exact ⟨k3, k4, trivial⟩

def Inv2S (C : Key → Nat) (rel : List (Key × Entry)) (sl1 : Array Slot) (pre : List (Key × Entry)) (sl : Array Slot) :
    Prop :=
  sl.size = sl1.size ∧
  (∀ j, j < rel.length → sl[j]!.kind = sl1[j]!.kind ∧ sl[j]!.rs = sl1[j]!.rs ∧ sl[j]!.rn = sl1[j]!.rn ∧
    sl[j]!.rc = sl1[j]!.rc) ∧
  (∀ i (hi : i < pre.length), ∃ j, ∃ hj : j < rel.length, rel[j].1 = pre[i].1 ∧
    sl[j]!.us = ((pre.take i).flatMap fun ke => heads ke.2).length ∧ sl[j]!.un = (heads pre[i].2).length ∧
    sl[j]!.uc = capCount C pre[i].1 pre[i].2) ∧
  (∀ j (hj : j < rel.length), (∀ i (hi : i < pre.length), pre[i].1 ≠ rel[j].1) → sl[j]!.un = 0 ∧ sl[j]!.uc = 0)

theorem Inv2S_step (C : Key → Nat) (rel : List (Key × Entry)) (sl1 : Array Slot) (hs1 : sl1.size = rel.length)
    (pre : List (Key × Entry)) (x : Key × Entry)
    (sl : Array Slot) (j0 : Nat) (hj0 : j0 < rel.length) (e0 : rel[j0].1 = x.1) (hx : x.1 ∉ pre.map (·.1))
    (N : Nat) (hN : N = (pre.flatMap fun ke => heads ke.2).length) (h : Inv2S C rel sl1 pre sl) :
    Inv2S C rel sl1 (pre ++ [x]) (sl.modify j0 fun s =>
      { kind := s.kind, rs := s.rs, rn := s.rn, rc := s.rc, us := N, un := (heads x.2).length,
        uc := capCount C x.1 x.2 }) := by
  obtain ⟨h1, h2, h3, h4⟩ := h
  have hj0s : j0 < sl.size := by omega
  refine ⟨by simp [h1], ?_, ?_, ?_⟩
  · intro j hj
    rw [arr_modify_get]
    obtain ⟨c1, c2, c3, c4⟩ := h2 j hj
    split <;> simp [c1, c2, c3, c4]
  · intro i hi
    simp only [List.length_append, List.length_singleton] at hi
    by_cases hlt : i < pre.length
    · obtain ⟨j, hj, c1, c2, c3, c4⟩ := h3 i hlt
      have e : (pre ++ [x])[i] = pre[i] := List.getElem_append_left hlt
      have hne : j ≠ j0 := by
        rintro rfl
        exact hx (by rw [← e0, c1]; exact List.mem_map_of_mem (List.getElem_mem hlt))
      refine ⟨j, hj, by rw [e]; exact c1, ?_⟩
      rw [arr_modify_get, if_neg (fun hh => hne hh.1), e, List.take_append_of_le_length (by omega)]
      exact ⟨c2, c3, c4⟩
    · have hi' : i = pre.length := by omega
      subst hi'
      refine ⟨j0, hj0, by simpa using e0, ?_⟩
      rw [arr_modify_get, if_pos ⟨rfl, hj0s⟩]
      simp [hN]
  · intro j hj hall
    have hne : j ≠ j0 := by
      rintro rfl
      exact hall pre.length (by simp) (by simpa using e0.symm)
    rw [arr_modify_get, if_neg (fun hh => hne hh.1)]
    refine h4 j hj fun i hi => ?_
    have := hall i (by simp; omega)
    rwa [List.getElem_append_left hi] at this

theorem rel_map_fst (s : St) (redo : List Nat) (b : List Line) :
    (fetch s redo b).rel.map (·.1) = probeKeys b ++ round2 redo (probeKeys b) (uEs s b) := by
  rw [fetch_rel']; unfold ksR
  simp [List.map_map, Function.comp_def]

theorem unr_sub_rel (s : St) (redo : List Nat) (b : List Line) {ke : Key × Entry} (h : ke ∈ (fetch s redo b).unr) :
    ∃ j, ∃ hj : j < (fetch s redo b).rel.length, (fetch s redo b).rel[j].1 = ke.1 := by
  have h1 : ke.1 ∈ (fetch s redo b).unr.map (·.1) := List.mem_map_of_mem h
  rw [unr_keys] at h1
  have h2 : ke.1 ∈ (fetch s redo b).rel.map (·.1) := by
    rw [rel_map_fst]; exact List.mem_append_left _ h1
  obtain ⟨j, hj, e⟩ := List.mem_iff_getElem.1 h2
  exact ⟨j, by simpa using hj, by simpa using e⟩

theorem key_in_rel (s : St) (redo : List Nat) (b : List Line) {l : Line} (hl : l ∈ b) {k : Key} (hk : k ∈ keys l) :
    ∃ j, ∃ hj : j < (fetch s redo b).rel.length, (fetch s redo b).rel[j].1 = k := by
  have h2 : k ∈ (fetch s redo b).rel.map (·.1) := by
    rw [rel_map_fst]; exact List.mem_append_left _ (mem_probeKeys.2 ⟨l, hl, hk⟩)
  obtain ⟨j, hj, e⟩ := List.mem_iff_getElem.1 h2
  exact ⟨j, by simpa using hj, by simpa using e⟩

theorem unr_nodup (s : St) (redo : List Nat) (b : List Line) : ((fetch s redo b).unr.map (·.1)).Nodup := by
  rw [unr_keys]; exact nodup_uniq _

theorem Inv2_init (C : Key → Nat) (rel : List (Key × Entry)) (sl1 : Array Slot)
    (h4 : ∀ j, j < rel.length → sl1[j]!.un = 0 ∧ sl1[j]!.uc = 0) : Inv2S C rel sl1 [] sl1 :=
  ⟨rfl, fun j _ => ⟨rfl, rfl, rfl, rfl⟩, by simp, fun j hj _ => h4 j hj⟩

def PayInv (fc : FCtx) (po : HashMap Nat Nat) (pr : Array Bool) (pb : Array (Option UInt32)) : Prop :=
  pb.size = pr.size ∧
  (∀ p j, po.get? p = some j → j < pr.size ∧ pr[j]! = fc.redo.contains p ∧
      pb[j]! = (fc.byp.lookup p).map fun m => (m % 2 ^ 32).toUInt32) ∧
  (∀ p p' j, po.get? p = some j → po.get? p' = some j → p = p')

theorem PayInv_new (fc : FCtx) (po : HashMap Nat Nat) (pr : Array Bool) (pb : Array (Option UInt32)) (p : Nat)
    (h : PayInv fc po pr pb) :
    PayInv fc (po.insert p pr.size) (pr.push (fc.redo.contains p))
      (pb.push ((fc.byp.lookup p).map fun m => (m % 2 ^ 32).toUInt32)) := by
  obtain ⟨h1, h2, h3⟩ := h
  refine ⟨by simp [h1], ?_, ?_⟩
  · intro q j hj
    rw [Std.HashMap.get?_insert] at hj
    split at hj
    · rename_i e
      cases hj
      obtain rfl := beq_iff_eq.1 e
      refine ⟨by simp, ?_, ?_⟩
      · rw [arr_push_get, if_neg (by omega), if_pos rfl]
      · rw [arr_push_get, if_neg (by omega), if_pos (by omega)]
    · obtain ⟨a, b, c⟩ := h2 q j hj
      refine ⟨by simp; omega, ?_, ?_⟩
      · rw [arr_push_get, if_pos a]; exact b
      · rw [arr_push_get, if_pos (by omega)]; exact c
  · intro q q' j hq hq'
    rw [Std.HashMap.get?_insert] at hq hq'
    split at hq <;> split at hq'
    · rename_i e1 e2
      exact (beq_iff_eq.1 e1).symm.trans (beq_iff_eq.1 e2)
    · rename_i e1 e2
      cases hq
      have := (h2 q' _ hq').1; omega
    · rename_i e1 e2
      cases hq'
      have := (h2 q _ hq).1; omega
    · exact h3 q q' j hq hq'

def LineOk (fc : FCtx) (f : List Nat) (m : HashMap Key Nat) (sp : Facts SpanF) (dm pd : Facts Death)
    (ex : Facts Exclusion) (po : HashMap Nat Nat) (l : Line) (li : LineIn) : Prop :=
  li.row = BlindLedger.Gate.Engine3.RowX.of l ∧ li.ke = m.getD (exactKey l) 0 ∧ li.kn = m.getD (nearKey l) 0 ∧
  li.ki = m.getD (idKey l) 0 ∧ po.get? l.pay = some li.pay ∧ li.fseen = (HashSet.ofList f).contains l.id ∧
  (Slice dm.2 li.dmf (facts (fc.feeds.dmf l.member)) ∧ li.dmf.over = feedOver (fc.feeds.dmf l.member)) ∧
  (Slice pd.2 li.pdP (facts (fc.feeds.pdeath l.payee)) ∧ li.pdP.over = feedOver (fc.feeds.pdeath l.payee)) ∧
  (Slice pd.2 li.pdR (facts (fc.feeds.pdeath l.rendering)) ∧ li.pdR.over = feedOver (fc.feeds.pdeath l.rendering)) ∧
  (Slice ex.2 li.exP (facts (fc.feeds.excl l.payee)) ∧ li.exP.over = feedOver (fc.feeds.excl l.payee)) ∧
  (Slice ex.2 li.exR (facts (fc.feeds.excl l.rendering)) ∧ li.exR.over = feedOver (fc.feeds.excl l.rendering)) ∧
  (Slice sp.2 li.span (facts ((fc.feeds.span l.member).map (spanF l.member))) ∧
    li.span.over = feedOver ((fc.feeds.span l.member).map (spanF l.member)))

theorem LineOk_mono {fc : FCtx} {f : List Nat} {m : HashMap Key Nat} {sp sp' : Facts SpanF} {dm dm' pd pd' : Facts Death}
    {ex ex' : Facts Exclusion} {po po' : HashMap Nat Nat} {l : Line} {li : LineIn}
    (h : LineOk fc f m sp dm pd ex po l li) (hsp : sp.2.toList <+: sp'.2.toList) (hdm : dm.2.toList <+: dm'.2.toList)
    (hpd : pd.2.toList <+: pd'.2.toList) (hex : ex.2.toList <+: ex'.2.toList)
    (hpo : ∀ p j, po.get? p = some j → po'.get? p = some j) : LineOk fc f m sp' dm' pd' ex' po' l li := by
  obtain ⟨a1, a2, a3, a4, a5, a6, ⟨b1, b2⟩, ⟨c1, c2⟩, ⟨d1, d2⟩, ⟨e1, e2⟩, ⟨g1, g2⟩, ⟨h1, h2⟩⟩ := h
  exact ⟨a1, a2, a3, a4, hpo _ _ a5, a6, ⟨b1.mono hdm, b2⟩, ⟨c1.mono hpd, c2⟩, ⟨d1.mono hpd, d2⟩,
    ⟨e1.mono hex, e2⟩, ⟨g1.mono hex, g2⟩, ⟨h1.mono hsp, h2⟩⟩

def Inv3 (fc : FCtx) (f : List Nat) (m : HashMap Key Nat) (sp0 : Array SpanF) (pre : List Line)
    (st : Facts SpanF × Facts Death × Facts Death × Facts Exclusion × HashMap Nat Nat × Array Bool ×
      Array (Option UInt32) × Array LineIn) : Prop :=
  FOk (fun i => (fc.feeds.span i).map (spanF i)) st.1 ∧ FOk fc.feeds.dmf st.2.1 ∧ FOk fc.feeds.pdeath st.2.2.1 ∧
  FOk fc.feeds.excl st.2.2.2.1 ∧ sp0.toList <+: st.1.2.toList ∧
  PayInv fc st.2.2.2.2.1 st.2.2.2.2.2.1 st.2.2.2.2.2.2.1 ∧
  st.2.2.2.2.2.2.2.size = pre.length ∧
  ∀ i (h : i < pre.length), LineOk fc f m st.1 st.2.1 st.2.2.1 st.2.2.2.1 st.2.2.2.2.1 pre[i] st.2.2.2.2.2.2.2[i]!

theorem Inv3_step (fc : FCtx) (f : List Nat) (m : HashMap Key Nat) (sp0 : Array SpanF) (pre : List Line) (l : Line)
    (sp : Facts SpanF) (dm pd : Facts Death) (ex : Facts Exclusion) (po : HashMap Nat Nat) (pr : Array Bool)
    (pb : Array (Option UInt32)) (ls : Array LineIn) (po' : HashMap Nat Nat) (pr' : Array Bool)
    (pb' : Array (Option UInt32)) (pj : Nat)
    (h : Inv3 fc f m sp0 pre (sp, dm, pd, ex, po, pr, pb, ls))
    (hpay : PayInv fc po' pr' pb') (hl : po'.get? l.pay = some pj)
    (hmono : ∀ p j, po.get? p = some j → po'.get? p = some j) :
    Inv3 fc f m sp0 (pre ++ [l])
      ((readFacts (fun i => (fc.feeds.span i).map (spanF i)) sp l.member).2,
        (readFacts fc.feeds.dmf dm l.member).2,
        (readFacts fc.feeds.pdeath (readFacts fc.feeds.pdeath pd l.payee).2 l.rendering).2,
        (readFacts fc.feeds.excl (readFacts fc.feeds.excl ex l.payee).2 l.rendering).2,
        po', pr', pb',
        ls.push
          { row := BlindLedger.Gate.Engine3.RowX.of l, ke := m.getD (exactKey l) 0, kn := m.getD (nearKey l) 0,
            ki := m.getD (idKey l) 0, pay := pj,
            dmf := (readFacts fc.feeds.dmf dm l.member).1,
            span := (readFacts (fun i => (fc.feeds.span i).map (spanF i)) sp l.member).1,
            pdP := (readFacts fc.feeds.pdeath pd l.payee).1,
            pdR := (readFacts fc.feeds.pdeath (readFacts fc.feeds.pdeath pd l.payee).2 l.rendering).1,
            exP := (readFacts fc.feeds.excl ex l.payee).1,
            exR := (readFacts fc.feeds.excl (readFacts fc.feeds.excl ex l.payee).2 l.rendering).1,
            fseen := (HashSet.ofList f).contains l.id }) := by
  obtain ⟨hF1, hF2, hF3, hF4, hpre, hP, hsz, hL⟩ := h
  simp only at hF1 hF2 hF3 hF4 hpre hP hsz hL
  obtain ⟨s1, s2, s3, s4⟩ := readFacts_ok _ sp l.member hF1
  obtain ⟨d1, d2, d3, d4⟩ := readFacts_ok _ dm l.member hF2
  obtain ⟨p1, p2, p3, p4⟩ := readFacts_ok _ pd l.payee hF3
  obtain ⟨q1, q2, q3, q4⟩ := readFacts_ok _ (readFacts fc.feeds.pdeath pd l.payee).2 l.rendering p1
  obtain ⟨e1, e2, e3, e4⟩ := readFacts_ok _ ex l.payee hF4
  obtain ⟨g1, g2, g3, g4⟩ := readFacts_ok _ (readFacts fc.feeds.excl ex l.payee).2 l.rendering e1
  refine ⟨s1, d1, q1, g1, hpre.trans s2, hpay, by simp [hsz], ?_⟩
  intro i hi
  simp only [List.length_append, List.length_singleton] at hi
  by_cases hi' : i < pre.length
  · simp only [List.getElem_append_left hi']
    rw [arr_push_get, if_pos (hsz ▸ hi')]
    exact LineOk_mono (hL i hi') s2 d2 (p2.trans q2) (e2.trans g2) hmono
  · have : i = pre.length := by omega
    subst this
    simp only [List.getElem_append_right (Nat.le_refl _), Nat.sub_self, List.getElem_singleton]
    rw [arr_push_get, if_neg (by omega), if_pos (by omega)]
    exact ⟨rfl, rfl, rfl, rfl, hl, rfl, ⟨d3, d4⟩, ⟨p3.mono q2, p4⟩, ⟨q3, q4⟩, ⟨e3.mono g2, e4⟩, ⟨g3, g4⟩, ⟨s3, s4⟩⟩

theorem new_notin {α : Type} (f : α → Key) (pre post : List α) (x : α) (hnd : ((pre ++ x :: post).map f).Nodup) :
    f x ∉ pre.map f := by
  simp only [List.map_append, List.map_cons, List.nodup_append, List.nodup_cons] at hnd
  intro hm; exact hnd.2.2 _ hm _ (by simp) rfl

theorem seg_flat {α β : Type} (L : List α) (g : α → List β) (j : Nat) (hj : j < L.length) :
    ((L.flatMap g).drop ((L.take j).flatMap g).length).take (g L[j]).length = g L[j] := by
  have e0 : L = L.take j ++ (L[j] :: L.drop (j + 1)) := by
    rw [← List.drop_eq_getElem_cons hj, List.take_append_drop]
  have e : L.flatMap g = (L.take j).flatMap g ++ (g L[j] ++ (L.drop (j + 1)).flatMap g) := by
    have := congrArg (List.flatMap g) e0
    rw [List.flatMap_append, List.flatMap_cons] at this
    exact this
  rw [e, List.drop_left' rfl, List.take_left' rfl]

theorem seg_map {α β : Type} (xs : List α) (F : α → β) (n m : Nat) :
    ((xs.map F).drop n).take m = (xs.drop n |>.take m).map F := by
  rw [← List.map_drop, ← List.map_take]

theorem arr_getD_map {α β : Type} (a : Array β) (xs : List α) (F : α → β) (d : β)
    (h : a.toList = xs.map F) (q : Nat) (hq : q < xs.length) : a.getD q d = F xs[q] := by
  have : q < a.size := by have := congrArg List.length h; simp at this; omega
  rw [Array.getD_eq_getD_getElem?, Array.getElem?_eq_getElem this]
  have h2 := congrArg (fun l => l[q]?) h
  simp only [Array.getElem?_toList, List.getElem?_map, List.getElem?_eq_getElem hq] at h2
  simp [Array.getElem?_eq_getElem this] at h2
  simpa using h2

theorem seg_bound {α β : Type} (L : List α) (g : α → List β) (j : Nat) (hj : j < L.length) :
    ((L.take j).flatMap g).length + (g L[j]).length ≤ (L.flatMap g).length := by
  have h := congrArg List.length (seg_flat L g j hj)
  simp only [List.length_take, List.length_drop] at h
  have e : (L.flatMap g).length = ((L.take j).flatMap g).length + ((L.drop j).flatMap g).length := by
    rw [← List.length_append, ← List.flatMap_append, List.take_append_drop]
  omega

theorem slot_of_key (rel : List (Key × Entry)) (m : HashMap Key Nat)
    (c1 : ∀ j (h : j < rel.length), m.get? rel[j].1 = some j) (k : Key)
    (hk : ∃ j, ∃ hj : j < rel.length, rel[j].1 = k) : rel[m.getD k 0]?.map (·.1) = some k := by
  obtain ⟨j, hj, e⟩ := hk
  have := c1 j hj
  rw [e, Std.HashMap.get?_eq_getElem?] at this
  rw [Std.HashMap.getD_eq_getD_getElem?, this]
  simp [hj, e]

theorem slot_inv (rel : List (Key × Entry)) (m : HashMap Key Nat) (hnd : (rel.map (·.1)).Nodup)
    (c1 : ∀ j (h : j < rel.length), m.get? rel[j].1 = some j)
    (c2 : ∀ k, k ∉ rel.map (·.1) → m.get? k = none) (k : Key) (j : Nat) (h : m.get? k = some j) :
    ∃ hj : j < rel.length, rel[j].1 = k := by
  by_cases hk : k ∈ rel.map (·.1)
  · obtain ⟨j', hj', e⟩ := List.mem_iff_getElem.1 hk
    simp only [List.getElem_map, List.length_map] at e hj'
    have := c1 j' hj'
    rw [e, h] at this
    cases this
    exact ⟨hj', e⟩
  · rw [c2 k hk] at h; cases h

theorem fseen_eq (f : List Nat) (l : Line) : (HashSet.ofList f).contains l.id = (idSeen f).contains (idKey l) := by
  rw [Bool.eq_iff_iff]
  simp [idSeen, idKey, Std.HashSet.contains_ofList]

set_option hygiene false in
local macro "RL" : term => `((fetch s fc.redo b).rel)
set_option hygiene false in
local macro "UL" : term => `((fetch s fc.redo b).unr)

/-- (1) The layout invariant: no hypothesis; the keys of `fetch` are distinct, so slots and keys correspond. -/
theorem layout_rep (s : St) (fc : FCtx) (f : List Nat) (b : List Line) : Rep (layout s fc f b) s fc f b := by
  have hnd := rel_keys_nodup s fc.redo b
  unfold layout
  simp only [Id.run, bind, pure]
  generalize hr1 : forIn (m := Id) (fetch s fc.redo b).rel _ _ = r1
  generalize hr2 : forIn (m := Id) (fetch s fc.redo b).unr _ _ = r2
  generalize hr3 : forIn (m := Id) b _ _ = r3
  have h1 := forIn_inv' _ _ _ (fun pre st => Inv1 (fetch s fc.redo b).relCore pre st) ?_ ?_ r1 hr1
  rotate_left
  · exact ⟨fun j hj => by simp at hj, fun k _ => by simp, by simp, fun j hj => by simp at hj, by simp, by simp, by simp⟩
  · intro pre x post st hl hP
    obtain ⟨m, sl, rp, rs, rr⟩ := st
    refine ⟨_, ?_, Inv1_step _ pre post x (hl ▸ hnd) m sl rp rs rr hP⟩
    simp only [forIn_push3]
  obtain ⟨c1, c2, c3, c4, c5, c6, c7⟩ := h1
  have hnd2 := unr_nodup s fc.redo b
  have h2 := forIn_inv' _ _ _ (fun pre st => st.1 = r1.1 ∧
      Inv2S (fetch s fc.redo b).unrCore (fetch s fc.redo b).rel r1.2.1 pre st.2.1 ∧
      Inv2P (fun i => (fc.feeds.span i).map (spanF i)) r1.1 r1.2.1.size (pre.flatMap fun ke => heads ke.2) st.2.2) ?_ ?_ r2 hr2
  rotate_left
  · refine ⟨rfl, Inv2_init _ _ _ (fun j hj => ?_), ?_⟩
    · have := c4 j hj
      rw [this]; exact ⟨rfl, rfl⟩
    · refine ⟨fun j r hj => by simp at hj, by simp, by simp, by simp, by simp, by simp, fun q hq => by simp at hq⟩
  · intro pre x post st hl hP
    obtain ⟨m, sl, sp, up, us, usrc, usp, uid⟩ := st
    obtain ⟨hm, hS, hP2⟩ := hP
    simp only at hm hS hP2
    subst hm
    have hx := new_notin (·.1) pre post x (hl ▸ hnd2)
    obtain ⟨j0, hj0, e0⟩ := unr_sub_rel s fc.redo b (show x ∈ (fetch s fc.redo b).unr by rw [hl]; simp)
    have hget : r1.1.get? x.1 = some j0 := by rw [← e0]; exact c1 j0 hj0
    have hN : up.size = (pre.flatMap fun ke => heads ke.2).length := by
      have := congrArg List.length hP2.2.1; simpa using this
    dsimp only
    rw [hget]
    generalize hI : forIn (m := Id) (heads x.2) (sp, up, us, usrc, usp, uid) _ = ri
    have hi := forIn_inv' _ _ _ (fun qs st => Inv2P (fun i => (fc.feeds.span i).map (spanF i)) r1.1 r1.2.1.size
      ((pre.flatMap fun ke => heads ke.2) ++ qs) st) ?_ ?_ ri hI
    rotate_left
    · simpa using hP2
    · intro qs p qpost st' hl' hP'
      obtain ⟨sp', up', us', usrc', usp', uid'⟩ := st'
      refine ⟨_, rfl, ?_⟩
      rw [← List.append_assoc]
      exact Inv2P_step _ _ _ _ p _ _ _ _ _ _ hP'
    refine ⟨_, rfl, rfl, ?_, ?_⟩
    · exact Inv2S_step _ _ _ (by omega) pre x sl j0 hj0 e0 hx up.size hN hS
    · simp only [List.flatMap_append, List.flatMap_cons, List.flatMap_nil, List.append_nil]
      exact hi
  have h3 := forIn_inv' _ _ _ (fun pre st => Inv3 fc f r2.1 r2.2.2.1.2 pre st) ?_ ?_ r3 hr3
  rotate_left
  · obtain ⟨-, -, hP2⟩ := h2
    exact ⟨hP2.1, fun j r h => by simp at h, fun j r h => by simp at h, fun j r h => by simp at h,
      List.prefix_refl _, ⟨rfl, fun p j h => by simp at h, fun p p' j h => by simp at h⟩, by simp,
      fun i hi => by simp at hi⟩
  · intro pre x post st hl hP
    obtain ⟨sp, dm, pd, ex, po, pr, pb, ls⟩ := st
    have hPay : PayInv fc po pr pb := hP.2.2.2.2.2.1
    dsimp only
    cases hg : po.get? x.pay with
    | some j =>
      refine ⟨_, ?_, Inv3_step fc f r2.1 _ pre x sp dm pd ex po pr pb ls po pr pb j hP hPay hg (fun p j h => h)⟩
      rfl
    | none =>
      refine ⟨_, ?_, Inv3_step fc f r2.1 _ pre x sp dm pd ex po pr pb ls (po.insert x.pay pr.size)
        (pr.push (fc.redo.contains x.pay)) (pb.push ((fc.byp.lookup x.pay).map fun m => (m % 2 ^ 32).toUInt32))
        pr.size hP (PayInv_new fc po pr pb x.pay hPay) (by simp) ?_⟩
      · rfl
      · intro p j hpj
        rw [Std.HashMap.get?_insert]
        split
        · rename_i e; obtain rfl := beq_iff_eq.1 e; rw [hg] at hpj; cases hpj
        · exact hpj
  obtain ⟨hm, hS, hP2⟩ := h2
  obtain ⟨F1, F2, F3, F4, hpre, hPay, hsz, hL⟩ := h3
  obtain ⟨g1, g2, g3, g4, g5, g6, g7⟩ := hP2
  have hkeys : ∀ i (hi : i < b.length), ∀ k ∈ keys b[i], ∃ j, ∃ hj : j < (RL).length, (RL)[j].1 = k :=
    fun i hi k hk => key_in_rel s fc.redo b (List.getElem_mem hi) hk
  have hqs : ∀ q, q < r2.snd.snd.snd.fst.size → q < ((UL).flatMap fun ke => heads ke.2).length := fun q hq => by
    have := congrArg List.length g2; simp only [Array.length_toList, List.length_map] at this; omega
  have hrow : ∀ q (hq : q < ((UL).flatMap fun ke => heads ke.2).length), r2.snd.snd.snd.snd.snd.fst.getD q nilLine = ((UL).flatMap fun ke => heads ke.2)[q].row := fun q hq =>
    arr_getD_map _ ((UL).flatMap fun ke => heads ke.2) (·.row) nilLine g4 q hq
  refine ⟨rfl, ?_, ⟨rfl, rfl, rfl⟩, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ⟨rfl, rfl, rfl, rfl, rfl, rfl, rfl, rfl⟩, rfl, ?_⟩
  · apply List.ext_getElem
    · simp [hsz]
    · intro i h1 h2
      have hb : i < b.length := by simpa using h2
      have := (hL i hb).1
      rw [getElem!_pos _ i (by omega)] at this
      simp only [List.getElem_map, Array.getElem_toList]
      exact this
  · exact hS.1.trans c3
  · intro j hj
    dsimp only
    have e1 := c4 j hj
    obtain ⟨k1, k2, k3, k4⟩ := hS.2.1 j hj
    have k1' : r2.snd.fst[j]!.kind = (RL)[j].1.headD 9 := by rw [k1, e1]
    have k2' : r2.snd.fst[j]!.rs = (((RL).take j).flatMap fun ke => heads ke.2).length := by rw [k2, e1]
    have k3' : r2.snd.fst[j]!.rn = (heads (RL)[j].2).length := by rw [k3, e1]
    have k4' : r2.snd.fst[j]!.rc = capCount (fetch s fc.redo b).relCore (RL)[j].1 (RL)[j].2 := by rw [k4, e1]
    refine ⟨k1', k4', k3', ?_, ?_, ?_⟩
    · rw [k2', k3', c5, seg_map, seg_flat RL (fun ke => heads ke.2) j hj]
    · rw [k2', k3', c6, seg_map, seg_flat RL (fun ke => heads ke.2) j hj]
    · rw [k2', k3', c7, seg_map, seg_flat RL (fun ke => heads ke.2) j hj]
  · intro j hj
    dsimp only
    cases hlk : (UL).lookup (RL)[j].1 with
    | none =>
      have hno : ∀ i (hi : i < (UL).length), (UL)[i].1 ≠ (RL)[j].1 := by
        intro i hi heq
        have := List.lookup_eq_none_iff.1 hlk (UL)[i] (List.getElem_mem hi)
        simp [heq] at this
      exact hS.2.2.2 j hj hno
    | some e =>
      obtain ⟨l1, l2, hl, -⟩ := List.lookup_eq_some_iff.1 hlk
      have hmem : ((RL)[j].1, e) ∈ UL := by rw [hl]; simp
      obtain ⟨i, hi, hu⟩ := List.mem_iff_getElem.1 hmem
      obtain ⟨j', hj', e1, s1, s2, s3⟩ := hS.2.2.1 i hi
      have hjj : j' = j := by
        have : ((RL).map (·.1))[j']'(by simpa using hj') = ((RL).map (·.1))[j]'(by simpa using hj) := by
          simp [e1, hu]
        exact (List.getElem_inj hnd).1 this
      rw [hjj] at s1 s2 s3
      have hue : (UL)[i].2 = e := by rw [hu]
      refine ⟨?_, ?_, ?_, ?_, ?_⟩
      · rw [s3, hu]
      · rw [s2, hue]
      · rw [s1, s2, g2, seg_map, seg_flat UL (fun ke => heads ke.2) i hi, hue]
      · rw [s1, s2, g3, seg_map, seg_flat UL (fun ke => heads ke.2) i hi, hue]
      · rw [s1, s2, g4, seg_map, seg_flat UL (fun ke => heads ke.2) i hi, hue]
  · intro i hi
    obtain ⟨-, k1, k2, k3, -⟩ := hL i hi
    refine ⟨?_, ?_, ?_⟩
    · rw [k1, hm]; exact slot_of_key RL _ c1 _ (hkeys i hi _ (by simp [keys]))
    · rw [k2, hm]; exact slot_of_key RL _ c1 _ (hkeys i hi _ (by simp [keys]))
    · rw [k3, hm]; exact slot_of_key RL _ c1 _ (hkeys i hi _ (by simp [keys]))
  · intro q hq hlt
    have hq' := hqs q hq
    dsimp only at hlt ⊢
    obtain ⟨-, -, hu⟩ := g7 q hq'
    have hsl : r2.snd.fst.size = r1.2.1.size := hS.1
    rw [hu] at hlt ⊢
    rw [hrow q hq']
    cases hg : r1.1.get? (idKey ((UL).flatMap fun ke => heads ke.2)[q].row) with
    | none => rw [hg] at hlt; simp at hlt; omega
    | some j =>
      by_cases hj : j < r1.2.1.size
      · obtain ⟨hj2, e2⟩ := slot_inv RL r1.1 hnd c1 c2 _ j hg
        have hf : ((some j).filter (· < r1.2.1.size)).getD r1.2.1.size = j := by
          have hd : decide (j < r1.2.1.size) = true := decide_eq_true hj
          simp [Option.filter, hd]
        rw [hf, List.getElem?_eq_getElem hj2]; simp [e2]
      · have hd : decide (j < r1.2.1.size) = false := decide_eq_false hj
        rw [hg] at hlt; simp [Option.filter, hd] at hlt; omega
  · intro q hq
    dsimp only
    have hq' := hqs q hq
    have e1 := arr_getD_map r2.snd.snd.snd.fst ((UL).flatMap fun ke => heads ke.2) (fun p => BlindLedger.Gate.Engine3.RowX.of p.row)
      default g2 q hq'
    have e2 : r2.snd.snd.snd.fst[q]! = r2.snd.snd.snd.fst.getD q default := by
      rw [Array.getD_eq_getD_getElem?, getElem!_pos _ q hq]; simp [Array.getElem?_eq_getElem hq]
    rw [e2, e1, hrow q hq']
  · intro q hq
    dsimp only
    have hq' := hqs q hq
    rw [hrow q hq']
    obtain ⟨ke, hke, hp⟩ := List.mem_flatMap.1 (List.getElem_mem hq')
    exact ⟨ke, hke, _, hp, rfl⟩
  · rintro q hq ⟨i, hi, hik⟩
    have hq' := hqs q hq
    dsimp only at hik ⊢
    obtain ⟨-, -, hu⟩ := g7 q hq'
    have hsl : r2.snd.fst.size = r1.2.1.size := hS.1
    rw [hrow q hq'] at hik
    have hg : r1.1.get? (idKey ((UL).flatMap fun ke => heads ke.2)[q].row) = some i := by
      rw [← hik]; exact c1 i hi
    have hi2 : i < r1.2.1.size := by rw [c3]; exact hi
    have hf : ((some i).filter (· < r1.2.1.size)).getD r1.2.1.size = i := by
      have hd : decide (i < r1.2.1.size) = true := decide_eq_true hi2
      simp [Option.filter, hd]
    rw [hu, hg, hf, hsl]
    exact hi2
  · intro i hi
    dsimp only
    obtain ⟨-, -, -, -, -, -, ⟨b1, b2⟩, ⟨c1', c2'⟩, ⟨d1, d2⟩, ⟨e1, e2⟩, ⟨x1, x2⟩, ⟨h1, h2⟩⟩ := hL i hi
    exact ⟨⟨b1, b2⟩, ⟨c1', c2'⟩, ⟨d1, d2⟩, ⟨e1, e2⟩, ⟨x1, x2⟩, ⟨h1, by rw [h2]; simp [feedOver]⟩⟩
  · intro q hq
    dsimp only
    have hq' := hqs q hq
    obtain ⟨⟨hs1, hs2⟩, ho, -⟩ := g7 q hq'
    have hs := Slice.mono ⟨hs1, hs2⟩ hpre
    rw [hrow q hq']
    exact ⟨hs, by rw [ho]; simp [feedOver]⟩
  · intro j hj
    dsimp only
    have e1 := c4 j hj
    obtain ⟨k1, k2, k3, k4⟩ := hS.2.1 j hj
    have k2' : r2.snd.fst[j]!.rs = (((RL).take j).flatMap fun ke => heads ke.2).length := by rw [k2, e1]
    have k3' : r2.snd.fst[j]!.rn = (heads (RL)[j].2).length := by rw [k3, e1]
    have hb := seg_bound RL (fun ke => heads ke.2) j hj
    have l5 := congrArg List.length c5
    have l6 := congrArg List.length c6
    simp only [Array.length_toList, List.length_map] at l5 l6
    rw [k2', k3']
    constructor <;> omega
  · intro j hj hpos
    dsimp only at hpos ⊢
    cases hlk : (UL).lookup (RL)[j].1 with
    | none =>
      have hno : ∀ i (hi : i < (UL).length), (UL)[i].1 ≠ (RL)[j].1 := by
        intro i hi heq
        have := List.lookup_eq_none_iff.1 hlk (UL)[i] (List.getElem_mem hi)
        simp [heq] at this
      have := (hS.2.2.2 j hj hno).1
      omega
    | some e =>
      obtain ⟨l1, l2, hl, -⟩ := List.lookup_eq_some_iff.1 hlk
      have hmem : ((RL)[j].1, e) ∈ UL := by rw [hl]; simp
      obtain ⟨i, hi, hu⟩ := List.mem_iff_getElem.1 hmem
      obtain ⟨j', hj', e1, s1, s2, s3⟩ := hS.2.2.1 i hi
      have hjj : j' = j := by
        have : ((RL).map (·.1))[j']'(by simpa using hj') = ((RL).map (·.1))[j]'(by simpa using hj) := by
          simp [e1, hu]
        exact (List.getElem_inj hnd).1 this
      rw [hjj] at s1 s2 s3
      have hue : (UL)[i].2 = e := by rw [hu]
      have hb := seg_bound UL (fun ke => heads ke.2) i hi
      have l2' := congrArg List.length g2
      have l3' := congrArg List.length g3
      simp only [Array.length_toList, List.length_map] at l2' l3'
      rw [s1, s2]
      constructor <;> omega
  · intro i hi
    obtain ⟨-, -, -, -, h5, -⟩ := hL i hi
    exact ⟨(hPay.2.1 _ _ h5).1, (hPay.2.1 _ _ h5).2.1, (hPay.2.1 _ _ h5).2.2⟩
  · intro i j hi hj
    obtain ⟨-, -, -, -, h5, -⟩ := hL i hi
    obtain ⟨-, -, -, -, h5', -⟩ := hL j hj
    constructor
    · intro e; exact hPay.2.2 _ _ _ h5 (by rw [e]; exact h5')
    · intro e; rw [e] at h5; exact Option.some.inj (h5.symm.trans h5')
  · intro i hi
    obtain ⟨-, -, -, -, -, h6, -⟩ := hL i hi
    rw [h6]; exact fseen_eq f b[i]
  · intro i hi
    simp [getElem!_pos, hi]

/-! Scans over a range equal the list scans of the reference (`Ix.enrolled`, `memberDead`, `providerDead`,
    `excluded`, `overlap`). -/

theorem forAny1 (P : Nat → Prop) [DecidablePred P] (l : List Nat) : (Id.run do
      for j in l do
        if P j then return true
      return false) = l.any fun j => decide (P j) := by
  induction l with
  | nil => simp
  | cons x t ih =>
    simp only [List.forIn_cons, List.any_cons]
    by_cases hx : P x
    · simp [hx]
    · simp [hx]; exact ih

theorem forAny2 (Q : Nat → Nat → Prop) [DecidableRel Q] (l1 l2 : List Nat) : (Id.run do
      for j in l1 do
        for k in l2 do
          if Q j k then return true
      return false) = l1.any fun j => l2.any fun k => decide (Q j k) := by
  have hin : ∀ x, (forIn l2 (none, ()) (fun k _ => if Q x k then pure (ForInStep.done (some true, ()))
      else pure (ForInStep.yield (none, ()))) : Id (Option Bool × Unit)) =
      (if l2.any (fun k => decide (Q x k)) = true then (some true, ()) else (none, ())) := by
    intro x
    induction l2 with
    | nil => simp <;> rfl
    | cons y t ih =>
      simp only [List.forIn_cons, List.any_cons]
      by_cases hy : Q x y
      · simp [hy] <;> rfl
      · simp [hy, ih] <;> rfl
  simp only [hin]
  induction l1 with
  | nil => simp <;> rfl
  | cons x t ih =>
    simp only [List.forIn_cons, List.any_cons]
    by_cases hx : l2.any (fun k => decide (Q x k)) = true
    · simp only [hx, Bool.true_or]; rfl
    · simp only [Bool.eq_false_iff.mpr hx, Bool.false_or]; exact ih

theorem rangeAny1 (a n : Nat) (P : Nat → Prop) [DecidablePred P] :
    (Id.run do
      for j in [a:a + n] do
        if P j then return true
      return false) = (List.range' a n).any fun j => decide (P j) := by
  rw [← forAny1]
  simp [Std.Legacy.Range.forIn_eq_forIn_range', Std.Legacy.Range.size]

theorem rangeAny2 (a n : Nat) (Q : Nat → Nat → Prop) [DecidableRel Q] :
    (Id.run do
      for j in [a:a + n] do
        for k in [a:a + n] do
          if Q j k then return true
      return false) = (List.range' a n).any fun j => (List.range' a n).any fun k => decide (Q j k) := by
  rw [← forAny2]
  simp [Std.Legacy.Range.forIn_eq_forIn_range', Std.Legacy.Range.size]

theorem any_range'_get {α : Type} [Inhabited α] (a : Array α) (s n : Nat) (h : s + n ≤ a.size) (P : α → Bool) :
    (List.range' s n).any (fun j => P a[j]!) = ((a.toList.drop s).take n).any P := by
  induction n generalizing s with
  | zero => simp
  | succ n ih =>
    have hs : s < a.size := by omega
    rw [List.range'_succ, List.any_cons, ih (s+1) (by omega)]
    have : (a.toList.drop s).take (n+1) = a[s] :: (a.toList.drop (s+1)).take n := by
      rw [List.drop_eq_getElem_cons (by simpa using hs)]; simp
    rw [this, List.any_cons]; simp [getElem!_pos, hs]

theorem deadIn_eq (ds : Array Death) (g : Rg) (xs : List Death) (d : Nat) (hs : g.s + g.n ≤ ds.size)
    (hg : (ds.toList.drop g.s).take g.n = xs) : deadIn ds g d = xs.any (·.date < d) := by
  unfold deadIn
  refine (rangeAny1 g.s g.n (fun j => ds[j]!.date < d)).trans ?_
  rw [any_range'_get ds g.s g.n hs (fun x => decide (x.date < d)), hg]

theorem exclIn_eq (es : Array Exclusion) (g : Rg) (xs : List Exclusion) (d : Nat) (hs : g.s + g.n ≤ es.size)
    (hg : (es.toList.drop g.s).take g.n = xs) : exclIn es g d = xs.any fun e => e.start ≤ d && d ≤ e.stop := by
  unfold exclIn
  refine (rangeAny1 g.s g.n (fun j => (es[j]!.start ≤ d && d ≤ es[j]!.stop) = true)).trans ?_
  rw [any_range'_get es g.s g.n hs (fun e => decide ((e.start ≤ d && d ≤ e.stop) = true)), hg]
  simp

theorem any_range'_get2 {α : Type} [Inhabited α] (a : Array α) (s n : Nat) (h : s + n ≤ a.size) (P : α → α → Bool) :
    (List.range' s n).any (fun j => (List.range' s n).any fun k => P a[j]! a[k]!) =
      ((a.toList.drop s).take n).any fun x => ((a.toList.drop s).take n).any (P x) := by
  have e : ∀ j : Nat, (List.range' s n).any (fun k : Nat => P a[j]! a[k]!) = ((a.toList.drop s).take n).any (P a[j]!) :=
    fun j => any_range'_get a s n h (P a[j]!)
  simp only [e]
  exact any_range'_get a s n h (fun x => ((a.toList.drop s).take n).any (P x))

theorem enrolledIn_eq (ss : Array SpanF) (g : Rg) (xs : List Span) (l : Line) (hl : fitsLine2 l = true)
    (hs : g.s + g.n ≤ ss.size) (hg : (ss.toList.drop g.s).take g.n = xs.map (spanF l.member)) :
    enrolledIn ss g (RowX.of l) = xs.any (covers l) := by
  unfold enrolledIn
  dsimp only
  rw [rangeAny1]
  obtain ⟨_, _, _, hpe, _, hda, _⟩ := Engine3.fits2 hl
  have hd : (RowX.of l).date.toNat = l.date := by
    simp only [RowX.of, Nat.toUInt32, UInt32.toNat_ofNat']; exact Nat.mod_eq_of_lt hda
  refine (any_range'_get ss g.s g.n hs (fun s => decide ((s.mOk && decide (s.start ≤ (RowX.of l).date.toNat) &&
    decide ((RowX.of l).date.toNat ≤ s.stop) && (!(RowX.of l).cap || s.small && s.p0 == (RowX.of l).a0 &&
      s.p1 == (RowX.of l).a1 && s.p2 == (RowX.of l).a2)) = true))).trans ?_
  rw [hg, List.any_map]
  congr 1
  funext x
  have hw : (x.plan < 2 ^ 192 ∧ word x.plan 2 = word l.payee 2 ∧ word x.plan 1 = word l.payee 1 ∧
      word x.plan 0 = word l.payee 0) ↔ x.plan = l.payee := by
    constructor
    · rintro ⟨hlt, h2, h1, h0⟩; exact (Engine3.words3 hlt hpe).1 ⟨h0, h1, h2⟩
    · intro h; rw [h]; exact ⟨hpe, rfl, rfl, rfl⟩
  rw [Bool.eq_iff_iff]
  simp only [Function.comp, spanF, covers, hd, Engine3.cap_of, Bool.and_eq_true, Bool.or_eq_true,
    decide_eq_true_eq, beq_iff_eq, Bool.not_eq_true', and_assoc]
  simp only [RowX.of, hw]

theorem overlapIn_eq (ss : Array SpanF) (g : Rg) (xs : List Span) (m : Nat) (d : Nat)
    (hs : g.s + g.n ≤ ss.size) (hg : (ss.toList.drop g.s).take g.n = xs.map (spanF m)) :
    overlapIn ss g d = (let first := d / 100 * 100 + 1
      let last := d / 100 * 100 + monthDays (d / 10000) (d / 100 % 100)
      xs.any fun s => xs.any fun t => s.plan != t.plan && max first (max s.start t.start) ≤ min last (min s.stop t.stop)) := by
  unfold overlapIn
  dsimp only
  rw [rangeAny2]
  simp only [Bool.decide_eq_true]
  refine (any_range'_get2 ss g.s g.n hs (fun s t => s.plan != t.plan &&
    decide (max (d / 100 * 100 + 1) (max s.start t.start) ≤
      min (d / 100 * 100 + monthDays (d / 10000) (d / 100 % 100)) (min s.stop t.stop)))).trans ?_
  rw [hg, List.any_map]
  congr 1
  funext s
  rw [Function.comp_apply, List.any_map]
  rfl

/-- (3a) The `qsort` order: with `p i = q b[i]`, the sorted indexes name `canonical` of the kept lines.  Needs
    `Array.qsort` to be a permutation and sorted (core has no lemma for either), then `Perm.eq_of_pairwise`
    as in `Rules/Theorems.lean:724`. -/
theorem qsort_canonical (b : List Line) (hb : ∀ l ∈ b, fitsLine2 l = true) (p : Nat → Bool) (q : Line → Bool)
    (hp : ∀ i, i < b.length → p i = q (b.getD i nilLine)) (ltf : Nat → Nat → Bool)
    (hl : ∀ i j, i < b.length → j < b.length → ltf i j = (RowX.of (b.getD i nilLine)).lt (RowX.of (b.getD j nilLine))) :
    ((((Array.range b.length).filter p).qsort ltf).toList.map (b.getD · nilLine) = canonical (b.filter q)) ∧
      ∀ x ∈ ((Array.range b.length).filter p).qsort ltf, x < b.length := by
  have trans : ∀ x y z : Line, lineLe x y → lineLe y z → lineLe x z := by
    simp only [lineLe, decide_eq_true_eq]; exact fun _ _ _ => List.le_trans
  have total : ∀ x y : Line, (lineLe x y || lineLe y x) = true := by
    intro x y; simp only [lineLe, Bool.or_eq_true, decide_eq_true_eq]
    exact @List.le_total Nat _ ⟨fun _ _ => Nat.lt_asymm⟩ _ _
  have hgd : ∀ i (h : i < b.length), b.getD i nilLine = b[i] := fun i h => by
    simp [List.getD_eq_getElem?_getD, h]
  have hfit : ∀ i, i < b.length → fitsLine2 (b.getD i nilLine) = true := fun i hi => by
    rw [hgd i hi]; exact hb _ (List.getElem_mem hi)
  have hS : QS.Strict ltf (· < b.length) := by
    refine ⟨fun x hx => ?_, fun x y z hx hy hz hxy hyz => ?_⟩
    · simp only [hl x x hx hx, rowX_lt_eq _ _ (hfit x hx) (hfit x hx), Bool.not_eq_false', lineLe, decide_eq_true_eq]
      exact List.le_refl _
    · simp only [hl x y hx hy, hl y z hy hz, hl x z hx hz, rowX_lt_eq _ _ (hfit _ hx) (hfit _ hy), rowX_lt_eq _ _ (hfit _ hy) (hfit _ hz),
        rowX_lt_eq _ _ (hfit _ hx) (hfit _ hz), Bool.not_eq_true'] at hxy hyz ⊢
      have h1 := total (b.getD x nilLine) (b.getD y nilLine)
      have h2 := total (b.getD y nilLine) (b.getD z nilLine)
      rw [hxy] at h1; rw [hyz] at h2
      simp only [Bool.or_false] at h1 h2
      cases hc : lineLe (b.getD z nilLine) (b.getD x nilLine)
      · rfl
      · have := trans _ _ _ h2 hc
        rw [hxy] at this; exact absurd this (by simp)
  have hq := QS.qsort_spec _ hS ((Array.range b.length).filter p)
    (fun x hx => Array.mem_range.1 (Array.mem_filter.1 hx).1)
  obtain ⟨hperm, hsorted⟩ := hq
  generalize ((Array.range b.length).filter p).qsort ltf = A at hperm hsorted ⊢
  have hmem : ∀ x ∈ A, x < b.length := fun x hx => by
    exact Array.mem_range.1 (Array.mem_filter.1 (hperm.mem_iff.1 hx)).1
  have hmap : ((List.range b.length).filter p).map (b.getD · nilLine) = b.filter q := by
    have hb' : (List.range b.length).map (b.getD · nilLine) = b := by
      apply List.ext_getElem (by simp)
      intro i h1 h2
      simp only [List.getElem_map, List.getElem_range]
      exact hgd i h2
    calc ((List.range b.length).filter p).map (b.getD · nilLine)
        = ((List.range b.length).filter (fun i => q (b.getD i nilLine))).map (b.getD · nilLine) := by
          rw [List.filter_congr (fun x hx => hp x (List.mem_range.1 hx))]
      _ = ((List.range b.length).map (b.getD · nilLine)).filter q := by rw [List.filter_map]; rfl
      _ = b.filter q := by rw [hb']
  have hpermL : (A.toList.map (b.getD · nilLine)).Perm (b.filter q) := by
    have := (Array.perm_iff_toList_perm.1 hperm).map (b.getD · nilLine)
    rw [Array.toList_filter, Array.toList_range, hmap] at this
    exact this
  have hpw : (A.toList.map (b.getD · nilLine)).Pairwise (fun x y => lineLe x y = true) := by
    rw [List.pairwise_iff_getElem]
    intro i j hi hj hij
    simp only [List.getElem_map, Array.getElem_toList]
    have hi' : i < A.size := by simpa using hi
    have hj' : j < A.size := by simpa using hj
    have := hsorted i j hi' hj' hij
    simp only [hl _ _ (hmem _ (Array.getElem_mem hj')) (hmem _ (Array.getElem_mem hi')),
      rowX_lt_eq _ _ (hfit _ (hmem _ (Array.getElem_mem hj'))) (hfit _ (hmem _ (Array.getElem_mem hi'))),
      Bool.not_eq_false'] at this
    exact this
  refine ⟨?_, hmem⟩
  unfold canonical
  refine List.Perm.eq_of_pairwise (le := fun x y => lineLe x y = true) ?_ hpw
    (List.pairwise_mergeSort trans total _) (hpermL.trans (List.mergeSort_perm _ _).symm)
  intro x y _ _ hxy hyx
  simp only [lineLe, decide_eq_true_eq] at hxy hyx
  exact enc_inj (List.le_antisymm hxy hyx)

/-! The fetched rows read through `postMap` when entries may be cut at `capN` (the lemmas of `Flat/Theorems.lean` need
    every entry whole): a posting's row is the snapshot row at its `seq`, so postings with one `seq` agree. -/

theorem heads_row {H : Bytes → Bytes} {S : SetIdx} {snap : Snapshot Line} (hS : IdxInv H S snap) {k : Key}
    {p : Posting} (hp : p ∈ heads (S.get k)) : snap.entries[p.seq]? = some p.row := by
  have h := (entryOf_count H snap.entries k).2
  rw [hS.2 k] at hp
  unfold heads at hp
  rw [h] at hp
  simp only [List.take_take, Nat.min_self] at hp
  obtain ⟨j, h1, h2, -⟩ := (mem_postingsFrom _ 0 p).mp (List.mem_of_mem_take hp)
  rw [h2]; simpa using h1

theorem probe_heads {H : Bytes → Bytes} {S : SetIdx} {snap : Snapshot Line} (hS : IdxInv H S snap) (ks : List Key)
    {k : Key} (hk : k ∈ ks) (P : Line → Bool) :
    (((postMap (localRows (ks.map fun k => (k, S.get k))) (ks.map fun k => (k, S.get k))).getD k []).any
      fun i => decide (i < (localRows (ks.map fun k => (k, S.get k))).length) &&
        ((localRows (ks.map fun k => (k, S.get k))).map (·.row)).toArray[i]?.any P) =
      (heads (S.get k)).any fun p => P p.row := by
  obtain ⟨L, hL⟩ : ∃ L, L = (ks.map fun k => (k, S.get k)).flatMap fun ke => heads ke.2 := ⟨_, rfl⟩
  have hLm : ∀ p, p ∈ L ↔ ∃ k' ∈ ks, p ∈ heads (S.get k') := by
    intro p
    rw [hL]
    simp only [List.mem_flatMap, List.mem_map]
    constructor
    · rintro ⟨ke, ⟨k', hk', rfl⟩, hp⟩; exact ⟨k', hk', hp⟩
    · rintro ⟨k', hk', hp⟩; exact ⟨(k', S.get k'), ⟨k', hk', rfl⟩, hp⟩
  have hLrow : ∀ p ∈ L, snap.entries[p.seq]? = some p.row := fun p hp => by
    obtain ⟨k', -, hp'⟩ := (hLm p).mp hp
    exact heads_row hS hp'
  have hM := List.pairwise_mergeSort (le := fun p q : Posting => decide (p.seq ≤ q.seq))
    (fun a b c h1 h2 => by simp at *; omega) (fun a b => by simp; omega) L
  have hM' : (L.mergeSort fun p q : Posting => decide (p.seq ≤ q.seq)).Pairwise (fun p q => p.seq ≤ q.seq) :=
    hM.imp (fun h => by simpa using h)
  have hMm : ∀ p, p ∈ L.mergeSort (fun p q : Posting => decide (p.seq ≤ q.seq)) ↔ p ∈ L := fun p =>
    (List.mergeSort_perm L _).mem_iff
  obtain ⟨i1, i2, i3⟩ := dedupSeq_spec _ hM'
  have hrr : localRows (ks.map fun k => (k, S.get k)) =
      dedupSeq (L.mergeSort fun p q : Posting => decide (p.seq ≤ q.seq)) := by
    unfold localRows; rw [← hL]
  rw [hrr]
  generalize dedupSeq (L.mergeSort fun p q : Posting => decide (p.seq ≤ q.seq)) = rr at i1 i2 i3 ⊢
  unfold postMap
  rw [List.foldl_map, foldl_insert_getD (fun k => (heads (S.get k)).filterMap fun p =>
    (rr.foldl (fun (acc : Std.HashMap Nat Nat × Nat) p => (acc.1.insert p.seq acc.2, acc.2 + 1)) (∅, 0)).1.get? p.seq) ks,
    if_pos hk, Bool.eq_iff_iff]
  simp only [List.any_eq_true, List.mem_filterMap, Std.HashMap.get?_eq_getElem?, Bool.and_eq_true,
    decide_eq_true_eq, List.getElem?_toArray, Option.any_eq_true]
  constructor
  · rintro ⟨i, ⟨p, hp, hpos⟩, hi, y, hy, hPy⟩
    rw [pos_foldl rr ∅ 0 i2] at hpos
    simp only [Nat.sub_zero, Nat.zero_le, true_and] at hpos
    rcases hpos with ⟨q, h2, h3⟩ | ⟨h, -⟩
    · refine ⟨p, hp, ?_⟩
      have hq : q ∈ L := (hMm q).mp (i1 q (List.mem_of_getElem? h2))
      have hpL : p ∈ L := (hLm p).mpr ⟨k, hk, hp⟩
      have e : q.row = p.row := by
        have h4 := hLrow q hq
        rw [h3] at h4
        exact Option.some.inj (h4.symm.trans (hLrow p hpL))
      simp only [List.getElem?_map, h2, Option.map_some, Option.some.injEq] at hy
      rw [← hy, e] at hPy
      exact hPy
    · simp at h
  · rintro ⟨p, hp, hP⟩
    have hpL : p ∈ L := (hLm p).mpr ⟨k, hk, hp⟩
    obtain ⟨q, hq, hs⟩ := i3 p ((hMm p).mpr hpL)
    obtain ⟨i, hi⟩ := List.mem_iff_getElem?.mp hq
    have e : q.row = p.row := by
      have h4 := hLrow q ((hMm q).mp (i1 q hq))
      rw [hs] at h4
      exact Option.some.inj (h4.symm.trans (hLrow p hpL))
    refine ⟨i, ⟨p, hp, ?_⟩, (List.getElem?_eq_some_iff.mp hi).1, q.row, by simp [hi], by rw [e]; exact hP⟩
    rw [pos_foldl rr ∅ 0 i2]
    simp only [Nat.sub_zero, Nat.zero_le, true_and]
    left; exact ⟨q, hi, hs⟩

/-! Masks: bit `r.idx` for reason `r`; `has m r` reads it.  The mask of a line is exact for the reasons list. -/

theorem mem_reasons (r : Reason) : r ∈ reasons := by cases r <;> decide

theorem idx_len (r : Reason) : r.idx < reasons.length := BlindLedger.Gate.Rules.idx_len r

/-- The UInt32 line-mask width until step 5; not a total-count guard. -/
theorem reasons_len_le32 : reasons.length ≤ 32 := by decide

theorem idx_lt32 (r : Reason) : r.idx < 32 := Nat.lt_of_lt_of_le (idx_len r) reasons_len_le32

theorem idx_inj {r r' : Reason} (h : r.idx = r'.idx) : r = r' := Reason.idx_inj h

theorem bit_toNat (r : Reason) : (bit r).toNat = 2 ^ r.idx := by
  have := idx_lt32 r
  simp only [bit, UInt32.toNat_shiftLeft, Nat.toUInt32, UInt32.toNat_ofNat]
  have h1 : (UInt32.ofNat r.idx).toNat % 32 = r.idx := by simp only [UInt32.toNat_ofNat']; omega
  have h2 : (1 % 2 ^ 32 : Nat) = 1 := by decide
  rw [h1, h2, Nat.one_shiftLeft]
  exact Nat.mod_eq_of_lt (Nat.lt_of_lt_of_le (Nat.pow_lt_pow_right (by decide) this) (Nat.pow_le_pow_right (by decide) (by decide)))

def has (m : UInt32) (r : Reason) : Bool := m &&& bit r != 0

theorem has_iff (m : UInt32) (r : Reason) : has m r = m.toNat.testBit r.idx := by
  have h := bit_toNat r
  unfold has
  rw [Bool.eq_iff_iff]
  simp only [bne_iff_ne, ne_eq, ← UInt32.toNat_inj, UInt32.toNat_and, h, UInt32.toNat_zero]
  constructor
  · intro hne
    refine Classical.byContradiction fun hb => hne ?_
    apply Nat.eq_of_testBit_eq
    intro j
    rw [Nat.testBit_and, Nat.testBit_two_pow, Nat.zero_testBit]
    by_cases hj : r.idx = j
    · subst hj; simp [Bool.not_eq_true] at hb; simp [hb]
    · simp [hj]
  · intro hb hz
    have := congrArg (fun n => n.testBit r.idx) hz
    simp [Nat.testBit_and, Nat.testBit_two_pow, hb] at this



theorem has_zero (r : Reason) : has 0 r = false := by
  rw [has_iff]; simp

theorem has_or (a b : UInt32) (r : Reason) : has (a ||| b) r = (has a r || has b r) := by
  simp only [has_iff, UInt32.toNat_or, Nat.testBit_or]

theorem has_bit (r r' : Reason) : has (bit r') r = decide (r = r') := by
  rw [has_iff, bit_toNat, Nat.testBit_two_pow]
  rw [Bool.eq_iff_iff]
  simp only [decide_eq_true_eq]
  exact ⟨fun h => idx_inj h.symm, fun h => by rw [h]⟩

theorem has_on (c : Bool) (r r' : Reason) : has (on c (bit r')) r = (c && decide (r = r')) := by
  cases c <;> simp [on, has_zero, has_bit]

def Lo (m : UInt32) : Prop := m.toNat < 2 ^ reasons.length

theorem Lo_zero : Lo 0 := by unfold Lo; simpa using Nat.two_pow_pos reasons.length

theorem Lo_bit (r : Reason) : Lo (bit r) := by
  unfold Lo; rw [bit_toNat]; exact Nat.pow_lt_pow_right (by decide) (idx_len r)

theorem Lo_or {a b : UInt32} (ha : Lo a) (hb : Lo b) : Lo (a ||| b) := by
  unfold Lo at *; rw [UInt32.toNat_or]; exact Nat.or_lt_two_pow ha hb

theorem Lo_on (c : Bool) (r : Reason) : Lo (on c (bit r)) := by
  cases c <;> simp [on, Lo_zero, Lo_bit]

theorem reasons_nodup : reasons.Nodup := BlindLedger.Gate.Rules.reasons_list_nodup

-- Step 2 evidence, outside `gate_engine`: today `Reason.idx` is each reason's place in name order, so numbering the
-- answer bits by `idx` moves no bit.  Expected to fail at step 3, when a reason sorts into the middle; removed then.
#guard reasons.zipIdx.all fun (r, i) => r.idx == i


theorem eq_zero_of_has {m : UInt32} (hm : Lo m) (h : ∀ r, has m r = false) : m = 0 := by
  rw [← UInt32.toNat_inj, UInt32.toNat_zero]
  apply Nat.eq_of_testBit_eq
  intro j
  rw [Nat.zero_testBit]
  by_cases hj : j < reasons.length
  · obtain ⟨r, -, rfl⟩ := BlindLedger.Gate.Rules.idx_dense j hj
    have := h r
    rwa [has_iff] at this
  · exact Nat.testBit_lt_two_pow (Nat.lt_of_lt_of_le hm (Nat.pow_le_pow_right (by decide) (by omega)))



theorem has_maskOf_aux (p : Reason → Bool) (r : Reason) : ∀ (l : List Reason) (acc : UInt32),
    has (l.foldl (fun a r => if p r then a ||| bit r else a) acc) r = (has acc r || (decide (r ∈ l) && p r))
  | [], acc => by simp
  | x :: t, acc => by
    rw [List.foldl_cons, has_maskOf_aux p r t]
    by_cases hp : p x
    · simp only [hp, if_true, has_or, has_bit, List.mem_cons]
      by_cases hr : r = x <;> simp [hr, hp]
    · simp only [hp, Bool.false_eq_true, if_false, List.mem_cons]
      by_cases hr : r = x <;> simp [hr, hp]

theorem has_maskOf (p : Reason → Bool) (r : Reason) : has (maskOf p) r = p r := by
  unfold maskOf
  rw [has_maskOf_aux, has_zero]
  simp [mem_reasons]

theorem Lo_maskOf_aux (p : Reason → Bool) : ∀ (l : List Reason) (acc : UInt32), Lo acc →
    Lo (l.foldl (fun a r => if p r then a ||| bit r else a) acc)
  | [], acc, h => h
  | x :: t, acc, h => by
    rw [List.foldl_cons]
    refine Lo_maskOf_aux p t _ ?_
    by_cases hp : p x
    · simp only [hp, if_true]; exact Lo_or h (Lo_bit x)
    · simpa [hp] using h

theorem Lo_maskOf (p : Reason → Bool) : Lo (maskOf p) := Lo_maskOf_aux p _ _ Lo_zero

theorem has_andnot (a b : UInt32) (r : Reason) : has (a &&& ~~~b) r = (has a r && !has b r) := by
  have hl := idx_lt32 r
  simp only [has_iff, UInt32.toNat_and, UInt32.toNat_not, Nat.testBit_and]
  have : 2 ^ 32 - 1 - b.toNat = 2 ^ 32 - (b.toNat + 1) := by omega
  rw [this, Nat.testBit_two_pow_sub_succ b.toNat_lt]
  simp [show r.idx < 32 by omega]

theorem Lo_andnot {a : UInt32} (b : UInt32) (h : Lo a) : Lo (a &&& ~~~b) := by
  unfold Lo at *
  rw [UInt32.toNat_and]
  exact Nat.lt_of_le_of_lt Nat.and_le_left h

theorem outOf_eq (m : UInt32) (hm : Lo m) :
    outcomeOf8 (outOf m) = outcomeOf (reasons.filter (has m ·)) := by
  have hz : (m == 0) = (reasons.filter (has m ·)).isEmpty := by
    rw [Bool.eq_iff_iff]
    simp only [beq_iff_eq, List.isEmpty_iff, List.filter_eq_nil_iff, Bool.not_eq_true']
    constructor
    · intro h r _; rw [h, has_zero]; simp
    · intro h; exact eq_zero_of_has hm fun r => by simpa using h r (mem_reasons r)
  have hr : ((m &&& ~~~reviewM) != 0) = (reasons.filter (has m ·)).any (!review ·) := by
    rw [Bool.eq_iff_iff]
    simp only [bne_iff_ne, ne_eq, List.any_eq_true, List.mem_filter, Bool.not_eq_true', Bool.not_eq_eq_eq_not,
      Bool.not_true]
    constructor
    · intro h
      refine Classical.byContradiction fun hc => h (eq_zero_of_has (Lo_andnot _ hm) fun r => ?_)
      rw [has_andnot]
      unfold reviewM
      rw [has_maskOf]
      cases hh : has m r
      · rfl
      · cases hv : review r
        · exact absurd ⟨r, ⟨mem_reasons r, hh⟩, by simp [hv]⟩ hc
        · rfl
    · rintro ⟨r, ⟨-, hh⟩, hv⟩ h0
      have := congrArg (fun z => has z r) h0
      simp only [has_andnot, has_zero, hh] at this
      unfold reviewM at this
      rw [has_maskOf] at this
      simp [hv] at this
  unfold outOf outcomeOf outcomeOf8
  rw [← hz, ← hr]
  by_cases h1 : (m == 0) = true
  · simp [h1]
  · simp only [Bool.not_eq_true] at h1
    by_cases h2 : ((m &&& ~~~reviewM) != 0) = true
    · simp [h1, h2]
    · simp only [Bool.not_eq_true] at h2
      simp [h1, h2]

/-! ## Per-line facts: `decideRows`' first pass against the local index of the reference -/

theorem anySame_eq (ps : Array RowX) (s n : Nat) (r : RowX) (hs : 0 < n → s + n ≤ ps.size) :
    anySame ps s n r = ((ps.toList.drop s).take n).any (fun p => p.same r) := by
  unfold anySame
  rw [rangeAny1 s n (fun j => (ps[j]!.same r) = true)]
  rcases Nat.eq_zero_or_pos n with rfl | hn
  · simp
  · rw [← any_range'_get ps s n (hs hn) (fun p => p.same r)]
    simp

theorem lookup_map {g : Key → Entry} : ∀ {ks : List Key} {k : Key}, k ∈ ks →
    (ks.map fun k => (k, g k)).lookup k = some (g k)
  | [], k, h => absurd h (by simp)
  | a :: t, k, h => by
    by_cases hk : a = k
    · subst hk; simp
    · have : k ∈ t := by simpa [Ne.symm hk] using h
      simp [List.lookup, beq_false_of_ne (Ne.symm hk), lookup_map this]

section
variable {H : Bytes → Bytes} {s : St} {fc : FCtx} {f : List Nat} {b : List Line} {rel unr : Snapshot Line}

theorem fetch_rel_get (j : Nat) (hj : j < (fetch s fc.redo b).rel.length) :
    ∃ k, k ∈ ksR s fc.redo b ∧ (fetch s fc.redo b).rel[j] = (k, s.rel.get k) := by
  have h : (fetch s fc.redo b).rel[j] ∈ (ksR s fc.redo b).map fun k => (k, s.rel.get k) := by
    rw [← fetch_rel']; exact List.getElem_mem hj
  rw [List.mem_map] at h
  obtain ⟨k, hk, e⟩ := h
  exact ⟨k, hk, e.symm⟩

theorem heads_fit {S : SetIdx} {snap : Snapshot Line} (hS : IdxInv H S snap) {k : Key} {p : Posting} (hp : p ∈ heads (S.get k))
    (hw : ∀ l ∈ snap.entries, fitsLine2 l = true) : fitsLine2 p.row = true :=
  hw _ (List.mem_of_getElem? (heads_row hS hp))

theorem relSlot_any (R : Rep (layout s fc f b) s fc f b) (hr : IdxInv H s.rel rel)
    (hw : ∀ l ∈ rel.entries, fitsLine2 l = true) (j : Nat) (hj : j < (fetch s fc.redo b).rel.length)
    (l : Line) (hl : fitsLine2 l = true) :
    anySame (layout s fc f b).relP (layout s fc f b).slots[j]!.rs (layout s fc f b).slots[j]!.rn (RowX.of l) =
      (heads (fetch s fc.redo b).rel[j].2).any fun p => p.row == l := by
  obtain ⟨k, hk, e⟩ := fetch_rel_get (s := s) (fc := fc) (b := b) j hj
  have e2 := congrArg Prod.snd e
  obtain ⟨-, -, -, h1, -, -⟩ := R.relSlot j hj
  obtain ⟨hb, -⟩ := R.relBnd j hj
  rw [anySame_eq _ _ _ _ (fun _ => hb), h1]
  rw [Bool.eq_iff_iff]
  simp only [List.any_map, List.any_eq_true, Function.comp]
  simp only [e2]
  constructor <;> rintro ⟨p, hp, h⟩ <;> refine ⟨p, hp, ?_⟩
  · have := (Engine3.rowX_same_iff _ _ (heads_fit hr hp hw) hl).1 h; simpa using this
  · exact (Engine3.rowX_same_iff _ _ (heads_fit hr hp hw) hl).2 (by simpa using h)

theorem date_toNat {l : Line} (hl : fitsLine2 l = true) : (RowX.of l).date.toNat = l.date := by
  obtain ⟨_, _, _, _, _, hda, _⟩ := Engine3.fits2 hl
  simp only [RowX.of, Nat.toUInt32, UInt32.toNat_ofNat']; exact Nat.mod_eq_of_lt hda

theorem slot_of_opt {l : List (Key × Entry)} {j : Nat} {k : Key} (h : l[j]?.map (·.1) = some k) :
    ∃ hj : j < l.length, l[j].1 = k := by
  cases hl : l[j]? with
  | none => simp [hl] at h
  | some ke =>
    obtain ⟨hj, e⟩ := List.getElem?_eq_some_iff.1 hl
    refine ⟨hj, ?_⟩
    rw [hl] at h
    simp only [Option.map_some, Option.some.injEq] at h
    rw [e]; exact h

theorem line_row (R : Rep (layout s fc f b) s fc f b) (i : Nat) (hi : i < b.length) :
    (layout s fc f b).lines[i]!.row = RowX.of b[i] := by
  have h := R.rows
  have hl : i < (layout s fc f b).lines.size := by have := congrArg List.length h; simp at this; omega
  have := congrArg (fun l => l[i]?) h
  simpa [hl, hi, getElem!_pos] using this

theorem relAny (hr : IdxInv H s.rel rel) {k : Key} (hk : k ∈ ksR s fc.redo b) (P : Line → Bool) :
    (((locIx s fc b).relPost.getD k []).any fun i => decide (i < (locIx s fc b).relN) && (locIx s fc b).rel[i]?.any P) =
      (heads (s.rel.get k)).any fun p => P p.row :=
  probe_heads hr (ksR s fc.redo b) hk P

theorem unrAny (hu : IdxInv H s.unr unr) {k : Key} (hk : k ∈ probeKeys b) (P : Line → Bool) :
    (((locIx s fc b).unrPost.getD k []).any fun i => decide (i < (locIx s fc b).unrN) && (locIx s fc b).unr[i]?.any P) =
      (heads (s.unr.get k)).any fun p => P p.row :=
  probe_heads hu (probeKeys b) hk P

theorem unrSlot_any (R : Rep (layout s fc f b) s fc f b) (hu : IdxInv H s.unr unr)
    (hw : ∀ l ∈ unr.entries, fitsLine2 l = true) (j : Nat) (hj : j < (fetch s fc.redo b).rel.length)
    (hk : (fetch s fc.redo b).rel[j].1 ∈ probeKeys b) (l : Line) (hl : fitsLine2 l = true) :
    anySame (layout s fc f b).unrP (layout s fc f b).slots[j]!.us (layout s fc f b).slots[j]!.un (RowX.of l) =
      (heads (s.unr.get (fetch s fc.redo b).rel[j].1)).any fun p => p.row == l := by
  have h := R.unrSlot j hj
  have hl' : (fetch s fc.redo b).unr.lookup (fetch s fc.redo b).rel[j].1 = some (s.unr.get (fetch s fc.redo b).rel[j].1) :=
    lookup_map (g := fun k => s.unr.get k) (ks := probeKeys b) hk
  simp only [hl'] at h
  obtain ⟨-, hn, h1, -, -⟩ := h
  have hb : 0 < (layout s fc f b).slots[j]!.un → (layout s fc f b).slots[j]!.us + (layout s fc f b).slots[j]!.un ≤ (layout s fc f b).unrP.size :=
    fun hp => (R.unrBnd j hj hp).1
  rw [anySame_eq _ _ _ _ hb, h1]
  rw [Bool.eq_iff_iff]
  simp only [List.any_map, List.any_eq_true, Function.comp]
  constructor <;> rintro ⟨p, hp, h⟩ <;> refine ⟨p, hp, ?_⟩
  · have := (Engine3.rowX_same_iff _ _ (heads_fit hu hp hw) hl).1 h; simpa using this
  · exact (Engine3.rowX_same_iff _ _ (heads_fit hu hp hw) hl).2 (by simpa using h)

theorem key_slot (R : Rep (layout s fc f b) s fc f b) (i : Nat) (hi : i < b.length) :
    ∃ (h1 : (layout s fc f b).lines[i]!.ke < (fetch s fc.redo b).rel.length) (h2 : (layout s fc f b).lines[i]!.kn < (fetch s fc.redo b).rel.length)
      (h3 : (layout s fc f b).lines[i]!.ki < (fetch s fc.redo b).rel.length),
      (fetch s fc.redo b).rel[(layout s fc f b).lines[i]!.ke].1 = exactKey b[i] ∧
      (fetch s fc.redo b).rel[(layout s fc f b).lines[i]!.kn].1 = nearKey b[i] ∧
      (fetch s fc.redo b).rel[(layout s fc f b).lines[i]!.ki].1 = idKey b[i] := by
  obtain ⟨a, bb, c⟩ := R.lineKeys i hi
  obtain ⟨h1, e1⟩ := slot_of_opt a
  obtain ⟨h2, e2⟩ := slot_of_opt bb
  obtain ⟨h3, e3⟩ := slot_of_opt c
  exact ⟨h1, h2, h3, e1, e2, e3⟩

theorem key_mem (k : Key) (hk : k ∈ keys l) (hl : l ∈ b) : k ∈ probeKeys b :=
  mem_probeKeys.2 ⟨l, hl, hk⟩

theorem own_line (R : Rep (layout s fc f b) s fc f b) (hr : IdxInv H s.rel rel)
    (hw : ∀ l ∈ rel.entries, fitsLine2 l = true) (hb : ∀ l ∈ b, fitsLine2 l = true) (i : Nat) (hi : i < b.length) :
    ((layout s fc f b).pRedo[(layout s fc f b).lines[i]!.pay]! &&
      anySame (layout s fc f b).relP (layout s fc f b).slots[(layout s fc f b).lines[i]!.ki]!.rs
        (layout s fc f b).slots[(layout s fc f b).lines[i]!.ki]!.rn (layout s fc f b).lines[i]!.row) =
      (locIx s fc b).own b[i] := by
  obtain ⟨-, -, h3, -, -, e3⟩ := key_slot R i hi
  have hbi : fitsLine2 b[i] = true := hb _ (List.getElem_mem hi)
  rw [line_row R i hi, relSlot_any R hr hw _ h3 _ hbi, (R.pay i hi).2.1]
  unfold Ix.own
  obtain ⟨k, hk, e⟩ := fetch_rel_get (s := s) (fc := fc) (b := b) _ h3
  have e1 := congrArg Prod.fst e
  have e2 := congrArg Prod.snd e
  rw [e3] at e1
  rw [relAny hr (k := idKey b[i]) (by rw [e1]; exact hk) (· == b[i]), e2, e1]
  simp [locIx, localIx, HashSet.contains_ofList]

theorem held_line (R : Rep (layout s fc f b) s fc f b) (hu : IdxInv H s.unr unr)
    (hw : ∀ l ∈ unr.entries, fitsLine2 l = true) (hb : ∀ l ∈ b, fitsLine2 l = true) (i : Nat) (hi : i < b.length) :
    anySame (layout s fc f b).unrP (layout s fc f b).slots[(layout s fc f b).lines[i]!.ki]!.us
        (layout s fc f b).slots[(layout s fc f b).lines[i]!.ki]!.un (layout s fc f b).lines[i]!.row =
      (locIx s fc b).held b[i] := by
  obtain ⟨-, -, h3, -, -, e3⟩ := key_slot R i hi
  have hbi : fitsLine2 b[i] = true := hb _ (List.getElem_mem hi)
  have hkp : (fetch s fc.redo b).rel[(layout s fc f b).lines[i]!.ki].1 ∈ probeKeys b :=
    by rw [e3]; exact key_mem _ (by simp [keys]) (List.getElem_mem hi)
  rw [line_row R i hi, unrSlot_any R hu hw _ h3 hkp _ hbi, e3]
  unfold Ix.held
  rw [unrAny hu (k := idKey b[i]) (key_mem _ (by simp [keys]) (List.getElem_mem hi)) (· == b[i])]


theorem loc_dmf {l : Line} (hl : l ∈ b) : (locIx s fc b).dmf.getD l.member [] = facts (fc.feeds.dmf l.member) := by
  show (idMap fc.feeds.dmf (members b)).getD _ [] = _
  rw [idMap_getD, if_pos]; exact List.mem_map.2 ⟨l, hl, rfl⟩

theorem loc_pdP {l : Line} (hl : l ∈ b) : (locIx s fc b).pdeath.getD l.payee [] = facts (fc.feeds.pdeath l.payee) := by
  show (idMap fc.feeds.pdeath (parties b)).getD _ [] = _
  rw [idMap_getD, if_pos]; simp only [parties, List.mem_flatMap]; exact ⟨l, hl, by simp⟩

theorem loc_pdR {l : Line} (hl : l ∈ b) : (locIx s fc b).pdeath.getD l.rendering [] = facts (fc.feeds.pdeath l.rendering) := by
  show (idMap fc.feeds.pdeath (parties b)).getD _ [] = _
  rw [idMap_getD, if_pos]; simp only [parties, List.mem_flatMap]; exact ⟨l, hl, by simp⟩

theorem loc_exP {l : Line} (hl : l ∈ b) : (locIx s fc b).excl.getD l.payee [] = facts (fc.feeds.excl l.payee) := by
  show (idMap fc.feeds.excl (parties b)).getD _ [] = _
  rw [idMap_getD, if_pos]; simp only [parties, List.mem_flatMap]; exact ⟨l, hl, by simp⟩

theorem loc_exR {l : Line} (hl : l ∈ b) : (locIx s fc b).excl.getD l.rendering [] = facts (fc.feeds.excl l.rendering) := by
  show (idMap fc.feeds.excl (parties b)).getD _ [] = _
  rw [idMap_getD, if_pos]; simp only [parties, List.mem_flatMap]; exact ⟨l, hl, by simp⟩

theorem loc_span {l : Line} (hl : l ∈ b) : (locIx s fc b).span.getD l.member [] = facts (fc.feeds.span l.member) := by
  show (idMap fc.feeds.span (spanIds b (localRows (fetch s fc.redo b).unr))).getD _ [] = _
  rw [idMap_getD, if_pos]
  exact List.mem_append_left _ (List.mem_map.2 ⟨l, hl, rfl⟩)

theorem dead_line (R : Rep (layout s fc f b) s fc f b) (i : Nat) (hi : i < b.length) :
    deadIn (layout s fc f b).dmf (layout s fc f b).lines[i]!.dmf b[i].date = (locIx s fc b).memberDead b[i] := by
  obtain ⟨⟨⟨hs1, hs2⟩, -⟩, -⟩ := R.feeds i hi
  rw [deadIn_eq _ _ _ _ hs1 hs2]
  unfold Ix.memberDead
  rw [loc_dmf (List.getElem_mem hi)]

theorem pdead_line (R : Rep (layout s fc f b) s fc f b) (i : Nat) (hi : i < b.length) :
    (deadIn (layout s fc f b).pdeath (layout s fc f b).lines[i]!.pdP b[i].date ||
      deadIn (layout s fc f b).pdeath (layout s fc f b).lines[i]!.pdR b[i].date) = (locIx s fc b).providerDead b[i] := by
  obtain ⟨-, ⟨⟨hs1, hs2⟩, -⟩, ⟨⟨hs3, hs4⟩, -⟩, -⟩ := R.feeds i hi
  rw [deadIn_eq _ _ _ _ hs1 hs2, deadIn_eq _ _ _ _ hs3 hs4]
  unfold Ix.providerDead
  rw [loc_pdP (List.getElem_mem hi), loc_pdR (List.getElem_mem hi)]

theorem excl_line (R : Rep (layout s fc f b) s fc f b) (i : Nat) (hi : i < b.length) :
    (exclIn (layout s fc f b).excl (layout s fc f b).lines[i]!.exP b[i].date ||
      exclIn (layout s fc f b).excl (layout s fc f b).lines[i]!.exR b[i].date) = (locIx s fc b).excluded b[i] := by
  obtain ⟨-, -, -, ⟨⟨hs1, hs2⟩, -⟩, ⟨⟨hs3, hs4⟩, -⟩, -⟩ := R.feeds i hi
  rw [exclIn_eq _ _ _ _ hs1 hs2, exclIn_eq _ _ _ _ hs3 hs4]
  unfold Ix.excluded
  rw [loc_exP (List.getElem_mem hi), loc_exR (List.getElem_mem hi)]

theorem span_slice (R : Rep (layout s fc f b) s fc f b) (i : Nat) (hi : i < b.length) :
    (layout s fc f b).lines[i]!.span.s + (layout s fc f b).lines[i]!.span.n ≤ (layout s fc f b).spans.size ∧
    (((layout s fc f b).spans.toList.drop (layout s fc f b).lines[i]!.span.s).take (layout s fc f b).lines[i]!.span.n =
      (facts (fc.feeds.span b[i].member)).map (spanF b[i].member)) := by
  obtain ⟨-, -, -, -, -, ⟨⟨hs1, hs2⟩, -⟩⟩ := R.feeds i hi
  refine ⟨hs1, ?_⟩
  rw [hs2]; simp [facts, List.map_take]

theorem enr_line (R : Rep (layout s fc f b) s fc f b) (hb : ∀ l ∈ b, fitsLine2 l = true) (i : Nat) (hi : i < b.length) :
    enrolledIn (layout s fc f b).spans (layout s fc f b).lines[i]!.span (RowX.of b[i]) =
      (locIx s fc b).enrolled b[i] := by
  obtain ⟨h1, h2⟩ := span_slice R i hi
  rw [enrolledIn_eq _ _ _ _ (hb _ (List.getElem_mem hi)) h1 h2]
  unfold Ix.enrolled
  rw [loc_span (List.getElem_mem hi)]

theorem overlap_line (R : Rep (layout s fc f b) s fc f b) (i : Nat) (hi : i < b.length) :
    overlapIn (layout s fc f b).spans (layout s fc f b).lines[i]!.span b[i].date = (locIx s fc b).overlap b[i] := by
  obtain ⟨h1, h2⟩ := span_slice R i hi
  rw [overlapIn_eq _ _ _ _ _ h1 h2]
  unfold Ix.overlap
  rw [loc_span (List.getElem_mem hi)]


end

/-- The part of a line's mask that reads neither the batch's claims nor the unresolved set (`decideRows`' `base`). -/
def baseOf (x : Lay) (li : LineIn) : UInt32 :=
  let r := li.row
  let d := r.date.toNat
  let v := validDate d
  let enr := enrolledIn x.spans li.span r
  let ne := x.spanOk && v && !enr
  let md := deadIn x.dmf li.dmf d
  let pdd := deadIn x.pdeath li.pdP d || deadIn x.pdeath li.pdR d
  let exd := exclIn x.excl li.exP d || exclIn x.excl li.exR d
  on (x.dmfOk && v && md) bMemDead ||| on (x.dmfSome && !x.dmfOk && v && md) bMemDeadU |||
    on ne bNotEnr ||| on (x.spanSome && !x.spanOk && v && !enr) bNotEnrU |||
    on (x.pdOk && v && pdd) bProvDead ||| on (x.pdSome && !x.pdOk && v && pdd) bProvDeadU |||
    on (x.exclOk && v && exd) bExcl ||| on (x.exclSome && !x.exclOk && v && exd) bExclU |||
    on (x.today < d) bFuture ||| on (!v) bInvalid ||| on (!x.dmfOk) bStaleDmf ||| on (!x.spanOk) bStaleEnr |||
    on (!x.exclOk) bStaleExcl ||| on (!x.pdOk) bStalePd ||| on (!x.relCh) bStaleRel ||| on (!x.unrCh) bStaleUnr |||
    on (r.cap && x.spanOk && v && overlapIn x.spans li.span d) bCapMM

theorem Lo_baseOf (x : Lay) (li : LineIn) : Lo (baseOf x li) := by
  unfold baseOf
  repeat (first | apply Lo_or | apply Lo_on)

/-- What `base` carries, reason by reason: `fires` without the claims, and `CAP_MEMBER_MONTH_DUPLICATE`'s overlap term. -/
def baseF (x : Ix) (l : Line) : Reason → Bool
  | .ALREADY_DECIDED | .COLLIDES_WITH_UNRESOLVED_NEAR | .DUPLICATE_OF_UNRESOLVED | .FFS_DUPLICATE_LINE
  | .FFS_DUPLICATE_UNVERIFIED | .FFS_NEAR_DUPLICATE | .POSTING_CAP => false
  | .CAP_MEMBER_MONTH_DUPLICATE => isCap l && x.spanOk && validDate l.date && x.overlap l
  | r => x.fires ∅ l r

theorem heads_member {H : Bytes → Bytes} {S : SetIdx} {snap : Snapshot Line} (hS : IdxInv H S snap) (ks : List Key)
    {k : Key} (hk : k ∈ ks) {p : Posting} (hp : p ∈ heads (S.get k)) :
    ∃ q ∈ localRows (ks.map fun k => (k, S.get k)), q.row = p.row := by
  obtain ⟨L, hL⟩ : ∃ L, L = (ks.map fun k => (k, S.get k)).flatMap fun ke => heads ke.2 := ⟨_, rfl⟩
  have hLm : ∀ p, p ∈ L ↔ ∃ k' ∈ ks, p ∈ heads (S.get k') := by
    intro p
    rw [hL]
    simp only [List.mem_flatMap, List.mem_map]
    constructor
    · rintro ⟨ke, ⟨k', hk', rfl⟩, hp⟩; exact ⟨k', hk', hp⟩
    · rintro ⟨k', hk', hp⟩; exact ⟨(k', S.get k'), ⟨k', hk', rfl⟩, hp⟩
  have hLrow : ∀ p ∈ L, snap.entries[p.seq]? = some p.row := fun p hp => by
    obtain ⟨k', -, hp'⟩ := (hLm p).mp hp
    exact heads_row hS hp'
  have hM := List.pairwise_mergeSort (le := fun p q : Posting => decide (p.seq ≤ q.seq))
    (fun a b c h1 h2 => by simp at *; omega) (fun a b => by simp; omega) L
  have hM' : (L.mergeSort fun p q : Posting => decide (p.seq ≤ q.seq)).Pairwise (fun p q => p.seq ≤ q.seq) :=
    hM.imp (fun h => by simpa using h)
  have hMm : ∀ p, p ∈ L.mergeSort (fun p q : Posting => decide (p.seq ≤ q.seq)) ↔ p ∈ L := fun p =>
    (List.mergeSort_perm L _).mem_iff
  obtain ⟨i1, i2, i3⟩ := dedupSeq_spec _ hM'
  have hrr : localRows (ks.map fun k => (k, S.get k)) =
      dedupSeq (L.mergeSort fun p q : Posting => decide (p.seq ≤ q.seq)) := by
    unfold localRows; rw [← hL]
  rw [hrr]
  have hpL : p ∈ L := (hLm p).mpr ⟨k, hk, hp⟩
  obtain ⟨q, hq, hs⟩ := i3 p ((hMm p).mpr hpL)
  refine ⟨q, hq, ?_⟩
  have h4 := hLrow q ((hMm q).mp (i1 q hq))
  rw [hs] at h4
  exact Option.some.inj (h4.symm.trans (hLrow p hpL))

section
variable {H : Bytes → Bytes} {s : St} {fc : FCtx} {f : List Nat} {b : List Line} {rel unr : Snapshot Line}

theorem locIx_today : (locIx s fc b).today = fc.today := rfl
theorem locIx_dmfOk : (locIx s fc b).dmfOk = fc.feeds.dmfOk := rfl
theorem locIx_pdOk : (locIx s fc b).pdOk = fc.feeds.pdOk := rfl
theorem locIx_exclOk : (locIx s fc b).exclOk = fc.feeds.exclOk := rfl
theorem locIx_spanOk : (locIx s fc b).spanOk = fc.feeds.spanOk := rfl
theorem locIx_dmfSome : (locIx s fc b).dmfSome = fc.feeds.dmfSome := rfl
theorem locIx_pdSome : (locIx s fc b).pdSome = fc.feeds.pdSome := rfl
theorem locIx_exclSome : (locIx s fc b).exclSome = fc.feeds.exclSome := rfl
theorem locIx_spanSome : (locIx s fc b).spanSome = fc.feeds.spanSome := rfl
theorem locIx_relChained : (locIx s fc b).relChained = s.rel.head.chained fc.today := rfl
theorem locIx_unrChained : (locIx s fc b).unrChained = s.unr.head.chained fc.today := rfl

theorem base_has (R : Rep (layout s fc f b) s fc f b) (hb : ∀ l ∈ b, fitsLine2 l = true) (i : Nat) (hi : i < b.length)
    (r : Reason) : has (baseOf (layout s fc f b) (layout s fc f b).lines[i]!) r = baseF (locIx s fc b) b[i] r := by
  have hbi : fitsLine2 b[i] = true := hb _ (List.getElem_mem hi)
  obtain ⟨f1, f2, f3, f4, f5, f6, f7, f8⟩ := R.flags
  obtain ⟨t1, t2, t3⟩ := R.scalars
  unfold baseOf
  simp only [line_row R i hi, date_toNat hbi, enr_line R hb i hi, dead_line R i hi, pdead_line R i hi, excl_line R i hi,
    overlap_line R i hi, f1, f2, f3, f4, f5, f6, f7, f8, t1, t2, t3, Engine3.cap_of, has_or]
  cases r <;> simp [baseF, Ix.fires, Ix.notEnrolled, locIx_today, locIx_dmfOk, locIx_pdOk, locIx_exclOk, locIx_spanOk,
    locIx_dmfSome, locIx_pdSome, locIx_exclSome, locIx_spanSome, locIx_relChained, locIx_unrChained, bMemDead, bMemDeadU,
    bNotEnr, bNotEnrU, bProvDead, bProvDeadU, bExcl, bExclU, bFuture, bInvalid, bStaleDmf, bStaleEnr, bStaleExcl, bStalePd,
    bStaleRel, bStaleUnr, bCapMM, has_on, Bool.and_assoc] <;> try rfl


theorem notEnr_line (R : Rep (layout s fc f b) s fc f b) (hb : ∀ l ∈ b, fitsLine2 l = true) (i : Nat) (hi : i < b.length) :
    ((layout s fc f b).spanOk && validDate (RowX.of b[i]).date.toNat &&
      !enrolledIn (layout s fc f b).spans (layout s fc f b).lines[i]!.span (RowX.of b[i])) =
      (locIx s fc b).notEnrolled b[i] := by
  rw [enr_line R hb i hi, date_toNat (hb _ (List.getElem_mem hi)), R.flags.2.2.2.1]
  rfl

theorem fcap_line (R : Rep (layout s fc f b) s fc f b) (i : Nat) (hi : i < b.length) :
    ((layout s fc f b).lines[i]!.dmf.over || (layout s fc f b).lines[i]!.span.over || (layout s fc f b).lines[i]!.pdP.over ||
      (layout s fc f b).lines[i]!.exP.over || (layout s fc f b).lines[i]!.pdR.over || (layout s fc f b).lines[i]!.exR.over) =
      feedCapped fc.feeds b[i] := by
  obtain ⟨⟨-, a1⟩, ⟨-, a2⟩, ⟨-, a3⟩, ⟨-, a4⟩, ⟨-, a5⟩, ⟨-, a6⟩⟩ := R.feeds i hi
  rw [a1, a2, a3, a4, a5, a6]
  simp only [feedCapped, List.any_cons, List.any_nil, Bool.or_false]
  generalize feedOver (fc.feeds.dmf b[i].member) = p1
  generalize feedOver (fc.feeds.span b[i].member) = p2
  generalize feedOver (fc.feeds.pdeath b[i].payee) = p3
  generalize feedOver (fc.feeds.excl b[i].payee) = p4
  generalize feedOver (fc.feeds.pdeath b[i].rendering) = p5
  generalize feedOver (fc.feeds.excl b[i].rendering) = p6
  cases p1 <;> cases p2 <;> cases p3 <;> cases p4 <;> cases p5 <;> cases p6 <;> rfl

theorem forIn_push5 {α A B C D E : Type} (l : Array α) (a : Array A) (b : Array B) (c : Array C) (d : Array D)
    (e : Array E) (f1 : α → A) (f2 : α → B) (f3 : α → C) (f4 : α → D) (f5 : α → E) :
    forIn (m := Id) l (a, b, c, d, e) (fun p s => pure (ForInStep.yield
      (s.1.push (f1 p), s.2.1.push (f2 p), s.2.2.1.push (f3 p), s.2.2.2.1.push (f4 p), s.2.2.2.2.push (f5 p)))) =
      (a ++ (l.map f1), b ++ (l.map f2), c ++ (l.map f3), d ++ (l.map f4), e ++ (l.map f5)) := by
  rw [← Array.forIn_toList]
  obtain ⟨r, er, hr⟩ := forIn_inv l.toList (a, b, c, d, e) (fun p s => pure (ForInStep.yield
      (s.1.push (f1 p), s.2.1.push (f2 p), s.2.2.1.push (f3 p), s.2.2.2.1.push (f4 p), s.2.2.2.2.push (f5 p))))
    (fun pre st => st = (a ++ (pre.toArray.map f1), b ++ (pre.toArray.map f2), c ++ (pre.toArray.map f3),
      d ++ (pre.toArray.map f4), e ++ (pre.toArray.map f5)))
    (by simp)
    (fun pre p post st _ hp => ⟨_, rfl, by subst hp; simp⟩)
  rw [er, hr]

theorem unr_y (R : Rep (layout s fc f b) s fc f b) (hu : IdxInv H s.unr unr)
    (hw : ∀ l ∈ unr.entries, fitsLine2 l = true) (j : Nat) (hj : j < (layout s fc f b).unrP.size) :
    fitsLine2 ((layout s fc f b).unrSrc.getD j nilLine) = true ∧
    ((layout s fc f b).unrSrc.getD j nilLine).member ∈ spanIds b (localRows (fetch s fc.redo b).unr) := by
  obtain ⟨ke, hke, p, hp, hpy⟩ := R.unrHead j hj
  rw [fetch_unr'] at hke
  obtain ⟨k, hk, rfl⟩ := List.mem_map.1 hke
  refine ⟨?_, ?_⟩
  · rw [← hpy]; exact hw _ (List.mem_of_getElem? (heads_row hu hp))
  · obtain ⟨q, hq, hqp⟩ := heads_member hu (probeKeys b) hk hp
    rw [fetch_unr']
    exact List.mem_append_right _ (List.mem_map.2 ⟨q, hq, by rw [hqp, hpy]⟩)

theorem loc_span' {l : Line} (hm : l.member ∈ spanIds b (localRows (fetch s fc.redo b).unr)) :
    (locIx s fc b).span.getD l.member [] = facts (fc.feeds.span l.member) := by
  show (idMap fc.feeds.span (spanIds b (localRows (fetch s fc.redo b).unr))).getD _ [] = _
  rw [idMap_getD, if_pos hm]


def capClaimAt (x : Lay) (j : Nat) : Bool :=
  x.unrP[j]!.cap && (x.spanOk && validDate x.unrP[j]!.date.toNat && !enrolledIn x.spans x.uSpan[j]! x.unrP[j]!) &&
    !ownRow x x.uId[j]! x.unrP[j]!

theorem capClaim_at (R : Rep (layout s fc f b) s fc f b)
    (hr : IdxInv H s.rel rel) (hu : IdxInv H s.unr unr)
    (hwr : ∀ l ∈ rel.entries, fitsLine2 l = true) (hwu : ∀ l ∈ unr.entries, fitsLine2 l = true)
    (j : Nat) (hj : j < (layout s fc f b).unrP.size) :
    capClaimAt (layout s fc f b) j =
      (isCap ((layout s fc f b).unrSrc.getD j nilLine) &&
        (locIx s fc b).notEnrolled ((layout s fc f b).unrSrc.getD j nilLine) &&
        !(locIx s fc b).own ((layout s fc f b).unrSrc.getD j nilLine)) := by
  have hre := R.redoEq
  obtain ⟨hy, hmem⟩ := unr_y R hu hwu j hj
  generalize hyd : (layout s fc f b).unrSrc.getD j nilLine = y at hy hmem
  have hrow := R.unrRowX j hj
  rw [hyd] at hrow
  unfold capClaimAt
  rw [hrow, Engine3.cap_of]
  -- not enrolled
  have hne : ((layout s fc f b).spanOk && validDate (RowX.of y).date.toNat &&
      !enrolledIn (layout s fc f b).spans (layout s fc f b).uSpan[j]! (RowX.of y)) = (locIx s fc b).notEnrolled y := by
    obtain ⟨⟨hs1, hs2⟩, -⟩ := R.unrSpan j hj
    simp only [hyd] at hs1 hs2
    rw [enrolledIn_eq _ _ (facts (fc.feeds.span y.member)) y hy hs1 (by rw [hs2]; simp [facts, List.map_take]), date_toNat hy, R.flags.2.2.2.1]
    unfold Ix.notEnrolled Ix.enrolled
    rw [loc_span' hmem]
    rfl
  rw [hne]
  by_cases hc : isCap y = true
  · simp only [hc, Bool.true_and]
    congr 1
    -- own
    by_cases hred : fc.redo.contains y.pay = true
    · -- the id key is fetched
      obtain ⟨ke, hke, p, hp, hpy⟩ := R.unrHead j hj
      rw [hyd] at hpy
      rw [fetch_unr'] at hke
      obtain ⟨k, hk, rfl⟩ := List.mem_map.1 hke
      have hcov := round2_cover (redo := fc.redo) (ks := probeKeys b) (u := uEs s b) (ke := (k, s.unr.get k))
        (List.mem_map.2 ⟨k, hk, rfl⟩) hp (by rw [hpy]; exact hc) (by rw [hpy]; exact hred)
      rw [hpy] at hcov
      have hkR : idKey y ∈ ksR s fc.redo b := by
        rcases hcov with h | h
        · exact List.mem_append_left _ h
        · exact List.mem_append_right _ h
      have hin : idKey y ∈ (fetch s fc.redo b).rel.map (·.1) := by
        rw [fetch_rel', List.map_map]; exact List.mem_map.2 ⟨idKey y, hkR, rfl⟩
      obtain ⟨i, hi, hik⟩ := List.mem_iff_getElem.1 hin
      simp only [List.getElem_map, List.length_map] at hik hi
      have htot := R.unrIdTot j hj ⟨i, hi, by rw [hyd]; exact hik⟩
      have hid := R.unrId j hj htot
      rw [hyd] at hid
      obtain ⟨h3, e3⟩ := slot_of_opt hid
      unfold ownRow Ix.own
      rw [hre, Engine3.redoW_mem_iff _ _ hy, hred]
      simp only [Bool.true_and, htot, decide_true, if_true]
      rw [relSlot_any R hr hwr _ h3 _ hy]
      obtain ⟨k0, hk0, e⟩ := fetch_rel_get (s := s) (fc := fc) (b := b) _ h3
      have e1 := congrArg Prod.fst e
      have e2 := congrArg Prod.snd e
      rw [e3] at e1
      rw [relAny hr (k := idKey y) (by rw [e1]; exact hk0) (· == y), e2, e1]
      have hred2 : y.pay ∈ fc.redo := by simpa using hred
      simp [locIx, localIx, HashSet.contains_ofList, hred2]
    · have hred' : y.pay ∉ fc.redo := by simpa using hred
      unfold ownRow Ix.own
      rw [hre, Engine3.redoW_mem_iff _ _ hy]
      simp [hred', locIx, localIx, HashSet.contains_ofList]
  · have hc' : isCap y = false := by simpa using hc
    simp [hc']

end

@[reducible] def un {α : Type} (a : Id α) : α := a

theorem range_inv {β : Type} (f : Nat → β → Id (ForInStep β)) (P : Nat → β → Prop) :
    ∀ m s (init : β), P s init → (∀ k, s ≤ k → k < s + m → ∀ st, P k st → ∃ st', f k st = .yield st' ∧ P (k + 1) st') →
      ∃ r, forIn (m := Id) (List.range' s m) init f = r ∧ P (s + m) r := by
  intro m
  induction m with
  | zero => intro s init h0 _; exact ⟨init, by rw [List.range'_zero, List.forIn_nil]; rfl, by simpa using h0⟩
  | succ m ih =>
    intro s init h0 hs
    obtain ⟨st', e, h1⟩ := hs s (Nat.le_refl _) (by omega) init h0
    obtain ⟨r, er, hr⟩ := ih (s + 1) st' h1 (fun k h2 h3 => hs k (by omega) (by omega))
    refine ⟨r, ?_, by rw [show s + (m + 1) = s + 1 + m by omega]; exact hr⟩
    rw [List.range'_succ, List.forIn_cons, e]
    exact er

theorem range_push {A : Type} [Inhabited A] (n c : Nat) (g : Nat → A) (r : Array A)
    (hr : forIn (m := Id) ([:n] : Std.Legacy.Range) (Array.emptyWithCapacity c)
      (fun (j : Nat) (s : Array A) => pure (ForInStep.yield (s.push (g j)))) = r) : r.size = n ∧ ∀ j, j < n → r[j]! = g j := by
  have e : forIn (m := Id) ([:n] : Std.Legacy.Range) (Array.emptyWithCapacity c)
      (fun (j : Nat) (s : Array A) => pure (ForInStep.yield (s.push (g j)))) =
      forIn (m := Id) (List.range' 0 n) (Array.emptyWithCapacity c) (fun (j : Nat) (s : Array A) => pure (ForInStep.yield (s.push (g j)))) := by
    simp [Std.Legacy.Range.forIn_eq_forIn_range', Std.Legacy.Range.size]
  rw [e] at hr
  obtain ⟨r', e1, h1, h2⟩ := range_inv (fun (j : Nat) (s : Array A) => pure (ForInStep.yield (s.push (g j))))
    (fun k (st : Array A) => st.size = k ∧ ∀ j, j < k → st[j]! = g j) n 0 (Array.emptyWithCapacity c) (by simp)
    (fun k _ _ (st : Array A) ⟨h1, h2⟩ => ⟨st.push (g k), rfl, by
      refine ⟨by simp [h1], fun j hj => ?_⟩
      by_cases hjk : j = k
      · subst hjk
        rw [← h1]; simp
      · have hj' : j < st.size := by omega
        rw [getElem!_pos _ _ (by simp; omega), Array.getElem_push_lt hj', ← getElem!_pos st j hj']
        exact h2 j (by omega)⟩)
  rw [e1] at hr
  subst hr
  simp only [Nat.zero_add] at h1 h2
  exact ⟨h1, h2⟩

theorem scan_break (a n : Nat) (Q : Nat → Bool) (init : Bool) :
    (forIn (m := Id) ([a:a + n] : Std.Legacy.Range) init
      (fun j s => if Q j = true then pure (ForInStep.done true) else pure (ForInStep.yield s))) =
      (init || (List.range' a n).any Q) := by
  have e : forIn (m := Id) ([a:a + n] : Std.Legacy.Range) init
      (fun j s => if Q j = true then pure (ForInStep.done true) else pure (ForInStep.yield s)) =
      forIn (m := Id) (List.range' a n) init (fun j s => if Q j = true then pure (ForInStep.done true) else pure (ForInStep.yield s)) := by
    simp [Std.Legacy.Range.forIn_eq_forIn_range', Std.Legacy.Range.size]
  rw [e]
  clear e
  induction n generalizing a init with
  | zero => simp; rfl
  | succ n ih =>
    rw [List.range'_succ, List.forIn_cons, List.any_cons]
    by_cases h : Q a = true
    · simp [h]; rfl
    · simp [h]
      exact ih (a + 1) init

def scanU (ov q : Nat → Bool) (ne : Nat → Nat → Bool) (h0 : Bool) (l : List Nat) : Option Nat × Bool × Bool :=
  (l.find? q, match l.find? q with | none => true | some f => !((l.filter q).any (ne f)), h0 || l.any ov)

theorem scan_unr (a n : Nat) (ov q : Nat → Bool) (ne : Nat → Nat → Bool) (h0 : Bool)
    (hne : ∀ f ∈ List.range' a n, ne f f = false) :
    (forIn (m := Id) ([a:a + n] : Std.Legacy.Range) ((none : Option Nat), true, h0)
      (fun j (s : Option Nat × Bool × Bool) =>
        if ov j = true then
          if q j = true then
            match s.1 with
            | none => pure (ForInStep.yield (some j, s.2.1, true))
            | some f => if ne f j = true then pure (ForInStep.yield (s.1, false, true))
                else pure (ForInStep.yield (s.1, s.2.1, true))
          else pure (ForInStep.yield (s.1, s.2.1, true))
        else
          if q j = true then
            match s.1 with
            | none => pure (ForInStep.yield (some j, s.2.1, s.2.2))
            | some f => if ne f j = true then pure (ForInStep.yield (s.1, false, s.2.2))
                else pure (ForInStep.yield (s.1, s.2.1, s.2.2))
          else pure (ForInStep.yield (s.1, s.2.1, s.2.2)))) =
      scanU ov q ne h0 (List.range' a n) := by
  rw [Std.Legacy.Range.forIn_eq_forIn_range']
  simp only [Std.Legacy.Range.size, Nat.add_sub_cancel_left, Nat.div_one] 
  refine forIn_inv' (List.range' a n) ((none : Option Nat), true, h0) _ (fun pre st => st = scanU ov q ne h0 pre) (by simp [scanU]) ?_ _ rfl
  intro pre j post st hl hP
  have hjj : ne j j = false := hne j (by rw [hl]; simp)
  subst hP
  refine ⟨scanU ov q ne h0 (pre ++ [j]), ?_, rfl⟩
  unfold scanU
  rcases hf : pre.find? q with _ | f <;> by_cases hov : ov j = true <;> by_cases hq : q j = true <;>
    simp [hf, hov, hq, hjj, List.find?_append, List.filter_append, List.any_append]
  all_goals first
    | rfl
    | (have hn := List.find?_eq_none.1 hf
       have h2 : (pre.any fun a => q a && ne j a) = false := by
         simp only [List.any_eq_false]; intro x hx; simp [hn x hx]
       simp [h2]; rfl)
    | (split <;> simp_all <;> rfl)

theorem mem_modify_push (a : Array (Array Nat)) (j x k : Nat) (hk : k < a.size) (i : Nat) :
    i ∈ (a.modify j (·.push x))[k]! ↔ i ∈ a[k]! ∨ (i = x ∧ k = j) := by
  rw [arr_modify_get]
  by_cases h : k = j ∧ j < a.size
  · obtain ⟨h1, h2⟩ := h
    simp [h1, h2, Array.mem_push]
  · have h3 : ¬ k = j := fun e => h ⟨e, e ▸ hk⟩
    simp [h3]

theorem set_get_true (a : Array Bool) (j k : Nat) (hk : k < a.size) :
    (a.set! j true)[k]! = true ↔ a[k]! = true ∨ k = j := by
  simp only [Array.set!_eq_setIfInBounds, Array.getElem!_eq_getD, Array.getD_eq_getD_getElem?, Array.getElem?_setIfInBounds]
  by_cases h : j = k
  · subst h; simp [hk]
  · simp [h, Ne.symm h]

theorem loop3 (nl : Nat) (own : Array Bool) (ke kn ki : Nat → Nat) (co : Nat → Bool)
    (oa0 : Array (Array Nat)) (h0 : Array Bool) (r : Array (Array Nat) × Array Bool)
    (hr : forIn (m := Id) ([:nl] : Std.Legacy.Range) (oa0, h0) (fun i (s : Array (Array Nat) × Array Bool) =>
      if own[i]! = true then
        if co i = true then
          pure (ForInStep.yield ((((s.1.modify (ke i) fun x => x.push i).modify (kn i) fun x => x.push i).modify (ki i)
            fun x => x.push i), (((s.2.set! (ke i) true).set! (kn i) true).set! (ki i) true)))
        else pure (ForInStep.yield ((((s.1.modify (ke i) fun x => x.push i).modify (kn i) fun x => x.push i).modify (ki i)
            fun x => x.push i), s.2))
      else
        if co i = true then
          pure (ForInStep.yield (s.1, (((s.2.set! (ke i) true).set! (kn i) true).set! (ki i) true)))
        else pure (ForInStep.yield (s.1, s.2))) = r) :
    r.1.size = oa0.size ∧ r.2.size = h0.size ∧
    (∀ k, k < oa0.size → ∀ i, i ∈ r.1[k]! ↔ (i ∈ oa0[k]! ∨ (i < nl ∧ own[i]! = true ∧ (k = ke i ∨ k = kn i ∨ k = ki i)))) ∧
    (∀ k, k < h0.size → (r.2[k]! = true ↔ (h0[k]! = true ∨ ∃ i, i < nl ∧ co i = true ∧ (k = ke i ∨ k = kn i ∨ k = ki i)))) := by
  have e : forIn (m := Id) ([:nl] : Std.Legacy.Range) (oa0, h0) (fun i (s : Array (Array Nat) × Array Bool) =>
      if own[i]! = true then
        if co i = true then
          pure (ForInStep.yield ((((s.1.modify (ke i) fun x => x.push i).modify (kn i) fun x => x.push i).modify (ki i)
            fun x => x.push i), (((s.2.set! (ke i) true).set! (kn i) true).set! (ki i) true)))
        else pure (ForInStep.yield ((((s.1.modify (ke i) fun x => x.push i).modify (kn i) fun x => x.push i).modify (ki i)
            fun x => x.push i), s.2))
      else
        if co i = true then
          pure (ForInStep.yield (s.1, (((s.2.set! (ke i) true).set! (kn i) true).set! (ki i) true)))
        else pure (ForInStep.yield (s.1, s.2))) =
      forIn (m := Id) (List.range' 0 nl) (oa0, h0) (fun i (s : Array (Array Nat) × Array Bool) =>
      if own[i]! = true then
        if co i = true then
          pure (ForInStep.yield ((((s.1.modify (ke i) fun x => x.push i).modify (kn i) fun x => x.push i).modify (ki i)
            fun x => x.push i), (((s.2.set! (ke i) true).set! (kn i) true).set! (ki i) true)))
        else pure (ForInStep.yield ((((s.1.modify (ke i) fun x => x.push i).modify (kn i) fun x => x.push i).modify (ki i)
            fun x => x.push i), s.2))
      else
        if co i = true then
          pure (ForInStep.yield (s.1, (((s.2.set! (ke i) true).set! (kn i) true).set! (ki i) true)))
        else pure (ForInStep.yield (s.1, s.2))) := by
    simp [Std.Legacy.Range.forIn_eq_forIn_range', Std.Legacy.Range.size]
  rw [e] at hr
  have key := forIn_inv' (List.range' 0 nl) (oa0, h0) _
    (fun pre (st : Array (Array Nat) × Array Bool) => st.1.size = oa0.size ∧ st.2.size = h0.size ∧
      (∀ k, k < oa0.size → ∀ i, i ∈ st.1[k]! ↔ (i ∈ oa0[k]! ∨ (i ∈ pre ∧ own[i]! = true ∧ (k = ke i ∨ k = kn i ∨ k = ki i)))) ∧
      (∀ k, k < h0.size → (st.2[k]! = true ↔ (h0[k]! = true ∨ ∃ i, i ∈ pre ∧ co i = true ∧ (k = ke i ∨ k = kn i ∨ k = ki i)))))
    (by refine ⟨rfl, rfl, fun k _ i => ?_, fun k _ => ?_⟩ <;> simp) ?_ r hr
  · obtain ⟨a1, a2, a3, a4⟩ := key
    refine ⟨a1, a2, fun k hk i => ?_, fun k hk => ?_⟩
    · rw [a3 k hk i]; simp [List.mem_range']
    · rw [a4 k hk]; simp [List.mem_range']
  · intro pre j post st hl hP
    obtain ⟨s1, s2, s3, s4⟩ := hP
    have hmod : ∀ (a : Array (Array Nat)) (x : Nat) (j : Nat), (a.modify j fun y => y.push x).size = a.size := by
      intro a x j; simp
    by_cases ho : own[j]! = true <;> by_cases hc : co j = true <;>
    refine ⟨_, (by simp only [ho, hc, if_true]; rfl : _ = _), ?_⟩ <;>
    refine ⟨by simp [hmod, s1], by simp [s2], fun k hk i => ?_, fun k hk => ?_⟩
    all_goals first
      | (rw [mem_modify_push, mem_modify_push, mem_modify_push, s3 k hk i]
         <;> first | (simp only [List.mem_append, List.mem_singleton]; grind) | (simp [hmod, s1, hk]; done))
      | (rw [s3 k hk i]; simp only [List.mem_append, List.mem_singleton]; grind)
      | (rw [set_get_true, set_get_true, set_get_true, s4 k hk]
         <;> first | (simp only [List.mem_append, List.mem_singleton]; grind) | (simp [s2, hk]; done))
      | (rw [s4 k hk]; simp only [List.mem_append, List.mem_singleton]; grind)

section
variable {H : Bytes → Bytes} {s : St} {fc : FCtx} {f : List Nat} {b : List Line} {rel unr : Snapshot Line}

theorem unr_same_refl (R : Rep (layout s fc f b) s fc f b) (hu : IdxInv H s.unr unr)
    (hwu : ∀ l ∈ unr.entries, fitsLine2 l = true) (g : Nat) (hg : g < (layout s fc f b).unrP.size) :
    (!(layout s fc f b).unrP[g]!.same (layout s fc f b).unrP[g]!) = false := by
  obtain ⟨hy, -⟩ := unr_y R hu hwu g hg
  rw [R.unrRowX g hg, (Engine3.rowX_same_iff _ _ hy hy).2 rfl]
  rfl

theorem slot_unr_bnd (R : Rep (layout s fc f b) s fc f b) (k : Nat) (hk : k < (layout s fc f b).slots.size)
    (g : Nat) (hg : g ∈ List.range' (layout s fc f b).slots[k]!.us (layout s fc f b).slots[k]!.un) :
    g < (layout s fc f b).unrP.size := by
  have hk' : k < (fetch s fc.redo b).rel.length := by rw [← R.nslots]; exact hk
  rw [List.mem_range'_1] at hg
  have := R.unrBnd k hk' (by omega)
  omega

end


theorem idbind {α β : Type} (a : Id α) (f : α → Id β) : bind a f = f a := rfl

theorem set_get (a : Array Bool) (j : Nat) (v : Bool) (k : Nat) :
    (a.set! j v)[k]! = if k = j ∧ j < a.size then v else a[k]! := by
  simp only [Array.set!_eq_setIfInBounds, Array.getElem!_eq_getD, Array.getD_eq_getD_getElem?, Array.getElem?_setIfInBounds]
  by_cases h : j = k
  · subst h
    by_cases h2 : j < a.size
    · simp [h2]
    · simp [h2]
  · simp [h, Ne.symm h]

/-- One slot of the pass that finds `seen0`, the first claimer, whether all claimers are one line, and `hot`. -/
def step4 (np : Nat) (kind rs rn rc us un : Nat → Nat) (oaAny : Nat → Nat → Bool) (ov cc : Nat → Bool)
    (ne : Nat → Nat → Bool) (k : Nat) (s : Array Bool × Bool × Array Bool × Array Nat × Array Bool) :
    Id (ForInStep (Array Bool × Bool × Array Bool × Array Nat × Array Bool)) :=
  if (kind k == 4 && decide (capN < rc k)) = true then
    do
    let s1 ← forIn (m := Id) ([rs k:rs k + rn k] : Std.Legacy.Range) false (fun j (s : Bool) =>
      if (!oaAny k j) = true then pure (ForInStep.done true) else pure (ForInStep.yield s))
    let s2 ← forIn (m := Id) ([us k:us k + un k] : Std.Legacy.Range) ((none : Option Nat), true, s.1[k]!)
      (fun j (s : Option Nat × Bool × Bool) =>
        if ov j = true then
          if (!(kind k == 0 || kind k == 2) || !cc j) = true then
            match s.1 with
            | none => pure (ForInStep.yield (some j, s.2.1, true))
            | some f => if ne f j = true then pure (ForInStep.yield (s.1, false, true))
                else pure (ForInStep.yield (s.1, s.2.1, true))
          else pure (ForInStep.yield (s.1, s.2.1, true))
        else
          if (!(kind k == 0 || kind k == 2) || !cc j) = true then
            match s.1 with
            | none => pure (ForInStep.yield (some j, s.2.1, s.2.2))
            | some f => if ne f j = true then pure (ForInStep.yield (s.1, false, s.2.2))
                else pure (ForInStep.yield (s.1, s.2.1, s.2.2))
          else pure (ForInStep.yield (s.1, s.2.1, s.2.2)))
    pure (ForInStep.yield (s.1.set! k s2.2.2, true, s.2.2.1.push s1, s.2.2.2.1.push (s2.1.getD np),
      s.2.2.2.2.push s2.2.1))
  else
    do
    let s1 ← forIn (m := Id) ([rs k:rs k + rn k] : Std.Legacy.Range) false (fun j (s : Bool) =>
      if (!oaAny k j) = true then pure (ForInStep.done true) else pure (ForInStep.yield s))
    let s2 ← forIn (m := Id) ([us k:us k + un k] : Std.Legacy.Range) ((none : Option Nat), true, s.1[k]!)
      (fun j (s : Option Nat × Bool × Bool) =>
        if ov j = true then
          if (!(kind k == 0 || kind k == 2) || !cc j) = true then
            match s.1 with
            | none => pure (ForInStep.yield (some j, s.2.1, true))
            | some f => if ne f j = true then pure (ForInStep.yield (s.1, false, true))
                else pure (ForInStep.yield (s.1, s.2.1, true))
          else pure (ForInStep.yield (s.1, s.2.1, true))
        else
          if (!(kind k == 0 || kind k == 2) || !cc j) = true then
            match s.1 with
            | none => pure (ForInStep.yield (some j, s.2.1, s.2.2))
            | some f => if ne f j = true then pure (ForInStep.yield (s.1, false, s.2.2))
                else pure (ForInStep.yield (s.1, s.2.1, s.2.2))
          else pure (ForInStep.yield (s.1, s.2.1, s.2.2)))
    pure (ForInStep.yield (s.1.set! k s2.2.2, s.2.1, s.2.2.1.push s1, s.2.2.2.1.push (s2.1.getD np),
      s.2.2.2.2.push s2.2.1))

def qOf (kind : Nat → Nat) (cc : Nat → Bool) (k j : Nat) : Bool := (!(kind k == 0 || kind k == 2) || !cc j)

theorem loop4 (np : Nat) (kind rs rn rc us un : Nat → Nat) (oaAny : Nat → Nat → Bool) (ov cc : Nat → Bool)
    (ne : Nat → Nat → Bool) (ns : Nat) (hot0 : Array Bool) (hh : hot0.size = ns)
    (hne : ∀ k, k < ns → ∀ g ∈ List.range' (us k) (un k), ne g g = false)
    (r : Array Bool × Bool × Array Bool × Array Nat × Array Bool)
    (hr : forIn (m := Id) ([:ns] : Std.Legacy.Range) (hot0, false, Array.emptyWithCapacity ns, Array.emptyWithCapacity ns,
      Array.emptyWithCapacity ns) (step4 np kind rs rn rc us un oaAny ov cc ne) = r) :
    r.1.size = ns ∧ r.2.2.1.size = ns ∧ r.2.2.2.1.size = ns ∧ r.2.2.2.2.size = ns ∧
    r.2.1 = (List.range' 0 ns).any (fun k => kind k == 4 && decide (capN < rc k)) ∧
    ∀ k, k < ns →
      r.2.2.1[k]! = (List.range' (rs k) (rn k)).any (fun j => !oaAny k j) ∧
      r.2.2.2.1[k]! = (scanU ov (qOf kind cc k) ne false (List.range' (us k) (un k))).1.getD np ∧
      r.2.2.2.2[k]! = (scanU ov (qOf kind cc k) ne false (List.range' (us k) (un k))).2.1 ∧
      r.1[k]! = (hot0[k]! || (List.range' (us k) (un k)).any ov) := by
  have e : forIn (m := Id) ([:ns] : Std.Legacy.Range) (hot0, false, Array.emptyWithCapacity ns, Array.emptyWithCapacity ns,
      Array.emptyWithCapacity ns) (step4 np kind rs rn rc us un oaAny ov cc ne) =
      forIn (m := Id) (List.range' 0 ns) (hot0, false, Array.emptyWithCapacity ns, Array.emptyWithCapacity ns,
      Array.emptyWithCapacity ns) (step4 np kind rs rn rc us un oaAny ov cc ne) := by
    simp [Std.Legacy.Range.forIn_eq_forIn_range', Std.Legacy.Range.size]
  rw [e] at hr
  have this := range_inv (step4 np kind rs rn rc us un oaAny ov cc ne)
    (fun k (st : Array Bool × Bool × Array Bool × Array Nat × Array Bool) =>
      st.1.size = ns ∧ st.2.2.1.size = k ∧ st.2.2.2.1.size = k ∧ st.2.2.2.2.size = k ∧
      st.2.1 = (List.range' 0 k).any (fun k => kind k == 4 && decide (capN < rc k)) ∧
      (∀ k', k' < k →
        st.2.2.1[k']! = (List.range' (rs k') (rn k')).any (fun j => !oaAny k' j) ∧
        st.2.2.2.1[k']! = (scanU ov (qOf kind cc k') ne false (List.range' (us k') (un k'))).1.getD np ∧
        st.2.2.2.2[k']! = (scanU ov (qOf kind cc k') ne false (List.range' (us k') (un k'))).2.1) ∧
      (∀ k', k' < ns → st.1[k']! = if k' < k then (hot0[k']! || (List.range' (us k') (un k')).any ov) else hot0[k']!))
    ns 0 (hot0, false, Array.emptyWithCapacity ns, Array.emptyWithCapacity ns, Array.emptyWithCapacity ns)
    (by simp [hh]) (by
      intro k _ hk st hP
      obtain ⟨a1, a2, a3, a4, a5, a6, a7⟩ := hP
      have hhk : k < st.1.size := by omega
      refine ⟨(st.1.set! k (scanU ov (qOf kind cc k) ne st.1[k]! (List.range' (us k) (un k))).2.2,
        if (kind k == 4 && decide (capN < rc k)) = true then true else st.2.1,
        st.2.2.1.push (false || (List.range' (rs k) (rn k)).any fun j => !oaAny k j),
        st.2.2.2.1.push ((scanU ov (qOf kind cc k) ne false (List.range' (us k) (un k))).1.getD np),
        st.2.2.2.2.push (scanU ov (qOf kind cc k) ne false (List.range' (us k) (un k))).2.1), ?_, ?_⟩
      · by_cases hc : (kind k == 4 && decide (capN < rc k)) = true
        · simp only [step4, hc, if_true, idbind]
          generalize hs1 : (forIn ([rs k:rs k + rn k] : Std.Legacy.Range) _ _ : Id _) = s1
          generalize hs2 : (forIn ([us k:us k + un k] : Std.Legacy.Range) _ _ : Id _) = s2
          have e1 : s1 = (false || (List.range' (rs k) (rn k)).any fun j => !oaAny k j) := by
            rw [← hs1]; exact scan_break _ _ _ _
          have e2 : s2 = scanU ov (qOf kind cc k) ne st.1[k]! (List.range' (us k) (un k)) := by
            rw [← hs2]; exact scan_unr _ _ ov (qOf kind cc k) ne _ (hne k (by omega))
          subst e1 e2
          rfl
        · simp only [step4, hc, idbind]
          generalize hs1 : (forIn ([rs k:rs k + rn k] : Std.Legacy.Range) _ _ : Id _) = s1
          generalize hs2 : (forIn ([us k:us k + un k] : Std.Legacy.Range) _ _ : Id _) = s2
          have e1 : s1 = (false || (List.range' (rs k) (rn k)).any fun j => !oaAny k j) := by
            rw [← hs1]; exact scan_break _ _ _ _
          have e2 : s2 = scanU ov (qOf kind cc k) ne st.1[k]! (List.range' (us k) (un k)) := by
            rw [← hs2]; exact scan_unr _ _ ov (qOf kind cc k) ne _ (hne k (by omega))
          subst e1 e2
          first | rfl | (rw [if_neg hc]; rfl)
      · refine ⟨by simp [a1], by simp [a2], by simp [a3], by simp [a4], ?_, ?_, ?_⟩
        · rw [List.range'_concat, List.any_append]
          by_cases hc : (kind k == 4 && decide (capN < rc k)) = true
          · simp [hc]
          · simp [hc, a5]
        · intro k' hk'
          by_cases hkk : k' < k
          · obtain ⟨b1, b2, b3⟩ := a6 k' hkk
            rw [arr_push_get, arr_push_get, arr_push_get]
            simp only [a2, a3, a4, hkk, if_true]
            exact ⟨b1, b2, b3⟩
          · have hk2 : k' = k := by omega
            subst hk2
            rw [arr_push_get, arr_push_get, arr_push_get]
            simp only [a2, a3, a4, Nat.lt_irrefl, if_false, if_true]
            simp
        · intro k' hk'
          rw [set_get]
          have hk7 := a7 k' hk'
          by_cases hkk : k' = k
          · subst hkk
            simp only [hhk, and_self, if_true, hk7, Nat.lt_irrefl, if_false]
            simp [scanU]
          · simp only [hkk, false_and, if_false]
            rw [a7 k' hk']
            by_cases h3 : k' < k
            · simp [h3, show k' < k + 1 by omega]
            · simp [h3, show ¬ k' < k + 1 by omega]) 
  obtain ⟨r', e1, hP⟩ := this
  rw [e1] at hr
  subst hr
  obtain ⟨p1, p2, p3, p4, p5, p6, p7⟩ := hP
  simp only [Nat.zero_add] at p2 p3 p4 p5 p6 p7
  refine ⟨p1, p2, p3, p4, p5, fun k hk => ⟨(p6 k hk).1, (p6 k hk).2.1, (p6 k hk).2.2, ?_⟩⟩
  have := p7 k hk
  simpa [hk] using this


theorem arr_any_iff {α : Type} (a : Array α) (p : α → Bool) : a.any p = true ↔ ∃ x ∈ a, p x = true :=
  Array.any_eq_true'

theorem range_getD {α : Type} (a : Array α) (d : α) (s n : Nat) (xs : List α)
    (h : (a.toList.drop s).take n = xs) (hn : xs.length = n) :
    (List.range' s n).map (fun j => a.getD j d) = xs := by
  subst h
  apply List.ext_getElem (by simp [hn])
  intro i h1 h2
  have h3 : i < n := by simpa using h1
  have hlen : n ≤ a.size - s := by
    have := hn
    simp at this
    omega
  have h4 : s + i < a.size := by omega
  simp only [List.getElem_map, List.getElem_range', List.getElem_take, List.getElem_drop, Array.getD_eq_getD_getElem?,
    Nat.one_mul]
  simp [Array.getElem?_eq_getElem h4]

section
variable {H : Bytes → Bytes} {s : St} {fc : FCtx} {f : List Nat} {b : List Line} {rel unr : Snapshot Line}

theorem slot_key_eq {a a' : Nat} {K : Key}
    (ha : (fetch s fc.redo b).rel[a]?.map (·.1) = some K)
    (ha' : (fetch s fc.redo b).rel[a']?.map (·.1) = some K) : a = a' := by
  obtain ⟨h1, e1⟩ := slot_of_opt ha
  obtain ⟨h2, e2⟩ := slot_of_opt ha'
  exact (List.getElem_inj (rel_keys_nodup s fc.redo b) (i := a) (j := a') (h₀ := by simpa using h1)
    (h₁ := by simpa using h2)).1 (by simp [e1, e2])

theorem heads_key {S : SetIdx} {snap : Snapshot Line} (hS : IdxInv H S snap) {k : Key} {p : Posting}
    (hp : p ∈ heads (S.get k)) : k ∈ keys p.row := by
  have h := (entryOf_count H snap.entries k).2
  rw [hS.2 k] at hp
  unfold heads at hp
  rw [h] at hp
  simp only [List.take_take, Nat.min_self] at hp
  obtain ⟨j, h1, h2, h3⟩ := (mem_postingsFrom _ 0 p).mp (List.mem_of_mem_take hp)
  exact h3

theorem seen0_link (R : Rep (layout s fc f b) s fc f b) (hr : IdxInv H s.rel rel)
    (hwr : ∀ l ∈ rel.entries, fitsLine2 l = true) (hb : ∀ l ∈ b, fitsLine2 l = true)
    (own : Array Bool) (hown : ∀ i (hi : i < b.length), own[i]! = (locIx s fc b).own b[i])
    (k : Nat) (hk : k < (fetch s fc.redo b).rel.length) (oa : Array Nat)
    (hoa : ∀ i, i ∈ oa ↔ (i < b.length ∧ own[i]! = true ∧ (k = (layout s fc f b).lines[i]!.ke ∨
      k = (layout s fc f b).lines[i]!.kn ∨ k = (layout s fc f b).lines[i]!.ki))) :
    (List.range' (layout s fc f b).slots[k]!.rs (layout s fc f b).slots[k]!.rn).any
      (fun j => !(oa.any fun i => (layout s fc f b).lines[i]!.row.same (layout s fc f b).relP[j]!)) =
    (locIx s fc b).seen0 (fetch s fc.redo b).rel[k].1 := by
  obtain ⟨K, hK, e⟩ := fetch_rel_get (s := s) (fc := fc) (b := b) k hk
  have e1 : (fetch s fc.redo b).rel[k].1 = K := congrArg Prod.fst e
  have e2 : (fetch s fc.redo b).rel[k].2 = s.rel.get K := congrArg Prod.snd e
  rw [e1]
  unfold Ix.seen0
  rw [relAny hr hK (fun y => !((locIx s fc b).own y && (locIx s fc b).batch.contains y))]
  obtain ⟨-, -, -, hrp, -, -⟩ := R.relSlot k hk
  obtain ⟨hbd, -⟩ := R.relBnd k hk
  rw [any_range'_get (layout s fc f b).relP _ _ hbd
    (fun y => !(oa.any fun i => (layout s fc f b).lines[i]!.row.same y)), hrp, e2]
  simp only [List.any_map]
  refine any_congr' _ _ _ (fun p hp => ?_)
  have hy := heads_fit hr hp hwr
  have hKy : K ∈ keys p.row := heads_key hr hp
  dsimp only [Function.comp]
  congr 1
  rw [Bool.eq_iff_iff, arr_any_iff]
  simp only [Bool.and_eq_true]
  have hbt : (locIx s fc b).batch.contains p.row = b.contains p.row := by
    simp [locIx, localIx, HashSet.contains_ofList]
  rw [hbt, List.contains_iff_mem]
  constructor
  · rintro ⟨i, hi, hs⟩
    obtain ⟨hib, hown_i, -⟩ := (hoa i).1 hi
    have hbi : fitsLine2 b[i] = true := hb _ (List.getElem_mem hib)
    rw [line_row R i hib] at hs
    have := (Engine3.rowX_same_iff _ _ hbi hy).1 hs
    refine ⟨?_, ?_⟩
    · rw [← this, ← hown i hib]; exact hown_i
    · rw [← this]; exact List.getElem_mem hib
  · rintro ⟨hown', hmem⟩
    obtain ⟨i, hib, hi⟩ := List.mem_iff_getElem.1 hmem
    have hbi : fitsLine2 b[i] = true := hb _ (List.getElem_mem hib)
    refine ⟨i, (hoa i).2 ⟨hib, ?_, ?_⟩, ?_⟩
    · rw [hown i hib, hi]; exact hown'
    · obtain ⟨a1, a2, a3⟩ := R.lineKeys i hib
      have hk' : (fetch s fc.redo b).rel[k]?.map (·.1) = some K := by
        simp [List.getElem?_eq_getElem hk, e1]
      rw [← hi] at hKy
      simp only [keys, List.mem_cons, List.not_mem_nil, or_false] at hKy
      rcases hKy with h | h | h
      · exact Or.inl (slot_key_eq hk' (h ▸ a1))
      · exact Or.inr (Or.inl (slot_key_eq hk' (h ▸ a2)))
      · exact Or.inr (Or.inr (slot_key_eq hk' (h ▸ a3)))
    · rw [line_row R i hib]
      exact (Engine3.rowX_same_iff _ _ hbi hy).2 hi


theorem claim_contains_iff (x : Ix) (y : Line) (K : Key) (hK : K ∈ keys y) :
    (x.claim y).contains K = (!(K.headD 9 == 0 || K.headD 9 == 2) || !(isCap y && x.notEnrolled y && !x.own y)) := by
  simp only [keys, List.mem_cons, List.not_mem_nil, or_false] at hK
  unfold Ix.claim
  by_cases hc : (isCap y && x.notEnrolled y && !x.own y) = true
  · rw [if_pos hc]
    simp only [Bool.and_eq_true, Bool.not_eq_true'] at hc
    obtain ⟨⟨hcp, hne⟩, hno⟩ := hc
    rcases hK with rfl | rfl | rfl <;> simp [exactKey, nearKey, idKey, hcp, hne, hno]
  · rw [if_neg hc]
    have : (!(isCap y && x.notEnrolled y && !x.own y)) = true := by
      generalize (isCap y && x.notEnrolled y && !x.own y) = c at hc ⊢
      cases c <;> simp_all
    rw [this, Bool.or_true]
    simp only [keys, List.contains_iff_mem, List.mem_cons, List.not_mem_nil, or_false]
    rcases hK with h | h | h <;> simp [h]

theorem pend_core (l : List Nat) (np : Nat) (hl : ∀ j ∈ l, j < np) (q ov : Nat → Bool) (ne : Nat → Nat → Bool)
    (byp : Bool) (y : Nat → Line) (lr : Line) (same : Nat → Bool)
    (hne : ∀ g ∈ l, ∀ j ∈ l, ne g j = true ↔ y g ≠ y j)
    (hsame : ∀ j ∈ l, same j = true ↔ y j = lr) :
    (decide ((scanU ov q ne false l).1.getD np < np) &&
      (!byp || !((scanU ov q ne false l).2.1 && same ((scanU ov q ne false l).1.getD np)))) =
    l.any (fun j => q j && (!byp || decide (y j ≠ lr))) := by
  unfold scanU
  simp only []
  rcases hf : l.find? q with _ | f0
  · have hn := List.find?_eq_none.1 hf
    have : l.any (fun j => q j && (!byp || decide (y j ≠ lr))) = false := by
      rw [List.any_eq_false]; intro j hj; simp [Bool.eq_false_iff.mpr (hn j hj)]
    rw [this]
    simp
  · have hf0 : f0 ∈ l := List.mem_of_find?_eq_some hf
    have hq0 : q f0 = true := List.find?_some hf
    have hlt : f0 < np := hl f0 hf0
    simp only [Option.getD_some, hlt, decide_true, Bool.true_and]
    cases byp
    · have : l.any (fun j => q j && (!false || decide (y j ≠ lr))) = true :=
        List.any_eq_true.2 ⟨f0, hf0, by simp [hq0]⟩
      rw [this]; simp
    · rw [Bool.eq_iff_iff]
      simp only [Bool.not_true, Bool.false_or, Bool.not_and, Bool.not_not, Bool.or_eq_true,
        List.any_eq_true, List.mem_filter, Bool.and_eq_true, decide_eq_true_eq, Bool.not_eq_eq_eq_not]
      constructor
      · rintro (⟨j, ⟨hj, hqj⟩, hnj⟩ | hs)
        · have hnj' := (hne f0 hf0 j hj).1 hnj
          by_cases hyj : y j = lr
          · refine ⟨f0, hf0, hq0, ?_⟩
            intro h; apply hnj'; rw [h, hyj]
          · exact ⟨j, hj, hqj, hyj⟩
        · refine ⟨f0, hf0, hq0, fun h => ?_⟩
          have := (hsame f0 hf0).2 h
          simp [this] at hs
      · rintro ⟨j, hj, hqj, hyj⟩
        by_cases hy : y f0 = y j
        · right
          cases hs : same f0
          · rfl
          · exact absurd (hy ▸ (hsame f0 hf0).1 hs) hyj
        · left
          exact ⟨j, ⟨hj, hqj⟩, (hne f0 hf0 j hj).2 hy⟩


theorem pend_link (R : Rep (layout s fc f b) s fc f b) (hu : IdxInv H s.unr unr)
    (hwu : ∀ l ∈ unr.entries, fitsLine2 l = true) (cc : Array Bool)
    (hcc : ∀ j (_ : j < (layout s fc f b).unrP.size), cc[j]! =
      (isCap ((layout s fc f b).unrSrc.getD j nilLine) &&
        (locIx s fc b).notEnrolled ((layout s fc f b).unrSrc.getD j nilLine) &&
        !(locIx s fc b).own ((layout s fc f b).unrSrc.getD j nilLine)))
    (k : Nat) (hk : k < (fetch s fc.redo b).rel.length) (hkp : (fetch s fc.redo b).rel[k].1 ∈ probeKeys b)
    (l : Line) (hl : fitsLine2 l = true) :
    let sc := scanU (fun j => (layout s fc f b).unrP[j]!.cap && (layout s fc f b).uSpan[j]!.over)
      (qOf (fun k => (layout s fc f b).slots[k]!.kind) (fun j => cc[j]!) k)
      (fun g j => !(layout s fc f b).unrP[g]!.same (layout s fc f b).unrP[j]!) false
      (List.range' (layout s fc f b).slots[k]!.us (layout s fc f b).slots[k]!.un)
    (decide (sc.1.getD (layout s fc f b).unrP.size < (layout s fc f b).unrP.size) &&
      (!(fc.byp.lookup l.pay).isSome ||
        !(sc.2.1 && (layout s fc f b).unrP[sc.1.getD (layout s fc f b).unrP.size]!.same (RowX.of l)))) =
    (locIx s fc b).pending l (fetch s fc.redo b).rel[k].1 := by
  intro sc
  have hkslots : k < (layout s fc f b).slots.size := by rw [R.nslots]; exact hk
  have hl' : (fetch s fc.redo b).unr.lookup (fetch s fc.redo b).rel[k].1 =
      some (s.unr.get (fetch s fc.redo b).rel[k].1) :=
    lookup_map (g := fun k => s.unr.get k) (ks := probeKeys b) hkp
  have h := R.unrSlot k hk
  simp only [hl'] at h
  obtain ⟨-, hn, -, -, h3⟩ := h
  have hkind := (R.relSlot k hk).1
  obtain ⟨K, hK, e⟩ := fetch_rel_get (s := s) (fc := fc) (b := b) k hk
  have e1 : (fetch s fc.redo b).rel[k].1 = K := congrArg Prod.fst e
  rw [e1] at hkp hn h3 hkind ⊢
  have hbound : ∀ g ∈ List.range' (layout s fc f b).slots[k]!.us (layout s fc f b).slots[k]!.un,
      g < (layout s fc f b).unrP.size := fun g hg => slot_unr_bnd R k hkslots g hg
  have hrow : ∀ g, g < (layout s fc f b).unrP.size →
      (layout s fc f b).unrP[g]! = RowX.of ((layout s fc f b).unrSrc.getD g nilLine) := fun g hg => R.unrRowX g hg
  refine (pend_core (List.range' (layout s fc f b).slots[k]!.us (layout s fc f b).slots[k]!.un)
    (layout s fc f b).unrP.size hbound (qOf (fun k => (layout s fc f b).slots[k]!.kind) (fun j => cc[j]!) k)
    (fun j => (layout s fc f b).unrP[j]!.cap && (layout s fc f b).uSpan[j]!.over)
    (fun g j => !(layout s fc f b).unrP[g]!.same (layout s fc f b).unrP[j]!) (fc.byp.lookup l.pay).isSome
    (fun j => (layout s fc f b).unrSrc.getD j nilLine) l
    (fun j => (layout s fc f b).unrP[j]!.same (RowX.of l)) ?_ ?_).trans ?_
  · intro g hg j hj
    obtain ⟨hyg, -⟩ := unr_y R hu hwu g (hbound g hg)
    obtain ⟨hyj, -⟩ := unr_y R hu hwu j (hbound j hj)
    simp only [hrow g (hbound g hg), hrow j (hbound j hj), Bool.not_eq_true']
    rw [← Bool.not_eq_true, Engine3.rowX_same_iff _ _ hyg hyj]
  · intro j hj
    obtain ⟨hyj, -⟩ := unr_y R hu hwu j (hbound j hj)
    simp only [hrow j (hbound j hj)]
    exact Engine3.rowX_same_iff _ _ hyj hl
  · unfold Ix.pending
    rw [unrAny hu hkp (fun y => ((locIx s fc b).claim y).contains K &&
      !(y == l && ((locIx s fc b).byp.lookup l.pay).isSome))]
    have hmap := range_getD (layout s fc f b).unrSrc nilLine (layout s fc f b).slots[k]!.us
      (layout s fc f b).slots[k]!.un ((heads (s.unr.get K)).map (·.row)) h3 (by simp [hn])
    have hbyp : (locIx s fc b).byp = fc.byp := rfl
    rw [hbyp]
    calc (List.range' (layout s fc f b).slots[k]!.us (layout s fc f b).slots[k]!.un).any
          (fun j => qOf (fun k => (layout s fc f b).slots[k]!.kind) (fun j => cc[j]!) k j &&
            (!(fc.byp.lookup l.pay).isSome || decide ((layout s fc f b).unrSrc.getD j nilLine ≠ l)))
        = (List.range' (layout s fc f b).slots[k]!.us (layout s fc f b).slots[k]!.un).any
          (fun j => (fun yy : Line => (!(K.headD 9 == 0 || K.headD 9 == 2) ||
              !(isCap yy && (locIx s fc b).notEnrolled yy && !(locIx s fc b).own yy)) &&
            (!(fc.byp.lookup l.pay).isSome || decide (yy ≠ l))) ((layout s fc f b).unrSrc.getD j nilLine)) := by
          refine any_congr' _ _ _ (fun j hj => ?_)
          simp only [qOf, hkind, hcc j (hbound j hj)]
      _ = ((List.range' (layout s fc f b).slots[k]!.us (layout s fc f b).slots[k]!.un).map
          (fun j => (layout s fc f b).unrSrc.getD j nilLine)).any
          (fun yy : Line => (!(K.headD 9 == 0 || K.headD 9 == 2) ||
              !(isCap yy && (locIx s fc b).notEnrolled yy && !(locIx s fc b).own yy)) &&
            (!(fc.byp.lookup l.pay).isSome || decide (yy ≠ l))) := by rw [List.any_map]; rfl
      _ = _ := by
          rw [hmap, List.any_map]
          refine any_congr' _ _ _ (fun p hp => ?_)
          simp only [Function.comp, claim_contains_iff (locIx s fc b) p.row K (heads_key hu hp)]
          cases hb : (fc.byp.lookup l.pay).isSome <;> simp <;> rfl

end

section
variable {H : Bytes → Bytes} {s : St} {fc : FCtx} {f : List Nat} {b : List Line} {rel unr : Snapshot Line}

theorem key_head_eq (K : Key) : (K.head? == some 4) = (K.headD 9 == 4) := by
  cases K <;> simp

/-- An id key has no core: its count is its own. -/
theorem capCount_id {C : Key → Nat} {k : Key} {e : Entry} (h : k.headD 9 = 4) : capCount C k e = e.count := by
  obtain _ | ⟨a, t⟩ := k
  · simp at h
  · simp only [List.headD_cons] at h
    subst h
    have : keyCore (4 :: t) = none := by unfold keyCore; split <;> simp_all
    simp [capCount, this]

theorem ic_link (R : Rep (layout s fc f b) s fc f b) :
    (List.range' 0 (layout s fc f b).slots.size).any
      (fun k => (layout s fc f b).slots[k]!.kind == 4 && decide (capN < (layout s fc f b).slots[k]!.rc)) =
    idCapped (fetch s fc.redo b) := by
  rw [R.nslots]
  have key : ∀ j (hj : j < (fetch s fc.redo b).rel.length),
      ((layout s fc f b).slots[j]!.kind == 4 && decide (capN < (layout s fc f b).slots[j]!.rc)) =
      ((fetch s fc.redo b).rel[j].1.head? == some 4 && decide (capN < (fetch s fc.redo b).rel[j].2.count)) := by
    intro j hj
    obtain ⟨h1, h2, -⟩ := R.relSlot j hj
    rw [h1, h2, key_head_eq]
    cases h : ((fetch s fc.redo b).rel[j].1.headD 9 == 4)
    · rfl
    · rw [capCount_id (beq_iff_eq.1 h)]
  apply Bool.eq_iff_iff.mpr
  unfold idCapped
  rw [List.any_eq_true, List.any_eq_true]
  constructor
  · rintro ⟨j, hj, hk⟩
    have hj' := List.mem_range'_1.1 hj
    have hj2 : j < (fetch s fc.redo b).rel.length := by omega
    refine ⟨(fetch s fc.redo b).rel[j], List.getElem_mem hj2, ?_⟩
    rw [key j hj2] at hk
    exact hk
  · rintro ⟨e, he, hk⟩
    obtain ⟨j, hj2, rfl⟩ := List.mem_iff_getElem.1 he
    refine ⟨j, List.mem_range'_1.2 ⟨Nat.zero_le _, by omega⟩, ?_⟩
    rw [key j hj2]
    exact hk

theorem mem_of_lookup : ∀ {l : List (Key × Entry)} {K : Key} {e : Entry}, l.lookup K = some e → (K, e) ∈ l := by
  intro l K e h
  obtain ⟨l₁, l₂, rfl, -⟩ := List.lookup_eq_some_iff.1 h
  simp

theorem unr_lookup_of_mem {K : Key} {e : Entry} (h : (K, e) ∈ (fetch s fc.redo b).unr) :
    (fetch s fc.redo b).unr.lookup K = some e := by
  rw [fetch_unr'] at h ⊢
  unfold uEs at h ⊢
  obtain ⟨k', hk', e'⟩ := List.mem_map.1 h
  simp only [Prod.mk.injEq] at e'
  obtain ⟨rfl, rfl⟩ := e'
  exact lookup_map hk'

theorem unr_slot_none (R : Rep (layout s fc f b) s fc f b) {k : Nat} (hk : k < (fetch s fc.redo b).rel.length)
    (he : (fetch s fc.redo b).unr.lookup (fetch s fc.redo b).rel[k].1 = none) :
    (layout s fc f b).slots[k]!.un = 0 ∧ (layout s fc f b).slots[k]!.uc = 0 := by
  have U := R.unrSlot k hk
  dsimp only at U
  rw [he] at U
  exact U

theorem unr_slot_some (R : Rep (layout s fc f b) s fc f b) {k : Nat} (hk : k < (fetch s fc.redo b).rel.length)
    {e : Entry} (he : (fetch s fc.redo b).unr.lookup (fetch s fc.redo b).rel[k].1 = some e) :
    (layout s fc f b).slots[k]!.uc = capCount (fetch s fc.redo b).unrCore (fetch s fc.redo b).rel[k].1 e ∧
    (∀ j ∈ List.range' (layout s fc f b).slots[k]!.us (layout s fc f b).slots[k]!.un,
      ∃ p ∈ heads e, p.row = (layout s fc f b).unrSrc.getD j nilLine) ∧
    (∀ p ∈ heads e, ∃ j ∈ List.range' (layout s fc f b).slots[k]!.us (layout s fc f b).slots[k]!.un,
      (layout s fc f b).unrSrc.getD j nilLine = p.row) := by
  have U := R.unrSlot k hk
  dsimp only at U
  rw [he] at U
  obtain ⟨h1, h2, -, -, h5⟩ := U
  have hr := range_getD (layout s fc f b).unrSrc nilLine _ _ _ h5 (by simp [h2])
  refine ⟨h1, fun j hj => ?_, fun p hp => ?_⟩
  · have : (layout s fc f b).unrSrc.getD j nilLine ∈ (heads e).map (·.row) := by
      rw [← hr]; exact List.mem_map.2 ⟨j, hj, rfl⟩
    obtain ⟨p, hp, hpe⟩ := List.mem_map.1 this
    exact ⟨p, hp, hpe⟩
  · have : p.row ∈ (List.range' (layout s fc f b).slots[k]!.us (layout s fc f b).slots[k]!.un).map
        (fun j => (layout s fc f b).unrSrc.getD j nilLine) := by
      rw [hr]; exact List.mem_map.2 ⟨p, hp, rfl⟩
    obtain ⟨j, hj, hje⟩ := List.mem_map.1 this
    exact ⟨j, hj, hje⟩

theorem line_cap (R : Rep (layout s fc f b) s fc f b) (i : Nat) (hi : i < b.length) :
    ((layout s fc f b).lines[i]!.row.cap && (layout s fc f b).lines[i]!.span.over) =
      (isCap b[i] && feedOver (fc.feeds.span b[i].member)) := by
  have h := (R.feeds i hi).2.2.2.2.2.2
  rw [line_row R i hi, Engine3.cap_of, h]

theorem ov_eq (R : Rep (layout s fc f b) s fc f b) (j : Nat) (hj : j < (layout s fc f b).unrP.size) :
    ((layout s fc f b).unrP[j]!.cap && (layout s fc f b).uSpan[j]!.over) =
      (isCap ((layout s fc f b).unrSrc.getD j nilLine) &&
        feedOver (fc.feeds.span ((layout s fc f b).unrSrc.getD j nilLine).member)) := by
  rw [R.unrRowX j hj, Engine3.cap_of, (R.unrSpan j hj).2]

theorem hot_link (R : Rep (layout s fc f b) s fc f b) {k : Nat} (hk : k < (fetch s fc.redo b).rel.length) :
    (((capN < (layout s fc f b).slots[k]!.rc || capN < (layout s fc f b).slots[k]!.uc) = true ∨
      (∃ i, i < b.length ∧ ((layout s fc f b).lines[i]!.row.cap && (layout s fc f b).lines[i]!.span.over) = true ∧
        (k = (layout s fc f b).lines[i]!.ke ∨ k = (layout s fc f b).lines[i]!.kn ∨ k = (layout s fc f b).lines[i]!.ki))) ∨
      (List.range' (layout s fc f b).slots[k]!.us (layout s fc f b).slots[k]!.un).any
        (fun j => (layout s fc f b).unrP[j]!.cap && (layout s fc f b).uSpan[j]!.over) = true) ↔
    (hotKeys (fetch s fc.redo b) fc.feeds b).contains (fetch s fc.redo b).rel[k].1 = true := by
  unfold hotKeys
  rw [HashSet.contains_ofList]
  simp only [List.contains_iff_mem, List.mem_append, List.mem_map, List.mem_filter, List.mem_flatMap,
    List.any_eq_true, decide_eq_true_eq, Bool.and_eq_true]
  have hkS : k < (layout s fc f b).slots.size := by rw [R.nslots]; exact hk
  have hKk : (fetch s fc.redo b).rel[k]?.map (·.1) = some (fetch s fc.redo b).rel[k].1 := by
    simp [List.getElem?_eq_getElem hk]
  have hrel : ∀ a ∈ (fetch s fc.redo b).rel, a.1 = (fetch s fc.redo b).rel[k].1 → a = (fetch s fc.redo b).rel[k] := by
    intro a ha hak
    obtain ⟨j, hj, rfl⟩ := List.mem_iff_getElem.1 ha
    have := (List.getElem_inj (rel_keys_nodup s fc.redo b) (i := j) (j := k) (h₀ := by simpa using hj)
      (h₁ := by simpa using hk)).1 (by simpa using hak)
    subst this; rfl
  have hulk : ∀ a ∈ (fetch s fc.redo b).unr, a.1 = (fetch s fc.redo b).rel[k].1 →
      (fetch s fc.redo b).unr.lookup (fetch s fc.redo b).rel[k].1 = some a.2 := by
    intro a ha hak
    rw [← hak]
    exact unr_lookup_of_mem ha
  have hlk : ∀ i (hi : i < b.length), ∀ K', (K' = exactKey b[i] ∨ K' = nearKey b[i] ∨ K' = idKey b[i]) →
      (fetch s fc.redo b).rel[k].1 = K' →
      (k = (layout s fc f b).lines[i]!.ke ∨ k = (layout s fc f b).lines[i]!.kn ∨ k = (layout s fc f b).lines[i]!.ki) := by
    intro i hi K' hK' hkK
    obtain ⟨l1, l2, l3⟩ := R.lineKeys i hi
    rcases hK' with rfl | rfl | rfl
    · exact Or.inl (slot_key_eq (by rw [hKk, hkK]) l1)
    · exact Or.inr (Or.inl (slot_key_eq (by rw [hKk, hkK]) l2))
    · exact Or.inr (Or.inr (slot_key_eq (by rw [hKk, hkK]) l3))
  obtain ⟨hs1, hs2, -⟩ := R.relSlot k hk
  constructor
  · rintro ((h | ⟨i, hi, ⟨hc, ho⟩, hkk⟩) | ⟨j, hj, hc, ho⟩)
    · rcases Bool.or_eq_true_iff.1 h with h1 | h1
      · left; left; left
        exact ⟨_, ⟨List.getElem_mem hk, by rw [hs2] at h1; simpa using h1⟩, rfl⟩
      · left; left; right
        rcases hl : (fetch s fc.redo b).unr.lookup (fetch s fc.redo b).rel[k].1 with _ | e
        · have := (unr_slot_none R hk hl).2
          simp [this] at h1
        · obtain ⟨u1, -, -⟩ := unr_slot_some R hk hl
          exact ⟨_, ⟨mem_of_lookup hl, by rw [u1] at h1; simpa using h1⟩, rfl⟩
    · right
      have hcc := line_cap R i hi
      rw [hc, ho] at hcc
      refine ⟨b[i], ⟨List.getElem_mem hi, ?_⟩, ?_⟩
      · simpa using hcc.symm
      · obtain ⟨l1, l2, l3⟩ := R.lineKeys i hi
        simp only [keys, List.mem_cons, List.not_mem_nil, or_false]
        rcases hkk with rfl | rfl | rfl
        · left; have := slot_of_opt l1; rw [← this.2]
        · right; left; have := slot_of_opt l2; rw [← this.2]
        · right; right; have := slot_of_opt l3; rw [← this.2]
    · left; right
      rcases hl : (fetch s fc.redo b).unr.lookup (fetch s fc.redo b).rel[k].1 with _ | e
      · have := (unr_slot_none R hk hl).1
        rw [this] at hj; simp at hj
      · obtain ⟨-, u2, -⟩ := unr_slot_some R hk hl
        obtain ⟨p, hp, hpe⟩ := u2 j hj
        have hjb := slot_unr_bnd R k hkS j hj
        have hov := ov_eq R j hjb
        rw [hc, ho, ← hpe] at hov
        have hov' := hov.symm
        simp at hov'
        exact ⟨_, ⟨mem_of_lookup hl, p, hp, hov'.1, hov'.2⟩, rfl⟩
  · rintro (((⟨a, ⟨hm, hcn⟩, hak⟩ | ⟨a, ⟨hm, hcn⟩, hak⟩) | ⟨a, ⟨hm, p, hp, hc, ho⟩, hak⟩) | ⟨m, ⟨hm, hc, ho⟩, hkm⟩)
    · have := hrel a hm hak
      subst this
      left; left
      rw [hs2]
      simp only [Bool.or_eq_true, decide_eq_true_eq]; exact Or.inl hcn
    · have hl := hulk a hm hak
      obtain ⟨u1, -, -⟩ := unr_slot_some R hk hl
      left; left
      rw [u1, ← hak]
      simp only [Bool.or_eq_true, decide_eq_true_eq]; exact Or.inr hcn
    · have hl := hulk a hm hak
      obtain ⟨-, -, u3⟩ := unr_slot_some R hk hl
      obtain ⟨j, hj, hje⟩ := u3 p hp
      have hjb := slot_unr_bnd R k hkS j hj
      have hov := ov_eq R j hjb
      rw [hje, hc, ho] at hov
      right
      refine ⟨j, hj, ?_⟩
      simpa using hov
    · obtain ⟨i, hi, rfl⟩ := List.mem_iff_getElem.1 hm
      left; right
      have hcc := line_cap R i hi
      simp only [keys, List.mem_cons, List.not_mem_nil, or_false] at hkm
      refine ⟨i, hi, ?_, hlk i hi _ hkm rfl⟩
      have h2 : ((layout s fc f b).lines[i]!.row.cap && (layout s fc f b).lines[i]!.span.over) = true := by
        rw [hcc]; simp [hc, ho]
      simpa using h2

end

/-- The keys a decision order has claimed after `L`, from `S`. -/
def foldS (x : Ix) (S : HashSet Key) (L : List Line) : HashSet Key := L.foldl (fun S y => S.insertMany (x.claim y)) S

theorem decideAll_snoc (x : Ix) : ∀ (L : List Line) (S : HashSet Key) (l : Line),
    x.decideAll S (L ++ [l]) = x.decideAll S L ++ [x.decideLine (foldS x S L) l]
  | [], S, l => by simp [Ix.decideAll, foldS]
  | y :: t, S, l => by
    simp only [List.cons_append, Ix.decideAll, foldS, List.foldl_cons, List.cons.injEq, true_and]
    exact decideAll_snoc x t _ l


theorem mask_has (x : Ix) (S : HashSet Key) (l : Line) (base : UInt32) (sE sN sI pE pN pI cp c : Bool)
    (hb : ∀ r, has base r = baseF x l r) (h1 : sE = x.seen S (exactKey l)) (h2 : sN = x.seen S (nearKey l))
    (h3 : sI = x.seen S (idKey l)) (h4 : pE = x.pending l (exactKey l)) (h5 : pN = x.pending l (nearKey l))
    (h6 : pI = x.pending l (idKey l)) (hc : c = isCap l) (hl : x.looseKeys.contains (exactKey l) = false) (r : Reason) :
    has (if cp = true then (base ||| on (sI || pI) bAlready ||| on (c && (sE || sN)) bCapMM |||
      on (!c && pN && !pE) bCollides ||| on (pE || c && pN) bDupUnr ||| on (!c && sE) bFfsDup |||
      on (!c && sN && !sE) bFfsNear) ||| bCap else (base ||| on (sI || pI) bAlready ||| on (c && (sE || sN)) bCapMM |||
      on (!c && pN && !pE) bCollides ||| on (pE || c && pN) bDupUnr ||| on (!c && sE) bFfsDup |||
      on (!c && sN && !sE) bFfsNear)) r = (x.fires S l r || cp && decide (r = .POSTING_CAP)) := by
  have hbr := hb r
  have hseen : ∀ k, x.seen S k = (S.contains k || x.seen0 k) := fun k => rfl
  cases cp <;> cases r <;>
  simp only [Bool.false_eq_true, if_false, if_true, has_or, bAlready, bCapMM, bCollides, bDupUnr, bFfsDup, bFfsNear, bCap, has_on, has_bit, hbr, baseF, Ix.fires, ← h1, ← h2, ← h3, ← h4,
    ← h5, ← h6, ← hc, hl, Bool.false_and, Bool.true_and, Bool.or_false, Bool.and_false] <;> (try simp) <;> (try grind)

section
variable {H : Bytes → Bytes} {s : St} {fc : FCtx} {f : List Nat} {b : List Line} {rel unr : Snapshot Line}

theorem ord_link (R : Rep (layout s fc f b) s fc f b) (hbf : ∀ l ∈ b, fitsLine2 l = true) (ownA : Array Bool)
    (q : Line → Bool) (hq : ∀ i (hi : i < b.length), ownA[i]! = q b[i]) (nl : Nat) (hnl : nl = b.length) :
    (((((Array.range nl).filter (ownA[·]!)).qsort fun i j => (layout s fc f b).lines[i]!.row.lt (layout s fc f b).lines[j]!.row) ++
      (((Array.range nl).filter (!ownA[·]!)).qsort fun i j => (layout s fc f b).lines[i]!.row.lt (layout s fc f b).lines[j]!.row)).toList.map
        (b.getD · nilLine)) = canonical (b.filter q) ++ canonical (b.filter fun y => !q y) ∧
    ∀ x ∈ ((((Array.range nl).filter (ownA[·]!)).qsort fun i j => (layout s fc f b).lines[i]!.row.lt (layout s fc f b).lines[j]!.row) ++
      (((Array.range nl).filter (!ownA[·]!)).qsort fun i j => (layout s fc f b).lines[i]!.row.lt (layout s fc f b).lines[j]!.row)).toList,
      x < b.length := by
  subst hnl
  have hgd : ∀ i (h : i < b.length), b.getD i nilLine = b[i] := fun i h => by
    simp [List.getD_eq_getElem?_getD, h]
  have hl : ∀ i j, i < b.length → j < b.length →
      (layout s fc f b).lines[i]!.row.lt (layout s fc f b).lines[j]!.row =
        (RowX.of (b.getD i nilLine)).lt (RowX.of (b.getD j nilLine)) := by
    intro i j hi hj
    rw [line_row R i hi, line_row R j hj, hgd i hi, hgd j hj]
  obtain ⟨e1, m1⟩ := qsort_canonical b hbf (ownA[·]!) q (fun i hi => by rw [hgd i hi]; exact hq i hi)
    (fun i j => (layout s fc f b).lines[i]!.row.lt (layout s fc f b).lines[j]!.row) hl
  obtain ⟨e2, m2⟩ := qsort_canonical b hbf (!ownA[·]!) (fun y => !q y)
    (fun i hi => by rw [hgd i hi]; simp [hq i hi])
    (fun i j => (layout s fc f b).lines[i]!.row.lt (layout s fc f b).lines[j]!.row) hl
  refine ⟨?_, ?_⟩
  · rw [Array.toList_append, List.map_append, e1, e2]
  · intro x hx
    rw [Array.toList_append, List.mem_append] at hx
    rcases hx with hx | hx
    · exact m1 x (Array.mem_toList_iff.1 hx)
    · exact m2 x (Array.mem_toList_iff.1 hx)

end

/-- The batch's own claims so far, as the slot flags read them: for each key of a line, the slot of that key holds
    whether the claims contain it. -/
def SnInv (s : St) (fc : FCtx) (b : List Line) (sn : Array Bool) (S : HashSet Key) : Prop :=
  ∀ i (hi : i < b.length), ∀ K ∈ keys b[i], ∀ a : Nat, (fetch s fc.redo b).rel[a]?.map (·.1) = some K →
    sn[a]! = S.contains K

section
variable {H : Bytes → Bytes} {s : St} {fc : FCtx} {f : List Nat} {b : List Line} {rel unr : Snapshot Line}

theorem slot_lt {a : Nat} {K : Key} (h : (fetch s fc.redo b).rel[a]?.map (·.1) = some K) :
    a < (fetch s fc.redo b).rel.length := (slot_of_opt h).1

theorem set_get_or (a : Array Bool) (j k : Nat) (hj : j < a.size) : (a.set! j true)[k]! = (decide (k = j) || a[k]!) := by
  rw [set_get]; by_cases h : k = j <;> simp [h, hj]

theorem snInv_step (R : Rep (layout s fc f b) s fc f b) (sn : Array Bool) (hsz : sn.size = (layout s fc f b).slots.size)
    (S : HashSet Key) (hI : SnInv s fc b sn S) (j : Nat) (hj : j < b.length) (cond : Bool)
    (hcond : cond = !(isCap b[j] && (locIx s fc b).notEnrolled b[j] && !(locIx s fc b).own b[j])) :
    SnInv s fc b (if cond = true then ((sn.set! (layout s fc f b).lines[j]!.ke true).set! (layout s fc f b).lines[j]!.ki true).set!
        (layout s fc f b).lines[j]!.kn true else (sn.set! (layout s fc f b).lines[j]!.ke true).set! (layout s fc f b).lines[j]!.ki true)
      (S.insertMany ((locIx s fc b).claim b[j])) := by
  obtain ⟨l1, l2, l3⟩ := R.lineKeys j hj
  have hke := slot_lt l1
  have hkn := slot_lt l2
  have hki := slot_lt l3
  rw [← R.nslots] at hke hkn hki
  intro i hi K hK a ha
  have hak := slot_lt ha
  rw [← R.nslots] at hak
  rw [HashSet.contains_insertMany_list]
  have hI' := hI i hi K hK a ha
  -- slot of the claimed key equals `a` exactly when the keys agree
  have iff_ke : a = (layout s fc f b).lines[j]!.ke ↔ K = exactKey b[j] := by
    constructor
    · rintro rfl
      have := slot_of_opt l1; have h2 := slot_of_opt ha
      rw [← this.2, ← h2.2]
    · rintro rfl; exact slot_key_eq ha l1
  have iff_kn : a = (layout s fc f b).lines[j]!.kn ↔ K = nearKey b[j] := by
    constructor
    · rintro rfl
      have := slot_of_opt l2; have h2 := slot_of_opt ha
      rw [← this.2, ← h2.2]
    · rintro rfl; exact slot_key_eq ha l2
  have iff_ki : a = (layout s fc f b).lines[j]!.ki ↔ K = idKey b[j] := by
    constructor
    · rintro rfl
      have := slot_of_opt l3; have h2 := slot_of_opt ha
      rw [← this.2, ← h2.2]
    · rintro rfl; exact slot_key_eq ha l3
  have hsz1 : (sn.set! (layout s fc f b).lines[j]!.ke true).size = sn.size := by simp [Array.set!_eq_setIfInBounds]
  have hsz2 : ((sn.set! (layout s fc f b).lines[j]!.ke true).set! (layout s fc f b).lines[j]!.ki true).size = sn.size := by
    simp [Array.set!_eq_setIfInBounds]
  have bke : (exactKey b[j] == K) = decide (a = (layout s fc f b).lines[j]!.ke) :=
    Bool.eq_iff_iff.2 (by rw [beq_iff_eq, decide_eq_true_eq, iff_ke]; exact eq_comm)
  have bke' : (K == exactKey b[j]) = decide (a = (layout s fc f b).lines[j]!.ke) :=
    Bool.eq_iff_iff.2 (by rw [beq_iff_eq, decide_eq_true_eq, iff_ke])
  have bkn : (nearKey b[j] == K) = decide (a = (layout s fc f b).lines[j]!.kn) :=
    Bool.eq_iff_iff.2 (by rw [beq_iff_eq, decide_eq_true_eq, iff_kn]; exact eq_comm)
  have bkn' : (K == nearKey b[j]) = decide (a = (layout s fc f b).lines[j]!.kn) :=
    Bool.eq_iff_iff.2 (by rw [beq_iff_eq, decide_eq_true_eq, iff_kn])
  have bki : (idKey b[j] == K) = decide (a = (layout s fc f b).lines[j]!.ki) :=
    Bool.eq_iff_iff.2 (by rw [beq_iff_eq, decide_eq_true_eq, iff_ki]; exact eq_comm)
  have bki' : (K == idKey b[j]) = decide (a = (layout s fc f b).lines[j]!.ki) :=
    Bool.eq_iff_iff.2 (by rw [beq_iff_eq, decide_eq_true_eq, iff_ki])
  by_cases hc : cond = true
  · have hn : (isCap b[j] && (locIx s fc b).notEnrolled b[j] && !(locIx s fc b).own b[j]) = false := by
      rw [hc] at hcond
      generalize (isCap b[j] && (locIx s fc b).notEnrolled b[j] && !(locIx s fc b).own b[j]) = P at hcond ⊢
      cases P <;> first | rfl | exact absurd hcond (by decide)
    have hcl : (locIx s fc b).claim b[j] = keys b[j] := by simp [Ix.claim, hn]
    rw [if_pos hc, set_get_or _ _ _ (by omega), set_get_or _ _ _ (by omega), set_get_or _ _ _ (by omega), hI', hcl]
    simp only [keys, List.contains_cons, List.contains_nil, bke, bkn, bki, bke', bkn', bki']
    cases S.contains K <;> cases decide (a = (layout s fc f b).lines[j]!.ke) <;>
      cases decide (a = (layout s fc f b).lines[j]!.kn) <;> cases decide (a = (layout s fc f b).lines[j]!.ki) <;> rfl
  · have hc' : cond = false := by simpa using hc
    have hn : (isCap b[j] && (locIx s fc b).notEnrolled b[j] && !(locIx s fc b).own b[j]) = true := by
      rw [hc'] at hcond
      generalize (isCap b[j] && (locIx s fc b).notEnrolled b[j] && !(locIx s fc b).own b[j]) = P at hcond ⊢
      cases P <;> first | rfl | exact absurd hcond (by decide)
    have hcl : (locIx s fc b).claim b[j] = [exactKey b[j], idKey b[j]] := by simp [Ix.claim, hn]
    rw [if_neg hc, set_get_or _ _ _ (by omega), set_get_or _ _ _ (by omega), hI', hcl]
    simp only [List.contains_cons, List.contains_nil, bke, bki, bke', bki']
    cases S.contains K <;> cases decide (a = (layout s fc f b).lines[j]!.ke) <;>
      cases decide (a = (layout s fc f b).lines[j]!.ki) <;> rfl


theorem idseen_key {l : Line} {K : Key} (hK : K ∈ keys l) (h : (idSeen f).contains K = true) : K = idKey l := by
  simp only [keys, List.mem_cons, List.not_mem_nil, or_false] at hK
  simp only [idSeen, List.contains_iff_mem, List.mem_map] at h
  obtain ⟨n, _, rfl⟩ := h
  rcases hK with h | h | h
  · simp [exactKey] at h
  · simp only [nearKey] at h; split at h <;> simp at h
  · exact h

theorem sn0_inv (R : Rep (layout s fc f b) s fc f b) (hnl : (layout s fc f b).lines.size = b.length) (r5 : Array Bool)
    (hr5 : (forIn (m := Id) (layout s fc f b).lines (Array.replicate (layout s fc f b).slots.size false) fun li st =>
      if li.fseen = true then pure (ForInStep.yield (st.set! li.ki true)) else pure (ForInStep.yield st)) = r5) :
    SnInv s fc b r5 (HashSet.ofList (idSeen f)) ∧ r5.size = (layout s fc f b).slots.size := by
  rw [← Array.forIn_toList] at hr5
  have hP := forIn_inv' (layout s fc f b).lines.toList (Array.replicate (layout s fc f b).slots.size false)
    (fun li st => if li.fseen = true then pure (ForInStep.yield (st.set! li.ki true)) else pure (ForInStep.yield st))
    (fun pre st => st.size = (layout s fc f b).slots.size ∧ ∀ a, a < (layout s fc f b).slots.size →
      (st[a]! = true ↔ ∃ li ∈ pre, li.fseen = true ∧ li.ki = a))
    ⟨by simp, fun a ha => by simp [Array.getD_eq_getD_getElem?, ha]⟩
    (by
      intro pre li post st _ ⟨hsz, hst⟩
      by_cases hf : li.fseen = true
      · refine ⟨st.set! li.ki true, by rw [if_pos hf]; rfl, ?_, fun a ha => ?_⟩
        · simp [Array.set!_eq_setIfInBounds, hsz]
        · rw [set_get_true _ _ _ (by rw [hsz]; exact ha), hst a ha]
          constructor
          · rintro (⟨x, hx, h1, h2⟩ | rfl)
            · exact ⟨x, List.mem_append_left _ hx, h1, h2⟩
            · exact ⟨li, by simp, hf, rfl⟩
          · rintro ⟨x, hx, h1, h2⟩
            rcases List.mem_append.1 hx with hx | hx
            · exact Or.inl ⟨x, hx, h1, h2⟩
            · rw [List.mem_singleton] at hx; subst hx; exact Or.inr h2.symm
      · refine ⟨st, by rw [if_neg hf]; rfl, hsz, fun a ha => ?_⟩
        rw [hst a ha]
        constructor
        · rintro ⟨x, hx, h1, h2⟩; exact ⟨x, List.mem_append_left _ hx, h1, h2⟩
        · rintro ⟨x, hx, h1, h2⟩
          rcases List.mem_append.1 hx with hx | hx
          · exact ⟨x, hx, h1, h2⟩
          · rw [List.mem_singleton] at hx; subst hx; exact absurd h1 hf)
    r5 hr5
  obtain ⟨hsz, hst⟩ := hP
  refine ⟨?_, hsz⟩
  intro i hi K hK a ha
  have hak := slot_lt ha
  rw [← R.nslots] at hak
  rw [HashSet.contains_ofList]
  obtain ⟨l1, l2, l3⟩ := R.lineKeys i hi
  refine Bool.eq_iff_iff.2 ?_
  rw [hst a hak]
  constructor
  · rintro ⟨li, hli, hfs, hki⟩
    obtain ⟨i', hi', rfl⟩ := List.mem_iff_getElem.1 hli
    have hi'' : i' < (layout s fc f b).lines.size := by simpa using hi'
    have hib : i' < b.length := by omega
    have hli : (layout s fc f b).lines.toList[i'] = (layout s fc f b).lines[i']! := by
      rw [Array.getElem_toList]; exact (getElem!_pos (layout s fc f b).lines i' hi'').symm
    rw [hli] at hfs hki
    have h1 := R.fseen i' hib
    rw [hfs] at h1
    have h2 := (R.lineKeys i' hib).2.2
    rw [hki, ha] at h2
    have h3 : K = idKey b[i'] := Option.some.inj h2
    rw [h3]; exact h1.symm
  · intro h
    have hK' := idseen_key hK h
    have hiL : i < (layout s fc f b).lines.size := by omega
    refine ⟨(layout s fc f b).lines[i]!, ?_, ?_, ?_⟩
    · rw [getElem!_pos (layout s fc f b).lines i hiL]; exact Array.mem_toList_iff.2 (Array.getElem_mem hiL)
    · rw [R.fseen i hi, ← hK']; exact h
    · rw [hK'] at ha
      exact (slot_key_eq ha l3).symm
end


set_option hygiene false in
local macro "unroll_dr" : tactic => `(tactic| (
  unfold decideRows
  dsimp only
  generalize hr1 : (forIn (layout s fc f b).lines _ _ : Id _) = r1
  rw [idbind]
  generalize hr2 : (forIn ([:(layout s fc f b).unrP.size] : Std.Legacy.Range) _ _ : Id _) = r2
  rw [idbind]
  generalize hr3 : (forIn ([:(layout s fc f b).lines.size] : Std.Legacy.Range) _ _ : Id _) = r3
  rw [idbind]
  generalize hr4 : (forIn ([:(layout s fc f b).slots.size] : Std.Legacy.Range) _ _ : Id _) = r4
  rw [idbind]
  generalize hr5 : (forIn (layout s fc f b).lines _ _ : Id _) = r5
  rw [idbind]
  generalize hr6 : (forIn (_ : Array Nat) _ _ : Id _) = r6
  rw [idbind]
  generalize hr7 : (forIn (_ : Array Dec) _ _ : Id _) = r7
  rw [idbind]
  generalize hr8 : (forIn (_ : Array Dec) _ _ : Id _) = r8
  rw [idbind]))

/-- The mask of a line before the cap bit, from the keys claimed and pending so far. -/
def mask0 (x : Lay) (base : Array UInt32) (sn seen0 : Array Bool) (cfirst : Array Nat) (csame : Array Bool) (i : Nat) :
    UInt32 :=
  base[i]! |||
    on (seenAt sn seen0 x.lines[i]!.ki || pendAt x cfirst csame x.pByp[x.lines[i]!.pay]!.isSome x.lines[i]!.row x.lines[i]!.ki)
      bAlready |||
    on (x.lines[i]!.row.cap && (seenAt sn seen0 x.lines[i]!.ke || seenAt sn seen0 x.lines[i]!.kn)) bCapMM |||
    on (!x.lines[i]!.row.cap && pendAt x cfirst csame x.pByp[x.lines[i]!.pay]!.isSome x.lines[i]!.row x.lines[i]!.kn &&
      !pendAt x cfirst csame x.pByp[x.lines[i]!.pay]!.isSome x.lines[i]!.row x.lines[i]!.ke) bCollides |||
    on (pendAt x cfirst csame x.pByp[x.lines[i]!.pay]!.isSome x.lines[i]!.row x.lines[i]!.ke ||
      x.lines[i]!.row.cap && pendAt x cfirst csame x.pByp[x.lines[i]!.pay]!.isSome x.lines[i]!.row x.lines[i]!.kn) bDupUnr |||
    on (!x.lines[i]!.row.cap && seenAt sn seen0 x.lines[i]!.ke) bFfsDup |||
    on (!x.lines[i]!.row.cap && seenAt sn seen0 x.lines[i]!.kn && !seenAt sn seen0 x.lines[i]!.ke) bFfsNear

/-- The first counterpart of a line: the earliest released row on a key of the line, else the earliest unresolved row
    whose claim meets the line's keys. -/
def cpOf (x : Lay) (capClaim : Array Bool) (i : Nat) : Nat :=
  if (relC x x.lines[i]!.ki (relC x x.lines[i]!.kn (relC x x.lines[i]!.ke (0, 0)))).1 != 0 then
    (relC x x.lines[i]!.ki (relC x x.lines[i]!.kn (relC x x.lines[i]!.ke (0, 0)))).1
  else (unrC x capClaim x.lines[i]!.row x.lines[i]!.ki (unrC x capClaim x.lines[i]!.row x.lines[i]!.kn
    (unrC x capClaim x.lines[i]!.row x.lines[i]!.ke (0, 0)))).1

/-- The mask of a line with the cap bit when the line is capped. -/
def maskC (x : Lay) (base : Array UInt32) (fcap hot : Array Bool) (ic : Bool) (sn seen0 : Array Bool) (cfirst : Array Nat)
    (csame : Array Bool) (i : Nat) : UInt32 :=
  if (ic || hot[x.lines[i]!.ke]! || hot[x.lines[i]!.kn]! || hot[x.lines[i]!.ki]! || fcap[i]!) = true then
    mask0 x base sn seen0 cfirst csame i ||| bCap
  else mask0 x base sn seen0 cfirst csame i

/-- One element of `decideRows`' decision-order loop, as a function. -/
def stepG (x : Lay) (own held notEnr : Array Bool) (base : Array UInt32) (fcap hot : Array Bool) (ic : Bool)
    (seen0 : Array Bool) (cfirst : Array Nat) (csame capClaim : Array Bool) (i : Nat)
    (s : Array Bool × Array Dec × Array Bool × Array Bool × Array Bool × Array Bool) :
    Array Bool × Array Dec × Array Bool × Array Bool × Array Bool × Array Bool :=
  let li := x.lines[i]!
  let r := li.row
  let byp := x.pByp[li.pay]!
  let bp := byp.isSome
  let c := r.cap
  let m := maskC x base fcap hot ic s.1 seen0 cfirst csame i
  let cp := cpOf x capClaim i
  let o := outOf m
  let sn := s.1.set! li.ke true |>.set! li.ki true
  let sn := if !(c && notEnr[i]! && !own[i]!) then sn.set! li.kn true else sn
  let p := li.pay
  let pHold := if o == 1 then s.2.2.1.set! p true else s.2.2.1
  let pAllow := if !(o == 0 && (!x.pRedo[p]! || own[i]!)) then s.2.2.2.1.set! p false else s.2.2.2.1
  let pHeld := if held[i]! then s.2.2.2.2.1.set! p true else s.2.2.2.2.1
  let pByp := match byp with
    | some bm => if m &&& ~~~(bypM &&& bm) != 0 then s.2.2.2.2.2.set! p false else s.2.2.2.2.2
    | none => s.2.2.2.2.2
  (sn, s.2.1.push ⟨i, m, o, cp⟩, pHold, pAllow, pHeld, pByp)

/-- A decision of the fixed-row decider against the reference decision it stands for. -/
def DecOK (L : Lay) (d : Dec) (rd : Decision) : Prop :=
  L.src.getD d.line nilLine = rd.line ∧ outcomeOf8 d.out = rd.outcome ∧ rd.reasons = reasons.filter (has d.mask ·) ∧
    cpId L d.cp = rd.counterparts.head? ∧ Lo d.mask ∧ d.out = outOf d.mask

section
variable {H : Bytes → Bytes} {s : St} {fc : FCtx} {f : List Nat} {b : List Line} {rel unr : Snapshot Line}

theorem Lo_mask0 (x : Lay) (base : Array UInt32) (sn seen0 : Array Bool) (cfirst : Array Nat) (csame : Array Bool) (i : Nat)
    (h : Lo base[i]!) : Lo (mask0 x base sn seen0 cfirst csame i) :=
  Lo_or (Lo_or (Lo_or (Lo_or (Lo_or (Lo_or h (Lo_on _ .ALREADY_DECIDED)) (Lo_on _ .CAP_MEMBER_MONTH_DUPLICATE))
    (Lo_on _ .COLLIDES_WITH_UNRESOLVED_NEAR)) (Lo_on _ .DUPLICATE_OF_UNRESOLVED)) (Lo_on _ .FFS_DUPLICATE_LINE))
    (Lo_on _ .FFS_NEAR_DUPLICATE)

theorem Lo_maskC (x : Lay) (base : Array UInt32) (fcap hot : Array Bool) (ic : Bool) (sn seen0 : Array Bool)
    (cfirst : Array Nat) (csame : Array Bool) (i : Nat) (h : Lo base[i]!) :
    Lo (maskC x base fcap hot ic sn seen0 cfirst csame i) := by
  unfold maskC
  split
  · exact Lo_or (Lo_mask0 x base sn seen0 cfirst csame i h) (Lo_bit .POSTING_CAP)
  · exact Lo_mask0 x base sn seen0 cfirst csame i h

theorem line_dec (R : Rep (layout s fc f b) s fc f b) (hbf : ∀ l ∈ b, fitsLine2 l = true) (i : Nat) (hi : i < b.length)
    (S : HashSet Key) (sn seen0 hot fcap csame capClaim : Array Bool) (ic : Bool) (cfirst : Array Nat) (base : Array UInt32)
    (hS : SnInv s fc b sn S)
    (hb : ∀ r, has base[i]! r = baseF (locIx s fc b) b[i] r) (hLo : Lo base[i]!)
    (h0 : ∀ k (hk : k < (fetch s fc.redo b).rel.length), seen0[k]! = (locIx s fc b).seen0 (fetch s fc.redo b).rel[k].1)
    (hp : ∀ k (hk : k < (fetch s fc.redo b).rel.length), (fetch s fc.redo b).rel[k].1 ∈ probeKeys b →
      ∀ l : Line, fitsLine2 l = true → ∀ bp, bp = (fc.byp.lookup l.pay).isSome →
        pendAt (layout s fc f b) cfirst csame bp (RowX.of l) k = (locIx s fc b).pending l (fetch s fc.redo b).rel[k].1)
    (hh : ∀ k (hk : k < (fetch s fc.redo b).rel.length),
      hot[k]! = (hotKeys (fetch s fc.redo b) fc.feeds b).contains (fetch s fc.redo b).rel[k].1)
    (hic : ic = idCapped (fetch s fc.redo b)) (hfc : fcap[i]! = feedCapped fc.feeds b[i])
    (hcp : cpId (layout s fc f b) (cpOf (layout s fc f b) capClaim i) = ((locIx s fc b).counterparts b[i]).head?) :
    DecOK (layout s fc f b)
      ⟨i, maskC (layout s fc f b) base fcap hot ic sn seen0 cfirst csame i,
        outOf (maskC (layout s fc f b) base fcap hot ic sn seen0 cfirst csame i), cpOf (layout s fc f b) capClaim i⟩
      (if cappedWith (idCapped (fetch s fc.redo b)) (hotKeys (fetch s fc.redo b) fc.feeds b) fc.feeds b[i]
        then capD ((locIx s fc b).decideLine S b[i]) else (locIx s fc b).decideLine S b[i]) := by
  obtain ⟨l1, l2, l3⟩ := R.lineKeys i hi
  obtain ⟨hke, ek⟩ := slot_of_opt l1
  obtain ⟨hkn, en⟩ := slot_of_opt l2
  obtain ⟨hki, ei⟩ := slot_of_opt l3
  have hbi : fitsLine2 b[i] = true := hbf _ (List.getElem_mem hi)
  have hrow := line_row R i hi
  have hcap : (layout s fc f b).lines[i]!.row.cap = isCap b[i] := by rw [hrow, Engine3.cap_of]
  have hbp : (layout s fc f b).pByp[(layout s fc f b).lines[i]!.pay]!.isSome = (fc.byp.lookup b[i].pay).isSome := by
    rw [(R.pay i hi).2.2]; simp
  have kE : exactKey b[i] ∈ keys b[i] := by simp [keys]
  have kN : nearKey b[i] ∈ keys b[i] := by simp [keys]
  have kI : idKey b[i] ∈ keys b[i] := by simp [keys]
  have pk : ∀ K, K ∈ keys b[i] → K ∈ probeKeys b := fun K hK => mem_probeKeys.2 ⟨b[i], List.getElem_mem hi, hK⟩
  have sE : seenAt sn seen0 (layout s fc f b).lines[i]!.ke = (locIx s fc b).seen (S) (exactKey b[i]) := by
    unfold seenAt; rw [hS i hi _ kE _ l1, h0 _ hke, ek]; rfl
  have sN : seenAt sn seen0 (layout s fc f b).lines[i]!.kn = (locIx s fc b).seen (S) (nearKey b[i]) := by
    unfold seenAt; rw [hS i hi _ kN _ l2, h0 _ hkn, en]; rfl
  have sI : seenAt sn seen0 (layout s fc f b).lines[i]!.ki = (locIx s fc b).seen (S) (idKey b[i]) := by
    unfold seenAt; rw [hS i hi _ kI _ l3, h0 _ hki, ei]; rfl
  have pE : pendAt (layout s fc f b) cfirst csame (layout s fc f b).pByp[(layout s fc f b).lines[i]!.pay]!.isSome
      (layout s fc f b).lines[i]!.row (layout s fc f b).lines[i]!.ke = (locIx s fc b).pending b[i] (exactKey b[i]) := by
    rw [hrow, hp _ hke (by rw [ek]; exact pk _ kE) b[i] hbi _ hbp, ek]
  have pN : pendAt (layout s fc f b) cfirst csame (layout s fc f b).pByp[(layout s fc f b).lines[i]!.pay]!.isSome
      (layout s fc f b).lines[i]!.row (layout s fc f b).lines[i]!.kn = (locIx s fc b).pending b[i] (nearKey b[i]) := by
    rw [hrow, hp _ hkn (by rw [en]; exact pk _ kN) b[i] hbi _ hbp, en]
  have pI : pendAt (layout s fc f b) cfirst csame (layout s fc f b).pByp[(layout s fc f b).lines[i]!.pay]!.isSome
      (layout s fc f b).lines[i]!.row (layout s fc f b).lines[i]!.ki = (locIx s fc b).pending b[i] (idKey b[i]) := by
    rw [hrow, hp _ hki (by rw [ei]; exact pk _ kI) b[i] hbi _ hbp, ei]
  have hcapd : (ic || hot[(layout s fc f b).lines[i]!.ke]! || hot[(layout s fc f b).lines[i]!.kn]! ||
      hot[(layout s fc f b).lines[i]!.ki]! || fcap[i]!) =
      cappedWith (idCapped (fetch s fc.redo b)) (hotKeys (fetch s fc.redo b) fc.feeds b) fc.feeds b[i] := by
    rw [hic, hh _ hke, hh _ hkn, hh _ hki, hfc, ek, en, ei]
    simp only [cappedWith, keys, List.any_cons, List.any_nil, Bool.or_false]
    generalize idCapped (fetch s fc.redo b) = a1
    generalize (hotKeys (fetch s fc.redo b) fc.feeds b).contains (exactKey b[i]) = a2
    generalize (hotKeys (fetch s fc.redo b) fc.feeds b).contains (nearKey b[i]) = a3
    generalize (hotKeys (fetch s fc.redo b) fc.feeds b).contains (idKey b[i]) = a4
    generalize feedCapped fc.feeds b[i] = a5
    cases a1 <;> cases a2 <;> cases a3 <;> cases a4 <;> cases a5 <;> rfl
  have hl : (locIx s fc b).looseKeys.contains (exactKey b[i]) = false := by
    simp [locIx, localIx]
  have hm : ∀ r, has (maskC (layout s fc f b) base fcap hot ic sn seen0 cfirst csame i) r =
      ((locIx s fc b).fires S b[i] r || (cappedWith (idCapped (fetch s fc.redo b))
        (hotKeys (fetch s fc.redo b) fc.feeds b) fc.feeds b[i]) && decide (r = .POSTING_CAP)) := by
    intro r
    rw [← hcapd]
    unfold maskC mask0
    exact mask_has (locIx s fc b) S b[i] base[i]! _ _ _ _ _ _ _ _ hb sE sN sI pE pN pI hcap hl r
  have hLo' : Lo (maskC (layout s fc f b) base fcap hot ic sn seen0 cfirst csame i) := Lo_maskC _ _ _ _ _ _ _ _ _ _ hLo
  have hrs : reasons.filter (has (maskC (layout s fc f b) base fcap hot ic sn seen0 cfirst csame i) ·) =
      (if cappedWith (idCapped (fetch s fc.redo b)) (hotKeys (fetch s fc.redo b) fc.feeds b) fc.feeds b[i]
        then capD ((locIx s fc b).decideLine S b[i]) else (locIx s fc b).decideLine S b[i]).reasons := by
    by_cases hc : cappedWith (idCapped (fetch s fc.redo b)) (hotKeys (fetch s fc.redo b) fc.feeds b) fc.feeds b[i] = true
    · rw [if_pos hc]
      simp only [capD, Ix.decideLine]
      apply List.filter_congr
      intro r _
      rw [hm r, hc]
      cases r <;> simp [Ix.fires, hl, List.mem_filter, mem_reasons]
    · rw [if_neg hc]
      simp only [Ix.decideLine]
      apply List.filter_congr
      intro r _
      rw [hm r]
      simp [hc]
  have hsrc : (layout s fc f b).src.getD i nilLine = b[i] := by
    simp [R.src, Array.getD_eq_getD_getElem?, hi]
  unfold DecOK
  refine ⟨?_, ?_, hrs.symm, ?_, hLo', rfl⟩
  · dsimp only
    rw [hsrc]
    split <;> simp [capD, Ix.decideLine]
  · dsimp only
    rw [outOf_eq _ hLo', hrs]
    split <;> simp [capD, Ix.decideLine]
  · dsimp only
    split <;> simpa [capD, Ix.decideLine] using hcp

end

/-- The decisions of the fixed-row decider, one for one with the reference decisions. -/
def AllOK (L : Lay) : List Dec → List Decision → Prop
  | [], [] => True
  | d :: ds, r :: rs => DecOK L d r ∧ AllOK L ds rs
  | _, _ => False

section
variable {H : Bytes → Bytes} {s : St} {fc : FCtx} {f : List Nat} {b : List Line} {rel unr : Snapshot Line}

theorem fold_ds (R : Rep (layout s fc f b) s fc f b) (hbf : ∀ l ∈ b, fitsLine2 l = true)
    (own held notEnr fcap hot seen0 csame capClaim : Array Bool) (ic : Bool) (cfirst : Array Nat) (base : Array UInt32)
    (hown : ∀ i (hi : i < b.length), own[i]! = (locIx s fc b).own b[i])
    (hne : ∀ i (hi : i < b.length), notEnr[i]! = (locIx s fc b).notEnrolled b[i])
    (hb : ∀ i (hi : i < b.length), ∀ r, has base[i]! r = baseF (locIx s fc b) b[i] r)
    (hLo : ∀ i (hi : i < b.length), Lo base[i]!)
    (h0 : ∀ k (hk : k < (fetch s fc.redo b).rel.length), seen0[k]! = (locIx s fc b).seen0 (fetch s fc.redo b).rel[k].1)
    (hp : ∀ k (hk : k < (fetch s fc.redo b).rel.length), (fetch s fc.redo b).rel[k].1 ∈ probeKeys b →
      ∀ l : Line, fitsLine2 l = true → ∀ bp, bp = (fc.byp.lookup l.pay).isSome →
        pendAt (layout s fc f b) cfirst csame bp (RowX.of l) k = (locIx s fc b).pending l (fetch s fc.redo b).rel[k].1)
    (hh : ∀ k (hk : k < (fetch s fc.redo b).rel.length),
      hot[k]! = (hotKeys (fetch s fc.redo b) fc.feeds b).contains (fetch s fc.redo b).rel[k].1)
    (hic : ic = idCapped (fetch s fc.redo b)) (hfc : ∀ i (hi : i < b.length), fcap[i]! = feedCapped fc.feeds b[i])
    (hcp : ∀ i (hi : i < b.length), cpId (layout s fc f b) (cpOf (layout s fc f b) capClaim i) =
      ((locIx s fc b).counterparts b[i]).head?) :
    ∀ (rest : List Nat), (∀ i ∈ rest, i < b.length) →
      ∀ (st : Array Bool × Array Dec × Array Bool × Array Bool × Array Bool × Array Bool) (S : HashSet Key),
        SnInv s fc b st.1 S → st.1.size = (layout s fc f b).slots.size →
        let fin := rest.foldl (fun st a => stepG (layout s fc f b) own held notEnr base fcap hot ic seen0 cfirst csame capClaim a st) st
        ∃ new : List Dec, fin.2.1.toList = st.2.1.toList ++ new ∧
          AllOK (layout s fc f b) new (((locIx s fc b).decideAll S (rest.map (b.getD · nilLine))).map fun d =>
            if cappedWith (idCapped (fetch s fc.redo b)) (hotKeys (fetch s fc.redo b) fc.feeds b) fc.feeds d.line
              then capD d else d) ∧
          SnInv s fc b fin.1 (foldS (locIx s fc b) S (rest.map (b.getD · nilLine))) ∧
          fin.1.size = (layout s fc f b).slots.size ∧ ∀ d ∈ new, d.line ∈ rest := by
  intro rest
  induction rest with
  | nil =>
    intro _ st S hS hsz
    exact ⟨[], by simp, by simp [Ix.decideAll, AllOK], by simpa [foldS] using hS, hsz, by simp⟩
  | cons a rest ih =>
    intro hrest st S hS hsz
    have ha : a < b.length := hrest a (by simp)
    have hrest' : ∀ i ∈ rest, i < b.length := fun i hi => hrest i (by simp [hi])
    have hgd : b.getD a nilLine = b[a] := by simp [List.getD_eq_getElem?_getD, ha]
    have hcap : (layout s fc f b).lines[a]!.row.cap = isCap b[a] := by rw [line_row R a ha, Engine3.cap_of]
    have hcond : (!((layout s fc f b).lines[a]!.row.cap && notEnr[a]! && !own[a]!)) =
        !(isCap b[a] && (locIx s fc b).notEnrolled b[a] && !(locIx s fc b).own b[a]) := by
      rw [hcap, hne a ha, hown a ha]
    have hS1 := snInv_step R st.1 hsz S hS a ha _ hcond
    have hdec := line_dec R hbf a ha S st.1 seen0 hot fcap csame capClaim ic cfirst base hS (hb a ha) (hLo a ha) h0 hp hh hic
      (hfc a ha) (hcp a ha)
    obtain ⟨new', e1, e2, e3, e4, e5⟩ := ih hrest'
      (stepG (layout s fc f b) own held notEnr base fcap hot ic seen0 cfirst csame capClaim a st)
      (S.insertMany ((locIx s fc b).claim b[a])) hS1 (by
        simp only [stepG]; split <;> simp [Array.set!_eq_setIfInBounds, hsz])
    refine ⟨⟨a, maskC (layout s fc f b) base fcap hot ic st.1 seen0 cfirst csame a,
      outOf (maskC (layout s fc f b) base fcap hot ic st.1 seen0 cfirst csame a),
      cpOf (layout s fc f b) capClaim a⟩ :: new', ?_, ?_, ?_, ?_, ?_⟩
    · simp only [List.foldl_cons]
      rw [e1]
      simp [stepG]
    · simp only [List.map_cons, hgd, Ix.decideAll, List.map_cons]
      exact ⟨hdec, e2⟩
    · unfold foldS at e3 ⊢
      simp only [List.map_cons, List.foldl_cons, hgd]
      exact e3
    · exact e4
    · intro d hd
      rcases List.mem_cons.1 hd with rfl | hd
      · simp
      · exact List.mem_cons_of_mem _ (e5 d hd)

end

/-- The payment arrays after the decision-order fold: each is a fold over the decisions made. -/
theorem get_set (a : Array Bool) (j k : Nat) (v : Bool) (hj : j < a.size) :
    (a.set! j v)[k]! = if j = k then v else a[k]! := by
  rw [set_get]; by_cases h : k = j
  · subst h; simp [hj]
  · simp [h, Ne.symm h]

theorem ite_set (a : Array Bool) (j k : Nat) (c : Bool) (v : Bool) (hj : j < a.size) :
    (if c = true then a.set! j v else a)[k]! = if c = true ∧ j = k then v else a[k]! := by
  by_cases hc : c = true
  · simp only [hc, if_true, true_and]; exact get_set a j k v hj
  · simp [hc]

section
variable (x : Lay) (own held notEnr : Array Bool) (base : Array UInt32) (fcap hot : Array Bool) (ic : Bool)
  (seen0 : Array Bool) (cfirst : Array Nat) (csame capClaim : Array Bool)

theorem fold_pay (n : Nat) : ∀ (rest : List Nat), (∀ i ∈ rest, x.lines[i]!.pay < n) →
    ∀ (st : Array Bool × Array Dec × Array Bool × Array Bool × Array Bool × Array Bool),
      st.2.2.1.size = n → st.2.2.2.1.size = n → st.2.2.2.2.1.size = n → st.2.2.2.2.2.size = n →
      let fin := rest.foldl (fun st a => stepG x own held notEnr base fcap hot ic seen0 cfirst csame capClaim a st) st
      fin.2.2.1.size = n ∧ fin.2.2.2.1.size = n ∧ fin.2.2.2.2.1.size = n ∧ fin.2.2.2.2.2.size = n ∧
      ∃ new : List Dec, fin.2.1.toList = st.2.1.toList ++ new ∧ (∀ d ∈ new, d.line ∈ rest) ∧
        (∀ p, fin.2.2.1[p]! = (st.2.2.1[p]! || new.any fun d => x.lines[d.line]!.pay == p && d.out == 1)) ∧
        (∀ p, fin.2.2.2.1[p]! = (st.2.2.2.1[p]! && new.all fun d => x.lines[d.line]!.pay != p ||
          (d.out == 0 && (!x.pRedo[x.lines[d.line]!.pay]! || own[d.line]!)))) ∧
        (∀ p, fin.2.2.2.2.1[p]! = (st.2.2.2.2.1[p]! || new.any fun d => x.lines[d.line]!.pay == p && held[d.line]!)) ∧
        (∀ p, fin.2.2.2.2.2[p]! = (st.2.2.2.2.2[p]! && new.all fun d => x.lines[d.line]!.pay != p ||
          match x.pByp[x.lines[d.line]!.pay]! with
          | some bm => !(d.mask &&& ~~~(bypM &&& bm) != 0)
          | none => true)) := by
  intro rest
  induction rest with
  | nil =>
    intro _ st h1 h2 h3 h4
    exact ⟨h1, h2, h3, h4, [], by simp, by simp, by simp, by simp, by simp, by simp⟩
  | cons a rest ih =>
    intro hrest st h1 h2 h3 h4
    have ha : x.lines[a]!.pay < n := hrest a (by simp)
    have hrest' : ∀ i ∈ rest, x.lines[i]!.pay < n := fun i hi => hrest i (by simp [hi])
    have hs1 : (stepG x own held notEnr base fcap hot ic seen0 cfirst csame capClaim a st).2.2.1.size = n := by
      simp only [stepG]; split <;> simp [Array.set!_eq_setIfInBounds, h1]
    have hs2 : (stepG x own held notEnr base fcap hot ic seen0 cfirst csame capClaim a st).2.2.2.1.size = n := by
      simp only [stepG]; split <;> simp [Array.set!_eq_setIfInBounds, h2]
    have hs3 : (stepG x own held notEnr base fcap hot ic seen0 cfirst csame capClaim a st).2.2.2.2.1.size = n := by
      simp only [stepG]; split <;> simp [Array.set!_eq_setIfInBounds, h3]
    have hs4 : (stepG x own held notEnr base fcap hot ic seen0 cfirst csame capClaim a st).2.2.2.2.2.size = n := by
      simp only [stepG]; split <;> (try split) <;> simp [Array.set!_eq_setIfInBounds, h4]
    obtain ⟨e1, e2, e3, e4, new', n1, n2, n3, n4, n5, n6⟩ := ih hrest' _ hs1 hs2 hs3 hs4
    refine ⟨e1, e2, e3, e4, ⟨a, maskC x base fcap hot ic st.1 seen0 cfirst csame a,
      outOf (maskC x base fcap hot ic st.1 seen0 cfirst csame a), cpOf x capClaim a⟩ :: new', ?_, ?_, ?_, ?_, ?_, ?_⟩
    · simp only [List.foldl_cons]
      rw [n1]
      simp [stepG]
    · intro d hd
      rcases List.mem_cons.1 hd with rfl | hd
      · simp
      · exact List.mem_cons_of_mem _ (n2 d hd)
    · intro p
      simp only [List.foldl_cons]
      rw [n3 p]
      have : (stepG x own held notEnr base fcap hot ic seen0 cfirst csame capClaim a st).2.2.1[p]! =
          (st.2.2.1[p]! || (x.lines[a]!.pay == p && outOf (maskC x base fcap hot ic st.1 seen0 cfirst csame a) == 1)) := by
        simp only [stepG]
        rw [ite_set _ _ _ _ _ (by omega)]
        generalize outOf (maskC x base fcap hot ic st.1 seen0 cfirst csame a) = o
        by_cases hp : x.lines[a]!.pay = p <;> by_cases ho : o = 1 <;> simp [hp, ho] <;> cases st.2.2.1[p]! <;> simp
      rw [this]
      simp [Bool.or_assoc]
    · intro p
      simp only [List.foldl_cons]
      rw [n4 p]
      have : (stepG x own held notEnr base fcap hot ic seen0 cfirst csame capClaim a st).2.2.2.1[p]! =
          (st.2.2.2.1[p]! && (x.lines[a]!.pay != p ||
            (outOf (maskC x base fcap hot ic st.1 seen0 cfirst csame a) == 0 &&
              (!x.pRedo[x.lines[a]!.pay]! || own[a]!)))) := by
        simp only [stepG]
        rw [ite_set _ _ _ _ _ (by omega)]
        generalize outOf (maskC x base fcap hot ic st.1 seen0 cfirst csame a) = o
        by_cases hp : x.lines[a]!.pay = p <;> by_cases ho : o = 0 <;> simp [hp, ho] <;> cases st.2.2.2.1[p]! <;> simp
      rw [this]
      simp [Bool.and_assoc]
    · intro p
      simp only [List.foldl_cons]
      rw [n5 p]
      have : (stepG x own held notEnr base fcap hot ic seen0 cfirst csame capClaim a st).2.2.2.2.1[p]! =
          (st.2.2.2.2.1[p]! || (x.lines[a]!.pay == p && held[a]!)) := by
        simp only [stepG]
        rw [ite_set _ _ _ _ _ (by omega)]
        by_cases hp : x.lines[a]!.pay = p <;> by_cases ho : held[a]! = true <;> simp [hp, ho] <;>
          cases st.2.2.2.2.1[p]! <;> simp
      rw [this]
      simp [Bool.or_assoc]
    · intro p
      simp only [List.foldl_cons]
      rw [n6 p]
      have : (stepG x own held notEnr base fcap hot ic seen0 cfirst csame capClaim a st).2.2.2.2.2[p]! =
          (st.2.2.2.2.2[p]! && (x.lines[a]!.pay != p ||
            match x.pByp[x.lines[a]!.pay]! with
            | some bm => !((maskC x base fcap hot ic st.1 seen0 cfirst csame a) &&& ~~~(bypM &&& bm) != 0)
            | none => true)) := by
        simp only [stepG]
        generalize maskC x base fcap hot ic st.1 seen0 cfirst csame a = m
        cases hb : x.pByp[x.lines[a]!.pay]! with
        | none => by_cases hp : x.lines[a]!.pay = p <;> simp [hp]
        | some bm =>
          simp only []
          rw [ite_set _ _ _ _ _ (by omega)]
          by_cases hp : x.lines[a]!.pay = p <;> by_cases ho : (m &&& ~~~(bypM &&& bm) != 0) = true <;> simp [hp, ho] <;>
            cases st.2.2.2.2.2[p]! <;> simp
      rw [this]
      simp [Bool.and_assoc]
end

/-- A payment's bypass: named, not a redo, held, and every decision of the payment within the bypass. -/
def bypOf (x : Lay) (pHeld pByp : Array Bool) (p : Nat) : Bool :=
  x.pByp[p]!.isSome && !x.pRedo[p]! && pHeld[p]! && pByp[p]!

/-- A payment that goes at HOLD authority, from line `i` of it: its entry is HOLD-level, it is not a redo, the rules do
    not allow it, and every decision of it is within the lift. -/
def liftOf (x : Lay) (pHold pAllow pLift : Array Bool) (i p : Nat) : Bool :=
  x.lLim[i]!.isSome && !x.pRedo[p]! && (pHold[p]! || !pAllow[p]!) && pLift[p]!

/-- A decision joins the released rows. -/
def relPr (x : Lay) (own pHold pAllow pHeld pByp pLift : Array Bool) (d : Dec) : Bool :=
  d.out == 0 && !x.pRedo[x.lines[d.line]!.pay]! && !pHold[x.lines[d.line]!.pay]! && pAllow[x.lines[d.line]!.pay]! ||
    bypOf x pHeld pByp x.lines[d.line]!.pay || liftOf x pHold pAllow pLift d.line x.lines[d.line]!.pay && !own[d.line]!

/-- A decision joins the unresolved rows. -/
def unrPr (x : Lay) (own held pHold pAllow pHeld pByp pLift : Array Bool) (d : Dec) : Bool :=
  d.out != 0 && d.mask &&& bAlready == 0 && !own[d.line]! &&
    !(x.pByp[x.lines[d.line]!.pay]!.isSome && held[d.line]!) && !bypOf x pHeld pByp x.lines[d.line]!.pay &&
    !liftOf x pHold pAllow pLift d.line x.lines[d.line]!.pay

/-- One element of `decideRows`' last loop, as a function. -/
def relStep (x : Lay) (own held pHold pAllow pHeld pByp pLift : Array Bool) (d : Dec) (s : Array Nat × Array Nat) :
    Array Nat × Array Nat :=
  (if relPr x own pHold pAllow pHeld pByp pLift d then s.fst.push d.line else s.fst,
   if unrPr x own held pHold pAllow pHeld pByp pLift d then s.snd.push d.line else s.snd)

theorem fold_rel (x : Lay) (own held pHold pAllow pHeld pByp pLift : Array Bool) :
    ∀ (l : List Dec) (st : Array Nat × Array Nat),
    (l.foldl (fun s d => relStep x own held pHold pAllow pHeld pByp pLift d s) st).fst.toList =
      st.fst.toList ++ (l.filter (relPr x own pHold pAllow pHeld pByp pLift)).map (·.line) ∧
    (l.foldl (fun s d => relStep x own held pHold pAllow pHeld pByp pLift d s) st).snd.toList =
      st.snd.toList ++ (l.filter (unrPr x own held pHold pAllow pHeld pByp pLift)).map (·.line) := by
  intro l
  induction l with
  | nil => intro st; simp
  | cons d l ih =>
    intro st
    obtain ⟨h1, h2⟩ := ih (relStep x own held pHold pAllow pHeld pByp pLift d st)
    simp only [List.foldl_cons, List.filter_cons]
    rw [h1, h2]
    unfold relStep
    split <;> split <;> simp_all

/-- A decision within the lift of its line's HOLD-level entry (vacuously so without one). -/
def inLift (x : Lay) (d : Dec) : Bool :=
  match x.lLim[d.line]! with
  | some lm => !(d.mask &&& ~~~(bypM &&& ~~~lm) != 0)
  | none => true

/-- One element of `decideRows`' lift loop, as a function. -/
def liftStep (x : Lay) (d : Dec) (a : Array Bool) : Array Bool :=
  match x.lLim[d.line]! with
  | some lm => if d.mask &&& ~~~(bypM &&& ~~~lm) != 0 then a.set! x.lines[d.line]!.pay false else a
  | none => a

theorem liftStep_size (x : Lay) (d : Dec) (a : Array Bool) : (liftStep x d a).size = a.size := by
  unfold liftStep; split <;> (try split) <;> simp [Array.set!_eq_setIfInBounds]

theorem fold_lift (x : Lay) (n : Nat) : ∀ (l : List Dec), (∀ d ∈ l, x.lines[d.line]!.pay < n) →
    ∀ (a : Array Bool), a.size = n → ∀ p,
      (l.foldl (fun a d => liftStep x d a) a)[p]! = (a[p]! && l.all fun d => x.lines[d.line]!.pay != p || inLift x d) := by
  intro l
  induction l with
  | nil => intro _ a _ p; simp
  | cons d l ih =>
    intro hl a ha p
    simp only [List.foldl_cons, List.all_cons]
    rw [ih (fun e he => hl e (by simp [he])) _ (by rw [liftStep_size]; exact ha) p]
    have hd : x.lines[d.line]!.pay < n := hl d (by simp)
    have : (liftStep x d a)[p]! = (a[p]! && (x.lines[d.line]!.pay != p || inLift x d)) := by
      unfold liftStep inLift
      split
      · rename_i lm _
        rw [ite_set _ _ _ _ _ (by omega)]
        by_cases hp : x.lines[d.line]!.pay = p <;>
          by_cases ho : (d.mask &&& ~~~(bypM &&& ~~~lm) != 0) = true <;> simp [hp, ho] <;> cases a[p]! <;> simp
      · simp
    rw [this, Bool.and_assoc]

/-- The lift loop reads the decisions' lines and masks only. -/
theorem fold_lift_congr (x : Lay) : ∀ (l l' : List Dec), l'.map (fun d => (d.line, d.mask, d.out)) =
    l.map (fun d => (d.line, d.mask, d.out)) → ∀ (a : Array Bool),
      l'.foldl (fun a d => liftStep x d a) a = l.foldl (fun a d => liftStep x d a) a
  | [], [], _, _ => rfl
  | d :: l, d' :: l', h, a => by
    simp only [List.map_cons, List.cons.injEq, Prod.mk.injEq] at h
    obtain ⟨⟨e1, e2, -⟩, h⟩ := h
    simp only [List.foldl_cons]
    have : liftStep x d' a = liftStep x d a := by unfold liftStep; rw [e1, e2]
    rw [this]; exact fold_lift_congr x l l' h _
  | [], _ :: _, h, _ => by simp at h
  | _ :: _, [], h, _ => by simp at h

theorem allok_any (L : Lay) (P : Dec → Prop) (g : Dec → Bool) (g' : Decision → Bool) :
    ∀ (ds : List Dec) (rs : List Decision), AllOK L ds rs → (∀ d ∈ ds, P d) →
      (∀ d r, P d → DecOK L d r → g d = g' r) → ds.any g = rs.any g'
  | [], [], _, _, _ => rfl
  | d :: ds, r :: rs, ⟨h1, h2⟩, hP, h => by
    simp only [List.any_cons]
    rw [h d r (hP d (by simp)) h1, allok_any L P g g' ds rs h2 (fun e he => hP e (by simp [he])) h]
  | [], _ :: _, h, _, _ => h.elim
  | _ :: _, [], h, _, _ => h.elim

theorem allok_all (L : Lay) (P : Dec → Prop) (g : Dec → Bool) (g' : Decision → Bool) :
    ∀ (ds : List Dec) (rs : List Decision), AllOK L ds rs → (∀ d ∈ ds, P d) →
      (∀ d r, P d → DecOK L d r → g d = g' r) → ds.all g = rs.all g'
  | [], [], _, _, _ => rfl
  | d :: ds, r :: rs, ⟨h1, h2⟩, hP, h => by
    simp only [List.all_cons]
    rw [h d r (hP d (by simp)) h1, allok_all L P g g' ds rs h2 (fun e he => hP e (by simp [he])) h]
  | [], _ :: _, h, _, _ => h.elim
  | _ :: _, [], h, _, _ => h.elim

theorem allok_fm {β : Type} (L : Lay) (P : Dec → Prop) (g : Dec → Bool) (g' : Decision → Bool) (F : Dec → β)
    (F' : Decision → β) :
    ∀ (ds : List Dec) (rs : List Decision), AllOK L ds rs → (∀ d ∈ ds, P d) →
      (∀ d r, r ∈ rs → P d → DecOK L d r → g d = g' r ∧ F d = F' r) → (ds.filter g).map F = (rs.filter g').map F'
  | [], [], _, _, _ => rfl
  | d :: ds, r :: rs, ⟨h1, h2⟩, hP, h => by
    obtain ⟨e1, e2⟩ := h d r (by simp) (hP d (by simp)) h1
    have ih := allok_fm L P g g' F F' ds rs h2 (fun e he => hP e (by simp [he]))
      (fun e r' hr' => h e r' (List.mem_cons_of_mem _ hr'))
    simp only [List.filter_cons, e1]
    split <;> simp [ih, e2]
  | [], _ :: _, h, _, _ => h.elim
  | _ :: _, [], h, _, _ => h.elim

theorem out8_hr (o : UInt8) (h0 : o ≠ 0) (h1 : o ≠ 1) : outcomeOf8 o = Outcome.HUMAN_REVIEW := by
  unfold outcomeOf8; split <;> simp_all

theorem out8_allow (o : UInt8) : (outcomeOf8 o == Outcome.ALLOW) = (o == 0) := by
  by_cases h0 : o = 0
  · subst h0; rfl
  by_cases h1 : o = 1
  · subst h1; rfl
  rw [out8_hr o h0 h1, beq_false_of_ne h0]; decide

theorem out8_hold (o : UInt8) : (outcomeOf8 o == Outcome.HOLD) = (o == 1) := by
  by_cases h0 : o = 0
  · subst h0; rfl
  by_cases h1 : o = 1
  · subst h1; rfl
  rw [out8_hr o h0 h1, beq_false_of_ne h1]; decide

theorem tb (m i : Nat) : ((m >>> i) % 2 == 1) = m.testBit i := by
  rw [Bool.eq_iff_iff]
  simp only [beq_iff_eq]
  constructor
  · intro h
    rw [Nat.testBit_eq_decide_div_mod_eq]
    simpa [Nat.shiftRight_eq_div_pow] using h
  · intro h
    have := Nat.testBit_eq_decide_div_mod_eq (x := m) (i := i)
    rw [h] at this
    simpa [Nat.shiftRight_eq_div_pow] using this.symm

theorem has_and (a b : UInt32) (r : Reason) : has (a &&& b) r = (has a r && has b r) := by
  simp only [has_iff, UInt32.toNat_and, Nat.testBit_and]

theorem has_mod (m : Nat) (r : Reason) : has (m % 2 ^ 32).toUInt32 r = m.testBit r.idx := by
  have := idx_lt32 r
  have h : ((m % 2 ^ 32).toUInt32).toNat = m % 2 ^ 32 := by
    simp only [Nat.toUInt32]; exact Nat.mod_mod _ _
  rw [has_iff, h, Nat.testBit_mod_two_pow]
  simp [show r.idx < 32 by omega]

theorem bm_ok (mask : UInt32) (hLo : Lo mask) (m : Nat) :
    (mask &&& ~~~(bypM &&& (m % 2 ^ 32).toUInt32) != 0) = false ↔
      ((reasons.filter (has mask ·)).all fun r => bypassable r && (m >>> r.idx % 2 == 1)) = true := by
  have e : ∀ z : UInt32, (z != 0) = false ↔ z = 0 := fun z => by simp
  rw [e]
  simp only [List.all_eq_true, List.mem_filter, Bool.and_eq_true, tb, and_imp]
  constructor
  · intro h r _ hr
    have this : has (mask &&& ~~~(bypM &&& (m % 2 ^ 32).toUInt32)) r = has 0 r := by rw [h]
    rw [has_andnot, has_and, has_mod, has_zero] at this
    unfold bypM at this
    rw [has_maskOf] at this
    simpa [hr] using this
  · intro h
    refine eq_zero_of_has (Lo_andnot _ hLo) fun r => ?_
    rw [has_andnot, has_and, has_mod]
    unfold bypM
    rw [has_maskOf]
    by_cases hr : has mask r = true
    · have := h r (mem_reasons r) hr
      simp [hr, this.1, this.2]
    · have hr' : has mask r = false := by simpa using hr
      simp [hr']

theorem bl_ok (mask : UInt32) (hLo : Lo mask) (m : Nat) :
    (mask &&& ~~~(bypM &&& ~~~(m % 2 ^ 32).toUInt32) != 0) = false ↔
      ((reasons.filter (has mask ·)).all fun r => bypassable r && !(m >>> r.idx % 2 == 1)) = true := by
  have e : ∀ z : UInt32, (z != 0) = false ↔ z = 0 := fun z => by simp
  rw [e]
  simp only [List.all_eq_true, List.mem_filter, Bool.and_eq_true, tb, and_imp, Bool.not_eq_true']
  constructor
  · intro h r _ hr
    have this : has (mask &&& ~~~(bypM &&& ~~~(m % 2 ^ 32).toUInt32)) r = has 0 r := by rw [h]
    rw [has_andnot, has_andnot, has_mod, has_zero] at this
    unfold bypM at this
    rw [has_maskOf] at this
    simpa [hr] using this
  · intro h
    refine eq_zero_of_has (Lo_andnot _ hLo) fun r => ?_
    rw [has_andnot, has_andnot, has_mod]
    unfold bypM
    rw [has_maskOf]
    by_cases hr : has mask r = true
    · have := h r (mem_reasons r) hr
      simp [hr, this.1, this.2]
    · have hr' : has mask r = false := by simpa using hr
      simp [hr']

theorem pair_facts (L : Lay) (b : List Line) (hsrc : L.src = b.toArray) {d : Dec} {r : Decision} (h : DecOK L d r)
    (hd : d.line < b.length) :
    r.line = b[d.line] ∧ r.outcome = outcomeOf8 d.out ∧ r.reasons = reasons.filter (has d.mask ·) ∧ Lo d.mask := by
  obtain ⟨h1, h2, h3, -, h5, -⟩ := h
  refine ⟨?_, h2.symm, h3, h5⟩
  rw [← h1, hsrc]
  simp [Array.getD, hd]

theorem pay_beq (L : Lay) (b : List Line)
    (hps : ∀ i j (hi : i < b.length) (hj : j < b.length), L.lines[i]!.pay = L.lines[j]!.pay ↔ b[i].pay = b[j].pay)
    (i j : Nat) (hi : i < b.length) (hj : j < b.length) :
    (L.lines[i]!.pay == L.lines[j]!.pay) = (b[i].pay == b[j].pay) := by
  rw [Bool.eq_iff_iff]; simpa using hps i j hi hj

theorem payOutcome_allow (x : Ix) (rs : List Decision) (P : Nat) (r : Decision) (hr : r ∈ rs) (hP : r.line.pay = P) :
    (x.payOutcome rs P == Outcome.ALLOW) =
      (!(rs.any fun r' => r'.line.pay == P && r'.outcome == Outcome.HOLD) &&
        rs.all fun r' => r'.line.pay != P || (r'.outcome == Outcome.ALLOW && (!x.redo.contains P || x.own r'.line))) := by
  have hne : (rs.filter (·.line.pay == P)).isEmpty = false := by
    cases h : (rs.filter (·.line.pay == P)).isEmpty
    · rfl
    · exact absurd (List.isEmpty_iff.1 h ▸ List.mem_filter.2 ⟨hr, by simp [hP]⟩) (by simp)
  unfold Ix.payOutcome
  simp only [List.any_filter, List.all_filter, hne]
  by_cases h1 : (rs.any fun r' => r'.line.pay == P && r'.outcome == Outcome.HOLD) = true
  · simp [h1]
  · simp only [Bool.not_eq_true] at h1
    simp [h1]
    rw [Bool.eq_iff_iff]
    split <;> simp_all

theorem mask_already (m : UInt32) :
    ((reasons.filter (has m ·)).contains Reason.ALREADY_DECIDED) = (m &&& bAlready != 0) := by
  have h : ((reasons.filter (has m ·)).contains Reason.ALREADY_DECIDED) = has m Reason.ALREADY_DECIDED := by
    rw [Bool.eq_iff_iff]
    rw [List.contains_iff_mem, List.mem_filter]
    exact ⟨fun h => h.2, fun h => ⟨mem_reasons _, h⟩⟩
  rw [h]; rfl

theorem lift_bool (a b c r y : Bool) (o : Outcome) (ho : (o == .ALLOW) = (!a && b)) (hy : y = true) :
    (true && !r && (a || !b) && c) = (!r && (o != .ALLOW && y && c)) := by
  subst hy; simp only [bne, ho]; cases a <;> cases b <;> cases c <;> cases r <;> rfl

theorem sets_core (L : Lay) (x : Ix) (b : List Line) (n : Nat)
    (hsrc : L.src = b.toArray)
    (hpay : ∀ i (h : i < b.length), L.lines[i]!.pay < n ∧ L.pRedo[L.lines[i]!.pay]! = x.redo.contains b[i].pay ∧
      L.pByp[L.lines[i]!.pay]! = (x.byp.lookup b[i].pay).map fun m => (m % 2 ^ 32).toUInt32)
    (hlim : ∀ i (hi : i < b.length), L.lLim[i]! = (x.lim.lookup b[i].pay).map fun m => (m % 2 ^ 32).toUInt32)
    (hps : ∀ i j (hi : i < b.length) (hj : j < b.length), L.lines[i]!.pay = L.lines[j]!.pay ↔ b[i].pay = b[j].pay)
    (new : List Dec) (rs : List Decision) (hall : AllOK L new rs) (hlt : ∀ d ∈ new, d.line < b.length)
    (own held pH pA pHe pB pL : Array Bool)
    (hown : ∀ i (hi : i < b.length), own[i]! = x.own b[i]) (hheld : ∀ i (hi : i < b.length), held[i]! = x.held b[i])
    (hH : ∀ p, p < n → pH[p]! = new.any fun d => L.lines[d.line]!.pay == p && d.out == 1)
    (hA : ∀ p, p < n → pA[p]! = new.all fun d => L.lines[d.line]!.pay != p ||
      (d.out == 0 && (!L.pRedo[L.lines[d.line]!.pay]! || own[d.line]!)))
    (hHe : ∀ p, p < n → pHe[p]! = new.any fun d => L.lines[d.line]!.pay == p && held[d.line]!)
    (hB : ∀ p, p < n → pB[p]! = new.all fun d => L.lines[d.line]!.pay != p ||
      match L.pByp[L.lines[d.line]!.pay]! with
      | some bm => !(d.mask &&& ~~~(bypM &&& bm) != 0)
      | none => true)
    (hL : ∀ p, p < n → pL[p]! = new.all fun d => L.lines[d.line]!.pay != p || inLift L d) :
    (new.filter (relPr L own pH pA pHe pB pL)).map (fun d => L.src.getD d.line nilLine) = x.releasedLines rs ∧
    (new.filter (unrPr L own held pH pA pHe pB pL)).map (fun d => L.src.getD d.line nilLine) = x.unresolvedLines rs := by
  have E1 : ∀ i (hi : i < b.length), pH[L.lines[i]!.pay]! =
      rs.any fun r' => r'.line.pay == b[i].pay && r'.outcome == Outcome.HOLD := by
    intro i hi
    rw [hH _ (hpay i hi).1]
    refine allok_any L (fun d => d.line < b.length) _ _ new rs hall hlt ?_
    intro d r hd hdok
    obtain ⟨h1, h2, -, -⟩ := pair_facts L b hsrc hdok hd
    rw [h1, h2, pay_beq L b hps d.line i hd hi, out8_hold]
  have E2 : ∀ i (hi : i < b.length), pA[L.lines[i]!.pay]! =
      rs.all fun r' => r'.line.pay != b[i].pay ||
        (r'.outcome == Outcome.ALLOW && (!x.redo.contains b[i].pay || x.own r'.line)) := by
    intro i hi
    rw [hA _ (hpay i hi).1]
    refine allok_all L (fun d => d.line < b.length) _ _ new rs hall hlt ?_
    intro d r hd hdok
    obtain ⟨h1, h2, -, -⟩ := pair_facts L b hsrc hdok hd
    have e3 : (L.lines[d.line]!.pay != L.lines[i]!.pay) = (b[d.line].pay != b[i].pay) := by
      simp only [bne, pay_beq L b hps d.line i hd hi]
    rw [h1, h2, e3, (hpay d.line hd).2.1, hown d.line hd, ← out8_allow]
    by_cases hq : b[d.line].pay = b[i].pay
    · simp [hq]
    · have hq' : (b[d.line].pay != b[i].pay) = true := bne_iff_ne.2 hq
      simp only [hq', Bool.true_or]
  have E3 : ∀ i (hi : i < b.length), pHe[L.lines[i]!.pay]! =
      rs.any fun r' => r'.line.pay == b[i].pay && x.held r'.line := by
    intro i hi
    rw [hHe _ (hpay i hi).1]
    refine allok_any L (fun d => d.line < b.length) _ _ new rs hall hlt ?_
    intro d r hd hdok
    obtain ⟨h1, h2, -, -⟩ := pair_facts L b hsrc hdok hd
    rw [h1, pay_beq L b hps d.line i hd hi, hheld d.line hd]
  have E4 : ∀ i (hi : i < b.length) (m : Nat), x.byp.lookup b[i].pay = some m → pB[L.lines[i]!.pay]! =
      rs.all fun r' => r'.line.pay != b[i].pay || r'.reasons.all fun r => bypassable r && (m >>> r.idx % 2 == 1) := by
    intro i hi m hm
    rw [hB _ (hpay i hi).1]
    refine allok_all L (fun d => d.line < b.length) _ _ new rs hall hlt ?_
    intro d r hd hdok
    obtain ⟨h1, h2, h3, h4⟩ := pair_facts L b hsrc hdok hd
    have e3 : (L.lines[d.line]!.pay != L.lines[i]!.pay) = (b[d.line].pay != b[i].pay) := by
      simp only [bne, pay_beq L b hps d.line i hd hi]
    by_cases hq : b[d.line].pay = b[i].pay
    · have hL := (hps d.line i hd hi).2 hq
      rw [h1, e3, hL, (hpay i hi).2.2, hm, h3]
      have := bm_ok d.mask h4 m
      simp only [Option.map_some, hq, bne_self_eq_false, Bool.false_or]
      rw [Bool.eq_iff_iff]
      simpa using this
    · have hq' : (b[d.line].pay != b[i].pay) = true := bne_iff_ne.2 hq
      simp only [h1, e3, hq', Bool.true_or]
  have E5 : ∀ i (hi : i < b.length) (m : Nat), x.lim.lookup b[i].pay = some m → pL[L.lines[i]!.pay]! =
      rs.all fun r' => r'.line.pay != b[i].pay || r'.reasons.all fun r => bypassable r && !(m >>> r.idx % 2 == 1) := by
    intro i hi m hm
    rw [hL _ (hpay i hi).1]
    refine allok_all L (fun d => d.line < b.length) _ _ new rs hall hlt ?_
    intro d r hd hdok
    obtain ⟨h1, h2, h3, h4⟩ := pair_facts L b hsrc hdok hd
    have e3 : (L.lines[d.line]!.pay != L.lines[i]!.pay) = (b[d.line].pay != b[i].pay) := by
      simp only [bne, pay_beq L b hps d.line i hd hi]
    by_cases hq : b[d.line].pay = b[i].pay
    · rw [h1, e3]
      unfold inLift
      rw [hlim d.line hd, hq, hm, h3]
      have := bl_ok d.mask h4 m
      simp only [Option.map_some, bne_self_eq_false, Bool.false_or]
      rw [Bool.eq_iff_iff]
      simpa using this
    · have hq' : (b[d.line].pay != b[i].pay) = true := bne_iff_ne.2 hq
      simp only [h1, e3, hq', Bool.true_or]
  have hbyp : ∀ i (hi : i < b.length), x.bypassed rs b[i].pay = bypOf L pHe pB (L.lines[i]!.pay) := by
    intro i hi
    obtain ⟨-, hr, hb⟩ := hpay i hi
    unfold Ix.bypassed bypOf
    rw [hr, hb, E3 i hi]
    cases hl : x.byp.lookup b[i].pay with
    | none => simp
    | some m =>
      rw [E4 i hi m hl]
      simp
  have hlf : ∀ d r, r ∈ rs → d.line < b.length → DecOK L d r →
      liftOf L pH pA pL d.line L.lines[d.line]!.pay = x.limitedPay rs r.line.pay := by
    intro d r hr hd hdok
    obtain ⟨h1, -, -, -⟩ := pair_facts L b hsrc hdok hd
    have hpr : r.line.pay = b[d.line].pay := by rw [h1]
    have hany : (rs.any fun r' => r'.line.pay == b[d.line].pay) = true := List.any_eq_true.2 ⟨r, hr, by simp [hpr]⟩
    have hpo := payOutcome_allow x rs _ r hr hpr
    unfold liftOf
    rw [hpr, hlim d.line hd, (hpay d.line hd).2.1]
    cases hl : x.lim.lookup b[d.line].pay with
    | none => simp [Ix.limitedPay, hl]
    | some m =>
      rw [E5 d.line hd m hl, E1 d.line hd, E2 d.line hd]
      unfold Ix.limitedPay
      rw [hl]
      exact lift_bool _ _ _ _ _ _ hpo hany
  have hrel : ∀ d r, r ∈ rs → d.line < b.length → DecOK L d r →
      relPr L own pH pA pHe pB pL d = ((r.outcome == Outcome.ALLOW && !x.redo.contains r.line.pay &&
        x.payOutcome rs r.line.pay == Outcome.ALLOW) || x.bypassed rs r.line.pay ||
        x.limitedPay rs r.line.pay && !x.own r.line) := by
    intro d r hr hd hdok
    obtain ⟨h1, h2, -, -⟩ := pair_facts L b hsrc hdok hd
    have hpr : r.line.pay = b[d.line].pay := by rw [h1]
    have hon : x.own r.line = own[d.line]! := by rw [h1, hown d.line hd]
    rw [← hlf d r hr hd hdok, hon]
    rw [hpr, payOutcome_allow x rs _ r hr hpr, hbyp d.line hd, ← E1 d.line hd, ← E2 d.line hd, h2, out8_allow]
    unfold relPr
    rw [(hpay d.line hd).2.1]
    simp [Bool.and_assoc]
  have hunr : ∀ d r, r ∈ rs → d.line < b.length → DecOK L d r →
      unrPr L own held pH pA pHe pB pL d = (r.outcome != Outcome.ALLOW && !r.reasons.contains Reason.ALREADY_DECIDED &&
        !x.own r.line && !x.ownU r.line && !x.bypassed rs r.line.pay && !x.limitedPay rs r.line.pay) := by
    intro d r hr hd hdok
    obtain ⟨h1, h2, h3, -⟩ := pair_facts L b hsrc hdok hd
    have hpr : r.line.pay = b[d.line].pay := by rw [h1]
    rw [← hlf d r hr hd hdok]
    rw [hpr, hbyp d.line hd, h2, h3, mask_already, h1]
    unfold unrPr Ix.ownU
    rw [hown d.line hd, hheld d.line hd, (hpay d.line hd).2.2]
    simp [bne, out8_allow, bAlready, Bool.and_assoc]
  refine ⟨?_, ?_⟩
  · unfold Ix.releasedLines
    exact allok_fm L (fun d => d.line < b.length) _ _ _ _ new rs hall hlt
      (fun d r hr hd hdok => ⟨hrel d r hr hd hdok, hdok.1⟩)
  · unfold Ix.unresolvedLines
    exact allok_fm L (fun d => d.line < b.length) _ _ _ _ new rs hall hlt
      (fun d r hr hd hdok => ⟨hunr d r hr hd hdok, hdok.1⟩)

theorem rep_get (n p : Nat) (v : Bool) (h : p < n) : (Array.replicate n v)[p]! = v := by
  rw [getElem!_pos _ p (by simpa using h)]; simp

theorem ite_pair_gen (c1 c2 : Bool) (s1 s2 : Array Nat) (n : Nat) :
    (if c1 = true then (if c2 = true then pure (ForInStep.yield (s1.push n, s2.push n))
        else pure (ForInStep.yield (s1.push n, s2)))
      else (if c2 = true then pure (ForInStep.yield (s1, s2.push n)) else pure (ForInStep.yield (s1, s2))) :
        Id (ForInStep (Array Nat × Array Nat))) =
      pure (ForInStep.yield ((if c1 = true then s1.push n else s1), (if c2 = true then s2.push n else s2))) := by
  cases c1 <;> cases c2 <;> rfl

/-- The first element of a `filterMap` of a list rising in `κ` has the least `κ` among those `g` keeps. -/
theorem head_fm_some {α β : Type} (κ : α → Nat) (g : α → Option β) : ∀ (l : List α),
    l.Pairwise (fun p q => κ p < κ q) → ∀ v, (l.filterMap g).head? = some v →
      ∃ q ∈ l, g q = some v ∧ ∀ q' ∈ l, (g q').isSome = true → κ q ≤ κ q'
  | [], _, v, h => by simp at h
  | p :: t, hl, v, h => by
    have hp := List.pairwise_cons.mp hl
    cases hg : g p with
    | some w =>
      rw [List.filterMap_cons_some hg] at h
      simp only [List.head?_cons, Option.some.injEq] at h
      subst h
      exact ⟨p, List.mem_cons_self .., hg, fun q' hq' _ => by
        rcases List.mem_cons.1 hq' with rfl | hq'
        · exact Nat.le_refl _
        · exact Nat.le_of_lt (hp.1 q' hq')⟩
    | none =>
      rw [List.filterMap_cons_none hg] at h
      obtain ⟨q, hq, hgq, hmin⟩ := head_fm_some κ g t hp.2 v h
      refine ⟨q, List.mem_cons_of_mem _ hq, hgq, fun q' hq' hs => ?_⟩
      rcases List.mem_cons.1 hq' with rfl | hq'
      · simp [hg] at hs
      · exact hmin q' hq' hs

theorem head_fm_none {α β : Type} (g : α → Option β) : ∀ (l : List α),
    (l.filterMap g).head? = none → ∀ q ∈ l, g q = none
  | [], _, q, hq => by simp at hq
  | p :: t, h, q, hq => by
    cases hg : g p with
    | some w => rw [List.filterMap_cons_some hg] at h; simp at h
    | none =>
      rw [List.filterMap_cons_none hg] at h
      rcases List.mem_cons.1 hq with rfl | hq
      · exact hg
      · exact head_fm_none g t h q hq

/-- One slot's contribution to the earliest-counterpart chain: its code and `seq`, a posting of `H` that passes `pred`
    with the least `seq`, or nothing when none passes. -/
def Good (L : Lay) (H : List Posting) (pred : Line → Bool) (o : Option (Nat × Nat)) : Prop :=
  (o = none ∧ ∀ q ∈ H, pred q.row = false) ∨
    ∃ c q, o = some (c, q.seq) ∧ c ≠ 0 ∧ cpId L c = some q.row.id ∧ q ∈ H ∧ pred q.row = true ∧
      ∀ q' ∈ H, pred q'.row = true → q.seq ≤ q'.seq

def stepC (o : Option (Nat × Nat)) (acc : Nat × Nat) : Nat × Nat :=
  match o with
  | none => acc
  | some (c, q) => if acc.1 == 0 || q < acc.2 then (c, q) else acc

def ChainInv (L : Lay) (X : List Posting) (pred : Line → Bool) (acc : Nat × Nat) : Prop :=
  (acc.1 = 0 ∧ ∀ q ∈ X, pred q.row = false) ∨
    (acc.1 ≠ 0 ∧ ∃ q ∈ X, pred q.row = true ∧ cpId L acc.1 = some q.row.id ∧ acc.2 = q.seq ∧
      ∀ q' ∈ X, pred q'.row = true → q.seq ≤ q'.seq)

theorem chain_step (L : Lay) (X H : List Posting) (pred : Line → Bool) (acc : Nat × Nat) (o : Option (Nat × Nat))
    (hi : ChainInv L X pred acc) (hg : Good L H pred o) : ChainInv L (X ++ H) pred (stepC o acc) := by
  rcases hg with ⟨rfl, hn⟩ | ⟨c, q, rfl, hc, hid, hqH, hpq, hmin⟩
  · simp only [stepC]
    rcases hi with ⟨h0, hX⟩ | ⟨h0, w, hw, hpw, hidw, hs, hmw⟩
    · exact Or.inl ⟨h0, fun q hq => by
        rcases List.mem_append.1 hq with h | h
        · exact hX q h
        · exact hn q h⟩
    · refine Or.inr ⟨h0, w, List.mem_append_left _ hw, hpw, hidw, hs, fun q' hq' hp' => ?_⟩
      rcases List.mem_append.1 hq' with h | h
      · exact hmw q' h hp'
      · simp [hn q' h] at hp'
  · simp only [stepC]
    rcases hi with ⟨h0, hX⟩ | ⟨h0, w, hw, hpw, hidw, hs, hmw⟩
    · simp only [h0, beq_self_eq_true, Bool.true_or, ↓reduceIte]
      refine Or.inr ⟨hc, q, List.mem_append_right _ hqH, hpq, hid, rfl, fun q' hq' hp' => ?_⟩
      rcases List.mem_append.1 hq' with h | h
      · simp [hX q' h] at hp'
      · exact hmin q' h hp'
    · have h0' : (acc.1 == 0) = false := by simpa using h0
      simp only [h0', Bool.false_or]
      by_cases hlt : q.seq < acc.2
      · simp only [hlt, decide_true, ↓reduceIte]
        refine Or.inr ⟨hc, q, List.mem_append_right _ hqH, hpq, hid, rfl, fun q' hq' hp' => ?_⟩
        rcases List.mem_append.1 hq' with h | h
        · have := hmw q' h hp'; omega
        · exact hmin q' h hp'
      · simp only [hlt, decide_false, Bool.false_eq_true, ↓reduceIte]
        refine Or.inr ⟨h0, w, List.mem_append_left _ hw, hpw, hidw, hs, fun q' hq' hp' => ?_⟩
        rcases List.mem_append.1 hq' with h | h
        · exact hmw q' h hp'
        · have := hmin q' h hp'; omega

theorem chain3 (L : Lay) (A B C : List Posting) (pred : Line → Bool) (o1 o2 o3 : Option (Nat × Nat))
    (h1 : Good L A pred o1) (h2 : Good L B pred o2) (h3 : Good L C pred o3) :
    ChainInv L (A ++ B ++ C) pred (stepC o3 (stepC o2 (stepC o1 (0, 0)))) := by
  have h0 : ChainInv L [] pred (0, 0) := Or.inl ⟨rfl, by simp⟩
  have e1 := chain_step L [] A pred _ _ h0 h1
  have e2 := chain_step L _ B pred _ _ e1 h2
  have e3 := chain_step L _ C pred _ _ e2 h3
  simpa using e3

theorem slice_head {α : Type} [Inhabited α] (a : Array α) (s n : Nat) (x : α) (xs : List α)
    (h : (a.toList.drop s).take n = x :: xs) : a[s]! = x := by
  have h0 := congrArg (fun l => l[0]?) h
  simp only [List.getElem?_take, List.getElem?_drop, List.getElem?_cons_zero ] at h0
  have hn : 0 < n := by
    rcases Nat.eq_zero_or_pos n with rfl | hn
    · simp at h
    · exact hn
  simp only [hn, ↓reduceIte] at h0
  have h1 : a[s]? = some x := by simpa using h0
  rw [getElem!_pos a s (by have := (Array.getElem?_eq_some_iff.1 h1).1; exact this)]
  exact Option.some.inj ((Array.getElem?_eq_getElem (Array.getElem?_eq_some_iff.1 h1).1).symm.trans h1)


theorem unrC_eq (x : Lay) (cc : Array Bool) (r : RowX) (k : Nat) (acc : Nat × Nat) :
    unrC x cc r k acc = stepC (match (List.range' x.slots[k]!.us x.slots[k]!.un).find?
        (fun j => r.exactEq x.unrP[j]! || r.idEq x.unrP[j]! || !cc[j]! && r.nearEq x.unrP[j]!) with
      | none => none
      | some j => some (2 * j + 2, x.unrSeq[j]!)) acc := by
  unfold unrC
  simp only [Id.run, Std.Legacy.Range.forIn_eq_forIn_range', Std.Legacy.Range.size]
  have hn : (x.slots[k]!.us + x.slots[k]!.un - x.slots[k]!.us + 1 - 1) / 1 = x.slots[k]!.un := by omega
  rw [hn]
  generalize List.range' x.slots[k]!.us x.slots[k]!.un = l
  induction l with
  | nil => simp [stepC]; rfl
  | cons j t ih =>
    by_cases h : (r.exactEq x.unrP[j]! || r.idEq x.unrP[j]! || !cc[j]! && r.nearEq x.unrP[j]!) = true
    · simp only [List.forIn_cons, h, ↓reduceIte, List.find?_cons_of_pos]
      simp only [stepC]
      rfl
    · have h' : (r.exactEq x.unrP[j]! || r.idEq x.unrP[j]! || !cc[j]! && r.nearEq x.unrP[j]!) = false := by simpa using h
      simp only [List.forIn_cons, h', Bool.false_eq_true, ↓reduceIte, List.find?_cons]
      exact ih

theorem relC_eq (x : Lay) (k : Nat) (acc : Nat × Nat) :
    relC x k acc = stepC (if x.slots[k]!.rn > 0 then some (2 * x.slots[k]!.rs + 1, x.relSeq[x.slots[k]!.rs]!) else none) acc := by
  unfold relC
  by_cases h : x.slots[k]!.rn > 0 <;> simp [h, stepC]


theorem find_par (J : List Nat) (src : Nat → Line) (sq : Nat → Nat) (Q : Line → Bool) :
    ∀ (H : List Posting), H.Pairwise (fun p q => p.seq < q.seq) → J.map src = H.map (·.row) → J.map sq = H.map (·.seq) →
    (J.find? (fun j => Q (src j)) = none ∧ ∀ q ∈ H, Q q.row = false) ∨
      ∃ j q, J.find? (fun j => Q (src j)) = some j ∧ q ∈ H ∧ src j = q.row ∧ sq j = q.seq ∧ Q q.row = true ∧
        ∀ q' ∈ H, Q q'.row = true → q.seq ≤ q'.seq := by
  induction J with
  | nil =>
    intro H _ h1 _
    have : H = [] := by simpa using h1.symm
    subst this
    exact Or.inl ⟨rfl, by simp⟩
  | cons j J ih =>
    intro H hp h1 h2
    cases H with
    | nil => simp at h1
    | cons q0 H' =>
      simp only [List.map_cons, List.cons.injEq] at h1 h2
      have hpw := List.pairwise_cons.mp hp
      by_cases hq : Q q0.row = true
      · refine Or.inr ⟨j, q0, ?_, List.mem_cons_self .., h1.1, h2.1, hq, fun q' hq' _ => ?_⟩
        · simp [h1.1, hq]
        · rcases List.mem_cons.1 hq' with rfl | h
          · exact Nat.le_refl _
          · exact Nat.le_of_lt (hpw.1 q' h)
      · have hq' : Q q0.row = false := by simpa using hq
        have hqj : Q (src j) = false := by rw [h1.1]; exact hq'
        rcases ih H' hpw.2 h1.2 h2.2 with ⟨hn, hall⟩ | ⟨j', q, hf, hqm, hs, hsq, hQ, hmin⟩
        · refine Or.inl ⟨by simp [hqj, hn], fun q' hq'' => ?_⟩
          rcases List.mem_cons.1 hq'' with rfl | h
          · exact hq'
          · exact hall q' h
        · refine Or.inr ⟨j', q, by simp [hqj, hf], List.mem_cons_of_mem _ hqm, hs, hsq, hQ, fun q' hq'' hQ' => ?_⟩
          rcases List.mem_cons.1 hq'' with rfl | h
          · simp [hq'] at hQ'
          · exact hmin q' h hQ'

theorem key_ne (l y : Line) : exactKey l ≠ nearKey y ∧ exactKey l ≠ idKey y ∧ nearKey l ≠ exactKey y ∧
    nearKey l ≠ idKey y ∧ idKey l ≠ exactKey y ∧ idKey l ≠ nearKey y := by
  refine ⟨?_, ?_, ?_, ?_, ?_, ?_⟩ <;> intro h <;> simp only [exactKey, nearKey, idKey] at h <;> (repeat' split at h) <;>
    simp at h

theorem predL_eq (x : Ix) (l y : Line) (hl : fitsLine2 l = true) (hy : fitsLine2 y = true) :
    (keys l).any (x.claim y).contains =
      ((RowX.of l).exactEq (RowX.of y) || (RowX.of l).idEq (RowX.of y) ||
        !(isCap y && x.notEnrolled y && !x.own y) && (RowX.of l).nearEq (RowX.of y)) := by
  obtain ⟨n1, n2, n3, n4, n5, n6⟩ := key_ne l y
  have e1 : (RowX.of l).exactEq (RowX.of y) = decide (exactKey l = exactKey y) := by
    rw [Bool.eq_iff_iff]; simpa using Engine3.rowX_exactEq_iff l y hl hy
  have e2 : (RowX.of l).idEq (RowX.of y) = decide (idKey l = idKey y) := by
    rw [Bool.eq_iff_iff]; simpa using Engine3.rowX_idEq_iff l y hl hy
  have e3 : (RowX.of l).nearEq (RowX.of y) = decide (nearKey l = nearKey y) := by
    rw [Bool.eq_iff_iff]; simpa using Engine3.rowX_nearEq_iff l y hl hy
  rw [e1, e2, e3]
  unfold Ix.claim
  by_cases hc : (isCap y && x.notEnrolled y && !x.own y) = true
  · rw [if_pos hc, hc]
    simp [keys, n2, n3, n4, n5]
  · have hc' : (isCap y && x.notEnrolled y && !x.own y) = false := by simpa using hc
    rw [if_neg hc, hc']
    simp [keys, n1, n2, n3, n4, n5, n6]
    generalize decide (exactKey l = exactKey y) = a
    generalize decide (nearKey l = nearKey y) = c
    generalize decide (idKey l = idKey y) = d
    cases a <;> cases c <;> cases d <;> rfl

theorem forIn_eq_foldl {α β : Type} (l : List α) (init : β) (F : α → β → Id (ForInStep β)) (g : α → β → β)
    (h : ∀ a st, F a st = pure (ForInStep.yield (g a st))) : forIn (m := Id) l init F = l.foldl (fun st a => g a st) init := by
  obtain ⟨r, er, hr⟩ := forIn_inv l init F (fun pre st => st = pre.foldl (fun st a => g a st) init) rfl
    (fun pre a post st _ hp => ⟨_, h a st, by subst hp; simp [List.foldl_append]⟩)
  rw [er, hr]

/-- What the head of a list of hits says: nothing passes, or the id of a posting of `U` that passes with the least
    `seq`. -/
def HeadSpec (U : List Posting) (P : Line → Bool) (o : Option Nat) : Prop :=
  (o = none ∧ ∀ q ∈ U, P q.row = false) ∨
    ∃ v q, o = some v ∧ q ∈ U ∧ P q.row = true ∧ q.row.id = v ∧ ∀ q' ∈ U, P q'.row = true → q.seq ≤ q'.seq

theorem rr_mono (rr : List Posting) (hpw : rr.Pairwise (fun p q => p.seq < q.seq)) (i j : Nat) (q q' : Posting)
    (h : i ≤ j) (hi : rr[i]? = some q) (hj : rr[j]? = some q') : q.seq ≤ q'.seq := by
  rcases Nat.eq_or_lt_of_le h with rfl | hlt
  · rw [hi] at hj; cases Option.some.inj hj; exact Nat.le_refl _
  · obtain ⟨hi1, hi2⟩ := List.getElem?_eq_some_iff.1 hi
    obtain ⟨hj1, hj2⟩ := List.getElem?_eq_some_iff.1 hj
    have := List.pairwise_iff_getElem.1 hpw i j hi1 hj1 hlt
    rw [hi2, hj2] at this
    exact Nat.le_of_lt this

theorem hits_abs (U rr : List Posting) (post : HashMap Key (List Nat)) (ks' : List Key) (P : Line → Bool)
    (hpw : rr.Pairwise (fun p q => p.seq < q.seq))
    (hrow : ∀ q ∈ rr, ∀ p ∈ U, q.seq = p.seq → q.row = p.row)
    (hcover : ∀ p ∈ U, ∃ q ∈ rr, q.seq = p.seq)
    (hmem : ∀ i, i ∈ ks'.flatMap (post.getD · []) ↔ ∃ p ∈ U, ∃ q, rr[i]? = some q ∧ q.seq = p.seq) :
    HeadSpec U P (hits (rr.map (·.row)).toArray post ks' P).head? := by
  have hM := List.pairwise_mergeSort (le := fun i j : Nat => decide (i ≤ j))
    (fun a b c h1 h2 => by simp at *; omega) (fun a b => by simp; omega) (ks'.flatMap (post.getD · []))
  have hM' : ((ks'.flatMap (post.getD · [])).mergeSort fun i j : Nat => decide (i ≤ j)).Pairwise (· ≤ ·) :=
    hM.imp (fun h => by simpa using h)
  obtain ⟨d1, d2⟩ := dedup_spec _ hM'
  have hPm : ∀ i, i ∈ dedup ((ks'.flatMap (post.getD · [])).mergeSort fun i j : Nat => decide (i ≤ j)) ↔
      ∃ p ∈ U, ∃ q, rr[i]? = some q ∧ q.seq = p.seq := fun i => by
    rw [d1, (List.mergeSort_perm _ _).mem_iff]; exact hmem i
  unfold hits
  generalize dedup ((ks'.flatMap (post.getD · [])).mergeSort fun i j : Nat => decide (i ≤ j)) = Ps at hPm d2
  rcases hh : (Ps.filterMap fun i => (rr.map (·.row)).toArray[i]?.bind fun y => if P y then some y.id else none).head? with _ | v
  · left
    refine ⟨hh, fun p hp => ?_⟩
    have hn := head_fm_none _ Ps hh
    obtain ⟨q, hq, hs⟩ := hcover p hp
    obtain ⟨i, hi⟩ := List.mem_iff_getElem?.mp hq
    have hiP : i ∈ Ps := (hPm i).2 ⟨p, hp, q, hi, hs⟩
    have h1 := hn i hiP
    have h2 : P q.row = false := by
      cases hc : P q.row
      · rfl
      · simp [hi, hc] at h1
    rw [← hrow q hq p hp hs]; exact h2
  · right
    obtain ⟨i, hiP, hgi, hmin⟩ := head_fm_some (fun i => i) _ Ps d2 v hh
    obtain ⟨p0, hp0, q, hq, hs⟩ := (hPm i).1 hiP
    have hqr : q ∈ rr := List.mem_of_getElem? hq
    have e0 := hrow q hqr p0 hp0 hs
    have hPq : P q.row = true ∧ q.row.id = v := by
      by_cases hc : P q.row = true
      · simp [hq, hc] at hgi; exact ⟨hc, hgi⟩
      · simp [hq, hc] at hgi
    refine ⟨v, p0, hh, hp0, by rw [← e0]; exact hPq.1, by rw [← e0]; exact hPq.2, fun q' hq' hPq' => ?_⟩
    obtain ⟨q'', hq'', hs''⟩ := hcover q' hq'
    obtain ⟨i'', hi''⟩ := List.mem_iff_getElem?.mp hq''
    have hi''P : i'' ∈ Ps := (hPm i'').2 ⟨q', hq', q'', hi'', hs''⟩
    have e1 := hrow q'' hq'' q' hq' hs''
    have hsome : ((fun i => (rr.map (·.row)).toArray[i]?.bind fun y => if P y then some y.id else none) i'').isSome = true := by
      simp [hi'', e1, hPq']
    have hle := hmin i'' hi''P hsome
    have := rr_mono rr hpw i i'' q q'' hle hq hi''
    omega

theorem hits_head {H : Bytes → Bytes} {S : SetIdx} {snap : Snapshot Line} (hS : IdxInv H S snap) (ks ks' : List Key)
    (hsub : ∀ k ∈ ks', k ∈ ks) (P : Line → Bool) :
    HeadSpec (ks'.flatMap fun k => heads (S.get k)) P
      (hits ((localRows (ks.map fun k => (k, S.get k))).map (·.row)).toArray
        (postMap (localRows (ks.map fun k => (k, S.get k))) (ks.map fun k => (k, S.get k))) ks' P).head? := by
  obtain ⟨L, hL⟩ : ∃ L, L = (ks.map fun k => (k, S.get k)).flatMap fun ke => heads ke.2 := ⟨_, rfl⟩
  have hLm : ∀ p, p ∈ L ↔ ∃ k' ∈ ks, p ∈ heads (S.get k') := by
    intro p
    rw [hL]
    simp only [List.mem_flatMap, List.mem_map]
    constructor
    · rintro ⟨ke, ⟨k', hk', rfl⟩, hp⟩; exact ⟨k', hk', hp⟩
    · rintro ⟨k', hk', hp⟩; exact ⟨(k', S.get k'), ⟨k', hk', rfl⟩, hp⟩
  have hLrow : ∀ p ∈ L, snap.entries[p.seq]? = some p.row := fun p hp => by
    obtain ⟨k', -, hp'⟩ := (hLm p).mp hp
    exact heads_row hS hp'
  have hM := List.pairwise_mergeSort (le := fun p q : Posting => decide (p.seq ≤ q.seq))
    (fun a b c h1 h2 => by simp at *; omega) (fun a b => by simp; omega) L
  have hM' : (L.mergeSort fun p q : Posting => decide (p.seq ≤ q.seq)).Pairwise (fun p q => p.seq ≤ q.seq) :=
    hM.imp (fun h => by simpa using h)
  have hMm : ∀ p, p ∈ L.mergeSort (fun p q : Posting => decide (p.seq ≤ q.seq)) ↔ p ∈ L := fun p =>
    (List.mergeSort_perm L _).mem_iff
  obtain ⟨i1, i2, i3⟩ := dedupSeq_spec _ hM'
  have hrr : localRows (ks.map fun k => (k, S.get k)) =
      dedupSeq (L.mergeSort fun p q : Posting => decide (p.seq ≤ q.seq)) := by
    unfold localRows; rw [← hL]
  rw [hrr]
  generalize dedupSeq (L.mergeSort fun p q : Posting => decide (p.seq ≤ q.seq)) = rr at i1 i2 i3 ⊢
  have hU : ∀ p ∈ (ks'.flatMap fun k => heads (S.get k)), p ∈ L := fun p hp => by
    obtain ⟨k, hk, hp'⟩ := List.mem_flatMap.1 hp
    exact (hLm p).2 ⟨k, hsub k hk, hp'⟩
  have hposiff : ∀ s i, (rr.foldl (fun (acc : Std.HashMap Nat Nat × Nat) p => (acc.1.insert p.seq acc.2, acc.2 + 1))
      (∅, 0)).1.get? s = some i ↔ ∃ q, rr[i]? = some q ∧ q.seq = s := by
    intro s i
    rw [Std.HashMap.get?_eq_getElem?, pos_foldl rr ∅ 0 i2]
    simp
  have hpost : ∀ k ∈ ks, (postMap rr (ks.map fun k => (k, S.get k))).getD k [] =
      (heads (S.get k)).filterMap fun p =>
        (rr.foldl (fun (acc : Std.HashMap Nat Nat × Nat) p => (acc.1.insert p.seq acc.2, acc.2 + 1)) (∅, 0)).1.get? p.seq := by
    intro k hk
    unfold postMap
    rw [List.foldl_map, foldl_insert_getD (fun k => (heads (S.get k)).filterMap fun p =>
      (rr.foldl (fun (acc : Std.HashMap Nat Nat × Nat) p => (acc.1.insert p.seq acc.2, acc.2 + 1)) (∅, 0)).1.get? p.seq) ks,
      if_pos hk]
  refine hits_abs _ rr _ ks' P i2 ?_ ?_ ?_
  · intro q hq p hp hs
    have h1 := hLrow q ((hMm q).1 (i1 q hq) |> fun h => h)
    have h2 := hLrow p (hU p hp)
    rw [hs] at h1
    exact Option.some.inj (h1.symm.trans h2)
  · intro p hp
    exact i3 p ((hMm p).2 (hU p hp))
  · intro i
    rw [List.mem_flatMap]
    constructor
    · rintro ⟨k, hk, hi⟩
      rw [hpost k (hsub k hk)] at hi
      simp only [List.mem_filterMap] at hi
      obtain ⟨p, hp, hpi⟩ := hi
      obtain ⟨q, hq1, hq2⟩ := (hposiff _ _).1 hpi
      exact ⟨p, List.mem_flatMap.2 ⟨k, hk, hp⟩, q, hq1, hq2⟩
    · rintro ⟨p, hp, q, hq1, hq2⟩
      obtain ⟨k, hk, hp'⟩ := List.mem_flatMap.1 hp
      refine ⟨k, hk, ?_⟩
      rw [hpost k (hsub k hk)]
      simp only [List.mem_filterMap]
      exact ⟨p, hp', (hposiff _ _).2 ⟨q, hq1, hq2⟩⟩

theorem find_congr (J : List Nat) (p q : Nat → Bool) (h : ∀ j ∈ J, p j = q j) : J.find? p = J.find? q := by
  induction J with
  | nil => rfl
  | cons a t ih =>
    have ha := h a (List.mem_cons_self ..)
    simp only [List.find?_cons, ha]
    split
    · rfl
    · exact ih (fun j hj => h j (List.mem_cons_of_mem _ hj))

theorem nat_get_eq (a : Array Nat) (j : Nat) : a[j]! = a.getD j 0 := by
  rcases Nat.lt_or_ge j a.size with h | h
  · rw [getElem!_pos a j h]; simp [Array.getD_eq_getD_getElem?, Array.getElem?_eq_getElem h]
  · rw [getElem!_neg a j (by omega)]; simp [Array.getD_eq_getD_getElem?, Array.getElem?_eq_none (by omega)]

theorem slice_some {α : Type} (a : Array α) (s n : Nat) (x : α) (xs : List α)
    (h : (a.toList.drop s).take n = x :: xs) : a[s]? = some x := by
  have h0 := congrArg (fun l => l[0]?) h
  simp only [List.getElem?_take, List.getElem?_drop, List.getElem?_cons_zero] at h0
  have hn : 0 < n := by
    rcases Nat.eq_zero_or_pos n with rfl | hn
    · simp at h
    · exact hn
  simp only [hn, ↓reduceIte] at h0
  simpa using h0

theorem slice_getD {α : Type} (a : Array α) (s n : Nat) (x : α) (xs : List α) (d : α)
    (h : (a.toList.drop s).take n = x :: xs) : a.getD s d = x := by
  simp [Array.getD_eq_getD_getElem?, slice_some a s n x xs h]

theorem heads_rise {H : Bytes → Bytes} {S : SetIdx} {snap : Snapshot Line} (hS : IdxInv H S snap) (k : Key) :
    (heads (S.get k)).Pairwise (fun p q => p.seq < q.seq) := by
  have h := (entryOf_count H snap.entries k).2
  rw [hS.2 k]; unfold heads; rw [h, List.take_take, Nat.min_self]
  exact (pairwise_postingsFrom (k := k) snap.entries 0).sublist (List.take_sublist _ _)

theorem rows_agree {H : Bytes → Bytes} {S : SetIdx} {snap : Snapshot Line} (hS : IdxInv H S snap) (ks : List Key) :
    ∀ p ∈ ks.flatMap (fun k => heads (S.get k)), ∀ q ∈ ks.flatMap (fun k => heads (S.get k)),
      p.seq = q.seq → p.row = q.row := by
  intro p hp q hq hs
  obtain ⟨k1, -, h1⟩ := List.mem_flatMap.1 hp
  obtain ⟨k2, -, h2⟩ := List.mem_flatMap.1 hq
  have a := heads_row hS h1
  have c := heads_row hS h2
  rw [hs] at a
  exact Option.some.inj (a.symm.trans c)

theorem HeadSpec_pred {U : List Posting} {P P' : Line → Bool} {o : Option Nat}
    (hP : ∀ q ∈ U, P q.row = P' q.row) (h : HeadSpec U P o) : HeadSpec U P' o := by
  rcases h with ⟨ho, hn⟩ | ⟨v, q, ho, hq, hp, hv, hmin⟩
  · exact Or.inl ⟨ho, fun q hq => by rw [← hP q hq]; exact hn q hq⟩
  · exact Or.inr ⟨v, q, ho, hq, by rw [← hP q hq]; exact hp, hv,
      fun q' hq' h' => hmin q' hq' (by rw [hP q' hq']; exact h')⟩

theorem spec_match (L : Lay) (X U : List Posting) (P : Line → Bool) (acc : Nat × Nat) (o : Option Nat)
    (hc : ChainInv L X P acc) (hs : HeadSpec U P o) (hm : ∀ q, q ∈ X ↔ q ∈ U)
    (hrows : ∀ p ∈ U, ∀ q ∈ U, p.seq = q.seq → p.row = q.row) :
    (acc.1 = 0 ∧ o = none) ∨ (acc.1 ≠ 0 ∧ cpId L acc.1 = o) := by
  rcases hc with ⟨h0, hX⟩ | ⟨h0, w, hw, hpw, hid, hws, hmw⟩
  · rcases hs with ⟨ho, -⟩ | ⟨v, q, ho, hq, hpq, -, -⟩
    · exact Or.inl ⟨h0, ho⟩
    · have := hX q ((hm q).2 hq)
      exact absurd (hpq.symm.trans this) (by decide)
  · right
    refine ⟨h0, ?_⟩
    rcases hs with ⟨-, hn⟩ | ⟨v, q, ho, hq, hpq, hv, hmin⟩
    · have := hn w ((hm w).1 hw)
      exact absurd (hpw.symm.trans this) (by decide)
    · have h1 := hmw q ((hm q).2 hq) hpq
      have h2 := hmin w ((hm w).1 hw) hpw
      have h3 : w.row = q.row := hrows w ((hm w).1 hw) q hq (by omega)
      rw [hid, ho, ← hv, h3]

theorem cpId_ne (L : Lay) (c : Nat) (h : c ≠ 0) : cpId L c ≠ none := by
  unfold cpId
  have : (c == 0) = false := by simpa using h
  simp only [this, Bool.false_eq_true, ↓reduceIte]
  split <;> simp

theorem cp_combine (L : Lay) (aR aU : Nat × Nat) (oR oU : Option Nat) (lR lU : List Nat)
    (hR : (aR.1 = 0 ∧ oR = none) ∨ (aR.1 ≠ 0 ∧ cpId L aR.1 = oR))
    (hU : (aU.1 = 0 ∧ oU = none) ∨ (aU.1 ≠ 0 ∧ cpId L aU.1 = oU))
    (hoR : oR = lR.head?) (hoU : oU = lU.head?) :
    cpId L (if (aR.1 != 0) = true then aR.1 else aU.1) = (lR ++ lU).head? := by
  rcases hR with ⟨h0, ho⟩ | ⟨h0, hc⟩
  · have e : (aR.1 != 0) = false := by simp [h0]
    rw [e]
    simp only [Bool.false_eq_true, ↓reduceIte]
    have hl : lR = [] := List.head?_eq_none_iff.1 (hoR ▸ ho)
    subst hl
    simp only [List.nil_append]
    rcases hU with ⟨h0', ho'⟩ | ⟨h0', hc'⟩
    · rw [h0', ← hoU, ho']; simp [cpId]
    · rw [hc', hoU]
  · have e : (aR.1 != 0) = true := by simp [h0]
    rw [e]
    simp only [↓reduceIte]
    cases lR with
    | nil => exact absurd (by rw [hc, hoR]; rfl) (cpId_ne L _ h0)
    | cons a t => rw [hc, hoR]; simp

section
variable {H : Bytes → Bytes} {s : St} {fc : FCtx} {f : List Nat} {b : List Line} {rel unr : Snapshot Line}


theorem slot_entry (j : Nat) (hj : j < (fetch s fc.redo b).rel.length) :
    (fetch s fc.redo b).rel[j].2 = s.rel.get (fetch s fc.redo b).rel[j].1 := by
  obtain ⟨k, -, e⟩ := fetch_rel_get (s := s) (fc := fc) (b := b) j hj
  rw [e]

theorem rel_good (R : Rep (layout s fc f b) s fc f b) (hr : IdxInv H s.rel rel) (j : Nat)
    (hj : j < (fetch s fc.redo b).rel.length) :
    Good (layout s fc f b) (heads (fetch s fc.redo b).rel[j].2) (fun _ => true)
      (if (layout s fc f b).slots[j]!.rn > 0 then
        some (2 * (layout s fc f b).slots[j]!.rs + 1, (layout s fc f b).relSeq[(layout s fc f b).slots[j]!.rs]!)
       else none) := by
  have hrise : (heads (fetch s fc.redo b).rel[j].2).Pairwise (fun p q => p.seq < q.seq) := by
    obtain ⟨k, -, e⟩ := fetch_rel_get (s := s) (fc := fc) (b := b) j hj
    rw [e]; exact heads_rise hr k
  obtain ⟨-, -, hrn, -, hseq, hsrc⟩ := R.relSlot j hj
  generalize (fetch s fc.redo b).rel[j].2 = e at hrise hrn hseq hsrc ⊢
  generalize hrs : (layout s fc f b).slots[j]!.rs = rs at *
  generalize hrn' : (layout s fc f b).slots[j]!.rn = rn at *
  by_cases hp : rn > 0
  · rw [if_pos hp]
    cases hh : heads e with
    | nil => rw [hh] at hrn; simp at hrn; omega
    | cons q0 qs =>
      rw [hh] at hseq hsrc hrise
      simp only [List.map_cons] at hseq hsrc
      have hs := slice_head _ _ _ _ _ hseq
      have hg := slice_getD _ _ _ _ _ nilLine hsrc
      right
      have e2 : (2 * rs + 1) % 2 = 1 := by omega
      have e3 : (2 * rs + 1) / 2 = rs := by omega
      refine ⟨2 * rs + 1, q0, by rw [hs], by omega, ?_, List.mem_cons_self .., rfl, ?_⟩
      · simp [cpId, e2, e3, hg]
      · intro q' hq' _
        rcases List.mem_cons.1 hq' with rfl | h
        · exact Nat.le_refl _
        · exact Nat.le_of_lt ((List.pairwise_cons.1 hrise).1 q' h)
  · rw [if_neg hp]
    left
    refine ⟨rfl, ?_⟩
    have : heads e = [] := List.eq_nil_of_length_eq_zero (by omega)
    intro q hq
    rw [this] at hq
    simp at hq

theorem unr_good (R : Rep (layout s fc f b) s fc f b) (hu : IdxInv H s.unr unr)
    (cc : Array Bool)
    (hcc : ∀ j (_ : j < (layout s fc f b).unrP.size), cc[j]! =
      (isCap ((layout s fc f b).unrSrc.getD j nilLine) &&
        (locIx s fc b).notEnrolled ((layout s fc f b).unrSrc.getD j nilLine) &&
        !(locIx s fc b).own ((layout s fc f b).unrSrc.getD j nilLine)))
    (j : Nat) (hj : j < (fetch s fc.redo b).rel.length) (hk : (fetch s fc.redo b).rel[j].1 ∈ probeKeys b) (y : Line) :
    Good (layout s fc f b) (heads (s.unr.get (fetch s fc.redo b).rel[j].1))
      (fun q => (RowX.of y).exactEq (RowX.of q) || (RowX.of y).idEq (RowX.of q) ||
        !(isCap q && (locIx s fc b).notEnrolled q && !(locIx s fc b).own q) && (RowX.of y).nearEq (RowX.of q))
      (match (List.range' (layout s fc f b).slots[j]!.us (layout s fc f b).slots[j]!.un).find?
          (fun j' => (RowX.of y).exactEq (layout s fc f b).unrP[j']! || (RowX.of y).idEq (layout s fc f b).unrP[j']! ||
            !cc[j']! && (RowX.of y).nearEq (layout s fc f b).unrP[j']!) with
        | none => none
        | some j' => some (2 * j' + 2, (layout s fc f b).unrSeq[j']!)) := by
  have h := R.unrSlot j hj
  have hl' : (fetch s fc.redo b).unr.lookup (fetch s fc.redo b).rel[j].1 =
      some (s.unr.get (fetch s fc.redo b).rel[j].1) :=
    lookup_map (g := fun k => s.unr.get k) (ks := probeKeys b) hk
  simp only [hl'] at h
  obtain ⟨-, hn, h1, h2, h3⟩ := h
  have hrise := heads_rise hu (fetch s fc.redo b).rel[j].1
  have hjs : j < (layout s fc f b).slots.size := by rw [R.nslots]; exact hj
  have hbnd := fun g hg => slot_unr_bnd R j hjs g hg
  generalize s.unr.get (fetch s fc.redo b).rel[j].1 = e at hrise hn h1 h2 h3 ⊢
  have hJ1 : (List.range' (layout s fc f b).slots[j]!.us (layout s fc f b).slots[j]!.un).map
      (fun j' => (layout s fc f b).unrSrc.getD j' nilLine) = (heads e).map (·.row) :=
    range_getD _ nilLine _ _ _ h3 (by simp [hn])
  have hJ2 : (List.range' (layout s fc f b).slots[j]!.us (layout s fc f b).slots[j]!.un).map
      (fun j' => (layout s fc f b).unrSeq.getD j' 0) = (heads e).map (·.seq) :=
    range_getD _ 0 _ _ _ h2 (by simp [hn])
  have hf := find_par (List.range' (layout s fc f b).slots[j]!.us (layout s fc f b).slots[j]!.un)
    (fun j' => (layout s fc f b).unrSrc.getD j' nilLine) (fun j' => (layout s fc f b).unrSeq.getD j' 0)
    (fun q => (RowX.of y).exactEq (RowX.of q) || (RowX.of y).idEq (RowX.of q) ||
        !(isCap q && (locIx s fc b).notEnrolled q && !(locIx s fc b).own q) && (RowX.of y).nearEq (RowX.of q))
    (heads e) hrise hJ1 hJ2
  have hfind := find_congr (List.range' (layout s fc f b).slots[j]!.us (layout s fc f b).slots[j]!.un)
    (fun j' => (RowX.of y).exactEq (layout s fc f b).unrP[j']! || (RowX.of y).idEq (layout s fc f b).unrP[j']! ||
            !cc[j']! && (RowX.of y).nearEq (layout s fc f b).unrP[j']!)
    (fun j' => (fun q => (RowX.of y).exactEq (RowX.of q) || (RowX.of y).idEq (RowX.of q) ||
        !(isCap q && (locIx s fc b).notEnrolled q && !(locIx s fc b).own q) && (RowX.of y).nearEq (RowX.of q))
      ((layout s fc f b).unrSrc.getD j' nilLine))
    (fun j' hj' => by
      have hlt := hbnd j' hj'
      simp only [R.unrRowX j' hlt, hcc j' hlt])
  rw [hfind]
  rcases hf with ⟨hnone, hall⟩ | ⟨j', q, hfs, hqH, hsrc, hsq, hQ, hmin⟩
  · left
    rw [hnone]
    exact ⟨rfl, hall⟩
  · right
    rw [hfs]
    have e2 : (2 * j' + 2) % 2 = 0 := by omega
    have e3 : (2 * j' + 2) / 2 - 1 = j' := by omega
    refine ⟨2 * j' + 2, q, ?_, by omega, ?_, hqH, hQ, hmin⟩
    · dsimp only
      rw [← hsq, nat_get_eq]
    · simp [cpId, e2, hsrc]

theorem cp_link (R : Rep (layout s fc f b) s fc f b) (hr : IdxInv H s.rel rel) (hu : IdxInv H s.unr unr)
    (hwu : ∀ l ∈ unr.entries, fitsLine2 l = true)
    (hbf : ∀ l ∈ b, fitsLine2 l = true) (cc : Array Bool)
    (hcc : ∀ j (_ : j < (layout s fc f b).unrP.size), cc[j]! =
      (isCap ((layout s fc f b).unrSrc.getD j nilLine) &&
        (locIx s fc b).notEnrolled ((layout s fc f b).unrSrc.getD j nilLine) &&
        !(locIx s fc b).own ((layout s fc f b).unrSrc.getD j nilLine)))
    (i : Nat) (hi : i < b.length) :
    cpId (layout s fc f b) (cpOf (layout s fc f b) cc i) = ((locIx s fc b).counterparts b[i]).head? := by
  have hbi : b[i] ∈ b := List.getElem_mem hi
  obtain ⟨h1, h2, h3, e1, e2, e3⟩ := key_slot R i hi
  have hrow := line_row R i hi
  have hfitb : fitsLine2 b[i] = true := hbf _ hbi
  have hsubU : ∀ k ∈ keys b[i], k ∈ probeKeys b := fun k hk => mem_probeKeys.mpr ⟨b[i], hbi, hk⟩
  have hsubR : ∀ k ∈ keys b[i], k ∈ ksR s fc.redo b := fun k hk => mem_ksR_of_probe (hsubU k hk)
  have hRef : HeadSpec ((keys b[i]).flatMap fun k => heads (s.rel.get k)) (fun _ => true)
      (hits (locIx s fc b).rel (locIx s fc b).relPost (keys b[i]) (fun _ => true)).head? :=
    hits_head hr (ksR s fc.redo b) (keys b[i]) hsubR _
  have hRefU : HeadSpec ((keys b[i]).flatMap fun k => heads (s.unr.get k))
      (fun y => (keys b[i]).any ((locIx s fc b).claim y).contains)
      (hits (locIx s fc b).unr (locIx s fc b).unrPost (keys b[i])
        fun y => (keys b[i]).any ((locIx s fc b).claim y).contains).head? :=
    hits_head hu (probeKeys b) (keys b[i]) hsubU _
  have hRefU' := HeadSpec_pred (P' := fun q => (RowX.of b[i]).exactEq (RowX.of q) || (RowX.of b[i]).idEq (RowX.of q) ||
        !(isCap q && (locIx s fc b).notEnrolled q && !(locIx s fc b).own q) && (RowX.of b[i]).nearEq (RowX.of q))
    (fun q hq => by
      obtain ⟨k, -, hk⟩ := List.mem_flatMap.1 hq
      exact predL_eq _ b[i] q.row hfitb (heads_fit hu hk hwu)) hRefU
  have gR1 := rel_good R hr _ h1
  have gR2 := rel_good R hr _ h2
  have gR3 := rel_good R hr _ h3
  have cR := chain3 (layout s fc f b) _ _ _ (fun _ => true) _ _ _ gR1 gR2 gR3
  have k1 : (fetch s fc.redo b).rel[(layout s fc f b).lines[i]!.ke].1 ∈ probeKeys b := by
    rw [e1]; exact hsubU _ (by simp [keys])
  have k2 : (fetch s fc.redo b).rel[(layout s fc f b).lines[i]!.kn].1 ∈ probeKeys b := by
    rw [e2]; exact hsubU _ (by simp [keys])
  have k3 : (fetch s fc.redo b).rel[(layout s fc f b).lines[i]!.ki].1 ∈ probeKeys b := by
    rw [e3]; exact hsubU _ (by simp [keys])
  have gU1 := unr_good R hu cc hcc _ h1 k1 b[i]
  have gU2 := unr_good R hu cc hcc _ h2 k2 b[i]
  have gU3 := unr_good R hu cc hcc _ h3 k3 b[i]
  have cU := chain3 (layout s fc f b) _ _ _ _ _ _ _ gU1 gU2 gU3
  have sR := spec_match _ _ _ _ _ _ cR hRef (by
    intro q
    rw [slot_entry _ h1, slot_entry _ h2, slot_entry _ h3, e1, e2, e3]
    simp only [keys, List.flatMap_cons, List.flatMap_nil, List.append_nil, List.mem_append, or_assoc])
    (rows_agree hr _)
  have sU := spec_match _ _ _ _ _ _ cU hRefU' (by
    intro q
    rw [e1, e2, e3]
    simp only [keys, List.flatMap_cons, List.flatMap_nil, List.append_nil, List.mem_append, or_assoc])
    (rows_agree hu _)
  unfold cpOf
  rw [hrow]
  rw [relC_eq, relC_eq, relC_eq, unrC_eq, unrC_eq, unrC_eq]
  unfold Ix.counterparts
  exact cp_combine _ _ _ _ _ _ _ sR sU rfl rfl

theorem allok_proj (L : Lay) : ∀ (ds : List Dec) (rs : List Decision), AllOK L ds rs →
    ds.map (fun d => (L.src.getD d.line nilLine, outcomeOf8 d.out, reasons.filter (fun r => d.mask &&& bit r != 0),
      cpId L d.cp)) = rs.map (fun d => (d.line, d.outcome, d.reasons, d.counterparts.head?))
  | [], [], _ => rfl
  | d :: ds, r :: rs, ⟨⟨h1, h2, h3, h4, _, _⟩, h⟩ => by
    rw [List.map_cons, List.map_cons, allok_proj L ds rs h, h1, h2, h4, h3] <;> rfl
  | [], _ :: _, h => h.elim
  | _ :: _, [], h => h.elim

end

set_option maxHeartbeats 4000000 in
/-- (2, 3b, 3c) The fixed-row decider against the reference: the fold over the decision order gives the per-line
    masks, outcomes and first counterparts, with `sn`/`seen0` holding the keys of `Ix.seen`, `cfirst`/`csame` the
    `Ix.pending`, `hot` and `ic` the cap; the payment pass then gives the rows each set gains. -/
theorem decideRows_both (H : Bytes → Bytes) (s : St) (fc : FCtx) (f : List Nat) (b : List Line) (rel unr : Snapshot Line)
    (hr : IdxInv H s.rel rel) (hu : IdxInv H s.unr unr) (hw : ∀ l ∈ b ++ rel.entries ++ unr.entries, fitsLine2 l = true) :
    (decideRows (layout s fc f b)).toRef (layout s fc f b) = project (decideBatchIdx s fc f b) := by
  have R := layout_rep s fc f b
  unroll_dr
  rw [forIn_push5] at hr1
  have hbf : ∀ l ∈ b, fitsLine2 l = true := fun l hl => hw l (by simp [hl])
  have hwr : ∀ l ∈ rel.entries, fitsLine2 l = true := fun l hl => hw l (by simp [hl])
  have hwu : ∀ l ∈ unr.entries, fitsLine2 l = true := fun l hl => hw l (by simp [hl])
  have hnl : (layout s fc f b).lines.size = b.length := by
    have := congrArg List.length R.rows; simpa using this
  have hF1 : ∀ i (hi : i < b.length), r1.1[i]! = (locIx s fc b).own b[i] ∧ r1.2.1[i]! = (locIx s fc b).held b[i] ∧
      r1.2.2.1[i]! = (locIx s fc b).notEnrolled b[i] ∧ (∀ r, has r1.2.2.2.1[i]! r = baseF (locIx s fc b) b[i] r) ∧
      r1.2.2.2.2[i]! = feedCapped fc.feeds b[i] ∧ Lo r1.2.2.2.1[i]! := by
    intro i hi
    have hi' : i < (layout s fc f b).lines.size := by omega
    rw [← hr1]
    simp only [Array.emptyWithCapacity, Array.empty_append, getElem!_pos, Array.getElem_map, hi', Array.size_map]
    clear hr1 hr2 hr3 hr4 hr5 hr6 hr7 hr8
    have e : (layout s fc f b).lines[i]! = (layout s fc f b).lines[i] := getElem!_pos _ i hi'
    have e2 := line_row R i hi
    rw [e] at e2
    refine ⟨?_, ?_, ?_, ?_, ?_, Lo_baseOf _ _⟩
    · have h := own_line R hr hwr hbf i hi
      rw [e] at h; exact h
    · have h := held_line R hu hwu hbf i hi
      rw [e] at h; exact h
    · have h := notEnr_line R hbf i hi
      rw [e, ← e2] at h; exact h
    · intro r
      have h := base_has R hbf i hi r
      rw [e] at h; exact h
    · have h := fcap_line R i hi
      rw [e] at h; exact h
  have hF2 : (un r2).size = (layout s fc f b).unrP.size ∧ ∀ j (hj : j < (layout s fc f b).unrP.size),
      (un r2)[j]! = (isCap ((layout s fc f b).unrSrc.getD j nilLine) &&
        (locIx s fc b).notEnrolled ((layout s fc f b).unrSrc.getD j nilLine) &&
        !(locIx s fc b).own ((layout s fc f b).unrSrc.getD j nilLine)) := by
    obtain ⟨h1, h2⟩ := range_push (g := capClaimAt (layout s fc f b)) _ _ (un r2) hr2
    exact ⟨h1, fun j hj => by rw [h2 j hj]; exact capClaim_at R hr hu hwr hwu j hj⟩
  obtain ⟨o1, o2, o3, o4⟩ := loop3 (layout s fc f b).lines.size r1.1 (fun i => (layout s fc f b).lines[i]!.ke)
    (fun i => (layout s fc f b).lines[i]!.kn) (fun i => (layout s fc f b).lines[i]!.ki)
    (fun i => (layout s fc f b).lines[i]!.row.cap && (layout s fc f b).lines[i]!.span.over) _ _ (un r3) hr3
  obtain ⟨p1, p2, p3, p4, p5, p6⟩ := loop4 (layout s fc f b).unrP.size (fun k => (layout s fc f b).slots[k]!.kind)
    (fun k => (layout s fc f b).slots[k]!.rs) (fun k => (layout s fc f b).slots[k]!.rn)
    (fun k => (layout s fc f b).slots[k]!.rc) (fun k => (layout s fc f b).slots[k]!.us)
    (fun k => (layout s fc f b).slots[k]!.un)
    (fun k j => (un r3).1[k]!.any fun i => (layout s fc f b).lines[i]!.row.same (layout s fc f b).relP[j]!)
    (fun j => (layout s fc f b).unrP[j]!.cap && (layout s fc f b).uSpan[j]!.over) (fun j => (un r2)[j]!)
    (fun g j => !(layout s fc f b).unrP[g]!.same (layout s fc f b).unrP[j]!) (layout s fc f b).slots.size (un r3).2
    (by simpa using o2)
    (fun k hk g hg => unr_same_refl R hu hwu g (slot_unr_bnd R k hk g hg)) (un r4) hr4
  rw [← Array.forIn_toList, forIn_eq_foldl _ _ _ (stepG (layout s fc f b) r1.1 r1.2.1 r1.2.2.1 r1.2.2.2.1 r1.2.2.2.2 r4.1 r4.2.1
    r4.2.2.1 r4.2.2.2.1 r4.2.2.2.2 (un r2)) ?hstep] at hr6
  case hstep =>
    intro i st
    clear hr1 hr2 hr3 hr4 hr5 hr6 hr7 hr8 hF1 hF2 o1 o2 o3 o4 p1 p2 p3 p4 p5 p6
    simp only [← mask0.eq_1, ← maskC.eq_1, ← cpOf.eq_1]
    simp only [stepG]
    repeat' split
    all_goals rfl
  rw [← Array.forIn_toList, forIn_eq_foldl _ _ _ (liftStep (layout s fc f b)) ?hstepL] at hr7
  case hstepL =>
    intro d st
    clear hr1 hr2 hr3 hr4 hr5 hr6 hr7 hr8 hF1 hF2 o1 o2 o3 o4 p1 p2 p3 p4 p5 p6
    simp only [liftStep]
    repeat' split
    all_goals rfl
  rw [← Array.forIn_toList, forIn_eq_foldl _ _ _ (relStep (layout s fc f b) r1.1 r1.2.1 r6.2.2.1 r6.2.2.2.1 r6.2.2.2.2.1
    r6.2.2.2.2.2 r7) ?hstep7] at hr8
  case hstep7 =>
    intro d st
    clear hr1 hr2 hr3 hr4 hr5 hr6 hr7 hr8 hF1 hF2 o1 o2 o3 o4 p1 p2 p3 p4 p5 p6
    exact ite_pair_gen _ _ _ _ _
  have hks : ∀ k, k < (fetch s fc.redo b).rel.length → k < (layout s fc f b).slots.size := fun k hk => by
    rw [R.nslots]; exact hk
  have hownA : ∀ i (hi : i < b.length), r1.1[i]! = (locIx s fc b).own b[i] := fun i hi => (hF1 i hi).1
  have hne : ∀ i (hi : i < b.length), r1.2.2.1[i]! = (locIx s fc b).notEnrolled b[i] := fun i hi => (hF1 i hi).2.2.1
  have hb : ∀ i (hi : i < b.length), ∀ r, has r1.2.2.2.1[i]! r = baseF (locIx s fc b) b[i] r :=
    fun i hi => (hF1 i hi).2.2.2.1
  have hfc : ∀ i (hi : i < b.length), r1.2.2.2.2[i]! = feedCapped fc.feeds b[i] := fun i hi => (hF1 i hi).2.2.2.2.1
  have hLo : ∀ i (hi : i < b.length), Lo r1.2.2.2.1[i]! := fun i hi => (hF1 i hi).2.2.2.2.2
  have h0 : ∀ k (hk : k < (fetch s fc.redo b).rel.length),
      (un r4).2.2.1[k]! = (locIx s fc b).seen0 (fetch s fc.redo b).rel[k].1 := by
    intro k hk
    rw [(p6 k (hks k hk)).1]
    refine seen0_link R hr hwr hbf r1.1 hownA k hk _ ?_
    intro i
    have hz : (Array.replicate (layout s fc f b).slots.size (#[] : Array Nat))[k]! = #[] := by
      rw [getElem!_pos _ k (by simpa using hks k hk)]; simp
    rw [o3 k (by simpa using hks k hk) i, hz]
    simp [hnl]
  have hp : ∀ k (hk : k < (fetch s fc.redo b).rel.length), (fetch s fc.redo b).rel[k].1 ∈ probeKeys b →
      ∀ l : Line, fitsLine2 l = true → ∀ bp, bp = (fc.byp.lookup l.pay).isSome →
        pendAt (layout s fc f b) (un r4).2.2.2.1 (un r4).2.2.2.2 bp (RowX.of l) k =
          (locIx s fc b).pending l (fetch s fc.redo b).rel[k].1 := by
    intro k hk hkp l hl bp hbp
    have h := pend_link R hu hwu (un r2) hF2.2 k hk hkp l hl
    rw [← h, hbp]
    simp only [pendAt]
    rw [(p6 k (hks k hk)).2.1, (p6 k (hks k hk)).2.2.1]
  have hh : ∀ k (hk : k < (fetch s fc.redo b).rel.length),
      (un r4).1[k]! = (hotKeys (fetch s fc.redo b) fc.feeds b).contains (fetch s fc.redo b).rel[k].1 := by
    intro k hk
    have h4 := o4 k (by simpa using hks k hk)
    have hl := hot_link R hk
    rw [(p6 k (hks k hk)).2.2.2]
    rw [Bool.eq_iff_iff, ← hl]
    simp only [Bool.or_eq_true, h4]
    simp [hnl, getElem!_pos, hks k hk]
  have hic : (un r4).2.1 = idCapped (fetch s fc.redo b) := by rw [p5]; exact ic_link R
  have hcp := cp_link R hr hu hwu hbf (un r2) hF2.2
  have hS0 := sn0_inv R hnl r5 hr5
  obtain ⟨hord, hordb⟩ := ord_link R hbf r1.1 (locIx s fc b).own hownA (layout s fc f b).lines.size hnl
  obtain ⟨new, hnew, hall, -, -, hmem⟩ := fold_ds R hbf r1.1 r1.2.1 r1.2.2.1 r1.2.2.2.2 (un r4).1 (un r4).2.2.1 (un r4).2.2.2.2
    (un r2) (un r4).2.1 (un r4).2.2.2.1 r1.2.2.2.1 hownA hne hb hLo h0 hp hh hic hfc hcp _ hordb
    (r5, Array.emptyWithCapacity (layout s fc f b).lines.size, Array.replicate (layout s fc f b).pRedo.size false,
      Array.replicate (layout s fc f b).pRedo.size true, Array.replicate (layout s fc f b).pRedo.size false,
      Array.replicate (layout s fc f b).pRedo.size true) (HashSet.ofList (idSeen f)) hS0.1 hS0.2
  have hnew' : r6.2.1.toList = new := by
    have h := hnew
    rw [hr6] at h
    simpa using h
  have key := allok_proj _ new _ hall
  have hRef : (project (decideBatchIdx s fc f b)).1 =
      (((locIx s fc b).decideAll (HashSet.ofList (idSeen f)) ((locIx s fc b).order b)).map fun d =>
        if cappedWith (idCapped (fetch s fc.redo b)) (hotKeys (fetch s fc.redo b) fc.feeds b) fc.feeds d.line
          then capD d else d).map (fun d => (d.line, d.outcome, d.reasons, d.counterparts.head?)) := rfl
  refine Prod.ext ?_ ?_
  · rw [hRef]
    unfold Out.toRef
    dsimp only
    change (r6.2.1.toList.map _) = _
    rw [hnew', key, hord]
    rfl
  · have hredo : ∀ y, (locIx s fc b).redo.contains y = fc.redo.contains y := fun y => by
      simp [locIx, localIx, HashSet.contains_ofList]
    obtain ⟨f7a, f7b⟩ := fold_rel (layout s fc f b) r1.1 r1.2.1 r6.2.2.1 r6.2.2.2.1 r6.2.2.2.2.1 r6.2.2.2.2.2 r7
      r6.2.1.toList (#[], #[])
    rw [hr8] at f7a f7b
    have c5 := fold_lift (layout s fc f b) (layout s fc f b).pRedo.size r6.2.1.toList
      (fun d hd => (R.pay _ (hordb _ (hmem d (by rwa [hnew'] at hd)))).1)
      (Array.replicate (layout s fc f b).pRedo.size true) (by simp)
    rw [hr7] at c5
    obtain ⟨-, -, -, -, new2, hnew2, -, c1, c2, c3, c4⟩ := fold_pay (layout s fc f b) r1.1 r1.2.1 r1.2.2.1 r1.2.2.2.1
      r1.2.2.2.2 (un r4).1 (un r4).2.1 (un r4).2.2.1 (un r4).2.2.2.1 (un r4).2.2.2.2 (un r2)
      (layout s fc f b).pRedo.size _ (fun i hi => (R.pay i (hordb i hi)).1)
      (r5, Array.emptyWithCapacity (layout s fc f b).lines.size, Array.replicate (layout s fc f b).pRedo.size false,
        Array.replicate (layout s fc f b).pRedo.size true, Array.replicate (layout s fc f b).pRedo.size false,
        Array.replicate (layout s fc f b).pRedo.size true) (by simp) (by simp) (by simp) (by simp)
    rw [hr6] at c1 c2 c3 c4 hnew2
    have hn2 : new2 = new := by
      have h1 : r6.2.1.toList = new2 := by
        have h := hnew2
        simpa using h
      rw [hnew'] at h1
      exact h1.symm
    rw [hn2] at c1 c2 c3 c4
    obtain ⟨s1, s2⟩ := sets_core (layout s fc f b) (locIx s fc b) b (layout s fc f b).pRedo.size R.src
      (fun i hi => ⟨(R.pay i hi).1, by rw [(R.pay i hi).2.1, hredo], (R.pay i hi).2.2⟩) (fun i hi => R.lim i hi)
      R.paySame new _ hall (fun d hd => hordb _ (hmem d hd)) r1.1 r1.2.1 r6.2.2.1 r6.2.2.2.1 r6.2.2.2.2.1 r6.2.2.2.2.2 r7
      hownA (fun i hi => (hF1 i hi).2.1)
      (fun p hp => by rw [c1 p, rep_get _ _ _ hp]; simp)
      (fun p hp => by rw [c2 p, rep_get _ _ _ hp]; simp)
      (fun p hp => by rw [c3 p, rep_get _ _ _ hp]; simp)
      (fun p hp => by rw [c4 p, rep_get _ _ _ hp]; simp)
      (fun p hp => by rw [c5 p, rep_get _ _ _ hp, hnew']; simp)
    rw [hord] at s1 s2
    unfold Out.toRef
    dsimp only
    change (r8.fst.toList.map _, r8.snd.toList.map _) = _
    rw [f7a, f7b, hnew']
    refine Prod.ext ?_ ?_
    · refine Eq.trans ?_ s1
      simp [List.map_map, Function.comp_def]
    · refine Eq.trans ?_ s2
      simp [List.map_map, Function.comp_def]

/-- The fixed-row decider decides as `decideBatchIdx` on indexes of real sets whose rows and lines fit the store
    widths; also checked on randomized batches by `decide_bench check`. -/
theorem decideRows_eq (H : Bytes → Bytes) (s : St) (fc : FCtx) (f : List Nat) (b : List Line) (rel unr : Snapshot Line)
    (hr : IdxInv H s.rel rel) (hu : IdxInv H s.unr unr)
    (hw : ∀ l ∈ b ++ rel.entries ++ unr.entries, fitsLine2 l = true) :
    (decideRows (layout s fc f b)).toRef (layout s fc f b) = project (decideBatchIdx s fc f b) :=
  decideRows_both H s fc f b rel unr hr hu hw

end BlindLedger.Gate.Flat.Rows
