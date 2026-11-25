import BlindLedger.X12.Run

/-! The 837 set reader: a step for each segment of a claim file's set, in the order of the checks of the Python reader
    (`app/right_rail_x12_837.py`, `_read_set`).  The state is one flat record updated in place and passed along, with
    no monad: the set reader is the hot path.

    Items (first word 5, second the item kind, third the set's offset):
    - 1 set-aside, 2 finding: level, cause, offset, form, a, b, c
    - 6 a service line row, written when its line closes and kept by the host until the claim item that follows:
      line number, form (0 professional, 1 institutional), procedure qualifier, procedure,
      modifier count and modifiers, revenue code, units present, units, line charge, service begin, service end
      (`yyyymmdd`, 0 for none), line control, rendering NPI, the line's rendering name (present, three elements),
      offset count and the line's offsets (the host joins the claim's offsets before them).
    - 4 claim: id, offset, end, cents, the number of rows before it, then a status word.  Status 0: the claim was set
      aside (a set-aside item follows) and its rows are dropped.  Status 1: billing NPI and the billing name's three
      elements, subscriber id, patient id, dependent, facility, frequency, original reference, diagnosis count and
      (qualifier, code) pairs, the claim's rendering name (present, three elements), offset count and the claim's
      offsets; a finding may follow.
    Every text is a range word. -/

namespace BlindLedger.X12

open Std

structure Bill where
  npi : Nat
  off : Nat
  n3 : Nat
  n4 : Nat
  n5 : Nat
  deriving Inhabited

/-- The open service line. -/
structure Ln where
  lnNumber : Nat := 0
  lnOffs : Array Nat := #[]
  lnFault : Option (Level × Cause × Nat) := none
  lnRend : Option Nat := none
  lnRname : Option (Nat × Nat × Nat) := none
  lnSv : Bool := false
  lnProf : Bool := true
  lnPq : Nat := 0
  lnProc : Nat := 0
  lnMods : Array Nat := #[]
  lnRev : Nat := 0
  lnBegin : Nat := 0
  lnFin : Nat := 0
  lnCharge : Int := 0
  lnHasUnits : Bool := false
  lnUnits : Int := 0
  lnCtl : Option Nat := none

/-- What the open claim holds besides what every segment looks at. -/
structure Cl where
  clId : Nat := 0
  clTotal : Option Int := none
  clFac : Nat := 0
  clFreq : Nat := 0
  clRef : Nat := 0
  clDx : Array Nat := #[]
  clOffs : Array Nat := #[]
  clFault : Option (Level × Cause × Nat) := none
  clRend : Option Nat := none
  clRname : Option (Nat × Nat × Nat) := none

/-- The state: small, so that updating it for each segment is cheap; the line and the claim's other parts are objects
    of their own, rebuilt only when they change. -/
structure S837 where
  billing : Option Bill := none
  subId : Nat := 0
  subOff : Nat := 0      -- 0: no subscriber
  patId : Nat := 0
  patOff : Nat := 0      -- 0: no patient
  hlSeen : HashSet Nat := {}
  hlLast : Nat := 0
  tops : HashMap Nat (Option Bill) := {}
  top : Option Nat := none
  cl : Bool := false
  clEnd : Nat := 0
  clLost : Bool := false
  clLx : Bool := false
  clSbr : Bool := false
  lineOn : Bool := false
  -- the closed lines of the open claim: how many, and their charges
  nrows : Nat := 0
  paid : Int := 0
  c : Cl := {}
  l : Ln := {}

def known837Names : List String :=
  ("BHT HL PRV CUR NM1 N3 N4 REF DMG SBR PAT CLM DTP CL1 PWK CN1 AMT HI HCP LX SV1 SV2 SV5 CR1 CR2 " ++
   "CR3 CR5 CRC QTY OI MOA LIN CTP SVD CAS PS1 NTE K3 DN1 DN2 PER OTI SV3 SV4 SV6 SV7 TOO LQ FRM MEA").splitOn " "

/-- The known ids by their residue modulo 305, a modulus under which no two of them meet. -/
def known837Tab : Array Nat := known837Names.foldl (fun a n => let i := pk n; a.set! (i % 305) i) (Array.replicate 305 0)

@[inline] def isKnown837 (sid : Nat) : Bool := sid != 0 && known837Tab[sid % 305]! == sid

def isEmpty (r : Nat) : Bool := rngLen r == 0

/-- The first word of an item: 5, the item kind (1 set-aside, 2 finding, 4 claim), a status (claims) and the set's offset. -/
def itemHead (kind status setOff : Nat) : Nat := 5 + kind * 256 + status * 4096 + setOff * 65536

/-- A set-aside or a finding: head, then level, cause and form in one word, then offset, a, b, c. -/
def itemQ (o : Out) (kind setOff : Nat) (lv : Level) (c : Cause) (off : Nat) (f : Form) (a b c3 : Nat) : Out :=
  o.w5 (itemHead kind 0 setOff) (lv.ctorIdx + c.ctorIdx * 256 + f.ctorIdx * 65536) off a b |>.w c3

/-- A set-aside of the open set. A claim with a segment of it set aside is never sent as if whole. -/
def bad (s : S837) (o : Out) (setOff : Nat) (lv : Level) (c : Cause) (off : Nat) (f : Form := .none) (a : Nat := 0) :
    S837 × Out :=
  ((if lv == .segment && s.cl then { s with clLost := true } else s), itemQ o 1 setOff lv c off f a 0 0)

/-- The line's rendering NPI: its own, else the claim's, else the billing provider's. -/
def rendOf (s : S837) : Nat :=
  let fallback := match s.c.clRend with
    | some c => if isEmpty c then (s.billing.map (·.npi)).getD 0 else c
    | none => (s.billing.map (·.npi)).getD 0
  match s.l.lnRend with
  | some r => if isEmpty r then fallback else r
  | none => fallback

/-- The state with no open service line. -/
def S837.noLine (s : S837) : S837 := { s with lineOn := false, l := {} }

/-- The three elements of a name, three words when present. -/
def putName (ev : ByteArray) (p : Nat) : Option (Nat × Nat × Nat) → ByteArray
  | some (a, b, c) => setW (setW (setW ev p a) (p + 8) b) (p + 16) c
  | none => ev

def nameLen : Option (Nat × Nat × Nat) → Nat
  | some _ => 3
  | none => 0

/-- Close the open service line: a row of the claim, or a set-aside. -/
def closeLine (s : S837) (o : Out) (setOff : Nat) : S837 × Out :=
  if !s.lineOn then (s, o)
  else if !s.l.lnSv then
    let off := s.l.lnOffs[0]!
    bad { s.noLine with clLost := true } o setOff .loop .noSvSegment off
  else if let some (lv, c, off) := s.l.lnFault then
    bad { s.noLine with clLost := true } o setOff lv c off
  else
    let l := s.l
    let nm := l.lnMods.size
    let no := l.lnOffs.size
    let n := 10 + nameLen l.lnRname + nm + no
    match o.reserve (8 * n) with
    | ⟨ev, p, side⟩ =>
      let flags := 6 + (if l.lnProf then 0 else 256) + (if l.lnHasUnits then 512 else 0) +
        (if l.lnRname.isSome then 1024 else 0) + nm * 65536 + no * 16777216
      let ev := setW (setW (setW (setW (setW ev p flags) (p + 8) l.lnNumber) (p + 16) l.lnPq) (p + 24) l.lnProc) (p + 32) l.lnRev
      let ev := setW (setW (setW (setW (setW ev (p + 40) (wordOfInt l.lnUnits)) (p + 48) (wordOfInt l.lnCharge))
        (p + 56) (l.lnBegin + l.lnFin * 4294967296)) (p + 64) (l.lnCtl.getD 0)) (p + 72) (rendOf s)
      let ev := putName ev (p + 80) l.lnRname
      let q := p + 80 + 8 * nameLen l.lnRname
      let ev := putArr (putArr ev q l.lnMods 0) (q + 8 * nm) l.lnOffs 0
      ({ s.noLine with nrows := s.nrows + 1, paid := s.paid + l.lnCharge }, ⟨ev, p + 8 * n, side⟩)

def lit7 : ByteArray := "7".toUTF8
def lit8 : ByteArray := "8".toUTF8

/-- Close the open claim: its claim item with rows, or its set-aside, and a finding. -/
def closeClaim (d : ByteArray) (s : S837) (o : Out) (setOff : Nat) : S837 × Out :=
  if !s.cl then (s, o) else
  let (s, o) := closeLine s o setOff
  let off0 := s.c.clOffs[0]!
  let freqS := rngStart s.c.clFreq
  let freqE := freqS + rngLen s.c.clFreq
  let fault : Option (Level × Cause × Nat) :=
    match s.c.clFault with
    | some f => some f
    | none =>
      if s.nrows == 0 then some (.loop, .noServiceLines, off0)
      else if s.billing.isNone then some (.loop, .noBillingNpi, off0)
      else if s.subOff == 0 then some (.loop, .noSubscriber, off0)
      else if (eqB d freqS freqE lit7 || eqB d freqS freqE lit8) && isEmpty s.c.clRef then some (.loop, .missingOriginalRef, off0)
      else none
  let o := o.w5 (itemHead 4 (if fault.isSome then 0 else 1) setOff) s.c.clId off0 (if s.clLx then s.clEnd else off0)
    (wordOfInt (s.c.clTotal.getD 0)) |>.w s.nrows
  -- the claim is closed from here on, so a set-aside of a segment kind does not mark it lost
  let paid := s.paid
  let s : S837 :=
    { s with cl := false, clLost := false, nrows := 0, paid := 0,
             c := { s.c with clDx := #[], clOffs := #[], clRend := none, clRname := none, clFault := none } }
  match fault with
  | some (lv, c, off) =>
    bad s o setOff lv c off
  | none =>
    let bill := s.billing.get!
    let total : Int := s.c.clTotal.getD 0
    let nd := s.c.clDx.size
    let no := 2 + (if s.subOff != 0 then 1 else 0) + (if s.patOff != 0 then 1 else 0) + (s.c.clOffs.size - 1)
    let n := 10 + nd + nameLen s.c.clRname + no
    match o.reserve (8 * n) with
    | ⟨ev, p, side⟩ =>
      let flags := (if s.patOff != 0 then 1 else 0) + (if s.c.clRname.isSome then 2 else 0) + nd * 256 + no * 65536
      let ev := setW (setW (setW (setW (setW ev p bill.npi) (p + 8) bill.n3) (p + 16) bill.n4) (p + 24) bill.n5) (p + 32) s.subId
      let ev := setW (setW (setW (setW (setW ev (p + 40) s.patId) (p + 48) s.c.clFac) (p + 56) s.c.clFreq) (p + 64) s.c.clRef) (p + 72) flags
      let q := p + 80
      let ev := putArr ev q s.c.clDx 0
      let q := q + 8 * nd
      let ev := putName ev q s.c.clRname
      let q := q + 8 * nameLen s.c.clRname
      let ev := setW (setW ev q off0) (q + 8) bill.off
      let q := q + 16
      let (ev, q) := if s.subOff != 0 then (setW ev q s.subOff, q + 8) else (ev, q)
      let (ev, q) := if s.patOff != 0 then (setW ev q s.patOff, q + 8) else (ev, q)
      let ev := putArr ev q s.c.clOffs 1
      let o : Out := ⟨ev, p + 8 * n, side⟩
      if s.clLost then
        (s, itemQ o 2 setOff .loop .totalUnchecked off0 .none 0 0 0)
      else if total != paid then
        let (o1, a) := o.num total
        let (o2, b) := o1.num paid
        (s, itemQ o2 2 setOff .loop .totalMismatch off0 .totals837 a b 0)
      else (s, o)

def nameWords (d : ByteArray) (dl : Delims) (sg : Seg) : Nat × Nat × Nat :=
  let r (k : Nat) := let (s, e) := el d dl.sub sg k; rng s e
  (r 3, r 4, r 5)

/-- The key of an HL number as spelled: its value and its leading zeros; none unless it is one to twelve ASCII digits. -/
def hlKey (d : ByteArray) (s e : Nat) : Option Nat :=
  if e == s || e - s > 12 || skipDig d s e != e then none
  else some (digVal d s e 0 * 16 + (skipZero d s e - s))

def hlVal (k : Nat) : Nat := k / 16

def lD8 : ByteArray := "D8".toUTF8
def lRD8 : ByteArray := "RD8".toUTF8

/-- DTP*472: (begin, end) as `yyyymmdd`, or none. -/
def serviceDates (d : ByteArray) (dl : Delims) (sg : Seg) : Option (Nat × Nat) :=
  let (fs, fe) := el d dl.sub sg 2
  let (ts, te) := el d dl.sub sg 3
  if eqB d fs fe lD8 then
    let day := date8 d ts te
    if day != 0 then some (day, day) else none
  else if eqB d fs fe lRD8 then
    let m := findB d 45 ts te
    let a := date8 d ts m
    let b := if m < te then date8 d (m + 1) te else 0
    if a != 0 && b != 0 && a ≤ b then some (a, b) else none
  else none

def lAA : ByteArray := "85".toUTF8
def l82 : ByteArray := "82".toUTF8
def lIL : ByteArray := "IL".toUTF8
def lQC : ByteArray := "QC".toUTF8
def lPR : ByteArray := "PR".toUTF8
def lXX : ByteArray := "XX".toUTF8
def lF8 : ByteArray := "F8".toUTF8
def l6R : ByteArray := "6R".toUTF8
def l472 : ByteArray := "472".toUTF8
def l20 : ByteArray := "20".toUTF8
def l22 : ByteArray := "22".toUTF8
def l23 : ByteArray := "23".toUTF8

def idHL := pk "HL"
def idNM1 := pk "NM1"
def idCLM := pk "CLM"
def idSBR := pk "SBR"
def idPAT := pk "PAT"
def idREF := pk "REF"
def idHI := pk "HI"
def idLX := pk "LX"
def idSV1 := pk "SV1"
def idSV2 := pk "SV2"
def idDTP := pk "DTP"
def idN3 := pk "N3"
def idN4 := pk "N4"
def idDMG := pk "DMG"

/-- The diagnosis (qualifier, code) pairs of an HI segment: elements `k` up to `n`. -/
def dxGo (d : ByteArray) (dl : Delims) (sg : Seg) (n k : Nat) (dx : Array Nat) : Array Nat :=
  if k > n then dx else
    let (s1, e1) := elp d dl.sub sg k 1
    let m := nsub d dl.sub sg k
    if e1 > s1 || m > 1 then
      let (s2, e2) := elp d dl.sub sg k 2
      dxGo d dl sg n (k + 1) ((dx.push (rng s1 e1)).push (if m > 1 then rng s2 e2 else 0))
    else dxGo d dl sg n (k + 1) dx
termination_by n + 1 - k

/-- The modifiers (sub-elements 3 to 6, when present and not empty) of composite `k`, whose sub-element count is `np`. -/
def modsGo (d : ByteArray) (dl : Delims) (sg : Seg) (k np j : Nat) (mods : Array Nat) : Array Nat :=
  if j > 6 then mods else
    if j ≤ np then
      let (ms, me) := elp d dl.sub sg k j
      modsGo d dl sg k np (j + 1) (if me > ms then mods.push (rng ms me) else mods)
    else modsGo d dl sg k np (j + 1) mods
termination_by 7 - j

/-- One segment of a claim file's set. -/
def step837 (d : ByteArray) (dl : Delims) (sg : Seg) (ctx : SetCtx) (s : S837) (o : Out) : S837 × Out :=
  let off := sg.s
  let setOff := ctx.off
  let sid := packId d sg.s sg.idEnd
  let idr := rng sg.s sg.idEnd
  let isE (k : Nat) (l : ByteArray) : Bool := let (a, b) := el d dl.sub sg k; eqB d a b l
  let rngE (k : Nat) : Nat := let (a, b) := el d dl.sub sg k; rng a b
  let isNm := sid == idNM1
  let w85 := isNm && isE 1 lAA
  let w82 := isNm && isE 1 l82
  let wIL := isNm && isE 1 lIL
  let wQC := isNm && isE 1 lQC
  let wPR := isNm && isE 1 lPR
  let other := s.cl && s.clSbr && !s.clLx
  if s.cl && (((sid == idPAT || w85) && !other) || wQC || (s.clLx && (sid == idSBR || wIL))) then
    let (s, o) := closeClaim d s o setOff
    let (s, o) := bad s o setOff .segment .headerWithoutHl off .text idr
    ({ s with billing := none, subOff := 0, patOff := 0 }, o)
  else
  let s := if s.cl && isKnown837 sid && !(sid == idHL || sid == idCLM || sid == idN3 || sid == idN4 || sid == idDMG) && !wPR
    then { s with clEnd := off } else s
  if !isKnown837 sid then
    bad s o setOff .segment .unknownSegment off .text idr
  else if sid == idHL then
    let (s, o) := closeClaim d s o setOff
    let (cs, ce) := el d dl.sub sg 3
    let (ns, ne) := el d dl.sub sg 1
    let (ps, pe) := el d dl.sub sg 2
    let c20 := eqB d cs ce l20
    let c22 := eqB d cs ce l22
    let key := hlKey d ns ne
    let parentOk := pe == ps || (match hlKey d ps pe with | some k => s.hlSeen.contains k | none => false)
    let last := s.hlLast
    let good := (c20 || c22 || eqB d cs ce l23) && (match key with | some k => hlVal k == last + 1 | none => false) && parentOk
    if !good then
      let (s, o) := bad s o setOff .segment .badHl off .hlParts
      let advance := match key with | some k => !(hlVal k ≤ last) | none => true
      ({ s with billing := none, subOff := 0, patOff := 0, top := none, hlLast := if advance then last + 1 else last }, o)
    else
      let k := key.get!
      let s := { s with hlSeen := s.hlSeen.insert k, hlLast := hlVal k }
      if c20 then
        ({ s with billing := none, subOff := 0, patOff := 0, top := some k }, o)
      else if c22 then
        let tb := match hlKey d ps pe with | some p => (s.tops.getD p none) | none => none
        ({ s with billing := tb, subOff := 0, patOff := 0 }, o)
      else
        ({ s with patId := 0, patOff := off }, o)
  else if isNm && !s.cl then
    if w85 then
      let b : Option Bill :=
        if isE 8 lXX && !isEmpty (rngE 9) then
          let (a, b, c) := nameWords d dl sg
          some { npi := rngE 9, off, n3 := a, n4 := b, n5 := c }
        else none
      ({ s with billing := b, tops := match s.top with | some t => s.tops.insert t b | none => s.tops }, o)
    else if wIL then
      (if isEmpty (rngE 9) then { s with subId := 0, subOff := 0 } else { s with subId := rngE 9, subOff := off }, o)
    else if wQC then
      ({ s with patId := rngE 9, patOff := off }, o)
    else (s, o)
  else if sid == idCLM then
    let (s, o) := closeClaim d s o setOff
    let (ts, te) := el d dl.sub sg 2
    let total := scaled d ts te 2
    let id := rngE 1
    let (f1s, f1e) := elp d dl.sub sg 5 1
    let (f3s, f3e) := elp d dl.sub sg 5 3
    let fault : Option (Level × Cause × Nat) :=
      if isEmpty id then some (.loop, .noClaimId, off)
      else if total.isNone then some (.loop, .badTotalCharge, off)
      else if f3e == f3s then some (.loop, .noFrequencyCode, off)
      else none
    ({ s with cl := true, clEnd := off, clLost := false, clLx := false, clSbr := false, nrows := 0, paid := 0, c := { s.c with clId := id, clTotal := total, clFac := rng f1s f1e, clFreq := rng f3s f3e, clRef := 0, clDx := #[], clOffs := #[off], clFault := fault, clRend := none, clRname := none } }, o)
  else if !s.cl then
    (s, o)
  else if sid == idSBR then
    ({ s with clSbr := true }, o)
  else if w82 && !other then
    let rendOpt := if s.lineOn then s.l.lnRend else s.c.clRend
    if rendOpt.isSome then
      bad s o setOff .segment .repeatedSegment off .nm182
    else
      let r := if isE 8 lXX then rngE 9 else 0
      let nw := nameWords d dl sg
      let prior := if s.lineOn then s.l.lnFault else s.c.clFault
      let fault := prior <|> (if isEmpty r then some (.loop, .noRenderingNpi, off) else none)
      if s.lineOn then
        ({ s with l := { s.l with lnRend := some r, lnRname := some nw, lnOffs := s.l.lnOffs.push off, lnFault := fault } }, o)
      else
        ({ s with c := { s.c with clRend := some r, clRname := some nw, clOffs := s.c.clOffs.push off, clFault := fault } }, o)
  else if sid == idREF && isE 1 lF8 && !s.lineOn then
    if !isEmpty s.c.clRef then
      bad s o setOff .segment .repeatedSegment off .refF8
    else
      ({ s with c := { s.c with clRef := rngE 2, clOffs := s.c.clOffs.push off } }, o)
  else if sid == idREF && isE 1 l6R && s.lineOn then
    ({ s with l := { s.l with lnCtl := some (if s.l.lnCtl.isSome then 0 else rngE 2) } }, o)
  else if sid == idHI && !s.lineOn then
    let dx := dxGo d dl sg (cntGo d sg.sep sg.e sg.s 0) 1 s.c.clDx
    ({ s with c := { s.c with clOffs := s.c.clOffs.push off, clDx := dx } }, o)
  else if sid == idLX then
    let (s, o) := closeLine s o setOff
    ({ s with clLx := true, lineOn := true, l := { s.l with lnNumber := rngE 1, lnOffs := #[off] } }, o)
  else if s.lineOn && (sid == idSV1 || sid == idSV2) then
    if s.l.lnSv then
      bad s o setOff .segment .repeatedSegment off .text idr
    else
      let prof := sid == idSV1
      let k := if prof then 1 else 2
      let (qs, qe) := elp d dl.sub sg k 1
      let np := nsub d dl.sub sg k
      let (ps, pe) := elp d dl.sub sg k 2
      let mods := modsGo d dl sg k np 3 #[]
      let rev := if prof then 0 else rngE 1
      let (cs, ce) := el d dl.sub sg (if prof then 2 else 3)
      let (us, ue) := el d dl.sub sg (if prof then 4 else 5)
      let charge := scaled d cs ce 2
      let units := if ue > us then scaled d us ue 3 else none
      let fault : Option (Level × Cause × Nat) :=
        if charge.isNone then some (.loop, .badLineCharge, off)
        else if ue > us && units.isNone then some (.loop, .badUnits, off)
        else if !prof && isEmpty rev then some (.loop, .noRevenueCode, off)
        else none
      -- a fault found here replaces an earlier one, as the Python reader assigns it
      let keep := if fault.isSome then fault else s.l.lnFault
      ({ s with l := { s.l with lnSv := true, lnOffs := s.l.lnOffs.push off, lnProf := prof, lnPq := rng qs qe, lnProc := (if np > 1 then rng ps pe else 0), lnMods := mods, lnRev := rev, lnBegin := 0, lnFin := 0, lnCharge := charge.getD 0, lnHasUnits := units.isSome, lnUnits := units.getD 0, lnFault := keep } }, o)
  else if s.lineOn && sid == idDTP && isE 1 l472 && s.l.lnSv then
    if s.l.lnBegin != 0 then
      bad s o setOff .segment .repeatedSegment off .dtp472
    else
      match serviceDates d dl sg with
      | none =>
        let (s, o) := bad s o setOff .segment .badDate off .dtp472
        ({ s with l := { s.l with lnFault := s.l.lnFault <|> some (.loop, .badServiceDate, off) } }, o)
      | some (a, b) =>
        ({ s with l := { s.l with lnBegin := a, lnFin := b, lnOffs := s.l.lnOffs.push off } }, o)
  else (s, o)

instance reader837 : SetReader S837 where
  init := {}
  step := step837
  finish d _ ctx st o := (closeClaim d st o ctx.off).2
  notCause := .not837
