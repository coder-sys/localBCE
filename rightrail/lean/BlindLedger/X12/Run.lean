import BlindLedger.X12.Frame

/-! The envelope fold.  `readX12` reads a whole file the way the Python envelope does and gives every event, in order,
    as little-endian 64-bit words: repairs counted, set-asides, retractions, set openings and what the set reader adds.

    Events (the first word is the tag):
    - 2 envelope set-aside: level, cause, offset, form, a, b, c
    - 3 retraction: level, offset (everything of the set, group or interchange that starts there is void)
    - 4 set opening: kind, control, offset, file date, file time, group offset, interchange offset
    - 5 an item of the set at `offset`: item kind, set offset, then the reader's words
    - 0 end: refusal (0 or the cause number plus one), repair count, (rule, count) in first-seen order, side-text length;
      the side text follows. -/

namespace BlindLedger.X12

open Std

instance : Hashable ByteArray := ⟨fun b => b.foldl (fun h c => mixHash h (hash c)) 7⟩
instance : BEq ByteArray := ⟨fun a b => a.data == b.data⟩

def Out.quar (o : Out) (lv : Level) (c : Cause) (off : Nat) (f : Form) (a b c' : Nat) : Out :=
  (((((((o.w 2).w lv.ctorIdx).w c.ctorIdx).w off).w f.ctorIdx).w a).w b).w c'

def Out.retract (o : Out) (lv : Level) (off : Nat) : Out := ((o.w 3).w lv.ctorIdx).w off

/-- The decimal digits of `n` are the bytes `s` up to `e` of `d`. -/
def numEq (d : ByteArray) (s e : Nat) (n : Nat) : Bool :=
  let t := (toString n).toUTF8
  eqB d s e t

structure Rep where
  counts : Array Nat := #[0, 0, 0, 0]
  order : Array Nat := #[]

@[inline] def Rep.add (r : Rep) (x : Rule) : Rep :=
  let i := x.ctorIdx
  { counts := r.counts.modify i (· + 1), order := if r.counts[i]! == 0 then r.order.push i else r.order }

/-- A group in progress. -/
structure Grp where
  control : Nat := 0
  count : Nat := 0
  bad : Option Cause := none
  detail : Form := .none
  fileDate : Nat := 0
  fileTime : Nat := 0
  off : Nat := 0
  sets : HashSet ByteArray := {}
  okSets : Nat := 0

/-- A transaction set in progress: its ST's first two elements, its segment count and its offset. -/
structure Cur where
  kindS : Nat
  kindE : Nat
  ctlS : Nat
  ctlE : Nat
  count : Nat
  off : Nat
  live : Bool
  active : Bool
  ctx : SetCtx

def mib : Nat := 1048576

def sameRange (d : ByteArray) (s1 e1 s2 e2 : Nat) : Bool := e1 - s1 == e2 - s2 && sameB d s1 s2 (e1 - s1)

def idST := pk "ST"
def idSE := pk "SE"
def idGS := pk "GS"
def idGE := pk "GE"
def idIEA := pk "IEA"

/-- The plain run of a set: the segments after `pos` that need no repair, set-aside or envelope handling go straight to
    the set reader's step.  It stops at the first segment of any other kind (white space to trim, too long, no end,
    an unusable id, a repeated element, bytes above 127 in a file that has them, or an envelope segment) and the
    general loop handles that one; so nothing here has a rare case in it.  Gives the position, the segment count of
    the set and the reader's state and output. -/
@[specialize] partial def plainRun {σ : Type} [rd : SetReader σ] (d : ByteArray) (dl : Delims) (ctx : SetCtx) (base n : Nat)
    (repOn hiOn : Bool) (pos count : Nat) (rs : σ) (o : Out) : Nat × Nat × σ × Out :=
  let t := findB d dl.term pos n
  if t ≥ n || base + t ≥ ((base + pos) / mib + 2) * mib then (pos, count, rs, o) else
  let s := skipSp d pos t
  let e := backSp d s t
  if s != pos || e != t || e == s || (e - s ≥ 3 && d[s]! == 73 && d[s + 1]! == 83 && d[s + 2]! == 65) then (pos, count, rs, o) else
  let sg := mkSeg d s e dl.sep
  let sid := packId d s sg.idEnd
  if sid == 0 || sid == idST || sid == idSE || sid == idGS || sid == idGE || sid == idIEA
      || (repOn && hasByte d dl.rep.toUInt8 s e) || (hiOn && hasHigh d s e) then (pos, count, rs, o) else
  let (rs', o') := rd.step d dl sg ctx rs o
  plainRun d dl ctx base n repOn hiOn (t + 1) (count + 1) rs' o'

/-- A set of interchange controls (nine digits, so below 10^9) as a bitmap in pages of 32,768 controls (4 KiB), each
    made when a control in it is first added: at most 125 MB, whatever the file. -/
structure Ctl where
  pages : Array ByteArray := #[]

/-- A page with no control in it. -/
def zeroPage : ByteArray := zeros 4096

def Ctl.contains (t : Ctl) (x : Nat) : Bool :=
  let pg := t.pages.getD (x >>> 15) ByteArray.empty
  pg.size > 0 && ((pg[(x >>> 3) &&& 4095]! >>> (x &&& 7).toUInt8) &&& 1) == 1

def Ctl.insert (t : Ctl) (x : Nat) : Ctl :=
  let p := x >>> 15
  let pages := if p < t.pages.size then t.pages else t.pages ++ Array.replicate (p + 1 - t.pages.size) ByteArray.empty
  let i := (x >>> 3) &&& 4095
  let bit : UInt8 := 1 <<< (x &&& 7).toUInt8
  { pages := pages.modify p fun pg => let pg := if pg.size == 0 then zeroPage else pg; pg.set! i (pg[i]! ||| bit) }

/-- What passes from one unit (one or more whole interchanges) to the next: everything the fold keeps between
    interchanges.  `closed` (the last interchange was closed by its `IEA`), `cut` (in the unit read last, the start of
    the last interchange that follows one so closed, 0 for none) and `ctls` (the controls of the unit read last, in
    file order) are the unit's own: each unit starts them afresh. -/
structure Carry where
  first : Bool := true
  taken : Ctl := {}
  ctls : Array Nat := #[]
  confirmed : Nat := 0
  ieaMissing : Bool := false
  refused : Nat := 0
  skipPost : Bool := false
  stop : Bool := false
  rep : Rep := {}
  closed : Bool := false
  cut : Nat := 0

/-- A repair count kept by a later part of the input, after this one's. -/
def Rep.join (a b : Rep) : Rep :=
  b.order.foldl (fun r i => { counts := r.counts.modify i (· + b.counts[i]!),
                              order := if r.counts[i]! == 0 then r.order.push i else r.order }) a

/-- What the fold kept over one part of the input, then what it kept over the next part when that part was read from a
    carry with nothing in it but `first := false` (the join is that part read from `a`, when no control in `b.ctls` is
    in `a.taken`: the controls are the only thing a part's events depend on in the carry).  `b`'s own set is not used:
    its controls are added to `a`'s one by one. -/
def Carry.join (a b : Carry) : Carry :=
  { first := a.first && b.first, taken := b.ctls.foldl Ctl.insert a.taken, ctls := b.ctls,
    confirmed := a.confirmed + b.confirmed, ieaMissing := a.ieaMissing || b.ieaMissing,
    refused := max a.refused b.refused, skipPost := a.skipPost || b.skipPost, stop := a.stop || b.stop,
    rep := a.rep.join b.rep, closed := b.closed, cut := b.cut }

/-- One interchange: its header is at `isa` with delimiters `dl`, and its segments are read up to the `IEA` that closes
    it, the next header at a segment's start, or the bound `n`.  Gives where it ended, whether an `IEA` closed it, and
    what the fold keeps after it. -/
@[specialize] def ichg {σ : Type} [rd : SetReader σ] (kind : ByteArray) (base : Nat) (d : ByteArray) (hiOn : Bool)
    (n isa : Nat) (dl : Delims) (st : Carry × Out) : Nat × Bool × (Carry × Out) := Id.run do
  let c0 := st.1
  let mut o := st.2
  let mut rep := c0.rep
  let ctl := (d.extract (rngStart dl.control) (rngStart dl.control + 9)).foldl (fun a c => a * 10 + (c - 48).toNat) 0
  let repeated := c0.taken.contains ctl
  if repeated then o := o.quar .interchange .duplicateControl isa .text dl.control 0 0
  if !dl.stampOk then rep := rep.add .badIsaStamp
  let void := repeated
  -- the repetition separator makes a segment bad wherever it stands, so the segments need a look for it only when the
  -- rest of the unit holds one (in a file with the usual header the scan stops at the next header's ISA11)
  let repOn := dl.rep != 256 && hasByte d dl.rep.toUInt8 (isa + 106) n
  let mut sg : Seg := {}
  let mut rs : σ := rd.init
  let mut pos := isa + 106
  let mut ok := 0
  let mut groupsSeen := 0
  let mut grp : Option Grp := none
  let mut cur : Option Cur := none
  let mut groupControls : HashSet ByteArray := {}
  let mut closed := false
  let mut seg := true
  while seg do
    if let some c := cur then
      if c.live && c.active then
        let (p', cnt, rs', o') := plainRun d dl c.ctx base n repOn hiOn pos c.count rs o
        pos := p'
        cur := some { c with count := cnt }
        rs := rs'
        o := o'
    let start := pos
    let t := findB d dl.term start n
    if t == n then
      let mut blank := true
      let mut i := start
      while i < n do
        if !isSpace d[i]! then blank := false
        i := i + 1
      if n - start > mib || !blank then
        o := o.quar .segment .unterminatedSegment start .noTerm 0 0 0
      pos := n
      seg := false
    else
      pos := t + 1
      if base + t ≥ ((base + start) / mib + 2) * mib then
        if let some c := cur then cur := some { c with count := c.count + 1 }
        o := o.quar .segment .segmentTooLong start .none 0 0 0
      else
        let s := skipSp d start t
        let e := backSp d s t
        let trimmed := s != start || e != t
        if trimmed then rep := rep.add .whitespace
        if trimmed && s == e then
          pure ()
        else
          let ofs := s
          let mut brk := false
          if e - s ≥ 3 && d[s]! == 73 && d[s + 1]! == 83 && d[s + 2]! == 65 then
            if (isaAt d ofs).isSome then
              pos := ofs
              brk := true
          if brk then
            seg := false
          else
            if let some c := cur then cur := some { c with count := c.count + 1 }
            let sg' := mkSeg d s e dl.sep
            let hasRep := repOn && hasByte d dl.rep.toUInt8 s e
            let hi := hiOn && hasHigh d s e
            sg := sg'
            let sid := packId d s sg.idEnd
            if sid == 0 then
              o := o.quar .segment .badSegmentId ofs .none 0 0 0
            else if dl.rep != 256 && hasRep then
              o := o.quar .segment .repeatedElement ofs .text (rng s sg.idEnd) 0 0
            else
              let rawHex := hi && !validUtf8 d s e
              let el1 := el d dl.sub sg
              if sid == idST then
                match grp with
                | none =>
                  o := o.quar .segment .stOutsideGroup ofs .none 0 0 0
                | some g =>
                  if let some c := cur then
                    -- _end: next ST before SE
                    o := o.quar .set .setUnclosed c.off .nextStBeforeSe 0 0 0
                    if c.live then
                      if c.active then o := rd.finish d dl c.ctx rs o
                      o := o.retract .set c.off
                  let (ks, ke) := el1 1
                  let (ns, ne) := el1 2
                  let live := g.bad.isNone && !void && threeChars d ks ke && ne > ns && !g.sets.contains (d.extract ns ne)
                  let active := eqB d ks ke kind
                  cur := some { kindS := ks, kindE := ke, ctlS := ns, ctlE := ne, count := 1, off := ofs, live, active,
                                ctx := { off := ofs, control := rng ns ne, fileDate := g.fileDate, fileTime := g.fileTime, group := g.off, ichg := isa } }
                  grp := some { g with count := g.count + 1 }
                  if live then
                    o := (((((((o.w 4).w (rng ks ke)).w (rng ns ne)).w ofs).w g.fileDate).w g.fileTime).w g.off).w isa
                    if active then
                      rs := rd.init
                    else
                      o := ((((((((o.w 5).w 1).w ofs).w Level.set.ctorIdx).w rd.notCause.ctorIdx).w ofs).w Form.none.ctorIdx).w 0).w 0
                      o := o.w 0
              else if sid == idSE then
                match cur with
                | none =>
                  o := o.quar .segment .seWithoutSt ofs .none 0 0 0
                | some c =>
                  let g := grp.getD {}
                  let (a1s, a1e) := el1 1
                  let (a2s, a2e) := el1 2
                  let mut cause : Option Cause := none
                  if c.ctlE == c.ctlS || !sameRange d a2s a2e c.ctlS c.ctlE then
                    cause := some .seControlMismatch
                  else if !numEq d a1s a1e c.count then
                    cause := some .seCountMismatch
                  else if !threeChars d c.kindS c.kindE then
                    cause := some .badSt
                  else if g.sets.contains (d.extract c.ctlS c.ctlE) then
                    cause := some .duplicateControl
                  grp := grp.map fun g => { g with sets := g.sets.insert (d.extract c.ctlS c.ctlE) }
                  if let some k := cause then
                    o := o.quar .set k c.off .none 0 0 0
                  if c.live then
                    grp := grp.map fun g => { g with okSets := g.okSets + (if cause.isNone then 1 else 0) }
                    if c.active then
                      o := rd.finish d dl c.ctx rs o
                    if cause.isSome then o := o.retract .set c.off
                  cur := none
              else if sid == idGS then
                if let some c := cur then
                  if c.live then
                    if c.active then o := rd.finish d dl c.ctx rs o
                    o := o.retract .set c.off
                  cur := none
                if let some g := grp then
                  o := o.quar .group .groupUnclosed g.off .nextGsBeforeGe 0 0 0
                  o := o.retract .group g.off
                groupsSeen := groupsSeen + 1
                let (ds, de) := el1 4
                let (cs, ce) := el1 5
                let day := date8 d ds de
                let clk := clock d cs ce
                let fileOk := day != 0 && clk.isSome
                let (gcs, gce) := el1 6
                let mut bad : Option Cause := if fileOk then none else some .badFileDatetime
                let dupG := groupControls.contains (d.extract gcs gce)
                if dupG && bad.isNone then bad := some .duplicateControl
                groupControls := groupControls.insert (d.extract gcs gce)
                if let some b := bad then
                  o := o.quar .group b ofs (if fileOk then Form.gs06 else Form.gs0405) 0 0 0
                grp := some { control := rng gcs gce, count := 0, bad, fileDate := day, fileTime := clk.getD 0, off := ofs, sets := {}, okSets := 0 }
              else if sid == idGE then
                match grp with
                | none =>
                  o := o.quar .segment .geWithoutGs ofs .none 0 0 0
                | some g =>
                  if let some c := cur then
                    o := o.quar .set .setUnclosed c.off .geBeforeSe 0 0 0
                    if c.live then
                      if c.active then o := rd.finish d dl c.ctx rs o
                      o := o.retract .set c.off
                    cur := none
                  let (a1s, a1e) := el1 1
                  let (a2s, a2e) := el1 2
                  let gs := rngStart g.control
                  let ge := gs + rngLen g.control
                  let mut cause : Option Cause := none
                  if ge == gs || !sameRange d a2s a2e gs ge then cause := some .geControlMismatch
                  else if !numEq d a1s a1e g.count then cause := some .geCountMismatch
                  if let some k := cause then
                    o := o.quar .group k g.off .none 0 0 0
                    o := o.retract .group g.off
                  else
                    ok := ok + g.okSets
                  grp := none
              else if sid == idIEA then
                if let some c := cur then
                  if c.live then
                    if c.active then o := rd.finish d dl c.ctx rs o
                    o := o.retract .set c.off
                  cur := none
                if let some g := grp then
                  o := o.quar .group .groupUnclosed g.off .ieaBeforeGe 0 0 0
                  o := o.retract .group g.off
                let (a1s, a1e) := el1 1
                let (a2s, a2e) := el1 2
                let cs := rngStart dl.control
                let mut cause : Option Cause := none
                if !sameRange d a2s a2e cs (cs + 9) then cause := some .ieaControlMismatch
                else if !numEq d a1s a1e groupsSeen then cause := some .ieaCountMismatch
                if let some k := cause then
                  o := o.quar .interchange k isa .text dl.control 0 0
                if cause.isSome || void then
                  o := o.retract .interchange isa
                  ok := 0
                closed := true
                seg := false
              else
                match cur with
                | some c =>
                  if c.live then
                    if rawHex then rep := rep.add .badUtf8
                    if c.active then
                      let (rs', o') := rd.step d dl sg c.ctx rs o
                      rs := rs'
                      o := o'
                | none =>
                  o := o.quar .segment .segmentOutsideSet ofs .text (rng s sg.idEnd) 0 0
  let mut confirmed := c0.confirmed
  let mut ieaMissing := c0.ieaMissing
  if closed then
    confirmed := confirmed + ok
  else
    if let some c := cur then
      o := o.quar .set .setUnclosed c.off .fileEndsBeforeSe 0 0 0
      if c.live then
        if c.active then o := rd.finish d dl c.ctx rs o
        o := o.retract .set c.off
    if let some g := grp then
      o := o.quar .group .groupUnclosed g.off .fileEndsBeforeGe 0 0 0
      o := o.retract .group g.off
    o := o.quar .interchange .ieaMissing isa .text dl.control 0 0
    o := o.retract .interchange isa
    ieaMissing := true
  let cut := if c0.closed then isa else c0.cut
  let ctls := c0.ctls.push ctl
  return (pos, closed,
    ({ c0 with first := false, taken := c0.taken.insert ctl, ctls, confirmed, ieaMissing, rep, closed, cut }, o))

/-- The fold over the interchanges from `pos`, bounded by `n`: white space, then a header read by `step` (bound,
    header offset, delimiters, state), until the bound, or a place with no header, which sets the rest of the input
    aside and stops (`stop`).  The flag is whether the fold reached the bound right after an interchange its `IEA`
    closed, with only white space between: there the input may be cut, and the next part read from what is kept. -/
@[specialize] def outerWith (step : Nat → Nat → Delims → Carry × Out → Nat × Bool × (Carry × Out)) (d : ByteArray)
    (n pos : Nat) (st : Carry × Out) (last : Bool) : (Carry × Out) × Bool :=
  let ofs := skipSp d pos n
  let st := if ofs > pos then ({ st.1 with rep := st.1.rep.add .whitespace }, st.2) else st
  if ofs ≥ n then (st, last) else
  match isaAt d ofs with
  | none =>
    if st.1.first then
      (({ st.1 with refused := Cause.isaUnframed.ctorIdx + 1, skipPost := true, stop := true },
        st.2.quar .file .isaUnframed ofs .none 0 0 0), false)
    else (({ st.1 with stop := true }, st.2.quar .file .isaUnframed ofs .restOfFile 0 0 0), false)
  | some dl =>
    match step n ofs dl st with
    | (pos', closed, st') =>
      -- an interchange always ends past its header; the other branch is never taken
      if _h : pos < pos' ∧ pos < n then outerWith step d n pos' st' closed else (st', false)
termination_by n - pos
decreasing_by have := _h.1; have := _h.2; omega

/-- One unit of the file: the first `n` bytes of `d`, which start at file offset `base` (every offset in the events is
    relative to the unit; the unit block says where it starts).  `d` may go on past `n`: a header test near the end
    then sees the bytes the whole file has there.  `kind` is the reader's set kind (`834`); `rd` reads its sets.  The
    file's own fold is this with the whole file as the one unit.  The flag is `outerWith`'s. -/
@[specialize] def readUnit {σ : Type} [rd : SetReader σ] (kind : ByteArray) (base : Nat) (c0 : Carry) (d : ByteArray)
    (n : Nat) : Carry × Out × Bool :=
  let bom := base == 0 && n ≥ 3 && d[0]! == 0xEF && d[1]! == 0xBB && d[2]! == 0xBF
  let c := { c0 with rep := if bom then c0.rep.add .bom else c0.rep, closed := false, cut := 0, ctls := #[] }
  let hiOn := anyHigh (byteSeen d)
  let r := outerWith (fun n isa dl st => ichg (σ := σ) kind base d hiOn n isa dl st) d n (if bom then 3 else 0)
    (c, { ev := zeros (n + n / 2 + n / 4 + 4096) }) false
  (r.1.1, r.1.2, r.2)

/-- The file's closing block: the cause that refused the whole file (0 for none), then the repairs in first-seen order
    with their counts (tag 8). -/
def trailer (c : Carry) : ByteArray :=
  let refused :=
    if c.skipPost then c.refused
    else if c.first then Cause.noInterchange.ctorIdx + 1
    else if c.confirmed == 0 && c.ieaMissing then Cause.ieaMissing.ctorIdx + 1
    else c.refused
  let o : Out := { ev := zeros 4096 }
  let o := if !c.skipPost && c.first then o.quar .file .noInterchange 0 .none 0 0 0 else o
  let o := (o.w 8).w refused |>.w c.rep.order.size
  let o := c.rep.order.foldl (fun o r => (o.w r).w c.rep.counts[r]!) o
  o.ev.extract 0 o.len

/-- A unit's output as it goes to the stream: tag 7, where the unit starts and its length in the file, then the sizes of
    its events and of its side text, then both. -/
def unitBlock (base len : Nat) (o : Out) : ByteArray :=
  pushW (pushW (pushW (pushW (pushW ByteArray.empty 7) base) len) o.len) o.side.size ++ o.ev.extract 0 o.len ++ o.side

/-- The whole file as one unit; the plain reading that the chunked driver must agree with. -/
@[specialize] def readX12 {σ : Type} [rd : SetReader σ] (kind : ByteArray) (d : ByteArray) : ByteArray :=
  let (c, o, _) := readUnit (σ := σ) kind 0 {} d d.size
  unitBlock 0 d.size o ++ trailer c

end BlindLedger.X12
