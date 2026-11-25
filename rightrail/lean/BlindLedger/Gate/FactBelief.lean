import BlindLedger.Gate.FactRegistry

namespace BlindLedger.Gate.FactBelief

open FactCodec FactRegistry

/-! What the store believes about one subject on one date (design `fact-record` §3.2 to §3.4).

    `belief` answers one read of the pack for one key and one date `D`.  It reads the records known at
    batch `K` and judges freshness at the reading batch's own day.  `belief0` is the same question with no
    age test, no future test and no reference lag: the baseline that reopening compares with (§5.4).

    The answer is one of four: present (with the decision fields and the rows cited), absent, unknown (with a
    cause) or conflict.  Each source registered for the read's kind gives its own answer, and the answers are
    then combined, one source per origin.

    Choices that go beyond the design text, each noted at its definition:
    - a class number counts up from the strongest: class 1 is the strongest, so "at or above the minimum" is
      `cls ≤ minCls`;
    - which part of a value is a "decision field" (`decOf`);
    - whether a full file's scope holds a subject is the shard's rule, passed in as `inScope`;
    - a row speaks for the dates up to its `until` and takes part in the order of a statement only there;
    - an end row cuts a statement only on the dates it speaks for;
    - the rows the engine writes itself (ends) are not source rows, so they lift no marker;
    - a row or full receipt lifts a marker only when its file ranks at or above the quarantined row's file, so
      a late file never lifts a newer file's quarantine (arrival order alone never decides, §3.2);
    - a late full file proves absence only for the dates it still speaks for;
    - the flags `reused`, `dropped` and `refCap` are raised, and a signed confirmation clears one; raises and
      confirmations carry the batch that wrote them, so a reading at `K` sees only those up to `K`, and a flag is
      in force when its latest raise is not earlier than its latest confirmation;
    - the copies of one origin all count: a marker on any copy blocks, the copy cited is the newest as-of,
      and a copy that states what the cited copy does not makes the origin unknown;
    - a full file lifts a marker only for the dates it states (`cfrom ≤ D`), only with rows of the marker's
      kind, and only when it quarantined no row whose subject could not be read;
    - a full file that quarantined such a row leaves every statement it does not restate unknown on the
      dates it speaks for, and proves no absence on them. -/

/-- The roff of a row the engine writes itself (an end row for full-file absence, §3.3). -/
def engineRoff : Nat := 2 ^ 40 - 1

/-! ## Records -/

/-- Why a row was quarantined (§2.5).  A flood marker lifts by the bounds; every other cause is a row cause. -/
inductive MCause where
  | cents | date | kind | flood | oldFlood | repair
  deriving BEq, DecidableEq, Repr

def MCause.rowCause : MCause → Bool
  | .flood => false
  | .oldFlood => false
  | _ => true

/-- A fact row as the store holds it.  `seq` is the record number, `src`, `fseq` and `reader` come from the
    row's receipt (`fact.receipt` is the receipt's record number), and the batch that admitted it is the
    receipt's. -/
structure Row where
  seq : Nat
  src : Nat
  fseq : Nat
  reader : Nat
  fact : Fact

/-- A quarantine marker (§2.5): an unreadable row that names a subject.  `sidk = 1` when the statement's
    identity could be read and `sid` then holds it. -/
structure Marker where
  seq : Nat
  src : Nat
  fkind : Nat
  subject : Bytes
  rn : Nat
  cause : MCause
  sidk : Nat
  sid : Bytes
  deriving BEq

/-- Everything a shard holds that belief reads.  `recs` are the admitted receipts with their record numbers,
    `lifts` the flood markers the bounds have released (marker record number, batch), `refCap` the sources
    stopped by the reference cap.  `reused`, `dropped` and `refCap` are the flags raised (a raise of `reused` or
    `refCap` carries its batch, a dropped receipt its own); `reusedOk`, `droppedOk` and `refCapOk` are the signed
    confirmations that clear them, each with the batch that wrote it. -/
structure Store where
  recs : List Slot := []
  rows : List Row := []
  marks : List Marker := []
  reused : List (Nat × Nat) := []
  dropped : List Nat := []
  refCap : List (Nat × Nat) := []
  reusedOk : List (Nat × Nat) := []
  droppedOk : List (Nat × Nat) := []
  refCapOk : List (Nat × Nat) := []
  lifts : List (Nat × Nat) := []

/-- Is the flag of `s` in force?  Its latest raise is not earlier than its latest confirmation (a tie counts as in
    force, the cautious reading). -/
def flagOn (raises oks : List (Nat × Nat)) (s : Nat) : Bool :=
  raises.any fun p => p.1 == s && oks.all fun q => q.1 != s || decide (q.2 ≤ p.2)

/-- The registry's state: a flag counts while it is in force. -/
def Store.state (S : Store) : State :=
  { recs := S.recs
    reused := (S.reused.map (·.1)).filter (flagOn S.reused S.reusedOk)
    dropped := S.dropped.filter fun n => !S.droppedOk.any (·.1 == n) }

/-- The store after receipt `R` is admitted as record `n` with its rows `rs` and markers `ms`; `d` says its
    drop check failed. -/
def Store.admit (S : Store) (n : Nat) (R : Receipt) (rs : List Row) (ms : List Marker) (d : Bool) : Store :=
  { S with recs := S.recs ++ [(n, R)], rows := S.rows ++ rs, marks := S.marks ++ ms,
           dropped := if d then n :: S.dropped else S.dropped }

/-- The store restricted to what was known at batch `K`: the receipts of batches up to `K`, the rows, markers
    and drop flags that belong to them, and the raises, confirmations and lifts written by batches up to `K`. -/
def Store.upTo (S : Store) (K : Nat) : Store :=
  let recs := S.recs.filter fun s => decide (s.2.kb ≤ K)
  let seen := fun n => recs.any fun s => s.1 == n
  { recs := recs
    rows := S.rows.filter fun r => seen r.fact.receipt
    marks := S.marks.filter fun m => seen m.rn
    reused := S.reused.filter fun p => decide (p.2 ≤ K)
    dropped := S.dropped.filter seen
    refCap := S.refCap.filter fun p => decide (p.2 ≤ K)
    reusedOk := S.reusedOk.filter fun p => decide (p.2 ≤ K)
    droppedOk := S.droppedOk.filter fun p => decide (p.2 ≤ K)
    refCapOk := S.refCapOk.filter fun p => decide (p.2 ≤ K)
    lifts := S.lifts.filter fun p => decide (p.2 ≤ K) }

/-! ## The question -/

/-- The context of a read: the signed registry, the reading batch's day (`none` for `belief0`), the highest
    `fseq` any shard has admitted per reference source (§2.9), and the shard's rule that a full file's scope
    holds a subject. -/
structure Ctx where
  reg : Registry
  today : Option Nat
  refhi : List (Nat × Nat)
  inScope : Bytes → Bytes → Bool

/-- The context of `belief0`: no day, no reference lag. -/
def Ctx.zero (c : Ctx) : Ctx := { c with today := none, refhi := [] }

/-- Why a source gives no answer. -/
inductive Why where
  | stale (c : Cause)
  | refCap
  | refLag
  | noSource
  | quar
  | flood
  | oldFlood
  | sidOverlap
  | noCover
  | copies

inductive Res where
  | present (dec : List Nat) (cites : List Nat)
  | absent
  | unknown (w : Why)
  | conflict

def Res.isPresent : Res → Bool
  | .present _ _ => true
  | _ => false

def Res.isAbsent : Res → Bool
  | .absent => true
  | _ => false

def Res.isConflict : Res → Bool
  | .conflict => true
  | _ => false

/-- An unknown that blocks: the source cannot say, and another origin's "absent" must not stand.  A quarantine
    does, so does a clash of statement identities (`SID_OVERLAP`), and so do copies of one origin that disagree. -/
def Res.blocking : Res → Bool
  | .unknown .quar => true
  | .unknown .flood => true
  | .unknown .oldFlood => true
  | .unknown .sidOverlap => true
  | .unknown .copies => true
  | _ => false

/-- A copy's answer states nothing that the cited copy's answer does not: it is no answer, or the same one. -/
def Res.agrees (cited other : Res) : Bool :=
  match cited, other with
  | _, .unknown _ => true
  | .present d _, .present d' _ => d == d'
  | .absent, .absent => true
  | .conflict, .conflict => true
  | _, _ => false

def Res.cites : Res → List Nat
  | .present _ c => c
  | _ => []

/-- Two definite answers that disagree: present against absent, or present with different decision fields. -/
def Res.diff : Res → Res → Bool
  | .present d _, .present d' _ => d != d'
  | .present _ _, .absent => true
  | .absent, .present _ _ => true
  | _, _ => false

/-! ## Order and statements (§3.2) -/

/-- The order of rows of one source: the file's sequence number, then the reader release, then the row's
    place in the file. -/
def rankLt (a b : Row) : Bool :=
  decide (a.fseq < b.fseq ∨ (a.fseq = b.fseq ∧ (a.reader < b.reader ∨ (a.reader = b.reader ∧ a.fact.roff < b.fact.roff))))

theorem rankLt_trans {a b c : Row} (h1 : rankLt a b = true) (h2 : rankLt b c = true) : rankLt a c = true := by
  simp only [rankLt, decide_eq_true_eq] at *
  omega

/-- The part of a value a decision reads.  Eligibility: the status.  Exclusion: the waiver.  Deaths carry
    none (a death statement holding on the date is the whole answer).  The events (kinds 5 to 7) are not read
    through belief; their whole value counts, so any difference shows. -/
def decOf : Value → List Nat
  | .elig v => [v.status]
  | .death _ => []
  | .excl v => [v.waiver]
  | .pdeath _ => []
  | v => v.enc.map UInt8.toNat

def Row.dec (r : Row) : List Nat := decOf r.fact.value

/-- The rows of one source, kind and subject. -/
def rowsOf (S : Store) (src kind : Nat) (key : Bytes) : List Row :=
  S.rows.filter fun r => r.src == src && r.fact.value.kind == kind && r.fact.subject == key

/-- A row speaks for the dates up to its `until`.  It is the newest statement of its `sid` on `D` when it is
    not an end row, speaks for `D`, and no row that speaks for `D` and is not an end row ranks above it. -/
def newest (L : List Row) (D : Nat) (r : Row) : Bool :=
  r.fact.op != 2 && decide (D ≤ r.fact.lineUntil) &&
    L.all fun x => x.fact.sid != r.fact.sid || x.fact.op == 2 || !decide (D ≤ x.fact.lineUntil) || !rankLt r x

/-- A statement holds on `D` when its newest row is an assertion (not a void), `vstart ≤ D ≤ vstop`, and no
    end row of the same `sid` that ranks above it and speaks for `D` cuts it before `D`. -/
def holdsOn (L : List Row) (D : Nat) (r : Row) : Bool :=
  newest L D r && r.fact.op == 0 && decide (r.fact.vstart ≤ D) && decide (D ≤ r.fact.vstop) &&
    L.all fun x => !(x.fact.op == 2 && x.fact.sid == r.fact.sid && rankLt r x && decide (x.fact.vstop < D) &&
      decide (D ≤ x.fact.lineUntil))

/-- The statements of the rows `L` that hold on `D`. -/
def stmts (L : List Row) (D : Nat) : List Row := L.filter (holdsOn L D)

/-! ## Quarantine markers (§2.5) -/

/-- A row the source sent, as against one the engine wrote itself. -/
def wireRow (r : Row) : Bool := r.fact.roff != engineRoff

/-- Does the stored receipt numbered `n` rank at or below the file (`f`, `rd`): a lower `fseq`, or the same
    `fseq` and a reader release not above `rd`?  False when no receipt `n` is stored. -/
def rcptAtOrBelow (S : Store) (n f rd : Nat) : Bool :=
  S.recs.any fun s => s.1 == n && decide (s.2.fseq < f ∨ (s.2.fseq = f ∧ s.2.reader ≤ rd))

/-- Did the receipt quarantine a row whose subject could not be read?  The receipt counts every row it
    quarantined, and a marker is written for each one that names a subject. -/
def subjectless (S : Store) (n : Nat) (F : Receipt) : Bool :=
  decide ((S.marks.filter fun m => m.rn == n).length < F.quar)

/-- Is the stored receipt numbered `n` one that quarantined no row whose subject could not be read? -/
def cleanFile (S : Store) (n : Nat) : Bool :=
  S.recs.any fun s => s.1 == n && !subjectless S s.1 s.2

/-- Does a source row of the receipt numbered `n` give `key` a statement of kind `kind`? -/
def hasRow (S : Store) (n : Nat) (key : Bytes) (kind : Nat) : Bool :=
  S.rows.any fun r => wireRow r && r.fact.receipt == n && r.fact.subject == key && r.fact.value.kind == kind

/-- Does a source row of the receipt numbered `n` restate the statement `sid` of `key`? -/
def restates (S : Store) (n : Nat) (key sid : Bytes) : Bool :=
  S.rows.any fun x => wireRow x && x.fact.receipt == n && x.fact.subject == key && x.fact.sid == sid

/-- Has a row-cause marker been lifted for the date `D`?  Only by a later source row of the marker's kind with
    the marker's `sid` (when it could be read), or by a later full receipt of the source that states `D`
    (`cfrom ≤ D`), whose scope holds the subject, that has a source row of the kind for the subject and
    quarantined none of the subject's rows; either way from a file that quarantined no unreadable row and
    ranks at or above the quarantined row's file.  A flood marker lifts only by the bounds. -/
def lifted (c : Ctx) (S : Store) (m : Marker) (D : Nat) : Bool :=
  if m.cause.rowCause then
    (m.sidk == 1 && S.rows.any fun r => wireRow r && r.src == m.src && decide (m.seq < r.seq) && r.fact.sid == m.sid &&
      r.fact.value.kind == m.fkind && cleanFile S r.fact.receipt && rcptAtOrBelow S m.rn r.fseq r.reader) ||
    S.recs.any fun s => s.2.src == m.src && s.2.cover == 1 && decide (m.rn < s.1) && decide (s.2.cfrom ≤ D) &&
      c.inScope s.2.scope m.subject && !subjectless S s.1 s.2 &&
      hasRow S s.1 m.subject m.fkind &&
      !S.marks.any (fun q => q.rn == s.1 && q.subject == m.subject) && rcptAtOrBelow S m.rn s.2.fseq s.2.reader
  else S.lifts.any fun p => p.1 == m.seq

/-- The marker that blocks belief for (`src`, `kind`, `key`) on `D`, if one is in force. -/
def blockingMark (c : Ctx) (S : Store) (src kind : Nat) (key : Bytes) (D : Nat) : Option Marker :=
  S.marks.find? fun m => m.src == src && m.fkind == kind && m.subject == key && !lifted c S m D

def blockWhy : MCause → Why
  | .flood => .flood
  | .oldFlood => .oldFlood
  | _ => .quar

/-! ## One source (§3.4 items 1 to 4) -/

/-- Without the age and future tests of `staleCause`. -/
def staleCause0 (e : RegEntry) (st : State) : Option Cause :=
  match pickMax (rcptsOf st.recs e.src) with
  | none => some .noReceipt
  | some _ =>
    if gapOpen e (rcptsOf st.recs e.src) then some .gap
    else if st.recs.any (fun s => s.2.src == e.src && st.dropped.contains s.1) then some .drop
    else if st.reused.contains e.src then some .reused
    else none

/-- Is a reference source behind the frame's `refhi`? -/
def refLagging (c : Ctx) (S : Store) (e : RegEntry) : Bool :=
  c.refhi.any fun p => p.1 == e.src &&
    decide ((match pickMax (rcptsOf S.recs e.src) with | some n => n.fseq | none => 0) < p.2)

/-- Why the source is stale, if it is: the causes of the registry, then the reference cap, then the lag. -/
def staleW (c : Ctx) (S : Store) (e : RegEntry) : Option Why :=
  match (match c.today with
    | some t => staleCause e S.state t
    | none => staleCause0 e S.state) with
  | some w => some (.stale w)
  | none => if flagOn S.refCap S.refCapOk e.src then some .refCap else if refLagging c S e then some .refLag else none

/-- Can a full receipt prove that the source states nothing about `key` on `D`?  It must hold the key in its
    scope, state from a date at or before `D` and still speak for `D` (a late full file stops speaking where
    a newer one begins), have quarantined no unreadable row, and be the newest receipt of the source, or the
    source is gapless with no gap since. -/
def absentProof (c : Ctx) (S : Store) (e : RegEntry) (key : Bytes) (D : Nat) : Bool :=
  let rs := rcptsOf S.recs e.src
  match pickMax rs with
  | none => false
  | some hi =>
    S.recs.any fun s => s.2.src == e.src && s.2.cover == 1 && c.inScope s.2.scope key &&
      decide (s.2.cfrom ≤ D) && decide (D ≤ lateUntil rs s.2.fseq) && !subjectless S s.1 s.2 &&
      (s.2.fseq == hi.fseq || (e.gapless == 1 && !gapAt rs s.2.fseq hi.fseq))

/-- Did a full receipt that quarantined a row whose subject could not be read hold `key` in its scope, state `D` and
    still speak for it?  Whatever the source says (or does not say) about `key` on `D` is then unconfirmed. -/
def silencedF (c : Ctx) (S : Store) (src : Nat) (key : Bytes) (D : Nat) : Bool :=
  S.recs.any fun s => s.2.src == src && s.2.cover == 1 && c.inScope s.2.scope key && decide (s.2.cfrom ≤ D) &&
    decide (D ≤ lateUntil (rcptsOf S.recs src) s.2.fseq) && subjectless S s.1 s.2

/-- Is the statement `r` left unconfirmed on `D` by a full receipt that quarantined a row whose subject could not
    be read?  That file holds `key` in its scope, states `D` and still speaks for it, and has no source row
    restating `r`'s `sid` for the subject: the unreadable row may have changed or ended it. -/
def unconfirmedF (c : Ctx) (S : Store) (src : Nat) (key : Bytes) (D : Nat) (r : Row) : Bool :=
  S.recs.any fun s => s.2.src == src && s.2.cover == 1 && c.inScope s.2.scope key && decide (s.2.cfrom ≤ D) &&
    decide (D ≤ lateUntil (rcptsOf S.recs src) s.2.fseq) && subjectless S s.1 s.2 &&
    !restates S s.1 key r.fact.sid

/-- Is there a full receipt of the source, later than a file of sequence `f`, that holds `key` in its scope, states
    `D`, still speaks for it and quarantined no unreadable row?  Such a file lifts what that earlier file left open. -/
def lifter (c : Ctx) (S : Store) (src : Nat) (key : Bytes) (D f : Nat) : Bool :=
  S.recs.any fun g => g.2.src == src && g.2.cover == 1 && decide (f < g.2.fseq) && c.inScope g.2.scope key &&
    decide (g.2.cfrom ≤ D) && decide (D ≤ lateUntil (rcptsOf S.recs src) g.2.fseq) && !subjectless S g.1 g.2

/-- Did a file that is not a full file quarantine a row whose subject could not be read, and no later clean full file
    lifted it for `D`?  `keep n` says the file numbered `n` restates the statement asked
    about.  The lost row may have changed or ended any statement of the subject the file does not restate. -/
def deltaLost (c : Ctx) (S : Store) (src : Nat) (key : Bytes) (D : Nat) (keep : Nat → Bool) : Bool :=
  S.recs.any fun s => s.2.src == src && s.2.cover != 1 && c.inScope s.2.scope key &&
    subjectless S s.1 s.2 && !keep s.1 && !lifter c S src key D s.2.fseq

/-- Whatever the source says (or does not say) about `key` on `D` is unconfirmed. -/
def silenced (c : Ctx) (S : Store) (src : Nat) (key : Bytes) (D : Nat) : Bool :=
  silencedF c S src key D || deltaLost c S src key D (fun _ => false)

/-- The statement `r` is left unconfirmed on `D`. -/
def unconfirmed (c : Ctx) (S : Store) (src : Nat) (key : Bytes) (D : Nat) (r : Row) : Bool :=
  unconfirmedF c S src key D r || deltaLost c S src key D (fun n => restates S n key r.fact.sid)

/-- One source's answer for (`kind`, `key`, `D`). -/
def srcRes (c : Ctx) (S : Store) (e : RegEntry) (kind : Nat) (key : Bytes) (D : Nat) : Res :=
  match staleW c S e with
  | some w => .unknown w
  | none =>
    match blockingMark c S e.src kind key D with
    | some m => .unknown (blockWhy m.cause)
    | none =>
      match stmts (rowsOf S e.src kind key) D with
      | [] => if silenced c S e.src key D then .unknown .quar
              else if absentProof c S e key D then .absent else .unknown .noCover
      | s :: t =>
        if (s :: t).any (unconfirmed c S e.src key D) then .unknown .quar
        else if (s :: t).any (fun x => x.dec != s.dec) then .conflict
        else if e.oneper == 1 && (s :: t).any (fun x => x.fact.sid != s.fact.sid) then .unknown .sidOverlap
        else .present s.dec ((s :: t).map (·.seq))

/-! ## Combining the sources -/

/-- A source's answer with what precedence needs: its entry, the batch and as-of day of its newest receipt,
    and whether it is fresh (not stale at the reading day). -/
structure Cand where
  e : RegEntry
  kb : Nat
  asof : Nat
  fresh : Bool
  r : Res

def newestKb (S : Store) (src : Nat) : Nat :=
  match pickMax (rcptsOf S.recs src) with
  | some n => n.kb
  | none => 0

def newestAsof (S : Store) (src : Nat) : Nat :=
  match pickMax (rcptsOf S.recs src) with
  | some n => n.asof
  | none => 0

/-- The sources registered for the kind, at or above the minimum class (class 1 is the strongest). -/
def cands (c : Ctx) (S : Store) (minCls kind : Nat) (key : Bytes) (D : Nat) : List Cand :=
  (c.reg.filter fun e => Nat.testBit e.kinds kind && decide (e.cls ≤ minCls)).map fun e =>
    { e := e, kb := newestKb S e.src, asof := newestAsof S e.src, fresh := (staleW c S e).isNone,
      r := srcRes c S e kind key D }

/-- Precedence: the stronger class, then the newer batch, then the lower source number. -/
def beats (a b : Cand) : Bool :=
  decide (a.e.cls < b.e.cls ∨ (a.e.cls = b.e.cls ∧ (b.kb < a.kb ∨ (b.kb = a.kb ∧ a.e.src < b.e.src))))

/-- Which of two copies of one origin is cited: a fresh one over a stale one, then the newer as-of day, then the
    newer batch, then the lower source number. -/
def citedOver (a b : Cand) : Bool :=
  (a.fresh && !b.fresh) || (a.fresh == b.fresh &&
    decide (b.asof < a.asof ∨ (b.asof = a.asof ∧ (b.kb < a.kb ∨ (b.kb = a.kb ∧ a.e.src < b.e.src)))))

/-- The copy that nothing else in the list beats. -/
def pick (over : Cand → Cand → Bool) : List Cand → Option Cand
  | [] => none
  | x :: t => some (t.foldl (fun a b => if over b a then b else a) x)

/-- The copies of `a`'s origin that are fresh. -/
def freshCopies (cs : List Cand) (a : Cand) : List Cand :=
  cs.filter fun x => x.e.origin == a.e.origin && x.fresh

/-- The answer of one origin, whose cited copy is `a`: a marker on any fresh copy blocks; otherwise a fresh copy
    that contradicts the cited copy (present against absent, or different decision fields), or any
    copy in conflict, makes the origin a conflict, one that states what the cited copy does not makes it unknown; otherwise the cited copy's answer. -/
def originRes (cs : List Cand) (a : Cand) : Res :=
  match (freshCopies cs a).find? (·.r.blocking) with
  | some x => x.r
  | none =>
    if a.fresh && (a.r.isConflict || (freshCopies cs a).any (fun x => x.r.isConflict || a.r.diff x.r)) then .conflict
    else if (freshCopies cs a).any (fun x => !a.r.agrees x.r) then .unknown .copies else a.r

/-- The copy of `a`'s origin that is cited. -/
def citedOf (cs : List Cand) (a : Cand) : Option Cand :=
  pick citedOver (cs.filter fun b => b.e.origin == a.e.origin)

/-- Sources with one origin count once: the cited copy, with the answer all its fresh copies give together. -/
def reps (cs : List Cand) : List Cand :=
  (cs.filter fun a => (citedOf cs a).any (·.e.src == a.e.src)).map fun a => { a with r := originRes cs a }

def strongest (cs : List Cand) : Option Cand := pick beats cs

def strongestWhy (cs : List Cand) : Why :=
  match strongest cs with
  | some { r := .unknown w, .. } => w
  | _ => .noSource

/-- The combination, given the answers `rs` of the sources `rc` that count.  Two origins that give different
    definite results are a conflict, whatever their classes.  Otherwise a blocking quarantine with no origin
    present is unknown.  Otherwise a definite result wins over unknowns; with none the answer is unknown with
    the strongest source's cause. -/
def combineRs (rc : List Cand) (rs : List Res) : Res :=
  if rs.any Res.isConflict || rs.any (fun a => rs.any (Res.diff a)) then .conflict
  else if rs.any Res.blocking && !rs.any Res.isPresent then
    .unknown (match rs.find? Res.blocking with
      | some (.unknown w) => w
      | _ => .quar)
  else
    match rs.find? Res.isPresent with
    | some (.present d _) => .present d (rs.flatMap Res.cites)
    | _ => if rs.any Res.isAbsent then .absent else .unknown (strongestWhy rc)

def combine (cs : List Cand) : Res := combineRs (reps cs) ((reps cs).map (·.r))

/-! ## Belief -/

/-- Belief on a store already restricted to what was known. -/
def beliefCore (c : Ctx) (S : Store) (minCls kind : Nat) (key : Bytes) (D : Nat) : Res :=
  combine (cands c S minCls kind key D)

/-- `belief(B, read, key, D)`: the records known at batch `K` (`B - 1`), the reading batch's day in `c.today`. -/
def belief (c : Ctx) (S : Store) (K minCls kind : Nat) (key : Bytes) (D : Nat) : Res :=
  beliefCore c (S.upTo K) minCls kind key D

/-- `belief0`: the same without the age test, the future test and the reference lag. -/
def belief0 (c : Ctx) (S : Store) (K minCls kind : Nat) (key : Bytes) (D : Nat) : Res :=
  belief c.zero S K minCls kind key D

/-! ## `belief_local` -/

/-- Belief is a function of the records known at `K`, the day and the registry. -/
theorem belief_local {c : Ctx} {S S' : Store} {K : Nat} (h : S.upTo K = S'.upTo K) (minCls kind : Nat)
    (key : Bytes) (D : Nat) : belief c S K minCls kind key D = belief c S' K minCls kind key D := by
  simp only [belief, h]

/-- The same for `belief0`, which takes no day. -/
theorem belief0_local {c : Ctx} {S S' : Store} {K : Nat} (h : S.upTo K = S'.upTo K) (minCls kind : Nat)
    (key : Bytes) (D : Nat) : belief0 c S K minCls kind key D = belief0 c S' K minCls kind key D :=
  belief_local h minCls kind key D

/-- `belief0` takes neither the day nor the reference highs. -/
theorem belief0_ignores_day_and_refhi (c : Ctx) (t : Option Nat) (r : List (Nat × Nat)) (S : Store) (K minCls kind : Nat)
    (key : Bytes) (D : Nat) :
    belief0 { c with today := t, refhi := r } S K minCls kind key D = belief0 c S K minCls kind key D := rfl

/-- A receipt of a later batch, with its rows and markers, changes nothing known at `K`. -/
theorem belief_ignores_later (c : Ctx) (S : Store) (n : Nat) (R : Receipt) (rs : List Row) (ms : List Marker)
    (d : Bool) (K minCls kind : Nat) (key : Bytes) (D : Nat) (hK : K < R.kb) (hn : ∀ s ∈ S.recs, s.1 ≠ n)
    (hrs : ∀ r ∈ rs, r.fact.receipt = n) (hms : ∀ m ∈ ms, m.rn = n) :
    belief c (S.admit n R rs ms d) K minCls kind key D = belief c S K minCls kind key D := by
  apply belief_local
  have hR : ¬ R.kb ≤ K := by omega
  have e1 : (S.recs ++ [(n, R)]).filter (fun s => decide (s.2.kb ≤ K)) = S.recs.filter (fun s => decide (s.2.kb ≤ K)) := by
    simp [List.filter_append, hR]
  have hseen : ∀ x, (∃ s ∈ S.recs.filter (fun s => decide (s.2.kb ≤ K)), s.1 = x) → x ≠ n := by
    rintro x ⟨s, hs, rfl⟩
    exact hn s (List.mem_filter.mp hs).1
  have hno : ∀ x, x = n → (S.recs.filter (fun s => decide (s.2.kb ≤ K))).any (fun s => s.1 == x) = false := by
    intro x hx
    rw [Bool.eq_false_iff]
    intro h
    obtain ⟨s, hs, hsx⟩ := List.any_eq_true.mp h
    exact hseen x ⟨s, hs, by simpa using hsx⟩ hx
  unfold Store.upTo Store.admit
  simp only [e1, List.filter_append]
  congr 1
  · have : rs.filter (fun r => (S.recs.filter (fun s => decide (s.2.kb ≤ K))).any (fun s => s.1 == r.fact.receipt)) = [] := by
      rw [List.filter_eq_nil_iff]
      intro r hr
      rw [hno _ (hrs r hr)]
      simp
    rw [this, List.append_nil]
  · have : ms.filter (fun m => (S.recs.filter (fun s => decide (s.2.kb ≤ K))).any (fun s => s.1 == m.rn)) = [] := by
      rw [List.filter_eq_nil_iff]
      intro m hm
      rw [hno _ (hms m hm)]
      simp
    rw [this, List.append_nil]
  · split
    · simp only [List.filter_cons]
      rw [if_neg]
      simp [hno n rfl]
    · rfl

/-! ## `stale_no_result` and `ref_lag` -/

/-- A stale source gives no answer, whatever its rows say. -/
theorem srcRes_stale {c : Ctx} {S : Store} {e : RegEntry} (kind : Nat) (key : Bytes) (D : Nat)
    (h : staleW c S e ≠ none) : ∃ w, srcRes c S e kind key D = .unknown w := by
  unfold srcRes
  cases hs : staleW c S e with
  | none => exact absurd hs h
  | some w => exact ⟨w, by simp [hs]⟩

/-- `stale_no_result`: a source stale at the reading day contributes neither present nor absent (nor a
    conflict of its own). -/
theorem stale_no_result {c : Ctx} {S : Store} {e : RegEntry} (kind : Nat) (key : Bytes) (D : Nat)
    (h : staleW c S e ≠ none) :
    (srcRes c S e kind key D).isPresent = false ∧ (srcRes c S e kind key D).isAbsent = false ∧
      (srcRes c S e kind key D).isConflict = false := by
  obtain ⟨w, hw⟩ := srcRes_stale kind key D h
  rw [hw]
  simp [Res.isPresent, Res.isAbsent, Res.isConflict]

theorem diff_sure {a b : Res} (h : Res.diff a b = true) : a.isPresent = true ∨ a.isAbsent = true := by
  cases a <;> cases b <;> simp_all [Res.diff, Res.isPresent, Res.isAbsent]

/-- A definite or conflicting result comes from a definite or conflicting answer of a source that counts. -/
theorem combineRs_definite {rc : List Cand} {rs : List Res} {r : Res} (hr : combineRs rc rs = r)
    (h : r.isPresent = true ∨ r.isAbsent = true ∨ r.isConflict = true) :
    ∃ a ∈ rs, (a.isPresent || a.isAbsent || a.isConflict) = true := by
  unfold combineRs at hr
  by_cases h1 : (rs.any Res.isConflict || rs.any (fun a => rs.any (Res.diff a))) = true
  · simp only [Bool.or_eq_true, List.any_eq_true] at h1
    rcases h1 with ⟨a, ha, hc⟩ | ⟨a, ha, b, hb, hab⟩
    · exact ⟨a, ha, by simp [hc]⟩
    · rcases diff_sure hab with hp | hp
      · exact ⟨a, ha, by simp [hp]⟩
      · exact ⟨a, ha, by simp [hp]⟩
  · rw [if_neg h1] at hr
    by_cases h2 : (rs.any Res.blocking && !rs.any Res.isPresent) = true
    · rw [if_pos h2] at hr
      subst hr
      simp [Res.isPresent, Res.isAbsent, Res.isConflict] at h
    · rw [if_neg h2] at hr
      cases hf : rs.find? Res.isPresent with
      | some a =>
        have ha := List.find?_some hf
        exact ⟨a, List.mem_of_find?_eq_some hf, by simp [ha]⟩
      | none =>
        rw [hf] at hr
        by_cases h3 : rs.any Res.isAbsent = true
        · obtain ⟨a, ha, hb⟩ := List.any_eq_true.mp h3
          exact ⟨a, ha, by simp [hb]⟩
        · simp only [h3] at hr
          subst hr
          simp [Res.isPresent, Res.isAbsent, Res.isConflict] at h

theorem combine_definite {cs : List Cand} {r : Res} (hr : combine cs = r)
    (h : r.isPresent = true ∨ r.isAbsent = true ∨ r.isConflict = true) :
    ∃ x ∈ reps cs, (x.r.isPresent || x.r.isAbsent || x.r.isConflict) = true := by
  obtain ⟨a, ha, hs⟩ := combineRs_definite hr h
  obtain ⟨x, hx, rfl⟩ := List.mem_map.mp ha
  exact ⟨x, hx, hs⟩

theorem mem_cands {c : Ctx} {S : Store} {minCls kind : Nat} {key : Bytes} {D : Nat} {x : Cand}
    (hx : x ∈ cands c S minCls kind key D) :
    ∃ e ∈ c.reg, x.e = e ∧ x.r = srcRes c S e kind key D ∧ x.fresh = (staleW c S e).isNone := by
  unfold cands at hx
  obtain ⟨e, he, rfl⟩ := List.mem_map.mp hx
  exact ⟨e, (List.mem_filter.mp he).1, rfl, rfl, rfl⟩

theorem mem_reps {cs : List Cand} {x : Cand} (hx : x ∈ reps cs) :
    ∃ a ∈ cs, x.e = a.e ∧ x.r = originRes cs a := by
  unfold reps at hx
  obtain ⟨a, ha, rfl⟩ := List.mem_map.mp hx
  exact ⟨a, (List.mem_filter.mp ha).1, rfl, rfl⟩

/-- A definite or conflicting answer of an origin comes only from a fresh cited copy. -/
theorem originRes_definite {cs : List Cand} {a : Cand}
    (hst : a.fresh = false → a.r.isPresent = false ∧ a.r.isAbsent = false ∧ a.r.isConflict = false)
    (h : (originRes cs a).isPresent = true ∨ (originRes cs a).isAbsent = true ∨ (originRes cs a).isConflict = true) :
    a.fresh = true := by
  refine Classical.byContradiction fun hf => ?_
  have hf' : a.fresh = false := by simpa using hf
  unfold originRes at h
  cases hf2 : (freshCopies cs a).find? (·.r.blocking) with
  | some x =>
    have hb := List.find?_some hf2
    rw [hf2] at h
    cases hr : x.r <;> simp_all [Res.blocking, Res.isPresent, Res.isAbsent, Res.isConflict]
  | none =>
    simp only [hf2, hf', Bool.false_and, Bool.false_eq_true, ↓reduceIte] at h
    by_cases hd2 : ((freshCopies cs a).any fun x => !a.r.agrees x.r) = true
    · rw [if_pos hd2] at h
      simp [Res.isPresent, Res.isAbsent, Res.isConflict] at h
    · rw [if_neg hd2] at h
      obtain ⟨h1, h2, h3⟩ := hst hf'
      simp [h1, h2, h3] at h

/-- A stale source is never the reason belief is present, absent or in conflict. -/
theorem belief_definite_fresh {c : Ctx} {S : Store} {minCls kind : Nat} {key : Bytes} {D : Nat} {r : Res}
    (hr : beliefCore c S minCls kind key D = r)
    (h : r.isPresent = true ∨ r.isAbsent = true ∨ r.isConflict = true) :
    ∃ x ∈ reps (cands c S minCls kind key D), staleW c S x.e = none := by
  obtain ⟨x, hx, hs⟩ := combine_definite hr h
  refine ⟨x, hx, ?_⟩
  obtain ⟨a, ha, hxe, hxr⟩ := mem_reps hx
  obtain ⟨e, _, hae, har, haf⟩ := mem_cands ha
  have hdef : x.r.isPresent = true ∨ x.r.isAbsent = true ∨ x.r.isConflict = true := by
    simpa [Bool.or_eq_true, or_assoc] using hs
  rw [hxr] at hdef
  have hdr := originRes_definite (a := a) (fun hf => by
    have hne : staleW c S e ≠ none := by
      intro h0
      rw [h0] at haf
      simp at haf
      simp [haf] at hf
    have := stale_no_result (S := S) kind key D hne
    rw [har]
    exact ⟨this.1, this.2.1, this.2.2⟩) hdef
  rw [hxe, hae]
  rw [hdr] at haf
  exact Option.isNone_iff_eq_none.mp haf.symm

theorem refLagging_stale {c : Ctx} {S : Store} {e : RegEntry} (h : refLagging c S e = true) :
    staleW c S e ≠ none := by
  unfold staleW
  split
  · simp
  · split <;> simp_all

/-- `ref_lag`: a source whose highest admitted `fseq` is below the frame's `refhi` gives neither present nor
    absent. -/
theorem ref_lag {c : Ctx} {S : Store} {e : RegEntry} (kind : Nat) (key : Bytes) (D : Nat)
    (h : refLagging c S e = true) :
    (srcRes c S e kind key D).isPresent = false ∧ (srcRes c S e kind key D).isAbsent = false :=
  ⟨(stale_no_result kind key D (refLagging_stale h)).1, (stale_no_result kind key D (refLagging_stale h)).2.1⟩

/-- `belief0` carries no reference highs, so no source lags in it: a lag never reopens a line. -/
theorem ref_lag_belief0 (c : Ctx) (S : Store) (e : RegEntry) : refLagging c.zero S e = false := by
  simp [refLagging, Ctx.zero]

/-! ## `quar_not_absent`, `marker_lift`, `conflict_kept` -/

theorem combineRs_ne_absent {rc : List Cand} {rs : List Res} (h : ∃ a ∈ rs, a.blocking = true) :
    combineRs rc rs ≠ .absent := by
  unfold combineRs
  by_cases h1 : (rs.any Res.isConflict || rs.any (fun a => rs.any (Res.diff a))) = true
  · rw [if_pos h1]; nofun
  · rw [if_neg h1]
    by_cases h2 : (rs.any Res.blocking && !rs.any Res.isPresent) = true
    · rw [if_pos h2]; nofun
    · rw [if_neg h2]
      have hb : rs.any Res.blocking = true := by
        obtain ⟨a, ha, hb⟩ := h
        exact List.any_eq_true.mpr ⟨a, ha, hb⟩
      have hp : rs.any Res.isPresent = true := by
        refine Classical.byContradiction fun hp => h2 ?_
        simp [hb, hp]
      obtain ⟨a, ha, hpa⟩ := List.any_eq_true.mp hp
      have hs : (rs.find? Res.isPresent).isSome = true := List.find?_isSome.mpr ⟨a, ha, hpa⟩
      obtain ⟨r, hr⟩ := Option.isSome_iff_exists.mp hs
      have hrp := List.find?_some hr
      rw [hr]
      cases r <;> simp_all [Res.isPresent]

theorem foldl_pick_mem (over : Cand → Cand → Bool) (t : List Cand) (x : Cand) :
    t.foldl (fun a b => if over b a then b else a) x ∈ x :: t := by
  induction t generalizing x with
  | nil => simp
  | cons y t ih =>
    simp only [List.foldl_cons]
    rcases List.mem_cons.mp (ih (if over y x = true then y else x)) with h2 | h2
    · rw [h2]
      split <;> simp
    · exact List.mem_cons_of_mem _ (List.mem_cons_of_mem _ h2)

theorem pick_mem {over : Cand → Cand → Bool} {l : List Cand} {p : Cand} (h : pick over l = some p) : p ∈ l := by
  cases l with
  | nil => simp [pick] at h
  | cons x t =>
    simp only [pick, Option.some.injEq] at h
    rw [← h]
    exact foldl_pick_mem over t x

/-- `quar_not_absent`: when a quarantine marker is in force on `D` for a source that counts and is not stale,
    belief is not absent.  Every copy of an origin counts, not only the cited one; only a stale source is not
    read. -/
theorem quar_not_absent {c : Ctx} {S : Store} {minCls kind : Nat} {key : Bytes} {D : Nat} {x : Cand}
    (hx : x ∈ cands c S minCls kind key D) (hs : staleW c S x.e = none)
    (hm : ∃ m ∈ S.marks, m.src = x.e.src ∧ m.fkind = kind ∧ m.subject = key ∧ lifted c S m D = false) :
    beliefCore c S minCls kind key D ≠ .absent := by
  obtain ⟨e, _, hxe, hxr, hxf⟩ := mem_cands hx
  have hfresh : x.fresh = true := by rw [hxf, ← hxe, hs]; rfl
  have hsome : (blockingMark c S x.e.src kind key D).isSome = true := by
    unfold blockingMark
    rw [List.find?_isSome]
    obtain ⟨m, hm1, h1, h2, h3, h4⟩ := hm
    exact ⟨m, hm1, by simp [h1, h2, h3, h4]⟩
  obtain ⟨m', hm'⟩ := Option.isSome_iff_exists.mp hsome
  have hb : x.r.blocking = true := by
    rw [hxr, ← hxe]
    unfold srcRes
    rw [hs]
    simp only [hm']
    cases m'.cause <;> rfl
  -- the cited copy of x's origin stands for it, and the origin's answer blocks
  unfold beliefCore combine
  generalize hcs : cands c S minCls kind key D = cs at hx ⊢
  have hg : x ∈ cs.filter fun b => b.e.origin == x.e.origin := List.mem_filter.mpr ⟨hx, by simp⟩
  have hne : (cs.filter fun b => b.e.origin == x.e.origin) ≠ [] := List.ne_nil_of_mem hg
  have hpk : ∃ p, pick citedOver (cs.filter fun b => b.e.origin == x.e.origin) = some p := by
    cases hl : cs.filter fun b => b.e.origin == x.e.origin with
    | nil => exact absurd hl hne
    | cons y t => exact ⟨_, rfl⟩
  obtain ⟨p, hp⟩ := hpk
  have hpm := List.mem_filter.mp (pick_mem hp)
  have hpo : p.e.origin = x.e.origin := by simpa using hpm.2
  have hcp : citedOf cs p = some p := by
    unfold citedOf
    rw [hpo]
    exact hp
  have hpr : { p with r := originRes cs p } ∈ reps cs := by
    unfold reps
    refine List.mem_map.mpr ⟨p, List.mem_filter.mpr ⟨hpm.1, ?_⟩, rfl⟩
    simp [hcp]
  have hfr : x ∈ freshCopies cs p :=
    List.mem_filter.mpr ⟨hx, by simp [hpo, hfresh]⟩
  have hfs : ((freshCopies cs p).find? (·.r.blocking)).isSome = true :=
    List.find?_isSome.mpr ⟨x, hfr, hb⟩
  obtain ⟨y, hy⟩ := Option.isSome_iff_exists.mp hfs
  have hyb := List.find?_some hy
  have hres : originRes cs p = y.r := by
    unfold originRes
    simp only [hy]
  exact combineRs_ne_absent ⟨_, List.mem_map.mpr ⟨_, hpr, rfl⟩, by simpa [hres] using hyb⟩

theorem upTo_mem_marks {S : Store} {K1 K2 : Nat} (h : K1 ≤ K2) {m : Marker} (hm : m ∈ (S.upTo K1).marks) :
    m ∈ (S.upTo K2).marks := by
  simp only [Store.upTo, List.mem_filter, List.any_eq_true, decide_eq_true_eq] at hm ⊢
  obtain ⟨h1, s, ⟨hs, hk⟩, hsn⟩ := hm
  exact ⟨h1, s, ⟨hs, by omega⟩, hsn⟩

/-- `marker_lift`: a row-cause marker that was in force on `D` at `K1` and is not at a later `K2` has been lifted,
    and only by a later source row of its kind with its `sid` (when it could be read), or by a later full receipt
    of the source that states `D` (`cfrom ≤ D`), holds the subject in its scope, has a source row of the kind for
    it and quarantined none of its rows; either way from a file that quarantined no unreadable row and ranks at
    or above the quarantined row's file. -/
theorem marker_lift (c : Ctx) (S : Store) {m : Marker} (hr : m.cause.rowCause = true) {K1 K2 D : Nat}
    (h12 : K1 ≤ K2) (hin : m ∈ (S.upTo K1).marks ∧ lifted c (S.upTo K1) m D = false)
    (hout : ¬ (m ∈ (S.upTo K2).marks ∧ lifted c (S.upTo K2) m D = false)) :
    (m.sidk = 1 ∧ ∃ r ∈ (S.upTo K2).rows, wireRow r = true ∧ r.src = m.src ∧ m.seq < r.seq ∧ r.fact.sid = m.sid ∧
      r.fact.value.kind = m.fkind ∧ cleanFile (S.upTo K2) r.fact.receipt = true ∧
      rcptAtOrBelow (S.upTo K2) m.rn r.fseq r.reader = true) ∨
    ∃ s ∈ (S.upTo K2).recs, s.2.src = m.src ∧ s.2.cover = 1 ∧ m.rn < s.1 ∧ s.2.cfrom ≤ D ∧
      c.inScope s.2.scope m.subject = true ∧ subjectless (S.upTo K2) s.1 s.2 = false ∧
      hasRow (S.upTo K2) s.1 m.subject m.fkind = true ∧
      (∀ q ∈ (S.upTo K2).marks, ¬ (q.rn = s.1 ∧ q.subject = m.subject)) ∧
      rcptAtOrBelow (S.upTo K2) m.rn s.2.fseq s.2.reader = true := by
  have hm2 := upTo_mem_marks h12 hin.1
  have hl : lifted c (S.upTo K2) m D = true := by
    refine Classical.byContradiction fun hn => hout ⟨hm2, ?_⟩
    simpa using hn
  unfold lifted at hl
  rw [if_pos hr] at hl
  simp only [Bool.or_eq_true, Bool.and_eq_true, List.any_eq_true, beq_iff_eq, decide_eq_true_eq,
    Bool.not_eq_eq_eq_not, Bool.not_true] at hl
  rcases hl with ⟨hk, r, hrm, ⟨⟨⟨⟨⟨hw, hsrc⟩, hseq⟩, hsid⟩, hkind⟩, hcl⟩, hrk⟩ |
    ⟨s, hs, ⟨⟨⟨⟨⟨⟨⟨hsrc, hcov⟩, hlt⟩, hcf⟩, hsc⟩, hsl⟩, hrow⟩, hnq⟩, hrk⟩
  · exact Or.inl ⟨hk, r, hrm, hw, hsrc, hseq, hsid, hkind, hcl, hrk⟩
  · refine Or.inr ⟨s, hs, hsrc, hcov, hlt, hcf, hsc, ?_, hrow, ?_, hrk⟩
    · simpa using hsl
    · intro q hq ⟨h1, h2⟩
      have h3 : ((S.upTo K2).marks.any fun q => q.rn == s.fst && q.subject == m.subject) = true :=
        List.any_eq_true.mpr ⟨q, hq, by simp [h1, h2]⟩
      rw [hnq] at h3
      exact Bool.noConfusion h3

/-- `conflict_kept`: two origins that give different definite results are a conflict, whatever their classes. -/
theorem conflict_kept (cs : List Cand) {a b : Cand} (ha : a ∈ reps cs) (hb : b ∈ reps cs)
    (hab : Res.diff a.r b.r = true) : combine cs = .conflict := by
  unfold combine combineRs
  have h : ((reps cs).map (·.r)).any (fun a => ((reps cs).map (·.r)).any (Res.diff a)) = true :=
    List.any_eq_true.mpr ⟨a.r, List.mem_map.mpr ⟨a, ha, rfl⟩,
      List.any_eq_true.mpr ⟨b.r, List.mem_map.mpr ⟨b, hb, rfl⟩, hab⟩⟩
  rw [if_pos]
  exact (Bool.or_eq_true _ _).mpr (Or.inr h)

/-! ## List facts -/

theorem any_false {α : Type} {l : List α} {p : α → Bool} (h : ∀ a ∈ l, p a = false) : l.any p = false := by
  rw [Bool.eq_false_iff]
  intro hp
  obtain ⟨a, ha, hpa⟩ := List.any_eq_true.mp hp
  rw [h a ha] at hpa
  exact Bool.noConfusion hpa

theorem any_congr_mem {α : Type} {l : List α} {p q : α → Bool} (h : ∀ a ∈ l, p a = q a) : l.any p = l.any q := by
  induction l with
  | nil => rfl
  | cons a t ih => simp only [List.any_cons, h a (by simp), ih (fun b hb => h b (by simp [hb]))]

theorem find?_congr_mem {α : Type} {l : List α} {p q : α → Bool} (h : ∀ a ∈ l, p a = q a) :
    l.find? p = l.find? q := by
  induction l with
  | nil => rfl
  | cons a t ih => simp only [List.find?_cons, h a (by simp), ih (fun b hb => h b (by simp [hb]))]

/-- An `any` over `l ++ m` that agrees with `q` on `l` and is false on `m`. -/
theorem any_append_false {α : Type} {l m : List α} {p q : α → Bool} (h1 : ∀ a ∈ l, p a = q a)
    (h2 : ∀ a ∈ m, p a = false) : (l ++ m).any p = l.any q := by
  rw [List.any_append, any_congr_mem h1, any_false h2, Bool.or_false]

theorem find?_append_none {α : Type} {l m : List α} {p q : α → Bool} (h1 : ∀ a ∈ l, p a = q a)
    (h2 : ∀ a ∈ m, p a = false) : (l ++ m).find? p = l.find? q := by
  have : m.find? p = none := List.find?_eq_none.mpr fun a ha => by simp [h2 a ha]
  rw [List.find?_append, find?_congr_mem h1, this, Option.or_none]

/-! ## Statements a row stops speaking for -/

/-- Rows that speak for no date at or after `D` (`until < D`), and end rows that do not cut before `D`
    (`vstop ≥ D`), change no statement that holds on `D`. -/
theorem stmts_silent (L E : List Row) (D : Nat)
    (hE : ∀ e ∈ E, (e.fact.op = 2 ∧ D ≤ e.fact.vstop) ∨ e.fact.lineUntil < D) :
    stmts (L ++ E) D = stmts L D := by
  have hh : ∀ r, holdsOn (L ++ E) D r = holdsOn L D r := by
    intro r
    unfold holdsOn newest
    have h1 : (E.all fun x => x.fact.sid != r.fact.sid || x.fact.op == 2 || !decide (D ≤ x.fact.lineUntil) ||
        !rankLt r x) = true := by
      rw [List.all_eq_true]
      intro x hx
      rcases hE x hx with ⟨h, _⟩ | h
      · simp [h]
      · simp [Nat.not_le.mpr h]
    have h2 : (E.all fun x => !(x.fact.op == 2 && x.fact.sid == r.fact.sid && rankLt r x &&
        decide (x.fact.vstop < D) && decide (D ≤ x.fact.lineUntil))) = true := by
      rw [List.all_eq_true]
      intro x hx
      rcases hE x hx with ⟨_, h⟩ | h
      · simp [Nat.not_lt.mpr h]
      · simp [Nat.not_le.mpr h]
    simp only [List.all_append, h1, h2, Bool.and_true]
  have hE0 : E.filter (holdsOn (L ++ E) D) = [] := by
    rw [List.filter_eq_nil_iff]
    intro r hr
    rw [hh]
    rcases hE r hr with ⟨h, _⟩ | h
    · simp [holdsOn, newest, h]
    · simp [holdsOn, newest, Nat.not_le.mpr h]
  unfold stmts
  rw [List.filter_append, hE0, List.append_nil]
  exact List.filter_congr (fun r _ => hh r)

/-! ## Congruence of one source's answer and of belief -/

theorem srcRes_congr {c : Ctx} {T T' : Store} {e : RegEntry} {kind : Nat} {key : Bytes} {D : Nat} (E : List Row)
    (hst : staleW c T' e = staleW c T e)
    (hbm : blockingMark c T' e.src kind key D = blockingMark c T e.src kind key D)
    (hrows : T'.rows = T.rows ++ E) (hE : ∀ x ∈ E, (x.fact.op = 2 ∧ D ≤ x.fact.vstop) ∨ x.fact.lineUntil < D)
    (hab : absentProof c T' e key D = absentProof c T e key D)
    (hsl : silenced c T' e.src key D = silenced c T e.src key D)
    (hun : ∀ r, unconfirmed c T' e.src key D r = unconfirmed c T e.src key D r) :
    srcRes c T' e kind key D = srcRes c T e kind key D := by
  have hs : stmts (rowsOf T' e.src kind key) D = stmts (rowsOf T e.src kind key) D := by
    unfold rowsOf
    rw [hrows, List.filter_append]
    exact stmts_silent _ _ D (fun x hx => hE x (List.mem_filter.mp hx).1)
  have hun' : unconfirmed c T' e.src key D = unconfirmed c T e.src key D := funext hun
  unfold srcRes
  simp only [hst, hbm, hab, hsl, hs, hun']

theorem beliefCore_congr {c : Ctx} {T T' : Store} {minCls kind : Nat} {key : Bytes} {D : Nat}
    (h : ∀ e ∈ c.reg, newestKb T' e.src = newestKb T e.src ∧ newestAsof T' e.src = newestAsof T e.src ∧
      staleW c T' e = staleW c T e ∧ srcRes c T' e kind key D = srcRes c T e kind key D) :
    beliefCore c T' minCls kind key D = beliefCore c T minCls kind key D := by
  unfold beliefCore cands
  congr 1
  apply List.map_congr_left
  intro e he
  have := h e (List.mem_filter.mp he).1
  simp only [this.1, this.2.1, this.2.2.1, this.2.2.2]

/-! ## `full_ends_not_voids` -/

theorem hasRow_ends (T : Store) (E : List Row) (hE : ∀ x ∈ E, wireRow x = false) (n : Nat) (key : Bytes) (kind : Nat) :
    hasRow { T with rows := T.rows ++ E } n key kind = hasRow T n key kind := by
  unfold hasRow
  apply any_append_false
  · intro _ _
    rfl
  · intro r hr
    simp [hE r hr]

theorem restates_ends (T : Store) (E : List Row) (hE : ∀ x ∈ E, wireRow x = false) (n : Nat) (key sid : Bytes) :
    restates { T with rows := T.rows ++ E } n key sid = restates T n key sid := by
  unfold restates
  apply any_append_false
  · intro _ _
    rfl
  · intro r hr
    simp [hE r hr]

/-- Rows the engine writes itself lift no marker. -/
theorem lifted_ends (c : Ctx) (T : Store) (E : List Row) (hE : ∀ x ∈ E, wireRow x = false) (m : Marker)
    (D : Nat) : lifted c { T with rows := T.rows ++ E } m D = lifted c T m D := by
  unfold lifted
  by_cases h : m.cause.rowCause = true
  · rw [if_pos h, if_pos h]
    congr 1
    · congr 1
      apply any_append_false
      · intro _ _
        rfl
      · intro r hr
        simp [hE r hr]
    · apply any_congr_mem
      intro s _
      simp only [hasRow_ends T E hE]
      try rfl
  · rw [if_neg h, if_neg h]

theorem silencedF_ends (c : Ctx) (T : Store) (E : List Row) (src : Nat) (key : Bytes) (D : Nat) :
    silencedF c { T with rows := T.rows ++ E } src key D = silencedF c T src key D := rfl

theorem unconfirmedF_ends (c : Ctx) (T : Store) (E : List Row) (hE : ∀ x ∈ E, wireRow x = false) (src : Nat)
    (key : Bytes) (D : Nat) (r : Row) :
    unconfirmedF c { T with rows := T.rows ++ E } src key D r = unconfirmedF c T src key D r := by
  unfold unconfirmedF
  apply any_congr_mem
  intro s _
  simp only [restates_ends T E hE]
  rfl

theorem silenced_ends (c : Ctx) (T : Store) (E : List Row) (src : Nat) (key : Bytes) (D : Nat) :
    silenced c { T with rows := T.rows ++ E } src key D = silenced c T src key D := rfl

theorem unconfirmed_ends (c : Ctx) (T : Store) (E : List Row) (hE : ∀ x ∈ E, wireRow x = false) (src : Nat)
    (key : Bytes) (D : Nat) (r : Row) :
    unconfirmed c { T with rows := T.rows ++ E } src key D r = unconfirmed c T src key D r := by
  unfold unconfirmed
  rw [unconfirmedF_ends c T E hE src key D r]
  have : (fun n => restates { T with rows := T.rows ++ E } n key r.fact.sid) = fun n => restates T n key r.fact.sid :=
    funext fun n => restates_ends T E hE n key r.fact.sid
  rw [this]
  rfl

theorem upTo_rows (S : Store) (E : List Row) (K : Nat) :
    ({ S with rows := S.rows ++ E } : Store).upTo K =
      { S.upTo K with rows := (S.upTo K).rows ++ E.filter fun r =>
          (S.upTo K).recs.any fun s => s.1 == r.fact.receipt } := by
  simp only [Store.upTo, List.filter_append]

/-- The end rows of full-file absence change no belief on a date they do not cut. -/
theorem beliefCore_ends (c : Ctx) (T : Store) (E : List Row) (minCls kind : Nat) (key : Bytes) (D : Nat)
    (hE : ∀ x ∈ E, x.fact.op = 2 ∧ x.fact.roff = engineRoff ∧ D ≤ x.fact.vstop) :
    beliefCore c { T with rows := T.rows ++ E } minCls kind key D = beliefCore c T minCls kind key D := by
  apply beliefCore_congr
  intro e _
  have hw : ∀ x ∈ E, wireRow x = false := fun x hx => by simp [wireRow, (hE x hx).2.1]
  refine ⟨rfl, rfl, rfl, srcRes_congr E rfl ?_ rfl (fun x hx => Or.inl ⟨(hE x hx).1, (hE x hx).2.2⟩) rfl
    (silenced_ends c T E e.src key D) (unconfirmed_ends c T E hw e.src key D)⟩
  unfold blockingMark
  apply find?_congr_mem
  intro m _
  rw [lifted_ends c T E hw m D]

/-- `full_ends_not_voids`: the end rows the engine writes when it admits a full receipt `F` (`op = 2`, never a void;
    the engine's `roff`; `vstop` the day before `cfrom(F)`) change no `belief`, so no `belief0`, for any key on any
    date before `cfrom(F)`.  `F`'s own rows, markers, receipt and staleness are the only ways its admission reaches
    those dates.  The end writer is not modelled here, so the shape of its rows is a hypothesis. -/
theorem full_ends_not_voids (c : Ctx) (S : Store) (F : Receipt) (es : List Row) (K minCls kind : Nat) (key : Bytes)
    (D : Nat) (hE : ∀ x ∈ es, x.fact.op = 2 ∧ x.fact.roff = engineRoff ∧ x.fact.vstop = dayBefore F.cfrom)
    (hD : Rules.validDate D = true) (hF : F.cfrom = 0 ∨ Rules.validDate F.cfrom = true) (hlt : D < F.cfrom) :
    belief c { S with rows := S.rows ++ es } K minCls kind key D = belief c S K minCls kind key D := by
  have hc : Rules.validDate F.cfrom = true := hF.resolve_left (by omega)
  have hle : D ≤ dayBefore F.cfrom := le_dayBefore hD hc hlt
  unfold belief
  rw [upTo_rows]
  refine beliefCore_ends c _ _ minCls kind key D fun x hx => ?_
  have h := hE x (List.mem_filter.mp hx).1
  exact ⟨h.1, h.2.1, by rw [h.2.2]; exact hle⟩

/-! ## `late_never_overrides` -/

theorem mem_rcptsOf {recs : List Slot} {s : Slot} {src : Nat} (h : s ∈ recs) (hs : s.2.src = src) :
    s.2 ∈ rcptsOf recs src :=
  List.mem_map.mpr ⟨s, List.mem_filter.mpr ⟨h, by simp [hs]⟩, rfl⟩

theorem rcptsOf_snoc_same (recs : List Slot) (n : Nat) (R : Receipt) (src : Nat) (h : R.src = src) :
    rcptsOf (recs ++ [(n, R)]) src = rcptsOf recs src ++ [R] := by
  simp [rcptsOf, h]

theorem rcptsOf_snoc_other (recs : List Slot) (n : Nat) (R : Receipt) (src : Nat) (h : ¬ R.src = src) :
    rcptsOf (recs ++ [(n, R)]) src = rcptsOf recs src := by
  simp [rcptsOf, h]

theorem pickMax_snoc_low (rs : List Receipt) (R : Receipt) (h : ∃ g ∈ rs, R.fseq < g.fseq) :
    pickMax (rs ++ [R]) = pickMax rs := by
  obtain ⟨g, hg, hlt⟩ := h
  cases rs with
  | nil => simp at hg
  | cons x t =>
    obtain ⟨_, h2, h3⟩ := foldl_stepMax t x
    have hR : R.fseq < (t.foldl stepMax x).fseq := by
      rcases List.mem_cons.mp hg with rfl | hg
      · omega
      · have := h3 g hg
        omega
    simp only [List.cons_append, pickMax, List.foldl_append, List.foldl_cons, List.foldl_nil, stepMax,
      Option.some.injEq]
    rw [if_neg (Nat.not_lt.mpr (Nat.le_of_lt hR))]

theorem gapAt_snoc_low (rs : List Receipt) (R : Receipt) (b h : Nat) (hb : ¬ (b < R.fseq ∧ R.fseq < h)) :
    gapAt (rs ++ [R]) b h = gapAt rs b h := by
  rw [Bool.eq_iff_iff, gapAt_iff, gapAt_iff]
  constructor
  · rintro ⟨f, h1, h2, h3⟩
    exact ⟨f, h1, h2, fun a ha => h3 a (List.mem_append_left _ ha)⟩
  · rintro ⟨f, h1, h2, h3⟩
    refine ⟨f, h1, h2, fun a ha => ?_⟩
    rcases List.mem_append.mp ha with ha | ha
    · exact h3 a ha
    · rw [List.mem_singleton.mp ha]
      intro hf
      exact hb ⟨by omega, by omega⟩

theorem lateUntil_snoc_low (rs : List Receipt) (R : Receipt) (f : Nat) (h : ¬ f < R.fseq) :
    lateUntil (rs ++ [R]) f = lateUntil rs f := by
  unfold lateUntil
  rw [List.filter_append]
  have : [R].filter (fun a => a.cover == 1 && decide (f < a.fseq)) = [] := by simp [h]
  rw [this, List.append_nil]

theorem gapOpen_snoc_low (e : RegEntry) (rs : List Receipt) (R G : Receipt) (hG : G ∈ rs) (hc : G.cover = 1)
    (hlt : R.fseq < G.fseq) : gapOpen e (rs ++ [R]) = gapOpen e rs := by
  have hm : pickMax (rs ++ [R]) = pickMax rs := pickMax_snoc_low rs R ⟨G, hG, hlt⟩
  have hGf : G ∈ rs.filter (·.cover == 1) := List.mem_filter.mpr ⟨hG, by simp [hc]⟩
  have hf : pickMax ((rs ++ [R]).filter (·.cover == 1)) = pickMax (rs.filter (·.cover == 1)) := by
    rw [List.filter_append]
    by_cases h : R.cover = 1
    · have : [R].filter (·.cover == 1) = [R] := by simp [h]
      rw [this]
      exact pickMax_snoc_low _ R ⟨G, hGf, hlt⟩
    · have : [R].filter (·.cover == 1) = [] := by simp [h]
      rw [this, List.append_nil]
  obtain ⟨f, hfe⟩ := pickMax_isSome (List.ne_nil_of_mem hGf)
  have hfG : G.fseq ≤ f.fseq := (pickMax_spec hfe).2 G hGf
  unfold gapOpen
  rw [hm, hf, hfe]
  cases pickMax rs with
  | none => rfl
  | some hi =>
    dsimp only
    rw [gapAt_snoc_low rs R f.fseq hi.fseq (by omega)]

/-- A receipt `n` with its rows and markers changes nothing about the other receipts' counts of quarantined rows. -/
theorem subjectless_admit {T T' : Store} {n : Nat} {ms : List Marker} (hmarks : T'.marks = T.marks ++ ms)
    (hms : ∀ q ∈ ms, q.rn = n) {k : Nat} (hk : k ≠ n) (F : Receipt) : subjectless T' k F = subjectless T k F := by
  unfold subjectless
  rw [hmarks, List.filter_append]
  have : ms.filter (fun m => m.rn == k) = [] := by
    rw [List.filter_eq_nil_iff]
    intro q hq
    simp [hms q hq, Ne.symm hk]
  rw [this, List.append_nil]

theorem cleanFile_admit {T T' : Store} {n : Nat} {R : Receipt} {ms : List Marker}
    (hrecs : T'.recs = T.recs ++ [(n, R)]) (hmarks : T'.marks = T.marks ++ ms) (hn : ∀ s ∈ T.recs, s.1 ≠ n)
    (hms : ∀ q ∈ ms, q.rn = n) {k : Nat} (hk : k ≠ n) : cleanFile T' k = cleanFile T k := by
  unfold cleanFile
  rw [hrecs]
  apply any_append_false
  · intro s hs
    rw [subjectless_admit hmarks hms (hn s hs)]
  · intro s hs
    simp only [List.mem_singleton] at hs
    subst hs
    simp [Ne.symm hk]

theorem hasRow_admit {T T' : Store} {n : Nat} {rs : List Row} (hrows : T'.rows = T.rows ++ rs)
    (hrs : ∀ r ∈ rs, r.fact.receipt = n) {k : Nat} (hk : k ≠ n) (key : Bytes) (kind : Nat) :
    hasRow T' k key kind = hasRow T k key kind := by
  unfold hasRow
  rw [hrows]
  apply any_append_false
  · intro _ _
    rfl
  · intro r hr
    simp [hrs r hr, Ne.symm hk]

theorem restates_admit {T T' : Store} {n : Nat} {rs : List Row} (hrows : T'.rows = T.rows ++ rs)
    (hrs : ∀ r ∈ rs, r.fact.receipt = n) {k : Nat} (hk : k ≠ n) (key sid : Bytes) :
    restates T' k key sid = restates T k key sid := by
  unfold restates
  rw [hrows]
  apply any_append_false
  · intro _ _
    rfl
  · intro r hr
    simp [hrs r hr, Ne.symm hk]

/-- A receipt, its rows and its markers lift no marker of another source anew and undo no lift of one. -/
theorem lifted_admit (c : Ctx) (T T' : Store) (n : Nat) (R : Receipt) (rs : List Row) (ms : List Marker)
    (hrecs : T'.recs = T.recs ++ [(n, R)]) (hrows : T'.rows = T.rows ++ rs) (hmarks : T'.marks = T.marks ++ ms)
    (hlifts : T'.lifts = T.lifts) (hn : ∀ s ∈ T.recs, s.1 ≠ n) (hnr : ∀ r ∈ T.rows, r.fact.receipt ≠ n)
    (hrs : ∀ r ∈ rs, r.src = R.src ∧ r.fact.receipt = n) (hms : ∀ q ∈ ms, q.rn = n)
    (m : Marker) (D : Nat) (hm : m.src ≠ R.src) (hmn : m.rn ≠ n) : lifted c T' m D = lifted c T m D := by
  have hb : ∀ f rd, rcptAtOrBelow T' m.rn f rd = rcptAtOrBelow T m.rn f rd := by
    intro f rd
    unfold rcptAtOrBelow
    rw [hrecs]
    apply any_append_false
    · intro _ _
      rfl
    · intro s hs
      simp only [List.mem_singleton] at hs
      subst hs
      simp [Ne.symm hmn]
  unfold lifted
  simp only [hb, hrows, hrecs, hmarks, hlifts]
  by_cases h : m.cause.rowCause = true
  · rw [if_pos h, if_pos h]
    congr 1
    · congr 1
      apply any_append_false
      · intro r hr
        rw [cleanFile_admit hrecs hmarks hn hms (hnr r hr)]
      · intro r hr
        simp [(hrs r hr).1, Ne.symm hm]
    · apply any_append_false
      · intro s hs
        rw [subjectless_admit hmarks hms (hn s hs), hasRow_admit hrows (fun r hr => (hrs r hr).2) (hn s hs)]
        have e2 : (T.marks ++ ms).any (fun q => q.rn == s.1 && q.subject == m.subject) =
            T.marks.any (fun q => q.rn == s.1 && q.subject == m.subject) := by
          apply any_append_false
          · intro _ _
            rfl
          · intro q hq
            simp [hms q hq, Ne.symm (hn s hs)]
        rw [e2]
      · intro s hs
        simp only [List.mem_singleton] at hs
        subst hs
        simp [Ne.symm hm]
  · rw [if_neg h, if_neg h]

theorem absentProof_late (c : Ctx) (T T' : Store) (n : Nat) (R : Receipt) (ms : List Marker) (e : RegEntry)
    (key : Bytes) (D : Nat) (hrecs : T'.recs = T.recs ++ [(n, R)]) (hmarks : T'.marks = T.marks ++ ms)
    (hn : ∀ s ∈ T.recs, s.1 ≠ n) (hms : ∀ q ∈ ms, q.rn = n) (G : Slot) (hGm : G ∈ T.recs)
    (hGs : G.2.src = R.src) (hGc : G.2.cover = 1) (hGf : R.fseq < G.2.fseq) (hGd : G.2.cfrom ≤ D) (hD : 0 < D) :
    absentProof c T' e key D = absentProof c T e key D := by
  have hsub : ∀ s ∈ T.recs, subjectless T' s.1 s.2 = subjectless T s.1 s.2 := by
    intro s hs
    unfold subjectless
    rw [hmarks, List.filter_append]
    have : ms.filter (fun m => m.rn == s.1) = [] := by
      rw [List.filter_eq_nil_iff]
      intro q hq
      simp [hms q hq, Ne.symm (hn s hs)]
    rw [this, List.append_nil]
  by_cases hsrc : R.src = e.src
  · have hGr : G.2 ∈ rcptsOf T.recs e.src := mem_rcptsOf hGm (hGs.trans hsrc)
    simp only [absentProof, hrecs, rcptsOf_snoc_same T.recs n R e.src hsrc,
      pickMax_snoc_low _ R ⟨G.2, hGr, hGf⟩]
    cases pickMax (rcptsOf T.recs e.src) with
    | none => rfl
    | some hi =>
      dsimp only
      apply any_append_false
      · intro s hs
        rw [hsub s hs]
        by_cases hlow : s.2.fseq < R.fseq
        · have h1 : lateUntil (rcptsOf T.recs e.src ++ [R]) s.2.fseq < D :=
            lateUntil_lt _ _ D G.2 (List.mem_append_left _ hGr) hGc (by omega) hGd hD
          have h2 : lateUntil (rcptsOf T.recs e.src) s.2.fseq < D :=
            lateUntil_lt _ _ D G.2 hGr hGc (by omega) hGd hD
          simp [Nat.not_le.mpr h1, Nat.not_le.mpr h2]
        · rw [lateUntil_snoc_low _ R _ hlow, gapAt_snoc_low (rcptsOf T.recs e.src) R s.2.fseq hi.fseq (by omega)]
      · intro s hs
        simp only [List.mem_singleton] at hs
        subst hs
        have h1 : lateUntil (rcptsOf T.recs e.src ++ [R]) R.fseq < D :=
          lateUntil_lt _ _ D G.2 (List.mem_append_left _ hGr) hGc hGf hGd hD
        simp [Nat.not_le.mpr h1]
  · simp only [absentProof, hrecs, rcptsOf_snoc_other T.recs n R e.src hsrc]
    cases pickMax (rcptsOf T.recs e.src) with
    | none => rfl
    | some hi =>
      dsimp only
      apply any_append_false
      · intro s hs
        rw [hsub s hs]
      · intro s hs
        simp only [List.mem_singleton] at hs
        subst hs
        simp [hsrc]

theorem silencedF_late (c : Ctx) (T T' : Store) (n : Nat) (R : Receipt) (ms : List Marker)
    (src : Nat) (key : Bytes) (D : Nat) (hrecs : T'.recs = T.recs ++ [(n, R)]) (hmarks : T'.marks = T.marks ++ ms)
    (hn : ∀ s ∈ T.recs, s.1 ≠ n) (hms : ∀ q ∈ ms, q.rn = n)
    (G : Slot) (hGm : G ∈ T.recs) (hGs : G.2.src = R.src) (hGc : G.2.cover = 1) (hGf : R.fseq < G.2.fseq)
    (hGd : G.2.cfrom ≤ D) (hD : 0 < D) :
    silencedF c T' src key D = silencedF c T src key D := by
  unfold silencedF
  by_cases hsrc : R.src = src
  · have hGr : G.2 ∈ rcptsOf T.recs src := mem_rcptsOf hGm (hGs.trans hsrc)
    simp only [hrecs, rcptsOf_snoc_same T.recs n R src hsrc]
    apply any_append_false
    · intro s hs
      rw [subjectless_admit hmarks hms (hn s hs)]
      by_cases hlow : s.2.fseq < R.fseq
      · have h1 : lateUntil (rcptsOf T.recs src ++ [R]) s.2.fseq < D :=
          lateUntil_lt _ _ D G.2 (List.mem_append_left _ hGr) hGc (by omega) hGd hD
        have h2 : lateUntil (rcptsOf T.recs src) s.2.fseq < D :=
          lateUntil_lt _ _ D G.2 hGr hGc (by omega) hGd hD
        simp [Nat.not_le.mpr h1, Nat.not_le.mpr h2]
      · rw [lateUntil_snoc_low _ R _ hlow]
    · intro s hs
      simp only [List.mem_singleton] at hs
      subst hs
      have h1 : lateUntil (rcptsOf T.recs src ++ [R]) R.fseq < D :=
        lateUntil_lt _ _ D G.2 (List.mem_append_left _ hGr) hGc hGf hGd hD
      simp [Nat.not_le.mpr h1]
  · simp only [hrecs, rcptsOf_snoc_other T.recs n R src hsrc]
    apply any_append_false
    · intro s hs
      rw [subjectless_admit hmarks hms (hn s hs)]
    · intro s hs
      simp only [List.mem_singleton] at hs
      subst hs
      simp [hsrc]

/-- A late receipt leaves the statements that a full file with an unreadable row leaves unconfirmed as they were
    on a date a newer full receipt states: it speaks for no such date, and every other file keeps its count. -/
theorem unconfirmedF_late (c : Ctx) (T T' : Store) (n : Nat) (R : Receipt) (rs : List Row) (ms : List Marker)
    (src : Nat) (key : Bytes) (D : Nat) (r : Row) (hrecs : T'.recs = T.recs ++ [(n, R)])
    (hrows : T'.rows = T.rows ++ rs) (hmarks : T'.marks = T.marks ++ ms)
    (hn : ∀ s ∈ T.recs, s.1 ≠ n) (hrs : ∀ x ∈ rs, x.fact.receipt = n) (hms : ∀ q ∈ ms, q.rn = n)
    (G : Slot) (hGm : G ∈ T.recs) (hGs : G.2.src = R.src) (hGc : G.2.cover = 1) (hGf : R.fseq < G.2.fseq)
    (hGd : G.2.cfrom ≤ D) (hD : 0 < D) :
    unconfirmedF c T' src key D r = unconfirmedF c T src key D r := by
  unfold unconfirmedF
  by_cases hsrc : R.src = src
  · have hGr : G.2 ∈ rcptsOf T.recs src := mem_rcptsOf hGm (hGs.trans hsrc)
    simp only [hrecs, rcptsOf_snoc_same T.recs n R src hsrc]
    apply any_append_false
    · intro s hs
      rw [subjectless_admit hmarks hms (hn s hs), restates_admit hrows hrs (hn s hs)]
      by_cases hlow : s.2.fseq < R.fseq
      · have h1 : lateUntil (rcptsOf T.recs src ++ [R]) s.2.fseq < D :=
          lateUntil_lt _ _ D G.2 (List.mem_append_left _ hGr) hGc (by omega) hGd hD
        have h2 : lateUntil (rcptsOf T.recs src) s.2.fseq < D :=
          lateUntil_lt _ _ D G.2 hGr hGc (by omega) hGd hD
        simp [Nat.not_le.mpr h1, Nat.not_le.mpr h2]
      · rw [lateUntil_snoc_low _ R _ hlow]
    · intro s hs
      simp only [List.mem_singleton] at hs
      subst hs
      have h1 : lateUntil (rcptsOf T.recs src ++ [R]) R.fseq < D :=
        lateUntil_lt _ _ D G.2 (List.mem_append_left _ hGr) hGc hGf hGd hD
      simp [Nat.not_le.mpr h1]
  · simp only [hrecs, rcptsOf_snoc_other T.recs n R src hsrc]
    apply any_append_false
    · intro s hs
      rw [subjectless_admit hmarks hms (hn s hs), restates_admit hrows hrs (hn s hs)]
    · intro s hs
      simp only [List.mem_singleton] at hs
      subst hs
      simp [hsrc]

theorem lifter_late (c : Ctx) (T T' : Store) (n : Nat) (R : Receipt) (ms : List Marker)
    (src : Nat) (key : Bytes) (D f : Nat) (hrecs : T'.recs = T.recs ++ [(n, R)]) (hmarks : T'.marks = T.marks ++ ms)
    (hn : ∀ s ∈ T.recs, s.1 ≠ n) (hms : ∀ q ∈ ms, q.rn = n)
    (G : Slot) (hGm : G ∈ T.recs) (hGs : G.2.src = R.src) (hGc : G.2.cover = 1) (hGf : R.fseq < G.2.fseq)
    (hGd : G.2.cfrom ≤ D) (hD : 0 < D) :
    lifter c T' src key D f = lifter c T src key D f := by
  unfold lifter
  by_cases hsrc : R.src = src
  · have hGr : G.2 ∈ rcptsOf T.recs src := mem_rcptsOf hGm (hGs.trans hsrc)
    simp only [hrecs, rcptsOf_snoc_same T.recs n R src hsrc]
    apply any_append_false
    · intro s hs
      rw [subjectless_admit hmarks hms (hn s hs)]
      by_cases hlow : s.2.fseq < R.fseq
      · have h1 : lateUntil (rcptsOf T.recs src ++ [R]) s.2.fseq < D :=
          lateUntil_lt _ _ D G.2 (List.mem_append_left _ hGr) hGc (by omega) hGd hD
        have h2 : lateUntil (rcptsOf T.recs src) s.2.fseq < D :=
          lateUntil_lt _ _ D G.2 hGr hGc (by omega) hGd hD
        simp [Nat.not_le.mpr h1, Nat.not_le.mpr h2]
      · rw [lateUntil_snoc_low _ R _ hlow]
    · intro s hs
      simp only [List.mem_singleton] at hs
      subst hs
      have h1 : lateUntil (rcptsOf T.recs src ++ [R]) R.fseq < D :=
        lateUntil_lt _ _ D G.2 (List.mem_append_left _ hGr) hGc hGf hGd hD
      simp [Nat.not_le.mpr h1]
  · simp only [hrecs, rcptsOf_snoc_other T.recs n R src hsrc]
    apply any_append_false
    · intro s hs
      rw [subjectless_admit hmarks hms (hn s hs)]
    · intro s hs
      simp only [List.mem_singleton] at hs
      subst hs
      simp [hsrc]

theorem deltaLost_late (c : Ctx) (T T' : Store) (n : Nat) (R : Receipt) (ms : List Marker)
    (src : Nat) (key : Bytes) (D : Nat) (keep keep' : Nat → Bool) (hkeep : ∀ k, k ≠ n → keep' k = keep k)
    (hrecs : T'.recs = T.recs ++ [(n, R)]) (hmarks : T'.marks = T.marks ++ ms)
    (hn : ∀ s ∈ T.recs, s.1 ≠ n) (hms : ∀ q ∈ ms, q.rn = n)
    (G : Slot) (hGm : G ∈ T.recs) (hGs : G.2.src = R.src) (hGc : G.2.cover = 1) (hGf : R.fseq < G.2.fseq)
    (hGd : G.2.cfrom ≤ D) (hD : 0 < D) (hq : R.cover = 1 ∨ subjectless T' n R = false) :
    deltaLost c T' src key D keep' = deltaLost c T src key D keep := by
  have hl : ∀ f, lifter c T' src key D f = lifter c T src key D f := fun f =>
    lifter_late c T T' n R ms src key D f hrecs hmarks hn hms G hGm hGs hGc hGf hGd hD
  unfold deltaLost
  simp only [hl]
  rw [hrecs]
  apply any_append_false
  · intro s hs
    rw [subjectless_admit hmarks hms (hn s hs), hkeep s.1 (hn s hs)]
  · intro s hs
    simp only [List.mem_singleton] at hs
    subst hs
    rcases hq with h | h <;> simp [h]

theorem silenced_late (c : Ctx) (T T' : Store) (n : Nat) (R : Receipt) (ms : List Marker)
    (src : Nat) (key : Bytes) (D : Nat) (hrecs : T'.recs = T.recs ++ [(n, R)]) (hmarks : T'.marks = T.marks ++ ms)
    (hn : ∀ s ∈ T.recs, s.1 ≠ n) (hms : ∀ q ∈ ms, q.rn = n)
    (G : Slot) (hGm : G ∈ T.recs) (hGs : G.2.src = R.src) (hGc : G.2.cover = 1) (hGf : R.fseq < G.2.fseq)
    (hGd : G.2.cfrom ≤ D) (hD : 0 < D) (hq : R.cover = 1 ∨ subjectless T' n R = false) :
    silenced c T' src key D = silenced c T src key D := by
  unfold silenced
  rw [silencedF_late c T T' n R ms src key D hrecs hmarks hn hms G hGm hGs hGc hGf hGd hD,
    deltaLost_late c T T' n R ms src key D _ _ (fun _ _ => rfl) hrecs hmarks hn hms G hGm hGs hGc hGf hGd hD hq]

theorem unconfirmed_late (c : Ctx) (T T' : Store) (n : Nat) (R : Receipt) (rs : List Row) (ms : List Marker)
    (src : Nat) (key : Bytes) (D : Nat) (r : Row) (hrecs : T'.recs = T.recs ++ [(n, R)])
    (hrows : T'.rows = T.rows ++ rs) (hmarks : T'.marks = T.marks ++ ms)
    (hn : ∀ s ∈ T.recs, s.1 ≠ n) (hrs : ∀ x ∈ rs, x.fact.receipt = n) (hms : ∀ q ∈ ms, q.rn = n)
    (G : Slot) (hGm : G ∈ T.recs) (hGs : G.2.src = R.src) (hGc : G.2.cover = 1) (hGf : R.fseq < G.2.fseq)
    (hGd : G.2.cfrom ≤ D) (hD : 0 < D) (hq : R.cover = 1 ∨ subjectless T' n R = false) :
    unconfirmed c T' src key D r = unconfirmed c T src key D r := by
  unfold unconfirmed
  rw [unconfirmedF_late c T T' n R rs ms src key D r hrecs hrows hmarks hn hrs hms G hGm hGs hGc hGf hGd hD,
    deltaLost_late c T T' n R ms src key D (fun k => restates T k key r.fact.sid)
      (fun k => restates T' k key r.fact.sid) (fun k hk => restates_admit hrows hrs hk key r.fact.sid)
      hrecs hmarks hn hms G hGm hGs hGc hGf hGd hD hq]

/-- The core of `late_never_overrides`, on a store already restricted to what was known. -/
theorem beliefCore_late (c : Ctx) (T : Store) (n : Nat) (R : Receipt) (rs : List Row) (ms : List Marker)
    (minCls kind : Nat) (key : Bytes) (D : Nat)
    (hn : ∀ s ∈ T.recs, s.1 ≠ n) (hnr : ∀ r ∈ T.rows, r.fact.receipt ≠ n) (hnm : ∀ m ∈ T.marks, m.rn ≠ n)
    (hnd : n ∉ T.dropped)
    (hrs : ∀ r ∈ rs, r.src = R.src ∧ r.fact.receipt = n ∧ r.fact.lineUntil < D)
    (hms : ∀ m ∈ ms, m.src = R.src ∧ m.rn = n)
    (G : Slot) (hGm : G ∈ T.recs) (hGs : G.2.src = R.src) (hGc : G.2.cover = 1) (hGf : R.fseq < G.2.fseq)
    (hGd : G.2.cfrom ≤ D) (hD : 0 < D) (hq : R.cover = 1 ∨ ¬ ms.length < R.quar)
    (hmk : blockingMark c.zero (T.admit n R rs ms false) R.src kind key D = blockingMark c.zero T R.src kind key D) :
    beliefCore c.zero (T.admit n R rs ms false) minCls kind key D = beliefCore c.zero T minCls kind key D := by
  have hrecs : (T.admit n R rs ms false).recs = T.recs ++ [(n, R)] := rfl
  have hrows : (T.admit n R rs ms false).rows = T.rows ++ rs := rfl
  have hmarks : (T.admit n R rs ms false).marks = T.marks ++ ms := rfl
  have hdrop : (T.admit n R rs ms false).dropped = T.dropped := rfl
  have hreused : (T.admit n R rs ms false).reused = T.reused := rfl
  have hcap : (T.admit n R rs ms false).refCap = T.refCap := rfl
  have hlifts : (T.admit n R rs ms false).lifts = T.lifts := rfl
  have hdropOk : (T.admit n R rs ms false).droppedOk = T.droppedOk := rfl
  have hreusedOk : (T.admit n R rs ms false).reusedOk = T.reusedOk := rfl
  have hcapOk : (T.admit n R rs ms false).refCapOk = T.refCapOk := rfl
  have hq' : R.cover = 1 ∨ subjectless (T.admit n R rs ms false) n R = false := by
    rcases hq with h | h
    · exact Or.inl h
    · right
      unfold subjectless
      rw [hmarks, List.filter_append,
        List.filter_eq_nil_iff.mpr (fun m hm => by simp [hnm m hm]),
        List.filter_eq_self.mpr (fun m hm => by simp [(hms m hm).2])]
      simp [h]
  have hpm : ∀ src, pickMax (rcptsOf (T.recs ++ [(n, R)]) src) = pickMax (rcptsOf T.recs src) := by
    intro src
    by_cases h : R.src = src
    · rw [rcptsOf_snoc_same _ n R src h]
      exact pickMax_snoc_low _ R ⟨G.2, mem_rcptsOf hGm (hGs.trans h), hGf⟩
    · rw [rcptsOf_snoc_other _ n R src h]
  have hgo : ∀ e : RegEntry, gapOpen e (rcptsOf (T.recs ++ [(n, R)]) e.src) = gapOpen e (rcptsOf T.recs e.src) := by
    intro e
    by_cases h : R.src = e.src
    · rw [rcptsOf_snoc_same _ n R e.src h]
      exact gapOpen_snoc_low e _ R G.2 (mem_rcptsOf hGm (hGs.trans h)) hGc hGf
    · rw [rcptsOf_snoc_other _ n R e.src h]
  have hnd' : ¬ n ∈ T.dropped.filter (fun k => !T.droppedOk.any (·.1 == k)) :=
    fun h => hnd (List.mem_filter.mp h).1
  have hst : ∀ e : RegEntry, staleW c.zero (T.admit n R rs ms false) e = staleW c.zero T e := by
    intro e
    have hd : (T.recs ++ [(n, R)]).any (fun s => s.2.src == e.src &&
          (T.dropped.filter fun k => !T.droppedOk.any (·.1 == k)).contains s.1) =
        T.recs.any (fun s => s.2.src == e.src && (T.dropped.filter fun k => !T.droppedOk.any (·.1 == k)).contains s.1) := by
      apply any_append_false
      · intro _ _
        rfl
      · intro s hs
        simp only [List.mem_singleton] at hs
        subst hs
        have : (T.dropped.filter fun k => !T.droppedOk.any (·.1 == k)).contains n = false := by
          rw [Bool.eq_false_iff]
          intro h
          exact hnd' (by simpa using h)
        show (R.src == e.src && (T.dropped.filter fun k => !T.droppedOk.any (·.1 == k)).contains n) = false
        rw [this, Bool.and_false]
    have h0 : staleCause0 e (T.admit n R rs ms false).state = staleCause0 e T.state := by
      unfold staleCause0 Store.state
      simp only [hrecs, hdrop, hreused, hdropOk, hreusedOk, hpm e.src, hgo e, hd]
    have ht : c.zero.today = none := rfl
    unfold staleW
    simp only [ht, ref_lag_belief0, h0, hcap, hcapOk]
  apply beliefCore_congr
  intro e _
  refine ⟨by unfold newestKb; rw [hrecs, hpm], by unfold newestAsof; rw [hrecs, hpm], hst e,
    srcRes_congr rs (hst e) ?_ hrows
    (fun x hx => Or.inr (hrs x hx).2.2) (absentProof_late c.zero T _ n R ms e key D hrecs hmarks hn
      (fun q hq => (hms q hq).2) G hGm hGs hGc hGf hGd hD)
    (silenced_late c.zero T _ n R ms e.src key D hrecs hmarks hn (fun q hq => (hms q hq).2)
      G hGm hGs hGc hGf hGd hD hq')
    (fun r => unconfirmed_late c.zero T _ n R rs ms e.src key D r hrecs hrows hmarks hn
      (fun x hx => (hrs x hx).2.1) (fun q hq => (hms q hq).2) G hGm hGs hGc hGf hGd hD hq')⟩
  by_cases h : e.src = R.src
  · rw [h]
    exact hmk
  · unfold blockingMark
    apply find?_append_none
    · intro m hm
      by_cases hs : m.src = e.src
      · rw [lifted_admit c.zero T _ n R rs ms hrecs hrows hmarks hlifts hn hnr
          (fun r hr => ⟨(hrs r hr).1, (hrs r hr).2.1⟩) (fun q hq => (hms q hq).2) m D
          (fun h' => h (hs.symm.trans h')) (hnm m hm)]
      · simp [beq_eq_false_iff_ne.mpr hs]
    · intro m hm
      simp [(hms m hm).1, Ne.symm h]

theorem upTo_admit (S : Store) (n : Nat) (R : Receipt) (rs : List Row) (ms : List Marker) (K : Nat)
    (hK : R.kb ≤ K) (hnr : ∀ r ∈ S.rows, r.fact.receipt ≠ n) (hnm : ∀ m ∈ S.marks, m.rn ≠ n)
    (hnd : n ∉ S.dropped) (hrs : ∀ r ∈ rs, r.fact.receipt = n) (hms : ∀ m ∈ ms, m.rn = n) :
    (S.admit n R rs ms false).upTo K = (S.upTo K).admit n R rs ms false := by
  have hr : (S.recs ++ [(n, R)]).filter (fun s => decide (s.2.kb ≤ K)) =
      S.recs.filter (fun s => decide (s.2.kb ≤ K)) ++ [(n, R)] := by
    simp [List.filter_append, hK]
  simp only [Store.upTo, Store.admit, hr, List.any_append, List.any_cons, List.any_nil, Bool.or_false,
    Bool.false_eq_true, ↓reduceIte]
  simp only [List.filter_append]
  congr 1
  · congr 1
    · exact List.filter_congr fun r hr => by simp [Ne.symm (hnr r hr)]
    · exact List.filter_eq_self.mpr fun r hr => by simp [hrs r hr]
  · congr 1
    · exact List.filter_congr fun m hm => by simp [Ne.symm (hnm m hm)]
    · exact List.filter_eq_self.mpr fun m hm => by simp [hms m hm]
  · exact List.filter_congr fun x hx => by
      have : x ≠ n := fun h => hnd (h ▸ hx)
      simp [Ne.symm this]

/-- `late_never_overrides`: a receipt `R` admitted below a newer full receipt `G` of its source that states
    `D` (`fseq(R) < fseq(G)`, `cfrom(G) ≤ D`, `G` known at `K`) leaves `belief0` for every key on `D` as it
    was, unless it changes the source's staleness or the marker in force for the key.  Both exceptions are
    hypotheses: its drop check passed (`d = false`), and the marker in force for (its source, kind, key) is
    the same.  Its rows speak only up to `lateUntil`, which is before `cfrom(G)`; it fills no gap above `G`;
    and it is no newer than `G`, so no newest receipt, precedence or proof of absence moves. -/
theorem late_never_overrides (c : Ctx) (S : Store) (n : Nat) (R : Receipt) (rs : List Row) (ms : List Marker)
    (K minCls kind : Nat) (key : Bytes) (D : Nat)
    (hn : ∀ s ∈ S.recs, s.1 ≠ n) (hnr : ∀ r ∈ S.rows, r.fact.receipt ≠ n) (hnm : ∀ m ∈ S.marks, m.rn ≠ n)
    (hnd : n ∉ S.dropped)
    (hrs : ∀ r ∈ rs, r.src = R.src ∧ r.fact.receipt = n ∧
      r.fact.lineUntil = lateUntil (rcptsOf S.recs R.src) R.fseq)
    (hms : ∀ m ∈ ms, m.src = R.src ∧ m.rn = n)
    (hG : ∃ G ∈ S.recs, G.2.kb ≤ K ∧ G.2.src = R.src ∧ G.2.cover = 1 ∧ R.fseq < G.2.fseq ∧ G.2.cfrom ≤ D)
    (hD : 0 < D) (hq : R.cover = 1 ∨ ¬ ms.length < R.quar)
    (hmk : blockingMark c.zero ((S.admit n R rs ms false).upTo K) R.src kind key D =
      blockingMark c.zero (S.upTo K) R.src kind key D) :
    belief0 c (S.admit n R rs ms false) K minCls kind key D = belief0 c S K minCls kind key D := by
  by_cases hK : R.kb ≤ K
  · obtain ⟨G, hGm, hGk, hGs, hGc, hGf, hGd⟩ := hG
    have hlu : lateUntil (rcptsOf S.recs R.src) R.fseq < D :=
      lateUntil_lt _ _ D G.2 (mem_rcptsOf hGm hGs) hGc hGf hGd hD
    have hT := upTo_admit S n R rs ms K hK hnr hnm hnd (fun r hr => (hrs r hr).2.1) (fun m hm => (hms m hm).2)
    rw [hT] at hmk
    unfold belief0 belief
    rw [hT]
    exact beliefCore_late c (S.upTo K) n R rs ms minCls kind key D
      (fun s hs => hn s (List.mem_filter.mp hs).1) (fun r hr => hnr r (List.mem_filter.mp hr).1)
      (fun m hm => hnm m (List.mem_filter.mp hm).1)
      (fun h => hnd (List.mem_filter.mp h).1)
      (fun r hr => ⟨(hrs r hr).1, (hrs r hr).2.1, by rw [(hrs r hr).2.2]; exact hlu⟩) hms
      G (List.mem_filter.mpr ⟨hGm, by simpa using hGk⟩) hGs hGc hGf hGd hD hq hmk
  · exact belief_ignores_later c.zero S n R rs ms false K minCls kind key D (by omega) hn
      (fun r hr => (hrs r hr).2.1) (fun m hm => (hms m hm).2)

/-- A raise or a confirmation written by a batch after `K` changes nothing known at `K`. -/
theorem belief_ignores_later_confirm (c : Ctx) (S : Store) (d r f ur uf : List (Nat × Nat)) (K minCls kind : Nat)
    (key : Bytes) (D : Nat) (hd : ∀ p ∈ d, K < p.2) (hr : ∀ p ∈ r, K < p.2) (hf : ∀ p ∈ f, K < p.2)
    (hur : ∀ p ∈ ur, K < p.2) (huf : ∀ p ∈ uf, K < p.2) :
    belief c { S with droppedOk := S.droppedOk ++ d, reusedOk := S.reusedOk ++ r, refCapOk := S.refCapOk ++ f
                      reused := S.reused ++ ur, refCap := S.refCap ++ uf }
      K minCls kind key D = belief c S K minCls kind key D := by
  apply belief_local
  have e : ∀ l m : List (Nat × Nat), (∀ p ∈ m, K < p.2) →
      (l ++ m).filter (fun p => decide (p.2 ≤ K)) = l.filter (fun p => decide (p.2 ≤ K)) := by
    intro l m h
    have hm : m.filter (fun p => decide (p.2 ≤ K)) = [] :=
      List.filter_eq_nil_iff.mpr fun p hp => by simp [Nat.not_le.mpr (h p hp)]
    rw [List.filter_append, hm, List.append_nil]
  simp only [Store.upTo, e _ _ hd, e _ _ hr, e _ _ hf, e _ _ hur, e _ _ huf]

/-! ## Checks

Each store below is one the review of 11-17 found to answer wrongly.  The answer before the fix is noted; the
answer ruled is the one checked.  Sources `1` and `2` read kind 1 (eligibility) or kind 2 (death) of one subject. -/

section Checks

private def M : Bytes := pat 32 7

private def rc (src cover kb asof cfrom fseq tag : Nat) (quar : Nat := 0) : Receipt :=
  { mkRcpt src cover asof cfrom fseq tag 0 0 with kb := kb, quar := quar }

private def eligV (st : Nat) : Value :=
  .elig { status := st, basis := 1, program := ident 21 "P", aid := ident 21 "A", determined := 0, notice := 0 }

private def deathV : Value := .death { proof := 1, record := zeros 64 }

private def fact (op : Nat) (sid : Nat) (vs vp un rcpt roff : Nat) (v : Value) : Fact :=
  { op := op, subject := M, sid := pat 32 sid, vstart := vs, vstop := vp, lineUntil := un, receipt := rcpt,
    roff := roff, value := v }

private def row (seq src fseq reader : Nat) (f : Fact) : Row :=
  { seq := seq, src := src, fseq := fseq, reader := reader, fact := f }

private def mk (seq src kind rn : Nat) : Marker :=
  { seq := seq, src := src, fkind := kind, subject := M, rn := rn, cause := .date, sidk := 0, sid := [] }

private def eDeath (src origin : Nat) : RegEntry :=
  { src := src, cls := 1, origin := origin, kinds := 4, gapless := 0, maxage := 400, drop := 50, oneper := 0,
    scope := ident 21 "MEDICAID", name := ident 31 "N", fseqRule := 2, full := 1, cfromRule := 1, ids := [(2, [1])] }

private def eElig (src origin : Nat) (gapless oneper cfromRule : Nat) : RegEntry :=
  { src := src, cls := 1, origin := origin, kinds := 2, gapless := gapless, maxage := 400, drop := 50,
    oneper := oneper, scope := ident 21 "MEDICAID", name := ident 31 "N", fseqRule := 2, full := 1,
    cfromRule := cfromRule, ids := [(1, [1])] }

private def eTwo : RegEntry := { eElig 1 7 0 0 1 with kinds := 6, ids := [(1, [1]), (2, [1])] }

private def ctx (r : Registry) : Ctx := { reg := r, today := some 20260215, refhi := [], inScope := fun _ _ => true }

private def name : Res → String
  | .present d c => s!"present {d} {c}"
  | .absent => "absent"
  | .conflict => "conflict"
  | .unknown w => "unknown " ++ (match w with
     | .stale _ => "stale" | .refCap => "refCap" | .refLag => "refLag" | .noSource => "noSource" | .quar => "quar"
     | .flood => "flood" | .oldFlood => "oldFlood" | .sidOverlap => "sidOverlap" | .noCover => "noCover"
     | .copies => "copies")

private def say (r : Registry) (S : Store) (K kind D : Nat) : String := name (belief (ctx r) S K 1 kind M D)

/-- R2: a marker on a copy that another copy of its origin outranks.  Before: absent. -/
private def copyMarked : Store :=
  { recs := [(0, rc 2 1 50 20260101 0 5 1), (1, rc 1 1 51 20260101 0 5 2)], marks := [mk 0 2 2 0] }

#guard say [eDeath 1 7, eDeath 2 7] copyMarked 100 2 20260120 == "unknown quar"
#guard say [eDeath 1 7, eDeath 2 8] copyMarked 100 2 20260120 == "unknown quar"

/-- R2: a copy delivered late with an older as-of day says absent, the newer copy says present.  Before: absent. -/
private def copiesDiffer : Store :=
  { recs := [(0, rc 1 1 50 20260201 0 5 1), (1, rc 2 1 51 20260101 0 5 2)],
    rows := [row 1 1 5 1 (fact 0 3 20260120 99991231 99991231 0 0 deathV)] }

#guard say [eDeath 1 7, eDeath 2 7] copiesDiffer 100 2 20260210 == "conflict"
#guard say [eDeath 1 7, eDeath 2 8] copiesDiffer 100 2 20260210 == "conflict"

/-- R1: the full file 2 (from 0201) restates the subject; file 1's unreadable row stays in force before 0201.
    Before: absent on 0115. -/
private def fullLift : Store :=
  { recs := [(0, rc 1 1 1 20260101 20260101 10 1), (1, rc 1 1 2 20260201 20260201 11 2)], marks := [mk 0 1 1 0],
    rows := [row 1 1 11 1 (fact 0 3 20260201 99991231 99991231 1 0 (eligV 1))] }

#guard say [eElig 1 7 1 0 0] fullLift 100 1 20260115 == "unknown quar"
#guard say [eElig 1 7 1 0 0] fullLift 100 1 20260210 == "present [1] [1]"

/-- R1, the present variant: file 1 also holds a readable row of its own.  Before: present on 0115. -/
private def fullLiftRow : Store :=
  { recs := [(0, rc 1 1 1 20260101 20260101 10 1), (1, rc 1 1 2 20260201 20260201 11 2)], marks := [mk 0 1 1 0],
    rows := [row 1 1 10 1 (fact 0 3 20260101 99991231 99991231 0 0 (eligV 1)),
             row 2 1 11 1 (fact 0 3 20260101 99991231 99991231 1 0 (eligV 1))] }

#guard say [eElig 1 7 1 0 0] fullLiftRow 100 1 20260115 == "unknown quar"

/-- R3: file 2 quarantined one row whose subject could not be read and lists nothing for the subject.
    Before: present on 0210. -/
private def subjectlessFull : Store :=
  { recs := [(0, rc 1 1 1 20260101 20260101 10 1), (1, rc 1 1 2 20260201 20260201 11 2 (quar := 1))],
    rows := [row 1 1 10 1 (fact 0 3 20260101 99991231 99991231 0 0 (eligV 1))] }

#guard say [eElig 1 7 0 0 0] subjectlessFull 100 1 20260210 == "unknown quar"
#guard say [eElig 1 7 0 0 0] subjectlessFull 100 1 20260115 == "present [1] [1]"

/-- R3, control: a clean file 2 with the end row the engine writes is absent, as before. -/
private def cleanFullEnd : Store :=
  { recs := [(0, rc 1 1 1 20260101 20260101 10 1), (1, rc 1 1 2 20260201 20260201 11 2)],
    rows := [row 1 1 10 1 (fact 0 3 20260101 99991231 99991231 0 0 (eligV 1)),
             row 2 1 11 1 (fact 2 3 20260201 20260131 99991231 1 engineRoff (eligV 1))] }

#guard say [eElig 1 7 0 0 0] cleanFullEnd 100 1 20260210 == "absent"

/-- R4: the drop flag of receipt 1 (batch 2) is confirmed by batch 3.  Before the stamp the store held the
    cleared flag, and a reading at batch 2 answered absent. -/
private def dropConfirmed : Store :=
  { recs := [(0, rc 1 1 1 20260101 20260101 10 1), (1, rc 1 1 2 20260201 20260201 11 2)],
    dropped := [1], droppedOk := [(1, 3)] }

#guard say [eElig 1 7 0 0 0] dropConfirmed 2 1 20260210 == "unknown stale"
#guard say [eElig 1 7 0 0 0] dropConfirmed 3 1 20260210 == "absent"

/-- R5: the lifting file 2 itself quarantined an unreadable row.  Before: present. -/
private def liftBySubjectless : Store :=
  { recs := [(0, rc 1 1 1 20260101 20260101 10 1), (1, rc 1 1 2 20260201 20260201 11 2 (quar := 1))],
    marks := [mk 0 1 1 0], rows := [row 1 1 11 1 (fact 0 3 20260201 99991231 99991231 1 0 (eligV 1))] }

#guard say [eElig 1 7 0 0 0] liftBySubjectless 100 1 20260210 == "unknown quar"

/-- R5: a marker on kind 2 and a later full file with a row of kind 1 only.  Before: absent. -/
private def liftByOtherKind : Store :=
  { recs := [(0, rc 1 1 1 20260101 0 10 1), (1, rc 1 1 2 20260201 0 11 2)], marks := [mk 0 1 2 0],
    rows := [row 1 1 11 1 (fact 0 3 20260201 99991231 99991231 1 0 (eligV 1))] }

#guard say [eTwo] liftByOtherKind 100 2 20260210 == "unknown quar"

/-- R6: two statement identities hold equally on one subject in a `oneper` source, and another origin says
    absent.  Before: absent. -/
private def overlap : Store :=
  { recs := [(0, rc 1 1 1 20260101 20260101 10 1), (1, rc 2 1 1 20260101 20260101 10 2)],
    rows := [row 1 1 10 1 (fact 0 3 20260101 99991231 99991231 0 0 (eligV 1)),
             row 2 1 10 1 (fact 0 4 20260101 99991231 99991231 0 1 (eligV 1))] }

#guard say [eElig 1 7 0 1 0, eElig 2 8 0 0 0] overlap 100 1 20260115 == "unknown sidOverlap"

private def lostAbsent (q : Nat) : Store :=
  { recs := [(0, rc 1 1 1 20260201 20260201 11 1 (quar := q)), (1, rc 2 1 1 20260201 20260201 10 2)] }

private def reraised : Store :=
  { recs := [(0, rc 1 1 1 20260101 20260101 10 1)], reused := [(1, 2), (1, 4)], reusedOk := [(1, 3)] }

/- Silence from a full file that lost an unreadable row proves no absence.  Before: absent. -/
#guard say [eElig 1 7 0 0 0, eElig 2 8 0 0 0] (lostAbsent 1) 100 1 20260210 == "unknown quar"
#guard say [eElig 1 7 0 0 0, eElig 2 8 0 0 0] (lostAbsent 0) 100 1 20260210 == "absent"

/- A flag raised again (batch 4) after its confirmation (batch 3) is in force from batch 4 on.  Before, the flag
    stayed cleared for good and a reading at batch 5 answered absent. -/
#guard say [eElig 1 7 0 0 0] reraised 5 1 20260210 == "unknown stale"
#guard say [eElig 1 7 0 0 0] reraised 4 1 20260210 == "unknown stale"
#guard say [eElig 1 7 0 0 0] reraised 3 1 20260210 == "absent"
#guard say [eElig 1 7 0 0 0] reraised 2 1 20260210 == "unknown stale"

private def copiesAndSilent : Store :=
  { recs := [(0, rc 1 0 50 20260201 0 5 1), (1, rc 2 1 51 20260101 0 5 2), (2, rc 3 1 52 20260101 0 5 3)]
    rows := [row 1 2 5 1 (fact 0 3 20260120 99991231 99991231 1 0 deathV)] }

private def lossyDelta (q : Nat) (later : Bool) (withRow : Bool) : Store :=
  { recs := [(0, rc 1 1 1 20260101 20260101 10 1), (1, rc 1 0 2 20260201 0 11 2 (quar := q))] ++
      (if later then [(2, rc 1 1 3 20260205 20260205 12 3)] else []),
    rows := if withRow then [row 1 1 10 1 (fact 0 3 20260101 99991231 99991231 0 0 (eligV 1))] else [] }

/- N1: origin 7 has two copies that disagree (the cited one, a delta file, can say nothing about the subject; the
   older full file says death) and origin 8 is a silent full file.  Before: absent. -/
#guard say [eDeath 1 7, eDeath 2 7, eDeath 3 8] copiesAndSilent 100 2 20260210 == "unknown copies"

/- S1: a delta file of a gapless source quarantined a row whose subject could not be read.  Before: absent (and
   present for the row variant, with the statement kept as if confirmed). -/
#guard say [eElig 1 7 1 0 0] (lossyDelta 1 false false) 100 1 20260210 == "unknown quar"
#guard say [eElig 1 7 1 0 0] (lossyDelta 1 false true) 100 1 20260210 == "unknown quar"
#guard say [eElig 1 7 1 0 0] (lossyDelta 0 false false) 100 1 20260210 == "absent"
#guard say [eElig 1 7 1 0 0] (lossyDelta 1 true false) 100 1 20260210 == "absent"
#guard say [eElig 1 7 1 0 0] (lossyDelta 1 true true) 100 1 20260210 == "present [1] [1]"

/- N2: origin 7 has a cited copy that says death (src 1, as-of 0201) and an older copy that is silent (src 2);
   origin 8 says death.  Before: present, citing origin 8 alone, because the disagreement hid as unknown.
   The second store has the roles of the two copies swapped. -/
private def n2A : Store :=
  { copiesDiffer with
    recs := copiesDiffer.recs ++ [(2, rc 3 1 52 20260101 0 5 3)]
    rows := copiesDiffer.rows ++ [row 2 3 5 1 (fact 0 3 20260120 99991231 99991231 2 0 deathV)] }

private def n2B : Store :=
  { recs := [(0, rc 1 1 50 20260201 0 5 1), (1, rc 2 1 51 20260101 0 5 2), (2, rc 3 1 52 20260101 0 5 3)]
    rows := [row 1 2 5 1 (fact 0 3 20260120 99991231 99991231 1 0 deathV),
             row 2 3 5 1 (fact 0 3 20260120 99991231 99991231 2 0 deathV)] }

#guard say [eDeath 1 7, eDeath 2 7, eDeath 3 8] n2A 100 2 20260210 == "conflict"
#guard say [eDeath 1 7, eDeath 2 7, eDeath 3 8] n2B 100 2 20260210 == "conflict"

/- A lost row in a delta file may be a retroactive end: before a delta's as-of day the answer is unknown too, until a
   later clean full file lifts it for the dates from its own start.  Before: absent on 0115. -/
#guard say [eElig 1 7 1 0 0] (lossyDelta 1 false false) 100 1 20260115 == "unknown quar"
#guard say [eElig 1 7 1 0 0] (lossyDelta 1 true false) 100 1 20260115 == "unknown quar"
#guard say [eElig 1 7 1 0 0] (lossyDelta 1 true false) 100 1 20260205 == "absent"

/- N4: origin 7 has a cited copy (src 1) with two statements of different status, which is a conflict by itself, and an
   older copy (src 2) with one; origin 8 (src 3) says the same as the older copy.  Before: present, citing origin 8
   only.  The second store has the conflict in the older copy, not the cited one. -/
private def n4A : Store :=
  { recs := [(0, rc 1 1 50 20260201 0 5 1), (1, rc 2 1 51 20260101 0 5 2), (2, rc 3 1 52 20260101 0 5 3)]
    rows := [row 1 1 5 1 (fact 0 3 20260120 99991231 99991231 0 0 (eligV 1)),
             row 2 1 5 1 (fact 0 4 20260120 99991231 99991231 0 1 (eligV 2)),
             row 3 2 5 1 (fact 0 3 20260120 99991231 99991231 1 0 (eligV 1)),
             row 4 3 5 1 (fact 0 3 20260120 99991231 99991231 2 0 (eligV 1))] }

private def n4B : Store :=
  { recs := [(0, rc 1 1 50 20260201 0 5 1), (1, rc 2 1 51 20260101 0 5 2), (2, rc 3 1 52 20260101 0 5 3)]
    rows := [row 1 1 5 1 (fact 0 3 20260120 99991231 99991231 0 0 (eligV 1)),
             row 2 2 5 1 (fact 0 3 20260120 99991231 99991231 1 0 (eligV 1)),
             row 3 2 5 1 (fact 0 4 20260120 99991231 99991231 1 1 (eligV 2)),
             row 4 3 5 1 (fact 0 3 20260120 99991231 99991231 2 0 (eligV 1))] }

#guard say [eElig 1 7 0 0 0, eElig 2 7 0 0 0, eElig 3 8 0 0 0] n4A 100 1 20260210 == "conflict"
#guard say [eElig 1 7 0 0 0, eElig 2 7 0 0 0, eElig 3 8 0 0 0] n4B 100 1 20260210 == "conflict"

end Checks

end BlindLedger.Gate.FactBelief
