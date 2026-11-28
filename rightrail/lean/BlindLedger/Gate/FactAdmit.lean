import BlindLedger.Gate.FactFrame
import BlindLedger.Gate.FactRegistry
import BlindLedger.Gate.FactStore
import BlindLedger.Gate.RefSet
import Std.Data.HashMap
import Std.Data.TreeMap

/-! The admission of a fact frame as the specification states it (fact record design §2.10, phase 1, step 5), and the
    checker's replay of a logged fact frame (`checkFact`, `rrdf_log`), whose answer carries the reference set's `rs`
    (§2.9, step 6; `RefSet`).

    The store is every record body of the shard's `facts` file, in record order.  Beside it the checker keeps its own
    tables (`Ix`), each a function of the records (`Ix.ofStore`) and kept up to date as a frame is admitted, so a row
    costs a few table reads whatever the store holds.  Receipts and fact rows are read by their codecs and the file is
    `FactStore.factsFile` of the bodies.  This is the reference the checker (`gate_verify3`) runs; the engine's admission
    (`Engine3/HFacts.lean`) is separate code with its own tables and shares only the codecs.

    Admission, in `FactRegistry.admit`'s order without the source registry, which is not wired yet:
    1. the same file as a stored receipt, unless a re-read, is `ALREADY` (rule 1);
    2. the receipt's own checks (cover 1 to 4, channel 1 to 3, a valid as-of date, `reread` only on a re-read) and rule 6,
       else `RECORD`;
    3. a re-read by a reader already stored for its source and `fseq` is `ALREADY`.
    `ALREADY` writes nothing and answers every row with disposition 4 and that receipt's record number.  Otherwise the
    receipt is written (`kb` the batch, `admitted` and `same` counted) and then, row by row in order: disposition 2 with the
    row in force when it has the same `op`, `vstart`, `vstop`, `until` and value and a rank at least the row's own (nothing
    is written); disposition 2 and a lift when it has them at a lower rank, the receipt is a full file (`cover` 1) and the
    row in force is of the receipt's source; else disposition 1 and a fact row with `until` from §3.2 (the day before the
    least `cfrom` of the source's stored full receipts of a higher `fseq`, as `FactRegistry.lateUntil`) and `receipt` the
    receipt's record number.  The frame's lifts follow its rows as lift records.  The row in force for (subject, kind,
    sid) is the one of greatest rank in force (`fseq`, reader, `roff`; §3.2; a lifted row's is its last lift's), and of
    equal ranks the later record (a lift's is its lift record's).  A batch number or a record number past 40 bits is
    `FULL`.
    Synthetic, nonpayment, non-PHI. -/

namespace BlindLedger.Gate.FactFrame

open BlindLedger.Gate.FactCodec (Receipt Fact zeros leBytes)
open BlindLedger.Gate.FactRegistry (Slot)
open BlindLedger.Gate.Frame (Word)
open Std (HashMap TreeMap)

/-- Every record body of a shard's facts, in record order. -/
abbrev Store := Array Bytes

/-- The receipts among bodies `bs` (the first at record `i`), with their record numbers. -/
def slotsFrom : Nat → List Bytes → List Slot
  | _, [] => []
  | i, b :: bs => match Receipt.dec b with
    | some r => (i, r) :: slotsFrom (i + 1) bs
    | none => slotsFrom (i + 1) bs

/-- What a receipt says of itself (§2.10): cover 1 to 4, channel 1 to 3, a valid as-of date, `reread` only on a re-read. -/
def ownOk (r : Receipt) : Bool :=
  decide (1 ≤ r.cover ∧ r.cover ≤ 4) && decide (1 ≤ r.channel ∧ r.channel ≤ 3) && Rules.validDate r.asof &&
    (r.cover == 4 || r.reread == 0)

/-- A row's rank (§3.2): its receipt's `fseq` and reader, then its `roff`. -/
abbrev Rank := Nat × Nat × Nat

/-- The order of ranks: `fseq`, then reader, then `roff`. -/
def rankLe (a b : Rank) : Bool :=
  a.1 < b.1 || (a.1 == b.1 && (a.2.1 < b.2.1 || (a.2.1 == b.2.1 && a.2.2 ≤ b.2.2)))

/-- `a` no later in force than `b` (each a rank and the record giving it): a lower rank, or the same rank at an earlier
    or the same record. -/
def inLe (a b : Rank × Nat) : Bool := rankLe a.1 b.1 && (a.1 != b.1 || a.2 ≤ b.2)

/-- A statement's key: subject, kind, sid. -/
def stmtKey (subject : Bytes) (kind : Nat) (sid : Bytes) : Bytes := subject ++ UInt8.ofNat kind :: sid

/-- The tables kept beside a store, each a function of its records:
    - `rcpt`: each receipt by its record number;
    - `file`: the first receipt of each file (rule 1);
    - `read`: the receipts of each (`src`, `fseq`), in record order (a reading already stored);
    - `late`: per source, its full receipts as `fseq ↦ cfrom`, less each one that a receipt of an `fseq` at least as high
      and a `cfrom` at most as low outdoes; so `cfrom` rises with `fseq`, and the least `cfrom` of the full receipts above
      an `fseq` is that of the first entry above it;
    - `stmt`: per statement, the row in force, its rank in force and the record that gives it (its own, or its last
      lift's lift record). -/
structure Ix where
  rcpt : HashMap Nat Receipt := {}
  file : HashMap Bytes Nat := {}
  read : HashMap (Nat × Nat) (List Slot) := {}
  late : HashMap Nat (TreeMap Nat Nat) := {}
  stmt : HashMap Bytes (Nat × Rank × Nat) := {}

/-- The rank of a row of receipt record `rc` at `roff`. -/
def Ix.rankAt (ix : Ix) (rc roff : Nat) : Rank :=
  match ix.rcpt[rc]? with
  | some r => (r.fseq, r.reader, roff)
  | none => (0, 0, roff)

/-- A source's `late` table less its entries at or below `fseq` `f` whose `cfrom` is at least `c` (they lie just below
    `f`, as `cfrom` rises with `fseq`); `n` bounds the steps. -/
def lateDrop (f c : Nat) : Nat → TreeMap Nat Nat → TreeMap Nat Nat
  | 0, t => t
  | n + 1, t => match t.getEntryLE? f with
    | some (k, c') => if c ≤ c' then lateDrop f c n (t.erase k) else t
    | none => t

/-- A full receipt of `fseq` `f` and `cfrom` `c` entered in its source's `late` table: nothing changes when an entry at or
    above `f` has a `cfrom` at most `c`; else the entries it outdoes go and it is added. -/
def lateAdd (t : TreeMap Nat Nat) (f c : Nat) : TreeMap Nat Nat :=
  match t.getEntryGE? f with
  | some (_, c') => if c' ≤ c then t else (lateDrop f c t.size t).insert f c
  | none => (lateDrop f c t.size t).insert f c

/-- The `until` of a row of source `src` and `fseq` `f` (`FactRegistry.lateUntil` over the source's stored receipts). -/
def Ix.lateUntil (ix : Ix) (src f : Nat) : Nat :=
  match (ix.late[src]?).bind (·.getEntryGT? f) with
  | some (_, c) => FactRegistry.dayBefore c
  | none => FactRegistry.OPEN

/-- Receipt `r` stored at record `i` entered in the tables. -/
def Ix.addRcpt (ix : Ix) (i : Nat) (r : Receipt) : Ix :=
  let ⟨rcpt, file, read, late, stmt⟩ := ix
  let k := (r.src, r.fseq)
  ⟨rcpt.insert i r, file.insertIfNew r.file i, read.insert k (read.getD k [] ++ [(i, r)]),
    if r.cover == 1 then late.insert r.src (lateAdd (late.getD r.src {}) r.fseq r.cfrom) else late, stmt⟩

/-- Row `j` offered for statement `k` at rank `kr`, given by record `q`: it is in force when nothing is or it is no earlier
    in force than the row that is. -/
def Ix.offer (ix : Ix) (k : Bytes) (j : Nat) (kr : Rank) (q : Nat) : Ix :=
  let ⟨rcpt, file, read, late, stmt⟩ := ix
  let put := match stmt[k]? with
    | some (_, kr', q') => inLe (kr', q') (kr, q)
    | none => true
  ⟨rcpt, file, read, late, if put then stmt.insert k (j, kr, q) else stmt⟩

/-- Record `b`, number `i` of store `st`, entered in the tables: a receipt; a fact row, offered at its own rank; each lift
    of a lift record, its row offered at the lift's rank, given by the lift record. -/
def Ix.addRec (st : Store) (ix : Ix) (i : Nat) (b : Bytes) : Ix :=
  match FactStore.FRec.dec b with
  | some (.receipt r) => ix.addRcpt i r
  | some (.fact f) => ix.offer (stmtKey f.subject f.value.kind f.sid) i (ix.rankAt f.receipt f.roff) i
  | some (.lift l) => l.list.foldl (fun ix x => match (st[x.row]?).bind Fact.dec with
      | some f => ix.offer (stmtKey f.subject f.value.kind f.sid) x.row (ix.rankAt l.receipt x.roff) i
      | none => ix) ix
  | _ => ix

/-- The tables of store `st`, from its records alone. -/
def Ix.ofStore (st : Store) : Ix := (st.foldl (fun (ix, i) b => (Ix.addRec st ix i b, i + 1)) (({} : Ix), 0)).1

/-- The checker's facts: the store and its tables. -/
structure Facts where
  st : Store := #[]
  ix : Ix := {}

/-- The record a lift holds until its frame's lift records are written: after every record (record numbers stay below
    `2 ^ 40`). -/
def pending : Nat := 2 ^ 41

/-- The answer entries, new row bodies, lifts (each with its statement) and tables of a frame so far. -/
abbrev Placed := Array Entry × Array Bytes × Array (Bytes × FactStore.Lift) × Ix

/-- Row `w` of receipt `r` written at record `n0` of store `st`, whose rows take `until` `u`, after the rows before it
    (`acc`).  When the row in force has the same `op`, `vstart`, `vstop`, `until` and value: disposition 2 if it ranks at
    least as high as `w`; else, for a full file (`cover` 1) and a row in force of the same source, disposition 2 and a
    lift of it to `w`'s rank; else `w` is written, so a newer restatement outranks a late file. -/
def place (st : Store) (r : Receipt) (u n0 : Nat) (acc : Placed) (w : Row) : Placed :=
  let (ents, news, lifts, ix) := acc
  let k := stmtKey w.subject w.value.kind w.sid
  let rk : Rank := (r.fseq, r.reader, w.roff)
  let seq := n0 + 1 + news.size
  let fresh (ix : Ix) : Placed := (ents.push ⟨1, 0, seq⟩, news.push (w.toFact u n0).enc, lifts, ix.offer k seq rk seq)
  match ix.stmt[k]? with
  | some (j, kr, _) =>
    match (if j < n0 then st[j]? else news[j - (n0 + 1)]?).bind Fact.dec with
    | some f =>
      if f.op == w.op && f.vstart == w.vstart && f.vstop == w.vstop && f.lineUntil == u && f.value.enc == w.value.enc then
        if rankLe rk kr then (ents.push ⟨2, 0, j⟩, news, lifts, ix)
        else if r.cover == 1 && (ix.rcpt[f.receipt]?).map (·.src) == some r.src then
          (ents.push ⟨2, 0, j⟩, news, lifts.push (k, ⟨j, w.roff⟩), ix.offer k j rk pending)
        else fresh ix
      else fresh ix
    | none => fresh ix
  | none => fresh ix

/-- The `i`th lift `x` of the frame of receipt `r`, for statement `k`, is in lift record `lr + i / liftMax`; when it holds
    the statement's row in force (it is the row's last lift there), that record gives it. -/
def settle (r : Receipt) (lr : Nat) (acc : Ix × Nat) (kx : Bytes × FactStore.Lift) : Ix × Nat :=
  let (ix, i) := acc
  let (k, x) := kx
  let ix := match ix.stmt[k]? with
    | some (j, kr, _) =>
      if j == x.row && kr == (r.fseq, r.reader, x.roff) then
        let ⟨rcpt, file, read, late, stmt⟩ := ix
        ⟨rcpt, file, read, late, stmt.insert k (j, kr, lr + i / FactStore.liftMax)⟩
      else ix
    | none => ix
  (ix, i + 1)

/-- The fact frame's receipt `r` and rows admitted as batch `kb` on facts `fx`: the answer entries and the facts after:
    the receipt (with `rd`, the hash under `H` of the frame's reference rows, `RefSet.rdOf`), the rows written, then the
    lift records. -/
def admit (H : Bytes → Bytes) (fx : Facts) (kb : Nat) (r : Receipt) (rows : List Row) : Except Word (List Entry × Facts) :=
  let ⟨st, ix⟩ := fx
  match (if r.cover == 4 then none else ix.file[r.file]?) with
  | some s => .ok (rows.map fun _ => ⟨4, 0, s⟩, ⟨st, ix⟩)
  | none =>
    let rereadOk := r.cover != 4 || match ix.rcpt[r.reread]? with
      | some s => s.src == r.src && s.fseq == r.fseq && s.file == r.file && s.asof == r.asof && s.scope == r.scope &&
          s.sender == r.sender && decide (s.reader < r.reader)
      | none => false
    if !(ownOk r && rereadOk) then .error .RECORD
    else match (if r.cover == 4 then (ix.read.getD (r.src, r.fseq) []).find? (·.2.reader == r.reader) else none) with
      | some s => .ok (rows.map fun _ => ⟨4, 0, s.1⟩, ⟨st, ix⟩)
      | none =>
        let n0 := st.size
        if !(decide (kb < 2 ^ 40) && decide (n0 + 1 + rows.length < 2 ^ 40)) then .error .FULL
        else
          let u := ix.lateUntil r.src r.fseq
          let ix := { ix with rcpt := ix.rcpt.insert n0 r }
          let (ents, news, lifts, ix) := rows.foldl (place st r u n0) (#[], #[], #[], ix)
          let rc := { r with kb := kb, admitted := news.size, same := rows.length - news.size, rd := RefSet.rdOf H rows }
          let ix := (lifts.foldl (settle r (n0 + 1 + news.size)) (ix, 0)).1
          let recs := (FactStore.liftRecs n0 (lifts.toList.map (·.2))).map FactStore.liftC.enc
          .ok (ents.toList, ⟨st.push rc.enc ++ news ++ recs.toArray, ix.addRcpt n0 rc⟩)

/-- The `facts` file of a store: each body with its chain link (`FactStore.factsP`). -/
def Store.file (st : Store) : Bytes := FactStore.factsFile st.toList

/-! ## Vectors

    A full file of three rows; the same file again (`ALREADY`); a later full file restating a row (a lift: disposition
    2 at that row and one lift record); then three files of one rank: a changed row, the first row again (of equal ranks
    the later record is in force, here the changed row, after the lift record, so it differs), and the first row once
    more (now the same as the row in force, disposition 2).  Then change files A, C (newest) restating A's row, and B
    (between them, a changed row), in the orders A, C, B and A, B, C: the row in force is C's in both.  After each, the
    rows in force kept during admission are those the store's records give (`Ix.ofStore`). -/

def entsOf (x : Except Word (List Entry × Facts)) : List (Nat × Nat × Nat) :=
  match x with
  | .ok (es, _) => es.map fun e => (e.disp, e.cause, e.seq)
  | .error _ => []

def factsOf (x : Except Word (List Entry × Facts)) : Facts :=
  match x with
  | .ok (_, s) => s
  | .error _ => {}

/-- The rows in force kept during admission are those the store's records give. -/
def Facts.settled (fx : Facts) : Bool :=
  let ix := Ix.ofStore fx.st
  ix.stmt.size == fx.ix.stmt.size && fx.ix.stmt.toList.all fun (k, v) => ix.stmt[k]? == some v

/-- The row in force for `w`'s statement on store `st`, read from its records alone: its `op`, valid dates, `until`, value
    and rank in force. -/
def held (st : Store) (w : Row) : Option (Nat × Nat × Nat × Nat × Bytes × Rank) :=
  match (Ix.ofStore st).stmt[stmtKey w.subject w.value.kind w.sid]? with
  | some (j, kr, _) => (st[j]?.bind Fact.dec).map fun f => (f.op, f.vstart, f.vstop, f.lineUntil, f.value.enc, kr)
  | none => none

def vRcpt (k f : Nat) : Receipt := { gRcpt with file := FactCodec.pat 64 k, fseq := gRcpt.fseq + f, rows := 1 }
def vS1 : Facts := factsOf (admit sha {} 2 gRcpt [r0, r1, r2])
def vS2 : Facts := factsOf (admit sha vS1 4 (vRcpt 41 100) [r0])
def r0' : Row := { r0 with vstop := r0.vstop + 1 }
def vS3 : Facts := factsOf (admit sha vS2 5 (vRcpt 44 100) [r0'])
def vS4 : Facts := factsOf (admit sha vS3 6 (vRcpt 45 100) [r0])

#guard entsOf (admit sha {} 2 gRcpt [r0, r1, r2]) == [(1, 0, 1), (1, 0, 2), (1, 0, 3)] && vS1.st.size == 4
#guard entsOf (admit sha vS1 3 { gRcpt with fseq := gRcpt.fseq + 7 } [r0, r2]) == [(4, 0, 0), (4, 0, 0)] &&
  (factsOf (admit sha vS1 3 { gRcpt with fseq := gRcpt.fseq + 7 } [r0, r2])).st == vS1.st
#guard entsOf (admit sha vS1 4 (vRcpt 41 100) [r0]) == [(2, 0, 1)] && vS2.st.size == 6 &&
  vS2.st[5]? == some (FactStore.liftC.enc ⟨4, 1, FactStore.liftE.enc ⟨1, r0.roff⟩ ++ zeros 228⟩)
#guard entsOf (admit sha vS2 5 (vRcpt 44 100) [r0']) == [(1, 0, 7)] && vS3.st.size == 8
#guard entsOf (admit sha vS3 6 (vRcpt 45 100) [r0]) == [(1, 0, 9)] && vS4.st.size == 10
#guard entsOf (admit sha vS4 7 (vRcpt 46 100) [r0]) == [(2, 0, 9)]
#guard admit sha vS1 3 { vRcpt 47 0 with channel := 0 } [r0] matches .error .RECORD
#guard [vS1, vS2, vS3, vS4].all Facts.settled

def vChg (k f : Nat) : Receipt := { vRcpt k f with cover := 2 }
def vA : Facts := factsOf (admit sha {} 2 (vChg 50 0) [r0])
def vAC : Facts := factsOf (admit sha vA 3 (vChg 52 20) [r0])
def vACB : Facts := factsOf (admit sha vAC 4 (vChg 51 10) [r0'])
def vAB : Facts := factsOf (admit sha vA 3 (vChg 51 10) [r0'])
def vABC : Facts := factsOf (admit sha vAB 4 (vChg 52 20) [r0])

#guard entsOf (admit sha vA 3 (vChg 52 20) [r0]) == [(1, 0, 3)] && entsOf (admit sha vAC 4 (vChg 51 10) [r0']) == [(1, 0, 5)]
#guard (held vACB.st r0).map (·.2.2.1) == some r0.vstop && held vACB.st r0 == held vABC.st r0

/-! Lifts.  A full file restating the row in force lifts it to its own row's rank, so a late change file of a rank
    between never outranks it, in either order of arrival, as a written restatement would not (full A, full C newest
    restating A's row, change B between them: orders A, C, B and A, B, C).  A full file of another source writes its row.
    More than `liftMax` lifts take a second lift record, which gives the rows of its lifts.  A late full file (`fseq`
    between two stored ones) takes the `until` of the newer one's `cfrom`, and outdoes nothing of a later `cfrom`. -/

def vF (k f : Nat) : Receipt := vRcpt k f
def vFA : Facts := factsOf (admit sha {} 2 (vF 60 0) [r0])
def vFAC : Facts := factsOf (admit sha vFA 3 (vF 62 20) [r0])
def vFACB : Facts := factsOf (admit sha vFAC 4 (vChg 61 10) [r0'])
def vFAB : Facts := factsOf (admit sha vFA 3 (vChg 61 10) [r0'])
def vFABC : Facts := factsOf (admit sha vFAB 4 (vF 62 20) [r0])

#guard (held vS2.st r0).map (·.2.2.2.2.2) == some (gRcpt.fseq + 100, gRcpt.reader, r0.roff)
#guard entsOf (admit sha vFA 3 (vF 62 20) [r0]) == [(2, 0, 1)] && vFAC.st.size == 4 &&
  entsOf (admit sha vFAC 4 (vChg 61 10) [r0']) == [(1, 0, 5)]
#guard (held vFACB.st r0).map (·.2.2.2.2.2) == some (gRcpt.fseq + 20, gRcpt.reader, r0.roff) &&
  (held vFACB.st r0).map (·.2.2.1) == some r0.vstop && held vFACB.st r0 == held vFABC.st r0
#guard entsOf (admit sha vFA 3 { vF 63 20 with src := gRcpt.src + 1 } [r0]) == [(1, 0, 3)]
#guard [vFA, vFAC, vFACB, vFAB, vFABC].all Facts.settled

def manyRows : List Row := (List.range 24).map fun i => { r0 with sid := FactCodec.pat 32 (90 + i) }
def vMany : Facts := factsOf (admit sha {} 2 (vF 64 0) manyRows)
def vMany2 : Facts := factsOf (admit sha vMany 3 (vF 65 20) manyRows)

#guard entsOf (admit sha vMany 3 (vF 65 20) manyRows) == (List.range 24).map (fun i => (2, 0, i + 1)) &&
  vMany2.st.size == vMany.st.size + 3 && vMany2.settled &&
  (vMany2.ix.stmt[stmtKey r0.subject r0.value.kind (FactCodec.pat 32 113)]?).map (·.2.2) == some (vMany.st.size + 2)

def vLate : Facts :=
  factsOf (admit sha (factsOf (admit sha {} 2 { vF 66 30 with cfrom := 20260201 } [r1])) 3
    { vF 67 10 with cfrom := 20260301 } [r1])
#guard vLate.ix.lateUntil gRcpt.src (gRcpt.fseq + 5) == 20260131 &&
  vLate.ix.lateUntil gRcpt.src (gRcpt.fseq + 20) == 20260131 &&
  vLate.ix.lateUntil gRcpt.src (gRcpt.fseq + 30) == FactRegistry.OPEN &&
  (vLate.ix.late[gRcpt.src]?).map (·.toList) == some [(gRcpt.fseq + 30, 20260201)]

def vLate2 : Facts :=
  factsOf (admit sha (factsOf (admit sha {} 2 { vF 67 10 with cfrom := 20260301 } [r1])) 3
    { vF 66 30 with cfrom := 20260201 } [r1])
#guard (vLate2.ix.late[gRcpt.src]?).map (·.toList) == (vLate.ix.late[gRcpt.src]?).map (·.toList) &&
  (Ix.ofStore vLate2.st).lateUntil gRcpt.src (gRcpt.fseq + 5) == 20260131 && vLate2.settled

/-! ## The checker's replay of a logged fact frame -/

/-- The fact answer as logged: `head` and `root` zero (the engine puts them in the copy it sends), the reference set's
    `rs` after the frame, and no work items or money rows (steps 5 and 6). -/
def factAns (shard batch : Nat) (dg : Bytes) (ents : List Entry) (rs : Bytes) : Ans :=
  ⟨shard, batch, dg, ents, zeros 64, zeros 64, rs, 0, 0⟩

/-- The reference set's entries the checker keeps, in byte order, and their `rs`. -/
structure Refs where
  es : List Bytes
  rs : Bytes

/-- No reference entry. -/
def Refs.none (H : Bytes → Bytes) : Refs := ⟨[], RefSet.rs H []⟩

/-- The reference entries of store `st`, each from a stored receipt (`RefSet.entOfRcpt`), in byte order, and their `rs`:
    those a replay of the store's frames carries (`refsAfter`), read from the store alone. -/
def Refs.ofStore (H : Bytes → Bytes) (st : Store) : Refs :=
  let es := (st.toList.filterMap fun b => (Receipt.dec b).bind RefSet.entOfRcpt).mergeSort RefSet.lexLe
  ⟨es, RefSet.rs H es⟩

#guard (Refs.ofStore sha vS4.st).es == (RefSet.ent sha gRcpt [r0, r1, r2]).toList &&
  (Refs.ofStore sha vS4.st).es.length == 1

/-- `e` put in its place among entries `l` in byte order (`RefSet.ins`, as a split, so a long list costs no deep
    recursion). -/
def insIn (e : Bytes) (l : List Bytes) : List Bytes :=
  let (a, b) := l.span fun y => !RefSet.lexLe e y
  a ++ e :: b

/-- The reference entries after a frame admitted receipt `r` with `rows` and took a store of `n` records to the facts
    `fx'`: a receipt that was written (the store grew; `ALREADY` writes nothing) adds its entry in its place when its frame
    has a reference row (`RefSet.ent`), and only then is `rs` computed again.  `RefSet.rs` does not depend on the order
    of the entries (`rs_order`). -/
def refsAfter (H : Bytes → Bytes) (rf : Refs) (n : Nat) (fx' : Facts) (r : Receipt) (rows : List Row) : Refs :=
  if fx'.st.size = n then rf else
  match RefSet.ent H r rows with
  | some e => let es := insIn e rf.es; ⟨es, RefSet.rs H es⟩
  | none => rf

/-- `refsAfter` keeps `rs` the `rs` of the entries. -/
theorem refsAfter_rs {H : Bytes → Bytes} {rf : Refs} {n : Nat} {fx' : Facts} {r : Receipt} {rows : List Row}
    (h : rf.rs = RefSet.rs H rf.es) : (refsAfter H rf n fx' r rows).rs = RefSet.rs H (refsAfter H rf n fx' r rows).es := by
  unfold refsAfter
  split
  · exact h
  · split
    · rfl
    · exact h

/-- A fact answer's bytes without `head` and `root`. -/
def Ans.bound (a : Ans) : Bytes :=
  ansMagic ++ leBytes 2 ansVersion ++ leBytes 1 0 ++ leBytes 4 a.shard ++ leBytes 8 a.batch ++
    leBytes 4 a.entries.length ++ a.digest ++ entsEnc a.entries ++ a.rs ++ leBytes 4 a.items ++ leBytes 4 a.money

/-- `an` of a fact answer: `H(dom ANSWER3 ‖ answer bytes without head and root)` (§2.8, §2.10). -/
def ansDigest (H : Bytes → Bytes) (a : Ans) : Bytes := H (domain "ANSWER3" ++ a.bound)

/-- Why a logged fact frame is refused: what differs, then the log's value and the checker's (or digests of them). -/
structure Fail where
  what : String
  logged : Bytes
  mine : Bytes

/-- Logged fact frame `rqb`, batch `batch` of shard `shard`, after the head `prev` under key-set pin `pin`, whose trailer
    names the request digest `rq`: its request and the entries and facts `admit` gives on `fx`.  The frame is refused when
    its request does not decode, names another shard, batch, head or pin or another digest than `rq`, or is not admitted. -/
def replay (H : Bytes → Bytes) (fx : Facts) (shard batch : Nat) (prev pin rq rqb : Bytes) :
    Except Fail (Req × List Entry × Facts) :=
  match decodeReq H rqb with
  | .error w => .error ⟨s!"fact request {reprStr w}", [], []⟩
  | .ok (q, dg) =>
    if dg = rq ∧ q.shard = shard ∧ q.batch = batch ∧ q.prev = prev ∧ q.pin = pin then
      match admit H fx batch q.rcpt q.rows with
      | .error w => .error ⟨s!"fact admission {reprStr w}", [], []⟩
      | .ok (ents, fx') => .ok (q, ents, fx')
    else if dg ≠ rq then .error ⟨"request digest", rq, dg⟩
    else if q.shard ≠ shard ∨ q.batch ≠ batch then .error ⟨"shard or batch number", [], []⟩
    else if q.prev ≠ prev then .error ⟨"previous head", prev, q.prev⟩
    else .error ⟨"key-set pin", pin, q.pin⟩

/-- `replay` on the facts `fx` and reference entries `rf`, then the logged answer bytes `anb` must be the answer of its
    entries with the `rs` of the entries after the frame, and the trailer's `an` its digest: the facts and entries after
    the frame. -/
def checkFact (H : Bytes → Bytes) (fx : Facts) (rf : Refs) (shard batch : Nat) (prev pin rq rqb anb an : Bytes) :
    Except Fail (Facts × Refs) :=
  let n := fx.st.size
  match replay H fx shard batch prev pin rq rqb with
  | .error f => .error f
  | .ok (q, ents, fx') =>
    let rf' := refsAfter H rf n fx' q.rcpt q.rows
    let a := factAns shard batch rq ents rf'.rs
    if anb = a.enc ∧ an = ansDigest H a then .ok (fx', rf')
    else if anb ≠ a.enc then .error ⟨"fact answer", H anb, H a.enc⟩
    else .error ⟨"fact answer digest", an, ansDigest H a⟩

/-- What `replay` accepts is the request its bytes decode to, at the shard, batch, head, pin and digest given, admitted by
    `admit`. -/
theorem replay_ok {H : Bytes → Bytes} {fx : Facts} {shard batch : Nat} {prev pin rq rqb : Bytes} {q : Req}
    {ents : List Entry} {fx' : Facts} (h : replay H fx shard batch prev pin rq rqb = .ok (q, ents, fx')) :
    decodeReq H rqb = .ok (q, rq) ∧ q.shard = shard ∧ q.batch = batch ∧ q.prev = prev ∧ q.pin = pin ∧
      admit H fx batch q.rcpt q.rows = .ok (ents, fx') := by
  unfold replay at h
  split at h
  · cases h
  · rename_i q0 dg hd
    split at h
    · rename_i hc
      obtain ⟨h1, h2, h3, h4, h5⟩ := hc
      split at h
      · cases h
      · rename_i ents0 fx0 ha
        cases h
        subst h1
        exact ⟨hd, h2, h3, h4, h5, ha⟩
    · split at h
      · cases h
      · split at h
        · cases h
        · split at h <;> cases h

/-- `rrdf_log`: a logged fact frame the checker accepts, on reference entries whose `rs` is theirs, is the request its
    bytes decode to, at the batch, head, key-set pin and digest the log gives it; its entries and the facts after it are
    `admit`'s on the facts before it; the reference entries after it are `refsAfter`'s and their `rs` is theirs; its logged
    answer is exactly the fact answer of those entries (with `head` and `root` zero, as logged) carrying the `rs` of the
    entries after it, and the trailer's `an` is that answer's digest under `ANSWER3`. -/
theorem rrdf_log {H : Bytes → Bytes} {fx : Facts} {rf : Refs} {shard batch : Nat} {prev pin rq rqb anb an : Bytes}
    {fx' : Facts} {rf' : Refs} (hrs : rf.rs = RefSet.rs H rf.es)
    (h : checkFact H fx rf shard batch prev pin rq rqb anb an = .ok (fx', rf')) :
    ∃ q ents, decodeReq H rqb = .ok (q, rq) ∧ q.shard = shard ∧ q.batch = batch ∧ q.prev = prev ∧ q.pin = pin ∧
      admit H fx batch q.rcpt q.rows = .ok (ents, fx') ∧ rf' = refsAfter H rf fx.st.size fx' q.rcpt q.rows ∧
      rf'.rs = RefSet.rs H rf'.es ∧
      anb = (factAns shard batch rq ents (RefSet.rs H rf'.es)).enc ∧
      an = ansDigest H (factAns shard batch rq ents (RefSet.rs H rf'.es)) := by
  unfold checkFact at h
  split at h
  · cases h
  · rename_i q ents fx0 hr
    dsimp only at h
    split at h
    · rename_i hc
      cases h
      obtain ⟨h1, h2, h3, h4, h5, h6⟩ := replay_ok hr
      have hk := refsAfter_rs (n := fx.st.size) (fx' := fx') (r := q.rcpt) (rows := q.rows) hrs
      refine ⟨q, ents, h1, h2, h3, h4, h5, h6, rfl, hk, ?_, ?_⟩
      · rw [← hk]; exact hc.1
      · rw [← hk]; exact hc.2
    · split at h <;> cases h

theorem push_app {α : Type} (st : Array α) (a : α) (n r : Array α) : ∃ xs, st.push a ++ n ++ r = st ++ xs :=
  ⟨#[a] ++ n ++ r, by simp [Array.append_assoc]⟩

/-- `admit` only appends: the store after it is the store before it and the records it wrote (none for a frame already
    held).  So a checker that keeps the store's bytes only appends the new records' bytes. -/
theorem admit_st {H : Bytes → Bytes} {fx : Facts} {kb : Nat} {r : Receipt} {rows : List Row} {es : List Entry}
    {fx' : Facts} (h : admit H fx kb r rows = .ok (es, fx')) : ∃ xs, fx'.st = fx.st ++ xs := by
  obtain ⟨st, ix⟩ := fx
  unfold admit at h
  simp only [] at h
  split at h
  · cases h; exact ⟨#[], by simp⟩
  · by_cases hc : (!(ownOk r && (r.cover != 4 || match ix.rcpt[r.reread]? with
        | some s => s.src == r.src && s.fseq == r.fseq && s.file == r.file && s.asof == r.asof && s.scope == r.scope &&
            s.sender == r.sender && decide (s.reader < r.reader)
        | none => false))) = true
    · rw [if_pos hc] at h; cases h
    · rw [if_neg hc] at h
      split at h
      · cases h; exact ⟨#[], by simp⟩
      · by_cases hf : (!(decide (kb < 2 ^ 40) && decide (Array.size st + 1 + rows.length < 2 ^ 40))) = true
        · rw [if_pos hf] at h; cases h
        · rw [if_neg hf] at h; cases h; exact push_app _ _ _ _

end BlindLedger.Gate.FactFrame
