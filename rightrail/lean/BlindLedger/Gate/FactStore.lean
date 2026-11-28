import BlindLedger.Gate.Obligations.Records
import Std.Data.HashMap

namespace BlindLedger.Gate.FactStore

open BlindLedger.Gate.FactCodec BlindLedger.Gate.Obligations
open Std (HashMap)

/-! The `facts` file and the two links files of a shard (fact record design §2.1-§2.7), as projections of the log.

    Records.  A `facts` record is the rows-file record: a 245-byte body, then its link (`prevCore`, the previous record
    of the same chain plus one, 40 bits; the chain's count up to it, 16 bits; four zero bytes).  The bodies are the
    receipt (tag `0x40`), the fact rows (tags 1 to `0x3F`, the fact kind), the lift record (`0x41`), the quarantine
    marker (`0x50`), the two parts of a member summary (`0x51` recent, `0x52` old) and the money row (`0x60`, forms 1, 2
    and 4; this module fixes its format only).  A links record is 32 bytes, one per row of a set's rows file at the row's own number: the previous
    row of the set with the same member, payee and rendering provider (each plus one, 40 bits), then the row's batch,
    its record's index in that batch's answer, its reason bits, its rule and the batch's authority day.

    Chains.  Every record names its chains by keys (`Proj.keys`); a table holds, per key, the newest record and the
    chain's count (`Tab`).  The facts chains: a receipt's source (and its file hash, the `rcpt` table, which the record
    does not link); a fact row's or marker's subject; a summary's member (`msum`); a money row's obligation (`obl`).
    The links chains: a row's member, payee and rendering provider in its set (`mrel` `prel` `rrel`, `munr` `punr`
    `runr`).

    Projection.  A file is `Proj.writerOf` of the records in log order: its bytes, its record count and its tables.
    Appending a batch (`Proj.put`) gives the writer of the longer list, and a load recomputes the writer from the
    records the file holds and accepts the file only if the recomputed bytes equal it, so a stored link is compared
    and never trusted.  `facts_projection` and `links_projection` are proved over records already derived, batch by
    batch: the file of the first batches, loaded and then extended by the later ones, is byte for byte the writer of all
    of them, with the same tables; with no batch loaded that is the rebuild.  They do not tie a frame or an answer to
    its records: that the engine derives the records from the answers (`Engine3/HLinks.lean`, `tailsOf`) and that its
    load keeps what `loadLinks` keeps (its kept prefix may end inside a batch) are checked by tests, not proved.

    The rows-file engine imports this module only to check its links encoders against it (`Engine3/HLinks.lean`); the
    financial worker does not import it. -/

/-! ## Member summary (tags `0x51`, `0x52`) -/

/-- One entry of a summary: the fact row or marker it lists (`seq`), its receipt, its kind (bit 7: a marker), its span
    after `end` rows and `until`, and the decision value or hint. -/
structure SumEnt where
  seq : Nat
  receipt : Nat
  fkind : Nat
  vstart : Nat
  vstop : Nat
  lineUntil : Nat
  dec : Nat
  deriving DecidableEq, Repr

def entC : RecCodec SumEnt where
  L := [.num 5, .num 5, .num 1, .num 4, .num 4, .num 4, .num 1]
  toC x := [.n x.seq, .n x.receipt, .n x.fkind, .n x.vstart, .n x.vstop, .n x.lineUntil, .n x.dec]
  build cs := ⟨nAt cs 0, nAt cs 1, nAt cs 2, nAt cs 3, nAt cs 4, nAt cs 5, nAt cs 6⟩
  chk _ := true

theorem entC_ok : entC.Lawful ∧ width entC.L = 24 := ⟨fun y _ => by cases y; rfl, rfl⟩

/-- The most entries one summary record holds. -/
def entMax : Nat := 8

/-- A summary record: `n` entries of 24 bytes, then zeros to the end of the 192-byte block. -/
structure SumRec where
  tag : Nat
  member : Bytes
  kb : Nat
  cut : Nat
  old : Nat
  more : Nat
  n : Nat
  entries : Bytes
  deriving DecidableEq, Repr

def sumC : RecCodec SumRec where
  L := [.num 1, .blk 32, .num 5, .num 4, .num 5, .num 5, .num 1, .blk (24 * entMax)]
  toC x := [.n x.tag, .b x.member, .n x.kb, .n x.cut, .n x.old, .n x.more, .n x.n, .b x.entries]
  build cs := ⟨nAt cs 0, bAt cs 1, nAt cs 2, nAt cs 3, nAt cs 4, nAt cs 5, nAt cs 6, bAt cs 7⟩
  chk x := decide ((x.tag = 0x51 ∨ x.tag = 0x52) ∧ x.n ≤ entMax) && allZero (x.entries.drop (24 * x.n))

theorem sumC_ok : sumC.Lawful ∧ width sumC.L = bodyBytes := ⟨fun y _ => by cases y; rfl, rfl⟩

/-- A summary record listing `es` (at most `entMax`). -/
def mkSum (tag : Nat) (member : Bytes) (kb cut old more : Nat) (es : List SumEnt) : SumRec :=
  ⟨tag, member, kb, cut, old, more, es.length, es.flatMap entC.enc ++ zeros (24 * entMax - 24 * es.length)⟩

/-- The entries a summary record lists. -/
def SumRec.list (s : SumRec) : List SumEnt :=
  (List.range s.n).filterMap fun i => entC.dec (slice s.entries (24 * i) 24)

/-! ## Lift record (tag `0x41`)

    A full file that states again, unchanged, the row in force of its own source at a lower rank writes no row: the
    statement's rank in force becomes the full file row's rank, kept as a lift.  A lift record holds the lifts of one
    receipt's frame, in its row order: the restated row's record number and the restating row's `roff` (10 bytes each),
    and the lifting receipt's record number once.  A frame with more than `liftMax` lifts writes several. -/

/-- One lift: the row in force that was stated again (`row`) and the `roff` of the row that stated it. -/
structure Lift where
  row : Nat
  roff : Nat
  deriving DecidableEq, Repr

def liftE : RecCodec Lift where
  L := [.num 5, .num 5]
  toC x := [.n x.row, .n x.roff]
  build cs := ⟨nAt cs 0, nAt cs 1⟩
  chk _ := true

theorem liftE_ok : liftE.Lawful ∧ width liftE.L = 10 := ⟨fun y _ => by cases y; rfl, rfl⟩

/-- The most lifts one lift record holds. -/
def liftMax : Nat := 23

/-- A lift record: the lifting receipt, `n` lifts of 10 bytes (1 to `liftMax`), then zeros to the end of the body. -/
structure LiftRec where
  receipt : Nat
  n : Nat
  entries : Bytes
  deriving DecidableEq, Repr

def liftC : RecCodec LiftRec where
  L := [.lit 1 0x41, .num 5, .num 1, .blk 238]
  toC x := [.n x.receipt, .n x.n, .b x.entries]
  build cs := ⟨nAt cs 0, nAt cs 1, bAt cs 2⟩
  chk x := decide (1 ≤ x.n ∧ x.n ≤ liftMax) && allZero (x.entries.drop (10 * x.n))

theorem liftC_ok : liftC.Lawful ∧ width liftC.L = bodyBytes := ⟨fun y _ => by cases y; rfl, rfl⟩

/-- The lift records of receipt record `rc` for lifts `ls`, in order, `liftMax` to a record. -/
def liftRecs (rc : Nat) (ls : List Lift) : List LiftRec :=
  (List.range ((ls.length + liftMax - 1) / liftMax)).map fun i =>
    let c := (ls.drop (liftMax * i)).take liftMax
    ⟨rc, c.length, c.flatMap liftE.enc ++ zeros (238 - 10 * c.length)⟩

/-- The lifts a lift record holds. -/
def LiftRec.list (l : LiftRec) : List Lift :=
  (List.range l.n).filterMap fun i => liftE.dec (slice l.entries (10 * i) 10)

/-! ## Money row (tag `0x60`), format only -/

structure MoneyRow where
  form : Nat
  mkind : Nat
  okey : Bytes
  line : Nat
  cents : Nat
  entitled : Nat
  verdict : Nat
  wbatch : Nat
  windex : Nat
  cause : Nat
  link : Nat
  identified : Nat
  discovered : Nat
  deadline : Nat
  reg : Nat
  due : Nat
  refunded : Nat
  questioned : Nat
  allocated : Nat
  available : Nat
  noticed : Nat
  under : Nat
  deriving DecidableEq, Repr

/-- The money row kinds of each form: a payment (1) VERDICT, DISCOVER, RECEIVED, EXEMPT, ALLOCATED and TPLDUE; a
    provider-level balance (2) PLB, OFFER, DONE and RETURNED; an advance (4) ADVANCE, OFFER, DONE and RETURNED.  Form 3
    is the capitation phase's and form 5 the program-obligations shard's (its own codec); kind 6 is withdrawn. -/
def moneyKinds : Nat → List Nat
  | 1 => [1, 2, 3, 4, 5, 7]
  | 2 => [8, 10, 11, 12]
  | 4 => [9, 10, 11, 12]
  | _ => []

/-- The obligation key: a payment's `pay` (form 1), or `payee 21 ‖ reference 31 ‖ period u32 ‖ zero` (forms 2 and 4). -/
def okeyOk (form : Nat) (k : Bytes) : Bool :=
  form == 1 || (idOk 21 (k.take 21) && idOk 31 (slice k 21 31) && allZero (k.drop 56))

def moneyC : RecCodec MoneyRow where
  L := [.lit 1 0x60, .num 1, .num 1, .blk 72, .num 5, .num 8, .num 8, .num 1, .num 8, .num 3, .num 5, .num 5, .num 4,
    .num 4, .num 4, .num 1, .num 8, .num 8, .num 8, .num 8, .num 8, .num 8, .num 8, z 58]
  toC x := [.n x.form, .n x.mkind, .b x.okey, .n x.line, .n x.cents, .n x.entitled, .n x.verdict, .n x.wbatch,
    .n x.windex, .n x.cause, .n x.link, .n x.identified, .n x.discovered, .n x.deadline, .n x.reg, .n x.due,
    .n x.refunded, .n x.questioned, .n x.allocated, .n x.available, .n x.noticed, .n x.under]
  build cs := ⟨nAt cs 0, nAt cs 1, bAt cs 2, nAt cs 3, nAt cs 4, nAt cs 5, nAt cs 6, nAt cs 7, nAt cs 8, nAt cs 9,
    nAt cs 10, nAt cs 11, nAt cs 12, nAt cs 13, nAt cs 14, nAt cs 15, nAt cs 16, nAt cs 17, nAt cs 18, nAt cs 19,
    nAt cs 20, nAt cs 21⟩
  chk x := decide (x.mkind ∈ moneyKinds x.form ∧ x.verdict ≤ 2 ∧ (x.form = 1 ∨ x.line = 0)) && okeyOk x.form x.okey

theorem moneyC_ok : moneyC.Lawful ∧ width moneyC.L = bodyBytes := ⟨fun y _ => by cases y; rfl, rfl⟩

/-! ## A `facts` body of any kind -/

inductive FRec where
  | fact (f : Fact)
  | receipt (r : Receipt)
  | mark (m : MarkRec)
  | summary (s : SumRec)
  | money (m : MoneyRow)
  | lift (l : LiftRec)

def FRec.enc : FRec → Bytes
  | .fact f => f.enc
  | .receipt r => r.enc
  | .mark m => markC.enc m
  | .summary s => sumC.enc s
  | .money m => moneyC.enc m
  | .lift l => liftC.enc l

def FRec.WF : FRec → Prop
  | .fact f => f.WF
  | .receipt r => r.WF
  | .mark m => markC.WF m
  | .summary s => sumC.WF s
  | .money m => moneyC.WF m
  | .lift l => liftC.WF l

/-- The kind of body a tag names: 1 a fact row, 2 a receipt, 3 a marker, 4 a summary, 5 a money row, 6 a lift record,
    0 none. -/
def kindOf (t : Nat) : Nat :=
  if 1 ≤ t ∧ t ≤ 0x3F then 1 else if t = 0x40 then 2 else if t = 0x50 then 3
  else if t = 0x51 ∨ t = 0x52 then 4 else if t = 0x60 then 5 else if t = 0x41 then 6 else 0

/-- Decode a body by its tag; none for an unknown tag or a body its kind refuses. -/
def FRec.dec (b : Bytes) : Option FRec :=
  match kindOf (tagOf b) with
  | 1 => (Fact.dec b).map .fact
  | 2 => (Receipt.dec b).map .receipt
  | 3 => (markC.dec b).map .mark
  | 4 => (sumC.dec b).map .summary
  | 5 => (moneyC.dec b).map .money
  | 6 => (liftC.dec b).map .lift
  | _ => none

theorem tagOf_le1 (v : Nat) (r : Bytes) : tagOf (leBytes 1 v ++ r) = v % 256 := by
  simp [tagOf, leBytes]

theorem tagOf_lit (v : Nat) (fs : List Fld) (cs : List Cell) : tagOf (encF (.lit 1 v :: fs) cs) = v % 256 := by
  rw [encF, tagOf_le1]

theorem tagOf_num (v : Nat) (fs : List Fld) (cs : List Cell) : tagOf (encF (.num 1 :: fs) (.n v :: cs)) = v % 256 := by
  rw [encF, tagOf_le1]

theorem Value.kind_range (v : Value) : 1 ≤ v.kind ∧ v.kind ≤ 7 := by cases v <;> simp [Value.kind]

theorem Fact.tag (f : Fact) : tagOf f.enc = f.value.kind := by
  simp only [Fact.enc, List.append_assoc, tagOf_le1]
  exact Nat.mod_eq_of_lt (Value.kind_lt _)

theorem Receipt.tag (r : Receipt) : tagOf r.enc = 0x40 := by
  simp only [Receipt.enc, List.append_assoc, tagOf_le1, receiptTag]

theorem FRec.dec_enc (x : FRec) (h : x.WF) : FRec.dec x.enc = some x := by
  cases x with
  | fact f =>
    have hk := Value.kind_range f.value
    have : kindOf (tagOf f.enc) = 1 := by rw [Fact.tag]; simp [kindOf]; omega
    simp only [FRec.dec, FRec.enc, this, Fact.dec_enc f h, Option.map_some]
  | receipt r =>
    have : kindOf (tagOf r.enc) = 2 := by rw [Receipt.tag]; decide
    simp only [FRec.dec, FRec.enc, this, Receipt.dec_enc r h, Option.map_some]
  | mark m =>
    have : kindOf (tagOf (markC.enc m)) = 3 := by rw [show tagOf (markC.enc m) = 0x50 from tagOf_lit _ _ _]; decide
    simp only [FRec.dec, FRec.enc, this, RecCodec.dec_enc markC_ok.1 h, Option.map_some]
  | summary s =>
    have ht : s.tag = 0x51 ∨ s.tag = 0x52 := by
      have := h.2
      simp only [sumC, Bool.and_eq_true, decide_eq_true_eq] at this
      exact this.1.1
    have : kindOf (tagOf (sumC.enc s)) = 4 := by
      rw [show tagOf (sumC.enc s) = s.tag % 256 from tagOf_num _ _ _]
      rcases ht with ht | ht <;> rw [ht] <;> decide
    simp only [FRec.dec, FRec.enc, this, RecCodec.dec_enc sumC_ok.1 h, Option.map_some]
  | money m =>
    have : kindOf (tagOf (moneyC.enc m)) = 5 := by rw [show tagOf (moneyC.enc m) = 0x60 from tagOf_lit _ _ _]; decide
    simp only [FRec.dec, FRec.enc, this, RecCodec.dec_enc moneyC_ok.1 h, Option.map_some]
  | lift l =>
    have : kindOf (tagOf (liftC.enc l)) = 6 := by rw [show tagOf (liftC.enc l) = 0x41 from tagOf_lit _ _ _]; decide
    simp only [FRec.dec, FRec.enc, this, RecCodec.dec_enc liftC_ok.1 h, Option.map_some]

theorem FRec.enc_dec {b : Bytes} {x : FRec} (h : FRec.dec b = some x) : x.enc = b := by
  unfold FRec.dec at h
  split at h
  · obtain ⟨y, hy, rfl⟩ := Option.map_eq_some_iff.1 h; exact Fact.enc_dec hy
  · obtain ⟨y, hy, rfl⟩ := Option.map_eq_some_iff.1 h; exact Receipt.enc_dec hy
  · obtain ⟨y, hy, rfl⟩ := Option.map_eq_some_iff.1 h; exact RecCodec.enc_dec hy
  · obtain ⟨y, hy, rfl⟩ := Option.map_eq_some_iff.1 h; exact RecCodec.enc_dec hy
  · obtain ⟨y, hy, rfl⟩ := Option.map_eq_some_iff.1 h; exact RecCodec.enc_dec hy
  · obtain ⟨y, hy, rfl⟩ := Option.map_eq_some_iff.1 h; exact RecCodec.enc_dec hy
  · cases h

theorem FRec.dec_wf {b : Bytes} {x : FRec} (h : FRec.dec b = some x) : x.WF := by
  unfold FRec.dec at h
  split at h
  · obtain ⟨y, hy, rfl⟩ := Option.map_eq_some_iff.1 h; exact Fact.dec_wf hy
  · obtain ⟨y, hy, rfl⟩ := Option.map_eq_some_iff.1 h; exact Receipt.dec_wf hy
  · obtain ⟨y, hy, rfl⟩ := Option.map_eq_some_iff.1 h; exact RecCodec.dec_wf hy
  · obtain ⟨y, hy, rfl⟩ := Option.map_eq_some_iff.1 h; exact RecCodec.dec_wf hy
  · obtain ⟨y, hy, rfl⟩ := Option.map_eq_some_iff.1 h; exact RecCodec.dec_wf hy
  · obtain ⟨y, hy, rfl⟩ := Option.map_eq_some_iff.1 h; exact RecCodec.dec_wf hy
  · cases h

/-- Every body that decodes is 245 bytes. -/
theorem FRec.dec_length {b : Bytes} {x : FRec} (h : FRec.dec b = some x) : b.length = bodyBytes := by
  rw [← FRec.enc_dec h]
  have hw := FRec.dec_wf h
  cases x with
  | fact f => exact Fact.enc_length f hw
  | receipt r => exact Receipt.enc_length r hw
  | mark m => exact (RecCodec.enc_length hw).trans markC_ok.2
  | summary s => exact (RecCodec.enc_length hw).trans sumC_ok.2
  | money m => exact (RecCodec.enc_length hw).trans moneyC_ok.2
  | lift l => exact (RecCodec.enc_length hw).trans liftC_ok.2

/-! ## Chains and the tables -/

/-- Per chain key, the newest record and the chain's count up to it. -/
abbrev Tab := HashMap Bytes (Nat × Nat)

/-- Record `i` joins the chain of key `k`: its link, and the table after it. -/
def step (t : Tab) (i : Nat) (k : Bytes) : Link × Tab :=
  let l : Link := match t[k]? with
    | some (j, c) => ⟨j + 1, nextCount c⟩
    | none => ⟨0, nextCount 0⟩
  (l, t.insert k (i, l.count))

/-- Record `i` joins each chain of its keys. -/
def stepAll (t : Tab) (i : Nat) : List Bytes → List Link × Tab
  | [] => ([], t)
  | k :: ks =>
    let s := step t i k
    let r := stepAll s.2 i ks
    (s.1 :: r.1, r.2)

/-- Records `n`, `n + 1`, ... with keys `kss`: each record's links, and the table after them. -/
def run (t : Tab) (n : Nat) : List (List Bytes) → List (List Link) × Tab
  | [] => ([], t)
  | ks :: kss =>
    let s := stepAll t n ks
    let r := run s.2 (n + 1) kss
    (s.1 :: r.1, r.2)

theorem run_length (t : Tab) (n : Nat) (kss : List (List Bytes)) : (run t n kss).1.length = kss.length := by
  induction kss generalizing t n with
  | nil => rfl
  | cons ks kss ih => simp [run, ih]

theorem run_append (t : Tab) (n : Nat) (a b : List (List Bytes)) :
    run t n (a ++ b) = ((run t n a).1 ++ (run (run t n a).2 (n + a.length) b).1,
      (run (run t n a).2 (n + a.length) b).2) := by
  induction a generalizing t n with
  | nil => simp [run]
  | cons ks a ih =>
    simp only [List.cons_append, run, ih, List.length_cons]
    rw [show n + 1 + a.length = n + (a.length + 1) by omega]

/-! ## A file as a projection of its records -/

/-- A file of records with chains: each record's keys, and its bytes given its links. -/
structure Proj (α : Type) where
  keys : α → List Bytes
  out : α → List Link → Bytes

/-- A file's bytes, its record count and its tables. -/
structure Writer where
  file : Bytes
  n : Nat
  tab : Tab

namespace Proj

variable {α : Type} (p : Proj α)

def emit (xs : List α) (ls : List (List Link)) : Bytes := (xs.zip ls).flatMap fun q => p.out q.1 q.2

/-- The file, count and tables the records `xs` derive. -/
def writerOf (xs : List α) : Writer :=
  let r := run ∅ 0 (xs.map p.keys)
  ⟨p.emit xs r.1, xs.length, r.2⟩

/-- Append the records of one batch. -/
def put (w : Writer) (xs : List α) : Writer :=
  let r := run w.tab w.n (xs.map p.keys)
  ⟨w.file ++ p.emit xs r.1, w.n + xs.length, r.2⟩

/-- Load a file: its records (`parse`), then their writer, accepted only if its bytes are the file's. -/
def load (parse : Bytes → Option (List α)) (f : Bytes) : Option Writer :=
  match parse f with
  | some xs => if (p.writerOf xs).file = f then some (p.writerOf xs) else none
  | none => none

theorem emit_append (xs ys : List α) (ls ms : List (List Link)) (h : xs.length = ls.length) :
    p.emit (xs ++ ys) (ls ++ ms) = p.emit xs ls ++ p.emit ys ms := by
  simp [emit, List.zip_append h]

theorem put_writerOf (xs ys : List α) : p.put (p.writerOf xs) ys = p.writerOf (xs ++ ys) := by
  simp only [put, writerOf, List.map_append, run_append, List.length_map, Nat.zero_add, List.length_append]
  rw [emit_append p xs ys _ _ (by rw [run_length, List.length_map])]

theorem foldl_put (xs : List α) (log : List (List α)) :
    log.foldl p.put (p.writerOf xs) = p.writerOf (xs ++ log.flatten) := by
  induction log generalizing xs with
  | nil => simp
  | cons ys log ih => simp only [List.foldl_cons, put_writerOf, ih, List.flatten_cons, List.append_assoc]

theorem load_writerOf {parse : Bytes → Option (List α)} {xs : List α} (h : parse (p.writerOf xs).file = some xs) :
    p.load parse (p.writerOf xs).file = some (p.writerOf xs) := by
  simp [load, h]

/-- What a load accepts is the writer of the records it read, and its bytes are the file. -/
theorem load_sound {parse : Bytes → Option (List α)} {f : Bytes} {w : Writer} (h : p.load parse f = some w) :
    ∃ xs, parse f = some xs ∧ w = p.writerOf xs ∧ w.file = f := by
  unfold load at h
  split at h
  · rename_i xs hx
    split at h
    · rename_i he
      cases h
      exact ⟨xs, hx, rfl, he⟩
    · cases h
  · cases h

/-- A file loaded after batch `k` and extended by the later batches is the writer of the whole log: the same bytes,
    count and tables. -/
theorem projection (parse : Bytes → Option (List α)) (log : List (List α)) (k : Nat)
    (hp : parse (p.writerOf (log.take k).flatten).file = some (log.take k).flatten) :
    (p.load parse (p.writerOf (log.take k).flatten).file).map (fun w => (log.drop k).foldl p.put w) =
      some (p.writerOf log.flatten) := by
  rw [p.load_writerOf hp, Option.map_some, foldl_put, ← List.flatten_append, List.take_append_drop]

end Proj

/-! ## Reading a file back into records -/

/-- The first `m` records of width `k`. -/
def chunks (k : Nat) : Nat → Bytes → List Bytes
  | 0, _ => []
  | m + 1, b => b.take k :: chunks k m (b.drop k)

theorem chunks_flatMap {β : Type} (k : Nat) (hk : 0 < k) (g : β → Bytes) :
    ∀ l : List β, (∀ x ∈ l, (g x).length = k) → chunks k ((l.flatMap g).length / k) (l.flatMap g) = l.map g
  | [], _ => by simp [chunks]
  | x :: l, h => by
    have hx := h x (by simp)
    have ih := chunks_flatMap k hk g l fun y hy => h y (by simp [hy])
    have hl : ((x :: l).flatMap g).length / k = (l.flatMap g).length / k + 1 := by
      rw [List.flatMap_cons, List.length_append, hx]
      exact Nat.add_div_left _ hk
    rw [hl, List.flatMap_cons, chunks, List.take_left' hx, List.drop_left' hx, ih, List.map_cons]

/-! ## The `facts` file -/

/-- A body's chains: a receipt's source and its file hash (the first 8 bytes, `rcpt`); a fact row's or marker's
    subject; a summary's member (`msum`); a money row's obligation, its form and key (`obl`).  A lift record joins no
    chain: its receipt names it.  The first key is the chain its link follows. -/
def chainKeys (b : Bytes) : List Bytes :=
  match kindOf (tagOf b) with
  | 1 => [2 :: slice b 2 32]
  | 2 => [1 :: slice b 1 2, 5 :: slice b 25 8]
  | 3 => [2 :: slice b 4 32]
  | 4 => [3 :: slice b 1 32]
  | 5 => [4 :: slice b 1 1 ++ slice b 3 72]
  | _ => []

/-- A body and its link. -/
def wrap (b : Bytes) (l : Link) : Bytes := b ++ encF linkL l.cells

def factsP : Proj Bytes := ⟨chainKeys, fun b ls => wrap b (ls.headD ⟨0, 0⟩)⟩

/-- The `facts` file of bodies `bs`, in log order. -/
def factsFile (bs : List Bytes) : Bytes := (factsP.writerOf bs).file

/-- The bodies of a `facts` file; none unless each decodes. -/
def parseFacts (f : Bytes) : Option (List Bytes) :=
  let bs := (chunks recBytes (f.length / recBytes) f).map (·.take bodyBytes)
  if bs.all (fun b => (FRec.dec b).isSome) then some bs else none

def loadFacts (f : Bytes) : Option Writer := factsP.load parseFacts f

theorem wrap_length (b : Bytes) (l : Link) : (wrap b l).length = b.length + 11 := by
  simp [wrap, encF, linkL, Link.cells, z, leBytes_length]

theorem parseFacts_file (bs : List Bytes) (hg : ∀ b ∈ bs, (FRec.dec b).isSome) :
    parseFacts (factsFile bs) = some bs := by
  have hlen : ∀ b ∈ bs, b.length = bodyBytes := fun b hb => by
    obtain ⟨x, hx⟩ := Option.isSome_iff_exists.1 (hg b hb)
    exact FRec.dec_length hx
  let ls := (run ∅ 0 (bs.map factsP.keys)).1
  have hls : bs.length ≤ ls.length := by simp [ls, run_length]
  have hmem : ∀ q ∈ bs.zip ls, q.1 ∈ bs := fun q hq => (List.of_mem_zip (a := q.1) (b := q.2) hq).1
  have hq : ∀ q ∈ bs.zip ls, (factsP.out q.1 q.2).length = recBytes := fun q hq => by
    rw [show factsP.out q.1 q.2 = wrap q.1 (q.2.headD ⟨0, 0⟩) from rfl, wrap_length, hlen q.1 (hmem q hq)]
    rfl
  have hc := chunks_flatMap recBytes (by decide) (fun q => factsP.out q.1 q.2) (bs.zip ls) hq
  have hb : ((bs.zip ls).map fun q => factsP.out q.1 q.2).map (·.take bodyBytes) = bs := by
    rw [List.map_map]
    have : ∀ q ∈ bs.zip ls, ((·.take bodyBytes) ∘ fun q => factsP.out q.1 q.2) q = q.1 := fun q hq =>
      List.take_left' (hlen q.1 (hmem q hq))
    exact (List.map_congr_left this).trans (List.map_fst_zip hls)
  have hf : factsFile bs = (bs.zip ls).flatMap fun q => factsP.out q.1 q.2 := rfl
  unfold parseFacts
  simp only [hf, hc, hb]
  rw [if_pos (List.all_eq_true.2 hg)]

/-- `facts_projection`: the `facts` file loaded after batch `k` of a log of well-formed bodies, then extended by the
    later batches, is byte for byte the file the whole log derives, with the same count and tables (`msum`, `obl`,
    `rcpt`, the chain heads).  At `k = 0` the loaded file is empty: the rebuild from the log. -/
theorem facts_projection (log : List (List Bytes)) (hg : ∀ b ∈ log.flatten, (FRec.dec b).isSome) (k : Nat) :
    (loadFacts (factsFile (log.take k).flatten)).map (fun w => (log.drop k).foldl factsP.put w) =
      some (factsP.writerOf log.flatten) := by
  refine factsP.projection parseFacts log k (parseFacts_file _ fun b hb => hg b ?_)
  obtain ⟨l, hl, hb⟩ := List.mem_flatten.1 hb
  exact List.mem_flatten.2 ⟨l, List.mem_of_mem_take hl, hb⟩

/-- What `loadFacts` accepts holds well-formed bodies whose links are the ones their order derives. -/
theorem loadFacts_sound {f : Bytes} {w : Writer} (h : loadFacts f = some w) :
    ∃ bs, (∀ b ∈ bs, (FRec.dec b).isSome) ∧ w = factsP.writerOf bs ∧ factsFile bs = f := by
  obtain ⟨bs, hp, hw, hf⟩ := factsP.load_sound h
  refine ⟨bs, ?_, hw, by subst hw; exact hf⟩
  simp only [parseFacts] at hp
  split at hp
  · rename_i ha
    cases hp
    exact fun b hb => List.all_eq_true.1 ha b hb
  · cases hp

/-! ## The links files -/

/-- The fields of a links record that come from the answer and the authority record. -/
structure LinkTail where
  batch : Nat
  windex : Nat
  reasons : Nat
  rule : Nat
  day : Nat
  deriving DecidableEq, Repr

def tailC : RecCodec LinkTail where
  L := [.num 5, .num 3, .num 4, .num 1, .num 4]
  toC x := [.n x.batch, .n x.windex, .n x.reasons, .n x.rule, .n x.day]
  build cs := ⟨nAt cs 0, nAt cs 1, nAt cs 2, nAt cs 3, nAt cs 4⟩
  chk x := decide (x.rule = 1 ∨ x.rule = 2 ∨ x.rule = 5)

theorem tailC_ok : tailC.Lawful ∧ width tailC.L = 17 := ⟨fun y _ => by cases y; rfl, rfl⟩

def linkW : Nat := 32

/-- A line row's member, payee and rendering provider (the row layout of the rows files). -/
def memberOf (r : Bytes) : Bytes := slice r 124 32
def payeeOf (r : Bytes) : Bytes := slice r 156 21
def renderingOf (r : Bytes) : Bytes := slice r 177 21

/-- The `prev` of link `i`. -/
def prevAt (ls : List Link) (i : Nat) : Nat := (ls.getD i ⟨0, 0⟩).prev

/-- A row (and its answer fields) of one set's links file. -/
def linksP : Proj (Bytes × LinkTail) :=
  ⟨fun x => [1 :: memberOf x.1, 2 :: payeeOf x.1, 3 :: renderingOf x.1],
    fun x ls => leBytes 5 (prevAt ls 0) ++ leBytes 5 (prevAt ls 1) ++ leBytes 5 (prevAt ls 2) ++ tailC.enc x.2⟩

def linksFile (xs : List (Bytes × LinkTail)) : Bytes := (linksP.writerOf xs).file

/-- A links file read beside its set's rows: the stored answer fields of each record, paired with the rows; none
    unless there is one record per row and each decodes. -/
def parseLinks (rows : List Bytes) (f : Bytes) : Option (List (Bytes × LinkTail)) :=
  match (chunks linkW (f.length / linkW) f).mapM (fun r => tailC.dec (r.drop 15)) with
  | some ts => if ts.length = rows.length then some (rows.zip ts) else none
  | none => none

def loadLinks (rows : List Bytes) (f : Bytes) : Option Writer := linksP.load (parseLinks rows) f

theorem mapM_map_some {β γ δ : Type} (f : β → δ) (g : δ → Option γ) (h : β → γ) :
    ∀ l : List β, (∀ x ∈ l, g (f x) = some (h x)) → (l.map f).mapM g = some (l.map h)
  | [], _ => rfl
  | x :: l, hx => by
    rw [List.map_cons, List.mapM_cons, hx x (by simp), mapM_map_some f g h l fun y hy => hx y (by simp [hy])]
    rfl

theorem zip_fst_snd {β γ : Type} : ∀ l : List (β × γ), (l.map Prod.fst).zip (l.map Prod.snd) = l
  | [] => rfl
  | _ :: l => by simp [zip_fst_snd l]

theorem linksP_out (x : Bytes × LinkTail) (ls : List Link) :
    linksP.out x ls = (leBytes 5 (prevAt ls 0) ++ leBytes 5 (prevAt ls 1) ++ leBytes 5 (prevAt ls 2)) ++ tailC.enc x.2 :=
  rfl

theorem linksP_out_length (x : Bytes × LinkTail) (ls : List Link) (h : tailC.WF x.2) : (linksP.out x ls).length = linkW := by
  have h1 := RecCodec.enc_length h
  rw [tailC_ok.2] at h1
  simp only [linksP_out, List.length_append, leBytes_length, h1, linkW]

theorem linksP_out_tail (x : Bytes × LinkTail) (ls : List Link) (h : tailC.WF x.2) :
    tailC.dec ((linksP.out x ls).drop 15) = some x.2 := by
  have h15 : (leBytes 5 (prevAt ls 0) ++ leBytes 5 (prevAt ls 1) ++ leBytes 5 (prevAt ls 2)).length = 15 := by
    simp only [List.length_append, leBytes_length]
  rw [linksP_out, List.drop_left' h15]
  exact RecCodec.dec_enc tailC_ok.1 h

theorem parseLinks_file (xs : List (Bytes × LinkTail)) (hg : ∀ x ∈ xs, tailC.WF x.2) :
    parseLinks (xs.map Prod.fst) (linksFile xs) = some xs := by
  let ls := (run ∅ 0 (xs.map linksP.keys)).1
  have hls : xs.length ≤ ls.length := by simp [ls, run_length]
  have hmem : ∀ q ∈ xs.zip ls, q.1 ∈ xs := fun q hq => (List.of_mem_zip (a := q.1) (b := q.2) hq).1
  have hq : ∀ q ∈ xs.zip ls, (linksP.out q.1 q.2).length = linkW := fun q hq =>
    linksP_out_length q.1 q.2 (hg q.1 (hmem q hq))
  have hc := chunks_flatMap (β := (Bytes × LinkTail) × List Link) linkW (by decide) (fun q => linksP.out q.1 q.2)
    (xs.zip ls) hq
  have hm : ((xs.zip ls).map fun q => linksP.out q.1 q.2).mapM (fun r => tailC.dec (r.drop 15)) =
      some ((xs.zip ls).map fun q => q.1.2) :=
    mapM_map_some _ _ _ _ fun q hq => linksP_out_tail q.1 q.2 (hg q.1 (hmem q hq))
  have hs : (xs.zip ls).map (fun q => q.1.2) = xs.map Prod.snd := by
    have := congrArg (List.map Prod.snd) (List.map_fst_zip hls)
    rw [List.map_map] at this
    exact this
  have hf : linksFile xs = (xs.zip ls).flatMap fun q => linksP.out q.1 q.2 := rfl
  unfold parseLinks
  rw [hf, hc, hm, hs]
  show (if (xs.map Prod.snd).length = (xs.map Prod.fst).length then some ((xs.map Prod.fst).zip (xs.map Prod.snd))
    else none) = some xs
  rw [if_pos (by simp only [List.length_map]), zip_fst_snd]

/-- `links_projection`: a set's links file loaded beside the set's rows after batch `k`, then extended by the later
    batches, is byte for byte the file the whole log derives, with the same count and tables (`mrel` `prel` `rrel`,
    or `munr` `punr` `runr`).  At `k = 0` the loaded file is empty: the rebuild from the log. -/
theorem links_projection (log : List (List (Bytes × LinkTail))) (hg : ∀ x ∈ log.flatten, tailC.WF x.2) (k : Nat) :
    (loadLinks ((log.take k).flatten.map Prod.fst) (linksFile (log.take k).flatten)).map
        (fun w => (log.drop k).foldl linksP.put w) = some (linksP.writerOf log.flatten) := by
  refine linksP.projection _ log k (parseLinks_file _ fun x hx => hg x ?_)
  obtain ⟨l, hl, hx⟩ := List.mem_flatten.1 hx
  exact List.mem_flatten.2 ⟨l, List.mem_of_mem_take hl, hx⟩

/-! ## Checks against the design's offset tables, and the chains of sample files -/

def sampleSum : SumRec :=
  mkSum 0x51 (pat 32 1) 7 20230101 0 0
    [⟨3, 1, 1, 20260101, 99991231, 99991231, 1⟩, ⟨5, 1, 0x81, 20260101, 99991231, 99991231, 0⟩]

#guard sumC.dec (sumC.enc sampleSum) == some sampleSum && sampleSum.list.length == 2
#guard slice (sumC.enc sampleSum) 0 33 == 0x51 :: pat 32 1 && slice (sumC.enc sampleSum) 33 9 == leBytes 5 7 ++ leBytes 4 20230101
#guard slice (sumC.enc sampleSum) 52 12 == [2] ++ leBytes 5 3 ++ leBytes 5 1 ++ [1] &&
  slice (sumC.enc sampleSum) 87 1 == [0x81] && slice (sumC.enc sampleSum) 101 144 == zeros 144
#guard [{ sampleSum with tag := 0x53 }, { sampleSum with n := 9 }, { sampleSum with n := 1 }].all fun s =>
  sumC.dec (sumC.enc s) == none

def sampleMoney : MoneyRow :=
  ⟨1, 1, pat 72 11, 4, 30000, 25000, 1, 9, 3, 5, 0, 20260301, 0, 0, 2, 5000, 0, 0, 0, 0, 0, 0⟩

def samplePlb : MoneyRow :=
  ⟨2, 8, ident 21 "1234567890" ++ ident 31 "PLB-REF-1" ++ leBytes 4 202603 ++ zeros 16, 0, 12000, 0, 0, 0, 0, 7, 6,
    0, 0, 0, 0, 0, 0, 0, 0, 12000, 0, 0⟩

#guard moneyC.dec (moneyC.enc sampleMoney) == some sampleMoney && moneyC.dec (moneyC.enc samplePlb) == some samplePlb
#guard slice (moneyC.enc sampleMoney) 0 3 == [0x60, 1, 1] && slice (moneyC.enc sampleMoney) 3 72 == pat 72 11 &&
  slice (moneyC.enc sampleMoney) 75 22 == leBytes 5 4 ++ leBytes 8 30000 ++ leBytes 8 25000 ++ [1]
#guard slice (moneyC.enc sampleMoney) 97 16 == leBytes 8 9 ++ leBytes 3 3 ++ leBytes 5 5 &&
  slice (moneyC.enc sampleMoney) 118 4 == leBytes 4 20260301 && slice (moneyC.enc sampleMoney) 130 9 == [2] ++ leBytes 8 5000
#guard slice (moneyC.enc samplePlb) 3 21 == ident 21 "1234567890" && slice (moneyC.enc samplePlb) 108 10 == leBytes 5 7 ++ leBytes 5 6 &&
  slice (moneyC.enc samplePlb) 163 8 == leBytes 8 12000 && slice (moneyC.enc samplePlb) 187 58 == zeros 58
#guard [{ sampleMoney with mkind := 6 }, { sampleMoney with form := 3 }, { sampleMoney with form := 5 },
  { sampleMoney with verdict := 3 }, { samplePlb with mkind := 1 }, { samplePlb with line := 1 },
  { samplePlb with okey := pat 72 1 }].all fun m => moneyC.dec (moneyC.enc m) == none

def sampleReceipt : Receipt :=
  ⟨3, 1, 12, 20260102, 20250101, 2026010201, pat 64 40, ident 21 "STATEMMIS", 1, 1, 2, 0, 1000, 990, 5, 5,
    ident 21 "MEDICAID", 4000, zeros 64⟩

def sampleFact : Fact :=
  ⟨0, pat 32 1, pat 32 100, 20260101, 99991231, 99991231, 5, 7, .elig ⟨1, 1, ident 21 "MEDICAID", ident 21 "", 20260105, 0⟩⟩

/-- A receipt, a fact row, a marker and a summary of one member, another fact row of it, two money rows of one payment,
    the source's next receipt of the same file, and a provider-level balance. -/
def sampleBodies : List Bytes :=
  [sampleReceipt.enc, sampleFact.enc, markC.enc ⟨3, 1, pat 32 1, 5, 9, 2, 1, pat 32 100⟩, sumC.enc sampleSum,
    { sampleFact with sid := pat 32 101 }.enc, moneyC.enc sampleMoney, moneyC.enc { sampleMoney with cents := 100 },
    { sampleReceipt with fseq := 2026010202 }.enc, moneyC.enc samplePlb]

#guard sampleBodies.all fun b => (FRec.dec b).map FRec.enc == some b
#guard (run ∅ 0 (sampleBodies.map chainKeys)).1.map (·.map fun l => (l.prev, l.count)) ==
  [[(0, 1), (0, 1)], [(0, 1)], [(2, 2)], [(0, 1)], [(3, 3)], [(0, 1)], [(6, 2)], [(1, 2), (1, 2)], [(0, 1)]]
#guard (factsFile sampleBodies).length == 9 * recBytes &&
  slice (factsFile sampleBodies) (4 * recBytes + bodyBytes) 11 == leBytes 5 3 ++ leBytes 2 3 ++ zeros 4
#guard (loadFacts (factsFile sampleBodies)).map (·.n) == some 9 &&
  (loadFacts ((factsFile sampleBodies).set (2 * recBytes + bodyBytes) 0)).isNone &&
  (loadFacts ((factsFile sampleBodies).set (3 * recBytes) 0x53)).isNone
#guard (loadFacts (factsFile (sampleBodies.take 4))).map (fun w => (factsP.put w (sampleBodies.drop 4)).file) ==
  some (factsFile sampleBodies)

def sampleTail : LinkTail := ⟨9, 3, 0x11, 1, 20260301⟩

#guard tailC.dec (tailC.enc sampleTail) == some sampleTail && tailC.dec (tailC.enc { sampleTail with rule := 3 }) == none

/-- A row with member `m`, payee `p` and rendering provider `r` at the rows file's offsets. -/
def sampleRow (m p r : Nat) : Bytes := zeros 124 ++ pat 32 m ++ pat 21 p ++ pat 21 r ++ zeros 47

def sampleRows : List (Bytes × LinkTail) :=
  [(sampleRow 1 2 3, sampleTail), (sampleRow 4 2 5, { sampleTail with windex := 4 }),
    (sampleRow 1 6 3, { sampleTail with batch := 10, windex := 0, rule := 5 })]

#guard (linksFile sampleRows).length == 3 * linkW && slice (linksFile sampleRows) 15 17 == tailC.enc sampleTail
#guard slice (linksFile sampleRows) 32 15 == leBytes 5 0 ++ leBytes 5 1 ++ leBytes 5 0 &&
  slice (linksFile sampleRows) 64 15 == leBytes 5 1 ++ leBytes 5 0 ++ leBytes 5 1
#guard (loadLinks (sampleRows.map (·.1)) (linksFile sampleRows)).isSome &&
  (loadLinks (sampleRows.map (·.1)) ((linksFile sampleRows).set 37 0)).isNone &&
  (loadLinks ((sampleRows.map (·.1)).take 2) (linksFile sampleRows)).isNone

/-- A lift record of receipt record 7: row 1 lifted to `roff` 7, row 300 to the largest `roff`. -/
def sampleLift : LiftRec := ⟨7, 2, (liftE.enc ⟨1, 7⟩ ++ liftE.enc ⟨300, 2 ^ 40 - 1⟩) ++ zeros 218⟩

#guard liftRecs 7 [⟨1, 7⟩, ⟨300, 2 ^ 40 - 1⟩] == [sampleLift] && sampleLift.list == [⟨1, 7⟩, ⟨300, 2 ^ 40 - 1⟩] &&
  (FRec.dec (liftC.enc sampleLift)).map FRec.enc == some (liftC.enc sampleLift) && chainKeys (liftC.enc sampleLift) == []
#guard slice (liftC.enc sampleLift) 0 7 == [0x41] ++ leBytes 5 7 ++ [2] &&
  slice (liftC.enc sampleLift) 7 20 == leBytes 5 1 ++ leBytes 5 7 ++ leBytes 5 300 ++ leBytes 5 (2 ^ 40 - 1)
#guard [{ sampleLift with n := 0 }, { sampleLift with n := 24 }, { sampleLift with n := 1 }].all fun l =>
  liftC.dec (liftC.enc l) == none
#guard (liftRecs 7 ((List.range 47).map fun i => ⟨i, i⟩)).map (·.n) == [23, 23, 1] && liftRecs 7 [] == []

/-- The golden bytes the Python twin's tests read (`tests/test_fact_store.py`): a summary, a marker, a payment money
    row, a provider-level balance, the link bytes of the sample `facts` file, the sample links file and a lift
    record. -/
def golden : List (String × String) :=
  [ ("summary",
    "510102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f200700000000d5af34010000000000000000000002030000000001000000000105253501bfbef505bfbef50501050000000001000000008105253501bfbef505bfbef50500000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000")
  , ("marker",
    "500300010102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f200500000000090000000002016465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f80818283000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000")
  , ("money",
    "6001010b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f50515204000000003075000000000000a86100000000000001090000000000000003000005000000000000000000cd253501000000000000000002881300000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000")
  , ("plb",
    "6002080a313233343536373839300000000000000000000009504c422d5245462d310000000000000000000000000000000000000000006b170300000000000000000000000000000000000000000000e02e000000000000000000000000000000000000000000000000000007000000000600000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000e02e0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000")
  , ("facts_links",
    "000000000001000000000000000000000100000000000200000000020000000000000000000001000000000003000000000300000000000000000000010000000000060000000002000000000001000000000200000000000000000000010000000000")
  , ("links_file",
    "00000000000000000000000000000009000000000300001100000001cd25350100000000000100000000000000000009000000000400001100000001cd2535010100000000000000000001000000000a000000000000001100000005cd253501")
  , ("lift",
    "41070000000002010000000007000000002c01000000ffffffffff0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000") ]

#guard golden.map (hexBytes ·.2) == [sumC.enc sampleSum, markC.enc ⟨3, 1, pat 32 1, 5, 9, 2, 1, pat 32 100⟩,
  moneyC.enc sampleMoney, moneyC.enc samplePlb,
  (List.range 9).flatMap (fun i => slice (factsFile sampleBodies) (i * recBytes + bodyBytes) 11), linksFile sampleRows,
  liftC.enc sampleLift]

end BlindLedger.Gate.FactStore
