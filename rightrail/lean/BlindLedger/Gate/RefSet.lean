import BlindLedger.Gate.FactFrame

/-! The reference set's digest `rs` (fact record design §2.9), as the specification states it; the checker
    (`gate_verify3`) computes it from its own replay.  The engine keeps the same set its own way (`Engine3/HFacts.lean`:
    sorted entries, the chain recomputed from a late receipt's place).

    Reference rows are the rows of kinds 3 (EXCL) and 4 (PDEATH), the kinds the design's kind table marks as reference
    spans (§2.4).  Until the source registry is wired into admission, an admitted receipt is a reference receipt when its
    frame carries at least one reference row, and only those rows enter its `rd`; reference rows go whole to every shard,
    so every shard holds the same reference receipts and the same `rd`, whatever member rows it holds.

    - A reference receipt's entry is `src u16 ‖ fseq u64 ‖ reader u16 ‖ file 64 ‖ rd 64`, the numbers big-endian so that
      the byte order of entries is the order of (`src`, `fseq`, reader, file).  `rd = H(dom REFROWS ‖ its reference wire
      rows in wire order)`.
    - Each source's chain runs over its receipts in that order: `h_0 = H(dom REFSRC ‖ src u16)`,
      `h_i = H(dom REFSRC ‖ h_{i−1} ‖ fseq_i u64 ‖ file_i ‖ rd_i)` (little-endian numbers, as everywhere else).  The reader
      orders a re-read after the reading it replaces (same `fseq`); the file orders two receipts that share `src`, `fseq`
      and reader.
    - `rs = H(dom REFSET ‖ for each reference source in ascending order: src u16 ‖ h_last)`; with no reference receipt it
      is `H(dom REFSET)`.

    `rs` is a function of the set of entries alone (`rs_order`: any arrival order gives the same `rs`), and of a shard's
    receipts it reads only those with reference rows, each by its source, `fseq`, reader, file and reference rows
    (`rs_shard`: member rows, row counts, batches and receipts without reference rows, in any number and order, do not
    enter it).  Synthetic, nonpayment, non-PHI. -/

namespace BlindLedger.Gate.RefSet

open BlindLedger.Gate.FactCodec (Receipt leBytes Bytes)
open BlindLedger.Gate.FactFrame (Row)

/-- The reference kinds: 3 EXCL and 4 PDEATH (§2.4). -/
def refKind (k : Nat) : Bool := k == 3 || k == 4

/-- A frame's reference rows, in wire order. -/
def refRows (rows : List Row) : List Row := rows.filter fun w => refKind w.value.kind

/-- `n` in `w` bytes, big-endian. -/
def be (w n : Nat) : Bytes := (leBytes w n).reverse

def beNat (b : Bytes) : Nat := b.foldl (fun a x => a * 256 + x.toNat) 0

/-- What `rs` reads of an admitted receipt and its frame's rows. -/
abbrev View := Nat × Nat × Nat × Bytes × List Row

def view (x : Receipt × List Row) : View := (x.1.src, x.1.fseq, x.1.reader, x.1.file, refRows x.2)

/-- A view with at least one reference row: the view of a reference receipt. -/
def hasRef (v : View) : Bool := !v.2.2.2.2.isEmpty

/-- The entry of a receipt with view `v`; none when its frame has no reference row. -/
def entOfView (H : Bytes → Bytes) (v : View) : Option Bytes :=
  let (src, fseq, reader, file, rr) := v
  if rr.isEmpty then none
  else some (be 2 src ++ be 8 fseq ++ be 2 reader ++ file ++ H (domain "REFROWS" ++ rr.flatMap Row.enc))

/-- The entry of admitted receipt `r` whose frame carried `rows`. -/
def ent (H : Bytes → Bytes) (r : Receipt) (rows : List Row) : Option Bytes := entOfView H (view (r, rows))

/-- The `rd` a written receipt stores: its entry's `rd` when its frame carried a reference row, else 64 zero bytes. -/
def rdOf (H : Bytes → Bytes) (rows : List Row) : Bytes :=
  let rr := refRows rows
  if rr.isEmpty then List.replicate 64 0 else H (domain "REFROWS" ++ rr.flatMap Row.enc)

/-- The entry a stored receipt gives (`src`, `fseq`, reader, file and its stored `rd`); none when `rd` is zero. -/
def entOfRcpt (r : Receipt) : Option Bytes :=
  if r.rd == List.replicate 64 0 then none else some (be 2 r.src ++ be 8 r.fseq ++ be 2 r.reader ++ r.file ++ r.rd)

def eSrc (e : Bytes) : Nat := beNat (e.take 2)
def eFseq (e : Bytes) : Nat := beNat ((e.drop 2).take 8)
/-- The entry's `file ‖ rd`. -/
def eTail (e : Bytes) : Bytes := e.drop 12

/-! ## The order of entries -/

/-- Byte order: `a` at or before `b`. -/
def lexLe : Bytes → Bytes → Bool
  | [], _ => true
  | _ :: _, [] => false
  | x :: xs, y :: ys => decide (x.toNat < y.toNat) || (x.toNat == y.toNat && lexLe xs ys)

theorem lexLe_total : ∀ a b : Bytes, lexLe a b = true ∨ lexLe b a = true
  | [], _ => by simp [lexLe]
  | _ :: _, [] => by simp [lexLe]
  | x :: xs, y :: ys => by
    simp only [lexLe, Bool.or_eq_true, Bool.and_eq_true, decide_eq_true_eq, beq_iff_eq]
    rcases Nat.lt_trichotomy x.toNat y.toNat with h | h | h
    · exact .inl (.inl h)
    · rcases lexLe_total xs ys with h' | h'
      · exact .inl (.inr ⟨h, h'⟩)
      · exact .inr (.inr ⟨h.symm, h'⟩)
    · exact .inr (.inl h)

theorem lexLe_antisymm : ∀ a b : Bytes, lexLe a b = true → lexLe b a = true → a = b
  | [], [], _, _ => rfl
  | [], _ :: _, _, h => by simp [lexLe] at h
  | _ :: _, [], h, _ => by simp [lexLe] at h
  | x :: xs, y :: ys, h1, h2 => by
    simp only [lexLe, Bool.or_eq_true, Bool.and_eq_true, decide_eq_true_eq, beq_iff_eq] at h1 h2
    rcases h1 with h1 | ⟨e1, h1⟩
    · rcases h2 with h2 | ⟨e2, _⟩ <;> omega
    · rcases h2 with h2 | ⟨_, h2⟩
      · omega
      · rw [UInt8.toNat.inj e1, lexLe_antisymm xs ys h1 h2]

theorem lexLe_trans : ∀ a b c : Bytes, lexLe a b = true → lexLe b c = true → lexLe a c = true
  | [], _, _, _, _ => by simp [lexLe]
  | _ :: _, [], _, h, _ => by simp [lexLe] at h
  | _ :: _, _ :: _, [], _, h => by simp [lexLe] at h
  | x :: xs, y :: ys, z :: zs, h1, h2 => by
    simp only [lexLe, Bool.or_eq_true, Bool.and_eq_true, decide_eq_true_eq, beq_iff_eq] at h1 h2 ⊢
    rcases h1 with h1 | ⟨e1, h1⟩ <;> rcases h2 with h2 | ⟨e2, h2⟩
    · exact .inl (by omega)
    · exact .inl (by omega)
    · exact .inl (by omega)
    · exact .inr ⟨by omega, lexLe_trans xs ys zs h1 h2⟩

/-- `e` put before the first entry it is at or before. -/
def ins (e : Bytes) : List Bytes → List Bytes
  | [] => [e]
  | y :: l => if lexLe e y then e :: y :: l else y :: ins e l

/-- The entries in byte order. -/
def sort (l : List Bytes) : List Bytes := l.foldr ins []

theorem ins_comm (a b : Bytes) (l : List Bytes) : ins a (ins b l) = ins b (ins a l) := by
  by_cases e : a = b
  · subst e; rfl
  have tot := lexLe_total a b
  have anti : lexLe a b = true → lexLe b a = true → False := fun h1 h2 => e (lexLe_antisymm a b h1 h2)
  induction l with
  | nil => cases hab : lexLe a b <;> cases hba : lexLe b a <;> simp_all [ins]
  | cons y l ih =>
    have t1 := lexLe_trans a b y
    have t2 := lexLe_trans b a y
    cases hay : lexLe a y <;> cases hby : lexLe b y <;> cases hab : lexLe a b <;> cases hba : lexLe b a <;>
      simp_all [ins]

/-- Any order of the same entries sorts the same. -/
theorem sort_perm {l1 l2 : List Bytes} (h : l1.Perm l2) : sort l1 = sort l2 := by
  induction h with
  | nil => rfl
  | cons x _ ih => exact congrArg (ins x) ih
  | swap x y l => exact ins_comm y x (sort l)
  | trans _ _ ih1 ih2 => exact ih1.trans ih2

/-! ## The chains and `rs` -/

/-- The chain of source `src` over its entries `es`, in order. -/
def chain (H : Bytes → Bytes) (src : Nat) (es : List Bytes) : Bytes :=
  es.foldl (fun h e => H (domain "REFSRC" ++ h ++ leBytes 8 (eFseq e) ++ eTail e)) (H (domain "REFSRC" ++ leBytes 2 src))

/-- `rs` of entries already in order: each source once, ascending, with the last value of its chain. -/
def rsSorted (H : Bytes → Bytes) (s : List Bytes) : Bytes :=
  H (domain "REFSET" ++ (s.map eSrc).eraseDups.flatMap fun src => leBytes 2 src ++ chain H src (s.filter (eSrc · == src)))

/-- `rs` of the reference receipts' entries, in any order. -/
def rs (H : Bytes → Bytes) (es : List Bytes) : Bytes := rsSorted H (sort es)

/-- `rs` of a shard's admitted receipts, each with the rows its frame carried. -/
def rsOf (H : Bytes → Bytes) (adm : List (Receipt × List Row)) : Bytes := rs H (adm.filterMap fun x => ent H x.1 x.2)

/-- `rs_order`: the same reference receipts, in any order of arrival, give the same `rs`. -/
theorem rs_order (H : Bytes → Bytes) {l1 l2 : List Bytes} (h : l1.Perm l2) : rs H l1 = rs H l2 := by
  unfold rs; rw [sort_perm h]

/-- A view without reference rows has no entry, so dropping such views changes no entry. -/
theorem filterMap_hasRef (H : Bytes → Bytes) (l : List View) :
    (l.filter hasRef).filterMap (entOfView H) = l.filterMap (entOfView H) := by
  induction l with
  | nil => rfl
  | cons v l ih =>
    obtain ⟨src, fseq, reader, file, rr⟩ := v
    cases rr <;> simp [hasRef, entOfView, ih]

/-- `rs_shard`: `rs` depends only on the reference receipts.  Two shards whose admitted receipts with reference rows
    agree, up to order, in source, `fseq`, reader, file and reference rows have the same `rs`, whatever their member
    rows, row counts and batches, and whatever receipts without reference rows each holds, in any number and order. -/
theorem rs_shard (H : Bytes → Bytes) {a1 a2 : List (Receipt × List Row)}
    (h : ((a1.map view).filter hasRef).Perm ((a2.map view).filter hasRef)) : rsOf H a1 = rsOf H a2 := by
  have e : ∀ a : List (Receipt × List Row),
      a.filterMap (fun x => ent H x.1 x.2) = ((a.map view).filter hasRef).filterMap (entOfView H) := by
    intro a; rw [filterMap_hasRef, List.filterMap_map]; rfl
  unfold rsOf
  rw [e a1, e a2]
  exact rs_order H (h.filterMap _)

/-! ## Vectors

    Two sources; source 7 has a late receipt (`fseq` 5 after 9) and a re-read of `fseq` 9 (reader 2): every order of
    the four entries gives the same `rs`, and it differs from the `rs` of three of them and from the empty set's. -/

def vE (src fseq reader k : Nat) : Bytes :=
  be 2 src ++ be 8 fseq ++ be 2 reader ++ FactCodec.pat 64 k ++ FactCodec.pat 64 (k + 1)

def vEs : List Bytes := [vE 7 9 1 10, vE 3 4 1 20, vE 7 5 1 30, vE 7 9 2 40]

#guard (sort vEs).map eSrc == [3, 7, 7, 7] && (sort vEs).map eFseq == [4, 5, 9, 9]
#guard [vEs.reverse, [vEs[2]!, vEs[0]!, vEs[3]!, vEs[1]!], [vEs[3]!, vEs[2]!, vEs[1]!, vEs[0]!]].all
  (rs FactFrame.sha · == rs FactFrame.sha vEs)
#guard rs FactFrame.sha (vEs.take 3) != rs FactFrame.sha vEs && rs FactFrame.sha [] == FactFrame.sha (domain "REFSET")

end BlindLedger.Gate.RefSet
