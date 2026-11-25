import Std.Tactic.BVDecide
import BlindLedger.Gate.Engine3.Layout

/-! The key directory of conformance/ENGINE_V3.md section 4 as running code.  `Layout.lean` is the model (`Dirs`, each
    segment a `Flat.Store.Dir`); here a segment keeps its slots as 4 little-endian bytes each in one `ByteArray`
    (4 bytes a slot, not a boxed word) and an insert writes into that array in place.

    The array has 8 bytes after the slots: two scratch slots through which the kick loop hands back the slot that
    overflowed, so an insert allocates nothing.  An insert that is refused leaves the segment as it was: while the
    stash is full the kicks are logged and undone.  With room in the stash an insert cannot be refused, so nothing is
    logged.

    Each function has an equality theorem with the model (`toDir`, `toDirs`); those are stated here and not yet
    proved. -/

namespace BlindLedger.Gate.Engine3

open Flat.Store

/-! ## One segment -/

/-- A segment: `nb` buckets of 4 slots, its salt, the slots held (table and stash), the slots as little-endian
    `UInt32`s followed by two scratch slots, and the stash. -/
structure FDir where
  nb : Nat
  salt : UInt64
  cnt : Nat
  t : ByteArray
  stash : List (UInt32 × Nat)
  /-- Whether the last insert was kept (false: refused `full`, nothing changed). -/
  ok : Bool

/-- Slot `j`: 4 bytes, little endian.  Compiled as one 32-bit load (the host is little endian; the slots are RAM only,
    never written to a file); the body is the meaning.  Out of range reads 0. -/
@[extern c inline "(lean_is_scalar(#2) && 4 * lean_unbox(#2) + 4 <= lean_sarray_size(#1) ? *(uint32_t*)(lean_sarray_cptr(#1) + 4 * lean_unbox(#2)) : (uint32_t)0)"]
def slotAt (t : @& ByteArray) (j : @& Nat) : UInt32 :=
  let o := 4 * j
  (t.get! o).toUInt32 ||| ((t.get! (o + 1)).toUInt32 <<< 8) ||| ((t.get! (o + 2)).toUInt32 <<< 16) |||
    ((t.get! (o + 3)).toUInt32 <<< 24)

/-- Slot `j` set, in place when the array is not shared.  Out of range changes nothing. -/
@[extern c inline "({ lean_object* a_ = #1; if (!lean_is_exclusive(a_)) a_ = lean_copy_sarray(a_, lean_sarray_capacity(a_)); if (lean_is_scalar(#2) && 4 * lean_unbox(#2) + 4 <= lean_sarray_size(a_)) *(uint32_t*)(lean_sarray_cptr(a_) + 4 * lean_unbox(#2)) = #3; a_; })"]
def slotSet (t : ByteArray) (j : @& Nat) (v : UInt32) : ByteArray :=
  let o := 4 * j
  (((t.set! o v.toUInt8).set! (o + 1) (v >>> 8).toUInt8).set! (o + 2) (v >>> 16).toUInt8).set! (o + 3)
    (v >>> 24).toUInt8

/-- `n` zero bytes. -/
def zeroBytes (n : Nat) : ByteArray := Id.run do
  let mut a := ByteArray.emptyWithCapacity n
  for _ in [0:n] do a := a.push 0
  return a

def FDir.empty (nb : Nat) (salt : UInt64) : FDir := ⟨nb, salt, 0, zeroBytes (16 * nb + 8), [], true⟩

/-- A cheap stand-in while a segment is taken out of its array. -/
def FDir.dummy : FDir := ⟨1, 0, 0, ByteArray.empty, [], true⟩

instance : Inhabited FDir := ⟨FDir.dummy⟩

/-- The shape the functions keep. -/
def FDir.Wf (f : FDir) : Prop :=
  0 < f.nb ∧ f.nb < segMax ∧ f.t.size = 16 * f.nb + 8 ∧ f.stash.length ≤ stashCap ∧
    slotAt f.t (4 * f.nb) = 0 ∧ slotAt f.t (4 * f.nb + 1) = 0

/-- `fpOf` on the machine word. -/
@[inline] def fpU (h : UInt64) : Nat := (h >>> 50).toNat % 16383 + 1

/-- `h.toNat % nb`. -/
@[inline] def bktU (h : UInt64) (nb : Nat) : Nat := (h % nb.toUInt64).toNat

/-- `slot`. -/
@[inline] def slotU (fp c : Nat) : UInt32 := UInt32.ofNat (fp * 262144 + c)

/-- `alt`. -/
@[inline] def altU (nb f b : Nat) : Nat := (f * 2654435761 + (nb - b)) % nb

/-- The first empty position of the 8 of a bucket pair, in the model's order; `4 * nb` when there is none.  Compiled as
    a loop over 32-bit loads (a slot out of range reads 0, as `slotAt` does). -/
@[extern c inline "({ const uint32_t* p_ = (const uint32_t*)lean_sarray_cptr(#1); size_t n_ = lean_sarray_size(#1) / 4; size_t a_ = 4 * lean_unbox(#3), c_ = 4 * lean_unbox(#4), r_ = 4 * lean_unbox(#2); int i_; for (i_ = 0; i_ < 4; i_++) if (a_ + i_ >= n_ || p_[a_ + i_] == 0) { r_ = a_ + i_; goto done_; } for (i_ = 0; i_ < 4; i_++) if (c_ + i_ >= n_ || p_[c_ + i_] == 0) { r_ = c_ + i_; goto done_; } done_: lean_box(r_); })"]
def firstEmpty (t : @& ByteArray) (nb b b2 : @& Nat) : Nat :=
  let a := 4 * b
  let c := 4 * b2
  if slotAt t a == 0 then a else if slotAt t (a + 1) == 0 then a + 1 else if slotAt t (a + 2) == 0 then a + 2
  else if slotAt t (a + 3) == 0 then a + 3 else if slotAt t c == 0 then c else if slotAt t (c + 1) == 0 then c + 1
  else if slotAt t (c + 2) == 0 then c + 2 else if slotAt t (c + 3) == 0 then c + 3 else 4 * nb

/-- `Dir.put` over the bytes, for a stash with room.  The slot left over for the stash, if any, is in scratch slot 0
    (the slot) and 1 (its bucket); both stay zero when every slot is placed. -/
def putF (nb : Nat) (t : ByteArray) (v : UInt32) (b n : Nat) : ByteArray :=
  let b2 := altU nb (v >>> 18).toNat b
  let j := firstEmpty t nb b b2
  if j < 4 * nb then slotSet t j v else
  match n with
  | 0 => slotSet (slotSet t (4 * nb) v) (4 * nb + 1) b.toUInt32
  | n + 1 =>
    let p := 4 * b2 + n % 4
    let w := slotAt t p
    putF nb (slotSet t p v) w b2 n

/-- The same for a full stash: also the slot left over (`0` when placed; else its bucket in the high word and the slot
    in the low one) and the kicks, each as (position, slot there before). -/
def putL (nb : Nat) (t : ByteArray) (v : UInt32) (b n : Nat) (log : Array UInt64) :
    ByteArray × UInt64 × Array UInt64 :=
  let b2 := altU nb (v >>> 18).toNat b
  let j := firstEmpty t nb b b2
  if j < 4 * nb then (slotSet t j v, 0, log) else
  match n with
  | 0 => (t, (b.toUInt64 <<< 32) ||| v.toUInt64, log)
  | n + 1 =>
    let p := 4 * b2 + n % 4
    let w := slotAt t p
    putL nb (slotSet t p v) w b2 n (log.push ((p.toUInt64 <<< 32) ||| w.toUInt64))

/-- The kicks undone, newest first. -/
def undoKicks (t : ByteArray) (log : Array UInt64) : ByteArray :=
  log.foldr (fun (e : UInt64) (t : ByteArray) => slotSet t (e >>> 32).toNat e.toUInt32) t

/-- A slot for chunk `c` under directory hash `h` (before the salt).  When the model refuses `full` the segment is as
    it was, which shows as `cnt` unchanged. -/
def FDir.insert (f : FDir) (h : UInt64) (c : Nat) : FDir :=
  match f with
  | ⟨nb, salt, cnt, t, stash, _⟩ =>
    let p := h ^^^ salt
    let v := slotU (fpU p) c
    if stash.length < stashCap then
      let t := putF nb t v (bktU p nb) maxKicks
      let l := slotAt t (4 * nb)
      if l == 0 then ⟨nb, salt, cnt + 1, t, stash, true⟩ else
      let lb := (slotAt t (4 * nb + 1)).toNat
      ⟨nb, salt, cnt + 1, slotSet (slotSet t (4 * nb) 0) (4 * nb + 1) 0,
        (l, min lb (altU nb (l >>> 18).toNat lb)) :: stash, true⟩
    else
      match putL nb t v (bktU p nb) maxKicks #[] with
      | (t, 0, _) => ⟨nb, salt, cnt + 1, t, stash, true⟩
      | (t, _, log) => ⟨nb, salt, cnt, undoKicks t log, stash, false⟩

/-- `Dirs.erase`'s step on one segment: the slot for chunk `c` under `h` leaves; nothing changes when it is absent. -/
def FDir.erase (f : FDir) (h : UInt64) (c : Nat) : FDir :=
  match f with
  | ⟨nb, salt, cnt, t, stash, ok⟩ =>
    let p := h ^^^ salt
    let v := slotU (fpU p) c
    let b := bktU p nb
    let f := (v >>> 18).toNat
    let pos (i : Nat) : Nat := if i < 4 then 4 * b + i else 4 * altU nb f b + (i - 4)
    match (List.range 8).find? fun i => slotAt t (pos i) == v with
    | some i => ⟨nb, salt, cnt - 1, slotSet t (pos i) 0, stash, ok⟩
    | none =>
      let lab := (v, min b (altU nb f b))
      if stash.contains lab then ⟨nb, salt, cnt - 1, t, stash.erase lab, ok⟩ else ⟨nb, salt, cnt, t, stash, ok⟩

/-- `Dir.drop`: chunk `c`'s slots leave. -/
def FDir.drop (f : FDir) (c : Nat) : FDir :=
  match f with
  | ⟨nb, salt, _, t, stash, ok⟩ => Id.run do
    let mut t := t
    let mut n := 0
    for j in [0:4 * nb] do
      let v := slotAt t j
      if v != 0 then
        if v.toNat % 262144 == c then t := slotSet t j 0 else n := n + 1
    let st := stash.filter (·.1.toNat % 262144 != c)
    return ⟨nb, salt, n + st.length, t, st, ok⟩

/-- `Dir.cands` as an array: chunks of the candidate slots whose fingerprint matches. -/
def FDir.cands (f : FDir) (h : UInt64) : Array Nat := Id.run do
  let p := h ^^^ f.salt
  let fp := fpU p
  let b := bktU p f.nb
  let b2 := altU f.nb fp b
  let mut o : Array Nat := #[]
  for i in [0:8] do
    let v := slotAt f.t (if i < 4 then 4 * b + i else 4 * b2 + (i - 4))
    if v != 0 && (v >>> 18).toNat == fp then o := o.push (v.toNat % 262144)
  let lab := min b b2
  for x in f.stash do
    if x.2 == lab && (x.1 >>> 18).toNat == fp then o := o.push (x.1.toNat % 262144)
  return o

/-- A segment of `nb` buckets and salt `σ` holding every (chunk, directory hash) of `items` in order; none when an
    insert is refused. -/
def FDir.rebuild (nb : Nat) (σ : UInt64) (items : Array (Nat × UInt64)) : Option FDir :=
  items.foldl (fun (a : Option FDir) x => match a with
    | none => none
    | some d => let d' := d.insert x.2 x.1; if d'.cnt == d.cnt then none else some d') (some (FDir.empty nb σ))

/-! ## The 64 segments -/

/-- The 64 segments. -/
abbrev FDirs := Array FDir

@[inline] def segU (h : UInt64) : Nat := ((h >>> 44) &&& 63).toNat

/-- `Dirs.insert`, the segment taken out of its array while it is written.  Whether it was kept is the segment's
    `ok` (`FDirs.kept`). -/
def FDirs.insert (ds : FDirs) (h : UInt64) (c : Nat) : FDirs :=
  ds.modify (segU h) fun d => d.insert h c

/-- Ask the cache for the two buckets an insert or lookup of `h` will read; returns 0.  A caller that inserts many
    hashes warms the one it will insert a few steps ahead and uses the result, so the loads overlap. -/
@[extern c inline "(__builtin_prefetch(lean_sarray_cptr(#1) + 16 * lean_unbox(#2)), __builtin_prefetch(lean_sarray_cptr(#1) + 16 * lean_unbox(#3)), (uint32_t)0)"]
def prefetch2 (t : @& ByteArray) (b b2 : @& Nat) : UInt32 := 0

def FDirs.warm (ds : FDirs) (h : UInt64) : UInt32 :=
  let d : FDir := ds[segU h]!
  let p := h ^^^ d.salt
  let b := bktU p d.nb
  prefetch2 d.t b (altU d.nb (fpU p) b)

def FDirs.kept (ds : FDirs) (h : UInt64) : Bool := ds[segU h]!.ok

def FDirs.erase (ds : FDirs) (h : UInt64) (c : Nat) : FDirs :=
  ds.modify (segU h) fun d => d.erase h c

def FDirs.drop (ds : FDirs) (c : Nat) : FDirs := ds.map (·.drop c)

def FDirs.cands (ds : FDirs) (h : UInt64) : Array Nat := (ds[segU h]!).cands h

/-! ## Slots over bytes -/

theorem fd_get! (d : ByteArray) (i : Nat) : d.get! i = d[i]! := by
  by_cases h : i < d.size
  · rw [getElem!_pos d i h]
    show d.data[i]! = _
    rw [getElem!_pos d.data i h]
    rfl
  · rw [getElem!_neg d i h]
    show d.data[i]! = _
    rw [getElem!_neg d.data i h]

theorem slotSet_size (t : ByteArray) (j : Nat) (v : UInt32) : (slotSet t j v).size = t.size := by
  simp [slotSet]

theorem slotSet_bytes (t : ByteArray) (j : Nat) (v : UInt32) (h : 4 * j + 3 < t.size) :
    (slotSet t j v)[4 * j]! = v.toUInt8 ∧ (slotSet t j v)[4 * j + 1]! = (v >>> 8).toUInt8 ∧
    (slotSet t j v)[4 * j + 2]! = (v >>> 16).toUInt8 ∧ (slotSet t j v)[4 * j + 3]! = (v >>> 24).toUInt8 := by
  have h0 : 4 * j < t.size := by omega
  have h1 : 4 * j + 1 < t.size := by omega
  have h2 : 4 * j + 2 < t.size := by omega
  refine ⟨?_, ?_, ?_, ?_⟩ <;> simp [slotSet, ByteArray.getElem!_set!, h, h0, h1, h2]

theorem slotSet_other (t : ByteArray) (j : Nat) (v : UInt32) (i : Nat) (hi : i < 4 * j ∨ 4 * j + 4 ≤ i) :
    (slotSet t j v)[i]! = t[i]! := by
  unfold slotSet
  have a0 : 4 * j ≠ i := by omega
  have a1 : 4 * j + 1 ≠ i := by omega
  have a2 : 4 * j + 2 ≠ i := by omega
  have a3 : 4 * j + 3 ≠ i := by omega
  rw [ByteArray.getElem!_set!_ne _ _ _ _ a3, ByteArray.getElem!_set!_ne _ _ _ _ a2,
    ByteArray.getElem!_set!_ne _ _ _ _ a1, ByteArray.getElem!_set!_ne _ _ _ _ a0]

theorem slotAt_eq' (t : ByteArray) (j : Nat) :
    slotAt t j = t[4 * j]!.toUInt32 ||| (t[4 * j + 1]!.toUInt32 <<< 8) ||| (t[4 * j + 2]!.toUInt32 <<< 16) |||
      (t[4 * j + 3]!.toUInt32 <<< 24) := by
  simp only [slotAt, fd_get!]

theorem slotAt_slotSet (t : ByteArray) (j : Nat) (v : UInt32) (h : 4 * j + 3 < t.size) (k : Nat) :
    slotAt (slotSet t j v) k = if k = j then v else slotAt t k := by
  rw [slotAt_eq']
  by_cases hk : k = j
  · subst hk
    obtain ⟨b0, b1, b2, b3⟩ := slotSet_bytes t k v h
    rw [if_pos rfl, b0, b1, b2, b3]
    bv_decide
  · rw [if_neg hk, slotAt_eq', slotSet_other t j v _ (by omega), slotSet_other t j v _ (by omega),
      slotSet_other t j v _ (by omega), slotSet_other t j v _ (by omega)]

theorem find_congr {α : Type} (l : List α) (p q : α → Bool) (h : ∀ x ∈ l, p x = q x) : l.find? p = l.find? q := by
  induction l with
  | nil => rfl
  | cons x xs ih =>
    simp only [List.find?_cons]
    rw [h x (by simp), ih (fun y hy => h y (by simp [hy]))]

theorem altU_eq (nb f b : Nat) : altU nb f b = alt nb f b := rfl

theorem alt_lt (nb f b : Nat) (h : 0 < nb) : alt nb f b < nb := Nat.mod_lt _ h

theorem idxs_eq (nb f b : Nat) :
    Flat.Store.idxs nb f b = (List.range 8).map (fun i => if i < 4 then 4 * b + i else 4 * Flat.Store.alt nb f b + (i - 4)) := by
  unfold Flat.Store.idxs
  have e : List.range 8 = [0, 1, 2, 3, 4, 5, 6, 7] := rfl
  have e4 : List.range 4 = [0, 1, 2, 3] := rfl
  rw [e, e4]
  simp only [List.map_cons, List.map_nil, List.cons_append, List.nil_append]
  rfl

/-! ## Equality with the model (stated, not yet proved) -/

theorem segU_eq (h : UInt64) : segU h = segOf h := by
  unfold segU segOf segN
  rw [UInt64.toNat_and, UInt64.toNat_shiftRight]
  have h63 : (63 : UInt64).toNat = 2 ^ 6 - 1 := by decide
  have h44 : (44 : UInt64).toNat % 64 = 44 := by decide
  rw [h63, h44, Nat.and_two_pow_sub_one_eq_mod, Nat.shiftRight_eq_div_pow]

theorem fpU_eq (p : UInt64) : fpU p = fpOf p := by
  unfold fpU fpOf
  rw [UInt64.toNat_shiftRight]
  have h50 : (50 : UInt64).toNat % 64 = 50 := by decide
  rw [h50, Nat.shiftRight_eq_div_pow]
  omega

theorem segMax_lt : segMax < 2 ^ 64 := by unfold segMax; decide

theorem bktU_eq (p : UInt64) (nb : Nat) (h : nb < 2 ^ 64) : bktU p nb = p.toNat % nb := by
  unfold bktU
  have h2 : nb.toUInt64.toNat = nb := by
    first | simp [Nat.toUInt64, Nat.mod_eq_of_lt h] | exact UInt64.toNat_ofNat_of_lt' h
  rw [UInt64.toNat_mod, h2]

theorem fpv_eq (v : UInt32) : (v >>> 18).toNat = fpv v := by
  unfold fpv cBits
  rw [UInt32.toNat_shiftRight]
  have h18 : (18 : UInt32).toNat % 32 = 18 := by decide
  rw [h18, Nat.shiftRight_eq_div_pow]

theorem slotU_eq (p : UInt64) (c : Nat) : slotU (fpU p) c = slot (fpOf p) c := by
  unfold slotU slot cBits
  rw [fpU_eq]

theorem firstEmpty_q (t : ByteArray) (nb b b2 : Nat) :
    firstEmpty t nb b b2 =
      match [4*b, 4*b+1, 4*b+2, 4*b+3, 4*b2, 4*b2+1, 4*b2+2, 4*b2+3].find? (fun j => slotAt t j == 0) with
      | some j => j
      | none => 4 * nb := by
  unfold firstEmpty
  simp only [List.find?_cons, List.find?_nil]
  generalize (slotAt t (4*b) == 0) = x0
  generalize (slotAt t (4*b+1) == 0) = x1
  generalize (slotAt t (4*b+2) == 0) = x2
  generalize (slotAt t (4*b+3) == 0) = x3
  generalize (slotAt t (4*b2) == 0) = x4
  generalize (slotAt t (4*b2+1) == 0) = x5
  generalize (slotAt t (4*b2+2) == 0) = x6
  generalize (slotAt t (4*b2+3) == 0) = x7
  cases x0 <;> cases x1 <;> cases x2 <;> cases x3 <;> cases x4 <;> cases x5 <;> cases x6 <;> cases x7 <;> rfl

theorem idxs_list (nb fp b : Nat) :
    idxs nb fp b = [4*b+0, 4*b+1, 4*b+2, 4*b+3, 4 * alt nb fp b + 0, 4 * alt nb fp b + 1, 4 * alt nb fp b + 2, 4 * alt nb fp b + 3] := by
  rw [idxs_eq]
  generalize alt nb fp b = a
  have e : List.range 8 = [0, 1, 2, 3, 4, 5, 6, 7] := rfl
  rw [e]
  rfl

theorem firstEmpty_none (t : ByteArray) (nb b b2 : Nat) (hb : b < nb) (hb2 : b2 < nb)
    (h : ¬ firstEmpty t nb b b2 < 4 * nb) : ∀ x, x < 4 → slotAt t (4 * b2 + x) ≠ 0 := by
  rw [firstEmpty_q] at h
  generalize hq : [4*b, 4*b+1, 4*b+2, 4*b+3, 4*b2, 4*b2+1, 4*b2+2, 4*b2+3].find? (fun j => slotAt t j == 0) = r at h
  cases r with
  | some j =>
    have hm := List.mem_of_find?_eq_some hq
    simp only [List.mem_cons, List.not_mem_nil, or_false] at hm
    exfalso; apply h; simp only; omega
  | none =>
    intro x hx
    have := List.find?_eq_none.mp hq (4 * b2 + x) (by simp only [List.mem_cons, List.not_mem_nil, or_false]; omega)
    intro h0
    apply this
    simp [h0]

theorem putF_found_eq (n : Nat) (t : ByteArray) (v : UInt32) (nb b : Nat)
    (hj : firstEmpty t nb b (alt nb (fpv v) b) < 4 * nb) :
    putF nb t v b n = slotSet t (firstEmpty t nb b (alt nb (fpv v) b)) v := by
  unfold putF
  dsimp only
  rw [fpv_eq, altU_eq, if_pos hj]

theorem putF_zero_eq (t : ByteArray) (v : UInt32) (nb b : Nat)
    (hj : ¬ firstEmpty t nb b (alt nb (fpv v) b) < 4 * nb) :
    putF nb t v b 0 = slotSet (slotSet t (4 * nb) v) (4 * nb + 1) b.toUInt32 := by
  unfold putF
  dsimp only
  rw [fpv_eq, altU_eq, if_neg hj]

theorem putF_succ_eq (n : Nat) (t : ByteArray) (v : UInt32) (nb b : Nat)
    (hj : ¬ firstEmpty t nb b (alt nb (fpv v) b) < 4 * nb) :
    putF nb t v b (n + 1) = putF nb (slotSet t (4 * alt nb (fpv v) b + n % 4) v) (slotAt t (4 * alt nb (fpv v) b + n % 4))
      (alt nb (fpv v) b) n := by
  conv =>
    lhs
    unfold putF
    dsimp only
    rw [fpv_eq, altU_eq, if_neg hj]

/-! ## the full stash -/

theorem slotSet_twice (t : ByteArray) (p : Nat) (v : UInt32) (h : 4 * p + 3 < t.size) (k : Nat) :
    slotAt (slotSet (slotSet t p v) p (slotAt t p)) k = slotAt t k := by
  have h' : 4 * p + 3 < (slotSet t p v).size := by rw [slotSet_size]; exact h
  rw [slotAt_slotSet _ _ _ h', slotAt_slotSet _ _ _ h]
  by_cases hk : k = p
  · rw [if_pos hk, hk]
  · rw [if_neg hk, if_neg hk]

theorem ent_hi (P : UInt64) (w : UInt32) (h : P < 4294967296) : ((P <<< 32) ||| w.toUInt64) >>> 32 = P := by
  bv_decide

theorem ent_lo (P : UInt64) (w : UInt32) : ((P <<< 32) ||| w.toUInt64).toUInt32 = w := by
  bv_decide

theorem ent_pos (p : Nat) (w : UInt32) (hp : p < 4294967296) :
    (((p.toUInt64 <<< 32) ||| w.toUInt64) >>> 32).toNat = p := by
  have hP : p.toUInt64 < 4294967296 := by
    rw [UInt64.lt_iff_toNat_lt]
    have hs : UInt64.size = 18446744073709551616 := rfl
    have : p.toUInt64.toNat = p := UInt64.toNat_ofNat_of_lt' (by omega)
    rw [this]; exact hp
  rw [ent_hi _ _ hP]
  have hs : UInt64.size = 18446744073709551616 := rfl
  exact UInt64.toNat_ofNat_of_lt' (by omega)

theorem putL_found_eq (n : Nat) (t : ByteArray) (v : UInt32) (nb b : Nat) (log : Array UInt64)
    (hj : firstEmpty t nb b (alt nb (fpv v) b) < 4 * nb) :
    putL nb t v b n log = (slotSet t (firstEmpty t nb b (alt nb (fpv v) b)) v, 0, log) := by
  unfold putL
  dsimp only
  rw [fpv_eq, altU_eq, if_pos hj]

theorem putL_zero_eq (t : ByteArray) (v : UInt32) (nb b : Nat) (log : Array UInt64)
    (hj : ¬ firstEmpty t nb b (alt nb (fpv v) b) < 4 * nb) :
    putL nb t v b 0 log = (t, (b.toUInt64 <<< 32) ||| v.toUInt64, log) := by
  unfold putL
  dsimp only
  rw [fpv_eq, altU_eq, if_neg hj]

theorem putL_succ_eq (n : Nat) (t : ByteArray) (v : UInt32) (nb b : Nat) (log : Array UInt64)
    (hj : ¬ firstEmpty t nb b (alt nb (fpv v) b) < 4 * nb) :
    putL nb t v b (n + 1) log = putL nb (slotSet t (4 * alt nb (fpv v) b + n % 4) v)
      (slotAt t (4 * alt nb (fpv v) b + n % 4)) (alt nb (fpv v) b) n
      (log.push (((4 * alt nb (fpv v) b + n % 4).toUInt64 <<< 32) ||| (slotAt t (4 * alt nb (fpv v) b + n % 4)).toUInt64)) := by
  conv =>
    lhs
    unfold putL
    dsimp only
    rw [fpv_eq, altU_eq, if_neg hj]

theorem forIn_id_yield {α β : Type} (l : List α) (g : α → β → β) (init : β) (f : α → β → Id (ForInStep β))
    (hf : ∀ a b, f a b = ForInStep.yield (g a b)) :
    forIn l init f = l.foldl (fun b a => g a b) init := by
  induction l generalizing init with
  | nil => rfl
  | cons x xs ih =>
    simp only [List.forIn_cons, hf, List.foldl_cons]
    exact ih _

theorem dropFold (c : Nat) : ∀ (l : List Nat) (s : ByteArray × Nat), l.Nodup → (∀ j ∈ l, 4 * j + 3 < s.1.size) →
    (l.foldl (fun b a => if slotAt b.1 a != 0 then (if (slotAt b.1 a).toNat % 262144 == c then (slotSet b.1 a 0, b.2) else (b.1, b.2 + 1)) else (b.1, b.2)) s).1.size = s.1.size ∧
    ∀ i, slotAt (l.foldl (fun b a => if slotAt b.1 a != 0 then (if (slotAt b.1 a).toNat % 262144 == c then (slotSet b.1 a 0, b.2) else (b.1, b.2 + 1)) else (b.1, b.2)) s).1 i =
      (if i ∈ l ∧ slotAt s.1 i ≠ 0 ∧ (slotAt s.1 i).toNat % 262144 = c then 0 else slotAt s.1 i) := by
  intro l
  induction l with
  | nil => intro s _ _; simp
  | cons j l ih =>
    intro s hnd hb
    simp only [List.foldl_cons]
    have hj := hb j (by simp)
    have hnd' := List.nodup_cons.mp hnd
    have key : ∀ s' : ByteArray × Nat, s'.1.size = s.1.size →
        (∀ i, slotAt s'.1 i = if i = j ∧ (slotAt s.1 i ≠ 0 ∧ (slotAt s.1 i).toNat % 262144 = c) then 0 else slotAt s.1 i) →
        (l.foldl (fun b a => if slotAt b.1 a != 0 then (if (slotAt b.1 a).toNat % 262144 == c then (slotSet b.1 a 0, b.2) else (b.1, b.2 + 1)) else (b.1, b.2)) s').1.size = s.1.size ∧
        ∀ i, slotAt (l.foldl (fun b a => if slotAt b.1 a != 0 then (if (slotAt b.1 a).toNat % 262144 == c then (slotSet b.1 a 0, b.2) else (b.1, b.2 + 1)) else (b.1, b.2)) s').1 i =
          (if i ∈ j :: l ∧ slotAt s.1 i ≠ 0 ∧ (slotAt s.1 i).toNat % 262144 = c then 0 else slotAt s.1 i) := by
      intro s' hs hat
      obtain ⟨ih1, ih2⟩ := ih s' hnd'.2 (by intro k hk; rw [hs]; exact hb k (by simp [hk]))
      refine ⟨by rw [ih1, hs], fun i => ?_⟩
      rw [ih2 i, hat i]
      have hjl := hnd'.1
      by_cases hi : i ∈ l <;> by_cases hij : i = j <;>
        by_cases hc : (slotAt s.1 i ≠ 0 ∧ (slotAt s.1 i).toNat % 262144 = c) <;>
        simp_all
    by_cases h0 : slotAt s.1 j = 0
    · have e : (slotAt s.1 j != 0) = false := by simp [h0]
      simp only [e]
      refine key (s.1, s.2) rfl (fun i => ?_)
      by_cases hij : i = j
      · subst hij; simp [h0]
      · simp [hij]
    · by_cases h1 : (slotAt s.1 j).toNat % 262144 = c
      · have e : (slotAt s.1 j != 0) = true := by simp [h0]
        have e1 : ((slotAt s.1 j).toNat % 262144 == c) = true := by simp [h1]
        simp only [e, e1, if_true]
        refine key (slotSet s.1 j 0, s.2) (slotSet_size _ _ _) (fun i => ?_)
        rw [slotAt_slotSet _ _ _ hj]
        by_cases hij : i = j
        · subst hij; simp [h0, h1]
        · simp [hij]
      · have e : (slotAt s.1 j != 0) = true := by simp [h0]
        have e1 : ((slotAt s.1 j).toNat % 262144 == c) = false := by simp [h1]
        simp only [e, e1, if_true, Bool.false_eq_true, if_false]
        refine key (s.1, s.2 + 1) rfl (fun i => ?_)
        by_cases hij : i = j
        · subst hij; simp [h1]
        · simp [hij]

theorem foldl_push {α : Type} (l : List α) (P : α → Bool) (g : α → Nat) (o : Array Nat) :
    (l.foldl (fun o a => if P a = true then o.push (g a) else o) o).toList =
      o.toList ++ l.filterMap (fun a => if P a = true then some (g a) else none) := by
  induction l generalizing o with
  | nil => simp
  | cons x xs ih =>
    simp only [List.foldl_cons, List.filterMap_cons]
    by_cases hx : P x = true
    · simp only [hx, if_true, ih, Array.toList_push, List.append_assoc, List.singleton_append]
    · simp [hx, ih]

theorem fm_cong {α β : Type} (l : List α) (f g : α → Option β) (h : ∀ x ∈ l, f x = g x) :
    l.filterMap f = l.filterMap g := by
  induction l with
  | nil => rfl
  | cons x xs ih =>
    simp only [List.filterMap_cons]
    rw [h x (by simp), ih (fun y hy => h y (by simp [hy]))]

theorem fpOf_pos (h : UInt64) : 1 ≤ fpOf h := by
  unfold fpOf; omega

theorem forIn_push_id {α : Type} (l : List α) (P : α → Bool) (g : α → Nat) (o : Array Nat)
    (f : α → Array Nat → Id (ForInStep (Array Nat)))
    (hf : ∀ a b, f a b = if P a = true then ForInStep.yield (b.push (g a)) else ForInStep.yield b) :
    forIn l o f = l.foldl (fun b a => if P a = true then b.push (g a) else b) o := by
  induction l generalizing o with
  | nil => rfl
  | cons x xs ih =>
    rw [List.forIn_cons, hf, List.foldl_cons]
    by_cases hx : P x = true
    · simp only [hx, if_true]; exact ih _
    · simp only [hx, Bool.false_eq_true, if_false]; exact ih _

theorem cand_pt (v : UInt32) (fp : Nat) (hfp : 1 ≤ fp) :
    (if (v != 0 && (v >>> 18).toNat == fp) = true then some (v.toNat % 262144) else none) =
      (if fpv v = fp then some (v.toNat % 2 ^ cBits) else none) := by
  have c18 : (2 : Nat) ^ cBits = 262144 := by decide
  rw [fpv_eq, c18]
  by_cases hv : v = 0
  · subst hv
    have h0 : fpv 0 = 0 := by simp [fpv]
    have h1 : ¬ (0 : Nat) = fp := by omega
    simp [h0, h1]
  · by_cases e : fpv v = fp
    · simp [hv, e]
    · simp [hv, e]

theorem FDir.insert_salt (f : FDir) (h : UInt64) (c : Nat) : (f.insert h c).salt = f.salt := by
  rcases f with ⟨nb, salt, cnt, t, stash, ok⟩
  unfold FDir.insert
  dsimp only
  split <;> (try split) <;> (try split) <;> rfl

theorem modify_salt (a : FDirs) (i : Nat) (f : FDir → FDir) (hf : ∀ x, (f x).salt = x.salt) :
    (a.modify i f).map (fun x => x.salt) = a.map (fun x => x.salt) := by
  apply Array.ext
  · simp
  · intro j h1 h2
    simp only [Array.getElem_map, Array.getElem_modify]
    by_cases hj : i = j
    · subst hj; simp [hf]
    · simp [hj]

theorem push_zeros (l : List Nat) : ∀ (a : ByteArray), (∀ i : Nat, a[i]! = 0) →
    (l.foldl (fun (a : ByteArray) _ => a.push 0) a).size = a.size + l.length ∧
    ∀ i : Nat, (l.foldl (fun (a : ByteArray) _ => a.push 0) a)[i]! = 0 := by
  induction l with
  | nil => intro a h; exact ⟨rfl, h⟩
  | cons x l ih =>
    intro a h
    have h' : ∀ i : Nat, (a.push 0)[i]! = 0 := by
      intro i
      by_cases hi : i < a.size
      · rw [ByteArray.getElem!_push_lt _ _ _ hi]; exact h i
      · by_cases he : i = a.size
        · subst he; exact ByteArray.getElem!_push_eq a 0
        · rw [ByteArray.getElem!_push]
          simp [hi, he]
          rfl
    obtain ⟨s, z⟩ := ih (a.push 0) h'
    simp only [List.foldl_cons, List.length_cons]
    refine ⟨by rw [s, ByteArray.size_push]; omega, z⟩

theorem forIn_push_zero (l : List Nat) : ∀ (a : ByteArray),
    forIn l a (fun _ (a : ByteArray) => (pure (ForInStep.yield (a.push 0)) : Id (ForInStep ByteArray))) =
      l.foldl (fun (a : ByteArray) _ => a.push 0) a := by
  induction l with
  | nil => intro a; rfl
  | cons x l ih => intro a; rw [List.forIn_cons]; exact ih _

theorem zeroBytes_spec (n : Nat) : (zeroBytes n).size = n ∧ ∀ i : Nat, (zeroBytes n)[i]! = 0 := by
  unfold zeroBytes
  simp only [Id.run, Std.Legacy.Range.forIn_eq_forIn_range', bind_pure]
  have hr : [:n].size = n := by simp [Std.Legacy.Range.size]
  rw [hr, forIn_push_zero]
  have hz : (ByteArray.emptyWithCapacity n).size = 0 := rfl
  have h0 : ∀ i : Nat, (ByteArray.emptyWithCapacity n)[i]! = 0 := by
    intro i
    rw [getElem!_neg _ _ (by rw [hz]; omega)]
    rfl
  obtain ⟨s, z⟩ := push_zeros (List.range' 0 n) _ h0
  refine ⟨?_, z⟩
  rw [s, hz]
  simp

theorem zero_slotAt (n k : Nat) : slotAt (zeroBytes n) k = 0 := by
  obtain ⟨_, z⟩ := zeroBytes_spec n
  rw [slotAt_eq', z, z, z, z]
  rfl

theorem rebuild_none (σ : UInt64) (l : List (Nat × UInt64)) :
    l.foldl (fun (a : Option FDir) x => match a with
      | none => none
      | some d => let d' := d.insert x.2 x.1; if d'.cnt == d.cnt then none else some d') none = none := by
  induction l with
  | nil => rfl
  | cons x l ih => exact ih

end BlindLedger.Gate.Engine3
