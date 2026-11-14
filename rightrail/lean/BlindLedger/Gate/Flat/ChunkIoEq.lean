import BlindLedger.Gate.Flat.ChunkIo

/-! The chunk path's byte-array code, stated equal to the model functions it replaces: the number writer, the key bytes,
    the row encoder, the directory candidates and the dead-bit kill.  Each statement is the fast function on the same inputs
    as the model function, and the two agree. -/

namespace BlindLedger.Gate.Flat.ChunkIo

open Chunk Store
open BlindLedger.Gate.Rules
open BlindLedger.Gate.OnepIndex (leb)
open Std (HashMap HashSet)

theorem lebS_eq (n : Nat) : ∀ b : ByteArray, (lebS b n).data.toList = b.data.toList ++ leb n := by
  induction n using Nat.strongRecOn with
  | _ n ih =>
    intro b
    rw [lebS, leb]
    by_cases h : n < 128
    · simp [h, ByteArray.data_push]
    · simp only [h, ↓reduceDIte, ↓reduceIte]
      rw [ih (n / 128) (by omega)]
      simp [ByteArray.data_push]

theorem lebK_eq (k : Nat) : ∀ (b : ByteArray) (n : Nat), 128 ^ k ≤ n →
    (lebK k b (n % 128 ^ k)).data.toList ++ leb (n / 128 ^ k) = b.data.toList ++ leb n := by
  induction k with
  | zero => intro b n _; simp [lebK]
  | succ k ih =>
    intro b n hn
    have hp : 128 ^ (k + 1) = 128 * 128 ^ k := by rw [Nat.pow_succ]; omega
    have h128 : 128 ≤ n := by
      have : 1 ≤ 128 ^ k := Nat.one_le_pow _ _ (by omega)
      omega
    have e1 : n % 128 ^ (k + 1) / 128 = n / 128 % 128 ^ k := by
      rw [hp, Nat.mod_mul_right_div_self]
    have e2 : n % 128 ^ (k + 1) % 128 = n % 128 := by
      exact Nat.mod_mod_of_dvd n (by rw [hp]; exact Nat.dvd_mul_right 128 _)
    have e3 : n / 128 / 128 ^ k = n / 128 ^ (k + 1) := by rw [Nat.div_div_eq_div_mul, hp]
    have hk : 128 ^ k ≤ n / 128 := by
      rw [Nat.le_div_iff_mul_le (by omega)]; omega
    simp only [lebK, e1, e2]
    have := ih (b.push (n % 128 + 128).toUInt8) (n / 128) hk
    rw [e3] at this
    rw [this]
    conv => rhs; rw [leb]
    simp [ByteArray.data_push, show ¬ n < 128 by omega]

theorem B56_eq : B56 = 128 ^ 8 := by decide

/-- `lebPush b n` appends exactly `leb n`. -/
theorem lebPush_eq (n : Nat) : ∀ b : ByteArray, (lebPush b n).data.toList = b.data.toList ++ leb n := by
  induction n using Nat.strongRecOn with
  | _ n ih =>
    intro b
    rw [lebPush]
    by_cases h : n < B56
    · simp only [h, ↓reduceIte]; exact lebS_eq n b
    · simp only [h, ↓reduceIte]
      have hl : 128 ^ 8 ≤ n := by rw [← B56_eq]; omega
      rw [ih (n / B56) (by unfold B56 at *; omega), B56_eq]
      have := lebK_eq 8 b n hl
      rw [← this]

theorem pushL_eq (l : List UInt8) : ∀ b : ByteArray, (pushL b l).data.toList = b.data.toList ++ l := by
  induction l with
  | nil => intro b; simp [pushL]
  | cons x l ih => intro b; simp only [pushL, List.foldl_cons] at *; rw [ih]; simp [ByteArray.data_push]

theorem foldl_lebPush_eq (l : List Nat) : ∀ b : ByteArray,
    (l.foldl lebPush b).data.toList = b.data.toList ++ l.flatMap leb := by
  induction l with
  | nil => intro b; simp
  | cons x l ih => intro b; simp only [List.foldl_cons, List.flatMap_cons]; rw [ih, lebPush_eq]; simp

/-- The key bytes built in one buffer are `Store.skey`. -/
theorem skeyB_eq (u : Bool) (k : Key) : (skeyB u k).data.toList = skey u k := by
  unfold skeyB skey encKey
  rw [foldl_lebPush_eq, lebPush_eq]
  simp [ByteArray.data_push]

theorem encBodyB_eq (w : Row) : (encBodyB w).data.toList = encBody w := by
  have hp : ∀ (l : List Posting) (b : ByteArray),
      (l.foldl (fun b p => (enc p.row).foldl lebPush (lebPush b p.seq)) b).data.toList =
        b.data.toList ++ l.flatMap encPosting := by
    intro l
    induction l with
    | nil => intro b; simp
    | cons p l ih =>
      intro b
      simp only [List.foldl_cons, List.flatMap_cons]
      rw [ih, foldl_lebPush_eq, lebPush_eq]
      simp [encPosting, encLine]
  unfold encBodyB encBody
  by_cases ht : w.2.tail = zeroDigest
  · simp only [ht, ↓reduceIte, encTail]
    simp [ByteArray.data_push, hp, pushL_eq, lebPush_eq]
  · simp only [ht, ↓reduceIte, encTail]
    simp [ByteArray.data_push, hp, pushL_eq, lebPush_eq]

theorem encRowB_eq (buf : ByteArray) (w : Row) : (encRowB buf w).data.toList = buf.data.toList ++ encRow w := by
  unfold encRowB encRow
  have hs : (encBodyB w).size = (encBody w).length := by
    rw [← ByteArray.size_data, ← Array.length_toList, encBodyB_eq]
  rw [ByteArray.toList_data_append, lebPush_eq, hs, encBodyB_eq]
  simp

theorem addPos_eq (d : Dir) (f : Nat) (o : Array Nat) (j : Nat) : (addPos d f o j).toList =
    o.toList ++ (((d.t[j]?).toList).filterMap fun v => if fpv v = f then some (v.toNat % 2 ^ cBits) else none) := by
  unfold addPos
  cases d.t[j]? with
  | none => simp
  | some v => by_cases hv : fpv v = f <;> simp [hv]

theorem stashFold_eq (L : List (UInt32 × Nat)) (f c : Nat) : ∀ (o : Array Nat),
    (L.foldl (fun o x => if x.2 = c ∧ fpv x.1 = f then o.push (x.1.toNat % 2 ^ cBits) else o) o).toList =
      o.toList ++ (L.filterMap fun x => if x.2 = c then (if fpv x.1 = f then some (x.1.toNat % 2 ^ cBits) else none) else none) := by
  induction L with
  | nil => intro o; simp
  | cons x L ih =>
    intro o
    simp only [List.foldl_cons, List.filterMap_cons]
    by_cases h1 : x.2 = c <;> by_cases h2 : fpv x.1 = f <;> simp [h1, h2, ih]

theorem addPosFold_eq (d : Dir) (f : Nat) : ∀ (I : List Nat) (o : Array Nat), (I.foldl (addPos d f) o).toList =
    o.toList ++ ((I.filterMap (d.t[·]?)).filterMap fun v => if fpv v = f then some (v.toNat % 2 ^ cBits) else none) := by
  intro I
  induction I with
  | nil => intro o; simp
  | cons j I ih =>
    intro o
    simp only [List.foldl_cons, List.filterMap_cons]
    rw [ih, addPos_eq]
    cases d.t[j]? with
    | none => simp
    | some v => by_cases hv : fpv v = f <;> simp [hv]

theorem range4_eq (b b2 : Nat) : (List.range 4).map (4*b + ·) ++ (List.range 4).map (4*b2 + ·) =
    [4*b, 4*b+1, 4*b+2, 4*b+3, 4*b2, 4*b2+1, 4*b2+2, 4*b2+3] := by
  simp [List.range, List.range.loop]

/-- `candsA` with the bucket numbers and the pair label as plain numbers. -/
def candsG (d : Dir) (f c b b2 : Nat) : Array Nat :=
  d.stash.foldl (fun o x => if x.2 = c ∧ fpv x.1 = f then o.push (x.1.toNat % 2 ^ cBits) else o)
    (addPos d f (addPos d f (addPos d f (addPos d f (addPos d f (addPos d f (addPos d f (addPos d f #[] (4*b))
      (4*b+1)) (4*b+2)) (4*b+3)) (4*b2)) (4*b2+1)) (4*b2+2)) (4*b2+3))

theorem candsG_eq (d : Dir) (f c b b2 : Nat) : (candsG d f c b b2).toList =
    (([4*b, 4*b+1, 4*b+2, 4*b+3, 4*b2, 4*b2+1, 4*b2+2, 4*b2+3].filterMap (d.t[·]?)) ++
      d.stash.filterMap fun x => if x.2 = c then some x.1 else none).filterMap fun v =>
        if fpv v = f then some (v.toNat % 2 ^ cBits) else none := by
  unfold candsG
  rw [stashFold_eq]
  have e : addPos d f (addPos d f (addPos d f (addPos d f (addPos d f (addPos d f (addPos d f (addPos d f #[] (4*b))
      (4*b+1)) (4*b+2)) (4*b+3)) (4*b2)) (4*b2+1)) (4*b2+2)) (4*b2+3) =
      [4*b, 4*b+1, 4*b+2, 4*b+3, 4*b2, 4*b2+1, 4*b2+2, 4*b2+3].foldl (addPos d f) #[] := rfl
  rw [e, addPosFold_eq]
  simp only [List.filterMap_append, List.nil_append]
  congr 1
  rw [List.filterMap_filterMap]
  congr 1
  funext x
  by_cases h1 : x.2 = c <;> simp [h1]

theorem candsA_G (d : Dir) (h : UInt64) :
    candsA d h = candsG d (fpOf h) (cls d.nb (fpOf h) (h.toNat % d.nb)) (h.toNat % d.nb)
      (alt d.nb (fpOf h) (h.toNat % d.nb)) := rfl

theorem cands_G (d : Dir) (h : UInt64) : d.cands h =
    (([4*(h.toNat % d.nb), 4*(h.toNat % d.nb)+1, 4*(h.toNat % d.nb)+2, 4*(h.toNat % d.nb)+3,
      4*(alt d.nb (fpOf h) (h.toNat % d.nb)), 4*(alt d.nb (fpOf h) (h.toNat % d.nb))+1,
      4*(alt d.nb (fpOf h) (h.toNat % d.nb))+2, 4*(alt d.nb (fpOf h) (h.toNat % d.nb))+3].filterMap (d.t[·]?)) ++
      d.stash.filterMap fun x => if x.2 = cls d.nb (fpOf h) (h.toNat % d.nb) then some x.1 else none).filterMap fun v =>
        if fpv v = fpOf h then some (v.toNat % 2 ^ cBits) else none := by
  unfold Dir.cands idxs
  dsimp only
  rw [range4_eq]

/-- The array directory candidates are `Dir.cands`. -/
theorem candsA_eq (d : Dir) (h : UInt64) : (candsA d h).toList = d.cands h := by
  rw [candsA_G, candsG_eq, cands_G]

/-- The in-place kill gives the same set at every chunk as `Store.kill`. -/
theorem killFast_get (d : HashMap Nat (HashSet Nat)) (c i c' : Nat) :
    (killFast d c i).get? c' = (kill d c i).get? c' := by
  unfold killFast kill
  by_cases hc : c = c' <;> simp [Std.HashMap.get?_eq_getElem?, Std.HashMap.getElem?_insert, hc]

/-- Deadness after the in-place kill is deadness after `Store.kill`, at every row. -/
theorem killFast_isDead (d : HashMap Nat (HashSet Nat)) (c i c' i' : Nat) :
    isDead (killFast d c i) c' i' = isDead (kill d c i) c' i' := by
  unfold isDead
  rw [killFast_get]

/-- `pushBE8` appends `natBE 8`. -/
theorem pushBE8_eq (b : ByteArray) (x : Nat) : (pushBE8 b x).data.toList = b.data.toList ++ natBE 8 x := by
  simp [pushBE8, natBE, List.range_succ, ByteArray.data_push, Nat.toUInt8]

/-- Page `p` of the data `d`: its slice, padded with zeros to a full page. -/
def pgAt (d : Bytes) (p : Nat) : Bytes :=
  (d.drop (p * pageSize)).take pageSize ++
    List.replicate (pageSize - ((d.drop (p * pageSize)).take pageSize).length) 0

theorem pagesN_eq : ∀ (f : Nat) (d : Bytes), d.length ≤ f →
    pagesN f d = (List.range ((d.length + pageSize - 1) / pageSize)).map (pgAt d) := by
  intro f
  induction f with
  | zero =>
    intro d hd
    have : d = [] := List.eq_nil_of_length_eq_zero (by omega)
    subst this; simp [pagesN, pageSize]
  | succ f ih =>
    intro d hd
    by_cases he : d.isEmpty = true
    · have : d = [] := List.isEmpty_iff.mp he
      subst this; simp [pagesN, pageSize]
    · have hpos : 0 < d.length := by
        cases d with
        | nil => simp at he
        | cons => simp
      rw [pagesN, if_neg he]
      have hk : (d.length + pageSize - 1) / pageSize = ((d.drop pageSize).length + pageSize - 1) / pageSize + 1 := by
        rw [List.length_drop]; unfold pageSize; omega
      rw [hk, List.range_succ_eq_map, List.map_cons, List.map_map]
      have hps : pageSize = 4096 := rfl
      rw [ih (d.drop pageSize) (by rw [List.length_drop]; omega)]
      refine List.cons_eq_cons.mpr ⟨?_, ?_⟩
      · unfold pgAt
        simp only [Nat.zero_mul, List.drop_zero]
        rw [List.length_take]
        have e : pageSize - min pageSize d.length = pageSize - d.length := by omega
        rw [e]
      · apply List.map_congr_left
        intro p _
        unfold pgAt
        simp only [Function.comp, List.drop_drop]
        rw [Nat.succ_mul, Nat.add_comm (p * pageSize)]

/-! ## `encFast` in named steps

`encFastP` is `encFast` with each loop's step a named function; `encFast_eq_P` is the rewrite of the loops to folds. -/

theorem rows_fold (l : List Row) : ∀ (d : ByteArray) (o k : Array Nat),
    (l.foldl (fun s w => (encRowB s.1 w, s.2.1.push s.1.size, s.2.2.push (kh w.1).toNat)) (d, o, k)).1.data.toList
        = d.data.toList ++ l.flatMap encRow ∧
    (l.foldl (fun s w => (encRowB s.1 w, s.2.1.push s.1.size, s.2.2.push (kh w.1).toNat)) (d, o, k)).2.1.toList
        = o.toList ++ (List.range l.length).map (fun i => d.size + ((l.take i).flatMap encRow).length) ∧
    (l.foldl (fun s w => (encRowB s.1 w, s.2.1.push s.1.size, s.2.2.push (kh w.1).toNat)) (d, o, k)).2.2.toList
        = k.toList ++ l.map (fun w => (kh w.1).toNat) := by
  induction l with
  | nil => intro d o k; simp
  | cons w l ih =>
    intro d o k
    obtain ⟨h1, h2, h3⟩ := ih (encRowB d w) (o.push d.size) (k.push (kh w.1).toNat)
    have hsz : (encRowB d w).size = d.size + (encRow w).length := by
      rw [← ByteArray.size_data, ← Array.length_toList, encRowB_eq]; simp
    simp only [List.foldl_cons]
    refine ⟨?_, ?_, ?_⟩
    · rw [h1, encRowB_eq]; simp
    · rw [h2, List.length_cons, List.range_succ_eq_map, List.map_cons, List.map_map, hsz, Array.toList_push]
      simp only [List.append_assoc, List.singleton_append, List.take_zero, List.flatMap_nil, List.length_nil, Nat.add_zero]
      congr 2
      apply List.map_congr_left
      intro i _
      simp [Function.comp, List.length_append]
      omega
    · rw [h3]; simp

theorem forIn_ite_yield {α β : Type} (l : List α) (init : β) (c : α → β → Prop) [∀ a s, Decidable (c a s)]
    (f g : α → β → β) :
    forIn (m := Id) l init (fun a s => if c a s then pure (ForInStep.yield (f a s)) else pure (ForInStep.yield (g a s)))
      = pure (l.foldl (fun s a => if c a s then f a s else g a s) init) := by
  calc _ = forIn (m := Id) l init (fun a s => pure (ForInStep.yield (if c a s then f a s else g a s))) := by
        congr; funext a s; split <;> rfl
    _ = _ := List.forIn_pure_yield_eq_foldl ..

theorem forIn_match_yield {α β γ : Type} (l : List α) (init : β) (o : α → β → Option γ)
    (f : α → β → γ → β) (g : α → β → β) :
    forIn (m := Id) l init (fun a s => Option.casesOn (motive := fun _ => Id (ForInStep β)) (o a s)
        (pure (ForInStep.yield (g a s))) (fun j => pure (ForInStep.yield (f a s j))))
      = pure (l.foldl (fun s a => Option.casesOn (motive := fun _ => β) (o a s) (g a s) (fun j => f a s j)) init) := by
  calc _ = forIn (m := Id) l init (fun a s => pure (ForInStep.yield (Option.casesOn (motive := fun _ => β) (o a s) (g a s) (fun j => f a s j)))) := by
        congr; funext a s; cases o a s <;> rfl
    _ = _ := List.forIn_pure_yield_eq_foldl ..

def rowStep (s : ByteArray × Array Nat × Array Nat) (w : Row) : ByteArray × Array Nat × Array Nat :=
  (encRowB s.1 w, s.2.1.push s.1.size, s.2.2.push (kh w.1).toNat)

def fmStep (offs : Array Nat) (s : Array (Option Nat) × Array Nat) (j : Nat) : Array (Option Nat) × Array Nat :=
  if s.1[offs[j]! / pageSize]!.isNone = true then
    (s.1.set! (offs[j]! / pageSize) (some j), s.2.modify (offs[j]! / pageSize) fun x => x + 1)
  else (s.1, s.2.modify (offs[j]! / pageSize) fun x => x + 1)

def mkStep (offs khs : Array Nat) (first : Array (Option Nat)) (rowsIn : Array Nat)
    (s : Array (Nat × Nat × Nat × Bool) × Array Ix × Nat) (p : Nat) :
    Array (Nat × Nat × Nat × Bool) × Array Ix × Nat :=
  match first[p]! with
  | some j =>
    (s.1.push (khs[j]!, offs[j]! % pageSize, j, j == 0 || khs[j - 1]! != khs[j]!),
      s.2.1.push { page := p, fence := khs[j]!, off := offs[j]! % pageSize, row := j,
                   fresh := j == 0 || khs[j - 1]! != khs[j]! },
      s.2.2 + rowsIn[p]!)
  | none => (s.1.push (khs[s.2.2 - 1]!, pageSize, s.2.2 - 1, false), s.2.1, s.2.2 + rowsIn[p]!)

def mdStep (marks : Array (Nat × Nat × Nat × Bool)) (s : ByteArray) (p : Nat) : ByteArray :=
  (lebPush (lebPush (lebPush s marks[p]!.fst) marks[p]!.2.fst) marks[p]!.2.2.fst).push
    (if marks[p]!.2.2.snd = true then 1 else 0)

def encFastP (ws : List Row) : Enc :=
  let n := ws.length
  let A := ws.foldl rowStep (ByteArray.empty, Array.mkEmpty n, Array.mkEmpty n)
  let np := ((A.1.push 0).size + pageSize - 1) / pageSize
  let data := A.1.push 0 ++ ⟨Array.replicate (np * pageSize - (A.1.push 0).size) 0⟩
  let FR := (List.range n).foldl (fmStep A.2.1) (Array.replicate np none, Array.replicate np 0)
  let MK := (List.range np).foldl (mkStep A.2.1 A.2.2 FR.1 FR.2) (Array.mkEmpty np, #[], 0)
  let PH := (List.range np).foldl
    (fun a p => a.push (Bin.HB (domPageS ++ data.extract (p * pageSize) ((p + 1) * pageSize)))) (Array.mkEmpty np)
  let md1 := A.2.2.toList.foldl pushBE8 (lebPush ByteArray.empty n)
  let md2 := (List.range np).foldl (mdStep MK.1) (lebPush (lebPush md1 A.1.size) np)
  let md3 := (List.range np).foldl (fun s p => lebPush s PH[p]!.size ++ PH[p]!) (lebPush md2 np)
  { file := data, mdata := md3, ix := MK.2.1, phash := PH, rowBytes := A.1.size, nrows := n }


theorem encFast_eq_P (ws : List Row) : encFast ws = encFastP ws := by
  simp only [encFast, encFastP, rowStep, fmStep, mkStep, mdStep, Id.run, bind_pure_comp, pure_bind, Std.Legacy.Range.forIn_eq_forIn_range', Std.Legacy.Range.size, List.forIn_toArray, Array.forIn_pure_yield_eq_foldl, List.forIn_pure_yield_eq_foldl, forIn_ite_yield, Nat.sub_zero, Nat.add_sub_cancel, Nat.div_one, ← List.range_eq_range', Array.foldl_toList, List.foldl_toArray', List.size_toArray, Array.forIn_toList]
  delta encFast.match_1 mkStep.match_1
  simp only [forIn_match_yield, pure_bind, map_pure]
  unfold rowStep fmStep mkStep mdStep
  try delta mkStep.match_1
  rfl
theorem getElem!_modify_Nat (xs : Array Nat) (q p : Nat) (f : Nat → Nat) (h : p < xs.size) :
    (xs.modify q f)[p]! = if q = p then f xs[p]! else xs[p]! := by
  have hs : p < (xs.modify q f).size := by simpa using h
  rw [getElem!_pos (xs.modify q f) p hs, Array.getElem_modify, getElem!_pos xs p h]

/-- The first-row and row-count tables after the first `m` rows. -/
def fmRun (offs : Array Nat) (np m : Nat) : Array (Option Nat) × Array Nat :=
  (List.range m).foldl (fmStep offs) (Array.replicate np none, Array.replicate np 0)

theorem fm_fold (offs : Array Nat) (n np : Nat) (hn : ∀ j, j < n → offs[j]! / pageSize < np) :
    ∀ m, m ≤ n → (fmRun offs np m).1.size = np ∧ (fmRun offs np m).2.size = np ∧
      (∀ p, p < np → (fmRun offs np m).1[p]! = (List.range m).find? (fun j => offs[j]! / pageSize == p)) ∧
      (∀ p, p < np → (fmRun offs np m).2[p]! = ((List.range m).filter (fun j => offs[j]! / pageSize == p)).length) := by
  intro m
  induction m with
  | zero =>
    intro _
    refine ⟨by simp [fmRun], by simp [fmRun], ?_, ?_⟩ <;> intro p hp <;> simp [fmRun, hp]
  | succ m ih =>
    intro hm
    obtain ⟨h1, h2, h3, h4⟩ := ih (by omega)
    have hq := hn m (by omega)
    have e : fmRun offs np (m + 1) = fmStep offs (fmRun offs np m) m := by
      simp [fmRun, List.range_succ, List.foldl_append]
    rw [e]
    unfold fmStep
    by_cases hnone : (fmRun offs np m).1[offs[m]! / pageSize]!.isNone = true
    · rw [if_pos hnone]
      dsimp only
      refine ⟨by simp [h1], by simp [h2], ?_, ?_⟩
      · intro p hp
        by_cases hpq : offs[m]! / pageSize = p
        · subst hpq
          rw [Array.getElem!_set!_self _ _ _ (by omega), List.range_succ, List.find?_append]
          rw [h3 _ hq] at hnone
          cases hf : (List.range m).find? (fun j => offs[j]! / pageSize == offs[m]! / pageSize) <;> simp_all
        · rw [Array.getElem!_set!_ne _ _ _ _ hpq, h3 p hp, List.range_succ, List.find?_append]
          have : (offs[m]! / pageSize == p) = false := by simpa using hpq
          simp [this]
      · intro p hp
        rw [getElem!_modify_Nat _ _ _ _ (by omega), h4 p hp, List.range_succ, List.filter_append]
        by_cases hpq : offs[m]! / pageSize = p
        · subst hpq; simp
        · have : (offs[m]! / pageSize == p) = false := by simpa using hpq
          simp [hpq, this]
    · rw [if_neg hnone]
      dsimp only
      refine ⟨h1, by simp [h2], ?_, ?_⟩
      · intro p hp
        rw [h3 p hp, List.range_succ, List.find?_append]
        by_cases hpq : offs[m]! / pageSize = p
        · subst hpq
          rw [h3 _ hq] at hnone
          cases hf : (List.range m).find? (fun j => offs[j]! / pageSize == offs[m]! / pageSize) <;> simp_all
        · have : (offs[m]! / pageSize == p) = false := by simpa using hpq
          simp [this]
      · intro p hp
        rw [getElem!_modify_Nat _ _ _ _ (by omega), h4 p hp, List.range_succ, List.filter_append]
        by_cases hpq : offs[m]! / pageSize = p
        · subst hpq; simp
        · have : (offs[m]! / pageSize == p) = false := by simpa using hpq
          simp [hpq, this]


theorem off_mono (ws : List Row) {i j : Nat} (h : i ≤ j) : off ws i ≤ off ws j := by
  obtain ⟨k, rfl⟩ := Nat.exists_eq_add_of_le h
  unfold off
  rw [List.take_add, List.flatMap_append, List.length_append]
  omega

theorem find?_filter_first {α : Type} (l : List α) (q pf : α → Bool)
    (h : ∀ j, l.find? pf = some j → q j = true) : (l.filter q).find? pf = l.find? pf := by
  induction l with
  | nil => rfl
  | cons x l ih =>
    by_cases hq : q x = true
    · rw [List.filter_cons_of_pos hq]
      cases hp : pf x
      · rw [List.find?_cons_of_neg (by simp [hp]), List.find?_cons_of_neg (by simp [hp])]
        exact ih (fun j hj => h j (by rw [List.find?_cons_of_neg (by simp [hp])]; exact hj))
      · simp [List.find?_cons, hp]
    · rw [List.filter_cons_of_neg hq]
      have hp : pf x = false := by
        cases hp : pf x
        · rfl
        · exact absurd (h x (by simp [List.find?_cons, hp])) hq
      rw [List.find?_cons_of_neg (by simp [hp])]
      exact ih (fun j hj => h j (by rw [List.find?_cons_of_neg (by simp [hp])]; exact hj))

/-- The page index finds the first row of a page as the plain row range does. -/
theorem pidx_find (ws : List Row) (p : Nat) :
    (pidx ws).find? (fun x => off ws x / pageSize == p) = (List.range ws.length).find? (fun x => off ws x / pageSize == p) := by
  unfold pidx
  apply find?_filter_first
  intro j hj
  rw [List.find?_range_eq_some] at hj
  obtain ⟨h1, -, h3⟩ := hj
  by_cases h0 : j = 0
  · simp [h0]
  · have h4 := h3 (j - 1) (by omega)
    have h5 : off ws (j - 1) / pageSize ≤ off ws j / pageSize := Nat.div_le_div_right (off_mono ws (by omega))
    simp only [beq_iff_eq, Bool.not_eq_true'] at h1 h4
    simp only [Bool.or_eq_true, beq_iff_eq, decide_eq_true_eq]
    have hps : pageSize = 4096 := rfl
    right
    have h6 : off ws (j - 1) / pageSize ≠ p := by simpa using h4
    omega

theorem count_lt_succ {α : Type} (l : List α) (f : α → Nat) (m : Nat) :
    (l.filter (fun x => decide (f x < m + 1))).length =
      (l.filter (fun x => decide (f x < m))).length + (l.filter (fun x => f x == m)).length := by
  induction l with
  | nil => simp
  | cons x l ih =>
    simp only [List.filter_cons]
    rcases Nat.lt_trichotomy (f x) m with h | h | h
    · have h' : f x < m + 1 := by omega
      have h3 : f x ≠ m := by omega
      simp [h, h', h3, ih] <;> omega
    · have h' : f x < m + 1 := by omega
      simp [h, ih] <;> omega
    · have h' : ¬ f x < m + 1 := by omega
      have h'' : ¬ f x < m := by omega
      have h3 : f x ≠ m := by omega
      simp [h', h'', h3, ih]

theorem find?_range_congr (f g : Nat → Bool) : ∀ n, (∀ j, j < n → f j = g j) →
    (List.range n).find? f = (List.range n).find? g := by
  intro n
  induction n with
  | zero => intro _; rfl
  | succ n ih =>
    intro h
    rw [List.range_succ, List.find?_append, List.find?_append, ih (fun j hj => h j (by omega))]
    simp [h n (by omega)]

/-- The marks, index and running row count after the first `m` pages. -/
def mkRun (offs khs : Array Nat) (first : Array (Option Nat)) (rowsIn : Array Nat) (np m : Nat) :
    Array (Nat × Nat × Nat × Bool) × Array Ix × Nat :=
  (List.range m).foldl (mkStep offs khs first rowsIn) (Array.mkEmpty np, #[], 0)

theorem mk_fold (kh : Bytes → UInt64) (ws : List Row) (offs khs : Array Nat) (first : Array (Option Nat))
    (rowsIn : Array Nat) (np : Nat)
    (hoff : ∀ j, j < ws.length → offs[j]! = off ws j) (hkh : ∀ j, khs[j]! = hashAt kh ws j)
    (hfirst : ∀ p, p < np → first[p]! = (List.range ws.length).find? (fun j => offs[j]! / pageSize == p))
    (hrows : ∀ p, p < np → rowsIn[p]! = ((List.range ws.length).filter (fun j => offs[j]! / pageSize == p)).length) :
    ∀ m, m ≤ np → (mkRun offs khs first rowsIn np m).1.toList = (List.range m).map (markAt kh ws) ∧
      (mkRun offs khs first rowsIn np m).2.2 = ((List.range ws.length).filter (fun j => decide (off ws j / pageSize < m))).length := by
  have hf : ∀ p, p < np → first[p]! = (List.range ws.length).find? (fun j => off ws j / pageSize == p) := by
    intro p hp
    rw [hfirst p hp]
    apply find?_range_congr
    intro j hj
    rw [hoff j hj]
  have hr : ∀ p, p < np → rowsIn[p]! = ((List.range ws.length).filter (fun j => off ws j / pageSize == p)).length := by
    intro p hp
    rw [hrows p hp]
    congr 1
    apply List.filter_congr
    intro j hj
    rw [hoff j (List.mem_range.mp hj)]
  intro m
  induction m with
  | zero =>
    intro _
    have h0 : (List.range ws.length).filter (fun _ => false) = [] :=
      List.filter_eq_nil_iff.mpr (fun a _ => by simp)
    simp [mkRun, h0]
  | succ m ih =>
    intro hm
    obtain ⟨h1, h2⟩ := ih (by omega)
    have e : mkRun offs khs first rowsIn np (m + 1) = mkStep offs khs first rowsIn (mkRun offs khs first rowsIn np m) m := by
      simp [mkRun, List.range_succ, List.foldl_append]
    rw [e, count_lt_succ]
    unfold mkStep
    rw [hf m (by omega), hr m (by omega), ← pidx_find ws m]
    cases hfd : (pidx ws).find? (fun x => off ws x / pageSize == m) with
    | none =>
      have hmk : markAt kh ws m = (hashAt kh ws (((List.range ws.length).filter (fun j => decide (off ws j / pageSize < m))).length - 1),
          pageSize, ((List.range ws.length).filter (fun j => decide (off ws j / pageSize < m))).length - 1, false) := by
        simp only [markAt, hfd]
      dsimp only
      refine ⟨?_, ?_⟩
      · rw [Array.toList_push, h1, List.range_succ, List.map_append, List.map_cons, List.map_nil, hmk, h2, hkh]
      · rw [h2]
    | some j =>
      have hj := hfd
      rw [pidx_find, List.find?_range_eq_some] at hj
      obtain ⟨hpj, hjm, -⟩ := hj
      have hjl := List.mem_range.mp hjm
      have hmk : markAt kh ws m = (hashAt kh ws j, off ws j % pageSize, j, fresh kh ws j) := by
        simp only [markAt, hfd]
      dsimp only
      refine ⟨?_, ?_⟩
      · rw [Array.toList_push, h1, List.range_succ, List.map_append, List.map_cons, List.map_nil, hmk, hkh, hkh, hoff j hjl]
        rfl
      · rw [h2]

theorem pgAt_zero (d : Bytes) : pgAt d 0 = d.take pageSize ++ List.replicate (pageSize - (d.take pageSize).length) 0 := by
  simp [pgAt]

theorem pgAt_succ (d : Bytes) (p : Nat) : pgAt d (p + 1) = pgAt (d.drop pageSize) p := by
  unfold pgAt
  simp only [List.drop_drop]
  rw [Nat.succ_mul, Nat.add_comm (p * pageSize)]

/-- The pages of `d` laid end to end are `d` padded with zeros to a whole number of pages. -/
theorem pg_flatten : ∀ (k : Nat) (d : Bytes), ((List.range k).map (pgAt d)).flatten =
    d.take (k * pageSize) ++ List.replicate (k * pageSize - (d.take (k * pageSize)).length) 0 := by
  intro k
  induction k with
  | zero => intro d; simp
  | succ k ih =>
    intro d
    rw [List.range_succ_eq_map, List.map_cons, List.map_map, List.flatten_cons]
    have hm : (pgAt d ∘ Nat.succ) = pgAt (d.drop pageSize) := by
      funext p; exact pgAt_succ d p
    rw [hm, ih, pgAt_zero]
    have hps : pageSize = 4096 := rfl
    rw [hps]
    by_cases h : 4096 ≤ d.length
    · have h1 : (k + 1) * 4096 = 4096 + k * 4096 := by omega
      have hl1 : (d.take 4096).length = 4096 := by simp; omega
      have hl3 : (d.take (4096 + k * 4096)).length = min (4096 + k * 4096) d.length := by simp
      have ht : d.take (4096 + k * 4096) = d.take 4096 ++ (d.drop 4096).take (k * 4096) := List.take_add ..
      have hl2 : ((d.drop 4096).take (k * 4096)).length = min (k * 4096) (d.length - 4096) := by simp
      rw [h1, hl3, ht, hl1, hl2, Nat.sub_self, List.replicate_zero, List.append_nil, List.append_assoc]
      have : k * 4096 - min (k * 4096) (d.length - 4096) = 4096 + k * 4096 - min (4096 + k * 4096) d.length := by omega
      rw [this]
    · have hd : d.drop 4096 = [] := List.drop_eq_nil_of_le (by omega)
      have h1 : d.take 4096 = d := List.take_of_length_le (by omega)
      have h2 : d.take ((k + 1) * 4096) = d := List.take_of_length_le (by omega)
      rw [hd, h1, h2, List.take_nil, List.length_nil, List.nil_append, List.append_assoc, List.replicate_append_replicate]
      have : 4096 - d.length + (k * 4096 - 0) = (k + 1) * 4096 - d.length := by omega
      rw [this]

theorem pgAt_pad (d : Bytes) (z p : Nat) (h : (p + 1) * pageSize ≤ d.length + z) :
    ((d ++ List.replicate z 0).drop (p * pageSize)).take pageSize = pgAt d p := by
  have hps : pageSize = 4096 := rfl
  unfold pgAt
  rw [List.drop_append, List.take_append]
  simp only [List.drop_replicate, List.take_replicate, List.length_take, List.length_drop]
  have : min (pageSize - (d.length - p * pageSize)) (z - (p * pageSize - d.length)) =
      pageSize - min pageSize (d.length - p * pageSize) := by
    have h' : (p + 1) * 4096 ≤ d.length + z := by rw [hps] at h; exact h
    rw [hps]; omega
  rw [this]

theorem foldl_push_toList {α β : Type} (f : α → β) (l : List α) : ∀ (init : Array β),
    (l.foldl (fun a p => a.push (f p)) init).toList = init.toList ++ l.map f := by
  induction l with
  | nil => intro init; simp
  | cons x l ih => intro init; simp [List.foldl_cons]

theorem foldl_pushBE8_eq (l : List Nat) : ∀ b : ByteArray,
    (l.foldl pushBE8 b).data.toList = b.data.toList ++ l.flatMap (natBE 8) := by
  induction l with
  | nil => intro b; simp
  | cons x l ih => intro b; simp only [List.foldl_cons, List.flatMap_cons]; rw [ih, pushBE8_eq]; simp

theorem md_marks (marks : Array (Nat × Nat × Nat × Bool)) (l : List Nat) : ∀ s : ByteArray,
    (l.foldl (mdStep marks) s).data.toList = s.data.toList ++ l.flatMap (fun p => encMark marks[p]!) := by
  induction l with
  | nil => intro b; simp
  | cons x l ih =>
    intro b
    simp only [List.foldl_cons, List.flatMap_cons]
    rw [ih]
    unfold mdStep encMark
    simp [ByteArray.data_push, lebPush_eq]

theorem md_ph (PH : Array ByteArray) (l : List Nat) : ∀ s : ByteArray,
    (l.foldl (fun s p => lebPush s PH[p]!.size ++ PH[p]!) s).data.toList =
      s.data.toList ++ l.flatMap (fun p => leb PH[p]!.data.toList.length ++ PH[p]!.data.toList) := by
  induction l with
  | nil => intro b; simp
  | cons x l ih =>
    intro b
    simp only [List.foldl_cons, List.flatMap_cons]
    rw [ih]
    simp [lebPush_eq]

theorem ba_eq_of_toList (a b : ByteArray) (h : a.toList = b.toList) : a = b := by
  rw [Bin.toList_eq', Bin.toList_eq'] at h
  cases a; cases b
  simp only [ByteArray.mk.injEq]
  exact Array.toList_inj.mp h

theorem arr_getBang {α : Type} [Inhabited α] (a : Array α) (l : List α) (h : a.toList = l) (j : Nat) (hj : j < l.length) :
    a[j]! = l[j] := by
  subst h
  have hj' : j < a.size := by simpa using hj
  rw [getElem!_pos a j hj']
  simp

theorem arr_getBang_opt (a : Array Nat) (l : List Nat) (h : a.toList = l) (j : Nat) :
    a[j]! = (l[j]?).getD 0 := by
  subst h
  simp [Array.getElem!_eq_getD, Array.getD_eq_getD_getElem?]

theorem off_len (ws : List Row) : off ws ws.length = (ws.flatMap encRow).length := by
  unfold off; rw [List.take_length]

theorem leb_zero : leb 0 = [0] := by
  rw [leb]; simp

/-! ## The encoder against the model, with the loops as named steps -/

def qData (A : ByteArray × Array Nat × Array Nat) (np : Nat) : ByteArray :=
  A.1.push 0 ++ ⟨Array.replicate (np * pageSize - (A.1.push 0).size) 0⟩

def qMK (ws : List Row) (A : ByteArray × Array Nat × Array Nat) (np : Nat) :
    Array (Nat × Nat × Nat × Bool) × Array Ix × Nat :=
  mkRun A.2.1 A.2.2 (fmRun A.2.1 np ws.length).1 (fmRun A.2.1 np ws.length).2 np np

def qPH (A : ByteArray × Array Nat × Array Nat) (np : Nat) : Array ByteArray :=
  (List.range np).foldl
    (fun a p => a.push (Bin.HB (domPageS ++ (qData A np).extract (p * pageSize) ((p + 1) * pageSize)))) (Array.mkEmpty np)

def qMd (ws : List Row) (A : ByteArray × Array Nat × Array Nat) (np : Nat) : ByteArray :=
  let md1 := A.2.2.toList.foldl pushBE8 (lebPush ByteArray.empty ws.length)
  let md2 := (List.range np).foldl (mdStep (qMK ws A np).1) (lebPush (lebPush md1 A.1.size) np)
  (List.range np).foldl (fun s p => lebPush s (qPH A np)[p]!.size ++ (qPH A np)[p]!) (lebPush md2 np)

def encFastQ (ws : List Row) (A : ByteArray × Array Nat × Array Nat) (np : Nat) : Enc :=
  { file := qData A np, mdata := qMd ws A np, ix := (qMK ws A np).2.1, phash := qPH A np,
    rowBytes := A.1.size, nrows := ws.length }

theorem encFastP_eq_Q (ws : List Row) : encFastP ws =
    encFastQ ws (ws.foldl rowStep (ByteArray.empty, Array.mkEmpty ws.length, Array.mkEmpty ws.length))
      ((((ws.foldl rowStep (ByteArray.empty, Array.mkEmpty ws.length, Array.mkEmpty ws.length)).1.push 0).size
        + pageSize - 1) / pageSize) := rfl

/-- What the encoder's row loop leaves in its buffers. -/
structure QH (ws : List Row) (A : ByteArray × Array Nat × Array Nat) (np : Nat) : Prop where
  h1 : A.1.data.toList = ws.flatMap encRow
  h2 : A.2.1.toList = (List.range ws.length).map (off ws)
  h3 : A.2.2.toList = ws.map (fun w => (kh w.1).toNat)
  hnp : np = ((A.1.push 0).size + pageSize - 1) / pageSize

theorem Q_np {ws : List Row} {A : ByteArray × Array Nat × Array Nat} {np : Nat} (h : QH ws A np) :
    A.1.size = (ws.flatMap encRow).length ∧ (A.1.push 0).size = (ws.flatMap encRow).length + 1 ∧
      np = ((ws.flatMap encRow).length + 4096) / 4096 := by
  have hL : A.1.size = (ws.flatMap encRow).length := by
    rw [← ByteArray.size_data, ← Array.length_toList, h.h1]
  have hsz : (A.1.push 0).size = (ws.flatMap encRow).length + 1 := by rw [ByteArray.size_push, hL]
  refine ⟨hL, hsz, ?_⟩
  have hps : pageSize = 4096 := rfl
  rw [h.hnp, hsz, hps]; omega

theorem Q_pages {ws : List Row} {A : ByteArray × Array Nat × Array Nat} {np : Nat} (h : QH ws A np) :
    (encChunk hl kh ws).pages = (List.range np).map (pgAt (ws.flatMap encRow ++ [0])) := by
  obtain ⟨-, -, hnp⟩ := Q_np h
  have hps : pageSize = 4096 := rfl
  have hD : encData ws = ws.flatMap encRow ++ [0] := by unfold encData; rw [leb_zero]
  have := pagesN_eq (encData ws).length (encData ws) (Nat.le_refl _)
  rw [hD] at this
  show pagesN (encData ws).length (encData ws) = _
  rw [hD, this]
  have hk : ((ws.flatMap encRow ++ [0]).length + pageSize - 1) / pageSize = np := by
    rw [List.length_append, List.length_singleton, hps, hnp]; omega
  rw [hk]

theorem Q_dataL {ws : List Row} {A : ByteArray × Array Nat × Array Nat} {np : Nat} (h : QH ws A np) :
    (qData A np).toList = (ws.flatMap encRow ++ [0]) ++
      List.replicate (np * pageSize - ((ws.flatMap encRow).length + 1)) 0 := by
  obtain ⟨hL, hsz, -⟩ := Q_np h
  unfold qData
  rw [Bin.toList_eq', ByteArray.toList_data_append, ByteArray.data_push, hsz]
  simp [h.h1]

theorem Q_data {ws : List Row} {A : ByteArray × Array Nat × Array Nat} {np : Nat} (h : QH ws A np) :
    (qData A np).data.toList = (encChunk hl kh ws).pages.flatten := by
  obtain ⟨hL, hsz, hnp⟩ := Q_np h
  have hps : pageSize = 4096 := rfl
  rw [← Bin.toList_eq', Q_dataL h, Q_pages h, pg_flatten, List.take_of_length_le (by rw [List.length_append, List.length_singleton, hps]; omega)]
  rw [List.length_append, List.length_singleton]

theorem Q_ph {ws : List Row} {A : ByteArray × Array Nat × Array Nat} {np : Nat} (h : QH ws A np) :
    (qPH A np).toList = (List.range np).map
      (fun p => Bin.HB ⟨(domain "STORE/PAGE" ++ pgAt (ws.flatMap encRow ++ [0]) p).toArray⟩) := by
  obtain ⟨hL, hsz, hnp⟩ := Q_np h
  have hps : pageSize = 4096 := rfl
  unfold qPH
  rw [foldl_push_toList]
  simp only [Array.mkEmpty_eq, Array.toList_empty, List.nil_append]
  apply List.map_congr_left
  intro p hp
  have hp' := List.mem_range.mp hp
  have e : domPageS ++ (qData A np).extract (p * pageSize) ((p + 1) * pageSize) =
      ⟨(domain "STORE/PAGE" ++ pgAt (ws.flatMap encRow ++ [0]) p).toArray⟩ := by
    apply ba_eq_of_toList
    rw [Bin.toList_append', Bin.toList_extract', Q_dataL h]
    unfold domPageS
    rw [Bin.toList_bytesOf, Bin.toList_eq']
    have e1 : (p + 1) * pageSize - p * pageSize = pageSize := by rw [hps]; omega
    rw [e1, pgAt_pad]
    rw [List.length_append, List.length_singleton, hps]; omega
  rw [e]

theorem Q_phash {ws : List Row} {A : ByteArray × Array Nat × Array Nat} {np : Nat} (h : QH ws A np) :
    (qPH A np).toList.map (fun b => b.data.toList) = (encChunk hl kh ws).pages.map (pageHash hl) := by
  rw [Q_ph h, Q_pages h, List.map_map, List.map_map]
  apply List.map_congr_left
  intro p _
  simp only [Function.comp, pageHash, hl]
  rw [← Bin.toList_eq']

theorem Q_mk {ws : List Row} {A : ByteArray × Array Nat × Array Nat} {np : Nat} (h : QH ws A np) :
    (qMK ws A np).1.toList = (List.range np).map (markAt kh ws) := by
  obtain ⟨hL, hsz, hnp⟩ := Q_np h
  have hps : pageSize = 4096 := rfl
  have hoff : ∀ j, j < ws.length → A.2.1[j]! = off ws j := by
    intro j hj
    rw [arr_getBang_opt _ _ h.h2 j]
    simp [hj]
  have hkh : ∀ j, A.2.2[j]! = hashAt kh ws j := by
    intro j
    rw [arr_getBang_opt _ _ h.h3 j]
    simp [hashAt, List.getElem?_map]
  have hn : ∀ j, j < ws.length → A.2.1[j]! / pageSize < np := by
    intro j hj
    rw [hoff j hj]
    have h1 : off ws j ≤ (ws.flatMap encRow).length := by
      rw [← off_len]; exact off_mono ws (by omega)
    rw [hps, hnp]
    omega
  obtain ⟨-, -, hf, hr⟩ := fm_fold A.2.1 ws.length np hn ws.length (Nat.le_refl _)
  exact (mk_fold kh ws A.2.1 A.2.2 (fmRun A.2.1 np ws.length).1 (fmRun A.2.1 np ws.length).2 np hoff hkh hf hr np
    (Nat.le_refl _)).1

theorem flatMap_congr' {α β : Type} (l : List α) (f g : α → List β) (h : ∀ x ∈ l, f x = g x) :
    l.flatMap f = l.flatMap g := by
  induction l with
  | nil => rfl
  | cons x l ih =>
    simp only [List.flatMap_cons]
    rw [h x (List.mem_cons_self ..), ih (fun y hy => h y (List.mem_cons_of_mem _ hy))]

theorem Q_md {ws : List Row} {A : ByteArray × Array Nat × Array Nat} {np : Nat} (h : QH ws A np) :
    (qMd ws A np).data.toList = (encChunk hl kh ws).mdata := by
  obtain ⟨hL, hsz, hnp⟩ := Q_np h
  have hpg := Q_pages h
  have hmd : (encChunk hl kh ws).mdata = Chunk.encMeta hl kh ws ((List.range np).map (pgAt (ws.flatMap encRow ++ [0]))) := by
    rw [← hpg]; rfl
  have hMK := Q_mk h
  have hPH := Q_ph h
  have hmk : ∀ p ∈ List.range np, (qMK ws A np).1[p]! = markAt kh ws p := by
    intro p hp
    have hp' := List.mem_range.mp hp
    rw [arr_getBang _ _ hMK p (by simp [hp'])]
    simp
  have hph : ∀ p ∈ List.range np, (qPH A np)[p]!.data.toList =
      pageHash hl (pgAt (ws.flatMap encRow ++ [0]) p) := by
    intro p hp
    have hp' := List.mem_range.mp hp
    rw [arr_getBang _ _ hPH p (by simp [hp'])]
    simp only [List.getElem_map, List.getElem_range, pageHash, hl]
    rw [Bin.toList_eq']
  unfold qMd
  dsimp only
  rw [md_ph, lebPush_eq, md_marks, lebPush_eq, lebPush_eq, foldl_pushBE8_eq, lebPush_eq, h.h3, hL, hmd]
  unfold Chunk.encMeta metaOf encM pageMarks
  simp only [ByteArray.data_empty, Array.toList_empty, List.length_map, List.length_range, List.flatMap_map,
    List.nil_append, List.append_assoc]
  have e1 : (List.range np).flatMap (fun p => encMark (qMK ws A np).1[p]!) =
      (List.range np).flatMap (fun a => encMark (markAt kh ws a)) :=
    flatMap_congr' _ _ _ (fun p hp => by rw [hmk p hp])
  have e2 : (List.range np).flatMap (fun p => leb (qPH A np)[p]!.data.toList.length ++ (qPH A np)[p]!.data.toList) =
      (List.range np).flatMap (fun a => leb (pageHash hl (pgAt (ws.flatMap encRow ++ [0]) a)).length ++
        pageHash hl (pgAt (ws.flatMap encRow ++ [0]) a)) :=
    flatMap_congr' _ _ _ (fun p hp => by rw [hph p hp])
  rw [e1, e2]

/-- What the encoder's row loop leaves in its buffers. -/
theorem encFast_QH (ws : List Row) : QH ws (ws.foldl rowStep (ByteArray.empty, Array.mkEmpty ws.length, Array.mkEmpty ws.length))
      ((((ws.foldl rowStep (ByteArray.empty, Array.mkEmpty ws.length, Array.mkEmpty ws.length)).1.push 0).size
        + pageSize - 1) / pageSize) := by
  obtain ⟨r1, r2, r3⟩ := rows_fold ws ByteArray.empty (Array.mkEmpty ws.length) (Array.mkEmpty ws.length)
  have r1' : (ws.foldl rowStep (ByteArray.empty, Array.mkEmpty ws.length, Array.mkEmpty ws.length)).1.data.toList =
      ByteArray.empty.data.toList ++ ws.flatMap encRow := r1
  have r2' : (ws.foldl rowStep (ByteArray.empty, Array.mkEmpty ws.length, Array.mkEmpty ws.length)).2.1.toList =
      (Array.mkEmpty ws.length : Array Nat).toList ++
        (List.range ws.length).map (fun i => ByteArray.empty.size + ((ws.take i).flatMap encRow).length) := r2
  have r3' : (ws.foldl rowStep (ByteArray.empty, Array.mkEmpty ws.length, Array.mkEmpty ws.length)).2.2.toList =
      (Array.mkEmpty ws.length : Array Nat).toList ++ ws.map (fun w => (kh w.1).toNat) := r3
  exact ⟨by rw [r1']; simp, by rw [r2']; simp [off], by rw [r3']; simp, rfl⟩

/-- The chunk encoder writes the file, metadata and page hashes the model writes. -/
theorem encFast_spec (ws : List Row) :
    (encFast ws).file.data.toList = (encChunk hl kh ws).pages.flatten ∧
    (encFast ws).mdata.data.toList = (encChunk hl kh ws).mdata ∧
    (encFast ws).phash.toList.map (fun b => b.data.toList) = (encChunk hl kh ws).pages.map (pageHash hl) ∧
    (encFast ws).rowBytes = (ws.flatMap encRow).length ∧ (encFast ws).nrows = ws.length := by
  have h := encFast_QH ws
  rw [encFast_eq_P, encFastP_eq_Q]
  exact ⟨Q_data h, Q_md h, Q_phash h, (Q_np h).1, rfl⟩

end BlindLedger.Gate.Flat.ChunkIo

