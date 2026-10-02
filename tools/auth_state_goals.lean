import BlindLedger.Gate.Spec
import BlindLedger.Gate.Rules.Spec

/-! auth-state-v1 goals (design, 2026-10-01).  Definitions are final text for the builder; every `sorry` is a
    proof the builder owes.  Product files (one namespace here so this file type-checks alone):
      §A  `Auth/Log.lean`        RFC 9162 log under SHA3-512: root, frontier, inclusion, consistency
      §B  `Auth/Map.lean`        sparse Merkle map with leaf lifting: root, pruned-tree proofs, insert
      §C  `Gate/StateV2.lean`    gate STATE/v2: entries, keys, buckets, hydration, the batch update
    §A and §B import only `Gate.Spec` (for `Bytes`, `pairUp`, `treeRoot`, `pathRoot`, `natBE`); §C also imports
    `Rules.Spec`.  `H` is the hash (SHA3-512 in every product use).  Every soundness claim is "or `breakIn`
    finds a break among the hash inputs the claim's own data determines"; `f id` is the input `f` hashes. -/

namespace BlindLedger.Gate.Auth
open BlindLedger.Gate

/-- The extractor: two listed hash inputs that differ and hash alike, or one listed input hashing to the all-zero
    digest (the map's empty marker), returned paired with itself. -/
def breakIn (H : Bytes → Bytes) (xs : List Bytes) : Option (Bytes × Bytes) :=
  (xs.flatMap fun x => xs.map fun y => (x, y)).find? fun (x, y) => H x == H y && (x != y || H x == zeroDigest)

theorem breakIn_sound {H : Bytes → Bytes} {xs : List Bytes} {x y : Bytes} (h : breakIn H xs = some (x, y)) :
    x ∈ xs ∧ y ∈ xs ∧ H x = H y ∧ (x ≠ y ∨ H x = zeroDigest) := by
  unfold breakIn at h
  have h1 := List.find?_some h
  have h2 := List.mem_of_find?_eq_some h
  simp only [List.mem_flatMap, List.mem_map] at h2
  obtain ⟨x', hx', y', hy', hxy⟩ := h2
  obtain ⟨rfl, rfl⟩ := Prod.mk.inj hxy
  simp only [Bool.and_eq_true, beq_iff_eq, Bool.or_eq_true, bne_iff_ne, ne_eq] at h1
  exact ⟨hx', hy', h1.1, h1.2⟩

/-- The one generic reduction: a listed pair of distinct inputs with equal hashes makes `breakIn` find something. -/
theorem breakIn_of_ne {H : Bytes → Bytes} {xs : List Bytes} {x y : Bytes} (hx : x ∈ xs) (hy : y ∈ xs)
    (hne : x ≠ y) (hh : H x = H y) : breakIn H xs ≠ none := by
  intro h
  unfold breakIn at h
  rw [List.find?_eq_none] at h
  apply h (x, y) (List.mem_flatMap.mpr ⟨x, hx, List.mem_map.mpr ⟨y, hy, rfl⟩⟩)
  simp [hh, hne]

theorem breakIn_of_zero {H : Bytes → Bytes} {xs : List Bytes} {x : Bytes} (hx : x ∈ xs)
    (hz : H x = zeroDigest) : breakIn H xs ≠ none := by
  intro h
  unfold breakIn at h
  rw [List.find?_eq_none] at h
  apply h (x, x) (List.mem_flatMap.mpr ⟨x, hx, List.mem_map.mpr ⟨x, hx, rfl⟩⟩)
  simp [hz]

/-- Under `breakIn = none`, listed inputs hash apart. -/
theorem inj_of_none {H : Bytes → Bytes} {xs : List Bytes} (h : breakIn H xs = none) {x y : Bytes}
    (hx : x ∈ xs) (hy : y ∈ xs) (hh : H x = H y) : x = y := by
  exact Classical.byContradiction fun hne => breakIn_of_ne hx hy hne hh h

theorem nz_of_none {H : Bytes → Bytes} {xs : List Bytes} (h : breakIn H xs = none) {x : Bytes}
    (hx : x ∈ xs) : H x ≠ zeroDigest := fun hz => breakIn_of_zero hx hz h

/-- Fewer listed inputs, fewer breaks. -/
theorem none_mono {H : Bytes → Bytes} {xs ys : List Bytes} (h : breakIn H xs = none)
    (hs : ∀ y ∈ ys, y ∈ xs) : breakIn H ys = none := by
  match hb : breakIn H ys with
  | none => rfl
  | some (x, y) =>
    obtain ⟨hx, hy, hh, hd⟩ := breakIn_sound hb
    exfalso
    rcases hd with hd | hd
    · exact breakIn_of_ne (hs _ hx) (hs _ hy) hd hh h
    · exact breakIn_of_zero (hs _ hx) hd h

def HashLen (H : Bytes → Bytes) : Prop := ∀ x, (H x).length = digestBytes

/-- Sizes are u64 on the wire and at most 2^63 - 1 (BLFIN02 convention). -/
def maxSize : Nat := 2 ^ 63 - 1

/-! ## §A  The log: RFC 9162 §2.1 shape, SHA3-512, tags 0x00 leaf / 0x01 node (domain `[]`)

    `leafHash H [] e = H (0x00 ‖ e)` and `nodeHash H [] l r = H (0x01 ‖ l ‖ r)` are RFC 9162's MTH hashes.
    `pairUp`'s carried odd node gives exactly RFC 9162's split-at-largest-power-of-two tree. -/

def logFuel : Nat := 64

def logLeaf (H : Bytes → Bytes) (e : Bytes) : Bytes := leafHash H [] e

def logRoot (H : Bytes → Bytes) (es : List Bytes) : Bytes :=
  if es.isEmpty then H [] else treeRoot H [] logFuel (es.map (logLeaf H))

def levelInputs (H : Bytes → Bytes) : Nat → List Bytes → List Bytes
  | 0, _ => []
  | fuel + 1, xs => pairUp id [] xs ++ levelInputs H fuel (pairUp H [] xs)

/-- Every hash input of the log over `es`: the empty log's, each leaf's, each level's nodes'. -/
def logInputs (H : Bytes → Bytes) (es : List Bytes) : List Bytes :=
  [] :: es.map (logLeaf id) ++ levelInputs H logFuel (es.map (logLeaf H))

/-- RFC 9162 §2.1.3.2, through the gate's existing `pathRoot` (the same shape rule). -/
def verifyInclusion (H : Bytes → Bytes) (root : Bytes) (size index : Nat) (e : Bytes) (path : List Bytes) : Bool :=
  index < size && pathRoot H [] logFuel index size (logLeaf H e) path == some root

/-- The hash inputs an inclusion path feeds `pathRoot`. -/
def pathInputs (H : Bytes → Bytes) : Nat → Nat → Nat → Bytes → List Bytes → List Bytes
  | fuel + 1, i, n, node, s :: rest =>
    if i % 2 == 0 && i + 1 == n then pathInputs H fuel (i / 2) ((n + 1) / 2) node (s :: rest)
    else stepInput [] i node s :: pathInputs H fuel (i / 2) ((n + 1) / 2) (H (stepInput [] i node s)) rest
  | _, _, _, _, _ => []

/-- The compact range: roots of the perfect subtrees, smallest first, one per set bit of `size`. -/
structure Frontier where
  size : Nat
  peaks : List Bytes

def Frontier.empty : Frontier := ⟨0, []⟩

def mergePeaks (H : Bytes → Bytes) : Nat → Bytes → List Bytes → List Bytes
  | n, h, p :: ps => if n % 2 == 1 then mergePeaks H (n / 2) (nodeHash H [] p h) ps else h :: p :: ps
  | _, h, [] => [h]

/-- Append one entry: one leaf hash plus one node hash per trailing one bit of `size` (amortized one). -/
def Frontier.push (H : Bytes → Bytes) (f : Frontier) (e : Bytes) : Frontier :=
  ⟨f.size + 1, mergePeaks H f.size (logLeaf H e) f.peaks⟩

def Frontier.root (H : Bytes → Bytes) (f : Frontier) : Bytes :=
  match f.peaks with
  | [] => H []
  | p :: ps => ps.foldl (fun acc q => nodeHash H [] q acc) p

def shiftWhileOdd : Nat → Nat → Nat → Nat × Nat
  | 0, fn, sn => (fn, sn)
  | fuel + 1, fn, sn => if fn % 2 == 1 then shiftWhileOdd fuel (fn / 2) (sn / 2) else (fn, sn)

def shiftWhileEven : Nat → Nat → Nat → Nat × Nat
  | 0, fn, sn => (fn, sn)
  | fuel + 1, fn, sn => if fn % 2 == 0 && fn != 0 then shiftWhileEven fuel (fn / 2) (sn / 2) else (fn, sn)

/-- RFC 9162 §2.1.4.2 step 6. -/
def consFold (H : Bytes → Bytes) : Nat → Nat → Bytes → Bytes → List Bytes → Option (Bytes × Bytes × Nat)
  | _, sn, fr, sr, [] => some (fr, sr, sn)
  | fn, sn, fr, sr, c :: cs =>
    if sn == 0 then none
    else if fn % 2 == 1 || fn == sn then
      let (a, b) := if fn % 2 == 1 then (fn, sn) else shiftWhileEven logFuel fn sn
      consFold H (a / 2) (b / 2) (nodeHash H [] c fr) (nodeHash H [] c sr) cs
    else consFold H (fn / 2) (sn / 2) fr (nodeHash H [] sr c) cs

/-- RFC 9162 §2.1.4.2: the log of size `n` with root `r2` extends the log of size `m` with root `r1`.
    Proof hashes are 64 bytes: the first one starts both folds, so no hash input around it fixes its width. -/
def verifyConsistency (H : Bytes → Bytes) (m n : Nat) (r1 r2 : Bytes) (proof : List Bytes) : Bool :=
  if m == 0 then proof.isEmpty && r1 == H []
  else if m == n then proof.isEmpty && r1 == r2
  else if n < m || proof.isEmpty || proof.any (·.length != 64) then false
  else
    let path := if m &&& (m - 1) == 0 then r1 :: proof else proof
    match path with
    | [] => false
    | p :: ps =>
      let (fn, sn) := shiftWhileOdd logFuel (m - 1) (n - 1)
      match consFold H fn sn p p ps with
      | some (fr, sr, s) => fr == r1 && sr == r2 && s == 0
      | none => false

/-- The hash inputs `verifyConsistency` feeds `consFold`. -/
def consInputs (H : Bytes → Bytes) (m n : Nat) (r1 : Bytes) (proof : List Bytes) : List Bytes :=
  match (if m &&& (m - 1) == 0 then r1 :: proof else proof) with
  | [] => []
  | p :: ps =>
    let (fn, sn) := shiftWhileOdd logFuel (m - 1) (n - 1)
    go fn sn p p ps
where
  go : Nat → Nat → Bytes → Bytes → List Bytes → List Bytes
    | _, _, _, _, [] => []
    | fn, sn, fr, sr, c :: cs =>
      if fn % 2 == 1 || fn == sn then
        let (a, b) := if fn % 2 == 1 then (fn, sn) else shiftWhileEven logFuel fn sn
        nodeHash id [] c fr :: nodeHash id [] c sr ::
          go (a / 2) (b / 2) (nodeHash H [] c fr) (nodeHash H [] c sr) cs
      else nodeHash id [] sr c :: go (fn / 2) (sn / 2) fr (nodeHash H [] sr c) cs

/-! ### §A helpers (this file's own; nothing here is a product lemma) -/

theorem pairUp_length (H : Bytes → Bytes) : ∀ xs : List Bytes, (pairUp H [] xs).length = (xs.length + 1) / 2
  | [] => rfl
  | [_] => by simp [pairUp]
  | _ :: _ :: rest => by
    have := pairUp_length H rest
    simp only [pairUp, List.length_cons]
    omega

theorem pairUp_getElem?_pair (H : Bytes → Bytes) : ∀ (xs : List Bytes) (k : Nat) (a b : Bytes),
    xs[2 * k]? = some a → xs[2 * k + 1]? = some b → (pairUp H [] xs)[k]? = some (nodeHash H [] a b)
  | [], _, _, _, ha, _ => by simp at ha
  | [_], _, _, _, _, hb => by simp at hb
  | x :: y :: rest, 0, a, b, ha, hb => by
    simp at ha hb
    subst ha; subst hb
    simp [pairUp]
  | x :: y :: rest, k + 1, a, b, ha, hb => by
    rw [show 2 * (k + 1) = 2 * k + 1 + 1 by omega] at ha
    rw [show 2 * (k + 1) + 1 = 2 * k + 1 + 1 + 1 by omega] at hb
    have h := pairUp_getElem?_pair H rest k a b (by simpa using ha) (by simpa using hb)
    simpa [pairUp] using h

theorem pairUp_getElem?_carry (H : Bytes → Bytes) : ∀ (xs : List Bytes) (k : Nat) (a : Bytes),
    xs.length = 2 * k + 1 → xs[2 * k]? = some a → (pairUp H [] xs)[k]? = some a
  | [], _, _, h, _ => by simp at h
  | [x], 0, a, _, ha => by simpa [pairUp] using ha
  | [x], k + 1, _, h, _ => by simp at h
  | x :: y :: rest, 0, _, h, _ => by simp at h
  | x :: y :: rest, k + 1, a, h, ha => by
    rw [show 2 * (k + 1) = 2 * k + 1 + 1 by omega] at ha
    have h' : rest.length = 2 * k + 1 := by simp at h; omega
    have := pairUp_getElem?_carry H rest k a h' (by simpa using ha)
    simpa [pairUp] using this

theorem mem_pairUp (H : Bytes → Bytes) : ∀ (xs : List Bytes) (x : Bytes), x ∈ pairUp H [] xs →
    (∃ a b, x = nodeHash H [] a b) ∨ x ∈ xs
  | [], x, h => by simp [pairUp] at h
  | [y], x, h => Or.inr (by simpa [pairUp] using h)
  | a :: b :: rest, x, h => by
    simp only [pairUp, List.mem_cons] at h
    rcases h with h | h
    · exact Or.inl ⟨a, b, h⟩
    · rcases mem_pairUp H rest x h with h' | h'
      · exact Or.inl h'
      · exact Or.inr (by simp [h'])

theorem pairUp_len64 {H : Bytes → Bytes} (hl : ∀ x, (H x).length = 64) {xs : List Bytes}
    (h : ∀ x ∈ xs, x.length = 64) : ∀ x ∈ pairUp H [] xs, x.length = 64 := by
  intro x hx
  rcases mem_pairUp H xs x hx with ⟨a, b, rfl⟩ | h'
  · exact hl _
  · exact h x h'

theorem treeRoot_succ (H : Bytes → Bytes) {xs : List Bytes} (h : 2 ≤ xs.length) (f : Nat) :
    treeRoot H [] (f + 1) xs = treeRoot H [] f (pairUp H [] xs) := by
  match xs, h with
  | a :: b :: rest, _ => rfl

theorem pathRoot_small {H : Bytes → Bytes} {f i count : Nat} {node : Bytes} {path : List Bytes}
    (h : count ≤ 1) : pathRoot H [] (f + 1) i count node path = if path.isEmpty then some node else none := by
  cases path <;> simp [pathRoot, h]

theorem pathRoot_carry {H : Bytes → Bytes} {f i count : Nat} {node : Bytes} {path : List Bytes}
    (h1 : ¬ count ≤ 1) (hc : (i % 2 == 0 && i + 1 == count) = true) :
    pathRoot H [] (f + 1) i count node path = pathRoot H [] f (i / 2) ((count + 1) / 2) node path := by
  have hc' : i % 2 = 0 ∧ i + 1 = count := by simpa using hc
  cases path <;> simp [pathRoot, h1, hc']

theorem pathRoot_step {H : Bytes → Bytes} {f i count : Nat} {node s : Bytes} {rest : List Bytes}
    (h1 : ¬ count ≤ 1) (hc : ¬ (i % 2 == 0 && i + 1 == count) = true) :
    pathRoot H [] (f + 1) i count node (s :: rest) =
      pathRoot H [] f (i / 2) ((count + 1) / 2) (H (stepInput [] i node s)) rest := by
  rw [pathRoot, if_neg h1, if_neg hc]

theorem pathRoot_step_nil {H : Bytes → Bytes} {f i count : Nat} {node : Bytes}
    (h1 : ¬ count ≤ 1) (hc : ¬ (i % 2 == 0 && i + 1 == count) = true) :
    pathRoot H [] (f + 1) i count node [] = none := by
  rw [pathRoot, if_neg h1, if_neg hc]

theorem pathInputs_nil (H : Bytes → Bytes) (f i n : Nat) (node : Bytes) : pathInputs H f i n node [] = [] := by
  cases f <;> simp [pathInputs]

theorem pathInputs_carry {H : Bytes → Bytes} {f i n : Nat} {node s : Bytes} {rest : List Bytes}
    (hc : (i % 2 == 0 && i + 1 == n) = true) :
    pathInputs H (f + 1) i n node (s :: rest) = pathInputs H f (i / 2) ((n + 1) / 2) node (s :: rest) := by
  rw [pathInputs, if_pos hc]

theorem pathInputs_step {H : Bytes → Bytes} {f i n : Nat} {node s : Bytes} {rest : List Bytes}
    (hc : ¬ (i % 2 == 0 && i + 1 == n) = true) :
    pathInputs H (f + 1) i n node (s :: rest) =
      stepInput [] i node s :: pathInputs H f (i / 2) ((n + 1) / 2) (H (stepInput [] i node s)) rest := by
  rw [pathInputs, if_neg hc]

/-- A pair of siblings' node input `1 :: (b0 ++ b1)` sits in the level inputs. -/
theorem node_mem_levelInputs {H : Bytes → Bytes} {f : Nat} {M : List Bytes} {k : Nat} {b0 b1 : Bytes}
    (h0 : M[2 * k]? = some b0) (h1 : M[2 * k + 1]? = some b1) :
    (1 :: (b0 ++ b1)) ∈ levelInputs H (f + 1) M := by
  have hp := pairUp_getElem?_pair id M k b0 b1 h0 h1
  have hm : nodeHash id [] b0 b1 ∈ pairUp id [] M := List.mem_of_getElem? hp
  exact List.mem_append_left _ hm

/-- The path fold, run against the log's own levels: an accepted path puts the leaf where the log has it. -/
theorem path_descent {H : Bytes → Bytes} (hl : ∀ x, (H x).length = 64) {L : List Bytes}
    (hg : breakIn H L = none) :
    ∀ (f : Nat) (M : List Bytes) (i : Nat) (a : Bytes) (p : List Bytes) (r : Bytes),
      (∀ x ∈ M, x.length = 64) → a.length = 64 → i < M.length →
      (∀ x ∈ levelInputs H f M, x ∈ L) → (∀ x ∈ pathInputs H f i M.length a p, x ∈ L) →
      pathRoot H [] f i M.length a p = some r → treeRoot H [] f M = r → M[i]? = some a := by
  intro f
  induction f with
  | zero => intro M i a p r _ _ _ _ _ hp _; simp [pathRoot] at hp
  | succ f ih =>
    intro M i a p r hM ha hi hL hP hp hr
    by_cases h1 : M.length ≤ 1
    · obtain ⟨x, rfl⟩ := List.length_eq_one_iff.mp (show M.length = 1 by omega)
      have hi0 : i = 0 := by simp at hi; omega
      subst hi0
      rw [pathRoot_small h1] at hp
      split at hp
      · have hax : a = r := (Option.some.inj hp)
        have hxr : x = r := by simpa [treeRoot] using hr
        simp [hax, hxr]
      · simp at hp
    · have h2 : 2 ≤ M.length := by omega
      have hr' : treeRoot H [] f (pairUp H [] M) = r := by rw [← treeRoot_succ H h2 f]; exact hr
      have hM' : ∀ x ∈ pairUp H [] M, x.length = 64 := pairUp_len64 hl hM
      have hlen' : (pairUp H [] M).length = (M.length + 1) / 2 := pairUp_length H M
      have hL' : ∀ x ∈ levelInputs H f (pairUp H [] M), x ∈ L :=
        fun x hx => hL x (List.mem_append_right _ hx)
      by_cases hc : (i % 2 == 0 && i + 1 == M.length) = true
      · rw [pathRoot_carry h1 hc] at hp
        rw [← hlen'] at hp
        have hP' : ∀ x ∈ pathInputs H f (i / 2) (pairUp H [] M).length a p, x ∈ L := by
          intro x hx
          rw [hlen'] at hx
          cases p with
          | nil => rw [pathInputs_nil] at hx; simp at hx
          | cons s rest => exact hP x (by rw [pathInputs_carry hc]; exact hx)
        have hi2 : M.length = 2 * (i / 2) + 1 := by simp at hc; omega
        have key := ih (pairUp H [] M) (i / 2) a p r hM' ha (by omega) hL' hP' hp hr'
        obtain ⟨b0, hb0⟩ : ∃ b0, M[i]? = some b0 := ⟨M[i], List.getElem?_eq_getElem hi⟩
        have e2 : 2 * (i / 2) = i := by simp at hc; omega
        have := pairUp_getElem?_carry H M (i / 2) b0 hi2 (by rw [e2]; exact hb0)
        rw [this] at key
        rw [hb0, Option.some.inj key]
      · cases p with
        | nil => rw [pathRoot_step_nil h1 hc] at hp; simp at hp
        | cons s rest =>
          rw [pathRoot_step h1 hc, ← hlen'] at hp
          have ha' : (H (stepInput [] i a s)).length = 64 := hl _
          rw [pathInputs_step hc] at hP
          have hP' : ∀ x ∈ pathInputs H f (i / 2) (pairUp H [] M).length (H (stepInput [] i a s)) rest, x ∈ L :=
            fun x hx => hP x (List.mem_cons_of_mem _ (by rw [hlen'] at hx; exact hx))
          have hx0 : stepInput [] i a s ∈ L := hP _ (List.mem_cons_self ..)
          have key := ih (pairUp H [] M) (i / 2) (H (stepInput [] i a s)) rest r hM' ha' (by omega) hL' hP'
            hp hr'
          have hnc : ¬ (i % 2 = 0 ∧ i + 1 = M.length) := by simpa using hc
          by_cases he : i % 2 = 0
          · have hi1 : i + 1 < M.length := by omega
            obtain ⟨b0, hb0⟩ : ∃ b0, M[i]? = some b0 := ⟨M[i], List.getElem?_eq_getElem hi⟩
            obtain ⟨b1, hb1⟩ : ∃ b1, M[i + 1]? = some b1 := ⟨M[i + 1], List.getElem?_eq_getElem hi1⟩
            have e2 : 2 * (i / 2) = i := by omega
            have hb0' : M[2 * (i / 2)]? = some b0 := by rw [e2]; exact hb0
            have hb1' : M[2 * (i / 2) + 1]? = some b1 := by rw [e2]; exact hb1
            have hpair := pairUp_getElem?_pair H M (i / 2) b0 b1 hb0' hb1'
            rw [hpair] at key
            have hy0 : (1 :: (b0 ++ b1)) ∈ L := hL _ (node_mem_levelInputs hb0' hb1')
            have heq : H (stepInput [] i a s) = H (1 :: (b0 ++ b1)) := (Option.some.inj key).symm
            have hxy := inj_of_none hg hx0 hy0 heq
            simp [stepInput, he] at hxy
            have hb0l : b0.length = 64 := hM b0 (List.mem_of_getElem? hb0)
            have := (List.append_inj hxy (by rw [ha, hb0l])).1
            rw [hb0, this]
          · have he1 : i % 2 = 1 := by omega
            obtain ⟨b0, hb0⟩ : ∃ b0, M[i - 1]? = some b0 := ⟨M[i - 1], List.getElem?_eq_getElem (by omega)⟩
            obtain ⟨b1, hb1⟩ : ∃ b1, M[i]? = some b1 := ⟨M[i], List.getElem?_eq_getElem hi⟩
            have hb0' : M[2 * (i / 2)]? = some b0 := by rw [show 2 * (i / 2) = i - 1 by omega]; exact hb0
            have hb1' : M[2 * (i / 2) + 1]? = some b1 := by rw [show 2 * (i / 2) + 1 = i by omega]; exact hb1
            have hpair := pairUp_getElem?_pair H M (i / 2) b0 b1 hb0' hb1'
            rw [hpair] at key
            have hy0 : (1 :: (b0 ++ b1)) ∈ L := hL _ (node_mem_levelInputs hb0' hb1')
            have heq : H (stepInput [] i a s) = H (1 :: (b0 ++ b1)) := (Option.some.inj key).symm
            have hxy := inj_of_none hg hx0 hy0 heq
            simp [stepInput, he1] at hxy
            have hb1l : b1.length = 64 := hM b1 (List.mem_of_getElem? hb1)
            have := (List.append_inj' hxy (by rw [ha, hb1l])).2
            rw [hb1, this]

theorem path_exists_single (H : Bytes → Bytes) (f : Nat) (M : List Bytes) (i : Nat) (a : Bytes)
    (ha : M[i]? = some a) (h1 : M.length ≤ 1) :
    ∃ p, pathRoot H [] (f + 1) i M.length a p = some (treeRoot H [] (f + 1) M) := by
  obtain ⟨x, rfl⟩ : ∃ x, M = [x] := by
    have hi := (List.getElem?_eq_some_iff.mp ha).1
    exact List.length_eq_one_iff.mp (by omega)
  have hi : i = 0 := by
    have := (List.getElem?_eq_some_iff.mp ha).1
    simp at this; omega
  subst hi
  have hxa : x = a := by simpa using ha
  subst hxa
  exact ⟨[], by rw [pathRoot_small h1]; simp [treeRoot]⟩

theorem path_exists (H : Bytes → Bytes) : ∀ (f : Nat) (M : List Bytes) (i : Nat) (a : Bytes),
    M[i]? = some a → M.length ≤ 2 ^ f →
    ∃ p, pathRoot H [] (f + 1) i M.length a p = some (treeRoot H [] (f + 1) M) := by
  intro f
  induction f with
  | zero => intro M i a ha hl; exact path_exists_single H 0 M i a ha (by simpa using hl)
  | succ f ih =>
    intro M i a ha hl
    by_cases h1 : M.length ≤ 1
    · exact path_exists_single H _ M i a ha h1
    · have h2 : 2 ≤ M.length := by omega
      have hi : i < M.length := (List.getElem?_eq_some_iff.mp ha).1
      have hlen' : (pairUp H [] M).length = (M.length + 1) / 2 := pairUp_length H M
      have hpow : 2 ^ (f + 1) = 2 * 2 ^ f := by rw [Nat.pow_succ]; omega
      obtain ⟨a', ha'⟩ : ∃ a', (pairUp H [] M)[i / 2]? = some a' :=
        ⟨(pairUp H [] M)[i / 2]'(by omega), List.getElem?_eq_getElem (by omega)⟩
      obtain ⟨p', hp'⟩ := ih (pairUp H [] M) (i / 2) a' ha' (by omega)
      rw [hlen'] at hp'
      rw [treeRoot_succ H h2 (f + 1)]
      by_cases hc : (i % 2 == 0 && i + 1 == M.length) = true
      · have hi2 : M.length = 2 * (i / 2) + 1 := by simp at hc; omega
        have e2 : 2 * (i / 2) = i := by simp at hc; omega
        have := pairUp_getElem?_carry H M (i / 2) a hi2 (by rw [e2]; exact ha)
        rw [ha'] at this
        have hh : a' = a := Option.some.inj this
        subst hh
        exact ⟨p', by rw [pathRoot_carry h1 hc]; exact hp'⟩
      · have hnc : ¬ (i % 2 = 0 ∧ i + 1 = M.length) := by simpa using hc
        by_cases he : i % 2 = 0
        · have hi1 : i + 1 < M.length := by omega
          obtain ⟨b1, hb1⟩ : ∃ b1, M[i + 1]? = some b1 := ⟨M[i + 1], List.getElem?_eq_getElem hi1⟩
          have e2 : 2 * (i / 2) = i := by omega
          have hpair := pairUp_getElem?_pair H M (i / 2) a b1 (by rw [e2]; exact ha) (by rw [e2]; exact hb1)
          rw [ha'] at hpair
          have hh : a' = H (stepInput [] i a b1) := by
            have := Option.some.inj hpair
            rw [this]; simp [nodeHash, stepInput, he]
          exact ⟨b1 :: p', by rw [pathRoot_step h1 hc, ← hh]; exact hp'⟩
        · have he1 : i % 2 = 1 := by omega
          obtain ⟨b0, hb0⟩ : ∃ b0, M[i - 1]? = some b0 := ⟨M[i - 1], List.getElem?_eq_getElem (by omega)⟩
          have hpair := pairUp_getElem?_pair H M (i / 2) b0 a (by rw [show 2 * (i / 2) = i - 1 by omega]; exact hb0)
            (by rw [show 2 * (i / 2) + 1 = i by omega]; exact ha)
          rw [ha'] at hpair
          have hh : a' = H (stepInput [] i a b0) := by
            have := Option.some.inj hpair
            rw [this]; simp [nodeHash, stepInput, he1]
          exact ⟨b0 :: p', by rw [pathRoot_step h1 hc, ← hh]; exact hp'⟩

/-! ### Frontier helpers -/

theorem list_snoc_induction {α : Type} {P : List α → Prop} (h0 : P []) (hs : ∀ l a, P l → P (l ++ [a])) :
    ∀ l, P l := by
  intro l
  have : ∀ r : List α, P r.reverse := by
    intro r
    induction r with
    | nil => exact h0
    | cons a r ih => simpa using hs _ a ih
  simpa using this l.reverse

theorem pairUp_append_even (H : Bytes → Bytes) : ∀ (A B : List Bytes), A.length % 2 = 0 →
    pairUp H [] (A ++ B) = pairUp H [] A ++ pairUp H [] B
  | [], B, _ => by simp [pairUp]
  | [_], _, h => by simp at h
  | a :: b :: rest, B, h => by
    have := pairUp_append_even H rest B (by simp at h; omega)
    simp [pairUp, this]

/-- The frontier's peaks, level by level: an odd level's last node is a peak, the rest pairs up. -/
def peaksOf (H : Bytes → Bytes) (M : List Bytes) : List Bytes :=
  if M.length = 0 then []
  else if M.length % 2 = 1 then M.getLastD [] :: peaksOf H (pairUp H [] M.dropLast)
  else peaksOf H (pairUp H [] M)
termination_by M.length
decreasing_by
  all_goals
    have h1 := pairUp_length H M.dropLast
    have h2 : M.dropLast.length = M.length - 1 := by simp
    have h3 := pairUp_length H M
    omega

theorem peaksOf_nil (H : Bytes → Bytes) : peaksOf H [] = [] := by
  rw [peaksOf]; simp

theorem peaksOf_odd (H : Bytes → Bytes) (M : List Bytes) (y : Bytes) (he : M.length % 2 = 0) :
    peaksOf H (M ++ [y]) = y :: peaksOf H (pairUp H [] M) := by
  have h1 : ¬ (M ++ [y]).length = 0 := by simp
  have h2 : (M ++ [y]).length % 2 = 1 := by simp; omega
  rw [peaksOf, if_neg h1, if_pos h2]
  simp

theorem peaksOf_even (H : Bytes → Bytes) (M : List Bytes) (he : M.length % 2 = 0) :
    peaksOf H M = peaksOf H (pairUp H [] M) := by
  by_cases h0 : M.length = 0
  · have : M = [] := List.length_eq_zero_iff.mp h0
    subst this
    simp [peaksOf_nil, pairUp]
  · rw [peaksOf, if_neg h0, if_neg (by omega)]

theorem mergePeaks_peaksOf (H : Bytes → Bytes) : ∀ (n : Nat) (M : List Bytes) (h : Bytes), M.length = n →
    mergePeaks H n h (peaksOf H M) = peaksOf H (M ++ [h]) := by
  intro n
  induction n using Nat.strongRecOn with
  | _ n ih =>
    intro M h hM
    by_cases hp : n % 2 = 0
    · rw [peaksOf_odd H M h (by omega), peaksOf_even H M (by omega)]
      generalize peaksOf H (pairUp H [] M) = ps
      cases ps with
      | nil => simp [mergePeaks]
      | cons p ps => simp [mergePeaks, hp]
    · obtain ⟨M', y, rfl⟩ : ∃ M' y, M = M' ++ [y] := by
        rcases List.eq_nil_or_concat M with h0 | ⟨L, b, hb⟩
        · subst h0; simp at hM; omega
        · exact ⟨L, b, by rw [hb, List.concat_eq_append]⟩
      have hM' : M'.length % 2 = 0 := by simp at hM; omega
      rw [peaksOf_odd H M' y hM']
      have hlen := pairUp_length H M'
      have := ih (n / 2) (by omega) (pairUp H [] M') (nodeHash H [] y h) (by simp at hM; omega)
      have e : M' ++ [y] ++ [h] = M' ++ [y, h] := by simp
      have hp1 : n % 2 = 1 := by omega
      rw [e, peaksOf_even H (M' ++ [y, h]) (by simp only [List.length_append, List.length_cons, List.length_nil]; omega),
        pairUp_append_even H M' [y, h] hM']
      simp [mergePeaks, hp1, this, pairUp]

theorem foldAcc_peaksOf (H : Bytes → Bytes) : ∀ (f : Nat) (M : List Bytes) (x : Bytes),
    M.length + 1 ≤ 2 ^ f →
    (peaksOf H M).foldl (fun acc q => nodeHash H [] q acc) x = treeRoot H [] f (M ++ [x]) := by
  intro f
  induction f with
  | zero =>
    intro M x hM
    have : M = [] := List.length_eq_zero_iff.mp (by simpa using hM)
    subst this
    simp [peaksOf_nil, treeRoot]
  | succ f ih =>
    intro M x hM
    have hpow : 2 ^ (f + 1) = 2 * 2 ^ f := by rw [Nat.pow_succ]; omega
    by_cases hM0 : M = []
    · subst hM0; simp [peaksOf_nil, treeRoot]
    rcases Nat.mod_two_eq_zero_or_one M.length with he | ho
    · have hlen := pairUp_length H M
      have hpos : 0 < M.length := List.length_pos_iff.mpr hM0
      rw [peaksOf_even H M he, treeRoot_succ H (by simp only [List.length_append, List.length_cons, List.length_nil]; omega) f,
        pairUp_append_even H M [x] he]
      have := ih (pairUp H [] M) x (by omega)
      simpa [pairUp] using this
    · obtain ⟨M', y, rfl⟩ : ∃ M' y, M = M' ++ [y] := by
        rcases List.eq_nil_or_concat M with h0 | ⟨L, b, hb⟩
        · exact absurd h0 hM0
        · exact ⟨L, b, by rw [hb, List.concat_eq_append]⟩
      have hM' : M'.length % 2 = 0 := by simp at ho; omega
      have hlen := pairUp_length H M'
      rw [peaksOf_odd H M' y hM', List.foldl_cons]
      have e : M' ++ [y] ++ [x] = M' ++ [y, x] := by simp
      rw [e, treeRoot_succ H (by simp only [List.length_append, List.length_cons, List.length_nil]; omega) f,
        pairUp_append_even H M' [y, x] hM']
      have := ih (pairUp H [] M') (nodeHash H [] y x) (by simp at hM; omega)
      simpa [pairUp] using this

theorem root_peaksOf (H : Bytes → Bytes) : ∀ (f : Nat) (M : List Bytes), M ≠ [] → M.length ≤ 2 ^ f →
    Frontier.root H ⟨M.length, peaksOf H M⟩ = treeRoot H [] f M := by
  intro f
  induction f with
  | zero =>
    intro M hne hM
    obtain ⟨x, rfl⟩ := List.length_eq_one_iff.mp (show M.length = 1 from by
      have := List.length_pos_iff.mpr hne; simp at hM; omega)
    have e : peaksOf H [x] = [x] := by
      have := peaksOf_odd H [] x rfl
      simpa [pairUp, peaksOf_nil] using this
    simp [Frontier.root, e, treeRoot]
  | succ f ih =>
    intro M hne hM
    have hpow : 2 ^ (f + 1) = 2 * 2 ^ f := by rw [Nat.pow_succ]; omega
    have hpos : 0 < M.length := List.length_pos_iff.mpr hne
    rcases Nat.mod_two_eq_zero_or_one M.length with he | ho
    · have hlen := pairUp_length H M
      rw [treeRoot_succ H (by omega) f, ← ih (pairUp H [] M) (by
        intro h0; have := congrArg List.length h0; rw [hlen, List.length_nil] at this; omega) (by omega)]
      simp only [Frontier.root, peaksOf_even H M he]
    · obtain ⟨M', y, rfl⟩ : ∃ M' y, M = M' ++ [y] := by
        rcases List.eq_nil_or_concat M with h0 | ⟨L, b, hb⟩
        · exact absurd h0 hne
        · exact ⟨L, b, by rw [hb, List.concat_eq_append]⟩
      have hM' : M'.length % 2 = 0 := by simp at ho; omega
      have := foldAcc_peaksOf H (f + 1) M' y (by simp at hM; omega)
      rw [peaksOf_even H M' hM'] at this
      simp only [Frontier.root, peaksOf_odd H M' y hM']
      exact this

/-! ### Level trees: the hash tree behind `treeRoot`, with its leaves kept -/

inductive LT where
  | leaf (e : Bytes)
  | node (l r : LT)

def LT.root (H : Bytes → Bytes) : LT → Bytes
  | .leaf e => H (0 :: e)
  | .node l r => H (1 :: (l.root H ++ r.root H))

def LT.inputs (H : Bytes → Bytes) : LT → List Bytes
  | .leaf e => [0 :: e]
  | .node l r => (1 :: (l.root H ++ r.root H)) :: (l.inputs H ++ r.inputs H)

def LT.leaves : LT → List Bytes
  | .leaf e => [e]
  | .node l r => l.leaves ++ r.leaves

def pairT : List LT → List LT
  | a :: b :: rest => .node a b :: pairT rest
  | xs => xs

def treeT : Nat → List LT → Option LT
  | _, [t] => some t
  | 0, _ => none
  | f + 1, ts => treeT f (pairT ts)

theorem treeT_single (f : Nat) (a : LT) : treeT f [a] = some a := by
  cases f <;> rfl

theorem pairT_root (H : Bytes → Bytes) : ∀ ts : List LT,
    (pairT ts).map (LT.root H) = pairUp H [] (ts.map (LT.root H))
  | [] => rfl
  | [_] => rfl
  | a :: b :: rest => by
    simp only [pairT, pairUp, List.map_cons, pairT_root H rest]
    try rfl

theorem pairT_leaves : ∀ ts : List LT, (pairT ts).flatMap LT.leaves = ts.flatMap LT.leaves
  | [] => rfl
  | [_] => rfl
  | a :: b :: rest => by
    simp [pairT, LT.leaves, pairT_leaves rest]

theorem pairT_inputs {H : Bytes → Bytes} {L : List Bytes} : ∀ ts : List LT,
    (∀ t ∈ ts, ∀ x ∈ t.inputs H, x ∈ L) → (∀ x ∈ pairUp id [] (ts.map (LT.root H)), x ∈ L) →
    ∀ t ∈ pairT ts, ∀ x ∈ t.inputs H, x ∈ L
  | [], _, _ => by simp [pairT]
  | [a], h, _ => by simpa [pairT] using h
  | a :: b :: rest, h, h2 => by
    intro t ht x hx
    simp only [pairT, List.mem_cons] at ht
    rcases ht with rfl | ht
    · simp only [LT.inputs, List.mem_cons, List.mem_append] at hx
      rcases hx with rfl | hx | hx
      · exact h2 _ (by simp [pairUp, nodeHash, LT.root])
      · exact h a (by simp) x hx
      · exact h b (by simp) x hx
    · exact pairT_inputs rest (fun t ht => h t (by simp [ht]))
        (fun x hx => h2 x (by simp [pairUp, hx])) t ht x hx

theorem treeT_nil : ∀ f, treeT f [] = none
  | 0 => rfl
  | f + 1 => by
    show treeT f (pairT []) = none
    exact treeT_nil f

theorem treeT_leaves : ∀ (f : Nat) (ts : List LT) (t : LT), treeT f ts = some t → t.leaves = ts.flatMap LT.leaves
  | f, [], t, h => by rw [treeT_nil] at h; simp at h
  | f, [a], t, h => by
    have : a = t := Option.some.inj (by rw [← treeT_single f a]; exact h)
    simp [this]
  | 0, a :: b :: rest, t, h => by simp [treeT] at h
  | f + 1, a :: b :: rest, t, h => by
    have h' : treeT f (pairT (a :: b :: rest)) = some t := h
    rw [treeT_leaves f _ t h', pairT_leaves]

theorem treeT_root {H : Bytes → Bytes} : ∀ (f : Nat) (ts : List LT) (t : LT), treeT f ts = some t →
    treeRoot H [] f (ts.map (LT.root H)) = t.root H
  | f, [], t, h => by rw [treeT_nil] at h; simp at h
  | f, [a], t, h => by
    have : a = t := Option.some.inj (by rw [← treeT_single f a]; exact h)
    simp [this, treeRoot]
  | 0, a :: b :: rest, t, h => by simp [treeT] at h
  | f + 1, a :: b :: rest, t, h => by
    have h' : treeT f (pairT (a :: b :: rest)) = some t := h
    have := treeT_root (H := H) f _ t h'
    rw [pairT_root] at this
    rw [treeRoot_succ H (by simp only [List.length_map, List.length_cons]; omega) f]
    exact this

theorem treeT_inputs {H : Bytes → Bytes} {L : List Bytes} : ∀ (f : Nat) (ts : List LT) (t : LT),
    treeT f ts = some t → (∀ t ∈ ts, ∀ x ∈ t.inputs H, x ∈ L) →
    (∀ x ∈ levelInputs H f (ts.map (LT.root H)), x ∈ L) → ∀ x ∈ t.inputs H, x ∈ L
  | f, [], t, h, _, _ => by rw [treeT_nil] at h; simp at h
  | f, [a], t, h, hI, _ => by
    have : a = t := Option.some.inj (by rw [← treeT_single f a]; exact h)
    subst this
    exact hI _ (by simp)
  | 0, a :: b :: rest, t, h, _, _ => by simp [treeT] at h
  | f + 1, a :: b :: rest, t, h, hI, hL => by
    have h' : treeT f (pairT (a :: b :: rest)) = some t := h
    have hL' : ∀ x ∈ pairUp id [] ((a :: b :: rest).map (LT.root H)), x ∈ L :=
      fun x hx => hL x (List.mem_append_left _ hx)
    refine treeT_inputs f _ t h' (pairT_inputs _ hI hL') ?_
    rw [pairT_root]
    exact fun x hx => hL x (List.mem_append_right _ hx)

theorem treeT_exists : ∀ (f : Nat) (ts : List LT), ts ≠ [] → ts.length ≤ 2 ^ f → ∃ t, treeT f ts = some t
  | f, [a], _, _ => ⟨a, treeT_single f a⟩
  | 0, a :: b :: rest, _, h => by simp at h
  | f + 1, a :: b :: rest, _, h => by
    have hlen : (pairT (a :: b :: rest)).length = ((a :: b :: rest).length + 1) / 2 := by
      have := congrArg List.length (pairT_root (H := fun x => x) (a :: b :: rest))
      simpa [pairUp_length] using this
    have hpow : 2 ^ (f + 1) = 2 * 2 ^ f := by rw [Nat.pow_succ]; omega
    have hne : pairT (a :: b :: rest) ≠ [] := by
      intro h0; rw [h0] at hlen; simp only [List.length_nil, List.length_cons] at hlen; omega
    exact treeT_exists f _ hne (by omega)
  | f, [], h, _ => absurd rfl h

theorem LT.root_len {H : Bytes → Bytes} (hl : ∀ x, (H x).length = 64) (t : LT) : (t.root H).length = 64 := by
  cases t <;> exact hl _

theorem LT.root_spec (H : Bytes → Bytes) (t : LT) : ∃ y ∈ t.inputs H, t.root H = H y ∧ y ≠ [] := by
  cases t with
  | leaf e => exact ⟨0 :: e, by simp [LT.inputs], rfl, by simp⟩
  | node l r => exact ⟨1 :: (l.root H ++ r.root H), by simp [LT.inputs], rfl, by simp⟩

theorem LT.inj {H : Bytes → Bytes} (hl : ∀ x, (H x).length = 64) {L : List Bytes} (hg : breakIn H L = none) :
    ∀ (t1 t2 : LT), (∀ x ∈ t1.inputs H, x ∈ L) → (∀ x ∈ t2.inputs H, x ∈ L) → t1.root H = t2.root H → t1 = t2
  | .leaf e1, .leaf e2, h1, h2, hr => by
    have := inj_of_none hg (x := 0 :: e1) (y := 0 :: e2) (h1 _ (by simp [LT.inputs])) (h2 _ (by simp [LT.inputs])) hr
    simp at this
    rw [this]
  | .leaf e1, .node l r, h1, h2, hr => by
    have := inj_of_none hg (x := 0 :: e1) (y := 1 :: (l.root H ++ r.root H))
      (h1 _ (by simp [LT.inputs])) (h2 _ (by simp [LT.inputs])) hr
    simp at this
  | .node l r, .leaf e2, h1, h2, hr => by
    have := inj_of_none hg (x := 1 :: (l.root H ++ r.root H)) (y := 0 :: e2)
      (h1 _ (by simp [LT.inputs])) (h2 _ (by simp [LT.inputs])) hr
    simp at this
  | .node a b, .node c d, h1, h2, hr => by
    have := inj_of_none hg (x := 1 :: (a.root H ++ b.root H)) (y := 1 :: (c.root H ++ d.root H))
      (h1 _ (by simp [LT.inputs])) (h2 _ (by simp [LT.inputs])) hr
    have hcons := (List.cons.inj this).2
    have hs := List.append_inj hcons (by rw [LT.root_len hl, LT.root_len hl])
    have e1 := LT.inj hl hg a c (fun x hx => h1 x (by simp [LT.inputs, hx])) (fun x hx => h2 x (by simp [LT.inputs, hx])) hs.1
    have e2 := LT.inj hl hg b d (fun x hx => h1 x (by simp [LT.inputs, hx])) (fun x hx => h2 x (by simp [LT.inputs, hx])) hs.2
    rw [e1, e2]

theorem log_tree {H : Bytes → Bytes} {L : List Bytes} (zs : List Bytes) (hne : zs ≠ [])
    (hlen : zs.length ≤ maxSize) (hsub : ∀ x ∈ logInputs H zs, x ∈ L) :
    ∃ t : LT, t.root H = logRoot H zs ∧ t.leaves = zs ∧ ∀ x ∈ t.inputs H, x ∈ L := by
  have hzne : zs.isEmpty = false := by
    cases zs with
    | nil => exact absurd rfl hne
    | cons => rfl
  have hne' : zs.map LT.leaf ≠ [] := by simpa using hne
  have hlen' : zs.length ≤ 2 ^ 63 - 1 := hlen
  obtain ⟨t, ht⟩ := treeT_exists 64 (zs.map LT.leaf) hne' (by simp; omega)
  have hm : (zs.map LT.leaf).map (LT.root H) = zs.map (logLeaf H) := by
    rw [List.map_map]; exact List.map_congr_left (fun e _ => rfl)
  have hfl : ∀ zs : List Bytes, (zs.map LT.leaf).flatMap LT.leaves = zs := by
    intro zs; induction zs with
    | nil => rfl
    | cons a r ih => simp [LT.leaves, ih]
  refine ⟨t, ?_, ?_, ?_⟩
  · have := treeT_root (H := H) 64 _ t ht
    rw [hm] at this
    rw [← this]; simp [logRoot, hzne, logFuel]
  · rw [treeT_leaves 64 _ t ht, hfl]
  · refine treeT_inputs 64 _ t ht ?_ ?_
    · intro t' ht' x hx
      obtain ⟨e, he, rfl⟩ := List.mem_map.mp ht'
      simp only [LT.inputs, List.mem_singleton] at hx
      subst hx
      exact hsub _ (List.mem_append_left _ (List.mem_cons_of_mem _ (List.mem_map.mpr ⟨e, he, rfl⟩)))
    · rw [hm]
      exact fun x hx => hsub x (List.mem_append_right _ hx)

/-- Log update correctness: the O(1)-amortized frontier gives the RFC 9162 root. -/
theorem frontier_root {H : Bytes → Bytes} (es : List Bytes) (hn : es.length ≤ maxSize) :
    (es.foldl (Frontier.push H) Frontier.empty).root H = logRoot H es := by
  have hf : ∀ es : List Bytes, es.foldl (Frontier.push H) Frontier.empty =
      ⟨es.length, peaksOf H (es.map (logLeaf H))⟩ := by
    refine list_snoc_induction (P := fun es : List Bytes => es.foldl (Frontier.push H) Frontier.empty =
      ⟨es.length, peaksOf H (es.map (logLeaf H))⟩) ?_ ?_
    · simp [Frontier.empty, peaksOf_nil]
    · intro es e ih
      rw [List.foldl_append, ih]
      have := mergePeaks_peaksOf H es.length (es.map (logLeaf H)) (logLeaf H e) (List.length_map _)
      simp [Frontier.push, this]
  rw [hf]
  by_cases h0 : es = []
  · subst h0; simp [Frontier.root, peaksOf_nil, logRoot]
  · have hne : es.isEmpty = false := by
      cases es with
      | nil => exact absurd rfl h0
      | cons => rfl
    have hn' : es.length ≤ 2 ^ 63 - 1 := hn
    have := root_peaksOf H 64 (es.map (logLeaf H)) (by simpa using h0) (by simp; omega)
    simpa [logRoot, hne, logFuel] using this

/-- Inclusion soundness. -/
theorem logInclusion_sound {H : Bytes → Bytes} (hl : HashLen H) (es : List Bytes) (i : Nat) (e : Bytes)
    (p : List Bytes) (hn : es.length ≤ maxSize) (h : verifyInclusion H (logRoot H es) es.length i e p = true) :
    es[i]? = some e ∨
      breakIn H (logLeaf id e :: pathInputs H logFuel i es.length (logLeaf H e) p ++ logInputs H es) ≠ none := by
  by_cases hg : breakIn H (logLeaf id e :: pathInputs H logFuel i es.length (logLeaf H e) p ++ logInputs H es) = none
  case neg => exact Or.inr hg
  left
  have hl64 : ∀ x, (H x).length = 64 := hl
  unfold verifyInclusion at h
  simp only [Bool.and_eq_true, decide_eq_true_eq, beq_iff_eq] at h
  obtain ⟨hi, hp⟩ := h
  have hne : es.isEmpty = false := by
    cases es with
    | nil => simp at hi
    | cons => rfl
  have hMl : (es.map (logLeaf H)).length = es.length := List.length_map _
  have hroot : logRoot H es = treeRoot H [] logFuel (es.map (logLeaf H)) := by simp [logRoot, hne]
  rw [hroot, ← hMl] at hp
  have key := path_descent hl64 hg logFuel (es.map (logLeaf H)) i (logLeaf H e) p _
    (by intro x hx; obtain ⟨y, _, rfl⟩ := List.mem_map.mp hx; exact hl64 _) (hl64 _) (by omega)
    (fun x hx => List.mem_append_right _ (List.mem_append_right _ hx))
    (fun x hx => List.mem_append_left _ (List.mem_cons_of_mem _ (by rw [← hMl]; exact hx))) hp rfl
  rw [List.getElem?_map] at key
  cases hy : es[i]? with
  | none => simp [hy] at key
  | some y =>
    rw [hy] at key
    have key' : H (0 :: y) = H (0 :: e) := Option.some.inj key
    have hym : logLeaf id y ∈ es.map (logLeaf id) := List.mem_map.mpr ⟨y, List.mem_of_getElem? hy, rfl⟩
    have h0 : (0 :: y) = (0 :: e) := inj_of_none hg
      (x := logLeaf id y) (y := logLeaf id e)
      (List.mem_append_right _ (List.mem_append_left _ (List.mem_cons_of_mem _ hym)))
      (List.mem_append_left _ (List.mem_cons_self ..)) key'
    rw [(List.cons.inj h0).2]

theorem logInclusion_complete {H : Bytes → Bytes} (es : List Bytes) (i : Nat) (hi : i < es.length)
    (hn : es.length ≤ maxSize) : ∃ p, verifyInclusion H (logRoot H es) es.length i es[i] p = true := by
  have hMl : (es.map (logLeaf H)).length = es.length := List.length_map _
  have hM : (es.map (logLeaf H))[i]? = some (logLeaf H es[i]) := by simp [List.getElem?_eq_getElem hi]
  have hn' : es.length ≤ 2 ^ 63 - 1 := hn
  obtain ⟨p, hp⟩ := path_exists H 63 (es.map (logLeaf H)) i _ hM (by rw [hMl]; omega)
  have hne : es.isEmpty = false := by
    cases es with
    | nil => simp at hi
    | cons => rfl
  rw [hMl] at hp
  refine ⟨p, ?_⟩
  simp only [verifyInclusion, Bool.and_eq_true, decide_eq_true_eq, beq_iff_eq]
  exact ⟨hi, by simpa [logRoot, hne, logFuel] using hp⟩

/-- Consistency soundness: an accepted proof means the old log is a prefix of the new (append-only). -/
theorem logConsistency_sound {H : Bytes → Bytes} (hl : HashLen H) (xs ys p : List Bytes)
    (hn : ys.length ≤ maxSize)
    (h : verifyConsistency H xs.length ys.length (logRoot H xs) (logRoot H ys) p = true) :
    xs <+: ys ∨
      breakIn H (consInputs H xs.length ys.length (logRoot H xs) p ++ logInputs H xs ++ logInputs H ys) ≠ none := by
  sorry

theorem logConsistency_complete {H : Bytes → Bytes} (xs zs : List Bytes) (hn : (xs ++ zs).length ≤ maxSize) :
    ∃ p, verifyConsistency H xs.length (xs ++ zs).length (logRoot H xs) (logRoot H (xs ++ zs)) p = true := by
  sorry

/-- Exports and the sweep: entries whose log root equals the head's are exactly the log. -/
theorem logRoot_binding {H : Bytes → Bytes} (hl : HashLen H) (xs ys : List Bytes)
    (hx : xs.length ≤ maxSize) (hy : ys.length ≤ maxSize) (h : logRoot H xs = logRoot H ys) :
    xs = ys ∨ breakIn H (logInputs H xs ++ logInputs H ys) ≠ none := by
  by_cases hg : breakIn H (logInputs H xs ++ logInputs H ys) = none
  case neg => exact Or.inr hg
  left
  have hl64 : ∀ x, (H x).length = 64 := hl
  have hxL : ∀ x ∈ logInputs H xs, x ∈ logInputs H xs ++ logInputs H ys := fun x hx => List.mem_append_left _ hx
  have hyL : ∀ x ∈ logInputs H ys, x ∈ logInputs H xs ++ logInputs H ys := fun x hx => List.mem_append_right _ hx
  have emp : ∀ zs : List Bytes, zs ≠ [] → zs.length ≤ maxSize →
      (∀ x ∈ logInputs H zs, x ∈ logInputs H xs ++ logInputs H ys) →
      ([] : Bytes) ∈ logInputs H xs ++ logInputs H ys → logRoot H zs = H [] → False := by
    intro zs hne hlen hsub hnil hr
    obtain ⟨t, htr, _, hti⟩ := log_tree zs hne hlen hsub
    obtain ⟨y0, hy0m, hy0e, hy0ne⟩ := LT.root_spec H t
    have := inj_of_none hg (x := y0) (y := []) (hti _ hy0m) hnil (by rw [← hy0e, htr, hr])
    exact hy0ne this
  have hnx : ([] : Bytes) ∈ logInputs H xs ++ logInputs H ys :=
    List.mem_append_left _ (List.mem_append_left _ (List.mem_cons_self ..))
  by_cases hx0 : xs = []
  · by_cases hy0 : ys = []
    · rw [hx0, hy0]
    · subst hx0
      exact (emp ys hy0 hy hyL hnx (by rw [← h]; simp [logRoot])).elim
  · by_cases hy0 : ys = []
    · subst hy0
      exact (emp xs hx0 hx hxL hnx (by rw [h]; simp [logRoot])).elim
    · obtain ⟨tx, htxr, htxl, htxi⟩ := log_tree xs hx0 hx hxL
      obtain ⟨ty, htyr, htyl, htyi⟩ := log_tree ys hy0 hy hyL
      have := LT.inj hl64 hg tx ty htxi htyi (by rw [htxr, htyr, h])
      rw [← htxl, ← htyl, this]

/-! ## §B  The map: binary sparse Merkle tree over 512-bit keys, a lone key's leaf lifted to its subtree root

    Empty subtree = `zeroDigest`; leaf = `H (0x02 ‖ K ‖ V)`; node = `H (0x03 ‖ L ‖ R)`; bit `i` of `K` is
    most-significant-first.  Keys and values are 64 bytes, and those widths are the leaf's only framing, so
    `find` and `insert` fail closed on a leaf of any other width.  No delete: a key once present stays present. -/

def bitAt (k : Bytes) (i : Nat) : Bool :=
  match k[i / 8]? with
  | some b => b.toNat / 2 ^ (7 - i % 8) % 2 == 1
  | none => false

def mapLeaf (H : Bytes → Bytes) (k v : Bytes) : Bytes := H (2 :: (k ++ v))
def mapNode (H : Bytes → Bytes) (l r : Bytes) : Bytes := H (3 :: (l ++ r))

def sized (k v : Bytes) : Bool := k.length == 64 && v.length == 64

/-- A proof is a pruned tree: the opened part of the map, everything else a stub carrying its hash.
    One key's proof is a path; a batch's is the union of paths (a multiproof). -/
inductive PTree where
  | empty
  | stub (h : Bytes)
  | leaf (k v : Bytes)
  | node (l r : PTree)

def PTree.hash (H : Bytes → Bytes) : PTree → Bytes
  | .empty => zeroDigest
  | .stub h => h
  | .leaf k v => mapLeaf H k v
  | .node l r => mapNode H (l.hash H) (r.hash H)

/-- Every hash input under a pruned tree (EMPTY and STUB hash nothing). -/
def PTree.inputs (H : Bytes → Bytes) : PTree → List Bytes
  | .leaf k v => [mapLeaf id k v]
  | .node l r => mapNode id (l.hash H) (r.hash H) :: l.inputs H ++ r.inputs H
  | _ => []

/-- The canonical map of a key-value list as a fully opened tree (fuel = remaining depth). -/
def mapTree : Nat → Nat → List (Bytes × Bytes) → PTree
  | _, _, [] => .empty
  | _, _, [(k, v)] => .leaf k v
  | 0, _, _ => .stub []
  | fuel + 1, d, kvs =>
    .node (mapTree fuel (d + 1) (kvs.filter fun kv => !bitAt kv.1 d))
      (mapTree fuel (d + 1) (kvs.filter fun kv => bitAt kv.1 d))

def mapRoot (H : Bytes → Bytes) (kvs : List (Bytes × Bytes)) : Bytes := (mapTree 512 0 kvs).hash H

def MapWf (kvs : List (Bytes × Bytes)) : Prop :=
  (kvs.map (·.1)).Nodup ∧ ∀ kv ∈ kvs, kv.1.length = 64 ∧ kv.2.length = 64

def lookup (kvs : List (Bytes × Bytes)) (k : Bytes) : Option Bytes := (kvs.find? (·.1 == k)).map (·.2)

def upsert (kvs : List (Bytes × Bytes)) (k v : Bytes) : List (Bytes × Bytes) :=
  kvs.filter (·.1 != k) ++ [(k, v)]

/-- Walk `k`'s bits.  `some (some v)`: present with `v`; `some none`: absent; `none`: the proof stops at a
    stub or a mis-sized leaf, so it says nothing. -/
def PTree.find (k : Bytes) : Nat → PTree → Option (Option Bytes)
  | _, .empty => some none
  | _, .stub _ => none
  | _, .leaf k' v => if sized k' v then some (if k' == k then some v else none) else none
  | d, .node l r => if bitAt k d then PTree.find k (d + 1) r else PTree.find k (d + 1) l

def verifyMap (H : Bytes → Bytes) (root k : Bytes) (p : PTree) : Option (Option Bytes) :=
  if p.hash H == root then p.find k 0 else none

/-- Two leaves that share a subtree at depth `d`: nodes with one empty side down to their first differing bit. -/
def splitLeaves : Nat → Nat → Bytes → Bytes → Bytes → Bytes → Option PTree
  | 0, _, _, _, _, _ => none
  | fuel + 1, d, a, va, b, vb =>
    match bitAt a d, bitAt b d with
    | false, false => (splitLeaves fuel (d + 1) a va b vb).map fun t => .node t .empty
    | true, true => (splitLeaves fuel (d + 1) a va b vb).map fun t => .node .empty t
    | false, true => some (.node (.leaf a va) (.leaf b vb))
    | true, false => some (.node (.leaf b vb) (.leaf a va))

/-- Set `k` to `v` inside a pruned tree; `none` if the walk meets a stub or either leaf is mis-sized. -/
def PTree.insert (k v : Bytes) : Nat → PTree → Option PTree
  | _, .empty => if sized k v then some (.leaf k v) else none
  | _, .stub _ => none
  | d, .leaf k' v' =>
    if !(sized k v && sized k' v') then none
    else if k' == k then some (.leaf k v) else splitLeaves (512 - d) d k' v' k v
  | d, .node l r =>
    if bitAt k d then (PTree.insert k v (d + 1) r).map fun t => .node l t
    else (PTree.insert k v (d + 1) l).map fun t => .node t r

/-! ### §B helpers (this file's own; nothing here is a product lemma) -/

theorem key_eq_of_bits {k1 k2 : Bytes} (h1 : k1.length = 64) (h2 : k2.length = 64)
    (h : ∀ i < 512, bitAt k1 i = bitAt k2 i) : k1 = k2 := by
  apply List.ext_getElem (by rw [h1, h2])
  intro j hj1 hj2
  have hj : j < 64 := by omega
  have e : ∀ t, t < 8 → (k1[j].toNat / 2 ^ (7 - t) % 2 = 1 ↔ k2[j].toNat / 2 ^ (7 - t) % 2 = 1) := by
    intro t ht
    have := h (8 * j + t) (by omega)
    have e1 : (8 * j + t) / 8 = j := by omega
    have e2 : (8 * j + t) % 8 = t := by omega
    simp only [bitAt, e1, e2, List.getElem?_eq_getElem hj1, List.getElem?_eq_getElem hj2] at this
    simpa using Bool.eq_iff_iff.mp this
  have hx : k1[j].toNat < 256 := by have := (k1[j]).toNat_lt; omega
  have hy : k2[j].toNat < 256 := by have := (k2[j]).toNat_lt; omega
  apply UInt8.toNat_inj.mp
  apply Nat.eq_of_testBit_eq
  intro i
  by_cases hi : i < 8
  · have h7 := e (7 - i) (by omega)
    rw [show 7 - (7 - i) = i by omega] at h7
    rw [Nat.testBit_eq_decide_div_mod_eq, Nat.testBit_eq_decide_div_mod_eq]
    exact decide_eq_decide.mpr h7
  · have h8 : 256 ≤ 2 ^ i := by
      calc 256 = 2 ^ 8 := rfl
        _ ≤ 2 ^ i := Nat.pow_le_pow_right (by omega) (by omega)
    rw [Nat.testBit_lt_two_pow (by omega : k1[j].toNat < 2 ^ i),
      Nat.testBit_lt_two_pow (by omega : k2[j].toNat < 2 ^ i)]

theorem sized_iff {k v : Bytes} : sized k v = true ↔ k.length = 64 ∧ v.length = 64 := by
  simp [sized]

theorem hash_len_of_find {H : Bytes → Bytes} (hl : ∀ x, (H x).length = 64) {p : PTree} {k : Bytes}
    {d : Nat} {a : Option Bytes} (h : p.find k d = some a) : (p.hash H).length = 64 := by
  cases p with
  | empty => simp [PTree.hash, zeroDigest, digestBytes]
  | stub _ => simp [PTree.find] at h
  | leaf _ _ => exact hl _
  | node _ _ => exact hl _

theorem leaf_find {k v kk : Bytes} {d : Nat} {r : Option Bytes} (h : (PTree.leaf k v).find kk d = some r) :
    sized k v = true ∧ r = if k == kk then some v else none := by
  unfold PTree.find at h
  by_cases hs : sized k v = true
  · rw [if_pos hs] at h
    exact ⟨hs, (Option.some.inj h).symm⟩
  · rw [if_neg hs] at h; simp at h

theorem mem_leaf_inputs {H : Bytes → Bytes} (k v : Bytes) : (2 :: (k ++ v)) ∈ (PTree.leaf k v).inputs H := by
  simp [PTree.inputs, mapLeaf]

theorem mem_node_inputs {H : Bytes → Bytes} (l r : PTree) :
    (3 :: (l.hash H ++ r.hash H)) ∈ (PTree.node l r).inputs H := by
  simp [PTree.inputs, mapNode]

theorem bind_aux {H : Bytes → Bytes} (hl : ∀ x, (H x).length = 64) {L : List Bytes}
    (hg : breakIn H L = none) (k : Bytes) : ∀ (p q : PTree) (d : Nat) (a b : Option Bytes),
    (∀ x ∈ p.inputs H, x ∈ L) → (∀ x ∈ q.inputs H, x ∈ L) → p.hash H = q.hash H →
    p.find k d = some a → q.find k d = some b → a = b := by
  intro p
  induction p with
  | empty =>
    intro q d a b hp hq hh ha hb
    cases q with
    | empty =>
      simp [PTree.find] at ha hb
      subst ha; subst hb; rfl
    | stub _ => simp [PTree.find] at hb
    | leaf k' v' =>
      exact absurd hh.symm (nz_of_none hg (x := 2 :: (k' ++ v')) (hq _ (mem_leaf_inputs k' v')))
    | node l r =>
      exact absurd hh.symm (nz_of_none hg (x := 3 :: (l.hash H ++ r.hash H)) (hq _ (mem_node_inputs l r)))
  | stub h => intro q d a b hp hq hh ha hb; simp [PTree.find] at ha
  | leaf k1 v1 =>
    intro q d a b hp hq hh ha hb
    obtain ⟨hs1, rfl⟩ := leaf_find ha
    cases q with
    | empty =>
      exact absurd hh (nz_of_none hg (x := 2 :: (k1 ++ v1)) (hp _ (mem_leaf_inputs k1 v1)))
    | stub _ => simp [PTree.find] at hb
    | leaf k2 v2 =>
      obtain ⟨hs2, rfl⟩ := leaf_find hb
      have hxy := inj_of_none hg (x := 2 :: (k1 ++ v1)) (y := 2 :: (k2 ++ v2))
        (hp _ (mem_leaf_inputs k1 v1)) (hq _ (mem_leaf_inputs k2 v2)) hh
      have hc := (List.cons.inj hxy).2
      have h1 := sized_iff.mp hs1
      have h2 := sized_iff.mp hs2
      have := List.append_inj hc (by rw [h1.1, h2.1])
      obtain ⟨e1, e2⟩ := this
      subst e1; subst e2; rfl
    | node l r =>
      have hxy := inj_of_none hg (x := 2 :: (k1 ++ v1)) (y := 3 :: (l.hash H ++ r.hash H))
        (hp _ (mem_leaf_inputs k1 v1)) (hq _ (mem_node_inputs l r)) hh
      simp at hxy
  | node l r ihl ihr =>
    intro q d a b hp hq hh ha hb
    cases q with
    | empty =>
      exact absurd hh (nz_of_none hg (x := 3 :: (l.hash H ++ r.hash H)) (hp _ (mem_node_inputs l r)))
    | stub _ => simp [PTree.find] at hb
    | leaf k2 v2 =>
      have hxy := inj_of_none hg (x := 3 :: (l.hash H ++ r.hash H)) (y := 2 :: (k2 ++ v2))
        (hp _ (mem_node_inputs l r)) (hq _ (mem_leaf_inputs k2 v2)) hh
      simp at hxy
    | node l2 r2 =>
      have hxy := inj_of_none hg (x := 3 :: (l.hash H ++ r.hash H)) (y := 3 :: (l2.hash H ++ r2.hash H))
        (hp _ (mem_node_inputs l r)) (hq _ (mem_node_inputs l2 r2)) hh
      have hc := (List.cons.inj hxy).2
      have hpl : ∀ x ∈ l.inputs H, x ∈ L := fun x hx => hp x (List.mem_append_left _ (List.mem_cons_of_mem _ hx))
      have hpr : ∀ x ∈ r.inputs H, x ∈ L := fun x hx => hp x (List.mem_append_right _ hx)
      have hql : ∀ x ∈ l2.inputs H, x ∈ L := fun x hx => hq x (List.mem_append_left _ (List.mem_cons_of_mem _ hx))
      have hqr : ∀ x ∈ r2.inputs H, x ∈ L := fun x hx => hq x (List.mem_append_right _ hx)
      by_cases hk : bitAt k d = true
      · have ha' : r.find k (d + 1) = some a := by simpa [PTree.find, hk] using ha
        have hb' : r2.find k (d + 1) = some b := by simpa [PTree.find, hk] using hb
        have := List.append_inj' hc (by rw [hash_len_of_find hl ha', hash_len_of_find hl hb'])
        exact ihr r2 (d + 1) a b hpr hqr this.2 ha' hb'
      · have ha' : l.find k (d + 1) = some a := by simpa [PTree.find, hk] using ha
        have hb' : l2.find k (d + 1) = some b := by simpa [PTree.find, hk] using hb
        have := List.append_inj hc (by rw [hash_len_of_find hl ha', hash_len_of_find hl hb'])
        exact ihl l2 (d + 1) a b hpl hql this.1 ha' hb'

/-- Binding: two accepted proofs for one key against one root agree, whatever produced the root. -/
theorem map_binding {H : Bytes → Bytes} (hl : HashLen H) (p q : PTree) (k : Bytes) (a b : Option Bytes)
    (hpq : p.hash H = q.hash H) (ha : p.find k 0 = some a) (hb : q.find k 0 = some b) :
    a = b ∨ breakIn H (p.inputs H ++ q.inputs H) ≠ none := by
  by_cases hg : breakIn H (p.inputs H ++ q.inputs H) = none
  case neg => exact Or.inr hg
  left
  exact bind_aux hl hg k p q 0 a b (fun x hx => List.mem_append_left _ hx)
    (fun x hx => List.mem_append_right _ hx) hpq ha hb

theorem mapTree_nil (f d : Nat) : mapTree f d [] = .empty := by
  cases f <;> rfl

theorem mapTree_single (f d : Nat) (a b : Bytes) : mapTree f d [(a, b)] = .leaf a b := by
  cases f <;> rfl

theorem mapTree_node (f d : Nat) (kvs : List (Bytes × Bytes)) (h2 : 2 ≤ kvs.length) :
    mapTree (f + 1) d kvs = .node (mapTree f (d + 1) (kvs.filter fun kv => !bitAt kv.1 d))
      (mapTree f (d + 1) (kvs.filter fun kv => bitAt kv.1 d)) := by
  match kvs, h2 with
  | a :: b :: rest, _ => rfl

theorem find_node (k : Bytes) (l r : PTree) (d : Nat) :
    (PTree.node l r).find k d = if bitAt k d then r.find k (d + 1) else l.find k (d + 1) := rfl

def Agree (k : Bytes) (d : Nat) (kvs : List (Bytes × Bytes)) : Prop :=
  ∀ kv ∈ kvs, ∀ i < d, bitAt kv.1 i = bitAt k i

theorem MapWf.filter {kvs : List (Bytes × Bytes)} (h : MapWf kvs) (p : Bytes × Bytes → Bool) :
    MapWf (kvs.filter p) :=
  ⟨List.Nodup.sublist (List.Sublist.map _ (List.filter_sublist ..)) h.1,
   fun kv hkv => h.2 kv (List.mem_filter.mp hkv).1⟩

theorem Agree.filter {k : Bytes} {d : Nat} {kvs : List (Bytes × Bytes)} (hag : Agree k d kvs)
    (p : Bytes × Bytes → Bool) (hp : ∀ kv, p kv = true → bitAt kv.1 d = bitAt k d) :
    Agree k (d + 1) (kvs.filter p) := by
  intro kv hkv i hi
  obtain ⟨hm, hpk⟩ := List.mem_filter.mp hkv
  by_cases h : i < d
  · exact hag kv hm i h
  · have : i = d := by omega
    subst this
    exact hp kv hpk

theorem hp_left {k : Bytes} {d : Nat} (hk : bitAt k d = false) (kv : Bytes × Bytes)
    (h : (!bitAt kv.1 d) = true) : bitAt kv.1 d = bitAt k d := by
  rw [hk]; simpa using h

theorem hp_right {k : Bytes} {d : Nat} (hk : bitAt k d = true) (kv : Bytes × Bytes)
    (h : bitAt kv.1 d = true) : bitAt kv.1 d = bitAt k d := by
  rw [hk]; exact h

theorem mapTree_cases (k : Bytes) (fuel d : Nat) (kvs : List (Bytes × Bytes)) (hd : d + fuel = 512)
    (hnd : (kvs.map (·.1)).Nodup) (hlen : ∀ kv ∈ kvs, kv.1.length = 64)
    (hag : ∀ kv ∈ kvs, ∀ i < d, bitAt kv.1 i = bitAt k i) :
    kvs = [] ∨ (∃ a, kvs = [a]) ∨ (∃ f, fuel = f + 1 ∧ 2 ≤ kvs.length) := by
  rcases kvs with _ | ⟨a, _ | ⟨b, rest⟩⟩
  · exact Or.inl rfl
  · exact Or.inr (Or.inl ⟨a, rfl⟩)
  · right; right
    cases fuel with
    | succ f => exact ⟨f, rfl, by simp⟩
    | zero =>
      exfalso
      have hd0 : d = 512 := by omega
      subst hd0
      have h1 := (List.nodup_cons.mp (by simpa using hnd : (a.1 :: b.1 :: rest.map (·.1)).Nodup)).1
      have hne : a.1 ≠ b.1 := fun h => h1 (by simp [h])
      apply hne
      apply key_eq_of_bits (hlen a (by simp)) (hlen b (by simp))
      intro i hi
      rw [hag a (by simp) i hi, hag b (by simp) i hi]

theorem mapTree_hash_len {H : Bytes → Bytes} (hl : ∀ x, (H x).length = 64) (k : Bytes) (fuel d : Nat)
    (kvs : List (Bytes × Bytes)) (hd : d + fuel = 512) (hnd : (kvs.map (·.1)).Nodup)
    (hlen : ∀ kv ∈ kvs, kv.1.length = 64) (hag : ∀ kv ∈ kvs, ∀ i < d, bitAt kv.1 i = bitAt k i) :
    ((mapTree fuel d kvs).hash H).length = 64 := by
  rcases mapTree_cases k fuel d kvs hd hnd hlen hag with h | ⟨⟨a1, a2⟩, h⟩ | ⟨f, rfl, h2⟩
  · subst h; rw [mapTree_nil]; simp [PTree.hash, zeroDigest, digestBytes]
  · subst h; rw [mapTree_single]; exact hl _
  · rw [mapTree_node f d kvs h2]; exact hl _

theorem lookup_filter {k : Bytes} (p : Bytes × Bytes → Bool) (hp : ∀ a : Bytes × Bytes, a.1 = k → p a = true)
    (kvs : List (Bytes × Bytes)) : lookup (kvs.filter p) k = lookup kvs k := by
  unfold lookup
  rw [List.find?_filter]
  congr 2
  funext a
  by_cases h : (a.1 == k) = true
  · simp [hp a (beq_iff_eq.mp h), h]
  · simp [h]

theorem find_nil_single (k : Bytes) (fuel d : Nat) (kvs : List (Bytes × Bytes)) (hw : MapWf kvs)
    (h : kvs = [] ∨ ∃ a, kvs = [a]) : (mapTree fuel d kvs).find k d = some (lookup kvs k) := by
  rcases h with rfl | ⟨⟨k0, v0⟩, rfl⟩
  · simp [mapTree_nil, PTree.find, lookup]
  · have h1 : k0.length = 64 ∧ v0.length = 64 := hw.2 (k0, v0) (by simp)
    have hs : sized k0 v0 = true := by simp [sized, h1.1, h1.2]
    rw [mapTree_single]
    by_cases hk : (k0 == k) = true <;> simp [PTree.find, hs, lookup, hk]

theorem find_mapTree (k : Bytes) : ∀ (fuel d : Nat) (kvs : List (Bytes × Bytes)), d + fuel = 512 →
    MapWf kvs → Agree k d kvs → (mapTree fuel d kvs).find k d = some (lookup kvs k) := by
  intro fuel
  induction fuel with
  | zero =>
    intro d kvs hd hw hag
    rcases mapTree_cases k 0 d kvs hd hw.1 (fun kv h => (hw.2 kv h).1) hag with h | ⟨a, h⟩ | ⟨f, hf, _⟩
    · exact find_nil_single k 0 d kvs hw (Or.inl h)
    · exact find_nil_single k 0 d kvs hw (Or.inr ⟨a, h⟩)
    · exact absurd hf (by omega)
  | succ f ih =>
    intro d kvs hd hw hag
    rcases mapTree_cases k (f + 1) d kvs hd hw.1 (fun kv h => (hw.2 kv h).1) hag with h | ⟨a, h⟩ | ⟨f', hf, h2⟩
    · exact find_nil_single k (f + 1) d kvs hw (Or.inl h)
    · exact find_nil_single k (f + 1) d kvs hw (Or.inr ⟨a, h⟩)
    · rw [mapTree_node f d kvs h2, find_node]
      by_cases hk : bitAt k d = true
      · rw [if_pos hk]
        have := ih (d + 1) (kvs.filter fun kv => bitAt kv.1 d) (by omega) (hw.filter _)
          (hag.filter _ (hp_right hk))
        rw [this]
        congr 1
        exact lookup_filter _ (fun a ha => by rw [ha]; exact hk) kvs
      · have hk' : bitAt k d = false := by simpa using hk
        rw [if_neg hk]
        have := ih (d + 1) (kvs.filter fun kv => !bitAt kv.1 d) (by omega) (hw.filter _)
          (hag.filter _ (hp_left hk'))
        rw [this]
        congr 1
        exact lookup_filter _ (fun a ha => by rw [ha, hk']; rfl) kvs

theorem lookup_some {kvs : List (Bytes × Bytes)} {k v : Bytes} (h : lookup kvs k = some v) : (k, v) ∈ kvs := by
  unfold lookup at h
  obtain ⟨a, ha, hav⟩ := Option.map_eq_some_iff.mp h
  have hm := List.mem_of_find?_eq_some ha
  have hk := List.find?_some ha
  obtain ⟨a1, a2⟩ := a
  simp only [beq_iff_eq] at hk hav
  subst hk; subst hav; exact hm

theorem lookup_none {kvs : List (Bytes × Bytes)} {k : Bytes} (h : lookup kvs k = none) : ∀ v, (k, v) ∉ kvs := by
  intro v hv
  have e' : kvs.find? (·.1 == k) = none := by simpa [lookup] using h
  exact absurd (by simp) (List.find?_eq_none.mp e' (k, v) hv)

theorem upsert_nil (k v : Bytes) : upsert [] k v = [(k, v)] := by simp [upsert]

theorem upsert_len {kvs : List (Bytes × Bytes)} (hw : MapWf kvs) (h2 : 2 ≤ kvs.length) (k v : Bytes) :
    2 ≤ (upsert kvs k v).length := by
  rcases kvs with _ | ⟨a, _ | ⟨b, rest⟩⟩
  · simp at h2
  · simp at h2
  · have h1 := (List.nodup_cons.mp (by simpa using hw.1 : (a.1 :: b.1 :: rest.map (·.1)).Nodup)).1
    have hne : a.1 ≠ b.1 := fun h => h1 (by simp [h])
    unfold upsert
    rw [List.length_append]
    have : 0 < (List.filter (fun x : Bytes × Bytes => x.1 != k) (a :: b :: rest)).length := by
      by_cases ha : (a.1 != k) = true
      · exact List.length_pos_of_mem (List.mem_filter.mpr ⟨by simp, ha⟩)
      · have hak : a.1 = k := by simpa using ha
        have hb : (b.1 != k) = true := by
          have : b.1 ≠ k := fun e => hne (hak.trans e.symm)
          simpa using this
        exact List.length_pos_of_mem (List.mem_filter.mpr ⟨by simp, hb⟩)
    simp only [List.length_singleton]
    omega

theorem uf_in (g : Bytes → Bool) {k v : Bytes} (hk : g k = true) (kvs : List (Bytes × Bytes)) :
    (upsert kvs k v).filter (fun kv => g kv.1) = upsert (kvs.filter fun kv => g kv.1) k v := by
  simp only [upsert, List.filter_append, List.filter_filter]
  have h1 : List.filter (fun kv : Bytes × Bytes => g kv.1) [(k, v)] = [(k, v)] := by simp [hk]
  rw [h1]
  congr 1
  apply List.filter_congr
  intro x _
  simp [Bool.and_comm]

theorem uf_out (g : Bytes → Bool) {k v : Bytes} (hk : g k = false) (kvs : List (Bytes × Bytes)) :
    (upsert kvs k v).filter (fun kv => g kv.1) = kvs.filter fun kv => g kv.1 := by
  simp only [upsert, List.filter_append, List.filter_filter]
  have h1 : List.filter (fun kv : Bytes × Bytes => g kv.1) [(k, v)] = [] := by simp [hk]
  rw [h1, List.append_nil]
  apply List.filter_congr
  intro x _
  by_cases e : x.1 = k
  · simp [e, hk]
  · have : (x.1 != k) = true := by simpa using e
    simp [this]

theorem inp_l {H : Bytes → Bytes} {x : Bytes} {l r : PTree} (hx : x ∈ l.inputs H) :
    x ∈ (PTree.node l r).inputs H := List.mem_append_left _ (List.mem_cons_of_mem _ hx)

theorem inp_r {H : Bytes → Bytes} {x : Bytes} {l r : PTree} (hx : x ∈ r.inputs H) :
    x ∈ (PTree.node l r).inputs H := List.mem_append_right _ hx

theorem leaf_nz {H : Bytes → Bytes} {L : List Bytes} (hg : breakIn H L = none) {a b : Bytes}
    (h : ∀ x ∈ (PTree.leaf a b).inputs H, x ∈ L) : (PTree.leaf a b).hash H ≠ zeroDigest :=
  nz_of_none hg (h _ (mem_leaf_inputs a b))

theorem node_nz {H : Bytes → Bytes} {L : List Bytes} (hg : breakIn H L = none) {l r : PTree}
    (h : ∀ x ∈ (PTree.node l r).inputs H, x ∈ L) : (PTree.node l r).hash H ≠ zeroDigest :=
  nz_of_none hg (h _ (mem_node_inputs l r))

theorem leaf_node_ne {H : Bytes → Bytes} {L : List Bytes} (hg : breakIn H L = none) {a b : Bytes} {l r : PTree}
    (h1 : ∀ x ∈ (PTree.leaf a b).inputs H, x ∈ L) (h2 : ∀ x ∈ (PTree.node l r).inputs H, x ∈ L)
    (hh : (PTree.leaf a b).hash H = (PTree.node l r).hash H) : False := by
  have := inj_of_none hg (h1 _ (mem_leaf_inputs a b)) (h2 _ (mem_node_inputs l r)) hh
  exact absurd (List.cons.inj this).1 (by decide)

theorem hash_len_of_insert {H : Bytes → Bytes} (hl : ∀ x, (H x).length = 64) {p p' : PTree} {k v : Bytes}
    {d : Nat} (h : p.insert k v d = some p') : (p.hash H).length = 64 := by
  cases p with
  | empty => simp [PTree.hash, zeroDigest, digestBytes]
  | stub _ => exact absurd h (by simp [PTree.insert])
  | leaf _ _ => exact hl _
  | node _ _ => exact hl _

theorem splitLeaves_eq : ∀ (f d : Nat) (a va b vb : Bytes) (t : PTree),
    splitLeaves f d a va b vb = some t → mapTree f d [(a, va), (b, vb)] = t := by
  intro f
  induction f with
  | zero => intro d a va b vb t h; simp [splitLeaves] at h
  | succ f ih =>
    intro d a va b vb t h
    rw [mapTree_node f d _ (by simp)]
    cases ha : bitAt a d <;> cases hb : bitAt b d <;> simp only [splitLeaves, ha, hb] at h
    · rcases hs : splitLeaves f (d + 1) a va b vb with _ | t'
      · rw [hs] at h; simp at h
      · rw [hs] at h
        have h' : PTree.node t' .empty = t := by simpa using h
        subst h'
        simp [List.filter, ha, hb, mapTree_nil, ih (d + 1) a va b vb t' hs]
    · have h' : PTree.node (.leaf a va) (.leaf b vb) = t := by simpa using h
      subst h'
      simp [List.filter, ha, hb, mapTree_nil, mapTree_single]
    · have h' : PTree.node (.leaf b vb) (.leaf a va) = t := by simpa using h
      subst h'
      simp [List.filter, ha, hb, mapTree_nil, mapTree_single]
    · rcases hs : splitLeaves f (d + 1) a va b vb with _ | t'
      · rw [hs] at h; simp at h
      · rw [hs] at h
        have h' : PTree.node .empty t' = t := by simpa using h
        subst h'
        simp [List.filter, ha, hb, mapTree_nil, ih (d + 1) a va b vb t' hs]

theorem beq_false_of_bit (a k' : Bytes) (d : Nat) (h : bitAt a d ≠ bitAt k' d) : (a == k') = false := by
  cases e : (a == k')
  · rfl
  · exact (h (by rw [beq_iff_eq.mp e])).elim

theorem splitLeaves_find (k' : Bytes) : ∀ (f d : Nat) (a va b vb : Bytes) (t : PTree),
    sized a va = true → sized b vb = true → splitLeaves f d a va b vb = some t →
    t.find k' d = some (if a == k' then some va else if b == k' then some vb else none) := by
  intro f
  induction f with
  | zero => intro d a va b vb t _ _ h; simp [splitLeaves] at h
  | succ f ih =>
    intro d a va b vb t hsa hsb h
    cases ha : bitAt a d <;> cases hb : bitAt b d <;> simp only [splitLeaves, ha, hb] at h
    · rcases hs : splitLeaves f (d + 1) a va b vb with _ | t'
      · rw [hs] at h; simp at h
      · rw [hs] at h
        have h' : PTree.node t' .empty = t := by simpa using h
        subst h'
        by_cases hk : bitAt k' d = true
        · rw [find_node, if_pos hk]
          rw [beq_false_of_bit a k' d (by rw [ha, hk]; decide), beq_false_of_bit b k' d (by rw [hb, hk]; decide)]
          simp [PTree.find]
        · rw [find_node, if_neg hk]
          exact ih (d + 1) a va b vb t' hsa hsb hs
    · have h' : PTree.node (.leaf a va) (.leaf b vb) = t := by simpa using h
      subst h'
      by_cases hk : bitAt k' d = true
      · rw [find_node, if_pos hk]
        rw [beq_false_of_bit a k' d (by rw [ha, hk]; decide)]
        simp [PTree.find, hsb]
      · have hk' : bitAt k' d = false := by simpa using hk
        rw [find_node, if_neg hk]
        rw [beq_false_of_bit b k' d (by rw [hb, hk']; decide)]
        simp [PTree.find, hsa]
    · have h' : PTree.node (.leaf b vb) (.leaf a va) = t := by simpa using h
      subst h'
      by_cases hk : bitAt k' d = true
      · rw [find_node, if_pos hk]
        rw [beq_false_of_bit b k' d (by rw [hb, hk]; decide)]
        simp [PTree.find, hsa]
      · have hk' : bitAt k' d = false := by simpa using hk
        rw [find_node, if_neg hk]
        rw [beq_false_of_bit a k' d (by rw [ha, hk']; decide)]
        simp [PTree.find, hsb]
    · rcases hs : splitLeaves f (d + 1) a va b vb with _ | t'
      · rw [hs] at h; simp at h
      · rw [hs] at h
        have h' : PTree.node .empty t' = t := by simpa using h
        subst h'
        by_cases hk : bitAt k' d = true
        · rw [find_node, if_pos hk]
          exact ih (d + 1) a va b vb t' hsa hsb hs
        · have hk' : bitAt k' d = false := by simpa using hk
          rw [find_node, if_neg hk]
          rw [beq_false_of_bit a k' d (by rw [ha, hk']; decide), beq_false_of_bit b k' d (by rw [hb, hk']; decide)]
          simp [PTree.find]

theorem ins_aux {H : Bytes → Bytes} (hl : ∀ x, (H x).length = 64) {L : List Bytes} (hg : breakIn H L = none)
    (k v : Bytes) (hk : k.length = 64) (hv : v.length = 64) :
    ∀ (p : PTree) (fuel d : Nat) (kvs : List (Bytes × Bytes)) (p' : PTree),
    d + fuel = 512 → MapWf kvs → Agree k d kvs →
    (∀ x ∈ p.inputs H, x ∈ L) → (∀ x ∈ (mapTree fuel d kvs).inputs H, x ∈ L) →
    p.hash H = (mapTree fuel d kvs).hash H → p.insert k v d = some p' →
    p'.hash H = (mapTree fuel d (upsert kvs k v)).hash H := by
  have hsk : sized k v = true := by simp [sized, hk, hv]
  intro p
  induction p with
  | empty =>
    intro fuel d kvs p' hd hw hag hp hq hh hi
    rcases mapTree_cases k fuel d kvs hd hw.1 (fun kv h => (hw.2 kv h).1) hag with h | ⟨a, h⟩ | ⟨f, hf, h2⟩
    · subst h
      have hi2 : (if sized k v = true then some (PTree.leaf k v) else none) = some p' := hi
      rw [if_pos hsk] at hi2
      cases hi2
      rw [upsert_nil, mapTree_single]
    · exfalso; subst h; obtain ⟨a1, a2⟩ := a
      rw [mapTree_single] at hh hq
      exact leaf_nz hg hq hh.symm
    · exfalso; subst hf
      rw [mapTree_node f d kvs h2] at hh hq
      exact node_nz hg hq hh.symm
  | stub s =>
    intro fuel d kvs p' hd hw hag hp hq hh hi
    have hi2 : (none : Option PTree) = some p' := hi
    cases hi2
  | leaf k0 v0 =>
    intro fuel d kvs p' hd hw hag hp hq hh hi
    rcases mapTree_cases k fuel d kvs hd hw.1 (fun kv h => (hw.2 kv h).1) hag with h | ⟨a, h⟩ | ⟨f, hf, h2⟩
    · exfalso; subst h; rw [mapTree_nil] at hh; exact leaf_nz hg hp hh
    · subst h
      obtain ⟨a1, a2⟩ := a
      have hw1 : a1.length = 64 ∧ a2.length = 64 := hw.2 (a1, a2) (by simp)
      rw [mapTree_single] at hh hq
      have hxy := inj_of_none hg (hp _ (mem_leaf_inputs k0 v0)) (hq _ (mem_leaf_inputs a1 a2)) hh
      have hc := (List.cons.inj hxy).2
      have hi2 : (if (!(sized k v && sized k0 v0)) = true then none else
          if (k0 == k) = true then some (PTree.leaf k v) else splitLeaves (512 - d) d k0 v0 k v) = some p' := hi
      by_cases hs : (!(sized k v && sized k0 v0)) = true
      · rw [if_pos hs] at hi2; cases hi2
      · rw [if_neg hs] at hi2
        have hs0 : sized k0 v0 = true := by
          revert hs; rw [hsk]; cases sized k0 v0 <;> simp
        have hl0 := sized_iff.mp hs0
        obtain ⟨e1, e2⟩ := List.append_inj hc (by rw [hl0.1, hw1.1])
        by_cases hkk : (k0 == k) = true
        · rw [if_pos hkk] at hi2; cases hi2
          have e : k0 = k := beq_iff_eq.mp hkk
          rw [← e1, ← e2, ← e]
          simp [upsert, mapTree_single]
        · rw [if_neg hkk] at hi2
          have hne : k0 ≠ k := fun e => hkk (by simp [e])
          have hu : upsert [(k0, v0)] k v = [(k0, v0), (k, v)] := by simp [upsert, hne]
          rw [← e1, ← e2, hu, show fuel = 512 - d by omega, splitLeaves_eq _ _ _ _ _ _ _ hi2]
    · exfalso; subst hf
      rw [mapTree_node f d kvs h2] at hh hq
      exact leaf_node_ne hg hp hq hh
  | node l r ihl ihr =>
    intro fuel d kvs p' hd hw hag hp hq hh hi
    rcases mapTree_cases k fuel d kvs hd hw.1 (fun kv h => (hw.2 kv h).1) hag with h | ⟨a, h⟩ | ⟨f, hf, h2⟩
    · exfalso; subst h; rw [mapTree_nil] at hh; exact node_nz hg hp hh
    · exfalso; subst h; obtain ⟨a1, a2⟩ := a
      rw [mapTree_single] at hh hq
      exact leaf_node_ne hg hq hp hh.symm
    · subst hf
      rw [mapTree_node f d kvs h2] at hh hq
      have hxy := inj_of_none hg (hp _ (mem_node_inputs _ _)) (hq _ (mem_node_inputs _ _)) hh
      have hc := (List.cons.inj hxy).2
      have hwl := hw.filter (fun kv => !bitAt kv.1 d)
      have hwr := hw.filter (fun kv => bitAt kv.1 d)
      have hi2 : (if bitAt k d = true then (r.insert k v (d + 1)).map (fun t => PTree.node l t)
          else (l.insert k v (d + 1)).map (fun t => PTree.node t r)) = some p' := hi
      rw [mapTree_node f d _ (upsert_len hw h2 k v)]
      by_cases hkb : bitAt k d = true
      · rw [if_pos hkb] at hi2
        have hag' := hag.filter (fun kv => bitAt kv.1 d) (hp_right hkb)
        rcases hr : r.insert k v (d + 1) with _ | r'
        · rw [hr] at hi2; simp at hi2
        · rw [hr] at hi2
          have hi' : PTree.node l r' = p' := by simpa using hi2
          subst hi'
          have hl1 := hash_len_of_insert hl hr
          have hl2 := mapTree_hash_len hl k f (d + 1) _ (by omega) hwr.1 (fun kv h => (hwr.2 kv h).1) hag'
          have hs := List.append_inj' hc (by rw [hl1, hl2])
          have ih := ihr f (d + 1) _ r' (by omega) hwr hag' (fun x hx => hp x (inp_r hx))
            (fun x hx => hq x (inp_r hx)) hs.2 hr
          have e1 : (upsert kvs k v).filter (fun kv => !bitAt kv.1 d) = kvs.filter (fun kv => !bitAt kv.1 d) :=
            uf_out (fun b => !bitAt b d) (by simp [hkb]) kvs
          have e2 : (upsert kvs k v).filter (fun kv => bitAt kv.1 d) =
              upsert (kvs.filter fun kv => bitAt kv.1 d) k v := uf_in (fun b => bitAt b d) hkb kvs
          rw [e1, e2]
          simp only [PTree.hash, mapNode]
          rw [hs.1, ih]
      · have hkb' : bitAt k d = false := by simpa using hkb
        rw [if_neg hkb] at hi2
        have hag' := hag.filter (fun kv => !bitAt kv.1 d) (hp_left hkb')
        rcases hr : l.insert k v (d + 1) with _ | l'
        · rw [hr] at hi2; simp at hi2
        · rw [hr] at hi2
          have hi' : PTree.node l' r = p' := by simpa using hi2
          subst hi'
          have hl1 := hash_len_of_insert hl hr
          have hl2 := mapTree_hash_len hl k f (d + 1) _ (by omega) hwl.1 (fun kv h => (hwl.2 kv h).1) hag'
          have hs := List.append_inj hc (by rw [hl1, hl2])
          have ih := ihl f (d + 1) _ l' (by omega) hwl hag' (fun x hx => hp x (inp_l hx))
            (fun x hx => hq x (inp_l hx)) hs.1 hr
          have e1 : (upsert kvs k v).filter (fun kv => bitAt kv.1 d) = kvs.filter (fun kv => bitAt kv.1 d) :=
            uf_out (fun b => bitAt b d) hkb' kvs
          have e2 : (upsert kvs k v).filter (fun kv => !bitAt kv.1 d) =
              upsert (kvs.filter fun kv => !bitAt kv.1 d) k v := uf_in (fun b => !bitAt b d) (by simp [hkb']) kvs
          rw [e1, e2]
          simp only [PTree.hash, mapNode]
          rw [hs.2, ih]

theorem sized_of_insert (k v : Bytes) : ∀ (p p' : PTree) (d : Nat), p.insert k v d = some p' →
    sized k v = true := by
  intro p
  induction p with
  | empty =>
    intro p' d hi
    have hi2 : (if sized k v = true then some (PTree.leaf k v) else none) = some p' := hi
    by_cases hs : sized k v = true
    · exact hs
    · rw [if_neg hs] at hi2; cases hi2
  | stub s =>
    intro p' d hi
    have hi2 : (none : Option PTree) = some p' := hi
    cases hi2
  | leaf k0 v0 =>
    intro p' d hi
    have hi2 : (if (!(sized k v && sized k0 v0)) = true then none else
        if (k0 == k) = true then some (PTree.leaf k v) else splitLeaves (512 - d) d k0 v0 k v) = some p' := hi
    by_cases hs : (!(sized k v && sized k0 v0)) = true
    · rw [if_pos hs] at hi2; cases hi2
    · revert hs; cases sized k v <;> simp
  | node l r ihl ihr =>
    intro p' d hi
    have hi2 : (if bitAt k d = true then (r.insert k v (d + 1)).map (fun t => PTree.node l t)
        else (l.insert k v (d + 1)).map (fun t => PTree.node t r)) = some p' := hi
    by_cases hkb : bitAt k d = true
    · rw [if_pos hkb] at hi2
      rcases hr : r.insert k v (d + 1) with _ | r'
      · rw [hr] at hi2; simp at hi2
      · exact ihr r' (d + 1) hr
    · rw [if_neg hkb] at hi2
      rcases hr : l.insert k v (d + 1) with _ | l'
      · rw [hr] at hi2; simp at hi2
      · exact ihl l' (d + 1) hr

theorem ifo_aux (k k' v : Bytes) (hne : k ≠ k') (hsk : sized k v = true) :
    ∀ (p p' : PTree) (d : Nat) (r : Option Bytes), p.insert k v d = some p' →
    p.find k' d = some r → p'.find k' d = some r := by
  have hkk : (k == k') = false := by
    cases e : (k == k')
    · rfl
    · exact (hne (beq_iff_eq.mp e)).elim
  intro p
  induction p with
  | empty =>
    intro p' d r hi hf
    have hi2 : (if sized k v = true then some (PTree.leaf k v) else none) = some p' := hi
    rw [if_pos hsk] at hi2
    cases hi2
    have hr : none = r := by simpa [PTree.find] using hf
    subst hr
    simp [PTree.find, hsk, hkk]
  | stub s =>
    intro p' d r hi hf
    have hi2 : (none : Option PTree) = some p' := hi
    cases hi2
  | leaf k0 v0 =>
    intro p' d r hi hf
    obtain ⟨hs0, hr⟩ := leaf_find hf
    have hi2 : (if (!(sized k v && sized k0 v0)) = true then none else
        if (k0 == k) = true then some (PTree.leaf k v) else splitLeaves (512 - d) d k0 v0 k v) = some p' := hi
    by_cases hs : (!(sized k v && sized k0 v0)) = true
    · rw [if_pos hs] at hi2; cases hi2
    · rw [if_neg hs] at hi2
      by_cases hk0 : (k0 == k) = true
      · rw [if_pos hk0] at hi2; cases hi2
        have e : k0 = k := beq_iff_eq.mp hk0
        have hr' : r = none := by rw [hr, e]; simp [hkk]
        subst hr'
        simp [PTree.find, hsk, hkk]
      · rw [if_neg hk0] at hi2
        rw [splitLeaves_find k' _ _ _ _ _ _ _ hs0 hsk hi2, hr]
        simp [hkk]
  | node l r ihl ihr =>
    intro p' d r0 hi hf
    have hi2 : (if bitAt k d = true then (r.insert k v (d + 1)).map (fun t => PTree.node l t)
        else (l.insert k v (d + 1)).map (fun t => PTree.node t r)) = some p' := hi
    by_cases hkb : bitAt k d = true
    · rw [if_pos hkb] at hi2
      rcases hr : r.insert k v (d + 1) with _ | r'
      · rw [hr] at hi2; simp at hi2
      · rw [hr] at hi2
        have hi' : PTree.node l r' = p' := by simpa using hi2
        subst hi'
        rw [find_node] at hf ⊢
        by_cases hk' : bitAt k' d = true
        · rw [if_pos hk'] at hf ⊢
          exact ihr r' (d + 1) r0 hr hf
        · rw [if_neg hk'] at hf ⊢
          exact hf
    · rw [if_neg hkb] at hi2
      rcases hr : l.insert k v (d + 1) with _ | l'
      · rw [hr] at hi2; simp at hi2
      · rw [hr] at hi2
        have hi' : PTree.node l' r = p' := by simpa using hi2
        subst hi'
        rw [find_node] at hf ⊢
        by_cases hk' : bitAt k' d = true
        · rw [if_pos hk'] at hf ⊢
          exact hf
        · rw [if_neg hk'] at hf ⊢
          exact ihl l' (d + 1) r0 hr hf

/-- Inclusion and absence soundness in one statement (`r = some v` / `r = none`). -/
theorem map_sound {H : Bytes → Bytes} (hl : HashLen H) (kvs : List (Bytes × Bytes)) (k : Bytes) (p : PTree)
    (r : Option Bytes) (hw : MapWf kvs) (h : verifyMap H (mapRoot H kvs) k p = some r) :
    r = lookup kvs k ∨ breakIn H (p.inputs H ++ (mapTree 512 0 kvs).inputs H) ≠ none := by
  unfold verifyMap at h
  by_cases hh : (p.hash H == mapRoot H kvs) = true
  · rw [if_pos hh] at h
    have hh' : p.hash H = (mapTree 512 0 kvs).hash H := beq_iff_eq.mp hh
    have hq := find_mapTree k 512 0 kvs (by omega) hw (fun kv _ i hi => absurd hi (Nat.not_lt_zero i))
    exact map_binding hl p (mapTree 512 0 kvs) k r (lookup kvs k) hh' h hq
  · rw [if_neg hh] at h; cases h

theorem inclusion_sound {H : Bytes → Bytes} (hl : HashLen H) (kvs : List (Bytes × Bytes)) (k v : Bytes)
    (p : PTree) (hw : MapWf kvs) (h : verifyMap H (mapRoot H kvs) k p = some (some v)) :
    (k, v) ∈ kvs ∨ breakIn H (p.inputs H ++ (mapTree 512 0 kvs).inputs H) ≠ none := by
  rcases map_sound hl kvs k p (some v) hw h with e | e
  · exact Or.inl (lookup_some e.symm)
  · exact Or.inr e

theorem absence_sound {H : Bytes → Bytes} (hl : HashLen H) (kvs : List (Bytes × Bytes)) (k : Bytes)
    (p : PTree) (hw : MapWf kvs) (h : verifyMap H (mapRoot H kvs) k p = some none) :
    (∀ v, (k, v) ∉ kvs) ∨ breakIn H (p.inputs H ++ (mapTree 512 0 kvs).inputs H) ≠ none := by
  rcases map_sound hl kvs k p none hw h with e | e
  · exact Or.inl (lookup_none e.symm)
  · exact Or.inr e

theorem map_complete {H : Bytes → Bytes} (kvs : List (Bytes × Bytes)) (k : Bytes) (hw : MapWf kvs)
    (hk : k.length = 64) : ∃ p, verifyMap H (mapRoot H kvs) k p = some (lookup kvs k) := by
  refine ⟨mapTree 512 0 kvs, ?_⟩
  unfold verifyMap
  rw [if_pos (by simp [mapRoot])]
  exact find_mapTree k 512 0 kvs (by omega) hw (fun kv _ i hi => absurd hi (Nat.not_lt_zero i))

/-- Map update correctness: inserting into a proof of the old root gives the canonical new root. -/
theorem map_insert_correct {H : Bytes → Bytes} (hl : HashLen H) (kvs : List (Bytes × Bytes)) (k v : Bytes)
    (p p' : PTree) (hw : MapWf kvs) (hk : k.length = 64) (hv : v.length = 64)
    (hp : p.hash H = mapRoot H kvs) (hi : p.insert k v 0 = some p') :
    p'.hash H = mapRoot H (upsert kvs k v) ∨ breakIn H (p.inputs H ++ (mapTree 512 0 kvs).inputs H) ≠ none := by
  by_cases hg : breakIn H (p.inputs H ++ (mapTree 512 0 kvs).inputs H) = none
  case neg => exact Or.inr hg
  left
  exact ins_aux hl hg k v hk hv p 512 0 kvs p' (by omega) hw (fun kv _ i hi => absurd hi (Nat.not_lt_zero i))
    (fun x hx => List.mem_append_left _ hx) (fun x hx => List.mem_append_right _ hx) hp hi

/-- The opened part survives an insert, so one multiproof serves a whole batch of inserts. -/
theorem insert_find_other (p p' : PTree) (k k' v : Bytes) (hne : k ≠ k') (hi : p.insert k v 0 = some p')
    (r : Option Bytes) (hf : p.find k' 0 = some r) : p'.find k' 0 = some r :=
  ifo_aux k k' v hne (sized_of_insert k v p p' 0 hi) p p' 0 r hi hf

/-! ## §C  Gate STATE/v2: the released and unresolved sets as one log plus one key index

    Entry  = `RR/GATE/STATE-ENTRY/v2\0 ‖ u8 set (1 released, 2 unresolved) ‖ row` (row = the 923-byte
             `Line.fields` encoding the v1 pins use).
    Key    = `H (RR/GATE/STATE-KEY/v2\0 ‖ keyBytes)` for each of a line's three `Rules.keys`.
    Value  = `H (RR/GATE/STATE-BUCKET/v2\0 ‖ u32 count ‖ (u64 index ‖ leaf hash)^count)`, indices ascending:
             every entry carrying that key.
    Head   = `RR/GATE/STATE/v2\0 ‖ u64 size ‖ logRoot ‖ mapRoot`; the checkpoint's `stateDigest` is `H head`. -/

def domainV (name : String) (v : Nat) : Bytes := ("RR/GATE/" ++ name ++ "/v" ++ toString v).toUTF8.toList ++ [0]

/-- Field widths of each key kind (`Rules.exactKey`, `nearKey`, `idKey`), as in `Line.fields`. -/
def keyWidths : Nat → Option (List Nat)
  | 0 => some [129, 4]
  | 1 => some [129, 129, 4, 129, 4, 8]
  | 2 => some [129, 129, 4, 129]
  | 3 => some [129, 129, 4, 129, 4, 8]
  | 4 => some [129]
  | _ => none

def keyBytes : Rules.Key → Option Bytes
  | kind :: fs => do
    let ws ← keyWidths kind
    guard (ws.length == fs.length)
    let parts ← (ws.zip fs).mapM fun (w, n) => Rules.be w n
    pure (kind.toUInt8 :: parts.flatten)
  | [] => none

def stateKey (H : Bytes → Bytes) (k : Rules.Key) : Option Bytes :=
  (keyBytes k).map fun b => H (domainV "STATE-KEY" 2 ++ b)

def rowBytes (l : Rules.Line) : Option Bytes :=
  ((Rules.Line.fields l).mapM fun (w, n) => Rules.be w n).map List.flatten

structure Entry where
  set : Nat
  line : Rules.Line

def entryBytes (e : Entry) : Option Bytes :=
  (rowBytes e.line).map fun r => domainV "STATE-ENTRY" 2 ++ (e.set.toUInt8 :: r)

def leafOf (H : Bytes → Bytes) (e : Entry) : Bytes := logLeaf H ((entryBytes e).getD [])

def bucketDigest (H : Bytes → Bytes) (items : List (Nat × Bytes)) : Bytes :=
  H (domainV "STATE-BUCKET" 2 ++ natBE 4 items.length ++ items.flatMap fun (i, h) => natBE 8 i ++ h)

def indexed {α : Type} : Nat → List α → List (Nat × α)
  | _, [] => []
  | n, x :: xs => (n, x) :: indexed (n + 1) xs

def hasKey (k : Rules.Key) (r : Nat × Entry) : Bool := (Rules.keys r.2.line).contains k

def bucketItems (H : Bytes → Bytes) (rows : List (Nat × Entry)) : List (Nat × Bytes) :=
  rows.map fun r => (r.1, leafOf H r.2)

/-- The full index of a log: one map entry per key any entry carries. -/
def gateMap (H : Bytes → Bytes) (E : List Entry) : List (Bytes × Bytes) :=
  ((E.flatMap fun e => Rules.keys e.line).eraseDups).filterMap fun k =>
    (stateKey H k).map fun K => (K, bucketDigest H (bucketItems H ((indexed 0 E).filter (hasKey k))))

/-- The index's hash inputs outside the map tree, over `rows` for keys `Q`: key digests, log leaves, buckets. -/
def indexInputs (H : Bytes → Bytes) (Q : List Rules.Key) (rows : List (Nat × Entry)) : List Bytes :=
  Q.filterMap (stateKey id) ++ rows.map (leafOf id ·.2) ++
    Q.map fun k => bucketDigest id (bucketItems H (rows.filter (hasKey k)))

def headBytes (d : Bytes) (size : Nat) (logR mapR : Bytes) : Bytes := d ++ natBE 8 size ++ logR ++ mapR

def gateHead (H : Bytes → Bytes) (E : List Entry) : Bytes :=
  headBytes (domainV "STATE" 2) E.length (logRoot H (E.map fun e => (entryBytes e).getD []))
    (mapRoot H (gateMap H E))

/-- Every entry encodes, names a set, and no identity appears twice in the two sets together. -/
def EntriesWf (E : List Entry) : Prop :=
  (∀ e ∈ E, (e.set = 1 ∨ e.set = 2) ∧ (entryBytes e).isSome) ∧ (E.map (·.line.id)).Nodup

def setOf (E : List Entry) (s : Nat) : List Rules.Line := (E.filter (·.set == s)).map (·.line)

/-- The v2 context: the set read and the gate's checkpoint are the same authenticated state. -/
def v2Ctx (c : Rules.Ctx) (E : List Entry) : Rules.Ctx :=
  let r := setOf E 1
  let u := setOf E 2
  { c with released := some ⟨c.today, r.length, r⟩, releasedPrior := ⟨c.today, r.length, r⟩,
           unresolved := some ⟨c.today, u.length, u⟩, unresolvedPrior := ⟨c.today, u.length, u⟩ }

def querySet (b : List Rules.Line) : List Rules.Key := b.flatMap Rules.keys

/-- The entries a batch can see: those sharing a key with one of its lines, in log order. -/
def sliceOf (E : List Entry) (Q : List Rules.Key) : List Entry :=
  E.filter fun e => (Rules.keys e.line).any Q.contains

def batchOutcome (c : Rules.Ctx) (b : List Rules.Line) :
    List Rules.Decision × List Rules.Line × List Rules.Line :=
  let ds := (Rules.decideBatch c b).decisions
  (ds, Rules.releasedLines c ds, Rules.unresolvedLines c ds)

/-- What the batch appends: released lines, then unresolved lines. -/
def adds (c : Rules.Ctx) (b : List Rules.Line) : List Entry :=
  let o := batchOutcome c b
  o.2.1.map (fun l => Entry.mk 1 l) ++ o.2.2.map (fun l => Entry.mk 2 l)

/-- What the adapter hands Lean per batch; nothing in it is trusted until `hydrateOk`. -/
structure Hydration where
  tree : PTree
  rows : List (Nat × Entry)

def ascending : List Nat → Bool
  | a :: b :: rest => a < b && ascending (b :: rest)
  | _ => true

def hydrateOk (H : Bytes → Bytes) (root : Bytes) (Q : List Rules.Key) (h : Hydration) : Bool :=
  h.tree.hash H == root && ascending (h.rows.map (·.1)) &&
  h.rows.all (fun r => r.1 ≤ maxSize && (Rules.keys r.2.line).any Q.contains && (r.2.set == 1 || r.2.set == 2) &&
    (entryBytes r.2).isSome) &&
  Q.all fun k => match stateKey H k with
    | none => false
    | some K => match h.tree.find K 0 with
      | some none => (h.rows.filter (hasKey k)).isEmpty
      | some (some v) => v == bucketDigest H (bucketItems H (h.rows.filter (hasKey k)))
      | none => false

/-- Every hash input behind a hydration for keys `Q` and behind the true index of `E`. -/
def hydrateInputs (H : Bytes → Bytes) (E : List Entry) (Q : List Rules.Key) (h : Hydration) : List Bytes :=
  h.tree.inputs H ++ (mapTree 512 0 (gateMap H E)).inputs H ++ indexInputs H Q h.rows ++
    indexInputs H (E.flatMap fun e => Rules.keys e.line) (indexed 0 E)

/-- The new map root: every key of an added entry gets its old bucket plus the new entries. -/
def applyBatch (H : Bytes → Bytes) (h : Hydration) (base : Nat) (new : List Entry) : Option PTree :=
  let all := h.rows ++ indexed base new
  ((new.flatMap fun e => Rules.keys e.line).eraseDups).foldlM
    (fun t k => do
      let K ← stateKey H k
      t.insert K (bucketDigest H (bucketItems H (all.filter (hasKey k)))) 0)
    h.tree

/-! ### §C helpers: the rule engine's decision list (this file's own) -/

theorem bnot_eq {b : Bool} : ((!b) = true) ↔ b = false := by cases b <;> simp

theorem not_contains {α : Type} [BEq α] [LawfulBEq α] {l : List α} {a : α} : l.contains a = false ↔ a ∉ l := by
  constructor
  · intro h hm
    have := List.contains_iff_mem.mpr hm
    rw [h] at this
    cases this
  · intro h
    cases hc : l.contains a
    · rfl
    · exact absurd (List.contains_iff_mem.mp hc) h

theorem filter_sub_filter {α : Type} (p q : α → Bool) :
    ∀ l : List α, (∀ a ∈ l, p a = true → q a = true) → List.Sublist (l.filter p) (l.filter q)
  | [], _ => by simp
  | a :: l, h => by
    have ih := filter_sub_filter p q l (fun x hx => h x (List.mem_cons_of_mem _ hx))
    have ha := h a (List.mem_cons_self ..)
    by_cases hp : p a = true
    · rw [List.filter_cons_of_pos hp, List.filter_cons_of_pos (ha hp)]
      exact ih.cons₂ a
    · rw [List.filter_cons_of_neg hp]
      by_cases hq : q a = true
      · rw [List.filter_cons_of_pos hq]; exact ih.cons a
      · rw [List.filter_cons_of_neg hq]; exact ih

theorem inj_of_nodup_map {α β : Type} (f : α → β) :
    ∀ (l : List α), (l.map f).Nodup → ∀ x ∈ l, ∀ y ∈ l, f x = f y → x = y
  | [], _, x, hx, _, _, _ => by simp at hx
  | a :: l, h, x, hx, y, hy, hxy => by
    rw [List.map_cons, List.nodup_cons] at h
    by_cases hxa : x = a
    · by_cases hya : y = a
      · rw [hxa, hya]
      · exfalso
        have hy' : y ∈ l := (List.mem_cons.mp hy).resolve_left hya
        apply h.1
        rw [← hxa, hxy]
        exact List.mem_map_of_mem hy'
    · have hx' : x ∈ l := (List.mem_cons.mp hx).resolve_left hxa
      by_cases hya : y = a
      · exfalso
        apply h.1
        rw [← hya, ← hxy]
        exact List.mem_map_of_mem hx'
      · exact inj_of_nodup_map f l h.2 x hx' y ((List.mem_cons.mp hy).resolve_left hya) hxy

theorem idKey_mem_claim (c : Rules.Ctx) (l : Rules.Line) : Rules.idKey l ∈ Rules.claim c l := by
  unfold Rules.claim
  split <;> simp [Rules.keys]

theorem decideAll_mem (c : Rules.Ctx) : ∀ (ls : List Rules.Line) (seen : List Rules.Key),
    ∀ d ∈ Rules.decideAll c seen ls,
      d.line ∈ ls ∧ d.outcome = Rules.outcomeOf d.reasons ∧ ∃ s, d = Rules.decideLine c s d.line := by
  intro ls
  induction ls with
  | nil => intro seen d hd; simp [Rules.decideAll] at hd
  | cons l ls ih =>
    intro seen d hd
    simp only [Rules.decideAll, List.mem_cons] at hd
    rcases hd with rfl | hd
    · exact ⟨List.mem_cons_self .., rfl, seen, rfl⟩
    · obtain ⟨h1, h2, h3⟩ := ih _ d hd
      exact ⟨List.mem_cons_of_mem _ h1, h2, h3⟩

theorem AD_of_seen (c : Rules.Ctx) (s : List Rules.Key) (l : Rules.Line) (h : s.contains (Rules.idKey l) = true) :
    Rules.Reason.ALREADY_DECIDED ∈ (Rules.decideLine c s l).reasons := by
  show _ ∈ Rules.reasons.filter (Rules.fires c s l)
  refine List.mem_filter.mpr ⟨by simp [Rules.reasons], ?_⟩
  have hm := List.contains_iff_mem.mp h
  simp [Rules.fires, hm]

theorem AD_of_pending (c : Rules.Ctx) (s : List Rules.Key) (l : Rules.Line)
    (h : (Rules.pending c).contains (Rules.idKey l) = true) :
    Rules.Reason.ALREADY_DECIDED ∈ (Rules.decideLine c s l).reasons := by
  show _ ∈ Rules.reasons.filter (Rules.fires c s l)
  refine List.mem_filter.mpr ⟨by simp [Rules.reasons], ?_⟩
  have hm := List.contains_iff_mem.mp h
  simp [Rules.fires, hm]

theorem decideAll_AD (c : Rules.Ctx) : ∀ (ls : List Rules.Line) (seen : List Rules.Key) (i : Nat), [4, i] ∈ seen →
    ∀ d ∈ Rules.decideAll c seen ls, d.line.id = i → Rules.Reason.ALREADY_DECIDED ∈ d.reasons := by
  intro ls
  induction ls with
  | nil => intro seen i _ d hd; simp [Rules.decideAll] at hd
  | cons l ls ih =>
    intro seen i hi d hd hdi
    simp only [Rules.decideAll, List.mem_cons] at hd
    rcases hd with rfl | hd
    · have hdi' : l.id = i := hdi
      have hk : Rules.idKey l = [4, i] := by
        show [4, l.id] = [4, i]
        rw [hdi']
      exact AD_of_seen c seen l (List.contains_iff_mem.mpr (by rw [hk]; exact hi))
    · exact ih _ i (List.mem_append_right _ hi) d hd hdi

theorem decideAll_pairwise (c : Rules.Ctx) : ∀ (ls : List Rules.Line) (seen : List Rules.Key),
    List.Pairwise (fun d1 d2 : Rules.Decision => d2.line.id = d1.line.id →
      Rules.Reason.ALREADY_DECIDED ∈ d2.reasons) (Rules.decideAll c seen ls)
  | [], _ => List.Pairwise.nil
  | l :: ls, seen => by
    simp only [Rules.decideAll]
    refine List.pairwise_cons.mpr ⟨?_, decideAll_pairwise c ls _⟩
    intro d2 hd2 hid
    exact decideAll_AD c ls (Rules.claim c l ++ seen) l.id
      (List.mem_append_left _ (idKey_mem_claim c l)) d2 hd2 hid

def seenAfter (c : Rules.Ctx) : List Rules.Line → List Rules.Key → List Rules.Key
  | [], s => s
  | l :: ls, s => seenAfter c ls (Rules.claim c l ++ s)

theorem decideAll_append (c : Rules.Ctx) : ∀ (A B : List Rules.Line) (s : List Rules.Key),
    Rules.decideAll c s (A ++ B) = Rules.decideAll c s A ++ Rules.decideAll c (seenAfter c A s) B
  | [], B, s => rfl
  | l :: A, B, s => by
    simp only [List.cons_append, Rules.decideAll, seenAfter, decideAll_append c A B]

theorem seenAfter_sub (c : Rules.Ctx) : ∀ (A : List Rules.Line) (s : List Rules.Key) (k : Rules.Key),
    k ∈ s → k ∈ seenAfter c A s
  | [], s, k, h => h
  | l :: A, s, k, h => seenAfter_sub c A _ k (List.mem_append_right _ h)

theorem seenAfter_claim (c : Rules.Ctx) : ∀ (A : List Rules.Line) (s : List Rules.Key) (l : Rules.Line)
    (k : Rules.Key), l ∈ A → k ∈ Rules.claim c l → k ∈ seenAfter c A s
  | [], _, l, k, h, _ => by simp at h
  | a :: A, s, l, k, h, hk => by
    rcases List.mem_cons.mp h with rfl | h
    · exact seenAfter_sub c A _ k (List.mem_append_left _ hk)
    · exact seenAfter_claim c A _ l k h hk

theorem outcomeOf_allow {rs : List Rules.Reason} (h : Rules.outcomeOf rs = .ALLOW) : rs = [] := by
  unfold Rules.outcomeOf at h
  by_cases hr : rs.isEmpty = true
  · simpa using hr
  · rw [if_neg hr] at h
    split at h <;> cases h

theorem releasedSet_v2 (c : Rules.Ctx) (E : List Entry) : Rules.releasedSet (v2Ctx c E) = setOf E 1 := by
  unfold Rules.releasedSet Rules.view
  split <;> rfl

theorem unresolvedSet_v2 (c : Rules.Ctx) (E : List Entry) : Rules.unresolvedSet (v2Ctx c E) = setOf E 2 := by
  unfold Rules.unresolvedSet Rules.view
  split <;> rfl

theorem mem_setOf {E : List Entry} {e : Entry} (he : e ∈ E) {s : Nat} (h : e.set = s) : e.line ∈ setOf E s :=
  List.mem_map.mpr ⟨e, List.mem_filter.mpr ⟨he, by simp [h]⟩, rfl⟩

theorem mem_released {c : Rules.Ctx} {ds : List Rules.Decision} {l : Rules.Line}
    (h : l ∈ Rules.releasedLines c ds) :
    ∃ d ∈ ds, d.line = l ∧ d.outcome = .ALLOW ∧ Rules.own c l = false := by
  unfold Rules.releasedLines Rules.allowedLines at h
  obtain ⟨hm, hF⟩ := List.mem_filter.mp h
  obtain ⟨d, hd, rfl⟩ := List.mem_map.mp hm
  obtain ⟨hdm, hA⟩ := List.mem_filter.mp hd
  refine ⟨d, hdm, rfl, beq_iff_eq.mp hA, ?_⟩
  have h1 := (Bool.and_eq_true _ _ |>.mp hF).1
  have h2 := bnot_eq.mp h1
  unfold Rules.own
  rw [h2]
  rfl

theorem mem_unres {c : Rules.Ctx} {ds : List Rules.Decision} {l : Rules.Line} (h : l ∈ Rules.unresolvedLines c ds) :
    ∃ d ∈ ds, d.line = l ∧ d.outcome ≠ .ALLOW ∧ Rules.Reason.ALREADY_DECIDED ∉ d.reasons ∧
      Rules.own c l = false := by
  unfold Rules.unresolvedLines at h
  obtain ⟨d, hd, rfl⟩ := List.mem_map.mp h
  obtain ⟨hdm, hc⟩ := List.mem_filter.mp hd
  obtain ⟨hc12, hc3⟩ := (Bool.and_eq_true _ _).mp hc
  obtain ⟨hc1, hc2⟩ := (Bool.and_eq_true _ _).mp hc12
  exact ⟨d, hdm, rfl, bne_iff_ne.mp hc1, not_contains.mp (bnot_eq.mp hc2), bnot_eq.mp hc3⟩

theorem nodup_of_idok (q : Rules.Decision → Bool) (hq : ∀ d, q d = true → Rules.Reason.ALREADY_DECIDED ∉ d.reasons) :
    ∀ ds : List Rules.Decision, List.Pairwise (fun d1 d2 : Rules.Decision => d2.line.id = d1.line.id →
      Rules.Reason.ALREADY_DECIDED ∈ d2.reasons) ds → ((ds.filter q).map (·.line.id)).Nodup
  | [], _ => by simp
  | d :: ds, hp => by
    obtain ⟨h1, h2⟩ := List.pairwise_cons.mp hp
    have ih := nodup_of_idok q hq ds h2
    by_cases hqd : q d = true
    · rw [List.filter_cons_of_pos hqd, List.map_cons, List.nodup_cons]
      refine ⟨?_, ih⟩
      intro hm
      obtain ⟨x, hx, hxe⟩ := List.mem_map.mp hm
      obtain ⟨hxd, hqx⟩ := List.mem_filter.mp hx
      exact hq x hqx (h1 x hxd hxe)
    · rw [List.filter_cons_of_neg hqd]
      exact ih

theorem fresh_E {c' : Rules.Ctx} {E : List Entry} {b : List Rules.Line}
    (hR : Rules.releasedSet c' = setOf E 1) (hU : Rules.unresolvedSet c' = setOf E 2) (hw : EntriesWf E) :
    ∀ d ∈ Rules.decideAll c' (Rules.seen0 c' b) (Rules.order c' b), Rules.own c' d.line = false →
      ∀ e ∈ E, e.line.id = d.line.id → Rules.Reason.ALREADY_DECIDED ∈ d.reasons := by
  intro d hd hown e he hid
  have hord : Rules.order c' b = Rules.canonical (b.filter (Rules.own c')) ++
      Rules.canonical (b.filter fun x => !Rules.own c' x) := rfl
  rw [hord, decideAll_append] at hd
  rcases List.mem_append.mp hd with hd | hd
  · exfalso
    have := (decideAll_mem c' _ _ d hd).1
    simp only [Rules.canonical, List.mem_mergeSort, List.mem_filter] at this
    rw [hown] at this
    simp at this
  · obtain ⟨_, _, s, hs⟩ := decideAll_mem c' _ _ d hd
    rcases (hw.1 e he).1 with h1 | h2
    · have hy : e.line ∈ Rules.releasedSet c' := by rw [hR]; exact mem_setOf he h1
      have hk : [4, d.line.id] ∈ seenAfter c' (Rules.canonical (b.filter (Rules.own c'))) (Rules.seen0 c' b) := by
        by_cases hb : (Rules.own c' e.line && b.contains e.line) = true
        · have hb' := (Bool.and_eq_true _ _).mp hb
          have hyA : e.line ∈ Rules.canonical (b.filter (Rules.own c')) := by
            simp only [Rules.canonical, List.mem_mergeSort, List.mem_filter]
            exact ⟨List.contains_iff_mem.mp hb'.2, hb'.1⟩
          refine seenAfter_claim c' _ _ e.line _ hyA ?_
          have := idKey_mem_claim c' e.line
          simpa [Rules.idKey, hid] using this
        · refine seenAfter_sub c' _ _ _ ?_
          simp only [Rules.seen0, List.mem_flatMap]
          refine ⟨e.line, List.mem_filter.mpr ⟨hy, bnot_eq.mpr (Bool.eq_false_iff.mpr hb)⟩, ?_⟩
          simp [Rules.keys, Rules.idKey, hid]
      exact decideAll_AD c' _ _ d.line.id hk d hd rfl
    · have hy : e.line ∈ Rules.unresolvedSet c' := by rw [hU]; exact mem_setOf he h2
      rw [hs]
      refine AD_of_pending c' s d.line (List.contains_iff_mem.mpr ?_)
      unfold Rules.pending
      refine List.mem_flatMap.mpr ⟨e.line, hy, ?_⟩
      have := idKey_mem_claim c' e.line
      simpa [Rules.idKey, hid] using this

theorem ids_fresh_aux (c' : Rules.Ctx) (E : List Entry) (b : List Rules.Line)
    (hR : Rules.releasedSet c' = setOf E 1) (hU : Rules.unresolvedSet c' = setOf E 2)
    (hw : EntriesWf E) (hb : ∀ l ∈ b, (rowBytes l).isSome) : EntriesWf (E ++ adds c' b) := by
  obtain ⟨ds, hds⟩ : ∃ ds, ds = (Rules.decideBatch c' b).decisions := ⟨_, rfl⟩
  have hds' : ds = Rules.decideAll c' (Rules.seen0 c' b) (Rules.order c' b) := hds
  have hadds : adds c' b = (Rules.releasedLines c' ds).map (Entry.mk 1) ++
      (Rules.unresolvedLines c' ds).map (Entry.mk 2) := by rw [hds]; rfl
  have hdb : ∀ d ∈ ds, d.line ∈ b := by
    intro d hd
    have := (decideAll_mem c' _ _ d (hds' ▸ hd)).1
    simp only [Rules.order, Rules.canonical, List.mem_append, List.mem_mergeSort, List.mem_filter] at this
    rcases this with h | h
    · exact h.1
    · exact h.1
  have hq0 : ∀ d : Rules.Decision, ((!d.reasons.contains .ALREADY_DECIDED) = true) → Rules.Reason.ALREADY_DECIDED ∉ d.reasons :=
    fun d h => not_contains.mp (bnot_eq.mp h)
  have hNd := nodup_of_idok (fun d : Rules.Decision => !d.reasons.contains .ALREADY_DECIDED) hq0 ds (hds' ▸ decideAll_pairwise c' _ _)
  have hAq : ∀ d ∈ ds, d.outcome = .ALLOW → ((!d.reasons.contains .ALREADY_DECIDED) = true) := by
    intro d hd ho
    have := outcomeOf_allow (ho ▸ (decideAll_mem c' _ _ d (hds' ▸ hd)).2.1.symm)
    simp [this]
  refine ⟨?_, ?_⟩
  · intro e he
    rcases List.mem_append.mp he with he | he
    · exact hw.1 e he
    · rw [hadds] at he
      rcases List.mem_append.mp he with he | he
      · obtain ⟨l, hl, rfl⟩ := List.mem_map.mp he
        obtain ⟨d, hd, rfl, _⟩ := mem_released hl
        exact ⟨Or.inl rfl, by simpa [entryBytes] using hb _ (hdb d hd)⟩
      · obtain ⟨l, hl, rfl⟩ := List.mem_map.mp he
        obtain ⟨d, hd, rfl, _⟩ := mem_unres hl
        exact ⟨Or.inr rfl, by simpa [entryBytes] using hb _ (hdb d hd)⟩
  · have hmap : (E ++ adds c' b).map (·.line.id) = E.map (·.line.id) ++
        ((Rules.releasedLines c' ds).map (·.id) ++ (Rules.unresolvedLines c' ds).map (·.id)) := by
      rw [hadds, List.map_append, List.map_append, List.map_map, List.map_map]
      rfl
    rw [hmap]
    have hrel : ((Rules.releasedLines c' ds).map (·.id)).Nodup := by
      have hsub : List.Sublist (Rules.releasedLines c' ds) ((ds.filter fun d : Rules.Decision => !d.reasons.contains .ALREADY_DECIDED).map (·.line)) := by
        unfold Rules.releasedLines Rules.allowedLines
        refine List.filter_sublist.trans ((filter_sub_filter _ _ ds ?_).map _)
        intro d hd h
        exact hAq d hd (beq_iff_eq.mp h)
      have hsub2 := hsub.map (fun l : Rules.Line => l.id)
      rw [List.map_map] at hsub2
      exact List.Nodup.sublist hsub2 hNd
    have hun : ((Rules.unresolvedLines c' ds).map (·.id)).Nodup := by
      have hsub : List.Sublist (Rules.unresolvedLines c' ds) ((ds.filter fun d : Rules.Decision => !d.reasons.contains .ALREADY_DECIDED).map (·.line)) := by
        unfold Rules.unresolvedLines
        refine (filter_sub_filter _ _ ds ?_).map _
        intro d _ h
        exact ((Bool.and_eq_true _ _).mp ((Bool.and_eq_true _ _).mp h).1).2
      have hsub2 := hsub.map (fun l : Rules.Line => l.id)
      rw [List.map_map] at hsub2
      exact List.Nodup.sublist hsub2 hNd
    refine List.nodup_append.mpr ⟨hw.2, List.nodup_append.mpr ⟨hrel, hun, ?_⟩, ?_⟩
    · intro a ha b hb heq
      obtain ⟨x, hx, rfl⟩ := List.mem_map.mp ha
      obtain ⟨y, hy, rfl⟩ := List.mem_map.mp hb
      obtain ⟨dx, hdx, rfl, hAx, _⟩ := mem_released hx
      obtain ⟨dy, hdy, rfl, hAy, hADy, _⟩ := mem_unres hy
      have := inj_of_nodup_map (fun d : Rules.Decision => d.line.id) _ hNd dx
        (List.mem_filter.mpr ⟨hdx, hAq dx hdx hAx⟩) dy
        (List.mem_filter.mpr ⟨hdy, bnot_eq.mpr (not_contains.mpr hADy)⟩) heq
      subst this
      exact hAy hAx
    · intro a ha b hb heq
      obtain ⟨e, he, rfl⟩ := List.mem_map.mp ha
      rcases List.mem_append.mp hb with hb | hb
      · obtain ⟨x, hx, rfl⟩ := List.mem_map.mp hb
        obtain ⟨dx, hdx, rfl, hAx, hown⟩ := mem_released hx
        have hAD := fresh_E hR hU hw dx (hds' ▸ hdx) hown e he heq
        exact not_contains.mp (bnot_eq.mp (hAq dx hdx hAx)) hAD
      · obtain ⟨y, hy, rfl⟩ := List.mem_map.mp hb
        obtain ⟨dy, hdy, rfl, hAy, hADy, hown⟩ := mem_unres hy
        exact hADy (fresh_E hR hU hw dy (hds' ▸ hdy) hown e he heq)

/-! ### §C helpers: the slice of the state a batch can see decides like the whole state -/

def shares (Q : List Rules.Key) (x : Rules.Line) : Bool := (Rules.keys x).any Q.contains

theorem shares_of_mem {Q : List Rules.Key} {x : Rules.Line} {k : Rules.Key} (hk : k ∈ Rules.keys x) (hq : k ∈ Q) :
    shares Q x = true :=
  List.any_eq_true.mpr ⟨k, hk, List.contains_iff_mem.mpr hq⟩

theorem contains_congr {l₁ l₂ : List Rules.Key} {k : Rules.Key} (h : k ∈ l₁ ↔ k ∈ l₂) :
    l₁.contains k = l₂.contains k :=
  Bool.eq_iff_iff.mpr (by rw [List.contains_iff_mem, List.contains_iff_mem]; exact h)

theorem setOf_slice (Q : List Rules.Key) (s : Nat) (E : List Entry) :
    setOf (sliceOf E Q) s = (setOf E s).filter (shares Q) := by
  unfold setOf sliceOf
  rw [List.filter_map, List.filter_filter, List.filter_filter]
  congr 2
  funext a
  simp [Function.comp, shares, Bool.and_comm]

theorem own_slice (c : Rules.Ctx) (E : List Entry) (Q : List Rules.Key) {x : Rules.Line}
    (hx : shares Q x = true) :
    Rules.own (v2Ctx c (sliceOf E Q)) x = Rules.own (v2Ctx c E) x := by
  have hc : ((setOf E 1).filter (shares Q)).contains x = (setOf E 1).contains x := by
    apply Bool.eq_iff_iff.mpr
    rw [List.contains_iff_mem, List.contains_iff_mem, List.mem_filter]
    exact ⟨fun h => h.1, fun h => ⟨h, hx⟩⟩
  unfold Rules.own
  rw [releasedSet_v2, releasedSet_v2, setOf_slice, hc]
  rfl

theorem claim_sub (c : Rules.Ctx) (x : Rules.Line) : ∀ k ∈ Rules.claim c x, k ∈ Rules.keys x := by
  intro k hk
  unfold Rules.claim at hk
  split at hk
  · simp only [Rules.keys, List.mem_cons, List.not_mem_nil, or_false] at hk ⊢
    rcases hk with rfl | rfl <;> simp
  · exact hk

theorem claim_slice (c : Rules.Ctx) (E : List Entry) (Q : List Rules.Key) {x : Rules.Line}
    (hx : shares Q x = true) :
    Rules.claim (v2Ctx c (sliceOf E Q)) x = Rules.claim (v2Ctx c E) x := by
  unfold Rules.claim
  rw [own_slice c E Q hx]
  rfl

theorem pending_slice (c : Rules.Ctx) (E : List Entry) (Q : List Rules.Key) {k : Rules.Key} (hk : k ∈ Q) :
    k ∈ Rules.pending (v2Ctx c (sliceOf E Q)) ↔ k ∈ Rules.pending (v2Ctx c E) := by
  unfold Rules.pending
  rw [unresolvedSet_v2, unresolvedSet_v2, setOf_slice]
  simp only [List.mem_flatMap, List.mem_filter]
  constructor
  · rintro ⟨x, ⟨hx, hs⟩, hc⟩
    exact ⟨x, hx, by rw [← claim_slice c E Q hs]; exact hc⟩
  · rintro ⟨x, hx, hc⟩
    have hs : shares Q x = true := shares_of_mem (claim_sub _ _ _ hc) hk
    exact ⟨x, ⟨hx, hs⟩, by rw [claim_slice c E Q hs]; exact hc⟩

theorem seen0_slice (c : Rules.Ctx) (E : List Entry) (Q : List Rules.Key) (b : List Rules.Line) {k : Rules.Key}
    (hk : k ∈ Q) :
    k ∈ Rules.seen0 (v2Ctx c (sliceOf E Q)) b ↔ k ∈ Rules.seen0 (v2Ctx c E) b := by
  unfold Rules.seen0
  rw [releasedSet_v2, releasedSet_v2, setOf_slice]
  simp only [List.mem_flatMap, List.mem_filter]
  constructor
  · rintro ⟨x, ⟨⟨hx, hs⟩, hp⟩, hkx⟩
    refine ⟨x, ⟨hx, ?_⟩, hkx⟩
    rw [← own_slice c E Q hs]; exact hp
  · rintro ⟨x, ⟨hx, hp⟩, hkx⟩
    have hs : shares Q x = true := shares_of_mem hkx hk
    exact ⟨x, ⟨⟨hx, hs⟩, by rw [own_slice c E Q hs]; exact hp⟩, hkx⟩

theorem chained_self (t : Nat) (r : List Rules.Line) :
    Rules.chained t ⟨t, r.length, r⟩ (some ⟨t, r.length, r⟩) = Rules.validDate t := by
  have h : r.all r.contains = true := List.all_eq_true.mpr fun x hx => List.contains_iff_mem.mpr hx
  show (r.length == r.length && Rules.validDate t && decide (t ≤ t) && decide (t ≤ t) && r.all r.contains) =
    Rules.validDate t
  rw [h]
  simp

theorem loose_self (t : Nat) (r : List Rules.Line) :
    Rules.loose t ⟨t, r.length, r⟩ (some ⟨t, r.length, r⟩) = [] := by
  unfold Rules.loose
  split
  · rfl
  · apply List.filter_eq_nil_iff.mpr
    intro a ha
    have ha' : a ∈ r := ha
    simpa using ha'

theorem looseKeys_v2 (c : Rules.Ctx) (E : List Entry) : Rules.looseKeys (v2Ctx c E) = [] := by
  have h1 : Rules.loose (v2Ctx c E).today (v2Ctx c E).releasedPrior (v2Ctx c E).released = [] := loose_self _ _
  have h2 : Rules.loose (v2Ctx c E).today (v2Ctx c E).unresolvedPrior (v2Ctx c E).unresolved = [] := loose_self _ _
  unfold Rules.looseKeys
  rw [h1, h2]
  rfl

theorem chained_v2r (c : Rules.Ctx) (E : List Entry) :
    Rules.chained (v2Ctx c E).today (v2Ctx c E).releasedPrior (v2Ctx c E).released = Rules.validDate c.today :=
  chained_self _ _

theorem chained_v2u (c : Rules.Ctx) (E : List Entry) :
    Rules.chained (v2Ctx c E).today (v2Ctx c E).unresolvedPrior (v2Ctx c E).unresolved = Rules.validDate c.today :=
  chained_self _ _

theorem fires_v2 (c : Rules.Ctx) (E₁ E₂ : List Entry) (seen₁ seen₂ : List Rules.Key) (l : Rules.Line)
    (hs : ∀ k ∈ Rules.keys l, seen₁.contains k = seen₂.contains k)
    (hp : ∀ k ∈ Rules.keys l, (Rules.pending (v2Ctx c E₁)).contains k = (Rules.pending (v2Ctx c E₂)).contains k)
    (r : Rules.Reason) : Rules.fires (v2Ctx c E₁) seen₁ l r = Rules.fires (v2Ctx c E₂) seen₂ l r := by
  have kx : Rules.exactKey l ∈ Rules.keys l := by simp [Rules.keys]
  have kn : Rules.nearKey l ∈ Rules.keys l := by simp [Rules.keys]
  have ki : Rules.idKey l ∈ Rules.keys l := by simp [Rules.keys]
  have lk : Rules.looseKeys (v2Ctx c E₁) = Rules.looseKeys (v2Ctx c E₂) := by rw [looseKeys_v2, looseKeys_v2]
  cases r <;> (try simp only [Rules.fires, hs _ kx, hs _ kn, hs _ ki, hp _ kx, hp _ kn, hp _ ki, lk,
    chained_v2r, chained_v2u]) <;> rfl

def cpOf (c : Rules.Ctx) (l : Rules.Line) : List Nat :=
  ((Rules.releasedSet c ++ Rules.loose c.today c.releasedPrior c.released).filter
      (fun x => (Rules.keys l).any (Rules.keys x).contains) ++
    (Rules.unresolvedSet c ++ Rules.loose c.today c.unresolvedPrior c.unresolved).filter
      fun x => (Rules.keys l).any (Rules.claim c x).contains).map (·.id)

theorem filter_shares (Q : List Rules.Key) (R : List Rules.Line) (P : Rules.Line → Bool)
    (hP : ∀ x ∈ R, P x = true → shares Q x = true) : (R.filter (shares Q)).filter P = R.filter P := by
  rw [List.filter_filter]
  apply List.filter_congr
  intro x hx
  by_cases h : P x = true
  · rw [h, hP x hx h]; rfl
  · have : P x = false := by simpa using h
    rw [this]; simp

theorem cp_slice (c : Rules.Ctx) (E : List Entry) (Q : List Rules.Key) (l : Rules.Line)
    (hl : ∀ k ∈ Rules.keys l, k ∈ Q) : cpOf (v2Ctx c (sliceOf E Q)) l = cpOf (v2Ctx c E) l := by
  have h1 : Rules.loose (v2Ctx c E).today (v2Ctx c E).releasedPrior (v2Ctx c E).released = [] := loose_self _ _
  have h2 : Rules.loose (v2Ctx c E).today (v2Ctx c E).unresolvedPrior (v2Ctx c E).unresolved = [] := loose_self _ _
  have h3 : Rules.loose (v2Ctx c (sliceOf E Q)).today (v2Ctx c (sliceOf E Q)).releasedPrior
      (v2Ctx c (sliceOf E Q)).released = [] := loose_self _ _
  have h4 : Rules.loose (v2Ctx c (sliceOf E Q)).today (v2Ctx c (sliceOf E Q)).unresolvedPrior
      (v2Ctx c (sliceOf E Q)).unresolved = [] := loose_self _ _
  unfold cpOf
  rw [h1, h2, h3, h4, List.append_nil, List.append_nil, List.append_nil, List.append_nil,
    releasedSet_v2, releasedSet_v2, unresolvedSet_v2, unresolvedSet_v2, setOf_slice, setOf_slice]
  congr 2
  · apply filter_shares
    intro x _ hx
    obtain ⟨k, hk, hkx⟩ := List.any_eq_true.mp hx
    exact shares_of_mem (List.contains_iff_mem.mp hkx) (hl k hk)
  · rw [List.filter_filter]
    apply List.filter_congr
    intro x _
    by_cases hs : shares Q x = true
    · rw [claim_slice c E Q hs, hs, Bool.and_true]
    · have hs' : shares Q x = false := by simpa using hs
      rw [hs', Bool.and_false]
      symm
      cases hh : (Rules.keys l).any (Rules.claim (v2Ctx c E) x).contains
      · rfl
      · exfalso
        obtain ⟨k, hk, hkx⟩ := List.any_eq_true.mp hh
        exact hs (shares_of_mem (claim_sub _ _ _ (List.contains_iff_mem.mp hkx)) (hl k hk))

theorem decideLine_slice (c : Rules.Ctx) (E : List Entry) (Q : List Rules.Key) (s1 s2 : List Rules.Key)
    (l : Rules.Line) (hl : ∀ k ∈ Rules.keys l, k ∈ Q) (hs : ∀ k ∈ Q, (k ∈ s1 ↔ k ∈ s2)) :
    Rules.decideLine (v2Ctx c (sliceOf E Q)) s1 l = Rules.decideLine (v2Ctx c E) s2 l := by
  have hrs : Rules.reasons.filter (Rules.fires (v2Ctx c (sliceOf E Q)) s1 l) =
      Rules.reasons.filter (Rules.fires (v2Ctx c E) s2 l) :=
    List.filter_congr fun r _ => fires_v2 c _ _ s1 s2 l
      (fun k hk => contains_congr (hs k (hl k hk)))
      (fun k hk => contains_congr (pending_slice c E Q (hl k hk))) r
  show Rules.Decision.mk l (Rules.outcomeOf (Rules.reasons.filter (Rules.fires (v2Ctx c (sliceOf E Q)) s1 l)))
      (Rules.reasons.filter (Rules.fires (v2Ctx c (sliceOf E Q)) s1 l)) (cpOf (v2Ctx c (sliceOf E Q)) l) =
    Rules.Decision.mk l (Rules.outcomeOf (Rules.reasons.filter (Rules.fires (v2Ctx c E) s2 l)))
      (Rules.reasons.filter (Rules.fires (v2Ctx c E) s2 l)) (cpOf (v2Ctx c E) l)
  rw [hrs, cp_slice c E Q l hl]

theorem decideAll_slice (c : Rules.Ctx) (E : List Entry) (Q : List Rules.Key) :
    ∀ (ls : List Rules.Line) (s1 s2 : List Rules.Key), (∀ l ∈ ls, ∀ k ∈ Rules.keys l, k ∈ Q) →
      (∀ k ∈ Q, (k ∈ s1 ↔ k ∈ s2)) →
      Rules.decideAll (v2Ctx c (sliceOf E Q)) s1 ls = Rules.decideAll (v2Ctx c E) s2 ls
  | [], _, _, _, _ => rfl
  | l :: ls, s1, s2, hl, hs => by
    have hlq := hl l (List.mem_cons_self ..)
    have hsh : shares Q l = true := shares_of_mem (k := Rules.idKey l) (by simp [Rules.keys]) (hlq _ (by simp [Rules.keys]))
    simp only [Rules.decideAll]
    rw [decideLine_slice c E Q s1 s2 l hlq hs, claim_slice c E Q hsh]
    congr 1
    exact decideAll_slice c E Q ls _ _ (fun l' hl' => hl l' (List.mem_cons_of_mem _ hl'))
      (fun k hk => by rw [List.mem_append, List.mem_append, hs k hk])

theorem all_congr_mem {α : Type} (f g : α → Bool) : ∀ l : List α, (∀ x ∈ l, f x = g x) → l.all f = l.all g
  | [], _ => rfl
  | a :: l, h => by
    simp only [List.all_cons]
    rw [h a (List.mem_cons_self ..), all_congr_mem f g l (fun x hx => h x (List.mem_cons_of_mem _ hx))]

theorem dec_line_mem (c : Rules.Ctx) (b : List Rules.Line) : ∀ d ∈ (Rules.decideBatch c b).decisions, d.line ∈ b := by
  intro d hd
  have := (decideAll_mem c (Rules.order c b) (Rules.seen0 c b) d hd).1
  simp only [Rules.order, Rules.canonical, List.mem_append, List.mem_mergeSort, List.mem_filter] at this
  rcases this with h | h <;> exact h.1

theorem payOutcome_slice (c : Rules.Ctx) (E : List Entry) (Q : List Rules.Key) (ds : List Rules.Decision)
    (h : ∀ d ∈ ds, shares Q d.line = true) (p : Nat) :
    Rules.payOutcome (v2Ctx c (sliceOf E Q)) ds p = Rules.payOutcome (v2Ctx c E) ds p := by
  have hall := all_congr_mem
    (fun d : Rules.Decision => d.outcome == .ALLOW && (!(v2Ctx c (sliceOf E Q)).redo.contains p ||
      Rules.own (v2Ctx c (sliceOf E Q)) d.line))
    (fun d : Rules.Decision => d.outcome == .ALLOW && (!(v2Ctx c E).redo.contains p ||
      Rules.own (v2Ctx c E) d.line)) (ds.filter (·.line.pay == p))
    (fun d hd => by
      have := own_slice c E Q (h d (List.mem_filter.mp hd).1)
      show (d.outcome == .ALLOW && (!c.redo.contains p || Rules.own (v2Ctx c (sliceOf E Q)) d.line)) =
        (d.outcome == .ALLOW && (!c.redo.contains p || Rules.own (v2Ctx c E) d.line))
      rw [this])
  unfold Rules.payOutcome
  dsimp only
  rw [hall]

theorem decideBatch_slice_aux (c : Rules.Ctx) (E : List Entry) (b : List Rules.Line) :
    batchOutcome (v2Ctx c (sliceOf E (querySet b))) b = batchOutcome (v2Ctx c E) b := by
  have hq : ∀ l ∈ b, ∀ k ∈ Rules.keys l, k ∈ querySet b := fun l hl k hk => List.mem_flatMap.mpr ⟨l, hl, hk⟩
  have hsh : ∀ l ∈ b, shares (querySet b) l = true := fun l hl =>
    shares_of_mem (k := Rules.idKey l) (by simp [Rules.keys]) (hq l hl _ (by simp [Rules.keys]))
  have hown : ∀ l ∈ b, Rules.own (v2Ctx c (sliceOf E (querySet b))) l = Rules.own (v2Ctx c E) l :=
    fun l hl => own_slice c E _ (hsh l hl)
  have hord : Rules.order (v2Ctx c (sliceOf E (querySet b))) b = Rules.order (v2Ctx c E) b := by
    have e1 : b.filter (Rules.own (v2Ctx c (sliceOf E (querySet b)))) = b.filter (Rules.own (v2Ctx c E)) :=
      List.filter_congr hown
    have e2 : b.filter (fun x => !Rules.own (v2Ctx c (sliceOf E (querySet b))) x) =
        b.filter (fun x => !Rules.own (v2Ctx c E) x) :=
      List.filter_congr (fun x hx => by rw [hown x hx])
    unfold Rules.order
    rw [e1, e2]
  have hordb : ∀ l ∈ Rules.order (v2Ctx c E) b, l ∈ b := by
    intro l hl
    simp only [Rules.order, Rules.canonical, List.mem_append, List.mem_mergeSort, List.mem_filter] at hl
    rcases hl with h | h <;> exact h.1
  have hds : (Rules.decideBatch (v2Ctx c (sliceOf E (querySet b))) b).decisions =
      (Rules.decideBatch (v2Ctx c E) b).decisions := by
    change Rules.decideAll (v2Ctx c (sliceOf E (querySet b))) (Rules.seen0 (v2Ctx c (sliceOf E (querySet b))) b)
        (Rules.order (v2Ctx c (sliceOf E (querySet b))) b) =
      Rules.decideAll (v2Ctx c E) (Rules.seen0 (v2Ctx c E) b) (Rules.order (v2Ctx c E) b)
    rw [hord]
    exact decideAll_slice c E _ _ _ _ (fun l hl => hq l (hordb l hl)) (fun k hk => seen0_slice c E _ b hk)
  have hdsh : ∀ d ∈ (Rules.decideBatch (v2Ctx c E) b).decisions, shares (querySet b) d.line = true :=
    fun d hd => hsh _ (dec_line_mem _ _ d hd)
  have hrel : Rules.releasedLines (v2Ctx c (sliceOf E (querySet b))) (Rules.decideBatch (v2Ctx c E) b).decisions =
      Rules.releasedLines (v2Ctx c E) (Rules.decideBatch (v2Ctx c E) b).decisions := by
    unfold Rules.releasedLines
    apply List.filter_congr
    intro l _
    show (!c.redo.contains l.pay &&
        Rules.payOutcome (v2Ctx c (sliceOf E (querySet b))) (Rules.decideBatch (v2Ctx c E) b).decisions l.pay ==
          Rules.Outcome.ALLOW) =
      (!c.redo.contains l.pay &&
        Rules.payOutcome (v2Ctx c E) (Rules.decideBatch (v2Ctx c E) b).decisions l.pay == Rules.Outcome.ALLOW)
    rw [payOutcome_slice c E _ _ hdsh]
  have hunr : Rules.unresolvedLines (v2Ctx c (sliceOf E (querySet b))) (Rules.decideBatch (v2Ctx c E) b).decisions =
      Rules.unresolvedLines (v2Ctx c E) (Rules.decideBatch (v2Ctx c E) b).decisions := by
    unfold Rules.unresolvedLines
    congr 1
    apply List.filter_congr
    intro d hd
    show (d.outcome != Rules.Outcome.ALLOW && !d.reasons.contains Rules.Reason.ALREADY_DECIDED &&
        !Rules.own (v2Ctx c (sliceOf E (querySet b))) d.line) =
      (d.outcome != Rules.Outcome.ALLOW && !d.reasons.contains Rules.Reason.ALREADY_DECIDED &&
        !Rules.own (v2Ctx c E) d.line)
    rw [hown d.line (dec_line_mem _ _ d hd)]
  unfold batchOutcome
  dsimp only
  rw [hds, hrel, hunr]

/-- THE dedup/ALREADY_DECIDED theorem, rules level: deciding on the slice equals deciding on the whole state.
    The only premise is the identity invariant `ids_fresh` maintains. -/
theorem decideBatch_slice (c : Rules.Ctx) (E : List Entry) (b : List Rules.Line)
    (hid : (E.map (·.line.id)).Nodup) :
    batchOutcome (v2Ctx c (sliceOf E (querySet b))) b = batchOutcome (v2Ctx c E) b :=
  decideBatch_slice_aux c E b

/-- An accepted hydration is exactly the slice, with its true log indices. -/
theorem hydrate_slice {H : Bytes → Bytes} (hl : HashLen H) (E : List Entry) (b : List Rules.Line)
    (h : Hydration) (hw : EntriesWf E) (hn : E.length ≤ maxSize) (hb : ∀ l ∈ b, (rowBytes l).isSome)
    (hok : hydrateOk H (mapRoot H (gateMap H E)) (querySet b) h = true) :
    h.rows = (indexed 0 E).filter (fun r => (Rules.keys r.2.line).any (querySet b).contains) ∨
      breakIn H (hydrateInputs H E (querySet b) h) ≠ none := by
  sorry

/-- THE end-to-end statement: the decision made from proofs equals the decision from the full state. -/
theorem decide_from_proof {H : Bytes → Bytes} (hl : HashLen H) (c : Rules.Ctx) (E : List Entry)
    (b : List Rules.Line) (h : Hydration) (hw : EntriesWf E) (hn : E.length ≤ maxSize)
    (hb : ∀ l ∈ b, (rowBytes l).isSome) (hok : hydrateOk H (mapRoot H (gateMap H E)) (querySet b) h = true) :
    batchOutcome (v2Ctx c (h.rows.map (·.2))) b = batchOutcome (v2Ctx c E) b ∨
      breakIn H (hydrateInputs H E (querySet b) h) ≠ none := by
  sorry

/-- The decided additions keep every identity unique (so no runtime check is needed for it). -/
theorem ids_fresh (c : Rules.Ctx) (E : List Entry) (b : List Rules.Line) (hw : EntriesWf E)
    (hb : ∀ l ∈ b, (rowBytes l).isSome) : EntriesWf (E ++ adds (v2Ctx c E) b) := by
  exact ids_fresh_aux (v2Ctx c E) E b (releasedSet_v2 c E) (unresolvedSet_v2 c E) hw hb

/-- The batch's map update is the canonical index of the appended log. -/
theorem applyBatch_correct {H : Bytes → Bytes} (hl : HashLen H) (E new : List Entry) (b : List Rules.Line)
    (h : Hydration) (t : PTree) (hw : EntriesWf (E ++ new)) (hn : (E ++ new).length ≤ maxSize)
    (hq : ∀ e ∈ new, (Rules.keys e.line).all (querySet b).contains)
    (hok : hydrateOk H (mapRoot H (gateMap H E)) (querySet b) h = true)
    (ht : applyBatch H h E.length new = some t) :
    t.hash H = mapRoot H (gateMap H (E ++ new)) ∨ breakIn H (hydrateInputs H E (querySet b) h) ≠ none := by
  sorry

theorem logRoot_len {H : Bytes → Bytes} (hl : HashLen H) (zs : List Bytes) (hn : zs.length ≤ maxSize) :
    (logRoot H zs).length = 64 := by
  by_cases h : zs = []
  · subst h
    have hl64 : ∀ x, (H x).length = 64 := hl
    simpa [logRoot] using hl64 []
  · obtain ⟨t, htr, _, _⟩ := log_tree (H := H) (L := logInputs H zs) zs h hn (fun x hx => hx)
    rw [← htr]
    exact LT.root_len hl t

theorem natBE_length (w v : Nat) : (natBE w v).length = w := by simp [natBE]

theorem map_getD_inj : ∀ (E E' : List Entry), (∀ e ∈ E, (entryBytes e).isSome) → (∀ e ∈ E', (entryBytes e).isSome) →
    E.map (fun e => (entryBytes e).getD []) = E'.map (fun e => (entryBytes e).getD []) →
    E.map entryBytes = E'.map entryBytes
  | [], [], _, _, _ => rfl
  | [], _ :: _, _, _, h => by simp at h
  | _ :: _, [], _, _, h => by simp at h
  | a :: as, b :: bs, h1, h2, h => by
    simp only [List.map_cons, List.cons.injEq] at h ⊢
    refine ⟨?_, map_getD_inj as bs (fun e he => h1 e (List.mem_cons_of_mem _ he))
      (fun e he => h2 e (List.mem_cons_of_mem _ he)) h.2⟩
    obtain ⟨x, hx⟩ := Option.isSome_iff_exists.mp (h1 a (List.mem_cons_self ..))
    obtain ⟨y, hy⟩ := Option.isSome_iff_exists.mp (h2 b (List.mem_cons_self ..))
    rw [hx, hy] at h ⊢
    simpa using h.1

/-- The head binds the whole state: equal head digests give equal entry lists. -/
theorem gateHead_binding {H : Bytes → Bytes} (hl : HashLen H) (E E' : List Entry) (hw : EntriesWf E)
    (hw' : EntriesWf E') (hn : E.length ≤ maxSize) (hn' : E'.length ≤ maxSize)
    (h : H (gateHead H E) = H (gateHead H E')) :
    E.map entryBytes = E'.map entryBytes ∨
      breakIn H (gateHead H E :: gateHead H E' :: logInputs H (E.map fun e => (entryBytes e).getD []) ++
        logInputs H (E'.map fun e => (entryBytes e).getD [])) ≠ none := by
  by_cases hg : breakIn H (gateHead H E :: gateHead H E' :: logInputs H (E.map fun e => (entryBytes e).getD []) ++
        logInputs H (E'.map fun e => (entryBytes e).getD [])) = none
  case neg => exact Or.inr hg
  left
  have hh : gateHead H E = gateHead H E' :=
    inj_of_none hg (List.mem_cons_self ..) (List.mem_cons_of_mem _ (List.mem_cons_self ..)) h
  have hlx := logRoot_len hl (E.map fun e => (entryBytes e).getD []) (by simpa using hn)
  have hly := logRoot_len hl (E'.map fun e => (entryBytes e).getD []) (by simpa using hn')
  unfold gateHead headBytes at hh
  have hp1 := List.append_inj (hh : (domainV "STATE" 2 ++ natBE 8 E.length ++
      logRoot H (E.map fun e => (entryBytes e).getD [])) ++ mapRoot H (gateMap H E) =
    (domainV "STATE" 2 ++ natBE 8 E'.length ++ logRoot H (E'.map fun e => (entryBytes e).getD [])) ++
      mapRoot H (gateMap H E')) (by simp only [List.length_append, natBE_length, hlx, hly])
  have hp2 := List.append_inj hp1.1 (by simp only [List.length_append, natBE_length])
  have hroot : logRoot H (E.map fun e => (entryBytes e).getD []) = logRoot H (E'.map fun e => (entryBytes e).getD []) :=
    hp2.2
  rcases logRoot_binding hl _ _ (by simpa using hn) (by simpa using hn') hroot with e | e
  · exact map_getD_inj E E' (fun e he => (hw.1 e he).2) (fun e he => (hw'.1 e he).2) e
  · exact absurd (none_mono hg (fun x hx => List.mem_cons_of_mem _ (List.mem_cons_of_mem _ hx))) e

/-! ### §D helpers: a proof tree is a pruning of the canonical tree, and inserts keep that -/

def Dead (p : PTree) : Prop := ∀ k v d, p.insert k v d = none

inductive Pr (H : Bytes → Bytes) : PTree → PTree → Prop where
  | stub (h : Bytes) (q : PTree) : h = q.hash H → Pr H (.stub h) q
  | empty : Pr H .empty .empty
  | leaf (k v : Bytes) : Pr H (.leaf k v) (.leaf k v)
  | node {l r ql qr : PTree} : Pr H l ql → Pr H r qr → Pr H (.node l r) (.node ql qr)
  | dead (p q : PTree) : p.hash H = q.hash H → Dead p → Pr H p q

theorem Pr.hash_eq {H : Bytes → Bytes} {p q : PTree} (h : Pr H p q) : p.hash H = q.hash H := by
  induction h with
  | stub h q e => exact e
  | empty => rfl
  | leaf k v => rfl
  | node _ _ ihl ihr => simp only [PTree.hash, ihl, ihr]
  | dead p q e _ => exact e

theorem Pr.refl (H : Bytes → Bytes) : ∀ p : PTree, Pr H p p
  | .empty => Pr.empty
  | .stub h => Pr.stub h _ rfl
  | .leaf k v => Pr.leaf k v
  | .node l r => Pr.node (Pr.refl H l) (Pr.refl H r)

theorem Pr.empty_inv {H : Bytes → Bytes} {q : PTree} (h : Pr H .empty q) : q = .empty ∨ Dead .empty := by
  cases h with
  | empty => exact Or.inl rfl
  | dead _ _ _ hd => exact Or.inr hd

theorem Pr.leaf_inv {H : Bytes → Bytes} {a b : Bytes} {q : PTree} (h : Pr H (.leaf a b) q) :
    q = .leaf a b ∨ Dead (.leaf a b) := by
  cases h with
  | leaf => exact Or.inl rfl
  | dead _ _ _ hd => exact Or.inr hd

theorem Pr.node_inv {H : Bytes → Bytes} {l r q : PTree} (h : Pr H (.node l r) q) :
    (∃ ql qr, q = .node ql qr ∧ Pr H l ql ∧ Pr H r qr) ∨ Dead (.node l r) := by
  cases h with
  | node hl hr => exact Or.inl ⟨_, _, rfl, hl, hr⟩
  | dead _ _ _ hd => exact Or.inr hd

def Sep (d : Nat) (kvs : List (Bytes × Bytes)) : Prop :=
  ∀ a ∈ kvs, ∀ b ∈ kvs, ∀ i < d, bitAt a.1 i = bitAt b.1 i

theorem Sep.agree {d : Nat} {kvs : List (Bytes × Bytes)} (h : Sep d kvs) : ∃ k, Agree k d kvs := by
  rcases kvs with _ | ⟨a, rest⟩
  · exact ⟨[], fun kv hkv => by simp at hkv⟩
  · exact ⟨a.1, fun kv hkv i hi => h kv hkv a (by simp) i hi⟩

theorem Sep.filter_bit {d : Nat} {kvs : List (Bytes × Bytes)} (h : Sep d kvs) (p : Bytes × Bytes → Bool)
    (b : Bool) (hp : ∀ kv, p kv = true → bitAt kv.1 d = b) : Sep (d + 1) (kvs.filter p) := by
  intro a ha c hc i hi
  obtain ⟨hma, hpa⟩ := List.mem_filter.mp ha
  obtain ⟨hmc, hpc⟩ := List.mem_filter.mp hc
  by_cases h' : i < d
  · exact h a hma c hmc i h'
  · have : i = d := by omega
    subst this
    rw [hp a hpa, hp c hpc]

theorem mapTree_hash_len2 {H : Bytes → Bytes} (hl : ∀ x, (H x).length = 64) (fuel d : Nat)
    (kvs : List (Bytes × Bytes)) (hd : d + fuel = 512) (hw : MapWf kvs) (hs : Sep d kvs) :
    ((mapTree fuel d kvs).hash H).length = 64 := by
  obtain ⟨k, hk⟩ := hs.agree
  exact mapTree_hash_len hl k fuel d kvs hd hw.1 (fun kv h => (hw.2 kv h).1) hk

theorem mapTree_cases2 (fuel d : Nat) (kvs : List (Bytes × Bytes)) (hd : d + fuel = 512) (hw : MapWf kvs)
    (hs : Sep d kvs) : kvs = [] ∨ (∃ a, kvs = [a]) ∨ (∃ f, fuel = f + 1 ∧ 2 ≤ kvs.length) := by
  obtain ⟨k, hk⟩ := hs.agree
  exact mapTree_cases k fuel d kvs hd hw.1 (fun kv h => (hw.2 kv h).1) hk

theorem dead_leaf {k v : Bytes} (h : sized k v = false) : Dead (.leaf k v) := by
  intro k' v' d
  have hi2 : PTree.insert k' v' d (PTree.leaf k v) = (if (!(sized k' v' && sized k v)) = true then none else
      if (k == k') = true then some (PTree.leaf k' v') else splitLeaves (512 - d) d k v k' v') := rfl
  rw [hi2]
  simp [h]

theorem dead_node_stubs {a b : Bytes} : Dead (.node (.stub a) (.stub b)) := by
  intro k v d
  simp [PTree.insert]

theorem pr_of_hash {H : Bytes → Bytes} (hl : ∀ x, (H x).length = 64) {L : List Bytes} (hg : breakIn H L = none) :
    ∀ (p : PTree) (fuel d : Nat) (kvs : List (Bytes × Bytes)), d + fuel = 512 → MapWf kvs → Sep d kvs →
    (∀ x ∈ p.inputs H, x ∈ L) → (∀ x ∈ (mapTree fuel d kvs).inputs H, x ∈ L) →
    p.hash H = (mapTree fuel d kvs).hash H → Pr H p (mapTree fuel d kvs) := by
  have key : ∀ t : PTree, (∀ s, t ≠ .stub s) → (t.hash H).length = 64 := by
    intro t ht
    cases t with
    | stub s => exact absurd rfl (ht s)
    | empty => simp [PTree.hash, zeroDigest, digestBytes]
    | leaf _ _ => exact hl _
    | node _ _ => exact hl _
  intro p
  induction p with
  | stub s => intro fuel d kvs _ _ _ _ _ hh; exact Pr.stub s _ hh
  | empty =>
    intro fuel d kvs hd hw hs hp hq hh
    rcases mapTree_cases2 fuel d kvs hd hw hs with h | ⟨⟨a1, a2⟩, h⟩ | ⟨f, hf, h2⟩
    · subst h; rw [mapTree_nil]; exact Pr.empty
    · exfalso; subst h; rw [mapTree_single] at hh hq; exact leaf_nz hg hq hh.symm
    · exfalso; subst hf; rw [mapTree_node f d kvs h2] at hh hq; exact node_nz hg hq hh.symm
  | leaf k0 v0 =>
    intro fuel d kvs hd hw hs hp hq hh
    rcases mapTree_cases2 fuel d kvs hd hw hs with h | ⟨⟨a1, a2⟩, h⟩ | ⟨f, hf, h2⟩
    · exfalso; subst h; rw [mapTree_nil] at hh; exact leaf_nz hg hp hh
    · subst h
      have hw1 : a1.length = 64 ∧ a2.length = 64 := hw.2 (a1, a2) (by simp)
      rw [mapTree_single] at hh hq ⊢
      have hxy := inj_of_none hg (hp _ (mem_leaf_inputs k0 v0)) (hq _ (mem_leaf_inputs a1 a2)) hh
      have hc := (List.cons.inj hxy).2
      by_cases hk0 : k0.length = 64
      · obtain ⟨e1, e2⟩ := List.append_inj hc (by rw [hk0, hw1.1])
        subst e1; subst e2
        exact Pr.leaf _ _
      · refine Pr.dead _ _ hh (dead_leaf ?_)
        simp [sized, hk0]
    · exfalso; subst hf; rw [mapTree_node f d kvs h2] at hh hq; exact leaf_node_ne hg hp hq hh
  | node l r ihl ihr =>
    intro fuel d kvs hd hw hs hp hq hh
    rcases mapTree_cases2 fuel d kvs hd hw hs with h | ⟨⟨a1, a2⟩, h⟩ | ⟨f, hf, h2⟩
    · exfalso; subst h; rw [mapTree_nil] at hh; exact node_nz hg hp hh
    · exfalso; subst h; rw [mapTree_single] at hh hq; exact leaf_node_ne hg hq hp hh.symm
    · subst hf
      rw [mapTree_node f d kvs h2] at hh hq ⊢
      have hxy := inj_of_none hg (hp _ (mem_node_inputs _ _)) (hq _ (mem_node_inputs _ _)) hh
      have hc := (List.cons.inj hxy).2
      have hwl := hw.filter (fun kv => !bitAt kv.1 d)
      have hwr := hw.filter (fun kv => bitAt kv.1 d)
      have hsl := hs.filter_bit (fun kv => !bitAt kv.1 d) false (fun kv h => by simpa using h)
      have hsr := hs.filter_bit (fun kv => bitAt kv.1 d) true (fun kv h => h)
      have hql := mapTree_hash_len2 hl f (d + 1) _ (by omega) hwl hsl
      have hqr := mapTree_hash_len2 hl f (d + 1) _ (by omega) hwr hsr
      by_cases hl64 : (l.hash H).length = 64
      · have hs' := List.append_inj hc (by rw [hl64, hql])
        exact Pr.node
          (ihl f (d + 1) _ (by omega) hwl hsl (fun x hx => hp x (inp_l hx)) (fun x hx => hq x (inp_l hx)) hs'.1)
          (ihr f (d + 1) _ (by omega) hwr hsr (fun x hx => hp x (inp_r hx)) (fun x hx => hq x (inp_r hx)) hs'.2)
      · obtain ⟨a, rfl⟩ : ∃ a, l = .stub a := by
          refine Classical.byContradiction fun hne => ?_
          exact hl64 (key l (fun s hs => hne ⟨s, hs⟩))
        obtain ⟨b, rfl⟩ : ∃ b, r = .stub b := by
          refine Classical.byContradiction fun hne => ?_
          have hr64 := key r (fun s hs => hne ⟨s, hs⟩)
          have hlen := congrArg List.length hc
          simp only [List.length_append, hql, hqr, hr64] at hlen
          exact hl64 (by omega)
        exact Pr.dead _ _ hh dead_node_stubs

theorem pr_insert {H : Bytes → Bytes} (k v : Bytes) (hsk : sized k v = true) :
    ∀ (p p' : PTree) (fuel d : Nat) (kvs : List (Bytes × Bytes)),
    d + fuel = 512 → MapWf kvs → Agree k d kvs → Pr H p (mapTree fuel d kvs) → p.insert k v d = some p' →
    Pr H p' (mapTree fuel d (upsert kvs k v)) := by
  intro p
  induction p with
  | stub s =>
    intro p' fuel d kvs hd hw hag hpr hi
    have hi2 : (none : Option PTree) = some p' := hi
    cases hi2
  | empty =>
    intro p' fuel d kvs hd hw hag hpr hi
    rcases mapTree_cases k fuel d kvs hd hw.1 (fun kv h => (hw.2 kv h).1) hag with h | ⟨⟨a1, a2⟩, h⟩ | ⟨f, hf, h2⟩
    · subst h
      rcases Pr.empty_inv hpr with _ | hdead
      · have hi2 : (if sized k v = true then some (PTree.leaf k v) else none) = some p' := hi
        rw [if_pos hsk] at hi2
        cases hi2
        rw [upsert_nil, mapTree_single]; exact Pr.leaf _ _
      · rw [hdead k v d] at hi; cases hi
    · subst h
      rcases Pr.empty_inv hpr with hq | hdead
      · rw [mapTree_single] at hq; cases hq
      · rw [hdead k v d] at hi; cases hi
    · subst hf
      rcases Pr.empty_inv hpr with hq | hdead
      · rw [mapTree_node f d kvs h2] at hq; cases hq
      · rw [hdead k v d] at hi; cases hi
  | leaf k0 v0 =>
    intro p' fuel d kvs hd hw hag hpr hi
    rcases mapTree_cases k fuel d kvs hd hw.1 (fun kv h => (hw.2 kv h).1) hag with h | ⟨⟨a1, a2⟩, h⟩ | ⟨f, hf, h2⟩
    · subst h
      rcases Pr.leaf_inv hpr with hq | hdead
      · rw [mapTree_nil] at hq; cases hq
      · rw [hdead k v d] at hi; cases hi
    · subst h
      rcases Pr.leaf_inv hpr with hq | hdead
      · rw [mapTree_single] at hq
        obtain ⟨e1, e2⟩ := PTree.leaf.inj hq
        subst e1; subst e2
        have hi2 : (if (!(sized k v && sized a1 a2)) = true then none else
            if (a1 == k) = true then some (PTree.leaf k v) else splitLeaves (512 - d) d a1 a2 k v) = some p' := hi
        by_cases hs : (!(sized k v && sized a1 a2)) = true
        · rw [if_pos hs] at hi2; cases hi2
        · rw [if_neg hs] at hi2
          by_cases hkk : (a1 == k) = true
          · rw [if_pos hkk] at hi2; cases hi2
            have e : a1 = k := beq_iff_eq.mp hkk
            subst e
            simp only [upsert, List.filter, bne_self_eq_false]
            rw [List.nil_append, mapTree_single]
            exact Pr.leaf _ _
          · rw [if_neg hkk] at hi2
            have hne : a1 ≠ k := fun e => hkk (by simp [e])
            have hu : upsert [(a1, a2)] k v = [(a1, a2), (k, v)] := by simp [upsert, hne]
            have hf : fuel = 512 - d := by omega
            rw [hu, hf, splitLeaves_eq _ _ _ _ _ _ _ hi2]
            exact Pr.refl H _
      · rw [hdead k v d] at hi; cases hi
    · subst hf
      rcases Pr.leaf_inv hpr with hq | hdead
      · rw [mapTree_node f d kvs h2] at hq; cases hq
      · rw [hdead k v d] at hi; cases hi
  | node l r ihl ihr =>
    intro p' fuel d kvs hd hw hag hpr hi
    rcases mapTree_cases k fuel d kvs hd hw.1 (fun kv h => (hw.2 kv h).1) hag with h | ⟨⟨a1, a2⟩, h⟩ | ⟨f, hf, h2⟩
    · subst h
      rcases Pr.node_inv hpr with ⟨ql, qr, hq, _⟩ | hdead
      · rw [mapTree_nil] at hq; cases hq
      · rw [hdead k v d] at hi; cases hi
    · subst h
      rcases Pr.node_inv hpr with ⟨ql, qr, hq, _⟩ | hdead
      · rw [mapTree_single] at hq; cases hq
      · rw [hdead k v d] at hi; cases hi
    · subst hf
      rcases Pr.node_inv hpr with ⟨ql, qr, hq, hl', hr'⟩ | hdead
      · rw [mapTree_node f d kvs h2] at hq
        obtain ⟨e1, e2⟩ := PTree.node.inj hq
        rw [← e1] at hl'
        rw [← e2] at hr'
        have hwl := hw.filter (fun kv => !bitAt kv.1 d)
        have hwr := hw.filter (fun kv => bitAt kv.1 d)
        have hi2 : (if bitAt k d = true then (r.insert k v (d + 1)).map (fun t => PTree.node l t)
            else (l.insert k v (d + 1)).map (fun t => PTree.node t r)) = some p' := hi
        rw [mapTree_node f d _ (upsert_len hw h2 k v)]
        by_cases hkb : bitAt k d = true
        · rw [if_pos hkb] at hi2
          rcases hr : r.insert k v (d + 1) with _ | r'
          · rw [hr] at hi2; simp at hi2
          · rw [hr] at hi2
            have hi' : PTree.node l r' = p' := by simpa using hi2
            subst hi'
            have ih := ihr r' f (d + 1) _ (by omega) hwr (hag.filter _ (hp_right hkb)) hr' hr
            have e1 : (upsert kvs k v).filter (fun kv => !bitAt kv.1 d) = kvs.filter (fun kv => !bitAt kv.1 d) :=
              uf_out (fun b => !bitAt b d) (by simp [hkb]) kvs
            have e2 : (upsert kvs k v).filter (fun kv => bitAt kv.1 d) =
                upsert (kvs.filter fun kv => bitAt kv.1 d) k v := uf_in (fun b => bitAt b d) hkb kvs
            rw [e1, e2]
            exact Pr.node hl' ih
        · have hkb' : bitAt k d = false := by simpa using hkb
          rw [if_neg hkb] at hi2
          rcases hr : l.insert k v (d + 1) with _ | l'
          · rw [hr] at hi2; simp at hi2
          · rw [hr] at hi2
            have hi' : PTree.node l' r = p' := by simpa using hi2
            subst hi'
            have ih := ihl l' f (d + 1) _ (by omega) hwl (hag.filter _ (hp_left hkb')) hl' hr
            have e1 : (upsert kvs k v).filter (fun kv => bitAt kv.1 d) = kvs.filter (fun kv => bitAt kv.1 d) :=
              uf_out (fun b => bitAt b d) hkb' kvs
            have e2 : (upsert kvs k v).filter (fun kv => !bitAt kv.1 d) =
                upsert (kvs.filter fun kv => !bitAt kv.1 d) k v := uf_in (fun b => !bitAt b d) (by simp [hkb']) kvs
            rw [e1, e2]
            exact Pr.node ih hr'
      · rw [hdead k v d] at hi; cases hi

theorem upsert_wf {base : List (Bytes × Bytes)} (hw : MapWf base) {k v : Bytes} (hk : k.length = 64)
    (hv : v.length = 64) : MapWf (upsert base k v) := by
  refine ⟨?_, ?_⟩
  · have e : (upsert base k v).map (·.1) = (base.filter (·.1 != k)).map (·.1) ++ [k] := by simp [upsert]
    rw [e]
    refine List.nodup_append.mpr ⟨?_, (List.nodup_cons.mpr ⟨by simp, List.nodup_nil⟩), ?_⟩
    · exact List.Nodup.sublist (List.Sublist.map _ (List.filter_sublist ..)) hw.1
    · intro a ha b hb
      obtain ⟨kv, hkv, rfl⟩ := List.mem_map.mp ha
      have hne := (List.mem_filter.mp hkv).2
      have hb' : b = k := by simpa using hb
      subst hb'
      simpa using hne
  · intro kv hkv
    unfold upsert at hkv
    rcases List.mem_append.mp hkv with h | h
    · exact hw.2 kv (List.mem_filter.mp h).1
    · have : kv = (k, v) := by simpa using h
      subst this
      exact ⟨hk, hv⟩

/-! ## §D  Verify-on-read (owner addendum, `auth-state-owner-addendum-v1.md`)

    A decision reads the store one key at a time; each answer arrives with the map proof against the root held in
    process memory, or the decision is refused.  §C's `decide_from_proof` is the gate instance; §D is the general
    form the owner uses, discharging the `hreads` premise of IH `chain_fold_threaded` instead of assuming T-A. -/

/-- A decision as its sequence of keyed reads; the next key may depend on earlier answers. -/
inductive Query (α : Type) where
  | done (a : α)
  | ask (k : Bytes) (next : Option Bytes → Query α)

/-- The decision against the full store (`look` = the true rows). -/
def Query.eval {α : Type} (look : Bytes → Option Bytes) : Query α → α
  | .done a => a
  | .ask k next => (next (look k)).eval look

/-- The index the owner maintains: each map value is the digest of the row stored under that key. -/
def rowIndex (H : Bytes → Bytes) (d : Bytes) (rows : List (Bytes × Bytes)) : List (Bytes × Bytes) :=
  rows.map fun kr => (kr.1, H (d ++ kr.2))

/-- The decision from untrusted rows (`sup`) and one multiproof `p` against the trusted `root`.
    A stub on a read path, or a row that does not match its proven digest, refuses the whole decision. -/
def Query.evalProved {α : Type} (H : Bytes → Bytes) (d root : Bytes) (p : PTree) (sup : Bytes → Option Bytes) :
    Query α → Option α
  | .done a => some a
  | .ask k next =>
    match verifyMap H root k p, sup k with
    | some none, _ => (next none).evalProved H d root p sup
    | some (some v), some r => if H (d ++ r) == v then (next (some r)).evalProved H d root p sup else none
    | _, _ => none

/-- Every hash input behind a proof-checked read and behind the true store. -/
def readInputs (H : Bytes → Bytes) (d : Bytes) (rows : List (Bytes × Bytes)) (p : PTree)
    (sup : Bytes → Option Bytes) : List Bytes :=
  p.inputs H ++ (mapTree 512 0 (rowIndex H d rows)).inputs H ++
    rows.flatMap fun kr => (d ++ kr.2) :: ((sup kr.1).map (d ++ ·)).toList

theorem lookup_rowIndex (H : Bytes → Bytes) (d : Bytes) (rows : List (Bytes × Bytes)) (k : Bytes) :
    lookup (rowIndex H d rows) k = (lookup rows k).map (fun r => H (d ++ r)) := by
  induction rows with
  | nil => rfl
  | cons a rest ih =>
    by_cases h : (a.1 == k) = true
    · simp [lookup, rowIndex, List.find?_cons, h]
    · simp only [lookup, rowIndex, List.map_cons, List.find?_cons, h] at ih ⊢
      simpa [h] using ih

theorem rts_aux {α : Type} {H : Bytes → Bytes} (hl : HashLen H) (d : Bytes)
    (rows : List (Bytes × Bytes)) (hw : MapWf (rowIndex H d rows)) (p : PTree)
    (sup : Bytes → Option Bytes) (hg : breakIn H (readInputs H d rows p sup) = none) :
    ∀ (q : Query α) (a : α), q.evalProved H d (mapRoot H (rowIndex H d rows)) p sup = some a →
      a = q.eval (lookup rows) := by
  intro q
  induction q with
  | done a0 =>
    intro a h
    simp only [Query.evalProved, Option.some.injEq] at h
    simp [Query.eval, h]
  | ask k next ih =>
    intro a h
    have hm : ∀ r, verifyMap H (mapRoot H (rowIndex H d rows)) k p = some r →
        r = lookup (rowIndex H d rows) k := by
      intro r hr
      rcases map_sound hl _ k p r hw hr with e | e
      · exact e
      · exact absurd (none_mono hg (fun x hx => List.mem_append_left _ hx)) e
    simp only [Query.evalProved] at h
    rcases hv : verifyMap H (mapRoot H (rowIndex H d rows)) k p with _ | _ | v
    · simp [hv] at h
    · simp only [hv] at h
      have e := hm _ hv
      rw [lookup_rowIndex] at e
      rcases hh : lookup rows k with _ | r0
      · simp only [Query.eval, hh]
        exact ih none a h
      · rw [hh] at e; simp at e
    · have e := hm _ hv
      rw [lookup_rowIndex] at e
      rcases hh : lookup rows k with _ | r0
      · rw [hh] at e; simp at e
      · rw [hh] at e
        have e' : H (d ++ r0) = v := by simpa using e.symm
        rcases hs : sup k with _ | r
        · simp [hv, hs] at h
        · simp only [hv, hs] at h
          by_cases hc : (H (d ++ r) == v) = true
          · rw [if_pos hc] at h
            have hc' : H (d ++ r) = v := beq_iff_eq.mp hc
            have hm0 : (k, r0) ∈ rows := lookup_some hh
            have i0 : d ++ r0 ∈ readInputs H d rows p sup := by
              unfold readInputs
              refine List.mem_append_right _ (List.mem_flatMap.mpr ⟨(k, r0), hm0, ?_⟩)
              simp
            have i1 : d ++ r ∈ readInputs H d rows p sup := by
              unfold readInputs
              refine List.mem_append_right _ (List.mem_flatMap.mpr ⟨(k, r0), hm0, ?_⟩)
              simp [hs]
            have hr := inj_of_none hg i1 i0 (hc'.trans e'.symm)
            have hr' : r = r0 := List.append_cancel_left hr
            subst hr'
            simp only [Query.eval, hh]
            exact ih (some r) a h
          · rw [if_neg hc] at h; cases h

/-- THE verify-on-read theorem: an accepted proof-checked run answers exactly as the full store would.
    No assumption about the file (no T-A); only SHA3-512 collision resistance and the root in memory. -/
theorem read_through_sound {α : Type} {H : Bytes → Bytes} (hl : HashLen H) (d : Bytes)
    (rows : List (Bytes × Bytes)) (hw : MapWf (rowIndex H d rows)) (q : Query α) (p : PTree)
    (sup : Bytes → Option Bytes) (a : α)
    (h : q.evalProved H d (mapRoot H (rowIndex H d rows)) p sup = some a) :
    a = q.eval (lookup rows) ∨ breakIn H (readInputs H d rows p sup) ≠ none := by
  by_cases hg : breakIn H (readInputs H d rows p sup) = none
  case neg => exact Or.inr hg
  exact Or.inl (rts_aux hl d rows hw p sup hg q a h)

/-- The owner form: if the decision's keyed reads determine the full-store decision `F`, then the decision made
    from proof-checked rows equals `F` of the whole store.  For a payment, `hf` is IH `fold_evaluate_eq_full`
    (the item state read under the obligation key summarizes every row of the item, `headAfter_summary`). -/
theorem decide_on_read {α : Type} {H : Bytes → Bytes} (hl : HashLen H) (d : Bytes)
    (F : List (Bytes × Bytes) → α) (q : Query α)
    (hf : ∀ rows, MapWf (rowIndex H d rows) → q.eval (lookup rows) = F rows)
    (rows : List (Bytes × Bytes)) (hw : MapWf (rowIndex H d rows)) (p : PTree) (sup : Bytes → Option Bytes)
    (a : α) (h : q.evalProved H d (mapRoot H (rowIndex H d rows)) p sup = some a) :
    a = F rows ∨ breakIn H (readInputs H d rows p sup) ≠ none := by
  by_cases hg : breakIn H (readInputs H d rows p sup) = none
  case neg => exact Or.inr hg
  exact Or.inl ((rts_aux hl d rows hw p sup hg q a h).trans (hf rows hw))

/-- A write's index update: upserts applied to an accepted multiproof give the canonical new root, so the
    in-memory root advances only to the index of the committed rows. -/
def PTree.insertAll (kvs : List (Bytes × Bytes)) (t : PTree) : Option PTree :=
  kvs.foldlM (fun t kv => t.insert kv.1 kv.2 0) t

theorem pr_insertAll {H : Bytes → Bytes} : ∀ (kvs : List (Bytes × Bytes)) (p p' : PTree)
    (base : List (Bytes × Bytes)), MapWf base → (∀ kv ∈ kvs, kv.1.length = 64 ∧ kv.2.length = 64) →
    Pr H p (mapTree 512 0 base) → p.insertAll kvs = some p' →
    Pr H p' (mapTree 512 0 (kvs.foldl (fun m kv => upsert m kv.1 kv.2) base)) := by
  intro kvs
  induction kvs with
  | nil =>
    intro p p' base hw hk hp hi
    have hi2 : (some p : Option PTree) = some p' := hi
    cases hi2
    exact hp
  | cons kv kvs ih =>
    intro p p' base hw hk hp hi
    have hi' : (p.insert kv.1 kv.2 0).bind (fun t => t.insertAll kvs) = some p' := hi
    rcases h1 : p.insert kv.1 kv.2 0 with _ | p1
    · rw [h1] at hi'; simp at hi'
    · rw [h1] at hi'
      have hi'' : p1.insertAll kvs = some p' := hi'
      have hkv := hk kv (by simp)
      have hsk : sized kv.1 kv.2 = true := by simp [sized, hkv.1, hkv.2]
      have hp1 := pr_insert kv.1 kv.2 hsk p p1 512 0 base (by omega) hw
        (fun _ _ i hi => absurd hi (Nat.not_lt_zero i)) hp h1
      exact ih p1 p' (upsert base kv.1 kv.2) (upsert_wf hw hkv.1 hkv.2)
        (fun x hx => hk x (List.mem_cons_of_mem _ hx)) hp1 hi''

theorem insertAll_correct {H : Bytes → Bytes} (hl : HashLen H) (base kvs : List (Bytes × Bytes)) (p p' : PTree)
    (hw : MapWf base) (hk : ∀ kv ∈ kvs, kv.1.length = 64 ∧ kv.2.length = 64)
    (hp : p.hash H = mapRoot H base) (hi : p.insertAll kvs = some p') :
    p'.hash H = mapRoot H (kvs.foldl (fun m kv => upsert m kv.1 kv.2) base) ∨
      breakIn H (p.inputs H ++ (mapTree 512 0 base).inputs H) ≠ none := by
  by_cases hg : breakIn H (p.inputs H ++ (mapTree 512 0 base).inputs H) = none
  case neg => exact Or.inr hg
  left
  have hp' : Pr H p (mapTree 512 0 base) :=
    pr_of_hash hl hg p 512 0 base (by omega) hw (fun a _ b _ i hi => absurd hi (Nat.not_lt_zero i))
      (fun x hx => List.mem_append_left _ hx) (fun x hx => List.mem_append_right _ hx) hp
  exact (pr_insertAll kvs p p' base hw hk hp' hi).hash_eq

end BlindLedger.Gate.Auth
