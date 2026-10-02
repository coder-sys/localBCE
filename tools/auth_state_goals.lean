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

/-- Binding: two accepted proofs for one key against one root agree, whatever produced the root. -/
theorem map_binding {H : Bytes → Bytes} (hl : HashLen H) (p q : PTree) (k : Bytes) (a b : Option Bytes)
    (hpq : p.hash H = q.hash H) (ha : p.find k 0 = some a) (hb : q.find k 0 = some b) :
    a = b ∨ breakIn H (p.inputs H ++ q.inputs H) ≠ none := by
  sorry

/-- Inclusion and absence soundness in one statement (`r = some v` / `r = none`). -/
theorem map_sound {H : Bytes → Bytes} (hl : HashLen H) (kvs : List (Bytes × Bytes)) (k : Bytes) (p : PTree)
    (r : Option Bytes) (hw : MapWf kvs) (h : verifyMap H (mapRoot H kvs) k p = some r) :
    r = lookup kvs k ∨ breakIn H (p.inputs H ++ (mapTree 512 0 kvs).inputs H) ≠ none := by
  sorry

theorem inclusion_sound {H : Bytes → Bytes} (hl : HashLen H) (kvs : List (Bytes × Bytes)) (k v : Bytes)
    (p : PTree) (hw : MapWf kvs) (h : verifyMap H (mapRoot H kvs) k p = some (some v)) :
    (k, v) ∈ kvs ∨ breakIn H (p.inputs H ++ (mapTree 512 0 kvs).inputs H) ≠ none := by
  sorry

theorem absence_sound {H : Bytes → Bytes} (hl : HashLen H) (kvs : List (Bytes × Bytes)) (k : Bytes)
    (p : PTree) (hw : MapWf kvs) (h : verifyMap H (mapRoot H kvs) k p = some none) :
    (∀ v, (k, v) ∉ kvs) ∨ breakIn H (p.inputs H ++ (mapTree 512 0 kvs).inputs H) ≠ none := by
  sorry

theorem map_complete {H : Bytes → Bytes} (kvs : List (Bytes × Bytes)) (k : Bytes) (hw : MapWf kvs)
    (hk : k.length = 64) : ∃ p, verifyMap H (mapRoot H kvs) k p = some (lookup kvs k) := by
  sorry

/-- Map update correctness: inserting into a proof of the old root gives the canonical new root. -/
theorem map_insert_correct {H : Bytes → Bytes} (hl : HashLen H) (kvs : List (Bytes × Bytes)) (k v : Bytes)
    (p p' : PTree) (hw : MapWf kvs) (hk : k.length = 64) (hv : v.length = 64)
    (hp : p.hash H = mapRoot H kvs) (hi : p.insert k v 0 = some p') :
    p'.hash H = mapRoot H (upsert kvs k v) ∨ breakIn H (p.inputs H ++ (mapTree 512 0 kvs).inputs H) ≠ none := by
  sorry

/-- The opened part survives an insert, so one multiproof serves a whole batch of inserts. -/
theorem insert_find_other (p p' : PTree) (k k' v : Bytes) (hne : k ≠ k') (hi : p.insert k v 0 = some p')
    (r : Option Bytes) (hf : p.find k' 0 = some r) : p'.find k' 0 = some r := by
  sorry

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

/-- THE dedup/ALREADY_DECIDED theorem, rules level: deciding on the slice equals deciding on the whole state.
    The only premise is the identity invariant `ids_fresh` maintains. -/
theorem decideBatch_slice (c : Rules.Ctx) (E : List Entry) (b : List Rules.Line)
    (hid : (E.map (·.line.id)).Nodup) :
    batchOutcome (v2Ctx c (sliceOf E (querySet b))) b = batchOutcome (v2Ctx c E) b := by
  sorry

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
  sorry

/-- The batch's map update is the canonical index of the appended log. -/
theorem applyBatch_correct {H : Bytes → Bytes} (hl : HashLen H) (E new : List Entry) (b : List Rules.Line)
    (h : Hydration) (t : PTree) (hw : EntriesWf (E ++ new)) (hn : (E ++ new).length ≤ maxSize)
    (hq : ∀ e ∈ new, (Rules.keys e.line).all (querySet b).contains)
    (hok : hydrateOk H (mapRoot H (gateMap H E)) (querySet b) h = true)
    (ht : applyBatch H h E.length new = some t) :
    t.hash H = mapRoot H (gateMap H (E ++ new)) ∨ breakIn H (hydrateInputs H E (querySet b) h) ≠ none := by
  sorry

/-- The head binds the whole state: equal head digests give equal entry lists. -/
theorem gateHead_binding {H : Bytes → Bytes} (hl : HashLen H) (E E' : List Entry) (hw : EntriesWf E)
    (hw' : EntriesWf E') (hn : E.length ≤ maxSize) (hn' : E'.length ≤ maxSize)
    (h : H (gateHead H E) = H (gateHead H E')) :
    E.map entryBytes = E'.map entryBytes ∨
      breakIn H (gateHead H E :: gateHead H E' :: logInputs H (E.map fun e => (entryBytes e).getD []) ++
        logInputs H (E'.map fun e => (entryBytes e).getD [])) ≠ none := by
  sorry

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

/-- THE verify-on-read theorem: an accepted proof-checked run answers exactly as the full store would.
    No assumption about the file (no T-A); only SHA3-512 collision resistance and the root in memory. -/
theorem read_through_sound {α : Type} {H : Bytes → Bytes} (hl : HashLen H) (d : Bytes)
    (rows : List (Bytes × Bytes)) (hw : MapWf (rowIndex H d rows)) (q : Query α) (p : PTree)
    (sup : Bytes → Option Bytes) (a : α)
    (h : q.evalProved H d (mapRoot H (rowIndex H d rows)) p sup = some a) :
    a = q.eval (lookup rows) ∨ breakIn H (readInputs H d rows p sup) ≠ none := by
  sorry

/-- The owner form: if the decision's keyed reads determine the full-store decision `F`, then the decision made
    from proof-checked rows equals `F` of the whole store.  For a payment, `hf` is IH `fold_evaluate_eq_full`
    (the item state read under the obligation key summarizes every row of the item, `headAfter_summary`). -/
theorem decide_on_read {α : Type} {H : Bytes → Bytes} (hl : HashLen H) (d : Bytes)
    (F : List (Bytes × Bytes) → α) (q : Query α)
    (hf : ∀ rows, MapWf (rowIndex H d rows) → q.eval (lookup rows) = F rows)
    (rows : List (Bytes × Bytes)) (hw : MapWf (rowIndex H d rows)) (p : PTree) (sup : Bytes → Option Bytes)
    (a : α) (h : q.evalProved H d (mapRoot H (rowIndex H d rows)) p sup = some a) :
    a = F rows ∨ breakIn H (readInputs H d rows p sup) ≠ none := by
  sorry

/-- A write's index update: upserts applied to an accepted multiproof give the canonical new root, so the
    in-memory root advances only to the index of the committed rows. -/
def PTree.insertAll (kvs : List (Bytes × Bytes)) (t : PTree) : Option PTree :=
  kvs.foldlM (fun t kv => t.insert kv.1 kv.2 0) t

theorem insertAll_correct {H : Bytes → Bytes} (hl : HashLen H) (base kvs : List (Bytes × Bytes)) (p p' : PTree)
    (hw : MapWf base) (hk : ∀ kv ∈ kvs, kv.1.length = 64 ∧ kv.2.length = 64)
    (hp : p.hash H = mapRoot H base) (hi : p.insertAll kvs = some p') :
    p'.hash H = mapRoot H (kvs.foldl (fun m kv => upsert m kv.1 kv.2) base) ∨
      breakIn H (p.inputs H ++ (mapTree 512 0 base).inputs H) ≠ none := by
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

end BlindLedger.Gate.Auth
