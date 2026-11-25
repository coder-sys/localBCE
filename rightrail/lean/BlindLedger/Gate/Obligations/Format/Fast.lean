import BlindLedger.Gate.Obligations.Format.Records

namespace BlindLedger.Gate.Obligations.Format

open BlindLedger.Gate.FactCodec

/-! The `ByteArray` twins of the record codecs.  The executables run these; the `List` codecs of `Layout` and
    `Records` are the model they are proved equal to.

    * Writing: one writer serves every layout (`RecCodec.encB`, proved by `RecCodec.encB_eq`).  It pushes each
      byte once into a buffer sized for a whole record, with no list appends.  Like the model, it is exact only for
      a well-formed record; `RecCodec.write` is the writer to use, which refuses a record that is not well formed
      (a number wider than its field, a block of another length, or its own check failing) instead of cutting it
      (`RecCodec.write_eq`, `RecCodec.write_dec`).
    * Reading: every record kind has a `Twin`: its codec, its builder and the table of where each cell sits.  The
      reader (`Twin.dec`) checks the length and the literal fields in place, then builds the record straight from
      the bytes through the builder, with no cell list and no re-encoding.  `Twin.dec_eq` proves once, for every
      twin, that it gives exactly the model's answer on every input, refusals included.  A twin exists only with
      proofs that its builder is its codec's (`build_eq`) and that the cells it reads are the ones its codec gives
      back (`exact`); both hold by computation on the layout. -/

/-! ## Writing -/

/-- Push the `w` little-endian bytes of `v`. -/
def pushLE (b : ByteArray) : Nat → Nat → ByteArray
  | 0, _ => b
  | w + 1, v => pushLE (b.push (UInt8.ofNat (v % 256))) w (v / 256)

/-- Push a block. -/
def pushBlk (b : ByteArray) : Bytes → ByteArray
  | [] => b
  | x :: xs => pushBlk (b.push x) xs

/-- `encF` into a buffer: the same cases, the same bytes. -/
def encFB : List Fld → List Cell → ByteArray → ByteArray
  | [], _, b => b
  | .lit w v :: fs, cs, b => encFB fs cs (pushLE b w v)
  | .num w :: fs, .n v :: cs, b => encFB fs cs (pushLE b w v)
  | .blk _ :: fs, .b v :: cs, b => encFB fs cs (pushBlk b v)
  | .num _ :: _, [], b => b
  | .num _ :: _, .b _ :: _, b => b
  | .blk _ :: _, [], b => b
  | .blk _ :: _, .n _ :: _, b => b

theorem pushLE_eq : ∀ (w v : Nat) (b : ByteArray), (pushLE b w v).data.toList = b.data.toList ++ leBytes w v
  | 0, _, _ => by simp [pushLE, leBytes]
  | w + 1, v, b => by
    rw [pushLE, pushLE_eq w (v / 256)]
    simp [leBytes, ByteArray.push]

theorem pushBlk_eq : ∀ (l : Bytes) (b : ByteArray), (pushBlk b l).data.toList = b.data.toList ++ l
  | [], _ => by simp [pushBlk]
  | x :: xs, b => by
    rw [pushBlk, pushBlk_eq xs]
    simp [ByteArray.push]

theorem encFB_eq : ∀ (fs : List Fld) (cs : List Cell) (b : ByteArray),
    (encFB fs cs b).data.toList = b.data.toList ++ encF fs cs
  | [], _, _ => by simp [encFB, encF]
  | .lit w v :: fs, cs, b => by simp [encFB, encF, encFB_eq fs, pushLE_eq]
  | .num w :: fs, .n v :: cs, b => by simp [encFB, encF, encFB_eq fs, pushLE_eq]
  | .blk _ :: fs, .b v :: cs, b => by simp [encFB, encF, encFB_eq fs, pushBlk_eq]
  | .num _ :: _, [], _ => by simp [encFB, encF]
  | .num _ :: _, .b _ :: _, _ => by simp [encFB, encF]
  | .blk _ :: _, [], _ => by simp [encFB, encF]
  | .blk _ :: _, .n _ :: _, _ => by simp [encFB, encF]

/-! ## Writing with a guard -/

/-- `pushLE`, and what is left of `v` after its `w` bytes: 0 exactly when `v` fits. -/
def pushLEr (b : ByteArray) : Nat → Nat → ByteArray × Nat
  | 0, v => (b, v)
  | w + 1, v => pushLEr (b.push (UInt8.ofNat (v % 256))) w (v / 256)

theorem pushLEr_eq : ∀ (w v : Nat) (b : ByteArray), pushLEr b w v = (pushLE b w v, v / 256 ^ w)
  | 0, v, b => by simp [pushLEr, pushLE]
  | w + 1, v, b => by
    rw [pushLEr, pushLEr_eq w (v / 256),
      show pushLE b (w + 1) v = pushLE (b.push (UInt8.ofNat (v % 256))) w (v / 256) from rfl,
      Nat.div_div_eq_div_mul, Nat.pow_succ, Nat.mul_comm (256 ^ w)]

/-- `encFB` that refuses cells which do not fit the layout: no bytes, rather than a number's low bytes or a block
    of another length. -/
def encFBc : List Fld → List Cell → ByteArray → Option ByteArray
  | [], [], b => some b
  | [], _ :: _, _ => none
  | .lit w v :: fs, cs, b => let p := pushLEr b w v; if p.2 = 0 then encFBc fs cs p.1 else none
  | .num w :: fs, .n v :: cs, b => let p := pushLEr b w v; if p.2 = 0 then encFBc fs cs p.1 else none
  | .blk w :: fs, .b v :: cs, b => if v.length = w then encFBc fs cs (pushBlk b v) else none
  | .num _ :: _, [], _ => none
  | .num _ :: _, .b _ :: _, _ => none
  | .blk _ :: _, [], _ => none
  | .blk _ :: _, .n _ :: _, _ => none

/-- The guarded writer gives bytes exactly when the cells fit, and then the unguarded writer's bytes. -/
theorem encFBc_eq : ∀ (fs : List Fld) (cs : List Cell) (b b' : ByteArray),
    encFBc fs cs b = some b' ↔ fit fs cs ∧ b' = encFB fs cs b
  | [], [], b, b' => by simp [encFBc, fit, encFB, eq_comm]
  | [], _ :: _, _, _ => by simp [encFBc, fit]
  | .lit w v :: fs, cs, b, b' => by
    by_cases h : v < 256 ^ w
    · simp [encFBc, fit, encFB, pushLEr_eq, h, encFBc_eq fs cs]
    · simp [encFBc, fit, pushLEr_eq, h]
  | .num w :: fs, .n v :: cs, b, b' => by
    by_cases h : v < 256 ^ w
    · simp [encFBc, fit, encFB, pushLEr_eq, h, encFBc_eq fs cs]
    · simp [encFBc, fit, pushLEr_eq, h]
  | .blk w :: fs, .b v :: cs, b, b' => by
    by_cases h : v.length = w
    · simp [encFBc, fit, encFB, h, encFBc_eq fs cs]
    · simp [encFBc, fit, h]
  | .num _ :: _, [], _, _ => by simp [encFBc, fit]
  | .num _ :: _, .b _ :: _, _, _ => by simp [encFBc, fit]
  | .blk _ :: _, [], _, _ => by simp [encFBc, fit]
  | .blk _ :: _, .n _ :: _, _, _ => by simp [encFBc, fit]

/-! ## Reading in place -/

theorem size_toList (b : ByteArray) : b.data.toList.length = b.size := rfl

/-- The little-endian number of `w` bytes at `o`. -/
def rdNB (b : ByteArray) : Nat → Nat → Nat
  | _, 0 => 0
  | o, w + 1 => (b.get! o).toNat + 256 * rdNB b (o + 1) w

/-- The `w` bytes at `o`. -/
def rdBlkB (b : ByteArray) : Nat → Nat → Bytes
  | _, 0 => []
  | o, w + 1 => b.get! o :: rdBlkB b (o + 1) w

theorem drop_cons (b : ByteArray) (o : Nat) (h : o < b.size) :
    b.data.toList.drop o = b.get! o :: b.data.toList.drop (o + 1) := by
  have h' : o < b.data.toList.length := by rw [size_toList]; exact h
  rw [List.drop_eq_getElem_cons h']
  congr 1
  cases b with
  | mk a =>
    simp only [ByteArray.size] at h
    simp [ByteArray.get!, getElem!_pos a o h]

theorem rdNB_eq (b : ByteArray) : ∀ (o w : Nat), o + w ≤ b.size →
    rdNB b o w = fromLE ((b.data.toList.drop o).take w)
  | _, 0, _ => by simp [rdNB, fromLE]
  | o, w + 1, h => by
    rw [drop_cons b o (by omega), rdNB, rdNB_eq b (o + 1) w (by omega)]
    simp [fromLE]

theorem rdBlkB_eq (b : ByteArray) : ∀ (o w : Nat), o + w ≤ b.size →
    rdBlkB b o w = (b.data.toList.drop o).take w
  | _, 0, _ => by simp [rdBlkB]
  | o, w + 1, h => by
    rw [drop_cons b o (by omega), rdBlkB, rdBlkB_eq b (o + 1) w (by omega)]
    simp

/-! The compiled readers run from the last byte to the first in a loop that keeps no stack: `rdNB` and `rdBlkB` are
    the definitions, `rdNT` and `rdBlkT` what the compiler uses in their place (`@[csimp]`, proved equal). -/

def rdNGo (b : ByteArray) (o : Nat) : Nat → Nat → Nat
  | 0, acc => acc
  | k + 1, acc => rdNGo b o k (acc * 256 + (b.get! (o + k)).toNat)

def rdNT (b : ByteArray) (o w : Nat) : Nat := rdNGo b o w 0

theorem rdNB_succ (b : ByteArray) : ∀ (o k : Nat), rdNB b o (k + 1) = rdNB b o k + 256 ^ k * (b.get! (o + k)).toNat
  | o, 0 => by simp [rdNB]
  | o, k + 1 => by
    rw [rdNB, rdNB_succ b (o + 1) k, rdNB, show o + 1 + k = o + (k + 1) by omega, Nat.pow_succ, Nat.mul_add]
    ac_rfl

theorem rdNGo_eq (b : ByteArray) (o : Nat) : ∀ (k acc : Nat), rdNGo b o k acc = acc * 256 ^ k + rdNB b o k
  | 0, acc => by simp [rdNGo, rdNB]
  | k + 1, acc => by
    rw [rdNGo, rdNGo_eq b o k, rdNB_succ, Nat.pow_succ, Nat.add_mul]
    ac_rfl

@[csimp] theorem rdNB_eq_rdNT : @rdNB = @rdNT := by
  funext b o w
  rw [rdNT, rdNGo_eq]
  simp

def rdBlkGo (b : ByteArray) (o : Nat) : Nat → Bytes → Bytes
  | 0, acc => acc
  | k + 1, acc => rdBlkGo b o k (b.get! (o + k) :: acc)

def rdBlkT (b : ByteArray) (o w : Nat) : Bytes := rdBlkGo b o w []

theorem rdBlkB_succ (b : ByteArray) : ∀ (o k : Nat), rdBlkB b o (k + 1) = rdBlkB b o k ++ [b.get! (o + k)]
  | o, 0 => by simp [rdBlkB]
  | o, k + 1 => by
    rw [rdBlkB, rdBlkB_succ b (o + 1) k, rdBlkB, show o + 1 + k = o + (k + 1) by omega]
    rfl

theorem rdBlkGo_eq (b : ByteArray) (o : Nat) : ∀ (k : Nat) (acc : Bytes), rdBlkGo b o k acc = rdBlkB b o k ++ acc
  | 0, acc => by simp [rdBlkGo, rdBlkB]
  | k + 1, acc => by rw [rdBlkGo, rdBlkGo_eq b o k, rdBlkB_succ]; simp

@[csimp] theorem rdBlkB_eq_rdBlkT : @rdBlkB = @rdBlkT := by
  funext b o w
  rw [rdBlkT, rdBlkGo_eq]
  simp

theorem rdLE_at (b : ByteArray) (o w : Nat) (ho : o ≤ b.size) :
    rdLE w (b.data.toList.drop o) =
      if o + w ≤ b.size then some (rdNB b o w, b.data.toList.drop (o + w)) else none := by
  rw [rdLE_def]
  by_cases h : o + w ≤ b.size
  · rw [if_neg (by rw [List.length_drop, size_toList]; omega), if_pos h, rdNB_eq b o w h]
    simp [List.drop_drop]
  · rw [if_pos (by rw [List.length_drop, size_toList]; omega), if_neg h]

theorem rdBlk_at (b : ByteArray) (o w : Nat) (ho : o ≤ b.size) :
    rdBlk w (b.data.toList.drop o) =
      if o + w ≤ b.size then some (rdBlkB b o w, b.data.toList.drop (o + w)) else none := by
  rw [rdBlk_def]
  by_cases h : o + w ≤ b.size
  · rw [if_neg (by rw [List.length_drop, size_toList]; omega), if_pos h, rdBlkB_eq b o w h]
    simp [List.drop_drop]
  · rw [if_pos (by rw [List.length_drop, size_toList]; omega), if_neg h]

/-- `decF` in place from offset `o`: the cells and the offset after them. -/
def decFB (b : ByteArray) : List Fld → Nat → Option (List Cell × Nat)
  | [], o => some ([], o)
  | .lit w v :: fs, o => if o + w ≤ b.size then (if rdNB b o w = v then decFB b fs (o + w) else none) else none
  | .num w :: fs, o =>
    if o + w ≤ b.size then (decFB b fs (o + w)).map fun p => (.n (rdNB b o w) :: p.1, p.2) else none
  | .blk w :: fs, o =>
    if o + w ≤ b.size then (decFB b fs (o + w)).map fun p => (.b (rdBlkB b o w) :: p.1, p.2) else none

/-- The reader gives the model's cells, and the rest of the input as the model gives it. -/
theorem decFB_eq (b : ByteArray) : ∀ (fs : List Fld) (o : Nat), o ≤ b.size →
    (decFB b fs o).map (fun p => (p.1, b.data.toList.drop p.2)) = decF fs (b.data.toList.drop o)
  | [], _, _ => by simp [decFB, decF]
  | .lit w v :: fs, o, ho => by
    by_cases h : o + w ≤ b.size
    · by_cases hv : rdNB b o w = v
      · simp only [decFB, decF, rdLE_at b o w ho, if_pos h, if_pos hv]
        exact decFB_eq b fs (o + w) h
      · simp [decFB, decF, rdLE_at b o w ho, h, hv]
    · simp [decFB, decF, rdLE_at b o w ho, h]
  | .num w :: fs, o, ho => by
    by_cases h : o + w ≤ b.size
    · simp only [decFB, decF, rdLE_at b o w ho, if_pos h]
      rw [← decFB_eq b fs (o + w) h]
      simp [Option.map_map, Function.comp_def]
    · simp [decFB, decF, rdLE_at b o w ho, h]
  | .blk w :: fs, o, ho => by
    by_cases h : o + w ≤ b.size
    · simp only [decFB, decF, rdBlk_at b o w ho, if_pos h]
      rw [← decFB_eq b fs (o + w) h]
      simp [Option.map_map, Function.comp_def]
    · simp [decFB, decF, rdBlk_at b o w ho, h]

/-- One whole record of the layout from offset 0: nothing may follow it. -/
def decExactB (L : List Fld) (b : ByteArray) : Option (List Cell) :=
  match decFB b L 0 with
  | some (cs, o) => if b.size ≤ o then some cs else none
  | none => none

theorem decExactB_eq (L : List Fld) (b : ByteArray) : decExactB L b = decExact L b.data.toList := by
  have h := decFB_eq b L 0 (Nat.zero_le _)
  rw [List.drop_zero] at h
  unfold decExactB decExact
  rw [← h]
  cases hd : decFB b L 0 with
  | none => rfl
  | some p =>
    obtain ⟨cs, o⟩ := p
    cases hdr : b.data.toList.drop o with
    | nil =>
      have ho : b.size ≤ o := by
        have := congrArg List.length hdr
        rw [List.length_drop, size_toList, List.length_nil] at this
        omega
      simp [hdr, ho]
    | cons x xs =>
      have ho : ¬ b.size ≤ o := by
        intro hle
        rw [List.drop_eq_nil_of_le (by rw [size_toList]; exact hle)] at hdr
        cases hdr
      simp [hdr, ho]


/-! ## Reading straight into a record -/

/-- `w` zero bytes at `o`. -/
def zeroB (b : ByteArray) : Nat → Nat → Bool
  | _, 0 => true
  | o, w + 1 => b.get! o == 0 && zeroB b (o + 1) w

theorem zeroB_eq (b : ByteArray) : ∀ (o w : Nat), zeroB b o w = decide (rdNB b o w = 0)
  | _, 0 => by simp [zeroB, rdNB]
  | o, w + 1 => by
    rw [zeroB, rdNB, zeroB_eq b (o + 1) w]
    have key : (b.get! o == 0) = decide ((b.get! o).toNat = 0) := by
      by_cases hx : b.get! o = 0
      · simp [hx]
      · have : (b.get! o).toNat ≠ 0 := fun h => hx (UInt8.toNat_inj.mp (by simpa using h))
        simp [hx, this]
    rw [key]
    apply Bool.eq_iff_iff.mpr
    simp only [Bool.and_eq_true, decide_eq_true_eq]
    constructor
    · intro h; omega
    · intro h; omega

/-- A literal field holds its value; zeros are compared byte by byte. -/
def litOk (b : ByteArray) (o w v : Nat) : Bool := if v = 0 then zeroB b o w else rdNB b o w == v

theorem litOk_eq (b : ByteArray) (o w v : Nat) : litOk b o w v = decide (rdNB b o w = v) := by
  unfold litOk
  split
  · subst v; exact zeroB_eq b o w
  · by_cases h : rdNB b o w = v <;> simp [h]

/-- Every literal of a layout from offset `o` holds its value. -/
def litsB (b : ByteArray) : List Fld → Nat → Bool
  | [], _ => true
  | .lit w v :: fs, o => litOk b o w v && litsB b fs (o + w)
  | .num w :: fs, o => litsB b fs (o + w)
  | .blk w :: fs, o => litsB b fs (o + w)

/-- The cells of a layout read in place from offset `o`. -/
def cellsAt (b : ByteArray) : List Fld → Nat → List Cell
  | [], _ => []
  | .lit w _ :: fs, o => cellsAt b fs (o + w)
  | .num w :: fs, o => .n (rdNB b o w) :: cellsAt b fs (o + w)
  | .blk w :: fs, o => .b (rdBlkB b o w) :: cellsAt b fs (o + w)

/-- Read in place, a layout gives its cells exactly when it fits the input and its literals hold. -/
theorem decFB_char (b : ByteArray) : ∀ (L : List Fld) (o : Nat), o ≤ b.size →
    decFB b L o = if o + width L ≤ b.size ∧ litsB b L o = true then some (cellsAt b L o, o + width L) else none
  | [], o, ho => by simp [decFB, width, litsB, cellsAt, ho]
  | .lit w v :: fs, o, _ => by
    show _ = if o + (w + width fs) ≤ b.size ∧ (litOk b o w v && litsB b fs (o + w)) = true then
      some (cellsAt b fs (o + w), o + (w + width fs)) else none
    simp only [decFB]
    rw [← Nat.add_assoc o w (width fs), litOk_eq]
    by_cases h : o + w ≤ b.size
    · rw [if_pos h, decFB_char b fs (o + w) h]
      by_cases hv : rdNB b o w = v
      · simp [hv]
      · simp [hv]
    · rw [if_neg h, if_neg (by omega)]
  | .num w :: fs, o, _ => by
    show _ = if o + (w + width fs) ≤ b.size ∧ litsB b fs (o + w) = true then
      some (.n (rdNB b o w) :: cellsAt b fs (o + w), o + (w + width fs)) else none
    simp only [decFB]
    rw [← Nat.add_assoc o w (width fs)]
    by_cases h : o + w ≤ b.size
    · rw [if_pos h, decFB_char b fs (o + w) h]
      by_cases hr : o + w + width fs ≤ b.size ∧ litsB b fs (o + w) = true
      · rw [if_pos hr, if_pos hr]; rfl
      · rw [if_neg hr, if_neg hr]; rfl
    · rw [if_neg h, if_neg (by omega)]
  | .blk w :: fs, o, _ => by
    show _ = if o + (w + width fs) ≤ b.size ∧ litsB b fs (o + w) = true then
      some (.b (rdBlkB b o w) :: cellsAt b fs (o + w), o + (w + width fs)) else none
    simp only [decFB]
    rw [← Nat.add_assoc o w (width fs)]
    by_cases h : o + w ≤ b.size
    · rw [if_pos h, decFB_char b fs (o + w) h]
      by_cases hr : o + w + width fs ≤ b.size ∧ litsB b fs (o + w) = true
      · rw [if_pos hr, if_pos hr]; rfl
      · rw [if_neg hr, if_neg hr]; rfl
    · rw [if_neg h, if_neg (by omega)]

theorem decExactB_char (L : List Fld) (b : ByteArray) :
    decExactB L b = if b.size = width L ∧ litsB b L 0 = true then some (cellsAt b L 0) else none := by
  unfold decExactB
  rw [decFB_char b L 0 (Nat.zero_le _), Nat.zero_add]
  by_cases h1 : width L ≤ b.size ∧ litsB b L 0 = true
  · rw [if_pos h1]
    dsimp only
    have := h1.1
    by_cases he : b.size = width L
    · rw [if_pos (Nat.le_of_eq he), if_pos ⟨he, h1.2⟩]
    · rw [if_neg (by omega), if_neg (fun h => he h.1)]
  · rw [if_neg h1, if_neg (fun h => h1 ⟨Nat.le_of_eq h.1.symm, h.2⟩)]

/-- Where cell `i` of a layout sits, with its field, counting from offset `o`; a number of width 0 at 0 when the
    layout has no cell `i`. -/
def cellPos : List Fld → Nat → Nat → Fld × Nat
  | [], _, _ => (.num 0, 0)
  | .lit w _ :: fs, o, i => cellPos fs (o + w) i
  | .num w :: _, o, 0 => (.num w, o)
  | .num w :: fs, o, i + 1 => cellPos fs (o + w) i
  | .blk w :: _, o, 0 => (.blk w, o)
  | .blk w :: fs, o, i + 1 => cellPos fs (o + w) i

/-- The cell a position names, read in place. -/
def cellB (b : ByteArray) : Fld × Nat → Cell
  | (.num w, o) => .n (rdNB b o w)
  | (.blk w, o) => .b (rdBlkB b o w)
  | (.lit _ _, _) => .n 0

theorem cellAt_cellsAt (b : ByteArray) : ∀ (L : List Fld) (o i : Nat),
    cellAt (cellsAt b L o) i = cellB b (cellPos L o i)
  | [], _, _ => by simp [cellsAt, cellAt, cellPos, cellB, rdNB]
  | .lit _ _ :: fs, o, i => by simp only [cellsAt, cellPos]; exact cellAt_cellsAt b fs _ i
  | .num _ :: _, _, 0 => rfl
  | .num _ :: fs, o, i + 1 => by simp only [cellsAt, cellPos, cellAt]; exact cellAt_cellsAt b fs _ i
  | .blk _ :: _, _, 0 => rfl
  | .blk _ :: fs, o, i + 1 => by simp only [cellsAt, cellPos, cellAt]; exact cellAt_cellsAt b fs _ i

/-- The number of cells of a layout. -/
def ncells : List Fld → Nat
  | [] => 0
  | .lit _ _ :: fs => ncells fs
  | .num _ :: fs => ncells fs + 1
  | .blk _ :: fs => ncells fs + 1

theorem cellPos_none : ∀ (L : List Fld) (o i : Nat), ncells L ≤ i → cellPos L o i = (.num 0, 0)
  | [], _, _, _ => rfl
  | .lit _ _ :: fs, o, i, h => by
    simp only [ncells] at h; simp only [cellPos]; exact cellPos_none fs _ i h
  | .num _ :: _, _, 0, h => by simp [ncells] at h
  | .num _ :: fs, o, i + 1, h => by
    simp only [ncells] at h; simp only [cellPos]; exact cellPos_none fs _ i (by omega)
  | .blk _ :: _, _, 0, h => by simp [ncells] at h
  | .blk _ :: fs, o, i + 1, h => by
    simp only [ncells] at h; simp only [cellPos]; exact cellPos_none fs _ i (by omega)

/-- Every cell's position, computed once per layout. -/
def cellTable (L : List Fld) : Array (Fld × Nat) := ((List.range (ncells L)).map (cellPos L 0)).toArray

theorem cellTable_getD (L : List Fld) (i : Nat) : (cellTable L).getD i (.num 0, 0) = cellPos L 0 i := by
  unfold cellTable
  by_cases h : i < ncells L
  · simp [Array.getD, h]
  · simp [Array.getD, h, cellPos_none L 0 i (by omega)]

/-- The number, or the block, at a position. -/
def numAt (b : ByteArray) : Fld × Nat → Nat
  | (.num w, o) => rdNB b o w
  | _ => 0

def blkAt (b : ByteArray) : Fld × Nat → Bytes
  | (.blk w, o) => rdBlkB b o w
  | _ => []

theorem nv_cellB (b : ByteArray) (p : Fld × Nat) : (cellB b p).nv = numAt b p := by
  rcases p with ⟨f, o⟩; cases f <;> rfl

theorem bv_cellB (b : ByteArray) (p : Fld × Nat) : (cellB b p).bv = blkAt b p := by
  rcases p with ⟨f, o⟩; cases f <;> rfl

/-- A record kind's reader twin: its codec, its builder over cell accessors, and its cell table.  `build_eq` and
    `exact` hold by computation on the layout, `tbl_eq` by definition. -/
structure Twin (α : Type) where
  c : RecCodec α
  make : (Nat → Nat) → (Nat → Bytes) → α
  tbl : Array (Fld × Nat)
  build_eq : ∀ cs, c.build cs = make (nAt cs) (bAt cs)
  exact : ∀ b, c.toC (c.build (cellsAt b c.L 0)) = cellsAt b c.L 0
  tbl_eq : tbl = cellTable c.L

/-- Check the length and the literals in place, then build the record from the bytes and apply its own check. -/
def Twin.dec {α : Type} (t : Twin α) (b : ByteArray) : Option α :=
  if b.size = width t.c.L ∧ litsB b t.c.L 0 = true then
    let x := t.make (fun i => numAt b (t.tbl.getD i (.num 0, 0))) (fun i => blkAt b (t.tbl.getD i (.num 0, 0)))
    if t.c.chk x then some x else none
  else none

/-- The reader twin gives the model's answer on every input. -/
theorem Twin.dec_eq {α : Type} (t : Twin α) (b : ByteArray) : t.dec b = t.c.dec b.data.toList := by
  have hm : t.make (fun i => numAt b (t.tbl.getD i (.num 0, 0))) (fun i => blkAt b (t.tbl.getD i (.num 0, 0))) =
      t.c.build (cellsAt b t.c.L 0) := by
    rw [t.build_eq, t.tbl_eq]
    congr 1 <;> funext i <;> rw [cellTable_getD] <;> simp [nAt, bAt, cellAt_cellsAt, nv_cellB, bv_cellB]
  rw [RecCodec.dec, ← decExactB_eq, decExactB_char]
  unfold Twin.dec
  by_cases h : b.size = width t.c.L ∧ litsB b t.c.L 0 = true
  · simp only [if_pos h, Option.bind_some, RecCodec.ofC, t.exact b, hm]
    simp
  · simp only [if_neg h]
    rfl

/-- The twin of every record kind. -/
def stateT : Twin StateRow := ⟨stateC, stateMk, cellTable stateC.L, fun _ => rfl, fun _ => rfl, rfl⟩
def caseT : Twin CaseRec := ⟨caseC, caseMk, cellTable caseC.L, fun _ => rfl, fun _ => rfl, rfl⟩
def actionT : Twin ActionRec := ⟨actionC, actionMk, cellTable actionC.L, fun _ => rfl, fun _ => rfl, rfl⟩
def cmdT : Twin CmdRec := ⟨cmdC, cmdMk, cellTable cmdC.L, fun _ => rfl, fun _ => rfl, rfl⟩
def markT : Twin MarkRec := ⟨markC, markMk, cellTable markC.L, fun _ => rfl, fun _ => rfl, rfl⟩
def foldT : Twin FoldRec := ⟨foldC, foldMk, cellTable foldC.L, fun _ => rfl, fun _ => rfl, rfl⟩
def obligT : Twin ObligF := ⟨obligC, obligMk, cellTable obligC.L, fun _ => rfl, fun _ => rfl, rfl⟩
def cashT : Twin CashF := ⟨cashC, cashMk, cellTable cashC.L, fun _ => rfl, fun _ => rfl, rfl⟩
def claimT : Twin ClaimF := ⟨claimC, claimMk, cellTable claimC.L, fun _ => rfl, fun _ => rfl, rfl⟩
def supportT : Twin SupportF := ⟨supportC, supportMk, cellTable supportC.L, fun _ => rfl, fun _ => rfl, rfl⟩
def reportT : Twin ReportF := ⟨reportC, reportMk, cellTable reportC.L, fun _ => rfl, fun _ => rfl, rfl⟩
def fundT : Twin FundF := ⟨fundC, fundMk, cellTable fundC.L, fun _ => rfl, fun _ => rfl, rfl⟩
def ackT : Twin AckF := ⟨ackC, ackMk, cellTable ackC.L, fun _ => rfl, fun _ => rfl, rfl⟩

end BlindLedger.Gate.Obligations.Format

/-! ## The twins of a record codec -/

namespace BlindLedger.Gate.Obligations.RecCodec

open BlindLedger.Gate.Obligations.Format
open BlindLedger.Gate.FactCodec

variable {α : Type} (c : RecCodec α)

/-- Encode into a buffer sized for a whole `facts` record. -/
def encB (x : α) : ByteArray := encFB c.L (c.toC x) (ByteArray.emptyWithCapacity recBytes)

theorem encB_eq (x : α) : (c.encB x).data.toList = c.enc x := by
  unfold encB enc
  rw [encFB_eq]
  rfl

/-- The writer to use: the record's bytes when it is well formed, and nothing otherwise, so a value that does not
    fit is refused and never cut. -/
def write (x : α) : Option ByteArray :=
  if c.chk x then encFBc c.L (c.toC x) (ByteArray.emptyWithCapacity recBytes) else none

/-- `write` gives bytes exactly for a well-formed record, and they are `encB`'s. -/
theorem write_eq (x : α) (b : ByteArray) : c.write x = some b ↔ c.WF x ∧ b = c.encB x := by
  unfold write WF encB
  by_cases h : c.chk x = true
  · rw [if_pos h, encFBc_eq]
    simp [h]
  · simp [h]

/-- What `write` gives reads back as the record it was given. -/
theorem write_dec (hl : c.Lawful) {x : α} {b : ByteArray} (h : c.write x = some b) :
    c.dec b.data.toList = some x := by
  obtain ⟨hw, rfl⟩ := (c.write_eq x b).mp h
  rw [c.encB_eq]
  exact c.dec_enc hl hw

-- The guarded writer gives a valid record's bytes, and nothing for a number wider than its field (a determination
-- time of `2 ^ 56` ms, an amount of `2 ^ 64`), a block of another length, or a record its check refuses.
#guard (actionC.write sampleAction).map (·.data) == some (actionC.encB sampleAction).data
#guard (actionC.write { sampleAction with decidedMs := 2 ^ 56, atMs := 2 ^ 56 }).isNone
#guard (actionC.write { sampleAction with decidedMs := 2 ^ 56 - 1, atMs := 2 ^ 56 }).isSome
#guard (actionC.write { sampleAction with amount := 2 ^ 64 }).isNone
#guard (actionC.write { sampleAction with ak := pat 33 3 }).isNone
#guard (actionC.write { sampleAction with decidedMs := sampleAction.atMs + 1 }).isNone
#guard (cashC.write { sampleCash with h := { sampleCash.h with op := opEnd } }).isNone

end BlindLedger.Gate.Obligations.RecCodec
