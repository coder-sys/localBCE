import BlindLedger.Gate.FactCodec

namespace BlindLedger.Gate.Obligations

open BlindLedger.Gate.FactCodec

/-! Fixed record layouts for the program-obligations shard (design `one-store` §2.3-§2.6), written once and
    proved once.

    A layout is the list of a record's fields in byte order, read straight off the design's tables: a number of
    a fixed width (little-endian, as every `facts` record), a block of a fixed width, or a literal (a tag, a
    form, a field that is always zero, the zero padding).  A record is the list of its cells, one per number or
    block; literals have no cell.  The encoder writes the fields in order; the decoder reads them back and
    refuses any literal that differs, so a record has one encoding.  The round trip, its converse and the
    width are proved here for every layout, so each record below proves only that its own structure and its
    cell list are the same thing.

    Nothing in the gate engine or the financial worker imports this module. -/

/-- One field of a layout. -/
inductive Fld where
  /-- A `w`-byte little-endian number. -/
  | num (w : Nat)
  /-- A `w`-byte block. -/
  | blk (w : Nat)
  /-- `w` bytes that must equal the little-endian `v`: a tag, a fixed code, or zeros. -/
  | lit (w v : Nat)
  deriving Repr

/-- The value of one number or block field. -/
inductive Cell where
  | n (v : Nat)
  | b (v : Bytes)
  deriving DecidableEq, Repr

def Fld.width : Fld → Nat
  | .num w => w
  | .blk w => w
  | .lit w _ => w

def width : List Fld → Nat
  | [] => 0
  | f :: fs => f.width + width fs

/-- The cells fit the layout: one cell per number or block, in order, each within its width; every literal fits
    its own width. -/
def fit : List Fld → List Cell → Prop
  | [], cs => cs = []
  | .lit w v :: fs, cs => v < 256 ^ w ∧ fit fs cs
  | .num w :: fs, .n v :: cs => v < 256 ^ w ∧ fit fs cs
  | .blk w :: fs, .b v :: cs => v.length = w ∧ fit fs cs
  | .num _ :: _, [] => False
  | .num _ :: _, .b _ :: _ => False
  | .blk _ :: _, [] => False
  | .blk _ :: _, .n _ :: _ => False

def encF : List Fld → List Cell → Bytes
  | [], _ => []
  | .lit w v :: fs, cs => leBytes w v ++ encF fs cs
  | .num w :: fs, .n v :: cs => leBytes w v ++ encF fs cs
  | .blk _ :: fs, .b v :: cs => v ++ encF fs cs
  | .num _ :: _, [] => []
  | .num _ :: _, .b _ :: _ => []
  | .blk _ :: _, [] => []
  | .blk _ :: _, .n _ :: _ => []

def decF : List Fld → Bytes → Option (List Cell × Bytes)
  | [], b => some ([], b)
  | .lit w v :: fs, b =>
    match rdLE w b with
    | some (x, b) => if x = v then decF fs b else none
    | none => none
  | .num w :: fs, b =>
    match rdLE w b with
    | some (x, b) => (decF fs b).map fun p => (.n x :: p.1, p.2)
    | none => none
  | .blk w :: fs, b =>
    match rdBlk w b with
    | some (x, b) => (decF fs b).map fun p => (.b x :: p.1, p.2)
    | none => none

theorem decF_encF : ∀ (fs : List Fld) (cs : List Cell) (r : Bytes), fit fs cs →
    decF fs (encF fs cs ++ r) = some (cs, r)
  | [], cs, r, h => by
    simp only [fit] at h
    subst h
    simp [encF, decF]
  | .lit w v :: fs, cs, r, h => by
    obtain ⟨hv, h⟩ := h
    simp [encF, decF, List.append_assoc, rdLE_enc _ hv, decF_encF fs cs r h]
  | .num w :: fs, .n v :: cs, r, h => by
    obtain ⟨hv, h⟩ := h
    simp [encF, decF, List.append_assoc, rdLE_enc _ hv, decF_encF fs cs r h]
  | .blk w :: fs, .b v :: cs, r, h => by
    obtain ⟨hv, h⟩ := h
    simp [encF, decF, List.append_assoc, rdBlk_enc _ hv, decF_encF fs cs r h]
  | .num _ :: _, [], _, h => by simp [fit] at h
  | .num _ :: _, .b _ :: _, _, h => by simp [fit] at h
  | .blk _ :: _, [], _, h => by simp [fit] at h
  | .blk _ :: _, .n _ :: _, _, h => by simp [fit] at h

/-- Whatever decodes is the encoding of cells that fit: decoding loses nothing and accepts nothing else. -/
theorem encF_decF : ∀ (fs : List Fld) (b : Bytes) (cs : List Cell) (r : Bytes), decF fs b = some (cs, r) →
    encF fs cs ++ r = b ∧ fit fs cs
  | [], b, cs, r, h => by
    simp only [decF, Option.some.injEq, Prod.mk.injEq] at h
    obtain ⟨rfl, rfl⟩ := h
    simp [encF, fit]
  | .lit w v :: fs, b, cs, r, h => by
    simp only [decF] at h
    split at h
    · rename_i x b' hx
      split at h
      · rename_i hxv
        obtain ⟨h1, h2⟩ := encF_decF fs b' cs r h
        refine ⟨?_, hxv ▸ rdLE_lt hx, h2⟩
        rw [encF, List.append_assoc, h1, ← hxv]
        exact rdLE_dec hx
      · cases h
    · cases h
  | .num w :: fs, b, cs, r, h => by
    simp only [decF] at h
    split at h
    · rename_i x b' hx
      cases hd : decF fs b' with
      | none => simp [hd] at h
      | some p =>
        obtain ⟨cs', r'⟩ := p
        simp [hd] at h
        obtain ⟨rfl, rfl⟩ := h
        obtain ⟨h1, h2⟩ := encF_decF fs b' cs' _ hd
        refine ⟨?_, rdLE_lt hx, h2⟩
        rw [encF, List.append_assoc, h1]
        exact rdLE_dec hx
    · cases h
  | .blk w :: fs, b, cs, r, h => by
    simp only [decF] at h
    split at h
    · rename_i x b' hx
      cases hd : decF fs b' with
      | none => simp [hd] at h
      | some p =>
        obtain ⟨cs', r'⟩ := p
        simp [hd] at h
        obtain ⟨rfl, rfl⟩ := h
        obtain ⟨h1, h2⟩ := encF_decF fs b' cs' _ hd
        refine ⟨?_, rdBlk_length hx, h2⟩
        rw [encF, List.append_assoc, h1]
        exact rdBlk_dec hx
    · cases h

theorem encF_length : ∀ (fs : List Fld) (cs : List Cell), fit fs cs → (encF fs cs).length = width fs
  | [], _, _ => rfl
  | .lit w v :: fs, cs, h => by
    simp [encF, width, Fld.width, leBytes_length, encF_length fs cs h.2]
  | .num w :: fs, .n v :: cs, h => by
    simp [encF, width, Fld.width, leBytes_length, encF_length fs cs h.2]
  | .blk w :: fs, .b v :: cs, h => by
    simp [encF, width, Fld.width, h.1, encF_length fs cs h.2]
  | .num _ :: _, [], h => by simp [fit] at h
  | .num _ :: _, .b _ :: _, h => by simp [fit] at h
  | .blk _ :: _, [], h => by simp [fit] at h
  | .blk _ :: _, .n _ :: _, h => by simp [fit] at h

/-- Decode one whole record of the layout: nothing may follow it. -/
def decExact (L : List Fld) (b : Bytes) : Option (List Cell) :=
  match decF L b with
  | some (cs, []) => some cs
  | _ => none

theorem decExact_enc (L : List Fld) (cs : List Cell) (h : fit L cs) : decExact L (encF L cs) = some cs := by
  have := decF_encF L cs [] h
  rw [List.append_nil] at this
  simp [decExact, this]

theorem decExact_dec {L : List Fld} {b : Bytes} {cs : List Cell} (h : decExact L b = some cs) :
    encF L cs = b ∧ fit L cs := by
  unfold decExact at h
  split at h
  · rename_i cs' hd
    simp only [Option.some.injEq] at h
    subst h
    have := encF_decF L b cs' [] hd
    rw [List.append_nil] at this
    exact this
  · cases h

/-! ## A record codec from a layout -/

/-- The number in a number cell, the bytes in a block cell. -/
def Cell.nv : Cell → Nat
  | .n v => v
  | .b _ => 0

def Cell.bv : Cell → Bytes
  | .b v => v
  | .n _ => []

def cellAt : List Cell → Nat → Cell
  | [], _ => .n 0
  | c :: _, 0 => c
  | _ :: cs, i + 1 => cellAt cs i

/-- Cell `i` of a list as a number, or as a block. -/
def nAt (cs : List Cell) (i : Nat) : Nat := (cellAt cs i).nv
def bAt (cs : List Cell) (i : Nat) : Bytes := (cellAt cs i).bv

/-- A record type with its layout, its cells, the function that reads a record back out of cells, and the record's
    own canonical check (what the widths do not already say, such as the range of an operation code). -/
structure RecCodec (α : Type) where
  L : List Fld
  toC : α → List Cell
  build : List Cell → α
  chk : α → Bool

namespace RecCodec

variable {α : Type} (c : RecCodec α)

def enc (x : α) : Bytes := encF c.L (c.toC x)

/-- Rebuilt cells are accepted only if the record they give has exactly those cells and passes its check. -/
def ofC (cs : List Cell) : Option α :=
  if c.toC (c.build cs) = cs ∧ c.chk (c.build cs) = true then some (c.build cs) else none

def dec (b : Bytes) : Option α := (decExact c.L b).bind c.ofC

/-- Every field within its width and the record's own check. -/
def WF (x : α) : Prop := fit c.L (c.toC x) ∧ c.chk x = true

/-- What each record proves: reading back the cells of a record whose fields fit gives the record. -/
def Lawful : Prop := ∀ y, fit c.L (c.toC y) → c.build (c.toC y) = y

variable {c}

theorem ofC_eq {cs : List Cell} {y : α} (h : c.ofC cs = some y) : c.toC y = cs ∧ c.chk y = true := by
  unfold ofC at h
  split at h
  · rename_i hc
    cases h
    exact hc
  · cases h

theorem dec_enc (hl : c.Lawful) {x : α} (h : c.WF x) : c.dec (c.enc x) = some x := by
  have hb := hl x h.1
  simp [dec, enc, decExact_enc c.L (c.toC x) h.1, ofC, hb, h.2]

theorem enc_dec {b : Bytes} {x : α} (h : c.dec b = some x) : c.enc x = b := by
  unfold dec at h
  cases hd : decExact c.L b with
  | none => rw [hd] at h; simp at h
  | some cs =>
    rw [hd] at h
    obtain ⟨h1, _⟩ := ofC_eq h
    simp only [enc, h1]
    exact (decExact_dec hd).1

theorem dec_wf {b : Bytes} {x : α} (h : c.dec b = some x) : c.WF x := by
  unfold dec at h
  cases hd : decExact c.L b with
  | none => rw [hd] at h; simp at h
  | some cs =>
    rw [hd] at h
    obtain ⟨h1, h2⟩ := ofC_eq h
    refine ⟨?_, h2⟩
    rw [h1]
    exact (decExact_dec hd).2

theorem enc_length {x : α} (h : c.WF x) : (c.enc x).length = width c.L := encF_length _ _ h.1

theorem enc_inj (hl : c.Lawful) {x y : α} (hx : c.WF x) (hy : c.WF y) (h : c.enc x = c.enc y) : x = y := by
  have := dec_enc hl hx
  rw [h, dec_enc hl hy] at this
  exact (Option.some.inj this).symm

theorem dec_wrong_length {b : Bytes} (h : b.length ≠ width c.L) : c.dec b = none := by
  cases hd : c.dec b with
  | none => rfl
  | some x =>
    have h1 := enc_dec hd
    have h2 := enc_length (dec_wf hd)
    rw [h1] at h2
    exact absurd h2 h

end RecCodec

end BlindLedger.Gate.Obligations
