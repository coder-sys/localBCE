import BlindLedger.Gate.Engine3.Layout

/-! Exact rows (conformance/ENGINE_V3.md §1, revision 2): a line at the store widths of `Layout.lean` (245 bytes, every
    identifier number kept whole), and the decision step's row: the same fields as machine words (`RowX`), compared word
    by word, so no two lines or payments merge.  The decision step (`Flat/DecideRows.lean`) runs on these rows (§20 step
    1); the proofs of what the rows mean are below.  Synthetic, nonpayment, non-PHI, activation=false. -/

namespace BlindLedger.Gate.Engine3

open BlindLedger.Gate.Rules
open Std (HashSet)

/-! ## Rows and their compares -/

/-- Word `k` (0 the lowest) of `n`. -/
def word (n k : Nat) : UInt64 := (n >>> (64 * k)).toUInt64

/-- A number of 3, 4, 7 or 9 words, high word first: a provider, a member (its low 32 bytes, `0x01` implied), a line id,
    a payment. -/
structure W3 where
  a : UInt64
  b : UInt64
  c : UInt64
  deriving BEq, Hashable

structure W4 where
  a : UInt64
  b : UInt64
  c : UInt64
  d : UInt64
  deriving BEq, Hashable

structure W7 where
  a : UInt64
  b : UInt64
  c : UInt64
  d : UInt64
  e : UInt64
  f : UInt64
  g : UInt64
  deriving BEq, Hashable

structure W9 where
  a : UInt64
  b : UInt64
  c : UInt64
  d : UInt64
  e : UInt64
  f : UInt64
  g : UInt64
  h : UInt64
  i : UInt64
  deriving BEq, Hashable

def W3.nat (w : W3) : Nat := (w.a.toNat <<< 128) + (w.b.toNat <<< 64) + w.c.toNat

def W4.nat (w : W4) : Nat := (1 <<< 256) + (w.a.toNat <<< 192) + (w.b.toNat <<< 128) + (w.c.toNat <<< 64) + w.d.toNat

def W7.ofNat (n : Nat) : W7 := ⟨word n 6, word n 5, word n 4, word n 3, word n 2, word n 1, word n 0⟩

def W9.ofNat (n : Nat) : W9 :=
  ⟨word n 8, word n 7, word n 6, word n 5, word n 4, word n 3, word n 2, word n 1, word n 0⟩

/-- A line as the decision step holds it: every field at its revision 2 width, as words, high word first (`i` the id,
    `p` the payment, `m` the member, `a` the payee, `r` the rendering provider, `q` the procedure). -/
structure RowX where
  i0 : UInt64
  i1 : UInt64
  i2 : UInt64
  i3 : UInt64
  i4 : UInt64
  i5 : UInt64
  i6 : UInt64
  p0 : UInt64
  p1 : UInt64
  p2 : UInt64
  p3 : UInt64
  p4 : UInt64
  p5 : UInt64
  p6 : UInt64
  p7 : UInt64
  p8 : UInt64
  m0 : UInt64
  m1 : UInt64
  m2 : UInt64
  m3 : UInt64
  a0 : UInt64
  a1 : UInt64
  a2 : UInt64
  r0 : UInt64
  r1 : UInt64
  r2 : UInt64
  q0 : UInt64
  q1 : UInt64
  q2 : UInt64
  q3 : UInt64
  cents : UInt64
  date : UInt32
  units : UInt32
  flow : UInt8
  deriving Inhabited

def RowX.of (l : Line) : RowX :=
  ⟨word l.id 6, word l.id 5, word l.id 4, word l.id 3, word l.id 2, word l.id 1, word l.id 0,
   word l.pay 8, word l.pay 7, word l.pay 6, word l.pay 5, word l.pay 4, word l.pay 3, word l.pay 2, word l.pay 1,
   word l.pay 0, word l.member 3, word l.member 2, word l.member 1, word l.member 0, word l.payee 2, word l.payee 1,
   word l.payee 0, word l.rendering 2, word l.rendering 1, word l.rendering 0, word l.proc 3, word l.proc 2,
   word l.proc 1, word l.proc 0, word l.cents 0, l.date.toUInt32, l.units.toUInt32, l.flow.tag.toUInt8⟩

@[inline] def RowX.w9 (x : RowX) : W9 := ⟨x.p0, x.p1, x.p2, x.p3, x.p4, x.p5, x.p6, x.p7, x.p8⟩

@[inline] def RowX.w7 (x : RowX) : W7 := ⟨x.i0, x.i1, x.i2, x.i3, x.i4, x.i5, x.i6⟩

@[inline] def RowX.w4 (x : RowX) : W4 := ⟨x.m0, x.m1, x.m2, x.m3⟩

@[inline] def RowX.payee (x : RowX) : W3 := ⟨x.a0, x.a1, x.a2⟩

@[inline] def RowX.rend (x : RowX) : W3 := ⟨x.r0, x.r1, x.r2⟩

@[inline] def RowX.cap (x : RowX) : Bool := x.flow == 3

@[inline] def RowX.memEq (a b : RowX) : Bool := a.m3 == b.m3 && a.m2 == b.m2 && a.m1 == b.m1 && a.m0 == b.m0

@[inline] def RowX.payeeEq (a b : RowX) : Bool := a.a2 == b.a2 && a.a1 == b.a1 && a.a0 == b.a0

@[inline] def RowX.rendEq (a b : RowX) : Bool := a.r2 == b.r2 && a.r1 == b.r1 && a.r0 == b.r0

@[inline] def RowX.procEq (a b : RowX) : Bool := a.q3 == b.q3 && a.q2 == b.q2 && a.q1 == b.q1 && a.q0 == b.q0

/-- Equal `idKey`. -/
@[inline] def RowX.idEq (a b : RowX) : Bool :=
  a.i6 == b.i6 && a.i5 == b.i5 && a.i4 == b.i4 && a.i3 == b.i3 && a.i2 == b.i2 && a.i1 == b.i1 && a.i0 == b.i0

@[inline] def RowX.payEq (a b : RowX) : Bool :=
  a.p8 == b.p8 && a.p7 == b.p7 && a.p6 == b.p6 && a.p5 == b.p5 && a.p4 == b.p4 && a.p3 == b.p3 && a.p2 == b.p2 &&
    a.p1 == b.p1 && a.p0 == b.p0

/-- Equal lines. -/
def RowX.same (a b : RowX) : Bool :=
  a.idEq b && a.payEq b && a.flow == b.flow && a.memEq b && a.payeeEq b && a.rendEq b && a.date == b.date &&
    a.procEq b && a.units == b.units && a.cents == b.cents

/-- Equal `exactKey`: the CAP_820 flag, member, payee, date, procedure, units and cents. -/
def RowX.exactEq (a b : RowX) : Bool :=
  a.cap == b.cap && a.memEq b && a.payeeEq b && a.date == b.date && a.procEq b && a.units == b.units &&
    a.cents == b.cents

/-- Equal `nearKey`: for CAP_820 the member and the month (`date / 100`), otherwise the member, rendering provider,
    date and procedure. -/
def RowX.nearEq (a b : RowX) : Bool :=
  if a.cap then b.cap && a.memEq b && a.date / 100 == b.date / 100
  else !b.cap && a.memEq b && a.rendEq b && a.date == b.date && a.procEq b

/-- `lineLe` strictly: `enc` order (flow, member, payee, rendering, date, procedure, units, cents, id, payment). -/
def RowX.lt (a b : RowX) : Bool :=
  ((compare a.flow b.flow).then <| (compare a.m0 b.m0).then <| (compare a.m1 b.m1).then <| (compare a.m2 b.m2).then <|
    (compare a.m3 b.m3).then <| (compare a.a0 b.a0).then <| (compare a.a1 b.a1).then <| (compare a.a2 b.a2).then <|
    (compare a.r0 b.r0).then <| (compare a.r1 b.r1).then <| (compare a.r2 b.r2).then <| (compare a.date b.date).then <|
    (compare a.q0 b.q0).then <| (compare a.q1 b.q1).then <| (compare a.q2 b.q2).then <| (compare a.q3 b.q3).then <|
    (compare a.units b.units).then <| (compare a.cents b.cents).then <| (compare a.i0 b.i0).then <|
    (compare a.i1 b.i1).then <| (compare a.i2 b.i2).then <| (compare a.i3 b.i3).then <| (compare a.i4 b.i4).then <|
    (compare a.i5 b.i5).then <| (compare a.i6 b.i6).then <| (compare a.p0 b.p0).then <| (compare a.p1 b.p1).then <|
    (compare a.p2 b.p2).then <| (compare a.p3 b.p3).then <| (compare a.p4 b.p4).then <| (compare a.p5 b.p5).then <|
    (compare a.p6 b.p6).then <| (compare a.p7 b.p7).then (compare a.p8 b.p8)) == .lt

/-- The redo set as payment words.  A redone payment of `256^72` or more matches no stored row, so leaving it out is
    exact. -/
def redoW (redo : List Nat) : HashSet W9 := HashSet.ofList ((redo.filter (· < 256 ^ payW)).map W9.ofNat)

def RowX.payIn (x : RowX) (ws : HashSet W9) : Bool := ws.contains x.w9

/-! ## Words and numbers (for the proofs) -/

set_option exponentiation.threshold 1024

theorem word_toNat (n k : Nat) : (word n k).toNat = (n >>> (64 * k)) % 2 ^ 64 := by
  simp [word, Nat.toUInt64]

theorem word_eq_iff (n m k : Nat) :
    word n k = word m k ↔ (n >>> (64 * k)) % 2 ^ 64 = (m >>> (64 * k)) % 2 ^ 64 := by
  rw [← UInt64.toNat_inj, word_toNat, word_toNat]

/-- A number below `2^(64k)` is determined by its `k` low words. -/
theorem eq_of_words : ∀ (k n m : Nat), n < 2 ^ (64 * k) → m < 2 ^ (64 * k) →
    (∀ i, i < k → word n i = word m i) → n = m
  | 0, n, m, hn, hm, _ => by simp at hn hm; omega
  | k + 1, n, m, hn, hm, h => by
    have p : 2 ^ (64 * (k + 1)) = 2 ^ (64 * k) * 2 ^ 64 := by rw [Nat.mul_succ, Nat.pow_add]
    have h0 := (word_eq_iff n m 0).mp (h 0 (by omega))
    simp only [Nat.mul_zero, Nat.shiftRight_zero] at h0
    have ih := eq_of_words k (n >>> 64) (m >>> 64)
      (by rw [Nat.shiftRight_eq_div_pow]; apply Nat.div_lt_of_lt_mul; rw [Nat.mul_comm, ← p]; exact hn)
      (by rw [Nat.shiftRight_eq_div_pow]; apply Nat.div_lt_of_lt_mul; rw [Nat.mul_comm, ← p]; exact hm)
      (fun i hi => by
        have := (word_eq_iff n m (i + 1)).mp (h (i + 1) (by omega))
        rw [word_eq_iff]
        have e : 64 * (i + 1) = 64 + 64 * i := by omega
        rw [e, Nat.shiftRight_add, Nat.shiftRight_add] at this
        exact this)
    rw [Nat.shiftRight_eq_div_pow, Nat.shiftRight_eq_div_pow] at ih
    omega

theorem words1 {n m : Nat} (hn : n < 2 ^ 64) (hm : m < 2 ^ 64) : word n 0 = word m 0 ↔ n = m := by
  constructor
  · intro h
    refine eq_of_words 1 n m (by omega) (by omega) (fun i hi => ?_)
    obtain rfl : i = 0 := by omega
    exact h
  · rintro rfl; rfl

theorem words3 {n m : Nat} (hn : n < 2 ^ 192) (hm : m < 2 ^ 192) :
    (word n 0 = word m 0 ∧ word n 1 = word m 1 ∧ word n 2 = word m 2) ↔ n = m := by
  constructor
  · rintro ⟨h0, h1, h2⟩
    exact eq_of_words 3 n m (by omega) (by omega)
      (fun i hi => match i, hi with | 0, _ => h0 | 1, _ => h1 | 2, _ => h2 | i + 3, hi => absurd hi (by omega))
  · rintro rfl; simp

theorem words4 {n m : Nat} (hn : n < 2 ^ 256) (hm : m < 2 ^ 256) :
    (word n 0 = word m 0 ∧ word n 1 = word m 1 ∧ word n 2 = word m 2 ∧ word n 3 = word m 3) ↔ n = m := by
  constructor
  · rintro ⟨h0, h1, h2, h3⟩
    exact eq_of_words 4 n m (by omega) (by omega)
      (fun i hi => match i, hi with | 0, _ => h0 | 1, _ => h1 | 2, _ => h2 | 3, _ => h3 | i + 4, hi => absurd hi (by omega))
  · rintro rfl; simp

theorem words7 {n m : Nat} (hn : n < 2 ^ 448) (hm : m < 2 ^ 448) :
    (word n 0 = word m 0 ∧ word n 1 = word m 1 ∧ word n 2 = word m 2 ∧ word n 3 = word m 3 ∧ word n 4 = word m 4 ∧
      word n 5 = word m 5 ∧ word n 6 = word m 6) ↔ n = m := by
  constructor
  · rintro ⟨h0, h1, h2, h3, h4, h5, h6⟩
    exact eq_of_words 7 n m (by omega) (by omega)
      (fun i hi => match i, hi with | 0, _ => h0 | 1, _ => h1 | 2, _ => h2 | 3, _ => h3 | 4, _ => h4 | 5, _ => h5 | 6, _ => h6 | i + 7, hi => absurd hi (by omega))
  · rintro rfl; simp

theorem words9 {n m : Nat} (hn : n < 2 ^ 576) (hm : m < 2 ^ 576) :
    (word n 0 = word m 0 ∧ word n 1 = word m 1 ∧ word n 2 = word m 2 ∧ word n 3 = word m 3 ∧ word n 4 = word m 4 ∧
      word n 5 = word m 5 ∧ word n 6 = word m 6 ∧ word n 7 = word m 7 ∧ word n 8 = word m 8) ↔ n = m := by
  constructor
  · rintro ⟨h0, h1, h2, h3, h4, h5, h6, h7, h8⟩
    exact eq_of_words 9 n m (by omega) (by omega)
      (fun i hi => match i, hi with | 0, _ => h0 | 1, _ => h1 | 2, _ => h2 | 3, _ => h3 | 4, _ => h4 | 5, _ => h5 | 6, _ => h6 | 7, _ => h7 | 8, _ => h8 | i + 9, hi => absurd hi (by omega))
  · rintro rfl; simp

/-- An `n33` number is determined by its low four words. -/
theorem words4m {n m : Nat} (hn : n / 2 ^ 256 = 1) (hm : m / 2 ^ 256 = 1) :
    (word n 0 = word m 0 ∧ word n 1 = word m 1 ∧ word n 2 = word m 2 ∧ word n 3 = word m 3) ↔ n = m := by
  constructor
  · rintro ⟨h0, h1, h2, h3⟩
    have h4 : word n 4 = word m 4 := by
      rw [word_eq_iff, Nat.shiftRight_eq_div_pow, Nat.shiftRight_eq_div_pow]
      show n / 2 ^ 256 % 2 ^ 64 = m / 2 ^ 256 % 2 ^ 64
      omega
    exact eq_of_words 5 n m (by omega) (by omega)
      (fun i hi => match i, hi with | 0, _ => h0 | 1, _ => h1 | 2, _ => h2 | 3, _ => h3 | 4, _ => h4 | i + 5, hi => absurd hi (by omega))
  · rintro rfl; simp

theorem toUInt32_eq_iff {a b : Nat} (ha : a < 2 ^ 32) (hb : b < 2 ^ 32) : a.toUInt32 = b.toUInt32 ↔ a = b := by
  rw [← UInt32.toNat_inj]
  simp only [Nat.toUInt32, UInt32.toNat_ofNat']
  omega

theorem flow_eq_iff (f g : Flow) : f.tag.toUInt8 = g.tag.toUInt8 ↔ f = g := by
  cases f <;> cases g <;> decide

theorem cap_of (l : Line) : (RowX.of l).cap = isCap l := by
  simp only [RowX.cap, RowX.of, isCap]
  generalize l.flow = f
  cases f <;> decide

theorem fits2 {l : Line} (h : fitsLine2 l = true) :
    l.id < 2 ^ 448 ∧ l.pay < 2 ^ 576 ∧ l.member / 2 ^ 256 = 1 ∧ l.payee < 2 ^ 192 ∧ l.rendering < 2 ^ 192 ∧
    l.date < 2 ^ 32 ∧ l.proc < 2 ^ 256 ∧ l.units < 2 ^ 32 ∧ l.cents < 2 ^ 64 := by
  simp only [fitsLine2, Bool.and_eq_true, isN33, beq_iff_eq] at h
  obtain ⟨⟨⟨⟨⟨⟨⟨⟨h1, h2⟩, h3⟩, h4⟩, h5⟩, h6⟩, h7⟩, h8⟩, h9⟩ := h
  have a1 := of_decide_eq_true h1
  have a2 := of_decide_eq_true h2
  have a4 := of_decide_eq_true h4
  have a5 := of_decide_eq_true h5
  have a7 := of_decide_eq_true h7
  simp only [idW, payW, provW, procW] at a1 a2 a4 a5 a7
  refine ⟨?_, ?_, h3, ?_, ?_, of_decide_eq_true h6, ?_, of_decide_eq_true h8, of_decide_eq_true h9⟩ <;> omega

/-- Each compare of two fitting rows, as the equality of the fields it covers. -/
theorem of_eqs (x y : Line) (hx : fitsLine2 x = true) (hy : fitsLine2 y = true) :
    ((RowX.of x).idEq (RowX.of y) = true ↔ x.id = y.id) ∧
    ((RowX.of x).payEq (RowX.of y) = true ↔ x.pay = y.pay) ∧
    ((RowX.of x).memEq (RowX.of y) = true ↔ x.member = y.member) ∧
    ((RowX.of x).payeeEq (RowX.of y) = true ↔ x.payee = y.payee) ∧
    ((RowX.of x).rendEq (RowX.of y) = true ↔ x.rendering = y.rendering) ∧
    ((RowX.of x).procEq (RowX.of y) = true ↔ x.proc = y.proc) ∧
    ((RowX.of x).date = (RowX.of y).date ↔ x.date = y.date) ∧
    ((RowX.of x).units = (RowX.of y).units ↔ x.units = y.units) ∧
    ((RowX.of x).cents = (RowX.of y).cents ↔ x.cents = y.cents) ∧
    ((RowX.of x).flow = (RowX.of y).flow ↔ x.flow = y.flow) := by
  obtain ⟨hid, hpay, hmem, hpe, hre, hda, hpr, hun, hce⟩ := fits2 hx
  obtain ⟨hid', hpay', hmem', hpe', hre', hda', hpr', hun', hce'⟩ := fits2 hy
  refine ⟨?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_⟩
  · simp only [RowX.idEq, RowX.of, Bool.and_eq_true, beq_iff_eq, and_assoc]; exact words7 hid hid'
  · simp only [RowX.payEq, RowX.of, Bool.and_eq_true, beq_iff_eq, and_assoc]; exact words9 hpay hpay'
  · simp only [RowX.memEq, RowX.of, Bool.and_eq_true, beq_iff_eq, and_assoc]; exact words4m hmem hmem'
  · simp only [RowX.payeeEq, RowX.of, Bool.and_eq_true, beq_iff_eq, and_assoc]; exact words3 hpe hpe'
  · simp only [RowX.rendEq, RowX.of, Bool.and_eq_true, beq_iff_eq, and_assoc]; exact words3 hre hre'
  · simp only [RowX.procEq, RowX.of, Bool.and_eq_true, beq_iff_eq, and_assoc]; exact words4 hpr hpr'
  · exact toUInt32_eq_iff hda hda'
  · exact toUInt32_eq_iff hun hun'
  · exact words1 hce hce'
  · exact flow_eq_iff _ _

theorem date100 {a b : Nat} (ha : a < 2 ^ 32) (hb : b < 2 ^ 32) :
    a.toUInt32 / 100 = b.toUInt32 / 100 ↔ a / 100 = b / 100 := by
  have e : (100 : UInt32).toNat = 100 := rfl
  rw [← UInt32.toNat_inj, UInt32.toNat_div, UInt32.toNat_div, e]
  simp only [Nat.toUInt32, UInt32.toNat_ofNat']
  omega

theorem line_ext (a b : Line) : a.id = b.id → a.pay = b.pay → a.flow = b.flow → a.member = b.member →
    a.payee = b.payee → a.rendering = b.rendering → a.date = b.date → a.proc = b.proc → a.units = b.units →
    a.cents = b.cents → a = b := by
  intro h1 h2 h3 h4 h5 h6 h7 h8 h9 h10
  cases a; cases b; simp_all

theorem w9_beq (a b : W9) : (a == b) = true ↔ a = b := by
  obtain ⟨a1,a2,a3,a4,a5,a6,a7,a8,a9⟩ := a
  obtain ⟨b1,b2,b3,b4,b5,b6,b7,b8,b9⟩ := b
  simp [BEq.beq, instBEqW9.beq, W9.mk.injEq]

theorem lt_then' (o p : Ordering) : (o.then p = .lt) ↔ o = .lt ∨ (o = .eq ∧ p = .lt) := by
  cases o <;> cases p <;> simp [Ordering.then]

def Fw : Nat → Nat → Nat → Prop → Prop
  | 0, _, _, T => T
  | k + 1, n, m, T => word n k < word m k ∨ word n k = word m k ∧ Fw k n m T

theorem lexcmp (X Y a b P : Nat) (ha : a < P) (hb : b < P) :
    X * P + a < Y * P + b ↔ X < Y ∨ (X = Y ∧ a < b) := by
  rcases Nat.lt_trichotomy X Y with h | h | h
  · have := Nat.mul_le_mul_right P (show X + 1 ≤ Y from h)
    rw [Nat.add_mul, Nat.one_mul] at this
    constructor
    · intro _; exact Or.inl h
    · intro _; omega
  · subst h; constructor
    · intro h; exact Or.inr ⟨rfl, by omega⟩
    · rintro (h | ⟨_, h⟩) <;> omega
  · have := Nat.mul_le_mul_right P (show Y + 1 ≤ X from h)
    rw [Nat.add_mul, Nat.one_mul] at this
    constructor
    · intro _; omega
    · rintro (h' | ⟨h', _⟩) <;> omega

theorem lexeq (X Y a b P : Nat) (ha : a < P) (hb : b < P) :
    X * P + a = Y * P + b ↔ X = Y ∧ a = b := by
  rcases Nat.lt_trichotomy X Y with h | h | h
  · have := Nat.mul_le_mul_right P (show X + 1 ≤ Y from h)
    rw [Nat.add_mul, Nat.one_mul] at this
    constructor <;> intro h' <;> omega
  · subst h; constructor <;> intro h' <;> omega
  · have := Nat.mul_le_mul_right P (show Y + 1 ≤ X from h)
    rw [Nat.add_mul, Nat.one_mul] at this
    constructor <;> intro h' <;> omega

theorem Fw_iff : ∀ (k n m : Nat) (T : Prop),
    Fw k n m T ↔ (n % 2 ^ (64 * k) < m % 2 ^ (64 * k) ∨ (n % 2 ^ (64 * k) = m % 2 ^ (64 * k) ∧ T))
  | 0, n, m, T => by
    show T ↔ _
    rw [Nat.mul_zero, Nat.pow_zero, Nat.mod_one, Nat.mod_one]
    simp
  | k + 1, n, m, T => by
    have ih := Fw_iff k n m T
    have p : 2 ^ (64 * (k + 1)) = 2 ^ (64 * k) * 2 ^ 64 := by rw [Nat.mul_succ, Nat.pow_add]
    have hP : 0 < 2 ^ (64 * k) := Nat.two_pow_pos _
    have dn : n % 2 ^ (64 * (k + 1)) = (n / 2 ^ (64 * k) % 2 ^ 64) * 2 ^ (64 * k) + n % 2 ^ (64 * k) := by
      rw [p, Nat.mod_mul, Nat.mul_comm (2 ^ (64 * k))]; omega
    have dm : m % 2 ^ (64 * (k + 1)) = (m / 2 ^ (64 * k) % 2 ^ 64) * 2 ^ (64 * k) + m % 2 ^ (64 * k) := by
      rw [p, Nat.mod_mul, Nat.mul_comm (2 ^ (64 * k))]; omega
    have wn : (word n k).toNat = n / 2 ^ (64 * k) % 2 ^ 64 := by
      rw [word_toNat, Nat.shiftRight_eq_div_pow]
    have wm : (word m k).toNat = m / 2 ^ (64 * k) % 2 ^ 64 := by
      rw [word_toNat, Nat.shiftRight_eq_div_pow]
    have lt1 : word n k < word m k ↔ n / 2 ^ (64 * k) % 2 ^ 64 < m / 2 ^ (64 * k) % 2 ^ 64 := by
      rw [UInt64.lt_iff_toNat_lt, wn, wm]
    have eq1 : word n k = word m k ↔ n / 2 ^ (64 * k) % 2 ^ 64 = m / 2 ^ (64 * k) % 2 ^ 64 := by
      rw [← UInt64.toNat_inj, wn, wm]
    have l1 := lexcmp (n / 2 ^ (64 * k) % 2 ^ 64) (m / 2 ^ (64 * k) % 2 ^ 64) (n % 2 ^ (64 * k)) (m % 2 ^ (64 * k)) (2 ^ (64 * k))
      (Nat.mod_lt _ hP) (Nat.mod_lt _ hP)
    have l2 := lexeq (n / 2 ^ (64 * k) % 2 ^ 64) (m / 2 ^ (64 * k) % 2 ^ 64) (n % 2 ^ (64 * k)) (m % 2 ^ (64 * k)) (2 ^ (64 * k))
      (Nat.mod_lt _ hP) (Nat.mod_lt _ hP)
    show (word n k < word m k ∨ word n k = word m k ∧ Fw k n m T) ↔ _
    rw [dn, dm, l1, l2, lt1, eq1, ih]
    constructor
    · rintro (h | ⟨h1, h2 | ⟨h2, h3⟩⟩)
      · exact Or.inl (Or.inl h)
      · exact Or.inl (Or.inr ⟨h1, h2⟩)
      · exact Or.inr ⟨⟨h1, h2⟩, h3⟩
    · rintro ((h | ⟨h1, h2⟩) | ⟨⟨h1, h2⟩, h3⟩)
      · exact Or.inl h
      · exact Or.inr ⟨h1, Or.inl h2⟩
      · exact Or.inr ⟨h1, Or.inr ⟨h2, h3⟩⟩

theorem Fw_lt {k n m : Nat} (T : Prop) (hn : n < 2 ^ (64 * k)) (hm : m < 2 ^ (64 * k)) :
    Fw k n m T ↔ n < m ∨ (n = m ∧ T) := by
  rw [Fw_iff, Nat.mod_eq_of_lt hn, Nat.mod_eq_of_lt hm]

theorem Fw4m {n m : Nat} (T : Prop) (hn : n / 2 ^ 256 = 1) (hm : m / 2 ^ 256 = 1) :
    Fw 4 n m T ↔ n < m ∨ (n = m ∧ T) := by
  rw [Fw_iff]
  have h1 : n % 2 ^ (64 * 4) < m % 2 ^ (64 * 4) ↔ n < m := by omega
  have h2 : n % 2 ^ (64 * 4) = m % 2 ^ (64 * 4) ↔ n = m := by omega
  rw [h1, h2]


theorem Fw9 {n m : Nat} (T : Prop) (hn : n < 2 ^ 576) (hm : m < 2 ^ 576) : Fw 9 n m T ↔ n < m ∨ (n = m ∧ T) :=
  Fw_lt T (by omega) (by omega)
theorem Fw7 {n m : Nat} (T : Prop) (hn : n < 2 ^ 448) (hm : m < 2 ^ 448) : Fw 7 n m T ↔ n < m ∨ (n = m ∧ T) :=
  Fw_lt T (by omega) (by omega)
theorem Fw3 {n m : Nat} (T : Prop) (hn : n < 2 ^ 192) (hm : m < 2 ^ 192) : Fw 3 n m T ↔ n < m ∨ (n = m ∧ T) :=
  Fw_lt T (by omega) (by omega)
theorem Fw4 {n m : Nat} (T : Prop) (hn : n < 2 ^ 256) (hm : m < 2 ^ 256) : Fw 4 n m T ↔ n < m ∨ (n = m ∧ T) :=
  Fw_lt T (by omega) (by omega)
theorem Fw1 {n m : Nat} (T : Prop) (hn : n < 2 ^ 64) (hm : m < 2 ^ 64) : Fw 1 n m T ↔ n < m ∨ (n = m ∧ T) :=
  Fw_lt T (by omega) (by omega)

theorem u32lt {a b : Nat} (ha : a < 2 ^ 32) (hb : b < 2 ^ 32) : a.toUInt32 < b.toUInt32 ↔ a < b := by
  rw [UInt32.lt_iff_toNat_lt]
  simp only [Nat.toUInt32, UInt32.toNat_ofNat']
  omega

theorem u32eq {a b : Nat} (ha : a < 2 ^ 32) (hb : b < 2 ^ 32) : a.toUInt32 = b.toUInt32 ↔ a = b := by
  rw [← UInt32.toNat_inj]
  simp only [Nat.toUInt32, UInt32.toNat_ofNat']
  omega

theorem u8lt (f g : Flow) : f.tag.toUInt8 < g.tag.toUInt8 ↔ f.tag < g.tag := by
  cases f <;> cases g <;> decide

theorem u8eq (f g : Flow) : f.tag.toUInt8 = g.tag.toUInt8 ↔ f.tag = g.tag := by
  cases f <;> cases g <;> decide


instance : LawfulBEq W9 where
  eq_of_beq {a b} h := (w9_beq a b).1 h
  rfl {a} := (w9_beq a a).2 rfl


/-! ## Statements -/

/-- Two fitting lines have the same row exactly when they are the same line: no two lines merge. -/
theorem rowX_same_iff (x y : Line) (hx : fitsLine2 x = true) (hy : fitsLine2 y = true) :
    (RowX.of x).same (RowX.of y) = true ↔ x = y := by
  obtain ⟨h1, h2, h3, h4, h5, h6, h7, h8, h9, h10⟩ := of_eqs x y hx hy
  simp only [RowX.same, Bool.and_eq_true, beq_iff_eq, h1, h2, h3, h4, h5, h6, h7, h8, h9, h10, and_assoc]
  constructor
  · rintro ⟨e1, e2, e3, e4, e5, e6, e7, e8, e9, e10⟩
    exact line_ext x y e1 e2 e3 e4 e5 e6 e7 e8 e9 e10
  · rintro rfl; simp

theorem rowX_exactEq_iff (x y : Line) (hx : fitsLine2 x = true) (hy : fitsLine2 y = true) :
    (RowX.of x).exactEq (RowX.of y) = true ↔ exactKey x = exactKey y := by
  obtain ⟨h1, h2, h3, h4, h5, h6, h7, h8, h9, h10⟩ := of_eqs x y hx hy
  simp only [RowX.exactEq, Bool.and_eq_true, beq_iff_eq, cap_of, h3, h4, h6, h7, h8, h9, exactKey, List.cons.injEq,
    and_true, and_assoc]
  cases isCap x <;> cases isCap y <;> simp

theorem rowX_nearEq_iff (x y : Line) (hx : fitsLine2 x = true) (hy : fitsLine2 y = true) :
    (RowX.of x).nearEq (RowX.of y) = true ↔ nearKey x = nearKey y := by
  obtain ⟨h1, h2, h3, h4, h5, h6, h7, h8, h9, h10⟩ := of_eqs x y hx hy
  obtain ⟨_, _, _, _, _, hda, _⟩ := fits2 hx
  obtain ⟨_, _, _, _, _, hda', _⟩ := fits2 hy
  have hd : (RowX.of x).date / 100 = (RowX.of y).date / 100 ↔ x.date / 100 = y.date / 100 := date100 hda hda'
  simp only [RowX.nearEq, nearKey, cap_of]
  cases isCap x <;> cases isCap y <;> simp [h3, h4, h5, h6, h7, hd, and_assoc]

theorem rowX_idEq_iff (x y : Line) (hx : fitsLine2 x = true) (hy : fitsLine2 y = true) :
    (RowX.of x).idEq (RowX.of y) = true ↔ idKey x = idKey y := by
  simp [idKey, (of_eqs x y hx hy).1]

/-- The row order is the canonical order of `canonical` (`lineLe`), strict. -/
theorem rowX_lt_eq (x y : Line) (hx : fitsLine2 x = true) (hy : fitsLine2 y = true) :
    (RowX.of x).lt (RowX.of y) = !lineLe y x := by
  obtain ⟨hid, hpay, hmem, hpe, hre, hda, hpr, hun, hce⟩ := fits2 hx
  obtain ⟨hid', hpay', hmem', hpe', hre', hda', hpr', hun', hce'⟩ := fits2 hy
  rw [Bool.eq_iff_iff]
  have R : (!lineLe y x) = true ↔ enc x < enc y := by simp [lineLe]
  rw [R]
  have W : (RowX.of x).lt (RowX.of y) = true ↔
      (x.flow.tag.toUInt8 < y.flow.tag.toUInt8 ∨ x.flow.tag.toUInt8 = y.flow.tag.toUInt8 ∧
        Fw 4 x.member y.member (Fw 3 x.payee y.payee (Fw 3 x.rendering y.rendering
          (x.date.toUInt32 < y.date.toUInt32 ∨ x.date.toUInt32 = y.date.toUInt32 ∧
            Fw 4 x.proc y.proc (x.units.toUInt32 < y.units.toUInt32 ∨ x.units.toUInt32 = y.units.toUInt32 ∧
              Fw 1 x.cents y.cents (Fw 7 x.id y.id (Fw 9 x.pay y.pay False))))))) := by
    simp only [RowX.lt, RowX.of, beq_iff_eq, lt_then', Std.compare_eq_lt, Std.compare_eq_iff_eq, Fw, and_false, or_false]
  rw [W, Fw9 _ hpay hpay', Fw7 _ hid hid', Fw1 _ hce hce', u32lt hun hun', u32eq hun hun', Fw4 _ hpr hpr',
    u32lt hda hda', u32eq hda hda', Fw3 _ hre hre', Fw3 _ hpe hpe', Fw4m _ hmem hmem', u8lt, u8eq]
  simp only [enc, List.cons_lt_cons_iff, List.not_lt_nil, and_false, or_false]

/-- A fitting line's payment is in the redo words exactly when it is in the redo set, at any size of redone payment. -/
theorem redoW_mem_iff (redo : List Nat) (l : Line) (h : fitsLine2 l = true) :
    (RowX.of l).payIn (redoW redo) = redo.contains l.pay := by
  obtain ⟨_, hp, _⟩ := fits2 h
  have hp' : l.pay < 256 ^ payW := by simp only [payW]; omega
  have hinj : ∀ r, r < 256 ^ payW → (W9.ofNat r = W9.ofNat l.pay ↔ r = l.pay) := by
    intro r hr
    have hr' : r < 2 ^ 576 := by simp only [payW] at hr; omega
    rw [← words9 hr' hp]
    simp only [W9.ofNat, W9.mk.injEq]
    constructor
    · rintro ⟨a8, a7, a6, a5, a4, a3, a2, a1, a0⟩; exact ⟨a0, a1, a2, a3, a4, a5, a6, a7, a8⟩
    · rintro ⟨a0, a1, a2, a3, a4, a5, a6, a7, a8⟩; exact ⟨a8, a7, a6, a5, a4, a3, a2, a1, a0⟩
  have hw : (RowX.of l).w9 = W9.ofNat l.pay := rfl
  rw [Bool.eq_iff_iff]
  simp only [RowX.payIn, hw, redoW, Std.HashSet.contains_ofList, List.contains_iff_mem,
    List.mem_map, List.mem_filter, decide_eq_true_eq]
  constructor
  · rintro ⟨a, ⟨ha, hlt⟩, he⟩
    obtain rfl := (hinj a hlt).1 he
    exact ha
  · intro hm
    exact ⟨l.pay, ⟨hm, hp'⟩, rfl⟩

end BlindLedger.Gate.Engine3
