import BlindLedger.Gate.FactCodec
import BlindLedger.Gate.Rules.Spec

namespace BlindLedger.Gate.FactRegistry

open FactCodec

/-! The source registry and the state of a source (design `fact-record` §2.3, §2.11, §3.1, §3.2, §3.3).

    The registry is part of the signed control pack.  An entry says what a source may state, how its
    sequence number is made, how old its newest file may be, how far its row count may fall and what a
    full file covers.  The source state is a function of the receipts admitted for the source in one
    shard, of the day of the batch that reads it, and of the signed confirmations seen so far.
    Nothing here reads a fact row: the engine passes in the one count it needs from them (the number of
    the source's statements in force in the file's scope, for the per-shard drop check).

    Two choices go beyond the design text and are recorded in its change notes: the entry carries a `full`
    flag and a `cfromRule`, and a re-read by a reader release that is already stored is answered
    `already` (so that one receipt is named by one (`src`, `fseq`, `reader`)). -/

/-- `OPEN`, the date of an open end. -/
def OPEN : Nat := 99991231

/-- The registry caps `drop` at this percentage, so a full file that passes the drop check has at
    least half the rows that were in force before it (design §5.7). -/
def maxDrop : Nat := 50

/-! ## The registry entry -/

/-- One registered source.  `kinds` is the u64 mask of the kinds it may state (bit `k` for kind `k`).
    `ids` lists, for each such kind in ascending order, the codes of the raw source fields that make its
    statement identity (§2.4); what a code names is the reader's table.  `full = 1`: the source sends
    full files.  `cfromRule = 1`: a full file states all of history (`cfrom = 0`); `0`: from its own as-of
    date.  `fseqRule`: 1 the date of the file's GS segment and its ISA13 (`fseqDateIsa`), 2 the source's own
    counter, used as it is. -/
structure RegEntry where
  src : Nat
  cls : Nat
  origin : Nat
  kinds : Nat
  gapless : Nat
  maxage : Nat
  drop : Nat
  oneper : Nat
  scope : Bytes
  name : Bytes
  fseqRule : Nat
  full : Nat
  cfromRule : Nat
  ids : List (Nat × List Nat)
  deriving BEq, Repr

def kindsOk : Nat → List (Nat × List Nat) → Bool
  | _, [] => true
  | lo, (k, cs) :: t => decide (lo ≤ k) && decide (k ≤ 63) && !cs.isEmpty && kindsOk (k + 1) t

def maskOf : List (Nat × List Nat) → Nat
  | [] => 0
  | (k, _) :: t => 2 ^ k + maskOf t

/-- Field widths; `scope` and `name` are identifier blocks in their one canonical form. -/
def RegEntry.WF (e : RegEntry) : Prop :=
  e.src < 65536 ∧ e.cls < 256 ∧ e.origin < 65536 ∧ e.kinds < 18446744073709551616 ∧ e.gapless < 256 ∧
    e.maxage < 65536 ∧ e.drop < 256 ∧ e.oneper < 256 ∧ idOk 21 e.scope = true ∧ idOk 31 e.name = true ∧
    e.fseqRule < 256 ∧ e.full < 256 ∧ e.cfromRule < 256 ∧ e.ids.length < 256 ∧
    ∀ p ∈ e.ids, p.1 < 256 ∧ p.2.length < 256 ∧ ∀ c ∈ p.2, c < 65536

/-- Meaning, which the signed pack must satisfy: a real source, a class from 1 to 5, flags of 0 or 1,
    `drop` at most `maxDrop`, a known `fseq` rule, a gapless source numbered by its own counter, and the
    kinds mask equal to the kinds listed (each from 1 to 63, ascending, each with at least one identity field). -/
def RegEntry.ok (e : RegEntry) : Bool :=
  decide (0 < e.src) && decide (1 ≤ e.cls) && decide (e.cls ≤ 5) && decide (e.gapless ≤ 1) &&
    decide (e.oneper ≤ 1) && decide (e.drop ≤ maxDrop) && (e.fseqRule == 1 || e.fseqRule == 2) &&
    (e.gapless == 0 || e.fseqRule == 2) && decide (e.full ≤ 1) && decide (e.cfromRule ≤ 1) &&
    kindsOk 1 e.ids && decide (e.kinds = maskOf e.ids)

def encCodes : List Nat → Bytes
  | [] => []
  | c :: cs => leBytes 2 c ++ encCodes cs

def decCodes : Nat → Bytes → Option (List Nat × Bytes)
  | 0, b => some ([], b)
  | n + 1, b => do
    let (c, b) ← rdLE 2 b
    let (cs, b) ← decCodes n b
    pure (c :: cs, b)

def encIds : List (Nat × List Nat) → Bytes
  | [] => []
  | (k, cs) :: t => leBytes 1 k ++ leBytes 1 cs.length ++ encCodes cs ++ encIds t

def decIds : Nat → Bytes → Option (List (Nat × List Nat) × Bytes)
  | 0, b => some ([], b)
  | n + 1, b => do
    let (k, b) ← rdLE 1 b
    let (nf, b) ← rdLE 1 b
    let (cs, b) ← decCodes nf b
    let (t, b) ← decIds n b
    pure ((k, cs) :: t, b)

def RegEntry.enc (e : RegEntry) : Bytes :=
  leBytes 2 e.src ++ leBytes 1 e.cls ++ leBytes 2 e.origin ++ leBytes 8 e.kinds ++ leBytes 1 e.gapless ++
    leBytes 2 e.maxage ++ leBytes 1 e.drop ++ leBytes 1 e.oneper ++ e.scope ++ e.name ++
    leBytes 1 e.fseqRule ++ leBytes 1 e.full ++ leBytes 1 e.cfromRule ++ leBytes 1 e.ids.length ++
    encIds e.ids

/-- Decode one entry and return the rest; none when too short or when the entry is not `ok`. -/
def RegEntry.dec (b : Bytes) : Option (RegEntry × Bytes) := do
  let (src, b) ← rdLE 2 b
  let (cls, b) ← rdLE 1 b
  let (origin, b) ← rdLE 2 b
  let (kinds, b) ← rdLE 8 b
  let (gapless, b) ← rdLE 1 b
  let (maxage, b) ← rdLE 2 b
  let (drop, b) ← rdLE 1 b
  let (oneper, b) ← rdLE 1 b
  let (scope, b) ← rdId 21 b
  let (name, b) ← rdId 31 b
  let (fseqRule, b) ← rdLE 1 b
  let (full, b) ← rdLE 1 b
  let (cfromRule, b) ← rdLE 1 b
  let (nk, b) ← rdLE 1 b
  let (ids, b) ← decIds nk b
  let e : RegEntry := ⟨src, cls, origin, kinds, gapless, maxage, drop, oneper, scope, name, fseqRule,
    full, cfromRule, ids⟩
  if e.ok then pure (e, b) else none

theorem decCodes_enc (cs : List Nat) (h : ∀ c ∈ cs, c < 65536) (r : Bytes) :
    decCodes cs.length (encCodes cs ++ r) = some (cs, r) := by
  induction cs with
  | nil => simp [encCodes, decCodes]
  | cons c cs ih =>
    have hc := h c (by simp)
    have := ih (fun x hx => h x (by simp [hx]))
    simp [encCodes, decCodes, List.append_assoc, rdLE_enc, hc, this]

theorem decIds_enc (ids : List (Nat × List Nat))
    (h : ∀ p ∈ ids, p.1 < 256 ∧ p.2.length < 256 ∧ ∀ c ∈ p.2, c < 65536) (r : Bytes) :
    decIds ids.length (encIds ids ++ r) = some (ids, r) := by
  induction ids with
  | nil => simp [encIds, decIds]
  | cons p t ih =>
    obtain ⟨k, cs⟩ := p
    obtain ⟨h1, h2, h3⟩ := h (k, cs) (by simp)
    have := ih (fun x hx => h x (by simp [hx]))
    simp only at h1 h2 h3
    simp [encIds, decIds, List.append_assoc, rdLE_enc, h1, h2, decCodes_enc cs h3, this]

theorem RegEntry.dec_enc (e : RegEntry) (h : e.WF) (hok : e.ok = true) (r : Bytes) :
    RegEntry.dec (e.enc ++ r) = some (e, r) := by
  obtain ⟨src, cls, origin, kinds, gapless, maxage, drop, oneper, scope, name, fseqRule, full, cfromRule,
    ids⟩ := e
  obtain ⟨h1, h2, h3, h4, h5, h6, h7, h8, h9, h10, h11, h12, h13, h14, h15⟩ := h
  simp only at h1 h2 h3 h4 h5 h6 h7 h8 h9 h10 h11 h12 h13 h14 h15
  simp [RegEntry.enc, RegEntry.dec, List.append_assoc, rdLE_enc, rdId_enc, h1, h2, h3, h4, h5, h6, h7, h8,
    h9, h10, h11, h12, h13, h14, decIds_enc ids h15, hok]

/-- The registry's own look-up: the first entry of that `src`. -/
abbrev Registry := List RegEntry

def lookup (reg : Registry) (src : Nat) : Option RegEntry := reg.find? (·.src == src)

/-- No two entries share a `src`. -/
def srcsNodup : Registry → Bool
  | [] => true
  | e :: t => !t.any (·.src == e.src) && srcsNodup t

/-- A registry is accepted when every entry is `ok` and no `src` is listed twice. -/
def Registry.ok (reg : Registry) : Bool := reg.all RegEntry.ok && srcsNodup reg

/-- In an accepted registry the look-up finds each entry itself, so no entry shadows another. -/
theorem lookup_of_mem {reg : Registry} (h : srcsNodup reg = true) {e : RegEntry} (he : e ∈ reg) :
    lookup reg e.src = some e := by
  induction reg with
  | nil => cases he
  | cons a t ih =>
    simp only [srcsNodup, Bool.and_eq_true, Bool.not_eq_true', List.any_eq_false, beq_iff_eq] at h
    rcases List.mem_cons.mp he with rfl | he
    · simp [lookup]
    · have hne : a.src ≠ e.src := fun hh => h.1 e he hh.symm
      have := ih h.2 he
      simp [lookup, List.find?_cons, hne] at this ⊢
      exact this

/-! ## The sequence number of the example rule -/

/-- Rule 1: the date of the file's GS segment and its ISA13, so the number never wraps. -/
def fseqDateIsa (date isa : Nat) : Nat := date * 1000000000 + isa

theorem fseqDateIsa_lt {d₁ i₁ d₂ i₂ : Nat} (h₁ : i₁ < 1000000000) (h₂ : i₂ < 1000000000)
    (h : d₁ < d₂ ∨ (d₁ = d₂ ∧ i₁ < i₂)) : fseqDateIsa d₁ i₁ < fseqDateIsa d₂ i₂ := by
  unfold fseqDateIsa
  rcases h with h | ⟨rfl, h⟩ <;> omega

theorem fseqDateIsa_u64 {d i : Nat} (hd : d ≤ OPEN) (hi : i < 1000000000) :
    fseqDateIsa d i < 18446744073709551616 := by
  unfold fseqDateIsa OPEN at *
  omega

/-! ## Dates -/

theorem monthDays_le (y m : Nat) : Rules.monthDays y m ≤ 31 ∧ (m = 2 → Rules.monthDays y m ≤ 29) := by
  unfold Rules.monthDays
  repeat' split
  all_goals simp_all

/-- The part of the day number that depends on the year alone. -/
def yf (y : Nat) : Nat := y * 365 + y / 4 - y / 100 + y / 400

/-- One year later is at least 365 days later (the leap terms only add). -/
theorem yf_step (y : Nat) : yf y + 365 ≤ yf (y + 1) := by
  unfold yf; omega

theorem yf_gap {y y' : Nat} (h : y < y') : yf y + 365 ≤ yf y' := by
  obtain ⟨k, rfl⟩ : ∃ k, y' = y + 1 + k := ⟨y' - y - 1, by omega⟩
  clear h
  induction k with
  | zero => exact yf_step y
  | succ n ih =>
    have e : y + 1 + (n + 1) = (y + 1 + n) + 1 := by omega
    rw [e]
    have := yf_step (y + 1 + n)
    omega

/-- `Rules.dayNum` on the three parts of a date. -/
def dn3 (y m d : Nat) : Nat :=
  yf (y - (if m ≤ 2 then 1 else 0)) + (153 * (if m > 2 then m - 3 else m + 9) + 2) / 5 + d - 1

theorem dayNum_dn3 (d : Nat) : Rules.dayNum d = dn3 (d / 10000) (d / 100 % 100) (d % 100) := rfl

theorem dn3_mono (ya ma da yb mb db : Nat) (hy : 1 ≤ ya) (ha1 : 1 ≤ ma) (ha2 : ma ≤ 12) (hb1 : 1 ≤ mb)
    (hb2 : mb ≤ 12) (hd : 1 ≤ da) (hd2 : da ≤ 31) (hd3 : ma = 2 → da ≤ 29) (hdb : 1 ≤ db)
    (h : ya < yb ∨ (ya = yb ∧ (ma < mb ∨ (ma = mb ∧ da ≤ db)))) : dn3 ya ma da ≤ dn3 yb mb db := by
  unfold dn3
  rcases h with hl | ⟨hyy, hm⟩
  · by_cases ha : ma ≤ 2 <;> by_cases hb : mb ≤ 2
    · have g := yf_gap (show ya - 1 < yb - 1 by omega)
      simp only [if_pos ha, if_pos hb, show ¬ 2 < ma by omega, show ¬ 2 < mb by omega, if_false]
      omega
    · have g := yf_gap (show ya - 1 < yb by omega)
      simp only [Nat.sub_zero, if_pos ha, if_neg hb, show ¬ 2 < ma by omega, show 2 < mb by omega, if_false, if_true]
      omega
    · by_cases hs : ya < yb - 1
      · have g := yf_gap hs
        simp only [Nat.sub_zero, if_neg ha, if_pos hb, show 2 < ma by omega, show ¬ 2 < mb by omega, if_false, if_true]
        omega
      · have e : yb - 1 = ya := by omega
        simp only [Nat.sub_zero, if_neg ha, if_pos hb, show 2 < ma by omega, show ¬ 2 < mb by omega, if_false, if_true, e]
        omega
    · have g := yf_gap hl
      simp only [Nat.sub_zero, if_neg ha, if_neg hb, show 2 < ma by omega, show 2 < mb by omega, if_true]
      omega
  · subst hyy
    by_cases ha : ma ≤ 2 <;> by_cases hb : mb ≤ 2
    · simp only [if_pos ha, if_pos hb, show ¬ 2 < ma by omega, show ¬ 2 < mb by omega, if_false]
      omega
    · have g := yf_step (ya - 1)
      have e : ya - 1 + 1 = ya := by omega
      rw [e] at g
      simp only [Nat.sub_zero, if_pos ha, if_neg hb, show ¬ 2 < ma by omega, show 2 < mb by omega, if_false, if_true]
      omega
    · omega
    · simp only [Nat.sub_zero, if_neg ha, if_neg hb, show 2 < ma by omega, show 2 < mb by omega, if_true]
      omega

/-- Chronological order of valid dates is the order of their day numbers. -/
theorem dayNum_mono {a b : Nat} (ha : Rules.validDate a = true) (hb : Rules.validDate b = true)
    (h : a ≤ b) : Rules.dayNum a ≤ Rules.dayNum b := by
  obtain ⟨ma1, ma2⟩ := monthDays_le (a / 10000) (a / 100 % 100)
  unfold Rules.validDate at ha hb
  simp only [Bool.and_eq_true, decide_eq_true_eq] at ha hb
  rw [dayNum_dn3, dayNum_dn3]
  apply dn3_mono <;> omega

/-! ## The receipts of a source -/

/-- A stored receipt and its record number. -/
abbrev Slot := Nat × Receipt

def rcptsOf (recs : List Slot) (src : Nat) : List Receipt :=
  (recs.filter (·.2.src == src)).map (·.2)

/-- The receipt of greatest `fseq` (the earliest of equals). -/
def stepMax (a r : Receipt) : Receipt := if a.fseq < r.fseq then r else a
def pickMax : List Receipt → Option Receipt
  | [] => none
  | x :: t => some (t.foldl stepMax x)

def stepMin (a r : Receipt) : Receipt := if r.fseq < a.fseq then r else a
def pickMin : List Receipt → Option Receipt
  | [] => none
  | x :: t => some (t.foldl stepMin x)

theorem foldl_stepMax (t : List Receipt) (x : Receipt) :
    t.foldl stepMax x ∈ x :: t ∧ x.fseq ≤ (t.foldl stepMax x).fseq ∧
      ∀ b ∈ t, b.fseq ≤ (t.foldl stepMax x).fseq := by
  induction t generalizing x with
  | nil => simp
  | cons c t ih =>
    obtain ⟨h1, h2, h3⟩ := ih (stepMax x c)
    simp only [List.foldl_cons]
    by_cases hlt : x.fseq < c.fseq
    · have e : stepMax x c = c := by simp [stepMax, hlt]
      rw [e] at h1 h2 h3 ⊢
      refine ⟨?_, by omega, ?_⟩
      · exact List.mem_cons_of_mem _ h1
      · intro b hb
        simp only [List.mem_cons] at hb
        rcases hb with rfl | hb
        · exact h2
        · exact h3 b hb
    · have e : stepMax x c = x := by simp [stepMax, hlt]
      rw [e] at h1 h2 h3 ⊢
      refine ⟨?_, h2, ?_⟩
      · rcases List.mem_cons.mp h1 with h | h
        · exact List.mem_cons.mpr (Or.inl h)
        · exact List.mem_cons_of_mem _ (List.mem_cons_of_mem _ h)
      · intro b hb
        simp only [List.mem_cons] at hb
        rcases hb with rfl | hb
        · omega
        · exact h3 b hb

theorem foldl_stepMin (t : List Receipt) (x : Receipt) :
    t.foldl stepMin x ∈ x :: t ∧ (t.foldl stepMin x).fseq ≤ x.fseq ∧
      ∀ b ∈ t, (t.foldl stepMin x).fseq ≤ b.fseq := by
  induction t generalizing x with
  | nil => simp
  | cons c t ih =>
    obtain ⟨h1, h2, h3⟩ := ih (stepMin x c)
    simp only [List.foldl_cons]
    by_cases hlt : c.fseq < x.fseq
    · have e : stepMin x c = c := by simp [stepMin, hlt]
      rw [e] at h1 h2 h3 ⊢
      refine ⟨?_, by omega, ?_⟩
      · exact List.mem_cons_of_mem _ h1
      · intro b hb
        simp only [List.mem_cons] at hb
        rcases hb with rfl | hb
        · exact h2
        · exact h3 b hb
    · have e : stepMin x c = x := by simp [stepMin, hlt]
      rw [e] at h1 h2 h3 ⊢
      refine ⟨?_, h2, ?_⟩
      · rcases List.mem_cons.mp h1 with h | h
        · exact List.mem_cons.mpr (Or.inl h)
        · exact List.mem_cons_of_mem _ (List.mem_cons_of_mem _ h)
      · intro b hb
        simp only [List.mem_cons] at hb
        rcases hb with rfl | hb
        · omega
        · exact h3 b hb

theorem pickMax_spec {l : List Receipt} {a : Receipt} (h : pickMax l = some a) :
    a ∈ l ∧ ∀ b ∈ l, b.fseq ≤ a.fseq := by
  cases l with
  | nil => simp [pickMax] at h
  | cons x t =>
    simp only [pickMax, Option.some.injEq] at h
    subst h
    obtain ⟨h1, h2, h3⟩ := foldl_stepMax t x
    refine ⟨h1, ?_⟩
    intro b hb
    simp only [List.mem_cons] at hb
    rcases hb with rfl | hb
    · exact h2
    · exact h3 b hb

theorem pickMin_spec {l : List Receipt} {a : Receipt} (h : pickMin l = some a) :
    a ∈ l ∧ ∀ b ∈ l, a.fseq ≤ b.fseq := by
  cases l with
  | nil => simp [pickMin] at h
  | cons x t =>
    simp only [pickMin, Option.some.injEq] at h
    subst h
    obtain ⟨h1, h2, h3⟩ := foldl_stepMin t x
    refine ⟨h1, ?_⟩
    intro b hb
    simp only [List.mem_cons] at hb
    rcases hb with rfl | hb
    · exact h2
    · exact h3 b hb

theorem pickMax_isSome {l : List Receipt} (h : l ≠ []) : ∃ a, pickMax l = some a := by
  cases l with
  | nil => exact absurd rfl h
  | cons x t => exact ⟨_, rfl⟩

theorem pickMin_isSome {l : List Receipt} (h : l ≠ []) : ∃ a, pickMin l = some a := by
  cases l with
  | nil => exact absurd rfl h
  | cons x t => exact ⟨_, rfl⟩

/-! ## Admission (§2.3) -/

/-- Where the engine's per-source state stands in one shard.  `recs` are the admitted receipts with their
    record numbers, oldest first; `reused` the sources with an `FSEQ_REUSED` refusal not yet confirmed;
    `dropped` the numbers of full receipts whose drop check failed and is not yet confirmed. -/
structure State where
  recs : List Slot := []
  reused : List Nat := []
  dropped : List Nat := []

inductive Refusal where
  | unregistered | record | reused | reread | day | registry

def Refusal.name : Refusal → String
  | .unregistered => "unregistered" | .record => "record" | .reused => "reused"
  | .reread => "reread" | .day => "day" | .registry => "registry"

inductive Answer where
  /-- Nothing is written; the number is the receipt that already holds this file. -/
  | already (seq : Nat)
  | refused (r : Refusal)
  /-- Admitted at this record number; the flag says the drop check failed. -/
  | admitted (seq : Nat) (dropped : Bool)

def Answer.show : Answer → String
  | .already s => s!"already {s}"
  | .refused r => s!"refused {r.name}"
  | .admitted s d => s!"admitted {s} {if d then 1 else 0}"

/-- Rule 3 of the shape: what a receipt must say about itself for its source's entry.  A full receipt
    comes only from a full source, names the entry's scope and has `cfrom` at the as-of date (or at the
    start of history when the entry says the source states all of it); any other receipt has `cfrom = 0`;
    only a re-read names another receipt. -/
def cfromOk (e : RegEntry) (r : Receipt) : Bool :=
  if r.cover == 1 then
    e.full == 1 && r.scope == e.scope && r.cfrom == (if e.cfromRule == 1 then 0 else r.asof)
  else r.cfrom == 0

/-- Rule 1 of the number: its date part is a valid date.  (That it is not after the batch day is checked by
    `admitFrame`; a file built after its as-of date is legitimate.) -/
def fseqDateOk (e : RegEntry) (r : Receipt) : Bool :=
  e.fseqRule != 1 || Rules.validDate (r.fseq / 1000000000)

def shapeOk (e : RegEntry) (r : Receipt) : Bool :=
  decide (1 ≤ r.cover ∧ r.cover ≤ 4) && cfromOk e r && Rules.validDate r.asof &&
    decide (1 ≤ r.channel ∧ r.channel ≤ 3) && (r.cover == 4 || r.reread == 0) && fseqDateOk e r

/-- Rule 1: the same file bytes as an admitted receipt, whatever its source, unless this is a re-read. -/
def alreadyOf (recs : List Slot) (r : Receipt) : Option Slot :=
  if r.cover == 4 then none else recs.find? (·.2.file == r.file)

/-- Rule 2: the same `src` and `fseq` as an admitted receipt, with another file. -/
def reusedBy (recs : List Slot) (r : Receipt) : Bool :=
  recs.any fun s => s.2.src == r.src && s.2.fseq == r.fseq && s.2.file != r.file

/-- A re-read by a reader release that is already stored for this `src` and `fseq`. -/
def sameReading (recs : List Slot) (r : Receipt) : Option Slot :=
  if r.cover == 4 then recs.find? fun s => s.2.src == r.src && s.2.fseq == r.fseq && s.2.reader == r.reader
  else none

/-- Rule 6: a re-read names a stored receipt with the same file, source, `fseq`, as-of date, scope and
    sender, and a lower reader. -/
def rereadOk (recs : List Slot) (r : Receipt) : Bool :=
  r.cover != 4 || recs.any fun s => s.1 == r.reread && s.2.src == r.src && s.2.fseq == r.fseq &&
    s.2.file == r.file && s.2.asof == r.asof && s.2.scope == r.scope && s.2.sender == r.sender &&
    decide (s.2.reader < r.reader)

/-- The drop check: fewer than `(100 - drop)` percent of the old count. -/
def dropFails (drop new old : Nat) : Bool := decide (new * 100 < (100 - drop) * old)

/-- The full receipt of the source with the greatest `fseq` below `f`. -/
def prevFull (rs : List Receipt) (f : Nat) : Option Receipt :=
  pickMax (rs.filter fun a => a.cover == 1 && a.fseq < f)

/-- Rule 5, both parts, for a full receipt: its `frows` against the previous full receipt's, and its
    `rows` against the number of the source's statements in force in its scope in this shard. -/
def dropCheck (e : RegEntry) (recs : List Slot) (r : Receipt) (inForce : Nat) : Bool :=
  r.cover == 1 &&
    ((match prevFull (rcptsOf recs r.src) r.fseq with
        | some p => dropFails e.drop r.frows p.frows
        | none => false) ||
      dropFails e.drop r.rows inForce)

/-- The receipt is admitted as record `n`; a full receipt whose drop check fails is marked. -/
def store (e : RegEntry) (st : State) (n : Nat) (r : Receipt) (inForce : Nat) : Answer × State :=
  let d := dropCheck e st.recs r inForce
  (.admitted n d, { st with recs := st.recs ++ [(n, r)], dropped := if d then n :: st.dropped else st.dropped })

/-- Admit one receipt as record `n`.  `inForce` is the shard's count of the source's statements in force
    in the receipt's scope (the engine reads it from its in-memory list). -/
def admit (reg : Registry) (st : State) (n : Nat) (r : Receipt) (inForce : Nat) : Answer × State :=
  match alreadyOf st.recs r with
  | some s => (.already s.1, st)
  | none =>
    match lookup reg r.src with
    | none => (.refused .unregistered, st)
    | some e =>
      if !shapeOk e r then (.refused .record, st)
      else if !rereadOk st.recs r then (.refused .reread, st)
      else if reusedBy st.recs r then
        (.refused .reused,
          { st with reused := if st.reused.contains r.src then st.reused else r.src :: st.reused })
      else
        match sameReading st.recs r with
        | some s => (.already s.1, st)
        | none => store e st n r inForce

/-- The day rule (§3.1): a batch's day is a valid date and not before the previous batch's. -/
def dayOk (prev today : Nat) : Bool := Rules.validDate today && decide (prev ≤ today)

/-- Does a rule-1 source's number carry a date after the batch day? -/
def fseqAhead (reg : Registry) (r : Receipt) (today : Nat) : Bool :=
  match lookup reg r.src with
  | some e => e.fseqRule == 1 && decide (today < r.fseq / 1000000000)
  | none => false

/-- A frame under the day rule: the whole frame is refused `DAY` and nothing is written.  A file that says
    it is as of a day after the batch's own, or whose number carries such a date, is refused as a bad record.
    This is the one entry for runtime code: a registry that is not `Registry.ok` refuses every frame, so no
    entry shadows another. -/
def admitFrame (reg : Registry) (st : State) (prev today n : Nat) (r : Receipt) (inForce : Nat) :
    Answer × State :=
  if Registry.ok reg = false then (.refused .registry, st)
  else if dayOk prev today = false then (.refused .day, st)
  else if today < r.asof || fseqAhead reg r today then (.refused .record, st)
  else admit reg st n r inForce

/-- A signed confirmation lifts `REUSED` for a source, or `DROP` for a receipt. -/
def State.confirmReuse (st : State) (src : Nat) : State :=
  { st with reused := st.reused.filter (· != src) }
def State.confirmDrop (st : State) (seq : Nat) : State :=
  { st with dropped := st.dropped.filter (· != seq) }

/-! ### What admission guarantees

    Each branch of `admit` has its own equation; `admit_cases` says every call is one of them, and the
    statements below follow from those. -/

theorem alreadyOf_mem {recs : List Slot} {r : Receipt} {s : Slot} (h : alreadyOf recs r = some s) :
    s ∈ recs := by
  unfold alreadyOf at h
  split at h
  · simp at h
  · exact List.mem_of_find?_eq_some h

theorem sameReading_mem {recs : List Slot} {r : Receipt} {s : Slot} (h : sameReading recs r = some s) :
    s ∈ recs := by
  unfold sameReading at h
  split at h
  · exact List.mem_of_find?_eq_some h
  · simp at h

theorem u_already {reg : Registry} {st : State} {n : Nat} {r : Receipt} {k : Nat} {s : Slot}
    (hA : alreadyOf st.recs r = some s) : admit reg st n r k = (.already s.1, st) := by
  simp [admit, hA]

theorem u_unreg {reg : Registry} {st : State} {n : Nat} {r : Receipt} {k : Nat}
    (hA : alreadyOf st.recs r = none) (hL : lookup reg r.src = none) :
    admit reg st n r k = (.refused .unregistered, st) := by
  simp [admit, hA, hL]

theorem u_record {reg : Registry} {st : State} {n : Nat} {r : Receipt} {k : Nat} {e : RegEntry}
    (hA : alreadyOf st.recs r = none) (hL : lookup reg r.src = some e) (hs : shapeOk e r = false) :
    admit reg st n r k = (.refused .record, st) := by
  simp [admit, hA, hL, hs]

theorem u_reread {reg : Registry} {st : State} {n : Nat} {r : Receipt} {k : Nat} {e : RegEntry}
    (hA : alreadyOf st.recs r = none) (hL : lookup reg r.src = some e) (hs : shapeOk e r = true)
    (hr : rereadOk st.recs r = false) : admit reg st n r k = (.refused .reread, st) := by
  simp [admit, hA, hL, hs, hr]

theorem u_reused {reg : Registry} {st : State} {n : Nat} {r : Receipt} {k : Nat} {e : RegEntry}
    (hA : alreadyOf st.recs r = none) (hL : lookup reg r.src = some e) (hs : shapeOk e r = true)
    (hr : rereadOk st.recs r = true) (hu : reusedBy st.recs r = true) :
    admit reg st n r k = (.refused .reused,
      { st with reused := if st.reused.contains r.src then st.reused else r.src :: st.reused }) := by
  simp [admit, hA, hL, hs, hr, hu]

theorem u_again {reg : Registry} {st : State} {n : Nat} {r : Receipt} {k : Nat} {e : RegEntry} {s : Slot}
    (hA : alreadyOf st.recs r = none) (hL : lookup reg r.src = some e) (hs : shapeOk e r = true)
    (hr : rereadOk st.recs r = true) (hu : reusedBy st.recs r = false) (hR : sameReading st.recs r = some s) :
    admit reg st n r k = (.already s.1, st) := by
  simp [admit, hA, hL, hs, hr, hu, hR]

theorem u_store {reg : Registry} {st : State} {n : Nat} {r : Receipt} {k : Nat} {e : RegEntry}
    (hA : alreadyOf st.recs r = none) (hL : lookup reg r.src = some e) (hs : shapeOk e r = true)
    (hr : rereadOk st.recs r = true) (hu : reusedBy st.recs r = false) (hR : sameReading st.recs r = none) :
    admit reg st n r k = store e st n r k := by
  simp [admit, hA, hL, hs, hr, hu, hR]

/-- Every call of `admit` is one of the seven branches, with the conditions that select it. -/
theorem admit_cases (reg : Registry) (st : State) (n : Nat) (r : Receipt) (k : Nat) :
    (∃ s, alreadyOf st.recs r = some s ∧ admit reg st n r k = (.already s.1, st)) ∨
    (alreadyOf st.recs r = none ∧ lookup reg r.src = none ∧
      admit reg st n r k = (.refused .unregistered, st)) ∨
    (∃ e, alreadyOf st.recs r = none ∧ lookup reg r.src = some e ∧ shapeOk e r = false ∧
      admit reg st n r k = (.refused .record, st)) ∨
    (∃ e, alreadyOf st.recs r = none ∧ lookup reg r.src = some e ∧ shapeOk e r = true ∧
      rereadOk st.recs r = true ∧ reusedBy st.recs r = true ∧
      admit reg st n r k = (.refused .reused,
        { st with reused := if st.reused.contains r.src then st.reused else r.src :: st.reused })) ∨
    (∃ e s, alreadyOf st.recs r = none ∧ lookup reg r.src = some e ∧ shapeOk e r = true ∧
      rereadOk st.recs r = true ∧ reusedBy st.recs r = false ∧ sameReading st.recs r = some s ∧
      admit reg st n r k = (.already s.1, st)) ∨
    (∃ e, alreadyOf st.recs r = none ∧ lookup reg r.src = some e ∧ shapeOk e r = true ∧
      rereadOk st.recs r = false ∧ admit reg st n r k = (.refused .reread, st)) ∨
    (∃ e, alreadyOf st.recs r = none ∧ lookup reg r.src = some e ∧ shapeOk e r = true ∧
      rereadOk st.recs r = true ∧ reusedBy st.recs r = false ∧ sameReading st.recs r = none ∧
      admit reg st n r k = store e st n r k) := by
  rcases hA : alreadyOf st.recs r with _ | s
  · rcases hL : lookup reg r.src with _ | e
    · exact Or.inr (Or.inl ⟨(by first | assumption | rfl), (by first | assumption | rfl), u_unreg hA hL⟩)
    · rcases hs : shapeOk e r
      · exact Or.inr (Or.inr (Or.inl ⟨e, (by first | assumption | rfl), (by first | assumption | rfl), (by first | assumption | rfl), u_record hA hL hs⟩))
      · rcases hr : rereadOk st.recs r
        · exact Or.inr (Or.inr (Or.inr (Or.inr (Or.inr (Or.inl ⟨e, (by first | assumption | rfl), (by first | assumption | rfl), (by first | assumption | rfl), (by first | assumption | rfl), u_reread hA hL hs hr⟩)))))
        · rcases hu : reusedBy st.recs r
          · rcases hR : sameReading st.recs r with _ | s
            · exact Or.inr (Or.inr (Or.inr (Or.inr (Or.inr (Or.inr
                ⟨e, (by first | assumption | rfl), (by first | assumption | rfl), (by first | assumption | rfl), (by first | assumption | rfl), (by first | assumption | rfl), (by first | assumption | rfl), u_store hA hL hs hr hu hR⟩)))))
            · exact Or.inr (Or.inr (Or.inr (Or.inr (Or.inl
                ⟨e, s, (by first | assumption | rfl), (by first | assumption | rfl), (by first | assumption | rfl), (by first | assumption | rfl), (by first | assumption | rfl), (by first | assumption | rfl), u_again hA hL hs hr hu hR⟩))))
          · exact Or.inr (Or.inr (Or.inr (Or.inl ⟨e, (by first | assumption | rfl), (by first | assumption | rfl), (by first | assumption | rfl), (by first | assumption | rfl), (by first | assumption | rfl), u_reused hA hL hs hr hu⟩)))
  · exact Or.inl ⟨s, rfl, u_already hA⟩

/-- `admit` is total: it answers `already` and leaves the store equal, refuses, or admits at record `n`. -/
theorem admit_total (reg : Registry) (st : State) (n : Nat) (r : Receipt) (k : Nat) :
    (∃ s ∈ st.recs, (admit reg st n r k).1 = .already s.1 ∧ (admit reg st n r k).2 = st) ∨
    (∃ x, (admit reg st n r k).1 = .refused x ∧ (admit reg st n r k).2.recs = st.recs ∧
        (admit reg st n r k).2.dropped = st.dropped) ∨
    (∃ d, (admit reg st n r k).1 = .admitted n d ∧ (admit reg st n r k).2.recs = st.recs ++ [(n, r)]) := by
  rcases admit_cases reg st n r k with
    ⟨s, hA, h⟩ | ⟨_, _, h⟩ | ⟨e, _, _, _, h⟩ | ⟨e, _, _, _, _, _, h⟩ | ⟨e, s, _, _, _, _, _, hR, h⟩ |
    ⟨e, _, _, _, _, h⟩ | ⟨e, _, _, _, _, _, _, h⟩ <;> rw [h]
  · exact Or.inl ⟨s, alreadyOf_mem hA, rfl, rfl⟩
  · exact Or.inr (Or.inl ⟨_, rfl, rfl, rfl⟩)
  · exact Or.inr (Or.inl ⟨_, rfl, rfl, rfl⟩)
  · exact Or.inr (Or.inl ⟨_, rfl, rfl, rfl⟩)
  · exact Or.inl ⟨s, sameReading_mem hR, rfl, rfl⟩
  · exact Or.inr (Or.inl ⟨_, rfl, rfl, rfl⟩)
  · exact Or.inr (Or.inr ⟨_, rfl, rfl⟩)

/-- Rule 1: the same file, not a re-read, is `already` and the store is equal. -/
theorem admit_already_file (reg : Registry) (st : State) (n : Nat) (r : Receipt) (k : Nat) (s : Slot)
    (hs : s ∈ st.recs) (hf : s.2.file = r.file) (hc : r.cover ≠ 4) :
    ∃ t ∈ st.recs, (admit reg st n r k).1 = .already t.1 ∧ (admit reg st n r k).2 = st := by
  have hn : (alreadyOf st.recs r).isSome = true := by
    have h4 : (r.cover == 4) = false := by simpa using hc
    simp only [alreadyOf, h4, Bool.false_eq_true, if_false, List.find?_isSome]
    exact ⟨s, hs, by simp [hf]⟩
  obtain ⟨t, ht⟩ := Option.isSome_iff_exists.mp hn
  exact ⟨t, alreadyOf_mem ht, by rw [u_already ht], by rw [u_already ht]⟩

/-- Rule 2: the same `src` and `fseq` with another file, and no stored file equal to this one, is
    refused `FSEQ_REUSED`; the receipts stay as they are and the source is marked. -/
theorem admit_reused (reg : Registry) (st : State) (n : Nat) (r : Receipt) (k : Nat) (e : RegEntry)
    (hA : alreadyOf st.recs r = none) (hL : lookup reg r.src = some e) (hs : shapeOk e r = true)
    (hr : rereadOk st.recs r = true) (hu : reusedBy st.recs r = true) :
    (admit reg st n r k).1 = .refused .reused ∧ (admit reg st n r k).2.recs = st.recs ∧
      r.src ∈ (admit reg st n r k).2.reused := by
  rw [u_reused hA hL hs hr hu]
  refine ⟨rfl, rfl, ?_⟩
  show r.src ∈ (if st.reused.contains r.src then st.reused else r.src :: st.reused)
  by_cases hc : st.reused.contains r.src = true
  · rw [if_pos hc]; simpa using hc
  · rw [if_neg hc]; simp

/-- No stored receipt has the new one's (`src`, `fseq`, `reader`) once rules 1, 2 and 6 have passed it. -/
theorem no_same_triple {recs : List Slot} {r : Receipt} (hA : alreadyOf recs r = none)
    (hu : reusedBy recs r = false) (hR : sameReading recs r = none) :
    ∀ s ∈ recs, ¬(s.2.src = r.src ∧ s.2.fseq = r.fseq ∧ s.2.reader = r.reader) := by
  rintro s hs ⟨h1, h2, h3⟩
  by_cases hc : r.cover = 4
  · have h4 : (r.cover == 4) = true := by simpa using hc
    simp only [sameReading, h4, if_true, List.find?_eq_none] at hR
    have := hR s hs
    simp [h1, h2, h3] at this
  · have h4 : (r.cover == 4) = false := by simpa using hc
    simp only [alreadyOf, h4, Bool.false_eq_true, if_false, List.find?_eq_none] at hA
    have a1 := hA s hs
    have a2 : ¬ (s.2.src == r.src && s.2.fseq == r.fseq && s.2.file != r.file) = true := by
      intro hx
      have this : reusedBy recs r = true := List.any_eq_true.mpr ⟨s, hs, hx⟩
      rw [hu] at this
      exact Bool.false_ne_true this
    simp [h1, h2] at a1 a2
    exact a1 a2

/-- Only an exact repeat is refused: a receipt whose `fseq` is new for its source is admitted, below the
    source's highest or not (§3.2). -/
theorem admit_late_ok (reg : Registry) (st : State) (n : Nat) (r : Receipt) (k : Nat) (e : RegEntry)
    (hc : r.cover ≠ 4) (hL : lookup reg r.src = some e) (hs : shapeOk e r = true)
    (hf : ∀ s ∈ st.recs, s.2.file ≠ r.file) (hq : ∀ s ∈ st.recs, s.2.src = r.src → s.2.fseq ≠ r.fseq) :
    admit reg st n r k = store e st n r k := by
  have h4 : (r.cover == 4) = false := by simpa using hc
  have hA : alreadyOf st.recs r = none := by
    simp only [alreadyOf, h4, Bool.false_eq_true, if_false, List.find?_eq_none]
    intro s hs'; simpa using hf s hs'
  have hu : reusedBy st.recs r = false := by
    cases hx : reusedBy st.recs r
    · rfl
    · obtain ⟨s, hs', h⟩ := List.any_eq_true.mp hx
      simp only [Bool.and_eq_true, beq_iff_eq] at h
      exact absurd h.1.2 (hq s hs' h.1.1)
  exact u_store hA hL hs (by simp [rereadOk, hc]) hu (by simp [sameReading, h4])

/-- A receipt that is admitted has the shape its entry asks for. -/
theorem admit_shape (reg : Registry) (st : State) (n : Nat) (r : Receipt) (k : Nat) (d : Bool)
    (h : (admit reg st n r k).1 = .admitted n d) : ∃ e, lookup reg r.src = some e ∧ shapeOk e r = true := by
  rcases admit_cases reg st n r k with
    ⟨s, hA, h'⟩ | ⟨_, _, h'⟩ | ⟨e, _, _, _, h'⟩ | ⟨e, _, _, _, _, _, h'⟩ | ⟨e, s, _, _, _, _, _, hR, h'⟩ |
    ⟨e, _, _, _, _, h'⟩ | ⟨e, _, hL, hs, _, _, _, h'⟩
  all_goals first
    | (rw [h'] at h; simp at h; done)
    | exact ⟨e, hL, hs⟩

theorem cfromOk_spec {e : RegEntry} {r : Receipt} (h : cfromOk e r = true) :
    r.cfrom ≤ r.asof ∧ (r.cover ≠ 1 → r.cfrom = 0) := by
  unfold cfromOk at h
  by_cases hc : r.cover = 1
  · have h1 : (r.cover == 1) = true := by simpa using hc
    simp only [h1, if_true, Bool.and_eq_true, beq_iff_eq] at h
    obtain ⟨_, h3⟩ := h
    refine ⟨?_, fun hne => absurd hc hne⟩
    by_cases hr : e.cfromRule = 1
    · simp [hr] at h3; omega
    · simp [hr] at h3; omega
  · have h1 : (r.cover == 1) = false := by simpa using hc
    simp only [h1, Bool.false_eq_true, if_false, beq_iff_eq] at h
    exact ⟨by omega, fun _ => h⟩

theorem shapeOk_cfrom {e : RegEntry} {r : Receipt} (h : shapeOk e r = true) :
    r.cfrom ≤ r.asof ∧ (r.cover ≠ 1 → r.cfrom = 0) := by
  unfold shapeOk at h
  simp only [Bool.and_eq_true] at h
  exact cfromOk_spec h.1.1.1.1.2

/-- Rules 1, 2 and 6 make `(src, fseq, reader)` name one stored receipt. -/
def Names1 (recs : List Slot) : Prop :=
  ∀ a ∈ recs, ∀ b ∈ recs, a.2.src = b.2.src → a.2.fseq = b.2.fseq → a.2.reader = b.2.reader → a = b

theorem names1_empty : Names1 [] := by simp [Names1]

theorem admit_names1 (reg : Registry) (st : State) (n : Nat) (r : Receipt) (k : Nat)
    (h : Names1 st.recs) : Names1 (admit reg st n r k).2.recs := by
  have keep : ∀ p : Answer × State, p.2.recs = st.recs → Names1 p.2.recs := fun p hp => by rw [hp]; exact h
  rcases admit_cases reg st n r k with
    ⟨s, hA, h'⟩ | ⟨_, _, h'⟩ | ⟨e, _, _, _, h'⟩ | ⟨e, _, _, _, _, _, h'⟩ | ⟨e, s, _, _, _, _, _, hR, h'⟩ |
    ⟨e, _, _, _, _, h'⟩ | ⟨e, hA, hL, hs, hr, hu, hR, h'⟩
  all_goals first
    | (rw [h']; exact keep _ rfl)
    | skip
  rw [h']
  have hk := no_same_triple hA hu hR
  show Names1 (st.recs ++ [(n, r)])
  intro a ha b hb h1 h2 h3
  rw [List.mem_append] at ha hb
  rcases ha with ha | ha <;> rcases hb with hb | hb
  · exact h a ha b hb h1 h2 h3
  · simp only [List.mem_singleton] at hb; subst hb
    exact absurd ⟨h1, h2, h3⟩ (hk a ha)
  · simp only [List.mem_singleton] at ha; subst ha
    exact absurd ⟨h1.symm, h2.symm, h3.symm⟩ (hk b hb)
  · simp only [List.mem_singleton] at ha hb; rw [ha, hb]

/-- `rank` names one row: with `(src, fseq, reader)` naming one receipt, equal ranks are one row. -/
theorem rank_strict {recs : List Slot} (h : Names1 recs) {a b : Slot} (ha : a ∈ recs) (hb : b ∈ recs)
    (hs : a.2.src = b.2.src) (o₁ o₂ : Nat) (hr : a.2.rankOf o₁ = b.2.rankOf o₂) : a = b ∧ o₁ = o₂ := by
  have := rank_names_row a.2 b.2 o₁ o₂ (fun h1 h2 => by rw [h a ha b hb hs h1 h2]) hr
  exact ⟨h a ha b hb hs (by simpa [Receipt.rankOf, rank] using congrArg (·.1) hr)
    (by simpa [Receipt.rankOf, rank] using congrArg (·.2.1) hr), this.2⟩

/-- A registry that is not `Registry.ok` admits nothing and changes nothing. -/
theorem admit_registry (reg : Registry) (st : State) (prev today n : Nat) (r : Receipt) (k : Nat)
    (h : Registry.ok reg = false) : admitFrame reg st prev today n r k = (.refused .registry, st) := by
  simp [admitFrame, h]

theorem admit_day (reg : Registry) (st : State) (prev today n : Nat) (r : Receipt) (k : Nat)
    (hg : Registry.ok reg = true) (h : dayOk prev today = false) :
    admitFrame reg st prev today n r k = (.refused .day, st) := by
  simp [admitFrame, hg, h]

theorem admit_future (reg : Registry) (st : State) (prev today n : Nat) (r : Receipt) (k : Nat)
    (hg : Registry.ok reg = true) (h : dayOk prev today = true) (hf : today < r.asof) :
    admitFrame reg st prev today n r k = (.refused .record, st) := by
  simp [admitFrame, hg, h, hf]

/-- A receipt whose source numbers by rule 1 and that is admitted has a valid date in its number. -/
theorem admit_fseq_date (reg : Registry) (st : State) (n : Nat) (r : Receipt) (k : Nat) (d : Bool) (e : RegEntry)
    (h : (admit reg st n r k).1 = .admitted n d) (hL : lookup reg r.src = some e) (hr : e.fseqRule = 1) :
    Rules.validDate (r.fseq / 1000000000) = true := by
  obtain ⟨e', hL', hs⟩ := admit_shape reg st n r k d h
  rw [hL] at hL'
  cases hL'
  unfold shapeOk fseqDateOk at hs
  simp [hr] at hs
  exact hs.2

/-- Through the one entry, a rule-1 number's date is valid and not after the batch day, so a number cannot be
    huge. -/
theorem admitFrame_fseq_date (reg : Registry) (st : State) (prev today n : Nat) (r : Receipt) (k : Nat)
    (d : Bool) (e : RegEntry) (h : (admitFrame reg st prev today n r k).1 = .admitted n d)
    (hL : lookup reg r.src = some e) (hr : e.fseqRule = 1) :
    Rules.validDate (r.fseq / 1000000000) = true ∧ r.fseq / 1000000000 ≤ today := by
  unfold admitFrame at h
  split at h
  · simp at h
  · split at h
    · simp at h
    · split at h
      · simp at h
      · rename_i h3
        refine ⟨?_, ?_⟩
        · exact admit_fseq_date reg st n r k d e h hL hr
        · simp [fseqAhead, hL, hr] at h3
          omega

/-! ## Drop check -/

/-- A file that passes keeps at least `(100 - drop)` percent of the old count, and because the registry
    caps `drop` at 50, the old count is at most twice the new one (the bound of design §5.7). -/
theorem drop_bound {drop new old : Nat} (hd : drop ≤ maxDrop) (h : dropFails drop new old = false) :
    old * (100 - drop) ≤ new * 100 ∧ old ≤ 2 * new := by
  unfold dropFails maxDrop at *
  simp only [decide_eq_false_iff_not, Nat.not_lt] at h
  have h50 : 50 * old ≤ (100 - drop) * old := Nat.mul_le_mul_right _ (by omega)
  constructor
  · rw [Nat.mul_comm]; exact h
  · omega

/-- The admitted receipt is marked when, and only when, the check failed (`n` a fresh number). -/
theorem store_drop (e : RegEntry) (st : State) (n : Nat) (r : Receipt) (k : Nat) (hn : n ∉ st.dropped) :
    n ∈ (store e st n r k).2.dropped ↔ (store e st n r k).1 = .admitted n true := by
  unfold store
  by_cases hd : dropCheck e st.recs r k = true
  · simp [hd]
  · simp only [Bool.not_eq_true] at hd
    simp [hd, hn]

/-- Only a full receipt can fail the drop check. -/
theorem dropCheck_full {e : RegEntry} {recs : List Slot} {r : Receipt} {k : Nat}
    (h : dropCheck e recs r k = true) : r.cover = 1 := by
  unfold dropCheck at h
  simp only [Bool.and_eq_true, beq_iff_eq] at h
  exact h.1

/-! ## Source state at a day (§3.4 item 1, §3.2) -/

/-- Is one of the `n` numbers from `f` on missing from the receipts?  It stops at the first missing
    number, so a huge range costs at most one step per stored receipt. -/
def gapFrom (rs : List Receipt) (f : Nat) : Nat → Bool
  | 0 => false
  | n + 1 => if rs.any (·.fseq == f) then gapFrom rs (f + 1) n else true

theorem gapFrom_iff (rs : List Receipt) (n f : Nat) :
    gapFrom rs f n = true ↔ ∃ g, f ≤ g ∧ g < f + n ∧ ∀ a ∈ rs, a.fseq ≠ g := by
  induction n generalizing f with
  | zero =>
    simp only [gapFrom, Bool.false_eq_true, false_iff, not_exists]
    intro g h1
    omega
  | succ n ih =>
    unfold gapFrom
    by_cases hp : rs.any (·.fseq == f) = true
    · rw [if_pos hp, ih]
      constructor
      · rintro ⟨g, h1, h2, h3⟩
        exact ⟨g, by omega, by omega, h3⟩
      · rintro ⟨g, h1, h2, h3⟩
        have : g ≠ f := by
          rintro rfl
          obtain ⟨a, ha, hae⟩ := List.any_eq_true.mp hp
          exact h3 a ha (by simpa using hae)
        exact ⟨g, by omega, by omega, h3⟩
    · rw [if_neg hp]
      simp only [true_iff]
      refine ⟨f, Nat.le_refl _, by omega, fun a ha hae => hp ?_⟩
      exact List.any_eq_true.mpr ⟨a, ha, by simp [hae]⟩

/-- Rule 4: is a number missing strictly between `b` and `h`? -/
def gapAt (rs : List Receipt) (b h : Nat) : Bool := gapFrom rs (b + 1) (h - b - 1)

theorem gapAt_iff (rs : List Receipt) (b h : Nat) :
    gapAt rs b h = true ↔ ∃ f, b < f ∧ f < h ∧ ∀ a ∈ rs, a.fseq ≠ f := by
  unfold gapAt
  rw [gapFrom_iff]
  constructor
  · rintro ⟨g, h1, h2, h3⟩
    exact ⟨g, by omega, by omega, h3⟩
  · rintro ⟨g, h1, h2, h3⟩
    exact ⟨g, by omega, by omega, h3⟩

/-- A gapless source has an open gap when a number is missing between its newest full receipt (or its
    lowest receipt, with no full one) and its highest.  A newer full receipt clears it, and so does the
    late file that fills it. -/
def gapOpen (e : RegEntry) (rs : List Receipt) : Bool :=
  e.gapless == 1 &&
    match pickMax rs with
    | none => false
    | some hi =>
      match pickMax (rs.filter (·.cover == 1)) with
      | some f => gapAt rs f.fseq hi.fseq
      | none =>
        match pickMin rs with
        | some lo => gapAt rs lo.fseq hi.fseq
        | none => false

/-- A late file that supplies the only missing number clears the gap. -/
theorem gap_filled (rs : List Receipt) (a : Receipt) (b h : Nat)
    (hall : ∀ f, b < f → f < h → f ≠ a.fseq → ∃ x ∈ rs, x.fseq = f) : gapAt (a :: rs) b h = false := by
  rw [Bool.eq_false_iff]
  intro hg
  obtain ⟨f, h1, h2, h3⟩ := (gapAt_iff _ _ _).mp hg
  by_cases hf : f = a.fseq
  · exact h3 a (by simp) hf.symm
  · obtain ⟨x, hx, hxf⟩ := hall f h1 h2 hf
    exact h3 x (by simp [hx]) hxf

/-- A newer full receipt clears the gap: when the newest receipt is a full one, there is none. -/
theorem gap_full_newest (e : RegEntry) (rs : List Receipt) (hi : Receipt) (hm : pickMax rs = some hi)
    (hc : hi.cover = 1) : gapOpen e rs = false := by
  obtain ⟨hm1, hm2⟩ := pickMax_spec hm
  have hh : hi ∈ rs.filter (·.cover == 1) := List.mem_filter.mpr ⟨hm1, by simp [hc]⟩
  obtain ⟨f, hf⟩ := pickMax_isSome (List.ne_nil_of_mem hh)
  obtain ⟨hf1, hf2⟩ := pickMax_spec hf
  have hfm := (List.mem_filter.mp hf1).1
  have h1 := hf2 hi hh
  have h2 := hm2 f hfm
  have hg : gapAt rs f.fseq hi.fseq = false := by
    have : hi.fseq - f.fseq - 1 = 0 := by omega
    simp [gapAt, gapFrom, this]
  simp [gapOpen, hm, hf, hg]

/-- The causes of staleness, in the order they are tried.  (`REF_CAP` and `REF_LAG` belong to the
    reference set, a later step.) -/
inductive Cause where
  | noReceipt | future | age | gap | drop | reused

def Cause.name : Cause → String
  | .noReceipt => "noReceipt" | .future => "future" | .age => "age" | .gap => "gap"
  | .drop => "drop" | .reused => "reused"

/-- Is the source stale at `today` (the reading batch's own day)?  Judged on its newest receipt by `fseq`. -/
def staleCause (e : RegEntry) (st : State) (today : Nat) : Option Cause :=
  match pickMax (rcptsOf st.recs e.src) with
  | none => some .noReceipt
  | some n =>
    if today < n.asof then some .future
    else if Rules.dayNum n.asof + e.maxage < Rules.dayNum today then some .age
    else if gapOpen e (rcptsOf st.recs e.src) then some .gap
    else if st.recs.any (fun s => s.2.src == e.src && st.dropped.contains s.1) then some .drop
    else if st.reused.contains e.src then some .reused
    else none

/-- An unconfirmed `DROP` on any of the source's receipts makes it stale. -/
theorem stale_of_drop (e : RegEntry) (st : State) (today : Nat) (s : Slot) (hs : s ∈ st.recs)
    (hsrc : s.2.src = e.src) (hd : s.1 ∈ st.dropped) : staleCause e st today ≠ none := by
  have hany : st.recs.any (fun s => s.2.src == e.src && st.dropped.contains s.1) = true :=
    List.any_eq_true.mpr ⟨s, hs, by simp [hsrc, hd]⟩
  unfold staleCause
  rcases pickMax (rcptsOf st.recs e.src) with _ | n
  · simp
  · simp only
    repeat' split
    all_goals simp_all

/-- An unconfirmed `REUSED` makes the source stale. -/
theorem stale_of_reused (e : RegEntry) (st : State) (today : Nat) (h : e.src ∈ st.reused) :
    staleCause e st today ≠ none := by
  unfold staleCause
  rcases pickMax (rcptsOf st.recs e.src) with _ | n
  · simp
  · simp only
    repeat' split
    all_goals simp_all

/-- A source with no receipt is stale. -/
theorem stale_of_none (e : RegEntry) (st : State) (today : Nat)
    (h : rcptsOf st.recs e.src = []) : staleCause e st today = some .noReceipt := by
  simp [staleCause, h, pickMax]

/-- Age is judged at the reading batch's day, so a later day never makes an old file look fresher; with the
    day rule, a gate that sits idle never revives a stale source. -/
theorem age_persists {a t t' m : Nat} (ht : Rules.validDate t = true) (ht' : Rules.validDate t' = true)
    (h : t ≤ t') (hs : Rules.dayNum a + m < Rules.dayNum t) : Rules.dayNum a + m < Rules.dayNum t' := by
  have := dayNum_mono ht ht' h
  omega

theorem idle_never_fresher {a prev today m : Nat} (hp : Rules.validDate prev = true)
    (hd : dayOk prev today = true) (hs : Rules.dayNum a + m < Rules.dayNum prev) :
    Rules.dayNum a + m < Rules.dayNum today := by
  unfold dayOk at hd
  simp only [Bool.and_eq_true, decide_eq_true_eq] at hd
  exact age_persists hp hd.1 hd.2 hs

/-- A source that is stale for age stays stale for age on any later valid day, whatever else is true then. -/
theorem stale_age_persists (e : RegEntry) (st : State) {t t' : Nat} (ht : Rules.validDate t = true)
    (h : dayOk t t' = true) (hs : staleCause e st t = some .age) : staleCause e st t' = some .age := by
  unfold dayOk at h
  simp only [Bool.and_eq_true, decide_eq_true_eq] at h
  unfold staleCause at hs ⊢
  rcases hp : pickMax (rcptsOf st.recs e.src) with _ | n
  · simp [hp] at hs
  · simp only [hp] at hs ⊢
    by_cases h1 : t < n.asof
    · simp [h1] at hs
    · by_cases h3 : Rules.dayNum n.asof + e.maxage < Rules.dayNum t
      · have h4 := age_persists ht h.1 h.2 h3
        have h2 : ¬ t' < n.asof := by omega
        simp [h2, h4]
      · revert hs
        simp only [h1, h3, if_false]
        repeat' split
        all_goals simp

/-- A source that is stale for a gap stays stale (for a gap, or by then for age) on any later day. -/
theorem stale_gap_persists (e : RegEntry) (st : State) {t t' : Nat} (h : t ≤ t')
    (hs : staleCause e st t = some .gap) : staleCause e st t' ≠ none := by
  unfold staleCause at hs ⊢
  rcases hp : pickMax (rcptsOf st.recs e.src) with _ | n
  · simp [hp] at hs
  · simp only [hp] at hs ⊢
    by_cases h1 : t < n.asof
    · simp [h1] at hs
    · have h2 : ¬ t' < n.asof := by omega
      by_cases h3 : Rules.dayNum n.asof + e.maxage < Rules.dayNum t
      · simp [h1, h3] at hs
      · by_cases h5 : Rules.dayNum n.asof + e.maxage < Rules.dayNum t'
        · simp [h2, h5]
        · by_cases h4 : gapOpen e (rcptsOf st.recs e.src) = true
          · simp [h2, h5, h4]
          · revert hs
            simp only [h1, h3, if_false, h4]
            repeat' split
            all_goals simp

/-! ## Late files and ends (§3.2, §3.3) -/

/-- The calendar day before a date; `0` for `0`, which stands for the start of history. -/
def dayBefore (d : Nat) : Nat :=
  if 1 < d % 100 then d - 1
  else if 1 < d / 100 % 100 then
    d / 10000 * 10000 + (d / 100 % 100 - 1) * 100 + Rules.monthDays (d / 10000) (d / 100 % 100 - 1)
  else if 1 < d / 10000 then (d / 10000 - 1) * 10000 + 1231
  else 0

theorem dayBefore_lt {d : Nat} (h : d ≠ 0) : dayBefore d < d := by
  unfold dayBefore
  have hm := (monthDays_le (d / 10000) (d / 100 % 100 - 1)).1
  repeat' split
  all_goals omega

/-- Every valid date before a valid date `c` is at or before the day before `c`. -/
theorem le_dayBefore {D c : Nat} (hD : Rules.validDate D = true) (hc : Rules.validDate c = true) (h : D < c) :
    D ≤ dayBefore c := by
  have hDm := (monthDays_le (D / 10000) (D / 100 % 100)).1
  have hc1 : 1 ≤ Rules.monthDays (c / 10000) (c / 100 % 100 - 1) := by
    unfold Rules.monthDays
    repeat' split
    all_goals omega
  unfold Rules.validDate at hD hc
  simp only [Bool.and_eq_true, decide_eq_true_eq] at hD hc
  obtain ⟨⟨⟨⟨⟨_, _⟩, _⟩, _⟩, _⟩, hDd⟩ := hD
  unfold dayBefore
  split
  · omega
  · split
    · by_cases hy : D / 10000 = c / 10000 ∧ D / 100 % 100 = c / 100 % 100 - 1
      · rw [hy.1, hy.2] at hDd
        omega
      · omega
    · split <;> omega

#guard dayBefore 20260301 == 20260228 && dayBefore 20280301 == 20280229 && dayBefore 20260101 == 20251231 &&
  dayBefore 20260401 == 20260331 && dayBefore 20260315 == 20260314 && dayBefore 0 == 0

/-- The last day of a month and the first day of the next are one day apart. -/
theorem dn3_prev_month (y m : Nat) (hy : 1 ≤ y) (h2 : 2 ≤ m) (h12 : m ≤ 12) :
    dn3 y (m - 1) (Rules.monthDays y (m - 1)) + 1 = dn3 y m 1 := by
  have : m = 2 ∨ m = 3 ∨ m = 4 ∨ m = 5 ∨ m = 6 ∨ m = 7 ∨ m = 8 ∨ m = 9 ∨ m = 10 ∨ m = 11 ∨ m = 12 := by omega
  rcases this with rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl
  · simp [dn3, yf, Rules.monthDays] <;> omega
  · simp [dn3, yf, Rules.monthDays, Rules.leap]
    by_cases a : y % 4 = 0 <;> by_cases b : y % 100 = 0 <;> by_cases c : y % 400 = 0 <;> simp [a, b, c] <;> omega
  all_goals simp [dn3, yf, Rules.monthDays] <;> omega

/-- The last day of a year and the first day of the next are one day apart. -/
theorem dn3_prev_year (y : Nat) : dn3 y 12 31 + 1 = dn3 (y + 1) 1 1 := by
  unfold dn3 yf
  simp <;> omega

/-- The day before a valid date after the first valid day is valid, and one day earlier. -/
theorem dayBefore_valid {d : Nat} (hd : Rules.validDate d = true) (hmin : 10101 < d) :
    Rules.validDate (dayBefore d) = true ∧ Rules.dayNum (dayBefore d) + 1 = Rules.dayNum d := by
  have hdn := dayNum_dn3 d
  unfold Rules.validDate at hd
  simp only [Bool.and_eq_true, decide_eq_true_eq] at hd
  have hm1 : 1 ≤ Rules.monthDays (d / 10000) (d / 100 % 100 - 1) := by
    unfold Rules.monthDays
    repeat' split
    all_goals omega
  have hm2 := (monthDays_le (d / 10000) (d / 100 % 100 - 1)).1
  unfold dayBefore
  split
  · have e1 : (d - 1) / 10000 = d / 10000 := by omega
    have e2 : (d - 1) / 100 % 100 = d / 100 % 100 := by omega
    have e3 : (d - 1) % 100 = d % 100 - 1 := by omega
    unfold Rules.validDate
    rw [dayNum_dn3 (d - 1), hdn, e1, e2, e3]
    simp only [Bool.and_eq_true, decide_eq_true_eq]
    refine ⟨by omega, ?_⟩
    unfold dn3 yf
    repeat' split
    all_goals omega
  · split
    · have hd1 : d % 100 = 1 := by omega
      have f1 : (d / 10000 * 10000 + (d / 100 % 100 - 1) * 100 + Rules.monthDays (d / 10000) (d / 100 % 100 - 1)) / 10000
          = d / 10000 := by omega
      have f2 : (d / 10000 * 10000 + (d / 100 % 100 - 1) * 100 + Rules.monthDays (d / 10000) (d / 100 % 100 - 1)) / 100 % 100
          = d / 100 % 100 - 1 := by omega
      have f3 : (d / 10000 * 10000 + (d / 100 % 100 - 1) * 100 + Rules.monthDays (d / 10000) (d / 100 % 100 - 1)) % 100
          = Rules.monthDays (d / 10000) (d / 100 % 100 - 1) := by omega
      have key := dn3_prev_month (d / 10000) (d / 100 % 100) (by omega) (by omega) (by omega)
      unfold Rules.validDate
      rw [dayNum_dn3 _, hdn, f1, f2, f3, hd1]
      simp only [Bool.and_eq_true, decide_eq_true_eq]
      exact ⟨by omega, key⟩
    · split
      · have hd1 : d % 100 = 1 := by omega
        have hm : d / 100 % 100 = 1 := by omega
        have f1 : ((d / 10000 - 1) * 10000 + 1231) / 10000 = d / 10000 - 1 := by omega
        have f2 : ((d / 10000 - 1) * 10000 + 1231) / 100 % 100 = 12 := by omega
        have f3 : ((d / 10000 - 1) * 10000 + 1231) % 100 = 31 := by omega
        have key := dn3_prev_year (d / 10000 - 1)
        have e : d / 10000 - 1 + 1 = d / 10000 := by omega
        rw [e] at key
        unfold Rules.validDate
        rw [dayNum_dn3 _, hdn, f1, f2, f3, hd1, hm]
        simp only [Bool.and_eq_true, decide_eq_true_eq]
        refine ⟨⟨by omega, ?_⟩, key⟩
        have : 31 ≤ Rules.monthDays (d / 10000 - 1) 12 := by simp [Rules.monthDays]
        omega
      · omega

/-- The `until` of a row of fseq `f`: the day before the least `cfrom` of the source's full receipts with an
    `fseq` above `f` (`0` when one of them states all of history, so the row speaks for no date), `OPEN`
    when there is none.  Every newer full file states each date from its own `cfrom` on, and `cfrom` need
    not rise with `fseq`, so the least one counts.  It depends on `fseq` and the receipts only, never on
    arrival order. -/
def lateUntil (rs : List Receipt) (f : Nat) : Nat :=
  match ((rs.filter fun a => a.cover == 1 && f < a.fseq).map (·.cfrom)).min? with
  | some c => dayBefore c
  | none => OPEN

theorem lateUntil_open (rs : List Receipt) (f : Nat) (h : ∀ a ∈ rs, a.cover = 1 → a.fseq ≤ f) :
    lateUntil rs f = OPEN := by
  have : rs.filter (fun a => a.cover == 1 && f < a.fseq) = [] := by
    rw [List.filter_eq_nil_iff]
    intro a ha hc
    simp only [Bool.and_eq_true, beq_iff_eq, decide_eq_true_eq] at hc
    have := h a ha hc.1
    omega
  simp [lateUntil, this]

theorem lateUntil_cut (rs : List Receipt) (f : Nat) (F : Receipt) (hF : F ∈ rs) (h1 : F.cover = 1)
    (h2 : f < F.fseq) :
    ∃ G ∈ rs, G.cover = 1 ∧ f < G.fseq ∧ lateUntil rs f = dayBefore G.cfrom ∧
      ∀ H ∈ rs, H.cover = 1 → f < H.fseq → G.cfrom ≤ H.cfrom := by
  have hmem : F.cfrom ∈ (rs.filter fun a => a.cover == 1 && f < a.fseq).map (·.cfrom) :=
    List.mem_map.mpr ⟨F, List.mem_filter.mpr ⟨hF, by simp [h1, h2]⟩, rfl⟩
  obtain ⟨c, hc⟩ := Option.isSome_iff_exists.mp (List.isSome_min?_of_mem hmem)
  obtain ⟨hc1, hc2⟩ := List.min?_eq_some_iff.mp hc
  obtain ⟨G, hG1, rfl⟩ := List.mem_map.mp hc1
  obtain ⟨hGm, hGp⟩ := List.mem_filter.mp hG1
  simp only [Bool.and_eq_true, beq_iff_eq, decide_eq_true_eq] at hGp
  refine ⟨G, hGm, hGp.1, hGp.2, by simp [lateUntil, hc], fun H hH hhc hf => hc2 _ ?_⟩
  exact List.mem_map.mpr ⟨H, List.mem_filter.mpr ⟨hH, by simp [hhc, hf]⟩, rfl⟩

/-- A late row never speaks for a date that a newer full file of its source states: a date at or after that
    file's `cfrom` (a real date, so not `0`). -/
theorem lateUntil_lt (rs : List Receipt) (f D : Nat) (F : Receipt) (hF : F ∈ rs) (h1 : F.cover = 1)
    (h2 : f < F.fseq) (hD : F.cfrom ≤ D) (hD0 : 0 < D) : lateUntil rs f < D := by
  obtain ⟨G, _, _, _, hu, hm⟩ := lateUntil_cut rs f F hF h1 h2
  have hGF := hm F hF h1 h2
  rw [hu]
  by_cases h0 : G.cfrom = 0
  · simp [h0, dayBefore, hD0]
  · have := dayBefore_lt h0
    omega

/-- Full-file absence ends statements only from a full receipt that left the source usable: no `DROP`, no
    `REUSED`, and no row of the file whose subject could not be read (§3.3). -/
def endsAllowed (st : State) (n : Nat) (r : Receipt) (subjectless : Bool) : Bool :=
  r.cover == 1 && !subjectless && !st.dropped.contains n && !st.reused.contains r.src

theorem no_ends_when_stale (st : State) (n : Nat) (r : Receipt) (sl : Bool)
    (h : n ∈ st.dropped ∨ r.src ∈ st.reused) : endsAllowed st n r sl = false := by
  rcases h with h | h <;> simp [endsAllowed, h]

/-! ## Golden vectors and a scripted run

    The bytes below were written by the independent Python twin (`app/right_rail_fact_registry.py`); this file
    checks them against its own encoder, and `tests/test_fact_registry.py` reads the same table and the same
    expected lines. -/

def e1 : RegEntry :=
  { src := 1, cls := 2, origin := 7, kinds := 6, gapless := 0, maxage := 90, drop := 10, oneper := 1,
    scope := ident 21 "MEDICAID", name := ident 31 "STATE ELIGIBILITY", fseqRule := 1, full := 1,
    cfromRule := 0, ids := [(1, [10, 11]), (2, [12])] }

def e2 : RegEntry :=
  { src := 2, cls := 3, origin := 8, kinds := 32, gapless := 1, maxage := 7, drop := 0, oneper := 0,
    scope := ident 21 "", name := ident 31 "SECOND SOURCE", fseqRule := 2, full := 0, cfromRule := 0,
    ids := [(5, [20])] }

def e3 : RegEntry :=
  { src := 3, cls := 1, origin := 9, kinds := 4, gapless := 0, maxage := 90, drop := 50, oneper := 0,
    scope := ident 21 "MEDICAID", name := ident 31 "THIRD SOURCE", fseqRule := 1, full := 1, cfromRule := 1,
    ids := [(2, [1, 2, 3, 65535])] }

/-- The widest entry: every kind 1 to 63, every number at its top. -/
def e4 : RegEntry :=
  { src := 65535, cls := 5, origin := 65535, kinds := 18446744073709551614, gapless := 1, maxage := 65535,
    drop := 50, oneper := 1, scope := ident 21 "PPPPPPPPPPPPPPPPPPPP", name := ident 31 "NNNNNNNNNNNNNNNNNNNNNNNNNNNNNN",
    fseqRule := 2, full := 1, cfromRule := 1, ids := (List.range 63).map fun i => (i + 1, [65535]) }

def goldenEntries : List (String × RegEntry × String) :=
  [("e1", e1, "01000207000600000000000000005a000a01084d4544494341494400000000000000000000000011535441544520454c49474942494c495459000000000000000000000000000101000201020a000b0002010c00"), ("e2", e2, "0200030800200000000000000001070000000000000000000000000000000000000000000000000d5345434f4e4420534f5552434500000000000000000000000000000000000200000105011400"), ("e3", e3, "03000109000400000000000000005a003200084d454449434149440000000000000000000000000c544849524420534f55524345000000000000000000000000000000000000010101010204010002000300ffff"), ("e4", e4, "ffff05fffffeffffffffffffff01ffff32011450505050505050505050505050505050505050501e4e4e4e4e4e4e4e4e4e4e4e4e4e4e4e4e4e4e4e4e4e4e4e4e4e4e4e4e4e4e0201013f0101ffff0201ffff0301ffff0401ffff0501ffff0601ffff0701ffff0801ffff0901ffff0a01ffff0b01ffff0c01ffff0d01ffff0e01ffff0f01ffff1001ffff1101ffff1201ffff1301ffff1401ffff1501ffff1601ffff1701ffff1801ffff1901ffff1a01ffff1b01ffff1c01ffff1d01ffff1e01ffff1f01ffff2001ffff2101ffff2201ffff2301ffff2401ffff2501ffff2601ffff2701ffff2801ffff2901ffff2a01ffff2b01ffff2c01ffff2d01ffff2e01ffff2f01ffff3001ffff3101ffff3201ffff3301ffff3401ffff3501ffff3601ffff3701ffff3801ffff3901ffff3a01ffff3b01ffff3c01ffff3d01ffff3e01ffff3f01ffff")]

def goldenEntriesOk : Bool :=
  goldenEntries.all fun (_, e, h) => e.ok && hexBytes h == e.enc && (RegEntry.dec (hexBytes h)).map (·.1) == some e

#guard goldenEntriesOk

/-- A receipt for the script: `cfrom` is given, the file is 64 bytes from `tag`. -/
def mkRcpt (src cover asof cfrom fseq tag rows frows : Nat) (reader : Nat := 1) (reread : Nat := 0)
    (inScope : Nat := 0) : Receipt :=
  { src := src, cover := cover, kb := 0, asof := asof, cfrom := cfrom, fseq := fseq, file := pat 64 tag,
    sender := ident 21 "SENDER", channel := 1, key := 1, reader := reader, reread := reread, rows := rows,
    admitted := rows, same := 0, quar := 0, scope := ident 21 (if cover == 1 || inScope == 1 then "MEDICAID" else ""),
    frows := frows }

-- `cfrom` need not rise with `fseq`: a newer full file that states from an earlier date cuts a late row there.
#guard lateUntil [mkRcpt 1 1 20260301 20260301 20 1 0 0, mkRcpt 1 1 20260215 20260215 30 2 0 0] 10 == 20260214

-- A gap at the next number is found at once, whatever the size of the range.
#guard gapAt [mkRcpt 2 2 20260101 0 5 1 0 0] 5 9223372036854775807 &&
  !gapAt [mkRcpt 2 2 20260101 0 6 1 0 0, mkRcpt 2 2 20260101 0 7 2 0 0] 5 8

-- A late row speaks only before the least `cfrom` above it, not the `cfrom` of the next `fseq`.
#guard lateUntil [mkRcpt 1 1 20260301 20260301 30 1 0 0, mkRcpt 1 1 20260201 20260201 40 2 0 0] 10 == 20260131

inductive Step where
  | adm (r : Receipt) (k : Nat)
  | frame (prev today : Nat) (r : Receipt) (k : Nat)
  | stale (src today : Nat)
  | cut (src f : Nat)
  | reuse (src : Nat)
  | drop (n : Nat)

def runStep (reg : Registry) : State × List String → Step → State × List String
  | (st, out), .adm r k =>
    let a := admit reg st st.recs.length r k
    (a.2, out ++ [a.1.show])
  | (st, out), .frame p t r k =>
    let a := admitFrame reg st p t st.recs.length r k
    (a.2, out ++ [a.1.show])
  | (st, out), .stale src t =>
    (st, out ++ [match lookup reg src with
      | none => "unregistered"
      | some e => match staleCause e st t with
        | none => "fresh"
        | some c => c.name])
  | (st, out), .cut src f => (st, out ++ [toString (lateUntil (rcptsOf st.recs src) f)])
  | (st, out), .reuse src => (st.confirmReuse src, out)
  | (st, out), .drop n => (st.confirmDrop n, out)

def script : List Step :=
  [.stale 2 20260101, .adm (mkRcpt 1 1 20260101 20260101 20260101000000100 1 1000 1000) 0, .stale 1 20260401,
   .stale 1 20260402, .stale 1 20251231, .adm (mkRcpt 2 2 20260101 0 5 1 0 0) 0,
   .adm (mkRcpt 1 2 20260101 0 20260101000000100 2 0 0) 0, .stale 1 20260401, .reuse 1, .stale 1 20260401,
   .adm (mkRcpt 1 1 20260301 20260301 20260101000000300 3 990 1000) 1000, .adm (mkRcpt 1 2 20260201 0 20260101000000200 4 0 0) 0,
   .cut 1 20260101000000200, .cut 1 20260101000000400, .cut 1 20260101000000100, .adm (mkRcpt 1 1 20260401 20260401 20260101000000400 5 500 500) 1000,
   .cut 1 20260101000000300, .stale 1 20260405, .drop 3, .stale 1 20260405,
   .adm (mkRcpt 3 1 20260301 0 20260101000000001 6 40 40) 100, .adm (mkRcpt 3 1 20260302 0 20260101000000002 7 50 50) 100, .cut 3 20260101000000001,
   .adm (mkRcpt 2 2 20260104 0 10 8 0 0) 0, .stale 2 20260105, .adm (mkRcpt 2 2 20260104 0 12 9 0 0) 0,
   .stale 2 20260105, .adm (mkRcpt 2 2 20260104 0 11 10 0 0) 0, .stale 2 20260105, .stale 2 20260103,
   .frame 20260105 20260104 (mkRcpt 2 2 20260105 0 13 11 0 0) 0,
   .frame 20260105 20260106 (mkRcpt 2 2 20260105 0 13 11 0 0) 0,
   .adm (mkRcpt 1 4 20260101 0 20260101000000100 1 0 0 2 0 1) 0, .adm (mkRcpt 1 4 20260101 0 20260101000000100 1 0 0 2 0 1) 0,
   .adm (mkRcpt 1 4 20260101 0 20260101000000100 1 0 0 3 6) 0, .adm (mkRcpt 1 2 20261301 0 20260101000000500 21 0 0) 0,
   .adm (mkRcpt 1 2 20260101 5 20260101000000500 22 0 0) 0, .adm (mkRcpt 9 2 20260101 0 500 23 0 0) 0,
   .adm (mkRcpt 2 1 20260101 20260101 500 24 0 0) 0,
   .adm (mkRcpt 1 2 20260101 0 9223372036854775807 25 0 0) 0,
   .adm (mkRcpt 1 2 20260101 0 20260102000000001 26 0 0) 0,
   .adm (mkRcpt 1 2 20260101 0 20261301000000001 27 0 0) 0,
   .frame 20260105 20260106 (mkRcpt 2 2 20260107 0 14 28 0 0) 0,
   .frame 20260101 20260101 (mkRcpt 1 2 20260101 0 20260102000000009 29 0 0) 0,
   .adm (mkRcpt 1 4 20260101 0 20260101000000100 99 0 0 3 0 1) 0,
   .adm (mkRcpt 1 4 20260102 0 20260101000000100 1 0 0 3 0 1) 0,
   .adm (mkRcpt 1 4 20260101 0 20260101000000100 1 0 0 3 0) 0,
   .adm (mkRcpt 1 1 20260215 20260215 20260101000000600 30 500 500) 1000, .cut 1 20260101000000100,
   .cut 1 20260101000000300, .cut 1 20260101000000400, .cut 1 20260101000000500, .cut 1 20260101000000600]

def expected : List String :=
  ["noReceipt", "admitted 0 0", "fresh", "age", "future", "already 0", "refused reused", "reused", "fresh",
   "admitted 1 0", "admitted 2 0", "20260228", "99991231", "20260228", "admitted 3 1", "20260331", "drop",
   "fresh", "admitted 4 1", "admitted 5 0", "0", "admitted 6 0", "fresh", "admitted 7 0", "gap",
   "admitted 8 0", "fresh", "future", "refused day", "admitted 9 0", "admitted 10 0", "already 10",
   "refused reread", "refused record", "refused record", "refused unregistered", "refused record",
   "refused record", "admitted 11 0", "refused record", "refused record", "refused record", "refused reread",
   "refused reread", "refused reread", "admitted 12 1", "20260214", "20260214",
   "20260214", "20260214", "99991231"]

#guard (script.foldl (runStep [e1, e2, e3]) ({}, [])).2 == expected

end BlindLedger.Gate.FactRegistry
