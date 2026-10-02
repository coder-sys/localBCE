import BlindLedger.Sha3
import BlindLedger.Sha3Fast

namespace BlindLedger.Semantic
open Fast

open Lean in
macro "priv%" n:ident : term =>
  return mkIdent (Name.mkNum `_private.BlindLedger.Sha3 0 ++ `BlindLedger.Semantic ++ n.getId)
open Lean in
macro "unfold_priv " n:ident : tactic =>
  `(tactic| unfold $(mkIdent (Name.mkNum `_private.BlindLedger.Sha3 0 ++ `BlindLedger.Semantic ++ n.getId)):ident)

def ofSt (s : St) : Array UInt64 := #[s.a0, s.a1, s.a2, s.a3, s.a4, s.a5, s.a6, s.a7, s.a8, s.a9, s.a10, s.a11, s.a12, s.a13, s.a14, s.a15, s.a16, s.a17, s.a18, s.a19, s.a20, s.a21, s.a22, s.a23, s.a24]

theorem rep25 : Array.replicate 25 (0 : UInt64) = #[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0] := rfl

theorem range5 : Array.range 5 = #[0, 1, 2, 3, 4] := rfl

theorem round_eq (s : St) (r : Nat) : (priv% round) (ofSt s) r = ofSt (Fast.round s ((priv% roundConstants)[r]!)) := by
  unfold_priv round
  unfold_priv rho
  unfold_priv rotl
  simp [rep25, range5, ofSt, Fast.round, Fast.rl, Id.run, Std.Legacy.Range.forIn_eq_forIn_range', Std.Legacy.Range.size, List.range']

theorem rc_eq : Fast.roundConstants = priv% roundConstants := rfl

theorem foldl_round (l : List Nat) (s : St) :
    l.foldl (priv% round) (ofSt s) = ofSt (l.foldl (fun st r => Fast.round st (Fast.roundConstants[r]!)) s) := by
  induction l generalizing s with
  | nil => rfl
  | cons r l ih => simp only [List.foldl_cons, rc_eq, round_eq, ih]

theorem keccakF_eq (s : St) : (priv% keccakF) (ofSt s) = ofSt (Fast.keccakF s) := by
  unfold_priv keccakF
  unfold Fast.keccakF
  simp only [Id.run, Std.Legacy.Range.forIn_eq_forIn_range', Std.Legacy.Range.size, Nat.sub_zero, Nat.add_sub_cancel, Nat.div_one,
    bind_pure, List.forIn_pure_yield_eq_foldl, List.range_eq_range']
  exact foldl_round _ s


theorem foldl_rel {α β γ : Type} (R : β → γ → Prop) (l : List α) (f : β → α → β) (g : γ → α → γ) (a : β) (c : γ)
    (h : R a c) (hs : ∀ x ∈ l, ∀ a c, R a c → R (f a x) (g c x)) : R (l.foldl f a) (l.foldl g c) := by
  induction l generalizing a c with
  | nil => exact h
  | cons x l ih => exact ih _ _ (hs x (by simp) a c h) (fun y hy => hs y (by simp [hy]))

/-- The slow sponge's lane load: eight bytes of `P` from `o`, little-endian. -/
def lq (P : ByteArray) (o : Nat) : UInt64 :=
  (List.range' 0 8).foldl (fun v j => v ||| (P.get! (o + j)).toUInt64 <<< UInt64.ofNat (8 * j)) 0

theorem lq_eq (P : ByteArray) (f : Nat → UInt8) (o : Nat) (h : ∀ j, j < 8 → P.get! (o + j) = f (o + j)) :
    lq P o = loadF f o := by
  have h0 : P.get! o = f o := h 0 (by omega)
  have h1 := h 1 (by omega)
  have h2 := h 2 (by omega)
  have h3 := h 3 (by omega)
  have h4 := h 4 (by omega)
  have h5 := h 5 (by omega)
  have h6 := h 6 (by omega)
  have h7 := h 7 (by omega)
  simp [lq, loadF, List.range', h0, h1, h2, h3, h4, h5, h6, h7]

theorem absorb_set (nl : Nat) (hn : nl = 9 ∨ nl = 17 ∨ nl = 21) (s : St) (f : Nat → UInt8) (P : ByteArray) (o : Nat)
    (h : ∀ j, o ≤ j → j < o + 8 * nl → P.get! j = f j) :
    (List.range' 0 nl).foldl (fun b i => b.set! i (b[i]! ^^^ lq P (o + 8 * i))) (ofSt s) = ofSt (absorb s f o nl) := by
  have e : (List.range' 0 nl).foldl (fun b i => b.set! i (b[i]! ^^^ lq P (o + 8 * i))) (ofSt s)
      = (List.range' 0 nl).foldl (fun b i => b.set! i (b[i]! ^^^ loadF f (o + 8 * i))) (ofSt s) :=
    foldl_rel (· = ·) _ _ _ _ _ rfl (fun i hi a c hac => by
      subst hac
      have hi' := List.mem_range'_1.1 hi
      rw [lq_eq P f (o + 8 * i) fun j hj => h _ (by omega) (by omega)])
  rw [e]
  rcases hn with rfl | rfl | rfl <;> simp [List.range', ofSt, absorb]

theorem get!_eq (b : ByteArray) (i : Nat) : b.get! i = b[i]! := by
  cases b; first | rfl | (simp [ByteArray.get!, getElem!_def]; rfl)

theorem zeros_size (k : Nat) : (ByteArray.mk (Array.replicate k 0)).size = k := by simp [ByteArray.size]

theorem getElem!_pad (data : ByteArray) (k i : Nat) (hi : i < data.size + k) :
    (data ++ ByteArray.mk (Array.replicate k 0))[i]! = if i < data.size then data[i]! else 0 := by
  have h1 : i < (data ++ ByteArray.mk (Array.replicate k 0)).size := by simp [zeros_size]; omega
  rw [getElem!_pos _ i h1]
  by_cases h : i < data.size
  · rw [if_pos h, getElem!_pos _ i h, ByteArray.getElem_append_left h]
  · rw [if_neg h, ByteArray.getElem_append_right (by omega)]
    simp [ByteArray.getElem_eq_getElem_data]

theorem pad_get (data : ByteArray) (suffix : UInt8) (total : Nat) (hs : data.size < total) (j : Nat) (hj : j < total) :
    (let p := (data ++ ByteArray.mk (Array.replicate (total - data.size) 0)).set! data.size suffix
     p.set! (total - 1) (p.get! (total - 1) ||| 0x80)).get! j = padByte data suffix total j := by
  simp only [get!_eq, padByte]
  have hsz : (data ++ ByteArray.mk (Array.replicate (total - data.size) 0)).size = total := by
    simp [zeros_size]; omega
  rw [ByteArray.getElem!_set! _ _ _ _ (by simp [hsz]; omega)]
  rw [ByteArray.getElem!_set! _ _ _ _ (by simp [hsz]; omega)]
  rw [ByteArray.getElem!_set! _ _ _ _ (by simp [hsz]; omega)]
  rw [getElem!_pad _ _ (total - 1) (by omega), getElem!_pad _ _ j (by omega)]
  repeat' split
  all_goals first | rfl | (exfalso; omega) | simp

/-- One slow absorb block: xor in the lanes of block `blk` of `P`, then permute. -/
def slowBlk (rate : Nat) (P : ByteArray) (b : Array UInt64) (blk : Nat) : Array UInt64 :=
  (priv% keccakF) ((List.range' 0 (rate / 8)).foldl (fun b i => b.set! i (b[i]! ^^^ lq P (blk * rate + 8 * i))) b)

def fastBlk (rate : Nat) (f : Nat → UInt8) (s : St) (blk : Nat) : St :=
  Fast.keccakF (absorb s f (blk * rate) (rate / 8))

theorem absorb_blk (rate : Nat) (hr : rate = 72 ∨ rate = 136 ∨ rate = 168) (s : St) (f : Nat → UInt8) (P : ByteArray)
    (blk : Nat) (h : ∀ j, blk * rate ≤ j → j < blk * rate + rate → P.get! j = f j) :
    slowBlk rate P (ofSt s) blk = ofSt (fastBlk rate f s blk) := by
  have h8 : 8 * (rate / 8) = rate := by omega
  unfold slowBlk fastBlk
  rw [absorb_set (rate / 8) (by omega) s f P (blk * rate) (fun j h1 h2 => h j h1 (by omega))]
  exact keccakF_eq _

theorem zero_eq : Array.replicate 25 (0 : UInt64) = ofSt Fast.zero := rfl

theorem absorb_phase (rate : Nat) (hr : rate = 72 ∨ rate = 136 ∨ rate = 168) (data : ByteArray) (suffix : UInt8)
    (P : ByteArray) (F : Nat) (hF : F * rate ≤ data.size) (hF2 : data.size < (F + 1) * rate)
    (hP : ∀ j, j < (F + 1) * rate → P.get! j = padByte data suffix ((F + 1) * rate) j) :
    (List.range' 0 (F + 1)).foldl (slowBlk rate P) (Array.replicate 25 0)
      = ofSt (fastBlk rate (padByte data suffix ((F + 1) * rate))
          ((List.range' 0 F).foldl (fastBlk rate (data.get! ·)) Fast.zero) F) := by
  have e : (F + 1) * rate = F * rate + rate := Nat.succ_mul ..
  have hd : ∀ j, j < F * rate → P.get! j = data.get! j := fun j hj => by
    rw [hP j (by omega)]
    have h1 : j < data.size := by omega
    have h2 : j ≠ (F + 1) * rate - 1 := by omega
    simp [padByte, h1, h2]
  have pre : (List.range' 0 F).foldl (slowBlk rate P) (Array.replicate 25 0)
      = ofSt ((List.range' 0 F).foldl (fastBlk rate (data.get! ·)) Fast.zero) :=
    foldl_rel (fun a c => a = ofSt c) _ (slowBlk rate P) (fastBlk rate (data.get! ·)) (Array.replicate 25 0) Fast.zero
      zero_eq (fun x hx a c hac => by
        subst hac
        have hx' := List.mem_range'_1.1 hx
        have : (x + 1) * rate ≤ F * rate := Nat.mul_le_mul_right _ (by omega)
        rw [Nat.succ_mul] at this
        exact absorb_blk rate hr c (data.get! ·) P x fun j h1 h2 => hd j (by omega))
  rw [List.range'_concat, List.foldl_append, pre]
  simp only [List.foldl_cons, List.foldl_nil, Nat.zero_add, Nat.one_mul]
  exact absorb_blk rate hr _ (padByte data suffix ((F + 1) * rate)) P F fun j h1 h2 => hP j (by omega)

theorem lane_ofSt (s : St) (i : Nat) (h : i < 25) : (ofSt s)[i]! = lane s i := by
  match i, h with
  | 0, _ | 1, _ | 2, _ | 3, _ | 4, _ | 5, _ | 6, _ | 7, _ | 8, _ | 9, _ | 10, _ | 11, _ | 12, _ | 13, _ | 14, _ | 15, _ | 16, _ | 17, _ | 18, _ | 19, _ | 20, _ | 21, _ | 22, _ | 23, _ | 24, _ => rfl
  | _ + 25, h => omega

/-- Squeeze one block of `rate` bytes from lanes `K`, stopping at `n` bytes. -/
def sqOut (n rate : Nat) (K : Array UInt64) (o : ByteArray) : ByteArray :=
  (List.range' 0 rate).foldl (fun b a => if b.size < n then b.push (K[a / 8]! >>> UInt64.ofNat (8 * (a % 8))).toUInt8 else b) o

def sqOutF (n rate : Nat) (s : St) (o : ByteArray) : ByteArray :=
  (List.range' 0 rate).foldl (fun b a => if b.size < n then b.push (lane s (a / 8) >>> UInt64.ofNat (8 * (a % 8))).toUInt8 else b) o

theorem sqOut_eq (n rate : Nat) (hr : rate ≤ 168) (s : St) (o : ByteArray) : sqOut n rate (ofSt s) o = sqOutF n rate s o :=
  foldl_rel (· = ·) _ _ _ _ _ rfl (fun a ha b c hbc => by
    subst hbc
    have := List.mem_range'_1.1 ha
    simp only [lane_ofSt s (a / 8) (by omega)])

def sqSlow (n rate : Nat) (b : Array UInt64 × ByteArray) (a : Nat) : Array UInt64 × ByteArray :=
  if a > 0 then ((priv% keccakF) b.fst, sqOut n rate ((priv% keccakF) b.fst) b.snd) else (b.fst, sqOut n rate b.fst b.snd)

def sqFast (n rate : Nat) (b : St × ByteArray) (a : Nat) : St × ByteArray :=
  if a > 0 then (Fast.keccakF b.fst, sqOutF n rate (Fast.keccakF b.fst) b.snd) else (b.fst, sqOutF n rate b.fst b.snd)

theorem sq_step (n rate : Nat) (hr : rate ≤ 168) (a : Nat) (b : Array UInt64 × ByteArray) (c : St × ByteArray)
    (h : b.1 = ofSt c.1 ∧ b.2 = c.2) : (sqSlow n rate b a).1 = ofSt (sqFast n rate c a).1 ∧ (sqSlow n rate b a).2 = (sqFast n rate c a).2 := by
  obtain ⟨h1, h2⟩ := h
  unfold sqSlow sqFast
  split
  · simp only [h1, h2, keccakF_eq, sqOut_eq n rate hr, and_self]
  · simp only [h1, h2, sqOut_eq n rate hr, and_self]

theorem ite_yield {β : Type} (c : Prop) [Decidable c] (x y : β) :
    (if c then (pure (ForInStep.yield x) : Id (ForInStep β)) else pure (ForInStep.yield y)) = pure (ForInStep.yield (if c then x else y)) := by
  split <;> rfl

theorem sponge_eq (rate : Nat) (hr : rate = 72 ∨ rate = 136 ∨ rate = 168) (suffix : UInt8) (data : ByteArray) (n : Nat) :
    (priv% sponge) rate suffix data n = Fast.sponge rate suffix data n := by
  have hpos : 0 < rate := by omega
  have h1 : data.size / rate * rate ≤ data.size := Nat.div_mul_le_self ..
  have h2 : data.size < (data.size / rate + 1) * rate := by
    have := Nat.lt_div_mul_add (a := data.size) hpos
    rw [Nat.succ_mul]; omega
  unfold_priv sponge
  unfold Fast.sponge
  simp only [Id.run, Std.Legacy.Range.forIn_eq_forIn_range', Std.Legacy.Range.size, Nat.sub_zero, Nat.add_sub_cancel, Nat.div_one,
    pure_bind, ite_yield, List.forIn_pure_yield_eq_foldl, List.range_eq_range']
  rw [Nat.mul_div_cancel _ hpos]
  exact (foldl_rel (fun (a : Array UInt64 × ByteArray) (c : St × ByteArray) => a.1 = ofSt c.1 ∧ a.2 = c.2) _
    (sqSlow n rate) (sqFast n rate) _ _
    ⟨absorb_phase rate hr data suffix _ _ h1 h2 (fun j hj => pad_get data suffix _ h2 j hj), rfl⟩
    (fun a _ b c h => sq_step n rate (by omega) a b c h)).2

theorem sha3_512_eq : sha3_512 = sha3_512Fast := funext fun d => sponge_eq 72 (by omega) _ d 64
theorem shake128_eq : shake128 = shake128Fast := funext fun d => funext fun n => sponge_eq 168 (by omega) _ d n
theorem shake256_eq : shake256 = shake256Fast := funext fun d => funext fun n => sponge_eq 136 (by omega) _ d n

end BlindLedger.Semantic

/-- info: 'BlindLedger.Semantic.sha3_512_eq' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Semantic.sha3_512_eq
/-- info: 'BlindLedger.Semantic.shake128_eq' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Semantic.shake128_eq
/-- info: 'BlindLedger.Semantic.shake256_eq' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Semantic.shake256_eq
