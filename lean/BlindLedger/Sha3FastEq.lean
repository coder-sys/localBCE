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

end BlindLedger.Semantic
