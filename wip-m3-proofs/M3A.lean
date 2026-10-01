import BlindLedger.Financial.Payment.Rev12
open BlindLedger.Financial BlindLedger.Financial.Payment BlindLedger.Financial.CorrectionTransition
namespace BlindLedger.Financial.Payment.Rev12

/-! ## Contributions: the insertion sort is a sort -/

def cb (x y : EvalContribution) : Bool :=
  contributionKeyBefore x.time x.amountCents x.identity y.time y.amountCents y.identity

theorem cb_iff {x y : EvalContribution} : cb x y = true ↔
    x.time < y.time ∨ (x.time = y.time ∧ (x.amountCents < y.amountCents ∨
      (x.amountCents = y.amountCents ∧ x.identity < y.identity))) := by
  simp [cb, contributionKeyBefore]

theorem cb_trans {x y z : EvalContribution} (h1 : cb x y = true) (h2 : cb y z = true) :
    cb x z = true := by
  rw [cb_iff] at *
  rcases h1 with h1 | ⟨e1, h1 | ⟨e1', h1⟩⟩ <;> rcases h2 with h2 | ⟨e2, h2 | ⟨e2', h2⟩⟩
  · exact .inl (by omega)
  · exact .inl (by omega)
  · exact .inl (by omega)
  · exact .inl (by omega)
  · exact .inr ⟨by omega, .inl (by omega)⟩
  · exact .inr ⟨by omega, .inl (by omega)⟩
  · exact .inl (by omega)
  · exact .inr ⟨by omega, .inl (by omega)⟩
  · exact .inr ⟨by omega, .inr ⟨by omega, String.lt_trans h1 h2⟩⟩

theorem cb_asymm {x y : EvalContribution} (h : cb x y = true) : cb y x = false := by
  cases h' : cb y x
  · rfl
  · have := cb_trans h h'
    rw [cb_iff] at this
    rcases this with h | ⟨-, h | ⟨-, h⟩⟩
    · omega
    · omega
    · exact absurd h (String.lt_irrefl _)

theorem cb_conn {x y : EvalContribution} (h1 : cb x y = false) (h2 : cb y x = false) : x = y := by
  rw [← Bool.not_eq_true, cb_iff] at h1 h2
  obtain ⟨t, i, a⟩ := x
  obtain ⟨t', i', a'⟩ := y
  simp only at h1 h2
  have ht : t = t' := by omega
  subst ht
  have ha : a = a' := by omega
  subst ha
  have hi : i = i' := String.le_antisymm (String.not_lt.1 (fun h => h2 (.inr ⟨rfl, .inr ⟨rfl, h⟩⟩)))
    (String.not_lt.1 (fun h => h1 (.inr ⟨rfl, .inr ⟨rfl, h⟩⟩)))
  rw [hi]

theorem ins_cons (y a : EvalContribution) (l : List EvalContribution) :
    evalInsertContribution y (a :: l) = if cb y a = true then y :: a :: l else a :: evalInsertContribution y l := rfl

def Sorted (l : List EvalContribution) : Prop := l.Pairwise fun a b => cb b a = false

theorem insert_sorted (y : EvalContribution) :
    ∀ {l : List EvalContribution}, Sorted l → Sorted (evalInsertContribution y l)
  | [], _ => by simp [evalInsertContribution, Sorted]
  | a :: l, h => by
    rw [ins_cons]
    obtain ⟨ha, hl⟩ := List.pairwise_cons.1 h
    by_cases hc : cb y a = true
    · rw [if_pos hc]
      refine List.pairwise_cons.2 ⟨fun z hz => ?_, h⟩
      rcases List.mem_cons.1 hz with rfl | hz
      · exact cb_asymm hc
      · cases hzy : cb z y
        · rfl
        · exact absurd (cb_trans hzy hc) (by rw [ha z hz]; simp)
    · rw [if_neg hc]
      refine List.pairwise_cons.2 ⟨fun z hz => ?_, insert_sorted y hl⟩
      rcases (List.mem_cons.1 ((evalInsertContribution_perm y l).mem_iff.1 hz)) with rfl | hz
      · simpa using hc
      · exact ha z hz

theorem sort_sorted : ∀ l, Sorted (evalSortContributions l)
  | [] => by simp [evalSortContributions, Sorted]
  | a :: l => insert_sorted a (sort_sorted l)

theorem sorted_eq {l₁ l₂ : List EvalContribution} (h : l₁.Perm l₂) (s₁ : Sorted l₁) (s₂ : Sorted l₂) :
    l₁ = l₂ :=
  h.eq_of_pairwise (fun _ _ _ _ h1 h2 => cb_conn h2 h1) s₁ s₂

theorem sort_congr {l₁ l₂ : List EvalContribution} (h : l₁.Perm l₂) :
    evalSortContributions l₁ = evalSortContributions l₂ :=
  sorted_eq ((evalSortContributions_perm _).trans (h.trans (evalSortContributions_perm _).symm))
    (sort_sorted _) (sort_sorted _)

theorem sort_erase (x : EvalContribution) {l : List EvalContribution} (h : x ∈ l) :
    (evalSortContributions l).erase x = evalSortContributions (l.erase x) := by
  have p : l.Perm (x :: l.erase x) := List.perm_cons_erase h
  have e : evalSortContributions l = evalInsertContribution x (evalSortContributions (l.erase x)) := by
    rw [sort_congr p]; rfl
  rw [e]
  refine sorted_eq ?_ ?_ (sort_sorted _)
  · exact ((evalInsertContribution_perm x _).erase x).trans (by simp)
  · exact (insert_sorted x (sort_sorted _)).sublist List.erase_sublist

end BlindLedger.Financial.Payment.Rev12
