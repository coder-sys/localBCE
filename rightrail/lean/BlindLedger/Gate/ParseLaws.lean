import BlindLedger.Gate.Spec

namespace BlindLedger.Gate.ParseLaws

open BlindLedger.Gate

/-! Run laws of the gate parser: each combinator consumes exactly the canonical bytes it accepts. -/

theorem bind_run {α β : Type} {p : P α} {f : α → P β} {b r : Bytes} {y : β}
    (h : (p >>= f).run b = some (y, r)) : ∃ x r1, p.run b = some (x, r1) ∧ (f x).run r1 = some (y, r) := by
  rw [StateT.run_bind] at h
  cases hp : p.run b with
  | none => simp [hp] at h
  | some q => rw [hp] at h; exact ⟨q.1, q.2, rfl, h⟩

theorem pure_run {α : Type} {x y : α} {b r : Bytes} (h : (pure x : P α).run b = some (y, r)) : x = y ∧ b = r := by
  cases h; exact ⟨rfl, rfl⟩

theorem take_run {n : Nat} {b x r : Bytes} (h : (take n).run b = some (x, r)) : x ++ r = b ∧ x.length = n := by
  change (if n ≤ b.length then some (b.take n, b.drop n) else none) = some (x, r) at h
  split at h
  · cases h
    exact ⟨List.take_append_drop n b, by rw [List.length_take]; omega⟩
  · simp at h

theorem many_run {α : Type} {p : P α} {e : α → Bytes} {Q : α → Prop}
    (hp : ∀ {b x r}, p.run b = some (x, r) → e x ++ r = b ∧ Q x) :
    ∀ k {b xs r}, (many p k).run b = some (xs, r) → xs.flatMap e ++ r = b ∧ xs.length = k ∧ ∀ x ∈ xs, Q x
  | 0, b, xs, r, h => by
    simp only [many] at h
    obtain ⟨rfl, rfl⟩ := pure_run h
    exact ⟨rfl, rfl, by simp⟩
  | k + 1, b, xs, r, h => by
    simp only [many] at h
    obtain ⟨x, r1, h1, h⟩ := bind_run h
    obtain ⟨ys, r2, h2, h⟩ := bind_run h
    obtain ⟨rfl, rfl⟩ := pure_run h
    obtain ⟨he, hq⟩ := hp h1
    obtain ⟨hes, hl, hqs⟩ := many_run hp k h2
    refine ⟨?_, by simp [hl], List.forall_mem_cons.2 ⟨hq, hqs⟩⟩
    rw [List.flatMap_cons, List.append_assoc, hes, he]

end BlindLedger.Gate.ParseLaws
