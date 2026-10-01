import BlindLedger.Financial.Payment.Rev12
import M3S
open BlindLedger.Financial BlindLedger.Financial.Payment BlindLedger.Financial.CorrectionTransition
namespace BlindLedger.Financial.Payment.Rev12

theorem bind_now {i : FinancialInput} {t : Nat} {a : ActionRecord}
    (h : actionBindingWellFormed i a = true) (hle : i.evaluatedAt ≤ t) :
    actionBindingWellFormed { i with evaluatedAt := t } a = true := by
  unfold actionBindingWellFormed at h ⊢
  cases hd : a.determinationId with
  | none => rw [hd] at h; exact h
  | some id =>
    rw [hd] at h
    simp only at h ⊢
    cases hf : findDetermination i.determinations id with
    | none => rw [hf] at h; exact h
    | some x =>
      rw [hf] at h
      simp only [Bool.and_eq_true, decide_eq_true_eq] at h ⊢
      exact ⟨h.1, by have := h.2; omega⟩

theorem actWF_now {i : FinancialInput} {t : Nat} {a : ActionRecord}
    (h : actionWellFormed i a = true) (hle : i.evaluatedAt ≤ t) :
    actionWellFormed { i with evaluatedAt := t } a = true := by
  unfold actionWellFormed at h ⊢
  rw [Bool.and_eq_true] at h ⊢
  exact ⟨h.1, bind_now h.2 hle⟩

theorem detAct_now {i : FinancialInput} {t : Nat} {x : OffsetDetermination}
    (h : determinationActionWellFormed i x = true) (hle : i.evaluatedAt ≤ t) :
    determinationActionWellFormed { i with evaluatedAt := t } x = true := by
  simp only [determinationActionWellFormed, actionsForDetermination, Bool.and_eq_true, decide_eq_true_eq,
    List.all_eq_true] at h ⊢
  exact ⟨h.1, fun a ha => bind_now (h.2 a ha) hle⟩

theorem detWF_now {i : FinancialInput} {t : Nat} {x : OffsetDetermination}
    (h : determinationWellFormed i x = true) (hle : i.evaluatedAt ≤ t) :
    determinationWellFormed { i with evaluatedAt := t } x = true := by
  unfold determinationWellFormed at h ⊢
  rw [Bool.and_eq_true, Bool.and_eq_true] at h ⊢
  obtain ⟨⟨hP, hD⟩, hM⟩ := h
  refine ⟨⟨hP, ?_⟩, hM⟩
  simp only [decide_eq_true_eq] at hD ⊢
  omega

theorem wf_now {i : FinancialInput} {t : Nat} (h : financialInputWellFormed i = true)
    (hle : i.evaluatedAt ≤ t) (ht : t ≤ maxTime) :
    financialInputWellFormed { i with evaluatedAt := t } = true := by
  unfold financialInputWellFormed at h ⊢
  simp only [Bool.and_eq_true, decide_eq_true_eq, List.all_eq_true, and_assoc] at h ⊢
  obtain ⟨h1, h2, h3, h4, h5, h6, h7, h8, h9, h10, h11, h12, h13, h14, h15, h16, h17, h18, h19, h20, h21, h22, h23, h24, h25, h26, h27, h28, h29, h30, h31, h32, h33, h34, h35, h36, h37, h38, h39, h40, h41, h42, h43, h44, h45, h46, h47, h48, h49, h50, h51, h52, h53, h54, h55⟩ := h
  exact ⟨h1, h2, h3, h4, h5, h6, (by simp only [timeWellFormed, decide_eq_true_eq]; exact ht), h8, h9, h10, h11, h12, h13, h14, h15, h16, h17, h18, h19, h20, h21, h22, h23, h24, h25, h26, h27, h28, h29, h30, h31, h32, h33, h34, fun x hx => detWF_now (h35 x hx) hle, h36, h37, fun x hx => actWF_now (h38 x hx) hle, h39, h40, h41, h42, h43, h44, fun x hx => detAct_now (h45 x hx) hle, h46, h47, h48, fun x hx => Nat.le_trans (h49 x hx) hle, fun x hx => Nat.le_trans (h50 x hx) hle, h51, h52, h53, h54, h55⟩

end BlindLedger.Financial.Payment.Rev12
