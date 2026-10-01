import BlindLedger.Financial.Payment.Rev12
import M3T
open BlindLedger.Financial BlindLedger.Financial.Payment BlindLedger.Financial.CorrectionTransition
namespace BlindLedger.Financial.Payment.Rev12

theorem step_eval (L : Ledger) (c : Call) :
    (step L c).input.evaluatedAt = L.input.evaluatedAt ∨ (step L c).input.evaluatedAt = c.now := by
  rcases step_cases L c with ⟨k, w, post, res, ho, he⟩ | ⟨pid, e, post, ho, he⟩ | ⟨-, -, he⟩ <;> rw [he]
  · right; rw [(paymentTransition_mutated_post ho).1]; rfl
  · right; rw [(alias_shape ho).1]; rfl
  · left; rfl

theorem step_before_le (L : Ledger) (c : Call) :
    (step L c).input.beforeRevision ≤ L.input.beforeRevision + 1 := by
  rcases step_cases L c with ⟨k, w, post, res, ho, he⟩ | ⟨pid, e, post, ho, he⟩ | ⟨-, -, he⟩ <;> rw [he]
  · have hb : post.beforeRevision = L.input.beforeRevision := by
      rw [(paymentTransition_mutated_post ho).1]; rfl
    show post.beforeRevision + 1 ≤ _
    rw [hb]
    exact Nat.le_refl _
  · rw [(alias_shape ho).1]; exact Nat.le_succ _
  · exact Nat.le_succ _

theorem chain_fold_eq_full' (L : Ledger) (hL : ledgerWellFormed L) (calls : List Call)
    (hc : clocksOk L calls) (hR : L.input.beforeRevision + calls.length ≤ maxRevision)
    (vs : List PaymentView) (hv : ChainFaithful L calls vs)
    (hw : vs.all fun v => commandWellFormed v.command && v.expectedRevision.all (· < 2 ^ 63)) :
    vs.map (some ∘ stepView) =
      ((ledgers L calls).zip calls).map fun M => project (M.1.request M.2) (outcome M.1 M.2) := by
  induction calls generalizing L vs with
  | nil =>
    obtain ⟨hlen, -⟩ := hv
    have : vs = [] := List.length_eq_zero_iff.1 (by simpa using hlen)
    subst this; rfl
  | cons c cs ih =>
    obtain ⟨hlen, hv⟩ := hv
    cases vs with
    | nil => simp at hlen
    | cons v vs' =>
      have hFv : Faithful (L.request c) v := hv 0 L c v rfl rfl rfl
      simp only [List.all_cons, Bool.and_eq_true] at hw
      obtain ⟨⟨hcmd, hexp⟩, hw2⟩ := hw
      obtain ⟨-, -, -, -, -, -, -, -, -, hexp', hcmd'⟩ := faithful_unpack (r := L.request c) (v := v) rfl hFv
      have hpw := (List.pairwise_cons.1 hc.1).1 c.now (by simp)
      have hnow : c.now < 2 ^ 63 := by
        have := hc.2
        simp only [List.all_cons, Bool.and_eq_true, decide_eq_true_eq] at this
        exact this.1
      have hmax : c.now ≤ maxTime := by simp only [maxTime, maxCents]; omega
      have hrq : requestWellFormed (L.request c) = true := by
        simp only [requestWellFormed, Bool.and_eq_true]
        refine ⟨⟨⟨wf_now hL.1 hpw hmax, hL.2⟩, ?_⟩, ?_⟩
        · show commandWellFormed c.command = true
          have e : v.command = c.command := hcmd'
          rw [e] at hcmd; exact hcmd
        · show c.expectedRevision.all (· < 2 ^ 63) = true
          have e : v.expectedRevision = c.expectedRevision := hexp'
          rw [e] at hexp; exact hexp
      have head : some (stepView v) = project (L.request c) (outcome L c) :=
        stepView_eq' hrq rfl hFv
      show some (stepView v) :: vs'.map (some ∘ stepView) =
        project (L.request c) (outcome L c) :: ((ledgers (step L c) cs).zip cs).map _
      rw [head]
      cases cs with
      | nil =>
        have : vs' = [] := List.length_eq_zero_iff.1 (by simpa using hlen)
        subst this; rfl
      | cons c' cs' =>
        congr 1
        have hRs : L.input.beforeRevision + 1 < maxRevision := by
          simp only [List.length_cons] at hR; omega
        have hclk : clocksOk L [c] := ⟨by simp [List.pairwise_cons, hpw], by simpa using hnow⟩
        refine ih (step L c) (step_wellFormed L hL c hclk hRs) ?_ ?_ vs' ?_ hw2
        · obtain ⟨hp1, hp2⟩ := hc
          simp only [List.all_cons, Bool.and_eq_true] at hp2
          refine ⟨?_, by simp only [List.all_cons, Bool.and_eq_true]; exact hp2.2⟩
          have h1 := List.pairwise_cons.1 hp1
          have h2 := List.pairwise_cons.1 h1.2
          refine List.pairwise_cons.2 ⟨fun b hb => ?_, h2.2⟩
          rcases step_eval L c with he | he <;> rw [he]
          · exact h1.1 b (List.mem_cons_of_mem _ hb)
          · exact h2.1 b hb
        · have := step_before_le L c
          simp only [List.length_cons] at hR ⊢; omega
        · refine ⟨by simpa using hlen, fun n M c'' v'' hM hc'' hv'' => hv (n + 1) M c'' v'' hM hc'' hv''⟩

end BlindLedger.Financial.Payment.Rev12
