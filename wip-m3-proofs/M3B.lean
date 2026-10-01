import BlindLedger.Financial.Payment.Rev12
import M3A
open BlindLedger.Financial BlindLedger.Financial.Payment BlindLedger.Financial.CorrectionTransition
namespace BlindLedger.Financial.Payment.Rev12

/-! ## Insertion, canonical lists -/

theorem insertBy_perm {α} (key : α → String) (row : α) :
    ∀ l : List α, (insertBy key row l).Perm (row :: l)
  | [] => .refl _
  | x :: xs => by
    unfold insertBy
    split
    · exact .refl _
    · exact ((insertBy_perm key row xs).cons x).trans (.swap row x xs)

theorem str_trich (a b : String) : a < b ∨ a = b ∨ b < a := by
  by_cases h1 : a < b
  · exact Or.inl h1
  · by_cases h2 : b < a
    · exact Or.inr (Or.inr h2)
    · exact Or.inr (Or.inl (String.le_antisymm (String.not_lt.1 h2) (String.not_lt.1 h1)))

theorem sa_iff : ∀ l : List String, strictlyAscending l = true ↔ l.Pairwise (· < ·)
  | [] => by simp [strictlyAscending]
  | [a] => by simp [strictlyAscending]
  | a :: b :: rest => by
      rw [strictlyAscending, Bool.and_eq_true, decide_eq_true_eq, sa_iff (b :: rest)]
      constructor
      · rintro ⟨hab, h⟩
        refine List.pairwise_cons.2 ⟨?_, h⟩
        intro x hx
        rcases List.mem_cons.1 hx with rfl | hx
        · exact hab
        · exact String.lt_trans hab ((List.pairwise_cons.1 h).1 x hx)
      · intro h
        obtain ⟨h1, h2⟩ := List.pairwise_cons.1 h
        exact ⟨h1 b (List.mem_cons_self ..), h2⟩

theorem pairwise_insert_str (s : String) :
    ∀ {l : List String}, l.Pairwise (· < ·) → s ∉ l → (insertBy (fun x => x) s l).Pairwise (· < ·)
  | [], _, _ => by simp [insertBy]
  | x :: xs, h, hn => by
    obtain ⟨h1, h2⟩ := List.pairwise_cons.1 h
    have e : insertBy (fun x : String => x) s (x :: xs) =
        if s < x then s :: x :: xs else x :: insertBy (fun x => x) s xs := rfl
    rw [e]
    by_cases hs : s < x
    · rw [if_pos hs]
      refine List.pairwise_cons.2 ⟨fun y hy => ?_, h⟩
      rcases List.mem_cons.1 hy with rfl | hy
      · exact hs
      · exact String.lt_trans hs (h1 y hy)
    · rw [if_neg hs]
      have hxs : s ∉ xs := fun m => hn (List.mem_cons_of_mem _ m)
      have hsx : s ≠ x := fun e => hn (e ▸ List.mem_cons_self ..)
      refine List.pairwise_cons.2 ⟨fun y hy => ?_, pairwise_insert_str s h2 hxs⟩
      rcases (mem_insertBy (fun x : String => x) s y xs).1 hy with rfl | hy
      · rcases str_trich x y with h' | h' | h'
        · exact h'
        · exact absurd h'.symm hsx
        · exact absurd h' hs
      · exact h1 y hy

theorem canonical_insert {l : List String} (h : canonicalIdList l = true) {s : String}
    (hs : idWellFormed s = true) (hn : s ∉ l) (hlen : l.length < maxRows) :
    canonicalIdList (insertBy (fun x => x) s l) = true := by
  obtain ⟨-, hid, hp⟩ := canonical_facts h
  have hperm := insertBy_perm (fun x : String => x) s l
  simp only [canonicalIdList, Bool.and_eq_true, decide_eq_true_eq, List.all_eq_true]
  refine ⟨⟨?_, fun x hx => ?_⟩, (sa_iff _).2 (pairwise_insert_str s hp hn)⟩
  · rw [hperm.length_eq]; simp only [List.length_cons]; omega
  · rcases List.mem_cons.1 (hperm.mem_iff.1 hx) with rfl | hx
    · exact hs
    · exact hid x hx

/-! ## Totals -/

theorem evalAdd_eq' (a b : Nat) : evalAdd a b = if a + b ≤ maxCents then some (a + b) else none := by
  unfold evalAdd
  by_cases h : a + b ≤ maxCents
  · rw [if_pos h, if_pos]
    simp only [Bool.and_eq_true, decide_eq_true_eq]; omega
  · rw [if_neg h, if_neg]
    simp only [Bool.and_eq_true, decide_eq_true_eq]; omega

theorem evalPaymentSum_eq : ∀ ps : List Payment,
    evalPaymentSum ps = if activeCents ps ≤ maxCents then some (activeCents ps) else none
  | [] => by simp [evalPaymentSum, activeCents, maxCents]
  | p :: ps => by
    have ih := evalPaymentSum_eq ps
    by_cases hs : p.status = .ACTIVE
    · have e : activeCents (p :: ps) = p.amountCents + activeCents ps := by
        simp [activeCents, List.filter_cons, hs]
      rw [e]
      by_cases h1 : activeCents ps ≤ maxCents
      · rw [if_pos h1] at ih
        simp only [evalPaymentSum, ih, hs, Option.bind_some, if_true]
        exact evalAdd_eq' _ _
      · rw [if_neg h1] at ih
        have : ¬ p.amountCents + activeCents ps ≤ maxCents := by omega
        simp only [evalPaymentSum, ih, if_neg this]; rfl
    · have e : activeCents (p :: ps) = activeCents ps := by
        simp [activeCents, List.filter_cons, hs]
      rw [e]
      by_cases h1 : activeCents ps ≤ maxCents
      · rw [if_pos h1] at ih
        simp [evalPaymentSum, ih, hs, h1]
      · rw [if_neg h1] at ih
        simp [evalPaymentSum, ih, hs, h1]

theorem evaluateTotals_payments {i : FinancialInput} {t} (h : evaluateTotals i = some t)
    (P : List Payment) :
    evaluateTotals { i with payments := P } =
      if activeCents P + t.lawful ≤ maxCents then
        some { cash := activeCents P, claimed := t.claimed, lawful := t.lawful,
               total := activeCents P + t.lawful }
      else none := by
  unfold evaluateTotals at h ⊢
  cases hc : evalPaymentSum i.payments with
  | none => simp [hc] at h
  | some cash =>
  cases hcl : evalClaimedSum i.claims with
  | none => simp [hc, hcl] at h
  | some cl =>
  cases hl : evalLawfulSum i.claims with
  | none => simp [hc, hcl, hl] at h
  | some la =>
  cases ht : evalAdd cash la with
  | none => simp [hc, hcl, hl, ht] at h
  | some tot =>
    simp only [hc, hcl, hl, ht, Option.some.injEq] at h
    subst h
    have hla : la ≤ maxCents := by
      rw [evalAdd_eq'] at ht
      by_cases hh : cash + la ≤ maxCents
      · omega
      · rw [if_neg hh] at ht; cases ht
    dsimp only
    rw [evalPaymentSum_eq]
    by_cases h1 : activeCents P ≤ maxCents
    · rw [if_pos h1]
      simp only [evalAdd_eq']
      by_cases h2 : activeCents P + la ≤ maxCents
      · rw [if_pos h2, if_pos h2]
      · rw [if_neg h2, if_neg h2]
    · rw [if_neg h1, if_neg (by omega)]

/-! ## Contribution multisets -/

def pcOf (P : List Payment) : List EvalContribution :=
  P.foldr (fun payment rest =>
    if payment.status = .ACTIVE then
      { time := payment.eventAt, identity := payment.paymentId, amountCents := payment.amountCents } :: rest
    else rest) []

def dcOf (D : List OffsetDetermination) : List EvalContribution :=
  D.foldr (fun determination rest =>
    if determination.decision = .OFFSET_AUTHORIZED then
      { time := determination.decidedAt, identity := determination.determinationId,
        amountCents := determination.amountCents } :: rest
    else rest) []

theorem evalContributions_eq (i : FinancialInput) :
    evalContributions i = pcOf i.payments ++ dcOf i.determinations := rfl

def cOf (p : Payment) : EvalContribution := ⟨p.eventAt, p.paymentId, p.amountCents⟩

theorem pcOf_eq (P : List Payment) :
    pcOf P = (P.filter fun q => q.status = .ACTIVE).map cOf := by
  induction P with
  | nil => rfl
  | cons p ps ih =>
    by_cases hs : p.status = .ACTIVE <;> simp [pcOf, List.filter_cons, hs, cOf] at ih ⊢ <;> exact ih

theorem pcOf_perm {P Q : List Payment} (h : P.Perm Q) : (pcOf P).Perm (pcOf Q) := by
  rw [pcOf_eq, pcOf_eq]; exact (h.filter _).map _

theorem pcOf_active {p : Payment} (P : List Payment) (h : p.status = .ACTIVE) :
    pcOf (p :: P) = cOf p :: pcOf P := by
  simp [pcOf, List.foldr_cons, h, cOf]

theorem pcOf_inactive {p : Payment} (P : List Payment) (h : p.status ≠ .ACTIVE) :
    pcOf (p :: P) = pcOf P := by
  simp [pcOf, List.foldr_cons, h]

theorem contrib_insert (dc : List EvalContribution) (P : List Payment) (x : Payment)
    (hx : x.status = .ACTIVE) :
    evalSortContributions (pcOf (insertBy Payment.paymentId x P) ++ dc) =
      evalInsertContribution (cOf x) (evalSortContributions (pcOf P ++ dc)) := by
  have hp : (pcOf (insertBy Payment.paymentId x P) ++ dc).Perm (cOf x :: (pcOf P ++ dc)) := by
    have := (pcOf_perm (insertBy_perm Payment.paymentId x P)).append_right dc
    rwa [pcOf_active _ hx, List.cons_append] at this
  rw [sort_congr hp]; rfl

theorem pcOf_replace (new : Payment) (hnew : new.status ≠ .ACTIVE) :
    ∀ (P : List Payment) (q : Payment), (P.map Payment.paymentId).Nodup →
      findPayment P new.paymentId = some q → q.status = .ACTIVE →
      (pcOf P).Perm (cOf q :: pcOf (P.map fun x => if x.paymentId = new.paymentId then new else x))
  | [], q, _, h, _ => by simp [findPayment] at h
  | x :: xs, q, hn, h, hq => by
    rw [List.map_cons, List.nodup_cons] at hn
    by_cases hx : x.paymentId = new.paymentId
    · simp only [findPayment, hx, ↓reduceIte, Option.some.injEq] at h
      subst h
      have hid : xs.map (fun y => if y.paymentId = new.paymentId then new else y) = xs := by
        refine (List.map_congr_left (g := id) fun y hy => ?_).trans (List.map_id _)
        have hy' : y.paymentId ≠ new.paymentId := fun e =>
          hn.1 (List.mem_map.2 ⟨y, hy, e.trans hx.symm⟩)
        simp [hy']
      simp only [List.map_cons, hx, ↓reduceIte, hid]
      rw [pcOf_active _ hq, pcOf_inactive _ hnew]
    · simp only [findPayment, hx, ↓reduceIte] at h
      have ih := pcOf_replace new hnew xs q hn.2 h hq
      simp only [List.map_cons, hx, ↓reduceIte]
      by_cases ha : x.status = .ACTIVE
      · rw [pcOf_active _ ha, pcOf_active _ ha]
        exact (ih.cons (cOf x)).trans (.swap _ _ _)
      · rw [pcOf_inactive _ ha, pcOf_inactive _ ha]
        exact ih

theorem contrib_replace (dc : List EvalContribution) (P : List Payment) (new q : Payment)
    (hnew : new.status ≠ .ACTIVE) (hn : (P.map Payment.paymentId).Nodup)
    (hf : findPayment P new.paymentId = some q) (hq : q.status = .ACTIVE) :
    evalSortContributions (pcOf (P.map fun x => if x.paymentId = new.paymentId then new else x) ++ dc) =
      (evalSortContributions (pcOf P ++ dc)).erase (cOf q) := by
  have hp := (pcOf_replace new hnew P q hn hf hq).append_right dc
  rw [List.cons_append] at hp
  have hm : cOf q ∈ pcOf P ++ dc := hp.symm.mem_iff.1 (List.mem_cons_self ..)
  rw [sort_erase _ hm]
  refine sort_congr ?_
  have := hp.erase (cOf q)
  rw [List.erase_cons_head] at this
  exact this.symm

end BlindLedger.Financial.Payment.Rev12
