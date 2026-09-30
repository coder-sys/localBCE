import BlindLedger.Financial.CorrectionTransition.Theorems

/-! Proofs of the statements in docs/CORE_REDESIGN.md, "Lean paid sum".  They
    name `CorrectionCommand.paymentLinks` and `derivedCorrectionPaid`, and sit
    alongside the caller-trusting B2 theorems they replace. -/

namespace BlindLedger.Financial.CorrectionTransition

open BlindLedger.Financial

/-! ## Order and sum helpers -/

private theorem str_trich (a b : String) : a < b ∨ a = b ∨ b < a := by
  by_cases h1 : a < b
  · exact Or.inl h1
  · by_cases h2 : b < a
    · exact Or.inr (Or.inr h2)
    · exact Or.inr (Or.inl (String.le_antisymm (String.not_lt.1 h2) (String.not_lt.1 h1)))

private theorem strictlyAscending_iff :
    ∀ l : List String, strictlyAscending l = true ↔ l.Pairwise (· < ·)
  | [] => by simp [strictlyAscending]
  | [a] => by simp [strictlyAscending]
  | a :: b :: rest => by
      rw [strictlyAscending, Bool.and_eq_true, decide_eq_true_eq, strictlyAscending_iff (b :: rest)]
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

private theorem canonical_facts {l : List String} (h : canonicalIdList l = true) :
    l.length ≤ maxRows ∧ (∀ x ∈ l, idWellFormed x = true) ∧ l.Pairwise (· < ·) := by
  simp only [canonicalIdList, Bool.and_eq_true, decide_eq_true_eq, List.all_eq_true] at h
  exact ⟨h.1.1, h.1.2, (strictlyAscending_iff l).1 h.2⟩

private theorem paidCents_eq_sum (E : List CorrectionPaid) (a : String) :
    correctionPaidCents E a = (E.map fun e => if e.actionId = a then e.paidCents else 0).sum := by
  induction E with
  | nil => rfl
  | cons e es ih =>
      simp only [correctionPaidCents, List.foldr_cons, List.map_cons, List.sum_cons] at ih ⊢
      rw [ih]

private theorem le_paidCents_of_mem {E : List CorrectionPaid} {e : CorrectionPaid} (h : e ∈ E) :
    e.paidCents ≤ correctionPaidCents E e.actionId := by
  rw [paidCents_eq_sum]
  induction E with
  | nil => cases h
  | cons x xs ih =>
      simp only [List.map_cons, List.sum_cons]
      rcases List.mem_cons.1 h with rfl | hx
      · simp
      · have := ih hx
        omega

/-! ## `linkedCents` -/

private theorem paidTerm_cons_ne (l : PaymentLink) (ls : List PaymentLink) (a : String)
    (q : Payment) (h : l.paymentId ≠ q.paymentId) :
    paidTerm (l :: ls) a q = paidTerm ls a q := by
  have hIff : (∃ link ∈ l :: ls, link.paymentId = q.paymentId ∧ link.actionId = a) ↔
      ∃ link ∈ ls, link.paymentId = q.paymentId ∧ link.actionId = a := by
    constructor
    · rintro ⟨link, hm, h1, h2⟩
      rcases List.mem_cons.1 hm with rfl | hm
      · exact absurd h1 h
      · exact ⟨link, hm, h1, h2⟩
    · rintro ⟨link, hm, h1, h2⟩
      exact ⟨link, List.mem_cons_of_mem _ hm, h1, h2⟩
  by_cases hc : ∃ link ∈ ls, link.paymentId = q.paymentId ∧ link.actionId = a
  · by_cases hs : q.status = .ACTIVE
    · rw [paidTerm, paidTerm, if_pos ⟨hs, hIff.2 hc⟩, if_pos ⟨hs, hc⟩]
    · rw [paidTerm, paidTerm, if_neg (fun x => hs x.1), if_neg (fun x => hs x.1)]
  · rw [paidTerm, paidTerm, if_neg (fun x => hc (hIff.1 x.2)), if_neg (fun x => hc x.2)]

private theorem paidTerm_zero (ls : List PaymentLink) (a : String) (p : Payment)
    (h : ∀ m ∈ ls, m.paymentId ≠ p.paymentId) : paidTerm ls a p = 0 := by
  rw [paidTerm, if_neg]
  rintro ⟨_, link, hm, h1, _⟩
  exact h link hm h1

private theorem paidTerm_head (l : PaymentLink) (ls : List PaymentLink) (a : String) (p : Payment)
    (hId : p.paymentId = l.paymentId) (hLater : ∀ m ∈ ls, l.paymentId < m.paymentId) :
    paidTerm (l :: ls) a p =
      if l.actionId = a then (if p.status = .ACTIVE then p.amountCents else 0) else 0 := by
  have hIff : (∃ link ∈ l :: ls, link.paymentId = p.paymentId ∧ link.actionId = a) ↔
      l.actionId = a := by
    constructor
    · rintro ⟨link, hm, h1, h2⟩
      rcases List.mem_cons.1 hm with rfl | hm
      · exact h2
      · exact absurd (h1.trans hId) (String.ne_of_lt (hLater link hm)).symm
    · intro h
      exact ⟨l, List.mem_cons_self .., hId.symm, h⟩
  by_cases hs : p.status = .ACTIVE
  · by_cases hc : l.actionId = a
    · rw [paidTerm, if_pos ⟨hs, hIff.2 hc⟩, if_pos hc, if_pos hs]
    · rw [paidTerm, if_neg (fun x => hc (hIff.1 x.2)), if_neg hc]
  · by_cases hc : l.actionId = a
    · rw [paidTerm, if_neg (fun x => hs x.1), if_pos hc, if_neg hs]
    · rw [paidTerm, if_neg (fun x => hs x.1), if_neg hc]

private theorem linkedCents_spec : ∀ (ps : List Payment) (ls : List PaymentLink)
    (E : List CorrectionPaid), (ps.map Payment.paymentId).Pairwise (· < ·) →
    (ls.map PaymentLink.paymentId).Pairwise (· < ·) → linkedCents ps ls = some E →
    E.map CorrectionPaid.actionId = ls.map PaymentLink.actionId ∧
      (∀ l ∈ ls, ∃ p ∈ ps, p.paymentId = l.paymentId) ∧
      ∀ a, (E.map fun e => if e.actionId = a then e.paidCents else 0).sum =
        (ps.map (paidTerm ls a)).sum := by
  intro ps
  induction ps with
  | nil =>
      intro ls E _ _ h
      cases ls with
      | nil =>
          rw [linkedCents] at h
          cases h
          exact ⟨rfl, by simp, fun a => rfl⟩
      | cons l ls => rw [linkedCents] at h; cases h
  | cons p ps ih =>
      intro ls E hp hl h
      obtain ⟨hpLt, hps⟩ := List.pairwise_cons.1 hp
      cases ls with
      | nil =>
          rw [linkedCents] at h
          cases h
          refine ⟨rfl, by simp, fun a => ?_⟩
          simp only [List.map_nil, List.sum_nil]
          exact (sum_map_zero _ _ fun q _ => paidTerm_zero [] a q (by simp)).symm
      | cons l ls =>
          obtain ⟨hlLt, hls⟩ := List.pairwise_cons.1 hl
          rw [linkedCents] at h
          by_cases hEq : p.paymentId = l.paymentId
          · rw [if_pos hEq] at h
            cases hRest : linkedCents ps ls with
            | none => rw [hRest] at h; cases h
            | some E' =>
                rw [hRest] at h
                cases h
                obtain ⟨k1, k2, k3⟩ := ih ls E' hps hls hRest
                refine ⟨by simp [k1], ?_, fun a => ?_⟩
                · intro m hm
                  rcases List.mem_cons.1 hm with rfl | hm
                  · exact ⟨p, List.mem_cons_self .., hEq⟩
                  · obtain ⟨q, hq, hqm⟩ := k2 m hm
                    exact ⟨q, List.mem_cons_of_mem _ hq, hqm⟩
                · have hLater : ∀ m ∈ ls, l.paymentId < m.paymentId := fun m hm =>
                    hlLt m.paymentId (List.mem_map_of_mem hm)
                  have hTail : (ps.map (paidTerm (l :: ls) a)) = ps.map (paidTerm ls a) :=
                    List.map_congr_left fun q hq =>
                      paidTerm_cons_ne l ls a q fun hne =>
                        String.lt_irrefl _ (hne ▸ hEq ▸ hpLt q.paymentId (List.mem_map_of_mem hq))
                  simp only [List.map_cons, List.sum_cons, hTail, paidTerm_head l ls a p hEq hLater,
                    ← k3 a]
          · by_cases hLt : p.paymentId < l.paymentId
            · rw [if_neg hEq, if_pos hLt] at h
              obtain ⟨k1, k2, k3⟩ := ih (l :: ls) E hps hl h
              refine ⟨k1, ?_, fun a => ?_⟩
              · intro m hm
                obtain ⟨q, hq, hqm⟩ := k2 m hm
                exact ⟨q, List.mem_cons_of_mem _ hq, hqm⟩
              · have hZero : paidTerm (l :: ls) a p = 0 := paidTerm_zero _ a p fun m hm =>
                  Ne.symm (String.ne_of_lt (by
                    rcases List.mem_cons.1 hm with rfl | hm
                    · exact hLt
                    · exact String.lt_trans hLt (hlLt m.paymentId (List.mem_map_of_mem hm))))
                simp only [List.map_cons, List.sum_cons, hZero, ← k3 a]
                omega
            · rw [if_neg hEq, if_neg hLt] at h
              cases h

private theorem linkedCents_complete : ∀ (ps : List Payment) (ls : List PaymentLink),
    (ps.map Payment.paymentId).Pairwise (· < ·) → (ls.map PaymentLink.paymentId).Pairwise (· < ·) →
    (∀ l ∈ ls, ∃ p ∈ ps, p.paymentId = l.paymentId) → ∃ E, linkedCents ps ls = some E := by
  intro ps
  induction ps with
  | nil =>
      intro ls _ _ hRows
      cases ls with
      | nil => exact ⟨[], by rw [linkedCents]⟩
      | cons l ls => obtain ⟨q, hq, _⟩ := hRows l (List.mem_cons_self ..); cases hq
  | cons p ps ih =>
      intro ls hp hl hRows
      obtain ⟨hpLt, hps⟩ := List.pairwise_cons.1 hp
      cases ls with
      | nil => exact ⟨[], by rw [linkedCents]⟩
      | cons l ls =>
          obtain ⟨hlLt, hls⟩ := List.pairwise_cons.1 hl
          rw [linkedCents]
          by_cases hEq : p.paymentId = l.paymentId
          · rw [if_pos hEq]
            obtain ⟨E, hE⟩ := ih ls hps hls fun m hm => by
              obtain ⟨q, hq, hqm⟩ := hRows m (List.mem_cons_of_mem _ hm)
              rcases List.mem_cons.1 hq with rfl | hq
              · exact absurd (hEq.symm.trans hqm)
                  (String.ne_of_lt (hlLt m.paymentId (List.mem_map_of_mem hm)))
              · exact ⟨q, hq, hqm⟩
            exact ⟨_, by rw [hE]; rfl⟩
          · by_cases hLt : p.paymentId < l.paymentId
            · rw [if_neg hEq, if_pos hLt]
              exact ih (l :: ls) hps hl fun m hm => by
                obtain ⟨q, hq, hqm⟩ := hRows m hm
                rcases List.mem_cons.1 hq with rfl | hq
                · have hml : q.paymentId < m.paymentId := by
                    rcases List.mem_cons.1 hm with rfl | hm
                    · exact hLt
                    · exact String.lt_trans hLt (hlLt m.paymentId (List.mem_map_of_mem hm))
                  exact absurd hqm (String.ne_of_lt hml)
                · exact ⟨q, hq, hqm⟩
            · exfalso
              obtain ⟨q, hq, hqm⟩ := hRows l (List.mem_cons_self ..)
              rcases List.mem_cons.1 hq with rfl | hq
              · exact hEq hqm
              · have h1 : p.paymentId < q.paymentId := hpLt _ (List.mem_map_of_mem hq)
                rcases str_trich p.paymentId l.paymentId with h | h | h
                · exact hLt h
                · exact hEq h
                · exact String.lt_irrefl _ (hqm ▸ String.lt_trans h h1)

/-! ## Grouping, filtering and the request-key check -/

private theorem sumSorted_cents (L : List CorrectionPaid) (a : String) :
    correctionPaidCents (sumSortedPaid L) a = correctionPaidCents L a := by
  induction L with
  | nil => rfl
  | cons e rest ih =>
      cases hs : sumSortedPaid rest with
      | nil =>
          rw [hs] at ih
          simp only [sumSortedPaid, hs, paidCents_eq_sum, List.map_cons, List.map_nil,
            List.sum_cons, List.sum_nil] at ih ⊢
          omega
      | cons first more =>
          rw [hs] at ih
          by_cases hk : first.actionId = e.actionId
          · simp only [sumSortedPaid, hs, if_pos hk, paidCents_eq_sum, List.map_cons,
              List.sum_cons] at ih ⊢
            rw [hk] at ih
            by_cases ha : e.actionId = a <;> simp [ha] at ih ⊢ <;> omega
          · simp only [sumSortedPaid, hs, if_neg hk, paidCents_eq_sum, List.map_cons,
              List.sum_cons] at ih ⊢
            omega

private theorem sumSorted_mem (L : List CorrectionPaid) (k : String) :
    k ∈ (sumSortedPaid L).map CorrectionPaid.actionId ↔ k ∈ L.map CorrectionPaid.actionId := by
  induction L with
  | nil => exact Iff.rfl
  | cons e rest ih =>
      cases hs : sumSortedPaid rest with
      | nil =>
          rw [hs] at ih
          simp only [sumSortedPaid, hs, List.map_cons, List.mem_cons, List.map_nil,
            List.not_mem_nil, or_false]
          constructor
          · exact Or.inl
          · rintro (h | h)
            · exact h
            · exact absurd (ih.2 h) (by simp)
      | cons first more =>
          rw [hs] at ih
          simp only [List.map_cons, List.mem_cons] at ih
          by_cases hk : first.actionId = e.actionId
          · simp only [sumSortedPaid, hs, if_pos hk, List.map_cons, List.mem_cons]
            rw [hk] at ih
            rw [← ih]
            simp
          · simp only [sumSortedPaid, hs, if_neg hk, List.map_cons, List.mem_cons]
            rw [← ih]

private theorem sumSorted_length (L : List CorrectionPaid) :
    (sumSortedPaid L).length ≤ L.length := by
  induction L with
  | nil => exact Nat.le_refl _
  | cons e rest ih =>
      cases hs : sumSortedPaid rest with
      | nil => simp [sumSortedPaid, hs]
      | cons first more =>
          rw [hs] at ih
          by_cases hk : first.actionId = e.actionId
          · simp only [sumSortedPaid, hs, if_pos hk, List.length_cons] at ih ⊢
            omega
          · simp only [sumSortedPaid, hs, if_neg hk, List.length_cons] at ih ⊢
            omega

private theorem sumSorted_lt (L : List CorrectionPaid)
    (h : (L.map CorrectionPaid.actionId).Pairwise (· ≤ ·)) :
    ((sumSortedPaid L).map CorrectionPaid.actionId).Pairwise (· < ·) := by
  induction L with
  | nil => simp [sumSortedPaid]
  | cons e rest ih =>
      simp only [List.map_cons] at h
      obtain ⟨hHead, hRest⟩ := List.pairwise_cons.1 h
      have ih' := ih hRest
      cases hs : sumSortedPaid rest with
      | nil => simp [sumSortedPaid, hs]
      | cons first more =>
          rw [hs] at ih'
          simp only [List.map_cons] at ih'
          obtain ⟨hFirst, hMore⟩ := List.pairwise_cons.1 ih'
          have hMem : ∀ k, k ∈ first.actionId :: more.map CorrectionPaid.actionId →
              e.actionId ≤ k := fun k hk =>
            hHead k ((sumSorted_mem rest k).1 (by rw [hs]; simpa using hk))
          by_cases hk : first.actionId = e.actionId
          · simp only [sumSortedPaid, hs, if_pos hk, List.map_cons]
            exact List.pairwise_cons.2 ⟨fun m hm => by rw [← hk]; exact hFirst m hm, hMore⟩
          · simp only [sumSortedPaid, hs, if_neg hk, List.map_cons]
            have hlt : e.actionId < first.actionId := by
              rcases str_trich e.actionId first.actionId with h1 | h1 | h1
              · exact h1
              · exact absurd h1.symm hk
              · exact absurd (hMem first.actionId (List.mem_cons_self ..)) (String.not_le.2 h1)
            exact List.pairwise_cons.2 ⟨fun m hm => by
              rcases List.mem_cons.1 hm with h | h
              · rw [h]; exact hlt
              · exact String.lt_trans hlt (hFirst m h), ih'⟩

/-- Rows sorted by request, neighbours added. -/
private def groupedOf (rows : List CorrectionPaid) : List CorrectionPaid :=
  sumSortedPaid (rows.mergeSort fun a b => decide (a.actionId ≤ b.actionId))

private def paidOf (rows : List CorrectionPaid) : List CorrectionPaid :=
  (groupedOf rows).filter fun entry => entry.paidCents ≠ 0

private theorem groupedOf_lt (rows : List CorrectionPaid) :
    ((groupedOf rows).map CorrectionPaid.actionId).Pairwise (· < ·) := by
  apply sumSorted_lt
  have hSorted := List.pairwise_mergeSort
    (le := fun a b : CorrectionPaid => decide (a.actionId ≤ b.actionId))
    (fun a b c hab hbc => by
      simp only [decide_eq_true_eq] at *
      exact String.le_trans hab hbc)
    (fun a b => by
      simp only [Bool.or_eq_true, decide_eq_true_eq]
      exact String.le_total _ _) rows
  exact List.pairwise_map.2 (hSorted.imp fun {a b} h => by simpa using h)

private theorem groupedOf_cents (rows : List CorrectionPaid) (a : String) :
    correctionPaidCents (groupedOf rows) a = correctionPaidCents rows a := by
  unfold groupedOf
  rw [sumSorted_cents, paidCents_eq_sum, paidCents_eq_sum]
  exact (((List.mergeSort_perm rows _)).map _).sum_nat

private theorem groupedOf_mem (rows : List CorrectionPaid) (k : String) :
    k ∈ (groupedOf rows).map CorrectionPaid.actionId ↔ k ∈ rows.map CorrectionPaid.actionId :=
  (sumSorted_mem _ k).trans (((List.mergeSort_perm rows _).map _).mem_iff)

private theorem groupedOf_length (rows : List CorrectionPaid) :
    (groupedOf rows).length ≤ rows.length :=
  Nat.le_trans (sumSorted_length _) (by rw [List.length_mergeSort]; exact Nat.le_refl _)

private theorem filter_zero_cents (L : List CorrectionPaid) (a : String) :
    correctionPaidCents (L.filter fun entry => entry.paidCents ≠ 0) a = correctionPaidCents L a := by
  induction L with
  | nil => rfl
  | cons e es ih =>
      by_cases h : e.paidCents = 0
      · simp only [List.filter_cons, h, ne_eq, not_true_eq_false, decide_false,
          Bool.false_eq_true, if_false]
        rw [ih]
        simp [correctionPaidCents, h]
      · simp only [List.filter_cons, h, ne_eq, not_false_eq_true, decide_true, if_true]
        simp only [correctionPaidCents, List.foldr_cons] at ih ⊢
        rw [ih]

private theorem paidOf_cents (rows : List CorrectionPaid) (a : String) :
    correctionPaidCents (paidOf rows) a = correctionPaidCents rows a := by
  unfold paidOf
  rw [filter_zero_cents, groupedOf_cents]

private theorem paidOf_lt (rows : List CorrectionPaid) :
    ((paidOf rows).map CorrectionPaid.actionId).Pairwise (· < ·) :=
  List.Pairwise.sublist (List.Sublist.map _ List.filter_sublist) (groupedOf_lt rows)

private theorem paidOf_mem_keys {rows : List CorrectionPaid} {k : String}
    (h : k ∈ (paidOf rows).map CorrectionPaid.actionId) :
    k ∈ rows.map CorrectionPaid.actionId :=
  (groupedOf_mem rows k).1 ((List.Sublist.map _ List.filter_sublist).subset h)

private theorem keysAmong_sound : ∀ (ids keys : List String), keysAmong keys ids = true →
    ∀ k ∈ keys, k ∈ ids := by
  intro ids
  induction ids with
  | nil =>
      intro keys h k hk
      cases keys with
      | nil => cases hk
      | cons key keys => rw [keysAmong] at h; cases h
  | cons id ids ih =>
      intro keys h k hk
      cases keys with
      | nil => cases hk
      | cons key keys =>
          rw [keysAmong] at h
          by_cases hEq : key = id
          · rw [if_pos hEq] at h
            rcases List.mem_cons.1 hk with rfl | hk
            · rw [hEq]; exact List.mem_cons_self ..
            · exact List.mem_cons_of_mem _ (ih keys h k hk)
          · rw [if_neg hEq] at h
            exact List.mem_cons_of_mem _ (ih (key :: keys) h k hk)

private theorem keysAmong_complete : ∀ (ids keys : List String), keys.Pairwise (· < ·) →
    ids.Pairwise (· < ·) → (∀ k ∈ keys, k ∈ ids) → keysAmong keys ids = true := by
  intro ids
  induction ids with
  | nil =>
      intro keys _ _ hIn
      cases keys with
      | nil => rw [keysAmong]
      | cons key keys => cases hIn key (List.mem_cons_self ..)
  | cons id ids ih =>
      intro keys hKeys hIds hIn
      obtain ⟨hIdLt, hIds'⟩ := List.pairwise_cons.1 hIds
      cases keys with
      | nil => rw [keysAmong]
      | cons key keys =>
          obtain ⟨hKeyLt, hKeys'⟩ := List.pairwise_cons.1 hKeys
          rw [keysAmong]
          by_cases hEq : key = id
          · rw [if_pos hEq]
            refine ih keys hKeys' hIds' fun k hk => ?_
            rcases List.mem_cons.1 (hIn k (List.mem_cons_of_mem _ hk)) with h | h
            · have hLt := hKeyLt k hk
              rw [h.trans hEq.symm] at hLt
              exact absurd hLt (String.lt_irrefl _)
            · exact h
          · rw [if_neg hEq]
            have hKeyIn : key ∈ ids := by
              rcases List.mem_cons.1 (hIn key (List.mem_cons_self ..)) with h | h
              · exact absurd h hEq
              · exact h
            refine ih (key :: keys) hKeys hIds' fun k hk => ?_
            rcases List.mem_cons.1 hk with rfl | hk
            · exact hKeyIn
            · rcases List.mem_cons.1 (hIn k (List.mem_cons_of_mem _ hk)) with h | h
              · exact absurd (hIdLt key hKeyIn) (by
                  rw [← h]; exact String.lt_asymm (hKeyLt k hk))
              · exact h

private theorem derived_of {payments : List Payment} {actions : List ActionRecord}
    {links : List PaymentLink} {rows : List CorrectionPaid}
    (hAsc : (strictlyAscending (payments.map Payment.paymentId) &&
      strictlyAscending (links.map PaymentLink.paymentId)) = true)
    (hRows : linkedCents payments links = some rows)
    (hCheck : (keysAmong ((groupedOf rows).map CorrectionPaid.actionId)
      ((actions.filter fun action => action.kind = "CORRECTION_PAYMENT_REQUEST").map
        ActionRecord.actionId) && correctionPaidWellFormed (paidOf rows)) = true) :
    derivedCorrectionPaid payments actions links = some (paidOf rows) := by
  unfold derivedCorrectionPaid
  rw [if_pos hAsc, hRows]
  exact if_pos hCheck

/-! ## Total sum of the active rows -/

private theorem evalAdd_some {l r t : Nat} (h : evalAdd l r = some t) :
    t = l + r ∧ t ≤ maxCents := by
  unfold evalAdd at h
  split at h
  · cases h
    rename_i hc
    simp only [Bool.and_eq_true, decide_eq_true_eq] at hc
    exact ⟨rfl, by omega⟩
  · cases h

private theorem evalPaymentSum_active : ∀ (ps : List Payment) (t : Nat),
    evalPaymentSum ps = some t →
    ((ps.filter fun p => p.status = .ACTIVE).map Payment.amountCents).sum = t ∧ t ≤ maxCents
  | [], t, h => by
      simp only [evalPaymentSum] at h
      cases h
      exact ⟨rfl, Nat.zero_le _⟩
  | p :: ps, t, h => by
      cases hT : evalPaymentSum ps with
      | none => simp [evalPaymentSum, hT] at h
      | some t' =>
          obtain ⟨e1, e2⟩ := evalPaymentSum_active ps t' hT
          by_cases hs : p.status = .ACTIVE
          · simp only [evalPaymentSum, hT, hs, if_true] at h
            obtain ⟨e3, e4⟩ := evalAdd_some (l := p.amountCents) (r := t') h
            refine ⟨?_, e4⟩
            simp [hs, e1, e3]
          · simp only [evalPaymentSum, hT, hs, if_false] at h
            cases h
            exact ⟨by simp [hs, e1], e2⟩

/-! ## Derivation contract (`derivedCorrectionPaid`, O(n + k log k)) -/

/-- What the derivation returns is canonical, comes only from admissible
    links, and is exactly the linked active cash per action. -/
theorem derivedCorrectionPaid_sound (payments : List Payment) (actions : List ActionRecord)
    (links : List PaymentLink) (paid : List CorrectionPaid)
    (hDerived : derivedCorrectionPaid payments actions links = some paid) :
    correctionPaidWellFormed paid = true ∧
      paymentLinksAdmissible payments actions links = true ∧
      ∀ actionId, correctionPaidCents paid actionId =
        linkedActivePaidCents payments links actionId := by
  unfold derivedCorrectionPaid at hDerived
  have hAsc : (strictlyAscending (payments.map Payment.paymentId) &&
      strictlyAscending (links.map PaymentLink.paymentId)) = true := by
    refine Decidable.byContradiction fun hNot => ?_
    rw [if_neg hNot] at hDerived
    cases hDerived
  rw [if_pos hAsc] at hDerived
  obtain ⟨hpa, hla⟩ := Bool.and_eq_true_iff.1 hAsc
  cases hRows : linkedCents payments links with
  | none => rw [hRows] at hDerived; cases hDerived
  | some rows =>
      rw [hRows] at hDerived
      dsimp only at hDerived
      split at hDerived
      next hCheck =>
        obtain ⟨hKeys, hWf⟩ := Bool.and_eq_true_iff.1 hCheck
        have hPaid : paid = paidOf rows := (Option.some.inj hDerived).symm
        subst hPaid
        obtain ⟨k1, k2, k3⟩ := linkedCents_spec payments links rows
          ((strictlyAscending_iff _).1 hpa) ((strictlyAscending_iff _).1 hla) hRows
        refine ⟨hWf, ?_, fun a => ?_⟩
        · unfold paymentLinksAdmissible
          rw [List.all_eq_true]
          intro l hl
          rw [Bool.and_eq_true, List.any_eq_true, List.any_eq_true]
          refine ⟨?_, ?_⟩
          · obtain ⟨p, hp, hpl⟩ := k2 l hl
            exact ⟨p, hp, decide_eq_true hpl⟩
          · have hMemL : l.actionId ∈ rows.map CorrectionPaid.actionId := by
              rw [k1]; exact List.mem_map_of_mem hl
            have hIds := keysAmong_sound _ _ hKeys _ ((groupedOf_mem rows _).2 hMemL)
            obtain ⟨action, hAct, hActId⟩ := List.mem_map.1 hIds
            obtain ⟨hAM, hKind⟩ := List.mem_filter.1 hAct
            exact ⟨action, hAM, Bool.and_eq_true_iff.2 ⟨decide_eq_true hActId, hKind⟩⟩
        · rw [paidOf_cents, paidCents_eq_sum, k3 a, ← linkedActivePaidCents_eq_sum]
      next => cases hDerived

/-- An honest snapshot is never refused: admissible, canonical links over a
    well-formed input that evaluates always derive. -/
theorem derivedCorrectionPaid_complete (input : FinancialInput) (links : List PaymentLink)
    (result : FinancialResult)
    (hInput : financialInputWellFormed input = true)
    (hLinks : paymentLinksWellFormed links = true)
    (hAdmissible : paymentLinksAdmissible input.payments input.actions links = true)
    (hEval : evaluate input = some result) :
    ∃ paid, derivedCorrectionPaid input.payments input.actions links = some paid := by
  obtain ⟨-, -, hpAsc⟩ := canonical_facts (l := input.payments.map Payment.paymentId) (by
    unfold financialInputWellFormed at hInput
    simp only [Bool.and_eq_true] at hInput
    grind)
  obtain ⟨-, -, hActAsc⟩ := canonical_facts (l := input.actions.map ActionRecord.actionId) (by
    unfold financialInputWellFormed at hInput
    simp only [Bool.and_eq_true] at hInput
    grind)
  simp only [paymentLinksWellFormed, Bool.and_eq_true, List.all_eq_true] at hLinks
  obtain ⟨hLen, -, hlAsc⟩ := canonical_facts hLinks.1
  have hLids := hLinks.2
  simp only [paymentLinksAdmissible, List.all_eq_true, Bool.and_eq_true, List.any_eq_true,
    decide_eq_true_eq] at hAdmissible
  obtain ⟨rows, hRows⟩ := linkedCents_complete _ _ hpAsc hlAsc fun l hl => (hAdmissible l hl).1
  obtain ⟨k1, k2, k3⟩ := linkedCents_spec _ _ rows hpAsc hlAsc hRows
  have hAsc : (strictlyAscending (input.payments.map Payment.paymentId) &&
      strictlyAscending (links.map PaymentLink.paymentId)) = true :=
    Bool.and_eq_true_iff.2 ⟨(strictlyAscending_iff _).2 hpAsc, (strictlyAscending_iff _).2 hlAsc⟩
  have hCash : ((input.payments.filter fun p => p.status = .ACTIVE).map
      Payment.amountCents).sum ≤ maxCents := by
    unfold evaluate at hEval
    rw [if_pos hInput] at hEval
    unfold evaluateWellFormed evaluateTotals at hEval
    cases h : evalPaymentSum input.payments with
    | none => simp [h] at hEval
    | some t =>
        obtain ⟨e1, e2⟩ := evalPaymentSum_active _ t h
        omega
  have hLen' : rows.length = links.length := by
    have := congrArg List.length k1
    simpa using this
  refine ⟨paidOf rows, derived_of hAsc hRows (Bool.and_eq_true_iff.2 ⟨?_, ?_⟩)⟩
  · refine keysAmong_complete _ _ (groupedOf_lt rows) (List.Pairwise.sublist
      (List.Sublist.map _ List.filter_sublist) hActAsc) fun k hk => ?_
    obtain ⟨l, hl, hlk⟩ := List.mem_map.1 (k1 ▸ (groupedOf_mem rows k).1 hk)
    obtain ⟨action, hAM, hActId, hKind⟩ := (hAdmissible l hl).2
    exact List.mem_map.2 ⟨action, List.mem_filter.2 ⟨hAM, decide_eq_true hKind⟩,
      hActId.trans hlk⟩
  · have hPaidLen : (paidOf rows).length ≤ maxRows :=
      Nat.le_trans (List.length_filter_le _ _) (Nat.le_trans (groupedOf_length rows)
        (by rw [hLen']; simpa using hLen))
    have hKeyLinks : ∀ k ∈ (paidOf rows).map CorrectionPaid.actionId,
        ∃ l ∈ links, l.actionId = k := fun k hk => by
      have := k1 ▸ paidOf_mem_keys hk
      exact List.mem_map.1 this
    unfold correctionPaidWellFormed
    simp only [Bool.and_eq_true, decide_eq_true_eq, List.all_eq_true]
    refine ⟨⟨hPaidLen, ?_⟩, fun e he => ?_⟩
    · unfold canonicalIdList
      simp only [Bool.and_eq_true, decide_eq_true_eq, List.all_eq_true, List.length_map]
      refine ⟨⟨hPaidLen, fun k hk => ?_⟩, (strictlyAscending_iff _).2 (paidOf_lt rows)⟩
      obtain ⟨l, hl, rfl⟩ := hKeyLinks k hk
      exact hLids l hl
    · obtain ⟨l, hl, hle⟩ := hKeyLinks e.actionId (List.mem_map_of_mem he)
      have hNe : e.paidCents ≠ 0 := by
        have := (List.mem_filter.1 he).2
        simpa using this
      have hBound : e.paidCents ≤ maxCents := by
        have h1 := le_paidCents_of_mem he
        rw [paidOf_cents, paidCents_eq_sum, k3 e.actionId,
          ← linkedActivePaidCents_eq_sum] at h1
        have h2 := linkedActivePaidCents_total_le_active input.payments links [e.actionId]
          (by simp) (hlAsc.imp fun h => String.ne_of_lt h)
        simp only [List.map_cons, List.map_nil, List.sum_cons, List.sum_nil, Nat.add_zero] at h2
        omega
      exact ⟨⟨hle ▸ hLids l hl, by omega⟩, by simpa [amountWellFormed] using hBound⟩

theorem outstandingCorrectionCents_eq_linked (paid : List CorrectionPaid)
    (payments : List Payment) (links : List PaymentLink) (actions : List ActionRecord)
    (hPaid : ∀ actionId, correctionPaidCents paid actionId =
      linkedActivePaidCents payments links actionId) :
    outstandingCorrectionCents paid actions = linkedOutstandingCents payments links actions := by
  induction actions with
  | nil => rfl
  | cons action rest ih =>
      simp only [outstandingCorrectionCents, linkedOutstandingCents, hPaid, ih]

/-! ## Transition statements -/

/-- An accepted correction only ever used links naming snapshot payment rows
    and snapshot correction requests. -/
theorem applyCorrectionTransition_links_admissible
    (request : CorrectionTransitionRequest) (mutation : CorrectionMutation)
    (hMutation : (applyCorrectionTransition request).mutation = some mutation) :
    paymentLinksAdmissible request.currentInput.payments request.currentInput.actions
      request.command.paymentLinks = true := by
  have hLinks := (applyCorrectionTransition_mutation_links request mutation hMutation).2.2.2.2.2.2
  exact (derivedCorrectionPaid_sound _ _ _ _ hLinks.derivedPaid).2.1

/-- Main theorem: for every action, the paid-so-far Lean decided with (and
    echoes in the facts) is the sum of the active snapshot payment rows linked
    to it.  No caller-supplied total exists. -/
theorem applyCorrectionTransition_paid_eq_linked
    (request : CorrectionTransitionRequest) (mutation : CorrectionMutation)
    (hMutation : (applyCorrectionTransition request).mutation = some mutation) :
    ∀ actionId, correctionPaidCents mutation.dependencies.correctionPaid actionId =
      linkedActivePaidCents request.currentInput.payments request.command.paymentLinks
        actionId := by
  have hLinks := (applyCorrectionTransition_mutation_links request mutation hMutation).2.2.2.2.2.2
  exact (derivedCorrectionPaid_sound _ _ _ _ hLinks.derivedPaid).2.2

/-- Corollary (B2 over derived paid): the request is the smaller of the
    rejected claim and the shortfall less what open corrections, net of their
    linked active payments, still ask for. -/
theorem applyCorrectionTransition_action_amount_eq_linked
    (request : CorrectionTransitionRequest) (mutation : CorrectionMutation)
    (hMutation : (applyCorrectionTransition request).mutation = some mutation) :
    ∃ result, evaluate request.currentInput = some result ∧
      linkedOutstandingCents request.currentInput.payments request.command.paymentLinks
          request.currentInput.actions < result.shortfallCents ∧
      mutation.action.amountCents = min mutation.dependencies.claimBefore.amountCents
        (result.shortfallCents -
          linkedOutstandingCents request.currentInput.payments request.command.paymentLinks
            request.currentInput.actions) ∧
      mutation.action.amountCents ≤ result.shortfallCents := by
  have hLinks := (applyCorrectionTransition_mutation_links request mutation hMutation).2.2.2.2.2.2
  obtain ⟨result, hEval, hShortfall, hBelow⟩ := hLinks.inputShortfall
  have hOut := outstandingCorrectionCents_eq_linked _ _ _ request.currentInput.actions
    (applyCorrectionTransition_paid_eq_linked request mutation hMutation)
  rw [hOut] at hBelow
  have hAmount : mutation.action.amountCents = min mutation.dependencies.claimBefore.amountCents
      (result.shortfallCents - linkedOutstandingCents request.currentInput.payments
        request.command.paymentLinks request.currentInput.actions) := by
    rw [hLinks.amountRule, hLinks.claimAmount, ← hShortfall, hOut]
  exact ⟨result, hEval, hBelow, hAmount, hAmount ▸ Nat.le_trans (Nat.min_le_right _ _)
    (Nat.sub_le _ _)⟩

/-- H1 over derived paid. -/
theorem applyCorrectionTransition_outstanding_within_shortfall_linked
    (request : CorrectionTransitionRequest) (mutation : CorrectionMutation)
    (hMutation : (applyCorrectionTransition request).mutation = some mutation) :
    ∃ result, evaluate request.currentInput = some result ∧
      linkedOutstandingCents request.currentInput.payments request.command.paymentLinks
          (mutation.action :: request.currentInput.actions) ≤ result.shortfallCents := by
  obtain ⟨result, hEval, hBelow, hAmount, -⟩ :=
    applyCorrectionTransition_action_amount_eq_linked request mutation hMutation
  have hLinks := (applyCorrectionTransition_mutation_links request mutation hMutation).2.2.2.2.2.2
  have hCounted : mutation.action.kind = "CORRECTION_PAYMENT_REQUEST" ∧
      mutation.action.status ≠ .CANCELLED :=
    ⟨hLinks.correctionKind, by rw [hLinks.readyAction]; decide⟩
  refine ⟨result, hEval, ?_⟩
  have hLe : mutation.action.amountCents ≤ result.shortfallCents - linkedOutstandingCents
      request.currentInput.payments request.command.paymentLinks request.currentInput.actions := by
    rw [hAmount]; exact Nat.min_le_right _ _
  simp only [linkedOutstandingCents, if_pos hCounted]
  omega

end BlindLedger.Financial.CorrectionTransition
