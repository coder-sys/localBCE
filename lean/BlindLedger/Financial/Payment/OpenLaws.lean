import BlindLedger.Financial.Payment.Open
import BlindLedger.Financial.Payment.Bridge

namespace BlindLedger.Financial.Payment

open BlindLedger.Financial BlindLedger.Financial.CorrectionTransition

/-! R2 laws (design `r2-request-shrink-v1.md` section 7, statements 1-5): the open amounts add up
    to the outstanding requests capped by the balance, and paying one request moves only that
    request.  Kept out of `Open.lean` so a proof edit never touches a module the worker imports. -/

private theorem servedBefore_irrefl (a : ActionRecord) : servedBefore a a = false := by
  simp [servedBefore]

private theorem servedBefore_trans {a b c : ActionRecord} (h1 : servedBefore a b = true)
    (h2 : servedBefore b c = true) : servedBefore a c = true := by
  simp only [servedBefore, Bool.or_eq_true, decide_eq_true_eq, Bool.and_eq_true, beq_iff_eq] at *
  rcases h1 with h1 | ⟨e1, l1⟩ <;> rcases h2 with h2 | ⟨e2, l2⟩
  · left; omega
  · left; omega
  · left; omega
  · right; exact ⟨by omega, String.lt_trans l1 l2⟩

private theorem servedBefore_total {a b : ActionRecord} (h : a.actionId ≠ b.actionId) :
    servedBefore a b = true ∨ servedBefore b a = true := by
  simp only [servedBefore, Bool.or_eq_true, decide_eq_true_eq, Bool.and_eq_true, beq_iff_eq]
  by_cases h1 : a.revision < b.revision
  · exact Or.inl (Or.inl h1)
  by_cases h2 : b.revision < a.revision
  · exact Or.inr (Or.inl h2)
  have he : a.revision = b.revision := by omega
  by_cases l1 : a.actionId < b.actionId
  · exact Or.inl (Or.inr ⟨he, l1⟩)
  by_cases l2 : b.actionId < a.actionId
  · exact Or.inr (Or.inr ⟨he.symm, l2⟩)
  exact absurd (String.le_antisymm (String.not_lt.1 l2) (String.not_lt.1 l1)) h

private theorem nodup_of_map {α β : Type} {f : α → β} : ∀ {l : List α}, (l.map f).Nodup → l.Nodup
  | [], _ => List.nodup_nil
  | b :: t, h => by
    rw [List.map_cons, List.nodup_cons] at h
    exact List.nodup_cons.2 ⟨fun hb => h.1 (List.mem_map_of_mem hb), nodup_of_map h.2⟩

private theorem sum_le_of {α : Type} (f g : α → Nat) :
    ∀ l : List α, (∀ a ∈ l, f a ≤ g a) → (l.map f).sum ≤ (l.map g).sum
  | [], _ => by simp
  | b :: t, h => by
    have := sum_le_of f g t fun a ha => h a (List.mem_cons_of_mem _ ha)
    have := h b (List.mem_cons_self ..)
    simp only [List.map_cons, List.sum_cons]; omega

private theorem eq_of_sum_eq {α : Type} (f g : α → Nat) :
    ∀ l : List α, (∀ a ∈ l, f a ≤ g a) → (l.map f).sum = (l.map g).sum → ∀ a ∈ l, f a = g a
  | [], _, _, a, ha => by simp at ha
  | b :: t, h, hs, a, ha => by
    have h1 := sum_le_of f g t fun a ha => h a (List.mem_cons_of_mem _ ha)
    have h2 := h b (List.mem_cons_self ..)
    simp only [List.map_cons, List.sum_cons] at hs
    rcases List.mem_cons.1 ha with rfl | ha'
    · omega
    · exact eq_of_sum_eq f g t (fun a ha => h a (List.mem_cons_of_mem _ ha)) (by omega) a ha'

private theorem sum_map_filter_zero {α : Type} (p : α → Bool) (f : α → Nat) :
    ∀ l : List α, (∀ a ∈ l, p a = false → f a = 0) → (l.map f).sum = ((l.filter p).map f).sum
  | [], _ => by simp
  | b :: t, h => by
    have ih := sum_map_filter_zero p f t fun a ha => h a (List.mem_cons_of_mem _ ha)
    by_cases hp : p b = true
    · simp [List.filter_cons, hp, ih]
    · have hp' : p b = false := by simpa using hp
      have := h b (List.mem_cons_self ..) hp'
      simp [List.filter_cons, hp, ih, this]

private theorem sum_filter_mono {α : Type} (p q : α → Bool) (u : α → Nat)
    (h : ∀ b, p b = true → q b = true) :
    ∀ l : List α, ((l.filter p).map u).sum ≤ ((l.filter q).map u).sum
  | [] => by simp
  | b :: t => by
    have := sum_filter_mono p q u h t
    by_cases hp : p b = true
    · have hq := h b hp
      simp [List.filter_cons, hp, hq] <;> omega
    · by_cases hq : q b = true
      · simp [List.filter_cons, hp, hq] <;> omega
      · simp [List.filter_cons, hp, hq] <;> omega

private theorem sum_filter_add_le {α : Type} (p q : α → Bool) (u : α → Nat)
    (h : ∀ b, p b = true → q b = true) {x : α} (hq : q x = true) (hp : p x = false) :
    ∀ l : List α, x ∈ l → ((l.filter p).map u).sum + u x ≤ ((l.filter q).map u).sum
  | [], hx => by simp at hx
  | b :: t, hx => by
    rcases List.mem_cons.1 hx with rfl | hx'
    · have := sum_filter_mono p q u h t
      simp [List.filter_cons, hp, hq] <;> omega
    · have := sum_filter_add_le p q u h hq hp t hx'
      by_cases hpb : p b = true
      · have hqb := h b hpb
        simp [List.filter_cons, hpb, hqb] <;> omega
      · by_cases hqb : q b = true
        · simp [List.filter_cons, hpb, hqb] <;> omega
        · simp [List.filter_cons, hpb, hqb] <;> omega

private theorem exists_max {α : Type} (lt : α → α → Bool)
    (htrans : ∀ a b c, lt a b = true → lt b c = true → lt a c = true) :
    ∀ l : List α, l ≠ [] → (∀ a ∈ l, ∀ b ∈ l, a ≠ b → lt a b = true ∨ lt b a = true) →
      ∃ m ∈ l, ∀ b ∈ l, b ≠ m → lt b m = true
  | [], h, _ => absurd rfl h
  | [h], _, _ => ⟨h, List.mem_cons_self .., fun b hb hne => absurd (List.mem_singleton.1 hb) hne⟩
  | h :: t, _, htot => by
    by_cases ht : t = []
    · subst ht
      exact ⟨h, List.mem_cons_self .., fun b hb hne => absurd (List.mem_singleton.1 hb) hne⟩
    obtain ⟨m', hm', hmax⟩ := exists_max lt htrans t ht
      fun a ha b hb => htot a (List.mem_cons_of_mem _ ha) b (List.mem_cons_of_mem _ hb)
    by_cases hh : h = m'
    · subst hh
      refine ⟨h, List.mem_cons_self .., fun b hb hne => ?_⟩
      rcases List.mem_cons.1 hb with rfl | hb'
      · exact absurd rfl hne
      · exact hmax b hb' hne
    · rcases htot h (List.mem_cons_self ..) m' (List.mem_cons_of_mem _ hm') hh with hlt | hlt
      · refine ⟨m', List.mem_cons_of_mem _ hm', fun b hb hne => ?_⟩
        rcases List.mem_cons.1 hb with rfl | hb'
        · exact hlt
        · exact hmax b hb' hne
      · refine ⟨h, List.mem_cons_self .., fun b hb hne => ?_⟩
        rcases List.mem_cons.1 hb with rfl | hb'
        · exact absurd rfl hne
        · by_cases hbm : b = m'
          · subst hbm; exact hlt
          · exact htrans b m' h (hmax b hb' hbm) hlt

/-- The allocation identity over a list of distinct elements in a total order. -/
private theorem sum_open_gen {α : Type} [DecidableEq α] (u : α → Nat) (lt : α → α → Bool) (s : Nat)
    (hirr : ∀ a, lt a a = false)
    (htrans : ∀ a b c, lt a b = true → lt b c = true → lt a c = true) :
    ∀ (n : Nat) (ys : List α), ys.length = n → ys.Nodup →
      (∀ a ∈ ys, ∀ b ∈ ys, a ≠ b → lt a b = true ∨ lt b a = true) →
      (ys.map fun a => min (u a) (s - ((ys.filter (lt · a)).map u).sum)).sum =
        min (ys.map u).sum s
  | 0, ys, hl, _, _ => by
    have : ys = [] := List.length_eq_zero_iff.1 hl
    subst this; simp
  | n + 1, ys, hl, hnd, htot => by
    have hne : ys ≠ [] := by intro h; subst h; simp at hl
    obtain ⟨m, hm, hmax⟩ := exists_max lt htrans ys hne htot
    have hperm := List.perm_cons_erase hm
    have hlen : (ys.erase m).length = n := by rw [List.length_erase_of_mem hm]; omega
    have hnd' : (ys.erase m).Nodup := hnd.erase m
    have hmem : ∀ a ∈ ys.erase m, a ≠ m ∧ a ∈ ys := fun a ha => (hnd.mem_erase_iff.1 ha)
    have ih := sum_open_gen u lt s hirr htrans n (ys.erase m) hlen hnd'
      fun a ha b hb => htot a (hmem a ha).2 b (hmem b hb).2
    have F1 : ∀ a ∈ ys.erase m, lt m a = false := by
      intro a ha
      cases hc : lt m a
      · rfl
      · have h1 := hmax a (hmem a ha).2 (hmem a ha).1
        have := htrans a m a h1 hc
        simp [hirr a] at this
    have F2 : ∀ a ∈ ys.erase m,
        ((ys.filter (lt · a)).map u).sum = (((ys.erase m).filter (lt · a)).map u).sum := by
      intro a ha
      rw [(((hperm.filter _).map u)).sum_nat]
      simp [List.filter_cons, F1 a ha]
    have F3 : ((ys.filter (lt · m)).map u).sum = ((ys.erase m).map u).sum := by
      rw [(((hperm.filter _).map u)).sum_nat]
      have : (ys.erase m).filter (lt · m) = ys.erase m :=
        List.filter_eq_self.2 fun b hb => hmax b (hmem b hb).2 (hmem b hb).1
      simp [List.filter_cons, hirr m, this]
    have F4 : (ys.erase m).map (fun a => min (u a) (s - ((ys.filter (lt · a)).map u).sum)) =
        (ys.erase m).map (fun a => min (u a) (s - (((ys.erase m).filter (lt · a)).map u).sum)) :=
      List.map_congr_left (fun a ha => by rw [F2 a ha])
    rw [(hperm.map _).sum_nat, List.map_cons, List.sum_cons, F4, ih, F3,
      (hperm.map u).sum_nat, List.map_cons, List.sum_cons]
    omega

private theorem countedRequest_iff (x : ActionRecord) :
    countedRequest x = true ↔ (x.kind = "CORRECTION_PAYMENT_REQUEST" ∧ x.status ≠ .CANCELLED) := by
  simp [countedRequest]

private theorem linkedOutstanding_map (ps : List Payment) (ls : List PaymentLink) :
    ∀ xs : List ActionRecord, linkedOutstandingCents ps ls xs =
      (xs.map fun x => if countedRequest x = true then unpaidOf ps ls x else 0).sum
  | [] => rfl
  | x :: t => by
    simp only [linkedOutstandingCents, List.map_cons, List.sum_cons, linkedOutstanding_map ps ls t,
      countedRequest_iff, unpaidOf]

private theorem linkedOutstanding_filter (ps : List Payment) (ls : List PaymentLink)
    (xs : List ActionRecord) :
    linkedOutstandingCents ps ls xs = ((xs.filter countedRequest).map (unpaidOf ps ls)).sum := by
  rw [linkedOutstanding_map, sum_map_filter_zero countedRequest _ xs
    (fun a _ h => by simp [h])]
  congr 1
  apply List.map_congr_left
  intro a ha
  simp [(List.mem_filter.1 ha).2]

private theorem unpaidBefore_eq (ps : List Payment) (ls : List PaymentLink) (xs : List ActionRecord)
    (a : ActionRecord) :
    unpaidBefore ps ls xs a =
      (((xs.filter countedRequest).filter (servedBefore · a)).map (unpaidOf ps ls)).sum := by
  simp [unpaidBefore, List.filter_filter, Bool.and_comm]

/-- 1. The allocation identity: the open amounts add up to the outstanding requests, capped by
    the balance.  The substance of R2; statements 2, 3, 4 and 8 follow from it. -/
theorem openTotal_eq_min (s : Nat) (ps : List Payment) (ls : List PaymentLink)
    (xs : List ActionRecord) (hn : (xs.map ActionRecord.actionId).Nodup) :
    openTotal s ps ls xs = min (linkedOutstandingCents ps ls xs) s := by
  have hnd : xs.Nodup := nodup_of_map hn
  have hys : (xs.filter countedRequest).Nodup := hnd.filter _
  have htot : ∀ a ∈ xs.filter countedRequest, ∀ b ∈ xs.filter countedRequest, a ≠ b →
      servedBefore a b = true ∨ servedBefore b a = true := by
    intro a ha b hb hab
    refine servedBefore_total fun he => hab ?_
    exact eq_of_nodup_map hn (List.mem_filter.1 ha).1 (List.mem_filter.1 hb).1 he
  have key := sum_open_gen (unpaidOf ps ls) servedBefore s servedBefore_irrefl
    (fun _ _ _ => servedBefore_trans) _ (xs.filter countedRequest) rfl hys htot
  unfold openTotal
  rw [sum_map_filter_zero countedRequest _ xs (fun a _ h => by simp [openCents, h]),
    linkedOutstanding_filter, ← key]
  congr 1
  apply List.map_congr_left
  intro a ha
  simp only [openCents, (List.mem_filter.1 ha).2, ↓reduceIte, unpaidBefore_eq]

/-- Both caps of the open amount: the balance and the request's own unpaid part. -/
theorem openCents_le (s : Nat) (ps : List Payment) (ls : List PaymentLink) (xs : List ActionRecord)
    (a : ActionRecord) :
    openCents s ps ls xs a ≤ s ∧ openCents s ps ls xs a ≤ unpaidOf ps ls a := by
  unfold openCents
  split <;> omega

/-- 2. The literal core-theorems item-1 invariant, for every state Lean evaluates, whatever
    command produced it (payment, reversal, correction or offset authorization).  From 1: `evaluate`
    answers only well-formed inputs, whose action ids are distinct (`nodup_actions_of_wf`). -/
theorem requests_within_balance (i : FinancialInput) (res : FinancialResult) (ls : List PaymentLink)
    (h : evaluate i = some res) :
    openTotal res.shortfallCents i.payments ls i.actions ≤ res.shortfallCents := by
  have hwf : financialInputWellFormed i = true := by
    cases hc : financialInputWellFormed i
    · simp [evaluate, hc] at h
    · rfl
  rw [openTotal_eq_min _ _ _ _ (nodup_actions_of_wf hwf)]
  omega

/-- 3. R2 is invisible while the requests fit the balance, in particular right after every
    correction (with T1.1, `applyCorrectionTransition_post_within_shortfall`). -/
theorem openCents_eq_unpaid_of_within (s : Nat) (ps : List Payment) (ls : List PaymentLink)
    (xs : List ActionRecord) (hn : (xs.map ActionRecord.actionId).Nodup)
    (hw : linkedOutstandingCents ps ls xs ≤ s) {a : ActionRecord} (ha : a ∈ xs)
    (hc : countedRequest a = true) :
    openCents s ps ls xs a = unpaidOf ps ls a := by
  have hsum : (xs.map (openCents s ps ls xs)).sum =
      (xs.map fun x => if countedRequest x = true then unpaidOf ps ls x else 0).sum := by
    rw [← linkedOutstanding_map]
    have := openTotal_eq_min s ps ls xs hn
    unfold openTotal at this
    rw [this]; omega
  have hle : ∀ x ∈ xs, openCents s ps ls xs x ≤
      (fun x => if countedRequest x = true then unpaidOf ps ls x else 0) x := by
    intro x _
    by_cases hx : countedRequest x = true
    · simpa [hx] using (openCents_le s ps ls xs x).2
    · simp [hx, openCents]
  simpa [hc] using eq_of_sum_eq _ _ xs hle hsum a ha

/-- 4. The pinned correction engine already decides by open amounts: its refusal
    `NO_REQUESTABLE_BALANCE` and its new request amount (`amountRule`, through
    `outstandingCorrectionCents_eq_linked`) are unchanged when outstanding requests are replaced by
    their open total.  No engine change and no re-pin. -/
theorem engine_requestable_agrees (s : Nat) (ps : List Payment) (ls : List PaymentLink)
    (xs : List ActionRecord) (hn : (xs.map ActionRecord.actionId).Nodup) :
    (linkedOutstandingCents ps ls xs < s ↔ openTotal s ps ls xs < s) ∧
      s - linkedOutstandingCents ps ls xs = s - openTotal s ps ls xs := by
  rw [openTotal_eq_min s ps ls xs hn]
  omega

private theorem sum_filter_pull {α : Type} [DecidableEq α] (p : α → Bool) (f : α → Nat) {a : α}
    {l : List α} (ha : a ∈ l) :
    ((l.filter p).map f).sum =
      (if p a = true then f a else 0) + (((l.erase a).filter p).map f).sum := by
  rw [(((List.perm_cons_erase ha).filter p).map f).sum_nat]
  by_cases h : p a = true <;> simp [List.filter_cons, h]

/-- 5. Paying request `a` by at most its open amount lowers `a`'s open amount by exactly the
    payment and leaves every other request's open amount unchanged. -/
theorem openCents_pay_local (s m : Nat) (ps ps' : List Payment) (ls ls' : List PaymentLink)
    (xs : List ActionRecord) (hn : (xs.map ActionRecord.actionId).Nodup)
    {a : ActionRecord} (ha : a ∈ xs) (hm : m ≤ openCents s ps ls xs a)
    (hpaid : ∀ x ∈ xs, linkedActivePaidCents ps' ls' x.actionId =
      linkedActivePaidCents ps ls x.actionId + (if x.actionId = a.actionId then m else 0)) :
    ∀ x ∈ xs, openCents (s - m) ps' ls' xs x + (if x.actionId = a.actionId then m else 0) =
      openCents s ps ls xs x := by
  have hnd : xs.Nodup := nodup_of_map hn
  have hle := openCents_le s ps ls xs a
  have hma : m ≤ unpaidOf ps ls a := by omega
  have hid : ∀ x ∈ xs, x.actionId = a.actionId → x = a := fun x hx h => eq_of_nodup_map hn hx ha h
  have hu : ∀ x ∈ xs, unpaidOf ps' ls' x + (if x.actionId = a.actionId then m else 0) =
      unpaidOf ps ls x := by
    intro x hx
    unfold unpaidOf
    rw [hpaid x hx]
    by_cases h : x.actionId = a.actionId
    · have hma' : m ≤ x.amountCents - linkedActivePaidCents ps ls x.actionId := by
        have := hid x hx h; subst this; exact hma
      rw [if_pos h]; omega
    · simp [h]
  have hR : ∀ b ∈ xs.erase a, unpaidOf ps' ls' b = unpaidOf ps ls b := by
    intro b hb
    obtain ⟨hba, hbx⟩ := hnd.mem_erase_iff.1 hb
    have hne : b.actionId ≠ a.actionId := fun e => hba (hid b hbx e)
    have := hu b hbx
    simp only [hne, ↓reduceIte] at this
    omega
  have hua : unpaidOf ps' ls' a + m = unpaidOf ps ls a := by simpa using hu a ha
  have W : ∀ x, unpaidBefore ps' ls' xs x +
      (if (countedRequest a && servedBefore a x) = true then m else 0) = unpaidBefore ps ls xs x := by
    intro x
    unfold unpaidBefore
    rw [sum_filter_pull _ (unpaidOf ps' ls') ha, sum_filter_pull _ (unpaidOf ps ls) ha]
    have hRsum : (((xs.erase a).filter fun b => countedRequest b && servedBefore b x).map
        (unpaidOf ps' ls')).sum = (((xs.erase a).filter fun b => countedRequest b && servedBefore b x).map
        (unpaidOf ps ls)).sum := by
      congr 1
      apply List.map_congr_left
      intro b hb
      exact hR b (List.mem_filter.1 hb).1
    by_cases hp : (countedRequest a && servedBefore a x) = true
    · simp only [hp, ↓reduceIte]; omega
    · simp only [hp, Bool.false_eq_true, ↓reduceIte]; omega
  have hmb : m = 0 ∨ (countedRequest a = true ∧ m ≤ unpaidOf ps ls a ∧
      m ≤ s - unpaidBefore ps ls xs a) := by
    by_cases hca : countedRequest a = true
    · right
      simp only [openCents, hca, ↓reduceIte] at hm
      exact ⟨hca, by omega, by omega⟩
    · left
      simp only [openCents, hca, Bool.false_eq_true, ↓reduceIte] at hm
      omega
  intro x hx
  by_cases hcx : countedRequest x = true
  · simp only [openCents, hcx, ↓reduceIte]
    have hux := hu x hx
    have hWx := W x
    by_cases hxa : x.actionId = a.actionId
    · have hxa' := hid x hx hxa
      rw [← hxa'] at hWx hmb
      simp only [servedBefore_irrefl, Bool.and_false, Bool.false_eq_true, ↓reduceIte] at hWx
      simp only [hxa, ↓reduceIte] at hux ⊢
      rcases hmb with h0 | ⟨-, h1, h2⟩ <;> omega
    · simp only [hxa, ↓reduceIte] at hux ⊢
      by_cases hlt : (countedRequest a && servedBefore a x) = true
      · simp only [hlt, ↓reduceIte] at hWx
        omega
      · simp only [hlt, Bool.false_eq_true, ↓reduceIte] at hWx
        rcases hmb with h0 | ⟨hca, h1, h2⟩
        · omega
        · have hlt' : servedBefore x a = true := by
            rcases servedBefore_total hxa with h | h
            · exact h
            · exact absurd (by simp [hca, h]) hlt
          have hle' : unpaidBefore ps ls xs x + unpaidOf ps ls x ≤ unpaidBefore ps ls xs a :=
            sum_filter_add_le (fun b => countedRequest b && servedBefore b x)
              (fun b => countedRequest b && servedBefore b a) (unpaidOf ps ls)
              (by
                intro b hb
                simp only [Bool.and_eq_true] at hb ⊢
                exact ⟨hb.1, servedBefore_trans hb.2 hlt'⟩)
              (by simp [hcx, hlt']) (by simp [servedBefore_irrefl]) xs hx
          omega
  · simp only [openCents, hcx, Bool.false_eq_true, ↓reduceIte]
    by_cases hxa : x.actionId = a.actionId
    · have hxa' := hid x hx hxa
      rw [← hxa'] at hmb
      rcases hmb with h0 | ⟨hca, -, -⟩
      · simp [hxa, h0]
      · exact absurd hca hcx
    · simp [hxa]

end BlindLedger.Financial.Payment
