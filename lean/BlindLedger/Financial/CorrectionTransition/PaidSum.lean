import BlindLedger.Financial.Codec

/-! Paid-so-far from the snapshot (design: docs/CORE_REDESIGN.md, "Lean paid
    sum").  `BLFCMD03` replaces the caller's `correctionPaid` totals with the
    payment-to-action links; Lean sums the active linked payment rows itself.

    The laws at the end are proved by summing `paidTerm` row by row. -/

namespace BlindLedger.Financial.CorrectionTransition

open BlindLedger.Financial

/-- One PAYMENT_RECEIVED link: payment row `paymentId` pays correction action
    `actionId`.  Sent only for linked rows, ascending by `paymentId`. -/
structure PaymentLink where
  paymentId : String
  actionId : String
deriving DecidableEq, Repr

def encodePaymentLink (link : PaymentLink) : Bytes :=
  encodeString link.paymentId ++ encodeString link.actionId

def readPaymentLink (bytes : Bytes) : Option (PaymentLink × Bytes) := do
  let (paymentId, rest) ← readString bytes
  let (actionId, rest) ← readString rest
  pure ({ paymentId := paymentId, actionId := actionId }, rest)

/-- At most one link per payment row, in canonical payment-ID order. -/
def paymentLinksWellFormed (links : List PaymentLink) : Bool :=
  canonicalIdList (links.map PaymentLink.paymentId) &&
    links.all (fun link => idWellFormed link.actionId)

/-! ## Specification (not executed: quadratic by design, for statements only) -/

/-- Every link names a payment row of the snapshot and a correction payment
    request of the snapshot.  Anything else is `INVALID_INPUT`. -/
def paymentLinksAdmissible (payments : List Payment) (actions : List ActionRecord)
    (links : List PaymentLink) : Bool :=
  links.all fun link =>
    payments.any (fun payment => payment.paymentId = link.paymentId) &&
      actions.any (fun action => action.actionId = link.actionId &&
        action.kind = "CORRECTION_PAYMENT_REQUEST")

/-- Cents of the active payment rows the links attribute to `actionId`. -/
def linkedActivePaidCents (payments : List Payment) (links : List PaymentLink)
    (actionId : String) : Nat :=
  ((payments.filter fun payment => payment.status = .ACTIVE &&
      links.any fun link => link.paymentId = payment.paymentId && link.actionId = actionId).map
    Payment.amountCents).sum

/-- `outstandingCorrectionCents` with the paid term derived from the rows. -/
def linkedOutstandingCents (payments : List Payment) (links : List PaymentLink) :
    List ActionRecord → Nat
  | [] => 0
  | action :: rest =>
      (if action.kind = "CORRECTION_PAYMENT_REQUEST" ∧ action.status ≠ .CANCELLED then
        action.amountCents - linkedActivePaidCents payments links action.actionId else 0) +
        linkedOutstandingCents payments links rest

/-- Tamper vocabulary for the laws below. -/
def reversePaymentRow (paymentId : String) (payments : List Payment) : List Payment :=
  payments.map fun payment =>
    if payment.paymentId = paymentId then { payment with status := .REVERSED } else payment

def retargetPaymentLink (paymentId actionId : String) (links : List PaymentLink) :
    List PaymentLink :=
  links.map fun link =>
    if link.paymentId = paymentId then { link with actionId := actionId } else link

/-! ## Row laws -/

/-- What one payment row contributes to `actionId`. -/
def paidTerm (links : List PaymentLink) (actionId : String) (payment : Payment) : Nat :=
  if payment.status = .ACTIVE ∧ ∃ link ∈ links,
      link.paymentId = payment.paymentId ∧ link.actionId = actionId then payment.amountCents else 0

theorem linkedActivePaidCents_eq_sum (payments : List Payment) (links : List PaymentLink)
    (actionId : String) :
    linkedActivePaidCents payments links actionId =
      (payments.map (paidTerm links actionId)).sum := by
  unfold linkedActivePaidCents
  induction payments with
  | nil => rfl
  | cons payment rest ih =>
      by_cases h : payment.status = .ACTIVE ∧ ∃ link ∈ links,
          link.paymentId = payment.paymentId ∧ link.actionId = actionId
      · simp [paidTerm, h, ih]
      · have h' : ¬ (decide (payment.status = .ACTIVE) &&
            links.any fun link => decide (link.paymentId = payment.paymentId) &&
              decide (link.actionId = actionId)) = true := by
          simpa [List.any_eq_true] using h
        simp [paidTerm, h, ih]

private theorem nodup_of_map_nodup {α β : Type} (f : α → β) {l : List α}
    (h : (l.map f).Nodup) : l.Nodup :=
  List.Pairwise.of_map f (fun _ _ hne hab => hne (congrArg f hab)) h

private theorem inj_of_map_nodup {α β : Type} (f : α → β) :
    ∀ {l : List α}, (l.map f).Nodup → ∀ {x y : α}, x ∈ l → y ∈ l → f x = f y → x = y
  | [], _, _, _, hx, _, _ => nomatch hx
  | a :: l, h, x, y, hx, hy, hxy => by
      obtain ⟨hna, hl⟩ := List.nodup_cons.1 h
      rcases List.mem_cons.1 hx with hxa | hx' <;> rcases List.mem_cons.1 hy with hya | hy'
      · exact hxa.trans hya.symm
      · exact absurd (hxa ▸ hxy ▸ List.mem_map_of_mem (f := f) hy') hna
      · exact absurd (hya ▸ hxy ▸ List.mem_map_of_mem (f := f) hx') hna
      · exact inj_of_map_nodup f hl hx' hy' hxy

private theorem sum_map_swap {α : Type} (l : List α) (F G : α → Nat) (x : α) (hx : x ∈ l)
    (hNodup : l.Nodup) (hAgree : ∀ y ∈ l, y ≠ x → F y = G y) :
    (l.map F).sum + G x = (l.map G).sum + F x := by
  induction l with
  | nil => cases hx
  | cons y ys ih =>
      obtain ⟨hy, hys⟩ := List.nodup_cons.1 hNodup
      rcases List.mem_cons.1 hx with rfl | hxs
      · have hTail : ys.map F = ys.map G := List.map_congr_left fun z hz =>
          hAgree z (List.mem_cons_of_mem _ hz) fun hzy => hy (hzy ▸ hz)
        simp only [List.map_cons, List.sum_cons, hTail]
        omega
      · have hHead : F y = G y := hAgree y (List.mem_cons_self ..) fun hyx => hy (hyx ▸ hxs)
        have := ih hxs hys fun z hz => hAgree z (List.mem_cons_of_mem _ hz)
        simp only [List.map_cons, List.sum_cons, hHead]
        omega

/-- Rows with distinct ids are distinct rows. -/
private theorem row_ne {payments : List Payment} (hRows : (payments.map Payment.paymentId).Nodup)
    {y x : Payment} (hy : y ∈ payments) (hx : x ∈ payments) (hne : y ≠ x) :
    y.paymentId ≠ x.paymentId := fun hId => hne (inj_of_map_nodup _ hRows hy hx hId)

/-- A link is determined by its row. -/
private theorem link_of_row {links : List PaymentLink}
    (hLinks : (links.map PaymentLink.paymentId).Nodup) {l m : PaymentLink}
    (hl : l ∈ links) (hm : m ∈ links) (hId : l.paymentId = m.paymentId) : l = m :=
  inj_of_map_nodup _ hLinks hl hm hId

theorem sum_map_zero {α : Type} (l : List α) (f : α → Nat) (h : ∀ b ∈ l, f b = 0) :
    (l.map f).sum = 0 := by
  induction l with
  | nil => rfl
  | cons b bs ih =>
      simp only [List.map_cons, List.sum_cons, h b (List.mem_cons_self ..),
        ih fun c hc => h c (List.mem_cons_of_mem _ hc)]

private theorem sum_map_add {α : Type} (l : List α) (f g : α → Nat) :
    (l.map fun a => f a + g a).sum = (l.map f).sum + (l.map g).sum := by
  induction l with
  | nil => rfl
  | cons a as ih => simp only [List.map_cons, List.sum_cons, ih]; omega

private theorem sum_filter_map {α : Type} (l : List α) (p : α → Bool) (f : α → Nat) :
    ((l.filter p).map f).sum = (l.map fun x => if p x = true then f x else 0).sum := by
  induction l with
  | nil => rfl
  | cons x xs ih =>
      by_cases h : p x = true
      · simp [h, ih]
      · simp [h, ih]

/-- At most one `a` satisfies `c`, and each `a` is listed once. -/
private theorem sum_ite_le {α : Type} (as : List α) (c : α → Prop) [DecidablePred c] (x : Nat)
    (hNodup : as.Nodup) (hUniq : ∀ a b, c a → c b → a = b) :
    (as.map fun a => if c a then x else 0).sum ≤ x := by
  induction as with
  | nil => simp
  | cons a as ih =>
      obtain ⟨ha, has⟩ := List.nodup_cons.1 hNodup
      by_cases hc : c a
      · have hTail : (as.map fun a => if c a then x else 0).sum = 0 :=
          sum_map_zero _ _ fun b hb => by
            by_cases hcb : c b
            · exact absurd (hUniq b a hcb hc ▸ hb) ha
            · simp [hcb]
        simp [hc, hTail]
      · have := ih has
        simp [hc, this]

private theorem total_le_aux (links : List PaymentLink) (actionIds : List String)
    (hActions : actionIds.Nodup) (hLinks : (links.map PaymentLink.paymentId).Nodup) :
    ∀ ps : List Payment, (actionIds.map fun a => (ps.map (paidTerm links a)).sum).sum ≤
      (ps.map fun p => if p.status = .ACTIVE then p.amountCents else 0).sum
  | [] => by
      simp only [List.map_nil, List.sum_nil]
      exact Nat.le_of_eq (sum_map_zero _ _ fun _ _ => rfl)
  | p :: ps => by
      have ih := total_le_aux links actionIds hActions hLinks ps
      have hHead : (actionIds.map fun a => paidTerm links a p).sum ≤
          if p.status = .ACTIVE then p.amountCents else 0 := by
        by_cases hActive : p.status = .ACTIVE
        · rw [if_pos hActive]
          have hRow : ∀ a, paidTerm links a p =
              if (∃ link ∈ links, link.paymentId = p.paymentId ∧ link.actionId = a) then
                p.amountCents else 0 := fun a => by
            by_cases hc : ∃ link ∈ links, link.paymentId = p.paymentId ∧ link.actionId = a
            · rw [paidTerm, if_pos ⟨hActive, hc⟩, if_pos hc]
            · rw [paidTerm, if_neg (fun h => hc h.2), if_neg hc]
          rw [List.map_congr_left fun a _ => hRow a]
          exact sum_ite_le actionIds
            (fun a => ∃ link ∈ links, link.paymentId = p.paymentId ∧ link.actionId = a)
            p.amountCents hActions fun a b ⟨l, hl, h1, h2⟩ ⟨m, hm, h3, h4⟩ =>
              h2.symm.trans ((congrArg PaymentLink.actionId
                (link_of_row hLinks hl hm (h1.trans h3.symm))).trans h4)
        · rw [if_neg hActive]
          exact Nat.le_of_eq (sum_map_zero _ _ fun a _ => by
            rw [paidTerm, if_neg (fun h => hActive h.1)])
      have hSplit : (actionIds.map fun a => ((p :: ps).map (paidTerm links a)).sum) =
          actionIds.map fun a => paidTerm links a p + (ps.map (paidTerm links a)).sum := rfl
      rw [hSplit, sum_map_add]
      simp only [List.map_cons, List.sum_cons]
      omega

/-- Reversing a linked active row lowers exactly its action's paid-so-far by
    exactly its amount; every other action is unchanged. -/
theorem linkedActivePaidCents_reverse (payments : List Payment) (links : List PaymentLink)
    (payment : Payment) (actionId other : String)
    (hRows : (payments.map Payment.paymentId).Nodup)
    (hLinks : (links.map PaymentLink.paymentId).Nodup)
    (hMember : payment ∈ payments) (hActive : payment.status = .ACTIVE)
    (hLinked : (⟨payment.paymentId, actionId⟩ : PaymentLink) ∈ links) :
    linkedActivePaidCents (reversePaymentRow payment.paymentId payments) links other +
        (if other = actionId then payment.amountCents else 0) =
      linkedActivePaidCents payments links other := by
  have hIff : (∃ link ∈ links, link.paymentId = payment.paymentId ∧ link.actionId = other) ↔
      other = actionId :=
    ⟨fun ⟨link, hl, hId, hAction⟩ => hAction.symm.trans
        (congrArg PaymentLink.actionId (link_of_row hLinks hl hLinked hId)),
      fun h => ⟨_, hLinked, rfl, h.symm⟩⟩
  have hSwap := sum_map_swap payments (paidTerm links other)
    (fun p => paidTerm links other (if p.paymentId = payment.paymentId then
      { p with status := .REVERSED } else p)) payment hMember
    (nodup_of_map_nodup _ hRows) (fun y hy hne => by
      simp [paidTerm, if_neg (row_ne hRows hy hMember hne)])
  have hHere : paidTerm links other payment = if other = actionId then payment.amountCents else 0 := by
    by_cases h : other = actionId
    · rw [paidTerm, if_pos ⟨hActive, hIff.2 h⟩, if_pos h]
    · rw [paidTerm, if_neg (fun hc => h (hIff.1 hc.2)), if_neg h]
  have hGone : paidTerm links other { payment with status := .REVERSED } = 0 := by
    simp [paidTerm]
  simp only [linkedActivePaidCents_eq_sum, reversePaymentRow, List.map_map, Function.comp_def]
  rw [if_pos rfl, hGone, hHere] at hSwap
  omega

/-- Moving a link moves exactly the row's amount from the old action to the
    new one; every other action is unchanged. -/
theorem linkedActivePaidCents_retarget (payments : List Payment) (links : List PaymentLink)
    (payment : Payment) (fromId toId other : String)
    (hRows : (payments.map Payment.paymentId).Nodup)
    (hLinks : (links.map PaymentLink.paymentId).Nodup)
    (hMember : payment ∈ payments) (hActive : payment.status = .ACTIVE)
    (hLinked : (⟨payment.paymentId, fromId⟩ : PaymentLink) ∈ links) :
    linkedActivePaidCents payments (retargetPaymentLink payment.paymentId toId links) other +
        (if other = fromId then payment.amountCents else 0) =
      linkedActivePaidCents payments links other +
        (if other = toId then payment.amountCents else 0) := by
  have hIffFrom : (∃ link ∈ links, link.paymentId = payment.paymentId ∧ link.actionId = other) ↔
      other = fromId :=
    ⟨fun ⟨link, hl, hId, hAction⟩ => hAction.symm.trans
        (congrArg PaymentLink.actionId (link_of_row hLinks hl hLinked hId)),
      fun h => ⟨_, hLinked, rfl, h.symm⟩⟩
  have hIffTo : (∃ link ∈ retargetPaymentLink payment.paymentId toId links,
      link.paymentId = payment.paymentId ∧ link.actionId = other) ↔ other = toId := by
    constructor
    · rintro ⟨link, hl, hId, hAction⟩
      obtain ⟨old, _, rfl⟩ := List.mem_map.1 hl
      by_cases hc : old.paymentId = payment.paymentId
      · simp only [if_pos hc] at hAction
        exact hAction.symm
      · simp only [if_neg hc] at hId
        exact absurd hId hc
    · intro h
      refine ⟨_, List.mem_map_of_mem (f := fun link : PaymentLink =>
        if link.paymentId = payment.paymentId then { link with actionId := toId } else link)
        hLinked, by simp, by simp [h]⟩
  have hHere : paidTerm links other payment = if other = fromId then payment.amountCents else 0 := by
    by_cases h : other = fromId
    · rw [paidTerm, if_pos ⟨hActive, hIffFrom.2 h⟩, if_pos h]
    · rw [paidTerm, if_neg (fun hc => h (hIffFrom.1 hc.2)), if_neg h]
  have hThere : paidTerm (retargetPaymentLink payment.paymentId toId links) other payment =
      if other = toId then payment.amountCents else 0 := by
    by_cases h : other = toId
    · rw [paidTerm, if_pos ⟨hActive, hIffTo.2 h⟩, if_pos h]
    · rw [paidTerm, if_neg (fun hc => h (hIffTo.1 hc.2)), if_neg h]
  have hAgree : ∀ y ∈ payments, y ≠ payment → paidTerm links other y =
      paidTerm (retargetPaymentLink payment.paymentId toId links) other y := by
    intro y hy hne
    have hId := row_ne hRows hy hMember hne
    have hIffY : (∃ link ∈ links, link.paymentId = y.paymentId ∧ link.actionId = other) ↔
        ∃ link ∈ retargetPaymentLink payment.paymentId toId links,
          link.paymentId = y.paymentId ∧ link.actionId = other := by
      constructor
      · rintro ⟨link, hl, h1, h2⟩
        have hc : ¬ link.paymentId = payment.paymentId := fun hc => hId (h1.symm.trans hc)
        refine ⟨link, ?_, h1, h2⟩
        have hm : (if link.paymentId = payment.paymentId then { link with actionId := toId }
            else link) ∈ retargetPaymentLink payment.paymentId toId links :=
          List.mem_map_of_mem hl
        rwa [if_neg hc] at hm
      · rintro ⟨link, hl, h1, h2⟩
        obtain ⟨old, hOld, rfl⟩ := List.mem_map.1 hl
        by_cases hc : old.paymentId = payment.paymentId
        · simp only [if_pos hc] at h1
          exact absurd (hc.symm.trans h1) (Ne.symm hId)
        · simp only [if_neg hc] at h1 h2
          exact ⟨old, hOld, h1, h2⟩
    unfold paidTerm
    by_cases hc : y.status = .ACTIVE ∧
        ∃ link ∈ links, link.paymentId = y.paymentId ∧ link.actionId = other
    · rw [if_pos hc, if_pos ⟨hc.1, hIffY.1 hc.2⟩]
    · rw [if_neg hc, if_neg (fun h => hc ⟨h.1, hIffY.2 h.2⟩)]
  have hSwap := sum_map_swap payments (paidTerm links other)
    (paidTerm (retargetPaymentLink payment.paymentId toId links) other) payment hMember
    (nodup_of_map_nodup _ hRows) hAgree
  simp only [linkedActivePaidCents_eq_sum]
  rw [hHere, hThere] at hSwap
  omega

/-- No cent is invented or counted twice: over distinct actions, paid-so-far
    never exceeds the active cash in the snapshot. -/
theorem linkedActivePaidCents_total_le_active (payments : List Payment)
    (links : List PaymentLink) (actionIds : List String)
    (hActions : actionIds.Nodup) (hLinks : (links.map PaymentLink.paymentId).Nodup) :
    (actionIds.map (linkedActivePaidCents payments links)).sum ≤
      ((payments.filter fun payment => payment.status = .ACTIVE).map Payment.amountCents).sum := by
  have hFun : linkedActivePaidCents payments links =
      fun a => (payments.map (paidTerm links a)).sum :=
    funext (linkedActivePaidCents_eq_sum payments links)
  rw [hFun, sum_filter_map]
  simp only [decide_eq_true_eq]
  exact total_le_aux links actionIds hActions hLinks payments

end BlindLedger.Financial.CorrectionTransition
