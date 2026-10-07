import BlindLedger.Financial.Payment.Batch
import BlindLedger.Financial.Payment.ChainLaws

namespace BlindLedger.Financial.Payment

open BlindLedger.Financial

/-- `erase` drops nothing section 11 stores: whenever today's projection (ChainLaws.lean:14) has a
    stored image, its stored part is the erased outcome. -/
theorem project_factors_erase (r : PaymentRequest) (o : PaymentOutcome) :
    (project r o).map Erased.ofStep = (project r o).map fun _ => erase o := by
  cases o <;> simp [project, erase, Erased.ofStep, Option.map_map, Function.comp_def]

/-- Section 11 step 2: running bytes. Insert or replace; a replacement must not shrink the row
    (true of `reversedImage`, which only adds a reversal evidence id). -/
theorem len_applyWrites (i : FinancialInput) (w : Writes)
    (hp : ∀ p, w.payment = some p → (findPayment i.payments p.paymentId).isSome = true →
      (i.payments.map Payment.paymentId).Nodup)
    (hgrow : oldPay i w ≤ newPay w) :
    (rawEncodeFinancialInput (applyWrites i w)).length =
      (rawEncodeFinancialInput i).length + addedBytes i w := by
  have := rawEncode_applyWrites_core i w hp
  simp only [addedBytes]
  omega

/-- REVERSE discharges `len_applyWrites`' `hgrow`: the reversed image only fills the empty
    reversal evidence slot (`[0]` becomes `1 :: encodeString id`) and swaps one status byte. -/
theorem oldPay_le_newPay_reversed (i : FinancialInput) (p : Payment) (c : ReverseCommand) (w : Writes)
    (hw : w.payment = some (reversedImage p c)) (hp : findPayment i.payments p.paymentId = some p)
    (hr : p.reversalEvidenceId = none) : oldPay i w ≤ newPay w := by
  simp [oldPay, newPay, hw, reversedImage, hp, encodePayment, encodeOptionString, hr]

/-! ## `evaluate_delta`: the post-state check read off the carried summary -/

/-- The `(kind, writes)` `paymentTransition` hands to `mutate` (Transition.lean:96, :102, :132), or
    `none` when it reaches no `mutate` call: the path conditions of those three calls, flattened
    (on both record paths `same` and `prior` are false, so the received time is `evaluatedAt`; a
    fresh slot implies no foreign evidence id). Proof-only: the premise of `evaluate_delta`. -/
def writesOf (r : PaymentRequest) : Option (Mutation × Writes) :=
  let i := r.input
  match r.command with
  | .record c =>
    let e := confirmation i c i.evaluatedAt
    let id := conflictIdOf i c
    if c.amountCents = 0 || r.foreign.paymentId || (findPayment i.payments c.paymentId).isSome ||
       !revisionOk r || (formRefusal e).isSome || decide (i.evaluatedAt < c.eventAt) then none else
    match evidenceSlot r e with
    | .clash => none
    | slot =>
      let ev := if slot.isFresh then some e else none
      match i.payments.find? (·.commonOriginId = c.commonOriginId) with
      | some p =>
        if p.amountCents = c.amountCents || i.conflicts.any (·.conflictId = id) || !idWellFormed id then none
        else some (.CONFLICT_RECORDED, ⟨ev, none, some (conflictImage i c p id), none⟩)
      | none =>
        if (linkRefusal i r.receipts c).isSome then none
        else some (.RECORDED, ⟨ev, some (recordedPayment i c), none, some (recordedReceipt i c)⟩)
  | .reverse c =>
    match findPayment i.payments c.paymentId with
    | none => none
    | some p =>
      let time := c.eventAt.getD (((findEvidence i.evidence c.evidenceId).map (·.eventAt)).getD i.evaluatedAt)
      let e := reversalRecord i c p time
      if (formRefusal e).isSome || decide (i.evaluatedAt < time) || !(evidenceSlot r e).isFresh ||
         !revisionOk r || decide (p.status = .REVERSED) then none
      else some (.REVERSED, ⟨some e, some (reversedImage p c), none, none⟩)

private theorem delta_recorded {i : FinancialInput} (hwf : financialInputWellFormed i = true)
    {c : RecordCommand} (hc : commandWellFormed (.record c) = true) (h0 : c.amountCents ≠ 0)
    (hpid : findPayment i.payments c.paymentId = none)
    (hno : ∀ q ∈ i.payments, q.commonOriginId ≠ c.commonOriginId)
    {ev : Option EvidenceRecord} (hev : EvCase i c ev) :
    (evaluate (applyWrites i ⟨ev, some (recordedPayment i c), none, some (recordedReceipt i c)⟩)).isSome =
      deltaOk (summary i) ⟨ev, some (recordedPayment i c), none, some (recordedReceipt i c)⟩ := by
  have hpay : (applyWrites i ⟨ev, some (recordedPayment i c), none, some (recordedReceipt i c)⟩).payments =
      insertBy Payment.paymentId (recordedPayment i c) i.payments := by
    simp [applyWrites, recordedPayment, hpid]
  rw [evaluate_isSome, recorded_post_wf hwf hc h0 hpid hno hev, hpay, activeCents_insert rfl,
    Nat.add_comm (recordedPayment i c).amountCents]
  have hC := (wf_facts hwf).2.2.1
  simp only [deltaOk, summary, Option.isSome_some, ↓reduceIte, Option.isSome_none, Bool.false_eq_true,
    Nat.add_zero, decide_eq_true hC, Bool.and_true]
  rfl

private theorem delta_conflict {i : FinancialInput} (hwf : financialInputWellFormed i = true)
    {c : RecordCommand} (hc : commandWellFormed (.record c) = true) (h0 : c.amountCents ≠ 0)
    {p : Payment} (hp : findPayment i.payments p.paymentId = some p)
    (hporig : p.commonOriginId = c.commonOriginId) (hne : p.amountCents ≠ c.amountCents)
    (hcv : i.conflicts.any (·.conflictId = conflictIdOf i c) = false)
    (hcid : idWellFormed (conflictIdOf i c) = true)
    {ev : Option EvidenceRecord} (hev : EvCase i c ev) :
    (evaluate (applyWrites i ⟨ev, none, some (conflictImage i c p (conflictIdOf i c)), none⟩)).isSome =
      deltaOk (summary i) ⟨ev, none, some (conflictImage i c p (conflictIdOf i c)), none⟩ := by
  rw [evaluate_isSome, conflict_post_wf hwf hc h0 hp hporig hne hcv hcid hev]
  simp only [deltaOk, summary, Bool.decide_and, Option.isSome_some, ↓reduceIte,
    Bool.and_assoc]
  rfl

private theorem delta_reversed {i : FinancialInput} (hwf : financialInputWellFormed i = true)
    {c : ReverseCommand} (hc : commandWellFormed (.reverse c) = true)
    {p : Payment} (hp : findPayment i.payments c.paymentId = some p) (hact : p.status ≠ .REVERSED) {time : Nat}
    (hfe : findEvidence i.evidence c.evidenceId = none)
    (hform : formRefusal (reversalRecord i c p time) = none) (htime : time ≤ i.evaluatedAt) :
    (evaluate (applyWrites i ⟨some (reversalRecord i c p time), some (reversedImage p c), none, none⟩)).isSome =
      deltaOk (summary i) ⟨some (reversalRecord i c p time), some (reversedImage p c), none, none⟩ := by
  have hfind : findPayment i.payments (reversedImage p c).paymentId = some p := by
    show findPayment i.payments p.paymentId = some p
    rw [findPayment_id _ _ _ hp]; exact hp
  have hpact : p.status = .ACTIVE := by
    cases h : p.status with
    | ACTIVE => rfl
    | REVERSED => exact absurd h hact
  have hrep := activeCents_replace (nodup_ids_of_wf hwf) hfind hpact (by simp [reversedImage])
  have hamt : (reversedImage p c).amountCents = p.amountCents := rfl
  have hpay : (applyWrites i ⟨some (reversalRecord i c p time), some (reversedImage p c), none, none⟩).payments =
      i.payments.map fun x => if x.paymentId = (reversedImage p c).paymentId then reversedImage p c else x := by
    simp [applyWrites, hfind]
  rw [evaluate_isSome, reversed_post_wf hwf hc hp hact hfe hform htime, hpay,
    show activeCents (i.payments.map fun x => if x.paymentId = (reversedImage p c).paymentId
      then reversedImage p c else x) = activeCents i.payments - (reversedImage p c).amountCents by omega]
  have hC := (wf_facts hwf).2.2.1
  simp only [deltaOk, summary, Option.isSome_some, ↓reduceIte, Option.isSome_none, Bool.false_eq_true,
    Nat.add_zero, decide_eq_true hC, Bool.and_true]
  rfl

/-- `writesOf` names the write `paymentTransition` passes to `mutate`. -/
theorem writesOf_spec {r : PaymentRequest} {k : Mutation} {w : Writes} (h : writesOf r = some (k, w)) :
    paymentTransition r = mutate r k w := by
  unfold writesOf at h
  unfold paymentTransition
  cases hcmd : r.command with
  | record c =>
    simp only [hcmd] at h
    split at h
    · cases h
    rename_i hcond
    simp only [Bool.or_eq_true, decide_eq_true_eq, not_or, Bool.not_eq_true, Bool.not_eq_false',
      Option.isSome_eq_false_iff, Option.isNone_iff_eq_none, Nat.not_lt, and_assoc] at hcond
    obtain ⟨h0, hfp, hpid, hrev, hform, hch⟩ := hcond
    unfold decideRecord recordNew
    cases hsl : evidenceSlot r (confirmation r.input c r.input.evaluatedAt) with
    | clash => simp [hsl] at h
    | fresh | same _ =>
      simp only [hsl] at h
      cases hex : r.input.payments.find? (·.commonOriginId = c.commonOriginId) with
      | some p =>
        simp only [hex] at h
        split at h
        · cases h
        rename_i hc2
        simp only [Bool.or_eq_true, decide_eq_true_eq, not_or, Bool.not_eq_true, Bool.not_eq_false',
          and_assoc] at hc2
        obtain ⟨hne, hcv, hid⟩ := hc2
        cases h
        simp [h0, hfp, hpid, hex, hne, hcv, hid, hrev, hform, Nat.not_lt.2 hch, hsl, Slot.isFresh,
          Slot.isSame]
      | none =>
        simp only [hex] at h
        split at h
        · cases h
        rename_i hlr
        simp only [Option.isSome_eq_false_iff, Option.isNone_iff_eq_none, Bool.not_eq_true] at hlr
        cases h
        simp [h0, hfp, hpid, hex, hlr, hrev, hform, Nat.not_lt.2 hch, hsl, Slot.isFresh, Slot.isSame]
  | reverse c =>
    simp only [hcmd] at h
    split at h
    · cases h
    rename_i p hp
    split at h
    · cases h
    rename_i hcond
    simp only [Bool.or_eq_true, decide_eq_true_eq, not_or, Bool.not_eq_true, Bool.not_eq_false',
      Option.isSome_eq_false_iff, Option.isNone_iff_eq_none, Nat.not_lt, and_assoc] at hcond
    obtain ⟨hform, hch, hfr, hrev, hst⟩ := hcond
    have hfresh := (show ∀ s : Slot, s.isFresh = true → s = .fresh by
      intro s; cases s <;> simp [Slot.isFresh]) _ hfr
    obtain ⟨hfe, hfor⟩ := slot_fresh hfresh
    cases h
    unfold decideReverse
    simp [hp, hfor, hform, Nat.not_lt.2 hch, hfresh, hrev, hst]

/-- Section 11 step 3: for every write a transition makes, `evaluate` of the post-state is `some`
    exactly when `deltaOk` of the pre-state's summary holds. -/
theorem evaluate_delta (r : PaymentRequest) (k : Mutation) (w : Writes) (hr : requestWellFormed r = true)
    (ho : writesOf r = some (k, w)) :
    (evaluate (applyWrites r.input w)).isSome = deltaOk (summary r.input) w := by
  simp only [requestWellFormed, Bool.and_eq_true] at hr
  obtain ⟨⟨⟨hwf, -⟩, hc⟩, -⟩ := hr
  unfold writesOf at ho
  cases hcmd : r.command with
  | record c =>
    rw [hcmd] at hc
    simp only [hcmd] at ho
    split at ho
    · cases ho
    rename_i hcond
    simp only [Bool.or_eq_true, decide_eq_true_eq, not_or, Bool.not_eq_true, Bool.not_eq_false',
      Option.isSome_eq_false_iff, Option.isNone_iff_eq_none, Nat.not_lt, and_assoc] at hcond
    obtain ⟨h0, -, hpid, -, hform, hch⟩ := hcond
    have hne : evidenceSlot r (confirmation r.input c r.input.evaluatedAt) ≠ .clash := by
      intro e; simp [e] at ho
    have hev := evCase_of (evidenceWrite_of_slot hform hch rfl hne)
    generalize evidenceSlot r (confirmation r.input c r.input.evaluatedAt) = slot at ho hne hev
    cases slot
    case clash => exact absurd rfl hne
    all_goals
      simp only at ho hev
      cases hex : r.input.payments.find? (·.commonOriginId = c.commonOriginId) with
      | some p =>
        simp only [hex] at ho
        split at ho
        · cases ho
        rename_i hc2
        simp only [Bool.or_eq_true, decide_eq_true_eq, not_or, Bool.not_eq_true, Bool.not_eq_false',
          and_assoc] at hc2
        obtain ⟨hne', hcv, hid⟩ := hc2
        cases ho
        have hpm := List.mem_of_find?_eq_some hex
        have hporig : p.commonOriginId = c.commonOriginId := by simpa using List.find?_some hex
        exact delta_conflict hwf hc h0 (findPayment_of_mem (nodup_ids_of_wf hwf) hpm) hporig hne' hcv hid hev
      | none =>
        simp only [hex] at ho
        split at ho
        · cases ho
        cases ho
        exact delta_recorded hwf hc h0 hpid
          (fun q hq e => by simpa [e] using List.find?_eq_none.1 hex q hq) hev
  | reverse c =>
    rw [hcmd] at hc
    simp only [hcmd] at ho
    split at ho
    · cases ho
    rename_i p hp
    split at ho
    · cases ho
    rename_i hcond
    simp only [Bool.or_eq_true, decide_eq_true_eq, not_or, Bool.not_eq_true, Bool.not_eq_false',
      Option.isSome_eq_false_iff, Option.isNone_iff_eq_none, Nat.not_lt, and_assoc] at hcond
    obtain ⟨hform, hch, hfr, -, hst⟩ := hcond
    have hfresh := (show ∀ s : Slot, s.isFresh = true → s = .fresh by
      intro s; cases s <;> simp [Slot.isFresh]) _ hfr
    cases ho
    exact delta_reversed hwf hc hp hst (slot_fresh hfresh).1 hform hch

end BlindLedger.Financial.Payment
