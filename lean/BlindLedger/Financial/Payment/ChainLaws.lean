import BlindLedger.Financial.Payment.Bridge
import BlindLedger.Financial.Payment.Codec
import BlindLedger.Financial.CodecLaws.Records

namespace BlindLedger.Financial.Payment

open BlindLedger.Financial BlindLedger.Financial.CorrectionTransition

/-- The owner's point reads return the rows the snapshot `r` holds, and its stored state plus
    pending aliases is that snapshot's summary. Carry premise (keys, coherence, checker; R20). -/
def Faithful (r : PaymentRequest) (v : PaymentView) : Prop := viewOfAnchor r = some (absorbed v)

/-- The stored-row image of a reference outcome: `post` replaced by the committed summary. -/
def project (r : PaymentRequest) : PaymentOutcome → Option StepOutcome
  | .mutated k w post res =>
      (summaryOf (commitInput post res) (commitReceipts r.receipts w)).map fun s => .mutated k w s res
  | .alias pid e _ => some (.alias pid e)
  | .duplicate pid => some (.duplicate pid)
  | .conflictUnchanged id => some (.conflictUnchanged id)
  | .refused f => some (.refused f)

def ChainFaithful (L : Ledger) (calls : List Call) (vs : List PaymentView) : Prop :=
  vs.length = calls.length ∧ ∀ (n : Nat) (M : Ledger) (c : Call) (v : PaymentView), (ledgers L calls)[n]? = some M → calls[n]? = some c →
    vs[n]? = some v → Faithful (M.request c) v


/-! ## 16.2-16.6, 16.9 Corrected and folded-in statements -/

open BlindLedger.Financial.CorrectionTransition

private theorem evidenceSlot_eq (r : PaymentRequest) (e : EvidenceRecord) :
    evidenceSlot r e = slotOf r.foreign.evidenceId (findEvidence r.input.evidence e.evidenceId) e := rfl

theorem wf_setCases {i : FinancialInput} {X : List CaseRecord} (h : financialInputWellFormed i = true)
    (hl : 1 ≤ X.length) (hl2 : X.length ≤ maxRows)
    (hid : X.map CaseRecord.caseId = i.cases.map CaseRecord.caseId)
    (hX : ∀ k ∈ X, caseWellFormed i k = true ∧ k.updatedAt ≤ i.evaluatedAt) :
    financialInputWellFormed { i with cases := X } = true := by
  simp only [financialInputWellFormed, envWellFormed, envOf, Bool.and_assoc, Bool.and_eq_true, decide_eq_true_eq] at h ⊢
  obtain ⟨h1,h2,h3,h4,h5,h6,h7,h8,h9,h10,h11,h12,h13,h14,h15,h16,h17,h18,h19,h20,h21,h22,h23,h24,h25,h26,h27,h28,h29,h30,h31,h32,h33,h34,h35,h36,h37,h38,h39,h40,h41,h42,h43,h44,h45,h46,h47,h48,h49,h50,h51,h52,h53,h54,h55⟩ := h
  repeat' apply And.intro
  all_goals first | assumption | skip
  · show canonicalIdList (X.map CaseRecord.caseId) = true
    rw [hid]; assumption
  · exact List.all_eq_true.2 fun k hk => (hX k hk).1
  · exact List.all_eq_true.2 fun k hk => decide_eq_true (hX k hk).2

theorem wf_commit {post : FinancialInput} (res : FinancialResult)
    (h : financialInputWellFormed post = true) (hR : post.beforeRevision + 1 < maxRevision) :
    financialInputWellFormed (commitInput post res) = true := by
  have hc := h
  simp only [financialInputWellFormed, envWellFormed, envOf, Bool.and_assoc, Bool.and_eq_true, decide_eq_true_eq] at hc
  obtain ⟨h1,h2,h3,h4,h5,h6,h7,h8,h9,h10,h11,h12,h13,h14,h15,h16,h17,h18,h19,h20,h21,h22,h23,h24,h25,h26,h27,h28,h29,h30,h31,h32,h33,h34,h35,h36,h37,h38,h39,h40,h41,h42,h43,h44,h45,h46,h47,h48,h49,h50,h51,h52,h53,h54,h55⟩ := hc
  have hcs : financialInputWellFormed { post with cases := post.cases.map fun k =>
      { k with status := res.caseStatus, updatedAt := post.evaluatedAt } } = true := by
    refine wf_setCases h ?_ ?_ ?_ ?_
    · simp only [List.length_map]; exact h22
    · simp only [List.length_map]; exact h23
    · simp [List.map_map, Function.comp_def]
    · intro k hk
      obtain ⟨k0, hk0, rfl⟩ := List.mem_map.1 hk
      refine ⟨?_, Nat.le_refl _⟩
      have hk1 := List.all_eq_true.1 h37 k0 hk0
      simp only [caseWellFormed, Bool.and_assoc, Bool.and_eq_true, decide_eq_true_eq] at hk1 ⊢
      obtain ⟨a, b, c, d, e, -⟩ := hk1
      exact ⟨a, b, c, d, e, h7⟩
  have e : commitInput post res = { ({ post with cases := post.cases.map fun k =>
      { k with status := res.caseStatus, updatedAt := post.evaluatedAt } } : FinancialInput) with
      beforeRevision := post.beforeRevision + 1 } := rfl
  rw [e]
  exact wf_setRevision hcs (by show post.beforeRevision ≤ post.beforeRevision + 1; omega) hR


theorem action_id_wf {i : FinancialInput} (h : financialInputWellFormed i = true) {x : ActionRecord}
    (hx : x ∈ i.actions) : idWellFormed x.actionId = true := by
  simp only [financialInputWellFormed, envWellFormed, envOf, Bool.and_assoc, Bool.and_eq_true, decide_eq_true_eq] at h
  obtain ⟨h1,h2,h3,h4,h5,h6,h7,h8,h9,h10,h11,h12,h13,h14,h15,h16,h17,h18,h19,h20,h21,h22,h23,h24,h25,h26,h27,h28,h29,h30,h31,h32,h33,h34,h35,h36,h37,h38,h39,h40,h41,h42,h43,h44,h45,h46,h47,h48,h49,h50,h51,h52,h53,h54,h55⟩ := h
  have := List.all_eq_true.1 h38 x hx
  simp only [actionWellFormed, Bool.and_assoc, Bool.and_eq_true] at this
  exact List.all_eq_true.1 this.1 x.actionId (by simp)

theorem step_wellFormed (L : Ledger) (hL : ledgerWellFormed L) (c : Call) (hc : clocksOk L [c])
    (hR : L.input.beforeRevision + 1 < maxRevision) : ledgerWellFormed (step L c) := by
  have hI := step_Inv c (Inv_of_wf hL)
  have hb : ∀ {k w post res}, L.outcome c = .mutated k w post res →
      post.beforeRevision = L.input.beforeRevision :=
    fun {k w post res} ho => by rw [(paymentTransition_mutated_post ho).1]; rfl
  have hA : financialInputWellFormed (step L c).input = true := by
    rcases step_cases L c with ⟨k, w, post, res, ho, he⟩ | ⟨pid, e, post, ho, he⟩ | ⟨-, -, he⟩ <;> rw [he]
    · exact wf_commit res (paymentTransition_mutated_post ho).2.1 (by rw [hb ho]; exact hR)
    · exact (alias_shape ho).2.1
    · exact hL.1
  have hB : L.input.beforeRevision ≤ (step L c).input.beforeRevision := by
    rcases step_cases L c with ⟨k, w, post, res, ho, he⟩ | ⟨pid, e, post, ho, he⟩ | ⟨-, -, he⟩ <;> rw [he]
    · show L.input.beforeRevision ≤ post.beforeRevision + 1
      rw [hb ho]; omega
    · rw [(alias_shape ho).1]; exact Nat.le_refl _
    · exact Nat.le_refl _
  have hC : ∀ {w post res}, L.outcome c = .mutated .RECORDED w post res →
      (step L c).input.beforeRevision = L.input.beforeRevision + 1 :=
    fun {w post res} ho => by
      rw [step_mutated ho]; show post.beforeRevision + 1 = _; rw [hb ho]
  have hrec : ∀ k ∈ L.receipts, k.recordedRevision < L.input.beforeRevision ∧
      k.paysActionId.all idWellFormed = true := by
    have := hL.2
    simp only [receiptsWellFormed, Bool.and_eq_true, beq_iff_eq, List.all_eq_true, decide_eq_true_eq] at this
    exact this.2
  refine ⟨hA, ?_⟩
  simp only [receiptsWellFormed, Bool.and_eq_true, beq_iff_eq, List.all_eq_true, decide_eq_true_eq]
  refine ⟨hI.2, ?_⟩
  have old : ∀ k ∈ L.receipts, k.recordedRevision < (step L c).input.beforeRevision ∧
      k.paysActionId.all idWellFormed = true :=
    fun k hk => ⟨Nat.lt_of_lt_of_le (hrec k hk).1 hB, (hrec k hk).2⟩
  rcases step_kind L c with ⟨-, -, hr⟩ | ⟨rc, w, post, res, hcmd, ho, -, -, -, -, -, -, -, -, hr⟩ |
    ⟨-, -, -, -, -, -, -, -, -, -, -, -, hr, -⟩
  · rw [hr]; exact old
  · rw [hr]; intro k hk
    rcases (mem_insertBy Receipt.paymentId _ k _).1 hk with rfl | hk
    · refine ⟨?_, ?_⟩
      · show L.input.beforeRevision < (step L c).input.beforeRevision
        rw [hC ho]; omega
      · show rc.paysActionId.all idWellFormed = true
        cases hpa : rc.paysActionId with
        | none => rfl
        | some a =>
          obtain ⟨x, hx, hxa, -⟩ := Base.record_link_within_request (r := L.request c) hcmd hpa (trm ho)
          simp only [Option.all_some]
          rw [← hxa]; exact action_id_wf hL.1 hx
    · exact old k hk
  · rw [hr]; exact old



theorem evalAdd_comm (a b : Nat) : evalAdd a b = evalAdd b a := by
  unfold evalAdd
  simp only [Bool.and_eq_true, decide_eq_true_eq]
  by_cases h : (a ≤ maxCents ∧ b ≤ maxCents) ∧ a ≤ maxCents - b
  · have h' : (b ≤ maxCents ∧ a ≤ maxCents) ∧ b ≤ maxCents - a := by omega
    rw [if_pos h, if_pos h', Nat.add_comm]
  · have h' : ¬ ((b ≤ maxCents ∧ a ≤ maxCents) ∧ b ≤ maxCents - a) := by omega
    rw [if_neg h, if_neg h']

theorem evaluateState_summarize {i : FinancialInput} {rs b s} (hw : financialInputWellFormed i = true)
    (h : summarize i rs b = some s) : evaluateState (envOf i) s = evaluate i := by
  have hev : evaluate i = evaluateWellFormed i := by unfold evaluate; rw [hw]; rfl
  rw [hev]
  unfold summarize at h
  unfold evaluateWellFormed evaluateTotals
  unfold evaluateTotals at h
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
        | some t =>
          simp only [hc, hcl, hl, ht, Option.map_some, Option.some.injEq] at h
          subst h
          have hcomp : evalCompletion i =
              (match evalCompletionLoop i.obligation.owedCents 0 (evalSortContributions (evalContributions i)) with
               | some x => some x
               | none => if t ≥ i.obligation.owedCents
                         then evalLatestContributionTime (evalSortContributions (evalContributions i)) else none) := by
            unfold evalCompletion
            dsimp only
            cases evalCompletionLoop i.obligation.owedCents 0 (evalSortContributions (evalContributions i)) with
            | some x => rfl
            | none => simp [hc, hl, evalAdd_comm la cash, ht]
          have hv : (if i.conflicts.length = 0 then
                (if (i.evidence.map EvidenceRecord.evidenceId).isEmpty then VerificationStatus.MISSING_EVIDENCE
                 else .SUPPORTED) else .CONFLICT_VISIBLE) = evalVerificationStatus i := by
            unfold evalVerificationStatus; cases i.conflicts <;> cases i.evidence <;> simp
          simp only [hc, hcl, hl, ht, Option.map_some]
          unfold evaluateState
          simp only [ht, Option.bind_some, Option.pure_def, bind, Option.bind]
          simp only [evaluateResult, envOf, hcomp, hv]
          cases hq : evalCompletionLoop i.obligation.owedCents 0 (evalSortContributions (evalContributions i))
          · simp [evalCaseStatus]
            cases (if i.obligation.owedCents ≤ t then evalLatestContributionTime
              (evalSortContributions (evalContributions i)) else none) <;> rfl
          · simp [evalCaseStatus]
            rfl

theorem state_requests_paid (L : Ledger) {s : ItemState} (h : summaryOf L.input L.receipts = some s)
    (a : RequestPaid) (ha : a ∈ s.requests) : a.paidCents = ledgerPaid L a.actionId := by
  unfold summaryOf summarize at h
  cases ht : evaluateTotals L.input with
  | none => simp [ht] at h
  | some t =>
    simp only [ht, Option.map_some, Option.some.injEq] at h
    subst h
    obtain ⟨x, -, rfl⟩ := List.mem_map.1 ha
    rfl

theorem rawEncode_evaluatedAt (i : FinancialInput) (t : Nat) :
    (rawEncodeFinancialInput { i with evaluatedAt := t }).length = (rawEncodeFinancialInput i).length := by
  simp only [rawEncodeFinancialInput, List.length_append, length_natBE]

theorem absorb_summarize (L : Ledger) (c : Call) {pid e post}
    (h : L.outcome c = .alias pid e post) :
    (summaryOf L.input L.receipts).map (absorb · [e]) = summaryOf (step L c).input (step L c).receipts := by
  have hstep : step L c = { L with input := post } := by simp only [step, h]
  obtain ⟨hpost, -, hfresh⟩ := alias_shape h
  have hlen : (rawEncodeFinancialInput post).length =
      (rawEncodeFinancialInput L.input).length + (encodeEvidence e).length := by
    have := rawEncode_applyWrites_core (L.request c).input
      { evidence := some e, payment := none, conflict := none, receipt := none } (fun p hp => by cases hp)
    rw [← hpost] at this
    have h0 : (rawEncodeFinancialInput (L.request c).input).length = (rawEncodeFinancialInput L.input).length :=
      rawEncode_evaluatedAt L.input c.now
    simp only [oldPay, newPay, evBytes, cfBytes, Option.map_some, Option.getD_some, Option.map_none,
      Option.getD_none, Option.bind_none] at this
    omega
  rw [hstep]
  unfold summaryOf summarize
  have hT : evaluateTotals post = evaluateTotals L.input := by rw [hpost]; rfl
  show _ = (evaluateTotals post).map _
  rw [hT]
  cases evaluateTotals L.input with
  | none => rfl
  | some t =>
    simp only [Option.map_some, absorb, List.foldl_cons, List.foldl_nil, Option.some.injEq]
    have hE : post.evidence.map EvidenceRecord.evidenceId =
        insertBy (fun x => x) e.evidenceId (L.input.evidence.map EvidenceRecord.evidenceId) := by
      rw [hpost]
      exact map_insertBy EvidenceRecord.evidenceId EvidenceRecord.evidenceId id (fun _ => rfl) e _
    have hA : anchorItemLength post L.receipts = anchorItemLength L.input L.receipts + (encodeEvidence e).length := by
      unfold anchorItemLength; omega
    rw [hE, hA]
    subst hpost
    rfl


/-! ## Conflict retry (16.2 item 1) -/

theorem find_insertBy_ne {α} (key : α → String) (row : α) (P : α → Bool) (hP : P row = false) :
    ∀ l : List α, (insertBy key row l).find? P = l.find? P
  | [] => by simp [insertBy, hP]
  | y :: ys => by
    unfold insertBy
    split
    · simp [List.find?_cons, hP]
    · cases hy : P y <;> simp [List.find?_cons, hy, find_insertBy_ne key row P hP ys]

theorem find_map_same {α} (f : α → α) (P : α → Bool) :
    ∀ l : List α, (∀ x ∈ l, P (f x) = P x) → (l.map f).find? P = (l.find? P).map f
  | [], _ => rfl
  | x :: xs, h => by
    have hx := h x (by simp)
    have ih := find_map_same f P xs fun y hy => h y (by simp [hy])
    cases hpx : P x <;> simp [List.find?_cons, hx, hpx, ih]

theorem eq_of_nodup_key {α} (key : α → String) : ∀ {l : List α}, (l.map key).Nodup →
    ∀ {x y}, x ∈ l → y ∈ l → key x = key y → x = y
  | [], _, _, _, hx, _, _ => by cases hx
  | z :: zs, hn, x, y, hx, hy, hk => by
    simp only [List.map_cons, List.nodup_cons, List.mem_map] at hn
    rcases List.mem_cons.1 hx with rfl | hx' <;> rcases List.mem_cons.1 hy with rfl | hy'
    · rfl
    · exact absurd ⟨y, hy', hk.symm⟩ hn.1
    · exact absurd ⟨x, hx', hk⟩ hn.1
    · exact eq_of_nodup_key key hn.2 hx' hy' hk

theorem rev_map_same {l : List Payment} (hnd : (l.map Payment.paymentId).Nodup) {p : Payment}
    (hp : p ∈ l) (vc : ReverseCommand) : ∀ x ∈ l,
    (if x.paymentId = p.paymentId then reversedImage p vc else x).paymentId = x.paymentId ∧
    (if x.paymentId = p.paymentId then reversedImage p vc else x).commonOriginId = x.commonOriginId ∧
    (if x.paymentId = p.paymentId then reversedImage p vc else x).amountCents = x.amountCents := by
  intro x hx
  by_cases h : x.paymentId = p.paymentId
  · obtain rfl := eq_of_nodup_key _ hnd hx hp h
    simp [reversedImage]
  · simp [h]

theorem conflict_existing {r : PaymentRequest} {c w post res}
    (h : Base.recordNew r c = .mutated .CONFLICT_RECORDED w post res) :
    ∃ p, r.input.payments.find? (·.commonOriginId = c.commonOriginId) = some p ∧
      p.amountCents ≠ c.amountCents := by
  unfold Base.recordNew at h
  dsimp only at h
  generalize hex : r.input.payments.find? (·.commonOriginId = c.commonOriginId) = existing at h
  generalize hsame : existing.any (·.amountCents = c.amountCents) = same at h
  generalize hprior : (same && ((findEvidence r.input.evidence c.evidenceId).isSome ||
    r.foreign.evidenceId)) = prior at h
  generalize hrecv : (if prior = true then
    ((findEvidence r.input.evidence c.evidenceId).map (·.receivedAt)).getD r.input.evaluatedAt
    else r.input.evaluatedAt) = receivedAt at h
  split at h
  · simp at h
  split at h
  · simp at h
  split at h
  · simp at h
  split at h
  · simp at h
  split at h
  · simp at h
  split at h
  · simp at h
  generalize hslot : evidenceSlot r (confirmation r.input c receivedAt) = slot at h
  cases slot
  case clash => simp at h
  all_goals
    dsimp only [Slot.isFresh] at h
    cases existing with
    | none =>
      dsimp only at h
      split at h
      · simp at h
      · obtain ⟨hk, -⟩ := Base.mutate_eq h; cases hk
    | some p =>
      dsimp only at h
      split at h
      · split at h
        · simp at h
        · exact absurd h Base.alias_or_dup_ne
      · rename_i hsm
        refine ⟨p, rfl, fun he => hsm ?_⟩
        simp [← hsame, he]

theorem recordRetry_conflict {r c p s} (hs : findEvidence r.input.evidence c.evidenceId = some s)
    (hfs : formRefusal s = none) (hle : c.eventAt ≤ s.receivedAt)
    (hc : confirmation r.input c s.receivedAt = s) (ho : p.commonOriginId ≠ c.commonOriginId) :
    recordRetry r c p = .refused .REQUEST_CONFLICT := by
  simp [recordRetry, hs, hfs, hc, Nat.not_lt.2 hle] <;> split <;> simp [ho]

theorem step_conflict (L c) {x} (h : x ∈ L.input.conflicts) : x ∈ (step L c).input.conflicts := by
  rcases step_cases L c with ⟨k, w, post, res, ho, he⟩ | ⟨pid, e, post, ho, he⟩ | ⟨-, -, he⟩ <;> rw [he]
  · dsimp only; rw [(paymentTransition_mutated_post ho).1]
    simp only [commitInput, applyWrites]
    cases w.conflict with
    | none => exact h
    | some X => simp only [Option.map_some, Option.getD_some]; exact (mem_insertBy _ _ _ _).2 (Or.inr h)
  · dsimp only; rw [(alias_shape ho).1]
    simp only [applyWrites, Option.map_none, Option.getD_none]; exact h
  · exact h

/-- The payment rows a conflict retry depends on. -/
def CRp (M : Ledger) (c : RecordCommand) : Prop :=
  (M.input.payments.map Payment.paymentId).Nodup ∧
  (∃ p0, M.input.payments.find? (·.commonOriginId = c.commonOriginId) = some p0 ∧
    p0.amountCents ≠ c.amountCents) ∧
  ∀ p ∈ M.input.payments, p.paymentId = c.paymentId → p.commonOriginId ≠ c.commonOriginId

def CR (M : Ledger) (c : RecordCommand) (cid : String) : Prop :=
  c.amountCents ≠ 0 ∧ CRp M c ∧
  (∃ s, findEvidence M.input.evidence c.evidenceId = some s ∧ c.eventAt ≤ s.receivedAt ∧
    confirmation M.input c s.receivedAt = s ∧ formRefusal s = none) ∧
  (∃ x ∈ M.input.conflicts, x.conflictId = cid) ∧ conflictIdOf M.input c = cid

theorem CRp_step {M c} (h : CRp M c) (c') : CRp (step M c') c := by
  obtain ⟨hnd, ⟨p0, hex, hsm⟩, hid⟩ := h
  rcases step_kind M c' with ⟨-, hp, -⟩ | ⟨rc, w, post, res, -, -, -, -, -, hor, -, -, hnd', hp, -⟩ |
    ⟨vc, p, w, post, res, -, -, hf, -, -, hnd', hp, -⟩
  · unfold CRp; rw [hp]; exact ⟨hnd, ⟨p0, hex, hsm⟩, hid⟩
  · have hp0 := List.mem_of_find?_eq_some hex
    have hpo : p0.commonOriginId = c.commonOriginId := by simpa using List.find?_some hex
    have hrow : (recordedPayment (M.request c').input rc).commonOriginId ≠ c.commonOriginId :=
      fun e => hor p0 hp0 (hpo.trans e.symm)
    refine ⟨hnd', ⟨p0, ?_, hsm⟩, fun q hq hqi => ?_⟩
    · rw [hp, find_insertBy_ne Payment.paymentId (recordedPayment (M.request c').input rc)
        (fun x => decide (x.commonOriginId = c.commonOriginId)) (decide_eq_false hrow)]
      exact hex
    · rw [hp, mem_insertBy] at hq
      rcases hq with rfl | hq
      · exact hrow
      · exact hid q hq hqi
  · have hmem : p ∈ M.input.payments := by
      rw [findPayment_eq] at hf; exact List.mem_of_find?_eq_some hf
    have hm := rev_map_same hnd hmem vc
    have hp0 := List.mem_of_find?_eq_some hex
    have hf2 := find_map_same (fun x : Payment => if x.paymentId = p.paymentId then reversedImage p vc else x)
      (fun x => decide (x.commonOriginId = c.commonOriginId)) M.input.payments
      (fun x hx => by simp only [(hm x hx).2.1])
    rw [hex, Option.map_some] at hf2
    refine ⟨hnd', ⟨_, by rw [hp]; exact hf2, fun e => hsm ((hm p0 hp0).2.2.symm.trans e)⟩, fun q hq hqi => ?_⟩
    rw [hp, List.mem_map] at hq
    obtain ⟨y, hy, rfl⟩ := hq
    exact fun e => hid y hy ((hm y hy).1.symm.trans hqi) ((hm y hy).2.1.symm.trans e)

theorem CR_step {M c cid} (h : CR M c cid) (c') : CR (step M c') c cid := by
  obtain ⟨hz, hp, ⟨s, hs, hle, hce, hfs⟩, ⟨x, hx, hxid⟩, hcid⟩ := h
  refine ⟨hz, CRp_step hp c', ⟨s, step_evidence M c' hs, hle, ?_, hfs⟩,
    ⟨x, step_conflict M c' hx, hxid⟩, ?_⟩
  · rw [confirmation_ctx (step_context M c') c s.receivedAt]; exact hce
  · unfold conflictIdOf at hcid ⊢; rw [step_context]; exact hcid

theorem run_CR {M c cid} (h : CR M c cid) : ∀ calls, CR (run M calls) c cid
  | [] => h
  | c' :: cs => run_CR (CR_step h c') cs

theorem CR_init {L : Ledger} {c : RecordCommand} {c0 : Call} {w post res}
    (hcmd : c0.command = .record c) (h : L.outcome c0 = .mutated .CONFLICT_RECORDED w post res) :
    CR (step L c0) c (conflictIdOf L.input c) := by
  have ht : Base.paymentTransition (L.request c0) = .mutated .CONFLICT_RECORDED w post res := trm h
  rcases Base.paymentTransition_cases ht with ⟨c', hc', hd⟩ | ⟨c', hc', hd⟩
  · obtain rfl : c = c' := (Command.record.inj (hc'.symm.trans hcmd)).symm
    obtain ⟨hf, hn⟩ := Base.decideRecord_mutated hd
    obtain ⟨p0, hex, hsm⟩ := conflict_existing hn
    obtain ⟨-, -, hew, ⟨hk, -⟩ | ⟨-, p, -, -, -, -, -, hwc⟩⟩ := Base.recordNew_mutated hn
    · cases hk
    obtain ⟨hpost, hwf, -⟩ := paymentTransition_mutated_post h
    have hpay : (step L c0).input.payments = L.input.payments := by
      rw [step_payments_mutated h]; exact (conflict_changes_no_cash h).1
    refine ⟨fun h0 => ?_, ⟨?_, ⟨p0, ?_, hsm⟩, ?_⟩, ?_, ⟨conflictImage (L.request c0).input c p
      ("conflict:" ++ (L.request c0).input.context.itemId ++ ":" ++ c.commonOriginId ++ ":" ++ c.evidenceId), ?_, rfl⟩, ?_⟩
    · have h' : paymentTransition (L.request c0) = .mutated .CONFLICT_RECORDED w post res := h
      rw [record_amount_zero (r := L.request c0) hcmd h0] at h'
      cases h'
    · rw [step_payments_mutated h]; exact nodup_ids_of_wf hwf
    · rw [hpay]; exact hex
    · rw [hpay]
      intro q hq hqi
      exact absurd (decide_eq_true hqi) (List.find?_eq_none.1 ((findPayment_eq _ _).symm.trans hf) q hq)
    · obtain ⟨hform, hle, -, hcase⟩ := hew
      rcases hcase with ⟨hw, -⟩ | ⟨-, s, hs, hle', hce⟩
      · refine ⟨_, step_mutated_evidence h hw, hle, ?_, hform⟩
        exact (confirmation_ctx (step_context L c0) c _).trans
          (confirmation_ctx (i := L.input) (j := (L.request c0).input) rfl c _)
      · refine ⟨s, step_evidence L c0 hs, hle', ?_, formRefusal_of_conf hce hform⟩
        exact (confirmation_ctx (step_context L c0) c _).trans
          ((confirmation_ctx (i := L.input) (j := (L.request c0).input) rfl c _).trans hce)
    · rw [step_mutated h, hpost]
      simp only [commitInput, applyWrites, hwc, Option.map_some, Option.getD_some]
      exact (mem_insertBy _ _ _ _).2 (Or.inl rfl)
    · unfold conflictIdOf; rw [step_context]
  · obtain ⟨-, -, hk, -⟩ := Base.decideReverse_mutated hd; cases hk

theorem CR_retry {M : Ledger} {c cid} (h : CR M c cid) (now' : Nat) (exp' : Option Nat) :
    M.outcome ⟨now', exp', .record c⟩ =
      if (findPayment M.input.payments c.paymentId).isSome
      then .refused .REQUEST_CONFLICT else .conflictUnchanged cid := by
  obtain ⟨hz, ⟨-, ⟨p0, hex, hsm⟩, hid⟩, ⟨s, hs, hle, hce, hfs⟩, ⟨x, hx, hxid⟩, hcid⟩ := h
  show decideRecord (M.request ⟨now', exp', .record c⟩) c = _
  have hce' : confirmation (M.request ⟨now', exp', .record c⟩).input c s.receivedAt = s :=
    (confirmation_ctx (i := (M.request ⟨now', exp', .record c⟩).input) (j := M.input) rfl c _).trans hce
  cases hp : findPayment M.input.payments c.paymentId with
  | some p =>
    have hp' : findPayment (M.request ⟨now', exp', .record c⟩).input.payments c.paymentId = some p := hp
    have hmem : p ∈ M.input.payments := by
      rw [findPayment_eq] at hp; exact List.mem_of_find?_eq_some hp
    rw [decideRecord_retry (r := M.request ⟨now', exp', .record c⟩) hz rfl hp',
      recordRetry_conflict hs hfs hle hce' (hid p hmem (findPayment_id _ _ _ hp'))]
    simp
  | none =>
    have hp' : findPayment (M.request ⟨now', exp', .record c⟩).input.payments c.paymentId = none := hp
    have hd : decideRecord (M.request ⟨now', exp', .record c⟩) c =
        recordNew (M.request ⟨now', exp', .record c⟩) c := by
      have hfor : (M.request ⟨now', exp', .record c⟩).foreign.paymentId = false := rfl
      simp [decideRecord, hz, hp', hfor]
    have hslot : evidenceSlot (M.request ⟨now', exp', .record c⟩)
        (confirmation (M.request ⟨now', exp', .record c⟩).input c
          (M.request ⟨now', exp', .record c⟩).input.evaluatedAt) = .same s :=
      evidenceSlot_same rfl hs hle hce'
    have hany : (M.request ⟨now', exp', .record c⟩).input.conflicts.any
        (·.conflictId = conflictIdOf (M.request ⟨now', exp', .record c⟩).input c) = true :=
      List.any_eq_true.2 ⟨x, hx, decide_eq_true (hxid.trans hcid.symm)⟩
    have hex' : (M.request ⟨now', exp', .record c⟩).input.payments.find?
        (·.commonOriginId = c.commonOriginId) = some p0 := hex
    rw [hd]
    unfold recordNew
    dsimp only
    simp [hex', hsm, hany, hslot, Slot.isSame, hcid]
    exact hcid

theorem run_conflict_retry_unchanged (L : Ledger) (c : RecordCommand) (now : Nat)
    (exp exp' : Option Nat) (calls : List Call) (now' : Nat)
    (h : ∃ w post res, L.outcome ⟨now, exp, .record c⟩ = .mutated .CONFLICT_RECORDED w post res) :
    (run (step L ⟨now, exp, .record c⟩) calls).outcome ⟨now', exp', .record c⟩ =
      if (findPayment (run (step L ⟨now, exp, .record c⟩) calls).input.payments c.paymentId).isSome
      then .refused .REQUEST_CONFLICT else .conflictUnchanged (conflictIdOf L.input c) := by
  obtain ⟨w, post, res, ho⟩ := h
  exact CR_retry (run_CR (CR_init (c0 := ⟨now, exp, .record c⟩) rfl ho) calls) now' exp'

/-! ## Anchor capacity (D3) -/

theorem advance_anchor {v s w s'} (h : advance v s w = some s') :
    s'.anchorBytes = s.anchorBytes + anchorGrowth v w := by
  unfold advance at h
  dsimp only at h
  repeat' split at h
  all_goals first | (obtain rfl := Option.some.inj h; rfl) | simp at h

theorem commitView_fits {v s k w k' w' s' r} (h : commitView v s k w = .mutated k' w' s' r) :
    s'.anchorBytes + maxCallTailBytes ≤ maxTotalEncodedBytes := by
  by_cases hs : v.env.context.mode = .SHADOW
  · simp [commitView, hs] at h
  by_cases hc : s.anchorBytes + anchorGrowth v w + maxCallTailBytes > maxTotalEncodedBytes
  · simp [commitView, hs, hc] at h
  cases hadv : advance v s w with
  | none => simp [commitView, hs, hc, hadv] at h
  | some s2 =>
    cases hev : evaluateState v.env s2 with
    | none => simp [commitView, hs, hc, hadv, hev] at h
    | some r2 =>
      simp only [commitView, hs, hc, hadv, hev, ↓reduceIte] at h
      cases h
      have := advance_anchor hadv
      show s2.anchorBytes + _ ≤ _
      omega

private def Fits (o : StepOutcome) : Prop :=
  ∀ k w s r, o = .mutated k w s r → s.anchorBytes + maxCallTailBytes ≤ maxTotalEncodedBytes

private theorem fits_commit {v s k w} : Fits (commitView v s k w) :=
  fun _ _ _ _ h => commitView_fits h
private theorem fits_refused {x} : Fits (.refused x) := fun _ _ _ _ h => by cases h
private theorem fits_dup {x} : Fits (.duplicate x) := fun _ _ _ _ h => by cases h
private theorem fits_cu {x} : Fits (.conflictUnchanged x) := fun _ _ _ _ h => by cases h
private theorem fits_alias {x y} : Fits (.alias x y) := fun _ _ _ _ h => by cases h

private theorem fits_ite {c : Prop} [Decidable c] {a b : StepOutcome} (ha : Fits a) (hb : Fits b) :
    Fits (if c then a else b) := by
  by_cases h : c
  · rw [if_pos h]; exact ha
  · rw [if_neg h]; exact hb

private theorem fits_aliasView {v s p e} : Fits (aliasView v s p e) := by
  unfold aliasView
  refine fits_ite fits_refused (fits_ite fits_refused (fits_ite fits_alias fits_refused))

set_option maxHeartbeats 1000000 in
private theorem fits_reverse {v s c} : Fits (viewReverse v s c) := by
  unfold viewReverse; dsimp only; repeat' split
  all_goals first | exact fits_refused | exact fits_dup | exact fits_commit | skip

set_option maxHeartbeats 1000000 in
private theorem fits_retry {v c p k} : Fits (viewRecordRetry v c p k) := by
  unfold viewRecordRetry; dsimp only; repeat' split
  all_goals first | exact fits_refused | exact fits_dup | skip

set_option maxHeartbeats 1000000 in
private theorem fits_new {v s c} : Fits (viewRecordNew v s c) := by
  unfold viewRecordNew
  dsimp only
  refine fits_ite fits_refused (fits_ite fits_cu (fits_ite fits_refused (fits_ite fits_refused ?_)))
  split
  · exact fits_refused
  · refine fits_ite fits_refused ?_
    split
    · exact fits_refused
    · split
      · exact fits_ite (fits_ite fits_refused (fits_ite fits_aliasView fits_dup))
          (fits_ite fits_cu (fits_ite fits_refused fits_commit))
      · split
        · exact fits_refused
        · exact fits_commit

private theorem fits_step {v} : Fits (stepView v) := by
  unfold stepView
  dsimp only
  split
  · refine fits_ite fits_refused (fits_ite fits_refused ?_)
    split
    · exact fits_retry
    · exact fits_new
  · exact fits_reverse

theorem anchorItem_fits {v : PaymentView} {k w s r} (h : stepView v = .mutated k w s r) :
    s.anchorBytes + maxCallTailBytes ≤ maxTotalEncodedBytes := fits_step k w s r h

theorem idWellFormed_len {s : String} (h : idWellFormed s = true) : s.toUTF8.toList.length ≤ 128 := by
  simp only [idWellFormed, Bool.and_eq_true, decide_eq_true_eq] at h
  exact h.1.2

theorem encodeString_len {s : String} (h : idWellFormed s = true) : (encodeString s).length ≤ 130 := by
  have := idWellFormed_len h
  simp only [encodeString, List.length_append, length_natBE]
  omega

theorem optId_len {o : Option String} (h : (nonEmpty o).all idWellFormed = true) :
    (encodeOptionString o).length ≤ 131 := by
  cases o with
  | none => simp [encodeOptionString]
  | some s =>
    by_cases hs : s = ""
    · subst hs; simp [encodeOptionString, encodeString, length_natBE]
    · have := encodeString_len (s := s) (by simpa [nonEmpty, hs] using h)
      simp only [encodeOptionString, List.length_cons]
      omega

theorem optAll_len {o : Option String} (h : o.all idWellFormed = true) :
    (encodeOptionString o).length ≤ 131 := by
  cases o with
  | none => simp [encodeOptionString]
  | some s =>
    have := encodeString_len (s := s) (by simpa using h)
    simp only [encodeOptionString, List.length_cons]
    omega

theorem anchorItem_length (r : PaymentRequest) (hc : commandWellFormed r.command = true) :
    (encodePaymentRequest r).length ≤ anchorItemLength r.input r.receipts + maxCallTailBytes := by
  have hcmd : (encodeCommand r.command).length ≤ 1000 := by
    cases hcm : r.command with
    | record c =>
      rw [hcm] at hc
      simp only [commandWellFormed, Bool.and_eq_true] at hc
      obtain ⟨⟨⟨⟨hids, hl⟩, hp⟩, -⟩, -⟩ := hc
      have h1 := encodeString_len (List.all_eq_true.1 hids c.paymentId (by simp))
      have h2 := encodeString_len (List.all_eq_true.1 hids c.evidenceId (by simp))
      have h3 := encodeString_len (List.all_eq_true.1 hids c.commonOriginId (by simp))
      have h4 := encodeString_len (List.all_eq_true.1 hids c.sourceId (by simp))
      have h5 := encodeString_len (List.all_eq_true.1 hids c.sourceVersion (by simp))
      have h6 := optId_len hl
      have h7 := optAll_len hp
      simp only [encodeCommand, List.length_cons, List.length_append, length_natBE]
      omega
    | reverse c =>
      rw [hcm] at hc
      simp only [commandWellFormed, Bool.and_eq_true] at hc
      obtain ⟨⟨⟨h1, h2⟩, h3⟩, -⟩ := hc
      have h1 := encodeString_len h1
      have h2 := encodeString_len h2
      have h3 := optId_len h3
      have h4 : (encodeOptionNat c.eventAt).length ≤ 9 := by
        cases c.eventAt <;> simp [encodeOptionNat, length_natBE]
      simp only [encodeCommand, List.length_cons, List.length_append]
      omega
  have ho : (encodeOptionNat r.expectedRevision).length ≤ 9 := by
    cases r.expectedRevision <;> simp [encodeOptionNat, length_natBE]
  have hf : (encodeForeign r.foreign).length = 1 := rfl
  simp only [encodePaymentRequest, anchorItemLength, anchorOverhead, maxCallTailBytes,
    List.length_append, length_natBE, List.length_singleton]
  omega

theorem rawEncode_commit_length (post : FinancialInput) (res : FinancialResult) :
    (rawEncodeFinancialInput (commitInput post res)).length = (rawEncodeFinancialInput post).length := by
  have hc : (encodeList encodeCase (post.cases.map fun k =>
      { k with status := res.caseStatus, updatedAt := post.evaluatedAt })).length =
      (encodeList encodeCase post.cases).length := by
    rw [length_encodeList, length_encodeList, List.map_map]
    congr 2
    exact List.map_congr_left fun k _ => by simp [Function.comp, encodeCase, length_natBE]
  simp only [rawEncodeFinancialInput, commitInput, List.length_append, length_natBE]
  omega

theorem post_len_le {r : PaymentRequest} {k w post res}
    (h : paymentTransition r = .mutated k w post res) :
    (rawEncodeFinancialInput post).length ≤ (rawEncodeFinancialInput r.input).length + addedBytes r.input w := by
  obtain ⟨hpost, hwf, -⟩ := paymentTransition_mutated_post h
  have hp : ∀ p, w.payment = some p → (findPayment r.input.payments p.paymentId).isSome = true →
      (r.input.payments.map Payment.paymentId).Nodup := fun p hw hs =>
    payments_nodup_of_replace (hpost ▸ hwf) hw hs
  have := rawEncode_applyWrites_core r.input w hp
  unfold addedBytes
  rw [hpost]
  omega

theorem alias_len {r : PaymentRequest} {pid e post} (h : paymentTransition r = .alias pid e post) :
    (rawEncodeFinancialInput post).length = (rawEncodeFinancialInput r.input).length + (encodeEvidence e).length := by
  rw [(alias_shape h).1]
  have := rawEncode_applyWrites_core r.input
    { evidence := some e, payment := none, conflict := none, receipt := none } (fun p hp => by cases hp)
  simpa [evBytes, newPay, oldPay, cfBytes] using this

theorem commitReceipts_len (rs : List Receipt) (w : Writes) :
    (encodeList encodeReceipt (commitReceipts rs w)).length = (encodeList encodeReceipt rs).length + receiptBytes w := by
  cases hw : w.receipt with
  | none => simp [commitReceipts, receiptBytes, hw]
  | some k => simp [commitReceipts, receiptBytes, hw, length_encodeList, sum_insertBy] <;> omega

theorem step_anchor_fits (L : Ledger) (hL : ledgerWellFormed L) (c : Call)
    (hfit : anchorItemLength L.input L.receipts + maxCallTailBytes ≤ maxTotalEncodedBytes) :
    anchorItemLength (step L c).input (step L c).receipts + maxCallTailBytes ≤ maxTotalEncodedBytes := by
  have e1 : (L.request c).inputBytes = (rawEncodeFinancialInput (L.request c).input).length := rfl
  rcases step_cases L c with ⟨k, w, post, res, ho, he⟩ | ⟨pid, e, post, ho, he⟩ | ⟨-, -, he⟩ <;> rw [he]
  · have hcap := transition_cap (r := L.request c) ho
    have hl := post_len_le (r := L.request c) ho
    simp only [withinCapacity, decide_eq_true_eq, e1] at hcap
    unfold anchorItemLength
    dsimp only
    have hcr := commitReceipts_len L.receipts w
    unfold commitReceipts at hcr
    rw [rawEncode_commit_length]
    have : (L.request c).receipts = L.receipts := rfl
    rw [this] at hcap
    omega
  · have hcap := transition_alias_cap (r := L.request c) ho
    have hl := alias_len (r := L.request c) ho
    simp only [withinCapacity, decide_eq_true_eq, e1] at hcap
    simp [addedBytes, evBytes, newPay, oldPay, cfBytes, receiptBytes] at hcap
    unfold anchorItemLength
    dsimp only
    rw [hl]
    have : (L.request c).receipts = L.receipts := rfl
    rw [this] at hcap
    omega
  · exact hfit

-- 16.2 item 1 (5.3): exact, hypothesis-free

-- 16.2 item 2 (5.6)

theorem find_requests (l : List ActionRecord) (a : String) (f : ActionRecord → RequestPaid)
    (hf : ∀ x, (f x).actionId = x.actionId) :
    ((l.filter (·.kind = "CORRECTION_PAYMENT_REQUEST")).map f).find? (·.actionId = a) =
      (l.find? fun x => x.actionId = a && x.kind = "CORRECTION_PAYMENT_REQUEST").map f := by
  induction l with
  | nil => rfl
  | cons x xs ih =>
    by_cases hk : x.kind = "CORRECTION_PAYMENT_REQUEST" <;> by_cases ha : x.actionId = a <;>
      simp [List.filter_cons, List.find?_cons, hk, ha, hf, ih]

/-- The link rule over the state is the link rule over the snapshot. -/
theorem linkRefusalView_eq {i : FinancialInput} {rs b S} (hw : financialInputWellFormed i = true)
    (hS : summarize i rs b = some S) (c : RecordCommand) :
    linkRefusalView (envOf i) S c = linkRefusal i rs c := by
  have hreq : S.requests = (i.actions.filter (·.kind = "CORRECTION_PAYMENT_REQUEST")).map
      (requestPaidOf i.payments (linksOf rs)) := by
    unfold summarize at hS
    cases hT : evaluateTotals i with
    | none => simp [hT] at hS
    | some t => simp only [hT, Option.map_some, Option.some.injEq] at hS; rw [← hS]
  have hev : evaluateState (envOf i) S = evaluate i := evaluateState_summarize hw hS
  cases hp : c.paysActionId with
  | none => simp [linkRefusalView, linkRefusal, hp]
  | some a =>
    simp only [linkRefusalView, linkRefusal, hp, Option.bind_some]
    rw [hev, hreq, find_requests _ _ _ (fun _ => rfl)]
    cases hfnd : i.actions.find? (fun x => x.actionId = a && x.kind = "CORRECTION_PAYMENT_REQUEST") with
    | none => simp
    | some q => simp only [Option.map_some, openState_summarize]

-- 16.2 item 5 (5.1): both forms
theorem paymentRespond_decode_none {w : Bytes} (h : decodePaymentItem w = none) :
    paymentRespond w = [UInt8.ofNat 1] := by
  simp [paymentRespond, h]

theorem decodeStepOutcome_encode {o : StepOutcome} {b : Bytes} (h : encodeStepOutcome o = some b) :
    decodeStepOutcome b = some o := by
  dsimp only [encodeStepOutcome] at h
  split at h <;> simp_all

theorem evalInsertContribution_perm (y : EvalContribution) :
    ∀ l, (evalInsertContribution y l).Perm (y :: l)
  | [] => .refl _
  | a :: l => by
    unfold evalInsertContribution
    split
    · exact .refl _
    · exact ((evalInsertContribution_perm y l).cons a).trans (.swap y a l)

theorem evalSortContributions_perm : ∀ l, (evalSortContributions l).Perm l
  | [] => .refl _
  | a :: l => (evalInsertContribution_perm a _).trans ((evalSortContributions_perm l).cons a)

theorem active_contribution {i : FinancialInput} {p : Payment} (hp : p ∈ i.payments)
    (ha : p.status = .ACTIVE) :
    (evalSortContributions (evalContributions i)).contains ⟨p.eventAt, p.paymentId, p.amountCents⟩ = true := by
  rw [List.contains_iff_mem, (evalSortContributions_perm _).mem_iff]
  simp only [evalContributions]
  apply List.mem_append_left
  generalize i.payments = ps at hp
  induction ps with
  | nil => cases hp
  | cons q qs ih =>
    rcases List.mem_cons.mp hp with rfl | h
    · simp [ha]
    · simp only [List.foldr_cons]; split <;> simp [ih h]

theorem findEvidence_id : ∀ {l : List EvidenceRecord} {id : String} {e : EvidenceRecord},
    findEvidence l id = some e → e.evidenceId = id
  | [], _, _, h => by simp [findEvidence] at h
  | x :: xs, id, e, h => by
      unfold findEvidence at h
      split at h
      · cases h; assumption
      · exact findEvidence_id h

theorem viewOfAnchor_coherent {r : PaymentRequest} {v : PaymentView} (h : viewOfAnchor r = some v) :
    coherent v = true := by
  obtain ⟨i, n, rs, fo, er, cmd⟩ := r
  unfold viewOfAnchor at h
  obtain ⟨S, hS, rfl⟩ := Option.map_eq_some_iff.mp h
  unfold summarize at hS
  obtain ⟨t, -, rfl⟩ := Option.map_eq_some_iff.mp hS
  have hc : ∀ p ∈ i.payments, (!decide (p.status = .ACTIVE) ||
      (evalSortContributions (evalContributions i)).contains ⟨p.eventAt, p.paymentId, p.amountCents⟩) = true := by
    intro p hp
    by_cases ha : p.status = .ACTIVE
    · rw [active_contribution hp ha, Bool.or_true]
    · simp [ha]
  have hid : ∀ x, ((findPayment i.payments (cmdPaymentId cmd)).bind fun p =>
      (receiptOf rs p.paymentId).map fun k => (p, k)) = some x →
      x.1.paymentId = cmdPaymentId cmd ∧ x.1 ∈ i.payments := by
    intro x hx
    obtain ⟨p, hp, hx⟩ := Option.bind_eq_some_iff.mp hx
    obtain ⟨k, -, rfl⟩ := Option.map_eq_some_iff.mp hx
    exact ⟨findPayment_id _ _ _ hp, findPayment_mem hp⟩
  cases cmd with
  | record c =>
    simp only [coherent, Bool.and_eq_true, Option.all_eq_true]
    refine ⟨⟨⟨⟨decide_eq_true rfl, fun x hx => ?_⟩, fun e he => decide_eq_true (findEvidence_id he)⟩, rfl⟩,
      fun x hx => ?_⟩
    · obtain ⟨hpid, hmem⟩ := hid x hx
      exact ⟨decide_eq_true hpid, hc _ hmem⟩
    · obtain ⟨p, hp, hx⟩ := Option.bind_eq_some_iff.mp hx
      obtain ⟨pk, hk, rfl⟩ := Option.map_eq_some_iff.mp hx
      obtain ⟨k, -, rfl⟩ := Option.map_eq_some_iff.mp hk
      have ho := List.find?_some hp
      simp only [decide_eq_true_eq] at ho
      refine ⟨⟨decide_eq_true ho, hc _ (List.mem_of_find?_eq_some hp)⟩,
        fun e he => decide_eq_true ?_⟩
      obtain ⟨id, hr, he⟩ := Option.bind_eq_some_iff.mp he
      show some e.evidenceId = p.reversalEvidenceId
      rw [hr, findEvidence_id he]
  | reverse c =>
    simp only [coherent, Bool.and_eq_true, Option.all_eq_true]
    refine ⟨⟨⟨⟨decide_eq_true rfl, fun x hx => ?_⟩, fun e he => decide_eq_true (findEvidence_id he)⟩, rfl⟩,
      rfl, rfl⟩
    obtain ⟨hpid, hmem⟩ := hid x hx
    exact ⟨decide_eq_true hpid, hc _ hmem⟩

theorem decodePaymentItem_cases {w : Bytes} {v : PaymentView} (h : decodePaymentItem w = some v) :
    (∃ r, decodePaymentRequest w = some r ∧ viewOfAnchor r = some v) ∨
      (viewWellFormed v = true ∧ coherent v = true) := by
  unfold decodePaymentItem at h
  split at h
  · split at h
    · exact .inl (Option.bind_eq_some_iff.mp h)
    · split at h
      · obtain ⟨-, hf⟩ := Option.filter_eq_some_iff.mp h
        simp only [Bool.and_eq_true] at hf
        exact .inr ⟨hf.1.1, hf.1.2⟩
      · cases h
  · cases h

/-- The worker steps only views whose command is well formed: the hypothesis `hw` of
    `chain_fold_eq_full`. Form A: `decodePaymentRequest`'s filter (Codec.lean:79, as
    CodecLaws.lean:371); form B: `viewWellFormed` (above). -/
theorem decodePaymentItem_command {w : Bytes} {v : PaymentView} (h : decodePaymentItem w = some v) :
    (commandWellFormed v.command && v.expectedRevision.all (· < 2 ^ 63)) = true := by
  rcases decodePaymentItem_cases h with ⟨r, hr, hv⟩ | ⟨hw, -⟩
  · unfold decodePaymentRequest at hr
    have hq := (Option.filter_eq_some_iff.mp hr).2
    simp only [Bool.and_eq_true] at hq
    have hq := hq.1.1
    simp only [requestWellFormed, Bool.and_eq_true] at hq
    unfold viewOfAnchor at hv
    obtain ⟨S, -, rfl⟩ := Option.map_eq_some_iff.mp hv
    simp [hq.1.2, hq.2]
  · simp only [viewWellFormed, Bool.and_eq_true] at hw
    simp [hw.1.2, hw.2]

theorem decodePaymentItem_coherent {w : Bytes} {v : PaymentView} (h : decodePaymentItem w = some v) :
    coherent v = true := by
  rcases decodePaymentItem_cases h with ⟨r, -, hv⟩ | ⟨-, hc⟩
  · exact viewOfAnchor_coherent hv
  · exact hc

/-! ## 16.2 items 3 and 4: the lockstep proofs (helpers are private) -/

/-! ## Contributions: the insertion sort is a sort -/

private def cb (x y : EvalContribution) : Bool :=
  contributionKeyBefore x.time x.amountCents x.identity y.time y.amountCents y.identity

private theorem cb_iff {x y : EvalContribution} : cb x y = true ↔
    x.time < y.time ∨ (x.time = y.time ∧ (x.amountCents < y.amountCents ∨
      (x.amountCents = y.amountCents ∧ x.identity < y.identity))) := by
  simp [cb, contributionKeyBefore]

private theorem cb_trans {x y z : EvalContribution} (h1 : cb x y = true) (h2 : cb y z = true) :
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

private theorem cb_asymm {x y : EvalContribution} (h : cb x y = true) : cb y x = false := by
  cases h' : cb y x
  · rfl
  · have := cb_trans h h'
    rw [cb_iff] at this
    rcases this with h | ⟨-, h | ⟨-, h⟩⟩
    · omega
    · omega
    · exact absurd h (String.lt_irrefl _)

private theorem cb_conn {x y : EvalContribution} (h1 : cb x y = false) (h2 : cb y x = false) : x = y := by
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

private theorem ins_cons (y a : EvalContribution) (l : List EvalContribution) :
    evalInsertContribution y (a :: l) = if cb y a = true then y :: a :: l else a :: evalInsertContribution y l := rfl

private def Sorted (l : List EvalContribution) : Prop := l.Pairwise fun a b => cb b a = false

private theorem insert_sorted (y : EvalContribution) :
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

private theorem sort_sorted : ∀ l, Sorted (evalSortContributions l)
  | [] => by simp [evalSortContributions, Sorted]
  | a :: l => insert_sorted a (sort_sorted l)

private theorem sorted_eq {l₁ l₂ : List EvalContribution} (h : l₁.Perm l₂) (s₁ : Sorted l₁) (s₂ : Sorted l₂) :
    l₁ = l₂ :=
  h.eq_of_pairwise (fun _ _ _ _ h1 h2 => cb_conn h2 h1) s₁ s₂

private theorem sort_congr {l₁ l₂ : List EvalContribution} (h : l₁.Perm l₂) :
    evalSortContributions l₁ = evalSortContributions l₂ :=
  sorted_eq ((evalSortContributions_perm _).trans (h.trans (evalSortContributions_perm _).symm))
    (sort_sorted _) (sort_sorted _)

private theorem sort_erase (x : EvalContribution) {l : List EvalContribution} (h : x ∈ l) :
    (evalSortContributions l).erase x = evalSortContributions (l.erase x) := by
  have p : l.Perm (x :: l.erase x) := List.perm_cons_erase h
  have e : evalSortContributions l = evalInsertContribution x (evalSortContributions (l.erase x)) := by
    rw [sort_congr p]; rfl
  rw [e]
  refine sorted_eq ?_ ?_ (sort_sorted _)
  · exact ((evalInsertContribution_perm x _).erase x).trans (by simp)
  · exact (insert_sorted x (sort_sorted _)).sublist List.erase_sublist

/-! ## Insertion, canonical lists -/

private theorem insertBy_perm {α} (key : α → String) (row : α) :
    ∀ l : List α, (insertBy key row l).Perm (row :: l)
  | [] => .refl _
  | x :: xs => by
    unfold insertBy
    split
    · exact .refl _
    · exact ((insertBy_perm key row xs).cons x).trans (.swap row x xs)

private theorem str_trich (a b : String) : a < b ∨ a = b ∨ b < a := by
  by_cases h1 : a < b
  · exact Or.inl h1
  · by_cases h2 : b < a
    · exact Or.inr (Or.inr h2)
    · exact Or.inr (Or.inl (String.le_antisymm (String.not_lt.1 h2) (String.not_lt.1 h1)))

private theorem sa_iff : ∀ l : List String, strictlyAscending l = true ↔ l.Pairwise (· < ·)
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

private theorem pairwise_insert_str (s : String) :
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

private theorem canonical_insert {l : List String} (h : canonicalIdList l = true) {s : String}
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

private theorem evalAdd_eq' (a b : Nat) : evalAdd a b = if a + b ≤ maxCents then some (a + b) else none := by
  unfold evalAdd
  by_cases h : a + b ≤ maxCents
  · rw [if_pos h, if_pos]
    simp only [Bool.and_eq_true, decide_eq_true_eq]; omega
  · rw [if_neg h, if_neg]
    simp only [Bool.and_eq_true, decide_eq_true_eq]; omega

private theorem evalPaymentSum_eq : ∀ ps : List Payment,
    evalPaymentSum ps = if activeCents ps ≤ maxCents then some (activeCents ps) else none
  | [] => by simp [evalPaymentSum, activeCents, maxCents]
  | p :: ps => by
    have ih := evalPaymentSum_eq ps
    by_cases hs : p.status = .ACTIVE
    · have e : activeCents (p :: ps) = p.amountCents + activeCents ps := by
        simp [activeCents, hs]
      rw [e]
      by_cases h1 : activeCents ps ≤ maxCents
      · rw [if_pos h1] at ih
        simp only [evalPaymentSum, ih, hs, if_true]
        exact evalAdd_eq' _ _
      · rw [if_neg h1] at ih
        have : ¬ p.amountCents + activeCents ps ≤ maxCents := by omega
        simp only [evalPaymentSum, ih, if_neg this]; rfl
    · have e : activeCents (p :: ps) = activeCents ps := by
        simp [activeCents, hs]
      rw [e]
      by_cases h1 : activeCents ps ≤ maxCents
      · rw [if_pos h1] at ih
        simp [evalPaymentSum, ih, hs, h1]
      · rw [if_neg h1] at ih
        simp [evalPaymentSum, ih, hs, h1]

/-- `evaluate` succeeds iff the input is well formed, both claim sums exist and cash + lawful fits. -/
theorem evaluate_isSome (i : FinancialInput) :
    (evaluate i).isSome = (financialInputWellFormed i &&
      ((evalClaimedSum i.claims).bind fun _ => evalLawfulSum i.claims).any
        fun l => activeCents i.payments + l ≤ maxCents) := by
  unfold evaluate
  cases hw : financialInputWellFormed i with
  | false => simp
  | true =>
    simp only [if_true, Bool.true_and, evaluateWellFormed, Option.isSome_map]
    unfold evaluateTotals
    rw [evalPaymentSum_eq]
    cases hc : evalClaimedSum i.claims with
    | none => by_cases h1 : activeCents i.payments ≤ maxCents <;> simp [h1]
    | some cl =>
      cases hl : evalLawfulSum i.claims with
      | none => by_cases h1 : activeCents i.payments ≤ maxCents <;> simp [h1]
      | some la =>
        by_cases h1 : activeCents i.payments ≤ maxCents
        · simp only [if_pos h1, evalAdd_eq']
          by_cases h2 : activeCents i.payments + la ≤ maxCents <;> simp [h2]
        · have h2 : ¬ activeCents i.payments + la ≤ maxCents := by omega
          simp [h1, h2]

private theorem evaluateTotals_payments {i : FinancialInput} {t} (h : evaluateTotals i = some t)
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

private def pcOf (P : List Payment) : List EvalContribution :=
  P.foldr (fun payment rest =>
    if payment.status = .ACTIVE then
      { time := payment.eventAt, identity := payment.paymentId, amountCents := payment.amountCents } :: rest
    else rest) []

private def dcOf (D : List OffsetDetermination) : List EvalContribution :=
  D.foldr (fun determination rest =>
    if determination.decision = .OFFSET_AUTHORIZED then
      { time := determination.decidedAt, identity := determination.determinationId,
        amountCents := determination.amountCents } :: rest
    else rest) []

private theorem evalContributions_eq (i : FinancialInput) :
    evalContributions i = pcOf i.payments ++ dcOf i.determinations := rfl

private def cOf (p : Payment) : EvalContribution := ⟨p.eventAt, p.paymentId, p.amountCents⟩

private theorem pcOf_eq (P : List Payment) :
    pcOf P = (P.filter fun q => q.status = .ACTIVE).map cOf := by
  induction P with
  | nil => rfl
  | cons p ps ih =>
    by_cases hs : p.status = .ACTIVE <;> simp [pcOf, hs, cOf] at ih ⊢ <;> exact ih

private theorem pcOf_perm {P Q : List Payment} (h : P.Perm Q) : (pcOf P).Perm (pcOf Q) := by
  rw [pcOf_eq, pcOf_eq]; exact (h.filter _).map _

private theorem pcOf_active {p : Payment} (P : List Payment) (h : p.status = .ACTIVE) :
    pcOf (p :: P) = cOf p :: pcOf P := by
  simp [pcOf, List.foldr_cons, h, cOf]

private theorem pcOf_inactive {p : Payment} (P : List Payment) (h : p.status ≠ .ACTIVE) :
    pcOf (p :: P) = pcOf P := by
  simp [pcOf, List.foldr_cons, h]

private theorem contrib_insert (dc : List EvalContribution) (P : List Payment) (x : Payment)
    (hx : x.status = .ACTIVE) :
    evalSortContributions (pcOf (insertBy Payment.paymentId x P) ++ dc) =
      evalInsertContribution (cOf x) (evalSortContributions (pcOf P ++ dc)) := by
  have hp : (pcOf (insertBy Payment.paymentId x P) ++ dc).Perm (cOf x :: (pcOf P ++ dc)) := by
    have := (pcOf_perm (insertBy_perm Payment.paymentId x P)).append_right dc
    rwa [pcOf_active _ hx, List.cons_append] at this
  rw [sort_congr hp]; rfl

private theorem pcOf_replace (new : Payment) (hnew : new.status ≠ .ACTIVE) :
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

private theorem contrib_replace (dc : List EvalContribution) (P : List Payment) (new q : Payment)
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

/-! ## Well-formedness of a post-state: the 19 conjuncts that read payments, evidence or conflicts -/

private def upd (i : FinancialInput) (P : List Payment) (E : List EvidenceRecord)
    (C : List FinancialConflict) : FinancialInput :=
  { i with payments := P, evidence := E, conflicts := C }

private theorem wf_of_parts {i : FinancialInput} (hi : financialInputWellFormed i = true)
    {P : List Payment} {E : List EvidenceRecord} {C : List FinancialConflict}
    (n17 : P.length ≤ maxRows) (n20 : E.length ≤ maxRows) (n21 : C.length ≤ maxRows)
    (n25 : canonicalIdList (P.map Payment.paymentId) = true)
    (n28 : canonicalIdList (E.map EvidenceRecord.evidenceId) = true)
    (n29 : canonicalIdList (C.map FinancialConflict.conflictId) = true)
    (n32 : P.all (paymentWellFormed i.context) = true)
    (n34 : E.all (evidenceWellFormed i.context) = true)
    (n36 : C.all (conflictWellFormed (upd i P E C)) = true)
    (n39 : P.all (paymentEvidenceWellFormed (upd i P E C)) = true)
    (n40 : P.all (reversalEvidenceWellFormed (upd i P E C)) = true)
    (n41 : i.claims.all (claimEvidenceWellFormed (upd i P E C)) = true)
    (n48 : E.all (fun evidence =>
      if evidence.kind = "PAYMENT_CONFIRMATION" then paymentConfirmationAccounted (upd i P E C) evidence
      else if evidence.kind = "PAYMENT_REVERSAL" then reversalEvidenceAccounted (upd i P E C) evidence
      else if evidence.kind = "OFFSET_CLAIM" then
        i.claims.any (fun claim => claim.evidenceId = evidence.evidenceId)
      else true) = true)
    (n49 : E.all (fun evidence => decide (evidence.receivedAt ≤ i.evaluatedAt)) = true)
    (n51 : allReferencesExist (E.map EvidenceRecord.evidenceId) (P.map Payment.evidenceId) = true)
    (n52 : allReferencesExist (E.map EvidenceRecord.evidenceId) (P.filterMap Payment.reversalEvidenceId) = true)
    (n53 : allReferencesExist (E.map EvidenceRecord.evidenceId) (i.claims.map Claim.evidenceId) = true)
    (n54 : i.determinations.all (fun determination =>
      allReferencesExist (E.map EvidenceRecord.evidenceId) determination.supportingEvidenceIds) = true)
    (n55 : noDuplicates (P.map Payment.commonOriginId) = true) :
    financialInputWellFormed (upd i P E C) = true := by
  simp only [financialInputWellFormed, envWellFormed, envOf, Bool.and_assoc, Bool.and_eq_true, decide_eq_true_eq] at hi ⊢
  obtain ⟨h1,h2,h3,h4,h5,h6,h7,h8,h9,h10,h11,h12,h13,h14,h15,h16,h17,h18,h19,h20,h21,h22,h23,h24,h25,h26,h27,h28,h29,h30,h31,h32,h33,h34,h35,h36,h37,h38,h39,h40,h41,h42,h43,h44,h45,h46,h47,h48,h49,h50,h51,h52,h53,h54,h55⟩ := hi
  exact ⟨h1,h2,h3,h4,h5,h6,h7,h8,h9,h10,h11,h12,h13,h14,h15,h16,n17,h18,h19,n20,n21,h22,h23,h24,n25,h26,h27,n28,n29,h30,h31,n32,h33,n34,h35,n36,h37,h38,n39,n40,n41,h42,h43,h44,h45,h46,h47,n48,n49,h50,n51,n52,n53,n54,n55⟩

private theorem noDup_iff : ∀ l : List String, noDuplicates l = true ↔ l.Nodup
  | [] => by simp [noDuplicates]
  | a :: l => by
    rw [noDuplicates, List.nodup_cons, ← noDup_iff l]
    simp [List.contains_iff_mem]

private theorem payments_le_evidence {post : FinancialInput}
    (h39 : post.payments.all (paymentEvidenceWellFormed post) = true)
    (h51 : allReferencesExist (post.evidence.map EvidenceRecord.evidenceId) (post.payments.map Payment.evidenceId) = true)
    (h55 : noDuplicates (post.payments.map Payment.commonOriginId) = true) :
    post.payments.length ≤ post.evidence.length := by
  let g : String → String := fun id => ((findEvidence post.evidence id).map (·.commonOriginId)).getD ""
  have hg : post.payments.map Payment.commonOriginId = (post.payments.map Payment.evidenceId).map g := by
    rw [List.map_map]
    refine List.map_congr_left fun p hp => ?_
    have := List.all_eq_true.1 h39 p hp
    unfold paymentEvidenceWellFormed at this
    cases hf : findEvidence post.evidence p.evidenceId with
    | none => simp [hf] at this
    | some ev =>
      rw [hf] at this
      simp only [Bool.and_eq_true, decide_eq_true_eq] at this
      show _ = g p.evidenceId
      simp only [g, hf, Option.map_some, Option.getD_some]
      exact this.1.1.2.symm
  have hnd : (post.payments.map Payment.evidenceId).Nodup := by
    have := (noDup_iff _).1 h55
    rw [hg] at this
    exact List.Pairwise.of_map g (fun a b h e => h (by rw [e])) this
  have hsub : (post.payments.map Payment.evidenceId) ⊆ post.evidence.map EvidenceRecord.evidenceId := by
    intro x hx
    have := List.all_eq_true.1 h51 x hx
    simpa using this
  have := hnd.length_le_of_subset hsub
  simpa using this

private theorem evalLatestCase_const (st : CaseStatus) (t : Nat) :
    ∀ K : List CaseRecord, K ≠ [] →
      evalLatestCase (K.map fun k => { k with status := st, updatedAt := t }) = st
  | [], h => absurd rfl h
  | [_], _ => rfl
  | _ :: k2 :: ks, _ => by
    simp only [List.map_cons]
    exact evalLatestCase_const st t (k2 :: ks) (by simp)

private theorem summarize_some {i : FinancialInput} {rs b S} (h : summarize i rs b = some S) :
    ∃ t, evaluateTotals i = some t ∧
      S = { revision := i.beforeRevision, cash := t.cash, claimed := t.claimed, lawful := t.lawful,
            contributions := evalSortContributions (evalContributions i),
            latestCase := evalLatestCase i.cases, delivery := evalLatestDelivery i.actions,
            conflictCount := i.conflicts.length, evidenceIds := i.evidence.map (·.evidenceId),
            requests := (i.actions.filter (·.kind = "CORRECTION_PAYMENT_REQUEST")).map
              (requestPaidOf i.payments (linksOf rs)),
            anchorBytes := b } := by
  unfold summarize at h
  cases ht : evaluateTotals i with
  | none => simp [ht] at h
  | some t =>
    simp only [ht, Option.map_some, Option.some.injEq] at h
    exact ⟨t, rfl, h.symm⟩

private theorem evaluate_after {i : FinancialInput} {res} (h : evaluate i = some res) :
    res.afterRevision = i.beforeRevision + 1 := by
  unfold evaluate at h
  split at h
  · unfold evaluateWellFormed at h
    cases hT : evaluateTotals i with
    | none => simp [hT] at h
    | some t => simp only [hT, Option.map_some, Option.some.injEq] at h; subst h; rfl
  · simp at h

private theorem evaluate_none_of {i : FinancialInput}
    (h : financialInputWellFormed i = true → evaluateTotals i = none) : evaluate i = none := by
  unfold evaluate
  by_cases hw : financialInputWellFormed i = true
  · rw [if_pos hw]; unfold evaluateWellFormed; rw [h hw]; rfl
  · rw [if_neg hw]

private theorem summary_commit {post : FinancialInput} {res : FinancialResult} {rs : List Receipt} {s' : ItemState}
    (hcases : post.cases ≠ [])
    (hs : summarize post rs (anchorItemLength post rs) = some s')
    (hres : res.afterRevision = post.beforeRevision + 1) :
    summaryOf (commitInput post res) rs = some (settle s' res) := by
  have hA : anchorItemLength (commitInput post res) rs = anchorItemLength post rs := by
    unfold anchorItemLength; rw [rawEncode_commit_length]
  unfold summaryOf
  rw [hA]
  obtain ⟨t, ht, rfl⟩ := summarize_some hs
  unfold summarize
  have hT : evaluateTotals (commitInput post res) = some t := ht
  rw [hT]
  simp only [Option.map_some, Option.some.injEq, settle, commitInput, hres]
  rw [evalLatestCase_const _ _ _ hcases]
  rfl

/-- The commit step, for any write set whose `advance` is the summary of the written post-state. -/
private theorem commit_core {r : PaymentRequest} {V : PaymentView} {S : ItemState} {k : Mutation} {w : Writes}
    (hb : r.inputBytes = (rawEncodeFinancialInput r.input).length)
    (hS : summarize r.input r.receipts (anchorItemLength r.input r.receipts) = some S)
    (hVenv : V.env = envOf r.input)
    (hgrow : anchorGrowth V w = addedBytes r.input w + receiptBytes w)
    (hraw : (rawEncodeFinancialInput (applyWrites r.input w)).length =
      (rawEncodeFinancialInput r.input).length + addedBytes r.input w)
    (hcases : r.input.cases ≠ [])
    (hadv : ∀ s', advance V S w = some s' → financialInputWellFormed (applyWrites r.input w) = true)
    (hsum : financialInputWellFormed (applyWrites r.input w) = true →
      advance V S w = summarize (applyWrites r.input w) (commitReceipts r.receipts w)
        (S.anchorBytes + anchorGrowth V w)) :
    some (commitView V S k w) = project r (mutate r k w) := by
  have hSb : S.anchorBytes = anchorItemLength r.input r.receipts := by
    obtain ⟨t, -, rfl⟩ := summarize_some hS; rfl
  have hcr := commitReceipts_len r.receipts w
  have hcap : (S.anchorBytes + anchorGrowth V w + maxCallTailBytes > maxTotalEncodedBytes) ↔
      ¬ withinCapacity r w = true := by
    simp only [withinCapacity, anchorItemLength, decide_eq_true_eq] at hSb ⊢
    omega
  unfold commitView mutate
  rw [hVenv]
  by_cases hsh : r.input.context.mode = .SHADOW
  · simp [envOf, hsh, project]
  have hsh' : (envOf r.input).context.mode ≠ .SHADOW := hsh
  simp only [hsh', hsh, if_false]
  by_cases hcp : withinCapacity r w = true
  · have hc2 : ¬ (S.anchorBytes + anchorGrowth V w + maxCallTailBytes > maxTotalEncodedBytes) :=
      fun h => (hcap.1 h) hcp
    simp only [hc2, hcp, if_false, Bool.not_true, Bool.false_eq_true]
    cases hA : advance V S w with
    | none =>
      have hnone : evaluate (applyWrites r.input w) = none := by
        refine evaluate_none_of fun hw => ?_
        have := hsum hw
        rw [hA] at this
        unfold summarize at this
        cases ht : evaluateTotals (applyWrites r.input w) with
        | none => rfl
        | some t => simp [ht] at this
      simp [hnone, project]
    | some s' =>
      have hw := hadv s' hA
      have hs' := (hsum hw).symm.trans hA
      have hb' : S.anchorBytes + anchorGrowth V w =
          anchorItemLength (applyWrites r.input w) (commitReceipts r.receipts w) := by
        simp only [anchorItemLength, hraw, hSb, hgrow] at hcr ⊢
        omega
      rw [hb'] at hs'
      have hev : evaluateState (envOf r.input) s' = evaluate (applyWrites r.input w) :=
        evaluateState_summarize hw hs'
      dsimp only
      rw [hev]
      cases hE : evaluate (applyWrites r.input w) with
      | none => simp [project]
      | some res =>
        have hres := evaluate_after hE
        have hsc := summary_commit (post := applyWrites r.input w) hcases hs' hres
        simp [project, hsc]
  · have hc2 : S.anchorBytes + anchorGrowth V w + maxCallTailBytes > maxTotalEncodedBytes :=
      hcap.2 hcp
    simp [hc2, hcp, project]

/-! ## Lookup and list facts -/

private theorem findEvidence_mem {l : List EvidenceRecord} {id e} (h : findEvidence l id = some e) : e ∈ l := by
  rw [findEvidence_eq] at h; exact List.mem_of_find?_eq_some h

private theorem findEvidence_none_ne {l : List EvidenceRecord} {id} (h : findEvidence l id = none) :
    ∀ e ∈ l, e.evidenceId ≠ id := by
  rw [findEvidence_eq, List.find?_eq_none] at h
  intro e he eq; exact h e he (by simp [eq])

private theorem findPayment_none_ne {l : List Payment} {id} (h : findPayment l id = none) :
    ∀ p ∈ l, p.paymentId ≠ id := by
  rw [findPayment_eq, List.find?_eq_none] at h
  intro e he eq; exact h e he (by simp [eq])

private theorem length_insertBy {α} (key : α → String) (row : α) (l : List α) :
    (insertBy key row l).length = l.length + 1 := by
  rw [(insertBy_perm key row l).length_eq]; rfl

private theorem all_insertBy {α} (key : α → String) (row : α) (f : α → Bool) {l : List α}
    (hr : f row = true) (hl : l.all f = true) : (insertBy key row l).all f = true := by
  rw [List.all_eq_true] at hl ⊢
  intro x hx
  rcases (mem_insertBy key row x l).1 hx with rfl | h
  · exact hr
  · exact hl x h

private theorem mem_replace {P : List Payment} {new : Payment} {pid : String} {x : Payment}
    (hx : x ∈ P.map fun y => if y.paymentId = pid then new else y) : x = new ∨ x ∈ P := by
  obtain ⟨y, hy, rfl⟩ := List.mem_map.1 hx
  by_cases h : y.paymentId = pid
  · left; simp [h]
  · right; simpa [h] using hy

/-! ## Row predicates are monotone under growth of the evidence list -/

private theorem pew_mono {i j : FinancialInput}
    (h : ∀ id ev, findEvidence i.evidence id = some ev → findEvidence j.evidence id = some ev)
    {q : Payment} (hq : paymentEvidenceWellFormed i q = true) : paymentEvidenceWellFormed j q = true := by
  unfold paymentEvidenceWellFormed at hq ⊢
  cases hf : findEvidence i.evidence q.evidenceId with
  | none => simp [hf] at hq
  | some ev => rw [hf] at hq; rw [h _ _ hf]; exact hq

private theorem cew_mono {i j : FinancialInput}
    (h : ∀ id ev, findEvidence i.evidence id = some ev → findEvidence j.evidence id = some ev)
    {q : Claim} (hq : claimEvidenceWellFormed i q = true) : claimEvidenceWellFormed j q = true := by
  unfold claimEvidenceWellFormed at hq ⊢
  cases hf : findEvidence i.evidence q.evidenceId with
  | none => simp [hf] at hq
  | some ev => rw [hf] at hq; rw [h _ _ hf]; exact hq

private theorem rew_mono {i j : FinancialInput}
    (h : ∀ id ev, findEvidence i.evidence id = some ev → findEvidence j.evidence id = some ev)
    {q : Payment} (hq : reversalEvidenceWellFormed i q = true) : reversalEvidenceWellFormed j q = true := by
  unfold reversalEvidenceWellFormed at hq ⊢
  rcases hs : q.status with _ | _ <;> rcases hr : q.reversalEvidenceId with _ | e <;>
    simp only [hs, hr] at hq ⊢
  · exact absurd hq (by decide)
  · exact absurd hq (by decide)
  cases hf : findEvidence i.evidence e with
  | none => simp [hf] at hq
  | some ev => rw [hf] at hq; rw [h _ _ hf]; exact hq

private theorem confl_mono {i j : FinancialInput} (hc : j.context = i.context)
    (he : ∀ id ev, findEvidence i.evidence id = some ev → findEvidence j.evidence id = some ev)
    (hp : ∀ id q, findPayment i.payments id = some q → ∃ q', findPayment j.payments id = some q' ∧
      q'.commonOriginId = q.commonOriginId ∧ q'.amountCents = q.amountCents)
    {x : FinancialConflict} (hx : conflictWellFormed i x = true) : conflictWellFormed j x = true := by
  unfold conflictWellFormed at hx ⊢
  rw [hc]
  simp only [Bool.and_eq_true] at hx ⊢
  obtain ⟨hA, hB⟩ := hx
  refine ⟨hA, ?_⟩
  rcases hq : findPayment i.payments x.existingPaymentId with _ | q <;>
    rcases hq' : findEvidence i.evidence x.candidateEvidenceId with _ | ev <;> simp only [hq, hq'] at hB
  all_goals try exact absurd hB (by decide)
  obtain ⟨q', hq2, ho, ha⟩ := hp _ _ hq
  rw [hq2, he _ _ hq']
  simpa only [ho, ha] using hB

private theorem accConf_mono {i j : FinancialInput}
    (hp : ∀ q ∈ i.payments, ∃ q' ∈ j.payments, q'.evidenceId = q.evidenceId ∧
      q'.commonOriginId = q.commonOriginId ∧ q'.amountCents = q.amountCents)
    (hc : ∀ x ∈ i.conflicts, x ∈ j.conflicts) {ev : EvidenceRecord}
    (h : paymentConfirmationAccounted i ev = true) : paymentConfirmationAccounted j ev = true := by
  unfold paymentConfirmationAccounted at h ⊢
  simp only [Bool.or_eq_true, List.any_eq_true, decide_eq_true_eq] at h ⊢
  rcases h with (⟨q, hq, hqe⟩ | ⟨x, hx, hxe⟩) | h
  · obtain ⟨q', hq', he, -, -⟩ := hp q hq
    exact Or.inl (Or.inl ⟨q', hq', he.trans hqe⟩)
  · exact Or.inl (Or.inr ⟨x, hc x hx, hxe⟩)
  · right
    cases ha : ev.amountCents with
    | none => simp [ha] at h
    | some a =>
      simp only [ha, List.any_eq_true, Bool.and_eq_true, decide_eq_true_eq] at h ⊢
      obtain ⟨q, hq, ho, hm⟩ := h
      obtain ⟨q', hq', -, ho', hm'⟩ := hp q hq
      exact ⟨q', hq', by rw [ho', ho], by rw [hm', hm]⟩

private theorem accRev_mono {i j : FinancialInput}
    (hp : ∀ id q, findPayment i.payments id = some q → q.status = .REVERSED →
      findPayment j.payments id = some q)
    {ev : EvidenceRecord} (h : reversalEvidenceAccounted i ev = true) :
    reversalEvidenceAccounted j ev = true := by
  unfold reversalEvidenceAccounted at h ⊢
  cases hr : ev.reversalOf with
  | none => simp [hr] at h
  | some pid =>
    simp only [hr] at h ⊢
    cases hf : findPayment i.payments pid with
    | none => simp [hf] at h
    | some q =>
      simp only [hf] at h
      have hq : q.status = .REVERSED := by
        revert h; simp only [Bool.and_eq_true, decide_eq_true_eq]; intro h; exact h.1.1.1.1
      rw [hp pid q hf hq]
      exact h

/-- The evidence-accounted conjunct, as a function of the input (its `i.claims` is `j.claims`). -/
private def accLam (j : FinancialInput) (evidence : EvidenceRecord) : Bool :=
  if evidence.kind = "PAYMENT_CONFIRMATION" then paymentConfirmationAccounted j evidence
  else if evidence.kind = "PAYMENT_REVERSAL" then reversalEvidenceAccounted j evidence
  else if evidence.kind = "OFFSET_CLAIM" then
    j.claims.any (fun claim => claim.evidenceId = evidence.evidenceId)
  else true

private theorem wf_ctx {i : FinancialInput} (h : financialInputWellFormed i = true) :
    idWellFormed i.context.obligationId = true ∧ idWellFormed i.context.itemId = true ∧
      i.evaluatedAt ≤ maxTime := by
  simp only [financialInputWellFormed, envWellFormed, envOf, Bool.and_assoc, Bool.and_eq_true, decide_eq_true_eq] at h
  obtain ⟨h1, -, -, -, -, -, h7, -⟩ := h
  have hc := h1
  unfold contextWellFormed at hc
  simp only [Bool.and_eq_true] at hc
  obtain ⟨⟨hall, -⟩, -⟩ := hc
  exact ⟨List.all_eq_true.1 hall _ (by simp), List.all_eq_true.1 hall _ (by simp), of_decide_eq_true h7⟩

private theorem accLam_mono {i j : FinancialInput} (hcl : j.claims = i.claims)
    (hp : ∀ q ∈ i.payments, ∃ q' ∈ j.payments, q'.evidenceId = q.evidenceId ∧
      q'.commonOriginId = q.commonOriginId ∧ q'.amountCents = q.amountCents)
    (hc : ∀ x ∈ i.conflicts, x ∈ j.conflicts)
    (hr : ∀ id q, findPayment i.payments id = some q → q.status = .REVERSED →
      findPayment j.payments id = some q)
    {x : EvidenceRecord} (h : accLam i x = true) : accLam j x = true := by
  unfold accLam at h ⊢
  by_cases h1 : x.kind = "PAYMENT_CONFIRMATION"
  · simp only [h1, ↓reduceIte] at h ⊢; exact accConf_mono hp hc h
  by_cases h2 : x.kind = "PAYMENT_REVERSAL"
  · simp only [h2, ↓reduceIte] at h ⊢; exact accRev_mono hr h
  by_cases h3 : x.kind = "OFFSET_CLAIM"
  · simp only [h3, ↓reduceIte] at h ⊢; rw [hcl]; exact h
  · simp only [h1, h2, h3, ↓reduceIte] at h ⊢

private theorem known_of_find {E : List EvidenceRecord} {id e} (h : findEvidence E id = some e) :
    (E.map EvidenceRecord.evidenceId).contains id = true :=
  List.contains_iff_mem.2 (List.mem_map.2 ⟨e, findEvidence_mem h, findEvidence_id h⟩)

private theorem find_of_known {E : List EvidenceRecord} {id}
    (h : (E.map EvidenceRecord.evidenceId).contains id = true) : ∃ e, findEvidence E id = some e := by
  cases hf : findEvidence E id with
  | some e => exact ⟨e, rfl⟩
  | none =>
    obtain ⟨e, he, rfl⟩ := List.mem_map.1 (List.contains_iff_mem.1 h)
    exact absurd rfl (findEvidence_none_ne hf e he)

private theorem wf_grow {i : FinancialInput} (hi : financialInputWellFormed i = true)
    {P : List Payment} {E : List EvidenceRecord} {C : List FinancialConflict}
    (hE : ∀ id ev, findEvidence i.evidence id = some ev → findEvidence E id = some ev)
    (hPf : ∀ id q, findPayment i.payments id = some q → ∃ q', findPayment P id = some q' ∧
      q'.commonOriginId = q.commonOriginId ∧ q'.amountCents = q.amountCents ∧ q'.evidenceId = q.evidenceId)
    (hPr : ∀ id q, findPayment i.payments id = some q → q.status = .REVERSED → findPayment P id = some q)
    (hCm : ∀ x ∈ i.conflicts, x ∈ C)
    (n20 : E.length ≤ maxRows) (n21 : C.length ≤ maxRows)
    (n25 : P.length ≤ maxRows → canonicalIdList (P.map Payment.paymentId) = true)
    (n28 : canonicalIdList (E.map EvidenceRecord.evidenceId) = true)
    (n29 : canonicalIdList (C.map FinancialConflict.conflictId) = true)
    (n55 : noDuplicates (P.map Payment.commonOriginId) = true)
    (hPnew : ∀ q ∈ P, q ∉ i.payments → paymentWellFormed i.context q = true ∧
      paymentEvidenceWellFormed (upd i P E C) q = true ∧ reversalEvidenceWellFormed (upd i P E C) q = true)
    (hEnew : ∀ x ∈ E, x ∉ i.evidence → evidenceWellFormed i.context x = true ∧
      x.receivedAt ≤ i.evaluatedAt ∧ accLam (upd i P E C) x = true)
    (hCnew : ∀ x ∈ C, x ∉ i.conflicts → conflictWellFormed (upd i P E C) x = true) :
    financialInputWellFormed (upd i P E C) = true := by
  have hi' := hi
  simp only [financialInputWellFormed, envWellFormed, envOf, Bool.and_assoc, Bool.and_eq_true, decide_eq_true_eq] at hi'
  obtain ⟨h1,h2,h3,h4,h5,h6,h7,h8,h9,h10,h11,h12,h13,h14,h15,h16,h17,h18,h19,h20,h21,h22,h23,h24,h25,h26,h27,h28,h29,h30,h31,h32,h33,h34,h35,h36,h37,h38,h39,h40,h41,h42,h43,h44,h45,h46,h47,h48,h49,h50,h51,h52,h53,h54,h55⟩ := hi'
  have hp : ∀ q ∈ i.payments, ∃ q' ∈ P, q'.evidenceId = q.evidenceId ∧
      q'.commonOriginId = q.commonOriginId ∧ q'.amountCents = q.amountCents := by
    intro q hq
    have hnd := nodup_ids_of_wf hi
    obtain ⟨q', hq', ho, ha, he⟩ := hPf q.paymentId q (findPayment_of_mem hnd hq)
    exact ⟨q', findPayment_mem hq', he, ho, ha⟩
  have hfp : ∀ id q, findPayment i.payments id = some q → ∃ q', findPayment (upd i P E C).payments id = some q' ∧
      q'.commonOriginId = q.commonOriginId ∧ q'.amountCents = q.amountCents := fun id q h =>
    let ⟨q', a, b, c, _⟩ := hPf id q h; ⟨q', a, b, c⟩
  have n39' : P.all (paymentEvidenceWellFormed (upd i P E C)) = true := by
    rw [List.all_eq_true] at h39 ⊢
    intro q hq
    by_cases hm : q ∈ i.payments
    · exact pew_mono (i := i) (j := upd i P E C) hE (h39 q hm)
    · exact (hPnew q hq hm).2.1
  have n40' : P.all (reversalEvidenceWellFormed (upd i P E C)) = true := by
    rw [List.all_eq_true] at h40 ⊢
    intro q hq
    by_cases hm : q ∈ i.payments
    · exact rew_mono (i := i) (j := upd i P E C) hE (h40 q hm)
    · exact (hPnew q hq hm).2.2
  have n41' : i.claims.all (claimEvidenceWellFormed (upd i P E C)) = true := by
    rw [List.all_eq_true] at h41 ⊢
    exact fun q hq => cew_mono (i := i) (j := upd i P E C) hE (h41 q hq)
  have n51' : allReferencesExist (E.map EvidenceRecord.evidenceId) (P.map Payment.evidenceId) = true := by
    unfold allReferencesExist
    rw [List.all_eq_true]
    intro id hid
    obtain ⟨q, hq, rfl⟩ := List.mem_map.1 hid
    have := List.all_eq_true.1 n39' q hq
    unfold paymentEvidenceWellFormed at this
    cases hf : findEvidence E q.evidenceId with
    | none => simp [upd, hf] at this
    | some e => exact known_of_find hf
  have n17 : P.length ≤ maxRows := Nat.le_trans (payments_le_evidence (post := upd i P E C) n39' n51' n55) n20
  refine wf_of_parts hi n17 n20 n21 (n25 n17) n28 n29 ?_ ?_ ?_ n39' n40' n41' ?_ ?_ n51' ?_ ?_ ?_ n55
  · rw [List.all_eq_true] at h32 ⊢
    intro q hq
    by_cases hm : q ∈ i.payments
    · exact h32 q hm
    · exact (hPnew q hq hm).1
  · rw [List.all_eq_true] at h34 ⊢
    intro x hx
    by_cases hm : x ∈ i.evidence
    · exact h34 x hm
    · exact (hEnew x hx hm).1
  · rw [List.all_eq_true] at h36 ⊢
    intro x hx
    by_cases hm : x ∈ i.conflicts
    · exact confl_mono (i := i) (j := upd i P E C) rfl hE hfp (h36 x hm)
    · exact hCnew x hx hm
  · rw [List.all_eq_true] at h48 ⊢
    intro x hx
    by_cases hm : x ∈ i.evidence
    · exact accLam_mono (i := i) (j := upd i P E C) rfl hp hCm hPr (h48 x hm)
    · exact (hEnew x hx hm).2.2
  · rw [List.all_eq_true] at h49 ⊢
    intro x hx
    by_cases hm : x ∈ i.evidence
    · exact h49 x hm
    · exact decide_eq_true (hEnew x hx hm).2.1
  · -- n52
    unfold allReferencesExist
    rw [List.all_eq_true]
    intro id hid
    obtain ⟨q, hq, hr⟩ := List.mem_filterMap.1 hid
    have := List.all_eq_true.1 n40' q hq
    unfold reversalEvidenceWellFormed at this
    rcases hs : q.status with _ | _ <;> rw [hs, hr] at this
    · simp at this
    · cases hf : findEvidence E id with
      | none => simp [upd, hf] at this
      | some e => exact known_of_find hf
  · -- n53
    unfold allReferencesExist
    rw [List.all_eq_true]
    intro id hid
    obtain ⟨q, hq, rfl⟩ := List.mem_map.1 hid
    have := List.all_eq_true.1 n41' q hq
    unfold claimEvidenceWellFormed at this
    cases hf : findEvidence E q.evidenceId with
    | none => simp [upd, hf] at this
    | some e => exact known_of_find hf
  · -- n54
    rw [List.all_eq_true] at h54 ⊢
    intro d hd
    have := h54 d hd
    unfold allReferencesExist at this ⊢
    rw [List.all_eq_true] at this ⊢
    intro id hid
    obtain ⟨e, he⟩ := find_of_known (this id hid)
    exact known_of_find (hE _ _ he)

/-! ## The fixed strings the row builders write are well formed -/

private theorem utf8_list (s : String) : s.toUTF8.toList = s.toList.flatMap String.utf8EncodeChar := by
  rw [byteArray_toList_eq, String.toUTF8_eq_toByteArray, ← String.utf8Encode_toList]
  unfold List.utf8Encode
  rw [List.toList_data_toByteArray]

private theorem tok_conf : tokenWellFormed "PAYMENT_CONFIRMATION" = true := by
  unfold tokenWellFormed; rw [utf8_list]; decide
private theorem tok_rev : tokenWellFormed "PAYMENT_REVERSAL" = true := by
  unfold tokenWellFormed; rw [utf8_list]; decide
private theorem id_src : idWellFormed "synthetic-payment-source" = true := by
  unfold idWellFormed; rw [utf8_list]; decide
private theorem id_ver : idWellFormed "fixture-v1" = true := by
  unfold idWellFormed; rw [utf8_list]; decide
private theorem id_reason : idWellFormed "CONFLICTING_COMMON_ORIGIN_AMOUNT" = true := by
  unfold idWellFormed; rw [utf8_list]; decide

private theorem maxTime_eq : maxTime = 2 ^ 63 - 1 := rfl

/-! ## What a well-formed command and a refusal-free row give -/

private theorem cmd_record {c : RecordCommand} (h : commandWellFormed (.record c) = true) :
    idWellFormed c.paymentId = true ∧ idWellFormed c.evidenceId = true ∧
      idWellFormed c.commonOriginId = true ∧ idWellFormed c.sourceId = true ∧
      idWellFormed c.sourceVersion = true ∧ c.amountCents ≤ maxCents ∧ c.eventAt ≤ maxTime := by
  have := maxTime_eq
  simp only [commandWellFormed, Bool.and_eq_true, decide_eq_true_eq, List.all_cons, List.all_nil,
    Bool.and_true] at h
  obtain ⟨⟨⟨⟨⟨h1, h2, h3, h4, h5⟩, -⟩, -⟩, h6⟩, h7⟩ := h
  exact ⟨h1, h2, h3, h4, h5, h6, by omega⟩

private theorem cmd_reverse {c : ReverseCommand} (h : commandWellFormed (.reverse c) = true) :
    idWellFormed c.paymentId = true ∧ idWellFormed c.evidenceId = true := by
  simp only [commandWellFormed, Bool.and_eq_true] at h
  exact ⟨h.1.1.1, h.1.1.2⟩

private theorem form_ids {e : EvidenceRecord} (h : formRefusal e = none) :
    idWellFormed e.commonOriginId = true ∧ idWellFormed e.localRef = true := by
  unfold formRefusal at h
  by_cases h1 : idWellFormed e.commonOriginId = true
  · by_cases h2 : idWellFormed e.localRef = true
    · exact ⟨h1, h2⟩
    · simp [h1, h2] at h
  · simp [h1] at h

private theorem confirmation_wf {i : FinancialInput}
    (hctx : idWellFormed i.context.obligationId = true ∧ idWellFormed i.context.itemId = true)
    {c : RecordCommand} (hc : commandWellFormed (.record c) = true) {t : Nat}
    (hform : formRefusal (confirmation i c t) = none) (hle : c.eventAt ≤ t) (ht : t ≤ maxTime) :
    evidenceWellFormed i.context (confirmation i c t) = true := by
  obtain ⟨h1, h2, h3, h4, h5, h6, h7⟩ := cmd_record hc
  obtain ⟨hf1, hf2⟩ := form_ids hform
  simp only [confirmation] at hf1 hf2
  simp [evidenceWellFormed, confirmation, timeWellFormed, amountWellFormed, optionalIdWellFormed,
    kindWellFormed, tok_conf, h2, h3, h4, h5, h6, h7, hf2, hctx.1, hctx.2, hle, ht]

private theorem reversalRecord_wf {i : FinancialInput}
    (hctx : idWellFormed i.context.obligationId = true ∧ idWellFormed i.context.itemId = true)
    (hnow : i.evaluatedAt ≤ maxTime) {c : ReverseCommand} (hc : commandWellFormed (.reverse c) = true)
    {p : Payment} (hp : paymentWellFormed i.context p = true) {time : Nat}
    (hform : formRefusal (reversalRecord i c p time) = none) (hle : time ≤ i.evaluatedAt) :
    evidenceWellFormed i.context (reversalRecord i c p time) = true := by
  obtain ⟨h1, h2⟩ := cmd_reverse hc
  obtain ⟨hf1, hf2⟩ := form_ids hform
  have ht : time ≤ maxTime := by omega
  simp only [reversalRecord] at hf1 hf2
  simp only [paymentWellFormed, Bool.and_eq_true, decide_eq_true_eq, List.all_cons, List.all_nil,
    Bool.and_true, positiveAmountWellFormed, amountWellFormed] at hp
  obtain ⟨⟨⟨⟨⟨⟨hp1, -, -, -, -⟩, -⟩, -⟩, ⟨-, hpa⟩⟩, -⟩, -⟩ := hp
  simp [evidenceWellFormed, reversalRecord, timeWellFormed, amountWellFormed, optionalIdWellFormed,
    kindWellFormed, tok_rev, id_src, id_ver, h2, hf1, hf2, hctx.1, hctx.2, hle, hnow, hp1, hpa, ht]

private theorem recordedPayment_wf {i : FinancialInput}
    (hctx : idWellFormed i.context.obligationId = true ∧ idWellFormed i.context.itemId = true)
    {c : RecordCommand} (hc : commandWellFormed (.record c) = true) (h0 : c.amountCents ≠ 0) :
    paymentWellFormed i.context (recordedPayment i c) = true := by
  obtain ⟨h1, h2, h3, h4, h5, h6, h7⟩ := cmd_record hc
  simp [paymentWellFormed, recordedPayment, timeWellFormed, positiveAmountWellFormed, amountWellFormed,
    optionalIdWellFormed, h1, h2, h3, h6, h7, hctx.1, hctx.2]
  omega

private theorem reversedImage_wf {i : FinancialInput} {p : Payment} (hp : paymentWellFormed i.context p = true)
    {c : ReverseCommand} (hc : commandWellFormed (.reverse c) = true) :
    paymentWellFormed i.context (reversedImage p c) = true := by
  obtain ⟨-, h2⟩ := cmd_reverse hc
  unfold paymentWellFormed at hp ⊢
  rw [Bool.and_eq_true] at hp ⊢
  exact ⟨hp.1, h2⟩

/-! ## Facts read off a well-formed input -/

theorem wf_facts {i : FinancialInput} (h : financialInputWellFormed i = true) :
    i.payments.length ≤ maxRows ∧ i.evidence.length ≤ maxRows ∧ i.conflicts.length ≤ maxRows ∧
    (∀ q ∈ i.payments, paymentWellFormed i.context q = true) ∧
    (∀ q ∈ i.payments, paymentEvidenceWellFormed i q = true) ∧
    (∀ q ∈ i.payments, reversalEvidenceWellFormed i q = true) ∧
    noDuplicates (i.payments.map Payment.commonOriginId) = true ∧ i.cases ≠ [] := by
  simp only [financialInputWellFormed, envWellFormed, envOf, Bool.and_assoc, Bool.and_eq_true, decide_eq_true_eq] at h
  obtain ⟨h1,h2,h3,h4,h5,h6,h7,h8,h9,h10,h11,h12,h13,h14,h15,h16,h17,h18,h19,h20,h21,h22,h23,h24,h25,h26,h27,h28,h29,h30,h31,h32,h33,h34,h35,h36,h37,h38,h39,h40,h41,h42,h43,h44,h45,h46,h47,h48,h49,h50,h51,h52,h53,h54,h55⟩ := h
  refine ⟨h17, h20, h21, List.all_eq_true.1 h32, List.all_eq_true.1 h39, List.all_eq_true.1 h40, h55, ?_⟩
  intro e
  rw [e] at h22
  exact absurd h22 (by simp)

/-! ## Paid totals under insert and replace (the `step_bridge` sums, on bare lists) -/

private theorem paid_eq (i0 : FinancialInput) {P : List Payment} {R : List Receipt}
    (hn : (P.map Payment.paymentId).Nodup) (hR : R.map Receipt.paymentId = P.map Payment.paymentId)
    (a : String) : linkedActivePaidCents P (linksOf R) a = (P.map (paidOn R a)).sum :=
  ledgerPaid_eq (L := ⟨{ i0 with payments := P }, R⟩) ⟨hn, hR⟩ a

private theorem ids_insert {x : Payment} {P : List Payment} :
    (insertBy Payment.paymentId x P).map Payment.paymentId = insertBy (fun s => s) x.paymentId (P.map Payment.paymentId) :=
  map_insertBy Payment.paymentId Payment.paymentId (fun s => s) (fun _ => rfl) x P

private theorem ids_insert_nodup {x : Payment} {P : List Payment} (hn : (P.map Payment.paymentId).Nodup)
    (hf : findPayment P x.paymentId = none) :
    ((insertBy Payment.paymentId x P).map Payment.paymentId).Nodup := by
  have hp := (insertBy_perm Payment.paymentId x P).map Payment.paymentId
  rw [hp.nodup_iff, List.map_cons, List.nodup_cons]
  exact ⟨fun h => let ⟨q, hq, e⟩ := List.mem_map.1 h; findPayment_none_ne hf q hq e, hn⟩

private theorem paid_insert (i0 : FinancialInput) {P : List Payment} {R : List Receipt}
    (hn : (P.map Payment.paymentId).Nodup) (hR : R.map Receipt.paymentId = P.map Payment.paymentId)
    {x : Payment} {K : Receipt} (hx : x.status = .ACTIVE) (hid : K.paymentId = x.paymentId)
    (hf : findPayment P x.paymentId = none) (a : String) :
    linkedActivePaidCents (insertBy Payment.paymentId x P) (linksOf (insertBy Receipt.paymentId K R)) a =
      linkedActivePaidCents P (linksOf R) a + (if K.paysActionId = some a then x.amountCents else 0) := by
  have hrn : receiptOf R K.paymentId = none := by
    rw [hid]; exact receiptOf_none (L := ⟨{ i0 with payments := P }, R⟩) ⟨hn, hR⟩ hf
  have hR' : (insertBy Receipt.paymentId K R).map Receipt.paymentId =
      (insertBy Payment.paymentId x P).map Payment.paymentId := by
    rw [ids_insert, map_insertBy Receipt.paymentId Receipt.paymentId (fun s => s) (fun _ => rfl) K R, hR, hid]
  rw [paid_eq i0 (ids_insert_nodup hn hf) hR', paid_eq i0 hn hR, sum_insertBy]
  have hne : ∀ q ∈ P, q.paymentId ≠ x.paymentId := findPayment_none_ne hf
  have hcongr : P.map (paidOn (insertBy Receipt.paymentId K R) a) = P.map (paidOn R a) :=
    List.map_congr_left fun q hq => by
      simp only [paidOn, receiptOf_insertBy hrn, if_neg (fun e : K.paymentId = q.paymentId =>
        hne q hq (e.symm.trans hid))]
  have hP : paidOn (insertBy Receipt.paymentId K R) a x = if K.paysActionId = some a then x.amountCents else 0 := by
    simp only [paidOn, receiptOf_insertBy hrn, hid, if_true, hx]
    by_cases h : K.paysActionId = some a <;> simp [h]
  rw [hcongr, hP]; omega

private theorem paid_replace (i0 : FinancialInput) {P : List Payment} {R : List Receipt}
    (hn : (P.map Payment.paymentId).Nodup) (hR : R.map Receipt.paymentId = P.map Payment.paymentId)
    {q p0 : Payment} (hq : findPayment P p0.paymentId = some q) (hact : q.status = .ACTIVE)
    (hp0 : p0.status ≠ .ACTIVE) {k : Receipt} (hk : receiptOf R q.paymentId = some k) (a : String) :
    linkedActivePaidCents (P.map fun x => if x.paymentId = p0.paymentId then p0 else x) (linksOf R) a +
      (if k.paysActionId = some a then q.amountCents else 0) = linkedActivePaidCents P (linksOf R) a := by
  have hids : (P.map fun x => if x.paymentId = p0.paymentId then p0 else x).map Payment.paymentId =
      P.map Payment.paymentId := by
    rw [List.map_map]
    refine List.map_congr_left fun x _ => ?_
    simp only [Function.comp]
    by_cases h : x.paymentId = p0.paymentId <;> simp [h]
  rw [paid_eq i0 (hids ▸ hn) (hR.trans hids.symm), paid_eq i0 hn hR]
  have hs := sum_replace (paidOn R a) p0 P q hn hq
  have e1 : paidOn R a q = if k.paysActionId = some a then q.amountCents else 0 := by
    simp [paidOn, hk, hact]
  have e2 : paidOn R a p0 = 0 := by simp [paidOn, hp0]
  rw [e1, e2] at hs
  omega

/-! ## The summary of a grown input -/

private theorem cash_eq {i : FinancialInput} {rs b S} (h : summarize i rs b = some S) :
    S.cash = activeCents i.payments := by
  obtain ⟨t, ht, rfl⟩ := summarize_some h
  have := evaluateTotals_payments ht i.payments
  have e : ({ i with payments := i.payments } : FinancialInput) = i := rfl
  rw [e, ht] at this
  by_cases hc : activeCents i.payments + t.lawful ≤ maxCents
  · rw [if_pos hc] at this
    simp only [Option.some.injEq] at this
    have := congrArg EvaluatedTotals.cash this
    exact this
  · rw [if_neg hc] at this; cases this

private theorem summarize_upd {i : FinancialInput} {rs b0 S} (hS : summarize i rs b0 = some S)
    (P : List Payment) (E : List EvidenceRecord) (C : List FinancialConflict) (rs' : List Receipt) (b : Nat) :
    summarize (upd i P E C) rs' b =
      if activeCents P + S.lawful ≤ maxCents then
        some { S with
          cash := activeCents P,
          contributions := evalSortContributions (pcOf P ++ dcOf i.determinations),
          conflictCount := C.length, evidenceIds := E.map EvidenceRecord.evidenceId,
          requests := (i.actions.filter (·.kind = "CORRECTION_PAYMENT_REQUEST")).map
            (requestPaidOf P (linksOf rs')),
          anchorBytes := b }
      else none := by
  obtain ⟨t, ht, rfl⟩ := summarize_some hS
  have e : evaluateTotals (upd i P E C) = evaluateTotals { i with payments := P } := rfl
  unfold summarize
  rw [e, evaluateTotals_payments ht P]
  by_cases hc : activeCents P + t.lawful ≤ maxCents
  · rw [if_pos hc, if_pos hc]; rfl
  · rw [if_neg hc, if_neg hc]; rfl

theorem activeCents_insert {x : Payment} (hx : x.status = .ACTIVE) (P : List Payment) :
    activeCents (insertBy Payment.paymentId x P) = x.amountCents + activeCents P := by
  rw [activeCents_eq, activeCents_eq, sum_insertBy, if_pos hx]

theorem activeCents_replace {P : List Payment} {q p0 : Payment} (hn : (P.map Payment.paymentId).Nodup)
    (hq : findPayment P p0.paymentId = some q) (hact : q.status = .ACTIVE) (hp0 : p0.status ≠ .ACTIVE) :
    activeCents (P.map fun x => if x.paymentId = p0.paymentId then p0 else x) + q.amountCents =
      activeCents P := by
  have := sum_replace (fun x : Payment => if x.status = .ACTIVE then x.amountCents else 0) p0 P q hn hq
  rw [activeCents_eq, activeCents_eq]
  simp only [if_pos hact, if_neg hp0] at this
  omega

/-! ## Facts read off a summary -/

private theorem S_facts {i : FinancialInput} {rs b S} (h : summarize i rs b = some S) :
    S.evidenceIds = i.evidence.map EvidenceRecord.evidenceId ∧ S.conflictCount = i.conflicts.length ∧
    S.cash = activeCents i.payments ∧ S.cash + S.lawful ≤ maxCents ∧
    S.contributions = evalSortContributions (pcOf i.payments ++ dcOf i.determinations) ∧
    S.requests = (i.actions.filter (·.kind = "CORRECTION_PAYMENT_REQUEST")).map
      (requestPaidOf i.payments (linksOf rs)) ∧
    S.anchorBytes = b := by
  have hc := cash_eq h
  obtain ⟨t, ht, rfl⟩ := summarize_some h
  have := evaluateTotals_payments ht i.payments
  have e : ({ i with payments := i.payments } : FinancialInput) = i := rfl
  rw [e, ht] at this
  refine ⟨rfl, rfl, hc, ?_, rfl, rfl, rfl⟩
  by_cases hq : activeCents i.payments + t.lawful ≤ maxCents
  · rw [hc]; exact hq
  · rw [if_neg hq] at this; cases this

/-! ## The evidence write of a record: a fresh confirmation, or a stored retry of it -/

def EvCase (i : FinancialInput) (c : RecordCommand) (ev : Option EvidenceRecord) : Prop :=
  (ev = some (confirmation i c i.evaluatedAt) ∧ findEvidence i.evidence c.evidenceId = none ∧
    formRefusal (confirmation i c i.evaluatedAt) = none ∧ c.eventAt ≤ i.evaluatedAt) ∨
  (ev = none ∧ ∃ t, findEvidence i.evidence c.evidenceId = some (confirmation i c t))

theorem evCase_of {r : PaymentRequest} {c ev} (h : EvidenceWrite r c ev) : EvCase r.input c ev := by
  obtain ⟨hf, hle, -, h | h⟩ := h
  · exact Or.inl ⟨h.1, h.2, hf, hle⟩
  · obtain ⟨hn, s, hs, -, hc⟩ := h
    exact Or.inr ⟨hn, s.receivedAt, by rw [hc]; exact hs⟩

private def evOf (i : FinancialInput) (ev : Option EvidenceRecord) : List EvidenceRecord :=
  (ev.map fun e => insertBy EvidenceRecord.evidenceId e i.evidence).getD i.evidence

private theorem evOf_ids (i : FinancialInput) (ev : Option EvidenceRecord) :
    (evOf i ev).map EvidenceRecord.evidenceId =
      (ev.map fun e => insertBy (fun x => x) e.evidenceId (i.evidence.map EvidenceRecord.evidenceId)).getD
        (i.evidence.map EvidenceRecord.evidenceId) := by
  cases ev with
  | none => rfl
  | some e =>
    simp only [evOf, Option.map_some, Option.getD_some]
    exact map_insertBy EvidenceRecord.evidenceId EvidenceRecord.evidenceId (fun s => s) (fun _ => rfl) e _

private theorem evOf_length (i : FinancialInput) (ev : Option EvidenceRecord) :
    (evOf i ev).length = i.evidence.length + (if ev.isSome then 1 else 0) := by
  cases ev with
  | none => rfl
  | some e => simp [evOf, length_insertBy]

private theorem wf_canon {i : FinancialInput} (h : financialInputWellFormed i = true) :
    canonicalIdList (i.payments.map Payment.paymentId) = true ∧
    canonicalIdList (i.evidence.map EvidenceRecord.evidenceId) = true ∧
    canonicalIdList (i.conflicts.map FinancialConflict.conflictId) = true := by
  simp only [financialInputWellFormed, envWellFormed, envOf, Bool.and_assoc, Bool.and_eq_true, decide_eq_true_eq] at h
  obtain ⟨h1,h2,h3,h4,h5,h6,h7,h8,h9,h10,h11,h12,h13,h14,h15,h16,h17,h18,h19,h20,h21,h22,h23,h24,h25,h26,h27,h28,h29,h30,h31,h32,h33,h34,h35,h36,h37,h38,h39,h40,h41,h42,h43,h44,h45,h46,h47,h48,h49,h50,h51,h52,h53,h54,h55⟩ := h
  exact ⟨h25, h28, h29⟩

private theorem ev_facts {i : FinancialInput} (hwf : financialInputWellFormed i = true) {c : RecordCommand}
    (hc : commandWellFormed (.record c) = true) {ev} (hev : EvCase i c ev) :
    (∀ id x, findEvidence i.evidence id = some x → findEvidence (evOf i ev) id = some x) ∧
    (∃ t, findEvidence (evOf i ev) c.evidenceId = some (confirmation i c t)) ∧
    (∀ x ∈ evOf i ev, x ∉ i.evidence → evidenceWellFormed i.context x = true ∧
      x.receivedAt ≤ i.evaluatedAt ∧ x.evidenceId = c.evidenceId ∧ x.kind = "PAYMENT_CONFIRMATION" ∧
      x.commonOriginId = c.commonOriginId ∧ x.amountCents = some c.amountCents) ∧
    (ev.isSome = true → (evOf i ev).length ≤ maxRows →
      canonicalIdList ((evOf i ev).map EvidenceRecord.evidenceId) = true) := by
  obtain ⟨hid1, hid2, hnow⟩ := wf_ctx hwf
  rcases hev with ⟨rfl, hf, hform, hle⟩ | ⟨rfl, t, ht⟩
  · have hf' : findEvidence i.evidence (confirmation i c i.evaluatedAt).evidenceId = none := hf
    have hfi : ∀ id, findEvidence (evOf i (some (confirmation i c i.evaluatedAt))) id =
        if c.evidenceId = id then some (confirmation i c i.evaluatedAt) else findEvidence i.evidence id :=
      fun id => findEvidence_insertBy hf'
    refine ⟨fun id x h => ?_, ⟨i.evaluatedAt, by rw [hfi]; simp⟩, fun x hx hn => ?_, fun _ hl => ?_⟩
    · rw [hfi]
      by_cases e : c.evidenceId = id
      · subst e; rw [hf] at h; cases h
      · rw [if_neg e]; exact h
    · have hx' : x ∈ insertBy EvidenceRecord.evidenceId (confirmation i c i.evaluatedAt) i.evidence := hx
      rcases (mem_insertBy _ _ x _).1 hx' with rfl | h
      · exact ⟨confirmation_wf ⟨hid1, hid2⟩ hc hform hle hnow, Nat.le_refl _, rfl, rfl, rfl, rfl⟩
      · exact absurd h hn
    · rw [evOf_ids]
      simp only [Option.map_some, Option.getD_some]
      refine canonical_insert (wf_canon hwf).2.1 (cmd_record hc).2.1 ?_ ?_
      · intro hm
        obtain ⟨x, hx⟩ := find_of_known (List.contains_iff_mem.2 hm)
        rw [hf'] at hx; cases hx
      · have := evOf_length i (some (confirmation i c i.evaluatedAt))
        simp only [Option.isSome_some, if_true] at this
        rw [List.length_map]; omega
  · exact ⟨fun id x h => h, ⟨t, ht⟩, fun x hx hn => absurd hx hn, fun h => by simp at h⟩

/-! ## `advance` on the three write shapes -/

private theorem adv_rec (V : PaymentView) (S : ItemState) (ev : Option EvidenceRecord) (p : Payment) (k : Receipt) :
    advance V S ⟨ev, some p, none, some k⟩ =
      if ((ev.map fun e => insertBy (fun x => x) e.evidenceId S.evidenceIds).getD S.evidenceIds).length > maxRows ||
          S.conflictCount > maxRows then none else
      if S.cash + p.amountCents + S.lawful > maxCents then none else
      some { S with
        evidenceIds := (ev.map fun e => insertBy (fun x => x) e.evidenceId S.evidenceIds).getD S.evidenceIds,
        anchorBytes := S.anchorBytes + anchorGrowth V ⟨ev, some p, none, some k⟩,
        cash := S.cash + p.amountCents,
        contributions := evalInsertContribution ⟨p.eventAt, p.paymentId, p.amountCents⟩ S.contributions,
        requests := S.requests.map fun q =>
          if k.paysActionId = some q.actionId then { q with paidCents := q.paidCents + p.amountCents } else q } := by
  unfold advance
  rfl

private theorem evOf_canon {i : FinancialInput} {ev : Option EvidenceRecord}
    (hcE : canonicalIdList (i.evidence.map EvidenceRecord.evidenceId) = true)
    (hEcan : ev.isSome = true → (evOf i ev).length ≤ maxRows →
      canonicalIdList ((evOf i ev).map EvidenceRecord.evidenceId) = true)
    (hl : (evOf i ev).length ≤ maxRows) :
    canonicalIdList ((evOf i ev).map EvidenceRecord.evidenceId) = true := by
  by_cases hs : ev.isSome = true
  · exact hEcan hs hl
  · have : ev = none := by cases ev with | none => rfl | some _ => exact absurd rfl hs
    subst this
    exact hcE

private theorem post_recorded {i : FinancialInput} {c : RecordCommand}
    (hpid : findPayment i.payments c.paymentId = none) (ev : Option EvidenceRecord) :
    applyWrites i ⟨ev, some (recordedPayment i c), none, some (recordedReceipt i c)⟩ =
      upd i (insertBy Payment.paymentId (recordedPayment i c) i.payments) (evOf i ev) i.conflicts := by
  unfold applyWrites upd evOf
  simp [recordedPayment, hpid]

/-- A RECORDED write keeps a well-formed input well formed iff the evidence count fits. -/
theorem recorded_post_wf {i : FinancialInput} (hwf : financialInputWellFormed i = true)
    {c : RecordCommand} (hc : commandWellFormed (.record c) = true) (h0 : c.amountCents ≠ 0)
    (hpid : findPayment i.payments c.paymentId = none)
    (hno : ∀ q ∈ i.payments, q.commonOriginId ≠ c.commonOriginId)
    {ev : Option EvidenceRecord} (hev : EvCase i c ev) :
    financialInputWellFormed (applyWrites i ⟨ev, some (recordedPayment i c), none, some (recordedReceipt i c)⟩) =
      decide (i.evidence.length + (if ev.isSome then 1 else 0) ≤ maxRows) := by
  rw [post_recorded hpid, ← evOf_length]
  by_cases hl : (evOf i ev).length ≤ maxRows
  · rw [decide_eq_true hl]
    obtain ⟨hE, ⟨t, hEt⟩, hEnew, hEcan⟩ := ev_facts hwf hc hev
    obtain ⟨-, -, hC1, -, -, -, hNo, -⟩ := wf_facts hwf
    obtain ⟨hcP, hcE, hcC⟩ := wf_canon hwf
    obtain ⟨hid1, hid2, -⟩ := wf_ctx hwf
    obtain ⟨hcid, -⟩ := cmd_record hc
    refine wf_grow hwf hE (fun id q h => ⟨q, ?_, rfl, rfl, rfl⟩) (fun id q h _ => ?_) (fun x hx => hx) hl hC1
      (fun hlen => ?_) ?_ hcC ?_ ?_ ?_ (fun q hq hn => absurd hq hn)
    · rw [findPayment_insertBy hpid]
      by_cases e : (recordedPayment i c).paymentId = id
      · exact absurd (e ▸ h) (by simp [recordedPayment, hpid])
      · rw [if_neg e]; exact h
    · rw [findPayment_insertBy hpid]
      by_cases e : (recordedPayment i c).paymentId = id
      · exact absurd (e ▸ h) (by simp [recordedPayment, hpid])
      · rw [if_neg e]; exact h
    · rw [ids_insert]
      refine canonical_insert hcP hcid ?_ ?_
      · intro hm
        obtain ⟨q, hq, e⟩ := List.mem_map.1 hm
        exact findPayment_none_ne hpid q hq e
      · rw [List.length_map]; rw [length_insertBy] at hlen; omega
    · exact evOf_canon hcE hEcan hl
    · rw [noDup_iff]
      refine ((insertBy_perm Payment.paymentId (recordedPayment i c) i.payments).map
        Payment.commonOriginId).nodup_iff.2 (List.nodup_cons.2 ⟨?_, (noDup_iff _).1 hNo⟩)
      intro hm
      obtain ⟨q, hq, e⟩ := List.mem_map.1 hm
      exact hno q hq e
    · intro q hq hn
      rcases (mem_insertBy _ _ q _).1 hq with rfl | h
      · refine ⟨recordedPayment_wf ⟨hid1, hid2⟩ hc h0, ?_, rfl⟩
        have hfe : findEvidence (evOf i ev) (recordedPayment i c).evidenceId =
            some (confirmation i c t) := hEt
        unfold paymentEvidenceWellFormed
        simp only [upd]
        rw [hfe]
        simp [confirmation, recordedPayment]
      · exact absurd h hn
    · intro x hx hn
      obtain ⟨a, b, d, e, -, -⟩ := hEnew x hx hn
      refine ⟨a, b, ?_⟩
      have hany : (upd i (insertBy Payment.paymentId (recordedPayment i c) i.payments)
          (evOf i ev) i.conflicts).payments.any (fun q => decide (q.evidenceId = x.evidenceId)) = true :=
        List.any_eq_true.2 ⟨recordedPayment i c, (mem_insertBy _ _ _ _).2 (Or.inl rfl),
          decide_eq_true (by rw [d]; rfl)⟩
      unfold accLam
      rw [if_pos e]
      unfold paymentConfirmationAccounted
      simp [hany]
  · rw [decide_eq_false hl]
    exact Bool.eq_false_iff.2 fun hw => hl (by simpa only [upd] using (wf_facts hw).2.1)

private theorem shape_recorded {r : PaymentRequest} {V : PaymentView} {S : ItemState}
    (hwf : financialInputWellFormed r.input = true)
    (hrec : r.receipts.map Receipt.paymentId = r.input.payments.map Payment.paymentId)
    (hb : r.inputBytes = (rawEncodeFinancialInput r.input).length)
    (hS : summarize r.input r.receipts (anchorItemLength r.input r.receipts) = some S)
    (hVenv : V.env = envOf r.input) (hbyId : V.byId = none)
    {c : RecordCommand} (hc : commandWellFormed (.record c) = true) (h0 : c.amountCents ≠ 0)
    (hpid : findPayment r.input.payments c.paymentId = none)
    (hno : ∀ q ∈ r.input.payments, q.commonOriginId ≠ c.commonOriginId)
    {ev : Option EvidenceRecord} (hev : EvCase r.input c ev) :
    some (commitView V S .RECORDED ⟨ev, some (recordedPayment r.input c), none, some (recordedReceipt r.input c)⟩) =
      project r (mutate r .RECORDED ⟨ev, some (recordedPayment r.input c), none, some (recordedReceipt r.input c)⟩) := by
  obtain ⟨hSe, hSc, hScash, hSle, hSctr, hSreq, hSab⟩ := S_facts hS
  obtain ⟨-, -, hC1, -, -, -, -, hcases⟩ := wf_facts hwf
  have hnd := nodup_ids_of_wf hwf
  have hpost := post_recorded hpid ev
  have hxact : (recordedPayment r.input c).status = .ACTIVE := rfl
  have hold : oldPay r.input ⟨ev, some (recordedPayment r.input c), none, some (recordedReceipt r.input c)⟩ = 0 := by
    simp [oldPay, recordedPayment, hpid]
  refine commit_core hb hS hVenv ?_ ?_ hcases ?_ ?_
  · unfold anchorGrowth addedBytes
    rw [hold, hbyId]
    simp
  · have := rawEncode_applyWrites_core r.input ⟨ev, some (recordedPayment r.input c), none, some (recordedReceipt r.input c)⟩
      (fun q hq hs => by simp [recordedPayment] at hq hs; subst hq; simp [hpid] at hs)
    unfold addedBytes
    rw [hold] at this ⊢
    omega
  · intro s' h
    rw [recorded_post_wf hwf hc h0 hpid hno hev, ← evOf_length]
    refine decide_eq_true ?_
    rw [adv_rec] at h
    by_cases h1 : ((ev.map fun e => insertBy (fun x => x) e.evidenceId S.evidenceIds).getD S.evidenceIds).length > maxRows ||
        S.conflictCount > maxRows
    · rw [if_pos h1] at h; cases h
    · rw [hSe, ← evOf_ids] at h1
      simp only [List.length_map, Bool.or_eq_true, decide_eq_true_eq, not_or, Nat.not_lt] at h1
      exact h1.1
  · intro hw
    rw [hpost] at hw ⊢
    have hl := (wf_facts hw).2.1
    simp only [upd] at hl
    rw [summarize_upd hS, adv_rec]
    have hids : (ev.map fun e => insertBy (fun x => x) e.evidenceId S.evidenceIds).getD S.evidenceIds =
        (evOf r.input ev).map EvidenceRecord.evidenceId := by rw [evOf_ids, hSe]
    have hcash := activeCents_insert hxact r.input.payments
    have h1 : ¬ (((ev.map fun e => insertBy (fun x => x) e.evidenceId S.evidenceIds).getD S.evidenceIds).length > maxRows ||
        S.conflictCount > maxRows) := by
      rw [hids, List.length_map, hSc]
      simp only [Bool.or_eq_true, decide_eq_true_eq, not_or, Nat.not_lt]
      exact ⟨hl, hC1⟩
    rw [if_neg h1]
    by_cases h2 : S.cash + (recordedPayment r.input c).amountCents + S.lawful > maxCents
    · rw [if_pos h2, if_neg]
      rw [hcash]; omega
    · rw [if_neg h2, if_pos]
      · have hcr : commitReceipts r.receipts ⟨ev, some (recordedPayment r.input c), none,
            some (recordedReceipt r.input c)⟩ = insertBy Receipt.paymentId (recordedReceipt r.input c) r.receipts := rfl
        rw [hcr]
        cases S with
        | mk rev cash claimed lawful contr lc dl cc eids reqs ab =>
          dsimp only at hScash hSe hSc hSctr hSreq hSab hcash hids
          subst hScash hSctr hSreq hSe hSc
          simp only [Option.some.injEq, ItemState.mk.injEq, true_and, and_true]
          refine ⟨?_, ?_, ?_, ?_⟩
          · rw [hcash]; omega
          · rw [contrib_insert _ _ _ hxact]; rfl
          · exact hids
          · rw [List.map_map]
            refine List.map_congr_left fun a _ => ?_
            have := paid_insert r.input (K := recordedReceipt r.input c) hnd hrec hxact rfl hpid a.actionId
            simp only [Function.comp]
            by_cases h : (recordedReceipt r.input c).paysActionId = some a.actionId <;> simp [requestPaidOf, h, this]
      · rw [hcash]; omega

private theorem adv_cf (V : PaymentView) (S : ItemState) (ev : Option EvidenceRecord) (x : FinancialConflict) :
    advance V S ⟨ev, none, some x, none⟩ =
      if ((ev.map fun e => insertBy (fun x => x) e.evidenceId S.evidenceIds).getD S.evidenceIds).length > maxRows ||
          S.conflictCount + 1 > maxRows then none else
      some { S with
        evidenceIds := (ev.map fun e => insertBy (fun x => x) e.evidenceId S.evidenceIds).getD S.evidenceIds,
        conflictCount := S.conflictCount + 1,
        anchorBytes := S.anchorBytes + anchorGrowth V ⟨ev, none, some x, none⟩ } := by
  unfold advance
  rfl

/-- A CONFLICT_RECORDED write keeps a well-formed input well formed iff both row counts fit
    (the new conflict row's fields are covered by the command, the stored payment and the evidence). -/
theorem conflict_post_wf {i : FinancialInput} (hwf : financialInputWellFormed i = true)
    {c : RecordCommand} (hc : commandWellFormed (.record c) = true) (h0 : c.amountCents ≠ 0)
    {p : Payment} (hp : findPayment i.payments p.paymentId = some p)
    (hporig : p.commonOriginId = c.commonOriginId) (hne : p.amountCents ≠ c.amountCents)
    (hcv : i.conflicts.any (·.conflictId = conflictIdOf i c) = false)
    (hcid : idWellFormed (conflictIdOf i c) = true)
    {ev : Option EvidenceRecord} (hev : EvCase i c ev) :
    financialInputWellFormed (applyWrites i ⟨ev, none, some (conflictImage i c p (conflictIdOf i c)), none⟩) =
      decide (i.evidence.length + (if ev.isSome then 1 else 0) ≤ maxRows ∧ i.conflicts.length + 1 ≤ maxRows) := by
  let x := conflictImage i c p (conflictIdOf i c)
  have hpost : applyWrites i ⟨ev, none, some x, none⟩ =
      upd i i.payments (evOf i ev) (insertBy FinancialConflict.conflictId x i.conflicts) := rfl
  rw [hpost, ← evOf_length]
  by_cases hlc : (evOf i ev).length ≤ maxRows ∧ i.conflicts.length + 1 ≤ maxRows
  · rw [decide_eq_true hlc]
    obtain ⟨hl, hcl⟩ := hlc
    obtain ⟨hE, ⟨t, hEt⟩, hEnew, hEcan⟩ := ev_facts hwf hc hev
    obtain ⟨hP1, hE1, hC1, hPwf, hPew, hPrew, hNo, hcases⟩ := wf_facts hwf
    obtain ⟨hcP, hcE, hcC⟩ := wf_canon hwf
    obtain ⟨hid1, hid2, hnow⟩ := wf_ctx hwf
    obtain ⟨hcid1, hcid2, hcid3, hcid4, hcid5, hcamt, hceve⟩ := cmd_record hc
    have hpm := findPayment_mem hp
    have hpwf := hPwf p hpm
    have hpwf' := hpwf
    simp only [paymentWellFormed, Bool.and_eq_true, decide_eq_true_eq, List.all_cons, List.all_nil,
      Bool.and_true, positiveAmountWellFormed, amountWellFormed] at hpwf'
    obtain ⟨⟨⟨⟨⟨⟨hp1, -, -, -, -⟩, -⟩, -⟩, ⟨hppos, hpamax⟩⟩, -⟩, -⟩ := hpwf'
    have hnc : conflictIdOf i c ∉ i.conflicts.map FinancialConflict.conflictId := by
      intro hm
      obtain ⟨y, hy, e⟩ := List.mem_map.1 hm
      have : i.conflicts.any (·.conflictId = conflictIdOf i c) = true :=
        List.any_eq_true.2 ⟨y, hy, decide_eq_true e⟩
      rw [hcv] at this; cases this
    refine wf_grow hwf hE (fun id q h => ⟨q, h, rfl, rfl, rfl⟩) (fun id q h _ => h)
      (fun y hy => (mem_insertBy _ _ _ _).2 (Or.inr hy)) hl ?_ (fun _ => hcP) ?_ ?_ hNo
      (fun q hq hn => absurd hq hn) ?_ ?_
    · rw [length_insertBy]; exact hcl
    · exact evOf_canon hcE hEcan hl
    · have : (insertBy FinancialConflict.conflictId x i.conflicts).map FinancialConflict.conflictId =
          insertBy (fun s => s) x.conflictId (i.conflicts.map FinancialConflict.conflictId) :=
        map_insertBy _ _ (fun s => s) (fun _ => rfl) x _
      rw [this]
      refine canonical_insert hcC hcid hnc ?_
      rw [List.length_map]; omega
    · intro y hy hn
      obtain ⟨a, b, d, e, -, -⟩ := hEnew y hy hn
      refine ⟨a, b, ?_⟩
      have hany : (upd i i.payments (evOf i ev)
          (insertBy FinancialConflict.conflictId x i.conflicts)).conflicts.any
          (fun z => decide (z.candidateEvidenceId = y.evidenceId)) = true :=
        List.any_eq_true.2 ⟨x, (mem_insertBy _ _ _ _).2 (Or.inl rfl), decide_eq_true (by rw [d]; rfl)⟩
      unfold accLam
      rw [if_pos e]
      unfold paymentConfirmationAccounted
      simp [hany]
    · intro y hy hn
      rcases (mem_insertBy _ _ y _).1 hy with rfl | h
      · have hr : idWellFormed "CONFLICTING_COMMON_ORIGIN_AMOUNT" = true := id_reason
        have hpa : 0 < p.amountCents := hppos
        have hca : 0 < c.amountCents := Nat.pos_of_ne_zero h0
        simp [conflictWellFormed, x, conflictImage, confirmation, upd, positiveAmountWellFormed, amountWellFormed,
          timeWellFormed, hcid, hid1, hcid3, hp1, hcid2, hr, hp, hEt, hporig, hne, hpamax, hcamt, hnow, hpa, hca]
      · exact absurd h hn
  · rw [decide_eq_false hlc]
    refine Bool.eq_false_iff.2 fun hw => hlc ?_
    obtain ⟨-, hl, hcl, -⟩ := wf_facts hw
    simp only [upd, length_insertBy] at hl hcl
    exact ⟨hl, hcl⟩

private theorem shape_conflict {r : PaymentRequest} {V : PaymentView} {S : ItemState}
    (hwf : financialInputWellFormed r.input = true)
    (hb : r.inputBytes = (rawEncodeFinancialInput r.input).length)
    (hS : summarize r.input r.receipts (anchorItemLength r.input r.receipts) = some S)
    (hVenv : V.env = envOf r.input)
    {c : RecordCommand} (hc : commandWellFormed (.record c) = true) (h0 : c.amountCents ≠ 0)
    {p : Payment} (hp : findPayment r.input.payments p.paymentId = some p)
    (hporig : p.commonOriginId = c.commonOriginId) (hne : p.amountCents ≠ c.amountCents)
    (hcv : r.input.conflicts.any (·.conflictId = conflictIdOf r.input c) = false)
    (hcid : idWellFormed (conflictIdOf r.input c) = true)
    {ev : Option EvidenceRecord} (hev : EvCase r.input c ev) :
    some (commitView V S .CONFLICT_RECORDED ⟨ev, none, some (conflictImage r.input c p (conflictIdOf r.input c)), none⟩) =
      project r (mutate r .CONFLICT_RECORDED ⟨ev, none, some (conflictImage r.input c p (conflictIdOf r.input c)), none⟩) := by
  obtain ⟨hSe, hSc, hScash, hSle, hSctr, hSreq, hSab⟩ := S_facts hS
  obtain ⟨-, -, -, -, -, -, -, hcases⟩ := wf_facts hwf
  let x := conflictImage r.input c p (conflictIdOf r.input c)
  have hpost : applyWrites r.input ⟨ev, none, some x, none⟩ =
      upd r.input r.input.payments (evOf r.input ev) (insertBy FinancialConflict.conflictId x r.input.conflicts) :=
    rfl
  have hold : oldPay r.input ⟨ev, none, some x, none⟩ = 0 := by simp [oldPay]
  have hnew : newPay ⟨ev, none, some x, none⟩ = 0 := by simp [newPay]
  refine commit_core hb hS hVenv ?_ ?_ hcases ?_ ?_
  · unfold anchorGrowth addedBytes
    rw [hold, hnew]
    simp
  · have := rawEncode_applyWrites_core r.input ⟨ev, none, some x, none⟩ (fun q hq => by cases hq)
    unfold addedBytes
    simp only [x] at this
    rw [hold, hnew] at this ⊢
    omega
  · intro s' h
    rw [conflict_post_wf hwf hc h0 hp hporig hne hcv hcid hev]
    rw [adv_cf] at h
    by_cases h1 : ((ev.map fun e => insertBy (fun x => x) e.evidenceId S.evidenceIds).getD S.evidenceIds).length > maxRows ||
        S.conflictCount + 1 > maxRows
    · rw [if_pos h1] at h; cases h
    · rw [hSe, ← evOf_ids] at h1
      simp only [List.length_map, Bool.or_eq_true, decide_eq_true_eq, not_or, Nat.not_lt] at h1
      rw [hSc, evOf_length] at h1
      exact decide_eq_true h1
  · intro hw
    rw [hpost] at hw ⊢
    obtain ⟨-, hl, hcl, -⟩ := wf_facts hw
    simp only [upd, length_insertBy] at hl hcl
    rw [summarize_upd hS, adv_cf]
    have hids : (ev.map fun e => insertBy (fun x => x) e.evidenceId S.evidenceIds).getD S.evidenceIds =
        (evOf r.input ev).map EvidenceRecord.evidenceId := by rw [evOf_ids, hSe]
    have h1 : ¬ (((ev.map fun e => insertBy (fun x => x) e.evidenceId S.evidenceIds).getD S.evidenceIds).length > maxRows ||
        S.conflictCount + 1 > maxRows) := by
      rw [hids, List.length_map, hSc]
      simp only [Bool.or_eq_true, decide_eq_true_eq, not_or, Nat.not_lt]
      exact ⟨hl, hcl⟩
    rw [if_neg h1, if_pos (by rw [← hScash]; exact hSle)]
    cases S with
    | mk rev cash claimed lawful contr lc dl cc eids reqs ab =>
      dsimp only at hScash hSe hSc hSctr hSreq hSab hids
      subst hScash hSctr hSreq hSe hSc
      simp only [Option.some.injEq, ItemState.mk.injEq, true_and, and_true]
      exact ⟨(length_insertBy _ _ _).symm, (evOf_ids _ _).symm, rfl⟩

private theorem adv_rev (V : PaymentView) (S : ItemState) (e : EvidenceRecord) (p' q : Payment) (k : Receipt)
    (hb : V.byId = some (q, k)) :
    advance V S ⟨some e, some p', none, none⟩ =
      if (insertBy (fun x => x) e.evidenceId S.evidenceIds).length > maxRows || S.conflictCount > maxRows
      then none else
      some { S with
        evidenceIds := insertBy (fun x => x) e.evidenceId S.evidenceIds,
        anchorBytes := S.anchorBytes + anchorGrowth V ⟨some e, some p', none, none⟩,
        cash := S.cash - q.amountCents,
        contributions := S.contributions.erase ⟨q.eventAt, q.paymentId, q.amountCents⟩,
        requests := S.requests.map fun x =>
          if k.paysActionId = some x.actionId then { x with paidCents := x.paidCents - q.amountCents } else x } := by
  unfold advance
  simp only [hb]
  rfl

private theorem enc_rev {p : Payment} (c : ReverseCommand) (h : p.reversalEvidenceId = none) :
    (encodePayment (reversedImage p c)).length = (encodePayment p).length + (encodeString c.evidenceId).length := by
  simp only [encodePayment, reversedImage, h, encodeOptionString, List.length_append, List.length_cons,
    List.length_nil]
  omega

private theorem rep_map {P : List Payment} {new p : Payment} (hnd : (P.map Payment.paymentId).Nodup)
    (hp : findPayment P new.paymentId = some p) {β : Type} (f : Payment → β) (hf : f new = f p) :
    (P.map fun x => if x.paymentId = new.paymentId then new else x).map f = P.map f := by
  rw [List.map_map]
  refine List.map_congr_left fun x hx => ?_
  simp only [Function.comp]
  by_cases h : x.paymentId = new.paymentId
  · rw [if_pos h]
    have h1 := findPayment_of_mem hnd hx
    rw [h, hp] at h1
    rw [hf, ← Option.some.inj h1]
  · rw [if_neg h]

private theorem rep_eq {P : List Payment} {new p q : Payment} (hnd : (P.map Payment.paymentId).Nodup)
    (hp : findPayment P new.paymentId = some p) (hq : q ∈ P) (h : q.paymentId = new.paymentId) : q = p := by
  have h1 := findPayment_of_mem hnd hq
  rw [h, hp] at h1
  exact (Option.some.inj h1).symm

/-- A REVERSED write keeps a well-formed input well formed iff the evidence count fits. -/
theorem reversed_post_wf {i : FinancialInput} (hwf : financialInputWellFormed i = true)
    {c : ReverseCommand} (hc : commandWellFormed (.reverse c) = true)
    {p : Payment} (hp : findPayment i.payments c.paymentId = some p) (hact : p.status ≠ .REVERSED) {time : Nat}
    (hfe : findEvidence i.evidence c.evidenceId = none)
    (hform : formRefusal (reversalRecord i c p time) = none) (htime : time ≤ i.evaluatedAt) :
    financialInputWellFormed (applyWrites i ⟨some (reversalRecord i c p time), some (reversedImage p c), none, none⟩) =
      decide (i.evidence.length + 1 ≤ maxRows) := by
  let e := reversalRecord i c p time
  let new := reversedImage p c
  obtain ⟨hP1, hE1, hC1, hPwf, hPew, hPrew, hNo, hcases⟩ := wf_facts hwf
  obtain ⟨hcP, hcE, hcC⟩ := wf_canon hwf
  obtain ⟨hid1, hid2, hnow⟩ := wf_ctx hwf
  have hnd := nodup_ids_of_wf hwf
  obtain ⟨hcid, hceid⟩ := cmd_reverse hc
  have hpc : p.paymentId = c.paymentId := findPayment_id _ _ _ hp
  have hp' : findPayment i.payments p.paymentId = some p := by rw [hpc]; exact hp
  have hpm := findPayment_mem hp
  have hpwf := hPwf p hpm
  have hpitem : p.itemId = i.context.itemId := by
    simp only [paymentWellFormed, Bool.and_eq_true, decide_eq_true_eq, List.all_cons, List.all_nil,
      Bool.and_true] at hpwf
    exact hpwf.1.1.1.2
  have hnew : findPayment i.payments new.paymentId = some p := hp'
  have hpost : applyWrites i ⟨some e, some new, none, none⟩ =
      upd i (i.payments.map fun x => if x.paymentId = new.paymentId then new else x)
        (insertBy EvidenceRecord.evidenceId e i.evidence) i.conflicts := by
    unfold applyWrites upd
    simp [hnew]
  have hfe' : findEvidence i.evidence e.evidenceId = none := hfe
  have hfe2 : findEvidence (insertBy EvidenceRecord.evidenceId e i.evidence) c.evidenceId = some e :=
    (findEvidence_insertBy hfe').trans (if_pos rfl)
  have hE : ∀ id x, findEvidence i.evidence id = some x →
      findEvidence (insertBy EvidenceRecord.evidenceId e i.evidence) id = some x := fun id x h => by
    rw [findEvidence_insertBy hfe']
    by_cases ee : e.evidenceId = id
    · subst ee; rw [hfe'] at h; cases h
    · rw [if_neg ee]; exact h
  have hfind : ∀ id, findPayment (i.payments.map fun x => if x.paymentId = new.paymentId then new else x) id =
      (findPayment i.payments id).map fun x => if x.paymentId = new.paymentId then new else x :=
    fun id => findPayment_replace _ new new rfl id
  rw [hpost, ← length_insertBy EvidenceRecord.evidenceId e i.evidence]
  by_cases hl : (insertBy EvidenceRecord.evidenceId e i.evidence).length ≤ maxRows
  · rw [decide_eq_true hl]
    refine wf_grow hwf hE (fun id q h => ?_) (fun id q h hr => ?_) (fun x hx => hx) hl hC1
      (fun _ => ?_) ?_ hcC ?_ ?_ ?_ (fun q hq hn => absurd hq hn)
    · have hq := findPayment_mem h
      have hid := findPayment_id _ _ _ h
      refine ⟨if q.paymentId = new.paymentId then new else q, by rw [hfind, h]; rfl, ?_⟩
      by_cases ee : q.paymentId = new.paymentId
      · rw [if_pos ee, rep_eq hnd hnew hq ee]; exact ⟨rfl, rfl, rfl⟩
      · rw [if_neg ee]; exact ⟨rfl, rfl, rfl⟩
    · have hq := findPayment_mem h
      rw [hfind, h]
      by_cases ee : q.paymentId = new.paymentId
      · have := rep_eq hnd hnew hq ee
        rw [this] at hr; exact absurd hr hact
      · simp [ee]
    · rw [List.map_map]
      have : (i.payments.map ((Payment.paymentId) ∘ fun x => if x.paymentId = new.paymentId then new else x)) =
          i.payments.map Payment.paymentId := by
        have := rep_map hnd hnew Payment.paymentId rfl
        rwa [List.map_map] at this
      rw [this]; exact hcP
    · have : (insertBy EvidenceRecord.evidenceId e i.evidence).map EvidenceRecord.evidenceId =
          insertBy (fun s => s) e.evidenceId (i.evidence.map EvidenceRecord.evidenceId) :=
        map_insertBy _ _ (fun s => s) (fun _ => rfl) e _
      rw [this]
      refine canonical_insert hcE hceid ?_ ?_
      · intro hm
        obtain ⟨x, hx⟩ := find_of_known (List.contains_iff_mem.2 hm)
        rw [hfe'] at hx; cases hx
      · rw [List.length_map]; rw [length_insertBy] at hl; omega
    · rw [noDup_iff]
      have := rep_map hnd hnew Payment.commonOriginId rfl
      rw [this]; exact (noDup_iff _).1 hNo
    · intro q hq hn
      rcases mem_replace hq with rfl | h
      · refine ⟨reversedImage_wf hpwf hc, ?_, ?_⟩
        · exact pew_mono (i := i) (j := upd i _ _ _) hE (hPew p hpm)
        · unfold reversalEvidenceWellFormed
          simp only [upd, new, reversedImage]
          rw [hfe2]
          simp [e, reversalRecord, hpitem]
      · exact absurd h hn
    · intro x hx hn
      rcases (mem_insertBy _ _ x _).1 hx with rfl | h
      · refine ⟨reversalRecord_wf ⟨hid1, hid2⟩ hnow hc hpwf hform htime, Nat.le_refl _, ?_⟩
        unfold accLam
        rw [if_neg (by simp [e, reversalRecord]), if_pos (by simp [e, reversalRecord])]
        unfold reversalEvidenceAccounted
        simp only [e, reversalRecord, upd]
        rw [hfind, hp']
        simp [new, reversedImage, hpitem]
      · exact absurd h hn
  · rw [decide_eq_false hl]
    exact Bool.eq_false_iff.2 fun hw => hl (by simpa only [upd] using (wf_facts hw).2.1)

private theorem shape_reversed {r : PaymentRequest} {V : PaymentView} {S : ItemState}
    (hwf : financialInputWellFormed r.input = true)
    (hrec : r.receipts.map Receipt.paymentId = r.input.payments.map Payment.paymentId)
    (hb : r.inputBytes = (rawEncodeFinancialInput r.input).length)
    (hS : summarize r.input r.receipts (anchorItemLength r.input r.receipts) = some S)
    (hVenv : V.env = envOf r.input)
    {c : ReverseCommand} (hc : commandWellFormed (.reverse c) = true)
    {p : Payment} {k : Receipt} (hp : findPayment r.input.payments c.paymentId = some p)
    (hk : receiptOf r.receipts p.paymentId = some k) (hbyId : V.byId = some (p, k))
    (hact : p.status ≠ .REVERSED) {time : Nat}
    (hfe : findEvidence r.input.evidence c.evidenceId = none)
    (hform : formRefusal (reversalRecord r.input c p time) = none) (htime : time ≤ r.input.evaluatedAt) :
    some (commitView V S .REVERSED ⟨some (reversalRecord r.input c p time), some (reversedImage p c), none, none⟩) =
      project r (mutate r .REVERSED ⟨some (reversalRecord r.input c p time), some (reversedImage p c), none, none⟩) := by
  let e := reversalRecord r.input c p time
  let new := reversedImage p c
  obtain ⟨hSe, hSc, hScash, hSle, hSctr, hSreq, hSab⟩ := S_facts hS
  obtain ⟨-, -, hC1, -, -, hPrew, -, hcases⟩ := wf_facts hwf
  have hnd := nodup_ids_of_wf hwf
  have hpc : p.paymentId = c.paymentId := findPayment_id _ _ _ hp
  have hp' : findPayment r.input.payments p.paymentId = some p := by rw [hpc]; exact hp
  have hpm := findPayment_mem hp
  have hpact : p.status = .ACTIVE := by
    cases h : p.status with
    | ACTIVE => rfl
    | REVERSED => exact absurd h hact
  have hpnone : p.reversalEvidenceId = none := by
    have := hPrew p hpm
    unfold reversalEvidenceWellFormed at this
    rw [hpact] at this
    cases h : p.reversalEvidenceId with
    | none => rfl
    | some _ => rw [h] at this; simp at this
  have hnew : findPayment r.input.payments new.paymentId = some p := hp'
  have hnewst : new.status ≠ .ACTIVE := by simp [new, reversedImage]
  have hpost : applyWrites r.input ⟨some e, some new, none, none⟩ =
      upd r.input (r.input.payments.map fun x => if x.paymentId = new.paymentId then new else x)
        (insertBy EvidenceRecord.evidenceId e r.input.evidence) r.input.conflicts := by
    unfold applyWrites upd
    simp [hnew]
  have hold : oldPay r.input ⟨some e, some new, none, none⟩ = (encodePayment p).length := by
    simp [oldPay, new, reversedImage, hp']
  have hnewp : newPay ⟨some e, some new, none, none⟩ = (encodePayment new).length := by simp [newPay]
  have hlenle : (encodePayment new).length = (encodePayment p).length + (encodeString c.evidenceId).length :=
    enc_rev c hpnone
  have hrep := activeCents_replace hnd hnew hpact hnewst
  refine commit_core hb hS hVenv ?_ ?_ hcases ?_ ?_
  · unfold anchorGrowth addedBytes
    rw [hold, hbyId]
    simp [receiptBytes]
  · have := rawEncode_applyWrites_core r.input ⟨some e, some new, none, none⟩ (fun q hq hs => hnd)
    unfold addedBytes
    rw [hold, hnewp] at this ⊢
    simp only [e, new] at this hlenle ⊢
    omega
  · intro s' h
    rw [reversed_post_wf hwf hc hp hact hfe hform htime]
    rw [adv_rev V S e new p k hbyId] at h
    by_cases h1 : (insertBy (fun x => x) e.evidenceId S.evidenceIds).length > maxRows || S.conflictCount > maxRows
    · rw [if_pos h1] at h; cases h
    · rw [hSe] at h1
      simp only [length_insertBy, List.length_map, Bool.or_eq_true, decide_eq_true_eq, not_or, Nat.not_lt] at h1
      exact decide_eq_true h1.1
  · intro hw
    rw [hpost] at hw ⊢
    have hl := (wf_facts hw).2.1
    simp only [upd, length_insertBy] at hl
    rw [summarize_upd hS, adv_rev V S e new p k hbyId]
    have h1 : ¬ ((insertBy (fun x => x) e.evidenceId S.evidenceIds).length > maxRows || S.conflictCount > maxRows) := by
      rw [hSe, hSc]
      simp only [length_insertBy, List.length_map, Bool.or_eq_true, decide_eq_true_eq, not_or, Nat.not_lt]
      exact ⟨hl, hC1⟩
    have hcr : commitReceipts r.receipts ⟨some (reversalRecord r.input c p time), some (reversedImage p c), none, none⟩ = r.receipts := rfl
    rw [hcr, if_neg h1, if_pos (by omega)]
    cases S with
    | mk rev cash claimed lawful contr lc dl cc eids reqs ab =>
      dsimp only at hScash hSe hSc hSctr hSreq hSab hl
      subst hScash hSctr hSreq hSe hSc
      simp only [Option.some.injEq, ItemState.mk.injEq, true_and]
      refine ⟨?_, ?_, ?_, ?_, rfl⟩
      · omega
      · exact (contrib_replace _ _ new p hnewst hnd hnew hpact).symm
      · exact (map_insertBy _ _ (fun s => s) (fun _ => rfl) e _).symm
      · rw [List.map_map]
        refine List.map_congr_left fun a _ => ?_
        have := paid_replace r.input hnd hrec hnew hpact hnewst hk a.actionId
        simp only [Function.comp]
        by_cases h : k.paysActionId = some a.actionId
        · rw [if_pos h] at this
          simp only [requestPaidOf, h, ↓reduceIte, RequestPaid.mk.injEq, eq_self, true_and, and_true]; omega
        · rw [if_neg h] at this
          simp only [requestPaidOf, h, ↓reduceIte, RequestPaid.mk.injEq, eq_self, true_and, and_true]; omega

private theorem alias_wf {r : PaymentRequest} (hwf : financialInputWellFormed r.input = true)
    {c : RecordCommand} (hc : commandWellFormed (.record c) = true)
    {p : Payment} (hp : p ∈ r.input.payments) (hporig : p.commonOriginId = c.commonOriginId)
    (hamt : p.amountCents = c.amountCents)
    (hfe : findEvidence r.input.evidence c.evidenceId = none)
    (hform : formRefusal (confirmation r.input c r.input.evaluatedAt) = none)
    (hle : c.eventAt ≤ r.input.evaluatedAt) :
    financialInputWellFormed (applyWrites r.input
      ⟨some (confirmation r.input c r.input.evaluatedAt), none, none, none⟩) = true ↔
      r.input.evidence.length < maxRows := by
  have hev : EvCase r.input c (some (confirmation r.input c r.input.evaluatedAt)) :=
    Or.inl ⟨rfl, hfe, hform, hle⟩
  obtain ⟨hE, ⟨t, hEt⟩, hEnew, hEcan⟩ := ev_facts hwf hc hev
  obtain ⟨hP1, hE1, hC1, hPwf, hPew, hPrew, hNo, hcases⟩ := wf_facts hwf
  obtain ⟨hcP, hcE, hcC⟩ := wf_canon hwf
  have hpost : applyWrites r.input ⟨some (confirmation r.input c r.input.evaluatedAt), none, none, none⟩ =
      upd r.input r.input.payments (evOf r.input (some (confirmation r.input c r.input.evaluatedAt)))
        r.input.conflicts := rfl
  rw [hpost]
  constructor
  · intro hw
    have hl := (wf_facts hw).2.1
    simp only [upd, evOf, Option.map_some, Option.getD_some, length_insertBy] at hl
    omega
  · intro hl
    have hl' : (evOf r.input (some (confirmation r.input c r.input.evaluatedAt))).length ≤ maxRows := by
      simp only [evOf, Option.map_some, Option.getD_some, length_insertBy]; omega
    refine wf_grow hwf hE (fun id q h => ⟨q, h, rfl, rfl, rfl⟩) (fun id q h _ => h) (fun x hx => hx) hl' hC1
      (fun _ => hcP) (evOf_canon hcE hEcan hl') hcC hNo (fun q hq hn => absurd hq hn) ?_ (fun x hx hn => absurd hx hn)
    intro x hx hn
    obtain ⟨a, b, d, e, f, g⟩ := hEnew x hx hn
    refine ⟨a, b, ?_⟩
    unfold accLam
    rw [if_pos e]
    unfold paymentConfirmationAccounted
    simp only [g, f, upd, Bool.or_eq_true, List.any_eq_true, decide_eq_true_eq, Bool.and_eq_true]
    exact Or.inr ⟨p, hp, hporig, hamt⟩

private theorem alias_cap {r : PaymentRequest} {S : ItemState}
    (hb : r.inputBytes = (rawEncodeFinancialInput r.input).length)
    (hSab : S.anchorBytes = anchorItemLength r.input r.receipts) (e : EvidenceRecord) :
    withinCapacity r ⟨some e, none, none, none⟩ = true ↔
      ¬ (S.anchorBytes + (encodeEvidence e).length + maxCallTailBytes > maxTotalEncodedBytes) := by
  unfold withinCapacity
  rw [decide_eq_true_iff]
  unfold addedBytes
  simp only [evBytes, newPay, oldPay, cfBytes, receiptBytes, Option.map_some, Option.getD_some,
    Option.map_none, Option.getD_none, Option.bind_none]
  unfold anchorItemLength at hSab
  omega

private theorem shape_alias {r : PaymentRequest} {V : PaymentView} {S : ItemState}
    (hwf : financialInputWellFormed r.input = true)
    (hb : r.inputBytes = (rawEncodeFinancialInput r.input).length)
    (hS : summarize r.input r.receipts (anchorItemLength r.input r.receipts) = some S)
    (hVenv : V.env = envOf r.input)
    {c : RecordCommand} (hc : commandWellFormed (.record c) = true)
    {p : Payment} (hp : p ∈ r.input.payments) (hporig : p.commonOriginId = c.commonOriginId)
    (hamt : p.amountCents = c.amountCents)
    (hfe : findEvidence r.input.evidence c.evidenceId = none)
    (hform : formRefusal (confirmation r.input c r.input.evaluatedAt) = none)
    (hle : c.eventAt ≤ r.input.evaluatedAt) (pid : String) :
    some (aliasView V S pid (confirmation r.input c r.input.evaluatedAt)) =
      project r (aliasOf r pid (confirmation r.input c r.input.evaluatedAt)) := by
  obtain ⟨hSe, hSc, hScash, hSle, hSctr, hSreq, hSab⟩ := S_facts hS
  have hwfiff := alias_wf hwf hc hp hporig hamt hfe hform hle
  have hcap := alias_cap hb hSab (confirmation r.input c r.input.evaluatedAt)
  have hmode : V.env.context.mode = r.input.context.mode := by rw [hVenv]; rfl
  unfold aliasView aliasOf
  dsimp only
  rw [hmode]
  by_cases hm : r.input.context.mode = .SHADOW
  · simp [hm, project]
  · rw [if_neg hm, if_neg hm]
    by_cases hcp : S.anchorBytes + (encodeEvidence (confirmation r.input c r.input.evaluatedAt)).length +
        maxCallTailBytes > maxTotalEncodedBytes
    · have : (!withinCapacity r ⟨some (confirmation r.input c r.input.evaluatedAt), none, none, none⟩) = true := by
        cases h : withinCapacity r ⟨some (confirmation r.input c r.input.evaluatedAt), none, none, none⟩
        · rfl
        · exact absurd hcp (hcap.1 h)
      rw [if_pos hcp, if_pos this]; rfl
    · have : ¬ ((!withinCapacity r ⟨some (confirmation r.input c r.input.evaluatedAt), none, none, none⟩) = true) := by
        simp only [Bool.not_eq_true', Bool.not_eq_false]
        exact hcap.2 hcp
      rw [if_neg hcp, if_neg this]
      rw [hSe, List.length_map]
      by_cases hlt : r.input.evidence.length < maxRows
      · rw [if_pos hlt, if_pos (hwfiff.2 hlt)]; rfl
      · rw [if_neg hlt, if_neg (fun h => hlt (hwfiff.1 h))]; rfl

private theorem faithful_unpack {r : PaymentRequest} {v : PaymentView}
    (hb : r.inputBytes = (rawEncodeFinancialInput r.input).length) (hv : Faithful r v) :
    ∃ S, summarize r.input r.receipts (anchorItemLength r.input r.receipts) = some S ∧
      absorb v.state v.pending = S ∧ v.env = envOf r.input ∧
      v.byId = (findPayment r.input.payments (cmdPaymentId r.command)).bind
        (fun p => (receiptOf r.receipts p.paymentId).map fun k => (p, k)) ∧
      v.byOrigin = (match r.command with
        | .record c => (r.input.payments.find? (·.commonOriginId = c.commonOriginId)).bind fun p =>
            ((receiptOf r.receipts p.paymentId).map fun k => (p, k)).map fun (p, k) =>
              (p, k, p.reversalEvidenceId.bind (findEvidence r.input.evidence))
        | .reverse _ => none) ∧
      v.evidence = findEvidence r.input.evidence (cmdEvidenceId r.command) ∧
      v.conflictVisible = (match r.command with
        | .record c => r.input.conflicts.any (·.conflictId = conflictIdOf r.input c)
        | .reverse _ => false) ∧
      v.foreign = r.foreign ∧ v.expectedRevision = r.expectedRevision ∧ v.command = r.command := by
  have hbA : anchorOverhead + r.inputBytes + (encodeList encodeReceipt r.receipts).length =
      anchorItemLength r.input r.receipts := by unfold anchorItemLength; omega
  unfold Faithful viewOfAnchor at hv
  dsimp only at hv
  rw [hbA] at hv
  cases hsum : summarize r.input r.receipts (anchorItemLength r.input r.receipts) with
  | none => rw [hsum] at hv; cases hv
  | some S =>
    rw [hsum] at hv
    simp only [Option.map_some, Option.some.injEq] at hv
    exact ⟨S, rfl, (congrArg PaymentView.state hv).symm,
      (congrArg PaymentView.env hv).symm, (congrArg PaymentView.byId hv).symm,
      (congrArg PaymentView.byOrigin hv).symm, (congrArg PaymentView.evidence hv).symm,
      (congrArg PaymentView.conflictVisible hv).symm, (congrArg PaymentView.foreign hv).symm,
      (congrArg PaymentView.expectedRevision hv).symm, (congrArg PaymentView.command hv).symm⟩

private theorem head_conf (i : FinancialInput) (c : RecordCommand) (t : Nat) :
    confirmation (envOf i).head c t = confirmation i c t := rfl
private theorem head_rrec (i : FinancialInput) (c : ReverseCommand) (p : Payment) (t : Nat) :
    reversalRecord (envOf i).head c p t = reversalRecord i c p t := rfl
private theorem head_rpay (i : FinancialInput) (c : RecordCommand) :
    recordedPayment (envOf i).head c = recordedPayment i c := rfl
private theorem head_rrcp (i : FinancialInput) (c : RecordCommand) :
    recordedReceipt (envOf i).head c = recordedReceipt i c := rfl
private theorem head_cimg (i : FinancialInput) (c : RecordCommand) (p : Payment) (id : String) :
    conflictImage (envOf i).head c p id = conflictImage i c p id := rfl
private theorem head_cid (i : FinancialInput) (c : RecordCommand) :
    conflictIdOf (envOf i).head c = conflictIdOf i c := rfl

private theorem retry_lock {r : PaymentRequest} {V : PaymentView} {c : RecordCommand} {p : Payment} {k : Receipt}
    (henv : V.env = envOf r.input) (hev : V.evidence = findEvidence r.input.evidence c.evidenceId)
    (hexp : V.expectedRevision = r.expectedRevision) (hk : receiptOf r.receipts p.paymentId = some k) :
    some (viewRecordRetry V c p k) = project r (recordRetry r c p) := by
  unfold viewRecordRetry recordRetry
  rw [hev]
  cases hf : findEvidence r.input.evidence c.evidenceId with
  | none => simp only [hf]; rfl
  | some s =>
    simp only [hf, hk, henv, hexp, head_conf]
    cases hform : formRefusal (confirmation r.input c s.receivedAt) with
    | some f => simp only [hform]; rfl
    | none =>
      simp only [hform]
      by_cases hch : c.eventAt > s.receivedAt
      · simp only [hch, ↓reduceIte]; rfl
      · simp only [hch, ↓reduceIte]
        by_cases hq : r.expectedRevision = some k.recordedRevision ∧ k.paysActionId = c.paysActionId ∧
            p.evidenceId = c.evidenceId ∧ p.commonOriginId = c.commonOriginId ∧
            p.amountCents = c.amountCents ∧ p.eventAt = c.eventAt ∧ confirmation r.input c s.receivedAt = s
        · simp only [hq, and_self, ↓reduceIte]; rfl
        · simp only [hq, ↓reduceIte]; rfl

private theorem envOf_eval (i : FinancialInput) : (envOf i).evaluatedAt = i.evaluatedAt := rfl
private theorem envOf_before (i : FinancialInput) : (envOf i).beforeRevision = i.beforeRevision := rfl

private theorem rev_lock {r : PaymentRequest} {V : PaymentView} {S : ItemState}
    (hwf : financialInputWellFormed r.input = true)
    (hrec : r.receipts.map Receipt.paymentId = r.input.payments.map Payment.paymentId)
    (hb : r.inputBytes = (rawEncodeFinancialInput r.input).length)
    (hS : summarize r.input r.receipts (anchorItemLength r.input r.receipts) = some S)
    (hVenv : V.env = envOf r.input) {c : ReverseCommand} (hc : commandWellFormed (.reverse c) = true)
    (hbyId : V.byId = (findPayment r.input.payments c.paymentId).bind
      (fun p => (receiptOf r.receipts p.paymentId).map fun k => (p, k)))
    (hev : V.evidence = findEvidence r.input.evidence c.evidenceId)
    (hfor : V.foreign = r.foreign) (hexp : V.expectedRevision = r.expectedRevision) :
    some (viewReverse V S c) = project r (decideReverse r c) := by
  have hnd := nodup_ids_of_wf hwf
  cases hfp : findPayment r.input.payments c.paymentId with
  | none =>
    rw [hfp] at hbyId
    simp only [viewReverse, decideReverse, hbyId, hfp, Option.bind_none]
    rfl
  | some p =>
    obtain ⟨k, hk⟩ := receipt_exists (L := ⟨r.input, r.receipts⟩) ⟨hnd, hrec⟩ hfp
    have hbyId' : V.byId = some (p, k) := by rw [hbyId, hfp]; simp [hk]
    unfold viewReverse decideReverse
    simp only [hbyId', hfp, hfor, hev, hVenv, head_rrec, envOf_eval, envOf_before, revisionOk, hexp]
    cases hfe : r.foreign.evidenceId with
    | true => simp only [hfe]; rfl
    | false =>
      simp only [Bool.false_eq_true, ↓reduceIte]
      generalize hT : c.eventAt.getD (((findEvidence r.input.evidence c.evidenceId).map (·.eventAt)).getD
        r.input.evaluatedAt) = time
      cases hform : formRefusal (reversalRecord r.input c p time) with
      | some f => simp only [hform]; rfl
      | none =>
        simp only [hform]
        by_cases hch : time > r.input.evaluatedAt
        · simp only [hch, ↓reduceIte]; rfl
        · simp only [hch, ↓reduceIte]
          have hs : slotOf false (findEvidence r.input.evidence c.evidenceId)
              (reversalRecord r.input c p time) = evidenceSlot r (reversalRecord r.input c p time) :=
            by rw [evidenceSlot_eq, hfe]; rfl
          rw [hs]
          cases hsl : evidenceSlot r (reversalRecord r.input c p time) with
          | clash => simp only [hsl]; rfl
          | same s => simp only [hsl]; rfl
          | fresh =>
            simp only [hsl]
            obtain ⟨-, hfs | ⟨s, hs', -⟩⟩ := slot_cases (r := r) (e := reversalRecord r.input c p time)
              (by rw [hsl]; intro h; cases h)
            · have hfe' : findEvidence r.input.evidence c.evidenceId = none := hfs.2
              by_cases hrv : (!r.expectedRevision.all fun x => decide (x = r.input.beforeRevision)) = true
              · simp only [hrv, ↓reduceIte]; rfl
              · simp only [hrv]
                by_cases hst : p.status = .REVERSED
                · simp only [hst, ↓reduceIte]; rfl
                · simp only [hst, ↓reduceIte]
                  exact shape_reversed hwf hrec hb hS hVenv hc hfp hk hbyId' hst hfe' hform
                    (Nat.not_lt.1 hch)
            · rw [hsl] at hs'; cases hs'

private theorem conf_evid (i : FinancialInput) (c : RecordCommand) (t : Nat) :
    (confirmation i c t).evidenceId = c.evidenceId := rfl

private theorem slot_facts {foreign : Bool} {stored : Option EvidenceRecord} {e : EvidenceRecord} {slot : Slot}
    (h : slotOf foreign stored e = slot) :
    (slot = .fresh → foreign = false ∧ stored = none) ∧
    (∀ s, slot = .same s → foreign = false ∧ stored = some s ∧ e.eventAt ≤ s.receivedAt ∧
      { e with receivedAt := s.receivedAt } = s) := by
  unfold slotOf at h
  cases foreign with
  | true =>
    simp only [↓reduceIte] at h
    subst h
    exact ⟨fun h => (nomatch h), fun s h => nomatch h⟩
  | false =>
    cases stored with
    | none =>
      simp only [Bool.false_eq_true, ↓reduceIte] at h
      subst h
      exact ⟨fun _ => ⟨rfl, rfl⟩, fun s h => nomatch h⟩
    | some s0 =>
      simp only [Bool.false_eq_true, ↓reduceIte] at h
      by_cases hc : e.eventAt ≤ s0.receivedAt ∧ { e with receivedAt := s0.receivedAt } = s0
      · rw [if_pos hc] at h
        subst h
        refine ⟨fun h => (nomatch h), fun s h => ?_⟩
        cases h
        exact ⟨rfl, rfl, hc.1, hc.2⟩
      · rw [if_neg hc] at h
        subst h
        exact ⟨fun h => (nomatch h), fun s h => nomatch h⟩

private theorem ev_leaf {i : FinancialInput} {c : RecordCommand} {R : Nat} {foreign : Bool} {slot : Slot}
    (hsl : slotOf foreign (findEvidence i.evidence c.evidenceId) (confirmation i c R) = slot)
    (hne : slot ≠ .clash) (hR : findEvidence i.evidence c.evidenceId = none → R = i.evaluatedAt)
    (hform : formRefusal (confirmation i c R) = none) (hle : c.eventAt ≤ R) :
    EvCase i c (if slot.isFresh = true then some (confirmation i c R) else none) := by
  obtain ⟨hf, hs⟩ := slot_facts hsl
  cases slot with
  | clash => exact absurd rfl hne
  | fresh =>
    obtain ⟨-, hst⟩ := hf rfl
    have := hR hst
    subst this
    exact Or.inl ⟨rfl, hst, hform, hle⟩
  | same s =>
    obtain ⟨-, hst, -, hs'⟩ := hs s rfl
    refine Or.inr ⟨rfl, s.receivedAt, ?_⟩
    rw [hst]
    exact congrArg some hs'.symm

private theorem new_none {r : PaymentRequest} {V : PaymentView} {S : ItemState}
    (hwf : financialInputWellFormed r.input = true)
    (hrec : r.receipts.map Receipt.paymentId = r.input.payments.map Payment.paymentId)
    (hb : r.inputBytes = (rawEncodeFinancialInput r.input).length)
    (hS : summarize r.input r.receipts (anchorItemLength r.input r.receipts) = some S)
    (hVenv : V.env = envOf r.input) {c : RecordCommand} (hc : commandWellFormed (.record c) = true)
    (h0 : c.amountCents ≠ 0) (hpid : findPayment r.input.payments c.paymentId = none)
    (hbyId : V.byId = none) (hbo : V.byOrigin = none)
    (hev : V.evidence = findEvidence r.input.evidence c.evidenceId)
    (hcv : V.conflictVisible = r.input.conflicts.any (·.conflictId = conflictIdOf r.input c))
    (hfor : V.foreign = r.foreign) (hexp : V.expectedRevision = r.expectedRevision)
    (hex : r.input.payments.find? (·.commonOriginId = c.commonOriginId) = none) :
    some (viewRecordNew V S c) = project r (recordNew r c) := by
  have hlink := linkRefusalView_eq hwf hS c
  have hno : ∀ q ∈ r.input.payments, q.commonOriginId ≠ c.commonOriginId :=
    fun q hq h => (List.find?_eq_none.1 hex q hq) (decide_eq_true h)
  unfold viewRecordNew recordNew
  simp only [hbo, hev, hcv, hfor, hexp, hVenv, hex, hlink, head_conf, head_rpay, head_rrcp,
    envOf_eval, envOf_before, revisionOk, evidenceSlot_eq, conf_evid, Option.any_none, Option.isSome_none,
    Bool.false_and, Bool.and_false, Bool.not_false, Bool.true_and,
    Bool.false_eq_true, ↓reduceIte]
  by_cases hrv : (!Option.all (fun x => decide (x = r.input.beforeRevision)) r.expectedRevision) = true
  · simp only [hrv, ↓reduceIte]; rfl
  · simp only [hrv, Bool.false_eq_true, ↓reduceIte]
    cases hform : formRefusal (confirmation r.input c r.input.evaluatedAt) with
    | some f => simp only [hform]; rfl
    | none =>
      simp only [hform]
      by_cases hch : c.eventAt > r.input.evaluatedAt
      · simp only [hch, ↓reduceIte]; rfl
      · simp only [hch, ↓reduceIte]
        cases hsl : slotOf r.foreign.evidenceId (findEvidence r.input.evidence c.evidenceId)
            (confirmation r.input c r.input.evaluatedAt) with
        | clash => simp only [hsl]; rfl
        | same s =>
          simp only [hsl]
          cases hlr : linkRefusal r.input r.receipts c with
          | some f => simp only [hlr]; rfl
          | none =>
            simp only [hlr]
            exact shape_recorded hwf hrec hb hS hVenv hbyId hc h0 hpid hno
              (ev_leaf hsl (by simp) (fun _ => rfl) hform (Nat.not_lt.1 hch))
        | fresh =>
          simp only [hsl]
          cases hlr : linkRefusal r.input r.receipts c with
          | some f => simp only [hlr]; rfl
          | none =>
            simp only [hlr]
            exact shape_recorded hwf hrec hb hS hVenv hbyId hc h0 hpid hno
              (ev_leaf hsl (by simp) (fun _ => rfl) hform (Nat.not_lt.1 hch))

private theorem receipt_of_mem {r : PaymentRequest} (hwf : financialInputWellFormed r.input = true)
    (hrec : r.receipts.map Receipt.paymentId = r.input.payments.map Payment.paymentId)
    {p : Payment} (hp : p ∈ r.input.payments) : ∃ k, receiptOf r.receipts p.paymentId = some k := by
  have hn : (r.receipts.map Receipt.paymentId).Nodup := by rw [hrec]; exact nodup_ids_of_wf hwf
  have : p.paymentId ∈ r.receipts.map Receipt.paymentId := by
    rw [hrec]; exact List.mem_map.2 ⟨p, hp, rfl⟩
  obtain ⟨k, hk, hkp⟩ := List.mem_map.1 this
  exact ⟨k, by rw [← hkp]; exact find_of_mem Receipt.paymentId hn hk⟩

private theorem new_diff {r : PaymentRequest} {V : PaymentView} {S : ItemState}
    (hwf : financialInputWellFormed r.input = true)
    (hb : r.inputBytes = (rawEncodeFinancialInput r.input).length)
    (hS : summarize r.input r.receipts (anchorItemLength r.input r.receipts) = some S)
    (hVenv : V.env = envOf r.input) {c : RecordCommand} (hc : commandWellFormed (.record c) = true)
    (h0 : c.amountCents ≠ 0)
    {p : Payment} {k : Receipt} (hex : r.input.payments.find? (·.commonOriginId = c.commonOriginId) = some p)
    (hne : p.amountCents ≠ c.amountCents)
    (hbo : V.byOrigin = some (p, k, p.reversalEvidenceId.bind (findEvidence r.input.evidence)))
    (hev : V.evidence = findEvidence r.input.evidence c.evidenceId)
    (hcv : V.conflictVisible = r.input.conflicts.any (·.conflictId = conflictIdOf r.input c))
    (hfor : V.foreign = r.foreign) (hexp : V.expectedRevision = r.expectedRevision) :
    some (viewRecordNew V S c) = project r (recordNew r c) := by
  have hp := List.mem_of_find?_eq_some hex
  have hporig : p.commonOriginId = c.commonOriginId := by
    have := List.find?_some hex
    simpa using this
  unfold viewRecordNew recordNew
  simp only [decide_eq_false hne, hbo, hev, hcv, hfor, hexp, hVenv, hex, head_conf, head_cid, head_cimg,
    envOf_eval, envOf_before, revisionOk, evidenceSlot_eq, conf_evid, Option.any_some, Option.isSome_some,
    Bool.false_and, Bool.not_false, Bool.true_and,
    Bool.false_eq_true, ↓reduceIte]
  have hfp := findPayment_of_mem (nodup_ids_of_wf hwf) hp
  by_cases h1 : ((r.input.conflicts.any fun x => decide (x.conflictId = conflictIdOf r.input c)) &&
      (slotOf r.foreign.evidenceId (findEvidence r.input.evidence c.evidenceId)
        (confirmation r.input c r.input.evaluatedAt)).isSame) = true
  · simp only [h1, ↓reduceIte]; rfl
  simp only [h1, Bool.false_eq_true, ↓reduceIte]
  by_cases hrv : (!Option.all (fun x => decide (x = r.input.beforeRevision)) r.expectedRevision) = true
  · simp only [hrv, ↓reduceIte]; rfl
  simp only [hrv, Bool.false_eq_true, ↓reduceIte]
  cases hform : formRefusal (confirmation r.input c r.input.evaluatedAt) with
  | some f => simp only [hform]; rfl
  | none =>
    simp only [hform]
    by_cases hch : c.eventAt > r.input.evaluatedAt
    · simp only [hch, ↓reduceIte]; rfl
    simp only [hch, ↓reduceIte]
    cases hsl : slotOf r.foreign.evidenceId (findEvidence r.input.evidence c.evidenceId)
        (confirmation r.input c r.input.evaluatedAt) with
    | clash => simp only [hsl]; rfl
    | same s =>
      simp only [hsl]
      by_cases hcvf : (r.input.conflicts.any fun x => decide (x.conflictId = conflictIdOf r.input c)) = true
      · simp only [hcvf, ↓reduceIte]; rfl
      by_cases hid : (!idWellFormed (conflictIdOf r.input c)) = true
      · simp only [hcvf, hid, ↓reduceIte]; rfl
      simp only [hcvf, hid, ↓reduceIte]
      exact shape_conflict hwf hb hS hVenv hc h0 hfp hporig hne (by simpa using hcvf) (by simpa using hid)
        (ev_leaf hsl (by simp) (fun _ => rfl) hform (Nat.not_lt.1 hch))
    | fresh =>
      simp only [hsl]
      by_cases hcvf : (r.input.conflicts.any fun x => decide (x.conflictId = conflictIdOf r.input c)) = true
      · simp only [hcvf, ↓reduceIte]; rfl
      by_cases hid : (!idWellFormed (conflictIdOf r.input c)) = true
      · simp only [hcvf, hid, ↓reduceIte]; rfl
      simp only [hcvf, hid, ↓reduceIte]
      exact shape_conflict hwf hb hS hVenv hc h0 hfp hporig hne (by simpa using hcvf) (by simpa using hid)
        (ev_leaf hsl (by simp) (fun _ => rfl) hform (Nat.not_lt.1 hch))

private theorem new_same {r : PaymentRequest} {V : PaymentView} {S : ItemState}
    (hwf : financialInputWellFormed r.input = true)
    (hb : r.inputBytes = (rawEncodeFinancialInput r.input).length)
    (hS : summarize r.input r.receipts (anchorItemLength r.input r.receipts) = some S)
    (hVenv : V.env = envOf r.input) {c : RecordCommand} (hc : commandWellFormed (.record c) = true)
    {p : Payment} {k : Receipt} (hex : r.input.payments.find? (·.commonOriginId = c.commonOriginId) = some p)
    (hs : p.amountCents = c.amountCents)
    (hk : receiptOf r.receipts p.paymentId = some k)
    (hbo : V.byOrigin = some (p, k, p.reversalEvidenceId.bind (findEvidence r.input.evidence)))
    (hev : V.evidence = findEvidence r.input.evidence c.evidenceId)
    (hcv : V.conflictVisible = r.input.conflicts.any (·.conflictId = conflictIdOf r.input c))
    (hfor : V.foreign = r.foreign) (hexp : V.expectedRevision = r.expectedRevision) :
    some (viewRecordNew V S c) = project r (recordNew r c) := by
  have hp := List.mem_of_find?_eq_some hex
  have hporig : p.commonOriginId = c.commonOriginId := by
    have := List.find?_some hex
    simpa using this
  unfold viewRecordNew recordNew
  simp only [decide_eq_true hs, hbo, hev, hcv, hfor, hexp, hVenv, hex, hk, head_conf, head_cid,
    envOf_eval, envOf_before, revisionOk, evidenceSlot_eq, conf_evid, Option.any_some, Option.isSome_some,
    Option.bind_some, Bool.true_and,
    ↓reduceIte]
  cases hf : r.foreign.evidenceId with
  | true =>
    simp only [hf, Bool.or_true, Bool.not_true, Bool.false_and, Bool.true_and, Bool.and_true,
      Bool.false_eq_true, ↓reduceIte]
    rfl
  | false =>
    cases hst : findEvidence r.input.evidence c.evidenceId with
    | some s0 =>
      simp only [hf, hst, Option.isSome_some, Bool.true_or, Bool.or_false, Bool.not_true, Bool.false_and,
        Bool.true_and, Bool.and_false, Bool.and_true, Option.map_some, Option.getD_some,
        Bool.false_eq_true, ↓reduceIte]
      cases hform : formRefusal (confirmation r.input c s0.receivedAt) with
      | some f => simp only [hform]; rfl
      | none =>
        simp only [hform]
        by_cases hch : c.eventAt > s0.receivedAt
        · simp only [hch, ↓reduceIte]; rfl
        simp only [hch, ↓reduceIte]
        cases hsl : slotOf false (some s0) (confirmation r.input c s0.receivedAt) with
        | clash => simp only [hsl]; rfl
        | fresh => exact absurd ((slot_facts hsl).1 rfl).2 (by simp)
        | same s =>
          simp only [hsl]
          by_cases hA : (c.paysActionId.isSome && decide (c.paysActionId ≠ k.paysActionId)) = true
          · simp only [hA, ↓reduceIte]; rfl
          · simp only [hA, Slot.isFresh, Bool.false_eq_true, ↓reduceIte]; rfl
    | none =>
      simp only [hf, hst, Option.isSome_none, Bool.or_false, Bool.not_false, Bool.true_and, Bool.false_and,
        Bool.and_false, Bool.and_true, Option.map_none, Option.getD_none, Bool.false_eq_true, ↓reduceIte]
      by_cases h1 : (decide (p.status = PaymentStatus.REVERSED) &&
          Option.any (fun x => decide (x.eventAt < c.eventAt))
            (p.reversalEvidenceId.bind (findEvidence r.input.evidence))) = true
      · simp only [h1, ↓reduceIte]; rfl
      simp only [h1, Bool.false_eq_true, ↓reduceIte]
      by_cases hrv : (!Option.all (fun x => decide (x = r.input.beforeRevision)) r.expectedRevision) = true
      · simp only [hrv, ↓reduceIte]; rfl
      simp only [hrv, Bool.false_eq_true, ↓reduceIte]
      cases hform : formRefusal (confirmation r.input c r.input.evaluatedAt) with
      | some f => simp only [hform]; rfl
      | none =>
        simp only [hform]
        by_cases hch : c.eventAt > r.input.evaluatedAt
        · simp only [hch, ↓reduceIte]; rfl
        simp only [hch, ↓reduceIte]
        have hsl : slotOf false none (confirmation r.input c r.input.evaluatedAt) = Slot.fresh := by
          simp [slotOf]
        simp only [hsl]
        by_cases hA : (c.paysActionId.isSome && decide (c.paysActionId ≠ k.paysActionId)) = true
        · simp only [hA, ↓reduceIte]; rfl
        simp only [hA, Slot.isFresh, Bool.false_eq_true, ↓reduceIte]
        exact shape_alias hwf hb hS hVenv hc hp hporig hs hst hform (Nat.not_lt.1 hch) p.paymentId

private theorem new_lock {r : PaymentRequest} {V : PaymentView} {S : ItemState}
    (hwf : financialInputWellFormed r.input = true)
    (hrec : r.receipts.map Receipt.paymentId = r.input.payments.map Payment.paymentId)
    (hb : r.inputBytes = (rawEncodeFinancialInput r.input).length)
    (hS : summarize r.input r.receipts (anchorItemLength r.input r.receipts) = some S)
    (hVenv : V.env = envOf r.input) {c : RecordCommand} (hc : commandWellFormed (.record c) = true)
    (h0 : c.amountCents ≠ 0) (hpid : findPayment r.input.payments c.paymentId = none)
    (hbyId : V.byId = none)
    (hbo : V.byOrigin = (r.input.payments.find? (·.commonOriginId = c.commonOriginId)).bind fun p =>
      ((receiptOf r.receipts p.paymentId).map fun k => (p, k)).map fun (p, k) =>
        (p, k, p.reversalEvidenceId.bind (findEvidence r.input.evidence)))
    (hev : V.evidence = findEvidence r.input.evidence c.evidenceId)
    (hcv : V.conflictVisible = r.input.conflicts.any (·.conflictId = conflictIdOf r.input c))
    (hfor : V.foreign = r.foreign) (hexp : V.expectedRevision = r.expectedRevision) :
    some (viewRecordNew V S c) = project r (recordNew r c) := by
  cases hex : r.input.payments.find? (·.commonOriginId = c.commonOriginId) with
  | none =>
    rw [hex] at hbo
    exact new_none hwf hrec hb hS hVenv hc h0 hpid hbyId hbo hev hcv hfor hexp hex
  | some p =>
    obtain ⟨k, hk⟩ := receipt_of_mem hwf hrec (List.mem_of_find?_eq_some hex)
    rw [hex] at hbo
    simp only [Option.bind_some, hk, Option.map_some] at hbo
    by_cases hs : p.amountCents = c.amountCents
    · exact new_same hwf hb hS hVenv hc hex hs hk hbo hev hcv hfor hexp
    · exact new_diff hwf hb hS hVenv hc h0 hex hs hbo hev hcv hfor hexp

-- 16.2 item 3 (5.6): request-level; stepView_state is deleted (it is the `project` clause)
theorem stepView_eq {r : PaymentRequest} (hr : requestWellFormed r = true)
    (hb : r.inputBytes = (rawEncodeFinancialInput r.input).length) {v : PaymentView}
    (hv : Faithful r v) : some (stepView v) = project r (paymentTransition r) := by
  obtain ⟨S, hS, habs, hVenv, hbyId, hbo, hev, hcv, hfor, hexp, hcmd⟩ := faithful_unpack hb hv
  simp only [requestWellFormed, Bool.and_eq_true] at hr
  obtain ⟨⟨⟨hwf, hrcp⟩, hcw⟩, -⟩ := hr
  have hrec : r.receipts.map Receipt.paymentId = r.input.payments.map Payment.paymentId := by
    simp only [receiptsWellFormed, Bool.and_eq_true, beq_iff_eq] at hrcp; exact hrcp.1
  unfold stepView paymentTransition
  dsimp only
  rw [habs, hcmd]
  cases hcm : r.command with
  | reverse c =>
    simp only [hcm, cmdPaymentId, cmdEvidenceId] at hbyId hev hcw
    exact rev_lock hwf hrec hb hS hVenv hcw hbyId hev hfor hexp
  | record c =>
    simp only [hcm, cmdPaymentId, cmdEvidenceId] at hbyId hev hbo hcv hcw
    dsimp only
    rw [hfor]
    unfold decideRecord
    by_cases h0 : c.amountCents = 0
    · simp only [h0, ↓reduceIte]; rfl
    · simp only [h0, ↓reduceIte]
      by_cases hf : r.foreign.paymentId = true
      · simp only [hf, ↓reduceIte]; rfl
      · simp only [hf]
        cases hfp : findPayment r.input.payments c.paymentId with
        | some p =>
          obtain ⟨k, hk⟩ := receipt_of_mem hwf hrec (findPayment_mem hfp)
          rw [hfp] at hbyId
          simp only [Option.bind_some, hk, Option.map_some] at hbyId
          rw [hbyId]
          exact retry_lock hVenv hev hexp hk
        | none =>
          rw [hfp] at hbyId
          simp only [Option.bind_none] at hbyId
          rw [hbyId]
          exact new_lock hwf hrec hb hS hVenv hcw h0 hfp hbyId hbo hev hcv hfor hexp

private theorem bind_now {i : FinancialInput} {t : Nat} {a : ActionRecord}
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

private theorem actWF_now {i : FinancialInput} {t : Nat} {a : ActionRecord}
    (h : actionWellFormed i a = true) (hle : i.evaluatedAt ≤ t) :
    actionWellFormed { i with evaluatedAt := t } a = true := by
  unfold actionWellFormed at h ⊢
  rw [Bool.and_eq_true] at h ⊢
  exact ⟨h.1, bind_now h.2 hle⟩

private theorem detAct_now {i : FinancialInput} {t : Nat} {x : OffsetDetermination}
    (h : determinationActionWellFormed i x = true) (hle : i.evaluatedAt ≤ t) :
    determinationActionWellFormed { i with evaluatedAt := t } x = true := by
  simp only [determinationActionWellFormed, actionsForDetermination, Bool.and_eq_true,
    List.all_eq_true] at h ⊢
  exact ⟨h.1, fun a ha => bind_now (h.2 a ha) hle⟩

private theorem detWF_now {i : FinancialInput} {t : Nat} {x : OffsetDetermination}
    (h : determinationWellFormed i x = true) (hle : i.evaluatedAt ≤ t) :
    determinationWellFormed { i with evaluatedAt := t } x = true := by
  unfold determinationWellFormed at h ⊢
  rw [Bool.and_eq_true, Bool.and_eq_true] at h ⊢
  obtain ⟨⟨hP, hD⟩, hM⟩ := h
  refine ⟨⟨hP, ?_⟩, hM⟩
  simp only [decide_eq_true_eq] at hD ⊢
  omega

private theorem wf_now {i : FinancialInput} {t : Nat} (h : financialInputWellFormed i = true)
    (hle : i.evaluatedAt ≤ t) (ht : t ≤ maxTime) :
    financialInputWellFormed { i with evaluatedAt := t } = true := by
  unfold financialInputWellFormed at h ⊢
  simp only [envWellFormed, envOf, Bool.and_eq_true, decide_eq_true_eq, List.all_eq_true, and_assoc] at h ⊢
  obtain ⟨h1, h2, h3, h4, h5, h6, h7, h8, h9, h10, h11, h12, h13, h14, h15, h16, h17, h18, h19, h20, h21, h22, h23, h24, h25, h26, h27, h28, h29, h30, h31, h32, h33, h34, h35, h36, h37, h38, h39, h40, h41, h42, h43, h44, h45, h46, h47, h48, h49, h50, h51, h52, h53, h54, h55⟩ := h
  exact ⟨h1, h2, h3, h4, h5, h6, (by simp only [timeWellFormed, decide_eq_true_eq]; exact ht), h8, h9, h10, h11, h12, h13, h14, h15, h16, h17, h18, h19, h20, h21, h22, h23, h24, h25, h26, h27, h28, h29, h30, h31, h32, h33, h34, fun x hx => detWF_now (h35 x hx) hle, h36, h37, fun x hx => actWF_now (h38 x hx) hle, h39, h40, h41, h42, h43, h44, fun x hx => detAct_now (h45 x hx) hle, h46, h47, h48, fun x hx => Nat.le_trans (h49 x hx) hle, fun x hx => Nat.le_trans (h50 x hx) hle, h51, h52, h53, h54, h55⟩

private theorem step_eval (L : Ledger) (c : Call) :
    (step L c).input.evaluatedAt = L.input.evaluatedAt ∨ (step L c).input.evaluatedAt = c.now := by
  rcases step_cases L c with ⟨k, w, post, res, ho, he⟩ | ⟨pid, e, post, ho, he⟩ | ⟨-, -, he⟩ <;> rw [he]
  · right; rw [(paymentTransition_mutated_post ho).1]; rfl
  · right; rw [(alias_shape ho).1]; rfl
  · left; rfl

private theorem step_before_le (L : Ledger) (c : Call) :
    (step L c).input.beforeRevision ≤ L.input.beforeRevision + 1 := by
  rcases step_cases L c with ⟨k, w, post, res, ho, he⟩ | ⟨pid, e, post, ho, he⟩ | ⟨-, -, he⟩ <;> rw [he]
  · have hb : post.beforeRevision = L.input.beforeRevision := by
      rw [(paymentTransition_mutated_post ho).1]; rfl
    show post.beforeRevision + 1 ≤ _
    rw [hb]
    exact Nat.le_refl _
  · rw [(alias_shape ho).1]; exact Nat.le_succ _
  · exact Nat.le_succ _

/-- `hw` is `decodePaymentItem_command` for each view: the worker steps only decoded views. -/
theorem chain_fold_eq_full (L : Ledger) (hL : ledgerWellFormed L) (calls : List Call)
    (hc : clocksOk L calls) (hR : L.input.beforeRevision + calls.length ≤ maxRevision)
    (vs : List PaymentView) (hv : ChainFaithful L calls vs)
    (hw : vs.all fun v => commandWellFormed v.command && v.expectedRevision.all (· < 2 ^ 63)) :
    vs.map (some ∘ stepView) =
      ((ledgers L calls).zip calls).map fun M => project (M.1.request M.2) (M.1.outcome M.2) := by
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
      have head : some (stepView v) = project (L.request c) (L.outcome c) :=
        stepView_eq hrq rfl hFv
      show some (stepView v) :: vs'.map (some ∘ stepView) =
        project (L.request c) (L.outcome c) :: ((ledgers (step L c) cs).zip cs).map _
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


theorem run_balance_identity (L : Ledger) (calls : List Call) {r r' : FinancialResult}
    (h : evaluate L.input = some r) (h' : evaluate (run L calls).input = some r') :
    r'.shortfallCents + r.overageCents + recordedCents (trace L calls) =
      r.shortfallCents + r'.overageCents + reversedOutcomeCents (trace L calls) := by
  obtain ⟨la, hla, e1⟩ := evaluate_balance h
  obtain ⟨la', hla', e2⟩ := evaluate_balance h'
  obtain ⟨hcl, hob⟩ := run_frame L calls
  rw [hcl, hla] at hla'
  have hl := Option.some.inj hla'
  rw [hob] at e2
  have hc := run_conservation L calls
  omega

end BlindLedger.Financial.Payment
