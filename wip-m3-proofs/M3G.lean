import BlindLedger.Financial.Payment.Rev12
import M3F
open BlindLedger.Financial BlindLedger.Financial.Payment BlindLedger.Financial.CorrectionTransition
namespace BlindLedger.Financial.Payment.Rev12

/-! ## The fixed strings the row builders write are well formed -/

theorem utf8_list (s : String) : s.toUTF8.toList = s.toList.flatMap String.utf8EncodeChar := by
  rw [byteArray_toList_eq, String.toUTF8_eq_toByteArray, ← String.utf8Encode_toList]
  unfold List.utf8Encode
  rw [List.toList_data_toByteArray]

theorem tok_conf : tokenWellFormed "PAYMENT_CONFIRMATION" = true := by
  unfold tokenWellFormed; rw [utf8_list]; decide
theorem tok_rev : tokenWellFormed "PAYMENT_REVERSAL" = true := by
  unfold tokenWellFormed; rw [utf8_list]; decide
theorem id_src : idWellFormed "synthetic-payment-source" = true := by
  unfold idWellFormed; rw [utf8_list]; decide
theorem id_ver : idWellFormed "fixture-v1" = true := by
  unfold idWellFormed; rw [utf8_list]; decide
theorem id_reason : idWellFormed "CONFLICTING_COMMON_ORIGIN_AMOUNT" = true := by
  unfold idWellFormed; rw [utf8_list]; decide

theorem maxTime_eq : maxTime = 2 ^ 63 - 1 := rfl

/-! ## What a well-formed command and a refusal-free row give -/

theorem cmd_record {c : RecordCommand} (h : commandWellFormed (.record c) = true) :
    idWellFormed c.paymentId = true ∧ idWellFormed c.evidenceId = true ∧
      idWellFormed c.commonOriginId = true ∧ idWellFormed c.sourceId = true ∧
      idWellFormed c.sourceVersion = true ∧ c.amountCents ≤ maxCents ∧ c.eventAt ≤ maxTime := by
  have := maxTime_eq
  simp only [commandWellFormed, Bool.and_eq_true, decide_eq_true_eq, List.all_cons, List.all_nil,
    Bool.and_true] at h
  obtain ⟨⟨⟨⟨⟨h1, h2, h3, h4, h5⟩, -⟩, -⟩, h6⟩, h7⟩ := h
  exact ⟨h1, h2, h3, h4, h5, h6, by omega⟩

theorem cmd_reverse {c : ReverseCommand} (h : commandWellFormed (.reverse c) = true) :
    idWellFormed c.paymentId = true ∧ idWellFormed c.evidenceId = true := by
  simp only [commandWellFormed, Bool.and_eq_true] at h
  exact ⟨h.1.1.1, h.1.1.2⟩

theorem form_ids {e : EvidenceRecord} (h : formRefusal e = none) :
    idWellFormed e.commonOriginId = true ∧ idWellFormed e.localRef = true := by
  unfold formRefusal at h
  by_cases h1 : idWellFormed e.commonOriginId = true
  · by_cases h2 : idWellFormed e.localRef = true
    · exact ⟨h1, h2⟩
    · simp [h1, h2] at h
  · simp [h1] at h

theorem confirmation_wf {i : FinancialInput}
    (hctx : idWellFormed i.context.obligationId = true ∧ idWellFormed i.context.itemId = true)
    {c : RecordCommand} (hc : commandWellFormed (.record c) = true) {t : Nat}
    (hform : formRefusal (confirmation i c t) = none) (hle : c.eventAt ≤ t) (ht : t ≤ maxTime) :
    evidenceWellFormed i.context (confirmation i c t) = true := by
  obtain ⟨h1, h2, h3, h4, h5, h6, h7⟩ := cmd_record hc
  obtain ⟨hf1, hf2⟩ := form_ids hform
  simp only [confirmation] at hf1 hf2
  simp [evidenceWellFormed, confirmation, timeWellFormed, amountWellFormed, optionalIdWellFormed,
    kindWellFormed, tok_conf, h1, h2, h3, h4, h5, h6, h7, hf1, hf2, hctx.1, hctx.2, hle, ht]

theorem reversalRecord_wf {i : FinancialInput}
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
    kindWellFormed, tok_rev, id_src, id_ver, h1, h2, hf1, hf2, hctx.1, hctx.2, hle, hnow, hp1, hpa, ht]

theorem recordedPayment_wf {i : FinancialInput}
    (hctx : idWellFormed i.context.obligationId = true ∧ idWellFormed i.context.itemId = true)
    {c : RecordCommand} (hc : commandWellFormed (.record c) = true) (h0 : c.amountCents ≠ 0) :
    paymentWellFormed i.context (recordedPayment i c) = true := by
  obtain ⟨h1, h2, h3, h4, h5, h6, h7⟩ := cmd_record hc
  simp [paymentWellFormed, recordedPayment, timeWellFormed, positiveAmountWellFormed, amountWellFormed,
    optionalIdWellFormed, h1, h2, h3, h6, h7, hctx.1, hctx.2]
  omega

theorem reversedImage_wf {i : FinancialInput} {p : Payment} (hp : paymentWellFormed i.context p = true)
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
  simp only [financialInputWellFormed, Bool.and_assoc, Bool.and_eq_true, decide_eq_true_eq] at h
  obtain ⟨h1,h2,h3,h4,h5,h6,h7,h8,h9,h10,h11,h12,h13,h14,h15,h16,h17,h18,h19,h20,h21,h22,h23,h24,h25,h26,h27,h28,h29,h30,h31,h32,h33,h34,h35,h36,h37,h38,h39,h40,h41,h42,h43,h44,h45,h46,h47,h48,h49,h50,h51,h52,h53,h54,h55⟩ := h
  refine ⟨h17, h20, h21, List.all_eq_true.1 h32, List.all_eq_true.1 h39, List.all_eq_true.1 h40, h55, ?_⟩
  intro e
  rw [e] at h22
  exact absurd h22 (by simp)

end BlindLedger.Financial.Payment.Rev12
