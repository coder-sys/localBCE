import BlindLedger.Financial.Payment.Rev12
import M3L
open BlindLedger.Financial BlindLedger.Financial.Payment BlindLedger.Financial.CorrectionTransition
namespace BlindLedger.Financial.Payment.Rev12

theorem alias_wf {r : PaymentRequest} (hwf : financialInputWellFormed r.input = true)
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

theorem alias_cap {r : PaymentRequest} {S : ItemState}
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

theorem shape_alias {r : PaymentRequest} {V : PaymentView} {S : ItemState}
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

end BlindLedger.Financial.Payment.Rev12
