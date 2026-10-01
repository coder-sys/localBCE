import BlindLedger.Financial.Payment.Rev12
import M3M
open BlindLedger.Financial BlindLedger.Financial.Payment BlindLedger.Financial.CorrectionTransition
namespace BlindLedger.Financial.Payment.Rev12

theorem faithful_unpack {r : PaymentRequest} {v : PaymentView}
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

theorem head_conf (i : FinancialInput) (c : RecordCommand) (t : Nat) :
    confirmation (envOf i).head c t = confirmation i c t := rfl
theorem head_rrec (i : FinancialInput) (c : ReverseCommand) (p : Payment) (t : Nat) :
    reversalRecord (envOf i).head c p t = reversalRecord i c p t := rfl
theorem head_rpay (i : FinancialInput) (c : RecordCommand) :
    recordedPayment (envOf i).head c = recordedPayment i c := rfl
theorem head_rrcp (i : FinancialInput) (c : RecordCommand) :
    recordedReceipt (envOf i).head c = recordedReceipt i c := rfl
theorem head_cimg (i : FinancialInput) (c : RecordCommand) (p : Payment) (id : String) :
    conflictImage (envOf i).head c p id = conflictImage i c p id := rfl
theorem head_cid (i : FinancialInput) (c : RecordCommand) :
    conflictIdOf (envOf i).head c = conflictIdOf i c := rfl

theorem retry_lock {r : PaymentRequest} {V : PaymentView} {c : RecordCommand} {p : Payment} {k : Receipt}
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

end BlindLedger.Financial.Payment.Rev12
