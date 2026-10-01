import BlindLedger.Financial.Payment.ChainLaws
import BlindLedger.Financial.Payment.Open
import BlindLedger.Financial.Theorems.Vectors

namespace BlindLedger.Financial.Payment

open BlindLedger.Financial

/-! Form-A known answers (design 7.5), checked when this file builds: a record and a reverse
    request round-trip byte for byte, and any change to the bytes is refused. -/

private def katRequest (command : Command) : PaymentRequest :=
  { input := katBase, inputBytes := (rawEncodeFinancialInput katBase).length, receipts := [],
    foreign := ⟨false, true⟩, expectedRevision := some 0, command }

private def katRecord : Command := .record
  { paymentId := "payment:kat:1", evidenceId := "evidence:kat:1", commonOriginId := "origin:kat:1",
    sourceId := "source:kat", sourceVersion := "v1", localRef := none, amountCents := 700_000,
    eventAt := 1_774_900_000_000, paysActionId := some "action:kat" }

private def katReverse : Command := .reverse
  { paymentId := "payment:kat:1", evidenceId := "evidence:kat:2", commonOriginId := none,
    eventAt := some 1_774_910_000_000 }

private def roundTrips (c : Command) : Bool :=
  let w := encodePaymentRequest (katRequest c)
  requestWellFormed (katRequest c) && (decodePaymentRequest w).map encodePaymentRequest == some w

#guard roundTrips katRecord
#guard roundTrips katReverse
#guard (encodePaymentRequest (katRequest katRecord)).take 9 == paymentMagic ++ [UInt8.ofNat 1]
#guard (decodePaymentRequest (encodePaymentRequest (katRequest katRecord) ++ [UInt8.ofNat 0])).isNone
#guard (decodePaymentRequest ((encodePaymentRequest (katRequest katReverse)).dropLast)).isNone

/-! ## 16.10 Known answers: the chain agrees with the reference on concrete calls, and the
    fixed bytes of each new layout (printed as hex into the build log) -/

private def hexDigit (n : Nat) : Char := Char.ofNat (if n < 10 then 48 + n else 87 + n)
private def hex (b : Bytes) : String :=
  String.ofList (b.flatMap fun x => [hexDigit (x.toNat / 16), hexDigit (x.toNat % 16)])

private def kNow : Nat := 1_774_922_400_000
private def kL0 : Ledger := ⟨katBase, []⟩
private def kRec : RecordCommand :=
  { paymentId := "payment:kat:1", evidenceId := "evidence:kat:1", commonOriginId := "origin:kat:1",
    sourceId := "source:kat", sourceVersion := "v1", localRef := none, amountCents := 700_000,
    eventAt := 1_774_900_000_000, paysActionId := none }
private def kRev : ReverseCommand :=
  { paymentId := "payment:kat:1", evidenceId := "evidence:kat:2", commonOriginId := none,
    eventAt := some 1_774_910_000_000 }
private def c1 : Call := ⟨kNow, some 0, .record kRec⟩
private def c2 : Call := ⟨kNow + 1_000, some 1, .reverse kRev⟩
private def cConflict : Call :=
  ⟨kNow + 1_000, none, .record { kRec with paymentId := "payment:kat:2", evidenceId := "evidence:kat:3", amountCents := 1 }⟩
private def cAlias : Call :=
  ⟨kNow + 1_000, none, .record { kRec with paymentId := "payment:kat:3", evidenceId := "evidence:kat:4" }⟩
private def kL1 : Ledger := step kL0 c1
private def kL2 : Ledger := step kL1 c2
private def kShadow : Ledger := ⟨{ katBase with context := { katBase.context with mode := .SHADOW } }, []⟩

private def agrees (L : Ledger) (c : Call) : Bool :=
  match viewOfAnchor (L.request c) with
  | none => false
  | some v => decide (some (stepView v) = project (L.request c) (L.outcome c))

private def kind : PaymentOutcome → String
  | .mutated .RECORDED .. => "RECORDED"
  | .mutated .REVERSED .. => "REVERSED"
  | .mutated .CONFLICT_RECORDED .. => "CONFLICT_RECORDED"
  | .alias .. => "ALIAS"
  | .duplicate _ => "DUPLICATE"
  | .conflictUnchanged _ => "CONFLICT_UNCHANGED"
  | .refused _ => "REFUSED"

private def absorbs (L : Ledger) (c : Call) : Bool :=
  match L.outcome c with
  | .alias _ e _ => decide ((summaryOf L.input L.receipts).map (absorb · [e]) =
      summaryOf (step L c).input (step L c).receipts)
  | _ => false

private def formBRoundTrips (L : Ledger) (c : Call) : Bool :=
  (viewOfAnchor (L.request c)).any fun v =>
    viewWellFormed v && coherent v && decide (decodePaymentItem (encodeFormB v) = some v)

private def answerRoundTrips (L : Ledger) (c : Call) : Bool :=
  (viewOfAnchor (L.request c)).any fun v => (encodeStepOutcome (stepView v)).isSome

#guard kind (kL0.outcome c1) == "RECORDED"
#guard agrees kL0 c1
#guard kind (kL1.outcome ⟨kNow + 1, some 0, .record kRec⟩) == "DUPLICATE"
#guard agrees kL1 ⟨kNow + 1, some 0, .record kRec⟩
#guard kind (kL1.outcome c2) == "REVERSED"
#guard agrees kL1 c2
#guard kind (kL2.outcome { c2 with now := kNow + 2_000, expectedRevision := none }) == "DUPLICATE"
#guard agrees kL2 { c2 with now := kNow + 2_000, expectedRevision := none }
#guard kind (kL1.outcome cConflict) == "CONFLICT_RECORDED"
#guard agrees kL1 cConflict
#guard kind ((step kL1 cConflict).outcome { cConflict with now := kNow + 5_000, expectedRevision := some 7 }) ==
  "CONFLICT_UNCHANGED"
#guard kind (kL1.outcome cAlias) == "ALIAS"
#guard agrees kL1 cAlias
#guard absorbs kL1 cAlias
#guard kind (kShadow.outcome c1) == "REFUSED"
#guard agrees kShadow c1
#guard formBRoundTrips kL0 c1
#guard formBRoundTrips kL1 c2
#guard answerRoundTrips kL0 c1
#guard answerRoundTrips kL1 c2
#guard answerRoundTrips kL1 cAlias
#guard decodeStepOutcome (rawEncodeStepOutcome (.refused .CAPACITY)) == some (.refused .CAPACITY)
#guard refusals.length = 16 && anchorOverhead = 13

private def longId : String := String.ofList (List.replicate 128 'a')
private def worstRecord : Command := .record
  { paymentId := longId, evidenceId := longId, commonOriginId := longId, sourceId := longId,
    sourceVersion := longId, localRef := some longId, amountCents := 1, eventAt := 1, paysActionId := some longId }
#guard commandWellFormed worstRecord
#guard (encodeForeign ⟨true, true⟩ ++ encodeOptionNat (some 0) ++ encodeCommand worstRecord).length = 939

#eval (viewOfAnchor (kL0.request c1)).map fun v => hex (encodeFormB v)
#eval (viewOfAnchor (kL1.request c2)).map fun v => hex (encodeFormB v)
#eval (summaryOf kL1.input kL1.receipts).map fun s => hex (encodeItemState s)
#eval hex (rawEncodeStepOutcome (.refused .CAPACITY))
#eval (viewOfAnchor (kL0.request c1)).map fun v => ((encodeStepOutcome (stepView v)).map hex)

/-! ## Why `chain_fold_eq_full` has `hw`, and why `coherent` skips REVERSED rows

    `hw`: with only the other hypotheses, an ill-formed command (empty payment id) makes the
    reference refuse (POST_REJECTED) while the view mutates. No worker input carries one
    (`decodePaymentItem_command`). `coherent`: a payment may share its (time, id, amount)
    contribution with an authorized determination. The `y` chain reaches that state through the
    reference ledger; the view agrees at every step, and the reversed row decodes in both forms. -/

private def badCall : Call := ⟨kNow, some 0, .record { kRec with paymentId := "" }⟩
#guard financialInputWellFormed kL0.input && receiptsWellFormed kL0.input kL0.receipts
#guard decide (kL0.input.evaluatedAt ≤ kNow) && decide (kNow < 2 ^ 63)
#guard decide (kL0.input.beforeRevision + 1 ≤ maxRevision)
#guard commandWellFormed badCall.command == false
#guard match viewOfAnchor (kL0.request badCall) with
  | none => false
  | some v => decide (absorbed v = v) && !decide (some (stepView v) = project (kL0.request badCall) (kL0.outcome badCall))

private def xCmd : RecordCommand :=
  { paymentId := "determination:action:h:offset", evidenceId := "evidence:cash", commonOriginId := "origin:cash:h",
    sourceId := "fixture-payment-file", sourceVersion := "cash-v1", localRef := none, amountCents := 300_000,
    eventAt := 1_774_864_800_000, paysActionId := none }
private def yL0 : Ledger :=
  ⟨{ katAuthorized with beforeRevision := 2, payments := [], evidence := [katOffsetEvidence] }, []⟩
private def yRec : Call := ⟨1_774_922_400_000, none, .record xCmd⟩
private def yRev : Call := ⟨1_774_922_401_000, none, .reverse
  { paymentId := xCmd.paymentId, evidenceId := "evidence:reversal", commonOriginId := none, eventAt := some 1_774_900_000_000 }⟩
private def yL1 : Ledger := step yL0 yRec
private def yL2 : Ledger := step yL1 yRev
private def yRetry : Call := { yRec with now := 1_774_922_402_000 }

#guard financialInputWellFormed yL0.input && requestWellFormed (yL2.request yRetry)
#guard kind (yL0.outcome yRec) == "RECORDED" && agrees yL0 yRec
#guard kind (yL1.outcome yRev) == "REVERSED" && agrees yL1 yRev

/-! R2 known answers: two requests of 300,000 at revisions 1 and 2. -/

private def kReq (id : String) (rev : Nat) : ActionRecord :=
  { actionId := id, obligationId := "o", determinationId := none, kind := "CORRECTION_PAYMENT_REQUEST",
    amountCents := 300000, currency := "USD", revision := rev, status := .READY, payloadDigest := [],
    createdAt := rev }
private def kPay (id : String) (cents : Nat) : Payment :=
  { paymentId := id, obligationId := "o", itemId := "i", evidenceId := id, commonOriginId := id,
    amountCents := cents, eventAt := 0, reversalEvidenceId := none, status := .ACTIVE }
private def kXs : List ActionRecord := [kReq "b" 2, kReq "a" 1]  -- list order is not service order

-- Balance 400,000 after 200,000 unlinked: the older request keeps 300,000, the newer is cut to 100,000.
#guard kXs.map (openCents 400000 [] [] kXs) == [100000, 300000]
-- Balance 0: both are cut to nothing; balance back to 600,000 (a reversal): both regrow to 300,000.
#guard kXs.map (openCents 0 [] [] kXs) == [0, 0]
#guard kXs.map (openCents 600000 [] [] kXs) == [300000, 300000]
-- 100,000 paid on the older one at balance 500,000: it keeps 200,000, the newer keeps all 300,000.
#guard kXs.map (openCents 500000 [kPay "p" 100000] [⟨"p", "a"⟩] kXs) == [300000, 200000]
-- A cancelled request asks for nothing and gives way to the next.
#guard openCents 300000 [] [] [kReq "b" 2, { kReq "a" 1 with status := .CANCELLED }] (kReq "b" 2) == 300000
#guard openTotal 400000 [] [] kXs == min (CorrectionTransition.linkedOutstandingCents [] [] kXs) 400000

end BlindLedger.Financial.Payment
