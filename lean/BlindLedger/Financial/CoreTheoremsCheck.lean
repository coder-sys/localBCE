import BlindLedger.Financial.CorrectionTransition.KAT
import BlindLedger.Financial.Worker

/-! core-theorems-v1 §6.1: every theorem's hypotheses are satisfiable on a known-answer value,
    and each conclusion holds there with the exact numbers. -/

open BlindLedger.Financial
open BlindLedger.Financial.CorrectionTransition

-- E1, E2 (unsatisfied side), T2 `before`: owed 10,000,000, cash 9,700,000, offset 300,000 claimed, not lawful.
#guard (evaluate correctionKatInput).any fun r =>
  r.owedCents == 10000000 && r.receivedCashCents == 9700000 && r.lawfulAdjustmentCents == 0 &&
  r.claimedAdjustmentCents == 300000 && r.shortfallCents == 300000 && r.overageCents == 0 &&
  !r.amountSatisfied && !r.cashSatisfied && r.completionAt == none && !r.timely

-- E1, E2, E3 (satisfied side): satisfied by the authorized offset.
#guard (evaluate katAuthorized).any fun r =>
  r.receivedCashCents + r.lawfulAdjustmentCents == r.owedCents + r.overageCents &&
  r.shortfallCents == 0 && r.amountSatisfied && r.completionAt.isSome

-- evalContributions_sum.
#guard (evaluate katAuthorized).any fun r =>
  ((evalContributions katAuthorized).map EvalContribution.amountCents).sum ==
    r.receivedCashCents + r.lawfulAdjustmentCents

-- E4: katAuthorized extends correctionKatInput by one contribution.
#guard katAuthorized.obligation == correctionKatInput.obligation
#guard (evalContributions katAuthorized).take (evalContributions correctionKatInput).length ==
  evalContributions correctionKatInput
#guard (evalContributions katAuthorized).length == (evalContributions correctionKatInput).length + 1

-- E5.
#guard (evaluate { katAuthorized with evaluatedAt := katAuthorized.evaluatedAt + 1 }) ==
  (evaluate katAuthorized).map fun r => { r with evaluatedAt := katAuthorized.evaluatedAt + 1 }

-- N1a, N1.
#guard match evaluateWire katWire with
  | .evaluated _ => true
  | _ => false

-- T1.1 (tight: outstanding equals shortfall), T2, A1.
#guard correctionKatAccepted.mutation.any fun m =>
  m.action.amountCents == 300000 && m.resultingResult.shortfallCents == 300000 &&
  m.resultingInput.payments == correctionKatInput.payments &&
  linkedOutstandingCents m.resultingInput.payments correctionKatRequest.command.paymentLinks
    m.resultingInput.actions == m.resultingResult.shortfallCents &&
  m.determination.actorId == correctionKatCommand.actorId &&
  m.determination.actorRole == correctionKatCommand.actorRole &&
  m.determination.authorityId == correctionKatCommand.currentAuthorityId

-- A1′.
#guard (assessCorrectionReuse correctionKatReuseRequest).localExecutionPermission == .ALLOWED

-- N2a, N2: an accepted and a SHADOW-rejected result both encode.
#guard (encodeCorrectionTransitionResult correctionKatAccepted).isSome
#guard (encodeCorrectionTransitionResult (applyCorrectionTransition { correctionKatRequest with
  currentInput := { correctionKatInput with
    context := { correctionKatInput.context with mode := .SHADOW } } })).isSome

-- BLFOFA01: the worker answers a served frame with applyOffsetAuthorization's encoded result.
private def servedOffset (request : CorrectionTransitionRequest) : Option Bytes :=
  (encodeCorrectionTransitionRequest request).map fun b => workerRespond (offsetAuthorizationMagic ++ b)
private def offsetAnswer (request : CorrectionTransitionRequest) : Option Bytes :=
  (encodeCorrectionTransitionResult (applyOffsetAuthorization request)).map (UInt8.ofNat 0 :: ·)
#guard (applyOffsetAuthorization correctionKatRequest).explanation.code == .OFFSET_AUTHORIZED
#guard (offsetAnswer correctionKatRequest).isSome &&
  servedOffset correctionKatRequest == offsetAnswer correctionKatRequest
#guard (applyOffsetAuthorization (correctionKatOwedRequest 9_800_000)).rejectReason ==
  some .CLAIM_EXCEEDS_SHORTFALL
#guard (offsetAnswer (correctionKatOwedRequest 9_800_000)).isSome &&
  servedOffset (correctionKatOwedRequest 9_800_000) == offsetAnswer (correctionKatOwedRequest 9_800_000)
#guard (applyOffsetAuthorization correctionKatBeforePackRequest).rejectReason ==
  some .DECISION_BEFORE_PACK_EFFECTIVE
#guard (offsetAnswer correctionKatBeforePackRequest).isSome &&
  servedOffset correctionKatBeforePackRequest == offsetAnswer correctionKatBeforePackRequest
-- A truncated BLFOFA01 frame is a decode rejection.
#guard workerRespond (offsetAuthorizationMagic ++ [UInt8.ofNat 1, UInt8.ofNat 2]) == [UInt8.ofNat 1]
