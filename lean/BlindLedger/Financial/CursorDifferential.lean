import BlindLedger.Financial.CursorCorrection
import BlindLedger.Financial.Theorems.Vectors
import BlindLedger.Financial.CorrectionTransition.KAT

/-! The cursor decoders against the list decoders, on the known-answer wires and on every one-byte
    damage of them: each truncation, a flipped bit and a 0xFF at every position, a trailing byte and a
    doubled frame.  They must agree exactly, `none` included.  This is a check on top of the
    equality theorems, and no executable links it. -/

open BlindLedger.Financial

private def pad5 (n : Nat) : String := "".pushn '0' (5 - (toString n).length) ++ toString n

private def wide (input : FinancialInput) (rows : Nat) : FinancialInput :=
  match input.evidence with
  | [] => input
  | e :: _ =>
    let extra := (List.range rows).map fun i =>
      { e with evidenceId := "zz" ++ pad5 i, kind := "NOTE", commonOriginId := "zz" ++ pad5 i,
               amountCents := none, reversalOf := none, supersedes := none }
    { input with evidence := (input.evidence ++ extra).mergeSort (fun a b => a.evidenceId ≤ b.evidenceId) }

private def mutations (w : Bytes) : List Bytes :=
  [w, [], w ++ [0], w ++ w] ++ (List.range w.length).map (w.take ·) ++
  (List.range w.length).map (fun i => w.set i (w[i]! ^^^ 1)) ++
  (List.range w.length).map (fun i => w.set i 255)

private def agreeInput (b : Bytes) : Bool :=
  (Cursor.decodeFinancialInput b.toByteArray).map rawEncodeFinancialInput ==
    (decodeFinancialInput b).map rawEncodeFinancialInput

#guard (mutations katWire).all agreeInput
#guard agreeInput (rawEncodeFinancialInput (wide katAuthorized 2500))
#guard (decodeFinancialInput (rawEncodeFinancialInput (wide katAuthorized 2500))).isSome

#guard (mutations ((CorrectionTransition.encodeCorrectionTransitionRequest CorrectionTransition.correctionKatRequest).getD [])).all fun b =>
  (Cursor.decodeCorrectionTransitionRequest b.toByteArray).bind CorrectionTransition.encodeCorrectionTransitionRequest ==
    (CorrectionTransition.decodeCorrectionTransitionRequest b).bind CorrectionTransition.encodeCorrectionTransitionRequest
