import BlindLedger.Financial.Theorems.Vectors
import BlindLedger.Financial.CorrectionTransition.KAT
import BlindLedger.Financial.Payment.Codec
import BlindLedger.Financial.Worker

/-! `wire_vectors` (test-only, not pinned): prints `<name> <hex>` of the Lean-encoded request bytes for fixed inputs.
    `tests/test_wire_vectors.py` encodes the same logical inputs with the live Python encoders and requires equal bytes. -/
namespace BlindLedger.Financial

def wvHex (b : Bytes) : String :=
  String.join (b.map fun x => let d := "0123456789abcdef".toList; s!"{d.getD (x.toNat / 16) '0'}{d.getD (x.toNat % 16) '0'}")

def wvHexVal (c : Char) : Nat := if c.toNat ≥ 65 then c.toNat - 55 else c.toNat - 48

def wvUnhex : List Char → Bytes
  | a :: b :: r => UInt8.ofNat (wvHexVal a * 16 + wvHexVal b) :: wvUnhex r
  | _ => []

/-- The control-pack digest the Python owner computes for `katPack`'s fields (sha3-512 over the canonical JSON). -/
def wvPackDigest : Bytes := wvUnhex "686AAFAB8E362CC65FC25722DADFFAA119BE819001179B7073A2BFA20E1B979C2ECB3D01EB9D62EFC5D0A7171B5BD3F2154C3DB36F9CFF2DE6EADCFEA23747EA".toList

def wvLongId : String := "a" ++ String.ofList (List.replicate 127 'b')
/-- 114 bytes: `"determination:" ++ wvActId` is then exactly `maxIdBytes` (128). -/
def wvActId : String := "a" ++ String.ofList (List.replicate 113 'b')
def wvDetId : String := "determination:" ++ wvActId

def wvFix (i : FinancialInput) : FinancialInput := { i with pack := { i.pack with digest := wvPackDigest } }

def wvInputs : List (String × FinancialInput) := [
  ("blfin02_base", wvFix katBase),
  ("blfin02_authorized", wvFix katAuthorized),
  ("blfin02_live_authorized", wvFix { katAuthorized with context := { katContext with mode := .LIVE } }),
  ("blfin02_reversed_conflict_shadow_restore", wvFix
    { katReversedInput with
      context := { katContext with mode := .SHADOW, provenance := .CONTINUITY_RESTORE }
      evidence := [katCashEvidence, katConflictEvidence, katOffsetEvidence, katReversalEvidence]
      conflicts := [katConflict] }),
  ("blfin02_max_length", wvFix
    { katAuthorized with
      evidence := [{ katCashEvidence with sourceId := wvLongId, sourceVersion := wvLongId, localRef := wvLongId },
                   katOffsetEvidence]
      determinations := [{ katDetermination with determinationId := wvDetId }]
      cases := [{ caseId := wvLongId, obligationId := katContext.obligationId, reason := wvLongId,
                  nextActionOwner := "CASE_OWNER", dueAt := katObligation.dueAt, status := .AUTHORIZED,
                  updatedAt := 1_774_864_800_000 }]
      actions := [{ katAuthorizedAction with actionId := wvActId, determinationId := some wvDetId }] })]

open CorrectionTransition in
/-- `correctionKatRequest` (BLFCMD03, absent lookup) over the Python-matching pack digest. -/
def wvCorrection : CorrectionTransitionRequest :=
  { correctionKatRequest with
    currentInput := wvFix correctionKatInput
    currentReceipt := { correctionKatCurrentReceipt with
      controlPack := { correctionKatCurrentReceipt.controlPack with digest := wvPackDigest } } }

open CorrectionTransition in
def wvQuery (p : CorrectionQueryPredicate) (subject : String) (id : Option String) : CorrectionQueryObservation :=
  { predicate := p, subject, complete := true, matchCount := if id.isSome then 1 else 0, resultIdentity := id,
    versionSequence := 11, versionHead := List.replicate digestBytes (UInt8.ofNat 43) }

open CorrectionTransition in
/-- The existing-action lookup, found query rows and two payment links. -/
def wvCorrectionExisting : CorrectionTransitionRequest :=
  { wvCorrection with command := { wvCorrection.command with
    actionLookup := .existing correctionKatStoredIdentity
    queryObservations := {
      actionId := wvQuery .ACTION_ID "action:correction:h:v1" (some "action:correction:h:v1")
      determinationId := wvQuery .DETERMINATION_ID "determination:action:correction:h:v1"
        (some "determination:action:correction:h:v1")
      evaluationConsumed := wvQuery .EVALUATION_CONSUMED "evaluation:obligation:item-h:period-01:r4"
        (some "determination:action:correction:h:v1") }
    currentEventSequence := 11
    previousHistoryHead := List.replicate digestBytes (UInt8.ofNat 43)
    paymentLinks := [⟨"payment:h:cash", "action:correction:h:v1"⟩, ⟨"payment:h:later", "action:correction:h:v1"⟩] } }

open CorrectionTransition in
def wvCorrectionConflicting : CorrectionTransitionRequest :=
  { wvCorrection with command := { wvCorrection.command with actionLookup := .conflicting } }

open Payment in
/-- A BLFPAY01 form-A item over `blfin02_authorized` (one payment row, so one receipt). -/
def wvPay (receipt : Receipt) (foreign : Foreign) (expectedRevision : Option Nat) (command : Command) : Bytes :=
  let input := wvFix katAuthorized
  encodePaymentRequest
    { input, inputBytes := (rawEncodeFinancialInput input).length, receipts := [receipt], foreign, expectedRevision, command }

open Payment in
def wvPayRecord (localRef paysActionId : Option String) : Command :=
  .record { paymentId := "payment:h:new", evidenceId := "evidence:new", commonOriginId := "origin:new",
            sourceId := "fixture-payment-file", sourceVersion := "cash-v2", localRef, amountCents := 250_000,
            eventAt := 1_774_900_000_000, paysActionId }

def wvOthers : List (String × Option Bytes) := [
  ("blfcmd03_absent", CorrectionTransition.encodeCorrectionTransitionRequest wvCorrection),
  ("blfcmd03_existing_links", CorrectionTransition.encodeCorrectionTransitionRequest wvCorrectionExisting),
  ("blfcmd03_conflicting", CorrectionTransition.encodeCorrectionTransitionRequest wvCorrectionConflicting),
  ("blfpay01_record", some (wvPay ⟨"payment:h:cash", 1, none⟩ ⟨false, false⟩ (some 1)
    (wvPayRecord (some "ref:new") (some "action:h:offset")))),
  ("blfpay01_record_minimal", some (wvPay ⟨"payment:h:cash", 0, some "action:h:offset"⟩ ⟨true, false⟩ none
    (wvPayRecord none none))),
  ("blfpay01_reverse", some (wvPay ⟨"payment:h:cash", 2, none⟩ ⟨false, true⟩ (some 2)
    (.reverse ⟨"payment:h:cash", "evidence:reversal", some "reversal:payment:h:cash", some 1_774_900_000_000⟩))),
  ("blfpay01_reverse_minimal", some (wvPay ⟨"payment:h:cash", 2, none⟩ ⟨true, true⟩ none
    (.reverse ⟨"payment:h:cash", "evidence:reversal", none, none⟩))),
  ("blfofa01_absent", encodeOffsetAuthorizationRequest wvCorrection)]

def wvAll : List (String × Option Bytes) := wvInputs.map (fun (n, i) => (n, encodeFinancialInput i)) ++ wvOthers

end BlindLedger.Financial

open BlindLedger.Financial in
def main : IO UInt32 := do
  let mut bad : UInt32 := 0
  for (name, encoded) in wvAll do
    match encoded with
    | some w => IO.println s!"{name} {wvHex w}"
    | none => IO.println s!"{name} NONE"; bad := 1
  return bad
