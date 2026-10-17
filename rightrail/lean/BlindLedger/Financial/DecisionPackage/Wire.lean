import BlindLedger.Financial.DecisionPackage.Conclude

namespace BlindLedger.Financial.DecisionPackage
open BlindLedger.Financial

/-- "BLFDPK01" and "BLFDPA01" as byte literals, so disjointness is kernel-decidable
    (`#guard`s in 4.6 tie them to the ASCII strings). -/
def packageItemMagic : Bytes := [0x42, 0x4C, 0x46, 0x44, 0x50, 0x4B, 0x30, 0x31]
def packageAnswerMagic : Bytes := [0x42, 0x4C, 0x46, 0x44, 0x50, 0x41, 0x30, 0x31]

def supportByte : Support → UInt8
  | .SUPPORTED => 1 | .NO_LINKED_EVIDENCE => 2 | .CONFLICTED => 3 | .UNKNOWN => 4 | .NOT_SATISFIED => 5
def decodeSupport (b : UInt8) : Option Support :=
  if b.toNat = 1 then some .SUPPORTED else if b.toNat = 2 then some .NO_LINKED_EVIDENCE
  else if b.toNat = 3 then some .CONFLICTED else if b.toNat = 4 then some .UNKNOWN
  else if b.toNat = 5 then some .NOT_SATISFIED else none
def assessmentByte : Assessment → UInt8
  | .NOT_RESOLVED => 1 | .CONFLICTED => 2 | .UNSUPPORTED => 3 | .UNKNOWN => 4 | .SUPPORTED => 5
def decodeAssessment (b : UInt8) : Option Assessment :=
  if b.toNat = 1 then some .NOT_RESOLVED else if b.toNat = 2 then some .CONFLICTED
  else if b.toNat = 3 then some .UNSUPPORTED else if b.toNat = 4 then some .UNKNOWN
  else if b.toNat = 5 then some .SUPPORTED else none

def readCents (b : Bytes) : Option (Nat × Bytes) := do
  let (v, r) ← readNatBE 8 b
  if v > maxCents then none else pure (v, r)

def readTagged (decode : UInt8 → Option α) (b : Bytes) : Option (α × Bytes) := do
  let (t, r) ← readByte b
  let v ← decode t
  pure (v, r)

def readOptionTagged (decode : UInt8 → Option α) (b : Bytes) : Option (Option α × Bytes) := do
  let (t, r) ← readByte b
  if t.toNat = 0 then pure (none, r) else
    let v ← decode t
    pure (some v, r)

def readPkgPayment (b : Bytes) : Option (PkgPayment × Bytes) := do
  let (amountCents, r) ← readCents b
  let (active, r) ← readBool r
  pure ({ amountCents, active }, r)

def readPkgClaim (b : Bytes) : Option (PkgClaim × Bytes) := do
  let (amountCents, r) ← readCents b
  let (status, r) ← readTagged decodeClaimStatus r
  pure ({ amountCents, status }, r)

def decodePackageFacts (item : Bytes) : Option PackageFacts := do
  if !packageItemMagic.isPrefixOf item then none else
  let b := item.drop packageItemMagic.length
  let (owedCents, b) ← readCents b
  let (receivedCashCents, b) ← readCents b
  let (claimedAdjustmentCents, b) ← readCents b
  let (lawfulAdjustmentCents, b) ← readCents b
  let (amountSatisfied, b) ← readBool b
  let (reportingComplete, b) ← readBool b
  let (verification, b) ← readTagged decodeVerificationStatus b
  let (payments, b) ← readList readPkgPayment b
  let (claims, b) ← readList readPkgClaim b
  let (reportCount, b) ← readCents b
  let (conflictCount, b) ← readCents b
  let (caseStatus, b) ← readOptionTagged decodeCaseStatus b
  let (actionStatus, b) ← readOptionTagged decodeActionStatus b
  let (acknowledged, b) ← readBool b
  if b ≠ [] then none else
  match actionStatus with
  | none => if acknowledged then none else
      pure { owedCents, receivedCashCents, claimedAdjustmentCents, lawfulAdjustmentCents, amountSatisfied,
             reportingComplete, verification, payments, claims, reportCount, conflictCount, caseStatus, action := none }
  | some status =>
      pure { owedCents, receivedCashCents, claimedAdjustmentCents, lawfulAdjustmentCents, amountSatisfied,
             reportingComplete, verification, payments, claims, reportCount, conflictCount, caseStatus,
             action := some { status, acknowledged } }

def encodePackageFacts (f : PackageFacts) : Bytes :=
  packageItemMagic ++ natBE 8 f.owedCents ++ natBE 8 f.receivedCashCents ++ natBE 8 f.claimedAdjustmentCents ++
    natBE 8 f.lawfulAdjustmentCents ++ encodeBool f.amountSatisfied ++ encodeBool f.reportingComplete ++
    [encodeVerificationStatus f.verification] ++
    encodeList (fun p => natBE 8 p.amountCents ++ encodeBool p.active) f.payments ++
    encodeList (fun c => natBE 8 c.amountCents ++ [encodeClaimStatus c.status]) f.claims ++
    natBE 8 f.reportCount ++ natBE 8 f.conflictCount ++
    [match f.caseStatus with | none => 0 | some s => encodeCaseStatus s] ++
    (match f.action with
      | none => [0, 0]
      | some a => [encodeActionStatus a.status] ++ encodeBool a.acknowledged)

def packageFactsWellFormed (f : PackageFacts) : Prop :=
  f.owedCents ≤ maxCents ∧ f.receivedCashCents ≤ maxCents ∧ f.claimedAdjustmentCents ≤ maxCents ∧
  f.lawfulAdjustmentCents ≤ maxCents ∧ f.reportCount ≤ maxCents ∧ f.conflictCount ≤ maxCents ∧
  f.payments.length ≤ maxRows ∧ f.claims.length ≤ maxRows ∧
  (∀ p ∈ f.payments, p.amountCents ≤ maxCents) ∧ (∀ c ∈ f.claims, c.amountCents ≤ maxCents)

def encodePackageAnswer (c : Conclusions) : Bytes :=
  packageAnswerMagic ++
    [supportByte c.cash, supportByte c.amount, supportByte c.reporting, supportByte c.delivery,
     supportByte c.requiredAmount, UInt8.ofNat c.missingMask, assessmentByte c.assessment] ++
    natBE 8 c.missingCents ++ natBE 2 c.activePaymentCount ++ natBE 2 c.authorizedClaimCount

/-- The specification of the Python reader `semantic.decode_package_answer`. -/
def decodePackageAnswer (b : Bytes) : Option Conclusions := do
  if !packageAnswerMagic.isPrefixOf b then none else
  let b := b.drop packageAnswerMagic.length
  let (cash, b) ← readTagged decodeSupport b
  let (amount, b) ← readTagged decodeSupport b
  let (reporting, b) ← readTagged decodeSupport b
  let (delivery, b) ← readTagged decodeSupport b
  let (requiredAmount, b) ← readTagged decodeSupport b
  let (mask, b) ← readByte b
  if mask.toNat > 7 then none else
  let (assessment, b) ← readTagged decodeAssessment b
  let (missingCents, b) ← readCents b
  let (activePaymentCount, b) ← readNatBE 2 b
  let (authorizedClaimCount, b) ← readNatBE 2 b
  if b ≠ [] then none else
  pure { cash, amount, reporting, delivery, requiredAmount, missingMask := mask.toNat, assessment, missingCents,
         activePaymentCount, authorizedClaimCount }

/-- Worker outcome bytes: 0 ‖ 27-byte answer, or the single byte 1. `conclude` is total and the
    answer encoder cannot fail, so 2 and 3 never occur. -/
def packageRespond (item : Bytes) : Bytes :=
  match decodePackageFacts item with
  | none => [UInt8.ofNat 1]
  | some f => UInt8.ofNat 0 :: encodePackageAnswer (conclude f)

end BlindLedger.Financial.DecisionPackage