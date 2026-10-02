import BlindLedger.Financial.Payment.Codec

namespace BlindLedger.Financial.Offset

open BlindLedger.Financial BlindLedger.Financial.Payment

/-! Lean-live M4 (rrb/designs/lean-live-m4-v1.md, 3.4): the claim item, BLFOFC01 request, BLFOCR01 answer.
    Nothing calls this yet; the laws are in `ClaimLaws`. -/

def claimMagic : Bytes := "BLFOFC01".toUTF8.toList
def claimAnswerMagic : Bytes := "BLFOCR01".toUTF8.toList

structure ClaimCommand where
  claimId : String
  evidenceId : String
  amountCents : Nat
  ownerRole : String
  deadlineAt : Nat
deriving DecidableEq, Repr

/-- Carried facts the adapter reads: the id is a row outside this input (another obligation's claim;
    evidence of another obligation or item). -/
structure ClaimForeign where
  claimId : Bool
  evidenceId : Bool
deriving DecidableEq, Repr

structure ClaimRequest where
  input : FinancialInput        -- the pre-state; now = input.evaluatedAt
  inputBytes : Nat              -- length of its BLFIN02 encoding (set by the decoder)
  foreign : ClaimForeign
  expectedRevision : Option Nat
  command : ClaimCommand
deriving Repr

-- Python order (record_offset_claim): mode, amount, evidence form, role, retry, revision, evidence slot.
inductive ClaimRefusal where
  | SHADOW_READ_ONLY | AMOUNT_ZERO | LOCAL_REF_FORM | OWNER_ROLE_UNAUTHORIZED | IDENTITY_CONFLICT
  | REVISION_CONFLICT | EVIDENCE_REUSED | EVIDENCE_CONFLICT | CAPACITY | POST_REJECTED
deriving DecidableEq, Repr

/-- Row images the adapter writes; nothing else is written. `case = none`: an outstanding correction
    keeps its case row (Python `_ensure_case`). Whether a case row is inserted or updated is the
    adapter's own read of `case:{obligation}`. -/
structure ClaimWrites where
  evidence : EvidenceRecord
  claim : Claim
  case : Option CaseRecord
deriving DecidableEq, Repr

inductive ClaimOutcome where
  | claimed (writes : ClaimWrites) (post : FinancialInput) (result : FinancialResult)
  | duplicate
  | refused (reason : ClaimRefusal)

def claimEvidence (i : FinancialInput) (c : ClaimCommand) : EvidenceRecord :=
  { evidenceId := c.evidenceId, obligationId := i.context.obligationId, itemId := i.context.itemId,
    kind := "OFFSET_CLAIM", commonOriginId := c.claimId, sourceId := "synthetic-offset-source",
    sourceVersion := "fixture-v1", localRef := "offset:" ++ c.claimId,
    applicableAt := i.evaluatedAt, eventAt := i.evaluatedAt, receivedAt := i.evaluatedAt,
    amountCents := some c.amountCents, reversalOf := none, supersedes := none }

def claimImage (i : FinancialInput) (c : ClaimCommand) : Claim :=
  { claimId := c.claimId, obligationId := i.context.obligationId, evidenceId := c.evidenceId,
    amountCents := c.amountCents, ownerRole := c.ownerRole, deadlineAt := c.deadlineAt, status := .CLAIMED }

def claimCaseImage (i : FinancialInput) (c : ClaimCommand) : Option CaseRecord :=
  let caseId := "case:" ++ i.context.obligationId
  if (i.cases.find? (·.caseId = caseId)).any (·.status = .CORRECTION_REQUIRED) then none
  else some { caseId := caseId, obligationId := i.context.obligationId, reason := "UNSUPPORTED_OFFSET",
              nextActionOwner := c.ownerRole, dueAt := c.deadlineAt, status := .OPEN,
              updatedAt := i.evaluatedAt }

def applyClaim (i : FinancialInput) (w : ClaimWrites) : FinancialInput :=
  { i with
    evidence := insertBy EvidenceRecord.evidenceId w.evidence i.evidence
    claims := insertBy Claim.claimId w.claim i.claims
    cases := match w.case with
      | none => i.cases
      | some k => if i.cases.any (·.caseId = k.caseId)
                  then i.cases.map fun x => if x.caseId = k.caseId then k else x
                  else insertBy CaseRecord.caseId k i.cases }

/-- BLFIN02 growth, additive as in `addedBytes` (lists carry fixed-width counts). -/
def claimAddedBytes (i : FinancialInput) (w : ClaimWrites) : Nat :=
  (encodeEvidence w.evidence).length + (encodeClaim w.claim).length +
    match w.case with
    | none => 0
    | some k => (encodeCase k).length -
        (((i.cases.find? (·.caseId = k.caseId)).map fun x => (encodeCase x).length).getD 0)

def claimWithinCapacity (r : ClaimRequest) (w : ClaimWrites) : Bool :=
  r.inputBytes + claimAddedBytes r.input w + maxCallTailBytes ≤ maxTotalEncodedBytes

def decideClaim (r : ClaimRequest) : ClaimOutcome :=
  let i := r.input
  let c := r.command
  if i.context.mode = .SHADOW then .refused .SHADOW_READ_ONLY else
  if c.amountCents = 0 then .refused .AMOUNT_ZERO else
  let e := claimEvidence i c
  if !idWellFormed e.localRef then .refused .LOCAL_REF_FORM else
  if !i.pack.authorizedRoles.contains c.ownerRole then .refused .OWNER_ROLE_UNAUTHORIZED else
  if r.foreign.claimId then .refused .IDENTITY_CONFLICT else
  match findClaim i.claims c.claimId with
  | some k =>
    if k.evidenceId = c.evidenceId ∧ k.amountCents = c.amountCents ∧ k.ownerRole = c.ownerRole ∧
       k.deadlineAt = c.deadlineAt then .duplicate else .refused .IDENTITY_CONFLICT
  | none =>
    if !(r.expectedRevision.all (· = i.beforeRevision)) then .refused .REVISION_CONFLICT else
    match slotOf r.foreign.evidenceId (findEvidence i.evidence c.evidenceId) e with
    | .same _ => .refused .EVIDENCE_REUSED
    | .clash => .refused .EVIDENCE_CONFLICT
    | .fresh =>
      let w : ClaimWrites := { evidence := e, claim := claimImage i c, case := claimCaseImage i c }
      if !claimWithinCapacity r w then .refused .CAPACITY else
      let post := applyClaim i w
      match evaluate post with
      | none => .refused .POST_REJECTED
      | some result => .claimed w post result

/-! ### Codec. Request: magic ‖ u32 n ‖ BLFIN02 (n bytes) ‖ foreign flags ‖ option u64 ‖ command.
    Answer: magic ‖ tag (1 claimed, 2 duplicate, 3 refused) ‖ body. Canonical by re-encode. -/

def encodeClaimCommand (c : ClaimCommand) : Bytes :=
  encodeString c.claimId ++ encodeString c.evidenceId ++ natBE 8 c.amountCents ++
    encodeString c.ownerRole ++ natBE 8 c.deadlineAt

def readClaimCommand (b : Bytes) : Option (ClaimCommand × Bytes) := do
  let (claimId, b) ← readString b
  let (evidenceId, b) ← readString b
  let (amountCents, b) ← readNatBE 8 b
  let (ownerRole, b) ← readString b
  let (deadlineAt, b) ← readNatBE 8 b
  pure (⟨claimId, evidenceId, amountCents, ownerRole, deadlineAt⟩, b)

def encodeClaimForeign (f : ClaimForeign) : Bytes :=
  [UInt8.ofNat ((if f.claimId then 1 else 0) + (if f.evidenceId then 2 else 0))]

def readClaimForeign (b : Bytes) : Option (ClaimForeign × Bytes) := do
  let (flags, rest) ← readByte b
  if flags.toNat < 4 then some ({ claimId := flags.toNat % 2 = 1, evidenceId := flags.toNat / 2 = 1 }, rest)
  else none

def encodeClaimRequest (r : ClaimRequest) : Bytes :=
  claimMagic ++ natBE 4 r.inputBytes ++ rawEncodeFinancialInput r.input ++ encodeClaimForeign r.foreign ++
    encodeOptionNat r.expectedRevision ++ encodeClaimCommand r.command

def claimRequestWellFormed (r : ClaimRequest) : Bool :=
  financialInputWellFormed r.input && idWellFormed r.command.claimId && idWellFormed r.command.evidenceId &&
    r.command.amountCents ≤ maxCents && roleWellFormed r.command.ownerRole &&
    timeWellFormed r.command.deadlineAt && r.expectedRevision.all (· < 2 ^ 63)

def parseClaimRequest (w : Bytes) : Option ClaimRequest := do
  let (n, rest) ← readNatBE 4 (w.drop claimMagic.length)
  let input ← decodeFinancialInput (rest.take n)
  let (foreign, rest) ← readClaimForeign (rest.drop n)
  let (expectedRevision, rest) ← readOptionNat rest
  let (command, _) ← readClaimCommand rest
  pure { input, inputBytes := n, foreign, expectedRevision, command }

def decodeClaimRequest (w : Bytes) : Option ClaimRequest :=
  (parseClaimRequest w).filter fun r => claimRequestWellFormed r &&
    r.inputBytes == (rawEncodeFinancialInput r.input).length && encodeClaimRequest r == w

/-- The wire answer omits `post` (the adapter writes rows, not the input). -/
inductive ClaimAnswer where
  | claimed (writes : ClaimWrites) (result : FinancialResult)
  | duplicate
  | refused (reason : ClaimRefusal)
deriving DecidableEq, Repr

def ClaimOutcome.answer : ClaimOutcome → ClaimAnswer
  | .claimed w _ r => .claimed w r
  | .duplicate => .duplicate
  | .refused f => .refused f

def claimRefusals : List ClaimRefusal :=
  [.SHADOW_READ_ONLY, .AMOUNT_ZERO, .LOCAL_REF_FORM, .OWNER_ROLE_UNAUTHORIZED, .IDENTITY_CONFLICT,
   .REVISION_CONFLICT, .EVIDENCE_REUSED, .EVIDENCE_CONFLICT, .CAPACITY, .POST_REJECTED]

def rawEncodeClaimAnswer : ClaimAnswer → Bytes
  | .claimed w r =>
    let res := rawEncodeFinancialResult r
    claimAnswerMagic ++ [UInt8.ofNat 1] ++ encodeEvidence w.evidence ++ encodeClaim w.claim ++
      encodeOpt encodeCase w.case ++ natBE 4 res.length ++ res
  | .duplicate => claimAnswerMagic ++ [UInt8.ofNat 2]
  | .refused f => claimAnswerMagic ++ [UInt8.ofNat 3, UInt8.ofNat (claimRefusals.findIdx (· == f) + 1)]

def parseClaimAnswer (b : Bytes) : Option ClaimAnswer := do
  let (tag, b) ← readByte (b.drop claimAnswerMagic.length)
  if tag.toNat = 1 then
    let (e, b) ← decodeEvidence b
    let (k, b) ← decodeClaim b
    let (c, b) ← readOpt decodeCase b
    let (n, b) ← readNatBE 4 b
    let r ← decodeFinancialResult (b.take n)
    pure (.claimed ⟨e, k, c⟩ r)
  else if tag.toNat = 2 then pure .duplicate
  else if tag.toNat = 3 then
    let (i, _) ← readByte b
    let f ← claimRefusals[i.toNat - 1]?
    pure (.refused f)
  else none

def decodeClaimAnswer (b : Bytes) : Option ClaimAnswer :=
  (parseClaimAnswer b).filter fun a => rawEncodeClaimAnswer a == b

def encodeClaimAnswer (a : ClaimAnswer) : Option Bytes :=
  let b := rawEncodeClaimAnswer a
  if b.length ≤ maxTotalEncodedBytes ∧ decodeClaimAnswer b = some a then some b else none

def claimRespond (w : Bytes) : Bytes :=
  match decodeClaimRequest w with
  | none => [UInt8.ofNat 1]
  | some r =>
    match encodeClaimAnswer (decideClaim r).answer with
    | none => [UInt8.ofNat 3]
    | some b => UInt8.ofNat 0 :: b

end BlindLedger.Financial.Offset
