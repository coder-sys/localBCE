import BlindLedger.Financial.FastDecode

/-! Accumulator twin of the `BLFIN02` encoder and the decoder that uses it.  The reference
    encoder builds a `List UInt8` with left-nested `++`, which copies the growing prefix at every
    field.  Each `xPush` below appends to a `ByteArray`; its `_eq` theorem states `xPush x acc`
    is `acc` followed by the reference bytes of `x`, so `rawEncodeFinancialInputBA_eq` proves the
    whole twin equal to `rawEncodeFinancialInput`.  `decodeFinancialInputBA₂` then parses once,
    checks well-formedness once, and compares that encoding to the frame with one `memcmp`. -/

namespace BlindLedger.Financial.Fast

def natBEPush : Nat → Nat → ByteArray → ByteArray
  | 0, _, acc => acc
  | width + 1, value, acc => (natBEPush width (value / 256) acc).push (UInt8.ofNat (value % 256))

def stringPush (value : String) (acc : ByteArray) : ByteArray :=
  let raw := value.toUTF8
  natBEPush 2 raw.size acc ++ raw

def boolPush (value : Bool) (acc : ByteArray) : ByteArray :=
  acc.push (if value then UInt8.ofNat 1 else UInt8.ofNat 0)

def optionNatPush : Option Nat → ByteArray → ByteArray
  | none, acc => acc.push (UInt8.ofNat 0)
  | some value, acc => natBEPush 8 value (acc.push (UInt8.ofNat 1))

def optionStringPush : Option String → ByteArray → ByteArray
  | none, acc => acc.push (UInt8.ofNat 0)
  | some value, acc => stringPush value (acc.push (UInt8.ofNat 1))

def listPush (push : α → ByteArray → ByteArray) (values : List α) (acc : ByteArray) : ByteArray :=
  values.foldl (fun bytes value => push value bytes) (natBEPush 2 values.length acc)

def contextPush (c : FinancialContext) (acc : ByteArray) : ByteArray :=
  acc |> stringPush c.ownerId |>.push (encodeMode c.mode) |>.push (encodeProvenance c.provenance)
    |> stringPush c.stateId |> stringPush c.deploymentId |> stringPush c.programId
    |> stringPush c.periodId |> stringPush c.populationId |> stringPush c.itemId
    |> stringPush c.obligationId |> stringPush c.currency

def authorityActorPush (a : AuthorityActor) (acc : ByteArray) : ByteArray :=
  acc |> stringPush a.actorId |> listPush stringPush a.roles

def authorityPush (a : TrustedAuthority) (acc : ByteArray) : ByteArray :=
  acc |> stringPush a.authorityId |> natBEPush 8 a.epoch |> (· ++ a.digest.toByteArray)
    |> boolPush a.syntheticOnly |> listPush authorityActorPush a.actors

def controlPackPush (p : ControlPack) (acc : ByteArray) : ByteArray :=
  acc |> stringPush p.packId |> stringPush p.stateId |> stringPush p.deploymentId
    |> stringPush p.programId |> stringPush p.periodId |> stringPush p.currency
    |> natBEPush 8 p.version |> listPush stringPush p.sourceRefs
    |> natBEPush 8 p.effectiveStart |> natBEPush 8 p.effectiveEnd
    |> natBEPush 8 p.recordedAt |> natBEPush 8 p.approvedAt
    |> stringPush p.calculationRuleId |> stringPush p.adjustmentRuleId
    |> listPush stringPush p.authorizedRoles |> listPush stringPush p.expectedTests
    |> (· ++ p.digest.toByteArray) |>.push (encodePackStatus p.status)

def obligationPush (o : Obligation) (acc : ByteArray) : ByteArray :=
  acc |> stringPush o.populationId |> stringPush o.itemId |> stringPush o.obligationId
    |> natBEPush 8 o.owedCents |> natBEPush 8 o.dueAt |> natBEPush 8 o.ruleVersion
    |> boolPush o.reportingComplete

def paymentPush (p : Payment) (acc : ByteArray) : ByteArray :=
  acc |> stringPush p.paymentId |> stringPush p.obligationId |> stringPush p.itemId
    |> stringPush p.evidenceId |> stringPush p.commonOriginId |> natBEPush 8 p.amountCents
    |> natBEPush 8 p.eventAt |> optionStringPush p.reversalEvidenceId
    |>.push (encodePaymentStatus p.status)

def claimPush (c : Claim) (acc : ByteArray) : ByteArray :=
  acc |> stringPush c.claimId |> stringPush c.obligationId |> stringPush c.evidenceId
    |> natBEPush 8 c.amountCents |> stringPush c.ownerRole |> natBEPush 8 c.deadlineAt
    |>.push (encodeClaimStatus c.status)

def determinationPush (d : OffsetDetermination) (acc : ByteArray) : ByteArray :=
  acc |> stringPush d.determinationId |> stringPush d.obligationId |> stringPush d.claimId
    |> stringPush d.actorId |> stringPush d.actorRole |> stringPush d.authorityId
    |> natBEPush 8 d.authorityEpoch |> (· ++ d.authorityDigest.toByteArray)
    |>.push (encodeDecision d.decision) |> natBEPush 8 d.amountCents
    |> listPush stringPush d.supportingEvidenceIds |> natBEPush 8 d.expectedRevision
    |> natBEPush 8 d.resultingRevision |> natBEPush 8 d.decidedAt

def evidencePush (e : EvidenceRecord) (acc : ByteArray) : ByteArray :=
  acc |> stringPush e.evidenceId |> stringPush e.obligationId |> stringPush e.itemId
    |> stringPush e.kind |> stringPush e.commonOriginId |> stringPush e.sourceId
    |> stringPush e.sourceVersion |> stringPush e.localRef |> natBEPush 8 e.applicableAt
    |> natBEPush 8 e.eventAt |> natBEPush 8 e.receivedAt |> optionNatPush e.amountCents
    |> optionStringPush e.reversalOf |> optionStringPush e.supersedes

def conflictPush (c : FinancialConflict) (acc : ByteArray) : ByteArray :=
  acc |> stringPush c.conflictId |> stringPush c.obligationId |> stringPush c.commonOriginId
    |> stringPush c.existingPaymentId |> stringPush c.candidateEvidenceId
    |> natBEPush 8 c.existingAmountCents |> natBEPush 8 c.candidateAmountCents
    |> stringPush c.reason |> natBEPush 8 c.visibleAt

def casePush (c : CaseRecord) (acc : ByteArray) : ByteArray :=
  acc |> stringPush c.caseId |> stringPush c.obligationId |> stringPush c.reason
    |> stringPush c.nextActionOwner |> natBEPush 8 c.dueAt
    |>.push (encodeCaseStatus c.status) |> natBEPush 8 c.updatedAt

def actionPush (a : ActionRecord) (acc : ByteArray) : ByteArray :=
  acc |> stringPush a.actionId |> stringPush a.obligationId |> optionStringPush a.determinationId
    |> stringPush a.kind |> natBEPush 8 a.amountCents |> stringPush a.currency
    |> natBEPush 8 a.revision |>.push (encodeActionStatus a.status)
    |> (· ++ a.payloadDigest.toByteArray) |> natBEPush 8 a.createdAt

def rawEncodeFinancialInputBA (input : FinancialInput) : ByteArray :=
  financialCodecMagic.toByteArray |> contextPush input.context |> authorityPush input.authority
    |> controlPackPush input.pack |> obligationPush input.obligation
    |> natBEPush 8 input.beforeRevision |> natBEPush 8 input.evaluatedAt
    |> listPush paymentPush input.payments |> listPush claimPush input.claims
    |> listPush determinationPush input.determinations |> listPush evidencePush input.evidence
    |> listPush conflictPush input.conflicts |> listPush casePush input.cases
    |> listPush actionPush input.actions

theorem toByteArray_toList (ba : ByteArray) : ba.toList.toByteArray = ba := by
  ext1; simp [toList_eq]

theorem length_toList (ba : ByteArray) : ba.toList.length = ba.size := by
  rw [toList_eq, Array.length_toList, ByteArray.size_data]

private theorem toByteArray_pair (a b : UInt8) :
    ([a, b] : List UInt8).toByteArray = [a].toByteArray ++ [b].toByteArray := by
  rw [← List.toByteArray_append]; rfl

private theorem toByteArray_cons (a : UInt8) (l : List UInt8) :
    (a :: l).toByteArray = [a].toByteArray ++ l.toByteArray := by
  rw [← List.toByteArray_append]; rfl

theorem natBEPush_eq (width value : Nat) (acc : ByteArray) :
    natBEPush width value acc = acc ++ (natBE width value).toByteArray := by
  induction width generalizing value with
  | zero => simp [natBEPush, natBE]
  | succ width ih =>
    simp only [natBEPush, natBE, ih, List.toByteArray_append, ← ByteArray.append_toByteArray_singleton,
      ByteArray.append_assoc]

theorem stringPush_eq (value : String) (acc : ByteArray) :
    stringPush value acc = acc ++ (encodeString value).toByteArray := by
  simp only [stringPush, encodeString, natBEPush_eq, List.toByteArray_append, toByteArray_toList,
    length_toList, ByteArray.append_assoc]

theorem boolPush_eq (value : Bool) (acc : ByteArray) :
    boolPush value acc = acc ++ (encodeBool value).toByteArray := by
  simp [boolPush, encodeBool]

theorem optionNatPush_eq (value : Option Nat) (acc : ByteArray) :
    optionNatPush value acc = acc ++ (encodeOptionNat value).toByteArray := by
  cases value with
  | none => simp [optionNatPush, encodeOptionNat]
  | some value =>
    simp only [optionNatPush, encodeOptionNat, natBEPush_eq]
    rw [toByteArray_cons, ← ByteArray.append_assoc, ByteArray.append_toByteArray_singleton]

theorem optionStringPush_eq (value : Option String) (acc : ByteArray) :
    optionStringPush value acc = acc ++ (encodeOptionString value).toByteArray := by
  cases value with
  | none => simp [optionStringPush, encodeOptionString]
  | some value =>
    simp only [optionStringPush, encodeOptionString, stringPush_eq]
    rw [toByteArray_cons, ← ByteArray.append_assoc, ByteArray.append_toByteArray_singleton]

theorem listPush_eq {push : α → ByteArray → ByteArray} {encode : α → Bytes}
    (h : ∀ value acc, push value acc = acc ++ (encode value).toByteArray)
    (values : List α) (acc : ByteArray) :
    listPush push values acc = acc ++ (encodeList encode values).toByteArray := by
  have key : ∀ (vs : List α) (a : ByteArray),
      vs.foldl (fun bytes value => push value bytes) a = a ++ (vs.flatMap encode).toByteArray := by
    intro vs
    induction vs with
    | nil => intro a; simp
    | cons v vs ih =>
      intro a
      rw [List.foldl_cons, h, ih, List.flatMap_cons, List.toByteArray_append, ByteArray.append_assoc]
  simp only [listPush, encodeList, key, natBEPush_eq, List.toByteArray_append, ByteArray.append_assoc]

local macro "push_eq " "[" ids:Lean.Parser.Tactic.simpLemma,* "]" : tactic =>
  `(tactic| simp only [$ids,*, stringPush_eq, natBEPush_eq, boolPush_eq, optionNatPush_eq,
    optionStringPush_eq, listPush_eq stringPush_eq, toByteArray_pair, List.toByteArray_append,
    ← ByteArray.append_toByteArray_singleton, ByteArray.append_assoc])

theorem contextPush_eq (c : FinancialContext) (acc : ByteArray) :
    contextPush c acc = acc ++ (encodeContext c).toByteArray := by
  push_eq [contextPush, encodeContext]

theorem authorityActorPush_eq (a : AuthorityActor) (acc : ByteArray) :
    authorityActorPush a acc = acc ++ (encodeAuthorityActor a).toByteArray := by
  push_eq [authorityActorPush, encodeAuthorityActor]

theorem authorityPush_eq (a : TrustedAuthority) (acc : ByteArray) :
    authorityPush a acc = acc ++ (encodeAuthority a).toByteArray := by
  push_eq [authorityPush, encodeAuthority, encodeDigest, listPush_eq authorityActorPush_eq]

theorem controlPackPush_eq (p : ControlPack) (acc : ByteArray) :
    controlPackPush p acc = acc ++ (encodeControlPack p).toByteArray := by
  push_eq [controlPackPush, encodeControlPack, encodeDigest]

theorem obligationPush_eq (o : Obligation) (acc : ByteArray) :
    obligationPush o acc = acc ++ (encodeObligation o).toByteArray := by
  push_eq [obligationPush, encodeObligation]

theorem paymentPush_eq (p : Payment) (acc : ByteArray) :
    paymentPush p acc = acc ++ (encodePayment p).toByteArray := by
  push_eq [paymentPush, encodePayment]

theorem claimPush_eq (c : Claim) (acc : ByteArray) :
    claimPush c acc = acc ++ (encodeClaim c).toByteArray := by
  push_eq [claimPush, encodeClaim]

theorem determinationPush_eq (d : OffsetDetermination) (acc : ByteArray) :
    determinationPush d acc = acc ++ (encodeDetermination d).toByteArray := by
  push_eq [determinationPush, encodeDetermination, encodeDigest]

theorem evidencePush_eq (e : EvidenceRecord) (acc : ByteArray) :
    evidencePush e acc = acc ++ (encodeEvidence e).toByteArray := by
  push_eq [evidencePush, encodeEvidence]

theorem conflictPush_eq (c : FinancialConflict) (acc : ByteArray) :
    conflictPush c acc = acc ++ (encodeConflict c).toByteArray := by
  push_eq [conflictPush, encodeConflict]

theorem casePush_eq (c : CaseRecord) (acc : ByteArray) :
    casePush c acc = acc ++ (encodeCase c).toByteArray := by
  push_eq [casePush, encodeCase]

theorem actionPush_eq (a : ActionRecord) (acc : ByteArray) :
    actionPush a acc = acc ++ (encodeAction a).toByteArray := by
  push_eq [actionPush, encodeAction, encodeDigest]

theorem rawEncodeFinancialInputBA_eq (input : FinancialInput) :
    rawEncodeFinancialInputBA input = (rawEncodeFinancialInput input).toByteArray := by
  simp only [rawEncodeFinancialInputBA, rawEncodeFinancialInput, contextPush_eq, authorityPush_eq,
    controlPackPush_eq, obligationPush_eq, natBEPush_eq, listPush_eq paymentPush_eq,
    listPush_eq claimPush_eq, listPush_eq determinationPush_eq, listPush_eq evidencePush_eq,
    listPush_eq conflictPush_eq, listPush_eq casePush_eq, listPush_eq actionPush_eq,
    List.toByteArray_append, ByteArray.append_assoc]

theorem beq_iff (a b : ByteArray) : (a == b) = true ↔ a = b :=
  (beq_iff_eq (a := a.data) (b := b.data)).trans ByteArray.ext_iff.symm

theorem toByteArray_eq_iff (l : List UInt8) (ba : ByteArray) : l.toByteArray = ba ↔ l = ba.toList := by
  constructor
  · rintro rfl; simp [toList_eq]
  · intro h; rw [h]; exact toByteArray_toList ba

/-- One parse, one well-formedness pass, then one `memcmp` of the rebuilt encoding against the frame.
    The size test is the reference's length bound; a rebuilt encoding equal to the frame is within it. -/
def decodeFinancialInputBA₂ (ba : ByteArray) : Option FinancialInput :=
  if ba.size > maxTotalEncodedBytes then none else
    parseInputWith (fun input =>
      if financialInputWellFormed input && rawEncodeFinancialInputBA input == ba then some input
      else none) ba.toList

theorem decodeFinancialInputBA₂_eq (ba : ByteArray) :
    decodeFinancialInputBA₂ ba = decodeFinancialInput ba.toList := by
  unfold decodeFinancialInputBA₂ decodeFinancialInput decodeInputWith
  rw [length_toList]
  by_cases h : ba.size > maxTotalEncodedBytes
  · simp only [h, if_true]
  · simp only [h, if_false]
    congr 1
    funext input
    by_cases hw : financialInputWellFormed input = true
    · have hb : (rawEncodeFinancialInputBA input == ba) = decide (rawEncodeFinancialInput input = ba.toList) := by
        rw [rawEncodeFinancialInputBA_eq]; exact Bool.eq_iff_iff.2 (by rw [beq_iff, decide_eq_true_eq]; exact toByteArray_eq_iff _ _)
      simp only [hw, Bool.true_and, hb, encodeFinancialInput, if_true, decide_eq_true_eq]
      by_cases hl : (rawEncodeFinancialInput input).length ≤ maxTotalEncodedBytes
      · simp [hl]
      · have hne : rawEncodeFinancialInput input ≠ ba.toList := fun e => hl (by rw [e, length_toList]; omega)
        simp [hl, hne]
    · simp [hw]

theorem parseInputWith_some {finish : FinancialInput → Option FinancialInput} {bytes : Bytes}
    {output : FinancialInput} (h : parseInputWith finish bytes = some output) :
    ∃ input, finish input = some output := by
  unfold parseInputWith at h
  simp only [Option.bind_eq_bind, Option.bind_eq_some_iff] at h
  repeat' (rcases h with ⟨_, -, h⟩)
  split at h
  · exact ⟨_, h⟩
  · simp at h

end BlindLedger.Financial.Fast
