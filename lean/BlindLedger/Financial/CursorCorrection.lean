import BlindLedger.Financial.Cursor
import BlindLedger.Financial.CorrectionTransition.Codec

/-! Cursor twin of the `BLFCMD03` decoder and of the receipt readers it reaches.  Same pattern as
    `Cursor.lean`: each twin is the reference text with `bytes`/`rest` replaced by the position, and
    a `SimOf` instance proves it returns the same value and the same unread suffix.  The two
    length-prefixed sections are read as slices of the frame, so no list of the frame is built; the
    canonical re-encode stays on the list encoder and takes one `toList` at the end. -/

namespace BlindLedger.Financial.Cursor

open BlindLedger.Financial.CorrectionTransition BlindLedger.Financial.DecisionPackage

def readOptional {α : Type} (parse : Reader α) : Reader (Option α) := fun ba i => do
  let (tag, i) ← readByte ba i
  if tag.toNat = 0 then some (none, i)
  else if tag.toNat = 1 then do
    let (value, i) ← parse ba i
    pure (some value, i)
  else none

def readActionLookup : Reader ActionIdentityLookup := fun ba i => do
  let (tag, i) ← readByte ba i
  if tag.toNat = 1 then some (.absent, i)
  else if tag.toNat = 3 then some (.conflicting, i)
  else if tag.toNat = 2 then do
    let (actionId, i) ← readString ba i
    let (actionObligationId, i) ← readString ba i
    let (determinationId, i) ← readString ba i
    let (determinationObligationId, i) ← readString ba i
    let (actionKind, i) ← readString ba i
    let (claimId, i) ← readString ba i
    let (actorId, i) ← readString ba i
    let (actorRole, i) ← readString ba i
    let (authorityId, i) ← readString ba i
    let (authorityEpoch, i) ← readNatBE 8 ba i
    let (authorityDigest, i) ← readDigest ba i
    let (decisionByte, i) ← readByte ba i
    let decision ← decodeDecision decisionByte
    let (inputEvaluationId, i) ← readString ba i
    let (inputEvaluationResultDigest, i) ← readDigest ba i
    let (expectedRevision, i) ← readNatBE 8 ba i
    let (decidedAtMs, i) ← readNatBE 8 ba i
    let identity : ExistingCorrectionIdentity := {
      actionId := actionId
      actionObligationId := actionObligationId
      determinationId := determinationId
      determinationObligationId := determinationObligationId
      actionKind := actionKind
      claimId := claimId
      actorId := actorId
      actorRole := actorRole
      authorityId := authorityId
      authorityEpoch := authorityEpoch
      authorityDigest := authorityDigest
      decision := decision
      inputEvaluationId := inputEvaluationId
      inputEvaluationResultDigest := inputEvaluationResultDigest
      expectedRevision := expectedRevision
      decidedAtMs := decidedAtMs }
    pure (.existing identity, i)
  else none

def readQueryPredicate : Reader CorrectionQueryPredicate := fun ba i => do
  let (tag, i) ← readByte ba i
  match tag.toNat with
  | 1 => some (.ACTION_ID, i)
  | 2 => some (.DETERMINATION_ID, i)
  | 3 => some (.EVALUATION_CONSUMED, i)
  | _ => none

def readQueryObservation : Reader CorrectionQueryObservation := fun ba i => do
  let (predicate, i) ← readQueryPredicate ba i
  let (subject, i) ← readString ba i
  let (complete, i) ← readBool ba i
  let (matchCount, i) ← readNatBE 8 ba i
  let (resultIdentity, i) ← readOptionString ba i
  let (versionSequence, i) ← readNatBE 8 ba i
  let (versionHead, i) ← readDigest ba i
  let observation : CorrectionQueryObservation := {
    predicate := predicate
    subject := subject
    complete := complete
    matchCount := matchCount
    resultIdentity := resultIdentity
    versionSequence := versionSequence
    versionHead := versionHead }
  if !correctionQueryObservationWellFormed observation then none
  else some (observation, i)

def readQueryObservations : Reader CorrectionQueryObservations := fun ba i => do
  let (actionId, i) ← readQueryObservation ba i
  let (determinationId, i) ← readQueryObservation ba i
  let (evaluationConsumed, i) ← readQueryObservation ba i
  pure ({
    actionId := actionId
    determinationId := determinationId
    evaluationConsumed := evaluationConsumed }, i)

def readPaymentLink : Reader PaymentLink := fun ba i => do
  let (paymentId, i) ← readString ba i
  let (actionId, i) ← readString ba i
  pure ({ paymentId := paymentId, actionId := actionId }, i)

def readPackageScope : Reader PackageScope := fun ba i => do
  let (stateId, i) ← readString ba i
  let (deploymentId, i) ← readString ba i
  let (programId, i) ← readString ba i
  let (periodId, i) ← readString ba i
  let (currency, i) ← readString ba i
  pure ({
    stateId := stateId
    deploymentId := deploymentId
    programId := programId
    periodId := periodId
    currency := currency }, i)

def readReceiptControlPack : Reader ReceiptControlPack := fun ba i => do
  let (packId, i) ← readString ba i
  let (version, i) ← readNatBE 8 ba i
  let (digest, i) ← readDigest ba i
  pure ({
    packId := packId
    version := version
    digest := digest }, i)

def readReceiptAuthority : Reader ReceiptAuthority := fun ba i => do
  let (authorityEpoch, i) ← readNatBE 8 ba i
  let (authorityDigest, i) ← readDigest ba i
  pure ({
    authorityEpoch := authorityEpoch
    authorityDigest := authorityDigest }, i)

def readEvidenceBinding : Reader EvidenceBinding := fun ba i => do
  let (evidenceId, i) ← readString ba i
  let (recordDigest, i) ← readDigest ba i
  pure ({
    evidenceId := evidenceId
    recordDigest := recordDigest }, i)

def readOwnerEvaluationResult : Reader OwnerEvaluationResult := fun ba i => do
  let (evaluationId, i) ← readString ba i
  let (obligationId, i) ← readString ba i
  let (revision, i) ← readNatBE 8 ba i
  let (ruleVersion, i) ← readNatBE 8 ba i
  let (evidenceIds, i) ← readList readString ba i
  let (authorityId, i) ← readString ba i
  let (evaluatedAtMs, i) ← readNatBE 8 ba i
  let (owedCents, i) ← readNatBE 8 ba i
  let (claimedAdjustmentCents, i) ← readNatBE 8 ba i
  let (lawfulAdjustmentCents, i) ← readNatBE 8 ba i
  let (receivedCashCents, i) ← readNatBE 8 ba i
  let (shortfallCents, i) ← readNatBE 8 ba i
  let (overageCents, i) ← readNatBE 8 ba i
  let (cashSatisfied, i) ← readBool ba i
  let (amountSatisfied, i) ← readBool ba i
  let (timely, i) ← readBool ba i
  let (reportingComplete, i) ← readBool ba i
  let (verificationStatus, i) ← readString ba i
  let (caseStatus, i) ← readString ba i
  let (deliveryStatus, i) ← readString ba i
  pure ({
    evaluationId := evaluationId
    obligationId := obligationId
    revision := revision
    ruleVersion := ruleVersion
    evidenceIds := evidenceIds
    authorityId := authorityId
    evaluatedAtMs := evaluatedAtMs
    owedCents := owedCents
    claimedAdjustmentCents := claimedAdjustmentCents
    lawfulAdjustmentCents := lawfulAdjustmentCents
    receivedCashCents := receivedCashCents
    shortfallCents := shortfallCents
    overageCents := overageCents
    cashSatisfied := cashSatisfied
    amountSatisfied := amountSatisfied
    timely := timely
    reportingComplete := reportingComplete
    verificationStatus := verificationStatus
    caseStatus := caseStatus
    deliveryStatus := deliveryStatus }, i)

def readEvaluationReceipt : Reader EvaluationReceipt := fun ba i => do
  let (contractVersion, i) ← readString ba i
  let (scope, i) ← readPackageScope ba i
  let (controlPack, i) ← readReceiptControlPack ba i
  let (evidenceBindings, i) ← readList readEvidenceBinding ba i
  let (inputSnapshotDigest, i) ← readOptional readDigest ba i
  let (authority, i) ← readReceiptAuthority ba i
  let (result, i) ← readOwnerEvaluationResult ba i
  let (resultDigest, i) ← readDigest ba i
  let (receiptDigest, i) ← readDigest ba i
  let (evaluationResultDigest, i) ← readDigest ba i
  pure ({
    contractVersion := contractVersion
    scope := scope
    controlPack := controlPack
    evidenceBindings := evidenceBindings
    inputSnapshotDigest := inputSnapshotDigest
    authority := authority
    result := result
    resultDigest := resultDigest
    receiptDigest := receiptDigest
    evaluationResultDigest := evaluationResultDigest }, i)

theorem sim_readOptional {α : Type} {p : Reader α} {P : Bytes → Option (α × Bytes)} [SimOf p P] :
    Sim (readOptional p) (DecisionPackage.readOptional P) := by
  have e : ∀ bs, DecisionPackage.readOptional P bs = (do
      let (tag, rest) ← Financial.readByte bs
      if tag.toNat = 0 then some (none, rest)
      else if tag.toNat = 1 then do
        let (value, rest) ← P rest
        pure (some value, rest)
      else none) := fun bs => by cases bs <;> rfl
  have hs : Sim (readOptional p) (fun bs => do
      let (tag, rest) ← Financial.readByte bs
      if tag.toNat = 0 then some (none, rest)
      else if tag.toNat = 1 then do
        let (value, rest) ← P rest
        pure (some value, rest)
      else none) := by unfold readOptional; sim_steps
  intro ba i hi
  simp only [e]
  exact hs ba i hi

instance {α : Type} {p : Reader α} {P : Bytes → Option (α × Bytes)} [SimOf p P] :
    SimOf (readOptional p) (DecisionPackage.readOptional P) := ⟨sim_readOptional⟩

theorem sim_readSizedBytes (maximum : Nat) : SimM ByteArray.toList (readSized maximum) (readSizedBytes maximum) :=
  sim_readSized maximum _ fun _ => rfl

instance : SimOf readActionLookup CorrectionTransition.readActionLookup := ⟨by unfold readActionLookup CorrectionTransition.readActionLookup; sim_steps⟩
instance : SimOf readQueryPredicate CorrectionTransition.readQueryPredicate := ⟨by
  unfold readQueryPredicate CorrectionTransition.readQueryPredicate
  refine Sim.bind SimOf.sim fun b => ?_
  intro ba j hj
  rcases hb : b.toNat with _ | _ | _ | _ | n <;> simp [hb, hj]⟩
instance : SimOf readQueryObservation CorrectionTransition.readQueryObservation := ⟨by unfold readQueryObservation CorrectionTransition.readQueryObservation; sim_steps⟩
instance : SimOf readQueryObservations CorrectionTransition.readQueryObservations := ⟨by unfold readQueryObservations CorrectionTransition.readQueryObservations; sim_steps⟩
instance : SimOf readPaymentLink CorrectionTransition.readPaymentLink := ⟨by unfold readPaymentLink CorrectionTransition.readPaymentLink; sim_steps⟩
instance : SimOf readPackageScope DecisionPackage.readPackageScope := ⟨by unfold readPackageScope DecisionPackage.readPackageScope; sim_steps⟩
instance : SimOf readReceiptControlPack DecisionPackage.readReceiptControlPack := ⟨by unfold readReceiptControlPack DecisionPackage.readReceiptControlPack; sim_steps⟩
instance : SimOf readReceiptAuthority DecisionPackage.readReceiptAuthority := ⟨by unfold readReceiptAuthority DecisionPackage.readReceiptAuthority; sim_steps⟩
instance : SimOf readEvidenceBinding DecisionPackage.readEvidenceBinding := ⟨by unfold readEvidenceBinding DecisionPackage.readEvidenceBinding; sim_steps⟩
instance : SimOf readOwnerEvaluationResult DecisionPackage.readOwnerEvaluationResult := ⟨by unfold readOwnerEvaluationResult DecisionPackage.readOwnerEvaluationResult; sim_steps⟩
instance : SimOf readEvaluationReceipt DecisionPackage.readEvaluationReceipt := ⟨by unfold readEvaluationReceipt DecisionPackage.readEvaluationReceipt; sim_steps⟩

/-- Reads one `BLFCMD03` request from the start of the frame and returns the position after it. -/
def parseCorrectionTransitionRequest (ba : ByteArray) :
    Option (CorrectionTransitionRequest × Nat) := do
  let i ← readMagic correctionTransitionInputMagic ba 0
  let (version, i) ← readNatBE 2 ba i
  if version ≠ 3 then none
  let (contract, i) ← readString ba i
  if contract ≠ correctionTransitionContract then none
  let (itemId, i) ← readString ba i
  let (claimId, i) ← readString ba i
  let (actionId, i) ← readString ba i
  let (actorId, i) ← readString ba i
  let (actorRole, i) ← readString ba i
  let (currentAuthorityId, i) ← readString ba i
  let (currentAuthorityEpoch, i) ← readNatBE 8 ba i
  let (currentAuthorityDigest, i) ← readDigest ba i
  let (expectedRevision, i) ← readNatBE 8 ba i
  let (evaluationId, i) ← readString ba i
  let (evaluationResultDigest, i) ← readDigest ba i
  let (decisionAtMs, i) ← readNatBE 8 ba i
  let (ownerNowMs, i) ← readNatBE 8 ba i
  let (actionLookup, i) ← readActionLookup ba i
  let (queryObservations, i) ← readQueryObservations ba i
  let (currentEventSequence, i) ← readNatBE 8 ba i
  let (previousHistoryHead, i) ← readDigest ba i
  let (paymentLinks, i) ← readList readPaymentLink ba i
  let (inputBytes, i) ← readSized maxCorrectionTransitionBytes ba i
  let (receiptBytes, i) ← readSized maxCorrectionTransitionBytes ba i
  let currentInput ← decodeFinancialInput inputBytes
  let (currentReceipt, receiptEnd) ← readEvaluationReceipt receiptBytes 0
  if receiptEnd ≠ receiptBytes.size then none
  let request : CorrectionTransitionRequest := {
    command := {
      itemId := itemId
      claimId := claimId
      actionId := actionId
      actorId := actorId
      actorRole := actorRole
      currentAuthorityId := currentAuthorityId
      currentAuthorityEpoch := currentAuthorityEpoch
      currentAuthorityDigest := currentAuthorityDigest
      expectedRevision := expectedRevision
      evaluationId := evaluationId
      evaluationResultDigest := evaluationResultDigest
      decisionAtMs := decisionAtMs
      ownerNowMs := ownerNowMs
      actionLookup := actionLookup
      queryObservations := queryObservations
      currentEventSequence := currentEventSequence
      previousHistoryHead := previousHistoryHead
      paymentLinks := paymentLinks }
    currentInput := currentInput
    currentReceipt := currentReceipt }
  pure (request, i)

/-- The reference decoder over the array: the whole frame is one request, and it is canonical. -/
def decodeCorrectionTransitionRequest (ba : ByteArray) : Option CorrectionTransitionRequest :=
  if ba.size > maxCorrectionTransitionBytes then none else
  (parseCorrectionTransitionRequest ba).bind fun (request, i) =>
    if i = ba.size ∧ encodeCorrectionTransitionRequest request = some ba.toList then some request
    else none

macro "sim_chain2" : tactic => `(tactic| repeat (first
  | refine Sim.bind0 SimOf.sim (by assumption) fun _ _ _ => ?_
  | refine Sim.bind0 SimOf.sim (Nat.zero_le _) fun _ _ _ => ?_
  | refine SimM.bind0 (sim_readSizedBytes _) (by assumption) fun _ _ _ => ?_
  | refine bindEq (decodeFinancialInput_eq _) fun _ => ?_
  | refine ite_none Iff.rfl fun _ => ?_
  | refine ite_none (end_iff (by assumption)) fun _ => ?_))

theorem parse_eq {γ : Type} (ba : ByteArray) {f : CorrectionTransitionRequest × Nat → Option γ}
    {F : CorrectionTransitionRequest × Bytes → Option γ}
    (hF : ∀ r j, j ≤ ba.size → f (r, j) = F (r, ba.toList.drop j)) :
    (parseCorrectionTransitionRequest ba).bind f =
      (CorrectionTransition.parseCorrectionTransitionRequest ba.toList).bind F := by
  unfold parseCorrectionTransitionRequest CorrectionTransition.parseCorrectionTransitionRequest
  cases hm : correctionTransitionInputMagic.isPrefixOf ba.toList
  · rw [readMagic_of_not_prefix hm]; simp
  · obtain ⟨h1, h2⟩ := readMagic_of_prefix (i := 0) (Nat.zero_le _) hm
    rw [Nat.zero_add] at h2
    simp only [h1, Nat.zero_add, Bool.not_true, Bool.false_eq_true, ↓reduceIte,
      Option.bind_eq_bind, Option.bind_assoc, Option.bind_some, Option.bind_none, ite_none_bind, Option.pure_def]
    sim_chain2
    exact hF _ _ (by assumption)

theorem decodeCorrectionTransitionRequest_eq (ba : ByteArray) :
    decodeCorrectionTransitionRequest ba =
      CorrectionTransition.decodeCorrectionTransitionRequest ba.toList := by
  unfold decodeCorrectionTransitionRequest CorrectionTransition.decodeCorrectionTransitionRequest
  rw [Fast.length_toList]
  by_cases hs : ba.size > maxCorrectionTransitionBytes
  · simp [hs]
  · simp only [hs, if_false]
    rw [parse_eq ba (F := fun p => match p.2 with
      | [] => if encodeCorrectionTransitionRequest p.1 = some ba.toList then some p.1 else none
      | _ => none) ?_]
    · rcases hp : CorrectionTransition.parseCorrectionTransitionRequest ba.toList with
        _ | ⟨r, _ | ⟨b, rest⟩⟩ <;> rfl
    · intro r j hj
      by_cases he : j = ba.size
      · subst he
        simp [drop_nil (Nat.le_refl _)]
      · rcases hd : ba.toList.drop j with _ | ⟨b, rest⟩
        · have := drop_length ba j
          rw [hd] at this
          simp at this
          omega
        · simp [he]

end BlindLedger.Financial.Cursor
