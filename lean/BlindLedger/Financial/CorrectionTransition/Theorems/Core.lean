import BlindLedger.Financial.CodecLaws.Correction
import BlindLedger.Financial.CorrectionTransition.PaidSumTheorems
import BlindLedger.Financial.Theorems.Conservation

/-! core-theorems-v1 §4.3: a correction moves no money (T2), its open requests stay within the
    balance it leaves (T1.1), and its actor and authority were checked (A1, A1'). -/

namespace BlindLedger.Financial.CorrectionTransition

open BlindLedger.Financial BlindLedger.Financial.DecisionPackage

private theorem linkedOutstandingCents_eq_sum (payments : List Payment) (links : List PaymentLink) :
    ∀ l : List ActionRecord, linkedOutstandingCents payments links l =
      (l.map fun a => if a.kind = "CORRECTION_PAYMENT_REQUEST" ∧ a.status ≠ .CANCELLED then
        a.amountCents - linkedActivePaidCents payments links a.actionId else 0).sum
  | [] => rfl
  | a :: r => by
      simp only [linkedOutstandingCents, List.map_cons, List.sum_cons,
        linkedOutstandingCents_eq_sum payments links r]

theorem linkedOutstandingCents_perm (payments : List Payment) (links : List PaymentLink)
    {l l' : List ActionRecord} (h : l.Perm l') :
    linkedOutstandingCents payments links l = linkedOutstandingCents payments links l' := by
  rw [linkedOutstandingCents_eq_sum, linkedOutstandingCents_eq_sum]
  exact (h.map _).sum_nat

/-- T2: a correction moves no money. -/
theorem applyCorrectionTransition_money_unchanged (request : CorrectionTransitionRequest)
    (mutation : CorrectionMutation)
    (hMutation : (applyCorrectionTransition request).mutation = some mutation) :
    ∃ before, evaluate request.currentInput = some before ∧
      evaluate mutation.resultingInput = some mutation.resultingResult ∧
      mutation.resultingResult.owedCents = before.owedCents ∧
      mutation.resultingResult.receivedCashCents = before.receivedCashCents ∧
      mutation.resultingResult.lawfulAdjustmentCents = before.lawfulAdjustmentCents ∧
      mutation.resultingResult.shortfallCents = before.shortfallCents ∧
      mutation.resultingResult.overageCents = before.overageCents ∧
      mutation.resultingResult.cashSatisfied = before.cashSatisfied ∧
      mutation.resultingResult.amountSatisfied = before.amountSatisfied ∧
      mutation.resultingResult.completionAt = before.completionAt ∧
      mutation.resultingResult.timely = before.timely := by
  have hL := (applyCorrectionTransition_mutation_links request mutation hMutation).2.2.2.2.2.2
  obtain ⟨before, hBefore, -, -⟩ := hL.inputShortfall
  refine ⟨before, hBefore, hL.resultingEvaluates, ?_⟩
  obtain ⟨hWf0, cash0, claimed0, lawful0, hp0, -, hl0, -, hr0⟩ := evaluate_facts hBefore
  obtain ⟨hWf1, cash1, claimed1, lawful1, hp1, -, hl1, -, hr1⟩ :=
    evaluate_facts hL.resultingEvaluates
  obtain ⟨-, -, -, hObl, hPay, -, -⟩ := hL.resultingFrame
  have hCash : cash1 = cash0 := by
    rw [hPay, hp0] at hp1
    exact (Option.some.inj hp1).symm
  have hLawful : lawful1 = lawful0 := by
    rw [← (evalLawfulSum_active _ _ hl1).1, ← (evalLawfulSum_active _ _ hl0).1, ← offset_sum hWf1,
      ← offset_sum hWf0, hL.authorizedDeterminations]
  subst hCash hLawful
  have hc : evalContributions mutation.resultingInput = evalContributions request.currentInput :=
    evalContributions_congr hPay hL.authorizedDeterminations
  have hComp : evalCompletion mutation.resultingInput = evalCompletion request.currentInput := by
    simp only [evalCompletion, hc, hObl, hPay, hl1, hl0]
  subst hr0
  simp only [hr1, evaluateResult, hObl, hComp, and_self]

/-- T1.1: after a correction, open requests are within the balance the correction leaves. -/
theorem applyCorrectionTransition_post_within_shortfall (request : CorrectionTransitionRequest)
    (mutation : CorrectionMutation)
    (hMutation : (applyCorrectionTransition request).mutation = some mutation) :
    evaluate mutation.resultingInput = some mutation.resultingResult ∧
      linkedOutstandingCents mutation.resultingInput.payments request.command.paymentLinks
          mutation.resultingInput.actions ≤ mutation.resultingResult.shortfallCents := by
  have hL := (applyCorrectionTransition_mutation_links request mutation hMutation).2.2.2.2.2.2
  obtain ⟨before, hBefore, -, -, -, -, hShort, -⟩ :=
    applyCorrectionTransition_money_unchanged request mutation hMutation
  obtain ⟨r, hr, hLe⟩ :=
    applyCorrectionTransition_outstanding_within_shortfall_linked request mutation hMutation
  rw [hBefore] at hr
  cases hr
  obtain ⟨-, -, -, -, hPay, -, -⟩ := hL.resultingFrame
  refine ⟨hL.resultingEvaluates, ?_⟩
  rw [hPay, linkedOutstandingCents_perm _ _ hL.resultingActions, hShort]
  exact hLe

/-- A1: every correction mutation passed the live-mode, authority, actor and pack checks,
    and the recorded determination names exactly that actor and authority. -/
theorem applyCorrectionTransition_mutation_authorized (request : CorrectionTransitionRequest)
    (mutation : CorrectionMutation)
    (hMutation : (applyCorrectionTransition request).mutation = some mutation) :
    request.currentInput.context.mode ≠ .SHADOW ∧
      sameAuthority request.currentInput.authority request.command.currentAuthorityId
        request.command.currentAuthorityEpoch request.command.currentAuthorityDigest = true ∧
      authorityActorBindingWellFormed request.currentInput.authority request.command.actorId
        request.command.actorRole = true ∧
      request.currentInput.pack.authorizedRoles.contains request.command.actorRole = true ∧
      request.currentInput.pack.status = .APPROVED ∧
      mutation.determination.actorId = request.command.actorId ∧
      mutation.determination.actorRole = request.command.actorRole ∧
      mutation.determination.authorityId = request.command.currentAuthorityId ∧
      mutation.determination.authorityEpoch = request.command.currentAuthorityEpoch ∧
      mutation.determination.authorityDigest = request.command.currentAuthorityDigest := by
  have hL := (applyCorrectionTransition_mutation_links request mutation hMutation).2.2.2.2.2.2
  have hReady : ∃ cr claim a b paid c d, preflightCorrectionTransition request =
      .ok (.ready cr claim a b paid c d) := by
    unfold applyCorrectionTransition at hMutation
    cases hP : preflightCorrectionTransition request with
    | error r => simp [hP, reject] at hMutation
    | ok p =>
        cases p with
        | duplicate => simp [hP, duplicate] at hMutation
        | ready cr claim a b paid c d => exact ⟨cr, claim, a, b, paid, c, d, rfl⟩
  obtain ⟨cr, claim, a, b, paid, c, d, hP⟩ := hReady
  obtain ⟨hm, hWf, hs, hbind, hc, -⟩ := preflightCorrectionTransition_ready_facts hP
  have hApproved : request.currentInput.pack.status = .APPROVED := by
    have hPack : controlPackWellFormed request.currentInput.pack = true := by
      unfold financialInputWellFormed at hWf
      simp only [envWellFormed, envOf, Bool.and_eq_true, decide_eq_true_eq] at hWf
      grind
    simp only [controlPackWellFormed, Bool.and_eq_true, decide_eq_true_eq] at hPack
    grind
  obtain ⟨hd1, hd2, hd3, hd4, hd5⟩ := hL.determinationActor
  have hs' := hs
  simp only [sameAuthority, Bool.and_eq_true, decide_eq_true_eq] at hs'
  exact ⟨hm, hs, hbind, hc, hApproved, hd1, hd2, hd3.trans hs'.1.1, hd4.trans hs'.1.2,
    hd5.trans hs'.2⟩

/-- A reuse is allowed only when no environment check denies it. -/
private theorem environment_none_facts {request : CorrectionReuseRequest}
    {mutation : CorrectionMutation}
    (h : executionEnvironmentDenial request mutation = none) :
    request.currentInput.context.mode ≠ .SHADOW ∧
      sameAuthority request.currentInput.authority mutation.dependencies.authorityId
        mutation.dependencies.authorityEpoch mutation.dependencies.authorityDigest = true ∧
      authorityActorBindingWellFormed request.currentInput.authority mutation.determination.actorId
        mutation.determination.actorRole = true ∧
      request.currentInput.pack.authorizedRoles.contains mutation.determination.actorRole = true ∧
      request.currentInput.pack.status = .APPROVED := by
  have hm : request.currentInput.context.mode ≠ .SHADOW := fun hm => by
    simp [executionEnvironmentDenial, hm] at h
  have hs : sameAuthority request.currentInput.authority mutation.dependencies.authorityId
      mutation.dependencies.authorityEpoch mutation.dependencies.authorityDigest = true := by
    refine Classical.byContradiction fun hn => ?_
    simp at hn
    simp [executionEnvironmentDenial, hm, hn] at h
  have hb : authorityActorBindingWellFormed request.currentInput.authority
      mutation.determination.actorId mutation.determination.actorRole = true := by
    refine Classical.byContradiction fun hn => ?_
    simp at hn
    simp [executionEnvironmentDenial, hm, hs, hn] at h
  have hc : request.currentInput.pack.authorizedRoles.contains mutation.determination.actorRole =
      true := by
    refine Classical.byContradiction fun hn => ?_
    simp at hn
    simp [executionEnvironmentDenial, hm, hs, hb, hn] at h
  have hp : request.currentInput.pack.status = .APPROVED := by
    refine Classical.byContradiction fun hn => ?_
    have hc' : mutation.determination.actorRole ∈ request.currentInput.pack.authorizedRoles := by
      simpa using hc
    simp [executionEnvironmentDenial, hm, hs, hb, hc', hn] at h
  exact ⟨hm, hs, hb, hc, hp⟩

/-- A1′: a reuse is ALLOWED only when the stored mutation's actor is still authorized now. -/
theorem assessCorrectionReuse_allowed_authorized (request : CorrectionReuseRequest)
    (hAllowed : (assessCorrectionReuse request).localExecutionPermission = .ALLOWED) :
    ∃ mutation, request.acceptedResult.mutation = some mutation ∧
      request.currentInput.context.mode ≠ .SHADOW ∧
      sameAuthority request.currentInput.authority mutation.dependencies.authorityId
        mutation.dependencies.authorityEpoch mutation.dependencies.authorityDigest = true ∧
      authorityActorBindingWellFormed request.currentInput.authority mutation.determination.actorId
        mutation.determination.actorRole = true ∧
      request.currentInput.pack.authorizedRoles.contains mutation.determination.actorRole = true ∧
      request.currentInput.pack.status = .APPROVED := by
  cases hStatus : request.acceptedResult.status <;>
    cases hMutation : request.acceptedResult.mutation <;>
    simp [assessCorrectionReuse, hStatus, hMutation, executionPermissionOfDenial] at hAllowed
  rename_i mutation
  refine ⟨mutation, rfl, environment_none_facts ?_⟩
  cases hE : executionEnvironmentDenial request mutation with
  | none => rfl
  | some d =>
      exfalso
      simp [assessAcceptedCorrectionReuse, executionDenial, hE, executionPermissionOfDenial]
        at hAllowed

/-! N2a and N2: a decoded request always yields a well-formed result, and that result encodes
    unless its mutation is oversize. -/

/-- A decoded request is canonical, so its command, input and receipt are well formed. -/
private theorem request_wellFormed {bytes : Bytes} {request : CorrectionTransitionRequest}
    (hDecode : decodeCorrectionTransitionRequest bytes = some request) :
    commandWellFormed request.command = true ∧ financialInputWellFormed request.currentInput = true ∧
      evaluationReceiptWellFormed request.currentReceipt = true := by
  have hE := encodeCorrectionTransitionRequest_of_decode bytes request hDecode
  unfold encodeCorrectionTransitionRequest encodeInputBody at hE
  cases hc : (!commandWellFormed request.command || !financialInputWellFormed request.currentInput ||
      !evaluationReceiptWellFormed request.currentReceipt)
  · simpa [and_assoc] using hc
  · simp [hc] at hE

private theorem wf_parts {input : FinancialInput} (h : financialInputWellFormed input = true) :
    (∀ c ∈ input.claims, claimWellFormed input.context c = true) ∧
    (∀ d ∈ input.determinations, determinationWellFormed input d = true) ∧
    (∀ a ∈ input.actions, actionWellFormed input a = true) := by
  unfold financialInputWellFormed at h
  simp only [Bool.and_eq_true] at h
  exact ⟨List.all_eq_true.1 (by grind), List.all_eq_true.1 (by grind), List.all_eq_true.1 (by grind)⟩

private theorem evaluate_frame {input : FinancialInput} {r : FinancialResult}
    (h : evaluate input = some r) :
    r.context = input.context ∧ r.authorityId = input.authority.authorityId ∧
      r.authorityEpoch = input.authority.epoch ∧ r.authorityDigest = input.authority.digest ∧
      r.packId = input.pack.packId ∧ r.packDigest = input.pack.digest ∧
      r.beforeRevision = input.beforeRevision ∧ r.afterRevision = input.beforeRevision + 1 := by
  obtain ⟨-, cash, claimed, lawful, -, -, -, -, rfl⟩ := evaluate_facts h
  exact ⟨rfl, rfl, rfl, rfl, rfl, rfl, rfl, rfl⟩

private theorem outstanding_perm {payments : List Payment} {actions : List ActionRecord}
    {links : List PaymentLink} {paid : List CorrectionPaid}
    (hDerived : derivedCorrectionPaid payments actions links = some paid)
    {l l' : List ActionRecord} (h : l.Perm l') :
    outstandingCorrectionCents paid l = outstandingCorrectionCents paid l' := by
  have hPaid := (derivedCorrectionPaid_sound _ _ _ _ hDerived).2.2
  rw [outstandingCorrectionCents_eq_linked paid payments links l hPaid,
    outstandingCorrectionCents_eq_linked paid payments links l' hPaid]
  exact linkedOutstandingCents_perm _ _ h

private theorem resultWellFormed_reject (command : CorrectionCommand)
    (reason : TransitionRejectReason) : resultWellFormed (reject command reason) = true := by
  by_cases h1 : idWellFormed command.claimId = true <;>
    by_cases h2 : idWellFormed command.actionId = true <;>
    by_cases h3 : idWellFormed command.evaluationId = true <;>
    by_cases h4 : revisionWellFormed command.expectedRevision = true <;>
    simp [reject, resultWellFormed, optionalIdWellFormed, optionalRevisionWellFormed, h1, h2, h3, h4]

private theorem resultWellFormed_duplicate {command : CorrectionCommand}
    (hCmd : commandWellFormed command = true) : resultWellFormed (duplicate command) = true := by
  have h : idWellFormed command.claimId = true ∧ idWellFormed command.actionId = true ∧
      idWellFormed command.evaluationId = true ∧ revisionWellFormed command.expectedRevision = true := by
    unfold commandWellFormed at hCmd
    simp only [Bool.and_eq_true, List.all_cons, List.all_nil, Bool.and_true] at hCmd
    grind
  simp [duplicate, resultWellFormed, optionalIdWellFormed, optionalRevisionWellFormed, h.1, h.2.1,
    h.2.2.1, h.2.2.2]

set_option maxHeartbeats 2000000 in
/-- N2a: a request that decodes always produces a well-formed result. -/
theorem applyCorrectionTransition_resultWellFormed (bytes : Bytes)
    (request : CorrectionTransitionRequest)
    (hDecode : decodeCorrectionTransitionRequest bytes = some request) :
    resultWellFormed (applyCorrectionTransition request) = true := by
  obtain ⟨hCmd, hCur, hRec⟩ := request_wellFormed hDecode
  unfold applyCorrectionTransition
  cases hP : preflightCorrectionTransition request with
  | error r => exact resultWellFormed_reject _ r
  | ok p =>
    cases p with
    | duplicate => exact resultWellFormed_duplicate hCmd
    | ready cr claim a b paid c d =>
      dsimp only
      cases hB : buildAccepted request cr claim b paid c d with
      | error r => exact resultWellFormed_reject _ r
      | ok certified =>
        obtain ⟨mutation, links⟩ := certified
        dsimp only
        have hL := links
        obtain ⟨-, -, -, -, -, hFind, hStatus, hEvId, hCover, hChron, hFresh, hQA, hQD, hQC, hAt⟩ :=
          preflightCorrectionTransition_ready_facts hP
        obtain ⟨hBClaim, hAgg, hCommit, hCreated, hDecided, hSupp, hContract, hVer, hDig, hReason,
          hOwner, hDue, hStat, hUpd, hAcc, hAmt, hRep, hDel, hResWf, hOutT⟩ := buildAccepted_facts hB
        obtain ⟨hClaims, -, -⟩ := wf_parts hCur
        obtain ⟨-, hDets, hActs⟩ := wf_parts hResWf
        have hClaimWf := hClaims claim (findClaim_mem _ _ _ hFind).1
        have hClaimId := (findClaim_mem _ _ _ hFind).2
        have hDetWf := hDets mutation.determination (hL.resultingDeterminations.mem_iff.2 (by simp))
        have hActWf := hActs mutation.action (hL.resultingActions.mem_iff.2 (by simp))
        obtain ⟨before, hBefore, hShortEq, hOutLt⟩ := hL.inputShortfall
        obtain ⟨hFr1, hFr2, hFr3, hFr4, hFr5, hFr6, hFr7, hFr8⟩ :=
          evaluate_frame hL.resultingEvaluates
        have hRRwf := evaluate_resultWellFormed hL.resultingEvaluates
        have hShortMax : before.shortfallCents ≤ maxCents := by
          have h := evaluate_resultWellFormed hBefore
          unfold financialResultWellFormed at h
          simp only [Bool.and_eq_true, amountWellFormed, decide_eq_true_eq] at h
          grind
        have hRecTime : request.currentReceipt.result.evaluatedAtMs ≤ maxTime := by
          unfold evaluationReceiptWellFormed ownerEvaluationResultWellFormed at hRec
          simp only [Bool.and_eq_true, decide_eq_true_eq] at hRec
          grind
        have hRecDigest : mutation.dependencies.inputEvaluationSnapshotDigest.length = digestBytes := by
          unfold evaluationReceiptWellFormed at hRec
          simp only [Bool.and_eq_true, hDig, optionalPackageDigestWellFormed, packageDigestWellFormed,
            decide_eq_true_eq] at hRec
          grind
        have hEvAll0 : request.currentReceipt.evidenceBindings.all (fun binding =>
            boundedPackageId binding.evidenceId && packageDigestWellFormed binding.recordDigest) =
            true := by
          unfold evaluationReceiptWellFormed at hRec
          simp only [Bool.and_eq_true] at hRec
          grind
        have hEvAll : mutation.dependencies.supportingEvidence.all (fun binding =>
            idWellFormed binding.evidenceId && digestWellFormed binding.recordDigest) = true := by
          rw [hL.dependencyEvidence]; exact hEvAll0
        have hAny : mutation.resultingInput.claims.any (fun c =>
            decide (c = { mutation.dependencies.claimBefore with status := .REJECTED })) = true := by
          rw [hL.resultingClaims, List.any_eq_true]
          refine ⟨if claim.claimId = request.command.claimId then
              { mutation.dependencies.claimBefore with status := .REJECTED } else claim,
            List.mem_map.2 ⟨claim, (findClaim_mem _ _ _ hFind).1, rfl⟩, ?_⟩
          rw [if_pos hClaimId]; simp
        have hAny2 : mutation.dependencies.supportingEvidence.any (fun binding =>
            decide (binding.evidenceId = mutation.dependencies.claimBefore.evidenceId)) = true := by
          rw [hL.dependencyEvidence, hBClaim]; exact hCover
        have hPaidWf := (derivedCorrectionPaid_sound _ _ _ _ hL.derivedPaid).1
        have hFilter : (mutation.action :: request.currentInput.actions).filter
            (fun x => decide (x.actionId ≠ request.command.actionId)) = request.currentInput.actions := by
          rw [List.filter_cons_of_neg (by simp [hL.acceptedActionIdentity]),
            List.filter_eq_self.2 (fun x hx => by simpa using hFresh x hx)]
        have hP := hL.resultingActions.filter (fun x => decide (x.actionId ≠ request.command.actionId))
        rw [hFilter] at hP
        have hOut : outstandingCorrectionCents mutation.dependencies.correctionPaid
            (mutation.resultingInput.actions.filter
              (fun x => decide (x.actionId ≠ request.command.actionId))) =
            outstandingCorrectionCents mutation.dependencies.correctionPaid
              request.currentInput.actions :=
          outstanding_perm hL.derivedPaid hP
        have hAmtRule := hL.amountRule
        rw [← hOut] at hAmtRule
        unfold commandWellFormed at hCmd
        unfold determinationWellFormed at hDetWf
        unfold actionWellFormed at hActWf
        unfold claimWellFormed at hClaimWf
        simp only [Bool.and_eq_true, List.all_cons, List.all_nil, Bool.and_true, decide_eq_true_eq,
          positiveAmountWellFormed, amountWellFormed, timeWellFormed, revisionWellFormed,
          digestWellFormed] at hCmd hDetWf hActWf hClaimWf
        clear hRec hCur hDecode hActs hDets hClaims hEvAll0 hB hP
        cases links
        unfold resultWellFormed
        simp only [Bool.and_eq_true, decide_eq_true_eq, timeWellFormed, revisionWellFormed,
          digestWellFormed, reduceCtorEq, ↓reduceIte, decide_false, Bool.false_and, Bool.or_false,
          Bool.false_or]
        repeat' apply And.intro
        all_goals first | assumption | rfl | grind

/-! N2 sizes. Every string the wire carries outside the named parts is at most 200 bytes. -/

private theorem ulen (s : String) : s.toUTF8.toList.length = s.utf8ByteSize := by
  rw [byteArray_toList_eq, Array.length_toList]
  rfl

private theorem id_size {s : String} (h : idWellFormed s = true) : s.utf8ByteSize ≤ 128 := by
  unfold idWellFormed at h
  simp only [Bool.and_eq_true, decide_eq_true_eq] at h
  have hLen := h.1.2
  have := ulen s
  unfold maxIdBytes at hLen
  omega

private theorem lit_size (s : String) (n : Nat) (h : s.toList.length ≤ n) :
    s.utf8ByteSize ≤ 4 * n := by
  have := string_utf8_length_le s
  have := ulen s
  omega

private theorem rev_size {n : Nat} (h : revisionWellFormed n = true) :
    (toString n).utf8ByteSize ≤ 20 := by
  unfold revisionWellFormed maxRevision at h
  simp only [decide_eq_true_eq] at h
  have h5 : n.repr.length ≤ 5 :=
    (Nat.length_repr_le_iff (by omega)).2 (by
      have : (10 : Nat) ^ 5 = 100000 := by decide
      omega)
  have := lit_size (toString n) 5 h5
  omega

private theorem sz_eval {o : String} {n : Nat} (ho : idWellFormed o = true)
    (hn : revisionWellFormed n = true) :
    ("evaluation:" ++ o ++ ":r" ++ toString n).utf8ByteSize ≤ 200 := by
  have h1 := lit_size "evaluation:" 11 (by first | decide | simp)
  have h2 := lit_size ":r" 2 (by first | decide | simp)
  have := id_size ho
  have := rev_size hn
  simp only [String.utf8ByteSize_append]
  omega

private theorem sz_case {o : String} (ho : idWellFormed o = true) :
    ("case:" ++ o).utf8ByteSize ≤ 200 := by
  have h1 := lit_size "case:" 5 (by first | decide | simp)
  have := id_size ho
  simp only [String.utf8ByteSize_append]
  omega

private theorem sz_det {a : String} (ha : idWellFormed a = true) :
    ("determination:" ++ a).utf8ByteSize ≤ 200 := by
  have h1 := lit_size "determination:" 14 (by first | decide | simp)
  have := id_size ha
  simp only [String.utf8ByteSize_append]
  omega

private theorem estr_le {s : String} (h : s.utf8ByteSize ≤ 200) : (encodeString s).length ≤ 202 := by
  rw [length_encodeString, ulen]
  omega

private theorem sz_id {s : String} (h : idWellFormed s = true) : (encodeString s).length ≤ 202 :=
  estr_le (Nat.le_trans (id_size h) (by omega))

private theorem sz_role {s : String} (h : roleWellFormed s = true) : (encodeString s).length ≤ 202 := by
  unfold roleWellFormed tokenWellFormed at h
  simp only [Bool.and_eq_true, decide_eq_true_eq] at h
  have hLen := h.1.2
  have := ulen s
  exact estr_le (by omega)

private theorem sz_lit (s : String) (h : s.toList.length ≤ 50) : (encodeString s).length ≤ 202 :=
  estr_le (Nat.le_trans (lit_size s 50 h) (by omega))

private theorem eopt_le {o : Option String} (h : ∀ s, o = some s → s.utf8ByteSize ≤ 200) :
    (encodeOptionString o).length ≤ 203 := by
  cases o with
  | none => simp [encodeOptionString]
  | some s =>
    have := estr_le (h s rfl)
    simp only [encodeOptionString, List.length_cons]
    omega

private theorem opt_id_size {o : Option String} {s : String} (h : optionalIdWellFormed o = true)
    (hs : o = some s) : s.utf8ByteSize ≤ 200 := by
  subst hs
  exact Nat.le_trans (id_size h) (by omega)

private theorem dig_len {d : Bytes} (h : digestWellFormed d = true) : d.length ≤ 64 := by
  unfold digestWellFormed digestBytes at h
  simp only [decide_eq_true_eq] at h
  omega

private theorem ctx_parts {x : FinancialInput} (h : financialInputWellFormed x = true) :
    x.context.currency = "USD" := by
  unfold financialInputWellFormed at h
  simp only [envWellFormed, envOf, Bool.and_eq_true] at h
  have hc : contextWellFormed x.context = true := by grind
  unfold contextWellFormed at hc
  simp only [Bool.and_eq_true, List.all_cons, List.all_nil, decide_eq_true_eq] at hc
  grind

private theorem len_effects (l : List CorrectionEffect) :
    (encodeList (fun effect => [encodeCorrectionEffect effect]) l).length = 2 + l.length := by
  have h : (l.flatMap fun effect => [encodeCorrectionEffect effect]).length = l.length := by
    induction l with
    | nil => simp
    | cons x xs ih => simp [List.flatMap_cons, ih]; try omega
  simp only [encodeList, List.length_append, length_natBE, h]

private theorem explanation_len (e : TransitionExplanation)
    (h1 : (encodeOptionString e.claimId).length ≤ 203)
    (h2 : (encodeOptionString e.actionId).length ≤ 203)
    (h3 : (encodeOptionString e.inputEvaluationId).length ≤ 203) :
    (encodeExplanation e).length ≤ 700 := by
  have h4 := length_encodeOptionNat_le e.expectedRevision
  have h5 := length_encodeOptionNat_le e.resultingRevision
  obtain ⟨code, tr, rr, rq, c, a, ev, x, y⟩ := e
  dsimp only at *
  cases tr <;> cases rr <;> cases rq <;>
    simp [encodeExplanation, encodeOptionalRejectReason, encodeOptionalRequirement] <;> omega

set_option maxHeartbeats 2000000 in
/-- What `resultWellFormed` says about the five optional ids the wire head carries. -/
private theorem head_facts {res : CorrectionTransitionResult} (hWf : resultWellFormed res = true) :
    (encodeOptionString res.explanation.claimId).length ≤ 203 ∧
    (encodeOptionString res.explanation.actionId).length ≤ 203 ∧
    (encodeOptionString res.explanation.inputEvaluationId).length ≤ 203 ∧
    (encodeOptionString res.actionId).length ≤ 203 ∧
    (encodeOptionString res.determinationId).length ≤ 203 := by
  unfold resultWellFormed at hWf
  split at hWf
  · have hA := ‹res.actionId = some _›
    have hD := ‹res.determinationId = some _›
    simp only [Bool.and_eq_true, decide_eq_true_eq, and_assoc] at hWf
    obtain ⟨c1, c2, c3, c4, c5, c6, c7, c8, c9, c10, c11, c12, c13, c14, c15, c16, c17, c18, c19,
      c20, c21, c22, c23, c24, c25, c26, c27, c28, c29, c30, c31, c32, c33, c34, c35, c36, c37,
      c38, c39, c40, c41, c42, c43, c44, c45, c46, c47, c48, c49, c50, c51, c52, c53, c54, c55,
      c56, c57, c58, c59, c60, c61, c62, c63, c64, c65, c66, c67, c68, c69, c70, c71, c72, c73,
      c74, c75, c76, c77, c78, c79, c80, c81, c82, c83, c84, c85, c86, c87, c88, c89, c90, c91,
      c92, c93, c94, c95, c96, c97, c98, c99, c100, c101, c102, c103, c104, c105, c106, c107,
      c108, c109, c110, c111, c112, c113, c114, c115, c116, c117, c118, c119, c120, c121, c122,
      c123, c124, c125, c126, c127⟩ := hWf
    refine ⟨eopt_le fun s hs => ?_, eopt_le fun s hs => ?_, eopt_le fun s hs => ?_,
      eopt_le fun s hs => ?_, eopt_le fun s hs => ?_⟩
    · have h := Option.some.inj (c3.symm.trans hs)
      subst h
      exact Nat.le_trans (id_size c22) (by omega)
    · have h := Option.some.inj (c4.symm.trans hs)
      subst h
      exact Nat.le_trans (id_size c1) (by omega)
    · have h := Option.some.inj (c5.symm.trans hs)
      subst h
      rw [c89]
      exact sz_eval (by rw [← c33]; exact c21) (by rw [c88]; exact c29)
    · have h := Option.some.inj (hA.symm.trans hs)
      subst h
      exact Nat.le_trans (id_size c1) (by omega)
    · have h := Option.some.inj (hD.symm.trans hs)
      subst h
      exact Nat.le_trans (id_size c2) (by omega)
  · have hA := ‹res.actionId = some _›
    have hD := ‹res.determinationId = some _›
    simp only [Bool.and_eq_true, decide_eq_true_eq, and_assoc] at hWf
    obtain ⟨d1, d2, d3, d4, d5, d6, d7, d8, d9, d10⟩ := hWf
    refine ⟨eopt_le fun s hs => opt_id_size d6 hs, eopt_le fun s hs => ?_,
      eopt_le fun s hs => opt_id_size d7 hs, eopt_le fun s hs => ?_, eopt_le fun s hs => ?_⟩
    · have h := Option.some.inj (d4.symm.trans hs)
      subst h
      exact Nat.le_trans (id_size d1) (by omega)
    · have h := Option.some.inj (hA.symm.trans hs)
      subst h
      exact Nat.le_trans (id_size d1) (by omega)
    · have h := Option.some.inj (hD.symm.trans hs)
      subst h
      rw [d2]
      exact sz_det d1
  · simp only [Bool.and_eq_true, decide_eq_true_eq, and_assoc] at hWf
    obtain ⟨r1, r2, r3, r4, r5, r6, r7, r8, r9, r10⟩ := hWf
    have hNone : res.actionId = none := Option.isNone_iff_eq_none.1 r4
    have hNoneD : res.determinationId = none := Option.isNone_iff_eq_none.1 r5
    refine ⟨eopt_le fun s hs => opt_id_size r7 hs, eopt_le fun s hs => opt_id_size r8 hs,
      eopt_le fun s hs => opt_id_size r9 hs, eopt_le fun s hs => ?_, eopt_le fun s hs => ?_⟩
    · rw [hNone] at hs
      cases hs
    · rw [hNoneD] at hs
      cases hs
  · simp at hWf

/-- What an accepted mutation's non-named wire parts are bounded by. -/
private def MutOK (m : CorrectionMutation) : Prop :=
  financialInputWellFormed m.resultingInput = true ∧ financialResultWellFormed m.resultingResult = true ∧
  m.orderedEffects.length ≤ 7 ∧
  (encodeString m.followUps.actionId).length ≤ 202 ∧
  (encodeString m.followUps.outboxActionId).length ≤ 202 ∧
  (encodeString m.followUps.caseId).length ≤ 202 ∧
  (encodeString m.followUps.resultingEvaluationId).length ≤ 202 ∧
  (encodeString m.action.actionId).length ≤ 202 ∧
  (encodeString m.action.obligationId).length ≤ 202 ∧
  (encodeOptionString m.action.determinationId).length ≤ 203 ∧
  (encodeString m.action.kind).length ≤ 202 ∧
  (encodeString m.action.currency).length ≤ 202 ∧
  m.action.payloadDigest.length ≤ 64 ∧
  (encodeString m.caseDelta.record.caseId).length ≤ 202 ∧
  (encodeString m.caseDelta.record.obligationId).length ≤ 202 ∧
  (encodeString m.caseDelta.record.reason).length ≤ 202 ∧
  (encodeString m.caseDelta.record.nextActionOwner).length ≤ 202 ∧
  (encodeString m.caseDelta.contractualAccountability).length ≤ 202 ∧
  (encodeString m.outbox.actionId).length ≤ 202 ∧
  (encodeOptionString m.outbox.acknowledgmentReference).length ≤ 203 ∧
  (encodeString m.event.aggregateType).length ≤ 202 ∧
  m.event.previousHead.length ≤ 64 ∧
  (encodeString m.event.aggregateId).length ≤ 202 ∧
  (encodeString m.event.kind).length ≤ 202

set_option maxHeartbeats 2000000 in
private theorem mut_facts {res : CorrectionTransitionResult} (hWf : resultWellFormed res = true) :
    ∀ m, res.mutation = some m → MutOK m := by
  unfold resultWellFormed at hWf
  split at hWf
  · have hq := ‹res.mutation = some _›
    simp only [Bool.and_eq_true, decide_eq_true_eq, and_assoc] at hWf
    obtain ⟨c1, c2, c3, c4, c5, c6, c7, c8, c9, c10, c11, c12, c13, c14, c15, c16, c17, c18, c19,
      c20, c21, c22, c23, c24, c25, c26, c27, c28, c29, c30, c31, c32, c33, c34, c35, c36, c37,
      c38, c39, c40, c41, c42, c43, c44, c45, c46, c47, c48, c49, c50, c51, c52, c53, c54, c55,
      c56, c57, c58, c59, c60, c61, c62, c63, c64, c65, c66, c67, c68, c69, c70, c71, c72, c73,
      c74, c75, c76, c77, c78, c79, c80, c81, c82, c83, c84, c85, c86, c87, c88, c89, c90, c91,
      c92, c93, c94, c95, c96, c97, c98, c99, c100, c101, c102, c103, c104, c105, c106, c107,
      c108, c109, c110, c111, c112, c113, c114, c115, c116, c117, c118, c119, c120, c121, c122,
      c123, c124, c125, c126, c127⟩ := hWf
    intro m hm
    have hEq : m = _ := Option.some.inj (hm.symm.trans hq)
    subst hEq
    have hOid : idWellFormed m.resultingInput.context.obligationId = true := by
      rw [← c33]; exact c21
    have hRev : revisionWellFormed m.resultingResult.afterRevision = true := by
      rw [← c51, c53]; exact c30
    refine ⟨c8, c9, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_,
      ?_, ?_⟩
    · rw [c18]; simp
    · rw [c61]; exact sz_id c1
    · rw [c62]; exact sz_id c1
    · rw [c63, c64]; exact estr_le (sz_case hOid)
    · rw [c78]; exact estr_le (sz_eval hOid hRev)
    · rw [c34]; exact sz_id c1
    · rw [c36]; exact sz_id c21
    · refine eopt_le fun s hs => ?_
      have h := Option.some.inj (c37.symm.trans hs)
      subst h
      exact Nat.le_trans (id_size c2) (by omega)
    · rw [c38]; split <;> exact sz_lit _ (by first | decide | simp)
    · rw [c43, ctx_parts c8]; exact sz_lit _ (by first | decide | simp)
    · exact dig_len c35
    · rw [c64]; exact estr_le (sz_case hOid)
    · rw [c65]; exact sz_id hOid
    · simp only [Bool.or_eq_true, Bool.and_eq_true, decide_eq_true_eq] at c66
      rcases c66 with h | h
      · rw [h]; split <;> exact sz_lit _ (by first | decide | simp)
      · exact sz_id h.2
    · simp only [Bool.or_eq_true, Bool.and_eq_true, decide_eq_true_eq] at c67
      rcases c67 with h | h
      · rw [h]; exact sz_lit _ (by first | decide | simp)
      · exact sz_role h.2
    · rw [c71]; exact sz_lit _ (by first | decide | simp)
    · rw [c47]; exact sz_id c1
    · refine eopt_le fun s hs => ?_
      rw [Option.isNone_iff_eq_none.1 c76] at hs
      cases hs
    · rw [c55]; exact sz_lit _ (by first | decide | simp)
    · have h := c60
      unfold digestBytes at h
      omega
    · rw [c56]; exact sz_id hOid
    · rw [c57]; split <;> exact sz_lit _ (by first | decide | simp)
  · intro m hm
    exact nomatch hm.symm.trans ‹res.mutation = none›
  · intro m hm
    exact nomatch hm.symm.trans ‹res.mutation = none›
  · simp at hWf

private theorem fin_raw {x : FinancialInput} (hWf : financialInputWellFormed x = true)
    (h : (rawEncodeFinancialInput x).length ≤ maxTotalEncodedBytes) :
    encodeFinancialInput x = some (rawEncodeFinancialInput x) := by
  simp [encodeFinancialInput, hWf, h]

private theorem res_raw {x : FinancialResult} (hWf : financialResultWellFormed x = true)
    (h : (rawEncodeFinancialResult x).length ≤ maxTotalEncodedBytes) :
    encodeFinancialResult x = some (rawEncodeFinancialResult x) := by
  simp [encodeFinancialResult, hWf, h]

set_option maxHeartbeats 4000000 in
private theorem mutation_len {m : CorrectionMutation} (h : MutOK m)
    (hIn : (rawEncodeFinancialInput m.resultingInput).length ≤ maxTotalEncodedBytes)
    (hRs : (rawEncodeFinancialResult m.resultingResult).length ≤ maxTotalEncodedBytes) :
    ∃ mb, encodeOptionalMutation (some m) = some mb ∧
      mb.length ≤ (rawEncodeFinancialInput m.resultingInput).length +
        (rawEncodeFinancialResult m.resultingResult).length +
        (encodeDependencyFacts m.dependencies).length + (encodeDetermination m.determination).length +
        8000 := by
  obtain ⟨hI, hR, hEff, s4, s5, s6, s7, s8, s9, s10, s11, s12, s13, s14, s15, s16, s17, s18, s19,
    s20, s21, s22, s23, s24⟩ := h
  have hEI := fin_raw hI hIn
  have hER := res_raw hR hRs
  cases hE : encodeOptionalMutation (some m) with
  | none => simp [encodeOptionalMutation, hEI, hER] at hE
  | some mb =>
    refine ⟨mb, rfl, ?_⟩
    simp [encodeOptionalMutation, hEI, hER] at hE
    subst hE
    simp only [encodeCase, encodeAction, encodeBool, encodeDigest, encodeSizedBytes, encodeFollowUps,
      List.length_append, List.length_cons, List.length_nil, length_natBE, len_effects]
    omega

set_option maxHeartbeats 4000000 in
private theorem result_encodes (res : CorrectionTransitionResult)
    (hWf : resultWellFormed res = true) :
    (encodeCorrectionTransitionResult res).isSome = true ∨
      ∃ m, res.mutation = some m ∧
        maxCorrectionTransitionBytes < (rawEncodeFinancialInput m.resultingInput).length +
          (rawEncodeFinancialResult m.resultingResult).length +
          (encodeDependencyFacts m.dependencies).length +
          (encodeDetermination m.determination).length + 65536 := by
  obtain ⟨hc1, hc2, hc3, hc4, hc5⟩ := head_facts hWf
  have hMagic : correctionTransitionResultMagic.length ≤ 32 := by
    unfold correctionTransitionResultMagic
    rw [ulen]
    exact Nat.le_trans (lit_size "BLFCRES3" 8 (by first | decide | simp)) (by omega)
  have hCon := sz_lit correctionTransitionContract (by simp [correctionTransitionContract])
  have hExp := explanation_len res.explanation hc1 hc2 hc3
  have hRej : (encodeOptionalRejectReason res.rejectReason).length ≤ 2 := by
    cases res.rejectReason <;> simp [encodeOptionalRejectReason]
  have hMax : maxCorrectionTransitionBytes = maxTotalEncodedBytes := rfl
  have hMaxVal : maxTotalEncodedBytes = 8388608 := by decide
  cases hm : res.mutation with
  | none =>
    left
    cases hE : encodeCorrectionTransitionResult res with
    | some w => rfl
    | none =>
      exfalso
      unfold encodeCorrectionTransitionResult at hE
      simp [hWf, hm, encodeOptionalMutation, length_natBE] at hE
      omega
  | some m =>
    have hOK := mut_facts hWf m hm
    by_cases hIn : (rawEncodeFinancialInput m.resultingInput).length ≤ maxTotalEncodedBytes
    · by_cases hRs : (rawEncodeFinancialResult m.resultingResult).length ≤ maxTotalEncodedBytes
      · obtain ⟨mb, hmb, hmbLen⟩ := mutation_len hOK hIn hRs
        cases hE : encodeCorrectionTransitionResult res with
        | some w => left; rfl
        | none =>
          right
          refine ⟨m, rfl, ?_⟩
          unfold encodeCorrectionTransitionResult at hE
          simp [hWf, hm, hmb, length_natBE] at hE
          omega
      · right
        exact ⟨m, rfl, by omega⟩
    · right
      exact ⟨m, rfl, by omega⟩

/-- N2: a decoded request's result encodes, unless its mutation is oversize. The slack 65536
    covers everything the wire carries besides the four named parts (about 6 KiB in all). -/
theorem applyCorrectionTransition_encodes_unless_oversize (bytes : Bytes)
    (request : CorrectionTransitionRequest)
    (hDecode : decodeCorrectionTransitionRequest bytes = some request) :
    (encodeCorrectionTransitionResult (applyCorrectionTransition request)).isSome = true ∨
      ∃ m, (applyCorrectionTransition request).mutation = some m ∧
        maxCorrectionTransitionBytes < (rawEncodeFinancialInput m.resultingInput).length +
          (rawEncodeFinancialResult m.resultingResult).length +
          (encodeDependencyFacts m.dependencies).length +
          (encodeDetermination m.determination).length + 65536 :=
  result_encodes _ (applyCorrectionTransition_resultWellFormed bytes request hDecode)

end BlindLedger.Financial.CorrectionTransition
