import BlindLedger.Financial.Offset.Claim
import BlindLedger.Financial.Payment.CodecLaws
import BlindLedger.Financial.Theorems.Conservation
import BlindLedger.Financial.CorrectionTransition.KAT

namespace BlindLedger.Financial.Offset

open BlindLedger.Financial BlindLedger.Financial.Payment

private theorem slotOf_fresh {f : Bool} {s : Option EvidenceRecord} {e : EvidenceRecord}
    (h : slotOf f s e = .fresh) : f = false ∧ s = none := by
  unfold slotOf at h
  cases f <;> cases s <;> simp_all
  split at h <;> simp at h

theorem decideClaim_claimed {r : ClaimRequest} {w : ClaimWrites} {post : FinancialInput}
    {result : FinancialResult} (h : decideClaim r = .claimed w post result) :
    r.input.context.mode ≠ .SHADOW ∧ 0 < r.command.amountCents ∧
      r.input.pack.authorizedRoles.contains r.command.ownerRole = true ∧
      r.foreign.claimId = false ∧ r.foreign.evidenceId = false ∧
      findClaim r.input.claims r.command.claimId = none ∧
      findEvidence r.input.evidence r.command.evidenceId = none ∧
      r.expectedRevision.all (· = r.input.beforeRevision) = true ∧
      w.evidence = claimEvidence r.input r.command ∧ w.claim = claimImage r.input r.command ∧
      w.case = claimCaseImage r.input r.command ∧
      post = applyClaim r.input w ∧ evaluate post = some result := by
  unfold decideClaim at h
  dsimp only at h
  split at h
  · cases h
  rename_i hMode
  split at h
  · cases h
  rename_i hAmt
  split at h
  · cases h
  split at h
  · cases h
  rename_i hRole
  split at h
  · cases h
  rename_i hFor
  split at h
  · split at h <;> cases h
  rename_i hFind
  split at h
  · cases h
  rename_i hRev
  split at h
  · cases h
  · cases h
  rename_i hSlot
  split at h
  · cases h
  rename_i hCap
  split at h
  · cases h
  rename_i result' hEv
  cases h
  obtain ⟨hF, hS⟩ := slotOf_fresh hSlot
  refine ⟨hMode, Nat.pos_of_ne_zero hAmt, by simpa using hRole, by simpa using hFor, by simpa using hF,
    hFind, hS, by simpa using hRev, rfl, rfl, rfl, rfl, hEv⟩

theorem decideClaim_duplicate {r : ClaimRequest} (h : decideClaim r = .duplicate) :
    ∃ k, findClaim r.input.claims r.command.claimId = some k ∧ k.evidenceId = r.command.evidenceId ∧
      k.amountCents = r.command.amountCents ∧ k.ownerRole = r.command.ownerRole ∧
      k.deadlineAt = r.command.deadlineAt ∧ r.foreign.claimId = false := by
  unfold decideClaim at h
  dsimp only at h
  split at h
  · cases h
  split at h
  · cases h
  split at h
  · cases h
  split at h
  · cases h
  split at h
  · cases h
  rename_i hFor
  split at h
  · rename_i k hk
    split at h
    · rename_i hk4
      exact ⟨k, hk, hk4.1, hk4.2.1, hk4.2.2.1, hk4.2.2.2, by simpa using hFor⟩
    · cases h
  · (repeat' split at h) <;> cases h

private theorem evalAdd_some {a b c : Nat} (h : evalAdd a b = some c) : c = a + b := by
  unfold evalAdd at h
  split at h
  · exact (Option.some.inj h).symm
  · cases h

private theorem claimedSum_cons {x : Claim} {l : List Claim} {tl : Nat}
    (h : evalClaimedSum l = some tl) :
    evalClaimedSum (x :: l) =
      if x.status = .CLAIMED || x.status = .AUTHORIZED then evalAdd x.amountCents tl else some tl := by
  simp [evalClaimedSum, h]

private theorem claimedSum_tail {x : Claim} {l : List Claim} {t : Nat}
    (h : evalClaimedSum (x :: l) = some t) : ∃ tl, evalClaimedSum l = some tl := by
  cases hl : evalClaimedSum l with
  | none => simp [evalClaimedSum, hl] at h
  | some tl => exact ⟨tl, rfl⟩

private theorem claimedSum_insertBy {k : Claim} (hk : k.status = .CLAIMED) :
    ∀ (l : List Claim) (t t' : Nat), evalClaimedSum l = some t →
      evalClaimedSum (insertBy Claim.claimId k l) = some t' → t' = k.amountCents + t := by
  intro l
  induction l with
  | nil =>
    intro t t' h h'
    have ht : t = 0 := by simpa [evalClaimedSum] using h.symm
    subst ht
    rw [insertBy, claimedSum_cons (x := k) (l := []) (tl := 0) rfl] at h'
    simp [hk] at h'
    have := evalAdd_some h'
    omega
  | cons x xs ih =>
    intro t t' h h'
    obtain ⟨tx, hx⟩ := claimedSum_tail h
    simp only [insertBy] at h'
    split at h'
    · rw [claimedSum_cons h] at h'
      simp [hk] at h'
      have := evalAdd_some h'
      omega
    · obtain ⟨ti, hti⟩ := claimedSum_tail h'
      have e := ih tx ti hx hti
      rw [claimedSum_cons hx] at h
      rw [claimedSum_cons hti] at h'
      by_cases hc : (x.status = .CLAIMED || x.status = .AUTHORIZED) = true
      · rw [if_pos hc] at h h'
        have a := evalAdd_some h
        have b := evalAdd_some h'
        omega
      · rw [if_neg hc, Option.some.injEq] at h h'
        omega

private theorem lawfulSum_insertBy {k : Claim} (hk : k.status ≠ .AUTHORIZED) :
    ∀ l : List Claim, evalLawfulSum (insertBy Claim.claimId k l) = evalLawfulSum l := by
  intro l
  induction l with
  | nil => simp [insertBy, evalLawfulSum, hk]
  | cons x xs ih =>
    simp only [insertBy]
    split
    · simp [evalLawfulSum, hk]
    · simp only [evalLawfulSum, ih]

theorem decideClaim_adds_claimed {r : ClaimRequest} {w : ClaimWrites} {post : FinancialInput}
    {result before : FinancialResult} (h : decideClaim r = .claimed w post result)
    (hBefore : evaluate r.input = some before) :
    result.claimedAdjustmentCents = before.claimedAdjustmentCents + r.command.amountCents ∧
      result.lawfulAdjustmentCents = before.lawfulAdjustmentCents ∧
      result.receivedCashCents = before.receivedCashCents ∧
      result.owedCents = before.owedCents ∧
      r.input.pack.authorizedRoles.contains r.command.ownerRole = true := by
  obtain ⟨-, -, hRole, -, -, -, -, -, -, hwC, -, hpost, hev⟩ := decideClaim_claimed h
  subst hpost
  obtain ⟨-, cash, claimed, lawful, hp, hc, hl, -, hr⟩ := evaluate_facts hBefore
  obtain ⟨-, cash', claimed', lawful', hp', hc', hl', -, hr'⟩ := evaluate_facts hev
  have hcl : (applyClaim r.input w).claims =
      insertBy Claim.claimId (claimImage r.input r.command) r.input.claims := by rw [← hwC]; rfl
  rw [hcl] at hc' hl'
  have e1 := claimedSum_insertBy (k := claimImage r.input r.command) rfl _ _ _ hc hc'
  rw [lawfulSum_insertBy (by simp [claimImage])] at hl'
  have hP : cash' = cash := Option.some.inj (hp'.symm.trans hp)
  have hL : lawful' = lawful := Option.some.inj (hl'.symm.trans hl)
  refine ⟨?_, ?_, ?_, ?_, hRole⟩ <;> rw [hr', hr]
  · show claimed' = claimed + r.command.amountCents
    simp only [claimImage] at e1
    omega
  · exact hL
  · exact hP
  · rfl

/-! Request codec round trip, one reader step at a time as in `Payment/CodecLaws.lean`. -/

local macro "step " h:term : tactic => `(tactic| (refine bind_step $h ?_; try dsimp only))

private theorem readClaimCommand_append (c : ClaimCommand) (rest : Bytes)
    (h1 : stringWireAdmissible c.claimId) (h2 : stringWireAdmissible c.evidenceId)
    (h3 : nat8WireAdmissible c.amountCents) (h4 : stringWireAdmissible c.ownerRole)
    (h5 : nat8WireAdmissible c.deadlineAt) :
    readClaimCommand (encodeClaimCommand c ++ rest) = some (c, rest) := by
  unfold readClaimCommand encodeClaimCommand
  simp only [List.append_assoc]
  step (readString_encodeString_append _ _ h1)
  step (readString_encodeString_append _ _ h2)
  step (readNat8_natBE_append _ _ h3)
  step (readString_encodeString_append _ _ h4)
  step (readNat8_natBE_append _ _ h5)
  rfl

private theorem readClaimForeign_append (f : ClaimForeign) (rest : Bytes) :
    readClaimForeign (encodeClaimForeign f ++ rest) = some (f, rest) := by
  obtain ⟨a, b⟩ := f
  cases a <;> cases b <;> rfl

private theorem parse_encode (r : ClaimRequest) (h : claimRequestWellFormed r = true)
    (hb : r.inputBytes = (rawEncodeFinancialInput r.input).length)
    (hl : (rawEncodeFinancialInput r.input).length ≤ maxTotalEncodedBytes) :
    parseClaimRequest (encodeClaimRequest r) = some r := by
  unfold claimRequestWellFormed at h
  simp only [Bool.and_eq_true, decide_eq_true_eq, and_assoc] at h
  obtain ⟨hIn, hCl, hEv, hAm, hRo, hTi, hEx⟩ := h
  have hW := inputWire_of_wellFormed hIn hl
  have hn : r.inputBytes < 256 ^ 4 := by rw [hb]; exact Nat.lt_of_le_of_lt hl (by decide)
  have hC : readClaimCommand (encodeClaimCommand r.command) = some (r.command, []) := by
    simpa using readClaimCommand_append r.command [] (idWire hCl) (idWire hEv)
      (cents8 hAm) (tokenWire hRo) (time8 (of_decide_eq_true hTi))
  have htk : ∀ Y, (rawEncodeFinancialInput r.input ++ Y).take r.inputBytes =
      rawEncodeFinancialInput r.input := fun Y => by rw [hb]; exact List.take_left' rfl
  have hdp : ∀ Y, (rawEncodeFinancialInput r.input ++ Y).drop r.inputBytes = Y := fun Y => by
    rw [hb]; exact List.drop_left' rfl
  have hEx' : optionNatWireAdmissible r.expectedRevision := by
    cases hq : r.expectedRevision with
    | none => trivial
    | some v =>
      rw [hq] at hEx
      exact Nat.lt_of_lt_of_le (of_decide_eq_true hEx) (by decide)
  unfold parseClaimRequest encodeClaimRequest
  simp only [List.append_assoc]
  rw [List.drop_left]
  step (readNatBE_natBE_append 4 _ _ hn)
  rw [htk, hdp]
  step (decodeFinancialInput_rawEncode _ hW)
  step (readClaimForeign_append _ _)
  step (readOptionNat_encodeOptionNat_append _ _ hEx')
  step hC
  rfl

theorem decodeClaimRequest_encode (r : ClaimRequest) (hw : claimRequestWellFormed r = true)
    (hn : r.inputBytes = (rawEncodeFinancialInput r.input).length)
    (hl : (rawEncodeFinancialInput r.input).length ≤ maxTotalEncodedBytes) :
    decodeClaimRequest (encodeClaimRequest r) = some r := by
  unfold decodeClaimRequest
  rw [parse_encode r hw hn hl]
  simp [Option.filter, hw, hn]

/-! Answer round trip. The rows come from `financialInputWellFormed post` (what `evaluate post` checks)
    and the result from `evaluate_resultWellFormed`; neither needs a byte bound on `post`, which the
    request's `inputBytes` field does not give. -/

private theorem case_mem {i : FinancialInput} {w : ClaimWrites} {k : CaseRecord} (h : w.case = some k) :
    k ∈ (applyClaim i w).cases := by
  simp only [applyClaim, h]
  split
  · rename_i hany
    obtain ⟨x, hx, hxk⟩ := List.any_eq_true.mp hany
    refine List.mem_map.mpr ⟨x, hx, ?_⟩
    rw [if_pos (of_decide_eq_true hxk)]
  · exact (mem_insertBy _ _ _ _).2 (Or.inl rfl)

private theorem claimed_rows {r : ClaimRequest} {w : ClaimWrites} {post : FinancialInput}
    {res : FinancialResult} (h : decideClaim r = .claimed w post res) :
    evidenceWireAdmissible w.evidence ∧ claimWireAdmissible w.claim ∧
      (∀ k, w.case = some k → caseWireAdmissible k) ∧ financialResultWellFormed res = true := by
  obtain ⟨-, -, -, -, -, -, -, -, -, -, -, hpost, hev⟩ := decideClaim_claimed h
  subst hpost
  obtain ⟨hWF, -⟩ := evaluate_facts hev
  unfold financialInputWellFormed at hWF
  simp only [envWellFormed, envOf, Bool.and_eq_true, decide_eq_true_eq, and_assoc] at hWF
  obtain ⟨-, -, -, -, -, -, -, -, -, -, -, -, -, -, -, -, -, -, -, -, -, -, -, -, -, -, -, -, -, -, -, -, hC, hEv, -, -, hCs, -, -⟩ := hWF
  exact ⟨evidenceWire (List.all_eq_true.mp hEv _ ((mem_insertBy _ _ _ _).2 (Or.inl rfl))),
    claimWire (List.all_eq_true.mp hC _ ((mem_insertBy _ _ _ _).2 (Or.inl rfl))),
    fun k hk => caseWire (List.all_eq_true.mp hCs _ (case_mem hk)), evaluate_resultWellFormed hev⟩

private theorem readByte_cons (b : UInt8) (X : Bytes) : readByte (b :: X) = some (b, X) := rfl

private theorem answer_claimed {w : ClaimWrites} {res : FinancialResult}
    (hE : evidenceWireAdmissible w.evidence) (hC : claimWireAdmissible w.claim)
    (hK : ∀ k, w.case = some k → caseWireAdmissible k) (hR : financialResultWireAdmissible res)
    (hn : (rawEncodeFinancialResult res).length < 256 ^ 4) :
    decodeClaimAnswer (rawEncodeClaimAnswer (.claimed w res)) = some (.claimed w res) := by
  have hp : parseClaimAnswer (rawEncodeClaimAnswer (.claimed w res)) = some (.claimed w res) := by
    unfold parseClaimAnswer rawEncodeClaimAnswer
    simp only [List.append_assoc, List.singleton_append, List.drop_left]
    step (readByte_cons _ _)
    rw [if_pos (show (UInt8.ofNat 1).toNat = 1 by decide)]
    step (decodeEvidence_encodeEvidence_append _ _ hE)
    step (decodeClaim_encodeClaim_append _ _ hC)
    step (readOpt_append _ fun k hk t => decodeCase_encodeCase_append k t (hK k hk))
    step (readNatBE_natBE_append 4 _ _ hn)
    rw [List.take_length]
    step (decodeFinancialResult_rawEncode res hR)
    rfl
  unfold decodeClaimAnswer
  rw [hp]
  simp [Option.filter]

theorem encodeClaimAnswer_some_unless_oversize (r : ClaimRequest) :
    (encodeClaimAnswer (decideClaim r).answer).isSome = true ∨
      maxTotalEncodedBytes < (rawEncodeClaimAnswer (decideClaim r).answer).length := by
  rcases Nat.lt_or_ge maxTotalEncodedBytes (rawEncodeClaimAnswer (decideClaim r).answer).length with hbig | hle
  · exact Or.inr hbig
  refine Or.inl ?_
  have hdec : decodeClaimAnswer (rawEncodeClaimAnswer (decideClaim r).answer) =
      some (decideClaim r).answer := by
    cases hd : decideClaim r with
    | claimed w post res =>
      obtain ⟨hE, hC, hK, hRes⟩ := claimed_rows hd
      rw [hd] at hle
      have hl : (rawEncodeFinancialResult res).length ≤ maxTotalEncodedBytes := by
        simp only [ClaimOutcome.answer, rawEncodeClaimAnswer, List.length_append] at hle
        omega
      exact answer_claimed hE hC hK (resultWire_of_wellFormed hRes hl) (Nat.lt_of_le_of_lt hl (by decide))
    | duplicate => decide +kernel
    | refused f => cases f <;> decide +kernel
  simp [encodeClaimAnswer, hle, hdec]

theorem claimRespond_length_le (w : Bytes) : (claimRespond w).length ≤ maxTotalEncodedBytes + 1 := by
  unfold claimRespond
  split
  · simp only [List.length_cons, List.length_nil]; omega
  · rename_i r _
    cases hb : encodeClaimAnswer (decideClaim r).answer with
    | none => simp only [List.length_cons, List.length_nil]; omega
    | some b =>
      have hlen : b.length ≤ maxTotalEncodedBytes := by
        unfold encodeClaimAnswer at hb
        dsimp only at hb
        split at hb
        · rename_i hfit
          cases hb
          exact hfit.1
        · cases hb
      simp only [List.length_cons]
      omega

-- Witness: a fresh claim on the correction KAT's pre-state is recorded and adds to claimed only.
def claimKatRequest : ClaimRequest :=
  let i := { CorrectionTransition.correctionKatInput with claims := [], evidence :=
    CorrectionTransition.correctionKatInput.evidence.filter (·.kind ≠ "OFFSET_CLAIM") }
  { input := i, inputBytes := (rawEncodeFinancialInput i).length,
    foreign := { claimId := false, evidenceId := false }, expectedRevision := some i.beforeRevision,
    command := { claimId := "claim:m4:kat", evidenceId := "evidence:m4:offset", amountCents := 125_000,
                 ownerRole := "CASE_OWNER", deadlineAt := 1_775_000_000_000 } }

#guard match decideClaim claimKatRequest with
  | .claimed w _ result => result.claimedAdjustmentCents == 125_000 && result.lawfulAdjustmentCents == 0 &&
      w.case.isSome && w.evidence.localRef == "offset:claim:m4:kat"
  | _ => false
#guard decodeClaimRequest (encodeClaimRequest claimKatRequest) |>.isSome
#guard match decideClaim { claimKatRequest with foreign := { claimId := true, evidenceId := false } } with
  | .refused .IDENTITY_CONFLICT => true
  | _ => false

end BlindLedger.Financial.Offset
