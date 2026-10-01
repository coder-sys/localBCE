import BlindLedger.Financial.Payment.Codec
import BlindLedger.Financial.Payment.ChainLaws
import BlindLedger.Financial.Worker
import BlindLedger.Financial.CodecLaws.CorrectionRecords

namespace BlindLedger.Financial.Payment

open BlindLedger.Financial BlindLedger.Financial.CorrectionTransition

/-! Form-A laws (design 5.1).  Well-formed BLFIN02 inputs are wire-admissible, so the
    existing BLFIN02 round trip applies to them. -/

private theorem lenWire {v : String} (h : v.toUTF8.toList.length ≤ 512) : stringWireAdmissible v :=
  stringWireAdmissible_of_length v (Nat.lt_of_le_of_lt h (by decide))

private theorem idWire {v : String} (h : idWellFormed v = true) : stringWireAdmissible v := by
  unfold idWellFormed maxIdBytes at h
  simp only [Bool.and_eq_true, decide_eq_true_eq] at h
  exact lenWire (Nat.le_trans h.1.2 (by decide))

private theorem textWire {v : String} (h : textWellFormed v = true) : stringWireAdmissible v := by
  unfold textWellFormed maxTextBytes at h
  simp only [Bool.and_eq_true, decide_eq_true_eq] at h
  exact lenWire h.1.2

private theorem tokenWire {v : String} (h : tokenWellFormed v = true) : stringWireAdmissible v := by
  unfold tokenWellFormed at h
  simp only [Bool.and_eq_true, decide_eq_true_eq] at h
  exact lenWire (Nat.le_trans h.1.2 (by decide))

private theorem usdWire : stringWireAdmissible "USD" := by
  apply stringWireAdmissible_of_length
  have hBytes := string_utf8_length_le "USD"
  have hChars : "USD".toList.length = 3 := by decide
  omega

private theorem nat8Wire {v b : Nat} (h : v ≤ b) (hb : b < 256 ^ 8) : nat8WireAdmissible v :=
  Nat.lt_of_le_of_lt h hb

private theorem cents8 {v : Nat} (h : v ≤ maxCents) : nat8WireAdmissible v := nat8Wire h maxCents_fits_u64
private theorem time8 {v : Nat} (h : v ≤ maxTime) : nat8WireAdmissible v := nat8Wire h maxTime_fits_u64
private theorem rev8 {v : Nat} (h : v ≤ maxRevision) : nat8WireAdmissible v :=
  nat8Wire h maxRevision_fits_u64

private theorem listWire {α : Type} {vs : List α} {P : α → Prop} (h : vs.length ≤ maxRows)
    (hP : ∀ x ∈ vs, P x) : wireListAdmissible vs P :=
  ⟨⟨h, Nat.lt_of_le_of_lt h (by decide)⟩, hP⟩

private theorem optIdWire {o : Option String} (h : optionalIdWellFormed o = true) :
    optionStringWireAdmissible o := by
  cases o with
  | none => trivial
  | some v => exact idWire h

private theorem digestWire {d : Bytes} (h : digestWellFormed d = true) : digestWireAdmissible d := by
  simpa [digestWellFormed, digestWireAdmissible] using h

private theorem contextWire {c : FinancialContext} (h : contextWellFormed c = true) :
    contextWireAdmissible c := by
  unfold contextWellFormed at h
  simp only [Bool.and_eq_true, decide_eq_true_eq, List.all_eq_true, and_assoc] at h
  obtain ⟨hI, hCur, _⟩ := h
  exact ⟨idWire (hI _ (by simp)), idWire (hI _ (by simp)), idWire (hI _ (by simp)),
    idWire (hI _ (by simp)), idWire (hI _ (by simp)), idWire (hI _ (by simp)),
    idWire (hI _ (by simp)), idWire (hI _ (by simp)), hCur ▸ usdWire⟩

private theorem authorityWire {a : TrustedAuthority} (h : authorityWellFormed a = true) :
    authorityWireAdmissible a := by
  unfold authorityWellFormed at h
  simp only [Bool.and_eq_true, decide_eq_true_eq, List.all_eq_true, and_assoc] at h
  obtain ⟨hId, -, hEpoch, hDig, -, -, hLen, -, hActors⟩ := h
  refine ⟨idWire hId, nat8Wire hEpoch maxCents_fits_u64, digestWire hDig,
    listWire hLen fun actor ha => ?_⟩
  have hA := hActors actor ha
  unfold authorityActorWellFormed at hA
  simp only [Bool.and_eq_true, decide_eq_true_eq, List.all_eq_true, and_assoc] at hA
  obtain ⟨hAId, -, hRLen, hRoles, -⟩ := hA
  exact ⟨idWire hAId, listWire hRLen fun r hr => tokenWire (hRoles r hr)⟩

private theorem packWire {p : ControlPack} (h : controlPackWellFormed p = true) :
    controlPackWireAdmissible p := by
  unfold controlPackWellFormed at h
  simp only [Bool.and_eq_true, decide_eq_true_eq, List.all_eq_true, and_assoc] at h
  obtain ⟨hI, hCur, -, hV, hSrc, hS, hE, hR, hA, -, -, hRoles, hTLen, hTests, hDig, -⟩ := h
  unfold sourceRefsWellFormed boundedTextList at hSrc
  simp only [Bool.and_eq_true, decide_eq_true_eq, List.all_eq_true] at hSrc
  unfold authorizedRolesWellFormed at hRoles
  simp only [Bool.and_eq_true, decide_eq_true_eq, List.all_eq_true, and_assoc] at hRoles
  unfold timeWellFormed at hS hE hR hA
  simp only [decide_eq_true_eq] at hS hE hR hA
  exact ⟨idWire (hI _ (by simp)), idWire (hI _ (by simp)), idWire (hI _ (by simp)),
    idWire (hI _ (by simp)), idWire (hI _ (by simp)), hCur ▸ usdWire, rev8 hV,
    listWire hSrc.2.1 fun s hs => textWire (hSrc.2.2 s hs), time8 hS, time8 hE, time8 hR, time8 hA,
    idWire (hI _ (by simp)), idWire (hI _ (by simp)),
    listWire hRoles.1 fun s hs => tokenWire (hRoles.2.1 s hs),
    listWire hTLen fun s hs => textWire (hTests s hs), digestWire hDig⟩

private theorem obligationWire {o : Obligation} (h : obligationWellFormed o = true) :
    obligationWireAdmissible o := by
  unfold obligationWellFormed positiveAmountWellFormed amountWellFormed timeWellFormed at h
  simp only [Bool.and_eq_true, decide_eq_true_eq, List.all_eq_true, and_assoc] at h
  obtain ⟨hI, -, hOwed, hDue, -, hRule⟩ := h
  exact ⟨idWire (hI _ (by simp)), idWire (hI _ (by simp)), idWire (hI _ (by simp)),
    cents8 hOwed, time8 hDue, rev8 hRule⟩

private theorem paymentWire {c : FinancialContext} {p : Payment}
    (h : paymentWellFormed c p = true) : paymentWireAdmissible p := by
  unfold paymentWellFormed positiveAmountWellFormed amountWellFormed timeWellFormed at h
  simp only [Bool.and_eq_true, decide_eq_true_eq, List.all_eq_true, and_assoc] at h
  obtain ⟨hI, -, -, -, hAmt, hTime, hRev⟩ := h
  exact ⟨idWire (hI _ (by simp)), idWire (hI _ (by simp)), idWire (hI _ (by simp)),
    idWire (hI _ (by simp)), idWire (hI _ (by simp)), cents8 hAmt, time8 hTime, optIdWire hRev⟩

private theorem claimWire {c : FinancialContext} {x : Claim} (h : claimWellFormed c x = true) :
    claimWireAdmissible x := by
  unfold claimWellFormed positiveAmountWellFormed amountWellFormed timeWellFormed at h
  simp only [Bool.and_eq_true, decide_eq_true_eq, List.all_eq_true, and_assoc] at h
  obtain ⟨hI, hRole, -, -, hAmt, hTime, _⟩ := h
  exact ⟨idWire (hI _ (by simp)), idWire (hI _ (by simp)), idWire (hI _ (by simp)),
    cents8 hAmt, tokenWire hRole, time8 hTime⟩

private theorem detWire {i : FinancialInput} {d : OffsetDetermination}
    (hEp : nat8WireAdmissible i.authority.epoch) (h : determinationWellFormed i d = true) :
    determinationWireAdmissible d := by
  unfold determinationWellFormed sameAuthority positiveAmountWellFormed amountWellFormed
    timeWellFormed revisionWellFormed canonicalIdList at h
  simp only [Bool.and_eq_true, decide_eq_true_eq, List.all_eq_true, and_assoc] at h
  obtain ⟨hI, hRole, -, -, hEq, -, hExp, -, hRes, -, -, hDig, -, hAmt, hTime, -, hSLen, hSAll, -, -, -, _⟩ := h
  exact ⟨idWire (hI _ (by simp)), idWire (hI _ (by simp)), idWire (hI _ (by simp)),
    idWire (hI _ (by simp)), tokenWire hRole, idWire (hI _ (by simp)), hEq ▸ hEp, digestWire hDig,
    cents8 hAmt, listWire hSLen fun s hs => idWire (hSAll s hs), rev8 hExp, rev8 hRes, time8 hTime⟩

private theorem evidenceWire {c : FinancialContext} {e : EvidenceRecord}
    (h : evidenceWellFormed c e = true) : evidenceWireAdmissible e := by
  unfold evidenceWellFormed timeWellFormed at h
  simp only [Bool.and_eq_true, decide_eq_true_eq, List.all_eq_true, and_assoc] at h
  obtain ⟨hI, hKind, -, -, hA, hE, hR, -, hM, hRev, hSup⟩ := h
  refine ⟨idWire (hI _ (by simp)), idWire (hI _ (by simp)), idWire (hI _ (by simp)),
    tokenWire hKind, idWire (hI _ (by simp)), idWire (hI _ (by simp)), idWire (hI _ (by simp)),
    idWire (hI _ (by simp)), time8 hA, time8 hE, time8 hR, ?_, optIdWire hRev, optIdWire hSup⟩
  cases hAm : e.amountCents with
  | none => trivial
  | some a => rw [hAm] at hM; exact cents8 (by simpa [amountWellFormed] using hM)

private theorem conflictWire {i : FinancialInput} {x : FinancialConflict}
    (h : conflictWellFormed i x = true) : conflictWireAdmissible x := by
  unfold conflictWellFormed positiveAmountWellFormed amountWellFormed timeWellFormed at h
  simp only [Bool.and_eq_true, decide_eq_true_eq, List.all_eq_true, and_assoc] at h
  obtain ⟨hI, -, -, hEx, -, hCa, hTime, _⟩ := h
  exact ⟨idWire (hI _ (by simp)), idWire (hI _ (by simp)), idWire (hI _ (by simp)),
    idWire (hI _ (by simp)), idWire (hI _ (by simp)), cents8 hEx, cents8 hCa,
    idWire (hI _ (by simp)), time8 hTime⟩

private theorem caseWire {i : FinancialInput} {x : CaseRecord} (h : caseWellFormed i x = true) :
    caseWireAdmissible x := by
  unfold caseWellFormed timeWellFormed at h
  simp only [Bool.and_eq_true, decide_eq_true_eq, List.all_eq_true, and_assoc] at h
  obtain ⟨hI, hRole, -, -, hDue, hUp⟩ := h
  exact ⟨idWire (hI _ (by simp)), idWire (hI _ (by simp)), idWire (hI _ (by simp)),
    tokenWire hRole, time8 hDue, time8 hUp⟩

private theorem findDetermination_mem : ∀ {l : List OffsetDetermination} {id : String}
    {d : OffsetDetermination}, findDetermination l id = some d → d ∈ l ∧ d.determinationId = id
  | [], _, _, h => by simp [findDetermination] at h
  | x :: xs, id, d, h => by
    unfold findDetermination at h
    split at h
    · rename_i hx
      obtain rfl := Option.some.inj h
      exact ⟨List.mem_cons_self, hx⟩
    · obtain ⟨hm, hi⟩ := findDetermination_mem h
      exact ⟨List.mem_cons_of_mem _ hm, hi⟩

private theorem actionWire {i : FinancialInput} {a : ActionRecord}
    (hCu : stringWireAdmissible i.context.currency)
    (hD : ∀ d ∈ i.determinations, stringWireAdmissible d.determinationId)
    (h : actionWellFormed i a = true) : actionWireAdmissible a := by
  unfold actionWellFormed positiveAmountWellFormed amountWellFormed timeWellFormed
    revisionWellFormed at h
  simp only [Bool.and_eq_true, decide_eq_true_eq, List.all_eq_true, and_assoc] at h
  obtain ⟨hI, -, -, hAmt, hCur, hRev, hDig, hTime, hB⟩ := h
  refine ⟨idWire (hI _ (by simp)), idWire (hI _ (by simp)), ?_, idWire (hI _ (by simp)),
    cents8 hAmt, ?_, rev8 hRev, digestWire hDig, time8 hTime⟩
  · unfold actionBindingWellFormed at hB
    cases hd : a.determinationId with
    | none => rw [hd] at hB; simp at hB
    | some id =>
      rw [hd] at hB
      dsimp only at hB
      cases hf : findDetermination i.determinations id with
      | none => rw [hf] at hB; simp at hB
      | some d =>
        obtain ⟨hm, rfl⟩ := findDetermination_mem hf
        exact hD d hm
  · rw [hCur]; exact hCu


theorem inputWire_of_wellFormed {i : FinancialInput} (h : financialInputWellFormed i = true)
    (hl : (rawEncodeFinancialInput i).length ≤ maxTotalEncodedBytes) :
    financialInputWireAdmissible i := by
  have hWF := h
  unfold financialInputWellFormed at h
  simp only [envWellFormed, envOf, Bool.and_eq_true, decide_eq_true_eq, and_assoc] at h
  obtain ⟨hCtx, hAuth, hPack, hObl, -, hBef, hEval, -, -, -, -, -, -, -, -, -, hPL, hCL, hDL, hEL,
    hFL, -, hCsL, hAL, -, -, -, -, -, -, -, hP, hC, hEv, hD, hF, hCs, hA, -⟩ := h
  have hAuthW := authorityWire hAuth
  have hCtxW := contextWire hCtx
  have hDetW : ∀ d ∈ i.determinations, determinationWireAdmissible d := fun d hd =>
    detWire hAuthW.2.1 (List.all_eq_true.mp hD d hd)
  exact ⟨hWF, hCtxW, hAuthW, packWire hPack, obligationWire hObl,
    rev8 (by simpa [revisionWellFormed] using hBef), time8 (by simpa [timeWellFormed] using hEval),
    listWire hPL fun p hp => paymentWire (List.all_eq_true.mp hP p hp),
    listWire hCL fun x hx => claimWire (List.all_eq_true.mp hC x hx),
    listWire hDL hDetW,
    listWire hEL fun x hx => evidenceWire (List.all_eq_true.mp hEv x hx),
    listWire hFL fun x hx => conflictWire (List.all_eq_true.mp hF x hx),
    listWire hCsL fun x hx => caseWire (List.all_eq_true.mp hCs x hx),
    listWire hAL fun x hx => actionWire hCtxW.2.2.2.2.2.2.2.2 (fun d hd => (hDetW d hd).1)
      (List.all_eq_true.mp hA x hx), hl⟩

/-! Reader round trips (one `do` step at a time, as in `CodecLaws/Correction.lean`). -/

private theorem bind_step {α β : Type} {x : Option α} {a : α} {f : α → Option β} {y : Option β}
    (hx : x = some a) (hf : f a = y) : (x >>= f) = y := by
  subst hx; exact hf

local macro "step " h:term : tactic => `(tactic| (refine bind_step $h ?_; try dsimp only))

private theorem optAllWire {o : Option String} (h : o.all idWellFormed = true) :
    optionStringWireAdmissible o := by
  cases o with
  | none => trivial
  | some v => exact idWire h

private theorem optNonEmptyWire {o : Option String} (h : (nonEmpty o).all idWellFormed = true) :
    optionStringWireAdmissible o := by
  cases o with
  | none => trivial
  | some v =>
    by_cases hv : v = ""
    · subst hv
      apply stringWireAdmissible_of_length
      have := string_utf8_length_le ""
      have h0 : "".toList.length = 0 := rfl
      omega
    · exact idWire (by simpa [nonEmpty, hv] using h)

private theorem opt63Wire {o : Option Nat} (h : o.all (· < 2 ^ 63) = true) :
    optionNatWireAdmissible o := by
  cases o with
  | none => trivial
  | some v => exact Nat.lt_of_lt_of_le (of_decide_eq_true h) (by decide)

private theorem readReceipt_append (k : Receipt) (rest : Bytes)
    (h1 : stringWireAdmissible k.paymentId) (h2 : nat8WireAdmissible k.recordedRevision)
    (h3 : optionStringWireAdmissible k.paysActionId) :
    readReceipt (encodeReceipt k ++ rest) = some (k, rest) := by
  unfold readReceipt encodeReceipt
  simp only [List.append_assoc]
  step (readString_encodeString_append _ _ h1)
  step (readNat8_natBE_append _ _ h2)
  step (readOptionString_encodeOptionString_append _ _ h3)
  rfl

private theorem readForeign_append (f : Foreign) (rest : Bytes) :
    readForeign (encodeForeign f ++ rest) = some (f, rest) := by
  cases f with | mk a b => cases a <;> cases b <;> rfl

private theorem readCommand_append (c : Command) (rest : Bytes) (h : commandWellFormed c = true) :
    readCommand (encodeCommand c ++ rest) = some (c, rest) := by
  unfold commandWellFormed at h
  cases c with
  | record c =>
    simp only [Bool.and_eq_true, decide_eq_true_eq, List.all_eq_true, and_assoc] at h
    obtain ⟨hI, hL, hP, hAmt, hTime⟩ := h
    unfold encodeCommand readCommand
    simp only [List.cons_append, List.append_assoc]
    step rfl
    rw [if_pos (by decide)]
    step (readString_encodeString_append _ _ (idWire (hI _ (by simp))))
    step (readString_encodeString_append _ _ (idWire (hI _ (by simp))))
    step (readString_encodeString_append _ _ (idWire (hI _ (by simp))))
    step (readString_encodeString_append _ _ (idWire (hI _ (by simp))))
    step (readString_encodeString_append _ _ (idWire (hI _ (by simp))))
    step (readOptionString_encodeOptionString_append _ _ (optNonEmptyWire hL))
    step (readNat8_natBE_append _ _ (cents8 hAmt))
    step (readNat8_natBE_append _ _ (Nat.lt_of_lt_of_le hTime (by decide)))
    step (readOptionString_encodeOptionString_append _ _ (optAllWire hP))
    rfl
  | reverse c =>
    simp only [Bool.and_eq_true, and_assoc] at h
    obtain ⟨hP, hE, hO, hT⟩ := h
    unfold encodeCommand readCommand
    simp only [List.cons_append, List.append_assoc]
    step rfl
    rw [if_neg (by decide), if_pos (by decide)]
    step (readString_encodeString_append _ _ (idWire hP))
    step (readString_encodeString_append _ _ (idWire hE))
    step (readOptionString_encodeOptionString_append _ _ (optNonEmptyWire hO))
    step (readOptionNat_encodeOptionNat_append _ _ (opt63Wire hT))
    rfl

private theorem drop_header (b : UInt8) (Y : Bytes) :
    (paymentMagic ++ (b :: Y)).drop (paymentMagic.length + 1) = Y := by
  rw [show paymentMagic.length + 1 = (paymentMagic ++ [b]).length by simp,
    show paymentMagic ++ (b :: Y) = (paymentMagic ++ [b]) ++ Y by simp]
  exact List.drop_left

private theorem parse_encode (r : PaymentRequest) (h : requestWellFormed r = true)
    (hb : r.inputBytes = (rawEncodeFinancialInput r.input).length)
    (hfit : (encodePaymentRequest r).length ≤ maxWorkerFrameBytes) :
    parsePaymentRequest (encodePaymentRequest r) = some r := by
  have hl : (rawEncodeFinancialInput r.input).length ≤ maxTotalEncodedBytes := by
    have := hfit
    simp only [encodePaymentRequest, List.length_append, length_natBE, List.length_singleton] at this
    unfold maxWorkerFrameBytes at this
    omega
  unfold requestWellFormed at h
  simp only [Bool.and_eq_true, and_assoc] at h
  obtain ⟨hIn, hRc, hCm, hEx⟩ := h
  have hW := inputWire_of_wellFormed hIn hl
  unfold receiptsWellFormed at hRc
  simp only [Bool.and_eq_true, decide_eq_true_eq, List.all_eq_true, beq_iff_eq] at hRc
  obtain ⟨hMap, hAll⟩ := hRc
  have hCount : r.receipts.length ≤ maxRows := by
    have := congrArg List.length hMap
    simp only [List.length_map] at this
    exact this ▸ hW.2.2.2.2.2.2.2.1.1.1
  have hRec : ∀ k ∈ r.receipts, ∀ tail, readReceipt (encodeReceipt k ++ tail) = some (k, tail) := by
    intro k hk tail
    obtain ⟨hRev, hAct⟩ := hAll k hk
    have hid : stringWireAdmissible k.paymentId := by
      have hm : k.paymentId ∈ r.input.payments.map Payment.paymentId := by
        rw [← hMap]; exact List.mem_map.mpr ⟨k, hk, rfl⟩
      obtain ⟨p, hp, hpe⟩ := List.mem_map.mp hm
      exact hpe ▸ (hW.2.2.2.2.2.2.2.1.2 p hp).1
    exact readReceipt_append k tail hid (Nat.lt_trans hRev hW.2.2.2.2.2.1) (optAllWire hAct)
  have hn : r.inputBytes < 256 ^ 4 := hb ▸ Nat.lt_of_le_of_lt hl (by decide)
  have htk : ∀ Y, (rawEncodeFinancialInput r.input ++ Y).take r.inputBytes =
      rawEncodeFinancialInput r.input := fun Y => by rw [hb]; exact List.take_left' rfl
  have hdp : ∀ Y, (rawEncodeFinancialInput r.input ++ Y).drop r.inputBytes = Y := fun Y => by
    rw [hb]; exact List.drop_left' rfl
  unfold parsePaymentRequest encodePaymentRequest
  simp only [List.append_assoc, List.cons_append]
  rw [drop_header]
  step (readNatBE_natBE_append 4 _ _ hn)
  rw [htk, hdp]
  step (decodeFinancialInput_rawEncode _ hW)
  step (readList_encodeList_append_of_mem encodeReceipt readReceipt r.receipts _ hCount
    (Nat.lt_of_le_of_lt hCount (by decide)) fun k hk tail => hRec k hk tail)
  step (readForeign_append _ _)
  step (readOptionNat_encodeOptionNat_append _ _ (opt63Wire hEx))
  step (by simpa using readCommand_append r.command [] hCm)
  rfl

private theorem decode_facts {w : Bytes} {r : PaymentRequest}
    (h : decodePaymentRequest w = some r) :
    requestWellFormed r = true ∧ r.inputBytes = (rawEncodeFinancialInput r.input).length ∧
      encodePaymentRequest r = w := by
  unfold decodePaymentRequest at h
  cases hp : parsePaymentRequest w with
  | none => rw [hp] at h; simp [Option.filter] at h
  | some r0 =>
    rw [hp] at h
    simp only [Option.filter] at h
    split at h
    · rename_i hc
      obtain rfl := Option.some.inj h
      simpa [Bool.and_eq_true, beq_iff_eq, and_assoc] using hc
    · simp at h

theorem decodePaymentRequest_wellFormed {w : Bytes} {r : PaymentRequest}
    (h : decodePaymentRequest w = some r) :
    requestWellFormed r = true ∧ r.inputBytes = (rawEncodeFinancialInput r.input).length :=
  ⟨(decode_facts h).1, (decode_facts h).2.1⟩

theorem decodePaymentRequest_canonical {w : Bytes} {r : PaymentRequest}
    (h : decodePaymentRequest w = some r) : encodePaymentRequest r = w :=
  (decode_facts h).2.2

theorem decodePaymentRequest_encode (r : PaymentRequest) (h : requestWellFormed r = true)
    (hb : r.inputBytes = (rawEncodeFinancialInput r.input).length)
    (hfit : (encodePaymentRequest r).length ≤ maxWorkerFrameBytes) :
    decodePaymentRequest (encodePaymentRequest r) = some r := by
  unfold decodePaymentRequest
  rw [parse_encode r h hb hfit]
  simp [Option.filter, h, hb]

theorem paymentMagic_disjoint : ¬ (paymentMagic.isPrefixOf financialCodecMagic = true ∨
    financialCodecMagic.isPrefixOf paymentMagic = true) := by
  have hU : ∀ s : String, s.toUTF8.toList = s.toList.flatMap String.utf8EncodeChar := fun s => by
    rw [byteArray_toList_eq, String.toUTF8_eq_toByteArray, ← String.utf8Encode_toList]
    unfold List.utf8Encode
    rw [List.toList_data_toByteArray]
  simp only [paymentMagic, financialCodecMagic, hU]
  decide

section FormBRoundTrip

private theorem drop_hdr {α : Type} (l : List α) (a : α) (b : List α) :
    (l ++ a :: b).drop (l.length + 1) = b := by
  have h := List.drop_left (l₁ := l ++ [a]) (l₂ := b)
  simpa [List.length_append] using h

private theorem readOpt_append {α : Type} {f : Bytes → Option (α × Bytes)} {g : α → Bytes}
    {o : Option α} (rest : Bytes) (h : ∀ a, o = some a → ∀ t, f (g a ++ t) = some (a, t)) :
    readOpt f (encodeOpt g o ++ rest) = some (o, rest) := by
  cases o with
  | none => simp [encodeOpt, readOpt, readByte]
  | some a => simp [encodeOpt, readOpt, readByte, h a rfl rest]

private theorem all_some {α : Type} {o : Option α} {p : α → Bool} (h : o.all p = true) {a : α}
    (ha : o = some a) : p a = true := by
  subst ha; exact h

private theorem encodeList_def {α : Type} (enc : α → Bytes) (vs : List α) :
    encodeList enc vs = natBE 2 vs.length ++ vs.flatMap enc := rfl

private theorem readContribution_append (x : EvalContribution) (t : Bytes)
    (h1 : nat8WireAdmissible x.time) (h2 : stringWireAdmissible x.identity)
    (h3 : nat8WireAdmissible x.amountCents) :
    readContribution (encodeContribution x ++ t) = some (x, t) := by
  unfold readContribution encodeContribution
  simp only [List.append_assoc]
  step (readNat8_natBE_append _ _ h1)
  step (readString_encodeString_append _ _ h2)
  step (readNat8_natBE_append _ _ h3)
  rfl

private theorem readRequestPaid_append (x : RequestPaid) (t : Bytes)
    (h1 : stringWireAdmissible x.actionId) (h2 : nat8WireAdmissible x.amountCents)
    (h3 : nat8WireAdmissible x.paidCents) :
    readRequestPaid (encodeRequestPaid x ++ t) = some (x, t) := by
  unfold readRequestPaid encodeRequestPaid
  simp only [List.append_assoc]
  step (readString_encodeString_append _ _ h1)
  step (readNat8_natBE_append _ _ h2)
  step (readNat8_natBE_append _ _ h3)
  rfl

private theorem readEnv_append (e : Env) (rest : Bytes) (h : envWellFormed e = true) :
    readEnv (encodeEnv e ++ rest) = some (e, rest) := by
  simp only [envWellFormed, Bool.and_eq_true, decide_eq_true_eq, and_assoc] at h
  obtain ⟨hC, hA, hP, hO, hB, -, hT, -⟩ := h
  unfold readEnv encodeEnv
  simp only [List.append_assoc]
  step (decodeContext_encodeContext_append _ _ (contextWire hC))
  step (decodeAuthority_encodeAuthority_append _ _ (authorityWire hA))
  step (decodeControlPack_encodeControlPack_append _ _ (packWire hP))
  step (decodeObligation_encodeObligation_append _ _ (obligationWire hO))
  step (readNat8_natBE_append _ _ (rev8 (Nat.le_of_lt hB)))
  step (readNat8_natBE_append _ _ (time8 (by simpa [timeWellFormed] using hT)))
  rfl

private theorem env_before_lt {e : Env} (h : envWellFormed e = true) :
    e.beforeRevision < maxRevision := by
  simp only [envWellFormed, Bool.and_eq_true, decide_eq_true_eq, and_assoc] at h
  obtain ⟨-, -, -, -, hB, -⟩ := h
  exact hB

private theorem readItemState_append (s : ItemState) (rest : Bytes) (h : stateWellFormed s = true) :
    readItemState (encodeItemState s ++ rest) = some (s, rest) := by
  simp only [stateWellFormed, Bool.and_eq_true, decide_eq_true_eq, and_assoc] at h
  obtain ⟨hRev, hCash, hCl, hLaw, hCN, hCon, hCC, hEL, hEC, hRL, hReq, hAB⟩ := h
  simp only [canonicalIdList, Bool.and_eq_true, decide_eq_true_eq] at hEC
  unfold readItemState encodeItemState
  rw [encodeList_def encodeContribution s.contributions]
  simp only [List.append_assoc, List.cons_append]
  step (readNat8_natBE_append _ _ (rev8 (Nat.le_of_lt hRev)))
  step (readNat8_natBE_append _ _ (cents8 hCash))
  step (readNat8_natBE_append _ _ (cents8 hCl))
  step (readNat8_natBE_append _ _ (cents8 hLaw))
  step (readNatBE_natBE_append 2 s.contributions.length _
    (Nat.lt_of_le_of_lt hCN (by unfold maxRows; decide)))
  rw [if_neg (by omega)]
  step (readMany_flatMap_append_of_mem encodeContribution readContribution s.contributions _
    (fun x hx t => by
      have hx2 := List.all_eq_true.mp hCon x hx
      simp only [Bool.and_eq_true, decide_eq_true_eq] at hx2
      exact readContribution_append x t (time8 (by simpa [timeWellFormed] using hx2.1.1))
        (idWire hx2.1.2) (cents8 hx2.2)))
  step rfl
  step (decodeCaseStatus_encodeCaseStatus _)
  step rfl
  step (decodeDeliveryStatus_encodeDeliveryStatus _)
  step (readNatBE_natBE_append 2 s.conflictCount _ (Nat.lt_of_le_of_lt hCC maxRows_fits_u16))
  step (readList_encodeString_append s.evidenceIds _ hEL
    (fun v hv => idWire (List.all_eq_true.mp hEC.1.2 v hv)))
  step (readList_encodeList_append_of_mem encodeRequestPaid readRequestPaid s.requests _ hRL
    (Nat.lt_of_le_of_lt hRL maxRows_fits_u16)
    (fun q hq t => by
      have hq2 := List.all_eq_true.mp hReq q hq
      simp only [Bool.and_eq_true, decide_eq_true_eq] at hq2
      exact readRequestPaid_append q t (idWire hq2.1.1) (cents8 hq2.1.2) (cents8 hq2.2)))
  step (readNatBE_natBE_append 4 s.anchorBytes _
    (Nat.lt_of_le_of_lt hAB (by unfold maxTotalEncodedBytes; decide)))
  rfl

private theorem parseFormB_encode (v : PaymentView) (hw : viewWellFormed v = true) :
    parseFormB (encodeFormB v) = some v := by
  simp only [viewWellFormed, Bool.and_eq_true, decide_eq_true_eq, and_assoc] at hw
  obtain ⟨hEnv, hSt, hPL, -, hPA, hId, hOr, hEv, hCmd, hEx⟩ := hw
  have hB := env_before_lt hEnv
  unfold parseFormB encodeFormB
  simp only [List.append_assoc, List.cons_append, List.nil_append]
  rw [drop_hdr]
  step (readEnv_append _ _ hEnv)
  step (readItemState_append _ _ hSt)
  step (readList_encodeList_append_of_mem encodeEvidence decodeEvidence v.pending _ hPL
    (Nat.lt_of_le_of_lt hPL maxRows_fits_u16)
    (fun e he t => decodeEvidence_encodeEvidence_append e t
      (evidenceWire (List.all_eq_true.mp hPA e he))))
  step (readOpt_append _ (fun a ha t => by
    have hr := all_some hId ha
    simp only [Bool.and_eq_true, decide_eq_true_eq, and_assoc] at hr
    obtain ⟨hp, hk, hlt, hpa⟩ := hr
    simp only [List.append_assoc]
    step (decodePayment_encodePayment_append _ _ (paymentWire hp))
    step (readReceipt_append _ _ (by rw [hk]; exact (paymentWire hp).1) (rev8 (by omega))
      (optAllWire hpa))
    rfl))
  step (readOpt_append _ (fun a ha t => by
    have hr := all_some hOr ha
    simp only [Bool.and_eq_true, decide_eq_true_eq, and_assoc] at hr
    obtain ⟨hp, hk, hlt, hpa, hev⟩ := hr
    simp only [List.append_assoc]
    step (decodePayment_encodePayment_append _ _ (paymentWire hp))
    step (readReceipt_append _ _ (by rw [hk]; exact (paymentWire hp).1) (rev8 (by omega))
      (optAllWire hpa))
    step (readOpt_append _ (fun e he t => decodeEvidence_encodeEvidence_append e t
      (evidenceWire (all_some hev he))))
    rfl))
  step (readOpt_append _ (fun e he t => decodeEvidence_encodeEvidence_append e t
    (evidenceWire (all_some hEv he))))
  step (readBool_encodeBool_append _ _)
  step (readForeign_append _ _)
  step (readOptionNat_encodeOptionNat_append _ _ (opt63Wire hEx))
  have hc := readCommand_append v.command [] hCmd
  rw [List.append_nil] at hc
  step hc
  rfl

end FormBRoundTrip

theorem decodePaymentItem_encode (v : PaymentView) (hw : viewWellFormed v = true)
    (hc : coherent v = true) : decodePaymentItem (encodeFormB v) = some v := by
  have hp := parseFormB_encode v hw
  have h1 : (encodeFormB v).drop paymentMagic.length =
      UInt8.ofNat 2 :: (encodeFormB v).drop (paymentMagic.length + 1) := by
    unfold encodeFormB
    simp only [List.append_assoc, List.cons_append, List.nil_append]
    rw [List.drop_left, drop_hdr]
  unfold decodePaymentItem
  rw [h1]
  simp [hp, hw, hc]

theorem refusals_complete (f : Refusal) : f ∈ refusals := by
  cases f <;> simp [refusals]

end BlindLedger.Financial.Payment
