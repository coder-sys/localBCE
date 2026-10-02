import BlindLedger.Financial.Worker
import BlindLedger.Financial.CodecLaws.CorrectionRecords
import BlindLedger.Financial.Theorems.Correspondence

namespace BlindLedger.Financial

/-! What the worker's frames prove.  The outcome codec round-trips, tag 0 carries
    exactly the specified evaluation of the decoded input, and no response exceeds
    the frame bound (which fits the u32 length prefix). -/

theorem decodeWorkerOutcome_encodeWorkerOutcome (outcome : WorkerOutcome) :
    decodeWorkerOutcome (encodeWorkerOutcome outcome) = some outcome := by
  cases outcome <;> simp [encodeWorkerOutcome, decodeWorkerOutcome]

private theorem idWire {value : String} (h : idWellFormed value = true) :
    stringWireAdmissible value := by
  refine CorrectionTransition.stringWireAdmissible_of_length value ?_
  unfold idWellFormed at h
  simp only [Bool.and_eq_true, decide_eq_true_eq] at h
  have hLen := h.1.2
  unfold maxIdBytes at hLen
  omega

private theorem nat8Wire {value bound : Nat} (h : value ≤ bound) (hBound : bound < 256 ^ 8) :
    nat8WireAdmissible value :=
  Nat.lt_of_le_of_lt h hBound

/-- Every well-formed result whose canonical bytes fit the cap is wire-admissible. -/
private theorem resultWire_of_wellFormed {result : FinancialResult}
    (hWell : financialResultWellFormed result = true)
    (hLen : (rawEncodeFinancialResult result).length ≤ maxTotalEncodedBytes) :
    financialResultWireAdmissible result := by
  have hWell0 := hWell
  have hCents : maxCents < 256 ^ 8 := by decide
  have hRevisions : maxRevision < 256 ^ 8 := by decide
  have hRows : maxRows < 256 ^ 2 := by decide
  unfold financialResultWellFormed contextWellFormed at hWell
  simp only [Bool.and_eq_true, decide_eq_true_eq, List.all_eq_true, amountWellFormed,
    positiveAmountWellFormed, timeWellFormed, revisionWellFormed, digestWellFormed,
    canonicalIdList, and_assoc] at hWell
  obtain ⟨hCtx, hCurrency, _, hAuthorityId, _, hEpoch, hAuthorityDigest, hPackId, hPackDigest,
    _, hBefore, _, hAfter, hEvaluated, _, hRule, hIdsLen, hIdsAll, _, hCompletion, _, hOwed,
    hClaimed, hLawful, hCash, hShortfall, hOverage⟩ := hWell
  refine ⟨hWell0, ⟨idWire (hCtx _ (by simp)), idWire (hCtx _ (by simp)), idWire (hCtx _ (by simp)),
    idWire (hCtx _ (by simp)), idWire (hCtx _ (by simp)), idWire (hCtx _ (by simp)),
    idWire (hCtx _ (by simp)), idWire (hCtx _ (by simp)), ?_⟩, idWire hAuthorityId,
    nat8Wire hEpoch hCents, hAuthorityDigest, idWire hPackId, hPackDigest, nat8Wire hBefore hRevisions,
    nat8Wire hAfter hRevisions, nat8Wire hEvaluated hCents, nat8Wire hRule hRevisions,
    ⟨⟨hIdsLen, Nat.lt_of_le_of_lt hIdsLen hRows⟩, fun value hValue => idWire (hIdsAll value hValue)⟩,
    ?_, nat8Wire hOwed hCents, nat8Wire hClaimed hCents, nat8Wire hLawful hCents,
    nat8Wire hCash hCents, nat8Wire hShortfall hCents, nat8Wire hOverage hCents, hLen⟩
  · rw [hCurrency]
    refine CorrectionTransition.stringWireAdmissible_of_length _ ?_
    have hBytes := CorrectionTransition.string_utf8_length_le "USD"
    have hChars : "USD".toList.length = 3 := by decide
    omega
  · cases hDone : result.completionAt with
    | none => trivial
    | some completion =>
        rw [hDone] at hCompletion
        exact nat8Wire (bound := maxTime) (by simpa using hCompletion) hCents

/-- A result the encoder accepts is wire-admissible, so the decoder returns it. -/
private theorem admissible_of_encoded {result : FinancialResult} {wire : Bytes}
    (h : encodeFinancialResult result = some wire) :
    financialResultWireAdmissible result ∧ wire.length ≤ maxTotalEncodedBytes := by
  unfold encodeFinancialResult at h
  by_cases hWell : financialResultWellFormed result = true
  · by_cases hLen : (rawEncodeFinancialResult result).length ≤ maxTotalEncodedBytes
    · simp only [hWell, hLen, if_true] at h
      obtain rfl := Option.some.inj h
      exact ⟨resultWire_of_wellFormed hWell hLen, hLen⟩
    · simp [hWell, hLen] at h
  · simp [hWell] at h

theorem evaluateWire_evaluated {wire result : Bytes}
    (h : evaluateWire wire = .evaluated result) :
    ∃ input decided,
      decodeFinancialInput wire = some input ∧
      evaluate input = some decided ∧
      satisfiesSpecification input decided ∧
      decodeFinancialResult result = some decided ∧
      result.length ≤ maxTotalEncodedBytes := by
  unfold evaluateWire at h
  rw [Fast.decodeFinancialInputFast_eq] at h
  cases hIn : decodeFinancialInput wire with
  | none => simp [hIn] at h
  | some input =>
      cases hEval : evaluate input with
      | none => simp [hIn, hEval] at h
      | some decided =>
          cases hEnc : encodeFinancialResult decided with
          | none => simp [hIn, hEval, hEnc] at h
          | some output =>
              simp [hIn, hEval, hEnc] at h
              subst h
              have hAdm := admissible_of_encoded hEnc
              exact ⟨input, decided, rfl, hEval, evaluate_satisfies_specification input decided hEval,
                decodeFinancialResult_of_encodeFinancialResult decided hAdm.1 output hEnc, hAdm.2⟩

private theorem prefix_exclusive {a b w : Bytes} (hab : a.isPrefixOf b = false) (hba : b.isPrefixOf a = false)
    (ha : a.isPrefixOf w = true) : b.isPrefixOf w = false := by
  cases hb : b.isPrefixOf w
  · rfl
  · rw [List.isPrefixOf_iff_prefix] at hb ha
    rcases List.prefix_or_prefix_of_prefix ha hb with h | h
    · rw [← List.isPrefixOf_iff_prefix] at h; simp [h] at hab
    · rw [← List.isPrefixOf_iff_prefix] at h; simp [h] at hba

private theorem magics_apart : Payment.paymentMagic.isPrefixOf CorrectionTransition.correctionTransitionInputMagic = false ∧
    CorrectionTransition.correctionTransitionInputMagic.isPrefixOf Payment.paymentMagic = false := by decide +kernel

/-- Every BLFIN02 frame is answered by the evaluator, whatever item kinds the worker also serves
    (E1: replaces `workerRespond_evaluator_unchanged`, which a second item kind falsifies). -/
theorem workerRespond_evaluator_frames (w : Bytes) (h : financialCodecMagic.isPrefixOf w = true) :
    workerRespond w = encodeWorkerOutcome (evaluateWire w) := by
  have hp := prefix_exclusive (b := Payment.paymentMagic) (by decide +kernel) (by decide +kernel) h
  have hc := prefix_exclusive (b := CorrectionTransition.correctionTransitionInputMagic) (by decide +kernel) (by decide +kernel) h
  simp [workerRespond, hp, hc]

/-- E1: the same conclusion; the hypothesis names every item magic. -/
theorem workerRespond_evaluator_unchanged₂ (w : Bytes)
    (h : itemMagics.all (fun m => !m.isPrefixOf w) = true) :
    workerRespond w = encodeWorkerOutcome (evaluateWire w) := by
  simp only [itemMagics, List.all_cons, List.all_nil, Bool.and_true, Bool.and_eq_true,
    Bool.not_eq_true'] at h
  simp [workerRespond, h.1, h.2]

theorem workerRespond_payment (w : Bytes) (h : Payment.paymentMagic.isPrefixOf w = true) :
    workerRespond w = Payment.paymentRespond w := by
  simp [workerRespond, h]

theorem workerRespond_correction (w : Bytes)
    (h : CorrectionTransition.correctionTransitionInputMagic.isPrefixOf w = true) :
    workerRespond w = correctionRespond w := by
  simp [workerRespond, prefix_exclusive magics_apart.2 magics_apart.1 h, h]

/-- A correction answer is a BLFCRES3 result whenever its request decodes and the result fits (N2 on the worker frame). -/
theorem correctionRespond_decoded (w : Bytes) (request : CorrectionTransition.CorrectionTransitionRequest)
    (h : CorrectionTransition.decodeCorrectionTransitionRequest w = some request) :
    correctionRespond w = [UInt8.ofNat 3] ∨
      ∃ b, CorrectionTransition.encodeCorrectionTransitionResult
          (CorrectionTransition.applyCorrectionTransition request) = some b ∧
        correctionRespond w = UInt8.ofNat 0 :: b := by
  unfold correctionRespond
  rw [h]
  dsimp only
  cases hres : CorrectionTransition.encodeCorrectionTransitionResult
      (CorrectionTransition.applyCorrectionTransition request) with
  | none => exact Or.inl rfl
  | some b => exact Or.inr ⟨b, rfl, rfl⟩

private theorem Payment.encodeStepOutcome_length_le {o : Payment.StepOutcome} {b : Bytes}
    (h : Payment.encodeStepOutcome o = some b) : b.length ≤ maxTotalEncodedBytes := by
  unfold Payment.encodeStepOutcome at h
  dsimp only at h
  split at h
  · simp only [Option.some.injEq] at h; subst h; omega
  · simp at h

theorem paymentRespond_length_le (w : Bytes) :
    (Payment.paymentRespond w).length ≤ maxWorkerFrameBytes := by
  unfold Payment.paymentRespond maxWorkerFrameBytes
  cases Payment.decodePaymentItem w with
  | none => simp
  | some v =>
    cases hE : Payment.encodeStepOutcome (Payment.stepView v) with
    | none => simp [hE]
    | some b =>
      have := Payment.encodeStepOutcome_length_le hE
      simp only [hE, List.length_cons]
      omega

private theorem correctionResult_length_le {r : CorrectionTransition.CorrectionTransitionResult} {b : Bytes}
    (h : CorrectionTransition.encodeCorrectionTransitionResult r = some b) : b.length ≤ maxTotalEncodedBytes := by
  unfold CorrectionTransition.encodeCorrectionTransitionResult at h
  dsimp only at h
  split at h
  · simp at h
  · cases hm : CorrectionTransition.encodeOptionalMutation r.mutation <;> simp [hm] at h
    split at h <;>
    · obtain ⟨h1, rfl⟩ := h
      simp only [List.length_append, List.length_cons]
      unfold CorrectionTransition.maxCorrectionTransitionBytes at h1
      omega

theorem correctionRespond_length_le (w : Bytes) :
    (correctionRespond w).length ≤ maxWorkerFrameBytes := by
  unfold correctionRespond maxWorkerFrameBytes
  cases CorrectionTransition.decodeCorrectionTransitionRequest w with
  | none => simp
  | some request =>
    cases hE : CorrectionTransition.encodeCorrectionTransitionResult
        (CorrectionTransition.applyCorrectionTransition request) with
    | none => simp [hE]
    | some b =>
      have := correctionResult_length_le hE
      simp only [hE, List.length_cons]
      omega

theorem workerRespond_length_le (wire : Bytes) :
    (workerRespond wire).length ≤ maxWorkerFrameBytes := by
  by_cases hm : Payment.paymentMagic.isPrefixOf wire = true
  · rw [workerRespond_payment wire hm]; exact paymentRespond_length_le wire
  by_cases hc : CorrectionTransition.correctionTransitionInputMagic.isPrefixOf wire = true
  · rw [workerRespond_correction wire hc]; exact correctionRespond_length_le wire
  rw [workerRespond_evaluator_unchanged₂ wire
    (by simp [itemMagics, hm, hc])]
  unfold maxWorkerFrameBytes
  cases hOut : evaluateWire wire with
  | evaluated result =>
      obtain ⟨_, _, _, _, _, _, hLen⟩ := evaluateWire_evaluated hOut
      simp only [encodeWorkerOutcome, List.length_cons]
      omega
  | decodeRejected => simp [encodeWorkerOutcome]
  | evaluationRejected => simp [encodeWorkerOutcome]
  | encodingRejected => simp [encodeWorkerOutcome]

theorem maxWorkerFrameBytes_fits_u32 : maxWorkerFrameBytes < 256 ^ 4 := by
  decide


/-! The worker's loop.  `serveWorker` runs on any monad; here it runs on a pure pipe, a byte stream that hands back
    at least one byte per read and any chunking the operating system may choose (`cut`).  `workerRun` is the same
    behaviour as a total function of the whole input, and `serveWorker_run` says the two agree on every pipe. -/

structure Pipe where
  input : Bytes
  output : Bytes
  reads : Nat
  cut : Nat → Nat

instance : Nonempty Pipe := ⟨⟨[], [], 0, fun _ => 0⟩⟩

def Pipe.read (n : USize) : StateM Pipe ByteArray := fun p =>
  let k := min n.toNat (max 1 (p.cut p.reads))
  ((p.input.take k).toByteArray, { p with input := p.input.drop k, reads := p.reads + 1 })

def Pipe.write (b : ByteArray) : StateM Pipe Unit := fun p => ((), { p with output := p.output ++ b.toList })

theorem toList_toByteArray (l : List UInt8) : l.toByteArray.toList = l :=
  ((Fast.toByteArray_eq_iff l l.toByteArray).1 rfl).symm

theorem toList_append (a b : ByteArray) : (a ++ b).toList = a.toList ++ b.toList :=
  ((Fast.toByteArray_eq_iff (a.toList ++ b.toList) (a ++ b)).1
    (by rw [List.toByteArray_append, Fast.toByteArray_toList, Fast.toByteArray_toList])).symm

theorem run_bind' {σ α β : Type} (x : StateM σ α) (f : α → StateM σ β) (s : σ) :
    (x >>= f).run s = (f (x.run s).1).run (x.run s).2 := rfl

theorem readUpTo_pipe (n : Nat) (acc : ByteArray) (p : Pipe) :
    let r := (readUpTo Pipe.read n acc).run p
    r.1.toList = acc.toList ++ p.input.take (n - acc.size) ∧
    r.2.input = p.input.drop (n - acc.size) ∧ r.2.output = p.output ∧ r.2.cut = p.cut := by
  induction hk : n - acc.size using Nat.strongRecOn generalizing acc p with
  | _ k ih =>
  simp only []
  rw [readUpTo]
  by_cases h : acc.size < n
  · rw [if_pos h]
    have hU : (USize.ofNat (min (n - acc.size) 65536)).toNat = min (n - acc.size) 65536 :=
      USize.toNat_ofNat_of_lt' (Nat.lt_of_le_of_lt (Nat.min_le_right _ _) (by have := USize.le_size; omega))
    have hread : (Pipe.read (USize.ofNat (min (n - acc.size) 65536))).run p =
        ((p.input.take (min (min (n - acc.size) 65536) (max 1 (p.cut p.reads)))).toByteArray,
          { p with input := p.input.drop (min (min (n - acc.size) 65536) (max 1 (p.cut p.reads))),
                   reads := p.reads + 1 }) := by
      simp only [Pipe.read, StateT.run, hU]
    rw [run_bind', hread]
    dsimp only
    have hj1 : 1 ≤ min (min (n - acc.size) 65536) (max 1 (p.cut p.reads)) := by omega
    have hjk : min (min (n - acc.size) 65536) (max 1 (p.cut p.reads)) ≤ k := by omega
    generalize min (min (n - acc.size) 65536) (max 1 (p.cut p.reads)) = j at hj1 hjk ⊢
    by_cases hc : (p.input.take j).toByteArray.size = 0
    · rw [if_pos hc, StateT.run_pure]
      have hnil : p.input = [] := by
        rw [List.size_toByteArray, List.length_take] at hc
        exact List.length_eq_zero_iff.1 (by omega)
      exact ⟨by show acc.toList = _; simp [hnil], by show List.drop j p.input = _; simp [hnil], rfl, rfl⟩
    · rw [if_neg hc]
      have hlen : 0 < (p.input.take j).length := by
        rw [List.size_toByteArray] at hc; omega
      have hsize : (acc ++ (p.input.take j).toByteArray).size = acc.size + (p.input.take j).length := by
        rw [ByteArray.size_append, List.size_toByteArray]
      obtain ⟨h1, h2, h3, h4⟩ := ih (n - (acc ++ (p.input.take j).toByteArray).size) (by omega)
        (acc ++ (p.input.take j).toByteArray)
        { p with input := p.input.drop j, reads := p.reads + 1 } rfl
      rw [List.length_take] at hsize
      have hjl : j ≤ p.input.length ∨ p.input.length ≤ j := by omega
      refine ⟨?_, ?_, h3, h4⟩
      · rw [h1]
        dsimp only
        rw [toList_append, toList_toByteArray, hsize, List.append_assoc]
        congr 1
        rcases hjl with hl | hl
        · have e : n - (acc.size + min j p.input.length) = k - j := by omega
          rw [e, ← List.take_add]; congr 1; omega
        · rw [List.take_of_length_le hl, List.drop_of_length_le hl, List.take_nil, List.append_nil,
            List.take_of_length_le (by omega)]
      · rw [h2]
        dsimp only
        rw [hsize]
        rcases hjl with hl | hl
        · have e : n - (acc.size + min j p.input.length) = k - j := by omega
          rw [e, List.drop_drop]; congr 1; omega
        · rw [List.drop_of_length_le hl, List.drop_nil, List.drop_of_length_le (by omega)]
  · have hk0 : k = 0 := by omega
    subst hk0
    rw [if_neg h, StateT.run_pure]
    exact ⟨by simp; rfl, rfl, rfl, rfl⟩

theorem readNatBE_length {w : Nat} {l : Bytes} {v : Nat} {rest : Bytes}
    (h : readNatBE w l = some (v, rest)) : l.length = rest.length + w := by
  induction w generalizing v rest with
  | zero =>
    simp only [readNatBE, Option.some.injEq, Prod.mk.injEq] at h
    obtain ⟨_, rfl⟩ := h; rfl
  | succ w ih =>
    simp only [readNatBE] at h
    cases hr : readNatBE w l with
    | none => simp [hr] at h
    | some r =>
      obtain ⟨a, r1⟩ := r
      have := ih hr
      cases r1 with
      | nil => simp [hr, readByte] at h
      | cons b t =>
        simp only [hr, readByte, Option.pure_def, Option.bind_eq_bind, Option.bind_some, Option.some.injEq,
          Prod.mk.injEq] at h
        obtain ⟨_, rfl⟩ := h
        simp only [List.length_cons] at this
        omega

theorem readNatBE_none {w : Nat} {l : Bytes} (h : l.length < w) : readNatBE w l = none := by
  cases hr : readNatBE w l with
  | none => rfl
  | some r => have := readNatBE_length hr; omega

theorem natBE_length (w n : Nat) : (natBE w n).length = w := by
  induction w generalizing n with
  | zero => rfl
  | succ w ih => simp [natBE, ih]

theorem readNatBE_append {w : Nat} {x y : Bytes} {v : Nat} {r : Bytes}
    (h : readNatBE w x = some (v, r)) : readNatBE w (x ++ y) = some (v, r ++ y) := by
  induction w generalizing v r with
  | zero => simp only [readNatBE, Option.some.injEq, Prod.mk.injEq] at h ⊢; obtain ⟨h1, rfl⟩ := h; simp [h1]
  | succ w ih =>
    simp only [readNatBE] at h ⊢
    cases hr : readNatBE w x with
    | none => simp [hr] at h
    | some q =>
      obtain ⟨a, r1⟩ := q
      rw [ih hr]
      cases r1 with
      | nil => simp [hr, readByte] at h
      | cons b t => simpa [hr, readByte] using h

theorem readNatBE_some {w : Nat} {l : Bytes} (h : w ≤ l.length) :
    ∃ v, readNatBE w l = some (v, l.drop w) := by
  induction w with
  | zero => exact ⟨0, rfl⟩
  | succ w ih =>
    obtain ⟨v, hv⟩ := ih (by omega)
    cases hd : l.drop w with
    | nil => have := List.length_drop (i := w) (l := l); simp [hd] at this; omega
    | cons b t =>
      refine ⟨v * 256 + b.toNat, ?_⟩
      simp only [readNatBE, hv, hd, readByte, Option.pure_def, Option.bind_eq_bind, Option.bind_some]
      have : l.drop (w + 1) = t := by rw [← List.drop_drop, hd]; rfl
      rw [this]

theorem readNatBE_natBE {w n : Nat} (h : n < 256 ^ w) (r : Bytes) : readNatBE w (natBE w n ++ r) = some (n, r) := by
  induction w generalizing n r with
  | zero => simp at h; subst h; rfl
  | succ w ih =>
    have h' : n / 256 < 256 ^ w := by rw [Nat.pow_succ] at h; omega
    have e : natBE (w + 1) n ++ r = natBE w (n / 256) ++ (UInt8.ofNat (n % 256) :: r) := by simp [natBE]
    rw [e]
    simp only [readNatBE]
    rw [ih h']
    have : (UInt8.ofNat (n % 256)).toNat = n % 256 := by simp
    simp [readByte, this]
    omega

/-- One framed message: u32 BE length, then the bytes. -/
def frame (b : Bytes) : Bytes := natBE 4 b.length ++ b

/-- The worker as a total function of its whole input: exit code, output bytes, input left unread.
    Well-founded on the input length, so it is a real function, not a fixpoint. -/
def workerRun (input : Bytes) : UInt32 × Bytes × Bytes :=
  if input = [] then (0, [], []) else
  match _h : readNatBE 4 input with
  | none => (workerExitFrame, [], [])
  | some (length, rest) =>
    if length > maxWorkerFrameBytes then (workerExitFrame, [], rest)
    else if rest.length < length then (workerExitFrame, [], [])
    else
      let (code, out, left) := workerRun (rest.drop length)
      (code, frame (workerRespond (rest.take length)) ++ out, left)
termination_by input.length
decreasing_by
  have := readNatBE_length _h
  simp only [List.length_drop]; omega

private theorem workerRun_nil : workerRun [] = (0, [], []) := by
  rw [workerRun, if_pos rfl]

private theorem workerRun_read {input rest : Bytes} {v : Nat} (hne : input ≠ []) (h : readNatBE 4 input = some (v, rest)) :
    workerRun input =
      if maxWorkerFrameBytes < v then (workerExitFrame, [], rest)
      else if rest.length < v then (workerExitFrame, [], [])
      else ((workerRun (rest.drop v)).1, frame (workerRespond (rest.take v)) ++ (workerRun (rest.drop v)).2.1,
        (workerRun (rest.drop v)).2.2) := by
  rw [workerRun, if_neg hne]
  split
  · rename_i hh; rw [h] at hh; cases hh
  · rename_i length rest' hh
    rw [h] at hh
    simp only [Option.some.injEq, Prod.mk.injEq] at hh
    obtain ⟨rfl, rfl⟩ := hh
    rfl

private theorem workerRun_short {t : Bytes} (hne : t ≠ []) (h : t.length < 4) : workerRun t = (workerExitFrame, [], []) := by
  rw [workerRun, if_neg hne]
  split
  · rfl
  · rename_i hh; rw [readNatBE_none h] at hh; cases hh

private theorem workerRun_frame {f X : Bytes} (hf : f.length ≤ maxWorkerFrameBytes) :
    workerRun (frame f ++ X) =
      ((workerRun X).1, frame (workerRespond f) ++ (workerRun X).2.1, (workerRun X).2.2) := by
  have hr : readNatBE 4 (frame f ++ X) = some (f.length, f ++ X) := by
    have := maxWorkerFrameBytes_fits_u32
    exact (List.append_assoc _ _ _) ▸ readNatBE_natBE (by omega) (f ++ X)
  have hne : frame f ++ X ≠ [] := by
    intro hh; have := congrArg List.length hh; simp [frame, natBE_length] at this
  rw [workerRun_read hne hr, if_neg (by omega), if_neg (by simp), List.drop_left' rfl, List.take_left' rfl]

theorem workerRun_frames (frames : List Bytes) (h : ∀ f ∈ frames, f.length ≤ maxWorkerFrameBytes) :
    workerRun (frames.flatMap frame) = (0, (frames.map workerRespond).flatMap frame, []) := by
  induction frames with
  | nil => simpa using workerRun_nil
  | cons f fs ih =>
    have hf := h f (by simp)
    have := ih (fun g hg => h g (by simp [hg]))
    simp only [List.flatMap_cons, List.map_cons]
    rw [workerRun_frame hf, this]

private theorem workerRun_head {n : Nat} {t : Bytes} (hFit : n < 256 ^ 4) (hne : natBE 4 n ++ t ≠ []) :
    workerRun (natBE 4 n ++ t) =
      if maxWorkerFrameBytes < n then (workerExitFrame, [], t)
      else if t.length < n then (workerExitFrame, [], [])
      else ((workerRun (t.drop n)).1, frame (workerRespond (t.take n)) ++ (workerRun (t.drop n)).2.1,
        (workerRun (t.drop n)).2.2) :=
  workerRun_read hne (readNatBE_natBE hFit t)

theorem workerRun_oversize (frames : List Bytes) (h : ∀ f ∈ frames, f.length ≤ maxWorkerFrameBytes)
    (length : Nat) (hBig : maxWorkerFrameBytes < length) (hFit : length < 256 ^ 4) (rest : Bytes) :
    workerRun (frames.flatMap frame ++ natBE 4 length ++ rest) =
      (workerExitFrame, (frames.map workerRespond).flatMap frame, rest) := by
  induction frames with
  | nil =>
    have hne : natBE 4 length ++ rest ≠ [] := by
      intro hh; have := congrArg List.length hh; simp [natBE_length] at this
    simp only [List.flatMap_nil, List.nil_append, List.map_nil]
    rw [workerRun_head hFit hne, if_pos hBig]
  | cons f fs ih =>
    have hf := h f (by simp)
    have e : (frame f ++ fs.flatMap frame) ++ natBE 4 length ++ rest
        = frame f ++ (fs.flatMap frame ++ natBE 4 length ++ rest) := by simp
    simp only [List.flatMap_cons, List.map_cons]
    rw [e, workerRun_frame hf, ih (fun g hg => h g (by simp [hg]))]

private theorem workerRun_cut {n : Nat} {t : Bytes} (hn : n ≤ maxWorkerFrameBytes) (ht : t.length < n) :
    workerRun (natBE 4 n ++ t) = (workerExitFrame, [], []) := by
  have hFit : n < 256 ^ 4 := Nat.lt_of_le_of_lt hn maxWorkerFrameBytes_fits_u32
  have hne : natBE 4 n ++ t ≠ [] := by
    intro hh; have := congrArg List.length hh; simp [natBE_length] at this
  rw [workerRun_head hFit hne, if_neg (by omega), if_pos ht]

theorem workerRun_truncated (frames : List Bytes) (h : ∀ f ∈ frames, f.length ≤ maxWorkerFrameBytes)
    (f t : Bytes) (hf : f.length ≤ maxWorkerFrameBytes) (ht : t <+: frame f) (hne : t ≠ [])
    (hshort : t.length < (frame f).length) :
    workerRun (frames.flatMap frame ++ t) = (workerExitFrame, (frames.map workerRespond).flatMap frame, []) := by
  have hbase : workerRun t = (workerExitFrame, [], []) := by
    by_cases h4 : t.length < 4
    · exact workerRun_short hne h4
    · have ht' := List.prefix_iff_eq_take.1 ht
      have hA : (natBE 4 f.length).length = 4 := natBE_length 4 f.length
      have hlen : (frame f).length = 4 + f.length := by simp [frame, hA]
      generalize hk : t.length = k at ht' h4 hshort
      have e : t = natBE 4 f.length ++ f.take (k - 4) := by
        rw [ht', frame, List.take_append, List.take_of_length_le (by omega), hA]
      have hlt : (f.take (k - 4)).length < f.length := by rw [List.length_take]; omega
      have hcut := workerRun_cut hf hlt
      rwa [← e] at hcut
  induction frames with
  | nil => simpa using hbase
  | cons g gs ih =>
    have hg := h g (by simp)
    simp only [List.flatMap_cons, List.map_cons, List.append_assoc]
    rw [workerRun_frame hg, ih (fun x hx => h x (by simp [hx]))]

theorem readNatBE_take {w : Nat} {l : Bytes} (h : w ≤ l.length) :
    ∃ v, readNatBE w (l.take w) = some (v, []) ∧ readNatBE w l = some (v, l.drop w) := by
  obtain ⟨v, hv⟩ := readNatBE_some (w := w) (l := l.take w) (by simp; omega)
  have hd : (l.take w).drop w = [] := List.drop_of_length_le (by simp; omega)
  rw [hd] at hv
  refine ⟨v, hv, ?_⟩
  have := readNatBE_append (y := l.drop w) hv
  simpa using this

theorem serveWorker_run (p : Pipe) :
    let r := (serveWorker Pipe.read Pipe.write).run p
    r.1 = (workerRun p.input).1 ∧
    r.2.output = p.output ++ (workerRun p.input).2.1 ∧
    r.2.input = (workerRun p.input).2.2 := by
  induction hk : p.input.length using Nat.strongRecOn generalizing p with
  | _ k ih =>
  simp only []
  rw [serveWorker, run_bind']
  obtain ⟨hA, hB, hC, hD⟩ := readUpTo_pipe 4 ByteArray.empty p
  generalize (readUpTo Pipe.read 4 ByteArray.empty).run p = r1 at hA hB hC hD ⊢
  simp only [ByteArray.size_empty, ByteArray.toList_empty, List.nil_append, Nat.sub_zero] at hA hB
  dsimp only
  have hsz : r1.1.size = (p.input.take 4).length := by rw [← Fast.length_toList, hA]
  by_cases hE : r1.1.size = 0
  · have hin : p.input = [] := by
      have : (p.input.take 4).length = 0 := by omega
      simpa using this
    rw [if_pos hE, StateT.run_pure, hin, workerRun_nil]
    exact ⟨rfl, by show r1.2.output = _; simp [hC], by show r1.2.input = _; simp [hB, hin]⟩
  · rw [if_neg hE]
    have hne : p.input ≠ [] := fun h0 => hE (by rw [hsz, h0]; rfl)
    rw [hA]
    by_cases h4 : p.input.length < 4
    · have hnone : readNatBE 4 (p.input.take 4) = none := readNatBE_none (by simp; omega)
      rw [hnone, workerRun_short hne h4]
      refine ⟨rfl, ?_, ?_⟩
      · show r1.2.output = _; simp [hC]
      · show r1.2.input = _; simp [hB, List.drop_of_length_le (by omega : p.input.length ≤ 4)]
    · obtain ⟨v, hv1, hv2⟩ := readNatBE_take (w := 4) (l := p.input) (by omega)
      rw [hv1]
      dsimp only
      rw [workerRun_read hne hv2]
      by_cases hBig : maxWorkerFrameBytes < v
      · rw [if_pos (show v > maxWorkerFrameBytes from hBig), if_pos hBig, StateT.run_pure]
        refine ⟨rfl, ?_, ?_⟩
        · show r1.2.output = _; simp [hC]
        · show r1.2.input = _; simp [hB]
      · rw [if_neg (show ¬ v > maxWorkerFrameBytes from hBig), if_neg hBig]
        obtain ⟨hA2, hB2, hC2, hD2⟩ := readUpTo_pipe v ByteArray.empty r1.2
        rw [run_bind']
        generalize (readUpTo Pipe.read v ByteArray.empty).run r1.2 = r2 at hA2 hB2 hC2 hD2 ⊢
        simp only [ByteArray.size_empty, ByteArray.toList_empty, List.nil_append, Nat.sub_zero, hB] at hA2 hB2
        have hsz2 : r2.1.size = (List.take v (p.input.drop 4)).length := by rw [← Fast.length_toList, hA2]
        by_cases hS : r2.1.size < v
        · have hl : (p.input.drop 4).length < v := by rw [hsz2, List.length_take] at hS; omega
          rw [if_pos hS, StateT.run_pure, if_pos hl]
          refine ⟨rfl, ?_, ?_⟩
          · show r2.2.output = _; simp [hC2, hC]
          · show r2.2.input = _; simp [hB2, List.drop_of_length_le (by omega : (p.input.drop 4).length ≤ v)]
        · have hl : ¬ (p.input.drop 4).length < v := by rw [hsz2, List.length_take] at hS; omega
          rw [if_neg hS, run_bind', if_neg hl]
          simp only [Pipe.write, StateT.run]
          have hlt : (List.drop v (List.drop 4 p.input)).length < k := by
            simp only [List.length_drop]; omega
          obtain ⟨i1, i2, i3⟩ := ih _ hlt
            { input := r2.2.input,
              output := r2.2.output ++
                (List.toByteArray (natBE 4 (List.length (workerRespondBA r2.1)) ++ workerRespondBA r2.1)).toList,
              reads := r2.2.reads, cut := r2.2.cut }
            (by show r2.2.input.length = _; rw [hB2])
          have hresp : workerRespondBA r2.1 = workerRespond (List.take v (List.drop 4 p.input)) := by
            rw [workerRespondBA_eq, hA2]
          refine ⟨i1.trans (by show (workerRun r2.2.input).1 = _; rw [hB2]), i2.trans ?_,
            i3.trans (by show (workerRun r2.2.input).2.2 = _; rw [hB2])⟩
          dsimp only
          rw [hB2, hC2, hC, toList_toByteArray, hresp]
          simp [frame]

/-- M1.5: on any chunking, the worker's output stream is `workerRespond` mapped over the input frames. -/
theorem serveWorker_stateless (frames : List Bytes) (h : ∀ f ∈ frames, f.length ≤ maxWorkerFrameBytes)
    (out : Bytes) (reads : Nat) (cut : Nat → Nat) :
    let r := (serveWorker Pipe.read Pipe.write).run ⟨frames.flatMap frame, out, reads, cut⟩
    r.1 = 0 ∧ r.2.output = out ++ (frames.map workerRespond).flatMap frame ∧ r.2.input = [] := by
  obtain ⟨h1, h2, h3⟩ := serveWorker_run ⟨frames.flatMap frame, out, reads, cut⟩
  dsimp only at h1 h2 h3 ⊢
  rw [workerRun_frames frames h] at h1 h2 h3
  exact ⟨h1, h2, h3⟩

private def runPipe (input : Bytes) (cut : Nat → Nat) : UInt32 × Bytes × Bytes :=
  let r := (serveWorker Pipe.read Pipe.write).run ⟨input, [], 0, cut⟩
  (r.1, r.2.output, r.2.input)
#guard workerRespond [] == [1]                                                   -- empty frame: decode rejected
#guard workerRespond CorrectionTransition.correctionTransitionInputMagic == [1]             -- bare BLFCMD03: decode rejected
#guard itemMagics.all (·.length == 8)
#guard (itemMagics.map fun m => (itemMagics.filter (· == m)).length).all (· == 1)
#guard itemMagics.all fun m => !(m.isPrefixOf financialCodecMagic || financialCodecMagic.isPrefixOf m)
#guard runPipe [] (fun _ => 1) == (0, [], [])                                    -- EOF at a frame boundary
#guard runPipe (frame [] ++ frame []) (fun _ => 1) == (0, frame [1] ++ frame [1], [])   -- one byte per read
#guard runPipe (frame [] ++ [0, 0]) (fun _ => 1) == (workerExitFrame, frame [1], [])    -- short header
#guard runPipe (frame [] ++ [0, 0, 0, 5, 9]) (· + 1) == (workerExitFrame, frame [1], [])  -- short body
#guard runPipe (natBE 4 (maxWorkerFrameBytes + 1) ++ [7]) (fun _ => 65536)
    == (workerExitFrame, [], [7])                                                -- oversize: body never read
#guard [1, 2, 3, 5, 4096].all fun c =>
    runPipe (frame [] ++ frame [9, 9] ++ [0, 0, 0]) (fun _ => c) == workerRun (frame [] ++ frame [9, 9] ++ [0, 0, 0])

end BlindLedger.Financial
