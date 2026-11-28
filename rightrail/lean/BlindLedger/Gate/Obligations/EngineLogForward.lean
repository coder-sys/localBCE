import BlindLedger.Gate.Obligations.EngineLogPass
import BlindLedger.Sha3FastEq
import BlindLedger.Sha3QuickEq

namespace BlindLedger.Gate.Obligations

open BlindLedger.Gate.FactCodec
open BlindLedger.Financial (FinancialInput FinancialResult ControlPack evaluate decodeFinancialInput decodeControlPack
  encodeControlPack rawEncodeFinancialInput rawEncodeFinancialResult)
open BlindLedger.Financial.Payment (Ledger Call Command ReverseCommand readCommand encodeCommand commitInput)

/-! Part 2 of `EngineLogChecks`: the checker passes the records of a decided command (`Forward`), one kind of
    command at a time.

    Nothing the program runs imports this module. -/

/-! ## What every decided command writes first -/

/-- The checker reads the `lg` of a command record back as what the engine wrote it from. -/
theorem lgOf_two (b : Bool) : (lgOf b == 2) = b := by cases b <;> rfl

/-- An obligation with no class keeps `lg` bit 1 on its next payment. -/
theorem lgOf_keeps (a b : Bool) : (!a || lgOf (a || b) == 2) = true := by cases a <;> cases b <;> rfl

theorem core_link {v : View} {c : Cmd} {f : Nat → Plan} (h : core v c = .ok f) (n : Nat) :
    (f n).link = ⟨v.cmdPrev, nextCount v.cmdCount⟩ := by
  unfold core at h
  dsimp only at h
  repeat' split at h
  all_goals try (cases h; done)
  all_goals
    simp only [Except.ok.injEq] at h
    subst h
    rfl

/-- The command record of a decided command passes the checks every command record meets, the records after it
    are the plan's body, and the record is found as a command record. -/
theorem cmd_start {st : Chk} {v : View} {c : Cmd} {f : Nat → Plan} {i : Nat} {bs : List Bytes}
    {rec : Nat → Option Bytes} (hpre : Pre st v c) (hpl : c.plain) (hcore : core v c = .ok f)
    (hb : (f i).bytes c = some bs) (hrec : ∀ j r, bs[j]? = some r → rec (i + j) = some r) :
    Start st rec i ((f i).cmd c) (f i).link ∧ Placed rec (i + 1) (f i).body ∧
      bs.length = 1 + (f i).body.length ∧ peek rec i 0x74 cmdC.dec = some ((f i).cmd c, (f i).link) := by
  obtain ⟨cb, rest, rfl, hcb, hrest⟩ := Plan.bytes_cons hb
  have h0 : rec i = some cb := hrec 0 cb rfl
  obtain ⟨hrd, hdec⟩ := rd_full cmdC_ok hcb h0
  refine ⟨⟨read_intro hrd hdec, hpre.fresh, ?_, ?_, ?_⟩, ⟨rest, hrest, fun j r hj => ?_⟩, ?_,
    peek_hit hrd (enc_tag (c := cmdC) (v := 0x74) rfl (by decide) _) hdec⟩
  · rw [core_link hcore i, hpre.prev, hpre.count]
  · obtain ⟨h1, h2, h3, -⟩ := hpl
    have hlg := (core_marks hcore i).1
    cases hnc : noClassOf v c <;> simp [cmdFixed, Plan.cmd, h1, h2, h3, hlg, lgOf, hnc]
  · rw [hpre.last]
    exact core_time hcore
  · have h3 := hrec (j + 1) r hj
    have e : i + 1 + j = i + (j + 1) := by omega
    rw [e]
    exact h3
  · simp [encAll_length hrest]
    omega

/-! ## Where a command's own records end

    The checker finds the end of a command's records from the records themselves (`ownEnd`): a pack's from its
    count of text records, any other command's from its state row and, after every row but an alias's, from the id
    length the evaluation reference states in its first two bytes.  The engine writes exactly that many: the id of
    a result Lean's evaluation returned is far shorter than two bytes can state. -/

theorem H_length (b : Bytes) : (H b).length = 64 := by
  unfold H
  rw [BlindLedger.Semantic.sha3_512Quick_eq, ← BlindLedger.Semantic.sha3_512_eq]
  exact BlindLedger.Semantic.sha3_512_toList_length _

theorem utf8_append (s t : String) : utf8 (s ++ t) = utf8 s ++ utf8 t := by
  unfold utf8
  rw [BlindLedger.Financial.CorrectionTransition.byteArray_toList_eq,
    BlindLedger.Financial.CorrectionTransition.byteArray_toList_eq,
    BlindLedger.Financial.CorrectionTransition.byteArray_toList_eq]
  simp only [String.toUTF8_eq_toByteArray, String.toByteArray_append, ByteArray.toList_data_append]

open BlindLedger.Financial BlindLedger.Financial.CorrectionTransition in
/-- The evaluation id of a well-formed result is short: its obligation id is at most 128 bytes and its revision
    at most five digits. -/
theorem evalId_length {res : FinancialResult} (hw : financialResultWellFormed res = true) :
    (utf8 ("evaluation:" ++ res.context.obligationId ++ ":r" ++ toString res.afterRevision)).length < 65536 := by
  unfold financialResultWellFormed at hw
  simp only [Bool.and_eq_true, decide_eq_true_eq, and_assoc] at hw
  obtain ⟨hctx, -, -, -, -, -, -, -, -, -, hrev, -⟩ := hw
  unfold contextWellFormed at hctx
  simp only [Bool.and_eq_true, List.all_eq_true] at hctx
  have hoid := hctx.1.1 res.context.obligationId (by simp)
  unfold idWellFormed maxIdBytes at hoid
  simp only [Bool.and_eq_true, decide_eq_true_eq] at hoid
  have h2 : (utf8 res.context.obligationId).length ≤ 128 := hoid.1.2
  unfold revisionWellFormed maxRevision at hrev
  simp only [decide_eq_true_eq] at hrev
  have hd : (toString res.afterRevision).toList.length ≤ 5 :=
    (Nat.length_repr_le_iff (by decide)).2 (Nat.lt_of_le_of_lt hrev (by decide))
  have h4 : (utf8 (toString res.afterRevision)).length ≤ 4 * (toString res.afterRevision).toList.length :=
    string_utf8_length_le _
  have h1 : (utf8 "evaluation:").length ≤ 4 * "evaluation:".toList.length := string_utf8_length_le _
  have h3 : (utf8 ":r").length ≤ 4 * ":r".toList.length := string_utf8_length_le _
  have c1 : "evaluation:".toList.length = 11 := by decide
  have c3 : ":r".toList.length = 2 := by decide
  rw [utf8_append, utf8_append, utf8_append]
  simp only [List.length_append]
  omega

/-- An evaluation reference starts with the two bytes of its id's length, and is as long as that length says. -/
theorem evalRef_layout {res : FinancialResult} (hw : BlindLedger.Financial.financialResultWellFormed res = true) :
    ∃ b0 b1 rest, evalRef res = b0 :: b1 :: rest ∧
      refBytes (b0.toNat + 256 * b1.toNat) = (evalRef res).length := by
  have hL := evalId_length hw
  obtain ⟨id, hid⟩ : ∃ id, id = utf8 ("evaluation:" ++ res.context.obligationId ++ ":r" ++
    toString res.afterRevision) := ⟨_, rfl⟩
  rw [← hid] at hL
  have he : evalRef res = lp16 id ++ erefOf (rawEncodeFinancialResult res) ++ zeros 128 := by rw [hid]; rfl
  rw [he]
  refine ⟨UInt8.ofNat (id.length % 256), UInt8.ofNat (id.length / 256 % 256),
    id ++ erefOf (rawEncodeFinancialResult res) ++ zeros 128, by first | rfl | simp [lp16, leBytes], ?_⟩
  simp only [refBytes, UInt8.toNat_ofNat', Nat.reducePow, lp16, List.length_append, leBytes_length, erefOf,
    H_length, zeros, List.length_replicate]
  omega

/-- An element of one byte or more takes one text record for each 242 bytes and one for the rest. -/
theorem partsFrom_length (i : Nat) (e : Bytes) (h : 1 ≤ e.length) :
    (partsFrom i e).length = (e.length + textBytes - 1) / textBytes := by
  rw [partsFrom]
  split
  · rename_i hl
    simp only [textBytes] at hl ⊢
    rw [List.length_cons, List.length_nil]
    omega
  · rename_i hl
    simp only [textBytes] at hl
    have ih := partsFrom_length (i + 1) (e.drop textBytes) (by simp only [List.length_drop, textBytes]; omega)
    simp only [textBytes, List.length_drop] at ih ⊢
    rw [List.length_cons, ih]
    omega
termination_by e.length
decreasing_by simp only [List.length_drop]; simp only [textBytes]; omega

/-- The first text record of an element holds the element's first two bytes. -/
theorem partsFrom_head (i : Nat) (b0 b1 : UInt8) (rest : Bytes) :
    ∃ t ts, partsFrom i (b0 :: b1 :: rest) = t :: ts ∧ t.bytes.getD 0 0 = b0 ∧ t.bytes.getD 1 0 = b1 := by
  by_cases hl : (b0 :: b1 :: rest).length ≤ textBytes
  · rw [partsFrom, dif_pos hl]
    exact ⟨_, _, rfl, rfl, rfl⟩
  · rw [partsFrom, dif_neg hl]
    exact ⟨_, _, rfl, rfl, rfl⟩

/-- The text records of an evaluation reference the engine wrote end where the checker counts them to end. -/
theorem Placed.ref_end {rec : Nat → Option Bytes} {r c : Nat} {res : FinancialResult}
    (h : Placed rec r (textsAt (evalRef res) r c))
    (hw : BlindLedger.Financial.financialResultWellFormed res = true) :
    refEnd rec r = r + nParts (evalRef res) := by
  obtain ⟨b0, b1, rest, he, hL⟩ := evalRef_layout hw
  have hne : (evalRef res).isEmpty = false := by rw [he]; rfl
  have hnp : nParts (evalRef res) = ((evalRef res).length + textBytes - 1) / textBytes := by
    unfold nParts
    simp only [hne, Bool.false_eq_true, ↓reduceIte]
    exact partsFrom_length 0 _ (evalRef_length res)
  obtain ⟨t, ts, hp, h0, h1⟩ := partsFrom_head 0 b0 b1 rest
  rw [← he] at hp
  unfold textsAt at h
  simp only [hne, Bool.false_eq_true, ↓reduceIte] at h
  rw [hp] at h
  simp only [linkTexts] at h
  obtain ⟨⟨rb, hrb, hrec⟩, -⟩ := h.head
  obtain ⟨hrd, hdec⟩ := rd_full textC_ok hrb hrec
  have hpk := peek_hit hrd (enc_tag (c := textC) (v := 0xF5) rfl (by decide) t) hdec
  unfold refEnd
  rw [hpk]
  dsimp only
  rw [h0, h1, hL, hnp]

/-- A state row the engine wrote is found as a state row. -/
theorem Placed.state_peek {rec : Nat → Option Bytes} {a : Nat} {x : StateRow} {l : Link} {ys : List Body}
    (h : Placed rec a (.state x l :: ys)) : peek rec a 0x60 stateC.dec = some (x, l) := by
  obtain ⟨⟨r, he, hr⟩, -⟩ := h.head
  obtain ⟨hrd, hdec⟩ := rd_full stateC_ok he hr
  exact peek_hit hrd (enc_tag (c := stateC) (v := 0x60) rfl (by decide) x) hdec

/-- A pack's own records are its command record and its text records. -/
theorem ownEnd_pack {rec : Nat → Option Bytes} {i : Nat} {x : CmdRec} {xl : Link}
    (hx : peek rec i 0x74 cmdC.dec = some (x, xl)) (hk : x.ckind = 1) : ownEnd rec i = i + 1 + x.nt := by
  unfold ownEnd
  rw [hx]
  dsimp only
  rw [if_pos hk]

/-- Any other command's own records run to its state row, record `q`, and on through the row's evaluation
    reference unless the row is an alias's. -/
theorem ownEnd_row {rec : Nat → Option Bytes} {i q k m : Nat} {x : CmdRec} {xl rl : Link} {row : StateRow}
    (hx : peek rec i 0x74 cmdC.dec = some (x, xl)) (hrow : peek rec q 0x60 stateC.dec = some (row, rl))
    (hk : x.ckind = k) (hk1 : k ≠ 1) (hq : x.result = q + 1) (hi : i < q) (hm : row.mkind = m) :
    ownEnd rec i = if m = 17 then q + 1 else refEnd rec (q + 1) := by
  subst hk
  subst hm
  have h2 : ¬q + 1 ≤ i + 1 := by omega
  unfold ownEnd
  rw [hx]
  dsimp only
  rw [if_neg hk1, hq, if_neg h2]
  unfold rowEnd
  simp only [Nat.add_sub_cancel, hrow]

/-- A command whose state row, record `q`, is followed by the evaluation reference of a result Lean's
    evaluation returned: its own records end after the reference. -/
theorem ownEnd_ref {rec : Nat → Option Bytes} {i q c k m : Nat} {x : CmdRec} {xl rl : Link} {row : StateRow}
    {res : FinancialResult} (hx : peek rec i 0x74 cmdC.dec = some (x, xl))
    (hS : Placed rec q (.state row rl :: textsAt (evalRef res) (q + 1) c))
    (hw : BlindLedger.Financial.financialResultWellFormed res = true) (hk : x.ckind = k) (hk1 : k ≠ 1)
    (hq : x.result = q + 1) (hi : i < q) (hm : row.mkind = m) (hm17 : m ≠ 17) :
    ownEnd rec i = q + 1 + nParts (evalRef res) := by
  rw [ownEnd_row hx hS.state_peek hk hk1 hq hi hm, if_neg hm17]
  exact hS.head.2.ref_end hw

/-! ## A pack command -/

open BlindLedger.Financial BlindLedger.Financial.Payment BlindLedger.Financial.CorrectionTransition in
/-- A well-formed pack is one the pack decoder reads back.  The payment rule proves this for its own use and
    keeps it to itself; this is that proof. -/
theorem pack_wire {p : ControlPack} (h : controlPackWellFormed p = true) : controlPackWireAdmissible p := by
  have textWire : ∀ v : String, textWellFormed v = true → stringWireAdmissible v := by
    intro v hv
    unfold textWellFormed maxTextBytes at hv
    simp only [Bool.and_eq_true, decide_eq_true_eq] at hv
    exact lenWire hv.1.2
  have usdWire : stringWireAdmissible "USD" := by
    apply stringWireAdmissible_of_length
    have hBytes := string_utf8_length_le "USD"
    have hChars : "USD".toList.length = 3 := by decide
    omega
  have listWire : ∀ {α : Type} {vs : List α} {P : α → Prop}, vs.length ≤ maxRows → (∀ x ∈ vs, P x) →
      wireListAdmissible vs P := fun hl hP => ⟨⟨hl, Nat.lt_of_le_of_lt hl (by decide)⟩, hP⟩
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
    idWire (hI _ (by simp)), idWire (hI _ (by simp)), hCur ▸ usdWire, nat8Wire hV maxRevision_fits_u64,
    listWire hSrc.2.1 fun s hs => textWire s (hSrc.2.2 s hs), time8 hS, time8 hE, time8 hR, time8 hA,
    idWire (hI _ (by simp)), idWire (hI _ (by simp)),
    listWire hRoles.1 fun s hs => tokenWire (hRoles.2.1 s hs),
    listWire hTLen fun s hs => textWire s (hTests s hs),
    by simpa [digestWellFormed, digestWireAdmissible] using hDig⟩

/-- What the engine checked of a pack it admitted, and what it then writes. -/
theorem core_pack {v : View} {c : Cmd} {f : Nat → Plan} {p : ControlPack} {cls : PackClass}
    (h : core v c = .ok f) (ha : c.act = .pack p cls) :
    scopeOfPack p = c.scope ∧ BlindLedger.Financial.controlPackWellFormed p = true ∧ c.exprev = none ∧
      f = fun n => { rqd := rqdIn c none .recorded, result := 0, nt := nParts (packElement p cls), lg := 0,
                     link := ⟨v.cmdPrev, nextCount v.cmdCount⟩,
                     body := textsAt (packElement p cls) (n + 1) (nextCount v.cmdCount), obl := none } := by
  unfold core at h
  simp only [ha] at h
  by_cases ht : c.atMs < v.lastMs ∨ 2 ^ 63 ≤ c.atMs
  · rw [if_pos ht] at h
    cases h
  rw [if_neg ht] at h
  by_cases hs : (scopeOfPack p != c.scope) = true
  · rw [if_pos hs] at h
    cases h
  rw [if_neg hs] at h
  split at h
  · cases h
  rename_i hwf
  split at h
  · cases h
  cases h
  exact ⟨by simpa using hs, by cases hw : BlindLedger.Financial.controlPackWellFormed p <;> simp_all,
    by cases hx : c.exprev <;> simp_all, rfl⟩

theorem forward_pack {st : Chk} {v : View} {c : Cmd} {f : Nat → Plan} {i : Nat} {bs : List Bytes}
    {rec : Nat → Option Bytes} {p : ControlPack} {cls : PackClass} (hpre : Pre st v c) (hpl : c.plain)
    (hcore : core v c = .ok f) (hb : (f i).bytes c = some bs)
    (hrec : ∀ j r, bs[j]? = some r → rec (i + j) = some r) (ha : c.act = .pack p cls) :
    ownEnd rec i = i + bs.length ∧
      ∃ st', checkOne st rec (i + bs.length) i = .ok (st', i + bs.length) ∧ Post st st' c (f i) i := by
  obtain ⟨hs, hbody, hlen, hpk⟩ := cmd_start hpre hpl hcore hb hrec
  obtain ⟨hscope, hwf, hex, rfl⟩ := core_pack hcore ha
  obtain ⟨act, scope, atMs, exprev, actor, role, attr, src⟩ := c
  dsimp only at ha hex
  subst ha
  subst hex
  dsimp only [Plan.cmd] at hs hpk
  have hown := ownEnd_pack hpk rfl
  dsimp only at hown
  have hbody' : Placed rec (i + 1) (textsAt (packElement p cls) (i + 1) (nextCount v.cmdCount)) := hbody
  have hlen' : bs.length = 1 + nParts (packElement p cls) := by simpa using hlen
  have he1 : 1 ≤ (packElement p cls).length := by
    unfold packElement
    rw [List.length_append, leBytes_length]
    omega
  have hj : i + 1 + nParts (packElement p cls) = i + bs.length := by omega
  have hel := hbody'.element (n := i + bs.length) he1 (by omega) (fun h => absurd h (by omega))
  rw [hj] at hel
  have hdec : decodeControlPack (packElement p cls) =
      some (p, leBytes 1 cls.offsetMin ++ leBytes 1 cls.dispatchMin) := by
    unfold packElement
    rw [List.append_assoc]
    exact BlindLedger.Financial.decodeControlPack_encodeControlPack_append p _ (pack_wire hwf)
  have hsc : scopeOf p.stateId.toUTF8.toList p.deploymentId.toUTF8.toList p.programId.toUTF8.toList
      p.periodId.toUTF8.toList p.currency.toUTF8.toList = scope := hscope
  refine ⟨hown.trans hj, _, checkOne_pack hs rfl hel hdec
    (band_intro (band_intro (band_intro (band_intro rfl rfl) rfl) (by simp [leBytes_length]))
      (by simp [packElement]))
    (by rw [hsc]; exact band_intro (beq_iff_eq.2 rfl) (beq_iff_eq.2 rfl)), ?_⟩
  exact ⟨rfl, rfl, rfl, rfl, rfl, rfl⟩

/-! ## An evaluation -/

/-- The text records of an element, and the records after them. -/
theorem Placed.texts {rec : Nat → Option Bytes} {a a' c : Nat} {e : Bytes} {ys : List Body}
    (h : Placed rec a (textsAt e a' c ++ ys)) : Placed rec a (textsAt e a' c) ∧ Placed rec (a + nParts e) ys := by
  have h2 := h.split
  rw [textsAt_length] at h2
  exact h2

/-- A state row the engine wrote reads back as itself and is no text record. -/
theorem Placed.state {rec : Nat → Option Bytes} {a : Nat} {x : StateRow} {l : Link} {ys : List Body}
    (h : Placed rec a (.state x l :: ys)) :
    read rec a stateC.dec "state row" = .ok (x, l) ∧ (∀ b l', rd rec a = some (b, l') → tagOf b ≠ 0xF5) ∧
      Placed rec (a + 1) ys := by
  obtain ⟨⟨r, he, hr⟩, hys⟩ := h.head
  obtain ⟨hrd, hdec⟩ := rd_full stateC_ok he hr
  refine ⟨read_intro hrd hdec, fun b l' hb => ?_, hys⟩
  rw [hrd] at hb
  cases hb
  rw [enc_tag (c := stateC) (v := 0x60) rfl (by decide)]
  decide

/-- What the engine checked of an evaluation it decided, and what it then writes. -/
theorem core_eval {v : View} {c : Cmd} {f : Nat → Plan} {item r : String} (h : core v c = .ok f)
    (ha : c.act = .evaluate item r) :
    ∃ o res, v.obl = some o ∧ o.names c.scope item = true ∧
      c.exprev.all (· == o.led.input.beforeRevision) = true ∧
      evaluate { o.led.input with evaluatedAt := c.atMs } = some res ∧
      f = fun n =>
        { rqd := rqdIn c (some o) .recorded, result := n + 1 + nParts (utf8 r) + 1, nt := nParts (utf8 r),
          lg := lgOf o.noClass, link := ⟨v.cmdPrev, nextCount v.cmdCount⟩,
          body := textsAt (utf8 r) (n + 1) (nextCount v.cmdCount) ++
            [.state (rowOf 25 0 res res.afterRevision o.led.input.conflicts.length o.fact o.caseRef (o.fact + 1)
              (n + 1) o.led.input.obligation.dueAt c.atMs (lgOf o.noClass)) ⟨o.head + 1, nextCount o.headCount⟩] ++
            textsAt (evalRef res) (n + 1 + nParts (utf8 r) + 1) (nextCount o.headCount),
          obl := some (obOf c.scope (utf8 item),
            { o with
              led := { o.led with input := commitInput { o.led.input with evaluatedAt := c.atMs } res },
              head := n + 1 + nParts (utf8 r), headCount := nextCount o.headCount }) } := by
  unfold core at h
  simp only [ha] at h
  by_cases ht : c.atMs < v.lastMs ∨ 2 ^ 63 ≤ c.atMs
  · rw [if_pos ht] at h
    cases h
  rw [if_neg ht] at h
  cases ho : v.obl with
  | none => simp [ho] at h
  | some o =>
    simp only [ho] at h
    split at h
    · cases h
    rename_i hnames
    split at h
    · cases h
    rename_i hex
    split at h
    · cases h
    rename_i res hres
    cases h
    exact ⟨o, res, rfl, by simpa using hnames, by simpa using hex, hres, rfl⟩

theorem forward_eval {st : Chk} {v : View} {c : Cmd} {f : Nat → Plan} {i : Nat} {bs : List Bytes}
    {rec : Nat → Option Bytes} {item r : String} (hpre : Pre st v c) (hpl : c.plain)
    (hcore : core v c = .ok f) (hb : (f i).bytes c = some bs)
    (hrec : ∀ j r, bs[j]? = some r → rec (i + j) = some r) (ha : c.act = .evaluate item r) :
    ownEnd rec i = i + bs.length ∧
      ∃ st', checkOne st rec (i + bs.length) i = .ok (st', i + bs.length) ∧ Post st st' c (f i) i := by
  obtain ⟨hs, hbody, hlen, hpk⟩ := cmd_start hpre hpl hcore hb hrec
  obtain ⟨o, res, hvo, hnames, hexp, hres, rfl⟩ := core_eval hcore ha
  obtain ⟨act, scope, atMs, exprev, actor, role, attr, src⟩ := c
  dsimp only at ha
  subst ha
  obtain ⟨hsc, hit⟩ : scopeOfCtx o.led.input.context = scope ∧ o.led.input.context.itemId = item := by
    simpa [Obl.names] using hnames
  subst hsc
  subst hit
  obtain ⟨E, hE, hsame⟩ := hpre.obl _ o rfl hvo
  obtain ⟨hled, hhead, hhc, hcr, hfact, hfc, hcash, hnc⟩ := hsame
  dsimp only [Plan.cmd] at hs
  dsimp only at hbody
  simp only [List.length_append, textsAt_length, List.length_cons, List.length_nil] at hlen
  simp only [List.append_assoc, List.cons_append, List.nil_append] at hbody
  obtain ⟨hA, hS⟩ := hbody.texts
  obtain ⟨hrow, htag, hB⟩ := hS.state
  have hctx : res.context = o.led.input.context :=
    evaluate_context (i := { o.led.input with evaluatedAt := atMs }) hres
  have ho : st.obl[obOfCtx res.context]? = some E := by
    rw [hctx]
    exact hE
  have hk : i + 1 + nParts (utf8 r) + 1 + nParts (evalRef res) = i + bs.length := by omega
  have href := hB.afterRef (n := i + bs.length) (by omega) (fun h => absurd h (by omega))
  rw [hk] at href
  have hle : i + 1 + nParts (utf8 r) ≤ i + bs.length := by omega
  have hel : (if (nParts (utf8 r) == 0) = true then (pure ([], i + 1) : Except String (Bytes × Nat))
      else element rec (i + bs.length) (i + 1) (nextCount v.cmdCount)) =
        .ok (utf8 r, i + 1 + nParts (utf8 r)) := by
    rcases Nat.eq_zero_or_pos (utf8 r).length with h0 | hpos
    · rw [List.eq_nil_of_length_eq_zero h0] <;> rfl
    · have hp := nParts_pos hpos
      have hne : ¬(nParts (utf8 r) == 0) = true := by
        rw [beq_iff_eq]
        omega
      rw [if_neg hne]
      exact hA.element hpos hle fun _ => htag
  refine ⟨(ownEnd_ref (k := 12) (m := 25) hpk hS (BlindLedger.Financial.evaluate_resultWellFormed hres) rfl
      (by decide) rfl (by omega) rfl (by decide)).trans hk,
    _, checkOne_eval hs rfl hel (beq_iff_eq.2 (by dsimp only; omega)) hrow ho
    (by dsimp only; rw [exprev_round, hled]; exact hexp)
    (by rw [hled]; exact hres)
    (by
      rw [hled]
      exact band_intro (band_intro (beq_iff_eq.2 rfl) (beq_iff_eq.2 rfl))
        (beq_iff_eq.2 ((lgOf_two o.noClass).trans hnc.symm)))
    (by
      rw [hled, hfact, hcr, hhead, hhc]
      refine band_intro (band_intro (band_intro (band_intro rfl (rowOf_agree _ _ _ _ _ _ _ _ _ _ _)) ?_)
        (beq_iff_eq.2 rfl)) (beq_iff_eq.2 rfl)
      simp [rowLinks, rowFixed, rowOf, commitInput])
    href, ?_⟩
  refine ⟨rfl, rfl, rfl, rfl, rfl, _, congrArg (fun k => st.obl.insert k _) (congrArg obOfCtx hctx), ?_⟩
  exact ⟨by rw [hled] <;> rfl, rfl, rfl, hcr, hfact, hfc, hcash, hnc⟩

/-! ## A payment or a reversal -/

/-- The checker's entry of an obligation, written out from the engine's. -/
theorem Entry.same.eq {E : Entry} {o : Obl} (h : E.same o) :
    E = ⟨o.led, o.head, o.headCount, o.caseRef, o.fact, o.factCount, o.cash, o.noClass⟩ := by
  obtain ⟨led, head, headCount, caseRef, fact, factCount, cash, noClass⟩ := E
  obtain ⟨h1, h2, h3, h4, h5, h6, h7, h8⟩ := h
  dsimp only at h1 h2 h3 h4 h5 h6 h7 h8
  subst h1 h2 h3 h4 h5 h6 h7 h8
  rfl

theorem encodeCommand_length (pc : Command) : 1 ≤ (encodeCommand pc).length := by
  have h := encodeCommand_isEmpty pc
  cases he : encodeCommand pc with
  | nil => simp [he] at h
  | cons _ _ => simp

/-- Where an element's text starts there is no CASH row. -/
theorem Placed.no_cash {rec : Nat → Option Bytes} {a a' c : Nat} {e : Bytes} {ys : List Body}
    (h : Placed rec a (textsAt e a' c ++ ys)) (he : 1 ≤ e.length) : peek rec a 15 cashC.dec = none := by
  have hlen : 1 ≤ (textsAt e a' c).length := by
    rw [textsAt_length]
    exact nParts_pos he
  cases hq : textsAt e a' c with
  | nil => simp [hq] at hlen
  | cons b bs =>
    obtain ⟨t, l, rfl⟩ := mem_textsAt (e := e) (a := a') (c := c) (b := b) (by simp [hq])
    rw [hq, List.cons_append] at h
    obtain ⟨⟨r, hr, hrec⟩, -⟩ := h.head
    obtain ⟨hrd, -⟩ := rd_full textC_ok hr hrec
    refine peek_miss hrd ?_
    rw [enc_tag (c := textC) (v := 0xF5) rfl (by decide)]
    decide

/-- A state row is no quarantine marker. -/
theorem Placed.no_mark {rec : Nat → Option Bytes} {a : Nat} {x : StateRow} {l : Link} {ys : List Body}
    (h : Placed rec a (.state x l :: ys)) : peek rec a 0x50 markC.dec = none := by
  obtain ⟨⟨r, he, hr⟩, -⟩ := h.head
  obtain ⟨hrd, -⟩ := rd_full stateC_ok he hr
  refine peek_miss hrd ?_
  rw [enc_tag (c := stateC) (v := 0x60) rfl (by decide)]
  decide

/-- A CASH row the engine wrote reads back as itself. -/
theorem Placed.cash {rec : Nat → Option Bytes} {a : Nat} {x : CashF} {l : Link} {ys : List Body}
    (h : Placed rec a (.cash x l :: ys)) : peek rec a 15 cashC.dec = some (x, l) ∧ Placed rec (a + 1) ys := by
  obtain ⟨⟨r, he, hr⟩, hys⟩ := h.head
  obtain ⟨hrd, hdec⟩ := rd_full cashC_ok he hr
  exact ⟨peek_hit hrd (enc_tag (c := cashC) (v := 15) rfl (by decide) x) hdec, hys⟩

/-- A quarantine marker the engine wrote reads back as itself and is no text record. -/
theorem Placed.mark {rec : Nat → Option Bytes} {a : Nat} {x : MarkRec} {l : Link} {ys : List Body}
    (h : Placed rec a (.mark x l :: ys)) :
    peek rec a 0x50 markC.dec = some (x, l) ∧ (∀ b l', rd rec a = some (b, l') → tagOf b ≠ 0xF5) ∧
      Placed rec (a + 1) ys := by
  obtain ⟨⟨r, he, hr⟩, hys⟩ := h.head
  obtain ⟨hrd, hdec⟩ := rd_full markC_ok he hr
  have ht := enc_tag (c := markC) (v := 0x50) rfl (by decide) x
  refine ⟨peek_hit hrd ht hdec, fun b l' hb => ?_, hys⟩
  rw [hrd] at hb
  cases hb
  rw [ht]
  decide

open BlindLedger.Financial BlindLedger.Financial.Payment in
/-- The payment a rule answer writes is among the payments after it. -/
theorem written_payment_mem {i : FinancialInput} {w : Writes} {p : Payment} (hw : w.payment = some p) :
    p ∈ (applyWrites i w).payments := by
  simp only [applyWrites, hw]
  split
  · rename_i hs
    obtain ⟨q, hq⟩ := Option.isSome_iff_exists.1 hs
    have hid : q.paymentId = p.paymentId := by
      have h := List.find?_some ((findPayment_eq _ _).symm.trans hq)
      simpa using h
    exact List.mem_map.2 ⟨q, findPayment_mem hq, if_pos hid⟩
  · exact (mem_insertBy _ _ _ _).2 (Or.inl rfl)

open BlindLedger.Financial BlindLedger.Financial.Payment in
/-- A recorded payment, a reversal or a recorded conflict keeps the obligation: the input after it and its result
    are of the obligation it was decided on, and so is the payment it writes. -/
theorem mutated_facts {L : Ledger} {call : Call} {k : Mutation} {w : Writes} {post : FinancialInput}
    {res : FinancialResult} (h : L.outcome call = .mutated k w post res) :
    post.context = L.input.context ∧ res.context = L.input.context ∧
      ∀ p, w.payment = some p →
        p.obligationId = L.input.context.obligationId ∧ p.itemId = L.input.context.itemId := by
  obtain ⟨rfl, hwf, hev, -⟩ := paymentTransition_mutated_post h
  refine ⟨rfl, (evaluate_context hev).trans rfl, fun p hp => ?_⟩
  have hq : paymentWellFormed L.input.context p = true := (wf_facts hwf).2.2.2.1 p (written_payment_mem hp)
  simp only [paymentWellFormed, Bool.and_eq_true, decide_eq_true_eq] at hq
  obtain ⟨⟨⟨⟨⟨-, hB⟩, hC⟩, -⟩, -⟩, -⟩ := hq
  exact ⟨hB, hC⟩

open BlindLedger.Financial BlindLedger.Financial.Payment in
/-- The result of a recorded payment, a reversal or a recorded conflict is one Lean's evaluation returned, so it
    is well formed. -/
theorem mutated_result {L : Ledger} {call : Call} {k : Mutation} {w : Writes} {post : FinancialInput}
    {res : FinancialResult} (h : L.outcome call = .mutated k w post res) : financialResultWellFormed res = true := by
  obtain ⟨-, -, hev, -⟩ := paymentTransition_mutated_post h
  exact evaluate_resultWellFormed hev

/-- An alias keeps the obligation. -/
theorem alias_facts {L : Ledger} {call : Call} {pid : String} {w : BlindLedger.Financial.EvidenceRecord}
    {post : FinancialInput} (h : L.outcome call = .alias pid w post) : post.context = L.input.context := by
  obtain ⟨rfl, -⟩ := BlindLedger.Financial.Payment.alias_shape h
  rfl

open BlindLedger.Financial BlindLedger.Financial.Payment in
/-- A reversal answers a reversal command, and its evidence is of the obligation and names the payment it
    reverses. -/
theorem reversed_facts {L : Ledger} {call : Call} {w : Writes} {post : FinancialInput} {res : FinancialResult}
    {p : Payment} {ev : EvidenceRecord} (h : L.outcome call = .mutated .REVERSED w post res)
    (hp : w.payment = some p) (hev : w.evidence = some ev) :
    (∃ vc, call.command = .reverse vc) ∧ ev.obligationId = L.input.context.obligationId ∧
      ev.reversalOf = some p.paymentId := by
  rcases mutated_shape h with ⟨hk, -⟩ | ⟨hk, -⟩ | ⟨-, vc, p0, e, hc, -, -, rfl, rfl, -⟩
  · cases hk
  · cases hk
  · simp only [Option.some.injEq] at hp hev
    subst hp
    subst hev
    exact ⟨⟨vc, hc⟩, rfl, rfl⟩

/-- The checker and the engine read the request an alias pays the same way. -/
theorem paidBy_eq (L : Ledger) (r : BlindLedger.Financial.Payment.RecordCommand) :
    paidBy L r.commonOriginId = existingPays L r := rfl

/-- The checker and the engine build a reversal's request the same way. -/
theorem reversalReq_eq (scope : Bytes) (item : String) (L : Ledger) (r : ReverseCommand) (now : Nat) :
    reversalReq scope item L r now = reverseReq scope item L.input.evidence r now := by
  obtain ⟨pid, eid, origin, eventAt⟩ := r
  have hfind : L.input.evidence.find? (·.evidenceId == eid) =
      BlindLedger.Financial.findEvidence L.input.evidence eid :=
    (BlindLedger.Financial.Payment.findEvidence_eq _ _).symm
  unfold reversalReq reverseReq reverseFilled BlindLedger.Financial.Payment.nonEmpty
  dsimp only
  rw [hfind]
  cases BlindLedger.Financial.findEvidence L.input.evidence eid <;> cases eventAt <;>
    cases origin with
    | none => rfl
    | some o => by_cases ho : o = "" <;> simp [Option.filter, ho, utf8]

/-- The CASH row (`op` 0) or void row (`op` 1) the engine writes for payment `p`, dated at `at_`. -/
def cashFact (c : Cmd) (item : String) (op : Nat) (p : BlindLedger.Financial.Payment) (at_ : Nat) (pays : Bytes) :
    CashF :=
  { h := { op, subject := obOf c.scope (utf8 item),
           sid := sidOf 15 [obOf c.scope (utf8 item), utf8 p.commonOriginId], vstart := utcDate at_,
           vstop := utcDate at_, lineUntil := 0, receipt := c.src, roff := 0 },
    amount := p.amountCents, eventMs := at_, pays, pid := cidOf c.scope (utf8 ("PAYMENT:" ++ p.paymentId)),
    ecls := 0, origin := display 51 p.commonOriginId }

/-- What the engine writes for a recorded payment or a reversal: the CASH or void row `cash` of payment `pid`,
    the command's text, the state row, and the evaluation reference. -/
def cashPlan (v : View) (c : Cmd) (o : Obl) (item : String) (pc : Command) (mkind : Nat) (res : FinancialResult)
    (cash : CashF) (pid : String) (rqd : Bytes) : Nat → Plan := fun n =>
  { rqd, result := n + 1 + 1 + nParts (encodeCommand pc) + 1, nt := 0,
    lg := lgOf (o.noClass || v.srcClass == 0), link := ⟨v.cmdPrev, nextCount v.cmdCount⟩,
    body := [Body.cash cash ⟨o.fact + 1, nextCount o.factCount⟩] ++
      textsAt (encodeCommand pc) (n + 1 + 1) (nextCount o.factCount) ++
      [.state (rowOf mkind cash.amount res res.afterRevision
        (BlindLedger.Financial.Payment.step o.led ⟨c.atMs, c.exprev, pc⟩).input.conflicts.length (n + 1) o.caseRef
        (n + 1 + 1) (n + 1) o.led.input.obligation.dueAt c.atMs (lgOf (o.noClass || v.srcClass == 0)))
        ⟨o.head + 1, nextCount o.headCount⟩] ++
      textsAt (evalRef res) (n + 1 + 1 + nParts (encodeCommand pc) + 1) (nextCount o.headCount),
    obl := some (obOf c.scope (utf8 item),
      { o with
        led := BlindLedger.Financial.Payment.step o.led ⟨c.atMs, c.exprev, pc⟩,
        noClass := o.noClass || v.srcClass == 0,
        head := n + 1 + 1 + nParts (encodeCommand pc), headCount := nextCount o.headCount,
        fact := n + 1, factCount := nextCount o.factCount, cash := (pid, n + 1) :: o.cash }) }

/-- What the engine checked of a payment or a reversal it decided, and what it then writes: one plan for each of
    the four answers of Lean's rule that it accepts. -/
theorem core_payment {v : View} {c : Cmd} {f : Nat → Plan} {item : String} {pc : Command} (h : core v c = .ok f)
    (ha : c.act = .payment item pc) :
    ∃ o, v.obl = some o ∧ o.names c.scope item = true ∧
      BlindLedger.Financial.Payment.commandWellFormed pc = true ∧
      ((∃ pid w post res k r, pc = .record r ∧ o.led.outcome ⟨c.atMs, c.exprev, pc⟩ = .alias pid w post ∧
          evaluate post = some res ∧ List.lookup pid o.cash = some k ∧
          f = fun n =>
            { rqd := rqdIn c (some o) (.alias (existingPays o.led r)),
              result := n + 1 + nParts (encodeCommand pc) + 1, nt := nParts (encodeCommand pc),
              lg := lgOf (o.noClass || v.srcClass == 0), link := ⟨v.cmdPrev, nextCount v.cmdCount⟩,
              body := textsAt (encodeCommand pc) (n + 1) (nextCount v.cmdCount) ++
                [.state (rowOf 17 0 res post.beforeRevision
                  (BlindLedger.Financial.Payment.step o.led ⟨c.atMs, c.exprev, pc⟩).input.conflicts.length k
                  o.caseRef (o.fact + 1) (n + 1) o.led.input.obligation.dueAt c.atMs
                  (lgOf (o.noClass || v.srcClass == 0))) ⟨o.head + 1, nextCount o.headCount⟩],
              obl := some (obOf c.scope (utf8 item),
                { o with
                  led := BlindLedger.Financial.Payment.step o.led ⟨c.atMs, c.exprev, pc⟩,
                  noClass := o.noClass || v.srcClass == 0,
                  head := n + 1 + nParts (encodeCommand pc), headCount := nextCount o.headCount }) }) ∨
       (∃ w post res r, pc = .record r ∧
          o.led.outcome ⟨c.atMs, c.exprev, pc⟩ = .mutated .CONFLICT_RECORDED w post res ∧
          f = fun n =>
            { rqd := rqdIn c (some o) .conflict,
              result := n + 1 + nParts (encodeCommand pc) + 2, nt := nParts (encodeCommand pc),
              lg := lgOf (o.noClass || v.srcClass == 0), link := ⟨v.cmdPrev, nextCount v.cmdCount⟩,
              body := textsAt (encodeCommand pc) (n + 1) (nextCount v.cmdCount) ++
                [.mark { src := c.src, fkind := 15, subject := obOf c.scope (utf8 item), receipt := 0, roff := 0,
                         cause := originConflict, sidk := 1,
                         sid := sidOf 15 [obOf c.scope (utf8 item), utf8 r.commonOriginId] }
                   ⟨o.fact + 1, nextCount o.factCount⟩,
                 .state (rowOf 16 0 res res.afterRevision
                  (BlindLedger.Financial.Payment.step o.led ⟨c.atMs, c.exprev, pc⟩).input.conflicts.length
                  (n + 1 + nParts (encodeCommand pc)) o.caseRef (n + 1 + nParts (encodeCommand pc) + 1) (n + 1)
                  o.led.input.obligation.dueAt c.atMs (lgOf (o.noClass || v.srcClass == 0)))
                  ⟨o.head + 1, nextCount o.headCount⟩] ++
                textsAt (evalRef res) (n + 1 + nParts (encodeCommand pc) + 2) (nextCount o.headCount),
              obl := some (obOf c.scope (utf8 item),
                { o with
                  led := BlindLedger.Financial.Payment.step o.led ⟨c.atMs, c.exprev, pc⟩,
                  noClass := o.noClass || v.srcClass == 0,
                  head := n + 1 + nParts (encodeCommand pc) + 1, headCount := nextCount o.headCount,
                  fact := n + 1 + nParts (encodeCommand pc), factCount := nextCount o.factCount }) }) ∨
       (∃ w post res p k r, pc = .record r ∧
          o.led.outcome ⟨c.atMs, c.exprev, pc⟩ = .mutated .RECORDED w post res ∧
          w.payment = some p ∧ w.receipt = some k ∧
          f = cashPlan v c o item pc 14 res (cashFact c item 0 p p.eventAt (paysOf c.scope k)) p.paymentId
            (rqdOf (canon (paymentIdentityReq c.scope item r k)))) ∨
       (∃ w post res p ev, o.led.outcome ⟨c.atMs, c.exprev, pc⟩ = .mutated .REVERSED w post res ∧
          w.payment = some p ∧ w.evidence = some ev ∧
          f = cashPlan v c o item pc 15 res (cashFact c item 1 p ev.eventAt (zeros 32)) p.paymentId
            (rqdIn c (some o) .recorded))) := by
  unfold core at h
  simp only [ha] at h
  by_cases ht : c.atMs < v.lastMs ∨ 2 ^ 63 ≤ c.atMs
  · rw [if_pos ht] at h
    cases h
  rw [if_neg ht] at h
  cases ho : v.obl with
  | none => simp [ho] at h
  | some o =>
    simp only [ho] at h
    split at h
    · cases h
    rename_i hnames
    split at h
    · cases h
    rename_i hwf
    refine ⟨o, rfl, by simpa using hnames, by simpa using hwf, ?_⟩
    split at h
    all_goals try (cases h; done)
    all_goals split at h
    all_goals try (cases h; done)
    all_goals cases h
    · exact Or.inl ⟨_, _, _, _, _, _, rfl, by assumption, by assumption, by assumption, rfl⟩
    · exact Or.inr (Or.inl ⟨_, _, _, _, rfl, by assumption, rfl⟩)
    · exact Or.inr (Or.inr (Or.inl ⟨_, _, _, _, _, _, rfl, by assumption, by assumption, by assumption, rfl⟩))
    · exact Or.inr (Or.inr (Or.inr ⟨_, _, _, _, _, by assumption, by assumption, by assumption, rfl⟩))

theorem forward_payment {st : Chk} {v : View} {c : Cmd} {f : Nat → Plan} {i : Nat} {bs : List Bytes}
    {rec : Nat → Option Bytes} {item : String} {pc : Command} (hpre : Pre st v c) (hpl : c.plain)
    (hcore : core v c = .ok f) (hb : (f i).bytes c = some bs)
    (hrec : ∀ j r, bs[j]? = some r → rec (i + j) = some r) (ha : c.act = .payment item pc) :
    ownEnd rec i = i + bs.length ∧
      ∃ st', checkOne st rec (i + bs.length) i = .ok (st', i + bs.length) ∧ Post st st' c (f i) i := by
  obtain ⟨hs, hbody, hlen, hpk⟩ := cmd_start hpre hpl hcore hb hrec
  obtain ⟨o, hvo, hnames, hwf, hcase⟩ := core_payment hcore ha
  obtain ⟨-, -, -, hsrc⟩ := hpl
  obtain ⟨act, scope, atMs, exprev, actor, role, attr, src⟩ := c
  dsimp only at ha hsrc hcase
  subst ha
  subst hsrc
  obtain ⟨hsc, hit⟩ : scopeOfCtx o.led.input.context = scope ∧ o.led.input.context.itemId = item := by
    simpa [Obl.names] using hnames
  subst hsc
  subst hit
  obtain ⟨E, hE, hsame⟩ := hpre.obl _ o rfl hvo
  obtain rfl := hsame.eq
  have hE' : ∀ ctx, ctx = o.led.input.context → st.obl[obOfCtx ctx]? =
      some ⟨o.led, o.head, o.headCount, o.caseRef, o.fact, o.factCount, o.cash, o.noClass⟩ := fun ctx h => by
    rw [h]
    exact hE
  have hframe := (BlindLedger.Financial.Payment.step_frame o.led ⟨atMs, exprev, pc⟩).2
  have he1 := encodeCommand_length pc
  have hcmd := command_rebuild pc hwf
  have hlg := lgOf_keeps o.noClass (v.srcClass == 0)
  rcases hcase with ⟨pid, w, post, res, k, r, rfl, hout, hres, hfact, rfl⟩ |
    ⟨w, post, res, r, rfl, hout, rfl⟩ | ⟨w, post, res, p, rc, r, rfl, hout, hp, hrc, rfl⟩ |
    ⟨w, post, res, p, ev, hout, hp, hev, rfl⟩
  · -- An alias.
    dsimp only [Plan.cmd] at hs
    dsimp only at hbody
    simp only [List.length_append, textsAt_length, List.length_cons, List.length_nil] at hlen
    obtain ⟨hA, hS⟩ := hbody.texts
    obtain ⟨hrow, htag, -⟩ := hS.state
    have hctx : res.context = o.led.input.context := (evaluate_context hres).trans (alias_facts hout)
    have hk : i + 1 + nParts (encodeCommand (.record r)) + 1 = i + bs.length := by omega
    rw [← hk]
    refine ⟨(ownEnd_row (k := 5) (m := 17) hpk hS.state_peek rfl (by decide) rfl (by omega) rfl).trans (if_pos rfl),
      _, checkOne_alias hs rfl (Placed.no_cash hbody he1) (hA.element he1 (by omega) fun _ => htag)
      (beq_iff_eq.2 (by dsimp only; omega)) hcmd (Placed.no_mark hS) hrow (hE' _ hctx) rfl
      (by dsimp only; rw [exprev_round]; exact hout) rfl hres hfact
      (band_intro (by simp [stateAgree, rowOf]) (beq_iff_eq.2 rfl)) hlg (beq_iff_eq.2 rfl)
      (beq_iff_eq.2 (by rw [paidBy_eq] <;> rfl)) (beq_iff_eq.2 rfl)
      (by dsimp only; rw [exprev_round]; simp [rowLinks, rowFixed, rowOf, hframe]), ?_⟩
    refine ⟨rfl, rfl, rfl, rfl, rfl, _, congrArg (fun k => st.obl.insert k _) (congrArg obOfCtx hctx), ?_⟩
    exact ⟨by dsimp only; rw [exprev_round] <;> rfl, rfl, rfl, rfl, rfl, rfl, rfl, lgOf_two _⟩
  · -- A recorded conflict.
    dsimp only [Plan.cmd] at hs
    dsimp only at hbody
    simp only [List.append_assoc, List.cons_append, List.nil_append] at hbody
    simp only [List.length_append, textsAt_length, List.length_cons, List.length_nil] at hlen
    obtain ⟨hA, hM⟩ := hbody.texts
    obtain ⟨hmark, hmtag, hS⟩ := Placed.mark hM
    obtain ⟨hrow, -, hB⟩ := hS.state
    have hB' : Placed rec (i + 1 + nParts (encodeCommand (.record r)) + 1 + 1)
        (textsAt (evalRef res) (i + 1 + nParts (encodeCommand (.record r)) + 1 + 1) (nextCount o.headCount)) := hB
    obtain ⟨-, hctx, -⟩ := mutated_facts hout
    have hk : i + 1 + nParts (encodeCommand (.record r)) + 1 + 1 + nParts (evalRef res) = i + bs.length := by
      omega
    have href := hB'.afterRef (n := i + bs.length) (by omega) (fun h => absurd h (by omega))
    rw [hk] at href
    refine ⟨(ownEnd_ref (k := 5) (m := 16) hpk hS (mutated_result hout) rfl (by decide) rfl (by omega) rfl
        (by decide)).trans hk,
      _, checkOne_conflict hs rfl (Placed.no_cash hbody he1) (hA.element he1 (by omega) fun _ => hmtag)
      (beq_iff_eq.2 (by dsimp only; omega)) hcmd hmark hrow (hE' _ hctx) rfl rfl
      (by dsimp only; rw [exprev_round]; exact hout) rfl (by simp [stateAgree, rowOf]) hlg (beq_iff_eq.2 rfl)
      (beq_iff_eq.2 rfl) (beq_iff_eq.2 rfl)
      (by dsimp only; rw [exprev_round]; simp [rowLinks, rowFixed, rowOf, hframe]) href, ?_⟩
    refine ⟨rfl, rfl, rfl, rfl, rfl, _, congrArg (fun k => st.obl.insert k _) (congrArg obOfCtx hctx), ?_⟩
    exact ⟨by dsimp only; rw [exprev_round] <;> rfl, rfl, rfl, rfl, rfl, rfl, rfl, lgOf_two _⟩
  · -- A recorded payment.
    dsimp only [Plan.cmd, cashPlan] at hs
    dsimp only [cashPlan] at hbody
    simp only [List.append_assoc, List.cons_append, List.nil_append] at hbody
    simp only [cashPlan, List.length_append, textsAt_length, List.length_cons, List.length_nil] at hlen
    obtain ⟨hcash, hT⟩ := Placed.cash hbody
    obtain ⟨hA, hS⟩ := hT.texts
    obtain ⟨hrow, htag, hB⟩ := hS.state
    obtain ⟨hpc, hctx, hpay⟩ := mutated_facts hout
    obtain ⟨hpo, hpi⟩ := hpay p hp
    have hk : i + 1 + 1 + nParts (encodeCommand (.record r)) + 1 + nParts (evalRef res) = i + bs.length := by
      omega
    have href := hB.afterRef (n := i + bs.length) (by omega) (fun h => absurd h (by omega))
    rw [hk] at href
    refine ⟨(ownEnd_ref (k := 5) (m := 14) hpk hS (mutated_result hout) rfl (by decide) rfl (by omega) rfl
        (by decide)).trans hk,
      _, checkOne_recorded hs rfl hcash (hA.element he1 (by omega) fun _ => htag) (beq_iff_eq.2 rfl) hcmd
      (Placed.no_mark hS) hrow (hE' _ hctx) rfl rfl (by simp [hdrFixed, cashFact])
      (by dsimp only; rw [exprev_round]; exact hout) rfl hp hrc
      (by simp [cashAgree, cashFact, stateAgree, rowOf, obOfCtx, hpc, hpo, hpi]) hlg (beq_iff_eq.2 rfl)
      (beq_iff_eq.2 rfl) (beq_iff_eq.2 rfl)
      (by dsimp only; rw [exprev_round]; simp [rowLinks, rowFixed, rowOf, hframe]) href, ?_⟩
    refine ⟨rfl, rfl, rfl, rfl, rfl, _, congrArg (fun k => st.obl.insert k _) (congrArg obOfCtx hctx), ?_⟩
    exact ⟨by dsimp only; rw [exprev_round] <;> rfl, rfl, rfl, rfl, rfl, rfl, rfl, lgOf_two _⟩
  · -- A reversal.
    obtain ⟨⟨vc, hvc⟩, heo, her⟩ := reversed_facts hout hp hev
    dsimp only at hvc
    subst hvc
    dsimp only [Plan.cmd, cashPlan] at hs
    dsimp only [cashPlan] at hbody
    simp only [List.append_assoc, List.cons_append, List.nil_append] at hbody
    simp only [cashPlan, List.length_append, textsAt_length, List.length_cons, List.length_nil] at hlen
    obtain ⟨hcash, hT⟩ := Placed.cash hbody
    obtain ⟨hA, hS⟩ := hT.texts
    obtain ⟨hrow, htag, hB⟩ := hS.state
    obtain ⟨hpc, hctx, hpay⟩ := mutated_facts hout
    obtain ⟨hpo, hpi⟩ := hpay p hp
    have hk : i + 1 + 1 + nParts (encodeCommand (.reverse vc)) + 1 + nParts (evalRef res) = i + bs.length := by
      omega
    have href := hB.afterRef (n := i + bs.length) (by omega) (fun h => absurd h (by omega))
    rw [hk] at href
    refine ⟨(ownEnd_ref (k := 6) (m := 15) hpk hS (mutated_result hout) rfl (by decide) rfl (by omega) rfl
        (by decide)).trans hk,
      _, checkOne_reversed hs rfl hcash (hA.element he1 (by omega) fun _ => htag) (beq_iff_eq.2 rfl) hcmd
      (Placed.no_mark hS) hrow (hE' _ hctx) rfl rfl (by simp [hdrFixed, cashFact])
      (by dsimp only; rw [exprev_round]; exact hout) rfl hp hev
      (by simp [cashVoidAgree, cashFact, stateAgree, rowOf, obOfCtx, hpc, hpo, hpi, heo, her]) hlg
      (beq_iff_eq.2 rfl) (beq_iff_eq.2 (by rw [reversalReq_eq] <;> rfl)) (beq_iff_eq.2 rfl)
      (by dsimp only; rw [exprev_round]; simp [rowLinks, rowFixed, rowOf, hframe]) href, ?_⟩
    refine ⟨rfl, rfl, rfl, rfl, rfl, _, congrArg (fun k => st.obl.insert k _) (congrArg obOfCtx hctx), ?_⟩
    exact ⟨by dsimp only; rw [exprev_round] <;> rfl, rfl, rfl, rfl, rfl, rfl, rfl, lgOf_two _⟩

/-! ## An opening -/

/-- The checker's and the engine's case reference of an opening's row are the same. -/
theorem caseRef_eq (a m : Nat) : (if a + m = a then 0 else a + m) = (if m = 0 then 0 else a + m) := by
  by_cases h : m = 0
  · simp [h]
  · rw [if_neg h, if_neg (by omega)]

/-- An OBLIG fact the engine wrote reads back as itself. -/
theorem Placed.oblig {rec : Nat → Option Bytes} {a : Nat} {x : ObligF} {l : Link} {ys : List Body}
    (h : Placed rec a (.oblig x l :: ys)) :
    read rec a obligC.dec "OBLIG fact" = .ok (x, l) ∧ Placed rec (a + 1) ys := by
  obtain ⟨⟨r, he, hr⟩, hys⟩ := h.head
  obtain ⟨hrd, hdec⟩ := rd_full obligC_ok he hr
  exact ⟨read_intro hrd hdec, hys⟩

/-- The case records the engine wrote read back as themselves, and none is a text record. -/
theorem placed_cases {α : Type} {rec : Nat → Option Bytes} {g : α → CaseRec} {lk : Link} :
    ∀ (ks : List α) (a : Nat), Placed rec a (ks.map fun k => Body.caseR (g k) lk) →
      ∀ (t : Nat) (ht : t < ks.length), read rec (a + t) caseC.dec "case record" = .ok (g ks[t], lk) ∧
        ∀ b l, rd rec (a + t) = some (b, l) → tagOf b ≠ 0xF5
  | [], _, _, t, ht => absurd ht (Nat.not_lt_zero t)
  | k :: ks, a, h, t, ht => by
    have h' : Placed rec a (Body.caseR (g k) lk :: ks.map fun k => Body.caseR (g k) lk) := h
    obtain ⟨⟨r, he, hr⟩, hys⟩ := h'.head
    cases t with
    | zero =>
      obtain ⟨hrd, hdec⟩ := rd_full caseC_ok he hr
      refine ⟨read_intro hrd hdec, fun b l hb => ?_⟩
      have hb' : rd rec a = some (b, l) := hb
      rw [hrd] at hb'
      cases hb'
      rw [enc_tag (c := caseC) (v := 0x72) rfl (by decide)]
      decide
    | succ t =>
      have ih := placed_cases ks (a + 1) hys t (Nat.lt_of_succ_lt_succ ht)
      rw [show a + (t + 1) = a + 1 + t by omega]
      exact ih

/-- The OBLIG fact the engine writes for an opening. -/
def openFact (c : Cmd) (i : FinancialInput) : ObligF :=
  { h := { op := 0, subject := obOfCtx i.context,
           sid := obligSidOf c.scope (utf8 i.context.populationId) (utf8 i.context.itemId),
           vstart := utcDate c.atMs, vstop := utcDate c.atMs, lineUntil := 0, receipt := c.src, roff := 0 },
    owed := i.obligation.owedCents, dueMs := i.obligation.dueAt, rule := i.obligation.ruleVersion,
    pop := popOf c.scope (utf8 i.context.populationId), item := display 51 i.context.itemId,
    period := display 21 i.context.periodId, ecls := 0 }

/-- The OPEN record the engine writes for a case of an opening whose command record is record `n`. -/
def openCase (c : Cmd) (i : FinancialInput) (lg n : Nat) (k : BlindLedger.Financial.CaseRecord) : CaseRec :=
  { op := 1, ck := ckOf c.scope (utf8 k.caseId), ob := obOfCtx i.context,
    status := (BlindLedger.Financial.encodeCaseStatus k.status).toNat, role := 0, acct := 0, reason := 0,
    dueMs := k.dueAt, atMs := k.updatedAt, conds := zeros 64, act := 0, cmd := n + 1, assignee := zeros 32, lg,
    nt := 0 }

/-- What the engine writes for an opening: the OBLIG fact, the input's text, one OPEN record for each case of the
    input after its evaluation, the state row, and the evaluation reference. -/
def openPlan (v : View) (c : Cmd) (i : FinancialInput) (res : FinancialResult) : Nat → Plan := fun n =>
  { rqd := rqdIn c none .recorded,
    result := n + 1 + 1 + nParts (rawEncodeFinancialInput i) + (commitInput i res).cases.length + 1, nt := 0,
    lg := lgOf (v.srcClass == 0 || !i.evidence.isEmpty), link := ⟨v.cmdPrev, nextCount v.cmdCount⟩,
    body := [Body.oblig (openFact c i) ⟨0, 1⟩] ++ textsAt (rawEncodeFinancialInput i) (n + 1 + 1) 1 ++
      (commitInput i res).cases.map (fun k =>
        Body.caseR (openCase c i (lgOf (v.srcClass == 0 || !i.evidence.isEmpty)) n k) ⟨0, 1⟩) ++
      [.state (rowOf 13 0 res res.afterRevision i.conflicts.length (n + 1)
        (if (commitInput i res).cases.length = 0 then 0
          else n + 1 + 1 + nParts (rawEncodeFinancialInput i) + (commitInput i res).cases.length)
        (n + 1 + 1) (n + 1) i.obligation.dueAt c.atMs (lgOf (v.srcClass == 0 || !i.evidence.isEmpty))) ⟨0, 1⟩] ++
      textsAt (evalRef res) (n + 1 + 1 + nParts (rawEncodeFinancialInput i) + (commitInput i res).cases.length + 1) 1,
    obl := some (obOfCtx i.context,
      { led := { input := commitInput i res, receipts := [] }, noClass := v.srcClass == 0 || !i.evidence.isEmpty,
        head := n + 1 + 1 + nParts (rawEncodeFinancialInput i) + (commitInput i res).cases.length, headCount := 1,
        caseRef := if (commitInput i res).cases.length = 0 then 0
          else n + 1 + 1 + nParts (rawEncodeFinancialInput i) + (commitInput i res).cases.length,
        fact := n + 1, factCount := 1, cash := [] }) }

/-- What the engine checked of an opening it decided, and what it then writes. -/
theorem core_open {v : View} {c : Cmd} {f : Nat → Plan} {i : FinancialInput} (h : core v c = .ok f)
    (ha : c.act = .population i) :
    ∃ p cls res, v.pack = some (p, cls) ∧ (p == i.pack) = true ∧ (scopeOfCtx i.context == c.scope) = true ∧
      v.oblKnown = false ∧
      (BlindLedger.Financial.financialInputWellFormed i && i.evaluatedAt == c.atMs && i.payments.isEmpty &&
        i.claims.isEmpty && i.determinations.isEmpty && i.conflicts.isEmpty && i.actions.isEmpty &&
        decide ((rawEncodeFinancialInput i).length ≤ BlindLedger.Financial.maxTotalEncodedBytes)) = true ∧
      evaluate i = some res ∧ (commitInput i res).cases.any (·.caseId.startsWith "FOLLOW:") = false ∧
      c.exprev = none ∧ f = openPlan v c i res := by
  unfold core at h
  simp only [ha] at h
  by_cases ht : c.atMs < v.lastMs ∨ 2 ^ 63 ≤ c.atMs
  · rw [if_pos ht] at h
    cases h
  rw [if_neg ht] at h
  by_cases hx : c.exprev.isSome = true
  · rw [if_pos hx] at h
    cases h
  rw [if_neg hx] at h
  have hex : c.exprev = none := by
    cases hc : c.exprev with
    | none => rfl
    | some r =>
      rw [hc] at hx
      exact absurd rfl hx
  cases hp : v.pack with
  | none => simp [hp] at h
  | some pc =>
    obtain ⟨p, cls⟩ := pc
    simp only [hp] at h
    split at h
    · cases h
    rename_i hpk
    split at h
    · cases h
    rename_i hsc
    split at h
    · cases h
    rename_i hknown
    split at h
    · cases h
    rename_i hwf
    split at h
    · cases h
    rename_i res hres
    split at h
    · cases h
    rename_i hfol
    cases h
    exact ⟨p, cls, res, rfl, by simpa [bne] using hpk, by simpa [bne] using hsc, eq_false_of_ne_true hknown,
      by simpa using hwf, hres, eq_false_of_ne_true hfol, hex, rfl⟩

theorem forward_open {st : Chk} {v : View} {c : Cmd} {f : Nat → Plan} {i : Nat} {bs : List Bytes}
    {rec : Nat → Option Bytes} {inp : FinancialInput} (hpre : Pre st v c) (hpl : c.plain)
    (hcore : core v c = .ok f) (hb : (f i).bytes c = some bs)
    (hrec : ∀ j r, bs[j]? = some r → rec (i + j) = some r) (ha : c.act = .population inp) :
    ownEnd rec i = i + bs.length ∧
      ∃ st', checkOne st rec (i + bs.length) i = .ok (st', i + bs.length) ∧ Post st st' c (f i) i := by
  obtain ⟨hs, hbody, hlen, hpk⟩ := cmd_start hpre hpl hcore hb hrec
  obtain ⟨p, cls, res, hvp, hpe, hscope, hunk, hwf, hres, hfol, hex, rfl⟩ := core_open hcore ha
  obtain ⟨-, -, -, hsrc⟩ := hpl
  obtain ⟨act, scope, atMs, exprev, actor, role, attr, src⟩ := c
  dsimp only at ha hex hsrc hscope hwf
  subst ha
  subst hex
  subst hsrc
  obtain rfl : scopeOfCtx inp.context = scope := beq_iff_eq.1 hscope
  simp only [Bool.and_eq_true, decide_eq_true_eq, beq_iff_eq] at hwf
  obtain ⟨⟨⟨⟨⟨⟨⟨hw, hat⟩, hpay⟩, hcl⟩, hdet⟩, hcon⟩, hact⟩, hlenE⟩ := hwf
  subst hat
  have hget : st.packs[cidFor (scopeOfCtx inp.context) 1 (utf8 inp.pack.packId)]? = some p :=
    hpre.pack _ p cls rfl hvp
  have hfree : st.obl.contains (obOfCtx inp.context) = false := hpre.unknown _ rfl hunk
  dsimp only [Plan.cmd, openPlan] at hs
  dsimp only [openPlan] at hbody
  simp only [List.append_assoc, List.cons_append, List.nil_append] at hbody
  simp only [openPlan, List.length_append, textsAt_length, List.length_cons, List.length_nil, List.length_map]
    at hlen
  obtain ⟨hf, hT⟩ := Placed.oblig hbody
  obtain ⟨hA, hC⟩ := hT.texts
  obtain ⟨hK, hS⟩ := hC.split
  rw [List.length_map] at hS
  have hcs := placed_cases _ _ hK
  obtain ⟨hrow, htag, hB⟩ := hS.state
  have he1 : 1 ≤ (rawEncodeFinancialInput inp).length := by
    have h := rawEncode_isEmpty inp
    cases he : rawEncodeFinancialInput inp with
    | nil => simp [he] at h
    | cons _ _ => simp
  -- The record after the input's text is a case record, or the row when the input has no case.
  have htagj : ∀ b l, rd rec (i + 1 + 1 + nParts (rawEncodeFinancialInput inp)) = some (b, l) → tagOf b ≠ 0xF5 := by
    rcases Nat.eq_zero_or_pos (commitInput inp res).cases.length with h0 | hpos
    · have h := htag
      rw [h0] at h
      exact h
    · exact (hcs 0 hpos).2
  have hel := hA.element (n := i + bs.length) he1 (by omega) fun _ => htagj
  have hk : i + 1 + 1 + nParts (rawEncodeFinancialInput inp) + (commitInput inp res).cases.length + 1 +
      nParts (evalRef res) = i + bs.length := by omega
  have href := hB.afterRef (n := i + bs.length) (by omega) (fun h => absurd h (by omega))
  rw [hk] at href
  refine ⟨(ownEnd_ref (k := 2) (m := 13) hpk hS (BlindLedger.Financial.evaluate_resultWellFormed hres) rfl
      (by decide) rfl (by omega) rfl (by decide)).trans hk,
    _, checkOne_open hs rfl hf hel (opening_rebuild hw hlenE) hres rfl
    (fun t ht => ⟨_, _, (hcs t ht).1, ?_⟩) hrow ?_ ?_ ?_ ?_ ?_ hfree href, ?_⟩
  · have hnf : ((commitInput inp res).cases[t].caseId.startsWith "FOLLOW:") = false :=
      eq_false_of_ne_true fun hy => by
        have hall := List.any_eq_false.1 hfol _ (List.getElem_mem ht)
        exact hall hy
    simp [openCase, caseAgree, caseFixed, hnf]
  · rw [hget]
    simpa using hpe
  · cases inp.evidence.isEmpty <;> simp [hpay, hcl, hdet, hcon, hact, lgOf]
  · exact band_intro (band_intro (band_intro (band_intro (band_intro (beq_iff_eq.2 rfl) (beq_iff_eq.2 rfl))
      (beq_iff_eq.2 rfl)) (beq_iff_eq.2 rfl)) (beq_iff_eq.2 rfl)) (beq_iff_eq.2 rfl)
  · refine band_intro (band_intro (band_intro (beq_iff_eq.2 rfl) (rowOf_agree _ _ _ _ _ _ _ _ _ _ _)) ?_)
      (beq_iff_eq.2 rfl)
    rw [caseRef_eq]
    simp [rowLinks, rowFixed, rowOf, commitInput]
  · simp [openFact, hdrFixed]
  · refine ⟨rfl, rfl, rfl, rfl, rfl, _, rfl, ?_⟩
    exact ⟨rfl, rfl, rfl, caseRef_eq _ _, rfl, rfl, rfl, lgOf_two _⟩

/-! ## Every decided command -/

/-- Part 2: the checker passes the records of every decided command. -/
theorem forward : Forward := by
  intro st v c f i bs rec hpre hpl hcore hb hrec
  cases ha : c.act with
  | pack p cls => exact forward_pack hpre hpl hcore hb hrec ha
  | population inp => exact forward_open hpre hpl hcore hb hrec ha
  | payment item pc => exact forward_payment hpre hpl hcore hb hrec ha
  | evaluate item r => exact forward_eval hpre hpl hcore hb hrec ha
  | other k =>
    unfold core at hcore
    simp only [ha] at hcore
    split at hcore <;> cases hcore

end BlindLedger.Gate.Obligations
