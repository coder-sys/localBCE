import BlindLedger.Financial.DecisionPackage.Decide

/-! Laws of the decision-package frame (Decide.lean). -/

namespace BlindLedger.Financial.DecisionPackage
open BlindLedger.Financial

theorem openRequests_length (left : Nat) (rs : List PkgActionRow) : (openRequests left rs).length = rs.length := by
  simp [openRequests]

private theorem rowBefore_irrefl (a : PkgActionRow) : rowBefore a a = false := by
  simp [rowBefore]
  exact Std.lt_irrefl

private theorem rowBefore_trans {a b c : PkgActionRow} (h1 : rowBefore a b = true) (h2 : rowBefore b c = true) :
    rowBefore a c = true := by
  simp only [rowBefore, Bool.or_eq_true, decide_eq_true_eq, Bool.and_eq_true, beq_iff_eq] at *
  rcases h1 with h1 | ⟨e1, l1⟩ <;> rcases h2 with h2 | ⟨e2, l2⟩
  · left; omega
  · left; omega
  · left; omega
  · right; exact ⟨by omega, String.lt_trans l1 l2⟩

private theorem rowBefore_asymm {a b : PkgActionRow} (h : rowBefore a b = true) : rowBefore b a = false := by
  cases h' : rowBefore b a
  · rfl
  · have := rowBefore_trans h h'; rw [rowBefore_irrefl] at this; exact absurd this (by decide)

private theorem inOrder_head {r : PkgActionRow} : ∀ {rs : List PkgActionRow}, inOrder (r :: rs) = true →
    ∀ x ∈ rs, rowBefore r x = true
  | [], _, x, hx => absurd hx List.not_mem_nil
  | b :: rs, h, x, hx => by
    simp only [inOrder, Bool.and_eq_true] at h
    rcases List.mem_cons.1 hx with rfl | hx
    · exact h.1
    · exact rowBefore_trans h.1 (inOrder_head h.2 x hx)

private theorem inOrder_tail {r : PkgActionRow} : ∀ {rs : List PkgActionRow}, inOrder (r :: rs) = true → inOrder rs = true
  | [], _ => rfl
  | b :: rs, h => by simp only [inOrder, Bool.and_eq_true] at h; exact h.2

/-- `Payment.openState` read on the rows. -/
private theorem openState_row (s : Nat) (rs : List PkgActionRow) (x : PkgActionRow) :
    Payment.openState s (rs.map requestPaid) (requestPaid x) =
      if collects x then min (x.amountCents - x.paidCents)
        (s - ((rs.filter fun b => collects b && rowBefore b x).map fun b => b.amountCents - b.paidCents).sum) else 0 := by
  simp only [Payment.openState, requestPaid, List.filter_map, List.map_map]
  rfl

private theorem openRequests_rows (s : Nat) (rs : List PkgActionRow) :
    openRequests s rs = rs.map fun x => if collects x then min (x.amountCents - x.paidCents)
      (s - ((rs.filter fun b => collects b && rowBefore b x).map fun b => b.amountCents - b.paidCents).sum) else 0 :=
  List.map_congr_left fun x _ => openState_row s rs x

/-- R2, row by row, exactly: in frame order the oldest row collects its unpaid part up to the shortfall, and the rows
    after it share what is left by the same rule. A row that does not collect gets 0 and leaves the shortfall whole. -/
theorem openRequests_cons {s : Nat} {r : PkgActionRow} {rs : List PkgActionRow} (h : inOrder (r :: rs) = true) :
    openRequests s (r :: rs) = (if collects r then min (r.amountCents - r.paidCents) s else 0) ::
      openRequests (s - if collects r then r.amountCents - r.paidCents else 0) rs := by
  have hb := inOrder_head h
  rw [openRequests_rows, openRequests_rows]
  simp only [List.map_cons, List.cons.injEq]
  constructor
  · have : ((r :: rs).filter fun b => collects b && rowBefore b r) = [] := by
      refine List.filter_eq_nil_iff.2 fun b hb' => ?_
      rcases List.mem_cons.1 hb' with rfl | hb'
      · simp [rowBefore_irrefl]
      · simp [rowBefore_asymm (hb b hb')]
    simp [this]
  · refine List.map_congr_left fun x hx => ?_
    simp only [List.filter_cons, hb x hx, Bool.and_true]
    cases collects r <;> cases collects x <;> simp [Nat.sub_sub]

/-- R2, the total, exactly: the open cents add up to the unpaid parts of the rows that collect, capped by the shortfall.
    So an answer of all zeros is impossible while the shortfall is positive and a collecting row is unpaid. -/
theorem openRequests_sum {s : Nat} : ∀ {rs : List PkgActionRow}, inOrder rs = true →
    (openRequests s rs).sum = min ((rs.filter collects).map fun r => r.amountCents - r.paidCents).sum s
  | [], _ => by simp [openRequests]
  | r :: rs, h => by
    rw [openRequests_cons h, List.sum_cons, openRequests_sum (inOrder_tail h), List.filter_cons]
    cases collects r <;> simp <;> omega

/-- Delivery (Constitution Article II): met exactly when there is an action and every action that is not cancelled
    and still asks (an offset authorization, or a correction request with open cents) is ACKNOWLEDGED and has an
    acknowledgment reference. An older demand counts as much as the newest. -/
theorem packageDelivery_supported_iff (q : PackageRequest) :
    packageDelivery q = .SUPPORTED ↔ q.actions ≠ [] ∧
      ∀ p ∈ q.actions.zip (openRequests q.shortfallCents q.actions),
        p.1.status ≠ .CANCELLED → (p.1.correction = false ∨ p.2 ≠ 0) → p.1.status = .ACKNOWLEDGED ∧ p.1.referenced = true := by
  have key : (∀ p ∈ q.actions.zip (openRequests q.shortfallCents q.actions), (!waits p.1 p.2 || delivered p.1) = true) ↔
      ∀ p ∈ q.actions.zip (openRequests q.shortfallCents q.actions),
        p.1.status ≠ .CANCELLED → (p.1.correction = false ∨ p.2 ≠ 0) → p.1.status = .ACKNOWLEDGED ∧ p.1.referenced = true := by
    refine forall₂_congr fun p _ => ?_
    cases hs : p.1.status <;> cases hc : p.1.correction <;> cases hr : p.1.referenced <;>
      by_cases ho : p.2 = 0 <;> simp [waits, delivered, hs, hc, hr, ho]
  unfold packageDelivery packageDeliveryWith
  by_cases h0 : q.actions = []
  · simp [h0]
  rw [if_neg h0]
  by_cases ha : (q.actions.zip (openRequests q.shortfallCents q.actions)).all (fun p => !waits p.1 p.2 || delivered p.1) = true
  · rw [if_pos ha]; exact iff_of_true rfl ⟨h0, key.1 (List.all_eq_true.1 ha)⟩
  · rw [if_neg ha]; exact iff_of_false (by decide) fun ⟨_, h⟩ => ha (List.all_eq_true.2 (key.2 h))

/-- Every other result is `conclude`'s: only the delivery requirement, and the mask and assessment it feeds, follow the
    per-action rule; `delivery`, the latest action's own acknowledgment, is `conclude`'s. -/
theorem packageAnswer_eq (q : PackageRequest) :
    packageAnswer q = concludeFor q.facts (packageDelivery q) ∧ conclude q.facts = concludeFor q.facts (deliverySupport q.facts) ∧
    (packageAnswer q).deliveryRequirement = packageDelivery q ∧ (packageAnswer q).delivery = (conclude q.facts).delivery ∧
    (packageAnswer q).cash = (conclude q.facts).cash ∧ (packageAnswer q).amount = (conclude q.facts).amount ∧
    (packageAnswer q).reporting = (conclude q.facts).reporting ∧
    (packageAnswer q).requiredAmount = (conclude q.facts).requiredAmount ∧
    (packageAnswer q).missingCents = (conclude q.facts).missingCents ∧
    (packageAnswer q).activePaymentCount = (conclude q.facts).activePaymentCount ∧
    (packageAnswer q).authorizedClaimCount = (conclude q.facts).authorizedClaimCount :=
  ⟨rfl, rfl, rfl, rfl, rfl, rfl, rfl, rfl, rfl, rfl, rfl⟩

private theorem readMany_length {α : Type} {parse : Bytes → Option (α × Bytes)} :
    ∀ {n : Nat} {b : Bytes} {xs : List α} {r : Bytes}, readMany parse n b = some (xs, r) → xs.length = n
  | 0, _, _, _, h => by simp [readMany] at h; simp [h.1]
  | n + 1, b, xs, r, h => by
    unfold readMany at h
    cases hp : parse b with
    | none => simp [hp] at h
    | some p =>
      obtain ⟨v, rest⟩ := p
      cases hm : readMany parse n rest with
      | none => simp [hp, hm] at h
      | some t =>
        obtain ⟨tail, rem⟩ := t
        simp [hp, hm] at h
        cases h.1
        simp [readMany_length hm]

theorem distinctIds_sound : ∀ (rs : List PkgActionRow) (s : Std.TreeSet String), distinctIds s rs = true →
    (rs.map (·.actionId)).Nodup ∧ ∀ r ∈ rs, s.contains r.actionId = false
  | [], _, _ => ⟨List.nodup_nil, by simp⟩
  | r :: rs, s, h => by
    have hc : s.contains r.actionId = false := by
      cases hc : s.contains r.actionId
      · rfl
      · simp [distinctIds, hc] at h
    have h2 : distinctIds (s.insert r.actionId) rs = true := by simpa [distinctIds, hc] using h
    obtain ⟨hr, hrest⟩ := distinctIds_sound rs _ h2
    have key : ∀ x ∈ rs, x.actionId ≠ r.actionId ∧ s.contains x.actionId = false := by
      intro x hx
      have h1 := hrest x hx
      rw [Std.TreeSet.contains_insert] at h1
      by_cases e : x.actionId = r.actionId
      · exfalso
        have c : compare r.actionId x.actionId = .eq := (Std.LawfulEqCmp.compare_eq_iff_eq (cmp := compare)).2 e.symm
        rw [c] at h1
        simp at h1
      · exact ⟨e, (Bool.or_eq_false_iff.1 h1).2⟩
    refine ⟨?_, ?_⟩
    · rw [List.map_cons, List.nodup_cons]
      refine ⟨fun hm => ?_, hr⟩
      obtain ⟨x, hx, hxe⟩ := List.mem_map.1 hm
      exact (key x hx).1 hxe
    · intro x hx
      rcases List.mem_cons.1 hx with rfl | hx
      · exact hc
      · exact (key x hx).2

theorem decodePackageRequest_inv {w : Bytes} {q : PackageRequest} (h : decodePackageRequest w = some q) :
    q.actions.length ≤ maxRows ∧ (∃ i, decodePackageFacts i = some q.facts) ∧ q.shortfallCents ≤ maxCents ∧
      inOrder q.actions = true ∧ (q.actions.map (·.actionId)).Nodup := by
  unfold decodePackageRequest at h
  split at h
  · cases h
  rcases h1 : readCents (w.drop packageRequestMagic.length) with _ | ⟨s, b⟩ <;> simp only [h1] at h
  · cases h
  rcases h2 : readList readPkgActionRow b with _ | ⟨rs, b'⟩ <;> simp only [h2] at h
  · cases h
  rcases h3 : decodePackageFacts b' with _ | f <;> simp only [h3] at h
  · cases h
  split at h
  · rename_i ho
    cases h
    refine ⟨?_, ⟨b', h3⟩, ?_, ho.1, (distinctIds_sound _ _ ho.2.1).1⟩
    rotate_left
    · unfold readCents at h1
      rcases h5 : readNatBE 8 (w.drop packageRequestMagic.length) with _ | ⟨v, r⟩ <;> simp only [h5] at h1
      · cases h1
      by_cases hv : v > maxCents
      · simp [hv] at h1
      · simp [hv] at h1; dsimp only; omega
    unfold readList at h2
    rcases h4 : readNatBE 2 b with _ | ⟨c, rest⟩ <;> simp only [h4] at h2
    · cases h2
    by_cases hc : c > maxRows
    · simp [hc] at h2
    · simp [hc] at h2
      have := readMany_length h2
      dsimp only; omega
  · cases h

theorem decodePackageRequest_actions_le {w : Bytes} {q : PackageRequest} (h : decodePackageRequest w = some q) :
    q.actions.length ≤ maxRows := (decodePackageRequest_inv h).1

/-- A decoded frame lists its actions oldest first; any other order is refused. -/
theorem decodePackageRequest_inOrder {w : Bytes} {q : PackageRequest} (h : decodePackageRequest w = some q) :
    inOrder q.actions = true := (decodePackageRequest_inv h).2.2.2.1

/-- A decoded frame holds no action id twice, at any revision. -/
theorem decodePackageRequest_distinct {w : Bytes} {q : PackageRequest} (h : decodePackageRequest w = some q) :
    (q.actions.map (·.actionId)).Nodup := (decodePackageRequest_inv h).2.2.2.2

theorem readStringQuick_eq (b : Bytes) : readStringQuick b = readString b := by
  unfold readStringQuick readString
  cases h : readNatBE 2 b with
  | none => rfl
  | some p =>
    obtain ⟨n, rest⟩ := p
    by_cases hn : n > rest.length
    · simp [hn, List.length_take]; omega
    · simp [hn, List.length_take]; intro; omega

/-- The one-pass open cents are the specification's, for rows in frame order. -/
theorem openRequestsFast_eq : ∀ {rs : List PkgActionRow}, inOrder rs = true → ∀ s, openRequestsFast s rs = openRequests s rs
  | [], _, s => by simp [openRequestsFast, openRequests]
  | r :: rs, h, s => by
    rw [openRequests_cons h, openRequestsFast, openRequestsFast_eq (inOrder_tail h)]
    cases collects r <;> simp

/-- The worker's response is the specification's, byte for byte. -/
theorem packageRequestRespondFast_eq (w : Bytes) : packageRequestRespondFast w = packageRequestRespond w := by
  unfold packageRequestRespondFast packageRequestRespond
  cases h : decodePackageRequest w with
  | none => rfl
  | some q => simp only [openRequestsFast_eq (decodePackageRequest_inOrder h)]; rfl

private theorem natBE_len (w v : Nat) : (natBE w v).length = w := by
  induction w generalizing v with
  | zero => rfl
  | succ w ih => simp [natBE, ih]

private theorem flatMap_natBE_len (xs : List Nat) : (xs.flatMap (natBE 8)).length = 8 * xs.length := by
  induction xs with
  | nil => rfl
  | cons x xs ih => simp only [List.flatMap_cons, List.length_append, natBE_len, ih, List.length_cons]; omega

theorem packageRequestRespond_length (w : Bytes) (q : PackageRequest) (h : decodePackageRequest w = some q) :
    (packageRequestRespond w).length = 31 + 8 * q.actions.length := by
  simp only [packageRequestRespond, h, List.length_cons, List.length_append, encodePackageAnswer, encodeList,
    natBE_len, flatMap_natBE_len, openRequests_length, packageAnswerMagic, List.length_nil]
  omega

/-! Known answers. A resolved case, its cash, amount and reporting all met; only the actions change. -/

private def kFacts : PackageFacts :=
  { owedCents := 10000, receivedCashCents := 10000, claimedAdjustmentCents := 0, lawfulAdjustmentCents := 0,
    amountSatisfied := true, reportingComplete := true, verification := .SUPPORTED,
    payments := [{ amountCents := 10000, active := true }], claims := [], reportCount := 1, conflictCount := 0,
    caseStatus := some .RESOLVED, action := none }
private def kq (shortfallCents : Nat) (actions : List PkgActionRow) : PackageRequest :=
  { shortfallCents, actions, facts := { kFacts with action := latestAction actions } }
private def kWire (q : PackageRequest) : Bytes :=
  packageRequestMagic ++ natBE 8 q.shortfallCents ++ encodeList (fun r => encodeString r.actionId ++ natBE 8 r.revision ++
    encodeBool r.correction ++
    [encodeActionStatus r.status] ++ encodeBool r.referenced ++ natBE 8 r.amountCents ++ natBE 8 r.paidCents) q.actions ++
    encodePackageFacts q.facts
-- `ready` is the older request (revision 1), `acked` the newer (revision 2).
private def ready : PkgActionRow :=
  { actionId := "action-1", revision := 1, correction := true, status := .READY, referenced := false, amountCents := 4000, paidCents := 0 }
private def acked : PkgActionRow := { ready with actionId := "action-2", revision := 2, status := .ACKNOWLEDGED, referenced := true }
private def nth (n : Nat) (r : PkgActionRow) : PkgActionRow := { r with actionId := "action-" ++ toString n, revision := n }
private def kd (shortfallCents : Nat) (actions : List PkgActionRow) : Support := packageDelivery (kq shortfallCents actions)

#guard packageRequestMagic == "BLFDPQ01".toUTF8.toList
-- The newest action is acknowledged, an older demand still asks and is not: not met (conclude's newest-only rule says met).
#guard kd 8000 [ready, acked] == .NOT_SATISFIED
#guard (conclude (kq 8000 [ready, acked]).facts).delivery == .SUPPORTED
#guard (packageAnswer (kq 8000 [ready, acked])).assessment == .UNSUPPORTED
#guard (packageAnswer (kq 8000 [ready, acked])).missingMask == 2
-- The newest action still asks and is not acknowledged: not met.
#guard kd 9000 [{ acked with revision := 0 }, { ready with amountCents := 5000 }] == .NOT_SATISFIED
#guard kd 4000 [ready] == .NOT_SATISFIED
-- Acknowledged status without a reference, or a reference without the status: not met.
#guard kd 4000 [{ acked with referenced := false }] == .NOT_SATISFIED
#guard kd 4000 [{ ready with referenced := true }] == .NOT_SATISFIED
-- Fully paid, cancelled, or left nothing by the shortfall: asks for nothing, so not waiting (conclude says not met).
#guard kd 0 [{ ready with paidCents := 4000 }] == .SUPPORTED
#guard (conclude (kq 0 [{ ready with paidCents := 4000 }]).facts).delivery == .NOT_SATISFIED
#guard (packageAnswer (kq 0 [{ ready with paidCents := 4000 }])).assessment == .SUPPORTED
#guard kd 4000 [{ ready with status := .CANCELLED }] == .SUPPORTED
-- READY then ACKNOWLEDGED on a 4000 shortfall: the older request keeps the 4000 and is not acknowledged, so not met.
-- Listed in reverse the frame is refused, and the open cents follow revision and action id, never list position.
#guard kd 4000 [ready, acked] == .NOT_SATISFIED
#guard openRequests 4000 [ready, acked] == [4000, 0]
#guard kd 4000 [acked, ready] == .NOT_SATISFIED
#guard openRequests 4000 [acked, ready] == [0, 4000]
#guard packageRequestRespond (kWire (kq 4000 [acked, ready])) == [1]
-- An acknowledged older request keeps the shortfall; the newer request is left nothing and does not wait.
#guard kd 4000 [{ acked with revision := 0 }, ready] == .SUPPORTED
#guard openRequests 4000 [{ acked with revision := 0 }, ready] == [4000, 0]
-- One revision: the smaller action id is served first. A repeated or misordered row is refused.
#guard openRequests 4000 [{ ready with actionId := "b" }, { ready with actionId := "a" }] == [0, 4000]
#guard decodePackageRequest (kWire (kq 4000 [{ ready with actionId := "a" }, { ready with actionId := "b" }])) ==
  some (kq 4000 [{ ready with actionId := "a" }, { ready with actionId := "b" }])
#guard packageRequestRespond (kWire (kq 4000 [{ ready with actionId := "b" }, { ready with actionId := "a" }])) == [1]
#guard packageRequestRespond (kWire (kq 8000 [ready, ready])) == [1]
-- An offset authorization has no open cents and waits until acknowledged.
#guard kd 0 [{ ready with correction := false }] == .NOT_SATISFIED
#guard kd 0 [{ acked with correction := false }] == .SUPPORTED
#guard kd 0 [] == .UNKNOWN
#guard openRequests 5000 [nth 1 { ready with paidCents := 1000 }, nth 2 { ready with status := .CANCELLED }, nth 3 ready,
    nth 4 { ready with amountCents := 100, paidCents := 200 }] == [3000, 0, 2000, 0]
#guard openRequests 5000 [nth 1 { ready with correction := false }, nth 2 ready, nth 3 ready] == [0, 4000, 1000]
-- Other results are conclude's.
#guard (packageAnswer (kq 8000 [ready, acked])).delivery == .SUPPORTED
#guard (packageAnswer (kq 0 [{ ready with paidCents := 4000 }])).delivery == .NOT_SATISFIED
#guard (packageAnswer (kq 8000 [ready, acked])).cash == (conclude kFacts).cash
#guard (packageAnswer (kq 8000 [ready, acked])).missingCents == (conclude kFacts).missingCents
-- The wire.
#guard decodePackageRequest (kWire (kq 8000 [ready, acked])) == some (kq 8000 [ready, acked])
#guard packageRequestRespond (kWire (kq 8000 [ready, acked])) ==
  UInt8.ofNat 0 :: encodePackageAnswer (packageAnswer (kq 8000 [ready, acked])) ++ [0, 2] ++ natBE 8 4000 ++ natBE 8 4000
#guard packageRequestRespond (kWire { kq 8000 [ready, acked] with facts := kFacts }) == [1]
#guard packageRequestRespond (kWire (kq 0 []) ++ [0]) == [1]
#guard packageRequestRespond packageRequestMagic == [1]

-- One action id at two revisions is refused (its paid cents would count twice); distinct ids in order are read.
#guard distinctIds ∅ [ready, acked]
#guard !distinctIds ∅ [ready, { acked with actionId := "action-1" }]
#guard !distinctIds ∅ [ready, acked, { ready with actionId := "action-3", revision := 3 }, { acked with actionId := "action-2", revision := 4 }]
#guard packageRequestRespond (kWire (kq 4000 [ready, acked])) != [1]
#guard packageRequestRespond (kWire (kq 4000 [ready, { acked with actionId := "action-1" }])) == [1]
#guard packageRequestRespond (kWire (kq 4000 [ready, acked, { ready with actionId := "action-3", revision := 3 }, { acked with actionId := "action-2", revision := 4 }])) == [1]

end BlindLedger.Financial.DecisionPackage
