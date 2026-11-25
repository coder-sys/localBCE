import BlindLedger.Gate.PublishFastEq
import BlindLedger.Gate.VerifyCli

/-! `decodeB_eq`, `decodeLinkB_eq` and `answerOf_eq`: the `ByteArray` readers of `InstallFast.lean` and `gate_verify`'s
    request dispatch answer exactly what the `List UInt8` specification answers, for every input (malformed ones
    included).  Readers are compared with the list parsers by `Sim` (`PublishFastEq.lean`). -/
namespace BlindLedger.Gate

/-- `Sim.bind` after a reader whose value the parser sees mapped by `φ`. -/
theorem SimM.bindS {α β γ : Type} {φ : α → β} {f : Rd α} {g : P β} {k : ByteArray → α × Nat → Option (γ × Nat)}
    {K : β → P γ} (hf : SimM φ f g) (hk : ∀ a, Sim (fun b j => k b (a, j)) (K (φ a))) :
    Sim (fun b o => (f b o).bind (k b)) (g >>= K) := by
  intro b o ho
  obtain ⟨h1, h2⟩ := hf b o ho
  rw [StateT.run_bind, ← h1]
  rcases hfi : f b o with _ | ⟨a, j⟩
  · simp [hfi]
  · obtain ⟨hij, hjs⟩ := h2 a j hfi
    obtain ⟨h3, h4⟩ := hk a b j hjs
    simp only [hfi, Option.bind_some, Option.map_some]
    refine ⟨by simpa using h3, fun c l hl => ?_⟩
    have := h4 c l hl
    omega

theorem sim_key : Sim Cosign.rKey Cosign.pKey := by
  unfold Cosign.rKey Cosign.pKey
  refine Sim.bind (sim_nat _ _ _) fun _ => ?_
  refine Sim.bind (sim_blob _ _) fun _ => ?_
  refine Sim.bind (sim_need _) fun _ => ?_
  exact Sim.pure _

theorem sim_keyCert : Sim Cosign.rKeyCert Cosign.pKeyCert := by
  unfold Cosign.rKeyCert Cosign.pKeyCert
  refine Sim.bind (sim_expect _) fun _ => ?_
  refine Sim.bind sim_ident fun _ => ?_
  refine Sim.bind (sim_nat _ _ _) fun _ => ?_
  refine Sim.bind (sim_take _) fun _ => ?_
  refine Sim.bind (sim_nat _ _ _) fun _ => ?_
  refine Sim.bind (sim_many (sim_nat _ _ _) _) fun _ => ?_
  refine Sim.bind (sim_need _) fun _ => ?_
  refine Sim.bind sim_key fun _ => ?_
  refine Sim.bind sim_key fun _ => ?_
  refine Sim.bind (sim_blob _ _) fun _ => ?_
  refine Sim.bind (sim_blob _ _) fun _ => ?_
  exact Sim.pure _

theorem sim_link : Sim Cosign.rLink Cosign.pLink := by
  unfold Cosign.rLink Cosign.pLink
  refine Sim.bind (sim_expect _) fun _ => ?_
  refine Sim.bind sim_ident fun _ => ?_
  refine Sim.bind (sim_nat _ _ _) fun _ => ?_
  refine Sim.bind (sim_nat _ _ _) fun _ => ?_
  refine Sim.bind (sim_take _) fun _ => ?_
  refine Sim.bind (sim_nat _ _ _) fun _ => ?_
  refine Sim.bind sim_key fun _ => ?_
  refine Sim.bind (sim_take _) fun _ => ?_
  refine Sim.bind sim_key fun _ => ?_
  refine Sim.bind (sim_take _) fun _ => ?_
  refine Sim.bind (sim_nat _ _ _) fun _ => ?_
  refine Sim.bind (sim_nat _ _ _) fun _ => ?_
  refine Sim.bind (sim_need _) fun _ => ?_
  refine Sim.bind (sim_take _) fun _ => ?_
  refine Sim.bind (sim_blob _ _) fun _ => ?_
  refine Sim.bind (sim_blob _ _) fun _ => ?_
  exact Sim.pure _

theorem decodeB_eq (b : ByteArray) : Cosign.decodeB b = Cosign.decode b.data.toList :=
  parseB_eq sim_keyCert Cosign.maxCertBytes b

theorem decodeLinkB_eq (b : ByteArray) : Cosign.decodeLinkB b = Cosign.decodeLink b.data.toList :=
  parseB_eq sim_link Cosign.maxLinkBytes b

/-! ## The INSTALL frame -/

theorem sim_framed : SimM lst rFramedB pFramed := by
  intro b o ho
  refine ⟨(framed_rd b o ho).symm, fun a j h => ⟨?_, rFramedB_le h⟩⟩
  unfold rFramedB at h
  rcases hn : rNat 4 0 maxNat b o with _ | ⟨n, o2⟩
  · simp [hn] at h
  · simp only [hn, Option.bind_some] at h
    have := ((sim_nat 4 0 maxNat) b o ho).2 n o2 hn
    have := (rdB_le h).1
    omega

theorem sim_list {α : Type} {r : Rd α} {p : P α} (h : Sim r p) : Sim (rList r) (_root_.pList p) :=
  Sim.bind (sim_nat 2 0 maxNat) fun k => sim_many h k

/-- A framed item that `d` decodes, against the list parser `K` whose every branch is `D`'s. -/
theorem sim_framedD {α : Type} {d : ByteArray → Option α} {D : Bytes → Option α} {K : Bytes → P α}
    (hd : ∀ x, d x = D (lst x)) (hK : ∀ b, K b = match D b with | some v => pure v | none => Gate.fail) :
    Sim (rFramedD d) (pFramed >>= K) := by
  unfold rFramedD
  refine SimM.bindS sim_framed fun x => ?_
  dsimp only
  rw [hK, hd x]
  cases D (lst x) with
  | some v => exact Sim.pure v
  | none => exact Sim.fail

theorem lst_isEmpty (x : ByteArray) : (lst x).isEmpty = (x.size == 0) := by
  cases x with
  | mk d => cases d with
    | mk l => cases l <;> simp [lst, ByteArray.size]

/-- `sim_framedD` where an empty item is `none`. -/
theorem sim_optFramedD {α : Type} {d : ByteArray → Option α} {D : Bytes → Option α} {K : Bytes → P (Option α)}
    (hd : ∀ x, d x = D (lst x))
    (hK : ∀ b, K b = if b.isEmpty then pure none else match D b with | some v => pure (some v) | none => Gate.fail) :
    Sim (rOptFramedD d) (pFramed >>= K) := by
  unfold rOptFramedD
  refine SimM.bindS sim_framed fun x => ?_
  dsimp only
  rw [hK, lst_isEmpty, hd x]
  by_cases e : (x.size == 0) = true
  · simp only [e, if_true]
    exact Sim.pure none
  · simp only [e, if_false, Bool.false_eq_true]
    cases D (lst x) with
    | some v => exact Sim.pure (some v)
    | none => exact Sim.fail

theorem sim_pLink : Sim (rFramedD Cosign.decodeLinkB) _root_.pLink := by
  unfold _root_.pLink
  exact sim_framedD decodeLinkB_eq fun b => by cases Cosign.decodeLink b <;> rfl

theorem sim_pCert : Sim (rFramedD Cosign.decodeB) _root_.pCert := by
  unfold _root_.pCert
  exact sim_framedD decodeB_eq fun b => by cases Cosign.decode b <;> rfl

theorem sim_pOptLink : Sim (rOptFramedD Cosign.decodeLinkB) _root_.pOptLink := by
  unfold _root_.pOptLink
  exact sim_optFramedD decodeLinkB_eq fun b => by cases Cosign.decodeLink b <;> rfl

theorem sim_pOptCert : Sim (rOptFramedD Cosign.decodeB) _root_.pOptCert := by
  unfold _root_.pOptCert
  exact sim_optFramedD decodeB_eq fun b => by cases Cosign.decode b <;> rfl

theorem sim_install : Sim installB _root_.install := by
  unfold installB _root_.install
  refine Sim.bind sim_pOptLink fun _ => ?_
  refine Sim.bind sim_pOptLink fun _ => ?_
  refine Sim.bind sim_pOptLink fun _ => ?_
  refine Sim.bind (sim_list sim_pLink) fun _ => ?_
  refine Sim.bind sim_pOptCert fun _ => ?_
  refine Sim.bind (sim_list sim_pLink) fun _ => ?_
  refine Sim.bind (sim_list sim_pCert) fun _ => ?_
  refine SimM.bindS sim_framed fun x => ?_
  dsimp only
  rw [decodeB_eq x]
  cases Cosign.decode (lst x) with
  | some e => exact Sim.pure _
  | none => exact Sim.pure _

/-! ## The STORE and RELEASE frames -/

theorem sim_framedL : Sim rFramedL pFramed :=
  Sim.bind (sim_nat 4 0 maxNat) fun n => sim_take n

theorem sim_authority : Sim rAuthority _root_.pAuthority := by
  unfold rAuthority _root_.pAuthority
  refine Sim.bind sim_pLink fun head => ?_
  refine Sim.bind sim_pOptLink fun _ => ?_
  refine Sim.bind (sim_list sim_pLink) fun links => ?_
  refine Sim.bind (sim_list sim_pCert) fun _ => ?_
  refine Sim.bind sim_pOptCert fun _ => ?_
  dsimp only
  cases links.all (·.tenantId == head.tenantId)
  · exact Sim.fail
  · exact Sim.pure _

theorem sim_fork : Sim rFork _root_.pFork := by
  unfold rFork _root_.pFork
  refine Sim.bind sim_framedL fun _ => ?_
  refine Sim.bind sim_framedL fun _ => ?_
  exact Sim.pure _

theorem sim_grant : Sim rGrant _root_.pGrant := by
  unfold rGrant _root_.pGrant
  refine Sim.bind sim_ident fun _ => ?_
  refine Sim.bind (sim_blob _ _) fun _ => ?_
  refine Sim.bind (sim_nat _ _ _) fun _ => ?_
  refine Sim.bind (sim_many (sim_blob _ _) _) fun _ => ?_
  refine Sim.bind (sim_nat _ _ _) fun _ => ?_
  refine Sim.bind (sim_many (sim_blob _ _) _) fun _ => ?_
  exact Sim.pure _

/-! ### Forks read without their bytes (`rListL`) -/

theorem rManyL_eq {α β : Type} (r : Rd α) (φ : α → β) :
    ∀ (k : Nat) (b : ByteArray) (o : Nat), rManyL r φ k b o = (rMany r k b o).map fun q => (q.1.map φ, q.2)
  | 0, _, _ => rfl
  | k + 1, b, o => by
    simp only [rManyL, rMany]
    cases r b o with
    | none => simp
    | some q =>
      obtain ⟨x, o1⟩ := q
      simp [rManyL_eq r φ k b o1] <;> (rcases rMany r k b o1 with _ | ⟨xs, o2⟩ <;> simp)

theorem rListL_eq {α β : Type} (r : Rd α) (φ : α → β) (b : ByteArray) (o : Nat) :
    rListL r φ b o = (rList r b o).map fun q => (q.1.map φ, q.2) := by
  unfold rListL rList
  rcases rNat 2 0 maxNat b o with _ | ⟨k, o1⟩
  · rfl
  · exact rManyL_eq r φ k b o1

theorem mapM_storedPairL : ∀ l : List (Bytes × Bytes),
    (l.map storedPairL).mapM id = (l.mapM storedPair).map (List.map liteP)
  | [] => rfl
  | f :: t => by
    simp only [List.map, List.mapM_cons, mapM_storedPairL t, storedPairL]
    cases storedPair f <;> cases t.mapM storedPair <;> rfl

/-- `Sim.bind` over a list read by `rListL`: the continuation sees the list mapped by `φ`. -/
theorem Sim.bindL {α β γ : Type} {r : Rd α} {p : P α} (φ : α → β) (h : Sim r p)
    {k : ByteArray → List β × Nat → Option (γ × Nat)} {K : List α → P γ}
    (hk : ∀ a, Sim (fun b j => k b (a.map φ, j)) (K a)) :
    Sim (fun b o => (rListL r φ b o).bind (k b)) (_root_.pList p >>= K) := by
  have h2 := Sim.bind (sim_list h) (k := fun b q => k b (q.1.map φ, q.2)) (K := K) hk
  have e : (fun b o => (rListL r φ b o).bind (k b))
      = fun b o => (rList r b o).bind (fun q => k b (q.1.map φ, q.2)) := by
    funext b o
    rw [rListL_eq]
    rcases rList r b o with _ | ⟨l, j⟩ <;> rfl
  rw [e]
  exact h2

theorem blocked_lite (s : PayerState) (fs : List (Stored × Stored)) (T : Bytes) (sh e : Nat) :
    blocked { s with forked := fs.map liteP } T sh e = blocked { s with forked := fs } T sh e := by
  simp [blocked, List.any_map, liteP, Function.comp_def]

theorem firstFailure_lite (c : Crypto) (s : PayerState) (fs : List (Stored × Stored)) (p : Payment) (bytes : Bytes) :
    firstFailure c { s with forked := fs.map liteP } p bytes = firstFailure c { s with forked := fs } p bytes := by
  unfold firstFailure
  cases decodeToken bytes with
  | none => rfl
  | some t =>
    simp only [unforked, blocked_lite]
    rfl

theorem releaseOutcome_lite (c : Crypto) (s0 : PayerState) (forks : List (Stored × Stored)) (cp : Bytes) (now : Nat)
    (grants : List Grant) (released : Bool) (pin : Option Bytes) (p : Payment) (token : Bytes) :
    releaseOutcome c s0 (forks.map liteP) cp now grants released pin p token
      = releaseOutcome c s0 forks cp now grants released pin p token := by
  unfold releaseOutcome
  generalize (storeCheckpoint c { s0 with equivocations := [], conflicts := [], forked := [] } cp).getD s0 = s1
  let S : PayerState := { s1 with equivocations := s0.equivocations, conflicts := s0.conflicts, now := now, grants := grants, released := if released then [p.key] else [], pins := pin.toList.map (p.key, ·) }
  exact firstFailure_lite c S forks p token

theorem storeOutcome_lite (c : Crypto) (s0 : PayerState) (old : List Stored) (forks : List (Stored × Stored))
    (new : Bytes) :
    storeOutcome c s0 old (forks.map liteP) new = storeOutcome c s0 old forks new := by
  have hb : ∀ T sh e, blocked { s0 with checkpoints := old, forked := forks.map liteP } T sh e
      = blocked { s0 with checkpoints := old, forked := forks } T sh e :=
    fun T sh e => blocked_lite { s0 with checkpoints := old } forks T sh e
  unfold storeOutcome storeCheckpoint
  cases decodeCheckpoint new with
  | none => rfl
  | some x =>
    simp only [hb]
    split <;> (try split) <;> (try split) <;> (try split) <;>
      (first | rfl | (cases forks <;> simp [List.length_map, liteP]))

theorem sim_store : Sim storeB _root_.store := by
  unfold storeB _root_.store
  refine Sim.bind sim_authority fun _ => ?_
  refine Sim.bind (sim_list sim_framedL) fun candidates => ?_
  refine Sim.bindL storedPairL sim_fork fun evidence => ?_
  refine Sim.bind sim_framedL fun _ => ?_
  dsimp only
  cases candidates.mapM (storedOf sha3) with
  | none => exact Sim.fail
  | some _ =>
    rw [mapM_storedPairL]
    cases evidence.mapM storedPair with
    | none => exact Sim.fail
    | some _ =>
      simp only [Option.map_some, storeOutcome_lite]
      exact Sim.pure _

theorem sim_release : Sim releaseB _root_.release := by
  unfold releaseB _root_.release
  refine Sim.bind sim_authority fun _ => ?_
  refine Sim.bindL storedPairL sim_fork fun evidence => ?_
  refine Sim.bind sim_framedL fun _ => ?_
  refine Sim.bind (sim_nat _ _ _) fun _ => ?_
  refine Sim.bind (sim_list sim_grant) fun _ => ?_
  refine Sim.bind (sim_nat _ _ _) fun _ => ?_
  refine Sim.bind (sim_nat _ _ _) fun pinned => ?_
  dsimp only
  -- the member key is read only when pinned: both sides join after it (`__do_jp`)
  by_cases hp : (pinned == 1) = true <;>
    first
    | (simp only [if_pos hp]; refine Sim.bind (sim_take _) fun _ => ?_)
    | (simp only [if_neg hp]; refine Sim.bind (Sim.pure []) fun _ => ?_)
  all_goals
    try dsimp only
    refine Sim.bind sim_framedL fun rq => ?_
    dsimp only
    cases decodeRequest rq with
    | none => exact Sim.fail
    | some _ =>
      refine Sim.bind sim_framedL fun _ => ?_
      dsimp only
      rw [mapM_storedPairL]
      cases evidence.mapM storedPair with
      | none => exact Sim.fail
      | some _ =>
        simp only [Option.map_some, releaseOutcome_lite]
        exact Sim.pure _

/-! ## The request -/

theorem toList_extract1 (bs : ByteArray) : (bs.extract 1 bs.size).data.toList = bs.data.toList.drop 1 := by
  simp [ByteArray.data_extract, Array.toList_extract, List.take_of_length_le]

theorem getElem?_data (bs : ByteArray) (i : Nat) : bs[i]? = bs.data[i]? := by
  by_cases hs : i < bs.size
  · rw [getElem?_pos bs i hs, getElem?_pos bs.data i (by simpa using hs)]
    rfl
  · rw [getElem?_neg bs i hs, getElem?_neg bs.data i (by simpa using hs)]

theorem toList_cons {bs : ByteArray} {m : UInt8} (h : bs[0]? = some m) :
    bs.data.toList = m :: bs.data.toList.drop 1 := by
  have h0 : bs.data.toList[0]? = some m := by simpa [getElem?_data] using h
  cases hl : bs.data.toList with
  | nil => simp [hl] at h0
  | cons a t => simp [hl] at h0; simp [h0]

/-- The whole parse of a mode byte then a frame is the frame's parse on the rest. -/
theorem parse_mode {m : UInt8} {rest : Bytes} {q : P (String × UInt32)}
    (hq : ∀ r, (StateT.run _root_.frame (m :: r)) = q.run r) :
    parse _root_.frame (m :: rest).length (m :: rest) = parse q rest.length rest := by
  simp only [parse, Nat.lt_irrefl, if_false, hq]

/-- A mode whose frame a simulated reader reads: its whole-slice read answers the list parse of the whole request. -/
theorem parseB_mode {m : UInt8} {r : Rd (String × UInt32)} {q : P (String × UInt32)} {bs : ByteArray}
    (hm : bs[0]? = some m) (hr : Sim r q) (hq : ∀ rest, (StateT.run _root_.frame (m :: rest)) = q.run rest) :
    parseB r bs.size (bs.extract 1 bs.size) = parse _root_.frame bs.data.toList.length bs.data.toList := by
  rw [parseB_eq hr, toList_extract1]
  conv => rhs; rw [toList_cons hm]
  rw [parse_mode hq]
  have hl : ¬ (bs.data.toList.drop 1).length > bs.size := by
    simp only [List.length_drop, Array.length_toList, ByteArray.size_data]
    omega
  unfold parse
  rw [if_neg hl, if_neg (Nat.lt_irrefl _)]

theorem answerOf_eq (bs : ByteArray) :
    _root_.answerOf bs = parse _root_.frame bs.data.toList.length bs.data.toList := by
  unfold _root_.answerOf
  by_cases h1 : bs[0]? = some 1
  · rw [if_pos (show (bs[0]? == some 1) = true by simp [h1]), publishFrameB_eq, toList_extract1]
    conv => rhs; rw [toList_cons h1]
    rw [parse_mode (q := _root_.publish) fun r => by
        simp only [_root_.frame, StateT.run_bind]; simp [StateT.run, take]]
    generalize bs.data.toList.drop 1 = t
    unfold publishFrame parse _root_.publish
    simp only [Nat.lt_irrefl, if_false, StateT.run_bind]
    rcases pPublishArgs.run t with _ | ⟨x, _ | ⟨c, r⟩⟩ <;> simp
  rw [if_neg (show ¬ (bs[0]? == some 1) = true by simp [h1])]
  by_cases h8 : bs[0]? = some 8
  · rw [if_pos (show (bs[0]? == some 8) = true by simp [h8])]
    exact parseB_mode h8 sim_install fun r => by
      simp only [_root_.frame, StateT.run_bind]; simp [StateT.run, take]
  rw [if_neg (show ¬ (bs[0]? == some 8) = true by simp [h8])]
  by_cases h3 : bs[0]? = some 3
  · rw [if_pos (show (bs[0]? == some 3) = true by simp [h3])]
    exact parseB_mode h3 sim_store fun r => by
      simp only [_root_.frame, StateT.run_bind]; simp [StateT.run, take]
  rw [if_neg (show ¬ (bs[0]? == some 3) = true by simp [h3])]
  by_cases h5 : bs[0]? = some 5
  · rw [if_pos (show (bs[0]? == some 5) = true by simp [h5])]
    exact parseB_mode h5 sim_release fun r => by
      simp only [_root_.frame, StateT.run_bind]; simp [StateT.run, take]
  simp [h5]

end BlindLedger.Gate
