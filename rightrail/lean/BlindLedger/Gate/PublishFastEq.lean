import BlindLedger.Gate.PublishFast
import BlindLedger.Sha3QuickEq

/-! `publishOkTreeB_eq` and `publishFrameB_eq`: the `ByteArray` readers and the slice-based decision answer exactly
    what the `List UInt8` specification answers, for every input (malformed ones included), so `gate_verify` may run
    the fast ones.  Readers are compared with the list parsers by `Sim` (the technique of `Financial/Cursor.lean`). -/
namespace BlindLedger.Gate

abbrev rest (b : ByteArray) (o : Nat) : Bytes := b.data.toList.drop o

theorem len_rest (b : ByteArray) (o : Nat) : (rest b o).length = b.size - o := by
  simp [rest, ByteArray.size_data]

theorem rd_le {b : ByteArray} {o n : Nat} {x : Bytes} {o' : Nat} (h : rd b o n = some (x, o')) :
    o' = o + n ∧ o' ≤ b.size := by
  unfold rd rdB at h
  split at h <;> simp_all

theorem take_rd (b : ByteArray) (o n : Nat) (ho : o ≤ b.size) :
    (take n).run (rest b o) = (rd b o n).map fun p => (p.1, rest b p.2) := by
  unfold take rd rdB
  simp only [StateT.run, len_rest]
  by_cases h : o + n ≤ b.size
  · have h' : n ≤ b.size - o := by omega
    simp [h, h', rest, ByteArray.data_extract, Array.toList_extract, List.drop_drop]
  · have h' : ¬ n ≤ b.size - o := by omega
    simp [h, h']

/-! ## Readers and their simulation -/

/-- `f` reads, from every in-bounds offset, what `g` reads from the rest of the array (value mapped by `φ`), and
    stays inside the array without moving back. -/
def SimM {α β : Type} (φ : α → β) (f : Rd α) (g : P β) : Prop :=
  ∀ (b : ByteArray) (o : Nat), o ≤ b.size →
    (f b o).map (fun q => (φ q.1, rest b q.2)) = g.run (rest b o) ∧
    ∀ a j, f b o = some (a, j) → o ≤ j ∧ j ≤ b.size

abbrev Sim {α : Type} (f : Rd α) (g : P α) : Prop := SimM id f g

theorem Sim.pure {α : Type} (v : α) : Sim (fun _ o => some (v, o)) (pure v) := by
  intro b o ho
  refine ⟨by simp [StateT.run_pure], fun a j h => ?_⟩
  simp only [Option.some.injEq, Prod.mk.injEq] at h
  omega

theorem Sim.fail {α : Type} : Sim (α := α) (fun _ _ => none) Gate.fail := by
  intro b o ho
  exact ⟨rfl, fun a j h => by simp at h⟩

theorem Sim.bind {α β : Type} {f : Rd α} {g : P α} {k : ByteArray → α × Nat → Option (β × Nat)} {K : α → P β}
    (hf : Sim f g) (hk : ∀ a, Sim (fun b j => k b (a, j)) (K a)) :
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

theorem sim_need (ok : Bool) : Sim (rNeed ok) (need ok) := by
  intro b o ho
  cases ok
  · exact ⟨rfl, fun a j h => by simp [rNeed] at h⟩
  · refine ⟨rfl, fun a j h => ?_⟩
    simp only [rNeed, if_true, Option.some.injEq, Prod.mk.injEq] at h
    omega

theorem sim_take (n : Nat) : Sim (rTake n) (take n) := by
  intro b o ho
  refine ⟨?_, fun a j h => ?_⟩
  · simpa [rTake] using (take_rd b o n ho).symm
  · have := rd_le (x := a) (o' := j) h
    omega

theorem sim_nat (w lo hi : Nat) : Sim (rNat w lo hi) (nat w lo hi) :=
  Sim.bind (sim_take w) fun x => Sim.bind (sim_need _) fun _ => Sim.pure _

theorem sim_tag {α : Type} (names : List α) : Sim (rTag names) (tag names) := by
  refine Sim.bind (sim_nat 1 1 names.length) fun n => ?_
  dsimp only
  cases names[n - 1]? with
  | some x => exact Sim.pure x
  | none => exact Sim.fail

theorem sim_blob (lo hi : Nat) : Sim (rBlob lo hi) (blob lo hi) :=
  Sim.bind (sim_nat 2 lo hi) fun n => sim_take n

theorem sim_ident : Sim rIdent ident :=
  Sim.bind (sim_blob 1 65535) fun bs => Sim.bind (sim_need _) fun _ => Sim.pure bs

theorem sim_code : Sim rCode code :=
  Sim.bind (sim_blob 1 65535) fun bs => Sim.bind (sim_need _) fun _ => Sim.pure bs

theorem sim_expect (d : Bytes) : Sim (rExpect d) (expect d) :=
  Sim.bind (sim_take d.length) fun _ => sim_need _

theorem sim_many {α : Type} {r : Rd α} {p : P α} (h : Sim r p) : ∀ k, Sim (rMany r k) (many p k)
  | 0 => Sim.pure []
  | k + 1 => Sim.bind h fun x => Sim.bind (sim_many h k) fun xs => Sim.pure (x :: xs)

theorem sim_consumed {α : Type} {r : Rd α} {p : P α} (h : Sim r p) : Sim (rConsumed r) (consumed p) := by
  intro b o ho
  obtain ⟨h1, h2⟩ := h b o ho
  unfold rConsumed consumed
  simp only [StateT.run]
  rcases hr : r b o with _ | ⟨x, o'⟩
  · rw [hr] at h1
    simp only [StateT.run, Option.map_none] at h1
    simp [← h1]
  · rw [hr] at h1
    obtain ⟨hle, hle2⟩ := h2 x o' hr
    simp only [StateT.run, Option.map_some, id] at h1
    rw [← h1]
    simp only [hr, Option.bind_some, Option.map_some]
    refine ⟨?_, fun a j hj => ?_⟩
    · simp only [len_rest]
      have e : b.size - o - (b.size - o') = o' - o := by omega
      simp [e, rest, ByteArray.data_extract, Array.toList_extract, List.drop_drop, List.take_drop]
    · simp [hr] at hj
      omega

theorem sim_leaf : Sim rLeaf pLeaf := by
  unfold rLeaf pLeaf
  refine Sim.bind (sim_expect _) fun _ => ?_
  refine Sim.bind sim_ident fun _ => ?_
  refine Sim.bind sim_ident fun _ => ?_
  refine Sim.bind (sim_nat _ _ _) fun _ => ?_
  refine Sim.bind (sim_tag _) fun _ => ?_
  refine Sim.bind (sim_nat _ _ _) fun _ => ?_
  refine Sim.bind sim_ident fun _ => ?_
  refine Sim.bind (sim_take _) fun _ => ?_
  refine Sim.bind sim_ident fun _ => ?_
  refine Sim.bind (sim_nat _ _ _) fun _ => ?_
  refine Sim.bind sim_ident fun _ => ?_
  refine Sim.bind (sim_take _) fun _ => ?_
  refine Sim.bind (sim_tag _) fun _ => ?_
  refine Sim.bind (sim_nat _ _ _) fun _ => ?_
  refine Sim.bind (sim_many sim_code _) fun _ => ?_
  refine Sim.bind (sim_tag _) fun _ => ?_
  refine Sim.bind (sim_take _) fun _ => ?_
  refine Sim.bind (sim_take _) fun _ => ?_
  refine Sim.bind (sim_take _) fun _ => ?_
  refine Sim.bind (sim_take _) fun _ => ?_
  refine Sim.bind (sim_take _) fun _ => ?_
  refine Sim.bind (sim_nat _ _ _) fun _ => ?_
  refine Sim.bind (sim_nat _ _ _) fun _ => ?_
  refine Sim.bind (sim_nat _ _ _) fun _ => ?_
  refine Sim.bind (sim_nat _ _ _) fun _ => ?_
  refine Sim.bind (sim_nat _ _ _) fun _ => ?_
  refine Sim.bind (sim_need _) fun _ => ?_
  refine Sim.bind (sim_need _) fun _ => ?_
  refine Sim.bind (sim_need _) fun _ => ?_
  refine Sim.bind (sim_need _) fun _ => ?_
  exact Sim.pure _

theorem sim_token : Sim rToken pToken := by
  unfold rToken pToken
  refine Sim.bind (sim_consumed sim_leaf) ?_
  rintro ⟨leaf, leafBytes⟩
  refine Sim.bind (sim_nat _ _ _) fun _ => ?_
  refine Sim.bind (sim_many (sim_take _) _) fun _ => ?_
  refine Sim.bind (sim_take _) fun _ => ?_
  exact Sim.pure _

theorem decodeTokenB_eq (b : ByteArray) : decodeTokenB b = decodeToken b.data.toList := by
  unfold decodeTokenB decodeToken parse
  obtain ⟨hs1, hs2⟩ := sim_token b 0 (Nat.zero_le _)
  have r0 : rest b 0 = b.data.toList := List.drop_zero
  have hl : b.data.toList.length = b.size := by simp
  rw [r0] at hs1
  by_cases hbig : b.size > maxTokenBytes
  · simp [hbig, hl]
  · have hbig' : ¬ b.data.toList.length > maxTokenBytes := by rw [hl]; exact hbig
    simp only [hbig, hbig', if_false]
    rcases hr : rToken b 0 with _ | ⟨t, o⟩
    · rw [hr] at hs1
      simp only [Option.map_none] at hs1
      rw [← hs1]
    · rw [hr] at hs1
      have l := (hs2 t o hr).2
      simp only [Option.map_some, id] at hs1
      have key : rest b o = [] ↔ o = b.size := by
        rw [← List.length_eq_zero_iff, len_rest]; omega
      rw [← hs1]
      by_cases e2 : o = b.size
      · subst e2
        have : rest b b.size = [] := key.2 rfl
        simp only [rest] at this
        simp [this]
      · have hne : rest b o ≠ [] := fun h => e2 (key.1 h)
        cases hrest : rest b o with
        | nil => exact absurd hrest hne
        | cons _ _ => simp [e2, rest] at hrest ⊢

/-! ## Hashing and the Merkle levels -/

abbrev lst (a : ByteArray) : Bytes := a.data.toList

theorem ba_roundtrip (a : ByteArray) : a.data.toList.toByteArray = a :=
  ByteArray.ext (Array.toList_inj.1 (by rw [List.toList_data_toByteArray]))

theorem lst_append (a b : ByteArray) : lst (a ++ b) = lst a ++ lst b := by
  simp [lst, ByteArray.data_append, Array.toList_append]

/-- The core `ByteArray.toList` loop equals `data.toList`. -/
theorem ba_toList_loop (bs : ByteArray) :
    ∀ (n i : Nat) (r : List UInt8), bs.size - i = n → i ≤ bs.size →
      ByteArray.toList.loop bs i r = r.reverse ++ bs.data.toList.drop i
  | 0, i, r, hn, hi => by
    rw [ByteArray.toList.loop]
    have h1 : ¬ i < bs.size := by omega
    have h2 : bs.data.toList.drop i = [] := List.drop_eq_nil_of_le (by simp; omega)
    simp [h1, h2]
  | n + 1, i, r, hn, hi => by
    rw [ByteArray.toList.loop]
    have h1 : i < bs.size := by omega
    simp only [h1, if_true]
    have hdi : bs.data.toList.drop i = bs.data[i] :: bs.data.toList.drop (i + 1) := by
      rw [List.drop_eq_getElem_cons (show i < bs.data.toList.length by simpa using h1)]; simp
    rw [ba_toList_loop bs n (i + 1) _ (by omega) (by omega), hdi]
    simp [ByteArray.get!, getElem!_pos, h1]

theorem ba_toList_eq (bs : ByteArray) : bs.toList = bs.data.toList := by
  unfold ByteArray.toList
  rw [ba_toList_loop bs bs.size 0 [] (by omega) (by omega)]
  simp

theorem hashB_lst (a : ByteArray) : lst (hashB a) = sha3 (lst a) := by
  unfold hashB sha3
  rw [ba_roundtrip, ba_toList_eq, BlindLedger.Semantic.sha3_512Quick_eq]
  all_goals rfl

theorem merkleD_lst : lst merkleD = domain "MERKLE-NODE" := by
  simp [merkleD, lst, List.toList_data_toByteArray]

theorem leafHashB_lst (x : ByteArray) :
    lst (leafHashB x) = leafHash sha3 (domain "MERKLE-NODE") (lst x) := by
  simp [leafHashB, leafHash, hashB_lst, lst_append, merkleD_lst, lst]

theorem nodeHashB_lst (l r : ByteArray) :
    lst (nodeHashB l r) = nodeHash sha3 (domain "MERKLE-NODE") (lst l) (lst r) := by
  simp [nodeHashB, nodeHash, hashB_lst, lst_append, merkleD_lst, lst]

theorem pairUpB_eq : ∀ xs : List ByteArray, (pairUpB xs).map lst = pairUp sha3 (domain "MERKLE-NODE") (xs.map lst)
  | [] => rfl
  | [a] => rfl
  | a :: b :: rest => by
    simp only [pairUpB, pairUp, List.map_cons, nodeHashB_lst, pairUpB_eq rest]

def lvs (lv : List (Array ByteArray)) : List (List Bytes) := lv.map fun a => a.toList.map lst

theorem levelsB_eq : ∀ (fuel : Nat) (xs : List ByteArray),
    lvs (levelsB fuel xs) = levels sha3 (domain "MERKLE-NODE") fuel (xs.map lst)
  | fuel, [x] => by simp [levelsB, levels, lvs]
  | 0, [] => by simp [levelsB, levels, lvs]
  | 0, a :: b :: t => by simp [levelsB, levels, lvs]
  | fuel + 1, [] => by
    have := levelsB_eq fuel []
    simp_all [levelsB, levels, lvs, pairUpB, pairUp]
  | fuel + 1, a :: b :: t => by
    have := levelsB_eq fuel (pairUpB (a :: b :: t))
    rw [pairUpB_eq] at this
    simp only [levelsB, levels, lvs, List.map_cons, List.toList_toArray] at this ⊢
    rw [this]

theorem getD_lst (a : Array ByteArray) (j : Nat) :
    lst (a.getD j ByteArray.empty) = (a.toList.map lst).getD j [] := by
  by_cases h : j < a.size
  · simp [Array.getD, h, List.getD_eq_getElem?_getD]
  · simp [Array.getD, h, List.getD_eq_getElem?_getD, Array.getElem?_eq_none, lst]

theorem pathOfB_eq : ∀ (lv : List (Array ByteArray)) (i : Nat), (pathOfB lv i).map lst = pathOf (lvs lv) i
  | [], _ => rfl
  | lvl :: rest, i => by
    have ih := pathOfB_eq rest (i / 2)
    simp only [lvs] at ih
    simp only [pathOfB, pathOf, lvs, List.map_cons, List.length_map, Array.length_toList]
    by_cases h1 : lvl.size ≤ 1
    · simp [h1]
    · by_cases h2 : (i % 2 == 0 && i + 1 == lvl.size) = true
      · simp [h1, h2, ih]
      · simp [h1, h2, ih]
        cases lvl[if i % 2 = 0 then i + 1 else i - 1]? <;> simp [lst]

theorem tokenFitsTreeB_eq (c : Crypto) (k : Nat) (x : Stored) (lv : List (Array ByteArray)) (i : Nat) (t : Token) :
    tokenFitsTreeB c k x lv i t = tokenFitsTree c k x (lvs lv) i t := by
  simp [tokenFitsTreeB, tokenFitsTree, pathOfB_eq]

theorem mapM_decode (tokens : List ByteArray) :
    tokens.mapM decodeTokenB = (tokens.map lst).mapM decodeToken := by
  induction tokens with
  | nil => rfl
  | cons a l ih => simp [List.mapM_cons, decodeTokenB_eq, ih, lst]

theorem decodeKeyCert_signed {b : Bytes} {e : EpochCert} (h : decodeKeyCert b = some e) : e.signed = b := by
  unfold decodeKeyCert parse at h
  generalize hr : (pKeyCert.run b) = r at h
  rcases r with _ | ⟨y, _ | ⟨a, l⟩⟩
  · simp at h
  · obtain ⟨_, rfl⟩ := by simpa using h
    unfold pKeyCert at hr
    simp only [StateT.run, bind, StateT.bind, consumed, pure, StateT.pure] at hr
    split at hr
    · simp [Option.bind] at hr
      rw [← hr.1]
      simp [hr.2]
    · simp [Option.bind] at hr
  · simp at h

theorem accepts_eq {rootPk cert new : Bytes} {x : SignedCheckpoint} {e : EpochCert}
    (hx : decodeCheckpoint new = some x) (he : decodeKeyCert cert = some e) :
    accepts rootPk cert new = acceptsD rootPk new x e := by
  have hs : decodeKeyCert e.signed = some e := by rw [decodeKeyCert_signed he]; exact he
  have hr : rootSignedFast [(x.checkpoint.tenantId, rootPk)] e =
      (realCrypto [(x.checkpoint.tenantId, rootPk)]).rootSigned e := by
    simp [realCrypto, rootSignedFast, hs]
  have hi : installCert { realCrypto [(x.checkpoint.tenantId, rootPk)] with
      rootSigned := rootSignedFast [(x.checkpoint.tenantId, rootPk)] } emptyState e =
      installCert (realCrypto [(x.checkpoint.tenantId, rootPk)]) emptyState e := by
    unfold installCert
    simp only [hr]
  unfold accepts acceptsD
  rw [hx, he]
  simp only [hi]
  rcases installCert (realCrypto [(x.checkpoint.tenantId, rootPk)]) emptyState e with ⟨s, b⟩
  cases b
  · rfl
  · unfold storeCheckpoint
    rw [hx]
    rfl

theorem publishOkTreeB_eq (rootPk cert : ByteArray) (last : Option ByteArray) (new : ByteArray)
    (tokens : List ByteArray) (tpm : Nat) :
    publishOkTreeB rootPk cert last new tokens tpm =
      publishOkTree rootPk.data.toList cert.data.toList (last.map (·.data.toList)) new.data.toList
        (tokens.map (·.data.toList)) tpm := by
  unfold publishOkTreeB publishOkTree
  rw [mapM_decode]
  rcases he : decodeKeyCert cert.data.toList with _ | e
  · rfl
  rcases hx : decodeCheckpoint new.data.toList with _ | x
  · simp [storedOf, hx]
  have hn : storedOf sha3 new.data.toList = some ⟨sha3 x.header, x.checkpoint, new.data.toList⟩ := by
    simp [storedOf, hx]
  rw [hn, accepts_eq hx he]
  rcases (tokens.map lst).mapM decodeToken with _ | ts
  · rfl
  have hl : lvs (levelsB treeFuel (ts.map fun t => leafHashB t.leafBytes.toByteArray)) =
      levels sha3 (domain "MERKLE-NODE") treeFuel (ts.map fun t => leafHash sha3 (domain "MERKLE-NODE") t.leafBytes) := by
    rw [levelsB_eq]
    simp [Function.comp_def, leafHashB_lst, lst, List.toList_data_toByteArray]
  have hlast : ((levelsB treeFuel (ts.map fun t => leafHashB t.leafBytes.toByteArray)).getLast?.map
      fun a => a.toList.map lst) = (levels sha3 (domain "MERKLE-NODE") treeFuel
        (ts.map fun t => leafHash sha3 (domain "MERKLE-NODE") t.leafBytes)).getLast? := by
    rw [← hl, lvs, List.getLast?_map]
  simp only [hlast, tokenFitsTreeB_eq, hl]

/-! ## The frame -/

theorem rdB_le {b : ByteArray} {o n : Nat} {x : ByteArray} {o' : Nat} (h : rdB b o n = some (x, o')) :
    o' = o + n ∧ o' ≤ b.size := by
  unfold rdB at h
  split at h <;> simp_all

theorem rFramedB_le {b : ByteArray} {o : Nat} {x : ByteArray} {o' : Nat} (h : rFramedB b o = some (x, o')) :
    o' ≤ b.size := by
  unfold rFramedB at h
  cases h2 : rNat 4 0 maxNat b o with
  | none => simp [h2] at h
  | some q =>
    obtain ⟨n, o2⟩ := q
    simp only [h2, Option.bind_some] at h
    exact (rdB_le h).2

theorem framed_rd (b : ByteArray) (o : Nat) (ho : o ≤ b.size) :
    pFramed.run (rest b o) = (rFramedB b o).map fun p => (lst p.1, rest b p.2) := by
  obtain ⟨hn1, hn2⟩ := sim_nat 4 0 maxNat b o ho
  unfold pFramed rFramedB
  rcases hr : rNat 4 0 maxNat b o with _ | ⟨n, o'⟩
  · rw [hr] at hn1
    simp [StateT.run_bind, ← hn1]
  · rw [hr] at hn1
    have l := (hn2 n o' hr).2
    simp only [Option.map_some, id] at hn1
    simp [StateT.run_bind, ← hn1, take_rd b o' n l, rd, lst, Option.map_map, Function.comp_def]

theorem rManyB_le {b : ByteArray} : ∀ {k o : Nat} {xs : List ByteArray} {o' : Nat}, o ≤ b.size →
    rManyB b o k = some (xs, o') → o' ≤ b.size
  | 0, o, xs, o', ho, h => by simp [rManyB] at h; omega
  | k + 1, o, xs, o', ho, h => by
    unfold rManyB at h
    cases h1 : rFramedB b o with
    | none => simp [h1] at h
    | some q =>
      obtain ⟨x, o1⟩ := q
      cases h2 : rManyB b o1 k with
      | none => simp [h1, h2] at h
      | some r =>
        obtain ⟨ys, o2⟩ := r
        simp [h1, h2] at h
        exact (by have := rManyB_le (rFramedB_le h1) h2; omega)

theorem many_rd (b : ByteArray) : ∀ (k o : Nat), o ≤ b.size →
    (many pFramed k).run (rest b o) = (rManyB b o k).map fun p => (p.1.map lst, rest b p.2)
  | 0, o, _ => by simp [many, rManyB]
  | k + 1, o, ho => by
    unfold many rManyB
    cases h1 : rFramedB b o with
    | none => simp [StateT.run_bind, framed_rd b o ho, h1]
    | some q =>
      obtain ⟨x, o1⟩ := q
      have := many_rd b k o1 (rFramedB_le h1)
      cases h2 : rManyB b o1 k with
      | none => simp [StateT.run_bind, framed_rd b o ho, h1, this, h2]
      | some r => obtain ⟨ys, o2⟩ := r; simp [StateT.run_bind, framed_rd b o ho, h1, this, h2]

theorem publishFrameB_eq (b : ByteArray) : publishFrameB b = publishFrame b.data.toList := by
  have z : 0 ≤ b.size := Nat.zero_le _
  have t0 : (take mlDsa87Key).run b.data.toList = (rdB b 0 mlDsa87Key).map fun p => (lst p.1, rest b p.2) := by
    simpa [rest, rd, lst, Option.map_map, Function.comp_def] using take_rd b 0 mlDsa87Key z
  have hemp : ∀ l : ByteArray, l = ByteArray.empty ↔ l.data = #[] := by
    intro l
    constructor
    · rintro rfl; rfl
    · intro h
      cases l with
      | mk d => simp only at h; subst h; rfl
  unfold publishFrame parse pPublishArgs publishFrameB
  simp only [Nat.lt_irrefl, if_false]
  rcases h1 : rdB b 0 mlDsa87Key with _ | ⟨r, o1⟩
  · simp [StateT.run_bind, t0, h1]
  have l1 := (rdB_le h1).2
  rcases h2 : rFramedB b o1 with _ | ⟨c, o2⟩
  · simp [StateT.run_bind, t0, h1, framed_rd b o1 l1, h2]
  have l2 := rFramedB_le h2
  rcases h3 : rFramedB b o2 with _ | ⟨l, o3⟩
  · simp [StateT.run_bind, t0, h1, framed_rd b o1 l1, h2, framed_rd b o2 l2, h3]
  have l3 := rFramedB_le h3
  rcases h4 : rFramedB b o3 with _ | ⟨n, o4⟩
  · simp [StateT.run_bind, t0, h1, framed_rd b o1 l1, h2, framed_rd b o2 l2, h3,
      framed_rd b o3 l3, h4]
  have l4 := rFramedB_le h4
  have n2 := (sim_nat 2 0 maxNat b o4 l4).1.symm
  rcases h5 : rNat 2 0 maxNat b o4 with _ | ⟨k, o5⟩
  · simp [StateT.run_bind, t0, h1, framed_rd b o1 l1, h2, framed_rd b o2 l2, h3,
      framed_rd b o3 l3, h4, n2, h5]
  have l5 := (sim_nat 2 0 maxNat b o4 l4).2 k o5 h5 |>.2
  rcases h6 : rManyB b o5 k with _ | ⟨ts, o6⟩
  · simp [StateT.run_bind, t0, h1, framed_rd b o1 l1, h2, framed_rd b o2 l2, h3,
      framed_rd b o3 l3, h4, n2, h5, many_rd b k o5 l5, h6]
  have l6 := rManyB_le l5 h6
  have n3 := (sim_nat 8 0 maxNat b o6 l6).1.symm
  rcases h7 : rNat 8 0 maxNat b o6 with _ | ⟨tpm, o7⟩
  · simp [StateT.run_bind, t0, h1, framed_rd b o1 l1, h2, framed_rd b o2 l2, h3,
      framed_rd b o3 l3, h4, n2, h5, many_rd b k o5 l5, h6, n3, h7]
  have l7 := (sim_nat 8 0 maxNat b o6 l6).2 tpm o7 h7 |>.2
  have key : rest b o7 = [] ↔ o7 = b.size := by
    rw [← List.length_eq_zero_iff, len_rest]; omega
  by_cases e : o7 = b.size
  · subst e
    have e' : rest b b.size = [] := by simp [rest]
    simp [StateT.run_bind, t0, h1, framed_rd b o1 l1, h2, framed_rd b o2 l2, h3,
      framed_rd b o3 l3, h4, n2, h5, many_rd b k o5 l5, h6, n3, h7, e', publishArgsOk, publishOkTreeB_eq]
    by_cases hl0 : l.data = #[] <;> simp [hl0, hemp, lst]
  · have e' : rest b o7 ≠ [] := fun h => e (key.1 h)
    simp [StateT.run_bind, t0, h1, framed_rd b o1 l1, h2, framed_rd b o2 l2, h3,
      framed_rd b o3 l3, h4, n2, h5, many_rd b k o5 l5, h6, n3, h7, e, e']

end BlindLedger.Gate
