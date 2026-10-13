import BlindLedger.Gate.Engine.Log

/-! ENGINE-0 S2/S3b (design `engine0-design-20261013` sections 1.5 and 7): the ENGINE-SNAP/v2
    snapshot codec and digest.  Synthetic, nonpayment; moves no money.

    `tag || be8 idx || entryDigest d || lp(LogState3)`, LogState3 = `rhead d || lp(reg rows) || asc
    shard rows`, a shard row = `be4 shard || own || sealed || be1 live || last || base d || pays`, own =
    `asc (be8 epoch || be8 count)`, sealed = `be1 0` or `be1 1 || lp tip`, last = `tipIn`, pays =
    `asc (be261 key || lp leaf)`, and `asc` = `be4 n || n items` with strictly ascending keys, so one
    state has one encoding.  `idx` is the anchor record (`len = idx + 1`) and `entryDigest` is `head`,
    so neither is repeated inside.  Rows carry their actual bytes (lead 2026-10-13: no padding).  The
    seal tip is `lp` (be4) because the S1 decoder accepts a seal tip of any length.  v1 (S2: sealed and
    live only) is refused by its tag.  `snapDigest = sha3_512(all)`.  The literal tag avoids `dom2`'s
    `/v1/v2`.

    The state is a `Std.TreeMap`, whose tree shape is not canonical, so E4 and E5 hold up to `abs`
    (the sorted row list), as the design's `abs` and `foldFrom P (abs m')` already read. -/

namespace BlindLedger.Gate.Engine

open BlindLedger.Gate BlindLedger.Gate.Rules

def snapTag : Bytes := "RR/GATE/ENGINE-SNAP/v2".toUTF8.toList ++ [0]

/-- The canonical state: what the snapshot binds. -/
structure LogState3 where
  len : Nat
  head : Bytes
  reg : List Row
  rhead : Bytes
  shards : List (Nat × ShardM)

def abs (m : LogStateM) : LogState3 := ⟨m.len, m.head, m.reg, m.rhead, m.shards.toList⟩

def bitIn : Bool → Bytes
  | false => natBE 1 0
  | true => natBE 1 1
def sealedIn : Option Bytes → Bytes
  | none => natBE 1 0
  | some t => natBE 1 1 ++ lp t
def ascIn {α : Type} (enc : Nat × α → Bytes) (xs : List (Nat × α)) : Bytes :=
  natBE 4 xs.length ++ xs.flatMap enc
def ownRow (x : Nat × Nat) : Bytes := natBE 8 x.1 ++ natBE 8 x.2
def payRow (x : Nat × Bytes) : Bytes := natBE payWidth x.1 ++ lp x.2
def shardRow (x : Nat × ShardM) : Bytes :=
  natBE 4 x.1 ++ ascIn ownRow x.2.own ++ sealedIn x.2.sealed ++ bitIn x.2.live ++ tipIn x.2.last ++ x.2.base ++
    ascIn payRow x.2.pays

def stateIn (m : LogStateM) : Bytes := m.rhead ++ lp (rows m.reg) ++ ascIn shardRow m.shards.toList
def snapIn (m : LogStateM) : Bytes := snapTag ++ natBE 8 (m.len - 1) ++ m.head ++ lp (stateIn m)
def encodeSnap (m : LogStateM) : ByteArray := (snapIn m).toByteArray
def snapDigest (m : LogStateM) : Bytes := sha3 (snapIn m)

def ascKeys {α : Type} : List (Nat × α) → Bool
  | a :: b :: t => decide (a.1 < b.1) && ascKeys (b :: t)
  | _ => true

/-- An `asc` list fits: its count fits be4, each item fits, its keys strictly ascend. -/
def ascFits {α : Type} (Q : Nat × α → Prop) (xs : List (Nat × α)) : Prop :=
  xs.length < 256 ^ 4 ∧ (∀ x ∈ xs, Q x) ∧ ascKeys xs = true
def ShardM.fits (x : Nat × ShardM) : Prop :=
  x.1 < 256 ^ 4 ∧ ascFits (fun e => e.1 < 256 ^ 8 ∧ e.2 < 256 ^ 8) x.2.own ∧
    (∀ t, x.2.sealed = some t → t.length < 256 ^ 4) ∧
    (∀ s c, x.2.last = some (s, c) → s.length < 256 ^ 4 ∧ c.length < 256 ^ 4) ∧
    x.2.base.length = digestBytes ∧ ascFits (fun e => e.1 < 256 ^ payWidth ∧ e.2.length < 256 ^ 4) x.2.pays
/-- A snapshot follows at least one record and every field fits its width. -/
def LogStateM.wf (m : LogStateM) : Prop :=
  0 < m.len ∧ m.len - 1 < 256 ^ 8 ∧ m.head.length = digestBytes ∧ m.rhead.length = digestBytes ∧
    (rows m.reg).length < 256 ^ 4 ∧ (∀ x ∈ m.reg, rowFits x) ∧ m.shards.toList.length < 256 ^ 4 ∧
    (∀ x ∈ m.shards.toList, ShardM.fits x) ∧ (stateIn m).length < 256 ^ 4

/-! ## Decoder -/

def pAsc {α : Type} (p : P (Nat × α)) : P (List (Nat × α)) := do
  let xs ← many p (← rd 4)
  need (ascKeys xs)
  pure xs

def pBit : P Bool := do
  match ← rd 1 with
  | 0 => pure false
  | 1 => pure true
  | _ => fail
def pSealed : P (Option Bytes) := do
  match ← rd 1 with
  | 0 => pure none
  | 1 => do let t ← pLp; pure (some t)
  | _ => fail
def pOwn : P (Nat × Nat) := do
  let e ← rd 8
  let c ← rd 8
  pure (e, c)
def pPay : P (Nat × Bytes) := do
  let n ← rd payWidth
  let x ← pLp
  pure (n, x)
def pShard : P (Nat × ShardM) := do
  let k ← rd 4
  let own ← pAsc pOwn
  let sealed ← pSealed
  let live ← pBit
  let last ← pTip
  let base ← digest
  let pays ← pAsc pPay
  pure (k, ⟨own, sealed, live, last, base, pays⟩)
def pState : P (Bytes × List Row × List (Nat × ShardM)) := do
  let rhead ← digest
  let reg ← pRows
  let rs ← pAsc pShard
  pure (rhead, reg, rs)
def pSnap : P LogStateM := do
  expect snapTag
  let idx ← rd 8
  let head ← digest
  let body ← pLp
  match pState.run body with
  | some ((rhead, reg, rs), []) => pure ⟨idx + 1, head, reg, rhead, Std.TreeMap.ofList rs compare⟩
  | _ => fail

def decodeSnap (b : ByteArray) : Option LogStateM :=
  match pSnap.run b.data.toList with
  | some (m, []) => some m
  | _ => none

/-! ## Round trip (E4) -/

theorem pBit_app (v : Bool) (r : Bytes) : pBit.run (bitIn v ++ r) = some (v, r) := by
  cases v
  · simp only [pBit, bitIn, seq_app (rd_app (w := 1) (v := 0) (by decide))] <;> rfl
  · simp only [pBit, bitIn, seq_app (rd_app (w := 1) (v := 1) (by decide))] <;> rfl

theorem pSealed_app (o : Option Bytes) (h : ∀ t, o = some t → t.length < 256 ^ 4) (r : Bytes) :
    pSealed.run (sealedIn o ++ r) = some (o, r) := by
  cases o with
  | none => simp only [pSealed, sealedIn, seq_app (rd_app (w := 1) (v := 0) (by decide))] <;> rfl
  | some t =>
    simp only [pSealed, sealedIn, List.append_assoc, seq_app (rd_app (w := 1) (v := 1) (by decide)),
      seq_app (pLp_app t (h t rfl))] <;> rfl

theorem pTip_app (o : Option (Bytes × Bytes)) (h : ∀ s c, o = some (s, c) → s.length < 256 ^ 4 ∧ c.length < 256 ^ 4)
    (r : Bytes) : pTip.run (tipIn o ++ r) = some (o, r) := by
  match o, h with
  | none, _ => simp only [pTip, tipIn, seq_app (rd_app (w := 1) (v := 0) (by decide))] <;> rfl
  | some (s, c), h =>
    obtain ⟨hs, hc⟩ := h s c rfl
    simp only [pTip, tipIn, List.append_assoc, seq_app (rd_app (w := 1) (v := 1) (by decide)),
      seq_app (pLp_app s hs), seq_app (pLp_app c hc)] <;> rfl

theorem pAsc_app {α : Type} {p : P (Nat × α)} {enc : Nat × α → Bytes} {Q : Nat × α → Prop}
    (hp : ∀ x, Q x → ∀ r, p.run (enc x ++ r) = some (x, r)) (xs : List (Nat × α)) (h : ascFits Q xs) (r : Bytes) :
    (pAsc p).run (ascIn enc xs ++ r) = some (xs, r) := by
  obtain ⟨hn, hq, ha⟩ := h
  simp only [pAsc, ascIn, List.append_assoc, seq_app (rd_app hn), seq_app (many_app hp xs hq), ha, need_seq] <;> rfl

theorem pOwn_app (x : Nat × Nat) (h : x.1 < 256 ^ 8 ∧ x.2 < 256 ^ 8) (r : Bytes) :
    pOwn.run (ownRow x ++ r) = some (x, r) := by
  simp only [pOwn, ownRow, List.append_assoc, seq_app (rd_app h.1), seq_app (rd_app h.2)] <;> rfl

theorem pPay_app (x : Nat × Bytes) (h : x.1 < 256 ^ payWidth ∧ x.2.length < 256 ^ 4) (r : Bytes) :
    pPay.run (payRow x ++ r) = some (x, r) := by
  simp only [pPay, payRow, List.append_assoc, seq_app (rd_app h.1), seq_app (pLp_app _ h.2)] <;> rfl

theorem pShard_app (x : Nat × ShardM) (h : ShardM.fits x) (r : Bytes) :
    pShard.run (shardRow x ++ r) = some (x, r) := by
  obtain ⟨k, o, s, l, t, b, ps⟩ := x
  obtain ⟨hk, ho, hs, ht, hb, hp⟩ := h
  simp only [pShard, shardRow, List.append_assoc, seq_app (rd_app hk), seq_app (pAsc_app pOwn_app o ho),
    seq_app (pSealed_app s hs), seq_app (pBit_app l), seq_app (pTip_app t ht), seq_app (digest_app hb),
    seq_app (pAsc_app pPay_app ps hp)] <;> rfl

theorem ascKeys_of {α : Type} : ∀ l : List (Nat × α), l.Pairwise (fun a b => compare a.1 b.1 = .lt) →
    ascKeys l = true
  | [], _ => rfl
  | [_], _ => rfl
  | a :: b :: t, h => by
    rw [List.pairwise_cons] at h
    have hab : a.1 < b.1 := Nat.compare_eq_lt.1 (h.1 b List.mem_cons_self)
    simp only [ascKeys, hab, decide_true, Bool.true_and]
    exact ascKeys_of (b :: t) h.2

theorem pState_app (m : LogStateM) (hr : m.rhead.length = digestBytes) (hg : (rows m.reg).length < 256 ^ 4)
    (hf : ∀ x ∈ m.reg, rowFits x) (hn : m.shards.toList.length < 256 ^ 4)
    (hs : ∀ x ∈ m.shards.toList, ShardM.fits x) :
    pState.run (stateIn m) = some ((m.rhead, m.reg, m.shards.toList), []) := by
  have ha : ascKeys m.shards.toList = true := ascKeys_of _ Std.TreeMap.ordered_keys_toList
  rw [← List.append_nil (stateIn m)]
  simp only [pState, stateIn, List.append_assoc, seq_app (digest_app hr), seq_app (pRows_app _ hg hf),
    seq_app (pAsc_app pShard_app _ ⟨hn, hs, ha⟩)] <;> rfl

theorem ofList_toList_equiv (t : Std.TreeMap Nat ShardM) :
    (Std.TreeMap.ofList t.toList compare).Equiv t := by
  apply Std.TreeMap.Equiv.of_forall_constGet?_eq
  intro k
  cases hk : t[k]? with
  | some v =>
    exact Std.TreeMap.getElem?_ofList_of_mem (Nat.compare_eq_eq.2 rfl) Std.TreeMap.distinct_keys_toList
      (Std.TreeMap.mem_toList_iff_getElem?_eq_some.2 hk)
  | none =>
    apply Std.TreeMap.getElem?_ofList_of_contains_eq_false
    simp [Std.TreeMap.mem_iff_isSome_getElem?, hk]

/-- The decoded state: `m` with its rows rebuilt into a fresh map. -/
def canon (m : LogStateM) : LogStateM :=
  ⟨m.len, m.head, m.reg, m.rhead, Std.TreeMap.ofList m.shards.toList compare⟩

theorem abs_canon (m : LogStateM) : abs (canon m) = abs m := by
  simp only [abs, canon, Std.TreeMap.equiv_iff_toList_eq.1 (ofList_toList_equiv m.shards)]

theorem decode_encodeSnap (m : LogStateM) (h : m.wf) : decodeSnap (encodeSnap m) = some (canon m) := by
  obtain ⟨h0, hi, hh, hr, hg, hf, hn, hs, hl⟩ := h
  have hrun : pSnap.run (snapIn m ++ []) = some (canon m, []) := by
    simp only [pSnap, snapIn, List.append_assoc, seq_app (p := expect snapTag) (fun _ => expect_app),
      seq_app (rd_app hi), seq_app (digest_app hh), seq_app (pLp_app _ hl), pState_app m hr hg hf hn hs,
      Nat.sub_add_cancel h0] <;> rfl
  rw [List.append_nil] at hrun
  simp only [decodeSnap, encodeSnap, List.toList_data_toByteArray, hrun]

/-- E4: a well-formed state decodes back to itself (up to the map's tree shape). -/
theorem E4_snap_roundtrip (m : LogStateM) (h : m.wf) : (decodeSnap (encodeSnap m)).map abs = some (abs m) := by
  rw [decode_encodeSnap m h, Option.map_some, abs_canon]

/-- E4b: equal snapshot digests mean equal states, or the two distinct encodings are an explicit
    SHA3 collision. -/
theorem E4b_snapDigest_binds {a b : LogStateM} (ha : a.wf) (hb : b.wf) (h : snapDigest a = snapDigest b) :
    abs a = abs b ∨ (snapIn a ≠ snapIn b ∧ sha3 (snapIn a) = sha3 (snapIn b)) := by
  by_cases he : snapIn a = snapIn b
  · left
    have h1 := E4_snap_roundtrip a ha
    rw [show encodeSnap a = encodeSnap b by simp only [encodeSnap, he], E4_snap_roundtrip b hb] at h1
    exact (Option.some.inj h1).symm
  · exact Or.inr ⟨he, h⟩

/-! ## Replay from a snapshot (E5) -/

theorem abs_inj {a b : LogStateM} (h : abs a = abs b) :
    a.len = b.len ∧ a.head = b.head ∧ a.reg = b.reg ∧ a.rhead = b.rhead ∧ a.shards.Equiv b.shards := by
  simp only [abs, LogState3.mk.injEq] at h
  exact ⟨h.1, h.2.1, h.2.2.1, h.2.2.2.1, Std.TreeMap.equiv_iff_toList_eq.2 h.2.2.2.2⟩

theorem stepM_abs {a b : LogStateM} (h : abs a = abs b) (body : Body3) :
    (stepM a body).map abs = (stepM b body).map abs := by
  obtain ⟨hl, hh, hg, hr, hs⟩ := abs_inj h
  have hk : ∀ k, a.shard k = b.shard k := fun k => hs.getD_eq
  have ht : a.shards.toList = b.shards.toList := Std.TreeMap.equiv_iff_toList_eq.1 hs
  have hi : ∀ k s, (a.shards.insert k s).toList = (b.shards.insert k s).toList :=
    fun k s => Std.TreeMap.equiv_iff_toList_eq.1 (hs.insert k s)
  cases body with
  | batch bt => simp only [stepM, hk]; split <;> simp [abs, hl, hh, hg, hr, ht]
  | resume k p => simp only [stepM, hk]; split <;> (try split) <;> simp [abs, hl, hh, hg, hr, hi]
  | «seal» k t => simp only [stepM, hk]; split <;> simp [abs, hl, hh, hg, hr, hi]
  | segment s => simp [stepM, h]

theorem pushM_abs {a b : LogStateM} (h : abs a = abs b) (x : ByteArray) :
    (pushM a x).map abs = (pushM b x).map abs := by
  obtain ⟨hl, hh, -, -, -⟩ := abs_inj h
  have hst := stepM_abs h
  unfold pushM
  cases decodeEntry3B x with
  | none => rfl
  | some e =>
    simp only [hl, hh]
    split
    · have hs := hst e.body
      rcases h1 : stepM a e.body with _ | s1 <;> rcases h2 : stepM b e.body with _ | s2 <;>
        rw [h1, h2] at hs <;> simp_all [abs]
    · rfl

theorem foldM_abs (es : List ByteArray) :
    ∀ {a b : LogStateM}, abs a = abs b → (es.foldlM pushM a).map abs = (es.foldlM pushM b).map abs := by
  induction es with
  | nil => intro a b h; simp [h]
  | cons x es ih =>
    intro a b h
    have hp := pushM_abs h x
    simp only [List.foldlM_cons]
    revert hp
    cases pushM a x <;> cases pushM b x <;> intro hp
    all_goals first
      | (simp at hp; done)
      | exact ih (by simpa using hp)
      | rfl

/-- E5: replaying the log tail from the snapshot of the folded prefix gives the full fold. -/
theorem E5_replay_from_snap (log : List ByteArray) (i : Nat) {m : LogStateM}
    (h : (log.take i).foldlM pushM LogStateM.init = some m) (hw : m.wf) :
    ((decodeSnap (encodeSnap m)).bind fun m' => (log.drop i).foldlM pushM m').map abs =
      (log.foldlM pushM LogStateM.init).map abs := by
  rw [decode_encodeSnap m hw, ← List.take_append_drop i log, List.foldlM_append, h,
    List.take_append_drop]
  exact foldM_abs _ (abs_canon m)

end BlindLedger.Gate.Engine
