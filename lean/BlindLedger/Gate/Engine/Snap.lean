import BlindLedger.Gate.Engine.Log

/-! ENGINE-0 S2 (design `engine0-design-20261013` sections 1.5 and 7): the ENGINE-SNAP/v1 snapshot
    codec and digest.  Synthetic, nonpayment; moves no money.

    `tag || be8 idx || entryDigest d || lp(LogState3)`, LogState3 = `rhead d || be4 n || n shard rows`,
    a shard row = `be4 shard || sealed || be1 live`, sealed = `be1 0` or `be1 1 || lp tip`.  `idx` is the
    anchor record (`len = idx + 1`) and `entryDigest` is `head`, so neither is repeated inside.  Rows
    carry their actual bytes (lead 2026-10-13: no padding); the decoder takes only strictly ascending
    shard keys, so one state has one encoding.  The tip is `lp` (be4) because the S1 decoder accepts a
    seal tip of any length.  `snapDigest = sha3_512(all)`.  The literal tag avoids `dom2`'s `/v1/v2`.

    The state is a `Std.TreeMap`, whose tree shape is not canonical, so E4 and E5 hold up to `abs`
    (the sorted row list), as the design's `abs` and `foldFrom P (abs m')` already read. -/

namespace BlindLedger.Gate.Engine

open BlindLedger.Gate

def snapTag : Bytes := "RR/GATE/ENGINE-SNAP/v1".toUTF8.toList ++ [0]

/-- The canonical state: what the snapshot binds. -/
structure LogState3 where
  len : Nat
  head : Bytes
  rhead : Bytes
  shards : List (Nat × ShardM)

def abs (m : LogStateM) : LogState3 := ⟨m.len, m.head, m.rhead, m.shards.toList⟩

def bitIn : Bool → Bytes
  | false => natBE 1 0
  | true => natBE 1 1
def sealedIn : Option Bytes → Bytes
  | none => natBE 1 0
  | some t => natBE 1 1 ++ lp t
def shardRow (x : Nat × ShardM) : Bytes := natBE 4 x.1 ++ sealedIn x.2.sealed ++ bitIn x.2.live

def stateIn (m : LogStateM) : Bytes :=
  m.rhead ++ natBE 4 m.shards.toList.length ++ m.shards.toList.flatMap shardRow
def snapIn (m : LogStateM) : Bytes := snapTag ++ natBE 8 (m.len - 1) ++ m.head ++ lp (stateIn m)
def encodeSnap (m : LogStateM) : ByteArray := (snapIn m).toByteArray
def snapDigest (m : LogStateM) : Bytes := sha3 (snapIn m)

def ShardM.fits (x : Nat × ShardM) : Prop := x.1 < 256 ^ 4 ∧ ∀ t, x.2.sealed = some t → t.length < 256 ^ 4
/-- A snapshot follows at least one record and every field fits its width. -/
def LogStateM.wf (m : LogStateM) : Prop :=
  0 < m.len ∧ m.len - 1 < 256 ^ 8 ∧ m.head.length = digestBytes ∧ m.rhead.length = digestBytes ∧
    m.shards.toList.length < 256 ^ 4 ∧ (∀ x ∈ m.shards.toList, ShardM.fits x) ∧ (stateIn m).length < 256 ^ 4

/-! ## Decoder -/

def ascKeys : List (Nat × ShardM) → Bool
  | a :: b :: t => decide (a.1 < b.1) && ascKeys (b :: t)
  | _ => true

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
def pShard : P (Nat × ShardM) := do
  let k ← rd 4
  let sealed ← pSealed
  let live ← pBit
  pure (k, ⟨sealed, live⟩)
def pState : P (Bytes × List (Nat × ShardM)) := do
  let rhead ← digest
  let rs ← many pShard (← rd 4)
  need (ascKeys rs)
  pure (rhead, rs)
def pSnap : P LogStateM := do
  expect snapTag
  let idx ← rd 8
  let head ← digest
  let body ← pLp
  match pState.run body with
  | some ((rhead, rs), []) => pure ⟨idx + 1, head, rhead, Std.TreeMap.ofList rs compare⟩
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

theorem pShard_app (x : Nat × ShardM) (h : ShardM.fits x) (r : Bytes) :
    pShard.run (shardRow x ++ r) = some (x, r) := by
  obtain ⟨k, s, l⟩ := x
  obtain ⟨hk, hs⟩ := h
  simp only [pShard, shardRow, List.append_assoc, seq_app (rd_app hk), seq_app (pSealed_app s hs),
    seq_app (pBit_app l)] <;> rfl

theorem ascKeys_of : ∀ l : List (Nat × ShardM), l.Pairwise (fun a b => compare a.1 b.1 = .lt) →
    ascKeys l = true
  | [], _ => rfl
  | [_], _ => rfl
  | a :: b :: t, h => by
    rw [List.pairwise_cons] at h
    have hab : a.1 < b.1 := Nat.compare_eq_lt.1 (h.1 b List.mem_cons_self)
    simp only [ascKeys, hab, decide_true, Bool.true_and]
    exact ascKeys_of (b :: t) h.2

theorem pState_app (m : LogStateM) (hr : m.rhead.length = digestBytes) (hn : m.shards.toList.length < 256 ^ 4)
    (hs : ∀ x ∈ m.shards.toList, ShardM.fits x) :
    pState.run (stateIn m) = some ((m.rhead, m.shards.toList), []) := by
  have ha : ascKeys m.shards.toList = true := ascKeys_of _ Std.TreeMap.ordered_keys_toList
  rw [← List.append_nil (stateIn m)]
  simp only [pState, stateIn, List.append_assoc, seq_app (digest_app hr), seq_app (rd_app hn),
    seq_app (many_app pShard_app _ hs), ha, need_seq] <;> rfl

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
def canon (m : LogStateM) : LogStateM := ⟨m.len, m.head, m.rhead, Std.TreeMap.ofList m.shards.toList compare⟩

theorem abs_canon (m : LogStateM) : abs (canon m) = abs m := by
  simp only [abs, canon, Std.TreeMap.equiv_iff_toList_eq.1 (ofList_toList_equiv m.shards)]

theorem decode_encodeSnap (m : LogStateM) (h : m.wf) : decodeSnap (encodeSnap m) = some (canon m) := by
  obtain ⟨h0, hi, hh, hr, hn, hs, hl⟩ := h
  have hrun : pSnap.run (snapIn m ++ []) = some (canon m, []) := by
    simp only [pSnap, snapIn, List.append_assoc, seq_app (p := expect snapTag) (fun _ => expect_app),
      seq_app (rd_app hi), seq_app (digest_app hh), seq_app (pLp_app _ hl), pState_app m hr hn hs,
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
    a.len = b.len ∧ a.head = b.head ∧ a.rhead = b.rhead ∧ a.shards.Equiv b.shards := by
  simp only [abs, LogState3.mk.injEq] at h
  exact ⟨h.1, h.2.1, h.2.2.1, Std.TreeMap.equiv_iff_toList_eq.2 h.2.2.2⟩

theorem stepM_abs {a b : LogStateM} (h : abs a = abs b) (body : Body3) :
    (stepM a body).map abs = (stepM b body).map abs := by
  obtain ⟨hl, hh, hr, hs⟩ := abs_inj h
  have hk : ∀ k, a.shard k = b.shard k := fun k => hs.getD_eq
  have ht : a.shards.toList = b.shards.toList := Std.TreeMap.equiv_iff_toList_eq.1 hs
  have hi : ∀ k s, (a.shards.insert k s).toList = (b.shards.insert k s).toList :=
    fun k s => Std.TreeMap.equiv_iff_toList_eq.1 (hs.insert k s)
  cases body with
  | batch bt => simp only [stepM, hk]; split <;> simp [abs, hl, hh, hr, ht]
  | resume k p => simp only [stepM, hk]; split <;> simp [abs, hl, hh, hr, hi]
  | «seal» k t => simp only [stepM, hk]; split <;> simp [abs, hl, hh, hr, hi]
  | segment s => simp [stepM, h]

theorem pushM_abs {a b : LogStateM} (h : abs a = abs b) (x : ByteArray) :
    (pushM a x).map abs = (pushM b x).map abs := by
  obtain ⟨hl, hh, -, -⟩ := abs_inj h
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
