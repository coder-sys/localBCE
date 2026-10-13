import BlindLedger.Gate.Engine.Log
import BlindLedger.Gate.StateV2
import BlindLedger.Sha3FastEq

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
    `/v1/v2`.  The encoder is in `Log.lean` (a segment binds `snapDigest`).  The decoder refuses an own
    count of 0, a live shard on the zero base, a parked (not live) shard with an own row, a `last` or a
    base other than the zero digest (StateV2 parks only `Shard.init` plus an optional seal), an `rhead`
    that is not `chainHead sha3 zeroDigest reg`, pays on a shard with no `last`, and a pay leaf that is
    not one whole Spec `pLeaf` of this shard keyed by its `payNat programId paymentId` (S3b review L3, M1,
    M2; S3d review MED-2, r2 LOW): states StateV2 never reaches.  The engine fold does reach a live
    shard on the zero base (its resume does not yet compute StateV2's base: that needs `Pins` and the
    permit's rel/unr sets), so no snapshot follows a resume until it does (S3d review HIGH-2, kept
    refusal).

    The state is a `Std.TreeMap`, whose tree shape is not canonical, so E4 and E5 hold up to `abs`
    (the sorted row list), as the design's `abs` and `foldFrom P (abs m')` already read. -/

namespace BlindLedger.Gate.Engine

open BlindLedger.Gate BlindLedger.Gate.Rules

/-- The canonical state: what the snapshot binds. -/
structure LogState3 where
  len : Nat
  head : Bytes
  reg : List Row
  rhead : Bytes
  shards : List (Nat × ShardM)

def abs (m : LogStateM) : LogState3 := ⟨m.len, m.head, m.reg, m.rhead, m.shards.toList⟩

/-- A pay row of shard `k` is one whole Spec leaf of shard `k` keyed by its `payNat programId paymentId`
    (S3b review L3, S3d review MED-2): no pay row whose key names another payment, whose leaf is not a
    decision, or whose decision belongs to another shard. -/
def payKeyOk (k n : Nat) (x : Bytes) : Bool :=
  match pLeaf.run x with
  | some (l, []) => n == StateV2.payNat l.programId l.paymentId && l.shardId == k
  | _ => false

def ascKeys {α : Type} : List (Nat × α) → Bool
  | a :: b :: t => decide (a.1 < b.1) && ascKeys (b :: t)
  | _ => true

/-- An `asc` list fits: its count fits be4, each item fits, its keys strictly ascend. -/
def ascFits {α : Type} (Q : Nat × α → Prop) (xs : List (Nat × α)) : Prop :=
  xs.length < 256 ^ 4 ∧ (∀ x ∈ xs, Q x) ∧ ascKeys xs = true
def ShardM.fits (x : Nat × ShardM) : Prop :=
  x.1 < 256 ^ 4 ∧ ascFits (fun e => e.1 < 256 ^ 8 ∧ 0 < e.2 ∧ e.2 < 256 ^ 8) x.2.own ∧
    (∀ t, x.2.sealed = some t → t.length < 256 ^ 4) ∧
    (∀ s c, x.2.last = some (s, c) → s.length < 256 ^ 4 ∧ c.length < 256 ^ 4) ∧
    x.2.base.length = digestBytes ∧ (x.2.live = true → x.2.base ≠ zeroDigest) ∧
    ascFits (fun e => e.1 < 256 ^ payWidth ∧ e.2.length < 256 ^ 4 ∧ payKeyOk x.1 e.1 e.2 = true) x.2.pays ∧
    (x.2.last = none → x.2.pays = []) ∧
    (x.2.live = false → x.2.own = [] ∧ x.2.last = none ∧ x.2.base = zeroDigest)
/-- A snapshot follows at least one record, every field fits its width, own counts are positive, a live
    shard has a base (M1, L3), a parked one is `ShardM.init` plus an optional seal (its pays are then
    empty by the `last` conjunct), pays need a `last` and `rhead` is the registry head of `reg` (M2, kept
    by `pushM_fold_rhead`). -/
def LogStateM.wf (m : LogStateM) : Prop :=
  0 < m.len ∧ m.len - 1 < 256 ^ 8 ∧ m.head.length = digestBytes ∧ m.rhead.length = digestBytes ∧
    (rows m.reg).length < 256 ^ 4 ∧ (∀ x ∈ m.reg, rowFits x) ∧ m.shards.toList.length < 256 ^ 4 ∧
    (∀ x ∈ m.shards.toList, ShardM.fits x) ∧ (stateIn m).length < 256 ^ 4 ∧
    m.rhead = chainHead sha3 zeroDigest m.reg

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
  need (decide (0 < c))
  pure (e, c)
def pPay (k : Nat) : P (Nat × Bytes) := do
  let n ← rd payWidth
  let x ← pLp
  need (payKeyOk k n x)
  pure (n, x)
def pShard : P (Nat × ShardM) := do
  let k ← rd 4
  let own ← pAsc pOwn
  let sealed ← pSealed
  let live ← pBit
  let last ← pTip
  let base ← digest
  need (!live || base != zeroDigest)
  need (live || (own.isEmpty && last.isNone && base == zeroDigest))
  let pays ← pAsc (pPay k)
  need (last.isSome || pays.isEmpty)
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
  | some ((rhead, reg, rs), []) => do
    need (rhead == chainHead sha3 zeroDigest reg)
    pure ⟨idx + 1, head, reg, rhead, Std.TreeMap.ofList rs compare⟩
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

theorem pOwn_app (x : Nat × Nat) (h : x.1 < 256 ^ 8 ∧ 0 < x.2 ∧ x.2 < 256 ^ 8) (r : Bytes) :
    pOwn.run (ownRow x ++ r) = some (x, r) := by
  simp only [pOwn, ownRow, List.append_assoc, seq_app (rd_app h.1), seq_app (rd_app h.2.2),
    decide_eq_true h.2.1, need_seq] <;> rfl

theorem pPay_app (k : Nat) (x : Nat × Bytes)
    (h : x.1 < 256 ^ payWidth ∧ x.2.length < 256 ^ 4 ∧ payKeyOk k x.1 x.2 = true) (r : Bytes) :
    (pPay k).run (payRow x ++ r) = some (x, r) := by
  simp only [pPay, payRow, List.append_assoc, seq_app (rd_app h.1), seq_app (pLp_app _ h.2.1), h.2.2,
    need_seq] <;> rfl

theorem pShard_app (x : Nat × ShardM) (h : ShardM.fits x) (r : Bytes) :
    pShard.run (shardRow x ++ r) = some (x, r) := by
  obtain ⟨k, o, s, l, t, b, ps⟩ := x
  obtain ⟨hk, ho, hs, ht, hb, hz, hp, hn, hq⟩ := h
  have hz' : (!l || b != zeroDigest) = true := by cases l <;> simp_all
  have hn' : (t.isSome || ps.isEmpty) = true := by cases t <;> simp_all
  have hq' : (l || (o.isEmpty && t.isNone && b == zeroDigest)) = true := by
    cases l
    · obtain ⟨rfl, rfl, rfl⟩ := hq rfl; simp
    · rfl
  simp only [pShard, shardRow, List.append_assoc, seq_app (rd_app hk), seq_app (pAsc_app pOwn_app o ho),
    seq_app (pSealed_app s hs), seq_app (pBit_app l), seq_app (pTip_app t ht), seq_app (digest_app hb), hz', hq',
    need_seq, seq_app (pAsc_app (pPay_app k) ps hp), hn'] <;> rfl

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

/-! ## Inverse of the decoder (L2) -/

theorem pBit_run {b r : Bytes} {v : Bool} (h : pBit.run b = some (v, r)) : bitIn v ++ r = b := by
  obtain ⟨x, r1, h1, hm⟩ := Approval.bind_run h
  obtain ⟨hx, -⟩ := rd_run h1
  rcases x with _ | _ | x
  · obtain ⟨rfl, rfl⟩ := Approval.pure_run hm; exact hx
  · obtain ⟨rfl, rfl⟩ := Approval.pure_run hm; exact hx
  · simp [fail, StateT.run] at hm

theorem pSealed_run {b r : Bytes} {o : Option Bytes} (h : pSealed.run b = some (o, r)) :
    sealedIn o ++ r = b ∧ ∀ t, o = some t → t.length < 256 ^ 4 := by
  obtain ⟨x, r1, h1, hm⟩ := Approval.bind_run h
  obtain ⟨hx, -⟩ := rd_run h1
  rcases x with _ | _ | x
  · obtain ⟨rfl, rfl⟩ := Approval.pure_run hm
    exact ⟨hx, fun t ht => by cases ht⟩
  · obtain ⟨t, r2, h2, hm2⟩ := Approval.bind_run hm
    obtain ⟨rfl, rfl⟩ := Approval.pure_run hm2
    obtain ⟨ht, hl⟩ := pLp_run h2
    subst hx ht
    refine ⟨by simp [sealedIn], fun t' ht' => ?_⟩
    cases ht'
    exact hl
  · simp [fail, StateT.run] at hm

theorem pTip_run {b r : Bytes} {o : Option (Bytes × Bytes)} (h : pTip.run b = some (o, r)) :
    tipIn o ++ r = b ∧ ∀ s c, o = some (s, c) → s.length < 256 ^ 4 ∧ c.length < 256 ^ 4 := by
  obtain ⟨x, r1, h1, hm⟩ := Approval.bind_run h
  obtain ⟨hx, -⟩ := rd_run h1
  rcases x with _ | _ | x
  · obtain ⟨rfl, rfl⟩ := Approval.pure_run hm
    exact ⟨hx, fun s c hc => by cases hc⟩
  · obtain ⟨s, r2, h2, hm2⟩ := Approval.bind_run hm
    obtain ⟨c, r3, h3, hm3⟩ := Approval.bind_run hm2
    obtain ⟨rfl, rfl⟩ := Approval.pure_run hm3
    obtain ⟨hs, hl⟩ := pLp_run h2
    obtain ⟨hc, hl'⟩ := pLp_run h3
    subst hx hs hc
    refine ⟨by simp [tipIn], fun s' c' hh => ?_⟩
    cases hh
    exact ⟨hl, hl'⟩
  · simp [fail, StateT.run] at hm

theorem pOwn_run {b r : Bytes} {x : Nat × Nat} (h : pOwn.run b = some (x, r)) :
    ownRow x ++ r = b ∧ x.1 < 256 ^ 8 ∧ 0 < x.2 ∧ x.2 < 256 ^ 8 := by
  obtain ⟨e, r1, h1, h⟩ := Approval.bind_run h
  obtain ⟨c, r2, h2, h⟩ := Approval.bind_run h
  obtain ⟨u, r3, h3, h⟩ := Approval.bind_run h
  obtain ⟨rfl, rfl⟩ := Approval.pure_run h
  obtain ⟨he, we⟩ := rd_run h1
  obtain ⟨hc, wc⟩ := rd_run h2
  obtain ⟨ok, rfl⟩ := Approval.need_run h3
  subst he hc
  exact ⟨by simp [ownRow], we, of_decide_eq_true ok, wc⟩

theorem pPay_run {k : Nat} {b r : Bytes} {x : Nat × Bytes} (h : (pPay k).run b = some (x, r)) :
    payRow x ++ r = b ∧ x.1 < 256 ^ payWidth ∧ x.2.length < 256 ^ 4 ∧ payKeyOk k x.1 x.2 = true := by
  obtain ⟨n, r1, h1, h⟩ := Approval.bind_run h
  obtain ⟨y, r2, h2, h⟩ := Approval.bind_run h
  obtain ⟨u, r3, h3, h⟩ := Approval.bind_run h
  obtain ⟨rfl, rfl⟩ := Approval.pure_run h
  obtain ⟨hn, wn⟩ := rd_run h1
  obtain ⟨hy, wy⟩ := pLp_run h2
  obtain ⟨ok, rfl⟩ := Approval.need_run h3
  subst hn hy
  exact ⟨by simp [payRow], wn, wy, ok⟩

theorem pAsc_run {α : Type} {p : P (Nat × α)} {enc : Nat × α → Bytes} {Q : Nat × α → Prop}
    (hp : ∀ {b x r}, p.run b = some (x, r) → enc x ++ r = b ∧ Q x) {b r : Bytes} {xs : List (Nat × α)}
    (h : (pAsc p).run b = some (xs, r)) : ascIn enc xs ++ r = b ∧ ascFits Q xs := by
  obtain ⟨n, r1, h1, h⟩ := Approval.bind_run h
  obtain ⟨hn, wn⟩ := rd_run h1
  obtain ⟨ys, r2, h2, h⟩ := Approval.bind_run h
  obtain ⟨hx, hl, hq⟩ := Approval.many_run hp n h2
  obtain ⟨u, r3, h3, h4⟩ := Approval.bind_run h
  obtain ⟨rfl, rfl⟩ := Approval.pure_run h4
  obtain ⟨ok, rfl⟩ := Approval.need_run h3
  subst hn hx
  refine ⟨by simp [ascIn, hl], ?_⟩
  unfold ascFits
  exact ⟨by rw [hl]; exact wn, hq, ok⟩

theorem pShard_run {b r : Bytes} {x : Nat × ShardM} (h : pShard.run b = some (x, r)) :
    shardRow x ++ r = b ∧ ShardM.fits x := by
  obtain ⟨k, r1, h1, h⟩ := Approval.bind_run h
  obtain ⟨own, r2, h2, h⟩ := Approval.bind_run h
  obtain ⟨sealed, r3, h3, h⟩ := Approval.bind_run h
  obtain ⟨live, r4, h4, h⟩ := Approval.bind_run h
  obtain ⟨last, r5, h5, h⟩ := Approval.bind_run h
  obtain ⟨base, r6, h6, h⟩ := Approval.bind_run h
  obtain ⟨u1, r7, h7, h⟩ := Approval.bind_run h
  obtain ⟨u2, r8, h8, h⟩ := Approval.bind_run h
  obtain ⟨pays, r9, h9, h⟩ := Approval.bind_run h
  obtain ⟨u3, r10, h10, h⟩ := Approval.bind_run h
  obtain ⟨rfl, rfl⟩ := Approval.pure_run h
  obtain ⟨hk, wk⟩ := rd_run h1
  obtain ⟨ho, fo⟩ := pAsc_run (enc := ownRow) (Q := fun e => e.1 < 256 ^ 8 ∧ 0 < e.2 ∧ e.2 < 256 ^ 8) pOwn_run h2
  obtain ⟨hs, fs⟩ := pSealed_run h3
  have hl := pBit_run h4
  obtain ⟨ht, ft⟩ := pTip_run h5
  obtain ⟨hb, wb⟩ := digest_run h6
  obtain ⟨ok1, rfl⟩ := Approval.need_run h7
  obtain ⟨ok2, rfl⟩ := Approval.need_run h8
  obtain ⟨hp, fp⟩ := pAsc_run (enc := payRow)
    (Q := fun e => e.1 < 256 ^ payWidth ∧ e.2.length < 256 ^ 4 ∧ payKeyOk k e.1 e.2 = true) (pPay_run (k := k)) h9
  obtain ⟨ok3, rfl⟩ := Approval.need_run h10
  have f1 : live = true → base ≠ zeroDigest := by
    intro hlv hbz; subst hlv; simp [hbz] at ok1
  have f2 : last = none → pays = [] := by
    intro hn; subst hn; simpa using ok3
  have f3 : live = false → own = [] ∧ last = none ∧ base = zeroDigest := by
    intro hf; subst hf; simpa [and_assoc] using ok2
  subst hk ho hs hl ht hb hp
  refine ⟨by simp [shardRow], ?_⟩
  unfold ShardM.fits
  exact ⟨wk, fo, fs, ft, wb, f1, fp, f2, f3⟩

theorem pState_run {b r rh : Bytes} {reg : List Row} {rs : List (Nat × ShardM)}
    (h : pState.run b = some ((rh, reg, rs), r)) :
    rh ++ lp (rows reg) ++ ascIn shardRow rs ++ r = b ∧ rh.length = digestBytes ∧
      (rows reg).length < 256 ^ 4 ∧ (∀ x ∈ reg, rowFits x) ∧ ascFits ShardM.fits rs := by
  obtain ⟨d, r1, h1, h⟩ := Approval.bind_run h
  obtain ⟨g, r2, h2, h⟩ := Approval.bind_run h
  obtain ⟨s, r3, h3, h⟩ := Approval.bind_run h
  obtain ⟨hp, rfl⟩ := Approval.pure_run h
  obtain ⟨rfl, hp2⟩ := Prod.mk.inj hp
  obtain ⟨rfl, rfl⟩ := Prod.mk.inj hp2
  obtain ⟨hd, wd⟩ := digest_run h1
  obtain ⟨hg, wg, fg⟩ := pRows_run h2
  obtain ⟨hs, fs⟩ := pAsc_run (enc := shardRow) (Q := ShardM.fits) pShard_run h3
  subst hd hg hs
  exact ⟨by simp, wd, wg, fg, fs⟩

theorem ascKeys_pairwise {α : Type} : ∀ l : List (Nat × α), ascKeys l = true → l.Pairwise (fun a b => a.1 < b.1)
  | [], _ => List.Pairwise.nil
  | [_], _ => List.pairwise_singleton _ _
  | a :: b :: t, h => by
    simp only [ascKeys, Bool.and_eq_true, decide_eq_true_eq] at h
    have ih := ascKeys_pairwise (b :: t) h.2
    refine List.Pairwise.cons ?_ ih
    intro x hx
    rcases List.mem_cons.1 hx with rfl | hx
    · exact h.1
    · exact Nat.lt_trans h.1 ((List.pairwise_cons.1 ih).1 x hx)

/-- A strictly ascending row list is its own map's `toList` (the tree shape is not canonical, its
    in-order list is). -/
theorem toList_ofList_asc (rs : List (Nat × ShardM)) (h : rs.Pairwise (fun a b => a.1 < b.1)) :
    (Std.TreeMap.ofList rs compare).toList = rs := by
  have hord : (Std.TreeMap.ofList rs compare).toList.Pairwise (fun a b => a.1 < b.1) :=
    Std.TreeMap.ordered_keys_toList.imp (fun hh => Nat.compare_eq_lt.1 hh)
  have hne : ∀ {l : List (Nat × ShardM)}, l.Pairwise (fun a b => a.1 < b.1) → l.Nodup := fun hl =>
    hl.imp (fun hlt heq => by subst heq; exact Nat.lt_irrefl _ hlt)
  have hdist : rs.Pairwise (fun a b => ¬ compare a.1 b.1 = .eq) :=
    h.imp (fun hlt heq => by have := Nat.compare_eq_eq.1 heq; omega)
  refine List.Perm.eq_of_pairwise (le := fun a b => a.1 < b.1)
    (fun a b _ _ h1 h2 => absurd (Nat.lt_trans h1 h2) (Nat.lt_irrefl _)) hord h ?_
  refine (List.perm_ext_iff_of_nodup (hne hord) (hne h)).2 ?_
  rintro ⟨k, v⟩
  constructor
  · intro hmem
    have hg := Std.TreeMap.mem_toList_iff_getElem?_eq_some.1 hmem
    have hc : (rs.map Prod.fst).contains k = true := by
      refine Classical.byContradiction fun hnc => ?_
      have hn := Std.TreeMap.getElem?_ofList_of_contains_eq_false (cmp := compare) (l := rs) (k := k)
        (by simpa using hnc)
      rw [hn] at hg
      cases hg
    obtain ⟨⟨k', v'⟩, hm', hk'⟩ := List.mem_map.1 (List.contains_iff_mem.1 hc)
    have hg' := Std.TreeMap.getElem?_ofList_of_mem (cmp := compare) (k := k') (k' := k)
      (Nat.compare_eq_eq.2 hk') hdist hm'
    rw [hg] at hg'
    cases hg'
    cases hk'
    exact hm'
  · intro hmem
    exact Std.TreeMap.mem_toList_iff_getElem?_eq_some.2
      (Std.TreeMap.getElem?_ofList_of_mem (Nat.compare_eq_eq.2 rfl) hdist hmem)

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
  obtain ⟨h0, hi, hh, hr, hg, hf, hn, hs, hl, hc⟩ := h
  have hc' : (m.rhead == chainHead sha3 zeroDigest m.reg) = true := beq_iff_eq.2 hc
  have hrun : pSnap.run (snapIn m ++ []) = some (canon m, []) := by
    simp only [pSnap, snapIn, List.append_assoc, seq_app (p := expect snapTag) (fun _ => expect_app),
      seq_app (rd_app hi), seq_app (digest_app hh), seq_app (pLp_app _ hl), pState_app m hr hg hf hn hs, hc',
      need_seq, Nat.sub_add_cancel h0] <;> rfl
  rw [List.append_nil] at hrun
  simp only [decodeSnap, encodeSnap, List.toList_data_toByteArray, hrun]

/-- E4: a well-formed state decodes back to itself (up to the map's tree shape). -/
theorem E4_snap_roundtrip (m : LogStateM) (h : m.wf) : (decodeSnap (encodeSnap m)).map abs = some (abs m) := by
  rw [decode_encodeSnap m h, Option.map_some, abs_canon]

/-- L2 (S3b review, S3d review MED-1): accepted bytes decode to a well-formed state and are its
    encoding, so one state has one snapshot and one `snapDigest` (a malleable snapshot is refused), and
    E4b and E5 apply to every accepted snapshot. -/
theorem decodeSnap_canonical {b : ByteArray} {m : LogStateM} (h : decodeSnap b = some m) :
    m.wf ∧ encodeSnap m = b := by
  unfold decodeSnap at h
  cases hr : pSnap.run b.data.toList with
  | none => rw [hr] at h; exact absurd h (by simp)
  | some pr =>
    obtain ⟨m0, rest⟩ := pr
    cases rest with
    | cons x xs => rw [hr] at h; exact absurd h (by simp)
    | nil =>
      rw [hr] at h
      have h' : some m0 = some m := h
      cases h'
      obtain ⟨u1, r1, h1, hr⟩ := Approval.bind_run hr
      obtain ⟨idx, r2, h2, hr⟩ := Approval.bind_run hr
      obtain ⟨head, r3, h3, hr⟩ := Approval.bind_run hr
      obtain ⟨body, r4, h4, hr⟩ := Approval.bind_run hr
      rcases hst : pState.run body with _ | ⟨⟨rh, reg, rs⟩, rest⟩
      · rw [hst] at hr; simp [fail, StateT.run] at hr
      · cases rest with
        | cons x xs => rw [hst] at hr; simp [fail, StateT.run] at hr
        | nil =>
          rw [hst] at hr
          dsimp only at hr
          obtain ⟨u2, r5, h5, hr'⟩ := Approval.bind_run hr
          obtain ⟨rfl, rfl⟩ := Approval.pure_run hr'
          obtain ⟨ok, rfl⟩ := Approval.need_run h5
          have hx1 := Approval.expect_run h1
          obtain ⟨hx2, wi⟩ := rd_run h2
          obtain ⟨hx3, wh⟩ := digest_run h3
          obtain ⟨hx4, wb⟩ := pLp_run h4
          obtain ⟨hs, wrh, wg, fg, fa⟩ := pState_run hst
          have hshards : (Std.TreeMap.ofList rs compare).toList = rs :=
            toList_ofList_asc rs (ascKeys_pairwise rs fa.2.2)
          have hst' : stateIn ⟨idx + 1, head, reg, rh, Std.TreeMap.ofList rs compare⟩ = body := by
            simp only [stateIn, hshards]
            rw [List.append_nil] at hs
            exact hs
          refine ⟨?_, ?_⟩
          · unfold LogStateM.wf
            dsimp only
            refine ⟨Nat.succ_pos _, by simpa using wi, wh, wrh, wg, fg, ?_, ?_, ?_, beq_iff_eq.1 ok⟩
            · rw [hshards]; exact fa.1
            · rw [hshards]; exact fa.2.1
            · rw [hst']; exact wb
          · subst hx2 hx3 hx4
            refine ByteArray.ext (Array.toList_inj.1 ?_)
            rw [encodeSnap, List.toList_data_toByteArray, ← hx1]
            simp only [snapIn, hst', Nat.add_sub_cancel]
            simp

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
  | segment s =>
    have hd : snapDigest a = snapDigest b := by simp only [snapDigest, snapIn, stateIn, hl, hh, hg, hr, ht]
    simp only [stepM, hd]; split <;> simp [h]

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

/-- E5: from any start `m0` (`init` or a decoded snapshot), replaying the log tail from the snapshot of
    the folded prefix gives the full fold, when that prefix state is well formed (`hw`).  From `init`,
    `foldM_wf` gives `hw` only for cuts before the first RESUME, prefixes of SEALs and SEGMENTs (a BATCH
    needs a live shard, which only a RESUME makes).  Every state after a RESUME fails `hw` until the
    resume computes StateV2's base (module note, HIGH-2), so E5 says nothing about post-activation state;
    from a decoded `m0` it reaches a BATCH only on a live shard with a nonzero base, which no engine fold
    produces yet (S3e). -/
theorem E5_replay_from_snap (log : List ByteArray) (i : Nat) {m0 m : LogStateM}
    (h : (log.take i).foldlM pushM m0 = some m) (hw : m.wf) :
    ((decodeSnap (encodeSnap m)).bind fun m' => (log.drop i).foldlM pushM m').map abs =
      (log.foldlM pushM m0).map abs := by
  rw [decode_encodeSnap m hw, ← List.take_append_drop i log, List.foldlM_append, h,
    List.take_append_drop]
  exact foldM_abs _ (abs_canon m)

/-! ## Well-formedness of a push -/

theorem sha3_len (x : Bytes) : (sha3 x).length = digestBytes := by
  unfold sha3
  rw [← Semantic.sha3_512_eq]
  exact Semantic.sha3_512_toList_length _

theorem chainHead_len (l : List Row) : (chainHead sha3 zeroDigest l).length = digestBytes := by
  cases l with
  | nil => simp [chainHead, zeroDigest]
  | cons r l => obtain ⟨kd, i, s⟩ := r; simp only [chainHead, idRegStep]; exact sha3_len _

theorem stateIn_len (m : LogStateM) : (stateIn m).length =
    m.rhead.length + (4 + (rows m.reg).length) + (4 + (m.shards.toList.flatMap shardRow).length) := by
  simp only [stateIn, ascIn, lp, List.length_append, natBE_length]

theorem shardRow_len (x : Nat × ShardM) : 4 ≤ (shardRow x).length := by
  simp only [shardRow, List.length_append, natBE_length]; omega

theorem length_le_flatMap : ∀ l : List (Nat × ShardM), l.length ≤ (l.flatMap shardRow).length
  | [] => by simp
  | x :: l => by
    have h1 := length_le_flatMap l
    have h2 := shardRow_len x
    simp only [List.flatMap_cons, List.length_cons, List.length_append]
    omega

theorem row_le_flatMap {x : Nat × ShardM} {l : List (Nat × ShardM)} (h : x ∈ l) :
    (shardRow x).length ≤ (l.flatMap shardRow).length := by
  obtain ⟨a, b, rfl⟩ := List.append_of_mem h
  simp only [List.flatMap_append, List.flatMap_cons, List.length_append]
  omega

theorem sealed_lt_row {x : Nat × ShardM} {t : Bytes} (h : x.2.sealed = some t) :
    t.length < (shardRow x).length := by
  simp only [shardRow, sealedIn, h, lp, List.length_append, natBE_length]; omega

theorem sealed_bound {m : LogStateM} (hs : (stateIn m).length < 256 ^ 4) {x : Nat × ShardM}
    (hx : x ∈ m.shards.toList) : ∀ t, x.2.sealed = some t → t.length < 256 ^ 4 := by
  intro t h
  have h1 := sealed_lt_row h
  have h2 := row_le_flatMap hx
  have h3 := stateIn_len m
  omega

theorem ascKeys_nil {α : Type} : ascKeys ([] : List (Nat × α)) = true := rfl

theorem wf_facts {m : LogStateM} (hw : m.wf ∨ m = LogStateM.init) :
    m.rhead = chainHead sha3 zeroDigest m.reg ∧ (∀ x ∈ m.reg, rowFits x) ∧
      (∀ x ∈ m.shards.toList, ShardM.fits x) := by
  rcases hw with ⟨-, -, -, -, -, h2, -, h3, -, h1⟩ | rfl
  · exact ⟨h1, h2, h3⟩
  · refine ⟨rfl, fun x hx => by simp [LogStateM.init] at hx, fun x hx => ?_⟩
    obtain ⟨a, b⟩ := x
    rw [Std.TreeMap.mem_toList_iff_getElem?_eq_some] at hx
    simp [LogStateM.init] at hx

theorem shard_fits {m : LogStateM} (hsh : ∀ x ∈ m.shards.toList, ShardM.fits x) {k : Nat}
    (hk : k < 256 ^ 4) : ShardM.fits (k, m.shard k) := by
  unfold LogStateM.shard
  rw [Std.TreeMap.getD_eq_getD_getElem?]
  cases hg : m.shards[k]? with
  | none =>
    simp only [Option.getD_none]
    unfold ShardM.fits
    simp [ShardM.init, ascFits, ascKeys_nil, zeroDigest, digestBytes, hk]
  | some v =>
    simp only [Option.getD_some]
    exact hsh _ (Std.TreeMap.mem_toList_iff_getElem?_eq_some.2 hg)

theorem mem_insert_toList {t : Std.TreeMap Nat ShardM} {k : Nat} {v : ShardM} {x : Nat × ShardM}
    (h : x ∈ (t.insert k v).toList) : x = (k, v) ∨ x ∈ t.toList := by
  obtain ⟨a, b⟩ := x
  rw [Std.TreeMap.mem_toList_iff_getElem?_eq_some] at h
  simp only [Std.TreeMap.getElem?_insert, Nat.compare_eq_eq] at h
  split at h
  · next hk => left; cases h; subst hk; rfl
  · right; exact Std.TreeMap.mem_toList_iff_getElem?_eq_some.2 h

theorem wf_mk (m : LogStateM) (hl : 0 < m.len) (hn : m.len - 1 < 256 ^ 8) (hh : m.head.length = digestBytes)
    (hrh : m.rhead = chainHead sha3 zeroDigest m.reg) (hreg : ∀ x ∈ m.reg, rowFits x)
    (hsh : ∀ x ∈ m.shards.toList, ShardM.fits x) (hs : (stateIn m).length < 256 ^ 4) : m.wf := by
  have h1 := stateIn_len m
  have h2 := length_le_flatMap m.shards.toList
  have h3 : m.rhead.length = digestBytes := by rw [hrh]; exact chainHead_len _
  unfold LogStateM.wf
  exact ⟨hl, hn, hh, h3, by omega, hreg, by omega, hsh, hs, hrh⟩

/-- S3d review HIGH-2: a push from `init` or a well-formed state gives a well-formed state while it fits
    its widths (`stateIn` under `256 ^ 4` bytes; a batch grows `reg`, a seal tip is unbounded), except a
    RESUME, which leaves a live shard on the zero base until it computes StateV2's base.  `init` itself
    is not well formed (`len = 0`). -/
theorem pushM_wf {m m' : LogStateM} {b : ByteArray} (hw : m.wf ∨ m = LogStateM.init) (h : pushM m b = some m')
    (hr : ∀ e, decodeEntry3B b = some e → ∀ k p, e.body ≠ .resume k p) (hs : (stateIn m').length < 256 ^ 4) :
    m'.wf := by
  obtain ⟨e, s, hd, hidx, hprev, hstep, rfl⟩ := pushM_step h
  obtain ⟨hA, hB, hC⟩ := wf_facts hw
  obtain ⟨he1, he2, he3⟩ := (decodeEntry3B_canonical hd).1
  have hnr := hr e hd
  have hrh := stepM_rhead hA hstep
  have hs' : (stateIn s).length < 256 ^ 4 := hs
  have key : (∀ x ∈ s.reg, rowFits x) ∧ (∀ x ∈ s.shards.toList, ShardM.fits x) := by
    generalize e.body = bd at hstep hnr he3
    cases bd with
    | batch bt =>
      simp only [stepM] at hstep
      split at hstep
      · cases hstep
        refine ⟨fun x hx => ?_, hC⟩
        rcases List.mem_append.1 hx with hx | hx
        · exact (he3 : Batch3.wf bt).2.2.2.2.2.1 x hx
        · exact hB x hx
      · cases hstep
    | resume k p => exact (hnr _ _ rfl).elim
    | «seal» k t =>
      simp only [stepM] at hstep
      split at hstep
      · cases hstep
        refine ⟨hB, fun x hx => ?_⟩
        have hb := sealed_bound hs' hx
        have hx' : x ∈ (m.shards.insert k { m.shard k with sealed := some t }).toList := hx
        rcases mem_insert_toList hx' with rfl | hx0
        · have hk : k < 256 ^ 4 := he3
          obtain ⟨f1, f2, -, f4, f5, f6, f7, f8, f9⟩ := shard_fits hC hk
          exact ⟨f1, f2, hb, f4, f5, f6, f7, f8, f9⟩
        · exact hC x hx0
      · cases hstep
    | segment sg =>
      simp only [stepM] at hstep
      split at hstep
      · cases hstep; exact ⟨hB, hC⟩
      · cases hstep
  refine wf_mk _ (Nat.succ_pos _) ?_ (sha3_len _) hrh key.1 key.2 hs
  show m.len + 1 - 1 < 256 ^ 8
  rw [Nat.add_sub_cancel, ← hidx]
  exact he1

theorem flat_le_of_key {t : Std.TreeMap Nat ShardM} {k : Nat} {v : ShardM}
    (h : ∀ v0, t[k]? = some v0 → (shardRow (k, v0)).length ≤ (shardRow (k, v)).length) :
    ∀ G : List (Nat × ShardM), (∀ x ∈ G, x.1 = k ∧ t[k]? = some x.2) →
      G.Pairwise (fun a b => ¬ compare a.1 b.1 = .eq) → (G.flatMap shardRow).length ≤ (shardRow (k, v)).length
  | [], _, _ => by simp
  | [x], hk, _ => by
    obtain ⟨e1, e2⟩ := hk x (by simp)
    obtain ⟨a1, a2⟩ := x
    simp only at e1 e2
    subst e1
    simp only [List.flatMap_cons, List.flatMap_nil, List.append_nil]
    exact h _ e2
  | a :: b :: r, hk, hp => by
    exfalso
    have hab := (List.pairwise_cons.1 hp).1 b (by simp)
    have ha := hk a (by simp)
    have hb := hk b (by simp)
    exact hab (Nat.compare_eq_eq.2 (ha.1.trans hb.1.symm))

theorem flat_insert_ge (t : Std.TreeMap Nat ShardM) (k : Nat) (v : ShardM)
    (h : ∀ v0, t[k]? = some v0 → (shardRow (k, v0)).length ≤ (shardRow (k, v)).length) :
    (t.toList.flatMap shardRow).length ≤ ((t.insert k v).toList.flatMap shardRow).length := by
  have p1 := (Std.TreeMap.toList_insert_perm (t := t) (k := k) (v := v)).flatMap_right shardRow
  have p2 := (List.filter_append_perm (fun x : Nat × ShardM => decide (¬k == x.1)) t.toList).flatMap_right shardRow
  have hG := flat_le_of_key (t := t) h
    (t.toList.filter (fun x : Nat × ShardM => !decide (¬k == x.1)))
    (fun x hx => by
      obtain ⟨hx1, hx2⟩ := List.mem_filter.1 hx
      have hk : x.1 = k := (by simpa using hx2 : k = x.1).symm
      refine ⟨hk, ?_⟩
      have := Std.TreeMap.mem_toList_iff_getElem?_eq_some.1 (show (x.1, x.2) ∈ t.toList from hx1)
      rw [hk] at this
      exact this)
    ((Std.TreeMap.distinct_keys_toList (t := t)).sublist List.filter_sublist)
  have l1 := p1.length_eq
  have l2 := p2.length_eq
  simp only [List.flatMap_append, List.flatMap_cons, List.length_append] at l1 l2
  omega

theorem stepM_mono {m s : LogStateM} {bd : Body3} (hA : m.rhead = chainHead sha3 zeroDigest m.reg)
    (hnr : ∀ k p, bd ≠ .resume k p) (h : stepM m bd = some s) :
    (stateIn m).length ≤ (stateIn s).length := by
  have hB := stepM_rhead hA h
  have l1 : m.rhead.length = digestBytes := by rw [hA]; exact chainHead_len _
  have l2 : s.rhead.length = digestBytes := by rw [hB]; exact chainHead_len _
  cases bd with
  | batch bt =>
    simp only [stepM] at h
    split at h
    · cases h
      have hr : (rows (bt.regRows ++ m.reg)).length = (rows bt.regRows).length + (rows m.reg).length := by
        simp [rows, List.flatMap_append]
      rw [stateIn_len m, stateIn_len]
      dsimp only at l2 ⊢
      omega
    · cases h
  | resume k p => exact (hnr k p rfl).elim
  | «seal» k t =>
    simp only [stepM] at h
    split at h
    · next hc =>
      cases h
      have hge : ∀ v0, m.shards[k]? = some v0 →
          (shardRow (k, v0)).length ≤ (shardRow (k, { m.shard k with sealed := some t })).length := by
        intro v0 hv0
        have e : m.shard k = v0 := by
          unfold LogStateM.shard
          rw [Std.TreeMap.getD_eq_getD_getElem?, hv0]
          rfl
        have hsn : v0.sealed = none := by rw [← e]; exact hc.2.1
        rw [e]
        simp only [shardRow, sealedIn, hsn, lp, List.length_append, natBE_length]
        omega
      have := flat_insert_ge m.shards k { m.shard k with sealed := some t } hge
      rw [stateIn_len m, stateIn_len]
      dsimp only at l2 this ⊢
      omega
    · cases h
  | segment sg =>
    simp only [stepM] at h
    split at h
    · cases h; exact Nat.le_refl _
    · cases h

theorem pushM_mono {m m' : LogStateM} {b : ByteArray} (hA : m.rhead = chainHead sha3 zeroDigest m.reg)
    (hr : ∀ e, decodeEntry3B b = some e → ∀ k p, e.body ≠ .resume k p) (h : pushM m b = some m') :
    (stateIn m).length ≤ (stateIn m').length := by
  obtain ⟨e, s, hd, -, -, hstep, rfl⟩ := pushM_step h
  have := stepM_mono hA (hr e hd) hstep
  exact this

theorem foldM_mono (es : List ByteArray) : ∀ {m0 m : LogStateM},
    m0.rhead = chainHead sha3 zeroDigest m0.reg → es.foldlM pushM m0 = some m →
    (∀ b ∈ es, ∀ e, decodeEntry3B b = some e → ∀ k p, e.body ≠ .resume k p) →
    (stateIn m0).length ≤ (stateIn m).length := by
  induction es with
  | nil =>
    intro m0 m _ h _
    have h' : some m0 = some m := h
    cases h'
    exact Nat.le_refl _
  | cons x es ih =>
    intro m0 m hA h hr
    cases hp : pushM m0 x with
    | none => simp [List.foldlM_cons, hp] at h
    | some m1 =>
      rw [List.foldlM_cons, hp] at h
      have h1 : es.foldlM pushM m1 = some m := h
      have hA1 : m1.rhead = chainHead sha3 zeroDigest m1.reg := by
        obtain ⟨e, s, hd, -, -, hst, rfl⟩ := pushM_step hp
        have := stepM_rhead hA hst
        exact this
      exact Nat.le_trans (pushM_mono hA (hr x (List.mem_cons_self ..)) hp)
        (ih hA1 h1 (fun b hb => hr b (List.mem_cons_of_mem _ hb)))

/-- The chain `pushM_wf` needs for E5 (S3d review r2): a resume-free fold from `init` or a well-formed
    state whose result fits its widths ends well formed, or is empty.  Only the end state's width is
    assumed: a BATCH, SEAL or SEGMENT never shrinks `stateIn`, so every state on the way fits too. -/
theorem foldM_wf (es : List ByteArray) {m0 m : LogStateM} (hw : m0.wf ∨ m0 = LogStateM.init)
    (h : es.foldlM pushM m0 = some m)
    (hr : ∀ b ∈ es, ∀ e, decodeEntry3B b = some e → ∀ k p, e.body ≠ .resume k p)
    (hs : (stateIn m).length < 256 ^ 4) :
    m.wf ∨ (es = [] ∧ m = m0) := by
  induction es generalizing m0 with
  | nil =>
    have h' : some m0 = some m := h
    cases h'
    exact Or.inr ⟨rfl, rfl⟩
  | cons x es ih =>
    cases hp : pushM m0 x with
    | none => simp [List.foldlM_cons, hp] at h
    | some m1 =>
      rw [List.foldlM_cons, hp] at h
      have h1 : es.foldlM pushM m1 = some m := h
      have hr1 : ∀ b ∈ es, ∀ e, decodeEntry3B b = some e → ∀ k p, e.body ≠ .resume k p :=
        fun b hb => hr b (List.mem_cons_of_mem _ hb)
      obtain ⟨hA, -, -⟩ := wf_facts hw
      have hA1 : m1.rhead = chainHead sha3 zeroDigest m1.reg := by
        obtain ⟨e, s, hd, -, -, hst, rfl⟩ := pushM_step hp
        have := stepM_rhead hA hst
        exact this
      have hs1 : (stateIn m1).length < 256 ^ 4 := Nat.lt_of_le_of_lt (foldM_mono es hA1 h1 hr1) hs
      have hw1 : m1.wf := pushM_wf hw hp (hr x (List.mem_cons_self ..)) hs1
      rcases ih (Or.inl hw1) h1 hr1 with h2 | ⟨-, h3⟩
      · exact Or.inl h2
      · rw [h3]; exact Or.inl hw1

/-- L4 (S3b review, restated by S3d review HIGH-1): the per-entry fold of a run of BATCH entries is one
    registry update, the batches' rows newest batch first ahead of `reg` and `rhead` moved over exactly
    those rows; every batched shard is live and a shard no batch names is untouched.  It rules out a
    fold that drops, reorders or replays a batch's rows.  It is not a custody property: the engine batch
    does not yet run StateV2 `payStep` over its leaves (nor set `last`, `base`, `own`), so two ALLOW
    leaves on one payment are both accepted (open, S3e).  `hb` is batch-only (no SEGMENT between), so
    this is not E5, and the `fold_batch_2x2{,_mid}` vectors (from a hand-built live snapshot) are
    pre-S3e pins, not E5 evidence. -/
theorem foldM_batches (es : List ByteArray) (bs : List Batch3) {m m' : LogStateM}
    (hb : (es.mapM decodeEntry3B).map (·.map Entry3.body) = some (bs.map Body3.batch))
    (h : es.foldlM pushM m = some m') :
    m'.reg = bs.reverse.flatMap Batch3.regRows ++ m.reg ∧
      m'.rhead = chainHead sha3 m.rhead (bs.reverse.flatMap Batch3.regRows) ∧
      (∀ b ∈ bs, (m.shard b.shard).live = true) ∧ ∀ k, k ∉ bs.map Batch3.shard → m'.shard k = m.shard k := by
  induction es generalizing bs m with
  | nil =>
    have h' : some m = some m' := h
    cases h'
    cases bs with
    | nil => exact ⟨rfl, rfl, (fun _ hb => nomatch hb), (fun _ _ => rfl)⟩
    | cons b bs => simp at hb
  | cons x es ih =>
    cases hp : pushM m x with
    | none => simp [List.foldlM_cons, hp] at h
    | some m1 =>
      rw [List.foldlM_cons, hp] at h
      have h1 : es.foldlM pushM m1 = some m' := h
      obtain ⟨e, s, hd, -, -, hs, rfl⟩ := pushM_step hp
      cases hm : es.mapM decodeEntry3B with
      | none => simp [List.mapM_cons, hd, hm] at hb
      | some ys =>
        cases bs with
        | nil => simp [List.mapM_cons, hd, hm] at hb
        | cons b0 bs =>
          simp [List.mapM_cons, hd, hm] at hb
          obtain ⟨hb0, hb1⟩ := hb
          have hb1' : (es.mapM decodeEntry3B).map (·.map Entry3.body) = some (bs.map Body3.batch) := by
            rw [hm]; simp [hb1]
          rw [hb0] at hs
          simp only [stepM] at hs
          split at hs
          next hlive =>
            have hs' : some { m with reg := b0.regRows ++ m.reg, rhead := chainHead sha3 m.rhead b0.regRows } =
                some s := hs
            cases hs'
            obtain ⟨hreg, hrh, hl, hsh⟩ := ih bs hb1' h1
            refine ⟨?_, ?_, ?_, ?_⟩
            · rw [hreg]; simp
            · have e : (b0 :: bs).reverse.flatMap Batch3.regRows = bs.reverse.flatMap Batch3.regRows ++ b0.regRows := by
                simp
              rw [hrh, e, chainHead_app]
              try rfl
            · intro b hbm
              rcases List.mem_cons.1 hbm with rfl | hbm
              · exact hlive
              · exact hl b hbm
            · intro k hk
              exact hsh k (fun hh => hk (List.mem_cons_of_mem _ hh))
          next => cases hs

end BlindLedger.Gate.Engine
