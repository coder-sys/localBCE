import Std.Data.TreeMap
import BlindLedger.Gate.Rules.ShardRun
import BlindLedger.Gate.CheckpointV2Theorems
import BlindLedger.Gate.Verify

/-! ENGINE-0 S1 (design `engine0-design-20261013` sections 1, 2, 7, L4): the v3 tenant-log entry
    codec, the log state maps and `pushM`.  Synthetic, nonpayment; moves no money.

    Fixed widths (L4): kind 1, idx 8, prev 64, shard 4, length prefixes 4, a registry row
    1 + 129 + 4 = 134 bytes.  Domain tag `RR/GATE/TENANT-LOG/v3\0`.

    `stepM` keeps only the S1 guards (live shard for a batch, no double resume, seal once on a
    parked shard).  They are necessary, not sufficient: custody, permit decode, activation,
    resume reserve rows, seal-of-v1-only and `last` are owed to S3. -/

namespace BlindLedger.Gate.Engine

open BlindLedger.Gate BlindLedger.Gate.Rules

/-! ## Encoder -/

def tag3 : Bytes := "RR/GATE/TENANT-LOG/v3".toUTF8.toList ++ [0]
def regRowWidth : Nat := 134

def regRow : Row → Bytes
  | (k, i, s) => natBE 1 k ++ natBE 129 i ++ natBE 4 s
def rows (rs : List Row) : Bytes := rs.flatMap regRow
def lp (x : Bytes) : Bytes := natBE 4 x.length ++ x
def lps (xs : List Bytes) : Bytes := natBE 4 xs.length ++ xs.flatMap lp
def lpsFit (xs : List Bytes) : Prop := xs.length < 256 ^ 4 ∧ ∀ x ∈ xs, x.length < 256 ^ 4

structure Batch3 where
  shard : Nat
  header : Bytes
  manifest : Bytes
  reqs : List Bytes
  regRows : List Row
  leaves : List Bytes

structure Segment3 where
  firstIdx : Nat
  lastIdx : Nat
  lastEntry : Bytes
  sha3Seg : Bytes
  sha512Seg : Bytes
  snap : Bytes

inductive Body3
  | batch (b : Batch3)
  | resume (shard : Nat) (permit : Bytes)
  | seal (shard : Nat) (tip : Bytes)
  | segment (s : Segment3)

structure Entry3 where
  idx : Nat
  prev : Bytes
  body : Body3

def batchIn (b : Batch3) : Bytes :=
  natBE 4 b.shard ++ lp b.header ++ lp b.manifest ++ lps b.reqs ++ lp (rows b.regRows) ++ lps b.leaves
def segIn (s : Segment3) : Bytes :=
  natBE 8 s.firstIdx ++ natBE 8 s.lastIdx ++ s.lastEntry ++ s.sha3Seg ++ s.sha512Seg ++ s.snap

def bodyIn3 : Body3 → Bytes
  | .batch b => natBE 1 0 ++ batchIn b
  | .resume k p => natBE 1 1 ++ natBE 4 k ++ p
  | .seal k t => natBE 1 2 ++ natBE 4 k ++ t
  | .segment s => natBE 1 3 ++ segIn s

def entryIn3 (e : Entry3) : Bytes := tag3 ++ natBE 8 e.idx ++ e.prev ++ bodyIn3 e.body
def entryDigest3 (e : Entry3) : Bytes := sha3 (entryIn3 e)
def encodeEntry3 (e : Entry3) : ByteArray := (entryIn3 e).toByteArray

/-- Every field fits its fixed width (otherwise `natBE` truncates and the encoding is lossy). -/
def Batch3.wf (b : Batch3) : Prop :=
  b.shard < 256 ^ 4 ∧ b.header.length < 256 ^ 4 ∧ b.manifest.length < 256 ^ 4 ∧ lpsFit b.reqs ∧
    (rows b.regRows).length < 256 ^ 4 ∧ (∀ r ∈ b.regRows, rowFits r) ∧ lpsFit b.leaves
def Segment3.wf (s : Segment3) : Prop :=
  s.firstIdx < 256 ^ 8 ∧ s.lastIdx < 256 ^ 8 ∧ s.lastEntry.length = digestBytes ∧
    s.sha3Seg.length = digestBytes ∧ s.sha512Seg.length = digestBytes ∧ s.snap.length = digestBytes
def Body3.wf : Body3 → Prop
  | .batch b => b.wf
  | .resume k _ => k < 256 ^ 4
  | .seal k _ => k < 256 ^ 4
  | .segment s => s.wf
def Entry3.wf (e : Entry3) : Prop := e.idx < 256 ^ 8 ∧ e.prev.length = digestBytes ∧ e.body.wf

/-! ## Decoder (the spec parser monad `P`) -/

def rd (w : Nat) : P Nat := do pure (beNat (← take w))
def rest : P Bytes := fun b => some (b, [])
def pLp : P Bytes := do take (← rd 4)
def pList : P (List Bytes) := do many pLp (← rd 4)
def pRow : P Row := do
  let k ← rd 1
  let i ← rd 129
  let s ← rd 4
  pure (k, i, s)
def pRows : P (List Row) := do
  let n ← rd 4
  need (n % regRowWidth == 0)
  many pRow (n / regRowWidth)
def pBatch : P Batch3 := do
  let shard ← rd 4
  let header ← pLp
  let manifest ← pLp
  let reqs ← pList
  let regRows ← pRows
  let leaves ← pList
  pure { shard, header, manifest, reqs, regRows, leaves }
def pSeg : P Segment3 := do
  let firstIdx ← rd 8
  let lastIdx ← rd 8
  let lastEntry ← digest
  let sha3Seg ← digest
  let sha512Seg ← digest
  let snap ← digest
  pure { firstIdx, lastIdx, lastEntry, sha3Seg, sha512Seg, snap }
def pBody : P Body3 := do
  match ← rd 1 with
  | 0 => do let b ← pBatch; pure (.batch b)
  | 1 => do let k ← rd 4; let p ← rest; pure (.resume k p)
  | 2 => do let k ← rd 4; let t ← rest; pure (.seal k t)
  | 3 => do let s ← pSeg; pure (.segment s)
  | _ => fail
def pEntry3 : P Entry3 := do
  expect tag3
  let idx ← rd 8
  let prev ← digest
  let body ← pBody
  pure { idx, prev, body }

def decodeEntry3 (x : Bytes) : Option (Entry3 × Bytes) := pEntry3.run x
/-- Refuses trailing bytes. -/
def decodeEntry3B (b : ByteArray) : Option Entry3 :=
  match decodeEntry3 b.data.toList with
  | some (e, []) => some e
  | _ => none

/-! ## Round trip -/

theorem run_seq {α β : Type} {p : P α} {f : α → P β} {b m : Bytes} {a : α}
    (h : p.run b = some (a, m)) : (p >>= f).run b = (f a).run m := by
  rw [StateT.run_bind, h]; rfl

theorem seq_app {α β : Type} {p : P α} {e : Bytes} {a : α} (h : ∀ r, p.run (e ++ r) = some (a, r))
    (r : Bytes) (f : α → P β) : (p >>= f).run (e ++ r) = (f a).run r := run_seq (h r)

theorem need_seq {β : Type} (b : Bytes) (f : Unit → P β) : (need true >>= f).run b = (f ()).run b :=
  run_seq (need_true b)

theorem rest_seq {β : Type} (b : Bytes) (f : Bytes → P β) : (rest >>= f).run b = (f b).run [] :=
  run_seq rfl

theorem rd_app {w v : Nat} (hv : v < 256 ^ w) (r : Bytes) : (rd w).run (natBE w v ++ r) = some (v, r) := by
  simp only [rd, run_seq (take_app (r := r) (natBE_length w v)), beNat_natBE w v hv] <;> rfl

theorem digest_app {x : Bytes} (h : x.length = digestBytes) (r : Bytes) :
    digest.run (x ++ r) = some (x, r) := take_app h

theorem many_app {α : Type} {p : P α} {enc : α → Bytes} {Q : α → Prop}
    (hp : ∀ x, Q x → ∀ r, p.run (enc x ++ r) = some (x, r)) :
    ∀ xs : List α, (∀ x ∈ xs, Q x) → ∀ r, (many p xs.length).run (xs.flatMap enc ++ r) = some (xs, r)
  | [], _, _ => rfl
  | x :: xs, h, r => by
    simp only [List.flatMap_cons, List.append_assoc, List.length_cons, many,
      seq_app (hp x (h x List.mem_cons_self)),
      seq_app (many_app hp xs (fun y hy => h y (List.mem_cons_of_mem _ hy)))] <;> rfl

theorem pLp_app (x : Bytes) (h : x.length < 256 ^ 4) (r : Bytes) : pLp.run (lp x ++ r) = some (x, r) := by
  simp only [pLp, lp, List.append_assoc, seq_app (rd_app h), take_app (a := x) (r := r) rfl] <;> rfl

theorem pList_app (xs : List Bytes) (h : lpsFit xs) (r : Bytes) : pList.run (lps xs ++ r) = some (xs, r) := by
  obtain ⟨hn, hx⟩ := h
  simp only [pList, lps, List.append_assoc, seq_app (rd_app hn)]
  exact many_app pLp_app xs hx r

theorem regRow_len (x : Row) : (regRow x).length = regRowWidth := by
  obtain ⟨k, i, s⟩ := x
  simp [regRow, natBE_length, regRowWidth]

theorem rows_len : ∀ rs : List Row, (rows rs).length = regRowWidth * rs.length
  | [] => by simp [rows]
  | x :: rs => by
    have h1 : rows (x :: rs) = regRow x ++ rows rs := by simp [rows]
    rw [h1, List.length_append, rows_len rs, regRow_len, List.length_cons]
    unfold regRowWidth
    omega

theorem pRow_app (x : Row) (h : rowFits x) (r : Bytes) : pRow.run (regRow x ++ r) = some (x, r) := by
  obtain ⟨k, i, s⟩ := x
  obtain ⟨hk, hi, hs⟩ := h
  have hk : k < 256 ^ 1 := hk
  have hi : i < 256 ^ 129 := hi
  have hs : s < 256 ^ 4 := hs
  simp only [pRow, regRow, List.append_assoc, seq_app (rd_app hk), seq_app (rd_app hi),
    seq_app (rd_app hs)] <;> rfl

theorem pRows_app (rs : List Row) (hn : (rows rs).length < 256 ^ 4) (h : ∀ x ∈ rs, rowFits x)
    (r : Bytes) : pRows.run (lp (rows rs) ++ r) = some (rs, r) := by
  have hl := rows_len rs
  have hm : (regRowWidth * rs.length % regRowWidth == 0) = true := by simp
  have hd : regRowWidth * rs.length / regRowWidth = rs.length :=
    Nat.mul_div_cancel_left rs.length (by unfold regRowWidth; decide)
  unfold lp
  rw [List.append_assoc, hl]
  rw [hl] at hn
  simp only [pRows, seq_app (rd_app hn), hm, need_seq, hd]
  exact many_app pRow_app rs h r

theorem pBatch_app (b : Batch3) (h : b.wf) (r : Bytes) : pBatch.run (batchIn b ++ r) = some (b, r) := by
  obtain ⟨hs, hh, hm, hq, hn, hr, hl⟩ := h
  simp only [pBatch, batchIn, List.append_assoc, seq_app (rd_app hs), seq_app (pLp_app _ hh),
    seq_app (pLp_app _ hm), seq_app (pList_app _ hq), seq_app (pRows_app _ hn hr),
    seq_app (pList_app _ hl)] <;> rfl

theorem pSeg_app (s : Segment3) (h : s.wf) (r : Bytes) : pSeg.run (segIn s ++ r) = some (s, r) := by
  obtain ⟨h1, h2, h3, h4, h5, h6⟩ := h
  simp only [pSeg, segIn, List.append_assoc, seq_app (rd_app h1), seq_app (rd_app h2),
    seq_app (digest_app h3), seq_app (digest_app h4), seq_app (digest_app h5),
    seq_app (digest_app h6)] <;> rfl

theorem pBody_app : ∀ b : Body3, b.wf → pBody.run (bodyIn3 b ++ []) = some (b, [])
  | .batch b, h => by
    simp only [pBody, bodyIn3, List.append_assoc, seq_app (rd_app (w := 1) (v := 0) (by decide)),
      seq_app (pBatch_app b h)] <;> rfl
  | .resume k p, h => by
    have h : k < 256 ^ 4 := h
    simp only [pBody, bodyIn3, List.append_assoc, seq_app (rd_app (w := 1) (v := 1) (by decide)),
      seq_app (rd_app h), rest_seq, List.append_nil] <;> rfl
  | .seal k t, h => by
    have h : k < 256 ^ 4 := h
    simp only [pBody, bodyIn3, List.append_assoc, seq_app (rd_app (w := 1) (v := 2) (by decide)),
      seq_app (rd_app h), rest_seq, List.append_nil] <;> rfl
  | .segment s, h => by
    simp only [pBody, bodyIn3, List.append_assoc, seq_app (rd_app (w := 1) (v := 3) (by decide)),
      seq_app (pSeg_app s h)] <;> rfl

/-- E1: a well-formed entry decodes back to itself with nothing left over. -/
theorem E1_entry3_roundtrip (e : Entry3) (h : e.wf) : decodeEntry3 (entryIn3 e) = some (e, []) := by
  obtain ⟨hi, hp, hb⟩ := h
  rw [← List.append_nil (entryIn3 e)]
  simp only [decodeEntry3, entryIn3, pEntry3, List.append_assoc,
    seq_app (p := expect tag3) (fun _ => expect_app), seq_app (rd_app hi), seq_app (digest_app hp),
    run_seq (pBody_app _ hb)] <;> rfl

/-- E2: the encoding is injective on well-formed entries (one entry per digest preimage). -/
theorem E2_entryIn3_inj {a b : Entry3} (ha : a.wf) (hb : b.wf) (h : entryIn3 a = entryIn3 b) : a = b := by
  have h1 := E1_entry3_roundtrip a ha
  rw [h, E1_entry3_roundtrip b hb] at h1
  exact (Prod.mk.inj (Option.some.inj h1)).1.symm

theorem decode_encode (e : Entry3) (h : e.wf) : decodeEntry3B (encodeEntry3 e) = some e := by
  simp only [decodeEntry3B, encodeEntry3, List.toList_data_toByteArray, E1_entry3_roundtrip e h] <;> rfl

/-! ## Log state and push -/

structure ShardM where
  sealed : Option Bytes
  live : Bool

def ShardM.init : ShardM := ⟨none, false⟩

structure LogStateM where
  len : Nat
  head : Bytes
  rhead : Bytes
  shards : Std.TreeMap Nat ShardM

def LogStateM.init : LogStateM := ⟨0, zeroDigest, zeroDigest, ∅⟩
def LogStateM.shard (m : LogStateM) (k : Nat) : ShardM := m.shards.getD k ShardM.init

def stepM (m : LogStateM) : Body3 → Option LogStateM
  | .batch b =>
    if (m.shard b.shard).live then some { m with rhead := chainHead sha3 m.rhead b.regRows } else none
  | .resume k _ =>
    if (m.shard k).live then none
    else some { m with shards := m.shards.insert k { m.shard k with live := true } }
  | .seal k t =>
    if (m.shard k).live = false ∧ (m.shard k).sealed = none then
      some { m with shards := m.shards.insert k { m.shard k with sealed := some t } }
    else none
  | .segment _ => some m

/-- Appends `e` only at the next index and only on the current head (no replay, no fork). -/
def pushM (m : LogStateM) (e : Entry3) : Option LogStateM :=
  if e.idx = m.len ∧ e.prev = m.head then
    (stepM m e.body).map fun s => { s with len := m.len + 1, head := entryDigest3 e }
  else none

/-- Append-only on shards: a seal is never rewritten and a live shard never parks again. -/
def Keeps (m m' : LogStateM) : Prop :=
  ∀ k, ((m.shard k).sealed.isSome → (m'.shard k).sealed = (m.shard k).sealed) ∧
    ((m.shard k).live → (m'.shard k).live)

theorem Keeps.refl (m : LogStateM) : Keeps m m := fun _ => ⟨fun _ => rfl, id⟩

theorem Keeps.trans {a b c : LogStateM} (h1 : Keeps a b) (h2 : Keeps b c) : Keeps a c := fun k =>
  ⟨fun hs => by rw [(h2 k).1 (by rw [(h1 k).1 hs]; exact hs), (h1 k).1 hs],
   fun hl => (h2 k).2 ((h1 k).2 hl)⟩

theorem shard_insert (m : LogStateM) (k a : Nat) (s : ShardM) :
    ({ m with shards := m.shards.insert k s } : LogStateM).shard a = if k = a then s else m.shard a := by
  simp only [LogStateM.shard, Std.TreeMap.getD_insert, Nat.compare_eq_eq]

theorem stepM_keep {m m' : LogStateM} {b : Body3} (h : stepM m b = some m') : Keeps m m' := by
  intro a
  cases b with
  | batch bt =>
    simp only [stepM] at h
    split at h
    · cases h; exact ⟨fun _ => rfl, id⟩
    · cases h
  | resume k p =>
    simp only [stepM] at h
    split at h
    · cases h
    · cases h
      rw [shard_insert]
      by_cases hka : k = a
      · rw [if_pos hka]; subst hka; exact ⟨fun _ => rfl, fun _ => rfl⟩
      · rw [if_neg hka]; exact ⟨fun _ => rfl, id⟩
  | «seal» k t =>
    simp only [stepM] at h
    split at h
    next hc =>
      cases h
      rw [shard_insert]
      by_cases hka : k = a
      · rw [if_pos hka]; subst hka
        refine ⟨fun hs => ?_, id⟩
        rw [hc.2] at hs
        simp at hs
      · rw [if_neg hka]; exact ⟨fun _ => rfl, id⟩
    next => cases h
  | segment s =>
    simp only [stepM] at h
    cases h; exact ⟨fun _ => rfl, id⟩

/-- A push links to the current head at the next index, grows the log by one, moves the head
    to the entry digest and keeps every shard seal and live mark. -/
theorem pushM_chain {m m' : LogStateM} {e : Entry3} (h : pushM m e = some m') :
    e.idx = m.len ∧ e.prev = m.head ∧ m'.len = m.len + 1 ∧ m'.head = entryDigest3 e ∧ Keeps m m' := by
  unfold pushM at h
  split at h
  next hc =>
    cases hs : stepM m e.body with
    | none => rw [hs] at h; cases h
    | some s =>
      rw [hs] at h
      have h' : some { s with len := m.len + 1, head := entryDigest3 e } = some m' := h
      cases h'
      have hk : Keeps m s := stepM_keep hs
      exact ⟨hc.1, hc.2, rfl, rfl, hk⟩
  next => cases h

/-- Folding pushes over a list: the log grows by exactly the list length, append-only. -/
theorem pushM_fold (es : List Entry3) : ∀ {m m' : LogStateM}, es.foldlM pushM m = some m' →
    m'.len = m.len + es.length ∧ Keeps m m' := by
  induction es with
  | nil =>
    intro m m' h
    have h' : some m = some m' := h
    cases h'
    exact ⟨rfl, Keeps.refl _⟩
  | cons e es ih =>
    intro m m' h
    cases h1 : pushM m e with
    | none => simp [List.foldlM_cons, h1] at h
    | some m1 =>
      rw [List.foldlM_cons, h1] at h
      obtain ⟨hl, hk⟩ := ih (h : es.foldlM pushM m1 = some m')
      obtain ⟨-, -, hl1, -, hk1⟩ := pushM_chain h1
      exact ⟨by rw [hl, hl1, List.length_cons]; omega, hk1.trans hk⟩

end BlindLedger.Gate.Engine
