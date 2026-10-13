import Std.Data.TreeMap
import BlindLedger.Gate.Rules.ShardRun
import BlindLedger.Gate.CheckpointV2Theorems
import BlindLedger.Gate.Verify
import BlindLedger.Gate.ApprovalLaws

/-! ENGINE-0 S1 (design `engine0-design-20261013` sections 1, 2, 7, L4): the v3 tenant-log entry
    codec, the log state maps and `pushM`.  Synthetic, nonpayment; moves no money.

    Fixed widths (L4): kind 1, idx 8, prev 64, shard 4, length prefixes 4, a registry row
    1 + 129 + 4 = 134 bytes.  Domain tag `RR/GATE/TENANT-LOG/v3\0`.

    `stepM` keeps the S1 guards (live shard for a batch, no double resume, seal once on a parked
    shard) and StateV2 `push`'s resume tip rule (S3 review HIGH-1: a resume needs a parked shard and
    a permit tip naming its seal, or no tip when unsealed; it sets live and `last`).  A batch appends
    its registry rows to `reg`.  The shard also carries `own`, `base` and `pays`, the custody state
    StateV2 `push` reads, so a snapshot holds it; `stepM` does not yet write them (StateV2's resume base
    needs pins and the permit sets, owed to `push3`; until then a snapshot refuses a live shard on the
    zero base, which StateV2 never reaches, S3b review M1).  A segment steps only when its `snap` is the
    `snapDigest` of the state before it (M3); its index and segment hashes are owed to S3c.  The guards are
    necessary, not sufficient: custody, the permit's rel/unr sets, activation, resume reserve rows
    and seal-of-v1-only are owed to `push3`. -/

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
/-- Exactly one entry: bytes after a BATCH or SEGMENT body are refused; a RESUME permit and a
    SEAL tip run to the end of the input, so bytes after them are part of the permit or tip. -/
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

/-! ## Decoder accept set: only canonical encodings of well-formed entries -/

theorem beNat_lt (bs : Bytes) : beNat bs < 256 ^ bs.length := by
  suffices h : ∀ (bs : Bytes) (acc : Nat),
      bs.foldl (fun a x => a * 256 + x.toNat) acc < (acc + 1) * 256 ^ bs.length by
    simpa [beNat] using h bs 0
  intro bs
  induction bs with
  | nil => intro acc; simp
  | cons x bs ih =>
    intro acc
    have hx : x.toNat < 256 := UInt8.toNat_lt x
    have h1 : acc * 256 + x.toNat + 1 ≤ (acc + 1) * 256 := by omega
    have h2 : (acc * 256 + x.toNat + 1) * 256 ^ bs.length ≤ (acc + 1) * 256 ^ (x :: bs).length := by
      simp only [List.length_cons, Nat.pow_succ]
      calc _ ≤ ((acc + 1) * 256) * 256 ^ bs.length := Nat.mul_le_mul_right _ h1
        _ = _ := by rw [Nat.mul_assoc, Nat.mul_comm 256 (256 ^ bs.length)]
    exact Nat.lt_of_lt_of_le (ih (acc * 256 + x.toNat)) h2

theorem rd_run {w v : Nat} {b r : Bytes} (h : (rd w).run b = some (v, r)) : natBE w v ++ r = b ∧ v < 256 ^ w := by
  obtain ⟨x, r1, h1, h⟩ := Approval.bind_run h
  obtain ⟨hx, hl⟩ := Approval.take_run h1
  obtain ⟨rfl, rfl⟩ := Approval.pure_run h
  subst hl hx
  exact ⟨by rw [Approval.natBE_beNat], beNat_lt x⟩

theorem digest_run {b x r : Bytes} (h : digest.run b = some (x, r)) : x ++ r = b ∧ x.length = digestBytes :=
  Approval.take_run h

theorem rest_run {b x r : Bytes} (h : rest.run b = some (x, r)) : x = b ∧ r = [] := by
  change some (b, []) = some (x, r) at h
  cases h; exact ⟨rfl, rfl⟩

theorem pLp_run {b x r : Bytes} (h : pLp.run b = some (x, r)) : lp x ++ r = b ∧ x.length < 256 ^ 4 := by
  obtain ⟨n, r1, h1, h⟩ := Approval.bind_run h
  obtain ⟨hn, hb⟩ := rd_run h1
  obtain ⟨hx, hl⟩ := Approval.take_run h
  subst hl hx hn
  exact ⟨by simp [lp], hb⟩

theorem pList_run {b r : Bytes} {xs : List Bytes} (h : pList.run b = some (xs, r)) : lps xs ++ r = b ∧ lpsFit xs := by
  obtain ⟨n, r1, h1, h⟩ := Approval.bind_run h
  obtain ⟨hn, hb⟩ := rd_run h1
  obtain ⟨hx, hl, hq⟩ := Approval.many_run (e := lp) (Q := fun x : Bytes => x.length < 256 ^ 4) pLp_run n h
  subst hl hx hn
  exact ⟨by simp [lps], hb, hq⟩

theorem pRow_run {b r : Bytes} {x : Row} (h : pRow.run b = some (x, r)) : regRow x ++ r = b ∧ rowFits x := by
  obtain ⟨k, r1, h1, h⟩ := Approval.bind_run h
  obtain ⟨i, r2, h2, h⟩ := Approval.bind_run h
  obtain ⟨s, r3, h3, h⟩ := Approval.bind_run h
  obtain ⟨rfl, rfl⟩ := Approval.pure_run h
  obtain ⟨e1, w1⟩ := rd_run h1
  obtain ⟨e2, w2⟩ := rd_run h2
  obtain ⟨e3, w3⟩ := rd_run h3
  subst e3 e2 e1
  exact ⟨by simp [regRow], w1, w2, w3⟩

theorem pRows_run {b r : Bytes} {rs : List Row} (h : pRows.run b = some (rs, r)) :
    lp (rows rs) ++ r = b ∧ (rows rs).length < 256 ^ 4 ∧ ∀ x ∈ rs, rowFits x := by
  obtain ⟨n, r1, h1, h⟩ := Approval.bind_run h
  obtain ⟨hn, hb⟩ := rd_run h1
  obtain ⟨u, r2, h2, hm⟩ := Approval.bind_run h
  obtain ⟨ok, rfl⟩ := Approval.need_run h2
  obtain ⟨hx, hl, hq⟩ := Approval.many_run (e := regRow) (Q := rowFits) pRow_run _ hm
  have hlen : (rows rs).length = n := by
    rw [rows_len, hl]
    simp only [regRowWidth, beq_iff_eq] at ok ⊢
    omega
  refine ⟨?_, by rw [hlen]; exact hb, hq⟩
  rw [lp, hlen, ← hn, ← hx]
  simp [rows]

theorem pBatch_run {b r : Bytes} {x : Batch3} (h : pBatch.run b = some (x, r)) : batchIn x ++ r = b ∧ x.wf := by
  obtain ⟨s, r1, h1, h⟩ := Approval.bind_run h
  obtain ⟨hd, r2, h2, h⟩ := Approval.bind_run h
  obtain ⟨mf, r3, h3, h⟩ := Approval.bind_run h
  obtain ⟨rq, r4, h4, h⟩ := Approval.bind_run h
  obtain ⟨rr, r5, h5, h⟩ := Approval.bind_run h
  obtain ⟨lv, r6, h6, h⟩ := Approval.bind_run h
  obtain ⟨rfl, rfl⟩ := Approval.pure_run h
  obtain ⟨e1, w1⟩ := rd_run h1
  obtain ⟨e2, w2⟩ := pLp_run h2
  obtain ⟨e3, w3⟩ := pLp_run h3
  obtain ⟨e4, w4⟩ := pList_run h4
  obtain ⟨e5, w5, w5'⟩ := pRows_run h5
  obtain ⟨e6, w6⟩ := pList_run h6
  subst e6 e5 e4 e3 e2 e1
  exact ⟨by simp [batchIn], w1, w2, w3, w4, w5, w5', w6⟩

theorem pSeg_run {b r : Bytes} {x : Segment3} (h : pSeg.run b = some (x, r)) : segIn x ++ r = b ∧ x.wf := by
  obtain ⟨f, r1, h1, h⟩ := Approval.bind_run h
  obtain ⟨l, r2, h2, h⟩ := Approval.bind_run h
  obtain ⟨d1, r3, h3, h⟩ := Approval.bind_run h
  obtain ⟨d2, r4, h4, h⟩ := Approval.bind_run h
  obtain ⟨d3, r5, h5, h⟩ := Approval.bind_run h
  obtain ⟨d4, r6, h6, h⟩ := Approval.bind_run h
  obtain ⟨rfl, rfl⟩ := Approval.pure_run h
  obtain ⟨e1, w1⟩ := rd_run h1
  obtain ⟨e2, w2⟩ := rd_run h2
  obtain ⟨e3, w3⟩ := digest_run h3
  obtain ⟨e4, w4⟩ := digest_run h4
  obtain ⟨e5, w5⟩ := digest_run h5
  obtain ⟨e6, w6⟩ := digest_run h6
  subst e6 e5 e4 e3 e2 e1
  exact ⟨by simp [segIn], w1, w2, w3, w4, w5, w6⟩

theorem pBody_run {b r : Bytes} {x : Body3} (h : pBody.run b = some (x, r)) : bodyIn3 x ++ r = b ∧ x.wf := by
  obtain ⟨v, r1, h1, hm⟩ := Approval.bind_run h
  obtain ⟨rfl, -⟩ := rd_run h1
  clear h
  split at hm
  · obtain ⟨bt, r2, h2, h⟩ := Approval.bind_run hm
    obtain ⟨rfl, rfl⟩ := Approval.pure_run h
    obtain ⟨e2, w⟩ := pBatch_run h2
    subst e2
    exact ⟨by simp [bodyIn3], w⟩
  · obtain ⟨k, r2, h2, h⟩ := Approval.bind_run hm
    obtain ⟨p, r3, h3, h⟩ := Approval.bind_run h
    obtain ⟨rfl, rfl⟩ := Approval.pure_run h
    obtain ⟨rfl, rfl⟩ := rest_run h3
    obtain ⟨e2, w⟩ := rd_run h2
    subst e2
    exact ⟨by simp [bodyIn3], w⟩
  · obtain ⟨k, r2, h2, h⟩ := Approval.bind_run hm
    obtain ⟨t, r3, h3, h⟩ := Approval.bind_run h
    obtain ⟨rfl, rfl⟩ := Approval.pure_run h
    obtain ⟨rfl, rfl⟩ := rest_run h3
    obtain ⟨e2, w⟩ := rd_run h2
    subst e2
    exact ⟨by simp [bodyIn3], w⟩
  · obtain ⟨sg, r2, h2, h⟩ := Approval.bind_run hm
    obtain ⟨rfl, rfl⟩ := Approval.pure_run h
    obtain ⟨e2, w⟩ := pSeg_run h2
    subst e2
    exact ⟨by simp [bodyIn3], w⟩
  · simp [fail, StateT.run] at hm

theorem pEntry3_run {b r : Bytes} {e : Entry3} (h : pEntry3.run b = some (e, r)) : entryIn3 e ++ r = b ∧ e.wf := by
  obtain ⟨u, r1, h1, h⟩ := Approval.bind_run h
  obtain ⟨i, r2, h2, h⟩ := Approval.bind_run h
  obtain ⟨p, r3, h3, h⟩ := Approval.bind_run h
  obtain ⟨bd, r4, h4, h⟩ := Approval.bind_run h
  obtain ⟨rfl, rfl⟩ := Approval.pure_run h
  have e1 := Approval.expect_run h1
  obtain ⟨e2, w2⟩ := rd_run h2
  obtain ⟨e3, w3⟩ := digest_run h3
  obtain ⟨e4, w4⟩ := pBody_run h4
  subst e4 e3 e2 e1
  exact ⟨by simp [entryIn3], w2, w3, w4⟩

/-- The decoder accepts only canonical bytes: what it returns is well formed and encodes back to
    exactly the input, so one entry has one byte string (with E2, decode and encode are inverse). -/
theorem decodeEntry3B_canonical {b : ByteArray} {e : Entry3} (h : decodeEntry3B b = some e) :
    e.wf ∧ encodeEntry3 e = b := by
  cases hd : decodeEntry3 b.data.toList with
  | none => simp [decodeEntry3B, hd] at h
  | some q =>
    obtain ⟨e', r⟩ := q
    cases r with
    | cons _ _ => simp [decodeEntry3B, hd] at h
    | nil =>
      simp only [decodeEntry3B, hd, Option.some.injEq] at h
      subst h
      obtain ⟨he, w⟩ := pEntry3_run hd
      refine ⟨w, ByteArray.ext (Array.toList_inj.1 ?_)⟩
      rw [encodeEntry3, List.toList_data_toByteArray, ← he, List.append_nil]

/-! ## Log state and push -/

/-- A permit opens with StateV2 `tipBytes` (`0`, or `1 || lp sealed || lp cert`); its rel/unr sets
    follow and have no decoder yet. -/
def tipIn : Option (Bytes × Bytes) → Bytes
  | none => natBE 1 0
  | some (s, c) => natBE 1 1 ++ lp s ++ lp c
def pTip : P (Option (Bytes × Bytes)) := do
  match ← rd 1 with
  | 0 => pure none
  | 1 => do let s ← pLp; let c ← pLp; pure (some (s, c))
  | _ => fail
def permitTip (p : Bytes) : Option (Option (Bytes × Bytes)) := (pTip.run p).map (·.1)

/-- StateV2 `Shard` with `own` as its (epoch, count) rows, epochs ascending, and each `pays` leaf as its bytes. -/
structure ShardM where
  own : List (Nat × Nat)
  sealed : Option Bytes
  live : Bool
  last : Option (Bytes × Bytes)
  base : Bytes
  pays : List (Nat × Bytes)

def ShardM.init : ShardM := ⟨[], none, false, none, zeroDigest, []⟩

structure LogStateM where
  len : Nat
  head : Bytes
  reg : List Row
  rhead : Bytes
  shards : Std.TreeMap Nat ShardM

def LogStateM.init : LogStateM := ⟨0, zeroDigest, [], zeroDigest, ∅⟩
def LogStateM.shard (m : LogStateM) (k : Nat) : ShardM := m.shards.getD k ShardM.init

/-! The ENGINE-SNAP/v2 encoding (layout and decoder in `Engine/Snap.lean`); here so a segment can bind it. -/

def snapTag : Bytes := "RR/GATE/ENGINE-SNAP/v2".toUTF8.toList ++ [0]
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

def stepM (m : LogStateM) : Body3 → Option LogStateM
  | .batch b =>
    if (m.shard b.shard).live then
      some { m with reg := b.regRows ++ m.reg, rhead := chainHead sha3 m.rhead b.regRows }
    else none
  | .resume k p =>
    match permitTip p with
    | some tip =>
      if (m.shard k).live = false ∧ tip.map (·.1) = (m.shard k).sealed then
        some { m with shards := m.shards.insert k { m.shard k with live := true, last := tip } }
      else none
    | none => none
  | .seal k t =>
    if (m.shard k).live = false ∧ (m.shard k).sealed = none ∧ (m.shard k).last = none then
      some { m with shards := m.shards.insert k { m.shard k with sealed := some t } }
    else none
  | .segment s => if s.snap = snapDigest m then some m else none

/-- Appends the entry bytes `b` only at the next index and only on the current head (no replay).
    `pushM` takes bytes, not an `Entry3`: the new head is the SHA3 of exactly `b` and the step is
    taken on the one entry `b` decodes to, so equal heads mean equal bytes and so equal states up to
    a SHA3 collision (no fork).  An `Entry3` whose fields overflow their widths has no bytes. -/
def pushM (m : LogStateM) (b : ByteArray) : Option LogStateM :=
  match decodeEntry3B b with
  | none => none
  | some e =>
    if e.idx = m.len ∧ e.prev = m.head then
      (stepM m e.body).map fun s => { s with len := m.len + 1, head := sha3 b.data.toList }
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
    · split at h
      · cases h
        rw [shard_insert]
        by_cases hka : k = a
        · rw [if_pos hka]; subst hka; exact ⟨fun _ => rfl, fun _ => rfl⟩
        · rw [if_neg hka]; exact ⟨fun _ => rfl, id⟩
      · cases h
    · cases h
  | «seal» k t =>
    simp only [stepM] at h
    split at h
    next hc =>
      cases h
      rw [shard_insert]
      by_cases hka : k = a
      · rw [if_pos hka]; subst hka
        refine ⟨fun hs => ?_, id⟩
        rw [hc.2.1] at hs
        simp at hs
      · rw [if_neg hka]; exact ⟨fun _ => rfl, id⟩
    next => cases h
  | segment s =>
    simp only [stepM] at h
    split at h
    · cases h; exact ⟨fun _ => rfl, id⟩
    · cases h

/-- L3 (S1 review 2): a push is exactly one `stepM` on the decoded body, then the new length and
    head; `rhead` and the shards come from the step alone. -/
theorem pushM_step {m m' : LogStateM} {b : ByteArray} (h : pushM m b = some m') :
    ∃ e s, decodeEntry3B b = some e ∧ e.idx = m.len ∧ e.prev = m.head ∧ stepM m e.body = some s ∧
      m' = { s with len := m.len + 1, head := sha3 b.data.toList } := by
  cases hd : decodeEntry3B b with
  | none => simp [pushM, hd] at h
  | some e =>
    simp only [pushM, hd] at h
    split at h
    next hc =>
      cases hs : stepM m e.body with
      | none => rw [hs] at h; cases h
      | some s =>
        rw [hs] at h
        have h' : some { s with len := m.len + 1, head := sha3 b.data.toList } = some m' := h
        cases h'
        exact ⟨e, s, rfl, hc.1, hc.2, hs, rfl⟩
    next => cases h

/-- L6, restated by S3 review HIGH-1 to StateV2 `push`'s resume guard (sealed + live is the normal
    post-cutover state): a seal is never taken twice, and on a sealed shard a resume is taken only
    when the shard is parked and the permit tip names that seal; it keeps the seal, sets live and
    records the tip as `last`. -/
theorem stepM_sealed_final {m : LogStateM} {k : Nat} {t : Bytes} (hs : (m.shard k).sealed = some t) :
    (∀ t', stepM m (.seal k t') = none) ∧
      ∀ p m', stepM m (.resume k p) = some m' → (m.shard k).live = false ∧
        ∃ c, permitTip p = some (some (t, c)) ∧ m'.shard k = { m.shard k with live := true, last := some (t, c) } := by
  refine ⟨fun t' => if_neg (fun hc => by rw [hc.2.1] at hs; cases hs), fun p m' h => ?_⟩
  simp only [stepM] at h
  split at h
  next tip htip =>
    split at h
    next hc =>
      cases h
      obtain ⟨hl, ht⟩ := hc
      rw [hs] at ht
      cases tip with
      | none => cases ht
      | some sc =>
        obtain ⟨s, c⟩ := sc
        simp only [Option.map_some, Option.some.injEq] at ht
        subst ht
        exact ⟨hl, c, htip, by rw [shard_insert, if_pos rfl]⟩
    next => cases h
  next => cases h

/-- StateV2 `push`'s seal guard (S3b review L1): a seal steps only on a parked, unsealed shard with no
    resume tip recorded. -/
theorem stepM_seal_guard {m m' : LogStateM} {k : Nat} {t : Bytes} (h : stepM m (.seal k t) = some m') :
    (m.shard k).live = false ∧ (m.shard k).sealed = none ∧ (m.shard k).last = none := by
  simp only [stepM] at h
  split at h
  next hc => exact hc
  next => cases h

/-- The post-cutover path (S3 review HIGH-1): on a parked unsealed shard a seal of `t` and then a
    resume whose permit tip is `(t, c)` both step, leaving the shard sealed at `t`, live, `last = (t, c)`. -/
theorem stepM_seal_resume {m : LogStateM} {k : Nat} {t c p : Bytes} (hl : (m.shard k).live = false)
    (hn : (m.shard k).sealed = none) (hlast : (m.shard k).last = none) (hp : permitTip p = some (some (t, c))) :
    ((stepM m (.seal k t)).bind fun m1 => stepM m1 (.resume k p)).map (·.shard k) =
      some { m.shard k with sealed := some t, live := true, last := some (t, c) } := by
  have h1 : stepM m (.seal k t) = some { m with shards := m.shards.insert k { m.shard k with sealed := some t } } :=
    if_pos ⟨hl, hn, hlast⟩
  rw [h1, Option.bind_some]
  have hm : ∀ a b c d s x, (LogStateM.mk a b c d s).shard x = s.getD x ShardM.init := fun _ _ _ _ _ _ => rfl
  simp [stepM, hp, hm, Std.TreeMap.getD_insert, Nat.compare_eq_eq]
  exact hl

/-- A push decodes `b` to one entry (well formed and canonical by `decodeEntry3B_canonical`), links
    it to the current head at the next index, grows the log by one, moves the head to the SHA3 of
    `b` and keeps every shard seal and live mark. -/
theorem pushM_chain {m m' : LogStateM} {b : ByteArray} (h : pushM m b = some m') :
    ∃ e, decodeEntry3B b = some e ∧ e.idx = m.len ∧ e.prev = m.head ∧ m'.len = m.len + 1 ∧
      m'.head = sha3 b.data.toList ∧ Keeps m m' := by
  obtain ⟨e, s, hd, hi, hp, hs, rfl⟩ := pushM_step h
  have hk := stepM_keep hs
  exact ⟨e, hd, hi, hp, rfl, rfl, hk⟩

/-- Folding pushes over a list: the log grows by exactly the list length, append-only. -/
theorem pushM_fold (es : List ByteArray) : ∀ {m m' : LogStateM}, es.foldlM pushM m = some m' →
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
      obtain ⟨_, -, -, -, hl1, -, hk1⟩ := pushM_chain h1
      exact ⟨by rw [hl, hl1, List.length_cons]; omega, hk1.trans hk⟩

theorem chainHead_app (g : Bytes) (d l : List Row) :
    chainHead sha3 g (d ++ l) = chainHead sha3 (chainHead sha3 g l) d := by
  induction d with
  | nil => rfl
  | cons r d ih => obtain ⟨kd, i, s⟩ := r; simp only [List.cons_append, chainHead, ih]

/-- S3b review M2: a step keeps `rhead` the registry head of `reg` from `zeroDigest`, which a snapshot
    decode checks. -/
theorem stepM_rhead {m m' : LogStateM} {b : Body3} (hm : m.rhead = chainHead sha3 zeroDigest m.reg)
    (h : stepM m b = some m') : m'.rhead = chainHead sha3 zeroDigest m'.reg := by
  cases b with
  | batch bt =>
    simp only [stepM] at h
    split at h
    · cases h; simp only [chainHead_app, ← hm]
    · cases h
  | resume k p =>
    simp only [stepM] at h
    split at h
    · split at h
      · cases h; exact hm
      · cases h
    · cases h
  | «seal» k t =>
    simp only [stepM] at h
    split at h
    · cases h; exact hm
    · cases h
  | segment s =>
    simp only [stepM] at h
    split at h
    · cases h; exact hm
    · cases h

/-- Every fold of pushes keeps `rhead = chainHead sha3 zeroDigest reg` (true at `init`), so each
    reachable state passes the snapshot registry check (S3b review M2). -/
theorem pushM_fold_rhead (es : List ByteArray) : ∀ {m m' : LogStateM},
    m.rhead = chainHead sha3 zeroDigest m.reg → es.foldlM pushM m = some m' →
      m'.rhead = chainHead sha3 zeroDigest m'.reg := by
  induction es with
  | nil =>
    intro m m' hm h
    have h' : some m = some m' := h
    cases h'
    exact hm
  | cons e es ih =>
    intro m m' hm h
    cases h1 : pushM m e with
    | none => simp [List.foldlM_cons, h1] at h
    | some m1 =>
      rw [List.foldlM_cons, h1] at h
      obtain ⟨_, s, -, -, -, hs, rfl⟩ := pushM_step h1
      have hr := stepM_rhead hm hs
      exact ih (m := { s with len := m.len + 1, head := sha3 e.data.toList }) hr h

end BlindLedger.Gate.Engine
