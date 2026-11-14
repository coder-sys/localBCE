import BlindLedger.Gate.Obligations.Layout

namespace BlindLedger.Gate.Obligations

open BlindLedger.Gate.FactCodec

/-! The records of the program-obligations shard (design `one-store` §2.3-§2.6), each a 245-byte `facts` body:
    the state row (money row form 5), the case, action, command and text records, and the fact rows of kinds 14,
    15 and 22-26.  Each record is its layout, its cells and its own check; `Layout` proves the round trip, the
    converse, the width and injectivity once, so each record proves only that reading its cells back gives it
    (`*_ok`, with its width).

    Numbers are little-endian, as in every `facts` record.  A codec checks widths, tags, zero fields, operation and
    kind codes, the closed lists of the design (event kinds, the state row's three statuses, action kinds and
    statuses, case statuses, the legacy marker `ecls`), and canonical identifier blocks.  Other codes are the
    reader's rule, as in the base fact codec.

    Cost: a record is 245 bytes to encode or decode, one pass, and no SHA3 permutation; the identities a record
    holds are computed by `Ident`. -/

/-- `w` bytes that must be zero. -/
def z (w : Nat) : Fld := .lit w 0

/-- A display field (design base §7.3): a canonical identifier block, or `0xFF` followed by the first bytes of the
    identifier's `H256` and zeros.  The length byte of an identifier is below the width, so the two forms differ. -/
def dispOk (w : Nat) (x : Bytes) : Bool := idOk w x || (x.head? == some 0xFF && allZero (x.drop 33))

/-! ## State row (tag `0x60`, form 5) -/

structure StateRow where
  mkind : Nat
  ob : Bytes
  cents : Nat
  wbatch : Nat
  windex : Nat
  cause : Nat
  link : Nat
  reg : Nat
  owed : Nat
  received : Nat
  claimed : Nat
  lawful : Nat
  shortfall : Nat
  overage : Nat
  conflicts : Nat
  flags : Nat
  verification : Nat
  caseStatus : Nat
  caseRef : Nat
  act : Nat
  fact : Nat
  cmd : Nat
  dueMs : Nat
  atMs : Nat
  lseq : Nat
  pack : Nat
  rev : Nat
  delivery : Nat
  lg : Nat
  deriving DecidableEq, Repr

/-- `okey` is `ob` then 40 zeros; `line`, `E`, `verdict` and the three day fields are zero for form 5. -/
def stateL : List Fld :=
  [.lit 1 0x60, .lit 1 5, .num 1, .blk 32, z 40, z 5, .num 8, z 8, z 1, .num 8, .num 3, .num 5, .num 5, z 12,
   .num 1, .num 8, .num 8, .num 8, .num 8, .num 8, .num 8, .num 5, .num 1, .num 1, .num 1, .num 5, .num 5,
   .num 5, .num 5, .num 8, .num 8, .num 5, .num 4, .num 5, .num 1, .num 1, z 6]

def stateC : RecCodec StateRow where
  L := stateL
  toC x := [.n x.mkind, .b x.ob, .n x.cents, .n x.wbatch, .n x.windex, .n x.cause, .n x.link, .n x.reg,
    .n x.owed, .n x.received, .n x.claimed, .n x.lawful, .n x.shortfall, .n x.overage, .n x.conflicts,
    .n x.flags, .n x.verification, .n x.caseStatus, .n x.caseRef, .n x.act, .n x.fact, .n x.cmd, .n x.dueMs,
    .n x.atMs, .n x.lseq, .n x.pack, .n x.rev, .n x.delivery, .n x.lg]
  build cs := ⟨nAt cs 0, bAt cs 1, nAt cs 2, nAt cs 3, nAt cs 4, nAt cs 5, nAt cs 6, nAt cs 7, nAt cs 8,
    nAt cs 9, nAt cs 10, nAt cs 11, nAt cs 12, nAt cs 13, nAt cs 14, nAt cs 15, nAt cs 16, nAt cs 17,
    nAt cs 18, nAt cs 19, nAt cs 20, nAt cs 21, nAt cs 22, nAt cs 23, nAt cs 24, nAt cs 25, nAt cs 26,
    nAt cs 27, nAt cs 28⟩
  -- mkind 13-25 (the closed list), flag bits 0-3, verification 1-3, case status 1-5, delivery 1-4 (the financial
  -- codec's codes), legacy bits 0-1.
  chk x := decide (13 ≤ x.mkind ∧ x.mkind ≤ 25 ∧ x.flags < 16 ∧ 1 ≤ x.verification ∧ x.verification ≤ 3 ∧
    1 ≤ x.caseStatus ∧ x.caseStatus ≤ 5 ∧ 1 ≤ x.delivery ∧ x.delivery ≤ 4 ∧ x.lg < 4)

theorem stateC_ok : stateC.Lawful ∧ width stateC.L = bodyBytes :=
  ⟨fun y _ => by cases y; rfl, rfl⟩

/-! ## Case record (tag `0x72`) -/

structure CaseRec where
  op : Nat
  ck : Bytes
  ob : Bytes
  status : Nat
  role : Nat
  acct : Nat
  reason : Nat
  dueMs : Nat
  atMs : Nat
  conds : Bytes
  act : Nat
  cmd : Nat
  assignee : Bytes
  lg : Nat
  nt : Nat
  deriving DecidableEq, Repr

def caseC : RecCodec CaseRec where
  L := [.lit 1 0x72, .num 1, .blk 32, .blk 32, .num 1, .num 1, .num 1, .num 2, .num 8, .num 8, .blk 64, .num 5,
    .num 5, .blk 32, .num 1, .num 1, z 50]
  toC x := [.n x.op, .b x.ck, .b x.ob, .n x.status, .n x.role, .n x.acct, .n x.reason, .n x.dueMs, .n x.atMs,
    .b x.conds, .n x.act, .n x.cmd, .b x.assignee, .n x.lg, .n x.nt]
  build cs := ⟨nAt cs 0, bAt cs 1, bAt cs 2, nAt cs 3, nAt cs 4, nAt cs 5, nAt cs 6, nAt cs 7, nAt cs 8,
    bAt cs 9, nAt cs 10, nAt cs 11, bAt cs 12, nAt cs 13, nAt cs 14⟩
  -- op 1 OPEN and 2 EVALUATED are the case chain: status 1-5, the owner's five case statuses.  op 3 ASSIGN and
  -- 4 CLOSE are the follow-through chain (§2.5): status 0, because the item's status is not stored; `followThrough`
  -- derives it from the records (§2.8), so it has one owner.  Held-payment and source items use tag 0x72 on their
  -- own shard under their own codec, not this one.
  chk x := decide (1 ≤ x.op ∧ x.op ≤ 4 ∧ (if x.op ≤ 2 then 1 ≤ x.status ∧ x.status ≤ 5 else x.status = 0) ∧
    x.lg < 4)

theorem caseC_ok : caseC.Lawful ∧ width caseC.L = bodyBytes :=
  ⟨fun y _ => by cases y; rfl, rfl⟩

/-! ## Action record (tag `0x73`) -/

structure ActionRec where
  op : Nat
  ak : Bytes
  ob : Bytes
  akind : Nat
  status : Nat
  attempt : Nat
  amount : Nat
  payload : Bytes
  idem : Bytes
  atMs : Nat
  claim : Nat
  ack : Nat
  cmd : Nat
  lg : Nat
  nt : Nat
  rev : Nat
  deriving DecidableEq, Repr

def actionC : RecCodec ActionRec where
  L := [.lit 1 0x73, .num 1, .blk 32, .blk 32, .num 1, .num 1, .num 4, .num 8, .blk 64, .blk 64, .num 8, .num 5,
    .num 5, .num 5, .num 1, .num 1, .num 5, z 7]
  toC x := [.n x.op, .b x.ak, .b x.ob, .n x.akind, .n x.status, .n x.attempt, .n x.amount, .b x.payload,
    .b x.idem, .n x.atMs, .n x.claim, .n x.ack, .n x.cmd, .n x.lg, .n x.nt, .n x.rev]
  build cs := ⟨nAt cs 0, bAt cs 1, bAt cs 2, nAt cs 3, nAt cs 4, nAt cs 5, nAt cs 6, bAt cs 7, bAt cs 8,
    nAt cs 9, nAt cs 10, nAt cs 11, nAt cs 12, nAt cs 13, nAt cs 14, nAt cs 15⟩
  -- op 1 CREATE, 2 ACK, 3 CANCEL, 4 ATTEMPT; akind 1-2 (the two owner kinds); status 1 READY, 2 ACKNOWLEDGED, 3 CANCELLED.
  chk x := decide (1 ≤ x.op ∧ x.op ≤ 4 ∧ 1 ≤ x.akind ∧ x.akind ≤ 2 ∧ 1 ≤ x.status ∧ x.status ≤ 3 ∧ x.lg < 4)

theorem actionC_ok : actionC.Lawful ∧ width actionC.L = bodyBytes :=
  ⟨fun y _ => by cases y; rfl, rfl⟩

/-! ## Command record (tag `0x74`) -/

structure CmdRec where
  ckind : Nat
  cid : Bytes
  rqd : Bytes
  lrq : Bytes
  actor : Bytes
  atMs : Nat
  role : Nat
  attr : Nat
  exprev : Nat
  result : Nat
  lseq : Nat
  epoch : Nat
  lg : Nat
  nt : Nat
  deriving DecidableEq, Repr

def cmdC : RecCodec CmdRec where
  L := [.lit 1 0x74, .num 1, .blk 32, .blk 64, .blk 64, .blk 32, .num 8, .num 1, .num 1, .num 5, .num 5, .num 5,
    .num 8, .num 1, .num 1, z 16]
  toC x := [.n x.ckind, .b x.cid, .b x.rqd, .b x.lrq, .b x.actor, .n x.atMs, .n x.role, .n x.attr, .n x.exprev,
    .n x.result, .n x.lseq, .n x.epoch, .n x.lg, .n x.nt]
  build cs := ⟨nAt cs 0, bAt cs 1, bAt cs 2, bAt cs 3, bAt cs 4, nAt cs 5, nAt cs 6, nAt cs 7, nAt cs 8,
    nAt cs 9, nAt cs 10, nAt cs 11, nAt cs 12, nAt cs 13⟩
  -- ckind 1-12 (the owner's twelve command kinds); attr 0 source row, 1 signed, 2 claimed.
  chk x := decide (1 ≤ x.ckind ∧ x.ckind ≤ 12 ∧ x.attr ≤ 2 ∧ x.lg < 4)

theorem cmdC_ok : cmdC.Lawful ∧ width cmdC.L = bodyBytes :=
  ⟨fun y _ => by cases y; rfl, rfl⟩

/-! ## Text record (tag `0x75`) and the split of one element -/

/-- Text bytes per record. -/
def textBytes : Nat := 242

structure TextRec where
  part : Nat
  len : Nat
  bytes : Bytes
  deriving DecidableEq, Repr

def textC : RecCodec TextRec where
  L := [.lit 1 0x75, .num 1, .num 1, .blk 242]
  toC x := [.n x.part, .n x.len, .b x.bytes]
  build cs := ⟨nAt cs 0, nAt cs 1, bAt cs 2⟩
  -- `len` from 1 to 242 and zeros after it.
  chk x := decide (1 ≤ x.len ∧ x.len ≤ textBytes) && allZero (x.bytes.drop x.len)

theorem textC_ok : textC.Lawful ∧ width textC.L = bodyBytes :=
  ⟨fun y _ => by cases y; rfl, rfl⟩

/-- An element's text records, numbered from `i`: full records of 242 bytes, then the rest (1 to 242 bytes). -/
def partsFrom (i : Nat) (e : Bytes) : List TextRec :=
  if h : e.length ≤ textBytes then [⟨i, e.length, e ++ List.replicate (textBytes - e.length) 0⟩]
  else ⟨i, textBytes, e.take textBytes⟩ :: partsFrom (i + 1) (e.drop textBytes)
termination_by e.length
decreasing_by simp only [List.length_drop]; simp only [textBytes] at h ⊢; omega

/-- Join text records numbered from `i`: no gap, every record but the last full, the last 1 to 242 bytes. -/
def joinFrom (i : Nat) : List TextRec → Option Bytes
  | [] => none
  | [t] => if t.part = i ∧ 1 ≤ t.len ∧ t.len ≤ textBytes then some (t.bytes.take t.len) else none
  | t :: ts => if t.part = i ∧ t.len = textBytes then (joinFrom (i + 1) ts).map (t.bytes ++ ·) else none

theorem joinFrom_cons {i : Nat} {t : TextRec} {ts : List TextRec} (h : ts ≠ []) :
    joinFrom i (t :: ts) =
      if t.part = i ∧ t.len = textBytes then (joinFrom (i + 1) ts).map (t.bytes ++ ·) else none := by
  cases ts with
  | nil => exact absurd rfl h
  | cons _ _ => rfl

theorem partsFrom_ne (i : Nat) (e : Bytes) : partsFrom i e ≠ [] := by
  rw [partsFrom]; split <;> simp

/-- The records of an element join back to it. -/
theorem join_parts (i : Nat) (e : Bytes) (h : 1 ≤ e.length) : joinFrom i (partsFrom i e) = some e := by
  rw [partsFrom]
  split
  · rename_i hl
    simp only [textBytes] at hl
    simp [joinFrom, textBytes, hl, h]
  · rename_i hl
    simp only [textBytes] at hl
    rw [joinFrom_cons (partsFrom_ne _ _), join_parts (i + 1) (e.drop textBytes) (by simp [textBytes]; omega)]
    simp [textBytes]
termination_by e.length
decreasing_by simp only [List.length_drop]; simp only [textBytes]; omega

/-- What a text record's check says, field by field. -/
theorem textC_wf {t : TextRec} (h : textC.WF t) :
    t.part < 256 ∧ t.len < 256 ∧ t.bytes.length = textBytes ∧ 1 ≤ t.len ∧ t.len ≤ textBytes ∧
      t.bytes = t.bytes.take t.len ++ List.replicate (textBytes - t.len) 0 := by
  obtain ⟨hf, hc⟩ := h
  simp only [textC, fit, Nat.pow_one, Bool.and_eq_true, decide_eq_true_eq] at hf hc
  obtain ⟨-, hp, hl, hb, -⟩ := hf
  obtain ⟨⟨h1, h2⟩, hz⟩ := hc
  refine ⟨hp, hl, hb, h1, h2, ?_⟩
  have := allZero_eq _ hz
  rw [List.length_drop, hb] at this
  conv => lhs; rw [← List.take_append_drop t.len t.bytes]
  rw [this]
  rfl

/-- One element, one split: records that join to `e` are exactly `e`'s records, so no other split is accepted. -/
theorem parts_join : ∀ (ts : List TextRec) (i : Nat) (e : Bytes), (∀ t ∈ ts, textC.WF t) →
    joinFrom i ts = some e → partsFrom i e = ts ∧ 1 ≤ e.length
  | [], _, _, _, h => by simp [joinFrom] at h
  | [t], i, e, hw, h => by
    obtain ⟨_, _, hb, h1, h2, hz⟩ := textC_wf (hw t (by simp))
    simp only [joinFrom] at h
    split at h
    · rename_i hp
      simp only [Option.some.injEq] at h
      subst h
      have hl : (t.bytes.take t.len).length = t.len := by simp only [List.length_take, hb]; omega
      refine ⟨?_, by omega⟩
      calc partsFrom i (t.bytes.take t.len)
          = [⟨i, t.len, t.bytes.take t.len ++ List.replicate (textBytes - t.len) 0⟩] := by
            rw [partsFrom, dif_pos (by omega), hl]
        _ = [⟨t.part, t.len, t.bytes⟩] := by rw [hp.1, ← hz]
        _ = [t] := rfl
    · cases h
  | t :: t' :: ts, i, e, hw, h => by
    obtain ⟨_, _, hb, -⟩ := textC_wf (hw t (by simp))
    rw [joinFrom_cons (by simp)] at h
    split at h
    · rename_i hp
      cases hj : joinFrom (i + 1) (t' :: ts) with
      | none => rw [hj] at h; simp at h
      | some e' =>
        rw [hj] at h
        simp only [Option.map_some, Option.some.injEq] at h
        subst h
        obtain ⟨ih, h1⟩ := parts_join (t' :: ts) (i + 1) e' (fun u hu => hw u (List.mem_cons_of_mem _ hu)) hj
        refine ⟨?_, by simp only [List.length_append]; omega⟩
        calc partsFrom i (t.bytes ++ e') = ⟨i, textBytes, t.bytes⟩ :: partsFrom (i + 1) e' := by
              rw [partsFrom, dif_neg (by simp only [List.length_append]; omega)]
              simp only [List.take_left' hb, List.drop_left' hb]
          _ = ⟨t.part, t.len, t.bytes⟩ :: t' :: ts := by rw [hp.1, hp.2, ih]
          _ = t :: t' :: ts := rfl
    · cases h

/-- Each record of a split, and how many there are, by the length of the element. -/
theorem parts_props (i : Nat) (e : Bytes) (h : 1 ≤ e.length) :
    (partsFrom i e).length * textBytes < e.length + textBytes ∧
    ∀ t ∈ partsFrom i e, i ≤ t.part ∧ (t.part - i) * textBytes < e.length ∧ t.len < 256 ∧
      t.bytes.length = textBytes ∧ textC.chk t = true := by
  rw [partsFrom]
  split
  · rename_i hl
    simp only [textBytes] at hl ⊢
    refine ⟨by simp; omega, ?_⟩
    intro t ht
    simp only [List.mem_singleton] at ht
    subst ht
    refine ⟨Nat.le_refl _, by simp; omega, by simp only; omega, by simp; omega, ?_⟩
    simp [textC, textBytes, hl, h, allZero_replicate]
  · rename_i hl
    simp only [textBytes] at hl
    obtain ⟨ihl, ihm⟩ := parts_props (i + 1) (e.drop textBytes) (by simp only [List.length_drop, textBytes]; omega)
    simp only [textBytes, List.length_drop] at ihl ihm ⊢
    refine ⟨by simp only [List.length_cons]; omega, ?_⟩
    intro t ht
    simp only [List.mem_cons] at ht
    rcases ht with rfl | ht
    · refine ⟨Nat.le_refl _, by simp only [Nat.sub_self]; omega, by simp, by simp; omega, ?_⟩
      have hd : (e.take 242).drop 242 = [] := by simp
      simp only [textC, hd]
      rfl
    · obtain ⟨h1, h2, h3, h4, h5⟩ := ihm t ht
      have e1 : t.part - i = (t.part - (i + 1)) + 1 := by omega
      rw [e1, Nat.add_mul, Nat.one_mul]
      generalize (t.part - (i + 1)) * 242 = k at h2 ⊢
      exact ⟨by omega, by omega, h3, h4, h5⟩
termination_by e.length
decreasing_by simp only [List.length_drop]; simp only [textBytes]; omega

/-- An element of 1 to 255 × 242 bytes (`nt` is one byte) splits into at most 255 well-formed records. -/
theorem parts_wf (e : Bytes) (h1 : 1 ≤ e.length) (h2 : e.length ≤ 255 * textBytes) :
    (partsFrom 0 e).length ≤ 255 ∧ ∀ t ∈ partsFrom 0 e, textC.WF t := by
  obtain ⟨hl, hm⟩ := parts_props 0 e h1
  simp only [textBytes] at hl h2 hm
  refine ⟨by omega, fun t ht => ?_⟩
  obtain ⟨-, hp, hlen, hb, hc⟩ := hm t ht
  refine ⟨?_, hc⟩
  simp only [textC, fit, Nat.pow_one]
  exact ⟨by decide, by omega, hlen, hb, trivial⟩

/-! ## Fact rows of kinds 14, 15 and 22-26 (§2.4) -/

/-- The base fact row from `op` to `roff`; the kind byte is the layout's literal. -/
structure FactHdr where
  op : Nat
  subject : Bytes
  sid : Bytes
  vstart : Nat
  vstop : Nat
  lineUntil : Nat
  receipt : Nat
  roff : Nat
  deriving DecidableEq, Repr

def hdrL (k : Nat) : List Fld := [.lit 1 k, .num 1, .blk 32, .blk 32, .num 4, .num 4, .num 4, .num 5, .num 5]

def FactHdr.cells (h : FactHdr) : List Cell :=
  [.n h.op, .b h.subject, .b h.sid, .n h.vstart, .n h.vstop, .n h.lineUntil, .n h.receipt, .n h.roff]

def hdrOf (cs : List Cell) : FactHdr :=
  ⟨nAt cs 0, bAt cs 1, bAt cs 2, nAt cs 3, nAt cs 4, nAt cs 5, nAt cs 6, nAt cs 7⟩

/-- As the base fact row: `op` 0 to 2, and a span that runs backwards only when `op` is 2. -/
def FactHdr.ok (h : FactHdr) : Bool := decide (h.op < 3 ∧ (h.op = 2 ∨ h.vstart ≤ h.vstop))

/-- OBLIG, kind 14: a population item. -/
structure ObligF where
  h : FactHdr
  owed : Nat
  dueMs : Nat
  rule : Nat
  pop : Bytes
  item : Bytes
  period : Bytes
  ecls : Nat
  deriving DecidableEq, Repr

def obligC : RecCodec ObligF where
  L := hdrL 14 ++ [.num 8, .num 8, .num 4, .blk 32, .blk 51, .blk 21, .num 1, z 32]
  toC x := x.h.cells ++ [.n x.owed, .n x.dueMs, .n x.rule, .b x.pop, .b x.item, .b x.period, .n x.ecls]
  build cs := ⟨hdrOf cs, nAt cs 8, nAt cs 9, nAt cs 10, bAt cs 11, bAt cs 12, bAt cs 13, nAt cs 14⟩
  chk x := x.h.ok && decide (x.ecls ≤ 4) && dispOk 51 x.item && dispOk 21 x.period

theorem obligC_ok : obligC.Lawful ∧ width obligC.L = bodyBytes :=
  ⟨fun y _ => by cases y with | mk h => cases h; rfl, rfl⟩

/-- CASH, kind 15: a payment confirmation; its void is the same `sid` ended. -/
structure CashF where
  h : FactHdr
  amount : Nat
  eventMs : Nat
  pays : Bytes
  pid : Bytes
  ecls : Nat
  origin : Bytes
  deriving DecidableEq, Repr

def cashC : RecCodec CashF where
  L := hdrL 15 ++ [.num 8, .num 8, .blk 32, .blk 32, .num 1, .blk 51, z 25]
  toC x := x.h.cells ++ [.n x.amount, .n x.eventMs, .b x.pays, .b x.pid, .n x.ecls, .b x.origin]
  build cs := ⟨hdrOf cs, nAt cs 8, nAt cs 9, bAt cs 10, bAt cs 11, nAt cs 12, bAt cs 13⟩
  chk x := x.h.ok && decide (x.ecls ≤ 4) && dispOk 51 x.origin

theorem cashC_ok : cashC.Lawful ∧ width cashC.L = bodyBytes :=
  ⟨fun y _ => by cases y with | mk h => cases h; rfl, rfl⟩

/-- CLAIM, kind 22: an offset claim. -/
structure ClaimF where
  h : FactHdr
  amount : Nat
  deadlineMs : Nat
  eventMs : Nat
  role : Nat
  ecls : Nat
  claim : Bytes
  deriving DecidableEq, Repr

def claimC : RecCodec ClaimF where
  L := hdrL 22 ++ [.num 8, .num 8, .num 8, .num 1, .num 1, .blk 51, z 80]
  toC x := x.h.cells ++ [.n x.amount, .n x.deadlineMs, .n x.eventMs, .n x.role, .n x.ecls, .b x.claim]
  build cs := ⟨hdrOf cs, nAt cs 8, nAt cs 9, nAt cs 10, nAt cs 11, nAt cs 12, bAt cs 13⟩
  chk x := x.h.ok && decide (x.ecls ≤ 4) && dispOk 51 x.claim

theorem claimC_ok : claimC.Lawful ∧ width claimC.L = bodyBytes :=
  ⟨fun y _ => by cases y with | mk h => cases h; rfl, rfl⟩

/-- SUPPORT, kind 23: supporting evidence. -/
structure SupportF where
  h : FactHdr
  content : Bytes
  applicableMs : Nat
  eventMs : Nat
  purpose : Nat
  ecls : Nat
  ref : Bytes
  deriving DecidableEq, Repr

def supportC : RecCodec SupportF where
  L := hdrL 23 ++ [.blk 64, .num 8, .num 8, .num 1, .num 1, .blk 51, z 24]
  toC x := x.h.cells ++ [.b x.content, .n x.applicableMs, .n x.eventMs, .n x.purpose, .n x.ecls, .b x.ref]
  build cs := ⟨hdrOf cs, bAt cs 8, nAt cs 9, nAt cs 10, nAt cs 11, nAt cs 12, bAt cs 13⟩
  chk x := x.h.ok && decide (x.ecls ≤ 4) && dispOk 51 x.ref

theorem supportC_ok : supportC.Lawful ∧ width supportC.L = bodyBytes :=
  ⟨fun y _ => by cases y with | mk h => cases h; rfl, rfl⟩

/-- REPORT, kind 24: a report or its correction. -/
structure ReportF where
  h : FactHdr
  content : Bytes
  applicableMs : Nat
  eventMs : Nat
  ecls : Nat
  ref : Bytes
  deriving DecidableEq, Repr

def reportC : RecCodec ReportF where
  L := hdrL 24 ++ [.blk 64, .num 8, .num 8, .num 1, .blk 51, z 25]
  toC x := x.h.cells ++ [.b x.content, .n x.applicableMs, .n x.eventMs, .n x.ecls, .b x.ref]
  build cs := ⟨hdrOf cs, bAt cs 8, nAt cs 9, nAt cs 10, nAt cs 11, bAt cs 12⟩
  chk x := x.h.ok && decide (x.ecls ≤ 4) && dispOk 51 x.ref

theorem reportC_ok : reportC.Lawful ∧ width reportC.L = bodyBytes :=
  ⟨fun y _ => by cases y with | mk h => cases h; rfl, rfl⟩

/-- FUND, kind 25: a program funding receipt. -/
structure FundF where
  h : FactHdr
  amount : Nat
  eventMs : Nat
  cclass : Nat
  estatus : Nat
  ecls : Nat
  ref : Bytes
  deriving DecidableEq, Repr

def fundC : RecCodec FundF where
  L := hdrL 25 ++ [.num 8, .num 8, .num 1, .num 1, .num 1, .blk 51, z 87]
  toC x := x.h.cells ++ [.n x.amount, .n x.eventMs, .n x.cclass, .n x.estatus, .n x.ecls, .b x.ref]
  build cs := ⟨hdrOf cs, nAt cs 8, nAt cs 9, nAt cs 10, nAt cs 11, nAt cs 12, bAt cs 13⟩
  chk x := x.h.ok && decide (x.ecls ≤ 4) && dispOk 51 x.ref

theorem fundC_ok : fundC.Lawful ∧ width fundC.L = bodyBytes :=
  ⟨fun y _ => by cases y with | mk h => cases h; rfl, rfl⟩

/-- ACTACK, kind 26: the acknowledgment of an action. -/
structure AckF where
  h : FactHdr
  action : Bytes
  payload : Bytes
  eventMs : Nat
  ecls : Nat
  ackref : Bytes
  deriving DecidableEq, Repr

def ackC : RecCodec AckF where
  L := hdrL 26 ++ [.blk 32, .blk 64, .num 8, .num 1, .blk 51, z 1]
  toC x := x.h.cells ++ [.b x.action, .b x.payload, .n x.eventMs, .n x.ecls, .b x.ackref]
  build cs := ⟨hdrOf cs, bAt cs 8, bAt cs 9, nAt cs 10, nAt cs 11, bAt cs 12⟩
  chk x := x.h.ok && decide (x.ecls ≤ 4) && dispOk 51 x.ackref

theorem ackC_ok : ackC.Lawful ∧ width ackC.L = bodyBytes :=
  ⟨fun y _ => by cases y with | mk h => cases h; rfl, rfl⟩

/-! ## Checks against the design's offset tables

    Each sample round-trips, is 245 bytes, and has its fields at the offsets the design's tables give. -/

/-- `w` bytes at offset `o`. -/
def slice (b : Bytes) (o w : Nat) : Bytes := (b.drop o).take w

def sampleState : StateRow :=
  ⟨19, pat 32 1, 30000, 7, 2, 11, 9, 1, 500000, 200000, 30000, 30000, 300000, 0, 1, 10, 2, 3, 12, 13, 14, 15,
    1767225600000, 1767225600001, 0, 4, 6, 1, 2⟩

#guard stateC.dec (stateC.enc sampleState) == some sampleState
#guard slice (stateC.enc sampleState) 0 3 == [0x60, 5, 19]
#guard slice (stateC.enc sampleState) 3 32 == pat 32 1 && slice (stateC.enc sampleState) 35 45 == zeros 45
#guard slice (stateC.enc sampleState) 80 8 == leBytes 8 30000 && slice (stateC.enc sampleState) 108 5 == leBytes 5 11
#guard slice (stateC.enc sampleState) 131 8 == leBytes 8 500000 &&
  slice (stateC.enc sampleState) 179 9 == [1, 0, 0, 0, 0, 10, 2, 3, 12]
#guard slice (stateC.enc sampleState) 207 8 == leBytes 8 1767225600000 &&
  slice (stateC.enc sampleState) 232 5 == leBytes 5 6
#guard slice (stateC.enc sampleState) 237 8 == [1, 2, 0, 0, 0, 0, 0, 0]
#guard [{ sampleState with delivery := 0 }, { sampleState with delivery := 5 }, { sampleState with verification := 4 },
  { sampleState with verification := 0 }, { sampleState with caseStatus := 6 }].all fun s =>
    stateC.dec (stateC.enc s) == none

/-- A follow-through ASSIGN: status 0. -/
def sampleCase : CaseRec :=
  ⟨3, pat 32 2, pat 32 1, 0, 4, 0xFF, 0xFFFF, 1767225600000, 1767225600001, pat 64 9, 0, 21, pat 32 7, 0, 1⟩

#guard caseC.dec (caseC.enc sampleCase) == some sampleCase
#guard caseC.dec (caseC.enc { sampleCase with op := 1, status := 2 }) != none
#guard [{ sampleCase with status := 2 }, { sampleCase with op := 4, status := 5 }, { sampleCase with op := 1 },
  { sampleCase with op := 2, status := 6 }].all fun c => caseC.dec (caseC.enc c) == none
#guard slice (caseC.enc sampleCase) 0 2 == [0x72, 3] && slice (caseC.enc sampleCase) 66 5 == [0, 4, 0xFF, 0xFF, 0xFF]
#guard slice (caseC.enc sampleCase) 87 64 == pat 64 9 && slice (caseC.enc sampleCase) 161 32 == pat 32 7
#guard slice (caseC.enc sampleCase) 193 2 == [0, 1] && (caseC.enc sampleCase).length == 245

def sampleAction : ActionRec :=
  ⟨1, pat 32 3, pat 32 1, 1, 1, 0, 30000, pat 64 4, pat 64 5, 1767225600000, 8, 0, 21, 0, 2, 1⟩

#guard actionC.dec (actionC.enc sampleAction) == some sampleAction
#guard slice (actionC.enc sampleAction) 72 8 == leBytes 8 30000 && slice (actionC.enc sampleAction) 144 64 == pat 64 5
#guard slice (actionC.enc sampleAction) 216 5 == leBytes 5 8 && slice (actionC.enc sampleAction) 233 5 == leBytes 5 1
#guard (actionC.enc sampleAction).length == 245

def sampleCmd : CmdRec :=
  ⟨8, pat 32 6, pat 64 7, zeros 64, pat 32 8, 1767225600000, 2, 2, 7, 22, 0, 3, 0, 4⟩

#guard cmdC.dec (cmdC.enc sampleCmd) == some sampleCmd
#guard slice (cmdC.enc sampleCmd) 34 64 == pat 64 7 && slice (cmdC.enc sampleCmd) 194 8 == leBytes 8 1767225600000
#guard slice (cmdC.enc sampleCmd) 202 7 == [2, 2, 7, 0, 0, 0, 0] &&
  slice (cmdC.enc sampleCmd) 219 10 == leBytes 8 3 ++ [0, 4]
#guard (cmdC.enc sampleCmd).length == 245

#guard (partsFrom 0 (pat 500 1)).map (fun t => (t.part, t.len)) == [(0, 242), (1, 242), (2, 16)]
#guard joinFrom 0 (partsFrom 0 (pat 500 1)) == some (pat 500 1)
#guard (partsFrom 0 (pat 500 1)).all fun t => textC.dec (textC.enc t) == some t
#guard joinFrom 0 [⟨0, 241, pat 241 1 ++ [0]⟩, ⟨1, 1, [7] ++ zeros 241⟩] == none

def sampleCash : CashF :=
  ⟨⟨0, pat 32 1, pat 32 40, 20260101, 20260101, 99991231, 5, 7⟩, 30000, 1767225600000, zeros 32, pat 32 9, 0,
    ident 51 "origin-1"⟩

#guard cashC.dec (cashC.enc sampleCash) == some sampleCash
#guard slice (cashC.enc sampleCash) 88 8 == leBytes 8 30000 && slice (cashC.enc sampleCash) 169 51 == ident 51 "origin-1"
#guard cashC.dec (cashC.enc { sampleCash with origin := 0xFF :: pat 32 3 ++ zeros 18 }) != none
#guard cashC.dec (cashC.enc { sampleCash with origin := 0xFF :: pat 33 3 ++ zeros 17 }) == none

end BlindLedger.Gate.Obligations
