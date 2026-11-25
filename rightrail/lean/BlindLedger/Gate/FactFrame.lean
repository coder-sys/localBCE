import BlindLedger.Sha3FastEq
import BlindLedger.Gate.FactCodec
import BlindLedger.Gate.Frame.Spec

/-! The fact frame `RRDF`, its answer and its retry rule (design fact-record §2.10).

    Request: a fixed header (magic `RRDF`, version 1 as u16, shard u32, batch u64, digest 64), 82 bytes as FRAME_V1's,
    then the body: `prev` 64 (the signed head the frame follows), FRAME_V1's authority section, which must be empty
    (the shard's pin 64, then 37 zero bytes), the source receipt's 165 field bytes with the fields the engine sets
    (`kb`, `admitted`, `same`) zero, the row count u32 (equal to the receipt's `rows`), the rows of 236 bytes each and
    a proof count u32 that must be 0.  A wire row is a fact row without `until` and `receipt`; it is never an end row
    (`op = 2`).  Rows are strictly increasing in (`subject`, kind, `sid`, `roff`), so no row is sent twice.

    The digest is `rq = H(dom FACTS ‖ body)` and is checked before any body byte is read.  A refusal carries
    FRAME_V1's word for the first fault met in byte order: `LENGTH`, `MAGIC`, `DIGEST` or `RECORD`.

    Answer: magic `RRDA`, version 3 as u16, status 0, shard u32, batch u64, line count u32 (one line per row), the
    request's digest (87 bytes), then per row disposition u8 ‖ cause u8 ‖ seq u40, then `head` 64, `root` 64, `rs` 64,
    work items u32 and money rows u32.

    Retry follows the engine's rule for a decision frame, except that a fact frame never opens the chain: batch 1 is
    `NOT_NEXT`.  The same batch with the logged digest gets the logged answer, another digest is `CONFLICT`.

    `H` is SHA3-512 at runtime (`sha`, the fast sponge, equal to the specification's by `sha_eq`); statements take it
    as a parameter.  `app/right_rail_fact_frame.py` is the twin that tests use; the golden bytes below are checked
    against it.  Synthetic, nonpayment, non-PHI. -/

namespace BlindLedger.Gate.FactFrame

open BlindLedger.Gate.FactCodec (leBytes fromLE rdLE rdBlk allZero leBytes_length fromLE_leBytes rdLE_enc
  rdBlk_enc rdLE_dec rdBlk_dec rdLE_lt rdBlk_length allZero_replicate allZero_eq valueBytes)
open BlindLedger.Gate.Frame (Word Eng Admit)

/-! ## Constants -/

def magicReq : Bytes := [0x52, 0x52, 0x44, 0x46]
def ansMagic : Bytes := [0x52, 0x52, 0x44, 0x41]
def version : Nat := 1
def ansVersion : Nat := 3
def hdrBytes : Nat := 82
def rcptBytes : Nat := 165
def rowBytes : Nat := 236
def authZero : Nat := 37
def factsDom : Bytes := domain "FACTS"

theorem magicReq_length : magicReq.length = 4 := rfl
theorem ansMagic_length : ansMagic.length = 4 := rfl

#guard magicReq == "RRDF".toUTF8.toList && ansMagic == Frame.magicAns && hdrBytes == Frame.hdrBytes &&
  Frame.ansHdrBytes == 87 && factsDom == "RR/GATE/FACTS/v1".toUTF8.toList ++ [0]

/-! ## Steps that refuse with a word -/

def need {α : Type} (o : Option α) (w : Word) : Except Word α :=
  match o with
  | some a => .ok a
  | none => .error w

def check (c : Bool) (w : Word) : Except Word Unit := if c then .ok () else .error w

def oguard (c : Bool) : Option Unit := if c then some () else none

/-- A block of `n` bytes, or `LENGTH`. -/
def blk (n : Nat) (b : Bytes) : Except Word (Bytes × Bytes) := need (rdBlk n b) .LENGTH

/-- An `n`-byte number, or `LENGTH`. -/
def num (n : Nat) (b : Bytes) : Except Word (Nat × Bytes) := need (rdLE n b) .LENGTH

section
variable {α β ε : Type}

@[simp] theorem ok_bind (a : α) (f : α → Except ε β) : (Except.ok a >>= f) = f a := rfl
@[simp] theorem error_bind (e : ε) (f : α → Except ε β) : (Except.error e >>= f) = .error e := rfl
@[simp] theorem pure_ok (a : α) : (pure a : Except ε α) = .ok a := rfl
@[simp] theorem osome_bind (a : α) (f : α → Option β) : (some a >>= f) = f a := rfl
@[simp] theorem onone_bind (f : α → Option β) : ((none : Option α) >>= f) = none := rfl
@[simp] theorem opure (a : α) : (pure a : Option α) = some a := rfl
@[simp] theorem need_some (a : α) (w : Word) : need (some a) w = .ok a := rfl
@[simp] theorem check_true (w : Word) : check true w = .ok () := rfl
@[simp] theorem check_false (w : Word) : check false w = .error w := rfl

theorem bind_ok {x : Except ε α} {f : α → Except ε β} {y : β} (h : (x >>= f) = .ok y) :
    ∃ a, x = .ok a ∧ f a = .ok y := by
  cases x with
  | error e => rw [error_bind] at h; cases h
  | ok a => exact ⟨a, rfl, h⟩

theorem obind_some {x : Option α} {f : α → Option β} {y : β} (h : (x >>= f) = some y) :
    ∃ a, x = some a ∧ f a = some y := by
  cases x with
  | none => rw [onone_bind] at h; cases h
  | some a => exact ⟨a, rfl, h⟩

theorem need_ok {o : Option α} {w : Word} {a : α} (h : need o w = .ok a) : o = some a := by
  cases o <;> simp_all [need]

end

theorem check_ok {c : Bool} {w : Word} {u : Unit} (h : check c w = .ok u) : c = true := by
  cases c <;> simp_all [check]

@[simp] theorem oguard_true : oguard true = some () := rfl

theorem oguard_some {c : Bool} {u : Unit} (h : oguard c = some u) : c = true := by
  cases c <;> simp_all [oguard]

theorem blk_enc {x : Bytes} (r : Bytes) {n : Nat} (h : x.length = n) : blk n (x ++ r) = .ok (x, r) := by
  simp [blk, rdBlk_enc r h]

theorem blk_dec {n : Nat} {b x r : Bytes} (h : blk n b = .ok (x, r)) : x ++ r = b ∧ x.length = n :=
  ⟨rdBlk_dec (need_ok h), rdBlk_length (need_ok h)⟩

theorem num_enc {w n : Nat} (r : Bytes) (h : n < 256 ^ w) : num w (leBytes w n ++ r) = .ok (n, r) := by
  simp [num, rdLE_enc r h]

theorem num_nil {w n : Nat} (h : n < 256 ^ w) : num w (leBytes w n) = .ok (n, []) := by
  simpa using num_enc [] h

theorem num_dec {w n : Nat} {b r : Bytes} (h : num w b = .ok (n, r)) : leBytes w n ++ r = b ∧ n < 256 ^ w :=
  ⟨rdLE_dec (need_ok h), rdLE_lt (need_ok h)⟩

theorem rdLE_nil {w n : Nat} (h : n < 256 ^ w) : rdLE w (leBytes w n) = some (n, []) := by
  simpa using rdLE_enc [] h

/-! ## The receipt on the wire -/

/-- The engine sets `kb`, `admitted`, `same` and `rd`; a frame sends them as zero. -/
def Wire (r : FactCodec.Receipt) : Prop :=
  r.WF ∧ r.kb = 0 ∧ r.admitted = 0 ∧ r.same = 0 ∧ r.rd = List.replicate 64 0

/-- The receipt's 165 field bytes, without the 80 zero bytes the stored record adds. -/
def encRcpt (r : FactCodec.Receipt) : Bytes := r.enc.take rcptBytes

def decRcpt (b : Bytes) : Option FactCodec.Receipt := do
  let r ← FactCodec.Receipt.dec (b ++ List.replicate 80 0)
  if r.kb == 0 && r.admitted == 0 && r.same == 0 && r.rd == List.replicate 64 0 then some r else none

theorem encRcpt_split {r : FactCodec.Receipt} (h : r.WF) (hz : r.rd = List.replicate 64 0) :
    encRcpt r ++ List.replicate 80 0 = r.enc := by
  have key : ∀ A : Bytes, A.length = rcptBytes →
      (A ++ List.replicate 80 0).take rcptBytes ++ List.replicate 80 0 = A ++ List.replicate 80 0 := by
    intro A hA
    rw [List.take_left' hA]
  obtain ⟨_, _, _, _, _, _, h7, h8, _, _, _, _, _, _, _, _, h17, _⟩ := h
  unfold encRcpt FactCodec.Receipt.enc
  rw [hz]
  simp only [List.append_assoc]
  rw [show List.replicate 64 (0 : UInt8) ++ List.replicate 16 0 = List.replicate 80 0 by simp [List.replicate_append_replicate]]
  simp only [← List.append_assoc]
  apply key
  simp [leBytes_length, h7, FactCodec.idOk_length h8, FactCodec.idOk_length h17, rcptBytes]

theorem encRcpt_length {r : FactCodec.Receipt} (h : r.WF) : (encRcpt r).length = rcptBytes := by
  simp [encRcpt, FactCodec.Receipt.enc_length r h, FactCodec.bodyBytes, rcptBytes]

theorem decRcpt_enc {r : FactCodec.Receipt} (h : Wire r) : decRcpt (encRcpt r) = some r := by
  obtain ⟨hw, h1, h2, h3, h4⟩ := h
  unfold decRcpt
  rw [encRcpt_split hw h4, FactCodec.Receipt.dec_enc r hw]
  simp [h1, h2, h3, h4]

theorem decRcpt_dec {b : Bytes} {r : FactCodec.Receipt} (h : decRcpt b = some r) : encRcpt r = b ∧ Wire r := by
  unfold decRcpt at h
  obtain ⟨r', h1, h2⟩ := obind_some h
  split at h2
  · rename_i hz
    cases h2
    simp only [Bool.and_eq_true, beq_iff_eq] at hz
    have hw := FactCodec.Receipt.dec_wf h1
    have he := FactCodec.Receipt.enc_dec h1
    rw [← encRcpt_split hw hz.2] at he
    exact ⟨List.append_cancel_right he, hw, hz.1.1.1, hz.1.1.2, hz.1.2, hz.2⟩
  · cases h2

/-! ## Rows on the wire -/

/-- A fact row without `until` (set by the engine) and `receipt` (the receipt the frame carries). -/
structure Row where
  op : Nat
  subject : Bytes
  sid : Bytes
  vstart : Nat
  vstop : Nat
  roff : Nat
  value : FactCodec.Value
  deriving BEq, Repr

def Row.toFact (w : Row) (u rc : Nat) : FactCodec.Fact :=
  ⟨w.op, w.subject, w.sid, w.vstart, w.vstop, u, rc, w.roff, w.value⟩

def Row.ofFact (f : FactCodec.Fact) : Row := ⟨f.op, f.subject, f.sid, f.vstart, f.vstop, f.roff, f.value⟩

/-- A canonical fact row that is not an end row. -/
def Row.WF (w : Row) : Prop := (w.toFact 0 0).WF ∧ w.op < 2

/-- The 74 bytes before `until`: kind, op, subject, sid, vstart, vstop. -/
def Row.head (w : Row) : Bytes :=
  leBytes 1 w.value.kind ++ leBytes 1 w.op ++ w.subject ++ w.sid ++ leBytes 4 w.vstart ++ leBytes 4 w.vstop

/-- The bytes after `receipt`: roff, the value, its zero padding. -/
def Row.tail (w : Row) : Bytes :=
  leBytes 5 w.roff ++ w.value.enc ++ List.replicate (valueBytes - w.value.enc.length) 0

def Row.enc (w : Row) : Bytes := w.head ++ w.tail

/-- The stored fact codec decides the row, with `until` and `receipt` read as zero; an end row is refused. -/
def Row.dec (b : Bytes) : Option Row := do
  let (hd, tl) ← rdBlk 74 b
  let f ← FactCodec.Fact.dec (hd ++ List.replicate 9 0 ++ tl)
  if f.op < 2 then some (Row.ofFact f) else none

theorem Row.fact_enc (f : FactCodec.Fact) :
    f.enc = (Row.ofFact f).head ++ (leBytes 4 f.lineUntil ++ leBytes 5 f.receipt) ++ (Row.ofFact f).tail := by
  simp [FactCodec.Fact.enc, Row.head, Row.tail, Row.ofFact, List.append_assoc]

theorem Row.head_length {w : Row} (h1 : w.subject.length = 32) (h2 : w.sid.length = 32) : w.head.length = 74 := by
  simp [Row.head, leBytes_length, h1, h2]

theorem Row.tail_length {w : Row} (h : w.value.WF) : w.tail.length = 162 := by
  have := FactCodec.Value.enc_length w.value h
  simp [Row.tail, leBytes_length, valueBytes] at this ⊢
  omega

theorem Row.enc_length {w : Row} (h : w.WF) : w.enc.length = rowBytes := by
  obtain ⟨⟨_, hs, hsid, _, _, _, _, _, hv, _⟩, _⟩ := h
  rw [Row.enc, List.length_append, Row.head_length (FactCodec.subjOk_length hs) hsid, Row.tail_length hv]
  rfl

theorem Row.dec_enc {w : Row} (h : w.WF) : Row.dec w.enc = some w := by
  have hl : w.head.length = 74 := Row.head_length (FactCodec.subjOk_length h.1.2.1) h.1.2.2.1
  have h9 : leBytes 4 0 ++ leBytes 5 0 = List.replicate 9 (0 : UInt8) := by decide
  have hw : Row.ofFact (w.toFact 0 0) = w := rfl
  have hz : w.head ++ List.replicate 9 0 ++ w.tail = (w.toFact 0 0).enc := by
    rw [Row.fact_enc, hw]
    show _ = w.head ++ (leBytes 4 0 ++ leBytes 5 0) ++ w.tail
    rw [h9]
  unfold Row.dec Row.enc
  rw [rdBlk_enc _ hl]
  simp only [osome_bind]
  rw [hz, FactCodec.Fact.dec_enc _ h.1]
  simp only [osome_bind]
  rw [if_pos (show (w.toFact 0 0).op < 2 from h.2), hw]

theorem Row.dec_spec {b : Bytes} {w : Row} (h : Row.dec b = some w) : w.enc = b ∧ w.WF := by
  unfold Row.dec at h
  obtain ⟨⟨hd, tl⟩, h1, h⟩ := obind_some h
  obtain ⟨f, h2, h⟩ := obind_some h
  split at h
  · rename_i hop
    cases h
    have hwf := FactCodec.Fact.dec_wf h2
    have he := FactCodec.Fact.enc_dec h2
    rw [Row.fact_enc] at he
    have hl : (Row.ofFact f).head.length = 74 := Row.head_length (FactCodec.subjOk_length hwf.2.1) hwf.2.2.1
    have hhd : hd.length = 74 := rdBlk_length h1
    obtain ⟨he1, ht⟩ := List.append_inj he (by simp [hl, hhd, leBytes_length])
    obtain ⟨hh, hm⟩ := List.append_inj he1 (by rw [hl, hhd])
    have hm' : leBytes 4 f.lineUntil ++ leBytes 5 f.receipt = List.replicate 4 0 ++ List.replicate 5 0 := by
      rw [hm]
      rfl
    obtain ⟨hu4, hr5⟩ := List.append_inj hm' (by simp [leBytes_length])
    have hu : f.lineUntil = 0 := by
      have := fromLE_leBytes 4 f.lineUntil (by have := hwf.2.2.2.2.2.1; simp; omega)
      rw [hu4] at this
      rw [← this]
      rfl
    have hrc : f.receipt = 0 := by
      have := fromLE_leBytes 5 f.receipt (by have := hwf.2.2.2.2.2.2.1; simp; omega)
      rw [hr5] at this
      rw [← this]
      rfl
    have hf : (Row.ofFact f).toFact 0 0 = f := by
      cases f
      simp only at hu hrc
      rw [hu, hrc]
      rfl
    refine ⟨?_, ?_, hop⟩
    · rw [← rdBlk_dec h1, Row.enc, hh, ht]
    · rw [hf]
      exact hwf
  · cases h

theorem Row.enc_dec {b : Bytes} {w : Row} (h : Row.dec b = some w) : w.enc = b := (Row.dec_spec h).1

theorem Row.dec_wf {b : Bytes} {w : Row} (h : Row.dec b = some w) : w.WF := (Row.dec_spec h).2

/-! ## Row order -/

/-- The row's place in the frame: subject, kind, sid, then `roff` big-endian, compared as bytes. -/
def Row.key (w : Row) : Bytes :=
  w.subject ++ [UInt8.ofNat w.value.kind] ++ w.sid ++ (leBytes 5 w.roff).reverse

/-- Bytes in lexicographic order, a proper prefix first. -/
def bLt : Bytes → Bytes → Bool
  | a :: as, b :: bs => a < b || (a == b && bLt as bs)
  | [], _ :: _ => true
  | _, [] => false

def sorted : List Bytes → Bool
  | a :: b :: t => bLt a b && sorted (b :: t)
  | _ => true

theorem bLt_irrefl : ∀ a : Bytes, bLt a a = false
  | [] => rfl
  | a :: as => by simp [bLt, bLt_irrefl as]

theorem bLt_trans : ∀ {a b c : Bytes}, bLt a b = true → bLt b c = true → bLt a c = true
  | [], [], _, h, _ => by simp [bLt] at h
  | _, _ :: _, [], _, h => by simp [bLt] at h
  | [], _ :: _, _ :: _, _, _ => rfl
  | _ :: _, [], _, h, _ => by simp [bLt] at h
  | x :: xs, y :: ys, z :: zs, h1, h2 => by
    simp only [bLt, Bool.or_eq_true, Bool.and_eq_true, decide_eq_true_eq, beq_iff_eq] at h1 h2 ⊢
    rcases h1 with h1 | ⟨rfl, h1⟩ <;> rcases h2 with h2 | ⟨rfl, h2⟩
    · left
      rw [UInt8.lt_iff_toNat_lt] at *
      omega
    · exact .inl h1
    · exact .inl h2
    · exact .inr ⟨rfl, bLt_trans h1 h2⟩

theorem sorted_pairwise : ∀ {l : List Bytes}, sorted l = true → l.Pairwise (fun a b => bLt a b = true)
  | [], _ => .nil
  | [_], _ => List.pairwise_singleton _ _
  | a :: b :: t, h => by
    simp only [sorted, Bool.and_eq_true] at h
    have ih := sorted_pairwise h.2
    refine .cons ?_ ih
    intro c hc
    rcases List.mem_cons.mp hc with rfl | hc
    · exact h.1
    · exact bLt_trans h.1 (List.rel_of_pairwise_cons ih hc)

/-- Sorted keys are distinct: no row is sent twice. -/
theorem sorted_nodup {l : List Bytes} (h : sorted l = true) : l.Nodup :=
  (sorted_pairwise h).imp fun {a b} hab e => by
    subst e
    simp [bLt_irrefl] at hab

/-! ## The request -/

structure Req where
  shard : Nat
  batch : Nat
  prev : Bytes
  pin : Bytes
  rcpt : FactCodec.Receipt
  rows : List Row
  deriving BEq, Repr

def rowsEnc : List Row → Bytes
  | [] => []
  | w :: ws => w.enc ++ rowsEnc ws

def bodyOf (prev pin : Bytes) (rcpt : FactCodec.Receipt) (rows : List Row) : Bytes :=
  prev ++ pin ++ List.replicate authZero 0 ++ encRcpt rcpt ++ leBytes 4 rows.length ++ rowsEnc rows ++ leBytes 4 0

def BodyWF (prev pin : Bytes) (rcpt : FactCodec.Receipt) (rows : List Row) : Prop :=
  prev.length = 64 ∧ pin.length = 64 ∧ Wire rcpt ∧ rows.length = rcpt.rows ∧ (∀ w ∈ rows, w.WF) ∧
    sorted (rows.map Row.key) = true

def Req.body (q : Req) : Bytes := bodyOf q.prev q.pin q.rcpt q.rows

def Req.WF (q : Req) : Prop :=
  q.shard < 4294967296 ∧ q.batch < 18446744073709551616 ∧ BodyWF q.prev q.pin q.rcpt q.rows

/-- The header in front of a body, its digest computed. -/
def frameBytes (H : Bytes → Bytes) (shard batch : Nat) (body : Bytes) : Bytes :=
  magicReq ++ leBytes 2 version ++ leBytes 4 shard ++ leBytes 8 batch ++ H (factsDom ++ body) ++ body

def encodeReq (H : Bytes → Bytes) (q : Req) : Bytes := frameBytes H q.shard q.batch q.body

def rowsDec : Nat → Bytes → Except Word (List Row × Bytes)
  | 0, b => .ok ([], b)
  | n + 1, b => do
    let (x, b) ← blk rowBytes b
    let w ← need (Row.dec x) .RECORD
    let (ws, b) ← rowsDec n b
    pure (w :: ws, b)

/-- `rowsDec` with the rows so far (latest first) kept, so the call is the last thing done and a request of any number of
    rows needs no stack (`rowsDecT_eq`). -/
def rowsDecT : Nat → List Row → Bytes → Except Word (List Row × Bytes)
  | 0, acc, b => .ok (acc.reverse, b)
  | n + 1, acc, b => do
    let (x, b) ← blk rowBytes b
    let w ← need (Row.dec x) .RECORD
    rowsDecT n (w :: acc) b

/-- Shard, batch, digest and body; a short header is `LENGTH`, a wrong magic or version `MAGIC`. -/
def decodeHdr (b : Bytes) : Except Word (Nat × Nat × Bytes × Bytes) := do
  check (decide (hdrBytes ≤ b.length)) .LENGTH
  let (m, b) ← blk 4 b
  let (v, b) ← num 2 b
  check (m == magicReq && v == version) .MAGIC
  let (shard, b) ← num 4 b
  let (batch, b) ← num 8 b
  let (dg, body) ← blk 64 b
  pure (shard, batch, dg, body)

def decodeBody (b : Bytes) : Except Word (Bytes × Bytes × FactCodec.Receipt × List Row) := do
  let (prev, b) ← blk 64 b
  let (pin, b) ← blk 64 b
  let (auth, b) ← blk authZero b
  check (allZero auth) .RECORD
  let (x, b) ← blk rcptBytes b
  let rcpt ← need (decRcpt x) .RECORD
  let (n, b) ← num 4 b
  check (n == rcpt.rows) .RECORD
  let (rows, b) ← rowsDecT n [] b
  check (sorted (rows.map Row.key)) .RECORD
  let (m, b) ← num 4 b
  check (m == 0) .RECORD
  check b.isEmpty .LENGTH
  pure (prev, pin, rcpt, rows)

/-- The request and its digest `rq`; the digest is checked before the body is read. -/
def decodeReq (H : Bytes → Bytes) (b : Bytes) : Except Word (Req × Bytes) := do
  let (shard, batch, dg, body) ← decodeHdr b
  check (H (factsDom ++ body) == dg) .DIGEST
  let (prev, pin, rcpt, rows) ← decodeBody body
  pure (⟨shard, batch, prev, pin, rcpt, rows⟩, dg)

theorem rowsEnc_length : ∀ {ws : List Row}, (∀ w ∈ ws, w.WF) → (rowsEnc ws).length = rowBytes * ws.length
  | [], _ => rfl
  | w :: ws, h => by
    rw [rowsEnc, List.length_append, Row.enc_length (h w (by simp)),
      rowsEnc_length (fun v hv => h v (by simp [hv])), List.length_cons, Nat.mul_succ, Nat.add_comm]

theorem rowsDecT_acc : ∀ (n : Nat) (acc : List Row) (b : Bytes),
    rowsDecT n acc b = (rowsDec n b).map fun p => (acc.reverse ++ p.1, p.2)
  | 0, acc, b => by simp [rowsDecT, rowsDec, Except.map]
  | n + 1, acc, b => by
    unfold rowsDecT rowsDec
    cases hb : blk rowBytes b with
    | error e => simp [hb, bind, Except.bind, Except.map]
    | ok p =>
      obtain ⟨x, b'⟩ := p
      cases hn : need (Row.dec x) .RECORD with
      | error e => simp [hb, hn, bind, Except.bind, Except.map]
      | ok w =>
        simp only [hb, hn, bind, Except.bind, rowsDecT_acc n (w :: acc) b']
        cases rowsDec n b' <;> simp [pure, Except.pure, Except.map]

/-- The tail recursive `rowsDecT` decodes as `rowsDec` does. -/
theorem rowsDecT_eq (n : Nat) (b : Bytes) : rowsDecT n [] b = rowsDec n b := by
  rw [rowsDecT_acc]
  cases rowsDec n b <;> simp [Except.map]

theorem rowsDec_enc : ∀ (ws : List Row), (∀ w ∈ ws, w.WF) → ∀ r, rowsDec ws.length (rowsEnc ws ++ r) = .ok (ws, r)
  | [], _, _ => rfl
  | w :: ws, h, r => by
    have hw := h w (by simp)
    have ih := rowsDec_enc ws (fun v hv => h v (by simp [hv])) r
    simp only [List.length_cons, rowsDec, rowsEnc, List.append_assoc, blk_enc _ (Row.enc_length hw), ok_bind,
      Row.dec_enc hw, need_some, ih, pure_ok]

theorem rowsDec_dec : ∀ {n : Nat} {b r : Bytes} {ws : List Row}, rowsDec n b = .ok (ws, r) →
    rowsEnc ws ++ r = b ∧ ws.length = n ∧ ∀ w ∈ ws, w.WF
  | 0, b, r, ws, h => by
    simp only [rowsDec, Except.ok.injEq, Prod.mk.injEq] at h
    obtain ⟨rfl, rfl⟩ := h
    simp [rowsEnc]
  | n + 1, b, r, ws, h => by
    simp only [rowsDec] at h
    obtain ⟨⟨x, b1⟩, h1, h⟩ := bind_ok h
    obtain ⟨w, h2, h⟩ := bind_ok h
    obtain ⟨⟨ws', b2⟩, h3, h⟩ := bind_ok h
    simp only [pure_ok, Except.ok.injEq, Prod.mk.injEq] at h
    obtain ⟨rfl, rfl⟩ := h
    obtain ⟨hx, -⟩ := blk_dec h1
    obtain ⟨he, hwf⟩ := Row.dec_spec (need_ok h2)
    obtain ⟨ih1, ih2, ih3⟩ := rowsDec_dec h3
    refine ⟨?_, by simp [ih2], ?_⟩
    · rw [rowsEnc, List.append_assoc, ih1, he, hx]
    · intro v hv
      rcases List.mem_cons.mp hv with rfl | hv
      · exact hwf
      · exact ih3 v hv

theorem decodeHdr_enc (H : Bytes → Bytes) (hH : ∀ x, (H x).length = 64) {s t : Nat} (hs : s < 4294967296)
    (ht : t < 18446744073709551616) (body : Bytes) :
    decodeHdr (frameBytes H s t body) = .ok (s, t, H (factsDom ++ body), body) := by
  have hl : hdrBytes ≤ (frameBytes H s t body).length := by
    simp [frameBytes, leBytes_length, hH, hdrBytes, magicReq]
    omega
  simp only [decodeHdr, decide_eq_true hl, check_true, ok_bind]
  simp only [frameBytes, List.append_assoc, blk_enc _ magicReq_length, ok_bind,
    num_enc _ (by decide : version < 256 ^ 2), beq_self_eq_true, Bool.and_self, check_true,
    num_enc _ (show s < 256 ^ 4 from hs), num_enc _ (show t < 256 ^ 8 from ht), blk_enc _ (hH _), pure_ok]

theorem decodeHdr_dec {b dg body : Bytes} {s t : Nat} (h : decodeHdr b = .ok (s, t, dg, body)) :
    magicReq ++ leBytes 2 version ++ leBytes 4 s ++ leBytes 8 t ++ dg ++ body = b ∧ s < 4294967296 ∧
      t < 18446744073709551616 ∧ dg.length = 64 := by
  unfold decodeHdr at h
  obtain ⟨⟨⟩, -, h⟩ := bind_ok h
  obtain ⟨⟨m, b1⟩, h1, h⟩ := bind_ok h
  obtain ⟨⟨v, b2⟩, h2, h⟩ := bind_ok h
  obtain ⟨⟨⟩, h3, h⟩ := bind_ok h
  obtain ⟨⟨s', b3⟩, h4, h⟩ := bind_ok h
  obtain ⟨⟨t', b4⟩, h5, h⟩ := bind_ok h
  obtain ⟨⟨dg', body'⟩, h6, h⟩ := bind_ok h
  simp only [pure_ok, Except.ok.injEq, Prod.mk.injEq] at h
  obtain ⟨rfl, rfl, rfl, rfl⟩ := h
  obtain ⟨e1, _⟩ := blk_dec h1
  obtain ⟨e2, _⟩ := num_dec h2
  have hc := check_ok h3
  simp only [Bool.and_eq_true, beq_iff_eq] at hc
  obtain ⟨e4, l4⟩ := num_dec h4
  obtain ⟨e5, l5⟩ := num_dec h5
  obtain ⟨e6, l6⟩ := blk_dec h6
  refine ⟨?_, l4, l5, l6⟩
  rw [← e1, ← e2, ← e4, ← e5, ← e6, hc.1, hc.2]
  simp [List.append_assoc]

theorem decodeBody_enc {prev pin : Bytes} {rcpt : FactCodec.Receipt} {rows : List Row}
    (h : BodyWF prev pin rcpt rows) : decodeBody (bodyOf prev pin rcpt rows) = .ok (prev, pin, rcpt, rows) := by
  obtain ⟨hp, hpin, hr, hn, hw, hs⟩ := h
  obtain ⟨_, _, _, _, _, _, _, _, _, _, _, _, hrows, _⟩ := hr.1
  have hn4 : rows.length < 256 ^ 4 := by rw [hn]; exact hrows
  have hn' : (rows.length == rcpt.rows) = true := by simp [hn]
  have hz : (List.replicate authZero (0 : UInt8)).length = authZero := by simp
  simp only [bodyOf, decodeBody, List.append_assoc, blk_enc _ hp, blk_enc _ hpin, blk_enc _ hz, ok_bind,
    allZero_replicate, check_true, blk_enc _ (encRcpt_length hr.1), decRcpt_enc hr, need_some, num_enc _ hn4, hn',
    rowsDecT_eq, rowsDec_enc _ hw, hs, num_nil (by decide : (0 : Nat) < 256 ^ 4), beq_self_eq_true, List.isEmpty_nil, pure_ok]

theorem decodeBody_dec {b prev pin : Bytes} {rcpt : FactCodec.Receipt} {rows : List Row}
    (h : decodeBody b = .ok (prev, pin, rcpt, rows)) : bodyOf prev pin rcpt rows = b ∧ BodyWF prev pin rcpt rows := by
  unfold decodeBody at h
  obtain ⟨⟨prev', b1⟩, h1, h⟩ := bind_ok h
  obtain ⟨⟨pin', b2⟩, h2, h⟩ := bind_ok h
  obtain ⟨⟨auth, b3⟩, h3, h⟩ := bind_ok h
  obtain ⟨⟨⟩, h4, h⟩ := bind_ok h
  obtain ⟨⟨x, b4⟩, h5, h⟩ := bind_ok h
  obtain ⟨rcpt', h6, h⟩ := bind_ok h
  obtain ⟨⟨n, b5⟩, h7, h⟩ := bind_ok h
  obtain ⟨⟨⟩, h8, h⟩ := bind_ok h
  obtain ⟨⟨rows', b6⟩, h9, h⟩ := bind_ok h
  obtain ⟨⟨⟩, h10, h⟩ := bind_ok h
  obtain ⟨⟨m, b7⟩, h11, h⟩ := bind_ok h
  obtain ⟨⟨⟩, h12, h⟩ := bind_ok h
  obtain ⟨⟨⟩, h13, h⟩ := bind_ok h
  simp only [pure_ok, Except.ok.injEq, Prod.mk.injEq] at h
  obtain ⟨rfl, rfl, rfl, rfl⟩ := h
  obtain ⟨e1, l1⟩ := blk_dec h1
  obtain ⟨e2, l2⟩ := blk_dec h2
  obtain ⟨e3, l3⟩ := blk_dec h3
  have hauth : auth = List.replicate authZero 0 := by rw [allZero_eq auth (check_ok h4), l3]
  obtain ⟨e5, _⟩ := blk_dec h5
  obtain ⟨e6, w6⟩ := decRcpt_dec (need_ok h6)
  obtain ⟨e7, _⟩ := num_dec h7
  have hn := beq_iff_eq.mp (check_ok h8)
  obtain ⟨e9, l9, w9⟩ := rowsDec_dec (by rw [← rowsDecT_eq]; exact h9)
  have hs := check_ok h10
  obtain ⟨e11, _⟩ := num_dec h11
  have hm := beq_iff_eq.mp (check_ok h12)
  have he := List.isEmpty_iff.mp (check_ok h13)
  subst hm he
  refine ⟨?_, l1, l2, w6, by rw [l9, hn], w9, hs⟩
  rw [← e1, ← e2, ← e3, ← e5, ← e7, ← e9, ← e11, hauth, ← e6, ← l9]
  simp [bodyOf, List.append_assoc]

/-- A well-formed request decodes to itself and its digest. -/
theorem decodeReq_enc (H : Bytes → Bytes) (hH : ∀ x, (H x).length = 64) {q : Req} (h : q.WF) :
    decodeReq H (encodeReq H q) = .ok (q, H (factsDom ++ q.body)) := by
  simp only [decodeReq, encodeReq, decodeHdr_enc H hH h.1 h.2.1, ok_bind, beq_self_eq_true, check_true,
    Req.body, decodeBody_enc h.2.2, pure_ok]

/-- Whatever decodes is well formed, is exactly the encoding of what it decoded to, and its digest is `rq`. -/
theorem decodeReq_dec {H : Bytes → Bytes} {b d : Bytes} {q : Req} (h : decodeReq H b = .ok (q, d)) :
    encodeReq H q = b ∧ q.WF ∧ d = H (factsDom ++ q.body) := by
  unfold decodeReq at h
  obtain ⟨⟨s, t, dg, body⟩, h1, h⟩ := bind_ok h
  obtain ⟨⟨⟩, h2, h⟩ := bind_ok h
  obtain ⟨⟨prev, pin, rcpt, rows⟩, h3, h⟩ := bind_ok h
  simp only [pure_ok, Except.ok.injEq, Prod.mk.injEq] at h
  obtain ⟨rfl, rfl⟩ := h
  obtain ⟨e1, hs, ht, _⟩ := decodeHdr_dec h1
  have hd := beq_iff_eq.mp (check_ok h2)
  obtain ⟨e3, w3⟩ := decodeBody_dec h3
  refine ⟨?_, ⟨hs, ht, w3⟩, ?_⟩
  · simp only [encodeReq, frameBytes, Req.body, e3, hd]
    exact e1
  · simp only [Req.body, e3, hd]

theorem decodeReq_wf {H : Bytes → Bytes} {b d : Bytes} {q : Req} (h : decodeReq H b = .ok (q, d)) : q.WF :=
  (decodeReq_dec h).2.1

/-- The body is read only under a matching digest. -/
theorem decodeReq_digest {H : Bytes → Bytes} {b dg body : Bytes} {s t : Nat}
    (h : decodeHdr b = .ok (s, t, dg, body)) (hd : H (factsDom ++ body) ≠ dg) : decodeReq H b = .error .DIGEST := by
  have : (H (factsDom ++ body) == dg) = false := by simpa using hd
  simp only [decodeReq, h, ok_bind, this, check_false, error_bind]

/-- A decoded frame holds no row twice and no end row. -/
theorem decodeReq_rows {H : Bytes → Bytes} {b d : Bytes} {q : Req} (h : decodeReq H b = .ok (q, d)) :
    (q.rows.map Row.key).Nodup ∧ ∀ w ∈ q.rows, w.op < 2 := by
  obtain ⟨_, _, _, _, _, _, hw, hs⟩ := decodeReq_wf h
  exact ⟨sorted_nodup hs, fun w hw' => (hw w hw').2⟩

theorem encodeReq_length (H : Bytes → Bytes) (hH : ∀ x, (H x).length = 64) {q : Req} (h : q.WF) :
    (encodeReq H q).length = 420 + rowBytes * q.rows.length := by
  obtain ⟨_, _, hp, hpin, hr, _, hw, _⟩ := h
  simp [encodeReq, frameBytes, Req.body, bodyOf, leBytes_length, hH, hp, hpin, encRcpt_length hr.1,
    rowsEnc_length hw, magicReq, rcptBytes, authZero] <;> omega

/-! ## The answer -/

/-- One line per row: disposition 1 to 4 (new, in force, quarantined, already held), a cause only for 3, and the
    sequence number of the record the line names. -/
structure Entry where
  disp : Nat
  cause : Nat
  seq : Nat
  deriving BEq, Repr

def entryOk (d c : Nat) : Bool := decide (1 ≤ d) && decide (d ≤ 4) && (d == 3 || c == 0)

def Entry.WF (e : Entry) : Prop := entryOk e.disp e.cause = true ∧ e.cause < 256 ∧ e.seq < 1099511627776

def Entry.enc (e : Entry) : Bytes := leBytes 1 e.disp ++ leBytes 1 e.cause ++ leBytes 5 e.seq

def entsEnc : List Entry → Bytes
  | [] => []
  | e :: es => e.enc ++ entsEnc es

def entsDec : Nat → Bytes → Option (List Entry × Bytes)
  | 0, b => some ([], b)
  | n + 1, b => do
    let (d, b) ← rdLE 1 b
    let (c, b) ← rdLE 1 b
    let (s, b) ← rdLE 5 b
    oguard (entryOk d c)
    let (es, b) ← entsDec n b
    pure (⟨d, c, s⟩ :: es, b)

structure Ans where
  shard : Nat
  batch : Nat
  digest : Bytes
  entries : List Entry
  head : Bytes
  root : Bytes
  rs : Bytes
  items : Nat
  money : Nat
  deriving BEq, Repr

def Ans.WF (a : Ans) : Prop :=
  a.shard < 4294967296 ∧ a.batch < 18446744073709551616 ∧ a.entries.length < 4294967296 ∧ a.digest.length = 64 ∧
    (∀ e ∈ a.entries, e.WF) ∧ a.head.length = 64 ∧ a.root.length = 64 ∧ a.rs.length = 64 ∧
    a.items < 4294967296 ∧ a.money < 4294967296

def Ans.enc (a : Ans) : Bytes :=
  ansMagic ++ leBytes 2 ansVersion ++ leBytes 1 0 ++ leBytes 4 a.shard ++ leBytes 8 a.batch ++
    leBytes 4 a.entries.length ++ a.digest ++ entsEnc a.entries ++ a.head ++ a.root ++ a.rs ++ leBytes 4 a.items ++
    leBytes 4 a.money

/-- Exactly the canonical bytes of a fact answer; otherwise none. -/
def Ans.dec (b : Bytes) : Option Ans := do
  let (m, b) ← rdBlk 4 b
  let (v, b) ← rdLE 2 b
  let (st, b) ← rdLE 1 b
  oguard (m == ansMagic && v == ansVersion && st == 0)
  let (shard, b) ← rdLE 4 b
  let (batch, b) ← rdLE 8 b
  let (n, b) ← rdLE 4 b
  let (digest, b) ← rdBlk 64 b
  let (entries, b) ← entsDec n b
  let (head, b) ← rdBlk 64 b
  let (root, b) ← rdBlk 64 b
  let (rs, b) ← rdBlk 64 b
  let (items, b) ← rdLE 4 b
  let (money, b) ← rdLE 4 b
  oguard b.isEmpty
  pure ⟨shard, batch, digest, entries, head, root, rs, items, money⟩

theorem entryOk_lt {d c : Nat} (h : entryOk d c = true) : d < 256 := by
  simp only [entryOk, Bool.and_eq_true, decide_eq_true_eq] at h
  omega

theorem entsDec_enc : ∀ (es : List Entry), (∀ e ∈ es, e.WF) → ∀ r, entsDec es.length (entsEnc es ++ r) = some (es, r)
  | [], _, _ => rfl
  | e :: es, h, r => by
    obtain ⟨hok, hc, hs⟩ := h e (by simp)
    have ih := entsDec_enc es (fun v hv => h v (by simp [hv])) r
    simp only [List.length_cons, entsDec, entsEnc, Entry.enc, List.append_assoc,
      rdLE_enc _ (show e.disp < 256 ^ 1 from entryOk_lt hok), osome_bind, rdLE_enc _ (show e.cause < 256 ^ 1 from hc),
      rdLE_enc _ (show e.seq < 256 ^ 5 from hs), hok, oguard_true, ih, opure]

theorem entsDec_dec : ∀ {n : Nat} {b r : Bytes} {es : List Entry}, entsDec n b = some (es, r) →
    entsEnc es ++ r = b ∧ es.length = n ∧ ∀ e ∈ es, e.WF
  | 0, b, r, es, h => by
    simp only [entsDec, Option.some.injEq, Prod.mk.injEq] at h
    obtain ⟨rfl, rfl⟩ := h
    simp [entsEnc]
  | n + 1, b, r, es, h => by
    simp only [entsDec] at h
    obtain ⟨⟨d, b1⟩, h1, h⟩ := obind_some h
    obtain ⟨⟨c, b2⟩, h2, h⟩ := obind_some h
    obtain ⟨⟨s, b3⟩, h3, h⟩ := obind_some h
    obtain ⟨⟨⟩, hok, h⟩ := obind_some h
    obtain ⟨⟨es', b4⟩, h4, h⟩ := obind_some h
    simp only [opure, Option.some.injEq, Prod.mk.injEq] at h
    obtain ⟨rfl, rfl⟩ := h
    have e1 : leBytes 1 d ++ b1 = b := rdLE_dec h1
    have e2 : leBytes 1 c ++ b2 = b1 := rdLE_dec h2
    have e3 : leBytes 5 s ++ b3 = b2 := rdLE_dec h3
    have hok' : entryOk d c = true := oguard_some hok
    have ih : entsEnc es' ++ b4 = b3 ∧ es'.length = n ∧ ∀ e ∈ es', e.WF := entsDec_dec h4
    refine ⟨?_, by simp [ih.2.1], ?_⟩
    · rw [← e1, ← e2, ← e3, ← ih.1]
      simp [entsEnc, Entry.enc, List.append_assoc]
    · intro v hv
      rcases List.mem_cons.mp hv with rfl | hv
      · exact ⟨hok', rdLE_lt h2, rdLE_lt h3⟩
      · exact ih.2.2 v hv

theorem Ans.dec_enc {a : Ans} (h : a.WF) : Ans.dec a.enc = some a := by
  obtain ⟨hs, hb, hn, hd, he, hh, hr, hrs, hi, hm⟩ := h
  simp only [Ans.dec, Ans.enc, List.append_assoc, rdBlk_enc _ ansMagic_length, osome_bind,
    rdLE_enc _ (by decide : ansVersion < 256 ^ 2), rdLE_enc _ (by decide : (0 : Nat) < 256 ^ 1),
    beq_self_eq_true, Bool.and_self, oguard_true, rdLE_enc _ (show a.shard < 256 ^ 4 from hs),
    rdLE_enc _ (show a.batch < 256 ^ 8 from hb), rdLE_enc _ (show a.entries.length < 256 ^ 4 from hn),
    rdBlk_enc _ hd, entsDec_enc _ he, rdBlk_enc _ hh, rdBlk_enc _ hr, rdBlk_enc _ hrs,
    rdLE_enc _ (show a.items < 256 ^ 4 from hi), rdLE_nil (show a.money < 256 ^ 4 from hm), List.isEmpty_nil, opure]

theorem Ans.dec_spec {b : Bytes} {a : Ans} (h : Ans.dec b = some a) : a.enc = b ∧ a.WF := by
  unfold Ans.dec at h
  obtain ⟨⟨m, b1⟩, h1, h⟩ := obind_some h
  obtain ⟨⟨v, b2⟩, h2, h⟩ := obind_some h
  obtain ⟨⟨st, b3⟩, h3, h⟩ := obind_some h
  obtain ⟨⟨⟩, hc, h⟩ := obind_some h
  obtain ⟨⟨shard, b4⟩, h4, h⟩ := obind_some h
  obtain ⟨⟨batch, b5⟩, h5, h⟩ := obind_some h
  obtain ⟨⟨n, b6⟩, h6, h⟩ := obind_some h
  obtain ⟨⟨digest, b7⟩, h7, h⟩ := obind_some h
  obtain ⟨⟨entries, b8⟩, h8, h⟩ := obind_some h
  obtain ⟨⟨head, b9⟩, h9, h⟩ := obind_some h
  obtain ⟨⟨root, b10⟩, h10, h⟩ := obind_some h
  obtain ⟨⟨rs, b11⟩, h11, h⟩ := obind_some h
  obtain ⟨⟨items, b12⟩, h12, h⟩ := obind_some h
  obtain ⟨⟨money, b13⟩, h13, h⟩ := obind_some h
  obtain ⟨⟨⟩, hz, h⟩ := obind_some h
  simp only [opure, Option.some.injEq] at h
  subst h
  have hc' : (m == ansMagic && v == ansVersion && st == 0) = true := oguard_some hc
  simp only [Bool.and_eq_true, beq_iff_eq] at hc'
  obtain ⟨⟨rfl, rfl⟩, rfl⟩ := hc'
  have e1 : ansMagic ++ b1 = b := rdBlk_dec h1
  have e2 : leBytes 2 ansVersion ++ b2 = b1 := rdLE_dec h2
  have e3 : leBytes 1 0 ++ b3 = b2 := rdLE_dec h3
  have e4 : leBytes 4 shard ++ b4 = b3 := rdLE_dec h4
  have e5 : leBytes 8 batch ++ b5 = b4 := rdLE_dec h5
  have e6 : leBytes 4 n ++ b6 = b5 := rdLE_dec h6
  have e7 : digest ++ b7 = b6 := rdBlk_dec h7
  have e8 : entsEnc entries ++ b8 = b7 ∧ entries.length = n ∧ ∀ e ∈ entries, e.WF := entsDec_dec h8
  have e9 : head ++ b9 = b8 := rdBlk_dec h9
  have e10 : root ++ b10 = b9 := rdBlk_dec h10
  have e11 : rs ++ b11 = b10 := rdBlk_dec h11
  have e12 : leBytes 4 items ++ b12 = b11 := rdLE_dec h12
  have e13 : leBytes 4 money ++ b13 = b12 := rdLE_dec h13
  have hb : b13 = [] := List.isEmpty_iff.mp (oguard_some hz)
  refine ⟨?_, rdLE_lt h4, rdLE_lt h5, by rw [e8.2.1]; exact rdLE_lt h6, rdBlk_length h7, e8.2.2, rdBlk_length h9,
    rdBlk_length h10, rdBlk_length h11, rdLE_lt h12, rdLE_lt h13⟩
  rw [← e1, ← e2, ← e3, ← e4, ← e5, ← e6, ← e7, ← e8.1, ← e9, ← e10, ← e11, ← e12, ← e13, hb, ← e8.2.1]
  simp [Ans.enc, List.append_assoc]

theorem Ans.enc_dec {b : Bytes} {a : Ans} (h : Ans.dec b = some a) : a.enc = b := (Ans.dec_spec h).1

theorem Ans.dec_wf {b : Bytes} {a : Ans} (h : Ans.dec b = some a) : a.WF := (Ans.dec_spec h).2

theorem Ans.enc_length {a : Ans} (h : a.WF) : a.enc.length = 87 + 7 * a.entries.length + 200 := by
  obtain ⟨_, _, _, hd, he, hh, hr, hrs, _, _⟩ := h
  have hl : ∀ es : List Entry, (entsEnc es).length = 7 * es.length := by
    intro es
    induction es with
    | nil => rfl
    | cons e es ih => simp [entsEnc, Entry.enc, leBytes_length, ih]; omega
  simp [Ans.enc, leBytes_length, hd, hh, hr, hrs, hl, ansMagic] <;> omega

/-! ## Retry

    The engine's rule for a frame against its log (one entry, digest and answer, per batch), with one change: a fact
    frame never opens the chain, so batch 1 is `NOT_NEXT` whatever the log holds. -/

def retry {σ : Type} (e : Eng σ) (q : Req) (rq : Bytes) : Admit :=
  if q.shard ≠ e.shard then .refuse .SHARD
  else if q.batch = 1 then .refuse .NOT_NEXT
  else if q.batch = e.log.length + 1 then
    if e.head = some q.prev then .decide else .refuse .HEAD
  else if q.batch = e.log.length then
    match e.log.getLast? with
    | some (d, a) => if d = rq then .replay a else .refuse .CONFLICT
    | none => .refuse .NOT_NEXT
  else .refuse .NOT_NEXT

/-- The last logged batch, sent again with the same digest, gets the logged answer. -/
theorem rrdf_retry {σ : Type} (e : Eng σ) (q : Req) {rq a : Bytes} (hs : q.shard = e.shard) (h1 : q.batch ≠ 1)
    (hb : q.batch = e.log.length) (hl : e.log.getLast? = some (rq, a)) : retry e q rq = .replay a := by
  have hn : q.batch ≠ e.log.length + 1 := by omega
  unfold retry
  rw [if_neg (by simp [hs]), if_neg h1, if_neg hn, if_pos hb, hl]
  simp

/-- The last logged batch with another digest is `CONFLICT`. -/
theorem rrdf_conflict {σ : Type} (e : Eng σ) (q : Req) {rq d a : Bytes} (hs : q.shard = e.shard)
    (h1 : q.batch ≠ 1) (hb : q.batch = e.log.length) (hl : e.log.getLast? = some (d, a)) (hd : d ≠ rq) :
    retry e q rq = .refuse .CONFLICT := by
  have hn : q.batch ≠ e.log.length + 1 := by omega
  unfold retry
  rw [if_neg (by simp [hs]), if_neg h1, if_neg hn, if_pos hb, hl]
  simp [hd]

/-- Batch 1, and any batch that is neither the next nor the last logged one, is `NOT_NEXT`. -/
theorem rrdf_not_next {σ : Type} (e : Eng σ) (q : Req) (rq : Bytes) (hs : q.shard = e.shard)
    (h : q.batch = 1 ∨ (q.batch ≠ e.log.length + 1 ∧ (q.batch ≠ e.log.length ∨ e.log = []))) :
    retry e q rq = .refuse .NOT_NEXT := by
  unfold retry
  rw [if_neg (by simp [hs])]
  rcases h with h | ⟨h1, h2⟩
  · rw [if_pos h]
  · by_cases hb1 : q.batch = 1
    · rw [if_pos hb1]
    · rw [if_neg hb1, if_neg h1]
      by_cases hb : q.batch = e.log.length
      · rw [if_pos hb, h2.resolve_left (fun hn => hn hb)]
        rfl
      · rw [if_neg hb]

/-! ## Golden bytes (written by the twin, checked here) -/

/-- SHA3-512 by the fast sponge: the same bytes as the specification's `sha3_512` (`sha_eq`). -/
def sha (b : Bytes) : Bytes := (BlindLedger.Semantic.sha3_512Fast b.toByteArray).toList

theorem sha_eq (b : Bytes) : sha b = (BlindLedger.Semantic.sha3_512 b.toByteArray).toList := by
  rw [sha, BlindLedger.Semantic.sha3_512_eq]

def gRow (n : String) : Row :=
  match FactCodec.goldenFacts.lookup n with
  | some f => Row.ofFact f
  | none => ⟨0, [], [], 0, 0, 0, .pdeath ⟨0⟩⟩

def r0 : Row := gRow "elig_basic"
def r1 : Row := gRow "death_state"
def r2 : Row := gRow "excl_basic"

def gRcpt : FactCodec.Receipt :=
  ⟨3, 1, 0, 20260102, 20250101, 2026010201, FactCodec.pat 64 40, FactCodec.ident 21 "STATEMMIS", 1, 1, 2, 0, 3,
    0, 0, 5, FactCodec.ident 21 "MEDICAID", 4000, FactCodec.zeros 64⟩

def gReq : Req := ⟨7, 42, FactCodec.pat 64 200, FactCodec.pat 64 100, gRcpt, [r0, r1, r2]⟩

def gAns : Ans :=
  ⟨7, 42, sha (factsDom ++ gReq.body), [⟨1, 0, 5⟩, ⟨3, 9, 77⟩, ⟨4, 0, FactCodec.m40⟩], FactCodec.pat 64 1,
    FactCodec.pat 64 2, FactCodec.zeros 64, 0, 0⟩

def golden : List (String × String) :=
  [ ("request", "525244460100070000002a00000000000000488f937f27e6eaf1c4a7b6cd29f90f2a55e5abfd1902ee18440e1ba070dc93b5cbc8128624174ec735db2c29bc7c623b265bc2831eef4c681b6ebcc24436c6ebc8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff00010203040506076465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a30000000000000000000000000000000000000000000000000000000000000000000000000040030001000000000006253501f5fd34015976c2780000000028292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f60616263646566670953544154454d4d495300000000000000000000000101000200000000000003000000000000000000000005000000084d45444943414944000000000000000000000000a00f0000000000000300000001000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f206465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f8081828305253501bfbef50507000000000101084d4544494341494400000000000000000000000000000000000000000000000000000000000000000009253501000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000200030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20212232333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f5051cafe3401bfbef5050100000000020708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f40414243444546000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000003000a31323334353637383930000000000000000000000000000000000000000000090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728e5d634017f5035010c000000000106313132386131000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000")
  , ("answer", "52524441030000070000002a0000000000000003000000488f937f27e6eaf1c4a7b6cd29f90f2a55e5abfd1902ee18440e1ba070dc93b5cbc8128624174ec735db2c29bc7c623b265bc2831eef4c681b6ebcc24436c6eb0100050000000003094d000000000400ffffffffff0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f4002030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f4041000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000") ]

def goldenOk : Bool :=
  golden.map (·.1) == ["request", "answer"] &&
    (golden.lookup "request").map FactCodec.hexBytes == some (encodeReq sha gReq) &&
    (golden.lookup "answer").map FactCodec.hexBytes == some gAns.enc &&
    (match decodeReq sha (encodeReq sha gReq) with
      | .ok (q, d) => q == gReq && d == gAns.digest
      | .error _ => false) &&
    Ans.dec gAns.enc == some gAns

#guard goldenOk

def errIs {α : Type} (x : Except Word α) (w : Word) : Bool :=
  match x with
  | .error v => v == w
  | .ok _ => false

def frm (body : Bytes) : Bytes := frameBytes sha 7 42 body

/-- The same frames and words as the twin's test `test_refusals_in_byte_order`. -/
def refusals : List (Bytes × Word) :=
  let b := encodeReq sha gReq
  let body := gReq.body
  [ (b.take 81, .LENGTH)
  , ([0x52, 0x52, 0x44, 0x51] ++ b.drop 4, .MAGIC)
  , (b.take 4 ++ [2, 0] ++ b.drop 6, .MAGIC)
  , (b.take 18 ++ FactCodec.zeros 64 ++ b.drop 82, .DIGEST)
  , (b.take 18 ++ FactCodec.zeros 64 ++ { gReq with rows := [r2, r1, r0] }.body, .DIGEST)
  , (frm (body.set 133 1), .RECORD)
  , (frm (body.set 169 1), .RECORD)
  , (frm { gReq with rcpt := { gRcpt with rows := 2 } }.body, .RECORD)
  , (frm (body.set 335 2), .RECORD)
  , (frm { gReq with rows := [r2, r1, r0] }.body, .RECORD)
  , (frm { gReq with rows := [r0, r0, r1] }.body, .RECORD)
  , (frm (body.take (body.length - 4) ++ leBytes 4 1), .RECORD)
  , (frm (body.take (body.length - 1)), .LENGTH)
  , (frm (body ++ [0]), .LENGTH)
  , (frm { gReq with rows := [{ r0 with roff := 256 }, { r0 with roff := 1 }, r1] }.body, .RECORD) ]

#guard refusals.all fun (b, w) => errIs (decodeReq sha b) w

-- `roff` orders as a number: 1 before 256, though its first little-endian byte is larger.
def gUp : Req := { gReq with rows := [{ r0 with roff := 1 }, { r0 with roff := 256 }, r1] }

#guard match decodeReq sha (encodeReq sha gUp) with
  | .ok (q, _) => q == gUp
  | .error _ => false

end BlindLedger.Gate.FactFrame
