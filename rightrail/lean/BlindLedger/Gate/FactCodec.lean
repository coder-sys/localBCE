namespace BlindLedger.Gate.FactCodec

/-! Byte codecs for the fee-for-service fact records, the source receipt and the statement order `rank`
    (design `fact-record` §2.3, §2.4, §3.2).  Nothing calls this yet: it is the specification the
    store and the engine will be built against.

    Every record of the `facts` file is 245 bytes of body, which is what is coded here; the rows-file
    codec adds its own link bytes around the body to fill the 256-byte record.  Numbers are
    little-endian.  A field is a number of a fixed width or a block of bytes of a fixed width.
    Padding is zero, and a decoder refuses any other padding, so each record has one encoding.

    The codec checks width, kind tag, padding and the canonical form of the record, and nothing about
    meaning: an operation code is 0, 1 or 2, a validity span does not run backwards, an identifier block
    has a length byte inside the block and zeros after its text, and a provider subject has zeros after
    its identifier.  A date's validity or a status code's range is the reader's rule, not the codec's.
    Kinds 8 to 13 are in the design but are built in later steps; they are refused here. -/

abbrev Bytes := List UInt8

/-- The body of every `facts` record, and the width of a fact row's `value` field. -/
def bodyBytes : Nat := 245
def valueBytes : Nat := 157

/-! ## Little-endian numbers and fixed-width reads -/

/-- `w` little-endian bytes of `n` (the low `w` bytes). -/
def leBytes : Nat → Nat → Bytes
  | 0, _ => []
  | w + 1, n => UInt8.ofNat (n % 256) :: leBytes w (n / 256)

def fromLE : Bytes → Nat
  | [] => 0
  | b :: bs => b.toNat + 256 * fromLE bs

theorem leBytes_length (w n : Nat) : (leBytes w n).length = w := by
  induction w generalizing n with
  | zero => rfl
  | succ w ih => simp [leBytes, ih]

theorem fromLE_leBytes (w n : Nat) (h : n < 256 ^ w) : fromLE (leBytes w n) = n := by
  induction w generalizing n with
  | zero => simp at h; simp [leBytes, fromLE, h]
  | succ w ih =>
    have h2 : n / 256 < 256 ^ w := by
      rw [Nat.pow_succ] at h
      exact (Nat.div_lt_iff_lt_mul (by omega)).2 (by omega)
    have h3 : (UInt8.ofNat (n % 256)).toNat = n % 256 := by simp
    simp only [leBytes, fromLE, ih _ h2, h3]
    omega

/-- Read a `w`-byte number, returning the rest; none when too short (`rdLE_def`).  The length tested is the taken
    block's, so a decoder that reads a long input field by field walks each byte a fixed number of times, not the whole
    rest at every field. -/
def rdLE (w : Nat) (b : Bytes) : Option (Nat × Bytes) :=
  let x := b.take w
  if x.length < w then none else some (fromLE x, b.drop w)

/-- Read a `w`-byte block, returning the rest; none when too short (`rdBlk_def`; the length tested as in `rdLE`). -/
def rdBlk (w : Nat) (b : Bytes) : Option (Bytes × Bytes) :=
  let x := b.take w
  if x.length < w then none else some (x, b.drop w)

theorem take_length_lt (w : Nat) (b : Bytes) : ((b.take w).length < w) = (b.length < w) :=
  propext (by rw [List.length_take]; constructor <;> intro _ <;> omega)

theorem rdLE_def (w : Nat) (b : Bytes) :
    rdLE w b = if b.length < w then none else some (fromLE (b.take w), b.drop w) := by
  simp only [rdLE, take_length_lt]

theorem rdBlk_def (w : Nat) (b : Bytes) :
    rdBlk w b = if b.length < w then none else some (b.take w, b.drop w) := by
  simp only [rdBlk, take_length_lt]

def allZero (b : Bytes) : Bool := b.all (· == 0)

theorem rdLE_enc {w n : Nat} (r : Bytes) (h : n < 256 ^ w) :
    rdLE w (leBytes w n ++ r) = some (n, r) := by
  have hl := leBytes_length w n
  rw [rdLE_def]
  rw [if_neg (by rw [List.length_append, hl]; omega), List.take_left' hl, List.drop_left' hl,
    fromLE_leBytes w n h]

theorem rdBlk_enc {w : Nat} {x : Bytes} (r : Bytes) (h : x.length = w) :
    rdBlk w (x ++ r) = some (x, r) := by
  rw [rdBlk_def]
  rw [if_neg (by rw [List.length_append, h]; omega), List.take_left' h, List.drop_left' h]

theorem allZero_replicate (m : Nat) : allZero (List.replicate m 0) = true := by
  induction m with
  | zero => rfl
  | succ m ih => simp [allZero, List.replicate_succ] at ih ⊢

theorem leBytes_fromLE (b : Bytes) : leBytes b.length (fromLE b) = b := by
  induction b with
  | nil => rfl
  | cons x t ih =>
    have hx : x.toNat < 256 := x.toNat_lt
    have h1 : (x.toNat + 256 * fromLE t) % 256 = x.toNat := by omega
    have h2 : (x.toNat + 256 * fromLE t) / 256 = fromLE t := by omega
    simp only [fromLE, List.length_cons, leBytes, h1, h2, ih]
    simp

/-- What a successful read took off the front: reading puts the bytes back. -/
theorem rdLE_dec {w : Nat} {b r : Bytes} {n : Nat} (h : rdLE w b = some (n, r)) : leBytes w n ++ r = b := by
  rw [rdLE_def] at h
  split at h
  · cases h
  · simp only [Option.some.injEq, Prod.mk.injEq] at h
    obtain ⟨rfl, rfl⟩ := h
    have hl : (b.take w).length = w := by simp; omega
    have := leBytes_fromLE (b.take w)
    rw [hl] at this
    rw [this, List.take_append_drop]

theorem rdBlk_dec {w : Nat} {b r x : Bytes} (h : rdBlk w b = some (x, r)) : x ++ r = b := by
  rw [rdBlk_def] at h
  split at h
  · cases h
  · simp only [Option.some.injEq, Prod.mk.injEq] at h
    obtain ⟨rfl, rfl⟩ := h
    exact List.take_append_drop _ _

/-- A canonical identifier block of width `w`: a length byte below `w`, that many bytes of text, then
    zeros to the end of the block. -/
def idOk (w : Nat) (x : Bytes) : Bool :=
  x.length == w &&
    match x with
    | [] => false
    | n :: t => decide (n.toNat < w) && allZero (t.drop n.toNat)

theorem idOk_length {w : Nat} {x : Bytes} (h : idOk w x = true) : x.length = w := by
  unfold idOk at h
  simp only [Bool.and_eq_true, beq_iff_eq] at h
  exact h.1

/-- Read a `w`-byte identifier block; a block that is not canonical is refused. -/
def rdId (w : Nat) (b : Bytes) : Option (Bytes × Bytes) :=
  match rdBlk w b with
  | some (x, r) => if idOk w x then some (x, r) else none
  | none => none

theorem rdId_enc {w : Nat} {x : Bytes} (r : Bytes) (h : idOk w x = true) : rdId w (x ++ r) = some (x, r) := by
  simp [rdId, rdBlk_enc r (idOk_length h), h]

theorem rdId_dec {w : Nat} {b r x : Bytes} (h : rdId w b = some (x, r)) : x ++ r = b := by
  unfold rdId at h
  split at h
  · rename_i x' r' h1
    split at h
    · simp only [Option.some.injEq, Prod.mk.injEq] at h
      obtain ⟨rfl, rfl⟩ := h
      exact rdBlk_dec h1
    · cases h
  · cases h

theorem rdBlk_length {w : Nat} {b r x : Bytes} (h : rdBlk w b = some (x, r)) : x.length = w := by
  rw [rdBlk_def] at h
  split at h
  · cases h
  · simp only [Option.some.injEq, Prod.mk.injEq] at h
    obtain ⟨rfl, rfl⟩ := h
    simp; omega

theorem rdId_length {w : Nat} {b r x : Bytes} (h : rdId w b = some (x, r)) : x.length = w := by
  unfold rdId at h
  split at h
  · rename_i x' r' h1
    split at h
    · simp only [Option.some.injEq, Prod.mk.injEq] at h
      obtain ⟨rfl, rfl⟩ := h
      exact rdBlk_length h1
    · cases h
  · cases h

theorem rdId_ok {w : Nat} {b r x : Bytes} (h : rdId w b = some (x, r)) : idOk w x = true := by
  unfold rdId at h
  split at h
  · split at h
    · rename_i hk
      simp only [Option.some.injEq, Prod.mk.injEq] at h
      obtain ⟨rfl, rfl⟩ := h
      exact hk
    · cases h
  · cases h

theorem fromLE_lt (l : Bytes) : fromLE l < 256 ^ l.length := by
  induction l with
  | nil => simp [fromLE]
  | cons x t ih =>
    have hx : x.toNat < 256 := x.toNat_lt
    simp only [fromLE, List.length_cons, Nat.pow_succ]
    omega

/-- A number that was read fits its width. -/
theorem rdLE_lt {w : Nat} {b r : Bytes} {n : Nat} (h : rdLE w b = some (n, r)) : n < 256 ^ w := by
  rw [rdLE_def] at h
  split at h
  · cases h
  · simp only [Option.some.injEq, Prod.mk.injEq] at h
    obtain ⟨rfl, rfl⟩ := h
    have hl : (b.take w).length = w := by simp; omega
    have := fromLE_lt (b.take w)
    rw [hl] at this
    exact this

theorem allZero_eq (l : Bytes) (h : allZero l = true) : l = List.replicate l.length 0 := by
  induction l with
  | nil => rfl
  | cons x t ih =>
    simp only [allZero, List.all_cons, Bool.and_eq_true, beq_iff_eq] at h
    have := ih h.2
    simp only [List.length_cons, List.replicate_succ]
    rw [← this, h.1]

/-! ## The value of each kind (§2.4 kinds table) -/

/-- 1 ELIG: eligibility determination, 52 bytes. -/
structure Elig where
  status : Nat
  basis : Nat
  program : Bytes
  aid : Bytes
  determined : Nat
  notice : Nat
  deriving BEq, Repr

/-- 2 DEATH: one kind for every death source, 65 bytes.  `record` is zero for a federal row. -/
structure Death where
  proof : Nat
  record : Bytes
  deriving BEq, Repr

/-- 3 EXCL: exclusion, 11 bytes. -/
structure Excl where
  list : Nat
  type : Bytes
  waiver : Nat
  deriving BEq, Repr

/-- 4 PDEATH: provider death, 1 byte. -/
structure Pdeath where
  proof : Nat
  deriving BEq, Repr

/-- 5 ACK: delivery acknowledgment, 132 bytes. -/
structure Ack where
  pay : Bytes
  status : Nat
  amount : Nat
  trace : Bytes
  deriving BEq, Repr

/-- 6 DISC: discovery event, 112 bytes. -/
structure Disc where
  event : Nat
  pay : Bytes
  amount : Nat
  caseId : Bytes
  deriving BEq, Repr

/-- 7 RECOV: recovery received, 132 bytes. -/
structure Recov where
  pay : Bytes
  amount : Nat
  source : Nat
  ref : Bytes
  deriving BEq, Repr

def Elig.enc (v : Elig) : Bytes :=
  leBytes 1 v.status ++ leBytes 1 v.basis ++ v.program ++ v.aid ++ leBytes 4 v.determined ++ leBytes 4 v.notice

def Elig.dec (b : Bytes) : Option (Elig × Bytes) := do
  let (status, b) ← rdLE 1 b
  let (basis, b) ← rdLE 1 b
  let (program, b) ← rdId 21 b
  let (aid, b) ← rdId 21 b
  let (determined, b) ← rdLE 4 b
  let (notice, b) ← rdLE 4 b
  pure ({ status, basis, program, aid, determined, notice }, b)

def Death.enc (v : Death) : Bytes := leBytes 1 v.proof ++ v.record

def Death.dec (b : Bytes) : Option (Death × Bytes) := do
  let (proof, b) ← rdLE 1 b
  let (record, b) ← rdBlk 64 b
  pure ({ proof, record }, b)

def Excl.enc (v : Excl) : Bytes := leBytes 1 v.list ++ v.type ++ leBytes 1 v.waiver

def Excl.dec (b : Bytes) : Option (Excl × Bytes) := do
  let (list, b) ← rdLE 1 b
  let (type, b) ← rdId 9 b
  let (waiver, b) ← rdLE 1 b
  pure ({ list, type, waiver }, b)

def Pdeath.enc (v : Pdeath) : Bytes := leBytes 1 v.proof

def Pdeath.dec (b : Bytes) : Option (Pdeath × Bytes) := do
  let (proof, b) ← rdLE 1 b
  pure ({ proof }, b)

def Ack.enc (v : Ack) : Bytes := v.pay ++ leBytes 1 v.status ++ leBytes 8 v.amount ++ v.trace

def Ack.dec (b : Bytes) : Option (Ack × Bytes) := do
  let (pay, b) ← rdBlk 72 b
  let (status, b) ← rdLE 1 b
  let (amount, b) ← rdLE 8 b
  let (trace, b) ← rdId 51 b
  pure ({ pay, status, amount, trace }, b)

def Disc.enc (v : Disc) : Bytes := leBytes 1 v.event ++ v.pay ++ leBytes 8 v.amount ++ v.caseId

def Disc.dec (b : Bytes) : Option (Disc × Bytes) := do
  let (event, b) ← rdLE 1 b
  let (pay, b) ← rdBlk 72 b
  let (amount, b) ← rdLE 8 b
  let (caseId, b) ← rdId 31 b
  pure ({ event, pay, amount, caseId }, b)

def Recov.enc (v : Recov) : Bytes := v.pay ++ leBytes 8 v.amount ++ leBytes 1 v.source ++ v.ref

def Recov.dec (b : Bytes) : Option (Recov × Bytes) := do
  let (pay, b) ← rdBlk 72 b
  let (amount, b) ← rdLE 8 b
  let (source, b) ← rdLE 1 b
  let (ref, b) ← rdId 51 b
  pure ({ pay, amount, source, ref }, b)

/-- Field widths: every number fits its width and every block has its width. -/
def Elig.WF (v : Elig) : Prop :=
  v.status < 256 ∧ v.basis < 256 ∧ idOk 21 v.program = true ∧ idOk 21 v.aid = true ∧
    v.determined < 4294967296 ∧ v.notice < 4294967296
def Death.WF (v : Death) : Prop := v.proof < 256 ∧ v.record.length = 64
def Excl.WF (v : Excl) : Prop := v.list < 256 ∧ idOk 9 v.type = true ∧ v.waiver < 256
def Pdeath.WF (v : Pdeath) : Prop := v.proof < 256
def Ack.WF (v : Ack) : Prop :=
  v.pay.length = 72 ∧ v.status < 256 ∧ v.amount < 18446744073709551616 ∧ idOk 51 v.trace = true
def Disc.WF (v : Disc) : Prop :=
  v.event < 256 ∧ v.pay.length = 72 ∧ v.amount < 18446744073709551616 ∧ idOk 31 v.caseId = true
def Recov.WF (v : Recov) : Prop :=
  v.pay.length = 72 ∧ v.amount < 18446744073709551616 ∧ v.source < 256 ∧ idOk 51 v.ref = true

theorem Elig.dec_enc (v : Elig) (h : v.WF) (r : Bytes) : Elig.dec (v.enc ++ r) = some (v, r) := by
  obtain ⟨status, basis, program, aid, determined, notice⟩ := v
  obtain ⟨h1, h2, h3, h4, h5, h6⟩ := h
  simp only at h1 h2 h3 h4 h5 h6
  simp [Elig.enc, Elig.dec, rdLE_enc, rdId_enc, h1, h2, h3, h4, h5, h6]

theorem Death.dec_enc (v : Death) (h : v.WF) (r : Bytes) : Death.dec (v.enc ++ r) = some (v, r) := by
  obtain ⟨proof, record⟩ := v
  obtain ⟨h1, h2⟩ := h
  simp only at h1 h2
  simp [Death.enc, Death.dec, rdLE_enc, rdBlk_enc, h1, h2]

theorem Excl.dec_enc (v : Excl) (h : v.WF) (r : Bytes) : Excl.dec (v.enc ++ r) = some (v, r) := by
  obtain ⟨list, type, waiver⟩ := v
  obtain ⟨h1, h2, h3⟩ := h
  simp only at h1 h2 h3
  simp [Excl.enc, Excl.dec, rdLE_enc, rdId_enc, h1, h2, h3]

theorem Pdeath.dec_enc (v : Pdeath) (h : v.WF) (r : Bytes) : Pdeath.dec (v.enc ++ r) = some (v, r) := by
  obtain ⟨proof⟩ := v
  simp only [Pdeath.WF] at h
  simp [Pdeath.enc, Pdeath.dec, rdLE_enc, h]

theorem Ack.dec_enc (v : Ack) (h : v.WF) (r : Bytes) : Ack.dec (v.enc ++ r) = some (v, r) := by
  obtain ⟨pay, status, amount, trace⟩ := v
  obtain ⟨h1, h2, h3, h4⟩ := h
  simp only at h1 h2 h3 h4
  simp [Ack.enc, Ack.dec, rdLE_enc, rdBlk_enc, rdId_enc, h1, h2, h3, h4]

theorem Disc.dec_enc (v : Disc) (h : v.WF) (r : Bytes) : Disc.dec (v.enc ++ r) = some (v, r) := by
  obtain ⟨event, pay, amount, caseId⟩ := v
  obtain ⟨h1, h2, h3, h4⟩ := h
  simp only at h1 h2 h3 h4
  simp [Disc.enc, Disc.dec, rdLE_enc, rdBlk_enc, rdId_enc, h1, h2, h3, h4]

theorem Recov.dec_enc (v : Recov) (h : v.WF) (r : Bytes) : Recov.dec (v.enc ++ r) = some (v, r) := by
  obtain ⟨pay, amount, source, ref⟩ := v
  obtain ⟨h1, h2, h3, h4⟩ := h
  simp only at h1 h2 h3 h4
  simp [Recov.enc, Recov.dec, rdLE_enc, rdBlk_enc, rdId_enc, h1, h2, h3, h4]

/-- Encoding after decoding: what a decoder accepts is exactly what the encoder writes, so each value has
    one encoding. -/
theorem Elig.enc_dec {b r : Bytes} {v : Elig} (h : Elig.dec b = some (v, r)) : v.enc ++ r = b := by
  unfold Elig.dec at h
  rcases h1 : rdLE 1 b with _ | ⟨status, b1⟩ <;> simp [h1] at h
  rcases h2 : rdLE 1 b1 with _ | ⟨basis, b2⟩ <;> simp [h2] at h
  rcases h3 : rdId 21 b2 with _ | ⟨program, b3⟩ <;> simp [h3] at h
  rcases h4 : rdId 21 b3 with _ | ⟨aid, b4⟩ <;> simp [h4] at h
  rcases h5 : rdLE 4 b4 with _ | ⟨determined, b5⟩ <;> simp [h5] at h
  rcases h6 : rdLE 4 b5 with _ | ⟨notice, b6⟩ <;> simp [h6] at h
  obtain ⟨rfl, rfl⟩ := h
  simp only [Elig.enc, List.append_assoc]
  rw [rdLE_dec h6, rdLE_dec h5, rdId_dec h4, rdId_dec h3, rdLE_dec h2, rdLE_dec h1]

theorem Death.enc_dec {b r : Bytes} {v : Death} (h : Death.dec b = some (v, r)) : v.enc ++ r = b := by
  unfold Death.dec at h
  rcases h1 : rdLE 1 b with _ | ⟨proof, b1⟩ <;> simp [h1] at h
  rcases h2 : rdBlk 64 b1 with _ | ⟨record, b2⟩ <;> simp [h2] at h
  obtain ⟨rfl, rfl⟩ := h
  simp only [Death.enc, List.append_assoc]
  rw [rdBlk_dec h2, rdLE_dec h1]

theorem Excl.enc_dec {b r : Bytes} {v : Excl} (h : Excl.dec b = some (v, r)) : v.enc ++ r = b := by
  unfold Excl.dec at h
  rcases h1 : rdLE 1 b with _ | ⟨list, b1⟩ <;> simp [h1] at h
  rcases h2 : rdId 9 b1 with _ | ⟨type, b2⟩ <;> simp [h2] at h
  rcases h3 : rdLE 1 b2 with _ | ⟨waiver, b3⟩ <;> simp [h3] at h
  obtain ⟨rfl, rfl⟩ := h
  simp only [Excl.enc, List.append_assoc]
  rw [rdLE_dec h3, rdId_dec h2, rdLE_dec h1]

theorem Pdeath.enc_dec {b r : Bytes} {v : Pdeath} (h : Pdeath.dec b = some (v, r)) : v.enc ++ r = b := by
  unfold Pdeath.dec at h
  rcases h1 : rdLE 1 b with _ | ⟨proof, b1⟩ <;> simp [h1] at h
  obtain ⟨rfl, rfl⟩ := h
  simp only [Pdeath.enc]
  rw [rdLE_dec h1]

theorem Ack.enc_dec {b r : Bytes} {v : Ack} (h : Ack.dec b = some (v, r)) : v.enc ++ r = b := by
  unfold Ack.dec at h
  rcases h1 : rdBlk 72 b with _ | ⟨pay, b1⟩ <;> simp [h1] at h
  rcases h2 : rdLE 1 b1 with _ | ⟨status, b2⟩ <;> simp [h2] at h
  rcases h3 : rdLE 8 b2 with _ | ⟨amount, b3⟩ <;> simp [h3] at h
  rcases h4 : rdId 51 b3 with _ | ⟨trace, b4⟩ <;> simp [h4] at h
  obtain ⟨rfl, rfl⟩ := h
  simp only [Ack.enc, List.append_assoc]
  rw [rdId_dec h4, rdLE_dec h3, rdLE_dec h2, rdBlk_dec h1]

theorem Disc.enc_dec {b r : Bytes} {v : Disc} (h : Disc.dec b = some (v, r)) : v.enc ++ r = b := by
  unfold Disc.dec at h
  rcases h1 : rdLE 1 b with _ | ⟨event, b1⟩ <;> simp [h1] at h
  rcases h2 : rdBlk 72 b1 with _ | ⟨pay, b2⟩ <;> simp [h2] at h
  rcases h3 : rdLE 8 b2 with _ | ⟨amount, b3⟩ <;> simp [h3] at h
  rcases h4 : rdId 31 b3 with _ | ⟨caseId, b4⟩ <;> simp [h4] at h
  obtain ⟨rfl, rfl⟩ := h
  simp only [Disc.enc, List.append_assoc]
  rw [rdId_dec h4, rdLE_dec h3, rdBlk_dec h2, rdLE_dec h1]

theorem Recov.enc_dec {b r : Bytes} {v : Recov} (h : Recov.dec b = some (v, r)) : v.enc ++ r = b := by
  unfold Recov.dec at h
  rcases h1 : rdBlk 72 b with _ | ⟨pay, b1⟩ <;> simp [h1] at h
  rcases h2 : rdLE 8 b1 with _ | ⟨amount, b2⟩ <;> simp [h2] at h
  rcases h3 : rdLE 1 b2 with _ | ⟨source, b3⟩ <;> simp [h3] at h
  rcases h4 : rdId 51 b3 with _ | ⟨ref, b4⟩ <;> simp [h4] at h
  obtain ⟨rfl, rfl⟩ := h
  simp only [Recov.enc, List.append_assoc]
  rw [rdId_dec h4, rdLE_dec h3, rdLE_dec h2, rdBlk_dec h1]

/-- What decodes is well formed: widths, canonical identifiers (so a dropped check would fail here). -/
theorem Elig.dec_wf {b r : Bytes} {v : Elig} (h : Elig.dec b = some (v, r)) : v.WF := by
  unfold Elig.dec at h
  rcases h1 : rdLE 1 b with _ | ⟨status, b1⟩ <;> simp [h1] at h
  rcases h2 : rdLE 1 b1 with _ | ⟨basis, b2⟩ <;> simp [h2] at h
  rcases h3 : rdId 21 b2 with _ | ⟨program, b3⟩ <;> simp [h3] at h
  rcases h4 : rdId 21 b3 with _ | ⟨aid, b4⟩ <;> simp [h4] at h
  rcases h5 : rdLE 4 b4 with _ | ⟨determined, b5⟩ <;> simp [h5] at h
  rcases h6 : rdLE 4 b5 with _ | ⟨notice, b6⟩ <;> simp [h6] at h
  obtain ⟨rfl, rfl⟩ := h
  exact ⟨by simpa using rdLE_lt h1, by simpa using rdLE_lt h2, rdId_ok h3, rdId_ok h4,
    by simpa using rdLE_lt h5, by simpa using rdLE_lt h6⟩

theorem Death.dec_wf {b r : Bytes} {v : Death} (h : Death.dec b = some (v, r)) : v.WF := by
  unfold Death.dec at h
  rcases h1 : rdLE 1 b with _ | ⟨proof, b1⟩ <;> simp [h1] at h
  rcases h2 : rdBlk 64 b1 with _ | ⟨record, b2⟩ <;> simp [h2] at h
  obtain ⟨rfl, rfl⟩ := h
  exact ⟨by simpa using rdLE_lt h1, rdBlk_length h2⟩

theorem Excl.dec_wf {b r : Bytes} {v : Excl} (h : Excl.dec b = some (v, r)) : v.WF := by
  unfold Excl.dec at h
  rcases h1 : rdLE 1 b with _ | ⟨list, b1⟩ <;> simp [h1] at h
  rcases h2 : rdId 9 b1 with _ | ⟨type, b2⟩ <;> simp [h2] at h
  rcases h3 : rdLE 1 b2 with _ | ⟨waiver, b3⟩ <;> simp [h3] at h
  obtain ⟨rfl, rfl⟩ := h
  exact ⟨by simpa using rdLE_lt h1, rdId_ok h2, by simpa using rdLE_lt h3⟩

theorem Pdeath.dec_wf {b r : Bytes} {v : Pdeath} (h : Pdeath.dec b = some (v, r)) : v.WF := by
  unfold Pdeath.dec at h
  rcases h1 : rdLE 1 b with _ | ⟨proof, b1⟩ <;> simp [h1] at h
  obtain ⟨rfl, rfl⟩ := h
  show proof < 256
  simpa using rdLE_lt h1

theorem Ack.dec_wf {b r : Bytes} {v : Ack} (h : Ack.dec b = some (v, r)) : v.WF := by
  unfold Ack.dec at h
  rcases h1 : rdBlk 72 b with _ | ⟨pay, b1⟩ <;> simp [h1] at h
  rcases h2 : rdLE 1 b1 with _ | ⟨status, b2⟩ <;> simp [h2] at h
  rcases h3 : rdLE 8 b2 with _ | ⟨amount, b3⟩ <;> simp [h3] at h
  rcases h4 : rdId 51 b3 with _ | ⟨trace, b4⟩ <;> simp [h4] at h
  obtain ⟨rfl, rfl⟩ := h
  exact ⟨rdBlk_length h1, by simpa using rdLE_lt h2, by simpa using rdLE_lt h3, rdId_ok h4⟩

theorem Disc.dec_wf {b r : Bytes} {v : Disc} (h : Disc.dec b = some (v, r)) : v.WF := by
  unfold Disc.dec at h
  rcases h1 : rdLE 1 b with _ | ⟨event, b1⟩ <;> simp [h1] at h
  rcases h2 : rdBlk 72 b1 with _ | ⟨pay, b2⟩ <;> simp [h2] at h
  rcases h3 : rdLE 8 b2 with _ | ⟨amount, b3⟩ <;> simp [h3] at h
  rcases h4 : rdId 31 b3 with _ | ⟨caseId, b4⟩ <;> simp [h4] at h
  obtain ⟨rfl, rfl⟩ := h
  exact ⟨by simpa using rdLE_lt h1, rdBlk_length h2, by simpa using rdLE_lt h3, rdId_ok h4⟩

theorem Recov.dec_wf {b r : Bytes} {v : Recov} (h : Recov.dec b = some (v, r)) : v.WF := by
  unfold Recov.dec at h
  rcases h1 : rdBlk 72 b with _ | ⟨pay, b1⟩ <;> simp [h1] at h
  rcases h2 : rdLE 8 b1 with _ | ⟨amount, b2⟩ <;> simp [h2] at h
  rcases h3 : rdLE 1 b2 with _ | ⟨source, b3⟩ <;> simp [h3] at h
  rcases h4 : rdId 51 b3 with _ | ⟨ref, b4⟩ <;> simp [h4] at h
  obtain ⟨rfl, rfl⟩ := h
  exact ⟨rdBlk_length h1, by simpa using rdLE_lt h2, by simpa using rdLE_lt h3, rdId_ok h4⟩

/-- Value lengths, as the kinds table gives them. -/
theorem Elig.enc_length (v : Elig) (h : v.WF) : v.enc.length = 52 := by
  obtain ⟨_, _, h3, h4, _, _⟩ := h
  simp [Elig.enc, leBytes_length, idOk_length h3, idOk_length h4]
theorem Death.enc_length (v : Death) (h : v.WF) : v.enc.length = 65 := by
  simp [Death.enc, leBytes_length, h.2]
theorem Excl.enc_length (v : Excl) (h : v.WF) : v.enc.length = 11 := by
  simp [Excl.enc, leBytes_length, idOk_length h.2.1]
theorem Pdeath.enc_length (v : Pdeath) : v.enc.length = 1 := by
  simp [Pdeath.enc, leBytes_length]
theorem Ack.enc_length (v : Ack) (h : v.WF) : v.enc.length = 132 := by
  obtain ⟨h1, _, _, h4⟩ := h
  simp [Ack.enc, leBytes_length, h1, idOk_length h4]
theorem Disc.enc_length (v : Disc) (h : v.WF) : v.enc.length = 112 := by
  obtain ⟨_, h2, _, h4⟩ := h
  simp [Disc.enc, leBytes_length, h2, idOk_length h4]
theorem Recov.enc_length (v : Recov) (h : v.WF) : v.enc.length = 132 := by
  obtain ⟨h1, _, _, h4⟩ := h
  simp [Recov.enc, leBytes_length, h1, idOk_length h4]

/-! ## The value of a fact row, by kind -/

inductive Value where
  | elig (v : Elig)
  | death (v : Death)
  | excl (v : Excl)
  | pdeath (v : Pdeath)
  | ack (v : Ack)
  | disc (v : Disc)
  | recov (v : Recov)
  deriving BEq, Repr

def Value.kind : Value → Nat
  | .elig _ => 1 | .death _ => 2 | .excl _ => 3 | .pdeath _ => 4
  | .ack _ => 5 | .disc _ => 6 | .recov _ => 7

def Value.enc : Value → Bytes
  | .elig v => v.enc | .death v => v.enc | .excl v => v.enc | .pdeath v => v.enc
  | .ack v => v.enc | .disc v => v.enc | .recov v => v.enc

/-- Decode the value of kind `k`; any kind outside 1 to 7 is refused. -/
def Value.dec (k : Nat) (b : Bytes) : Option (Value × Bytes) :=
  match k with
  | 1 => (Elig.dec b).map fun (v, r) => (.elig v, r)
  | 2 => (Death.dec b).map fun (v, r) => (.death v, r)
  | 3 => (Excl.dec b).map fun (v, r) => (.excl v, r)
  | 4 => (Pdeath.dec b).map fun (v, r) => (.pdeath v, r)
  | 5 => (Ack.dec b).map fun (v, r) => (.ack v, r)
  | 6 => (Disc.dec b).map fun (v, r) => (.disc v, r)
  | 7 => (Recov.dec b).map fun (v, r) => (.recov v, r)
  | _ => none

def Value.WF : Value → Prop
  | .elig v => v.WF | .death v => v.WF | .excl v => v.WF | .pdeath v => v.WF
  | .ack v => v.WF | .disc v => v.WF | .recov v => v.WF

theorem Value.dec_enc (v : Value) (h : v.WF) (r : Bytes) :
    Value.dec v.kind (v.enc ++ r) = some (v, r) := by
  cases v <;> simp_all [Value.kind, Value.enc, Value.dec, Value.WF, Elig.dec_enc, Death.dec_enc,
    Excl.dec_enc, Pdeath.dec_enc, Ack.dec_enc, Disc.dec_enc, Recov.dec_enc]

theorem Value.enc_dec {k : Nat} {b r : Bytes} {v : Value} (h : Value.dec k b = some (v, r)) :
    v.enc ++ r = b ∧ v.kind = k := by
  match k with
  | 0 => simp [Value.dec] at h
  | 1 =>
    cases hd : Elig.dec b with
    | none => simp [Value.dec, hd] at h
    | some p => obtain ⟨v', r'⟩ := p; simp [Value.dec, hd] at h; obtain ⟨rfl, rfl⟩ := h; exact ⟨Elig.enc_dec hd, rfl⟩
  | 2 =>
    cases hd : Death.dec b with
    | none => simp [Value.dec, hd] at h
    | some p => obtain ⟨v', r'⟩ := p; simp [Value.dec, hd] at h; obtain ⟨rfl, rfl⟩ := h; exact ⟨Death.enc_dec hd, rfl⟩
  | 3 =>
    cases hd : Excl.dec b with
    | none => simp [Value.dec, hd] at h
    | some p => obtain ⟨v', r'⟩ := p; simp [Value.dec, hd] at h; obtain ⟨rfl, rfl⟩ := h; exact ⟨Excl.enc_dec hd, rfl⟩
  | 4 =>
    cases hd : Pdeath.dec b with
    | none => simp [Value.dec, hd] at h
    | some p => obtain ⟨v', r'⟩ := p; simp [Value.dec, hd] at h; obtain ⟨rfl, rfl⟩ := h; exact ⟨Pdeath.enc_dec hd, rfl⟩
  | 5 =>
    cases hd : Ack.dec b with
    | none => simp [Value.dec, hd] at h
    | some p => obtain ⟨v', r'⟩ := p; simp [Value.dec, hd] at h; obtain ⟨rfl, rfl⟩ := h; exact ⟨Ack.enc_dec hd, rfl⟩
  | 6 =>
    cases hd : Disc.dec b with
    | none => simp [Value.dec, hd] at h
    | some p => obtain ⟨v', r'⟩ := p; simp [Value.dec, hd] at h; obtain ⟨rfl, rfl⟩ := h; exact ⟨Disc.enc_dec hd, rfl⟩
  | 7 =>
    cases hd : Recov.dec b with
    | none => simp [Value.dec, hd] at h
    | some p => obtain ⟨v', r'⟩ := p; simp [Value.dec, hd] at h; obtain ⟨rfl, rfl⟩ := h; exact ⟨Recov.enc_dec hd, rfl⟩
  | k + 8 => simp [Value.dec] at h

theorem Value.dec_wf {k : Nat} {b r : Bytes} {v : Value} (h : Value.dec k b = some (v, r)) : v.WF := by
  match k with
  | 0 => simp [Value.dec] at h
  | 1 =>
    cases hd : Elig.dec b with
    | none => simp [Value.dec, hd] at h
    | some p => obtain ⟨v', r'⟩ := p; simp [Value.dec, hd] at h; obtain ⟨rfl, rfl⟩ := h; exact Elig.dec_wf hd
  | 2 =>
    cases hd : Death.dec b with
    | none => simp [Value.dec, hd] at h
    | some p => obtain ⟨v', r'⟩ := p; simp [Value.dec, hd] at h; obtain ⟨rfl, rfl⟩ := h; exact Death.dec_wf hd
  | 3 =>
    cases hd : Excl.dec b with
    | none => simp [Value.dec, hd] at h
    | some p => obtain ⟨v', r'⟩ := p; simp [Value.dec, hd] at h; obtain ⟨rfl, rfl⟩ := h; exact Excl.dec_wf hd
  | 4 =>
    cases hd : Pdeath.dec b with
    | none => simp [Value.dec, hd] at h
    | some p => obtain ⟨v', r'⟩ := p; simp [Value.dec, hd] at h; obtain ⟨rfl, rfl⟩ := h; exact Pdeath.dec_wf hd
  | 5 =>
    cases hd : Ack.dec b with
    | none => simp [Value.dec, hd] at h
    | some p => obtain ⟨v', r'⟩ := p; simp [Value.dec, hd] at h; obtain ⟨rfl, rfl⟩ := h; exact Ack.dec_wf hd
  | 6 =>
    cases hd : Disc.dec b with
    | none => simp [Value.dec, hd] at h
    | some p => obtain ⟨v', r'⟩ := p; simp [Value.dec, hd] at h; obtain ⟨rfl, rfl⟩ := h; exact Disc.dec_wf hd
  | 7 =>
    cases hd : Recov.dec b with
    | none => simp [Value.dec, hd] at h
    | some p => obtain ⟨v', r'⟩ := p; simp [Value.dec, hd] at h; obtain ⟨rfl, rfl⟩ := h; exact Recov.dec_wf hd
  | k + 8 => simp [Value.dec] at h

theorem Value.dec_unknown(k : Nat) (b : Bytes) (h : k = 0 ∨ 7 < k) : Value.dec k b = none := by
  match k, h with
  | 0, _ => rfl
  | k + 8, _ => rfl

theorem Value.enc_length (v : Value) (h : v.WF) : v.enc.length ≤ valueBytes := by
  cases v <;> simp_all [Value.enc, Value.WF, valueBytes, Elig.enc_length, Death.enc_length,
    Excl.enc_length, Pdeath.enc_length, Ack.enc_length, Disc.enc_length, Recov.enc_length]

/-! ## Fact row (§2.4) -/

/-- A fact row.  `lineUntil` is the design's `until`. -/
structure Fact where
  op : Nat
  subject : Bytes
  sid : Bytes
  vstart : Nat
  vstop : Nat
  lineUntil : Nat
  receipt : Nat
  roff : Nat
  value : Value
  deriving BEq, Repr

/-- The subject: 32 bytes; of a provider (kinds 3 and 4) an identifier of 21 bytes then 11 zeros. -/
def subjOk (k : Nat) (s : Bytes) : Bool :=
  s.length == 32 && ((k != 3 && k != 4) || (idOk 21 (s.take 21) && allZero (s.drop 21)))

theorem subjOk_length {k : Nat} {s : Bytes} (h : subjOk k s = true) : s.length = 32 := by
  unfold subjOk at h
  simp only [Bool.and_eq_true, beq_iff_eq] at h
  exact h.1

/-- Width, operation 0 to 2 (0 assert, 1 void, 2 end), a span that does not run backwards unless the row is an end row
    (its stop is the day before the full file that ended the statement), a canonical subject. -/
def Fact.WF (f : Fact) : Prop :=
  f.op < 3 ∧ subjOk f.value.kind f.subject = true ∧ f.sid.length = 32 ∧ f.vstart < 4294967296 ∧
    f.vstop < 4294967296 ∧ f.lineUntil < 4294967296 ∧ f.receipt < 1099511627776 ∧
    f.roff < 1099511627776 ∧ f.value.WF ∧ (f.op = 2 ∨ f.vstart ≤ f.vstop)

def Fact.enc (f : Fact) : Bytes :=
  leBytes 1 f.value.kind ++ leBytes 1 f.op ++ f.subject ++ f.sid ++ leBytes 4 f.vstart ++
    leBytes 4 f.vstop ++ leBytes 4 f.lineUntil ++ leBytes 5 f.receipt ++ leBytes 5 f.roff ++
    f.value.enc ++ List.replicate (valueBytes - f.value.enc.length) 0

/-- The body after the length check.  The padding after the value must be zero. -/
def Fact.decBody (b : Bytes) : Option Fact := do
  let (k, b) ← rdLE 1 b
  let (op, b) ← rdLE 1 b
  let (subject, b) ← rdBlk 32 b
  let (sid, b) ← rdBlk 32 b
  let (vstart, b) ← rdLE 4 b
  let (vstop, b) ← rdLE 4 b
  let (lineUntil, b) ← rdLE 4 b
  let (receipt, b) ← rdLE 5 b
  let (roff, b) ← rdLE 5 b
  let (value, pad) ← Value.dec k b
  if op < 3 && (op == 2 || decide (vstart ≤ vstop)) && subjOk k subject && allZero pad then
    pure { op, subject, sid, vstart, vstop, lineUntil, receipt, roff, value }
  else none

/-- Decode a fact row: exactly 245 bytes, a kind from 1 to 7, a canonical row, zero padding; otherwise none. -/
def Fact.dec (b : Bytes) : Option Fact :=
  if b.length = bodyBytes then Fact.decBody b else none

theorem Value.kind_lt (v : Value) : v.kind < 256 := by cases v <;> simp [Value.kind]

theorem Fact.enc_length (f : Fact) (h : f.WF) : f.enc.length = bodyBytes := by
  obtain ⟨_, h2, h3, _, _, _, _, _, h9, _⟩ := h
  have := Value.enc_length f.value h9
  simp [Fact.enc, leBytes_length, subjOk_length h2, h3, bodyBytes, valueBytes] at this ⊢
  omega

theorem Fact.dec_enc (f : Fact) (h : f.WF) : Fact.dec f.enc = some f := by
  have hl := Fact.enc_length f h
  unfold Fact.dec
  rw [if_pos hl]
  obtain ⟨op, subject, sid, vstart, vstop, lineUntil, receipt, roff, value⟩ := f
  obtain ⟨h1, h2, h3, h4, h5, h6, h7, h8, h9, h10⟩ := h
  simp only at h1 h2 h3 h4 h5 h6 h7 h8 h9 h10
  have h1' : op < 256 := by omega
  have h2' := subjOk_length h2
  have h10' : ¬op = 2 → vstart ≤ vstop := fun hn => h10.resolve_left hn
  simp [Fact.enc, Fact.decBody, List.append_assoc, rdLE_enc, rdBlk_enc, h1, h1', h2, h2', h3, h4, h5, h6, h7,
    h8, Value.kind_lt value, Value.dec_enc value h9, allZero_replicate]
  exact h10'

theorem Fact.enc_dec {b : Bytes} {f : Fact} (h : Fact.dec b = some f) : f.enc = b := by
  unfold Fact.dec at h
  split at h
  · rename_i hb
    unfold Fact.decBody at h
    rcases h1 : rdLE 1 b with _ | ⟨k, b1⟩ <;> simp [h1] at h
    rcases h2 : rdLE 1 b1 with _ | ⟨op, b2⟩ <;> simp [h2] at h
    rcases h3 : rdBlk 32 b2 with _ | ⟨subject, b3⟩ <;> simp [h3] at h
    rcases h4 : rdBlk 32 b3 with _ | ⟨sid, b4⟩ <;> simp [h4] at h
    rcases h5 : rdLE 4 b4 with _ | ⟨vstart, b5⟩ <;> simp [h5] at h
    rcases h6 : rdLE 4 b5 with _ | ⟨vstop, b6⟩ <;> simp [h6] at h
    rcases h7 : rdLE 4 b6 with _ | ⟨lineUntil, b7⟩ <;> simp [h7] at h
    rcases h8 : rdLE 5 b7 with _ | ⟨receipt, b8⟩ <;> simp [h8] at h
    rcases h9 : rdLE 5 b8 with _ | ⟨roff, b9⟩ <;> simp [h9] at h
    rcases hv : Value.dec k b9 with _ | ⟨value, pad⟩ <;> simp [hv] at h
    have hz : allZero pad = true := by simp_all
    obtain ⟨_, rfl⟩ := h
    obtain ⟨hv1, hv2⟩ := Value.enc_dec hv
    have l1 := congrArg List.length (rdLE_dec h1)
    have l2 := congrArg List.length (rdLE_dec h2)
    have l3 := congrArg List.length (rdBlk_dec h3)
    have l4 := congrArg List.length (rdBlk_dec h4)
    have l5 := congrArg List.length (rdLE_dec h5)
    have l6 := congrArg List.length (rdLE_dec h6)
    have l7 := congrArg List.length (rdLE_dec h7)
    have l8 := congrArg List.length (rdLE_dec h8)
    have l9 := congrArg List.length (rdLE_dec h9)
    have l10 := congrArg List.length hv1
    have s3 := rdBlk_length h3
    have s4 := rdBlk_length h4
    simp only [List.length_append, leBytes_length] at l1 l2 l3 l4 l5 l6 l7 l8 l9 l10
    have hpad := allZero_eq pad hz
    have hlen : valueBytes - value.enc.length = pad.length := by
      simp [bodyBytes, valueBytes] at hb ⊢; omega
    simp only [Fact.enc, List.append_assoc]
    rw [hv2, hlen, ← hpad, hv1, rdLE_dec h9, rdLE_dec h8, rdLE_dec h7, rdLE_dec h6, rdLE_dec h5,
      rdBlk_dec h4, rdBlk_dec h3, rdLE_dec h2, rdLE_dec h1]
  · cases h

/-- Whatever decodes is a well-formed row: this is what fails if any canonical check is dropped. -/
theorem Fact.dec_wf {b : Bytes} {f : Fact} (h : Fact.dec b = some f) : f.WF := by
  unfold Fact.dec at h
  split at h
  · unfold Fact.decBody at h
    rcases h1 : rdLE 1 b with _ | ⟨k, b1⟩ <;> simp [h1] at h
    rcases h2 : rdLE 1 b1 with _ | ⟨op, b2⟩ <;> simp [h2] at h
    rcases h3 : rdBlk 32 b2 with _ | ⟨subject, b3⟩ <;> simp [h3] at h
    rcases h4 : rdBlk 32 b3 with _ | ⟨sid, b4⟩ <;> simp [h4] at h
    rcases h5 : rdLE 4 b4 with _ | ⟨vstart, b5⟩ <;> simp [h5] at h
    rcases h6 : rdLE 4 b5 with _ | ⟨vstop, b6⟩ <;> simp [h6] at h
    rcases h7 : rdLE 4 b6 with _ | ⟨lineUntil, b7⟩ <;> simp [h7] at h
    rcases h8 : rdLE 5 b7 with _ | ⟨receipt, b8⟩ <;> simp [h8] at h
    rcases h9 : rdLE 5 b8 with _ | ⟨roff, b9⟩ <;> simp [h9] at h
    rcases hv : Value.dec k b9 with _ | ⟨value, pad⟩ <;> simp [hv] at h
    obtain ⟨hc, rfl⟩ := h
    have hc' : op < 3 ∧ subjOk k subject = true ∧ (op = 2 ∨ vstart ≤ vstop) :=
      ⟨hc.1.1.1, hc.1.2, hc.1.1.2⟩
    have hk := (Value.enc_dec hv).2
    subst hk
    exact ⟨hc'.1, hc'.2.1, rdBlk_length h4, by simpa using rdLE_lt h5, by simpa using rdLE_lt h6,
      by simpa using rdLE_lt h7, by simpa using rdLE_lt h8, by simpa using rdLE_lt h9,
      Value.dec_wf hv, hc'.2.2⟩
  · cases h

theorem Fact.dec_wrong_length(b : Bytes) (h : b.length ≠ bodyBytes) : Fact.dec b = none := by
  simp [Fact.dec, h]

/-! ## Source receipt (§2.3) -/

section Receipt
-- The receipt's eighteen fields make its definitions and proofs long; the limit is raised for this
-- section only.
set_option maxHeartbeats 4000000

def receiptTag : Nat := 0x40

structure Receipt where
  src : Nat
  cover : Nat
  kb : Nat
  asof : Nat
  cfrom : Nat
  fseq : Nat
  file : Bytes
  sender : Bytes
  channel : Nat
  key : Nat
  reader : Nat
  reread : Nat
  rows : Nat
  admitted : Nat
  same : Nat
  quar : Nat
  scope : Bytes
  frows : Nat
  /-- The hash of the frame's reference rows (`RefSet.rdOf`) in a stored receipt; zero on the wire and without any. -/
  rd : Bytes := List.replicate 64 0
  deriving BEq, Repr

def Receipt.WF (r : Receipt) : Prop :=
  r.src < 65536 ∧ r.cover < 256 ∧ r.kb < 1099511627776 ∧ r.asof < 4294967296 ∧
    r.cfrom < 4294967296 ∧ r.fseq < 18446744073709551616 ∧ r.file.length = 64 ∧
    idOk 21 r.sender = true ∧ r.channel < 256 ∧ r.key < 65536 ∧ r.reader < 65536 ∧
    r.reread < 1099511627776 ∧ r.rows < 4294967296 ∧ r.admitted < 4294967296 ∧
    r.same < 4294967296 ∧ r.quar < 4294967296 ∧ idOk 21 r.scope = true ∧
    r.frows < 18446744073709551616 ∧ r.rd.length = 64

def Receipt.enc (r : Receipt) : Bytes :=
  leBytes 1 receiptTag ++ leBytes 2 r.src ++ leBytes 1 r.cover ++ leBytes 5 r.kb ++
    leBytes 4 r.asof ++ leBytes 4 r.cfrom ++ leBytes 8 r.fseq ++ r.file ++ r.sender ++
    leBytes 1 r.channel ++ leBytes 2 r.key ++ leBytes 2 r.reader ++ leBytes 5 r.reread ++
    leBytes 4 r.rows ++ leBytes 4 r.admitted ++ leBytes 4 r.same ++ leBytes 4 r.quar ++
    r.scope ++ leBytes 8 r.frows ++ r.rd ++ List.replicate 16 0

def Receipt.decBody (b : Bytes) : Option Receipt := do
  let (tag, b) ← rdLE 1 b
  if tag = receiptTag then
    let (src, b) ← rdLE 2 b
    let (cover, b) ← rdLE 1 b
    let (kb, b) ← rdLE 5 b
    let (asof, b) ← rdLE 4 b
    let (cfrom, b) ← rdLE 4 b
    let (fseq, b) ← rdLE 8 b
    let (file, b) ← rdBlk 64 b
    let (sender, b) ← rdId 21 b
    let (channel, b) ← rdLE 1 b
    let (key, b) ← rdLE 2 b
    let (reader, b) ← rdLE 2 b
    let (reread, b) ← rdLE 5 b
    let (rows, b) ← rdLE 4 b
    let (admitted, b) ← rdLE 4 b
    let (same, b) ← rdLE 4 b
    let (quar, b) ← rdLE 4 b
    let (scope, b) ← rdId 21 b
    let (frows, b) ← rdLE 8 b
    let (rd, pad) ← rdBlk 64 b
    if allZero pad then
      pure ⟨src, cover, kb, asof, cfrom, fseq, file, sender, channel, key, reader, reread, rows,
        admitted, same, quar, scope, frows, rd⟩
    else none
  else none

/-- Decode a receipt: exactly 245 bytes, tag 0x40, canonical identifiers, zero padding; otherwise none. -/
def Receipt.dec (b : Bytes) : Option Receipt :=
  if b.length = bodyBytes then Receipt.decBody b else none

theorem Receipt.enc_length (r : Receipt) (h : r.WF) : r.enc.length = bodyBytes := by
  obtain ⟨_, _, _, _, _, _, h7, h8, _, _, _, _, _, _, _, _, h17, _, h19⟩ := h
  simp only [Receipt.enc, List.length_append, leBytes_length, List.length_replicate, h7,
    idOk_length h8, idOk_length h17, h19, bodyBytes]

theorem Receipt.dec_enc (r : Receipt) (h : r.WF) : Receipt.dec r.enc = some r := by
  have hl := Receipt.enc_length r h
  unfold Receipt.dec
  rw [if_pos hl]
  obtain ⟨src, cover, kb, asof, cfrom, fseq, file, sender, channel, key, reader, reread, rows,
    admitted, same, quar, scope, frows, rd⟩ := r
  obtain ⟨h1, h2, h3, h4, h5, h6, h7, h8, h9, h10, h11, h12, h13, h14, h15, h16, h17, h18, h19⟩ := h
  simp only at h1 h2 h3 h4 h5 h6 h7 h8 h9 h10 h11 h12 h13 h14 h15 h16 h17 h18 h19
  simp [Receipt.enc, Receipt.decBody, receiptTag, List.append_assoc, rdLE_enc, rdBlk_enc, rdId_enc, h1,
    h2, h3, h4, h5, h6, h7, h8, h9, h10, h11, h12, h13, h14, h15, h16, h17, h18, h19]
  exact allZero_replicate 16

theorem Receipt.enc_dec {b : Bytes} {r : Receipt} (h : Receipt.dec b = some r) : r.enc = b := by
  unfold Receipt.dec at h
  split at h
  · rename_i hb
    unfold Receipt.decBody at h
    rcases h0 : rdLE 1 b with _ | ⟨tag, b0⟩ <;> simp [h0] at h
    obtain ⟨ht, h⟩ := h
    rcases h1 : rdLE 2 b0 with _ | ⟨src, b1⟩ <;> simp [h1] at h
    rcases h2 : rdLE 1 b1 with _ | ⟨cover, b2⟩ <;> simp [h2] at h
    rcases h3 : rdLE 5 b2 with _ | ⟨kb, b3⟩ <;> simp [h3] at h
    rcases h4 : rdLE 4 b3 with _ | ⟨asof, b4⟩ <;> simp [h4] at h
    rcases h5 : rdLE 4 b4 with _ | ⟨cfrom, b5⟩ <;> simp [h5] at h
    rcases h6 : rdLE 8 b5 with _ | ⟨fseq, b6⟩ <;> simp [h6] at h
    rcases h7 : rdBlk 64 b6 with _ | ⟨file, b7⟩ <;> simp [h7] at h
    rcases h8 : rdId 21 b7 with _ | ⟨sender, b8⟩ <;> simp [h8] at h
    rcases h9 : rdLE 1 b8 with _ | ⟨channel, b9⟩ <;> simp [h9] at h
    rcases h10 : rdLE 2 b9 with _ | ⟨key, b10⟩ <;> simp [h10] at h
    rcases h11 : rdLE 2 b10 with _ | ⟨reader, b11⟩ <;> simp [h11] at h
    rcases h12 : rdLE 5 b11 with _ | ⟨reread, b12⟩ <;> simp [h12] at h
    rcases h13 : rdLE 4 b12 with _ | ⟨rows, b13⟩ <;> simp [h13] at h
    rcases h14 : rdLE 4 b13 with _ | ⟨admitted, b14⟩ <;> simp [h14] at h
    rcases h15 : rdLE 4 b14 with _ | ⟨same, b15⟩ <;> simp [h15] at h
    rcases h16 : rdLE 4 b15 with _ | ⟨quar, b16⟩ <;> simp [h16] at h
    rcases h17 : rdId 21 b16 with _ | ⟨scope, b17⟩ <;> simp [h17] at h
    rcases h18 : rdLE 8 b17 with _ | ⟨frows, b18⟩ <;> simp [h18] at h
    rcases h19 : rdBlk 64 b18 with _ | ⟨rd, pad⟩ <;> simp [h19] at h
    have hz : allZero pad = true := by simp_all
    have hpad := allZero_eq pad hz
    have l0 := congrArg List.length (rdLE_dec h0)
    have l1 := congrArg List.length (rdLE_dec h1)
    have l2 := congrArg List.length (rdLE_dec h2)
    have l3 := congrArg List.length (rdLE_dec h3)
    have l4 := congrArg List.length (rdLE_dec h4)
    have l5 := congrArg List.length (rdLE_dec h5)
    have l6 := congrArg List.length (rdLE_dec h6)
    have l7 := congrArg List.length (rdBlk_dec h7)
    have l8 := congrArg List.length (rdId_dec h8)
    have l9 := congrArg List.length (rdLE_dec h9)
    have l10 := congrArg List.length (rdLE_dec h10)
    have l11 := congrArg List.length (rdLE_dec h11)
    have l12 := congrArg List.length (rdLE_dec h12)
    have l13 := congrArg List.length (rdLE_dec h13)
    have l14 := congrArg List.length (rdLE_dec h14)
    have l15 := congrArg List.length (rdLE_dec h15)
    have l16 := congrArg List.length (rdLE_dec h16)
    have l17 := congrArg List.length (rdId_dec h17)
    have l18 := congrArg List.length (rdLE_dec h18)
    have l19 := congrArg List.length (rdBlk_dec h19)
    have s7 := rdBlk_length h7
    have s8 := rdId_length h8
    have s17 := rdId_length h17
    have s19 := rdBlk_length h19
    simp only [List.length_append, leBytes_length] at l0 l1 l2 l3 l4 l5 l6 l7 l8 l9 l10 l11 l12 l13 l14 l15 l16 l17 l18 l19
    have hlen : pad.length = 16 := by simp [bodyBytes] at hb; omega
    rw [hlen] at hpad
    obtain ⟨_, rfl⟩ := h
    simp only [Receipt.enc, List.append_assoc]
    rw [← hpad, ← ht, rdBlk_dec h19, rdLE_dec h18, rdId_dec h17, rdLE_dec h16, rdLE_dec h15, rdLE_dec h14, rdLE_dec h13,
      rdLE_dec h12, rdLE_dec h11, rdLE_dec h10, rdLE_dec h9, rdId_dec h8, rdBlk_dec h7, rdLE_dec h6,
      rdLE_dec h5, rdLE_dec h4, rdLE_dec h3, rdLE_dec h2, rdLE_dec h1]
    exact rdLE_dec h0
  · cases h

theorem Receipt.dec_wf {b : Bytes} {r : Receipt} (h : Receipt.dec b = some r) : r.WF := by
  unfold Receipt.dec at h
  split at h
  · unfold Receipt.decBody at h
    rcases h0 : rdLE 1 b with _ | ⟨tag, b0⟩ <;> simp [h0] at h
    obtain ⟨ht, h⟩ := h
    rcases h1 : rdLE 2 b0 with _ | ⟨src, b1⟩ <;> simp [h1] at h
    rcases h2 : rdLE 1 b1 with _ | ⟨cover, b2⟩ <;> simp [h2] at h
    rcases h3 : rdLE 5 b2 with _ | ⟨kb, b3⟩ <;> simp [h3] at h
    rcases h4 : rdLE 4 b3 with _ | ⟨asof, b4⟩ <;> simp [h4] at h
    rcases h5 : rdLE 4 b4 with _ | ⟨cfrom, b5⟩ <;> simp [h5] at h
    rcases h6 : rdLE 8 b5 with _ | ⟨fseq, b6⟩ <;> simp [h6] at h
    rcases h7 : rdBlk 64 b6 with _ | ⟨file, b7⟩ <;> simp [h7] at h
    rcases h8 : rdId 21 b7 with _ | ⟨sender, b8⟩ <;> simp [h8] at h
    rcases h9 : rdLE 1 b8 with _ | ⟨channel, b9⟩ <;> simp [h9] at h
    rcases h10 : rdLE 2 b9 with _ | ⟨key, b10⟩ <;> simp [h10] at h
    rcases h11 : rdLE 2 b10 with _ | ⟨reader, b11⟩ <;> simp [h11] at h
    rcases h12 : rdLE 5 b11 with _ | ⟨reread, b12⟩ <;> simp [h12] at h
    rcases h13 : rdLE 4 b12 with _ | ⟨rows, b13⟩ <;> simp [h13] at h
    rcases h14 : rdLE 4 b13 with _ | ⟨admitted, b14⟩ <;> simp [h14] at h
    rcases h15 : rdLE 4 b14 with _ | ⟨same, b15⟩ <;> simp [h15] at h
    rcases h16 : rdLE 4 b15 with _ | ⟨quar, b16⟩ <;> simp [h16] at h
    rcases h17 : rdId 21 b16 with _ | ⟨scope, b17⟩ <;> simp [h17] at h
    rcases h18 : rdLE 8 b17 with _ | ⟨frows, b18⟩ <;> simp [h18] at h
    rcases h19 : rdBlk 64 b18 with _ | ⟨rd, pad⟩ <;> simp [h19] at h
    obtain ⟨_, rfl⟩ := h
    exact ⟨by simpa using rdLE_lt h1, by simpa using rdLE_lt h2, by simpa using rdLE_lt h3,
      by simpa using rdLE_lt h4, by simpa using rdLE_lt h5, by simpa using rdLE_lt h6, rdBlk_length h7,
      rdId_ok h8, by simpa using rdLE_lt h9, by simpa using rdLE_lt h10, by simpa using rdLE_lt h11,
      by simpa using rdLE_lt h12, by simpa using rdLE_lt h13, by simpa using rdLE_lt h14,
      by simpa using rdLE_lt h15, by simpa using rdLE_lt h16, rdId_ok h17, by simpa using rdLE_lt h18,
      rdBlk_length h19⟩
  · cases h

end Receipt

theorem Receipt.dec_wrong_length (b : Bytes) (h : b.length ≠ bodyBytes) : Receipt.dec b = none := by
  simp [Receipt.dec, h]

/-! ## Statement order (§3.2) -/

/-- `rank(row) = (fseq, reader, roff)`: the receipt's sequence number and reader release, then the
    row's place in the file.  A larger rank is the newer statement. -/
def rank (fseq reader roff : Nat) : Nat × Nat × Nat := (fseq, reader, roff)

def Receipt.rankOf (r : Receipt) (roff : Nat) : Nat × Nat × Nat := rank r.fseq r.reader roff

/-- Lexicographic order on ranks. -/
def rankLt (a b : Nat × Nat × Nat) : Prop :=
  a.1 < b.1 ∨ (a.1 = b.1 ∧ (a.2.1 < b.2.1 ∨ (a.2.1 = b.2.1 ∧ a.2.2 < b.2.2)))

theorem rankLt_irrefl (a : Nat × Nat × Nat) : ¬ rankLt a a := by
  obtain ⟨a1, a2, a3⟩ := a
  simp only [rankLt]; omega

theorem rankLt_trans {a b c : Nat × Nat × Nat} (h1 : rankLt a b) (h2 : rankLt b c) : rankLt a c := by
  obtain ⟨a1, a2, a3⟩ := a
  obtain ⟨b1, b2, b3⟩ := b
  obtain ⟨c1, c2, c3⟩ := c
  simp only [rankLt] at *; omega

theorem rankLt_total (a b : Nat × Nat × Nat) : rankLt a b ∨ a = b ∨ rankLt b a := by
  obtain ⟨a1, a2, a3⟩ := a
  obtain ⟨b1, b2, b3⟩ := b
  simp only [rankLt, Prod.mk.injEq]; omega

/-- Two rows of one source with equal rank are one row, given that (`fseq`, `reader`) names one
    receipt (admission rules 2 and 6 make it so; that is the hypothesis `hone`). -/
theorem rank_names_row (r₁ r₂ : Receipt) (o₁ o₂ : Nat)
    (hone : r₁.fseq = r₂.fseq → r₁.reader = r₂.reader → r₁ = r₂)
    (h : r₁.rankOf o₁ = r₂.rankOf o₂) : r₁ = r₂ ∧ o₁ = o₂ := by
  simp only [Receipt.rankOf, rank, Prod.mk.injEq] at h
  exact ⟨hone h.1 h.2.1, h.2.2⟩

/-! ## Golden vectors

    One table of hand-checked bytes.  `tests/test_fact_codecs.py` reads this table from this file and
    checks the Python twin against it, so the two codecs agree on the same bytes.  Each line of the
    table is checked below when this file is built. -/

def hexVal (c : Char) : Nat := if c.isDigit then c.toNat - 48 else c.toNat - 87

def hexBytes (s : String) : Bytes :=
  let rec go : List Char → Bytes
    | a :: b :: t => UInt8.ofNat (hexVal a * 16 + hexVal b) :: go t
    | _ => []
  go s.toList

/-- Bytes `s, s+1, ...` (mod 256), `n` of them. -/
def pat (n s : Nat) : Bytes := (List.range n).map fun i => UInt8.ofNat (s + i)

/-- An identifier field of width `w`: a length byte, the text, zero padding. -/
def ident (w : Nat) (s : String) : Bytes :=
  UInt8.ofNat s.utf8ByteSize :: s.toUTF8.toList ++ List.replicate (w - 1 - s.utf8ByteSize) 0

/-- A provider subject: a 21-byte identifier, then zeros to 32 bytes. -/
def prov (s : String) : Bytes := ident 21 s ++ List.replicate 11 0

def zeros (n : Nat) : Bytes := List.replicate n 0

def m32 : Nat := 4294967295
def m40 : Nat := 1099511627775
def m64 : Nat := 18446744073709551615

def golden : List (String × String) :=
  [("elig_basic",
    "01000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f206465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f8081828305253501bfbef505bfbef505050000000007000000000101084d454449434149440000000000000000000000000000000000000000000000000000000000000000000925350100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000")
  , ("elig_edge",
    "0102000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1fc8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7000000000000000000000000ffffffffffffffffffffffff145858585858585858585858585858585858585858014100000000000000000000000000000000000000ffffffffffffffff000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000")
  , ("death_state",
    "0200030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20212232333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f5051cafe3401bfbef505bfbef50509000000000100000000020708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445460000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000")
  , ("death_federal",
    "0200030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f2021223c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b00000000ffffffffffffffff0000000000000000000001000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000")
  , ("excl_basic",
    "03000a31323334353637383930000000000000000000000000000000000000000000090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728e5d634017f503501bfbef50503000000000c0000000001063131323861310000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000")
  , ("excl_edge",
    "03010000000000000000000000000000000000000000000000000000000000000000000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f00000000bfbef50500000000ffffffffffffffffffffff083132333435363738ff0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000")
  , ("pdeath_basic",
    "04000a393837363534333231300000000000000000000000000000000000000000002122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f40cd253501bfbef505bfbef5050400000000020000000001000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000")
  , ("ack_basic",
    "050005060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f2021222324969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b57225350172253501bfbef505060000000028000000000b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f5051520139300000000000000c54524e2a312a414243313233000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000")
  , ("ack_edge",
    "050005060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20212223249798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b60000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000ffffffffffffffff00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000")
  , ("disc_basic",
    "0600060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf3126350131263501bfbef505070000000003000000000215161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c50c300000000000007434153452d37370000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000")
  , ("disc_edge",
    "0601060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0ffffffffffffffffffffffffffffffffffffffffffffff000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000ffffffffffffffff1e434343434343434343434343434343434343434343434343434343434343000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000")
  , ("recov_basic",
    "07000708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20212223242526aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c99526350195263501bfbef505080000000009000000001f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465664c1d0000000000000209504c422d5245462d31000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000")
  , ("recov_edge",
    "07000708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20212223242526abacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9ca0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000")
  , ("receipt_full",
    "400300010c0000000006253501f5fd34015976c2780000000028292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f60616263646566670953544154454d4d4953000000000000000000000001010002000000000000e8030000de0300000500000005000000084d45444943414944000000000000000000000000a00f0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000")
  , ("receipt_edge",
    "40ffff04ffffffffff0000000000000000ffffffffffffffff00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000030000ffffffffffffffffffffffffffffffffffffffffffffff145050505050505050505050505050505050505050ffffffffffffffff0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000")
  , ("receipt_rd",
    "400300010c0000000006253501f5fd34015976c2780000000028292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f60616263646566670953544154454d4d4953000000000000000000000001010002000000000000e8030000de0300000500000005000000084d45444943414944000000000000000000000000a00f0000000000004d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c00000000000000000000000000000000")
  ]

def goldenFacts : List (String × Fact) :=
  [ ("elig_basic", ⟨0, pat 32 1, pat 32 100, 20260101, 99991231, 99991231, 5, 7,
      .elig ⟨1, 1, ident 21 "MEDICAID", ident 21 "", 20260105, 0⟩⟩)
  , ("elig_edge", ⟨2, pat 32 0, pat 32 200, 0, 0, 0, m40, m40,
      .elig ⟨255, 255, ident 21 "XXXXXXXXXXXXXXXXXXXX", ident 21 "A", m32, m32⟩⟩)
  , ("death_state", ⟨0, pat 32 3, pat 32 50, 20250314, 99991231, 99991231, 9, 1,
      .death ⟨2, pat 64 7⟩⟩)
  , ("death_federal", ⟨0, pat 32 3, pat 32 60, 0, m32, m32, 0, 0, .death ⟨1, zeros 64⟩⟩)
  , ("excl_basic", ⟨0, prov "1234567890", pat 32 9, 20240101, 20271231, 99991231, 3, 12,
      .excl ⟨1, ident 9 "1128a1", 0⟩⟩)
  , ("excl_edge", ⟨1, prov "", pat 32 0, 0, 99991231, 0, m40, m40,
      .excl ⟨255, ident 9 "12345678", 255⟩⟩)
  , ("pdeath_basic", ⟨0, prov "9876543210", pat 32 33, 20260301, 99991231, 99991231, 4, 2,
      .pdeath ⟨1⟩⟩)
  , ("ack_basic", ⟨0, pat 32 5, pat 32 150, 20260210, 20260210, 99991231, 6, 40,
      .ack ⟨pat 72 11, 1, 12345, ident 51 "TRN*1*ABC123"⟩⟩)
  , ("ack_edge", ⟨0, pat 32 5, pat 32 151, 0, 0, 0, 0, 0, .ack ⟨zeros 72, 0, m64, ident 51 ""⟩⟩)
  , ("disc_basic", ⟨0, pat 32 6, pat 32 160, 20260401, 20260401, 99991231, 7, 3,
      .disc ⟨2, pat 72 21, 50000, ident 31 "CASE-77"⟩⟩)
  , ("disc_edge", ⟨1, pat 32 6, pat 32 161, m32, m32, m32, m40, m40,
      .disc ⟨255, zeros 72, m64, ident 31 "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCC"⟩⟩)
  , ("recov_basic", ⟨0, pat 32 7, pat 32 170, 20260501, 20260501, 99991231, 8, 9,
      .recov ⟨pat 72 31, 7500, 2, ident 51 "PLB-REF-1"⟩⟩)
  , ("recov_edge", ⟨0, pat 32 7, pat 32 171, 0, 0, 0, 0, 0,
      .recov ⟨zeros 72, 0, 0, ident 51 ""⟩⟩) ]

def goldenReceipts : List (String × Receipt) :=
  [ ("receipt_full", ⟨3, 1, 12, 20260102, 20250101, 2026010201, pat 64 40, ident 21 "STATEMMIS", 1,
      1, 2, 0, 1000, 990, 5, 5, ident 21 "MEDICAID", 4000, zeros 64⟩)
  , ("receipt_edge", ⟨65535, 4, m40, 0, 0, m64, zeros 64, ident 21 "", 3, 0, 65535, m40, m32, m32,
      m32, m32, ident 21 "PPPPPPPPPPPPPPPPPPPP", m64, zeros 64⟩)
  , ("receipt_rd", ⟨3, 1, 12, 20260102, 20250101, 2026010201, pat 64 40, ident 21 "STATEMMIS", 1,
      1, 2, 0, 1000, 990, 5, 5, ident 21 "MEDICAID", 4000, pat 64 77⟩) ]

def goldenOk : Bool :=
  goldenFacts.all (fun (n, f) => (golden.lookup n).map hexBytes == some f.enc &&
      Fact.dec (hexBytes ((golden.lookup n).getD "")) == some f) &&
  goldenReceipts.all (fun (n, r) => (golden.lookup n).map hexBytes == some r.enc &&
      Receipt.dec (hexBytes ((golden.lookup n).getD "")) == some r) &&
  golden.length == goldenFacts.length + goldenReceipts.length

#guard goldenOk

end BlindLedger.Gate.FactCodec
