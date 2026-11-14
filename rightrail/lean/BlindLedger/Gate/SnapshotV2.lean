import BlindLedger.Gate.Keyset

namespace BlindLedger.Gate.SnapshotV2
open Keyset (cut chop cut_app chop_flatten natBE_length SigRec SigsWf decodeSigBlock encodeSigs quorum sourceOk ksLive
  liveAt bit digestOf)

/-- Decision 11: K2's SNAPSHOT/v2 and READ-MANIFEST/v3 are on trunk, so the changed layouts take new tags (same widths
    20 and 25, so `headW`/`manW` keep their first field). -/
def tag : Bytes := [82, 82, 47, 71, 65, 84, 69, 47, 83, 78, 65, 80, 83, 72, 79, 84, 47, 118, 51, 0]
def sigTag : Bytes := "RR/GATE/SNAPSHOT/v3/SIG".toUTF8.toList ++ [0]
def manTag : Bytes := [82, 82, 47, 71, 65, 84, 69, 47, 82, 69, 65, 68, 45, 77, 65, 78, 73, 70, 69, 83, 84, 47, 118, 52, 0]
#guard tag == "RR/GATE/SNAPSHOT/v3".toUTF8.toList ++ [0]
#guard manTag == "RR/GATE/READ-MANIFEST/v4".toUTF8.toList ++ [0]

/-- 1 identity-verified, 2 provider enrolled, 3 eligible-on-date, 4 service-rendered, 5 self-declared; 0, 6..255 refused. -/
inductive Scope | IDV | ENR | ELIG | SVC | SELF deriving DecidableEq, Repr

def Scope.byte : Scope → Nat | .IDV => 1 | .ENR => 2 | .ELIG => 3 | .SVC => 4 | .SELF => 5

def Scope.ofByte : Nat → Option Scope
  | 1 => some .IDV | 2 => some .ENR | 3 => some .ELIG | 4 => some .SVC | 5 => some .SELF | _ => none

/-- K3 r2 (review F1): the reference kind a header's signed kind byte names: 1 DMF, 2 PROVIDER-DEATH, 3 EXCLUSION,
    4 ENROLLMENT; closed, so a rule states the kind it reads and a fact of another kind never fills it. -/
inductive Kind | DMF | PROVIDER_DEATH | EXCLUSION | ENROLLMENT deriving DecidableEq, Repr

def Kind.byte : Kind → Nat | .DMF => 1 | .PROVIDER_DEATH => 2 | .EXCLUSION => 3 | .ENROLLMENT => 4

def Kind.ofByte : Nat → Option Kind
  | 1 => some .DMF | 2 => some .PROVIDER_DEATH | 3 => some .EXCLUSION | 4 => some .ENROLLMENT | _ => none

def setTag : Bytes := [82, 82, 47, 71, 65, 84, 69, 47, 82, 69, 65, 68, 45, 83, 69, 84, 47, 118, 50, 0]
def authByte : Authority → Nat | .OBSERVE => 1 | .HOLD => 2 | .TRANSFER => 3
def authOf : Nat → Option Authority | 1 => some .OBSERVE | 2 => some .HOLD | 3 => some .TRANSFER | _ => none


/-- `signer` is gone: who signed is the set of records, counted against the keyset (k-of-n). -/
structure Header where
  kind : Nat
  scope : Scope
  asOf : Nat
  validUntil : Nat
  count : Nat
  rows : Bytes
  deriving DecidableEq

structure Snap where
  head : Header
  sigs : List SigRec
  deriving DecidableEq

/-- 98 bytes; scope still at offset 21. -/
def headW : List Nat := [20, 1, 1, 4, 4, 4, 64]

def Header.parts (h : Header) : List Bytes :=
  [tag, natBE 1 h.kind, natBE 1 h.scope.byte, natBE 4 h.asOf, natBE 4 h.validUntil, natBE 4 h.count, h.rows]

def Header.bytes (h : Header) : Bytes := h.parts.flatten
def encode (s : Snap) : Bytes := s.head.bytes ++ encodeSigs s.sigs
def digest (h : Header) : Bytes := sha3 h.bytes
/-- Binds the keyset digest: a signature for one keyset never counts under another. -/
def sigMsg (ksd : Bytes) (h : Header) : Bytes := sha3 (sigTag ++ ksd ++ h.bytes)

def decodeHeader (x : Bytes) : Option (Header × Bytes) := do
  let (ps, r) ← chop headW x
  match ps with
  | [t, k, sc, a, v, n, rw] =>
    guard (t = tag ∧ 1 ≤ beNat k ∧ beNat k ≤ 4 ∧ beNat a ≤ beNat v)
    let s ← Scope.ofByte (beNat sc)
    pure (⟨beNat k, s, beNat a, beNat v, beNat n, rw⟩, r)
  | _ => none

def decode (x : Bytes) : Option Snap := do
  let (h, sb) ← decodeHeader x
  let ss ← decodeSigBlock sb
  pure ⟨h, ss⟩

/-- Replaces K2's HWf (round-1 HIGH-1: natBE truncates mod 256^w, so injectivity needs these bounds). -/
def Header.Wf (h : Header) : Prop :=
  1 ≤ h.kind ∧ h.kind ≤ 4 ∧ h.asOf < 2 ^ 32 ∧ h.validUntil < 2 ^ 32 ∧ h.asOf ≤ h.validUntil ∧ h.count < 2 ^ 32 ∧
    h.rows.length = 64

/-- The READ-<kind>/v2 digest of a rules snapshot: what `optPin` hashes, a header's `rows` signs, and the READ-SET slot
    of that kind carries. -/
def rowsDigest {α : Type} (d : String) (k : Nat) (f : α → List (Nat × Nat)) (s : Rules.Snapshot α) : Option Bytes :=
  (Rules.pinInput d k f s).map sha3

/-- A rules snapshot with its SNAPSHOT/v3 facts.  It exists only if kSource distinct employees' SOURCE keys signed
    (round 5 MED-2: there is no flag to skip), and only while the verifier's day is at most validUntil (MED-1).  Its
    constructor is private (review stmts5 L1): only `attach`, reached only through `attachChain`, builds one. -/
structure Signed (α : Type) extends Rules.Snapshot α where
  private mk ::
  /-- K3 r2: the kind of the header's signed kind byte, which `attach` checked equals the kind it attached as. -/
  kind : Kind
  scope : Scope
  validUntil : Nat
  /-- K3: the verifier's day it was attached on; it counts in a batch of that day only (`Scoped.counts`). -/
  day : Nat
  /-- K3: the digest of the head keyset that counted its signers; a batch under another keyset does not count it. -/
  keyset : Bytes

/-! ### READ-MANIFEST/v4 -/

/-- One READ-SET slot: `0` iff the pin is zero (no digest), else `1` and the 64-byte digest. -/
def slot (p : Bytes) : Bytes → Option (Option Bytes × Bytes)
  | b :: y => if b = 0 ∧ p = zeroDigest then some (none, y)
    else if b = 1 ∧ p ≠ zeroDigest ∧ digestBytes ≤ y.length then some (some (y.take digestBytes), y.drop digestBytes)
    else none
  | [] => none

/-- Every slot's digest, in pin order, and the rest of the READ-SET. -/
def slotDigests : List Bytes → Bytes → Option (List (Option Bytes) × Bytes)
  | [], y => some ([], y)
  | p :: ps, y => do
    let (o, y) ← slot p y
    let (os, z) ← slotDigests ps y
    pure (o :: os, z)

structure Manifest where
  grant : Bytes
  rule : Bytes
  engine : Bytes
  authority : Authority
  today : Nat
  keyset : Bytes
  genesis : Bytes
  pins : List Bytes
  pre : Bytes
  deriving DecidableEq

/-- 610 bytes before `pre`. -/
def manW : List Nat := [25, 64, 64, 64, 1, 4, 64, 64, 64, 64, 64, 64, 4]

def Manifest.parts (m : Manifest) : List Bytes :=
  [manTag, m.grant, m.rule, m.engine, natBE 1 (authByte m.authority), natBE 4 m.today, m.keyset, m.genesis] ++ m.pins ++
    [natBE 4 m.pre.length]

def encodeMan (m : Manifest) : Bytes := m.parts.flatten ++ m.pre

/-- The READ-SET in `pre`: tag, one slot per pin, `u32 r`, r redo rows of payWidth bytes,
    the shard's 64-byte base digest, and nothing after (train14 LOW-6: K2 stopped after the slots and ignored the
    rest).  The length guard runs before `chop`, so a hostile r never builds a 2^32-long width list.  Returns the slot
    digests, the redo rows and the base. -/
def Manifest.reads (m : Manifest) : Option (List (Option Bytes) × List Bytes × Bytes) := do
  let (h, y) ← cut setTag.length m.pre
  guard (h = setTag)
  let (sd, z) ← slotDigests m.pins y
  let (r, z) ← cut 4 z
  guard (z.length = beNat r * Rules.payWidth + digestBytes)
  let (redo, base) ← chop (List.replicate (beNat r) Rules.payWidth) z
  pure (sd, redo, base)

def decodeMan (x : Bytes) : Option Manifest := do
  let (ps, pre) ← chop manW x
  match ps with
  | [t, g, r, e, a, td, ks, gn, p1, p2, p3, p4, n] =>
    guard (t = manTag ∧ ks ≠ zeroDigest ∧ gn ≠ zeroDigest ∧ beNat n = pre.length)
    let au ← authOf (beNat a)
    let m : Manifest := ⟨g, r, e, au, beNat td, ks, gn, [p1, p2, p3, p4], pre⟩
    let _ ← m.reads
    pure m
  | _ => none

/-- Replaces K2's MWf: structural, the read-set parse is the real parser. -/
def Manifest.Wf (m : Manifest) : Prop :=
  m.grant.length = 64 ∧ m.rule.length = 64 ∧ m.engine.length = 64 ∧ m.keyset.length = 64 ∧ m.keyset ≠ zeroDigest ∧
    m.genesis.length = 64 ∧ m.genesis ≠ zeroDigest ∧ m.today < 2 ^ 32 ∧ m.pins.length = 4 ∧
    (∀ p ∈ m.pins, p.length = 64) ∧ m.pre.length < 2 ^ 32 ∧ m.reads.isSome = true

/-- Review stmts5 L3: why a kind stays unattached.  `binding`: the snapshot, manifest, keyset or chain does not bind
    (malformed bytes; wrong day, kind, rows, count, pin, slot or keyset; dead keyset or expired fact; chain refused), a
    loud refuse (design s2).  `quorum`: everything binds but fewer than kSource distinct employees' SOURCE keys signed;
    the rows are absorbed and the kind's lines go to review (D7 strictest, *_UNVERIFIED).  Neither carries facts
    (`attachChain_refused_unusable`). -/
inductive Refusal | binding | quorum deriving DecidableEq, Repr

/-- Bind SNAPSHOT/v3 bytes `x` to rows `s` of kind `k` under manifest `m` and keyset `ks` on the verifier's day `now`:
    `.binding` unless the manifest is for today (`m.today = now`, review r3 LOW-5: the manifest is untrusted input), the
    header names exactly those rows, is not dated after today (MED-B) and has not expired (`now ≤ validUntil`, round 5
    MED-1: an expired fact must not pay), the manifest names this keyset (live today) and pins this header, and its
    READ-SET slot for kind k carries the same rows digest (a pin is a header digest and a slot a rows digest, never
    byte-equal; train14 LOW-6); then `.quorum` unless kSource distinct employees' SOURCE keys with this scope and kind,
    live at asOf, their windows covering validUntil, signed (round 5 MED-2).  `now` is the verifier's persisted,
    nondecreasing day (A5, `Keyset.admitHead`), so a keyset dead on one day stays dead (`attach_dead_after`).  Private
    (review stmts5 L1): it trusts `ks`, and only `attachChain` calls it, with the head of the node's own chain.  K3: the
    manifest checks, then `attachCore` (the same conjunction split in two; a binding failure in either precedes the
    quorum check, so the refusal is unchanged).  The checks read the rows only through their date, count and digest
    (`attachHdr`), so a store that keeps those three per snapshot runs them without the rows (`attachAt_hdr`).  Macro-inlined, so a digest passed in is computed only once the decode, kind, date and count
    checks have passed. -/
@[macro_inline] def attachHdr {β : Type} (verify : Bytes → Bytes → Bytes → Bool) (now : Nat) (ks : Keyset.Keyset) (k : Nat)
    (asOf count : Nat) (rd : Option Bytes) (x : Bytes) (mk : Snap → Kind → β) : Except Refusal β := do
  let some v := decode x | throw Refusal.binding
  unless v.head.kind = k ∧ v.head.asOf = asOf ∧ v.head.asOf ≤ now ∧ now ≤ v.head.validUntil ∧ v.head.count = count ∧
      rd = some v.head.rows ∧ ksLive ks now = true do
    throw Refusal.binding
  unless quorum verify (sourceOk v.head.scope.byte k v.head.asOf v.head.validUntil) (·.employee) ks ks.kSource
      (sigMsg (digestOf ks) v.head) v.sigs = true do
    throw Refusal.quorum
  let some kd := Kind.ofByte k | throw Refusal.binding
  pure (mk v kd)

private def attachCore {α : Type} (verify : Bytes → Bytes → Bytes → Bool) (now : Nat) (ks : Keyset.Keyset) (d : String)
    (k : Nat) (f : α → List (Nat × Nat)) (s : Rules.Snapshot α) (x : Bytes) : Except Refusal (Signed α) :=
  attachHdr verify now ks k s.asOf s.count (rowsDigest d k f s) x fun v kd =>
    ⟨s, kd, v.head.scope, v.head.validUntil, now, digestOf ks⟩

private def attach {α : Type} (verify : Bytes → Bytes → Bytes → Bool) (now : Nat) (ks : Keyset.Keyset) (m : Manifest)
    (d : String) (k : Nat) (f : α → List (Nat × Nat)) (s : Rules.Snapshot α) (x : Bytes) : Except Refusal (Signed α) := do
  let some v := decode x | throw Refusal.binding
  let some (sd, _) := m.reads | throw Refusal.binding
  unless m.today = now ∧ m.keyset = digestOf ks ∧ m.pins[k - 1]? = some (digest v.head) ∧
      sd[k - 1]? = some (some v.head.rows) do
    throw Refusal.binding
  attachCore verify now ks d k f s x

/-- Round 5 MED-3, review stmts5 MED-A / MED-B / L2: attach under the head of the verifier's own chain.  `pin` is the
    node's genesis pin (A4, design decision 10) and must be the manifest's `genesis`; `steps` are its admission records
    (A5); `st` is the ratchet it persisted last.  `Keyset.admitHead` refuses a day behind `st.day` or too far past it,
    a chain below `st.epoch`, a fork at or below it, and steps past `st.epoch` not dated `now`
    (`attachChain_rollback`), before any snapshot signature is checked.  Returns the
    ratchet to persist, advanced whenever the chain is admitted, whatever the snapshot (MED-B: a failed attach cannot
    leave an older, still-live chain replayable), and the attach result. -/
def attachChain {α : Type} (verify : Bytes → Bytes → Bytes → Bool) (pin : Bytes) (now : Nat) (st : Keyset.Ratchet)
    (m : Manifest) (g : Bytes) (steps : List (Nat × Bytes)) (d : String) (k : Nat) (f : α → List (Nat × Nat))
    (s : Rules.Snapshot α) (x : Bytes) : Keyset.Ratchet × Except Refusal (Signed α) :=
  match Keyset.admitHead verify pin now st g steps with
  | none => (st, .error .binding)
  | some (ks, st') => (st', if m.genesis = pin then attach verify now ks m d k f s x else .error .binding)

/-- K3 consumer: a head admitted on `day` from genesis `pin` by `Keyset.admitHead`.  Private constructor, so
    `attachAt` mints only under a head `admitBatchHead` admitted (one head per batch for all four kinds). -/
structure Head where
  private mk ::
  ks : Keyset.Keyset
  day : Nat
  pin : Bytes

/-- `Keyset.admitHead`, its head kept as a `Head` for the batch day. -/
def admitBatchHead (verify : Bytes → Bytes → Bytes → Bool) (pin : Bytes) (now : Nat) (st : Keyset.Ratchet) (g : Bytes)
    (steps : List (Nat × Bytes)) : Option (Head × Keyset.Ratchet) :=
  (Keyset.admitHead verify pin now st g steps).map fun (ks, st') => (⟨ks, now, pin⟩, st')

/-- Attach under an admitted head on its day: attach's checks that read no manifest (`chain_attachAt`). -/
def attachAt {α : Type} (verify : Bytes → Bytes → Bytes → Bool) (H : Head) (d : String) (k : Nat)
    (f : α → List (Nat × Nat)) (s : Rules.Snapshot α) (x : Bytes) : Except Refusal (Signed α) :=
  attachCore verify H.day H.ks d k f s x

/-- What a manifest must say for kind k's attach of x under ks on now (attach's manifest checks, named). -/
def ManPins (m : Manifest) (now : Nat) (pin : Bytes) (ks : Keyset.Keyset) (k : Nat) (x : Bytes) : Prop :=
  m.today = now ∧ m.genesis = pin ∧ m.keyset = Keyset.digestOf ks ∧ ∃ v sd rest, decode x = some v ∧
    m.pins[k - 1]? = some (digest v.head) ∧ m.reads = some (sd, rest) ∧ sd[k - 1]? = some (some v.head.rows)

variable {α : Type} {verify : Bytes → Bytes → Bytes → Bool} {now : Nat} {ks : Keyset.Keyset} {m : Manifest}
  {d : String} {k : Nat} {f : α → List (Nat × Nat)} {s : Rules.Snapshot α} {x : Bytes} {r : Signed α}
  {sd : List (Option Bytes)} {redo : List Bytes} {base : Bytes} {pin g : Bytes} {steps : List (Nat × Bytes)}
  {st st' : Keyset.Ratchet} {e : Refusal} {H : Head}

theorem ofByte_byte {n : Nat} {s : Scope} (h : Scope.ofByte n = some s) : s.byte = n := by
  unfold Scope.ofByte at h
  split at h <;> first | (injection h with h; subst h; rfl) | (simp at h)

theorem decodeHeader_spec {x y : Bytes} {h : Header} (hd : decodeHeader x = some (h, y)) :
    x = h.bytes ++ y ∧ h.Wf := by
  unfold decodeHeader at hd
  rcases hch : chop headW x with _ | ⟨ps, r'⟩
  · simp [hch] at hd
  · obtain ⟨hmap, hx⟩ := Keyset.chop_spec _ _ _ _ hch
    have hlen : ps.length = 7 := by simpa [headW] using congrArg List.length hmap
    simp only [hch, Option.bind_some] at hd
    rcases ps with _ | ⟨t, _ | ⟨k, _ | ⟨sc, _ | ⟨a, _ | ⟨v, _ | ⟨n, _ | ⟨rw, _ | ⟨z, zs⟩⟩⟩⟩⟩⟩⟩⟩ <;>
      first | (simp at hlen; done) | skip
    simp only [headW, List.map_cons, List.map_nil, List.cons.injEq, and_true] at hmap
    obtain ⟨l1, l2, l3, l4, l5, l6, l7⟩ := hmap
    simp [guard] at hd
    split at hd
    · rename_i hg
      obtain ⟨ht, hk1, hk2, hav⟩ := hg
      cases hs : Scope.ofByte (beNat sc) with
      | none => simp [hs] at hd
      | some s =>
        simp [hs] at hd
        obtain ⟨rfl, rfl⟩ := hd
        have e2 : Scope.byte s = beNat sc := ofByte_byte hs
        have f1 : natBE 1 (beNat k) = k := Keyset.natBE_beNat' l2
        have f2 : natBE 1 (beNat sc) = sc := Keyset.natBE_beNat' l3
        have f3 : natBE 4 (beNat a) = a := Keyset.natBE_beNat' l4
        have f4 : natBE 4 (beNat v) = v := Keyset.natBE_beNat' l5
        have f5 : natBE 4 (beNat n) = n := Keyset.natBE_beNat' l6
        refine ⟨?_, ?_⟩
        · rw [hx]; simp [Header.bytes, Header.parts, e2, f1, f2, f3, f4, f5, ht]
        · exact ⟨hk1, hk2, Keyset.beNat_lt4 l4, Keyset.beNat_lt4 l5, hav, Keyset.beNat_lt4 l6, l7⟩
    · exact absurd hd (Keyset.fail_bind _ _)

theorem decodeHeader_bytes {h : Header} (hw : h.Wf) (y : Bytes) : decodeHeader (h.bytes ++ y) = some (h, y) := by
  obtain ⟨kind, scope, asOf, vu, cnt, rows⟩ := h
  obtain ⟨w1, w2, w3, w4, w5, w6, w7⟩ := hw
  simp only at w1 w2 w3 w4 w5 w6 w7
  have hc := Keyset.chop_flatten [tag, natBE 1 kind, natBE 1 scope.byte, natBE 4 asOf, natBE 4 vu, natBE 4 cnt, rows] y
  have hl : [tag, natBE 1 kind, natBE 1 scope.byte, natBE 4 asOf, natBE 4 vu, natBE 4 cnt, rows].map List.length =
      headW := by
    simp [headW, Keyset.natBE_length, tag, w7]
  rw [hl] at hc
  have hb : (Header.bytes ⟨kind, scope, asOf, vu, cnt, rows⟩ ++ y) =
      [tag, natBE 1 kind, natBE 1 scope.byte, natBE 4 asOf, natBE 4 vu, natBE 4 cnt, rows].flatten ++ y := rfl
  rw [hb]
  unfold decodeHeader
  rw [hc]
  have g1 : beNat (natBE 1 kind) = kind := beNat_natBE 1 _ (by omega)
  have g3 : beNat (natBE 4 asOf) = asOf := beNat_natBE 4 _ w3
  have g4 : beNat (natBE 4 vu) = vu := beNat_natBE 4 _ w4
  have g5 : beNat (natBE 4 cnt) = cnt := beNat_natBE 4 _ w6
  cases scope <;> simp [guard, g1, g3, g4, g5, w1, w2, w5, Scope.byte, Scope.ofByte, beNat_natBE]

theorem decode_spec {x : Bytes} {sn : Snap} (h : decode x = some sn) :
    x = encode sn ∧ sn.head.Wf ∧ SigsWf sn.sigs := by
  unfold decode at h
  cases h1 : decodeHeader x with
  | none => simp [h1] at h
  | some q =>
    cases h2 : decodeSigBlock q.2 with
    | none => simp [h1, h2] at h
    | some ss =>
      simp [h1, h2] at h
      subst h
      obtain ⟨i1, i2⟩ := decodeHeader_spec (x := x) (h := q.1) (y := q.2) h1
      obtain ⟨j1, j2⟩ := Keyset.decodeSigBlock_spec h2
      refine ⟨?_, i2, j2⟩
      simp only [encode]
      rw [← j1]; exact i1

/-- LOW a: every decoded header is well formed, so `sigMsg_pre_inj` applies to decoded headers. -/
theorem decodeHeader_wf {h : Header} {y : Bytes} (hd : decodeHeader x = some (h, y)) : h.Wf :=
  (decodeHeader_spec hd).2

/-- Well-formed snapshots round-trip. -/
theorem decode_encode {sn : Snap} (h : sn.head.Wf) (hs : SigsWf sn.sigs) : decode (encode sn) = some sn := by
  obtain ⟨hd, ss⟩ := sn
  unfold decode encode
  simp only at h hs ⊢
  rw [decodeHeader_bytes h]
  simp [Keyset.decodeSigBlock_encode hs]

/-- Canonical: a decoded snapshot re-encodes to exactly its bytes. -/
theorem encode_decode {sn : Snap} (h : decode x = some sn) : encode sn = x := (decode_spec h).1.symm

/-- LOW a: a decoded snapshot is well formed (header and signature block); the converse of `decode_encode`. -/
theorem decode_wf {sn : Snap} (h : decode x = some sn) : sn.head.Wf ∧ SigsWf sn.sigs :=
  ⟨(decode_spec h).2.1, (decode_spec h).2.2⟩

theorem slot_spec {p y z : Bytes} {o : Option Bytes} (h : slot p y = some (o, z)) :
    y = o.elim [0] (1 :: ·) ++ z ∧ (o = none ↔ p = zeroDigest) ∧ ∀ dg, o = some dg → dg.length = digestBytes := by
  cases y with
  | nil => simp [slot] at h
  | cons b y =>
    simp only [slot] at h
    by_cases h1 : b = 0 ∧ p = zeroDigest
    · rw [if_pos h1] at h
      simp only [Option.some.injEq, Prod.mk.injEq] at h
      obtain ⟨rfl, rfl⟩ := h
      simp [h1.1, h1.2]
    · rw [if_neg h1] at h
      by_cases h2 : b = 1 ∧ p ≠ zeroDigest ∧ digestBytes ≤ y.length
      · rw [if_pos h2] at h
        simp only [Option.some.injEq, Prod.mk.injEq] at h
        obtain ⟨rfl, rfl⟩ := h
        refine ⟨by simp [h2.1], ?_, ?_⟩
        · simp [h2.2.1]
        · intro dg hdg
          cases hdg
          simp [h2.2.2]
      · rw [if_neg h2] at h
        cases h

theorem slot_app {p y z w : Bytes} {o : Option Bytes} (h : slot p y = some (o, z)) :
    slot p (y ++ w) = some (o, z ++ w) := by
  cases y with
  | nil => simp [slot] at h
  | cons b y =>
    simp only [slot] at h ⊢
    by_cases h1 : b = 0 ∧ p = zeroDigest
    · rw [if_pos h1] at h
      simp only [Option.some.injEq, Prod.mk.injEq] at h
      obtain ⟨rfl, rfl⟩ := h
      simp [if_pos h1]
    · rw [if_neg h1] at h
      by_cases h2 : b = 1 ∧ p ≠ zeroDigest ∧ digestBytes ≤ y.length
      · rw [if_pos h2] at h
        simp only [Option.some.injEq, Prod.mk.injEq] at h
        obtain ⟨rfl, rfl⟩ := h
        have h3 : digestBytes ≤ (y ++ w).length := by simp; omega
        simp only [List.cons_append]
        rw [if_neg h1, if_pos ⟨h2.1, h2.2.1, h3⟩]
        simp [List.take_append_of_le_length h2.2.2, List.drop_append_of_le_length h2.2.2]
      · rw [if_neg h2] at h
        cases h

theorem slotDigests_spec : ∀ {ps : List Bytes} {y z : Bytes} {os : List (Option Bytes)},
    slotDigests ps y = some (os, z) → ps.length = os.length ∧ y = (os.map fun o => o.elim [0] (1 :: ·)).flatten ++ z ∧
      ∀ i : Nat, (os[i]? = some none ↔ ps[i]? = some zeroDigest) ∧ ∀ dg : Bytes, os[i]? = some (some dg) → dg.length = digestBytes
  | [], y, z, os, h => by
    simp only [slotDigests, Option.some.injEq, Prod.mk.injEq] at h
    obtain ⟨rfl, rfl⟩ := h
    simp
  | p :: ps, y, z, os, h => by
    simp only [slotDigests] at h
    cases h1 : slot p y with
    | none => simp [h1] at h
    | some a =>
      obtain ⟨o, y1⟩ := a
      simp only [h1] at h
      cases h2 : slotDigests ps y1 with
      | none => simp [h2] at h
      | some b =>
        obtain ⟨os1, z1⟩ := b
        simp [h2] at h
        obtain ⟨rfl, rfl⟩ := h
        obtain ⟨s1, s2, s3⟩ := slot_spec h1
        obtain ⟨t1, t2, t3⟩ := slotDigests_spec h2
        refine ⟨by simp [t1], ?_, ?_⟩
        · simp only [List.map_cons, List.flatten_cons, List.append_assoc]
          rw [← t2]; exact s1
        · intro i
          cases i with
          | zero =>
            simp only [List.getElem?_cons_zero, Option.some.injEq]
            exact ⟨s2, fun dg hdg => s3 dg hdg⟩
          | succ i =>
            simp only [List.getElem?_cons_succ]
            exact t3 i

theorem slotDigests_app : ∀ {ps : List Bytes} {y z w : Bytes} {os : List (Option Bytes)},
    slotDigests ps y = some (os, z) → slotDigests ps (y ++ w) = some (os, z ++ w)
  | [], y, z, w, os, h => by
    simp only [slotDigests, Option.some.injEq, Prod.mk.injEq] at h
    obtain ⟨rfl, rfl⟩ := h
    simp [slotDigests]
  | p :: ps, y, z, w, os, h => by
    simp only [slotDigests] at h ⊢
    cases h1 : slot p y with
    | none => simp [h1] at h
    | some a =>
      obtain ⟨o, y1⟩ := a
      simp only [h1] at h
      cases h2 : slotDigests ps y1 with
      | none => simp [h2] at h
      | some b =>
        obtain ⟨os1, z1⟩ := b
        simp [h2] at h
        obtain ⟨rfl, rfl⟩ := h
        simp [slot_app h1, slotDigests_app h2]

theorem reads_unfold {sd : List (Option Bytes)} {redo : List Bytes} {base : Bytes} (h : m.reads = some (sd, redo, base)) :
    ∃ y z0 r z, cut setTag.length m.pre = some (setTag, y) ∧ slotDigests m.pins y = some (sd, z0) ∧
      cut 4 z0 = some (r, z) ∧ z.length = beNat r * Rules.payWidth + digestBytes ∧
      chop (List.replicate (beNat r) Rules.payWidth) z = some (redo, base) := by
  unfold Manifest.reads at h
  cases h1 : cut setTag.length m.pre with
  | none => simp [h1] at h
  | some a =>
    obtain ⟨hh, y⟩ := a
    simp [h1] at h
    by_cases hg : hh = setTag
    · subst hg
      cases h2 : slotDigests m.pins y with
      | none => simp [h2] at h
      | some b =>
        obtain ⟨sd0, z0⟩ := b
        cases h3 : cut 4 z0 with
        | none => simp [h2, h3] at h
        | some c =>
          obtain ⟨r, z⟩ := c
          by_cases hz : z.length = beNat r * Rules.payWidth + digestBytes
          · cases h4 : chop (List.replicate (beNat r) Rules.payWidth) z with
            | none => simp [h2, h3, hz, h4] at h
            | some e =>
              obtain ⟨rd, bs⟩ := e
              simp [h2, h3, hz, h4] at h
              obtain ⟨rfl, rfl, rfl⟩ := h
              exact ⟨y, z0, r, z, rfl, h2, h3, hz, h4⟩
          · simp [h2, h3, hz, guard] at h
            exact absurd h (Keyset.fail_bind _ _)
    · simp [hg, guard] at h
      exact absurd h (Keyset.fail_bind _ _)

/-- The manifest (with its genesis field) round-trips. -/
theorem decodeMan_encode (h : m.Wf) : decodeMan (encodeMan m) = some m := by
  obtain ⟨hg, hr, he, hk, hkz, hgn, hgz, ht, hp, hpl, hpre, hrd⟩ := h
  obtain ⟨grant, rule, engine, auth, today, keyset, genesis, pins, pre⟩ := m
  simp only at *
  obtain ⟨p1, p2, p3, p4, rfl⟩ : ∃ p1 p2 p3 p4, pins = [p1, p2, p3, p4] := by
    match pins, hp with
    | [p1, p2, p3, p4], _ => exact ⟨p1, p2, p3, p4, rfl⟩
  simp only [List.mem_cons, forall_eq_or_imp, List.not_mem_nil, or_false, forall_eq] at hpl
  have hmt : manTag.length = 25 := by decide
  have hl : manW = ([manTag, grant, rule, engine, natBE 1 (authByte auth), natBE 4 today, keyset, genesis, p1, p2, p3, p4,
      natBE 4 pre.length]).map List.length := by
    simp [manW, hmt, natBE_length, hg, hr, he, hk, hgn, hpl]
  have key : chop manW (encodeMan ⟨grant, rule, engine, auth, today, keyset, genesis, [p1, p2, p3, p4], pre⟩) =
      some ([manTag, grant, rule, engine, natBE 1 (authByte auth), natBE 4 today, keyset, genesis, p1, p2, p3, p4,
        natBE 4 pre.length], pre) := by
    rw [hl]; exact chop_flatten _ _
  have hn : beNat (natBE 4 pre.length) = pre.length := beNat_natBE 4 _ (by simpa using hpre)
  have ha : authOf (beNat (natBE 1 (authByte auth))) = some auth := by
    rw [beNat_natBE 1 _ (by cases auth <;> decide)]; cases auth <;> rfl
  have htd : beNat (natBE 4 today) = today := beNat_natBE 4 _ (by simpa using ht)
  obtain ⟨o, ho⟩ := Option.isSome_iff_exists.mp hrd
  unfold decodeMan
  rw [key]
  simp [hn, ha, htd, hkz, hgz, guard, ho]

/-- train14 LOW-6: nothing may follow the base digest; any bytes appended to `pre` refuse the read set (and so
    `decodeMan`).  Redo rows and base stay bound only by `evidenceRoot = sha3 (encodeMan m)`. -/
theorem reads_trailing {o : List (Option Bytes) × List Bytes × Bytes} {z : Bytes} (h : m.reads = some o) (hz : z ≠ []) :
    ({ m with pre := m.pre ++ z } : Manifest).reads = none := by
  obtain ⟨sd, redo, base⟩ := o
  obtain ⟨y, z0, r, z1, h1, h2, h3, h4, h5⟩ := reads_unfold h
  obtain ⟨c1, c2⟩ := Keyset.cut_spec h1
  obtain ⟨e1, e2⟩ := Keyset.cut_spec h3
  have k1 : cut setTag.length (m.pre ++ z) = some (setTag, y ++ z) := by
    rw [c2, List.append_assoc]; exact Keyset.cut_app rfl
  have k2 : slotDigests m.pins (y ++ z) = some (sd, z0 ++ z) := slotDigests_app h2
  have k3 : cut 4 (z0 ++ z) = some (r, z1 ++ z) := by
    rw [e2, List.append_assoc]; exact Keyset.cut_app e1
  have hpos : 0 < z.length := by
    cases z with
    | nil => exact absurd rfl hz
    | cons a t => simp
  have hg : ¬ (z1.length + z.length = beNat r * Rules.payWidth + digestBytes) := by omega
  simp [Manifest.reads, k1, k2, k3, hg, guard]

/-- train14 LOW-6: an accepted READ-SET is exactly `readSetPre`'s layout: tag, slot bytes (`0` or `1 ‖ digest`), `u32 r`,
    r rows of payWidth bytes, a 64-byte base, and nothing else. -/
theorem reads_exact (h : m.reads = some (sd, redo, base)) :
    base.length = digestBytes ∧ redo.length < 2 ^ 32 ∧ (∀ w ∈ redo, w.length = Rules.payWidth) ∧
      m.pre = setTag ++ (sd.map fun o => o.elim [0] (1 :: ·)).flatten ++ natBE 4 redo.length ++ redo.flatten ++ base := by
  obtain ⟨y, z0, r, z, h1, h2, h3, h4, h5⟩ := reads_unfold h
  obtain ⟨c1, c2⟩ := Keyset.cut_spec h1
  obtain ⟨_, d2, _⟩ := slotDigests_spec h2
  obtain ⟨e1, e2⟩ := Keyset.cut_spec h3
  obtain ⟨f1, f2⟩ := Keyset.chop_spec _ _ _ _ h5
  have hlen : redo.length = beNat r := by simpa using congrArg List.length f1
  have hrow : ∀ w ∈ redo, w.length = Rules.payWidth := by
    intro w hw
    have : w.length ∈ List.replicate (beNat r) Rules.payWidth := by
      rw [← f1]; exact List.mem_map_of_mem hw
    exact List.eq_of_mem_replicate this
  have hflat : redo.flatten.length = beNat r * Rules.payWidth := by
    rw [List.length_flatten, f1]
    simp
  have hbase : base.length = digestBytes := by
    have := congrArg List.length f2
    rw [List.length_append, hflat] at this
    omega
  refine ⟨hbase, by rw [hlen]; exact Keyset.beNat_lt4 e1, hrow, ?_⟩
  have hn : natBE 4 redo.length = r := by rw [hlen]; exact Keyset.natBE_beNat' e1
  rw [hn, c2, d2, e2, f2]
  simp [setTag] 

/-- One slot per pin; a slot is empty exactly when its pin is zero (D7: an empty slot reads strictest), else it carries
    a 64-byte digest that `attach` must match to the pinned header's rows (K3 attaches every nonzero pin). -/
theorem reads_slots (h : m.reads = some (sd, redo, base)) :
    sd.length = m.pins.length ∧ ∀ i : Nat, (sd[i]? = some none ↔ m.pins[i]? = some zeroDigest) ∧
      ∀ dg : Bytes, sd[i]? = some (some dg) → dg.length = digestBytes := by
  obtain ⟨y, z0, r, z, h1, h2, h3, h4, h5⟩ := reads_unfold h
  obtain ⟨a, _, b⟩ := slotDigests_spec h2
  exact ⟨a.symm, fun i => by
    have := b i
    exact ⟨this.1, this.2⟩⟩

private theorem attachCore_ok (h : attachCore verify now ks d k f s x = .ok r) :
    ∃ v kd, decode x = some v ∧ (v.head.kind = k ∧ v.head.asOf = s.asOf ∧ v.head.asOf ≤ now ∧
      now ≤ v.head.validUntil ∧ v.head.count = s.count ∧ rowsDigest d k f s = some v.head.rows ∧ ksLive ks now = true) ∧
      quorum verify (sourceOk v.head.scope.byte k v.head.asOf v.head.validUntil) (·.employee) ks ks.kSource
        (sigMsg (digestOf ks) v.head) v.sigs = true ∧ Kind.ofByte k = some kd ∧ r.toSnapshot = s ∧ r.kind = kd ∧
      r.scope = v.head.scope ∧ r.validUntil = v.head.validUntil ∧ r.day = now ∧ r.keyset = digestOf ks := by
  unfold attachCore attachHdr at h
  cases hd : decode x with
  | none => simp [hd] at h
  | some v =>
    simp [hd] at h
    by_cases hc : (v.head.kind = k ∧ v.head.asOf = s.asOf ∧ v.head.asOf ≤ now ∧ now ≤ v.head.validUntil ∧
        v.head.count = s.count ∧ rowsDigest d k f s = some v.head.rows ∧ ksLive ks now = true)
    · by_cases hq : quorum verify (sourceOk v.head.scope.byte k v.head.asOf v.head.validUntil) (·.employee) ks ks.kSource
          (sigMsg (digestOf ks) v.head) v.sigs = true
      · rw [if_pos hc, if_pos hq] at h
        cases hk : Kind.ofByte k with
        | none => simp [hk] at h
        | some kd =>
          simp only [hk] at h
          cases h
          exact ⟨v, kd, rfl, hc, hq, rfl, rfl, rfl, rfl, rfl, rfl, rfl⟩
      · rw [if_pos hc, if_neg hq] at h
        cases h
    · rw [if_neg hc] at h
      cases h

private theorem attachCore_quorum (h : attachCore verify now ks d k f s x = .error .quorum) :
    ∃ v, decode x = some v ∧ (v.head.kind = k ∧ v.head.asOf = s.asOf ∧ v.head.asOf ≤ now ∧
      now ≤ v.head.validUntil ∧ v.head.count = s.count ∧ rowsDigest d k f s = some v.head.rows ∧ ksLive ks now = true) ∧
      quorum verify (sourceOk v.head.scope.byte k v.head.asOf v.head.validUntil) (·.employee) ks ks.kSource
        (sigMsg (digestOf ks) v.head) v.sigs = false := by
  unfold attachCore attachHdr at h
  cases hd : decode x with
  | none => simp [hd] at h; cases h
  | some v =>
    simp [hd] at h
    by_cases hc : (v.head.kind = k ∧ v.head.asOf = s.asOf ∧ v.head.asOf ≤ now ∧ now ≤ v.head.validUntil ∧
        v.head.count = s.count ∧ rowsDigest d k f s = some v.head.rows ∧ ksLive ks now = true)
    · by_cases hq : quorum verify (sourceOk v.head.scope.byte k v.head.asOf v.head.validUntil) (·.employee) ks ks.kSource
          (sigMsg (digestOf ks) v.head) v.sigs = true
      · rw [if_pos hc, if_pos hq] at h
        cases hk : Kind.ofByte k <;> simp only [hk] at h <;> cases h
      · rw [if_pos hc, if_neg hq] at h
        exact ⟨v, rfl, hc, by simpa using hq⟩
    · rw [if_neg hc] at h
      cases h

private theorem attachCore_of_quorum {v : Snap} (hd : decode x = some v) (hc : v.head.kind = k ∧ v.head.asOf = s.asOf ∧
    v.head.asOf ≤ now ∧ now ≤ v.head.validUntil ∧ v.head.count = s.count ∧ rowsDigest d k f s = some v.head.rows ∧
    ksLive ks now = true) (hq : quorum verify (sourceOk v.head.scope.byte k v.head.asOf v.head.validUntil) (·.employee) ks
    ks.kSource (sigMsg (digestOf ks) v.head) v.sigs = false) :
    attachCore verify now ks d k f s x = .error .quorum := by
  have hq' : ¬ (quorum verify (sourceOk v.head.scope.byte k v.head.asOf v.head.validUntil) (·.employee) ks ks.kSource
      (sigMsg (digestOf ks) v.head) v.sigs = true) := by simp [hq]
  unfold attachCore attachHdr
  simp [hd]
  rw [if_pos hc, if_neg hq']
  rfl

/-- Any attach result but a binding refusal passed the manifest checks and is attachCore's. -/
private theorem attach_split {res : Except Refusal (Signed α)} (h : attach verify now ks m d k f s x = res)
    (hb : res ≠ .error .binding) : ∃ v sd rb, decode x = some v ∧ m.reads = some (sd, rb) ∧ (m.today = now ∧
      m.keyset = digestOf ks ∧ m.pins[k - 1]? = some (digest v.head) ∧ sd[k - 1]? = some (some v.head.rows)) ∧
      attachCore verify now ks d k f s x = res := by
  unfold attach at h
  cases hd : decode x with
  | none => simp [hd] at h; cases h; exact absurd rfl hb
  | some v =>
    cases hr : m.reads with
    | none => simp [hd, hr] at h; cases h; exact absurd rfl hb
    | some o =>
      obtain ⟨sd, rb⟩ := o
      simp [hd, hr] at h
      by_cases hm : (m.today = now ∧ m.keyset = digestOf ks ∧ m.pins[k - 1]? = some (digest v.head) ∧
          sd[k - 1]? = some (some v.head.rows))
      · rw [if_pos hm] at h
        exact ⟨v, sd, rb, rfl, rfl, hm, h⟩
      · rw [if_neg hm] at h
        cases h
        exact absurd rfl hb

private theorem attach_of_core {v : Snap} {rb : List Bytes × Bytes} (hd : decode x = some v)
    (hr : m.reads = some (sd, rb)) (hm : m.today = now ∧ m.keyset = digestOf ks ∧ m.pins[k - 1]? = some (digest v.head) ∧
      sd[k - 1]? = some (some v.head.rows)) :
    attach verify now ks m d k f s x = attachCore verify now ks d k f s x := by
  unfold attach
  simp [hd, hr, hm]

theorem attach_dec (h : attach verify now ks m d k f s x = Except.ok r) :
    ∃ v sd rb, decode x = some v ∧ m.reads = some (sd, rb) ∧ (m.today = now ∧ v.head.kind = k ∧ v.head.asOf = s.asOf ∧
      v.head.asOf ≤ now ∧ now ≤ v.head.validUntil ∧ v.head.count = s.count ∧ rowsDigest d k f s = some v.head.rows ∧
      m.keyset = digestOf ks ∧ ksLive ks now = true ∧ m.pins[k - 1]? = some (digest v.head) ∧
      sd[k - 1]? = some (some v.head.rows)) ∧
      quorum verify (sourceOk v.head.scope.byte k v.head.asOf v.head.validUntil) (·.employee) ks ks.kSource
        (sigMsg m.keyset v.head) v.sigs = true ∧ r.toSnapshot = s ∧ r.scope = v.head.scope ∧ r.validUntil = v.head.validUntil := by
  obtain ⟨v, sd, rb, hd, hr, ⟨m1, m2, m3, m4⟩, hc⟩ := attach_split h (by simp)
  obtain ⟨v', kd, hd', ⟨c1, c2, c3, c4, c5, c6, c7⟩, hq, -, e1, -, e3, e4, -, -⟩ := attachCore_ok hc
  obtain rfl : v = v' := Option.some.inj (hd.symm.trans hd')
  exact ⟨v, sd, rb, hd, hr, ⟨m1, c1, c2, c3, c4, c5, c6, m2, c7, m3, m4⟩, by rw [m2]; exact hq, e1, e3, e4⟩

private theorem ofByte_kind {k : Nat} {kd : Kind} (h : Kind.ofByte k = some kd) : kd.byte = k := by
  rcases k with _ | _ | _ | _ | _ | n <;> cases kd <;> simp [Kind.ofByte, Kind.byte] at h ⊢

private theorem attach_fields (h : attach verify now ks m d k f s x = Except.ok r) :
    ∃ kd, Kind.ofByte k = some kd ∧ r.kind = kd ∧ r.day = now ∧ r.keyset = digestOf ks := by
  obtain ⟨-, -, -, -, -, -, hc⟩ := attach_split h (by simp)
  obtain ⟨-, kd, -, -, -, hk, -, e2, -, -, e5, e6⟩ := attachCore_ok hc
  exact ⟨kd, hk, e2, e5, e6⟩

theorem attach_quorum_dec (h : attach verify now ks m d k f s x = Except.error Refusal.quorum) :
    ∃ v sd rb, decode x = some v ∧ m.reads = some (sd, rb) ∧ (m.today = now ∧ v.head.kind = k ∧ v.head.asOf = s.asOf ∧
      v.head.asOf ≤ now ∧ now ≤ v.head.validUntil ∧ v.head.count = s.count ∧ rowsDigest d k f s = some v.head.rows ∧
      m.keyset = digestOf ks ∧ ksLive ks now = true ∧ m.pins[k - 1]? = some (digest v.head) ∧
      sd[k - 1]? = some (some v.head.rows)) ∧
      quorum verify (sourceOk v.head.scope.byte k v.head.asOf v.head.validUntil) (·.employee) ks ks.kSource
        (sigMsg m.keyset v.head) v.sigs = false := by
  obtain ⟨v, sd, rb, hd, hr, ⟨m1, m2, m3, m4⟩, hc⟩ := attach_split h (by simp)
  obtain ⟨v', hd', ⟨c1, c2, c3, c4, c5, c6, c7⟩, hq⟩ := attachCore_quorum hc
  obtain rfl : v = v' := Option.some.inj (hd.symm.trans hd')
  exact ⟨v, sd, rb, hd, hr, ⟨m1, c1, c2, c3, c4, c5, c6, m2, c7, m3, m4⟩, by rw [m2]; exact hq⟩

/-- Attach is pinned (round-1 HIGH-2): the manifest is for the verifier's day (LOW-5); kind, asOf, count and rows
    match the header, asOf is not after today and validUntil not before it (round 5 MED-1); the manifest names this
    keyset, live today, pins this header, and its READ-SET slot for kind k carries the header's rows digest. -/
theorem attach_pinned (h : attach verify now ks m d k f s x = .ok r) :
    ∃ v sd rb, decode x = some v ∧ m.reads = some (sd, rb) ∧ m.today = now ∧ v.head.kind = k ∧ v.head.asOf = s.asOf ∧
      v.head.asOf ≤ now ∧ now ≤ v.head.validUntil ∧ v.head.count = s.count ∧ rowsDigest d k f s = some v.head.rows ∧
      m.keyset = digestOf ks ∧ ksLive ks now = true ∧ m.pins[k - 1]? = some (digest v.head) ∧
      sd[k - 1]? = some (some v.head.rows) ∧ r.toSnapshot = s ∧ r.scope = v.head.scope ∧
      r.validUntil = v.head.validUntil := by
  obtain ⟨v, sd, rb, hd, hr, ⟨c1, c2, c3, c4, c5, c6, c7, c8, c9, c10, c11⟩, -, e1, e2, e3⟩ := attach_dec h
  exact ⟨v, sd, rb, hd, hr, c1, c2, c3, c4, c5, c6, c7, c8, c9, c10, c11, e1, e2, e3⟩

/-- attach_sound's quorum half, shared with `attachAt_sound`. -/
private theorem quorum_entries {v : Snap} (hw : Keyset.Wf ks) (c4 : v.head.asOf ≤ now) (c5 : now ≤ v.head.validUntil)
    (hq : quorum verify (sourceOk v.head.scope.byte k v.head.asOf v.head.validUntil) (·.employee) ks ks.kSource
      (sigMsg (digestOf ks) v.head) v.sigs = true) :
    Keyset.minSource ≤ ks.kSource ∧ ∃ es : List Keyset.Entry,
      es.Sublist ks.entries ∧ ks.kSource ≤ es.length ∧ (es.map (·.keyId)).Nodup ∧ (es.map (·.employee)).Nodup ∧
      ∀ e ∈ es, e.role = Keyset.source ∧ bit e.scopes (v.head.scope.byte - 1) = true ∧ bit e.kinds (k - 1) = true ∧
        liveAt e v.head.asOf = true ∧ liveAt e now = true ∧ v.head.validUntil ≤ e.validUntil ∧
        ∃ q ∈ v.sigs, q.keyId = e.keyId ∧ verify e.pk (sigMsg (digestOf ks) v.head) q.sig = true := by
  have hsrt : Keyset.Sorted ks.entries := hw.2.2.2.2.2.2.2.2.2.2.2.2.2.1
  have hmin : Keyset.minSource ≤ ks.kSource := hw.2.2.2.2.2.2.2.2.2.2.1
  obtain ⟨es, hsub, h1, hl, hn1, hn2, he⟩ := Keyset.quorum_sound hsrt hq
  refine ⟨hmin, es, hsub, hl, hn2, hn1, ?_⟩
  intro e hem
  obtain ⟨hok, q, hqm, hq1, hq2⟩ := he e hem
  simp only [Keyset.sourceOk, Bool.and_eq_true, beq_iff_eq, decide_eq_true_eq] at hok
  obtain ⟨⟨⟨⟨⟨⟨ha, hb⟩, hrole⟩, hsc⟩, hki⟩, hlive⟩, hvu⟩ := hok
  have hl2 : liveAt e now = true := by
    simp only [Keyset.liveAt, Bool.and_eq_true, beq_iff_eq, decide_eq_true_eq] at hlive ⊢
    obtain ⟨⟨hr, hvf⟩, hvu'⟩ := hlive
    exact ⟨⟨hr, by omega⟩, by omega⟩
  exact ⟨hrole, hsc, hki, hlive, hl2, hvu, q, hqm, hq1, hq2⟩

/-- Round 5 MED-2, review stmts5 L4: every attach carries at least kSource ≥ minSource = 2 distinct EMPLOYEES (and
    keyIds) of the well-formed keyset (`attachChain_sound` supplies Wf), each through a SOURCE key with this scope and
    kind, live at asOf and on the verifier's day (validFrom ≤ asOf ≤ now ≤ validUntil ≤ the key's end), signed (keyset
    digest, header). [A1] -/
theorem attach_sound (hw : Keyset.Wf ks) (h : attach verify now ks m d k f s x = .ok r) :
    ∃ v, decode x = some v ∧ v.head.asOf ≤ now ∧ now ≤ v.head.validUntil ∧ Keyset.minSource ≤ ks.kSource ∧
      ∃ es : List Keyset.Entry,
      es.Sublist ks.entries ∧ ks.kSource ≤ es.length ∧ (es.map (·.keyId)).Nodup ∧ (es.map (·.employee)).Nodup ∧
      ∀ e ∈ es, e.role = Keyset.source ∧ bit e.scopes (v.head.scope.byte - 1) = true ∧ bit e.kinds (k - 1) = true ∧
        liveAt e v.head.asOf = true ∧ liveAt e now = true ∧ v.head.validUntil ≤ e.validUntil ∧
        ∃ q ∈ v.sigs, q.keyId = e.keyId ∧ verify e.pk (sigMsg (digestOf ks) v.head) q.sig = true := by
  obtain ⟨v, sd, rb, hd, hr, ⟨c1, c2, c3, c4, c5, c6, c7, c8, c9, c10, c11⟩, hq, -⟩ := attach_dec h
  rw [c8] at hq
  exact ⟨v, hd, c4, c5, quorum_entries hw c4 c5 hq⟩

/-- Review stmts5 L3: a quorum refusal is exactly a snapshot that binds in every other respect whose signatures fall
    short of kSource distinct employees; every other refusal is `.binding`. -/
theorem attach_review : attach verify now ks m d k f s x = .error .quorum ↔
    ∃ v sd rb, decode x = some v ∧ m.reads = some (sd, rb) ∧ m.today = now ∧ v.head.kind = k ∧ v.head.asOf = s.asOf ∧
      v.head.asOf ≤ now ∧ now ≤ v.head.validUntil ∧ v.head.count = s.count ∧ rowsDigest d k f s = some v.head.rows ∧
      m.keyset = digestOf ks ∧ ksLive ks now = true ∧ m.pins[k - 1]? = some (digest v.head) ∧
      sd[k - 1]? = some (some v.head.rows) ∧
      quorum verify (sourceOk v.head.scope.byte k v.head.asOf v.head.validUntil) (·.employee) ks ks.kSource
        (sigMsg m.keyset v.head) v.sigs = false := by
  constructor
  · intro h
    obtain ⟨v, sd, rb, hd, hr, ⟨c1, c2, c3, c4, c5, c6, c7, c8, c9, c10, c11⟩, hq⟩ := attach_quorum_dec h
    exact ⟨v, sd, rb, hd, hr, c1, c2, c3, c4, c5, c6, c7, c8, c9, c10, c11, hq⟩
  · rintro ⟨v, sd, rb, hd, hr, c1, c2, c3, c4, c5, c6, c7, c8, c9, c10, c11, hq⟩
    rw [attach_of_core hd hr ⟨c1, c8, c10, c11⟩]
    rw [c8] at hq
    exact attachCore_of_quorum hd ⟨c2, c3, c4, c5, c6, c7, c9⟩ hq

/-- Review r3 LOW-4: one manifest admits one keyset.  Two attaches under the same manifest with well-formed keysets
    used the same keyset; `hcr` is the run-local A2 instance for these two bodies (without Wf, natBE truncation lets a
    keyset with validUntil + 2^32 share the pinned digest). -/
theorem attach_keyset_unique {β : Type} {ks' : Keyset.Keyset} {now' k' : Nat} {d' : String}
    {f' : β → List (Nat × Nat)} {s' : Rules.Snapshot β} {x' : Bytes} {r' : Signed β} (hw : Keyset.Wf ks)
    (hw' : Keyset.Wf ks') (hcr : digestOf ks = digestOf ks' → Keyset.body ks = Keyset.body ks')
    (h : attach verify now ks m d k f s x = .ok r) (h' : attach verify now' ks' m d' k' f' s' x' = .ok r') :
    ks = ks' := by
  obtain ⟨v, sd, rb, hd, hr, ⟨c1, c2, c3, c4, c5, c6, c7, c8, c9, c10, c11⟩, -⟩ := attach_dec h
  obtain ⟨v', sd', rb', hd', hr', ⟨c1', c2', c3', c4', c5', c6', c7', c8', c9', c10', c11'⟩, -⟩ := attach_dec h'
  exact Keyset.body_inj hw hw' (hcr (c8.symm.trans c8'))

/-- Review r3 LOW-5, monotone: on a nondecreasing clock, a keyset expired on day `now` attaches nothing on any later
    day, under any manifest (a snapshot expired on `now` likewise: `attach_expired`); a binding refusal. -/
theorem attach_dead_after {now' : Nat} (hle : now ≤ now') (hk : ks.notAfter < now) :
    attach verify now' ks m d k f s x = .error .binding := by
  cases hres : attach verify now' ks m d k f s x with
  | ok r =>
    obtain ⟨v, sd, rb, hd, hr, ⟨c1, c2, c3, c4, c5, c6, c7, c8, c9, c10, c11⟩, -⟩ := attach_dec hres
    simp only [Keyset.ksLive, Bool.and_eq_true, decide_eq_true_eq] at c9
    omega
  | error e =>
    cases e with
    | binding => rfl
    | quorum =>
      obtain ⟨v, sd, rb, hd, hr, ⟨c1, c2, c3, c4, c5, c6, c7, c8, c9, c10, c11⟩, -⟩ := attach_quorum_dec hres
      simp only [Keyset.ksLive, Bool.and_eq_true, decide_eq_true_eq] at c9
      omega

/-- The message preimage fixes (keyset digest, header) for well-formed headers (round-1 HIGH-1): no cross-keyset or
    cross-header reuse short of a SHA3 collision [A2].  `decode_wf` / `decodeHeader_wf` discharge hw for decoded
    headers; `Manifest.Wf` gives the 64-byte keyset digest. -/
theorem sigMsg_pre_inj {a b : Bytes} {h h' : Header} (hw : h.Wf) (hw' : h'.Wf) (ha : a.length = 64)
    (hb : b.length = 64) (he : sigTag ++ a ++ h.bytes = sigTag ++ b ++ h'.bytes) : a = b ∧ h = h' := by
  rw [List.append_assoc, List.append_assoc] at he
  have he2 := List.append_cancel_left he
  obtain ⟨h1, h2⟩ := List.append_inj he2 (by rw [ha, hb])
  refine ⟨h1, ?_⟩
  have := decodeHeader_bytes hw []
  rw [List.append_nil] at this
  have := decodeHeader_bytes hw' []
  rw [List.append_nil] at this
  have e1 := decodeHeader_bytes hw []
  have e2 := decodeHeader_bytes hw' []
  rw [h2] at e1
  rw [e1] at e2
  exact (Prod.mk.inj (Option.some.inj e2)).1

/-- Domain separation: no keyset-signature preimage is a snapshot-signature preimage (tags differ). -/
theorem sigTag_sep (a b : Bytes) : Keyset.sigTag ++ a ≠ sigTag ++ b := by
  intro h
  have l1 : 4 ≤ Keyset.sigTag.length := by decide +kernel
  have l2 : 4 ≤ sigTag.length := by decide +kernel
  have t1 : Keyset.sigTag.take 4 = [82, 82, 47, 75] := by decide +kernel
  have t2 : sigTag.take 4 = [82, 82, 47, 71] := by decide +kernel
  have h4 := congrArg (fun l => l.take 4) h
  simp only [List.take_append_of_le_length l1, List.take_append_of_le_length l2, t1, t2] at h4
  simp at h4

/-- Round 5 MED-1: a snapshot past its validUntil attaches nothing, whoever signed it; a binding refusal. -/
theorem attach_expired {v : Snap} (hd : decode x = some v) (hv : v.head.validUntil < now) :
    attach verify now ks m d k f s x = .error .binding := by
  cases hres : attach verify now ks m d k f s x with
  | ok r =>
    obtain ⟨v', sd, rb, hd', hr, ⟨c1, c2, c3, c4, c5, c6, c7, c8, c9, c10, c11⟩, -⟩ := attach_dec hres
    rw [hd] at hd'
    cases hd'
    omega
  | error e =>
    cases e with
    | binding => rfl
    | quorum =>
      obtain ⟨v', sd, rb, hd', hr, ⟨c1, c2, c3, c4, c5, c6, c7, c8, c9, c10, c11⟩, -⟩ := attach_quorum_dec hres
      rw [hd] at hd'
      cases hd'
      omega

theorem attachChain_some_eq (hh : Keyset.admitHead verify pin now st g steps = some (ks, st')) :
    attachChain verify pin now st m g steps d k f s x =
      (st', if m.genesis = pin then attach verify now ks m d k f s x else .error .binding) := by
  unfold attachChain
  rw [hh]

theorem attachChain_none_eq (hh : Keyset.admitHead verify pin now st g steps = none) :
    attachChain verify pin now st m g steps d k f s x = (st, .error .binding) := by
  unfold attachChain
  rw [hh]

/-- Round 5 MED-3: a chain attach used the head of the verifier's chain from its own genesis pin, which the manifest
    names; the head is well formed (no Wf hypothesis here: `attach_sound` and `attach_pinned` apply to it), is epoch
    `steps.length ≥ st.epoch`, every new step dated `now` (stmts6 MED-C), on a day not before `st.day`, and the ratchet
    returned is (head epoch, head digest, `now`, `st.cp`; STMT-CHANGE K2).  STMT-CHANGE final review MED-1: steps at or
    below the persisted epoch are not bounded by `now` (`Keyset.walk`).  STMT-CHANGE final review 2 LOW-1: nor ordered
    (`Keyset.admitFold` for `Keyset.admitChain`). -/
theorem attachChain_sound (h : attachChain verify pin now st m g steps d k f s x = (st', .ok r)) :
    ∃ ks, Keyset.admitHead verify pin now st g steps = some (ks, st') ∧ Keyset.admitFold verify pin g steps = some ks ∧
      Keyset.Wf ks ∧ st' = ⟨ks.epoch, digestOf ks, now, st.cp⟩ ∧ ks.epoch = steps.length ∧ st.epoch ≤ ks.epoch ∧
      st.day ≤ now ∧ m.genesis = pin ∧ (∀ p ∈ steps.drop st.epoch, p.1 = now) ∧
      attach verify now ks m d k f s x = .ok r := by
  cases hh : Keyset.admitHead verify pin now st g steps with
  | none =>
    rw [attachChain_none_eq hh] at h
    cases h
  | some o =>
    obtain ⟨ks, st''⟩ := o
    rw [attachChain_some_eq hh] at h
    have h1 := (Prod.mk.inj h).1
    have h2 := (Prod.mk.inj h).2
    subst h1
    by_cases hg : m.genesis = pin
    · rw [if_pos hg] at h2
      obtain ⟨hc, hst, he, hd, _, _, hp2, _⟩ := Keyset.admitHead_sound hh
      exact ⟨ks, rfl, hc, (Keyset.admitFold_wf hc).1, hst, Keyset.admitFold_epoch hc, he, hd, hg, hp2, h2⟩
    · rw [if_neg hg] at h2
      cases h2

/-- K3 consumer: `admitBatchHead` is `Keyset.admitHead`, the head kept with the batch day and genesis pin. -/
theorem admitBatchHead_eq : admitBatchHead verify pin now st g steps = some (H, st') ↔
    Keyset.admitHead verify pin now st g steps = some (H.ks, st') ∧ H.day = now ∧ H.pin = pin := by
  unfold admitBatchHead
  cases hh : Keyset.admitHead verify pin now st g steps with
  | none => simp
  | some p =>
    obtain ⟨ks, st''⟩ := p
    cases H
    simp only [Option.map_some, Option.some.injEq, Prod.mk.injEq]
    constructor
    · rintro ⟨h1, rfl⟩
      cases h1
      exact ⟨⟨rfl, rfl⟩, rfl, rfl⟩
    · rintro ⟨⟨rfl, rfl⟩, rfl, rfl⟩
      exact ⟨rfl, rfl⟩

/-- K3 consumer: an attach under an admitted head, with a manifest pinning it (`ManPins`), is K2's chain attach. -/
theorem attachAt_chain (hh : admitBatchHead verify pin now st g steps = some (H, st'))
    (ha : attachAt verify H d k f s x = .ok r) (hm : ManPins m now pin H.ks k x) :
    attachChain verify pin now st m g steps d k f s x = (st', .ok r) := by
  obtain ⟨hh', hday, -⟩ := admitBatchHead_eq.1 hh
  obtain ⟨hmt, hmg, hmk, v, sd, rest, hd, hp, hr, hs⟩ := hm
  rw [attachChain_some_eq hh', if_pos hmg, attach_of_core hd hr ⟨hmt, hmk, hp, hs⟩, ← hday]
  unfold attachAt at ha
  rw [ha]

/-- K3 consumer: K2's chain attach that succeeds is the attach under the head it admitted. -/
theorem chain_attachAt (hh : admitBatchHead verify pin now st g steps = some (H, st'))
    (hc : attachChain verify pin now st m g steps d k f s x = (st', .ok r)) : attachAt verify H d k f s x = .ok r := by
  obtain ⟨hh', hday, -⟩ := admitBatchHead_eq.1 hh
  rw [attachChain_some_eq hh'] at hc
  have h2 := (Prod.mk.inj hc).2
  by_cases hg : m.genesis = pin
  · rw [if_pos hg] at h2
    obtain ⟨-, -, -, -, -, -, hcore⟩ := attach_split h2 (by simp)
    unfold attachAt
    rw [hday]
    exact hcore
  · rw [if_neg hg] at h2
    cases h2

/-- K3 consumer: what an attach under a head checked (attach_pinned and attach_sound without a manifest), on the
    head's day and keyset; `Keyset.Wf` holds for every admitted head (`Keyset.admitChain_wf`). -/
theorem attachAt_sound (hw : Keyset.Wf H.ks) (h : attachAt verify H d k f s x = .ok r) :
    ∃ v, decode x = some v ∧ v.head.kind = k ∧ v.head.asOf = s.asOf ∧ v.head.asOf ≤ H.day ∧
      H.day ≤ v.head.validUntil ∧ v.head.count = s.count ∧ rowsDigest d k f s = some v.head.rows ∧
      ksLive H.ks H.day = true ∧ r.toSnapshot = s ∧ r.scope = v.head.scope ∧ r.validUntil = v.head.validUntil ∧
      r.day = H.day ∧ r.keyset = digestOf H.ks ∧ Keyset.minSource ≤ H.ks.kSource ∧ ∃ es : List Keyset.Entry,
      es.Sublist H.ks.entries ∧ H.ks.kSource ≤ es.length ∧ (es.map (·.keyId)).Nodup ∧ (es.map (·.employee)).Nodup ∧
      ∀ e ∈ es, e.role = Keyset.source ∧ bit e.scopes (v.head.scope.byte - 1) = true ∧ bit e.kinds (k - 1) = true ∧
        liveAt e v.head.asOf = true ∧ liveAt e H.day = true ∧ v.head.validUntil ≤ e.validUntil ∧
        ∃ q ∈ v.sigs, q.keyId = e.keyId ∧ verify e.pk (sigMsg (digestOf H.ks) v.head) q.sig = true := by
  obtain ⟨v, -, hd, ⟨c1, c2, c3, c4, c5, c6, c7⟩, hq, -, e1, -, e3, e4, e5, e6⟩ := attachCore_ok h
  exact ⟨v, hd, c1, c2, c3, c4, c5, c6, c7, e1, e3, e4, e5, e6, quorum_entries hw c3 c4 hq⟩

theorem attachHdr_map {β γ : Type} {a n : Nat} {rd : Option Bytes} (mk : Snap → Kind → β) (g : β → γ) :
    (attachHdr verify now ks k a n rd x mk).map g = attachHdr verify now ks k a n rd x fun v kd => g (mk v kd) := by
  unfold attachHdr
  cases decode x with
  | none => rfl
  | some v =>
    dsimp only
    split
    · split
      · split <;> rfl
      · rfl
    · rfl

/-- An attach under a head carries the rows it was given. -/
theorem attachAt_rows (h : attachAt verify H d k f s x = .ok r) : r.toSnapshot = s := by
  obtain ⟨-, -, -, -, -, -, e, -⟩ := attachCore_ok h
  exact e

/-- K3 on the flat index: an attach under a head is `attachHdr` on the rows' date, count and digest, the rest of the
    fact being the rows themselves and the head's day and keyset: the rows enter its checks only through those three. -/
theorem attachAt_hdr : (attachAt verify H d k f s x).map (fun r => (r.toSnapshot, r.kind, r.scope, r.validUntil, r.day,
      r.keyset)) = attachHdr verify H.day H.ks k s.asOf s.count (rowsDigest d k f s) x fun v kd =>
      (s, kd, v.head.scope, v.head.validUntil, H.day, digestOf H.ks) := by
  unfold attachAt attachCore
  exact attachHdr_map _ _

/-- Round 5 MED-3, review stmts5 MED-A / L2, stmts6 MED-C / LOW-D, rollback: a chain below the persisted epoch, a clock
    behind the persisted day, not a calendar date or more than `Keyset.maxSkewDays` past a non-fresh persisted day, a
    new step not dated `now`, or a chain whose keyset at the persisted epoch is not the persisted head (fork) is
    refused, however live and well signed, and the ratchet stays where it was.  STMT-CHANGE final review MED-1: "a step
    after `now`" is gone (`Keyset.admitHead_refuses`).  STMT-CHANGE final review 2 LOW-1: the fork is any keyset the
    prefix reaches (`Keyset.admitFold`). -/
theorem attachChain_rollback (h : steps.length < st.epoch ∨ now < st.day ∨ Rules.validDate now = false ∨
      (st.day ≠ 0 ∧ Rules.dayNum st.day + Keyset.maxSkewDays < Rules.dayNum now) ∨
      (∃ p ∈ steps.drop st.epoch, p.1 ≠ now) ∨
      ∃ c, Keyset.admitFold verify pin g (steps.take st.epoch) = some c ∧ digestOf c ≠ st.head) :
    attachChain verify pin now st m g steps d k f s x = (st, .error .binding) := by
  apply attachChain_none_eq
  apply Keyset.admitHead_refuses
  rcases h with h | h | h | h | h | h
  · exact Or.inr (Or.inr (Or.inr (Or.inl h)))
  · exact Or.inl h
  · exact Or.inr (Or.inl h)
  · exact Or.inr (Or.inr (Or.inl h))
  · exact Or.inr (Or.inr (Or.inr (Or.inr (Or.inl h))))
  · exact Or.inr (Or.inr (Or.inr (Or.inr (Or.inr h))))

/-- Round 5 MED-3: a manifest naming another genesis, or a new step dated after `now`, is a binding refusal.
    STMT-CHANGE final review MED-1: new steps only (`Keyset.walk`). -/
theorem attachChain_refuses (h : m.genesis ≠ pin ∨ ∃ p ∈ steps.drop st.epoch, now < p.1) :
    (attachChain verify pin now st m g steps d k f s x).2 = .error .binding := by
  cases hh : Keyset.admitHead verify pin now st g steps with
  | none => rw [attachChain_none_eq hh]
  | some o =>
    obtain ⟨ks, st''⟩ := o
    rw [attachChain_some_eq hh]
    rcases h with h | ⟨p, hp, hlt⟩
    · simp [if_neg h]
    · obtain ⟨⟨_, _, _, _, hp1⟩, _⟩ := Keyset.admitHead_some hh
      have := hp1 p hp
      omega

/-- Review stmts5 MED-B: once the chain is admitted the ratchet advances to its head, whatever the snapshot does, so a
    refused attach on the new head never leaves an older, still-live chain replayable. -/
theorem attachChain_ratchet (h : Keyset.admitHead verify pin now st g steps = some (ks, st')) :
    (attachChain verify pin now st m g steps d k f s x).1 = st' := by
  rw [attachChain_some_eq h]

/-- Review stmts5 L3: neither refusal is ALLOW-equivalent: it carries no facts, and the Rules layer finds no usable
    snapshot in it (D7 strictest; `.quorum` lines go to review, `.binding` is refused loudly). -/
theorem attachChain_refused_unusable (h : (attachChain verify pin now st m g steps d k f s x).2 = .error e) :
    (attachChain verify pin now st m g steps d k f s x).2.toOption = none ∧ ∀ (today maxAge : Nat) (ok : Nat → α → Bool),
      Rules.usable today maxAge ok ((attachChain verify pin now st m g steps d k f s x).2.toOption.map (·.toSnapshot)) =
        false := by
  rw [h]
  refine ⟨rfl, fun today maxAge ok => rfl⟩

/-- Review stmts5 MED-A, persisted head pin: if any chain from the same pin reaches the persisted head digest, an attach
    from that ratchet used a chain that agrees with it at every epoch up to the persisted one (no fork at or below it).
    `hcr` is the run-local A2 instance, as in `Keyset.admitFold_pinned`.  STMT-CHANGE final review 2 LOW-1:
    `Keyset.admitFold` for `Keyset.admitChain` (labels unordered; an `admitChain` chain is one, `admitChain_fold`). -/
theorem attachChain_head_pinned {g' : Bytes} {steps' : List (Nat × Bytes)} {c' : Keyset.Keyset}
    (h : attachChain verify pin now st m g steps d k f s x = (st', .ok r))
    (h' : Keyset.admitFold verify pin g' steps' = some c') (hd : digestOf c' = st.head)
    (hcr : ∀ i j c c'', Keyset.admitFold verify pin g (steps.take i) = some c →
      Keyset.admitFold verify pin g' (steps'.take j) = some c'' → digestOf c = digestOf c'' →
      Keyset.body c = Keyset.body c'') :
    steps'.length = st.epoch ∧ ∀ i c c'', i ≤ st.epoch → Keyset.admitFold verify pin g (steps.take i) = some c →
      Keyset.admitFold verify pin g' (steps'.take i) = some c'' → c = c'' := by
  obtain ⟨ks, hh, -⟩ := attachChain_sound h
  obtain ⟨⟨_, _, _, g4, _⟩, ⟨c, hc, hdc⟩, _⟩ := Keyset.admitHead_some hh
  have key := Keyset.admitFold_pinned hc h' (by rw [hd, hdc]) (by
    intro i j c1 c2 e1 e2 e3
    rw [List.take_take] at e1
    exact hcr _ _ c1 c2 e1 e2 e3)
  have hlen : (steps.take st.epoch).length = st.epoch := by simp; omega
  refine ⟨by rw [key.1, hlen], ?_⟩
  intro i c1 c2 hi e1 e2
  apply key.2 i c1 c2
  · rw [List.take_take, Nat.min_eq_left hi]; exact e1
  · exact e2

/-- Review stmts5 L6: an attach is live on the verifier's day: its chain did not go back (epoch, day), its head keyset is
    the one the manifest names and is live today, the fact is in its window, and kSource ≥ 2 distinct employees' SOURCE
    keys, live at asOf and today, signed it. -/
theorem attachChain_live (h : attachChain verify pin now st m g steps d k f s x = (st', .ok r)) :
    ∃ ks v, Keyset.admitHead verify pin now st g steps = some (ks, st') ∧ st.epoch ≤ ks.epoch ∧ st.day ≤ now ∧
      ksLive ks now = true ∧ m.keyset = digestOf ks ∧ decode x = some v ∧ v.head.asOf ≤ now ∧
      now ≤ v.head.validUntil ∧ Keyset.minSource ≤ ks.kSource ∧ ∃ es : List Keyset.Entry, es.Sublist ks.entries ∧
        ks.kSource ≤ es.length ∧ (es.map (·.employee)).Nodup ∧ ∀ e ∈ es, e.role = Keyset.source ∧
          liveAt e v.head.asOf = true ∧ liveAt e now = true ∧
          ∃ q ∈ v.sigs, q.keyId = e.keyId ∧ verify e.pk (sigMsg (digestOf ks) v.head) q.sig = true := by
  obtain ⟨ks, hh, hc, hw, hst, hep, hse, hday, hg, hp2, hat⟩ := attachChain_sound h
  obtain ⟨v, sd, rb, hd, hr, c1, c2, c3, c4, c5, c6, c7, c8, c9, c10, c11, -⟩ := attach_pinned hat
  obtain ⟨v', hd', _, _, hmin, es, hsub, hl, hn2, hn1, hes⟩ := attach_sound hw hat
  rw [hd] at hd'
  cases hd'
  refine ⟨ks, v, hh, hse, hday, c9, c8, hd, c4, c5, hmin, es, hsub, hl, hn1, ?_⟩
  intro e he
  obtain ⟨r1, r2, r3, r4, r5, r6, r7⟩ := hes e he
  exact ⟨r1, r4, r5, r7⟩

/-- K3: an attached fact records the kind it was attached as, which is its header's signed kind byte (review F1), the
    verifier's day and the digest of the head keyset it was counted under, so a fact of another kind, day or epoch
    never counts in a batch (`Scoped.counts`).  Proof: `attachChain_sound` gives the head `ks` and `attach … = .ok r`;
    unfold `attach` as `attach_dec` does (cases on decode, reads, both guards, then `Kind.ofByte k`, a `cases` on `kd`
    closing `kd.byte = k`); in the ok branch every conjunct is `rfl`. -/
-- STMT-CHANGE r2
theorem attachChain_binds (h : attachChain verify pin now st m g steps d k f s x = (st', .ok r)) :
    r.kind.byte = k ∧ (∃ v, decode x = some v ∧ v.head.kind = r.kind.byte) ∧ r.day = now ∧
      ∃ ks, Keyset.admitHead verify pin now st g steps = some (ks, st') ∧ r.keyset = digestOf ks := by
  obtain ⟨ks, hh, -, -, -, -, -, -, -, -, hat⟩ := attachChain_sound h
  obtain ⟨kd, hk, e1, e2, e3⟩ := attach_fields hat
  obtain ⟨v, sd, rb, hd, hr, c, -⟩ := attach_dec hat
  have hb : r.kind.byte = k := by rw [e1]; exact ofByte_kind hk
  exact ⟨hb, ⟨v, hd, by rw [hb]; exact c.2.1⟩, e2, ks, hh, e3⟩

/-! Attach vectors (cross vectors for tests/test_right_rail_gate_snapshot.py), stub verify; every negative has a
    positive twin differing in one fact.  Keysets: roster 9, 10 (employees 1, 2) plus the SOURCE keys given, live
    20261021..20261121, kSource 2 (`Keyset.minSource`, review stmts5 L4). -/
/-- SOURCE key with pk byte `b`, employee `p`, scope mask `sc`, kind mask `ki`, window 20261001..`vu`. -/
def vecSrc (b p : UInt8) (sc : Nat := 255) (ki : Nat := 255) (vu : Nat := 20261031) : Keyset.Entry :=
  { Keyset.vecRoster b p with role := Keyset.source, scopes := sc, kinds := ki, validFrom := 20261001, validUntil := vu }
def vecLong : Keyset.Entry := vecSrc 20 3 255 255 20271231
def vecLong2 : Keyset.Entry := vecSrc 21 4 255 255 20271231
def vecKsOf (srcs : List Keyset.Entry) : Keyset.Keyset :=
  (Keyset.vecGen ([Keyset.vecRoster 9 1, Keyset.vecRoster 10 2] ++ srcs) []).ks
def vecKs : Keyset.Keyset := vecKsOf [vecSrc 20 3, vecSrc 21 4]
def vecS (a : Nat) : Rules.Snapshot Rules.Death := ⟨a, 0, []⟩
/-- Kind-1 IDV header for asOf `a`, validUntil `vu`, count 0, over `vecS a`'s rows digest. -/
def vecHead (a vu : Nat) : Header :=
  ⟨1, .IDV, a, vu, 0, (rowsDigest "RR/GATE/READ-DMF/v2" 1 Rules.Death.fields (vecS a)).getD []⟩
/-- Manifest for day `td` naming `ks` and genesis `gen`, pinning `h` in slot 1 (which carries `sl`), three empty slots,
    no redo rows, zero base. -/
def vecMan (ks : Keyset.Keyset) (h : Header) (td : Nat) (sl : Bytes := h.rows) (gen : Bytes := List.replicate 64 4) :
    Manifest :=
  ⟨List.replicate 64 1, List.replicate 64 2, List.replicate 64 3, .OBSERVE, td, digestOf ks, gen,
    [digest h, zeroDigest, zeroDigest, zeroDigest], setTag ++ 1 :: sl ++ [0, 0, 0] ++ natBE 4 0 ++ zeroDigest⟩
/-- The refusal, if any. -/
def vecErr {β : Type} : Except Refusal β → Option Refusal | .ok _ => none | .error e => some e
/-- The refusal, if any, when `h`, with stub records from the keys `sg`, attaches as kind 1 over `vecS h.asOf` under
    `ks` on the verifier's day `now` and manifest `m` (default: for `now`, pinning `h`). -/
def vecAtt (ks : Keyset.Keyset) (h : Header) (sg : List Keyset.Entry) (now : Nat) (m : Manifest := vecMan ks h now) :
    Option Refusal :=
  vecErr (attach (fun _ _ _ => true) now ks m "RR/GATE/READ-DMF/v2" 1 Rules.Death.fields (vecS h.asOf)
    (encode ⟨h, Keyset.vecRecs sg⟩))
def vecH : Header := vecHead 20261020 20261031
def vecK : List Keyset.Entry := [vecSrc 20 3, vecSrc 21 4]
#guard vecAtt vecKs vecH vecK 20261021 == none
-- round 5 MED-1: validUntil 20261025 on day 20261030 is refused; validUntil 20261031 attaches that day
#guard vecAtt vecKs (vecHead 20261020 20261025) vecK 20261030 == some Refusal.binding
#guard vecAtt vecKs vecH vecK 20261030 == none
-- the snapshot expired by the verifier's day (validUntil 20261031 < now; the keyset is live to 20261121): refused
#guard vecAtt vecKs vecH vecK 20261101 == some Refusal.binding
-- backdated asOf (before the keys' window), or validUntil past it: everything binds, no quorum (round 5 MED-2)
#guard vecAtt vecKs (vecHead 20260930 20261031) vecK 20261021 == some Refusal.quorum
#guard vecAtt vecKs (vecHead 20261020 20261105) vecK 20261021 == some Refusal.quorum
-- asOf after today, or a manifest whose today is not the verifier's day (LOW-5): refused
#guard vecAtt vecKs (vecHead 20261022 20261031) vecK 20261021 == some Refusal.binding
#guard vecAtt vecKs vecH vecK 20261022 (vecMan vecKs vecH 20261021) == some Refusal.binding
-- keyset expired on the verifier's day (keys valid to 20271231, header to 20261231): refused; its last day attaches
#guard vecAtt (vecKsOf [vecLong, vecLong2]) (vecHead 20261020 20261231) [vecLong, vecLong2] 20261122 ==
  some Refusal.binding
#guard vecAtt (vecKsOf [vecLong, vecLong2]) (vecHead 20261020 20261231) [vecLong, vecLong2] 20261121 == none
-- slot, keyset digest or pin does not match: refused
#guard vecAtt vecKs vecH vecK 20261021 (vecMan vecKs vecH 20261021 (List.replicate 64 1)) == some Refusal.binding
#guard vecAtt vecKs vecH vecK 20261021 { vecMan vecKs vecH 20261021 with keyset := List.replicate 64 5 } ==
  some Refusal.binding
#guard vecAtt vecKs vecH vecK 20261021
  { vecMan vecKs vecH 20261021 with pins := [digest (vecHead 20261020 20261030), zeroDigest, zeroDigest, zeroDigest] } ==
  some Refusal.binding
-- header kind, count or rows differ from the attached rules (the manifest pins the changed header): refused
#guard vecAtt vecKs { vecH with kind := 2 } vecK 20261021 == some Refusal.binding
#guard vecAtt vecKs { vecH with count := 1 } vecK 20261021 == some Refusal.binding
#guard vecAtt vecKs { vecH with rows := List.replicate 64 6 } vecK 20261021 == some Refusal.binding
-- key 20 lacks the IDV scope bit or the kind-1 bit, or is revoked; an absent key or a ROSTER key signs: no quorum
#guard vecAtt (vecKsOf [vecSrc 20 3 254, vecSrc 21 4]) vecH vecK 20261021 == some Refusal.quorum
#guard vecAtt (vecKsOf [vecSrc 20 3 255 254, vecSrc 21 4]) vecH vecK 20261021 == some Refusal.quorum
#guard vecAtt (vecKsOf [{ vecSrc 20 3 with revokedFrom := 20261015 }, vecSrc 21 4]) vecH vecK 20261021 ==
  some Refusal.quorum
-- a revocation dated after asOf and after today still kills the key (liveAt ignores the date)
#guard vecAtt (vecKsOf [{ vecSrc 20 3 with revokedFrom := 20261030 }, vecSrc 21 4]) vecH vecK 20261021 ==
  some Refusal.quorum
#guard vecAtt vecKs vecH [vecSrc 20 3, vecSrc 23 5] 20261021 == some Refusal.quorum
#guard vecAtt vecKs vecH [vecSrc 20 3, Keyset.vecRoster 9 1] 20261021 == some Refusal.quorum
/-- Round 5 MED-2, k-of-n: kSource 2 over SOURCE keys 20 and 22 (employee 3) and 21 (employee 4). -/
def vecKs2 : Keyset.Keyset := vecKsOf [vecSrc 20 3, vecSrc 21 4, vecSrc 22 3]
#guard vecAtt vecKs2 vecH [vecSrc 20 3, vecSrc 21 4] 20261021 == none
-- one signer (k-1) and two keys of one employee: no quorum.  A duplicate record is not even a short quorum: the
-- sig block must have strictly increasing keyIds (`SigsSorted`), so decode fails and the refusal is `.binding`.
#guard vecAtt vecKs2 vecH [vecSrc 20 3] 20261021 == some Refusal.quorum
#guard vecAtt vecKs2 vecH [vecSrc 20 3, vecSrc 22 3] 20261021 == some Refusal.quorum
#guard vecAtt vecKs2 vecH [vecSrc 20 3, vecSrc 20 3] 20261021 == some Refusal.binding
-- train14 LOW-6: one byte after the base refuses the manifest
#guard decodeMan (encodeMan (vecMan vecKs vecH 20261021)) == some (vecMan vecKs vecH 20261021)
#guard decodeMan (encodeMan { vecMan vecKs vecH 20261021 with pre := (vecMan vecKs vecH 20261021).pre ++ [0] }) == none

/-! Round 5 MED-3, review stmts5 MED-A / MED-B / L2: attachChain vectors.  Genesis vecG: roster 9, 10 and SOURCE keys
    vecLong, vecLong2, signed by 9 and 10, live 20261021..20261121; vecC1, vecC2 re-issue it from 20261101, 20261102;
    vecC3 from 20261103 revokes vecLong; vecF1 is a true fork (another epoch 1, from 20261102, signed by the same two
    employees). -/
def vecG : Keyset.Frame :=
  Keyset.vecGen [Keyset.vecRoster 9 1, Keyset.vecRoster 10 2, vecLong, vecLong2]
    [Keyset.vecRoster 9 1, Keyset.vecRoster 10 2]
def vecC1 : Keyset.Frame :=
  Keyset.vecNext vecG.ks 20261101 vecG.ks.entries [Keyset.vecRoster 9 1, Keyset.vecRoster 10 2]
def vecC2 : Keyset.Frame :=
  Keyset.vecNext vecC1.ks 20261102 vecC1.ks.entries [Keyset.vecRoster 9 1, Keyset.vecRoster 10 2]
def vecC3 : Keyset.Frame :=
  Keyset.vecNext vecC2.ks 20261103
    (vecC2.ks.entries.map fun e => if e.keyId = vecLong.keyId then { e with revokedFrom := 20261103 } else e)
    [Keyset.vecRoster 9 1, Keyset.vecRoster 10 2]
def vecF1 : Keyset.Frame :=
  Keyset.vecNext vecG.ks 20261102 vecG.ks.entries [Keyset.vecRoster 9 1, Keyset.vecRoster 10 2]
def vecH1 : Header := vecHead 20261104 20261110
/-- A persisted ratchet: epoch `e`, head `k`, day `day`; vecI is a fresh node's. -/
def vecSt (e : Nat) (k : Keyset.Keyset) (day : Nat) : Keyset.Ratchet := ⟨e, digestOf k, day, zeroDigest⟩
def vecI : Keyset.Ratchet := Keyset.Ratchet.init (digestOf vecG.ks)
/-- Ratchet and refusal from `attachChain` with vecG's pin on day 20261105, persisted ratchet `st` and steps `ch`,
    attaching `h` (signed by vecLong and vecLong2) under a manifest for that day naming head `hd` and genesis `gen`. -/
def vecCh (ch : List (Nat × Keyset.Frame)) (st : Keyset.Ratchet) (hd : Keyset.Keyset) (gen : Bytes := digestOf vecG.ks)
    (h : Header := vecH1) : Keyset.Ratchet × Option Refusal :=
  let o := attachChain (fun _ _ _ => true) (digestOf vecG.ks) 20261105 st (vecMan hd h 20261105 (gen := gen))
    (Keyset.encode vecG) (ch.map fun p => (p.1, Keyset.encode p.2)) "RR/GATE/READ-DMF/v2" 1 Rules.Death.fields
    (vecS h.asOf) (encode ⟨h, Keyset.vecRecs [vecLong, vecLong2]⟩)
  (o.1, vecErr o.2)
#guard vecCh [] vecI vecG.ks == (vecSt 0 vecG.ks 20261105, none)
-- rollback below the persisted epoch: refused, ratchet unchanged; a manifest naming another genesis: refused, but the
-- node's own chain was admitted, so its ratchet advances (MED-B)
#guard vecCh [] (vecSt 1 vecC1.ks 20261101) vecG.ks == (vecSt 1 vecC1.ks 20261101, some Refusal.binding)
#guard vecCh [] vecI vecG.ks (List.replicate 64 4) == (vecSt 0 vecG.ks 20261105, some Refusal.binding)
-- stmts6 MED-C: a new step must be dated the verifier's day; vecC1 dated 20261101 is refused by a fresh node, but a
-- node that admitted it on 20261101 re-walks it with that record
#guard vecCh [(20261101, vecC1)] vecI vecC1.ks == (vecI, some Refusal.binding)
#guard vecCh [(20261101, vecC1)] (vecSt 1 vecC1.ks 20261101) vecC1.ks == (vecSt 1 vecC1.ks 20261105, none)
#guard vecCh [(20261101, vecC1)] (vecSt 2 vecC2.ks 20261102) vecC1.ks == (vecSt 2 vecC2.ks 20261102, some Refusal.binding)
-- a step dated after the verifier's day is refused (vecC1 is live and signed on 20261106 as well)
#guard vecCh [(20261106, vecC1)] vecI vecC1.ks == (vecI, some Refusal.binding)
#guard vecCh [(20261105, vecC1)] vecI vecC1.ks == (vecSt 1 vecC1.ks 20261105, none)
-- MED-A, true fork: the walk admits vecF1, and a fresh node attaches through it (only the head pin closes forks, A6),
-- but a node that persisted vecC1 at epoch 1 refuses it, under a manifest naming either head
#guard Keyset.vecWalk vecG [(20261102, vecF1)] == some (digestOf vecF1.ks)
#guard vecCh [(20261105, vecF1)] vecI vecF1.ks == (vecSt 1 vecF1.ks 20261105, none)
#guard vecCh [(20261105, vecF1)] vecI vecC1.ks == (vecSt 1 vecF1.ks 20261105, some Refusal.binding)
#guard vecCh [(20261102, vecF1)] (vecSt 1 vecC1.ks 20261101) vecF1.ks ==
  (vecSt 1 vecC1.ks 20261101, some Refusal.binding)
-- MED-B: an epoch-3 chain with a bad READ-DMF header is refused but advances the ratchet to epoch 3, so the epoch-2
-- chain, where vecLong is still live, is refused afterwards; a fresh node attaches through it
#guard vecCh [(20261105, vecC1), (20261105, vecC2), (20261105, vecC3)] vecI vecC3.ks
  (h := { vecH1 with rows := List.replicate 64 6 }) == (vecSt 3 vecC3.ks 20261105, some Refusal.binding)
#guard vecCh [(20261105, vecC1), (20261105, vecC2)] (vecSt 3 vecC3.ks 20261105) vecC2.ks ==
  (vecSt 3 vecC3.ks 20261105, some Refusal.binding)
#guard vecCh [(20261105, vecC1), (20261105, vecC2)] vecI vecC2.ks == (vecSt 2 vecC2.ks 20261105, none)
-- L2: a clock behind the persisted day is refused; the persisted day itself attaches
#guard vecCh [(20261101, vecC1)] (vecSt 1 vecC1.ks 20261106) vecC1.ks == (vecSt 1 vecC1.ks 20261106, some Refusal.binding)
#guard vecCh [(20261101, vecC1)] (vecSt 1 vecC1.ks 20261105) vecC1.ks == (vecSt 1 vecC1.ks 20261105, none)
-- MED-C: a new step dated before the persisted day, or between it and the verifier's day, is refused; dated the
-- verifier's day, it attaches
#guard vecCh [(20261101, vecC1), (20261102, vecC2)] (vecSt 1 vecC1.ks 20261103) vecC2.ks ==
  (vecSt 1 vecC1.ks 20261103, some Refusal.binding)
#guard vecCh [(20261101, vecC1), (20261103, vecC2)] (vecSt 1 vecC1.ks 20261103) vecC2.ks ==
  (vecSt 1 vecC1.ks 20261103, some Refusal.binding)
#guard vecCh [(20261101, vecC1), (20261105, vecC2)] (vecSt 1 vecC1.ks 20261103) vecC2.ks ==
  (vecSt 2 vecC2.ks 20261105, none)
-- LOW-D: 32 days past the persisted day is refused and not persisted; 31 days attaches
#guard vecCh [] (vecSt 0 vecG.ks 20261004) vecG.ks == (vecSt 0 vecG.ks 20261004, some Refusal.binding)
#guard vecCh [] (vecSt 0 vecG.ks 20261005) vecG.ks == (vecSt 0 vecG.ks 20261105, none)
-- MED-C literal: the node last ran 20261030, vecG expires 20261121, today is 20261130 (31 days on); a fork of vecG
-- labelled 20261110 (inside vecG's life, signed by its two employees) is refused though vecG signed it on that day
def vecFork2 : Keyset.Frame :=
  Keyset.vecNext vecG.ks 20261110 vecG.ks.entries [Keyset.vecRoster 9 1, Keyset.vecRoster 10 2]
def vecChLate (ch : List (Nat × Keyset.Frame)) (hd : Keyset.Keyset) : Keyset.Ratchet × Option Refusal :=
  let h := vecHead 20261104 20261210
  let o := attachChain (fun _ _ _ => true) (digestOf vecG.ks) 20261130 (vecSt 0 vecG.ks 20261030) (vecMan hd h 20261130)
    (Keyset.encode vecG) (ch.map fun p => (p.1, Keyset.encode p.2)) "RR/GATE/READ-DMF/v2" 1 Rules.Death.fields
    (vecS h.asOf) (encode ⟨h, Keyset.vecRecs [vecLong, vecLong2]⟩)
  (o.1, vecErr o.2)
#guard vecChLate [(20261110, vecFork2)] vecFork2.ks == (vecSt 0 vecG.ks 20261030, some Refusal.binding)
#guard vecChLate [(20261130, vecFork2)] vecFork2.ks == (vecSt 0 vecG.ks 20261030, some Refusal.binding)

end BlindLedger.Gate.SnapshotV2
