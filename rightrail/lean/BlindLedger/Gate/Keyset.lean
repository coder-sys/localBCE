import BlindLedger.Gate.Verify
import BlindLedger.Gate.AnchorTheorems
import BlindLedger.Sha3FastEq

namespace BlindLedger.Gate.Keyset

def keyTag : Bytes := "RR/KEY/v1".toUTF8.toList ++ [0]
def live : Nat := 0xFFFFFFFF

structure Entry where
  keyId : Bytes
  employee : Bytes
  idp : Bytes
  role : Nat
  scopes : Nat
  kinds : Nat
  validFrom : Nat
  validUntil : Nat
  revokedFrom : Nat
  capCount : Nat
  capCents : Nat
  pk : Bytes

def entryW : List Nat := [64, 64, 64, 1, 1, 1, 4, 4, 4, 2, 8, 2, mlDsa87Key]

def Entry.parts (e : Entry) : List Bytes :=
  [e.keyId, e.employee, e.idp, natBE 1 e.role, natBE 1 e.scopes, natBE 1 e.kinds, natBE 4 e.validFrom,
   natBE 4 e.validUntil, natBE 4 e.revokedFrom, natBE 2 e.capCount, natBE 8 e.capCents, natBE 2 e.pk.length, e.pk]

def cut (n : Nat) (x : Bytes) : Option (Bytes × Bytes) := if n ≤ x.length then some (x.take n, x.drop n) else none

def chop : List Nat → Bytes → Option (List Bytes × Bytes)
  | [], x => some ([], x)
  | w :: ws, x => do
    let a ← cut w x
    let r ← chop ws a.2
    pure (a.1 :: r.1, r.2)

def Sorted (es : List Entry) : Prop := (es.map (beNat ·.keyId)).Pairwise (· < ·)

instance (es : List Entry) : Decidable (Sorted es) := by unfold Sorted; infer_instance

def bit (mask i : Nat) : Bool := mask >>> i % 2 == 1

theorem cut_app {n : Nat} {l y : Bytes} (h : l.length = n) : cut n (l ++ y) = some (l, y) := by
  subst h; simp [cut]

theorem chop_flatten (ps : List Bytes) (y : Bytes) : chop (ps.map List.length) (ps.flatten ++ y) = some (ps, y) := by
  induction ps with
  | nil => simp [chop]
  | cons p ps ih => simp [chop, List.append_assoc, cut_app (l := p) rfl, ih]

theorem natBE_length (w v : Nat) : (natBE w v).length = w := by simp [natBE]


/-- `"RR/KEYSET/v2NUL"` (13 bytes, same width as v1). -/
def tag : Bytes := [82, 82, 47, 75, 69, 89, 83, 69, 84, 47, 118, 50, 0]
def sigTag : Bytes := "RR/KEYSET/v2/SIG".toUTF8.toList ++ [0]
def source : Nat := 1
def approver : Nat := 2
def roster : Nat := 5
def maxKeys : Nat := 1024
def maxSigs : Nat := 16
/-- Two-person key: a snapshot needs SOURCE keys of at least two distinct
    employees (1 < kSource), so one person never attaches facts alone. -/
def minSource : Nat := 2
/-- Two-person floor, counted in distinct employees (`roster_persons`); lowering it
    needs an approved design change. -/
def minRoster : Nat := 2
/-- Roster threshold cap, maxSigs / 2 (review r3 MED-2): a rotation's one block carries kRoster(cur) + kRoster(new)
    records at most, so every well-formed successor fits one 16-record block (`admitSucc_fits`); without it a roster
    above 8 could never rotate, and with no grace that is permanent lock-out. -/
def maxRoster : Nat := 8
/-- STMT-CHANGE K2 MED1: keyset life cap in calendar days (`Rules.dayNum`), at most 32 dates across a month or a year end
    alike (the YYYYMMDD cap it replaces let no keyset span 31 Dec, so every chain died with its genesis year). -/
def maxLife : Nat := 31
/-- K2 recovery (b): a successor is live `minOverlap` days before its predecessor expires (`succOk`), so every rotation
    window holds ≥ 8 dates; a life shorter than that could never have a successor and is refused at decode. -/
def minOverlap : Nat := 7
/-- Review stmts6 LOW-D: the verifier's day may run at most 31 calendar days (`Rules.dayNum`) past its persisted day, the
    longest span of one keyset life (≤ 32 dates).  A clock skewed further forward is refused and never persisted; a node
    idle longer is refused too, fail-closed, and recovers by `reinit` (K2 recovery (c)), not re-provisioning; a skew
    within it that was persisted is undone by an in-band `reinit` to the real day when the persisted head is live on
    that day, else from the head's notBefore (`walk`, final review MED-1 and review 2 LOW-2, `vecSkewL`). -/
def maxSkewDays : Nat := 31
/-- Both ends calendar dates, life `minOverlap .. maxLife` days (Python `decode`). -/
def lifeOk (nb na : Nat) : Bool :=
  Rules.validDate nb && Rules.validDate na && Rules.dayNum nb + minOverlap ≤ Rules.dayNum na &&
    Rules.dayNum na ≤ Rules.dayNum nb + maxLife

structure SigRec where
  keyId : Bytes
  sig : Bytes
  deriving DecidableEq

structure Keyset where
  state : Bytes
  epoch : Nat
  prev : Bytes
  notBefore : Nat
  notAfter : Nat
  kRoster : Nat
  kSource : Nat
  entries : List Entry

structure Frame where
  ks : Keyset
  sigs : List SigRec

def headW : List Nat := [13, 64, 4, 64, 4, 4, 1, 1, 4]

def body (k : Keyset) : Bytes :=
  [tag, k.state, natBE 4 k.epoch, k.prev, natBE 4 k.notBefore, natBE 4 k.notAfter, natBE 1 k.kRoster,
    natBE 1 k.kSource, natBE 4 k.entries.length].flatten ++ (k.entries.map (·.parts.flatten)).flatten

def encodeSigs (ss : List SigRec) : Bytes := natBE 1 ss.length ++ (ss.map fun r => r.keyId ++ r.sig).flatten
def encode (f : Frame) : Bytes := body f.ks ++ encodeSigs f.sigs
def digestOf (k : Keyset) : Bytes := sha3 (body k)
def msgOf (k : Keyset) : Bytes := sha3 (sigTag ++ body k)

/-- K2's guard plus: role 1..5 (ROSTER = 5 now decodes; review LOW), window ordered, scopes/kinds only on SOURCE, caps
    only on APPROVER. -/
def decodeEntry (x : Bytes) : Option (Entry × Bytes) := do
  let (ps, r) ← chop entryW x
  match ps with
  | [id, emp, idp, ro, sc, ki, vf, vu, rv, cc, cents, pl, pk] =>
    guard (beNat pl = mlDsa87Key ∧ id = sha3 (keyTag ++ pk) ∧ 1 ≤ beNat ro ∧ beNat ro ≤ roster ∧ beNat vf ≤ beNat vu ∧
      (beNat ro = source ∨ beNat sc = 0 ∧ beNat ki = 0) ∧ (beNat ro = approver ∨ beNat cc = 0 ∧ beNat cents = 0))
    pure (⟨id, emp, idp, beNat ro, beNat sc, beNat ki, beNat vf, beNat vu, beNat rv, beNat cc, beNat cents, pk⟩, r)
  | _ => none

def SigsSorted (ss : List SigRec) : Prop := (ss.map (beNat ·.keyId)).Pairwise (· < ·)
instance (ss : List SigRec) : Decidable (SigsSorted ss) := by unfold SigsSorted; infer_instance

def decodeEntries : Nat → Bytes → Option (List Entry × Bytes)
  | 0, x => some ([], x)
  | n + 1, x => do
    let (e, r) ← decodeEntry x
    let (es, r) ← decodeEntries n r
    pure (e :: es, r)

def decodeSigs : Nat → Bytes → Option (List SigRec × Bytes)
  | 0, x => some ([], x)
  | n + 1, x => do
    let (ps, r) ← chop [64, mlDsa87Signature] x
    match ps with
    | [id, sg] => let (ss, r) ← decodeSigs n r; pure (⟨id, sg⟩ :: ss, r)
    | _ => none

/-- `u8 m ‖ (keyId ‖ sig)^m`, 1 ≤ m ≤ 16, strictly ascending keyIds (a duplicate record refuses), nothing after. -/
def decodeSigBlock (x : Bytes) : Option (List SigRec) := do
  let (m, r) ← cut 1 x
  guard (1 ≤ beNat m ∧ beNat m ≤ maxSigs)
  let (ss, rest) ← decodeSigs (beNat m) r
  guard (rest = [] ∧ SigsSorted ss)
  pure ss

/-- Number of distinct `key` values among `es` (the employee, for ROSTER and SOURCE quorums alike; LOW b, round 5 MED-2). -/
def nDistinct (key : Entry → Bytes) (es : List Entry) : Nat := (es.map key).eraseDups.length

def liveAt (e : Entry) (t : Nat) : Bool := e.revokedFrom == live && e.validFrom ≤ t && t ≤ e.validUntil

/-- Distinct EMPLOYEES holding an unrevoked ROSTER key (window ignored); roster votes never exceed it in persons
    (`persons_le_liveRoster`). -/
def liveRoster (k : Keyset) : Nat :=
  nDistinct (·.employee) (k.entries.filter fun e => e.role == roster && e.revokedFrom == live)

/-- Round 5 LOW (roster windows): distinct EMPLOYEES holding a ROSTER key live over the keyset's whole life.  The
    decoder floor kRoster ≤ coverRoster (it implies round 4's kRoster ≤ liveRoster) means a live keyset always reaches
    its own roster quorum (`roster_available`): a key expiring mid-life never strands a rotation. -/
def coverRoster (k : Keyset) : Nat :=
  nDistinct (·.employee) (k.entries.filter fun e => e.role == roster && liveAt e k.notBefore && liveAt e k.notAfter)

def decode (x : Bytes) : Option Frame := do
  let (ps, r) ← chop headW x
  match ps with
  | [t, st, ep, pv, nb, na, kr, kso, n] =>
    guard (t = tag ∧ (beNat ep = 0 → pv = zeroDigest) ∧ beNat nb ≤ beNat na ∧ lifeOk (beNat nb) (beNat na) = true ∧
      beNat n ≤ maxKeys ∧ minSource ≤ beNat kso ∧ beNat kso ≤ maxSigs)
    let (es, sb) ← decodeEntries (beNat n) r
    let k : Keyset := ⟨st, beNat ep, pv, beNat nb, beNat na, beNat kr, beNat kso, es⟩
    guard (Sorted es ∧ minRoster ≤ k.kRoster ∧ k.kRoster ≤ maxRoster ∧ k.kRoster ≤ coverRoster k)
    let ss ← decodeSigBlock sb
    pure ⟨k, ss⟩
  | _ => none

/-! ### Counting -/

def rosterOk (t : Nat) (e : Entry) : Bool := e.role == roster && liveAt e t
/-- SOURCE key for scope byte s (bit s-1) and kind kd (bit kd-1), live at the snapshot's asOf `a`, its window covering
    the snapshot's validUntil `vu` (MED-B: an expired, unrevoked key cannot sign a backdated asOf, nor a validUntil past
    its own).  Round 5: no today test; attach checks asOf ≤ now ≤ vu, so the key is live on the verifier's day too
    (`attach_sound`).  s = 0 or kd = 0 fails closed (round-1 MED-3). -/
def sourceOk (s kd a vu : Nat) (e : Entry) : Bool :=
  1 ≤ s && 1 ≤ kd && e.role == source && bit e.scopes (s - 1) && bit e.kinds (kd - 1) && liveAt e a && vu ≤ e.validUntil

def signedBy (verify : Bytes → Bytes → Bytes → Bool) (msg : Bytes) (ss : List SigRec) (e : Entry) : Bool :=
  ss.any fun r => r.keyId == e.keyId && verify e.pk msg r.sig

/-- Filtered over ENTRIES (sorted, distinct), not records: a key counts once however many records name it. -/
def signers (verify : Bytes → Bytes → Bytes → Bool) (ok : Entry → Bool) (k : Keyset) (msg : Bytes)
    (ss : List SigRec) : List Entry :=
  k.entries.filter fun e => ok e && signedBy verify msg ss e

/-- thr distinct `key` values among the signers, `(·.employee)` at every call site (ROSTER, and SOURCE since round 5
    MED-2): two keys of one employee are one vote. -/
def quorum (verify : Bytes → Bytes → Bytes → Bool) (ok : Entry → Bool) (key : Entry → Bytes) (k : Keyset) (thr : Nat)
    (msg : Bytes) (ss : List SigRec) : Bool :=
  1 ≤ thr && thr ≤ nDistinct key (signers verify ok k msg ss)

def ksLive (k : Keyset) (t : Nat) : Bool := k.notBefore ≤ t && t ≤ k.notAfter

/-! ### Rotation -/

def succOk (old new : Keyset) : Bool :=
  new.state == old.state && new.epoch == old.epoch + 1 && new.prev == digestOf old && old.notBefore ≤ new.notBefore &&
    Rules.dayNum new.notBefore + minOverlap ≤ Rules.dayNum old.notAfter &&
    old.entries.all fun e => e.revokedFrom == live ||
      new.entries.any fun f => f.keyId == e.keyId && f.revokedFrom != live && f.revokedFrom ≤ e.revokedFrom

/-- Genesis: the pin is the authority (A4); its own roster quorum (in employees) is checked at its notBefore. -/
def admitGenesis (verify : Bytes → Bytes → Bytes → Bool) (pin x : Bytes) : Option Keyset := do
  let f ← decode x
  guard (f.ks.epoch = 0 ∧ digestOf f.ks = pin ∧
    quorum verify (rosterOk f.ks.notBefore) (·.employee) f.ks f.ks.kRoster (msgOf f.ks) f.sigs = true)
  pure f.ks

/-- Admitted on day `today` (A5): BOTH keysets live today, kRoster(cur) distinct employees with roster keys of epoch e
    live today authorize it, kRoster(new) distinct employees of epoch e+1 live today possess it.
    Review MED-A, design decision 8 amended: no succession from an expired keyset, no grace constant.  Reason: freshness
    bounds a fork by keys revoked later in the chain to the life of the last keyset they were live in (≤ 32 dates) on an
    honest clock, while a grace would only widen that window for a node that cannot attach anyway (ksLive); a fresh
    node's walk is closed by the head pin (`admitChain_pinned`). -/
def admitSucc (verify : Bytes → Bytes → Bytes → Bool) (today : Nat) (cur : Keyset) (x : Bytes) : Option Keyset := do
  let f ← decode x
  guard (succOk cur f.ks = true ∧ ksLive cur today = true ∧ ksLive f.ks today = true ∧
    quorum verify (rosterOk today) (·.employee) cur cur.kRoster (msgOf f.ks) f.sigs = true ∧
    quorum verify (rosterOk today) (·.employee) f.ks f.ks.kRoster (msgOf f.ks) f.sigs = true)
  pure f.ks

/-- Genesis bytes, then each successor with the day it was admitted (the verifier's own record, A5; days never go
    backwards, review LOW e), so re-walking history does not fail on keysets that expired after their step. -/
def admitChain (verify : Bytes → Bytes → Bytes → Bool) (pin x : Bytes) (steps : List (Nat × Bytes)) :
    Option Keyset := do
  guard ((steps.map (·.1)).Pairwise (· ≤ ·))
  let g ← admitGenesis verify pin x
  steps.foldlM (fun c s => admitSucc verify s.1 c s.2) g

/-- `admitChain` without its day-order guard (`admitChain_fold`).  `walk` admits the hash-pinned prefix with it: those
    labels are in no digest (final review 2 LOW-1). -/
def admitFold (verify : Bytes → Bytes → Bytes → Bool) (pin x : Bytes) (steps : List (Nat × Bytes)) : Option Keyset := do
  let g ← admitGenesis verify pin x
  steps.foldlM (fun c s => admitSucc verify s.1 c s.2) g

/-- Review stmts5 MED-A / MED-B / L2: what the verifier persists after every chain it admits: the head's epoch and
    digest, the day it ran, and the digest of the last `reinit` record it applied (zeros if none). -/
structure Ratchet where
  epoch : Nat
  head : Bytes
  day : Nat
  cp : Bytes
  deriving DecidableEq

/-- A fresh node: epoch 0, its genesis pin as head (`admitGenesis` checks digest = pin), day 0, no reinit. -/
def Ratchet.init (pin : Bytes) : Ratchet := ⟨0, pin, 0, zeroDigest⟩

/-- A chain at or past the persisted epoch whose keyset AT that epoch is the persisted head (MED-A: no fork at or below
    it, so no revocation is lost), then the steps past that epoch in day order, none dated after the calendar day `now`,
    its head live on `now` (K2 recovery (a): a day that puts no live keyset in force attaches nothing, so it is refused
    and a bad clock is never persisted).  STMT-CHANGE final review MED-1 and review 2 LOW-1: the prefix up to the
    persisted epoch is checked through `st.head` only.  Its keysets are pinned by that digest and its labels are in no
    digest, so a store writer rewrites them at will: a `now` bound or an order against them protects nothing against
    that writer, while a label from a forward-skewed run locked the node until the real day reached it and, after
    recovery, refused a new rotation dated before it.  The first new step's lower bound is `admitSucc`'s (the pinned
    head, signed notBefore, and its roster keys live on its day); the clock floor is the persisted day (`admitHead`),
    which only a `reinit` moves back, in band only by keys also live on that day (`reinitKeyOk`, final review 3 LOW-A). -/
def walk (verify : Bytes → Bytes → Bytes → Bool) (pin : Bytes) (now : Nat) (st : Ratchet) (x : Bytes)
    (steps : List (Nat × Bytes)) : Option Keyset := do
  guard (Rules.validDate now = true ∧ st.epoch ≤ steps.length ∧ (steps.drop st.epoch).Pairwise (·.1 ≤ ·.1) ∧
    ∀ p ∈ steps.drop st.epoch, p.1 ≤ now)
  let c ← admitFold verify pin x (steps.take st.epoch)
  guard (digestOf c = st.head)
  let k ← (steps.drop st.epoch).foldlM (fun c s => admitSucc verify s.1 c s.2) c
  if ksLive k now then pure k else none

/-- Admit the verifier's chain on day `now` against its persisted ratchet `st` (`walk`): `now` not behind the persisted
    day (L2) and, unless the node is fresh (`st.day = 0`), at most `maxSkewDays` past it (stmts6 LOW-D); every step past
    the persisted epoch is dated `now` (stmts6 MED-C: a new step is checked against keysets live today, so keys of a
    keyset expired before today authorize nothing, whatever day the step claims).  Returns the head and the next
    ratchet (head epoch, head digest, `now`, `st.cp`), whatever any snapshot later does (MED-B).  A persisted day ahead
    of the real one holds the node until the real day reaches it, or until an in-band `reinit` to the real day under a
    head live on it (`vecSkew`); after that, new steps dated the real day are admitted whatever the persisted labels
    (`walk`, `vecRot2`). -/
def admitHead (verify : Bytes → Bytes → Bytes → Bool) (pin : Bytes) (now : Nat) (st : Ratchet) (x : Bytes)
    (steps : List (Nat × Bytes)) : Option (Keyset × Ratchet) := do
  guard (st.day ≤ now ∧ (st.day = 0 ∨ Rules.dayNum now ≤ Rules.dayNum st.day + maxSkewDays) ∧
    ∀ p ∈ steps.drop st.epoch, p.1 = now)
  let k ← walk verify pin now st x steps
  pure (k, ⟨steps.length, digestOf k, now, st.cp⟩)

/-- `"RR/KEYSET/REINIT/v1NUL"` (20 bytes), in the domain-tag table. -/
def reinitTag : Bytes := "RR/KEYSET/REINIT/v1".toUTF8.toList ++ [0]
/-- Bytes `o ..< o + n` of `r` (a fixed-offset field, as Python's `struct.unpack_from`). -/
def field (r : Bytes) (o n : Nat) : Bytes := (r.drop o).take n
/-- REINIT/v1 body: tag 20 ‖ node 64 ‖ from (u32 epoch ‖ head 64 ‖ u32 day ‖ cp 64) ‖ to (u32 epoch ‖ head 64 ‖ u32 day),
    292 bytes; the sig block follows. -/
def reinitBody (node : Bytes) (fr : Ratchet) (te : Nat) (th : Bytes) (td : Nat) : Bytes :=
  reinitTag ++ node ++ natBE 4 fr.epoch ++ fr.head ++ natBE 4 fr.day ++ fr.cp ++ natBE 4 te ++ th ++ natBE 4 td

/-- A key that counts toward a re-init: a ROSTER key live on `now`; in band (final review 3 LOW-A), unless the node is
    fresh (`day = 0`), also live on the persisted day `day`, so a clock rollback cannot let keys that expired before the
    node admitted its head move the day back into their window and sign a fork dated there.  Every lawful in-band
    recovery passes: its head is the persisted head (`inband_reinit_same_epoch`), which was live on `day` (every run that
    persists a day needs its head live that day: `walk`) and is live on `now` (`walk`), and its kRoster cover-roster
    employees (`decode`) hold ROSTER keys live over its whole life, so on both days.  Residual: kRoster employees whose
    keys are live on both days (a window is an interval, so on every day between) still move the day back to `now`;
    those keys already authorize the head's successors on the persisted day with no re-init.  A ratchet whose day no
    head key covers (a pre-K2 lock at 99991231, `vecLock`) recovers by provisioning only (`inBand = false`). -/
def reinitKeyOk (inBand : Bool) (day now : Nat) (e : Entry) : Bool :=
  rosterOk now e && (!inBand || day == 0 || liveAt e day)

/-- K2 recovery (c), Python `_reinit`: operator recovery from a bad-clock lock-out or a missed rotation.  `r` = body ‖
    sig block, signed over SHA3-512(body) by kRoster(to-head) employees whose keys count (`reinitKeyOk`: ROSTER, live
    on `now` and, in band, on `st.day`; revoked keys never count).  It applies only on this node, from exactly the persisted ratchet (which then records the digest,
    so it applies once: `reinit_no_replay`), on to-day = `now`, along a `walk` to the to-head (steps keep their
    historical labels).  `inBand` (Python `reinit_day`, the feed's only entry) also needs to.epoch = st.epoch: it resets
    the day under the live persisted head and admits no keyset.  to.epoch > st.epoch (`inBand = false`, Python
    `reinit_provisioned`) carries the authority of its delivery channel, the genesis pin's custody: past an expired
    keyset no in-band signature tells the real chain from a fork made with its leaked keys (MED-C). -/
def reinit (verify : Bytes → Bytes → Bytes → Bool) (pin node : Bytes) (now : Nat) (st : Ratchet) (x : Bytes)
    (steps : List (Nat × Bytes)) (r : Bytes) (inBand : Bool) : Option Ratchet := do
  let ss ← decodeSigBlock (r.drop 292)
  guard (field r 0 20 = reinitTag ∧ field r 20 64 = node ∧ beNat (field r 84 4) = st.epoch ∧ field r 88 64 = st.head ∧
    beNat (field r 152 4) = st.day ∧ field r 156 64 = st.cp ∧ (inBand = true → beNat (field r 220 4) = st.epoch) ∧
    beNat (field r 220 4) = steps.length ∧ beNat (field r 288 4) = now ∧
    sha3 (r.take 292) ≠ field r 156 64)
  let k ← walk verify pin now st x steps
  if digestOf k = field r 224 64 ∧
    quorum verify (reinitKeyOk inBand st.day now) (·.employee) k k.kRoster (sha3 (r.take 292)) ss = true
  then pure ⟨steps.length, digestOf k, now, sha3 (r.take 292)⟩ else none

def EntryWf (e : Entry) : Prop :=
  e.keyId.length = 64 ∧ e.employee.length = 64 ∧ e.idp.length = 64 ∧ e.pk.length = mlDsa87Key ∧
    e.keyId = sha3 (keyTag ++ e.pk) ∧ 1 ≤ e.role ∧ e.role ≤ roster ∧ e.scopes < 256 ∧ e.kinds < 256 ∧
    e.validFrom ≤ e.validUntil ∧ e.validUntil < 2 ^ 32 ∧ e.revokedFrom < 2 ^ 32 ∧ e.capCount < 2 ^ 16 ∧
    e.capCents < 2 ^ 64 ∧ (e.role = source ∨ e.scopes = 0 ∧ e.kinds = 0) ∧
    (e.role = approver ∨ e.capCount = 0 ∧ e.capCents = 0)

def Wf (k : Keyset) : Prop :=
  k.state.length = 64 ∧ k.prev.length = 64 ∧ k.epoch < 2 ^ 32 ∧ (k.epoch = 0 → k.prev = zeroDigest) ∧
    k.notBefore ≤ k.notAfter ∧ lifeOk k.notBefore k.notAfter = true ∧ k.notAfter < 2 ^ 32 ∧
    minRoster ≤ k.kRoster ∧ k.kRoster ≤ maxRoster ∧ k.kRoster ≤ coverRoster k ∧ minSource ≤ k.kSource ∧ k.kSource ≤ maxSigs ∧
    k.entries.length ≤ maxKeys ∧ Sorted k.entries ∧ ∀ e ∈ k.entries, EntryWf e

def SigsWf (ss : List SigRec) : Prop :=
  1 ≤ ss.length ∧ ss.length ≤ maxSigs ∧ SigsSorted ss ∧ ∀ r ∈ ss, r.keyId.length = 64 ∧ r.sig.length = mlDsa87Signature

instance (e : Entry) : Decidable (EntryWf e) := by unfold EntryWf; infer_instance
instance (k : Keyset) : Decidable (Wf k) := by unfold Wf; infer_instance
instance (ss : List SigRec) : Decidable (SigsWf ss) := by unfold SigsWf; infer_instance

variable {verify : Bytes → Bytes → Bytes → Bool} {ok : Entry → Bool} {key : Entry → Bytes} {k cur : Keyset}
  {thr t now : Nat} {msg pin x y : Bytes} {ss ss' : List SigRec} {steps : List (Nat × Bytes)} {st st' : Ratchet}

/-! ### Codec: determinism, canonical form, bounds (no crypto assumption) -/


theorem sha3_len64 (x : Bytes) : (sha3 x).length = 64 := by
  unfold sha3
  rw [← Semantic.sha3_512_eq]
  exact Semantic.sha3_512_toList_length _

theorem cut_spec {n : Nat} {x a r : Bytes} (h : cut n x = some (a, r)) : a.length = n ∧ x = a ++ r := by
  unfold cut at h
  split at h
  · rename_i hn
    obtain ⟨rfl, rfl⟩ := Prod.mk.inj (Option.some.inj h)
    exact ⟨by simp [hn], (List.take_append_drop n x).symm⟩
  · simp at h

theorem chop_spec : ∀ (ws : List Nat) (x : Bytes) (ps : List Bytes) (r : Bytes), chop ws x = some (ps, r) →
    ps.map List.length = ws ∧ x = ps.flatten ++ r
  | [], x, ps, r, h => by
    simp only [chop, Option.some.injEq, Prod.mk.injEq] at h
    obtain ⟨rfl, rfl⟩ := h
    simp
  | w :: ws, x, ps, r, h => by
    unfold chop at h
    cases hc : cut w x with
    | none => simp [hc] at h
    | some a =>
      cases hr : chop ws a.2 with
      | none => simp [hc, hr] at h
      | some q =>
        simp [hc, hr] at h
        obtain ⟨rfl, rfl⟩ := h
        obtain ⟨h1, h2⟩ := cut_spec (a := a.1) (r := a.2) hc
        obtain ⟨h3, h4⟩ := chop_spec ws a.2 q.1 q.2 hr
        refine ⟨?_, ?_⟩
        · simp [h1, h3]
        · rw [List.flatten_cons, List.append_assoc, ← h4]; exact h2

theorem natBE_beNat' {w : Nat} {b : Bytes} (h : b.length = w) : natBE w (beNat b) = b := by
  subst h; exact natBE_beNat b

theorem beNat_lt_pow : ∀ (n : Nat) (bs : Bytes), bs.length = n → beNat bs < 256 ^ n
  | 0, bs, h => by
    cases bs with
    | nil => simp [beNat]
    | cons _ _ => simp at h
  | n + 1, bs, h => by
    have hne : bs ≠ [] := by
      rintro rfl
      simp at h
    obtain ⟨d, x, rfl⟩ : ∃ d x, bs = d ++ [x] := ⟨bs.dropLast, bs.getLast hne, (List.dropLast_concat_getLast hne).symm⟩
    have hl : d.length = n := by simpa using h
    have ih := beNat_lt_pow n d hl
    rw [beNat_append_singleton, Nat.pow_succ]
    have hx : x.toNat < 256 := UInt8.toNat_lt x
    have : (beNat d + 1) * 256 ≤ 256 ^ n * 256 := Nat.mul_le_mul_right 256 ih
    omega

theorem beNat_lt1 {b : Bytes} (h : b.length = 1) : beNat b < 256 := by
  have := beNat_lt_pow 1 b h; simpa using this
theorem beNat_lt2 {b : Bytes} (h : b.length = 2) : beNat b < 2 ^ 16 := by
  have := beNat_lt_pow 2 b h; simpa using this
theorem beNat_lt4 {b : Bytes} (h : b.length = 4) : beNat b < 2 ^ 32 := by
  have := beNat_lt_pow 4 b h; simpa using this
theorem beNat_lt8 {b : Bytes} (h : b.length = 8) : beNat b < 2 ^ 64 := by
  have := beNat_lt_pow 8 b h; simpa using this

theorem fail_bind {α β : Type} (f : α → Option β) (v : β) : (failure : Option α).bind f ≠ some v := by
  first | (intro h; cases h) | (intro h; simp [failure] at h)

theorem decodeEntry_spec {x r : Bytes} {e : Entry} (h : decodeEntry x = some (e, r)) :
    x = e.parts.flatten ++ r ∧ EntryWf e := by
  unfold decodeEntry at h
  rcases hch : chop entryW x with _ | ⟨ps, r'⟩
  · simp [hch] at h
  · obtain ⟨hmap, hx⟩ := chop_spec _ _ _ _ hch
    have hlen : ps.length = 13 := by simpa [entryW] using congrArg List.length hmap
    simp only [hch, Option.bind_some] at h
    rcases ps with _ | ⟨id, _ | ⟨emp, _ | ⟨idp, _ | ⟨ro, _ | ⟨sc, _ | ⟨ki, _ | ⟨vf, _ | ⟨vu, _ | ⟨rv, _ | ⟨cc, _ | ⟨cents, _ | ⟨pl, _ | ⟨pk, _ | ⟨z, zs⟩⟩⟩⟩⟩⟩⟩⟩⟩⟩⟩⟩⟩⟩ <;> first | (simp at hlen; done) | skip
    simp only [entryW, List.map_cons, List.map_nil, List.cons.injEq, and_true] at hmap
    obtain ⟨l1, l2, l3, l4, l5, l6, l7, l8, l9, l10, l11, l12, l13⟩ := hmap
    simp [guard] at h
    split at h
    · rename_i hg
      obtain ⟨hpl, hid, hro1, hro2, hvf, hsc, hcc⟩ := hg
      simp only [Option.bind_some, Option.some.injEq, Prod.mk.injEq] at h
      obtain ⟨rfl, rfl⟩ := h
      have e4 : natBE 1 (beNat ro) = ro := natBE_beNat' l4
      have e5 : natBE 1 (beNat sc) = sc := natBE_beNat' l5
      have e6 : natBE 1 (beNat ki) = ki := natBE_beNat' l6
      have e7 : natBE 4 (beNat vf) = vf := natBE_beNat' l7
      have e8 : natBE 4 (beNat vu) = vu := natBE_beNat' l8
      have e9 : natBE 4 (beNat rv) = rv := natBE_beNat' l9
      have e10 : natBE 2 (beNat cc) = cc := natBE_beNat' l10
      have e11 : natBE 8 (beNat cents) = cents := natBE_beNat' l11
      have e12 : natBE 2 pk.length = pl := by rw [l13, ← hpl]; exact natBE_beNat' l12
      refine ⟨?_, ?_⟩
      · rw [hx]; simp [Entry.parts, e4, e5, e6, e7, e8, e9, e10, e11, e12]
      · unfold EntryWf
        exact ⟨l1, l2, l3, l13, hid, hro1, hro2, beNat_lt1 l5, beNat_lt1 l6, hvf, beNat_lt4 l8, beNat_lt4 l9,
          beNat_lt2 l10, beNat_lt8 l11, hsc, hcc⟩
    · exact absurd h (fail_bind _ _)

theorem decodeEntries_spec : ∀ (n : Nat) (x : Bytes) (es : List Entry) (r : Bytes), decodeEntries n x = some (es, r) →
    x = (es.map (·.parts.flatten)).flatten ++ r ∧ es.length = n ∧ ∀ e ∈ es, EntryWf e
  | 0, x, es, r, h => by
    simp only [decodeEntries, Option.some.injEq, Prod.mk.injEq] at h
    obtain ⟨rfl, rfl⟩ := h
    simp
  | n + 1, x, es, r, h => by
    unfold decodeEntries at h
    cases h1 : decodeEntry x with
    | none => simp [h1] at h
    | some a =>
      cases h2 : decodeEntries n a.2 with
      | none => simp [h1, h2] at h
      | some q =>
        simp [h1, h2] at h
        obtain ⟨rfl, rfl⟩ := h
        obtain ⟨i1, i2⟩ := decodeEntry_spec (e := a.1) (r := a.2) h1
        obtain ⟨j1, j2, j3⟩ := decodeEntries_spec n a.2 q.1 q.2 h2
        refine ⟨?_, by simp [j2], ?_⟩
        · rw [i1, j1]; simp [List.append_assoc]
        · intro e he
          rcases List.mem_cons.1 he with rfl | he
          · exact i2
          · exact j3 e he

theorem decodeSigs_spec : ∀ (n : Nat) (x : Bytes) (ss : List SigRec) (r : Bytes), decodeSigs n x = some (ss, r) →
    x = (ss.map fun s => s.keyId ++ s.sig).flatten ++ r ∧ ss.length = n ∧
      ∀ s ∈ ss, s.keyId.length = 64 ∧ s.sig.length = mlDsa87Signature
  | 0, x, ss, r, h => by
    simp only [decodeSigs, Option.some.injEq, Prod.mk.injEq] at h
    obtain ⟨rfl, rfl⟩ := h
    simp
  | n + 1, x, ss, r, h => by
    unfold decodeSigs at h
    rcases hch : chop [64, mlDsa87Signature] x with _ | ⟨ps, r0⟩
    · simp [hch] at h
    · obtain ⟨hmap, hx⟩ := chop_spec _ _ _ _ hch
      simp only [hch, Option.bind_some] at h
      rcases ps with _ | ⟨id, _ | ⟨sg, _ | ⟨z, zs⟩⟩⟩
      · simp at hmap
      · simp at hmap
      · simp only [List.map_cons, List.map_nil, List.cons.injEq, and_true] at hmap
        obtain ⟨l1, l2⟩ := hmap
        cases h2 : decodeSigs n r0 with
        | none => simp [h2] at h
        | some q =>
          simp [h2] at h
          obtain ⟨rfl, rfl⟩ := h
          obtain ⟨j1, j2, j3⟩ := decodeSigs_spec n r0 q.1 q.2 h2
          refine ⟨?_, by simp [j2], ?_⟩
          · rw [hx, j1]; simp [List.append_assoc]
          · intro s hs
            rcases List.mem_cons.1 hs with rfl | hs
            · exact ⟨l1, l2⟩
            · exact j3 s hs
      · simp at hmap

theorem decodeSigBlock_spec {x : Bytes} {ss : List SigRec} (h : decodeSigBlock x = some ss) :
    x = encodeSigs ss ∧ SigsWf ss := by
  unfold decodeSigBlock at h
  rcases hc : cut 1 x with _ | ⟨m, r0⟩
  · simp [hc] at h
  · obtain ⟨hm, hx⟩ := cut_spec hc
    simp only [hc] at h
    rcases hd : decodeSigs (beNat m) r0 with _ | ⟨ss', rest⟩
    · simp [guard, hd] at h
    · simp [guard, hd] at h
      split at h
      · rename_i hg1
        simp only [Option.bind_some] at h
        split at h
        · rename_i hg2
          simp only [Option.bind_some, Option.some.injEq] at h
          subst h
          obtain ⟨j1, j2, j3⟩ := decodeSigs_spec _ _ _ _ hd
          refine ⟨?_, ?_⟩
          · unfold encodeSigs
            rw [hx, j1, hg2.1, j2, natBE_beNat' hm]; simp
          · unfold SigsWf
            exact ⟨by omega, by omega, hg2.2, j3⟩
        · exact absurd h (fail_bind _ _)
      · exact absurd h (fail_bind _ _)

theorem decode_spec {x : Bytes} {f : Frame} (h : decode x = some f) :
    x = encode f ∧ Wf f.ks ∧ SigsWf f.sigs := by
  unfold decode at h
  rcases hch : chop headW x with _ | ⟨ps, r⟩
  · simp [hch] at h
  · obtain ⟨hmap, hx⟩ := chop_spec _ _ _ _ hch
    have hlen : ps.length = 9 := by simpa [headW] using congrArg List.length hmap
    simp only [hch] at h
    rcases ps with _ | ⟨t, _ | ⟨st, _ | ⟨ep, _ | ⟨pv, _ | ⟨nb, _ | ⟨na, _ | ⟨kr, _ | ⟨kso, _ | ⟨n, _ | ⟨z, zs⟩⟩⟩⟩⟩⟩⟩⟩⟩⟩ <;> first | (simp at hlen; done) | skip
    simp only [headW, List.map_cons, List.map_nil, List.cons.injEq, and_true] at hmap
    obtain ⟨l1, l2, l3, l4, l5, l6, l7, l8, l9⟩ := hmap
    simp [guard] at h
    split at h
    · rename_i hg1
      obtain ⟨hT, hEp, hNb, hNa, hN, hS1, hS2⟩ := hg1
      subst hT
      simp only [Option.bind_some] at h
      rcases h2 : decodeEntries (beNat n) r with _ | ⟨es, sb⟩
      · simp [h2] at h
      · simp only [h2, Option.bind_some] at h
        split at h
        · rename_i hg2
          rcases h3 : decodeSigBlock sb with _ | ss
          · simp [h3] at h
          · simp only [h3, Option.bind_some, Option.some.injEq] at h
            subst h
            obtain ⟨j1, j2, j3⟩ := decodeEntries_spec _ _ _ _ h2
            obtain ⟨k1, k2⟩ := decodeSigBlock_spec h3
            have e3 : natBE 4 (beNat ep) = ep := natBE_beNat' l3
            have e5 : natBE 4 (beNat nb) = nb := natBE_beNat' l5
            have e6 : natBE 4 (beNat na) = na := natBE_beNat' l6
            have e7 : natBE 1 (beNat kr) = kr := natBE_beNat' l7
            have e8 : natBE 1 (beNat kso) = kso := natBE_beNat' l8
            have e9 : natBE 4 (beNat n) = n := natBE_beNat' l9
            refine ⟨?_, ?_, k2⟩
            · rw [hx, j1, k1]
              simp [encode, body, e3, e5, e6, e7, e8, j2, e9, List.append_assoc]
            · unfold Wf
              exact ⟨l2, l4, beNat_lt4 l3, hEp, hNb, hNa, beNat_lt4 l6, hg2.2.1, hg2.2.2.1, hg2.2.2.2, hS1, hS2,
                by rw [j2]; exact hN, hg2.1, j3⟩
        · exact absurd h (fail_bind _ _)
    · exact absurd h (fail_bind _ _)

/-- Entries round-trip under the v2 EntryWf, ROSTER (role 5) included (round-1 LOW). -/
theorem decodeEntry_enc {e : Entry} (h : EntryWf e) (y : Bytes) : decodeEntry (e.parts.flatten ++ y) = some (e, y) := by
  obtain ⟨h1, h2, h3, h4, h5, h6, h7, h8, h9, h10, h11, h12, h13, h14, h15, h16⟩ := h
  have hc : chop entryW (e.parts.flatten ++ y) = some (e.parts, y) := by
    have := chop_flatten e.parts y
    have hm : e.parts.map List.length = entryW := by
      simp [Entry.parts, entryW, natBE_length, h1, h2, h3, h4]
    rwa [hm] at this
  have f1 : beNat (natBE 2 e.pk.length) = mlDsa87Key := by
    rw [beNat_natBE 2 _ (by rw [h4]; unfold mlDsa87Key; decide)]; exact h4
  have f2 : beNat (natBE 1 e.role) = e.role := beNat_natBE 1 _ (by unfold roster at h7; omega)
  have f3 : beNat (natBE 1 e.scopes) = e.scopes := beNat_natBE 1 _ (by omega)
  have f4 : beNat (natBE 1 e.kinds) = e.kinds := beNat_natBE 1 _ (by omega)
  have f5 : beNat (natBE 4 e.validFrom) = e.validFrom := beNat_natBE 4 _ (by omega)
  have f6 : beNat (natBE 4 e.validUntil) = e.validUntil := beNat_natBE 4 _ (by omega)
  have f7 : beNat (natBE 4 e.revokedFrom) = e.revokedFrom := beNat_natBE 4 _ (by omega)
  have f8 : beNat (natBE 2 e.capCount) = e.capCount := beNat_natBE 2 _ (by omega)
  have f9 : beNat (natBE 8 e.capCents) = e.capCents := beNat_natBE 8 _ (by omega)
  unfold decodeEntry
  rw [hc]
  simp only [Option.bind_some]
  simp [Entry.parts, guard, f1, f2, f3, f4, f5, f6, f7, f8, f9, ← h5, h6, h7, h10, h15, h16]

theorem decodeEntries_enc : ∀ (es : List Entry), (∀ e ∈ es, EntryWf e) → ∀ y : Bytes,
    decodeEntries es.length ((es.map (·.parts.flatten)).flatten ++ y) = some (es, y)
  | [], _, y => by simp [decodeEntries]
  | e :: es, h, y => by
    have he := h e (by simp)
    have hes : ∀ e' ∈ es, EntryWf e' := fun e' h' => h e' (List.mem_cons_of_mem _ h')
    have := decodeEntry_enc he ((es.map (·.parts.flatten)).flatten ++ y)
    simp only [List.length_cons, decodeEntries, List.map_cons, List.flatten_cons, List.append_assoc]
    rw [this]
    simp [decodeEntries_enc es hes y]

theorem decodeSigs_enc : ∀ (ss : List SigRec), (∀ r ∈ ss, r.keyId.length = 64 ∧ r.sig.length = mlDsa87Signature) →
    ∀ y : Bytes, decodeSigs ss.length ((ss.map fun r => r.keyId ++ r.sig).flatten ++ y) = some (ss, y)
  | [], _, y => by simp [decodeSigs]
  | r :: ss, h, y => by
    have hr := h r (by simp)
    have hss : ∀ r' ∈ ss, r'.keyId.length = 64 ∧ r'.sig.length = mlDsa87Signature :=
      fun r' h' => h r' (List.mem_cons_of_mem _ h')
    have hc := chop_flatten [r.keyId, r.sig] ((ss.map fun r => r.keyId ++ r.sig).flatten ++ y)
    simp only [List.map_cons, List.map_nil, hr.1, hr.2, List.flatten_cons, List.flatten_nil, List.append_nil,
      List.append_assoc] at hc
    simp only [List.length_cons, decodeSigs, List.map_cons, List.flatten_cons, List.append_assoc]
    rw [hc]
    simp [decodeSigs_enc ss hss y]

/-- The signature block round-trips. -/
theorem decodeSigBlock_encode {ss : List SigRec} (h : SigsWf ss) : decodeSigBlock (encodeSigs ss) = some ss := by
  obtain ⟨h1, h2, h3, h4⟩ := h
  have h2' : ss.length < 256 := by unfold maxSigs at h2; omega
  have hb : beNat (natBE 1 ss.length) = ss.length := beNat_natBE 1 _ (by omega)
  have hd := decodeSigs_enc ss h4 []
  rw [List.append_nil] at hd
  unfold decodeSigBlock encodeSigs
  rw [cut_app (natBE_length 1 _)]
  simp [guard, hb, hd, h1, h2, h3]

theorem hdr_len {k : Keyset} (hst : k.state.length = 64) (hpv : k.prev.length = 64) :
    [tag, k.state, natBE 4 k.epoch, k.prev, natBE 4 k.notBefore, natBE 4 k.notAfter, natBE 1 k.kRoster,
      natBE 1 k.kSource, natBE 4 k.entries.length].map List.length = headW := by
  simp [headW, natBE_length, hst, hpv, tag]

/-- Well-formed frames round-trip. -/
theorem decode_encode {f : Frame} (hk : Wf f.ks) (hs : SigsWf f.sigs) : decode (encode f) = some f := by
  obtain ⟨k, ss⟩ := f
  obtain ⟨hst, hpv, hep, hep0, hnb, hna, hna2, hr1, hr2, hr3, hs1, hs2, hn, hsort, hent⟩ := hk
  simp only at hst hpv hep hep0 hnb hna hna2 hr1 hr2 hr3 hs1 hs2 hn hsort hent hs
  have hc := chop_flatten [tag, k.state, natBE 4 k.epoch, k.prev, natBE 4 k.notBefore, natBE 4 k.notAfter,
    natBE 1 k.kRoster, natBE 1 k.kSource, natBE 4 k.entries.length]
    ((k.entries.map (·.parts.flatten)).flatten ++ encodeSigs ss)
  rw [hdr_len hst hpv] at hc
  have he := decodeEntries_enc k.entries hent (encodeSigs ss)
  have hsb := decodeSigBlock_encode hs
  have hbody : encode ⟨k, ss⟩ = [tag, k.state, natBE 4 k.epoch, k.prev, natBE 4 k.notBefore, natBE 4 k.notAfter,
    natBE 1 k.kRoster, natBE 1 k.kSource, natBE 4 k.entries.length].flatten ++
      ((k.entries.map (·.parts.flatten)).flatten ++ encodeSigs ss) := by
    simp [encode, body, List.append_assoc]
  have g1 : beNat (natBE 4 k.epoch) = k.epoch := beNat_natBE 4 _ hep
  have g2 : beNat (natBE 4 k.notBefore) = k.notBefore := beNat_natBE 4 _ (by omega)
  have g3 : beNat (natBE 4 k.notAfter) = k.notAfter := beNat_natBE 4 _ hna2
  have g4 : beNat (natBE 1 k.kRoster) = k.kRoster := beNat_natBE 1 _ (by unfold maxRoster at hr2; omega)
  have g5 : beNat (natBE 1 k.kSource) = k.kSource := beNat_natBE 1 _ (by unfold maxSigs at hs2; omega)
  have g6 : beNat (natBE 4 k.entries.length) = k.entries.length := beNat_natBE 4 _ (by unfold maxKeys at hn; omega)
  have hk' : (⟨k.state, k.epoch, k.prev, k.notBefore, k.notAfter, k.kRoster, k.kSource, k.entries⟩ : Keyset) = k := rfl
  unfold decode
  rw [hbody, hc]
  simp only [Option.bind_some]
  simp [guard, g1, g2, g3, g4, g5, g6, he, hsb, hk', eq_true hep0, hnb, hna, hn, hs1, hs2, hsort, hr1, hr2, hr3]

/-- Review stmts5 L5, tombstone cap: a keyset of more than maxKeys = 1024 entries (revoked ones included; they are
    never pruned) is refused, whatever else holds; at 1024 a well-formed keyset round-trips (`decode_encode`). -/
theorem decode_over_cap {f : Frame} (hs : f.ks.state.length = 64) (hp : f.ks.prev.length = 64)
    (hn : maxKeys < f.ks.entries.length) (hl : f.ks.entries.length < 2 ^ 32) : decode (encode f) = none := by
  obtain ⟨k, ss⟩ := f
  simp only at hs hp hn hl
  have hc := chop_flatten [tag, k.state, natBE 4 k.epoch, k.prev, natBE 4 k.notBefore, natBE 4 k.notAfter,
    natBE 1 k.kRoster, natBE 1 k.kSource, natBE 4 k.entries.length]
    ((k.entries.map (·.parts.flatten)).flatten ++ encodeSigs ss)
  rw [hdr_len hs hp] at hc
  have hbody : encode ⟨k, ss⟩ = [tag, k.state, natBE 4 k.epoch, k.prev, natBE 4 k.notBefore, natBE 4 k.notAfter,
    natBE 1 k.kRoster, natBE 1 k.kSource, natBE 4 k.entries.length].flatten ++
      ((k.entries.map (·.parts.flatten)).flatten ++ encodeSigs ss) := by
    simp [encode, body, List.append_assoc]
  have g6 : beNat (natBE 4 k.entries.length) = k.entries.length := beNat_natBE 4 _ (by omega)
  have hn' : ¬ k.entries.length ≤ maxKeys := by omega
  unfold decode
  rw [hbody, hc]
  simp only [Option.bind_some]
  simp [guard, g6, hn']

/-- Canonical: a decoded frame re-encodes to exactly the input, so the signed body is the received prefix. -/
theorem encode_decode {x : Bytes} {f : Frame} (h : decode x = some f) : encode f = x := (decode_spec h).1.symm

/-- Everything decoded is well formed, with bounded keys (≤ 1024), records (1..16), thresholds (2 ≤ kRoster ≤ 8
    persons, kSource ≥ minSource = 2) and life. -/
theorem decode_wf {x : Bytes} {f : Frame} (h : decode x = some f) : Wf f.ks ∧ SigsWf f.sigs := (decode_spec h).2

/-- Unique encoding: two inputs that decode to the same frame are the same bytes. -/
theorem decode_inj {x y : Bytes} {f : Frame} (hx : decode x = some f) (hy : decode y = some f) : x = y :=
  (decode_spec hx).1.trans (decode_spec hy).1.symm

/-- A decoded signature block re-encodes to exactly its bytes. -/
theorem encodeSigs_decode {x : Bytes} {ss : List SigRec} (h : decodeSigBlock x = some ss) : encodeSigs ss = x :=
  (decodeSigBlock_spec h).1.symm

/-- Review r3 LOW-4: on well-formed keysets the body is injective (natBE truncation is excluded by the Wf bounds), so a
    keyset digest names one keyset short of a SHA3 collision [A2]; `admitChain_pinned` and `attach_keyset_unique` use
    it. -/
theorem body_inj {k k' : Keyset} (hw : Wf k) (hw' : Wf k') (h : body k = body k') : k = k' := by
  obtain ⟨ss0, hs⟩ : ∃ ss0 : List SigRec, SigsWf ss0 :=
    ⟨[⟨List.replicate 64 0, List.replicate mlDsa87Signature 0⟩], by
      refine ⟨by simp, by simp [maxSigs], by simp [SigsSorted], ?_⟩
      intro r hr
      simp at hr
      subst hr
      simp⟩
  have h1 := decode_encode (f := ⟨k, ss0⟩) hw hs
  have h2 := decode_encode (f := ⟨k', ss0⟩) hw' hs
  have e : encode ⟨k, ss0⟩ = encode ⟨k', ss0⟩ := by simp only [encode, h]
  rw [e, h2] at h1
  exact (Frame.mk.inj (Option.some.inj h1)).1.symm

theorem eraseDups_props' {α : Type} [BEq α] [LawfulBEq α] : ∀ (n : Nat) (l : List α), l.length ≤ n →
    l.eraseDups.Nodup ∧ l.eraseDups.length ≤ l.length
  | 0, [], _ => by simp
  | 0, _ :: _, h => by simp at h
  | _ + 1, [], _ => by simp
  | n + 1, a :: as, h => by
    rw [List.eraseDups_cons]
    have hl := List.length_filter_le (fun b => !b == a) as
    have hf : (as.filter fun b => !b == a).length ≤ n := by
      simp only [List.length_cons] at h; omega
    obtain ⟨ih1, ih2⟩ := eraseDups_props' n _ hf
    refine ⟨?_, ?_⟩
    · rw [List.nodup_cons]
      refine ⟨?_, ih1⟩
      intro hm
      rw [List.mem_eraseDups, List.mem_filter] at hm
      simp at hm
    · simp only [List.length_cons]
      omega

theorem dedup_nodup {α : Type} [BEq α] [LawfulBEq α] (l : List α) : l.eraseDups.Nodup :=
  (eraseDups_props' l.length l (Nat.le_refl _)).1

theorem dedup_le {α : Type} [BEq α] [LawfulBEq α] (l : List α) : l.eraseDups.length ≤ l.length :=
  (eraseDups_props' l.length l (Nat.le_refl _)).2

theorem dedup_mono {α : Type} [BEq α] [LawfulBEq α] {A B : List α} (h : ∀ x ∈ A, x ∈ B) :
    A.eraseDups.length ≤ B.eraseDups.length :=
  (dedup_nodup A).length_le_of_subset (fun x hx => List.mem_eraseDups.2 (h x (List.mem_eraseDups.1 hx)))

theorem pick_distinct {α β : Type} [BEq β] [LawfulBEq β] (f : α → β) : ∀ (n : Nat) (l : List α), l.length ≤ n →
    ∃ l' : List α, l'.Sublist l ∧ (l'.map f).Nodup ∧ l'.length = (l.map f).eraseDups.length
  | 0, [], _ => ⟨[], .slnil, by simp, by simp⟩
  | 0, _ :: _, h => by simp at h
  | _ + 1, [], _ => ⟨[], .slnil, by simp, by simp⟩
  | n + 1, a :: as, h => by
    have hf : (as.filter fun b => !(f b == f a)).length ≤ n := by
      have := List.length_filter_le (fun b => !(f b == f a)) as
      simp only [List.length_cons] at h; omega
    obtain ⟨l', hs, hn, hl⟩ := pick_distinct f n _ hf
    refine ⟨a :: l', (hs.trans List.filter_sublist).cons₂ a, ?_, ?_⟩
    · rw [List.map_cons, List.nodup_cons]
      refine ⟨?_, hn⟩
      intro hm
      rw [List.mem_map] at hm
      obtain ⟨y, hy, hy2⟩ := hm
      have := List.mem_filter.1 (hs.subset hy)
      simp [hy2] at this
    · rw [List.map_cons, List.eraseDups_cons, List.filter_map, List.length_cons, List.length_cons, hl]
      try rfl

theorem sorted_pw {es es' : List Entry} (hs : Sorted es) (hsub : es'.Sublist es) :
    es'.Pairwise (fun a b => a.keyId ≠ b.keyId) :=
  ((List.pairwise_map.1 hs).sublist hsub).imp (fun h h2 => by rw [h2] at h; exact Nat.lt_irrefl _ h)

theorem sorted_ids_nodup {es es' : List Entry} (hs : Sorted es) (hsub : es'.Sublist es) :
    (es'.map (·.keyId)).Nodup :=
  List.pairwise_map.2 (sorted_pw hs hsub)

theorem sorted_inj : ∀ {es : List Entry}, Sorted es → ∀ {e f : Entry}, e ∈ es → f ∈ es → e.keyId = f.keyId → e = f
  | [], _, e, f, he, _, _ => by simp at he
  | a :: es, hs, e, f, he, hf, h => by
    have hp := List.pairwise_map.1 hs
    rw [List.pairwise_cons] at hp
    obtain ⟨h1, h2⟩ := hp
    have hs2 : Sorted es := List.pairwise_map.2 h2
    rcases List.mem_cons.1 he with he1 | he' <;> rcases List.mem_cons.1 hf with hf1 | hf'
    · rw [he1, hf1]
    · have : beNat a.keyId < beNat f.keyId := h1 f hf'
      rw [← he1, h] at this; exact absurd this (Nat.lt_irrefl _)
    · have : beNat a.keyId < beNat e.keyId := h1 e he'
      rw [← hf1, ← h] at this; exact absurd this (Nat.lt_irrefl _)
    · exact sorted_inj hs2 he' hf' h

/-! ### Threshold soundness, completeness and non-inflation [A1: "signed" = verify true] -/

/-- Accepted means at least thr entries of THIS keyset with pairwise-distinct `key` values (and keyIds), each passing
    `ok`, each with a verifying record. -/
theorem quorum_sound (hs : Sorted k.entries) (h : quorum verify ok key k thr msg ss = true) :
    ∃ es : List Entry, es.Sublist k.entries ∧ 1 ≤ thr ∧ thr ≤ es.length ∧ (es.map key).Nodup ∧
      (es.map (·.keyId)).Nodup ∧ ∀ e ∈ es, ok e = true ∧ ∃ r ∈ ss, r.keyId = e.keyId ∧ verify e.pk msg r.sig = true := by
  unfold quorum at h
  simp only [Bool.and_eq_true, decide_eq_true_eq] at h
  obtain ⟨h1, h2⟩ := h
  obtain ⟨l', hs0, hn, hl⟩ := pick_distinct key _ (signers verify ok k msg ss) (Nat.le_refl _)
  have hsub : l'.Sublist k.entries := hs0.trans List.filter_sublist
  refine ⟨l', hsub, h1, ?_, hn, sorted_ids_nodup hs hsub, ?_⟩
  · unfold nDistinct at h2; omega
  · intro e he
    have := List.mem_filter.1 (hs0.subset he)
    simp only [Bool.and_eq_true] at this
    refine ⟨this.2.1, ?_⟩
    have h3 := this.2.2
    simp only [signedBy, List.any_eq_true, Bool.and_eq_true, beq_iff_eq] at h3
    obtain ⟨r, hr, hr1, hr2⟩ := h3
    exact ⟨r, hr, hr1, hr2⟩

/-- Converse: thr (≥ 1) entries of the keyset with distinct `key` values that pass `ok` and each have a verifying record
    make a quorum. -/
theorem quorum_complete {es : List Entry} (hes : es.Sublist k.entries) (h1 : 1 ≤ thr) (hl : thr ≤ es.length)
    (hn : (es.map key).Nodup) (he : ∀ e ∈ es, ok e = true ∧ ∃ r ∈ ss, r.keyId = e.keyId ∧ verify e.pk msg r.sig = true) :
    quorum verify ok key k thr msg ss = true := by
  unfold quorum
  simp only [Bool.and_eq_true, decide_eq_true_eq]
  refine ⟨h1, ?_⟩
  have hmem : ∀ e ∈ es, e ∈ signers verify ok k msg ss := by
    intro e hme
    obtain ⟨hok, r, hr, hr1, hr2⟩ := he e hme
    refine List.mem_filter.2 ⟨hes.subset hme, ?_⟩
    simp only [Bool.and_eq_true, signedBy, List.any_eq_true, beq_iff_eq]
    exact ⟨hok, r, hr, hr1, hr2⟩
  have h3 : (es.map key).length ≤ ((signers verify ok k msg ss).map key).eraseDups.length :=
    hn.length_le_of_subset (fun x hx => by
      obtain ⟨e, hme, rfl⟩ := List.mem_map.1 hx
      exact List.mem_eraseDups.2 (List.mem_map_of_mem (hmem e hme)))
  unfold nDistinct
  rw [List.length_map] at h3
  omega

/-- Those signers also hold pairwise-distinct public keys (keyId is the hash of pk, checked per entry). -/
theorem quorum_distinct_pk (hs : Sorted k.entries) (hw : ∀ e ∈ k.entries, EntryWf e)
    (h : quorum verify ok key k thr msg ss = true) :
    ∃ es : List Entry, es.Sublist k.entries ∧ thr ≤ es.length ∧ (es.map (·.pk)).Nodup ∧
      ∀ e ∈ es, ok e = true ∧ ∃ r ∈ ss, r.keyId = e.keyId ∧ verify e.pk msg r.sig = true := by
  obtain ⟨es, hsub, h1, h2, _, _, h5⟩ := quorum_sound hs h
  refine ⟨es, hsub, h2, ?_, h5⟩
  have hp := sorted_pw hs hsub
  refine List.pairwise_map.2 (List.Pairwise.imp_of_mem ?_ hp)
  intro a b ha hb hne hpk
  apply hne
  rw [(hw a (hsub.subset ha)).2.2.2.2.1, (hw b (hsub.subset hb)).2.2.2.2.1, hpk]

/-- Duplicating or reordering signature records never changes the verdict. -/
theorem quorum_congr (h : ∀ r, r ∈ ss ↔ r ∈ ss') :
    quorum verify ok key k thr msg ss = quorum verify ok key k thr msg ss' := by
  have hsg : ∀ e, signedBy verify msg ss e = signedBy verify msg ss' e := by
    intro e
    apply Bool.eq_iff_iff.2
    simp only [signedBy, List.any_eq_true]
    constructor
    · rintro ⟨r, hr, h2⟩; exact ⟨r, (h r).1 hr, h2⟩
    · rintro ⟨r, hr, h2⟩; exact ⟨r, (h r).2 hr, h2⟩
  unfold quorum signers
  simp only [hsg]

/-- Non-inflation: the signers are at most the number of distinct keyIds the records name. -/
theorem signers_le_ids (hs : Sorted k.entries) (ids : List Bytes) (hc : ∀ r ∈ ss, r.keyId ∈ ids) :
    (signers verify ok k msg ss).length ≤ ids.length := by
  have hn : ((signers verify ok k msg ss).map (·.keyId)).Nodup :=
    sorted_ids_nodup hs List.filter_sublist
  have := hn.length_le_of_subset (l₂ := ids) (fun x hx => by
    obtain ⟨e, he, rfl⟩ := List.mem_map.1 hx
    have h3 := (List.mem_filter.1 he).2
    simp only [Bool.and_eq_true, signedBy, List.any_eq_true, beq_iff_eq] at h3
    obtain ⟨_, r, hr, hr1, _⟩ := h3
    rw [← hr1]; exact hc r hr)
  rwa [List.length_map] at this

/-- Roster votes (distinct employees) never exceed the live roster in persons (round-1 MED-2, now in persons). -/
theorem persons_le_liveRoster : nDistinct (·.employee) (signers verify (rosterOk t) k msg ss) ≤ liveRoster k := by
  unfold liveRoster nDistinct
  apply dedup_mono
  intro x hx
  obtain ⟨e, he, rfl⟩ := List.mem_map.1 hx
  have h3 := List.mem_filter.1 he
  simp only [Bool.and_eq_true] at h3
  have h4 := h3.2.1
  simp only [rosterOk, liveAt, Bool.and_eq_true] at h4
  refine List.mem_map_of_mem (List.mem_filter.2 ⟨h3.1, ?_⟩)
  simp only [Bool.and_eq_true]
  exact ⟨h4.1, h4.2.1.1⟩

/-- An accepted threshold is at least 1 and bounded by the votes, the signers, and the records (round-1 MED-2). -/
theorem quorum_le (hs : Sorted k.entries) (h : quorum verify ok key k thr msg ss = true) :
    1 ≤ thr ∧ thr ≤ nDistinct key (signers verify ok k msg ss) ∧
      nDistinct key (signers verify ok k msg ss) ≤ (signers verify ok k msg ss).length ∧
      (signers verify ok k msg ss).length ≤ ss.length := by
  unfold quorum at h
  simp only [Bool.and_eq_true, decide_eq_true_eq] at h
  have h3 : nDistinct key (signers verify ok k msg ss) ≤ (signers verify ok k msg ss).length := by
    unfold nDistinct
    have := dedup_le ((signers verify ok k msg ss).map key)
    rwa [List.length_map] at this
  have h4 := signers_le_ids (verify := verify) (ok := ok) (msg := msg) hs (ss.map (·.keyId))
    (fun r hr => List.mem_map_of_mem hr)
  rw [List.length_map] at h4
  exact ⟨h.1, h.2, h3, h4⟩

/-- A record whose key is unknown, fails `ok`, or does not verify can be dropped without changing the verdict. -/
theorem quorum_drop (r : SigRec)
    (hd : ∀ e ∈ k.entries, e.keyId = r.keyId → ok e = true → verify e.pk msg r.sig = false) :
    quorum verify ok key k thr msg (r :: ss) = quorum verify ok key k thr msg ss := by
  have : signers verify ok k msg (r :: ss) = signers verify ok k msg ss := by
    unfold signers
    apply List.filter_congr
    intro e he
    by_cases hok : ok e = true
    · have h5 : signedBy verify msg (r :: ss) e = signedBy verify msg ss e := by
        unfold signedBy
        rw [List.any_cons]
        by_cases hk : (r.keyId == e.keyId) = true
        · have h6 := hd e he (beq_iff_eq.1 hk).symm hok
          simp [hk, h6]
        · simp [hk]
      rw [h5]
    · simp [hok]
  unfold quorum
  rw [this]

/-- LOW b, negative: if every signer (entry passing `ok` with a verifying record) belongs to one employee, no threshold
    ≥ 2 is met, however many of that employee's keys sign (review r3 LOW-3: over the signers, not all passing entries;
    concrete: `vecSame` below, where employee 2's key 11 passes `ok` but does not sign). -/
theorem quorum_one_person {p : Bytes} (h2 : 2 ≤ thr) (hp : ∀ e ∈ signers verify ok k msg ss, e.employee = p) :
    quorum verify ok (·.employee) k thr msg ss = false := by
  unfold quorum
  have : nDistinct (·.employee) (signers verify ok k msg ss) ≤ 1 := by
    unfold nDistinct
    have := (dedup_nodup ((signers verify ok k msg ss).map (·.employee))).length_le_of_subset (l₂ := [p])
      (fun x hx => by
        obtain ⟨e, he, rfl⟩ := List.mem_map.1 (List.mem_eraseDups.1 hx)
        simp [hp e he])
    simpa using this
  simp only [Bool.and_eq_false_iff]
  right
  simp only [decide_eq_false_iff_not]
  omega

/-- LOW b: a roster quorum of a well-formed keyset is at least kRoster ≥ 2 DISTINCT EMPLOYEES, each with a live roster
    key of this keyset that signed: the two-person floor is structural (A3 only says an employee id is one person). -/
theorem roster_persons (hw : Wf k) (h : quorum verify (rosterOk t) (·.employee) k k.kRoster msg ss = true) :
    ∃ ps : List Bytes, ps.Nodup ∧ minRoster ≤ k.kRoster ∧ k.kRoster ≤ ps.length ∧
      ∀ p ∈ ps, ∃ e ∈ k.entries, e.employee = p ∧ rosterOk t e = true ∧ signedBy verify msg ss e = true := by
  unfold quorum at h
  simp only [Bool.and_eq_true, decide_eq_true_eq] at h
  refine ⟨((signers verify (rosterOk t) k msg ss).map (·.employee)).eraseDups, dedup_nodup _, hw.2.2.2.2.2.2.2.1, ?_, ?_⟩
  · have := h.2; unfold nDistinct at this; exact this
  · intro p hp
    obtain ⟨e, he, rfl⟩ := List.mem_map.1 (List.mem_eraseDups.1 hp)
    have h3 := List.mem_filter.1 he
    simp only [Bool.and_eq_true] at h3
    exact ⟨e, h3.1, rfl, h3.2.1, h3.2.2⟩

/-- Round 5 LOW (roster windows): a well-formed keyset live on day t has kRoster distinct employees with roster keys
    live that day, so its own roster quorum is reachable on every live day (no lock-out from key windows). -/
theorem roster_available (hw : Wf k) (hl : ksLive k t = true) :
    ∃ es : List Entry, es.Sublist k.entries ∧ es.length = k.kRoster ∧ (es.map (·.employee)).Nodup ∧
      ∀ e ∈ es, rosterOk t e = true := by
  obtain ⟨_, _, _, _, _, _, _, _, _, hcov, _⟩ := hw
  simp only [ksLive, Bool.and_eq_true, decide_eq_true_eq] at hl
  obtain ⟨l', hs0, hn, hlen⟩ := pick_distinct (fun e : Entry => e.employee) _
    (k.entries.filter fun e => e.role == roster && liveAt e k.notBefore && liveAt e k.notAfter) (Nat.le_refl _)
  have hcov' : k.kRoster ≤ l'.length := by rw [hlen]; exact hcov
  have hall : ∀ e ∈ l', rosterOk t e = true := by
    intro e he
    have h3 := (List.mem_filter.1 (hs0.subset he)).2
    simp only [Bool.and_eq_true, liveAt, decide_eq_true_eq, beq_iff_eq] at h3
    simp only [rosterOk, liveAt, Bool.and_eq_true, decide_eq_true_eq, beq_iff_eq]
    omega
  have htk := List.take_sublist k.kRoster l'
  refine ⟨l'.take k.kRoster, htk.trans (hs0.trans List.filter_sublist), ?_, ?_, fun e he => hall e (htk.subset he)⟩
  · simp only [List.length_take]; omega
  · exact List.Nodup.sublist (htk.map _) hn

/-- A revoked, out-of-window or non-ROSTER key never counts toward a roster quorum. -/
theorem rosterOk_dead (e : Entry) (t : Nat)
    (h : e.revokedFrom ≠ live ∨ t < e.validFrom ∨ e.validUntil < t ∨ e.role ≠ roster) : rosterOk t e = false := by
  rcases h with h | h | h | h
  · simp [rosterOk, liveAt, h]
  · simp [rosterOk, liveAt, Nat.not_le.mpr h]
  · simp [rosterOk, liveAt, Nat.not_le.mpr h]
  · simp [rosterOk, h]

/-- A revoked, non-SOURCE or wrong-scope/kind key, a key out of window at asOf `a`, or one whose window ends before the
    snapshot's validUntil `vu`, never counts toward a snapshot quorum (MED-B: validUntil past the key is the backdating
    case; a key expired by the verifier's day ends before `vu` once attach checks now ≤ vu). -/
theorem sourceOk_dead (e : Entry) (s kd a vu : Nat)
    (h : e.revokedFrom ≠ live ∨ a < e.validFrom ∨ e.validUntil < a ∨ e.validUntil < vu ∨ e.role ≠ source ∨
      bit e.scopes (s - 1) = false ∨ bit e.kinds (kd - 1) = false) :
    sourceOk s kd a vu e = false := by
  rcases h with h | h | h | h | h | h | h
  · simp [sourceOk, liveAt, h]
  · simp [sourceOk, liveAt, Nat.not_le.mpr h]
  · simp [sourceOk, liveAt, Nat.not_le.mpr h]
  · simp [sourceOk, Nat.not_le.mpr h]
  · simp [sourceOk, h]
  · simp [sourceOk, h]
  · simp [sourceOk, h]

/-- Scope 0 and kind 0 fail closed for every key (round-1 MED-3). -/
theorem sourceOk_zero (e : Entry) (s kd a vu : Nat) : sourceOk 0 kd a vu e = false ∧ sourceOk s 0 a vu e = false := by
  simp [sourceOk]

/-- A key revoked in epoch e is dead in epoch e+1 for any role and any time. -/
theorem succ_revoked_dead {old new : Keyset} {e f : Entry} (h : succOk old new = true) (hs : Sorted new.entries)
    (he : e ∈ old.entries) (hr : e.revokedFrom ≠ live) (hf : f ∈ new.entries) (hid : f.keyId = e.keyId)
    (t s kd a vu : Nat) : rosterOk t f = false ∧ sourceOk s kd a vu f = false := by
  have h2 : (old.entries.all fun e => e.revokedFrom == live ||
      new.entries.any fun f => f.keyId == e.keyId && f.revokedFrom != live && f.revokedFrom ≤ e.revokedFrom) = true := by
    unfold succOk at h
    simp only [Bool.and_eq_true] at h
    exact h.2
  have h3 := List.all_eq_true.1 h2 e he
  simp only [Bool.or_eq_true] at h3
  rcases h3 with h3 | h6
  · exact absurd (beq_iff_eq.1 h3) hr
  · obtain ⟨f', hf', h4⟩ := List.any_eq_true.1 h6
    simp only [Bool.and_eq_true, beq_iff_eq, bne_iff_ne, ne_eq, decide_eq_true_eq] at h4
    have : f = f' := sorted_inj hs hf hf' (hid.trans h4.1.1.symm)
    subst this
    have h5 := h4.1.2
    exact ⟨rosterOk_dead _ _ (Or.inl h5), sourceOk_dead _ _ _ _ _ (Or.inl h5)⟩

/-! ### Rotation chain and monotone epoch -/

theorem admitGenesis_some (h : admitGenesis verify pin x = some k) :
    ∃ f, decode x = some f ∧ f.ks = k ∧ f.ks.epoch = 0 ∧ digestOf f.ks = pin ∧
      quorum verify (rosterOk f.ks.notBefore) (·.employee) f.ks f.ks.kRoster (msgOf f.ks) f.sigs = true := by
  unfold admitGenesis at h
  cases hd : decode x with
  | none => simp [hd] at h
  | some f =>
    simp [guard, hd] at h
    split at h
    · rename_i hc
      simp at h
      exact ⟨f, rfl, h, hc.1, hc.2.1, hc.2.2⟩
    · exact absurd h (fail_bind _ _)

theorem admitSucc_some (h : admitSucc verify t cur x = some k) :
    ∃ f, decode x = some f ∧ f.ks = k ∧ succOk cur k = true ∧ ksLive cur t = true ∧ ksLive k t = true ∧
      quorum verify (rosterOk t) (·.employee) cur cur.kRoster (msgOf k) f.sigs = true ∧
      quorum verify (rosterOk t) (·.employee) k k.kRoster (msgOf k) f.sigs = true := by
  unfold admitSucc at h
  cases hd : decode x with
  | none => simp [hd] at h
  | some f =>
    simp [guard, hd] at h
    split at h
    · rename_i hc
      simp at h
      subst h
      exact ⟨f, rfl, rfl, hc.1, hc.2.1, hc.2.2.1, hc.2.2.2.1, hc.2.2.2.2⟩
    · exact absurd h (fail_bind _ _)

theorem admitSucc_of {f : Frame} (hd : decode x = some f) (h1 : succOk cur f.ks = true)
    (h2 : ksLive cur t = true) (h3 : ksLive f.ks t = true)
    (h4 : quorum verify (rosterOk t) (·.employee) cur cur.kRoster (msgOf f.ks) f.sigs = true)
    (h5 : quorum verify (rosterOk t) (·.employee) f.ks f.ks.kRoster (msgOf f.ks) f.sigs = true) :
    admitSucc verify t cur x = some f.ks := by
  unfold admitSucc
  simp [guard, hd, h1, h2, h3, h4, h5]

/-- An admitted genesis is epoch 0, has the pinned digest, and carries its own kRoster-of-roster quorum in employees. -/
theorem admitGenesis_pin (h : admitGenesis verify pin x = some k) :
    k.epoch = 0 ∧ digestOf k = pin ∧ Wf k ∧ ∃ f, decode x = some f ∧ f.ks = k ∧
      quorum verify (rosterOk k.notBefore) (·.employee) k k.kRoster (msgOf k) f.sigs = true := by
  obtain ⟨f, hd, rfl, h1, h2, h3⟩ := admitGenesis_some h
  exact ⟨h1, h2, (decode_wf hd).1, f, hd, rfl, h3⟩

/-- Epoch e+1 is admitted on day t only if kRoster(e) DISTINCT EMPLOYEES, through ROSTER keys OF EPOCH e live on day t,
    signed it. -/
theorem admitSucc_quorum (hc : Sorted cur.entries) (h : admitSucc verify t cur x = some k) :
    k.state = cur.state ∧ k.epoch = cur.epoch + 1 ∧ k.prev = digestOf cur ∧ ∃ f, decode x = some f ∧ f.ks = k ∧
      ∃ es : List Entry, es.Sublist cur.entries ∧ cur.kRoster ≤ es.length ∧ (es.map (·.keyId)).Nodup ∧
        (es.map (·.employee)).Nodup ∧ ∀ e ∈ es, rosterOk t e = true ∧
          ∃ r ∈ f.sigs, r.keyId = e.keyId ∧ verify e.pk (msgOf k) r.sig = true := by
  obtain ⟨f, hd, rfl, hso, hl, hl', hq, hq'⟩ := admitSucc_some h
  have hso' := hso
  unfold succOk at hso'
  simp only [Bool.and_eq_true, beq_iff_eq] at hso'
  obtain ⟨⟨⟨⟨⟨hs1, he1⟩, hp1⟩, _⟩, _⟩, _⟩ := hso'
  refine ⟨hs1, he1, hp1, f, hd, rfl, ?_⟩
  obtain ⟨es, hes, _, hl2, hn, hn2, hall⟩ := quorum_sound hc hq
  exact ⟨es, hes, hl2, hn2, hn, hall⟩

/-- ... and kRoster(e+1) distinct employees of epoch e+1, live on day t, signed the same message (possession). -/
theorem admitSucc_possession (h : admitSucc verify t cur x = some k) :
    ∃ f, decode x = some f ∧ f.ks = k ∧
      quorum verify (rosterOk t) (·.employee) k k.kRoster (msgOf k) f.sigs = true := by
  obtain ⟨f, hd, rfl, _, _, _, _, hq'⟩ := admitSucc_some h
  exact ⟨f, hd, rfl, hq'⟩

/-- Epoch goes up by exactly one per admitted step. -/
theorem admitSucc_epoch (h : admitSucc verify t cur x = some k) : k.epoch = cur.epoch + 1 := by
  obtain ⟨f, hd, rfl, hso, _⟩ := admitSucc_some h
  unfold succOk at hso
  simp only [Bool.and_eq_true, beq_iff_eq] at hso
  exact hso.1.1.1.1.2

/-- A keyset at or below the current epoch (replay, rollback) is refused on any day. -/
theorem admitSucc_rejects_old {f : Frame} (hd : decode x = some f) (ho : f.ks.epoch ≤ cur.epoch) :
    admitSucc verify t cur x = none := by
  cases hr : admitSucc verify t cur x with
  | none => rfl
  | some k =>
    have := admitSucc_epoch hr
    obtain ⟨f', hd', rfl, _⟩ := admitSucc_some hr
    rw [hd] at hd'
    obtain rfl := Option.some.inj hd'
    omega

/-- Issuance never goes backwards, and both the authorizing and the admitted keyset are live on the admission day
    (MED-A; `k.notBefore ≤ t` is part of `ksLive k t`). -/
theorem admitSucc_live (h : admitSucc verify t cur x = some k) :
    cur.notBefore ≤ k.notBefore ∧ ksLive cur t = true ∧ ksLive k t = true := by
  obtain ⟨f, hd, rfl, hso, hl, hl', _⟩ := admitSucc_some h
  unfold succOk at hso
  simp only [Bool.and_eq_true, decide_eq_true_eq] at hso
  exact ⟨hso.1.1.2, hl, hl'⟩

/-- MED-2 (review r3): every well-formed successor of a well-formed keyset can be admitted with ONE valid block on any
    day both are live, given kRoster(cur) employees with live roster keys of cur and kRoster(new) of new whose keys
    sign (`sg` maps a keyId to its signature, so a key kept across the rotation needs one record): the records are the
    distinct keyIds of es ++ es', at most maxRoster + maxRoster = maxSigs. -/
theorem admitSucc_fits {new : Keyset} {es es' : List Entry} {sg : Bytes → Bytes} (hw : Wf cur) (hw' : Wf new)
    (hso : succOk cur new = true) (hl : ksLive cur t = true) (hl' : ksLive new t = true) (hes : es.Sublist cur.entries)
    (hes' : es'.Sublist new.entries) (hn : es.length = cur.kRoster) (hn' : es'.length = new.kRoster)
    (hp : (es.map (·.employee)).Nodup) (hp' : (es'.map (·.employee)).Nodup) (hr : ∀ e ∈ es, rosterOk t e = true)
    (hr' : ∀ e ∈ es', rosterOk t e = true)
    (hv : ∀ e ∈ es ++ es', verify e.pk (msgOf new) (sg e.keyId) = true ∧ (sg e.keyId).length = mlDsa87Signature) :
    ∃ ss, SigsWf ss ∧ admitSucc verify t cur (encode ⟨new, ss⟩) = some new := by
  have hw0 := hw
  have hw0' := hw'
  obtain ⟨_, _, _, _, _, _, _, hrc1, hrc2, _, _, _, _, _, hent⟩ := hw
  obtain ⟨_, _, _, _, _, _, _, hrn1, hrn2, _, _, _, _, _, hent'⟩ := hw'
  let L : List Bytes := ((es ++ es').map (·.keyId)).eraseDups
  let M : List Bytes := L.mergeSort (fun a b => decide (beNat a ≤ beNat b))
  have hLn : L.Nodup := dedup_nodup _
  have hperm : M.Perm L := List.mergeSort_perm _ _
  have hmemL : ∀ a, a ∈ L ↔ ∃ e ∈ es ++ es', e.keyId = a := by
    intro a
    simp only [L, List.mem_eraseDups, List.mem_map]
  have hlen64 : ∀ e ∈ es ++ es', e.keyId.length = 64 := by
    intro e he
    rcases List.mem_append.1 he with h | h
    · exact (hent e (hes.subset h)).1
    · exact (hent' e (hes'.subset h)).1
  have hM64 : ∀ a ∈ M, a.length = 64 := by
    intro a ha
    obtain ⟨e, he, rfl⟩ := (hmemL a).1 (hperm.mem_iff.1 ha)
    exact hlen64 e he
  have hMn : M.Nodup := hperm.nodup_iff.2 hLn
  have hinj : ∀ a ∈ M, ∀ b ∈ M, beNat a = beNat b → a = b := by
    intro a ha b hb hab
    have h1 := natBE_beNat' (hM64 a ha)
    have h2 := natBE_beNat' (hM64 b hb)
    rw [← h1, ← h2, hab]
  have hmap_n : (M.map beNat).Nodup := by
    show (M.map beNat).Pairwise (· ≠ ·)
    rw [List.pairwise_map]
    exact hMn.imp_of_mem (fun ha hb hne hab => hne (hinj _ ha _ hb hab))
  have hpw : (M.map beNat).Pairwise (· ≤ ·) := by
    have := List.pairwise_mergeSort (le := fun a b : Bytes => decide (beNat a ≤ beNat b))
      (fun a b c h1 h2 => by simp at h1 h2 ⊢; omega) (fun a b => by simp; omega) L
    rw [List.pairwise_map]
    exact this.imp (fun h => by simpa using h)
  have hlt : (M.map beNat).Pairwise (· < ·) := by
    have := hpw.and hmap_n
    exact this.imp (fun ⟨h1, h2⟩ => Nat.lt_of_le_of_ne h1 h2)
  have hlenM : M.length ≤ 16 := by
    have h1 : M.length = L.length := hperm.length_eq
    have h2 : L.length ≤ ((es ++ es').map (·.keyId)).length := dedup_le _
    simp only [List.length_map, List.length_append] at h2
    unfold maxRoster at hrc2 hrn2
    omega
  have hmemM : ∀ e ∈ es ++ es', e.keyId ∈ M := fun e he => hperm.mem_iff.2 ((hmemL _).2 ⟨e, he, rfl⟩)
  have hpos : 1 ≤ M.length := by
    unfold minRoster at hrc1
    cases es with
    | nil => simp at hn; omega
    | cons e0 _ =>
      exact List.length_pos_iff_exists_mem.2 ⟨_, hmemM e0 (by simp)⟩
  let ss : List SigRec := M.map fun id => ⟨id, sg id⟩
  have hss : SigsWf ss := by
    unfold SigsWf
    refine ⟨by simpa [ss] using hpos, by unfold maxSigs; simpa [ss] using hlenM, ?_, ?_⟩
    · unfold SigsSorted
      simpa [ss, List.map_map, Function.comp_def] using hlt
    · intro r hr0
      obtain ⟨id, hid, rfl⟩ := List.mem_map.1 hr0
      obtain ⟨e, he, rfl⟩ := (hmemL id).1 (hperm.mem_iff.1 hid)
      exact ⟨hlen64 e he, (hv e he).2⟩
  have hdec := decode_encode (f := ⟨new, ss⟩) hw0' hss
  have hrec : ∀ e ∈ es ++ es', ∃ r ∈ ss, r.keyId = e.keyId ∧ verify e.pk (msgOf new) r.sig = true := by
    intro e he
    exact ⟨⟨e.keyId, sg e.keyId⟩, List.mem_map.2 ⟨e.keyId, hmemM e he, rfl⟩, rfl, (hv e he).1⟩
  have hq : quorum verify (rosterOk t) (·.employee) cur cur.kRoster (msgOf new) ss = true := by
    refine quorum_complete hes (by unfold minRoster at hrc1; omega) (by omega) hp ?_
    intro e he
    exact ⟨hr e he, hrec e (List.mem_append.2 (Or.inl he))⟩
  have hq' : quorum verify (rosterOk t) (·.employee) new new.kRoster (msgOf new) ss = true := by
    refine quorum_complete hes' (by unfold minRoster at hrn1; omega) (by omega) hp' ?_
    intro e he
    exact ⟨hr' e he, hrec e (List.mem_append.2 (Or.inr he))⟩
  exact ⟨ss, hss, admitSucc_of (f := ⟨new, ss⟩) hdec hso hl hl' hq hq'⟩

/-- MED-A, negative: nothing succeeds an expired keyset, whoever signs (so keys revoked at e+1 cannot fork from epoch e
    after e's notAfter). -/
theorem admitSucc_expired (he : cur.notAfter < t) : admitSucc verify t cur x = none := by
  cases hr : admitSucc verify t cur x with
  | none => rfl
  | some k =>
    obtain ⟨f, hd, rfl, hso, hl, hl', _⟩ := admitSucc_some hr
    simp only [ksLive, Bool.and_eq_true, decide_eq_true_eq] at hl
    omega

theorem list_snoc_ind {α : Type} {motive : List α → Prop} (nil : motive [])
    (snoc : ∀ l a, motive l → motive (l ++ [a])) : ∀ l, motive l := by
  have key : ∀ n (l : List α), l.length = n → motive l := by
    intro n
    induction n with
    | zero => intro l h; rw [List.length_eq_zero_iff.1 h]; exact nil
    | succ n ih =>
      intro l h
      rcases List.eq_nil_or_concat l with rfl | ⟨l', b, rfl⟩
      · simp at h
      · rw [List.concat_eq_append] at h ⊢
        simp at h
        exact snoc l' b (ih l' h)
  exact fun l => key _ l rfl

theorem admitChain_some (h : admitChain verify pin x steps = some k) :
    (steps.map (·.1)).Pairwise (· ≤ ·) ∧ ∃ g, admitGenesis verify pin x = some g ∧
      steps.foldlM (fun c s => admitSucc verify s.1 c s.2) g = some k := by
  unfold admitChain at h
  simp [guard] at h
  split at h
  · rename_i hp
    cases hg : admitGenesis verify pin x with
    | none => simp [hg] at h
    | some g =>
      simp [hg] at h
      exact ⟨hp, g, rfl, h⟩
  · exact absurd h (fail_bind _ _)

theorem admitChain_mk (hp : (steps.map (·.1)).Pairwise (· ≤ ·)) {g : Keyset} (hg : admitGenesis verify pin x = some g)
    (hf : steps.foldlM (fun c s => admitSucc verify s.1 c s.2) g = some k) : admitChain verify pin x steps = some k := by
  unfold admitChain
  simp [guard, hp, hg, hf]

theorem admitChain_fold : admitChain verify pin x steps = some k ↔
    (steps.map (·.1)).Pairwise (· ≤ ·) ∧ admitFold verify pin x steps = some k := by
  constructor
  · intro h
    obtain ⟨hp, g, hg, hf⟩ := admitChain_some h
    exact ⟨hp, by simp [admitFold, hg, hf]⟩
  · rintro ⟨hp, h⟩
    unfold admitFold at h
    cases hg : admitGenesis verify pin x with
    | none => simp [hg] at h
    | some g =>
      simp [hg] at h
      exact admitChain_mk hp hg h

theorem admitFold_append {ys : List (Nat × Bytes)} : admitFold verify pin x (steps ++ ys) =
    (admitFold verify pin x steps).bind fun c => ys.foldlM (fun c s => admitSucc verify s.1 c s.2) c := by
  unfold admitFold
  cases admitGenesis verify pin x <;> simp [List.foldlM_append]

/-- A fold through a keyset `c` at epoch n continues from `c`. -/
theorem admitFold_split {n : Nat} {c : Keyset} (hc : admitFold verify pin x (steps.take n) = some c) :
    admitFold verify pin x steps = (steps.drop n).foldlM (fun c s => admitSucc verify s.1 c s.2) c := by
  have h := admitFold_append (verify := verify) (pin := pin) (x := x) (steps := steps.take n) (ys := steps.drop n)
  rw [List.take_append_drop, hc] at h
  simpa using h

theorem admitFold_snoc {s : Nat × Bytes} : admitFold verify pin x (steps ++ [s]) = some k ↔
    ∃ c, admitFold verify pin x steps = some c ∧ admitSucc verify s.1 c s.2 = some k := by
  rw [admitFold_append]
  simp [Option.bind_eq_some_iff]

theorem admitFold_prefix {ys : List (Nat × Bytes)} (h : admitFold verify pin x (steps ++ ys) = some k) :
    ∃ c, admitFold verify pin x steps = some c := by
  rw [admitFold_append] at h
  cases hc : admitFold verify pin x steps with
  | none => simp [hc] at h
  | some c => exact ⟨c, rfl⟩

/-- A chain one longer is exactly the shorter chain followed by one successor admitted on a day no earlier than any
    previous step's. -/
theorem admitChain_snoc {s : Nat × Bytes} :
    admitChain verify pin x (steps ++ [s]) = some k ↔ (∀ p ∈ steps, p.1 ≤ s.1) ∧
      ∃ c, admitChain verify pin x steps = some c ∧ admitSucc verify s.1 c s.2 = some k := by
  constructor
  · intro h
    obtain ⟨hp, g, hg, hf⟩ := admitChain_some h
    rw [List.foldlM_append] at hf
    simp only [List.map_append, List.map_cons, List.map_nil, List.pairwise_append] at hp
    have hp1 : (steps.map (·.1)).Pairwise (· ≤ ·) := hp.1
    have hall : ∀ p ∈ steps, p.1 ≤ s.1 := by
      intro p hpm
      exact hp.2.2 p.1 (List.mem_map.2 ⟨p, hpm, rfl⟩) s.1 (by simp)
    cases hc : steps.foldlM (fun c s => admitSucc verify s.1 c s.2) g with
    | none => simp [hc] at hf
    | some c =>
      simp [hc] at hf
      exact ⟨hall, c, admitChain_mk hp1 hg hc, hf⟩
  · rintro ⟨hall, c, hc, hs⟩
    obtain ⟨hp1, g, hg, hf⟩ := admitChain_some hc
    apply admitChain_mk _ hg
    · rw [List.foldlM_append, hf]
      simp [hs]
    · simp only [List.map_append, List.map_cons, List.map_nil, List.pairwise_append]
      refine ⟨hp1, by simp, ?_⟩
      intro a ha b hb
      obtain ⟨p, hpm, rfl⟩ := List.mem_map.1 ha
      simp at hb
      subst hb
      exact hall p hpm

theorem admitChain_prefix {ys : List (Nat × Bytes)} (h : admitChain verify pin x (steps ++ ys) = some k) :
    ∃ c, admitChain verify pin x steps = some c := by
  induction ys using list_snoc_ind generalizing k with
  | nil => exact ⟨k, by simpa using h⟩
  | snoc ys s ih =>
    rw [← List.append_assoc, admitChain_snoc] at h
    obtain ⟨_, c, hc, _⟩ := h
    exact ih hc

theorem admitFold_inv (h : admitFold verify pin x steps = some k) :
    Wf k ∧ k.epoch = steps.length ∧ ∃ g, admitGenesis verify pin x = some g ∧ k.state = g.state := by
  induction steps using list_snoc_ind generalizing k with
  | nil =>
    have hg : admitGenesis verify pin x = some k := by simpa [admitFold] using h
    obtain ⟨h1, _, h3, _⟩ := admitGenesis_pin hg
    exact ⟨h3, by simpa using h1, k, hg, rfl⟩
  | snoc steps s ih =>
    rw [admitFold_snoc] at h
    obtain ⟨c, hc, hs⟩ := h
    obtain ⟨hwc, hec, g, hg, hst⟩ := ih hc
    obtain ⟨f, hd, hfk, _⟩ := admitSucc_possession hs
    have hq := admitSucc_quorum (hwc.2.2.2.2.2.2.2.2.2.2.2.2.2.1) hs
    refine ⟨?_, ?_, g, hg, ?_⟩
    · have := (decode_wf hd).1
      rw [hfk] at this
      exact this
    · rw [admitSucc_epoch hs, hec]; simp
    · rw [hq.1, hst]

theorem succOk_keep {old new : Keyset} {e : Entry} (h : succOk old new = true) (he : e ∈ old.entries)
    (hr : e.revokedFrom ≠ live) : ∃ f ∈ new.entries, f.keyId = e.keyId ∧ f.revokedFrom ≠ live := by
  have h2 : (old.entries.all fun e => e.revokedFrom == live ||
      new.entries.any fun f => f.keyId == e.keyId && f.revokedFrom != live && f.revokedFrom ≤ e.revokedFrom) = true := by
    unfold succOk at h
    simp only [Bool.and_eq_true] at h
    exact h.2
  have h3 := List.all_eq_true.1 h2 e he
  simp only [Bool.or_eq_true] at h3
  rcases h3 with h3 | h6
  · exact absurd (beq_iff_eq.1 h3) hr
  · obtain ⟨f', hf', h4⟩ := List.any_eq_true.1 h6
    simp only [Bool.and_eq_true, beq_iff_eq, bne_iff_ne, ne_eq, decide_eq_true_eq] at h4
    exact ⟨f', hf', h4.1.1, h4.1.2⟩

theorem admitFold_persists {c : Keyset} (hc : admitFold verify pin x steps = some c) :
    ∀ (ts : List (Nat × Bytes)) (k : Keyset), admitFold verify pin x (steps ++ ts) = some k →
      ∀ e ∈ c.entries, e.revokedFrom ≠ live → ∃ f ∈ k.entries, f.keyId = e.keyId ∧ f.revokedFrom ≠ live := by
  intro ts
  induction ts using list_snoc_ind with
  | nil =>
    intro k hk e he hr
    rw [List.append_nil, hc] at hk
    obtain rfl := Option.some.inj hk
    exact ⟨e, he, rfl, hr⟩
  | snoc ts s ih =>
    intro k hk e he hr
    rw [← List.append_assoc, admitFold_snoc] at hk
    obtain ⟨c', hc', hs⟩ := hk
    obtain ⟨f', hf', hid', hr'⟩ := ih c' hc' e he hr
    have hso : succOk c' k = true := (admitSucc_some hs).choose_spec.2.2.1
    obtain ⟨f2, hf2, hid2, hr2⟩ := succOk_keep hso hf' hr'
    exact ⟨f2, hf2, hid2.trans hid', hr2⟩

theorem admitFold_step_prev {i : Nat} {c1 : Keyset} (hi : i < steps.length)
    (h : admitFold verify pin x (steps.take (i + 1)) = some c1) :
    ∃ c, admitFold verify pin x (steps.take i) = some c ∧ c1.prev = digestOf c := by
  have ht : steps.take (i + 1) = steps.take i ++ [steps[i]] := by
    rw [List.take_add_one]; simp [List.getElem?_eq_getElem hi]
  rw [ht, admitFold_snoc] at h
  obtain ⟨c, hc, hs⟩ := h
  obtain ⟨hwc, _⟩ := admitFold_inv hc
  exact ⟨c, hc, (admitSucc_quorum (hwc.2.2.2.2.2.2.2.2.2.2.2.2.2.1) hs).2.2.1⟩

/-- LOW e: admission days of an accepted chain never go backwards. -/
theorem admitChain_days (h : admitChain verify pin x steps = some k) : (steps.map (·.1)).Pairwise (· ≤ ·) :=
  (admitChain_some h).1

/-- The head of a chain with n successor steps is epoch n (monotone, gap-free epochs). -/
theorem admitFold_epoch (h : admitFold verify pin x steps = some k) : k.epoch = steps.length :=
  (admitFold_inv h).2.1

/-- Every keyset reached by a chain is well formed (so kRoster ≥ 2 persons, sorted, bounded) and keeps the genesis
    state. -/
theorem admitFold_wf (h : admitFold verify pin x steps = some k) :
    Wf k ∧ ∃ g, admitGenesis verify pin x = some g ∧ k.state = g.state := by
  obtain ⟨h1, _, h3⟩ := admitFold_inv h
  exact ⟨h1, h3⟩

/-- Headline: the head of a chain was authorized by at least kRoster ≥ 2 distinct EMPLOYEES through ROSTER keys of the
    previous epoch, live on the day it was admitted, while that previous keyset was itself live. -/
theorem admitFold_rotation {s : Nat × Bytes} (h : admitFold verify pin x (steps ++ [s]) = some k) :
    ∃ c f, admitFold verify pin x steps = some c ∧ decode s.2 = some f ∧ f.ks = k ∧ k.prev = digestOf c ∧
      k.epoch = c.epoch + 1 ∧ ksLive c s.1 = true ∧ ksLive k s.1 = true ∧ ∃ es : List Entry, es.Sublist c.entries ∧
        minRoster ≤ c.kRoster ∧ c.kRoster ≤ es.length ∧ (es.map (·.keyId)).Nodup ∧ (es.map (·.employee)).Nodup ∧
        ∀ e ∈ es, rosterOk s.1 e = true ∧ ∃ r ∈ f.sigs, r.keyId = e.keyId ∧ verify e.pk (msgOf k) r.sig = true := by
  rw [admitFold_snoc] at h
  obtain ⟨c, hc, hs⟩ := h
  obtain ⟨hwc, _⟩ := admitFold_inv hc
  have hq := admitSucc_quorum (hwc.2.2.2.2.2.2.2.2.2.2.2.2.2.1) hs
  obtain ⟨hl1, hl2, hl3⟩ := admitSucc_live hs
  obtain ⟨_, he, hp, f, hd, hfk, es, hes, hl, hn1, hn2, hall⟩ := hq
  exact ⟨c, f, hc, hd, hfk, hp, he, hl2, hl3, es, hes, hwc.2.2.2.2.2.2.2.1, hl, hn1, hn2, hall⟩

/-- Revoked stays dead down the whole chain: a key revoked at any reached epoch is dead at every later one (MED-4).
    STMT-CHANGE final review 3 LOW-B: `admitFold` premises (was `admitChain_revoked_dead`), so it covers the records
    `walk` admits, labels unordered (`admitChain_fold`: every `admitChain` premise gives these). -/
theorem admitFold_revoked_dead {ts : List (Nat × Bytes)} {c : Keyset} {e f : Entry}
    (hc : admitFold verify pin x steps = some c) (hk' : admitFold verify pin x (steps ++ ts) = some k)
    (he : e ∈ c.entries) (hr : e.revokedFrom ≠ live) (hf : f ∈ k.entries) (hid : f.keyId = e.keyId)
    (s kd a vu : Nat) : rosterOk t f = false ∧ sourceOk s kd a vu f = false := by
  obtain ⟨f0, hf0, hid0, hr0⟩ := admitFold_persists hc ts k hk' e he hr
  have hsort := (admitFold_inv hk').1.2.2.2.2.2.2.2.2.2.2.2.2.2.1
  have : f = f0 := sorted_inj hsort hf hf0 (hid.trans hid0.symm)
  subst this
  exact ⟨rosterOk_dead _ _ (Or.inl hr0), sourceOk_dead _ _ _ _ _ (Or.inl hr0)⟩

/-- MED-A, head pin: two chains from the same genesis pin whose heads have the digest the manifest pins
    (`m.keyset = digestOf k`) are the same chain: same length and the same keyset at every epoch.  `hcr` is the run-local
    A2 instance (no SHA3 collision among the keysets the two chains reach); it is a hypothesis, not an axiom.  Labels
    play no part (`admitFold`), so it pins `walk`'s prefix too. -/
theorem admitFold_pinned {x' : Bytes} {steps' : List (Nat × Bytes)} {k' : Keyset}
    (h : admitFold verify pin x steps = some k) (h' : admitFold verify pin x' steps' = some k')
    (hd : digestOf k' = digestOf k)
    (hcr : ∀ i j c c', admitFold verify pin x (steps.take i) = some c →
      admitFold verify pin x' (steps'.take j) = some c' → digestOf c = digestOf c' → body c = body c') :
    steps'.length = steps.length ∧ ∀ i c c', admitFold verify pin x (steps.take i) = some c →
      admitFold verify pin x' (steps'.take i) = some c' → c = c' := by
  have hwk := (admitFold_inv h).1
  have hwk' := (admitFold_inv h').1
  have hek := admitFold_epoch h
  have hek' := admitFold_epoch h'
  have hkk : k = k' := by
    apply body_inj hwk hwk'
    apply hcr steps.length steps'.length k k'
    · rw [List.take_of_length_le (Nat.le_refl _)]; exact h
    · rw [List.take_of_length_le (Nat.le_refl _)]; exact h'
    · exact hd.symm
  subst hkk
  have hlen : steps'.length = steps.length := by omega
  refine ⟨hlen, ?_⟩
  have key : ∀ d i, steps.length - i = d → ∀ c c', admitFold verify pin x (steps.take i) = some c →
      admitFold verify pin x' (steps'.take i) = some c' → c = c' := by
    intro d
    induction d with
    | zero =>
      intro i hi c c' hc hc'
      rw [List.take_of_length_le (by omega)] at hc
      rw [List.take_of_length_le (by omega)] at hc'
      rw [h] at hc
      rw [h'] at hc'
      rw [← Option.some.inj hc, ← Option.some.inj hc']
    | succ d ih =>
      intro i hi c c' hc hc'
      have hi1 : i < steps.length := by omega
      obtain ⟨c1, hc1⟩ := admitFold_prefix (steps := steps.take (i + 1)) (ys := steps.drop (i + 1))
        (by rw [List.take_append_drop]; exact h)
      obtain ⟨c1', hc1'⟩ := admitFold_prefix (steps := steps'.take (i + 1)) (ys := steps'.drop (i + 1))
        (by rw [List.take_append_drop]; exact h')
      have heq := ih (i + 1) (by omega) c1 c1' hc1 hc1'
      subst heq
      obtain ⟨c0, hc0, hp0⟩ := admitFold_step_prev hi1 hc1
      obtain ⟨c0', hc0', hp0'⟩ := admitFold_step_prev (by omega) hc1'
      rw [hc] at hc0
      rw [hc'] at hc0'
      obtain rfl := Option.some.inj hc0
      obtain rfl := Option.some.inj hc0'
      have hdg : digestOf c = digestOf c' := hp0.symm.trans hp0'
      have hwc := (admitFold_inv hc).1
      have hwc' := (admitFold_inv hc').1
      exact body_inj hwc hwc' (hcr i i c c' hc hc' hdg)
  exact fun i c c' hc hc' => key _ i rfl c c' hc hc'

theorem admitChain_pinned {x' : Bytes} {steps' : List (Nat × Bytes)} {k' : Keyset}
    (h : admitChain verify pin x steps = some k) (h' : admitChain verify pin x' steps' = some k')
    (hd : digestOf k' = digestOf k)
    (hcr : ∀ i j c c', admitChain verify pin x (steps.take i) = some c →
      admitChain verify pin x' (steps'.take j) = some c' → digestOf c = digestOf c' → body c = body c') :
    steps'.length = steps.length ∧ ∀ i c c', admitChain verify pin x (steps.take i) = some c →
      admitChain verify pin x' (steps'.take i) = some c' → c = c' := by
  have up : ∀ {ss : List (Nat × Bytes)} {k0 : Keyset} {y : Bytes} {c : Keyset} (i : Nat),
      admitChain verify pin y ss = some k0 → admitFold verify pin y (ss.take i) = some c →
        admitChain verify pin y (ss.take i) = some c := fun i h0 hc =>
    admitChain_fold.2 ⟨(admitChain_fold.1 h0).1.sublist ((List.take_sublist i _).map _), hc⟩
  obtain ⟨hl, hp⟩ := admitFold_pinned (admitChain_fold.1 h).2 (admitChain_fold.1 h').2 hd
    fun i j c c' hc hc' => hcr i j c c' (up i h hc) (up j h' hc')
  exact ⟨hl, fun i c c' hc hc' => hp i c c' (admitChain_fold.1 hc).2 (admitChain_fold.1 hc').2⟩

/-- MED-A, no fork: a chain whose head is the pinned head cannot be forked by keys revoked earlier in the honest chain.
    If e is revoked at the keyset c reached by `steps`, then in ANY chain to the same pinned head, every keyset at
    epoch ≥ c.epoch holds e only dead, so e authorizes no step after c.epoch (and the step into c.epoch is c itself,
    `admitChain_pinned`). -/
theorem admitChain_pinned_revoked {x' : Bytes} {steps' ts : List (Nat × Bytes)} {k' c c' : Keyset} {e f : Entry}
    {i : Nat} (h : admitChain verify pin x (steps ++ ts) = some k) (hc : admitChain verify pin x steps = some c)
    (he : e ∈ c.entries) (hr : e.revokedFrom ≠ live) (h' : admitChain verify pin x' steps' = some k')
    (hd : digestOf k' = digestOf k)
    (hcr : ∀ i j c c', admitChain verify pin x ((steps ++ ts).take i) = some c →
      admitChain verify pin x' (steps'.take j) = some c' → digestOf c = digestOf c' → body c = body c')
    (hi : steps.length ≤ i) (hc' : admitChain verify pin x' (steps'.take i) = some c') (hf : f ∈ c'.entries)
    (hid : f.keyId = e.keyId) (s kd a vu : Nat) : rosterOk t f = false ∧ sourceOk s kd a vu f = false := by
  obtain ⟨_, hpin⟩ := admitChain_pinned h h' hd hcr
  obtain ⟨c0, hc0⟩ := admitChain_prefix (steps := (steps ++ ts).take i) (ys := (steps ++ ts).drop i)
    (by rw [List.take_append_drop]; exact h)
  have hceq : c0 = c' := hpin i c0 c' hc0 hc'
  subst hceq
  rw [List.take_append, List.take_of_length_le hi] at hc0
  exact admitFold_revoked_dead (admitChain_fold.1 hc).2 (admitChain_fold.1 hc0).2 he hr hf hid s kd a vu

/-- Satisfiability (round-1 LOW): a well-formed 2-of-2 genesis whose two live roster keys, held by two employees, both
    signed is admitted.  Concrete witness: `vecTwo` below, `#guard`ed with a stub verify at implementation time. -/
theorem admitChain_two_of_two {f : Frame} {e₁ e₂ : Entry} {r₁ r₂ : SigRec} (hw : Wf f.ks) (hs : SigsWf f.sigs)
    (h0 : f.ks.epoch = 0) (h2 : f.ks.kRoster = 2) (hes : [e₁, e₂].Sublist f.ks.entries)
    (hp : e₁.employee ≠ e₂.employee)
    (hl₁ : rosterOk f.ks.notBefore e₁ = true) (hl₂ : rosterOk f.ks.notBefore e₂ = true)
    (hr₁ : r₁ ∈ f.sigs) (hr₂ : r₂ ∈ f.sigs) (hi₁ : r₁.keyId = e₁.keyId) (hi₂ : r₂.keyId = e₂.keyId)
    (hv₁ : verify e₁.pk (msgOf f.ks) r₁.sig = true) (hv₂ : verify e₂.pk (msgOf f.ks) r₂.sig = true) :
    admitChain verify (digestOf f.ks) (encode f) [] = some f.ks := by
  have hdec := decode_encode hw hs
  have hq : quorum verify (rosterOk f.ks.notBefore) (·.employee) f.ks f.ks.kRoster (msgOf f.ks) f.sigs = true := by
    refine quorum_complete hes (by rw [h2]; omega) (by rw [h2]; simp) ?_ ?_
    · simp [hp]
    · intro e he
      simp only [List.mem_cons, List.not_mem_nil, or_false] at he
      rcases he with rfl | rfl
      · exact ⟨hl₁, r₁, hr₁, hi₁, hv₁⟩
      · exact ⟨hl₂, r₂, hr₂, hi₂, hv₂⟩
  have hg : admitGenesis verify (digestOf f.ks) (encode f) = some f.ks := by
    unfold admitGenesis
    simp [guard, hdec, h0, hq]
  exact admitChain_mk (by simp) hg (by simp)

/-! ### Persisted head (review stmts5 MED-A, MED-B, L2) -/

/-- STMT-CHANGE final review 2 LOW-1: `admitFold` for `admitChain`, so labels are ordered among the new steps only. -/
theorem walk_some (h : walk verify pin now st x steps = some k) :
    (Rules.validDate now = true ∧ st.epoch ≤ steps.length ∧ (steps.drop st.epoch).Pairwise (·.1 ≤ ·.1) ∧
      ∀ p ∈ steps.drop st.epoch, p.1 ≤ now) ∧
    (∃ c, admitFold verify pin x (steps.take st.epoch) = some c ∧ digestOf c = st.head) ∧
    admitFold verify pin x steps = some k ∧ ksLive k now = true := by
  unfold walk at h
  simp [guard] at h
  split at h
  · rename_i hg
    cases hc : admitFold verify pin x (steps.take st.epoch) with
    | none => simp [hc] at h
    | some c =>
      simp [hc] at h
      split at h
      · rename_i hd
        cases hk : (steps.drop st.epoch).foldlM (fun c s => admitSucc verify s.1 c s.2) c with
        | none => simp [hk] at h
        | some k0 =>
          simp [hk] at h
          obtain ⟨hl, rfl⟩ := h
          exact ⟨hg, ⟨c, rfl, hd⟩, by rw [admitFold_split hc, hk], hl⟩
      · exact absurd h (fail_bind _ _)
  · exact absurd h (fail_bind _ _)

/-- STMT-CHANGE final review 2 LOW-1: as `walk_some`. -/
theorem walk_mk {c : Keyset}
    (hg : Rules.validDate now = true ∧ st.epoch ≤ steps.length ∧ (steps.drop st.epoch).Pairwise (·.1 ≤ ·.1) ∧
      ∀ p ∈ steps.drop st.epoch, p.1 ≤ now)
    (hc : admitFold verify pin x (steps.take st.epoch) = some c) (hd : digestOf c = st.head)
    (hk : admitFold verify pin x steps = some k) (hl : ksLive k now = true) :
    walk verify pin now st x steps = some k := by
  rw [admitFold_split hc] at hk
  unfold walk
  simp [guard, hc, hd, hk, hl]
  rw [if_pos hg]
  rfl

/-- Steps all dated one day are in day order. -/
theorem dated_pairwise {l : List (Nat × Bytes)} (h : ∀ p ∈ l, p.1 = t) : l.Pairwise (·.1 ≤ ·.1) :=
  List.pairwise_of_forall_mem_list fun a ha b hb => Nat.le_of_eq ((h a ha).trans (h b hb).symm)

theorem admitHead_walk (h : admitHead verify pin now st x steps = some (k, st')) :
    (st.day ≤ now ∧ (st.day = 0 ∨ Rules.dayNum now ≤ Rules.dayNum st.day + maxSkewDays) ∧
      ∀ p ∈ steps.drop st.epoch, p.1 = now) ∧
    walk verify pin now st x steps = some k ∧ st' = ⟨steps.length, digestOf k, now, st.cp⟩ := by
  unfold admitHead at h
  simp [guard] at h
  split at h
  · rename_i hg
    cases hw : walk verify pin now st x steps with
    | none => simp [hw] at h
    | some k0 =>
      simp [hw] at h
      obtain ⟨rfl, rfl⟩ := h
      exact ⟨hg, rfl, rfl⟩
  · exact absurd h (fail_bind _ _)

/-- STMT-CHANGE K2 (ratchet field): the returned ratchet carries `st.cp`.  STMT-CHANGE final review MED-1: no bound
    on steps at or below the persisted epoch (`walk`).  STMT-CHANGE final review 2 LOW-1: `admitFold` for
    `admitChain` (the new steps, all dated `now`, are in order: `dated_pairwise`). -/
theorem admitHead_some (h : admitHead verify pin now st x steps = some (k, st')) :
    (st.day ≤ now ∧ Rules.validDate now = true ∧ (st.day = 0 ∨ Rules.dayNum now ≤ Rules.dayNum st.day + maxSkewDays) ∧
      st.epoch ≤ steps.length ∧ ∀ p ∈ steps.drop st.epoch, p.1 = now) ∧
    (∃ c, admitFold verify pin x (steps.take st.epoch) = some c ∧ digestOf c = st.head) ∧
    admitFold verify pin x steps = some k ∧ st' = ⟨steps.length, digestOf k, now, st.cp⟩ := by
  obtain ⟨⟨g1, g2, g3⟩, hw, hst⟩ := admitHead_walk h
  obtain ⟨⟨w1, w2, _⟩, hc, hk, _⟩ := walk_some hw
  exact ⟨⟨g1, w1, g2, w2, g3⟩, hc, hk, hst⟩

/-- K2 recovery (a): an admitted head is live on `now`. -/
theorem admitHead_live (h : admitHead verify pin now st x steps = some (k, st')) : ksLive k now = true :=
  (walk_some (admitHead_walk h).2.1).2.2.2

/-- STMT-CHANGE K2: + the head live on `now`; the ratchet carries `st.cp`.  STMT-CHANGE final review MED-1: no bound
    on steps at or below the persisted epoch (`walk`).  STMT-CHANGE final review 2 LOW-1: `admitFold` for `admitChain`
    (weaker premises). -/
theorem admitHead_mk {c : Keyset}
    (hg : st.day ≤ now ∧ Rules.validDate now = true ∧ (st.day = 0 ∨ Rules.dayNum now ≤ Rules.dayNum st.day + maxSkewDays) ∧
      st.epoch ≤ steps.length ∧ ∀ p ∈ steps.drop st.epoch, p.1 = now)
    (hc : admitFold verify pin x (steps.take st.epoch) = some c) (hd : digestOf c = st.head)
    (hk : admitFold verify pin x steps = some k) (hl : ksLive k now = true) :
    admitHead verify pin now st x steps = some (k, ⟨steps.length, digestOf k, now, st.cp⟩) := by
  obtain ⟨g1, g2, g3, g4, g6⟩ := hg
  unfold admitHead
  simp [guard, walk_mk ⟨g2, g4, dated_pairwise g6, fun p hp => Nat.le_of_eq (g6 p hp)⟩ hc hd hk hl]
  rw [if_pos ⟨g1, g3, g6⟩]
  rfl

/-- An admitted head is the chain's head; the ratchet returned is (head epoch, head digest, `now`), so the persisted
    day is the last accepted `now`; epoch and day never go back, and the day moves at most `maxSkewDays` from a
    non-fresh ratchet (LOW-D); every new step is dated `now` (MED-C); and the chain's keyset at the persisted epoch has
    the persisted digest.  STMT-CHANGE K2: the ratchet carries `st.cp`.  STMT-CHANGE final review MED-1: no bound on
    steps at or below the persisted epoch (`walk`).  STMT-CHANGE final review 2 LOW-1: `admitFold` for `admitChain`. -/
theorem admitHead_sound (h : admitHead verify pin now st x steps = some (k, st')) :
    admitFold verify pin x steps = some k ∧ st' = ⟨k.epoch, digestOf k, now, st.cp⟩ ∧ st.epoch ≤ k.epoch ∧ st.day ≤ now ∧
      Rules.validDate now = true ∧ (st.day = 0 ∨ Rules.dayNum now ≤ Rules.dayNum st.day + maxSkewDays) ∧
      (∀ p ∈ steps.drop st.epoch, p.1 = now) ∧
      ∃ c, admitFold verify pin x (steps.take st.epoch) = some c ∧ digestOf c = st.head := by
  obtain ⟨⟨g1, g2, g3, g4, g6⟩, hc, hk, hst⟩ := admitHead_some h
  have he := admitFold_epoch hk
  refine ⟨hk, ?_, by omega, g1, g2, g3, g6, hc⟩
  rw [hst, he]

/-- Refused: a clock behind the persisted day (L2), not a calendar date, or more than `maxSkewDays` past a non-fresh
    persisted day (LOW-D); a chain shorter than the persisted epoch (rollback, replay), a new step not dated `now`
    (MED-C), or a keyset at the persisted epoch that is not the persisted head (MED-A fork).  STMT-CHANGE final review
    MED-1: "a step after `now`" is gone; a new one is covered by "not dated `now`", an older one is not checked (`walk`).
    STMT-CHANGE final review 2 LOW-1: the fork is any keyset the prefix reaches (`admitFold`, labels unordered). -/
theorem admitHead_refuses (h : now < st.day ∨ Rules.validDate now = false ∨
      (st.day ≠ 0 ∧ Rules.dayNum st.day + maxSkewDays < Rules.dayNum now) ∨ steps.length < st.epoch ∨
      (∃ p ∈ steps.drop st.epoch, p.1 ≠ now) ∨
      ∃ c, admitFold verify pin x (steps.take st.epoch) = some c ∧ digestOf c ≠ st.head) :
    admitHead verify pin now st x steps = none := by
  cases hh : admitHead verify pin now st x steps with
  | none => rfl
  | some r =>
    obtain ⟨k, st'⟩ := r
    obtain ⟨⟨g1, g2, g3, g4, g6⟩, ⟨c0, hc0, hd0⟩, hk, hst⟩ := admitHead_some hh
    exfalso
    rcases h with h | h | h | h | ⟨p, hp, hn⟩ | ⟨c, hc, hn⟩
    · omega
    · rw [g2] at h; exact absurd h (by simp)
    · rcases g3 with g3 | g3
      · exact h.1 g3
      · omega
    · omega
    · exact hn (g6 p hp)
    · rw [hc0] at hc
      obtain rfl := Option.some.inj hc
      exact hn hd0

/-- Review stmts6 MED-C: a new step out of a keyset not live on `now` is refused, whatever day it claims and whoever
    signed it, so leaked keys of a keyset that expired before today cannot extend a node's chain (e.g. node last ran
    1030, G expired 1121, now 1200: a fork labelled 1100 is refused).  STMT-CHANGE final review 2 LOW-1: `admitFold`
    for `admitChain` (weaker premise). -/
theorem admitHead_expired {c : Keyset} {i : Nat} (hi : st.epoch ≤ i) (hl : i < steps.length)
    (hc : admitFold verify pin x (steps.take i) = some c) (he : ksLive c now = false) :
    admitHead verify pin now st x steps = none := by
  cases hh : admitHead verify pin now st x steps with
  | none => rfl
  | some r =>
    obtain ⟨k, st'⟩ := r
    obtain ⟨⟨g1, g2, g3, g4, g6⟩, _, hk, _⟩ := admitHead_some hh
    exfalso
    have ht : steps.take (i + 1) = steps.take i ++ [steps[i]] := by
      rw [List.take_add_one]; simp [List.getElem?_eq_getElem hl]
    obtain ⟨c1, hc1⟩ := admitFold_prefix (steps := steps.take (i + 1)) (ys := steps.drop (i + 1))
      (by rw [List.take_append_drop]; exact hk)
    rw [ht] at hc1
    obtain ⟨c', f, hc', _, _, _, _, hlv, _⟩ := admitFold_rotation hc1
    rw [hc] at hc'
    obtain rfl := Option.some.inj hc'
    have hm : steps[i] ∈ steps.drop st.epoch := by
      rw [List.mem_drop_iff_getElem]
      exact ⟨i - st.epoch, by omega, by simp [Nat.add_sub_cancel' hi]⟩
    have := g6 _ hm
    rw [this] at hlv
    rw [hlv] at he
    exact absurd he (by simp)

/-- Liveness: a fresh node admits, on a calendar day `now`, any chain from its pin whose steps are all dated `now`
    (MED-C).  STMT-CHANGE K2: + its head live on `now` (`walk`); the ratchet has no reinit digest. -/
theorem admitHead_init (h : admitChain verify pin x steps = some k) (hv : Rules.validDate now = true)
    (hn : ∀ p ∈ steps, p.1 = now) (hl : ksLive k now = true) :
    admitHead verify pin now (Ratchet.init pin) x steps = some (k, ⟨steps.length, digestOf k, now, zeroDigest⟩) := by
  have hk := (admitChain_fold.1 h).2
  have hc0 : admitFold verify pin x (steps.take (Ratchet.init pin).epoch) = admitFold verify pin x [] := by
    simp [Ratchet.init]
  obtain ⟨c, hc⟩ := admitFold_prefix (steps := ([] : List (Nat × Bytes))) (ys := steps) (by simpa using hk)
  have hg : admitGenesis verify pin x = some c := by simpa [admitFold] using hc
  obtain ⟨f, _, hfk, _, hdg, _⟩ := admitGenesis_some hg
  refine admitHead_mk (c := _) ⟨by simp [Ratchet.init], hv, Or.inl rfl, by simp [Ratchet.init], ?_⟩ (by rw [hc0]; exact hc) ?_ hk hl
  · intro p hp; exact hn p (List.mem_of_mem_drop hp)
  · rw [← hfk]; exact hdg

/-- Liveness: after admitting `steps` on day `now`, the node admits their extension by steps dated `now'` on any
    calendar day now' ≥ now within `maxSkewDays` (an honest node only appends to its record), given `hl` (the extension
    is a lawful chain).  A node strands only if it does not run within 31 days or inside the 8-date overlap window.  STMT-CHANGE K2: + the new head live on
    now'; the ratchet keeps `st.cp`.  STMT-CHANGE final review 2 LOW-1: `h'` is `admitFold` (labels of `steps` need
    not precede now'), so it covers a record with a forward-skewed label. -/
theorem admitHead_extend {ts : List (Nat × Bytes)} {k' : Keyset} {now' : Nat}
    (h : admitHead verify pin now st x steps = some (k, st')) (h' : admitFold verify pin x (steps ++ ts) = some k')
    (hn : now ≤ now') (hv : Rules.validDate now' = true) (hs : Rules.dayNum now' ≤ Rules.dayNum now + maxSkewDays)
    (ht : ∀ p ∈ ts, p.1 = now') (hl : ksLive k' now' = true) :
    admitHead verify pin now' st' x (steps ++ ts) = some (k', ⟨(steps ++ ts).length, digestOf k', now', st.cp⟩) := by
  obtain ⟨_, _, hk, hst⟩ := admitHead_some h
  subst hst
  refine admitHead_mk (c := k) ⟨hn, hv, Or.inr hs, by simp, ?_⟩ ?_ rfl h' hl
  · intro p hp
    rw [List.drop_left] at hp
    exact ht p hp
  · rw [List.take_left]; exact hk

/-- K2 recovery (b): a successor is live `minOverlap` days before its predecessor's last day. -/
theorem succOk_overlap {old new : Keyset} (h : succOk old new = true) :
    Rules.dayNum new.notBefore + minOverlap ≤ Rules.dayNum old.notAfter := by
  unfold succOk at h
  simp only [Bool.and_eq_true, decide_eq_true_eq] at h
  exact h.1.2

/-- K2 MED1: proves `lifeOk` for a keyset live 20261220..20270115 and for a successor live 20270105..20270205, plus the
    7-day overlap arithmetic.  That a node admits the successor across 31 Dec is shown by the `vecYear` `#guard`
    (stub verify), not by this theorem. -/
theorem chain_crosses_year_end :
    lifeOk 20261220 20270115 = true ∧ lifeOk 20270105 20270205 = true ∧
      Rules.dayNum 20270105 + minOverlap ≤ Rules.dayNum 20270115 := by decide

/-! ### Re-init (K2 recovery (c)) -/

variable {node r : Bytes} {b : Bool}

/-- STMT-CHANGE final review 3 LOW-A: the quorum counts `reinitKeyOk` keys (was `rosterOk now`). -/
theorem reinit_some (h : reinit verify pin node now st x steps r b = some st') :
    ∃ ss k, decodeSigBlock (r.drop 292) = some ss ∧
      (field r 0 20 = reinitTag ∧ field r 20 64 = node ∧ beNat (field r 84 4) = st.epoch ∧ field r 88 64 = st.head ∧
        beNat (field r 152 4) = st.day ∧ field r 156 64 = st.cp ∧ (b = true → beNat (field r 220 4) = st.epoch) ∧
        beNat (field r 220 4) = steps.length ∧ beNat (field r 288 4) = now ∧
        sha3 (r.take 292) ≠ field r 156 64) ∧
      walk verify pin now st x steps = some k ∧ digestOf k = field r 224 64 ∧
      quorum verify (reinitKeyOk b st.day now) (·.employee) k k.kRoster (sha3 (r.take 292)) ss = true ∧
      st' = ⟨steps.length, digestOf k, now, sha3 (r.take 292)⟩ := by
  unfold reinit at h
  cases hs : decodeSigBlock (r.drop 292) with
  | none => simp [hs] at h
  | some ss =>
    simp [hs, guard] at h
    split at h
    · rename_i hg
      cases hw : walk verify pin now st x steps with
      | none => simp [hw] at h
      | some k =>
        simp [hw] at h
        try simp only [and_assoc] at h
        obtain ⟨hd, hq, rfl⟩ := h
        exact ⟨ss, k, rfl, hg, rfl, hd, hq, rfl⟩
    · exact absurd h (fail_bind _ _)

/-- An applied re-init (node, tag and to-head binding: `reinit_some`; the feed uses only `inBand`, enforced by the Python
    import test `test_provisioning_entry_is_imported_nowhere_in_app`) walked through the persisted head to a head live on `now` that kRoster of its employees, by
    ROSTER keys live on `now`, signed; the new ratchet is (chain length, head digest, `now`, record digest); epoch never
    goes back.  STMT-CHANGE final review 2 LOW-1: `admitFold` for `admitChain`, plus the new steps in day order and
    none after `now` (`walk`).  STMT-CHANGE final review 3 LOW-A: the quorum counts `reinitKeyOk` keys, each also
    `rosterOk now` (stronger; `inband_reinit_keys_live`). -/
theorem reinit_sound (h : reinit verify pin node now st x steps r b = some st') :
    ∃ k ss, admitFold verify pin x steps = some k ∧
      (∃ c, admitFold verify pin x (steps.take st.epoch) = some c ∧ digestOf c = st.head) ∧
      (steps.drop st.epoch).Pairwise (·.1 ≤ ·.1) ∧ (∀ p ∈ steps.drop st.epoch, p.1 ≤ now) ∧ ksLive k now = true ∧
      decodeSigBlock (r.drop 292) = some ss ∧
      quorum verify (reinitKeyOk b st.day now) (·.employee) k k.kRoster (sha3 (r.take 292)) ss = true ∧
      st' = ⟨steps.length, digestOf k, now, sha3 (r.take 292)⟩ ∧ st.epoch ≤ st'.epoch := by
  obtain ⟨ss, k, hs, _, hw, _, hq, rfl⟩ := reinit_some h
  obtain ⟨⟨_, he, ho, hn⟩, hc, hk, hl⟩ := walk_some hw
  exact ⟨k, ss, hk, hc, ho, hn, hl, hs, hq, rfl, he⟩

theorem field_add (r : Bytes) (o i j : Nat) : field r o (i + j) = field r o i ++ field r (o + i) j := by
  simp [field, List.take_add, List.drop_drop]

/-- The record names the exact persisted ratchet (epoch, head, day, cp) it applies from. -/
theorem reinit_from (h : reinit verify pin node now st x steps r b = some st') :
    (r.drop 84).take 136 = natBE 4 st.epoch ++ st.head ++ natBE 4 st.day ++ st.cp := by
  obtain ⟨ss, _, hs, ⟨_, _, h1, h2, h3, h4, _⟩, _⟩ := reinit_some h
  have hlen := congrArg List.length (decodeSigBlock_spec hs).1
  simp [encodeSigs, natBE_length] at hlen
  have l1 : (field r 84 4).length = 4 := by simp [field]; omega
  have l3 : (field r 152 4).length = 4 := by simp [field]; omega
  rw [← h1, ← h2, ← h3, ← h4, natBE_beNat' l1, natBE_beNat' l3]
  show field r 84 (4 + (64 + (4 + 64))) = _
  rw [field_add, field_add, field_add]
  simp [List.append_assoc]

/-- No replay of the step right after the record: from the ratchet it produced (cp = its digest) the same record never
    applies again, on any day, chain or entry (`reinit` refuses a record whose digest is its own cp field).  A replay
    after other records (R1, R2, R1) is not shown here: it rests on SHA3 collision resistance (R2's cp would be R1's
    digest) outside Lean. -/
theorem reinit_no_replay {steps' : List (Nat × Bytes)} {now' : Nat} {b' : Bool}
    (h : reinit verify pin node now st x steps r b = some st') :
    reinit verify pin node now' st' x steps' r b' = none := by
  obtain ⟨_, _, _, _, _, _, _, rfl⟩ := reinit_some h
  cases h' : reinit verify pin node now' _ x steps' r b' with
  | none => rfl
  | some _ =>
    obtain ⟨_, _, _, ⟨_, _, _, _, _, hc, _, _, _, hfp⟩, _⟩ := reinit_some h'
    exact absurd hc.symm hfp

/-- The in-band re-init (the feed's only entry) keeps the persisted epoch and head: it resets the day and admits no
    keyset. -/
theorem inband_reinit_same_epoch (h : reinit verify pin node now st x steps r true = some st') :
    st' = ⟨st.epoch, st.head, now, sha3 (r.take 292)⟩ := by
  obtain ⟨_, k, _, ⟨_, _, _, _, _, _, hb, hte, _⟩, hw, _, _, rfl⟩ := reinit_some h
  obtain ⟨_, ⟨c, hc, hd⟩, hk, _⟩ := walk_some hw
  have he : st.epoch = steps.length := (hb rfl).symm.trans hte
  rw [he, List.take_length, hk] at hc
  obtain rfl := Option.some.inj hc
  rw [he, hd]

/-- Final review 3 LOW-A: an applied in-band re-init on a node that has run (`st.day ≠ 0`) was signed, for the persisted
    head, by kRoster ≥ 2 distinct employees whose ROSTER keys are live on `now` AND on the persisted day. -/
theorem inband_reinit_keys_live (h : reinit verify pin node now st x steps r true = some st') (hd : st.day ≠ 0) :
    ∃ k ss, ∃ es : List Entry, admitFold verify pin x steps = some k ∧ digestOf k = st.head ∧
      decodeSigBlock (r.drop 292) = some ss ∧ es.Sublist k.entries ∧ minRoster ≤ k.kRoster ∧ k.kRoster ≤ es.length ∧ (es.map (·.employee)).Nodup ∧
      ∀ e ∈ es, rosterOk now e = true ∧ rosterOk st.day e = true ∧
        ∃ q ∈ ss, q.keyId = e.keyId ∧ verify e.pk (sha3 (r.take 292)) q.sig = true := by
  obtain ⟨ss, k, hs, _, hw, _, hq, hst⟩ := reinit_some h
  obtain ⟨_, _, hk, _⟩ := walk_some hw
  obtain ⟨hwf, _⟩ := admitFold_wf hk
  obtain ⟨es, hes, _, hl, hn, _, hall⟩ := quorum_sound hwf.2.2.2.2.2.2.2.2.2.2.2.2.2.1 hq
  have hh : digestOf k = st.head := congrArg Ratchet.head (hst.symm.trans (inband_reinit_same_epoch h))
  refine ⟨k, ss, es, hk, hh, hs, hes, hwf.2.2.2.2.2.2.2.1, hl, hn, fun e he => ?_⟩
  obtain ⟨hok, hsig⟩ := hall e he
  have h0 : (st.day == 0) = false := by simpa using hd
  simp only [reinitKeyOk, h0, Bool.not_true, Bool.false_or, Bool.and_eq_true] at hok
  refine ⟨hok.1, ?_, hsig⟩
  have h2 := hok.1
  simp only [rosterOk, Bool.and_eq_true] at h2 ⊢
  exact ⟨h2.1, hok.2⟩

/-- Never un-revokes (as `admitFold_persists`): every key revoked in the persisted head's keyset is present and revoked
    in the re-init's head.  STMT-CHANGE final review 2 LOW-1: `admitFold` for `admitChain` (weaker premise). -/
theorem reinit_never_unrevokes {c : Keyset} (h : reinit verify pin node now st x steps r b = some st')
    (hc : admitFold verify pin x (steps.take st.epoch) = some c) :
    digestOf c = st.head ∧ ∃ k, admitFold verify pin x steps = some k ∧ digestOf k = st'.head ∧
      ∀ e ∈ c.entries, e.revokedFrom ≠ live → ∃ f ∈ k.entries, f.keyId = e.keyId ∧ f.revokedFrom ≠ live := by
  obtain ⟨k, _, hk, ⟨c', hc', hd⟩, _, _, _, _, _, rfl, _⟩ := reinit_sound h
  rw [hc] at hc'
  obtain rfl := Option.some.inj hc'
  exact ⟨hd, k, hk, rfl, admitFold_persists hc _ k (by rw [List.take_append_drop]; exact hk)⟩

/-- K2 recovery (a): a run whose head is not live on `now` is refused by both entries, so it persists nothing
    (`SnapshotV2.attachChain` returns `st` on a refused head).  STMT-CHANGE final review 3 LOW-B: `admitFold` premise
    (weaker; `admitChain_fold`), so it covers a record with unordered persisted labels. -/
theorem refused_run_persists_nothing (hk : admitFold verify pin x steps = some k) (hl : ksLive k now = false) :
    admitHead verify pin now st x steps = none ∧ ∀ node r b, reinit verify pin node now st x steps r b = none := by
  have hw : walk verify pin now st x steps = none := by
    cases h : walk verify pin now st x steps with
    | none => rfl
    | some k' =>
      obtain ⟨_, _, hk', hl'⟩ := walk_some h
      rw [hk] at hk'
      obtain rfl := Option.some.inj hk'
      rw [hl] at hl'
      exact absurd hl' (by simp)
  refine ⟨?_, fun node r b => ?_⟩
  · cases h : admitHead verify pin now st x steps with
    | none => rfl
    | some o => obtain ⟨_, _⟩ := o; rw [(admitHead_walk h).2.1] at hw; cases hw
  · cases h : reinit verify pin node now st x steps r b with
    | none => rfl
    | some _ => obtain ⟨_, _, _, _, hw', _⟩ := reinit_some h; rw [hw'] at hw; cases hw

/-! Witnesses (cross vectors for tests/test_right_rail_gate_keyset.py).  `Entry` has no DecidableEq, so results compare
    through `digestOf`.  Records are sorted like entries, so no vector is refused for record order. -/
def vecPk (b : UInt8) : Bytes := List.replicate mlDsa87Key b
/-- ROSTER key with pk byte `b`, held by employee `p`. -/
def vecRoster (b p : UInt8) : Entry :=
  ⟨sha3 (keyTag ++ vecPk b), List.replicate 64 p, List.replicate 64 2, roster, 0, 0, 20260101, 20271231, live, 0, 0,
    vecPk b⟩
def vecSort (es : List Entry) : List Entry := es.mergeSort fun a b => decide (beNat a.keyId ≤ beNat b.keyId)
/-- Stub records (83s) from the keys in `sg`, sorted. -/
def vecRecs (sg : List Entry) : List SigRec := (vecSort sg).map fun e => ⟨e.keyId, List.replicate mlDsa87Signature 83⟩
/-- Genesis over roster `es` (kRoster 2, kSource 2, life 20261021..20261121), with stub records from `sg`. -/
def vecGen (es sg : List Entry) : Frame :=
  ⟨⟨List.replicate 64 7, 0, zeroDigest, 20261021, 20261121, 2, 2, vecSort es⟩, vecRecs sg⟩
/-- Epoch e+1 after `c`, live from `nb` to the same day next month, kRoster 2, kSource 2, roster `es`, records from `sg`. -/
def vecNext (c : Keyset) (nb : Nat) (es sg : List Entry) : Frame :=
  ⟨⟨c.state, c.epoch + 1, digestOf c, nb, nb + 100, 2, 2, vecSort es⟩, vecRecs sg⟩
/-- `admitChain` with a stub verify (every record verifies, so only counting, liveness and linkage decide), reported
    as the head's digest. -/
def vecWalk (g : Frame) (steps : List (Nat × Frame)) : Option Bytes :=
  (admitChain (fun _ _ _ => true) (digestOf g.ks) (encode g) (steps.map fun s => (s.1, encode s.2))).map digestOf
/-- 2-of-2, two employees (witness for admitChain_two_of_two). -/
def vecTwo : Frame := vecGen [vecRoster 9 1, vecRoster 10 2] [vecRoster 9 1, vecRoster 10 2]
#guard (admitChain (fun _ _ _ => true) (digestOf vecTwo.ks) (encode vecTwo) []).map digestOf == some (digestOf vecTwo.ks)
#guard (admitChain (fun pk _ _ => pk == vecPk 9) (digestOf vecTwo.ks) (encode vecTwo) []).isNone
#guard (admitChain (fun _ _ _ => true) (digestOf vecTwo.ks) (encode ⟨vecTwo.ks, vecTwo.sigs.take 1⟩) []).isNone
/-- LOW b negative (witness for quorum_one_person): keys 9 and 10 both belong to employee 1, so two keys are one vote and
    the genesis has no quorum.  `vecMixed` is the same keyset signed by keys 9 and 11 (two employees) and is admitted, so
    `vecSame` fails on persons only, not on decode or record order. -/
def vecThree : List Entry := [vecRoster 9 1, vecRoster 10 1, vecRoster 11 2]
def vecSame : Frame := vecGen vecThree [vecRoster 9 1, vecRoster 10 1]
def vecMixed : Frame := vecGen vecThree [vecRoster 9 1, vecRoster 11 2]
#guard (admitChain (fun _ _ _ => true) (digestOf vecSame.ks) (encode vecSame) []).isNone
#guard (admitChain (fun _ _ _ => true) (digestOf vecMixed.ks) (encode vecMixed) []).map digestOf ==
  some (digestOf vecMixed.ks)
/-- vecTwo's keyset live 20261101..20261201, so Nov 30 and Nov 31 differ only in being a calendar date. -/
def vecNov : Frame := ⟨{ vecTwo.ks with notBefore := 20261101, notAfter := 20261201 }, vecTwo.sigs⟩
-- stmts6 LOW-D: a day that is not a calendar date (Nov 31) is refused by a fresh node; Nov 30 is admitted
#guard (admitHead (fun _ _ _ => true) (digestOf vecNov.ks) 20261131 (Ratchet.init (digestOf vecNov.ks)) (encode vecNov)
  []).isNone
#guard (admitHead (fun _ _ _ => true) (digestOf vecNov.ks) 20261130 (Ratchet.init (digestOf vecNov.ks)) (encode vecNov)
  []).isSome
-- K2 recovery (a): a fresh node whose clock puts no live keyset in force persists nothing; a live day is admitted
#guard [99991231, 20261020, 20261122].all fun d =>
  (admitHead (fun _ _ _ => true) (digestOf vecTwo.ks) d (Ratchet.init (digestOf vecTwo.ks)) (encode vecTwo) []).isNone
#guard (admitHead (fun _ _ _ => true) (digestOf vecTwo.ks) 20261022 (Ratchet.init (digestOf vecTwo.ks)) (encode vecTwo)
  []).map (·.2) == some ⟨0, digestOf vecTwo.ks, 20261022, zeroDigest⟩
/-! MED-1 (review r3): succession vectors.  vecTwo is live 20261021..20261121; each successor below is live from
    20261101 (or 20261110) for a month.  Every negative has a positive twin differing in one fact. -/
def vecR0 : List Entry := [vecRoster 9 1, vecRoster 10 2]
/-- Re-issue of vecTwo (same roster), signed by keys 9 and 10 (both quorums: cur and new). -/
def vecS1 : Frame := vecNext vecTwo.ks 20261101 vecR0 vecR0
#guard vecWalk vecTwo [(20261101, vecS1)] == some (digestOf vecS1.ks)
-- expired cur: 20261122 is after vecTwo.notAfter (vecS1 is live that day)
#guard vecWalk vecTwo [(20261122, vecS1)] == none
-- new not yet live: 20261025 is before vecS1.notBefore (vecTwo is live that day)
#guard vecWalk vecTwo [(20261025, vecS1)] == none
/-- Rotation: key 10 (employee 2) revoked, key 12 (employee 3) added; cur quorum 9 + 10, new quorum 9 + 12. -/
def vecR1 : List Entry := [vecRoster 9 1, { vecRoster 10 2 with revokedFrom := 20261101 }, vecRoster 12 3]
def vecRot : Frame := vecNext vecTwo.ks 20261101 vecR1 [vecRoster 9 1, vecRoster 10 2, vecRoster 12 3]
#guard vecWalk vecTwo [(20261101, vecRot)] == some (digestOf vecRot.ks)
/-- Revoked fork: a re-issue of vecRot signed by 9 + 10 (10 revoked) is refused; the same keyset signed by 9 + 12 is
    admitted; un-revoking 10 is refused even when 9 + 12 sign (succOk). -/
def vecFork : Frame := vecNext vecRot.ks 20261110 vecR1 [vecRoster 9 1, vecRoster 10 2]
def vecHonest : Frame := vecNext vecRot.ks 20261110 vecR1 [vecRoster 9 1, vecRoster 12 3]
def vecUnrevoke : Frame :=
  vecNext vecRot.ks 20261110 [vecRoster 9 1, vecRoster 10 2, vecRoster 12 3] [vecRoster 9 1, vecRoster 12 3]
#guard vecWalk vecTwo [(20261101, vecRot), (20261110, vecFork)] == none
#guard vecWalk vecTwo [(20261101, vecRot), (20261110, vecHonest)] == some (digestOf vecHonest.ks)
#guard vecWalk vecTwo [(20261101, vecRot), (20261110, vecUnrevoke)] == none
-- days going backwards are refused though each step is live and signed on its own day (LOW e)
#guard vecWalk vecTwo [(20261111, vecRot), (20261112, vecHonest)] == some (digestOf vecHonest.ks)
#guard vecWalk vecTwo [(20261112, vecRot), (20261111, vecHonest)] == none
-- review K2 F5: a successor that moves key 10's revocation LATER, or drops the revoked entry, is refused; earlier is fine
def vecLater : Frame :=
  vecNext vecRot.ks 20261110 [vecRoster 9 1, { vecRoster 10 2 with revokedFrom := 20261105 }, vecRoster 12 3]
    [vecRoster 9 1, vecRoster 12 3]
def vecEarlier : Frame :=
  vecNext vecRot.ks 20261110 [vecRoster 9 1, { vecRoster 10 2 with revokedFrom := 20261031 }, vecRoster 12 3]
    [vecRoster 9 1, vecRoster 12 3]
def vecDropped : Frame := vecNext vecRot.ks 20261110 [vecRoster 9 1, vecRoster 12 3] [vecRoster 9 1, vecRoster 12 3]
#guard vecWalk vecTwo [(20261101, vecRot), (20261110, vecLater)] == none
#guard vecWalk vecTwo [(20261101, vecRot), (20261110, vecEarlier)] == some (digestOf vecEarlier.ks)
#guard vecWalk vecTwo [(20261101, vecRot), (20261110, vecDropped)] == none
/-- Same-employee pair: a re-issue of vecMixed signed by keys 9 + 10 (both employee 1) is refused; 9 + 11 admitted. -/
def vecSameSucc : Frame := vecNext vecMixed.ks 20261101 vecThree [vecRoster 9 1, vecRoster 10 1]
def vecMixedSucc : Frame := vecNext vecMixed.ks 20261101 vecThree [vecRoster 9 1, vecRoster 11 2]
#guard vecWalk vecMixed [(20261101, vecSameSucc)] == none
#guard vecWalk vecMixed [(20261101, vecMixedSucc)] == some (digestOf vecMixedSucc.ks)
/-- MED-2: nine roster keys of nine employees decode at kRoster 8 and are refused at kRoster 9. -/
def vecNine : Frame :=
  let es := (List.range 9).map fun i => vecRoster (30 + i).toUInt8 (30 + i).toUInt8
  vecGen es es
#guard (decode (encode ⟨{ vecNine.ks with kRoster := 8 }, vecNine.sigs⟩)).isSome
#guard (decode (encode ⟨{ vecNine.ks with kRoster := 9 }, vecNine.sigs⟩)).isNone


/-! Round 5 LOW (review r4): roster windows, and 8 + 8 at the maxRoster cap. -/
/-- Key 10 expires 20261110, inside vecGen's life (20261021..20261121), so it does not count toward kRoster 2 and the
    keyset is refused; a third employee's covering key 11 makes it decode. -/
def vecShort : Entry := { vecRoster 10 2 with validUntil := 20261110 }
#guard (decode (encode (vecGen [vecRoster 9 1, vecShort] vecR0))).isNone
#guard (decode (encode (vecGen [vecRoster 9 1, vecShort, vecRoster 11 3] vecR0))).isSome
/-- Eight roster keys of eight employees, pk and employee bytes from `b`. -/
def vec8 (b : Nat) : List Entry := (List.range 8).map fun i => vecRoster (b + i).toUInt8 (b + i).toUInt8
/-- kRoster 8 genesis over vec8 30, signed by all eight. -/
def vecG8 : Frame := ⟨{ (vecGen (vec8 30) []).ks with kRoster := 8 }, vecRecs (vec8 30)⟩
/-- Epoch 1 over eight new keys of eight new employees (vec8 40, kRoster 8), records from `sg`. -/
def vecN8 (sg : List Entry) : Frame := ⟨{ (vecNext vecG8.ks 20261101 (vec8 40) []).ks with kRoster := 8 }, vecRecs sg⟩
-- all 16 keys sign: one 16-record block carries both 8-employee quorums (admitSucc_fits at the cap)
#guard vecWalk vecG8 [(20261101, vecN8 (vec8 30 ++ vec8 40))] == some (digestOf (vecN8 []).ks)
-- one cur or one new record short: refused
#guard vecWalk vecG8 [(20261101, vecN8 ((vec8 30).drop 1 ++ vec8 40))] == none
#guard vecWalk vecG8 [(20261101, vecN8 (vec8 30 ++ (vec8 40).drop 1))] == none

/-! Review stmts5 L4 and L5. -/
-- L4: kSource 1 is refused at decode (one person never attaches facts); vecTwo (kSource 2) decodes
#guard (decode (encode vecTwo)).isSome
#guard (decode (encode ⟨{ vecTwo.ks with kSource := 1 }, vecTwo.sigs⟩)).isNone
/-- L5: tombstone `i`, a revoked ROSTER key with its own pk (u16 i, then zeros). -/
def vecTomb (i : Nat) : Entry :=
  let pk := natBE 2 i ++ List.replicate (mlDsa87Key - 2) 0
  ⟨sha3 (keyTag ++ pk), List.replicate 64 0, List.replicate 64 2, roster, 0, 0, 20260101, 20271231, 20261001, 0, 0, pk⟩
/-- vecTwo's roster plus `n` tombstones. -/
def vecCap (n : Nat) : Frame := vecGen (vecR0 ++ (List.range n).map vecTomb) vecR0
-- 1024 entries meet `decode_encode`'s premises (decoding them is quadratic in `cut` and too slow to evaluate here);
-- 1025 are refused by decode on the count alone (`decode_over_cap`)
#guard decide (Wf (vecCap 1022).ks ∧ SigsWf (vecCap 1022).sigs)
#guard (decode (encode (vecCap 1023))).isNone

/-- K2 MED1 (`chain_crosses_year_end`): vecTwo re-dated 20261220..20270115 decodes and admits a successor from 20270105;
    one from 20270110 (6 days of overlap) is refused. -/
def vecYear : Frame := ⟨{ vecTwo.ks with notBefore := 20261220, notAfter := 20270115 }, vecTwo.sigs⟩
#guard vecWalk vecYear [(20270105, vecNext vecYear.ks 20270105 vecR0 vecR0)] ==
  some (digestOf (vecNext vecYear.ks 20270105 vecR0 vecR0).ks)
#guard vecWalk vecYear [(20270110, vecNext vecYear.ks 20270110 vecR0 vecR0)] == none
-- boundaries of the real `succOk` (overlap 7 days) and `lifeOk` (7..31 days)
def vecOv (nb : Nat) : Keyset := { (vecNext vecYear.ks 20270105 vecR0 vecR0).ks with notBefore := nb }
#guard succOk vecYear.ks (vecOv 20270108) == true && succOk vecYear.ks (vecOv 20270109) == false
#guard lifeOk 20270101 20270108 && lifeOk 20270101 20270201 && !lifeOk 20270101 20270107 && !lifeOk 20270101 20270202
/-- Lowercase hex (`Vectors.toHex`, which this module cannot import: its `main` clashes in the axiom printer). -/
def vecHex (b : Bytes) : String := String.join (b.map fun x => String.ofList ((Nat.toDigits 16 (x.toNat + 256)).drop 1))
/-- K2 recovery (c) record (tests/test_right_rail_gate_keyset.py test_reinit_record_vector): node 0x0e^64, locked at
    (0, vecTwo, 99991231), re-initialised to (0, vecTwo, 20261022) by keys 9 and 10.  Lean's encoder gives Python's
    bytes.  No key is live on 99991231 (the pre-K2 lock), so in band it is refused (`reinitKeyOk`, final review 3 LOW-A);
    provisioned it applies once. -/
def vecLock : Ratchet := ⟨0, digestOf vecTwo.ks, 99991231, zeroDigest⟩
def vecReinit : Bytes :=
  reinitBody (List.replicate 64 14) vecLock 0 (digestOf vecTwo.ks) 20261022 ++ encodeSigs (vecRecs vecR0)
#guard (vecReinit.length, vecHex (sha3 vecReinit)) == (292 + 1 + 2 * (64 + mlDsa87Signature),
  "a0f763e7919e7f2384a605e42a742667b2735cdc858752f5cf288cb7eff82c11862e21b31a0f618b744ca7b21d27b4b541623e06085d66c2eccfaba9b3d147e9")
def vecApplied : Ratchet := ⟨0, digestOf vecTwo.ks, 20261022, sha3 (vecReinit.take 292)⟩
#guard [true, false].map (reinit (fun _ _ _ => true) (digestOf vecTwo.ks) (List.replicate 64 14) 20261022 vecLock
  (encode vecTwo) [] vecReinit) == [none, some vecApplied]
#guard (reinit (fun _ _ _ => true) (digestOf vecTwo.ks) (List.replicate 64 14) 20261022 vecApplied (encode vecTwo) []
  vecReinit false).isNone
/-- Final review MED-1 (`walk`; test_forward_skewed_rotation_label_does_not_lock_recovery): ran 20261102 on vecTwo, the
    clock jumped to 20261115 and vecRot was admitted with that label; on the real day 20261103 the node is behind its
    persisted day, the in-band re-init to 20261103 under vecRot (live that day; roster 9 + 12, 10 is revoked) recovers
    it, and the next day's run is admitted.  Under the old bound on every step both refuse until 20261115. -/
def vecSkewSteps : List (Nat × Bytes) := [(20261115, encode vecRot)]
def vecSkew : Ratchet := ⟨1, digestOf vecRot.ks, 20261115, zeroDigest⟩
#guard ((admitHead (fun _ _ _ => true) (digestOf vecTwo.ks) 20261102 (Ratchet.init (digestOf vecTwo.ks)) (encode vecTwo)
  []).bind fun (_, st) => admitHead (fun _ _ _ => true) (digestOf vecTwo.ks) 20261115 st (encode vecTwo)
  vecSkewSteps).map (·.2) == some vecSkew
#guard (admitHead (fun _ _ _ => true) (digestOf vecTwo.ks) 20261103 vecSkew (encode vecTwo) vecSkewSteps).isNone
def vecFix : Bytes := reinitBody (List.replicate 64 14) vecSkew 1 (digestOf vecRot.ks) 20261103 ++
  encodeSigs (vecRecs [vecRoster 9 1, vecRoster 12 3])
def vecFixed : Ratchet := ⟨1, digestOf vecRot.ks, 20261103, sha3 (vecFix.take 292)⟩
#guard reinit (fun _ _ _ => true) (digestOf vecTwo.ks) (List.replicate 64 14) 20261103 vecSkew (encode vecTwo) vecSkewSteps
  vecFix true == some vecFixed
#guard (admitHead (fun _ _ _ => true) (digestOf vecTwo.ks) 20261104 vecFixed (encode vecTwo) vecSkewSteps).isSome
/-- `admitHead` and `walk` on vecTwo's pin with a stub verify. -/
def vecH (now : Nat) (st : Ratchet) (ss : List (Nat × Bytes)) := admitHead (fun _ _ _ => true) (digestOf vecTwo.ks) now st
  (encode vecTwo) ss
def vecW (now : Nat) (st : Ratchet) (ss : List (Nat × Bytes)) := walk (fun _ _ _ => true) (digestOf vecTwo.ks) now st
  (encode vecTwo) ss
/-- Final review 2 LOW-1 (`walk`; test_skewed_label_does_not_refuse_a_new_rotation): after the recovery above, ROT2 dated
    20261105 revokes key 12 (employee 3) and adds key 13 (employee 4), signed by 9 + 12 (cur) and 9 + 13 (new).  The
    recovered node admits it below the persisted label 20261115 and runs on over that unordered record, with key 12 dead;
    new steps out of day order among themselves, or dated after `now`, are still refused (twins admitted).  Under the
    order from genesis the first `#guard` fails. -/
def vecR2 : List Entry :=
  [vecRoster 9 1, { vecRoster 10 2 with revokedFrom := 20261101 }, { vecRoster 12 3 with revokedFrom := 20261105 }, vecRoster 13 4]
def vecRot2 : Frame := vecNext vecRot.ks 20261105 vecR2 [vecRoster 9 1, vecRoster 12 3, vecRoster 13 4]
def vecRot3 : Frame := vecNext vecRot2.ks 20261105 vecR2 [vecRoster 9 1, vecRoster 13 4]
def vecRec (ss : List (Nat × Frame)) : List (Nat × Bytes) := vecSkewSteps ++ ss.map fun s => (s.1, encode s.2)
#guard ((vecH 20261105 vecFixed (vecRec [(20261105, vecRot2)])).bind fun (_, st) =>
  vecH 20261106 st (vecRec [(20261105, vecRot2)])).map (digestOf ·.1) == some (digestOf vecRot2.ks)
#guard !(vecRot2.ks.entries.any fun e => e.keyId == (vecRoster 12 3).keyId && rosterOk 20261105 e)
#guard (vecW 20261106 vecFixed (vecRec [(20261105, vecRot2), (20261106, vecRot3)])).map digestOf == some (digestOf vecRot3.ks)
#guard (vecW 20261106 vecFixed (vecRec [(20261106, vecRot2), (20261105, vecRot3)])).isNone
#guard (vecW 20261105 vecFixed (vecRec [(20261106, vecRot2)])).isNone
/-- Review 2 LOW-2 (`maxSkewDays`; test_skewed_head_not_yet_live_waits_for_its_notbefore): a rotation admitted under the
    20261115 clock that is live only from 20261112 holds the node on the real days 20261103..20261111 (no in-band re-init
    applies: the head is not live) and one applies from 20261112. -/
def vecRotL : Frame := vecNext vecTwo.ks 20261112 vecR1 [vecRoster 9 1, vecRoster 10 2, vecRoster 12 3]
def vecSkewL : Ratchet := ⟨1, digestOf vecRotL.ks, 20261115, zeroDigest⟩
def vecFixL (d : Nat) : Bytes :=
  reinitBody (List.replicate 64 14) vecSkewL 1 (digestOf vecRotL.ks) d ++ encodeSigs (vecRecs [vecRoster 9 1, vecRoster 12 3])
#guard ((vecH 20261102 (Ratchet.init (digestOf vecTwo.ks)) []).bind fun (_, st) =>
  vecH 20261115 st [(20261115, encode vecRotL)]).map (·.2) == some vecSkewL
#guard [20261103, 20261111, 20261112].map (fun d => (reinit (fun _ _ _ => true) (digestOf vecTwo.ks) (List.replicate 64 14)
  d vecSkewL (encode vecTwo) [(20261115, encode vecRotL)] (vecFixL d) true).isSome) == [false, false, true]
/-- Final review 3 LOW-A (`reinitKeyOk`; test_rollback_reinit_needs_keys_live_on_the_persisted_day): vecC (epoch 1, live
    20261101..20261201) lists keys 21 and 22 (employees 5, 6) valid to 20261104 beside its cover roster 9 + 10; the node
    admitted it on 20261110.  With the clock set back to 20261103, an in-band re-init signed by 21 + 22 (live that day,
    expired by 20261110) is refused, so they cannot sign a fork dated 20261103 that the node later runs on; signed by
    9 + 10 (live on both days) it applies.  Under the `rosterOk now` quorum both apply. -/
def vecS21 : Entry := { vecRoster 21 5 with validUntil := 20261104 }
def vecS22 : Entry := { vecRoster 22 6 with validUntil := 20261104 }
def vecC : Frame := vecNext vecTwo.ks 20261101 [vecRoster 9 1, vecRoster 10 2, vecS21, vecS22] vecR0
def vecRb : Ratchet := ⟨1, digestOf vecC.ks, 20261110, zeroDigest⟩
#guard (vecH 20261110 (Ratchet.init (digestOf vecTwo.ks)) [(20261110, encode vecC)]).map (·.2) == some vecRb
#guard [[vecS21, vecS22], vecR0].map (fun sg => (reinit (fun _ _ _ => true) (digestOf vecTwo.ks) (List.replicate 64 14)
  20261103 vecRb (encode vecTwo) [(20261110, encode vecC)]
  (reinitBody (List.replicate 64 14) vecRb 1 (digestOf vecC.ks) 20261103 ++ encodeSigs (vecRecs sg)) true).isSome) ==
  [false, true]

end BlindLedger.Gate.Keyset
