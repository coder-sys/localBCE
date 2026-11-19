import BlindLedger.Gate.Anchor
import BlindLedger.Gate.Authority
import BlindLedger.Gate.Rules.Fast
import BlindLedger.Gate.Rules.Request
import BlindLedger.Sha3Fast
import BlindLedger.Sha3Quick
import BlindLedger.Sha3

/-! The vector runner (runs per gate batch; emits `RULES_READS`, `reads`): decides with `Fast.decideBatchFIn` (= `decideBatchIn`, `FastEq.decideBatchFIn_eq`; no reversed re-run, order independence `Theorems.decideBatchIn_perm`) and pins with `Fast.pinBytes` (`pin_run_eq`). Lines marked `-- FAST` differ from the pre-twin runner. -/

namespace BlindLedger.Gate.Rules.Run

open BlindLedger.Gate.Rules

/-! Runs a rules vector file through `decideBatchIn` (its proved twin `Fast.decideBatchFIn`).  Directives,
    one per line: `case NAME` clears the batch, the totals, the lines earlier commits
    released or left unresolved and the gate's checkpoints; `today D`;
    `snap KIND ASOF COUNT PIN` (re)declares a snapshot (`dmf`, `pdeath`,
    `excl`, `span`, `elig` with rows `MEMBER AID LEVEL START STOP`) or the `released` or `unresolved` set (rows `ID[:PAY] FLOW
    M PAYEE REND DATE PROC UNITS CENTS`, PAY defaulting to ID; it also drops
    the lines earlier commits added to that set), whose rows are the
    following lines starting with KIND.  PIN is the SHA3-512 hex of
    `pinInput`; a snapshot whose pin does not match or with a row that does
    not parse is treated as missing, as is one after `drop KIND`.
    `line ...row fields... [OUTCOME REASONS [with=IDS]]` adds a line to the
    batch, `redo PAY` makes the batch re-decide that payment and `pay PAY
    OUTCOME` expects its `payOutcome`; `commit` decides the batch, checks the
    expectations (all lines or none), adds its released and unresolved lines
    to those sets, and takes the result's checkpoints (`advance`).  `anchor
    HEX` names the latest sealed checkpoint's state digest for the next commit,
    which then decides only if the checkpoints it extends hash to it
    (`Gate.decideAnchored`); without one, the runner's own last commit is that
    checkpoint.  `commit UNANCHORED` expects the refusal.  `commit SHOW` also prints each line (`RULES_LINE`), the state
    digest after it (`RULES_DIGEST`, `Gate.setsDigest`), the rows it appended (`RULES_ADDS`: per row
    `u8 set` (1 released, 2 unresolved) then the `Line.fields` row, hex) and what it read (`RULES_READS`, `reads`
    on the checkpoint it extends, or before the first on the sets it declares; redo order is part of the record).  `load G_ASOF ADDSHEX ANCHORHEX`
    drops the released and unresolved sets and replays those rows onto empty sets dated G_ASOF
    (`ShardState.loadAdds`); unless they hash to ANCHORHEX it prints `RULES_STATE_MISMATCH` and fails.  Arrival
    order cannot change a decision (`decideBatchIn_perm`).  `report`
    prints totals; `end N` is the number of checked lines.  Test-only; never
    a payment path. -/

def name {α : Type} [Repr α] (x : α) : String := ((reprStr x).splitOn ".").getLast!

def parse {α : Type} [Repr α] (all : List α) (s : String) : Option α := all.find? (name · == s)

#guard (reasons.map name).zip ((reasons.map name).drop 1) |>.all fun (a, b) => decide (a < b)

-- G2's allowed aid codes are the identifiers of localBCE's (rust-engine/src/main.rs:235).
#guard allowedAid == ["13", "23", "53", "103", "104"].map aidId

-- Every unverified or stale reason is a review reason: `review`'s `| _ => false` cannot silently make one a HOLD.
#guard reasons.all fun r => review r || !((name r).endsWith "_UNVERIFIED" || (name r).startsWith "STALE_")

def hB (b : ByteArray) : List UInt8 := (BlindLedger.Semantic.sha3_512Quick b).toList

def hexOf (b : ByteArray) : String :=
  let d (n : UInt8) : UInt8 := if n < 10 then 48 + n else 87 + n
  String.fromUTF8! (b.foldl (fun a x => (a.push (d (x >>> 4))).push (d (x &&& 15))) (ByteArray.emptyWithCapacity (2 * b.size)))

/-- A hex digit's value. -/
def nib (c : UInt8) : Option UInt8 :=
  if 48 ≤ c && c ≤ 57 then some (c - 48) else if 97 ≤ c && c ≤ 102 then some (c - 87) else none

/-- Hex to bytes, high digit first; linear in the input. -/
def unhex (s : String) : Option ByteArray :=
  let u := s.toUTF8
  if u.size % 2 != 0 then none else
  (List.range (u.size / 2)).foldlM (fun a i => do pure (a.push ((← nib u[2 * i]!) * 16 + (← nib u[2 * i + 1]!))))
    (ByteArray.emptyWithCapacity (u.size / 2))

/-- `unhex`'s loop over `k` digit pairs from pair `i`, with no list and no closure per pair (`unhexFast_eq`). -/
def unhexGo (u : ByteArray) : Nat → Nat → ByteArray → Option ByteArray
  | 0, _, a => some a
  | k + 1, i, a => do unhexGo u k (i + 1) (a.push ((← nib u[2 * i]!) * 16 + (← nib u[2 * i + 1]!)))

def unhexFast (s : String) : Option ByteArray :=
  let u := s.toUTF8
  if u.size % 2 != 0 then none else unhexGo u (u.size / 2) 0 (ByteArray.emptyWithCapacity (u.size / 2))

/-- `s` cut at every `c`, empty pieces kept (`String.split` has lemmas, the old `splitOn` none). -/
def splitC (s : String) (c : Char) : List String := (s.split c).toList.map (·.copy)

/-- A vector line's fields: `\r` dropped, split on spaces, empties skipped. -/
def fields (raw : String) : List String := (splitC (String.ofList (raw.toList.filter (· ≠ '\r'))) ' ').filter (· ≠ "")

/-- `fields` without the per-character list round trip when the line has no `\r` (`fieldsFast_eq`). -/
def fieldsFast (raw : String) : List String :=
  if raw.contains '\r' then fields raw else (splitC raw ' ').filter (· ≠ "")

/-- One `RULES_ADDS` row: the set tag, then the `Line.fields` row. -/
def rowBytes (tag : UInt8) (l : Line) : Option (List UInt8) :=
  do let bs ← l.fields.mapM fun (w, n) => be w n
     pure (tag :: bs.flatten)

/-- `rowBytes` as one ByteArray (`rowBytesFast_eq`). -/
def rowBytesFast (tag : UInt8) (l : Line) : Option ByteArray := Fast.pushRow (ByteArray.empty.push tag) l.fields

def rowWidths : List Nat := (Line.fields ⟨0, 0, .FFS_CYCLE, 0, 0, 0, 0, 0, 0, 0⟩).map (·.1)

/-- The row at byte offset `o` of `b`: the set tag and the line. -/
def parseRow (b : ByteArray) (o : Nat) : Option (UInt8 × Line) := do
  let be (o w : Nat) : Nat := (List.range w).foldl (fun n i => n * 256 + (b.get! (o + i)).toNat) 0
  match (rowWidths.foldl (fun (r, o) w => (r.push (be o w), o + w)) (#[], o + 1)).1.toList with
  | [i, y, f, m, p, r, d, c, u, a] =>
    pure (b.get! o, ⟨i, y, ← [Flow.FFS_CYCLE, .FFS_CLAIM, .CAP_820].find? (·.tag == f), m, p, r, d, c, u, a⟩)
  | _ => none

/-- `RULES_ADDS` back into the released and unresolved rows. -/
def parseAdds (bs : ByteArray) : Option (List Line × List Line) := do
  let n := 1 + rowWidths.sum
  guard (bs.size % n == 0)
  let rows ← (List.range (bs.size / n)).mapM fun i => parseRow bs (n * i)
  guard (rows.all fun (t, _) => t == 1 || t == 2)
  pure ((rows.filter (·.1 == 1)).map (·.2), (rows.filter (·.1 == 2)).map (·.2))

/-- The pin of an empty set dated `a` (`snapshot`'s check, for a set that `load` declares). -/
def emptyPin (kind : String) (a : Nat) : Option String :=
  (Fast.pinBytes s!"RR/GATE/{kind.toUpper}/v1" (if kind == "released" then 5 else 6) Line.fields
    (⟨a, 0, []⟩ : Snapshot Line)).map fun b => hexOf (BlindLedger.Semantic.sha3_512Quick b)

/-- The seven pinned inputs with their checked pins, and the five kinds' `readPin`s, once per declaration.  -- FAST -/
structure Pinned where
  dmf : Option (Snapshot Death × List UInt8)
  pdeath : Option (Snapshot Death × List UInt8)
  excl : Option (Snapshot Exclusion × List UInt8)
  span : Option (Snapshot Span × List UInt8)
  elig : Option (Snapshot Elig × List UInt8)
  released : Option (Snapshot Line × List UInt8)
  unresolved : Option (Snapshot Line × List UInt8)
  kinds : Option (List (List UInt8 × List UInt8))

/-- The checkpoint sets' digest kept with the sets it was computed over, so it can never be applied to others (`Memo.get_eq`). -/
structure Memo where
  r : Snapshot Line
  u : Snapshot Line
  d : Option (List UInt8)
  ok : d = Fast.setsDigestF hB r u

/-- `Fast.setsDigestF hB r u`, reusing the memo when it is for exactly these sets. -/
def Memo.get (m : Option Memo) (r u : Snapshot Line) : Option (List UInt8) :=
  match m with
  | some m => if m.r = r ∧ m.u = u then m.d else Fast.setsDigestF hB r u
  | none => Fast.setsDigestF hB r u

/-- A payment request a frame carried (`req HEX`): the request Lean decoded, its payment number (`payNat`) and the lines
    it is decided on (`linesOf`; none for a flow with no rules, whose payment is HUMAN_REVIEW by `payOutcome`). -/
structure Req where
  q : Nat
  /-- The decoded request, its byte fields as byte arrays (`r` is the request). -/
  ra : RequestBA
  ls : List Line
  /-- The request's bytes as the frame carried them (`r` is what they decode to). -/
  x : ByteArray

@[inline] def Req.r (e : Req) : Request := e.ra.toModel

structure St where
  today : Nat := 0
  snaps : List (String × Nat × Nat × String) := []
  rows : Array (String × List String) := #[]           -- FAST: was a List grown by `++ [x]`
  /-- `pin` of the current `snaps` and `rows`; cleared whenever either changes.  -- FAST -/
  pinned : Option Pinned := none
  memo : Option Memo := none
  extra : List Line := []
  held : List Line := []
  rprior : Snapshot Line := ⟨0, 0, []⟩
  uprior : Snapshot Line := ⟨0, 0, []⟩
  anchor : Option Nat := none
  batch : Array (Line × Option String) := #[]          -- FAST
  redo : List Nat := []
  pays : List (Nat × String) := []
  /-- The batch's requests, in frame order; a batch has requests or `line` lines, never both. -/
  reqs : Array Req := #[]
  /-- `grant HEX`: the APPROVAL/v2 grant bytes as the state delivered them (admitted at commit); `release HEX`: the engine
      release (64 bytes); `bypass HEX`: one APPROVAL/v2 bypass per held payment (any bytes: `admit` refuses a bad one alone); `floor N`: the grant serial
      floor the host asserts (it may raise the stored floor, never lower it); `kfloor N`: the key-set epoch the host asserts
      (the highest any shard of the tenant has admitted: a head below it is refused); `keyset HEX` and `kstep DAY HEX`: the
      key-set chain the batch head is admitted from.  A batch with requests commits to them (`Gate.inputV6`, `Frame.ident`). -/
  grant : Option (List UInt8) := none
  release : Option (List UInt8) := none
  byps : List (List UInt8) := []
  floorIn : Option Nat := none
  kfloorIn : Option Nat := none
  keyset : Option (List UInt8) := none
  ksteps : List (Nat × List UInt8) := []
  done : List Decision := []
  checked : Nat := 0
  failed : Nat := 0
  expected : Option Nat := none
  /-- A checkpoint (`load`, `anchor` or a commit) precedes the next commit; else its read-set base is the declared sets'. -/
  sealed : Bool := false

/-- A declared snapshot and its pin, checked against the declared one. -/
def snapshot {α : Type} (st : St) (kind : String) (row : List String → Option α) (domain : String) (k : Nat)
    (fields : α → List (Nat × Nat)) : Option (Snapshot α × List UInt8) := do
  let (asOf, count, pin) ← st.snaps.lookup kind
  let s : Snapshot α := ⟨asOf, count, ← ((st.rows.filter (·.1 == kind)).toList.map (·.2)).mapM row⟩
  let h := BlindLedger.Semantic.sha3_512Quick (← Fast.pinBytes domain k fields s)   -- FAST: `pin_run_eq`
  guard (hexOf h == pin)
  pure (s, h.toList)

/-- A numeral: ASCII digits only (`String.toNat?` also takes `_` between digits). -/
def nat? (s : String) : Option Nat := if s.contains '_' then none else s.toNat?

def parseLine : List String → Option Line
  | [i, f, m, p, r, d, c, u, a] => do
    let (i, y) ← match i.splitOn ":" with | [i] => some (i, i) | [i, y] => some (i, y) | _ => none
    pure ⟨← nat? i, ← nat? y, ← parse [Flow.FFS_CYCLE, .FFS_CLAIM, .CAP_820] f, ← nat? m, ← nat? p,
      ← nat? r, ← nat? d, ← nat? c, ← nat? u, ← nat? a⟩
  | _ => none

/-- `req HEX`: one DECIDE-REQUEST/v1 (`Gate.decodeRequest`), and the lines Lean reads from it.  Refused when it does not
    decode or a ruled line does not map (`linesOf`), when the batch has `line` lines, when its payment is already in the
    batch, or when its tenant or program is not the batch's first request's. -/
def reqOf (x : ByteArray) : Option Req := do
  let r ← Gate.decodeRequest x.toList
  let ls ← (if r.flow.ruled then linesOf r else pure [])
  pure ⟨payNat r.programId r.paymentId, .ofModel r, ls, x⟩

def addReq (st : St) (h : String) : Option St := do
  let e ← reqOf (← unhexFast h)
  guard (st.batch.isEmpty && st.reqs.all fun o => o.q != e.q && o.r.tenantId == e.r.tenantId && o.r.programId == e.r.programId)
  pure { st with reqs := st.reqs.push e }

/-- The lines a commit decides: the `line` lines, or the lines of the requests `cov` accepts (a request no grant entry
    covers has none decided). -/
def St.lines (st : St) (cov : Req → Bool) : List Line :=
  if st.reqs.isEmpty then st.batch.toList.map (·.1) else (st.reqs.toList.filter cov).flatMap (·.ls)

def death (r : List String) : Option Death := match r.mapM nat? with
  | some [i, d] => some ⟨i, d⟩
  | _ => none

/-- A set plus the lines earlier commits added to it. -/
def grow (o : Option (Snapshot Line)) (xs : List Line) : Option (Snapshot Line) :=
  o.map fun s => { s with count := s.count + xs.length, entries := s.entries ++ xs }

/-- One kind's SNAPSHOT/v1 pin (zero if none; refused if zero) and READ-*/v2 slot (one slot of `reads`). -/
def readPin {α : Type} (d : String) (k : Nat) (f : α → List (Nat × Nat)) :
    Option (Snapshot α × List UInt8) → Option (List UInt8 × List UInt8)
  | none => some (Gate.zeroDigest, [0])
  | some (s, p) => do
    guard (p ≠ Gate.zeroDigest)
    let q ← Fast.pinBytes d k f s
    pure (p, 1 :: hB q)

def St.pin (st : St) : Pinned :=
  let dmf := snapshot st "dmf" death "RR/GATE/SNAPSHOT/v1" 1 Death.fields
  let pdeath := snapshot st "pdeath" death "RR/GATE/SNAPSHOT/v1" 2 Death.fields
  let excl := snapshot st "excl" (fun r => match r.mapM nat? with
    | some [i, a, b] => some ⟨i, a, b⟩
    | _ => none) "RR/GATE/SNAPSHOT/v1" 3 Exclusion.fields
  let span := snapshot st "span" (fun r => match r.mapM nat? with
    | some [m, p, a, b] => some ⟨m, p, a, b⟩
    | _ => none) "RR/GATE/SNAPSHOT/v1" 4 Span.fields
  let elig := snapshot st "elig" (fun r => match r.mapM nat? with
    | some [m, a, v, s, t] => some ⟨m, a, v, s, t⟩
    | _ => none) "RR/GATE/SNAPSHOT/v1" 7 Elig.fields
  { dmf, pdeath, excl, span, elig,
    released := snapshot st "released" parseLine "RR/GATE/RELEASED/v1" 5 Line.fields
    unresolved := snapshot st "unresolved" parseLine "RR/GATE/UNRESOLVED/v1" 6 Line.fields
    kinds := do pure [← readPin "RR/GATE/READ-DMF/v2" 1 Death.fields dmf, ← readPin "RR/GATE/READ-PROVIDER-DEATH/v2" 2 Death.fields pdeath,
      ← readPin "RR/GATE/READ-EXCLUSION/v2" 3 Exclusion.fields excl, ← readPin "RR/GATE/READ-ENROLLMENT/v2" 4 Span.fields span,
      ← readPin "RR/GATE/READ-ELIGIBILITY/v2" 7 Elig.fields elig] }

/-- The digest of the four reference-snapshot pins (death, provider death, exclusion, enrollment), each its declared
    64-byte pin (zero for a snapshot the frame did not declare or whose rows do not match their pin), in that order. -/
def factsDigest (p : Pinned) : List UInt8 :=
  let pin {α : Type} (o : Option (Snapshot α × List UInt8)) : List UInt8 := o.elim Gate.zeroDigest (·.2)
  hB ⟨(pin p.dmf ++ pin p.pdeath ++ pin p.excl ++ pin p.span).toArray⟩

/-- `grant HEX`: the bytes, non-empty; `Authority.admitGrant` reads them at commit. -/
def addGrant (st : St) (h : String) : Option St := do
  let x ← unhexFast h
  guard (x.size != 0)
  pure { st with grant := some x.toList }

/-- The (program, payment) a bypass names. -/
def bypKey (f : Authority.Frame) : Option (Bytes × Bytes) :=
  match f.a.body with
  | .bypass p q _ _ => some (p, q)
  | .grant .. => none

/-- `bypass HEX`: any bytes; whether they are an admissible bypass is decided at commit, and a bad one is refused alone. -/
def addBypass (st : St) (h : String) : Option St := do
  let x ← unhexFast h
  pure { st with byps := st.byps ++ [x.toList] }

/-- `floor N`: a grant serial floor (a u64). -/
def addFloor (st : St) (s : String) : Option St := do
  let n ← nat? s
  guard (n < 2 ^ 64)
  pure { st with floorIn := some n }

/-- `kfloor N`: a key-set epoch floor (a u32, the ratchet's epoch width). -/
def addKfloor (st : St) (s : String) : Option St := do
  let n ← nat? s
  guard (n < 2 ^ 32)
  pure { st with kfloorIn := some n }

def addKeyset (st : St) (h : String) : Option St := do
  let x ← unhexFast h
  guard (x.size != 0)
  pure { st with keyset := some x.toList }

def addKstep (st : St) (d h : String) : Option St := do
  let n ← nat? d
  let x ← unhexFast h
  guard (x.size != 0)
  pure { st with ksteps := st.ksteps ++ [(n, x.toList)] }

/-- `release HEX`: a SHA3-512 digest. -/
def addRelease (st : St) (h : String) : Option St := do
  let x ← unhexFast h
  guard (x.size == 64)
  pure { st with release := some x.toList }

def St.ctx (st : St) (p : Pinned) : Ctx where
  today := st.today
  dmf := p.dmf.map (·.1)
  providerDeaths := p.pdeath.map (·.1)
  exclusions := p.excl.map (·.1)
  enrollment := p.span.map (·.1)
  eligibility := p.elig.map (·.1)
  released := grow (p.released.map (·.1)) st.extra
  unresolved := grow (p.unresolved.map (·.1)) st.held
  releasedPrior := st.rprior
  unresolvedPrior := st.uprior
  anchor := 0
  redo := st.redo

/-- The `k` low decimal digits of `r` (most significant first, zero-padded), then `acc`. -/
def lowDigits : Nat → Nat → List Char → List Char
  | 0, _, acc => acc
  | k + 1, r, acc => lowDigits k (r / 10) ((r % 10).digitChar :: acc)

/-- `toDigits 10 n ++ acc`, a big `n` cut into 18-digit blocks: no bignum division per digit. -/
def bigDigits (n : Nat) (acc : List Char) : List Char :=
  if h : n < 1000000000000000000 then Nat.toDigits 10 n ++ acc
  else bigDigits (n / 1000000000000000000) (lowDigits 18 (n % 1000000000000000000) acc)
termination_by n
decreasing_by omega

/-- `toString n` (`natStr_eq`), fast for the identifier numbers, which are far past a machine word: a request's line, payment, member and payee ids print in every answer line. -/
def natStr (n : Nat) : String :=
  if n < 1000000000000000000 then toString n else String.ofList (bigDigits n [])

private def digs : Nat → Nat → List Char
  | 0, _ => []
  | k + 1, r => digs k (r / 10) ++ [(r % 10).digitChar]

private theorem lowDigits_eq (k r : Nat) (acc : List Char) : lowDigits k r acc = digs k r ++ acc := by
  induction k generalizing r acc with
  | zero => rfl
  | succ k ih => simp [lowDigits, digs, ih]

private theorem toDigits_block (k q r : Nat) (hq : 0 < q) (hr : r < 10 ^ k) :
    Nat.toDigits 10 (q * 10 ^ k + r) = Nat.toDigits 10 q ++ digs k r := by
  induction k generalizing r with
  | zero => simp at hr; simp [hr, digs]
  | succ k ih =>
    have hp : 0 < 10 ^ k := Nat.pow_pos (by omega)
    have e : q * 10 ^ (k + 1) = 10 * (q * 10 ^ k) := by rw [Nat.pow_succ, Nat.mul_comm (10 ^ k) 10, Nat.mul_left_comm]
    have hqp : 0 < q * 10 ^ k := Nat.mul_pos hq hp
    have hpow : 10 ^ (k + 1) = 10 * 10 ^ k := by rw [Nat.pow_succ]; omega
    have h10 : 10 ≤ q * 10 ^ (k + 1) + r := by omega
    have h1 : (q * 10 ^ (k + 1) + r) / 10 = q * 10 ^ k + r / 10 := by omega
    have h2 : (q * 10 ^ (k + 1) + r) % 10 = r % 10 := by omega
    rw [Nat.toDigits_of_base_le (by omega) h10, h1, h2, ih (r / 10) (by rw [hpow] at hr; omega)]
    simp [digs]

private theorem bigDigits_eq (n : Nat) (acc : List Char) : bigDigits n acc = Nat.toDigits 10 n ++ acc := by
  induction n using Nat.strongRecOn generalizing acc with
  | _ n ih =>
    unfold bigDigits
    split
    · rfl
    · rename_i h
      have hq : 0 < n / 1000000000000000000 := by omega
      rw [ih _ (by omega), lowDigits_eq]
      have := toDigits_block 18 (n / 1000000000000000000) (n % 1000000000000000000) hq (by omega)
      have e : n / 1000000000000000000 * 10 ^ 18 + n % 1000000000000000000 = n := by omega
      rw [e] at this
      rw [this, List.append_assoc]

theorem natStr_eq (n : Nat) : natStr n = toString n := by
  unfold natStr
  split
  · rfl
  · rw [bigDigits_eq, List.append_nil]; rfl

def lineText (l : Line) : String :=
  s!"{natStr l.id}:{natStr l.pay} {name l.flow} {natStr l.member} {natStr l.payee} {natStr l.rendering} {natStr l.date} {natStr l.proc} {natStr l.units} {natStr l.cents}"

/-- Every field fits its stored width (`Line.fields`, `be`): the line has `RULES_ADDS` bytes and a digest. -/
def fits (l : Line) : Bool := l.fields.all fun (w, n) => n < 256 ^ w

/-- The pays with a line that does not fit: held whole, before the rules, in no set (their cash stays unallocated). -/
def unfit (ls : List Line) : Std.HashSet Nat := Std.HashSet.ofList ((ls.filter (!fits ·)).map (·.pay))

/-- The lines the rules decide: those of pays with no unfit line. -/
def keep (ls : List Line) : List Line := let qs := unfit ls; ls.filter fun l => !qs.contains l.pay

def sorted (xs : List String) : List String := xs.mergeSort fun a b => decide (a < b) || a == b

/-- The answer to each line of a held pay, sorted (arrival order changes no answer): the unfit line by name, its
    siblings by their pay. -/
def quarantined (ls : List Line) : List String := let qs := unfit ls
  sorted ((ls.filter fun l => qs.contains l.pay).map fun l =>
    lineText l ++ if fits l then " HOLD UNENCODABLE_PAYMENT" else " HOLD UNENCODABLE_FIELD")

/-- The rules decide only lines that fit, and no line of a pay with an unfit line: such a pay is never released or
    held in a set, and the batch keeps its `RULES_ADDS` and digest. -/
theorem keep_fits (ls : List Line) (l : Line) (h : l ∈ keep ls) :
    fits l = true ∧ ∀ m ∈ ls, m.pay = l.pay → fits m = true := by
  simp only [keep, List.mem_filter] at h
  have hm : ∀ m ∈ ls, m.pay = l.pay → fits m = true := fun m hm hp => by
    cases hf : fits m
    · have : (unfit ls).contains l.pay = true := by
        simp only [unfit, Std.HashSet.contains_ofList, List.contains_iff_mem, List.mem_map, List.mem_filter]
        exact ⟨m, ⟨hm, by simp [hf]⟩, hp⟩
      simp [this] at h
    · rfl
  exact ⟨hm l h.1 rfl, hm⟩

/-- `REPORT` counts the held lines too, as HOLD with no reason (a waiting line is in no tally). -/
def heldDecisions (ls : List Line) : List Decision := let qs := unfit ls
  (ls.filter fun l => qs.contains l.pay).map fun l => ⟨l, .HOLD, [], []⟩

/-- The batch rule, in one place: the outcome a payment's token carries.  A payment with a line that does not fit is
    HOLD; any other is `out p`, its lines' combined outcome (`payOutcome`: ALLOW only when every line is ALLOW). -/
def leafOutcome (out : Nat → Outcome) (unfit : Nat → Bool) (p : Nat) : Outcome := if unfit p then .HOLD else out p

/-- The reason codes a payment's token carries: every reason of its decided lines, sorted, each once (UNENCODABLE_PAYMENT
    for a payment with a line that does not fit); `-` for none. -/
def leafReasons (ds : List Decision) (unfit : Nat → Bool) (p : Nat) : String :=
  let rs := if unfit p then ["UNENCODABLE_PAYMENT"]
    else (sorted ((ds.filter (·.line.pay == p)).flatMap fun d => d.reasons.map name)).eraseDups
  if rs.isEmpty then "-" else ",".intercalate rs

/-- A payment's leaf as the worker prints it: the batch rule's outcome and reasons, the authority of the grant entry that
    covers its program and flow, that grant's id, and the id of the one admitted bypass that released it (zero if none). -/
structure Pay where
  q : Nat
  outcome : Outcome
  reasons : String
  authority : Gate.Authority
  grantId : Bytes
  bypass : Bytes

/-- At HOLD level, a payment the rules do not allow is allowed when the entry's holds mask lifts it (`Rules.lifts`: it has
    decided lines and every reason is bypassable and not named); the reasons stay on the leaf, and its lines join the
    released set (`Rules.limitedPay`, with `limOf`).  A payment with no lines (a flow the rules do not decide) and every
    other level keep the rules' outcome, and so does a re-decision (`r`: a payment released before), as in
    `Rules.limitedPay`. -/
def limited (en : Authority.Entry) (r : Bool) (ds : List Decision) (p : Nat) (o : Outcome) : Outcome :=
  if en.authority == .HOLD && !r && lifts en.holds ds p o then .ALLOW else o

/-- `emit` with the payment outcome `out`, the bypass test `byd` and the re-decision test `rdo` given (the worker passes
    the fast index's, equal to the Spec's).  None when no grant entry covers the request's program and flow. -/
def emitWith (hsh : Bytes → Bytes) (g : Authority.Grant) (bps : List Authority.Bypass) (out : Nat → Outcome)
    (byd rdo : Nat → Bool) (ds : List Decision) (unf : Nat → Bool) (e : Req) : Option Pay := do
  let en ← Authority.entryFor g e.r.programId e.r.flow
  let bp : Bytes := match bps.filter (fun b => b.program == e.r.programId && b.payment == e.r.paymentId) with
    | [b] => if !unf e.q && byd e.q && b.request == hsh e.x.toList && b.id != Gate.zeroDigest then b.id else Gate.zeroDigest
    | _ => Gate.zeroDigest
  let o := if unf e.q then Outcome.HOLD else if bp != Gate.zeroDigest then .ALLOW else limited en (rdo e.q) ds e.q (out e.q)
  pure ⟨e.q, o, leafReasons ds unf e.q, en.authority, g.id, bp⟩

def emit (hsh : Bytes → Bytes) (g : Authority.Grant) (bps : List Authority.Bypass) (c : Ctx) (ds : List Decision)
    (unf : Nat → Bool) (e : Req) : Option Pay :=
  emitWith hsh g bps (payOutcome c ds) (bypassed c ds) c.redo.contains ds unf e

/-! ### Admission at commit -/

/-- The floor a frame asserts: the stored one, or the frame's if not below it (a lowered floor would re-admit a revoked grant). -/
def effFloor (stored : Nat) : Option Nat → Option Nat
  | none => some stored
  | some n => if n < stored then none else some n

/-- The authority a request frame admits: the grant, the admitted bypasses, the ratchet and key-set digest the batch head
    gives, and the `RULES_BYPASS` lines of the bypasses not admitted (`-` for the payment of bytes that are no bypass). -/
structure Admitted where
  grant : Authority.Grant
  byps : List Authority.Bypass
  ratchet : Keyset.Ratchet
  ksDigest : Bytes
  notes : List String

/-- The leaf of a request no grant entry covers: reason SCOPE, no authority; HOLD for a ruled flow, HUMAN_REVIEW for one
    with no rules (the token format requires it).  Only this request's row is held; the rest of the frame proceeds, and
    its lines are not decided (`St.lines`). -/
def uncovered (g : Authority.Grant) (e : Req) : Pay :=
  ⟨e.q, if e.r.flow.ruled then .HOLD else .HUMAN_REVIEW, "SCOPE", .OBSERVE, g.id, Gate.zeroDigest⟩

/-- The bypasses of one batch that are read; each later one is refused alone (TOO_MANY) without a signature check. -/
def maxBypasses : Nat := 64

/-- Admits the batch head from the stored ratchet `rat` and genesis `pin` (an epoch below the frame's `kfloor` is
    STALE_KEYSET), then the grant (against the batch's
    tenant, the first request's, and the floor), then each bypass, alone: the bytes are no bypass or are not signed
    (the cause of `Authority.admitBypassR`), it is past the first `maxBypasses` (TOO_MANY), two admitted ones name one payment for one request (both DUPLICATE), the payment is not a
    request of the frame (NOT_IN_BATCH), is re-decided (REDO), or its covering entry does not let it transfer (SCOPE).
    A refused bypass releases nothing and the rest of the frame is decided.  `error why`: the frame is refused (`RULES_GRANT_HOLD why`). -/
def admit (verify : Bytes → Bytes → Bytes → Bool) (pin : Bytes) (rat : Keyset.Ratchet) (stored : Nat) (st : St) :
    Except String Admitted :=
  match st.reqs[0]?, st.grant, st.keyset with
  | some e0, some gx, some ks =>
    match SnapshotV2.admitBatchHead verify pin st.today rat ks st.ksteps with
    | none => .error "HEAD"
    | some (H, rat') =>
      if !(st.kfloorIn.all (· ≤ rat'.epoch)) then .error "STALE_KEYSET" else
      match effFloor stored st.floorIn with
      | none => .error "FLOOR"
      | some fl =>
        match Authority.admitGrant verify H e0.r.tenantId fl gx with
        | .error r => .error (name r)
        | .ok g =>
          let xfer (b : Authority.Bypass) : Bool := st.reqs.any fun e => e.r.programId == b.program && e.r.paymentId == b.payment &&
            (Authority.entryFor g e.r.programId e.r.flow).any (·.authority == .TRANSFER)
          let signed := (st.byps.take maxBypasses).map fun x => (x, Authority.admitBypassR verify H e0.r.tenantId x)
          let once (b : Authority.Bypass) : Bool := (signed.filter fun (_, r) => match r with
            | .ok c => c.program == b.program && c.payment == b.payment && c.request == b.request
            | .error _ => false).length == 1
          let judge (b : Authority.Bypass) : Except String Authority.Bypass :=
            if !once b then .error "DUPLICATE"
            else if !st.reqs.any (fun e => e.r.programId == b.program && e.r.paymentId == b.payment) then .error "NOT_IN_BATCH"
            else if st.redo.contains (payNat b.program b.payment) then .error "REDO"
            else if !xfer b then .error "SCOPE" else .ok b
          let rs := signed.map fun (x, r) => match r with
            | .ok b => (some (payNat b.program b.payment), judge b)
            | .error w => (((Authority.decode x).bind bypKey).map fun (p, q) => payNat p q, Except.error (name w))
          let rs := rs ++ (st.byps.drop maxBypasses).map fun x =>
            (((Authority.decode x).bind bypKey).map fun (p, q) => payNat p q, Except.error "TOO_MANY")
          .ok ⟨g, rs.filterMap (·.2.toOption), rat', Keyset.digestOf H.ks,
            rs.filterMap fun (n, b) => match b with
              | .ok _ => none
              | .error why => some s!"RULES_BYPASS {(n.map natStr).getD "-"} {why}"⟩
  | _, _, _ => .error "MISSING"

/-- The admitted bypasses `emit` reads for request `e`: those for its payment that were signed for this very request.  A valid
    bypass for an earlier request of the payment is left out, so it cannot hide the right one. -/
def bypsFor (hsh : Bytes → Bytes) (bps : List Authority.Bypass) (e : Req) : List Authority.Bypass :=
  (bps.filter fun b => b.program == e.r.programId && b.payment == e.r.paymentId).filter fun b => b.request == hsh e.x.toList

/-- The (payment number, override mask) of each admitted bypass whose request digest is the frame request's (`Ctx.byp`). -/
def bypOf (hsh : Bytes → Bytes) (bps : List Authority.Bypass) (reqs : List Req) : List (Nat × Nat) :=
  bps.filterMap fun b =>
    (reqs.find? fun e => e.q == payNat b.program b.payment && b.request == hsh e.x.toList).map fun e => (e.q, b.overrides)

/-- The (payment number, holds mask) of each request whose covering grant entry is HOLD-level (`Ctx.lim`). -/
def limOf (g : Authority.Grant) (reqs : List Req) : List (Nat × Nat) :=
  reqs.filterMap fun e => (Authority.entryFor g e.r.programId e.r.flow).bind fun en =>
    if en.authority == .HOLD then some (e.q, en.holds) else none

/-- `RULES_BYPASS` for an admitted bypass that releases nothing: its request digest is not the frame's, or the frame's payment is not one the bypass
    releases (not held for it, or already allowed). -/
def bypNotes (hsh : Bytes → Bytes) (bps : List Authority.Bypass) (reqs : List Req) (byd : Nat → Bool) :
    List String :=
  bps.filterMap fun b => (reqs.find? fun e => e.r.programId == b.program && e.r.paymentId == b.payment).bind fun e =>
    if b.request != hsh e.x.toList then some s!"RULES_BYPASS {natStr e.q} WRONG_REQUEST"
    else if !byd e.q then some s!"RULES_BYPASS {natStr e.q} NOT_HELD" else none

/-- A token says ALLOW only for a payment with no unfit line whose every decided line is ALLOW. -/
theorem leafOutcome_allow {c : Ctx} {ds : List Decision} {u : Nat → Bool} {p : Nat}
    (h : leafOutcome (payOutcome c ds) u p = .ALLOW) :
    u p = false ∧ ∀ d ∈ ds, d.line.pay = p → d.outcome = .ALLOW := by
  unfold leafOutcome payOutcome at h
  cases hu : u p
  · refine ⟨rfl, fun d hd hp => ?_⟩
    simp only [hu, Bool.false_eq_true, if_false] at h
    by_cases hh : (ds.filter (·.line.pay == p)).any (·.outcome == .HOLD) = true
    · simp [hh] at h
    · by_cases ha : (!(ds.filter (·.line.pay == p)).isEmpty && (ds.filter (·.line.pay == p)).all fun d =>
          d.outcome == .ALLOW && (!c.redo.contains p || own c d.line)) = true
      · simp only [Bool.and_eq_true, List.all_eq_true, List.mem_filter, beq_iff_eq] at ha
        exact (by simpa using (ha.2 d ⟨hd, by simp [hp]⟩) : d.outcome = .ALLOW ∧ _).1
      · simp [hh] at h
        obtain ⟨_, _, _, hall⟩ := h
        exact (hall d hd hp).1
  · simp [hu] at h

-- Cents 2^64 holds its pay whole, the sibling by its pay; the other pay is the rules' alone.
#guard
  let a : Line := ⟨1, 1, .FFS_CLAIM, 1, 4, 5, 20270310, 99213, 1, 9200⟩
  let ls := [{ a with id := 2, cents := 2 ^ 64 }, a, { a with id := 3, pay := 2 }]
  (keep ls).map (·.id) == [3] && quarantined ls ==
    ["1:1 FFS_CLAIM 1 4 5 20270310 99213 1 9200 HOLD UNENCODABLE_PAYMENT",
     "2:1 FFS_CLAIM 1 4 5 20270310 99213 1 18446744073709551616 HOLD UNENCODABLE_FIELD"]

def render (d : Decision) : String :=
  let rs := if d.reasons.isEmpty then "-" else ",".intercalate (d.reasons.map name)
  let w := if d.counterparts.isEmpty then "" else s!" with={",".intercalate (d.counterparts.map natStr)}"
  s!"{lineText d.line} {name d.outcome} {rs}{w}"

def money (cents : Nat) : String :=
  let c := toString (cents % 100)
  s!"${cents / 100}.{if c.length < 2 then "0" ++ c else c}"

def tally (ds : List Decision) : String :=
  let c := ds.foldl (· + ·.line.cents) 0
  s!"lines={ds.length} cents={c} ({money c})"

/-- Each id once, first occurrence first: a batch may carry a payment once per request. -/
def uniq (ids : List Nat) : List Nat :=
  (ids.foldl (fun (s, r) i => if s.contains i then (s, r) else (s.insert i, i :: r))
    ((∅ : Std.HashSet Nat), ([] : List Nat))).2.reverse

/-- `RULES_READS`: u32 today ‖ the five SNAPSHOT/v1 pins ‖ u32 |P| ‖ P, P the READ-SET/v5 bytes over `base` (the five
    READ-*/v2 slots of `kinds`), redo in the order read. -/
def reads (p : Pinned) (c : Ctx) (base : List UInt8) : Option (List UInt8) := do
  let ks ← p.kinds
  let pre := "RR/GATE/READ-SET/v5".toUTF8.toList ++ [0] ++ (ks.map (·.2)).flatten ++ (← be 4 c.redo.length) ++
    (← c.redo.mapM (be payWidth)).flatten ++ base
  pure ((← be 4 c.today) ++ (ks.map (·.1)).flatten ++ (← be 4 pre.length) ++ pre)

def commit (st : St) (unanchored : Bool) (show_ : Bool := false) : St × List String :=
  let p := st.pinned.getD st.pin                        -- FAST: pin once per declaration
  let c := st.ctx p
  -- `Gate.decideAnchored`, with the twin deciding (`FastEq`): an unanchored batch decides nothing.
  let prior := if st.sealed || st.anchor.isSome then Memo.get st.memo c.releasedPrior c.unresolvedPrior else none
  if !st.anchor.all fun a => prior == some (Gate.natBE Gate.digestBytes a) then
    ({ st with pinned := some p, anchor := none, batch := #[], redo := [], pays := [],
               checked := st.checked + unanchored.toNat, failed := st.failed + (!unanchored).toNat },
     if unanchored then [] else ["RULES_UNANCHORED commit"])
  else
  let all := st.batch.toList.map (·.1)
  let lines := keep all
  let b := lines
  let x := Fast.Ix.build c b                            -- FAST
  let r := x.runIn [] b                                 -- FAST: = decideBatchIn c [] b
  let exp := st.batch.toList.filterMap (·.2)
  let got := r.decisions.map render ++ quarantined all
  let bad := st.pays.filter fun (q, o) => name (if (unfit all).contains q then .HOLD else x.payOutcome r.decisions q) != o
  let (ok, n, msg) :=
    if exp.isEmpty then (true, 0, [])                   -- FAST: no reversed re-run
    else if exp.length == all.length && sorted exp == sorted got then (true, all.length, [])
    else (false, 0, ((sorted got).filter (!exp.contains ·)).map ("RULES_GOT " ++ ·))
  let ok := ok && bad.isEmpty && !unanchored
  let msg := msg ++ bad.map (fun (q, o) => s!"RULES_PAY {q} expected={o}") ++
    (if unanchored then ["RULES_ANCHORED commit"] else [])
  let fresh := (r.released.entries.drop x.relN, r.unresolved.entries.drop x.unrN)
  let adds := do pure (((← fresh.1.mapM (rowBytesFast 1)) ++ (← fresh.2.mapM (rowBytesFast 2))).foldl (· ++ ·) ByteArray.empty)
  -- The checkpoint extended; before the first, the declared sets (pins from declaration) or the empty priors.
  let pinOf (o : Option (Snapshot Line × List UInt8)) (d : String) (k : Nat) (s : Snapshot Line) :=
    o.elim ((Fast.pinBytes d k Line.fields s).map hB) (some ·.2)
  let base := if st.sealed then prior else do
    pure (Gate.stateDigest (fun x => hB ⟨x.toArray⟩) (← pinOf p.released "RR/GATE/RELEASED/v1" 5 c.releasedPrior)
      (← pinOf p.unresolved "RR/GATE/UNRESOLVED/v1" 6 c.unresolvedPrior))
  let shown := if !show_ then [] else got.map ("RULES_LINE " ++ ·) ++
    (Fast.setsDigestF hB r.released r.unresolved).toList.map (fun d => s!"RULES_DIGEST {hexOf d.toByteArray}") ++
    adds.toList.map (fun b => s!"RULES_ADDS {hexOf b}") ++
    (base.bind (reads p c)).toList.map fun b => s!"RULES_READS {hexOf b.toByteArray}"
  ({ st with pinned := some p, anchor := none, sealed := true,
             extra := st.extra ++ fresh.1,                            -- FAST: `run_relN`
             held := st.held ++ fresh.2,
             rprior := r.released, uprior := r.unresolved, batch := #[], redo := [], pays := [],
             done := st.done ++ r.decisions ++ heldDecisions all, checked := st.checked + (if ok then n + st.pays.length else 0),
             failed := st.failed + (if ok then 0 else 1) },
   shown ++ if ok then [] else "RULES_VECTOR_MISMATCH commit" :: msg)

/-- `load` with the adds stream `bs` already decoded (`loadparts` hands it over without a hex field). -/
def loadBytes (st : St) (a : String) (bs : ByteArray) (h : String) : Option (St × List String) := do
  guard (h.length == 128)
  let g : Snapshot Line := ⟨← nat? a, 0, []⟩
  let anchor := Gate.beNat (← unhexFast h).toList
  -- `Gate.ShardState.loadAdds`, with the fast digest (`Fast.setsDigestF_eq`)
  match (parseAdds bs).bind fun ad => (fun (s : Snapshot Line × Snapshot Line) =>
      (Memo.mk s.1 s.2 _ rfl).d.bind fun d =>
        if d == Gate.natBE Gate.digestBytes anchor then some (s, Memo.mk s.1 s.2 _ rfl) else none) (Rules.replay (g, g) [ad]) with
  | none => pure ({ st with failed := st.failed + 1 }, ["RULES_STATE_MISMATCH load"])
  | some (s, m) => pure ({ st with
      snaps := ("released", g.asOf, 0, ← emptyPin "released" g.asOf) :: ("unresolved", g.asOf, 0, ← emptyPin "unresolved" g.asOf) :: st.snaps,
      rows := st.rows.filter fun r => r.1 != "released" && r.1 != "unresolved", pinned := none, anchor := none,
      extra := s.1.entries, held := s.2.entries, rprior := s.1, uprior := s.2, sealed := true, memo := some m }, [])

def step (st : St) : List String → Option (St × List String)
  | ["case", _] => pure ({ st with extra := [], held := [], rprior := ⟨0, 0, []⟩, uprior := ⟨0, 0, []⟩,
                                   anchor := none, batch := #[], redo := [],
                                   pays := [], reqs := #[], done := [], sealed := false }, [])
  | ["anchor", h] => do
    guard (h.length == 128)
    pure ({ st with sealed := true, anchor := some (← h.toList.foldlM (fun n x => (n * 16 + ·) <$> "0123456789abcdef".toList.idxOf? x) 0) }, [])
  | ["load", a, adds, h] => do
    loadBytes st a (← if adds == "-" then pure ByteArray.empty else unhexFast adds) h   -- `-` is zero rows (the field cannot be empty)
  | ["today", d] => do
    let n ← nat? d
    guard (n < 2 ^ 64)                                  -- INPUT/v4 carries `today` in eight bytes
    pure ({ st with today := n }, [])
  | ["snap", k, a, n, pin] => do
    pure ({ st with snaps := (k, ← nat? a, ← nat? n, pin) :: st.snaps, rows := st.rows.filter (·.1 != k),
                    pinned := none,
                    extra := if k == "released" then [] else st.extra,
                    held := if k == "unresolved" then [] else st.held }, [])
  | ["drop", k] => pure ({ st with snaps := st.snaps.filter (·.1 != k), pinned := none }, [])
  | "line" :: fs => do
    guard st.reqs.isEmpty
    let l ← parseLine (fs.take 9)
    let e := fs.drop 9
    guard ([0, 2, 3].contains e.length)
    pure ({ st with batch := st.batch.push (l, if e.isEmpty then none else some (" ".intercalate (lineText l :: e))) }, [])
  | ["redo", p] => do   -- a pay too wide to encode is in no set, so a redo of it changes nothing (and `reads` would refuse)
    let q ← nat? p
    pure ({ st with redo := if q < 256 ^ payWidth then q :: st.redo else st.redo }, [])
  | ["pay", p, o] => do pure ({ st with pays := st.pays ++ [(← nat? p, o)] }, [])
  | ["commit"] => if st.reqs.isEmpty then pure (commit st false) else none   -- requests: the flat commit only
  | ["commit", "SHOW"] => if st.reqs.isEmpty then pure (commit st false true) else none
  | ["commit", "UNANCHORED"] => if st.reqs.isEmpty then pure (commit st true) else none
  | ["report"] =>
    let by_ (p : Decision → Bool) := tally (st.done.filter p)
    pure (st, s!"REPORT all {by_ fun _ => true}" ::
      ([Outcome.ALLOW, .HOLD, .HUMAN_REVIEW].map fun o => s!"REPORT {name o} {by_ (·.outcome == o)}") ++
      reasons.map fun r => s!"REPORT {name r} {by_ (·.reasons.contains r)}")
  | ["end", n] => do pure ({ st with expected := some (← nat? n) }, [])
  | k :: fs => do
    guard (["dmf", "pdeath", "excl", "span", "elig", "released", "unresolved"].contains k)
    pure ({ st with rows := st.rows.push (k, fs), pinned := none }, [])
  | [] => none

/-- The vector lines through `stp`, numbered from 1; blank and `#` lines skipped. -/
def runLoop {σ : Type} (stp : σ → List String → Option (σ × List String)) (get : σ → St) (bump : σ → σ) :
    List String → Nat → σ → Array String → σ × Array String
  | [], _, s, out => (s, out)
  | raw :: rest, n, s, out =>
    let n := n + 1
    let fs := fieldsFast raw
    if fs.isEmpty || fs.head!.startsWith "#" then runLoop stp get bump rest n s out
    else match stp s fs with
      | none => runLoop stp get bump rest n (bump s) (out.push s!"RULES_VECTOR_MALFORMED line={n}")
      | some (next, ls) => runLoop stp get bump rest n next
          ((if (get next).failed > (get s).failed then out.push s!"RULES_VECTOR_FAIL line={n}" else out) ++ ls)

/-- The loop over any step state `σ` (its `St` by `get`, a malformed line by `bump`): the output, whether it passed, and
    the final state.  `runWith` is `step` on `St`; the resident worker runs it on its `Worker`. -/
def runOn {σ : Type} (stp : σ → List String → Option (σ × List String)) (get : σ → St) (bump : σ → σ) (s0 : σ)
    (text : String) : Array String × Bool × σ :=
  let (s, out) := runLoop stp get bump (splitC text '\n') 0 s0 #[]
  let st := get s
  let pass := st.failed == 0 && st.expected == some st.checked
  (out.push s!"RULES_VECTORS={if pass then "PASS" else "FAIL"} checked={st.checked} expected={st.expected.getD 0} failed={st.failed}", pass, s)

def runWith (text : String) : Array String × Bool × St :=
  runOn step id (fun st => { st with failed := st.failed + 1 }) {} text

/-- The vector text through the rules: the output lines and whether it passed.  Each text starts from the empty state;
    `gate_rules` runs it on a vector file. -/
def runText (text : String) : Array String × Bool := let r := runWith text; (r.1, r.2.1)

/-! Long-lived worker, the shape of `Financial.WorkerCli`: each stdin frame is a u32 BE length and
    a vector text, each stdout frame a u32 BE length and the lines `frame` returns for it (`serve` threads its state `s`
    across frames; the profile tool passes a stateless `runText`, `Engine.OneProc` has its own tagged loop).  Clean end of input exits 0; a short, oversize
    or non-UTF-8 frame, or an answer past the cap, exits 65 without output. -/

def maxFrame : Nat := 64 * 1024 * 1024

/-- `n` bytes from `read`, fewer only at end of input.  Fuel `n + 1` always suffices (each round that goes on read at least
    one byte, so `acc` reaches `n` within `n` rounds); running out of fuel gives `none`, which callers exit on, never an answer. -/
def readN (read : USize → IO ByteArray) (n : Nat) (acc : ByteArray := .empty) : Nat → IO (Option ByteArray)
  | 0 => return none
  | fuel + 1 => do
    if acc.size ≥ n then return some acc
    let b ← read (min (n - acc.size) 1048576).toUSize
    if b.size = 0 then return some acc else readN read n (acc ++ b) fuel

partial def serve {σ : Type} (frame : σ → String → Array String × σ) (s : σ) (read : USize → IO ByteArray)
    (write : ByteArray → IO Unit) : IO UInt32 := do
  let some h ← readN read 4 .empty 5 | return 66
  if h.size = 0 then return 0
  let n := h.foldl (fun a b => a * 256 + b.toNat) 0
  if h.size < 4 || n > maxFrame then return 65
  let some f ← readN read n .empty (n + 1) | return 66
  if f.size < n then return 65
  let some text := String.fromUTF8? f | return 65
  let (out, s) := frame s text
  let resp := (String.join (out.toList.map (· ++ "\n"))).toUTF8
  if resp.size > maxFrame then return 65
  write (ByteArray.mk #[(resp.size >>> 24).toUInt8, (resp.size >>> 16).toUInt8, (resp.size >>> 8).toUInt8, resp.size.toUInt8] ++ resp)
  serve frame s read write

end BlindLedger.Gate.Rules.Run
