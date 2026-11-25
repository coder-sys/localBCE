import BlindLedger.Gate.Flat.Model
import BlindLedger.Gate.Rules.Run
import BlindLedger.Gate.Flat.Bin

/-! The binary frames between the host and the rules engine (formats conformance/FRAME_V1.md).

    Host to engine: one request per batch, a fixed header (magic `RRDQ`, version, shard, batch number, the SHA3-512 of
    the body under `dom FRAME2`) and a body of fixed-width little-endian sections: the context (today, the genesis date,
    the signed head the batch follows, four feed descriptors with their pins), the feed rows, the redone payments and
    the authority section (the shard's pin, grant, key set, signed bypasses, release and the payment requests, each as
    the bytes the state delivered them).  The lines a batch is decided on are not sent: the engine reads them from the
    signed request bytes (`Run.reqOf`), so a product identifier is never encoded twice.  The engine alone derives the
    bypasses from the signed bypass requests.  A bad header, length or record refuses the whole frame; the engine
    carries the digest and does not recompute it, the checker does.

    Engine to host: one answer per request, a fixed header (magic `RRDA`, version, status, shard, batch, record count,
    the request's digest; answer header version 4) and, when decided, one 20-byte record per decided line (position
    among the decided lines, outcome, rule, reasons as a u64 bitmask with reason `r` at bit `r.idx`, the counterpart's
    store position), the chain head and the state root after the batch, and the extension (grant refusal, bypass notes, token leaves, the rows appended).
    Everything today's text answer carried that the record does not is recomputed by `join` from the record, the frame
    and the store state before the batch; `Ans.text` is the human text, produced on demand.

    `H` is SHA3-512 at runtime; statements take it as a parameter.
    Synthetic, nonpayment, non-PHI, activation=false. -/

namespace BlindLedger.Gate.Frame

open BlindLedger.Gate.Rules BlindLedger.Gate.Rules.Fast BlindLedger.Gate.Flat

/-! ## Fixed-width little-endian numbers -/

/-- `n` as `w` little-endian bytes, `none` if it does not fit. -/
def le (w n : Nat) : Option Bytes :=
  if n < 256 ^ w then some ((List.range w).map fun i => (n / 256 ^ i % 256).toUInt8) else none

def unle (bs : Bytes) : Nat := bs.foldr (fun b n => b.toNat + 256 * n) 0

/-! ## Refusal words (the answer's status byte is the index in `words`) -/

inductive Word
  | OK | MAGIC | LENGTH | DIGEST | RECORD | NOT_NEXT | CONFLICT | HEAD | SHARD
  | LOCK | FILES | IMAGE | REPLAY | IO | CORRUPT | INIT | KILL | NUMBER | FULL | TREE | FRAME | PIN
  deriving DecidableEq, Repr

def words : List Word :=
  [.OK, .MAGIC, .LENGTH, .DIGEST, .RECORD, .NOT_NEXT, .CONFLICT, .HEAD, .SHARD,
   .LOCK, .FILES, .IMAGE, .REPLAY, .IO, .CORRUPT, .INIT, .KILL, .NUMBER, .FULL, .TREE, .FRAME, .PIN]

def Word.code (w : Word) : Nat := words.idxOf w

/-! ## The request -/

/-- A feed as sent.  `state` 0: absent; 1: these rows, checked against `pin`; 2: a row the host could not encode (the
    feed counts as missing).  States 0 and 2 carry zeros and no rows. -/
structure Feed (α : Type) where
  state : Nat
  asOf : Nat
  count : Nat
  rows : List α
  pin : Bytes

/-- A feed row's fields: their widths, the values of a row, and the row of values. -/
structure RowCodec (α : Type) where
  widths : List Nat
  get : α → List Nat
  ofNums : List Nat → Option α

def dmfC : RowCodec Death := ⟨[33, 4], fun d => [d.id, d.date], fun | [i, d] => some ⟨i, d⟩ | _ => none⟩
def pdeathC : RowCodec Death := ⟨[21, 4], fun d => [d.id, d.date], fun | [i, d] => some ⟨i, d⟩ | _ => none⟩
def exclC : RowCodec Exclusion :=
  ⟨[21, 4, 4], fun e => [e.id, e.start, e.stop], fun | [i, a, b] => some ⟨i, a, b⟩ | _ => none⟩
def spanC : RowCodec Span :=
  ⟨[33, 21, 4, 4], fun s => [s.member, s.plan, s.start, s.stop], fun | [m, p, a, b] => some ⟨m, p, a, b⟩ | _ => none⟩

/-- The authority a batch carries: the key-set genesis pin (checked against the store's at every batch), the asserted
    grant floor, the asserted key-set epoch floor (`kfloor`, a u32; zero asserts none), the asserted rule-set floor
    (`rsv`, a u32, and the digest `rs` of the record at that version; 0 and `zeroDigest` assert none), the signed
    grant, key set and key-set steps, the signed bypasses, the signed rule-set records the batch presents (`rsets`,
    conformance/RULESET_V1.md section 9), the engine release and the payment requests, each as the bytes the state
    delivered them (`Run.Req.x`). -/
structure Auth where
  pin : Bytes
  floor : Option Nat
  kfloor : Nat
  rsv : Nat
  rs : Bytes
  grant : Bytes
  keyset : Bytes
  release : Bytes
  ksteps : List (Nat × Bytes)
  byps : List Bytes
  rsets : List Bytes
  reqs : List Run.Req

structure Req where
  shard : Nat
  batch : Nat
  today : Nat
  /-- The sets' genesis date: read at batch 1 only, zero otherwise. -/
  asOf : Nat
  /-- The signed chain head the batch follows (the genesis head at batch 1). -/
  prev : Bytes
  dmf : Feed Death
  pdeath : Feed Death
  excl : Feed Exclusion
  span : Feed Span
  redo : List Nat
  auth : Auth

/-- What the engine derives from the signed bytes of a request (admission, `Run.admit`): the lines it decides, in frame
    order (`Run.St.lines`), the admitted bypasses' and cause records' pairs, payment number and override mask (`FCtx.byp`,
    `Run.approvals`), and the
    payments under a HOLD-level grant entry, payment number and holds mask (`FCtx.lim`, `Run.limOf`). -/
structure Derived where
  lines : List Line
  byp : List (Nat × Nat)
  lim : List (Nat × Nat)

structure Hdr where
  shard : Nat
  batch : Nat
  digest : Bytes
  deriving DecidableEq, Repr

def magicReq : Bytes := "RRDQ".toUTF8.toList
def magicAns : Bytes := "RRDA".toUTF8.toList
/-- The answer header's version.  4: u64 reason fields with reason `r` at bit `r.idx` and the leaf-only codes at bits 62
    and 63 (version 1 had u32 fields numbered by place in `reasons`; 3 is the fact answer's, `FactFrame.ansVersion`). -/
def version : Nat := 4
/-- The request header's version.  2: the digest is `frameDigest`, which the engine carries and does not recompute. -/
def reqVersion : Nat := 2
def hdrBytes : Nat := 82
def ansHdrBytes : Nat := 87

/-! ### Encode (`none`: a value does not fit, or the request is not canonical) -/

def leAll (ws ns : List Nat) : Option Bytes := do
  guard (ws.length = ns.length)
  ((ws.zip ns).mapM fun (w, n) => le w n).map List.flatten

def encFeed {α : Type} (c : RowCodec α) (f : Feed α) : Option (Bytes × Bytes) := do
  guard (f.state ≤ 2 && f.pin.length == 64 &&
    (f.state == 1 || (f.asOf == 0 && f.count == 0 && f.rows.isEmpty && f.pin == zeroDigest)))
  let d ← leAll [1, 4, 4, 4] [f.state, f.asOf, f.count, f.rows.length]
  let rows ← f.rows.mapM fun x => leAll c.widths (c.get x)
  pure (d ++ f.pin, rows.flatten)

/-- A length (`u32`) and then the bytes. -/
def blob (b : Bytes) : Option Bytes := do pure ((← le 4 b.length) ++ b)

def encAuth (a : Auth) : Option Bytes := do
  guard (a.pin.length = 64 ∧ a.rs.length = 64)
  let f ← leAll [1, 8] [if a.floor.isSome then 1 else 0, a.floor.getD 0]
  let kf ← le 4 a.kfloor
  let v ← le 4 a.rsv
  let g ← blob a.grant
  let k ← blob a.keyset
  let r ← blob a.release
  let ks ← a.ksteps.mapM fun (d, b) => do pure ((← le 4 d) ++ (← blob b))
  let bs ← a.byps.mapM blob
  let ss ← a.rsets.mapM blob
  let rs ← a.reqs.mapM (blob ·.x.toList)
  pure (a.pin ++ f ++ kf ++ v ++ a.rs ++ g ++ k ++ r ++ (← le 4 a.ksteps.length) ++ ks.flatten ++ (← le 4 a.byps.length) ++
    bs.flatten ++ (← le 4 a.rsets.length) ++ ss.flatten ++ (← le 4 a.reqs.length) ++ rs.flatten)

def encodeBody (q : Req) : Option Bytes := do
  guard (q.prev.length = 64 && (q.batch == 1 || q.asOf == 0))
  let c ← leAll [4, 4] [q.today, q.asOf]
  let n ← le 4 q.redo.length
  let (d1, r1) ← encFeed dmfC q.dmf
  let (d2, r2) ← encFeed pdeathC q.pdeath
  let (d3, r3) ← encFeed exclC q.excl
  let (d4, r4) ← encFeed spanC q.span
  let rs ← q.redo.mapM (le payWidth)
  let au ← encAuth q.auth
  pure (c ++ q.prev ++ n ++ d1 ++ d2 ++ d3 ++ d4 ++ r1 ++ r2 ++ r3 ++ r4 ++ rs.flatten ++ au)

/-- `FRAME2/v1`'s preimage: the whole body of a request frame. -/
def framePre (body : Bytes) : Bytes := domain "FRAME2" ++ body

/-- The request frame's digest: one hash of the whole body.  The host computes it over the bytes it sends and the
    checker recomputes it over the bytes logged; the engine carries it into its answer. -/
def frameDigest (H : Bytes → Bytes) (body : Bytes) : Bytes := H (framePre body)

def encodeReq (H : Bytes → Bytes) (q : Req) : Option Bytes := do
  let body ← encodeBody q
  let h ← leAll [2, 4, 8] [reqVersion, q.shard, q.batch]
  pure (magicReq ++ h ++ frameDigest H body ++ body)

/-- The body of request frame `bs` before its request count: what `Gate.context` hashes. -/
def ctxBytes (bs : Bytes) (q : Req) : Bytes :=
  let body := bs.drop hdrBytes
  body.take (body.length - 4 - (q.auth.reqs.map fun e => 4 + e.x.size).sum)

/-- The batch's identity (III.3, the retry key): `BATCH-INPUT` over the context and each request's `INPUT/v7`, so a
    retry with the same payments has the same identity. -/
def ident (H : Bytes → Bytes) (bs : Bytes) (q : Req) : Bytes :=
  let c := Gate.context H (ctxBytes bs q)
  Gate.batchInput H c (q.auth.reqs.map fun e => Gate.inputV7 H c e.ra.toModel)

/-! ### Decode (fail closed: the first failure in byte order names the word) -/

/-- `n` bytes, else the body is short. -/
def cut (n : Nat) (bs : Bytes) : Except Word (Bytes × Bytes) :=
  match takeN n bs with
  | some p => .ok p
  | none => .error .LENGTH

def nums : List Nat → Bytes → Except Word (List Nat × Bytes)
  | [], r => .ok ([], r)
  | w :: ws, r => do
    let (a, r) ← cut w r
    let (as, r) ← nums ws r
    pure (unle a :: as, r)

def numRec (w : Nat) (bs : Bytes) : Except Word (Nat × Bytes) := do
  let (a, r) ← cut w bs
  pure (unle a, r)

def many {α : Type} (f : Bytes → Except Word (α × Bytes)) : Nat → Bytes → Except Word (List α × Bytes)
  | 0, r => .ok ([], r)
  | n + 1, r => do
    let (a, r) ← f r
    let (as, r) ← many f n r
    pure (a :: as, r)

def decodeHdr (bs : Bytes) : Except Word (Hdr × Bytes) := do
  let some (h, body) := takeN hdrBytes bs | throw .LENGTH
  unless h.take 4 == magicReq && unle ((h.drop 4).take 2) == reqVersion do throw .MAGIC
  pure (⟨unle ((h.drop 6).take 4), unle ((h.drop 10).take 8), h.drop 18⟩, body)

/-- A feed descriptor: state, asOf, count, rows; then the pin. -/
def desc (bs : Bytes) : Except Word ((Nat × Nat × Nat × Nat × Bytes) × Bytes) := do
  let ([st, a, c, n], r) ← nums [1, 4, 4, 4] bs | throw .RECORD
  let (pin, r) ← cut 64 r
  unless st ≤ 2 && (st == 1 || (a == 0 && c == 0 && n == 0 && pin == zeroDigest)) do throw .RECORD
  pure ((st, a, c, n, pin), r)

def feedRow {α : Type} (c : RowCodec α) (bs : Bytes) : Except Word (α × Bytes) := do
  let (ns, r) ← nums c.widths bs
  let some x := c.ofNums ns | throw .RECORD
  pure (x, r)

def feed {α : Type} (c : RowCodec α) (d : Nat × Nat × Nat × Nat × Bytes) (bs : Bytes) :
    Except Word (Feed α × Bytes) := do
  let (st, a, n, k, pin) := d
  let (rows, r) ← many (feedRow c) k bs
  pure (⟨st, a, n, rows, pin⟩, r)

def blobRec (bs : Bytes) : Except Word (Bytes × Bytes) := do
  let (n, r) ← numRec 4 bs
  cut n r

/-- A payment request: its bytes within the request bound, and as `Run.addReq` reads them. -/
def reqRec (bs : Bytes) : Except Word (Run.Req × Bytes) := do
  let (x, r) ← blobRec bs
  unless x.length ≤ maxRequestBytes do throw .RECORD
  let some e := Run.reqOf x.toByteArray | throw .RECORD
  pure (e, r)

def kstepRec (bs : Bytes) : Except Word ((Nat × Bytes) × Bytes) := do
  let (d, r) ← numRec 4 bs
  let (x, r) ← blobRec r
  pure ((d, x), r)

def authRec (bs : Bytes) : Except Word (Auth × Bytes) := do
  let (pin, r) ← cut 64 bs
  let ([fp, fv], r) ← nums [1, 8] r | throw .RECORD
  unless fp ≤ 1 && (fp == 1 || fv == 0) do throw .RECORD
  let (kfloor, r) ← numRec 4 r
  let (rsv, r) ← numRec 4 r
  let (rs, r) ← cut 64 r
  unless rsv != 0 || rs == zeroDigest do throw .RECORD
  let (grant, r) ← blobRec r
  let (keyset, r) ← blobRec r
  let (release, r) ← blobRec r
  unless release.length == 0 || release.length == 64 do throw .RECORD
  let (nk, r) ← numRec 4 r
  let (ksteps, r) ← many kstepRec nk r
  let (nb, r) ← numRec 4 r
  let (byps, r) ← many blobRec nb r
  let (ns, r) ← numRec 4 r
  let (rsets, r) ← many blobRec ns r
  let (nq, r) ← numRec 4 r
  let (reqs, r) ← many reqRec nq r
  unless reqs.Pairwise (fun a b => a.q != b.q) && (match reqs with | [] => true | e0 :: _ => reqs.all fun e => e.r.tenantId == e0.r.tenantId && e.r.programId == e0.r.programId) do
    throw .RECORD
  pure ({ pin, floor := if fp == 1 then some fv else none, kfloor, rsv, rs, grant, keyset, release, ksteps, byps, rsets,
          reqs }, r)

/-- Everything before the authority section: the context, the feed rows and the redone payments. -/
structure Pre where
  today : Nat
  asOf : Nat
  prev : Bytes
  dmf : Feed Death
  pdeath : Feed Death
  excl : Feed Exclusion
  span : Feed Span
  redo : List Nat

def decodePre (h : Hdr) (bs : Bytes) : Except Word (Pre × Bytes) := do
  let ([today, asOf], r) ← nums [4, 4] bs | throw .RECORD
  let (prev, r) ← cut 64 r
  let (nr, r) ← numRec 4 r
  let (d1, r) ← desc r
  let (d2, r) ← desc r
  let (d3, r) ← desc r
  let (d4, r) ← desc r
  unless h.batch == 1 || asOf == 0 do throw .RECORD
  let (dmf, r) ← feed dmfC d1 r
  let (pdeath, r) ← feed pdeathC d2 r
  let (excl, r) ← feed exclC d3 r
  let (span, r) ← feed spanC d4 r
  let (redo, r) ← many (numRec payWidth) nr r
  pure ({ today, asOf, prev, dmf, pdeath, excl, span, redo }, r)

def decodeBody (h : Hdr) (bs : Bytes) : Except Word (Req × Bytes) := do
  let (p, r) ← decodePre h bs
  let (auth, r) ← authRec r
  pure ({ shard := h.shard, batch := h.batch, today := p.today, asOf := p.asOf, prev := p.prev, dmf := p.dmf,
          pdeath := p.pdeath, excl := p.excl, span := p.span, redo := p.redo, auth }, r)

/-- The request and the digest its header carries.  The body must be used exactly.  The digest is not compared here:
    whoever relies on it compares it with `frameDigest` of the body (`encodeReq_decodeReq`). -/
def decodeReq (bs : Bytes) : Except Word (Req × Bytes) := do
  let (h, body) ← decodeHdr bs
  let (q, rest) ← decodeBody h body
  unless rest.isEmpty do throw .LENGTH
  pure (q, h.digest)

/-- The length of a request's body. -/
def bodyBytes (q : Req) : Nat :=
  384 + 37 * q.dmf.rows.length + 25 * q.pdeath.rows.length + 29 * q.excl.rows.length + 62 * q.span.rows.length +
    payWidth * q.redo.length + ((encAuth q.auth).map List.length).getD 0

/-! ## The decision of a request (today's values, from `Flat/Worker.lean` `commitChunk`) -/

/-- A feed whose pin is the hash of its rows' SNAPSHOT/v1 input; anything else is missing. -/
def snap {α : Type} (H : Bytes → Bytes) (kind : Nat) (fields : α → List (Nat × Nat)) (f : Feed α) :
    Option (Snapshot α) :=
  let s : Snapshot α := ⟨f.asOf, f.count, f.rows⟩
  if f.state == 1 && (pinInput "RR/GATE/SNAPSHOT/v1" kind fields s).map H == some f.pin then some s else none

/-- The read set (the sets themselves are the store's, so they are not in it). -/
def ctxOf (H : Bytes → Bytes) (q : Req) (dv : Derived) : Ctx :=
  { today := q.today, dmf := snap H 1 Death.fields q.dmf, providerDeaths := snap H 2 Death.fields q.pdeath,
    exclusions := snap H 3 Exclusion.fields q.excl, enrollment := snap H 4 Span.fields q.span,
    released := none, unresolved := none, releasedPrior := ⟨0, 0, []⟩, unresolvedPrior := ⟨0, 0, []⟩, anchor := 0,
    redo := q.redo, byp := dv.byp, lim := dv.lim }

def feedsOf (c : Ctx) : Feeds :=
  { dmfSome := c.dmf.isSome, pdSome := c.providerDeaths.isSome, exclSome := c.exclusions.isSome,
    spanSome := c.enrollment.isSome,
    dmfOk := usable c.today 90 okDeath c.dmf, pdOk := usable c.today 90 okDeath c.providerDeaths,
    exclOk := usable c.today 31 okExclusion c.exclusions, spanOk := usable c.today 7 okSpan c.enrollment,
    dmf := fun i => (entries c.dmf).filter (·.id == i), pdeath := fun i => (entries c.providerDeaths).filter (·.id == i),
    excl := fun i => (entries c.exclusions).filter (·.id == i),
    span := fun i => (entries c.enrollment).filter (·.member == i) }

def fcOf (H : Bytes → Bytes) (q : Req) (dv : Derived) : FCtx := ⟨q.today, q.redo, feedsOf (ctxOf H q dv), dv.byp, dv.lim⟩

/-- The decide theorems' hypothesis holds for every request. -/
theorem fcOf_inv (H : Bytes → Bytes) (q : Req) (dv : Derived) : FCtxInv (fcOf H q dv) (ctxOf H q dv) := by
  unfold FCtxInv
  exact ⟨rfl, rfl, rfl, rfl, rfl, rfl, rfl, rfl, rfl, rfl, fun _ => rfl, fun _ => rfl, fun _ => rfl, fun _ => rfl, rfl, rfl⟩

/-- The lines the rules see (`Run.keep`), with their positions among the decided lines. -/
def kept (dv : Derived) : List (Nat × Line) :=
  dv.lines.zipIdx.filterMap fun (l, i) => if (Run.unfit dv.lines).contains l.pay then none else some (i, l)

/-- One batch's decide values, as `commitChunk` computes them. -/
structure Decided where
  /-- The lines decided now. -/
  b : List Line
  /-- The decisions in decision order, then the rows appended to the released and unresolved sets. -/
  ds : List Decision
  fr : List Line
  fu : List Line
  /-- The index the decisions were made on. -/
  x : Ix

def decidedOf (H : Bytes → Bytes) (s : St) (q : Req) (dv : Derived) : Decided :=
  let fc := fcOf H q dv
  let lines := (kept dv).map (·.2)
  let b := lines
  let fe := fetch s fc.redo b
  let r := decideFetched s.rel.head s.unr.head fe fc [] b
  ⟨b, r.1, r.2.1, r.2.2, localIx s.rel.head s.unr.head fe (localRows fe.rel) (localRows fe.unr) fc b⟩

/-- One line's answer. -/
inductive Ans
  | rules (d : Decision)
  | wide (l : Line)
  | sibling (l : Line)
  deriving DecidableEq, Repr

def Ans.widthHeld : Ans → Bool
  | .wide _ | .sibling _ => true
  | _ => false

/-- Positions for `ls`: each line takes the first position in `pool` that holds it and no earlier line took. -/
def place : List (Nat × Line) → List Line → List Nat
  | _, [] => []
  | pool, l :: ls => match pool.find? (·.2 == l) with
    | some p => p.1 :: place (pool.erase p) ls
    | none => place pool ls

/-- Every line's answer with its input position, in record order: the decisions in decision order, then the lines held
    for width in input order. -/
def answers (H : Bytes → Bytes) (s : St) (q : Req) (dv : Derived) : List (Nat × Ans) :=
  let d := decidedOf H s q dv
  let held : List (Nat × Ans) := dv.lines.zipIdx.filterMap fun (l, i) =>
    if !Run.fits l then some (i, Ans.wide l)
    else if (Run.unfit dv.lines).contains l.pay then some (i, Ans.sibling l) else none
  (place (kept dv) (d.ds.map (·.line))).zip (d.ds.map Ans.rules) ++ held

/-! ## The record -/

/-- 0: decided, joins no set; 1: ALLOW, joins the released set; 2: joins the unresolved set; 3: a field over width;
    4: another line of its payment over width; 5: joins the released set because its payment is in the engine's
    bypasses (rr-core to confirm; the only way a HOLD is released). -/
inductive Rule | decided | released | unresolved | wide | sibling | bypassed
  deriving DecidableEq, Repr

def rules : List Rule := [.decided, .released, .unresolved, .wide, .sibling, .bypassed]

structure Rec where
  index : Nat
  /-- 0 ALLOW, 1 HOLD, 2 HUMAN_REVIEW. -/
  outcome : Nat
  rule : Rule
  /-- Bit `r.idx` is reason `r`. -/
  reasons : Nat
  /-- The store position (chunk, row) of the counterparts' key entry. -/
  ref : Option (Nat × Nat)
  deriving DecidableEq, Repr

def outCode : Outcome → Nat
  | .ALLOW => 0 | .HOLD => 1 | .HUMAN_REVIEW => 2

def outOf : Nat → Option Outcome
  | 0 => some .ALLOW | 1 => some .HOLD | 2 => some .HUMAN_REVIEW | _ => none

/-- A reason list's mask: bit `r.idx` for each listed reason. -/
def maskOf (rs : List Reason) : Nat := reasons.foldl (fun m r => if rs.contains r then m ||| 2 ^ r.idx else m) 0

/-- The reasons a mask names, in `reasons` (name) order. -/
def unmask (m : Nat) : List Reason := reasons.filter fun r => m.testBit r.idx

/-- A leaf's own codes, never a rule reason: UNENCODABLE_PAYMENT at bit 62 and SCOPE at bit 63 (each emitted alone).
    Bits from `reasons.length` to 61 are refused. -/
def leafUnencodable : Nat := 2 ^ 62
def leafScope : Nat := 2 ^ 63

/-- The rule of a decision: `releasedLines` and `unresolvedLines` row for row.  `bypassed` is a line released beyond the
    rules: by an admitted bypass, or at HOLD authority (`limitedPay`); the payment's leaf names which (its bypass id). -/
def ruleOf (d : Decided) (e : Decision) : Rule :=
  if e.outcome == .ALLOW && !d.x.redo.contains e.line.pay && d.x.payOutcome d.ds e.line.pay == .ALLOW then .released
  else if d.x.bypassed d.ds e.line.pay || d.x.limitedPay d.ds e.line.pay && !d.x.own e.line then .bypassed
  else if e.outcome != .ALLOW && !e.reasons.contains .ALREADY_DECIDED && !d.x.own e.line && !d.x.ownU e.line then .unresolved
  else .decided

/-- The first of the line's keys whose entry gives a counterpart, released set first, at its store position
    (`loc unresolved key`). -/
def firstRef (loc : Bool → Key → Option (Nat × Nat)) (x : Ix) (l : Line) : Option (Nat × Nat) :=
  let rel := (keys l).filter fun k => !(hits x.rel x.relPost [k] fun _ => true).isEmpty
  let unr := (keys l).filter fun k => !(hits x.unr x.unrPost [k] fun y => (keys l).any (x.claim y).contains).isEmpty
  match rel.head? with
  | some k => loc false k
  | none => unr.head?.bind (loc true)

def recOf (loc : Bool → Key → Option (Nat × Nat)) (d : Decided) (i : Nat) : Ans → Rec
  | .rules e => ⟨i, outCode e.outcome, ruleOf d e, maskOf e.reasons, firstRef loc d.x e.line⟩
  | .wide _ => ⟨i, 1, .wide, 0, none⟩
  | .sibling _ => ⟨i, 1, .sibling, 0, none⟩

def records (H : Bytes → Bytes) (loc : Bool → Key → Option (Nat × Nat)) (s : St) (q : Req) (dv : Derived) : List Rec :=
  (answers H s q dv).map fun (i, a) => recOf loc (decidedOf H s q dv) i a

/-- A record's line answer from the record, the request and the store state before the batch.  Counterparts are
    recomputed (`Ix.counterparts`); nothing else is. -/
def join (H : Bytes → Bytes) (s : St) (q : Req) (dv : Derived) (r : Rec) : Option Ans := do
  let l ← dv.lines[r.index]?
  match r.rule with
  | .wide => pure (.wide l)
  | .sibling => pure (.sibling l)
  | _ => pure (.rules ⟨l, ← outOf r.outcome, unmask r.reasons, (decidedOf H s q dv).x.counterparts l⟩)

/-! ## The human text (on demand; never on the decision path) -/

def Ans.text : Ans → String
  | .rules d => Run.render d
  | .wide l => Run.lineText l ++ " HOLD UNENCODABLE_FIELD"
  | .sibling l => Run.lineText l ++ " HOLD UNENCODABLE_PAYMENT"

def textOf (H : Bytes → Bytes) (s : St) (q : Req) (dv : Derived) (r : Rec) : Option String := (join H s q dv r).map Ans.text

/-! ## The answer frame -/

def manyO {α : Type} (f : Bytes → Option (α × Bytes)) : Nat → Bytes → Option (List α × Bytes)
  | 0, r => some ([], r)
  | n + 1, r => do
    let (a, r) ← f r
    let (as, r) ← manyO f n r
    pure (a :: as, r)

/-- A length (`u16`) and then the bytes. -/
def blob2 (b : Bytes) : Option Bytes := do pure ((← le 2 b.length) ++ b)

/-- One payment's leaf: its outcome, reason mask and authority, the id of the bypass that released it (zero when none),
    its input (`INPUT/v7`) and, for an `ANSWERED` payment, its earlier list (the `RR/GATE/EARLIER/v1` count and entries).
    The host builds the token leaf from its own request fields, this and the answer's grant id. -/
structure Leaf where
  outcome : Nat
  reasons : Nat
  authority : Nat
  bypass : ByteArray
  input : ByteArray
  earlier : ByteArray := ByteArray.empty
  deriving DecidableEq

/-- Outcome codes 0-3 (3 `ANSWERED`: exactly the leaves with an earlier list, and those carry no bypass), authority codes
    0-2; the reasons are a u64 whose low 62 bits are rule reasons (bit `r.idx`) and whose bits 62 and 63 are the leaf's
    own codes (`leafUnencodable`, `leafScope`). -/
def Leaf.ok (l : Leaf) : Bool :=
  l.outcome ≤ 3 && l.reasons < 2 ^ 64 && l.reasons % 2 ^ 62 < 2 ^ Rules.reasons.length && l.authority ≤ 2 && ((l.outcome == 3) == (l.earlier.size != 0)) &&
    (l.earlier.size == 0 || l.bypass.toList == zeroDigest)

/-- A zero bypass id is one byte 0; any other is a byte 1 and the id; an earlier list is a byte 2 and the list as a
    `blob2`. -/
def encLeaf (l : Leaf) : Option Bytes := do
  guard (l.ok && l.bypass.size = 64 && l.input.size = 64)
  let h ← leAll [1, 8, 1] [l.outcome, l.reasons, l.authority]
  let bp ← (if l.earlier.size != 0 then (2 :: ·) <$> blob2 l.earlier.toList
    else some (if l.bypass.toList == zeroDigest then [0] else 1 :: l.bypass.toList))
  pure (h ++ bp ++ l.input.toList)

def blob2Rec (bs : Bytes) : Option (Bytes × Bytes) := do
  let (n, r) ← (numRec 2 bs).toOption
  takeN n r

def decLeaf (bs : Bytes) : Option (Leaf × Bytes) := do
  let ([o, m, a, f], r) ← (nums [1, 8, 1, 1] bs).toOption | none
  let (b, e, r) ← if f == 0 then pure (zeroDigest, [], r)
    else if f == 1 then do
      let (b, r) ← takeN 64 r
      guard (b != zeroDigest)
      pure (b, [], r)
    else if f == 2 then do
      let (e, r) ← blob2Rec r
      guard (e != [])
      pure (zeroDigest, e, r)
    else none
  let (i, r) ← takeN 64 r
  let l : Leaf := ⟨o, m, a, b.toByteArray, i.toByteArray, e.toByteArray⟩
  guard l.ok
  pure (l, r)

/-- Added by the implementer, rr-core to confirm: what the frame carries beyond the records, a 1:1 transcription of
    today's text fields.  `hold`: a grant refusal (16 bytes, zero padded, empty when none), in which case the batch
    decided nothing; `grant`: the admitted grant's id (zero when none), once for every leaf; `auth`: the shard's authority
    record after the batch (`Worker.encAuth`, `authLen` bytes, zero on a refusal), which the batch digest binds; `notes`: the
    bypass notes;
    `leaves`: the payment leaves; `adds`: the rows the batch appended. -/
structure Ext where
  hold : ByteArray
  grant : ByteArray
  auth : ByteArray
  notes : List ByteArray
  leaves : List Leaf
  adds : List ByteArray
  deriving DecidableEq

def encExt (e : Ext) : Option Bytes := do
  guard (e.hold.size = 16 && e.grant.size = 64 && e.auth.size = authLen)
  let ns ← e.notes.mapM (blob2 ·.toList)
  let ls ← e.leaves.mapM encLeaf
  let as ← e.adds.mapM (blob2 ·.toList)
  pure (e.hold.toList ++ e.grant.toList ++ e.auth.toList ++ (← le 4 e.notes.length) ++ ns.flatten ++ (← le 4 e.leaves.length) ++ ls.flatten ++
    (← le 4 e.adds.length) ++ as.flatten)

def decExt (bs : Bytes) : Option (Ext × Bytes) := do
  let (hold, r) ← takeN 16 bs
  let (grant, r) ← takeN 64 r
  let (auth, r) ← takeN authLen r
  let (nn, r) ← (numRec 4 r).toOption
  let (notes, r) ← manyO blob2Rec nn r
  let (nl, r) ← (numRec 4 r).toOption
  let (leaves, r) ← manyO decLeaf nl r
  let (na, r) ← (numRec 4 r).toOption
  let (adds, r) ← manyO blob2Rec na r
  pure (⟨hold.toByteArray, grant.toByteArray, auth.toByteArray, notes.map (·.toByteArray), leaves, adds.map (·.toByteArray)⟩, r)

structure AnsFrame where
  word : Word
  shard : Nat
  batch : Nat
  digest : ByteArray
  recs : List Rec
  head : ByteArray
  root : ByteArray
  ext : Ext
  deriving DecidableEq

/-- The chunk and row that mean "no counterpart". -/
def noChunk : Nat := 2 ^ 32 - 1
def noRow : Nat := 2 ^ 24 - 1

/-- Structure only (no policy): outcome and rule agree, ALLOW exactly when no reason is set, a reference only on a
    decided line. -/
def Rec.ok (r : Rec) : Bool :=
  r.index < 2 ^ 24 && r.reasons < 2 ^ Rules.reasons.length &&
  (match r.ref with | some (c, w) => c < noChunk && w < noRow | none => true) &&
  match r.rule with
  | .wide | .sibling => r.outcome == 1 && r.reasons == 0 && r.ref.isNone
  | .released => r.outcome == 0 && r.reasons == 0
  | .bypassed => r.outcome ≤ 2 && (r.outcome == 0) == (r.reasons == 0)
  | .unresolved => (r.outcome == 1 || r.outcome == 2) && r.reasons != 0
  | .decided => r.outcome ≤ 2 && (r.outcome == 0) == (r.reasons == 0)

def encRec (r : Rec) : Option Bytes := do
  guard r.ok
  let (c, w) := r.ref.getD (noChunk, noRow)
  leAll [3, 1, 1, 8, 4, 3] [r.index, r.outcome, rules.idxOf r.rule, r.reasons, c, w]

def encodeAns (a : AnsFrame) : Option Bytes := do
  guard (a.digest.size = 64)
  guard (if a.word == .OK then a.head.size = 64 && a.root.size = 64 &&
      (a.recs.map (·.index)).mergeSort (fun i j => decide (i ≤ j)) == List.range a.recs.length
    else a.recs.isEmpty && a.head.isEmpty && a.root.isEmpty && a.ext == ⟨.empty, .empty, .empty, [], [], []⟩)
  let h ← leAll [2, 1, 4, 8, 4] [version, a.word.code, a.shard, a.batch, a.recs.length]
  let rs ← a.recs.mapM encRec
  let x ← if a.word == .OK then encExt a.ext else pure []
  pure (magicAns ++ h ++ a.digest.toList ++ rs.flatten ++ a.head.toList ++ a.root.toList ++ x)

def decRec (bs : Bytes) : Option (Rec × Bytes) := do
  let ([i, o, u, m, c, w], r) ← (nums [3, 1, 1, 8, 4, 3] bs).toOption | none
  let u ← rules[u]?
  let ref : Option (Nat × Nat) ← if c == noChunk && w == noRow then some none else if c == noChunk || w == noRow then none else some (some (c, w))
  let x : Rec := ⟨i, o, u, m, ref⟩
  guard x.ok
  pure (x, r)

/-- `none` for anything but the canonical bytes of an answer: the host then HOLDs every line of the batch. -/
def decodeAns (bs : Bytes) : Option AnsFrame := do
  let (h, r) ← takeN ansHdrBytes bs
  guard (h.take 4 == magicAns)
  let ([v, st, k, b, n], dg) ← (nums [2, 1, 4, 8, 4] (h.drop 4)).toOption | none
  guard (v == version)
  let w ← words[st]?
  if w == .OK then
    let (recs, r) ← manyO decRec n r
    let (head, r) ← takeN 64 r
    let (root, r) ← takeN 64 r
    let (ext, r) ← decExt r
    guard (r.isEmpty && (recs.map (·.index)).mergeSort (fun i j => decide (i ≤ j)) == List.range n)
    pure ⟨w, k, b, dg.toByteArray, recs, head.toByteArray, root.toByteArray, ext⟩
  else
    guard (n == 0 && r.isEmpty)
    pure ⟨w, k, b, dg.toByteArray, [], .empty, .empty, ⟨.empty, .empty, .empty, [], [], []⟩⟩

/-- The answer to a decided request: `dg` its digest, `head` and `root` the chain head and state root after it. -/
def answerOf (H : Bytes → Bytes) (loc : Bool → Key → Option (Nat × Nat)) (s : St) (q : Req) (dv : Derived) (dg head root : Bytes)
    (ext : Ext) : AnsFrame :=
  ⟨.OK, q.shard, q.batch, dg.toByteArray, records H loc s q dv, head.toByteArray, root.toByteArray, ext⟩

/-- A refusal, echoing the header when it parsed (zeros when it did not).  The header's fields always fit, so the
    empty fallback (which the host's decoder refuses) is never taken. -/
def refusal (w : Word) (h : Option Hdr) : Bytes :=
  let h := h.getD ⟨0, 0, zeroDigest⟩
  (encodeAns ⟨w, h.shard, h.batch, h.digest.toByteArray, [], .empty, .empty, ⟨.empty, .empty, .empty, [], [], []⟩⟩).getD []

/-! ## Admission and retry (III.3) -/

/-- The engine of one shard: its shard (fixed at launch), the chain head after its last logged batch (`none`: no
    store yet), per logged batch its identity (`ident`) and the answer bytes, and the store. -/
structure Eng (σ : Type) where
  shard : Nat
  head : Option Bytes
  log : List (Bytes × Bytes)
  store : σ

inductive Admit
  | decide
  | replay (a : Bytes)
  | refuse (w : Word)

def genesis (asOf : Nat) : Snapshot Line × Snapshot Line := (⟨asOf, 0, []⟩, ⟨asOf, 0, []⟩)

/-- Batch n+1 following the engine's head is decided; batch n with the logged digest gets the logged answer; batch n
    with another digest is a conflict; anything else is not next. -/
def admit {σ : Type} (H : Bytes → Bytes) (e : Eng σ) (q : Req) (dg : Bytes) : Admit :=
  let n := e.log.length
  if q.shard != e.shard then .refuse .SHARD
  else if q.batch == n + 1 then
    if q.prev == e.head.getD (chainStart H q.shard q.auth.pin (genesis q.asOf)) then .decide else .refuse .HEAD
  else if q.batch == n && 0 < n then
    match e.log.getLast? with
    | some (d, a) => if d == dg then .replay a else .refuse .CONFLICT
    | none => .refuse .NOT_NEXT
  else .refuse .NOT_NEXT

/-- One request.  `dec` decides and installs an admitted batch: the new store, the head after it, the answer bytes
    (`encodeAns (answerOf ...)`), or a store word.  A refusal changes nothing. -/
-- TODO(slice 0, StoreLog): the durable retry log (request digest and the unsealed last batch) is the store's; `Eng.log` stands for it.
def serve {σ : Type} (H : Bytes → Bytes) (dec : Eng σ → Req → Except Word (σ × Bytes × Bytes)) (e : Eng σ)
    (bs : Bytes) : Eng σ × Bytes :=
  let no (w : Word) : Eng σ × Bytes := (e, refusal w ((decodeHdr bs).toOption.map (·.1)))
  match decodeReq bs with
  | .error w => no w
  | .ok (q, _) => match admit H e q (ident H bs q) with
    | .refuse w => no w
    | .replay a => (e, a)
    | .decide => match dec e q with
      | .error w => no w
      | .ok (st, h, a) => ({ e with head := some h, log := e.log ++ [(ident H bs q, a)], store := st }, a)

/-! ## Statements -/

/-! ### Decoding is stable under appended bytes -/

theorem cut_ok {n : Nat} {bs a r : Bytes} (h : cut n bs = .ok (a, r)) : n ≤ bs.length ∧ a = bs.take n ∧ r = bs.drop n := by
  unfold cut takeN at h
  by_cases hn : n ≤ bs.length
  · simp [hn] at h; exact ⟨hn, h.1.symm, h.2.symm⟩
  · simp [hn] at h

theorem cut_app (n : Nat) (bs e a r : Bytes) (h : cut n bs = .ok (a, r)) : cut n (bs ++ e) = .ok (a, r ++ e) := by
  obtain ⟨hn, rfl, rfl⟩ := cut_ok h
  have h2 : n ≤ (bs ++ e).length := by simp; omega
  have h3 : n ≤ bs.length + e.length := by omega
  simp [cut, takeN, h3, List.take_append_of_le_length hn, List.drop_append_of_le_length hn]

theorem nums_app (e : Bytes) : ∀ (ws : List Nat) (bs a r : Bytes) (as : List Nat),
    nums ws bs = .ok (as, r) → nums ws (bs ++ e) = .ok (as, r ++ e)
  | [], bs, _, r, as, h => by simp [nums] at h ⊢; obtain ⟨rfl, rfl⟩ := h; simp
  | w :: ws, bs, _, r, as, h => by
    unfold nums at h ⊢
    cases hc : cut w bs with
    | error _ => simp [hc, bind, Except.bind] at h
    | ok p =>
      obtain ⟨a, r1⟩ := p
      have hc' := cut_app w bs e a r1 hc
      cases hn : nums ws r1 with
      | error _ => simp [hc, hn, bind, Except.bind] at h
      | ok p2 =>
        obtain ⟨as2, r2⟩ := p2
        have hn' := nums_app e ws r1 a r2 as2 hn
        simp [hc, hn, hc', hn', bind, Except.bind, pure, Except.pure] at h ⊢
        obtain ⟨rfl, rfl⟩ := h
        simp


theorem bind_ok {α β : Type} (x : Except Word α) (f : α → Except Word β) (y : β) (h : (x >>= f) = .ok y) :
    ∃ a, x = .ok a ∧ f a = .ok y := by
  cases x <;> simp_all [bind, Except.bind]

theorem ok_bind {α β : Type} (x : Except Word α) (f : α → Except Word β) (a : α) (y : β) (h1 : x = .ok a)
    (h2 : f a = .ok y) : (x >>= f) = .ok y := by
  subst h1; simpa [bind, Except.bind] using h2

def Stab {α : Type} (f : Bytes → Except Word (α × Bytes)) : Prop :=
  ∀ bs e a r, f bs = .ok (a, r) → f (bs ++ e) = .ok (a, r ++ e)

theorem numRec_stab (w : Nat) : Stab (numRec w) := by
  intro bs e a r h
  unfold numRec at h ⊢
  obtain ⟨⟨x, y⟩, h1, h2⟩ := bind_ok _ _ _ h
  have h2' : (Except.ok (unle x, y) : Except Word _) = .ok (a, r) := h2
  have h3 := Except.ok.inj h2'
  simp only [Prod.mk.injEq] at h3
  obtain ⟨rfl, rfl⟩ := h3
  exact ok_bind _ _ (x, y ++ e) _ (cut_app w bs e x y h1) rfl

theorem many_stab {α : Type} {f : Bytes → Except Word (α × Bytes)} (hf : Stab f) : ∀ n, Stab (many f n)
  | 0 => by intro bs e a r h; simp [many] at h ⊢; obtain ⟨rfl, rfl⟩ := h; simp
  | n + 1 => by
    intro bs e a r h
    unfold many at h ⊢
    obtain ⟨⟨x, y⟩, h1, h2⟩ := bind_ok _ _ _ h
    obtain ⟨⟨xs, z⟩, h3, h4⟩ := bind_ok _ _ _ h2
    have h1' := hf bs e x y h1
    have h3' := many_stab hf n y e xs z h3
    refine ok_bind _ _ (x, y ++ e) _ h1' ?_
    refine ok_bind _ _ (xs, z ++ e) _ h3' ?_
    simp only [pure, Except.pure] at h4 ⊢
    have := Except.ok.inj h4
    simp only [Prod.mk.injEq] at this
    obtain ⟨rfl, rfl⟩ := this
    rfl


theorem nums_len : ∀ (ws : List Nat) (bs : Bytes) (ns : List Nat) (r : Bytes), nums ws bs = .ok (ns, r) → ns.length = ws.length
  | [], bs, ns, r, h => by simp [nums] at h; obtain ⟨rfl, rfl⟩ := h; rfl
  | w :: ws, bs, ns, r, h => by
    unfold nums at h
    obtain ⟨⟨a, r1⟩, h1, h2⟩ := bind_ok _ _ _ h
    obtain ⟨⟨as, r2⟩, h3, h4⟩ := bind_ok _ _ _ h2
    have h4' : (Except.ok (unle a :: as, r2) : Except Word _) = .ok (ns, r) := h4
    have := Except.ok.inj h4'
    simp only [Prod.mk.injEq] at this
    obtain ⟨rfl, rfl⟩ := this
    simp [nums_len ws r1 as r2 h3]

theorem desc_stab : Stab desc := by
  intro bs e a r h
  unfold desc at h ⊢
  obtain ⟨⟨ns, r1⟩, h1, h2⟩ := bind_ok _ _ _ h
  have hl := nums_len _ _ _ _ h1
  match ns, hl with
  | [st, a1, c1, n1], _ =>
    obtain ⟨⟨pin, r2⟩, h3, h4⟩ := bind_ok _ _ _ h2
    refine ok_bind _ _ ([st, a1, c1, n1], r1 ++ e) _ (nums_app e _ _ [] _ _ h1) ?_
    refine ok_bind _ _ (pin, r2 ++ e) _ (cut_app _ _ e _ _ h3) ?_
    by_cases hP : (st ≤ 2 && (st == 1 || (a1 == 0 && c1 == 0 && n1 == 0 && pin == zeroDigest))) = true
    · simp [hP, bind, Except.bind, pure, Except.pure] at h4 ⊢
      obtain ⟨rfl, rfl⟩ := h4
      simp_all
    · simp [hP, bind, Except.bind, pure, Except.pure, throwThe, MonadExceptOf.throw] at h4

theorem feedRow_stab {α : Type} (c : RowCodec α) : Stab (feedRow c) := by
  intro bs e a r h
  unfold feedRow at h ⊢
  obtain ⟨⟨ns, r1⟩, h1, h2⟩ := bind_ok _ _ _ h
  refine ok_bind _ _ (ns, r1 ++ e) _ (nums_app e _ _ [] _ _ h1) ?_
  cases hc : c.ofNums ns with
  | none => simp [hc, throwThe, MonadExceptOf.throw] at h2
  | some x =>
    simp [hc, bind, Except.bind, pure, Except.pure] at h2 ⊢
    obtain ⟨rfl, rfl⟩ := h2
    simp

theorem feed_stab {α : Type} (c : RowCodec α) (d : Nat × Nat × Nat × Nat × Bytes) : Stab (feed c d) := by
  intro bs e a r h
  obtain ⟨st, a0, n, k, pin⟩ := d
  unfold feed at h ⊢
  obtain ⟨⟨rows, r1⟩, h1, h2⟩ := bind_ok _ _ _ h
  refine ok_bind _ _ (rows, r1 ++ e) _ (many_stab (feedRow_stab c) k _ e _ _ h1) ?_
  simp [bind, Except.bind, pure, Except.pure] at h2 ⊢
  obtain ⟨rfl, rfl⟩ := h2
  simp

theorem blobRec_stab : Stab blobRec := by
  intro bs e a r h
  unfold blobRec at h ⊢
  obtain ⟨⟨n, r1⟩, h1, h2⟩ := bind_ok _ _ _ h
  refine ok_bind _ _ (n, r1 ++ e) _ (numRec_stab 4 _ e _ _ h1) ?_
  exact cut_app _ _ e _ _ h2

theorem kstepRec_stab : Stab kstepRec := by
  intro bs e a r h
  unfold kstepRec at h ⊢
  obtain ⟨⟨d, r1⟩, h1, h2⟩ := bind_ok _ _ _ h
  obtain ⟨⟨x, r2⟩, h3, h4⟩ := bind_ok _ _ _ h2
  refine ok_bind _ _ (d, r1 ++ e) _ (numRec_stab 4 _ e _ _ h1) ?_
  refine ok_bind _ _ (x, r2 ++ e) _ (blobRec_stab _ e _ _ h3) ?_
  simp [bind, Except.bind, pure, Except.pure] at h4 ⊢
  obtain ⟨rfl, rfl⟩ := h4
  simp


theorem reqRec_stab : Stab reqRec := by
  intro bs e a r h
  unfold reqRec at h ⊢
  obtain ⟨⟨x, r1⟩, h1, h2⟩ := bind_ok _ _ _ h
  refine ok_bind _ _ (x, r1 ++ e) _ (blobRec_stab _ e _ _ h1) ?_
  dsimp only at h2 ⊢
  split at h2
  · rename_i hP
    rw [if_pos hP]
    cases hc : Run.reqOf x.toByteArray with
    | none => simp [hc, throwThe, MonadExceptOf.throw] at h2
    | some y =>
      simp [hc, bind, Except.bind, pure, Except.pure] at h2 ⊢
      obtain ⟨rfl, rfl⟩ := h2
      simp
  · cases h2

theorem decodePre_stab (hd : Hdr) : Stab (decodePre hd) := by
  intro bs e a r h
  unfold decodePre at h ⊢
  obtain ⟨⟨ns, r1⟩, h1, h2⟩ := bind_ok _ _ _ h
  have hl := nums_len _ _ _ _ h1
  match ns, hl with
  | [today, asOf], _ =>
    obtain ⟨⟨prev, r2⟩, h3, h4⟩ := bind_ok _ _ _ h2
    obtain ⟨⟨nr, r3⟩, h5, h6⟩ := bind_ok _ _ _ h4
    obtain ⟨⟨d1, r4⟩, h7, h8⟩ := bind_ok _ _ _ h6
    obtain ⟨⟨d2, r5⟩, h9, h10⟩ := bind_ok _ _ _ h8
    obtain ⟨⟨d3, r6⟩, h11, h12⟩ := bind_ok _ _ _ h10
    obtain ⟨⟨d4, r7⟩, h13, h14⟩ := bind_ok _ _ _ h12
    refine ok_bind _ _ ([today, asOf], r1 ++ e) _ (nums_app e _ _ [] _ _ h1) ?_
    refine ok_bind _ _ (prev, r2 ++ e) _ (cut_app _ _ e _ _ h3) ?_
    refine ok_bind _ _ (nr, r3 ++ e) _ (numRec_stab 4 _ e _ _ h5) ?_
    refine ok_bind _ _ (d1, r4 ++ e) _ (desc_stab _ e _ _ h7) ?_
    refine ok_bind _ _ (d2, r5 ++ e) _ (desc_stab _ e _ _ h9) ?_
    refine ok_bind _ _ (d3, r6 ++ e) _ (desc_stab _ e _ _ h11) ?_
    refine ok_bind _ _ (d4, r7 ++ e) _ (desc_stab _ e _ _ h13) ?_
    dsimp only at h14 ⊢
    split at h14
    · rename_i hP
      rw [if_pos hP]
      obtain ⟨⟨dmf, s1⟩, k1, k2⟩ := bind_ok _ _ _ h14
      obtain ⟨⟨pd, s2⟩, k3, k4⟩ := bind_ok _ _ _ k2
      obtain ⟨⟨ex, s3⟩, k5, k6⟩ := bind_ok _ _ _ k4
      obtain ⟨⟨sp, s4⟩, k7, k8⟩ := bind_ok _ _ _ k6
      obtain ⟨⟨rd, s5⟩, k9, k10⟩ := bind_ok _ _ _ k8
      refine ok_bind _ _ (dmf, s1 ++ e) _ (feed_stab _ _ _ e _ _ k1) ?_
      refine ok_bind _ _ (pd, s2 ++ e) _ (feed_stab _ _ _ e _ _ k3) ?_
      refine ok_bind _ _ (ex, s3 ++ e) _ (feed_stab _ _ _ e _ _ k5) ?_
      refine ok_bind _ _ (sp, s4 ++ e) _ (feed_stab _ _ _ e _ _ k7) ?_
      refine ok_bind _ _ (rd, s5 ++ e) _ (many_stab (numRec_stab _) _ _ e _ _ k9) ?_
      simp [bind, Except.bind, pure, Except.pure] at k10 ⊢
      obtain ⟨rfl, rfl⟩ := k10
      simp
    · cases h14


theorem authRec_stab : Stab authRec := by
  intro bs e a r h
  unfold authRec at h ⊢
  obtain ⟨⟨pin, r1⟩, h1, h2⟩ := bind_ok _ _ _ h
  refine ok_bind _ _ (pin, r1 ++ e) _ (cut_app _ _ e _ _ h1) ?_
  obtain ⟨⟨ns, r2⟩, h3, h4⟩ := bind_ok _ _ _ h2
  have hl := nums_len _ _ _ _ h3
  match ns, hl with
  | [fp, fv], _ =>
    refine ok_bind _ _ ([fp, fv], r2 ++ e) _ (nums_app e _ _ [] _ _ h3) ?_
    dsimp only at h4 ⊢
    split at h4
    · rename_i hP
      rw [if_pos hP]
      obtain ⟨⟨kf, s0⟩, k0, h4⟩ := bind_ok _ _ _ h4
      refine ok_bind _ _ (kf, s0 ++ e) _ (numRec_stab _ _ e _ _ k0) ?_
      obtain ⟨⟨rsv, sv⟩, kv, h4⟩ := bind_ok _ _ _ h4
      refine ok_bind _ _ (rsv, sv ++ e) _ (numRec_stab _ _ e _ _ kv) ?_
      obtain ⟨⟨rs, sr⟩, kr, h4⟩ := bind_ok _ _ _ h4
      refine ok_bind _ _ (rs, sr ++ e) _ (cut_app _ _ e _ _ kr) ?_
      dsimp only at h4 ⊢
      split at h4
      rotate_left
      · cases h4
      rename_i hV
      rw [if_pos hV]
      obtain ⟨⟨grant, s1⟩, k1, k2⟩ := bind_ok _ _ _ h4
      obtain ⟨⟨keyset, s2⟩, k3, k4⟩ := bind_ok _ _ _ k2
      obtain ⟨⟨release, s3⟩, k5, k6⟩ := bind_ok _ _ _ k4
      refine ok_bind _ _ (grant, s1 ++ e) _ (blobRec_stab _ e _ _ k1) ?_
      refine ok_bind _ _ (keyset, s2 ++ e) _ (blobRec_stab _ e _ _ k3) ?_
      refine ok_bind _ _ (release, s3 ++ e) _ (blobRec_stab _ e _ _ k5) ?_
      dsimp only at k6 ⊢
      split at k6
      · rename_i hQ
        rw [if_pos hQ]
        obtain ⟨⟨nk, t1⟩, m1, m2⟩ := bind_ok _ _ _ k6
        obtain ⟨⟨ksteps, t2⟩, m3, m4⟩ := bind_ok _ _ _ m2
        obtain ⟨⟨nb, t3⟩, m5, m6⟩ := bind_ok _ _ _ m4
        obtain ⟨⟨byps, t4⟩, m7, m8⟩ := bind_ok _ _ _ m6
        obtain ⟨⟨ns, u1⟩, s1, s2⟩ := bind_ok _ _ _ m8
        obtain ⟨⟨rsets, u2⟩, s3, m8⟩ := bind_ok _ _ _ s2
        obtain ⟨⟨nq, t5⟩, m9, m10⟩ := bind_ok _ _ _ m8
        obtain ⟨⟨reqs, t6⟩, m11, m12⟩ := bind_ok _ _ _ m10
        refine ok_bind _ _ (nk, t1 ++ e) _ (numRec_stab _ _ e _ _ m1) ?_
        refine ok_bind _ _ (ksteps, t2 ++ e) _ (many_stab kstepRec_stab _ _ e _ _ m3) ?_
        refine ok_bind _ _ (nb, t3 ++ e) _ (numRec_stab _ _ e _ _ m5) ?_
        refine ok_bind _ _ (byps, t4 ++ e) _ (many_stab blobRec_stab _ _ e _ _ m7) ?_
        refine ok_bind _ _ (ns, u1 ++ e) _ (numRec_stab _ _ e _ _ s1) ?_
        refine ok_bind _ _ (rsets, u2 ++ e) _ (many_stab blobRec_stab _ _ e _ _ s3) ?_
        refine ok_bind _ _ (nq, t5 ++ e) _ (numRec_stab _ _ e _ _ m9) ?_
        refine ok_bind _ _ (reqs, t6 ++ e) _ (many_stab reqRec_stab _ _ e _ _ m11) ?_
        rcases reqs with _ | ⟨e0, tl⟩
        · simp [bind, Except.bind, pure, Except.pure] at m12 ⊢
          obtain ⟨rfl, rfl⟩ := m12
          simp
        · by_cases hR : (decide ((e0 :: tl).Pairwise (fun a b => (a.q != b.q) = true)) &&
              (e0 :: tl).all fun e => e.r.tenantId == e0.r.tenantId && e.r.programId == e0.r.programId) = true
          · dsimp only at m12 ⊢
            rw [if_pos hR] at m12 ⊢
            simp [pure, Except.pure] at m12 ⊢
            obtain ⟨rfl, rfl⟩ := m12
            simp
          · dsimp only at m12
            rw [if_neg hR] at m12
            cases m12
      · cases k6
    · cases h4

theorem decodeBody_stab (hd : Hdr) : Stab (decodeBody hd) := by
  intro bs e a r h
  unfold decodeBody at h ⊢
  obtain ⟨⟨p, r1⟩, h1, h2⟩ := bind_ok _ _ _ h
  obtain ⟨⟨au, r2⟩, h3, h4⟩ := bind_ok _ _ _ h2
  refine ok_bind _ _ (p, r1 ++ e) _ (decodePre_stab hd _ e _ _ h1) ?_
  refine ok_bind _ _ (au, r2 ++ e) _ (authRec_stab _ e _ _ h3) ?_
  simp [bind, Except.bind, pure, Except.pure] at h4 ⊢
  obtain ⟨rfl, rfl⟩ := h4
  simp

theorem decodeHdr_app {bs : Bytes} {hd : Hdr} {body : Bytes} (e : Bytes) (h : decodeHdr bs = .ok (hd, body)) :
    decodeHdr (bs ++ e) = .ok (hd, body ++ e) ∧ hdrBytes ≤ bs.length ∧ body = bs.drop hdrBytes := by
  unfold decodeHdr at h ⊢
  by_cases hn : hdrBytes ≤ bs.length
  · have hn2 : hdrBytes ≤ bs.length + e.length := by omega
    simp [takeN, hn, hn2, List.take_append_of_le_length hn, List.drop_append_of_le_length hn,
      bind, Except.bind, pure, Except.pure] at h ⊢
    split at h
    · rename_i hP
      obtain ⟨rfl, rfl⟩ := Prod.mk.inj (Except.ok.inj h)
      exact ⟨by rw [if_pos hP], rfl⟩
    · cases h
  · simp [takeN, hn] at h


theorem err_bind {α β : Type} (x : Except Word α) (f : α → Except Word β) (a : α) (w : Word) (h1 : x = .ok a)
    (h2 : f a = .error w) : (x >>= f) = .error w := by
  subst h1; simpa [bind, Except.bind] using h2

/-- A body whose sections end before or after the frame does is refused `LENGTH`. -/
theorem decodeReq_trailing (bs dg : Bytes) (q : Req) (h : decodeReq bs = .ok (q, dg)) (extra : Bytes) (hx : extra ≠ []) :
    decodeReq (bs ++ extra) = .error .LENGTH := by
  unfold decodeReq at h ⊢
  obtain ⟨⟨hd, body⟩, h1, h2⟩ := bind_ok _ _ _ h
  obtain ⟨h1', -, -⟩ := decodeHdr_app extra h1
  refine err_bind _ _ (hd, body ++ extra) _ h1' ?_
  dsimp only at h2 ⊢
  obtain ⟨⟨q', rest⟩, h3, h4⟩ := bind_ok _ _ _ h2
  refine err_bind _ _ (q', rest ++ extra) _ (decodeBody_stab hd _ extra _ _ h3) ?_
  split at h4
  · rename_i hE
    have : rest = [] := by simpa using hE
    subst this
    simp [hx] <;> rfl
  · cases h4


section
variable (H : Bytes → Bytes) (loc : Bool → Key → Option (Nat × Nat)) (s : St) (q : Req) (dv : Derived)

/-! ### The answer frame round trip -/

private theorem some_bind {α β : Type} (a : α) (f : α → Option β) : (some a >>= f) = f a := rfl

private theorem ba_list (b : ByteArray) : b.toList.toByteArray = b := by
  ext1; simp [Flat.Bin.toList_eq']

private theorem list_ba (l : Bytes) : l.toByteArray.toList = l := Flat.Bin.toList_toByteArray l

private theorem obind_some {α β : Type} {x : Option α} {f : α → Option β} {y : β} (h : (x >>= f) = some y) :
    ∃ a, x = some a ∧ f a = some y :=
  Option.bind_eq_some_iff.mp h

private theorem guard_bind_some {p : Prop} [Decidable p] {β : Type} {f : Unit → Option β} {y : β}
    (h : (guard p >>= f) = some y) : p ∧ f () = some y := by
  by_cases hp : p
  · simp only [guard, if_pos hp] at h
    exact ⟨hp, h⟩
  · simp only [guard, if_neg hp] at h
    cases h

private theorem guard_pos {p : Prop} [Decidable p] {β : Type} (hp : p) (f : Unit → Option β) : (guard p >>= f) = f () := by
  simp only [guard, if_pos hp]; rfl

private theorem toOption_ok {α : Type} {x : Except Word α} {a : α} (h : x.toOption = some a) : x = .ok a := by
  cases x <;> simp_all [Except.toOption]

private theorem takeN_append (a r : Bytes) : takeN a.length (a ++ r) = some (a, r) := by
  simp [takeN]

private theorem takeN_of_len {n : Nat} {a : Bytes} (h : a.length = n) (r : Bytes) : takeN n (a ++ r) = some (a, r) := by
  subst h; exact takeN_append a r

private theorem takeN_eq {n : Nat} {bs a r : Bytes} (h : takeN n bs = some (a, r)) : a.length = n ∧ bs = a ++ r := by
  unfold takeN at h
  split at h
  · rename_i hn
    simp only [Option.some.injEq, Prod.mk.injEq] at h
    obtain ⟨rfl, rfl⟩ := h
    exact ⟨by rw [List.length_take, Nat.min_eq_left hn], (List.take_append_drop n bs).symm⟩
  · cases h

private theorem le_succ (w n : Nat) : le (w + 1) n = (le w (n / 256)).map ((n % 256).toUInt8 :: ·) := by
  unfold le
  have hiff : n < 256 ^ (w + 1) ↔ n / 256 < 256 ^ w := by
    rw [Nat.div_lt_iff_lt_mul (by decide), Nat.pow_succ]
  have hl : (List.range (w + 1)).map (fun i => (n / 256 ^ i % 256).toUInt8) =
      (n % 256).toUInt8 :: (List.range w).map (fun i => (n / 256 / 256 ^ i % 256).toUInt8) := by
    rw [List.range_succ_eq_map, List.map_cons, List.map_map]
    congr 1
    · simp
    · apply List.map_congr_left
      intro i _
      show (n / 256 ^ (i + 1) % 256).toUInt8 = (n / 256 / 256 ^ i % 256).toUInt8
      rw [Nat.pow_succ', Nat.div_div_eq_div_mul]
  by_cases hn : n < 256 ^ (w + 1)
  · rw [if_pos hn, if_pos (hiff.mp hn), hl]; rfl
  · rw [if_neg hn, if_neg (fun h => hn (hiff.mpr h))]; rfl

private theorem le_zero (n : Nat) : le 0 n = if n = 0 then some [] else none := by
  unfold le; by_cases h : n = 0 <;> simp [h]

private theorem le_length {w n : Nat} {b : Bytes} (h : le w n = some b) : b.length = w := by
  unfold le at h
  split at h
  · cases h; simp
  · cases h

private theorem unle_cons (x : UInt8) (t : Bytes) : unle (x :: t) = x.toNat + 256 * unle t := rfl

private theorem unle_le : ∀ (w n : Nat) (b : Bytes), le w n = some b → unle b = n
  | 0, n, b, h => by
    rw [le_zero] at h
    split at h
    · rename_i hn; cases h; subst hn; rfl
    · cases h
  | w + 1, n, b, h => by
    rw [le_succ] at h
    cases ht : le w (n / 256) with
    | none => rw [ht] at h; cases h
    | some t =>
      rw [ht] at h
      simp only [Option.map_some, Option.some.injEq] at h
      subst h
      rw [unle_cons, unle_le w _ t ht]
      simp only [Nat.toUInt8_eq, UInt8.toNat_ofNat', Nat.reducePow]
      omega

private theorem le_unle : ∀ (b : Bytes), le b.length (unle b) = some b
  | [] => by simp [le_zero, unle]
  | x :: t => by
    have hx : x.toNat < 256 := x.toNat_lt
    rw [List.length_cons, le_succ, unle_cons]
    have h1 : (x.toNat + 256 * unle t) / 256 = unle t := by omega
    have h2 : (x.toNat + 256 * unle t) % 256 = x.toNat := by omega
    rw [h1, h2, le_unle t]
    simp

private theorem le_byte (y : UInt8) : le 1 y.toNat = some [y] := by
  have := le_unle [y]; simpa [unle] using this

private theorem leAll_nil : leAll [] [] = some [] := rfl

private theorem leAll_len {ws ns : List Nat} {b : Bytes} (h : leAll ws ns = some b) : ws.length = ns.length := by
  unfold leAll at h
  by_cases hl : ws.length = ns.length
  · exact hl
  · simp only [guard, if_neg hl] at h
    cases h

private theorem leAll_cons (w n : Nat) (ws ns : List Nat) :
    leAll (w :: ws) (n :: ns) = (le w n).bind fun a => (leAll ws ns).map (a ++ ·) := by
  unfold leAll
  by_cases hl : ws.length = ns.length
  · simp [hl, List.zip_cons_cons, guard]
    cases le w n <;> simp
    cases (ws.zip ns).mapM (fun x => le x.1 x.2) <;> simp
  · simp [hl, guard]
    cases le w n <;> rfl

private theorem leAll_cons_some {w n : Nat} {ws ns : List Nat} {b : Bytes} (h : leAll (w :: ws) (n :: ns) = some b) :
    ∃ x y, le w n = some x ∧ leAll ws ns = some y ∧ b = x ++ y := by
  rw [leAll_cons] at h
  cases h1 : le w n with
  | none => simp [h1] at h
  | some x =>
    cases h2 : leAll ws ns with
    | none => simp [h1, h2] at h
    | some y =>
      simp only [h1, h2, Option.bind_some, Option.map_some, Option.some.injEq] at h
      exact ⟨x, y, rfl, rfl, h.symm⟩

private theorem leAll_length : ∀ (ws ns : List Nat) (b : Bytes), leAll ws ns = some b → b.length = ws.sum
  | [], [], b, h => by cases h; rfl
  | [], _ :: _, _, h => absurd (leAll_len h) (by simp)
  | _ :: _, [], _, h => absurd (leAll_len h) (by simp)
  | w :: ws, n :: ns, b, h => by
    obtain ⟨x, y, h1, h2, rfl⟩ := leAll_cons_some h
    simp [le_length h1, leAll_length ws ns y h2]

private theorem nums_leAll (ws' : List Nat) (r : Bytes) : ∀ (ws ns : List Nat) (b : Bytes), leAll ws ns = some b →
    nums (ws ++ ws') (b ++ r) = (nums ws' r).map fun p => (ns ++ p.1, p.2)
  | [], [], b, h => by
    cases h; simp only [List.nil_append, List.reverse_nil, List.flatten_nil]; cases nums ws' r <;> rfl
  | [], _ :: _, _, h => absurd (leAll_len h) (by simp)
  | _ :: _, [], _, h => absurd (leAll_len h) (by simp)
  | w :: ws, n :: ns, b, h => by
    obtain ⟨x, y, h1, h2, rfl⟩ := leAll_cons_some h
    have ih := nums_leAll ws' r ws ns y h2
    have hc : cut w (x ++ (y ++ r)) = .ok (x, y ++ r) := by
      unfold cut; rw [← le_length h1, takeN_append]
    rw [List.cons_append, List.append_assoc]
    simp only [nums, hc, bind, Except.bind, ih]
    cases nums ws' r <;> simp [Except.map, pure, Except.pure, unle_le w n x h1]

private theorem nums_leAll' {ws ns : List Nat} {b : Bytes} (h : leAll ws ns = some b) (r : Bytes) :
    nums ws (b ++ r) = .ok (ns, r) := by
  have := nums_leAll [] r ws ns b h; simpa [nums, Except.map] using this

private theorem nums_byte (y : UInt8) (t : Bytes) : nums [1] (y :: t) = .ok ([y.toNat], t) := by
  have h : leAll [1] [y.toNat] = some [y] := by rw [leAll_cons, le_byte]; rfl
  simpa using nums_leAll' h t

private theorem leAll_nums : ∀ (ws : List Nat) (bs : Bytes) (ns : List Nat) (r : Bytes), nums ws bs = .ok (ns, r) →
    ∃ b, leAll ws ns = some b ∧ bs = b ++ r
  | [], bs, ns, r, h => by
    simp [nums] at h
    obtain ⟨rfl, rfl⟩ := h
    exact ⟨[], rfl, rfl⟩
  | w :: ws, bs, ns, r, h => by
    unfold nums at h
    obtain ⟨⟨a, r1⟩, h1, h2⟩ := bind_ok _ _ _ h
    obtain ⟨⟨as, r2⟩, h3, h4⟩ := bind_ok _ _ _ h2
    have h4' : (Except.ok (unle a :: as, r2) : Except Word _) = .ok (ns, r) := h4
    obtain ⟨rfl, rfl⟩ := Prod.mk.inj (Except.ok.inj h4')
    obtain ⟨hn, rfl, rfl⟩ := cut_ok h1
    obtain ⟨c, hc, heq⟩ := leAll_nums ws _ as _ h3
    refine ⟨bs.take w ++ c, ?_, ?_⟩
    · have := le_unle (bs.take w)
      rw [List.length_take, Nat.min_eq_left hn] at this
      rw [leAll_cons, this, hc]; rfl
    · rw [List.append_assoc, ← heq, List.take_append_drop]

private theorem numRec_le {w n : Nat} {b : Bytes} (h : le w n = some b) (r : Bytes) : numRec w (b ++ r) = .ok (n, r) := by
  have hu := unle_le _ _ _ h
  unfold numRec cut
  rw [← le_length h, takeN_append]
  simp [bind, Except.bind, pure, Except.pure, hu]

private theorem numRec_eq {w n : Nat} {bs r : Bytes} (h : numRec w bs = .ok (n, r)) : ∃ b, le w n = some b ∧ bs = b ++ r := by
  unfold numRec at h
  obtain ⟨⟨a, r1⟩, h1, h2⟩ := bind_ok _ _ _ h
  obtain ⟨hn, rfl, rfl⟩ := cut_ok h1
  have h2' : (Except.ok (unle (bs.take w), bs.drop w) : Except Word _) = .ok (n, r) := h2
  obtain ⟨rfl, rfl⟩ := Prod.mk.inj (Except.ok.inj h2')
  refine ⟨bs.take w, ?_, (List.take_append_drop w bs).symm⟩
  have := le_unle (bs.take w)
  rwa [List.length_take, Nat.min_eq_left hn] at this

/-! ### Lists of items -/

private theorem manyO_enc {α : Type} {enc : α → Option Bytes} {dec : Bytes → Option (α × Bytes)}
    (hd : ∀ x b r, enc x = some b → dec (b ++ r) = some (x, r)) :
    ∀ (xs : List α) (cs : List Bytes) (r : Bytes), xs.mapM enc = some cs → manyO dec xs.length (cs.flatten ++ r) = some (xs, r)
  | [], cs, r, h => by
    simp at h
    subst h; rfl
  | x :: xs, cs, r, h => by
    rw [List.mapM_cons] at h
    obtain ⟨c, hc, h⟩ := obind_some h
    obtain ⟨cs', hcs, h⟩ := obind_some h
    cases h
    simp only [List.flatten_cons, List.length_cons, List.append_assoc, manyO, hd x c (cs'.flatten ++ r) hc,
      manyO_enc hd xs cs' r hcs, Option.bind_eq_bind, Option.bind_some]
    rfl

private theorem manyO_dec {α : Type} {enc : α → Option Bytes} {dec : Bytes → Option (α × Bytes)}
    (he : ∀ bs x r, dec bs = some (x, r) → ∃ c, enc x = some c ∧ bs = c ++ r) :
    ∀ (n : Nat) (bs : Bytes) (xs : List α) (r : Bytes), manyO dec n bs = some (xs, r) →
      xs.length = n ∧ ∃ cs, xs.mapM enc = some cs ∧ bs = cs.flatten ++ r
  | 0, bs, xs, r, h => by
    simp only [manyO, Option.some.injEq, Prod.mk.injEq] at h
    obtain ⟨rfl, rfl⟩ := h
    exact ⟨rfl, [], rfl, rfl⟩
  | n + 1, bs, xs, r, h => by
    simp only [manyO] at h
    obtain ⟨⟨x, r1⟩, h1, h⟩ := obind_some h
    obtain ⟨⟨ys, r2⟩, h2, h⟩ := obind_some h
    cases h
    obtain ⟨c, hc, rfl⟩ := he _ _ _ h1
    obtain ⟨hl, cs, hcs, rfl⟩ := manyO_dec he n _ _ _ h2
    refine ⟨by simp [hl], c :: cs, ?_, by simp [List.append_assoc]⟩
    simp [List.mapM_cons, hc, hcs]

/-! ### Codes -/

private theorem words_code (w : Word) : words[w.code]? = some w := by cases w <;> rfl

private theorem code_words : ∀ st, st < 22 → (words[st]?).map Word.code = some st := by decide

private theorem code_of {st : Nat} {w : Word} (h : words[st]? = some w) : w.code = st := by
  by_cases hs : st < 22
  · have := code_words st hs; rw [h] at this; simpa using this
  · have : words.length ≤ st := by simp [words]; omega
    rw [List.getElem?_eq_none_iff.mpr this] at h; cases h

private theorem rules_idx (r : Rule) : rules[rules.idxOf r]? = some r := by cases r <;> rfl

private theorem idx_rules : ∀ u, u < 6 → (rules[u]?).map rules.idxOf = some u := by decide

private theorem idx_of {u : Nat} {r : Rule} (h : rules[u]? = some r) : rules.idxOf r = u := by
  by_cases hs : u < 6
  · have := idx_rules u hs; rw [h] at this; simpa using this
  · have : rules.length ≤ u := by simp [rules]; omega
    rw [List.getElem?_eq_none_iff.mpr this] at h; cases h

/-! ### Items -/

private theorem Rec.ok_ref {i o m c w : Nat} {u : Rule} (h : Rec.ok ⟨i, o, u, m, some (c, w)⟩ = true) : c < noChunk ∧ w < noRow := by
  simp only [Rec.ok, Bool.and_eq_true, decide_eq_true_eq] at h
  exact h.1.2

private theorem decRec_encRec (x : Rec) (b r : Bytes) (h : encRec x = some b) : decRec (b ++ r) = some (x, r) := by
  obtain ⟨i, o, u, m, ref⟩ := x
  unfold encRec at h
  obtain ⟨hok, h⟩ := guard_bind_some h
  cases ref with
  | none =>
    dsimp only [Option.getD] at h
    unfold decRec
    simp [nums_leAll' h r, Except.toOption, rules_idx, hok, guard]
  | some p =>
    obtain ⟨c, w⟩ := p
    obtain ⟨hc, hw⟩ := Rec.ok_ref hok
    dsimp only [Option.getD] at h
    unfold decRec
    simp [nums_leAll' h r, Except.toOption, rules_idx, hok, guard, Nat.ne_of_lt hc, Nat.ne_of_lt hw]

private theorem encRec_decRec (bs : Bytes) (x : Rec) (r : Bytes) (h : decRec bs = some (x, r)) :
    ∃ c, encRec x = some c ∧ bs = c ++ r := by
  unfold decRec at h
  obtain ⟨⟨ns, r1⟩, hn, h⟩ := obind_some h
  have hn := toOption_ok hn
  obtain ⟨b, hb, rfl⟩ := leAll_nums _ _ _ _ hn
  match ns, nums_len _ _ _ _ hn with
  | [i, o, u, m, c, w], _ =>
    dsimp only at h
    obtain ⟨rl, hu, h⟩ := obind_some h
    have hi := idx_of hu
    split at h
    · rename_i hcw
      obtain ⟨ref, hr, h⟩ := obind_some h
      cases hr
      obtain ⟨hok, h⟩ := guard_bind_some h
      cases h
      simp only [Bool.and_eq_true, beq_iff_eq] at hcw
      obtain ⟨rfl, rfl⟩ := hcw
      refine ⟨b, ?_, rfl⟩
      unfold encRec; rw [guard_pos hok]
      simpa [hi] using hb
    · split at h
      · obtain ⟨ref, hr, h⟩ := obind_some h
        cases hr
      · obtain ⟨ref, hr, h⟩ := obind_some h
        cases hr
        obtain ⟨hok, h⟩ := guard_bind_some h
        cases h
        refine ⟨b, ?_, rfl⟩
        unfold encRec; rw [guard_pos hok]
        simpa [hi] using hb

private theorem nums_leaf {o m a : Nat} {hd : Bytes} (h : leAll [1, 8, 1] [o, m, a] = some hd) (y : UInt8) (t : Bytes) :
    nums [1, 8, 1, 1] (hd ++ y :: t) = .ok ([o, m, a, y.toNat], t) := by
  have := nums_leAll [1] (y :: t) _ _ _ h
  rw [nums_byte] at this
  simpa [Except.map] using this

private theorem blob2Rec_blob2 (x c r : Bytes) (h : blob2 x = some c) : blob2Rec (c ++ r) = some (x, r) := by
  unfold blob2 at h
  obtain ⟨l, hl, h⟩ := obind_some h
  cases h
  unfold blob2Rec
  rw [List.append_assoc, numRec_le hl]
  simp [Except.toOption, takeN_append]

private theorem blob2_blob2Rec (bs x r : Bytes) (h : blob2Rec bs = some (x, r)) : ∃ c, blob2 x = some c ∧ bs = c ++ r := by
  unfold blob2Rec at h
  obtain ⟨⟨n, r1⟩, hn, h2⟩ := obind_some h
  obtain ⟨b, hb, hbs⟩ := numRec_eq (toOption_ok hn)
  dsimp only at h2
  obtain ⟨hl, hr1⟩ := takeN_eq h2
  refine ⟨b ++ x, ?_, by rw [hbs, hr1, List.append_assoc]⟩
  simp [blob2, hl, hb]

private theorem decLeaf_encLeaf (l : Leaf) (b r : Bytes) (h : encLeaf l = some b) : decLeaf (b ++ r) = some (l, r) := by
  obtain ⟨o, m, a, byp, inp, ear⟩ := l
  unfold encLeaf at h
  obtain ⟨hg, h⟩ := guard_bind_some h
  simp only [Bool.and_eq_true, decide_eq_true_eq] at hg
  obtain ⟨⟨hok, hbs⟩, his⟩ := hg
  obtain ⟨hd, hh, h⟩ := obind_some h
  obtain ⟨bp, hbp, h⟩ := obind_some h
  cases h
  have hil : inp.toList.length = 64 := by rw [← Flat.Bin.size_eq_length']; exact his
  have hbl : byp.toList.length = 64 := by rw [← Flat.Bin.size_eq_length']; exact hbs
  have h0 : (0 : UInt8).toNat = 0 := rfl
  have h1 : (1 : UInt8).toNat = 1 := rfl
  have h2 : (2 : UInt8).toNat = 2 := rfl
  by_cases he : ear.size = 0
  · rw [if_neg (by simp [he])] at hbp
    cases hbp
    obtain rfl : ear = ByteArray.empty := by
      have hl : ear.toList = [] := List.eq_nil_of_length_eq_zero (by rw [← Flat.Bin.size_eq_length']; exact he)
      rw [← ba_list ear, hl]; rfl
    unfold decLeaf
    by_cases hz : byp.toList = zeroDigest
    · rw [if_pos (by simp [hz])]
      simp [nums_leaf hh, Except.toOption, h0, takeN_of_len hil, ← hz, ba_list, hok, guard]
    · rw [if_neg (by simpa using hz)]
      simp [nums_leaf hh, Except.toOption, h1, takeN_of_len hil, takeN_of_len hbl, hz, ba_list, hok, guard]
  · rw [if_pos (by simpa using he)] at hbp
    obtain ⟨c, hc, rfl⟩ : ∃ c, blob2 ear.toList = some c ∧ bp = 2 :: c := by
      cases hc : blob2 ear.toList with
      | none => rw [hc] at hbp; cases hbp
      | some c => rw [hc] at hbp; exact ⟨c, rfl, (Option.some.inj hbp).symm⟩
    have hz : byp.toList = zeroDigest := by
      have := hok
      simp only [Leaf.ok, Bool.and_eq_true, Bool.or_eq_true, beq_iff_eq] at this
      exact this.2.resolve_left he
    have hne : ear.toList ≠ [] := fun h => he (by rw [Flat.Bin.size_eq_length', h]; rfl)
    unfold decLeaf
    simp [nums_leaf hh, Except.toOption, h2, blob2Rec_blob2 _ _ _ hc, hne, takeN_of_len hil, ← hz, ba_list, hok, guard]

private theorem encLeaf_decLeaf (bs : Bytes) (l : Leaf) (r : Bytes) (h : decLeaf bs = some (l, r)) :
    ∃ c, encLeaf l = some c ∧ bs = c ++ r := by
  unfold decLeaf at h
  replace h := obind_some h; obtain ⟨⟨ns, r1⟩, hn, h⟩ := h
  have hn := toOption_ok hn
  obtain ⟨b, hb, rfl⟩ := leAll_nums _ _ _ _ hn
  match ns, nums_len _ _ _ _ hn with
  | [o, m, a, f], _ =>
    dsimp only at h
    obtain ⟨x1, y1, h1, hy1, rfl⟩ := leAll_cons_some hb
    obtain ⟨x2, y2, h2, hy2, rfl⟩ := leAll_cons_some hy1
    obtain ⟨x3, y3, h3, hy3, rfl⟩ := leAll_cons_some hy2
    obtain ⟨x4, y4, h4, hy4, rfl⟩ := leAll_cons_some hy3
    rw [leAll_nil] at hy4; cases hy4
    have hhd : leAll [1, 8, 1] [o, m, a] = some (x1 ++ (x2 ++ (x3 ++ []))) := by
      simp [leAll_cons, h1, h2, h3, leAll_nil]
    have hzl : zeroDigest.length = 64 := by simp [zeroDigest, digestBytes]
    split at h
    · rename_i hf
      obtain rfl : f = 0 := by simpa using hf
      rw [pure_bind] at h
      dsimp only at h
      replace h := obind_some h; obtain ⟨⟨ii, r3⟩, hii, h⟩ := h
      dsimp only at h
      replace h := guard_bind_some h; obtain ⟨hok, h⟩ := h
      cases h
      obtain ⟨hil, rfl⟩ := takeN_eq hii
      rw [show le 1 0 = some [0] by decide] at h4; cases h4
      rw [List.toByteArray_nil] at hok
      refine ⟨x1 ++ (x2 ++ (x3 ++ [])) ++ [0] ++ ii, ?_, by simp⟩
      simp [encLeaf, guard, hok, hzl, hil, hhd, list_ba, List.size_toByteArray]
    · split at h
      · rename_i hf0 hf1
        obtain rfl : f = 1 := by simpa using hf1
        replace h := obind_some h; obtain ⟨⟨bb, r2⟩, ht, h⟩ := h
        dsimp only at h
        replace h := guard_bind_some h; obtain ⟨hne, h⟩ := h
        try rw [pure_bind] at h
        try dsimp only at h
        replace h := obind_some h; obtain ⟨⟨ii, r3⟩, hii, h⟩ := h
        dsimp only at h
        replace h := guard_bind_some h; obtain ⟨hok, h⟩ := h
        cases h
        obtain ⟨hbl, rfl⟩ := takeN_eq ht
        obtain ⟨hil, rfl⟩ := takeN_eq hii
        rw [show le 1 1 = some [1] by decide] at h4; cases h4
        rw [List.toByteArray_nil] at hok
        refine ⟨x1 ++ (x2 ++ (x3 ++ [])) ++ (1 :: bb) ++ ii, ?_, by simp⟩
        have hz : (bb == zeroDigest) = false := by simpa using hne
        simp [encLeaf, guard, hok, hbl, hil, hhd, list_ba, hz, List.size_toByteArray]
      · split at h
        · rename_i hf0 hf1 hf2
          obtain rfl : f = 2 := by simpa using hf2
          replace h := obind_some h; obtain ⟨⟨ee, r2⟩, he2, h⟩ := h
          dsimp only at h
          replace h := guard_bind_some h; obtain ⟨hne, h⟩ := h
          try rw [pure_bind] at h
          try dsimp only at h
          replace h := obind_some h; obtain ⟨⟨ii, r3⟩, hii, h⟩ := h
          dsimp only at h
          replace h := guard_bind_some h; obtain ⟨hok, h⟩ := h
          cases h
          obtain ⟨c, hc, rfl⟩ := blob2_blob2Rec _ _ _ he2
          obtain ⟨hil, rfl⟩ := takeN_eq hii
          rw [show le 1 2 = some [2] by decide] at h4; cases h4
          refine ⟨x1 ++ (x2 ++ (x3 ++ [])) ++ (2 :: c) ++ ii, ?_, by simp⟩
          have hne' : ee ≠ [] := by simpa using hne
          simp [encLeaf, guard, hok, hzl, hil, hhd, list_ba, List.size_toByteArray, hc, hne']
        · first | cases h | (obtain ⟨_, hbb, _⟩ := obind_some h; cases hbb)


private theorem mapM_toList {β : Type} (f : Bytes → Option β) (l : List ByteArray) :
    l.mapM (fun x => f x.toList) = (l.map (·.toList)).mapM f := by
  induction l with
  | nil => rfl
  | cons x l ih => simp only [List.map_cons, List.mapM_cons, ih]

private theorem decExt_encExt (e : Ext) (x r : Bytes) (h : encExt e = some x) : decExt (x ++ r) = some (e, r) := by
  obtain ⟨hold, grant, auth, notes, leaves, adds⟩ := e
  unfold encExt at h
  obtain ⟨hg, h⟩ := guard_bind_some h
  simp only [Bool.and_eq_true, decide_eq_true_eq] at hg
  obtain ⟨⟨hh, hgr⟩, har⟩ := hg
  obtain ⟨ns, hns, h⟩ := obind_some h
  obtain ⟨ls, hls, h⟩ := obind_some h
  obtain ⟨as, has, h⟩ := obind_some h
  obtain ⟨l1, hl1, h⟩ := obind_some h
  obtain ⟨l2, hl2, h⟩ := obind_some h
  obtain ⟨l3, hl3, h⟩ := obind_some h
  cases h
  rw [mapM_toList] at hns has
  have hhl : hold.toList.length = 16 := by rw [← Flat.Bin.size_eq_length']; exact hh
  have hgl : grant.toList.length = 64 := by rw [← Flat.Bin.size_eq_length']; exact hgr
  have hal : auth.toList.length = authLen := by rw [← Flat.Bin.size_eq_length']; exact har
  have m1 : ∀ r, manyO blob2Rec notes.length (ns.flatten ++ r) = some (notes.map (·.toList), r) := by
    intro r; have := manyO_enc blob2Rec_blob2 _ ns r hns; simpa using this
  have m2 : ∀ r, manyO decLeaf leaves.length (ls.flatten ++ r) = some (leaves, r) :=
    fun r => manyO_enc decLeaf_encLeaf leaves ls r hls
  have m3 : ∀ r, manyO blob2Rec adds.length (as.flatten ++ r) = some (adds.map (·.toList), r) := by
    intro r; have := manyO_enc blob2Rec_blob2 _ as r has; simpa using this
  unfold decExt
  simp [takeN_of_len hhl, takeN_of_len hgl, takeN_of_len hal, numRec_le hl1, numRec_le hl2, numRec_le hl3, m1, m2, m3,
    Except.toOption, ba_list, List.map_map, Function.comp_def]

private theorem encExt_decExt (bs : Bytes) (e : Ext) (r : Bytes) (h : decExt bs = some (e, r)) :
    ∃ c, encExt e = some c ∧ bs = c ++ r := by
  unfold decExt at h
  obtain ⟨⟨hold, r1⟩, h1, h⟩ := obind_some h
  obtain ⟨⟨grant, r2⟩, h2, h⟩ := obind_some h
  obtain ⟨⟨auth, r2a⟩, h2a, h⟩ := obind_some h
  obtain ⟨⟨nn, r3⟩, h3, h⟩ := obind_some h
  obtain ⟨⟨notes, r4⟩, h4, h⟩ := obind_some h
  obtain ⟨⟨nl, r5⟩, h5, h⟩ := obind_some h
  obtain ⟨⟨leaves, r6⟩, h6, h⟩ := obind_some h
  obtain ⟨⟨na, r7⟩, h7, h⟩ := obind_some h
  obtain ⟨⟨adds, r8⟩, h8, h⟩ := obind_some h
  cases h
  obtain ⟨hl1, rfl⟩ := takeN_eq h1
  obtain ⟨hl2, rfl⟩ := takeN_eq h2
  obtain ⟨hl2a, rfl⟩ := takeN_eq h2a
  obtain ⟨b3, hb3, rfl⟩ := numRec_eq (toOption_ok h3)
  obtain ⟨hn4, cs4, hcs4, rfl⟩ := manyO_dec blob2_blob2Rec _ _ _ _ h4
  obtain ⟨b5, hb5, rfl⟩ := numRec_eq (toOption_ok h5)
  obtain ⟨hn6, cs6, hcs6, rfl⟩ := manyO_dec encLeaf_decLeaf _ _ _ _ h6
  obtain ⟨b7, hb7, rfl⟩ := numRec_eq (toOption_ok h7)
  obtain ⟨hn8, cs8, hcs8, rfl⟩ := manyO_dec blob2_blob2Rec _ _ _ _ h8
  refine ⟨hold ++ grant ++ auth ++ b3 ++ cs4.flatten ++ b5 ++ cs6.flatten ++ b7 ++ cs8.flatten, ?_, by simp⟩
  have hg : (hold.toByteArray.size = 16 && grant.toByteArray.size = 64 && auth.toByteArray.size = authLen) = true := by
    simp [hl1, hl2, hl2a]
  unfold encExt
  rw [guard_pos hg]
  simp [Function.comp_def, list_ba, hcs4, hcs6, hcs8, hn4, hn6, hn8, hb3, hb5, hb7]

private theorem isEmpty_ba {b : ByteArray} (h : b.isEmpty = true) : b = .empty := by
  have hs : b.toList.length = 0 := by rw [← Flat.Bin.size_eq_length']; simpa [ByteArray.isEmpty] using h
  rw [← ba_list b, List.eq_nil_of_length_eq_zero hs]; rfl

private theorem magic_length : magicAns.length = 4 := by
  decide +kernel

private theorem empty_toList : ByteArray.empty.toList = [] :=
  List.eq_nil_of_length_eq_zero (by rw [← Flat.Bin.size_eq_length']; rfl)


/-! ### The request frame round trip -/

/-- What the decoder enforces on the authority section beyond its shape: each payment request is the request its bytes
    decode to and fits the request bound, the engine release is empty or 64 bytes, the payments are distinct and share
    one tenant and program. -/
abbrev reqsOk (reqs : List Run.Req) : Bool :=
  decide (reqs.Pairwise (fun x y => (x.q != y.q) = true)) &&
    (match reqs with
      | [] => true
      | e0 :: _ => reqs.all fun e => e.r.tenantId == e0.r.tenantId && e.r.programId == e0.r.programId)

def AuthWF (a : Auth) : Prop :=
  (∀ e ∈ a.reqs, e.x.toList.length ≤ maxRequestBytes ∧ Run.reqOf e.x = some e) ∧
  (a.rsv != 0 || a.rs == zeroDigest) = true ∧
  (a.release.length == 0 || a.release.length == 64) = true ∧ reqsOk a.reqs = true

/-- The well-formedness every decodable request has. -/
def ReqWF (q : Req) : Prop := AuthWF q.auth

private theorem magicReq_length : magicReq.length = 4 := by
  decide +kernel

private theorem cut_inv {n : Nat} {bs a r : Bytes} (h : cut n bs = .ok (a, r)) : a.length = n ∧ bs = a ++ r := by
  obtain ⟨hn, rfl, rfl⟩ := cut_ok h
  exact ⟨by simp [hn], (List.take_append_drop n bs).symm⟩

private theorem cut_enc {n : Nat} {a : Bytes} (h : a.length = n) (r : Bytes) : cut n (a ++ r) = .ok (a, r) := by
  unfold cut; rw [takeN_of_len h]

private theorem manyE_dec {α : Type} {enc : α → Option Bytes} {f : Bytes → Except Word (α × Bytes)}
    (he : ∀ bs x r, f bs = .ok (x, r) → ∃ c, enc x = some c ∧ bs = c ++ r) :
    ∀ (n : Nat) (bs : Bytes) (xs : List α) (r : Bytes), many f n bs = .ok (xs, r) →
      xs.length = n ∧ ∃ cs, xs.mapM enc = some cs ∧ bs = cs.flatten ++ r
  | 0, bs, xs, r, h => by
    simp [many] at h
    obtain ⟨rfl, rfl⟩ := h
    exact ⟨rfl, [], rfl, rfl⟩
  | n + 1, bs, xs, r, h => by
    unfold many at h
    obtain ⟨⟨x, r1⟩, h1, h2⟩ := bind_ok _ _ _ h
    obtain ⟨⟨ys, r2⟩, h3, h4⟩ := bind_ok _ _ _ h2
    simp only [pure, Except.pure] at h4
    have h5 := Except.ok.inj h4
    simp only [Prod.mk.injEq] at h5
    obtain ⟨rfl, rfl⟩ := h5
    obtain ⟨c, hc, rfl⟩ := he _ _ _ h1
    obtain ⟨hl, cs, hcs, rfl⟩ := manyE_dec he n _ _ _ h3
    refine ⟨by simp [hl], c :: cs, ?_, by simp [List.append_assoc]⟩
    simp [List.mapM_cons, hc, hcs]

private theorem manyE_enc {α : Type} {enc : α → Option Bytes} {f : Bytes → Except Word (α × Bytes)} :
    ∀ (xs : List α), (∀ x ∈ xs, ∀ b r, enc x = some b → f (b ++ r) = .ok (x, r)) →
    ∀ (cs : List Bytes) (r : Bytes), xs.mapM enc = some cs → many f xs.length (cs.flatten ++ r) = .ok (xs, r)
  | [], _, cs, r, h => by
    simp at h
    subst h; rfl
  | x :: xs, hd, cs, r, h => by
    rw [List.mapM_cons] at h
    obtain ⟨c, hc, h⟩ := obind_some h
    obtain ⟨cs', hcs, h⟩ := obind_some h
    cases h
    simp only [List.flatten_cons, List.length_cons, List.append_assoc, many]
    refine ok_bind _ _ (x, cs'.flatten ++ r) _ (hd x (List.mem_cons_self ..) c _ hc) ?_
    refine ok_bind _ _ (xs, r) _
      (manyE_enc xs (fun y hy => hd y (List.mem_cons_of_mem _ hy)) cs' r hcs) ?_
    rfl

private theorem many_all {α : Type} {f : Bytes → Except Word (α × Bytes)} {P : α → Prop}
    (hP : ∀ bs x r, f bs = .ok (x, r) → P x) :
    ∀ (n : Nat) (bs : Bytes) (xs : List α) (r : Bytes), many f n bs = .ok (xs, r) → ∀ x ∈ xs, P x
  | 0, bs, xs, r, h => by
    simp [many] at h
    obtain ⟨rfl, rfl⟩ := h
    intro x hx; simp at hx
  | n + 1, bs, xs, r, h => by
    unfold many at h
    obtain ⟨⟨x, r1⟩, h1, h2⟩ := bind_ok _ _ _ h
    obtain ⟨⟨ys, r2⟩, h3, h4⟩ := bind_ok _ _ _ h2
    simp only [pure, Except.pure] at h4
    have h5 := Except.ok.inj h4
    simp only [Prod.mk.injEq] at h5
    obtain ⟨rfl, rfl⟩ := h5
    intro z hz
    rcases List.mem_cons.mp hz with rfl | hz
    · exact hP _ _ _ h1
    · exact many_all hP n _ _ _ h3 z hz

/-! #### Rows -/

private def Lawful {α : Type} (c : RowCodec α) : Prop :=
  (∀ x, c.ofNums (c.get x) = some x) ∧ (∀ ns x, c.ofNums ns = some x → c.get x = ns)

private theorem dmfC_lawful : Lawful dmfC := by
  refine ⟨fun x => by cases x; rfl, fun ns x h => ?_⟩
  rcases ns with _ | ⟨a, _ | ⟨b, _ | ⟨c, ns⟩⟩⟩ <;> simp [dmfC] at h <;> (subst h; rfl)

private theorem pdeathC_lawful : Lawful pdeathC := by
  refine ⟨fun x => by cases x; rfl, fun ns x h => ?_⟩
  rcases ns with _ | ⟨a, _ | ⟨b, _ | ⟨c, ns⟩⟩⟩ <;> simp [pdeathC] at h <;> (subst h; rfl)

private theorem exclC_lawful : Lawful exclC := by
  refine ⟨fun x => by cases x; rfl, fun ns x h => ?_⟩
  rcases ns with _ | ⟨a, _ | ⟨b, _ | ⟨c, _ | ⟨d, ns⟩⟩⟩⟩ <;> simp [exclC] at h <;> (subst h; rfl)

private theorem spanC_lawful : Lawful spanC := by
  refine ⟨fun x => by cases x; rfl, fun ns x h => ?_⟩
  rcases ns with _ | ⟨a, _ | ⟨b, _ | ⟨c, _ | ⟨d, _ | ⟨e, ns⟩⟩⟩⟩⟩ <;> simp [spanC] at h <;> (subst h; rfl)

private theorem feedRow_enc {α : Type} {c : RowCodec α} (hl : Lawful c) (x : α) (b r : Bytes)
    (h : leAll c.widths (c.get x) = some b) : feedRow c (b ++ r) = .ok (x, r) := by
  unfold feedRow
  rw [nums_leAll' h r]
  simp [bind, Except.bind, hl.1 x, pure, Except.pure]

private theorem feedRow_dec {α : Type} {c : RowCodec α} (hl : Lawful c) {bs : Bytes} {x : α} {r : Bytes}
    (h : feedRow c bs = .ok (x, r)) : ∃ b, leAll c.widths (c.get x) = some b ∧ bs = b ++ r := by
  unfold feedRow at h
  obtain ⟨⟨ns, r1⟩, h1, h2⟩ := bind_ok _ _ _ h
  obtain ⟨b, hb, rfl⟩ := leAll_nums _ _ _ _ h1
  cases hc : c.ofNums ns with
  | none => simp [hc, throwThe, MonadExceptOf.throw] at h2
  | some y =>
    simp [hc, bind, Except.bind, pure, Except.pure] at h2
    obtain ⟨rfl, rfl⟩ := h2
    exact ⟨b, by rw [hl.2 ns y hc]; exact hb, rfl⟩

private theorem desc_enc {st a c n : Nat} {d pin : Bytes} (hd : leAll [1, 4, 4, 4] [st, a, c, n] = some d)
    (hp : pin.length = 64)
    (hc : (st ≤ 2 && (st == 1 || (a == 0 && c == 0 && n == 0 && pin == zeroDigest))) = true) (r : Bytes) :
    desc (d ++ pin ++ r) = .ok ((st, a, c, n, pin), r) := by
  unfold desc
  rw [List.append_assoc]
  simp [bind, Except.bind, nums_leAll' hd, cut_enc hp, hc, pure, Except.pure]

private theorem desc_dec {bs : Bytes} {st a c n : Nat} {pin r : Bytes} (h : desc bs = .ok ((st, a, c, n, pin), r)) :
    ∃ d, leAll [1, 4, 4, 4] [st, a, c, n] = some d ∧ pin.length = 64 ∧
      (st ≤ 2 && (st == 1 || (a == 0 && c == 0 && n == 0 && pin == zeroDigest))) = true ∧ bs = d ++ pin ++ r := by
  unfold desc at h
  obtain ⟨⟨ns, r1⟩, h1, h2⟩ := bind_ok _ _ _ h
  have hl := nums_len _ _ _ _ h1
  match ns, hl with
  | [st0, a0, c0, n0], _ =>
    obtain ⟨d, hd, rfl⟩ := leAll_nums _ _ _ _ h1
    obtain ⟨⟨pin0, r2⟩, h3, h4⟩ := bind_ok _ _ _ h2
    obtain ⟨hl3, rfl⟩ := cut_inv h3
    by_cases hP : (st0 ≤ 2 && (st0 == 1 || (a0 == 0 && c0 == 0 && n0 == 0 && pin0 == zeroDigest))) = true
    · simp [hP, bind, Except.bind, pure, Except.pure] at h4
      obtain ⟨⟨rfl, rfl, rfl, rfl, rfl⟩, rfl⟩ := h4
      exact ⟨d, hd, hl3, hP, by simp⟩
    · simp [hP, bind, Except.bind, pure, Except.pure, throwThe, MonadExceptOf.throw] at h4

private theorem rows_empty_iff {β : Type} (rows : List β) : rows.isEmpty = (rows.length == 0) := by
  cases rows <;> simp

private theorem and_ac {A B C : Bool} (h : (A && B && C) = true) : (A && C) = true := by
  cases A <;> cases B <;> cases C <;> simp_all

private theorem and_b {A B C : Bool} (h : (A && B && C) = true) : B = true := by
  cases A <;> cases B <;> cases C <;> simp_all

private theorem and_mk {A B C : Bool} (hA : (A && C) = true) (hB : B = true) : (A && B && C) = true := by
  cases A <;> cases B <;> cases C <;> simp_all

private theorem feedE_enc {α : Type} {c : RowCodec α} (hl : Lawful c) (f : Feed α) {dd rb : Bytes}
    (h : encFeed c f = some (dd, rb)) (r1 r2 : Bytes) :
    desc (dd ++ r1) = .ok ((f.state, f.asOf, f.count, f.rows.length, f.pin), r1) ∧
    feed c (f.state, f.asOf, f.count, f.rows.length, f.pin) (rb ++ r2) = .ok (f, r2) := by
  obtain ⟨st, a, n, rows, pin⟩ := f
  unfold encFeed at h
  obtain ⟨hg, h⟩ := guard_bind_some h
  obtain ⟨d, hd, h⟩ := obind_some h
  obtain ⟨rs, hrs, h⟩ := obind_some h
  cases h
  dsimp only at hg hd hrs ⊢
  rw [rows_empty_iff] at hg
  have hpl : pin.length = 64 := by simpa using and_b hg
  have hc := and_ac hg
  refine ⟨desc_enc hd hpl hc r1, ?_⟩
  have hm := manyE_enc (enc := fun x => leAll c.widths (c.get x)) (f := feedRow c) rows
    (fun x _ b r h => feedRow_enc hl x b r h) rs r2 hrs
  unfold feed
  simp [hm, bind, Except.bind, pure, Except.pure]

private theorem feedE_dec {α : Type} {c : RowCodec α} (hl : Lawful c) {st a n k : Nat} {pin bs rest rs r : Bytes}
    {f : Feed α} (hd : desc bs = .ok ((st, a, n, k, pin), rest)) (hf : feed c (st, a, n, k, pin) rs = .ok (f, r)) :
    ∃ dd rb, encFeed c f = some (dd, rb) ∧ bs = dd ++ rest ∧ rs = rb ++ r := by
  obtain ⟨d, hdd, hpl, hcnd, rfl⟩ := desc_dec hd
  unfold feed at hf
  obtain ⟨⟨rows, r1⟩, h1, h2⟩ := bind_ok _ _ _ hf
  have h2' : (Except.ok (({ state := st, asOf := a, count := n, rows := rows, pin := pin } : Feed α), r1) :
      Except Word _) = .ok (f, r) := h2
  obtain ⟨rfl, rfl⟩ := Prod.mk.inj (Except.ok.inj h2')
  obtain ⟨hlen, cs, hcs, rfl⟩ := manyE_dec (enc := fun x => leAll c.widths (c.get x))
    (fun bs x r h => feedRow_dec hl h) k _ _ _ h1
  subst hlen
  have hg : (st ≤ 2 && pin.length == 64 && (st == 1 || (a == 0 && n == 0 && rows.isEmpty && pin == zeroDigest))) = true := by
    rw [rows_empty_iff]
    exact and_mk hcnd (by simpa using hpl)
  refine ⟨d ++ pin, cs.flatten, ?_, rfl, rfl⟩
  unfold encFeed
  dsimp only
  rw [guard_pos hg]
  simp [hdd, hcs]

/-! #### Byte strings and the authority section -/

private theorem blobRec_enc {x b : Bytes} (h : blob x = some b) (r : Bytes) : blobRec (b ++ r) = .ok (x, r) := by
  unfold blob at h
  obtain ⟨l, hl, h⟩ := obind_some h
  cases h
  unfold blobRec
  rw [List.append_assoc, numRec_le hl]
  simp [bind, Except.bind, cut, takeN_append]

private theorem blobRec_dec {bs x r : Bytes} (h : blobRec bs = .ok (x, r)) : ∃ b, blob x = some b ∧ bs = b ++ r := by
  unfold blobRec at h
  obtain ⟨⟨n, r1⟩, h1, h2⟩ := bind_ok _ _ _ h
  obtain ⟨b, hb, rfl⟩ := numRec_eq h1
  obtain ⟨hl, rfl⟩ := cut_inv h2
  subst hl
  exact ⟨b ++ x, by simp [blob, hb], by simp⟩

private def ksEnc : Nat × Bytes → Option Bytes := fun (d, b) => do pure ((← le 4 d) ++ (← blob b))

private theorem kstepRec_enc {p : Nat × Bytes} {b : Bytes} (h : ksEnc p = some b) (r : Bytes) :
    kstepRec (b ++ r) = .ok (p, r) := by
  obtain ⟨d, x⟩ := p
  unfold ksEnc at h
  obtain ⟨l, hl, h⟩ := obind_some h
  obtain ⟨g, hg, h⟩ := obind_some h
  cases h
  unfold kstepRec
  rw [List.append_assoc, numRec_le hl]
  simp [bind, Except.bind, blobRec_enc hg, pure, Except.pure]

private theorem kstepRec_dec {bs : Bytes} {p : Nat × Bytes} {r : Bytes} (h : kstepRec bs = .ok (p, r)) :
    ∃ b, ksEnc p = some b ∧ bs = b ++ r := by
  obtain ⟨d, x⟩ := p
  unfold kstepRec at h
  obtain ⟨⟨d', r1⟩, h1, h2⟩ := bind_ok _ _ _ h
  obtain ⟨⟨x', r2⟩, h3, h4⟩ := bind_ok _ _ _ h2
  have h4' : (Except.ok ((d', x'), r2) : Except Word _) = .ok ((d, x), r) := h4
  obtain ⟨hh, rfl⟩ := Prod.mk.inj (Except.ok.inj h4')
  obtain ⟨hd, hx⟩ := Prod.mk.inj hh
  subst hd hx
  obtain ⟨b1, hb1, rfl⟩ := numRec_eq h1
  obtain ⟨b2, hb2, rfl⟩ := blobRec_dec h3
  exact ⟨b1 ++ b2, by simp [ksEnc, hb1, hb2], by simp⟩

private theorem reqOf_x {z : ByteArray} {e : Run.Req} (h : Run.reqOf z = some e) : e.x = z := by
  unfold Run.reqOf at h
  obtain ⟨r, _, h⟩ := obind_some h
  obtain ⟨ls, _, h⟩ := obind_some h
  cases h
  rfl

private theorem reqRec_enc {e : Run.Req} {b : Bytes} (h : blob e.x.toList = some b)
    (hl : e.x.toList.length ≤ maxRequestBytes) (hr : Run.reqOf e.x = some e) (r : Bytes) :
    reqRec (b ++ r) = .ok (e, r) := by
  unfold reqRec
  rw [blobRec_enc h]
  simp [bind, Except.bind, hl, ba_list, hr, pure, Except.pure]

private theorem reqRec_dec {bs r : Bytes} {e : Run.Req} (h : reqRec bs = .ok (e, r)) :
    ∃ b, blob e.x.toList = some b ∧ bs = b ++ r ∧ e.x.toList.length ≤ maxRequestBytes ∧ Run.reqOf e.x = some e := by
  unfold reqRec at h
  obtain ⟨⟨x, r1⟩, h1, h2⟩ := bind_ok _ _ _ h
  obtain ⟨b, hb, rfl⟩ := blobRec_dec h1
  dsimp only at h2
  split at h2
  · rename_i hP
    cases hc : Run.reqOf x.toByteArray with
    | none => simp [hc, throwThe, MonadExceptOf.throw] at h2
    | some y =>
      simp [hc, bind, Except.bind, pure, Except.pure] at h2
      obtain ⟨rfl, rfl⟩ := h2
      have hx := reqOf_x hc
      refine ⟨b, ?_, rfl, ?_, ?_⟩
      · simpa [hx, list_ba] using hb
      · simpa [hx, list_ba] using hP
      · rw [hx]; exact hc
  · cases h2

private theorem floor_norm {fp fv : Nat} (h : (fp ≤ 1 && (fp == 1 || fv == 0)) = true) :
    (if (if fp == 1 then some fv else none).isSome then 1 else 0) = fp ∧
      (if fp == 1 then some fv else none).getD 0 = fv := by
  simp only [Bool.and_eq_true, Bool.or_eq_true, decide_eq_true_eq, beq_iff_eq] at h
  obtain ⟨h1, h2 | h2⟩ := h
  · subst h2; simp
  · subst h2
    rcases (by omega : fp = 0 ∨ fp = 1) with rfl | rfl <;> simp

private def encAuth' (a : Auth) : Option Bytes := do
  guard (a.pin.length = 64 ∧ a.rs.length = 64)
  let f ← leAll [1, 8] [if a.floor.isSome then 1 else 0, a.floor.getD 0]
  let kf ← le 4 a.kfloor
  let v ← le 4 a.rsv
  let g ← blob a.grant
  let k ← blob a.keyset
  let r ← blob a.release
  let ks ← a.ksteps.mapM ksEnc
  let bs ← a.byps.mapM blob
  let ss ← a.rsets.mapM blob
  let rs ← a.reqs.mapM (fun e => blob e.x.toList)
  let n1 ← le 4 a.ksteps.length
  let n2 ← le 4 a.byps.length
  let n4 ← le 4 a.rsets.length
  let n3 ← le 4 a.reqs.length
  pure (a.pin ++ f ++ kf ++ v ++ a.rs ++ g ++ k ++ r ++ n1 ++ ks.flatten ++ n2 ++ bs.flatten ++ n4 ++ ss.flatten ++ n3 ++
    rs.flatten)

private theorem encAuth_eq (a : Auth) : encAuth a = encAuth' a := rfl

private theorem encAuth_some {a : Auth} {b : Bytes} (h : encAuth a = some b) :
    (a.pin.length = 64 ∧ a.rs.length = 64) ∧ ∃ fb kf v g k rr n1 n2 n4 n3 : Bytes, ∃ ks bs ss rs : List Bytes,
      leAll [1, 8] [if a.floor.isSome then 1 else 0, a.floor.getD 0] = some fb ∧ le 4 a.kfloor = some kf ∧
      le 4 a.rsv = some v ∧ blob a.grant = some g ∧ blob a.keyset = some k ∧ blob a.release = some rr ∧
      a.ksteps.mapM ksEnc = some ks ∧ a.byps.mapM blob = some bs ∧ a.rsets.mapM blob = some ss ∧
      a.reqs.mapM (fun e => blob e.x.toList) = some rs ∧
      le 4 a.ksteps.length = some n1 ∧ le 4 a.byps.length = some n2 ∧ le 4 a.rsets.length = some n4 ∧
      le 4 a.reqs.length = some n3 ∧
      b = a.pin ++ fb ++ kf ++ v ++ a.rs ++ g ++ k ++ rr ++ n1 ++ ks.flatten ++ n2 ++ bs.flatten ++ n4 ++ ss.flatten ++ n3 ++
        rs.flatten := by
  rw [encAuth_eq] at h
  unfold encAuth' at h
  obtain ⟨hp, h⟩ := guard_bind_some h
  obtain ⟨fb, hfb, h⟩ := obind_some h
  obtain ⟨kf, hkf, h⟩ := obind_some h
  obtain ⟨v, hv, h⟩ := obind_some h
  obtain ⟨g, hg, h⟩ := obind_some h
  obtain ⟨k, hk, h⟩ := obind_some h
  obtain ⟨rr, hrr, h⟩ := obind_some h
  obtain ⟨ks, hks, h⟩ := obind_some h
  obtain ⟨bs, hbs, h⟩ := obind_some h
  obtain ⟨ss, hss, h⟩ := obind_some h
  obtain ⟨rs, hrs, h⟩ := obind_some h
  obtain ⟨n1, hn1, h⟩ := obind_some h
  obtain ⟨n2, hn2, h⟩ := obind_some h
  obtain ⟨n4, hn4, h⟩ := obind_some h
  obtain ⟨n3, hn3, h⟩ := obind_some h
  cases h
  exact ⟨hp, fb, kf, v, g, k, rr, n1, n2, n4, n3, ks, bs, ss, rs, hfb, hkf, hv, hg, hk, hrr, hks, hbs, hss, hrs, hn1, hn2,
    hn4, hn3, rfl⟩

private theorem encAuth_of {a : Auth} {fb kf v g k rr n1 n2 n4 n3 : Bytes} {ks bs ss rs : List Bytes}
    (hp : a.pin.length = 64 ∧ a.rs.length = 64)
    (hfb : leAll [1, 8] [if a.floor.isSome then 1 else 0, a.floor.getD 0] = some fb) (hkf : le 4 a.kfloor = some kf)
    (hv : le 4 a.rsv = some v) (hg : blob a.grant = some g) (hk : blob a.keyset = some k) (hrr : blob a.release = some rr)
    (hks : a.ksteps.mapM ksEnc = some ks) (hbs : a.byps.mapM blob = some bs) (hss : a.rsets.mapM blob = some ss)
    (hrs : a.reqs.mapM (fun e => blob e.x.toList) = some rs)
    (hn1 : le 4 a.ksteps.length = some n1) (hn2 : le 4 a.byps.length = some n2) (hn4 : le 4 a.rsets.length = some n4)
    (hn3 : le 4 a.reqs.length = some n3) :
    encAuth a = some (a.pin ++ fb ++ kf ++ v ++ a.rs ++ g ++ k ++ rr ++ n1 ++ ks.flatten ++ n2 ++ bs.flatten ++ n4 ++
      ss.flatten ++ n3 ++ rs.flatten) := by
  rw [encAuth_eq]
  unfold encAuth'
  rw [guard_pos hp]
  simp [hfb, hkf, hv, hg, hk, hrr, hks, hbs, hss, hrs, hn1, hn2, hn4, hn3]

private theorem authRec_dec {bs r : Bytes} {a : Auth} (h : authRec bs = .ok (a, r)) :
    ∃ b, encAuth a = some b ∧ bs = b ++ r ∧ AuthWF a := by
  unfold authRec at h
  obtain ⟨⟨pin, r1⟩, h1, h2⟩ := bind_ok _ _ _ h
  obtain ⟨⟨ns, r2⟩, h3, h4⟩ := bind_ok _ _ _ h2
  have hl := nums_len _ _ _ _ h3
  match ns, hl with
  | [fp, fv], _ =>
    obtain ⟨fb, hfb, rfl⟩ := leAll_nums _ _ _ _ h3
    obtain ⟨hpl, rfl⟩ := cut_inv h1
    dsimp only at h4
    split at h4
    · rename_i hP
      obtain ⟨⟨kf, s0⟩, k0, h4⟩ := bind_ok _ _ _ h4
      obtain ⟨⟨rsv, sv⟩, kv, h4⟩ := bind_ok _ _ _ h4
      obtain ⟨⟨rs, sr⟩, kr, h4⟩ := bind_ok _ _ _ h4
      dsimp only at h4
      split at h4
      rotate_left
      · cases h4
      rename_i hV
      obtain ⟨⟨grant, s1⟩, k1, k2⟩ := bind_ok _ _ _ h4
      obtain ⟨⟨keyset, s2⟩, k3, k4⟩ := bind_ok _ _ _ k2
      obtain ⟨⟨release, s3⟩, k5, k6⟩ := bind_ok _ _ _ k4
      dsimp only at k6
      split at k6
      · rename_i hQ
        obtain ⟨⟨nk, t1⟩, m1, m2⟩ := bind_ok _ _ _ k6
        obtain ⟨⟨ksteps, t2⟩, m3, m4⟩ := bind_ok _ _ _ m2
        obtain ⟨⟨nb, t3⟩, m5, m6⟩ := bind_ok _ _ _ m4
        obtain ⟨⟨byps, t4⟩, m7, m8⟩ := bind_ok _ _ _ m6
        obtain ⟨⟨ns, u1⟩, s1, s2⟩ := bind_ok _ _ _ m8
        obtain ⟨⟨rsets, u2⟩, s3, m8⟩ := bind_ok _ _ _ s2
        obtain ⟨⟨nq, t5⟩, m9, m10⟩ := bind_ok _ _ _ m8
        obtain ⟨⟨reqs, t6⟩, m11, m12⟩ := bind_ok _ _ _ m10
        dsimp only at m12
        by_cases hR : reqsOk reqs = true
        · rw [if_pos hR] at m12
          simp only [pure, Except.pure] at m12
          have m13 := Except.ok.inj m12
          simp only [Prod.mk.injEq] at m13
          obtain ⟨rfl, rfl⟩ := m13
          obtain ⟨bkf, hbkf, rfl⟩ := numRec_eq k0
          obtain ⟨bv, hbv, rfl⟩ := numRec_eq kv
          obtain ⟨hrsl, rfl⟩ := cut_inv kr
          obtain ⟨bg, hbg, rfl⟩ := blobRec_dec k1
          obtain ⟨bk, hbk, rfl⟩ := blobRec_dec k3
          obtain ⟨brr, hbrr, rfl⟩ := blobRec_dec k5
          obtain ⟨bn1, hbn1, rfl⟩ := numRec_eq m1
          obtain ⟨hlk, cks, hcks, rfl⟩ := manyE_dec (enc := ksEnc) (fun bs x r h => kstepRec_dec h) _ _ _ _ m3
          obtain ⟨bn2, hbn2, rfl⟩ := numRec_eq m5
          obtain ⟨hlb, cbs, hcbs, rfl⟩ := manyE_dec (enc := blob) (fun bs x r h => blobRec_dec h) _ _ _ _ m7
          obtain ⟨bn4, hbn4, rfl⟩ := numRec_eq s1
          obtain ⟨hls, css, hcss, rfl⟩ := manyE_dec (enc := blob) (fun bs x r h => blobRec_dec h) _ _ _ _ s3
          obtain ⟨bn3, hbn3, rfl⟩ := numRec_eq m9
          obtain ⟨hlr, crs, hcrs, rfl⟩ := manyE_dec (enc := fun e => blob e.x.toList)
            (fun bs x r h => let ⟨b, hb, hbs, _, _⟩ := reqRec_dec h; ⟨b, hb, hbs⟩) _ _ _ _ m11
          have hall := many_all (P := fun e : Run.Req => e.x.toList.length ≤ maxRequestBytes ∧ Run.reqOf e.x = some e)
            (fun bs x r h => let ⟨_, _, _, h1, h2⟩ := reqRec_dec h; ⟨h1, h2⟩) _ _ _ _ m11
          obtain ⟨hf1, hf2⟩ := floor_norm hP
          subst hlk hlb hls hlr
          have hfb' : leAll [1, 8] [if (if fp == 1 then some fv else none).isSome then 1 else 0,
              (if fp == 1 then some fv else none).getD 0] = some fb := by
            rw [hf1, hf2]; exact hfb
          have henc := encAuth_of (a := ⟨pin, (if fp == 1 then some fv else none), kf, rsv, rs, grant, keyset, release,
            ksteps, byps, rsets, reqs⟩) ⟨hpl, hrsl⟩ hfb' hbkf hbv hbg hbk hbrr hcks hcbs hcss hcrs hbn1 hbn2 hbn4 hbn3
          refine ⟨_, henc, ?_, hall, hV, hQ, hR⟩
          simp [List.append_assoc]
        · rw [if_neg hR] at m12
          cases m12
      · cases k6
    · cases h4


private theorem authRec_enc {a : Auth} {b : Bytes} (h : encAuth a = some b) (hw : AuthWF a) (r : Bytes) :
    authRec (b ++ r) = .ok (a, r) := by
  obtain ⟨⟨hp, hrsl⟩, fb, kf, v, g, k, rr, n1, n2, n4, n3, ks, bs, ss, rs, hfb, hkf, hv, hg, hk, hrr, hks, hbs, hss, hrs,
    hn1, hn2, hn4, hn3, rfl⟩ := encAuth_some h
  obtain ⟨hreq, hV, hrel, hcond⟩ := hw
  have hP : ((if a.floor.isSome then 1 else 0) ≤ 1 &&
      ((if a.floor.isSome then 1 else 0) == 1 || a.floor.getD 0 == 0)) = true := by
    rcases hfl : a.floor with _ | v <;> simp [hfl]
  have hA : a.floor = (if (if a.floor.isSome then 1 else 0) == 1 then some (a.floor.getD 0) else none) := by
    rcases hfl : a.floor with _ | v <;> simp [hfl]
  unfold authRec
  rw [show a.pin ++ fb ++ kf ++ v ++ a.rs ++ g ++ k ++ rr ++ n1 ++ ks.flatten ++ n2 ++ bs.flatten ++ n4 ++ ss.flatten ++
      n3 ++ rs.flatten ++ r =
    a.pin ++ (fb ++ (kf ++ (v ++ (a.rs ++ (g ++ (k ++ (rr ++ (n1 ++ (ks.flatten ++ (n2 ++ (bs.flatten ++ (n4 ++
      (ss.flatten ++ (n3 ++ (rs.flatten ++ r))))))))))))))) by simp]
  refine ok_bind _ _ (a.pin, _) _ (cut_enc hp _) ?_
  refine ok_bind _ _ ([if a.floor.isSome then 1 else 0, a.floor.getD 0], _) _ (nums_leAll' hfb _) ?_
  dsimp only
  rw [if_pos hP]
  refine ok_bind _ _ (a.kfloor, _) _ (numRec_le hkf _) ?_
  refine ok_bind _ _ (a.rsv, _) _ (numRec_le hv _) ?_
  refine ok_bind _ _ (a.rs, _) _ (cut_enc hrsl _) ?_
  dsimp only
  rw [if_pos hV]
  refine ok_bind _ _ (a.grant, _) _ (blobRec_enc hg _) ?_
  refine ok_bind _ _ (a.keyset, _) _ (blobRec_enc hk _) ?_
  refine ok_bind _ _ (a.release, _) _ (blobRec_enc hrr _) ?_
  dsimp only
  split
  rotate_left
  · rename_i hn; exact absurd hrel hn
  refine ok_bind _ _ (a.ksteps.length, _) _ (numRec_le hn1 _) ?_
  refine ok_bind _ _ (a.ksteps, _) _
    (manyE_enc (enc := ksEnc) (f := kstepRec) a.ksteps (fun x _ b r h => kstepRec_enc h r) ks _ hks) ?_
  refine ok_bind _ _ (a.byps.length, _) _ (numRec_le hn2 _) ?_
  refine ok_bind _ _ (a.byps, _) _
    (manyE_enc (enc := blob) (f := blobRec) a.byps (fun x _ b r h => blobRec_enc h r) bs _ hbs) ?_
  refine ok_bind _ _ (a.rsets.length, _) _ (numRec_le hn4 _) ?_
  refine ok_bind _ _ (a.rsets, _) _
    (manyE_enc (enc := blob) (f := blobRec) a.rsets (fun x _ b r h => blobRec_enc h r) ss _ hss) ?_
  refine ok_bind _ _ (a.reqs.length, _) _ (numRec_le hn3 _) ?_
  refine ok_bind _ _ (a.reqs, _) _
    (manyE_enc (enc := fun e => blob e.x.toList) (f := reqRec) a.reqs
      (fun e he b r h => reqRec_enc h (hreq e he).1 (hreq e he).2 r) rs _ hrs) ?_
  dsimp only
  split
  rotate_left
  · rename_i hn; exact absurd hcond hn
  have hfin : (⟨a.pin, (if (if a.floor.isSome then 1 else 0) == 1 then some (a.floor.getD 0) else none), a.kfloor,
      a.rsv, a.rs, a.grant, a.keyset, a.release, a.ksteps, a.byps, a.rsets, a.reqs⟩ : Auth) = a := by
    rw [← hA]
  exact congrArg (fun x => (Except.ok (x, r) : Except Word (Auth × Bytes))) hfin

/-! #### The body -/

private theorem encodeBody_some {q : Req} {b : Bytes} (h : encodeBody q = some b) :
    q.prev.length = 64 ∧ (q.batch == 1 || q.asOf == 0) = true ∧ ∃ c n d1 r1 d2 r2 d3 r3 d4 r4 au : Bytes, ∃ rs : List Bytes,
      leAll [4, 4] [q.today, q.asOf] = some c ∧ le 4 q.redo.length = some n ∧
      encFeed dmfC q.dmf = some (d1, r1) ∧ encFeed pdeathC q.pdeath = some (d2, r2) ∧
      encFeed exclC q.excl = some (d3, r3) ∧ encFeed spanC q.span = some (d4, r4) ∧
      q.redo.mapM (le payWidth) = some rs ∧ encAuth q.auth = some au ∧
      b = c ++ q.prev ++ n ++ d1 ++ d2 ++ d3 ++ d4 ++ r1 ++ r2 ++ r3 ++ r4 ++ rs.flatten ++ au := by
  unfold encodeBody at h
  obtain ⟨hg, h⟩ := guard_bind_some h
  obtain ⟨c, hc, h⟩ := obind_some h
  obtain ⟨n, hn, h⟩ := obind_some h
  obtain ⟨⟨d1, r1⟩, h1, h⟩ := obind_some h
  obtain ⟨⟨d2, r2⟩, h2, h⟩ := obind_some h
  obtain ⟨⟨d3, r3⟩, h3, h⟩ := obind_some h
  obtain ⟨⟨d4, r4⟩, h4, h⟩ := obind_some h
  obtain ⟨rs, hrs, h⟩ := obind_some h
  obtain ⟨au, hau, h⟩ := obind_some h
  cases h
  rw [Bool.and_eq_true] at hg
  exact ⟨decide_eq_true_eq.mp hg.1, hg.2, c, n, d1, r1, d2, r2, d3, r3, d4, r4, au, rs, hc, hn, h1, h2, h3, h4, hrs,
    hau, rfl⟩

private theorem encodeBody_of {q : Req} {c n d1 r1 d2 r2 d3 r3 d4 r4 au : Bytes} {rs : List Bytes}
    (hp : q.prev.length = 64) (hb : (q.batch == 1 || q.asOf == 0) = true)
    (hc : leAll [4, 4] [q.today, q.asOf] = some c) (hn : le 4 q.redo.length = some n)
    (h1 : encFeed dmfC q.dmf = some (d1, r1)) (h2 : encFeed pdeathC q.pdeath = some (d2, r2))
    (h3 : encFeed exclC q.excl = some (d3, r3)) (h4 : encFeed spanC q.span = some (d4, r4))
    (hrs : q.redo.mapM (le payWidth) = some rs) (hau : encAuth q.auth = some au) :
    encodeBody q = some (c ++ q.prev ++ n ++ d1 ++ d2 ++ d3 ++ d4 ++ r1 ++ r2 ++ r3 ++ r4 ++ rs.flatten ++ au) := by
  have hg : (q.prev.length = 64 && (q.batch == 1 || q.asOf == 0)) = true := by
    rw [Bool.and_eq_true]; exact ⟨decide_eq_true hp, hb⟩
  unfold encodeBody
  rw [guard_pos hg]
  simp [hc, hn, h1, h2, h3, h4, hrs, hau]

private theorem decodePre_dec {hd : Hdr} {bs : Bytes} {p : Pre} {r : Bytes} (h : decodePre hd bs = .ok (p, r)) :
    p.prev.length = 64 ∧ (hd.batch == 1 || p.asOf == 0) = true ∧ ∃ c n d1 r1 d2 r2 d3 r3 d4 r4 : Bytes, ∃ rs : List Bytes,
      leAll [4, 4] [p.today, p.asOf] = some c ∧ le 4 p.redo.length = some n ∧
      encFeed dmfC p.dmf = some (d1, r1) ∧ encFeed pdeathC p.pdeath = some (d2, r2) ∧
      encFeed exclC p.excl = some (d3, r3) ∧ encFeed spanC p.span = some (d4, r4) ∧
      p.redo.mapM (le payWidth) = some rs ∧
      bs = (c ++ p.prev ++ n ++ d1 ++ d2 ++ d3 ++ d4 ++ r1 ++ r2 ++ r3 ++ r4 ++ rs.flatten) ++ r := by
  unfold decodePre at h
  obtain ⟨⟨ns, s1⟩, h1, h2⟩ := bind_ok _ _ _ h
  have hl := nums_len _ _ _ _ h1
  match ns, hl with
  | [today, asOf], _ =>
    obtain ⟨c, hc, rfl⟩ := leAll_nums _ _ _ _ h1
    obtain ⟨⟨prev, s2⟩, h3, h4⟩ := bind_ok _ _ _ h2
    obtain ⟨⟨nr, s3⟩, h5, h6⟩ := bind_ok _ _ _ h4
    obtain ⟨⟨⟨st1, a1, c1, n1, pin1⟩, s4⟩, h7, h8⟩ := bind_ok _ _ _ h6
    obtain ⟨⟨⟨st2, a2, c2, n2, pin2⟩, s5⟩, h9, h10⟩ := bind_ok _ _ _ h8
    obtain ⟨⟨⟨st3, a3, c3, n3, pin3⟩, s6⟩, h11, h12⟩ := bind_ok _ _ _ h10
    obtain ⟨⟨⟨st4, a4, c4, n4, pin4⟩, s7⟩, h13, h14⟩ := bind_ok _ _ _ h12
    dsimp only at h14
    split at h14
    · rename_i hP
      obtain ⟨⟨dmf, t1⟩, k1, k2⟩ := bind_ok _ _ _ h14
      obtain ⟨⟨pd, t2⟩, k3, k4⟩ := bind_ok _ _ _ k2
      obtain ⟨⟨ex, t3⟩, k5, k6⟩ := bind_ok _ _ _ k4
      obtain ⟨⟨sp, t4⟩, k7, k8⟩ := bind_ok _ _ _ k6
      obtain ⟨⟨rd, t5⟩, k9, k10⟩ := bind_ok _ _ _ k8
      simp only [pure, Except.pure] at k10
      have k11 := Except.ok.inj k10
      simp only [Prod.mk.injEq] at k11
      obtain ⟨rfl, rfl⟩ := k11
      obtain ⟨hpl, rfl⟩ := cut_inv h3
      obtain ⟨bnr, hbnr, rfl⟩ := numRec_eq h5
      obtain ⟨dd1, rb1, e1, rfl, rfl⟩ := feedE_dec dmfC_lawful h7 k1
      obtain ⟨dd2, rb2, e2, rfl, rfl⟩ := feedE_dec pdeathC_lawful h9 k3
      obtain ⟨dd3, rb3, e3, rfl, rfl⟩ := feedE_dec exclC_lawful h11 k5
      obtain ⟨dd4, rb4, e4, rfl, rfl⟩ := feedE_dec spanC_lawful h13 k7
      obtain ⟨hlr, cs, hcs, rfl⟩ := manyE_dec (enc := le payWidth) (fun bs x r h => numRec_eq h) _ _ _ _ k9
      subst hlr
      exact ⟨hpl, hP, c, bnr, dd1, rb1, dd2, rb2, dd3, rb3, dd4, rb4, cs, hc, hbnr, e1, e2, e3, e4, hcs,
        by simp [List.append_assoc]⟩
    · cases h14

private theorem decodePre_enc {hd : Hdr} {p : Pre} {c n d1 r1 d2 r2 d3 r3 d4 r4 : Bytes} {rs : List Bytes}
    (hp : p.prev.length = 64) (hb : (hd.batch == 1 || p.asOf == 0) = true)
    (hc : leAll [4, 4] [p.today, p.asOf] = some c) (hn : le 4 p.redo.length = some n)
    (h1 : encFeed dmfC p.dmf = some (d1, r1)) (h2 : encFeed pdeathC p.pdeath = some (d2, r2))
    (h3 : encFeed exclC p.excl = some (d3, r3)) (h4 : encFeed spanC p.span = some (d4, r4))
    (hrs : p.redo.mapM (le payWidth) = some rs) (r : Bytes) :
    decodePre hd ((c ++ p.prev ++ n ++ d1 ++ d2 ++ d3 ++ d4 ++ r1 ++ r2 ++ r3 ++ r4 ++ rs.flatten) ++ r) = .ok (p, r) := by
  unfold decodePre
  rw [show (c ++ p.prev ++ n ++ d1 ++ d2 ++ d3 ++ d4 ++ r1 ++ r2 ++ r3 ++ r4 ++ rs.flatten) ++ r =
    c ++ (p.prev ++ (n ++ (d1 ++ (d2 ++ (d3 ++ (d4 ++ (r1 ++ (r2 ++ (r3 ++ (r4 ++ (rs.flatten ++ r))))))))))) by simp]
  refine ok_bind _ _ ([p.today, p.asOf], _) _ (nums_leAll' hc _) ?_
  refine ok_bind _ _ (p.prev, _) _ (cut_enc hp _) ?_
  refine ok_bind _ _ (p.redo.length, _) _ (numRec_le hn _) ?_
  refine ok_bind _ _ (_, _) _ (feedE_enc dmfC_lawful p.dmf h1 _ []).1 ?_
  refine ok_bind _ _ (_, _) _ (feedE_enc pdeathC_lawful p.pdeath h2 _ []).1 ?_
  refine ok_bind _ _ (_, _) _ (feedE_enc exclC_lawful p.excl h3 _ []).1 ?_
  refine ok_bind _ _ (_, _) _ (feedE_enc spanC_lawful p.span h4 _ []).1 ?_
  dsimp only
  split
  rotate_left
  · rename_i hn'; exact absurd hb hn'
  refine ok_bind _ _ (_, _) _ (feedE_enc dmfC_lawful p.dmf h1 [] _).2 ?_
  refine ok_bind _ _ (_, _) _ (feedE_enc pdeathC_lawful p.pdeath h2 [] _).2 ?_
  refine ok_bind _ _ (_, _) _ (feedE_enc exclC_lawful p.excl h3 [] _).2 ?_
  refine ok_bind _ _ (_, _) _ (feedE_enc spanC_lawful p.span h4 [] _).2 ?_
  refine ok_bind _ _ (p.redo, _) _
    (manyE_enc (enc := le payWidth) (f := numRec payWidth) p.redo (fun x _ b r h => numRec_le h r) rs _ hrs) ?_
  rfl

private theorem decodeBody_dec {hd : Hdr} {bs r : Bytes} {q : Req} (h : decodeBody hd bs = .ok (q, r)) :
    ∃ b, encodeBody q = some b ∧ bs = b ++ r ∧ q.shard = hd.shard ∧ q.batch = hd.batch ∧ ReqWF q := by
  unfold decodeBody at h
  obtain ⟨⟨p, s1⟩, h1, h2⟩ := bind_ok _ _ _ h
  obtain ⟨⟨au, s2⟩, h3, h4⟩ := bind_ok _ _ _ h2
  obtain ⟨hp, hb, c, n, d1, r1, d2, r2, d3, r3, d4, r4, rs, hc, hn, e1, e2, e3, e4, hrs, rfl⟩ := decodePre_dec h1
  obtain ⟨ab, hab, rfl, hwf⟩ := authRec_dec h3
  simp only [pure, Except.pure] at h4
  have h5 := Except.ok.inj h4
  simp only [Prod.mk.injEq] at h5
  obtain ⟨rfl, rfl⟩ := h5
  exact ⟨_, encodeBody_of hp hb hc hn e1 e2 e3 e4 hrs hab, by simp [List.append_assoc], rfl, rfl, hwf⟩

private theorem decodeBody_enc {hd : Hdr} {q : Req} {b : Bytes} (h : encodeBody q = some b)
    (hs : hd.shard = q.shard) (hbt : hd.batch = q.batch) (hw : ReqWF q) (r : Bytes) :
    decodeBody hd (b ++ r) = .ok (q, r) := by
  obtain ⟨hp, hb, c, n, d1, r1, d2, r2, d3, r3, d4, r4, au, rs, hc, hn, e1, e2, e3, e4, hrs, hau, rfl⟩ :=
    encodeBody_some h
  have hpre := decodePre_enc (hd := hd)
    (p := ⟨q.today, q.asOf, q.prev, q.dmf, q.pdeath, q.excl, q.span, q.redo⟩) hp (by rw [hbt]; exact hb) hc hn e1 e2 e3 e4
    hrs (au ++ r)
  unfold decodeBody
  rw [List.append_assoc]
  refine ok_bind _ _ _ _ hpre ?_
  refine ok_bind _ _ (q.auth, r) _ (authRec_enc hau hw r) ?_
  obtain ⟨sh, bt, dg⟩ := hd
  dsimp only at hs hbt
  subst hs hbt
  rfl

/-! #### The header -/

private theorem decodeHdr_dec {bs body : Bytes} {hd : Hdr} (h : decodeHdr bs = .ok (hd, body)) :
    ∃ hh, leAll [2, 4, 8] [reqVersion, hd.shard, hd.batch] = some hh ∧ hd.digest.length = 64 ∧
      bs = magicReq ++ hh ++ hd.digest ++ body := by
  unfold decodeHdr at h
  rcases ht : takeN hdrBytes bs with _ | ⟨hh, body'⟩
  · rw [ht] at h; cases h
  · rw [ht] at h
    obtain ⟨hl, rfl⟩ := takeN_eq ht
    dsimp only at h
    split at h
    · rename_i hc
      simp only [pure, Except.pure] at h
      have h' := Except.ok.inj h
      simp only [Prod.mk.injEq] at h'
      obtain ⟨rfl, rfl⟩ := h'
      rw [Bool.and_eq_true, beq_iff_eq, beq_iff_eq] at hc
      obtain ⟨hmag, hver⟩ := hc
      have hl' : hh.length = 82 := hl
      have e1 : (hh.drop 4).drop 2 = hh.drop 6 := by simp [List.drop_drop]
      have e2 : (hh.drop 6).drop 4 = hh.drop 10 := by simp [List.drop_drop]
      have e3 : (hh.drop 10).drop 8 = hh.drop 18 := by simp [List.drop_drop]
      have s3 : (hh.drop 10).take 8 ++ hh.drop 18 = hh.drop 10 := by rw [← e3]; exact List.take_append_drop _ _
      have s2 : (hh.drop 6).take 4 ++ hh.drop 10 = hh.drop 6 := by rw [← e2]; exact List.take_append_drop _ _
      have s1 : (hh.drop 4).take 2 ++ hh.drop 6 = hh.drop 4 := by rw [← e1]; exact List.take_append_drop _ _
      have s0 : hh.take 4 ++ hh.drop 4 = hh := List.take_append_drop _ _
      have l1 : ((hh.drop 4).take 2).length = 2 := by simp; omega
      have l2 : ((hh.drop 6).take 4).length = 4 := by simp; omega
      have l3 : ((hh.drop 10).take 8).length = 8 := by simp; omega
      have l4 : (hh.drop 18).length = 64 := by simp; omega
      refine ⟨(hh.drop 4).take 2 ++ ((hh.drop 6).take 4 ++ ((hh.drop 10).take 8 ++ [])), ?_, l4, ?_⟩
      · have a1 := le_unle ((hh.drop 4).take 2)
        have a2 := le_unle ((hh.drop 6).take 4)
        have a3 := le_unle ((hh.drop 10).take 8)
        rw [l1] at a1; rw [l2] at a2; rw [l3] at a3
        rw [← hver]
        simp [leAll_cons, a1, a2, a3, leAll_nil]
      · have hid : hh.take 4 ++ ((hh.drop 4).take 2 ++ ((hh.drop 6).take 4 ++ ((hh.drop 10).take 8 ++ hh.drop 18))) = hh := by
          rw [s3, s2, s1, s0]
        rw [← hmag]
        have e : List.take 4 hh ++ (List.take 2 (List.drop 4 hh) ++ (List.take 4 (List.drop 6 hh) ++
            (List.take 8 (List.drop 10 hh) ++ []))) ++ List.drop 18 hh = hh := by
          simpa [List.append_assoc] using hid
        show hh ++ body' = _ ++ List.drop 18 hh ++ body'
        rw [e]
    · cases h

private theorem decodeHdr_enc {sh bt : Nat} {hh dg : Bytes} (h : leAll [2, 4, 8] [reqVersion, sh, bt] = some hh)
    (hdl : dg.length = 64) (body : Bytes) :
    decodeHdr (magicReq ++ hh ++ dg ++ body) = .ok (⟨sh, bt, dg⟩, body) := by
  obtain ⟨x1, y1, h1, hy1, rfl⟩ := leAll_cons_some h
  obtain ⟨x2, y2, h2, hy2, rfl⟩ := leAll_cons_some hy1
  obtain ⟨x3, y3, h3, hy3, rfl⟩ := leAll_cons_some hy2
  rw [leAll_nil] at hy3
  cases hy3
  have l1 := le_length h1
  have l2 := le_length h2
  have l3 := le_length h3
  obtain ⟨HH, hHH⟩ : ∃ HH, HH = magicReq ++ (x1 ++ (x2 ++ (x3 ++ []))) ++ dg := ⟨_, rfl⟩
  rw [← hHH]
  have hlen : HH.length = hdrBytes := by
    rw [hHH]; simp [magicReq_length, l1, l2, l3, hdl, hdrBytes]
  have v4 : HH = magicReq ++ (x1 ++ (x2 ++ (x3 ++ dg))) := by rw [hHH]; simp
  have v6 : HH = (magicReq ++ x1) ++ (x2 ++ (x3 ++ dg)) := by rw [hHH]; simp
  have v10 : HH = (magicReq ++ x1 ++ x2) ++ (x3 ++ dg) := by rw [hHH]; simp
  have v18 : HH = (magicReq ++ x1 ++ x2 ++ x3) ++ dg := by rw [hHH]; simp
  have t4 : HH.take 4 = magicReq := by rw [v4]; exact List.take_left' magicReq_length
  have d4 : HH.drop 4 = x1 ++ (x2 ++ (x3 ++ dg)) := by rw [v4]; exact List.drop_left' magicReq_length
  have hx1 : (HH.drop 4).take 2 = x1 := by rw [d4]; exact List.take_left' l1
  have d6 : HH.drop 6 = x2 ++ (x3 ++ dg) := by
    rw [v6]; exact List.drop_left' (by simp [magicReq_length, l1])
  have hx2 : (HH.drop 6).take 4 = x2 := by rw [d6]; exact List.take_left' l2
  have d10 : HH.drop 10 = x3 ++ dg := by
    rw [v10]; exact List.drop_left' (by simp [magicReq_length, l1, l2])
  have hx3 : (HH.drop 10).take 8 = x3 := by rw [d10]; exact List.take_left' l3
  have d18 : HH.drop 18 = dg := by
    rw [v18]; exact List.drop_left' (by simp [magicReq_length, l1, l2, l3])
  unfold decodeHdr
  rw [takeN_of_len hlen]
  simp [bind, Except.bind, pure, Except.pure, t4, hx1, hx2, hx3, d18, unle_le _ _ _ h1, unle_le _ _ _ h2,
    unle_le _ _ _ h3]

private theorem decodeReq_inv {bs dg : Bytes} {q : Req} (h : decodeReq bs = .ok (q, dg)) :
    ∃ hh b, leAll [2, 4, 8] [reqVersion, q.shard, q.batch] = some hh ∧ encodeBody q = some b ∧
      dg.length = 64 ∧ bs = magicReq ++ hh ++ dg ++ b ∧ ReqWF q := by
  unfold decodeReq at h
  obtain ⟨⟨hd, body⟩, h1, h2⟩ := bind_ok _ _ _ h
  obtain ⟨hh, hhh, hdl, hbs⟩ := decodeHdr_dec h1
  dsimp only at h2
  obtain ⟨⟨q', rest⟩, h3, h4⟩ := bind_ok _ _ _ h2
  obtain ⟨b, hb, hbody, hsh, hba, hwf⟩ := decodeBody_dec h3
  split at h4
  · rename_i hE
    have hE' : rest = [] := by simpa using hE
    have h4' := Except.ok.inj h4
    simp only [Prod.mk.injEq] at h4'
    obtain ⟨rfl, rfl⟩ := h4'
    subst hE'
    rw [List.append_nil] at hbody
    subst hbody
    refine ⟨hh, body, ?_, hb, hdl, hbs, hwf⟩
    rw [hsh, hba]; exact hhh
  · cases h4

private theorem mapM_len {β γ : Type} {g : β → Option (List γ)} {w : Nat} (hg : ∀ x b, g x = some b → b.length = w) :
    ∀ (xs : List β) (cs : List (List γ)), xs.mapM g = some cs → cs.flatten.length = w * xs.length
  | [], cs, h => by simp at h; subst h; simp
  | x :: xs, cs, h => by
    rw [List.mapM_cons] at h
    obtain ⟨c, hc, h⟩ := obind_some h
    obtain ⟨cs', hcs, h⟩ := obind_some h
    cases h
    rw [List.flatten_cons, List.length_append, hg x c hc, mapM_len hg xs cs' hcs, List.length_cons, Nat.mul_succ]
    omega

private theorem encFeed_len {α : Type} {c : RowCodec α} {f : Feed α} {dd rb : Bytes}
    (h : encFeed c f = some (dd, rb)) : dd.length = 77 ∧ rb.length = c.widths.sum * f.rows.length := by
  unfold encFeed at h
  obtain ⟨hg, h⟩ := guard_bind_some h
  obtain ⟨d, hd, h⟩ := obind_some h
  obtain ⟨rs, hrs, h⟩ := obind_some h
  cases h
  rw [Bool.and_eq_true, Bool.and_eq_true] at hg
  have hpl : f.pin.length = 64 := beq_iff_eq.mp hg.1.2
  refine ⟨?_, mapM_len (fun x b hb => leAll_length _ _ _ hb) f.rows rs hrs⟩
  simp [leAll_length _ _ _ hd, hpl]

private theorem encodeBody_length {q : Req} {b : Bytes} (h : encodeBody q = some b) : b.length = bodyBytes q := by
  obtain ⟨hp, hb, c, n, d1, r1, d2, r2, d3, r3, d4, r4, au, rs, hc, hn, e1, e2, e3, e4, hrs, hau, rfl⟩ :=
    encodeBody_some h
  have lc := leAll_length _ _ _ hc
  have ln := le_length hn
  obtain ⟨a1, a2⟩ := encFeed_len e1
  obtain ⟨b1, b2⟩ := encFeed_len e2
  obtain ⟨c1, c2⟩ := encFeed_len e3
  obtain ⟨d1', d2'⟩ := encFeed_len e4
  have lr := mapM_len (fun x b hb => le_length hb) _ _ hrs
  unfold bodyBytes
  rw [hau]
  simp [lc, ln, hp, a1, a2, b1, b2, c1, c2, d1', d2', lr, dmfC, pdeathC, exclC, spanC]
  omega

/-- Round trip, both ways: the request bytes are canonical, so the digest names the request.  The request must be
    one the decoder can read (`ReqWF`): the encoder does not check that each payment request decodes from its bytes. -/
theorem decodeReq_encodeReq (hH : ∀ x, (H x).length = 64) (hw : ReqWF q) (bs : Bytes) (h : encodeReq H q = some bs) :
    decodeReq bs = .ok (q, frameDigest H (bs.drop hdrBytes)) := by
  unfold encodeReq at h
  obtain ⟨b, hb, h⟩ := obind_some h
  obtain ⟨hh, hhh, h⟩ := obind_some h
  cases h
  have hhl : (magicReq ++ hh ++ frameDigest H b).length = hdrBytes := by
    simp [magicReq_length, leAll_length _ _ _ hhh, hH, hdrBytes, frameDigest]
  have hdrop : (magicReq ++ hh ++ frameDigest H b ++ b).drop hdrBytes = b := by
    rw [← hhl]; exact List.drop_left' rfl
  rw [hdrop]
  unfold decodeReq
  refine ok_bind _ _ (⟨q.shard, q.batch, frameDigest H b⟩, b) _ (decodeHdr_enc (dg := frameDigest H b) hhh (hH (framePre b)) b) ?_
  dsimp only
  refine ok_bind _ _ (q, []) _
    (by simpa using decodeBody_enc (hd := ⟨q.shard, q.batch, frameDigest H b⟩) hb rfl rfl hw []) ?_
  dsimp only
  split
  rotate_left
  · rename_i hn; exact absurd (by simp) hn
  rfl

/-- The decoder does not compare the digest, so this direction needs it said: a frame that decodes, and whose header
    carries the digest of its body (what the host writes and the checker recomputes), is the encoding of its request. -/
theorem encodeReq_decodeReq (bs dg : Bytes) (h : decodeReq bs = .ok (q, dg))
    (hdg : frameDigest H (bs.drop hdrBytes) = dg) : encodeReq H q = some bs := by
  obtain ⟨hh, b, hhh, hb, hdl, hbs, hwf⟩ := decodeReq_inv h
  subst hbs
  have hhl : (magicReq ++ hh ++ dg).length = hdrBytes := by
    simp [magicReq_length, leAll_length _ _ _ hhh, hdl, hdrBytes]
  have hdrop : (magicReq ++ hh ++ dg ++ b).drop hdrBytes = b := by
    rw [← hhl]; exact List.drop_left' rfl
  rw [hdrop] at hdg
  subst hdg
  unfold encodeReq
  rw [hb, hhh]
  rfl

/-- Every request the decoder returns is well-formed, so the round trip above covers every decodable request. -/
theorem decodeReq_wf (bs dg : Bytes) (h : decodeReq bs = .ok (q, dg)) : ReqWF q := by
  obtain ⟨hh, b, hhh, hb, hdl, hbs, hwf⟩ := decodeReq_inv h
  exact hwf

/-- An accepted frame has exactly the length its counts give. -/
theorem decodeReq_length (bs dg : Bytes) (h : decodeReq bs = .ok (q, dg)) :
    bs.length = hdrBytes + bodyBytes q := by
  obtain ⟨hh, b, hhh, hb, hdl, hbs, hwf⟩ := decodeReq_inv h
  rw [hbs, ← encodeBody_length hb]
  simp [leAll_length _ _ _ hhh, magicReq_length, hdl, hdrBytes]
  omega

/-! ### The frame digest (XI.2: one hash of the whole body, which the engine carries) -/

/-- The digest's preimage fixes the body, byte for byte. -/
theorem framePre_inj (a b : Bytes) : framePre a = framePre b ↔ a = b := by
  simp [framePre]

private theorem decodeReq_body {bs dg : Bytes} {q : Req} (h : decodeReq bs = .ok (q, dg)) :
    encodeBody q = some (bs.drop hdrBytes) ∧ ReqWF q := by
  obtain ⟨hh, b, hhh, hb, hdl, rfl, hwf⟩ := decodeReq_inv h
  have hhl : (magicReq ++ hh ++ dg).length = hdrBytes := by
    simp [magicReq_length, leAll_length _ _ _ hhh, hdl, hdrBytes]
  have hdrop : (magicReq ++ hh ++ dg ++ b).drop hdrBytes = b := by
    rw [← hhl]; exact List.drop_left' rfl
  rw [hdrop]
  exact ⟨hb, hwf⟩

/-- A body encodes the same under any shard, and as a first batch (whose genesis date is free). -/
private theorem encodeBody_first {q : Req} {b : Bytes} (h : encodeBody q = some b) :
    encodeBody { q with shard := 0, batch := 1 } = some b := by
  obtain ⟨hp, -, c, n, d1, r1, d2, r2, d3, r3, d4, r4, au, rs, hc, hn, e1, e2, e3, e4, hrs, hau, rfl⟩ :=
    encodeBody_some h
  exact encodeBody_of (q := { q with shard := 0, batch := 1 }) hp (by simp) hc hn e1 e2 e3 e4 hrs hau

/-- The digest binds the frame it is carried in.  Two frames the decoder reads (so within every bound of the format)
    whose bodies have the same preimage have the same body bytes and the same request: the context, the feeds, the
    authority section and every payment request's bytes, in the order sent.  Shard and batch are header fields: the
    digest does not cover them, and never did. -/
theorem frameDigest_binds (bs1 bs2 dg1 dg2 : Bytes) (q1 q2 : Req) (h1 : decodeReq bs1 = .ok (q1, dg1))
    (h2 : decodeReq bs2 = .ok (q2, dg2)) (h : framePre (bs1.drop hdrBytes) = framePre (bs2.drop hdrBytes)) :
    bs1.drop hdrBytes = bs2.drop hdrBytes ∧ q2 = { q1 with shard := q2.shard, batch := q2.batch } := by
  have hb := (framePre_inj _ _).mp h
  refine ⟨hb, ?_⟩
  obtain ⟨e1, w1⟩ := decodeReq_body h1
  obtain ⟨e2, w2⟩ := decodeReq_body h2
  rw [← hb] at e2
  have k1 := decodeBody_enc (hd := ⟨0, 1, []⟩) (encodeBody_first e1) rfl rfl w1 []
  have k2 := decodeBody_enc (hd := ⟨0, 1, []⟩) (encodeBody_first e2) rfl rfl w2 []
  have k := (Prod.mk.inj (Except.ok.inj (k1.symm.trans k2))).1
  cases q1
  cases q2
  simp at k
  simp [k]

/-! ### The answer -/

theorem decodeAns_encodeAns (a : AnsFrame) (bs : Bytes) (h : encodeAns a = some bs) : decodeAns bs = some a := by
  obtain ⟨w, k, b, dg, recs, head, root, ext⟩ := a
  unfold encodeAns at h
  replace h := guard_bind_some h; obtain ⟨hd, h⟩ := h
  replace h := guard_bind_some h; obtain ⟨hw, h⟩ := h
  replace h := obind_some h; obtain ⟨hb, hhb, h⟩ := h
  replace h := obind_some h; obtain ⟨rs, hrs, h⟩ := h
  dsimp only at h hd hw hhb hrs
  have hdl : dg.toList.length = 64 := by rw [← Flat.Bin.size_eq_length']; exact hd
  have hbl : hb.length = 19 := leAll_length _ _ _ hhb
  have hlen : (magicAns ++ hb ++ dg.toList).length = ansHdrBytes := by simp [magic_length, hbl, hdl, ansHdrBytes]
  have htake : (magicAns ++ hb ++ dg.toList).take 4 = magicAns := by rw [List.append_assoc, List.take_left' magic_length]
  have hdrop : (magicAns ++ hb ++ dg.toList).drop 4 = hb ++ dg.toList := by
    rw [List.append_assoc, List.drop_left' magic_length]
  split at h
  · rename_i hwo
    obtain rfl : w = .OK := by simpa using hwo
    replace h := obind_some h; obtain ⟨x, hx, h⟩ := h
    cases h
    obtain ⟨hhs, hrs', hsort⟩ : head.size = 64 ∧ root.size = 64 ∧
        (recs.map (·.index)).mergeSort (fun i j => decide (i ≤ j)) = List.range recs.length := by
      simpa [and_assoc] using hw
    have hhl : head.toList.length = 64 := by rw [← Flat.Bin.size_eq_length']; exact hhs
    have hrl : root.toList.length = 64 := by rw [← Flat.Bin.size_eq_length']; exact hrs'
    have hm := fun r => manyO_enc decRec_encRec recs rs r hrs
    have he := decExt_encExt ext x [] hx
    rw [List.append_nil] at he
    rw [show magicAns ++ hb ++ dg.toList ++ rs.flatten ++ head.toList ++ root.toList ++ x =
      (magicAns ++ hb ++ dg.toList) ++ (rs.flatten ++ (head.toList ++ (root.toList ++ x))) by simp]
    unfold decodeAns
    rw [takeN_of_len hlen]
    simp only [some_bind]
    rw [htake, hdrop, nums_leAll' hhb]
    simp [Except.toOption, guard, words_code, hm, takeN_of_len hhl, takeN_of_len hrl, he, hsort, ba_list]
  · rename_i hwo
    have hne : w ≠ .OK := by simpa using hwo
    cases h
    obtain ⟨hr0, hh0, hr0', rfl⟩ : recs = [] ∧ head.isEmpty = true ∧ root.isEmpty = true ∧
        ext = ⟨.empty, .empty, .empty, [], [], []⟩ := by
      simpa [hne, and_assoc] using hw
    subst hr0
    simp at hrs
    subst hrs
    obtain rfl := isEmpty_ba hh0
    obtain rfl := isEmpty_ba hr0'
    simp only [List.flatten_nil, empty_toList, List.append_nil]
    rw [← List.append_nil (magicAns ++ hb ++ dg.toList)]
    unfold decodeAns
    rw [takeN_of_len hlen]
    simp only [some_bind]
    rw [htake, hdrop, nums_leAll' hhb]
    simp [Except.toOption, guard, words_code, hne, ba_list]

theorem encodeAns_decodeAns (a : AnsFrame) (bs : Bytes) (h : decodeAns bs = some a) : encodeAns a = some bs := by
  unfold decodeAns at h
  replace h := obind_some h; obtain ⟨⟨hh, r⟩, h1, h⟩ := h
  obtain ⟨hl, hbs⟩ := takeN_eq h1
  dsimp only at h
  replace h := guard_bind_some h; obtain ⟨hm, h⟩ := h
  replace h := obind_some h; obtain ⟨⟨ns, dg⟩, hn, h⟩ := h
  have hn := toOption_ok hn
  obtain ⟨hb, hhb, hdrop⟩ := leAll_nums _ _ _ _ hn
  match ns, nums_len _ _ _ _ hn with
  | [v, st, k, b, n], _ =>
    dsimp only at h
    replace h := guard_bind_some h; obtain ⟨hv, h⟩ := h
    replace h := obind_some h; obtain ⟨w, hw, h⟩ := h
    have hc := code_of hw
    subst hc
    obtain rfl : v = version := by simpa using hv
    have hbl : hb.length = 19 := leAll_length _ _ _ hhb
    have hsplit : hh = magicAns ++ hb ++ dg := by
      rw [← List.take_append_drop 4 hh, hdrop, (by simpa using hm : hh.take 4 = magicAns)]; simp
    have hdl : dg.length = 64 := by
      have := congrArg List.length hsplit; simp [magic_length, hbl, hl, ansHdrBytes] at this; omega
    split at h
    · rename_i hwo
      obtain rfl : w = .OK := by simpa using hwo
      replace h := obind_some h; obtain ⟨⟨recs, r1⟩, h2, h⟩ := h
      dsimp only at h
      replace h := obind_some h; obtain ⟨⟨head, r2⟩, h3, h⟩ := h
      dsimp only at h
      replace h := obind_some h; obtain ⟨⟨root, r3⟩, h4, h⟩ := h
      dsimp only at h
      replace h := obind_some h; obtain ⟨⟨ext, r4⟩, h5, h⟩ := h
      dsimp only at h
      replace h := guard_bind_some h; obtain ⟨hg, h⟩ := h
      cases h
      simp only [Bool.and_eq_true, List.isEmpty_iff, beq_iff_eq] at hg
      obtain ⟨rfl, hsort⟩ := hg
      obtain ⟨hrn, cs, hcs, hr⟩ := manyO_dec encRec_decRec _ _ _ _ h2
      obtain ⟨hhl, hr1⟩ := takeN_eq h3
      obtain ⟨hrl, hr2⟩ := takeN_eq h4
      obtain ⟨xc, hxc, hr3⟩ := encExt_decExt _ _ _ h5
      subst hrn hbs hsplit hr hr1 hr2 hr3
      simp [encodeAns, guard, hdl, hhl, hrl, hsort, hhb, hcs, hxc, list_ba, List.size_toByteArray]
    · rename_i hwo
      have hne : w ≠ .OK := by simpa using hwo
      replace h := guard_bind_some h; obtain ⟨hg, h⟩ := h
      cases h
      simp only [Bool.and_eq_true, beq_iff_eq, List.isEmpty_iff] at hg
      obtain ⟨rfl, rfl⟩ := hg
      subst hbs hsplit
      simp [encodeAns, guard, hdl, hne, hhb, list_ba, List.size_toByteArray, ByteArray.isEmpty]

private theorem place_mem : ∀ (pool : List (Nat × Line)) (ls : List Line) (p : Nat), p ∈ place pool ls →
    ∃ x ∈ pool, x.1 = p
  | _, [], p, h => by simp [place] at h
  | pool, l :: ls, p, h => by
    simp only [place] at h
    split at h
    · rename_i x hx
      rcases List.mem_cons.mp h with rfl | h
      · exact ⟨x, List.mem_of_find?_eq_some hx, rfl⟩
      · obtain ⟨y, hy, rfl⟩ := place_mem _ ls p h
        exact ⟨y, List.mem_of_mem_erase hy, rfl⟩
    · exact place_mem pool ls p h

private theorem kept_mem {dv : Derived} {x : Nat × Line} (h : x ∈ kept dv) :
    dv.lines[x.1]? = some x.2 ∧ (Run.unfit dv.lines).contains x.2.pay = false := by
  unfold kept at h
  obtain ⟨⟨l, k⟩, hm, hf⟩ := List.mem_filterMap.mp h
  dsimp only at hf
  split at hf
  · cases hf
  · rename_i hc
    cases hf
    exact ⟨List.mem_zipIdx_iff_getElem?.mp hm, by simpa using hc⟩

private theorem find_append_none {α : Type} {p : α → Bool} {xs ys : List α} (h : ∀ x ∈ xs, p x = false) :
    (xs ++ ys).find? p = ys.find? p := by
  rw [List.find?_append, List.find?_eq_none.mpr (fun x hx => by simp [h x hx]), Option.none_or]

/-- Among lines with their positions, the first entry a map keeps at position `i` is the one line `i` gives. -/
private theorem find_zipIdx {β : Type} (ls : List Line) (g : Line × Nat → Option (Nat × β))
    (hg : ∀ x y, g x = some y → y.1 = x.2) {i : Nat} {l : Line} {y : Nat × β} (hi : ls[i]? = some l)
    (hy : g (l, i) = some y) : (ls.zipIdx.filterMap g).find? (·.1 == i) = some y := by
  rw [List.find?_filterMap]
  have hmem : (l, i) ∈ ls.zipIdx := List.mem_zipIdx_iff_getElem?.mpr hi
  cases hf : ls.zipIdx.find? (fun a => (g a).any (·.1 == i)) with
  | none =>
    have := List.find?_eq_none.mp hf _ hmem
    simp [hy, hg _ _ hy] at this
  | some x =>
    have hp := List.find?_some hf
    have hxm := List.mem_zipIdx_iff_getElem?.mp (List.mem_of_find?_eq_some hf)
    cases hgx : g x with
    | none => simp [hgx] at hp
    | some z =>
      simp only [hgx, Option.any_some, beq_iff_eq] at hp
      have h2 : x.2 = i := (hg _ _ hgx).symm.trans hp
      rw [h2, hi] at hxm
      have hx : x = (l, i) := Prod.ext (Option.some.inj hxm).symm h2
      subst hx
      simp only [Option.bind_some]
      exact hy

/-- A line of a payment held for width is found, by its position, among the held lines. -/
private theorem answers_find {i : Nat} {l : Line} {a : Ans} (hi : dv.lines[i]? = some l)
    (hk : (Run.unfit dv.lines).contains l.pay = true)
    (ha : (if !Run.fits l then some (i, Ans.wide l)
      else if (Run.unfit dv.lines).contains l.pay then some (i, Ans.sibling l) else none) = some (i, a)) :
    (answers H s q dv).find? (·.1 == i) = some (i, a) := by
  unfold answers
  refine (find_append_none ?_).trans (find_zipIdx _ _ ?_ hi ha)
  · -- the decided lines take positions of kept lines only, and line `i`'s payment is not kept
    intro x hx
    obtain ⟨hx1, -⟩ := List.of_mem_zip hx
    obtain ⟨y, hy, hyx⟩ := place_mem _ _ _ hx1
    obtain ⟨hl, hc⟩ := kept_mem hy
    cases he : (x.1 == i)
    · rfl
    · have hyi : y.1 = i := hyx.trans (beq_iff_eq.mp he)
      rw [hyi, hi] at hl
      have hl := Option.some.inj hl
      subst hl
      rw [hk] at hc
      cases hc
  · rintro ⟨l', j⟩ y h
    dsimp only at h
    split at h
    · cases h; rfl
    · split at h
      · cases h; rfl
      · cases h

private theorem find?_map_of {α β : Type} {f : α → β} {p : β → Bool} {p' : α → Bool} {l : List α} {a : α}
    (hpq : ∀ x, p (f x) = p' x) (h : l.find? p' = some a) : (l.map f).find? p = some (f a) := by
  rw [List.find?_map]
  have : (p ∘ f) = p' := funext hpq
  rw [this, h]
  rfl

private theorem unfit_of {l : Line} {i : Nat} (hi : dv.lines[i]? = some l) (hw : Run.fits l = false) :
    (Run.unfit dv.lines).contains l.pay = true := by
  rw [Run.unfit, Std.HashSet.contains_ofList, List.contains_iff_mem]
  exact List.mem_map.mpr ⟨l, List.mem_filter.mpr ⟨List.mem_of_getElem? hi, by simp [hw]⟩, rfl⟩

/-- A line with a field over its stored width answers HOLD UNENCODABLE_FIELD (rule 3). -/
theorem wide_hold (i : Nat) (l : Line) (hi : dv.lines[i]? = some l) (hw : Run.fits l = false) :
    (records H loc s q dv).find? (·.index == i) = some ⟨i, 1, .wide, 0, none⟩ := by
  have ha := answers_find (H := H) (s := s) (q := q) (dv := dv) (a := .wide l) hi (unfit_of dv hi hw) (by simp [hw])
  unfold records
  exact find?_map_of (fun x => by obtain ⟨j, a⟩ := x; cases a <;> rfl) ha

/-- The other lines of its payment answer HOLD UNENCODABLE_PAYMENT (rule 4). -/
theorem sibling_hold (i : Nat) (l : Line) (hi : dv.lines[i]? = some l) (hw : Run.fits l = true)
    (hp : (Run.unfit dv.lines).contains l.pay) :
    (records H loc s q dv).find? (·.index == i) = some ⟨i, 1, .sibling, 0, none⟩ := by
  have ha := answers_find (H := H) (s := s) (q := q) (dv := dv) (a := .sibling l) hi hp (by simp [hw, hp])
  unfold records
  exact find?_map_of (fun x => by obtain ⟨j, a⟩ := x; cases a <;> rfl) ha

/-- `place` pairs every decision with a position when the decided lines are the pool's lines. -/
theorem place_spec {α : Type} (f : α → Line) : ∀ (as : List α) (pool : List (Nat × Line)),
    (as.map f).Perm (pool.map (·.2)) →
    (place pool (as.map f)).Perm (pool.map (·.1)) ∧ ∀ y ∈ (place pool (as.map f)).zip as, (y.1, f y.2) ∈ pool
  | [], pool, h => by
    have : pool = [] := by
      have := h.length_eq
      simpa using this.symm
    subst this
    simp [place]
  | a :: as, pool, h => by
    have hm : f a ∈ pool.map (·.2) := h.subset (List.mem_cons_self ..)
    obtain ⟨p, hp, hpa⟩ := List.mem_map.mp hm
    obtain ⟨p', hf⟩ : ∃ p', pool.find? (·.2 == f a) = some p' := by
      cases hf : pool.find? (·.2 == f a) with
      | none => exact absurd (List.find?_eq_none.mp hf p hp) (by simp [hpa])
      | some p' => exact ⟨p', rfl⟩
    have hp'mem := List.mem_of_find?_eq_some hf
    have hp'2 : p'.2 = f a := by simpa using List.find?_some hf
    have h2 : (as.map f).Perm ((pool.erase p').map (·.2)) := by
      have h3 := (List.perm_cons_erase hp'mem).map (·.2)
      have h4 := h.trans h3
      simp only [List.map_cons, hp'2] at h4
      exact h4.cons_inv
    obtain ⟨ih1, ih2⟩ := place_spec f as _ h2
    have hpl : place pool (f a :: as.map f) = p'.1 :: place (pool.erase p') (as.map f) := by
      simp only [place, hf]
    rw [List.map_cons, hpl]
    refine ⟨?_, ?_⟩
    · have h4 := (List.perm_cons_erase hp'mem).map (·.1)
      simp only [List.map_cons] at h4
      exact (ih1.cons _).trans h4.symm
    · intro y hy
      rw [List.zip_cons_cons] at hy
      rcases List.mem_cons.mp hy with rfl | hy
      · have : (p'.1, f a) = p' := by rw [← hp'2]
        simp only
        rw [this]; exact hp'mem
      · exact List.mem_of_mem_erase (ih2 y hy)

/-- The kept and the held positions together are all the positions. -/
theorem part_perm (U : Std.HashSet Nat) : ∀ (L : List Line) (n : Nat),
    (∀ l ∈ L, Run.fits l = false → U.contains l.pay = true) →
    (((L.zipIdx n).filterMap fun (l, i) => if U.contains l.pay then none else some (i, l)).map (·.1) ++
     ((L.zipIdx n).filterMap fun (l, i) =>
        if !Run.fits l then some (i, Ans.wide l)
        else if U.contains l.pay then some (i, Ans.sibling l) else none).map (·.1)).Perm (List.range' n L.length)
  | [], n, _ => by simp
  | l :: L, n, h => by
    have ih := part_perm U L (n + 1) (fun l' hl' => h l' (List.mem_cons_of_mem _ hl'))
    simp only [List.zipIdx_cons, List.filterMap_cons, List.length_cons, List.range'_succ]
    by_cases hc : U.contains l.pay = true
    · by_cases hf : Run.fits l = true
      · simp only [hc, hf, if_true, Bool.not_true, Bool.false_eq_true, if_false, List.map_cons, ↓reduceIte]
        exact List.perm_middle.trans (ih.cons _)
      · have hf' : Run.fits l = false := by simpa using hf
        simp only [hc, hf', if_true, Bool.not_false, List.map_cons, ↓reduceIte]
        exact List.perm_middle.trans (ih.cons _)
    · have hf : Run.fits l = true := by
        cases hfl : Run.fits l with
        | true => rfl
        | false => exact absurd (h l (List.mem_cons_self ..) hfl) hc
      simp only [hc, hf, Bool.not_true, Bool.false_eq_true, if_false, List.map_cons, List.cons_append]
      exact ih.cons _

theorem decideAll_map_line (x : Ix) : ∀ (S : Std.HashSet Key) (ls : List Line), (x.decideAll S ls).map (·.line) = ls
  | _, [] => rfl
  | S, l :: ls => by
    simp only [Ix.decideAll, List.map_cons]
    exact congrArg (l :: ·) (decideAll_map_line x _ ls)

theorem order_perm_ix (x : Ix) (b : List Line) : (x.order b).Perm b := by
  unfold Ix.order canonical
  exact ((List.mergeSort_perm _ _).append (List.mergeSort_perm _ _)).trans (List.filter_append_perm _ _)

open BlindLedger.Gate.OnepIndex in
theorem map_cap_line (ds : List Decision) (c : Decision → Bool) :
    (ds.map fun d => if c d then capD d else d).map (·.line) = ds.map (·.line) := by
  rw [List.map_map]
  exact List.map_congr_left fun d _ => by simp only [Function.comp]; split <;> rfl

theorem decidedOf_lines : ((decidedOf H s q dv).ds.map (·.line)).Perm ((kept dv).map (·.2)) := by
  unfold decidedOf decideFetched
  dsimp only
  rw [map_cap_line, decideAll_map_line]
  exact order_perm_ix _ _

/-- The lines held for width, with their positions (`answers`'s second part). -/
def heldOf (dv : Derived) : List (Nat × Ans) :=
  dv.lines.zipIdx.filterMap fun (l, i) =>
    if !Run.fits l then some (i, Ans.wide l)
    else if (Run.unfit dv.lines).contains l.pay then some (i, Ans.sibling l) else none

theorem answers_eq : answers H s q dv =
    ((place (kept dv) ((decidedOf H s q dv).ds.map (·.line))).zip (decidedOf H s q dv).ds).map
      (fun y => (y.1, Ans.rules y.2)) ++ heldOf dv := by
  unfold answers heldOf
  dsimp only
  rw [List.zip_map_right]
  rfl

theorem place_len : (place (kept dv) ((decidedOf H s q dv).ds.map (·.line))).length = (decidedOf H s q dv).ds.length := by
  have hp := decidedOf_lines H s q dv
  have e1 := (place_spec (fun d : Decision => d.line) (decidedOf H s q dv).ds (kept dv) hp).1.length_eq
  have e2 := hp.length_eq
  simp only [List.length_map] at e1 e2
  omega

theorem unfit_of_mem (L : List Line) {l : Line} (hl : l ∈ L) (hf : Run.fits l = false) :
    (Run.unfit L).contains l.pay = true := by
  rw [Run.unfit, Std.HashSet.contains_ofList, List.contains_iff_mem]
  exact List.mem_map.mpr ⟨l, List.mem_filter.mpr ⟨hl, by simp [hf]⟩, rfl⟩

theorem kept_map (U : Std.HashSet Nat) : ∀ (L : List Line) (n : Nat),
    ((L.zipIdx n).filterMap fun (l, i) => if U.contains l.pay then none else some (i, l)).map (·.2) =
      L.filter fun l => !U.contains l.pay
  | [], n => rfl
  | l :: L, n => by
    simp only [List.zipIdx_cons, List.filterMap_cons, List.filter_cons]
    cases hc : U.contains l.pay
    · simp only [hc, Bool.false_eq_true, Bool.not_false, ↓reduceIte, List.map_cons]
      exact congrArg (l :: ·) (kept_map U L (n + 1))
    · simp only [hc, Bool.not_true, ↓reduceIte, Bool.false_eq_true]
      exact kept_map U L (n + 1)

theorem kept_lines : (kept dv).map (·.2) = Run.keep dv.lines := kept_map _ _ 0

theorem fits_keep {L : List Line} {l : Line} (hl : l ∈ Run.keep L) : Run.fits l = true := by
  unfold Run.keep at hl
  obtain ⟨hl, hc⟩ := List.mem_filter.mp hl
  cases hf : Run.fits l with
  | true => rfl
  | false => rw [unfit_of_mem L hl hf] at hc; cases hc

theorem unfit_keep (L : List Line) (p : Nat) : (Run.unfit (Run.keep L)).contains p = false := by
  have : (Run.keep L).filter (!Run.fits ·) = [] :=
    List.filter_eq_nil_iff.mpr fun l hl => by simp [fits_keep hl]
  unfold Run.unfit
  rw [this, Std.HashSet.contains_ofList]
  simp

theorem keep_keep (L : List Line) : Run.keep (Run.keep L) = Run.keep L := by
  exact List.filter_eq_self.mpr fun l _ => by simp [unfit_keep]

theorem heldOf_keep : heldOf { dv with lines := Run.keep dv.lines } = [] := by
  unfold heldOf
  refine List.filterMap_eq_nil_iff.mpr ?_
  rintro ⟨l, i⟩ hm
  have hl : l ∈ Run.keep dv.lines := List.mem_of_getElem? (List.mem_zipIdx_iff_getElem?.mp hm)
  simp [fits_keep hl, unfit_keep]

theorem decided_keep : decidedOf H s q { dv with lines := Run.keep dv.lines } = decidedOf H s q dv := by
  have hk : (kept { dv with lines := Run.keep dv.lines }).map (·.2) = (kept dv).map (·.2) := by
    rw [kept_lines, kept_lines]
    exact keep_keep _
  unfold decidedOf
  rw [hk]
  rfl

theorem zipA_snd : (((place (kept dv) ((decidedOf H s q dv).ds.map (·.line))).zip (decidedOf H s q dv).ds).map
      fun y => (y.1, Ans.rules y.2)).map (·.2) = (decidedOf H s q dv).ds.map Ans.rules := by
  rw [List.map_map]
  have : ((·.2) ∘ fun y : Nat × Decision => (y.1, Ans.rules y.2)) = Ans.rules ∘ (·.2) := rfl
  rw [this, ← List.map_map, List.map_snd_zip (Nat.le_of_eq (place_len H s q dv).symm)]

theorem answers_snd : (answers H s q dv).map (·.2) =
    (decidedOf H s q dv).ds.map Ans.rules ++ (heldOf dv).map (·.2) := by
  rw [answers_eq, List.map_append, zipA_snd]

theorem answers_filter : ((answers H s q dv).filter (!·.2.widthHeld)).map (·.2) =
    (decidedOf H s q dv).ds.map Ans.rules := by
  rw [answers_eq, List.filter_append]
  have h1 : (((place (kept dv) ((decidedOf H s q dv).ds.map (·.line))).zip (decidedOf H s q dv).ds).map
      fun y => (y.1, Ans.rules y.2)).filter (!·.2.widthHeld) = ((place (kept dv)
        ((decidedOf H s q dv).ds.map (·.line))).zip (decidedOf H s q dv).ds).map fun y => (y.1, Ans.rules y.2) :=
    List.filter_eq_self.mpr fun a ha => by
      obtain ⟨y, _, rfl⟩ := List.mem_map.mp ha
      rfl
  have h2 : (heldOf dv).filter (!·.2.widthHeld) = [] :=
    List.filter_eq_nil_iff.mpr fun a ha => by
      obtain ⟨⟨l, i⟩, _, hl⟩ := List.mem_filterMap.mp ha
      dsimp only at hl
      split at hl
      · cases hl; simp [Ans.widthHeld]
      · split at hl
        · cases hl; simp [Ans.widthHeld]
        · cases hl
  rw [h1, h2, List.append_nil, zipA_snd]

/-- Every other line answers as if the held payments' lines were not there. -/
theorem wide_local :
    let dv' := { dv with lines := Run.keep dv.lines }
    ((answers H s q dv).filter (!·.2.widthHeld)).map (·.2) = (answers H s q dv').map (·.2) := by
  intro dv'
  rw [answers_filter, answers_snd, show dv' = { dv with lines := Run.keep dv.lines } from rfl, heldOf_keep,
    decided_keep]
  simp


/-- Every decided line has exactly one record. -/
theorem records_perm :
    ((records H loc s q dv).map (·.index)).Perm (List.range dv.lines.length) := by
  have e : (records H loc s q dv).map (·.index) = (answers H s q dv).map (·.1) := by
    unfold records
    rw [List.map_map]
    exact List.map_congr_left (fun x _ => by obtain ⟨i, a⟩ := x; cases a <;> rfl)
  rw [e, answers_eq, List.map_append, List.map_map]
  have hz : ((place (kept dv) ((decidedOf H s q dv).ds.map (·.line))).zip (decidedOf H s q dv).ds).map
      ((·.1) ∘ fun y => (y.1, Ans.rules y.2)) = place (kept dv) ((decidedOf H s q dv).ds.map (·.line)) := by
    exact List.map_fst_zip (Nat.le_of_eq (place_len H s q dv))
  rw [hz]
  have hpp := (place_spec (fun d : Decision => d.line) (decidedOf H s q dv).ds (kept dv) (decidedOf_lines H s q dv)).1
  have hpart := part_perm (Run.unfit dv.lines) dv.lines 0 (fun l hl hf => unfit_of_mem dv.lines hl hf)
  rw [List.range_eq_range']
  exact (hpp.append_right _).trans hpart


/-! ### Reasons are canonical -/

theorem reason_mem (r : Reason) : r ∈ reasons := by cases r <;> decide

/-- Bit `j` of a partial `maskOf` fold. -/
theorem maskOf_fold_testBit (rs : List Reason) (j : Nat) : ∀ (L : List Reason) (m : Nat),
    (L.foldl (fun m r => if rs.contains r then m ||| 2 ^ r.idx else m) m).testBit j =
      (m.testBit j || L.any fun r => rs.contains r && decide (r.idx = j))
  | [], m => by simp
  | r :: L, m => by
    rw [List.foldl_cons, maskOf_fold_testBit rs j L]
    cases hc : rs.contains r
    · simp only [Bool.false_eq_true, ↓reduceIte, List.any_cons, hc, Bool.false_and, Bool.false_or]
    · simp only [↓reduceIte, Nat.testBit_or, Nat.testBit_two_pow, List.any_cons, hc, Bool.true_and, Bool.or_assoc]

theorem maskOf_testBit (rs : List Reason) (j : Nat) :
    (maskOf rs).testBit j = reasons.any fun r => rs.contains r && decide (r.idx = j) := by
  unfold maskOf
  rw [maskOf_fold_testBit]
  simp

/-- The mask's bit `r.idx` is set exactly when `r` is listed (bits are distinct: `Reason.idx_inj`). -/
theorem maskOf_testBit_idx (rs : List Reason) (r : Reason) : (maskOf rs).testBit r.idx = rs.contains r := by
  rw [maskOf_testBit, Bool.eq_iff_iff, List.any_eq_true]
  constructor
  · rintro ⟨r', -, h⟩
    simp only [Bool.and_eq_true, decide_eq_true_eq] at h
    rw [← Reason.idx_inj h.2]
    exact h.1
  · intro h
    exact ⟨r, reason_mem r, by simp only [h, Bool.true_and, decide_eq_true_eq]⟩

theorem unmask_maskOf {p : Reason → Bool} : unmask (maskOf (reasons.filter p)) = reasons.filter p := by
  unfold unmask
  exact List.filter_congr fun r hr => by
    rw [maskOf_testBit_idx]
    simp [hr]
theorem decideAll_canon (x : Ix) : ∀ (S : Std.HashSet Key) (ls : List Line), ∀ d ∈ x.decideAll S ls,
    (∃ p : Reason → Bool, d.reasons = reasons.filter p) ∧ d.counterparts = x.counterparts d.line
  | _, [], d, hd => by simp [Ix.decideAll] at hd
  | S, l :: ls, d, hd => by
    simp only [Ix.decideAll, List.mem_cons] at hd
    rcases hd with rfl | hd
    · exact ⟨⟨x.fires S l, rfl⟩, rfl⟩
    · exact decideAll_canon x _ ls d hd

theorem decidedOf_canon {d : Decision} (hd : d ∈ (decidedOf H s q dv).ds) :
    (∃ p : Reason → Bool, d.reasons = reasons.filter p) ∧
      d.counterparts = (decidedOf H s q dv).x.counterparts d.line := by
  unfold decidedOf decideFetched at hd ⊢
  dsimp only at hd ⊢
  obtain ⟨d0, hd0, rfl⟩ := List.mem_map.mp hd
  obtain ⟨⟨p, hp⟩, hc⟩ := decideAll_canon _ _ _ d0 hd0
  split
  · exact ⟨⟨fun r => r == .POSTING_CAP || d0.reasons.contains r, rfl⟩, hc⟩
  · exact ⟨⟨p, hp⟩, hc⟩

theorem ruleOf_ne (d : Decided) (e : Decision) : ruleOf d e ≠ .wide ∧ ruleOf d e ≠ .sibling := by
  unfold ruleOf
  split
  · exact ⟨by decide, by decide⟩
  · split
    · exact ⟨by decide, by decide⟩
    · split <;> exact ⟨by decide, by decide⟩

theorem outOf_outCode (o : Outcome) : outOf (outCode o) = some o := by cases o <;> rfl

theorem join_rules {i : Nat} {e : Decision} (hl : dv.lines[i]? = some e.line)
    (hm : unmask (maskOf e.reasons) = e.reasons)
    (hc : (decidedOf H s q dv).x.counterparts e.line = e.counterparts) :
    join H s q dv (recOf loc (decidedOf H s q dv) i (.rules e)) = some (.rules e) := by
  obtain ⟨h1, h2⟩ := ruleOf_ne (decidedOf H s q dv) e
  unfold join
  simp only [recOf, hl, Option.bind_some]
  cases hr : ruleOf (decidedOf H s q dv) e
  · simp [hm, hc, outOf_outCode]
  · simp [hm, hc, outOf_outCode]
  · simp [hm, hc, outOf_outCode]
  · exact absurd hr h1
  · exact absurd hr h2
  · simp [hm, hc, outOf_outCode]

/-- The record binds the decision: joined with the lines and the state before the batch, each record is that line's
    answer (decision, reasons, outcome and counterparts included). -/
theorem record_binds :
    (records H loc s q dv).map (join H s q dv) = (answers H s q dv).map (some ·.2) := by
  unfold records
  rw [List.map_map]
  refine List.map_congr_left fun y hy => ?_
  obtain ⟨i, a⟩ := y
  show join H s q dv (recOf loc (decidedOf H s q dv) i a) = some a
  rw [answers_eq] at hy
  rcases List.mem_append.mp hy with hy | hy
  · obtain ⟨⟨j, e⟩, hz, hfe⟩ := List.mem_map.mp hy
    simp only [Prod.mk.injEq] at hfe
    obtain ⟨rfl, rfl⟩ := hfe
    obtain ⟨he, hpool⟩ := place_spec (fun d : Decision => d.line) (decidedOf H s q dv).ds (kept dv)
      (decidedOf_lines H s q dv)
    have hmem := hpool _ hz
    have hed := (List.of_mem_zip hz).2
    obtain ⟨hcan, hcp⟩ := decidedOf_canon H s q dv hed
    obtain ⟨p, hp⟩ := hcan
    exact join_rules H loc s q dv (kept_mem hmem).1 (by rw [hp]; exact unmask_maskOf) hcp.symm
  · obtain ⟨⟨l, k⟩, hm, hl⟩ := List.mem_filterMap.mp hy
    dsimp only at hl
    have hlk := List.mem_zipIdx_iff_getElem?.mp hm
    split at hl
    · cases hl
      unfold join
      simp [recOf, hlk]
    · split at hl
      · cases hl
        unfold join
        simp [recOf, hlk]
      · cases hl


/-! ### The rows the batch appends -/

theorem rule_bool (a1 a2 a3 b1 b2 o1 o2 ad : Bool) :
    let r := if (a1 && !a2 && a3) = true then Rule.released
      else if (b1 || b2 && !o1) = true then Rule.bypassed
      else if (!a1 && !ad && !o1 && !o2) = true then Rule.unresolved else Rule.decided
    ((r == .released || r == .bypassed) = (a1 && !a2 && a3 || b1 || b2 && !o1)) ∧
      ((r == .unresolved) = (!a1 && !ad && !o1 && !o2 && !b1 && !b2)) := by
  cases a1 <;> cases a2 <;> cases a3 <;> cases b1 <;> cases b2 <;> cases o1 <;> cases o2 <;> cases ad <;> decide

theorem ruleOf_pred (d : Decided) (e : Decision) :
    (ruleOf d e == .released || ruleOf d e == .bypassed) =
      ((e.outcome == .ALLOW && !d.x.redo.contains e.line.pay && d.x.payOutcome d.ds e.line.pay == .ALLOW) ||
        d.x.bypassed d.ds e.line.pay || d.x.limitedPay d.ds e.line.pay && !d.x.own e.line) ∧
    (ruleOf d e == .unresolved) =
      (e.outcome != .ALLOW && !e.reasons.contains .ALREADY_DECIDED && !d.x.own e.line && !d.x.ownU e.line &&
        !d.x.bypassed d.ds e.line.pay && !d.x.limitedPay d.ds e.line.pay) := by
  unfold ruleOf
  simp only [bne]
  exact rule_bool _ _ _ _ _ _ _ _

theorem filterMap_eq_map_of {α γ : Type} {φ : α → Option γ} {ψ : α → γ} {l : List α}
    (h : ∀ x ∈ l, φ x = some (ψ x)) : l.filterMap φ = l.map ψ := by
  induction l with
  | nil => rfl
  | cons a l ih =>
    rw [List.filterMap_cons, h a (List.mem_cons_self ..), List.map_cons, ih fun x hx => h x (List.mem_cons_of_mem _ hx)]

theorem filterMap_recs (G : Rule → Bool) (d : Decided) (T : List (Nat × Decision))
    (hT : ∀ y ∈ T, dv.lines[y.1]? = some y.2.line) :
    ((T.map fun y => recOf loc d y.1 (.rules y.2)).filter fun r => G r.rule).filterMap (fun r => dv.lines[r.index]?) =
      ((T.map (·.2)).filter fun e => G (ruleOf d e)).map (·.line) := by
  rw [List.filter_map, List.filterMap_map, List.filter_map, List.map_map]
  rw [filterMap_eq_map_of (ψ := fun y : Nat × Decision => y.2.line)]
  · rfl
  · intro y hy
    exact hT y ((List.mem_filter.mp hy).1)

theorem records_eq : records H loc s q dv =
    ((place (kept dv) ((decidedOf H s q dv).ds.map (·.line))).zip (decidedOf H s q dv).ds).map
      (fun y => recOf loc (decidedOf H s q dv) y.1 (.rules y.2)) ++
    (heldOf dv).map (fun y => recOf loc (decidedOf H s q dv) y.1 y.2) := by
  unfold records
  rw [answers_eq, List.map_append, List.map_map]
  rfl

/-- The rows the batch appends, in order, are the lines of the rule 1, rule 5 and rule 2 records (the host rebuilds the
    batch digest from them). -/
theorem rows_of_records :
    ((records H loc s q dv).filter (fun r => r.rule == .released || r.rule == .bypassed)).filterMap
        (fun r => dv.lines[r.index]?) = (decidedOf H s q dv).fr ∧
      ((records H loc s q dv).filter (·.rule == .unresolved)).filterMap (fun r => dv.lines[r.index]?) =
        (decidedOf H s q dv).fu := by
  have hT : ∀ y ∈ (place (kept dv) ((decidedOf H s q dv).ds.map (·.line))).zip (decidedOf H s q dv).ds,
      dv.lines[y.1]? = some y.2.line := fun y hy =>
    (kept_mem ((place_spec (fun d : Decision => d.line) (decidedOf H s q dv).ds (kept dv)
      (decidedOf_lines H s q dv)).2 y hy)).1
  have hsnd : (((place (kept dv) ((decidedOf H s q dv).ds.map (·.line))).zip (decidedOf H s q dv).ds).map (·.2)) =
      (decidedOf H s q dv).ds := List.map_snd_zip (Nat.le_of_eq (place_len H s q dv).symm)
  have hheld : ∀ r ∈ (heldOf dv).map (fun y => recOf loc (decidedOf H s q dv) y.1 y.2),
      r.rule = .wide ∨ r.rule = .sibling := by
    intro r hr
    obtain ⟨⟨i, a⟩, hm, rfl⟩ := List.mem_map.mp hr
    obtain ⟨⟨l, k⟩, -, hl⟩ := List.mem_filterMap.mp hm
    dsimp only at hl
    split at hl
    · cases hl; exact Or.inl rfl
    · split at hl
      · cases hl; exact Or.inr rfl
      · cases hl
  refine ⟨?_, ?_⟩
  · rw [records_eq, List.filter_append]
    have h0 : ((heldOf dv).map (fun y => recOf loc (decidedOf H s q dv) y.1 y.2)).filter
        (fun r => r.rule == .released || r.rule == .bypassed) = [] :=
      List.filter_eq_nil_iff.mpr fun r hr => by
        rcases hheld r hr with h | h <;> simp [h]
    rw [h0, List.append_nil]
    have := filterMap_recs loc dv (fun ρ : Rule => ρ == Rule.released || ρ == Rule.bypassed) (decidedOf H s q dv) _ hT
    rw [this, hsnd]
    show _ = (decidedOf H s q dv).x.releasedLines (decidedOf H s q dv).ds
    unfold Ix.releasedLines
    congr 1
    exact List.filter_congr fun e _ => (ruleOf_pred (decidedOf H s q dv) e).1
  · rw [records_eq, List.filter_append]
    have h0 : ((heldOf dv).map (fun y => recOf loc (decidedOf H s q dv) y.1 y.2)).filter
        (fun r => r.rule == .unresolved) = [] :=
      List.filter_eq_nil_iff.mpr fun r hr => by
        rcases hheld r hr with h | h <;> simp [h]
    rw [h0, List.append_nil]
    have := filterMap_recs loc dv (fun ρ : Rule => ρ == Rule.unresolved) (decidedOf H s q dv) _ hT
    rw [this, hsnd]
    show _ = (decidedOf H s q dv).x.unresolvedLines (decidedOf H s q dv).ds
    unfold Ix.unresolvedLines
    congr 1
    exact List.filter_congr fun e _ => (ruleOf_pred (decidedOf H s q dv) e).2


/-! ### The answer always encodes -/

theorem leAll_isSome : ∀ (ws ns : List Nat), ws.length = ns.length →
    (∀ p ∈ ws.zip ns, p.2 < 256 ^ p.1) → (leAll ws ns).isSome
  | [], [], _, _ => by
    have e : leAll [] [] = some [] := rfl
    rw [e]; rfl
  | [], _ :: _, h, _ => absurd h (by simp)
  | _ :: _, [], h, _ => absurd h (by simp)
  | w :: ws, n :: ns, hl, hp => by
    have h1 : (le w n).isSome := by
      unfold le
      rw [if_pos (hp (w, n) (List.mem_cons_self ..))]
      rfl
    have h2 := leAll_isSome ws ns (by simpa using hl) (fun p hp' => hp p (List.mem_cons_of_mem (w, n) hp'))
    obtain ⟨x, hx⟩ := Option.isSome_iff_exists.mp h1
    obtain ⟨y, hy⟩ := Option.isSome_iff_exists.mp h2
    rw [leAll_cons, hx, hy]
    rfl

theorem mapM_isSome {α β : Type} {f : α → Option β} : ∀ (xs : List α), (∀ x ∈ xs, (f x).isSome) →
    (xs.mapM f).isSome
  | [], _ => by simp
  | x :: xs, h => by
    obtain ⟨a, ha⟩ := Option.isSome_iff_exists.mp (h x (List.mem_cons_self ..))
    obtain ⟨bs, hbs⟩ := Option.isSome_iff_exists.mp (mapM_isSome xs fun y hy => h y (List.mem_cons_of_mem _ hy))
    simp [List.mapM_cons, ha, hbs]

theorem maskOf_fold_lt (rs : List Reason) : ∀ (L : List Reason) (m : Nat), m < 2 ^ reasons.length →
    L.foldl (fun m r => if rs.contains r then m ||| 2 ^ r.idx else m) m < 2 ^ reasons.length
  | [], _, h => h
  | r :: L, m, h => by
    rw [List.foldl_cons]
    refine maskOf_fold_lt rs L _ ?_
    split
    · exact Nat.or_lt_two_pow h (Nat.pow_lt_pow_right (by decide) (BlindLedger.Gate.Rules.idx_len r))
    · exact h

theorem maskOf_lt (rs : List Reason) : maskOf rs < 2 ^ reasons.length :=
  maskOf_fold_lt rs reasons 0 (Nat.two_pow_pos _)

theorem maskOf_zero_iff {p : Reason → Bool} : maskOf (reasons.filter p) = 0 ↔ reasons.filter p = [] := by
  constructor
  · intro h
    have := unmask_maskOf (p := p)
    rw [h] at this
    rw [← this]
    simp [unmask]
  · intro h
    rw [h]
    exact (by decide : maskOf [] = 0)

theorem decideAll_out (x : Ix) : ∀ (S : Std.HashSet Key) (ls : List Line), ∀ d ∈ x.decideAll S ls,
    d.outcome = outcomeOf d.reasons
  | _, [], d, hd => by simp [Ix.decideAll] at hd
  | S, l :: ls, d, hd => by
    simp only [Ix.decideAll, List.mem_cons] at hd
    rcases hd with rfl | hd
    · rfl
    · exact decideAll_out x _ ls d hd

theorem decidedOf_out {d : Decision} (hd : d ∈ (decidedOf H s q dv).ds) : d.outcome = outcomeOf d.reasons := by
  unfold decidedOf decideFetched at hd
  dsimp only at hd
  obtain ⟨d0, hd0, rfl⟩ := List.mem_map.mp hd
  have := decideAll_out _ _ _ d0 hd0
  split
  · rfl
  · exact this

theorem rule_bool2 (a1 a2 a3 b1 b2 o1 o2 ad : Bool) :
    let r := if (a1 && !a2 && a3) = true then Rule.released
      else if (b1 || b2 && !o1) = true then Rule.bypassed
      else if (!a1 && !ad && !o1 && !o2) = true then Rule.unresolved else Rule.decided
    (r = .released → a1 = true) ∧ (r = .unresolved → a1 = false) := by
  cases a1 <;> cases a2 <;> cases a3 <;> cases b1 <;> cases b2 <;> cases o1 <;> cases o2 <;> cases ad <;> decide

theorem ruleOf_out (d : Decided) (e : Decision) :
    (ruleOf d e = .released → (e.outcome == .ALLOW) = true) ∧
      (ruleOf d e = .unresolved → (e.outcome == .ALLOW) = false) := by
  unfold ruleOf
  simp only [bne]
  exact rule_bool2 _ _ _ _ _ _ _ _

theorem firstRef_ok (hl : ∀ u k c w, loc u k = some (c, w) → c < noChunk ∧ w < noRow) (x : Ix) (l : Line) :
    ∀ c w, firstRef loc x l = some (c, w) → c < noChunk ∧ w < noRow := by
  intro c w h
  unfold firstRef at h
  dsimp only at h
  split at h
  · exact hl _ _ c w h
  · obtain ⟨k, -, hk⟩ := Option.bind_eq_some_iff.mp h
    exact hl _ _ c w hk

theorem outCode_zero (o : Outcome) : (outCode o == 0) = (o == .ALLOW) := by cases o <;> rfl
theorem outCode_le (o : Outcome) : outCode o ≤ 2 := by cases o <;> decide
theorem outCode_12 (o : Outcome) (h : (o == .ALLOW) = false) : (outCode o == 1 || outCode o == 2) = true := by
  cases o <;> first | rfl | exact absurd h (by decide)

theorem ref_match {ref : Option (Nat × Nat)} :
    (∀ c w, ref = some (c, w) → c < noChunk ∧ w < noRow) →
      (match ref with | some (c, w) => c < noChunk && w < noRow | none => true) = true := by
  intro hr
  cases ref with
  | none => rfl
  | some p =>
    obtain ⟨c, w⟩ := p
    obtain ⟨h1, h2⟩ := hr c w rfl
    simp [h1, h2]

theorem ok_rules (i : Nat) (e : Decision) (d : Decided) (ref : Option (Nat × Nat))
    (hi : i < 2 ^ 24) (hout : e.outcome = outcomeOf e.reasons) (hcan : ∃ p : Reason → Bool, e.reasons = reasons.filter p)
    (hr : ∀ c w, ref = some (c, w) → c < noChunk ∧ w < noRow) :
    (⟨i, outCode e.outcome, ruleOf d e, maskOf e.reasons, ref⟩ : Rec).ok = true := by
  obtain ⟨p, hp⟩ := hcan
  have hz : maskOf e.reasons = 0 ↔ e.reasons = [] := by rw [hp]; exact maskOf_zero_iff
  have ha : e.outcome = .ALLOW ↔ e.reasons = [] := by rw [hout]; exact outcomeOf_allow
  have hm0 : (maskOf e.reasons == 0) = (e.outcome == .ALLOW) := by
    rw [Bool.eq_iff_iff]
    simp only [beq_iff_eq]
    exact hz.trans ha.symm
  have hml := maskOf_lt e.reasons
  obtain ⟨hrel, hunr⟩ := ruleOf_out d e
  obtain ⟨hw, hs⟩ := ruleOf_ne d e
  unfold Rec.ok
  simp only [Bool.and_eq_true, decide_eq_true_eq]
  refine ⟨⟨⟨hi, hml⟩, ref_match hr⟩, ?_⟩
  generalize ruleOf d e = R at hrel hunr hw hs ⊢
  cases R
  · simp [outCode_le, outCode_zero, hm0]
  · have h := hrel rfl
    simp [outCode_zero, hm0, h]
  · have h := hunr rfl
    have hnz : maskOf e.reasons ≠ 0 := by
      intro h0
      have h1 : (maskOf e.reasons == 0) = true := by simp [h0]
      rw [hm0, h] at h1
      cases h1
    simp [outCode_12 _ h, hnz]
  · exact absurd rfl hw
  · exact absurd rfl hs
  · simp [outCode_le, outCode_zero, hm0]

theorem ok_outcome {r : Rec} (h : r.ok = true) : r.outcome < 3 := by
  obtain ⟨i, o, ru, m, ref⟩ := r
  show o < 3
  cases ru <;> simp only [Rec.ok, Bool.and_eq_true, decide_eq_true_eq, beq_iff_eq, Bool.or_eq_true] at h <;> omega

theorem ref_fits {ref : Option (Nat × Nat)}
    (h : (match ref with | some (c, w) => c < noChunk && w < noRow | none => true) = true) :
    (ref.getD (noChunk, noRow)).1 < 256 ^ 4 ∧ (ref.getD (noChunk, noRow)).2 < 256 ^ 3 := by
  have e4 : (256 : Nat) ^ 4 = 4294967296 := by decide
  have e3 : (256 : Nat) ^ 3 = 16777216 := by decide
  rw [e4, e3]
  cases ref with
  | none => simp [noChunk, noRow]
  | some p =>
    obtain ⟨c, w⟩ := p
    simp only [Bool.and_eq_true, decide_eq_true_eq] at h
    simp only [Option.getD_some]
    unfold noChunk noRow at h
    constructor <;> omega

theorem encRec_some (r : Rec) (h : r.ok = true) : (encRec r).isSome := by
  have h' := h
  obtain ⟨i, o, ru, m, ref⟩ := r
  have ho : o < 3 := ok_outcome h
  simp only [Rec.ok, Bool.and_eq_true, decide_eq_true_eq] at h'
  obtain ⟨⟨⟨hi, hm⟩, hrf⟩, hrule⟩ := h'
  obtain ⟨hc, hw⟩ := ref_fits hrf
  have hidx : rules.idxOf ru < 256 := by cases ru <;> decide
  have e1 : (256 : Nat) ^ 1 = 256 := by decide
  have e3 : (256 : Nat) ^ 3 = 16777216 := by decide
  have e4 : (256 : Nat) ^ 4 = 4294967296 := by decide
  have e24 : (2 : Nat) ^ 24 = 16777216 := by decide
  have hL : (leAll [3, 1, 1, 8, 4, 3] [i, o, rules.idxOf ru, m, (ref.getD (noChunk, noRow)).1,
      (ref.getD (noChunk, noRow)).2]).isSome := by
    refine leAll_isSome _ _ rfl ?_
    intro p hp
    simp only [List.zip_cons_cons, List.zip_nil_left, List.mem_cons, List.not_mem_nil, or_false] at hp
    rcases hp with rfl | rfl | rfl | rfl | rfl | rfl
    · show i < 256 ^ 3
      omega
    · show o < 256 ^ 1
      omega
    · show rules.idxOf ru < 256 ^ 1
      omega
    · show m < 256 ^ 8
      have h64 : 2 ^ Rules.reasons.length ≤ 2 ^ 64 :=
        Nat.pow_le_pow_right (by decide) (Nat.le_trans BlindLedger.Gate.Rules.reasons_len_le (by decide))
      have e8 : (256 : Nat) ^ 8 = 2 ^ 64 := by decide
      rw [e8]
      exact Nat.lt_of_lt_of_le hm h64
    · exact hc
    · exact hw
  unfold encRec
  rw [guard_pos h]
  exact hL


theorem records_ok (hn : dv.lines.length < 2 ^ 24)
    (hl : ∀ u k c w, loc u k = some (c, w) → c < noChunk ∧ w < noRow) :
    ∀ r ∈ records H loc s q dv, r.ok = true := by
  intro r hr
  rw [records_eq] at hr
  rcases List.mem_append.mp hr with hr | hr
  · obtain ⟨⟨i, e⟩, hz, rfl⟩ := List.mem_map.mp hr
    obtain ⟨-, hpool⟩ := place_spec (fun d : Decision => d.line) (decidedOf H s q dv).ds (kept dv)
      (decidedOf_lines H s q dv)
    have hli : dv.lines[i]? = some e.line := (kept_mem (hpool _ hz)).1
    have hi : i < 2 ^ 24 := Nat.lt_trans (List.getElem?_eq_some_iff.mp hli).1 hn
    have he := (List.of_mem_zip hz).2
    exact ok_rules i e _ _ hi (decidedOf_out H s q dv he) (decidedOf_canon H s q dv he).1
      (firstRef_ok loc hl _ _)
  · obtain ⟨⟨i, a⟩, hm, rfl⟩ := List.mem_map.mp hr
    obtain ⟨⟨l, k⟩, hm', hl'⟩ := List.mem_filterMap.mp hm
    dsimp only at hl'
    have hlk : dv.lines[k]? = some l := List.mem_zipIdx_iff_getElem?.mp hm'
    have hk : k < 2 ^ 24 := Nat.lt_trans (List.getElem?_eq_some_iff.mp hlk).1 hn
    have hp0 : 0 < 2 ^ reasons.length := Nat.two_pow_pos _
    split at hl'
    · cases hl'
      simp [recOf, Rec.ok, hk, hp0]
    · split at hl'
      · cases hl'
        simp [recOf, Rec.ok, hk, hp0]
      · cases hl'

/-- The engine can always send its answer. -/
theorem answer_encodes (hn : dv.lines.length < 2 ^ 24)
    (hk : q.shard < 2 ^ 32) (hb : q.batch < 2 ^ 64)
    (hl : ∀ u k c w, loc u k = some (c, w) → c < noChunk ∧ w < noRow) (dg head root : Bytes)
    (h64 : dg.length = 64 ∧ head.length = 64 ∧ root.length = 64) (ext : Ext) (hx : (encExt ext).isSome) :
    (encodeAns (answerOf H loc s q dv dg head root ext)).isSome := by
  obtain ⟨hdg, hhd, hrt⟩ := h64
  have hrecs := records_ok H loc s q dv hn hl
  have hperm := records_perm H loc s q dv
  have hlen : (records H loc s q dv).length = dv.lines.length := by
    have := hperm.length_eq
    simpa using this
  have hsort : (((records H loc s q dv).map (·.index)).mergeSort (fun i j => decide (i ≤ j)) ==
      List.range (records H loc s q dv).length) = true := by
    rw [beq_iff_eq, hlen]
    have hS : (((records H loc s q dv).map (·.index)).mergeSort (fun i j => decide (i ≤ j))).Pairwise
        (· ≤ ·) :=
      (List.pairwise_mergeSort (le := fun i j : Nat => decide (i ≤ j))
        (fun a b c h1 h2 => by simp at h1 h2 ⊢; omega) (fun a b => by simp; omega) _).imp
        (fun h => of_decide_eq_true h)
    exact List.Perm.eq_of_pairwise (le := (· ≤ ·)) (fun a b _ _ h1 h2 => Nat.le_antisymm h1 h2) hS
      List.pairwise_le_range ((List.mergeSort_perm _ _).trans hperm)
  have e1 : (256 : Nat) ^ 1 = 256 := by decide
  have e2 : (256 : Nat) ^ 2 = 65536 := by decide
  have e4 : (256 : Nat) ^ 4 = 4294967296 := by decide
  have e8 : (256 : Nat) ^ 8 = 18446744073709551616 := by decide
  have e24 : (2 : Nat) ^ 24 = 16777216 := by decide
  have e32 : (2 : Nat) ^ 32 = 4294967296 := by decide
  have e64 : (2 : Nat) ^ 64 = 18446744073709551616 := by decide
  have hh : (leAll [2, 1, 4, 8, 4] [version, Word.OK.code, q.shard, q.batch, (records H loc s q dv).length]).isSome := by
    refine leAll_isSome _ _ rfl ?_
    intro p hp
    simp only [List.zip_cons_cons, List.zip_nil_left, List.mem_cons, List.not_mem_nil, or_false] at hp
    rcases hp with rfl | rfl | rfl | rfl | rfl
    · show version < 256 ^ 2
      rw [e2]; decide
    · show Word.OK.code < 256 ^ 1
      rw [e1]; decide
    · show q.shard < 256 ^ 4
      rw [e4]; omega
    · show q.batch < 256 ^ 8
      rw [e8]; omega
    · show (records H loc s q dv).length < 256 ^ 4
      rw [e4, hlen]; omega
  obtain ⟨hb', hhb⟩ := Option.isSome_iff_exists.mp hh
  obtain ⟨rs, hrs⟩ := Option.isSome_iff_exists.mp
    (mapM_isSome (f := encRec) (records H loc s q dv) (fun r hr => encRec_some r (hrecs r hr)))
  obtain ⟨xb, hxb⟩ := Option.isSome_iff_exists.mp hx
  simp [encodeAns, answerOf, guard, hdg, hhd, hrt, hsort, hhb, hrs, hxb, List.size_toByteArray]


end

private theorem unle_lt (b : Bytes) : unle b < 256 ^ b.length := by
  have := le_unle b
  unfold le at this
  split at this
  · assumption
  · cases this

private theorem le_some {w n : Nat} (h : n < 256 ^ w) :
    le w n = some ((List.range w).map fun i => (n / 256 ^ i % 256).toUInt8) := by
  simp [le, h]

/-- A decoded header's shard and batch fit their fields and its digest is 64 bytes. -/
private theorem decodeHdr_fits {bs body : Bytes} {hd : Hdr} (h : decodeHdr bs = .ok (hd, body)) :
    hd.shard < 256 ^ 4 ∧ hd.batch < 256 ^ 8 ∧ hd.digest.length = 64 := by
  unfold decodeHdr at h
  by_cases hn : hdrBytes ≤ bs.length
  · simp [takeN, hn, bind, Except.bind, pure, Except.pure] at h
    split at h
    · obtain ⟨rfl, rfl⟩ := Prod.mk.inj (Except.ok.inj h)
      refine ⟨Nat.lt_of_lt_of_le (unle_lt _) (Nat.pow_le_pow_right (by decide) ?_),
        Nat.lt_of_lt_of_le (unle_lt _) (Nat.pow_le_pow_right (by decide) ?_), ?_⟩ <;>
        simp [hdrBytes] at hn ⊢ <;> omega
    · cases h
  · simp [takeN, hn] at h

/-- The refusal of a request whose header decoded carries the refusal's word. -/
private theorem refusal_word {w : Word} (hw : w ≠ .OK) {bs body : Bytes} {hd : Hdr}
    (h : decodeHdr bs = .ok (hd, body)) :
    (decodeAns (refusal w ((decodeHdr bs).toOption.map (·.1)))).map (·.word) = some w := by
  obtain ⟨hs, hb, hg⟩ := decodeHdr_fits h
  have hc : w.code < 256 ^ 1 := by cases w <;> decide
  have hm : (decodeHdr bs).toOption.map (·.1) = some hd := by rw [h]; rfl
  have hL : leAll [2, 1, 4, 8, 4] [version, w.code, hd.shard, hd.batch, 0] =
      some (((List.range 2).map fun i => (version / 256 ^ i % 256).toUInt8) ++
        (((List.range 1).map fun i => (w.code / 256 ^ i % 256).toUInt8) ++
        (((List.range 4).map fun i => (hd.shard / 256 ^ i % 256).toUInt8) ++
        (((List.range 8).map fun i => (hd.batch / 256 ^ i % 256).toUInt8) ++
        (((List.range 4).map fun i => (0 / 256 ^ i % 256).toUInt8) ++ []))))) := by
    simp only [leAll_cons, le_some (w := 2) (n := version) (by decide), le_some hc, le_some hs, le_some hb,
      le_some (w := 4) (n := 0) (by decide), leAll_nil, Option.bind_some, Option.map_some]
  obtain ⟨x, hx⟩ : ∃ x, encodeAns ⟨w, hd.shard, hd.batch, hd.digest.toByteArray, [], .empty, .empty,
      ⟨.empty, .empty, .empty, [], [], []⟩⟩ = some x := by
    simp [encodeAns, guard, hw, hL, hg, List.size_toByteArray, ByteArray.isEmpty]
  rw [hm]
  simp only [refusal, Option.getD_some, hx]
  rw [decodeAns_encodeAns _ _ hx]
  rfl

/-- An admitted batch is the next one, of the engine's shard, following its head. -/
private theorem admit_decide {σ : Type} {H : Bytes → Bytes} {e : Eng σ} {q : Req} {dg : Bytes}
    (h : admit H e q dg = .decide) :
    q.shard = e.shard ∧ q.batch = e.log.length + 1 ∧
      q.prev = e.head.getD (chainStart H q.shard q.auth.pin (genesis q.asOf)) := by
  unfold admit at h
  try dsimp only at h
  split at h
  · cases h
  · rename_i h1
    split at h
    · rename_i h2
      split at h
      · rename_i h3
        exact ⟨by simpa using h1, beq_iff_eq.mp h2, beq_iff_eq.mp h3⟩
      · cases h
    · split at h
      · split at h
        · split at h <;> cases h
        · cases h
      · cases h

/-- A decoded request's header decoded. -/
private theorem decodeReq_hdr {bs dg : Bytes} {q : Req} (h : decodeReq bs = .ok (q, dg)) :
    ∃ hd body, decodeHdr bs = .ok (hd, body) := by
  unfold decodeReq at h
  obtain ⟨⟨hd, body⟩, hh, -⟩ := bind_ok _ _ _ h
  exact ⟨hd, body, hh⟩

section
variable {σ : Type} (H : Bytes → Bytes) (dec : Eng σ → Req → Except Word (σ × Bytes × Bytes)) (e : Eng σ) (bs : Bytes)

/-- A resent frame gets the logged answer, byte for byte, and changes nothing. -/
theorem serve_retry (e' : Eng σ) (a : Bytes) (h : serve H dec e bs = (e', a))
    (hd : e'.log.length = e.log.length + 1) : serve H dec e' bs = (e', a) := by
  -- only a decided batch grows the log; resent, it is the logged batch with the logged identity
  unfold serve at h
  cases hq : decodeReq bs with
  | error w => simp only [hq] at h; cases h; omega
  | ok p =>
    obtain ⟨q, dg⟩ := p
    simp only [hq] at h
    cases ha : admit H e q (ident H bs q) with
    | refuse w => simp only [ha] at h; cases h; omega
    | replay a' => simp only [ha] at h; cases h; omega
    | decide =>
      simp only [ha] at h
      cases hdc : dec e q with
      | error w => simp only [hdc] at h; cases h; omega
      | ok r =>
        obtain ⟨st, h', a'⟩ := r
        simp only [hdc] at h
        cases h
        obtain ⟨h1, h2, -⟩ := admit_decide ha
        simp [serve, hq, admit, h1, h2]

/-- The logged batch number with another identity is refused. -/
theorem serve_conflict (q : Req) (dg : Bytes) (h : decodeReq bs = .ok (q, dg)) (hk : q.shard = e.shard)
    (hb : q.batch = e.log.length) (h0 : 0 < q.batch) (hne : e.log.getLast?.map (·.1) ≠ some (ident H bs q)) :
    (serve H dec e bs).1 = e ∧ (decodeAns (serve H dec e bs).2).map (·.word) = some .CONFLICT := by
  obtain ⟨hd, body, hh⟩ := decodeReq_hdr h
  have h0' : 0 < e.log.length := hb ▸ h0
  have hA : admit H e q (ident H bs q) = .refuse .CONFLICT := by
    unfold admit
    cases hl : e.log.getLast? with
    | none => simp at hl; simp [hl] at h0'
    | some p =>
      obtain ⟨d, a⟩ := p
      rw [hl] at hne
      have hd : d ≠ ident H bs q := by simpa using hne
      simp [hk, hb, h0', hd]
  unfold serve
  rw [h]
  dsimp only
  rw [hA]
  exact ⟨rfl, refusal_word (by decide) hh⟩

/-- Any batch number but the next or the last logged is refused. -/
theorem serve_not_next (q : Req) (dg : Bytes) (h : decodeReq bs = .ok (q, dg)) (hk : q.shard = e.shard)
    (hb : q.batch ≠ e.log.length + 1) (hl : q.batch ≠ e.log.length ∨ q.batch = 0) :
    (serve H dec e bs).1 = e ∧ (decodeAns (serve H dec e bs).2).map (·.word) = some .NOT_NEXT := by
  obtain ⟨hd, body, hh⟩ := decodeReq_hdr h
  have hA : admit H e q (ident H bs q) = .refuse .NOT_NEXT := by
    unfold admit
    try dsimp only
    split
    · rename_i h1; simp [hk] at h1
    · split
      · rename_i h2; exact absurd (beq_iff_eq.mp h2) hb
      · split
        · rename_i h3
          simp only [Bool.and_eq_true, beq_iff_eq, decide_eq_true_eq] at h3
          omega
        · rfl
  unfold serve
  rw [h]
  dsimp only
  rw [hA]
  exact ⟨rfl, refusal_word (by decide) hh⟩

/-- The log changes only by the next batch, following the engine's head, logged with its identity and the bytes sent. -/
theorem serve_log :
    (serve H dec e bs).1 = e ∨ ∃ q dg, decodeReq bs = .ok (q, dg) ∧ q.shard = e.shard ∧
      q.batch = e.log.length + 1 ∧ q.prev = e.head.getD (chainStart H q.shard q.auth.pin (genesis q.asOf)) ∧
      (serve H dec e bs).1.log = e.log ++ [(ident H bs q, (serve H dec e bs).2)] := by
  cases hq : decodeReq bs with
  | error w => left; simp [serve, hq]
  | ok p =>
    obtain ⟨q, dg⟩ := p
    cases ha : admit H e q (ident H bs q) with
    | refuse w => left; simp [serve, hq, ha]
    | replay a => left; simp [serve, hq, ha]
    | decide =>
      cases hdc : dec e q with
      | error w => left; simp [serve, hq, ha, hdc]
      | ok r =>
        obtain ⟨st, h', a⟩ := r
        obtain ⟨h1, h2, h3⟩ := admit_decide ha
        right
        exact ⟨q, dg, rfl, h1, h2, h3, by simp [serve, hq, ha, hdc]⟩

end

end BlindLedger.Gate.Frame
