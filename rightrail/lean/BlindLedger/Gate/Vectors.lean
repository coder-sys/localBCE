import BlindLedger.Gate.Verify
import BlindLedger.Gate.Frame.Spec
import BlindLedger.Gate.Cosign.Verify

namespace BlindLedger.Gate.Vectors

open BlindLedger.Gate

/-! Conformance check of `tests/gate_vectors/gate_v1.vectors` against the Lean
    specification.  Lines run in order against one payer state: `cert`,
    `payment` (a `send`), `checkpoint` and `release` lines are the payer's own
    steps (and are checked); `grants` and `now` lines set context.  A payment
    line is kept under its name even when its send is refused; an `unsent`
    one only records the payment and checks it has no pin.  `root` lines set
    the tenants' root public keys; a `cert` line is a whole KEY-CERT (one that
    does not decode can only be `reject`); signatures are verified by the
    real ML-DSA-87 verifier (`realCrypto`), and `mldsa87` lines
    check it against known answers.  A checkpoint line
    expects `accept` (stored), `fork`
    (recorded as a fork) or `reject`.  Accepted request, response and
    checkpoint lines, and tokens that decode, list the decoded fields they must
    yield; a response line
    names the decoded request it answers, and a `reissue` (`redecide`) line
    checks `reissues` (`redecides`) on the latest revision and two tokens.  An accepted `answer` line (an engine answer,
    `Frame.decodeAns`) lists its decoded fields and must encode back to the same bytes.  In
    `tests/gate_vectors/key_cert_v2.vectors` a `link` line adds an authority link to the tenant's chain (another tenant starts a chain;
    its last field is the closing epoch of the generation before, `-` for none), a `genesis` line with the same fields
    starts a new chain of the same tenant from a later generation and retires the links of the chain it replaces, and a
    `key-cert` line is a whole KEY-CERT/v2 verified against the current chain (`Cosign.verify`): it expects `accept` or the refusal code, and lists the decoded
    fields whenever the bytes decode.  The last line, `end N`, is the number
    of checked lines; anything else is a FAIL.  Test-only: this executable is
    never a release path. -/

def nibble (c : Char) : Option Nat :=
  if '0' ≤ c && c ≤ '9' then some (c.toNat - 48)
  else if 'a' ≤ c && c ≤ 'f' then some (c.toNat - 87) else none

def unhex : List Char → Option Bytes
  | [] => some []
  | a :: b :: rest => do pure (UInt8.ofNat ((← nibble a) * 16 + (← nibble b)) :: (← unhex rest))
  | _ => none

def hex (s : String) : Option Bytes := unhex s.toList
def ascii (s : String) : Bytes := s.toUTF8.toList

def hexDigit (n : Nat) : Char := Char.ofNat (if n < 10 then 48 + n else 87 + n)
def toHex (b : Bytes) : String :=
  String.ofList (b.flatMap fun x => [hexDigit (x.toNat / 16), hexDigit (x.toNat % 16)])
def text (b : Bytes) : String := String.ofList (b.map fun x => Char.ofNat x.toNat)

def list {α : Type} (f : String → Option α) : String → Option (List α)
  | "-" => some []
  | s => (s.splitOn ",").mapM f

def hexList : List Bytes → String
  | [] => "-"
  | xs => ",".intercalate (xs.map toHex)

def flowNames : List (String × WireFlow) :=
  [("FFS_CYCLE", .FFS_CYCLE), ("FFS_CLAIM", .FFS_CLAIM), ("CAP_820", .CAP_820), ("SDP", .SDP),
   ("PLAN_PAY", .PLAN_PAY)]

def nameOf {α : Type} [BEq α] (names : List (String × α)) (x : α) : String :=
  ((names.find? (·.2 == x)).map (·.1)).getD "?"

def statusNames : List (String × Status) :=
  [("DECIDED", .DECIDED), ("DUPLICATE", .DUPLICATE), ("REJECTED", .REJECTED),
   ("UNAVAILABLE", .UNAVAILABLE), ("PAYMENT_ALREADY_DECIDED", .PAYMENT_ALREADY_DECIDED)]

def rejectNames : List (String × RejectCode) :=
  [("MALFORMED", .MALFORMED), ("COMMAND_KEY_CONFLICT", .COMMAND_KEY_CONFLICT)]

def renderRequest (r : Request) : List String :=
  [text r.tenantId, text r.programId, nameOf flowNames r.flow, text r.commandKey,
   text r.paymentId, toHex r.memberKey, text r.payeeRef, toString r.amountCents, text r.period, hexList r.lines,
   hexList r.evidenceRefs]

def renderResponse (r : Response) : List String :=
  [text r.tenantId, text r.programId, text r.commandKey, nameOf statusNames r.status,
   match r.token, r.rejectCode, r.retryAfterMs with
   | some t, _, _ => toHex t
   | _, some c, _ => nameOf rejectNames c
   | _, _, some ms => toString ms
   | _, _, _ => "?"]

def renderCheckpoint (x : SignedCheckpoint) : List String :=
  let c := x.checkpoint
  [text c.tenantId, text c.programId, toString c.shardId, toString c.seqFrom, toString c.seqTo, toString c.epoch,
   toHex c.prevCheckpoint, toHex c.eventHead, toHex c.tokenRoot, toHex c.evidenceRoot, toHex c.stateDigest,
   toString c.count, toString c.createdAt, toString c.counter, toHex (sha3 x.header)]

def tagName {α : Type} [Repr α] (x : α) : String := ((reprStr x).splitOn ".").getLast!

def renderToken (t : Token) : List String :=
  let l := t.leaf
  [text l.tenantId, text l.programId, toString l.shardId, tagName l.flow, toString l.revision,
   text l.paymentId, toHex l.memberKey, text l.payeeRef, toString l.amountCents, text l.period,
   toHex l.linesRoot, tagName l.outcome, if l.reasonCodes.isEmpty then "-" else ",".intercalate (l.reasonCodes.map text),
   tagName l.authority, toHex l.grantId, toHex l.bypass, toHex l.ruleVersion, toHex l.engineRelease, toHex l.inputCommitment,
   toString l.decidedAt, toString l.epoch, toString l.seq, toString l.issuedAt, toString l.expiresAt,
   hexList t.siblings, toHex t.checkpointDigest]

/-- An engine answer (`Frame.decodeAns`): status code, shard, batch, the request digest it echoes, the record count, and
    each leaf's bypass id. -/
def renderAns (a : Frame.AnsFrame) : List String :=
  [toString a.word.code, toString a.shard, toString a.batch, toHex a.digest.toList, toString a.recs.length,
   hexList (a.ext.leaves.map (·.bypass.toList))]

/-- A decoded KEY-CERT/v2: tenant, epoch, link, shard counts, the digests of both encoded keys and of the body, and the
    two signature lengths. -/
def renderKeyCert (e : Cosign.KeyCert) : List String :=
  [text e.tenantId, toString e.epoch, toHex e.link, ",".intercalate (e.chain.map toString), toHex (sha3 e.key.enc),
   toHex (sha3 e.verifierKey.enc), toHex (sha3 e.body), toString e.rootSig.length, toString e.coSig.length]

def key (s : String) : Option Cosign.Key := (hex s).bind (parse Cosign.pKey Cosign.maxCertBytes)

structure Ctx where
  state : PayerState := emptyState
  roots : List (Bytes × Bytes) := []
  /-- The authority chain of the tenant of the newest `link` line. -/
  chain : Option Cosign.Chain := none
  /-- The links of that tenant's chains that a `genesis` line replaced. -/
  retired : List Cosign.Link := []
  payments : List (String × Payment) := []
  requests : List (String × Request) := []
  expected : Option Nat := none

/-- A `link` line: the next link of the current tenant's chain, or the first link of another tenant's.  A `genesis` line
    (`regen`): a new chain of the current tenant from a later generation, which retires the links of the chain it
    replaces.  Any other link, or one with one key in both roles, is a fault in the vector file. -/
def admit (ch : Option Cosign.Chain) (retired : List Cosign.Link) (regen : Bool) (l : Cosign.Link) :
    Option (Cosign.Chain × List Cosign.Link) :=
  if hr : l.root ≠ l.witness then
    match ch with
    | some c =>
      if ht : l.tenantId = c.head.tenantId then
        if regen then (if c.head.gen < l.gen then some (.genesis l hr, c.links ++ retired) else none)
        else if hg : l.gen = c.head.gen + 1 then some (c.extend l ht hg hr, retired) else none
      else if regen then none else some (.genesis l hr, [])
    | none => if regen then none else some (.genesis l hr, [])
  else none

def Ctx.crypto (x : Ctx) : Crypto := realCrypto x.roots

def verdict : String → Option Bool
  | "accept" => some true
  | "reject" => some false
  | _ => none

/-- A payer step: keep its new state, and check it happened iff expected. -/
def stepped (x : Ctx) (expect : String) (result : Option PayerState) : Option (Ctx × Option Bool) := do
  pure ({ x with state := result.getD x.state }, some (result.isSome == (← verdict expect)))

/-- A decode: accepted lines must yield exactly `fields`, rejected lines list none. -/
def decoded {α : Type} (expect : String) (render : α → List String) (result : Option α)
    (fields : List String) : Option Bool := do
  match (← verdict expect), result with
  | true, some r => pure (render r == fields)
  | false, none => pure fields.isEmpty
  | _, _ => pure false

/-- One line: the new context and, for a checked line, whether it matched. -/
def step (x : Ctx) (fields : List String) : Option (Ctx × Option Bool) := do
  match fields with
  | ["root", tenant, pk] => pure ({ x with roots := x.roots ++ [(ascii tenant, ← hex pk)] }, none)
  | ["cert", expect, signed] =>
    match decodeKeyCert (← hex signed) with
    | none => pure (x, some (expect == "reject"))
    | some e =>
      let (s, ok) := installCert x.crypto x.state e
      pure ({ x with state := s }, some (ok == (← verdict expect)))
  | "key-cert" :: expect :: _ :: bytes :: rest =>
    let b ← hex bytes
    let got := match Cosign.verify Cosign.realCrypto (← x.chain) x.retired b with
      | .ok _ => "accept"
      | .error r => tagName r
    pure (x, some (got == expect && ((Cosign.decode b).map renderKeyCert).getD [] == rest))
  | ["mldsa87", expect, pk, msg, sig] =>
    pure (x, some (MlDsa87.verify (← hex pk).toByteArray (← hex msg).toByteArray (← hex sig).toByteArray == (← verdict expect)))
  | ["grants", tenants, id, rules, releases] =>  -- the same grant for each listed tenant
    let (gid, rs, es) := ((← hex id), (← list hex rules), (← list hex releases))
    let gs := (tenants.splitOn ",").map fun t =>
      ({ tenantId := ascii t, grantId := gid, ruleVersions := rs, engineReleases := es } : Grant)
    pure ({ x with state := { x.state with grants := gs } }, none)
  | ["now", now] => pure ({ x with state := { x.state with now := (← now.toNat?) } }, none)
  | ["payment", expect, name, tenant, program, flow, id, member, payee, amount, period, lines] =>
    let p : Payment := { tenantId := ascii tenant, programId := ascii program,
                         flow := (← flowNames.lookup flow), paymentId := ascii id,
                         memberKey := (← hex member), payeeRef := ascii payee, amountCents := (← amount.toNat?),
                         period := ascii period, lines := (← list hex lines) }
    let x := { x with payments := x.payments ++ [(name, p)] }
    if expect == "unsent" then return (x, some (x.state.pins.lookup p.key).isNone)
    match send x.state p with
    | .ok s => pure ({ x with state := s }, some (expect == "accept"))
    | .error .member_key_changed => pure (x, some (expect == "member_key_changed"))
  | "checkpoint" :: expect :: _ :: bytes :: rest =>
    let b ← hex bytes
    let result := storeCheckpoint x.crypto x.state b
    let got := match result with
      | none => "reject"
      | some s => if s.forked.length > x.state.forked.length then "fork" else "accept"
    let fields := if got != "accept" then [] else ((decodeCheckpoint b).map renderCheckpoint).getD []
    pure ({ x with state := result.getD x.state }, some (got == expect && fields == rest))
  | "token" :: expect :: decodes :: _ :: payment :: bytes :: rest =>
    let b ← hex bytes
    let p ← List.lookup payment x.payments
    let ok := verifyToken x.crypto x.state p b == (← verdict expect) &&
      (decodeToken b).isSome == (decodes == "decode-ok") && ((decodeToken b).map renderToken).getD [] == rest
    pure (x, some ok)
  | ["release", expect, _, payment, bytes] =>
    stepped x expect (release x.crypto x.state (← List.lookup payment x.payments) (← hex bytes))
  | "request" :: expect :: name :: bytes :: rest =>
    let r := decodeRequest (← hex bytes)
    pure ({ x with requests := x.requests ++ (r.map (name, ·)).toList },
      some (← decoded expect renderRequest r rest))
  | "response" :: expect :: _ :: request :: bytes :: rest =>
    let r ← List.lookup request x.requests
    pure (x, some (← decoded expect renderResponse (decodeResponse sha3 r (← hex bytes)) rest))
  | [kind, expect, _, latest, old, new] =>
    let f ← [("reissue", reissues), ("redecide", redecides)].lookup kind
    let a ← decodeToken (← hex old)
    let b ← decodeToken (← hex new)
    pure (x, some (f (← latest.toNat?) a.leaf b.leaf == (← verdict expect)))
  | ["decision-id", _, tenant, program, payment, rev, out] =>
    pure (x, some (decisionId sha3 (ascii tenant) (ascii program) (ascii payment) (← rev.toNat?) ==
      (← hex out)))
  | ["input", _, request, readSet, out] =>
    pure (x, some (inputCommitment sha3 (← hex request) (← hex readSet) == (← hex out)))
  | ["state", _, released, unresolved, out] =>
    pure (x, some (stateDigest sha3 (← hex released) (← hex unresolved) == (← hex out)))
  | ["lines-root", _, lines, out] => pure (x, some (linesRoot sha3 (← list hex lines) == (← hex out)))
  | ["context", _, body, out] => pure (x, some (Gate.context sha3 (← hex body) == (← hex out)))
  | ["pay-digest", _, request, out] =>
    pure (x, some ((decodeRequest (← hex request)).map (Gate.payDigest sha3) == some (← hex out)))
  | ["input6", _, ctx, rd, out] => pure (x, some (Gate.inputV6 sha3 (← hex ctx) (← hex rd) == (← hex out)))
  | ["batch-input", _, ctx, rqs, out] =>
    pure (x, some (Gate.batchInput sha3 (← hex ctx) (← list hex rqs) == (← hex out)))
  | "answer" :: expect :: _ :: bytes :: rest =>
    let b ← hex bytes
    let r := Frame.decodeAns b
    pure (x, some ((← decoded expect renderAns r rest) && r.all (Frame.encodeAns · == some b)))
  | [kind, tenant, gen, digest, root, rootNext, witness, witnessNext, closed] =>
    let regen ← [("link", false), ("genesis", true)].lookup kind
    let closedThrough ← if closed == "-" then some none else closed.toNat?.map some
    let l : Cosign.Link := { tenantId := ascii tenant, gen := (← gen.toNat?), digest := (← hex digest),
                             root := (← key root), rootNext := (← hex rootNext), witness := (← key witness),
                             witnessNext := (← hex witnessNext), closedThrough }
    let (ch, retired) ← admit x.chain x.retired regen l
    pure ({ x with chain := some ch, retired }, none)
  | ["end", n] => pure ({ x with expected := some (← n.toNat?) }, none)
  | _ => none

def main (args : List String) : IO UInt32 := do
  match args with
  | [path] =>
    let mut ctx : Ctx := {}
    let mut number := 0
    let mut checked := 0
    let mut failed := 0
    for line in (← IO.FS.readFile path).splitOn "\n" do
      number := number + 1
      let fields := ((String.ofList (line.toList.filter (· ≠ '\r'))).splitOn " ").filter (· ≠ "")
      if fields.isEmpty || fields.head! == "#" then continue
      match step ctx fields with
      | none =>
        failed := failed + 1
        IO.println s!"GATE_VECTOR_MALFORMED line={number}"
      | some (next, result) =>
        ctx := next
        if let some ok := result then
          checked := checked + 1
          unless ok do
            failed := failed + 1
            IO.println s!"GATE_VECTOR_MISMATCH line={number} kind={fields.head!}"
    let pass := failed == 0 && ctx.expected == some checked
    IO.println s!"GATE_VECTORS={if pass then "PASS" else "FAIL"} checked={checked} expected={ctx.expected.getD 0} failed={failed}"
    return (if pass then 0 else 1)
  | _ =>
    IO.eprintln "GATE_VECTORS=USAGE gate_vectors <path>"
    return 2

end BlindLedger.Gate.Vectors

def main (args : List String) : IO UInt32 := BlindLedger.Gate.Vectors.main args
