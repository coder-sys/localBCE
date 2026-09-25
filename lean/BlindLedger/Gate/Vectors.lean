import BlindLedger.Gate.Spec
import BlindLedger.Sha3

namespace BlindLedger.Gate.Vectors

open BlindLedger.Gate

/-! Conformance check of `tests/gate_vectors/gate_v1.vectors` against the Lean
    specification.  Lines run in order against one payer state: `cert`,
    `admit` and `release` lines are the payer's own steps (and are checked);
    `grants`, `now` and `payment` lines set context.  The `sig` lines are the
    only ML-DSA-87 triples treated as valid; the Python test verifies each of
    them with AWS-LC.  Accepted request, response and checkpoint lines list
    the decoded fields they must yield.  The last line, `end N`, is the number
    of checked lines; anything else is a FAIL.  Test-only: this executable is
    never a release path. -/

def sha3 (x : Bytes) : Bytes := (BlindLedger.Semantic.sha3_512 x.toByteArray).toList

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

def flowNames : List (String × Flow) :=
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
   text r.paymentId, text r.payeeRef, toString r.amountCents, text r.period, hexList r.lines,
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
  [text c.tenantId, text c.programId, toString c.seqFrom, toString c.seqTo, toString c.epoch,
   toHex c.prevCheckpoint, toHex c.eventHead, toHex c.tokenRoot, toHex c.evidenceRoot,
   toHex c.projections, toString c.count, toString c.createdAt, toHex (sha3 x.header)]

structure Ctx where
  state : PayerState :=
    { fence := fun _ => 0, now := 0, certs := [], checkpoints := [], grants := [], released := [] }
  chains : List (Bytes × Bool) := []
  sigs : List (Bytes × Bytes × Bytes) := []
  payments : List (String × Payment) := []
  expected : Option Nat := none

def Ctx.crypto (x : Ctx) : Crypto where
  hash := sha3
  certChainOk e := x.chains.contains (e.certId, true)
  sigOk pk msg sig := x.sigs.contains (pk, msg, sig)

def verdict : String → Option Bool
  | "accept" => some true
  | "reject" => some false
  | _ => none

def chainFlag : String → Option Bool
  | "chain-ok" => some true
  | "chain-bad" => some false
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
  | ["cert", expect, id, epoch, tenant, pk, chain] =>
    let e : EpochCert := { certId := (← hex id), epoch := (← epoch.toNat?),
                           tenantId := ascii tenant, publicKey := (← hex pk) }
    let x := { x with chains := x.chains ++ [(e.certId, (← chainFlag chain))] }
    stepped x expect (installCert x.crypto x.state e)
  | ["grants", id, rules, releases] =>
    let g : Grant := { grantId := (← hex id), ruleVersions := (← list hex rules),
                       engineReleases := (← list hex releases) }
    pure ({ x with state := { x.state with grants := [g] } }, none)
  | ["now", now] => pure ({ x with state := { x.state with now := (← now.toNat?) } }, none)
  | ["sig", pk, msg, sig] => pure ({ x with sigs := x.sigs ++ [((← hex pk), (← hex msg), (← hex sig))] }, none)
  | ["payment", name, tenant, program, flow, id, payee, amount, period, lines] =>
    let p : Payment := { tenantId := ascii tenant, programId := ascii program,
                         flow := (← flowNames.lookup flow), paymentId := ascii id,
                         payeeRef := ascii payee, amountCents := (← amount.toNat?),
                         period := ascii period, lines := (← list hex lines) }
    pure ({ x with payments := x.payments ++ [(name, p)] }, none)
  | "admit" :: expect :: _ :: bytes :: rest =>
    let b ← hex bytes
    let result := admitCheckpoint x.crypto x.state b
    pure ({ x with state := result.getD x.state },
      some (← decoded expect renderCheckpoint (result.bind fun _ => decodeCheckpoint b) rest))
  | ["token", expect, decodes, _, payment, bytes] =>
    let b ← hex bytes
    let p ← List.lookup payment x.payments
    let ok := verifyToken x.crypto x.state p b == (← verdict expect) &&
      (decodeToken b).isSome == (decodes == "decode-ok")
    pure (x, some ok)
  | ["release", expect, _, payment, bytes] =>
    stepped x expect (release x.crypto x.state (← List.lookup payment x.payments) (← hex bytes))
  | "request" :: expect :: _ :: bytes :: rest =>
    pure (x, some (← decoded expect renderRequest (decodeRequest (← hex bytes)) rest))
  | "response" :: expect :: _ :: bytes :: rest =>
    pure (x, some (← decoded expect renderResponse (decodeResponse sha3 (← hex bytes)) rest))
  | ["decision-id", _, tenant, program, flow, payment, rev, out] =>
    pure (x, some (decisionId sha3 (ascii tenant) (ascii program) (← flowNames.lookup flow)
      (ascii payment) (← rev.toNat?) == (← hex out)))
  | ["input", _, request, readSet, out] =>
    pure (x, some (inputCommitment sha3 (← hex request) (← hex readSet) == (← hex out)))
  | ["lines-root", _, lines, out] => pure (x, some (linesRoot sha3 (← list hex lines) == (← hex out)))
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
