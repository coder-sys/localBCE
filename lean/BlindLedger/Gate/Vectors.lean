import BlindLedger.Gate.Theorems
import BlindLedger.Sha3

namespace BlindLedger.Gate.Vectors

open BlindLedger.Gate

/-! Conformance check of `tests/gate_vectors/gate_v1.vectors` against the Lean
    specification.  Lines are read in order; `cert`, `grant`, `state`, `sig`
    and `payment` lines set the payer context for later `token` lines.  The
    `sig` lines are the only ML-DSA-87 triples this check treats as valid; the
    Python test verifies each of them with AWS-LC.  Test-only: this executable
    is never a release path. -/

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

def list {α : Type} (f : String → Option α) : String → Option (List α)
  | "-" => some []
  | s => (s.splitOn ",").mapM f

structure Ctx where
  certs : List (EpochCert × Bool) := []
  grants : List Grant := []
  fence : Nat := 0
  now : Nat := 0
  released : List Bytes := []
  sigs : List (Bytes × Bytes × Bytes) := []
  payments : List (String × Payment) := []

def Ctx.crypto (x : Ctx) : Crypto where
  hash := sha3
  certChainOk e := x.certs.any fun (k, ok) => ok && k.certId == e.certId
  sigOk pk msg sig := x.sigs.contains (pk, msg, sig)

def Ctx.payer (x : Ctx) : PayerState :=
  { fence := x.fence, now := x.now, certs := x.certs.map (·.1), grants := x.grants,
    released := x.released }

def flowOf : String → Option Flow
  | "FFS_CYCLE" => some .FFS_CYCLE
  | "FFS_CLAIM" => some .FFS_CLAIM
  | "CAP_820" => some .CAP_820
  | "SDP" => some .SDP
  | "PLAN_PAY" => some .PLAN_PAY
  | _ => none

def verdict : String → Option Bool
  | "accept" => some true
  | "reject" => some false
  | _ => none

/-- One line: the new context and, for a checked line, whether it matched. -/
def step (x : Ctx) (fields : List String) : Option (Ctx × Option Bool) := do
  match fields with
  | ["cert", id, epoch, tenant, pk, chain] =>
    let e : EpochCert := { certId := (← hex id), epoch := (← epoch.toNat?),
                           tenantId := ascii tenant, publicKey := (← hex pk) }
    pure ({ x with certs := x.certs ++ [(e, chain == "chain-ok")] }, none)
  | ["grant", id, rules, releases] =>
    let g : Grant := { grantId := (← hex id), ruleVersions := (← list hex rules),
                       engineReleases := (← list hex releases) }
    pure ({ x with grants := x.grants ++ [g] }, none)
  | ["state", fence, now, released] =>
    pure ({ x with fence := (← fence.toNat?), now := (← now.toNat?),
                   released := (← list (some ∘ ascii) released) }, none)
  | ["sig", pk, msg, sig] => pure ({ x with sigs := x.sigs ++ [((← hex pk), (← hex msg), (← hex sig))] }, none)
  | ["payment", name, tenant, program, flow, id, payee, amount, period, lines] =>
    let p : Payment := { tenantId := ascii tenant, programId := ascii program, flow := (← flowOf flow),
                         paymentId := ascii id,
                         payeeRef := ascii payee, amountCents := (← amount.toNat?),
                         period := ascii period, lines := (← list hex lines) }
    pure ({ x with payments := x.payments ++ [(name, p)] }, none)
  | ["token", expect, decodes, _, payment, bytes] =>
    let b ← hex bytes
    let p ← List.lookup payment x.payments
    let ok := verifyToken x.crypto x.payer p b == (← verdict expect) &&
      (decodeToken b).isSome == (decodes == "decode-ok")
    pure (x, some ok)
  | ["request", expect, _, bytes] => pure (x, some ((decodeRequest (← hex bytes)).isSome == (← verdict expect)))
  | ["response", expect, _, bytes] =>
    pure (x, some ((decodeResponse sha3 (← hex bytes)).isSome == (← verdict expect)))
  | ["checkpoint", expect, _, bytes] =>
    pure (x, some ((decodeCheckpoint (← hex bytes)).isSome == (← verdict expect)))
  | ["decision-id", _, tenant, program, key, rev, out] =>
    pure (x, some (decisionId sha3 (ascii tenant) (ascii program) (ascii key) (← rev.toNat?) == (← hex out)))
  | ["input", _, request, readSet, out] =>
    pure (x, some (inputCommitment sha3 (← hex request) (← hex readSet) == (← hex out)))
  | ["lines-root", _, lines, out] => pure (x, some (linesRoot sha3 (← list hex lines) == (← hex out)))
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
    let pass := failed == 0 && checked > 0
    IO.println s!"GATE_VECTORS={if pass then "PASS" else "FAIL"} checked={checked} failed={failed}"
    return (if pass then 0 else 1)
  | _ =>
    IO.eprintln "GATE_VECTORS=USAGE gate_vectors <path>"
    return 2

end BlindLedger.Gate.Vectors

def main (args : List String) : IO UInt32 := BlindLedger.Gate.Vectors.main args
