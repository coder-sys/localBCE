import BlindLedger.Gate.Producer
import BlindLedger.Gate.Payer
import BlindLedger.Gate.Batch

open BlindLedger.Gate

/-! `gate_verify`: stdin is one mode byte and its frame; stdout one answer line.  Exit 0 for ACCEPT, INDEX,
    STORED and FORK, 1 for REJECT and HOLD, 2 (stderr `GATE_VERIFY=FRAME`) for a malformed frame.  Every
    decision is a theorem-covered function (`publishOkTree`,`storeCheckpointAny`, `firstFailure`); this file only
    reads the frame into the state they take.  Integers are big-endian; `u32‖x` is a length then `x`.
    - 0x01 PUBLISH: root_pk · u32‖cert · u32‖last (0 = genesis) · u32‖signed new · u16 k · (u32‖token)^k
    - 0x02 INDEX: u32‖signed checkpoint
    - 0x03 STORE: root_pk · u16 m · (u32‖cert)^m · u16 j · (u32‖candidate)^j · u16 f · (u32‖fork evidence)^f ·
      u32‖new, where a fork evidence is the stored side of a recorded fork
    - 0x05 RELEASE: root_pk · u16 m · (u32‖cert)^m · u16 f · (u32‖fork evidence)^f · u32‖checkpoint · u64 now ·
      u16 g · grants · u8 released · u8 pinned [‖ 32-byte member key] · u32‖DECIDE-REQUEST · u32‖token
      (a grant: tenant ident, then id, u16 n and n rule versions, u16 n and n engine releases, each u16‖bytes).
      0x04, the grant without a tenant, is gone: such a frame is malformed. -/

def pBytes : P Bytes := do take (← nat 4)
def pList {α : Type} (p : P α) : P (List α) := do many p (← nat 2)
def pRoot : P Bytes := take mlDsa87Key

def pGrant : P Grant := do
  let tenantId ← ident
  let grantId ← blob 0 65535
  let ruleVersions ← many (blob 0 65535) (← nat 2)
  let engineReleases ← many (blob 0 65535) (← nat 2)
  pure { tenantId, grantId, ruleVersions, engineReleases }

def hex (b : Bytes) : String :=
  String.join (b.map fun x => String.ofList [Nat.digitChar (x.toNat / 16), Nat.digitChar (x.toNat % 16)])

def failureName : Failure → String
  | .parse => "parse" | .batch => "batch" | .path => "path" | .fence => "fence" | .expiry => "expiry"
  | .payment => "payment" | .route => "route" | .outcome => "outcome" | .grant => "grant"
  | .released => "released" | .forked => "forked" | .pin => "pin"

def accept (ok : Bool) : String × UInt32 :=
  if ok then ("GATE_VERIFY=ACCEPT", 0) else ("GATE_VERIFY=REJECT", 1)

/-- The installed certificates: `installCert` on each, in order. -/
def certState (c : Crypto) (certs : List Bytes) : Option PayerState :=
  certs.foldlM (fun s b => (fun e => (installCert c s e).1) <$> decodeKeyCert b) emptyState

def publish : P (String × UInt32) := do
  let rootPk ← pRoot
  let cert ← pBytes
  let last ← pBytes
  let new ← pBytes
  let tokens ← pList pBytes
  pure (accept (publishOkTree rootPk cert (if last.isEmpty then none else some last) new tokens))

def index : P (String × UInt32) := do
  match storedOfAny sha3 (← pBytes) with
  | none => pure (accept false)
  | some x =>
    let c := x.checkpoint
    pure (s!"GATE_VERIFY=INDEX {hex c.tenantId} {c.shardId} {c.epoch} {c.seqFrom} {c.seqTo} {hex x.digest} {hex c.prevCheckpoint}", 0)

def store : P (String × UInt32) := do
  let rootPk ← pRoot
  let certs ← pList pBytes
  let candidates ← pList pBytes
  let evidence ← pList pBytes
  let new ← pBytes
  let some x := decodeAnyCheckpoint new | pure (accept false)
  let c := realCrypto [(x.checkpoint.tenantId, rootPk)]
  let some s := certState c certs | fail
  let some old := candidates.mapM (storedOfAny sha3) | fail
  let some forks := evidence.mapM (storedOfAny sha3) | fail
  match storeCheckpointAny c { s with checkpoints := old, forked := forks.map fun f => (f, f) } new with
  | none => pure (accept false)
  | some s' =>
    match s'.forked with  -- a new fork is put in front of the recorded ones
    | f :: rest => pure (if rest.length == forks.length then (s!"GATE_VERIFY=FORK {hex f.1.digest}", 0)
                         else ("GATE_VERIFY=STORED", 0))
    | [] => pure ("GATE_VERIFY=STORED", 0)

/-- The payer's slice of state for one token (`slice`), from what the adapter loaded, and `firstFailure` on it. -/
def release : P (String × UInt32) := do
  let rootPk ← pRoot
  let certs ← pList pBytes
  let evidence ← pList pBytes
  let checkpoint ← pBytes
  let now ← nat 8
  let grants ← pList pGrant
  let released ← nat 1 0 1
  let pinned ← nat 1 0 1
  let memberKey ← if pinned == 1 then take memberKeyBytes else pure []
  let some r := decodeRequest (← pBytes) | fail
  let token ← pBytes
  let p : Payment := { tenantId := r.tenantId, programId := r.programId, flow := r.flow, paymentId := r.paymentId,
                       memberKey := r.memberKey, payeeRef := r.payeeRef, amountCents := r.amountCents,
                       period := r.period, lines := r.lines }
  let c := realCrypto [(p.tenantId, rootPk)]
  let some s0 := certState c certs | fail
  let some forks := evidence.mapM (storedOfAny sha3) | fail
  let s1 := (storeCheckpointAny c { s0 with equivocations := [], forked := [] } checkpoint).getD s0
  let s := { s1 with equivocations := s0.equivocations, forked := forks.map fun f => (f, f), now, grants,
                     released := if released == 1 then [p.key] else [],
                     pins := if pinned == 1 then [(p.key, memberKey)] else [] }
  pure (match firstFailure c s p token with
    | none => ("GATE_VERIFY=ACCEPT", 0)
    | some f => (s!"GATE_VERIFY=HOLD {failureName f}", 1))

def frame : P (String × UInt32) := do
  match ← take 1 with
  | [1] => publish
  | [2] => index
  | [3] => store
  | [5] => release
  | _ => fail

def main : IO UInt32 := do
  let input := (← (← IO.getStdin).readBinToEnd).toList
  match parse frame input.length input with
  | some (line, code) =>
    IO.println line
    return code
  | none =>
    IO.eprintln "GATE_VERIFY=FRAME"
    return 2
