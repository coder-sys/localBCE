import BlindLedger.Gate.Producer
import BlindLedger.Gate.Payer
import BlindLedger.Gate.Batch
import BlindLedger.Gate.PublishSpec
import BlindLedger.Gate.PublishFast
import BlindLedger.Gate.Custody
import BlindLedger.Gate.Witness

open BlindLedger.Gate

/-! `gate_verify`: stdin is one mode byte and its frame; stdout one answer line.  Exit 0 for ACCEPT, INDEX,
    STORED, FORK, CERT and CERT-INDEX, 1 for REJECT, HOLD and CERT REFUSED, 2 (stderr `GATE_VERIFY=FRAME`) for a malformed frame.  Every
    decision is a theorem-covered function (`publishOkTree`,`storeCheckpoint`, `firstFailure`); this file only
    reads the frame into the state they take.  Integers are big-endian; `u32‖x` is a length then `x`.
    - 0x01 PUBLISH: root_pk · u32‖cert · u32‖last (0 = genesis) · u32‖signed new · u16 k · (u32‖token)^k · u64 tpm
    - 0x02 INDEX: u32‖signed checkpoint
    - 0x03 STORE: root_pk · u16 m · (u32‖cert)^m · u16 j · (u32‖candidate)^j · u16 f · (u32‖stored · u32‖forking)^f ·
      u32‖new, where each fork evidence is both checkpoints of a recorded fork
    - 0x05 RELEASE: root_pk · u16 m · (u32‖cert)^m · u16 f · (u32‖stored · u32‖forking)^f · u32‖checkpoint · u64 now ·
      u16 g · grants · u8 released · u8 pinned [‖ 32-byte member key] · u32‖DECIDE-REQUEST · u32‖token
      (a grant: tenant ident, then id, u16 n and n rule versions, u16 n and n engine releases, each u16‖bytes).
      0x04, the grant without a tenant, is gone: such a frame is malformed.
    - 0x07 CUSTODY: u8 written · u64 tpm · root_pk · u32‖cert · u32‖signed newest checkpoint (empty: nothing sealed;
      its own counter is the store's)
    - 0x08 INSTALL: root_pk · u16 m · (u32‖witness)^m · u32‖new: the new certificate's `Role` (`classify`) on the
      state the witnesses install, `GATE_VERIFY=CERT <role>`, exit 1 for REFUSED (also a certificate that does not decode)
    - 0x09 CERT-INDEX: u32‖cert: its tenant, epoch and the SHA3-512 of its body, which the store keys rows by
    STORE and RELEASE take every certificate, or the payer's witnesses (`select`, `selectForks`), which decide alike
    (`select_decides`, `forks_witness`). -/

def pBytes : P Bytes := do take (← nat 4)
def pList {α : Type} (p : P α) : P (List α) := do many p (← nat 2)
def pRoot : P Bytes := take mlDsa87Key

/-- A recorded fork: both of its checkpoints, the stored side first. -/
def pFork : P (Bytes × Bytes) := do let a ← pBytes; let b ← pBytes; pure (a, b)

def storedPair (f : Bytes × Bytes) : Option (Stored × Stored) := do pure (← storedOf sha3 f.1, ← storedOf sha3 f.2)

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

/-- The installed certificates: `installCert` on each, in order; none when one does not decode. -/
def certState (c : Crypto) (certs : List Bytes) : Option PayerState := (certs.mapM decodeKeyCert).map (replay c)

def publish : P (String × UInt32) := do pure (accept (publishArgsOk (← pPublishArgs)))

/-- `custodyOf` on the TPM counter (`written` 0: defined, never written) and the newest sealed checkpoint (signed; empty:
    nothing sealed), whose own counter is the store's and which `firstSealed` checks under the root key and its
    certificate. Create, ready and catch-up exit 0; a refusal names its reason and exits 1. -/
def custody : P (String × UInt32) := do
  let written ← nat 1 0 1
  let tpm ← nat 8
  let rootPk ← take mlDsa87Key
  let cert ← pFramed
  let signed ← pFramed
  pure (match custodyOf rootPk cert signed (if written == 0 then none else some tpm) with
    | .create => ("GATE_VERIFY=CUSTODY create", 0)
    | .ready => ("GATE_VERIFY=CUSTODY ready", 0)
    | .catchUp => ("GATE_VERIFY=CUSTODY catch_up", 0)
    | .refuse .noStore => ("GATE_VERIFY=CUSTODY no_store", 1)
    | .refuse .counterReset => ("GATE_VERIFY=CUSTODY counter_reset", 1)
    | .refuse .storeRewound => ("GATE_VERIFY=CUSTODY store_rewound", 1)
    | .refuse .storeAhead => ("GATE_VERIFY=CUSTODY store_ahead", 1))

def index : P (String × UInt32) := do
  match storedOf sha3 (← pBytes) with
  | none => pure (accept false)
  | some x =>
    let c := x.checkpoint
    pure (s!"GATE_VERIFY=INDEX {hex c.tenantId} {c.shardId} {c.epoch} {c.seqFrom} {c.seqTo} {hex x.digest} {hex c.prevCheckpoint} {c.counter}", 0)

def store : P (String × UInt32) := do
  let rootPk ← pRoot
  let certs ← pList pBytes
  let candidates ← pList pBytes
  let evidence ← pList pFork
  let new ← pBytes
  let some x := decodeCheckpoint new | pure (accept false)
  let c := realCrypto [(x.checkpoint.tenantId, rootPk)]
  let some s := certState c certs | fail
  let some old := candidates.mapM (storedOf sha3) | fail
  let some forks := evidence.mapM storedPair | fail
  pure (match storeOutcome c s old forks new with
    | none => accept false
    | some none => ("GATE_VERIFY=STORED", 0)
    | some (some d) => (s!"GATE_VERIFY=FORK {hex d}", 0))

/-- The payer's slice of state for one token (`slice`), from what the adapter loaded, and `firstFailure` on it. -/
def release : P (String × UInt32) := do
  let rootPk ← pRoot
  let certs ← pList pBytes
  let evidence ← pList pFork
  let checkpoint ← pBytes
  let now ← nat 8
  let grants ← pList pGrant
  let released ← nat 1 0 1
  let pinned ← nat 1 0 1
  let memberKey ← if pinned == 1 then take memberKeyBytes else pure []
  let some r := decodeRequest (← pBytes) | fail
  let token ← pBytes
  let c := realCrypto [(r.tenantId, rootPk)]
  let some s0 := certState c certs | fail
  let some forks := evidence.mapM storedPair | fail
  pure (match releaseOutcome c s0 forks checkpoint now grants (released == 1)
      (if pinned == 1 then some memberKey else none) r.payment token with
    | none => ("GATE_VERIFY=ACCEPT", 0)
    | some f => (s!"GATE_VERIFY=HOLD {failureName f}", 1))

def roleName : Role → String
  | .INSTALLED => "INSTALLED" | .SAME => "SAME" | .EQUIVOCATES => "EQUIVOCATES" | .FENCE_ONLY => "FENCE_ONLY"
  | .REFUSED => "REFUSED"

def install : P (String × UInt32) := do
  let rootPk ← pRoot
  let certs ← pList pBytes
  let some e := decodeKeyCert (← pBytes) | pure ("GATE_VERIFY=CERT REFUSED", 1)
  let c := realCrypto [(e.tenantId, rootPk)]
  let some s := certState c certs | fail
  let r := classify c s e
  pure (s!"GATE_VERIFY=CERT {roleName r}", if r == .REFUSED then 1 else 0)

def certIndex : P (String × UInt32) := do
  match decodeKeyCert (← pBytes) with
  | none => pure (accept false)
  | some e => pure (s!"GATE_VERIFY=CERT-INDEX {hex e.tenantId} {e.epoch} {hex (sha3 (certBody e))}", 0)

def frame : P (String × UInt32) := do
  match ← take 1 with
  | [1] => publish
  | [2] => index
  | [3] => store
  | [5] => release
  | [7] => custody
  | [8] => install
  | [9] => certIndex
  | _ => fail

/-- The answer to one request (mode byte then frame): PUBLISH frames take the `ByteArray` reader
    (`publishFrameB_eq`: same answer as `publish`, linear time). Pure: nothing is kept between requests. -/
def answerOf (bs : ByteArray) : Option (String × UInt32) :=
  if bs[0]? == some 1 then (publishFrameB (bs.extract 1 bs.size)).map accept
  else let input := bs.data.toList; parse frame input.length input

def answer (r : Option (String × UInt32)) : IO UInt32 := do
  match r with
  | some (line, code) => IO.println line; return code
  | none => IO.eprintln "GATE_VERIFY=FRAME"; return 2

/-- `n` bytes from `h`, fewer only at end of input. -/
def readN (h : IO.FS.Stream) (n : Nat) (acc : ByteArray := .empty) : Nat → IO ByteArray
  | 0 => return acc
  | fuel + 1 => do
    if acc.size >= n then return acc
    let chunk ← h.read (min (n - acc.size) 1048576).toUSize
    if chunk.isEmpty then return acc else readN h n (acc ++ chunk) fuel

/-- Fuel for `serve`: far beyond any session; running out exits nonzero, never as success. -/
def serveFuel : Nat := 2 ^ 64

/-- `gate_verify serve`: requests `u32 BE L ‖ (mode ‖ frame)` on stdin, each answered `u32 BE (1+len line) ‖ exit code
    ‖ line` on stdout; clean end of input between requests exits 0; a malformed request or a short read exits 2
    (`answer`), so the caller sees end of output instead of an answer. Every request is decided from its own bytes. -/
def serve (i o : IO.FS.Stream) : Nat → IO UInt32
  | 0 => do IO.eprintln "GATE_VERIFY=FUEL"; return 2
  | fuel + 1 => do
  let head ← readN i 4 .empty 5
  if head.isEmpty then return 0
  let len := head.foldl (fun a b => a * 256 + b.toNat) 0
  let body ← readN i len .empty (len + 1)
  match (if head.size == 4 && body.size == len then answerOf body else none) with
  | some (line, code) =>
    let out := line.toUTF8
    let n := out.size + 1
    o.write ((ByteArray.mk #[(n >>> 24).toUInt8, (n >>> 16).toUInt8, (n >>> 8).toUInt8, n.toUInt8, code.toUInt8]) ++ out)
    o.flush
    serve i o fuel
  | none => answer none

def main (args : List String) : IO UInt32 := do
  if args == ["serve"] then serve (← IO.getStdin) (← IO.getStdout) serveFuel
  else answer (answerOf (← (← IO.getStdin).readBinToEnd))
