import BlindLedger.Gate.Producer
import BlindLedger.Gate.Payer
import BlindLedger.Gate.Batch
import BlindLedger.Gate.PublishSpec
import BlindLedger.Gate.InstallFast
import BlindLedger.Gate.Custody
import BlindLedger.Gate.Witness

open BlindLedger.Gate

/-! `gate_verify`: stdin is one mode byte and its frame; stdout one answer line.  Exit 0 for ACCEPT, INDEX,
    STORED, FORK, CERT, LINK, CERT-INDEX and LINK-INDEX, 1 for REJECT, HOLD, a refused certificate or link, 2 (stderr
    `GATE_VERIFY=FRAME`) for a malformed frame.  Every decision is a theorem-covered function (`publishOkTree`,
    `storeCheckpoint`, `firstFailure`, `Cosign.install`, `Cosign.installLink`); this file only reads the frame into the
    state they take.  Integers are big-endian; `u32‖x` is a length then `x`, and an optional link or certificate is
    empty when absent.  A link is an AUTHORITY-LINK/v1 and a certificate a KEY-CERT/v2; one that does not decode makes
    the frame malformed (PUBLISH answers REJECT).
    - 0x01 PUBLISH: u32‖link · u32‖cert · u32‖last (0 = genesis) · u32‖signed new · u16 k · (u32‖token)^k · u64 tpm
    - 0x02 INDEX: u32‖signed checkpoint
    - 0x03 STORE: authority · u16 j · (u32‖candidate)^j · u16 f · (u32‖stored · u32‖forking)^f · u32‖new, where each
      fork evidence is both checkpoints of a recorded fork
    - 0x05 RELEASE: authority · u16 f · (u32‖stored · u32‖forking)^f · u32‖checkpoint · u64 now ·
      u16 g · grants · u8 released · u8 pinned [‖ 32-byte member key] · u32‖DECIDE-REQUEST · u32‖token
      (a grant: tenant ident, then id, u16 n and n rule versions, u16 n and n engine releases, each u16‖bytes).
    - authority: u32‖head · u32‖conflict (optional) · u16 l · (u32‖link)^l · u16 m · (u32‖cert)^m · u32‖fence cert
      (optional): the tenant's head link, its carried link conflict (`selectConflict`), the links the certificates
      name, every one of the head's tenant, the certificate witnesses (`select`) and the fence certificate
      (`selectFence`).  The state is `onLinks` of their `replay` under `linkView`.
    - 0x07 CUSTODY: u8 written · u64 tpm · u32‖link · u32‖cert · u32‖signed newest checkpoint (empty: nothing sealed;
      its own counter is the store's)
    - 0x08 INSTALL: u32‖head · u32‖own · u32‖next · u16 k · (u32‖link)^k · u32‖same cert · u16 l · (u32‖link)^l ·
      u16 m · (u32‖witness)^m · u32‖new: `installOutcome` (head, the chain's links of the certificate's generation and
      the next, the links its keys touch, the held certificate of its body, the links the witnesses name and the
      witnesses the caller carries), `GATE_VERIFY=CERT <answer>`, exit 1 for UNKNOWN_TENANT and REFUSED (also a
      certificate that does not decode).  `installOutcome_install` proves the answer is `Cosign.install`'s only if those
      witnesses agree with the state on the certificate's epoch (`hany`) and, when it holds none there, on its fit
      (`hfit`); the payer's SQL is written to select them as `selectInstall` does, and no theorem discharges that
    - 0x09 CERT-INDEX: u32‖cert: its tenant, epoch, the SHA3-512 of its body, the link it names and the SHA3-512 of
      its two encoded keys, which the store keys rows by
    - 0x0A LINK: 64-byte pin · u16 a · (u32‖link)^a · u16 r · (u16 b · (u32‖link)^b)^r · u16 k · (u32‖link)^k · u16 m ·
      (u32‖cert)^m · u32‖new: `linkOutcome` (the present chain and each retired chain newest first, the recorded
      conflicts of the new link's digest, the installed certificates its keys touch), `GATE_VERIFY=LINK <answer>`,
      exit 1 for REFUSED
    - 0x0B LINK-INDEX: u32‖link: its tenant, generation, base, digest, the SHA3-512 of its two encoded keys, its
      two commitments and the last epoch it closes (`-` for none)
    STORE and RELEASE decide on the witnesses as on the whole history (`select_decides`, `forks_witness`), INSTALL
    too (`install_classifies`). -/

def pList {α : Type} (p : P α) : P (List α) := do many p (← nat 2)
def pLink : P Cosign.SignedLink := do
  let some n := Cosign.decodeLink (← pFramed) | fail
  pure n

def pOptLink : P (Option Cosign.SignedLink) := do
  let b ← pFramed
  if b.isEmpty then pure none else
  let some n := Cosign.decodeLink b | fail
  pure (some n)

def pCert : P Cosign.KeyCert := do
  let some e := Cosign.decode (← pFramed) | fail
  pure e

def pOptCert : P (Option Cosign.KeyCert) := do
  let b ← pFramed
  if b.isEmpty then pure none else
  let some e := Cosign.decode b | fail
  pure (some e)

/-- A STORE or RELEASE frame's authority part, as the state it decides on.  A link of another tenant than the
    head's makes the frame malformed: a certificate counts only under a link of the head's tenant. -/
def pAuthority : P PayerState := do
  let head ← pLink
  let conflict ← pOptLink
  let links ← pList pLink
  let certs ← pList pCert
  let fence ← pOptCert
  if !links.all (·.tenantId == head.tenantId) then fail
  let ok := underLinks realCrypto (links.map (·.link sha3))
  pure (onLinks (replay ok certs) (linkView sha3 head conflict (fenceOf ok fence)))

/-- A recorded fork: both of its checkpoints, the stored side first. -/
def pFork : P (Bytes × Bytes) := do let a ← pFramed; let b ← pFramed; pure (a, b)

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

def publish : P (String × UInt32) := do pure (accept (publishArgsOk (← pPublishArgs)))

/-- `custodyOf` on the TPM counter (`written` 0: defined, never written) and the newest sealed checkpoint (signed; empty:
    nothing sealed), whose own counter is the store's and which `firstSealed` checks under the held link and its
    certificate. Create, ready and catch-up exit 0; a refusal names its reason and exits 1. -/
def custody : P (String × UInt32) := do
  let written ← nat 1 0 1
  let tpm ← nat 8
  let link ← pLink
  let cert ← pFramed
  let signed ← pFramed
  pure (match custodyOf (link.link sha3) cert signed (if written == 0 then none else some tpm) with
    | .create => ("GATE_VERIFY=CUSTODY create", 0)
    | .ready => ("GATE_VERIFY=CUSTODY ready", 0)
    | .catchUp => ("GATE_VERIFY=CUSTODY catch_up", 0)
    | .refuse .noStore => ("GATE_VERIFY=CUSTODY no_store", 1)
    | .refuse .counterReset => ("GATE_VERIFY=CUSTODY counter_reset", 1)
    | .refuse .storeRewound => ("GATE_VERIFY=CUSTODY store_rewound", 1)
    | .refuse .storeAhead => ("GATE_VERIFY=CUSTODY store_ahead", 1))

def index : P (String × UInt32) := do
  match storedOf sha3 (← pFramed) with
  | none => pure (accept false)
  | some x =>
    let c := x.checkpoint
    pure (s!"GATE_VERIFY=INDEX {hex c.tenantId} {c.shardId} {c.epoch} {c.seqFrom} {c.seqTo} {hex x.digest} {hex c.prevCheckpoint} {c.counter}", 0)

def store : P (String × UInt32) := do
  let s ← pAuthority
  let candidates ← pList pFramed
  let evidence ← pList pFork
  let new ← pFramed
  let some old := candidates.mapM (storedOf sha3) | fail
  let some forks := evidence.mapM storedPair | fail
  pure (match storeOutcome realCrypto s old forks new with
    | none => accept false
    | some none => ("GATE_VERIFY=STORED", 0)
    | some (some d) => (s!"GATE_VERIFY=FORK {hex d}", 0))

/-- The payer's state for one token, from what the adapter loaded, and `firstFailure` on it. -/
def release : P (String × UInt32) := do
  let s0 ← pAuthority
  let evidence ← pList pFork
  let checkpoint ← pFramed
  let now ← nat 8
  let grants ← pList pGrant
  let released ← nat 1 0 1
  let pinned ← nat 1 0 1
  let memberKey ← if pinned == 1 then take memberKeyBytes else pure []
  let some r := decodeRequest (← pFramed) | fail
  let token ← pFramed
  let some forks := evidence.mapM storedPair | fail
  pure (match releaseOutcome realCrypto s0 forks checkpoint now grants (released == 1)
      (if pinned == 1 then some memberKey else none) r.payment token with
    | none => ("GATE_VERIFY=ACCEPT", 0)
    | some f => (s!"GATE_VERIFY=HOLD {failureName f}", 1))

def refusalName : Cosign.Refusal → String
  | .MALFORMED => "MALFORMED" | .WRONG_TENANT => "WRONG_TENANT" | .GENERATION_AHEAD => "GENERATION_AHEAD"
  | .STALE_KEYSET => "STALE_KEYSET" | .WRONG_LINK => "WRONG_LINK" | .KEY_REUSE => "KEY_REUSE"
  | .AFTER_ROTATION => "AFTER_ROTATION" | .BAD_ROOT_SIGNATURE => "BAD_ROOT_SIGNATURE"
  | .BAD_WITNESS_SIGNATURE => "BAD_WITNESS_SIGNATURE"

def certAnswer : Cosign.CertAnswer → String × UInt32
  | .same => ("SAME", 0) | .installed => ("INSTALLED", 0) | .unfit => ("UNFIT", 0)
  | .equivocates => ("EQUIVOCATES", 0) | .unknownTenant => ("UNKNOWN_TENANT", 1) | .belowFence => ("REFUSED BELOW_FENCE", 1)
  | .refused r => (s!"REFUSED {refusalName r}", 1)

/-- INSTALL's answer on what its frame carries, the new certificate decoded. -/
def installAnswer (head own next : Option Cosign.SignedLink) (keyLinks : List Cosign.SignedLink)
    (same : Option Cosign.KeyCert) (links : List Cosign.SignedLink) (certs : List Cosign.KeyCert) (e : Cosign.KeyCert) :
    String × UInt32 :=
  let L := fun (n : Cosign.SignedLink) => n.link sha3
  let s0 := replay (underLinks realCrypto (links.map L)) certs
  let (a, code) := certAnswer (installOutcome realCrypto (head.map L) (own.map L) (next.map L) (keyLinks.map L) same s0 e)
  (s!"GATE_VERIFY=CERT {a}", code)

def install : P (String × UInt32) := do
  let head ← pOptLink
  let own ← pOptLink
  let next ← pOptLink
  let keyLinks ← pList pLink
  let same ← pOptCert
  let links ← pList pLink
  let certs ← pList pCert
  let some e := Cosign.decode (← pFramed) | pure ("GATE_VERIFY=CERT REFUSED MALFORMED", 1)
  pure (installAnswer head own next keyLinks same links certs e)

/-- `install` over the array by offset, each link and certificate decoded from its slice (`sim_install`). -/
def installB : Rd (String × UInt32) := fun b o => do
  let (head, o) ← rOptFramedD Cosign.decodeLinkB b o
  let (own, o) ← rOptFramedD Cosign.decodeLinkB b o
  let (next, o) ← rOptFramedD Cosign.decodeLinkB b o
  let (keyLinks, o) ← rList (rFramedD Cosign.decodeLinkB) b o
  let (same, o) ← rOptFramedD Cosign.decodeB b o
  let (links, o) ← rList (rFramedD Cosign.decodeLinkB) b o
  let (certs, o) ← rList (rFramedD Cosign.decodeB) b o
  let (new, o) ← rFramedB b o
  match Cosign.decodeB new with
  | some e => some (installAnswer head own next keyLinks same links certs e, o)
  | none => some (("GATE_VERIFY=CERT REFUSED MALFORMED", 1), o)

/-- `pAuthority` over the array by offset (`sim_authority`). -/
def rAuthority : Rd PayerState := fun b o => do
  let (head, o) ← rFramedD Cosign.decodeLinkB b o
  let (conflict, o) ← rOptFramedD Cosign.decodeLinkB b o
  let (links, o) ← rList (rFramedD Cosign.decodeLinkB) b o
  let (certs, o) ← rList (rFramedD Cosign.decodeB) b o
  let (fence, o) ← rOptFramedD Cosign.decodeB b o
  if !links.all (·.tenantId == head.tenantId) then none else
  let ok := underLinks realCrypto (links.map (·.link sha3))
  some (onLinks (replay ok certs) (linkView sha3 head conflict (fenceOf ok fence)), o)

/-- `pFork` over the array by offset (`sim_fork`). -/
def rFork : Rd (Bytes × Bytes) := fun b o => do
  let (x, o) ← rFramedL b o
  let (y, o) ← rFramedL b o
  some ((x, y), o)

/-- A recorded fork without the signed bytes of its two sides: a fork is read only through its checkpoints' fields
    (`releaseOutcome_lite`, `storeOutcome_lite`), and the bytes are most of a frame's memory. -/
def liteP (p : Stored × Stored) : Stored × Stored := ({ p.1 with bytes := [] }, { p.2 with bytes := [] })

/-- `storedPair`, without the sides' bytes. -/
def storedPairL (f : Bytes × Bytes) : Option (Stored × Stored) := (storedPair f).map liteP

/-- `rMany`, each item mapped by `φ` as soon as it is read, so the item itself is not kept (`rManyL_eq`). -/
def rManyL {α β : Type} (r : Rd α) (φ : α → β) : Nat → Rd (List β)
  | 0 => fun _ o => some ([], o)
  | k + 1 => fun b o => do
    let (x, o) ← r b o
    let y := φ x
    let (ys, o) ← rManyL r φ k b o
    some (y :: ys, o)

/-- `rList`, each item mapped by `φ` as it is read. -/
def rListL {α β : Type} (r : Rd α) (φ : α → β) : Rd (List β) := fun b o => do
  let (k, o) ← rNat 2 0 maxNat b o
  rManyL r φ k b o

/-- `pGrant` over the array by offset (`sim_grant`). -/
def rGrant : Rd Grant := fun b o => do
  let (tenantId, o) ← rIdent b o
  let (grantId, o) ← rBlob 0 65535 b o
  let (n, o) ← rNat 2 0 maxNat b o
  let (ruleVersions, o) ← rMany (rBlob 0 65535) n b o
  let (m, o) ← rNat 2 0 maxNat b o
  let (engineReleases, o) ← rMany (rBlob 0 65535) m b o
  some ({ tenantId, grantId, ruleVersions, engineReleases }, o)

/-- `store` over the array by offset (`sim_store`). -/
def storeB : Rd (String × UInt32) := fun b o => do
  let (s, o) ← rAuthority b o
  let (candidates, o) ← rList rFramedL b o
  let (evidence, o) ← rListL rFork storedPairL b o
  let (new, o) ← rFramedL b o
  let some old := candidates.mapM (storedOf sha3) | none
  let some forks := evidence.mapM id | none
  some ((match storeOutcome realCrypto s old forks new with
    | none => accept false
    | some none => ("GATE_VERIFY=STORED", 0)
    | some (some d) => (s!"GATE_VERIFY=FORK {hex d}", 0)), o)

/-- `release` over the array by offset (`sim_release`). -/
def releaseB : Rd (String × UInt32) := fun b o => do
  let (s0, o) ← rAuthority b o
  let (evidence, o) ← rListL rFork storedPairL b o
  let (checkpoint, o) ← rFramedL b o
  let (now, o) ← rNat 8 0 maxNat b o
  let (grants, o) ← rList rGrant b o
  let (released, o) ← rNat 1 0 1 b o
  let (pinned, o) ← rNat 1 0 1 b o
  let (memberKey, o) ← if pinned == 1 then rTake memberKeyBytes b o else some ([], o)
  let (rq, o) ← rFramedL b o
  let some r := decodeRequest rq | none
  let (token, o) ← rFramedL b o
  let some forks := evidence.mapM id | none
  some ((match releaseOutcome realCrypto s0 forks checkpoint now grants (released == 1)
      (if pinned == 1 then some memberKey else none) r.payment token with
    | none => ("GATE_VERIFY=ACCEPT", 0)
    | some f => (s!"GATE_VERIFY=HOLD {failureName f}", 1)), o)

def certIndex : P (String × UInt32) := do
  match Cosign.decode (← pFramed) with
  | none => pure (accept false)
  | some e => pure (s!"GATE_VERIFY=CERT-INDEX {hex e.tenantId} {e.epoch} {hex (sha3 e.body)} {hex e.link} {hex (sha3 e.key.enc)} {hex (sha3 e.verifierKey.enc)}", 0)

def linkAnswerName : Cosign.LinkAnswer → String
  | .same => "SAME" | .genesis => "GENESIS" | .extends => "EXTENDS" | .conflicts => "CONFLICTS" | .stale => "STALE"
  | .refused => "REFUSED"

def link : P (String × UInt32) := do
  let pin ← take 64
  let chain ← pList pLink
  let retired ← pList (pList pLink)
  let conflicts ← pList pLink
  let certs ← pList pCert
  let n ← pLink
  let L := fun (n : Cosign.SignedLink) => n.link sha3
  let some a := linkOutcome realCrypto pin (chain.map L) (retired.map (·.map L)) (conflicts.map L) certs n | fail
  pure (s!"GATE_VERIFY=LINK {linkAnswerName a}", if a == .refused then 1 else 0)

def linkIndex : P (String × UInt32) := do
  match Cosign.decodeLink (← pFramed) with
  | none => pure (accept false)
  | some n => pure (s!"GATE_VERIFY=LINK-INDEX {hex n.tenantId} {n.gen} {n.base} {hex (sha3 n.body)} {hex (sha3 n.root.enc)} {hex (sha3 n.witness.enc)} {hex n.rootNext} {hex n.witnessNext} {(n.closedThrough.map toString).getD "-"}", 0)

def frame : P (String × UInt32) := do
  match ← take 1 with
  | [1] => publish
  | [2] => index
  | [3] => store
  | [5] => release
  | [7] => custody
  | [8] => install
  | [9] => certIndex
  | [10] => link
  | [11] => linkIndex
  | _ => fail

/-- The answer to one request (mode byte then frame): PUBLISH, STORE, RELEASE and INSTALL frames take the `ByteArray`
    readers (`answerOf_eq`: the same answer as `frame` on the list, linear time; the list reader's `take` measures the
    whole remaining input at every field, quadratic on a RELEASE of many stored forks). Pure: nothing is kept between
    requests. -/
def answerOf (bs : ByteArray) : Option (String × UInt32) :=
  if bs[0]? == some 1 then (publishFrameB (bs.extract 1 bs.size)).map accept
  else if bs[0]? == some 8 then parseB installB bs.size (bs.extract 1 bs.size)
  else if bs[0]? == some 3 then parseB storeB bs.size (bs.extract 1 bs.size)
  else if bs[0]? == some 5 then parseB releaseB bs.size (bs.extract 1 bs.size)
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
