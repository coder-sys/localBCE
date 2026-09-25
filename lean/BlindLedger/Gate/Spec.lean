namespace BlindLedger.Gate

/-! Payment gate formats, first slice (founder decision D1, 2026-09-25):
    `RR/GATE/DECIDE-REQUEST/v1`, `DECIDE-RESPONSE/v1`, `TOKEN/v1`,
    `CHECKPOINT/v1` (ML-DSA-87 per-batch variant) and the SHA3-512 digest
    domains `DECISION-ID/v1`, `INPUT/v1`, `MERKLE-NODE/v1`.

    These decoders are the specification; `app/right_rail_gate_codec.py` only
    produces bytes.  `verifyToken` is the payer's whole release decision: one
    predicate over nine checks.  Hashing, the epoch-certificate chain (format
    #5, not yet built) and ML-DSA-87 verification enter only through `Crypto`,
    so every statement here holds for any instantiation.  Synthetic,
    nonpayment, activation=false. -/

abbrev Bytes := List UInt8

def digestBytes : Nat := 64
def maxNat : Nat := 2 ^ 63 - 1
def maxBatch : Nat := 1000
def maxTokenPath : Nat := 10
def maxLines : Nat := 65535
def maxLineBytes : Nat := 512
def maxEvidenceRefs : Nat := 256
def maxReasonCodes : Nat := 32
def maxRetryAfterMs : Nat := 3600000
def maxRequestBytes : Nat := 8 * 1024 * 1024
def maxTokenBytes : Nat := 16 * 1024
def mlDsa87Signature : Nat := 4627
def clockSkew : Nat := 60
def zeroDigest : Bytes := List.replicate digestBytes 0

def domain (name : String) : Bytes := ("RR/GATE/" ++ name ++ "/v1").toUTF8.toList ++ [0]

inductive Flow | FFS_CYCLE | FFS_CLAIM | CAP_820 | SDP | PLAN_PAY deriving DecidableEq, Repr
inductive Outcome | ALLOW | HOLD | HUMAN_REVIEW | BLOCK deriving DecidableEq, Repr
inductive Authority | OBSERVE | HOLD | TRANSFER deriving DecidableEq, Repr
inductive Status | DECIDED | DUPLICATE | REJECTED | UNAVAILABLE deriving DecidableEq, Repr
inductive RejectCode | MALFORMED | COMMAND_KEY_CONFLICT deriving DecidableEq, Repr

/-! ## Canonical reader: fixed-width big-endian naturals, u16-length
    identifiers, raw 64-byte digests, one-byte tags, bounded counts. -/

abbrev P := StateT Bytes Option

def fail {α : Type} : P α := fun _ => none
def need (ok : Bool) : P Unit := fun b => if ok then some ((), b) else none
def take (n : Nat) : P Bytes := fun b => if n ≤ b.length then some (b.take n, b.drop n) else none
def beNat (bs : Bytes) : Nat := bs.foldl (fun acc x => acc * 256 + x.toNat) 0

def nat (width : Nat) (lo : Nat := 0) (hi : Nat := maxNat) : P Nat := do
  let value := beNat (← take width)
  need (lo ≤ value && value ≤ hi)
  pure value

def tag {α : Type} (names : List α) : P α := do
  match names[(← nat 1 1 names.length) - 1]? with
  | some x => pure x
  | none => fail

def digest : P Bytes := take digestBytes
def blob (lo hi : Nat) : P Bytes := do take (← nat 2 lo hi)
def expect (d : Bytes) : P Unit := do need ((← take d.length) == d)

def many {α : Type} (p : P α) : Nat → P (List α)
  | 0 => pure []
  | k + 1 => do
      let x ← p
      pure (x :: (← many p k))

/-- The consumed bytes of `p`, so a signature or Merkle leaf covers exactly
    what was parsed. -/
def consumed {α : Type} (p : P α) : P (α × Bytes) := fun b =>
  match p.run b with
  | some (x, rest) => some ((x, b.take (b.length - rest.length)), rest)
  | none => none

def within (lo hi : UInt8) (c : UInt8) : Bool := lo ≤ c && c ≤ hi
def alnum (c : UInt8) : Bool := within 48 57 c || within 65 90 c || within 97 122 c

/-- `[A-Za-z0-9][A-Za-z0-9._:-]{0,127}` -/
def identOk : Bytes → Bool
  | [] => false
  | c :: rest => alnum c && rest.length ≤ 127 &&
      rest.all (fun x => alnum x || x == 46 || x == 95 || x == 58 || x == 45)

/-- `[A-Z][A-Z0-9_]{0,63}` -/
def codeOk : Bytes → Bool
  | [] => false
  | c :: rest => within 65 90 c && rest.length ≤ 63 &&
      rest.all (fun x => within 65 90 x || within 48 57 x || x == 95)

def ident : P Bytes := do
  let bs ← blob 1 65535
  need (identOk bs)
  pure bs

def code : P Bytes := do
  let bs ← blob 1 65535
  need (codeOk bs)
  pure bs

def lexLt : Bytes → Bytes → Bool
  | [], [] => false
  | [], _ :: _ => true
  | _ :: _, [] => false
  | a :: as, b :: bs => a < b || (a == b && lexLt as bs)

def ascending : List Bytes → Bool
  | a :: b :: rest => lexLt a b && ascending (b :: rest)
  | _ => true

/-- Whole-input parse: size bound, then no trailing bytes. -/
def parse {α : Type} (p : P α) (limit : Nat) (b : Bytes) : Option α :=
  if b.length > limit then none else
  match p.run b with
  | some (x, []) => some x
  | _ => none

/-! ## #12 digest domains -/

def natBE (width value : Nat) : Bytes :=
  (List.range width).reverse.map (fun i => UInt8.ofNat (value / 256 ^ i % 256))

def identField (x : Bytes) : Bytes := natBE 2 x.length ++ x

def decisionId (H : Bytes → Bytes) (tenant program commandKey : Bytes) (revision : Nat) : Bytes :=
  H (domain "DECISION-ID" ++ identField tenant ++ identField program ++ identField commandKey ++
    natBE 8 revision)

def inputCommitment (H : Bytes → Bytes) (request readSet : Bytes) : Bytes :=
  H (domain "INPUT" ++ natBE 4 request.length ++ request ++ readSet)

def leafHash (H : Bytes → Bytes) (x : Bytes) : Bytes := H (domain "MERKLE-NODE" ++ (0 :: x))
def nodeHash (H : Bytes → Bytes) (l r : Bytes) : Bytes := H (domain "MERKLE-NODE" ++ (1 :: (l ++ r)))

/-- One tree level: pairs hash up; an odd last node is carried unchanged. -/
def pairUp (H : Bytes → Bytes) : List Bytes → List Bytes
  | a :: b :: rest => nodeHash H a b :: pairUp H rest
  | xs => xs

def treeRoot (H : Bytes → Bytes) : Nat → List Bytes → Bytes
  | _, [x] => x
  | 0, _ => zeroDigest
  | fuel + 1, xs => treeRoot H fuel (pairUp H xs)

/-- Bounded depth: 65,535 lines or 1,000 batch leaves need at most 16 levels. -/
def treeFuel : Nat := 17

def linesRoot (H : Bytes → Bytes) (lines : List Bytes) : Bytes :=
  if lines.isEmpty then zeroDigest else treeRoot H treeFuel (lines.map (leafHash H))

/-- Fold an inclusion path.  The shape comes from `(index, count)` alone: a
    carried node consumes no sibling, and the path must be used up exactly. -/
def pathRoot (H : Bytes → Bytes) : Nat → Nat → Nat → Bytes → List Bytes → Option Bytes
  | 0, _, _, _, _ => none
  | fuel + 1, index, count, node, path =>
    if count ≤ 1 then (if path.isEmpty then some node else none)
    else if index % 2 == 0 && index + 1 == count then
      pathRoot H fuel (index / 2) ((count + 1) / 2) node path
    else match path with
      | [] => none
      | s :: rest =>
        pathRoot H fuel (index / 2) ((count + 1) / 2)
          (if index % 2 == 0 then nodeHash H node s else nodeHash H s node) rest

def verifyPath (H : Bytes → Bytes) (leaf : Bytes) (index count : Nat) (path : List Bytes)
    (root : Bytes) : Bool :=
  index < count && pathRoot H treeFuel index count (leafHash H leaf) path == some root

/-! ## #1 DECIDE-REQUEST/v1 -/

def flows : List Flow := [.FFS_CYCLE, .FFS_CLAIM, .CAP_820, .SDP, .PLAN_PAY]
def outcomes : List Outcome := [.ALLOW, .HOLD, .HUMAN_REVIEW, .BLOCK]
def authorities : List Authority := [.OBSERVE, .HOLD, .TRANSFER]
def statuses : List Status := [.DECIDED, .DUPLICATE, .REJECTED, .UNAVAILABLE]
def rejectCodes : List RejectCode := [.MALFORMED, .COMMAND_KEY_CONFLICT]

structure Request where
  tenantId : Bytes
  programId : Bytes
  flow : Flow
  commandKey : Bytes
  paymentId : Bytes
  payeeRef : Bytes
  amountCents : Nat
  period : Bytes
  lines : List Bytes
  evidenceRefs : List Bytes

def pRequest : P Request := do
  expect (domain "DECIDE-REQUEST")
  let tenantId ← ident
  let programId ← ident
  let flow ← tag flows
  let commandKey ← ident
  let paymentId ← ident
  let payeeRef ← ident
  let amountCents ← nat 8
  let period ← ident
  let lines ← many (blob 1 maxLineBytes) (← nat 2 0 maxLines)
  need (flow != .FFS_CLAIM || lines.isEmpty)
  let evidenceRefs ← many digest (← nat 2 0 maxEvidenceRefs)
  need (ascending evidenceRefs)
  pure { tenantId, programId, flow, commandKey, paymentId, payeeRef, amountCents, period, lines,
         evidenceRefs }

def decodeRequest : Bytes → Option Request := parse pRequest maxRequestBytes

/-! ## #4 CHECKPOINT/v1 (ML-DSA-87 per-batch variant): the signed bytes -/

structure Checkpoint where
  tenantId : Bytes
  programId : Bytes
  seqFrom : Nat
  seqTo : Nat
  epoch : Nat
  prevCheckpoint : Bytes
  eventHead : Bytes
  tokenRoot : Bytes
  evidenceRoot : Bytes
  projections : Bytes
  count : Nat
  createdAt : Nat

def pCheckpoint : P Checkpoint := do
  expect (domain "CHECKPOINT")
  let _ ← nat 1 1 1
  let tenantId ← ident
  let programId ← ident
  let seqFrom ← nat 8
  let seqTo ← nat 8
  let epoch ← nat 8
  let prevCheckpoint ← digest
  let eventHead ← digest
  let tokenRoot ← digest
  let evidenceRoot ← digest
  let projections ← digest
  let count ← nat 2 1 maxBatch
  let createdAt ← nat 8
  need (seqTo + 1 == seqFrom + count)
  pure { tenantId, programId, seqFrom, seqTo, epoch, prevCheckpoint, eventHead, tokenRoot,
         evidenceRoot, projections, count, createdAt }

def decodeCheckpoint : Bytes → Option Checkpoint := parse pCheckpoint maxTokenBytes

/-! ## #3 TOKEN/v1: leaf || checkpoint || path || signature || epoch_cert_id -/

structure Leaf where
  tenantId : Bytes
  programId : Bytes
  flow : Flow
  decisionId : Bytes
  revision : Nat
  supersedes : Option Bytes
  paymentId : Bytes
  payeeRef : Bytes
  amountCents : Nat
  period : Bytes
  linesRoot : Bytes
  lineCount : Nat
  outcome : Outcome
  reasonCodes : List Bytes
  authority : Authority
  grantId : Bytes
  ruleVersion : Bytes
  engineRelease : Bytes
  inputCommitment : Bytes
  epoch : Nat
  seq : Nat
  issuedAt : Nat
  expiresAt : Nat

def pLeaf : P Leaf := do
  expect (domain "TOKEN")
  let tenantId ← ident
  let programId ← ident
  let flow ← tag flows
  let decisionId ← digest
  let revision ← nat 8
  let supersedes ← if (← nat 1 0 1) == 1 then some <$> digest else pure none
  let paymentId ← ident
  let payeeRef ← ident
  let amountCents ← nat 8
  let period ← ident
  let linesRoot ← digest
  let lineCount ← nat 2 0 maxLines
  let outcome ← tag outcomes
  let reasonCodes ← many code (← nat 1 0 maxReasonCodes)
  let authority ← tag authorities
  let grantId ← digest
  let ruleVersion ← digest
  let engineRelease ← digest
  let inputCommitment ← digest
  let epoch ← nat 8
  let seq ← nat 8
  let issuedAt ← nat 8
  let expiresAt ← nat 8
  need ((revision == 0) == supersedes.isNone)
  need ((lineCount == 0) == (linesRoot == zeroDigest))
  need (flow != .FFS_CLAIM || lineCount == 0)
  need (ascending reasonCodes)
  pure { tenantId, programId, flow, decisionId, revision, supersedes, paymentId, payeeRef,
         amountCents, period, linesRoot, lineCount, outcome, reasonCodes, authority, grantId,
         ruleVersion, engineRelease, inputCommitment, epoch, seq, issuedAt, expiresAt }

structure Token where
  leaf : Leaf
  leafBytes : Bytes
  checkpoint : Checkpoint
  checkpointBytes : Bytes
  siblings : List Bytes
  signature : Bytes
  epochCertId : Bytes

def pToken : P Token := do
  let (leaf, leafBytes) ← consumed pLeaf
  let (checkpoint, checkpointBytes) ← consumed pCheckpoint
  let siblings ← many digest (← nat 1 0 maxTokenPath)
  let signature ← blob mlDsa87Signature mlDsa87Signature
  let epochCertId ← digest
  pure { leaf, leafBytes, checkpoint, checkpointBytes, siblings, signature, epochCertId }

def decodeToken : Bytes → Option Token := parse pToken maxTokenBytes

/-! ## #2 DECIDE-RESPONSE/v1: outcome and reasons travel only inside the token -/

structure Response where
  tenantId : Bytes
  programId : Bytes
  commandKey : Bytes
  status : Status
  token : Option Token
  rejectCode : Option RejectCode
  retryAfterMs : Option Nat

def pResponse (H : Bytes → Bytes) : P Response := do
  expect (domain "DECIDE-RESPONSE")
  let tenantId ← ident
  let programId ← ident
  let commandKey ← ident
  let status ← tag statuses
  let base : Response := { tenantId, programId, commandKey, status, token := none,
                           rejectCode := none, retryAfterMs := none }
  match status with
  | .DECIDED | .DUPLICATE =>
    match decodeToken (← take (← nat 4 0 maxTokenBytes)) with
    | none => fail
    | some t =>
      need (t.leaf.tenantId == tenantId && t.leaf.programId == programId &&
        t.leaf.decisionId == decisionId H tenantId programId commandKey t.leaf.revision)
      pure { base with token := some t }
  | .REJECTED => pure { base with rejectCode := some (← tag rejectCodes) }
  | .UNAVAILABLE => pure { base with retryAfterMs := some (← nat 4 1 maxRetryAfterMs) }

def decodeResponse (H : Bytes → Bytes) : Bytes → Option Response :=
  parse (pResponse H) (maxTokenBytes + 1024)

/-! ## The payer's release decision -/

structure EpochCert where
  certId : Bytes
  epoch : Nat
  tenantId : Bytes
  publicKey : Bytes

structure Crypto where
  hash : Bytes → Bytes
  /-- KEY-CERT (#5) chain validity; supplied until that format exists. -/
  certChainOk : EpochCert → Bool
  /-- ML-DSA-87 verification: public key, message, signature. -/
  sigOk : Bytes → Bytes → Bytes → Bool

structure Grant where
  grantId : Bytes
  ruleVersions : List Bytes
  engineReleases : List Bytes

/-- Payer-side state.  `grants` holds only active grants; `released` holds
    every payment id already released. -/
structure PayerState where
  fence : Nat
  now : Nat
  certs : List EpochCert
  grants : List Grant
  released : List Bytes

/-- The payment the payer is about to release. -/
structure Payment where
  tenantId : Bytes
  programId : Bytes
  flow : Flow
  paymentId : Bytes
  payeeRef : Bytes
  amountCents : Nat
  period : Bytes
  lines : List Bytes

def certFor (s : PayerState) (t : Token) : Option EpochCert :=
  s.certs.find? (·.certId == t.epochCertId)

/-- Check 2: the epoch certificate chains and names the token's epoch and tenant. -/
def certValid (c : Crypto) (s : PayerState) (t : Token) : Bool :=
  match certFor s t with
  | some e => c.certChainOk e && e.epoch == t.leaf.epoch && e.tenantId == t.leaf.tenantId
  | none => false

/-- Check 3: the batch checkpoint is signed under the epoch key, is the
    token's own batch, and the Merkle path hashes the leaf to `token_root`. -/
def batchSigned (c : Crypto) (s : PayerState) (t : Token) : Bool :=
  let cp := t.checkpoint
  match certFor s t with
  | some e => c.sigOk e.publicKey t.checkpointBytes t.signature &&
      cp.tenantId == t.leaf.tenantId && cp.programId == t.leaf.programId &&
      cp.epoch == t.leaf.epoch && cp.seqFrom ≤ t.leaf.seq &&
      verifyPath c.hash t.leafBytes (t.leaf.seq - cp.seqFrom) cp.count t.siblings cp.tokenRoot
  | none => false

/-- Check 4: epoch ≥ fence. -/
def aboveFence (s : PayerState) (t : Token) : Bool := s.fence ≤ t.leaf.epoch

/-- Check 5: not expired, allowing `clockSkew` seconds. -/
def unexpired (s : PayerState) (t : Token) : Bool := s.now < t.leaf.expiresAt + clockSkew

/-- Check 6: the payment matches field for field and its lines hash to `lines_root`. -/
def paymentMatches (c : Crypto) (p : Payment) (t : Token) : Bool :=
  let l := t.leaf
  l.tenantId == p.tenantId && l.programId == p.programId && l.flow == p.flow &&
    l.paymentId == p.paymentId &&
    l.payeeRef == p.payeeRef && l.amountCents == p.amountCents && l.period == p.period &&
    p.lines.length == l.lineCount && linesRoot c.hash p.lines == l.linesRoot

/-- Check 7. -/
def allows (t : Token) : Bool := t.leaf.outcome == .ALLOW

/-- Check 8: an active grant approves this rule version and engine release. -/
def granted (s : PayerState) (t : Token) : Bool :=
  s.grants.any fun g => g.grantId == t.leaf.grantId &&
    g.ruleVersions.contains t.leaf.ruleVersion && g.engineReleases.contains t.leaf.engineRelease

/-- Check 9. -/
def unreleased (s : PayerState) (t : Token) : Bool := !s.released.contains t.leaf.paymentId

/-- Release only when all nine checks hold; check 1 is a canonical `TOKEN/v1` parse. -/
def verifyToken (c : Crypto) (s : PayerState) (p : Payment) (bytes : Bytes) : Bool :=
  match decodeToken bytes with
  | none => false
  | some t => certValid c s t && batchSigned c s t && aboveFence s t && unexpired s t &&
      paymentMatches c p t && allows t && granted s t && unreleased s t

/-- The payer's step after releasing on `t`, as `PayerRelease` in
    `docs/formal/gate_failover/gate_failover.tla`: record the payment and
    raise the fence to the token's epoch. -/
def release (s : PayerState) (t : Token) : PayerState :=
  { s with fence := max s.fence t.leaf.epoch, released := t.leaf.paymentId :: s.released }

end BlindLedger.Gate
