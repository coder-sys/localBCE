namespace BlindLedger.Gate

/-! Payment gate formats, first slice (2026-09-25):
    `RR/GATE/DECIDE-REQUEST/v2`, `DECIDE-RESPONSE/v2`, `TOKEN/v3`, `EARLIER/v1`,
    `CHECKPOINT/v3` (ML-DSA-87 per-batch variant, with the verifier's cosign record
    `VCOSIGN/v1`) and the SHA3-512 digest domains `DECISION-ID/v1`, `INPUT/v1`, `MERKLE-NODE/v1` (batch token tree),
    `LINES-NODE/v1` (a payment's lines tree), `SHARD/v1` and `STATE/v1` (the
    rules' released and unresolved sets).  Every name, the rules' set pins
    included, is registered in `docs/RIGHTRAIL_FULL_STACK_TARGET.md` §5.  Gate
    `WireFlow` and `WireOutcome` are the wire enums; `BlindLedger.Gate.Rules`
    has its own `Flow` and `Outcome`, whose tags and names equal these.

    These decoders are the specification; `app/right_rail_gate_codec.py` only
    produces bytes.  The key certificate (`KEY-CERT/v2`) is `Cosign.Codec`, and
    the payer that reads these formats is `Payer`.  Synthetic, nonpayment, activation=false. -/

abbrev Bytes := List UInt8

def digestBytes : Nat := 64
def maxNat : Nat := 2 ^ 63 - 1
def maxBatch : Nat := 1000
def maxTokenPath : Nat := 10
def maxLines : Nat := 65535
/-- The largest canonical line (`pLine`: four 128-byte identifiers). -/
def maxLineBytes : Nat := 569
def maxEvidenceRefs : Nat := 256
def maxReasonCodes : Nat := 32
def maxRetryAfterMs : Nat := 3600000
def maxRequestBytes : Nat := 8 * 1024 * 1024
def maxTokenBytes : Nat := 4 * 1024
/-- A signed checkpoint with its cosign record is at most 9,990 bytes. -/
def maxCheckpointBytes : Nat := 16 * 1024
def mlDsa87Signature : Nat := 4627
def mlDsa87Key : Nat := 2592
/-- A member key: the member's salted hash (D5 salt vault), 32 bytes. -/
def memberKeyBytes : Nat := 32
/-- Seconds of clock difference a payer allows on either side of a token's lifetime. -/
def clockSkew : Nat := 300
/-- Seven days: the longest `expires_at - issued_at` a token may carry. -/
def maxTokenLifetime : Nat := 7 * 24 * 3600
def zeroDigest : Bytes := List.replicate digestBytes 0

def domain (name : String) : Bytes := ("RR/GATE/" ++ name ++ "/v1").toUTF8.toList ++ [0]

inductive WireFlow | FFS_CYCLE | FFS_CLAIM | CAP_820 | SDP | PLAN_PAY deriving DecidableEq, Repr
inductive WireOutcome | ALLOW | HOLD | HUMAN_REVIEW | BLOCK | ANSWERED deriving DecidableEq, Repr
inductive Authority | OBSERVE | HOLD | TRANSFER deriving DecidableEq, Repr
/-- OBSERVE below HOLD below TRANSFER. -/
def Authority.rank : Authority → Nat | .OBSERVE => 0 | .HOLD => 1 | .TRANSFER => 2
/-- `PAYMENT_ALREADY_DECIDED`: a new command key, under any flow, for a payment
    that already has a decision; the existing decision comes back, re-issued
    (`reissues`) if its token is fenced or expired, or re-decided (`redecides`)
    if it is an ALLOW past its age.  Otherwise only a state official's
    determination (a later format) changes a decision. -/
inductive Status | DECIDED | DUPLICATE | REJECTED | UNAVAILABLE | PAYMENT_ALREADY_DECIDED
  deriving DecidableEq, Repr
inductive RejectCode | MALFORMED | COMMAND_KEY_CONFLICT deriving DecidableEq, Repr

/-- How long an ALLOW stays payable: the run it was decided for and one missed
    run.  FFS_CLAIM (and the unruled flows): 14 days, as FFS checkwrites run
    weekly or biweekly.  FFS_CYCLE: 28 days, one biweekly cycle and one missed
    run.  CAP_820: 62 days, one monthly capitation run (at most 31 days) and one
    missed.  An older ALLOW is refused (check 5) and re-decided (`redecides`). -/
def maxDecisionAge : WireFlow → Nat
  | .FFS_CYCLE => 28 * 24 * 3600
  | .CAP_820 => 62 * 24 * 3600
  | _ => 14 * 24 * 3600

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

def flows : List WireFlow := [.FFS_CYCLE, .FFS_CLAIM, .CAP_820, .SDP, .PLAN_PAY]

/-- The wire tag of a flow: its position in `flows`, plus one. -/
def WireFlow.tag : WireFlow → UInt8
  | .FFS_CYCLE => 1 | .FFS_CLAIM => 2 | .CAP_820 => 3 | .SDP => 4 | .PLAN_PAY => 5

/-- Flows the rules decide line by line (`BlindLedger.Gate.Rules.Flow`): each payment carries a
    line.  SDP and PLAN_PAY have no rules; the gate sends them to HUMAN_REVIEW. -/
def WireFlow.ruled (f : WireFlow) : Bool := f == .FFS_CYCLE || f == .FFS_CLAIM || f == .CAP_820

/-- One decision per payment and revision.  Neither the command key nor the
    flow is part of it, so a resubmission under another key or flow finds the
    existing decision. -/
def decisionId (H : Bytes → Bytes) (tenant program paymentId : Bytes) (revision : Nat) : Bytes :=
  H (domain "DECISION-ID" ++ identField tenant ++ identField program ++ identField paymentId ++
    natBE 8 revision)

/-- The shard of a member: the first four bytes of `H(SHARD ‖ tenant ‖
    member_key)` as a big-endian u32, mod the tenant's shard count.  The gate
    routes a payment by it and the payer recomputes it (`routed`), so no
    registry is needed.  v1 fixes the shard count per tenant (`installCert`);
    resharding needs a future migration spec. -/
def shardOf (H : Bytes → Bytes) (tenant memberKey : Bytes) (shardCount : Nat) : Nat :=
  beNat ((H (domain "SHARD" ++ identField tenant ++ memberKey)).take 4) % shardCount

def inputCommitment (H : Bytes → Bytes) (request readSet : Bytes) : Bytes :=
  H (domain "INPUT" ++ natBE 4 request.length ++ request ++ readSet)

/-- A variable-length field: its 4-byte big-endian length, then its bytes. -/
def lp32 (x : Bytes) : Bytes := natBE 4 x.length ++ x

/-- `CONTEXT/v1`, hashed once a batch: the request frame's body before its request count (`Frame.ctxBytes`): today,
    the chain head the batch follows, the feeds with their pins, the redone payments, the key-set pin, the grant floor,
    the signed grant, key set and key-set steps, the signed bypasses and the engine release. -/
def contextPre (body : Bytes) : Bytes := domain "CONTEXT" ++ body

def context (H : Bytes → Bytes) (body : Bytes) : Bytes := H (contextPre body)

/-- `INPUT/v7`'s preimage, a token's input commitment: the batch context (64 bytes), a request's bytes before its
    lines (length-prefixed), the root of its lines (64 bytes), then its bytes after them (the evidence count and
    references). -/
def inputV7Pre (ctx head root tail : Bytes) : Bytes :=
  "RR/GATE/INPUT/v7".toUTF8.toList ++ [0] ++ ctx ++ lp32 head ++ root ++ tail

/-- `BATCH-INPUT/v1`'s preimage, a batch's identity (III.3): the context, then each payment's input in frame order. -/
def batchInputPre (ctx : Bytes) (rqs : List Bytes) : Bytes := domain "BATCH-INPUT" ++ ctx ++ rqs.flatten

def batchInput (H : Bytes → Bytes) (ctx : Bytes) (rqs : List Bytes) : Bytes := H (batchInputPre ctx rqs)

/-- A checkpoint's state digest: the gate's checkpoints of its released and
    unresolved sets after the batch (`BlindLedger.Gate.Rules.Result`), each as
    the 64-byte pin the rules runner checks (`Rules/Run.lean` `snapshot`). -/
def stateDigest (H : Bytes → Bytes) (releasedPin unresolvedPin : Bytes) : Bytes :=
  H (domain "STATE" ++ releasedPin ++ unresolvedPin)

/-- Merkle trees under a domain `d`: `MERKLE-NODE` for a batch's tokens,
    `LINES-NODE` for a payment's lines.  Leaf `H(d ‖ 0 ‖ x)`, node `H(d ‖ 1 ‖ l ‖ r)`. -/
def leafHash (H : Bytes → Bytes) (d x : Bytes) : Bytes := H (d ++ (0 :: x))
def nodeHash (H : Bytes → Bytes) (d l r : Bytes) : Bytes := H (d ++ (1 :: (l ++ r)))

/-- One tree level: pairs hash up; an odd last node is carried unchanged. -/
def pairUp (H : Bytes → Bytes) (d : Bytes) : List Bytes → List Bytes
  | a :: b :: rest => nodeHash H d a b :: pairUp H d rest
  | xs => xs

/-- Out of fuel yields `[]`, which no 64-byte digest equals. -/
def treeRoot (H : Bytes → Bytes) (d : Bytes) : Nat → List Bytes → Bytes
  | _, [x] => x
  | 0, _ => []
  | fuel + 1, xs => treeRoot H d fuel (pairUp H d xs)

/-- Bounded depth: 65,535 lines or 1,000 batch leaves need at most 16 levels. -/
def treeFuel : Nat := 17

/-- A payment's lines root; it also fixes their number, so no line count travels. -/
def linesRoot (H : Bytes → Bytes) (lines : List Bytes) : Bytes :=
  let d := domain "LINES-NODE"
  if lines.isEmpty then zeroDigest else treeRoot H d treeFuel (lines.map (leafHash H d))

/-- The hash input of one path step: the node and its sibling in tree order. -/
def stepInput (d : Bytes) (index : Nat) (node s : Bytes) : Bytes :=
  d ++ (1 :: (if index % 2 == 0 then node ++ s else s ++ node))

/-- Fold an inclusion path.  The shape comes from `(index, count)` alone: a
    carried node consumes no sibling, and the path must be used up exactly. -/
def pathRoot (H : Bytes → Bytes) (d : Bytes) : Nat → Nat → Nat → Bytes → List Bytes → Option Bytes
  | 0, _, _, _, _ => none
  | fuel + 1, index, count, node, path =>
    if count ≤ 1 then (if path.isEmpty then some node else none)
    else if index % 2 == 0 && index + 1 == count then
      pathRoot H d fuel (index / 2) ((count + 1) / 2) node path
    else match path with
      | [] => none
      | s :: rest => pathRoot H d fuel (index / 2) ((count + 1) / 2) (H (stepInput d index node s)) rest

def verifyPath (H : Bytes → Bytes) (d leaf : Bytes) (index count : Nat) (path : List Bytes)
    (root : Bytes) : Bool :=
  index < count && pathRoot H d treeFuel index count (leafHash H d leaf) path == some root

/-- Walk two folds at one position in lockstep and return the first pair of
    distinct hash inputs with one output. -/
def pathCollision (H : Bytes → Bytes) (d : Bytes) :
    Nat → Nat → Nat → Bytes → Bytes → List Bytes → List Bytes → Option (Bytes × Bytes)
  | 0, _, _, _, _, _, _ => none
  | fuel + 1, index, count, a, b, p, q =>
    if count ≤ 1 then none
    else if index % 2 == 0 && index + 1 == count then
      pathCollision H d fuel (index / 2) ((count + 1) / 2) a b p q
    else match p, q with
      | s :: ps, t :: qs =>
        if stepInput d index a s ≠ stepInput d index b t ∧
            H (stepInput d index a s) = H (stepInput d index b t) then
          some (stepInput d index a s, stepInput d index b t)
        else pathCollision H d fuel (index / 2) ((count + 1) / 2)
          (H (stepInput d index a s)) (H (stepInput d index b t)) ps qs
      | _, _ => none

/-- The colliding pair behind two leaves accepted at one position under one root. -/
def leafCollision (H : Bytes → Bytes) (d x y : Bytes) (index count : Nat) (p q : List Bytes) :
    Option (Bytes × Bytes) :=
  if d ++ (0 :: x) ≠ d ++ (0 :: y) ∧ H (d ++ (0 :: x)) = H (d ++ (0 :: y)) then
    some (d ++ (0 :: x), d ++ (0 :: y))
  else pathCollision H d treeFuel index count (leafHash H d x) (leafHash H d y) p q

/-! ## #1 DECIDE-REQUEST/v2 -/

def outcomes : List WireOutcome := [.ALLOW, .HOLD, .HUMAN_REVIEW, .BLOCK, .ANSWERED]
def authorities : List Authority := [.OBSERVE, .HOLD, .TRANSFER]
def statuses : List Status := [.DECIDED, .DUPLICATE, .REJECTED, .UNAVAILABLE, .PAYMENT_ALREADY_DECIDED]
def rejectCodes : List RejectCode := [.MALFORMED, .COMMAND_KEY_CONFLICT]

/-- One line of `Request.lines`, a leaf of `lines_root`: the rules' `Line`
    as flow tag, line id, member key, payee, rendering party, service date
    (CCYYMMDD), procedure, units and cents; identifiers are u16-length. -/
structure WireLine where
  flow : WireFlow
  memberKey : Bytes
  payeeRef : Bytes
  cents : Nat

def pLine : P WireLine := do
  let flow ← tag flows
  let _ ← ident
  let memberKey ← take memberKeyBytes
  let payeeRef ← ident
  let _ ← ident
  let _ ← nat 4
  let _ ← ident
  let _ ← nat 4
  let cents ← nat 8
  pure { flow, memberKey, payeeRef, cents }

structure Request where
  tenantId : Bytes
  programId : Bytes
  flow : WireFlow
  commandKey : Bytes
  paymentId : Bytes
  memberKey : Bytes
  payeeRef : Bytes
  amountCents : Nat
  period : Bytes
  lines : List Bytes
  evidenceRefs : List Bytes
  /-- The sender contests an answer that a line exactly repeats a paid line: the payment is decided as before. -/
  contest : Bool := false

def decideRequestDomain : Bytes := "RR/GATE/DECIDE-REQUEST/v2".toUTF8.toList ++ [0]

def pRequest : P Request := do
  expect decideRequestDomain
  let tenantId ← ident
  let programId ← ident
  let flow ← tag flows
  let commandKey ← ident
  let paymentId ← ident
  let memberKey ← take memberKeyBytes
  let payeeRef ← ident
  let amountCents ← nat 8
  let period ← ident
  let lines ← many (blob 1 maxLineBytes) (← nat 2 0 maxLines)
  -- Each line is canonical and this payment's (flow, member, payee), the
  -- lines sum to its amount, and a ruled flow's payment carries its lines.
  let ls := lines.filterMap (parse pLine maxLineBytes)
  need (ls.length == lines.length)
  need (ls.all fun l => l.flow == flow && l.memberKey == memberKey && l.payeeRef == payeeRef)
  need (lines.isEmpty || ls.foldl (· + ·.cents) 0 == amountCents)
  need (!flow.ruled || !lines.isEmpty)
  let evidenceRefs ← many digest (← nat 2 0 maxEvidenceRefs)
  need (ascending evidenceRefs)
  let contest ← nat 1 0 1
  pure { tenantId, programId, flow, commandKey, paymentId, memberKey, payeeRef, amountCents, period,
         lines, evidenceRefs, contest := contest == 1 }

def decodeRequest : Bytes → Option Request := parse pRequest maxRequestBytes

/-- A request's bytes before its lines, as `pRequest` reads them: the domain, the payment's fields and the line count. -/
def requestHead (r : Request) : Bytes :=
  decideRequestDomain ++ identField r.tenantId ++ identField r.programId ++ [r.flow.tag] ++ identField r.commandKey ++
    identField r.paymentId ++ r.memberKey ++ identField r.payeeRef ++ natBE 8 r.amountCents ++ identField r.period ++
    natBE 2 r.lines.length

/-- A request's bytes after its lines: the evidence count and references, and the contest flag. -/
def requestTail (r : Request) : Bytes :=
  natBE 2 r.evidenceRefs.length ++ r.evidenceRefs.flatten ++ [if r.contest then 1 else 0]

/-- A token's input under the batch context `ctx`: each byte of the request is hashed once, its lines as leaves of
    their root. -/
def inputV7 (H : Bytes → Bytes) (ctx : Bytes) (r : Request) : Bytes :=
  H (inputV7Pre ctx (requestHead r) (linesRoot H r.lines) (requestTail r))

/-! ## #4 CHECKPOINT/v3 (ML-DSA-87 per-batch variant): header ‖ signature.
    A payer fetches it once per batch.  The ledger is sharded by member key
    (`shardOf`).  Normative: there is one seq counter per (tenant, shard,
    epoch), shared by all of the tenant's programs, starting at 0 in each
    epoch.  Within one tenant, shard and epoch no two checkpoints cover a
    common seq whatever their program, and `prevCheckpoint` is the digest of
    the checkpoint ending at `seqFrom - 1` (`forks` checks both, within one
    epoch); the first checkpoint of an epoch has `seqFrom` 0 and an all-zero
    `prevCheckpoint` (the decoder checks it).  Unbuilt requirement of any
    producer (none exists; `sign_batch` keeps no state): serial per (tenant,
    shard), persist before publish, and run `forks` against its own stored
    checkpoints before publishing.  The engine release travels in each leaf,
    since a re-issued leaf keeps the release that decided it. -/

structure Checkpoint where
  tenantId : Bytes
  programId : Bytes
  shardId : Nat
  seqFrom : Nat
  seqTo : Nat
  epoch : Nat
  prevCheckpoint : Bytes
  eventHead : Bytes
  tokenRoot : Bytes
  evidenceRoot : Bytes
  stateDigest : Bytes
  count : Nat
  createdAt : Nat
  counter : Nat

/-- The fields after the magic and `sig_alg`: `prevCheckpoint` is the hash of the previous header; the state
    digest (`stateDigest`) is never zero; `counter` is the shard's TPM counter value this checkpoint takes
    (`follows` steps it by one). -/
def pCheckpointFields : P Checkpoint := do
  let tenantId ← ident
  let programId ← ident
  let shardId ← nat 4
  let seqFrom ← nat 8
  let seqTo ← nat 8
  let epoch ← nat 8
  let prevCheckpoint ← digest
  let eventHead ← digest
  let tokenRoot ← digest
  let evidenceRoot ← digest
  let stateDigest ← digest
  let count ← nat 2 1 maxBatch
  let createdAt ← nat 8
  let counter ← nat 8
  need (stateDigest != zeroDigest)
  need (seqTo + 1 == seqFrom + count)
  need ((seqFrom == 0) == (prevCheckpoint == zeroDigest))
  pure { tenantId, programId, shardId, seqFrom, seqTo, epoch, prevCheckpoint, eventHead, tokenRoot,
         evidenceRoot, stateDigest, count, createdAt, counter }

/-- CHECKPOINT/v3, the only checkpoint format (v1 and v2 were never deployed and are not read). -/
def pCheckpoint : P Checkpoint := do
  expect ("RR/GATE/CHECKPOINT/v3".toUTF8.toList ++ [0])
  let _ ← nat 1 1 1
  pCheckpointFields

/-- The verifier's cosignature of a checkpoint. -/
structure VCosign where
  /-- SHA3-512 of the verifier executable as launched: audit evidence of which build cosigned.  Payers do not
      judge it; the signature binds it. -/
  vrel : Bytes
  sig : Bytes
  deriving DecidableEq

/-- What the verifier signs: the checkpoint digest `d` (the SHA3-512 of the header) and its own release. -/
def vcosignMsg (d vrel : Bytes) : Bytes := domain "VCOSIGN" ++ d ++ vrel

/-- The cosign record: `VCOSIGN ‖ vrel 64 ‖ u16 4627 ‖ ML-DSA-87 signature`, 4,712 bytes. -/
def pCosign : P VCosign := do
  expect (domain "VCOSIGN")
  let vrel ← digest
  let sig ← blob mlDsa87Signature mlDsa87Signature
  pure { vrel, sig }

/-- Nothing when no byte is left; otherwise what `p` reads. -/
def orEnd {α : Type} (p : P α) : P (Option α) := fun b =>
  if b.isEmpty then some (none, b) else (p b).map fun r => (some r.1, r.2)

structure SignedCheckpoint where
  checkpoint : Checkpoint
  header : Bytes
  signature : Bytes
  /-- The verifier's cosignature.  A checkpoint without one is read only as fork evidence: it is never stored. -/
  cosign : Option VCosign

/-- The header, its signature, then nothing or exactly one cosign record. -/
def pSignedCheckpoint : P SignedCheckpoint := do
  let (checkpoint, header) ← consumed pCheckpoint
  let signature ← blob mlDsa87Signature mlDsa87Signature
  let cosign ← orEnd pCosign
  pure { checkpoint, header, signature, cosign }

def decodeCheckpoint : Bytes → Option SignedCheckpoint := parse pSignedCheckpoint maxCheckpointBytes

/-! ## #3 TOKEN/v3: leaf ‖ path ‖ checkpoint_digest.  The decision id is
    recomputed from the leaf and the checkpoint was verified under the installed certificate for its tenant and
    epoch, so none of them travels in the token. -/

structure Leaf where
  tenantId : Bytes
  programId : Bytes
  shardId : Nat
  flow : WireFlow
  revision : Nat
  paymentId : Bytes
  memberKey : Bytes
  payeeRef : Bytes
  amountCents : Nat
  period : Bytes
  linesRoot : Bytes
  outcome : WireOutcome
  reasonCodes : List Bytes
  authority : Authority
  grantId : Bytes
  bypass : Bytes
  /-- `earlierRoot` of the earlier payments an `ANSWERED` payment repeats; zero for any other outcome. -/
  earlierRoot : Bytes := zeroDigest
  ruleVersion : Bytes
  engineRelease : Bytes
  inputCommitment : Bytes
  decidedAt : Nat
  epoch : Nat
  seq : Nat
  issuedAt : Nat
  expiresAt : Nat
  deriving DecidableEq

def pLeaf : P Leaf := do
  expect ("RR/GATE/TOKEN/v3".toUTF8.toList ++ [0])
  let tenantId ← ident
  let programId ← ident
  let shardId ← nat 4
  let flow ← tag flows
  let revision ← nat 8
  let paymentId ← ident
  let memberKey ← take memberKeyBytes
  let payeeRef ← ident
  let amountCents ← nat 8
  let period ← ident
  let linesRoot ← digest
  let outcome ← tag outcomes
  let reasonCodes ← many code (← nat 1 0 maxReasonCodes)
  let authority ← tag authorities
  let grantId ← digest
  let bypass ← digest
  let earlierRoot ← digest
  let ruleVersion ← digest
  let engineRelease ← digest
  let inputCommitment ← digest
  let decidedAt ← nat 8
  let epoch ← nat 8
  let seq ← nat 8
  let issuedAt ← nat 8
  let expiresAt ← nat 8
  need (if flow.ruled then linesRoot != zeroDigest else outcome == .HUMAN_REVIEW)
  need (ascending reasonCodes)
  need (bypass == zeroDigest || (outcome == .ALLOW && flow.ruled))
  need ((earlierRoot == zeroDigest) == (outcome != .ANSWERED))
  need (decidedAt ≤ issuedAt && issuedAt ≤ expiresAt && expiresAt ≤ issuedAt + maxTokenLifetime)
  pure { tenantId, programId, shardId, flow, revision, paymentId, memberKey, payeeRef, amountCents, period,
         linesRoot, outcome, reasonCodes, authority, grantId, bypass, earlierRoot, ruleVersion, engineRelease,
         inputCommitment, decidedAt, epoch, seq, issuedAt, expiresAt }

structure Token where
  leaf : Leaf
  leafBytes : Bytes
  siblings : List Bytes
  checkpointDigest : Bytes

def pToken : P Token := do
  let (leaf, leafBytes) ← consumed pLeaf
  let siblings ← many digest (← nat 1 0 maxTokenPath)
  let checkpointDigest ← digest
  pure { leaf, leafBytes, siblings, checkpointDigest }

def decodeToken : Bytes → Option Token := parse pToken maxTokenBytes

/-- Re-issue (the model's `EmitToken`).  When the stored token of an
    unreleased decision is fenced by a newer epoch or has expired, the gate
    answers `DUPLICATE` or `PAYMENT_ALREADY_DECIDED` with the same decision
    signed again: every leaf field (engine release and decision time
    included) equal except a
    later (epoch, seq), compared in that order since the seq counter restarts
    at each epoch, and a new lifetime.  Only the payment's `latest` revision
    in the gate's store is re-issued.  It never decides again; `redecides` does. -/
def reissues (latest : Nat) (old new : Leaf) : Bool :=
  old.revision == latest &&
    decide ({ new with epoch := old.epoch, seq := old.seq, issuedAt := old.issuedAt,
                       expiresAt := old.expiresAt } = old) &&
    (old.epoch < new.epoch || old.epoch == new.epoch && old.seq < new.seq)

/-- Re-decision (M-A): the payment's `latest` revision is an ALLOW past its
    age by both clock skews, so every payer refuses it (check 5); the gate
    decides the same payment again, on current data, as revision `latest + 1`.
    The rules read the lines it released as its own (`Rules.own`): they neither
    hold it nor are released again.  A payer that released it refuses the new
    token (check 10: the release key has no revision). -/
def redecides (latest : Nat) (old new : Leaf) : Bool :=
  old.revision == latest && new.revision == latest + 1 && old.outcome == .ALLOW &&
    old.decidedAt + maxDecisionAge old.flow + 2 * clockSkew ≤ new.decidedAt &&
    old.tenantId == new.tenantId && old.programId == new.programId && old.shardId == new.shardId &&
    old.flow == new.flow && old.paymentId == new.paymentId && old.memberKey == new.memberKey &&
    old.payeeRef == new.payeeRef && old.amountCents == new.amountCents && old.period == new.period &&
    old.linesRoot == new.linesRoot

/-! ## #2 DECIDE-RESPONSE/v2: outcome and reasons travel only inside the token -/

/-- One entry of `RR/GATE/EARLIER/v1`: a line of the answered payment that exactly repeats a paid line, as its line id,
    the earlier program and payment id, and the earlier line id. -/
abbrev Earlier := Bytes × Bytes × Bytes × Bytes

def pEarlier : P Earlier := do
  let lineId ← ident
  let program ← ident
  let payment ← ident
  let earlierLine ← ident
  pure (lineId, program, payment, earlierLine)

/-- `earlier_root`: the digest of the list's bytes, its count and its entries. -/
def earlierRoot (H : Bytes → Bytes) (body : Bytes) : Bytes := H (domain "EARLIER" ++ body)

structure Response where
  tenantId : Bytes
  programId : Bytes
  commandKey : Bytes
  status : Status
  token : Option Bytes
  rejectCode : Option RejectCode
  retryAfterMs : Option Nat
  /-- The earlier payments of an `ANSWERED` token, ascending by line id; empty for any other. -/
  earlier : List Earlier := []

/-- The requester's decoder: the response answers its own request, and a
    carried token is for the requested payment, member, payee, amount, period
    and lines; after it, the earlier list, which must be the token's `earlierRoot` and name at most one entry a line.
    `PAYMENT_ALREADY_DECIDED` carries the existing decision, whose
    flow may differ from the request's; a ruled flow's lines carry their flow,
    so across flows they never match and the response fails closed. -/
def pResponse (H : Bytes → Bytes) (r : Request) : P Response := do
  expect ("RR/GATE/DECIDE-RESPONSE/v2".toUTF8.toList ++ [0])
  let tenantId ← ident
  let programId ← ident
  let commandKey ← ident
  need (tenantId == r.tenantId)
  need (programId == r.programId)
  need (commandKey == r.commandKey)
  let status ← tag statuses
  let base : Response := { tenantId, programId, commandKey, status, token := none,
                           rejectCode := none, retryAfterMs := none }
  match status with
  | .DECIDED | .DUPLICATE | .PAYMENT_ALREADY_DECIDED =>
    let bytes ← take (← nat 4 0 maxTokenBytes)
    match decodeToken bytes with
    | none => fail
    | some t =>
      need (t.leaf.tenantId == r.tenantId)
      need (t.leaf.programId == r.programId)
      need (t.leaf.paymentId == r.paymentId)
      need (t.leaf.memberKey == r.memberKey)
      need (t.leaf.payeeRef == r.payeeRef)
      need (t.leaf.amountCents == r.amountCents)
      need (t.leaf.period == r.period)
      need (t.leaf.linesRoot == linesRoot H r.lines)
      need (status == .PAYMENT_ALREADY_DECIDED || t.leaf.flow == r.flow)
      let n ← nat 2 0 r.lines.length
      let (earlier, body) ← consumed (many pEarlier n)
      need ((n == 0) == (t.leaf.earlierRoot == zeroDigest))
      need (n == 0 || t.leaf.earlierRoot == earlierRoot H (natBE 2 n ++ body))
      need (ascending (earlier.map (·.1)))
      pure { base with token := some bytes, earlier }
  | .REJECTED => pure { base with rejectCode := some (← tag rejectCodes) }
  | .UNAVAILABLE => pure { base with retryAfterMs := some (← nat 4 1 maxRetryAfterMs) }

def decodeResponse (H : Bytes → Bytes) (r : Request) : Bytes → Option Response :=
  parse (pResponse H r) (maxTokenBytes + 1024 + 520 * r.lines.length)
end BlindLedger.Gate
