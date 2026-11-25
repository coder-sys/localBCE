import BlindLedger.Gate.Cosign.Install

/-! The payer: authority links and certificates once (`Cosign.installLink`, `Cosign.installCert`, on the authority
    part of its state), checkpoints once, then one release decision per payment (`verifyToken`, one predicate over
    twelve checks), and the payer adapter's reads (gate-producer-v1 §2): the rows of state one token's decision
    needs, and the reason a release is held.  Hashing and signature verification enter only through `Crypto`
    (instantiated by `realCrypto`), so every statement holds for any instantiation.  Theorems: `Theorems`,
    `ProducerTheorems`. -/
namespace BlindLedger.Gate

/-- The epoch's shard count: the last count of the certificate's chain (a decoded certificate has at least one). -/
def Cosign.KeyCert.shardCount (e : Cosign.KeyCert) : Nat := e.chain.getLastD 0

/-- Why the payer refuses to send a command.  `member_key_changed`: the
    payment's member key differs from the one pinned by its first send;
    only a state official's determination (a later format, not built) could
    change it. -/
inductive Refusal | member_key_changed deriving DecidableEq, Repr

/-- The verifier's cosignature of the checkpoint of digest `d` verifies under the epoch certificate's verifier
    key. -/
def cosignOk (c : Crypto) (e : Cosign.KeyCert) (d : Bytes) (v : VCosign) : Bool :=
  c.verify e.verifierKey (vcosignMsg d v.vrel) v.sig

/-- A payer's approval of rule versions and engine releases, for one tenant: tenant and id are its identity. -/
structure Grant where
  tenantId : Bytes
  grantId : Bytes
  ruleVersions : List Bytes
  engineReleases : List Bytes

/-- A stored checkpoint: its signature verified, filed under the hash of its
    header, with the signed bytes kept as evidence. -/
structure Stored where
  digest : Bytes
  checkpoint : Checkpoint
  bytes : Bytes

/-- What a release is recorded against: tenant, program and payment id.  Flow
    is not part of it, so a payment is released at most once across flows. -/
abbrev PayKey := Bytes × Bytes × Bytes

/-- Payer-side state.  The authority part (`Cosign.Auth`): per tenant the authority chain, the chains a genesis
    replaced and the recorded link conflicts; `certs`, the installed certificates, each verified against its
    tenant's chain; `equivocations`, each verified certificate with another body than the installed one of its
    tenant and epoch, with it; `fence`, per tenant.  `grants` holds only active grants; `forked` each detected
    fork as (stored side, new side), both signed checkpoints as evidence; `pins` is the sent set: each payment
    the payer sent a command for, with the member key its first send pinned. -/
structure PayerState extends Cosign.Auth where
  now : Nat
  checkpoints : List Stored
  grants : List Grant
  released : List PayKey
  forked : List (Stored × Stored)
  pins : List (PayKey × Bytes)

/-- Install an authority link (`Cosign.installLink`): the new state and the answer. -/
def installLink (c : Crypto) (pin : Bytes) (s : PayerState) (n : Cosign.SignedLink) :
    PayerState × Cosign.LinkAnswer :=
  ({ s with toAuth := (Cosign.installLink c pin s.toAuth n).1 }, (Cosign.installLink c pin s.toAuth n).2)

/-- Install an epoch certificate (`Cosign.installCert`): the new state and the answer.  A verified certificate
    raises the tenant's fence to its epoch (the model's `PayerLearnFence`) even when its shard counts do not fit,
    so a refused newer certificate fails closed until a fitting one arrives. -/
def installCert (c : Crypto) (s : PayerState) (bytes : Bytes) : PayerState × Cosign.CertAnswer :=
  ({ s with toAuth := (Cosign.installCert c s.toAuth bytes).1 }, (Cosign.installCert c s.toAuth bytes).2)

/-- The shard count of the tenant's installed certificate for the epoch.  A tenant's count changes only between
    epochs, so a token is routed under the count of its own epoch. -/
def countAt (s : PayerState) (tenant : Bytes) (epoch : Nat) : Option Nat :=
  (s.certs.find? fun e => e.tenantId == tenant && e.epoch == epoch).map (·.shardCount)

/-- `b` starts right after `a` ends but does not name `a` as its previous
    checkpoint, or names `a` without starting right after it. -/
def misLinked (a b : Stored) : Bool :=
  (a.checkpoint.seqTo + 1 == b.checkpoint.seqFrom) != (b.checkpoint.prevCheckpoint == a.digest)

/-- Same tenant and shard. -/
def sameShard (a b : Stored) : Bool :=
  a.checkpoint.tenantId == b.checkpoint.tenantId && a.checkpoint.shardId == b.checkpoint.shardId

/-- `b` takes the counter right after `a`'s but does not name `a` as the shard's previous checkpoint. -/
def unlinked (a b : Stored) : Bool :=
  b.checkpoint.counter == a.checkpoint.counter + 1 && b.checkpoint.eventHead != a.digest

/-- Two different checkpoints of one tenant and shard fork when they share a counter value, or one takes the
    next counter without naming the other (in any epoch), or, within one epoch, they cover a common seq or one
    follows the other without linking to it. -/
def forks (a b : Stored) : Bool :=
  a.digest != b.digest && sameShard a b &&
    (a.checkpoint.counter == b.checkpoint.counter || unlinked a b || unlinked b a ||
      a.checkpoint.epoch == b.checkpoint.epoch &&
        (a.checkpoint.seqFrom ≤ b.checkpoint.seqTo && b.checkpoint.seqFrom ≤ a.checkpoint.seqTo ||
          misLinked a b || misLinked b a))

/-- What the payer's candidate query selects for a new checkpoint `n` among the stored ones (`right_rail_gate_payer.py`
    mirrors it clause for clause): the same shard, and a counter within one of `n`'s, or, in `n`'s epoch, a seq range
    touching or a link either way. Every fork is a candidate (`forks_candidate`). -/
def candidate (n x : Stored) : Bool :=
  sameShard x n &&
    (n.checkpoint.counter ≤ x.checkpoint.counter + 1 && x.checkpoint.counter ≤ n.checkpoint.counter + 1 ||
      x.checkpoint.epoch == n.checkpoint.epoch &&
        (x.checkpoint.seqFrom ≤ n.checkpoint.seqTo + 1 && n.checkpoint.seqFrom ≤ x.checkpoint.seqTo + 1 ||
          x.digest == n.checkpoint.prevCheckpoint || x.checkpoint.prevCheckpoint == n.digest))

/-- A recorded fork pins its tenant and shard in every epoch, and blocks the epochs of both sides on every shard of
    the tenant; an equivocation blocks its tenant and epoch on every shard: the epoch's key or writer cannot be
    trusted on any; a link conflict of the tenant's present chain blocks every epoch from the conflict's generation
    on.  A conflict of a chain that a genesis replaced blocks nothing: it is kept as evidence only. -/
def blocked (s : PayerState) (tenant : Bytes) (shard epoch : Nat) : Bool :=
  s.forked.any (fun f => f.1.checkpoint.tenantId == tenant &&
      (f.1.checkpoint.shardId == shard || f.1.checkpoint.epoch == epoch || f.2.checkpoint.epoch == epoch)) ||
    Cosign.certBlocked s.toAuth tenant epoch || Cosign.linkBlocked s.toAuth tenant epoch

/-- Store a signed checkpoint.  Its signature verifies under the installed certificate of the checkpoint's
    tenant and epoch (check 2).  A verified checkpoint that forks a stored one is not stored;
    the pair is recorded, which pins its shard and blocks its epochs (check 11), whether or not it carries a
    cosignature, so stripping the cosignature hides no fork.  No other checkpoint of a blocked tenant, shard and
    epoch is stored, and none is stored without the verifier's cosignature under that same certificate: every
    stored checkpoint is cosigned, so a release (which needs a stored checkpoint) waits for the cosignature. -/
def storeCheckpoint (c : Crypto) (s : PayerState) (bytes : Bytes) : Option PayerState :=
  match decodeCheckpoint bytes with
  | none => none
  | some x =>
    let new : Stored := ⟨c.hash x.header, x.checkpoint, bytes⟩
    if s.certs.any fun e => e.tenantId == x.checkpoint.tenantId && e.epoch == x.checkpoint.epoch &&
        c.verify e.key x.header x.signature then
      match s.checkpoints.find? (forks new) with
      | some old => some { s with forked := (old, new) :: s.forked }
      | none =>
        if blocked s x.checkpoint.tenantId x.checkpoint.shardId x.checkpoint.epoch then none
        else if s.certs.any fun e => e.tenantId == x.checkpoint.tenantId && e.epoch == x.checkpoint.epoch &&
            c.verify e.key x.header x.signature && x.cosign.any (cosignOk c e new.digest) then
          some { s with checkpoints := new :: s.checkpoints }
        else none
    else none

/-- The payment the payer is about to release, from the payer's own records. -/
structure Payment where
  tenantId : Bytes
  programId : Bytes
  flow : WireFlow
  paymentId : Bytes
  memberKey : Bytes
  payeeRef : Bytes
  amountCents : Nat
  period : Bytes
  lines : List Bytes

def payKey (t : Token) : PayKey := (t.leaf.tenantId, t.leaf.programId, t.leaf.paymentId)

def Payment.key (p : Payment) : PayKey := (p.tenantId, p.programId, p.paymentId)

/-- The payer sends a DECIDE command for a payment (the model's only command
    step): the first send pins its member key, and every later send (a retry,
    a new command key, another flow) must carry the pinned key.  A pin is
    never changed, and a lost or HOLD response opens no gap.  Unbuilt
    requirement of any payer adapter (none exists): the pin is durably
    persisted before the command leaves the payer, every command path uses
    this one pin store, and a refused send sends nothing. -/
def send (s : PayerState) (p : Payment) : Except Refusal PayerState :=
  match s.pins.lookup p.key with
  | none => .ok { s with pins := (p.key, p.memberKey) :: s.pins }
  | some m => if m == p.memberKey then .ok s else .error .member_key_changed

/-- Check 2: the token names a stored checkpoint (verified under its tenant's epoch certificate). -/
def batchOf (s : PayerState) (t : Token) : Option Stored :=
  s.checkpoints.find? (·.digest == t.checkpointDigest)

/-- Check 3: the checkpoint is the token's own batch, on its own shard, and
    the Merkle path hashes the leaf to its `token_root`. -/
def inBatch (c : Crypto) (cp : Checkpoint) (t : Token) : Bool :=
  cp.tenantId == t.leaf.tenantId && cp.programId == t.leaf.programId &&
    cp.shardId == t.leaf.shardId && cp.epoch == t.leaf.epoch && cp.seqFrom ≤ t.leaf.seq &&
    verifyPath c.hash (domain "MERKLE-NODE") t.leafBytes (t.leaf.seq - cp.seqFrom) cp.count
      t.siblings cp.tokenRoot

/-- Check 4: epoch ≥ the tenant's fence. -/
def aboveFence (s : PayerState) (t : Token) : Bool := s.fence t.leaf.tenantId ≤ t.leaf.epoch

/-- Check 5: issued, not expired and decided less than its flow's
    `maxDecisionAge` ago, each allowing `clockSkew` seconds. -/
def unexpired (s : PayerState) (t : Token) : Bool :=
  t.leaf.issuedAt ≤ s.now + clockSkew && s.now < t.leaf.expiresAt + clockSkew &&
    s.now < t.leaf.decidedAt + maxDecisionAge t.leaf.flow + clockSkew

/-- Check 6: the payment matches field for field and its lines hash to `lines_root`. -/
def paymentMatches (c : Crypto) (p : Payment) (t : Token) : Bool :=
  let l := t.leaf
  l.tenantId == p.tenantId && l.programId == p.programId && l.flow == p.flow &&
    l.paymentId == p.paymentId && l.memberKey == p.memberKey && l.payeeRef == p.payeeRef &&
    l.amountCents == p.amountCents && l.period == p.period && linesRoot c.hash p.lines == l.linesRoot

/-- Check 7: the token is from the payment's own shard, the route of the
    payer's member key under its tenant's shard count for the token's epoch, so a decision from any
    other shard is refused.  Within that shard `PAYMENT_ALREADY_DECIDED` is
    authoritative. -/
def routed (c : Crypto) (s : PayerState) (p : Payment) (t : Token) : Bool :=
  (countAt s p.tenantId t.leaf.epoch).any fun n => t.leaf.shardId == shardOf c.hash p.tenantId p.memberKey n

/-- Check 8: the rules ALLOWed it and the grant let the gate move it (authority TRANSFER). -/
def allows (t : Token) : Bool := t.leaf.outcome == .ALLOW && t.leaf.authority == .TRANSFER

/-- Check 9: an active grant of the token's own tenant approves the leaf's rule
    version and the engine release that decided it. -/
def granted (s : PayerState) (t : Token) : Bool :=
  s.grants.any fun g => g.grantId == t.leaf.grantId && g.tenantId == t.leaf.tenantId &&
    g.ruleVersions.contains t.leaf.ruleVersion && g.engineReleases.contains t.leaf.engineRelease

/-- Check 10. -/
def unreleased (s : PayerState) (t : Token) : Bool := !s.released.contains (payKey t)

/-- Check 11: no fork or equivocation was recorded for the token's tenant, shard and epoch. -/
def unforked (s : PayerState) (t : Token) : Bool := !blocked s t.leaf.tenantId t.leaf.shardId t.leaf.epoch

/-- Check 12: a command was sent for the token's payment and the token
    carries the member key its first send pinned (`send`), so a payment never
    sent, or an edited member key, never reaches a release. -/
def keyPinned (s : PayerState) (t : Token) : Bool :=
  s.pins.lookup (t.leaf.tenantId, t.leaf.programId, t.leaf.paymentId) == some t.leaf.memberKey

/-- Release only when all twelve checks hold; check 1 is a canonical `TOKEN/v3` parse. -/
def verifyToken (c : Crypto) (s : PayerState) (p : Payment) (bytes : Bytes) : Bool :=
  match decodeToken bytes with
  | none => false
  | some t =>
    match batchOf s t with
    | none => false
    | some st => inBatch c st.checkpoint t && aboveFence s t && unexpired s t &&
        paymentMatches c p t && routed c s p t && allows t && granted s t && unreleased s t &&
        unforked s t && keyPinned s t

/-- The payer's release on the token bytes `verifyToken` accepts: record the
    payment key.  The fence needs no raise: on a `Coherent` state it already
    equals the token's epoch (`verifyToken_fence_eq_epoch`), which is where
    `PayerRelease` in `docs/formal/gate_failover/gate_failover.tla` puts it.
    Install, store and release are proved to keep `Coherent`, and so is every
    step sequence (`Steps.coherent`). -/
def release (c : Crypto) (s : PayerState) (p : Payment) (bytes : Bytes) : Option PayerState :=
  match decodeToken bytes with
  | none => none
  | some t => if verifyToken c s p bytes then some { s with released := payKey t :: s.released } else none

/-- The rows of payer state one token's decision reads: the adapter loads only these. -/
def slice (s : PayerState) (t : Token) : PayerState :=
  { s with
    certs := s.certs.filter (·.tenantId == t.leaf.tenantId),
    checkpoints := (batchOf s t).toList,
    grants := s.grants.filter (·.grantId == t.leaf.grantId),
    released := s.released.filter (· == payKey t),
    forked := s.forked.filter fun f =>
      f.1.checkpoint.tenantId == t.leaf.tenantId &&
        (f.1.checkpoint.shardId == t.leaf.shardId || f.1.checkpoint.epoch == t.leaf.epoch || f.2.checkpoint.epoch == t.leaf.epoch),
    equivocations := s.equivocations.filter fun q => q.1.tenantId == t.leaf.tenantId && q.1.epoch == t.leaf.epoch,
    conflicts := s.conflicts.filter fun q => q.2.tenantId == t.leaf.tenantId && q.2.gen ≤ Cosign.genOf t.leaf.epoch,
    pins := s.pins.filter (·.1 == payKey t) }

/-- The first of the twelve checks a token fails, in `verifyToken`'s order: the HOLD reason. -/
inductive Failure
  | parse | batch | path | fence | expiry | payment | route | outcome | grant | released | forked | pin
  deriving DecidableEq, Repr

def firstFailure (c : Crypto) (s : PayerState) (p : Payment) (bytes : Bytes) : Option Failure :=
  match decodeToken bytes with
  | none => some .parse
  | some t =>
    match batchOf s t with
    | none => some .batch
    | some st =>
      ([(inBatch c st.checkpoint t, Failure.path), (aboveFence s t, .fence), (unexpired s t, .expiry),
        (paymentMatches c p t, .payment), (routed c s p t, .route), (allows t, .outcome), (granted s t, .grant),
        (unreleased s t, .released), (unforked s t, .forked), (keyPinned s t, .pin)].find? (!·.1)).map (·.2)

end BlindLedger.Gate
