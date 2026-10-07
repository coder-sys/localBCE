import BlindLedger.Gate.Verify
import BlindLedger.Gate.Payer
import BlindLedger.Gate.Producer

/-! payer-batch-release-v1 (design 2026-10-01, `rrb/designs/payer-batch-release-goals.lean`; definitions are its
    final text).  Not imported by `VerifyCli` until step B4, so the pinned exe's sources stay untouched.
      §A  RELEASE-BATCH: install certificates and verify each checkpoint once, then decide every item
      §B  one-tree PUBLISH (`publishOkTree`), checked against `publishOk`
    Theorems: `BatchTheorems`. -/

namespace BlindLedger.Gate

/-! ## §A  RELEASE-BATCH -/

/-- The payment a DECIDE-REQUEST asks about (moved out of `VerifyCli.release`, which built it inline). -/
def Request.payment (r : Request) : Payment :=
  { tenantId := r.tenantId, programId := r.programId, flow := r.flow, paymentId := r.paymentId,
    memberKey := r.memberKey, payeeRef := r.payeeRef, amountCents := r.amountCents, period := r.period,
    lines := r.lines }

/-- One payment of a payer run: the payer's own request, the token it holds for it, and the two rows the
    adapter reads inside the run's transaction (released already; the pinned member key). -/
structure Item where
  payment : Payment
  token : Bytes
  released : Bool
  pin : Option Bytes

/-- What a RELEASE-BATCH frame carries once for all its items.  Bytes only, except fork evidence, which the
    frame parser decodes (an undecodable one is a FRAME error: dropping it could only unblock). -/
structure ReleaseRun where
  certs : List Bytes
  evidence : List Stored
  checkpoints : List Bytes
  now : Nat
  grants : List Grant

/-- The installed certificates: `installCert` on each that decodes, in order, then only those that pass
    `certChainOk` kept.  Fence and equivocations are `installCert`'s, so a root-signed certificate whose key is
    not usable (a root key certified as an epoch key) still raises its tenant's fence, still blocks the epoch
    it conflicts with, and still keeps a later certificate of its epoch out, but is never installed.  Replaces
    `VerifyCli.certState`, which refused the whole frame on one undecodable certificate; such a certificate can
    never pass `certChainOk`, so skipping it is exactly an `installCert` that refuses. -/
def certsInstalled (c : Crypto) (certs : List Bytes) : PayerState :=
  let s := (certs.filterMap decodeKeyCert).foldl (fun s e => (installCert c s e).1) emptyState
  { s with certs := s.certs.filter c.certChainOk }

/-- The signature step for one checkpoint: ML-DSA-87 under an installed certificate of its tenant and epoch
    (`storeCheckpoint`'s check 2), against no stored checkpoint.  Fork detection is STORE's job, done when
    the payer stored it; RELEASE reads the recorded forks from `evidence`. -/
def verified (c : Crypto) (s0 : PayerState) (b : Bytes) : Option Stored :=
  (storeCheckpoint c { s0 with checkpoints := [], forked := [], equivocations := [] } b).bind
    (·.checkpoints.head?)

/-- The state one item is decided on: certificates, fence and equivocations from the frame's certificates,
    the given verified checkpoints, the frame's fork evidence, clock and grants, and the item's own rows. -/
def itemState (s0 : PayerState) (cps : List Stored) (r : ReleaseRun) (it : Item) : PayerState :=
  { s0 with checkpoints := cps, forked := r.evidence.map (fun f => (f, f)), now := r.now, grants := r.grants,
            released := if it.released then [it.payment.key] else [],
            pins := it.pin.toList.map fun m => (it.payment.key, m) }

/-- The single-token RELEASE (mode 0x04 today) as a function: install the certificates, verify the one
    checkpoint, decide the one item.  Kept only as the specification `releaseBatch` is proved against. -/
def releaseOne (c : Crypto) (r : ReleaseRun) (cp : Bytes) (it : Item) : Option Failure :=
  let s0 := certsInstalled c r.certs
  firstFailure c (itemState s0 (verified c s0 cp).toList r it) it.payment it.token

/-- Every checkpoint of the frame that verifies, each verified once. -/
def verifiedAll (c : Crypto) (r : ReleaseRun) : List Stored :=
  r.checkpoints.filterMap (verified c (certsInstalled c r.certs))

/-- RELEASE-BATCH: one answer per item, in item order; `none` is ACCEPT, `some f` is HOLD f. -/
def releaseBatch (c : Crypto) (r : ReleaseRun) (items : List Item) : List (Option Failure) :=
  let s0 := certsInstalled c r.certs
  let cps := verifiedAll c r
  items.map fun it => firstFailure c (itemState s0 cps r it) it.payment it.token

/-- The digests (hash of the signed header) of the frame's checkpoints. -/
def cpDigests (c : Crypto) (cps : List Bytes) : List Bytes :=
  cps.filterMap fun b => (decodeCheckpoint b).map fun x => c.hash x.header

/-- The frame checkpoint an item's token names, or the empty bytes (which never verify). -/
def cpFor (c : Crypto) (cps : List Bytes) (it : Item) : Bytes :=
  ((decodeToken it.token).bind fun t =>
    cps.find? fun b => (decodeCheckpoint b).any fun x => c.hash x.header == t.checkpointDigest).getD []

/-- The frame's canonical order, checked by the parser (else FRAME): every checkpoint decodes and their
    digests strictly ascend, so each is present once; 1..1,000 items whose payment ids strictly ascend (the
    parser also requires every request's tenant and program to equal the frame's), so each payment is
    present once.  Canonical order also makes the frame digest a function of the run's content. -/
def frameOrdered (c : Crypto) (cps : List Bytes) (items : List Item) : Bool :=
  (cps.all fun b => (decodeCheckpoint b).isSome) && ascending (cpDigests c cps) &&
    0 < items.length && items.length ≤ maxBatch && ascending (items.map (·.payment.paymentId))

/-! ## §B  One-tree PUBLISH -/

/-- The levels of a Merkle tree, leaf hashes first, each the `pairUp` of the one below, ending at the root
    level (or at the level where fuel ran out, which `publishOkTree` refuses: it is not a singleton). -/
def levels (H : Bytes → Bytes) (d : Bytes) : Nat → List Bytes → List (List Bytes)
  | _, [x] => [[x]]
  | 0, xs => [xs]
  | fuel + 1, xs => xs :: levels H d fuel (pairUp H d xs)

/-- The siblings the token at `index` must carry, read off the levels: none where it is a carried odd last
    node (`pathRoot`'s rule), else its pair's node. -/
def pathOf : List (List Bytes) → Nat → List Bytes
  | [], _ => []
  | lvl :: rest, i =>
    if lvl.length ≤ 1 then []
    else if i % 2 == 0 && i + 1 == lvl.length then pathOf rest (i / 2)
    else lvl.getD (if i % 2 == 0 then i + 1 else i - 1) [] :: pathOf rest (i / 2)

/-- `tokenFits` on a decoded token, with the Merkle path compared to the batch's one tree instead of
    re-hashed. -/
def tokenFitsTree (c : Crypto) (k : Nat) (x : Stored) (lv : List (List Bytes)) (i : Nat) (t : Token) : Bool :=
  let cp := x.checkpoint
  t.checkpointDigest == x.digest && t.leaf.seq == cp.seqFrom + i &&
    cp.tenantId == t.leaf.tenantId && cp.programId == t.leaf.programId && cp.shardId == t.leaf.shardId &&
    cp.epoch == t.leaf.epoch && t.siblings == pathOf lv i &&
    t.leaf.shardId == shardOf c.hash t.leaf.tenantId t.leaf.memberKey k

/-- `publishOk` with each token decoded once and the tree built once: about 2k hashes per 1,000 tokens
    instead of about 11k.  The exe runs this; `publishOk` stays the specification. -/
def publishOkTree (rootPk cert : Bytes) (last : Option Bytes) (new : Bytes) (tokens : List Bytes) : Bool :=
  match decodeKeyCert cert, storedOf sha3 new, tokens.mapM decodeToken with
  | some e, some n, some ts =>
    let d := domain "MERKLE-NODE"
    let lv := levels sha3 d treeFuel (ts.map fun t => leafHash sha3 d t.leafBytes)
    accepts rootPk cert new && last.all (fun b => (storedOf sha3 b).isSome) &&
      follows (last.bind (storedOf sha3)) n && ts.length == n.checkpoint.count &&
      lv.getLast? == some [n.checkpoint.tokenRoot] &&
      (ts.zipIdx.all fun (t, i) =>
        tokenFitsTree (realCrypto [(n.checkpoint.tenantId, rootPk)]) e.shardCount n lv i t) &&
      ascending (ts.map (·.leaf.paymentId))
  | _, _, _ => false

/-- The hash inputs of `pathRoot`'s fold, in order: one `stepInput` per sibling consumed. -/
def pathInputs (H : Bytes → Bytes) (d : Bytes) : Nat → Nat → Nat → Bytes → List Bytes → List Bytes
  | 0, _, _, _, _ => []
  | fuel + 1, index, count, node, path =>
    if count ≤ 1 then []
    else if index % 2 == 0 && index + 1 == count then
      pathInputs H d fuel (index / 2) ((count + 1) / 2) node path
    else match path with
      | [] => []
      | s :: rest => stepInput d index node s ::
          pathInputs H d fuel (index / 2) ((count + 1) / 2) (H (stepInput d index node s)) rest

/-- The hash inputs of the decoded tokens' path folds, each token at its position in the batch. -/
def batchInputs (ts : List Token) : List Bytes :=
  let d := domain "MERKLE-NODE"
  ts.zipIdx.flatMap fun p => pathInputs sha3 d treeFuel p.2 ts.length (leafHash sha3 d p.1.leafBytes) p.1.siblings

/-- The SHA3 collision behind a batch `publishOk` accepts and `publishOkTree` refuses
    (`publishOkTree_complete`): the first pair of distinct `batchInputs` with one output.  Only `tokens`
    matter.  Quadratic: a witness for the theorem, which the exe never runs. -/
def publishCollision (tokens : List Bytes) : Option (Bytes × Bytes) :=
  let xs := batchInputs (tokens.filterMap decodeToken)
  (xs.flatMap fun x => xs.map (x, ·)).find? fun p => p.1 != p.2 && sha3 p.1 == sha3 p.2

end BlindLedger.Gate
