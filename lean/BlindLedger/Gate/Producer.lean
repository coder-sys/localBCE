import BlindLedger.Gate.Verify

/-! The checkpoint producer's chain and its publish check (gate-producer-v1 §1).  `publishOk` is the whole
    decision of `gate_verify` PUBLISH: a signed checkpoint leaves custody only when it extends the producer's
    last published one and its tokens are exactly the batch.  Theorems: `ProducerTheorems`. -/
namespace BlindLedger.Gate

/-- A checkpoint as the payer stores it (`storeCheckpointAny` builds the same triple). -/
def storedOf (H : Bytes → Bytes) (b : Bytes) : Option Stored :=
  (decodeAnyCheckpoint b).map fun x => ⟨H x.header, x.checkpoint, b⟩

/-- `n` is the next checkpoint of the shard after `last` (none: the shard's first ever).  Same tenant and
    shard; `eventHead` is the digest of the shard's previous checkpoint in any epoch (zero only at the shard's
    genesis); within an epoch the seq range is adjacent and `prevCheckpoint` links; a new epoch is higher
    and restarts at seq 0 (the decoder then forces a zero `prevCheckpoint`). -/
def follows : Option Stored → Stored → Bool
  | none, n => n.checkpoint.seqFrom == 0 && n.checkpoint.eventHead == zeroDigest
  | some p, n =>
    let a := p.checkpoint
    let b := n.checkpoint
    a.tenantId == b.tenantId && a.shardId == b.shardId && b.eventHead == p.digest &&
      if a.epoch == b.epoch then a.seqTo + 1 == b.seqFrom && b.prevCheckpoint == p.digest
      else a.epoch < b.epoch && b.seqFrom == 0

/-- The producer's store of one shard, newest first. -/
def chainOk : List Stored → Bool
  | [] => true
  | n :: rest => follows rest.head? n && chainOk rest

/-- What the checkpoint decoder guarantees (`storedOf_wf`); the chain theorems assume it. -/
def Wf (x : Stored) : Prop :=
  x.checkpoint.seqFrom ≤ x.checkpoint.seqTo ∧
    (x.checkpoint.seqFrom = 0 → x.checkpoint.prevCheckpoint = zeroDigest)

/-- Token `i` of batch `x`: it decodes, names `x`, carries seq `seqFrom + i`, passes checks 3 (`inBatch`) and
    routes its own member key to its shard under the tenant's shard count `k`. -/
def tokenFits (c : Crypto) (k : Nat) (x : Stored) (i : Nat) (bytes : Bytes) : Bool :=
  match decodeToken bytes with
  | none => false
  | some t =>
    t.checkpointDigest == x.digest && t.leaf.seq == x.checkpoint.seqFrom + i && inBatch c x.checkpoint t &&
      t.leaf.shardId == shardOf c.hash t.leaf.tenantId t.leaf.memberKey k

/-- The whole decision of `gate_verify publish`: the signed checkpoint verifies under the epoch certificate
    (`accepts`), follows the producer's last published checkpoint, and the batch's tokens are exactly its
    `count` leaves in seq order, each fitting, payment ids strictly ascending (so no payment twice, checked in
    one pass). -/
def publishOk (rootPk cert : Bytes) (last : Option Bytes) (new : Bytes) (tokens : List Bytes) : Bool :=
  match decodeKeyCert cert, storedOf sha3 new with
  | some e, some n =>
    accepts rootPk cert new && last.all (fun b => (storedOf sha3 b).isSome) &&
      follows (last.bind (storedOf sha3)) n && tokens.length == n.checkpoint.count &&
      (tokens.zipIdx.all fun (b, i) => tokenFits (realCrypto [(n.checkpoint.tenantId, rootPk)]) e.shardCount n i b) &&
      ascending ((tokens.filterMap decodeToken).map (·.leaf.paymentId))
  | _, _ => false

end BlindLedger.Gate
