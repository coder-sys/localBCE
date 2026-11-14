import BlindLedger.Gate.Batch

/-! Key authority without a lifetime limit (design key-authority-witnesses, 2026-10-31).  A STORE or RELEASE
    decision reads, for its tenant `T` and the epochs `Q` and shards `S` it decides, only a few self-authenticating
    objects: the payer store keeps every certificate with the role INSTALL gave it, and every fork, and sends Lean
    only `select` and `selectForks` of them (`right_rail_gate_payer.py` mirrors both clause for clause).  The
    decision on the witnesses equals the decision on the whole history (`WitnessTheorems`). -/

namespace BlindLedger.Gate

/-- What a new certificate does to the payer's state (`installCert`), named: INSTALL's answer. -/
inductive Role | INSTALLED | SAME | EQUIVOCATES | FENCE_ONLY | REFUSED
  deriving DecidableEq, Repr

/-- `INSTALLED`: it fits and is installed.  `SAME`: a re-signature of the installed body of its tenant and
    epoch (no effect).  `EQUIVOCATES`: another key or shard count than that installed body (blocks the epoch).
    `FENCE_ONLY`: root-signed, no installed body for its epoch, another shard count than its tenant's (raises
    the fence only).  `REFUSED`: not root-signed. -/
def classify (c : Crypto) (s : PayerState) (e : EpochCert) : Role :=
  if !c.rootSigned e then .REFUSED
  else if fits s e then .INSTALLED
  else match s.certs.find? (fun x => x.tenantId == e.tenantId && x.epoch == e.epoch) with
    | some x => if x.publicKey == e.publicKey && x.shardCount == e.shardCount then .SAME else .EQUIVOCATES
    | none => .FENCE_ONLY

/-- The signed body of a certificate (`realCrypto.rootSigned` verifies the root signature over it). -/
def certBody (e : EpochCert) : Bytes := e.signed.take (e.signed.length - 2 - mlDsa87Signature)

/-- The state `installCert` builds from certificates in install order (`gate_verify` on a frame's list). -/
def replay (c : Crypto) (h : List EpochCert) : PayerState :=
  h.foldl (fun s e => (installCert c s e).1) emptyState

/-- A role the payer store keeps a row for; `SAME` and `REFUSED` change nothing and write none. -/
def Role.kept : Role → Bool
  | .INSTALLED | .EQUIVOCATES | .FENCE_ONLY => true
  | .SAME | .REFUSED => false

/-- The certificate rows of a store that installed `h` in order from `s`: each certificate with its role. -/
def rowsFrom (c : Crypto) : PayerState → List EpochCert → List (EpochCert × Role)
  | _, [] => []
  | s, e :: h =>
    (if (classify c s e).kept then [(e, classify c s e)] else []) ++ rowsFrom c (installCert c s e).1 h

def table (c : Crypto) (h : List EpochCert) : List (EpochCert × Role) := rowsFrom c emptyState h

/-- The elements of `l` at the positions `ids`, in `l`'s order (SQL `WHERE id IN (...) ORDER BY id`). -/
def pick {α : Type} (l : List α) (ids : List Nat) : List α :=
  (l.zipIdx.filter fun p => ids.contains p.2).map (·.1)

/-- The highest epoch of the tenant's rows. -/
def topEpoch (rows : List (EpochCert × Role)) (T : Bytes) : Option Nat :=
  ((rows.filter (·.1.tenantId == T)).map (·.1.epoch)).max?

/-- The certificate witnesses for tenant `T` and epochs `Q`, one clause per SQL subquery: the tenant's first
    `INSTALLED` row (which fixes its shard count); the first of its rows at its highest epoch (its fence); and
    for each epoch the first `INSTALLED` row (its key) and the first `EQUIVOCATES` row. -/
def selectIds (rows : List (EpochCert × Role)) (T : Bytes) (Q : List Nat) : List Nat :=
  (rows.findIdx? fun r => r.1.tenantId == T && r.2 == .INSTALLED).toList ++
    ((topEpoch rows T).bind fun m => rows.findIdx? fun r => r.1.tenantId == T && r.1.epoch == m).toList ++
    Q.flatMap fun E =>
      (rows.findIdx? fun r => r.1.tenantId == T && r.2 == .INSTALLED && r.1.epoch == E).toList ++
        (rows.findIdx? fun r => r.1.tenantId == T && r.2 == .EQUIVOCATES && r.1.epoch == E).toList

def select (rows : List (EpochCert × Role)) (T : Bytes) (Q : List Nat) : List EpochCert :=
  (pick rows (selectIds rows T Q)).map (·.1)

/-- The fork witnesses for tenant `T`, shards `S` and epochs `Q`: per shard the tenant's first fork on it; per
    epoch its first fork whose stored side is in it and its first whose forking side is. -/
def selectForkIds (forks : List (Stored × Stored)) (T : Bytes) (S Q : List Nat) : List Nat :=
  S.flatMap (fun s => (forks.findIdx? fun f => f.1.checkpoint.tenantId == T && f.1.checkpoint.shardId == s).toList) ++
    Q.flatMap fun E =>
      (forks.findIdx? fun f => f.1.checkpoint.tenantId == T && f.1.checkpoint.epoch == E).toList ++
        (forks.findIdx? fun f => f.1.checkpoint.tenantId == T && f.2.checkpoint.epoch == E).toList

def selectForks (forks : List (Stored × Stored)) (T : Bytes) (S Q : List Nat) : List (Stored × Stored) :=
  pick forks (selectForkIds forks T S Q)

/-- STORE's outcome on installed certificates `s0`, candidates `old`, recorded forks and the new checkpoint:
    `none` refused, `some none` stored, `some (some d)` forks the stored checkpoint of digest `d`. -/
def storeOutcome (c : Crypto) (s0 : PayerState) (old : List Stored) (forks : List (Stored × Stored)) (new : Bytes) :
    Option (Option Bytes) :=
  (storeCheckpoint c { s0 with checkpoints := old, forked := forks } new).map fun s' =>
    match s'.forked with  -- a new fork is put in front of the recorded ones
    | f :: rest => if rest.length == forks.length then some f.1.digest else none
    | [] => none

/-- RELEASE's outcome (`firstFailure`): the one checkpoint verified under `s0`'s certificates against no stored
    one, then the item decided on the frame's forks, clock, grants and the item's own rows. -/
def releaseOutcome (c : Crypto) (s0 : PayerState) (forks : List (Stored × Stored)) (cp : Bytes) (now : Nat)
    (grants : List Grant) (released : Bool) (pin : Option Bytes) (p : Payment) (token : Bytes) : Option Failure :=
  let s1 := (storeCheckpoint c { s0 with equivocations := [], forked := [] } cp).getD s0
  firstFailure c { s1 with equivocations := s0.equivocations, forked := forks, now, grants,
                           released := if released then [p.key] else [],
                           pins := pin.toList.map (p.key, ·) } p token

end BlindLedger.Gate
