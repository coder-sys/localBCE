import BlindLedger.Gate.Batch

/-! Key authority without a lifetime limit (design key-authority-witnesses, 2026-10-31; links and chain-prefix
    shard counts, root-rotation 2026-11-01).  A STORE or RELEASE decision reads, for its tenant `T` and the epochs
    `Q` and shards `S` it decides, only a few objects: the payer store keeps every link, every certificate with the
    answer INSTALL gave it, and every fork, and sends Lean only `select`, `selectFence`, `selectConflict` and
    `selectForks` of them (`right_rail_gate_payer.py` mirrors each clause for clause).  The decision on the
    witnesses equals the decision on the whole history (`WitnessTheorems`).  A frame re-verifies every carried
    certificate under the link it names (`underLinks`); the links themselves were verified once, when
    `Cosign.installLink` answered, and the store is trusted for them as it is for the released set. -/

namespace BlindLedger.Gate

/-- The certificate rows of a store that admitted `h` in order from `s`: each recorded certificate with
    `Cosign.record`'s answer (`installed`, `equivocates` or `unfit`).  A certificate that is not admitted (not
    verified, or its body already held) writes no row. -/
def rowsFrom (ok : Cosign.KeyCert → Bool) : PayerState → List Cosign.KeyCert → List (Cosign.KeyCert × Cosign.CertAnswer)
  | _, [] => []
  | s, e :: h => ((admit ok s e).2.map (e, ·)).toList ++ rowsFrom ok (admit ok s e).1 h

def table (ok : Cosign.KeyCert → Bool) (h : List Cosign.KeyCert) : List (Cosign.KeyCert × Cosign.CertAnswer) :=
  rowsFrom ok emptyState h

/-- The elements of `l` at the positions `ids`, in `l`'s order (SQL `WHERE id IN (...) ORDER BY id`). -/
def pick {α : Type} (l : List α) (ids : List Nat) : List α :=
  (l.zipIdx.filter fun p => ids.contains p.2).map (·.1)

/-- The highest epoch of the tenant's rows. -/
def topEpoch (rows : List (Cosign.KeyCert × Cosign.CertAnswer)) (T : Bytes) : Option Nat :=
  ((rows.filter (·.1.tenantId == T)).map (·.1.epoch)).max?

/-- The certificate witnesses for tenant `T` and epochs `Q`, one clause per SQL subquery: for each epoch the first
    `installed` row (its key and shard counts) and the first `equivocates` row (which blocks it). -/
def selectIds (rows : List (Cosign.KeyCert × Cosign.CertAnswer)) (T : Bytes) (Q : List Nat) : List Nat :=
  Q.flatMap fun E =>
    (rows.findIdx? fun r => r.1.tenantId == T && r.2 == .installed && r.1.epoch == E).toList ++
      (rows.findIdx? fun r => r.1.tenantId == T && r.2 == .equivocates && r.1.epoch == E).toList

def select (rows : List (Cosign.KeyCert × Cosign.CertAnswer)) (T : Bytes) (Q : List Nat) : List Cosign.KeyCert :=
  (pick rows (selectIds rows T Q)).map (·.1)

/-- The fence certificate: the first of the tenant's rows at its highest epoch, unless the witnesses already
    carry it.  A frame verifies it and raises the fence to its epoch, and never admits it: among other witnesses
    than those it was recorded after, a certificate recorded `unfit` could be answered `installed`. -/
def selectFence (rows : List (Cosign.KeyCert × Cosign.CertAnswer)) (T : Bytes) (Q : List Nat) : Option Cosign.KeyCert :=
  ((topEpoch rows T).bind fun m => rows.find? fun r => r.1.tenantId == T && r.1.epoch == m).bind fun r =>
    if Q.contains r.1.epoch && (r.2 == .installed || r.2 == .equivocates) then none else some r.1

/-- The fence a frame's fence certificate gives: its epoch when it passes the frame's check. -/
def fenceOf (ok : Cosign.KeyCert → Bool) (f : Option Cosign.KeyCert) : Nat := ((f.filter ok).map (·.epoch)).getD 0

/-- The conflict of the lower generation; of two of one generation, the later in the list (recorded earlier). -/
def lowerGen (best : Option (Nat × Cosign.Link)) (q : Nat × Cosign.Link) : Option (Nat × Cosign.Link) :=
  match best with
  | some b => if q.2.gen ≤ b.2.gen then some q else some b
  | none => some q

/-- The link conflict a frame carries for tenant `T`: of the recorded conflicts of the tenant's present chain,
    the one of the lowest generation (the first recorded of that generation).  It blocks every epoch any of them
    blocks (`selectConflict_blocks`). -/
def selectConflict (s : Cosign.Auth) (T : Bytes) : Option (Nat × Cosign.Link) :=
  (s.chainOf T).bind fun ch =>
    (s.conflicts.filter fun q => q.2.tenantId == T && q.1 == ch.base).foldl lowerGen none

/-- A frame's link part: the tenant's head link as a chain of its own; the carried link conflict, when it is the
    tenant's and of the head's chain; the tenant's fence at the head's generation and at `fence`, the fence
    certificate's. -/
def linkView (H : Bytes → Bytes) (head : Cosign.SignedLink) (conflict : Option Cosign.SignedLink) (fence : Nat) :
    Cosign.Auth :=
  { Cosign.Auth.empty with
    chainOf := fun t => if t = head.tenantId then Cosign.Chain.start (head.link H) else none,
    conflicts := (conflict.filter fun n => n.tenantId == head.tenantId && n.base == head.base).toList.map
      fun n => (head.gen, n.link H),
    fence := raiseFence (fun _ => 0) head.tenantId (max (head.gen * Cosign.genSpan) fence) }

/-- The fork witnesses for tenant `T`, shards `S` and epochs `Q`: per shard the tenant's first fork on it; per
    epoch its first fork whose stored side is in it and its first whose forking side is. -/
def selectForkIds (forks : List (Stored × Stored)) (T : Bytes) (S Q : List Nat) : List Nat :=
  S.flatMap (fun s => (forks.findIdx? fun f => f.1.checkpoint.tenantId == T && f.1.checkpoint.shardId == s).toList) ++
    Q.flatMap fun E =>
      (forks.findIdx? fun f => f.1.checkpoint.tenantId == T && f.1.checkpoint.epoch == E).toList ++
        (forks.findIdx? fun f => f.1.checkpoint.tenantId == T && f.2.checkpoint.epoch == E).toList

def selectForks (forks : List (Stored × Stored)) (T : Bytes) (S Q : List Nat) : List (Stored × Stored) :=
  pick forks (selectForkIds forks T S Q)

/-- STORE's outcome on the frame's state `s0`, candidates `old`, recorded forks and the new checkpoint:
    `none` refused, `some none` stored, `some (some d)` forks the stored checkpoint of digest `d`. -/
def storeOutcome (c : Crypto) (s0 : PayerState) (old : List Stored) (forks : List (Stored × Stored)) (new : Bytes) :
    Option (Option Bytes) :=
  (storeCheckpoint c { s0 with checkpoints := old, forked := forks } new).map fun s' =>
    match s'.forked with  -- a new fork is put in front of the recorded ones
    | f :: rest => if rest.length == forks.length then some f.1.digest else none
    | [] => none

/-- RELEASE's outcome (`firstFailure`): the one checkpoint verified under `s0`'s certificates against no stored
    one and no recorded block, then the item decided on the frame's blocks, forks, clock, grants and the item's own
    rows. -/
def releaseOutcome (c : Crypto) (s0 : PayerState) (forks : List (Stored × Stored)) (cp : Bytes) (now : Nat)
    (grants : List Grant) (released : Bool) (pin : Option Bytes) (p : Payment) (token : Bytes) : Option Failure :=
  let s1 := (storeCheckpoint c { s0 with equivocations := [], conflicts := [], forked := [] } cp).getD s0
  firstFailure c { s1 with equivocations := s0.equivocations, conflicts := s0.conflicts, forked := forks, now, grants,
                           released := if released then [p.key] else [],
                           pins := pin.toList.map (p.key, ·) } p token

/-! ### INSTALL: a new certificate -/

/-- The tenant's `installed` row of the highest epoch below `E`. -/
def lowerId (rows : List (Cosign.KeyCert × Cosign.CertAnswer)) (T : Bytes) (E : Nat) : Option Nat :=
  ((rows.filter fun r => r.1.tenantId == T && r.2 == .installed && r.1.epoch < E).map (·.1.epoch)).max?.bind fun m =>
    rows.findIdx? fun r => r.1.tenantId == T && r.2 == .installed && r.1.epoch == m

/-- The tenant's `installed` row of the lowest epoch above `E`. -/
def upperId (rows : List (Cosign.KeyCert × Cosign.CertAnswer)) (T : Bytes) (E : Nat) : Option Nat :=
  ((rows.filter fun r => r.1.tenantId == T && r.2 == .installed && E < r.1.epoch).map (·.1.epoch)).min?.bind fun m =>
    rows.findIdx? fun r => r.1.tenantId == T && r.2 == .installed && r.1.epoch == m

/-- INSTALL's witnesses for a new certificate of tenant `T` and epoch `E`: the witnesses of its epoch, and the
    tenant's installed certificates of the nearest epoch below and above, which decide whether its shard counts
    fit (the counts of the tenant's installed certificates extend one another in epoch order). -/
def selectInstall (rows : List (Cosign.KeyCert × Cosign.CertAnswer)) (T : Bytes) (E : Nat) : List Cosign.KeyCert :=
  (pick rows (selectIds rows T [E] ++ (lowerId rows T E).toList ++ (upperId rows T E).toList)).map (·.1)

/-- The first row holding the certificate's body as installed or as an equivocation. -/
def sameRow (rows : List (Cosign.KeyCert × Cosign.CertAnswer)) (e : Cosign.KeyCert) : Option Cosign.KeyCert :=
  (rows.find? fun r => (r.2 == .installed || r.2 == .equivocates) && r.1.body == e.body).map (·.1)

/-- A key of the certificate is, or is committed to become, a key of the link: the links `Cosign.keysApart`
    can fail on. -/
def touches (H : Bytes → Bytes) (e : Cosign.KeyCert) (p : Cosign.Link) : Bool :=
  [e.key, e.verifierKey].any fun k => k == p.root || k == p.witness || H k.enc == p.rootNext || H k.enc == p.witnessNext

/-- INSTALL's answer (`Cosign.install`) from what a frame carries: `same`, the held certificate of the new one's
    body; `head`, the tenant's head link; `own` and `next`, the chain's links of the certificate's generation and
    of the one after; `keyLinks`, the tenant's links its keys touch; `s0`, the state of its witnesses. -/
def installOutcome (c : Crypto) (head own next : Option Cosign.Link) (keyLinks : List Cosign.Link)
    (same : Option Cosign.KeyCert) (s0 : PayerState) (e : Cosign.KeyCert) : Cosign.CertAnswer :=
  if same.any (·.body == e.body) then .same
  else match head with
    | none => .unknownTenant
    | some hd =>
      match Cosign.judgeWith c hd own keyLinks
          (hd.gen ≤ Cosign.genOf e.epoch || (next.bind (·.closedThrough)).any (e.epoch ≤ ·)) e with
      | .error r => .refused r
      | .ok _ => if Cosign.late s0.toAuth hd e then .belowFence else (Cosign.record s0.toAuth e).2

/-! ### LINK: a new authority link -/

/-- The chain of the given links, newest first, when each is the tenant's next after the one before it. -/
def chainOfLinks : List Cosign.Link → Option Cosign.Chain
  | [] => none
  | [l] => Cosign.Chain.start l
  | l :: rest => (chainOfLinks rest).bind (·.push l)

/-- LINK's answer (`Cosign.installLink`) from what a frame carries of the new link's tenant: its present chain
    and the chains a genesis replaced, each newest first (a link install is rare, and reads every link of the
    tenant: no key that served comes back); the recorded conflict of the new link's digest; and the installed
    certificates whose keys the new link's keys or commitments match.  `none`: the carried links are no chains. -/
def linkOutcome (c : Crypto) (pin : Bytes) (chain : List Cosign.Link) (retired : List (List Cosign.Link))
    (conflicts : List Cosign.Link) (certs : List Cosign.KeyCert) (n : Cosign.SignedLink) : Option Cosign.LinkAnswer :=
  match (if chain.isEmpty then some none else (chainOfLinks chain).map some), retired.mapM chainOfLinks with
  | some ch, some rs =>
    some (Cosign.installLink c pin
      { Cosign.Auth.empty with chainOf := fun _ => ch, retired := fun _ => rs,
                               conflicts := conflicts.map (0, ·), certs := certs } n).2
  | _, _ => none

end BlindLedger.Gate
