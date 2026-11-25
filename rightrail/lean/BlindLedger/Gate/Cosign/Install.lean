import BlindLedger.Gate.Cosign.Link

/-! A reader's authority state: for each tenant the chain since its latest genesis, the chains a later genesis
    replaced, the recorded link conflicts, the installed key certificates and their equivocations, and the fence.
    `installLink` and `installCert` are its only two steps.

    A link is answered in this order: `same` (its body is already held: no effect); `genesis` (the configured pin, a
    generation above every held link of the tenant: the tenant's chain is replaced and retired); `extends` (it
    validly follows the head); `conflicts` (it validly follows an earlier link of the chain, which already has
    another successor: the pair is recorded and blocks the tenant from that generation on); `stale` (it validly
    follows a link of a retired chain: no effect); `refused` (anything else: no effect).  A link that would be
    installed is refused when a key it brings into office has served in any held link of the tenant, or when a
    key or commitment of it matches a key of an installed certificate.  Installed certificates refuse a link in no
    other way: a certificate of the closing generation above the link's closing bound stays installed, below the
    fence the link raises.

    A certificate is answered `same` when its body is already held, before any verification, so a replay is the
    same answer whatever the chain has become since.  Otherwise it is verified against the tenant's chain and its
    retired links (`verify`), and answered `belowFence` (no effect) when its epoch is below the fence the head link
    set and no installed certificate holds that epoch (`late`): a late certificate of an older generation could
    otherwise fix shard counts that no certificate of the current generation may then contradict.  A verified
    certificate raises the fence to its epoch; one with another body than an installed certificate of its tenant
    and epoch is recorded with it as an equivocation; otherwise it is installed when its shard counts fit those of
    the installed certificates the tenant's chain owns (`fits`, `ownedBy`): a certificate a rotation link or a
    genesis disowned is kept but ignored, so a re-genesis starts with no counts to fit. -/
namespace BlindLedger.Gate

def raiseFence (fence : Bytes → Nat) (tenant : Bytes) (epoch : Nat) : Bytes → Nat :=
  fun x => if x = tenant then max (fence x) epoch else fence x

end BlindLedger.Gate

namespace BlindLedger.Gate.Cosign

open BlindLedger.Gate

/-- A chain of the one link `l`, unless `l` has one key in both roles. -/
def Chain.start (l : Link) : Option Chain :=
  if h : l.root ≠ l.witness then some (.genesis l h) else none

/-- The chain with the new head `l`, when `l` is the tenant's, of the next generation, with two different keys. -/
def Chain.push (c : Chain) (l : Link) : Option Chain :=
  if h : l.tenantId = c.head.tenantId ∧ l.gen = c.head.gen + 1 ∧ l.root ≠ l.witness then
    some (c.extend l h.1 h.2.1 h.2.2)
  else none

/-- The generation of the chain's genesis. -/
def Chain.base (c : Chain) : Nat := c.head.gen - c.earlier.length

structure Auth where
  /-- Per tenant, the chain since its latest genesis. -/
  chainOf : Bytes → Option Chain
  /-- Per tenant, the chains a later genesis replaced. -/
  retired : Bytes → List Chain
  /-- Each second successor of a link that already had one, with the base of its chain. -/
  conflicts : List (Nat × Link)
  certs : List KeyCert
  /-- (installed certificate, a verified certificate of the same tenant and epoch with another body). -/
  equivocations : List (KeyCert × KeyCert)
  fence : Bytes → Nat

def Auth.empty : Auth :=
  { chainOf := fun _ => none, retired := fun _ => [], conflicts := [], certs := [], equivocations := [],
    fence := fun _ => 0 }

/-- The links of the tenant's chains that a later genesis replaced.  They still count for key reuse. -/
def retiredLinks (s : Auth) (tenant : Bytes) : List Link := (s.retired tenant).flatMap (·.links)

/-- Every link held for the tenant. -/
def linksOf (s : Auth) (tenant : Bytes) : List Link :=
  ((s.chainOf tenant).map (·.links)).getD [] ++ retiredLinks s tenant

/-- No installed certificate of the link's tenant has a key that is, or is committed to become, a key of the link. -/
def certsApart (c : Crypto) (s : Auth) (n : SignedLink) : Bool :=
  s.certs.all fun e => e.tenantId != n.tenantId || keysApart c.hash [n.link c.hash] e

/-- No key the link brings into office has served in a held link of the tenant. -/
def freshKeys (s : Auth) (n : SignedLink) : Bool :=
  n.introduced.all fun k => (linksOf s n.tenantId).all fun l => k != l.root && k != l.witness

inductive LinkAnswer | same | genesis | extends | conflicts | stale | refused
  deriving DecidableEq, Repr

def installLink (c : Crypto) (pin : Bytes) (s : Auth) (n : SignedLink) : Auth × LinkAnswer :=
  if (linksOf s n.tenantId).any (·.digest == c.hash n.body) || s.conflicts.any (·.2.digest == c.hash n.body) then
    (s, .same)
  else if n.change == .genesis then
    match Chain.start (n.link c.hash) with
    | none => (s, .refused)
    | some g =>
      if genesisOk c pin n && (linksOf s n.tenantId).all (·.gen < n.gen) && freshKeys s n && certsApart c s n then
        ({ s with chainOf := fun t => if t = n.tenantId then some g else s.chainOf t,
                  retired := fun t => if t = n.tenantId then (s.chainOf t).toList ++ s.retired t else s.retired t,
                  fence := raiseFence s.fence n.tenantId (n.gen * genSpan) }, .genesis)
      else (s, .refused)
  else match s.chainOf n.tenantId with
    | none => (s, .refused)
    | some ch =>
      if succeeds c ch.head ch.base n then
        match ch.push (n.link c.hash) with
        | none => (s, .refused)
        | some ch' =>
          if freshKeys s n && certsApart c s n then
            ({ s with chainOf := fun t => if t = n.tenantId then some ch' else s.chainOf t,
                      fence := raiseFence s.fence n.tenantId (n.gen * genSpan) }, .extends)
          else (s, .refused)
      else if ch.earlier.any (fun p => succeeds c p ch.base n) then
        ({ s with conflicts := (ch.base, n.link c.hash) :: s.conflicts,
                  fence := raiseFence s.fence n.tenantId (n.gen * genSpan) }, .conflicts)
      else if (s.retired n.tenantId).any (fun r => r.links.any fun p => succeeds c p r.base n) then (s, .stale)
      else (s, .refused)

/-- A recorded conflict of the tenant's present chain blocks every epoch from the conflict's generation on.  A
    genesis replaces the chain, and with it the conflict stops blocking. -/
def linkBlocked (s : Auth) (tenant : Bytes) (epoch : Nat) : Bool :=
  (s.chainOf tenant).any fun ch =>
    s.conflicts.any fun q => q.2.tenantId == tenant && q.1 == ch.base && q.2.gen ≤ genOf epoch

/-- The chain owns the certificate: it holds the link of the certificate's generation, and the certificate's epoch
    is one that generation certified before it was closed (`Chain.inTime`).  A rotation link closing a generation
    disowns that generation's certificates above its closing bound, and a genesis disowns every certificate of the
    chain it replaces.  Without a chain (a replay that holds no links) every certificate is owned.  It depends on the
    certificate's epoch alone, so a certificate the chain verifies shares its epoch only with owned ones. -/
def ownedBy (ch : Option Chain) (x : KeyCert) : Bool :=
  ch.all fun c => (c.linkAt (genOf x.epoch)).isSome && c.inTime x

/-- The shard counts of the tenant's certificates that its chain owns agree: of two certificates the earlier epoch's
    counts begin the later epoch's, and no epoch has two certificates.  A disowned certificate stays in the state,
    and still counts for key reuse (`certsApart`), but never decides a fit. -/
def fits (s : Auth) (e : KeyCert) : Bool :=
  s.certs.all fun x => x.tenantId != e.tenantId || !ownedBy (s.chainOf e.tenantId) x ||
    (x.epoch != e.epoch && if x.epoch < e.epoch then x.chain.isPrefixOf e.chain else e.chain.isPrefixOf x.chain)

/-- `unknownTenant`: no chain is held for the certificate's tenant.  `unfit`: verified, fence raised, not installed,
    because its shard counts disagree with an installed certificate's.  `belowFence`: verified, but its epoch is below the
    fence its tenant's head link set (generation times 2^32) and no installed certificate holds it (`late`): nothing
    changes. -/
inductive CertAnswer | same | installed | unfit | equivocates | unknownTenant | belowFence | refused (r : Refusal)
  deriving DecidableEq, Repr

/-- The certificate's body is installed or recorded as an equivocation. -/
def held (s : Auth) (e : KeyCert) : Bool :=
  s.certs.any (·.body == e.body) || s.equivocations.any (·.2.body == e.body)

/-- A certificate of an older generation than the head link's (its epoch is below the fence the head link set) for an
    epoch no installed certificate holds.  One that does hold it is still recorded as an equivocation. -/
def late (s : Auth) (head : Link) (e : KeyCert) : Bool :=
  decide (e.epoch < head.gen * genSpan) && !(s.certs.any fun x => x.tenantId == e.tenantId && x.epoch == e.epoch)

/-- A verified certificate enters the state: the fence rises to its epoch; with another body than the installed
    certificate of its tenant and epoch it is recorded with it; otherwise it is installed when it fits. -/
def record (s : Auth) (e : KeyCert) : Auth × CertAnswer :=
  if s.certs.any (fun x => x.tenantId == e.tenantId && x.epoch == e.epoch) then
    ({ s with fence := raiseFence s.fence e.tenantId e.epoch,
              equivocations := (s.certs.filter fun x => x.tenantId == e.tenantId && x.epoch == e.epoch).map (·, e)
                ++ s.equivocations }, .equivocates)
  else if fits s e then
    ({ s with certs := e :: s.certs, fence := raiseFence s.fence e.tenantId e.epoch }, .installed)
  else ({ s with fence := raiseFence s.fence e.tenantId e.epoch }, .unfit)

/-- The step on a decoded certificate. -/
def install (c : Crypto) (s : Auth) (e : KeyCert) : Auth × CertAnswer :=
  if held s e then (s, .same)
  else match s.chainOf e.tenantId with
    | none => (s, .unknownTenant)
    | some ch =>
      match judge c ch (retiredLinks s e.tenantId) e with
      | .error r => (s, .refused r)
      | .ok _ => if late s ch.head e then (s, .belowFence) else record s e

def installCert (c : Crypto) (s : Auth) (bytes : Bytes) : Auth × CertAnswer :=
  match decode bytes with
  | none => (s, .refused .MALFORMED)
  | some e => install c s e

/-- An equivocation blocks its tenant and epoch. -/
def certBlocked (s : Auth) (tenant : Bytes) (epoch : Nat) : Bool :=
  s.equivocations.any fun q => q.1.tenantId == tenant && q.1.epoch == epoch

end BlindLedger.Gate.Cosign
