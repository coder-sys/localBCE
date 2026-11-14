import BlindLedger.Gate.Cosign.Codec

/-! Where a key certificate stands in its tenant's authority chain.  The chain is a list of authority links, each
    one generation after the last; generation `g` holds authority for the epochs `[g·2^32, (g+1)·2^32)` and for no
    others, so a replaced root or witness key can never certify an epoch of a later generation, and the rotation away
    from `g` closes it at the last epoch it certified, so no epoch of `g` after the closing is ever accepted.  A
    certificate is judged against the link of its own generation, and its keys against every link of the chain and of
    the tenant's chains that a later genesis replaced. -/
namespace BlindLedger.Gate.Cosign

open BlindLedger.Gate

def genSpan : Nat := 2 ^ 32

/-- The generation an epoch belongs to. -/
def genOf (epoch : Nat) : Nat := epoch / genSpan

/-- An authority link, as certificate verification reads it. -/
structure Link where
  tenantId : Bytes
  /-- The link's position in the chain. -/
  gen : Nat
  /-- SHA3-512 of the link's body: what a certificate under it names. -/
  digest : Bytes
  /-- The root key: it signs certificates. -/
  root : Key
  /-- SHA3-512 of the encoded next root key, held cold until it replaces `root`. -/
  rootNext : Bytes
  /-- The witness key: it countersigns certificates. -/
  witness : Key
  /-- SHA3-512 of the encoded next witness key. -/
  witnessNext : Bytes
  /-- The last epoch certified under the previous generation: no later epoch of that generation is ever accepted.  A
      field of this link's body, so covered by this link's own two signatures (the incoming key's and the cosignature
      of the other role's current key); the outgoing key signs nothing at rotation.  `none` when that generation
      certified nothing, and for the tenant's first link. -/
  closedThrough : Option Nat

/-- Each link is one generation after the link that follows it. -/
def Consecutive : List Link → Prop
  | a :: t@(b :: _) => a.gen = b.gen + 1 ∧ Consecutive t
  | _ => True

/-- A tenant's authority chain as a reader holds it: the head, the newest link, and the links before it, newest first.
    Every link is the tenant's, each is one generation after the next, and no link has one key in both roles.  The
    only builders are `genesis` and `extend`, so every chain verification sees has these properties. -/
structure Chain where
  head : Link
  earlier : List Link
  sameTenant : ∀ p ∈ earlier, p.tenantId = head.tenantId
  consecutive : Consecutive (head :: earlier)
  rootNeWitness : ∀ p ∈ head :: earlier, p.root ≠ p.witness

/-- Every link, the head first. -/
def Chain.links (c : Chain) : List Link := c.head :: c.earlier

/-- The held link of generation `g`, if any. -/
def Chain.linkAt (c : Chain) (g : Nat) : Option Link := c.links.find? (·.gen == g)

def Chain.genesis (l : Link) (hr : l.root ≠ l.witness) : Chain where
  head := l
  earlier := []
  sameTenant := by simp
  consecutive := by simp [Consecutive]
  rootNeWitness := by simpa using hr

/-- A new head: the tenant's, of the next generation, with distinct root and witness keys. -/
def Chain.extend (c : Chain) (l : Link) (ht : l.tenantId = c.head.tenantId) (hg : l.gen = c.head.gen + 1)
    (hr : l.root ≠ l.witness) : Chain where
  head := l
  earlier := c.head :: c.earlier
  sameTenant p hp := by
    rcases List.mem_cons.1 hp with rfl | hp
    · exact ht.symm
    · exact (c.sameTenant p hp).trans ht.symm
  consecutive := by simp only [Consecutive]; exact ⟨hg, c.consecutive⟩
  rootNeWitness p hp := by
    rcases List.mem_cons.1 hp with rfl | hp
    · exact hr
    · exact c.rootNeWitness p hp

/-- One key per purpose, for good.  The epoch key and the verifier key differ from each other, and for every link
    given (verification gives the chain's links and those of the chains it replaced), neither is its root or witness
    key (a retired key never comes back) or one of its committed next keys (a cold key never goes hot). -/
def keysApart (H : Bytes → Bytes) (links : List Link) (e : KeyCert) : Bool :=
  e.key != e.verifierKey && [e.key, e.verifierKey].all fun k => links.all fun p =>
    k != p.root && k != p.witness && H k.enc != p.rootNext && H k.enc != p.witnessNext

/-- The certificate was made before its generation closed: its generation is the head's, or its epoch is at most the
    last epoch the next generation's link records as certified under it. -/
def Chain.inTime (c : Chain) (e : KeyCert) : Bool :=
  c.head.gen ≤ genOf e.epoch || ((c.linkAt (genOf e.epoch + 1)).bind (·.closedThrough)).any (e.epoch ≤ ·)

end BlindLedger.Gate.Cosign
