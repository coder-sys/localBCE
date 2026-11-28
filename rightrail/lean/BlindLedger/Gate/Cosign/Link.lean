import BlindLedger.Gate.Cosign.Verify

/-! AUTHORITY-LINK/v1, one step of a tenant's authority chain: it starts a chain (genesis) or replaces exactly one of
    the two keys, the root key or the witness key.

        AUTHORITY-LINK/v1 ‖ tenant ident ‖ gen u32 (< 2^31) ‖ base u32 (≤ gen) ‖ prev 64
        ‖ change u8 (0 genesis, 1 root, 2 witness) ‖ root key ‖ root_next 64 ‖ witness key ‖ witness_next 64
        ‖ closed u8 (0 none, 1 some) ‖ closed epoch u64 (0 when none) ‖ approval 64
        then u16 ‖ self signature ‖ u16 ‖ cosignature

    Everything before the two signatures is the body: both signatures cover it, and its SHA3-512 is the link's
    identity, so a hedged re-signature is the same link.  `closed` is the last epoch certified under the generation
    before; a genesis closes nothing.  Who signs what:

    | change  | self signature by                                   | cosignature by                  |
    | genesis | the new root key                                    | the new witness key             |
    | root    | the new root key, which hashes to the committed one | the previous link's witness key |
    | witness | the new witness key, which hashes to the committed  | the previous link's root key    |

    The outgoing key signs nothing: its commitment to its successor was made when it took office.  The decoder is
    the specification: it reads at most `maxLinkBytes` and accepts exactly the encodings of well-formed links
    (`LinkLaws`). -/
namespace BlindLedger.Gate.Cosign

open BlindLedger.Gate

inductive Change | genesis | root | witness
  deriving DecidableEq, Repr

def Change.tag : Change → Nat
  | .genesis => 0
  | .root => 1
  | .witness => 2

structure SignedLink where
  tenantId : Bytes
  /-- The link's position in the chain. -/
  gen : Nat
  /-- The generation of this chain's genesis; a genesis names its own. -/
  base : Nat
  /-- SHA3-512 of the body of the link before; in a genesis, zeros or the digest of the chain it replaces. -/
  prev : Bytes
  change : Change
  root : Key
  rootNext : Bytes
  witness : Key
  witnessNext : Bytes
  /-- The last epoch certified under the generation before, if any. -/
  closedThrough : Option Nat
  /-- SHA3-512 of the state's approval of this change; carried for audit. -/
  approval : Bytes
  selfSig : Bytes
  coSig : Bytes
  deriving DecidableEq

def linkTag : Bytes := "RR/GATE/AUTHORITY-LINK/v1".toUTF8.toList ++ [0]

/-- The other tags decode nowhere (`pLink` reads 0 to 2). -/
def Change.ofTag : Nat → Change
  | 0 => .genesis
  | 1 => .root
  | _ => .witness

/-- The decoder's own size bound.  A link with ML-DSA-87 keys and signatures is 14,751 to 14,878 bytes. -/
def maxLinkBytes : Nat := 16 * 1024

/-- The last generation: 2^31 generations of 2^32 epochs each fill the u63 epoch range. -/
def maxGen : Nat := 2 ^ 31 - 1

def closedField : Option Nat → Bytes
  | none => natBE 1 0 ++ natBE 8 0
  | some e => natBE 1 1 ++ natBE 8 e

/-- The signed bytes; their hash is the link's identity. -/
def SignedLink.body (x : SignedLink) : Bytes :=
  linkTag ++ identField x.tenantId ++ natBE 4 x.gen ++ natBE 4 x.base ++ x.prev ++ natBE 1 x.change.tag ++
    x.root.enc ++ x.rootNext ++ x.witness.enc ++ x.witnessNext ++ closedField x.closedThrough ++ x.approval

def SignedLink.encode (x : SignedLink) : Bytes :=
  x.body ++ natBE 2 x.selfSig.length ++ x.selfSig ++ natBE 2 x.coSig.length ++ x.coSig

def pLink : P SignedLink := do
  expect linkTag
  let tenantId ← ident
  let gen ← nat 4 0 maxGen
  let base ← nat 4 0 gen
  let prev ← digest
  let tag ← nat 1 0 2
  let root ← pKey
  let rootNext ← digest
  let witness ← pKey
  let witnessNext ← digest
  let flag ← nat 1 0 1
  let epoch ← nat 8
  need (flag == 1 || epoch == 0)
  let approval ← digest
  let selfSig ← blob 0 65535
  let coSig ← blob 0 65535
  pure { tenantId, gen, base, prev, change := .ofTag tag, root, rootNext, witness, witnessNext,
         closedThrough := if flag == 1 then some epoch else none, approval, selfSig, coSig }

def decodeLink : Bytes → Option SignedLink := parse pLink maxLinkBytes

/-- The link as certificate verification reads it. -/
def SignedLink.link (H : Bytes → Bytes) (x : SignedLink) : Link :=
  { tenantId := x.tenantId, gen := x.gen, digest := H x.body, root := x.root, rootNext := x.rootNext,
    witness := x.witness, witnessNext := x.witnessNext, closedThrough := x.closedThrough }

/-- The four keys of a link are four: the root and witness keys differ, the two commitments differ, and neither
    commitment is the hash of a key in office. -/
def SignedLink.apart (H : Bytes → Bytes) (x : SignedLink) : Bool :=
  x.root != x.witness && x.rootNext != x.witnessNext &&
    H x.root.enc != x.rootNext && H x.root.enc != x.witnessNext &&
    H x.witness.enc != x.rootNext && H x.witness.enc != x.witnessNext

/-- A genesis is the reader's configured pin, signed by both of its own keys. -/
def genesisOk (c : Crypto) (pin : Bytes) (g : SignedLink) : Bool :=
  g.change == .genesis && g.base == g.gen && g.closedThrough.isNone && c.hash g.body == pin && g.apart c.hash &&
    c.verify g.root g.body g.selfSig && c.verify g.witness g.body g.coSig

/-- `n` validly follows `p`, a link of the chain whose genesis is of generation `base`: the next generation of the
    same tenant and chain, naming `p`, closing only epochs of `p`'s generation, signed by the key `p` committed to
    and cosigned by the other role's key in `p`; the other role's key and commitment do not move. -/
def succeeds (c : Crypto) (p : Link) (base : Nat) (n : SignedLink) : Bool :=
  n.tenantId == p.tenantId && n.gen == p.gen + 1 && n.base == base && n.prev == p.digest && n.apart c.hash &&
    n.closedThrough.all (fun e => genOf e == p.gen) &&
    match n.change with
    | .genesis => false
    | .root => c.hash n.root.enc == p.rootNext && c.verify n.root n.body n.selfSig &&
        c.verify p.witness n.body n.coSig && n.witness == p.witness && n.witnessNext == p.witnessNext
    | .witness => c.hash n.witness.enc == p.witnessNext && c.verify n.witness n.body n.selfSig &&
        c.verify p.root n.body n.coSig && n.root == p.root && n.rootNext == p.rootNext

/-- The keys a link brings into office. -/
def SignedLink.introduced (n : SignedLink) : List Key :=
  match n.change with
  | .genesis => [n.root, n.witness]
  | .root => [n.root]
  | .witness => [n.witness]

end BlindLedger.Gate.Cosign
