import BlindLedger.Gate.Spec

/-! KEY-CERT/v2, the key certificate of one tenant epoch: the epoch key that signs checkpoints and the verifier key
    that cosigns them, under the tenant's authority link, signed by the root key and countersigned by the witness key.

        KEY-CERT/v2 ‖ tenant ident ‖ epoch u64 ‖ link 64 ‖ u8 g ‖ u32 count_0 … u32 count_{g-1} ‖ epoch key ‖ verifier key
        then u16 ‖ root signature ‖ u16 ‖ witness cosignature
        key = scheme u8 ‖ u16 length ‖ public key

    Everything before the two signatures is the body: both signatures cover it, and it is the certificate's identity,
    so a hedged re-signature is the same certificate.  A key owns its scheme; a signature carries only its length and
    is judged under its signer's scheme at verification.  The decoder is the specification.  It reads at most
    `maxCertBytes`, accepts exactly the encodings of well-formed certificates (`CodecLaws`), and decodes KEY-CERT/v1
    nowhere.  Synthetic, nonpayment, activation=false. -/
namespace BlindLedger.Gate.Cosign

open BlindLedger.Gate

/-- The decoder's own size bound.  An ML-DSA-87 certificate is 14,548 to 14,799 bytes. -/
def maxCertBytes : Nat := 16 * 1024

/-- The longest shard-count chain: 32 strict multiples from 1 reach the u32 limit. -/
def maxChain : Nat := 32

/-- The registered signature schemes, as the public key length of each.  Scheme 1 is ML-DSA-87.  Only post-quantum
    schemes are ever registered; an unregistered scheme decodes nowhere. -/
def keyBytes : Nat → Option Nat
  | 1 => some mlDsa87Key
  | _ => none

structure Key where
  scheme : Nat
  pk : Bytes
  deriving DecidableEq

/-- A key's bytes: what a certificate carries and what a next-key commitment hashes, scheme byte included. -/
def Key.enc (k : Key) : Bytes := natBE 1 k.scheme ++ natBE 2 k.pk.length ++ k.pk

def pKey : P Key := do
  let scheme ← nat 1
  let pk ← blob 0 65535
  need (keyBytes scheme == some pk.length)
  pure { scheme, pk }

/-- Each shard count is a larger multiple of the one before it: a split only ever multiplies the count. -/
def rises : List Nat → Bool
  | a :: b :: rest => a < b && b % a == 0 && rises (b :: rest)
  | _ => true

/-- A shard-count chain: one count per split so far, 1 to `maxChain` of them, each a u32 of at least 1, rising. -/
def chainOk (c : List Nat) : Bool :=
  0 < c.length && c.length ≤ maxChain && c.all (fun n => 1 ≤ n && n < 2 ^ 32) && rises c

structure KeyCert where
  tenantId : Bytes
  epoch : Nat
  /-- SHA3-512 of the body of the authority link this certificate stands under. -/
  link : Bytes
  /-- The tenant's shard counts up to this epoch; the last one is the epoch's own. -/
  chain : List Nat
  /-- The epoch key: it signs the epoch's checkpoints. -/
  key : Key
  /-- The verifier key: it cosigns the epoch's checkpoints. -/
  verifierKey : Key
  rootSig : Bytes
  coSig : Bytes
  deriving DecidableEq

def certTag : Bytes := "RR/GATE/KEY-CERT/v2".toUTF8.toList ++ [0]

/-- The signed bytes and the certificate's identity. -/
def KeyCert.body (x : KeyCert) : Bytes :=
  certTag ++ identField x.tenantId ++ natBE 8 x.epoch ++ x.link ++ natBE 1 x.chain.length ++
    x.chain.flatMap (natBE 4) ++ x.key.enc ++ x.verifierKey.enc

def KeyCert.encode (x : KeyCert) : Bytes :=
  x.body ++ natBE 2 x.rootSig.length ++ x.rootSig ++ natBE 2 x.coSig.length ++ x.coSig

def pKeyCert : P KeyCert := do
  expect certTag
  let tenantId ← ident
  let epoch ← nat 8
  let link ← digest
  let chain ← many (nat 4) (← nat 1)
  need (chainOk chain)
  let key ← pKey
  let verifierKey ← pKey
  let rootSig ← blob 0 65535
  let coSig ← blob 0 65535
  pure { tenantId, epoch, link, chain, key, verifierKey, rootSig, coSig }

def decode : Bytes → Option KeyCert := parse pKeyCert maxCertBytes

end BlindLedger.Gate.Cosign
