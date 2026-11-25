import BlindLedger.Gate.Cosign.Chain
import BlindLedger.Gate.MlDsa87

/-! Verification of a KEY-CERT/v2 against its tenant's authority chain.  A certificate is judged against the chain's
    link of the certificate's own generation, so a late certificate of an older generation is still accepted or
    refused on its merits, provided its epoch is one that generation certified before it was closed; its keys are
    judged against every link of the chain and every retired link, a link of a chain of the same tenant that a later
    genesis replaced, so a key never comes back across a re-genesis either.  The checks run in the order of the
    refusal codes, and the first one that fails is the answer.  Hashing and signature verification enter only through
    `Crypto`, so every statement in `Theorems` holds for any instantiation; `realCrypto` is the gate's own: SHA3-512
    and ML-DSA-87 (pure, empty context, so M' = `00 00 ‖ message`). -/
namespace BlindLedger.Gate

/-- Hashing and signature verification, as every reader of the gate's formats takes them. -/
structure Crypto where
  hash : Bytes → Bytes
  /-- Signature verification under a key's own scheme: key, message, signature. -/
  verify : Cosign.Key → Bytes → Bytes → Bool

def sha3 (x : Bytes) : Bytes := (Semantic.sha3_512Fast x.toByteArray).toList

def mlDsaOk (pk msg sig : Bytes) : Bool :=
  MlDsa87.verify pk.toByteArray (([0, 0] ++ msg).toByteArray) sig.toByteArray

/-- Verification under the key's own scheme.  Scheme 1 is pure ML-DSA-87; no other scheme verifies. -/
def schemeOk (k : Cosign.Key) (msg sig : Bytes) : Bool :=
  match k.scheme with
  | 1 => mlDsaOk k.pk msg sig
  | _ => false

/-- SHA3-512 and, for scheme 1, pure ML-DSA-87 with an empty context.  No other scheme verifies. -/
def realCrypto : Crypto where
  hash := sha3
  verify := schemeOk

namespace Cosign

/-- Why a certificate is refused, in the order the checks run.
    `MALFORMED`: the bytes are not the encoding of a well-formed certificate.
    `WRONG_TENANT`: it is another tenant's.
    `GENERATION_AHEAD`: its epoch belongs to a generation above the head link's; that link has not arrived.
    `STALE_KEYSET`: its epoch belongs to a generation of which the chain holds no link, so the chain has no keys to
    judge it by (it begins later, or the generation was replaced by a new genesis).
    `WRONG_LINK`: it does not name the chain's link of its own generation.
    `KEY_REUSE`: a certified key serves, has served or is committed to another purpose, in any link of the chain or
    any retired link (`keysApart`).
    `AFTER_ROTATION`: its generation is below the head's and its epoch is later than the last epoch the next
    generation's link records as certified under it (`Chain.inTime`): it was made, or claims an epoch, after its
    generation was closed.
    `BAD_ROOT_SIGNATURE`: the root signature does not verify under the own-generation link's root key.
    `BAD_WITNESS_SIGNATURE`: the cosignature does not verify under the own-generation link's witness key. -/
inductive Refusal
  | MALFORMED | WRONG_TENANT | GENERATION_AHEAD | STALE_KEYSET | WRONG_LINK | KEY_REUSE | AFTER_ROTATION
  | BAD_ROOT_SIGNATURE | BAD_WITNESS_SIGNATURE
  deriving DecidableEq, Repr

/-- The checks on a decoded certificate, on what they read of its tenant's links: the head; `own`, the chain's link
    of the certificate's generation; `keyLinks`, every link its keys are held apart from; `inTime`, whether it was
    made before its generation closed. -/
def judgeWith (c : Crypto) (head : Link) (own : Option Link) (keyLinks : List Link) (inTime : Bool) (e : KeyCert) :
    Except Refusal KeyCert :=
  if e.tenantId != head.tenantId then .error .WRONG_TENANT
  else if head.gen < genOf e.epoch then .error .GENERATION_AHEAD
  else match own with
  | none => .error .STALE_KEYSET
  | some l =>
    if e.link != l.digest then .error .WRONG_LINK
    else if !keysApart c.hash keyLinks e then .error .KEY_REUSE
    else if !inTime then .error .AFTER_ROTATION
    else if !c.verify l.root e.body e.rootSig then .error .BAD_ROOT_SIGNATURE
    else if !c.verify l.witness e.body e.coSig then .error .BAD_WITNESS_SIGNATURE
    else .ok e

/-- The checks against the tenant's chain.  `retired`: the links of the tenant's chains that a later genesis
    replaced. -/
def judge (c : Crypto) (ch : Chain) (retired : List Link) (e : KeyCert) : Except Refusal KeyCert :=
  judgeWith c ch.head (ch.linkAt (genOf e.epoch)) (ch.links ++ retired) (ch.inTime e) e

def verify (c : Crypto) (ch : Chain) (retired : List Link) (bytes : Bytes) : Except Refusal KeyCert :=
  match decode bytes with
  | none => .error .MALFORMED
  | some e => judge c ch retired e

/-- A certificate stands under the link: the link is its tenant's, of its epoch's generation, the one it names,
    and the link's root and witness keys both signed its body. -/
def certUnder (c : Crypto) (l : Link) (e : KeyCert) : Bool :=
  l.tenantId == e.tenantId && l.gen == genOf e.epoch && l.digest == e.link &&
    c.verify l.root e.body e.rootSig && c.verify l.witness e.body e.coSig

end Cosign

end BlindLedger.Gate
