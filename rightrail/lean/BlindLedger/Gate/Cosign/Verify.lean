import BlindLedger.Gate.Cosign.Chain
import BlindLedger.Gate.Verify

/-! Verification of a KEY-CERT/v2 against its tenant's authority chain.  A certificate is judged against the chain's
    link of the certificate's own generation, so a late certificate of an older generation is still accepted or
    refused on its merits, provided its epoch is one that generation certified before it was closed; its keys are
    judged against every link of the chain and every retired link, a link of a chain of the same tenant that a later
    genesis replaced, so a key never comes back across a re-genesis either.  The checks run in the order of the
    refusal codes, and the first one that fails is the answer.  Hashing and signature verification enter only through
    `Crypto`, so every statement in `Theorems` holds for any instantiation. -/
namespace BlindLedger.Gate.Cosign

open BlindLedger.Gate

structure Crypto where
  hash : Bytes → Bytes
  /-- Signature verification under a key's own scheme: key, message, signature. -/
  verify : Key → Bytes → Bytes → Bool

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

/-- `retired`: the links of the tenant's chains that a later genesis replaced. -/
def verify (c : Crypto) (ch : Chain) (retired : List Link) (bytes : Bytes) : Except Refusal KeyCert :=
  match decode bytes with
  | none => .error .MALFORMED
  | some e =>
    if e.tenantId != ch.head.tenantId then .error .WRONG_TENANT
    else if ch.head.gen < genOf e.epoch then .error .GENERATION_AHEAD
    else match ch.linkAt (genOf e.epoch) with
    | none => .error .STALE_KEYSET
    | some l =>
      if e.link != l.digest then .error .WRONG_LINK
      else if !keysApart c.hash (ch.links ++ retired) e then .error .KEY_REUSE
      else if !ch.inTime e then .error .AFTER_ROTATION
      else if !c.verify l.root e.body e.rootSig then .error .BAD_ROOT_SIGNATURE
      else if !c.verify l.witness e.body e.coSig then .error .BAD_WITNESS_SIGNATURE
      else .ok e

/-- SHA3-512 and, for scheme 1, pure ML-DSA-87 with an empty context.  No other scheme verifies. -/
def realCrypto : Crypto where
  hash := sha3
  verify k m sg := match k.scheme with
    | 1 => mlDsaOk k.pk m sg
    | _ => false

end BlindLedger.Gate.Cosign
