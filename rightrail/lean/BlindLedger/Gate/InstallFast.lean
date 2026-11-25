import BlindLedger.Gate.PublishFast

/-! Fast twins of the KEY-CERT/v2 and AUTHORITY-LINK/v1 decoders (`Cosign.decode`, `Cosign.decodeLink`): the same reads
    over a `ByteArray` by offset with `PublishFast`'s readers, so a length check is O(1) instead of the O(remaining)
    `List.length` that `take` pays at every field.  `gate_verify` INSTALL, STORE and RELEASE read their frames with
    them (`installB`, `storeB`, `releaseB`).
    `decodeB_eq`, `decodeLinkB_eq` and `answerOf_eq` (`InstallFastEq.lean`) prove they answer exactly what the list
    decoders answer, for every input.  Pure Lean, total, no `@[extern]`. -/
namespace BlindLedger.Gate

namespace Cosign

def rKey : Rd Key := fun b o => do
  let (scheme, o) ← rNat 1 0 maxNat b o
  let (pk, o) ← rBlob 0 65535 b o
  let (_, o) ← rNeed (keyBytes scheme == some pk.length) b o
  some ({ scheme, pk }, o)

def rKeyCert : Rd KeyCert := fun b o => do
  let (_, o) ← rExpect certTag b o
  let (tenantId, o) ← rIdent b o
  let (epoch, o) ← rNat 8 0 maxNat b o
  let (link, o) ← rDigest b o
  let (g, o) ← rNat 1 0 maxNat b o
  let (chain, o) ← rMany (rNat 4 0 maxNat) g b o
  let (_, o) ← rNeed (chainOk chain) b o
  let (key, o) ← rKey b o
  let (verifierKey, o) ← rKey b o
  let (rootSig, o) ← rBlob 0 65535 b o
  let (coSig, o) ← rBlob 0 65535 b o
  some ({ tenantId, epoch, link, chain, key, verifierKey, rootSig, coSig }, o)

def rLink : Rd SignedLink := fun b o => do
  let (_, o) ← rExpect linkTag b o
  let (tenantId, o) ← rIdent b o
  let (gen, o) ← rNat 4 0 maxGen b o
  let (base, o) ← rNat 4 0 gen b o
  let (prev, o) ← rDigest b o
  let (tag, o) ← rNat 1 0 2 b o
  let (root, o) ← rKey b o
  let (rootNext, o) ← rDigest b o
  let (witness, o) ← rKey b o
  let (witnessNext, o) ← rDigest b o
  let (flag, o) ← rNat 1 0 1 b o
  let (epoch, o) ← rNat 8 0 maxNat b o
  let (_, o) ← rNeed (flag == 1 || epoch == 0) b o
  let (approval, o) ← rDigest b o
  let (selfSig, o) ← rBlob 0 65535 b o
  let (coSig, o) ← rBlob 0 65535 b o
  some ({ tenantId, gen, base, prev, change := .ofTag tag, root, rootNext, witness, witnessNext,
          closedThrough := if flag == 1 then some epoch else none, approval, selfSig, coSig }, o)

/-- `decode` on one slice. -/
def decodeB (b : ByteArray) : Option KeyCert := parseB rKeyCert maxCertBytes b

/-- `decodeLink` on one slice. -/
def decodeLinkB (b : ByteArray) : Option SignedLink := parseB rLink maxLinkBytes b

end Cosign

/-! ### A frame's lists and framed items (`VerifyCli`'s `pList`, `pLink`, `pOptLink`, `pCert`, `pOptCert`) -/

/-- A u16 count, then that many items. -/
def rList {α : Type} (r : Rd α) : Rd (List α) := fun b o => do
  let (k, o) ← rNat 2 0 maxNat b o
  rMany r k b o

/-- A framed item as a list (`pFramed`). -/
def rFramedL : Rd Bytes := fun b o => do
  let (n, o) ← rNat 4 0 maxNat b o
  rTake n b o

/-- A framed item that `d` decodes; one it does not decode fails the read. -/
def rFramedD {α : Type} (d : ByteArray → Option α) : Rd α := fun b o => do
  let (x, o) ← rFramedB b o
  match d x with
  | some v => some (v, o)
  | none => none

/-- `rFramedD`, where an empty item is `none`. -/
def rOptFramedD {α : Type} (d : ByteArray → Option α) : Rd (Option α) := fun b o => do
  let (x, o) ← rFramedB b o
  if x.size == 0 then some (none, o) else
  match d x with
  | some v => some (some v, o)
  | none => none

end BlindLedger.Gate
