import BlindLedger.Sha3Quick
import BlindLedger.Gate.PublishSpec

/-! Fast twin of `publishFrame` (`PublishSpec.lean`): the frame read over a `ByteArray` by offset, so a length
    check is O(1) instead of the O(remaining) `List.length` that `take` pays at every field, and the decision
    `publishOkTreeB`, which decodes each token from its slice, hashes with `Semantic.sha3_512Quick` on `ByteArray`s
    and keeps the Merkle levels in `Array`s (O(1) path lookup).  Pure Lean, total, no `@[extern]`.
    `publishOkTreeB_eq` and `publishFrameB_eq` (`PublishFastEq.lean`) prove it answers exactly what
    `publishOkTree` / `publishFrame b.data.toList` answer, for every input. -/
namespace BlindLedger.Gate

/-- `n` bytes at offset `o` as a slice, and the offset after them. -/
def rdB (b : ByteArray) (o n : Nat) : Option (ByteArray × Nat) :=
  if o + n ≤ b.size then some (b.extract o (o + n), o + n) else none

def rd (b : ByteArray) (o n : Nat) : Option (Bytes × Nat) :=
  (rdB b o n).map fun (x, o') => (x.data.toList, o')

/-- A reader: the array and a start offset in, a value and the next offset out. -/
abbrev Rd (α : Type) := ByteArray → Nat → Option (α × Nat)

def rNeed (ok : Bool) : Rd Unit := fun _ o => if ok then some ((), o) else none

def rTake (n : Nat) : Rd Bytes := fun b o => rd b o n

def rNat (w : Nat) (lo : Nat := 0) (hi : Nat := maxNat) : Rd Nat := fun b o => do
  let (x, o) ← rTake w b o
  let (_, o) ← rNeed (lo ≤ beNat x && beNat x ≤ hi) b o
  some (beNat x, o)

def rFramedB (b : ByteArray) (o : Nat) : Option (ByteArray × Nat) :=
  (rNat 4 0 maxNat b o).bind fun (n, o') => rdB b o' n

def rManyB (b : ByteArray) : Nat → Nat → Option (List ByteArray × Nat)
  | o, 0 => some ([], o)
  | o, k + 1 => (rFramedB b o).bind fun (x, o1) => (rManyB b o1 k).map fun (xs, o2) => (x :: xs, o2)

/-! ### TOKEN/v2 over the array (`pLeaf`, `pToken` of `Spec.lean` with `take` and `nat` replaced by offsets) -/

def rTag {α : Type} (names : List α) : Rd α := fun b o => do
  let (n, o) ← rNat 1 1 names.length b o
  match names[n - 1]? with
  | some x => some (x, o)
  | none => none

def rDigest : Rd Bytes := rTake digestBytes

def rBlob (lo hi : Nat) : Rd Bytes := fun b o => do
  let (n, o) ← rNat 2 lo hi b o
  rTake n b o

def rIdent : Rd Bytes := fun b o => do
  let (bs, o) ← rBlob 1 65535 b o
  let (_, o) ← rNeed (identOk bs) b o
  some (bs, o)

def rCode : Rd Bytes := fun b o => do
  let (bs, o) ← rBlob 1 65535 b o
  let (_, o) ← rNeed (codeOk bs) b o
  some (bs, o)

def rExpect (d : Bytes) : Rd Unit := fun b o => do
  let (x, o) ← rTake d.length b o
  rNeed (x == d) b o

def rMany {α : Type} (r : Rd α) : Nat → Rd (List α)
  | 0 => fun _ o => some ([], o)
  | k + 1 => fun b o => do
    let (x, o) ← r b o
    let (xs, o) ← rMany r k b o
    some (x :: xs, o)

/-- The bytes `r` consumed, as a list. -/
def rConsumed {α : Type} (r : Rd α) : Rd (α × Bytes) := fun b o => do
  let (x, o') ← r b o
  some ((x, (b.extract o o').data.toList), o')

def rLeaf : Rd Leaf := fun b o => do
  let (_, o) ← rExpect ("RR/GATE/TOKEN/v2".toUTF8.toList ++ [0]) b o
  let (tenantId, o) ← rIdent b o
  let (programId, o) ← rIdent b o
  let (shardId, o) ← rNat 4 0 maxNat b o
  let (flow, o) ← rTag flows b o
  let (revision, o) ← rNat 8 0 maxNat b o
  let (paymentId, o) ← rIdent b o
  let (memberKey, o) ← rTake memberKeyBytes b o
  let (payeeRef, o) ← rIdent b o
  let (amountCents, o) ← rNat 8 0 maxNat b o
  let (period, o) ← rIdent b o
  let (linesRoot, o) ← rDigest b o
  let (outcome, o) ← rTag outcomes b o
  let (nReasons, o) ← rNat 1 0 maxReasonCodes b o
  let (reasonCodes, o) ← rMany rCode nReasons b o
  let (authority, o) ← rTag authorities b o
  let (grantId, o) ← rDigest b o
  let (bypass, o) ← rDigest b o
  let (ruleVersion, o) ← rDigest b o
  let (engineRelease, o) ← rDigest b o
  let (inputCommitment, o) ← rDigest b o
  let (decidedAt, o) ← rNat 8 0 maxNat b o
  let (epoch, o) ← rNat 8 0 maxNat b o
  let (seq, o) ← rNat 8 0 maxNat b o
  let (issuedAt, o) ← rNat 8 0 maxNat b o
  let (expiresAt, o) ← rNat 8 0 maxNat b o
  let (_, o) ← rNeed (if flow.ruled then linesRoot != zeroDigest else outcome == .HUMAN_REVIEW) b o
  let (_, o) ← rNeed (ascending reasonCodes) b o
  let (_, o) ← rNeed (bypass == zeroDigest || (outcome == .ALLOW && flow.ruled)) b o
  let (_, o) ← rNeed (decidedAt ≤ issuedAt && issuedAt ≤ expiresAt && expiresAt ≤ issuedAt + maxTokenLifetime) b o
  some ({ tenantId, programId, shardId, flow, revision, paymentId, memberKey, payeeRef, amountCents, period,
          linesRoot, outcome, reasonCodes, authority, grantId, bypass, ruleVersion, engineRelease, inputCommitment,
          decidedAt, epoch, seq, issuedAt, expiresAt }, o)

def rToken : Rd Token := fun b o => do
  let (lf, o) ← rConsumed rLeaf b o
  let (nPath, o) ← rNat 1 0 maxTokenPath b o
  let (siblings, o) ← rMany rDigest nPath b o
  let (checkpointDigest, o) ← rDigest b o
  some ({ leaf := lf.1, leafBytes := lf.2, siblings, checkpointDigest }, o)

/-- `decodeToken` on one slice. -/
def decodeTokenB (b : ByteArray) : Option Token :=
  if b.size > maxTokenBytes then none else
  match rToken b 0 with
  | some (t, o) => if o = b.size then some t else none
  | none => none

/-! ### The batch decision -/

def hashB (a : ByteArray) : ByteArray := Semantic.sha3_512Quick a

def merkleD : ByteArray := (domain "MERKLE-NODE").toByteArray

def leafHashB (x : ByteArray) : ByteArray := hashB (merkleD ++ ⟨#[0]⟩ ++ x)

def nodeHashB (l r : ByteArray) : ByteArray := hashB (merkleD ++ ⟨#[1]⟩ ++ l ++ r)

def pairUpB : List ByteArray → List ByteArray
  | a :: b :: rest => nodeHashB a b :: pairUpB rest
  | xs => xs

/-- `levels`, each level an `Array`. -/
def levelsB : Nat → List ByteArray → List (Array ByteArray)
  | _, [x] => [#[x]]
  | 0, xs => [xs.toArray]
  | fuel + 1, xs => xs.toArray :: levelsB fuel (pairUpB xs)

/-- `pathOf` over the arrays: each sibling is an O(1) read. -/
def pathOfB : List (Array ByteArray) → Nat → List ByteArray
  | [], _ => []
  | lvl :: rest, i =>
    if lvl.size ≤ 1 then []
    else if i % 2 == 0 && i + 1 == lvl.size then pathOfB rest (i / 2)
    else lvl.getD (if i % 2 == 0 then i + 1 else i - 1) ByteArray.empty :: pathOfB rest (i / 2)

def tokenFitsTreeB (c : Crypto) (k : Nat) (x : Stored) (lv : List (Array ByteArray)) (i : Nat) (t : Token) : Bool :=
  let cp := x.checkpoint
  t.checkpointDigest == x.digest && t.leaf.seq == cp.seqFrom + i &&
    cp.tenantId == t.leaf.tenantId && cp.programId == t.leaf.programId && cp.shardId == t.leaf.shardId &&
    cp.epoch == t.leaf.epoch && t.siblings == (pathOfB lv i).map (·.data.toList) &&
    t.leaf.shardId == shardOf c.hash t.leaf.tenantId t.leaf.memberKey k

/-- `storeCheckpoint` once `decodeCheckpoint bytes = some x` is known. -/
def storeCheckpointD (c : Crypto) (s : PayerState) (bytes : Bytes) (x : SignedCheckpoint) : Option PayerState :=
  let new : Stored := ⟨c.hash x.header, x.checkpoint, bytes⟩
  if s.certs.any fun e => e.tenantId == x.checkpoint.tenantId && e.epoch == x.checkpoint.epoch &&
      (c.keyUsable e && c.sigOk e.publicKey x.header x.signature) then
    match s.checkpoints.find? (forks new) with
    | some old => some { s with forked := (old, new) :: s.forked }
    | none =>
      if blocked s x.checkpoint.tenantId x.checkpoint.shardId x.checkpoint.epoch then none
      else some { s with checkpoints := new :: s.checkpoints }
  else none

/-- `realCrypto`'s `rootSigned` without the re-decode of `e.signed` (which holds for a decoded certificate:
    `decodeKeyCert_signed`). -/
def rootSignedFast (roots : List (Bytes × Bytes)) (e : EpochCert) : Bool :=
  roots.any fun r => r.1 == e.tenantId &&
    mlDsaOk r.2 (e.signed.take (e.signed.length - 2 - mlDsa87Signature)) (e.signed.drop (e.signed.length - mlDsa87Signature))

/-- `accepts` once both decodes are known (`accepts_eq`). -/
def acceptsD (rootPk new : Bytes) (x : SignedCheckpoint) (e : EpochCert) : Bool :=
  let roots := [(x.checkpoint.tenantId, rootPk)]
  let c := { realCrypto roots with rootSigned := rootSignedFast roots }
  match installCert c emptyState e with
  | (s, true) => match storeCheckpointD c s new x with
    | some s' => s'.forked.isEmpty
    | none => false
  | _ => false

/-- `publishOkTree` with the tokens as slices of the frame. -/
def publishOkTreeB (rootPk cert : ByteArray) (last : Option ByteArray) (new : ByteArray)
    (tokens : List ByteArray) (tpm : Nat) : Bool :=
  match decodeKeyCert cert.data.toList, decodeCheckpoint new.data.toList, tokens.mapM decodeTokenB with
  | some e, some x, some ts =>
    let n : Stored := ⟨sha3 x.header, x.checkpoint, new.data.toList⟩
    let lv := levelsB treeFuel (ts.map fun t => leafHashB t.leafBytes.toByteArray)
    acceptsD rootPk.data.toList new.data.toList x e &&
      (last.map (·.data.toList)).all (fun b => (storedOf sha3 b).isSome) &&
      follows ((last.map (·.data.toList)).bind (storedOf sha3)) n && n.checkpoint.counter == tpm + 1 && ts.length == n.checkpoint.count &&
      (lv.getLast?.map fun a => a.toList.map (·.data.toList)) == some [n.checkpoint.tokenRoot] &&
      (ts.zipIdx.all fun (t, i) =>
        tokenFitsTreeB (realCrypto [(n.checkpoint.tenantId, rootPk.data.toList)]) e.shardCount n lv i t) &&
      ascending (ts.map (·.leaf.paymentId))
  | _, _, _ => false

def publishFrameB (b : ByteArray) : Option Bool :=
  (rdB b 0 mlDsa87Key).bind fun (rootPk, o1) => (rFramedB b o1).bind fun (cert, o2) =>
  (rFramedB b o2).bind fun (last, o3) => (rFramedB b o3).bind fun (new, o4) =>
  (rNat 2 0 maxNat b o4).bind fun (k, o5) => (rManyB b o5 k).bind fun (tokens, o6) => (rNat 8 0 maxNat b o6).bind fun (tpm, o7) =>
  if o7 = b.size then
    some (publishOkTreeB rootPk cert (if last.size = 0 then none else some last) new tokens tpm)
  else none

end BlindLedger.Gate
