import BlindLedger.Gate.Spec

namespace BlindLedger.Gate.Approval

open BlindLedger.Gate

/-! APPROVAL/v1 (hold-release r4.2 section 10, slice S2): a person's act and the
    moves it binds, in the gate grammar (`Spec`).  A move's `lineDigest` is a raw
    64-byte digest field like every gate digest, so a digest of another length
    has no encoding: the decoder reads exactly 64 bytes and the whole input must
    be consumed (`ApprovalLaws.decodeMoves_lineDigest`).  `lineDigest` is the one
    way to make one; a digest under another domain is refused where admission
    compares the moves with its dry run.  Signatures and the roster are a later slice. -/

def dom (name : String) : Bytes := name.toUTF8.toList ++ [0]

def approvalDomain : Bytes := dom "RR/APPROVAL/v1"
def movesDomain : Bytes := dom "RR/APPROVAL/MOVES/v1"
def lineDomain : Bytes := dom "RR/APPROVAL/LINE/v1"

/-- `SHA3-512("RR/APPROVAL/LINE/v1\0" ‖ raw)`; a gate cell's `raw` is its DECIDE-REQUEST bytes. -/
def lineDigest (H : Bytes → Bytes) (raw : Bytes) : Bytes := H (lineDomain ++ raw)

inductive Kind | PROPOSE | RELEASE | DENY | TOTAL | RESTATE | BYPASS | CANCEL
  deriving DecidableEq, Repr

def kinds : List Kind := [.PROPOSE, .RELEASE, .DENY, .TOTAL, .RESTATE, .BYPASS, .CANCEL]

def Kind.num : Kind → Nat
  | .PROPOSE => 1 | .RELEASE => 2 | .DENY => 3 | .TOTAL => 4 | .RESTATE => 5 | .BYPASS => 6 | .CANCEL => 7

structure Move where
  cell : Bytes
  paymentId : Bytes
  claimKey : Bytes
  payeeKey : Bytes
  cents : Nat
  lineDigest : Bytes
  deriving DecidableEq, Repr

structure Approval where
  kind : Kind
  subject : Bytes
  arg : Bytes
  movesDigest : Bytes
  ownerId : Bytes
  mode : Bytes
  pack : Bytes
  notAfter : Nat
  deriving DecidableEq, Repr

def key : P Bytes := blob 1 65535

def pMove : P Move := do
  let cell ← digest
  let paymentId ← key
  let claimKey ← key
  let payeeKey ← key
  let cents ← nat 8 1
  let lineDigest ← digest
  pure { cell, paymentId, claimKey, payeeKey, cents, lineDigest }

/-- Cells strictly ascending: canonical order, at most one move per cell. -/
def pMoves : P (List Move) := do
  expect movesDomain
  let ms ← many pMove (← nat 2 0 maxLines)
  need (ascending (ms.map (·.cell)))
  pure ms

def pApproval : P Approval := do
  expect approvalDomain
  let kind ← tag kinds
  let subject ← digest
  let arg ← blob 0 65535
  let movesDigest ← digest
  let ownerId ← ident
  let mode ← ident
  let pack ← digest
  let notAfter ← nat 8
  pure { kind, subject, arg, movesDigest, ownerId, mode, pack, notAfter }

def decodeMoves (b : Bytes) : Option (List Move) := parse pMoves maxRequestBytes b
def decodeApproval (b : Bytes) : Option Approval := parse pApproval maxRequestBytes b

/-- Admission's one check of an act's moves: the approval's `movesDigest` is `H`
    of exactly the stored bytes, and those bytes decode.  It never re-encodes;
    the caller compares the result with its dry run by value.  The writer's twin
    is Python `moves_digest`. -/
def admitMoves (H : Bytes → Bytes) (movesDigest stored : Bytes) : Option (List Move) :=
  if H stored = movesDigest then decodeMoves stored else none

/-! `encMove`, `encMoves` and `encApproval` state canonicity (`ApprovalLaws`) and
    serve tests only.  Outside decoded values they collide (a 63-byte cell, a
    2^16-byte key, cents ≥ 2^64), so nothing admits by them. -/

def encMove (m : Move) : Bytes :=
  m.cell ++ identField m.paymentId ++ identField m.claimKey ++ identField m.payeeKey ++ natBE 8 m.cents ++
    m.lineDigest

def encMoves (ms : List Move) : Bytes := movesDomain ++ natBE 2 ms.length ++ ms.flatMap encMove

def encApproval (a : Approval) : Bytes :=
  approvalDomain ++ natBE 1 a.kind.num ++ a.subject ++ identField a.arg ++ a.movesDigest ++ identField a.ownerId ++
    identField a.mode ++ a.pack ++ natBE 8 a.notAfter

end BlindLedger.Gate.Approval
