import BlindLedger.Gate.Flat.Store

/-! The history engine v3 as a reference model (format: conformance/ENGINE_V3.md).  Definitions only.

    A key's stored bytes are its set tag and its fixed-width key bytes (`sk`, `kbytes`).  The store keeps the decision
    state `Flat.St` as: an open window and a sealing window of entries (`Fs3.win`, `Fs3.sealing`), and installed chunks
    of entries (`files c`), each entry live unless its dead bit is set.  A directory of 64 cuckoo segments (`Dirs`,
    each a `Flat.Store.Dir`) names the chunks that may hold a key.  Positions come from the key's directory hash `dh` (a slice
    of the keyed SHA3-256 key digest; any function here) XOR the segment's salt.

    A batch removes lines in fixed stages, each closed over payments: widths, failed block reads, then the admission
    budget; the kept lines are decided by `decideBatchIdx` (`run3`).  Every hash is a parameter: `H` (SHA3-512).  Synthetic, nonpayment, non-PHI, activation=false. -/

namespace BlindLedger.Gate.Engine3

open BlindLedger.Gate.Rules
open BlindLedger.Gate.OnepIndex (leb)
open Std (HashMap)

/-! ## Store widths and key bytes -/

/-- `leB` by one division of `n` per byte, where `leB` takes a power and a division of the whole number per byte. -/
def leBF : Nat → Nat → Bytes
  | 0, _ => []
  | w + 1, n => (n % 256).toUInt8 :: leBF w (n / 256)

theorem leBF_add (a b n : Nat) : leBF (a + b) n = leBF a n ++ leBF b (n / 256 ^ a) := by
  induction a generalizing n with
  | zero => simp [leBF]
  | succ a ih =>
    rw [Nat.add_right_comm a 1 b, leBF, leBF, ih, Nat.pow_succ, Nat.mul_comm (256 ^ a) 256, ← Nat.div_div_eq_div_mul]
    try rfl

theorem leBF_mod (k n : Nat) : leBF k (n % 256 ^ k) = leBF k n := by
  induction k generalizing n with
  | zero => rfl
  | succ k ih =>
    rw [leBF, leBF, Nat.pow_succ, Nat.mul_comm (256 ^ k) 256, Nat.mod_mul_right_div_self, ih,
      Nat.mod_mod_of_dvd n (Nat.dvd_mul_right 256 (256 ^ k))]

/-- `leB` eight bytes per division of `n`: a 32-byte member takes 4 big-number steps, not 32. -/
def leBW (w n : Nat) : Bytes :=
  if h : 8 ≤ w then leBF 8 (n % 2 ^ 64) ++ leBW (w - 8) (n >>> 64) else leBF w n
termination_by w
decreasing_by omega

/-- An `n33` number `0x01 ‖ 32 bytes`; the store keeps its low 32 bytes. -/
def isN33 (n : Nat) : Bool := n / 2 ^ 256 == 1

/-! Store widths of a line (conformance/ENGINE_V3.md section 1): every identifier number is kept whole. -/
def idW : Nat := 51
def payW : Nat := 72
def provW : Nat := 21
def procW : Nat := 31
def lineW2 : Nat := 245

/-- Whether each field fits its width; a line that does not is held `FIELD_WIDTH` (rule 3). -/
def fitsLine2 (l : Line) : Bool :=
  decide (l.id < 256 ^ idW) && decide (l.pay < 256 ^ payW) && isN33 l.member && decide (l.payee < 256 ^ provW) &&
  decide (l.rendering < 256 ^ provW) && decide (l.date < 2 ^ 32) && decide (l.proc < 256 ^ procW) &&
  decide (l.units < 2 ^ 32) && decide (l.cents < 2 ^ 64)

/-- A key whose kind and fields fit the layout: exact (kind 1 or 3), FFS near (2), CAP near (0), id (4). -/
def fitsKey : Key → Bool
  | [t, m, p, d, pr, u, c] => (t == 1 || t == 3) && isN33 m && decide (p < 256 ^ provW) && decide (d < 2 ^ 32) &&
      decide (pr < 256 ^ procW) && decide (u < 2 ^ 32) && decide (c < 2 ^ 64)
  | [t, m, r, d, pr] => t == 2 && isN33 m && decide (r < 256 ^ provW) && decide (d < 2 ^ 32) && decide (pr < 256 ^ procW)
  | [t, m, mo] => t == 0 && isN33 m && decide (mo < 2 ^ 32)
  | [t, i] => t == 4 && decide (i < 256 ^ idW)
  | _ => false

/-- An identifier field: its byte count `n` (at most the width `w`), then the number's minimal big-endian bytes. -/
def idField (w n : Nat) : Bytes :=
  let b := (leBW w n).reverse.dropWhile (· == 0)
  b.length.toUInt8 :: b

/-- The key bytes of a fitting key (conformance/ENGINE_V3.md section 2); any other key is `0xFF ‖ encKey`, so the map is
    one to one. -/
def kbytes (k : Key) : Bytes :=
  if fitsKey k then
    match k with
    | [t, m, p, d, pr, u, c] =>
      t.toUInt8 :: leBW 32 m ++ idField provW p ++ leBF 4 d ++ idField procW pr ++ leBF 4 u ++ leBF 8 c
    | [t, m, r, d, pr] => t.toUInt8 :: leBW 32 m ++ idField provW r ++ leBF 4 d ++ idField procW pr
    | [t, m, mo] => t.toUInt8 :: leBW 32 m ++ leBF 4 mo
    | [t, i] => t.toUInt8 :: idField idW i
    | _ => 0xFF :: Flat.encKey k
  else 0xFF :: Flat.encKey k

/-- A key's stored bytes: set tag (0 released, 1 unresolved), then the key bytes. -/
def sk (u : Bool) (k : Key) : Bytes := (if u then 1 else 0) :: kbytes k

/-! ## Causes -/

/-- Why the open window has no room for a line. -/
inductive Why | installing | growing | dirFull | noNumber | disk | budget
  deriving DecidableEq, Repr

def Why.code : Why → Nat
  | .installing => 0 | .growing => 1 | .dirFull => 2 | .noNumber => 3 | .disk => 4 | .budget => 5

/-- A hold's cause.  No line, batch, payment or time field: the same cause has the same id in every batch. -/
inductive Cause
  | block (shard chunk page blk : Nat)
  | window (shard : Nat) (why : Why)
  | rows (shard : Nat)
  | width (field : Nat)
  deriving DecidableEq, Repr

/-! ## Directory -/

def segN : Nat := 64

/-- A segment has fewer than `2^30` buckets: a kick position (up to 4 buckets) then fits the 32 bits the kick log gives it. -/
def segMax : Nat := 2 ^ 30

/-- A key's segment: bits 44-49 of its directory hash. -/
def segOf (h : UInt64) : Nat := h.toNat / 2 ^ 44 % segN

/-- 64 segments, each a cuckoo table with its own salt (fresh at each build, never written). -/
structure Dirs where
  t : Array Flat.Store.Dir
  salt : Array UInt64

def Dirs.seg (ds : Dirs) (j : Nat) : Flat.Store.Dir := ds.t.getD j (Flat.Store.Dir.empty 1)

/-- The value the segment's table hashes: the directory hash XOR the segment's salt. -/
def Dirs.pos (ds : Dirs) (h : UInt64) : UInt64 := h ^^^ ds.salt.getD (segOf h) 0

/-- Chunks that may hold a key of directory hash `h`. -/
def Dirs.cands (ds : Dirs) (h : UInt64) : List Nat := (ds.seg (segOf h)).cands (ds.pos h)

def Dirs.Ok (ds : Dirs) : Prop := ds.t.size = segN ∧ ds.salt.size = segN ∧ ∀ j < segN, (ds.seg j).Ok ∧ (ds.seg j).nb < segMax

def Dirs.insert (ds : Dirs) (h : UInt64) (c : Nat) : Except Flat.Store.Refusal Dirs :=
  ((ds.seg (segOf h)).insert (ds.pos h) c).map fun d => { ds with t := ds.t.set! (segOf h) d }

def Dirs.erase (ds : Dirs) (h : UInt64) (c : Nat) : Dirs :=
  let d := ds.seg (segOf h)
  let p := ds.pos h
  { ds with t := ds.t.set! (segOf h) (d.erase (Flat.Store.slot (Flat.Store.fpOf p) c) (p.toNat % d.nb)) }

def Dirs.drop (ds : Dirs) (c : Nat) : Dirs := { ds with t := ds.t.map (·.drop c) }

/-! ## Store state -/

/-- A chunk's entries in order (entry `i` is the `i`-th). -/
abbrev Ents := List (Bytes × Flat.Entry)

/-! ## Steps -/

/-! ## Blocks and the clean tier -/

/-! ## A batch -/

structure Out where
  holds : List (Nat × Cause)
  res : List Decision × List Line × List Line

/-! ## Retry -/

/-- A logged frame: its request digest and its answer and trailer bytes. -/
structure Fr where
  rq : Bytes
  bytes : Bytes
  deriving DecidableEq

inductive Act
  /-- A committed batch's logged bytes, served unchanged. -/
  | serve (bytes : Bytes)
  /-- The pending frame equals the fresh decision: it stays and is served. -/
  | keep (bytes : Bytes)
  /-- The pending frame is cut and the fresh one appended, naming the old one's digest. -/
  | replace (old new : Fr)
  /-- Nothing pending: the fresh frame is appended. -/
  | append (new : Fr)
  | refuse (word : String)

/-- The bytes an action returns. -/
def Act.out : Act → Option Bytes
  | .serve b => some b
  | .keep b => some b
  | .replace _ f => some f.bytes
  | .append f => some f.bytes
  | .refuse _ => none

/-! ## Payment outcome in one pass -/

end BlindLedger.Gate.Engine3
