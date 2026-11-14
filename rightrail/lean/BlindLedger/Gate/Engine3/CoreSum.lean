import BlindLedger.Gate.Engine3.Index

/-! # Long-core summary (gate speed design section 3.4)

RAM only, never stored, rebuilt from a rows file at load (`Hist.Side.load`).  A core of more than `longMin` rows is
*summarised*: each exact key and each near key that occurs among its first `capN` rows (`POSTING_CAP`) has one entry
holding what the decider reads of the key's rows (`Flat.DecideCut`): the first row, the row count, and the first row that
is not identical (`RowX.same`) to the first.  The rows are not listed, so a read of a key fetches at most two rows however
long its history.

* **Flags.**  One bit per row: *its core is summarised up to this row* (every row of the core up to this row, within the
  first `capN`, is counted in the entries of its two keys).  Bits live in segments of 8192 rows (1 KB) allocated at the
  first write into them.
* **Entries.**  Two open tables (exact, near), three words an entry: the key's 64-bit digest word (0 empty); the first
  row plus one (low 40 bits), the count (bits 40 to 55) and bit 63 *mixed*; the first row not identical to the first, plus
  one (0 none).  A table is allocated at its first insert and doubles when an insert would fill it past half, up to
  `slots` entries; past that an insert refuses (the core is then not summarised: its flag stays off and readers walk its
  chain).  A row at or above `cap` is not counted either.
* **Keys.**  The digest word is a seeded mix of the key's words (`Hist.exactHashR`, `Hist.nearHashR`, a seed random per
  open).  Two keys can share a word: a row whose key is not the key of the entry's first row marks the entry mixed, and a
  reader of a mixed entry walks the core's chain.

Soundness of a read rests on one invariant: for a row whose flag is on, every earlier row of its core within the first
`capN` was counted, in ascending row order, in the entry of its exact key and in that of its near key, and each count
compared the row with the entry's first row.  So an entry that is not mixed holds, for the key of its first row, its
lowest row, its count and its lowest row not identical to the first; a key of a summarised core that has no entry, or
whose entry's first row has another key, has no row in the core.  The reader compares the rows it fetches with its key.
Synthetic, nonpayment, non-PHI, activation=false. -/

namespace BlindLedger.Gate.Engine3.CoreSum

open BlindLedger.Gate.Engine3.Index (wAt wSet zeros)

/-- A core of more rows than this is summarised. -/
def longMin : Nat := 32

def segRows : Nat := 8192

def lo40 : UInt64 := 0xFF_FFFF_FFFF
def mixBit : UInt64 := 0x8000_0000_0000_0000

structure Sum where
  /-- Rows that can be counted (row numbers below it). -/
  cap : Nat
  /-- The most entries each of the two tables may grow to (a power of two). -/
  slots : Nat
  seed : UInt64
  flg : Array ByteArray
  ex : ByteArray
  nr : ByteArray
  usedEx : Nat
  usedNr : Nat

/-- Entries of a table at its first insert (small, so that every run grows its tables: the doublings cost at most the final
    table's size again). -/
def startSlots : Nat := 4

/-- Countable rows and the most entries per table.  `RR_CORESUM_CAP=rows,slots` sets them (tests only; slots is rounded up
    to a power of two).  The default counts every row the first-row field holds (40 bits) in tables of at most 4M entries
    (96 MB each, reached only with 2M distinct keys of long cores in a set), and a bit per row. -/
def sizes : IO (Nat × Nat) := do
  let dflt := (lo40.toNat - 1, 1 <<< 22)
  let some v ← IO.getEnv "RR_CORESUM_CAP" | return dflt
  match (v.splitOn ",").map String.toNat? with
  | [some r, some s] => return (min r dflt.1, Nat.nextPowerOfTwo (max s 2))
  | _ => return dflt

def Sum.new : IO Sum := do
  let (cap, slots) ← sizes
  let b ← IO.getRandomBytes 8
  let seed := (List.range 8).foldl (fun a i => a ||| (b.get! i).toUInt64 <<< (8 * i).toUInt64) 0
  return ⟨cap, slots, seed, #[], .empty, .empty, 0, 0⟩

/-- Whether row `q`'s core is summarised up to `q`. -/
@[inline] def Sum.flagOf (s : @& Sum) (q : Nat) : Bool :=
  let b := s.flg.getD (q / segRows) .empty
  let i := q % segRows
  i / 8 < b.size && (b.get! (i / 8) >>> (i % 8).toUInt8) &&& 1 == 1

/-- Row `q` flagged. -/
def Sum.setFlag (s : Sum) (q : Nat) : Sum :=
  let ⟨cap, slots, seed, flg, ex, nr, ue, un⟩ := s
  let i := q / segRows
  let j := q % segRows
  let flg := if i < flg.size then flg else flg ++ Array.replicate (i + 1 - flg.size) ByteArray.empty
  let flg := flg.modify i fun b =>
    let b := if b.isEmpty then zeros (segRows / 8) else b
    b.set! (j / 8) (b.get! (j / 8) ||| ((1 : UInt8) <<< (j % 8).toUInt8))
  ⟨cap, slots, seed, flg, ex, nr, ue, un⟩

/-- What an entry holds: its first row, its count, its first row not identical to the first, and whether it is mixed. -/
structure Ent where
  first : Nat
  count : Nat
  diff : Option Nat
  mixed : Bool
  deriving Inhabited

/-- The table slot of digest word `h` (nonzero) in `t`: the slot holding it, or the first empty slot of its probe. -/
def slotOf (t : @& ByteArray) (m : Nat) (h : UInt64) : Nat × Bool := Id.run do
  let mut i := ((h ^^^ (h >>> 32)).toNat) &&& (m - 1)
  for _ in [0:m] do
    let w := wAt t (3 * i)
    if w == 0 then return (i, false)
    if w == h then return (i, true)
    i := (i + 1) &&& (m - 1)
  return (m, false)

@[inline] def nz (h : UInt64) : UInt64 := if h == 0 then 1 else h

def entAt (t : @& ByteArray) (i : Nat) : Ent :=
  let w1 := wAt t (3 * i + 1)
  let w2 := wAt t (3 * i + 2)
  ⟨(w1 &&& lo40).toNat - 1, ((w1 >>> 40) &&& 0xFFFF).toNat, if w2 == 0 then none else some (w2.toNat - 1), w1 &&& mixBit != 0⟩

/-- The entry of digest word `h` in the exact (`near` false) or near table, with its slot. -/
def Sum.find (s : @& Sum) (near : Bool) (h : UInt64) : Option (Nat × Ent) :=
  let t := if near then s.nr else s.ex
  if t.isEmpty then none
  else match slotOf t (t.size / 24) (nz h) with
    | (i, true) => some (i, entAt t i)
    | _ => none

/-- The entries of table `t` (`m` slots) in a table of `2 m` slots. -/
def grow (t : @& ByteArray) (m : Nat) : ByteArray := Id.run do
  let mut u := zeros (48 * m)
  for i in [0:m] do
    let h := wAt t (3 * i)
    if h != 0 then
      let j := (slotOf u (2 * m) h).1
      u := wSet (wSet (wSet u (3 * j) h) (3 * j + 1) (wAt t (3 * i + 1))) (3 * j + 2) (wAt t (3 * i + 2))
  return u

/-- Table `t` (`used` entries; at most `slots`) with a new entry for `h` whose first row is `q`: doubled first when the
    entry would fill it past half; false when even the largest table would be. -/
def insertIn (slots : Nat) (t : ByteArray) (used : Nat) (h : UInt64) (q : Nat) : ByteArray × Nat × Bool := Id.run do
  let mut t := if t.isEmpty then zeros (24 * min startSlots slots) else t
  let mut m := t.size / 24
  while 2 * (used + 1) > m && 2 * m ≤ slots do
    t := grow t m
    m := 2 * m
  if 2 * (used + 1) > m then return (t, used, false)
  match slotOf t m h with
  | (i, false) =>
    if i ≥ m then return (t, used, false)
    return (wSet (wSet t (3 * i) h) (3 * i + 1) ((q + 1).toUInt64 ||| ((1 : UInt64) <<< 40)), used + 1, true)
  | _ => return (t, used, false)

/-- Row `q`, the first of its key, as a new entry of `h` (false, and nothing changed, when it cannot be). -/
def Sum.insert (s : Sum) (near : Bool) (h : UInt64) (q : Nat) : Sum × Bool :=
  let ⟨cap, slots, seed, flg, ex, nr, ue, un⟩ := s
  if q ≥ cap then (⟨cap, slots, seed, flg, ex, nr, ue, un⟩, false)
  else if near then
    let (nr, un, ok) := insertIn slots nr un (nz h) q
    (⟨cap, slots, seed, flg, ex, nr, ue, un⟩, ok)
  else
    let (ex, ue, ok) := insertIn slots ex ue (nz h) q
    (⟨cap, slots, seed, flg, ex, nr, ue, un⟩, ok)

/-- Entry `i` of table `t`: counted once more and, when `d` is a row and the entry has none yet, `d` its first row not
    identical to the first; or marked mixed (`mix`). -/
def bumpIn (t : ByteArray) (i : Nat) (d : Option Nat) (mix : Bool) : ByteArray :=
  let w1 := wAt t (3 * i + 1)
  if mix then wSet t (3 * i + 1) (w1 ||| mixBit)
  else
    let t := wSet t (3 * i + 1) (w1 + ((1 : UInt64) <<< 40))
    match d with
    | some q => if wAt t (3 * i + 2) == 0 then wSet t (3 * i + 2) (q + 1).toUInt64 else t
    | none => t

/-- Entry `i` of the exact or near table bumped (`bumpIn`). -/
def Sum.bump (s : Sum) (near : Bool) (i : Nat) (d : Option Nat) (mix : Bool) : Sum :=
  let ⟨cap, slots, seed, flg, ex, nr, ue, un⟩ := s
  if near then ⟨cap, slots, seed, flg, ex, bumpIn nr i d mix, ue, un⟩
  else ⟨cap, slots, seed, flg, bumpIn ex i d mix, nr, ue, un⟩

end BlindLedger.Gate.Engine3.CoreSum
