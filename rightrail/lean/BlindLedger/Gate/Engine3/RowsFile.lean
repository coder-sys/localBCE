import BlindLedger.Gate.Flat.Io

/-! # Rows file (gate path design section 3.3)

One append-only file per row set.  Record `seq` is the 256 bytes at byte `256 * seq`:

| bytes | field |
|---|---|
| 0..244 | the 245-byte canonical row |
| 245..249 | `prevCore`, the sequence number of the previous row with the same core key (40 bits, little endian) |
| 250..251 | the number of rows of this core up to and including this one (16 bits, saturating) |
| 252 | flags: bit 0 claims its near key, bit 1 is a cap row |
| 253..255 | zero |

A set only grows, so a record never changes.  The file is a projection of the log: on open, a torn tail (a partial record,
or records the log does not confirm) is cut back and the log replays the rest.  Position reads and writes are the existing
page-file calls of `Flat.Io`, so this module adds nothing to the trusted base.

Open obligation, tested by `rows_test` (tests/test_rows_file.py): `open_cut` (after `open path (some k)` the file holds exactly the first
`min k n` whole records it held). -/

namespace BlindLedger.Gate.Engine3.RowsFile

open BlindLedger.Gate.Flat.Io

def recW : Nat := 256
def rowW : Nat := 245

structure Rows where
  fd : UInt32
  /-- Whole records in the file. -/
  n : Nat

/-- A record from a row (245 bytes), `prevCore` (below 2^40), the core count and the flags. -/
def mkRecord (row : ByteArray) (prevCore : Nat) (count : Nat) (flags : UInt8) : ByteArray := Id.run do
  let mut b := row.extract 0 rowW
  for i in [0:5] do b := b.push ((prevCore >>> (8 * i)) % 256).toUInt8
  let count := min count 65535
  b := b.push (count % 256).toUInt8
  b := b.push (count / 256).toUInt8
  b := b.push flags
  for _ in [0:3] do b := b.push 0
  return b

/-- Record `i` of the byte array `b` of records: its `prevCore`. -/
def prevCoreAt (b : @& ByteArray) (i : Nat) : Nat := Id.run do
  let mut v := 0
  for j in [0:5] do v := v ||| ((b.get! (recW * i + rowW + j)).toNat <<< (8 * j))
  return v

def countAt (b : @& ByteArray) (i : Nat) : Nat :=
  (b.get! (recW * i + 250)).toNat + 256 * (b.get! (recW * i + 251)).toNat

def flagsAt (b : @& ByteArray) (i : Nat) : UInt8 := b.get! (recW * i + 252)

/-- Opens (creating) the rows file.  A partial record at the end is cut; with `some k`, records from `k` on are cut too
    (the log confirms `k`). -/
def «open» (path : String) (keep : Option Nat) : IO Rows := do
  let fd ← pgOpen path
  if fd == 0xFFFFFFFF then throw (IO.userError s!"rows file {path}: open failed")
  let size := (← System.FilePath.metadata path).byteSize.toNat
  let n := match keep with
    | some k => min k (size / recW)
    | none => size / recW
  if size != n * recW then
    if (← pgTrunc fd (recW * n).toUInt64) != 0 then throw (IO.userError s!"rows file {path}: cut failed")
  return ⟨fd, n⟩

/-- `recs` (whole records) appended; the new record count is `n + recs.size / 256`.  Not durable until `sync`. -/
def Rows.append (r : Rows) (recs : ByteArray) : IO Rows := do
  if recs.size % recW != 0 then throw (IO.userError "rows file: append of a partial record")
  if (← pgWrite r.fd (recW * r.n).toUInt64 recs) != 0 then throw (IO.userError "rows file: write failed")
  return { r with n := r.n + recs.size / recW }

def Rows.sync (r : Rows) : IO Unit := do
  if (← pgSync r.fd) != 0 then throw (IO.userError "rows file: sync failed")

/-- Records `seq .. seq + cnt - 1`, 256 bytes each. -/
def Rows.fetch (r : Rows) (seq : Nat) (cnt : Nat := 1) : IO ByteArray := do
  if seq + cnt > r.n then throw (IO.userError s!"rows file: record {seq + cnt - 1} is beyond {r.n}")
  let b ← pgRead r.fd (recW * seq).toUInt64 (recW * cnt).toUSize
  if b.size != recW * cnt then throw (IO.userError "rows file: short read")
  return b

/-- The records at the positions listed as 40-bit-or-wider little endian words in `seqs` (8 bytes each), concatenated. -/
def Rows.fetchMany (r : Rows) (seqs : @& ByteArray) (count : Nat) : IO ByteArray := do
  let mut out := ByteArray.emptyWithCapacity (recW * count)
  for i in [0:count] do
    let mut s := 0
    for j in [0:8] do s := s ||| ((seqs.get! (8 * i + j)).toNat <<< (8 * j))
    out := out ++ (← r.fetch s)
  return out

def Rows.close (r : Rows) : IO Unit := do
  let _ ← pgClose r.fd
  pure ()

end BlindLedger.Gate.Engine3.RowsFile
