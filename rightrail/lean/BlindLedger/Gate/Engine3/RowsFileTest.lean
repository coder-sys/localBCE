import BlindLedger.Gate.Engine3.RowsFile

/-! Test-only: `rows_test DIR` exercises the rows file in the empty directory DIR: append and fetch of 2000 records,
    reopen, a torn tail (a partial record), a cut to what the log confirms, and a read past the end.  Prints ROWS_OK. -/

open BlindLedger.Gate.Engine3.RowsFile
open BlindLedger.Gate.Flat.Io

def rec (i : Nat) : ByteArray :=
  mkRecord (ByteArray.mk ((Array.range 245).map fun j => ((i * 31 + j) % 256).toUInt8)) (i * 1000003 % 1099511627776)
    (i % 70000) (i % 4).toUInt8

def main (args : List String) : IO UInt32 := do
  let [dir] := args | IO.eprintln "usage: rows_test DIR"; return 2
  IO.FS.createDirAll dir
  let path := dir ++ "/rows.bin"
  let mut bad := 0
  let mut r ← «open» path none
  let mut batch := ByteArray.empty
  for i in [0:2000] do batch := batch ++ rec i
  r ← r.append batch
  r.sync
  r.close
  -- reopen, all there, fields round-trip
  r ← «open» path none
  if r.n != 2000 then bad := bad + 1
  let all ← r.fetch 0 2000
  if all != batch then bad := bad + 1
  for i in [0:2000] do
    if prevCoreAt all i != i * 1000003 % 1099511627776 then bad := bad + 1
    if countAt all i != min (i % 70000) 65535 then bad := bad + 1
    if flagsAt all i != (i % 4).toUInt8 then bad := bad + 1
  let two ← r.fetchMany (ByteArray.mk #[5,0,0,0,0,0,0,0, 0xCF,0x07,0,0,0,0,0,0]) 2
  if two != rec 5 ++ rec 1999 then bad := bad + 1
  -- a read past the end is an error
  let past ← (r.fetch 1999 2).toBaseIO
  if past.toOption.isSome then bad := bad + 1
  -- a torn tail: 100 stray bytes after the last record are cut on open
  let _ ← pgWrite r.fd (recW * 2000).toUInt64 (ByteArray.mk (Array.replicate 100 7))
  r.close
  r ← «open» path none
  if r.n != 2000 then bad := bad + 1
  r.close
  -- the log confirms only 1500
  r ← «open» path (some 1500)
  if r.n != 1500 then bad := bad + 1
  r.close
  r ← «open» path none
  if r.n != 1500 then bad := bad + 1
  if (← r.fetch 1499) != rec 1499 then bad := bad + 1
  -- append goes on from 1500
  r ← r.append (rec 1500)
  if (← r.fetch 1500) != rec 1500 || r.n != 1501 then bad := bad + 1
  r.close
  IO.println (if bad == 0 then "ROWS_OK" else s!"ROWS_FAIL {bad}")
  return if bad == 0 then 0 else 1
