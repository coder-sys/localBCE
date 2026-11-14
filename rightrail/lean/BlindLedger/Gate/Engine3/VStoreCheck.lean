import BlindLedger.Gate.Engine3.VStore

/-! `vstore_check DIR`: tests of the checker's tagged rows file (VStore.lean) with a fixed test key, and of its key file
    (DPAPI).  Prints `N checks, F failures`; exit 0 only with no failure.  Test only. -/

open BlindLedger.Gate.Engine3 BlindLedger.Gate.Flat

def row (i : Nat) : ByteArray := Id.run do
  let mut b := ByteArray.empty
  for j in [0:256] do b := b.push (UInt8.ofNat (i * 31 + j * 7 + i / 5))
  pure b

def rows (lo cnt : Nat) : ByteArray := Id.run do
  let mut b := ByteArray.emptyWithCapacity (256 * cnt)
  for i in [lo:lo + cnt] do b := b ++ row i
  pure b

def noEach (_ : Nat → IO (Option ByteArray)) (u : Unit) (_ : ByteArray) (_ _ : Nat) : IO Unit := pure u

def openPlain (path : String) (k : ByteArray) (shard set : Nat) : IO (Except String VStore.T) :=
  return (← VStore.openAt path k shard set () noEach).map (·.1)

/-- `vstore_check DIR time`: nanoseconds per record of the tag, a batch append, the open (which checks every record)
    and a cold fetch. -/
def timeIt (dir : String) : IO UInt32 := do
  let k := ByteArray.mk (Array.range 32 |>.map UInt8.ofNat)
  let n := 20000
  let pre := VStore.preOf k 0 0
  let all := rows 0 n
  let mut acc := 0
  let t0 ← IO.monoNanosNow
  for i in [0:n] do acc := acc + (VStore.tagInto ByteArray.empty pre all (256 * i) i)[0]!.toNat
  let t1 ← IO.monoNanosNow
  let .ok b0 ← openPlain s!"{dir}/vtime" k 0 0 | return 1
  let mut b := b0
  for j in [0:n / 2000] do b ← VStore.appendMany b (all.extract (256 * 2000 * j) (256 * 2000 * (j + 1)))
  let t2 ← IO.monoNanosNow
  VStore.close b
  let .ok c ← openPlain s!"{dir}/vtime" k 0 0 | return 1
  let t3 ← IO.monoNanosNow
  for i in [0:n] do acc := acc + ((← VStore.fetch c i).map (·.size)).getD 0
  let t4 ← IO.monoNanosNow
  VStore.close c
  IO.println s!"ns per record: tag {(t1 - t0) / n} batch of 2000 append {(t2 - t1) / n} open (checks all) {(t3 - t2) / n} fetch cold {(t4 - t3) / n} ({acc})"
  return 0

def main (args : List String) : IO UInt32 := do
  let some dir := args.head? | return 64
  if args.tail == ["time"] then return ← timeIt dir
  let k := ByteArray.mk (Array.range 32 |>.map UInt8.ofNat)
  let k2 := k.set! 0 99
  let ok ← IO.mkRef (0 : Nat)
  let bad ← IO.mkRef (0 : Nat)
  let chk (name : String) (b : Bool) : IO Unit := do
    ok.modify (· + 1)
    if !b then bad.modify (· + 1); IO.println s!"FAIL {name}"
  -- pure: the in-place tag is the definition, and it names the key, shard, set and place
  let pre := VStore.preOf k 3 1
  let s5 := VStore.packInto ByteArray.empty pre (row 1) 0 5
  chk "size" (s5.size == 320 && s5.extract 0 256 == row 1)
  chk "tag is the definition" (s5.extract 256 320 == VStore.tagOf k 3 1 5 (row 1))
  chk "in-place tag at an offset" (VStore.tagInto ByteArray.empty pre (rows 0 3) 512 5 == VStore.tagOf k 3 1 5 (row 2))
  chk "holds" (VStore.holds pre s5 0 5)
  chk "wrong place" (!VStore.holds pre s5 0 6)
  chk "wrong key" (!VStore.holds (VStore.preOf k2 3 1) s5 0 5)
  chk "wrong shard" (!VStore.holds (VStore.preOf k 4 1) s5 0 5)
  chk "wrong set" (!VStore.holds (VStore.preOf k 3 0) s5 0 5)
  chk "short" (!VStore.holds pre (s5.extract 0 319) 0 5)
  let mut flips := 0
  for i in [0:320] do
    if !VStore.holds pre (s5.set! i (s5[i]! ^^^ 1)) 0 5 then flips := flips + 1
  chk "every flipped byte refused" (flips == 320)
  -- file
  let path := s!"{dir}/vrows"
  let .ok a0 ← openPlain path k 0 0 | chk "open" false; return 1
  chk "new file empty" (a0.n == 0 && a0.cut == 0)
  let mut m := a0
  for i in [0:1000] do m ← VStore.appendMany m (row i)
  chk "appended" (m.n == 1000)
  let mut all := true
  for i in [0:1000] do all := all && (← VStore.fetch m i) == some (row i)
  chk "fetch every place" all
  chk "fetch past the end" (← VStore.fetch m 1000).isNone
  chk "a record size that is not whole refused" (← (do let _ ← VStore.appendMany m ((row 0).extract 0 255); pure false) <|> pure true)
  VStore.close m
  -- restart: every record goes through the fold once, in order, and every fetch is a cold read
  let .ok (t, seen) ← VStore.openAt path k 0 0 (0, true) (fun _ (c, good) blk i seq =>
      pure (c + 1, good && seq == c && blk.extract (320 * i) (320 * i + 256) == row seq)) | chk "reopen" false; return 1
  chk "restart keeps all" (t.n == 1000 && t.cut == 0 && seen == (1000, true))
  chk "restart fetch" ((← VStore.fetch t 999) == some (row 999) && (← VStore.fetch t 0) == some (row 0))
  -- the one-call read equals the two-call read over random places and lengths, past the end included
  let mut x : UInt64 := 12345
  let mut same := true
  for _ in [0:500] do
    x := x * 6364136223846793005 + 1442695040888963407
    let off := (x >>> 33) % (320 * 1000 + 700)
    x := x * 6364136223846793005 + 1442695040888963407
    let len := ((x >>> 33) % 1000).toUSize
    same := same && (← Io.pgReadAt t.fd off len) == (← Io.pgRead t.fd off len)
  chk "pgReadAt equals pgRead" same
  -- a tampered body byte at 700 and a tampered tag byte at 400 are refused where they lie
  let w (off : Nat) (v : UInt8) : IO Unit := do let _ ← Io.pgWrite t.fd off.toUInt64 (ByteArray.mk #[v]); pure ()
  let r1 ← Io.pgRead t.fd (320 * 700 + 9).toUInt64 1
  w (320 * 700 + 9) (r1[0]! ^^^ 4)
  let r2 ← Io.pgRead t.fd (320 * 400 + 300).toUInt64 1
  w (320 * 400 + 300) (r2[0]! ^^^ 128)
  let r3 ← Io.pgRead t.fd (320 * 800 + 250).toUInt64 1
  w (320 * 800 + 250) (r3[0]! ^^^ 2)
  chk "tampered row refused" (← VStore.fetch t 700).isNone
  chk "tampered tag refused" (← VStore.fetch t 400).isNone
  chk "tampered link refused" (← VStore.fetch t 800).isNone
  chk "neighbours fine" ((← VStore.fetch t 699) == some (row 699) && (← VStore.fetch t 401) == some (row 401))
  VStore.close t
  -- reopen cuts back to the last good record before the first bad one (place 400)
  let .ok t ← openPlain path k 0 0 | chk "reopen2" false; return 1
  chk "cut at first bad record" (t.n == 400 && t.cut == 320 * 600)
  VStore.close t
  chk "file is that long" ((← System.FilePath.metadata path).byteSize.toNat == 320 * 400)
  -- a wrong key, another shard or another set reads nothing
  let .ok tw ← openPlain path k2 0 0 | chk "reopen wrong key" false; return 1
  chk "wrong key cuts all" (tw.n == 0)
  VStore.close tw
  let ps := s!"{dir}/vrows4"
  let .ok q0 ← openPlain ps k 0 0 | chk "open4" false; return 1
  VStore.close (← VStore.appendMany q0 (rows 0 10))
  let .ok q1 ← openPlain ps k 1 0 | chk "reopen other shard" false; return 1
  chk "other shard cuts all" (q1.n == 0)
  VStore.close (← VStore.appendMany q1 (rows 0 10))
  let .ok q2 ← openPlain ps k 1 1 | chk "reopen other set" false; return 1
  chk "other set cuts all" (q2.n == 0)
  VStore.close q2
  -- the memory ring: a first batch larger than it, then batches that wrap it; every place agrees with what was appended
  let base := (Array.range 4099).map row
  let p3 := s!"{dir}/vrows3"
  let .ok r0 ← openPlain p3 k 0 0 | chk "open3" false; return 1
  let mut rg := r0
  for cnt in [70000, 40000, 40000, 1, 40000] do
    let mut batch := ByteArray.emptyWithCapacity (256 * cnt)
    for i in [0:cnt] do batch := batch ++ base[(rg.n + i) % 4099]!
    rg ← VStore.appendMany rg batch
  chk "ring appended" (rg.n == 190001)
  let mut ringOk := true
  for q in [rg.n - VStore.cacheRows - 3:rg.n] do ringOk := ringOk && (← VStore.fetch rg q) == some base[q % 4099]!
  for q in [0:50] do ringOk := ringOk && (← VStore.fetch rg (q * 3001)) == some base[(q * 3001) % 4099]!
  chk "ring fetch" ringOk
  VStore.close rg
  -- a torn tail: ten records, then half of an eleventh
  let p2 := s!"{dir}/vrows2"
  let pre0 := VStore.preOf k 0 0
  let .ok b0 ← openPlain p2 k 0 0 | chk "open2" false; return 1
  let m2 ← VStore.appendMany b0 (rows 0 10)
  let half := VStore.packInto ByteArray.empty pre0 (row 10) 0 10
  let _ ← Io.pgWrite m2.fd (320 * 10).toUInt64 (half.extract 0 150)
  VStore.close m2
  let .ok t ← openPlain p2 k 0 0 | chk "reopen torn" false; return 1
  chk "torn tail cut" (t.n == 10 && t.cut == 150 && (← VStore.fetch t 9) == some (row 9))
  -- a record moved to another place is refused
  let _ ← Io.pgWrite t.fd (320 * 7).toUInt64 (VStore.packInto ByteArray.empty pre0 (row 3) 0 3)
  chk "moved record refused" (← VStore.fetch t 7).isNone
  VStore.close t
  -- the key file: sealed for this user, opened again, and refused when changed or missing
  let kp := s!"{dir}/vkey"
  chk "no key file" (← VStore.loadKey kp).isNone
  let nk ← VStore.newKey kp
  let raw ← IO.FS.readBinFile kp
  chk "key sealed, not stored plain" (nk.size == 32 && raw.size > 32 && (List.range (raw.size - 31)).all fun i => raw.extract i (i + 32) != nk)
  chk "key opens" ((← VStore.loadKey kp) == some nk)
  let nk2 ← VStore.newKey kp
  chk "a new key replaces it" (nk2 != nk && (← VStore.loadKey kp) == some nk2)
  IO.FS.writeBinFile kp (raw.set! (raw.size - 1) (raw[raw.size - 1]! ^^^ 1))
  chk "changed key file refused" (← VStore.loadKey kp).isNone
  let n ← ok.get
  let f ← bad.get
  IO.println s!"{n} checks, {f} failures"
  return if f == 0 then 0 else 1
