import BlindLedger.X12.R837
import BlindLedger.X12.Stream

/-! `x12_read`: the X12 reader as a program.  `x12_read KIND FILE [REPEAT [OUT]]` reads FILE as KIND (837), REPEAT times
    (default 1), prints the time of each read, and writes the output of the last to OUT when given.

    `x12_read stream FILE OUT` reads FILE as an 837 in units (`Stream.lean`) and writes the stream to OUT, which must
    not be FILE.  Two settings come from the environment, each a whole number: `X12LOW`, the least length of a unit in
    KiB (default 512), and `X12PAR`, how many units are read at once (default 1, at least 1).  The output does not
    depend on `X12PAR`. -/

open BlindLedger.X12

partial def segLoop (d : ByteArray) (i : Nat) (c : Nat) (mode : Nat) (sg : Seg) : Nat :=
  if i < d.size then
    let t := findB d 126 i d.size
    if mode == 1 then segLoop d (t + 1) (c + 1) mode sg
    else
      let s := skipSp d i t
      let e := backSp d s t
      if mode == 2 then segLoop d (t + 1) (c + e - s) mode sg
      else if mode == 7 then (let sg' := mkSeg d s e 42; let (a, b) := el d 58 sg' 3; segLoop d (t + 1) (c + a + b) mode sg')
      else if mode == 8 then (let sg' := mkSeg d s e 42; let (a, b) := elp d 58 sg' 1 2; segLoop d (t + 1) (c + a + b) mode sg')
      else if mode == 9 then segLoop d (t + 1) (c + (scaled d s e 2).isSome.toNat) mode sg
      else if mode == 10 then (let sg' := mkSeg d s e 42; segLoop d (t + 1) (c + nsub d 58 sg' 1) mode sg')
      else if mode == 11 then segLoop d (t + 1) (c + (date8 d s e)) mode sg
      else if mode == 5 then segLoop d (t + 1) (c + cntGo d 42 e s 0) mode sg
      else if mode == 6 then segLoop d (t + 1) (c + cntGo d 42 e s 0 + findB d 42 s e) mode sg
      else
        let sg' := mkSeg d s e 42
        if mode == 3 then segLoop d (t + 1) (c + sg'.idEnd) mode sg'
        else segLoop d (t + 1) (c + packId d s sg'.idEnd) mode sg'
  else c

def updLoop (i n mode : Nat) (s : S837) : S837 :=
  if i < n then
    if mode == 1 then updLoop (i + 1) n mode { s with clEnd := i, cl := true }
    else updLoop (i + 1) n mode { s with clEnd := i, l := { s.l with lnOffs := if i % 3 == 0 then #[i] else s.l.lnOffs.push i } }
  else s
termination_by n - i

def grpTxt : ByteArray := "LX*1~SV1*HC:99213*100*UN*1***1~DTP*472*D8*20260101~".toUTF8

def grpDl : Delims := { sep := 42, sub := 58, term := 126, rep := 256, control := 0, stampOk := true }

def grpCtx : SetCtx := { off := 0, control := 0, fileDate := 0, fileTime := 0, group := 0, ichg := 0 }

/-- The three segments of a service line, read `n` times by the set reader alone (no envelope); `mode` picks how many. -/
def grpLoop (i n mode : Nat) (s : S837) (o : Out) : S837 × Out :=
  if i < n then
    let d := grpTxt
    let a := mkSeg d 0 4 42
    let b := mkSeg d 5 30 42
    let c := mkSeg d 31 50 42
    let (s, o) := step837 d grpDl { a with s := a.s + i } grpCtx s o
    if mode == 1 then grpLoop (i + 1) n mode s o else
    let (s, o) := step837 d grpDl b grpCtx s o
    if mode == 2 then grpLoop (i + 1) n mode s o else
    let (s, o) := step837 d grpDl c grpCtx s o
    grpLoop (i + 1) n mode s o
  else (s, o)
termination_by n - i

/-- The file's segments straight to the 837 step, with no envelope. -/
partial def stepLoop (d : ByteArray) (i : Nat) (s : S837) (o : Out) : S837 × Out :=
  if i < d.size then
    let t := findB d 126 i d.size
    let s0 := skipSp d i t
    let e := backSp d s0 t
    let sg := mkSeg d s0 e 42
    let (s, o) := step837 d grpDl sg grpCtx s o
    stepLoop d (t + 1) s o
  else (s, o)

def clmTxt : ByteArray := "CLM*C0000001*200***11:B:1*Y*A*Y*Y~HI*ABK:E119~".toUTF8

/-- Claims: a CLM, an HI and `mode` line groups each, by the set reader alone. -/
def clmLoop (i n mode : Nat) (s : S837) (o : Out) : S837 × Out :=
  if i < n then
    let d := clmTxt
    let a := mkSeg d 0 33 42
    let b := mkSeg d 34 45 42
    let (s, o) := step837 d grpDl { a with s := a.s + i } grpCtx s o
    let (s, o) := step837 d grpDl b grpCtx s o
    if mode == 0 then clmLoop (i + 1) n mode s o else
    let g := grpTxt
    let (s, o) := step837 g grpDl (mkSeg g 0 4 42) grpCtx s o
    let (s, o) := step837 g grpDl (mkSeg g 5 30 42) grpCtx s o
    let (s, o) := step837 g grpDl (mkSeg g 31 50 42) grpCtx s o
    if mode == 1 then clmLoop (i + 1) n mode s o else
    let (s, o) := step837 g grpDl (mkSeg g 0 4 42) grpCtx s o
    let (s, o) := step837 g grpDl (mkSeg g 5 30 42) grpCtx s o
    let (s, o) := step837 g grpDl (mkSeg g 31 50 42) grpCtx s o
    clmLoop (i + 1) n mode s o
  else (s, o)
termination_by n - i

def clm0 : S837 := { billing := some { npi := 1, off := 1, n3 := 0, n4 := 0, n5 := 0 }, subOff := 5, subId := 1 }

def sbrTxt : ByteArray := "SBR*P*18*******CI".toUTF8

/-- One segment read over and over by the set reader alone, to see what a step costs. -/
def sbrLoop (d : ByteArray) (sg : Seg) (i n : Nat) (s : S837) (o : Out) : S837 × Out :=
  if i < n then
    let (s, o) := step837 d grpDl sg grpCtx s o
    sbrLoop d sg (i + 1) n s o
  else (s, o)
termination_by n - i

/-- `n` words written, to see what a word costs. -/
def wordLoop (i n : Nat) (o : Out) : Out :=
  if i < n then wordLoop (i + 1) n (o.w (i * 7919))
  else o
termination_by n - i

def rawLoop (i n : Nat) (b : ByteArray) : ByteArray :=
  if i < n then rawLoop (i + 1) n (setW b (i * 8) (i * 7919))
  else b
termination_by n - i

def nullRd : SetReader Unit where
  init := ()
  step _ _ _ _ s o := (s, o)
  finish _ _ _ _ o := o
  notCause := .not837

def hashRd : SetReader Nat where
  init := 0
  step d _ sg _ s o := (if isKnown837 (packId d sg.s sg.idEnd) then s + 1 else s, o)
  finish _ _ _ _ o := o
  notCause := .not837

/-- Gives the output a word per segment, to see what writing costs. -/
def wordRd : SetReader Nat where
  init := 0
  step _ _ sg _ s o := (s, o.w sg.s)
  finish _ _ _ _ o := o
  notCause := .not837

def onlyRd (ids : List Nat) : SetReader S837 where
  init := {}
  step d dl sg ctx s o := if ids.contains (packId d sg.s sg.idEnd) then step837 d dl sg ctx s o else (s, o)
  finish d _ ctx st o := (closeClaim d st o ctx.off).2
  notCause := .not837

def runKind (kind : String) (d : ByteArray) : Option ByteArray :=
  match kind with
  | "837" => some (readX12 (rd := reader837) "837".toUTF8 d)
  | "scan" => some (readX12 (rd := reader837) "999".toUTF8 d)
  | "ph1" => some (ByteArray.empty.push (segLoop d 0 0 1 {}).toUInt8)
  | "ph2" => some (ByteArray.empty.push (segLoop d 0 0 2 {}).toUInt8)
  | "ph3" => some (ByteArray.empty.push (segLoop d 0 0 3 {}).toUInt8)
  | "ph5" => some (ByteArray.empty.push (segLoop d 0 0 5 {}).toUInt8)
  | "ph6" => some (ByteArray.empty.push (segLoop d 0 0 6 {}).toUInt8)
  | "plain" => some (readX12 (rd := nullRd) "837".toUTF8 d)
  | "hash" => some (readX12 (rd := hashRd) "837".toUTF8 d)
  | "word" => some (readX12 (rd := wordRd) "837".toUTF8 d)
  | "oSV" => some (readX12 (rd := (onlyRd [idLX, idSV1])) "837".toUTF8 d)
  | "oDTP" => some (readX12 (rd := (onlyRd [idLX, idSV1, idDTP])) "837".toUTF8 d)
  | "oLX" => some (readX12 (rd := (onlyRd [idLX])) "837".toUTF8 d)
  | "oCL" => some (readX12 (rd := (onlyRd [idHL, idNM1, idSBR, idCLM, idHI])) "837".toUTF8 d)
  | "oHL" => some (readX12 (rd := (onlyRd [idHL])) "837".toUTF8 d)
  | "oNM" => some (readX12 (rd := (onlyRd [idNM1])) "837".toUTF8 d)
  | "oCLM" => some (readX12 (rd := (onlyRd [idCLM])) "837".toUTF8 d)
  | "oHI" => some (readX12 (rd := (onlyRd [idHI, idSBR])) "837".toUTF8 d)
  | "oLN" => some (readX12 (rd := (onlyRd [idCLM, idLX, idSV1])) "837".toUTF8 d)
  | "oLN2" => some (readX12 (rd := (onlyRd [idCLM, idLX, idSV1, idDTP])) "837".toUTF8 d)
  | "oALL" => some (readX12 (rd := (onlyRd [idCLM, idLX, idSV1, idDTP, idHL, idNM1])) "837".toUTF8 d)
  | "m7" => some (ByteArray.empty.push (segLoop d 0 0 7 {}).toUInt8)
  | "m8" => some (ByteArray.empty.push (segLoop d 0 0 8 {}).toUInt8)
  | "m9" => some (ByteArray.empty.push (segLoop d 0 0 9 {}).toUInt8)
  | "m10" => some (ByteArray.empty.push (segLoop d 0 0 10 {}).toUInt8)
  | "m11" => some (ByteArray.empty.push (segLoop d 0 0 11 {}).toUInt8)
  | "u1" => some (ByteArray.empty.push (updLoop 0 (d.size / 20) 1 {}).clEnd.toUInt8)
  | "u2" => some (ByteArray.empty.push (updLoop 0 (d.size / 20) 2 {}).clEnd.toUInt8)
  | "g1" => some (ByteArray.empty.push (grpLoop 0 100000 1 { cl := true, c := { clOffs := #[0] } } ({ ev := zeros 4096, len := 0, side := ByteArray.empty } : Out)).1.clEnd.toUInt8)
  | "g2" => some (ByteArray.empty.push (grpLoop 0 100000 2 { cl := true, c := { clOffs := #[0] } } ({ ev := zeros 4096, len := 0, side := ByteArray.empty } : Out)).1.clEnd.toUInt8)
  | "g3" => some (ByteArray.empty.push (grpLoop 0 100000 3 { cl := true, c := { clOffs := #[0] } } ({ ev := zeros 4096, len := 0, side := ByteArray.empty } : Out)).1.clEnd.toUInt8)
  | "st" => some (stepLoop d 0 {} ({ ev := zeros (d.size + 4096), len := 0, side := ByteArray.empty } : Out)).2.bytes
  | "c0" => some (ByteArray.empty.push (clmLoop 0 (d.size / 216) 0 clm0 ({ ev := zeros 4096, len := 0, side := ByteArray.empty } : Out)).1.clEnd.toUInt8)
  | "c1" => some (ByteArray.empty.push (clmLoop 0 (d.size / 216) 1 clm0 ({ ev := zeros 4096, len := 0, side := ByteArray.empty } : Out)).1.clEnd.toUInt8)
  | "c4" => some (ByteArray.empty.push (clmLoop 0 (d.size / 216) 4 clm0 ({ ev := zeros 4096, len := 0, side := ByteArray.empty } : Out)).1.clEnd.toUInt8)
  | "c2" => some (ByteArray.empty.push (clmLoop 0 (d.size / 216) 2 clm0 ({ ev := zeros 4096, len := 0, side := ByteArray.empty } : Out)).1.clEnd.toUInt8)
  | "sb" => some (ByteArray.empty.push (sbrLoop sbrTxt (mkSeg sbrTxt 0 sbrTxt.size 42) 0 (d.size / 20) { cl := true } ({ ev := zeros 4096, len := 0, side := ByteArray.empty } : Out)).1.clEnd.toUInt8)
  | "wl" => some (wordLoop 0 (d.size / 2) ({ ev := zeros 4096, len := 0, side := ByteArray.empty } : Out)).bytes
  | "wz" => some (zeros (d.size * 4 + 4096))
  | "wl2" => some (wordLoop 0 (d.size / 2) ({ ev := zeros (d.size * 4 + 4096), len := 0, side := ByteArray.empty } : Out)).bytes
  | "wb" => some (rawLoop 0 (d.size / 2) (zeros (d.size * 4 + 4096)))
  | "ph4" => some (ByteArray.empty.push (segLoop d 0 0 4 {}).toUInt8)
  | _ => none

def bucketOf (sid : Nat) : Nat :=
  if sid == idHL then 0 else if sid == idNM1 then 1 else if sid == idCLM then 2 else if sid == idHI then 3
  else if sid == idLX then 4 else if sid == idSV1 then 5 else if sid == idDTP then 6 else if sid == idSBR then 7 else 8

/-- Time of each kind of segment in the set reader alone: nanoseconds and counts. -/
partial def profLoop (d : ByteArray) (i : Nat) (s : S837) (o : Out) (ns cnt : Array Nat) : IO (Array Nat × Array Nat) := do
  if i < d.size then
    let t := findB d 126 i d.size
    let s0 := skipSp d i t
    let e := backSp d s0 t
    let sg := mkSeg d s0 e 42
    let b := bucketOf (packId d sg.s sg.idEnd)
    let t0 ← IO.monoNanosNow
    let (s, o) := step837 d grpDl sg grpCtx s o
    let t1 ← IO.monoNanosNow
    let t2 ← IO.monoNanosNow
    profLoop d (t + 1) s o ((ns.modify b (· + (t1 - t0))).modify 9 (· + (t2 - t1))) ((cnt.modify b (· + 1)).modify 9 (· + 1))
  else return (ns, cnt)

/-- A setting from the environment: `dflt` when unset, none when set to anything but a whole number. -/
def envNum (name : String) (dflt : Nat) : IO (Option Nat) := do
  match ← IO.getEnv name with
  | none => pure (some dflt)
  | some v => pure v.toNat?

def main (args : List String) : IO UInt32 := do
  match args with
  | kind :: file :: rest =>
    if kind == "stream" then
      let [outPath] := rest | do IO.eprintln "usage: x12_read stream FILE OUT"; return 2
      let some lowK ← envNum "X12LOW" 512 | do IO.eprintln "X12LOW must be a whole number of KiB"; return 2
      let some par ← envNum "X12PAR" 1 | do IO.eprintln "X12PAR must be a whole number"; return 2
      if par == 0 then
        IO.eprintln "X12PAR must be at least 1"
        return 2
      let inp ← IO.FS.Handle.mk file .read
      -- OUT is opened without emptying it, then locked for itself while FILE holds a shared lock: when both name one
      -- file (by any path or link) the lock is refused and FILE is left as it was
      let out ← IO.FS.Handle.mk outPath .append
      unless (← inp.tryLock (exclusive := false)) && (← out.tryLock) do
        IO.eprintln "OUT must not be FILE, and neither may be locked by another program"
        return 2
      out.rewind
      out.truncate
      let t0 ← IO.monoNanosNow
      streamX12 (σ := S837) "837".toUTF8 inp out 1048576 (lowK * 1024) par
      out.flush
      let t1 ← IO.monoNanosNow
      IO.println s!"kind=stream best_ns={t1 - t0}"
      return 0
    let d ← IO.FS.readBinFile file
    if kind == "prof" then
      let o : Out := { ev := zeros (d.size + 4096), len := 0, side := ByteArray.empty }
      let (ns, cnt) ← profLoop d 0 {} o (Array.replicate 10 0) (Array.replicate 10 0)
      let names := #["HL", "NM1", "CLM", "HI", "LX", "SV1", "DTP", "SBR", "other", "timer"]
      for k in [0:10] do
        IO.println s!"{names[k]!} count={cnt[k]!} total_ns={ns[k]!} per_call_ns={ns[k]! / (max 1 cnt[k]!)}"
      return 0
    let reps := (rest.head?.bind String.toNat?).getD 1
    let mut last : ByteArray := ByteArray.empty
    let mut best : Nat := 1000000000000
    for _ in [0:reps] do
      let t0 ← IO.monoNanosNow
      match runKind kind d with
      | some r => last := r
      | none => return 2
      let t1 ← IO.monoNanosNow
      best := min best (t1 - t0)
    IO.println s!"kind={kind} bytes={d.size} out={last.size} best_ns={best}"
    if let some out := rest.getLast? then
      if rest.length ≥ 2 then IO.FS.writeBinFile out last
    return 0
  | _ =>
    IO.eprintln "usage: x12_read KIND FILE [REPEAT [OUT]], or x12_read stream FILE OUT"
    return 2
