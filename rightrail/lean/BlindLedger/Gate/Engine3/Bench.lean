import BlindLedger.Gate.Engine3.Keys
import BlindLedger.Gate.Engine3.Sha3Short
import BlindLedger.Gate.Engine3.Sha3Range
import BlindLedger.Gate.Engine3.ReadB
import BlindLedger.Gate.Engine3.Chunk
import BlindLedger.Gate.Engine3.Frame3
import BlindLedger.Gate.Engine3.Step
import BlindLedger.Gate.Engine3.Index
import BlindLedger.Gate.Flat.Worker

/-! Test-only checks of the key digests and the hashes (`key`, `sha3`, `hb`, `kat`: tests/test_sha3_known_answers.py) and of the
    batch's entry slots against the model (`puts`: tests/test_engine3_recovery.py), and the memory of the links files' head
    tables (`links-mem M P`: two tables of `M` members and four of `P` providers, as `Engine3/HLinks.lean` fills them).  Not
    part of the engine. -/

open BlindLedger.Gate.Engine3
open BlindLedger.Gate.Flat.Store
open Std (HashMap)

@[inline] def mix (x : UInt64) : UInt64 :=
  let z := x + 0x9E3779B97F4A7C15
  let z := (z ^^^ (z >>> 30)) * 0xBF58476D1CE4E5B9
  let z := (z ^^^ (z >>> 27)) * 0x94D049BB133111EB
  z ^^^ (z >>> 31)

open BlindLedger.Gate.Rules BlindLedger.Gate.Flat in
def khT (kb : List UInt8) : UInt64 := kb.foldl (fun a x => mix (a ^^^ x.toUInt64)) 7
open BlindLedger.Gate.Rules BlindLedger.Gate.Flat in
def uniKey (i : Nat) : BlindLedger.Gate.Bytes × Line :=
  let r := (i * 16 + 5).toUInt64
  let cap := i % 4 == 0
  let l : Line := ⟨2 ^ 256 + (mix r).toNat, (mix (r + 1)).toNat % 2 ^ 40, if cap then .CAP_820 else .FFS_CLAIM,
    2 ^ 256 + (mix (r + 2)).toNat, (mix (r + 3)).toNat % 2 ^ 20, (mix (r + 4)).toNat % 2 ^ 20, (mix (r + 5)).toNat % 2 ^ 30,
    (mix (r + 6)).toNat % 2 ^ 30, (mix (r + 7)).toNat % 2 ^ 20, (mix (r + 8)).toNat⟩
  (sk (i % 2 == 0) ([exactKey l, nearKey l, idKey l][i % 3]!), l)

open BlindLedger.Gate.Rules BlindLedger.Gate.Flat in
/-- The batch's entry slots (`ReadB.entryB`) against the model: an entry of 0, 3, 1,020, 1,024 or 1,030 postings gains
    1, 7 or 40 rows (all of a batch's rows, or every other one); its slots must be `putEntry` of the entry
    `EntryA.push` gives, byte for byte. -/
def putsRun : IO Bool := do
  let mut bad := 0
  let mut cases := 0
  for i in [0:24] do
    let (kb, l) := uniKey i
    let kh := khT kb
    let fl : UInt8 := ((kb.getD 1 (0 : UInt8)) &&& (7 : UInt8)) ||| (((kb.headD (0 : UInt8)) &&& (1 : UInt8)) <<< (3 : UInt8))
    for cnt in [0, 3, 1020, 1024, 1030] do
      let hd := (List.range (min cnt capN)).map fun j => (⟨j * 3 + 1, { l with pay := l.pay + j }⟩ : Posting)
      let tl := if capN < cnt then (List.range 64).map fun j => (mix (i.toUInt64 + j.toUInt64 * 31)).toUInt8
        else BlindLedger.Gate.zeroDigest
      let old : Entry := ⟨cnt, hd, tl⟩
      for m in [1, 7, 40] do
        let ls := (Array.range m).map fun k => { l with pay := l.pay + 5000 + k, units := l.units + k }
        let lb := ls.foldl putLine ByteArray.empty
        for every in [1, 2] do
          let adds := (Array.range m).filter (· % every == 0)
          let en := adds.foldl (fun e k => e.push Worker.H ⟨9000 + k, ls.getD k l⟩) old.toA
          let want := putEntry .empty kh kb en.toEntry
          cases := cases + 1
          if ReadB.entryB (putEntry .empty kh kb old) cnt kh fl lb (Array.range m) 9000 adds != some want then
            bad := bad + 1
  IO.println s!"entry slots of a batch vs the model: {bad} mismatches over {cases} cases"
  return bad == 0

def main (args : List String) : IO UInt32 := do
  match args with
  | ["key", dir] =>
    -- init writes 32 bytes; load reads them back; a second init refuses; a short file is refused
    let sec ← initKey dir
    let back ← readKey dir
    let again ← (initKey dir).toBaseIO
    IO.FS.writeBinFile s!"{dir}/short" (ByteArray.mk #[1, 2, 3])
    IO.FS.writeBinFile s!"{dir}/key" (ByteArray.mk #[1, 2, 3])
    let bad ← readKey dir
    let good := sec.size == 32 && back.toOption == some sec && again.toOption.isNone && bad.toOption.isNone
    -- digest words
    let kd := keyDigest sec (ByteArray.mk #[1, 2, 3])
    IO.println s!"key init/read/refuse/short: {good}; digest size {kd.size} dh {dhAt kd false} {dhAt kd true}"
    return if good && kd.size == 32 then 0 else 1
  | ["sha3", n] =>
    let n := n.toNat!
    let sec := ByteArray.mk ((Array.range 32).map fun i => (mix i.toUInt64).toUInt8)
    let c := KeyCtx.ofSecret sec
    -- equality with the SHA3-256 of the joined message, every length, many contents
    let mut bad := 0
    for len in [0:shortMax + 1] do
      for r in [0:200] do
        let kb := ByteArray.mk ((Array.range len).map fun i => (mix (i + 1000 * r + 7 * len).toUInt64).toUInt8)
        if keyDigestFast c kb != keyDigest sec kb then bad := bad + 1
        let s := keyState c kb
        let kd := keyDigest sec kb
        if khSt s false != khAt kd false || khSt s true != khAt kd true || dhSt s false != dhAt kd false ||
           dhSt s true != dhAt kd true then bad := bad + 1
    IO.println s!"sha3 short vs Sha3Quick: {bad} mismatches over {(shortMax + 1) * 200} messages"
    -- timing, 65 key bytes (an exact key)
    let kbs : Array ByteArray := (Array.range 256).map fun r => ByteArray.mk ((Array.range 65).map fun i => (mix (i + 100 * r).toUInt64).toUInt8)
    let t0 ← IO.monoNanosNow
    let mut acc : UInt64 := 0
    for i in [0:n] do
      acc := acc + dhAt (keyDigest sec kbs[i % 256]!) false
    let t1 ← IO.monoNanosNow
    for i in [0:n] do
      acc := acc + dhSt (keyState c kbs[i % 256]!) false
    let t2 ← IO.monoNanosNow
    let mut st := BlindLedger.Semantic.Quick.flipped
    for _ in [0:n] do
      st := BlindLedger.Semantic.Quick.keccakF st
    let t3 ← IO.monoNanosNow
    let per (a b : Nat) := (b - a).toFloat / n.toFloat / 1000
    IO.println s!"us per call: old keyDigest {per t0 t1}; keyState {per t1 t2}; bare permutation {per t2 t3} (acc {acc % 2} {st.a0 % 2})"
    return if bad == 0 then 0 else 1
  | ["sha3_512", n] =>
    let n := n.toNat!
    let src := ByteArray.mk ((Array.range 5000).map fun i => (mix i.toUInt64).toUInt8)
    -- equality with sha3_512Quick of the joined message: prefixes 0 to 80 bytes, ranges 0 to 300 bytes at 3 offsets, and long ranges
    let mut bad := 0
    let mut cnt := 0
    for p in [0:81] do
      let pre := src.extract 4000 (4000 + p)
      for len in ([0:301].toList ++ [1056, 4096]) do
        for off in [0, 1, 7] do
          cnt := cnt + 1
          let acc := src.extract 0 (p % 5)
          if sha3_512Into acc pre src off len != acc ++ BlindLedger.Semantic.sha3_512Quick (pre ++ src.extract off (off + len)) then
            bad := bad + 1
    -- FIPS 202 vectors: SHA3-512 of "" and of "abc" (whole, and split as "ab" before the range "c")
    let hx (b : ByteArray) : String :=
      String.join (b.toList.map fun x => let h := Nat.toDigits 16 x.toNat; String.ofList (if h.length < 2 then '0' :: h else h))
    let abc := "abc".toUTF8
    let v0 := "a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a615b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26"
    let v1 := "b751850b1a57168a5693cd924b6b096e08f621827444f70d884f5d0240d2712e10e116e9192af3c91a7ec57647e3934057340b4cf408d5a56592f8274eec53f0"
    if hx (sha3_512Into ByteArray.empty ByteArray.empty src 0 0) != v0 then bad := bad + 1
    if hx (sha3_512Into ByteArray.empty ByteArray.empty abc 0 3) != v1 then bad := bad + 1
    if hx (sha3_512Into ByteArray.empty (abc.extract 0 2) abc 2 1) != v1 then bad := bad + 1
    IO.println s!"sha3_512Into vs sha3_512Quick and FIPS 202: {bad} mismatches over {cnt} messages and 3 vectors"
    -- ns per call, least of 20 rounds of n calls, both ways interleaved: a 24-byte domain and a range of 0, 229, 1032 or 4072 bytes
    let dom := domB "STORE/BLOCK2"
    let per (a b : Nat) := (b - a).toFloat / n.toFloat
    let mut rows : List (Nat × Float) := []
    for len in [0, 221, 1032, 4072] do
      let mut old := 1e18
      let mut new := 1e18
      let mut acc : UInt8 := 0
      for _ in [0:20] do
        let t0 ← IO.monoNanosNow
        for i in [0:n] do
          acc := acc + (BlindLedger.Semantic.sha3_512Quick (dom ++ src.extract (i % 64) (i % 64 + len)))[0]!
        let t1 ← IO.monoNanosNow
        for i in [0:n] do
          acc := acc + (sha3_512Into ByteArray.empty dom src (i % 64) len)[0]!
        let t2 ← IO.monoNanosNow
        old := min old (per t0 t1)
        new := min new (per t1 t2)
      IO.println s!"SHA3-512 of {dom.size} + {len} bytes, ns per call: joined {old}; range {new} (acc {acc % 2})"
      rows := rows ++ [((dom.size + len) / 72 + 1, new)]
    let mut st := BlindLedger.Semantic.Quick.flipped
    let mut perm := 1e18
    for _ in [0:20] do
      let t0 ← IO.monoNanosNow
      for _ in [0:n] do
        st := BlindLedger.Semantic.Quick.keccakF st
      let t1 ← IO.monoNanosNow
      perm := min perm (per t0 t1)
    let mut sa := BlindLedger.Semantic.Quick.flipped
    let mut permA := 1e18
    for _ in [0:20] do
      let t0 ← IO.monoNanosNow
      for _ in [0:n] do
        sa := BlindLedger.Semantic.Lanes.permA sa.a0 sa.a1 sa.a2 sa.a3 sa.a4 sa.a5 sa.a6 sa.a7 sa.a8 sa.a9 sa.a10 sa.a11 sa.a12
          sa.a13 sa.a14 sa.a15 sa.a16 sa.a17 sa.a18 sa.a19 sa.a20 sa.a21 sa.a22 sa.a23 sa.a24
      let t1 ← IO.monoNanosNow
      permA := min permA (per t0 t1)
    for (b, t) in rows do
      IO.println s!"{b} perms: ns per call minus {b} x faster permutation = {t - b.toFloat * permA}"
    IO.println s!"bare permutation ns: {perm} ({st.a0 % 2}); faster permutation ns: {permA} ({sa.a0 % 2})"
    return if bad == 0 then 0 else 1
  | ["hb", n] =>
    -- `Bin.HB` against `sha3_512Quick` over every length 0 to 4096 (all rate boundaries), `n` random messages each, and two FIPS 202 vectors
    let mut bad := 0
    let mut cnt := 0
    let mut seed : UInt64 := 12345
    for len in [0:4097] do
      for _ in [0:n.toNat!] do
        let m := ByteArray.mk ((Array.range len).map fun i => (mix (seed + i.toUInt64)).toUInt8)
        seed := mix seed
        cnt := cnt + 1
        if BlindLedger.Gate.Flat.Bin.HB m != BlindLedger.Semantic.sha3_512Quick m then bad := bad + 1
    let hx (b : ByteArray) : String :=
      String.join (b.toList.map fun x => let h := Nat.toDigits 16 x.toNat; String.ofList (if h.length < 2 then '0' :: h else h))
    if hx (BlindLedger.Gate.Flat.Bin.HB ByteArray.empty) != "a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a615b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26" then bad := bad + 1
    if hx (BlindLedger.Gate.Flat.Bin.HB "abc".toUTF8) != "b751850b1a57168a5693cd924b6b096e08f621827444f70d884f5d0240d2712e10e116e9192af3c91a7ec57647e3934057340b4cf408d5a56592f8274eec53f0" then bad := bad + 1
    IO.println s!"Bin.HB vs sha3_512Quick and FIPS 202: {bad} mismatches over {cnt} messages of lengths 0 to 4096 and 2 vectors"
    return if bad == 0 then 0 else 1
  | ["kat"] =>
    -- digests of messages given as hex on stdin, one request a line; `tests/test_sha3_known_answers.py` checks them against hashlib.
    --   s512 M | hb M | s256 M | key256 SEC KB | s512r PRE JUNK M (hash of PRE ++ M, M read from JUNK ++ M at an offset)
    let stdin ← IO.getStdin
    let hexv (c : Char) : UInt8 := if c.isDigit then (c.toNat - 48).toUInt8 else (c.toNat - 87).toUInt8
    let unhex (t : String) : ByteArray :=
      let cs := (if t == "-" then "" else t).toList.toArray
      ByteArray.mk ((Array.range (cs.size / 2)).map fun i => hexv cs[2 * i]! * 16 + hexv cs[2 * i + 1]!)
    let hx (b : ByteArray) : String :=
      String.join (b.toList.map fun x => let h := Nat.toDigits 16 x.toNat; String.ofList (if h.length < 2 then '0' :: h else h))
    repeat
      let line ← stdin.getLine
      if line.isEmpty then break
      -- fields are split on single spaces; `-` is an empty message
      let f := (line.trimAsciiEnd.toString.splitOn " ").toArray
      let m := unhex (f[1]!)
      match f[0]! with
      | "s512" => IO.println (hx (BlindLedger.Gate.Engine3.sha3_512Into ByteArray.empty ByteArray.empty m 0 m.size))
      | "hb" => IO.println (hx (BlindLedger.Gate.Flat.Bin.HB m))
      | "s256" => IO.println (hx (BlindLedger.Semantic.sha3_256Quick m))
      | "key256" =>
        IO.println (hx (keyDigestFast (KeyCtx.ofSecret m) (unhex f[2]!)))
      | "s512r" =>
        let src := unhex f[2]! ++ unhex f[3]!
        IO.println (hx (BlindLedger.Gate.Engine3.sha3_512Into ByteArray.empty m src (if f[2]! == "-" then 0 else f[2]!.length / 2) (if f[3]! == "-" then 0 else f[3]!.length / 2)))
      | _ => IO.println "?"
    return 0
  | ["puts"] => return if (← putsRun) then 0 else 1
  | ["links-mem", m, p] =>
    let (some m, some p) := (m.toNat?, p.toNat?) | return 2
    Run.lazyCommit
    let b0 ← Run.procMem 1
    let w (i : Nat) : UInt64 × UInt64 := (mix (2 * i).toUInt64, mix (2 * i + 1).toUInt64)
    let mut mr := Index.Idx.new 10
    let mut mu := Index.Idx.new 10
    for i in [0:m] do
      mr := mr.insert (w i).1 (w i).2 i
      mu := mu.insert (w i).1 (w i).2 i
    let mut pr := Index.Idx.new 10
    let mut pu := Index.Idx.new 10
    let mut rr := Index.Idx.new 10
    let mut ru := Index.Idx.new 10
    for i in [0:p] do
      let (h1, h2) := w (m + i)
      pr := pr.insert h1 h2 i
      pu := pu.insert h1 h2 i
      rr := rr.insert h1 h2 i
      ru := ru.insert h1 h2 i
    let b1 ← Run.procMem 2
    let gain (i : Nat) : Int := (getN b1 (8 * i) 8 : Int) - getN b0 (8 * i) 8
    let tm := mr.bytes + mu.bytes
    let tp := pr.bytes + pu.bytes + rr.bytes + ru.bytes
    IO.println s!"LINKS_MEM members {m} providers {p} table bytes members {tm} providers {tp} total {tm + tp}; bytes gained: private {gain 0} working set {gain 1} allocator committed {gain 2}"
    return 0
  | _ => IO.println "usage: engine3_bench key DIR | sha3 N | hb N | kat | puts | links-mem M P"; return 2
