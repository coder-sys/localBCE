import BlindLedger.Gate.Flat.DecideRows
import BlindLedger.Gate.Engine3.Chunk

/-! The fixed-width decision layout (`Flat.Rows.Lay`) built straight from stored chunk rows and the key directory, with
    no `Line`, `Key` or `List` in between (conformance/ENGINE_V3.md section 12).

    Stages, each a function of arrays: `keysOf` (the three keys of every request row as store bytes, each distinct key
    once, with its two digests), `HistStore.probe` (directory, then the chunk's page fences and block fence, then the
    slots to the entry's first row; no hashing of blocks, as a read from the clean tier), `HistStore.decode` (an entry's
    rows read into `RowX`s), `round2Keys` (id keys of unresolved CAP rows of redone payments) and `assemble` (slots,
    feed facts, payments, lines).  `layoutStore` is their composition.

    It gives the `Lay` that `Flat.Rows.layout` gives over an index holding the same entries and the feeds of the decoded
    rows (`FeedsX`), with the same facts for every line; the feed fact arrays are the whole feeds' rather than one copy
    per id read, and `src`, `relSrc` and `unrSrc`, which are for `toRef` only, stay empty.  Checked, not proved, by
    `decide_bench rows` and `rowscheck`.
    Not modelled here: the open and sealing windows (the store is installed chunks only) and a failed block read.
    Test-only, nonpayment, non-PHI. -/

namespace BlindLedger.Gate.Engine3

open BlindLedger.Gate.Rules BlindLedger.Gate.Flat BlindLedger.Gate.Flat.Rows
open Std (HashMap HashSet)

/-- The stored row whose line starts at byte `o` of a chunk image, as words: what `RowX.of (getLine img o).get!` gives.
    A number whose width is not a whole number of words has its top word cut to its bytes. -/
def RowX.ofChunk (img : ByteArray) (o : Nat) : RowX :=
  ⟨ld64 img (o + 48) &&& 0xFFFFFF, ld64 img (o + 40), ld64 img (o + 32), ld64 img (o + 24), ld64 img (o + 16),
   ld64 img (o + 8), ld64 img o,
   ld64 img (o + 115), ld64 img (o + 107), ld64 img (o + 99), ld64 img (o + 91), ld64 img (o + 83), ld64 img (o + 75),
   ld64 img (o + 67), ld64 img (o + 59), ld64 img (o + 51),
   ld64 img (o + 148), ld64 img (o + 140), ld64 img (o + 132), ld64 img (o + 124),
   ld64 img (o + 172) &&& 0xFFFFFFFFFF, ld64 img (o + 164), ld64 img (o + 156),
   ld64 img (o + 193) &&& 0xFFFFFFFFFF, ld64 img (o + 185), ld64 img (o + 177),
   ld64 img (o + 226) &&& 0xFFFFFFFFFFFFFF, ld64 img (o + 218), ld64 img (o + 210), ld64 img (o + 202),
   ld64 img (o + 237), (ld64 img (o + 198)).toUInt32, (ld64 img (o + 233)).toUInt32, img[o + 123]!⟩

def put32u (b : ByteArray) (v : UInt32) : ByteArray :=
  b.push v.toUInt8 |>.push (v >>> 8).toUInt8 |>.push (v >>> 16).toUInt8 |>.push (v >>> 24).toUInt8

/-- Bytes in the minimal big-endian form of the nonzero word `w`. -/
@[inline] def beLen (w : UInt64) : Nat := w.log2.toNat / 8 + 1

@[inline] def be8 (b : ByteArray) (w : UInt64) : ByteArray :=
  b.push (w >>> 56).toUInt8 |>.push (w >>> 48).toUInt8 |>.push (w >>> 40).toUInt8 |>.push (w >>> 32).toUInt8
    |>.push (w >>> 24).toUInt8 |>.push (w >>> 16).toUInt8 |>.push (w >>> 8).toUInt8 |>.push w.toUInt8

/-- The byte count (`extra` for the words below `w`, then the bytes of `w`), then the minimal bytes of the top nonzero word. -/
@[inline] def beLead (b : ByteArray) (w : UInt64) (extra : Nat) : ByteArray := Id.run do
  let n := beLen w
  let mut b := b.push (extra + n).toUInt8
  for j in [0:n] do b := b.push (w >>> (8 * (n - 1 - j)).toUInt64).toUInt8
  return b

/-! An identifier field of `k` words (high first): its byte count, then its minimal big-endian bytes (`idField`).  One
    function per width, so no array of words is made. -/
def putBE1 (b : ByteArray) (w0 : UInt64) : ByteArray := if w0 != 0 then beLead b w0 0 else b.push 0
def putBE2 (b : ByteArray) (w0 w1 : UInt64) : ByteArray := if w0 != 0 then be8 (beLead b w0 8) w1 else putBE1 b w1
def putBE3 (b : ByteArray) (w0 w1 w2 : UInt64) : ByteArray :=
  if w0 != 0 then be8 (be8 (beLead b w0 16) w1) w2 else putBE2 b w1 w2
def putBE4 (b : ByteArray) (w0 w1 w2 w3 : UInt64) : ByteArray :=
  if w0 != 0 then be8 (be8 (be8 (beLead b w0 24) w1) w2) w3 else putBE3 b w1 w2 w3
def putBE5 (b : ByteArray) (w0 w1 w2 w3 w4 : UInt64) : ByteArray :=
  if w0 != 0 then be8 (be8 (be8 (be8 (beLead b w0 32) w1) w2) w3) w4 else putBE4 b w1 w2 w3 w4
def putBE6 (b : ByteArray) (w0 w1 w2 w3 w4 w5 : UInt64) : ByteArray :=
  if w0 != 0 then be8 (be8 (be8 (be8 (be8 (beLead b w0 40) w1) w2) w3) w4) w5 else putBE5 b w1 w2 w3 w4 w5
def putBE7 (b : ByteArray) (w0 w1 w2 w3 w4 w5 w6 : UInt64) : ByteArray :=
  if w0 != 0 then be8 (be8 (be8 (be8 (be8 (be8 (beLead b w0 48) w1) w2) w3) w4) w5) w6
  else putBE6 b w1 w2 w3 w4 w5 w6

/-- The stored key bytes (`kbytes`, without the set tag) of key `j` of the row: 0 exact, 1 near, 2 id. -/
def RowX.keyBytes (r : RowX) (j : Nat) : ByteArray :=
  let b := ByteArray.emptyWithCapacity 104
  let mem (b : ByteArray) := put64 (put64 (put64 (put64 b r.m3) r.m2) r.m1) r.m0
  match j with
  | 0 => put64 (put32u (putBE4 (put32u (putBE3 (mem (b.push (if r.cap then 3 else 1))) r.a0 r.a1 r.a2) r.date)
           r.q0 r.q1 r.q2 r.q3) r.units) r.cents
  | 1 => if r.cap then put32u (mem (b.push 0)) (r.date / 100)
         else putBE4 (put32u (putBE3 (mem (b.push 2)) r.r0 r.r1 r.r2) r.date) r.q0 r.q1 r.q2 r.q3
  | _ => putBE7 (b.push 4) r.i0 r.i1 r.i2 r.i3 r.i4 r.i5 r.i6

/-! ## Keys -/

/-- A distinct key of a batch: its stored bytes (the first is its kind), a row that has it, and its sort and directory
    hashes in the released and the unresolved set. -/
structure KeyQ where
  kb : ByteArray
  row : RowX
  kh0 : UInt64
  kh1 : UInt64
  dh0 : UInt64
  dh1 : UInt64
  deriving Inhabited

def keyQ (ctx : KeyCtx) (r : RowX) (kb : ByteArray) : KeyQ :=
  if kb.size ≤ shortMax then
    let s := keyState ctx kb
    ⟨kb, r, khSt s false, khSt s true, dhSt s false, dhSt s true⟩
  else
    let d := keyDigest ctx.sec kb
    ⟨kb, r, khAt d false, khAt d true, dhAt d false, dhAt d true⟩

/-- The distinct keys in first-occurrence order (exact, near, id of each row), the key of each request position
    (`3 * i + j`), and the key bytes' place in that order. -/
structure Ks where
  keys : Array KeyQ
  idx : Array Nat
  map : HashMap ByteArray Nat

def keysOf (ctx : KeyCtx) (req : Array RowX) : Ks := Id.run do
  let mut keys : Array KeyQ := Array.emptyWithCapacity (3 * req.size)
  let mut idx : Array Nat := Array.emptyWithCapacity (3 * req.size)
  let mut map : HashMap ByteArray Nat := {}
  for r in req do
    for j in [0:3] do
      let kb := r.keyBytes j
      match map.get? kb with
      | some i => idx := idx.push i
      | none =>
        idx := idx.push keys.size
        map := map.insert kb keys.size
        keys := keys.push (keyQ ctx r kb)
  return ⟨keys, idx, map⟩

/-- Round 2: the id key of each unresolved CAP row of a redone payment that is not yet a key, once. -/
def round2Keys (ctx : KeyCtx) (redo : HashSet W9) (ks : Ks) (ur : Array RowX) : Array KeyQ × HashMap ByteArray Nat := Id.run do
  let mut out : Array KeyQ := #[]
  let mut map := ks.map
  for y in ur do
    if y.cap && y.payIn redo then
      let kb := y.keyBytes 2
      if !map.contains kb then
        map := map.insert kb (ks.keys.size + out.size)
        out := out.push (keyQ ctx y kb)
  return (out, map)

/-! ## Store -/

/-- An installed chunk: metadata, the pages, and a dead bit at the first slot of each superseded entry (empty: none). -/
structure Img where
  m : Meta
  img : ByteArray
  dead : ByteArray

structure HistStore where
  ctx : KeyCtx
  dirs : FDirs
  chunks : Array Img

/-- Where an entry is: chunk, first slot and posting count (none when `cnt` is 0), the key's kind, and `rn`, how many of its rows
    the decider reads (`min cnt capN` on the chunk store; on the rows files a key of a core over the cap has fewer rows than
    its count, which is the core's). -/
structure Hit where
  c : Nat
  first : Nat
  cnt : Nat
  kind : Nat := 0
  rn : Nat := 0
  deriving Inhabited

def Hit.none : Hit := ⟨0, 0, 0, 0, 0⟩

def deadAt (b : ByteArray) (i : Nat) : Bool := i / 8 < b.size && (b[i / 8]! >>> (i % 8).toUInt8) &&& 1 == 1

/-- Whether the stored first row `y` has the key of `q`. -/
def keyIs (q : KeyQ) (y : RowX) : Bool :=
  match q.kb[0]! with
  | 4 => q.row.idEq y
  | 1 | 3 => q.row.exactEq y
  | _ => q.row.nearEq y

/-- The entry of `q` in set `u` (sort hash `kh`) in one chunk: page fence, block fence, then slots up to the first past
    `kh`, as `lookupWith` over blocks already verified. -/
def Img.find (ch : Img) (q : KeyQ) (u : Bool) (kh : UInt64) : Hit := Id.run do
  let m := ch.m
  if m.rows == 0 then return Hit.none
  let img := ch.img
  let p0 := lastBelow (fun p => m.fence[p]!) m.fence.size kh
  let b0 := lastBelow (fun b => ld64 img (p0 * pageLen + b * hdrEnt + hbLen)) blocksPage kh
  let mut i := slotsPage * p0 + slotsBlock * b0
  for _ in [0:m.rows + 1] do
    if i ≥ m.rows then return Hit.none
    let o := slotOff i
    let k := ld64 img o
    if kh < k then return Hit.none
    let fl := img[o + 8]!
    if k == kh && fl &&& flagFirst != 0 && (fl &&& 8 != 0) == u && (fl &&& 7).toNat == q.kb[0]!.toNat &&
        keyIs q (RowX.ofChunk img (o + 19)) then
      let cnt := getN img (o + 14) 5
      if m.rows < i + min cnt capN + (if capN < cnt then 1 else 0) then return Hit.none
      return ⟨0, i, cnt, 0, min cnt capN⟩
    i := i + 1
  return Hit.none

/-- The live entry of `q` in set `u` in the first chunk the directory names that holds it. -/
def HistStore.probe (st : HistStore) (q : KeyQ) (u : Bool) : Hit := Id.run do
  let kh := if u then q.kh1 else q.kh0
  let kind := q.kb[0]!.toNat
  for c in st.dirs.cands (if u then q.dh1 else q.dh0) do
    if let some ch := st.chunks[c]? then
      let h := ch.find q u kh
      if h.cnt != 0 && !deadAt ch.dead h.first then return { h with c, kind }
  return { Hit.none with kind }

/-- The rows (`min cnt capN` of each entry, first row, then after the tail row if any) and their `seq`. -/
def HistStore.decode (st : HistStore) (hits : Array Hit) : Array RowX × Array Nat := Id.run do
  let mut rows : Array RowX := #[]
  let mut seq : Array Nat := #[]
  for h in hits do
    if h.cnt != 0 then
      let img := (st.chunks[h.c]?.map (·.img)).getD ByteArray.empty
      let t := if capN < h.cnt then 1 else 0
      for j in [0:min h.cnt capN] do
        let o := slotOff (if j == 0 then h.first else h.first + t + j)
        rows := rows.push (RowX.ofChunk img (o + 19))
        seq := seq.push (getN img (o + 9) 5)
  return (rows, seq)

/-! ## Feeds (conformance/ENGINE_V3.md §19)

    A feed arrives as its rows at fixed stride, little-endian, ids at the row widths, in the order of §19: DMF
    `member 32 ‖ date u32` (36 bytes), provider death `id 21 ‖ date u32` (25), exclusion `id 21 ‖ start u32 ‖ stop u32`
    (29), enrollment span `member 32 ‖ plan 21 ‖ start u32 ‖ stop u32` (61).  `FeedIx.decode` reads it once: it refuses
    a half row or a row below the one before it, decodes the facts in row order, and builds an open-addressing table from
    each key to its run, so a lookup is one hashed probe and no copy.  The state (present, usable) is computed from the
    same bytes, so the facts and the state cannot come from two sources. -/

/-- The splitmix64 finaliser. -/
@[inline] def mix64 (x : UInt64) : UInt64 :=
  let x := (x ^^^ (x >>> 30)) * 0xbf58476d1ce4e5b9
  let x := (x ^^^ (x >>> 27)) * 0x94d049bb133111eb
  x ^^^ (x >>> 31)

@[inline] def ld32 (b : ByteArray) (o : Nat) : Nat :=
  (b[o]!.toUInt32 ||| b[o + 1]!.toUInt32 <<< 8 ||| b[o + 2]!.toUInt32 <<< 16 ||| b[o + 3]!.toUInt32 <<< 24).toNat

/-- The member (32 bytes, `0x01` implied) or provider id (21 bytes) at byte `o`, high word first. -/
@[inline] def memAt (b : ByteArray) (o : Nat) : W4 := ⟨ld64 b (o + 24), ld64 b (o + 16), ld64 b (o + 8), ld64 b o⟩

@[inline] def provAt (b : ByteArray) (o : Nat) : W3 := ⟨ld64 b (o + 16) &&& 0xFFFFFFFFFF, ld64 b (o + 8), ld64 b o⟩

/-- A key as four words, high first (a provider's top word is 0). -/
@[inline] def W4.key (w : W4) : UInt64 × UInt64 × UInt64 × UInt64 := (w.a, w.b, w.c, w.d)

@[inline] def W3.key (w : W3) : UInt64 × UInt64 × UInt64 × UInt64 := (0, w.a, w.b, w.c)

@[inline] def keyHash (seed : UInt64) (k : UInt64 × UInt64 × UInt64 × UInt64) : UInt64 :=
  mix64 (mix64 (mix64 (mix64 (seed ^^^ k.1) ^^^ k.2.1) ^^^ k.2.2.1) ^^^ k.2.2.2)

/-- Keys in order, high word first. -/
@[inline] def keyLt (x y : UInt64 × UInt64 × UInt64 × UInt64) : Bool :=
  x.1 < y.1 || x.1 == y.1 && (x.2.1 < y.2.1 || x.2.1 == y.2.1 &&
    (x.2.2.1 < y.2.2.1 || x.2.2.1 == y.2.2.1 && x.2.2.2 < y.2.2.2))

/-- One feed: present (state 1, its pin checked), usable, its facts in row order, and a table of 40-byte slots (key
    words high first, run start u32, run length u32; length 0 is an empty slot) over `mask + 1` slots. -/
structure FeedIx (α : Type) where
  present : Bool
  ok : Bool
  facts : Array α
  tab : ByteArray
  mask : UInt64
  seed : UInt64

/-- The probe of table `t` for key words `a b c d` from slot `i`, at most `k` slots (no word boxed). -/
def findRun (t : @& ByteArray) (mask a b c d i : UInt64) : Nat → Rg
  | 0 => ⟨0, 0, false⟩
  | k + 1 =>
    let o := 40 * i.toNat
    let n := ld32 t (o + 36)
    if n == 0 then ⟨0, 0, false⟩
    else if ld64 t o == a && ld64 t (o + 8) == b && ld64 t (o + 16) == c && ld64 t (o + 24) == d then
      ⟨ld32 t (o + 32), min n capN, capN < n⟩
    else findRun t mask a b c d ((i + 1) &&& mask) k

/-- The run of key `k`: its first fact, `min run capN` and whether the run is longer than `capN`. -/
@[inline] def FeedIx.find {α : Type} (f : FeedIx α) (k : UInt64 × UInt64 × UInt64 × UInt64) : Rg :=
  findRun f.tab f.mask k.1 k.2.1 k.2.2.1 k.2.2.2 (keyHash f.seed k &&& f.mask) (f.mask.toNat + 1)

/-- The table of `FeedIx` over facts `0..n` whose keys `keyAt j` come in `runs` runs (equal keys next to each other):
    each run's key, first fact and length, and the mask. -/
def runTable (seed : UInt64) (n runs : Nat) (keyAt : Nat → UInt64 × UInt64 × UInt64 × UInt64) : ByteArray × UInt64 :=
    Id.run do
  let mut slots := 2
  while slots < 2 * runs do slots := 2 * slots
  let mask := (slots - 1).toUInt64
  let mut tab := ByteArray.mk (Array.replicate (40 * slots) 0)
  let mut j := 0
  while j < n do
    let k := keyAt j
    let mut e := j + 1
    while e < n && keyAt e == k do e := e + 1
    let mut i := keyHash seed k &&& mask
    while ld32 tab (40 * i.toNat + 36) != 0 do i := (i + 1) &&& mask
    let o := 40 * i.toNat
    tab := st32 (st32 (st64 (st64 (st64 (st64 tab o k.1) (o + 8) k.2.1) (o + 16) k.2.2.1) (o + 24) k.2.2.2) (o + 32) j)
      (o + 36) (e - j)
    j := e
  return (tab, mask)

/-- A feed as the codec hands it over: present (state 1 and the pin over its rows checked), its date, its declared
    count, its rows. -/
structure FeedSrc where
  present : Bool
  asOf : Nat
  count : Nat
  rows : ByteArray

/-- `usable`'s test of the snapshot date against today and the feed's maximum age. -/
def dateOk (today maxAge asOf : Nat) : Bool :=
  validDate today && validDate asOf && asOf ≤ today && dayNum today ≤ dayNum asOf + maxAge

/-- Feed `src` of `stride`-byte rows (`key` a row's key, its first order field; `rest b o o'` the order of the other
    fields of two rows of one key; `fact` its fact; `rowOk` the snapshot's row test on its date): none when a row is cut
    short, a row is below the one before it, or an absent feed carries rows.  Usable as `usable` says: present, `dateOk`, as many rows as declared,
    at least one, every row well formed. -/
def FeedIx.decode {α : Type} (today maxAge : Nat) (seed : UInt64) (src : FeedSrc) (stride : Nat)
    (key : ByteArray → Nat → UInt64 × UInt64 × UInt64 × UInt64) (rest : ByteArray → Nat → Nat → Bool)
    (fact : ByteArray → Nat → α) (rowOk : Nat → ByteArray → Nat → Bool) : Option (FeedIx α) := Id.run do
  let b := src.rows
  if b.size % stride != 0 || (!src.present && b.size != 0) then return none
  let n := b.size / stride
  let mut runs := 0
  let mut good := true
  let mut facts : Array α := Array.emptyWithCapacity n
  let mut prev := (0, 0, 0, 0)
  for j in [0:n] do
    let o := stride * j
    let k := key b o
    if j == 0 || prev != k then
      if j != 0 && keyLt k prev then return none
      runs := runs + 1
    else if !rest b (o - stride) o then return none
    prev := k
    good := good && rowOk src.asOf b o
    facts := facts.push (fact b o)
  let (tab, mask) := runTable seed n runs fun j => key b (stride * j)
  let ok := src.present && dateOk today maxAge src.asOf && n == src.count && 0 < n && good
  return some ⟨src.present, ok, facts, tab, mask, seed⟩

/-- An absent feed (not present, not usable, no facts, an empty two-slot table), as `ReadB.feedW` gives for a feed
    whose snapshot is not present. -/
def FeedIx.absent {α : Type} (seed : UInt64) : FeedIx α :=
  ⟨false, false, #[], ByteArray.mk (Array.replicate 80 0), 1, seed⟩

/-- The five feeds of a frame.  Eligibility (`el`) is not yet on the frame: it is always `FeedIx.absent` (G2 then
    decides STALE_ELIGIBILITY on every line). -/
structure FeedsX where
  dmf : FeedIx Death
  pd : FeedIx Death
  ex : FeedIx Exclusion
  sp : FeedIx SpanF
  el : FeedIx EligF

/-- The feeds of a frame from the four the codec hands over (DMF, provider deaths, exclusions, enrollment, with the
    maximum ages of `usable`: 90, 90, 31, 7 days), with eligibility absent; none refuses the frame. -/
def FeedsX.decode (today : Nat) (seed : UInt64) (d p e s : FeedSrc) : Option FeedsX := do
  let okD := fun (asOf : Nat) (b : ByteArray) (o : Nat) => let x := ld32 b (o + 32); validDate x && x ≤ asOf
  let okP := fun (asOf : Nat) (b : ByteArray) (o : Nat) => let x := ld32 b (o + 21); validDate x && x ≤ asOf
  let okW := fun (a z : Nat) => validDate a && validDate z && a ≤ z
  let le1 := fun (at_ : Nat) (b : ByteArray) (o o' : Nat) => decide (ld32 b (o + at_) ≤ ld32 b (o' + at_))
  let le2 := fun (at_ : Nat) (b : ByteArray) (o o' : Nat) =>
    let x := ld32 b (o + at_); let y := ld32 b (o' + at_)
    x < y || x == y && ld32 b (o + at_ + 4) ≤ ld32 b (o' + at_ + 4)
  let dmf ← FeedIx.decode today 90 seed d 36 (fun b o => (memAt b o).key) (le1 32)
    (fun b o => (⟨(memAt b o).nat, ld32 b (o + 32)⟩ : Death)) okD
  let pd ← FeedIx.decode today 90 seed p 25 (fun b o => (provAt b o).key) (le1 21)
    (fun b o => (⟨(provAt b o).nat, ld32 b (o + 21)⟩ : Death)) okP
  let ex ← FeedIx.decode today 31 seed e 29 (fun b o => (provAt b o).key) (le2 21)
    (fun b o => (⟨(provAt b o).nat, ld32 b (o + 21), ld32 b (o + 25)⟩ : Exclusion))
    (fun _ b o => okW (ld32 b (o + 21)) (ld32 b (o + 25)))
  let sp ← FeedIx.decode today 7 seed s 61 (fun b o => (memAt b o).key)
    (fun b o o' => let x := (provAt b (o + 32)).key; let y := (provAt b (o' + 32)).key
      keyLt x y || x == y && le2 53 b o o')
    (fun b o => let p := provAt b (o + 32); (⟨p.nat, true, p.a, p.b, p.c, ld32 b (o + 53), ld32 b (o + 57), true⟩ : SpanF))
    (fun _ b o => okW (ld32 b (o + 53)) (ld32 b (o + 57)))
  pure ⟨dmf, pd, ex, sp, FeedIx.absent seed⟩

/-! ## Assembly -/

/-- `hu1` the unresolved hits of the batch's keys; `hr1` the released hits of those keys and then of the round 2 keys;
    `idx` the key of each request position (`3 * i + j`); `uIdOf y` the slot of the id key of unresolved row `y`
    (`hr1.size` when it is not a key of the batch); the rows are those hits decoded; `byp` the admitted bypasses; `lim`
    the HOLD-level payments and their holds masks. -/
def assemble (hr hu : Head) (today : Nat) (byp lim : List (Nat × Nat)) (fx : FeedsX) (f : List Nat) (redo : HashSet W9)
    (req : Array RowX) (pidx : Array Nat) (idx : Array Nat) (uIdOf : RowX → Nat)
    (hu1 hr1 : Array Hit) (relP : Array RowX) (relSeq : Array Nat) (unrP : Array RowX) (unrSeq : Array Nat) : Lay :=
    Id.run do
  let nk := hu1.size
  let nr := hr1.size
  let mut slots : Array Slot := Array.emptyWithCapacity nr
  let mut rs := 0
  let mut us := 0
  for j in [0:nr] do
    let h := hr1[j]!
    let rn := h.rn
    if j < nk then
      let g := hu1[j]!
      let un := g.rn
      slots := slots.push { kind := h.kind, rs, rn, rc := h.cnt, us, un, uc := g.cnt }
      us := us + un
    else slots := slots.push { kind := h.kind, rs, rn, rc := h.cnt }
    rs := rs + rn
  let mut uSpan : Array Rg := Array.emptyWithCapacity unrP.size
  let mut uId : Array Nat := Array.emptyWithCapacity unrP.size
  for y in unrP do
    uSpan := uSpan.push (fx.sp.find y.w4.key)
    uId := uId.push (uIdOf y)
  let np := pidx.foldl (fun m p => max m (p + 1)) 0
  let mut pDone : Array Bool := Array.replicate np false
  let mut pRedo : Array Bool := Array.replicate np false
  let mut pByp : Array (Option UInt32) := Array.replicate np none
  -- per payment number, its first entry (`List.lookup`); a number too wide for a payment names none
  let first (l : List (Nat × Nat)) : HashMap W9 UInt32 := l.foldl (fun m x =>
    if x.1 < 256 ^ payW && !m.contains (W9.ofNat x.1) then m.insert (W9.ofNat x.1) (x.2 % 2 ^ 32).toUInt32 else m) ∅
  let bm := first byp
  let lm := first lim
  let mut lLim : Array (Option UInt32) := Array.emptyWithCapacity req.size
  let fs : HashSet W7 := f.foldl (fun s n => if n < 256 ^ idW then s.insert (W7.ofNat n) else s) ∅
  let mut lines : Array LineIn := Array.emptyWithCapacity req.size
  for i in [0:req.size] do
    let r := req[i]!
    let pj := pidx[i]!
    if !pDone[pj]! then
      pDone := pDone.set! pj true
      pRedo := pRedo.set! pj (r.payIn redo)
      pByp := pByp.set! pj (bm.get? r.w9)
    lLim := lLim.push (lm.get? r.w9)
    lines := lines.push
      { row := r, ke := idx[3 * i]!, kn := idx[3 * i + 1]!, ki := idx[3 * i + 2]!, pay := pj,
        dmf := fx.dmf.find r.w4.key, span := fx.sp.find r.w4.key, pdP := fx.pd.find r.payee.key,
        pdR := fx.pd.find r.rend.key, exP := fx.ex.find r.payee.key, exR := fx.ex.find r.rend.key,
        elig := fx.el.find r.w4.key, fseen := fs.contains r.w7 }
  return {
    today, relCh := hr.chained today, unrCh := hu.chained today,
    dmfSome := fx.dmf.present, pdSome := fx.pd.present, exclSome := fx.ex.present, spanSome := fx.sp.present,
    eligSome := fx.el.present,
    dmfOk := fx.dmf.ok, pdOk := fx.pd.ok, exclOk := fx.ex.ok, spanOk := fx.sp.ok, eligOk := fx.el.ok,
    lines, slots, relP, relSeq, unrP, unrSeq, uSpan, uId, dmf := fx.dmf.facts, pdeath := fx.pd.facts,
    excl := fx.ex.facts, spans := fx.sp.facts, eligs := fx.el.facts, redo, pRedo, pByp, lLim, src := #[], relSrc := #[], unrSrc := #[] }

/-- `Flat.Rows.layout` from the request rows, the heads of the two sets, the key directory, the chunk images and the
    frame's feeds (`fx`, from `FeedsX.decode`); the feed facts are `fx`'s arrays and each line's runs index into them. -/
def layoutStore (st : HistStore) (hr hu : Head) (today : Nat) (redoL : List Nat) (byp lim : List (Nat × Nat))
    (fx : FeedsX) (f : List Nat) (req : Array RowX) (pidx : Array Nat) : Lay :=
  let ks := keysOf st.ctx req
  let hu1 := ks.keys.map (st.probe · true)
  let ur := st.decode hu1
  let redo := redoW redoL
  let (k2, smap) := round2Keys st.ctx redo ks ur.1
  let hr1 := (ks.keys ++ k2).map (st.probe · false)
  let rr := st.decode hr1
  assemble hr hu today byp lim fx f redo req pidx ks.idx (fun y => smap.getD (y.keyBytes 2) (ks.keys.size + k2.size))
    hu1 hr1 rr.1 rr.2 ur.1 ur.2

end BlindLedger.Gate.Engine3
