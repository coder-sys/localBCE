import BlindLedger.Gate.Flat.Bin
import BlindLedger.Gate.Flat.Io
import BlindLedger.Gate.Flat.Store
import BlindLedger.Gate.Flat.StoreLog

/-! Measurement glue: the chunk store (`Store.lean`, `Chunk.lean`) run as code over chunk files, for the worker's second
    store path.  The model's directory, dead bits, window, sealing, placing, sorting, kill and tree functions are called as
    they are.  Only what the model states on lists is done on byte arrays here: the read of a lookup window through the
    page marks (`Store.loIx`, `hiIx`, `pagesIn`), the row scan of those pages, and the chunk encoder (`encFast`, equal to
    `Chunk.encChunk` by the check run, not by a proof).  Bench only; no decision reads anything here but through the
    model's `decideFetched`. -/

namespace BlindLedger.Gate.Flat.ChunkIo

open Chunk Store StoreLog
open BlindLedger.Gate.Rules
open BlindLedger.Gate.OnepIndex (leb)
open Std (HashMap HashSet)

abbrev Prof := Option (IO.Ref (Array Nat))

def tp {α : Type} (pf : Prof) (i : Nat) (f : Unit → α) (sz : α → Nat) : IO α := do
  let some prof := pf | return f ()
  let t0 ← IO.monoNanosNow
  let a ← IO.lazyPure f
  let n := sz a
  let t1 ← IO.monoNanosNow
  prof.modify fun p => (p.modify i (· + (t1 - t0))).modify 15 (· + n)
  pure a

def ti {α : Type} (pf : Prof) (i : Nat) (act : IO α) : IO α := do
  let some prof := pf | act
  let t0 ← IO.monoNanosNow
  let a ← act
  let t1 ← IO.monoNanosNow
  prof.modify fun p => p.modify i (· + (t1 - t0))
  pure a

/-- SHA3-512 (the worker's `H`) on lists. -/
def hl (b : Bytes) : Bytes := (Bin.HB ⟨b.toArray⟩).toList

/-- The directory's speed hash of key bytes (FNV-1a, then a 64-bit mix); no result depends on it. -/
def khB (b : ByteArray) : UInt64 := Id.run do
  let mut h : UInt64 := 0xcbf29ce484222325
  for x in b do h := (h ^^^ x.toUInt64) * 0x100000001b3
  h := (h ^^^ (h >>> 33)) * 0xff51afd7ed558ccd
  h := (h ^^^ (h >>> 33)) * 0xc4ceb9fe1a85ec53
  return h ^^^ (h >>> 33)

/-- `khB` on a list, without copying it to an array. -/
def kh (b : Bytes) : UInt64 :=
  let h := b.foldl (fun h x => (h ^^^ x.toUInt64) * 0x100000001b3) 0xcbf29ce484222325
  let h := (h ^^^ (h >>> 33)) * 0xff51afd7ed558ccd
  let h := (h ^^^ (h >>> 33)) * 0xc4ceb9fe1a85ec53
  h ^^^ (h >>> 33)

/-! ## Number writers: `leb` into a buffer -/

/-- `leb n` for `n` below `2^56`, pushed byte by byte (small numbers only, so every step is a machine word). -/
def lebS (b : ByteArray) (n : Nat) : ByteArray :=
  if n < 128 then b.push n.toUInt8 else lebS (b.push (n % 128 + 128).toUInt8) (n / 128)
termination_by n
decreasing_by omega

/-- The first `k` groups of `m`, each with its continuation bit. -/
def lebK : Nat → ByteArray → Nat → ByteArray
  | 0, b, _ => b
  | k + 1, b, m => lebK k (b.push (m % 128 + 128).toUInt8) (m / 128)

def B56 : Nat := 72057594037927936

/-- `leb n` appended to `b`: a big number is cut in 56-bit limbs (8 groups each), so a big-number division happens once per limb. -/
def lebPush (b : ByteArray) (n : Nat) : ByteArray :=
  if n < B56 then lebS b n else lebPush (lebK 8 b (n % B56)) (n / B56)
termination_by n
decreasing_by all_goals (simp only [B56] at *; omega)

def pushL (b : ByteArray) (l : List UInt8) : ByteArray := l.foldl ByteArray.push b

/-- `Store.skey` as bytes, built once: the set tag, then the key's length and numbers. -/
def skeyB (u : Bool) (k : Key) : ByteArray :=
  k.foldl lebPush (lebPush (ByteArray.empty.push (if u then 1 else 0)) k.length)

/-- Key bytes with their speed hash, the memo key of a lookup. -/
structure BK where
  b : ByteArray
  h : UInt64

def sameAt (buf : ByteArray) (p : Nat) (kb : ByteArray) : Bool := Id.run do
  for i in [0:kb.size] do
    if buf[p + i]! != kb[i]! then return false
  return true

instance : BEq BK := ⟨fun x y => x.h == y.h && x.b.size == y.b.size && sameAt x.b 0 y.b⟩
instance : Hashable BK := ⟨(·.h)⟩

def mkBK (b : ByteArray) : BK := ⟨b, khB b⟩

/-- A slot position's chunk number when its fingerprint is `f`. -/
def addPos (d : Dir) (f : Nat) (out : Array Nat) (j : Nat) : Array Nat :=
  match d.t[j]? with
  | some v => if fpv v = f then out.push (v.toNat % 2 ^ cBits) else out
  | none => out

/-- `Dir.cands` as an array, without lists. -/
def candsA (d : Dir) (h : UInt64) : Array Nat :=
  let f := fpOf h
  let b := h.toNat % d.nb
  let b2 := alt d.nb f b
  let o := addPos d f #[] (4 * b)
  let o := addPos d f o (4 * b + 1)
  let o := addPos d f o (4 * b + 2)
  let o := addPos d f o (4 * b + 3)
  let o := addPos d f o (4 * b2)
  let o := addPos d f o (4 * b2 + 1)
  let o := addPos d f o (4 * b2 + 2)
  let o := addPos d f o (4 * b2 + 3)
  d.stash.foldl (fun o x => if x.2 = cls d.nb f b ∧ fpv x.1 = f then o.push (x.1.toNat % 2 ^ cBits) else o) o

/-- `Store.kill` taking the chunk's set out of the map first, so the set is edited in place once it is not shared. -/
def killFast (d : HashMap Nat (HashSet Nat)) (c i : Nat) : HashMap Nat (HashSet Nat) :=
  let s := (d.get? c).getD ∅
  let d := d.insert c ∅
  d.insert c (s.insert i)

def killRowFast (h : UInt64) (a : HashMap Nat (HashSet Nat) × Dir) (x : Nat × Nat × Entry) :
    HashMap Nat (HashSet Nat) × Dir :=
  if isDead a.1 x.1 x.2.1 then a else (killFast a.1 x.1 x.2.1, a.2.erase (slot (fpOf h) x.1) (h.toNat % a.2.nb))

/-- `Store.place` with `fs` taken apart first, so the directory is held once while its slots are written (in place);
    `place` itself keeps `fs` whole and so shares the array. -/
def placeFast (kh : Bytes → UInt64) (fs : Fs) (c : Nat) (ws : List Row) : Except Store.Refusal Fs :=
  let ⟨hr, hu, dir, inst, dead0, win, _⟩ := fs
  let dead := dead0.insert c (bornDead win ws)
  ((liveHashes kh dead c ws).foldlM (fun (d : Dir) h => d.insert h c) dir).map fun d =>
    ⟨hr, hu, d, inst.insert c, dead, win, none⟩

theorem placeFast_eq (kh : Bytes → UInt64) (fs : Fs) (c : Nat) (ws : List Row) :
    placeFast kh fs c ws = place kh fs c ws := by
  cases fs; rfl

def domPageS : ByteArray := Bin.bytesOf (domain "STORE/PAGE")
def domChunkS : ByteArray := Bin.bytesOf (domain "STORE/CHUNK")

/-- A page the index names: page number, fence (key hash), offset, row number, fresh flag. -/
structure Ix where
  page : Nat
  fence : Nat
  off : Nat
  row : Nat
  fresh : Bool

/-- What RAM keeps of an installed chunk: where its pages start in the log, row count, bytes of rows (before the
    terminator), the index and the page hashes. -/
structure CMetaR where
  base : Nat
  rowBytes : Nat
  nrows : Nat
  ix : Array Ix
  phash : Array ByteArray
  /-- The SHA3-512 of its metadata (`"STORE/CHUNK"`-tagged): its tree leaf. -/
  mh : Bytes

structure CS where
  dir : String
  shard : Nat
  /-- The bucket count the store was created with: every frame carries it. -/
  nb0 : Nat
  fs : Fs
  metas : HashMap Nat CMetaR := ∅
  tree : Tree
  head : Bytes
  batches : Nat
  /-- Each installed chunk's number, install number and tombstones (its metadata). -/
  book : Book := []
  /-- The next install number. -/
  nx : Nat := 0
  /-- The open `log`, and where the next frame goes. -/
  log : UInt32
  logLen : Nat := 0
  /-- The shard's authority record (`authLen` bytes): its last frame carries it and the state root binds it. -/
  au : Bytes
  /-- The last frame's request digest (64 bytes): the state root binds it. -/
  rq : Bytes := List.replicate 64 0
  /-- The whole frame after the last one, unsigned (`loadLog`'s second result): its request digest, its authority record and
      its bytes.  It is never an answer; a retry decides the batch again and its frame must equal these bytes. -/
  pend : Option (Bytes × Bytes × ByteArray) := none
  /-- The last install's counts (bench): bytes its store-side hashes read, and syncs it ran. -/
  stat : Nat × Nat := (0, 0)

/-- Leading elements of `a` with `p` true (`p` rises from true to false). -/
def partGo {α : Type} [Inhabited α] (a : Array α) (p : α → Bool) : Nat → Nat → Nat → Nat
  | 0, lo, _ => lo
  | f + 1, lo, hi =>
    if lo < hi then
      if p a[(lo + hi) / 2]! then partGo a p f ((lo + hi) / 2 + 1) hi else partGo a p f lo ((lo + hi) / 2)
    else lo

def partPoint {α : Type} [Inhabited α] (a : Array α) (p : α → Bool) : Nat := partGo a p a.size 0 a.size

instance : Inhabited Ix := ⟨⟨0, 0, 0, 0, false⟩⟩

/-- The window of key hash `h` (`loIx`, `hiIx` on the marks): first row and its byte offset, end row and its byte offset. -/
def CMetaR.window (m : CMetaR) (h : Nat) : Nat × Nat × Nat × Nat :=
  let at_ (e : Ix) : Nat × Nat := (e.row, e.page * pageSize + e.off)
  let i := partPoint m.ix (·.fence < h)
  let lo : Ix :=
    match m.ix[i]? with
    | some e => if e.fence == h && e.fresh then e else (if i > 0 then m.ix[i - 1]! else m.ix[0]!)
    | none => m.ix.back!
  let u := partPoint m.ix (·.fence ≤ h)
  let (hr, ho) := match m.ix[u]? with | some e => at_ e | none => (m.nrows, m.rowBytes)
  (lo.row, (at_ lo).2, hr, ho)

/-- The rows of key bytes `kb` among the rows from byte `start` (row `j0`) to `stop` of the data, whose pages `buf`
    starts at byte `bufOff`; `none` when a length is out of range or a matching body does not decode. -/
def scanGo (buf : ByteArray) (kb : ByteArray) (stop : Nat) :
    Nat → Array (Nat × Row) → Nat → Nat → Option (Array (Nat × Row))
  | 0, out, pos, _ => if pos < stop then none else some out
  | f + 1, out, pos, j =>
    if pos < stop then
      match Bin.unlebAt buf pos with
      | none => none
      | some (len, p1) =>
        match Bin.unlebAt buf p1 with
        | none => none
        | some (kl, p2) =>
          if len == 0 || p1 + len > buf.size || p2 + kl > p1 + len then none
          else if kl == kb.size && sameAt buf p2 kb then
            match decBody (buf.extract p1 (p1 + len)).toList with
            | none => none
            | some w => scanGo buf kb stop f (out.push (j, w)) (p1 + len) (j + 1)
          else scanGo buf kb stop f out (p1 + len) (j + 1)
    else some out

/-- Each row is at least two bytes, so `stop - start` steps suffice. -/
def scan (buf : ByteArray) (bufOff j0 start stop : Nat) (kb : ByteArray) : Option (Array (Nat × Row)) :=
  scanGo buf kb (stop - bufOff) ((stop - bufOff) - (start - bufOff)) #[] (start - bufOff) j0

/-- Rows of key `kb` (hash `h`) in chunk `c`, read through its marks: one pread of the window's pages, each checked
    against its recorded SHA3-512.  `none`: a page or row is bad. -/
def readHits (pf : Prof) (pg : IO.Ref Nat) (fd : UInt32) (c : Nat) (m : CMetaR) (kbA : ByteArray) (h : UInt64) :
    IO (Option (List (Nat × Nat × Entry))) := do
  let (lo, loOff, hi, hiOff) := m.window h.toNat
  if hi ≤ lo then return some []
  let p0 := loOff / pageSize
  let p1 := (hiOff - 1) / pageSize
  let np := p1 - p0 + 1
  let buf ← ti pf 0 (Io.pgRead fd (m.base + p0 * pageSize).toUInt64 (np * pageSize).toUSize)
  pg.modify (· + np)
  if buf.size != np * pageSize then return none
  let ok ← tp pf 1 (fun _ => Id.run do
      for i in [0:np] do
        let hh := Bin.HB (domPageS ++ buf.extract (i * pageSize) ((i + 1) * pageSize))
        let w := m.phash[p0 + i]!
        if hh.size != w.size || !sameAt hh 0 w then return false
      return true)
    fun b => if b then 1 else 0
  if !ok then return none
  let r ← tp pf 2 (fun _ => scan buf (p0 * pageSize) lo loOff hiOff kbA) (·.elim 0 (·.size))
  return r.map fun a => a.toList.map fun (j, w) => (c, j, w.2)

/-- `Store.hits` for key bytes `kbA` (hash `h`): the live rows of the chunks the directory names. -/
def liveHits (pf : Prof) (pg : IO.Ref Nat) (cs : CS) (kbA : ByteArray) (h : UInt64) : IO (Option (List (Nat × Nat × Entry))) := do
  let cands ← tp pf 14 (fun _ => candsA cs.fs.dir h) (·.size)
  let mut out : Array (Nat × Nat × Entry) := #[]
  for c in cands do
    if !cs.fs.inst.contains c then continue
    let some m := cs.metas[c]? | return none
    let some hs ← readHits pf pg cs.log c m kbA h | return none
    for x in hs do
      if !isDead cs.fs.dead x.1 x.2.1 then out := out.push x
  return some out.toList

/-- `Store.lookup` with the sealed window empty (a batch's chunk installs before the next batch). -/
def lookupE (cs : CS) (kb : ByteArray) (hs : List (Nat × Nat × Entry)) : Entry :=
  match (if cs.fs.win.isEmpty then none else cs.fs.win.get? kb.toList) with
  | some e => e
  | none => match hs with | (_, _, e) :: _ => e | [] => Entry.empty

/-! ## Encoding -/

structure Enc where
  file : ByteArray
  mdata : ByteArray
  ix : Array Ix
  phash : Array ByteArray
  rowBytes : Nat
  nrows : Nat

/-- `Chunk.encBody` into a fresh buffer. -/
def encBodyB (w : Row) : ByteArray :=
  let b := pushL (lebPush ByteArray.empty w.1.length) w.1
  let b := lebPush (lebPush b w.2.count) w.2.head.length
  let b := w.2.head.foldl (fun b p => (enc p.row).foldl lebPush (lebPush b p.seq)) b
  if w.2.tail = zeroDigest then b.push 0 else pushL (b.push 1) w.2.tail

/-- `Chunk.encRow` appended to `buf`. -/
def encRowB (buf : ByteArray) (w : Row) : ByteArray :=
  let bd := encBodyB w
  lebPush buf bd.size ++ bd

/-- 8 bytes, big-endian (`natBE 8`). -/
def pushBE8 (b : ByteArray) (x : Nat) : ByteArray :=
  (List.range 8).foldl (fun b i => b.push (x / 256 ^ (7 - i) % 256).toUInt8) b

/-- `Chunk.encChunk` (with `encM`/`metaOf`) on byte arrays (rows by `Chunk.encRow`; pages, marks and metadata by running offsets). -/
def encFast (ws : List Row) : Enc := Id.run do
  let rows := ws.toArray
  let n := rows.size
  let mut data := ByteArray.empty
  let mut offs : Array Nat := Array.mkEmpty n
  let mut khs : Array Nat := Array.mkEmpty n
  for w in rows do
    offs := offs.push data.size
    khs := khs.push (kh w.1).toNat
    data := encRowB data w
  let rowBytes := data.size
  data := data.push 0
  let np := (data.size + pageSize - 1) / pageSize
  data := data ++ ⟨Array.replicate (np * pageSize - data.size) 0⟩
  let mut first : Array (Option Nat) := Array.replicate np none
  let mut rowsIn : Array Nat := Array.replicate np 0
  for j in [0:n] do
    let p := offs[j]! / pageSize
    if first[p]!.isNone then first := first.set! p (some j)
    rowsIn := rowsIn.modify p (· + 1)
  let mut marks : Array (Nat × Nat × Nat × Bool) := Array.mkEmpty np
  let mut ix : Array Ix := #[]
  let mut cnt := 0
  for p in [0:np] do
    match first[p]! with
    | some j =>
      let fr := j == 0 || khs[j - 1]! != khs[j]!
      marks := marks.push (khs[j]!, offs[j]! % pageSize, j, fr)
      ix := ix.push ⟨p, khs[j]!, offs[j]! % pageSize, j, fr⟩
    | none =>
      let j := cnt - 1
      marks := marks.push (khs[j]!, pageSize, j, false)
    cnt := cnt + rowsIn[p]!
  let mut phash : Array ByteArray := Array.mkEmpty np
  for p in [0:np] do
    phash := phash.push (Bin.HB (domPageS ++ data.extract (p * pageSize) ((p + 1) * pageSize)))
  -- `Chunk.encM (metaOf ..)`: key hashes, row data length, marks, then length-prefixed page hashes
  let mut md := lebPush ByteArray.empty n
  for x in khs do md := pushBE8 md x
  md := lebPush (lebPush md rowBytes) np
  for p in [0:np] do
    let (f, o, r, fr) := marks[p]!
    md := (lebPush (lebPush (lebPush md f) o) r).push (if fr then 1 else 0)
  md := lebPush md np
  for p in [0:np] do md := lebPush md phash[p]!.size ++ phash[p]!
  return { file := data, mdata := md, ix, phash, rowBytes, nrows := n }


/-! ## The log: files and the stop points of a crash test -/

def logPath (dir : String) : String := s!"{dir}/log"

/-- Test only (the crash-test exe): the process is killed after step `s` of the write of `what` when `crash` names
    `what-s`; the pinned exes pass "none". -/
def stopAt (crash what : String) (s : String) : IO Unit :=
  if crash == s!"{what}-{s}" then IO.Process.exit 99 else pure ()

def stateRootOf (cs : CS) : Bytes := stateRoot3 hl cs.shard cs.nb0 cs.tree.root cs.fs.hr cs.fs.hu cs.nx cs.au cs.rq

def closeAll (cs : CS) : IO Unit := do let _ ← Io.pgClose cs.log

/-- The directory `d` plus the live key hashes of the chunks `cs` (ascending), inserted chunk by chunk:
    each chunk's rows are read, decoded by the model (`decRows`), inserted and dropped before the next is read, so no list of
    all the hashes exists.  The recursion is the fold of `regrowH_stream`.  It passes `d` on as its only reference (in a `for`
    loop each insert copied the whole array, measured). -/
def regrowIo (fd : UInt32) (metas : HashMap Nat CMetaR) (dead : HashMap Nat (HashSet Nat)) :
    List Nat → Dir → IO (Except Store.Refusal Dir)
  | [], d => pure (.ok d)
  | c :: cs, d => do
    let some m := metas[c]? | regrowIo fd metas dead cs d
    let buf ← Io.pgRead fd m.base.toUInt64 (m.phash.size * pageSize).toUSize
    match (liveHashes kh dead c ((decRows buf.size buf.toList).getD [])).foldlM (fun d h => d.insert h c) d with
    | .ok d' => regrowIo fd metas dead cs d'
    | .error e => pure (.error e)

theorem regrowH_stream (fs : Fs) (hs : Nat → List UInt64) :
    regrowH kh fs hs = ((fs.inst.toList.mergeSort fun a b => decide (a ≤ b)).foldlM
      (fun d c => (hs c).foldlM (fun d h => d.insert h c) d) (Dir.empty (2 * fs.dir.nb + 1))).map fun d => { fs with dir := d } := by
  simp [regrowH, Dir.rebuild, List.foldlM_map]

/-! ## Frames on byte arrays -/

def le32At (d : ByteArray) (q : Nat) : UInt32 :=
  d[q]!.toUInt32 ||| (d[q + 1]!.toUInt32 <<< 8) ||| (d[q + 2]!.toUInt32 <<< 16) ||| (d[q + 3]!.toUInt32 <<< 24)

/-- A whole frame in the log: where it starts, its header's lengths, its chunk number plus one and its trailer's fields. -/
structure FrameAt where
  start : Nat
  np : Nat
  ml : Nat
  tl : Nat
  c : Nat
  f : Frame

def FrameAt.len (x : FrameAt) : Nat := 16 + x.np * pageSize + x.ml + x.tl

/-- The whole frame starting at byte `p` of the log `fd` (`size` bytes) and its metadata bytes, from the header (16 bytes)
    and one read of the metadata and trailer; the pages are skipped.  `none` unless a whole frame decodes there
    (`decFrame` without the pages). -/
def readFrameAt (fd : UInt32) (size p : Nat) : IO (Option (FrameAt × ByteArray)) := do
  if p + 16 > size then return none
  let h ← Io.pgRead fd p.toUInt64 16
  if h.size != 16 || !sameAt h 0 (Bin.bytesOf frameTag) then return none
  let np := (le32At h 4).toNat
  let ml := (le32At h 8).toNat
  let tl := (le32At h 12).toNat
  if p + 16 + np * pageSize + ml + tl > size then return none
  let mt ← Io.pgRead fd (p + 16 + np * pageSize).toUInt64 (ml + tl).toUSize
  if mt.size != ml + tl then return none
  match decTrailer (mt.extract ml (ml + tl)).toList with
  | none => return none
  | some (c, f) =>
    if c == 0 && !(np == 0 && ml == 0) then return none
    return some (⟨p, np, ml, tl, c, f⟩, mt.extract 0 ml)

/-- `n` steps of `f` from `a`, none as soon as one fails (each step uses a byte, so a huge count ends with the data). -/
def stepN {α : Type} (f : α → Option α) : Nat → α → Option α
  | 0, a => some a
  | n + 1, a => match f a with
    | some a' => stepN f n a'
    | none => none

/-- The big-endian number of the 8 bytes at `i` (the caller has checked they exist). -/
def be64At (d : ByteArray) (i : Nat) : UInt64 :=
  (d[i]!.toUInt64 <<< 56) ||| (d[i + 1]!.toUInt64 <<< 48) ||| (d[i + 2]!.toUInt64 <<< 40) ||| (d[i + 3]!.toUInt64 <<< 32) |||
  (d[i + 4]!.toUInt64 <<< 24) ||| (d[i + 5]!.toUInt64 <<< 16) ||| (d[i + 6]!.toUInt64 <<< 8) ||| d[i + 7]!.toUInt64

/-- What a replay takes from one frame's metadata (`decMeta3` and `decM`, read straight from the bytes): the install
    number, the tombstones with their rows' key hashes, the chunk's key hashes and row-byte length, what RAM keeps of it
    (the index and the page hashes). -/
structure M3 where
  seq : Nat
  ts : Array Tomb
  tk : Array UInt64
  khs : Array UInt64
  dlen : Nat
  ix : Array Ix
  phash : Array ByteArray

/-- `count` key hashes (8 bytes each) from `i`; the offset after them. -/
def khsAt (d : ByteArray) (i count : Nat) : Option (Array UInt64 × Nat) :=
  if i + 8 * count ≤ d.size then some ((Array.range count).map fun k => be64At d (i + 8 * k), i + 8 * count) else none

/-- `decM`'s fields from `d`, all bytes used. -/
def decMA (d : ByteArray) : Option (Array UInt64 × Nat × Array Ix × Array ByteArray) := do
  let (n, i) ← Bin.unlebAt d 0
  let (khs, i) ← khsAt d i n
  let (dlen, i) ← Bin.unlebAt d i
  let (nm, i) ← Bin.unlebAt d i
  let (ix, _, i) ← stepN (fun (ix, p, i) => do
      let (f, i) ← Bin.unlebAt d i
      let (o, i) ← Bin.unlebAt d i
      let (j, i) ← Bin.unlebAt d i
      guard (i < d.size)
      let x := d[i]!
      guard (x ≤ 1)
      pure (if o < pageSize then ix.push ⟨p, f, o, j, x == 1⟩ else ix, p + 1, i + 1)) nm (#[], 0, i)
  let (np, i) ← Bin.unlebAt d i
  let (ph, i) ← stepN (fun (ph, i) => do
      let (n, i) ← Bin.unlebAt d i
      guard (i + n ≤ d.size)
      pure (ph.push (d.extract i (i + n)), i + n)) np (#[], i)
  guard (i = d.size)
  pure (khs, dlen, ix, ph)

/-- `decMeta3` then `decM` of its chunk metadata, from the bytes. -/
def decM3 (d : ByteArray) : Option M3 := do
  let (ml, i) ← Bin.unlebAt d 0
  guard (i + ml ≤ d.size)
  let (khs, dlen, ix, phash) ← decMA (d.extract i (i + ml))
  let (seq, i) ← Bin.unlebAt d (i + ml)
  let (nt, i) ← Bin.unlebAt d i
  let (ts, i) ← stepN (fun (ts, i) => do
      let (c, i) ← Bin.unlebAt d i
      let (s, i) ← Bin.unlebAt d i
      let (r, i) ← Bin.unlebAt d i
      pure (ts.push ⟨c, s, r⟩, i)) nt (#[], i)
  let (kn, i) ← Bin.unlebAt d i
  let (tk, i) ← khsAt d i kn
  guard (i = d.size)
  pure ⟨seq, ts, tk, khs, dlen, ix, phash⟩

/-- Each key hash of `khs` whose row is not in `born`, in order, inserted for chunk `c` (a loop on the directory, so the
    directory is written in place). -/
def insKhs (khs : Array UInt64) (born : HashSet Nat) (c n : Nat) : Nat → Dir → Except Store.Refusal Dir
  | 0, d => .ok d
  | j + 1, d =>
    let k := n - (j + 1)
    if born.contains k then insKhs khs born c n j d else
    match d.insert khs[k]! c with
    | .ok d' => insKhs khs born c n j d'
    | .error e => .error e

/-- The state while a load replays frames. -/
structure RS where
  fs : Fs
  metas : HashMap Nat CMetaR
  book : Array (Nat × Nat × List Tomb)
  cur : HashSet (Nat × Nat)
  tree : Tree
  head : Bytes
  nx : Nat
  batches : Nat
  logLen : Nat
  au : Bytes
  rq : Bytes

/-- Authority record `b` may follow `a` (layout `Worker.encAuth`: pin 64 ‖ epoch u32 ‖ head 64 ‖ day u32 ‖ cp 64 ‖
    floor u64 ‖ rs 64 ‖ rsv u32): both are `authLen` bytes, under the same key-set pin; neither the key-set epoch, the
    grant floor nor the rule-set version is lower; at the same rule-set version the rule-set digest is the same; and the
    rule-set version is zero exactly when the digest is zero (a record of version zero names no digest). -/
def authFollows (a b : Bytes) : Bool :=
  a.length == authLen && b.length == authLen && a.take 64 == b.take 64 &&
    beNat ((a.drop 64).take 4) ≤ beNat ((b.drop 64).take 4) &&
    beNat ((a.drop 200).take 8) ≤ beNat ((b.drop 200).take 8) &&
    beNat ((a.drop 272).take 4) ≤ beNat ((b.drop 272).take 4) &&
    (beNat ((a.drop 272).take 4) != beNat ((b.drop 272).take 4) || (a.drop 208).take 64 == (b.drop 208).take 64) &&
    (beNat ((b.drop 272).take 4) == 0 || (b.drop 208).take 64 != zeroDigest) &&
    (beNat ((b.drop 272).take 4) != 0 || (b.drop 208).take 64 == zeroDigest)

theorem authFollows_iff {a b : Bytes} : authFollows a b = true ↔ a.length = authLen ∧ b.length = authLen ∧
    a.take 64 = b.take 64 ∧ beNat ((a.drop 64).take 4) ≤ beNat ((b.drop 64).take 4) ∧
    beNat ((a.drop 200).take 8) ≤ beNat ((b.drop 200).take 8) ∧
    beNat ((a.drop 272).take 4) ≤ beNat ((b.drop 272).take 4) ∧
    (beNat ((a.drop 272).take 4) = beNat ((b.drop 272).take 4) → (a.drop 208).take 64 = (b.drop 208).take 64) ∧
    (0 < beNat ((b.drop 272).take 4) → (b.drop 208).take 64 ≠ zeroDigest) ∧
    (beNat ((b.drop 272).take 4) = 0 → (b.drop 208).take 64 = zeroDigest) := by
  simp only [authFollows, Bool.and_eq_true, Bool.or_eq_true, beq_iff_eq, bne_iff_ne, ne_eq, decide_eq_true_eq,
    and_assoc]
  constructor
  · rintro ⟨h1, h2, h3, h4, h5, h6, h7, h8, h9⟩
    refine ⟨h1, h2, h3, h4, h5, h6, fun e => h7.resolve_left (fun n => n e), fun p => h8.resolve_left (by omega),
      fun z => h9.resolve_left (fun n => n z)⟩
  · rintro ⟨h1, h2, h3, h4, h5, h6, h7, h8, h9⟩
    refine ⟨h1, h2, h3, h4, h5, h6, ?_, ?_, ?_⟩
    · by_cases e : beNat ((a.drop 272).take 4) = beNat ((b.drop 272).take 4)
      · exact Or.inr (h7 e)
      · exact Or.inl e
    · by_cases z : beNat ((b.drop 272).take 4) = 0
      · exact Or.inl z
      · exact Or.inr (h8 (by omega))
    · by_cases z : beNat ((b.drop 272).take 4) = 0
      · exact Or.inr (h9 z)
      · exact Or.inl z

/-- Records that each follow the one before keep the first record's key-set pin; its key-set epoch, grant floor and
    rule-set version are a lower bound of every later one; and a later record at its rule-set version has its digest. -/
theorem authFollows_trans {a b c : Bytes} (h1 : authFollows a b = true) (h2 : authFollows b c = true) :
    authFollows a c = true := by
  obtain ⟨a1, -, a3, a4, a5, a6, a7, -, -⟩ := authFollows_iff.mp h1
  obtain ⟨-, b2, b3, b4, b5, b6, b7, b8, b9⟩ := authFollows_iff.mp h2
  refine authFollows_iff.mpr ⟨a1, b2, a3.trans b3, Nat.le_trans a4 b4, Nat.le_trans a5 b5, Nat.le_trans a6 b6,
    fun e => ?_, b8, b9⟩
  have e1 : beNat ((a.drop 272).take 4) = beNat ((b.drop 272).take 4) := by omega
  exact (a7 e1).trans (b7 (by omega))

/-- `replayFrame` on RAM: frame `x` (its metadata bytes `m3`) on `S`, of shard `shard` and starting bucket count `nb0`.
    Where the chunk's slots do not fit, the directory is rebuilt as the writer does (`regrowIo` over the log `fd`).  `S`
    is owned and taken apart first, so the directory is written in place. -/
def replayOne (fd : UInt32) (shard nb0 : Nat) (S : RS) (x : FrameAt) (m3 : ByteArray) : IO (Option RS) := do
  let ⟨⟨_, _, dir0, inst0, dead0, win0, seal0⟩, metas0, book0, cur0, tree0, head0, nx0, batches0, _, au0, _⟩ := S
  let f := x.f
  unless f.shard = shard ∧ f.nb0 = nb0 ∧ f.batches = batches0 + 1 ∧ f.prev = head0 ∧ authFollows au0 f.au do return none
  let r ← match x.c with
    | 0 => pure <|
      if f.nx = nx0 then some (⟨f.hr, f.hu, dir0, inst0, dead0, win0, seal0⟩, book0, cur0, metas0, tree0, nx0) else none
    | c + 1 => do
      let some m := decM3 m3 | pure none
      unless m.seq = nx0 ∧ f.nx = nx0 + 1 ∧ m.ts.size = m.tk.size ∧ x.np = m.phash.size ∧
          inst0.contains c = false ∧ c < 2 ^ cBits ∧ c = nx0 do return none
      let (dead1, dir1) := (Array.range m.ts.size).foldl (fun a k =>
        let t := m.ts[k]?.getD ⟨0, 0, 0⟩
        if t.c ≠ c ∧ cur0.contains (t.c, t.seq) then killRowFast m.tk[k]! a (t.c, t.i, Entry.empty) else a) (dead0, dir0)
      let born : HashSet Nat := m.ts.foldl (fun s t => if t.c = c ∧ t.seq = nx0 then s.insert t.i else s) ∅
      let nb := dir1.nb
      let dir ← match insKhs m.khs born c m.khs.size m.khs.size dir1 with
        | .ok d => pure (some d)
        | .error _ =>
          match ← regrowIo fd metas0 dead1 (inst0.toList.mergeSort fun a b => decide (a ≤ b)) (Dir.empty (2 * nb + 1)) with
          | .ok g => pure (insKhs m.khs born c m.khs.size m.khs.size g).toOption
          | .error _ => pure none
      let some dir := dir | pure none
      let mh := (Bin.HB (domChunkS ++ m3)).toList
      let some tree := tree0.set hl c (some mh) | pure none
      pure (some (⟨f.hr, f.hu, dir, inst0.insert c, dead1.insert c born, ∅, none⟩, book0.push (c, nx0, m.ts.toList),
        cur0.insert (c, nx0), metas0.insert c ⟨x.start + 16, m.dlen, m.khs.size, m.ix, m.phash, mh⟩, tree, nx0 + 1))
  let some (fs3, book, cur, metas, tree, nx) := r | return none
  if f.head = chainStepR hl head0 f.bd (stateRoot3 hl shard nb0 tree.root f.hr f.hu nx f.au f.rq) then
    return some { fs := fs3, metas, book, cur, tree, head := f.head, nx, batches := f.batches,
                  logLen := x.start + x.len, au := f.au, rq := f.rq }
  else return none

/-- The next `n` frames of the log `fd` (`size` bytes), read one by one from where `S` ends and replayed on `S`.  `S` is
    passed on, never kept for a refusal, so each replay writes the directory in place. -/
def replayLog (fd : UInt32) (size shard nb0 : Nat) : Nat → RS → IO (Except String RS)
  | 0, S => pure (.ok S)
  | n + 1, S => do
    let some (x, m3) ← readFrameAt fd size S.logLen | pure (.error "HEAD")
    let some T ← replayOne fd shard nb0 S x m3 | pure (.error "REPLAY")
    replayLog fd size shard nb0 n T

/-- A directory name that is `lock` or `log`. -/
def knownFile (n : String) : Bool := n == "lock" || n == "log"

/-- A new store in `dir`: it holds nothing but its lock, or only the files of a first batch that never completed
    (no whole first frame, which a head could have been released from); those are removed. -/
def initStore (dir : String) (shard asOf nb : Nat) (au : Bytes) : IO (Option CS) := do
  -- a directory with no buckets holds no key
  if nb == 0 then return none
  let names := (← System.FilePath.readDir dir).map (·.fileName)
  unless names.all knownFile do return none
  if names.contains "log" then
    let sz := (← System.FilePath.metadata (logPath dir)).byteSize.toNat
    if sz > 0 then
      let fd ← Io.pgOpen (logPath dir)
      if fd == 0xFFFFFFFF then return none
      let h ← Io.pgRead fd 0 16
      let _ ← Io.pgClose fd
      let tagOk := h.size == 16 && sameAt h 0 (Bin.bytesOf frameTag)
      let whole := tagOk && sz ≥ 16 + (le32At h 4).toNat * pageSize + (le32At h 8).toNat + (le32At h 12).toNat
      if whole || !tagOk then return none
  for n in names do
    if n != "lock" then IO.FS.removeFile s!"{dir}/{n}"
  let fd ← Io.pgOpen (logPath dir)
  if fd == 0xFFFFFFFF then return none
  let g : Snapshot Rules.Line := ⟨asOf, 0, []⟩
  return some { dir, shard, nb0 := nb, fs := ⟨⟨asOf, 0, 0⟩, ⟨asOf, 0, 0⟩, Dir.empty nb, ∅, ∅, ∅, none⟩, tree := Tree.empty hl,
                head := chainStart hl shard (au.take 64) (g, g), batches := 0, log := fd, au }

/-- A batch's changed entries (`kb`, new entry) and the live rows of those keys (`kills`, read before the batch) go
    through `writeBatch`'s steps: kills (dead bits, slots), the window sealed, sorted and placed in the smallest free
    chunk number (`place`; on `full`, `regrowH` once from the book, the live hashes read from the log), metadata v3, tree
    leaf, state root v3 (binding the request digest `rq`) and head.  Then the writes of `stepOps`: the frame appended
    (body, then trailer) and one sync, the commit.  `cs` is owned: its parts are taken apart, so the directory, dead
    bits and window change in place.  On `Except`'s error the log is closed. -/
def installBatch (pf : Prof) (crash : String) (cs : CS) (changed : Array (Bytes × Entry))
    (kills : HashMap Bytes (List (Nat × Nat × Entry))) (hr hu : Head) (au bd rq : Bytes) (check : Option String) :
    IO (Except String CS) := do
  let ⟨dir, shard, nb0, fs, metas, tree, head, batches, book, nx, log, logLen, _, _, pnd, _⟩ := cs
  let ⟨_, _, fdir, inst, dead, _, _⟩ := fs
  let fail (why : String) : IO (Except String CS) := do let _ ← Io.pgClose log; pure (.error why)
  -- a kill of a row of a chunk that is not installed would set a dead bit no tombstone carries
  if changed.any (fun ke => (kills.getD ke.1 []).any fun x => !inst.contains x.1) then return ← fail "KILL"
  let prep ← tp pf 4 (fun _ =>
    let kd := changed.foldl (fun a ke => ((kills.getD ke.1 []).foldl (killRowFast (kh ke.1)) a)) (dead, fdir)
    let fs1 : Fs := { hr, hu, dir := kd.2, inst, dead := kd.1, win := changed.foldl (fun m ke => m.insert ke.1 ke.2) ∅,
                      sealing := none }
    if changed.isEmpty then (some (fs1, 0, ([] : List Row), fs1.dir.nb), none) else
    match sealWindow fs1, freeNum fs1.inst (2 ^ cBits) 0 with
    | some fs2, some c => (some (fs2, c, sortRows kh (fs2.sealing.getD ∅).toList, fs2.dir.nb), none)
    | _, _ => (none, some "NUMBER")) fun r => (r.1.elim 0 (·.2.2.1.length))
  let some (fs2, c, ws, nb) := prep.1 | fail (prep.2.getD "NUMBER")
  let pend : List Tomb := changed.toList.flatMap fun ke => (kills.getD ke.1 []).map fun x => ⟨x.1, seqOf book x.1, x.2.1⟩
  let pendK : List Nat := changed.toList.flatMap fun ke => (kills.getD ke.1 []).map fun _ => (kh ke.1).toNat
  let ts := placeTombs fs2.win c nx ws pend
  let tk := pendK ++ bornKh kh fs2.win ws
  let win2 := fs2.win
  let placed ← if changed.isEmpty then pure (some fs2) else do
    let r ← tp pf 5 (fun _ => placeFast kh fs2 c ws) fun r => match r with | .ok p => p.dir.nb | .error _ => 0
    match r with
    | .ok p => pure (some p)
    | .error _ =>
      match ← regrowIo log metas (deadOf book pend) ((book.map (·.1)).mergeSort fun a b => decide (a ≤ b)) (Dir.empty (2 * nb + 1)) with
      | .ok d => pure ((placeFast kh ⟨hr, hu, d, HashSet.ofList (book.map (·.1)), deadOf book pend, win2, none⟩ c ws).toOption)
      | .error _ => pure none
  let some fs3 := placed | fail "FULL"
  -- an empty batch writes no chunk: `encFast []` would read the key hash of a row that is not there (a panic message)
  let enc ← tp pf 13 (fun _ => if changed.isEmpty then ⟨ByteArray.empty, ByteArray.empty, #[], #[], 0, 0⟩ else encFast ws)
    (·.file.size)
  let m3 := Bin.bytesOf (encMeta3 enc.mdata.toList nx ts tk)
  let mh := (Bin.HB (domChunkS ++ m3)).toList
  let tree' ← if changed.isEmpty then pure (some tree) else
    tp pf 11 (fun _ => tree.set hl c (some mh)) (·.elim 0 (·.nodes.size))
  let some tree' := tree' | fail "TREE"
  let nx' := if changed.isEmpty then nx else nx + 1
  let book' := if changed.isEmpty then book else book ++ [(c, nx, ts)]
  let metas' := if changed.isEmpty then metas else
    metas.insert c ⟨logLen + 16, enc.rowBytes, enc.nrows, enc.ix, enc.phash, mh⟩
  let rows := if changed.isEmpty then 0 else ws.length
  let batches' := batches + 1
  let ch : Option (Nat × List Bytes × Bytes) := if changed.isEmpty then none else some (c, [], [])
  let head' := chainStepR hl head bd (stateRoot3 hl shard nb0 tree'.root hr hu nx' au rq)
  let fr : Frame := ⟨ch, shard, nb0, batches', hr, hu, nx', au, rq, head, bd, head'⟩
  let trailer := Bin.bytesOf (frameTrailer fr)
  let body := if changed.isEmpty then Bin.bytesOf (frameHdr 0 0 trailer.size) else
    Bin.bytesOf (frameHdr (enc.file.size / pageSize) m3.size trailer.size) ++ enc.file ++ m3
  -- bench count: the bytes this batch's page and metadata hashes read (the tree path, state root and chain step are a few
  -- hundred bytes per batch, whatever the history)
  let hashed := (enc.file.size / pageSize) * (pageSize + domPageS.size) + domChunkS.size + m3.size
  let syncs ← IO.mkRef 0
  let sync : IO UInt32 := do syncs.modify (· + 1); ti pf 7 (Io.pgSync log)
  -- a frame the format cannot hold (`Frame.Wf`: a 32-bit length or a 64-bit counter overflows, a hash is not 64 bytes)
  unless decide fr.Wf && enc.file.size / pageSize < 2 ^ 32 && m3.size < 2 ^ 32 do return ← fail "FRAME"
  if let some chk := check then
    let t0 ← IO.monoNanosNow
    let same ← IO.lazyPure fun _ =>
      changed.isEmpty || (let mc := encChunk hl kh ws
        mc.pages.flatten == enc.file.toList && mc.mdata == enc.mdata.toList)
    let t1 ← IO.monoNanosNow
    IO.FS.withFile ⟨chk⟩ .append fun h =>
      h.putStr s!"batch {batches'} chunk {c} rows {rows} same {same} model_us {(t1 - t0) / 1000}\n"
  -- a retry of a batch whose frame is already in the log, unsigned: decided again, it must come out as the same bytes
  if let some (_, _, pb) := pnd then
    let fb := body ++ trailer
    unless pb.size == fb.size && sameAt pb 0 fb do return ← fail "PENDING"
  let ok ← try
      if pnd.isNone then
        if (← ti pf 6 (Io.pgWrite log logLen.toUInt64 body)) != 0 then throw (IO.userError "body")
        -- the crash test's torn frame: the body written, the trailer not
        stopAt crash "frame" "torn"
        if (← Io.pgWrite log (logLen + body.size).toUInt64 trailer) != 0 then throw (IO.userError "trailer")
        stopAt crash "frame" "write"
      if (← sync) != 0 then throw (IO.userError "sync")
      stopAt crash "frame" "sync"
      pure true
    catch _ => pure false
  unless ok do return ← fail "IO"
  return .ok { dir, shard, nb0, fs := fs3, metas := metas', tree := tree', head := head', batches := batches',
               book := book', nx := nx', log, logLen := logLen + body.size + trailer.size, au, rq, stat := (hashed, ← syncs.get) }

/-! ## Load -/

/-- Opens the store in `dir` at the signed head `hd` and batch count `bt` (`loadLog`, on byte arrays).  Batch 0 is
    refused as a head mismatch (a store is opened at batch 0 only by `flat init`): no frame says the shard or the bucket
    count.  The files must be `lock` and `log`.  Frames are read one by one from the front, header, metadata and trailer
    only, and each is replayed (`replayFrame`) from the empty store of the first frame's shard and bucket count, so the
    chain and every frame's metadata are checked; the first frame must follow the genesis under its record's key-set pin,
    and each frame's authority record must follow the one before it (`authFollows`); frame `bt` must hold `hd`.  A whole frame after it (a batch never
    released) must replay too and is kept as `pend` for a retry with the same request bytes (`retryOf`); a torn tail is
    cut.  `Except` names a refusal. -/
def openStore (dir : String) (hd : Bytes) (bt : Nat) (check : Option String) : IO (Except String CS) := do
  if bt == 0 then return .error "HEAD"
  let names := (← System.FilePath.readDir dir).map (·.fileName)
  unless names.all knownFile do return .error "FILES"
  unless names.contains "log" do return .error "LOG"
  let fd ← Io.pgOpen (logPath dir)
  if fd == 0xFFFFFFFF then return .error "IO"
  let fail (why : String) : IO (Except String CS) := do let _ ← Io.pgClose fd; pure (.error why)
  let size := (← System.FilePath.metadata (logPath dir)).byteSize.toNat
  let some (x0, _) ← readFrameAt fd size 0 | fail "HEAD"
  let f0 := x0.f
  -- the first frame follows the genesis of its shard and date under the key-set pin of its authority record
  let g0 : Snapshot Rules.Line := ⟨f0.hr.asOf, 0, []⟩
  unless f0.prev == chainStart hl f0.shard (f0.au.take 64) (g0, g0) do return ← fail "HEAD"
  -- the empty store's heads and authority record are never read: every frame replaces them
  let S : RS := ⟨⟨⟨0, 0, 0⟩, ⟨0, 0, 0⟩, Dir.empty f0.nb0, ∅, ∅, ∅, none⟩, ∅, #[], ∅, Tree.empty hl, f0.prev, 0, 0, 0,
                 f0.au, f0.rq⟩
  let S ← match ← replayLog fd size f0.shard f0.nb0 bt S with
    | .ok S => pure S
    | .error why => return ← fail why
  unless S.head == hd && S.batches == bt do return ← fail "HEAD"
  let pr ← match ← readFrameAt fd size S.logLen with
    | none => pure (Except.ok none)
    | some (x, m3) =>
      -- `S` is shared here, so the replay of the pending frame copies what it writes and `S` stays as it was
      match ← replayOne fd f0.shard f0.nb0 S x m3 with
      | none => pure (.error "REPLAY")
      | some _ =>
        if (← readFrameAt fd size (x.start + x.len)).isSome then pure (.error "HEAD") else
        pure (.ok (some (x.f.rq, x.f.au, ← Io.pgRead fd x.start.toUInt64 x.len.toUSize)))
  let pend ← match pr with
    | .ok p => pure p
    | .error why => return ← fail why
  -- this engine runs no rule set and writes rule-set version 0: a store whose record names one is not opened
  unless (S.au :: pend.toList.map (·.2.1)).all (fun a => beNat ((a.drop 272).take 4) == 0) do return ← fail "CORRUPT"
  if let some chk := check then
    IO.FS.withFile ⟨chk⟩ .append fun h => h.putStrLn s!"load frames {bt + if pend.isSome then 1 else 0} replayed {bt}"
  try
    let keep := S.logLen + (pend.elim 0 (·.2.2.size))
    if size > keep then
      if (← Io.pgTrunc fd keep.toUInt64) != 0 || (← Io.pgSync fd) != 0 then throw (IO.userError "trunc")
  catch _ => return ← fail "IO"
  return .ok { dir, shard := f0.shard, nb0 := f0.nb0, fs := S.fs, metas := S.metas, tree := S.tree, head := S.head,
               batches := S.batches, book := S.book.toList, nx := S.nx, log := fd, logLen := S.logLen, au := S.au,
               rq := S.rq, pend }

end BlindLedger.Gate.Flat.ChunkIo
