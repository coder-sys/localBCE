import BlindLedger.Gate.Flat.StoreTombs
import Std.Data.String.ToNat

/-! The chunk store's log format (v2): definitions and statements to prove before it replaces the per-chunk files.
    Proved here: a load of the log the writer produced replays to the writer's state; a crash at any point of a batch's
    writes loads to the state before the batch or the state after it (and the repair cuts the log back to a whole
    frame); and whatever the files hold, a load at the signed head gives the writer's state or exhibits two distinct
    inputs with one digest (`load_binds`).

    A store directory holds `log` and `lock`.  Each batch appends one frame to `log` and syncs it once: the new chunk's
    pages and metadata, then the trailer, which commits the batch: the shard, the starting bucket count, the batch
    count, set heads, next install number, authority record, the request digest, the head before, the batch digest and
    the head.  No image of the RAM state is ever written, so a batch's work does not grow with the store.  Load replays
    every frame from the first exactly as the writer ran it (growing the directory where the writer did), recomputing
    every state root and head up to the signed head, and keeps a whole frame one batch past it (never released) for a
    retry with the same request bytes.  Pages are checked against their hashes when read.

    Synthetic, nonpayment, non-PHI, activation=false. -/

namespace BlindLedger.Gate.Flat.StoreLog

open Chunk Store
open BlindLedger.Gate.Rules
open BlindLedger.Gate.OnepIndex (leb unleb unleb_leb)
open Std (HashMap HashSet)

/-- Two distinct inputs with one digest. -/
def Collides (H : Bytes → Bytes) : Prop := ∃ x y, x ≠ y ∧ H x = H y

/-! ## Disk and writes -/

/-- The store directory: each file name's bytes, `none` where no file is. -/
abbrev Disk := String → Option Bytes

def Disk.empty : Disk := fun _ => none

def Disk.set (d : Disk) (f : String) (v : Option Bytes) : Disk := fun g => if g = f then v else d g

/-- `names` are exactly the files present. -/
def Lists (d : Disk) (names : List String) : Prop := ∀ f, (d f).isSome = true ↔ f ∈ names

/-- One write the store makes.  `put` writes a whole file (created, or cut to the bytes).  `rename`, `trunc` and `del`
    are journaled metadata changes, each applied whole or not at all. -/
inductive Op
  | append (f : String) (b : Bytes)
  | put (f : String) (b : Bytes)
  | sync (f : String)
  | rename (a b : String)
  | trunc (f : String) (n : Nat)
  | del (f : String)

def Op.run : Op → Disk → Disk
  | .append f b, d => d.set f (some ((d f).getD [] ++ b))
  | .put f b, d => d.set f (some b)
  | .sync _, d => d
  | .rename a b, d => match d a with
    | some x => (d.set b (some x)).set a none
    | none => d
  | .trunc f n, d => d.set f ((d f).map (·.take n))
  | .del f, d => d.set f none

/-- The file a data write fills. -/
def Op.data : Op → Option String
  | .append f _ => some f
  | .put f _ => some f
  | _ => none

/-- A write cut short by a crash: an append or a whole-file write keeps only its first `n` bytes; any other is whole. -/
def Op.part : Op → Nat → Op
  | .append f b, n => .append f (b.take n)
  | .put f b, n => .put f (b.take n)
  | o, _ => o

def runOps (ops : List Op) (d : Disk) : Disk := ops.foldl (fun d o => o.run d) d

/-- The disk after a crash during write `i` of `ops`: the writes before it whole, write `i` cut to `n` bytes
    (`i = ops.length` is no crash). -/
def crash (ops : List Op) (i n : Nat) (d : Disk) : Disk :=
  runOps (ops.take i ++ (ops[i]?.map (·.part n)).toList) d

/-- Each data write is synced at once, so no later byte reaches the disk before an earlier one and a crash leaves
    exactly a `crash` prefix. -/
def SyncedOrder (ops : List Op) : Prop :=
  ∀ i f, (ops[i]?.bind Op.data) = some f → ops[i + 1]? = some (.sync f)

/-! ## Frames -/

/-- A 32-bit number, little endian. -/
def le32 (n : Nat) : Bytes := (natBE 4 n).reverse

def unle32 (bs : Bytes) : Option (Nat × Bytes) := do
  let (b, r) ← takeN 4 bs
  pure (beNat b.reverse, r)

/-- Metadata v3: v2's bytes, then the key hash of each tombstone's row (counted, 8 bytes each), so a replay takes the
    killed row's slot without reading its page. -/
def encMeta3 (m : Bytes) (seq : Nat) (ts : List Tomb) (tk : List Nat) : Bytes :=
  encMeta2 m seq ts ++ leb tk.length ++ tk.flatMap (natBE 8)

/-- `encMeta3`'s fields, all bytes used. -/
def decMeta3 (bs : Bytes) : Option (Bytes × Nat × List Tomb × List Nat) := do
  let (ml, r) ← unleb bs
  let (m, r) ← takeN ml r
  let (seq, r) ← unleb r
  let (n, r) ← unleb r
  let (ts, r) ← decTombs n r
  let (kn, r) ← unleb r
  let (tk, r) ← decKhs kn r
  if r.isEmpty then pure (m, seq, ts, tk) else none

/-- One batch's frame: the installed chunk (number, pages, metadata v3), none when the batch changed nothing; then the
    trailer's fields. -/
structure Frame where
  chunk : Option (Nat × List Bytes × Bytes)
  shard : Nat
  /-- The directory's bucket count at the store's creation (load starts from it). -/
  nb0 : Nat
  batches : Nat
  hr : Head
  hu : Head
  nx : Nat
  /-- The shard's authority record after the batch (grant serial floor, key-set ratchet, genesis pin), `authLen` bytes. -/
  au : Bytes
  /-- The request digest, SHA3-512 of `"FLAT/REQUEST"` and the request bytes as the host sent them (a retry sends
      them unchanged, Constitution III.3). -/
  rq : Bytes
  prev : Bytes
  bd : Bytes
  head : Bytes

/-- The chunk number plus one in the trailer; 0 when the batch changed nothing. -/
def Frame.cnum (f : Frame) : Nat := match f.chunk with | some x => x.1 + 1 | none => 0

/-- Pages of `pageSize` bytes, lengths within the header's 32-bit fields, the trailer's numbers below 2^64 (so the
    trailer's length fits its 32-bit field too), hashes of 64 bytes. -/
def Frame.Wf (f : Frame) : Prop :=
  (∀ x ∈ f.chunk, (∀ p ∈ x.2.1, p.length = pageSize) ∧ x.2.1.length < 2 ^ 32 ∧ x.2.2.length < 2 ^ 32) ∧
  (∀ n ∈ [f.shard, f.nb0, f.batches, f.cnum, f.hr.asOf, f.hr.count, f.hr.n, f.hu.asOf, f.hu.count, f.hu.n, f.nx],
    n < 2 ^ 64) ∧
  f.au.length = authLen ∧ f.rq.length = 64 ∧ f.prev.length = 64 ∧ f.bd.length = 64 ∧ f.head.length = 64

instance (f : Frame) : Decidable f.Wf := by unfold Frame.Wf; infer_instance

/-- The tag `RRF2`. -/
def frameTag : Bytes := [0x52, 0x52, 0x46, 0x32]

/-- The 16-byte header: tag, page count, metadata length, trailer length (32 bits, little endian). -/
def frameHdr (np ml tl : Nat) : Bytes := frameTag ++ le32 np ++ le32 ml ++ le32 tl

/-- The trailer: the tagged fields after the chunk; once it is on disk the batch is committed. -/
def frameTrailer (f : Frame) : Bytes :=
  domain "FLAT/FRAME" ++ leb f.shard ++ leb f.nb0 ++ leb f.batches ++ leb f.cnum ++ encHead f.hr ++ encHead f.hu ++
    leb f.nx ++ f.au ++ f.rq ++ f.prev ++ f.bd ++ f.head

/-- The header, the pages, the metadata. -/
def frameBody (f : Frame) : Bytes :=
  match f.chunk with
  | some x => frameHdr x.2.1.length x.2.2.length (frameTrailer f).length ++ x.2.1.flatten ++ x.2.2
  | none => frameHdr 0 0 (frameTrailer f).length

def encFrame (f : Frame) : Bytes := frameBody f ++ frameTrailer f

/-- The trailer's fields (the chunk number plus one, then the frame without its chunk), all bytes used. -/
def decTrailer (bs : Bytes) : Option (Nat × Frame) := do
  let (t, r) ← takeN (domain "FLAT/FRAME").length bs
  let r ← if t = domain "FLAT/FRAME" then some r else none
  let (sh, r) ← unleb r
  let (nb, r) ← unleb r
  let (b, r) ← unleb r
  let (c, r) ← unleb r
  let (hr, r) ← decHead r
  let (hu, r) ← decHead r
  let (nx, r) ← unleb r
  let (au, r) ← takeN authLen r
  let (rq, r) ← takeN 64 r
  let (pv, r) ← takeN 64 r
  let (bd, r) ← takeN 64 r
  let (hd, r) ← takeN 64 r
  if r.isEmpty then pure (c, ⟨none, sh, nb, b, hr, hu, nx, au, rq, pv, bd, hd⟩) else none

/-- `n` pages of `pageSize` bytes from the front of `bs`. -/
def splitPages : Nat → Bytes → List Bytes
  | 0, _ => []
  | n + 1, b => b.take pageSize :: splitPages n (b.drop pageSize)

/-- The frame at the front of `bs` and the bytes after it; `none` unless a whole frame is there. -/
def decFrame (bs : Bytes) : Option (Frame × Bytes) := do
  let (t, r) ← takeN 4 bs
  let r ← if t = frameTag then some r else none
  let (np, r) ← unle32 r
  let (ml, r) ← unle32 r
  let (tl, r) ← unle32 r
  let (pg, r) ← takeN (np * pageSize) r
  let (m, r) ← takeN ml r
  let (tb, r) ← takeN tl r
  let (c, f) ← decTrailer tb
  match c with
  | 0 => if np = 0 ∧ ml = 0 then pure (f, r) else none
  | c + 1 => pure ({ f with chunk := some (c, splitPages np pg, m) }, r)

/-! ## RAM records of installed chunks -/

/-- What RAM keeps of an installed chunk: where its pages start in the log, its row bytes and row count, the index
    (page, fence, offset, row, fresh of each page a row starts in), the page hashes and its tree leaf's hash. -/
structure CR where
  base : Nat
  rowBytes : Nat
  nrows : Nat
  ix : List (Nat × Nat × Nat × Nat × Bool)
  phs : List Bytes
  mh : Bytes

/-- What RAM keeps of a chunk whose pages start at log offset `base`, from its decoded metadata and its leaf hash. -/
def CR.ofMeta (base : Nat) (m : CMeta) (mh : Bytes) : CR :=
  ⟨base, m.dlen, m.khs.length,
    m.marks.zipIdx.filterMap fun ((f, o, j, fr), p) => if o < pageSize then some (p, f, o, j, fr) else none, m.phs, mh⟩

/-- `x` into the installed chunks, ascending by number. -/
def insertCR (L : List (Nat × CR)) (x : Nat × CR) : List (Nat × CR) :=
  (L ++ [x]).mergeSort fun a b => decide (a.1 ≤ b.1)


/-- The state root (v3): the shard, the starting bucket count, the tree root, the set heads, the next install number,
    the authority record and the request digest. -/
def stateRoot3 (H : Bytes → Bytes) (k nb0 : Nat) (tr : Bytes) (hr hu : Head) (nx : Nat) (au rq : Bytes) : Bytes :=
  H (domain "STORE/STATE3" ++ leb k ++ leb nb0 ++ tr ++ encHead hr ++ encHead hu ++ leb nx ++ encBs au ++ encBs rq)

/-! ## The committed state -/

/-- What a commit point holds (both windows empty): layout, book, chunks, tree, head, the log length. -/
structure LState where
  shard : Nat
  /-- The directory's bucket count at creation: load starts from it and grows where the writer grew. -/
  nb0 : Nat
  batches : Nat
  fs : Fs
  book : Book
  nx : Nat
  chunks : List (Nat × CR)
  tree : Tree
  head : Bytes
  logLen : Nat
  /-- The authority record the last frame carries (`Frame.au`). -/
  au : Bytes

/-- Equal as state: the installed chunks and dead bits as sets and the tree by contents (the same empty nodes and the
    same stored node at every position, whatever the hash map's layout); the directory itself is equal. -/
def LState.Same (a b : LState) : Prop :=
  a.shard = b.shard ∧ a.nb0 = b.nb0 ∧ a.batches = b.batches ∧ a.fs.hr = b.fs.hr ∧ a.fs.hu = b.fs.hu ∧
  a.fs.dir = b.fs.dir ∧
  (∀ c, a.fs.inst.contains c = b.fs.inst.contains c) ∧ (∀ c i, isDead a.fs.dead c i = isDead b.fs.dead c i) ∧
  a.fs.win.isEmpty = true ∧ b.fs.win.isEmpty = true ∧ a.fs.sealing = none ∧ b.fs.sealing = none ∧
  a.book = b.book ∧ a.nx = b.nx ∧ a.chunks = b.chunks ∧
  (a.tree.emp = b.tree.emp ∧ ∀ k : Nat × Nat, a.tree.nodes[k]? = b.tree.nodes[k]?) ∧
  a.head = b.head ∧ a.logLen = b.logLen ∧ a.au = b.au

/-- The empty store of shard `shard`: no chunk, no frame, `nb` buckets, head `chainStart` under the key-set pin `au` opens
    with (its first 64 bytes), authority record `au`. -/
def LState.genesis (H : Bytes → Bytes) (shard asOf nb : Nat) (au : Bytes) : LState :=
  let g : Snapshot Rules.Line := ⟨asOf, 0, []⟩
  { shard, nb0 := nb, batches := 0, fs := ⟨⟨asOf, 0, 0⟩, ⟨asOf, 0, 0⟩, Dir.empty nb, ∅, ∅, ∅, none⟩, book := [],
    nx := 0, chunks := [], tree := Tree.empty H, head := chainStart H shard (au.take 64) (g, g), logLen := 0, au }

/-! ## Writing a batch -/

/-- A batch as the decision hands it over: the changed entries in order, the live rows each changed key had (read
    before the batch), the set heads after it, its digest and its request's digest. -/
structure BatchIn where
  changed : List (Bytes × Entry)
  kills : Bytes → List (Nat × Nat × Entry)
  hr : Head
  hu : Head
  /-- The authority record after the batch. -/
  au : Bytes
  bd : Bytes
  /-- The request digest (`Frame.rq`). -/
  rq : Bytes
  /-- The rows of every installed chunk, read when a directory growth needs them (the only use). -/
  rows : Nat → List Row

/-- `Store.regrow` over the installed chunks in ascending number, so the grown directory depends on the installed set
    and dead bits only, never on a hash set's order (replaces `Store.regrow`). -/
def regrowC (kh : Bytes → UInt64) (fs : Fs) (rows : Nat → List Row) : Except Store.Refusal Fs :=
  (Dir.rebuild (2 * fs.dir.nb + 1)
      ((fs.inst.toList.mergeSort fun a b => decide (a ≤ b)).map fun c => (c, liveHashes kh fs.dead c (rows c)))).map
    fun d => { fs with dir := d }

/-- `regrowC` from each installed chunk's live key hashes (`hs c = liveHashes kh fs.dead c (rows c)`), so the host never
    holds more than one chunk's rows. -/
def regrowH (kh : Bytes → UInt64) (fs : Fs) (hs : Nat → List UInt64) : Except Store.Refusal Fs :=
  (Dir.rebuild (2 * fs.dir.nb + 1) ((fs.inst.toList.mergeSort fun a b => decide (a ≤ b)).map fun c => (c, hs c))).map
    fun d => { fs with dir := d }

theorem regrowH_eq (kh : Bytes → UInt64) (fs : Fs) (rows : Nat → List Row) :
    regrowH kh fs (fun c => liveHashes kh fs.dead c (rows c)) = regrowC kh fs rows := rfl

/-- One batch's result: the frame, whether the directory grew, the state after. -/
structure Step where
  frame : Frame
  grew : Bool
  next : LState

/-- Batch `b` on committed state `S`, as `ChunkIo.installBatch` runs it: refused `kill` when a kill names a chunk that
    is not installed; kills (dead bits set, slots taken), window sealed, sorted and placed at the smallest free number
    (`Store.place`; on `full`, `regrowC` once, from the book's installed set and dead bits); metadata v3 with the pending
    tombstones, their rows' key hashes and the rows dead at birth; the tree leaf; the state root v3 and the head;
    refused `frame` when the frame is one the format cannot hold (`Frame.Wf`: a 32-bit length or a 64-bit counter
    overflows, a hash is not 64 bytes).  A refusal writes nothing. -/
def writeDone (H : Bytes → Bytes) (kh : Bytes → UInt64) (S : LState) (b : BatchIn) (fs3 : Fs)
    (cw : Option (Nat × List Row × List Tomb × List Nat)) (grew : Bool) : Except Store.Refusal Step := do
  let (tree, book, chunks, nx, ch) ← match cw with
    | none => pure (S.tree, S.book, S.chunks, S.nx, none)
    | some (c, ws, ts, tk) => do
      let ec := encChunk H kh ws
      let m3 := encMeta3 ec.mdata S.nx ts tk
      let mh := H (domain "STORE/CHUNK" ++ m3)
      let some tree := S.tree.set H c (some mh) | throw .noNumber
      pure (tree, S.book ++ [(c, S.nx, ts)],
        insertCR S.chunks (c, CR.ofMeta (S.logLen + 16) (metaOf H kh ws ec.pages) mh), S.nx + 1, some (c, ec.pages, m3))
  let head := chainStepR H S.head b.bd (stateRoot3 H S.shard S.nb0 tree.root b.hr b.hu nx b.au b.rq)
  let fr : Frame := ⟨ch, S.shard, S.nb0, S.batches + 1, b.hr, b.hu, nx, b.au, b.rq, S.head, b.bd, head⟩
  if fr.Wf then
    pure ⟨fr, grew, { S with batches := S.batches + 1, fs := fs3, book, nx, chunks, tree, head, au := b.au,
                             logLen := S.logLen + (encFrame fr).length }⟩
  else .error .frame

/-- The key hashes of the rows of `ws` whose key `win` holds (born dead), in row order. -/
def bornKh (kh : Bytes → UInt64) (win : Std.HashMap Bytes Entry) (ws : List Row) : List Nat :=
  (ixs 0 ws).filterMap fun iw => if win.contains iw.2.1 then some (kh iw.2.1).toNat else none

def writeBatch (H : Bytes → Bytes) (kh : Bytes → UInt64) (S : LState) (b : BatchIn) :
    Except Store.Refusal Step :=
  -- a kill of a row of a chunk that is not installed would set a dead bit no tombstone carries: refused
  if b.changed.any (fun ke => (b.kills ke.1).any fun x => !S.fs.inst.contains x.1) then .error .kill else
  let kd := b.changed.foldl (fun a ke => (b.kills ke.1).foldl (killRow (kh ke.1)) a) (S.fs.dead, S.fs.dir)
  let fs1 : Fs := { S.fs with hr := b.hr, hu := b.hu, dead := kd.1, dir := kd.2,
                              win := b.changed.foldl (fun m ke => m.insert ke.1 ke.2) S.fs.win }
  let pend : List Tomb := b.changed.flatMap fun ke => (b.kills ke.1).map fun x => ⟨x.1, seqOf S.book x.1, x.2.1⟩
  let pendK : List Nat := b.changed.flatMap fun ke => (b.kills ke.1).map fun _ => (kh ke.1).toNat
  if b.changed.isEmpty then writeDone H kh S b fs1 none false else
  match sealWindow fs1, freeNum fs1.inst (2 ^ cBits) 0 with
  | none, _ => .error .unsealed
  | some _, none => .error .noNumber
  | some fs2, some c =>
    let ws := sortRows kh (fs2.sealing.getD ∅).toList
    let cw := some (c, ws, placeTombs fs2.win c S.nx ws pend, pendK ++ bornKh kh fs2.win ws)
    match place kh fs2 c ws with
    | .ok p => writeDone H kh S b p cw false
    | .error _ =>
      match regrowC kh { fs2 with inst := HashSet.ofList (S.book.map (·.1)), dead := deadOf S.book pend } b.rows with
      | .ok g => (place kh g c ws).bind fun p => writeDone H kh S b p cw true
      | .error e => .error e

/-- A step's writes: the frame appended to `log`, then one sync, which commits the batch.  A crash leaves the frame
    torn (part written), written whole but not synced, or synced. -/
def stepOps (st : Step) : List Op := [.append "log" (encFrame st.frame), .sync "log"]

/-- The live key hashes of installed chunk `c` from its rows' key hashes `khs` (metadata order), dead rows left out:
    `liveHashes` without reading the rows. -/
def liveKhs (dead : HashMap Nat (HashSet Nat)) (c : Nat) (khs : List Nat) : List UInt64 :=
  (khs.map Nat.toUInt64).zipIdx.filterMap fun (h, i) => if isDead dead c i then none else some h

/-- One frame replayed on the state before it, `khs c` the key hashes of installed chunk `c`'s rows: tombstones on
    older chunks set dead bits and take their rows' slots (by the key hashes metadata v3 holds), the chunk is placed
    with its own tombstones dead at birth and a slot for each other row's key hash in row order (where that fails, as
    the writer does: the directory rebuilt once with twice the buckets plus one from the installed chunks' live key
    hashes in ascending number, then the slots), tree, book, counts and heads advance, and the state root and head are
    recomputed; `none` unless that head is the frame's. -/
def replayFrame (H : Bytes → Bytes) (khs : Nat → List Nat) (S : LState) (f : Frame) : Option LState := do
  let _ ← if f.shard = S.shard ∧ f.nb0 = S.nb0 ∧ f.batches = S.batches + 1 ∧ f.prev = S.head then some () else none
  let (fs3, book, chunks, tree, nx) ← match f.chunk with
    | none =>
      if f.nx = S.nx then some ({ S.fs with hr := f.hr, hu := f.hu }, S.book, S.chunks, S.tree, S.nx) else none
    | some (c, pages, m3) => do
      let (md, seq, ts, tk) ← decMeta3 m3
      let cm ← decM md
      let _ ← if seq = S.nx ∧ f.nx = S.nx + 1 ∧ ts.length = tk.length ∧ pages.length = cm.phs.length ∧
          S.fs.inst.contains c = false ∧ c < 2 ^ cBits ∧ c = S.nx then some () else none
      let kd := (ts.zip tk).foldl (fun a p =>
        if p.1.c ≠ c ∧ current S.book p.1 then killRow p.2.toUInt64 a (p.1.c, p.1.i, Entry.empty) else a)
        (S.fs.dead, S.fs.dir)
      let born : HashSet Nat := (ts.filter fun t => t.c = c ∧ t.seq = S.nx).foldl (fun s t => s.insert t.i) ∅
      let hs : List UInt64 :=
        (cm.khs.map Nat.toUInt64).zipIdx.filterMap fun (h, i) => if born.contains i then none else some h
      let dir ← match hs.foldlM (fun (d : Dir) h => d.insert h c) kd.2 with
        | .ok d => some d
        | .error _ => do
          let g ← (Dir.rebuild (2 * kd.2.nb + 1) ((S.fs.inst.toList.mergeSort fun a b => decide (a ≤ b)).map
            fun x => (x, liveKhs kd.1 x (khs x)))).toOption
          (hs.foldlM (fun (d : Dir) h => d.insert h c) g).toOption
      let mh := H (domain "STORE/CHUNK" ++ m3)
      let tree ← S.tree.set H c (some mh)
      pure (⟨f.hr, f.hu, dir, S.fs.inst.insert c, kd.1.insert c born, ∅, none⟩, S.book ++ [(c, S.nx, ts)],
        insertCR S.chunks (c, CR.ofMeta (S.logLen + 16) cm mh), tree, S.nx + 1)
  if f.head = chainStepR H S.head f.bd (stateRoot3 H S.shard S.nb0 tree.root f.hr f.hu nx f.au f.rq) then
    some { S with batches := f.batches, fs := fs3, book, nx, chunks, tree, head := f.head,
                  logLen := S.logLen + (encFrame f).length, au := f.au }
  else none

/-! ## Loading -/

/-- At most `fuel` whole frames in a row from the front of `bs`. -/
def decFrames : Nat → Bytes → List Frame
  | 0, _ => []
  | f + 1, b => match decFrame b with
    | some (fr, r) => fr :: decFrames f r
    | none => []

/-- The key hashes of chunk `c`'s rows, from the metadata of the first of `frs` that installs it. -/
def khsOf (frs : List Frame) (c : Nat) : List Nat :=
  (frs.findSome? fun f => match f.chunk with
    | some (x, _, m3) => if x = c then (decMeta3 m3 >>= fun y => decM y.1).map (·.khs) else none
    | none => none).getD []

/-- What the writer's batch hands over for a growth, `b.rows`, agrees with the log: every installed chunk's rows have the
    key hashes the log's metadata holds for it.  The writer reads the rows from the chunk's own pages, which the
    metadata was made from, and a reload regrows from the metadata. -/
def RowsAgree (kh : Bytes → UInt64) (d : Disk) (S : LState) (b : BatchIn) : Prop :=
  ∀ c, S.fs.inst.contains c = true →
    (b.rows c).map (fun r => (kh r.1).toNat) = khsOf (decFrames ((d "log").getD []).length ((d "log").getD [])) c

/-- The disks the writer reaches: genesis (at least one bucket); a batch's writes (its rows agree with the log); the
    same disk at an equal state. -/
inductive Reach (H : Bytes → Bytes) (kh : Bytes → UInt64) : Disk → LState → Prop
  | genesis (shard asOf nb : Nat) (au : Bytes) : 0 < nb → Reach H kh Disk.empty (LState.genesis H shard asOf nb au)
  | step {d : Disk} {S : LState} {b : BatchIn} {st : Step} :
      Reach H kh d S → writeBatch H kh S b = .ok st → RowsAgree kh d S b →
        Reach H kh (runOps (stepOps st) d) st.next
  | same {d : Disk} {S T : LState} : Reach H kh d S → S.Same T → Reach H kh d T

/-- Load (`ChunkIo.openStore`) at signed head `hd` and batch count `bt`, `names` the files present.  Batch 0 is a head
    mismatch (`flat init` makes a store).  The files must be `lock` and `log`.  Frames are decoded from the start of the
    log until no whole frame decodes; the target, frame `bt`, must hold `hd` and `bt` and be the last whole frame or the
    one before it.  Every frame up to the target is replayed (`replayFrame`) from the empty store of the first frame's
    shard and starting bucket count, at the first frame's head before (the signed head binds it).  A whole frame after
    the target (a batch ahead, never released) must replay on the target's state too, and is kept for a retry with the
    same request bytes (`retryOf`).  Any other file or any mismatch refuses.  The repair returned: the log cut after the
    last frame kept. -/
def loadLog (H : Bytes → Bytes) (d : Disk) (names : List String) (hd : Bytes) (bt : Nat) :
    Except String (LState × Option Frame × List Op) :=
  -- Batch 0 has no frame to read the shard and the bucket count from: a store is opened at batch 0 only by the
  -- process that created it, and a first batch that died is created again (`flat init`).
  if bt = 0 then .error "HEAD" else
  if names.any (fun n => !(n = "lock" || n = "log")) then .error "FILES" else
  match d "log" with
  | none => .error "LOG"
  | some L =>
    let frs := decFrames L.length L
    match frs[0]?, frs[bt - 1]? with
    | some f0, some tg =>
      if (frs.length = bt ∨ frs.length = bt + 1) ∧ tg.head = hd ∧ tg.batches = bt then
        -- the empty store's heads and authority record are never read: every frame replaces them
        match (frs.take bt).foldlM (replayFrame H (khsOf frs))
            { LState.genesis H f0.shard 0 f0.nb0 f0.au with head := f0.prev } with
        | none => .error "REPLAY"
        | some T =>
          match frs[bt]? with
          | none => .ok (T, none, [.trunc "log" T.logLen])
          | some p =>
            match replayFrame H (khsOf frs) T p with
            | none => .error "REPLAY"
            | some _ => .ok (T, some p, [.trunc "log" (T.logLen + (encFrame p).length)])
      else .error "HEAD"
    | _, _ => .error "HEAD"

/-- A request with digest `rq` for the batch after the loaded one: the pending frame when its request digest is `rq`
    (its bytes are the answer, unchanged); `HOLD RETRY` when the pending batch had another request; `none` when nothing
    is pending, so the batch is decided afresh. -/
def retryOf (pend : Option Frame) (rq : Bytes) : Except String (Option Frame) :=
  match pend with
  | none => .ok none
  | some p => if p.rq = rq then .ok (some p) else .error "HOLD RETRY"

/-- An open at batch `bt` by a process that opened batch `seen` before (kept in memory): `HOLD STALE` when
    `bt < seen`, a rewound head; else `loadLog`. -/
def openLog (H : Bytes → Bytes) (d : Disk) (names : List String) (hd : Bytes) (bt seen : Nat) :
    Except String (LState × Option Frame × List Op) :=
  if bt < seen then .error "HOLD STALE" else loadLog H d names hd bt

/-- Page `p` of chunk `r` from the log bytes `L`, only when it hashes to the page hash RAM holds. -/
def pageAt (H : Bytes → Bytes) (L : Bytes) (r : CR) (p : Nat) : Option Bytes :=
  let x := (L.drop (r.base + p * pageSize)).take pageSize
  if x.length = pageSize ∧ r.phs[p]? = some (pageHash H x) then some x else none

/-! ## Statements -/

variable {H : Bytes → Bytes} {kh : Bytes → UInt64}

theorem decMeta3_enc (m : Bytes) (seq : Nat) (ts : List Tomb) (tk : List Nat) (htk : ∀ h ∈ tk, h < 2 ^ 64) :
    decMeta3 (encMeta3 m seq ts tk) = some (m, seq, ts, tk) := by
  have h1 := decTombs_enc ts (leb tk.length ++ tk.flatMap (natBE 8))
  have h2 := decKhs_enc tk [] htk
  rw [List.append_nil] at h2
  have hm : takeN m.length (m ++ (leb seq ++ (leb ts.length ++ (ts.flatMap encTomb ++
      (leb tk.length ++ tk.flatMap (natBE 8)))))) =
      some (m, leb seq ++ (leb ts.length ++ (ts.flatMap encTomb ++ (leb tk.length ++ tk.flatMap (natBE 8))))) :=
    takeN_app _ _ _ rfl
  simp only [decMeta3, encMeta3, encMeta2, List.append_assoc] at hm h1 ⊢
  simp [unleb_leb, hm, h1, h2]

theorem le32_length (n : Nat) : (le32 n).length = 4 := by simp [le32, natBE]

theorem unle32_le32 {n : Nat} (h : n < 2 ^ 32) (r : Bytes) : unle32 (le32 n ++ r) = some (n, r) := by
  have := takeN_app 4 (le32 n) r (le32_length n)
  have hb : beNat (natBE 4 n) = n := beNat_natBE' 4 n (by simpa using h)
  simp [unle32, this, le32, hb] at *

theorem splitPages_flatten : ∀ (ps : List Bytes), (∀ p ∈ ps, p.length = pageSize) →
    splitPages ps.length ps.flatten = ps
  | [], _ => rfl
  | p :: ps, h => by
    have hp : p.length = pageSize := h p (by simp)
    have := splitPages_flatten ps (fun q hq => h q (by simp [hq]))
    simp [splitPages, hp, this]

theorem flatten_length : ∀ (ps : List Bytes), (∀ p ∈ ps, p.length = pageSize) →
    ps.flatten.length = ps.length * pageSize
  | [], _ => rfl
  | p :: ps, h => by
    have hp : p.length = pageSize := h p (by simp)
    have := flatten_length ps (fun q hq => h q (by simp [hq]))
    simp [hp, this, Nat.add_mul, Nat.add_comm]

theorem decTrailer_enc {f : Frame} (hf : f.Wf) :
    decTrailer (frameTrailer f) = some (f.cnum, { f with chunk := none }) := by
  obtain ⟨_, _, h0, h1, h2, h3, h4⟩ := hf
  have t64 : ∀ x r : Bytes, x.length = 64 → takeN 64 (x ++ r) = some (x, r) := fun x r h => takeN_app 64 x r h
  have t64' : takeN 64 f.head = some (f.head, []) := by simpa using t64 f.head [] h4
  have ta : ∀ r : Bytes, takeN authLen (f.au ++ r) = some (f.au, r) := fun r => takeN_app _ _ r h0
  simp only [decTrailer, frameTrailer, List.append_assoc]
  rw [takeN_app _ _ _ rfl]
  simp [unleb_leb, decHead_enc, ta, t64 _ _ h1, t64 _ _ h2, t64 _ _ h3, t64']

theorem decFrame_gen {np ml : Nat} {pg m T r : Bytes} (h1 : np < 2 ^ 32) (h2 : ml < 2 ^ 32) (h3 : T.length < 2 ^ 32)
    (hp : pg.length = np * pageSize) (hm : m.length = ml) :
    decFrame (frameHdr np ml T.length ++ pg ++ m ++ T ++ r) = (decTrailer T).bind (fun x => match x.1 with
      | 0 => if np = 0 ∧ ml = 0 then some (x.2, r) else none
      | c + 1 => some ({ x.2 with chunk := some (c, splitPages np pg, m) }, r)) := by
  have F1 : ∀ X, takeN 4 (frameTag ++ X) = some (frameTag, X) := fun X => takeN_app _ _ _ rfl
  have F2 : ∀ X, unle32 (le32 np ++ X) = some (np, X) := unle32_le32 h1
  have F3 : ∀ X, unle32 (le32 ml ++ X) = some (ml, X) := unle32_le32 h2
  have F4 : ∀ X, unle32 (le32 T.length ++ X) = some (T.length, X) := unle32_le32 h3
  have F5 : ∀ X, takeN (np * pageSize) (pg ++ X) = some (pg, X) := fun X => takeN_app _ _ _ hp
  have F6 : ∀ X, takeN ml (m ++ X) = some (m, X) := fun X => takeN_app _ _ _ hm
  have F7 : ∀ X, takeN T.length (T ++ X) = some (T, X) := fun X => takeN_app _ _ _ rfl
  simp only [frameHdr, List.append_assoc]
  simp [decFrame, F1, F2, F3, F4, F5, F6, F7]

theorem leb_length_le : ∀ (k n : Nat), n < 128 ^ (k + 1) → (leb n).length ≤ k + 1
  | 0, n, h => by rw [leb, dif_pos (by simpa using h)]; simp
  | k + 1, n, h => by
    by_cases h0 : n < 128
    · rw [leb, dif_pos h0]; simp
    · rw [leb, dif_neg h0]
      have := leb_length_le k (n / 128) (by rw [Nat.pow_succ] at h; omega)
      simp only [List.length_cons]; omega

theorem leb_length_64 {n : Nat} (h : n < 2 ^ 64) : (leb n).length ≤ 10 :=
  leb_length_le 9 n (Nat.lt_trans h (by decide))

theorem frameDom_length : (domain "FLAT/FRAME").length = 22 := by
  decide +kernel

/-- The trailer of a well-formed frame fits its 32-bit header field. -/
theorem frameTrailer_lt {f : Frame} (hf : f.Wf) : (frameTrailer f).length < 2 ^ 32 := by
  obtain ⟨-, hn, h0, h1, h2, h3, h4⟩ := hf
  have b : ∀ n ∈ [f.shard, f.nb0, f.batches, f.cnum, f.hr.asOf, f.hr.count, f.hr.n, f.hu.asOf, f.hu.count, f.hu.n,
      f.nx], (leb n).length ≤ 10 := fun n hm => leb_length_64 (hn n hm)
  simp only [List.mem_cons, List.mem_nil_iff, or_false, forall_eq_or_imp, forall_eq] at b
  obtain ⟨b1, b2, b3, b4, b5, b6, b7, b8, b9, b10, b11⟩ := b
  simp only [frameTrailer, encHead, List.length_append, frameDom_length, h0, authLen, h1, h2, h3, h4, Nat.reducePow]
  omega

theorem decFrame_enc {f : Frame} (hf : f.Wf) (r : Bytes) : decFrame (encFrame f ++ r) = some (f, r) := by
  have htl := frameTrailer_lt hf
  have hT := decTrailer_enc hf
  obtain ⟨hc, _⟩ := hf
  cases f with
  | mk ch sh nb b hr hu nx au rq pv bd hd =>
    cases ch with
    | none =>
      have := decFrame_gen (np := 0) (ml := 0) (pg := []) (m := []) (r := r)
        (T := frameTrailer ⟨none, sh, nb, b, hr, hu, nx, au, rq, pv, bd, hd⟩)
        (by decide) (by decide) htl rfl rfl
      simp only [encFrame, frameBody, List.append_assoc, List.nil_append] at this ⊢
      rw [this, hT]
      simp [Frame.cnum]
    | some x =>
      obtain ⟨c, pages, m⟩ := x
      obtain ⟨hpg, hnp, hml⟩ := hc (c, pages, m) rfl
      have := decFrame_gen (np := pages.length) (ml := m.length) (pg := pages.flatten) (m := m) (r := r)
        (T := frameTrailer ⟨some (c, pages, m), sh, nb, b, hr, hu, nx, au, rq, pv, bd, hd⟩) hnp hml htl
        (flatten_length pages hpg) rfl
      simp only [encFrame, frameBody, List.append_assoc] at this ⊢
      rw [this, hT]
      simp [Frame.cnum, splitPages_flatten pages hpg]


theorem takeN_stable {n : Nat} {Y a b s : Bytes} (h : takeN n Y = some (a, b)) :
    takeN n (Y ++ s) = some (a, b ++ s) := by
  unfold takeN at h ⊢
  split at h
  · rename_i hn
    have h2 : n ≤ (Y ++ s).length := by simp; omega
    simp only [Option.some.injEq, Prod.mk.injEq] at h
    obtain ⟨rfl, rfl⟩ := h
    rw [if_pos h2, List.take_append_of_le_length hn, List.drop_append_of_le_length hn]
  · cases h

theorem unle32_stable {Y s : Bytes} {v : Nat} {r : Bytes} (h : unle32 Y = some (v, r)) :
    unle32 (Y ++ s) = some (v, r ++ s) := by
  unfold unle32 at h ⊢
  rcases hh : takeN 4 Y with _ | ⟨b, r1⟩
  · simp [hh] at h
  · simp only [hh, Option.bind_some, pure, Option.some.injEq, Prod.mk.injEq] at h
    obtain ⟨rfl, rfl⟩ := h
    rw [takeN_stable hh]
    rfl

theorem decFrame_app {X s : Bytes} {g : Frame} {r : Bytes} (h : decFrame X = some (g, r)) :
    decFrame (X ++ s) = some (g, r ++ s) := by
  unfold decFrame at h ⊢
  rcases h1 : takeN 4 X with _ | ⟨t, r1⟩
  · simp [h1] at h
  simp [h1, takeN_stable h1] at h ⊢
  obtain ⟨ht, h⟩ := h
  refine ⟨ht, ?_⟩
  rcases h2 : unle32 r1 with _ | ⟨np, r2⟩
  · simp [h2] at h
  rw [unle32_stable h2]
  simp only [h2, Option.bind_some] at h ⊢
  rcases h3 : unle32 r2 with _ | ⟨ml, r3⟩
  · simp [h3] at h
  rw [unle32_stable h3]
  simp only [h3, Option.bind_some] at h ⊢
  rcases h4 : unle32 r3 with _ | ⟨tl, r4⟩
  · simp [h4] at h
  rw [unle32_stable h4]
  simp only [h4, Option.bind_some] at h ⊢
  rcases h5 : takeN (np * pageSize) r4 with _ | ⟨pg, r5⟩
  · simp [h5] at h
  rw [takeN_stable h5]
  simp only [h5, Option.bind_some] at h ⊢
  rcases h6 : takeN ml r5 with _ | ⟨m, r6⟩
  · simp [h6] at h
  rw [takeN_stable h6]
  simp only [h6, Option.bind_some] at h ⊢
  rcases h7 : takeN tl r6 with _ | ⟨tb, r7⟩
  · simp [h7] at h
  rw [takeN_stable h7]
  simp only [h7, Option.bind_some] at h ⊢
  rcases h8 : decTrailer tb with _ | ⟨c, f⟩
  · simp [h8] at h
  simp only [h8, Option.bind_some] at h ⊢
  cases c with
  | zero =>
    by_cases hc : np = 0 ∧ ml = 0
    · simp [hc] at h ⊢
      obtain ⟨rfl, rfl⟩ := h
      exact ⟨rfl, rfl⟩
    · simp [hc] at h
  | succ c =>
    simp only [Option.some.injEq, Prod.mk.injEq] at h
    obtain ⟨rfl, rfl⟩ := h
    rfl

/-- A torn frame never decodes. -/
theorem decFrame_torn {f : Frame} (hf : f.Wf) {i : Nat} (hi : i < (encFrame f).length) :
    decFrame ((encFrame f).take i) = none := by
  rcases hx : decFrame ((encFrame f).take i) with _ | ⟨g, r⟩
  · rfl
  · exfalso
    have h1 := decFrame_app (s := (encFrame f).drop i) hx
    rw [List.take_append_drop] at h1
    have h2 := decFrame_enc hf []
    rw [List.append_nil] at h2
    rw [h1] at h2
    simp only [Option.some.injEq, Prod.mk.injEq] at h2
    have h3 : (encFrame f).drop i = [] := (List.append_eq_nil_iff.mp h2.2).2
    have := congrArg List.length h3
    simp at this
    omega


theorem leb_cancel {a b : Nat} {r r' : Bytes} (h : leb a ++ r = leb b ++ r') : a = b ∧ r = r' := by
  have := congrArg unleb h
  rw [unleb_leb, unleb_leb] at this
  simpa using this

theorem head_cancel {a b : Head} {r r' : Bytes} (h : encHead a ++ r = encHead b ++ r') : a = b ∧ r = r' := by
  have := congrArg decHead h
  rw [decHead_enc, decHead_enc] at this
  simpa using this

theorem bs_cancel {a b : Bytes} {r r' : Bytes} (h : encBs a ++ r = encBs b ++ r') : a = b ∧ r = r' := by
  have := congrArg decBs h
  rw [decBs_enc, decBs_enc] at this
  simpa using this

theorem stateRoot3_binds {k k' nb nb' nx nx' : Nat} {tr tr' au au' rq rq' : Bytes} {hr hu hr' hu' : Head}
    (ht : tr.length = tr'.length)
    (h : stateRoot3 H k nb tr hr hu nx au rq = stateRoot3 H k' nb' tr' hr' hu' nx' au' rq') :
    (k = k' ∧ nb = nb' ∧ tr = tr' ∧ hr = hr' ∧ hu = hu' ∧ nx = nx' ∧ au = au' ∧ rq = rq') ∨ Collides H := by
  by_cases e : domain "STORE/STATE3" ++ leb k ++ leb nb ++ tr ++ encHead hr ++ encHead hu ++ leb nx ++ encBs au ++
      encBs rq =
      domain "STORE/STATE3" ++ leb k' ++ leb nb' ++ tr' ++ encHead hr' ++ encHead hu' ++ leb nx' ++ encBs au' ++
      encBs rq'
  · left
    simp only [List.append_assoc] at e
    obtain ⟨e1, e2⟩ := List.append_cancel_left e |> leb_cancel
    subst e1
    obtain ⟨e1b, e2b⟩ := leb_cancel e2
    subst e1b
    obtain ⟨e3, e4⟩ := List.append_inj e2b ht
    subst e3
    obtain ⟨e5, e6⟩ := head_cancel e4
    subst e5
    obtain ⟨e7, e8⟩ := head_cancel e6
    subst e7
    obtain ⟨e9, e10⟩ := leb_cancel e8
    subst e9
    obtain ⟨ea, e10a⟩ := bs_cancel e10
    subst ea
    obtain ⟨e11, -⟩ := bs_cancel (by simpa using e10a : encBs rq ++ [] = encBs rq' ++ [])
    exact ⟨rfl, rfl, rfl, rfl, rfl, rfl, rfl, e11⟩
  · exact Or.inr ⟨_, _, e, h⟩

theorem stepOps_synced (st : Step) : SyncedOrder (stepOps st) := by
  intro i f h
  rcases i with _ | _ | i <;> simp_all [stepOps, Op.data]

theorem sortInst_eq {a b : HashSet Nat} (hi : ∀ c, a.contains c = b.contains c) :
    (a.toList.mergeSort fun x y => decide (x ≤ y)) = (b.toList.mergeSort fun x y => decide (x ≤ y)) := by
  have hna : a.toList.Nodup := by
    have := a.distinct_toList
    refine List.Pairwise.imp ?_ this
    intro x y h hxy; subst hxy; simp at h
  have hnb : b.toList.Nodup := by
    have := b.distinct_toList
    refine List.Pairwise.imp ?_ this
    intro x y h hxy; subst hxy; simp at h
  have hp : a.toList.Perm b.toList := by
    rw [List.perm_ext_iff_of_nodup hna hnb]
    intro c
    rw [Std.HashSet.mem_toList, Std.HashSet.mem_toList]
    exact (by rw [Std.HashSet.mem_iff_contains, Std.HashSet.mem_iff_contains, hi c] : c ∈ a ↔ c ∈ b)
  have htr : ∀ x y z : Nat, (decide (x ≤ y)) = true → decide (y ≤ z) = true → decide (x ≤ z) = true := by
    intro x y z h1 h2; simp at *; omega
  have hto : ∀ x y : Nat, (decide (x ≤ y) || decide (y ≤ x)) = true := by intro x y; simp; omega
  refine List.Perm.eq_of_pairwise (le := fun x y => decide (x ≤ y) = true) ?_ ?_ ?_ ?_
  · intro x y _ _ h1 h2; simp at h1 h2; omega
  · exact List.pairwise_mergeSort htr hto _
  · exact List.pairwise_mergeSort htr hto _
  · exact (List.mergeSort_perm _ _).trans (hp.trans (List.mergeSort_perm _ _).symm)

theorem liveHashes_congr {a b : HashMap Nat (HashSet Nat)} (hd : ∀ c i, isDead a c i = isDead b c i) (c : Nat)
    (ws : List Row) : liveHashes kh a c ws = liveHashes kh b c ws := by
  unfold liveHashes
  have : liveHash kh a c = liveHash kh b c := by
    funext iw
    simp [liveHash, hd]
  rw [this]

/-- The grown directory depends on the installed set and dead bits only. -/
theorem regrowC_congr {a b : Fs} (hn : a.dir.nb = b.dir.nb) (hi : ∀ c, a.inst.contains c = b.inst.contains c)
    (hd : ∀ c i, isDead a.dead c i = isDead b.dead c i) (rows : Nat → List Row) :
    (regrowC kh a rows).map (·.dir) = (regrowC kh b rows).map (·.dir) := by
  have hL : (a.inst.toList.mergeSort fun x y => decide (x ≤ y)).map (fun c => (c, liveHashes kh a.dead c (rows c))) =
      (b.inst.toList.mergeSort fun x y => decide (x ≤ y)).map (fun c => (c, liveHashes kh b.dead c (rows c))) := by
    rw [sortInst_eq hi]
    apply List.map_congr_left
    intro c _
    rw [liveHashes_congr hd]
  unfold regrowC
  rw [hL, hn]
  generalize Dir.rebuild (2 * b.dir.nb + 1) _ = r
  cases r <;> rfl

/-- So growth may start from the book instead of the store it consumed (the install that takes its store unshared). -/
theorem regrowC_book {fs : Fs} {L : Book} {pend : List Tomb} {nx : Nat} (hB : BInv fs L pend nx)
    (rows : Nat → List Row) :
    (regrowC kh fs rows).map (·.dir) =
      (regrowC kh { fs with inst := HashSet.ofList (L.map (·.1)), dead := deadOf L pend } rows).map (·.dir) := by
  obtain ⟨h1, -, -, -, h5⟩ := hB
  refine regrowC_congr (a := fs) (b := { fs with inst := HashSet.ofList (L.map (·.1)), dead := deadOf L pend }) rfl ?_ (by intro c i; exact h5 c i) rows
  intro c
  apply Bool.eq_iff_iff.mpr
  show fs.inst.contains c = true ↔ (HashSet.ofList (L.map (·.1))).contains c = true
  rw [Std.HashSet.contains_ofList]
  have hc : ∀ l : List Nat, l.contains c = true ↔ c ∈ l := fun l => by
    first | exact List.contains_iff_mem | exact List.elem_iff | simp
  rw [h1 c, hc, List.mem_map]

/-- The slots growth makes are the live rows' slots, one each (what `FInv` needs). -/
theorem regrowC_items {fs g : Fs} {rows : Nat → List Row} (hc : ∀ c, fs.inst.contains c = true → c < 2 ^ cBits)
    (h : regrowC kh fs rows = .ok g) (x : UInt32 × Nat) :
    g.dir.items.count x = (liveItems kh fs.inst fs.dead g.dir.nb rows).count x := by
  cases hr : Dir.rebuild (2 * fs.dir.nb + 1)
      ((fs.inst.toList.mergeSort fun a b => decide (a ≤ b)).map fun c => (c, liveHashes kh fs.dead c (rows c))) with
  | error e => simp [regrowC, hr, Except.map] at h
  | ok d =>
    simp only [regrowC, hr, Except.map, Except.ok.injEq] at h
    subst h
    have hb : ∀ ch ∈ (fs.inst.toList.mergeSort fun a b => decide (a ≤ b)).map
        (fun c => (c, liveHashes kh fs.dead c (rows c))), ch.1 < 2 ^ cBits := by
      intro ch hch
      obtain ⟨c', hc', rfl⟩ := List.mem_map.mp hch
      exact hc c' (Std.HashSet.mem_iff_contains.mp (Std.HashSet.mem_toList.mp ((List.mergeSort_perm _ _).mem_iff.mp hc')))
    obtain ⟨-, hdn, hdc⟩ := rebuild_inv (by omega) hb hr
    rw [hdc x]
    show _ = (liveItems kh fs.inst fs.dead d.nb rows).count x
    rw [hdn]
    simp only [liveItems, List.flatMap_map]
    exact ((List.mergeSort_perm _ _).flatMap_right _).count_eq x

/-! ## The reachable states -/

/-- What every reachable state keeps: the book matches the installed set and dead bits with nothing pending, both
    windows are empty, the tree's empty nodes are the empty tree's, and the installed chunks are numbered `0` to
    `nx - 1` (nothing is reclaimed, and each batch takes the smallest free number); the tree's root is a digest. -/
def LState.Inv (H : Bytes → Bytes) (S : LState) : Prop :=
  BInv S.fs S.book [] S.nx ∧ S.fs.win.isEmpty = true ∧ S.fs.sealing = none ∧ S.tree.emp = (Tree.empty H).emp ∧
    (∀ c, S.fs.inst.contains c = true ↔ c < S.nx) ∧ ∃ x, S.tree.root = H x

theorem ite_ok {ε α : Type} {p : Prop} [Decidable p] {x : Except ε α} {e : ε} {y : α}
    (h : (if p then x else .error e) = .ok y) : p ∧ x = .ok y := by
  by_cases hp : p
  · rw [if_pos hp] at h; exact ⟨hp, h⟩
  · rw [if_neg hp] at h; cases h

theorem up_emp : ∀ (t : Tree) (k l j : Nat), (Tree.up H t k l j).emp = t.emp
  | _, 0, _, _ => rfl
  | t, k + 1, l, j => by simp only [Tree.up]; exact up_emp _ k _ _

theorem set_emp {t t' : Tree} {i : Nat} {v : Option Bytes} (h : t.set H i v = some t') : t'.emp = t.emp := by
  unfold Tree.set at h
  split at h
  · rw [← Option.some.inj h]
    exact (up_emp (H := H) (t.put 0 i (leafH H v)) depth 0 i).trans (rfl : (t.put 0 i (leafH H v)).emp = t.emp)
  · cases h

theorem up_top : ∀ (k : Nat) (t : Tree) (l j : Nat),
    ∃ x, (Tree.up H t (k + 1) l j).get (l + (k + 1)) (j / 2 ^ (k + 1)) = H x
  | 0, t, l, j => ⟨domain "STORE/NODE" ++ t.get l (2 * (j / 2)) ++ t.get l (2 * (j / 2) + 1), by simp [Tree.up, get_put, nodeH]⟩
  | k + 1, t, l, j => by
    obtain ⟨x, hx⟩ := up_top k (t.put (l + 1) (j / 2) (nodeH H (t.get l (2 * (j / 2))) (t.get l (2 * (j / 2) + 1))))
      (l + 1) (j / 2)
    refine ⟨x, ?_⟩
    have e1 : l + (k + 1 + 1) = l + 1 + (k + 1) := by omega
    have e2 : j / 2 ^ (k + 1 + 1) = j / 2 / 2 ^ (k + 1) := by
      rw [Nat.div_div_eq_div_mul, Nat.pow_succ, Nat.mul_comm]
    rw [e1, e2]
    exact hx

/-- A tree's root after a leaf is set is a digest. -/
theorem set_root {t t' : Tree} {i : Nat} {v : Option Bytes} (h : t.set H i v = some t') : ∃ x, t'.root = H x := by
  unfold Tree.set at h
  split at h
  · rename_i hi
    have h := Option.some.inj h
    subst h
    obtain ⟨x, hx⟩ := up_top (H := H) (depth - 1) (t.put 0 i (leafH H v)) 0 i
    have hd : depth - 1 + 1 = depth := rfl
    rw [hd, Nat.zero_add, Nat.div_eq_of_lt hi] at hx
    exact ⟨x, hx⟩
  · cases h

/-- Trees of the same contents read the same at every node. -/
theorem get_congr {t u : Tree} (he : t.emp = u.emp) (hn : ∀ k : Nat × Nat, t.nodes[k]? = u.nodes[k]?) (l i : Nat) :
    t.get l i = u.get l i := by
  unfold Tree.get
  rw [Std.HashMap.getD_eq_getD_getElem?, Std.HashMap.getD_eq_getD_getElem?, hn, he]

theorem placeTombs_empty (c n : Nat) (ws : List Row) (pend : List Tomb) : placeTombs ∅ c n ws pend = pend := by
  unfold placeTombs
  rw [List.filterMap_eq_nil_iff.mpr (fun iw _ => by simp), List.append_nil]

theorem bornKh_empty (ws : List Row) : bornKh kh ∅ ws = [] := by
  unfold bornKh
  exact List.filterMap_eq_nil_iff.mpr (fun iw _ => by simp)

theorem bornDead_empty (ws : List Row) : bornDead ∅ ws = ∅ := by
  unfold bornDead
  generalize ixs 0 ws = l
  generalize (∅ : HashSet Nat) = s
  induction l generalizing s with
  | nil => rfl
  | cons iw l ih =>
    simp only [List.foldl_cons, Std.HashMap.contains_empty, Bool.false_eq_true, if_false] at ih ⊢
    exact ih s

theorem ixs_some {β : Type _} (f : Row → β) : ∀ (i : Nat) (ws : List Row),
    (ixs i ws).filterMap (fun iw => some (f iw.2)) = ws.map f
  | _, [] => rfl
  | i, w :: ws => by simp only [ixs, List.filterMap_cons, List.map_cons, ixs_some f (i + 1) ws]

theorem liveHashes_fresh (d : HashMap Nat (HashSet Nat)) (c : Nat) (ws : List Row) :
    liveHashes kh (d.insert c ∅) c ws = ws.map fun w => kh w.1 := by
  have h : liveHash kh (d.insert c ∅) c = fun iw => some (kh iw.2.1) := by
    funext iw; simp [liveHash, isDead_insert]
  rw [liveHashes, h]
  exact ixs_some (fun w => kh w.1) 0 ws

theorem place_ok {fs p : Fs} {c : Nat} {ws : List Row} (h : place kh fs c ws = .ok p) :
    ∃ d, (liveHashes kh (fs.dead.insert c (bornDead fs.win ws)) c ws).foldlM (fun (d : Dir) h => d.insert h c)
        fs.dir = .ok d ∧
      p = { fs with dir := d, inst := fs.inst.insert c, sealing := none, dead := fs.dead.insert c (bornDead fs.win ws) } := by
  simp only [place, Except.map] at h
  split at h
  · cases h
  · rename_i d hd; cases h; exact ⟨d, hd, rfl⟩

theorem place_error {fs : Fs} {c : Nat} {ws : List Row} {e : Store.Refusal} (h : place kh fs c ws = .error e) :
    ∃ e', (liveHashes kh (fs.dead.insert c (bornDead fs.win ws)) c ws).foldlM (fun (d : Dir) h => d.insert h c)
      fs.dir = .error e' := by
  simp only [place, Except.map] at h
  split at h
  · rename_i e' he; exact ⟨e', he⟩
  · cases h

theorem regrowC_rebuild {fs g : Fs} {rows : Nat → List Row} (h : regrowC kh fs rows = .ok g) :
    ∃ dg, g = { fs with dir := dg } ∧
      Dir.rebuild (2 * fs.dir.nb + 1) ((fs.inst.toList.mergeSort fun a b => decide (a ≤ b)).map fun c =>
        (c, liveHashes kh fs.dead c (rows c))) = .ok dg := by
  simp only [regrowC, Except.map] at h
  split at h
  · cases h
  · rename_i d hd; cases h; exact ⟨d, rfl, hd⟩

theorem regrowC_ok {fs g : Fs} {rows : Nat → List Row} (h : regrowC kh fs rows = .ok g) : ∃ d, g = { fs with dir := d } :=
  let ⟨d, hg, _⟩ := regrowC_rebuild h; ⟨d, hg⟩

theorem ofList_mem (L : Book) (c : Nat) : (HashSet.ofList (L.map (·.1))).contains c = true ↔ ∃ x ∈ L, x.1 = c := by
  rw [Std.HashSet.contains_ofList]
  have hc : ∀ l : List Nat, l.contains c = true ↔ c ∈ l := fun l => by
    first | exact List.contains_iff_mem | exact List.elem_iff | simp
  rw [hc, List.mem_map]

theorem ofList_book {fs : Fs} {L : Book} {pend : List Tomb} {nx : Nat} (hB : BInv fs L pend nx) (c : Nat) :
    (HashSet.ofList (L.map (·.1))).contains c = fs.inst.contains c :=
  Bool.eq_iff_iff.mpr ((ofList_mem L c).trans (hB.1 c).symm)

/-- Growth rebuilds the installed set and dead bits from the book, so `BInv` carries over. -/
theorem book_regrow {fs g : Fs} {L : Book} {pend : List Tomb} {nx : Nat} (hB : BInv fs L pend nx)
    (hi : g.inst = HashSet.ofList (L.map (·.1))) (hd : g.dead = deadOf L pend) : BInv g L pend nx := by
  obtain ⟨-, h2, h3, h4, -⟩ := hB
  refine ⟨fun c => ?_, h2, h3, h4, fun c i => by rw [hd]⟩
  rw [hi]; exact ofList_mem L c

theorem kills_ok {S : LState} {b : BatchIn}
    (h : ¬(b.changed.any fun ke => (b.kills ke.1).any fun x => !S.fs.inst.contains x.1) = true) :
    ∀ ke ∈ b.changed, ∀ x ∈ b.kills ke.1, S.fs.inst.contains x.1 = true := by
  intro ke hke x hx
  cases hc : S.fs.inst.contains x.1
  · exact absurd (List.any_eq_true.mpr ⟨ke, hke, List.any_eq_true.mpr ⟨x, hx, by simp [hc]⟩⟩) h
  · rfl

/-- `freeNum` passes over installed numbers only. -/
theorem freeNum_min {inst : HashSet Nat} : ∀ (n c c' : Nat), freeNum inst n c = some c' →
    ∀ y, c ≤ y → y < c' → inst.contains y = true
  | 0, _, _, h => by simp [freeNum] at h
  | n + 1, c, c', h => by
    unfold freeNum at h
    split at h
    · rename_i hc
      intro y h1 h2
      rcases Nat.eq_or_lt_of_le h1 with rfl | h1
      · exact hc
      · exact freeNum_min n (c + 1) c' h y h1 h2
    · simp only [Option.some.injEq] at h
      subst h
      intro y h1 h2
      omega

/-- What a batch the writer accepts did: its kills name installed chunks, and either nothing was placed or chunk `c`
    was, at a free number below `2 ^ cBits`, with the batch's kills as its tombstones (the sealed window is empty, so
    nothing is born dead); without growth its slots are its rows' key hashes in row order. -/
theorem writeBatch_ok {S : LState} {b : BatchIn} {st : Step} (hI : S.Inv H) (hw : writeBatch H kh S b = .ok st) :
    ∃ fs3 cw grew, writeDone H kh S b fs3 cw grew = .ok st ∧ fs3.hr = b.hr ∧ fs3.hu = b.hu ∧
      fs3.win.isEmpty = true ∧ fs3.sealing = none ∧
      ((cw = none ∧ fs3 = { S.fs with hr := b.hr, hu := b.hu }) ∨
        ∃ c ws, cw = some (c, ws,
            b.changed.flatMap (fun ke => (b.kills ke.1).map fun x => (⟨x.1, seqOf S.book x.1, x.2.1⟩ : Tomb)),
            b.changed.flatMap fun ke => (b.kills ke.1).map fun _ => (kh ke.1).toNat) ∧
          BInv fs3 (S.book ++ [(c, S.nx,
            b.changed.flatMap fun ke => (b.kills ke.1).map fun x => (⟨x.1, seqOf S.book x.1, x.2.1⟩ : Tomb))]) []
            (S.nx + 1) ∧
          (c < 2 ^ cBits ∧ c = S.nx) ∧ S.fs.inst.contains c = false ∧
          (∀ ke ∈ b.changed, ∀ x ∈ b.kills ke.1, S.fs.inst.contains x.1 = true) ∧
          ((grew = false → ∃ d, (ws.map fun w => kh w.1).foldlM (fun (d : Dir) h => d.insert h c)
              (b.changed.foldl (fun a ke => (b.kills ke.1).foldl (killRow (kh ke.1)) a) (S.fs.dead, S.fs.dir)).2 = .ok d ∧
            fs3 = ⟨b.hr, b.hu, d, S.fs.inst.insert c,
              (b.changed.foldl (fun a ke => (b.kills ke.1).foldl (killRow (kh ke.1)) a) (S.fs.dead, S.fs.dir)).1.insert c ∅,
              ∅, none⟩) ∧
           -- grown: the slots did not fit, the directory was rebuilt from the book's chunks (their live rows' key
           -- hashes from `b.rows`) with twice the buckets plus one, and then the slots fit
           (grew = true → ∃ e dg d, (ws.map fun w => kh w.1).foldlM (fun (d : Dir) h => d.insert h c)
              (b.changed.foldl (fun a ke => (b.kills ke.1).foldl (killRow (kh ke.1)) a) (S.fs.dead, S.fs.dir)).2 = .error e ∧
            Dir.rebuild (2 * (b.changed.foldl (fun a ke => (b.kills ke.1).foldl (killRow (kh ke.1)) a)
                (S.fs.dead, S.fs.dir)).2.nb + 1)
              (((HashSet.ofList (S.book.map (·.1))).toList.mergeSort fun a b => decide (a ≤ b)).map fun x =>
                (x, liveHashes kh (deadOf S.book (b.changed.flatMap fun ke => (b.kills ke.1).map fun x =>
                  (⟨x.1, seqOf S.book x.1, x.2.1⟩ : Tomb))) x (b.rows x))) = .ok dg ∧
            (ws.map fun w => kh w.1).foldlM (fun (d : Dir) h => d.insert h c) dg = .ok d ∧
            fs3 = ⟨b.hr, b.hu, d, (HashSet.ofList (S.book.map (·.1))).insert c,
              (deadOf S.book (b.changed.flatMap fun ke => (b.kills ke.1).map fun x =>
                (⟨x.1, seqOf S.book x.1, x.2.1⟩ : Tomb))).insert c ∅, ∅, none⟩ ∧
            ∀ c' i, isDead (b.changed.foldl (fun a ke => (b.kills ke.1).foldl (killRow (kh ke.1)) a)
                (S.fs.dead, S.fs.dir)).1 c' i =
              isDead (deadOf S.book (b.changed.flatMap fun ke => (b.kills ke.1).map fun x =>
                (⟨x.1, seqOf S.book x.1, x.2.1⟩ : Tomb))) c' i))) := by
  obtain ⟨hB, hwin, hseal, -, hct, -⟩ := hI
  unfold writeBatch at hw
  split at hw
  · cases hw
  rename_i hk0
  have hk := kills_ok hk0
  have hBk := kills_book (kh := kh) (fs' := { S.fs with
      dead := (b.changed.foldl (fun a ke => (b.kills ke.1).foldl (killRow (kh ke.1)) a) (S.fs.dead, S.fs.dir)).1 })
    b.kills b.changed hB hk rfl rfl
  rw [List.nil_append] at hBk
  by_cases hc : b.changed.isEmpty = true
  · have hnil := List.isEmpty_iff.mp hc
    simp only [hnil, List.isEmpty_nil, if_true, List.foldl_nil] at hw
    exact ⟨_, none, false, hw, rfl, rfl, hwin, hseal, .inl ⟨rfl, rfl⟩⟩
  · simp only [hc, Bool.false_eq_true, if_false] at hw
    cases hf : freeNum S.fs.inst (2 ^ cBits) 0 with
    | none => simp [sealWindow, hseal, hf] at hw
    | some c =>
      obtain ⟨hc0, hcb⟩ := freeNum_spec _ _ _ hf
      have hcb' : c < 2 ^ cBits ∧ c = S.nx := by
        refine ⟨by simpa using hcb, Nat.le_antisymm (Nat.le_of_not_lt fun h => ?_)
          (Nat.le_of_not_lt fun h => by rw [(hct c).mpr h] at hc0; cases hc0)⟩
        have := freeNum_min _ _ _ hf S.nx (Nat.zero_le _) h
        exact absurd ((hct _).mp this) (Nat.lt_irrefl _)
      simp only [sealWindow, hseal, hf, placeTombs_empty, bornKh_empty, List.append_nil] at hw
      split at hw
      · rename_i p hp
        have hBp := place_book (kh := kh) (book_congr (by rfl) (by rfl) hBk) (by exact hc0) hp
        simp only [placeTombs_empty] at hBp
        obtain ⟨d, hd, rfl⟩ := place_ok hp
        simp only [bornDead_empty, liveHashes_fresh] at hd
        refine ⟨_, _, false, hw, rfl, rfl, Std.HashMap.isEmpty_empty, rfl,
          .inr ⟨c, _, rfl, hBp, hcb', hc0, hk, ⟨fun _ => ⟨d, hd, ?_⟩, fun h => absurd h (by decide)⟩⟩⟩
        simp only [bornDead_empty]
      · rename_i e0 h0
        split at hw
        · rename_i g hg
          obtain ⟨dg, rfl, hrb⟩ := regrowC_rebuild hg
          simp only [Except.bind] at hw
          split at hw
          · cases hw
          · rename_i p hp
            have hBp := place_book (kh := kh) (book_regrow hBk (by rfl) (by rfl))
              (by exact (ofList_book hB c).trans hc0) hp
            simp only [placeTombs_empty] at hBp
            obtain ⟨d, hd, rfl⟩ := place_ok hp
            obtain ⟨e, he⟩ := place_error h0
            simp only [bornDead_empty, liveHashes_fresh] at hd he
            refine ⟨_, _, true, hw, rfl, rfl, Std.HashMap.isEmpty_empty, rfl,
              .inr ⟨c, _, rfl, hBp, hcb', hc0, hk, ⟨fun h => absurd h (by decide),
                fun _ => ⟨e, dg, d, he, hrb, hd, ?_, fun c' i => hBk.2.2.2.2 c' i⟩⟩⟩⟩
            simp only [bornDead_empty]
        · cases hw

theorem genesis_inv (shard asOf nb : Nat) (au : Bytes) : (LState.genesis H shard asOf nb au).Inv H := by
  refine ⟨book_init (fun c => ?_) (fun c i => ?_), ?_, rfl, rfl, fun c => ?_, domain "STORE/NODE" ++ emptyAt H 17 ++ emptyAt H 17,
    (empty_inv H depth 0 (Nat.le_refl _)).trans ((emptyAt_spec H depth 0).trans rfl)⟩
  · exact Std.HashSet.contains_empty
  · exact isDead_empty c i
  · exact Std.HashMap.isEmpty_empty
  · simp [LState.genesis]

theorem inv_same {S T : LState} (hI : S.Inv H) (h : S.Same T) : T.Inv H := by
  obtain ⟨hB, -, -, he, hct, x, hx⟩ := hI
  obtain ⟨-, -, -, -, -, -, hi, hd, -, hwT, -, hsT, hb, hn, -, ht, -⟩ := h
  obtain ⟨h1, h2, h3, h4, h5⟩ := hB
  refine ⟨⟨fun c => ?_, ?_, ?_, ?_, fun c i => ?_⟩, hwT, hsT, ht.1.symm.trans he, fun c => ?_, x, ?_⟩
  · rw [← hi, ← hb]; exact h1 c
  · rw [← hb]; exact h2
  · rw [← hb, ← hn]; exact h3
  · rw [← hb, ← hn]; exact h4
  · rw [← hd, ← hb]; exact h5 c i
  · rw [← hi, ← hn]; exact hct c
  · rw [← hx]; exact (get_congr ht.1 ht.2 depth 0).symm

theorem writeBatch_inv {S : LState} {b : BatchIn} {st : Step} (hI : S.Inv H) (hw : writeBatch H kh S b = .ok st) :
    st.next.Inv H := by
  obtain ⟨fs3, cw, grew, hd, -, -, hw3, hs3, hc⟩ := writeBatch_ok hI hw
  obtain ⟨hB, -, -, hemp, hct, hrt⟩ := hI
  unfold writeDone at hd
  rcases hc with ⟨rfl, rfl⟩ | ⟨c, ws, rfl, hB3, ⟨-, hcn⟩, -, -, -⟩
  · simp only [bind, Except.bind, pure, Except.pure] at hd
    cases (ite_ok hd).2
    exact ⟨book_congr (by rfl) (by rfl) hB, hw3, hs3, hemp, hct, hrt⟩
  · simp only [bind, Except.bind, pure, Except.pure] at hd
    split at hd
    · rename_i tree ht
      cases (ite_ok hd).2
      refine ⟨hB3, hw3, hs3, (set_emp ht).trans hemp, fun y => ?_, set_root ht⟩
      rw [hB3.1 y]
      simp only [List.mem_append, List.mem_singleton]
      constructor
      · rintro ⟨x, hx | rfl, rfl⟩
        · exact Nat.lt_succ_of_lt ((hct _).mp ((hB.1 _).mpr ⟨x, hx, rfl⟩))
        · exact hcn ▸ Nat.lt_succ_self _
      · intro hy
        rcases Nat.lt_succ_iff_lt_or_eq.mp hy with hy | rfl
        · obtain ⟨x, hx, e⟩ := (hB.1 y).mp ((hct y).mpr hy)
          exact ⟨x, .inl hx, e⟩
        · exact ⟨_, .inr rfl, hcn⟩
    · cases hd

/-- Every state the writer reaches keeps `LState.Inv`. -/
theorem reach_inv {d : Disk} {S : LState} (hR : Reach H kh d S) : S.Inv H := by
  induction hR with
  | genesis shard asOf nb au => exact genesis_inv shard asOf nb au
  | step _ hw _ ih => exact writeBatch_inv ih hw
  | same _ hs ih => exact inv_same ih hs

/-! ## The directory keeps its shape -/

theorem foldl_pres {α β : Type _} (P : α → Prop) {f : α → β → α} (hf : ∀ a x, P a → P (f a x)) :
    ∀ (l : List β) {a : α}, P a → P (l.foldl f a)
  | [], _, h => h
  | x :: l, _, h => foldl_pres P hf l (hf _ x h)

theorem put_ok (n : Nat) : ∀ {d d' : Dir} {v : UInt32} {b : Nat}, d.Ok → d.put v b n = .ok d' → d'.Ok := by
  induction n with
  | zero =>
    intro d d' v b hO h
    unfold Dir.put at h
    cases hf : (idxs d.nb (fpv v) b).find? (d.t[·]? = some 0) with
    | some j => simp only [hf, Except.ok.injEq] at h; subst h; exact ok_set hO j v
    | none =>
      simp only [hf] at h
      split at h
      · rename_i hl
        simp only [Except.ok.injEq] at h
        subst h
        exact ⟨hO.1, hO.2.1, show d.stash.length + 1 ≤ stashCap by omega⟩
      · cases h
  | succ n ih =>
    intro d d' v b hO h
    unfold Dir.put at h
    cases hf : (idxs d.nb (fpv v) b).find? (d.t[·]? = some 0) with
    | some j => simp only [hf, Except.ok.injEq] at h; subst h; exact ok_set hO j v
    | none => simp only [hf] at h; exact ih (ok_set hO _ v) h

theorem inserts_ok (c : Nat) : ∀ (hs : List UInt64) {d d' : Dir}, d.Ok →
    hs.foldlM (fun d h => d.insert h c) d = .ok d' → d'.Ok
  | [], d, d', hO, e => by
    obtain rfl : d = d' := Except.ok.inj e
    exact hO
  | h :: hs, d, d', hO, e => by
    simp only [List.foldlM_cons] at e
    cases h1 : d.insert h c with
    | error r => rw [h1] at e; cases e
    | ok d1 => rw [h1] at e; exact inserts_ok c hs (put_ok maxKicks hO h1) e

theorem rebuild_ok : ∀ (cs : List (Nat × List UInt64)) {d0 d : Dir}, d0.Ok →
    cs.foldlM (fun d ch => ch.2.foldlM (fun d h => d.insert h ch.1) d) d0 = .ok d → d.Ok
  | [], d0, d, hO, e => by
    obtain rfl : d0 = d := Except.ok.inj e
    exact hO
  | ch :: cs, d0, d, hO, e => by
    simp only [List.foldlM_cons] at e
    cases h1 : ch.2.foldlM (fun d h => d.insert h ch.1) d0 with
    | error r => rw [h1] at e; cases e
    | ok d1 => rw [h1] at e; exact rebuild_ok cs (inserts_ok ch.1 ch.2 hO h1) e

theorem erase_ok {d : Dir} (hO : d.Ok) (v : UInt32) (b : Nat) : (d.erase v b).Ok := by
  unfold Dir.erase
  split
  · exact ok_set hO _ 0
  · exact ⟨hO.1, hO.2.1, Nat.le_trans List.length_erase_le hO.2.2⟩

theorem killRow_ok (h : UInt64) {a : HashMap Nat (HashSet Nat) × Dir} (hO : a.2.Ok) (x : Nat × Nat × Entry) :
    (killRow h a x).2.Ok := by
  unfold killRow
  split
  · exact hO
  · exact erase_ok hO _ _

theorem regrowC_dirOk {fs g : Fs} {rows : Nat → List Row} (h : regrowC kh fs rows = .ok g) : g.dir.Ok := by
  simp only [regrowC, Except.map] at h
  split at h
  · cases h
  · rename_i d hd
    cases h
    exact rebuild_ok _ (d0 := Dir.empty (2 * fs.dir.nb + 1)) ⟨by simp [Dir.empty], by simp [Dir.empty],
      by simp [Dir.empty]⟩ hd

theorem writeDone_fs {S : LState} {b : BatchIn} {fs3 : Fs} {cw : Option (Nat × List Row × List Tomb × List Nat)}
    {grew : Bool} {st : Step} (h : writeDone H kh S b fs3 cw grew = .ok st) : st.next.fs = fs3 := by
  unfold writeDone at h
  cases cw with
  | none =>
    simp only [bind, Except.bind, pure, Except.pure] at h
    cases (ite_ok h).2
    rfl
  | some w =>
    obtain ⟨c, ws, ts, tk⟩ := w
    simp only [bind, Except.bind, pure, Except.pure] at h
    split at h
    · cases (ite_ok h).2
      rfl
    · cases h

theorem writeBatch_dirOk {S : LState} {b : BatchIn} {st : Step} (hseal : S.fs.sealing = none) (hO : S.fs.dir.Ok)
    (h : writeBatch H kh S b = .ok st) : st.next.fs.dir.Ok := by
  have hk : (b.changed.foldl (fun a ke => (b.kills ke.1).foldl (killRow (kh ke.1)) a) (S.fs.dead, S.fs.dir)).2.Ok :=
    foldl_pres (fun a : HashMap Nat (HashSet Nat) × Dir => a.2.Ok)
      (fun a ke ha => foldl_pres (fun a : HashMap Nat (HashSet Nat) × Dir => a.2.Ok)
        (fun a x ha => killRow_ok _ ha x) _ ha) _ hO
  unfold writeBatch at h
  split at h
  · cases h
  by_cases hc : b.changed.isEmpty = true
  · simp only [hc, if_true] at h
    rw [writeDone_fs h]
    exact hk
  · simp only [hc, Bool.false_eq_true, if_false] at h
    cases hf : freeNum S.fs.inst (2 ^ cBits) 0 with
    | none => simp [sealWindow, hseal, hf] at h
    | some c =>
      simp only [sealWindow, hseal, hf] at h
      split at h
      · rename_i p hp
        rw [writeDone_fs h]
        obtain ⟨d, hd, rfl⟩ := place_ok hp
        exact inserts_ok c _ hk hd
      · split at h
        · rename_i g hg
          have hg' := regrowC_dirOk hg
          obtain ⟨dg, rfl⟩ := regrowC_ok hg
          simp only [Except.bind] at h
          split at h
          · cases h
          · rename_i p hp
            rw [writeDone_fs h]
            obtain ⟨d, hd, rfl⟩ := place_ok hp
            exact inserts_ok c _ hg' hd
        · cases h

/-- Every state the writer reaches keeps its directory's shape. -/
theorem reach_ok {d : Disk} {S : LState} (hR : Reach H kh d S) : S.fs.dir.Ok := by
  induction hR with
  | genesis shard asOf nb au h0 => exact ⟨h0, by simp [LState.genesis, Dir.empty], by simp [LState.genesis, Dir.empty]⟩
  | step hR hw _ ih => exact writeBatch_dirOk (reach_inv hR).2.2.1 ih hw
  | same _ hs ih => rw [← hs.2.2.2.2.2.1]; exact ih

theorem fold_pairs {α β γ δ ε : Type _} (F : α → γ × δ → α) (G : β → α → ε → α) (ks : β → List ε) (t : ε → γ)
    (k : β → δ) : ∀ (ch : List β), (∀ e ∈ ch, ∀ x ∈ ks e, ∀ a, F a (t x, k e) = G e a x) → ∀ a : α,
      ((ch.flatMap fun e => (ks e).map t).zip (ch.flatMap fun e => (ks e).map fun _ => k e)).foldl F a =
        ch.foldl (fun a e => (ks e).foldl (G e) a) a
  | [], _, a => rfl
  | e :: ch, hFG, a => by
    have hin : ∀ (l : List ε), (∀ x ∈ l, ∀ a, F a (t x, k e) = G e a x) → ∀ a : α,
        (l.map fun x => (t x, k e)).foldl F a = l.foldl (G e) a := by
      intro l; induction l with
      | nil => intro _ a; rfl
      | cons x l ih =>
        intro hl a
        simp only [List.map_cons, List.foldl_cons]
        rw [hl x List.mem_cons_self a]
        exact ih (fun y hy => hl y (List.mem_cons_of_mem _ hy)) _
    have hlen : ((ks e).map t).length = ((ks e).map fun _ => k e).length := by simp
    simp only [List.flatMap_cons, List.foldl_cons]
    rw [List.zip_append hlen, List.foldl_append, List.zip_map', hin (ks e) (hFG e List.mem_cons_self) a,
      fold_pairs F G ks t k ch (fun e' he' => hFG e' (List.mem_cons_of_mem _ he')) _]

theorem filterMap_zipIdx_fst {α : Type _} {g : α × Nat → Option α} (hg : ∀ x, g x = some x.1) :
    ∀ (l : List α) (i : Nat), (l.zipIdx i).filterMap g = l
  | [], _ => rfl
  | a :: l, i => by rw [List.zipIdx_cons, List.filterMap_cons_some (hg (a, i)), filterMap_zipIdx_fst hg l (i + 1)]

/-- A frame that changed nothing replays to the state with the frame's heads. -/
theorem replayFrame_none {khs : Nat → List Nat} {S : LState} {f : Frame}
    (h1 : f.shard = S.shard ∧ f.nb0 = S.nb0 ∧ f.batches = S.batches + 1 ∧ f.prev = S.head)
    (hch : f.chunk = none) (hnx : f.nx = S.nx)
    (hh : f.head = chainStepR H S.head f.bd (stateRoot3 H S.shard S.nb0 S.tree.root f.hr f.hu S.nx f.au f.rq)) :
    replayFrame H khs S f = some { S with
      batches := f.batches, fs := { S.fs with hr := f.hr, hu := f.hu },
      head := f.head, logLen := S.logLen + (encFrame f).length, au := f.au } := by
  simp only [replayFrame, eq_true h1.1, eq_true h1.2.1, eq_true h1.2.2.1, eq_true h1.2.2.2, hch, eq_true hnx,
    eq_true hh, and_self, if_true, Option.bind_eq_bind, Option.bind_some, Option.pure_def]

/-- A frame that placed chunk `c` replays to the state the frame's metadata describes. -/
theorem replayFrame_chunk {khs : Nat → List Nat} {S : LState} {f : Frame} {c : Nat} {pages : List Bytes}
    {m3 md : Bytes} {ts : List Tomb} {tk : List Nat} {cm : CMeta} {kd : HashMap Nat (HashSet Nat) × Dir}
    {hs : List UInt64} {dir : Dir} {tree : Tree}
    (h1 : f.shard = S.shard ∧ f.nb0 = S.nb0 ∧ f.batches = S.batches + 1 ∧ f.prev = S.head)
    (hch : f.chunk = some (c, pages, m3)) (h3 : decMeta3 m3 = some (md, S.nx, ts, tk)) (hm : decM md = some cm)
    (hok : f.nx = S.nx + 1 ∧ ts.length = tk.length ∧ pages.length = cm.phs.length ∧ S.fs.inst.contains c = false ∧
      c < 2 ^ cBits ∧ c = S.nx)
    (hf : (ts.filter fun t => t.c = c ∧ t.seq = S.nx) = [])
    (hkd : (ts.zip tk).foldl (fun a p =>
        if p.1.c ≠ c ∧ current S.book p.1 then killRow p.2.toUInt64 a (p.1.c, p.1.i, Entry.empty) else a)
        (S.fs.dead, S.fs.dir) = kd)
    (hk : cm.khs.map Nat.toUInt64 = hs) (hdir : hs.foldlM (fun (d : Dir) h => d.insert h c) kd.2 = .ok dir)
    (ht : S.tree.set H c (some (H (domain "STORE/CHUNK" ++ m3))) = some tree)
    (hh : f.head = chainStepR H S.head f.bd (stateRoot3 H S.shard S.nb0 tree.root f.hr f.hu (S.nx + 1) f.au f.rq)) :
    replayFrame H khs S f = some { S with
      batches := f.batches,
      fs := ⟨f.hr, f.hu, dir, S.fs.inst.insert c, kd.1.insert c ∅, ∅, none⟩, book := S.book ++ [(c, S.nx, ts)],
      nx := S.nx + 1, chunks := insertCR S.chunks (c, CR.ofMeta (S.logLen + 16) cm (H (domain "STORE/CHUNK" ++ m3))),
      tree := tree, head := f.head, logLen := S.logLen + (encFrame f).length, au := f.au } := by
  simp only [replayFrame, eq_true h1.1, eq_true h1.2.1, eq_true h1.2.2.1, eq_true h1.2.2.2, hch, h3, hm,
    eq_true hok.1, eq_true hok.2.1, eq_true hok.2.2.1, eq_true hok.2.2.2.1, eq_true hok.2.2.2.2.1, eq_true hok.2.2.2.2.2, hf, hkd, hk,
    List.foldl_nil, Std.HashSet.contains_empty, Bool.false_eq_true, if_false, if_true, eq_self, true_and, and_self,
    Option.bind_eq_bind, Option.bind_some, Option.pure_def]
  rw [filterMap_zipIdx_fst]
  · simp only [hdir, Option.bind_some, ht, Option.pure_def, eq_true hh, if_true]
  · rintro ⟨h, i⟩; simp

/-- `replayFrame_chunk` where the slots did not fit: the directory is rebuilt from the installed chunks' live key
    hashes with twice the buckets plus one, and then they do. -/
theorem replayFrame_chunk_grew {khs : Nat → List Nat} {S : LState} {f : Frame} {c : Nat} {pages : List Bytes}
    {m3 md : Bytes} {ts : List Tomb} {tk : List Nat} {cm : CMeta} {kd : HashMap Nat (HashSet Nat) × Dir}
    {hs : List UInt64} {dir g : Dir} {tree : Tree} {e : Store.Refusal}
    (h1 : f.shard = S.shard ∧ f.nb0 = S.nb0 ∧ f.batches = S.batches + 1 ∧ f.prev = S.head)
    (hch : f.chunk = some (c, pages, m3)) (h3 : decMeta3 m3 = some (md, S.nx, ts, tk)) (hm : decM md = some cm)
    (hok : f.nx = S.nx + 1 ∧ ts.length = tk.length ∧ pages.length = cm.phs.length ∧ S.fs.inst.contains c = false ∧
      c < 2 ^ cBits ∧ c = S.nx)
    (hf : (ts.filter fun t => t.c = c ∧ t.seq = S.nx) = [])
    (hkd : (ts.zip tk).foldl (fun a p =>
        if p.1.c ≠ c ∧ current S.book p.1 then killRow p.2.toUInt64 a (p.1.c, p.1.i, Entry.empty) else a)
        (S.fs.dead, S.fs.dir) = kd)
    (hk : cm.khs.map Nat.toUInt64 = hs) (hd1 : hs.foldlM (fun (d : Dir) h => d.insert h c) kd.2 = .error e)
    (hrb : Dir.rebuild (2 * kd.2.nb + 1) ((S.fs.inst.toList.mergeSort fun a b => decide (a ≤ b)).map
      fun x => (x, liveKhs kd.1 x (khs x))) = .ok g)
    (hd2 : hs.foldlM (fun (d : Dir) h => d.insert h c) g = .ok dir)
    (ht : S.tree.set H c (some (H (domain "STORE/CHUNK" ++ m3))) = some tree)
    (hh : f.head = chainStepR H S.head f.bd (stateRoot3 H S.shard S.nb0 tree.root f.hr f.hu (S.nx + 1) f.au f.rq)) :
    replayFrame H khs S f = some { S with
      batches := f.batches,
      fs := ⟨f.hr, f.hu, dir, S.fs.inst.insert c, kd.1.insert c ∅, ∅, none⟩, book := S.book ++ [(c, S.nx, ts)],
      nx := S.nx + 1, chunks := insertCR S.chunks (c, CR.ofMeta (S.logLen + 16) cm (H (domain "STORE/CHUNK" ++ m3))),
      tree := tree, head := f.head, logLen := S.logLen + (encFrame f).length, au := f.au } := by
  simp only [replayFrame, eq_true h1.1, eq_true h1.2.1, eq_true h1.2.2.1, eq_true h1.2.2.2, hch, h3, hm,
    eq_true hok.1, eq_true hok.2.1, eq_true hok.2.2.1, eq_true hok.2.2.2.1, eq_true hok.2.2.2.2.1, eq_true hok.2.2.2.2.2, hf, hkd, hk,
    List.foldl_nil, Std.HashSet.contains_empty, Bool.false_eq_true, if_false, if_true, eq_self, true_and, and_self,
    Option.bind_eq_bind, Option.bind_some, Option.pure_def]
  rw [filterMap_zipIdx_fst]
  · simp only [hd1, hrb, hd2, Except.toOption, Option.bind_some, ht, Option.pure_def, eq_true hh, if_true]
  · rintro ⟨h, i⟩; simp

theorem foldl_rel {α β : Type _} {R : α → α → Prop} {f : α → β → α} (hf : ∀ a a' x, R a a' → R (f a x) (f a' x)) :
    ∀ (l : List β) {a a' : α}, R a a' → R (l.foldl f a) (l.foldl f a')
  | [], _, _, h => h
  | x :: l, _, _, h => foldl_rel hf l (hf _ _ x h)

/-- A kill on dead bits equal as sets and one directory gives dead bits equal as sets and one directory. -/
theorem killRow_congr (h : UInt64) {a a' : HashMap Nat (HashSet Nat) × Dir} (x : Nat × Nat × Entry)
    (hr : (∀ c i, isDead a.1 c i = isDead a'.1 c i) ∧ a.2 = a'.2) :
    (∀ c i, isDead (killRow h a x).1 c i = isDead (killRow h a' x).1 c i) ∧ (killRow h a x).2 = (killRow h a' x).2 := by
  obtain ⟨hd, he⟩ := hr
  unfold killRow
  by_cases hk : isDead a'.1 x.1 x.2.1 = true
  · rw [if_pos ((hd _ _).trans hk), if_pos hk]; exact ⟨hd, he⟩
  · rw [if_neg (by rw [hd]; exact hk), if_neg hk]
    refine ⟨fun c i => Bool.eq_iff_iff.mpr ?_, by rw [he]⟩
    rw [isDead_kill, isDead_kill, hd c i]

theorem killRows_congr (h : UInt64) : ∀ (l : List (Nat × Nat × Entry)) {a a' : HashMap Nat (HashSet Nat) × Dir},
    ((∀ c i, isDead a.1 c i = isDead a'.1 c i) ∧ a.2 = a'.2) →
    (∀ c i, isDead (l.foldl (killRow h) a).1 c i = isDead (l.foldl (killRow h) a').1 c i) ∧
      (l.foldl (killRow h) a).2 = (l.foldl (killRow h) a').2
  | [], _, _, hr => hr
  | x :: l, _, _, hr => killRows_congr h l (killRow_congr h x hr)

/-- A batch's kills on dead bits equal as sets and one directory give dead bits equal as sets and one directory. -/
theorem killAll_congr (kills : Bytes → List (Nat × Nat × Entry)) : ∀ (ch : List (Bytes × Entry))
    {a a' : HashMap Nat (HashSet Nat) × Dir}, ((∀ c i, isDead a.1 c i = isDead a'.1 c i) ∧ a.2 = a'.2) →
    (∀ c i, isDead (ch.foldl (fun a ke => (kills ke.1).foldl (killRow (kh ke.1)) a) a).1 c i =
      isDead (ch.foldl (fun a ke => (kills ke.1).foldl (killRow (kh ke.1)) a) a').1 c i) ∧
      (ch.foldl (fun a ke => (kills ke.1).foldl (killRow (kh ke.1)) a) a).2 =
        (ch.foldl (fun a ke => (kills ke.1).foldl (killRow (kh ke.1)) a) a').2
  | [], _, _, hr => hr
  | ke :: ch, _, _, hr => killAll_congr kills ch (killRows_congr (kh ke.1) (kills ke.1) hr)

theorem freeNum_congr {a b : HashSet Nat} (hi : ∀ c, a.contains c = b.contains c) :
    ∀ n c, freeNum a n c = freeNum b n c
  | 0, _ => rfl
  | n + 1, c => by simp only [freeNum, hi c, freeNum_congr hi n (c + 1)]

theorem rowLe_trans (a b c : Row) (h1 : (!rowLt kh b.1 a.1) = true) (h2 : (!rowLt kh c.1 b.1) = true) :
    (!rowLt kh c.1 a.1) = true := by
  simp only [Bool.not_eq_eq_eq_not, Bool.not_true] at h1 h2 ⊢
  cases h3 : rowLt kh c.1 a.1
  · rfl
  · by_cases e : b.1 = a.1
    · rw [← e] at h3; rw [h3] at h2; cases h2
    · rcases rowLt_total (kh := kh) e with h4 | h4
      · rw [h4] at h1; cases h1
      · have := rowLt_trans h3 h4; rw [this] at h2; cases h2

theorem rowLe_total (a b : Row) : ((!rowLt kh b.1 a.1) || (!rowLt kh a.1 b.1)) = true := by
  cases h1 : rowLt kh b.1 a.1 <;> cases h2 : rowLt kh a.1 b.1 <;> simp
  exact rowLt_asymm h1 h2

/-- Windows of the same contents sort to the same rows, whatever their hash maps' layout. -/
theorem sortRows_equiv {m m' : HashMap Bytes Entry} (h : m.Equiv m') :
    sortRows kh m.toList = sortRows kh m'.toList := by
  refine List.Perm.eq_of_pairwise (le := fun a b : Row => (!rowLt kh b.1 a.1) = true) ?_
    (List.pairwise_mergeSort rowLe_trans rowLe_total _) (List.pairwise_mergeSort rowLe_trans rowLe_total _)
    ((List.mergeSort_perm _ _).trans (h.toList_perm.trans (List.mergeSort_perm _ _).symm))
  intro a c ha hc h1 h2
  have e : a.1 = c.1 := by
    by_cases e : a.1 = c.1
    · exact e
    · rcases rowLt_total (kh := kh) e with h3 | h3
      · simp [h3] at h2
      · simp [h3] at h1
  have ga := mem_sortRows.mp ha
  have gc := mem_sortRows.mp hc
  rw [Std.HashMap.get?_eq_getElem?] at ga gc
  rw [e, h.getElem?_eq] at ga
  exact Prod.ext e (Option.some.inj (ga.symm.trans gc))

theorem up_congr : ∀ (k : Nat) {t u : Tree} (l j : Nat), t.emp = u.emp → (∀ x : Nat × Nat, t.nodes[x]? = u.nodes[x]?) →
    (Tree.up H t k l j).emp = (Tree.up H u k l j).emp ∧
      ∀ x : Nat × Nat, (Tree.up H t k l j).nodes[x]? = (Tree.up H u k l j).nodes[x]?
  | 0, _, _, _, _, he, hn => ⟨he, hn⟩
  | k + 1, t, u, l, j, he, hn => by
    simp only [Tree.up, get_congr he hn]
    exact up_congr k (l + 1) (j / 2) he (fun x => by simp only [Tree.put, Std.HashMap.getElem?_insert, hn x])

/-- Setting a leaf of trees of the same contents gives trees of the same contents (or fails for both). -/
theorem set_congr {t u : Tree} (he : t.emp = u.emp) (hn : ∀ x : Nat × Nat, t.nodes[x]? = u.nodes[x]?) (i : Nat)
    (v : Option Bytes) :
    (t.set H i v = none ↔ u.set H i v = none) ∧ ∀ t' u', t.set H i v = some t' → u.set H i v = some u' →
      t'.emp = u'.emp ∧ ∀ x : Nat × Nat, t'.nodes[x]? = u'.nodes[x]? := by
  unfold Tree.set
  by_cases hi : i < 2 ^ depth
  · rw [if_pos hi, if_pos hi]
    refine ⟨by simp, fun t' u' h1 h2 => ?_⟩
    rw [← Option.some.inj h1, ← Option.some.inj h2]
    exact up_congr depth 0 i he (fun x => by simp only [Tree.put, Std.HashMap.getElem?_insert, hn x])
  · rw [if_neg hi, if_neg hi]
    exact ⟨Iff.rfl, fun _ _ h => nomatch h⟩

/-- Placing chunk `c` on stores of one directory, dead bits equal as sets and one open window gives one directory
    (or one refusal). -/
theorem place_congr {a a' : Fs} (c : Nat) (ws : List Row) (hdir : a.dir = a'.dir)
    (hd : ∀ c i, isDead a.dead c i = isDead a'.dead c i) (hw : a.win = a'.win) :
    (place kh a c ws).map (·.dir) = (place kh a' c ws).map (·.dir) := by
  have hl : liveHashes kh (a.dead.insert c (bornDead a.win ws)) c ws =
      liveHashes kh (a'.dead.insert c (bornDead a'.win ws)) c ws := by
    apply liveHashes_congr
    intro c' i
    rw [isDead_insert, isDead_insert, hw, hd]
  unfold place
  dsimp only
  rw [hl, hdir]
  cases (List.foldlM (fun (d : Dir) h => d.insert h c) a'.dir
    (liveHashes kh (a'.dead.insert c (bornDead a'.win ws)) c ws) : Except Store.Refusal Dir) <;> rfl

/-- Two writes agree: both refused alike, or both give the same frame and image and equal states. -/
def StepAgree (x y : Except Store.Refusal Step) : Prop :=
  match x, y with
  | .ok s, .ok t => s.frame = t.frame ∧ s.grew = t.grew ∧ s.next.Same t.next
  | .error e, .error e' => e = e'
  | _, _ => False

theorem match_ite {p : Prop} [Decidable p] {x y : Step} (hxy : x.frame = y.frame ∧ x.grew = y.grew ∧ x.next.Same y.next) :
    StepAgree (if p then .ok x else .error .frame) (if p then .ok y else .error .frame) := by
  by_cases hp : p
  · rw [if_pos hp, if_pos hp]; exact hxy
  · rw [if_neg hp, if_neg hp]; rfl

/-- Equal states and stores equal as state give agreeing writes: the frame and head read the tree only through
    its root. -/
theorem writeDone_congr {S T : LState} {fs fs' : Fs} (h : S.Same T) (hfr : fs.hr = fs'.hr) (hfu : fs.hu = fs'.hu)
    (hfd : fs.dir = fs'.dir) (hfi : ∀ c, fs.inst.contains c = fs'.inst.contains c)
    (hfk : ∀ c i, isDead fs.dead c i = isDead fs'.dead c i) (hw : fs.win.isEmpty = true) (hw' : fs'.win.isEmpty = true)
    (hs : fs.sealing = none) (hs' : fs'.sealing = none) (b : BatchIn)
    (cw : Option (Nat × List Row × List Tomb × List Nat)) (grew : Bool) :
    StepAgree (writeDone H kh S b fs cw grew) (writeDone H kh T b fs' cw grew) := by
  obtain ⟨sh, nb, bt, sfs, bk, nx, ch, ⟨sn, se⟩, hd, ll, sa⟩ := S
  obtain ⟨sh', nb', bt', tfs, bk', nx', ch', ⟨tn, te⟩, hd', ll', sa'⟩ := T
  simp only [LState.Same] at h
  obtain ⟨rfl, rfl, rfl, -, -, -, -, -, -, -, -, -, rfl, rfl, rfl, ⟨rfl, hn⟩, rfl, rfl, rfl⟩ := h
  obtain ⟨fhr, fhu, fdir, fi, fk, fw, fsl⟩ := fs
  obtain ⟨fhr', fhu', fdir', fi', fk', fw', fsl'⟩ := fs'
  obtain rfl : fhr = fhr' := hfr
  obtain rfl : fhu = fhu' := hfu
  obtain rfl : fdir = fdir' := hfd
  obtain rfl : fsl = none := hs
  obtain rfl : fsl' = none := hs'
  unfold writeDone
  cases cw with
  | none =>
    have hro : Tree.root ⟨sn, se⟩ = Tree.root ⟨tn, se⟩ := get_congr (t := ⟨sn, se⟩) (u := ⟨tn, se⟩) rfl hn depth 0
    simp only [bind, Except.bind, pure, Except.pure, hro]
    refine match_ite ⟨rfl, rfl, ?_⟩
    exact ⟨rfl, rfl, rfl, rfl, rfl, rfl, hfi, hfk, hw, hw', rfl, rfl, rfl, rfl, rfl, ⟨rfl, hn⟩, rfl, rfl, rfl⟩
  | some w =>
    obtain ⟨c, ws, ts, tk⟩ := w
    simp only [bind, Except.bind, pure, Except.pure]
    have hsc := set_congr (H := H) (t := ⟨sn, se⟩) (u := ⟨tn, se⟩) rfl hn c
      (some (H (domain "STORE/CHUNK" ++ encMeta3 (encChunk H kh ws).mdata nx ts tk)))
    cases h1 : Tree.set H ⟨sn, se⟩ c (some (H (domain "STORE/CHUNK" ++ encMeta3 (encChunk H kh ws).mdata nx ts tk))) with
    | none =>
      rw [hsc.1.mp h1]
      rfl
    | some t1 =>
      cases h2 : Tree.set H ⟨tn, se⟩ c (some (H (domain "STORE/CHUNK" ++ encMeta3 (encChunk H kh ws).mdata nx ts tk))) with
      | none => rw [← hsc.1] at h2; rw [h1] at h2; cases h2
      | some t2 =>
        obtain ⟨he1, hn1⟩ := hsc.2 t1 t2 h1 h2
        have hro : t1.root = t2.root := get_congr he1 hn1 depth 0
        simp only [hro]
        refine match_ite ⟨rfl, rfl, ?_⟩
        exact ⟨rfl, rfl, rfl, rfl, rfl, rfl, hfi, hfk, hw, hw', rfl, rfl, rfl, rfl, rfl, ⟨he1, hn1⟩, rfl, rfl, rfl⟩

/-- Equal states write the same frame and reach equal states: heads do not depend on restarts. -/
theorem writeBatch_congr {S T : LState} (h : S.Same T) (b : BatchIn) :
    match writeBatch H kh S b, writeBatch H kh T b with
    | .ok s, .ok t => s.frame = t.frame ∧ s.grew = t.grew ∧ s.next.Same t.next
    | .error e, .error e' => e = e'
    | _, _ => False := by
  show StepAgree (writeBatch H kh S b) (writeBatch H kh T b)
  have hS := h
  obtain ⟨-, -, -, -, -, hdir, hi, hd, hwS, hwT, hsS, hsT, hbk, hnx, -⟩ := h
  have hK := killAll_congr (kh := kh) b.kills b.changed (a := (S.fs.dead, S.fs.dir)) (a' := (T.fs.dead, T.fs.dir))
    ⟨hd, hdir⟩
  have hW := foldl_rel (R := Std.HashMap.Equiv) (f := fun (m : HashMap Bytes Entry) (ke : Bytes × Entry) => m.insert ke.1 ke.2)
    (fun _ _ ke hr => hr.insert ke.1 ke.2) b.changed
    ((Std.HashMap.equiv_empty_iff_isEmpty.mpr hwS).trans (Std.HashMap.equiv_empty_iff_isEmpty.mpr hwT).symm)
  unfold writeBatch
  simp only [hi, hbk, hnx]
  by_cases hk : (b.changed.any fun ke => (b.kills ke.1).any fun x => !T.fs.inst.contains x.1) = true
  · rw [if_pos hk, if_pos hk]; rfl
  rw [if_neg hk, if_neg hk]
  by_cases hc : b.changed.isEmpty = true
  · rw [if_pos hc, if_pos hc]
    have hnil := List.isEmpty_iff.mp hc
    refine writeDone_congr hS ?_ ?_ ?_ ?_ ?_ ?_ ?_ ?_ ?_ b none false
    · rfl
    · rfl
    · exact hK.2
    · exact hi
    · exact hK.1
    · simp only [hnil, List.foldl_nil]; exact hwS
    · simp only [hnil, List.foldl_nil]; exact hwT
    · exact hsS
    · exact hsT
  rw [if_neg hc, if_neg hc]
  simp only [sealWindow, hsS, hsT, freeNum_congr hi]
  cases freeNum T.fs.inst (2 ^ cBits) 0 with
  | none => rfl
  | some c =>
    simp only [Option.getD_some, sortRows_equiv hW]
    split
    · rename_i p1 h1
      split
      · rename_i p2 h2
        have hpc : Except.map (·.dir) (Except.ok p1 : Except Store.Refusal Fs) = Except.map (·.dir) (Except.ok p2 : Except Store.Refusal Fs) := by
          rw [← h1, ← h2]; refine place_congr c _ ?_ ?_ ?_
          · exact hK.2
          · exact hK.1
          · rfl
        obtain ⟨d1, -, rfl⟩ := place_ok h1
        obtain ⟨d2, -, rfl⟩ := place_ok h2
        simp only [Except.map, Except.ok.injEq] at hpc
        refine writeDone_congr hS ?_ ?_ ?_ ?_ ?_ ?_ ?_ ?_ ?_ b _ false
        · rfl
        · rfl
        · exact hpc
        · intro c'; simp only [Std.HashSet.contains_insert, hi c']
        · intro c' i; simp only [isDead_insert, hK.1 c' i]
        · exact Std.HashMap.isEmpty_empty
        · exact Std.HashMap.isEmpty_empty
        · rfl
        · rfl
      · rename_i e2 h2
        have hpc : Except.map (·.dir) (Except.ok p1 : Except Store.Refusal Fs) = Except.map (·.dir) (Except.error e2 : Except Store.Refusal Fs) := by
          rw [← h1, ← h2]; refine place_congr c _ ?_ ?_ ?_
          · exact hK.2
          · exact hK.1
          · rfl
        simp [Except.map] at hpc
    · rename_i e0 h0
      split
      · rename_i g1 hg1
        split
        · rename_i p2 h2
          have hpc : Except.map (·.dir) (Except.error e0 : Except Store.Refusal Fs) = Except.map (·.dir) (Except.ok p2 : Except Store.Refusal Fs) := by
            rw [← h0, ← h2]; refine place_congr c _ ?_ ?_ ?_
            · exact hK.2
            · exact hK.1
            · rfl
          simp [Except.map] at hpc
        · rename_i e2 h2
          split
          · rename_i g2 hg2
            have hrc : Except.map (·.dir) (Except.ok g1 : Except Store.Refusal Fs) = Except.map (·.dir) (Except.ok g2 : Except Store.Refusal Fs) := by
              rw [← hg1, ← hg2]; refine regrowC_congr ?_ ?_ ?_ _
              · exact congrArg Dir.nb hK.2
              · intro _; rfl
              · intro _ _; rfl
            obtain ⟨dg1, rfl⟩ := regrowC_ok hg1
            obtain ⟨dg2, rfl⟩ := regrowC_ok hg2
            simp only [Except.map, Except.ok.injEq] at hrc
            simp only [Except.bind]
            clear h0 h2
            split
            · rename_i e1 h1
              split
              · rename_i e2 h2
                have hpc : Except.map (·.dir) (Except.error e1 : Except Store.Refusal Fs) = Except.map (·.dir) (Except.error e2 : Except Store.Refusal Fs) := by
                  rw [← h1, ← h2]; refine place_congr c _ ?_ ?_ ?_
                  · exact hrc
                  · intro _ _; rfl
                  · rfl
                simp only [Except.map, Except.error.injEq] at hpc
                exact hpc
              · rename_i q2 h2
                have hpc : Except.map (·.dir) (Except.error e1 : Except Store.Refusal Fs) = Except.map (·.dir) (Except.ok q2 : Except Store.Refusal Fs) := by
                  rw [← h1, ← h2]; refine place_congr c _ ?_ ?_ ?_
                  · exact hrc
                  · intro _ _; rfl
                  · rfl
                simp [Except.map] at hpc
            · rename_i q1 h1
              split
              · rename_i e2 h2
                have hpc : Except.map (·.dir) (Except.ok q1 : Except Store.Refusal Fs) = Except.map (·.dir) (Except.error e2 : Except Store.Refusal Fs) := by
                  rw [← h1, ← h2]; refine place_congr c _ ?_ ?_ ?_
                  · exact hrc
                  · intro _ _; rfl
                  · rfl
                simp [Except.map] at hpc
              · rename_i q2 h2
                have hpc : Except.map (·.dir) (Except.ok q1 : Except Store.Refusal Fs) = Except.map (·.dir) (Except.ok q2 : Except Store.Refusal Fs) := by
                  rw [← h1, ← h2]; refine place_congr c _ ?_ ?_ ?_
                  · exact hrc
                  · intro _ _; rfl
                  · rfl
                obtain ⟨d1, -, rfl⟩ := place_ok h1
                obtain ⟨d2, -, rfl⟩ := place_ok h2
                simp only [Except.map, Except.ok.injEq] at hpc
                refine writeDone_congr hS ?_ ?_ ?_ ?_ ?_ ?_ ?_ ?_ ?_ b _ true
                · rfl
                · rfl
                · exact hpc
                · intro _; rfl
                · intro _ _; rfl
                · exact Std.HashMap.isEmpty_empty
                · exact Std.HashMap.isEmpty_empty
                · rfl
                · rfl
          · rename_i e2 hg2
            have hrc : Except.map (·.dir) (Except.ok g1 : Except Store.Refusal Fs) = Except.map (·.dir) (Except.error e2 : Except Store.Refusal Fs) := by
              rw [← hg1, ← hg2]; refine regrowC_congr ?_ ?_ ?_ _
              · exact congrArg Dir.nb hK.2
              · intro _; rfl
              · intro _ _; rfl
            simp [Except.map] at hrc
      · rename_i e1 hg1
        split
        · rename_i p2 h2
          have hpc : Except.map (·.dir) (Except.error e0 : Except Store.Refusal Fs) = Except.map (·.dir) (Except.ok p2 : Except Store.Refusal Fs) := by
            rw [← h0, ← h2]; refine place_congr c _ ?_ ?_ ?_
            · exact hK.2
            · exact hK.1
            · rfl
          simp [Except.map] at hpc
        · rename_i e2 h2
          split
          · rename_i g2 hg2
            have hrc : Except.map (·.dir) (Except.error e1 : Except Store.Refusal Fs) = Except.map (·.dir) (Except.ok g2 : Except Store.Refusal Fs) := by
              rw [← hg1, ← hg2]; refine regrowC_congr ?_ ?_ ?_ _
              · exact congrArg Dir.nb hK.2
              · intro _; rfl
              · intro _ _; rfl
            simp [Except.map] at hrc
          · rename_i e2 hg2
            have hrc : Except.map (·.dir) (Except.error e1 : Except Store.Refusal Fs) = Except.map (·.dir) (Except.error e2 : Except Store.Refusal Fs) := by
              rw [← hg1, ← hg2]; refine regrowC_congr ?_ ?_ ?_ _
              · exact congrArg Dir.nb hK.2
              · intro _; rfl
              · intro _ _; rfl
            simp only [Except.map, Except.error.injEq] at hrc
            exact hrc

/-- The live key hashes of rows, from their key hashes. -/
theorem liveKhs_rows (dead : HashMap Nat (HashSet Nat)) (c : Nat) (rows : List Row) :
    liveKhs dead c (rows.map fun r => (kh r.1).toNat) = liveHashes kh dead c rows := by
  have hto : ∀ x : UInt64, x.toNat.toUInt64 = x := fun x => UInt64.ofNat_toNat
  have e : (rows.map fun r => (kh r.1).toNat).map Nat.toUInt64 = rows.map fun r => kh r.1 := by
    simp only [List.map_map, Function.comp_def, hto]
  have key : ∀ (rows : List Row) (i : Nat), ((rows.map fun r => kh r.1).zipIdx i).filterMap
        (fun (h, i) => if isDead dead c i then none else some h) = (ixs i rows).filterMap (liveHash kh dead c) := by
    intro rows
    induction rows with
    | nil => intro i; rfl
    | cons w ws ih =>
      intro i
      simp only [List.map_cons, List.zipIdx_cons, ixs, List.filterMap_cons, liveHash]
      by_cases hd : isDead dead c i = true
      · simp [hd, ih]
      · simp [hd, ih]
  unfold liveKhs liveHashes
  rw [e]
  exact key rows 0

/-- A frame replays, under key hashes that are the installed chunks' rows' key hashes (where the batch grew the
    directory the rebuild reads them), to the writer's state. -/
theorem replayFrame_step {khs : Nat → List Nat} {d : Disk} {S : LState} {b : BatchIn} {st : Step}
    (hR : Reach H kh d S) (hw : writeBatch H kh S b = .ok st)
    (hkh : ∀ c, S.fs.inst.contains c = true → khs c = (b.rows c).map fun r => (kh r.1).toNat) :
    ∃ T, replayFrame H khs S st.frame = some T ∧ T.Same st.next := by
  have hI := reach_inv hR
  obtain ⟨fs3, cw, grew, hd, -, -, -, -, hc⟩ := writeBatch_ok hI hw
  obtain ⟨hB, hwin, hseal, -⟩ := hI
  unfold writeDone at hd
  rcases hc with ⟨rfl, rfl⟩ | ⟨c, ws, rfl, -, ⟨hcb, hcn⟩, hc0, hk, hgr⟩
  · simp only [bind, Except.bind, pure, Except.pure] at hd
    cases (ite_ok hd).2
    exact ⟨_, replayFrame_none ⟨rfl, rfl, rfl, rfl⟩ rfl rfl rfl,
      rfl, rfl, rfl, rfl, rfl, rfl, fun _ => rfl, fun _ _ => rfl, hwin, hwin, hseal, hseal, rfl, rfl, rfl,
      ⟨rfl, fun _ => rfl⟩, rfl, rfl, rfl⟩
  · simp only [bind, Except.bind, pure, Except.pure] at hd
    split at hd
    · rename_i tree ht
      cases (ite_ok hd).2
      have hto : ∀ x : UInt64, x.toNat.toUInt64 = x := fun x => UInt64.ofNat_toNat
      have htk : ∀ h ∈ b.changed.flatMap (fun ke => (b.kills ke.1).map fun _ => (kh ke.1).toNat), h < 2 ^ 64 := by
        intro h hh
        obtain ⟨ke, -, hh⟩ := List.mem_flatMap.mp hh
        obtain ⟨_, -, rfl⟩ := List.mem_map.mp hh
        exact UInt64.toNat_lt _
      have hkhs : ∀ ps, ∀ k ∈ (metaOf H kh ws ps).khs, k < 2 ^ 64 := by
        intro ps k hk'
        obtain ⟨w, -, rfl⟩ := List.mem_map.mp hk'
        exact UInt64.toNat_lt _
      have hne : ∀ ke ∈ b.changed, ∀ x ∈ b.kills ke.1, x.1 ≠ c := by
        intro ke hke x hx he
        have h1 := hk ke hke x hx
        rw [he, hc0] at h1
        cases h1
      have htc : ∀ t ∈ b.changed.flatMap
          (fun ke => (b.kills ke.1).map fun x => (⟨x.1, seqOf S.book x.1, x.2.1⟩ : Tomb)), t.c ≠ c := by
        intro t ht'
        obtain ⟨ke, hke, hx'⟩ := List.mem_flatMap.mp ht'
        obtain ⟨x, hx, rfl⟩ := List.mem_map.mp hx'
        exact hne ke hke x hx
      have hmk : ∀ ps, (metaOf H kh ws ps).khs.map Nat.toUInt64 = ws.map fun w => kh w.1 := by
        intro ps
        simp only [metaOf, List.map_map]
        apply List.map_congr_left
        intro w _
        exact hto (kh w.1)
      have hkd := fold_pairs (F := fun (a : HashMap Nat (HashSet Nat) × Dir) (p : Tomb × Nat) =>
          if p.1.c ≠ c ∧ current S.book p.1 then killRow p.2.toUInt64 a (p.1.c, p.1.i, Entry.empty) else a)
        (fun ke => killRow (kh ke.1)) (fun ke => b.kills ke.1)
        (fun x => (⟨x.1, seqOf S.book x.1, x.2.1⟩ : Tomb)) (fun ke => (kh ke.1).toNat) b.changed
        (by
          intro ke hke x hx a
          dsimp only
          split
          · rw [hto]; rfl
          · rename_i hno
            exact (hno ⟨hne ke hke x hx,
              current_iff.mpr (seqOf_mem ((hB.1 x.1).mp (hk ke hke x hx)))⟩).elim) (S.fs.dead, S.fs.dir)
      cases grew
      · obtain ⟨d, hdir, rfl⟩ := hgr.1 rfl
        exact ⟨_, replayFrame_chunk ⟨rfl, rfl, rfl, rfl⟩ rfl
            (decMeta3_enc _ _ _ _ htk) (decM_encM _ (hkhs _))
            ⟨rfl, by simp [List.length_flatMap], by simp [metaOf, encChunk], hc0, hcb, hcn⟩
            (List.filter_eq_nil_iff.mpr fun t ht' => by simp [htc t ht'])
            hkd (hmk _) hdir ht rfl,
          rfl, rfl, rfl, rfl, rfl, rfl, fun _ => rfl, fun _ _ => rfl, Std.HashMap.isEmpty_empty,
          Std.HashMap.isEmpty_empty, rfl, rfl, rfl, rfl, rfl, ⟨rfl, fun _ => rfl⟩, rfl, rfl, rfl⟩
      · obtain ⟨e, dg, d', hd1, hrb, hd2, rfl, hdead⟩ := hgr.2 rfl
        have hconv : ((S.fs.inst.toList.mergeSort fun a b => decide (a ≤ b)).map fun x =>
              (x, liveKhs (b.changed.foldl (fun a ke => (b.kills ke.1).foldl (killRow (kh ke.1)) a)
                (S.fs.dead, S.fs.dir)).1 x (khs x))) =
            (((HashSet.ofList (S.book.map (·.1))).toList.mergeSort fun a b => decide (a ≤ b)).map fun x =>
              (x, liveHashes kh (deadOf S.book (b.changed.flatMap fun ke => (b.kills ke.1).map fun x =>
                (⟨x.1, seqOf S.book x.1, x.2.1⟩ : Tomb))) x (b.rows x))) := by
          rw [sortInst_eq (fun c' => (ofList_book hB c').symm)]
          apply List.map_congr_left
          intro x hx
          have hxc : S.fs.inst.contains x = true := by
            rw [← ofList_book hB x]
            exact Std.HashSet.mem_iff_contains.mp (Std.HashSet.mem_toList.mp ((List.mergeSort_perm _ _).mem_iff.mp hx))
          simp only [hkh x hxc, liveKhs_rows, liveHashes_congr hdead]
        exact ⟨_, replayFrame_chunk_grew ⟨rfl, rfl, rfl, rfl⟩ rfl
            (decMeta3_enc _ _ _ _ htk) (decM_encM _ (hkhs _))
            ⟨rfl, by simp [List.length_flatMap], by simp [metaOf, encChunk], hc0, hcb, hcn⟩
            (List.filter_eq_nil_iff.mpr fun t ht' => by simp [htc t ht'])
            hkd (hmk _) hd1 (by rw [hconv]; exact hrb) hd2 ht rfl,
          rfl, rfl, rfl, rfl, rfl, rfl,
          fun c' => by simp only [Std.HashSet.contains_insert, ofList_book hB c'],
          fun c' i => by simp only [isDead_insert, hdead c' i], Std.HashMap.isEmpty_empty,
          Std.HashMap.isEmpty_empty, rfl, rfl, rfl, rfl, rfl, ⟨rfl, fun _ => rfl⟩, rfl, rfl, rfl⟩
    · cases hd

theorem bind_ok {α β ε : Type} {x : Except ε α} {f : α → Except ε β} {y : β} (h : x.bind f = .ok y) :
    ∃ a, f a = .ok y := by
  cases x with
  | error e => simp [Except.bind] at h
  | ok a => exact ⟨a, by simpa [Except.bind] using h⟩

/-! ## What a reached disk holds -/

theorem same_symm {a b : LState} (h : a.Same b) : b.Same a := by
  obtain ⟨h1, h2, h3, h4, h5, h6, h7, h8, h9, h10, h11, h12, h13, h14, h15, ⟨h16, h17⟩, h18, h19, h20⟩ := h
  exact ⟨h1.symm, h2.symm, h3.symm, h4.symm, h5.symm, h6.symm, fun c => (h7 c).symm, fun c i => (h8 c i).symm, h10,
    h9, h12, h11, h13.symm, h14.symm, h15.symm, ⟨h16.symm, fun k => (h17 k).symm⟩, h18.symm, h19.symm, h20.symm⟩

theorem same_trans {a b c : LState} (h : a.Same b) (h' : b.Same c) : a.Same c := by
  obtain ⟨h1, h2, h3, h4, h5, h6, h7, h8, h9, -, h11, -, h13, h14, h15, ⟨h16, h17⟩, h18, h19, h20⟩ := h
  obtain ⟨g1, g2, g3, g4, g5, g6, g7, g8, -, g10, -, g12, g13, g14, g15, ⟨g16, g17⟩, g18, g19, g20⟩ := h'
  exact ⟨h1.trans g1, h2.trans g2, h3.trans g3, h4.trans g4, h5.trans g5, h6.trans g6, fun x => (h7 x).trans (g7 x),
    fun x i => (h8 x i).trans (g8 x i), h9, g10, h11, g12, h13.trans g13, h14.trans g14, h15.trans g15,
    ⟨h16.trans g16, fun k => (h17 k).trans (g17 k)⟩, h18.trans g18, h19.trans g19, h20.trans g20⟩

theorem encFrame_length_pos (f : Frame) : 0 < (encFrame f).length := by
  unfold encFrame frameBody frameHdr frameTag
  cases f.chunk <;> simp

theorem length_le_flatMap : ∀ (fs : List Frame), fs.length ≤ (fs.flatMap encFrame).length
  | [] => by simp
  | f :: fs => by
    have := encFrame_length_pos f
    have := length_le_flatMap fs
    simp only [List.flatMap_cons, List.length_append, List.length_cons]
    omega

theorem decFrames_app : ∀ (fs : List Frame) (n : Nat) (X : Bytes), (∀ f ∈ fs, f.Wf) → fs.length ≤ n →
    decFrames n (fs.flatMap encFrame ++ X) = fs ++ decFrames (n - fs.length) X
  | [], n, X, _, _ => by simp
  | f :: fs, 0, X, _, hn => by simp at hn
  | f :: fs, n + 1, X, hw, hn => by
    simp only [List.flatMap_cons, List.append_assoc, decFrames, decFrame_enc (hw f (List.mem_cons_self ..)),
      List.cons_append, List.length_cons]
    rw [decFrames_app fs n X (fun g hg => hw g (List.mem_cons_of_mem _ hg)) (by simp only [List.length_cons] at hn; omega)]
    simp

theorem decFrames_nil : ∀ n, decFrames n [] = []
  | 0 => rfl
  | n + 1 => by simp [decFrames, decFrame, takeN]

/-- A batch that placed chunk `c` wrote the pages and the metadata of its rows `ws`. -/
theorem writeDone_fields {S : LState} {b : BatchIn} {fs3 : Fs} {cw : Option (Nat × List Row × List Tomb × List Nat)}
    {grew : Bool} {st : Step} (h : writeDone H kh S b fs3 cw grew = .ok st) :
    st.frame.shard = S.shard ∧ st.frame.nb0 = S.nb0 ∧ st.frame.prev = S.head ∧ st.next.shard = S.shard ∧
      st.next.nb0 = S.nb0 ∧ st.frame.head = st.next.head ∧ st.frame.batches = st.next.batches ∧
      (cw = none → st.frame.chunk = none ∧ st.next.nx = S.nx) ∧
      ∀ c ws ts tk, cw = some (c, ws, ts, tk) →
        st.frame.chunk = some (c, (encChunk H kh ws).pages, encMeta3 (encChunk H kh ws).mdata S.nx ts tk) ∧
          st.next.nx = S.nx + 1 := by
  unfold writeDone at h
  cases cw with
  | none =>
    simp only [bind, Except.bind, pure, Except.pure] at h
    obtain ⟨-, h⟩ := ite_ok h
    cases h
    exact ⟨rfl, rfl, rfl, rfl, rfl, rfl, rfl, fun _ => ⟨rfl, rfl⟩, (fun _ _ _ _ h => by cases h)⟩
  | some w =>
    obtain ⟨c, ws, ts, tk⟩ := w
    simp only [bind, Except.bind, pure, Except.pure] at h
    split at h
    · obtain ⟨-, h⟩ := ite_ok h
      cases h
      exact ⟨rfl, rfl, rfl, rfl, rfl, rfl, rfl, (fun h => by cases h),
        (fun c' ws' ts' tk' h' => by cases h'; exact ⟨rfl, rfl⟩)⟩
    · cases h

/-- The key hashes `khsOf` takes from one frame. -/
def khsIn (c : Nat) (f : Frame) : Option (List Nat) :=
  match f.chunk with
  | some (x, _, m3) => if x = c then (decMeta3 m3 >>= fun y => decM y.1).map (·.khs) else none
  | none => none

theorem khsOf_eq (frs : List Frame) (c : Nat) : khsOf frs c = (frs.findSome? (khsIn c)).getD [] := rfl

/-- The metadata a frame writes for rows `ws` holds their key hashes. -/
theorem khsIn_enc {f : Frame} {c : Nat} {pages : List Bytes} {ws : List Row} {ps : List Bytes} {seq : Nat}
    {ts : List Tomb} {tk : List Nat} (htk : ∀ h ∈ tk, h < 2 ^ 64)
    (hch : f.chunk = some (c, pages, encMeta3 (encMeta H kh ws ps) seq ts tk)) :
    khsIn c f = some (ws.map fun w => (kh w.1).toNat) := by
  have hkhs : ∀ k ∈ (metaOf H kh ws ps).khs, k < 2 ^ 64 := by
    intro k hk'
    obtain ⟨w, -, rfl⟩ := List.mem_map.mp hk'
    exact UInt64.toNat_lt _
  simp only [khsIn, hch, if_true, decMeta3_enc _ _ _ _ htk, encMeta]
  show Option.map _ (decM (encM (metaOf H kh ws ps))) = _
  rw [decM_encM _ hkhs]
  rfl

/-- What one batch's frame holds: the writer's shard, bucket count and head before; the chunk, when there is one, is
    the next number, with the pages of its rows and the key hashes of them in its metadata. -/
theorem writeBatch_chunk {S : LState} {b : BatchIn} {st : Step} (hI : S.Inv H) (hw : writeBatch H kh S b = .ok st) :
    st.frame.shard = S.shard ∧ st.frame.nb0 = S.nb0 ∧ st.frame.prev = S.head ∧ st.next.shard = S.shard ∧
      st.next.nb0 = S.nb0 ∧ st.frame.head = st.next.head ∧ st.frame.batches = st.next.batches ∧
      ((st.frame.chunk = none ∧ st.next.nx = S.nx) ∨
        ∃ c ws m3, st.frame.chunk = some (c, (encChunk H kh ws).pages, m3) ∧ c = S.nx ∧ st.next.nx = S.nx + 1 ∧
          khsIn c st.frame = some (ws.map fun w => (kh w.1).toNat)) := by
  obtain ⟨fs3, cw, grew, hd, -, -, -, -, hc⟩ := writeBatch_ok hI hw
  obtain ⟨h1, h2, h3, h4, h5, h6, h7, h8, h9⟩ := writeDone_fields hd
  refine ⟨h1, h2, h3, h4, h5, h6, h7, ?_⟩
  rcases hc with ⟨rfl, -⟩ | ⟨c, ws, rfl, -, ⟨-, hcn⟩, -, -, -⟩
  · exact .inl (h8 rfl)
  · obtain ⟨hch, hnx⟩ := h9 _ _ _ _ rfl
    have htk : ∀ h ∈ b.changed.flatMap (fun ke => (b.kills ke.1).map fun _ => (kh ke.1).toNat), h < 2 ^ 64 := by
      intro h hh
      obtain ⟨ke, -, hh⟩ := List.mem_flatMap.mp hh
      obtain ⟨_, -, rfl⟩ := List.mem_map.mp hh
      exact UInt64.toNat_lt _
    exact .inr ⟨c, ws, _, hch, hcn, hnx, khsIn_enc htk hch⟩

theorem khsOf_append {frs gs : List Frame} {c : Nat} (h : (frs.findSome? (khsIn c)).isSome = true) :
    khsOf (frs ++ gs) c = khsOf frs c := by
  rw [khsOf_eq, khsOf_eq, List.findSome?_append]
  cases hx : frs.findSome? (khsIn c) with
  | none => rw [hx] at h; simp at h
  | some v => simp

theorem isSome_append {frs gs : List Frame} {c : Nat} (h : (frs.findSome? (khsIn c)).isSome = true) :
    ((frs ++ gs).findSome? (khsIn c)).isSome = true := by
  rw [List.findSome?_append]
  cases hx : frs.findSome? (khsIn c) with
  | none => rw [hx] at h; simp at h
  | some v => simp

theorem isSome_append_right {frs gs : List Frame} {c : Nat} (h : (gs.findSome? (khsIn c)).isSome = true) :
    ((frs ++ gs).findSome? (khsIn c)).isSome = true := by
  rw [List.findSome?_append]
  cases hx : frs.findSome? (khsIn c) with
  | none => simpa using h
  | some v => simp

/-- The start state's heads and authority record are never read by a replay. -/
theorem replayFrame_start (khs : Nat → List Nat) (S : LState) (x y : Head) (z : Bytes) (f : Frame) :
    replayFrame H khs { S with fs := { S.fs with hr := x, hu := y }, au := z } f = replayFrame H khs S f := rfl

/-- A replay reads key hashes only for the installed chunks. -/
theorem replayFrame_khs {khs khs' : Nat → List Nat} {S : LState}
    (h : ∀ c, S.fs.inst.contains c = true → khs c = khs' c) (f : Frame) :
    replayFrame H khs S f = replayFrame H khs' S f := by
  have key : ∀ a, ((S.fs.inst.toList.mergeSort fun a b => decide (a ≤ b)).map fun x => (x, liveKhs a x (khs x))) =
      ((S.fs.inst.toList.mergeSort fun a b => decide (a ≤ b)).map fun x => (x, liveKhs a x (khs' x))) := by
    intro a
    apply List.map_congr_left
    intro x hx
    have : S.fs.inst.contains x = true :=
      Std.HashSet.mem_iff_contains.mp (Std.HashSet.mem_toList.mp ((List.mergeSort_perm _ _).mem_iff.mp hx))
    rw [h x this]
  unfold replayFrame
  simp only [key]

theorem same_refl_of {S : LState} (h1 : S.fs.win.isEmpty = true) (h2 : S.fs.sealing = none) : S.Same S :=
  ⟨rfl, rfl, rfl, rfl, rfl, rfl, fun _ => rfl, fun _ _ => rfl, h1, h1, h2, h2, rfl, rfl, rfl, ⟨rfl, fun _ => rfl⟩,
    rfl, rfl, rfl⟩

theorem decFrames_flat {frs : List Frame} (hWf : ∀ f ∈ frs, f.Wf) :
    decFrames (frs.flatMap encFrame).length (frs.flatMap encFrame) = frs := by
  have := decFrames_app frs (frs.flatMap encFrame).length [] hWf (length_le_flatMap frs)
  simpa [decFrames_nil] using this

theorem stepOps_log (st : Step) (d : Disk) :
    runOps (stepOps st) d "log" = some ((d "log").getD [] ++ encFrame st.frame) := by
  simp [stepOps, runOps, Op.run, Disk.set]

theorem crash_nil (i n : Nat) (d : Disk) : crash [] i n d = d := by simp [crash, runOps]

theorem crash_zero (o : Op) (os : List Op) (n : Nat) (d : Disk) : crash (o :: os) 0 n d = (o.part n).run d := by
  simp [crash, runOps]

theorem crash_succ (o : Op) (os : List Op) (i n : Nat) (d : Disk) :
    crash (o :: os) (i + 1) n d = crash os i n (o.run d) := by
  simp [crash, runOps]

/-- A crash in a batch's writes (the frame torn, written but not synced, or synced) leaves the old log followed by a
    start of the frame, and every other file as it was. -/
theorem crash_log (st : Step) (d : Disk) (i n : Nat) :
    ∃ X, X <+: encFrame st.frame ∧ crash (stepOps st) i n d "log" = some ((d "log").getD [] ++ X) ∧
      ∀ f, f ≠ "log" → crash (stepOps st) i n d f = d f := by
  rcases i with _ | i
  · exact ⟨(encFrame st.frame).take n, List.take_prefix _ _,
      by simp [stepOps, crash_zero, Op.part, Op.run, Disk.set],
      fun f hf => by simp [stepOps, crash_zero, Op.part, Op.run, Disk.set, hf]⟩
  · rcases i with _ | i <;>
      exact ⟨encFrame st.frame, List.prefix_refl _,
        by simp [stepOps, crash_zero, crash_succ, crash_nil, Op.part, Op.run, Disk.set],
        fun f hf => by simp [stepOps, crash_zero, crash_succ, crash_nil, Op.part, Op.run, Disk.set, hf]⟩

theorem decFrames_prefix {fr : Frame} {X : Bytes} (hf : fr.Wf) (hX : X <+: encFrame fr) (m : Nat) :
    (decFrames m X).length ≤ 1 := by
  obtain ⟨Y, hY⟩ := hX
  cases m with
  | zero => simp [decFrames]
  | succ m =>
    rcases Nat.lt_or_ge X.length (encFrame fr).length with hlt | hge
    · have e : X = (encFrame fr).take X.length := by rw [← hY]; simp
      rw [e]
      simp [decFrames, decFrame_torn hf hlt]
    · have hl := congrArg List.length hY
      rw [List.length_append] at hl
      have hY0 : Y = [] := List.eq_nil_of_length_eq_zero (by omega)
      rw [hY0, List.append_nil] at hY
      rw [hY]
      have := decFrame_enc hf []
      rw [List.append_nil] at this
      simp [decFrames, this, decFrames_nil]

/-- Equal leaf hashes: the same leaf, or two distinct leaf inputs with one digest. -/
theorem leafH_binds {v v' : Option Bytes} (h : leafH H v = leafH H v') : v = v' ∨ Collides H := by
  by_cases e : (domain "STORE/LEAF" ++ (match v with | none => [0] | some r => 1 :: r)) =
      (domain "STORE/LEAF" ++ (match v' with | none => [0] | some r => 1 :: r))
  · left
    have e2 := List.append_cancel_left e
    cases v <;> cases v' <;> simp at e2 ⊢ <;> exact e2
  · right
    refine ⟨_, _, e, ?_⟩
    cases v <;> cases v' <;> simpa [leafH] using h

/-- Going up from level `l` to `l + k`: nodes that agree off the path and recompute to one node agree on the path, or
    two distinct node inputs share a digest. -/
theorem up_binds : ∀ (k : Nat) (t u : Tree) (l j : Nat),
    (∀ l' i', l ≤ l' → (l', i') ≠ (l, j) → t.get l' i' = u.get l' i') →
    (Tree.up H t k l j).get (l + k) (j / 2 ^ k) = (Tree.up H u k l j).get (l + k) (j / 2 ^ k) →
    t.get l j = u.get l j ∨ Collides H
  | 0, t, u, l, j, hn, h => by
    left
    simpa [Tree.up] using h
  | k + 1, t, u, l, j, hn, h => by
    simp only [Tree.up] at h
    have e1 : l + (k + 1) = l + 1 + k := by omega
    have e2 : j / 2 ^ (k + 1) = j / 2 / 2 ^ k := by
      rw [Nat.div_div_eq_div_mul, Nat.pow_succ, Nat.mul_comm]
    rw [e1, e2] at h
    have ih := up_binds k _ _ (l + 1) (j / 2) (by
      intro l' i' hl hne
      simp only [Chunk.get_put]
      have h1 : ¬ (l + 1 = l' ∧ j / 2 = i') := fun ⟨a, b⟩ => hne (by rw [← a, ← b])
      rw [if_neg h1, if_neg h1]
      exact hn l' i' (by omega) (fun hh => by have := congrArg Prod.fst hh; simp at this; omega)) h
    rcases ih with ih | ih
    · simp only [Chunk.get_put, and_self, if_true] at ih
      by_cases e : domain "STORE/NODE" ++ t.get l (2 * (j / 2)) ++ t.get l (2 * (j / 2) + 1) =
          domain "STORE/NODE" ++ u.get l (2 * (j / 2)) ++ u.get l (2 * (j / 2) + 1)
      · left
        have hj : j = 2 * (j / 2) ∨ j = 2 * (j / 2) + 1 := by omega
        rcases hj with hj | hj
        · have hb := hn l (2 * (j / 2) + 1) (Nat.le_refl _) (fun hh => by simp at hh; omega)
          rw [hb] at e
          have e' := List.append_cancel_right e
          have e'' := List.append_cancel_left e'
          have h1 : t.get l j = t.get l (2 * (j / 2)) := by congr 1
          have h2 : u.get l j = u.get l (2 * (j / 2)) := by congr 1
          rw [h1, h2, e'']
        · have ha := hn l (2 * (j / 2)) (Nat.le_refl _) (fun hh => by simp at hh; omega)
          rw [ha] at e
          simp only [List.append_assoc] at e
          have e'' := List.append_cancel_left (List.append_cancel_left e)
          have h1 : t.get l j = t.get l (2 * (j / 2) + 1) := by congr 1
          have h2 : u.get l j = u.get l (2 * (j / 2) + 1) := by congr 1
          rw [h1, h2]
          exact e''
      · right
        exact ⟨_, _, e, ih⟩
    · right; exact ih

/-- A chunk tree's root after one `Tree.set` from trees of equal contents fixes the leaf, or two distinct inputs share a
    digest. -/
theorem set_binds {t u t1 u1 : Tree} {i : Nat} {v v' : Option Bytes}
    (he : ∀ l i', t.get l i' = u.get l i') (h1 : t.set H i v = some t1) (h2 : u.set H i v' = some u1)
    (hr : t1.root = u1.root) : v = v' ∨ Collides H := by
  unfold Tree.set at h1 h2
  split at h1
  · rename_i hi
    rw [if_pos hi] at h2
    have h1 := Option.some.inj h1
    have h2 := Option.some.inj h2
    subst h1 h2
    unfold Tree.root at hr
    have e : (0 : Nat) + depth = depth := by omega
    have e2 : i / 2 ^ depth = 0 := Nat.div_eq_of_lt hi
    have hb := up_binds (H := H) depth (t.put 0 i (leafH H v)) (u.put 0 i (leafH H v')) 0 i (by
      intro l' i' _ hne
      simp only [Chunk.get_put]
      have h1 : ¬ (0 = l' ∧ i = i') := fun ⟨a, b⟩ => hne (by rw [← a, ← b])
      rw [if_neg h1, if_neg h1]
      exact he l' i') (by rw [e, e2]; exact hr)
    rcases hb with hb | hb
    · simp only [Chunk.get_put, and_self, if_true] at hb
      exact leafH_binds hb
    · exact Or.inr hb
  · cases h1

theorem writeDone_frame {S : LState} {b : BatchIn} {fs3 : Fs} {cw : Option (Nat × List Row × List Tomb × List Nat)}
    {grew : Bool} {st : Step} (h : writeDone H kh S b fs3 cw grew = .ok st) :
    st.frame.Wf ∧ st.next.batches = S.batches + 1 := by
  unfold writeDone at h
  cases cw with
  | none =>
    simp only [bind, Except.bind, pure, Except.pure] at h
    obtain ⟨hf, h⟩ := ite_ok h
    cases h
    exact ⟨hf, rfl⟩
  | some w =>
    obtain ⟨c, ws, ts, tk⟩ := w
    simp only [bind, Except.bind, pure, Except.pure] at h
    split at h
    · obtain ⟨hf, h⟩ := ite_ok h
      cases h
      exact ⟨hf, rfl⟩
    · cases h

/-- A batch's frame is one the format holds, and it counts one batch more. -/
theorem writeBatch_frame {S : LState} {b : BatchIn} {st : Step} (hI : S.Inv H) (hw : writeBatch H kh S b = .ok st) :
    st.frame.Wf ∧ st.next.batches = S.batches + 1 := by
  obtain ⟨_, _, _, hd, -⟩ := writeBatch_ok hI hw
  exact writeDone_frame hd

/-- A reached disk's log is the whole frames of its batches, one per batch. -/
theorem reach_log {d : Disk} {S : LState} (hR : Reach H kh d S) :
    ∃ frs : List Frame, (∀ f ∈ frs, f.Wf) ∧ frs.length = S.batches ∧ (d "log").getD [] = frs.flatMap encFrame := by
  induction hR with
  | genesis => exact ⟨[], by simp, rfl, rfl⟩
  | @step d S b st hR hw _ ih =>
    obtain ⟨frs, hf, hl, hd⟩ := ih
    obtain ⟨hw', hb⟩ := writeBatch_frame (reach_inv hR) hw
    refine ⟨frs ++ [st.frame], ?_, by simp [hl, hb], by rw [stepOps_log, Option.getD_some, hd]; simp⟩
    intro f hm
    rcases List.mem_append.mp hm with hm | hm
    · exact hf f hm
    · rw [List.mem_singleton.mp hm]; exact hw'
  | same _ hs ih =>
    obtain ⟨frs, hf, hl, hd⟩ := ih
    exact ⟨frs, hf, hl.trans hs.2.2.1, hd⟩

theorem crash_new_refused' {d : Disk} {S : LState} {b : BatchIn} {st : Step} {names : List String}
    (hR : Reach H kh d S) (hw : writeBatch H kh S b = .ok st) {n : Nat} (hn : n < (encFrame st.frame).length) :
    ∀ T p rep, loadLog H (crash (stepOps st) 0 n d) names st.next.head st.next.batches ≠ .ok (T, p, rep) := by
  intro T p rep hl
  obtain ⟨frs, hfw, hlen, hd⟩ := reach_log hR
  obtain ⟨hf, hb⟩ := writeBatch_frame (reach_inv hR) hw
  -- the log holds the old frames and a torn start of the new one, so no frame is read at the new batch
  have hc : crash (stepOps st) 0 n d "log" = some (frs.flatMap encFrame ++ (encFrame st.frame).take n) := by
    rw [← hd]; simp [stepOps, crash_zero, Op.part, Op.run, Disk.set]
  have hfr : decFrames (frs.flatMap encFrame ++ (encFrame st.frame).take n).length
      (frs.flatMap encFrame ++ (encFrame st.frame).take n) = frs := by
    have := length_le_flatMap frs
    rw [decFrames_app frs _ _ hfw (by simp only [List.length_append]; omega)]
    cases (frs.flatMap encFrame ++ (encFrame st.frame).take n).length - frs.length with
    | zero => simp [decFrames]
    | succ m => simp [decFrames, decFrame_torn hf hn]
  have hnone : (decFrames (frs.flatMap encFrame ++ (encFrame st.frame).take n).length
      (frs.flatMap encFrame ++ (encFrame st.frame).take n))[st.next.batches - 1]? = none := by
    rw [hfr, hb, Nat.add_sub_cancel, ← hlen]; simp
  unfold loadLog at hl
  split at hl
  · cases hl
  split at hl
  · cases hl
  simp only [hc, hnone] at hl
  split at hl <;> simp_all

/-- While the frame is torn the new head is refused. -/
theorem crash_new_refused {d : Disk} {S : LState} {b : BatchIn} {st : Step} {names : List String}
    (hR : Reach H kh d S) (hw : writeBatch H kh S b = .ok st) {n : Nat} (hn : n < (encFrame st.frame).length) :
    (∀ T p rep, loadLog H (crash (stepOps st) 0 n d) names st.next.head st.next.batches ≠ .ok (T, p, rep)) ∨
      Collides H :=
  Or.inl (crash_new_refused' hR hw hn)


/-- The chunks the writer's state has installed: the old ones and the one its frame holds. -/
theorem writeBatch_inst {S : LState} {b : BatchIn} {st : Step} (hI : S.Inv H) (hw : writeBatch H kh S b = .ok st)
    (c : Nat) :
    st.next.fs.inst.contains c = true ↔ S.fs.inst.contains c = true ∨ (khsIn c st.frame).isSome = true := by
  obtain ⟨fs3, cw, grew, hd, -, -, -, -, hc⟩ := writeBatch_ok hI hw
  obtain ⟨-, -, -, -, -, -, -, hx⟩ := writeBatch_chunk hI hw
  obtain ⟨hB, -⟩ := hI
  have hfs := writeDone_fs hd
  obtain ⟨-, -, -, -, -, -, -, h8, h9⟩ := writeDone_fields hd
  rw [hfs]
  rcases hc with ⟨rfl, rfl⟩ | ⟨c0, ws, rfl, -, ⟨-, hcn⟩, hc0, -, hgr⟩
  · have hn := (h8 rfl).1
    simp [khsIn, hn]
  · obtain ⟨hch, -⟩ := h9 _ _ _ _ rfl
    rcases hx with ⟨hn, -⟩ | ⟨c1, ws1, m3, hch1, -, -, hk1⟩
    · rw [hch] at hn; cases hn
    rw [hch] at hch1
    simp only [Option.some.injEq, Prod.mk.injEq] at hch1
    obtain ⟨rfl, -⟩ := hch1
    have hn : ∀ c, c ≠ c0 → khsIn c st.frame = none := by
      intro c hcc
      simp [khsIn, hch, Ne.symm hcc]
    cases grew
    · obtain ⟨d, -, rfl⟩ := hgr.1 rfl
      by_cases hcc : c0 = c
      · subst hcc
        simp [hk1]
      · simp [hcc, hn c (Ne.symm hcc)]
    · obtain ⟨e, dg, d, -, -, -, rfl, -⟩ := hgr.2 rfl
      by_cases hcc : c0 = c
      · subst hcc
        simp [hk1]
      · simp [hcc, hn c (Ne.symm hcc), ofList_book hB c]

theorem replayFrame_check {khs : Nat → List Nat} {S T : LState} {f : Frame} (h : replayFrame H khs S f = some T) :
    f.shard = S.shard ∧ f.nb0 = S.nb0 ∧ f.batches = S.batches + 1 ∧ f.prev = S.head := by
  refine Classical.byContradiction fun hn => ?_
  unfold replayFrame at h
  simp [hn] at h

/-- A frame replays on any state equal to the writer's, to a state equal to the writer's next. -/
theorem replay_step_at {khs : Nat → List Nat} {d : Disk} {S T : LState} {b : BatchIn} {st : Step}
    (hR : Reach H kh d S) (hT : T.Same S) (hw : writeBatch H kh S b = .ok st)
    (hkh : ∀ c, S.fs.inst.contains c = true → khs c = (b.rows c).map fun r => (kh r.1).toNat) :
    ∃ T', replayFrame H khs T st.frame = some T' ∧ T'.Same st.next := by
  have hRT : Reach H kh d T := Reach.same hR (same_symm hT)
  have hc := writeBatch_congr (H := H) (kh := kh) (same_symm hT) b
  rw [hw] at hc
  cases hw' : writeBatch H kh T b with
  | error e => rw [hw'] at hc; exact hc.elim
  | ok st' =>
    rw [hw'] at hc
    obtain ⟨hf, -, hn⟩ := hc
    have hkhT : ∀ c, T.fs.inst.contains c = true → khs c = (b.rows c).map fun r => (kh r.1).toNat := by
      intro c hcT
      apply hkh c
      have := hT.2.2.2.2.2.2.1 c
      rw [← this]
      exact hcT
    obtain ⟨T', hr, hs⟩ := replayFrame_step hRT hw' hkhT
    exact ⟨T', by rw [hf]; exact hr, same_trans hs (same_symm hn)⟩

/-- What a reached disk holds: the log's whole frames, one per batch, and no other file; the key hashes the log gives
    every installed chunk; and the replay of the log from the empty store reaches the writer's state under any key
    hashes agreeing with the log on the installed chunks. -/
theorem reach_replay {d : Disk} {S : LState} (hR : Reach H kh d S) :
    ∃ (sh asOf nb : Nat) (au : Bytes) (frs : List Frame), (∀ f ∈ frs, f.Wf) ∧ frs.length = S.batches ∧
      (d "log").getD [] = frs.flatMap encFrame ∧ (∀ f, f ≠ "log" → d f = none) ∧
      (∀ c, S.fs.inst.contains c = true → (frs.findSome? (khsIn c)).isSome = true) ∧
      (∀ f, frs.getLast? = some f → f.head = S.head ∧ f.batches = S.batches) ∧
      ∀ khs : Nat → List Nat, (∀ c, S.fs.inst.contains c = true → khs c = khsOf frs c) →
        ∃ T, frs.foldlM (replayFrame H khs) (LState.genesis H sh asOf nb au) = some T ∧ T.Same S := by
  induction hR with
  | genesis shard asOf nb au _ =>
    refine ⟨shard, asOf, nb, au, [], by simp, rfl, rfl, fun f _ => rfl, fun c hc => ?_, fun f h => by simp at h,
      fun khs _ => ⟨_, rfl, same_refl_of Std.HashMap.isEmpty_empty rfl⟩⟩
    simp [LState.genesis] at hc
  | @step d S b st hR hw hb ih =>
    obtain ⟨sh, asOf, nb, au, frs, hwf, hlen, hlog, hfiles, hQ, hlast, hrep⟩ := ih
    have hI := reach_inv hR
    obtain ⟨hw', hbt⟩ := writeBatch_frame hI hw
    obtain ⟨-, -, -, -, -, h6, h7, -⟩ := writeBatch_chunk hI hw
    have hinst := writeBatch_inst hI hw
    refine ⟨sh, asOf, nb, au, frs ++ [st.frame], ?_, by simp [hlen, hbt],
      by rw [stepOps_log, Option.getD_some, hlog]; simp, ?_, ?_, ?_, ?_⟩
    · intro f hm
      rcases List.mem_append.mp hm with hm | hm
      · exact hwf f hm
      · rw [List.mem_singleton.mp hm]; exact hw'
    · intro f hf
      simp [stepOps, runOps, Op.run, Disk.set, hf, hfiles f hf]
    · intro c hc
      rcases (hinst c).mp hc with h | h
      · exact isSome_append (hQ c h)
      · exact isSome_append_right (by simpa using h)
    · intro f hf
      simp at hf
      subst hf
      exact ⟨h6, h7⟩
    · intro khs hkhs
      have hkhs' : ∀ c, S.fs.inst.contains c = true → khs c = khsOf frs c := fun c hc =>
        (hkhs c ((hinst c).mpr (.inl hc))).trans (khsOf_append (hQ c hc))
      obtain ⟨T, hT, hTS⟩ := hrep khs hkhs'
      have hb' : ∀ c, S.fs.inst.contains c = true → (b.rows c).map (fun r => (kh r.1).toNat) = khsOf frs c := by
        intro c hc
        have := hb c hc
        rw [hlog, decFrames_flat hwf] at this
        exact this
      obtain ⟨T', hT', hT'S⟩ := replay_step_at hR hTS hw fun c hc => (hkhs' c hc).trans (hb' c hc).symm
      exact ⟨T', by simp [List.foldlM_append, hT, hT'], hT'S⟩
  | same hR hs ih =>
    obtain ⟨sh, asOf, nb, au, frs, hwf, hlen, hlog, hfiles, hQ, hlast, hrep⟩ := ih
    have hs' := hs
    obtain ⟨-, -, hbt, -, -, -, hin, -, -, -, -, -, -, -, -, -, hhd, -, -⟩ := hs'
    refine ⟨sh, asOf, nb, au, frs, hwf, hlen.trans hbt, hlog, hfiles, fun c hc => hQ c (by rw [hin c]; exact hc),
      fun f hf => ⟨(hlast f hf).1.trans hhd, (hlast f hf).2.trans hbt⟩, fun khs hk => ?_⟩
    obtain ⟨T0, h0, hs0⟩ := hrep khs fun c hc => hk c (by rw [← hin c]; exact hc)
    exact ⟨T0, h0, same_trans hs0 hs⟩
theorem names_ok {names : List String} (hn : ∀ n ∈ names, n = "lock" ∨ n = "log") :
    names.any (fun n => !(n = "lock" || n = "log")) = false := by
  simp only [List.any_eq_false]
  intro x hx
  rcases hn x hx with rfl | rfl <;> simp

theorem loadLog_of {d' : Disk} {names : List String} {hd : Bytes} {bt : Nat} {L : Bytes} {fs : List Frame}
    {f0 tg : Frame} {T : LState}
    (hbt : bt ≠ 0) (hn : names.any (fun n => !(n = "lock" || n = "log")) = false) (hL : d' "log" = some L)
    (hfs : decFrames L.length L = fs) (h0 : fs[0]? = some f0) (hg : fs[bt - 1]? = some tg)
    (hc : (fs.length = bt ∨ fs.length = bt + 1) ∧ tg.head = hd ∧ tg.batches = bt)
    (hT : (fs.take bt).foldlM (replayFrame H (khsOf fs))
      { LState.genesis H f0.shard 0 f0.nb0 f0.au with head := f0.prev } = some T) :
    loadLog H d' names hd bt = (match fs[bt]? with
      | none => .ok (T, none, [.trunc "log" T.logLen])
      | some p => match replayFrame H (khsOf fs) T p with
        | none => .error "REPLAY"
        | some _ => .ok (T, some p, [.trunc "log" (T.logLen + (encFrame p).length)])) := by
  unfold loadLog
  simp only [hbt, if_false, hn, Bool.false_eq_true, hL, hfs, h0, hg, hc, and_self, if_true, hT]
  all_goals rfl

/-- The replay from the empty store of the first frame's shard and bucket count, with that frame's head before it,
    is the replay from the writer's genesis: a replay never reads the start state's heads or authority record. -/
theorem replay_start {khs : Nat → List Nat} {sh asOf nb : Nat} {au : Bytes} {f0 : Frame} {rest : List Frame}
    {T : LState} (h : (f0 :: rest).foldlM (replayFrame H khs) (LState.genesis H sh asOf nb au) = some T) :
    (f0 :: rest).foldlM (replayFrame H khs)
      { LState.genesis H f0.shard 0 f0.nb0 f0.au with head := f0.prev } = some T := by
  cases hr : replayFrame H khs (LState.genesis H sh asOf nb au) f0 with
  | none => simp [List.foldlM, hr] at h
  | some T1 =>
    obtain ⟨hsh, hnb, -, hpr⟩ := replayFrame_check hr
    have hsh' : f0.shard = sh := hsh
    have hnb' : f0.nb0 = nb := hnb
    subst hsh' hnb'
    have key : replayFrame H khs { LState.genesis H f0.shard 0 f0.nb0 f0.au with head := f0.prev } f0 = some T1 := by
      have hG : ({ LState.genesis H f0.shard 0 f0.nb0 f0.au with head := f0.prev } : LState) =
          { LState.genesis H f0.shard asOf f0.nb0 au with
            fs := { (LState.genesis H f0.shard asOf f0.nb0 au).fs with
              hr := (LState.genesis H f0.shard 0 f0.nb0 f0.au).fs.hr, hu := (LState.genesis H f0.shard 0 f0.nb0 f0.au).fs.hu },
            au := f0.au } := by
        rw [hpr]; rfl
      rw [hG, replayFrame_start]
      exact hr
    simpa [List.foldlM, key, hr] using h
/-- A start of one frame decodes to nothing or, when it is the whole frame, to that frame. -/
theorem decFrames_part {fr : Frame} {X : Bytes} (hf : fr.Wf) (hX : X <+: encFrame fr) (m : Nat) :
    decFrames m X = [] ∨ (decFrames m X = [fr] ∧ X = encFrame fr) := by
  obtain ⟨Y, hY⟩ := hX
  cases m with
  | zero => left; simp [decFrames]
  | succ m =>
    rcases Nat.lt_or_ge X.length (encFrame fr).length with hlt | hge
    · have e : X = (encFrame fr).take X.length := by rw [← hY]; simp
      left
      rw [e]
      simp [decFrames, decFrame_torn hf hlt]
    · have hl := congrArg List.length hY
      rw [List.length_append] at hl
      have hY0 : Y = [] := List.eq_nil_of_length_eq_zero (by omega)
      rw [hY0, List.append_nil] at hY
      right
      refine ⟨?_, hY⟩
      rw [hY]
      have := decFrame_enc hf []
      rw [List.append_nil] at this
      simp [decFrames, this, decFrames_nil]

theorem loadLog_congr {d1 d2 : Disk} (h : d1 "log" = d2 "log") (names : List String) (hd : Bytes) (bt : Nat) :
    loadLog H d1 names hd bt = loadLog H d2 names hd bt := by
  simp only [loadLog, h]

theorem names_of_lists {d : Disk} {names : List String} (hl : Lists d names) (h : ∀ f, f ≠ "log" → d f = none) :
    names.any (fun n => !(n = "lock" || n = "log")) = false := by
  apply names_ok
  intro n hn
  by_cases hne : n = "log"
  · exact Or.inr hne
  · have := (hl n).mpr hn
    rw [h n hne] at this
    simp at this

/-- Whatever follows the writer's log (nothing, or the whole frame of a batch ahead that replays), a load at the writer's
    head gives the writer's state, the frame ahead kept pending. -/
theorem load_old {d d' : Disk} {S : LState} {names : List String} (hR : Reach H kh d S) (h0 : 0 < S.batches)
    (hno : names.any (fun n => !(n = "lock" || n = "log")) = false) {X : Bytes}
    (hX : d' "log" = some ((d "log").getD [] ++ X)) (g0 : Frame)
    (hgs : ∀ m, decFrames m X = [] ∨ (decFrames m X = [g0] ∧ X = encFrame g0 ∧ ∀ (T : LState) (khs : Nat → List Nat),
        T.Same S → (∀ c, S.fs.inst.contains c = true →
          khs c = khsOf (decFrames ((d "log").getD []).length ((d "log").getD [])) c) →
        ∃ T', replayFrame H khs T g0 = some T')) :
    ∃ T p rep, loadLog H d' names S.head S.batches = .ok (T, p, rep) ∧ T.Same S ∧
      (p = none ∨ (p = some g0 ∧ X = encFrame g0)) := by
  obtain ⟨sh, asOf, nb, au, frs, hwf, hlen, hlog, -, hQ, hlast, hrep⟩ := reach_replay hR
  obtain ⟨f0, rest, hfr⟩ : ∃ f0 rest, frs = f0 :: rest := by
    cases frs with
    | nil => simp at hlen; omega
    | cons a r => exact ⟨a, r, rfl⟩
  subst hfr
  have hdf := decFrames_flat hwf
  rw [hlog] at hX
  have hlen' : ((f0 :: rest).flatMap encFrame).length ≤ ((f0 :: rest).flatMap encFrame ++ X).length := by simp
  have hdec : decFrames ((f0 :: rest).flatMap encFrame ++ X).length ((f0 :: rest).flatMap encFrame ++ X) =
      (f0 :: rest) ++ decFrames (((f0 :: rest).flatMap encFrame ++ X).length - (f0 :: rest).length) X :=
    decFrames_app _ _ _ hwf (Nat.le_trans (length_le_flatMap _) hlen')
  generalize hm : (((f0 :: rest).flatMap encFrame ++ X).length - (f0 :: rest).length) = m at hdec
  have hgs' := hgs m
  rw [hlog, hdf] at hgs'
  have hlen2 : rest.length + 1 = S.batches := by simpa using hlen
  obtain ⟨tg, htg⟩ : ∃ tg, (f0 :: rest).getLast? = some tg := ⟨_, List.getLast?_eq_some_getLast (by simp)⟩
  have key : ∀ gs : List Frame, decFrames ((f0 :: rest).flatMap encFrame ++ X).length
        ((f0 :: rest).flatMap encFrame ++ X) = (f0 :: rest) ++ gs →
      (gs = [] ∨ (gs = [g0] ∧ X = encFrame g0 ∧ ∀ (T : LState) (khs : Nat → List Nat), T.Same S →
          (∀ c, S.fs.inst.contains c = true → khs c = khsOf (f0 :: rest) c) → ∃ T', replayFrame H khs T g0 = some T')) →
      ∃ T p rep, loadLog H d' names S.head S.batches = .ok (T, p, rep) ∧ T.Same S ∧
        (p = none ∨ (p = some g0 ∧ X = encFrame g0)) := by
    intro gs hdec' hgs2
    have hgl : gs.length ≤ 1 := by rcases hgs2 with rfl | ⟨rfl, -⟩ <;> simp
    obtain ⟨T, hT, hTS⟩ := hrep (khsOf ((f0 :: rest) ++ gs)) (fun c hc => khsOf_append (hQ c hc))
    have hT0 := replay_start hT
    have hg1 : ((f0 :: rest) ++ gs)[S.batches - 1]? = some tg := by
      rw [List.getElem?_append_left (by simp only [List.length_cons, List.length_append, List.length_nil]; omega), ← hlen, ← List.getLast?_eq_getElem?]
      exact htg
    have hld := loadLog_of (d' := d') (names := names) (T := T) (f0 := f0) (tg := tg) (hd := S.head)
      (bt := S.batches) (by omega) hno hX hdec' (by simp) hg1
      ⟨by simp only [List.length_append, List.length_cons]; omega, (hlast tg htg).1, (hlast tg htg).2⟩
      (by rw [List.take_append_of_le_length (Nat.le_of_eq hlen.symm), ← hlen, List.take_length]; exact hT0)
    rcases hgs2 with rfl | ⟨rfl, hxne, hrg⟩
    · have hnone : ((f0 :: rest) ++ [])[S.batches]? = none := List.getElem?_eq_none (by simp only [List.length_cons, List.length_append, List.length_nil]; omega)
      exact ⟨T, none, [.trunc "log" T.logLen], hld.trans (by simp only [hnone]), hTS, Or.inl rfl⟩
    · have hsome : ((f0 :: rest) ++ [g0])[S.batches]? = some g0 := by
        rw [← hlen]; simp
      obtain ⟨T', hT'⟩ := hrg T (khsOf ((f0 :: rest) ++ [g0])) hTS (fun c hc => khsOf_append (hQ c hc))
      exact ⟨T, some g0, [.trunc "log" (T.logLen + (encFrame g0).length)],
        hld.trans (by simp only [hsome, hT']), hTS, Or.inr ⟨rfl, hxne⟩⟩
  rcases hgs' with hg | ⟨hg, hxne, hrg⟩
  · rw [hg] at hdec
    exact key [] hdec (Or.inl rfl)
  · rw [hg] at hdec
    exact key [g0] hdec (Or.inr ⟨rfl, hxne, hrg⟩)

theorem reach_log_some {d : Disk} {S : LState} (hR : Reach H kh d S) (h0 : 0 < S.batches) :
    ∃ L f0, d "log" = some L ∧ (∃ frs : List Frame, frs.length = S.batches ∧ f0 ∈ frs) := by
  obtain ⟨frs, hf, hl, hlog⟩ := reach_log hR
  cases frs with
  | nil => simp at hl; omega
  | cons a r =>
    refine ⟨(d "log").getD [], a, ?_, a :: r, hl, List.mem_cons_self ..⟩
    cases hd : d "log" with
    | some L => rfl
    | none =>
      rw [hd, Option.getD_none] at hlog
      have h1 := congrArg List.length hlog
      simp only [List.length_nil, List.flatMap_cons, List.length_append] at h1
      have := encFrame_length_pos a
      omega
theorem reach_files {d : Disk} {S : LState} (hR : Reach H kh d S) : ∀ f, f ≠ "log" → d f = none := by
  obtain ⟨_, _, _, _, _, _, _, _, hf, _⟩ := reach_replay hR
  exact hf

/-- Load at the signed head gives the writer's state, its directory slot for slot, with nothing pending (batch 0 is
    the create path). -/
theorem load_reach' {d : Disk} {S : LState} {names : List String} (hR : Reach H kh d S) (h0 : 0 < S.batches)
    (hno : names.any (fun n => !(n = "lock" || n = "log")) = false) :
    ∃ T rep, loadLog H d names S.head S.batches = .ok (T, none, rep) ∧ T.Same S := by
  obtain ⟨L, f0, hL, -⟩ := reach_log_some hR h0
  obtain ⟨T, p, rep, h, hs, hp⟩ := load_old (d' := d) hR h0 hno (X := []) (by simp [hL]) f0 fun m => Or.inl (decFrames_nil m)
  rcases hp with rfl | ⟨-, hne⟩
  · exact ⟨T, rep, h, hs⟩
  · have := congrArg List.length hne
    have := encFrame_length_pos f0
    simp_all

/-- A name other than `lock` and `log` is refused (or the head is batch 0, refused first). -/
theorem loadLog_err {d : Disk} {names : List String} {hd : Bytes} {bt : Nat}
    (hno : names.any (fun n => !(n = "lock" || n = "log")) = true) : ∃ e, loadLog H d names hd bt = .error e := by
  unfold loadLog
  by_cases h : bt = 0
  · exact ⟨"HEAD", by simp only [h, if_true]⟩
  · exact ⟨"FILES", by simp only [h, if_false, hno, if_true]⟩

theorem crash_log_whole (st : Step) (d : Disk) {i n : Nat} (hi : 0 < i ∨ (encFrame st.frame).length ≤ n) :
    crash (stepOps st) i n d "log" = some ((d "log").getD [] ++ encFrame st.frame) := by
  rcases i with _ | i
  · have hn : (encFrame st.frame).length ≤ n := by
      rcases hi with h | h
      · omega
      · exact h
    simp [stepOps, crash_zero, Op.part, Op.run, Disk.set, List.take_of_length_le hn]
  · rcases i with _ | i <;> simp [stepOps, crash_zero, crash_succ, crash_nil, Op.part, Op.run, Disk.set]

theorem crash_old' {d : Disk} {S : LState} {b : BatchIn} {st : Step} {names : List String}
    (hR : Reach H kh d S) (h0 : 0 < S.batches) (hw : writeBatch H kh S b = .ok st) (hb : RowsAgree kh d S b) (i n : Nat)
    (hno : names.any (fun n => !(n = "lock" || n = "log")) = false) :
    ∃ T p rep, loadLog H (crash (stepOps st) i n d) names S.head S.batches = .ok (T, p, rep) ∧ T.Same S ∧
      (p = none ∨ (p = some st.frame ∧
        crash (stepOps st) i n d "log" = some ((d "log").getD [] ++ encFrame st.frame))) := by
  obtain ⟨X, hXp, hlogc, -⟩ := crash_log st d i n
  obtain ⟨hf, -⟩ := writeBatch_frame (reach_inv hR) hw
  have hg : ∀ m, decFrames m X = [] ∨ (decFrames m X = [st.frame] ∧ X = encFrame st.frame ∧ ∀ (T : LState) (khs : Nat → List Nat),
      T.Same S → (∀ c, S.fs.inst.contains c = true →
        khs c = khsOf (decFrames ((d "log").getD []).length ((d "log").getD [])) c) →
      ∃ T', replayFrame H khs T st.frame = some T') := by
    intro m
    rcases decFrames_part hf hXp m with h | ⟨h, hX⟩
    · exact Or.inl h
    · refine Or.inr ⟨h, hX, fun T khs hTS hk => ?_⟩
      · obtain ⟨T', h', -⟩ := replay_step_at hR hTS hw fun c hc => (hk c hc).trans (hb c hc).symm
        exact ⟨T', h'⟩
  obtain ⟨T, p, rep, h, hs, hp⟩ := load_old hR h0 hno hlogc st.frame hg
  refine ⟨T, p, rep, h, hs, ?_⟩
  rcases hp with h | ⟨h, hX⟩
  · exact Or.inl h
  · exact Or.inr ⟨h, by rw [hlogc, hX]⟩

theorem crash_new' {d : Disk} {S : LState} {b : BatchIn} {st : Step} {names : List String}
    (hR : Reach H kh d S) (hw : writeBatch H kh S b = .ok st) (hb : RowsAgree kh d S b) {i n : Nat}
    (hi : 0 < i ∨ (encFrame st.frame).length ≤ n)
    (hno : names.any (fun n => !(n = "lock" || n = "log")) = false) :
    ∃ T rep, loadLog H (crash (stepOps st) i n d) names st.next.head st.next.batches = .ok (T, none, rep) ∧
      T.Same st.next := by
  have hR' := Reach.step hR hw hb
  obtain ⟨-, hbt⟩ := writeBatch_frame (reach_inv hR) hw
  have hlogeq : crash (stepOps st) i n d "log" = runOps (stepOps st) d "log" := by
    rw [crash_log_whole st d hi, stepOps_log]
  obtain ⟨T, rep, h, hs⟩ := load_reach' hR' (by omega) hno
  exact ⟨T, rep, by rw [loadLog_congr hlogeq]; exact h, hs⟩

/-- Load at the signed head gives the writer's state, its directory slot for slot, with nothing pending (batch 0 is
    the create path). -/
theorem load_reach {d : Disk} {S : LState} {names : List String} (hR : Reach H kh d S) (h0 : 0 < S.batches)
    (hl : Lists d names) :
    ∃ T rep, loadLog H d names S.head S.batches = .ok (T, none, rep) ∧ T.Same S :=
  load_reach' hR h0 (names_of_lists hl (reach_files hR))

/-- The old signed head always loads the old state after a crash; the batch's frame, when it is whole, is kept
    pending (never released) and nothing else is. -/
theorem crash_old_loads {d : Disk} {S : LState} {b : BatchIn} {st : Step} {names : List String}
    (hR : Reach H kh d S) (h0 : 0 < S.batches) (hw : writeBatch H kh S b = .ok st) (hb : RowsAgree kh d S b) (i n : Nat)
    (hl : Lists (crash (stepOps st) i n d) names) :
    ∃ T p rep, loadLog H (crash (stepOps st) i n d) names S.head S.batches = .ok (T, p, rep) ∧ T.Same S ∧
      (p = none ∨ p = some st.frame) := by
  obtain ⟨X, -, -, hoth⟩ := crash_log st d i n
  obtain ⟨T, p, rep, h, hs, hp⟩ := crash_old' hR h0 hw hb i n
    (names_of_lists hl (fun f hf => by rw [hoth f hf]; exact reach_files hR f hf))
  exact ⟨T, p, rep, h, hs, hp.imp id And.left⟩

/-- Once the whole frame is on disk the new signed head loads the new state. -/
theorem crash_new_loads {d : Disk} {S : LState} {b : BatchIn} {st : Step} {names : List String}
    (hR : Reach H kh d S) (hw : writeBatch H kh S b = .ok st) (hb : RowsAgree kh d S b) {i n : Nat}
    (hi : 0 < i ∨ (encFrame st.frame).length ≤ n) (hl : Lists (crash (stepOps st) i n d) names) :
    ∃ T rep, loadLog H (crash (stepOps st) i n d) names st.next.head st.next.batches = .ok (T, none, rep) ∧
      T.Same st.next := by
  obtain ⟨X, -, -, hoth⟩ := crash_log st d i n
  exact crash_new' hR hw hb hi
    (names_of_lists hl (fun f hf => by rw [hoth f hf]; exact reach_files hR f hf))

/-- Crash recovery: a crash anywhere in a batch's writes loads, at the old or the new signed head, to the old or the
    new committed state, or is refused. -/
theorem crash_prefix_loads {d : Disk} {S : LState} {b : BatchIn} {st : Step} {names : List String} {hd : Bytes}
    {bt : Nat} (hR : Reach H kh d S) (hw : writeBatch H kh S b = .ok st) (hb : RowsAgree kh d S b) (i n : Nat)
    (hh : (hd, bt) = (S.head, S.batches) ∨ (hd, bt) = (st.next.head, st.next.batches)) :
    (match loadLog H (crash (stepOps st) i n d) names hd bt with
      | .ok (T, _, _) => T.Same S ∨ T.Same st.next
      | .error _ => True) ∨ Collides H := by
  rcases hh with hh | hh <;> obtain ⟨rfl, rfl⟩ := Prod.mk.inj hh
  · by_cases hb0 : S.batches = 0
    · left; simp [loadLog, hb0]
    · cases hno : names.any (fun n => !(n = "lock" || n = "log")) with
      | true =>
        left
        obtain ⟨e, he⟩ := loadLog_err (H := H) (d := crash (stepOps st) i n d) (hd := S.head) (bt := S.batches) hno
        rw [he]
        trivial
      | false =>
        left
        obtain ⟨T, p, rep, h, hs, -⟩ := crash_old' hR (Nat.pos_of_ne_zero hb0) hw hb i n hno
        rw [h]
        exact Or.inl hs
  · by_cases ht : 0 < i ∨ (encFrame st.frame).length ≤ n
    · cases hno : names.any (fun n => !(n = "lock" || n = "log")) with
      | true =>
        left
        obtain ⟨e, he⟩ := loadLog_err (H := H) (d := crash (stepOps st) i n d) (hd := st.next.head)
          (bt := st.next.batches) hno
        rw [he]
        trivial
      | false =>
        left
        obtain ⟨T, rep, h, hs⟩ := crash_new' hR hw hb ht hno
        rw [h]
        exact Or.inr hs
    · obtain ⟨rfl, hn⟩ : i = 0 ∧ n < (encFrame st.frame).length := ⟨by omega, by omega⟩
      rcases crash_new_refused (names := names) hR hw hn with hne | hc
      · left
        cases hl : loadLog H (crash (stepOps st) 0 n d) names st.next.head st.next.batches with
        | error _ => trivial
        | ok r =>
          obtain ⟨T, p, rep⟩ := r
          exact absurd hl (hne T p rep)
      · exact Or.inr hc

/-- A rewound head (below one this process opened) is refused before anything is read. -/
theorem open_stale {d : Disk} {names : List String} {hd : Bytes} {bt seen : Nat} (h : bt < seen) :
    openLog H d names hd bt seen = .error "HOLD STALE" := by
  simp [openLog, h]

/-- A retry of the pending batch with other request bytes is refused. -/
theorem retry_other {p : Frame} {rq : Bytes} (h : p.rq ≠ rq) : retryOf (some p) rq = .error "HOLD RETRY" := by
  simp [retryOf, h]

theorem unleb_canon : ∀ (bs : Bytes) (n : Nat) (r : Bytes), unleb bs = some (n, r) → bs = leb n ++ r
  | [], n, r, h => by simp [unleb] at h
  | b :: t, n, r, h => by
    unfold unleb at h
    have hb8 := UInt8.toNat_lt b
    by_cases hb : b < 128
    · rw [if_pos hb] at h
      simp only [Option.some.injEq, Prod.mk.injEq] at h
      obtain ⟨rfl, rfl⟩ := h
      have h1 : b.toNat < 128 := by rw [UInt8.lt_iff_toNat_lt] at hb; simpa using hb
      rw [BlindLedger.Gate.OnepIndex.leb, dif_pos h1]
      simp
    · rw [if_neg hb] at h
      have h1 : 128 ≤ b.toNat := by
        rw [UInt8.lt_iff_toNat_lt] at hb; simpa using hb
      rcases h2 : unleb t with _ | ⟨n', r'⟩
      · simp [h2] at h
      · simp only [h2] at h
        by_cases h0 : n' = 0
        · simp [h0] at h
        · rw [if_neg h0] at h
          simp only [Option.some.injEq, Prod.mk.injEq] at h
          obtain ⟨rfl, rfl⟩ := h
          have ih := unleb_canon t n' r' h2
          have hs : (b - 128).toNat = b.toNat - 128 := by
            have hle : (128 : UInt8) ≤ b := by rw [UInt8.le_iff_toNat_le]; simpa using h1
            rw [UInt8.toNat_sub_of_le _ _ hle]; rfl
          rw [hs]
          have hn : ¬ (b.toNat - 128 + 128 * n' < 128) := by omega
          rw [BlindLedger.Gate.OnepIndex.leb, dif_neg hn]
          have e1 : (b.toNat - 128 + 128 * n') / 128 = n' := by omega
          have e2 : (b.toNat - 128 + 128 * n') % 128 + 128 = b.toNat := by omega
          have e3 : b.toNat.toUInt8 = b := UInt8.ofNat_toNat
          rw [e1, e2, e3, List.cons_append, ← ih]

theorem le32_beNat (b : Bytes) (h : b.length = 4) : le32 (beNat b.reverse) = b := by
  match b, h with
  | [a, b, c, d], _ =>
    have ha := UInt8.toNat_lt a
    have hb := UInt8.toNat_lt b
    have hc := UInt8.toNat_lt c
    have hd := UInt8.toNat_lt d
    have key : ∀ (x : UInt8) (m : Nat), m % 256 = x.toNat → UInt8.ofNat m = x := by
      intro x m hm
      apply UInt8.toNat_inj.mp
      simp [UInt8.toNat_ofNat, hm]
    simp [le32, natBE, beNat, List.range_succ]
    refine ⟨?_, ?_, ?_⟩ <;> apply key <;> omega

theorem takeN_canon {n : Nat} {bs a r : Bytes} (h : takeN n bs = some (a, r)) : bs = a ++ r ∧ a.length = n := by
  unfold takeN at h
  split at h
  · rename_i hn
    simp only [Option.some.injEq, Prod.mk.injEq] at h
    obtain ⟨rfl, rfl⟩ := h
    exact ⟨(List.take_append_drop _ _).symm, by simp; omega⟩
  · cases h

theorem unle32_canon {bs : Bytes} {n : Nat} {r : Bytes} (h : unle32 bs = some (n, r)) : bs = le32 n ++ r := by
  unfold unle32 at h
  rcases h1 : takeN 4 bs with _ | ⟨b, r1⟩
  · simp [h1] at h
  · simp only [h1, Option.bind_some, pure, Option.some.injEq, Prod.mk.injEq] at h
    obtain ⟨rfl, rfl⟩ := h
    obtain ⟨e, hl⟩ := takeN_canon h1
    rw [le32_beNat b hl]
    exact e

theorem decHead_canon {bs : Bytes} {h : Head} {r : Bytes} (hd : decHead bs = some (h, r)) : bs = encHead h ++ r := by
  unfold decHead at hd
  rcases h1 : unleb bs with _ | ⟨a, r1⟩
  · simp [h1] at hd
  rcases h2 : unleb r1 with _ | ⟨c, r2⟩
  · simp [h1, h2] at hd
  rcases h3 : unleb r2 with _ | ⟨n, r3⟩
  · simp [h1, h2, h3] at hd
  simp [h1, h2, h3] at hd
  obtain ⟨rfl, rfl⟩ := hd
  rw [unleb_canon _ _ _ h1, unleb_canon _ _ _ h2, unleb_canon _ _ _ h3]
  simp [encHead]

theorem decTrailer_canon {tb : Bytes} {c : Nat} {f : Frame} (h : decTrailer tb = some (c, f)) :
    f.chunk = none ∧ tb = domain "FLAT/FRAME" ++ leb f.shard ++ leb f.nb0 ++ leb f.batches ++ leb c ++ encHead f.hr ++
      encHead f.hu ++ leb f.nx ++ f.au ++ f.rq ++ f.prev ++ f.bd ++ f.head := by
  unfold decTrailer at h
  rcases h1 : takeN (domain "FLAT/FRAME").length tb with _ | ⟨t, r0⟩
  · simp [h1] at h
  by_cases ht : t = domain "FLAT/FRAME"
  case neg => simp [h1, ht] at h
  rcases h2a : unleb r0 with _ | ⟨sh, r0a⟩
  · simp [h1, ht, h2a] at h
  rcases h2b : unleb r0a with _ | ⟨nb, r0b⟩
  · simp [h1, ht, h2a, h2b] at h
  rcases h2 : unleb r0b with _ | ⟨b, r1⟩
  · simp [h1, ht, h2a, h2b, h2] at h
  rcases h3 : unleb r1 with _ | ⟨c', r2⟩
  · simp [h1, ht, h2a, h2b, h2, h3] at h
  rcases h4 : decHead r2 with _ | ⟨hr, r3⟩
  · simp [h1, ht, h2a, h2b, h2, h3, h4] at h
  rcases h5 : decHead r3 with _ | ⟨hu, r4⟩
  · simp [h1, ht, h2a, h2b, h2, h3, h4, h5] at h
  rcases h6 : unleb r4 with _ | ⟨nx, r5⟩
  · simp [h1, ht, h2a, h2b, h2, h3, h4, h5, h6] at h
  rcases h6a : takeN authLen r5 with _ | ⟨au, r5a⟩
  · simp [h1, ht, h2a, h2b, h2, h3, h4, h5, h6, h6a] at h
  rcases h8 : takeN 64 r5a with _ | ⟨rq, r7⟩
  · simp [h1, ht, h2a, h2b, h2, h3, h4, h5, h6, h6a, h8] at h
  rcases h9 : takeN 64 r7 with _ | ⟨pv, r8⟩
  · simp [h1, ht, h2a, h2b, h2, h3, h4, h5, h6, h6a, h8, h9] at h
  rcases h10 : takeN 64 r8 with _ | ⟨bd, r9⟩
  · simp [h1, ht, h2a, h2b, h2, h3, h4, h5, h6, h6a, h8, h9, h10] at h
  rcases h11 : takeN 64 r9 with _ | ⟨hd, r10⟩
  · simp [h1, ht, h2a, h2b, h2, h3, h4, h5, h6, h6a, h8, h9, h10, h11] at h
  by_cases hr10 : r10 = []
  case neg => simp [h1, ht, h2a, h2b, h2, h3, h4, h5, h6, h6a, h8, h9, h10, h11, hr10] at h
  subst hr10
  simp [h1, ht, h2a, h2b, h2, h3, h4, h5, h6, h6a, h8, h9, h10, h11] at h
  obtain ⟨rfl, rfl⟩ := h
  refine ⟨rfl, ?_⟩
  obtain ⟨e1, -⟩ := takeN_canon h1
  obtain ⟨e6a, -⟩ := takeN_canon h6a
  obtain ⟨e8, -⟩ := takeN_canon h8
  obtain ⟨e9, -⟩ := takeN_canon h9
  obtain ⟨e10, -⟩ := takeN_canon h10
  obtain ⟨e11, -⟩ := takeN_canon h11
  rw [e1, ht, unleb_canon _ _ _ h2a, unleb_canon _ _ _ h2b, unleb_canon _ _ _ h2, unleb_canon _ _ _ h3,
    decHead_canon h4, decHead_canon h5, unleb_canon _ _ _ h6, e6a, e8, e9, e10, e11]
  simp [List.append_assoc]

theorem splitPages_length : ∀ (n : Nat) (b : Bytes), (splitPages n b).length = n
  | 0, _ => rfl
  | n + 1, b => by simp [splitPages, splitPages_length n]

theorem splitPages_flatten' : ∀ (n : Nat) (b : Bytes), b.length = n * pageSize → (splitPages n b).flatten = b
  | 0, b, h => by
    have : b = [] := List.eq_nil_of_length_eq_zero (by simpa using h)
    simp [splitPages, this]
  | n + 1, b, h => by
    simp only [splitPages, List.flatten_cons]
    rw [splitPages_flatten' n _ (by simp [List.length_drop, h, Nat.add_mul])]
    exact List.take_append_drop _ _

theorem decFrame_canon {b : Bytes} {f : Frame} {r : Bytes} (h : decFrame b = some (f, r)) : b = encFrame f ++ r := by
  unfold decFrame at h
  rcases h1 : takeN 4 b with _ | ⟨t, r1⟩
  · simp [h1] at h
  by_cases ht : t = frameTag
  case neg => simp [h1, ht] at h
  rcases h2 : unle32 r1 with _ | ⟨np, r2⟩
  · simp [h1, ht, h2] at h
  rcases h3 : unle32 r2 with _ | ⟨ml, r3⟩
  · simp [h1, ht, h2, h3] at h
  rcases h4 : unle32 r3 with _ | ⟨tl, r4⟩
  · simp [h1, ht, h2, h3, h4] at h
  rcases h5 : takeN (np * pageSize) r4 with _ | ⟨pg, r5⟩
  · simp [h1, ht, h2, h3, h4, h5] at h
  rcases h6 : takeN ml r5 with _ | ⟨m, r6⟩
  · simp [h1, ht, h2, h3, h4, h5, h6] at h
  rcases h7 : takeN tl r6 with _ | ⟨tb, r7⟩
  · simp [h1, ht, h2, h3, h4, h5, h6, h7] at h
  rcases h8 : decTrailer tb with _ | ⟨c, f0⟩
  · simp [h1, ht, h2, h3, h4, h5, h6, h7, h8] at h
  obtain ⟨e1, -⟩ := takeN_canon h1
  obtain ⟨e5, l5⟩ := takeN_canon h5
  obtain ⟨e6, l6⟩ := takeN_canon h6
  obtain ⟨e7, l7⟩ := takeN_canon h7
  have e2 := unle32_canon h2
  have e3 := unle32_canon h3
  have e4 := unle32_canon h4
  obtain ⟨hch, htb⟩ := decTrailer_canon h8
  have hbb : b = frameHdr np ml tl ++ pg ++ m ++ tb ++ r7 := by
    rw [e1, e2, e3, e4, e5, e6, e7, ht]
    simp [frameHdr, List.append_assoc]
  cases c with
  | zero =>
    simp [h1, ht, h2, h3, h4, h5, h6, h7, h8] at h
    obtain ⟨⟨hnp, hml⟩, hf, hr⟩ := h
    have hpg : pg = [] := List.eq_nil_of_length_eq_zero (by rw [l5, hnp]; simp)
    have hm : m = [] := List.eq_nil_of_length_eq_zero (by rw [l6, hml])
    rw [hnp, hml] at hbb
    have hft : frameTrailer f0 = tb := by
      unfold frameTrailer
      rw [htb]
      simp [Frame.cnum, hch, List.append_assoc]
    rw [← hf, ← hr, hbb, hpg, hm, encFrame, frameBody, hch, hft, ← l7]
    simp
  | succ c =>
    simp [h1, ht, h2, h3, h4, h5, h6, h7, h8] at h
    obtain ⟨rfl, rfl⟩ := h
    have hft : frameTrailer { f0 with chunk := some (c, splitPages np pg, m) } = tb := by
      unfold frameTrailer
      rw [htb]
      simp [Frame.cnum, hch, List.append_assoc]
    rw [hbb, encFrame, frameBody]
    simp only [hft, splitPages_length, splitPages_flatten' np pg (by simpa using l5), ← l7, ← l6]

theorem decFrames_split : ∀ (m : Nat) (b : Bytes), ∃ rest, b = (decFrames m b).flatMap encFrame ++ rest
  | 0, b => ⟨b, by simp [decFrames]⟩
  | m + 1, b => by
    unfold decFrames
    rcases h : decFrame b with _ | ⟨fr, r⟩
    · exact ⟨b, by simp⟩
    · obtain ⟨rest, hr⟩ := decFrames_split m r
      refine ⟨rest, ?_⟩
      have := decFrame_canon h
      simp only [List.flatMap_cons, List.append_assoc]
      rw [← hr]
      exact this

theorem replayFrame_out {khs : Nat → List Nat} {S T : LState} {f : Frame} (h : replayFrame H khs S f = some T) :
    T.batches = f.batches ∧ T.head = f.head ∧ T.logLen = S.logLen + (encFrame f).length := by
  unfold replayFrame at h
  simp only [Option.bind_eq_bind] at h
  repeat' (first
    | (cases h; done)
    | (cases h; exact ⟨rfl, rfl, rfl⟩)
    | (split at h)
    | (rw [Option.bind_eq_some_iff] at h; obtain ⟨_, _, h⟩ := h))

theorem foldlM_last {khs : Nat → List Nat} : ∀ {l : List Frame} {G T : LState}, l ≠ [] →
    l.foldlM (replayFrame H khs) G = some T → ∃ f, l.getLast? = some f ∧ T.batches = f.batches ∧ T.head = f.head
  | [], _, _, h, _ => absurd rfl h
  | [f], G, T, _, h => by
    simp only [List.foldlM] at h
    cases hf : replayFrame H khs G f with
    | none => rw [hf] at h; cases h
    | some G' =>
      rw [hf] at h
      have hG : G' = T := by simpa using h
      subst hG
      obtain ⟨h1, h2, -⟩ := replayFrame_out hf
      exact ⟨f, rfl, h1, h2⟩
  | f :: g :: r, G, T, _, h => by
    simp only [List.foldlM] at h
    cases hf : replayFrame H khs G f with
    | none => rw [hf] at h; cases h
    | some G' =>
      rw [hf] at h
      obtain ⟨x, hx, h1, h2⟩ := foldlM_last (l := g :: r) (G := G') (T := T) (by simp) h
      exact ⟨x, by simpa [List.getLast?_cons_cons] using hx, h1, h2⟩

theorem foldlM_logLen {khs : Nat → List Nat} : ∀ {l : List Frame} {G T : LState},
    l.foldlM (replayFrame H khs) G = some T → T.logLen = G.logLen + (l.flatMap encFrame).length
  | [], G, T, h => by simp [List.foldlM] at h; subst h; simp
  | f :: r, G, T, h => by
    simp only [List.foldlM] at h
    cases hf : replayFrame H khs G f with
    | none => rw [hf] at h; cases h
    | some G' =>
      rw [hf] at h
      have h1 := foldlM_logLen (l := r) h
      have h2 := (replayFrame_out hf).2.2
      simp only [List.flatMap_cons, List.length_append]
      omega

theorem loadLog_ok {d : Disk} {names : List String} {hd : Bytes} {bt : Nat} {T : LState} {p : Option Frame}
    {rep : List Op} (h : loadLog H d names hd bt = .ok (T, p, rep)) :
    bt ≠ 0 ∧ names.any (fun n => !(n = "lock" || n = "log")) = false ∧ T.batches = bt ∧ T.head = hd ∧
      rep = [.trunc "log" (T.logLen + (p.elim 0 fun q => (encFrame q).length))] := by
  unfold loadLog at h
  by_cases hb : bt = 0
  · simp [hb] at h
  simp only [hb, if_false] at h
  cases hn : names.any (fun n => !(n = "lock" || n = "log")) with
  | true => simp only [hn, if_true] at h; cases h
  | false =>
    simp only [hn, Bool.false_eq_true, if_false] at h
    cases hL : d "log" with
    | none => simp [hL] at h
    | some L =>
      simp only [hL] at h
      cases h0 : (decFrames L.length L)[0]? with
      | none => simp [h0] at h
      | some f0 =>
        cases ht : (decFrames L.length L)[bt - 1]? with
        | none => simp [h0, ht] at h
        | some tg =>
          simp only [h0, ht] at h
          by_cases hc : ((decFrames L.length L).length = bt ∨ (decFrames L.length L).length = bt + 1) ∧
              tg.head = hd ∧ tg.batches = bt
          · simp only [hc, and_self, if_true] at h
            cases hT : ((decFrames L.length L).take bt).foldlM (replayFrame H (khsOf (decFrames L.length L)))
                { LState.genesis H f0.shard 0 f0.nb0 f0.au with head := f0.prev } with
            | none => simp [hT] at h
            | some T0 =>
              simp only [hT] at h
              have hlt : bt - 1 < (decFrames L.length L).length := by
                refine Classical.byContradiction fun hh => ?_
                rw [List.getElem?_eq_none (by omega)] at ht
                cases ht
              have hne : (decFrames L.length L).take bt ≠ [] := by
                intro hh
                have := congrArg List.length hh
                simp only [List.length_take, List.length_nil] at this
                omega
              obtain ⟨x, hx, hxb, hxh⟩ := foldlM_last hne hT
              have hx' : (decFrames L.length L).getLast? = none ∨ True := Or.inr trivial
              have hxe : ((decFrames L.length L).take bt).getLast? = some tg := by
                rw [List.getLast?_eq_getElem?, List.getElem?_take]
                simp only [List.length_take]
                have : min bt (decFrames L.length L).length - 1 = bt - 1 := by omega
                rw [this]
                simp [ht]
                omega
              rw [hxe] at hx
              obtain rfl := Option.some.inj hx
              cases hq : (decFrames L.length L)[bt]? with
              | none =>
                simp only [hq, Except.ok.injEq, Prod.mk.injEq] at h
                obtain ⟨rfl, rfl, rfl⟩ := h
                exact ⟨hb, rfl, hxb.trans hc.2.2, hxh.trans hc.2.1, by simp⟩
              | some q =>
                simp only [hq] at h
                cases hr : replayFrame H (khsOf (decFrames L.length L)) T0 q with
                | none => simp [hr] at h
                | some _ =>
                  simp only [hr, Except.ok.injEq, Prod.mk.injEq] at h
                  obtain ⟨rfl, rfl, rfl⟩ := h
                  exact ⟨hb, rfl, hxb.trans hc.2.2, hxh.trans hc.2.1, by simp⟩
          · simp [hc] at h

theorem loadLog_names {d d' : Disk} {names names' : List String} {hd : Bytes} {bt : Nat}
    (hn : names.any (fun n => !(n = "lock" || n = "log")) = false)
    (hn' : names'.any (fun n => !(n = "lock" || n = "log")) = false) (h : d "log" = d' "log") :
    loadLog H d names hd bt = loadLog H d' names' hd bt := by
  simp only [loadLog, hn, hn', h]

theorem crash_trunc (f : String) (n j m : Nat) (D : Disk) : crash [.trunc f n] j m D = (Op.trunc f n).run D := by
  rcases j with _ | j <;> simp [crash, runOps, Op.part]

theorem stepOps_other (st : Step) (d : Disk) {f : String} (hf : f ≠ "log") : runOps (stepOps st) d f = d f := by
  simp [stepOps, runOps, Op.run, Disk.set, hf]

theorem reach_logLen {d : Disk} {S : LState} (hR : Reach H kh d S) : S.logLen = ((d "log").getD []).length := by
  obtain ⟨sh, asOf, nb, au, frs, hwf, hlen, hlog, -, hQ, hlast, hrep⟩ := reach_replay hR
  obtain ⟨T, hT, hTS⟩ := hrep (khsOf frs) (fun c _ => rfl)
  have h1 := foldlM_logLen hT
  obtain ⟨-, -, -, -, -, -, -, -, -, -, -, -, -, -, -, -, -, hl, -⟩ := hTS
  rw [hlog, ← hl]
  simpa [LState.genesis] using h1

theorem trunc_whole {D : Disk} {L : Bytes} (hL : D "log" = some L) : (Op.trunc "log" L.length).run D = D := by
  funext f
  by_cases hf : f = "log"
  · subst hf; simp [Op.run, Disk.set, hL]
  · simp [Op.run, Disk.set, hf]

/-- The repair a load after a crash returns leaves a disk the writer reaches (at the loaded state, or at the new state
    when the batch's frame is kept pending), and a crash during it loads the same state and pending frame. -/
theorem crash_repair {d : Disk} {S T : LState} {b : BatchIn} {st : Step} {names : List String} {hd : Bytes}
    {bt : Nat} {p : Option Frame} {rep : List Op} (hR : Reach H kh d S) (hw : writeBatch H kh S b = .ok st)
    (hb : RowsAgree kh d S b)
    (i n : Nat) (hl : Lists (crash (stepOps st) i n d) names)
    (h : loadLog H (crash (stepOps st) i n d) names hd bt = .ok (T, p, rep)) (hT : T.Same S ∨ T.Same st.next) :
    Reach H kh (runOps rep (crash (stepOps st) i n d)) (match p with | none => T | some _ => st.next) ∧
      ∀ j m names', Lists (crash rep j m (crash (stepOps st) i n d)) names' →
        ∃ T' rep', loadLog H (crash rep j m (crash (stepOps st) i n d)) names' hd bt = .ok (T', p, rep') ∧
          T'.Same T := by
  obtain ⟨hb0, hno, hTb, hTh, hrep⟩ := loadLog_ok h
  obtain ⟨X, -, hlogc, hoth⟩ := crash_log st d i n
  have hfiles : ∀ f, f ≠ "log" → crash (stepOps st) i n d f = none := fun f hf => by
    rw [hoth f hf]; exact reach_files hR f hf
  -- a load is the same on any names that pass, and a whole log is untouched by the repair
  have hRr : ∀ j m, crash rep j m (crash (stepOps st) i n d) =
      (Op.trunc "log" (T.logLen + (p.elim 0 fun q => (encFrame q).length))).run (crash (stepOps st) i n d) := by
    intro j m
    rw [hrep, crash_trunc]
  have hnames : ∀ j m names', Lists (crash rep j m (crash (stepOps st) i n d)) names' →
      names'.any (fun n => !(n = "lock" || n = "log")) = false := by
    intro j m names' hl'
    apply names_of_lists hl'
    intro f hf
    rw [hRr]
    simp [Op.run, Disk.set, hf, hfiles f hf]
  rcases hT with hTS | hTN
  · obtain ⟨-, -, hbt, -, -, -, -, -, -, -, -, -, -, -, -, -, hhd, hlen, -⟩ := id hTS
    have e1 : hd = S.head := hTh.symm.trans hhd
    have e2 : bt = S.batches := hTb.symm.trans hbt
    subst e1 e2
    have hbS : 0 < S.batches := Nat.pos_of_ne_zero hb0
    obtain ⟨L, f0, hL, -⟩ := reach_log_some hR hbS
    have hlen' : T.logLen = L.length := by rw [hlen, reach_logLen hR, hL]; rfl
    obtain ⟨T0, p0, rep0, h0, hs0, hp0⟩ := crash_old' hR hbS hw hb i n hno
    have e := h0.symm.trans h
    simp only [Except.ok.injEq, Prod.mk.injEq] at e
    obtain ⟨-, e2, -⟩ := e
    rcases hp0 with h1 | ⟨h1, hX⟩
    · have hp : p = none := e2.symm.trans h1
      subst hp
      have hRd : (Op.trunc "log" (T.logLen + (none : Option Frame).elim 0 fun q => (encFrame q).length)).run
          (crash (stepOps st) i n d) = d := by
        funext f
        by_cases hf : f = "log"
        · subst hf
          simp [Op.run, Disk.set, hlogc, hL, hlen']
        · simp [Op.run, Disk.set, hf, hoth f hf]
      have hD : ∀ j m, crash rep j m (crash (stepOps st) i n d) = d := fun j m => (hRr j m).trans hRd
      refine ⟨?_, fun j m names' hl' => ?_⟩
      · have hRo : runOps rep (crash (stepOps st) i n d) = d := by rw [hrep]; exact hRd
        show Reach H kh (runOps rep (crash (stepOps st) i n d)) T
        rw [hRo]; exact Reach.same hR (same_symm hTS)
      · rw [hD] at hl' ⊢
        obtain ⟨T', rep', h', hs'⟩ := load_reach' hR hbS (names_of_lists hl' (reach_files hR))
        exact ⟨T', rep', h', same_trans hs' (same_symm hTS)⟩
    · have hp : p = some st.frame := e2.symm.trans h1
      subst hp
      have hCl : crash (stepOps st) i n d "log" = some ((d "log").getD [] ++ encFrame st.frame) := hX
      have hCw : crash (stepOps st) i n d = runOps (stepOps st) d := by
        funext f
        by_cases hf : f = "log"
        · subst hf; rw [hCl, stepOps_log]
        · rw [hfiles f hf, stepOps_other st d hf, reach_files hR f hf]
      have hRfix : (Op.trunc "log" (T.logLen + (some st.frame).elim 0 fun q => (encFrame q).length)).run
          (crash (stepOps st) i n d) = crash (stepOps st) i n d := by
        have : T.logLen + (some st.frame).elim 0 (fun q => (encFrame q).length) =
            ((d "log").getD [] ++ encFrame st.frame).length := by simp [hlen', hL]
        rw [this]; exact trunc_whole hCl
      have hRo : runOps rep (crash (stepOps st) i n d) = crash (stepOps st) i n d := by
        rw [hrep]; exact hRfix
      refine ⟨?_, fun j m names' hl' => ?_⟩
      · show Reach H kh (runOps rep (crash (stepOps st) i n d)) st.next
        rw [hRo, hCw]; exact Reach.step hR hw hb
      · have hno' := hnames j m names' hl'
        have hRC : crash rep j m (crash (stepOps st) i n d) = crash (stepOps st) i n d := (hRr j m).trans hRfix
        rw [hRC]
        exact ⟨T, rep, (loadLog_names hno' hno rfl).trans h, same_trans hTS (same_symm hTS)⟩
  · obtain ⟨-, -, hbt, -, -, -, -, -, -, -, -, -, -, -, -, -, hhd, hlen, -⟩ := id hTN
    have e1 : hd = st.next.head := hTh.symm.trans hhd
    have e2 : bt = st.next.batches := hTb.symm.trans hbt
    subst e1 e2
    by_cases hi : 0 < i ∨ (encFrame st.frame).length ≤ n
    · obtain ⟨T0, rep0, h0, hs0⟩ := crash_new' hR hw hb hi hno
      have e := h0.symm.trans h
      simp only [Except.ok.injEq, Prod.mk.injEq] at e
      obtain ⟨-, e2, -⟩ := e
      have hp : p = none := e2.symm
      subst hp
      have hCl := crash_log_whole st d hi
      have hCw : crash (stepOps st) i n d = runOps (stepOps st) d := by
        funext f
        by_cases hf : f = "log"
        · subst hf; rw [hCl, stepOps_log]
        · rw [hfiles f hf, stepOps_other st d hf, reach_files hR f hf]
      have hR' : Reach H kh (crash (stepOps st) i n d) st.next := by rw [hCw]; exact Reach.step hR hw hb
      have hlen' : T.logLen = ((d "log").getD [] ++ encFrame st.frame).length := by
        rw [hlen, reach_logLen hR', hCl]; rfl
      have hRfix : (Op.trunc "log" (T.logLen + (none : Option Frame).elim 0 fun q => (encFrame q).length)).run
          (crash (stepOps st) i n d) = crash (stepOps st) i n d := by
        have : T.logLen + (none : Option Frame).elim 0 (fun q => (encFrame q).length) =
            ((d "log").getD [] ++ encFrame st.frame).length := hlen'
        rw [this]; exact trunc_whole hCl
      have hRo : runOps rep (crash (stepOps st) i n d) = crash (stepOps st) i n d := by
        rw [hrep]; exact hRfix
      refine ⟨?_, fun j m names' hl' => ?_⟩
      · show Reach H kh (runOps rep (crash (stepOps st) i n d)) T
        rw [hRo]; exact Reach.same hR' (same_symm hTN)
      · have hno' := hnames j m names' hl'
        have hRC : crash rep j m (crash (stepOps st) i n d) = crash (stepOps st) i n d := (hRr j m).trans hRfix
        rw [hRC]
        exact ⟨T, rep, (loadLog_names hno' hno rfl).trans h, same_trans hTN (same_symm hTN)⟩
    · have hi0 : i = 0 := by omega
      have hn : n < (encFrame st.frame).length := by omega
      subst hi0
      exact absurd h (crash_new_refused' (names := names) hR hw hn T p rep)

theorem inst_perm {a b : HashSet Nat} (hi : ∀ c, a.contains c = b.contains c) : a.toList.Perm b.toList := by
  have hna : a.toList.Nodup := by
    have := a.distinct_toList
    refine List.Pairwise.imp ?_ this
    intro x y h hxy; subst hxy; simp at h
  have hnb : b.toList.Nodup := by
    have := b.distinct_toList
    refine List.Pairwise.imp ?_ this
    intro x y h hxy; subst hxy; simp at h
  rw [List.perm_ext_iff_of_nodup hna hnb]
  intro c
  rw [Std.HashSet.mem_toList, Std.HashSet.mem_toList]
  exact (by rw [Std.HashSet.mem_iff_contains, Std.HashSet.mem_iff_contains, hi c] : c ∈ a ↔ c ∈ b)

theorem liveItems_congr {a b : HashSet Nat} {da db : HashMap Nat (HashSet Nat)} (hi : ∀ c, a.contains c = b.contains c)
    (hd : ∀ c i, isDead da c i = isDead db c i) (nb : Nat) (rows : Nat → List Row) (x : UInt32 × Nat) :
    (liveItems kh a da nb rows).count x = (liveItems kh b db nb rows).count x := by
  unfold liveItems
  have h1 : (a.toList.flatMap fun c => (liveHashes kh da c (rows c)).map (Dir.item nb · c)) =
      (a.toList.flatMap fun c => (liveHashes kh db c (rows c)).map (Dir.item nb · c)) := by
    congr 1
    funext c
    rw [liveHashes_congr hd]
  rw [h1]
  exact ((inst_perm hi).flatMap_right _).count_eq x

theorem live_iff {S T : LState} (h : S.Same T) (rows : Nat → List Row) (c i : Nat) (kb : Bytes) (e : Entry) :
    Live S.fs rows c i kb e ↔ Live T.fs rows c i kb e := by
  obtain ⟨-, -, -, -, -, -, hi, hd, -⟩ := h
  unfold Live
  rw [hi c, hd c i]

/-- A loaded store keeps every key: `FInv` holds of an equal state. -/
theorem finv_same {S T : LState} {files : Nat → Chunk} {s : St} (h : S.Same T) (hf : FInv H kh S.fs files s) :
    FInv H kh T.fs files s := by
  have hL := live_iff h (layout H kh files)
  obtain ⟨-, -, -, hhr, hhu, hdir, hi, hd, hwS, hwT, hsS, hsT, -⟩ := h
  obtain ⟨h1, h2, hC, hD, hDI, hWf, hK, hI, hO⟩ := hf
  have gT : ∀ kb, T.fs.win.get? kb = none := fun kb =>
    Std.HashMap.getElem?_eq_none (Std.HashMap.not_mem_of_isEmpty hwT)
  have gS : ∀ kb, S.fs.win.get? kb = none := fun kb =>
    Std.HashMap.getElem?_eq_none (Std.HashMap.not_mem_of_isEmpty hwS)
  have sT : ∀ kb, sealGet T.fs kb = none := fun kb => by simp [sealGet, hsT]
  have sS : ∀ kb, sealGet S.fs kb = none := fun kb => by simp [sealGet, hsS]
  refine ⟨hhr ▸ h1, hhu ▸ h2, fun c hc => hC c (by rw [hi c]; exact hc), ?_, ?_, ?_, ?_, ?_, ?_⟩
  · intro c j w hc hw
    exact hD c j w (by rw [hi c]; exact hc) hw
  · intro c j hdd
    rw [← hi c]
    exact hDI c j (by rw [hd c j]; exact hdd)
  · intro kb e he
    rcases he with he | he
    · rw [gT] at he; cases he
    · rw [sT] at he; cases he
  · intro u k
    obtain ⟨k1, k2, k3, k4, k5⟩ := hK u k
    refine ⟨?_, ?_, ?_, ?_, ?_⟩
    · intro e he; rw [gT] at he; cases he
    · intro _ e he; rw [sT] at he; cases he
    · intro _ _
      rcases k3 (gS _) (sS _) with hh | ⟨c, j, hl⟩
      · exact Or.inl hh
      · exact Or.inr ⟨c, j, (hL c j _ _).1 hl⟩
    · intro c j e hl; exact k4 c j e ((hL c j _ e).2 hl)
    · intro c j e hl
      exact ⟨gT _, sT _, fun c' j' e' hl' => (k5 c j e ((hL c j _ e).2 hl)).2.2 c' j' e' ((hL c' j' _ e').2 hl')⟩
  · intro x
    rw [← hdir]
    rw [hI x]
    exact liveItems_congr hi hd _ _ x |>.trans (by rw [hdir])
  · rw [← hdir]; exact hO

/-- A page read from the log is the page the index hashed, or a collision. -/
theorem pageAt_binds {L : Bytes} {r : CR} {p : Nat} {x y : Bytes} (h : pageAt H L r p = some x)
    (hy : r.phs[p]? = some (pageHash H y)) : x = y ∨ Collides H := by
  unfold pageAt at h
  dsimp only at h
  split at h
  · rename_i hc
    have hx := Option.some.inj h
    rw [hc.2] at hy
    have hh := Option.some.inj hy
    rw [hx] at hh
    by_cases e : x = y
    · exact Or.inl e
    · exact Or.inr ⟨domain "STORE/PAGE" ++ x, domain "STORE/PAGE" ++ y, fun hq => e (List.append_cancel_left hq), hh⟩
  · cases h

/-- What a successful replay of a frame says: the checks, the head, and the tree and install number it ends with (the
    frame's chunk, when there is one, is the next number and its leaf is the hash of its metadata). -/
theorem replayFrame_inv {khs : Nat → List Nat} {S T : LState} {f : Frame} (h : replayFrame H khs S f = some T) :
    (f.shard = S.shard ∧ f.nb0 = S.nb0 ∧ f.batches = S.batches + 1 ∧ f.prev = S.head) ∧
    f.head = chainStepR H S.head f.bd (stateRoot3 H S.shard S.nb0 T.tree.root f.hr f.hu T.nx f.au f.rq) ∧
    T.batches = f.batches ∧ T.head = f.head ∧ T.shard = S.shard ∧ T.nb0 = S.nb0 ∧ T.fs.hr = f.hr ∧
    T.fs.hu = f.hu ∧ T.au = f.au ∧ f.nx = T.nx ∧
    ((f.chunk = none ∧ T.nx = S.nx ∧ T.tree = S.tree ∧ T.fs.inst = S.fs.inst) ∨
     (∃ c pages m3, f.chunk = some (c, pages, m3) ∧ c = S.nx ∧ T.nx = S.nx + 1 ∧
       S.tree.set H c (some (H (domain "STORE/CHUNK" ++ m3))) = some T.tree ∧ T.fs.inst = S.fs.inst.insert c ∧
       ∃ md seq ts tk cm, decMeta3 m3 = some (md, seq, ts, tk) ∧ decM md = some cm ∧
         pages.length = cm.phs.length ∧ S.fs.inst.contains c = false)) := by
  have hc := replayFrame_check h
  unfold replayFrame at h
  simp only [eq_true hc.1, eq_true hc.2.1, eq_true hc.2.2.1, eq_true hc.2.2.2, and_self, if_true,
    Option.bind_eq_bind, Option.bind_some, Option.pure_def] at h
  cases hch : f.chunk with
  | none =>
    simp only [hch] at h
    by_cases hx : f.nx = S.nx
    · simp only [hx, if_true, Option.bind_some] at h
      by_cases hh : f.head = chainStepR H S.head f.bd (stateRoot3 H S.shard S.nb0 S.tree.root f.hr f.hu S.nx f.au f.rq)
      · rw [if_pos hh] at h
        cases h
        exact ⟨hc, hh, rfl, rfl, rfl, rfl, rfl, rfl, rfl, hx, Or.inl ⟨rfl, rfl, rfl, rfl⟩⟩
      · simp [hh] at h
    · simp [hx] at h
  | some x =>
    obtain ⟨c, pages, m3⟩ := x
    simp only [hch] at h
    rw [Option.bind_eq_some_iff] at h
    obtain ⟨⟨md, seq, ts, tk⟩, hd, h⟩ := h
    rw [Option.bind_eq_some_iff] at h
    obtain ⟨cm, hm, h⟩ := h
    dsimp only at h
    by_cases hok : seq = S.nx ∧ f.nx = S.nx + 1 ∧ ts.length = tk.length ∧ pages.length = cm.phs.length ∧
        S.fs.inst.contains c = false ∧ c < 2 ^ cBits ∧ c = S.nx
    · rw [if_pos hok] at h
      split at h
      · rw [Option.bind_eq_some_iff] at h
        obtain ⟨tree, ht, h⟩ := h
        by_cases hh : f.head = chainStepR H S.head f.bd (stateRoot3 H S.shard S.nb0 tree.root f.hr f.hu (S.nx + 1) f.au f.rq)
        · rw [if_pos hh] at h
          cases h
          exact ⟨hc, hh, rfl, rfl, rfl, rfl, rfl, rfl, rfl, hok.2.1, Or.inr ⟨c, pages, m3, rfl, hok.2.2.2.2.2.2, rfl,
            ht, rfl, md, seq, ts, tk, cm, hd, hm, hok.2.2.2.1, hok.2.2.2.2.1⟩⟩
        · rw [if_neg hh] at h; cases h
      · rw [Option.bind_eq_some_iff] at h
        obtain ⟨g, hg, h⟩ := h
        rw [Option.bind_eq_some_iff] at h
        obtain ⟨dir, hd2, h⟩ := h
        rw [Option.bind_eq_some_iff] at h
        obtain ⟨tree, ht, h⟩ := h
        by_cases hh : f.head = chainStepR H S.head f.bd (stateRoot3 H S.shard S.nb0 tree.root f.hr f.hu (S.nx + 1) f.au f.rq)
        · rw [if_pos hh] at h
          cases h
          exact ⟨hc, hh, rfl, rfl, rfl, rfl, rfl, rfl, rfl, hok.2.1, Or.inr ⟨c, pages, m3, rfl, hok.2.2.2.2.2.2, rfl,
            ht, rfl, md, seq, ts, tk, cm, hd, hm, hok.2.2.2.1, hok.2.2.2.2.1⟩⟩
        · rw [if_neg hh] at h; cases h
    · rw [if_neg hok] at h
      cases h

/-- The facts about a frame that its fields' lengths and its pages need: heads and digests of 64 bytes, whole pages. -/
def FrOK (f : Frame) : Prop :=
  f.prev.length = 64 ∧ f.bd.length = 64 ∧ ∀ x ∈ f.chunk, ∀ p ∈ x.2.1, p.length = pageSize

theorem frOK_of_wf {f : Frame} (h : f.Wf) : FrOK f :=
  ⟨h.2.2.2.2.1, h.2.2.2.2.2.1, fun x hx => (h.1 x hx).1⟩

theorem decTrailer_len {tb : Bytes} {c : Nat} {f : Frame} (h : decTrailer tb = some (c, f)) :
    f.prev.length = 64 ∧ f.bd.length = 64 := by
  unfold decTrailer at h
  rcases h1 : takeN (domain "FLAT/FRAME").length tb with _ | ⟨t, r0⟩
  · simp [h1] at h
  by_cases ht : t = domain "FLAT/FRAME"
  case neg => simp [h1, ht] at h
  rcases h2a : unleb r0 with _ | ⟨sh, r0a⟩
  · simp [h1, ht, h2a] at h
  rcases h2b : unleb r0a with _ | ⟨nb, r0b⟩
  · simp [h1, ht, h2a, h2b] at h
  rcases h2 : unleb r0b with _ | ⟨b, r1⟩
  · simp [h1, ht, h2a, h2b, h2] at h
  rcases h3 : unleb r1 with _ | ⟨c', r2⟩
  · simp [h1, ht, h2a, h2b, h2, h3] at h
  rcases h4 : decHead r2 with _ | ⟨hr, r3⟩
  · simp [h1, ht, h2a, h2b, h2, h3, h4] at h
  rcases h5 : decHead r3 with _ | ⟨hu, r4⟩
  · simp [h1, ht, h2a, h2b, h2, h3, h4, h5] at h
  rcases h6 : unleb r4 with _ | ⟨nx, r5⟩
  · simp [h1, ht, h2a, h2b, h2, h3, h4, h5, h6] at h
  rcases h6a : takeN authLen r5 with _ | ⟨au, r5a⟩
  · simp [h1, ht, h2a, h2b, h2, h3, h4, h5, h6, h6a] at h
  rcases h8 : takeN 64 r5a with _ | ⟨rq, r7⟩
  · simp [h1, ht, h2a, h2b, h2, h3, h4, h5, h6, h6a, h8] at h
  rcases h9 : takeN 64 r7 with _ | ⟨pv, r8⟩
  · simp [h1, ht, h2a, h2b, h2, h3, h4, h5, h6, h6a, h8, h9] at h
  rcases h10 : takeN 64 r8 with _ | ⟨bd, r9⟩
  · simp [h1, ht, h2a, h2b, h2, h3, h4, h5, h6, h6a, h8, h9, h10] at h
  rcases h11 : takeN 64 r9 with _ | ⟨hd, r10⟩
  · simp [h1, ht, h2a, h2b, h2, h3, h4, h5, h6, h6a, h8, h9, h10, h11] at h
  by_cases hr10 : r10 = []
  case neg => simp [h1, ht, h2a, h2b, h2, h3, h4, h5, h6, h6a, h8, h9, h10, h11, hr10] at h
  subst hr10
  simp [h1, ht, h2a, h2b, h2, h3, h4, h5, h6, h6a, h8, h9, h10, h11] at h
  obtain ⟨rfl, rfl⟩ := h
  exact ⟨(takeN_canon h9).2, (takeN_canon h10).2⟩

theorem splitPages_len : ∀ (n : Nat) (b : Bytes), b.length = n * pageSize → ∀ p ∈ splitPages n b, p.length = pageSize
  | 0, _, _ => by simp [splitPages]
  | n + 1, b, h => by
    intro p hp
    simp only [splitPages, List.mem_cons] at hp
    rcases hp with rfl | hp
    · have : pageSize ≤ b.length := by rw [h]; exact Nat.le_mul_of_pos_left _ (Nat.succ_pos n)
      rw [List.length_take]
      exact Nat.min_eq_left this
    · exact splitPages_len n _ (by simp [List.length_drop, h, Nat.add_mul]) p hp

theorem decFrame_ok {b : Bytes} {f : Frame} {r : Bytes} (h : decFrame b = some (f, r)) : FrOK f := by
  unfold decFrame at h
  rcases h1 : takeN 4 b with _ | ⟨t, r1⟩
  · simp [h1] at h
  by_cases ht : t = frameTag
  case neg => simp [h1, ht] at h
  rcases h2 : unle32 r1 with _ | ⟨np, r2⟩
  · simp [h1, ht, h2] at h
  rcases h3 : unle32 r2 with _ | ⟨ml, r3⟩
  · simp [h1, ht, h2, h3] at h
  rcases h4 : unle32 r3 with _ | ⟨tl, r4⟩
  · simp [h1, ht, h2, h3, h4] at h
  rcases h5 : takeN (np * pageSize) r4 with _ | ⟨pg, r5⟩
  · simp [h1, ht, h2, h3, h4, h5] at h
  rcases h6 : takeN ml r5 with _ | ⟨m, r6⟩
  · simp [h1, ht, h2, h3, h4, h5, h6] at h
  rcases h7 : takeN tl r6 with _ | ⟨tb, r7⟩
  · simp [h1, ht, h2, h3, h4, h5, h6, h7] at h
  rcases h8 : decTrailer tb with _ | ⟨c, f0⟩
  · simp [h1, ht, h2, h3, h4, h5, h6, h7, h8] at h
  obtain ⟨-, l5⟩ := takeN_canon h5
  obtain ⟨hl9, hl10⟩ := decTrailer_len h8
  obtain ⟨hch, -⟩ := decTrailer_canon h8
  cases c with
  | zero =>
    simp [h1, ht, h2, h3, h4, h5, h6, h7, h8] at h
    obtain ⟨-, hf, -⟩ := h
    subst hf
    exact ⟨hl9, hl10, by simp [hch]⟩
  | succ c =>
    simp [h1, ht, h2, h3, h4, h5, h6, h7, h8] at h
    obtain ⟨rfl, rfl⟩ := h
    refine ⟨hl9, hl10, ?_⟩
    intro x hx p hp
    simp at hx
    subst hx
    exact splitPages_len np pg l5 p hp

theorem decFrames_ok : ∀ (n : Nat) (b : Bytes), ∀ f ∈ decFrames n b, FrOK f
  | 0, _ => by simp [decFrames]
  | n + 1, b => by
    unfold decFrames
    rcases h : decFrame b with _ | ⟨fr, r⟩
    · simp
    · simp only [List.mem_cons]
      intro f hf
      rcases hf with rfl | hf
      · exact decFrame_ok h
      · exact decFrames_ok n r f hf

theorem replay_rootDig {khs : Nat → List Nat} {S T : LState} {f : Frame} (h : replayFrame H khs S f = some T)
    (hS : ∃ x, S.tree.root = H x) : ∃ x, T.tree.root = H x := by
  obtain ⟨-, -, -, -, -, -, -, -, -, -, hc⟩ := replayFrame_inv h
  rcases hc with ⟨-, -, ht, -⟩ | ⟨c, pages, m3, -, -, -, hset, -⟩
  · rw [ht]; exact hS
  · exact set_root hset

/-- One replayed step on both sides, with equal heads after it and equal trees and install numbers before it: the same
    shard, bucket count, set heads, authority record, request digest and batch digest, and the same chunk (the same
    metadata, so pages in equal number), or two distinct inputs with one digest. -/
theorem step_bind {kf kg : Nat → List Nat} {A B A1 B1 : LState} {f g : Frame}
    (hH : ∀ x, (H x).length = 64)
    (hT : A.tree = B.tree) (hnx : A.nx = B.nx) (hhd : A.head = B.head) (hroot : ∃ x, A.tree.root = H x)
    (hf : replayFrame H kf A f = some A1) (hg : replayFrame H kg B g = some B1) (hfh : f.head = g.head)
    (hbd : f.bd.length = g.bd.length) :
    (A.shard = B.shard ∧ A.nb0 = B.nb0 ∧ f.hr = g.hr ∧ f.hu = g.hu ∧ f.nx = g.nx ∧ f.au = g.au ∧ f.rq = g.rq ∧
      f.bd = g.bd ∧
      ((f.chunk = none ∧ g.chunk = none) ∨ ∃ c ps ps' m3, f.chunk = some (c, ps, m3) ∧ g.chunk = some (c, ps', m3) ∧
        ps.length = ps'.length)) ∨ Collides H := by
  obtain ⟨hcf, hchf, -, -, -, -, -, -, -, hnxf, hf'⟩ := replayFrame_inv hf
  obtain ⟨hcg, hchg, -, -, -, -, -, -, -, hnxg, hg'⟩ := replayFrame_inv hg
  have hch : chainStepR H A.head f.bd (stateRoot3 H A.shard A.nb0 A1.tree.root f.hr f.hu A1.nx f.au f.rq) =
      chainStepR H B.head g.bd (stateRoot3 H B.shard B.nb0 B1.tree.root g.hr g.hu B1.nx g.au g.rq) := by
    rw [← hchf, ← hchg, hfh]
  rw [hhd] at hch
  rcases chainStepR_binds H rfl hbd hch with ⟨-, hbd', hrb⟩ | ⟨hne, heq⟩
  case inr => exact Or.inr ⟨_, _, hne, heq⟩
  obtain ⟨xa, hxa⟩ := replay_rootDig hf hroot
  obtain ⟨xb, hxb⟩ := replay_rootDig hg (by rw [← hT]; exact hroot)
  have hlen : A1.tree.root.length = B1.tree.root.length := by rw [hxa, hxb, hH, hH]
  rcases stateRoot3_binds hlen hrb with ⟨hk, hnb, htr, hhr, hhu, hnx', hau, hrq⟩ | hcol
  case inr => exact Or.inr hcol
  have hnxe : f.nx = g.nx := by rw [hnxf, hnxg]; exact hnx'
  have hshape : ((f.chunk = none ∧ g.chunk = none) ∨ ∃ c ps ps' m3, f.chunk = some (c, ps, m3) ∧
      g.chunk = some (c, ps', m3) ∧ ps.length = ps'.length) ∨ Collides H := by
    rcases hf' with ⟨hfc, hn1, ht1, -⟩ | ⟨c, ps, m3, hfc, hc1, hn1, hs1, -, md, seq, ts, tk, cm, hd1, hm1, hl1, -⟩ <;>
    rcases hg' with ⟨hgc, hn2, ht2, -⟩ | ⟨c', ps', m3', hgc, hc2, hn2, hs2, -, md', seq', ts', tk', cm', hd2, hm2, hl2, -⟩
    · exact Or.inl (Or.inl ⟨hfc, hgc⟩)
    · exfalso; omega
    · exfalso; omega
    · have hcc : c = c' := by omega
      subst hcc
      rcases set_binds (fun l i => by rw [hT]) hs1 hs2 htr with hv | hcol
      · have hv' := Option.some.inj hv
        by_cases hm : m3 = m3'
        · subst hm
          have e1 := hd1.symm.trans hd2
          cases e1
          have e2 := hm1.symm.trans hm2
          cases e2
          exact Or.inl (Or.inr ⟨c, ps, ps', m3, hfc, hgc, by rw [hl1, hl2]⟩)
        · exact Or.inr ⟨_, _, fun e => hm (List.append_cancel_left e), hv'⟩
      · exact Or.inr hcol
  rcases hshape with hs | hc
  · exact Or.inl ⟨hk, hnb, hhr, hhu, hnxe, hau, hrq, hbd', hs⟩
  · exact Or.inr hc

theorem replayFrame_au {khs : Nat → List Nat} (S : LState) (x : Bytes) (f : Frame) :
    replayFrame H khs { S with au := x } f = replayFrame H khs S f := rfl

theorem replayFrame_pages {khs : Nat → List Nat} {S : LState} {f g : Frame} {c : Nat} {ps ps' : List Bytes}
    {m3 : Bytes} (hf : f.chunk = some (c, ps, m3)) (hg : g = { f with chunk := some (c, ps', m3) })
    (hl : ps.length = ps'.length) (he : (encFrame f).length = (encFrame g).length) :
    replayFrame H khs S f = replayFrame H khs S g := by
  subst hg
  unfold replayFrame
  simp only [hf, hl, he]

theorem encFrame_length_pages {f : Frame} {c : Nat} {ps ps' : List Bytes} {m3 : Bytes}
    (hf : f.chunk = some (c, ps, m3)) (hl : ps.length = ps'.length) (hp : ∀ p ∈ ps, p.length = pageSize)
    (hp' : ∀ p ∈ ps', p.length = pageSize) :
    (encFrame f).length = (encFrame { f with chunk := some (c, ps', m3) }).length := by
  have e1 := flatten_length ps hp
  have e2 := flatten_length ps' hp'
  simp [encFrame, frameBody, frameTrailer, Frame.cnum, hf, e1, e2, hl]

theorem frame_ext {f g : Frame} (h1 : f.chunk = g.chunk) (h2 : f.shard = g.shard) (h3 : f.nb0 = g.nb0)
    (h4 : f.batches = g.batches) (h5 : f.hr = g.hr) (h6 : f.hu = g.hu) (h7 : f.nx = g.nx) (h8 : f.au = g.au)
    (h9 : f.rq = g.rq) (h10 : f.prev = g.prev) (h11 : f.bd = g.bd) (h12 : f.head = g.head) : f = g := by
  cases f; cases g
  dsimp only at *
  subst_vars
  rfl

/-- A replay step from states equal up to the authority record, on frames of one head after it and key hashes agreeing on
    the installed chunks: the same state after it, and the same chunk number and metadata (or none on both sides), or
    two distinct inputs with one digest. -/
theorem step_eq {kf kg : Nat → List Nat} {A B A1 B1 : LState} {f g : Frame}
    (hH : ∀ x, (H x).length = 64)
    (hAB : A = { B with au := A.au }) (hroot : ∃ x, B.tree.root = H x)
    (hk : ∀ x, A.fs.inst.contains x = true → kf x = kg x)
    (hof : FrOK f) (hog : FrOK g)
    (hf : replayFrame H kf A f = some A1) (hg : replayFrame H kg B g = some B1) (hfh : f.head = g.head) :
    (A1 = B1 ∧ ((f.chunk = none ∧ g.chunk = none) ∨
      ∃ c ps ps' m3, f.chunk = some (c, ps, m3) ∧ g.chunk = some (c, ps', m3))) ∨ Collides H := by
  have hT : A.tree = B.tree := by rw [hAB]
  have hnx : A.nx = B.nx := by rw [hAB]
  have hhd : A.head = B.head := by rw [hAB]
  have hbt : A.batches = B.batches := by rw [hAB]
  have hfsAB : A.fs = B.fs := by rw [hAB]
  have hroot' : ∃ x, A.tree.root = H x := by rw [hT]; exact hroot
  rcases step_bind hH hT hnx hhd hroot' hf hg hfh (hof.2.1.trans hog.2.1.symm) with
    ⟨hsh, hnb, hhr, hhu, hnxe, hau, hrq, hbd, hshape⟩ | hcol
  case inr => exact Or.inr hcol
  obtain ⟨hcf, -⟩ := replayFrame_inv hf
  obtain ⟨hcg, -⟩ := replayFrame_inv hg
  have hA : replayFrame H kg B f = some A1 := by
    have h1 : replayFrame H kf A f = replayFrame H kf B f := by
      have := replayFrame_au (H := H) (khs := kf) B A.au f
      rw [← hAB] at this
      exact this
    have h2 : replayFrame H kf B f = replayFrame H kg B f :=
      replayFrame_khs (fun x hx => hk x (by rw [hfsAB]; exact hx)) f
    rw [← h2, ← h1]
    exact hf
  rcases hshape with ⟨hfc, hgc⟩ | ⟨c, ps, ps', m3, hfc, hgc, hl⟩
  · have hgf : g = f := frame_ext (hgc.trans hfc.symm) (by show g.shard = f.shard; rw [hcg.1, hcf.1, hsh])
      (by show g.nb0 = f.nb0; rw [hcg.2.1, hcf.2.1, hnb]) (by show g.batches = f.batches; rw [hcg.2.2.1, hcf.2.2.1, hbt])
      hhr.symm hhu.symm hnxe.symm hau.symm hrq.symm (by show g.prev = f.prev; rw [hcg.2.2.2, hcf.2.2.2, hhd])
      hbd.symm hfh.symm
    subst hgf
    rw [hA] at hg
    exact Or.inl ⟨Option.some.inj hg, Or.inl ⟨hfc, hgc⟩⟩
  · have hgf : g = { f with chunk := some (c, ps', m3) } := frame_ext hgc
      (by show g.shard = f.shard; rw [hcg.1, hcf.1, hsh]) (by show g.nb0 = f.nb0; rw [hcg.2.1, hcf.2.1, hnb])
      (by show g.batches = f.batches; rw [hcg.2.2.1, hcf.2.2.1, hbt]) hhr.symm hhu.symm hnxe.symm hau.symm hrq.symm
      (by show g.prev = f.prev; rw [hcg.2.2.2, hcf.2.2.2, hhd]) hbd.symm hfh.symm
    have hpf : ∀ p ∈ ps, p.length = pageSize := fun p hp => hof.2.2 (c, ps, m3) (by simp [hfc]) p hp
    have hpg : ∀ p ∈ ps', p.length = pageSize := fun p hp => hog.2.2 (c, ps', m3) (by simp [hgc]) p hp
    have he := encFrame_length_pages hfc hl hpf hpg
    have hB : replayFrame H kg B f = replayFrame H kg B g :=
      replayFrame_pages hfc hgf hl (by rw [hgf]; exact he)
    rw [hB, hg] at hA
    exact Or.inl ⟨(Option.some.inj hA).symm, Or.inr ⟨c, ps, ps', m3, hfc, hgc⟩⟩

/-- The head after a step binds the head, the shard and the bucket count before it. -/
theorem step_back {kf kg : Nat → List Nat} {A B A1 B1 : LState} {f g : Frame}
    (hH : ∀ x, (H x).length = 64) (hof : FrOK f) (hog : FrOK g)
    (hrA : ∃ x, A.tree.root = H x) (hrB : ∃ x, B.tree.root = H x)
    (hf : replayFrame H kf A f = some A1) (hg : replayFrame H kg B g = some B1) (hfh : f.head = g.head) :
    (A.head = B.head ∧ A.shard = B.shard ∧ A.nb0 = B.nb0) ∨ Collides H := by
  obtain ⟨hcf, hchf, -⟩ := replayFrame_inv hf
  obtain ⟨hcg, hchg, -⟩ := replayFrame_inv hg
  have hch : chainStepR H A.head f.bd (stateRoot3 H A.shard A.nb0 A1.tree.root f.hr f.hu A1.nx f.au f.rq) =
      chainStepR H B.head g.bd (stateRoot3 H B.shard B.nb0 B1.tree.root g.hr g.hu B1.nx g.au g.rq) := by
    rw [← hchf, ← hchg, hfh]
  have hD : A.head.length = B.head.length := by rw [← hcf.2.2.2, ← hcg.2.2.2, hof.1, hog.1]
  rcases chainStepR_binds H hD (hof.2.1.trans hog.2.1.symm) hch with ⟨hD', -, hrb⟩ | ⟨hne, heq⟩
  case inr => exact Or.inr ⟨_, _, hne, heq⟩
  obtain ⟨xa, hxa⟩ := replay_rootDig hf hrA
  obtain ⟨xb, hxb⟩ := replay_rootDig hg hrB
  have hlen : A1.tree.root.length = B1.tree.root.length := by rw [hxa, hxb, hH, hH]
  rcases stateRoot3_binds hlen hrb with ⟨hk, hnb, -⟩ | hcol
  case inr => exact Or.inr hcol
  exact Or.inl ⟨hD', hk, hnb⟩

theorem foldl_cons {khs : Nat → List Nat} {f : Frame} {r : List Frame} {G T : LState}
    (h : (f :: r).foldlM (replayFrame H khs) G = some T) :
    ∃ G', replayFrame H khs G f = some G' ∧ r.foldlM (replayFrame H khs) G' = some T := by
  simp only [List.foldlM] at h
  cases hf : replayFrame H khs G f with
  | none => rw [hf] at h; cases h
  | some G' => rw [hf] at h; exact ⟨G', rfl, h⟩

theorem foldl_nil {khs : Nat → List Nat} {G T : LState} (h : ([] : List Frame).foldlM (replayFrame H khs) G = some T) :
    G = T := by
  simp [List.foldlM] at h
  exact h

/-- Two replays of lists of one length, from starts of roots that are digests, ending at one head, start at one head,
    shard and bucket count, or two distinct inputs share a digest. -/
theorem back {kf kg : Nat → List Nat} (hH : ∀ x, (H x).length = 64) : ∀ (r1 r2 : List Frame) (f g : Frame)
    (A B A1 B1 : LState), r1.length = r2.length → (∀ x ∈ f :: r1, FrOK x) → (∀ x ∈ g :: r2, FrOK x) →
    (∃ x, A.tree.root = H x) → (∃ x, B.tree.root = H x) →
    (f :: r1).foldlM (replayFrame H kf) A = some A1 → (g :: r2).foldlM (replayFrame H kg) B = some B1 →
    A1.head = B1.head → (A.head = B.head ∧ A.shard = B.shard ∧ A.nb0 = B.nb0) ∨ Collides H := by
  intro r1
  induction r1 with
  | nil =>
    intro r2 f g A B A1 B1 hl hof hog hrA hrB hf hg hh
    cases r2 with
    | cons => simp at hl
    | nil =>
      obtain ⟨A', hfA, hfr⟩ := foldl_cons hf
      obtain ⟨B', hgB, hgr⟩ := foldl_cons hg
      have e1 := foldl_nil hfr
      have e2 := foldl_nil hgr
      subst e1 e2
      have hfh : f.head = g.head := by
        rw [← (replayFrame_out hfA).2.1, ← (replayFrame_out hgB).2.1]; exact hh
      exact step_back hH (hof f (List.mem_cons_self ..)) (hog g (List.mem_cons_self ..)) hrA hrB hfA hgB hfh
  | cons f2 r1' ih =>
    intro r2 f g A B A1 B1 hl hof hog hrA hrB hf hg hh
    cases r2 with
    | nil => simp at hl
    | cons g2 r2' =>
      obtain ⟨A', hfA, hfr⟩ := foldl_cons hf
      obtain ⟨B', hgB, hgr⟩ := foldl_cons hg
      have hrA' := replay_rootDig hfA hrA
      have hrB' := replay_rootDig hgB hrB
      rcases ih r2' f2 g2 A' B' A1 B1 (by simpa using hl) (fun x hx => hof x (List.mem_cons_of_mem _ hx))
        (fun x hx => hog x (List.mem_cons_of_mem _ hx)) hrA' hrB' hfr hgr hh with ⟨hhd, -, -⟩ | hcol
      case inr => exact Or.inr hcol
      have hfh : f.head = g.head := by
        rw [← (replayFrame_out hfA).2.1, ← (replayFrame_out hgB).2.1]; exact hhd
      exact step_back hH (hof f (List.mem_cons_self ..)) (hog g (List.mem_cons_self ..)) hrA hrB hfA hgB hfh

theorem nx_lt {khs : Nat → List Nat} {S T : LState} {f : Frame} {pre : List Frame}
    (h : replayFrame H khs S f = some T)
    (hp : ∀ f' ∈ pre, ∀ x ps m, f'.chunk = some (x, ps, m) → x < S.nx) :
    ∀ f' ∈ pre ++ [f], ∀ x ps m, f'.chunk = some (x, ps, m) → x < T.nx := by
  obtain ⟨-, -, -, -, -, -, -, -, -, -, hc⟩ := replayFrame_inv h
  intro f' hf' x ps m hx
  rcases List.mem_append.mp hf' with hm | hm
  · have := hp f' hm x ps m hx
    rcases hc with ⟨-, h1, -⟩ | ⟨c, pages, m3, -, -, h1, -⟩ <;> omega
  · rw [List.mem_singleton.mp hm] at hx
    rcases hc with ⟨h0, -⟩ | ⟨c, pages, m3, h0, h2, h1, -⟩
    · rw [hx] at h0; cases h0
    · rw [hx] at h0
      cases h0
      omega

/-- The key hashes the log gives chunk `c`: those of the first frame that installs it. -/
theorem khsOf_first {pre rest : List Frame} {f : Frame} {c : Nat} {ps : List Bytes} {m3 : Bytes}
    {y : Bytes × Nat × List Tomb × List Nat} {cm : CMeta}
    (hpre : ∀ f' ∈ pre, ∀ x ps m, f'.chunk = some (x, ps, m) → x ≠ c)
    (hf : f.chunk = some (c, ps, m3)) (hd : decMeta3 m3 = some y) (hm : decM y.1 = some cm) :
    khsOf (pre ++ f :: rest) c = cm.khs := by
  have h1 : ∀ p : Frame → Option (List Nat), (∀ f' ∈ pre, p f' = none) → pre.findSome? p = none :=
    fun p h => List.findSome?_eq_none_iff.mpr h
  unfold khsOf
  rw [List.findSome?_append, h1 _ ?_]
  · simp [hf, hd, hm]
  · intro f' hf'
    cases hc : f'.chunk with
    | none => simp
    | some t =>
      obtain ⟨x, ps', m⟩ := t
      simp [hpre f' hf' x ps' m hc]

/-- One step of two replays that agree so far: the states after it are one state, the key hashes agree on its installed
    chunks (the first frame to install a chunk is the one that did), and every earlier frame's chunk number is below its
    install count; or two distinct inputs share a digest. -/
theorem fwd_step (hH : ∀ x, (H x).length = 64) {F1 F2 pre1 pre2 r1 r2 post1 post2 : List Frame} {f g : Frame}
    {A B A' B' : LState}
    (hF1 : F1 = pre1 ++ f :: (r1 ++ post1)) (hF2 : F2 = pre2 ++ g :: (r2 ++ post2))
    (hof : FrOK f) (hog : FrOK g) (hAB : A = { B with au := A.au }) (hrB : ∃ x, B.tree.root = H x)
    (hk : ∀ x, A.fs.inst.contains x = true → khsOf F1 x = khsOf F2 x)
    (hp1 : ∀ f' ∈ pre1, ∀ x ps m, f'.chunk = some (x, ps, m) → x < A.nx)
    (hp2 : ∀ f' ∈ pre2, ∀ x ps m, f'.chunk = some (x, ps, m) → x < A.nx)
    (hf : replayFrame H (khsOf F1) A f = some A') (hg : replayFrame H (khsOf F2) B g = some B')
    (hfh : f.head = g.head) :
    (A' = B' ∧ (∀ x, A'.fs.inst.contains x = true → khsOf F1 x = khsOf F2 x) ∧
      (∀ f' ∈ pre1 ++ [f], ∀ x ps m, f'.chunk = some (x, ps, m) → x < A'.nx) ∧
      (∀ f' ∈ pre2 ++ [g], ∀ x ps m, f'.chunk = some (x, ps, m) → x < A'.nx)) ∨ Collides H := by
  have hnx : A.nx = B.nx := by rw [hAB]
  rcases step_eq hH hAB hrB hk hof hog hf hg hfh with ⟨hEq, hshape⟩ | hcol
  case inr => exact Or.inr hcol
  refine Or.inl ⟨hEq, ?_, nx_lt hf hp1, ?_⟩
  · intro x hx
    obtain ⟨-, -, -, -, -, -, -, -, -, -, hc⟩ := replayFrame_inv hf
    rcases hc with ⟨-, -, -, hi⟩ | ⟨c, pages, m3, hfc, hc, -, -, hi, md, seq, ts, tk, cm, hd, hm, -, -⟩
    · rw [hi] at hx
      exact hk x hx
    · rw [hi] at hx
      simp only [Std.HashSet.contains_insert, Bool.or_eq_true, beq_iff_eq] at hx
      rcases hx with hx | hx
      · subst hx
        rcases hshape with ⟨h0, -⟩ | ⟨c', ps, ps', m3', hfc', hgc'⟩
        · rw [hfc] at h0; cases h0
        · rw [hfc] at hfc'
          cases hfc'
          have e1 : khsOf F1 c = cm.khs := by
            rw [hF1]
            exact khsOf_first (fun f' hf' x ps m h => by have := hp1 f' hf' x ps m h; omega) hfc hd hm
          have e2 : khsOf F2 c = cm.khs := by
            rw [hF2]
            exact khsOf_first (fun f' hf' x ps m h => by have := hp2 f' hf' x ps m h; omega) hgc' hd hm
          rw [e1, e2]
      · exact hk x hx
  · have := nx_lt hg (pre := pre2) (fun f' hf' x ps m h => by have := hp2 f' hf' x ps m h; omega)
    rw [hEq]
    exact this

/-- Two replays of lists of one length from states equal but for the authority record, with frames of equal heads at the
    end, key hashes read from the whole logs agreeing as chunks are installed: one state at the end, or two distinct
    inputs share a digest. -/
theorem fwd (hH : ∀ x, (H x).length = 64) {F1 F2 : List Frame} : ∀ (r1 r2 pre1 pre2 post1 post2 : List Frame)
    (f g : Frame) (A B A1 B1 : LState), r1.length = r2.length → F1 = pre1 ++ f :: (r1 ++ post1) →
    F2 = pre2 ++ g :: (r2 ++ post2) → (∀ x ∈ f :: r1, FrOK x) → (∀ x ∈ g :: r2, FrOK x) →
    A = { B with au := A.au } → (∃ x, B.tree.root = H x) →
    (∀ x, A.fs.inst.contains x = true → khsOf F1 x = khsOf F2 x) →
    (∀ f' ∈ pre1, ∀ x ps m, f'.chunk = some (x, ps, m) → x < A.nx) →
    (∀ f' ∈ pre2, ∀ x ps m, f'.chunk = some (x, ps, m) → x < A.nx) →
    (f :: r1).foldlM (replayFrame H (khsOf F1)) A = some A1 →
    (g :: r2).foldlM (replayFrame H (khsOf F2)) B = some B1 → A1.head = B1.head → A1 = B1 ∨ Collides H := by
  intro r1
  induction r1 with
  | nil =>
    intro r2 pre1 pre2 post1 post2 f g A B A1 B1 hl hF1 hF2 hof hog hAB hrB hk hp1 hp2 hf hg hh
    cases r2 with
    | cons => simp at hl
    | nil =>
      obtain ⟨A', hfA, hfr⟩ := foldl_cons hf
      obtain ⟨B', hgB, hgr⟩ := foldl_cons hg
      have e1 := foldl_nil hfr
      have e2 := foldl_nil hgr
      subst e1 e2
      have hfh : f.head = g.head := by
        rw [← (replayFrame_out hfA).2.1, ← (replayFrame_out hgB).2.1]; exact hh
      rcases fwd_step hH hF1 hF2 (hof f (List.mem_cons_self ..)) (hog g (List.mem_cons_self ..)) hAB hrB hk hp1 hp2
        hfA hgB hfh with ⟨hEq, -⟩ | hcol
      · exact Or.inl hEq
      · exact Or.inr hcol
  | cons f2 r1' ih =>
    intro r2 pre1 pre2 post1 post2 f g A B A1 B1 hl hF1 hF2 hof hog hAB hrB hk hp1 hp2 hf hg hh
    cases r2 with
    | nil => simp at hl
    | cons g2 r2' =>
      obtain ⟨A', hfA, hfr⟩ := foldl_cons hf
      obtain ⟨B', hgB, hgr⟩ := foldl_cons hg
      have hrA : ∃ x, A.tree.root = H x := by
        obtain ⟨x, hx⟩ := hrB
        exact ⟨x, by rw [hAB]; exact hx⟩
      have hrA' := replay_rootDig hfA hrA
      have hrB' := replay_rootDig hgB hrB
      rcases back (kf := khsOf F1) (kg := khsOf F2) hH r1' r2' f2 g2 A' B' A1 B1 (by simpa using hl)
        (fun x hx => hof x (List.mem_cons_of_mem _ hx)) (fun x hx => hog x (List.mem_cons_of_mem _ hx)) hrA' hrB'
        hfr hgr hh with ⟨hhd, -, -⟩ | hcol
      case inr => exact Or.inr hcol
      have hfh : f.head = g.head := by
        rw [← (replayFrame_out hfA).2.1, ← (replayFrame_out hgB).2.1]; exact hhd
      rcases fwd_step hH hF1 hF2 (hof f (List.mem_cons_self ..)) (hog g (List.mem_cons_self ..)) hAB hrB hk hp1 hp2
        hfA hgB hfh with ⟨hEq, hk', hp1', hp2'⟩ | hcol
      case inr => exact Or.inr hcol
      subst hEq
      exact ih r2' (pre1 ++ [f]) (pre2 ++ [g]) post1 post2 f2 g2 A' A' A1 B1 (by simpa using hl)
        (by rw [hF1]; simp) (by rw [hF2]; simp) (fun x hx => hof x (List.mem_cons_of_mem _ hx))
        (fun x hx => hog x (List.mem_cons_of_mem _ hx)) rfl hrB' hk' hp1' hp2' hfr hgr hh

/-- What a load that succeeds read: the log's whole frames, the first and the target among them, the checks at the target,
    and the replay of the first `bt` of them from the empty store of the first frame's shard and bucket count. -/
theorem loadLog_fold {d' : Disk} {names : List String} {hd : Bytes} {bt : Nat} {T : LState} {p : Option Frame}
    {rep : List Op} (h : loadLog H d' names hd bt = .ok (T, p, rep)) :
    ∃ (L : Bytes) (f0 tg : Frame), bt ≠ 0 ∧ d' "log" = some L ∧ (decFrames L.length L)[0]? = some f0 ∧
      (decFrames L.length L)[bt - 1]? = some tg ∧
      ((decFrames L.length L).length = bt ∨ (decFrames L.length L).length = bt + 1) ∧ tg.head = hd ∧
      tg.batches = bt ∧
      ((decFrames L.length L).take bt).foldlM (replayFrame H (khsOf (decFrames L.length L)))
        { LState.genesis H f0.shard 0 f0.nb0 f0.au with head := f0.prev } = some T := by
  unfold loadLog at h
  by_cases hb : bt = 0
  · simp [hb] at h
  simp only [hb, if_false] at h
  cases hn : names.any (fun n => !(n = "lock" || n = "log")) with
  | true => simp only [hn, if_true] at h; cases h
  | false =>
    simp only [hn, Bool.false_eq_true, if_false] at h
    cases hL : d' "log" with
    | none => simp [hL] at h
    | some L =>
      simp only [hL] at h
      cases h0 : (decFrames L.length L)[0]? with
      | none => simp [h0] at h
      | some f0 =>
        cases ht : (decFrames L.length L)[bt - 1]? with
        | none => simp [h0, ht] at h
        | some tg =>
          simp only [h0, ht] at h
          by_cases hc : ((decFrames L.length L).length = bt ∨ (decFrames L.length L).length = bt + 1) ∧
              tg.head = hd ∧ tg.batches = bt
          · simp only [hc, and_self, if_true] at h
            cases hT : ((decFrames L.length L).take bt).foldlM (replayFrame H (khsOf (decFrames L.length L)))
                { LState.genesis H f0.shard 0 f0.nb0 f0.au with head := f0.prev } with
            | none => simp [hT] at h
            | some T0 =>
              simp only [hT] at h
              have hTT : T0 = T := by
                cases hq : (decFrames L.length L)[bt]? with
                | none =>
                  simp only [hq, Except.ok.injEq, Prod.mk.injEq] at h
                  exact h.1
                | some q =>
                  simp only [hq] at h
                  cases hr : replayFrame H (khsOf (decFrames L.length L)) T0 q with
                  | none => simp [hr] at h
                  | some _ =>
                    simp only [hr, Except.ok.injEq, Prod.mk.injEq] at h
                    exact h.1
              subst hTT
              exact ⟨L, f0, tg, hb, rfl, h0, ht, hc.1, hc.2.1, hc.2.2, hT⟩
          · simp [hc] at h

/-- Whatever the files hold (any frame, metadata or name changed, added or removed), a load at the signed head gives
    the writer's state or exhibits a collision (digests of one length).  The replay of the loaded log and the replay of
    the writer's log end at one head, so by the hash chain they agree at every step; each step then agrees in the
    shard, the set heads, the chunk's metadata (through the tree's root after one `Tree.set`) and the page count. -/
theorem load_binds {d d' : Disk} {S T : LState} {names : List String} {p : Option Frame} {rep : List Op}
    (hH : ∀ x, (H x).length = 64) (hR : Reach H kh d S) (hl : loadLog H d' names S.head S.batches = .ok (T, p, rep)) :
    T.Same S ∨ Collides H := by
  obtain ⟨L, f0, tg, hb, hL, h0, ht, hlen', hth, htb, hT⟩ := loadLog_fold hl
  obtain ⟨-, -, hTb, hTh, -⟩ := loadLog_ok hl
  obtain ⟨sh, asOf, nb, au, frs, hwf, hlen, hlog, hfiles, hQ, hlast, hrep⟩ := reach_replay hR
  obtain ⟨R, hRf, hRS⟩ := hrep (khsOf frs) (fun _ _ => rfl)
  have hfok := decFrames_ok L.length L
  generalize decFrames L.length L = fs at hfok h0 ht hlen' hT
  obtain ⟨k, hk⟩ : ∃ k, S.batches = k + 1 := ⟨S.batches - 1, by omega⟩
  obtain ⟨r1, hr1⟩ : ∃ r1, fs = f0 :: r1 := by
    cases fs with
    | nil => simp at h0
    | cons a r => simp at h0; exact ⟨r, by rw [h0]⟩
  subst hr1
  cases frs with
  | nil => simp at hlen; omega
  | cons g0 rest =>
    have hrl : rest.length = k := by simp at hlen; omega
    have hr1l : k ≤ r1.length := by rw [hk] at hlen'; simp at hlen'; omega
    have hRf' := replay_start hRf
    rw [hk, List.take_succ_cons] at hT
    have hRS' := hRS
    obtain ⟨-, -, -, -, -, -, -, -, -, -, -, -, -, -, -, -, hRhd, -, -⟩ := hRS'
    have hend : R.head = T.head := by rw [hRhd, hTh]
    have hrA : ∃ x, ({ LState.genesis H g0.shard 0 g0.nb0 g0.au with head := g0.prev } : LState).tree.root = H x := by
      obtain ⟨x, hx⟩ := (genesis_inv (H := H) g0.shard 0 g0.nb0 g0.au).2.2.2.2.2
      exact ⟨x, hx⟩
    have hrB : ∃ x, ({ LState.genesis H f0.shard 0 f0.nb0 f0.au with head := f0.prev } : LState).tree.root = H x := by
      obtain ⟨x, hx⟩ := (genesis_inv (H := H) f0.shard 0 f0.nb0 f0.au).2.2.2.2.2
      exact ⟨x, hx⟩
    have hok1 : ∀ x ∈ g0 :: rest, FrOK x := fun x hx => frOK_of_wf (hwf x hx)
    have hok2 : ∀ x ∈ f0 :: r1.take k, FrOK x := fun x hx => by
      apply hfok
      rcases List.mem_cons.mp hx with rfl | hx
      · exact List.mem_cons_self ..
      · exact List.mem_cons_of_mem _ (List.mem_of_mem_take hx)
    have hlt : rest.length = (r1.take k).length := by rw [hrl]; simp; omega
    rcases back (kf := khsOf (g0 :: rest)) (kg := khsOf (f0 :: r1)) hH rest (r1.take k) g0 f0 _ _ R T hlt hok1 hok2
      hrA hrB hRf' hT hend with ⟨hhd, hsh, hnb⟩ | hcol
    case inr => exact Or.inr hcol
    have hprev : g0.prev = f0.prev := hhd
    have hsh' : g0.shard = f0.shard := hsh
    have hnb' : g0.nb0 = f0.nb0 := hnb
    have hAB : ({ LState.genesis H g0.shard 0 g0.nb0 g0.au with head := g0.prev } : LState) =
        { ({ LState.genesis H f0.shard 0 f0.nb0 f0.au with head := f0.prev } : LState) with
          au := ({ LState.genesis H g0.shard 0 g0.nb0 g0.au with head := g0.prev } : LState).au } := by
      rw [hsh', hnb', hprev]
      rfl
    rcases fwd hH (F1 := g0 :: rest) (F2 := f0 :: r1) rest (r1.take k) [] [] [] (r1.drop k) g0 f0 _ _ R T hlt
      (by simp) (by simp) hok1 hok2 hAB hrB
      (fun x hx => by simp [LState.genesis] at hx) (fun f' hf' => by simp at hf') (fun f' hf' => by simp at hf')
      hRf' hT hend with hRT | hcol
    · left
      rw [← hRT]
      exact hRS
    · exact Or.inr hcol

end BlindLedger.Gate.Flat.StoreLog
