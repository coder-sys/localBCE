import BlindLedger.Gate.Flat.Model

/-! The history store's chunk format and its whole-state root.

    A chunk is an immutable sorted run of rows `(key bytes, entry)`, strictly rising by `(key hash, key bytes)`.  Rows
    are packed by bytes into 4 KB pages: each row is its length then its body, and a zero length ends the run (the
    rest of the last page is zero).  An entry is stored as `encEntry` is, except that its tail digest is one flag byte
    while it is still `zeroDigest` (no posting past `capN`).  The metadata holds the 8-byte key hash of every row (the
    key directory is rebuilt from these), the row data's length (so a read knows where the last row ends), then per
    page its mark, then per page its SHA3-512.  The mark names the first row that
    starts in the page: its key hash (the page's fence), its offset in the page, its row number, and whether the row
    before it has another key hash; a page no row starts in names the row running through it, with offset `pageSize`.
    The marks with offset below `pageSize` are exactly the page index a lookup reads through (`Store.marks_index`).
    A chunk's root is the hash of its metadata.  `decChunk` accepts only the canonical bytes of what it decodes, so a
    page or metadata byte that differs from what `encChunk` writes gives `none`.

    The whole-state root is a Merkle tree of fixed depth over chunk numbers: leaf `i` is chunk `i`'s root or empty.
    `Tree` keeps the non-empty nodes and updates one leaf with `depth` hashes.  `H` is SHA3-512 at runtime;
    statements take it as a parameter.  Proofs are in `Flat/ChunkTheorems.lean`. -/

namespace BlindLedger.Gate.Flat.Chunk

open BlindLedger.Gate.OnepIndex (leb unleb)
open Std (HashMap)

/-- A stored row: the key's bytes (set tag first) and the key's newest entry. -/
abbrev Row := Bytes × Entry

def pageSize : Nat := 4096

/-! ## Rows -/

/-- The tail digest: flag 0 while it is `zeroDigest`, else flag 1 and the 64 bytes. -/
def encTail (t : Bytes) : Bytes := if t = zeroDigest then [0] else 1 :: t

def decTail : Bytes → Option (Bytes × Bytes)
  | [] => none
  | f :: r => if f = 0 then some (zeroDigest, r) else if f = 1 then takeN digestBytes r else none

def encBody (w : Row) : Bytes :=
  leb w.1.length ++ w.1 ++ leb w.2.count ++ leb w.2.head.length ++ w.2.head.flatMap encPosting ++ encTail w.2.tail

def encRow (w : Row) : Bytes := leb (encBody w).length ++ encBody w

/-- A row body, all bytes used, its entry `Entry.Wf`. -/
def decBody (bs : Bytes) : Option Row := do
  let (kl, r) ← unleb bs
  let (k, r) ← takeN kl r
  let (c, r) ← unleb r
  let (n, r) ← unleb r
  let (ps, r) ← decPostings n r
  let (t, r) ← decTail r
  if r.isEmpty && n == min c capN && rising ps then pure (k, ⟨c, ps, t⟩) else none

/-- At most `fuel` rows, up to the zero length that ends the run. -/
def decRows : Nat → Bytes → Option (List Row)
  | 0, _ => none
  | f + 1, bs => do
    let (l, r) ← unleb bs
    if l = 0 then pure [] else do
      let (b, r) ← takeNFast l r
      let w ← decBody b
      let ws ← decRows f r
      pure (w :: ws)

def encData (ws : List Row) : Bytes := ws.flatMap encRow ++ leb 0

/-! ## Pages and metadata -/

/-- Cut into `pageSize` pages, the last one padded with zeros. -/
def pagesN : Nat → Bytes → List Bytes
  | 0, _ => []
  | f + 1, d =>
    if d.isEmpty then [] else (d.take pageSize ++ List.replicate (pageSize - d.length) 0) :: pagesN f (d.drop pageSize)

def pagesOf (d : Bytes) : List Bytes := pagesN d.length d

/-- Strict lexicographic order on bytes. -/
def bytesLt : Bytes → Bytes → Bool
  | [], _ :: _ => true
  | a :: as, b :: bs => a < b || (a == b && bytesLt as bs)
  | _, _ => false

def rowLt (kh : Bytes → UInt64) (a b : Bytes) : Bool := kh a < kh b || (kh a == kh b && bytesLt a b)

def sortedB (kh : Bytes → UInt64) : List Row → Bool
  | a :: b :: ws => rowLt kh a.1 b.1 && sortedB kh (b :: ws)
  | _ => true

/-- Where row `j` starts in the chunk data (the data's row bytes past the last row). -/
def off (ws : List Row) (j : Nat) : Nat := ((ws.take j).flatMap encRow).length

/-- Row `j`'s key hash, 0 past the rows. -/
def hashAt (kh : Bytes → UInt64) (ws : List Row) (j : Nat) : Nat := (ws[j]?.map fun w => (kh w.1).toNat).getD 0

/-- Row `j` begins the run of its key hash: it is the first row, or the row before it has another key hash. -/
def fresh (kh : Bytes → UInt64) (ws : List Row) (j : Nat) : Bool := j == 0 || hashAt kh ws (j - 1) != hashAt kh ws j

/-- The page index: the rows that are the first to start in their page. -/
def pidx (ws : List Row) : List Nat :=
  (List.range ws.length).filter fun j => j == 0 || off ws (j - 1) / pageSize < off ws j / pageSize

/-- Page `p`'s mark `(fence, offset, row, fresh)`: for the first row that starts in it, its key hash, where it
    starts in the page, its number and its `fresh` flag; for a page no row starts in, the key hash and number of the
    row running through it, offset `pageSize` and flag false. -/
def markAt (kh : Bytes → UInt64) (ws : List Row) (p : Nat) : Nat × Nat × Nat × Bool :=
  match (pidx ws).find? (off ws · / pageSize == p) with
  | some j => (hashAt kh ws j, off ws j % pageSize, j, fresh kh ws j)
  | none =>
    let j := ((List.range ws.length).filter (off ws · / pageSize < p)).length - 1
    (hashAt kh ws j, pageSize, j, false)

def pageMarks (kh : Bytes → UInt64) (ws : List Row) (n : Nat) : List (Nat × Nat × Nat × Bool) :=
  (List.range n).map (markAt kh ws)

def pageHash (H : Bytes → Bytes) (p : Bytes) : Bytes := H (domain "STORE/PAGE" ++ p)

/-- A chunk's metadata as a reader holds it: each row's key hash, the length of the row data (where the last row
    ends), each page's mark and each page's SHA3-512. -/
structure CMeta where
  khs : List Nat
  dlen : Nat
  marks : List (Nat × Nat × Nat × Bool)
  phs : List Bytes

def metaOf (H : Bytes → Bytes) (kh : Bytes → UInt64) (ws : List Row) (ps : List Bytes) : CMeta :=
  ⟨ws.map (fun w => (kh w.1).toNat), (ws.flatMap encRow).length, pageMarks kh ws ps.length, ps.map (pageHash H)⟩

def encMark (k : Nat × Nat × Nat × Bool) : Bytes := leb k.1 ++ leb k.2.1 ++ leb k.2.2.1 ++ [if k.2.2.2 then 1 else 0]

/-- Every field a reader uses is self-delimiting (`leb`, counted lists, length-prefixed hashes), so two metadata
    records with the same bytes are equal. -/
def encM (m : CMeta) : Bytes :=
  leb m.khs.length ++ m.khs.flatMap (natBE 8) ++ leb m.dlen ++ leb m.marks.length ++ m.marks.flatMap encMark ++
    leb m.phs.length ++ m.phs.flatMap fun p => leb p.length ++ p

def encMeta (H : Bytes → Bytes) (kh : Bytes → UInt64) (ws : List Row) (ps : List Bytes) : Bytes :=
  encM (metaOf H kh ws ps)

structure Chunk where
  pages : List Bytes
  mdata : Bytes
  deriving DecidableEq

def encChunk (H : Bytes → Bytes) (kh : Bytes → UInt64) (ws : List Row) : Chunk :=
  let ps := pagesOf (encData ws)
  ⟨ps, encMeta H kh ws ps⟩

/-- The rows of a chunk whose pages and metadata are exactly what `encChunk` writes for them (so every page matches
    its recorded SHA3-512), sorted; anything else is `none`. -/
def decChunk (H : Bytes → Bytes) (kh : Bytes → UInt64) (c : Chunk) : Option (List Row) := do
  let d := c.pages.flatten
  let ws ← decRows d.length d
  if sortedB kh ws && decide (encChunk H kh ws = c) then pure ws else none

def chunkRoot (H : Bytes → Bytes) (c : Chunk) : Bytes := H (domain "STORE/CHUNK" ++ c.mdata)

/-- The root of the chunk whose metadata is `m`. -/
def metaRoot (H : Bytes → Bytes) (m : CMeta) : Bytes := H (domain "STORE/CHUNK" ++ encM m)

/-! ## Metadata v2: the metadata file -/

/-- Row `i` of the chunk installed at number `c` with install number `seq` is dead.  A row dead at birth has a
    tombstone naming its own chunk; a tombstone whose `seq` is not that of the chunk now at `c` is stale. -/
structure Tomb where
  c : Nat
  seq : Nat
  i : Nat
  deriving DecidableEq, Repr

def encTomb (t : Tomb) : Bytes := leb t.c ++ leb t.seq ++ leb t.i

/-- A chunk's metadata file: its `encM` bytes (counted), its install number, then its tombstones (counted).  The
    chunk root of the whole-state tree is the hash of these bytes. -/
def encMeta2 (m : Bytes) (seq : Nat) (ts : List Tomb) : Bytes :=
  leb m.length ++ m ++ leb seq ++ leb ts.length ++ ts.flatMap encTomb

def decTombs : Nat → Bytes → Option (List Tomb × Bytes)
  | 0, r => some ([], r)
  | n + 1, r => do
    let (c, r) ← unleb r
    let (s, r) ← unleb r
    let (i, r) ← unleb r
    let (ts, r) ← decTombs n r
    pure (⟨c, s, i⟩ :: ts, r)

/-- `encMeta2`'s fields, all bytes used. -/
def decMeta2 (bs : Bytes) : Option (Bytes × Nat × List Tomb) := do
  let (ml, r) ← unleb bs
  let (m, r) ← takeN ml r
  let (seq, r) ← unleb r
  let (n, r) ← unleb r
  let (ts, r) ← decTombs n r
  if r.isEmpty then pure (m, seq, ts) else none

/-- Exactly `k` rows, from bytes that start at a row (`Store.rows_mid`). -/
def decRowsN : Nat → Bytes → Option (List Row)
  | 0, _ => some []
  | k + 1, bs => do
    let (l, r) ← unleb bs
    let (b, r) ← takeNFast l r
    let w ← decBody b
    let ws ← decRowsN k r
    pure (w :: ws)

/-! ## The whole-state root -/

/-- Chunk numbers below `2 ^ depth`. -/
def depth : Nat := 18

def leafH (H : Bytes → Bytes) : Option Bytes → Bytes
  | none => H (domain "STORE/LEAF" ++ [0])
  | some r => H (domain "STORE/LEAF" ++ 1 :: r)

def nodeH (H : Bytes → Bytes) (a b : Bytes) : Bytes := H (domain "STORE/NODE" ++ a ++ b)

/-- Node `i` of level `l` over the chunk roots `m` (level 0 = leaves). -/
def nodeSpec (H : Bytes → Bytes) (m : Nat → Option Bytes) : Nat → Nat → Bytes
  | 0, i => leafH H (m i)
  | l + 1, i => nodeH H (nodeSpec H m l (2 * i)) (nodeSpec H m l (2 * i + 1))

def rootB (H : Bytes → Bytes) (m : Nat → Option Bytes) : Bytes := nodeSpec H m depth 0

/-- The node of an empty subtree of level `l`. -/
def emptyAt (H : Bytes → Bytes) : Nat → Bytes
  | 0 => leafH H none
  | l + 1 => let e := emptyAt H l; nodeH H e e

structure Tree where
  nodes : HashMap (Nat × Nat) Bytes
  emp : Array Bytes

def Tree.empty (H : Bytes → Bytes) : Tree := ⟨∅, ((List.range (depth + 1)).map (emptyAt H)).toArray⟩

def Tree.get (t : Tree) (l i : Nat) : Bytes := t.nodes.getD (l, i) (t.emp.getD l [])

def Tree.put (t : Tree) (l i : Nat) (x : Bytes) : Tree := { t with nodes := t.nodes.insert (l, i) x }

/-- Recompute the `k` nodes above node `j` of level `l`. -/
def Tree.up (H : Bytes → Bytes) (t : Tree) : Nat → Nat → Nat → Tree
  | 0, _, _ => t
  | k + 1, l, j =>
    let p := j / 2
    Tree.up H (t.put (l + 1) p (nodeH H (t.get l (2 * p)) (t.get l (2 * p + 1)))) k (l + 1) p

/-- Leaf `i` becomes `v` (a chunk root, or `none` when the chunk leaves the layout); `none` past the leaves the root
    covers. -/
def Tree.set (H : Bytes → Bytes) (t : Tree) (i : Nat) (v : Option Bytes) : Option Tree :=
  if i < 2 ^ depth then some (Tree.up H (t.put 0 i (leafH H v)) depth 0 i) else none

def Tree.root (t : Tree) : Bytes := t.get depth 0

def upd (m : Nat → Option Bytes) (i : Nat) (v : Option Bytes) : Nat → Option Bytes := fun j => if j = i then v else m j

/-! ## Reading metadata back -/

def decKhs : Nat → Bytes → Option (List Nat × Bytes)
  | 0, r => some ([], r)
  | n + 1, r => do
    let (b, r) ← takeNFast 8 r
    let (ks, r) ← decKhs n r
    pure (beNat b :: ks, r)

def decMarks : Nat → Bytes → Option (List (Nat × Nat × Nat × Bool) × Bytes)
  | 0, r => some ([], r)
  | n + 1, r => do
    let (f, r) ← unleb r
    let (o, r) ← unleb r
    let (j, r) ← unleb r
    let (x, r) ← takeNFast 1 r
    let fr ← if x = [0] then some false else if x = [1] then some true else none
    let (ms, r) ← decMarks n r
    pure ((f, o, j, fr) :: ms, r)

/-- A length-prefixed byte string. -/
def encBs (b : Bytes) : Bytes := leb b.length ++ b

def decBs (r : Bytes) : Option (Bytes × Bytes) := do
  let (n, r) ← unleb r
  takeNFast n r

def decBss : Nat → Bytes → Option (List Bytes × Bytes)
  | 0, r => some ([], r)
  | n + 1, r => do
    let (b, r) ← decBs r
    let (bs, r) ← decBss n r
    pure (b :: bs, r)

/-- `encM`'s fields, all bytes used. -/
def decM (bs : Bytes) : Option CMeta := do
  let (n, r) ← unleb bs
  let (khs, r) ← decKhs n r
  let (dlen, r) ← unleb r
  let (nm, r) ← unleb r
  let (marks, r) ← decMarks nm r
  let (np, r) ← unleb r
  let (phs, r) ← decBss np r
  if r.isEmpty then pure ⟨khs, dlen, marks, phs⟩ else none

/-! ## The commit record and the chunk store's chain step

    The chain head after a batch on the chunk store hashes the head before it, the batch's digest and the state root
    after it (tag 0x02), so the signed head binds the store.  The state root hashes the shard, the chunk tree's root,
    the two set heads and the next install number.  The commit record holds what load needs to check all of this against the
    signed head: every field below is bound by it (at genesis, through `chainStart`). -/

/-- The digest of one batch: the shard's authority record after it (`Worker.encAuth`: key-set pin, ratchet, grant floor)
    and the rows it appends, so the host, which cannot open the state root, still checks the record from the head. -/
def batchDigest (H : Bytes → Bytes) (au : Bytes) (d : List Rules.Line × List Rules.Line) : Bytes :=
  H (domain "CHAIN" ++ [0x03] ++ leb au.length ++ au ++ encDelta d)

/-- The chain step of the chunk store: head before, batch digest, state root after. -/
def chainStepR (H : Bytes → Bytes) (D bd rb : Bytes) : Bytes := H (domain "CHAIN" ++ [0x02] ++ D ++ bd ++ rb)

def encHead (h : Head) : Bytes := leb h.asOf ++ leb h.count ++ leb h.n

def decHead (r : Bytes) : Option (Head × Bytes) := do
  let (a, r) ← unleb r
  let (c, r) ← unleb r
  let (n, r) ← unleb r
  pure (⟨a, c, n⟩, r)

end BlindLedger.Gate.Flat.Chunk
