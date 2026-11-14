import BlindLedger.Gate.Flat.Chunk

/-! The history store's layout: which chunks are installed, the key directory that says where a key may be, the dead
    bits of superseded rows, the open window of entries changed since the last seal, and the sealed window waiting to
    install.  Both sets share one store: a key's stored bytes start with its set tag (`skey`).

    The directory is a cuckoo filter that also stores where a key is: 2 candidate buckets of 4 slots per key hash, and
    a stash.  A slot is a 14-bit fingerprint (never 0, so 0 marks an empty slot) and an 18-bit chunk number.  The
    first bucket comes from the key hash and the second from the first and the fingerprint (`alt`), so a slot can
    move to its other bucket without its key, and keys of one fingerprint share both buckets or neither.  An insert
    takes an empty candidate position, else moves slots on to their other buckets a bounded number of times, else puts
    the last moved slot in the stash with its pair's label; with the stash at `stashCap` it refuses `full`, and
    install grows the directory once (`regrow`) before it refuses.  Growth cannot always help: keys of one hash share
    their 8 positions.  A slot is never dropped silently (a dropped slot would be a missed duplicate): every step
    adds or takes exactly the slots it names (`StoreTheorems`).  The directory holds exactly one slot for each live
    row of each installed chunk, and no other.  Its layout is part of the state: the store log's images hold it and the state root binds
    them (`StoreLog`), so growth runs in ascending chunk order.  Any such directory gives the same lookups, whatever
    its false positives.

    A row is live unless its dead bit is set.  A key has at most one live row, none while either window holds the key,
    and that row holds the key's newest entry, so a lookup takes
    the window, then the sealed window, then any live row the directory leads to.  Applying a batch sets the dead bit
    of every live row of each key it changes and takes that row's slot.  A sealed window installs as one chunk sorted
    strictly by key hash; its rows whose key the open window already holds are dead at birth, and every other row gets
    a slot.  A reclaimed chunk's live rows re-enter the window and its dead rows go, so reclaim drops only superseded
    versions, never a key.

    `rows c` is chunk `c` decoded (`layout`).  Statements are in `Flat/StoreTheorems.lean`. -/

namespace BlindLedger.Gate.Flat.Store

open Chunk
open BlindLedger.Gate.Rules
open Std (HashMap HashSet)

/-- A key's stored bytes: its set tag (0 released, 1 unresolved), then the key. -/
def skey (u : Bool) (k : Key) : Bytes := (if u then 1 else 0) :: encKey k

/-- The state's entry of `k` in the set `u` names. -/
def sget (s : St) (u : Bool) (k : Key) : Entry := if u then s.unr.get k else s.rel.get k

/-! ## Key directory -/

/-- Chunk number bits of a slot (= the root's `depth`). -/
def cBits : Nat := 18

/-- The fingerprint, 1 to `2^14 - 1`. -/
def fpOf (h : UInt64) : Nat := 1 + h.toNat / 2 ^ 50 % (2 ^ 14 - 1)

def slot (fp c : Nat) : UInt32 := UInt32.ofNat (fp * 2 ^ cBits + c)

/-- A slot's fingerprint. -/
def fpv (v : UInt32) : Nat := v.toNat / 2 ^ cBits

/-- The other bucket of a slot of fingerprint `f` in bucket `b`, from the two alone (a slot holds no key hash).  For
    `b < nb` it undoes itself, so keys of one fingerprint share both buckets or neither. -/
def alt (nb f b : Nat) : Nat := (f * 2654435761 + (nb - b)) % nb

/-- A bucket pair's label: its smaller bucket. -/
def cls (nb f b : Nat) : Nat := min b (alt nb f b)

/-- The 8 positions of fingerprint `f` with first bucket `b`: 4 in each bucket of the pair. -/
def idxs (nb f b : Nat) : List Nat := (List.range 4).map (4 * b + ·) ++ (List.range 4).map (4 * alt nb f b + ·)

/-- Why an insert or an install refuses: nothing is sealed, every chunk number is in use, the directory has no
    room (every candidate position and the stash are full), a batch kills a row of a chunk that is not installed, or
    its log frame is one the format cannot hold (`StoreLog.Frame.Wf`). -/
inductive Refusal | unsealed | noNumber | full | kill | frame
  deriving DecidableEq, Repr

/-- The stash holds at most this many slots (every probe scans it). -/
def stashCap : Nat := 8

/-- Kicks one insert may make before its last moved slot goes to the stash. -/
def maxKicks : Nat := 32

/-- `nb` buckets of 4 positions, and a stash of slots, each with its bucket pair's label. -/
structure Dir where
  nb : Nat
  t : Array UInt32
  stash : List (UInt32 × Nat)

/-- The shape every directory step keeps. -/
def Dir.Ok (d : Dir) : Prop := 0 < d.nb ∧ d.t.size = 4 * d.nb ∧ d.stash.length ≤ stashCap

def Dir.empty (nb : Nat) : Dir := ⟨nb, Array.replicate (4 * nb) 0, []⟩

/-- The slot at position `j` with its bucket pair's label; `none` when empty. -/
def Dir.at (d : Dir) (j : Nat) : Option (UInt32 × Nat) :=
  match d.t[j]? with
  | some v => if v = 0 then none else some (v, cls d.nb (fpv v) (j / 4))
  | none => none

/-- Every slot the directory holds, labelled. -/
def Dir.items (d : Dir) : List (UInt32 × Nat) := (List.range d.t.size).filterMap d.at ++ d.stash

/-- Key hash `h`'s slot for chunk `c` with its bucket pair's label, among `nb` buckets. -/
def Dir.item (nb : Nat) (h : UInt64) (c : Nat) : UInt32 × Nat := (slot (fpOf h) c, cls nb (fpOf h) (h.toNat % nb))

/-- The directory holds a slot for chunk `c` under key hash `h`'s bucket pair. -/
def Dir.Has (d : Dir) (h : UInt64) (c : Nat) : Prop := Dir.item d.nb h c ∈ d.items

/-- Chunks that may hold a key of hash `h` (any false positives). -/
def Dir.cands (d : Dir) (h : UInt64) : List Nat :=
  let f := fpOf h
  let b := h.toNat % d.nb
  ((idxs d.nb f b).filterMap (d.t[·]?) ++
      d.stash.filterMap fun x => if x.2 = cls d.nb f b then some x.1 else none).filterMap fun v =>
    if fpv v = f then some (v.toNat % 2 ^ cBits) else none

/-- Slot `v` into the pair of bucket `b`: an empty position if one is free; else it takes a position of the other
    bucket and the slot there moves on to its own other bucket, at most `n` times; the last slot moved goes to the
    stash, refused `full` when the stash is at `stashCap`. -/
def Dir.put (d : Dir) (v : UInt32) (b : Nat) (n : Nat) : Except Refusal Dir :=
  match (idxs d.nb (fpv v) b).find? (d.t[·]? = some 0) with
  | some j => .ok { d with t := d.t.set! j v }
  | none =>
    match n with
    | 0 =>
      if d.stash.length < stashCap then .ok { d with stash := (v, cls d.nb (fpv v) b) :: d.stash }
      else .error .full
    | n + 1 =>
      let b' := alt d.nb (fpv v) b
      let p := 4 * b' + n % 4
      let w := (d.t[p]?).getD 0
      Dir.put { d with t := d.t.set! p v } w b' n

/-- A slot for chunk `c` under key hash `h`. -/
def Dir.insert (d : Dir) (h : UInt64) (c : Nat) : Except Refusal Dir :=
  d.put (slot (fpOf h) c) (h.toNat % d.nb) maxKicks

/-- One slot `v` of the pair of bucket `b` leaves (a row is superseded); nothing changes when there is none. -/
def Dir.erase (d : Dir) (v : UInt32) (b : Nat) : Dir :=
  match (idxs d.nb (fpv v) b).find? (d.t[·]? = some v) with
  | some j => { d with t := d.t.set! j 0 }
  | none => { d with stash := d.stash.erase (v, cls d.nb (fpv v) b) }

/-- Chunk `c`'s slots leave (its whole chunk is reclaimed). -/
def Dir.drop (d : Dir) (c : Nat) : Dir :=
  { d with t := d.t.map (fun v => if v ≠ 0 ∧ v.toNat % 2 ^ cBits = c then 0 else v),
           stash := d.stash.filter (·.1.toNat % 2 ^ cBits ≠ c) }

/-- Load and growth: a directory of `nb` buckets holding every key hash of every listed chunk. -/
def Dir.rebuild (nb : Nat) (cs : List (Nat × List UInt64)) : Except Refusal Dir :=
  cs.foldlM (fun d ch => ch.2.foldlM (fun d h => d.insert h ch.1) d) (Dir.empty nb)

/-! ## Layout -/

structure Fs where
  hr : Head
  hu : Head
  dir : Dir
  inst : HashSet Nat
  dead : HashMap Nat (HashSet Nat)
  win : HashMap Bytes Entry
  sealing : Option (HashMap Bytes Entry)

/-- The rows of every chunk file (`[]` where none decodes). -/
def layout (H : Bytes → Bytes) (kh : Bytes → UInt64) (files : Nat → Chunk) (c : Nat) : List Row :=
  (decChunk H kh (files c)).getD []

/-- Row `i` of chunk `c` is dead (its entry superseded). -/
def isDead (d : HashMap Nat (HashSet Nat)) (c i : Nat) : Bool := ((d.get? c).map (·.contains i)).getD false

def kill (d : HashMap Nat (HashSet Nat)) (c i : Nat) : HashMap Nat (HashSet Nat) :=
  d.insert c (((d.get? c).getD ∅).insert i)

/-- Rows with their indexes from `i`. -/
def ixs : Nat → List Row → List (Nat × Row)
  | _, [] => []
  | i, w :: ws => (i, w) :: ixs (i + 1) ws

/-- Row `iw` of chunk `c` gives its key hash when it is live. -/
def liveHash (kh : Bytes → UInt64) (dead : HashMap Nat (HashSet Nat)) (c : Nat) (iw : Nat × Row) : Option UInt64 :=
  if isDead dead c iw.1 then none else some (kh iw.2.1)

/-- The key hashes of the live rows `ws` of chunk `c`. -/
def liveHashes (kh : Bytes → UInt64) (dead : HashMap Nat (HashSet Nat)) (c : Nat) (ws : List Row) : List UInt64 :=
  (ixs 0 ws).filterMap (liveHash kh dead c)

/-- The live rows of key bytes `kb` in the installed chunks the directory names: `(chunk, index, entry)`. -/
def hits (kh : Bytes → UInt64) (fs : Fs) (rows : Nat → List Row) (kb : Bytes) : List (Nat × Nat × Entry) :=
  (fs.dir.cands (kh kb)).flatMap fun c =>
    if fs.inst.contains c then
      (ixs 0 (rows c)).filterMap fun iw =>
        if iw.2.1 = kb ∧ isDead fs.dead c iw.1 = false then some (c, iw.1, iw.2.2) else none
    else []

def sealGet (fs : Fs) (kb : Bytes) : Option Entry := fs.sealing.bind (·.get? kb)

def lookup (kh : Bytes → UInt64) (fs : Fs) (rows : Nat → List Row) (kb : Bytes) : Entry :=
  match fs.win.get? kb with
  | some e => e
  | none =>
    match sealGet fs kb with
    | some e => e
    | none =>
      match hits kh fs rows kb with
      | (_, _, e) :: _ => e
      | [] => Entry.empty

/-- The state the store holds.  It keeps no core counts (`SetIdx.core` is 0): it caps per key. -/
def view (kh : Bytes → UInt64) (fs : Fs) (rows : Nat → List Row) : St :=
  ⟨⟨fs.hr, fun k => lookup kh fs rows (skey false k), fun _ => 0⟩,
    ⟨fs.hu, fun k => lookup kh fs rows (skey true k), fun _ => 0⟩⟩

/-! ## Steps -/

/-- The entries a batch's result changes: each key of each appended row, with its new entry. -/
def changed (s' : St) (r : List Decision × List Line × List Line) : List (Bytes × Entry) :=
  (r.2.1.flatMap keys).map (fun k => (skey false k, s'.rel.get k)) ++
    (r.2.2.flatMap keys).map (fun k => (skey true k, s'.unr.get k))

/-- Row `x` (chunk, index, entry) of a key of hash `h` dies and its slot leaves the directory; nothing changes when
    the row is dead already (the directory may name a chunk twice, and a batch may change a key twice). -/
def killRow (h : UInt64) (a : HashMap Nat (HashSet Nat) × Dir) (x : Nat × Nat × Entry) :
    HashMap Nat (HashSet Nat) × Dir :=
  if isDead a.1 x.1 x.2.1 then a else (kill a.1 x.1 x.2.1, a.2.erase (slot (fpOf h) x.1) (h.toNat % a.2.nb))

/-- A batch's result: new heads, the changed entries into the window, and every live row of a changed key dead,
    its slot gone. -/
def apply (H : Bytes → Bytes) (kh : Bytes → UInt64) (fs : Fs) (rows : Nat → List Row)
    (r : List Decision × List Line × List Line) : Fs :=
  let s' := (view kh fs rows).apply H r
  let ch := changed s' r
  let kd := ch.foldl (fun a ke => (hits kh fs rows ke.1).foldl (killRow (kh ke.1)) a) (fs.dead, fs.dir)
  { fs with hr := s'.rel.head, hu := s'.unr.head,
            win := ch.foldl (fun m ke => m.insert ke.1 ke.2) fs.win, dead := kd.1, dir := kd.2 }

/-- The open window becomes the sealed one; a seal never starts before the previous one has installed. -/
def sealWindow (fs : Fs) : Option Fs :=
  match fs.sealing with
  | none => some { fs with sealing := some fs.win, win := ∅ }
  | some _ => none

/-- Rows strictly rising by `rowLt` (the keys of a window are distinct). -/
def sortRows (kh : Bytes → UInt64) (ws : List Row) : List Row := ws.mergeSort fun a b => !rowLt kh b.1 a.1

/-- The smallest chunk number from `c` on, among `n`, that is not installed. -/
def freeNum (inst : HashSet Nat) : Nat → Nat → Option Nat
  | 0, _ => none
  | n + 1, c => if inst.contains c then freeNum inst n (c + 1) else some c

/-- The indexes of the rows whose key the open window holds: they are superseded at birth. -/
def bornDead (win : HashMap Bytes Entry) (ws : List Row) : HashSet Nat :=
  (ixs 0 ws).foldl (fun s iw => if win.contains iw.2.1 then s.insert iw.1 else s) ∅

/-- Chunk `c` holds the sorted rows `ws` of the sealed window: the rows whose key the open window holds born dead,
    and a slot for each other row.  Refused `full` when the directory has no room. -/
def place (kh : Bytes → UInt64) (fs : Fs) (c : Nat) (ws : List Row) : Except Refusal Fs :=
  let dead := fs.dead.insert c (bornDead fs.win ws)
  ((liveHashes kh dead c ws).foldlM (fun (d : Dir) h => d.insert h c) fs.dir).map fun d =>
    { fs with dir := d, inst := fs.inst.insert c, sealing := none, dead := dead }

/-- The directory rebuilt with twice the buckets (plus one, so an empty one grows) from the key hashes of the
    installed chunks' live rows. -/
def regrow (kh : Bytes → UInt64) (fs : Fs) (rows : Nat → List Row) : Except Refusal Fs :=
  (Dir.rebuild (2 * fs.dir.nb + 1) (fs.inst.toList.map fun c => (c, liveHashes kh fs.dead c (rows c)))).map
    fun d => { fs with dir := d }

/-- Load: the heads, installed chunks and dead bits a commit point keeps (its windows are empty), with the directory of
    `nb` buckets rebuilt as growth rebuilds it. -/
def load (kh : Bytes → UInt64) (nb : Nat) (hr hu : Head) (inst : HashSet Nat) (dead : HashMap Nat (HashSet Nat))
    (rows : Nat → List Row) : Except Refusal Fs :=
  (Dir.rebuild nb (inst.toList.map fun c => (c, liveHashes kh dead c (rows c)))).map
    fun d => ⟨hr, hu, d, inst, dead, ∅, none⟩

/-- The sealed window installs as chunk `c`, the smallest free number: its rows sorted strictly by key hash, the
    rows whose key the open window holds born dead, and a slot for each other row.  When the directory has no room,
    it grows once and the chunk is placed in the grown one; `full` if that has no room either.  The host writes the
    returned chunk at `c`. -/
def install (H : Bytes → Bytes) (kh : Bytes → UInt64) (fs : Fs) (rows : Nat → List Row) :
    Except Refusal (Fs × Nat × Chunk) :=
  match fs.sealing, freeNum fs.inst (2 ^ cBits) 0 with
  | none, _ => .error .unsealed
  | some _, none => .error .noNumber
  | some m, some c =>
    let ws := sortRows kh m.toList
    match place kh fs c ws with
    | .ok p => .ok (p, c, encChunk H kh ws)
    | .error _ =>
      match regrow kh fs rows with
      | .ok g => (place kh g c ws).map (·, c, encChunk H kh ws)
      | .error e => .error e

/-- Installed chunk `c` leaves: its live rows re-enter the window, its dead rows and slots go.  `none` for a chunk
    that is not installed. -/
def reclaim (fs : Fs) (rows : Nat → List Row) (c : Nat) : Option Fs :=
  if fs.inst.contains c then
    some { fs with win := (ixs 0 (rows c)).foldl (fun m iw => if isDead fs.dead c iw.1 then m else m.insert iw.2.1 iw.2.2)
                            fs.win,
                   inst := fs.inst.erase c, dir := fs.dir.drop c, dead := fs.dead.erase c }
  else none

/-! ## Tombstones: the dead bits on disk

    The metadata files of the installed chunks, as a list of (number, install number, tombstones), and the
    tombstones of rows killed since the last install, which the next installed chunk's file holds.  Load sets the
    dead bits from the files alone (`deadOf`, with nothing pending); `StoreTombs` proves they are `fs.dead`. -/

abbrev Book := List (Nat × Nat × List Tomb)

/-- The tombstone names the chunk now at its number. -/
def current (L : Book) (t : Tomb) : Bool := L.any fun x => x.1 == t.c && x.2.1 == t.seq

/-- The dead bits the current tombstones of the files `L` and of `pend` set. -/
def deadOf (L : Book) (pend : List Tomb) : HashMap Nat (HashSet Nat) :=
  (L.flatMap (·.2.2) ++ pend).foldl (fun d t => if current L t then kill d t.c t.i else d) ∅

/-- The install number of the chunk at `c` (0 when none is). -/
def seqOf (L : Book) (c : Nat) : Nat := ((L.find? (·.1 == c)).map (·.2.1)).getD 0

/-- The tombstones of the rows `apply` kills: the live rows of every changed key, read before the batch. -/
def applyTombs (kh : Bytes → UInt64) (fs : Fs) (rows : Nat → List Row) (L : Book) (ch : List (Bytes × Entry)) :
    List Tomb :=
  ch.flatMap fun ke => (hits kh fs rows ke.1).map fun x => ⟨x.1, seqOf L x.1, x.2.1⟩

/-- The file of chunk `c` placed with install number `n`: the pending tombstones and one for each row dead at birth. -/
def placeTombs (win : HashMap Bytes Entry) (c n : Nat) (ws : List Row) (pend : List Tomb) : List Tomb :=
  pend ++ (ixs 0 ws).filterMap fun iw => if win.contains iw.2.1 then some ⟨c, n, iw.1⟩ else none

/-- Reclaiming chunk `c` removes its file: its tombstones that still name a current chunk become pending. -/
def reclaimBook (L : Book) (pend : List Tomb) (c : Nat) : Book × List Tomb :=
  let L' := L.filter (·.1 != c)
  (L', pend ++ ((L.filter (·.1 == c)).flatMap (·.2.2)).filter (current L'))

/-- The files and pending tombstones match the store: one file per installed chunk, install numbers and tombstone
    numbers below `nx`, and the dead bits are exactly those the current tombstones set. -/
def BInv (fs : Fs) (L : Book) (pend : List Tomb) (nx : Nat) : Prop :=
  (∀ c, fs.inst.contains c = true ↔ ∃ x ∈ L, x.1 = c) ∧ (L.map (·.1)).Nodup ∧
  (∀ x ∈ L, x.2.1 < nx) ∧ (∀ t ∈ L.flatMap (·.2.2) ++ pend, t.seq < nx) ∧
  ∀ c i, isDead fs.dead c i = isDead (deadOf L pend) c i

/-! ## The invariant -/

/-- Row `i` of installed chunk `c` holds `kb`'s entry `e` and is not dead. -/
def Live (fs : Fs) (rows : Nat → List Row) (c i : Nat) (kb : Bytes) (e : Entry) : Prop :=
  fs.inst.contains c = true ∧ (rows c)[i]? = some (kb, e) ∧ isDead fs.dead c i = false

/-- Where key `k` of set `u` lives, `n` its state entry: the window holds `n`; else the sealed window does; else a
    live row does, or `n` is empty; every live row of the key holds `n`; and the key has at most one live row in the
    installed chunks and the two windows together: a live row is the only one, and neither window holds the key. -/
def KeyInv (fs : Fs) (rows : Nat → List Row) (kb : Bytes) (n : Entry) : Prop :=
  (∀ e, fs.win.get? kb = some e → e = n) ∧
  (fs.win.get? kb = none → ∀ e, sealGet fs kb = some e → e = n) ∧
  (fs.win.get? kb = none → sealGet fs kb = none → n = Entry.empty ∨ ∃ c i, Live fs rows c i kb n) ∧
  (∀ c i e, Live fs rows c i kb e → e = n) ∧
  (∀ c i e, Live fs rows c i kb e → fs.win.get? kb = none ∧ sealGet fs kb = none ∧
    ∀ c' i' e', Live fs rows c' i' kb e' → c' = c ∧ i' = i)

/-- The labelled slots the live rows of the installed chunks need, among `nb` buckets: one per live row. -/
def liveItems (kh : Bytes → UInt64) (inst : HashSet Nat) (dead : HashMap Nat (HashSet Nat)) (nb : Nat)
    (rows : Nat → List Row) : List (UInt32 × Nat) :=
  inst.toList.flatMap fun c => (liveHashes kh dead c (rows c)).map (Dir.item nb · c)

/-- The store holds `s`: heads equal; every installed chunk decodes and its number fits a slot; the entries of its
    rows are `Entry.Wf`; dead bits name installed chunks; the entries of both windows are `Entry.Wf` (so a sealed
    window encodes to a chunk that decodes); each key as `KeyInv`; for every (slot, bucket pair) the directory holds
    as many slots as there are live installed rows that need it, and it keeps its shape. -/
def FInv (H : Bytes → Bytes) (kh : Bytes → UInt64) (fs : Fs) (files : Nat → Chunk) (s : St) : Prop :=
  fs.hr = s.rel.head ∧ fs.hu = s.unr.head ∧
  (∀ c, fs.inst.contains c = true → c < 2 ^ cBits ∧ (decChunk H kh (files c)).isSome) ∧
  (∀ (c i : Nat) (w : Row), fs.inst.contains c = true → (layout H kh files c)[i]? = some w → w.2.Wf) ∧
  (∀ (c i : Nat), isDead fs.dead c i = true → fs.inst.contains c = true) ∧
  (∀ kb e, fs.win.get? kb = some e ∨ sealGet fs kb = some e → e.Wf) ∧
  (∀ u k, KeyInv fs (layout H kh files) (skey u k) (sget s u k)) ∧
  (∀ x, fs.dir.items.count x = (liveItems kh fs.inst fs.dead fs.dir.nb (layout H kh files)).count x) ∧ fs.dir.Ok

end BlindLedger.Gate.Flat.Store
