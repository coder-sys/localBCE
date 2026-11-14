import BlindLedger.Gate.Engine3.Sha3Range
import BlindLedger.Gate.Engine3.FastDir

/-! Rows, blocks, pages and chunk files of conformance/ENGINE_V3.md section 3 as running code.

    A chunk is its sorted entries (`Ents`, the model's `files c`) written row after row.  A row is 256 bytes, a slot is
    the entry's sort hash and a row (264 bytes), a block is 4 slots (1,056), a page is a 504-byte header and 7 blocks
    (7,896).  The header holds, block after block, the block's hash (SHA3-512, 64 bytes) and fence (8 bytes).

    The file `c<number>` is the pages, the metadata, and the metadata's length as a `u32`.  The metadata lists, per
    entry, its directory hash and the slot number of its first row, grouped by directory segment; the dead bits and the
    entry's tombstone are named by that slot number, which is one to one with the entry's place in the chunk.

    `decodeChunk (encodeChunk ents)` is `ents` for well-formed entries (`decode_encode`, stated, not yet proved). -/

namespace BlindLedger.Gate.Engine3

open BlindLedger.Gate.Rules BlindLedger.Gate.Flat BlindLedger.Semantic

/-! ## Numbers and rows -/

/-- `v` as `w` bytes, little endian (its low `w` bytes). -/
def putN (b : ByteArray) (v : Nat) : Nat → ByteArray
  | 0 => b
  | w + 1 => putN (b.push (UInt8.ofNat v)) (v >>> 8) w

def put64 (b : ByteArray) (v : UInt64) : ByteArray :=
  b.push v.toUInt8 |>.push (v >>> 8).toUInt8 |>.push (v >>> 16).toUInt8 |>.push (v >>> 24).toUInt8
    |>.push (v >>> 32).toUInt8 |>.push (v >>> 40).toUInt8 |>.push (v >>> 48).toUInt8 |>.push (v >>> 56).toUInt8

/-- The `w` bytes at `o`, little endian. -/
def getN (b : ByteArray) (o : Nat) : Nat → Nat
  | 0 => 0
  | w + 1 => b[o]!.toNat + 256 * getN b (o + 1) w

def setN (b : ByteArray) (o v : Nat) : Nat → ByteArray
  | 0 => b
  | w + 1 => setN (b.set! o (UInt8.ofNat v)) (o + 1) (v >>> 8) w

@[inline] def st32 (b : ByteArray) (o v : Nat) : ByteArray :=
  b.set! o v.toUInt8 |>.set! (o + 1) (v >>> 8).toUInt8 |>.set! (o + 2) (v >>> 16).toUInt8 |>.set! (o + 3) (v >>> 24).toUInt8

/-- `b` with `v` at byte `o`, little endian. -/
@[inline] def st64 (b : ByteArray) (o : Nat) (v : UInt64) : ByteArray :=
  st32 (st32 b o (v &&& 0xFFFFFFFF).toNat) (o + 4) (v >>> 32).toNat

/-- The low 32 bytes of `v`, as four words (one big-number step each, not 32). -/
def put256 (b : ByteArray) (v : Nat) : ByteArray :=
  put64 (put64 (put64 (put64 b (UInt64.ofNat v)) (UInt64.ofNat (v >>> 64))) (UInt64.ofNat (v >>> 128))) (UInt64.ofNat (v >>> 192))

/-- `2^256` plus the 32 bytes at `o`: an `n33` number. -/
def get256 (b : ByteArray) (o : Nat) : Nat :=
  2 ^ 256 + (ld64 b o).toNat + ((ld64 b (o + 8)).toNat <<< 64) + ((ld64 b (o + 16)).toNat <<< 128) + ((ld64 b (o + 24)).toNat <<< 192)

def zeroBlock (n : Nat) : ByteArray := ByteArray.mk (Array.replicate n 0)

def slotLen : Nat := 264
def slotsBlock : Nat := 4
def blockLen : Nat := slotsBlock * slotLen
/-- Width of a block or page hash (SHA3-512, `hb` of conformance/ENGINE_V3.md §1), and of a header entry: the hash
    and an 8-byte fence. -/
def hbLen : Nat := 64
def hdrEnt : Nat := hbLen + 8
def blocksPage : Nat := 7
def hdrLen : Nat := blocksPage * hdrEnt
def pageLen : Nat := hdrLen + blocksPage * blockLen
def slotsPage : Nat := slotsBlock * blocksPage
def noFence : UInt64 := 0xFFFFFFFFFFFFFFFF

/-- A line at store widths, 245 bytes (`lineBytes2`). -/
def putLine (b : ByteArray) (l : Line) : ByteArray :=
  let b := putN b l.id idW
  let b := putN b l.pay payW
  let b := b.push l.flow.tag.toUInt8
  let b := put256 b l.member
  let b := putN b l.payee provW
  let b := putN b l.rendering provW
  let b := putN b l.date 4
  let b := putN b l.proc procW
  let b := putN b l.units 4
  putN b l.cents 8

def getLine (b : ByteArray) (o : Nat) : Option Line :=
  (flowOf (getN b (o + 123) 1)).map fun fl =>
    ⟨getN b o idW, getN b (o + 51) payW, fl, get256 b (o + 124), getN b (o + 156) provW, getN b (o + 177) provW,
     getN b (o + 198) 4, getN b (o + 202) procW, getN b (o + 233) 4, getN b (o + 237) 8⟩

def flagFirst : UInt8 := 16
def flagTail : UInt8 := 32

/-- One slot: the entry's sort hash and a posting's row. -/
def putPostSlot (b : ByteArray) (kh : UInt64) (fl : UInt8) (seq cnt : Nat) (l : Line) : ByteArray :=
  putLine (putN (putN ((put64 b kh).push fl) seq 5) cnt 5) l

/-- A tail row: the 64-byte tail digest at offset 11 of the row, zeros elsewhere. -/
def putTailSlot (b : ByteArray) (kh : UInt64) (fl : UInt8) (tl : Bytes) : ByteArray :=
  let b := putN (putN ((put64 b kh).push fl) 0 5) 0 5
  let b := tl.foldl (fun b x => b.push x) b
  b ++ zeroBlock (slotLen - 19 - tl.length)

/-- The rows an entry takes: its first row, the tail row when `count > capN`, the other postings. -/
def entRows (e : Entry) : Nat := e.head.length + (if capN < e.count then 1 else 0)

def putEntry (b : ByteArray) (kh : UInt64) (kb : Bytes) (e : Entry) : ByteArray :=
  let fl : UInt8 := ((kb.getD 1 (0 : UInt8)) &&& (7 : UInt8)) ||| (((kb.headD (0 : UInt8)) &&& (1 : UInt8)) <<< (3 : UInt8))
  match e.head with
  | [] => b
  | p :: ps =>
    let b := putPostSlot b kh (fl ||| flagFirst) p.seq e.count p.row
    let b := if capN < e.count then putTailSlot b kh (fl ||| flagTail) e.tail else b
    ps.foldl (fun b q => putPostSlot b kh fl q.seq 0 q.row) b

/-- The slots of sorted entries; with each entry's directory hash and first slot, and the slot count. -/
def encodeSlots (kh dh : Bytes → UInt64) (ents : Ents) : ByteArray × Array (UInt64 × Nat) × Nat := Id.run do
  let mut buf := ByteArray.empty
  let mut es : Array (UInt64 × Nat) := #[]
  let mut n := 0
  for x in ents do
    es := es.push (dh x.1, n)
    buf := putEntry buf (kh x.1) x.1 x.2
    n := n + entRows x.2
  return (buf, es, n)

/-! ## Pages -/

def blockDom : ByteArray := Bin.bytesOf (domain "STORE/BLOCK2")
def pageDom : ByteArray := Bin.bytesOf (domain "STORE/PAGE4")
/-- Page `p` of `n` slots: header then blocks; the page hash `ph`; the page fence. -/
def packPage (slots : ByteArray) (n p : Nat) : ByteArray × ByteArray × UInt64 := Id.run do
  let mut hdr := ByteArray.empty
  let mut body := ByteArray.empty
  for b in [0:blocksPage] do
    let i := slotsPage * p + slotsBlock * b
    let blk := slots.extract (i * slotLen) ((i + slotsBlock) * slotLen)
    hdr := put64 (sha3_512Into hdr blockDom blk 0 blk.size) (if i < n then ld64 slots (i * slotLen) else noFence)
    body := body ++ blk
  return (hdr ++ body, hashDom pageDom hdr, if slotsPage * p < n then ld64 slots (slotsPage * p * slotLen) else noFence)

/-- The pages of `n` slots, with the page hashes (64 bytes each) and fences.  The page bytes have room for `extra` more
    bytes, so a caller's append to them does not copy; `slots` already padded to whole pages is not copied either. -/
def packPages (slots : ByteArray) (n : Nat) (extra : Nat := 0) : ByteArray × ByteArray × Array UInt64 := Id.run do
  let np := (n + slotsPage - 1) / slotsPage
  let s := if slots.size < np * slotsPage * slotLen then slots ++ zeroBlock (np * slotsPage * slotLen - slots.size) else slots
  let mut pg := ByteArray.emptyWithCapacity (np * pageLen + extra)
  let mut ph := ByteArray.emptyWithCapacity (np * hbLen)
  let mut fe : Array UInt64 := Array.mkEmpty np
  for p in [0:np] do
    let r := packPage s n p
    pg := pg ++ r.1
    ph := ph ++ r.2.1
    fe := fe.push r.2.2
  return (pg, ph, fe)

/-! ## Metadata -/

structure Meta where
  chunk : Nat
  inst : Nat
  rows : Nat
  ph : ByteArray
  fence : Array UInt64
  tombs : Array (Nat × Nat × Nat)
  nent : Nat
  offs : Array Nat
  ents : ByteArray

def Meta.np (m : Meta) : Nat := m.fence.size

/-- Entries grouped by segment, stably: the 65 offsets and the 12-byte records. -/
def groupEnts (es : Array (UInt64 × Nat)) : Array Nat × ByteArray :=
  let cnt := es.foldl (fun (c : Array Nat) x => c.modify (segU x.1) (· + 1)) (Array.replicate 64 0)
  let offs := (List.range 64).foldl (fun (o : Array Nat) j => o.push (o.back! + cnt[j]!)) #[0]
  let r := es.foldl (fun (acc : Array Nat × ByteArray) x =>
    let j := segU x.1
    let o := acc.1[j]! * 12
    (acc.1.modify j (· + 1), setN (st64 acc.2 o x.1) (o + 8) x.2 4)) (offs.extract 0 64, zeroBlock (es.size * 12))
  (offs, r.2)

def encodeMeta (m : Meta) : ByteArray :=
  let b := putN (putN (putN (putN ByteArray.empty m.chunk 4) m.inst 8) m.rows 8) m.np 4
  let b := (List.range m.np).foldl (fun b p => put64 (b ++ m.ph.extract (hbLen * p) (hbLen * p + hbLen)) m.fence[p]!) b
  let b := putN b m.tombs.size 4
  let b := m.tombs.foldl (fun b t => putN (putN (putN b t.1 4) t.2.1 8) t.2.2 4) b
  let b := putN b m.nent 4
  (m.offs.foldl (fun b o => putN b o 4) b) ++ m.ents

/-- Strict: the exact length, page count and offset table must agree. -/
def parseMeta (b : ByteArray) : Option Meta := do
  guard (24 ≤ b.size)
  let np := getN b 20 4
  let rows := getN b 12 8
  guard (np ≤ b.size / hdrEnt && np == (rows + slotsPage - 1) / slotsPage)
  let o1 := 24 + hdrEnt * np
  guard (o1 + 4 ≤ b.size)
  let nt := getN b o1 4
  guard (nt ≤ b.size / 16)
  let o2 := o1 + 4 + 16 * nt
  guard (o2 + 4 + 260 ≤ b.size)
  let ne := getN b o2 4
  let o3 := o2 + 4 + 260
  guard (b.size == o3 + 12 * ne && ne ≤ rows)
  let offs := (Array.range 65).map fun j => getN b (o2 + 4 + 4 * j) 4
  guard (offs[0]! == 0 && offs[64]! == ne && (List.range 64).all fun j => offs[j]! ≤ offs[j + 1]!)
  let ph := (List.range np).foldl (fun a p => a ++ b.extract (24 + hdrEnt * p) (24 + hdrEnt * p + hbLen)) ByteArray.empty
  pure ⟨getN b 0 4, getN b 4 8, rows, ph, (Array.range np).map fun p => ld64 b (24 + hdrEnt * p + hbLen),
    (Array.range nt).map fun t => (getN b (o1 + 4 + 16 * t) 4, getN b (o1 + 8 + 16 * t) 8, getN b (o1 + 16 + 16 * t) 4),
    ne, offs, b.extract o3 b.size⟩

/-- The file `c<number>`: pages, metadata, metadata length.  Also the metadata, for its tree leaf. -/
def encodeChunk (kh dh : Bytes → UInt64) (ents : Ents) (chunk inst : Nat) (tombs : Array (Nat × Nat × Nat)) :
    ByteArray × ByteArray :=
  let s := encodeSlots kh dh ents
  let pg := packPages s.1 s.2.2
  let g := groupEnts s.2.1
  let md := encodeMeta ⟨chunk, inst, s.2.2, pg.2.1, pg.2.2, tombs, s.2.1.size, g.1, g.2⟩
  (putN (pg.1 ++ md) md.size 4, md)

/-- Pages and metadata of a chunk file; none when the lengths do not agree. -/
def parseChunk (f : ByteArray) : Option (Meta × ByteArray) := do
  guard (4 ≤ f.size)
  let ml := getN f (f.size - 4) 4
  guard (ml + 4 ≤ f.size)
  let ms := f.size - 4 - ml
  let m ← parseMeta (f.extract ms (f.size - 4))
  guard (ms == m.np * pageLen)
  pure (m, f.extract 0 ms)

/-! ## Reading -/

def slotOff (i : Nat) : Nat :=
  i / slotsPage * pageLen + hdrLen + (i % slotsPage) / slotsBlock * blockLen + (i % slotsBlock) * slotLen

/-- The last index in `[lo, hi)` whose fence is under `kh` (`lo` when none), in at most `f` halvings.  Specialized at
    each use, so the fence read is inlined and no word is boxed. -/
@[specialize] def lastBelowIn (fence : Nat → UInt64) (kh : UInt64) (lo hi : Nat) : Nat → Nat
  | 0 => lo
  | f + 1 => if hi ≤ lo + 1 then lo else
      let mid := (lo + hi) / 2
      if fence mid < kh then lastBelowIn fence kh mid hi f else lastBelowIn fence kh lo mid f

/-- The last index below `n` whose fence is under `kh` (0 when none); fences rise. -/
@[inline] def lastBelow (fence : Nat → UInt64) (n : Nat) (kh : UInt64) : Nat := lastBelowIn fence kh 0 n 64

/-! ## Equality with the model -/

/-- `v` as `w` little-endian bytes, as a list. -/
def lN : Nat → Nat → List UInt8
  | _, 0 => []
  | v, w + 1 => UInt8.ofNat v :: lN (v >>> 8) w

theorem lN_length : ∀ (w v : Nat), (lN v w).length = w
  | 0, _ => rfl
  | w + 1, v => by simp [lN, lN_length w]

theorem push_tl' (b : ByteArray) (c : UInt8) : (b.push c).toList = b.toList ++ [c] := by
  simp [Bin.toList_eq', ByteArray.data_push]

theorem putN_tl : ∀ (w : Nat) (b : ByteArray) (v : Nat), (putN b v w).toList = b.toList ++ lN v w
  | 0, b, v => by simp [putN, lN]
  | w + 1, b, v => by
    simp only [putN, lN, putN_tl w, push_tl']
    simp

theorem put64_tl (b : ByteArray) (v : UInt64) : ∃ s : List UInt8, s.length = 8 ∧ (put64 b v).toList = b.toList ++ s :=
  ⟨[v.toUInt8, (v >>> 8).toUInt8, (v >>> 16).toUInt8, (v >>> 24).toUInt8, (v >>> 32).toUInt8, (v >>> 40).toUInt8,
    (v >>> 48).toUInt8, (v >>> 56).toUInt8], rfl, by simp [put64, push_tl']⟩

theorem getN_tl : ∀ (w : Nat) (b : ByteArray) (pre suf : List UInt8) (v o : Nat),
    b.toList = pre ++ lN v w ++ suf → pre.length = o → getN b o w = v % 256 ^ w
  | 0, b, pre, suf, v, o, _, _ => by simp [getN]; omega
  | w + 1, b, pre, suf, v, o, h, ho => by
    have hl : b.toList = pre ++ (UInt8.ofNat v :: (lN (v >>> 8) w ++ suf)) := by rw [h]; simp [lN]
    have hlt : o < b.toList.length := by rw [hl]; simp; omega
    have hq : b.toList[o]? = some (UInt8.ofNat v) := by
      rw [hl, List.getElem?_append_right (by omega)]; simp [← ho]
    have hb : b[o]! = UInt8.ofNat v := by
      rw [Bin.getBang' b o (by rw [Bin.size_eq_length']; exact hlt)]
      rw [List.getElem?_eq_getElem hlt] at hq
      exact Option.some.inj hq
    have ih := getN_tl w b (pre ++ [UInt8.ofNat v]) suf (v >>> 8) (o + 1) (by rw [h]; simp [lN]) (by simp [ho])
    simp only [getN, hb, ih]
    rw [Nat.pow_succ', Nat.mod_mul, Nat.shiftRight_eq_div_pow]
    simp [UInt8.toNat_ofNat]

theorem flatMap_len {α : Type} (f : α → List UInt8) (c : Nat) (l : List α) (h : ∀ x, (f x).length = c) :
    (l.flatMap f).length = c * l.length := by
  induction l with
  | nil => simp
  | cons x xs ih => simp [List.flatMap_cons, h, ih, Nat.mul_succ]; omega

theorem tomb_fold (ts : List (Nat × Nat × Nat)) : ∀ b : ByteArray,
    ((ts.foldl (fun b t => putN (putN (putN b t.1 4) t.2.1 8) t.2.2 4) b).toList =
      b.toList ++ ts.flatMap fun t => lN t.1 4 ++ lN t.2.1 8 ++ lN t.2.2 4) := by
  induction ts with
  | nil => intro b; simp
  | cons t ts ih => intro b; simp [List.foldl_cons, ih, putN_tl, List.flatMap_cons]

theorem offs_fold (os : List Nat) : ∀ b : ByteArray,
    ((os.foldl (fun b o => putN b o 4) b).toList = b.toList ++ os.flatMap fun o => lN o 4) := by
  induction os with
  | nil => intro b; simp
  | cons t ts ih => intro b; simp [List.foldl_cons, ih, putN_tl, List.flatMap_cons]

theorem page_fold (m : Meta) (hph : m.ph.size = hbLen * m.np) (b : ByteArray) :
    ∀ k, k ≤ m.np → ∃ s : List UInt8, s.length = 72 * k ∧
      ((List.range k).foldl (fun b p => put64 (b ++ m.ph.extract (hbLen * p) (hbLen * p + hbLen)) m.fence[p]!) b).toList
        = b.toList ++ s := by
  intro k
  induction k with
  | zero => intro _; exact ⟨[], rfl, by simp⟩
  | succ k ih =>
    intro hk
    obtain ⟨s, hs, hE⟩ := ih (by omega)
    obtain ⟨t, ht, hP⟩ := put64_tl
      (((List.range k).foldl (fun b p => put64 (b ++ m.ph.extract (hbLen * p) (hbLen * p + hbLen)) m.fence[p]!) b) ++
        m.ph.extract (hbLen * k) (hbLen * k + hbLen)) m.fence[k]!
    refine ⟨s ++ (m.ph.extract (hbLen * k) (hbLen * k + hbLen)).toList ++ t, ?_, ?_⟩
    · have : (m.ph.extract (hbLen * k) (hbLen * k + hbLen)).toList.length = 64 := by
        rw [← Bin.size_eq_length', ByteArray.size_extract]
        simp only [hbLen] at hph ⊢
        omega
      simp [hs, this, ht]; omega
    · rw [List.range_succ, List.foldl_append, List.foldl_cons, List.foldl_nil, hP, Bin.toList_append', hE]
      simp

theorem encodeMeta_tl (m : Meta) (hph : m.ph.size = hbLen * m.np) :
    ∃ P : List UInt8, P.length = 72 * m.np ∧ (encodeMeta m).toList =
      lN m.chunk 4 ++ lN m.inst 8 ++ lN m.rows 8 ++ lN m.np 4 ++ P ++ lN m.tombs.size 4 ++
        (m.tombs.toList.flatMap fun t => lN t.1 4 ++ lN t.2.1 8 ++ lN t.2.2 4) ++ lN m.nent 4 ++
        (m.offs.toList.flatMap fun o => lN o 4) ++ m.ents.toList := by
  obtain ⟨P, hP, hE⟩ := page_fold m hph
    (putN (putN (putN (putN ByteArray.empty m.chunk 4) m.inst 8) m.rows 8) m.np 4) m.np (Nat.le_refl _)
  refine ⟨P, hP, ?_⟩
  unfold encodeMeta
  simp only [Bin.toList_append', offs_fold, ← Array.foldl_toList, tomb_fold, putN_tl, hE]
  simp [lN]


/-- Metadata that satisfies what `parseMeta` checks (page count from the rows, field widths, the offset table running
    from 0 to the entry count, the entry records the right length) parses.  The proof reads the encoded bytes back
    field by field (`getN` over `putN`, the page, tomb and offset folds). -/
theorem parseMeta_encode (m : Meta)
    (h : m.ph.size = hbLen * m.np ∧ m.offs.size = 65 ∧ m.np = (m.rows + slotsPage - 1) / slotsPage ∧
      m.chunk < 2 ^ 32 ∧ m.inst < 2 ^ 64 ∧ m.rows < 2 ^ 64 ∧ m.np < 2 ^ 32 ∧ m.tombs.size < 2 ^ 32 ∧
      (∀ t ∈ m.tombs, t.1 < 2 ^ 32 ∧ t.2.1 < 2 ^ 64 ∧ t.2.2 < 2 ^ 32) ∧ m.nent < 2 ^ 32 ∧ m.nent ≤ m.rows ∧
      m.ents.size = 12 * m.nent ∧ (∀ j < 65, m.offs[j]! < 2 ^ 32) ∧ m.offs[0]! = 0 ∧ m.offs[64]! = m.nent ∧
      (∀ j < 64, m.offs[j]! ≤ m.offs[j + 1]!)) :
    ∃ m', parseMeta (encodeMeta m) = some m' := by
  obtain ⟨hph, hoffs, hnp, hc, hi, hr, hnp32, hnt, htb, hne, hnr, hents, hob, h0, h64, hmono⟩ := h
  obtain ⟨P, hP, hE⟩ := encodeMeta_tl m hph
  have e4 : (256 : Nat) ^ 4 = 2 ^ 32 := by decide
  have e8 : (256 : Nat) ^ 8 = 2 ^ 64 := by decide
  have hTl := flatMap_len (fun t : Nat × Nat × Nat => lN t.1 4 ++ lN t.2.1 8 ++ lN t.2.2 4) 16 m.tombs.toList
    (fun t => by simp [lN_length])
  have hO := flatMap_len (fun o => lN o 4) 4 m.offs.toList (fun o => lN_length 4 o)
  simp only [Array.length_toList] at hTl hO
  rw [hoffs] at hO
  have hsz : (encodeMeta m).size = 24 + 72 * m.np + 4 + 16 * m.tombs.size + 4 + 260 + 12 * m.nent := by
    rw [Bin.size_eq_length', hE]
    simp only [List.length_append, lN_length, hP, hTl, hO, ← Bin.size_eq_length', hents]
  have r_np : getN (encodeMeta m) 20 4 = m.np :=
    (getN_tl 4 _ (lN m.chunk 4 ++ lN m.inst 8 ++ lN m.rows 8)
      (P ++ lN m.tombs.size 4 ++ (m.tombs.toList.flatMap fun t => lN t.1 4 ++ lN t.2.1 8 ++ lN t.2.2 4) ++
        lN m.nent 4 ++ (m.offs.toList.flatMap fun o => lN o 4) ++ m.ents.toList) m.np 20
      (by rw [hE]; simp only [List.append_assoc]) (by simp [lN_length])).trans
      (Nat.mod_eq_of_lt (by rw [e4]; exact hnp32))
  have r_rows : getN (encodeMeta m) 12 8 = m.rows :=
    (getN_tl 8 _ (lN m.chunk 4 ++ lN m.inst 8)
      (lN m.np 4 ++ P ++ lN m.tombs.size 4 ++ (m.tombs.toList.flatMap fun t => lN t.1 4 ++ lN t.2.1 8 ++ lN t.2.2 4) ++
        lN m.nent 4 ++ (m.offs.toList.flatMap fun o => lN o 4) ++ m.ents.toList) m.rows 12
      (by rw [hE]; simp only [List.append_assoc]) (by simp [lN_length])).trans
      (Nat.mod_eq_of_lt (by rw [e8]; exact hr))
  have r_nt : getN (encodeMeta m) (24 + 72 * m.np) 4 = m.tombs.size :=
    (getN_tl 4 _ (lN m.chunk 4 ++ lN m.inst 8 ++ lN m.rows 8 ++ lN m.np 4 ++ P) 
      ((m.tombs.toList.flatMap fun t => lN t.1 4 ++ lN t.2.1 8 ++ lN t.2.2 4) ++
        lN m.nent 4 ++ (m.offs.toList.flatMap fun o => lN o 4) ++ m.ents.toList) m.tombs.size (24 + 72 * m.np)
      (by rw [hE]; simp only [List.append_assoc]) (by simp [lN_length, hP]; omega)).trans
      (Nat.mod_eq_of_lt (by rw [e4]; exact hnt))
  have r_ne : getN (encodeMeta m) (24 + 72 * m.np + 4 + 16 * m.tombs.size) 4 = m.nent :=
    (getN_tl 4 _ (lN m.chunk 4 ++ lN m.inst 8 ++ lN m.rows 8 ++ lN m.np 4 ++ P ++ lN m.tombs.size 4 ++
        (m.tombs.toList.flatMap fun t => lN t.1 4 ++ lN t.2.1 8 ++ lN t.2.2 4))
      ((m.offs.toList.flatMap fun o => lN o 4) ++ m.ents.toList) m.nent (24 + 72 * m.np + 4 + 16 * m.tombs.size)
      (by rw [hE]; simp only [List.append_assoc]) (by simp only [List.length_append, lN_length, hP, hTl])).trans
      (Nat.mod_eq_of_lt (by rw [e4]; exact hne))
  have r_off : ∀ j < 65, getN (encodeMeta m) (24 + 72 * m.np + 4 + 16 * m.tombs.size + 4 + 4 * j) 4 = m.offs[j]! := by
    intro j hj
    have hj' : j < m.offs.toList.length := by simp [hoffs]; omega
    have hx : m.offs.toList = m.offs.toList.take j ++ (m.offs.toList[j] :: m.offs.toList.drop (j + 1)) := by
      rw [← List.drop_eq_getElem_cons hj', List.take_append_drop]
    have hO' : (m.offs.toList.flatMap fun o => lN o 4) =
        ((m.offs.toList.take j).flatMap fun o => lN o 4) ++
          (lN m.offs.toList[j] 4 ++ ((m.offs.toList.drop (j + 1)).flatMap fun o => lN o 4)) := by
      have := congrArg (List.flatMap fun o => lN o 4) hx
      simpa [List.flatMap_append, List.flatMap_cons] using this
    have hpl := flatMap_len (fun o => lN o 4) 4 (m.offs.toList.take j) (fun o => lN_length 4 o)
    have hg : m.offs[j]! = m.offs.toList[j] := by
      rw [getElem!_pos m.offs j (by omega)]; simp
    rw [hg]
    refine (getN_tl 4 _ (lN m.chunk 4 ++ lN m.inst 8 ++ lN m.rows 8 ++ lN m.np 4 ++ P ++ lN m.tombs.size 4 ++
        (m.tombs.toList.flatMap fun t => lN t.1 4 ++ lN t.2.1 8 ++ lN t.2.2 4) ++ lN m.nent 4 ++
        ((m.offs.toList.take j).flatMap fun o => lN o 4))
      (((m.offs.toList.drop (j + 1)).flatMap fun o => lN o 4) ++ m.ents.toList) m.offs.toList[j]
      (24 + 72 * m.np + 4 + 16 * m.tombs.size + 4 + 4 * j)
      (by rw [hE, hO']; simp only [List.append_assoc]) ?_).trans (Nat.mod_eq_of_lt ?_)
    · simp only [List.length_append, lN_length, hP, hTl, hpl, List.length_take]
      omega
    · rw [e4, ← hg]; exact hob j hj
  generalize encodeMeta m = b at *
  have hH : hdrEnt = 72 := rfl
  have hmap : (Array.range 65).map (fun j => getN b (24 + 72 * m.np + 4 + 16 * m.tombs.size + 4 + 4 * j) 4) = m.offs := by
    apply Array.ext
    · simp [hoffs]
    · intro i h1 h2
      simp only [Array.getElem_map, Array.getElem_range]
      rw [r_off i (by simpa using h1)]
      exact getElem!_pos m.offs i h2
  unfold parseMeta
  simp [hH, r_np, r_rows, r_nt, r_ne, hmap, h0, h64, hsz]
  have f1 : 24 ≤ 24 + 72 * m.np + 4 + 16 * m.tombs.size + 4 + 260 + 12 * m.nent := by omega
  have g2 : m.np ≤ (24 + 72 * m.np + 4 + 16 * m.tombs.size + 4 + 260 + 12 * m.nent) / 72 ∧
      m.np = (m.rows + slotsPage - 1) / slotsPage := ⟨by omega, hnp⟩
  have f3 : 24 + 72 * m.np + 4 ≤ 24 + 72 * m.np + 4 + 16 * m.tombs.size + 4 + 260 + 12 * m.nent := by omega
  have f4 : m.tombs.size ≤ (24 + 72 * m.np + 4 + 16 * m.tombs.size + 4 + 260 + 12 * m.nent) / 16 := by omega
  simp only [guard, if_pos f1, if_pos g2, if_pos f3, if_pos f4, if_pos hnr, if_pos hmono]
  simp

end BlindLedger.Gate.Engine3
