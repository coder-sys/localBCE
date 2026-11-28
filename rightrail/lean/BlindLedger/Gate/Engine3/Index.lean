/-! # History index table (gate path design section 3.3)

RAM only, never stored, rebuilt from a rows file at load.  A table holds 8-byte slots; a slot names a row by its
sequence number in the rows file and is a hint: the caller confirms it against the row bytes.  It grows from any start
size without limit and without the caller sizing it.

* **Key:** two 64-bit words `h1`, `h2` of its key digest.  A keyed mix of both with the table's secret (128 bits, random
  per process) gives the word `a0`; the fingerprint `f` is its top 8 bits.  The two address words are `a0` and
  `a1 = a0 xor spread f`; either one with `f` gives the other.  A sender who cannot see the secret cannot choose keys
  that share buckets, and keys that agree on part of their digest still spread.  The secret is never stored.
* **Slot:** tag 22 bits (bits 63..42) = `f` (8 bits) then a reserve (14 bits); choice bit (41); over bit (40);
  `seq + 1` in the low 40 bits (0 = empty).  A slot of choice `c` sits in the bucket of `a_c`.  The reserve holds the
  next bits of `a_c` above its bucket's level under a stop bit: `1` then `v` bits, `v ≤ 13`.  Reserve 0 is a void slot:
  no bits above the level are known.
* **Bucket:** 8 slots, 64 bytes, one cache line; the used slots are a prefix.  Buckets live in segments of 1023
  (65,472 bytes), so growth allocates one segment at a time and never copies the table.  With the byte array's header a
  segment is one 64 KB allocation; 1024 buckets would pass 64 KB by the header and cost the allocator twice that.
* **Linear hashing:** `2^k + p` buckets.  The address of `a` is `a mod 2^k`, or `a mod 2^(k+1)` when that is below the
  split pointer `p`.  When the slots pass 9/10 of the room, bucket `p` splits: a slot's lowest reserve bit says whether
  it moves to bucket `p + 2^k`, and its reserve shifts down one.  A split reads no key and hashes nothing.  A void
  slot, or one with no reserve bit left, is copied to both halves, so it stays where its key looks.
* **Insert:** into the emptier of the key's two buckets.  When both are full, a chain of moves frees a slot: each
  moved slot goes to its other bucket, whose address its own bits and `f` give.  The chain is found breadth first over
  at most `maxNodes` buckets, so it is the shortest, and then done from its end, so a failed search changes nothing;
  the key then goes to the stash (full words, exact), tried again whenever a split changes one of its buckets.  The
  stash is a hash table of 24-byte entries (`h1`, `h2`, slot) found by `a0`, linear probing, at most half full: it
  doubles before it passes that, so a lookup reads the entries of its hash run, not the stash.
  Breadth first matters: during a round the unsplit buckets hold twice the keys per address range of the split ones,
  and short chains carry their surplus over to the split side.
* **Fingerprint:** a probe compares `f`, the choice bit and the known reserve bits, 8 + up to 13 bits.  A slot loses
  one reserve bit per doubling after it was placed, so only slots placed 13 doublings ago are void.  Fewer bits only
  raise the rate of confirming reads, never a wrong answer.

A position from `probe` (`8 * bucket + slot`, or `stashBase + entry`) is good until the next insert, which may move
slots.  Proved at the end: `probe_complete`, `probe_get`.  Both need the start
size `k0 ≤ 20` (the engine builds with 10) and fewer than `2^40` rows: wider shifts wrap in 64 bits. -/

namespace BlindLedger.Gate.Engine3.Index

/-- Word `j` of `t` (8 bytes, little endian; host is little endian, the table is never written to a file); out of range 0. -/
@[extern c inline "(lean_is_scalar(#2) && 8 * lean_unbox(#2) + 8 <= lean_sarray_size(#1) ? *(uint64_t*)(lean_sarray_cptr(#1) + 8 * lean_unbox(#2)) : (uint64_t)0)"]
def wAt (t : @& ByteArray) (j : @& Nat) : UInt64 :=
  (List.range 8).foldl (fun a i => a ||| ((t.get! (8 * j + i)).toUInt64 <<< (8 * i).toUInt64)) 0

/-- Word `j` set, in place when `t` is not shared.  Out of range changes nothing. -/
@[extern c inline "({ lean_object* a_ = #1; if (!lean_is_exclusive(a_)) a_ = lean_copy_sarray(a_, lean_sarray_capacity(a_)); if (lean_is_scalar(#2) && 8 * lean_unbox(#2) + 8 <= lean_sarray_size(a_)) *(uint64_t*)(lean_sarray_cptr(a_) + 8 * lean_unbox(#2)) = #3; a_; })"]
def wSet (t : ByteArray) (j : @& Nat) (v : UInt64) : ByteArray :=
  (List.range 8).foldl (fun a i => a.set! (8 * j + i) (v >>> (8 * i).toUInt64).toUInt8) t

/-- `n` zero bytes, allocated at their exact size. -/
@[extern c inline "({ size_t n_ = lean_is_scalar(#1) ? lean_unbox(#1) : 0; lean_object* r_ = lean_alloc_sarray(1, n_, n_); __builtin_memset(lean_sarray_cptr(r_), 0, n_); r_; })"]
def zeros (n : @& Nat) : ByteArray := ⟨Array.replicate n 0⟩

/-! ## Buckets in segments -/

/-- Slot `j` (taken mod 8) of bucket `b`: word `8 * (b mod 1023) + j` of segment `b / 1023`; 0 (empty) past the end. -/
@[extern c inline "({ size_t b_ = lean_unbox(#2); lean_object* s_ = (lean_is_scalar(#2) && (b_ / 1023) < lean_array_size(#1)) ? lean_array_get_core(#1, b_ / 1023) : NULL; size_t o_ = 64 * (b_ % 1023) + 8 * (lean_unbox(#3) & 7); (s_ != NULL && lean_is_scalar(#3) && o_ + 8 <= lean_sarray_size(s_)) ? *(uint64_t*)(lean_sarray_cptr(s_) + o_) : (uint64_t)0; })"]
def slotAt (segs : @& Array ByteArray) (b j : @& Nat) : UInt64 :=
  wAt (segs.getD (b / 1023) .empty) (8 * (b % 1023) + (j &&& 7))

/-- Slot `j` of bucket `b` set, in place when the segments are not shared. -/
@[inline] def slotSet (segs : Array ByteArray) (b j : Nat) (v : UInt64) : Array ByteArray :=
  segs.modify (b / 1023) fun s => wSet s (8 * (b % 1023) + (j &&& 7)) v

/-- Asks the processor to fetch bucket `b`; no effect on any value (returns 0). -/
@[extern c inline "({ size_t b_ = lean_unbox(#2); if (lean_is_scalar(#2) && (b_ / 1023) < lean_array_size(#1)) __builtin_prefetch(lean_sarray_cptr(lean_array_get_core(#1, b_ / 1023)) + 64 * (b_ % 1023)); (uint64_t)0; })"]
def warmAt (_segs : @& Array ByteArray) (_b : @& Nat) : UInt64 := 0

/-! ## Slot -/

def lowMask : UInt64 := 0xFF_FFFF_FFFF
def choiceBit : UInt64 := 0x200_0000_0000
def overBit : UInt64 := 0x100_0000_0000
/-- The reserve field, bits 55..42. -/
def resField : UInt64 := 0x00FF_FC00_0000_0000
/-- Reserve bits a placed slot holds. -/
def resBits : Nat := 13

@[inline] def isEmpty (s : UInt64) : Bool := s &&& lowMask == 0
@[inline] def seqOf (s : UInt64) : Nat := ((s &&& lowMask) - 1).toNat
@[inline] def withSeq (s : UInt64) (seq : Nat) : UInt64 := (s &&& ~~~lowMask) ||| (seq + 1).toUInt64
@[inline] def resOf (s : UInt64) : UInt64 := (s >>> 42) &&& 0x3FFF
@[inline] def withRes (s r : UInt64) : UInt64 := (s &&& ~~~resField) ||| (r <<< 42)

/-- The bits of `r` below its highest set bit: the reserve bits its stop bit marks as known. -/
@[inline] def belowTop (r : UInt64) : UInt64 :=
  let r := r ||| (r >>> 1)
  let r := r ||| (r >>> 2)
  let r := r ||| (r >>> 4)
  let r := r ||| (r >>> 8)
  r >>> 1

/-! ## Addresses -/

@[inline] def spread (x : UInt64) : UInt64 :=
  let z := x + 0x9E3779B97F4A7C15
  let z := (z ^^^ (z >>> 30)) * 0xBF58476D1CE4E5B9
  let z := (z ^^^ (z >>> 27)) * 0x94D049BB133111EB
  z ^^^ (z >>> 31)

/-- The address word of the key `(h1, h2)` under the secret `(s0, s1)`: both words and both secret halves go through
    two multiply rounds.  Its top 8 bits are the fingerprint. -/
@[inline] def keyed (s0 s1 h1 h2 : UInt64) : UInt64 :=
  let z := (h1 ^^^ s0) + (h2 ^^^ s1) * 0xD6E8FEB86659FD93
  let z := (z ^^^ (z >>> 32)) * 0xBF58476D1CE4E5B9
  let z := (z ^^^ (z >>> 29)) * 0x94D049BB133111EB
  z ^^^ (z >>> 32)

/-- The other address word of a key with fingerprint `f`. -/
@[inline] def otherWord (a f : UInt64) : UInt64 := a ^^^ spread f

/-- The bucket of address word `a`. -/
@[inline] def addrK (k p : Nat) (a : UInt64) : Nat :=
  let lo := a &&& ((1 <<< k.toUInt64) - 1)
  if lo.toNat < p then (a &&& ((2 <<< k.toUInt64) - 1)).toNat else lo.toNat

/-- The level of bucket `b`: the address bits it fixes. -/
@[inline] def lvlK (k p b : Nat) : Nat := if b < p || b.toUInt64 >>> k.toUInt64 != 0 then k + 1 else k

/-- The slot of row `seq` placed with choice `c` in a bucket at level `l`, for fingerprint `f` and address word `a`. -/
@[inline] def fresh (f a : UInt64) (l : Nat) (c : Bool) (seq : Nat) : UInt64 :=
  (f <<< 56) ||| ((0x2000 ||| ((a >>> l.toUInt64) &&& 0x1FFF)) <<< 42) ||| (if c then choiceBit else 0) |||
    (seq + 1).toUInt64

/-- Whether slot `s` is a hint for the key whose fingerprint and choice are `q` and whose address bits above the
    bucket's level are `x`. -/
@[inline] def hit (s q x : UInt64) : Bool :=
  (s &&& 0xFF00_0200_0000_0000) == q && ((resOf s ^^^ x) &&& belowTop (resOf s)) == 0

/-- No bucket.  Not inlined: a literal above 2^32 compiles to a decimal string parsed at each use. -/
@[noinline] def noB : Nat := 4611686018427387904

/-- The other address word of the slot `s` in a bucket `b` at level `l`, right on its low `l + log2 (resOf s)` bits. -/
@[inline] def otherOf (l b : Nat) (s : UInt64) : UInt64 :=
  let r := resOf s
  otherWord (b.toUInt64 ||| ((r &&& belowTop r) <<< l.toUInt64)) (s >>> 56)

/-- The other bucket of the slot `s` in bucket `b`, or `noB` when the slot's bits do not fix it. -/
def altB (k p b : Nat) (s : UInt64) : Nat :=
  let r := resOf s
  if r == 0 then noB
  else
    let l := lvlK k p b
    let a := otherOf l b s
    let lo := (a &&& ((1 <<< k.toUInt64) - 1)).toNat
    -- below `p` the bucket needs bit `k` too: known when `b` is at level `k + 1` or the reserve holds a bit
    if lo < p then (if l > k || r ≥ 2 then (a &&& ((2 <<< k.toUInt64) - 1)).toNat else noB) else lo

/-- The slot `s` of bucket `b` as it reads in its other bucket `b' = altB k p b s`. -/
def altS (k p b b' : Nat) (s : UInt64) : UInt64 :=
  let r := resOf s
  let l := lvlK k p b
  let a := otherOf l b s
  let l' := lvlK k p b'
  let v := (min (l + r.log2.toNat - l') resBits).toUInt64
  withRes (s ^^^ choiceBit) ((1 <<< v) ||| ((a >>> l'.toUInt64) &&& ((1 <<< v) - 1)))

/-! ## Table -/

structure Idx where
  /-- Segments of 1023 buckets of 8 slots (65,472 bytes each). -/
  segs : Array ByteArray
  k : Nat
  /-- Split pointer, below `2^k`. -/
  p : Nat
  /-- Slots held in buckets (a slot copied by a split counts twice; the stash is apart). -/
  n : Nat
  /-- A hash table of 24-byte entries (`h1`, `h2`, slot word, tag 0; slot word 0 = free), a power of 2 of them or none. -/
  stash : ByteArray
  /-- Entries in the stash. -/
  sn : Nat
  /-- The secret of `keyed`. -/
  s0 : UInt64
  s1 : UInt64

instance : Inhabited Idx := ⟨⟨#[], 0, 0, 0, ByteArray.empty, 0, 0, 0⟩⟩

/-- The secret of this process: 128 random bits, drawn once when the program starts. -/
initialize procSecret : UInt64 × UInt64 ← do
  let b ← IO.getRandomBytes 16
  -- plain Lean, not `wAt`: Lean runs this initializer in its interpreter when another module imports this one
  let w (o : Nat) : UInt64 := (List.range 8).foldl (fun a i => a ||| ((b.get! (o + i)).toUInt64 <<< (8 * i).toUInt64)) 0
  return (w 0, w 8)

/-- The stash positions start here; bucket positions are `8 * bucket + slot`.  Not inlined (see `noB`). -/
@[noinline] def stashBase : Nat := 1152921504606846976

/-- An empty table of `2^k0` buckets under the secret `(s0, s1)` (tests use a known one). -/
def Idx.newKeyed (k0 : Nat) (s0 s1 : UInt64) : Idx := Id.run do
  let mut segs : Array ByteArray := #[]
  for _ in [0:max 1 ((2 ^ k0 + 1022) / 1023)] do segs := segs.push (zeros 65472)
  return ⟨segs, k0, 0, 0, .empty, 0, s0, s1⟩

/-- An empty table of `2^k0` buckets under this process's secret. -/
def Idx.new (k0 : Nat) : Idx := Idx.newKeyed k0 procSecret.1 procSecret.2

/-- The address word of the key `(h1, h2)` in this table. -/
@[inline] def Idx.addr (x : @& Idx) (h1 h2 : UInt64) : UInt64 := keyed x.s0 x.s1 h1 h2

@[inline] def Idx.nb (x : Idx) : Nat := ((1 : UInt64) <<< x.k.toUInt64).toNat + x.p
def Idx.cap (x : Idx) : Nat := 8 * x.nb
/-- Bytes held by the segments and the stash. -/
def Idx.bytes (x : Idx) : Nat := 65472 * x.segs.size + x.stash.size

/-- Used slots of bucket `b` (they are a prefix).  Without branches: a branch on each loaded slot mispredicts. -/
@[extern c inline "({ size_t b_ = lean_unbox(#2); lean_object* s_ = (lean_is_scalar(#2) && (b_ / 1023) < lean_array_size(#1)) ? lean_array_get_core(#1, b_ / 1023) : NULL; size_t u_ = 0; if (s_ != NULL) { size_t z_ = lean_sarray_size(s_); const uint8_t* c_ = lean_sarray_cptr(s_); size_t o_ = 64 * (b_ % 1023); for (int j_ = 0; j_ < 8; j_++) u_ += (o_ + 8 * j_ + 8 <= z_) && ((*(const uint64_t*)(c_ + o_ + 8 * j_) & 0xFFFFFFFFFFULL) != 0); } lean_box(u_); })"]
def usedIn (segs : @& Array ByteArray) (b : @& Nat) : Nat :=
  (List.range 8).foldl (fun u j => if isEmpty (slotAt segs b j) then u else u + 1) 0

/-! ## Probe -/

/-- `out` with room for `w` words. -/
def room (out : ByteArray) (w : Nat) : ByteArray := if 8 * w ≤ out.size then out else out ++ zeros (8 * w - out.size)

/-- Bit `j` set for each used slot `j` of bucket `b` that is a hint for `q`, `x` (see `hit`).  Without branches, as
    `usedIn`. -/
@[extern c inline "({ size_t b_ = lean_unbox(#2); lean_object* s_ = (lean_is_scalar(#2) && (b_ / 1023) < lean_array_size(#1)) ? lean_array_get_core(#1, b_ / 1023) : NULL; uint64_t m_ = 0; if (s_ != NULL) { size_t z_ = lean_sarray_size(s_); const uint8_t* c_ = lean_sarray_cptr(s_); size_t o_ = 64 * (b_ % 1023); for (int j_ = 0; j_ < 8; j_++) { uint64_t w_ = (o_ + 8 * j_ + 8 <= z_) ? *(const uint64_t*)(c_ + o_ + 8 * j_) : 0; uint64_t r_ = (w_ >> 42) & 0x3FFF; uint64_t t_ = r_ | (r_ >> 1); t_ |= t_ >> 2; t_ |= t_ >> 4; t_ |= t_ >> 8; t_ >>= 1; m_ |= (uint64_t)(((w_ & 0xFFFFFFFFFFULL) != 0) & ((w_ & 0xFF00020000000000ULL) == #3) & (((r_ ^ #4) & t_) == 0)) << j_; } } m_; })"]
def hitMask (segs : @& Array ByteArray) (b : @& Nat) (q x : UInt64) : UInt64 :=
  (List.range 8).foldl (fun m j =>
    let s := slotAt segs b j
    if !isEmpty s && hit s q x then m ||| (1 <<< j.toUInt64) else m) 0

/-- The slots of bucket `b` named by mask `m`, from slot `j` on, added to the list at word `o` of `out` (count, then
    position and slot pairs). -/
def scanB (segs : @& Array ByteArray) (b : Nat) (m : UInt64) (o : Nat) (out : ByteArray) (j : Nat) : Nat → ByteArray
  | 0 => out
  | fuel + 1 =>
    if m >>> j.toUInt64 == 0 then out
    else if (m >>> j.toUInt64) &&& 1 == 1 then
      let c := (wAt out o).toNat
      scanB segs b m o (wSet (wSet (wSet out (o + 1 + 2 * c) (8 * b + j).toUInt64) (o + 2 + 2 * c) (slotAt segs b j)) o
        (c + 1).toUInt64) (j + 1) fuel
    else scanB segs b m o out (j + 1) fuel

/-- Where the key with address word `a` starts in a stash of `m + 1` entries. -/
@[inline] def stashHome (a : UInt64) (m : Nat) : Nat := ((a * 0x9E3779B97F4A7C15) >>> 32).toNat &&& m

/-- The stash entries of the run from entry `i` (to the first free entry) with both words equal, added to the list; `m + 1`
    entries in all, and at most half are used, so the run ends. -/
def scanS (st : @& ByteArray) (h1 h2 : UInt64) (m : Nat) (o : Nat) (out : ByteArray) (i : Nat) : Nat → ByteArray
  | 0 => out
  | fuel + 1 =>
    if wAt st (3 * i + 2) == 0 then out
    else if wAt st (3 * i) == h1 && wAt st (3 * i + 1) == h2 then
      let c := (wAt out o).toNat
      let out := room out (o + 3 + 2 * c)
      scanS st h1 h2 m o (wSet (wSet (wSet out (o + 1 + 2 * c) (stashBase + i).toUInt64) (o + 2 + 2 * c)
        (wAt st (3 * i + 2))) o (c + 1).toUInt64) ((i + 1) &&& m) fuel
    else scanS st h1 h2 m o out ((i + 1) &&& m) fuel

/-- The hints of the key `(h1, h2)`, written to the words of `out` from `o` (grown when needed): count, then (position,
    slot) pairs, at most 16 from buckets and every stash entry with both words equal. -/
def probe (x : @& Idx) (h1 h2 : UInt64) (out : ByteArray) (o : Nat) : ByteArray :=
  let a0 := x.addr h1 h2
  let f := a0 >>> 56
  let a1 := otherWord a0 f
  let b0 := addrK x.k x.p a0
  let b1 := addrK x.k x.p a1
  let out := wSet (room out (o + 33)) o 0
  let m0 := hitMask x.segs b0 (f <<< 56) (a0 >>> (lvlK x.k x.p b0).toUInt64)
  let m1 := hitMask x.segs b1 ((f <<< 56) ||| choiceBit) (a1 >>> (lvlK x.k x.p b1).toUInt64)
  let out := scanB x.segs b1 m1 o (scanB x.segs b0 m0 o out 0 8) 0 8
  if x.sn == 0 then out
  else
    let m := x.stash.size / 24 - 1
    scanS x.stash h1 h2 m o out (stashHome a0 m) (m + 1)

/-- Words one probe writes when the key has no stash entries (count and 16 pairs), plus room for 7 stash pairs. -/
def probeWords : Nat := 1 + 2 * 23

/-- Asks the processor to fetch the two buckets of `(h1, h2)` and returns 0.  On a batch, call it a few keys ahead of
    `probe` or `insert` and fold the result into a value that is kept. -/
def Idx.warm (x : @& Idx) (h1 h2 : UInt64) : UInt64 :=
  let a0 := x.addr h1 h2
  warmAt x.segs (addrK x.k x.p a0) ^^^ warmAt x.segs (addrK x.k x.p (otherWord a0 (a0 >>> 56)))

/-! ## Batches

A miss costs one memory latency whatever else is waiting, so a batch keeps `d` keys' buckets in flight: before key `i` is
resolved, the buckets of key `i + d` are fetched.  (Fetching a whole chunk first and then resolving it was slower: the
burst fills the processor's miss queue and nothing overlaps the resolving.)  Keys are the words `2i`, `2i + 1` of `ks`
(`h1`, `h2`).  The fetch results (always 0) are added to the key index, so the compiler cannot drop or move the fetches. -/

/-- The buckets of keys `i ..` of `ks`, `c` of them, fetched; the sum of the (zero) results. -/
def warmRange (x : @& Idx) (ks : @& ByteArray) (i : Nat) (acc : UInt64) : Nat → UInt64
  | 0 => acc
  | c + 1 => warmRange x ks (i + 1) (acc ^^^ x.warm (wAt ks (2 * i)) (wAt ks (2 * i + 1))) c

/-- `f` applied to the probe of each key `i .. n - 1` of `ks` (`f b i out`: the key's index and its `probe` output,
    which is reused for the next key, so `f` must not keep it), the buckets of key `i + d` fetched before key `i`. -/
@[specialize] def probeRun {β : Type} (x : @& Idx) (ks : @& ByteArray) (f : β → Nat → ByteArray → β) (d n : Nat)
    (i : Nat) (out : ByteArray) (b : β) : Nat → β
  | 0 => b
  | fuel + 1 =>
    if i ≥ n then b
    else
      let w := x.warm (wAt ks (2 * (i + d))) (wAt ks (2 * (i + d) + 1))
      let j := i + w.toNat
      let out := probe x (wAt ks (2 * j)) (wAt ks (2 * j + 1)) out 0
      probeRun x ks f d n (i + 1) out (f b i out) fuel

/-- `f` over the probes of keys `0 .. n - 1` of `ks`, each as `probe` returns it, with `d` keys' buckets in flight. -/
@[inline] def probeEach {β : Type} (x : @& Idx) (ks : @& ByteArray) (f : β → Nat → ByteArray → β) (d n : Nat) (b : β) : β :=
  let w := warmRange x ks 0 0 (min d n)
  probeRun x ks f d n w.toNat (zeros (8 * probeWords)) b n

/-- The slot word at a position from `probe`. -/
def Idx.get (x : @& Idx) (pos : Nat) : UInt64 :=
  if pos ≥ stashBase then wAt x.stash (3 * (pos - stashBase) + 2) else slotAt x.segs (pos / 8) (pos % 8)

/-- The slot word at `pos` set (the over bit, a newer sequence number). -/
def Idx.set (x : Idx) (pos : Nat) (v : UInt64) : Idx :=
  let ⟨segs, k, p, n, st, sn, s0, s1⟩ := x
  if pos ≥ stashBase then ⟨segs, k, p, n, wSet st (3 * (pos - stashBase) + 2) v, sn, s0, s1⟩
  else ⟨slotSet segs (pos / 8) (pos % 8) v, k, p, n, st, sn, s0, s1⟩

/-! ## Insert

These take the table apart first (`let ⟨segs, ..⟩ := x`), so the segments are uniquely owned and every write is in
place. -/

/-- Buckets the search for a free slot may visit to place one key. -/
def maxNodes : Nat := 128

/-- Bucket of node `i` of a search record (see `search`). -/
@[inline] def nodeB (r : @& ByteArray) (i : Nat) : Nat := (wAt r (5 + 3 * i)).toNat

/-- Whether bucket `b` is node `i` or one of its ancestors (nodes 0 and 1 are the roots). -/
def onChain (r : @& ByteArray) (b i : Nat) : Nat → Bool
  | 0 => true
  | fuel + 1 => nodeB r i == b || (i ≥ 2 && onChain r b (wAt r (6 + 3 * i)).toNat fuel)

/-- Breadth-first search, from slot `j` of node `i` on, for a chain of moves that ends in a free slot.  Node `i` is
    words `5 + 3i` (its full bucket), `6 + 3i` (its parent node) and `7 + 3i` (the parent's slot that would move into
    it); `m` nodes so far, at most `maxNodes`, no bucket twice on one chain.  When found, words 0..4 are 1, the node,
    its slot, the free bucket and its first free slot; word 0 stays 0 when not.  Reads only. -/
def search (segs : @& Array ByteArray) (k p : Nat) (r : ByteArray) (i j m : Nat) : Nat → ByteArray
  | 0 => r
  | fuel + 1 =>
    if i ≥ m then r
    else if j ≥ 8 then search segs k p r (i + 1) 0 m fuel
    else
      let b := nodeB r i
      let b' := altB k p b (slotAt segs b j)
      if b' == noB then search segs k p r i (j + 1) m fuel
      else if isEmpty (slotAt segs b' 7) then
        wSet (wSet (wSet (wSet (wSet r 0 1) 1 i.toUInt64) 2 j.toUInt64) 3 b'.toUInt64) 4 (usedIn segs b').toUInt64
      else if m < maxNodes && !onChain r b' i maxNodes then
        search segs k p (wSet (wSet (wSet r (5 + 3 * m) b'.toUInt64) (6 + 3 * m) i.toUInt64) (7 + 3 * m) j.toUInt64)
          i (j + 1) (m + 1) fuel
      else search segs k p r i (j + 1) m fuel

/-- The chain done from its end: slot `j` of node `i` moved to free slot `u` of bucket `b'` in its other bucket's form,
    its place then taken by the parent's slot, and so on up to a root, whose place takes the key (`s0` in bucket 0,
    `s1` in bucket 1). -/
def exec (segs : Array ByteArray) (k p : Nat) (r : @& ByteArray) (s0 s1 : UInt64) (i j b' u : Nat) :
    Nat → Array ByteArray
  | 0 => segs
  | fuel + 1 =>
    let b := nodeB r i
    let v := slotAt segs b j
    let segs := slotSet segs b' u (altS k p b b' v)
    if i < 2 then slotSet segs b j (if i == 0 then s0 else s1)
    else exec segs k p r s0 s1 (wAt r (6 + 3 * i)).toNat (wAt r (7 + 3 * i)).toNat b j fuel

/-! The chains of one and two moves, which are most of them, are found first without `search`'s record, in its order,
    so the table comes out the same. -/

/-- The first slot of bucket `b` from `j` on whose other bucket has a free slot; 8 when none. -/
def freeAlt (segs : @& Array ByteArray) (k p b j : Nat) : Nat → Nat
  | 0 => 8
  | fuel + 1 =>
    let b' := altB k p b (slotAt segs b j)
    if b' != noB && isEmpty (slotAt segs b' 7) then j else freeAlt segs k p b (j + 1) fuel

/-- The first chain of two moves from root slot `i` on (slot `i mod 8` of `b0` when `i < 8`, else of `b1`): `8 * i + j`
    when slot `j` of the root slot's other bucket `c` has a free other bucket; 128 when none.  As in `search`, `c` is
    not the root slot's own bucket. -/
def twoMoves (segs : @& Array ByteArray) (k p b0 b1 i : Nat) : Nat → Nat
  | 0 => 128
  | fuel + 1 =>
    let b := if i < 8 then b0 else b1
    let c := altB k p b (slotAt segs b i)
    let j := if c == noB || c == b then 8 else freeAlt segs k p c 0 8
    if j < 8 then 8 * i + j else twoMoves segs k p b0 b1 (i + 1) fuel

/-- Words `o + c ..` of `t`, `fuel` of them, zeroed. -/
def clearW (t : ByteArray) (o c : Nat) : Nat → ByteArray
  | 0 => t
  | fuel + 1 => clearW (wSet t (o + c) 0) o (c + 1) fuel

/-- One half of a split of bucket `p` (whose 8 slots are the words of `src`), from slot `j` on, written to the bucket at
    word `o` of segment `t` from its slot `c` on: the low half (`hi` false, bucket `p`) or the high half (bucket
    `p + 2^k`).  A slot with a reserve bit goes to the half its lowest bit names, its reserve shifted down one; a void
    slot, or one with no reserve bit left, goes to both.  The slots after the last written are zeroed. -/
def half (src : @& ByteArray) (hi : Bool) (t : ByteArray) (o j c : Nat) : Nat → ByteArray
  | 0 => clearW t o c (8 - c)
  | fuel + 1 =>
    let s := wAt src j
    if isEmpty s then clearW t o c (8 - c)
    else
      let r := resOf s
      if r < 2 then half src hi (wSet t (o + c) (withRes s 0)) o (j + 1) (c + 1) fuel
      else if (r &&& 1 == 1) == hi then half src hi (wSet t (o + c) (withRes s (r >>> 1))) o (j + 1) (c + 1) fuel
      else half src hi t o (j + 1) c fuel

/-- Bucket `p` split into `p` and `q`: `half` of each, from a copy of bucket `p`.  In C, one pass with no allocation:
    the Lean steps cost about 0.3 us a split even on an empty table. -/
@[extern c inline "({ lean_object* a_ = lean_ensure_exclusive_array(#1); size_t n_ = lean_array_size(a_); lean_object** e_ = lean_array_cptr(a_); uint64_t w_[8] = {0}; size_t p_ = lean_unbox(#2), q_ = lean_unbox(#3); if (lean_is_scalar(#2) && (p_ / 1023) < n_) { lean_object* sp_ = e_[p_ / 1023]; for (int j_ = 0; j_ < 8; j_++) { size_t f_ = 64 * (p_ % 1023) + 8 * j_; if (f_ + 8 <= lean_sarray_size(sp_)) w_[j_] = *(const uint64_t*)(lean_sarray_cptr(sp_) + f_); } } for (int h_ = 1; h_ >= 0; h_--) { size_t b_ = h_ ? q_ : p_; if (!lean_is_scalar(h_ ? #3 : #2) || (b_ / 1023) >= n_) continue; if (!lean_is_exclusive(e_[b_ / 1023])) e_[b_ / 1023] = lean_copy_sarray(e_[b_ / 1023], lean_sarray_capacity(e_[b_ / 1023])); lean_object* t_ = e_[b_ / 1023]; size_t z_ = lean_sarray_size(t_); uint8_t* d_ = lean_sarray_cptr(t_) + 64 * (b_ % 1023); size_t o_ = 64 * (b_ % 1023); size_t c_ = 0; for (int j_ = 0; j_ < 8; j_++) { uint64_t s_ = w_[j_]; if ((s_ & 0xFFFFFFFFFFULL) == 0) break; uint64_t r_ = (s_ >> 42) & 0x3FFF; if (r_ < 2 || (int)(r_ & 1) == h_) { if (o_ + 8 * c_ + 8 <= z_) *(uint64_t*)(d_ + 8 * c_) = (s_ & ~0x00FFFC0000000000ULL) | ((r_ < 2 ? 0 : r_ >> 1) << 42); c_++; } } for (; c_ < 8; c_++) if (o_ + 8 * c_ + 8 <= z_) *(uint64_t*)(d_ + 8 * c_) = 0; } a_; })"]
def splitB (segs : Array ByteArray) (p q : @& Nat) : Array ByteArray :=
  let src := (segs.getD (p / 1023) .empty).extract (64 * (p % 1023)) (64 * (p % 1023) + 64)
  let segs := segs.modify (q / 1023) fun t => half src true t (8 * (q % 1023)) 0 0 8
  segs.modify (p / 1023) fun t => half src false t (8 * (p % 1023)) 0 0 8

/-- Slots of bucket `b` from `j` on that a split copies to both halves. -/
def copied (segs : @& Array ByteArray) (b j : Nat) : Nat → Nat
  | 0 => 0
  | fuel + 1 =>
    let s := slotAt segs b j
    if isEmpty s then 0 else (if resOf s < 2 then 1 else 0) + copied segs b (j + 1) fuel

/-- Entry `(h1, h2, w)` put in the first free entry of the stash `st` of `m + 1` entries from entry `i` on. -/
def stashPut (st : ByteArray) (h1 h2 w : UInt64) (m i : Nat) : Nat → ByteArray
  | 0 => st
  | fuel + 1 =>
    if wAt st (3 * i + 2) == 0 then wSet (wSet (wSet st (3 * i) h1) (3 * i + 1) h2) (3 * i + 2) w
    else stashPut st h1 h2 w m ((i + 1) &&& m) fuel

/-- The entries of `old` from `i` on, all put in `nw` (a larger, empty stash). -/
def stashMove (s0 s1 : UInt64) (old : @& ByteArray) (nw : ByteArray) (i : Nat) : Nat → ByteArray
  | 0 => nw
  | fuel + 1 =>
    let w := wAt old (3 * i + 2)
    if w == 0 then stashMove s0 s1 old nw (i + 1) fuel
    else
      let h1 := wAt old (3 * i)
      let h2 := wAt old (3 * i + 1)
      let m := nw.size / 24 - 1
      stashMove s0 s1 old (stashPut nw h1 h2 w m (stashHome (keyed s0 s1 h1 h2) m) (m + 1)) (i + 1) fuel

/-- The stash `old` from entry `i` on: entries with a bucket among `p0`, `q` and room there go in and leave, the others are
    put in `nw` (empty, as large as `old`), of which `sn` entries are used. -/
def retry (segs : Array ByteArray) (k p n : Nat) (old nw : ByteArray) (sn : Nat) (s0 s1 : UInt64) (p0 q i : Nat) :
    Nat → Idx
  | 0 => ⟨segs, k, p, n, if sn == 0 then .empty else nw, sn, s0, s1⟩
  | fuel + 1 =>
    let w := wAt old (3 * i + 2)
    if w == 0 then retry segs k p n old nw sn s0 s1 p0 q (i + 1) fuel
    else
      let h1 := wAt old (3 * i)
      let h2 := wAt old (3 * i + 1)
      let a0 := keyed s0 s1 h1 h2
      let f := a0 >>> 56
      let a1 := otherWord a0 f
      let b0 := addrK k p a0
      let b1 := addrK k p a1
      let u0 := usedIn segs b0
      let u1 := usedIn segs b1
      let near := b0 == p0 || b0 == q || b1 == p0 || b1 == q
      if near && (u0 < 8 || u1 < 8) then
        let segs := if u1 < u0 then slotSet segs b1 u1 (fresh f a1 (lvlK k p b1) true (seqOf w) ||| (w &&& overBit))
          else slotSet segs b0 u0 (fresh f a0 (lvlK k p b0) false (seqOf w) ||| (w &&& overBit))
        retry segs k p (n + 1) old nw sn s0 s1 p0 q (i + 1) fuel
      else
        let m := nw.size / 24 - 1
        retry segs k p n old (stashPut nw h1 h2 w m (stashHome a0 m) (m + 1)) (sn + 1) s0 s1 p0 q (i + 1) fuel

/-- One bucket split, then the stash tried where the split made room. -/
def Idx.split (x : Idx) : Idx :=
  let ⟨segs, k, p, n, st, sn, s0, s1⟩ := x
  let q := (1 <<< k) + p
  let segs := if q / 1023 < segs.size then segs else segs.push (zeros 65472)
  let n := n + copied segs p 0 8
  let segs := splitB segs p q
  let (k', p') := if p + 1 == 1 <<< k then (k + 1, 0) else (k, p + 1)
  if sn == 0 then ⟨segs, k', p', n, st, 0, s0, s1⟩
  else retry segs k' p' n st (zeros st.size) 0 s0 s1 p q 0 (st.size / 24)

/-- The row `seq` under the key `(h1, h2)`: a slot in the emptier of its buckets, else by a chain of moves from either,
    else in the stash.  Past 9/10 load one bucket splits. -/
def Idx.insert (x : Idx) (h1 h2 : UInt64) (seq : Nat) : Idx :=
  let ⟨segs, k, p, n, st, sn, s0, s1⟩ := x
  let a0 := keyed s0 s1 h1 h2
  let f := a0 >>> 56
  let a1 := otherWord a0 f
  let b0 := addrK k p a0
  let b1 := addrK k p a1
  let u0 := usedIn segs b0
  let u1 := usedIn segs b1
  let t0 := fresh f a0 (lvlK k p b0) false seq
  let t1 := fresh f a1 (lvlK k p b1) true seq
  let x : Idx :=
    if u0 < 8 || u1 < 8 then
      if u1 < u0 then ⟨slotSet segs b1 u1 t1, k, p, n + 1, st, sn, s0, s1⟩ else ⟨slotSet segs b0 u0 t0, k, p, n + 1, st, sn, s0, s1⟩
    else
      let j0 := freeAlt segs k p b0 0 8
      let i := if j0 < 8 then j0 else 8 + freeAlt segs k p b1 0 8
      let t := if i < 16 then 0 else twoMoves segs k p b0 b1 0 16
      if i < 16 || t < 128 then
        -- root slot `r`, its other bucket `c`; with two moves, slot `j` of `c` goes on to its other bucket first
        let r := if i < 16 then i else t / 8
        let b := if r < 8 then b0 else b1
        let v := slotAt segs b r
        let c := altB k p b v
        let segs := if i < 16 then slotSet segs c (usedIn segs c) (altS k p b c v)
          else
            let j := t % 8
            let w := slotAt segs c j
            let b' := altB k p c w
            slotSet (slotSet segs b' (usedIn segs b') (altS k p c b' w)) c j (altS k p b c v)
        ⟨slotSet segs b r (if r < 8 then t0 else t1), k, p, n + 1, st, sn, s0, s1⟩
      else
        let r := search segs k p (wSet (wSet (zeros (8 * (5 + 3 * maxNodes))) 5 b0.toUInt64) 8 b1.toUInt64)
          0 0 2 (9 * maxNodes + 2)
        if wAt r 0 != 0 then
          ⟨exec segs k p r t0 t1 (wAt r 1).toNat (wAt r 2).toNat (wAt r 3).toNat (wAt r 4).toNat maxNodes, k, p, n + 1,
            st, sn, s0, s1⟩
        else
          -- the stash doubles (16 entries at first) before it passes half full
          let c := st.size / 24
          let st := if 2 * (sn + 1) ≤ c then st else stashMove s0 s1 st (zeros (24 * max 16 (2 * c))) 0 c
          let m := st.size / 24 - 1
          ⟨segs, k, p, n, stashPut st h1 h2 (seq + 1).toUInt64 m (stashHome a0 m) (m + 1), sn + 1, s0, s1⟩
  if 10 * (x.n + x.sn) > 72 * x.nb then x.split else x

/-- Keys `i .. n - 1` of `ks` inserted as rows `seq0 + i`, in order, the buckets of key `i + d` fetched before key `i`. -/
def insertRun (x : Idx) (ks : @& ByteArray) (d n seq0 i : Nat) : Nat → Idx
  | 0 => x
  | fuel + 1 =>
    if i ≥ n then x
    else
      let w := x.warm (wAt ks (2 * (i + d))) (wAt ks (2 * (i + d) + 1))
      insertRun (x.insert (wAt ks (2 * i)) (wAt ks (2 * i + 1)) (seq0 + i + w.toNat)) ks d n seq0 (i + 1) fuel

/-- Keys `0 .. n - 1` of `ks` inserted as rows `seq0 + i`, in order, with `d` keys' buckets in flight.  The table is the
    one the same `insert`s give. -/
def Idx.insertMany (x : Idx) (ks : @& ByteArray) (d n seq0 : Nat) : Idx :=
  let w := warmRange x ks 0 0 (min d n)
  insertRun x ks d n (seq0 + w.toNat) 0 n

/-! ## Bits of 64-bit words -/

/-- Bit `i` of a word. -/
def bit (a : UInt64) (i : Nat) : Bool := a.toNat.testBit i

theorem bit_high' (a : UInt64) (i : Nat) (hi : 64 ≤ i) : a.toNat.testBit i = false :=
  Nat.testBit_lt_two_pow (Nat.lt_of_lt_of_le a.toNat_lt (Nat.pow_le_pow_right (by omega) hi))

theorem bit_ext {a b : UInt64} (h : ∀ i, i < 64 → bit a i = bit b i) : a = b := by
  apply UInt64.toNat_inj.mp
  apply Nat.eq_of_testBit_eq
  intro i
  by_cases hi : i < 64
  · exact h i hi
  · have ha := bit_high' a i (by omega)
    have hb := bit_high' b i (by omega)
    rw [ha, hb]

theorem bit_high (a : UInt64) (i : Nat) (hi : 64 ≤ i) : bit a i = false := by
  exact bit_high' a i hi

@[simp] theorem bit_and (a b : UInt64) (i : Nat) : bit (a &&& b) i = (bit a i && bit b i) := by
  simp [bit, Nat.testBit_and]

@[simp] theorem bit_or (a b : UInt64) (i : Nat) : bit (a ||| b) i = (bit a i || bit b i) := by
  simp [bit, Nat.testBit_or]

@[simp] theorem bit_xor (a b : UInt64) (i : Nat) : bit (a ^^^ b) i = (bit a i ^^ bit b i) := by
  simp [bit, Nat.testBit_xor]

theorem bit_shr (a s : UInt64) (i : Nat) : bit (a >>> s) i = bit a (i + s.toNat % 64) := by
  simp [bit, Nat.testBit_shiftRight, Nat.add_comm]

theorem bit_shl (a s : UInt64) (i : Nat) :
    bit (a <<< s) i = (decide (i < 64) && decide (s.toNat % 64 ≤ i) && bit a (i - s.toNat % 64)) := by
  simp only [bit, UInt64.toNat_shiftLeft]
  rw [Nat.testBit_mod_two_pow, Nat.testBit_shiftLeft]
  by_cases h1 : i < 64 <;> by_cases h2 : s.toNat % 64 ≤ i <;> simp [h1, h2]

theorem bit_u8 (u : UInt8) (q : Nat) : bit u.toUInt64 q = (decide (q < 8) && u.toNat.testBit q) := by
  simp only [bit, UInt8.toNat_toUInt64]
  by_cases h : q < 8
  · simp [h]
  · simp [h]
    exact Nat.testBit_lt_two_pow (Nat.lt_of_lt_of_le u.toNat_lt (Nat.pow_le_pow_right (by omega) (by omega)))

/-! ## Words in byte arrays -/

theorem range8 : List.range 8 = [0, 1, 2, 3, 4, 5, 6, 7] := rfl

theorem wAt_unfold (t : ByteArray) (j : Nat) : wAt t j =
    ((t.get! (8 * j + 0)).toUInt64 <<< (8 * 0).toUInt64) ||| ((t.get! (8 * j + 1)).toUInt64 <<< (8 * 1).toUInt64) |||
    ((t.get! (8 * j + 2)).toUInt64 <<< (8 * 2).toUInt64) ||| ((t.get! (8 * j + 3)).toUInt64 <<< (8 * 3).toUInt64) |||
    ((t.get! (8 * j + 4)).toUInt64 <<< (8 * 4).toUInt64) ||| ((t.get! (8 * j + 5)).toUInt64 <<< (8 * 5).toUInt64) |||
    ((t.get! (8 * j + 6)).toUInt64 <<< (8 * 6).toUInt64) ||| ((t.get! (8 * j + 7)).toUInt64 <<< (8 * 7).toUInt64) := by
  unfold wAt
  rw [range8]
  simp only [List.foldl_cons, List.foldl_nil]
  simp only [UInt64.zero_or]

theorem wSet_unfold (t : ByteArray) (j : Nat) (v : UInt64) : wSet t j v =
    ((((((((t.set! (8 * j + 0) (v >>> (8 * 0).toUInt64).toUInt8).set! (8 * j + 1) (v >>> (8 * 1).toUInt64).toUInt8).set!
      (8 * j + 2) (v >>> (8 * 2).toUInt64).toUInt8).set! (8 * j + 3) (v >>> (8 * 3).toUInt64).toUInt8).set!
      (8 * j + 4) (v >>> (8 * 4).toUInt64).toUInt8).set! (8 * j + 5) (v >>> (8 * 5).toUInt64).toUInt8).set!
      (8 * j + 6) (v >>> (8 * 6).toUInt64).toUInt8).set! (8 * j + 7) (v >>> (8 * 7).toUInt64).toUInt8) := by
  unfold wSet
  rw [range8]
  simp only [List.foldl_cons, List.foldl_nil]

theorem get!_eq (t : ByteArray) (n : Nat) : t.get! n = t[n]! := by
  by_cases h : n < t.size
  · rw [getElem!_pos t n h]; show t.data[n]! = t.data[n]; exact getElem!_pos t.data n h
  · rw [getElem!_neg t n h]; show t.data[n]! = default; exact getElem!_neg t.data n h

theorem wSet_size (t : ByteArray) (j : Nat) (v : UInt64) : (wSet t j v).size = t.size := by
  rw [wSet_unfold]; simp only [ByteArray.size_set!]

theorem get_wSet_ne (t : ByteArray) (j : Nat) (v : UInt64) (n : Nat) (h : n < 8 * j ∨ 8 * j + 8 ≤ n) :
    (wSet t j v).get! n = t.get! n := by
  rw [wSet_unfold]
  simp only [get!_eq]
  rw [ByteArray.getElem!_set!_ne _ _ _ _ (by omega), ByteArray.getElem!_set!_ne _ _ _ _ (by omega),
    ByteArray.getElem!_set!_ne _ _ _ _ (by omega), ByteArray.getElem!_set!_ne _ _ _ _ (by omega),
    ByteArray.getElem!_set!_ne _ _ _ _ (by omega), ByteArray.getElem!_set!_ne _ _ _ _ (by omega),
    ByteArray.getElem!_set!_ne _ _ _ _ (by omega), ByteArray.getElem!_set!_ne _ _ _ _ (by omega)]

theorem get_wSet_eq (t : ByteArray) (j : Nat) (v : UInt64) (hj : 8 * j + 8 ≤ t.size) (i : Nat) (hi : i < 8) :
    (wSet t j v).get! (8 * j + i) = (v >>> (8 * i).toUInt64).toUInt8 := by
  rw [wSet_unfold]
  simp only [get!_eq]
  have : i = 0 ∨ i = 1 ∨ i = 2 ∨ i = 3 ∨ i = 4 ∨ i = 5 ∨ i = 6 ∨ i = 7 := by omega
  rcases this with rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl <;>
  ( repeat rw [ByteArray.getElem!_set!_ne _ _ _ _ (by omega)]
    rw [ByteArray.getElem!_set!_self]
    all_goals (try simp only [ByteArray.size_set!])
    all_goals omega )

@[simp] theorem bit_mod256 (v : UInt64) (q : Nat) : bit (v % 256) q = (decide (q < 8) && bit v q) := by
  simp only [bit, UInt64.toNat_mod]
  rw [show (256 : UInt64).toNat = 2 ^ 8 from rfl, Nat.testBit_mod_two_pow]

theorem q64 (q : Nat) (h : q < 64) : q = 0 ∨ q = 1 ∨ q = 2 ∨ q = 3 ∨ q = 4 ∨ q = 5 ∨ q = 6 ∨ q = 7 ∨ q = 8 ∨ q = 9 ∨ q = 10 ∨ q = 11 ∨ q = 12 ∨ q = 13 ∨ q = 14 ∨ q = 15 ∨ q = 16 ∨ q = 17 ∨ q = 18 ∨ q = 19 ∨ q = 20 ∨ q = 21 ∨ q = 22 ∨ q = 23 ∨ q = 24 ∨ q = 25 ∨ q = 26 ∨ q = 27 ∨ q = 28 ∨ q = 29 ∨ q = 30 ∨ q = 31 ∨ q = 32 ∨ q = 33 ∨ q = 34 ∨ q = 35 ∨ q = 36 ∨ q = 37 ∨ q = 38 ∨ q = 39 ∨ q = 40 ∨ q = 41 ∨ q = 42 ∨ q = 43 ∨ q = 44 ∨ q = 45 ∨ q = 46 ∨ q = 47 ∨ q = 48 ∨ q = 49 ∨ q = 50 ∨ q = 51 ∨ q = 52 ∨ q = 53 ∨ q = 54 ∨ q = 55 ∨ q = 56 ∨ q = 57 ∨ q = 58 ∨ q = 59 ∨ q = 60 ∨ q = 61 ∨ q = 62 ∨ q = 63 := by omega

theorem wAt_wSet_eq (t : ByteArray) (j : Nat) (v : UInt64) (hj : 8 * j + 8 ≤ t.size) : wAt (wSet t j v) j = v := by
  rw [wAt_unfold]
  rw [get_wSet_eq t j v hj 0 (by omega), get_wSet_eq t j v hj 1 (by omega), get_wSet_eq t j v hj 2 (by omega),
    get_wSet_eq t j v hj 3 (by omega), get_wSet_eq t j v hj 4 (by omega), get_wSet_eq t j v hj 5 (by omega),
    get_wSet_eq t j v hj 6 (by omega), get_wSet_eq t j v hj 7 (by omega)]
  apply bit_ext
  intro q hq
  rcases q64 q hq with rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl <;>
  simp [bit_or, bit_shl, bit_u8, bit_shr, Nat.testBit_mod_two_pow]

theorem wAt_wSet_ne (t : ByteArray) (j j' : Nat) (v : UInt64) (h : j ≠ j') : wAt (wSet t j v) j' = wAt t j' := by
  rw [wAt_unfold, wAt_unfold]
  repeat rw [get_wSet_ne _ _ _ _ (by omega)]

theorem get!_oob (t : ByteArray) (n : Nat) (h : t.size ≤ n) : t.get! n = 0 := by
  rw [get!_eq, getElem!_neg t n (by omega)]; rfl

theorem wAt_oob (t : ByteArray) (j : Nat) (h : t.size ≤ 8 * j) : wAt t j = 0 := by
  rw [wAt_unfold]
  repeat rw [get!_oob _ _ (by omega)]
  simp

theorem set!_oob (t : ByteArray) (n : Nat) (w : UInt8) (h : t.size ≤ n) : t.set! n w = t := by
  cases t with
  | mk d =>
    show (⟨d.set! n w⟩ : ByteArray) = ⟨d⟩
    congr 1
    rw [Array.set!_eq_setIfInBounds]
    exact Array.setIfInBounds_eq_of_size_le (by simpa [ByteArray.size] using h)

theorem wSet_oob (t : ByteArray) (j : Nat) (v : UInt64) (h : t.size ≤ 8 * j) : wSet t j v = t := by
  rw [wSet_unfold]
  repeat rw [set!_oob _ _ _ (by first | omega | (simp only [ByteArray.size_set!]; omega))]

/-- Word reads and writes in a byte array whose size is a whole number of words. -/
theorem wAt_wSet (t : ByteArray) (hal : t.size % 8 = 0) (j j' : Nat) (v : UInt64) :
    wAt (wSet t j v) j' = if j' = j ∧ 8 * j + 8 ≤ t.size then v else wAt t j' := by
  by_cases hjj : j' = j
  · subst hjj
    by_cases hr : 8 * j' + 8 ≤ t.size
    · simp [wAt_wSet_eq t j' v hr, hr]
    · rw [wSet_oob t j' v (by omega)]; simp [hr]
  · rw [wAt_wSet_ne t j j' v (Ne.symm hjj)]; simp [hjj]

theorem zeros_size (n : Nat) : (zeros n).size = n := by
  simp [zeros, ByteArray.size]

theorem wAt_zeros (n j : Nat) : wAt (zeros n) j = 0 := by
  rw [wAt_unfold]
  have : ∀ m, (zeros n).get! m = 0 := by
    intro m
    have e : (zeros n).get! m = (Array.replicate n (0 : UInt8))[m]! := rfl
    by_cases h : m < n
    · rw [e, getElem!_pos _ m (by simpa using h)]; simp
    · rw [e, getElem!_neg _ m (by simpa using h)]; rfl
  simp [this]

theorem wAt_wSet_in (t : ByteArray) (hal : t.size % 8 = 0) (j j' : Nat) (v : UInt64) (hj : 8 * j + 8 ≤ t.size) :
    wAt (wSet t j v) j' = if j' = j then v else wAt t j' := by
  rw [wAt_wSet t hal]; simp [hj]

theorem zeros_get (n m : Nat) : (zeros n).get! m = 0 := by
  have e : (zeros n).get! m = (Array.replicate n (0 : UInt8))[m]! := rfl
  by_cases h : m < n
  · rw [e, getElem!_pos _ m (by simpa using h)]; simp
  · rw [e, getElem!_neg _ m (by simpa using h)]; rfl

theorem get!_append_zeros (a : ByteArray) (n m : Nat) : (a ++ zeros n).get! m = a.get! m := by
  by_cases h : m < a.size
  · have h2 : m < (a ++ zeros n).size := by simp only [ByteArray.size_append, zeros_size]; omega
    rw [get!_eq, get!_eq, getElem!_pos (a ++ zeros n) m h2, getElem!_pos a m h, ByteArray.getElem_append_left h]
  · rw [get!_oob a m (by omega)]
    by_cases h3 : m < a.size + n
    · have h2 : m < (a ++ zeros n).size := by simp only [ByteArray.size_append, zeros_size]; omega
      rw [get!_eq, getElem!_pos (a ++ zeros n) m h2, ByteArray.getElem_append_right (by omega)]
      have := zeros_get n (m - a.size)
      rw [get!_eq, getElem!_pos (zeros n) (m - a.size) (by rw [zeros_size]; omega)] at this
      exact this
    · exact get!_oob (a ++ zeros n) m (by simp only [ByteArray.size_append, zeros_size]; omega)

theorem wAt_append_zeros (a : ByteArray) (n j : Nat) : wAt (a ++ zeros n) j = wAt a j := by
  rw [wAt_unfold, wAt_unfold]
  simp only [get!_append_zeros]

theorem room_size (out : ByteArray) (w : Nat) (hal : out.size % 8 = 0) :
    (room out w).size % 8 = 0 ∧ 8 * w ≤ (room out w).size ∧ out.size ≤ (room out w).size := by
  unfold room
  split
  · omega
  · simp only [ByteArray.size_append, zeros_size]; omega

theorem wAt_room (out : ByteArray) (w j : Nat) : wAt (room out w) j = wAt out j := by
  unfold room
  split
  · rfl
  · exact wAt_append_zeros _ _ _

theorem stashBase_eq : stashBase = 2 ^ 60 := by unfold stashBase; decide

theorem toNat_toUInt64 (n : Nat) (h : n < 2 ^ 64) : n.toUInt64.toNat = n := by
  show (UInt64.ofNat n).toNat = n
  rw [UInt64.toNat_ofNat']; exact Nat.mod_eq_of_lt h

/-! ## Pairs written by a probe -/

theorem push2 (out : ByteArray) (hal : out.size % 8 = 0) (o c : Nat) (pos slot : UInt64)
    (hr : 8 * (o + 3 + 2 * c) ≤ out.size) :
    (wSet (wSet (wSet out (o + 1 + 2 * c) pos) (o + 2 + 2 * c) slot) o (c + 1).toUInt64).size = out.size ∧
    (∀ j', wAt (wSet (wSet (wSet out (o + 1 + 2 * c) pos) (o + 2 + 2 * c) slot) o (c + 1).toUInt64) j' =
      if j' = o then (c + 1).toUInt64 else if j' = o + 2 + 2 * c then slot else if j' = o + 1 + 2 * c then pos
      else wAt out j') := by
  have h1 : (wSet out (o + 1 + 2 * c) pos).size = out.size := wSet_size _ _ _
  have h2 : (wSet (wSet out (o + 1 + 2 * c) pos) (o + 2 + 2 * c) slot).size = out.size := by rw [wSet_size, h1]
  have a1 : (wSet out (o + 1 + 2 * c) pos).size % 8 = 0 := by rw [h1]; exact hal
  have a2 : (wSet (wSet out (o + 1 + 2 * c) pos) (o + 2 + 2 * c) slot).size % 8 = 0 := by rw [h2]; exact hal
  refine ⟨by rw [wSet_size, h2], ?_⟩
  intro j'
  rw [wAt_wSet_in _ a2 _ _ _ (by omega), wAt_wSet_in _ a1 _ _ _ (by omega), wAt_wSet_in _ hal _ _ _ (by omega)]

theorem shl1 (k : Nat) (hk : k < 64) : ((1 : UInt64) <<< k.toUInt64).toNat = 2 ^ k := by
  rw [UInt64.toNat_shiftLeft, toNat_toUInt64 k (by omega)]
  have : (1 : UInt64).toNat = 1 := rfl
  rw [this, Nat.mod_eq_of_lt hk, Nat.one_shiftLeft]
  exact Nat.mod_eq_of_lt (Nat.pow_lt_pow_right (by omega) hk)

theorem shl2 (k : Nat) (hk : k < 63) : ((2 : UInt64) <<< k.toUInt64).toNat = 2 ^ (k + 1) := by
  rw [UInt64.toNat_shiftLeft, toNat_toUInt64 k (by omega)]
  have : (2 : UInt64).toNat = 2 := rfl
  rw [this, Nat.mod_eq_of_lt (by omega : k < 64), Nat.shiftLeft_eq, Nat.pow_succ, Nat.mul_comm]
  exact Nat.mod_eq_of_lt (Nat.pow_lt_pow_right (by omega : 1 < 2) (by omega : k + 1 < 64))

theorem addrK_lt (k p : Nat) (a : UInt64) (hk : k ≤ 56) : addrK k p a < 2 ^ (k + 1) := by
  have h1 := shl1 k (by omega)
  have h2 := shl2 k (by omega)
  have p1 : (1 : UInt64) ≤ (1 : UInt64) <<< k.toUInt64 := by
    rw [UInt64.le_iff_toNat_le, h1]
    show 1 ≤ 2 ^ k
    exact Nat.one_le_two_pow
  have p2 : (1 : UInt64) ≤ (2 : UInt64) <<< k.toUInt64 := by
    rw [UInt64.le_iff_toNat_le, h2]
    show 1 ≤ 2 ^ (k + 1)
    exact Nat.one_le_two_pow
  have m1 : (((1 : UInt64) <<< k.toUInt64) - 1).toNat = 2 ^ k - 1 := by
    rw [UInt64.toNat_sub_of_le _ _ p1, h1]; rfl
  have m2 : (((2 : UInt64) <<< k.toUInt64) - 1).toNat = 2 ^ (k + 1) - 1 := by
    rw [UInt64.toNat_sub_of_le _ _ p2, h2]; rfl
  have l1 : (a &&& (((1 : UInt64) <<< k.toUInt64) - 1)).toNat ≤ 2 ^ k - 1 := by
    rw [UInt64.toNat_and, ← m1]; exact Nat.and_le_right
  have l2 : (a &&& (((2 : UInt64) <<< k.toUInt64) - 1)).toNat ≤ 2 ^ (k + 1) - 1 := by
    rw [UInt64.toNat_and, ← m2]; exact Nat.and_le_right
  have hp := Nat.one_le_two_pow (n := k)
  have hp2 := Nat.one_le_two_pow (n := k + 1)
  unfold addrK
  dsimp only
  split
  · omega
  · have : 2 ^ k ≤ 2 ^ (k + 1) := Nat.pow_le_pow_right (by omega) (by omega)
    omega

/-! ## Statements (proved below) -/

/-- The table after the inserts `ks` (`h1`, `h2`, `seq`) in order. -/
def build (k0 : Nat) (ks : List (UInt64 × UInt64 × Nat)) : Idx :=
  ks.foldl (fun x e => x.insert e.1 e.2.1 e.2.2) (Idx.new k0)

/-! ## Proof layers -/


/-! ## Shifts and constants as bits -/

theorem bit_shr' (a : UInt64) (s i : Nat) (hs : s < 64) : bit (a >>> s.toUInt64) i = bit a (i + s) := by
  rw [bit_shr, toNat_toUInt64 s (by omega), Nat.mod_eq_of_lt hs]

theorem bit_shl' (a : UInt64) (s i : Nat) (hs : s < 64) :
    bit (a <<< s.toUInt64) i = (decide (i < 64) && decide (s ≤ i) && bit a (i - s)) := by
  rw [bit_shl, toNat_toUInt64 s (by omega), Nat.mod_eq_of_lt hs]

@[simp] theorem bit_not (a : UInt64) (i : Nat) : bit (~~~a) i = (decide (i < 64) && !bit a i) := by
  have h : (~~~a).toNat = 2 ^ 64 - 1 - a.toNat := by
    rw [← UInt64.toNat_toBitVec]; simp [BitVec.toNat_not]
  by_cases hi : i < 64
  · unfold bit
    rw [h]
    have h1 := a.toNat_lt
    have h2 : (2 ^ 64 - 1 - a.toNat).testBit i = !a.toNat.testBit i := by
      have := Nat.testBit_two_pow_sub_succ (x := a.toNat) (n := 64) h1 i
      simpa [hi] using this
    simp [h2, hi]
  · simp [hi]; exact bit_high _ _ (by omega)

theorem bit_lit_low (c : UInt64) (n : Nat) (h : c.toNat = 2 ^ n - 1) (i : Nat) : bit c i = decide (i < n) := by
  simp [bit, h, Nat.testBit_two_pow_sub_one]

theorem bit_lit_pow (c : UInt64) (n : Nat) (h : c.toNat = 2 ^ n) (i : Nat) : bit c i = decide (n = i) := by
  simp [bit, h, Nat.testBit_two_pow]

theorem bit_lowMask (i : Nat) : bit lowMask i = decide (i < 40) := bit_lit_low _ 40 (by decide) i
theorem bit_choiceBit (i : Nat) : bit choiceBit i = decide (41 = i) := bit_lit_pow _ 41 (by decide) i
theorem bit_overBit (i : Nat) : bit overBit i = decide (40 = i) := bit_lit_pow _ 40 (by decide) i
theorem bit_m3fff (i : Nat) : bit 0x3FFF i = decide (i < 14) := bit_lit_low _ 14 (by decide) i
theorem bit_m1fff (i : Nat) : bit 0x1FFF i = decide (i < 13) := bit_lit_low _ 13 (by decide) i
theorem bit_m2000 (i : Nat) : bit 0x2000 i = decide (13 = i) := bit_lit_pow _ 13 (by decide) i
theorem bit_resField (i : Nat) : bit resField i = (decide (42 ≤ i) && decide (i < 56)) := by
  by_cases hi : i < 64
  · rcases q64 i hi with rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl
    all_goals (subst_vars; decide)
  · rw [bit_high _ _ (by omega)]; simp; omega
theorem bit_zero (i : Nat) : bit 0 i = false := by simp [bit]
theorem bit_ff (i : Nat) : bit 0xFF00_0200_0000_0000 i = ((decide (56 ≤ i) && decide (i < 64)) || decide (41 = i)) := by
  by_cases hi : i < 64
  · rcases q64 i hi with rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl
    all_goals (subst_vars; decide)
  · rw [bit_high _ _ (by omega)]; simp; omega


/-! ## belowTop and the hit test -/

theorem belowTop_toNat (r : UInt64) (h : r.toNat < 2 ^ 14) : (belowTop r).toNat = 2 ^ r.toNat.log2 - 1 := by
  have key0 : ∀ a : Nat, a < 64 → ∀ m : Nat, m < 256 →
      (belowTop (256 * a + m).toUInt64).toNat = 2 ^ (256 * a + m).log2 - 1 := by decide +kernel
  have key : ∀ n : Nat, n < 16384 → (belowTop n.toUInt64).toNat = 2 ^ n.log2 - 1 := by
    intro n hn
    have := key0 (n / 256) (by omega) (n % 256) (by omega)
    rwa [show 256 * (n / 256) + n % 256 = n by omega] at this
  have e : r.toNat.toUInt64 = r := by
    apply UInt64.toNat_inj.mp
    rw [toNat_toUInt64 _ r.toNat_lt]
  have := key r.toNat (by omega)
  rwa [e] at this

theorem bit_belowTop (r : UInt64) (h : r.toNat < 2 ^ 14) (i : Nat) :
    bit (belowTop r) i = decide (i < r.toNat.log2) := by
  unfold bit
  rw [belowTop_toNat r h, Nat.testBit_two_pow_sub_one]

theorem resOf_lt (s : UInt64) : (resOf s).toNat < 2 ^ 14 := by
  unfold resOf
  rw [UInt64.toNat_and]
  have : (0x3FFF : UInt64).toNat = 2 ^ 14 - 1 := rfl
  rw [this]
  exact Nat.lt_of_le_of_lt Nat.and_le_right (by decide)

theorem bit_shr_lit (a s : UInt64) (n : Nat) (hn : s.toNat = n) (hn' : n < 64) (i : Nat) :
    bit (a >>> s) i = bit a (i + n) := by
  rw [bit_shr, hn, Nat.mod_eq_of_lt hn']

theorem bit_resOf (s : UInt64) (i : Nat) : bit (resOf s) i = (decide (i < 14) && bit s (i + 42)) := by
  unfold resOf
  rw [bit_and, bit_shr_lit _ _ 42 (by decide) (by omega), bit_m3fff]
  simp [Bool.and_comm]

theorem hit_of (s q x : UInt64) (ht : s &&& 0xFF00_0200_0000_0000 = q)
    (hr : ∀ i, i < (resOf s).toNat.log2 → bit (resOf s) i = bit x i) : hit s q x = true := by
  unfold hit
  have h2 : ((resOf s ^^^ x) &&& belowTop (resOf s)) = 0 := by
    apply bit_ext
    intro i _
    rw [bit_and, bit_xor, bit_belowTop _ (resOf_lt s), bit_zero]
    by_cases hi : i < (resOf s).toNat.log2
    · simp [hr i hi]
    · simp [hi]
  simp [ht, h2]

/-! ## Addresses -/

theorem land_mask1 (a : UInt64) (k : Nat) (hk : k < 64) :
    (a &&& (((1 : UInt64) <<< k.toUInt64) - 1)).toNat = a.toNat % 2 ^ k := by
  have h1 := shl1 k hk
  have p1 : (1 : UInt64) ≤ (1 : UInt64) <<< k.toUInt64 := by
    rw [UInt64.le_iff_toNat_le, h1]; show 1 ≤ 2 ^ k; exact Nat.one_le_two_pow
  have m1 : (((1 : UInt64) <<< k.toUInt64) - 1).toNat = 2 ^ k - 1 := by
    rw [UInt64.toNat_sub_of_le _ _ p1, h1]; rfl
  rw [UInt64.toNat_and, m1, Nat.and_two_pow_sub_one_eq_mod]

theorem land_mask2 (a : UInt64) (k : Nat) (hk : k < 63) :
    (a &&& (((2 : UInt64) <<< k.toUInt64) - 1)).toNat = a.toNat % 2 ^ (k + 1) := by
  have h2 := shl2 k hk
  have p2 : (1 : UInt64) ≤ (2 : UInt64) <<< k.toUInt64 := by
    rw [UInt64.le_iff_toNat_le, h2]; show 1 ≤ 2 ^ (k + 1); exact Nat.one_le_two_pow
  have m2 : (((2 : UInt64) <<< k.toUInt64) - 1).toNat = 2 ^ (k + 1) - 1 := by
    rw [UInt64.toNat_sub_of_le _ _ p2, h2]; rfl
  rw [UInt64.toNat_and, m2, Nat.and_two_pow_sub_one_eq_mod]

theorem addrK_eq (k p : Nat) (hk : k < 63) (a : UInt64) :
    addrK k p a = if a.toNat % 2 ^ k < p then a.toNat % 2 ^ (k + 1) else a.toNat % 2 ^ k := by
  unfold addrK
  dsimp only
  rw [land_mask1 a k (by omega), land_mask2 a k hk]

theorem mod2k (n k : Nat) : n % 2 ^ (k + 1) = n % 2 ^ k ∨ n % 2 ^ (k + 1) = n % 2 ^ k + 2 ^ k := by
  rw [Nat.mod_pow_succ]
  have h : n / 2 ^ k % 2 < 2 := Nat.mod_lt _ (by omega)
  rcases (by omega : n / 2 ^ k % 2 = 0 ∨ n / 2 ^ k % 2 = 1) with h | h <;> rw [h]
  · left; omega
  · right; omega

theorem lvlK_eq (k p b : Nat) (hk : k < 64) (hb : b < 2 ^ 64) :
    lvlK k p b = if b < p ∨ 2 ^ k ≤ b then k + 1 else k := by
  unfold lvlK
  have hs : (b.toUInt64 >>> k.toUInt64).toNat = b / 2 ^ k := by
    rw [UInt64.toNat_shiftRight, toNat_toUInt64 b hb, toNat_toUInt64 k (by omega), Nat.mod_eq_of_lt hk,
      Nat.shiftRight_eq_div_pow]
  have hne : (b.toUInt64 >>> k.toUInt64 != 0) = decide (2 ^ k ≤ b) := by
    by_cases h : 2 ^ k ≤ b
    · have h1 : b / 2 ^ k ≠ 0 := by have := Nat.div_pos h (Nat.two_pow_pos k); omega
      have h2 : (b.toUInt64 >>> k.toUInt64) ≠ 0 := fun e => h1 (by rw [← hs, e]; rfl)
      simp [h, h2]
    · have h1 : b / 2 ^ k = 0 := Nat.div_eq_of_lt (by omega)
      have h2 : (b.toUInt64 >>> k.toUInt64) = 0 := by
        apply UInt64.toNat_inj.mp; rw [hs, h1]; rfl
      simp [h, h2]
  rw [hne]
  simp

/-- A bucket and the level of its address word: the word agrees with the bucket on the low `l` bits. -/
theorem addr_lvl (k p : Nat) (hk : k ≤ 56) (hp : p < 2 ^ k) (a : UInt64) :
    ∃ l, lvlK k p (addrK k p a) = l ∧ (l = k ∨ l = k + 1) ∧ addrK k p a < 2 ^ l ∧ a.toNat % 2 ^ l = addrK k p a := by
  have h64 : 2 ^ (k + 1) < 2 ^ 64 := Nat.pow_lt_pow_right (by omega) (by omega)
  have hm := Nat.mod_lt a.toNat (Nat.two_pow_pos k)
  have hm1 := Nat.mod_lt a.toNat (Nat.two_pow_pos (k + 1))
  by_cases hc : a.toNat % 2 ^ k < p
  · refine ⟨k + 1, ?_, Or.inr rfl, ?_, ?_⟩
    · rw [lvlK_eq k p _ (by omega) (by rw [addrK_eq k p (by omega), if_pos hc]; omega)]
      rw [if_pos]
      rw [addrK_eq k p (by omega), if_pos hc]
      rcases mod2k a.toNat k with h | h
      · left; omega
      · right; omega
    · rw [addrK_eq k p (by omega), if_pos hc]; exact hm1
    · rw [addrK_eq k p (by omega), if_pos hc]
  · refine ⟨k, ?_, Or.inl rfl, ?_, ?_⟩
    · rw [lvlK_eq k p _ (by omega) (by rw [addrK_eq k p (by omega), if_neg hc]; omega)]
      rw [if_neg]
      rw [addrK_eq k p (by omega), if_neg hc]
      omega
    · rw [addrK_eq k p (by omega), if_neg hc]; exact hm
    · rw [addrK_eq k p (by omega), if_neg hc]

theorem addrK_lt_nb (k p : Nat) (hk : k ≤ 56) (hp : p ≤ 2 ^ k) (a : UInt64) : addrK k p a < 2 ^ k + p := by
  have hm := Nat.mod_lt a.toNat (Nat.two_pow_pos k)
  rw [addrK_eq k p (by omega)]
  split
  · rcases mod2k a.toNat k with h | h <;> omega
  · omega


/-! ## Slots that belong to a key, and moving them to the other bucket -/

theorem bit_shl_lit (a s : UInt64) (n : Nat) (hn : s.toNat = n) (hn' : n < 64) (i : Nat) :
    bit (a <<< s) i = (decide (i < 64) && decide (n ≤ i) && bit a (i - n)) := by
  rw [bit_shl, hn, Nat.mod_eq_of_lt hn']

/-- The tag mask of a slot: fingerprint, choice bit. -/
def tagMask : UInt64 := 0xFF00_0200_0000_0000

/-- Slot `s` in bucket `b` is a faithful slot for the address word `A` (fingerprint `f`, choice `c`): `b` is the bucket
    of `A`, the tag is `f` and `c`, and the known reserve bits are bits of `A` above the bucket's level. -/
def SlotOK (k p : Nat) (A f : UInt64) (c : Bool) (b : Nat) (s : UInt64) : Prop :=
  addrK k p A = b ∧ s &&& tagMask = (f <<< (56 : UInt64)) ||| (if c then choiceBit else (0 : UInt64)) ∧
  ∀ i, i < (resOf s).toNat.log2 → bit (resOf s) i = bit A (lvlK k p b + i)

theorem bit_tagMask (i : Nat) : bit tagMask i = ((decide (56 ≤ i) && decide (i < 64)) || decide (41 = i)) := bit_ff i

theorem agree_mod (x y : UInt64) (n : Nat) (h : ∀ i, i < n → bit x i = bit y i) :
    x.toNat % 2 ^ n = y.toNat % 2 ^ n := by
  apply Nat.eq_of_testBit_eq
  intro i
  rw [Nat.testBit_mod_two_pow, Nat.testBit_mod_two_pow]
  by_cases hi : i < n
  · have := h i hi
    unfold bit at this
    simp [hi, this]
  · simp [hi]

theorem log2_le13 (n : Nat) (h : n < 2 ^ 14) : n.log2 ≤ 13 := by
  by_cases hn : n = 0
  · simp [hn]
  · have := (Nat.log2_lt hn).2 h
    omega

theorem uint_log2 (r : UInt64) : r.log2.toNat = r.toNat.log2 := rfl

theorem bit_shl56 (a : UInt64) (i : Nat) :
    bit (a <<< (56 : UInt64)) i = (decide (i < 64) && decide (56 ≤ i) && bit a (i - 56)) :=
  bit_shl_lit a 56 56 (by decide) (by omega) i

theorem slot_shr56 (f : UInt64) (hf : f.toNat < 256) (c : Bool) (s : UInt64)
    (h : s &&& tagMask = (f <<< (56 : UInt64)) ||| (if c then choiceBit else (0 : UInt64))) : s >>> (56 : UInt64) = f := by
  apply bit_ext
  intro i hi
  rw [bit_shr_lit _ _ 56 (by decide) (by omega)]
  by_cases hi8 : i < 8
  · have e1 : bit tagMask (i + 56) = true := by
      rw [bit_tagMask]; simp <;> omega
    have hite : bit (if c then choiceBit else (0 : UInt64)) (i + 56) = false := by
      cases c
      · exact bit_zero _
      · show bit choiceBit (i + 56) = false
        rw [bit_choiceBit]
        exact decide_eq_false (by omega)
    have e2 : decide (i + 56 < 64) = true := decide_eq_true (by omega)
    have e3 : decide (56 ≤ i + 56) = true := decide_eq_true (by omega)
    have hh : bit (s &&& tagMask) (i + 56) = bit ((f <<< (56 : UInt64)) ||| (if c then choiceBit else (0 : UInt64))) (i + 56) :=
      congrArg (fun x => bit x (i + 56)) h
    rw [bit_and, bit_or, e1, hite, bit_shl56] at hh
    simp only [e2, e3, Nat.add_sub_cancel, Bool.and_true, Bool.true_and, Bool.or_false] at hh
    exact hh
  · rw [bit_high s (i + 56) (by omega)]
    unfold bit
    rw [Nat.testBit_lt_two_pow (Nat.lt_of_lt_of_le (show f.toNat < 2 ^ 8 from hf)
      (Nat.pow_le_pow_right (by omega : 0 < 2) (by omega : 8 ≤ i)))]

theorem otherOf_agree (k p b : Nat) (hk : k ≤ 48) (hp : p < 2 ^ k) (A f : UInt64) (hf : f.toNat < 256) (c : Bool)
    (s : UInt64) (h : SlotOK k p A f c b s) :
    ∀ i, i < lvlK k p b + (resOf s).toNat.log2 → bit (otherOf (lvlK k p b) b s) i = bit (otherWord A f) i := by
  obtain ⟨hb, htag, hres⟩ := h
  obtain ⟨l, hl, hl2, hlt, hmod⟩ := addr_lvl k p (by omega) hp A
  rw [hb] at hl hlt hmod
  have hsf := slot_shr56 f hf c s htag
  have hb64 : b < 2 ^ 64 := Nat.lt_of_lt_of_le hlt (Nat.pow_le_pow_right (by omega) (by omega))
  have hbit_b : ∀ i, bit b.toUInt64 i = b.testBit i := by
    intro i; unfold bit; rw [toNat_toUInt64 b hb64]
  have ht13 := log2_le13 _ (resOf_lt s)
  intro i hi
  rw [hl] at hi ⊢
  unfold otherOf
  dsimp only
  rw [hsf]
  unfold otherWord
  rw [bit_xor, bit_xor]
  congr 1
  rw [bit_or, bit_shl' _ l _ (by omega), bit_and, bit_belowTop _ (resOf_lt s), hbit_b]
  by_cases hil : i < l
  · have : b.testBit i = A.toNat.testBit i := by
      rw [← hmod, Nat.testBit_mod_two_pow]; simp [hil]
    have h2 : decide (l ≤ i) = false := by simp; omega
    simp [h2, this, bit]
  · have h1 : b.testBit i = false :=
      Nat.testBit_lt_two_pow (Nat.lt_of_lt_of_le hlt (Nat.pow_le_pow_right (by omega) (by omega)))
    have h3 := hres (i - l) (by omega)
    rw [hl] at h3
    have h4 : i - l < (resOf s).toNat.log2 := by omega
    have h5 : l + (i - l) = i := by omega
    rw [h5] at h3
    have h6 : decide (i < 64) = true := by simp; omega
    have h7 : decide (l ≤ i) = true := by simp; omega
    simp [h1, h3, h4, h6, h7]

theorem altB_spec (k p b : Nat) (hk : k ≤ 48) (hp : p < 2 ^ k) (A f : UInt64) (hf : f.toNat < 256) (c : Bool)
    (s : UInt64) (h : SlotOK k p A f c b s) (hne : altB k p b s ≠ noB) :
    altB k p b s = addrK k p (otherWord A f) := by
  have hag := otherOf_agree k p b hk hp A f hf c s h
  obtain ⟨l, hl, hl2, hlt, hmod⟩ := addr_lvl k p (by omega) hp A
  have hb := h.1
  rw [hb] at hl
  by_cases hr : (resOf s == 0) = true
  · unfold altB at hne
    simp only [hr, if_true] at hne
    exact absurd rfl hne
  · unfold altB at hne ⊢
    rw [if_neg hr] at hne ⊢
    dsimp only at hne ⊢
    generalize ha : otherOf (lvlK k p b) b s = a at hag hne ⊢
    rw [hl] at hag hne ⊢
    have hmodag : ∀ n, n ≤ l + (resOf s).toNat.log2 → a.toNat % 2 ^ n = (otherWord A f).toNat % 2 ^ n :=
      fun n hn => agree_mod _ _ n (fun i hi => hag i (by omega))
    have hk2 : k ≤ l := by omega
    rw [land_mask1 a k (by omega)] at hne ⊢
    rw [addrK_eq k p (by omega), ← hmodag k (by omega)]
    by_cases hlo : a.toNat % 2 ^ k < p
    · by_cases hc2 : (decide (l > k) || decide (resOf s ≥ 2)) = true
      · simp only [if_pos hlo, if_pos hc2] at hne ⊢
        rw [land_mask2 a k (by omega)] at hne ⊢
        have hk1 : k + 1 ≤ l + (resOf s).toNat.log2 := by
          rcases Bool.or_eq_true_iff.mp hc2 with h1 | h1
          · have := of_decide_eq_true h1; omega
          · have h2 := of_decide_eq_true h1
            have h3 : 2 ≤ (resOf s).toNat := UInt64.le_iff_toNat_le.mp h2
            have h4 : 1 ≤ (resOf s).toNat.log2 := (Nat.le_log2 (by omega)).2 (by simpa using h3)
            omega
        rw [hmodag (k + 1) hk1]
      · simp only [if_pos hlo, if_neg hc2] at hne
        exact absurd rfl hne
    · simp only [if_neg hlo] at hne ⊢


theorem bit_shl42 (a : UInt64) (i : Nat) :
    bit (a <<< (42 : UInt64)) i = (decide (i < 64) && decide (42 ≤ i) && bit a (i - 42)) :=
  bit_shl_lit a 42 42 (by decide) (by omega) i

theorem bit_hi14 (R : UInt64) (h : R.toNat < 2 ^ 14) (i : Nat) (hi : 14 ≤ i) : bit R i = false := by
  unfold bit
  exact Nat.testBit_lt_two_pow (Nat.lt_of_lt_of_le h (Nat.pow_le_pow_right (by omega) hi))

theorem resOf_withRes (s R : UInt64) (h : R.toNat < 2 ^ 14) : resOf (withRes s R) = R := by
  apply bit_ext
  intro i hi
  rw [bit_resOf]
  unfold withRes
  rw [bit_or, bit_and, bit_not, bit_resField, bit_shl42]
  by_cases hi14 : i < 14
  · have e1 : decide (i + 42 < 64) = true := decide_eq_true (by omega)
    have e2 : decide (42 ≤ i + 42) = true := decide_eq_true (by omega)
    have e3 : decide (i + 42 < 56) = true := decide_eq_true (by omega)
    simp [hi14, e1, e2, e3]
  · have := bit_hi14 R h i (by omega)
    simp [hi14, this]

theorem withRes_tag (s R : UInt64) (h : R.toNat < 2 ^ 14) : withRes s R &&& tagMask = s &&& tagMask := by
  apply bit_ext
  intro i hi
  unfold withRes
  rw [bit_and, bit_and, bit_or, bit_and, bit_not, bit_resField, bit_shl42, bit_tagMask]
  by_cases h1 : 56 ≤ i
  · have e1 : decide (56 ≤ i) = true := decide_eq_true h1
    have e2 : decide (i < 64) = true := decide_eq_true hi
    have e3 : decide (42 ≤ i) = true := decide_eq_true (by omega)
    have e4 : decide (i < 56) = false := decide_eq_false (by omega)
    have := bit_hi14 R h (i - 42) (by omega)
    simp [e1, e2, e3, e4, this]
  · by_cases h2 : i = 41
    · subst h2
      simp
    · have e1 : decide (56 ≤ i) = false := decide_eq_false h1
      have e2 : decide (41 = i) = false := decide_eq_false (fun e => h2 e.symm)
      simp [e1, e2]

theorem withRes_low (s R : UInt64) : withRes s R &&& lowMask = s &&& lowMask := by
  apply bit_ext
  intro i hi
  unfold withRes
  rw [bit_and, bit_and, bit_or, bit_and, bit_not, bit_resField, bit_shl42, bit_lowMask]
  by_cases h1 : i < 40
  · have e1 : decide (42 ≤ i) = false := decide_eq_false (by omega)
    simp [e1, h1, hi]
  · simp [h1]

theorem xor_choice_low (s : UInt64) : (s ^^^ choiceBit) &&& lowMask = s &&& lowMask := by
  apply bit_ext
  intro i hi
  rw [bit_and, bit_and, bit_xor, bit_lowMask, bit_choiceBit]
  by_cases h1 : i < 40
  · have e : decide (41 = i) = false := decide_eq_false (by omega)
    simp [e, h1]
  · simp [h1]

theorem xor_choice_tag (s : UInt64) : (s ^^^ choiceBit) &&& tagMask = (s &&& tagMask) ^^^ choiceBit := by
  apply bit_ext
  intro i hi
  rw [bit_and, bit_xor, bit_xor, bit_and, bit_tagMask, bit_choiceBit]
  by_cases h : i = 41
  · subst h; simp
  · have e : decide (41 = i) = false := decide_eq_false (fun e => h e.symm)
    simp [e]

theorem flip_tag (f : UInt64) (c : Bool) :
    ((f <<< (56 : UInt64)) ||| (if c then choiceBit else (0 : UInt64))) ^^^ choiceBit =
      (f <<< (56 : UInt64)) ||| (if (!c) = true then choiceBit else (0 : UInt64)) := by
  apply bit_ext
  intro i hi
  rw [bit_xor, bit_or, bit_or, bit_shl56]
  by_cases h : i = 41
  · subst h
    cases c <;> simp [bit_choiceBit, bit_zero]
  · have e : decide (41 = i) = false := decide_eq_false (fun e => h e.symm)
    cases c <;> simp [bit_choiceBit, bit_zero, e]

theorem mask_toNat (v : Nat) (hv : v < 64) : (((1 : UInt64) <<< v.toUInt64) - 1).toNat = 2 ^ v - 1 := by
  have h1 := shl1 v hv
  have p1 : (1 : UInt64) ≤ (1 : UInt64) <<< v.toUInt64 := by
    rw [UInt64.le_iff_toNat_le, h1]; show 1 ≤ 2 ^ v; exact Nat.one_le_two_pow
  rw [UInt64.toNat_sub_of_le _ _ p1, h1]; rfl

theorem bit_one (j : Nat) : bit (1 : UInt64) j = decide (j = 0) := by
  have := bit_lit_pow 1 0 rfl j
  rw [this]
  by_cases h : j = 0 <;> simp [h, eq_comm]


/-! ## Bucket memory -/

/-- Every segment is 1023 buckets (65,472 bytes). -/
def SegsWf (segs : Array ByteArray) : Prop := ∀ i (h : i < segs.size), (segs[i]'h).size = 65472

theorem getD_seg (segs : Array ByteArray) (i : Nat) :
    segs.getD i .empty = if h : i < segs.size then segs[i]'h else .empty := by
  by_cases h : i < segs.size
  · simp [h, Array.getD_eq_getD_getElem?]
  · simp [h, Array.getD_eq_getD_getElem?]

theorem slotAt_eq (segs : Array ByteArray) (b j : Nat) (hj : j < 8) :
    slotAt segs b j = wAt (segs.getD (b / 1023) .empty) (8 * (b % 1023) + j) := by
  unfold slotAt
  have e3 : j &&& 7 = j := by
    have := Nat.and_two_pow_sub_one_eq_mod j 3
    have h8 : j % 8 = j := Nat.mod_eq_of_lt hj
    simpa [h8] using this
  rw [e3]

theorem slotSet_eq (segs : Array ByteArray) (b j : Nat) (hj : j < 8) (v : UInt64) :
    slotSet segs b j v = segs.modify (b / 1023) fun s => wSet s (8 * (b % 1023) + j) v := by
  unfold slotSet
  have e3 : j &&& 7 = j := by
    have := Nat.and_two_pow_sub_one_eq_mod j 3
    have h8 : j % 8 = j := Nat.mod_eq_of_lt hj
    simpa [h8] using this
  rw [e3]

theorem getD_modify (segs : Array ByteArray) (i n : Nat) (f : ByteArray → ByteArray) :
    (segs.modify i f).getD n .empty =
      if i = n ∧ n < segs.size then f (segs.getD n .empty) else segs.getD n .empty := by
  rw [getD_seg, getD_seg]
  by_cases hn : n < segs.size
  · have hn' : n < (segs.modify i f).size := by simpa using hn
    rw [dif_pos hn', dif_pos hn]
    rw [Array.getElem_modify hn']
    by_cases hi : i = n
    · subst hi; simp [hn]
    · simp [hi]
  · have hn' : ¬ n < (segs.modify i f).size := by simpa using hn
    rw [dif_neg hn', dif_neg hn]
    simp [hn]

theorem segsWf_slotSet (segs : Array ByteArray) (hw : SegsWf segs) (b j : Nat) (hj : j < 8) (v : UInt64) :
    SegsWf (slotSet segs b j v) := by
  rw [slotSet_eq _ _ _ hj]
  intro i hi
  have hi' : i < segs.size := by simpa using hi
  rw [Array.getElem_modify hi]
  by_cases h : b / 1023 = i
  · rw [if_pos h, wSet_size]; exact hw i hi'
  · rw [if_neg h]; exact hw i hi'

theorem slotAt_slotSet (segs : Array ByteArray) (hw : SegsWf segs) (b' j' : Nat) (hj' : j' < 8) (v : UInt64)
    (b j : Nat) (hj : j < 8) :
    slotAt (slotSet segs b' j' v) b j =
      if b = b' ∧ j = j' ∧ b' / 1023 < segs.size then v else slotAt segs b j := by
  rw [slotAt_eq _ _ _ hj, slotAt_eq _ _ _ hj, slotSet_eq _ _ _ hj', getD_modify]
  by_cases hc : b' / 1023 = b / 1023 ∧ b / 1023 < segs.size
  · rw [if_pos hc]
    have hsz : (segs.getD (b / 1023) .empty).size = 65472 := by
      rw [getD_seg, dif_pos hc.2]; exact hw _ hc.2
    rw [wAt_wSet _ (by rw [hsz])]
    split <;> split <;> first | rfl | (exfalso; omega)
  · rw [if_neg hc]
    have : ¬ (b = b' ∧ j = j' ∧ b' / 1023 < segs.size) := by
      rintro ⟨rfl, _, h3⟩
      exact hc ⟨rfl, h3⟩
    rw [if_neg this]

theorem slotAt_ne_zero_inb (segs : Array ByteArray) (b j : Nat) (hj : j < 8) (h : slotAt segs b j ≠ 0) :
    b / 1023 < segs.size := by
  by_cases hb : b / 1023 < segs.size
  · exact hb
  · exfalso
    apply h
    rw [slotAt_eq _ _ _ hj, getD_seg, dif_neg hb]
    have e0 : ByteArray.empty.size = 0 := rfl
    exact wAt_oob _ _ (by omega)


/-! ## Used slots of a bucket -/

theorem count_fold (e : Nat → Bool) (N : Nat) (hp : ∀ j, j + 1 < N → e j = true → e (j + 1) = true) :
    ∀ n, n ≤ N →
      ((List.range n).foldl (fun u j => if e j then u else u + 1) 0 ≤ n ∧
      (∀ j, j < (List.range n).foldl (fun u j => if e j then u else u + 1) 0 → e j = false) ∧
      (∀ j, (List.range n).foldl (fun u j => if e j then u else u + 1) 0 ≤ j → j < n → e j = true)) := by
  intro n
  induction n with
  | zero => intro _; simp
  | succ n ih =>
    intro hn
    obtain ⟨h1, h2, h3⟩ := ih (by omega)
    rw [List.range_succ, List.foldl_append]
    simp only [List.foldl_cons, List.foldl_nil]
    generalize (List.range n).foldl (fun u j => if e j then u else u + 1) 0 = u at *
    by_cases hen : e n = true
    · simp only [hen, if_true]
      refine ⟨by omega, h2, ?_⟩
      intro j hj1 hj2
      by_cases jn : j = n
      · subst jn; exact hen
      · exact h3 j hj1 (by omega)
    · have hen' : e n = false := by simpa using hen
      have hu : u = n := by
        by_cases hlt : u < n
        · exfalso
          have := h3 (n - 1) (by omega) (by omega)
          have h4 := hp (n - 1) (by omega) this
          rw [show n - 1 + 1 = n by omega] at h4
          exact hen h4
        · omega
      subst hu
      simp only [hen', Bool.false_eq_true, if_false]
      refine ⟨by omega, ?_, ?_⟩
      · intro j hj
        by_cases jn : j = u
        · subst jn; exact hen'
        · exact h2 j (by omega)
      · intro j hj1 hj2; omega

theorem usedIn_spec (segs : Array ByteArray) (b : Nat)
    (hp : ∀ j, j + 1 < 8 → isEmpty (slotAt segs b j) = true → isEmpty (slotAt segs b (j + 1)) = true) :
    usedIn segs b ≤ 8 ∧ (∀ j, j < usedIn segs b → isEmpty (slotAt segs b j) = false) ∧
    (∀ j, usedIn segs b ≤ j → j < 8 → isEmpty (slotAt segs b j) = true) := by
  unfold usedIn
  exact count_fold (fun j => isEmpty (slotAt segs b j)) 8 hp 8 (Nat.le_refl _)

/-! ## The hit mask -/

theorem bit_one_shl (j i : Nat) (hj : j < 64) : bit ((1 : UInt64) <<< j.toUInt64) i = decide (i = j) := by
  rw [bit_shl' _ j _ hj, bit_one]
  rw [Bool.eq_iff_iff]
  simp
  omega

theorem mask_fold (cond : Nat → Bool) : ∀ (L : List Nat) (m : UInt64) (i : Nat), (∀ j ∈ L, j < 64) →
    bit (L.foldl (fun m j => if cond j then m ||| ((1 : UInt64) <<< j.toUInt64) else m) m) i =
      (bit m i || (decide (i ∈ L) && cond i)) := by
  intro L
  induction L with
  | nil => intro m i _; simp
  | cons j L ih =>
    intro m i hL
    simp only [List.foldl_cons]
    have hj : j < 64 := hL j (List.mem_cons_self ..)
    rw [ih _ i (fun x hx => hL x (List.mem_cons_of_mem _ hx))]
    by_cases hc : cond j = true
    · simp only [hc, if_true, bit_or, bit_one_shl j i hj]
      by_cases hij : i = j
      · subst hij; simp [hc]
      · simp [hij]
    · have hc' : cond j = false := by simpa using hc
      simp only [hc', if_false, Bool.false_eq_true]
      by_cases hij : i = j
      · subst hij; simp [hc']
      · simp [hij]

theorem hitMask_bit (segs : Array ByteArray) (b : Nat) (q x : UInt64) (j : Nat) (hj : j < 8) :
    bit (hitMask segs b q x) j = (!isEmpty (slotAt segs b j) && hit (slotAt segs b j) q x) := by
  unfold hitMask
  have := mask_fold (fun j => !isEmpty (slotAt segs b j) && hit (slotAt segs b j) q x) (List.range 8) 0 j
    (fun x hx => by have := List.mem_range.mp hx; omega)
  simp only [bit_zero, Bool.false_or] at this
  have hm : decide (j ∈ List.range 8) = true := by simp [hj]
  rw [hm, Bool.true_and] at this
  exact this

/-! ## What a probe writes -/

/-- The pair `(pos, slot)` is among the first `c` pairs of the list at word `o` of `out`. -/
def Has (out : ByteArray) (o c : Nat) (pos slot : UInt64) : Prop :=
  ∃ t, t < c ∧ wAt out (o + 1 + 2 * t) = pos ∧ wAt out (o + 2 + 2 * t) = slot

theorem has_push (out : ByteArray) (hal : out.size % 8 = 0) (o c : Nat) (pos slot : UInt64)
    (hr : 8 * (o + 3 + 2 * c) ≤ out.size) (pos' slot' : UInt64) :
    (Has out o c pos' slot' →
      Has (wSet (wSet (wSet out (o + 1 + 2 * c) pos) (o + 2 + 2 * c) slot) o (c + 1).toUInt64) o (c + 1) pos' slot') ∧
    Has (wSet (wSet (wSet out (o + 1 + 2 * c) pos) (o + 2 + 2 * c) slot) o (c + 1).toUInt64) o (c + 1) pos slot := by
  obtain ⟨_, hw⟩ := push2 out hal o c pos slot hr
  constructor
  · rintro ⟨t, ht, h1, h2⟩
    refine ⟨t, by omega, ?_, ?_⟩
    · have e1 : ¬ (o + 1 + 2 * t = o) := by omega
      have e2 : ¬ (o + 1 + 2 * t = o + 2 + 2 * c) := by omega
      have e3 : ¬ (o + 1 + 2 * t = o + 1 + 2 * c) := by omega
      rw [hw]; simp only [e1, e2, e3, if_false]; exact h1
    · have e1 : ¬ (o + 2 + 2 * t = o) := by omega
      have e2 : ¬ (o + 2 + 2 * t = o + 2 + 2 * c) := by omega
      have e3 : ¬ (o + 2 + 2 * t = o + 1 + 2 * c) := by omega
      rw [hw]; simp only [e1, e2, e3, if_false]; exact h2
  · refine ⟨c, by omega, ?_, ?_⟩
    · have e1 : ¬ (o + 1 + 2 * c = o) := by omega
      have e2 : ¬ (o + 1 + 2 * c = o + 2 + 2 * c) := by omega
      rw [hw]; simp only [e1, e2, if_false, if_true]
    · have e1 : ¬ (o + 2 + 2 * c = o) := by omega
      rw [hw]; simp only [e1, if_false, if_true]

theorem and1_beq (x : UInt64) : ((x &&& 1) == 1) = bit x 0 := by
  have h1 : ∀ i, bit (x &&& 1) i = (bit x i && decide (i = 0)) := by
    intro i; rw [bit_and, bit_one]
  by_cases hx : bit x 0 = true
  · have : x &&& 1 = 1 := by
      apply bit_ext
      intro i _
      rw [h1, bit_one]
      by_cases hi : i = 0
      · subst hi; simp [hx]
      · simp [hi]
    simp [this, hx]
  · have hx' : bit x 0 = false := by simpa using hx
    have : x &&& 1 ≠ 1 := fun e => by
      have := congrArg (fun y => bit y 0) e
      simp [h1, bit_one, hx'] at this
    simp [this, hx']

theorem shr_ne_zero (m : UInt64) (j j' : Nat) (hj : j ≤ j') (hj' : j' < 64) (hb : bit m j' = true) :
    (m >>> j.toUInt64 == 0) = false := by
  rw [Bool.eq_false_iff]
  intro h
  have h0 : m >>> j.toUInt64 = 0 := beq_iff_eq.mp h
  have h1 : bit (m >>> j.toUInt64) (j' - j) = bit 0 (j' - j) := congrArg (fun y => bit y (j' - j)) h0
  rw [bit_shr' _ j _ (by omega), Nat.sub_add_cancel hj, hb, bit_zero] at h1
  exact absurd h1 (by simp)


theorem scanB_has (segs : Array ByteArray) (b : Nat) (m : UInt64) (o : Nat) :
    ∀ (fuel j : Nat) (out : ByteArray) (c : Nat), j + fuel ≤ 8 → out.size % 8 = 0 → 8 * (o + 33) ≤ out.size →
      (wAt out o).toNat = c → c + fuel ≤ 16 →
      (scanB segs b m o out j fuel).size = out.size ∧ ∃ c', c ≤ c' ∧ c' ≤ c + fuel ∧
        (wAt (scanB segs b m o out j fuel) o).toNat = c' ∧
        (∀ pos slot, Has out o c pos slot → Has (scanB segs b m o out j fuel) o c' pos slot) ∧
        (∀ j', j ≤ j' → j' < j + fuel → bit m j' = true →
          Has (scanB segs b m o out j fuel) o c' (8 * b + j').toUInt64 (slotAt segs b j')) := by
  intro fuel
  induction fuel with
  | zero =>
    intro j out c _ _ _ hc _
    have e : scanB segs b m o out j 0 = out := by simp [scanB]
    rw [e]
    exact ⟨rfl, c, Nat.le_refl _, by omega, hc, fun _ _ h => h, fun j' h1 h2 _ => absurd h2 (by omega)⟩
  | succ fuel ih =>
    intro j out c hj hal hsz hc hcf
    rw [scanB]
    by_cases h0 : (m >>> j.toUInt64 == 0) = true
    · rw [if_pos h0]
      refine ⟨rfl, c, Nat.le_refl _, by omega, hc, fun _ _ h => h, ?_⟩
      intro j' h1 h2 hb
      have := shr_ne_zero m j j' h1 (by omega) hb
      rw [h0] at this
      exact absurd this (by simp)
    · rw [if_neg h0]
      by_cases h1 : ((m >>> j.toUInt64) &&& 1 == 1) = true
      · rw [if_pos h1]
        dsimp only
        rw [hc]
        obtain ⟨hs, hw⟩ := push2 out hal o c (8 * b + j).toUInt64 (slotAt segs b j) (by omega)
        have hal' : (wSet (wSet (wSet out (o + 1 + 2 * c) (8 * b + j).toUInt64) (o + 2 + 2 * c) (slotAt segs b j)) o
            (c + 1).toUInt64).size % 8 = 0 := by rw [hs]; exact hal
        have hcnt : (wAt (wSet (wSet (wSet out (o + 1 + 2 * c) (8 * b + j).toUInt64) (o + 2 + 2 * c) (slotAt segs b j)) o
            (c + 1).toUInt64) o).toNat = c + 1 := by
          rw [hw]; simp only [if_true]; exact toNat_toUInt64 _ (by omega)
        have hp := has_push out hal o c (8 * b + j).toUInt64 (slotAt segs b j) (by omega)
        obtain ⟨hs2, c', hc1, hc2, hc3, hprev, hlate⟩ :=
          ih (j + 1) _ (c + 1) (by omega) hal' (by omega) hcnt (by omega)
        refine ⟨by rw [hs2, hs], c', by omega, by omega, hc3,
          fun pos slot h => hprev pos slot ((hp pos slot).1 h), ?_⟩
        intro j' h1' h2' hb
        by_cases jj : j' = j
        · subst jj
          exact hprev _ _ (hp 0 0).2
        · exact hlate j' (by omega) (by omega) hb
      · rw [if_neg h1]
        obtain ⟨hs2, c', hc1, hc2, hc3, hprev, hlate⟩ := ih (j + 1) out c (by omega) hal hsz hc (by omega)
        refine ⟨hs2, c', hc1, by omega, hc3, hprev, ?_⟩
        intro j' h1' h2' hb
        by_cases jj : j' = j
        · subst jj
          exfalso
          rw [and1_beq, bit_shr' _ _ _ (by omega), Nat.zero_add] at h1
          rw [hb] at h1
          exact absurd h1 (by simp)
        · exact hlate j' (by omega) (by omega) hb

theorem step_idx (home e m n : Nat) (hn : m + 1 = 2 ^ n) :
    (((home + e) &&& m) + 1) &&& m = (home + (e + 1)) &&& m := by
  have hm : m = 2 ^ n - 1 := by omega
  rw [hm, Nat.and_two_pow_sub_one_eq_mod, Nat.and_two_pow_sub_one_eq_mod, Nat.and_two_pow_sub_one_eq_mod,
    Nat.mod_add_mod, Nat.add_assoc]

theorem has_room (out : ByteArray) (w o c : Nat) (pos slot : UInt64) (h : Has out o c pos slot) :
    Has (room out w) o c pos slot := by
  obtain ⟨t, ht, h1, h2⟩ := h
  exact ⟨t, ht, by rw [wAt_room]; exact h1, by rw [wAt_room]; exact h2⟩

theorem scanS_has (st : ByteArray) (h1 h2 : UInt64) (m o n home : Nat) (hn : m + 1 = 2 ^ n) :
    ∀ (fuel e : Nat) (out : ByteArray) (c : Nat), out.size % 8 = 0 → (wAt out o).toNat = c → c + fuel < 2 ^ 64 →
      (scanS st h1 h2 m o out ((home + e) &&& m) fuel).size % 8 = 0 ∧ ∃ c',
        (wAt (scanS st h1 h2 m o out ((home + e) &&& m) fuel) o).toNat = c' ∧
        (∀ pos slot, Has out o c pos slot → Has (scanS st h1 h2 m o out ((home + e) &&& m) fuel) o c' pos slot) ∧
        (∀ d, e ≤ d → d < e + fuel → (∀ d', e ≤ d' → d' < d → wAt st (3 * ((home + d') &&& m) + 2) ≠ 0) →
          wAt st (3 * ((home + d) &&& m) + 2) ≠ 0 → wAt st (3 * ((home + d) &&& m)) = h1 →
          wAt st (3 * ((home + d) &&& m) + 1) = h2 →
          Has (scanS st h1 h2 m o out ((home + e) &&& m) fuel) o c' (stashBase + ((home + d) &&& m)).toUInt64
            (wAt st (3 * ((home + d) &&& m) + 2))) := by
  intro fuel
  induction fuel with
  | zero =>
    intro e out c hal hc _
    have eq : scanS st h1 h2 m o out ((home + e) &&& m) 0 = out := by simp [scanS]
    rw [eq]
    exact ⟨hal, c, hc, fun _ _ h => h, fun d hd1 hd2 => absurd hd2 (by omega)⟩
  | succ fuel ih =>
    intro e out c hal hc hcf
    rw [scanS]
    by_cases hz : (wAt st (3 * ((home + e) &&& m) + 2) == 0) = true
    · rw [if_pos hz]
      refine ⟨hal, c, hc, fun _ _ h => h, ?_⟩
      intro d hd1 hd2 hnf htg _ _
      exfalso
      have hz' : wAt st (3 * ((home + e) &&& m) + 2) = 0 := beq_iff_eq.mp hz
      by_cases hde : d = e
      · subst hde; exact htg hz'
      · exact hnf e (Nat.le_refl _) (by omega) hz'
    · rw [if_neg hz]
      by_cases hm' : (wAt st (3 * ((home + e) &&& m)) == h1 && wAt st (3 * ((home + e) &&& m) + 1) == h2) = true
      · rw [if_pos hm']
        dsimp only
        rw [hc]
        obtain ⟨hr1, hr2, hr3⟩ := room_size out (o + 3 + 2 * c) hal
        obtain ⟨hs, hw⟩ := push2 (room out (o + 3 + 2 * c)) hr1 o c (stashBase + ((home + e) &&& m)).toUInt64
          (wAt st (3 * ((home + e) &&& m) + 2)) hr2
        have hal' : (wSet (wSet (wSet (room out (o + 3 + 2 * c)) (o + 1 + 2 * c) (stashBase + ((home + e) &&& m)).toUInt64)
            (o + 2 + 2 * c) (wAt st (3 * ((home + e) &&& m) + 2))) o (c + 1).toUInt64).size % 8 = 0 := by
          rw [hs]; exact hr1
        have hcnt : (wAt (wSet (wSet (wSet (room out (o + 3 + 2 * c)) (o + 1 + 2 * c)
            (stashBase + ((home + e) &&& m)).toUInt64) (o + 2 + 2 * c) (wAt st (3 * ((home + e) &&& m) + 2))) o
            (c + 1).toUInt64) o).toNat = c + 1 := by
          rw [hw]; simp only [if_true]; exact toNat_toUInt64 _ (by omega)
        have hp := has_push (room out (o + 3 + 2 * c)) hr1 o c (stashBase + ((home + e) &&& m)).toUInt64
          (wAt st (3 * ((home + e) &&& m) + 2)) hr2
        rw [step_idx home e m n hn]
        obtain ⟨hs2, c', hc2, hprev, hlate⟩ := ih (e + 1) _ (c + 1) hal' hcnt (by omega)
        refine ⟨hs2, c', hc2, fun pos slot h => hprev pos slot ((hp pos slot).1 (has_room _ _ _ _ _ _ h)), ?_⟩
        intro d hd1 hd2 hnf htg hw1 hw2
        by_cases hde : d = e
        · subst hde
          exact hprev _ _ (hp 0 0).2
        · exact hlate d (by omega) (by omega) (fun d' h1' h2' => hnf d' (by omega) h2') htg hw1 hw2
      · rw [if_neg hm']
        rw [step_idx home e m n hn]
        obtain ⟨hs2, c', hc2, hprev, hlate⟩ := ih (e + 1) out c hal hc (by omega)
        refine ⟨hs2, c', hc2, hprev, ?_⟩
        intro d hd1 hd2 hnf htg hw1 hw2
        by_cases hde : d = e
        · subst hde
          exfalso
          apply hm'
          simp [hw1, hw2]
        · exact hlate d (by omega) (by omega) (fun d' h1' h2' => hnf d' (by omega) h2') htg hw1 hw2


/-! ## Findable keys -/

theorem lvlK_le (k p b : Nat) : lvlK k p b ≤ k + 1 := by unfold lvlK; split <;> omega

/-- The address word a key's slot is placed by: the key's own (`c` false) or its other one. -/
def addrC (a0 : UInt64) (c : Bool) : UInt64 := if c then otherWord a0 (a0 >>> 56) else a0

/-- Slot `j` of bucket `b` is a live slot of the key with address word `a0`, row `seq`. -/
def WB (k p : Nat) (segs : Array ByteArray) (a0 : UInt64) (seq b j : Nat) : Prop :=
  j < 8 ∧ isEmpty (slotAt segs b j) = false ∧ seqOf (slotAt segs b j) = seq ∧
    ∃ c, SlotOK k p (addrC a0 c) (a0 >>> 56) c b (slotAt segs b j)

def FndB (k p : Nat) (segs : Array ByteArray) (a0 : UInt64) (seq : Nat) : Prop := ∃ b j, WB k p segs a0 seq b j

def sHome (a0 : UInt64) : Nat := ((a0 * 0x9E3779B97F4A7C15) >>> 32).toNat

/-- A stash entry of the key: equal words, row `seq`, in the run from the key's home entry. -/
def FndS (st : ByteArray) (h1 h2 a0 : UInt64) (seq : Nat) : Prop :=
  ∃ d, d < st.size / 24 ∧ (∀ d', d' < d → wAt st (3 * ((sHome a0 + d') &&& (st.size / 24 - 1)) + 2) ≠ 0) ∧
    wAt st (3 * ((sHome a0 + d) &&& (st.size / 24 - 1)) + 2) ≠ 0 ∧
    wAt st (3 * ((sHome a0 + d) &&& (st.size / 24 - 1))) = h1 ∧
    wAt st (3 * ((sHome a0 + d) &&& (st.size / 24 - 1)) + 1) = h2 ∧
    seqOf (wAt st (3 * ((sHome a0 + d) &&& (st.size / 24 - 1)) + 2)) = seq

theorem slot_hit (k p : Nat) (segs : Array ByteArray) (A f : UInt64) (c : Bool) (b j : Nat) (hj : j < 8)
    (hne : isEmpty (slotAt segs b j) = false) (hs : SlotOK k p A f c b (slotAt segs b j)) (hk : k ≤ 48) :
    bit (hitMask segs b ((f <<< 56) ||| (if c then choiceBit else 0)) (A >>> (lvlK k p b).toUInt64)) j = true := by
  rw [hitMask_bit _ _ _ _ _ hj, hne, Bool.not_false, Bool.true_and]
  apply hit_of
  · exact hs.2.1
  · intro i hi
    have := lvlK_le k p b
    rw [bit_shr' _ _ _ (by omega), hs.2.2 i hi, Nat.add_comm]

theorem has_hints (O : ByteArray) (c : Nat) (hc : (wAt O 0).toNat = c) (pos slot : UInt64) (h : Has O 0 c pos slot)
    (seq : Nat) (hs : seqOf slot = seq) :
    ∃ s ∈ (List.range (wAt O 0).toNat).map (fun j => wAt O (2 + 2 * j)), seqOf s = seq := by
  obtain ⟨t, ht, _, h2⟩ := h
  refine ⟨slot, List.mem_map.mpr ⟨t, List.mem_range.mpr (by omega), ?_⟩, hs⟩
  have : wAt O (0 + 2 + 2 * t) = slot := h2
  rw [Nat.zero_add] at this
  exact this

theorem has_mem (O : ByteArray) (c : Nat) (s : UInt64)
    (hs : s ∈ (List.range (wAt O 0).toNat).map (fun j => wAt O (2 + 2 * j))) (hc : (wAt O 0).toNat = c) :
    ∃ pos, Has O 0 c pos s := by
  obtain ⟨t, ht, rfl⟩ := List.mem_map.mp hs
  exact ⟨wAt O (0 + 1 + 2 * t), t, by have := List.mem_range.mp ht; omega, rfl, by rw [Nat.zero_add]⟩


/-! ## Moving slots between buckets -/

theorem xor_cancel (a s : UInt64) : a ^^^ s ^^^ s = a := by
  apply bit_ext; intro i _
  rw [bit_xor, bit_xor]
  cases bit a i <;> cases bit s i <;> rfl

theorem otherWord_inv (a f : UInt64) : otherWord (otherWord a f) f = a := xor_cancel a (spread f)

theorem shr56_lt (a : UInt64) : (a >>> 56).toNat < 256 := by
  have h := a.toNat_lt_size
  rw [UInt64.toNat_shiftRight]
  have e : (56 : UInt64).toNat % 64 = 56 := by decide
  rw [e, Nat.shiftRight_eq_div_pow, Nat.div_lt_iff_lt_mul (by decide)]
  have : UInt64.size = 256 * 2 ^ 56 := by decide
  omega

theorem addrC_flip (a0 : UInt64) (c : Bool) : addrC a0 (!c) = otherWord (addrC a0 c) (a0 >>> 56) := by
  cases c
  · rfl
  · exact (otherWord_inv a0 _).symm

theorem and7 (j : Nat) : j &&& 7 = j % 8 := by
  have := Nat.and_two_pow_sub_one_eq_mod j 3
  simpa using this

theorem slotAt_mod (segs : Array ByteArray) (b j : Nat) : slotAt segs b j = slotAt segs b (j % 8) := by
  unfold slotAt; rw [and7 j, and7 (j % 8), Nat.mod_mod]

theorem slotSet_mod (segs : Array ByteArray) (b j : Nat) (v : UInt64) : slotSet segs b j v = slotSet segs b (j % 8) v := by
  unfold slotSet; rw [and7 j, and7 (j % 8), Nat.mod_mod]

theorem slotSet_size (segs : Array ByteArray) (b j : Nat) (v : UInt64) : (slotSet segs b j v).size = segs.size := by
  unfold slotSet; simp

theorem wb_set_other (k p : Nat) (segs : Array ByteArray) (hw : SegsWf segs) (a0 : UInt64) (seq b j b'' u : Nat)
    (hu : u < 8) (v : UInt64) (h : WB k p segs a0 seq b j) (hne : ¬(b = b'' ∧ j = u)) :
    WB k p (slotSet segs b'' u v) a0 seq b j := by
  obtain ⟨hj, h1, h2, c, h3⟩ := h
  have e : slotAt (slotSet segs b'' u v) b j = slotAt segs b j := by
    rw [slotAt_slotSet segs hw b'' u hu v b j hj, if_neg]
    rintro ⟨a, b2, _⟩
    exact hne ⟨a, b2⟩
  exact ⟨hj, by rw [e]; exact h1, by rw [e]; exact h2, c, by rw [e]; exact h3⟩

theorem wb_new (k p : Nat) (segs : Array ByteArray) (hw : SegsWf segs) (a0 : UInt64) (seq b u : Nat) (hu : u < 8)
    (hb : b / 1023 < segs.size) (v : UInt64) (hne : isEmpty v = false) (hsq : seqOf v = seq) (c : Bool)
    (hok : SlotOK k p (addrC a0 c) (a0 >>> 56) c b v) : WB k p (slotSet segs b u v) a0 seq b u := by
  have e : slotAt (slotSet segs b u v) b u = v := by
    rw [slotAt_slotSet segs hw b u hu v b u hu, if_pos ⟨rfl, rfl, hb⟩]
  exact ⟨hu, by rw [e]; exact hne, by rw [e]; exact hsq, c, by rw [e]; exact hok⟩

/-- Every key findable in `S0` has a live slot in `S` other than `T`. -/
def Q (k p : Nat) (S0 S : Array ByteArray) (tb tu : Nat) : Prop :=
  ∀ a0 seq, FndB k p S0 a0 seq → ∃ b j, WB k p S a0 seq b j ∧ ¬(b = tb ∧ j = tu)

theorem q_start (k p : Nat) (S : Array ByteArray) (tb tu : Nat) (h : isEmpty (slotAt S tb tu) = true) :
    Q k p S S tb tu := by
  intro a0 seq ⟨b, j, hW⟩
  refine ⟨b, j, hW, ?_⟩
  rintro ⟨rfl, rfl⟩
  have := hW.2.1
  rw [h] at this
  exact absurd this (by simp)

theorem q_final (k p : Nat) (S0 S : Array ByteArray) (hw : SegsWf S) (tb tu : Nat) (hu : tu < 8) (v : UInt64)
    (hQ : Q k p S0 S tb tu) : ∀ a0 seq, FndB k p S0 a0 seq → FndB k p (slotSet S tb tu v) a0 seq := by
  intro a0 seq hF
  obtain ⟨b, j, hW, hnT⟩ := hQ a0 seq hF
  exact ⟨b, j, wb_set_other k p S hw a0 seq b j tb tu hu v hW hnT⟩

/-! ## Slot prefixes -/

/-- In every bucket, an empty slot is followed by empty slots. -/
def Pre (segs : Array ByteArray) : Prop :=
  ∀ b j, j + 1 < 8 → isEmpty (slotAt segs b j) = true → isEmpty (slotAt segs b (j + 1)) = true

theorem pre_set (segs : Array ByteArray) (hw : SegsWf segs) (hP : Pre segs) (b u : Nat) (hu : u < 8) (v : UInt64)
    (hv : isEmpty v = false)
    (hT : isEmpty (slotAt segs b u) = false ∨ ∀ j, j < u → isEmpty (slotAt segs b j) = false) :
    Pre (slotSet segs b u v) := by
  intro b' j hj hE
  have e1 := slotAt_slotSet segs hw b u hu v b' j (by omega)
  have e2 := slotAt_slotSet segs hw b u hu v b' (j + 1) (by omega)
  rw [e1] at hE
  rw [e2]
  by_cases h1 : b' = b ∧ j = u ∧ b / 1023 < segs.size
  · rw [if_pos h1, hv] at hE
    exact absurd hE (by simp)
  · rw [if_neg h1] at hE
    have h3 := hP b' j hj hE
    by_cases h2 : b' = b ∧ j + 1 = u ∧ b / 1023 < segs.size
    · exfalso
      obtain ⟨rfl, hju, _⟩ := h2
      rcases hT with hT | hT
      · rw [← hju, h3] at hT; exact absurd hT (by simp)
      · have := hT j (by omega)
        rw [hE] at this; exact absurd this (by simp)
    · rw [if_neg h2]; exact h3

theorem full_of_7 (segs : Array ByteArray) (hP : Pre segs) (b : Nat) (h7 : isEmpty (slotAt segs b 7) = false) :
    ∀ j, j < 8 → isEmpty (slotAt segs b j) = false := by
  intro j hj
  by_cases h : isEmpty (slotAt segs b j) = true
  · exfalso
    have : ∀ d, j + d < 8 → isEmpty (slotAt segs b (j + d)) = true := by
      intro d
      induction d with
      | zero => intro _; simpa using h
      | succ d ih =>
        intro hd
        have := hP b (j + d) (by omega) (ih (by omega))
        simpa [Nat.add_assoc] using this
    have h8 := this (7 - j) (by omega)
    rw [show j + (7 - j) = 7 by omega, h7] at h8
    exact absurd h8 (by simp)
  · simpa using h

/-! ## The one-move and two-move searches -/

theorem freeAlt_spec (segs : Array ByteArray) (k p b : Nat) : ∀ fuel j, freeAlt segs k p b j fuel < 8 →
    altB k p b (slotAt segs b (freeAlt segs k p b j fuel)) ≠ noB ∧
    isEmpty (slotAt segs (altB k p b (slotAt segs b (freeAlt segs k p b j fuel))) 7) = true := by
  intro fuel
  induction fuel with
  | zero => intro j h; simp [freeAlt] at h
  | succ fuel ih =>
    intro j h
    by_cases hc : (altB k p b (slotAt segs b j) != noB && isEmpty (slotAt segs (altB k p b (slotAt segs b j)) 7)) = true
    · have e : freeAlt segs k p b j (fuel + 1) = j := by simp only [freeAlt, if_pos hc]
      rw [e]
      simpa using hc
    · have e : freeAlt segs k p b j (fuel + 1) = freeAlt segs k p b (j + 1) fuel := by
        simp only [freeAlt, if_neg hc]
      rw [e] at h ⊢
      exact ih (j + 1) h

/-- A slot of bucket `b` whose other bucket has no free slot cannot be found by `freeAlt`. -/
theorem freeAlt_none (segs : Array ByteArray) (k p b : Nat) : ∀ fuel j, j + fuel ≤ 8 → freeAlt segs k p b j fuel = 8 →
    ∀ j', j ≤ j' → j' < j + fuel →
      ¬(altB k p b (slotAt segs b j') != noB && isEmpty (slotAt segs (altB k p b (slotAt segs b j')) 7)) = true := by
  intro fuel
  induction fuel with
  | zero => intro j _ _ j' h1 h2; omega
  | succ fuel ih =>
    intro j hf h j' h1 h2
    by_cases hc : (altB k p b (slotAt segs b j) != noB && isEmpty (slotAt segs (altB k p b (slotAt segs b j)) 7)) = true
    · have e : freeAlt segs k p b j (fuel + 1) = j := by simp only [freeAlt, if_pos hc]
      rw [e] at h
      subst h
      omega
    · have e : freeAlt segs k p b j (fuel + 1) = freeAlt segs k p b (j + 1) fuel := by
        simp only [freeAlt, if_neg hc]
      rw [e] at h
      by_cases hj : j' = j
      · subst hj; exact hc
      · exact ih (j + 1) (by omega) h j' (by omega) (by omega)

def rootB (b0 b1 i : Nat) : Nat := if i < 8 then b0 else b1

/-! ## Fresh slots -/

theorem sq_toNat (seq : Nat) (h : seq + 1 < 2 ^ 40) : ((seq + 1).toUInt64).toNat = seq + 1 :=
  toNat_toUInt64 _ (by have : (2 : Nat) ^ 40 < 2 ^ 64 := by decide
                       omega)

theorem bit_sq_hi (seq : Nat) (h : seq + 1 < 2 ^ 40) (i : Nat) (hi : 40 ≤ i) : bit (seq + 1).toUInt64 i = false := by
  unfold bit; rw [sq_toNat seq h]
  exact Nat.testBit_lt_two_pow (Nat.lt_of_lt_of_le h (Nat.pow_le_pow_right (by omega) hi))

theorem bit_ch (c : Bool) (i : Nat) (h : i ≠ 41) : bit (if c then choiceBit else (0 : UInt64)) i = false := by
  cases c
  · exact bit_zero _
  · show bit choiceBit i = false
    rw [bit_choiceBit]; exact decide_eq_false (fun e => h e.symm)

theorem bit_R (A : UInt64) (l : Nat) (hl : l < 64) (i : Nat) (hi : i < 13) :
    bit (0x2000 ||| ((A >>> l.toUInt64) &&& 0x1FFF)) i = bit A (l + i) := by
  have e7 : decide (13 = i) = false := decide_eq_false (by omega)
  have e8 : decide (i < 13) = true := decide_eq_true hi
  have e9 := bit_shr' A l i hl
  rw [bit_or, bit_and, bit_m2000, bit_m1fff, e9, e7, e8, Nat.add_comm]
  simp

theorem bit_R_hi (A : UInt64) (l : Nat) (j : Nat) (hj : 14 ≤ j) :
    bit (0x2000 ||| ((A >>> l.toUInt64) &&& 0x1FFF)) j = false := by
  have e1 : decide (13 = j) = false := decide_eq_false (by omega)
  have e2 : decide (j < 13) = false := decide_eq_false (by omega)
  rw [bit_or, bit_and, bit_m2000, bit_m1fff, e1, e2]
  simp

/-! ## The chain search -/

theorem altB_lt (k p b : Nat) (s : UInt64) (hk : k < 63) (hp : p ≤ 2 ^ k) (h : altB k p b s ≠ noB) :
    altB k p b s < 2 ^ k + p := by
  unfold altB at h ⊢
  dsimp only at h ⊢
  by_cases hr : (resOf s == 0) = true
  · rw [if_pos hr] at h; exact absurd rfl h
  · rw [if_neg hr] at h ⊢
    rw [land_mask1 _ k (by omega)] at h ⊢
    have hm := Nat.mod_lt (otherOf (lvlK k p b) b s).toNat (Nat.two_pow_pos k)
    by_cases hlo : (otherOf (lvlK k p b) b s).toNat % 2 ^ k < p
    · rw [if_pos hlo] at h ⊢
      by_cases hc : (decide (lvlK k p b > k) || decide (resOf s ≥ 2)) = true
      · rw [if_pos hc] at h ⊢
        rw [land_mask2 _ k hk]
        rcases mod2k (otherOf (lvlK k p b) b s).toNat k with e | e <;> omega
      · rw [if_neg hc] at h; exact absurd rfl h
    · rw [if_neg hlo]; omega

theorem low5_vals (r : ByteArray) (hal : r.size % 8 = 0) (hsz : 40 ≤ r.size) (a b c d e : UInt64) :
    wAt (wSet (wSet (wSet (wSet (wSet r 0 a) 1 b) 2 c) 3 d) 4 e) 0 = a ∧
    wAt (wSet (wSet (wSet (wSet (wSet r 0 a) 1 b) 2 c) 3 d) 4 e) 1 = b ∧
    wAt (wSet (wSet (wSet (wSet (wSet r 0 a) 1 b) 2 c) 3 d) 4 e) 2 = c ∧
    wAt (wSet (wSet (wSet (wSet (wSet r 0 a) 1 b) 2 c) 3 d) 4 e) 3 = d ∧
    wAt (wSet (wSet (wSet (wSet (wSet r 0 a) 1 b) 2 c) 3 d) 4 e) 4 = e ∧
    (wSet (wSet (wSet (wSet (wSet r 0 a) 1 b) 2 c) 3 d) 4 e).size = r.size ∧
    ∀ w, 5 ≤ w → wAt (wSet (wSet (wSet (wSet (wSet r 0 a) 1 b) 2 c) 3 d) 4 e) w = wAt r w := by
  have s1 : (wSet r 0 a).size = r.size := wSet_size _ _ _
  have s2 : (wSet (wSet r 0 a) 1 b).size = r.size := by rw [wSet_size, s1]
  have s3 : (wSet (wSet (wSet r 0 a) 1 b) 2 c).size = r.size := by rw [wSet_size, s2]
  have s4 : (wSet (wSet (wSet (wSet r 0 a) 1 b) 2 c) 3 d).size = r.size := by rw [wSet_size, s3]
  have h1 : (wSet r 0 a).size % 8 = 0 := by rw [s1]; exact hal
  have h2 : (wSet (wSet r 0 a) 1 b).size % 8 = 0 := by rw [s2]; exact hal
  have h3 : (wSet (wSet (wSet r 0 a) 1 b) 2 c).size % 8 = 0 := by rw [s3]; exact hal
  have h4 : (wSet (wSet (wSet (wSet r 0 a) 1 b) 2 c) 3 d).size % 8 = 0 := by rw [s4]; exact hal
  refine ⟨?_, ?_, ?_, ?_, ?_, by rw [wSet_size, s4], ?_⟩
  · rw [wAt_wSet_ne _ 4 0 e (by omega), wAt_wSet_ne _ 3 0 d (by omega), wAt_wSet_ne _ 2 0 c (by omega),
      wAt_wSet_ne _ 1 0 b (by omega), wAt_wSet_in _ hal 0 0 a (by omega)]
    simp
  · rw [wAt_wSet_ne _ 4 1 e (by omega), wAt_wSet_ne _ 3 1 d (by omega), wAt_wSet_ne _ 2 1 c (by omega),
      wAt_wSet_in _ h1 1 1 b (by omega)]
    simp
  · rw [wAt_wSet_ne _ 4 2 e (by omega), wAt_wSet_ne _ 3 2 d (by omega), wAt_wSet_in _ h2 2 2 c (by omega)]
    simp
  · rw [wAt_wSet_ne _ 4 3 e (by omega), wAt_wSet_in _ h3 3 3 d (by omega)]
    simp
  · rw [wAt_wSet_in _ h4 4 4 e (by omega)]
    simp
  · intro w hw
    rw [wAt_wSet_ne _ 4 w e (by omega), wAt_wSet_ne _ 3 w d (by omega), wAt_wSet_ne _ 2 w c (by omega),
      wAt_wSet_ne _ 1 w b (by omega), wAt_wSet_ne _ 0 w a (by omega)]

theorem app3_vals (r : ByteArray) (hal : r.size % 8 = 0) (m : Nat) (hsz : 8 * (8 + 3 * m) ≤ r.size) (x y z : UInt64) :
    wAt (wSet (wSet (wSet r (5 + 3 * m) x) (6 + 3 * m) y) (7 + 3 * m) z) (5 + 3 * m) = x ∧
    wAt (wSet (wSet (wSet r (5 + 3 * m) x) (6 + 3 * m) y) (7 + 3 * m) z) (6 + 3 * m) = y ∧
    wAt (wSet (wSet (wSet r (5 + 3 * m) x) (6 + 3 * m) y) (7 + 3 * m) z) (7 + 3 * m) = z ∧
    (wSet (wSet (wSet r (5 + 3 * m) x) (6 + 3 * m) y) (7 + 3 * m) z).size = r.size ∧
    ∀ w, (w < 5 + 3 * m ∨ 8 + 3 * m ≤ w) →
      wAt (wSet (wSet (wSet r (5 + 3 * m) x) (6 + 3 * m) y) (7 + 3 * m) z) w = wAt r w := by
  have s1 : (wSet r (5 + 3 * m) x).size = r.size := wSet_size _ _ _
  have s2 : (wSet (wSet r (5 + 3 * m) x) (6 + 3 * m) y).size = r.size := by rw [wSet_size, s1]
  have h1 : (wSet r (5 + 3 * m) x).size % 8 = 0 := by rw [s1]; exact hal
  have h2 : (wSet (wSet r (5 + 3 * m) x) (6 + 3 * m) y).size % 8 = 0 := by rw [s2]; exact hal
  refine ⟨?_, ?_, ?_, by rw [wSet_size, s2], ?_⟩
  · rw [wAt_wSet_ne _ (7 + 3 * m) _ z (by omega), wAt_wSet_ne _ (6 + 3 * m) _ y (by omega),
      wAt_wSet_in _ hal (5 + 3 * m) _ x (by omega)]
    simp
  · rw [wAt_wSet_ne _ (7 + 3 * m) _ z (by omega), wAt_wSet_in _ h1 (6 + 3 * m) _ y (by omega)]
    simp
  · rw [wAt_wSet_in _ h2 (7 + 3 * m) _ z (by omega)]
    simp
  · intro w hw
    rw [wAt_wSet_ne _ (7 + 3 * m) w z (by omega), wAt_wSet_ne _ (6 + 3 * m) w y (by omega),
      wAt_wSet_ne _ (5 + 3 * m) w x (by omega)]

/-! ## Placing one key in the buckets -/

theorem free_of_7 (S : Array ByteArray) (hP : Pre S) (b : Nat) (h7 : isEmpty (slotAt S b 7) = true) :
    usedIn S b < 8 := by
  obtain ⟨h1, h2, _⟩ := usedIn_spec S b (fun j hj => hP b j hj)
  rcases Nat.lt_or_ge (usedIn S b) 8 with h | h
  · exact h
  · have := h2 7 (by omega)
    rw [h7] at this
    exact absurd this (by simp)

theorem free_u (S : Array ByteArray) (hP : Pre S) (b : Nat) (h : usedIn S b < 8) :
    isEmpty (slotAt S b (usedIn S b)) = true ∧ ∀ j, j < usedIn S b → isEmpty (slotAt S b j) = false := by
  obtain ⟨_, h2, h3⟩ := usedIn_spec S b (fun j hj => hP b j hj)
  exact ⟨h3 _ (Nat.le_refl _) h, h2⟩

theorem seg_of (S : Array ByteArray) (k p β : Nat) (hnb : 2 ^ k + p ≤ 1023 * S.size) (h : β < 2 ^ k + p) :
    β / 1023 < S.size := by
  rw [Nat.div_lt_iff_lt_mul (by decide)]; omega

theorem freeAlt_le (S : Array ByteArray) (k p b : Nat) : ∀ fuel j, freeAlt S k p b j fuel ≤ 8 ∨ j + fuel > 8 := by
  intro fuel
  induction fuel with
  | zero => intro j; left; simp [freeAlt]
  | succ fuel ih =>
    intro j
    by_cases hc : (altB k p b (slotAt S b j) != noB && isEmpty (slotAt S (altB k p b (slotAt S b j)) 7)) = true
    · have e : freeAlt S k p b j (fuel + 1) = j := by simp only [freeAlt, if_pos hc]
      rw [e]; by_cases h : j ≤ 8
      · left; exact h
      · right; omega
    · have e : freeAlt S k p b j (fuel + 1) = freeAlt S k p b (j + 1) fuel := by simp only [freeAlt, if_neg hc]
      rw [e]
      rcases ih (j + 1) with h | h
      · left; exact h
      · right; omega

theorem freeAlt_le8 (S : Array ByteArray) (k p b : Nat) : freeAlt S k p b 0 8 ≤ 8 := by
  rcases freeAlt_le S k p b 8 0 with h | h
  · exact h
  · omega

theorem search_nodes (S : Array ByteArray) (k p : Nat) : ∀ fuel i j m r, 2 ≤ m →
    wAt (search S k p r i j m fuel) 5 = wAt r 5 ∧ wAt (search S k p r i j m fuel) 8 = wAt r 8 := by
  intro fuel
  induction fuel with
  | zero => intro i j m r _; simp [search]
  | succ fuel ih =>
    intro i j m r hm
    simp only [search]
    by_cases h1 : i ≥ m
    · rw [if_pos h1]; exact ⟨rfl, rfl⟩
    · rw [if_neg h1]
      by_cases h2 : j ≥ 8
      · rw [if_pos h2]; exact ih _ _ _ _ hm
      · rw [if_neg h2]
        generalize altB k p (nodeB r i) (slotAt S (nodeB r i) j) = b'
        by_cases hn : (b' == noB) = true
        · rw [if_pos hn]; exact ih _ _ _ _ hm
        · rw [if_neg hn]
          by_cases he : isEmpty (slotAt S b' 7) = true
          · rw [if_pos he]
            refine ⟨?_, ?_⟩
            · rw [wAt_wSet_ne _ 4 5 _ (by omega), wAt_wSet_ne _ 3 5 _ (by omega), wAt_wSet_ne _ 2 5 _ (by omega),
                wAt_wSet_ne _ 1 5 _ (by omega), wAt_wSet_ne _ 0 5 _ (by omega)]
            · rw [wAt_wSet_ne _ 4 8 _ (by omega), wAt_wSet_ne _ 3 8 _ (by omega), wAt_wSet_ne _ 2 8 _ (by omega),
                wAt_wSet_ne _ 1 8 _ (by omega), wAt_wSet_ne _ 0 8 _ (by omega)]
          · rw [if_neg he]
            by_cases hc : (decide (m < maxNodes) && !onChain r b' i maxNodes) = true
            · rw [if_pos hc]
              obtain ⟨a1, a2⟩ := ih i (j + 1) (m + 1) _ (by omega)
              rw [a1, a2]
              refine ⟨?_, ?_⟩
              · rw [wAt_wSet_ne _ (7 + 3 * m) 5 _ (by omega), wAt_wSet_ne _ (6 + 3 * m) 5 _ (by omega),
                  wAt_wSet_ne _ (5 + 3 * m) 5 _ (by omega)]
              · rw [wAt_wSet_ne _ (7 + 3 * m) 8 _ (by omega), wAt_wSet_ne _ (6 + 3 * m) 8 _ (by omega),
                  wAt_wSet_ne _ (5 + 3 * m) 8 _ (by omega)]
            · rw [if_neg hc]; exact ih _ _ _ _ hm

/-! ## The stash -/

theorem andm (x n : Nat) : x &&& (2 ^ n - 1) = x % 2 ^ n := Nat.and_two_pow_sub_one_eq_mod x n

/-- The stash `st` has, in the run from the home entry of `a0`, an entry with the words `h1`, `h2`, `w`. -/
def FndW (st : ByteArray) (h1 h2 w a0 : UInt64) : Prop :=
  ∃ d, d < st.size / 24 ∧ (∀ d', d' < d → wAt st (3 * ((sHome a0 + d') &&& (st.size / 24 - 1)) + 2) ≠ 0) ∧
    wAt st (3 * ((sHome a0 + d) &&& (st.size / 24 - 1)) + 2) = w ∧
    wAt st (3 * ((sHome a0 + d) &&& (st.size / 24 - 1))) = h1 ∧
    wAt st (3 * ((sHome a0 + d) &&& (st.size / 24 - 1)) + 1) = h2 ∧ w ≠ 0

theorem fnds_of_fndw {st : ByteArray} {h1 h2 w a0 : UInt64} (h : FndW st h1 h2 w a0) (seq : Nat)
    (hs : seqOf w = seq) : FndS st h1 h2 a0 seq := by
  obtain ⟨d, hd, hr, hw, e1, e2, hne⟩ := h
  exact ⟨d, hd, hr, by rw [hw]; exact hne, e1, e2, by rw [hw]; exact hs⟩

theorem fndw_of_fnds {st : ByteArray} {h1 h2 a0 : UInt64} {seq : Nat} (h : FndS st h1 h2 a0 seq) :
    ∃ w, FndW st h1 h2 w a0 ∧ seqOf w = seq := by
  obtain ⟨d, hd, hr, hne, e1, e2, hs⟩ := h
  exact ⟨_, ⟨d, hd, hr, rfl, e1, e2, hne⟩, hs⟩

/-- `st'` has every used entry of `st` unchanged. -/
def Keeps (st st' : ByteArray) : Prop :=
  st'.size = st.size ∧ ∀ q, q < st.size / 24 → wAt st (3 * q + 2) ≠ 0 →
    wAt st' (3 * q) = wAt st (3 * q) ∧ wAt st' (3 * q + 1) = wAt st (3 * q + 1) ∧
    wAt st' (3 * q + 2) = wAt st (3 * q + 2)

theorem fndw_keeps {st st' : ByteArray} {h1 h2 w a0 : UInt64} (hpw : ∃ n, st.size / 24 = 2 ^ n)
    (hK : Keeps st st') (h : FndW st h1 h2 w a0) : FndW st' h1 h2 w a0 := by
  obtain ⟨n, hn⟩ := hpw
  obtain ⟨d, hd, hr, hw, e1, e2, hne⟩ := h
  have hq : ∀ x, (x &&& (st.size / 24 - 1)) < st.size / 24 := by
    intro x; rw [hn, andm]; exact Nat.mod_lt _ (Nat.two_pow_pos n)
  unfold FndW
  rw [hK.1]
  refine ⟨d, hd, ?_, ?_⟩
  · intro d' hd'
    obtain ⟨_, _, e3⟩ := hK.2 _ (hq _) (hr d' hd')
    rw [e3]; exact hr d' hd'
  · obtain ⟨f1, f2, f3⟩ := hK.2 _ (hq (sHome a0 + d)) (by rw [hw]; exact hne)
    exact ⟨f3.trans hw, f1.trans e1, f2.trans e2, hne⟩

def Cn (st : ByteArray) : Nat → Nat
  | 0 => 0
  | i + 1 => Cn st i + (if wAt st (3 * i + 2) = 0 then 0 else 1)

theorem cn_zeros (n i : Nat) : Cn (zeros n) i = 0 := by
  induction i with
  | zero => rfl
  | succ i ih => simp [Cn, ih, wAt_zeros]

theorem cn_full (st : ByteArray) : ∀ i, (∀ q, q < i → wAt st (3 * q + 2) ≠ 0) → Cn st i = i := by
  intro i
  induction i with
  | zero => intro _; rfl
  | succ i ih =>
    intro h
    simp only [Cn]
    rw [ih (fun q hq => h q (by omega)), if_neg (h i (by omega))]

theorem free_of_cn (st : ByteArray) (c : Nat) (h : Cn st c < c) : ∃ q, q < c ∧ wAt st (3 * q + 2) = 0 := by
  rcases Classical.em (∃ q, q < c ∧ wAt st (3 * q + 2) = 0) with h' | h'
  · exact h'
  · exfalso
    have := cn_full st c (fun q hq e => h' ⟨q, hq, e⟩)
    omega

theorem cn_put (st st' : ByteArray) (pos : Nat) (h0 : wAt st (3 * pos + 2) = 0) (h1 : wAt st' (3 * pos + 2) ≠ 0)
    (hs : ∀ q, q ≠ pos → wAt st' (3 * q + 2) = wAt st (3 * q + 2)) :
    ∀ i, Cn st' i = Cn st i + (if pos < i then 1 else 0) := by
  intro i
  induction i with
  | zero => simp [Cn]
  | succ i ih =>
    simp only [Cn]
    rw [ih]
    by_cases hp : pos = i
    · subst hp
      rw [if_neg (show ¬ pos < pos by omega), if_pos h0, if_neg h1, if_pos (show pos < pos + 1 by omega)]
    · rw [hs i (fun e => hp e.symm)]
      by_cases hlt : pos < i
      · rw [if_pos hlt, if_pos (show pos < i + 1 by omega)]; omega
      · rw [if_neg hlt, if_neg (show ¬ pos < i + 1 by omega)]; omega

theorem put_vals (st : ByteArray) (hal : st.size % 8 = 0) (pos : Nat) (hb : 8 * (3 * pos + 3) ≤ st.size)
    (h1 h2 w : UInt64) :
    wAt (wSet (wSet (wSet st (3 * pos) h1) (3 * pos + 1) h2) (3 * pos + 2) w) (3 * pos) = h1 ∧
    wAt (wSet (wSet (wSet st (3 * pos) h1) (3 * pos + 1) h2) (3 * pos + 2) w) (3 * pos + 1) = h2 ∧
    wAt (wSet (wSet (wSet st (3 * pos) h1) (3 * pos + 1) h2) (3 * pos + 2) w) (3 * pos + 2) = w ∧
    (wSet (wSet (wSet st (3 * pos) h1) (3 * pos + 1) h2) (3 * pos + 2) w).size = st.size ∧
    ∀ x, (x < 3 * pos ∨ 3 * pos + 3 ≤ x) →
      wAt (wSet (wSet (wSet st (3 * pos) h1) (3 * pos + 1) h2) (3 * pos + 2) w) x = wAt st x := by
  have s1 : (wSet st (3 * pos) h1).size = st.size := wSet_size _ _ _
  have s2 : (wSet (wSet st (3 * pos) h1) (3 * pos + 1) h2).size = st.size := by rw [wSet_size, s1]
  have a1 : (wSet st (3 * pos) h1).size % 8 = 0 := by rw [s1]; exact hal
  have a2 : (wSet (wSet st (3 * pos) h1) (3 * pos + 1) h2).size % 8 = 0 := by rw [s2]; exact hal
  refine ⟨?_, ?_, ?_, by rw [wSet_size, s2], ?_⟩
  · rw [wAt_wSet_ne _ (3 * pos + 2) _ w (by omega), wAt_wSet_ne _ (3 * pos + 1) _ h2 (by omega),
      wAt_wSet_in _ hal (3 * pos) _ h1 (by omega)]
    simp
  · rw [wAt_wSet_ne _ (3 * pos + 2) _ w (by omega), wAt_wSet_in _ a1 (3 * pos + 1) _ h2 (by omega)]
    simp
  · rw [wAt_wSet_in _ a2 (3 * pos + 2) _ w (by omega)]
    simp
  · intro x hx
    rw [wAt_wSet_ne _ (3 * pos + 2) x w (by omega), wAt_wSet_ne _ (3 * pos + 1) x h2 (by omega),
      wAt_wSet_ne _ (3 * pos) x h1 (by omega)]

theorem stashPut_spec (st : ByteArray) (h1 h2 w : UInt64) (n : Nat) :
    ∀ fuel i, i < 2 ^ n → (∃ d, d < fuel ∧ wAt st (3 * ((i + d) % 2 ^ n) + 2) = 0) →
    ∃ d, d < fuel ∧ (∀ d', d' < d → wAt st (3 * ((i + d') % 2 ^ n) + 2) ≠ 0) ∧
      wAt st (3 * ((i + d) % 2 ^ n) + 2) = 0 ∧
      stashPut st h1 h2 w (2 ^ n - 1) i fuel =
        wSet (wSet (wSet st (3 * ((i + d) % 2 ^ n)) h1) (3 * ((i + d) % 2 ^ n) + 1) h2)
          (3 * ((i + d) % 2 ^ n) + 2) w := by
  intro fuel
  induction fuel with
  | zero => intro i _ hex; obtain ⟨d, hd, _⟩ := hex; omega
  | succ fuel ih =>
    intro i hi hex
    obtain ⟨d, hd, hfree⟩ := hex
    have e : stashPut st h1 h2 w (2 ^ n - 1) i (fuel + 1) =
        if wAt st (3 * i + 2) == 0 then wSet (wSet (wSet st (3 * i) h1) (3 * i + 1) h2) (3 * i + 2) w
        else stashPut st h1 h2 w (2 ^ n - 1) ((i + 1) &&& (2 ^ n - 1)) fuel := rfl
    rw [e]
    by_cases h0 : wAt st (3 * i + 2) = 0
    · have hi0 : (i + 0) % 2 ^ n = i := by simp [Nat.mod_eq_of_lt hi]
      refine ⟨0, by omega, fun d' hd' => by omega, ?_, ?_⟩
      · rw [hi0]; exact h0
      · rw [if_pos (beq_iff_eq.mpr h0), hi0]
    · have hd0 : d ≠ 0 := by
        intro e0
        subst e0
        have hi0 : (i + 0) % 2 ^ n = i := by simp [Nat.mod_eq_of_lt hi]
        rw [hi0] at hfree
        exact h0 hfree
      have hi' : (i + 1) &&& (2 ^ n - 1) < 2 ^ n := by rw [andm]; exact Nat.mod_lt _ (Nat.two_pow_pos n)
      have hm : ∀ d', (((i + 1) &&& (2 ^ n - 1)) + d') % 2 ^ n = (i + (d' + 1)) % 2 ^ n := by
        intro d'; rw [andm, Nat.mod_add_mod]; congr 1; omega
      obtain ⟨d2, hd2, hrun, hfr, heq⟩ := ih ((i + 1) &&& (2 ^ n - 1)) hi'
        ⟨d - 1, by omega, by rw [hm]; rw [show d - 1 + 1 = d by omega]; exact hfree⟩
      simp only [hm] at hrun hfr heq
      rw [if_neg (fun h => h0 (beq_iff_eq.mp h))]
      refine ⟨d2 + 1, by omega, ?_, hfr, heq⟩
      intro d' hd'
      cases d' with
      | zero =>
        have hi0 : (i + 0) % 2 ^ n = i := by simp [Nat.mod_eq_of_lt hi]
        rw [hi0]; exact h0
      | succ e' => exact hrun e' (by omega)

theorem orbit_hit (n i q : Nat) (hi : i < 2 ^ n) (hq : q < 2 ^ n) : ∃ d, d < 2 ^ n ∧ (i + d) % 2 ^ n = q := by
  by_cases h : i ≤ q
  · exact ⟨q - i, by omega, by rw [show i + (q - i) = q by omega]; exact Nat.mod_eq_of_lt hq⟩
  · refine ⟨q + 2 ^ n - i, by omega, ?_⟩
    rw [show i + (q + 2 ^ n - i) = q + 2 ^ n by omega, Nat.add_mod_right]
    exact Nat.mod_eq_of_lt hq

theorem put_ok (st : ByteArray) (h1 h2 w a0 : UInt64) (n : Nat) (hsz : st.size = 24 * 2 ^ n) (hw : w ≠ 0)
    (hfree : Cn st (2 ^ n) < 2 ^ n) :
    (stashPut st h1 h2 w (st.size / 24 - 1) (stashHome a0 (st.size / 24 - 1)) (st.size / 24 - 1 + 1)).size = st.size ∧
    Keeps st (stashPut st h1 h2 w (st.size / 24 - 1) (stashHome a0 (st.size / 24 - 1)) (st.size / 24 - 1 + 1)) ∧
    FndW (stashPut st h1 h2 w (st.size / 24 - 1) (stashHome a0 (st.size / 24 - 1)) (st.size / 24 - 1 + 1)) h1 h2 w a0 ∧
    Cn (stashPut st h1 h2 w (st.size / 24 - 1) (stashHome a0 (st.size / 24 - 1)) (st.size / 24 - 1 + 1)) (2 ^ n) =
      Cn st (2 ^ n) + 1 := by
  have hp2 := Nat.two_pow_pos n
  have hc : st.size / 24 = 2 ^ n := by omega
  have hal : st.size % 8 = 0 := by omega
  rw [hc, show 2 ^ n - 1 + 1 = 2 ^ n by omega]
  have hh : stashHome a0 (2 ^ n - 1) = sHome a0 % 2 ^ n := by unfold stashHome sHome; rw [andm]
  rw [hh]
  have hi0 : sHome a0 % 2 ^ n < 2 ^ n := Nat.mod_lt _ hp2
  obtain ⟨q, hq, hqf⟩ := free_of_cn st _ hfree
  obtain ⟨d, hd, hdq⟩ := orbit_hit n _ q hi0 hq
  obtain ⟨d0, hd0, hrun, hfr, heq⟩ := stashPut_spec st h1 h2 w n (2 ^ n) _ hi0 ⟨d, hd, by rw [hdq]; exact hqf⟩
  have hm2 : ∀ d', (sHome a0 % 2 ^ n + d') % 2 ^ n = (sHome a0 + d') % 2 ^ n := fun d' => Nat.mod_add_mod _ _ _
  simp only [hm2] at hrun hfr heq
  rw [heq]
  have hpos : (sHome a0 + d0) % 2 ^ n < 2 ^ n := Nat.mod_lt _ hp2
  obtain ⟨v1, v2, v3, v4, v5⟩ := put_vals st hal ((sHome a0 + d0) % 2 ^ n) (by rw [hsz]; omega) h1 h2 w
  refine ⟨v4, ?_, ?_, ?_⟩
  · unfold Keeps
    refine ⟨v4, ?_⟩
    intro q' hq' hnf
    have hne : q' ≠ (sHome a0 + d0) % 2 ^ n := fun e => hnf (by rw [e]; exact hfr)
    exact ⟨v5 _ (by omega), v5 _ (by omega), v5 _ (by omega)⟩
  · unfold FndW
    rw [v4, hc]
    simp only [andm]
    refine ⟨d0, hd0, ?_, v3, v1, v2, hw⟩
    intro d' hd'
    have hne : (sHome a0 + d') % 2 ^ n ≠ (sHome a0 + d0) % 2 ^ n := fun e => by
      have := hrun d' hd'
      rw [e, hfr] at this
      exact this rfl
    rw [v5 _ (by omega)]
    exact hrun d' hd'
  · rw [cn_put st _ ((sHome a0 + d0) % 2 ^ n) hfr (by rw [v3]; exact hw) (fun q hq => v5 _ (by omega)) (2 ^ n),
      if_pos hpos]

theorem keeps_refl (st : ByteArray) : Keeps st st := ⟨rfl, fun _ _ _ => ⟨rfl, rfl, rfl⟩⟩

theorem keeps_trans {a b c : ByteArray} (h1 : Keeps a b) (h2 : Keeps b c) : Keeps a c := by
  refine ⟨h2.1.trans h1.1, ?_⟩
  intro q hq hn
  obtain ⟨e1, e2, e3⟩ := h1.2 q hq hn
  have hq' : q < b.size / 24 := by rw [h1.1]; exact hq
  have hn' : wAt b (3 * q + 2) ≠ 0 := by rw [e3]; exact hn
  obtain ⟨f1, f2, f3⟩ := h2.2 q hq' hn'
  exact ⟨f1.trans e1, f2.trans e2, f3.trans e3⟩

theorem cn_mono (st : ByteArray) (i : Nat) : ∀ j, i ≤ j → Cn st i ≤ Cn st j := by
  intro j
  induction j with
  | zero => intro h; have : i = 0 := by omega
            subst this; exact Nat.le_refl _
  | succ j ih =>
    intro h
    by_cases hij : i ≤ j
    · exact Nat.le_trans (ih hij) (Nat.le_add_right _ _)
    · have : i = j + 1 := by omega
      subst this; exact Nat.le_refl _

theorem stashMove_spec (s0 s1 : UInt64) (old : ByteArray) (n : Nat) :
    ∀ fuel i nw, nw.size = 24 * 2 ^ n → Cn nw (2 ^ n) + (Cn old (i + fuel) - Cn old i) ≤ 2 ^ n →
      (stashMove s0 s1 old nw i fuel).size = nw.size ∧ Keeps nw (stashMove s0 s1 old nw i fuel) ∧
      Cn (stashMove s0 s1 old nw i fuel) (2 ^ n) = Cn nw (2 ^ n) + (Cn old (i + fuel) - Cn old i) ∧
      ∀ q, i ≤ q → q < i + fuel → wAt old (3 * q + 2) ≠ 0 →
        FndW (stashMove s0 s1 old nw i fuel) (wAt old (3 * q)) (wAt old (3 * q + 1)) (wAt old (3 * q + 2))
          (keyed s0 s1 (wAt old (3 * q)) (wAt old (3 * q + 1))) := by
  intro fuel
  induction fuel with
  | zero =>
    intro i nw hsz hcap
    have e : stashMove s0 s1 old nw i 0 = nw := rfl
    rw [e]
    refine ⟨rfl, keeps_refl nw, ?_, fun q h1 h2 _ => by omega⟩
    simp
  | succ fuel ih =>
    intro i nw hsz hcap
    have e : stashMove s0 s1 old nw i (fuel + 1) =
        if wAt old (3 * i + 2) == 0 then stashMove s0 s1 old nw (i + 1) fuel
        else stashMove s0 s1 old (stashPut nw (wAt old (3 * i)) (wAt old (3 * i + 1)) (wAt old (3 * i + 2))
          (nw.size / 24 - 1)
          (stashHome (keyed s0 s1 (wAt old (3 * i)) (wAt old (3 * i + 1))) (nw.size / 24 - 1))
          (nw.size / 24 - 1 + 1)) (i + 1) fuel := rfl
    have e1 : i + 1 + fuel = i + (fuel + 1) := by omega
    rw [e]
    by_cases h0 : wAt old (3 * i + 2) = 0
    · rw [if_pos (beq_iff_eq.mpr h0)]
      have hc1 : Cn old (i + 1) = Cn old i := by simp only [Cn]; rw [if_pos h0, Nat.add_zero]
      obtain ⟨a, b, c, d⟩ := ih (i + 1) nw hsz (by rw [e1, hc1]; exact hcap)
      rw [e1, hc1] at c
      refine ⟨a, b, c, ?_⟩
      intro q hq1 hq2 hnf
      by_cases hqi : q = i
      · exact absurd (by rw [hqi]; exact h0) hnf
      · exact d q (by omega) (by omega) hnf
    · rw [if_neg (fun h => h0 (beq_iff_eq.mp h))]
      have hc1 : Cn old (i + 1) = Cn old i + 1 := by simp only [Cn]; rw [if_neg h0]
      have hmono := cn_mono old (i + 1) (i + (fuel + 1)) (by omega)
      have hcn : Cn nw (2 ^ n) < 2 ^ n := by omega
      obtain ⟨p1, p2, p3, p4⟩ := put_ok nw (wAt old (3 * i)) (wAt old (3 * i + 1)) (wAt old (3 * i + 2))
        (keyed s0 s1 (wAt old (3 * i)) (wAt old (3 * i + 1))) n hsz h0 hcn
      generalize stashPut nw (wAt old (3 * i)) (wAt old (3 * i + 1)) (wAt old (3 * i + 2))
        (nw.size / 24 - 1) (stashHome (keyed s0 s1 (wAt old (3 * i)) (wAt old (3 * i + 1))) (nw.size / 24 - 1))
        (nw.size / 24 - 1 + 1) = nw1 at p1 p2 p3 p4 ⊢
      have hsz1 : nw1.size = 24 * 2 ^ n := by rw [p1]; exact hsz
      obtain ⟨a, b, c, d⟩ := ih (i + 1) nw1 hsz1 (by rw [p4, e1, hc1]; omega)
      rw [p4, e1, hc1] at c
      refine ⟨a.trans p1, keeps_trans p2 b, by rw [c]; omega, ?_⟩
      intro q hq1 hq2 hnf
      by_cases hqi : q = i
      · subst hqi
        exact fndw_keeps ⟨n, by rw [hsz1]; omega⟩ b p3
      · exact d q (by omega) (by omega) hnf

/-! ## Well-formed tables -/

/-- The key `(h1, h2)`, row `seq`, is findable: a live slot in a bucket, or an entry in its stash run. -/
def Fnd1 (x : Idx) (h1 h2 : UInt64) (seq : Nat) : Prop :=
  FndB x.k x.p x.segs (keyed x.s0 x.s1 h1 h2) seq ∨ FndS x.stash h1 h2 (keyed x.s0 x.s1 h1 h2) seq

/-- Every used stash entry holds a non-empty slot word. -/
def SW (st : ByteArray) : Prop := ∀ q, wAt st (3 * q + 2) ≠ 0 → isEmpty (wAt st (3 * q + 2)) = false

/-- The stash after `m` inserts: a power-of-two number of entries (or none), at most half used, `sn` counting at least
    the used ones. -/
def StOK (st : ByteArray) (sn m : Nat) : Prop :=
  (st.size = 0 ∨ ∃ n, st.size = 24 * 2 ^ n) ∧ 2 * sn ≤ st.size / 24 ∧ Cn st (st.size / 24) ≤ sn ∧ sn ≤ m ∧
    st.size / 24 ≤ 16 + 4 * m ∧ SW st

/-- The table after `m` inserts is well formed: whole segments, slot prefixes, the buckets inside the segments and
    within `m` of the start size, and a well-formed stash. -/
def Wf (x : Idx) (m : Nat) : Prop :=
  SegsWf x.segs ∧ Pre x.segs ∧ x.p < 2 ^ x.k ∧ 2 ^ x.k + x.p ≤ 1023 * x.segs.size ∧ 2 ^ x.k + x.p ≤ 2 ^ 20 + m ∧
    StOK x.stash x.sn m

/-! ## The insert's stash branch -/

theorem stashPut_size (h1 h2 w : UInt64) (m : Nat) :
    ∀ fuel i (st : ByteArray), (stashPut st h1 h2 w m i fuel).size = st.size := by
  intro fuel
  induction fuel with
  | zero => intro i st; rfl
  | succ fuel ih =>
    intro i st
    have e : stashPut st h1 h2 w m i (fuel + 1) =
        if wAt st (3 * i + 2) == 0 then wSet (wSet (wSet st (3 * i) h1) (3 * i + 1) h2) (3 * i + 2) w
        else stashPut st h1 h2 w m ((i + 1) &&& m) fuel := rfl
    rw [e]
    split
    · simp only [wSet_size]
    · exact ih _ _

theorem stashPut_words (h1 h2 w : UInt64) (m : Nat) :
    ∀ fuel i (st : ByteArray), st.size % 8 = 0 → ∀ q, wAt (stashPut st h1 h2 w m i fuel) (3 * q + 2) = wAt st (3 * q + 2) ∨
      wAt (stashPut st h1 h2 w m i fuel) (3 * q + 2) = w := by
  intro fuel
  induction fuel with
  | zero => intro i st _ q; left; rfl
  | succ fuel ih =>
    intro i st hal q
    have e : stashPut st h1 h2 w m i (fuel + 1) =
        if wAt st (3 * i + 2) == 0 then wSet (wSet (wSet st (3 * i) h1) (3 * i + 1) h2) (3 * i + 2) w
        else stashPut st h1 h2 w m ((i + 1) &&& m) fuel := rfl
    rw [e]
    split
    · have s1 : (wSet st (3 * i) h1).size % 8 = 0 := by rw [wSet_size]; exact hal
      have s2 : (wSet (wSet st (3 * i) h1) (3 * i + 1) h2).size % 8 = 0 := by rw [wSet_size, wSet_size]; exact hal
      rw [wAt_wSet _ s2, wAt_wSet _ s1, wAt_wSet _ hal]
      simp only [wSet_size]
      by_cases h : 3 * q + 2 = 3 * i + 2
      · by_cases h' : 8 * (3 * i + 2) + 8 ≤ st.size
        · right; simp [h, h']
        · left; simp [h, h']
      · have h3 : ¬ (3 * q + 2 = 3 * i + 1) := by omega
        have h4 : ¬ (3 * q + 2 = 3 * i) := by omega
        left; simp only [h, h3, h4, false_and, if_false]
    · exact ih _ st hal q

theorem sw_put (h1 h2 w : UInt64) (hw : isEmpty w = false) (m : Nat) (fuel i : Nat) (st : ByteArray)
    (hal : st.size % 8 = 0) (h : SW st) : SW (stashPut st h1 h2 w m i fuel) := by
  intro q hq
  rcases stashPut_words h1 h2 w m fuel i st hal q with e | e
  · rw [e] at hq ⊢; exact h q hq
  · rw [e]; exact hw

theorem stashMove_sw (s0 s1 : UInt64) (old : ByteArray) (hold : SW old) :
    ∀ fuel i nw, nw.size % 8 = 0 → SW nw → SW (stashMove s0 s1 old nw i fuel) := by
  intro fuel
  induction fuel with
  | zero => intro i nw _ h; exact h
  | succ fuel ih =>
    intro i nw hal h
    have e : stashMove s0 s1 old nw i (fuel + 1) =
        if wAt old (3 * i + 2) == 0 then stashMove s0 s1 old nw (i + 1) fuel
        else stashMove s0 s1 old (stashPut nw (wAt old (3 * i)) (wAt old (3 * i + 1)) (wAt old (3 * i + 2))
          (nw.size / 24 - 1)
          (stashHome (keyed s0 s1 (wAt old (3 * i)) (wAt old (3 * i + 1))) (nw.size / 24 - 1))
          (nw.size / 24 - 1 + 1)) (i + 1) fuel := rfl
    rw [e]
    split
    · exact ih _ _ hal h
    · rename_i hne
      have hne' : wAt old (3 * i + 2) ≠ 0 := fun h0 => by simp [h0] at hne
      refine ih _ _ (by rw [stashPut_size]; exact hal) (sw_put _ _ _ (hold i hne') _ _ _ _ hal h)

theorem cn_pos (st : ByteArray) : ∀ i q, q < i → wAt st (3 * q + 2) ≠ 0 → 1 ≤ Cn st i := by
  intro i
  induction i with
  | zero => intro q h; omega
  | succ i ih =>
    intro q hq hne
    simp only [Cn]
    by_cases h : q < i
    · have := ih q h hne; omega
    · have : q = i := by omega
      subst this
      rw [if_neg hne]; omega

theorem cn_le (st : ByteArray) : ∀ i, Cn st i ≤ i := by
  intro i
  induction i with
  | zero => exact Nat.le_refl _
  | succ i ih => simp only [Cn]; split <;> omega

theorem pow2_max (c : Nat) (h : c = 0 ∨ ∃ n, c = 2 ^ n) : ∃ N, max 16 (2 * c) = 2 ^ N := by
  rcases h with rfl | ⟨n, rfl⟩
  · exact ⟨4, by decide⟩
  · by_cases hn : 3 ≤ n
    · refine ⟨n + 1, ?_⟩
      have : 2 ^ 3 ≤ 2 ^ n := Nat.pow_le_pow_right (by omega) hn
      rw [Nat.pow_succ]
      omega
    · refine ⟨4, ?_⟩
      have : 2 ^ n ≤ 2 ^ 2 := Nat.pow_le_pow_right (by omega) (by omega)
      omega

theorem and_low_sq (seq : Nat) (h : seq + 1 < 2 ^ 40) : (seq + 1).toUInt64 &&& lowMask = (seq + 1).toUInt64 := by
  apply bit_ext
  intro i _
  rw [bit_and, bit_lowMask]
  by_cases hi : i < 40
  · simp [hi]
  · have := bit_sq_hi seq h i (by omega)
    rw [this]; simp [hi]

theorem isEmpty_sq (seq : Nat) (h : seq + 1 < 2 ^ 40) : isEmpty (seq + 1).toUInt64 = false := by
  unfold isEmpty
  rw [and_low_sq seq h]
  have hne : (seq + 1).toUInt64 ≠ 0 := fun e => by
    have := sq_toNat seq h
    rw [e] at this
    simp at this
  exact Bool.eq_false_iff.mpr (fun e => hne (beq_iff_eq.mp e))

theorem seqOf_sq (seq : Nat) (h : seq + 1 < 2 ^ 40) : seqOf (seq + 1).toUInt64 = seq := by
  unfold seqOf
  rw [and_low_sq seq h]
  have p1 : (1 : UInt64) ≤ (seq + 1).toUInt64 := by
    rw [UInt64.le_iff_toNat_le, sq_toNat seq h]; show 1 ≤ seq + 1; omega
  rw [UInt64.toNat_sub_of_le _ _ p1, sq_toNat seq h]
  show seq + 1 - 1 = seq
  omega


/-- The stash after making room (doubling when it would pass half full): a power-of-two table with room, every
    stashed key still findable. -/
theorem ins_grow (s0 s1 : UInt64) (st st1 : ByteArray) (sn m : Nat) (hS : StOK st sn m)
    (h1e : st1 = if 2 * (sn + 1) ≤ st.size / 24 then st
      else stashMove s0 s1 st (zeros (24 * max 16 (2 * (st.size / 24)))) 0 (st.size / 24)) :
    ∃ n, st1.size = 24 * 2 ^ n ∧ Cn st1 (2 ^ n) ≤ sn ∧ 2 * (sn + 1) ≤ 2 ^ n ∧ 2 ^ n ≤ 16 + 4 * (m + 1) ∧ SW st1 ∧
      ∀ g1 g2 sq, FndS st g1 g2 (keyed s0 s1 g1 g2) sq → FndS st1 g1 g2 (keyed s0 s1 g1 g2) sq := by
  obtain ⟨hp2, hhalf, hcn, hsnm, hcm, hsw⟩ := hS
  by_cases hg : 2 * (sn + 1) ≤ st.size / 24
  · rw [if_pos hg] at h1e
    subst h1e
    have hne : st1.size ≠ 0 := by omega
    obtain ⟨n, hn⟩ : ∃ n, st1.size = 24 * 2 ^ n := by
      rcases hp2 with h | h
      · exact absurd h hne
      · exact h
    have hc : st1.size / 24 = 2 ^ n := by omega
    rw [hc] at hcn hhalf hg hcm
    exact ⟨n, hn, hcn, hg, by omega, hsw, fun _ _ _ h => h⟩
  · rw [if_neg hg] at h1e
    have hc0 : st.size / 24 = 0 ∨ ∃ n, st.size / 24 = 2 ^ n := by
      rcases hp2 with h | ⟨n, hn⟩
      · left; omega
      · right; exact ⟨n, by omega⟩
    obtain ⟨N, hN⟩ := pow2_max _ hc0
    have hsz : (zeros (24 * max 16 (2 * (st.size / 24)))).size = 24 * 2 ^ N := by
      rw [zeros_size, hN]
    have hcle := cn_le st (st.size / 24)
    have hm1 : 16 ≤ 2 ^ N := by rw [← hN]; exact Nat.le_max_left _ _
    have hm2 : 2 * (st.size / 24) ≤ 2 ^ N := by rw [← hN]; exact Nat.le_max_right _ _
    have hm3 : 2 ^ N = 16 ∨ 2 ^ N = 2 * (st.size / 24) := by
      rw [← hN]
      rcases Nat.le_total 16 (2 * (st.size / 24)) with h | h
      · right; exact Nat.max_eq_right h
      · left; exact Nat.max_eq_left h
    have hcap : Cn (zeros (24 * max 16 (2 * (st.size / 24)))) (2 ^ N) +
        (Cn st (0 + st.size / 24) - Cn st 0) ≤ 2 ^ N := by
      simp only [cn_zeros, Nat.zero_add]
      have : Cn st 0 = 0 := rfl
      omega
    obtain ⟨a, b, c, d⟩ := stashMove_spec s0 s1 st N (st.size / 24) 0 _ hsz hcap
    rw [← h1e] at a c d
    refine ⟨N, by rw [a, hsz], ?_, by omega, by omega, ?_, ?_⟩
    · rw [c]
      simp only [cn_zeros, Nat.zero_add]
      have : Cn st 0 = 0 := rfl
      omega
    · subst h1e
      exact stashMove_sw s0 s1 st hsw _ _ _ (by rw [hsz]; omega)
        (fun q hq => absurd (wAt_zeros _ _) hq)
    · intro g1 g2 sq hF
      obtain ⟨w, hW, hsq⟩ := fndw_of_fnds hF
      obtain ⟨dd, hd, hr, hw, e1, e2, hne⟩ := hW
      obtain ⟨n0, hn0⟩ : ∃ n0, st.size = 24 * 2 ^ n0 := by
        rcases hp2 with h | h
        · omega
        · exact h
      have hc : st.size / 24 = 2 ^ n0 := by omega
      have hq : (sHome (keyed s0 s1 g1 g2) + dd) &&& (st.size / 24 - 1) < st.size / 24 := by
        rw [hc, andm]; exact Nat.mod_lt _ (Nat.two_pow_pos n0)
      generalize (sHome (keyed s0 s1 g1 g2) + dd) &&& (st.size / 24 - 1) = q' at hq hw e1 e2
      have hnz : wAt st (3 * q' + 2) ≠ 0 := by rw [hw]; exact hne
      have := d q' (Nat.zero_le _) (by omega) hnz
      rw [e1, e2, hw] at this
      exact fnds_of_fndw this sq hsq

theorem ins_stash (s0 s1 : UInt64) (st st1 : ByteArray) (sn m : Nat) (hS : StOK st sn m) (h1 h2 : UInt64) (seq : Nat)
    (hs : seq + 1 < 2 ^ 40)
    (h1e : st1 = if 2 * (sn + 1) ≤ st.size / 24 then st
      else stashMove s0 s1 st (zeros (24 * max 16 (2 * (st.size / 24)))) 0 (st.size / 24)) :
    StOK (stashPut st1 h1 h2 (seq + 1).toUInt64 (st1.size / 24 - 1)
        (stashHome (keyed s0 s1 h1 h2) (st1.size / 24 - 1)) (st1.size / 24 - 1 + 1)) (sn + 1) (m + 1) ∧
    FndS (stashPut st1 h1 h2 (seq + 1).toUInt64 (st1.size / 24 - 1)
        (stashHome (keyed s0 s1 h1 h2) (st1.size / 24 - 1)) (st1.size / 24 - 1 + 1)) h1 h2 (keyed s0 s1 h1 h2) seq ∧
    ∀ g1 g2 sq, FndS st g1 g2 (keyed s0 s1 g1 g2) sq →
      FndS (stashPut st1 h1 h2 (seq + 1).toUInt64 (st1.size / 24 - 1)
        (stashHome (keyed s0 s1 h1 h2) (st1.size / 24 - 1)) (st1.size / 24 - 1 + 1)) g1 g2 (keyed s0 s1 g1 g2) sq := by
  obtain ⟨n, hsz, hcn, hroom, hcm, hsw, hfnd⟩ := ins_grow s0 s1 st st1 sn m hS h1e
  have hw : (seq + 1).toUInt64 ≠ 0 := fun e => by
    have := sq_toNat seq hs
    rw [e] at this
    simp at this
  have hfree : Cn st1 (2 ^ n) < 2 ^ n := by omega
  have hsnm := hS.2.2.2.1
  obtain ⟨p1, p2, p3, p4⟩ := put_ok st1 h1 h2 (seq + 1).toUInt64 (keyed s0 s1 h1 h2) n hsz hw hfree
  have hc : st1.size / 24 = 2 ^ n := by omega
  have hal : st1.size % 8 = 0 := by omega
  have hsw2 := sw_put h1 h2 (seq + 1).toUInt64 (isEmpty_sq seq hs) (st1.size / 24 - 1)
    (st1.size / 24 - 1 + 1) (stashHome (keyed s0 s1 h1 h2) (st1.size / 24 - 1)) st1 hal hsw
  generalize stashPut st1 h1 h2 (seq + 1).toUInt64 (st1.size / 24 - 1)
    (stashHome (keyed s0 s1 h1 h2) (st1.size / 24 - 1)) (st1.size / 24 - 1 + 1) = stp at p1 p2 p3 p4 hsw2 ⊢
  have e24 : stp.size / 24 = 2 ^ n := by rw [p1, hc]
  refine ⟨⟨Or.inr ⟨n, by rw [p1]; exact hsz⟩, by rw [e24]; omega, by rw [e24, p4]; omega, by omega,
    by rw [e24]; omega, hsw2⟩, ?_, ?_⟩
  · exact fnds_of_fndw p3 seq (seqOf_sq seq hs)
  · intro g1 g2 sq hF
    obtain ⟨w, hW, hsq⟩ := fndw_of_fnds (hfnd g1 g2 sq hF)
    exact fnds_of_fndw (fndw_keeps ⟨n, hc⟩ p2 hW) sq hsq

/-! ## Splitting a bucket -/

theorem get_extract (t : ByteArray) (a i : Nat) (h : i < 64) (h2 : a + 64 ≤ t.size) :
    (t.extract a (a + 64)).get! i = t.get! (a + i) := by
  have hs : t.data.size = t.size := ByteArray.size_data
  show (t.extract a (a + 64)).data[i]! = t.data[a + i]!
  rw [ByteArray.data_extract]
  have h3 : i < (t.data.extract a (a + 64)).size := by rw [Array.size_extract]; omega
  rw [getElem!_pos (t.data.extract a (a + 64)) i h3, getElem!_pos t.data (a + i) (by omega)]
  simp [Array.getElem_extract]

theorem wAt_extract (t : ByteArray) (a j : Nat) (ha : a % 8 = 0) (hj : j < 8) (h2 : a + 64 ≤ t.size) :
    wAt (t.extract a (a + 64)) j = wAt t (a / 8 + j) := by
  have e : ∀ i, i < 8 → (t.extract a (a + 64)).get! (8 * j + i) = t.get! (8 * (a / 8 + j) + i) := by
    intro i hi
    rw [get_extract t a _ (by omega) h2]
    congr 1
    omega
  rw [wAt_unfold, wAt_unfold, e 0 (by omega), e 1 (by omega), e 2 (by omega), e 3 (by omega), e 4 (by omega),
    e 5 (by omega), e 6 (by omega), e 7 (by omega)]

theorem clearW_zero (t : ByteArray) (o c : Nat) : clearW t o c 0 = t := rfl

theorem clearW_succ (t : ByteArray) (o c f : Nat) :
    clearW t o c (f + 1) = clearW (wSet t (o + c) 0) o (c + 1) f := by
  conv => lhs; unfold clearW

theorem clearW_spec (o : Nat) : ∀ (f c : Nat) (t : ByteArray), t.size % 8 = 0 → 8 * (o + c + f) ≤ t.size →
    (clearW t o c f).size = t.size ∧ (∀ w, (w < o + c ∨ o + c + f ≤ w) → wAt (clearW t o c f) w = wAt t w) ∧
      ∀ w, o + c ≤ w → w < o + c + f → wAt (clearW t o c f) w = 0 := by
  intro f
  induction f with
  | zero =>
    intro c t _ _
    rw [clearW_zero]
    exact ⟨rfl, fun _ _ => rfl, fun w h1 h2 => by omega⟩
  | succ f ih =>
    intro c t hal hsz
    have e : clearW t o c (f + 1) = clearW (wSet t (o + c) 0) o (c + 1) f := clearW_succ t o c f
    rw [e]
    have hal' : (wSet t (o + c) 0).size % 8 = 0 := by rw [wSet_size]; exact hal
    obtain ⟨a, b, d⟩ := ih (c + 1) (wSet t (o + c) 0) hal' (by rw [wSet_size]; omega)
    refine ⟨by rw [a, wSet_size], ?_, ?_⟩
    · intro w hw
      rw [b w (by omega), wAt_wSet_ne _ _ _ _ (by omega)]
    · intro w h1 h2
      by_cases hw : w = o + c
      · subst hw
        rw [b _ (by omega), wAt_wSet_in _ hal _ _ _ (by omega)]
        simp
      · exact d w (by omega) (by omega)




/-! ## Addresses after a split -/

theorem pow_succ2 (k : Nat) : 2 ^ (k + 1) = 2 * 2 ^ k := by rw [Nat.pow_succ]; omega

theorem lt64 (k : Nat) (hk : k ≤ 47) : 2 ^ (k + 1) < 2 ^ 64 := by
  have h1 : 2 ^ (k + 1) ≤ 2 ^ 48 := Nat.pow_le_pow_right (by omega) (by omega)
  have h2 : (2 : Nat) ^ 48 < 2 ^ 64 := by decide
  omega

theorem lvl_old (k p : Nat) (hk : k ≤ 47) (hp : p < 2 ^ k) : lvlK k p p = k := by
  have h2 := pow_succ2 k
  have hb64 : p < 2 ^ 64 := by have := lt64 k hk; omega
  rw [lvlK_eq k p p (by omega) hb64, if_neg (by omega)]


theorem isEmpty_zero : isEmpty 0 = true := by decide


/-! ## Placing a stash entry in the buckets -/

theorem ov_props (v ov : UInt64) (hov : ∀ i, i ≠ 40 → bit ov i = false) :
    (v ||| ov) &&& lowMask = v &&& lowMask ∧ (v ||| ov) &&& tagMask = v &&& tagMask ∧
      resOf (v ||| ov) = resOf v := by
  refine ⟨?_, ?_, ?_⟩
  · apply bit_ext; intro i hi
    rw [bit_and, bit_and, bit_or, bit_lowMask]
    by_cases h : i < 40
    · rw [hov i (by omega)]; simp
    · simp [h]
  · apply bit_ext; intro i hi
    rw [bit_and, bit_and, bit_or, bit_tagMask]
    by_cases h : i = 40
    · subst h; simp
    · rw [hov i h]; simp
  · apply bit_ext; intro i hi
    rw [bit_resOf, bit_resOf, bit_or]
    by_cases h : i < 14
    · rw [hov (i + 42) (by omega)]; simp
    · simp [h]

theorem ov_over (w : UInt64) : ∀ i, i ≠ 40 → bit (w &&& overBit) i = false := by
  intro i hi
  rw [bit_and, bit_overBit]
  have : decide (40 = i) = false := decide_eq_false (fun e => hi e.symm)
  rw [this]; simp

theorem seqOf_lt (w : UInt64) (h : isEmpty w = false) : seqOf w + 1 < 2 ^ 40 := by
  unfold isEmpty at h
  unfold seqOf
  have hne : w &&& lowMask ≠ 0 := fun e => by rw [e] at h; simp at h
  have h1 : 1 ≤ (w &&& lowMask).toNat := by
    have : (w &&& lowMask).toNat ≠ 0 := fun e => hne (UInt64.toNat_inj.mp (by simpa using e))
    omega
  have h2 : (w &&& lowMask).toNat ≤ 2 ^ 40 - 1 := by
    rw [UInt64.toNat_and]
    exact Nat.le_trans Nat.and_le_right (by decide)
  have p1 : (1 : UInt64) ≤ w &&& lowMask := by
    rw [UInt64.le_iff_toNat_le]; simpa using h1
  rw [UInt64.toNat_sub_of_le _ _ p1]
  have h3 : (1 : UInt64).toNat = 1 := rfl
  rw [h3]
  omega


theorem k47 (k p m : Nat) (hnb : 2 ^ k + p ≤ 2 ^ 20 + m) (hm : m < 2 ^ 40) : k ≤ 47 := by
  refine Nat.le_of_not_lt (fun h => ?_)
  have h1 : 2 ^ 48 ≤ 2 ^ k := Nat.pow_le_pow_right (by omega) (by omega)
  have h3 : (2 : Nat) ^ 40 ≤ 2 ^ 48 := Nat.pow_le_pow_right (by omega) (by omega)
  have h4 : (2 : Nat) ^ 20 ≤ 2 ^ 40 := Nat.pow_le_pow_right (by omega) (by omega)
  have h5 : (2 : Nat) ^ 40 + 2 ^ 40 ≤ 2 ^ 48 := by decide
  omega


/-! ## Splitting a bucket -/

theorem slotAt_push_lt (segs : Array ByteArray) (b j : Nat) (hb : b / 1023 < segs.size) :
    slotAt (segs.push (zeros 65472)) b j = slotAt segs b j := by
  rw [slotAt_mod, slotAt_mod segs, slotAt_eq _ _ _ (Nat.mod_lt _ (by decide)),
    slotAt_eq _ _ _ (Nat.mod_lt _ (by decide))]
  rw [Array.getD_eq_getD_getElem?, Array.getD_eq_getD_getElem?, Array.getElem?_push_lt hb, Array.getElem?_eq_getElem hb]

theorem slotAt_push_out (segs : Array ByteArray) (b j : Nat) (hb : ¬ b / 1023 < segs.size) :
    slotAt (segs.push (zeros 65472)) b j = 0 := by
  rw [slotAt_mod]
  by_cases h : b / 1023 = segs.size
  · rw [slotAt_eq _ _ _ (Nat.mod_lt _ (by decide)), Array.getD_eq_getD_getElem?, h, Array.getElem?_push_size]
    simp [wAt_zeros]
  · by_cases hne : slotAt (segs.push (zeros 65472)) b (j % 8) = 0
    · exact hne
    exfalso
    have := slotAt_ne_zero_inb _ b (j % 8) (Nat.mod_lt _ (by decide)) hne
    rw [Array.size_push] at this
    omega

theorem push_facts (segs : Array ByteArray) (hw : SegsWf segs) (hP : Pre segs) :
    SegsWf (segs.push (zeros 65472)) ∧ Pre (segs.push (zeros 65472)) ∧
      (segs.push (zeros 65472)).size = segs.size + 1 ∧
      ∀ k p a s, FndB k p segs a s → FndB k p (segs.push (zeros 65472)) a s := by
  refine ⟨?_, ?_, Array.size_push .., ?_⟩
  · intro i hi
    rw [Array.size_push] at hi
    by_cases h : i < segs.size
    · rw [Array.getElem_push_lt h]; exact hw i h
    · have : i = segs.size := by omega
      subst this
      rw [Array.getElem_push_eq]; exact zeros_size _
  · intro b j hj he
    by_cases hb : b / 1023 < segs.size
    · rw [slotAt_push_lt _ _ _ hb] at he ⊢; exact hP b j hj he
    · rw [slotAt_push_out _ _ _ hb]; exact isEmpty_zero
  · rintro k p a s ⟨b, j, hj, he, hs, c, hc⟩
    have hne : slotAt segs b j ≠ 0 := fun e => by rw [e] at he; simp [isEmpty_zero] at he
    have hb := slotAt_ne_zero_inb segs b j hj hne
    refine ⟨b, j, hj, ?_, ?_, c, ?_⟩ <;> rw [slotAt_push_lt _ _ _ hb] <;> assumption

/-! ## Insert -/

/-- The table after the split check of an insert. -/
def finish (x : Idx) : Idx := if 10 * (x.n + x.sn) > 72 * x.nb then x.split else x

/-- `x'` is `x` with the key `(h1, h2)`, row `seq`, placed (before any split): same shape, the keys of `x` still
    findable, the new one findable. -/
def Core (x x' : Idx) (m : Nat) (h1 h2 : UInt64) (seq : Nat) : Prop :=
  x'.k = x.k ∧ x'.p = x.p ∧ x'.s0 = x.s0 ∧ x'.s1 = x.s1 ∧ x'.segs.size = x.segs.size ∧ SegsWf x'.segs ∧
    Pre x'.segs ∧ StOK x'.stash x'.sn (m + 1) ∧ (∀ g1 g2 sq, Fnd1 x g1 g2 sq → Fnd1 x' g1 g2 sq) ∧
    Fnd1 x' h1 h2 seq

theorem stok_mono (st : ByteArray) (sn m m' : Nat) (h : StOK st sn m) (hm : m ≤ m') : StOK st sn m' := by
  obtain ⟨a, b, c, d, e, f⟩ := h
  exact ⟨a, b, c, by omega, by omega, f⟩

theorem core_stash (x : Idx) (m : Nat) (hw : Wf x m) (st2 : ByteArray) (n' : Nat) (h1 h2 : UInt64) (seq : Nat)
    (hst : StOK st2 (x.sn + 1) (m + 1)) (hfn : FndS st2 h1 h2 (keyed x.s0 x.s1 h1 h2) seq)
    (hfa : ∀ g1 g2 sq, FndS x.stash g1 g2 (keyed x.s0 x.s1 g1 g2) sq → FndS st2 g1 g2 (keyed x.s0 x.s1 g1 g2) sq) :
    Core x ⟨x.segs, x.k, x.p, n', st2, x.sn + 1, x.s0, x.s1⟩ m h1 h2 seq := by
  refine ⟨rfl, rfl, rfl, rfl, rfl, hw.1, hw.2.1, hst, ?_, Or.inr hfn⟩
  intro g1 g2 sq h
  rcases h with h | h
  · exact Or.inl h
  · exact Or.inr (hfa _ _ _ h)

theorem full_of_used (S : Array ByteArray) (hP : Pre S) (b : Nat) (h : ¬ usedIn S b < 8) :
    isEmpty (slotAt S b 7) = false := by
  obtain ⟨h1, h2, _⟩ := usedIn_spec S b (fun j hj => hP b j hj)
  exact h2 7 (by omega)

/-! ## The build -/

theorem new_eq (k0 : Nat) (s0 s1 : UInt64) :
    Idx.newKeyed k0 s0 s1 =
      ⟨Array.replicate (max 1 ((2 ^ k0 + 1022) / 1023)) (zeros 65472), k0, 0, 0, .empty, 0, s0, s1⟩ := by
  unfold Idx.newKeyed
  simp only [Std.Legacy.Range.forIn_eq_forIn_range']
  simp [List.forIn_pure_yield_eq_foldl, Std.Legacy.Range.size]
  apply Array.ext'
  simp [List.map_const']

theorem slot_rep (m b j : Nat) : slotAt (Array.replicate m (zeros 65472)) b j = 0 := by
  have hE : (ByteArray.empty : ByteArray) = zeros 0 := rfl
  unfold slotAt
  rw [Array.getD_eq_getD_getElem?, Array.getElem?_replicate]
  split <;> simp [hE, wAt_zeros]

theorem new_wf (k0 : Nat) (hk0 : k0 ≤ 20) (s0 s1 : UInt64) : Wf (Idx.newKeyed k0 s0 s1) 0 := by
  rw [new_eq]
  have hE : (ByteArray.empty : ByteArray) = zeros 0 := rfl
  have hpos := Nat.two_pow_pos k0
  have h20 : 2 ^ k0 ≤ 2 ^ 20 := Nat.pow_le_pow_right (by omega) hk0
  dsimp only [Wf]
  refine ⟨?_, ?_, hpos, ?_, by omega, ?_⟩
  · intro i hi; simp [zeros_size]
  · intro b j _ _; rw [slot_rep]; exact isEmpty_zero
  · rw [Array.size_replicate]
    have h1 := Nat.div_add_mod (2 ^ k0 + 1022) 1023
    have h2 := Nat.mod_lt (2 ^ k0 + 1022) (show 1023 > 0 by decide)
    have h4 : 1023 * ((2 ^ k0 + 1022) / 1023) ≤ 1023 * max 1 ((2 ^ k0 + 1022) / 1023) :=
      Nat.mul_le_mul_left _ (Nat.le_max_right _ _)
    omega
  · show StOK ByteArray.empty 0 0
    rw [hE]
    refine ⟨Or.inl (zeros_size _), by omega, ?_, by omega, by rw [zeros_size]; omega, ?_⟩
    · rw [zeros_size]; simp [Cn]
    · intro q hq; rw [wAt_zeros] at hq; exact absurd rfl hq

end BlindLedger.Gate.Engine3.Index
