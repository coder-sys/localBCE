import BlindLedger.Gate.Engine3.Frame3
import BlindLedger.Gate.Flat.Io
import BlindLedger.Gate.Engine3.Index

/-! The checker's own rows file.  A record is 320 bytes: the 256-byte rows record (the 245-byte row, then 11 link bytes:
    the previous row of its core plus one, its core's row count, flags, zeros), then a 64-byte tag

      `H512(dom VTAG2 ‖ k ‖ shard u32 ‖ set u8 ‖ seq u64 ‖ record)`,

    one hash of 318 bytes (five permutations).  Record `seq` sits at byte `320 · seq`.  Without the key `k` a party that can
    write the files cannot make a record the checker accepts; a record moved to another place, set or shard fails
    because the tag names them.  `k` is 32 bytes, sealed for the current user by DPAPI in a file of its own, and a new
    one is made whenever the store is rebuilt, so no record of an earlier build passes either.  A file written under the
    earlier tag (`VTAG`: a leaf of the row, then a tag over the leaf and the link bytes) holds no record that passes
    this one, so it is cut to nothing at open and rebuilt from the log.

    The file is a projection of the log: a torn tail, or the first record that fails its tag, is cut back at open, and
    the caller replays the log from there.  An open store never holds a bad record.  The newest records appended in
    this process are also kept in memory (tagged when they were made), so a fetch of one costs no read and no hash.
    Anything older, and everything after a restart, is read and its tag computed again. -/

namespace BlindLedger.Gate.Engine3.VStore

open BlindLedger.Gate.Flat

def recLen : Nat := 256
def tagLen : Nat := 64
def sealedLen : Nat := recLen + tagLen
/-- Records kept in memory: the newest this many appended in this process, in a ring allocated once at open (at its exact size, never through an array of boxed bytes). -/
def cacheRows : Nat := 65536

/-- The tag of the 256-byte record `rec` as place `seq` of set `set` of shard `shard` under `k`: the definition, by the
    generic digest. -/
def tagOf (k : ByteArray) (shard set seq : Nat) (rec : ByteArray) : ByteArray :=
  hD "VTAG2" [k, putN ByteArray.empty shard 4, putN ByteArray.empty set 1, putN ByteArray.empty seq 8, rec.extract 0 recLen]

/-- What every tag of one set starts with: the domain, the key, the shard and the set. -/
def preOf (k : ByteArray) (shard set : Nat) : ByteArray := putN (putN (domB "VTAG2" ++ k) shard 4) set 1

/-- `acc` followed by the tag of the record at byte `off` of `b` as place `seq`, the record read in place (`tagOf`). -/
@[inline] def tagInto (acc pre b : ByteArray) (off seq : Nat) : ByteArray :=
  sha3_512Into acc (putN pre seq 8) b off recLen

/-- `a[ao, ao + n)` equals `b[bo, bo + n)`; false when either is out of range. -/
@[extern c inline "({ extern int rr_memcmp(const void*, const void*, size_t) __asm__(\"memcmp\"); (lean_is_scalar(#2) && lean_is_scalar(#4) && lean_is_scalar(#5) && lean_unbox(#2) + lean_unbox(#5) <= lean_sarray_size(#1) && lean_unbox(#4) + lean_unbox(#5) <= lean_sarray_size(#3) && rr_memcmp(lean_sarray_cptr(#1) + lean_unbox(#2), lean_sarray_cptr(#3) + lean_unbox(#4), lean_unbox(#5)) == 0); })"]
def eqRange (a : @& ByteArray) (ao : @& Nat) (b : @& ByteArray) (bo : @& Nat) (n : @& Nat) : Bool :=
  ao + n ≤ a.size && bo + n ≤ b.size && a.extract ao (ao + n) == b.extract bo (bo + n)

/-- The tag of the 256 bytes of `raw` from `off` is the 64 bytes after them. -/
def holds (pre raw : ByteArray) (off seq : Nat) : Bool :=
  off + sealedLen ≤ raw.size && eqRange (tagInto ByteArray.empty pre raw off seq) 0 raw (off + recLen) tagLen

/-- The 320 stored bytes of `recs[off, off + 256)` as place `seq`, appended to `acc`. -/
def packInto (acc pre recs : ByteArray) (off seq : Nat) : ByteArray :=
  tagInto (recs.copySlice off acc acc.size recLen false) pre recs off seq

/-! ## The key -/

/-- DPAPI for the current user with no UI (crypt32 `CryptProtectData` when `enc` is 1, `CryptUnprotectData` when 0)
    of `data` with entropy `ent`; empty when it fails.  crypt32 is loaded by name and the kernel32 calls are
    asm-labelled, as in `Io`. -/
@[extern c inline "({ extern void* rr_ll(const char*) __asm__(\"LoadLibraryA\"); extern void* rr_gpa(void*, const char*) __asm__(\"GetProcAddress\"); extern void* rr_lfree(void*) __asm__(\"LocalFree\"); struct rr_blob { unsigned cb; unsigned char* pb; }; typedef int (*rr_dpf)(struct rr_blob*, void*, struct rr_blob*, void*, void*, unsigned, struct rr_blob*); void* m = rr_ll(\"crypt32.dll\"); rr_dpf f = m ? (rr_dpf)rr_gpa(m, #1 ? \"CryptProtectData\" : \"CryptUnprotectData\") : 0; struct rr_blob di = { (unsigned)lean_sarray_size(#2), lean_sarray_cptr(#2) }; struct rr_blob de = { (unsigned)lean_sarray_size(#3), lean_sarray_cptr(#3) }; struct rr_blob dout = { 0, 0 }; int ok = f != 0 && f(&di, 0, &de, 0, 0, 1, &dout) != 0; size_t n = ok ? dout.cb : 0; lean_object* a = lean_alloc_sarray(1, n, n); for (size_t i = 0; i < n; i++) lean_sarray_cptr(a)[i] = dout.pb[i]; if (ok) rr_lfree(dout.pb); lean_io_result_mk_ok(a); })"]
opaque dpapi (enc : UInt8) (data : @& ByteArray) (ent : @& ByteArray) : IO ByteArray

def keyEnt : ByteArray := domB "VKEY"

/-- The key sealed in `path`; none when the file is missing or does not open to 32 bytes for this user. -/
def loadKey (path : String) : IO (Option ByteArray) := do
  if !(← System.FilePath.pathExists path) then return none
  let k ← dpapi 0 (← IO.FS.readBinFile path) keyEnt
  return if k.size == 32 then some k else none

/-- A fresh key, sealed into `path` (written beside it, then renamed over it).  Every record and state tagged under an
    earlier key fails from now on. -/
def newKey (path : String) : IO ByteArray := do
  let k ← IO.getRandomBytes 32
  let b ← dpapi 1 k keyEnt
  if b.isEmpty then throw (IO.userError "VStore: DPAPI seal")
  IO.FS.writeBinFile s!"{path}.new" b
  IO.FS.rename s!"{path}.new" path
  return k

/-! ## The file -/

/-- An open file: `n` good records from place 0. -/
structure T where
  fd : UInt32
  /-- `preOf` of the key, shard and set. -/
  pre : ByteArray
  n : Nat
  /-- The bytes cut from the end when it was opened. -/
  cut : Nat
  /-- `cacheRows` slots of 256 bytes; place `q` is in slot `q % cacheRows` while `q` is among the newest `cacheRows` places and
      at least `tailAt` (the first place appended in this process). -/
  ring : ByteArray
  tailAt : Nat

/-- The lowest place held in memory. -/
def T.lo (s : T) : Nat := max s.tailAt (s.n - cacheRows)

/-- The memory copy of place `q` (which must be held there) is 256 bytes from this offset of `ring`. -/
def slotOff (q : Nat) : Nat := recLen * (q % cacheRows)

/-- Record `seq` read from the file, if it is whole and its tag holds. -/
def readAt (fd : UInt32) (pre : ByteArray) (seq : Nat) : IO (Option ByteArray) := do
  let raw ← Io.pgReadAt fd (sealedLen * seq).toUInt64 sealedLen.toUSize
  return if holds pre raw 0 seq then some (raw.extract 0 recLen) else none

/-- Opens (creating) `path` for set `set` of shard `shard` under `k`, cuts it back to its longest run of good records
    from place 0 and syncs.  Each good record goes through `each` as it is checked (`each get acc blk i seq`: the
    record at byte `320 · i` of `blk` is place `seq`; `get` reads an earlier place, checked), so what is built from the
    file is built from the bytes whose tags held. -/
def openAt {β : Type} (path : String) (k : ByteArray) (shard set : Nat) (init : β)
    (each : (Nat → IO (Option ByteArray)) → β → ByteArray → Nat → Nat → IO β) : IO (Except String (T × β)) := do
  let fd ← Io.pgOpen path
  if fd == 0xFFFFFFFF then return .error "open"
  let size := (← System.FilePath.metadata path).byteSize.toNat
  let pre := preOf k shard set
  let mut n := 0
  let mut acc := init
  repeat
    let want := min 64 ((size - sealedLen * n) / sealedLen)
    if want == 0 then break
    let blk ← Io.pgRead fd (sealedLen * n).toUInt64 (sealedLen * want).toUSize
    let mut good := 0
    for i in [0:want] do
      if good == i && holds pre blk (sealedLen * i) (n + i) then
        acc ← each (readAt fd pre) acc blk i (n + i)
        good := i + 1
    n := n + good
    if good < want then break
  let cut := size - sealedLen * n
  if cut != 0 then
    if (← Io.pgTrunc fd (sealedLen * n).toUInt64) != 0 || (← Io.pgSync fd) != 0 then
      let _ ← Io.pgClose fd
      return .error "trunc"
  return .ok (⟨fd, pre, n, cut, Index.zeros (cacheRows * recLen), n⟩, acc)

/-- `recs` (a whole number of 256-byte records) as the next places, in one write; an IO error if the write fails.  Not
    synced: a lost tail is replayed from the log.  Take `s` by value and keep no other reference to it, or the ring is copied. -/
def appendMany (s : T) (recs : ByteArray) : IO T := do
  if recs.size % recLen != 0 then throw (IO.userError "VStore: record size")
  let ⟨fd, pre, n, cut, ring, tailAt⟩ := s
  let cnt := recs.size / recLen
  let mut raw := ByteArray.emptyWithCapacity (sealedLen * cnt)
  for i in [0:cnt] do raw := packInto raw pre recs (recLen * i) (n + i)
  if (← Io.pgWrite fd (sealedLen * n).toUInt64 raw) != 0 then throw (IO.userError "VStore: write")
  let mut ring := ring
  for i in [cnt - min cnt cacheRows:cnt] do ring := recs.copySlice (recLen * i) ring (slotOff (n + i)) recLen false
  return ⟨fd, pre, n + cnt, cut, ring, tailAt⟩

/-- The record at place `seq`, if it is there and its tag holds. -/
def fetch (s : T) (seq : Nat) : IO (Option ByteArray) := do
  if seq >= s.n then return none
  if s.lo ≤ seq then return some (s.ring.extract (slotOff seq) (slotOff seq + recLen))
  readAt s.fd s.pre seq

def close (s : T) : IO Unit := do let _ ← Io.pgClose s.fd

end BlindLedger.Gate.Engine3.VStore
