import Std.Tactic.BVDecide
import BlindLedger.Gate.Engine3.Layout
import BlindLedger.Gate.Flat.Io
import BlindLedger.Gate.Flat.Bin

/-! The store secret and key digests of conformance/ENGINE_V3.md section 2.

    `kd = H256(dom KEY2 ‖ s ‖ kb)`, `kb` a key's kind and fields at store widths (`kbytes`, without the set tag).  Its
    four 64-bit words are the sort hash and the directory hash of the released set and of the unresolved set.  The
    model's `dh` and `kh` take a key's stored bytes `sk u k` (set tag first), which `dhM` and `khM` cut the same way. -/

namespace BlindLedger.Gate.Engine3

open BlindLedger.Gate.Flat

/-- The bytes of `RR/GATE/KEY2/v1` and its zero byte. -/
def keyDom : ByteArray := Bin.bytesOf (domain "KEY2")

/-- Little-endian 64-bit word at offset `o`. -/
@[inline] def le64At (d : ByteArray) (o : Nat) : UInt64 :=
  d[o]!.toUInt64 ||| (d[o + 1]!.toUInt64 <<< 8) ||| (d[o + 2]!.toUInt64 <<< 16) ||| (d[o + 3]!.toUInt64 <<< 24) |||
    (d[o + 4]!.toUInt64 <<< 32) ||| (d[o + 5]!.toUInt64 <<< 40) ||| (d[o + 6]!.toUInt64 <<< 48) |||
    (d[o + 7]!.toUInt64 <<< 56)

/-- A key's digest from the secret and the key bytes `kb` (kind and fields). -/
def keyDigest (sec kb : ByteArray) : ByteArray := BlindLedger.Semantic.sha3_256Quick (keyDom ++ sec ++ kb)

/-- The four words of a digest: sort hash and directory hash, released then unresolved set. -/
@[inline] def khAt (kd : ByteArray) (unres : Bool) : UInt64 := le64At kd (if unres then 8 else 0)
@[inline] def dhAt (kd : ByteArray) (unres : Bool) : UInt64 := le64At kd (if unres then 24 else 16)

/-! ## The `key` file -/

/-- `init`: 32 bytes from the operating system's random generator, written to `key` and synced before the first
    frame.  An existing `key` is never overwritten.  (The directory entry rides on the file's own commit; no separate
    directory sync is available through `Flat.Io`.) -/
def initKey (dir : String) : IO ByteArray := do
  let path := s!"{dir}/key"
  if ← System.FilePath.pathExists path then throw (IO.userError "KEY exists")
  let s ← IO.getRandomBytes 32
  let fd ← Io.pgOpen path
  if fd == 0xFFFFFFFF then throw (IO.userError "KEY open")
  let w ← Io.pgWrite fd 0 s
  let y ← Io.pgSync fd
  let _ ← Io.pgClose fd
  if w != 0 || y != 0 then throw (IO.userError "KEY write")
  return s

/-- Load: `key` must exist and hold exactly 32 bytes (`KEY` otherwise). -/
def readKey (dir : String) : IO (Except String ByteArray) := do
  let path := s!"{dir}/key"
  if !(← System.FilePath.pathExists path) then return .error "KEY"
  let b ← IO.FS.readBinFile path
  return if b.size == 32 then .ok b else .error "KEY"

/-! ## Equality with the model (stated, not yet proved) -/

theorem bytesOf_toList (b : ByteArray) : Bin.bytesOf b.toList = b := by
  unfold Bin.bytesOf
  rw [Bin.toList_eq']

theorem getD_toList (d : ByteArray) (j : Nat) : d.toList.getD j 0 = d[j]! := by
  by_cases h : j < d.size
  · have hj : j < d.toList.length := by rw [← Bin.size_eq_length']; exact h
    rw [Bin.getBang' d j h]
    simp [List.getD_eq_getElem?_getD, hj]
  · have h2 : d.toList.length ≤ j := by rw [← Bin.size_eq_length']; omega
    simp [List.getD_eq_getElem?_getD, List.getElem?_eq_none h2, h]
    try rfl

theorem keyMsg_eq (sec kb : ByteArray) :
    Bin.bytesOf (domain "KEY2" ++ sec.toList ++ kb.toList) = keyDom ++ sec ++ kb := by
  apply ByteArray.ext
  apply Array.ext'
  have := Bin.toList_append' (keyDom ++ sec) kb
  have h2 := Bin.toList_append' keyDom sec
  have h3 : keyDom.toList = domain "KEY2" := Bin.toList_bytesOf _
  rw [Bin.toList_eq'] at this h2
  rw [Bin.toList_eq'] at h3
  simp only [Bin.bytesOf, Bin.toList_eq'] at *
  rw [List.toList_toArray]
  simp only [ByteArray.toList_data_append] at *
  rw [h3]

end BlindLedger.Gate.Engine3
