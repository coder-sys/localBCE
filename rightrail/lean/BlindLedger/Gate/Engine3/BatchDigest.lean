import BlindLedger.Gate.Flat.Worker

/-! The CHAIN batch digest (`Flat.Chunk.batchDigest`) with its input built as one byte array: the domain, the authority
    record after the batch with its length, then each appended row's ten numbers as minimal LEB128 bytes pushed in place, hashed once.  `batchDigestFast_eq` is its
    proof of equality with the list-based definition, whose input is a list of one byte per cell of memory. -/

namespace BlindLedger.Gate.Engine3

open BlindLedger.Gate BlindLedger.Gate.Rules BlindLedger.Gate.Flat
open BlindLedger.Gate.OnepIndex (leb)

/-- `b` and the LEB128 bytes of `n`. -/
def lebPush (b : ByteArray) (n : Nat) : ByteArray :=
  if n < 128 then b.push n.toUInt8 else lebPush (b.push (n % 128 + 128).toUInt8) (n / 128)
termination_by n
decreasing_by omega

theorem lebPush_toList (n : Nat) : ∀ b : ByteArray, (lebPush b n).data.toList = b.data.toList ++ leb n := by
  induction n using Nat.strongRecOn with
  | _ n ih =>
    intro b
    rw [lebPush, leb]
    by_cases h : n < 128
    · simp [h, ByteArray.push]
    · simp only [h, if_false, dif_neg, not_false_eq_true]
      rw [ih (n / 128) (by omega)]
      simp [ByteArray.push]

theorem foldl_lebPush (xs : List Nat) : ∀ b : ByteArray,
    (xs.foldl lebPush b).data.toList = b.data.toList ++ xs.flatMap leb := by
  induction xs with
  | nil => intro b; simp
  | cons x xs ih => intro b; rw [List.foldl_cons, ih, lebPush_toList]; simp [List.append_assoc]

def pushLine (b : ByteArray) (l : Line) : ByteArray := (enc l).foldl lebPush b

theorem foldl_pushLine (ls : List Line) : ∀ b : ByteArray,
    (ls.foldl pushLine b).data.toList = b.data.toList ++ ls.flatMap encLine := by
  induction ls with
  | nil => intro b; simp
  | cons l ls ih =>
    intro b
    rw [List.foldl_cons, ih, pushLine, foldl_lebPush]
    simp [encLine, List.append_assoc]

/-- The input of `batchDigest` for the authority record `au`, as bytes. -/
def batchBytes (au : ByteArray) (d : List Line × List Line) : ByteArray :=
  let b : ByteArray := ⟨(domain "CHAIN" ++ [0x03]).toArray⟩
  let b := lebPush b au.size ++ au
  let b := d.1.foldl pushLine (lebPush b d.1.length)
  d.2.foldl pushLine (lebPush b d.2.length)

theorem batchBytes_toList (au : ByteArray) (d : List Line × List Line) :
    (batchBytes au d).data.toList = domain "CHAIN" ++ [0x03] ++ leb au.toList.length ++ au.toList ++ encDelta d := by
  have hs : au.size = au.data.toList.length := by rw [Flat.Bin.size_eq_length', Flat.Bin.toList_eq']
  rw [Flat.Bin.toList_eq' au]
  simp only [batchBytes, foldl_pushLine, lebPush_toList, encDelta, ByteArray.data_append, Array.toList_append, hs]
  simp only [List.toList_toArray, List.append_assoc, List.cons_append, List.nil_append]

def batchDigestFast (au : ByteArray) (d : List Line × List Line) : ByteArray := Bin.HB (batchBytes au d)

/-- The fast digest is the list-based one, for the hash `Flat.Worker.H`. -/
theorem batchDigestFast_eq (au : ByteArray) (d : List Line × List Line) :
    (batchDigestFast au d).toList = Chunk.batchDigest Flat.Worker.H au.toList d := by
  have h : batchBytes au d = ⟨(domain "CHAIN" ++ [0x03] ++ leb au.toList.length ++ au.toList ++ encDelta d).toArray⟩ := by
    apply ByteArray.ext
    apply Array.ext'
    simpa using batchBytes_toList au d
  simp [batchDigestFast, Chunk.batchDigest, Flat.Worker.H, h]

/-- info: 'BlindLedger.Gate.Engine3.batchDigestFast_eq' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms batchDigestFast_eq

end BlindLedger.Gate.Engine3
