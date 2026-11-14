import BlindLedger.Sha3Quick
import BlindLedger.Gate.Engine3.Sha3Fused
import BlindLedger.Gate.OnepIndex

/-! Byte-array helpers of the chunk store: the hash on `ByteArray` (SHA3-512, the `H` of the list model), the variable-length
    number decoder at an offset, and the facts that tie a `ByteArray` to its byte list. -/

namespace BlindLedger.Gate.Flat.Bin

open BlindLedger.Gate.OnepIndex (leb unleb)

def bytesOf (l : List UInt8) : ByteArray := ⟨l.toArray⟩

/-- The hash `H` of the list model. -/
def HB (b : ByteArray) : ByteArray := BlindLedger.Gate.Engine3.sha3_512Into ByteArray.empty ByteArray.empty b 0 b.size

/-- `unleb` at an offset: the number and the offset after it. -/
def unlebAt (d : ByteArray) (i : Nat) : Option (Nat × Nat) :=
  if h : i < d.size then
    let b := d[i]
    if b < 128 then some (b.toNat, i + 1) else
    match unlebAt d (i + 1) with
    | some (n, j) => if n = 0 then none else some ((b - 128).toNat + 128 * n, j)
    | none => none
  else none
termination_by d.size - i

theorem toList_eq' (b : ByteArray) : b.toList = b.data.toList := by
  suffices h : ∀ i r, ByteArray.toList.loop b i r = r.reverse ++ b.data.toList.drop i by
    unfold ByteArray.toList
    simpa using h 0 []
  intro i r
  induction hn : b.size - i generalizing i r with
  | zero =>
    unfold ByteArray.toList.loop
    rw [if_neg (by omega)]
    have hs : b.data.toList.length = b.size := Array.length_toList
    simp [List.drop_eq_nil_of_le (show b.data.toList.length ≤ i by omega)]
  | succ n ih =>
    unfold ByteArray.toList.loop
    rw [if_pos (by omega), ih (i + 1) _ (by omega)]
    have hs : b.data.toList.length = b.size := Array.length_toList
    have hi : i < b.data.toList.length := by omega
    have hi' : i < b.data.size := by omega
    have : b.get! i = b.data.toList[i] := by
      simp only [ByteArray.get!, Array.getElem_toList]
      exact getElem!_pos b.data i hi'
    rw [List.drop_eq_getElem_cons hi, this]
    simp

theorem toList_append' (a b : ByteArray) : (a ++ b).toList = a.toList ++ b.toList := by
  simp only [toList_eq', ByteArray.toList_data_append]

theorem toList_bytesOf (l : List UInt8) : (bytesOf l).toList = l := by
  simp [toList_eq', bytesOf]

theorem toList_toByteArray (l : List UInt8) : l.toByteArray.toList = l := by
  rw [toList_eq', List.toList_data_toByteArray]

theorem size_eq_length' (b : ByteArray) : b.size = b.toList.length := by
  rw [toList_eq', Array.length_toList]; rfl

theorem toList_extract' (b : ByteArray) (i j : Nat) : (b.extract i j).toList = (b.toList.drop i).take (j - i) := by
  simp [toList_eq', ByteArray.data_extract]

theorem getBang' (b : ByteArray) (j : Nat) (h : j < b.size) : b[j]! = b.toList[j]'(by rw [← size_eq_length']; exact h) := by
  have : b[j]! = b[j] := getElem!_pos b j h
  rw [this]; simp only [toList_eq', Array.getElem_toList]; rfl

/-! ## `unlebAt` -/

theorem unlebAt_eq (d : ByteArray) (i : Nat) :
    unleb (d.toList.drop i) = (unlebAt d i).map (fun (n, j) => (n, d.toList.drop j)) ∧
    ∀ n j, unlebAt d i = some (n, j) → j ≤ d.size := by
  have hl := size_eq_length' d
  by_cases hi : i < d.size
  · have hi2 : i < d.toList.length := by omega
    have hd : d.toList.drop i = d.toList[i] :: d.toList.drop (i + 1) := List.drop_eq_getElem_cons hi2
    have hb : d[i] = d.toList[i] := by
      have := getBang' d i hi
      rwa [getElem!_pos d i hi] at this
    rw [unlebAt, dif_pos hi]
    simp only [hd, hb]
    by_cases h128 : d.toList[i] < 128
    · simp [unleb, h128]; omega
    · obtain ⟨ih1, ih2⟩ := unlebAt_eq d (i + 1)
      simp only [unleb, h128, if_false]
      rcases hu : unlebAt d (i + 1) with _ | ⟨n, j⟩
      · simp [hu] at ih1; simp [ih1]
      · simp [hu] at ih1
        simp [ih1]
        constructor
        · by_cases hn : n = 0 <;> simp [hn]
        · intro _; exact ih2 n j hu
  · have hnil : d.toList.drop i = [] := List.drop_eq_nil_of_le (by omega)
    rw [unlebAt, dif_neg hi, hnil]
    simp [unleb]
termination_by d.size - i

end BlindLedger.Gate.Flat.Bin
