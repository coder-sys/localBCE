import BlindLedger.Gate.Engine.OneProc

/-! The frame bytes of `gate_engine`: the length header round-trips (`be32`, `frameLen`) and the splitter reads back exactly
    the frames written (`splitFrames_join`) and nothing else (`splitFrames_sound`).  Nothing on an exe path imports this
    module (`gate_axioms` only). -/

namespace BlindLedger.Gate.Engine.OneProc

/-! Helpers for S0b/S0c: the frame header round-trips and the splitter's recursion. -/

theorem be32_size (n : Nat) : (be32 n).size = 4 := rfl

theorem fold4 (a b c d : UInt8) :
    (ByteArray.mk #[a, b, c, d]).foldl (fun x y => x * 256 + y.toNat) 0 = ((a.toNat * 256 + b.toNat) * 256 + c.toNat) * 256 + d.toNat := by
  show (((0 * 256 + a.toNat) * 256 + b.toNat) * 256 + c.toNat) * 256 + d.toNat = _
  simp

theorem toNat_toUInt8 (n : Nat) : n.toUInt8.toNat = n % 256 := by
  simp [Nat.toUInt8]

theorem frameLen_be32 (n : Nat) (h : n ≤ Rules.Run.maxFrame) : frameLen (be32 n) = some n := by
  have hm : Rules.Run.maxFrame = 67108864 := rfl
  have h1 : (be32 n).size = 4 := rfl
  have hf : (be32 n).foldl (fun a b => a * 256 + b.toNat) 0 = n := by
    unfold be32
    rw [fold4]
    simp only [toNat_toUInt8]
    omega
  unfold frameLen
  rw [hf]
  rw [hm] at h
  simp [h1]
  omega

theorem u8_of (x : Nat) (a : UInt8) (h : x % 256 = a.toNat) : x.toUInt8 = a :=
  UInt8.toNat_inj.1 (by rw [toNat_toUInt8]; exact h)

theorem be32_of_frameLen (h : ByteArray) (n : Nat) (hf : frameLen h = some n) (hs : h.size = 4) : be32 n = h := by
  obtain ⟨⟨l⟩⟩ := h
  have hl : l.length = 4 := hs
  match l, hl with
  | [a, b, c, d], _ =>
    have e : ByteArray.foldl (fun x y => x * 256 + y.toNat) 0 (⟨⟨[a, b, c, d]⟩⟩ : ByteArray) =
        ((a.toNat * 256 + b.toNat) * 256 + c.toNat) * 256 + d.toNat := fold4 a b c d
    have hn : n = ((a.toNat * 256 + b.toNat) * 256 + c.toNat) * 256 + d.toNat := by
      simp only [frameLen] at hf
      rw [e] at hf
      split at hf
      · simp at hf
      · exact (Option.some.inj hf).symm
    have la := UInt8.toNat_lt a
    have lb := UInt8.toNat_lt b
    have lc := UInt8.toNat_lt c
    have ld := UInt8.toNat_lt d
    have h1 : (n >>> 24).toUInt8 = a := u8_of _ _ (by omega)
    have h2 : (n >>> 16).toUInt8 = b := u8_of _ _ (by omega)
    have h3 : (n >>> 8).toUInt8 = c := u8_of _ _ (by omega)
    have h4 : n.toUInt8 = d := u8_of _ _ (by omega)
    simp only [be32, h1, h2, h3, h4]

theorem foldl_step (x : ByteArray) (fs : List ByteArray) :
    fs.foldl (fun o f => o ++ be32 f.size ++ f) x = x ++ fs.foldl (fun o f => o ++ be32 f.size ++ f) ByteArray.empty := by
  induction fs generalizing x with
  | nil => simp
  | cons f fs ih =>
    simp only [List.foldl_cons]
    rw [ih, ih (ByteArray.empty ++ be32 f.size ++ f)]
    simp [ByteArray.append_assoc]

theorem join_cons (f : ByteArray) (fs : List ByteArray) :
    (f :: fs).foldl (fun o f => o ++ be32 f.size ++ f) ByteArray.empty =
      be32 f.size ++ (f ++ fs.foldl (fun o f => o ++ be32 f.size ++ f) ByteArray.empty) := by
  simp only [List.foldl_cons]
  rw [foldl_step]
  simp [ByteArray.append_assoc]

theorem split_aux (a : ByteArray) (fs : List ByteArray) (h : ∀ f ∈ fs, f.size ≤ Rules.Run.maxFrame) :
    splitFramesFrom (a ++ fs.foldl (fun o f => o ++ be32 f.size ++ f) ByteArray.empty) a.size = some fs := by
  induction fs generalizing a with
  | nil => unfold splitFramesFrom; simp
  | cons f fs ih =>
    have hf := h f (by simp)
    have key : a ++ (f :: fs).foldl (fun o f => o ++ be32 f.size ++ f) ByteArray.empty
        = (a ++ be32 f.size ++ f) ++ fs.foldl (fun o f => o ++ be32 f.size ++ f) ByteArray.empty := by
      rw [join_cons]; simp [ByteArray.append_assoc]
    rw [key]
    generalize fs.foldl (fun o f => o ++ be32 f.size ++ f) ByteArray.empty = J at ih ⊢
    have hs : (a ++ be32 f.size ++ f).size = a.size + 4 + f.size := by simp [be32_size]
    have e1 : ((a ++ be32 f.size ++ f) ++ J).extract a.size (a.size + 4) = be32 f.size := by
      simp only [ByteArray.append_assoc]
      have := ByteArray.extract_append_size_add (a := a) (b := be32 f.size ++ (f ++ J)) (i := 0) (j := 4)
      simp only [Nat.add_zero] at this
      rw [this]
      exact ByteArray.extract_append_eq_left (by simp [be32_size])
    have e2 : ((a ++ be32 f.size ++ f) ++ J).extract (a.size + 4) (a.size + 4 + f.size) = f := by
      simp only [ByteArray.append_assoc]
      rw [Nat.add_assoc, ByteArray.extract_append_size_add]
      have h4 := ByteArray.extract_append_size_add' (a := be32 f.size) (b := f ++ J) (k := 4) (i := 0) (j := f.size) (by simp [be32_size])
      simp only [Nat.add_zero] at h4
      rw [h4]
      exact ByteArray.extract_append_eq_left (by simp)
    have := ih (a ++ be32 f.size ++ f) (fun g hg => h g (by simp [hg]))
    rw [hs] at this
    have hlt : a.size < ((a ++ be32 f.size ++ f) ++ J).size := by simp [be32_size]; omega
    unfold splitFramesFrom
    rw [dif_pos hlt, e1, frameLen_be32 _ hf]
    simp only []
    rw [if_neg (by simp [be32_size]), e2]
    simp [this]

theorem frameLen_some (h : ByteArray) (n : Nat) (hf : frameLen h = some n) : 4 ≤ h.size ∧ n ≤ Rules.Run.maxFrame := by
  unfold frameLen at hf
  dsimp only at hf
  split at hf
  · simp at hf
  · rename_i hc
    simp only [Bool.or_eq_true, decide_eq_true_eq] at hc
    have heq := Option.some.inj hf
    have hc' : ¬ (h.size < 4 ∨ ByteArray.foldl (fun a b => a * 256 + b.toNat) 0 h > Rules.Run.maxFrame) := hc
    rw [← heq]
    omega

theorem split_sound_aux (b : ByteArray) : ∀ k o fs, b.size - o = k → splitFramesFrom b o = some fs →
    fs.foldl (fun o f => o ++ be32 f.size ++ f) ByteArray.empty = b.extract o b.size ∧
      ∀ f ∈ fs, f.size ≤ Rules.Run.maxFrame := by
  intro k
  induction k using Nat.strongRecOn with
  | _ k ih =>
    intro o fs hk h
    unfold splitFramesFrom at h
    split at h
    · rename_i hlt
      cases hfl : frameLen (b.extract o (o + 4)) with
      | none => simp [hfl] at h
      | some n =>
        simp only [hfl] at h
        split at h
        · simp at h
        · rename_i hns
          cases hr : splitFramesFrom b (o + 4 + n) with
          | none => simp [hr] at h
          | some fs' =>
            simp only [hr] at h
            have h' := Option.some.inj h
            subst h'
            
            obtain ⟨h4, hmax⟩ := frameLen_some _ _ hfl
            rw [ByteArray.size_extract] at h4
            have hsz : (b.extract o (o + 4)).size = 4 := by rw [ByteArray.size_extract]; omega
            have hbe := be32_of_frameLen _ _ hfl hsz
            have hfs : (b.extract (o + 4) (o + 4 + n)).size = n := by rw [ByteArray.size_extract]; omega
            obtain ⟨ih1, ih2⟩ := ih (b.size - (o + 4 + n)) (by omega) (o + 4 + n) fs' rfl hr
            refine ⟨?_, ?_⟩
            · rw [join_cons, hfs, hbe, ih1,
                ByteArray.extract_eq_extract_append_extract (a := b) (i := o) (k := b.size) (o + 4) (by omega) (by omega),
                ByteArray.extract_eq_extract_append_extract (a := b) (i := o + 4) (k := b.size) (o + 4 + n) (by omega) (by omega)]
            · intro f hf
              rcases List.mem_cons.1 hf with rfl | hf
              · rw [hfs]; exact hmax
              · exact ih2 f hf
    · simp only [Option.some.injEq] at h
      subst h
      refine ⟨?_, by simp⟩
      simp only [List.foldl_nil]
      exact (ByteArray.extract_eq_empty_iff.2 (by omega)).symm

/-- S0b: `serve`'s framing reads back exactly the frames written, each a `be32` length then its bytes.
    Design deviation: no `0 < f.size` premise; the splitter takes an empty frame (`answer` then refuses it), so the
    premise would be unused.  `serve` is a fuel-recursive IO loop and nothing here unfolds it (IO is opaque to the prover); it shares `frameLen`/`be32` with
    `splitFrames` instead of a stated equality. -/
theorem splitFrames_join (fs : List ByteArray) (h : ∀ f ∈ fs, f.size ≤ Rules.Run.maxFrame) :
    splitFrames (fs.foldl (fun o f => o ++ be32 f.size ++ f) ByteArray.empty) = some fs := by
  have := split_aux ByteArray.empty fs h
  simpa [splitFrames, ByteArray.empty_append] using this

/-- S0c, the converse of S0b: whatever `splitFrames` accepts is a join of frames, each within `maxFrame`, so the
    frames `serve` answers are exactly the input's bytes. -/
theorem splitFrames_sound (b : ByteArray) (fs : List ByteArray) (h : splitFrames b = some fs) :
    fs.foldl (fun o f => o ++ be32 f.size ++ f) ByteArray.empty = b ∧ ∀ f ∈ fs, f.size ≤ Rules.Run.maxFrame := by
  have := split_sound_aux b (b.size - 0) 0 fs rfl h
  refine ⟨?_, this.2⟩
  rw [this.1]
  exact ByteArray.extract_zero_size

end BlindLedger.Gate.Engine.OneProc
