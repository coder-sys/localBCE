import BlindLedger.Financial.Batch
import BlindLedger.Financial.WorkerLaws
import BlindLedger.Financial.CodecLaws.Primitives
import BlindLedger.Financial.Theorems.Vectors

/-! The batch theorems: the request parser accepts exactly the canonical encoding of a well-formed
    batch, a batch answer is the map of the single answers, and the response framing is unambiguous.
    The `#guard`s at the end are the known answers. -/

namespace BlindLedger.Financial.Batch

theorem natBE_len (w n : Nat) : (natBE w n).length = w := by
  induction w generalizing n with
  | zero => rfl
  | succ w ih => simp [natBE, ih]

theorem readNatBE_inv {w : Nat} {l : Bytes} {v : Nat} {r : Bytes} (h : readNatBE w l = some (v, r)) :
    l = natBE w v ++ r ∧ v < 256 ^ w := by
  induction w generalizing l v r with
  | zero =>
    simp only [readNatBE, Option.some.injEq, Prod.mk.injEq] at h
    obtain ⟨rfl, rfl⟩ := h
    exact ⟨rfl, by decide⟩
  | succ w ih =>
    simp only [readNatBE] at h
    rcases hr : readNatBE w l with _ | ⟨a, _ | ⟨b, t⟩⟩
    · simp [hr] at h
    · simp [hr, readByte] at h
    · simp only [hr, readByte, Option.pure_def, Option.bind_eq_bind, Option.bind_some, Option.some.injEq,
        Prod.mk.injEq] at h
      obtain ⟨rfl, rfl⟩ := h
      obtain ⟨hl, ha⟩ := ih hr
      have hb : b.toNat < 256 := UInt8.toNat_lt_size b
      refine ⟨?_, ?_⟩
      · have e1 : (a * 256 + b.toNat) / 256 = a := by omega
        have e2 : (a * 256 + b.toNat) % 256 = b.toNat := by omega
        simp only [natBE, e1, e2, UInt8.ofNat_toNat, List.append_assoc, List.singleton_append]
        exact hl
      · rw [Nat.pow_succ]; omega

theorem readItem_inv {l b r : Bytes} (h : readItem l = some (b, r)) :
    l = encodeItem b ++ r ∧ b.length ≤ maxTotalEncodedBytes := by
  unfold readItem at h
  rcases hn : readNatBE 4 l with _ | ⟨len, rest⟩
  · simp [hn] at h
  · simp only [hn, Option.bind_eq_bind, Option.bind_some] at h
    by_cases hc : (len > maxTotalEncodedBytes || len > rest.length) = true
    · simp [hc] at h
    · rw [if_neg hc] at h
      simp only [Option.some.injEq, Prod.mk.injEq] at h
      obtain ⟨rfl, rfl⟩ := h
      simp only [Bool.or_eq_true, decide_eq_true_eq, not_or, Nat.not_lt] at hc
      have hlen : (rest.take len).length = len := by simp; omega
      refine ⟨?_, by omega⟩
      unfold encodeItem
      rw [hlen, List.append_assoc, List.take_append_drop]
      exact (readNatBE_inv hn).1

theorem readMany_inv {n : Nat} {l : Bytes} {items : List Bytes} {r : Bytes}
    (h : readMany readItem n l = some (items, r)) :
    items.length = n ∧ (∀ b ∈ items, b.length ≤ maxTotalEncodedBytes) ∧
      l = items.flatMap encodeItem ++ r := by
  induction n generalizing l items r with
  | zero =>
    simp only [readMany, Option.some.injEq, Prod.mk.injEq] at h
    obtain ⟨rfl, rfl⟩ := h
    exact ⟨rfl, by simp, rfl⟩
  | succ n ih =>
    simp only [readMany] at h
    rcases hi : readItem l with _ | ⟨b, l1⟩
    · simp [hi] at h
    · rcases hm : readMany readItem n l1 with _ | ⟨ts, r1⟩
      · simp [hi, hm] at h
      · simp only [hi, hm, Option.bind_eq_bind, Option.bind_some, Option.pure_def, Option.some.injEq,
          Prod.mk.injEq] at h
        obtain ⟨rfl, rfl⟩ := h
        obtain ⟨h1, h2⟩ := readItem_inv hi
        obtain ⟨g1, g2, g3⟩ := ih hm
        refine ⟨by simp [g1], ?_, ?_⟩
        · intro x hx
          rcases List.mem_cons.1 hx with rfl | hx
          · exact h2
          · exact g2 x hx
        · rw [List.flatMap_cons, List.append_assoc, ← g3]; exact h1

/-- T-exact: the parser accepts only the canonical encoding of a well-formed batch. -/
theorem parseBatchRequest_exact {wire tag : Bytes} {items : List Bytes}
    (h : parseBatchRequest wire = some (tag, items)) :
    wire = encodeBatchRequest tag items ∧ batchWellFormed tag items := by
  unfold parseBatchRequest at h
  by_cases hg : (wire.length > maxBatchBytes || !batchRequestMagic.isPrefixOf wire) = true
  · simp [hg] at h
  · rw [if_neg hg] at h
    simp only [Bool.or_eq_true, decide_eq_true_eq, not_or, Bool.not_eq_true', Nat.not_lt] at hg
    obtain ⟨hgl, hgp⟩ := hg
    have hgp' : batchRequestMagic.isPrefixOf wire = true := by simpa using hgp
    obtain ⟨t0, ht0⟩ := List.isPrefixOf_iff_prefix.1 hgp'
    rw [← ht0, List.drop_left] at h
    unfold readDigest at h
    by_cases hd : t0.length < digestBytes
    · simp [hd] at h
    · rw [if_neg hd] at h
      simp only [Option.bind_eq_bind, Option.bind_some] at h
      rcases hc : readNatBE 2 (t0.drop digestBytes) with _ | ⟨count, r2⟩
      · simp [hc] at h
      · simp [hc] at h
        obtain ⟨⟨hk1, hk2⟩, h⟩ := h
        rcases hm : readMany readItem count r2 with _ | ⟨its, r3⟩
        · simp [hm] at h
        · by_cases he : r3 = []
          · simp [hm, he] at h
            obtain ⟨h1, h2⟩ := h
            subst he
            rw [← h1, ← h2]
            obtain ⟨m1, m2, m3⟩ := readMany_inv hm
            obtain ⟨n1, -⟩ := readNatBE_inv hc
            have e : t0 = t0.take digestBytes ++ (natBE 2 count ++ its.flatMap encodeItem) := by
              have := List.take_append_drop digestBytes t0
              rw [n1, m3, List.append_nil] at this
              exact this.symm
            have hw : wire = encodeBatchRequest (t0.take digestBytes) its := by
              rw [← ht0]
              conv =>
                lhs
                rw [e]
              simp [encodeBatchRequest, m1, List.append_assoc]
            refine ⟨hw, by simp only [List.length_take, batchTagBytes]; omega, by omega, by omega, m2, ?_⟩
            rw [← hw]; exact hgl
          · simp [hm, he] at h

theorem parseBatchRequest_encode {tag : Bytes} {items : List Bytes} (h : batchWellFormed tag items) :
    parseBatchRequest (encodeBatchRequest tag items) = some (tag, items) := by
  obtain ⟨ht, h1, h2, hb, hl⟩ := h
  have hw : encodeBatchRequest tag items =
      batchRequestMagic ++ (tag ++ (natBE 2 items.length ++ items.flatMap encodeItem)) := by
    simp [encodeBatchRequest, List.append_assoc]
  have hp : batchRequestMagic.isPrefixOf (encodeBatchRequest tag items) = true := by
    rw [List.isPrefixOf_iff_prefix, hw]; exact List.prefix_append _ _
  have hd : readDigest (tag ++ (natBE 2 items.length ++ items.flatMap encodeItem)) =
      some (tag, natBE 2 items.length ++ items.flatMap encodeItem) :=
    readDigest_encodeDigest_append tag _ ht
  have hn : readNatBE 2 (natBE 2 items.length ++ items.flatMap encodeItem) =
      some (items.length, items.flatMap encodeItem) :=
    readNatBE_natBE_append 2 _ _ (by unfold maxBatchItems at h2; omega)
  have hparse : ∀ b ∈ items, ∀ tail, readItem (encodeItem b ++ tail) = some (b, tail) := by
    intro b hb' tail
    have hlen : b.length < 256 ^ 4 :=
      Nat.lt_of_le_of_lt (hb b hb') (by unfold maxTotalEncodedBytes; decide)
    unfold readItem encodeItem
    rw [List.append_assoc, readNatBE_natBE_append 4 b.length _ hlen]
    have hc : ¬ (b.length > maxTotalEncodedBytes || b.length > (b ++ tail).length) = true := by
      have := hb b hb'
      simp only [Bool.or_eq_true, decide_eq_true_eq, not_or, List.length_append]; omega
    simp only [Option.bind_eq_bind, Option.bind_some, if_neg hc, List.take_left', List.drop_left']
  have hm := readMany_flatMap_append_of_mem encodeItem readItem items [] hparse
  rw [List.append_nil] at hm
  have hg : ¬ ((encodeBatchRequest tag items).length > maxBatchBytes ||
      !batchRequestMagic.isPrefixOf (encodeBatchRequest tag items)) = true := by
    simp [hp]; exact hl
  have hk : ¬ (items.length = 0 ∨ maxBatchItems < items.length) := by omega
  unfold parseBatchRequest
  rw [if_neg hg, hw, List.drop_left]
  simp [hd, hn, hm]
  exact ⟨fun e => by simp [e] at h1, h2⟩

/-- T-map: a batch is the map of the single answer, and the tag comes back. -/
theorem respondBatch_map {tag : Bytes} {items : List Bytes} (h : batchWellFormed tag items) :
    respondBatch (encodeBatchRequest tag items) = encodeBatchResponse tag (items.map workerRespond) := by
  unfold respondBatch
  rw [parseBatchRequest_encode h]

/-- T-reject: anything else gets the one-byte whole-batch rejection, never a partial answer. -/
theorem respondBatch_rejects {wire : Bytes}
    (h : ∀ tag items, batchWellFormed tag items → wire ≠ encodeBatchRequest tag items) :
    respondBatch wire = batchRejected := by
  unfold respondBatch
  rcases hp : parseBatchRequest wire with _ | ⟨tag, items⟩
  · rfl
  · obtain ⟨e, wf⟩ := parseBatchRequest_exact hp
    exact absurd e (h tag items wf)

/-- T-iso: item i's answer depends on item i alone; changing, failing or reordering others cannot move it. -/
theorem batch_isolation {tag tag' : Bytes} {items items' : List Bytes} {i : Nat}
    (h : batchWellFormed tag items) (h' : batchWellFormed tag' items') (hi : items[i]? = items'[i]?) :
    ∃ outs outs', respondBatch (encodeBatchRequest tag items) = encodeBatchResponse tag outs ∧
      respondBatch (encodeBatchRequest tag' items') = encodeBatchResponse tag' outs' ∧
      outs[i]? = (items[i]?).map workerRespond ∧ outs[i]? = outs'[i]? :=
  ⟨items.map workerRespond, items'.map workerRespond, respondBatch_map h, respondBatch_map h',
    by simp [List.getElem?_map], by simp [List.getElem?_map, hi]⟩

theorem flatMap_encodeItem_inj : ∀ {os os' : List Bytes}, os.length = os'.length →
    (∀ o ∈ os, o.length < 256 ^ 4) → (∀ o ∈ os', o.length < 256 ^ 4) →
    os.flatMap encodeItem = os'.flatMap encodeItem → os = os'
  | [], [], _, _, _, _ => rfl
  | [], _ :: _, hl, _, _, _ => by simp at hl
  | _ :: _, [], hl, _, _, _ => by simp at hl
  | o :: os, o' :: os', hl, hb, hb', h => by
    simp only [List.flatMap_cons, encodeItem, List.append_assoc] at h
    obtain ⟨e1, e2⟩ := List.append_inj h (by rw [natBE_len, natBE_len])
    have hlen : o.length = o'.length :=
      natBE_injective_of_fits 4 _ _ (hb o (by simp)) (hb' o' (by simp)) e1
    obtain ⟨e3, e4⟩ := List.append_inj e2 hlen
    have := flatMap_encodeItem_inj (by simpa using hl) (fun x hx => hb x (by simp [hx]))
      (fun x hx => hb' x (by simp [hx])) e4
    rw [e3, this]

/-- The response framing is unambiguous, so Python's exact parse recovers exactly the map. -/
theorem encodeBatchResponse_inj {t t' : Bytes} {os os' : List Bytes}
    (ht : t.length = batchTagBytes) (ht' : t'.length = batchTagBytes)
    (hn : os.length ≤ maxBatchItems) (hn' : os'.length ≤ maxBatchItems)
    (hb : ∀ o ∈ os, o.length < 256 ^ 4) (hb' : ∀ o ∈ os', o.length < 256 ^ 4)
    (h : encodeBatchResponse t os = encodeBatchResponse t' os') : t = t' ∧ os = os' := by
  unfold encodeBatchResponse at h
  simp only [List.append_assoc] at h
  obtain ⟨-, h⟩ := List.append_inj h rfl
  obtain ⟨e1, h⟩ := List.append_inj h (ht.trans ht'.symm)
  obtain ⟨e2, e3⟩ := List.append_inj h (by rw [natBE_len, natBE_len])
  have hlen : os.length = os'.length :=
    natBE_injective_of_fits 2 _ _ (by unfold maxBatchItems at hn; omega)
      (by unfold maxBatchItems at hn'; omega) e2
  exact ⟨e1, flatMap_encodeItem_inj hlen hb hb' e3⟩

theorem workerRespond_lt_u32 (wire : Bytes) : (workerRespond wire).length < 256 ^ 4 :=
  Nat.lt_of_le_of_lt (workerRespond_length_le wire) maxWorkerFrameBytes_fits_u32

#guard respondBatch (encodeBatchRequest (List.replicate 64 7) [katWire, [], katWire.dropLast]) =
  encodeBatchResponse (List.replicate 64 7) [workerRespond katWire, [UInt8.ofNat 1], [UInt8.ofNat 1]]
#guard respondBatch (encodeBatchRequest (List.replicate 64 7) []) = batchRejected
#guard respondBatch (encodeBatchRequest (List.replicate 63 7) [katWire]) = batchRejected
#guard respondBatch (encodeBatchRequest (List.replicate 64 7) [katWire] ++ [0]) = batchRejected
#guard respondBatchBA (encodeBatchRequest (List.replicate 64 7) [katWire, katWire]).toByteArray =
  respondBatch (encodeBatchRequest (List.replicate 64 7) [katWire, katWire])

end BlindLedger.Financial.Batch
