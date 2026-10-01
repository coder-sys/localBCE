import BlindLedger.Financial.Cursor
import BlindLedger.Financial.Worker

/-! Batch frames.  A request is `BLFBQ01`, a 64-byte tag, a `u16` count and that many `u32`-prefixed
    `BLFIN02` items.  The response is `BLFBR01`, the same tag, the same count and one `workerRespond`
    outcome per item.  The tag is copied back and never inspected, so the owner can bind every answer
    to the request that asked for it.  Any request that is not exactly a well-formed batch is answered
    with the one byte 4.  `parseBatchRequest` on lists is the specification; `parseBatchRequestBA` reads
    the array in place and `respondBatchBA_eq` shows the two answer alike. -/

namespace BlindLedger.Financial.Batch

def batchRequestMagic : Bytes := "BLFBQ01".toUTF8.toList
def batchResponseMagic : Bytes := "BLFBR01".toUTF8.toList
def batchTagBytes : Nat := digestBytes
def maxBatchItems : Nat := 256
def maxBatchBytes : Nat := 2 * maxTotalEncodedBytes
def batchRejected : Bytes := [UInt8.ofNat 4]

def encodeItem (b : Bytes) : Bytes := natBE 4 b.length ++ b

def encodeBatchRequest (tag : Bytes) (items : List Bytes) : Bytes :=
  batchRequestMagic ++ tag ++ natBE 2 items.length ++ items.flatMap encodeItem

def encodeBatchResponse (tag : Bytes) (outcomes : List Bytes) : Bytes :=
  batchResponseMagic ++ tag ++ natBE 2 outcomes.length ++ outcomes.flatMap encodeItem

def batchWellFormed (tag : Bytes) (items : List Bytes) : Prop :=
  tag.length = batchTagBytes ∧ 1 ≤ items.length ∧ items.length ≤ maxBatchItems ∧
  (∀ b ∈ items, b.length ≤ maxTotalEncodedBytes) ∧
  (encodeBatchRequest tag items).length ≤ maxBatchBytes

def readItem (bytes : Bytes) : Option (Bytes × Bytes) := do
  let (length, rest) ← readNatBE 4 bytes
  if length > maxTotalEncodedBytes || length > rest.length then none
  else some (rest.take length, rest.drop length)

/-- The specification: the list decoder. -/
def parseBatchRequest (wire : Bytes) : Option (Bytes × List Bytes) :=
  if wire.length > maxBatchBytes || !batchRequestMagic.isPrefixOf wire then none else do
    let (tag, rest) ← readDigest (wire.drop batchRequestMagic.length)
    let (count, rest) ← readNatBE 2 rest
    if count < 1 || count > maxBatchItems then none
    let (items, rest) ← readMany readItem count rest
    if !rest.isEmpty then none
    pure (tag, items)

def respondBatch (wire : Bytes) : Bytes :=
  match parseBatchRequest wire with
  | none => batchRejected
  | some (tag, items) => encodeBatchResponse tag (items.map workerRespond)

/-- The runtime decoder: one pass over the array, each item a slice of it. -/
def parseBatchRequestBA (wire : ByteArray) : Option (Bytes × List ByteArray) :=
  if wire.size > maxBatchBytes then none else do
    let i ← Cursor.readMagic batchRequestMagic wire 0
    let (tag, i) ← Cursor.readDigest wire i
    let (count, i) ← Cursor.readNatBE 2 wire i
    if count < 1 || count > maxBatchItems then none
    let (items, i) ← Cursor.readMany (Cursor.readSized maxTotalEncodedBytes) count wire i
    if i ≠ wire.size then none
    pure (tag, items)

def respondBatchBA (wire : ByteArray) : Bytes :=
  match parseBatchRequestBA wire with
  | none => batchRejected
  | some (tag, items) => encodeBatchResponse tag (items.map workerRespondBA)

theorem sim_readItem :
    Cursor.SimM ByteArray.toList (Cursor.readSized maxTotalEncodedBytes) readItem :=
  Cursor.sim_readSized _ _ fun _ => rfl

theorem parse_eq {γ : Type} (wire : ByteArray) {f : Bytes × List ByteArray → Option γ}
    {F : Bytes × List Bytes → Option γ} (hF : ∀ t s, f (t, s) = F (t, s.map ByteArray.toList)) :
    (parseBatchRequestBA wire).bind f = (parseBatchRequest wire.toList).bind F := by
  unfold parseBatchRequestBA parseBatchRequest
  rw [Fast.length_toList]
  by_cases hs : wire.size > maxBatchBytes
  · simp [hs]
  · cases hm : batchRequestMagic.isPrefixOf wire.toList
    · rw [Cursor.readMagic_of_not_prefix hm]; simp [hs]
    · obtain ⟨h1, h2⟩ := Cursor.readMagic_of_prefix (i := 0) (Nat.zero_le _) hm
      rw [Nat.zero_add] at h2
      simp only [hs, h1, Nat.zero_add, Bool.not_true, Bool.or_false, ↓reduceIte,
        Option.bind_eq_bind, Option.bind_assoc, Option.bind_some, Option.bind_none, Cursor.ite_none_bind,
        Option.pure_def]
      repeat (first
        | refine Cursor.Sim.bind0 Cursor.SimOf.sim (by assumption) fun _ _ _ => ?_
        | refine Cursor.SimM.bind0 (Cursor.simM_readMany sim_readItem _) (by assumption) fun _ _ _ => ?_
        | refine Cursor.ite_none Iff.rfl fun _ => ?_
        | refine Cursor.ite_none (Cursor.end_iff (by assumption)) fun _ => ?_)
      exact hF _ _

theorem parseBatchRequestBA_eq (wire : ByteArray) :
    (parseBatchRequestBA wire).map (fun p => (p.1, p.2.map ByteArray.toList)) =
      parseBatchRequest wire.toList := by
  rw [Option.map_eq_bind]
  exact (parse_eq wire (f := fun p => some (p.1, p.2.map ByteArray.toList)) (F := some) fun _ _ => rfl).trans
    (by cases parseBatchRequest wire.toList <;> rfl)

theorem respondBatchBA_eq (wire : ByteArray) : respondBatchBA wire = respondBatch wire.toList := by
  unfold respondBatchBA respondBatch
  rw [← parseBatchRequestBA_eq]
  rcases parseBatchRequestBA wire with _ | ⟨tag, items⟩
  · rfl
  · simp only [Option.map_some, List.map_map]
    exact congrArg (encodeBatchResponse tag) (List.map_congr_left fun x _ => workerRespondBA_eq x)

end BlindLedger.Financial.Batch
