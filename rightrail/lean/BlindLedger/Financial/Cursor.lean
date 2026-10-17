import BlindLedger.Financial.FastEncode

/-! Cursor twin of the `BLFIN02` decoder.  A reader takes the frame as a `ByteArray` and a start
    position and returns the value and the next position, so no list of bytes is built and no field
    measures the rest of the input.  Each twin is the reference text with `bytes`/`rest` replaced by
    the position, and `Sim` (one simulation, then a mechanical proof per twin) shows it returns the
    same value and the same unread suffix as the list reader in `Codec.lean`, which stays the
    specification. -/

namespace BlindLedger.Financial.Cursor

/-- A reader over a fixed array: start position in, value and next position out. -/
abbrev Reader (α : Type) := ByteArray → Nat → Option (α × Nat)

def readByte : Reader UInt8 := fun ba i => if h : i < ba.size then some (ba[i], i + 1) else none

def readNatBE : Nat → Reader Nat
  | 0 => fun _ i => some (0, i)
  | width + 1 => fun ba i => do
      let (accumulated, i) ← readNatBE width ba i
      let (byte, i) ← readByte ba i
      pure (accumulated * 256 + byte.toNat, i)

def readString : Reader String := fun ba i => do
  let (length, i) ← readNatBE 2 ba i
  if i + length > ba.size then none else
    let value ← String.fromUTF8? (ba.extract i (i + length))
    pure (value, i + length)

def readDigest : Reader Bytes := fun ba i =>
  if i + digestBytes > ba.size then none
  else some ((ba.extract i (i + digestBytes)).toList, i + digestBytes)

def readBool : Reader Bool := fun ba i => do
  let (byte, i) ← readByte ba i
  if byte.toNat = 0 then some (false, i)
  else if byte.toNat = 1 then some (true, i)
  else none

def readOptionNat : Reader (Option Nat) := fun ba i => do
  let (tag, i) ← readByte ba i
  if tag.toNat = 0 then some (none, i)
  else if tag.toNat = 1 then do
    let (value, i) ← readNatBE 8 ba i
    pure (some value, i)
  else none

def readOptionString : Reader (Option String) := fun ba i => do
  let (tag, i) ← readByte ba i
  if tag.toNat = 0 then some (none, i)
  else if tag.toNat = 1 then do
    let (value, i) ← readString ba i
    pure (some value, i)
  else none

def readMany {α : Type} (parse : Reader α) : Nat → Reader (List α)
  | 0 => fun _ i => some ([], i)
  | count + 1 => fun ba i => do
      let (value, i) ← parse ba i
      let (tail, i) ← readMany parse count ba i
      pure (value :: tail, i)

def readList {α : Type} (parse : Reader α) : Reader (List α) := fun ba i => do
  let (count, i) ← readNatBE 2 ba i
  if count > maxRows then none else readMany parse count ba i

/-- The next bytes at `i` are `magic`: the position after it. -/
def readMagic (magic : Bytes) (ba : ByteArray) (i : Nat) : Option Nat :=
  if i + magic.length ≤ ba.size && ba.extract i (i + magic.length) == magic.toByteArray
  then some (i + magic.length) else none

/-! ## Simulation -/

/-- `f` simulates the list reader `g`: from any in-bounds position, the same value and the same
    unread suffix, and the position stays inside the array and never moves back. -/
def Sim {α : Type} (f : Reader α) (g : Bytes → Option (α × Bytes)) : Prop :=
  ∀ (ba : ByteArray) (i : Nat), i ≤ ba.size →
    (f ba i).map (fun p => (p.1, ba.toList.drop p.2)) = g (ba.toList.drop i) ∧
    ∀ a j, f ba i = some (a, j) → i ≤ j ∧ j ≤ ba.size

theorem drop_length (ba : ByteArray) (i : Nat) : (ba.toList.drop i).length = ba.size - i := by
  rw [List.length_drop, Fast.length_toList]

theorem drop_nil {ba : ByteArray} {i : Nat} (h : ba.size ≤ i) : ba.toList.drop i = [] :=
  List.drop_eq_nil_of_le (by rw [Fast.length_toList]; exact h)

theorem drop_cons {ba : ByteArray} {i : Nat} (h : i < ba.size) :
    ba.toList.drop i = ba[i] :: ba.toList.drop (i + 1) := by
  rw [List.drop_eq_getElem_cons (by rw [Fast.length_toList]; exact h)]
  simp [Fast.toList_eq, ByteArray.getElem_eq_getElem_data]

theorem extract_toList (ba : ByteArray) (i n : Nat) :
    (ba.extract i (i + n)).toList = (ba.toList.drop i).take n := by
  rw [Fast.toList_eq, ByteArray.data_extract, Array.toList_extract, ← Fast.toList_eq,
    List.extract_eq_drop_take', List.take_drop]

theorem Sim.pure {α : Type} (v : α) : Sim (fun _ i => some (v, i)) (fun bs => some (v, bs)) := by
  intro ba i hi
  refine ⟨rfl, fun a j h => ?_⟩
  simp only [Option.some.injEq, Prod.mk.injEq] at h
  omega

theorem Sim.fail {α : Type} : Sim (α := α) (fun _ _ => none) (fun _ => none) := by
  intro ba i hi
  simp

theorem Sim.ite {α : Type} (c : Prop) [Decidable c] {f g : Reader α} {F G}
    (hf : Sim f F) (hg : Sim g G) :
    Sim (fun ba i => if c then f ba i else g ba i) (fun bs => if c then F bs else G bs) := by
  intro ba i hi
  by_cases h : c
  · simp only [h, ↓reduceIte]; exact hf ba i hi
  · simp only [h, ↓reduceIte]; exact hg ba i hi

theorem Sim.bind {α β : Type} {f : Reader α} {F : Bytes → Option (α × Bytes)}
    {k : ByteArray → α × Nat → Option (β × Nat)} {K : α × Bytes → Option (β × Bytes)}
    (hf : Sim f F) (hk : ∀ a, Sim (fun ba j => k ba (a, j)) (fun bs => K (a, bs))) :
    Sim (fun ba i => (f ba i).bind (k ba)) (fun bs => (F bs).bind K) := by
  intro ba i hi
  obtain ⟨h1, h2⟩ := hf ba i hi
  dsimp only
  rcases hfi : f ba i with _ | ⟨a, j⟩
  · simp only [hfi, Option.map_none, Option.bind_none] at h1 ⊢
    rw [← h1]; simp
  · obtain ⟨hij, hjs⟩ := h2 a j hfi
    simp only [hfi, Option.map_some, Option.bind_some] at h1 ⊢
    rw [← h1, Option.bind_some]
    obtain ⟨h3, h4⟩ := hk a ba j hjs
    exact ⟨h3, fun b l hl => by have := h4 b l hl; omega⟩

theorem Sim.bindOpt {γ β : Type} (o : Option γ) {f : γ → Reader β} {F : γ → Bytes → Option (β × Bytes)}
    (h : ∀ c, Sim (f c) (F c)) :
    Sim (fun ba i => o.bind fun c => f c ba i) (fun bs => o.bind fun c => F c bs) := by
  intro ba i hi
  cases o with
  | none => simp
  | some c => simpa using h c ba i hi

/-- `Sim` with the value mapped: a slice reader simulates a list reader up to `φ`. -/
def SimM {α β : Type} (φ : α → β) (f : Reader α) (g : Bytes → Option (β × Bytes)) : Prop :=
  ∀ (ba : ByteArray) (i : Nat), i ≤ ba.size →
    (f ba i).map (fun p => (φ p.1, ba.toList.drop p.2)) = g (ba.toList.drop i) ∧
    ∀ a j, f ba i = some (a, j) → i ≤ j ∧ j ≤ ba.size

/-- The same, at one position, for a whole parse: what the rest of the parse returns is compared
    only at positions that stay in the array. -/
theorem SimM.bind0 {α β γ : Type} {φ : α → β} {f : Reader α} {F : Bytes → Option (β × Bytes)}
    (hf : SimM φ f F) {ba : ByteArray} {i : Nat} (hi : i ≤ ba.size) {k : α × Nat → Option γ}
    {K : β × Bytes → Option γ} (hk : ∀ a j, j ≤ ba.size → k (a, j) = K (φ a, ba.toList.drop j)) :
    (f ba i).bind k = (F (ba.toList.drop i)).bind K := by
  obtain ⟨h1, h2⟩ := hf ba i hi
  rcases hfi : f ba i with _ | ⟨a, j⟩
  · rw [hfi] at h1
    simp only [Option.map_none] at h1
    simp [← h1]
  · rw [hfi] at h1
    simp only [Option.map_some] at h1
    rw [Option.bind_some, ← h1, Option.bind_some]
    exact hk a j (h2 a j hfi).2

theorem Sim.bind0 {α γ : Type} {f : Reader α} {F : Bytes → Option (α × Bytes)} (hf : Sim f F)
    {ba : ByteArray} {i : Nat} (hi : i ≤ ba.size) {k : α × Nat → Option γ} {K : α × Bytes → Option γ}
    (hk : ∀ a j, j ≤ ba.size → k (a, j) = K (a, ba.toList.drop j)) :
    (f ba i).bind k = (F (ba.toList.drop i)).bind K :=
  SimM.bind0 (φ := id) hf hi hk

/-! ## Primitives -/

theorem sim_readByte : Sim readByte Financial.readByte := by
  intro ba i hi
  by_cases h : i < ba.size
  · simp [readByte, h, drop_cons h, Financial.readByte]
    omega
  · have hd := drop_nil (ba := ba) (i := i) (by omega)
    simp [readByte, h, hd, Financial.readByte]

theorem sim_readNatBE : ∀ width, Sim (readNatBE width) (Financial.readNatBE width)
  | 0 => Sim.pure 0
  | width + 1 => Sim.bind (sim_readNatBE width) fun _ => Sim.bind sim_readByte fun _ => Sim.pure _

theorem sim_readString : Sim readString Financial.readString := by
  refine Sim.bind (sim_readNatBE 2) fun length => ?_
  intro ba j hj
  by_cases h : j + length > ba.size
  · have h' : length > ba.size - j := by omega
    simp [h, h', Fast.length_toList]
  · have h' : ¬ length > (ba.toList.drop j).length := by rw [drop_length]; omega
    have hx : ba.extract j (j + length) = ((ba.toList.drop j).take length).toByteArray := by
      rw [← Fast.toByteArray_toList (ba.extract j (j + length)), extract_toList]
    simp only [h, h', if_false, hx]
    rcases hs : String.fromUTF8? ((ba.toList.drop j).take length).toByteArray with _ | v
    · simp
    · refine ⟨by simp [Nat.add_comm], fun a l hl => ?_⟩
      simp at hl
      omega

theorem sim_readDigest : Sim readDigest Financial.readDigest := by
  intro ba i hi
  by_cases h : i + digestBytes > ba.size
  · have h' : ba.size - i < digestBytes := by omega
    simp [readDigest, Financial.readDigest, h, h', Fast.length_toList]
  · have h' : ¬ (ba.toList.drop i).length < digestBytes := by rw [drop_length]; omega
    simp only [readDigest, Financial.readDigest, h, h', if_false, extract_toList]
    refine ⟨by simp, fun a j hj => ?_⟩
    simp only [Option.some.injEq, Prod.mk.injEq] at hj
    omega

theorem sim_readBool : Sim readBool Financial.readBool := by
  unfold readBool Financial.readBool
  refine Sim.bind sim_readByte fun _ => ?_
  exact Sim.ite _ (Sim.pure _) (Sim.ite _ (Sim.pure _) Sim.fail)

theorem sim_readOptionNat : Sim readOptionNat Financial.readOptionNat := by
  unfold readOptionNat Financial.readOptionNat
  refine Sim.bind sim_readByte fun _ => ?_
  exact Sim.ite _ (Sim.pure _) (Sim.ite _ (Sim.bind (sim_readNatBE 8) fun _ => Sim.pure _) Sim.fail)

theorem sim_readOptionString : Sim readOptionString Financial.readOptionString := by
  unfold readOptionString Financial.readOptionString
  refine Sim.bind sim_readByte fun _ => ?_
  exact Sim.ite _ (Sim.pure _) (Sim.ite _ (Sim.bind sim_readString fun _ => Sim.pure _) Sim.fail)

theorem sim_readMany {α : Type} {p : Reader α} {P} (h : Sim p P) :
    ∀ n, Sim (readMany p n) (Financial.readMany P n)
  | 0 => Sim.pure []
  | n + 1 => Sim.bind h fun _ => Sim.bind (sim_readMany h n) fun _ => Sim.pure _

theorem sim_readList {α : Type} {p : Reader α} {P} (h : Sim p P) :
    Sim (readList p) (Financial.readList P) := by
  unfold readList Financial.readList
  refine Sim.bind (sim_readNatBE 2) fun count => ?_
  exact Sim.ite _ Sim.fail (fun ba j hj => sim_readMany h count ba j hj)

theorem simM_readMany {α β : Type} {φ : α → β} {p : Reader α} {P} (h : SimM φ p P) :
    ∀ n, SimM (List.map φ) (readMany p n) (Financial.readMany P n)
  | 0 => fun ba i hi => ⟨rfl, fun a j hj => by
      simp only [readMany, Option.some.injEq, Prod.mk.injEq] at hj
      obtain ⟨-, rfl⟩ := hj
      exact ⟨Nat.le_refl _, hi⟩⟩
  | n + 1 => fun ba i hi => by
    obtain ⟨h1, h2⟩ := h ba i hi
    simp only [readMany, Financial.readMany]
    rcases hp : p ba i with _ | ⟨a, j⟩
    · rw [hp] at h1
      simp only [Option.map_none] at h1
      simp [← h1]
    · rw [hp] at h1
      simp only [Option.map_some] at h1
      obtain ⟨hij, hjs⟩ := h2 a j hp
      obtain ⟨g1, g2⟩ := simM_readMany h n ba j hjs
      simp only [← h1, Option.bind_eq_bind, Option.bind_some]
      rcases hq : readMany p n ba j with _ | ⟨t, k⟩
      · rw [hq] at g1
        simp only [Option.map_none] at g1
        simp [← g1]
      · rw [hq] at g1
        simp only [Option.map_some] at g1
        obtain ⟨hjk, hks⟩ := g2 t k hq
        rw [← g1]
        refine ⟨by simp, fun a' l hl => ?_⟩
        simp only [Option.bind_some, Option.pure_def, Option.some.injEq, Prod.mk.injEq] at hl
        obtain ⟨-, rfl⟩ := hl
        omega

/-- A length-prefixed section as a slice of the frame. -/
def readSized (maximum : Nat) : Reader ByteArray := fun ba i => do
  let (length, i) ← readNatBE 4 ba i
  if length > maximum || i + length > ba.size then none
  else some (ba.extract i (i + length), i + length)

theorem sim_readSized (maximum : Nat) (R : Bytes → Option (Bytes × Bytes))
    (hR : ∀ bs, R bs = (do
      let (length, rest) ← Financial.readNatBE 4 bs
      if length > maximum || length > rest.length then none
      else some (rest.take length, rest.drop length))) :
    SimM ByteArray.toList (readSized maximum) R := by
  intro ba i hi
  rw [hR]
  obtain ⟨h1, h2⟩ := sim_readNatBE 4 ba i hi
  unfold readSized
  rcases hr : readNatBE 4 ba i with _ | ⟨length, j⟩
  · rw [hr] at h1
    simp only [Option.map_none] at h1
    simp [← h1]
  · rw [hr] at h1
    obtain ⟨hij, hjs⟩ := h2 length j hr
    simp only [Option.map_some] at h1
    simp only [Option.bind_eq_bind, Option.bind_some, ← h1]
    by_cases hc : length > maximum || j + length > ba.size
    · have hc' : (length > maximum || length > (ba.toList.drop j).length) = true := by
        simp only [Bool.or_eq_true, decide_eq_true_eq, drop_length] at hc ⊢; omega
      rw [if_pos hc, if_pos hc']
      simp
    · have hc' : ¬ (length > maximum || length > (ba.toList.drop j).length) = true := by
        simp only [Bool.or_eq_true, decide_eq_true_eq, drop_length, not_or] at hc ⊢; omega
      rw [if_neg hc, if_neg hc']
      refine ⟨?_, fun a l hl => ?_⟩
      · simp only [Option.map_some, Option.some.injEq, Prod.mk.injEq]
        exact ⟨extract_toList ba j length, by rw [List.drop_drop]⟩
      · simp only [Option.some.injEq, Prod.mk.injEq] at hl
        simp only [Bool.or_eq_true, decide_eq_true_eq, not_or] at hc
        omega

theorem bindEq {γ δ : Type} {o O : Option γ} {k K : γ → Option δ} (h : o = O) (hk : ∀ c, k c = K c) :
    o.bind k = O.bind K := by
  subst h
  exact congrArg _ (funext hk)

theorem end_iff {s : ByteArray} {j : Nat} (hj : j ≤ s.size) :
    j ≠ s.size ↔ (!(s.toList.drop j).isEmpty) = true := by
  have h : (s.toList.drop j).isEmpty = true ↔ j = s.size := by
    rw [List.isEmpty_iff_length_eq_zero, drop_length]; omega
  cases hx : (s.toList.drop j).isEmpty <;> simp_all

theorem ite_none_bind {α β : Type} {c : Prop} [Decidable c] {a : Option α} {f : α → Option β} :
    (if c then none else a).bind f = if c then none else a.bind f := by
  split <;> rfl

theorem ite_none {γ : Type} {c c' : Prop} [Decidable c] [Decidable c'] {a b : Option γ}
    (hc : c ↔ c') (h : ¬ c → a = b) : (if c then none else a) = (if c' then none else b) := by
  by_cases hc0 : c
  · simp [hc0, hc.1 hc0]
  · simp [hc0, mt hc.2 hc0, h hc0]

theorem readMagic_of_prefix {magic : Bytes} {ba : ByteArray} {i : Nat}
    (hi : i ≤ ba.size) (h : magic.isPrefixOf (ba.toList.drop i) = true) :
    readMagic magic ba i = some (i + magic.length) ∧ i + magic.length ≤ ba.size := by
  rw [List.isPrefixOf_iff_prefix, List.prefix_iff_eq_take] at h
  have hl := congrArg List.length h
  rw [List.length_take, drop_length] at hl
  have hb : i + magic.length ≤ ba.size := by omega
  refine ⟨?_, hb⟩
  have he : magic.toByteArray = ba.extract i (i + magic.length) := by
    rw [Fast.toByteArray_eq_iff, extract_toList]; exact h
  have hbe : (ba.extract i (i + magic.length) == magic.toByteArray) = true :=
    (Fast.beq_iff _ _).2 he.symm
  simp [readMagic, hb, hbe]

theorem readMagic_of_not_prefix {magic : Bytes} {ba : ByteArray} {i : Nat}
    (h : magic.isPrefixOf (ba.toList.drop i) = false) : readMagic magic ba i = none := by
  unfold readMagic
  by_cases hb : i + magic.length ≤ ba.size
  · have hne : ba.extract i (i + magic.length) ≠ magic.toByteArray := by
      intro he
      rw [eq_comm, Fast.toByteArray_eq_iff, extract_toList] at he
      have : magic.isPrefixOf (ba.toList.drop i) = true := by
        rw [List.isPrefixOf_iff_prefix, List.prefix_iff_eq_take]; exact he
      simp [this] at h
    have hbe : (ba.extract i (i + magic.length) == magic.toByteArray) = false :=
      Bool.eq_false_iff.2 fun hh => hne ((Fast.beq_iff _ _).1 hh)
    simp [hb, hbe]
  · simp [hb]

/-! ## Twins of the record readers -/

class SimOf {α : Type} (f : Reader α) (g : Bytes → Option (α × Bytes)) : Prop where
  sim : Sim f g

instance : SimOf readByte Financial.readByte := ⟨sim_readByte⟩
instance (n : Nat) : SimOf (readNatBE n) (Financial.readNatBE n) := ⟨sim_readNatBE n⟩
instance : SimOf readString Financial.readString := ⟨sim_readString⟩
instance : SimOf readDigest Financial.readDigest := ⟨sim_readDigest⟩
instance : SimOf readBool Financial.readBool := ⟨sim_readBool⟩
instance : SimOf readOptionNat Financial.readOptionNat := ⟨sim_readOptionNat⟩
instance : SimOf readOptionString Financial.readOptionString := ⟨sim_readOptionString⟩
instance {α : Type} {p : Reader α} {P} [h : SimOf p P] :
    SimOf (readList p) (Financial.readList P) := ⟨sim_readList h.sim⟩

/-- Peel a `do` block one bind at a time, closing each reader with its `SimOf`. -/
syntax "sim_steps" : tactic
macro_rules
  | `(tactic| sim_steps) => `(tactic| repeat (first
    | exact Sim.pure _
    | exact Sim.fail
    | refine Sim.bind SimOf.sim fun _ => ?_
    | refine Sim.bindOpt _ fun _ => ?_
    | (refine Sim.ite _ ?_ ?_ <;> sim_steps)))

def decodeContext : Reader FinancialContext := fun ba i => do
  let (ownerId, i) ← readString ba i
  let (modeByte, i) ← readByte ba i
  let mode ← decodeMode modeByte
  let (provenanceByte, i) ← readByte ba i
  let provenance ← decodeProvenance provenanceByte
  let (stateId, i) ← readString ba i
  let (deploymentId, i) ← readString ba i
  let (programId, i) ← readString ba i
  let (periodId, i) ← readString ba i
  let (populationId, i) ← readString ba i
  let (itemId, i) ← readString ba i
  let (obligationId, i) ← readString ba i
  let (currency, i) ← readString ba i
  pure
    ({ ownerId := ownerId
       mode := mode
       provenance := provenance
       stateId := stateId
       deploymentId := deploymentId
       programId := programId
       periodId := periodId
       populationId := populationId
       itemId := itemId
       obligationId := obligationId
       currency := currency }, i)

def decodeAuthorityActor : Reader AuthorityActor := fun ba i => do
  let (actorId, i) ← readString ba i
  let (roles, i) ← readList readString ba i
  pure ({ actorId := actorId, roles := roles }, i)

def decodeAuthority : Reader TrustedAuthority := fun ba i => do
  let (authorityId, i) ← readString ba i
  let (epoch, i) ← readNatBE 8 ba i
  let (digest, i) ← readDigest ba i
  let (syntheticOnly, i) ← readBool ba i
  let (actors, i) ← readList decodeAuthorityActor ba i
  pure
    ({ authorityId := authorityId
       epoch := epoch
       digest := digest
       syntheticOnly := syntheticOnly
       actors := actors }, i)

def decodeControlPack : Reader ControlPack := fun ba i => do
  let (packId, i) ← readString ba i
  let (stateId, i) ← readString ba i
  let (deploymentId, i) ← readString ba i
  let (programId, i) ← readString ba i
  let (periodId, i) ← readString ba i
  let (currency, i) ← readString ba i
  let (version, i) ← readNatBE 8 ba i
  let (sourceRefs, i) ← readList readString ba i
  let (effectiveStart, i) ← readNatBE 8 ba i
  let (effectiveEnd, i) ← readNatBE 8 ba i
  let (recordedAt, i) ← readNatBE 8 ba i
  let (approvedAt, i) ← readNatBE 8 ba i
  let (calculationRuleId, i) ← readString ba i
  let (adjustmentRuleId, i) ← readString ba i
  let (authorizedRoles, i) ← readList readString ba i
  let (expectedTests, i) ← readList readString ba i
  let (digest, i) ← readDigest ba i
  let (statusByte, i) ← readByte ba i
  let status ← decodePackStatus statusByte
  pure
    ({ packId := packId
       stateId := stateId
       deploymentId := deploymentId
       programId := programId
       periodId := periodId
       currency := currency
       version := version
       sourceRefs := sourceRefs
       effectiveStart := effectiveStart
       effectiveEnd := effectiveEnd
       recordedAt := recordedAt
       approvedAt := approvedAt
       calculationRuleId := calculationRuleId
       adjustmentRuleId := adjustmentRuleId
       authorizedRoles := authorizedRoles
       expectedTests := expectedTests
       digest := digest
       status := status }, i)

def decodeObligation : Reader Obligation := fun ba i => do
  let (populationId, i) ← readString ba i
  let (itemId, i) ← readString ba i
  let (obligationId, i) ← readString ba i
  let (owedCents, i) ← readNatBE 8 ba i
  let (dueAt, i) ← readNatBE 8 ba i
  let (ruleVersion, i) ← readNatBE 8 ba i
  let (reportingComplete, i) ← readBool ba i
  pure
    ({ populationId := populationId
       itemId := itemId
       obligationId := obligationId
       owedCents := owedCents
       dueAt := dueAt
       ruleVersion := ruleVersion
       reportingComplete := reportingComplete }, i)

def decodePayment : Reader Payment := fun ba i => do
  let (paymentId, i) ← readString ba i
  let (obligationId, i) ← readString ba i
  let (itemId, i) ← readString ba i
  let (evidenceId, i) ← readString ba i
  let (commonOriginId, i) ← readString ba i
  let (amountCents, i) ← readNatBE 8 ba i
  let (eventAt, i) ← readNatBE 8 ba i
  let (reversalEvidenceId, i) ← readOptionString ba i
  let (statusByte, i) ← readByte ba i
  let status ← decodePaymentStatus statusByte
  pure
    ({ paymentId := paymentId
       obligationId := obligationId
       itemId := itemId
       evidenceId := evidenceId
       commonOriginId := commonOriginId
       amountCents := amountCents
       eventAt := eventAt
       reversalEvidenceId := reversalEvidenceId
       status := status }, i)

def decodeClaim : Reader Claim := fun ba i => do
  let (claimId, i) ← readString ba i
  let (obligationId, i) ← readString ba i
  let (evidenceId, i) ← readString ba i
  let (amountCents, i) ← readNatBE 8 ba i
  let (ownerRole, i) ← readString ba i
  let (deadlineAt, i) ← readNatBE 8 ba i
  let (statusByte, i) ← readByte ba i
  let status ← decodeClaimStatus statusByte
  pure
    ({ claimId := claimId
       obligationId := obligationId
       evidenceId := evidenceId
       amountCents := amountCents
       ownerRole := ownerRole
       deadlineAt := deadlineAt
       status := status }, i)

def decodeDetermination : Reader OffsetDetermination := fun ba i => do
  let (determinationId, i) ← readString ba i
  let (obligationId, i) ← readString ba i
  let (claimId, i) ← readString ba i
  let (actorId, i) ← readString ba i
  let (actorRole, i) ← readString ba i
  let (authorityId, i) ← readString ba i
  let (authorityEpoch, i) ← readNatBE 8 ba i
  let (authorityDigest, i) ← readDigest ba i
  let (decisionByte, i) ← readByte ba i
  let decision ← decodeDecision decisionByte
  let (amountCents, i) ← readNatBE 8 ba i
  let (supportingEvidenceIds, i) ← readList readString ba i
  let (expectedRevision, i) ← readNatBE 8 ba i
  let (resultingRevision, i) ← readNatBE 8 ba i
  let (decidedAt, i) ← readNatBE 8 ba i
  pure
    ({ determinationId := determinationId
       obligationId := obligationId
       claimId := claimId
       actorId := actorId
       actorRole := actorRole
       authorityId := authorityId
       authorityEpoch := authorityEpoch
       authorityDigest := authorityDigest
       decision := decision
       amountCents := amountCents
       supportingEvidenceIds := supportingEvidenceIds
       expectedRevision := expectedRevision
       resultingRevision := resultingRevision
       decidedAt := decidedAt }, i)

def decodeEvidence : Reader EvidenceRecord := fun ba i => do
  let (evidenceId, i) ← readString ba i
  let (obligationId, i) ← readString ba i
  let (itemId, i) ← readString ba i
  let (kind, i) ← readString ba i
  let (commonOriginId, i) ← readString ba i
  let (sourceId, i) ← readString ba i
  let (sourceVersion, i) ← readString ba i
  let (localRef, i) ← readString ba i
  let (applicableAt, i) ← readNatBE 8 ba i
  let (eventAt, i) ← readNatBE 8 ba i
  let (receivedAt, i) ← readNatBE 8 ba i
  let (amountCents, i) ← readOptionNat ba i
  let (reversalOf, i) ← readOptionString ba i
  let (supersedes, i) ← readOptionString ba i
  pure
    ({ evidenceId := evidenceId
       obligationId := obligationId
       itemId := itemId
       kind := kind
       commonOriginId := commonOriginId
       sourceId := sourceId
       sourceVersion := sourceVersion
       localRef := localRef
       applicableAt := applicableAt
       eventAt := eventAt
       receivedAt := receivedAt
       amountCents := amountCents
       reversalOf := reversalOf
       supersedes := supersedes }, i)

def decodeConflict : Reader FinancialConflict := fun ba i => do
  let (conflictId, i) ← readString ba i
  let (obligationId, i) ← readString ba i
  let (commonOriginId, i) ← readString ba i
  let (existingPaymentId, i) ← readString ba i
  let (candidateEvidenceId, i) ← readString ba i
  let (existingAmountCents, i) ← readNatBE 8 ba i
  let (candidateAmountCents, i) ← readNatBE 8 ba i
  let (reason, i) ← readString ba i
  let (visibleAt, i) ← readNatBE 8 ba i
  pure
    ({ conflictId := conflictId
       obligationId := obligationId
       commonOriginId := commonOriginId
       existingPaymentId := existingPaymentId
       candidateEvidenceId := candidateEvidenceId
       existingAmountCents := existingAmountCents
       candidateAmountCents := candidateAmountCents
       reason := reason
       visibleAt := visibleAt }, i)

def decodeCase : Reader CaseRecord := fun ba i => do
  let (caseId, i) ← readString ba i
  let (obligationId, i) ← readString ba i
  let (reason, i) ← readString ba i
  let (nextActionOwner, i) ← readString ba i
  let (dueAt, i) ← readNatBE 8 ba i
  let (statusByte, i) ← readByte ba i
  let status ← decodeCaseStatus statusByte
  let (updatedAt, i) ← readNatBE 8 ba i
  pure
    ({ caseId := caseId
       obligationId := obligationId
       reason := reason
       nextActionOwner := nextActionOwner
       dueAt := dueAt
       status := status
       updatedAt := updatedAt }, i)

def decodeAction : Reader ActionRecord := fun ba i => do
  let (actionId, i) ← readString ba i
  let (obligationId, i) ← readString ba i
  let (determinationId, i) ← readOptionString ba i
  let (kind, i) ← readString ba i
  let (amountCents, i) ← readNatBE 8 ba i
  let (currency, i) ← readString ba i
  let (revision, i) ← readNatBE 8 ba i
  let (statusByte, i) ← readByte ba i
  let status ← decodeActionStatus statusByte
  let (payloadDigest, i) ← readDigest ba i
  let (createdAt, i) ← readNatBE 8 ba i
  pure
    ({ actionId := actionId
       obligationId := obligationId
       determinationId := determinationId
       kind := kind
       amountCents := amountCents
       currency := currency
       revision := revision
       status := status
       payloadDigest := payloadDigest
       createdAt := createdAt }, i)

instance : SimOf decodeContext Financial.decodeContext := ⟨by unfold decodeContext Financial.decodeContext; sim_steps⟩
instance : SimOf decodeAuthorityActor Financial.decodeAuthorityActor := ⟨by unfold decodeAuthorityActor Financial.decodeAuthorityActor; sim_steps⟩
instance : SimOf decodeAuthority Financial.decodeAuthority := ⟨by unfold decodeAuthority Financial.decodeAuthority; sim_steps⟩
instance : SimOf decodeControlPack Financial.decodeControlPack := ⟨by unfold decodeControlPack Financial.decodeControlPack; sim_steps⟩
instance : SimOf decodeObligation Financial.decodeObligation := ⟨by unfold decodeObligation Financial.decodeObligation; sim_steps⟩
instance : SimOf decodePayment Financial.decodePayment := ⟨by unfold decodePayment Financial.decodePayment; sim_steps⟩
instance : SimOf decodeClaim Financial.decodeClaim := ⟨by unfold decodeClaim Financial.decodeClaim; sim_steps⟩
instance : SimOf decodeDetermination Financial.decodeDetermination := ⟨by unfold decodeDetermination Financial.decodeDetermination; sim_steps⟩
instance : SimOf decodeEvidence Financial.decodeEvidence := ⟨by unfold decodeEvidence Financial.decodeEvidence; sim_steps⟩
instance : SimOf decodeConflict Financial.decodeConflict := ⟨by unfold decodeConflict Financial.decodeConflict; sim_steps⟩
instance : SimOf decodeCase Financial.decodeCase := ⟨by unfold decodeCase Financial.decodeCase; sim_steps⟩
instance : SimOf decodeAction Financial.decodeAction := ⟨by unfold decodeAction Financial.decodeAction; sim_steps⟩

/-! ## The whole `BLFIN02` input -/

/-- `Fast.decodeFinancialInputBA₂` without the list: one parse over the array, one well-formedness
    pass, one `memcmp` of the rebuilt encoding against the frame. -/
def decodeFinancialInput (ba : ByteArray) : Option FinancialInput :=
  if ba.size > maxTotalEncodedBytes then none else do
    let i ← readMagic financialCodecMagic ba 0
    let (context, i) ← decodeContext ba i
    let (authority, i) ← decodeAuthority ba i
    let (pack, i) ← decodeControlPack ba i
    let (obligation, i) ← decodeObligation ba i
    let (beforeRevision, i) ← readNatBE 8 ba i
    let (evaluatedAt, i) ← readNatBE 8 ba i
    let (payments, i) ← readList decodePayment ba i
    let (claims, i) ← readList decodeClaim ba i
    let (determinations, i) ← readList decodeDetermination ba i
    let (evidence, i) ← readList decodeEvidence ba i
    let (conflicts, i) ← readList decodeConflict ba i
    let (cases, i) ← readList decodeCase ba i
    let (actions, i) ← readList decodeAction ba i
    if i = ba.size then
      let input :=
        { context := context
          authority := authority
          pack := pack
          obligation := obligation
          beforeRevision := beforeRevision
          evaluatedAt := evaluatedAt
          payments := payments
          claims := claims
          determinations := determinations
          evidence := evidence
          conflicts := conflicts
          cases := cases
          actions := actions }
      if financialInputWellFormed input && Fast.rawEncodeFinancialInputBA input == ba then some input
      else none
    else none

theorem finish_eq {ba : ByteArray} (hs : ¬ ba.size > maxTotalEncodedBytes) (input : FinancialInput) :
    (if financialInputWellFormed input && Fast.rawEncodeFinancialInputBA input == ba then some input
      else none) =
    (if financialInputWellFormed input then
      match encodeFinancialInput input with
      | some canonical => if canonical = ba.toList then some input else none
      | none => none
    else none) := by
  by_cases hw : financialInputWellFormed input = true
  · have hb : (Fast.rawEncodeFinancialInputBA input == ba) =
        decide (rawEncodeFinancialInput input = ba.toList) := by
      rw [Fast.rawEncodeFinancialInputBA_eq]
      exact Bool.eq_iff_iff.2 (by rw [Fast.beq_iff, decide_eq_true_eq]; exact Fast.toByteArray_eq_iff _ _)
    simp only [hw, Bool.true_and, hb, encodeFinancialInput, if_true, decide_eq_true_eq]
    by_cases hl : (rawEncodeFinancialInput input).length ≤ maxTotalEncodedBytes
    · simp [hl]
    · have hne : rawEncodeFinancialInput input ≠ ba.toList :=
        fun e => hl (by rw [e, Fast.length_toList]; omega)
      simp [hl, hne]
  · simp [hw]

theorem tail_eq {ba : ByteArray} (hs : ¬ ba.size > maxTotalEncodedBytes) {j : Nat} (hj : j ≤ ba.size)
    (input : FinancialInput) :
    (if j = ba.size then
      if (financialInputWellFormed input && Fast.rawEncodeFinancialInputBA input == ba) = true then
        some input
      else none
    else none) =
    (if (ba.toList.drop j).isEmpty = true then
      if financialInputWellFormed input = true then
        match encodeFinancialInput input with
        | some canonical => if canonical = ba.toList then some input else none
        | none => none
      else none
    else none) := by
  by_cases he : j = ba.size
  · have hd : (ba.toList.drop j).isEmpty = true := by rw [drop_nil (Nat.le_of_eq he.symm)]; rfl
    rw [if_pos he, if_pos hd]
    exact finish_eq hs input
  · have hd : ¬ (ba.toList.drop j).isEmpty = true := fun h => by
      have := List.isEmpty_iff_length_eq_zero.1 h
      rw [drop_length] at this
      omega
    rw [if_neg he, if_neg hd]

macro "sim_chain" : tactic => `(tactic| repeat (refine Sim.bind0 SimOf.sim (by assumption) fun _ _ _ => ?_))

theorem decodeFinancialInput_eq (ba : ByteArray) :
    decodeFinancialInput ba = Financial.decodeFinancialInput ba.toList := by
  unfold decodeFinancialInput Financial.decodeFinancialInput
  rw [Fast.length_toList]
  by_cases hs : ba.size > maxTotalEncodedBytes
  · simp [hs]
  · simp only [hs, if_false]
    cases hm : financialCodecMagic.isPrefixOf ba.toList
    · rw [readMagic_of_not_prefix hm]
      simp [Financial.readMagic, hm]
    · obtain ⟨h1, h2⟩ := readMagic_of_prefix (i := 0) (Nat.zero_le _) hm
      rw [Nat.zero_add] at h2
      simp only [h1, Financial.readMagic, hm, Nat.zero_add, if_true, Option.bind_eq_bind, Option.bind_some]
      sim_chain
      exact tail_eq hs (by assumption) _

end BlindLedger.Financial.Cursor
