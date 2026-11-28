import BlindLedger.Gate.Producer

/-! The producer's startup check against the shard's TPM counter (rollback custody design §2.2, §4).

    Each (tenant, shard) has one TPM monotonic counter.  The counter moves from s to s+1 only after the
    checkpoint whose header says `counter = s+1` is durably signed in the store, and nothing of that checkpoint
    leaves the machine before the increment.  So at every open the store's newest sealed counter is either the
    TPM value (the last seal completed) or one above it (the crash fell between the signature commit and the
    increment); before the first increment the counter is unwritten, so that crash after the shard's first seal
    leaves an unwritten counter under the signed first checkpoint.  Anything else is a store that was restored,
    copied or forged, and the producer refuses it.  Theorems on the first seal: `BatchTheorems`. -/
namespace BlindLedger.Gate

/-- Why the producer refuses to open a shard. -/
inductive CustodyRefusal
  /-- The counter was written but the store has no creation record: nothing was ever signed; re-create the shard
      on a new index. -/
  | noStore
  /-- The store exists but its counter was never written: the index was redefined under it. -/
  | counterReset
  /-- The store is behind the counter: an older copy of the store was restored. -/
  | storeRewound
  /-- The store is two or more ahead of the counter: the honest write order cannot produce it. -/
  | storeAhead
  deriving DecidableEq, Repr

/-- What the producer does at open: create the shard, serve, or increment the counter once (read back, then
    serve), or refuse. -/
inductive CustodyStep | create | ready | catchUp | refuse (why : CustodyRefusal) deriving DecidableEq, Repr

/-- `newest`, the store's newest sealed checkpoint with its signature, is the shard's first (`follows none`) and
    verifies under its epoch certificate `cert` and the tenant's root key: the store a crash between the first
    seal's signature commit and the counter's first increment leaves. -/
def firstSealed (link : Cosign.Link) (cert newest : Bytes) : Bool :=
  accepts link cert newest && (storedOf sha3 newest).any (follows none)

/-- `first`: `firstSealed` of the store's newest sealed checkpoint; `tpm`: the shard's counter (`none`: defined,
    never written); `store`: the counter of the store's newest sealed checkpoint (`none`: nothing sealed).  An
    unwritten counter under a store is a redefined index, except under the signed first checkpoint at counter 1:
    there the first increment was lost, and the start takes it. -/
def custodyStep (first : Bool) : Option Nat → Option Nat → CustodyStep
  | none, none => .create
  | some _, none => .refuse .noStore
  | none, some s => if first && s == 1 then .catchUp else .refuse .counterReset
  | some t, some s =>
    if s == t then .ready else if s == t + 1 then .catchUp
    else if s < t then .refuse .storeRewound else .refuse .storeAhead

/-- A restored store (behind the counter) is never resumed. -/
theorem custodyStep_behind {f : Bool} {t s : Nat} (h : s < t) :
    custodyStep f (some t) (some s) = .refuse .storeRewound := by
  have h1 : s ≠ t := by omega
  have h2 : s ≠ t + 1 := by omega
  simp [custodyStep, h1, h2, h]

/-- The producer serves exactly when the store is at the counter, and catches up exactly when it is one ahead. -/
theorem custodyStep_proceeds {f : Bool} {t s : Nat} :
    (custodyStep f (some t) (some s) = .ready ↔ s = t) ∧ (custodyStep f (some t) (some s) = .catchUp ↔ s = t + 1) := by
  unfold custodyStep
  by_cases h1 : s = t
  · subst h1
    simp
  · by_cases h2 : s = t + 1
    · subst h2
      simp
    · by_cases h3 : s < t <;> simp [h1, h2, h3]

/-- Over a sealed store an unwritten counter is never served or created on: the start increments it first (the
    signed first checkpoint, counter 1) or refuses, so no seal is ever signed at the unwritten counter's value. -/
theorem custodyStep_unwritten {f : Bool} {s : Nat} :
    custodyStep f none (some s) ≠ .ready ∧ custodyStep f none (some s) ≠ .create := by
  unfold custodyStep
  cases f <;> by_cases h : s = 1 <;> simp [h]

/-- An unwritten counter over a sealed store is caught up only under the signed first checkpoint at counter 1. -/
theorem custodyStep_catchUp_unwritten {f : Bool} {s : Nat} :
    custodyStep f none (some s) = .catchUp ↔ f = true ∧ s = 1 := by
  unfold custodyStep
  cases f <;> by_cases h : s = 1 <;> simp [h]

/-- The start's step with the store's counter taken from the newest sealed checkpoint `signed` itself (empty: nothing
    sealed), the same bytes `firstSealed` checks, so the two cannot come from different checkpoints.  A non-empty
    `signed` that does not decode is refused. -/
def custodyOf (link : Cosign.Link) (cert signed : Bytes) (tpm : Option Nat) : CustodyStep :=
  match storedOf sha3 signed with
  | some x => custodyStep (firstSealed link cert signed) tpm (some x.checkpoint.counter)
  | none => if signed.isEmpty then custodyStep false tpm none else .refuse .storeRewound

/-- An unreadable newest checkpoint is never served or created on, whatever the counter. -/
theorem custodyOf_unreadable {link : Cosign.Link} {cert signed : Bytes} {tpm : Option Nat} (h : storedOf sha3 signed = none)
    (hs : signed.isEmpty = false) : custodyOf link cert signed tpm = .refuse .storeRewound := by
  simp [custodyOf, h, hs]

/-- Every crash point of the seal order (TPM value, store's newest counter) resumes: before the signature commit,
    between the commit and the increment, and after the increment. -/
theorem seal_crash_resumes (f : Bool) (t : Nat) :
    ∀ x ∈ [(some t, some t), (some t, some (t + 1)), (some (t + 1), some (t + 1))],
      custodyStep f x.1 x.2 = .ready ∨ custodyStep f x.1 x.2 = .catchUp := by
  intro x hx
  simp only [List.mem_cons, List.not_mem_nil, or_false] at hx
  rcases hx with rfl | rfl | rfl <;> simp [custodyStep]

end BlindLedger.Gate
