import BlindLedger.Gate.Spec
import BlindLedger.Gate.Rules.Spec

/-! The prior-digest check (gate-producer-v1 §4): the rules' released and unresolved priors must hash to the
    latest signed checkpoint's state digest, or nothing is decided.  The decide runtime imports this; the
    pinned verifier does not.  Theorems: `AnchorTheorems`. -/
namespace BlindLedger.Gate

/-- The released and unresolved pins of two sets (`Rules/Run.lean` `snapshot`, kinds 5 and 6). -/
def setPins (H : Bytes → Bytes) (r u : Rules.Snapshot Rules.Line) : Option (Bytes × Bytes) := do
  let a ← Rules.pinInput "RR/GATE/RELEASED/v1" 5 Rules.Line.fields r
  let b ← Rules.pinInput "RR/GATE/UNRESOLVED/v1" 6 Rules.Line.fields u
  pure (H a, H b)

/-- The checkpoint state digest of two sets; none when a row does not fit its width. -/
def setsDigest (H : Bytes → Bytes) (r u : Rules.Snapshot Rules.Line) : Option Bytes :=
  (setPins H r u).map fun (a, b) => stateDigest H a b

/-- The priors hash to the anchor (the latest signed checkpoint's `stateDigest`, read big-endian). -/
def anchored (H : Bytes → Bytes) (c : Rules.Ctx) : Bool :=
  setsDigest H c.releasedPrior c.unresolvedPrior == some (natBE digestBytes c.anchor)

/-- The spec of every runtime decide: unanchored priors decide nothing. -/
def decideAnchored (H : Bytes → Bytes) (c : Rules.Ctx) (b : List Rules.Line) : Option Rules.Result :=
  if anchored H c then some (Rules.decideBatch c b) else none

/-- A shard's sets with their cached digest, so the per-batch anchor check is one 64-byte compare. -/
structure ShardState where
  released : Rules.Snapshot Rules.Line
  unresolved : Rules.Snapshot Rules.Line
  digest : Bytes

def ShardState.Ok (H : Bytes → Bytes) (st : ShardState) : Prop :=
  setsDigest H st.released st.unresolved = some st.digest

def ShardState.load (H : Bytes → Bytes) (r u : Rules.Snapshot Rules.Line) : Option ShardState :=
  (setsDigest H r u).map fun d => ⟨r, u, d⟩

/-- One batch: the priors are the state's own sets, refused unless the anchor names the cached digest. -/
def ShardState.step (H : Bytes → Bytes) (st : ShardState) (c : Rules.Ctx) (b : List Rules.Line) :
    Option (Rules.Result × ShardState) :=
  if st.digest == natBE digestBytes c.anchor then
    let r := Rules.decideBatch { c with releasedPrior := st.released, unresolvedPrior := st.unresolved } b
    (ShardState.load H r.released r.unresolved).map fun st' => (r, st')
  else none

/-- `step` with the ids `f` that the tenant's id registry gives another shard (gate-shard-uniqueness-v1). -/
def ShardState.stepIn (H : Bytes → Bytes) (st : ShardState) (c : Rules.Ctx) (f : List Nat) (b : List Rules.Line) :
    Option (Rules.Result × ShardState) :=
  if st.digest == natBE digestBytes c.anchor then
    let r := Rules.decideBatchIn { c with releasedPrior := st.released, unresolvedPrior := st.unresolved } f b
    (ShardState.load H r.released r.unresolved).map fun st' => (r, st')
  else none

end BlindLedger.Gate
