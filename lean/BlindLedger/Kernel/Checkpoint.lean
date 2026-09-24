import BlindLedger.Types

namespace BlindLedger.Kernel

/-! Checkpoints are audit commitments only.  The append operation binds the
    previous tip and ordered batch, and carries an explicit non-operative bit;
    it cannot authorize a clearance transition or a payment. -/

structure Checkpoint where
  sequence : Nat
  previous : Id
  batch : List Id
  next : Id
  operative : Bool
deriving DecidableEq, Repr

def checkpointGenesis : Id := idOfNat 200

def chainTip : List Checkpoint → Id
  | [] => checkpointGenesis
  | checkpoint :: rest =>
      match rest with
      | [] => checkpoint.next
      | _ => chainTip rest

def checkpointWellFormed (checkpoint : Checkpoint) : Bool :=
  checkpoint.next.isNonzero &&
    checkpoint.previous.isNonzero &&
    checkpoint.batch.length > 0 &&
    checkpoint.operative = false

def appendCheckpoint
    (chain : List Checkpoint) (checkpoint : Checkpoint) :
    Option (List Checkpoint) :=
  if checkpointWellFormed checkpoint &&
      checkpoint.sequence = chain.length &&
      checkpoint.previous = chainTip chain then
    some (chain ++ [checkpoint])
  else
    none

theorem checkpoint_append_preserves_prefix
    {chain result : List Checkpoint} {checkpoint : Checkpoint}
    (h : appendCheckpoint chain checkpoint = some result) :
    result = chain ++ [checkpoint] := by
  unfold appendCheckpoint at h
  split at h
  · simpa using h.symm
  · simp_all

theorem checkpoint_chain_append_only
    {chain result : List Checkpoint} {checkpoint : Checkpoint}
    (h : appendCheckpoint chain checkpoint = some result) :
    result = chain ++ [checkpoint] ∧ checkpoint.operative = false := by
  have hprefix := checkpoint_append_preserves_prefix h
  unfold appendCheckpoint at h
  split at h
  · have hvalid : checkpointWellFormed checkpoint = true := by
      simp_all
    constructor
    · exact hprefix
    · unfold checkpointWellFormed at hvalid
      simp_all
  · simp_all

def checkpointExample : Checkpoint :=
  { sequence := 0
    previous := checkpointGenesis
    batch := [idOfNat 1]
    next := idOfNat 201
    operative := false }

def checkpointExampleChain : Option (List Checkpoint) :=
  appendCheckpoint [] checkpointExample

theorem checkpoint_example_appends :
    checkpointExampleChain = some [checkpointExample] := by
  decide

end BlindLedger.Kernel
