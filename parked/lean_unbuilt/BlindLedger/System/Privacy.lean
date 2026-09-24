import BlindLedger.System.Types

namespace BlindLedger.System

/-! Private source material has its own types and has no conversion function to
    any public type in this model. The widths here describe wrappers only. -/
abbrev PrivateByte := Fin 256

structure Witness where
  bytes : Fin 800 → PrivateByte

structure Randomness where
  bytes : Fin 32 → PrivateByte

structure Seed where
  bytes : Fin 128 → PrivateByte

structure PrivateSourceRecord where
  witness : Witness
  randomness : Randomness
  seed : Seed

/-! These are the public allowlisted wrappers. -/
structure CanonicalStatement where
  bytes : Fin 304 → Byte

structure OrderedOpaqueRefs where
  batch : OperationBatch

def OrderedOpaqueRefs.predecessorRef
    (ordered : OrderedOpaqueRefs) (i : BatchIndex) : Option OperationRef :=
  ordered.batch.predecessorRef i

inductive QualifiedOutcome where
  | qualified
  | unqualified
deriving DecidableEq, Repr

structure FrameResult where
  frame : FrameRef
  outcome : QualifiedOutcome

structure PublicAllowlist where
  statement : CanonicalStatement
  refs : OrderedOpaqueRefs
  result : FrameResult

inductive PublicValue where
  | canonicalStatement (value : CanonicalStatement)
  | orderedOpaqueRefs (value : OrderedOpaqueRefs)
  | frameResult (value : FrameResult)
  | qualifiedOutcome (value : QualifiedOutcome)
  | allowlist (value : PublicAllowlist)

inductive PrivateValue where
  | witness (value : Witness)
  | randomness (value : Randomness)
  | seed (value : Seed)
  | sourceRecord (value : PrivateSourceRecord)

inductive BoundaryValue where
  | publicValue (value : PublicValue)
  | privateValue (value : PrivateValue)

/-! This is a constructor-level non-flow fact only. It says nothing about
    semantic identification, side channels, or a deployed zero-PHI property. -/
theorem public_private_boundary_disjoint
    (publicValue : PublicValue) (privateValue : PrivateValue) :
    BoundaryValue.publicValue publicValue ≠ BoundaryValue.privateValue privateValue := by
  intro h
  cases h

theorem orderedOpaqueRefs_predecessor_first (ordered : OrderedOpaqueRefs) :
    ordered.predecessorRef firstBatchIndex = none := by
  exact ordered.batch.predecessorRef_first

theorem orderedOpaqueRefs_predecessor_positive
    (ordered : OrderedOpaqueRefs) (i : BatchIndex) (h : 0 < i.val) :
    ordered.predecessorRef i =
      some (ordered.batch.refs ⟨i.val - 1, by omega⟩) := by
  exact ordered.batch.predecessorRef_positive i h

end BlindLedger.System
