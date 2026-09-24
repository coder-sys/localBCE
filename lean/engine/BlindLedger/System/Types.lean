import Std

namespace BlindLedger.System

/-! The system kernel uses wrappers with fixed byte widths but assigns no
    cryptographic or semantic meaning to their contents. -/

abbrev Byte := Fin 256
abbrev BatchIndex := Fin 100

/-! These are the only effective directives in the system model. -/
inductive EffectiveDirective where
  | CLEAR
  | HOLD
  | HUMAN_REVIEW
  | BLOCK
  | EXCEPTION_APPROVED
deriving DecidableEq, Repr

/-! Policy and verification outcomes are deliberately not directives. -/
inductive PolicyResult where
  | accepted
  | rejected
  | unavailable
deriving DecidableEq, Repr

inductive VerificationOutcome where
  | verified
  | failed
deriving DecidableEq, Repr

/-! Public source identifiers are opaque 32-byte wrappers. OperationRef is an
    alias so the operation-batch and public Queue representations cannot drift
    into two different reference authorities. -/
structure SourceRef32 where
  bytes : Fin 32 → Byte

abbrev OperationRef := SourceRef32

structure LaunchRef where
  bytes : Fin 32 → Byte

structure ReceiptRef where
  bytes : Fin 32 → Byte

structure LeaseRef where
  bytes : Fin 32 → Byte

structure FrameRef where
  bytes : Fin 32 → Byte

structure IdempotencyIdentity where
  bytes : Fin 32 → Byte

/-! A batch has exactly one opaque operation reference at every Fin 100 index. -/
structure OperationBatch where
  refs : BatchIndex → OperationRef

def firstBatchIndex : BatchIndex := ⟨0, by decide⟩

def predecessorIndex (i : BatchIndex) : Option BatchIndex :=
  if h : i.val = 0 then
    none
  else
    some ⟨i.val - 1, by omega⟩

def OperationBatch.predecessorRef
    (batch : OperationBatch) (i : BatchIndex) : Option OperationRef :=
  match predecessorIndex i with
  | none => none
  | some j => some (batch.refs j)

theorem predecessorIndex_first : predecessorIndex firstBatchIndex = none := by
  simp [predecessorIndex, firstBatchIndex]

theorem predecessorIndex_positive (i : BatchIndex) (h : 0 < i.val) :
    predecessorIndex i = some ⟨i.val - 1, by omega⟩ := by
  simp [predecessorIndex, Nat.ne_of_gt h]

theorem OperationBatch.predecessorRef_first (batch : OperationBatch) :
    batch.predecessorRef firstBatchIndex = none := by
  simp [OperationBatch.predecessorRef, predecessorIndex_first]

theorem OperationBatch.predecessorRef_positive
    (batch : OperationBatch) (i : BatchIndex) (h : 0 < i.val) :
    batch.predecessorRef i = some (batch.refs ⟨i.val - 1, by omega⟩) := by
  simp [OperationBatch.predecessorRef, predecessorIndex, Nat.ne_of_gt h]

inductive DeliveryState where
  | queued
  | leased (lease : LeaseRef)
  | retrying (attempt : Nat)
  | acknowledged
  | deliveryUnconfirmed (attempt : Nat)
  | failed

structure AuthorizationBatch where
  directives : BatchIndex → EffectiveDirective
  idempotency : BatchIndex → IdempotencyIdentity

inductive OutboxReadiness where
  | READY

structure OutboxEntry where
  operation : OperationRef
  directive : EffectiveDirective
  idempotency : IdempotencyIdentity
  readiness : OutboxReadiness
  delivery : DeliveryState

structure Outbox where
  entries : BatchIndex → Option OutboxEntry

end BlindLedger.System
