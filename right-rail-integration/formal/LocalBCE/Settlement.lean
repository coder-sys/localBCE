namespace LocalBCE

inductive SettlementState where
  | prepared
  | submitted
  | mined
  | finalized
  | localStateCommitted
  deriving DecidableEq, Repr

inductive Decision where
  | approved
  | denied
  deriving DecidableEq, Repr

inductive Role where
  | governance
  | pauser
  | treasury
  deriving DecidableEq, Repr

inductive Backend where
  | groth16
  | starkAttested
  deriving DecidableEq, Repr

def LegalTransition : SettlementState -> SettlementState -> Prop
  | .prepared, .submitted => True
  | .submitted, .mined => True
  | .mined, .finalized => True
  | .finalized, .localStateCommitted => True
  | _, _ => False

theorem noLocalCommitBeforeFinality {source : SettlementState}
    (h : LegalTransition source .localStateCommitted) : source = .finalized := by
  cases source <;> simp_all [LegalTransition]

structure RootTransition where
  beforeRoot : Nat
  afterRoot : Nat
  decision : Decision

def ValidRootTransition (transition : RootTransition) : Prop :=
  match transition.decision with
  | .approved => True
  | .denied => transition.afterRoot = transition.beforeRoot

theorem deniedPreservesRoots (transition : RootTransition)
    (decision : transition.decision = .denied)
    (valid : ValidRootTransition transition) :
    transition.afterRoot = transition.beforeRoot := by
  simp [ValidRootTransition, decision] at valid
  exact valid

def RetryAccepted (expectedGeneration actualGeneration : Nat)
    (sameCanonicalInput : Bool) : Prop :=
  And (expectedGeneration = actualGeneration) (sameCanonicalInput = true)

theorem staleGenerationFailsClosed {expectedGeneration actualGeneration : Nat}
    {sameCanonicalInput : Bool}
    (stale : Not (expectedGeneration = actualGeneration)) :
    Not (RetryAccepted expectedGeneration actualGeneration sameCanonicalInput) := by
  intro accepted
  exact stale accepted.1

theorem conflictingRetryFailsClosed {generation : Nat} :
    Not (RetryAccepted generation generation false) := by
  simp [RetryAccepted]

def MayTransferTreasury : Role -> Prop
  | .treasury => True
  | _ => False

theorem governanceCannotTransferTreasury : Not (MayTransferTreasury .governance) := by
  simp [MayTransferTreasury]

def RecoveryBackend (backend : Backend) : Backend := backend

theorem recoveryNeverFallsBack (backend : Backend) : RecoveryBackend backend = backend := by
  rfl

end LocalBCE
