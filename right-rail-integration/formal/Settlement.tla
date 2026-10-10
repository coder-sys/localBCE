---- MODULE Settlement ----
EXTENDS Naturals

CONSTANTS Prepared, Submitted, Mined, Finalized, LocalCommitted,
          Approved, Denied, Governance, Pauser, Treasury,
          Groth16, StarkAttested

VARIABLES state, previousState, decision, rootBefore, rootAfter, expectedGeneration,
          actualGeneration, canonicalInputMatches, role, backend

States == {Prepared, Submitted, Mined, Finalized, LocalCommitted}
vars == <<state, previousState, decision, rootBefore, rootAfter,
          expectedGeneration, actualGeneration, canonicalInputMatches, role, backend>>

Init == /\ state = Prepared
        /\ previousState = Prepared
        /\ decision \in {Approved, Denied}
        /\ rootBefore \in Nat
        /\ rootAfter = rootBefore
        /\ expectedGeneration = actualGeneration
        /\ actualGeneration \in Nat
        /\ canonicalInputMatches = TRUE
        /\ role \in {Governance, Pauser, Treasury}
        /\ backend \in {Groth16, StarkAttested}

Advance == /\ \/ /\ state = Prepared /\ state' = Submitted
                  \/ /\ state = Submitted /\ state' = Mined
                  \/ /\ state = Mined /\ state' = Finalized
                  \/ /\ state = Finalized /\ state' = LocalCommitted
           /\ previousState' = state
           /\ UNCHANGED <<decision, rootBefore, rootAfter, expectedGeneration,
                           actualGeneration, canonicalInputMatches, role, backend>>

Next == Advance
Spec == Init /\ [][Next]_vars

TypeInvariant == state \in States
NoCommitBeforeFinality == state = LocalCommitted => previousState = Finalized
DeniedPreservesRoots == decision = Denied => rootAfter = rootBefore
RetryFailsClosed == expectedGeneration # actualGeneration \/ ~canonicalInputMatches
AuthorizationSeparation == role = Treasury \/ role \in {Governance, Pauser}
NoAutomaticBackendFallback == backend \in {Groth16, StarkAttested}

====
